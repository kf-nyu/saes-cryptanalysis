//! S-AES [2] and Double S-AES: exhaustive and MITM wall-clock benchmarks.
//! Each S-AES includes the initial AddRoundKey.

use rayon::prelude::*;
use std::hint::black_box;
use std::time::Instant;

const SBOX: [u8; 16] = [
    0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7,
];

const INV_SBOX: [u8; 16] = [
    0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE,
];

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..4 {
        if b & 1 != 0 {
            product ^= a;
        }
        let carry = a & 0x8;
        a = (a << 1) & 0xF;
        if carry != 0 {
            a ^= 0b0011;
        }
        b >>= 1;
    }
    product
}

fn rot_nibble(byte: u8) -> u8 {
    ((byte << 4) | (byte >> 4)) & 0xFF
}

fn sub_nibble(byte: u8) -> u8 {
    (SBOX[((byte >> 4) & 0xF) as usize] << 4) | SBOX[(byte & 0xF) as usize]
}

fn key_expansion(key: u16) -> (u16, u16, u16) {
    let w0 = ((key >> 8) & 0xFF) as u8;
    let w1 = (key & 0xFF) as u8;
    let w2 = w0 ^ (sub_nibble(rot_nibble(w1)) ^ 0x80);
    let w3 = w1 ^ w2;
    let w4 = w2 ^ (sub_nibble(rot_nibble(w3)) ^ 0x30);
    let w5 = w3 ^ w4;
    let k0 = ((w0 as u16) << 8) | (w1 as u16);
    let k1 = ((w2 as u16) << 8) | (w3 as u16);
    let k2 = ((w4 as u16) << 8) | (w5 as u16);
    (k0, k1, k2)
}

fn nibble(word: u16, i: u32) -> u8 {
    ((word >> (12 - 4 * i)) & 0xF) as u8
}

fn pack(n0: u8, n1: u8, n2: u8, n3: u8) -> u16 {
    ((n0 as u16) << 12) | ((n1 as u16) << 8) | ((n2 as u16) << 4) | (n3 as u16)
}

fn substitute(word: u16, box_: &[u8; 16]) -> u16 {
    pack(
        box_[nibble(word, 0) as usize],
        box_[nibble(word, 1) as usize],
        box_[nibble(word, 2) as usize],
        box_[nibble(word, 3) as usize],
    )
}

fn shift(word: u16) -> u16 {
    // [n0 n2; n1 n3] -> [n0 n2; n3 n1]
    pack(nibble(word, 0), nibble(word, 3), nibble(word, 2), nibble(word, 1))
}

fn mix_columns(word: u16, a: u8, b: u8) -> u16 {
    let n0 = nibble(word, 0);
    let n1 = nibble(word, 1);
    let n2 = nibble(word, 2);
    let n3 = nibble(word, 3);
    pack(
        gf_mul(a, n0) ^ gf_mul(b, n1),
        gf_mul(b, n0) ^ gf_mul(a, n1),
        gf_mul(a, n2) ^ gf_mul(b, n3),
        gf_mul(b, n2) ^ gf_mul(a, n3),
    )
}

fn encrypt_round1(state: u16, k1: u16) -> u16 {
    mix_columns(shift(substitute(state, &SBOX)), 1, 4) ^ k1
}

fn encrypt_round2(state: u16, k2: u16) -> u16 {
    shift(substitute(state, &SBOX)) ^ k2
}

fn decrypt_round2(state: u16, k2: u16) -> u16 {
    substitute(shift(state ^ k2), &INV_SBOX)
}

fn decrypt_round1(state: u16, k1: u16) -> u16 {
    substitute(shift(mix_columns(state ^ k1, 9, 2)), &INV_SBOX)
}

fn saes_encrypt(plaintext: u16, key: u16) -> u16 {
    let (k0, k1, k2) = key_expansion(key);
    encrypt_round2(encrypt_round1(plaintext ^ k0, k1), k2)
}

fn saes_decrypt(ciphertext: u16, key: u16) -> u16 {
    let (k0, k1, k2) = key_expansion(key);
    decrypt_round1(decrypt_round2(ciphertext, k2), k1) ^ k0
}

fn double_encrypt(plaintext: u16, ka: u16, kb: u16) -> u16 {
    saes_encrypt(saes_encrypt(plaintext, ka), kb)
}

fn saes_exhaustive(plaintext: u16, ciphertext: u16) -> (Vec<u16>, f64) {
    let t0 = Instant::now();
    let mut hits = Vec::new();
    for k in 0u16..=0xFFFF {
        if saes_encrypt(plaintext, k) == ciphertext {
            hits.push(k);
        }
    }
    (hits, t0.elapsed().as_secs_f64())
}

fn saes_exhaustive_parallel(plaintext: u16, ciphertext: u16) -> (Vec<u16>, f64) {
    let t0 = Instant::now();
    let mut hits: Vec<u16> = (0u32..=0xFFFF)
        .into_par_iter()
        .filter_map(|k| {
            let k = k as u16;
            if saes_encrypt(plaintext, k) == ciphertext {
                Some(k)
            } else {
                None
            }
        })
        .collect();
    hits.sort_unstable();
    (hits, t0.elapsed().as_secs_f64())
}

fn mitm_double(plaintext: u16, ciphertext: u16) -> (Vec<(u16, u16)>, u64, f64) {
    let t0 = Instant::now();
    let mut by_middle = vec![Vec::new(); 0x10000];
    let mut enc_calls = 0u64;
    for ka in 0u16..=0xFFFF {
        let x = saes_encrypt(plaintext, ka);
        by_middle[x as usize].push(ka);
        enc_calls += 1;
    }
    let mut hits = Vec::new();
    for kb in 0u16..=0xFFFF {
        let xp = saes_decrypt(ciphertext, kb);
        enc_calls += 1;
        for &ka in &by_middle[xp as usize] {
            hits.push((ka, kb));
        }
    }
    let secs = t0.elapsed().as_secs_f64();
    assert!(!hits.is_empty(), "MITM found no (KA, KB)");
    (hits, enc_calls, secs)
}

fn exhaustive_rate(plaintext: u16, trials: u64) -> f64 {
    let t0 = Instant::now();
    let mut acc = 0u16;
    for i in 0..trials {
        let ka = (i & 0xFFFF) as u16;
        let kb = ((i >> 16) & 0xFFFF) as u16;
        acc ^= double_encrypt(plaintext, ka, kb);
    }
    black_box(acc);
    t0.elapsed().as_secs_f64()
}

/// Same 2^32 `double_encrypt` trials as `exhaustive_rate`, split across Rayon threads.
fn exhaustive_rate_parallel(plaintext: u16, trials: u64) -> f64 {
    let nthreads = rayon::current_num_threads() as u64;
    let chunk = trials.div_ceil(nthreads);
    let t0 = Instant::now();
    let acc: u16 = (0..nthreads)
        .into_par_iter()
        .map(|t| {
            let start = t * chunk;
            let end = (start + chunk).min(trials);
            let mut local = 0u16;
            for i in start..end {
                let ka = (i & 0xFFFF) as u16;
                let kb = ((i >> 16) & 0xFFFF) as u16;
                local ^= double_encrypt(plaintext, ka, kb);
            }
            local
        })
        .reduce(|| 0, |a, b| a ^ b);
    black_box(acc);
    t0.elapsed().as_secs_f64()
}

fn main() {
    let p = 0x6F6Bu16;
    let k = 0xA73Bu16;
    let c_saes = 0x0738u16;
    assert_eq!(saes_encrypt(p, k), c_saes);
    assert_eq!(saes_decrypt(c_saes, k), p);

    let ka = 0xA73Bu16;
    let kb = 0x1337u16;
    let c_double = double_encrypt(p, ka, kb);
    assert_eq!(c_double, 0xD62C);
    assert_eq!(saes_decrypt(saes_decrypt(c_double, kb), ka), p);

    let nthreads = rayon::current_num_threads();
    println!("S-AES and Double S-AES (Rust, release)");
    println!("  S-AES [2]     P={p:04X}  K={k:04X}  C={c_saes:04X}");
    println!("  Double S-AES  P={p:04X}  KA={ka:04X}  KB={kb:04X}  C={c_double:04X}");
    println!("  Rayon threads {nthreads}");
    println!();

    let (saes_hits, saes_s) = saes_exhaustive(p, c_saes);
    let (saes_hits_par, saes_par_s) = saes_exhaustive_parallel(p, c_saes);
    println!("S-AES exhaustive  (2^16 master keys)");
    println!("  hits on one pair     {}", saes_hits.len());
    println!("  published K in list  {}", saes_hits.contains(&k));
    println!("  time, one core       {saes_s:.6} s");
    println!("  time, {nthreads} cores      {saes_par_s:.6} s");
    println!("  per trial (1 core)   {:.2} ns", saes_s / 65536.0 * 1e9);
    println!(
        "  parallel hits match  {}",
        saes_hits_par.len() == saes_hits.len()
    );
    println!();

    let (hits, mitm_ops, mitm_s) = mitm_double(p, c_double);
    let found = hits.iter().any(|&(a, b)| a == ka && b == kb);
    println!("Double S-AES MITM  (2^16 + 2^16 = 2^17 S-AES calls)");
    println!("  candidates on one pair  {}", hits.len());
    println!("  true (KA, KB) in list   {found}");
    println!("  operations {mitm_ops}");
    println!("  time       {mitm_s:.4} s");
    println!();

    let full: u64 = 1u64 << 32;
    println!("Double S-AES exhaustive FULL 2^32 (every trial)");
    let full_s = exhaustive_rate(p, full);
    println!("  time, one core       {full_s:.2} s  ({:.2} min)", full_s / 60.0);
    println!("  per trial (1 core)   {:.2} ns", (full_s / full as f64) * 1e9);
    let full_par_s = exhaustive_rate_parallel(p, full);
    println!(
        "  time, {nthreads} cores      {full_par_s:.2} s  ({:.2} min)",
        full_par_s / 60.0
    );
    println!(
        "  per trial ({nthreads} cores)  {:.2} ns",
        (full_par_s / full as f64) * 1e9
    );
    println!("  speedup              {:.2}x", full_s / full_par_s);
    println!();

    println!("Compare (this Rust CPU run)");
    println!("  S-AES 2^16, one core           {saes_s:.6} s");
    println!("  S-AES 2^16, {nthreads} cores          {saes_par_s:.6} s");
    println!("  Double MITM 2^17               {mitm_s:.4} s");
    println!("  Double exhaustive 2^32, 1 core {full_s:.2} s");
    println!("  Double exhaustive 2^32, {nthreads} cores {full_par_s:.2} s");
    println!(
        "  2^32 / 2^16                    {:.0}x more trials",
        (1u64 << 32) as f64 / (1u64 << 16) as f64
    );
}
