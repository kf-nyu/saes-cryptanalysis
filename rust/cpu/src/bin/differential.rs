//! Differential cryptanalysis of S-AES [2], from the S-box.
//! Same first-round characteristic and last-round peel as python/differential.py.

use std::time::Instant;

const SBOX: [u8; 16] = [
    0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7,
];
const INV_SBOX: [u8; 16] = [
    0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE,
];

const DELTA_P: u16 = 0x1000;
const DELTA_X: u16 = 0xD100;
const N_PAIRS: usize = 32;

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

fn invert_from_k2(k2: u16) -> u16 {
    let w4 = ((k2 >> 8) & 0xFF) as u8;
    let w5 = (k2 & 0xFF) as u8;
    let w3 = w5 ^ w4;
    let w2 = w4 ^ (sub_nibble(rot_nibble(w3)) ^ 0x30);
    let w1 = w3 ^ w2;
    let w0 = w2 ^ (sub_nibble(rot_nibble(w1)) ^ 0x80);
    ((w0 as u16) << 8) | (w1 as u16)
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

fn saes_encrypt(plaintext: u16, key: u16) -> u16 {
    let (k0, k1, k2) = key_expansion(key);
    encrypt_round2(encrypt_round1(plaintext ^ k0, k1), k2)
}

fn double_encrypt(plaintext: u16, ka: u16, kb: u16) -> u16 {
    saes_encrypt(saes_encrypt(plaintext, ka), kb)
}

fn ddt_max() -> u8 {
    let mut table = [[0u8; 16]; 16];
    for x in 0..16u8 {
        for din in 0..16u8 {
            let dout = SBOX[x as usize] ^ SBOX[(x ^ din) as usize];
            table[din as usize][dout as usize] += 1;
        }
    }
    let mut mx = 0u8;
    for din in 1..16 {
        for dout in 0..16 {
            mx = mx.max(table[din][dout]);
        }
    }
    mx
}

fn chosen_pairs<F: Fn(u16) -> u16>(n: usize, delta: u16, encrypt: F) -> Vec<(u16, u16, u16, u16)> {
    let mut pairs = Vec::with_capacity(n);
    let mut used = [false; 0x10000];
    let mut i = 0u32;
    while pairs.len() < n {
        // Walk the 16-bit space so the active nibble takes many values.
        let p = (i.wrapping_mul(0x9E37) & 0xFFFF) as u16;
        i += 1;
        let q = p ^ delta;
        if used[p as usize] || used[q as usize] {
            continue;
        }
        used[p as usize] = true;
        used[q as usize] = true;
        pairs.push((p, encrypt(p), q, encrypt(q)));
    }
    pairs
}

fn score_k2(pairs: &[(u16, u16, u16, u16)], delta_x: u16) -> Vec<u16> {
    let mut scores = vec![0u16; 0x10000];
    for &(_, c, _, cc) in pairs {
        for k2 in 0u16..=0xFFFF {
            if decrypt_round2(c, k2) ^ decrypt_round2(cc, k2) == delta_x {
                scores[k2 as usize] += 1;
            }
        }
    }
    scores
}

fn recover(scores: &[u16]) -> (u16, usize, Option<u16>) {
    let top = *scores.iter().max().unwrap();
    let winners: Vec<u16> = scores
        .iter()
        .enumerate()
        .filter_map(|(k2, &s)| if s == top { Some(k2 as u16) } else { None })
        .collect();
    let mut recovered = None;
    for k2 in &winners {
        let cand = invert_from_k2(*k2);
        if saes_encrypt(0x6F6B, cand) == 0x0738 {
            recovered = Some(cand);
            break;
        }
    }
    (top, winners.len(), recovered)
}

fn main() {
    assert_eq!(ddt_max(), 4);
    let k = 0xA73Bu16;
    let (_, _, k2_true) = key_expansion(k);
    assert_eq!(invert_from_k2(k2_true), k);
    assert_eq!(saes_encrypt(0x6F6B, k), 0x0738);

    println!("S-AES differential (Rust, release)");
    println!("  DDT max (Δin ≠ 0)     4/16");
    println!("  characteristic        ΔP={DELTA_P:04X} → ΔX={DELTA_X:04X}  p=4/16");
    println!("  secret K              {k:04X}   (K2={k2_true:04X})");
    println!("  chosen pairs          {N_PAIRS}  ({} plaintexts)", 2 * N_PAIRS);
    println!();

    let t0 = Instant::now();
    let pairs = chosen_pairs(N_PAIRS, DELTA_P, |p| saes_encrypt(p, k));
    let scores = score_k2(&pairs, DELTA_X);
    let (top, nw, recovered) = recover(&scores);
    let dc_s = t0.elapsed().as_secs_f64();

    println!("Last-round score (S-AES)");
    println!("  true K2 score         {} / {N_PAIRS}", scores[k2_true as usize]);
    println!("  max score             {top}  ({nw} keys)");
    match recovered {
        Some(r) => println!("  recovered K           {r:04X}"),
        None => println!("  recovered K           none"),
    }
    println!("  time                  {dc_s:.4} s");
    println!();

    let ka = 0xA73Bu16;
    let kb = 0x1337u16;
    let (_, _, kb2) = key_expansion(kb);
    let t1 = Instant::now();
    let dpairs = chosen_pairs(N_PAIRS, DELTA_P, |p| double_encrypt(p, ka, kb));
    let dscores = score_k2(&dpairs, DELTA_X);
    let dtop = *dscores.iter().max().unwrap();
    let dnw = dscores.iter().filter(|&&s| s == dtop).count();
    let double_s = t1.elapsed().as_secs_f64();

    println!("Same peel on Double S-AES (outer last round)");
    println!("  true outer K2 score   {} / {N_PAIRS}", dscores[kb2 as usize]);
    println!("  max score             {dtop}  ({dnw} keys)");
    if dscores[kb2 as usize] < dtop {
        println!("  true outer key ranked  no");
    } else {
        println!("  true outer key ranked  tied at max");
    }
    println!("  time                  {double_s:.4} s");
    println!();
    println!("Compare");
    println!(
        "  S-AES DC              {dc_s:.4} s   recovered={}",
        recovered == Some(k)
    );
    println!("  Double S-AES DC       does not isolate (KA, KB); MITM is the right tool");
}
