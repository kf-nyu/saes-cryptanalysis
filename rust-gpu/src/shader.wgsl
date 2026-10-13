const SBOX = array<u32, 16>(9u, 4u, 10u, 11u, 13u, 1u, 8u, 5u, 6u, 2u, 0u, 3u, 12u, 14u, 15u, 7u);

fn gf_mul(a_in: u32, b_in: u32) -> u32 {
    var a = a_in & 15u;
    var b = b_in & 15u;
    var product = 0u;
    for (var i = 0u; i < 4u; i++) {
        if ((b & 1u) == 1u) {
            product ^= a;
        }
        let carry = a & 8u;
        a = (a << 1u) & 15u;
        if (carry != 0u) {
            a ^= 3u;
        }
        b >>= 1u;
    }
    return product;
}

fn rot_nibble(byte: u32) -> u32 {
    return ((byte << 4u) | (byte >> 4u)) & 255u;
}

fn sub_nibble(byte: u32) -> u32 {
    let hi = SBOX[(byte >> 4u) & 15u];
    let lo = SBOX[byte & 15u];
    return (hi << 4u) | lo;
}

fn key_expansion(key: u32) -> vec3<u32> {
    let w0 = (key >> 8u) & 255u;
    let w1 = key & 255u;
    let w2 = w0 ^ (sub_nibble(rot_nibble(w1)) ^ 128u);
    let w3 = w1 ^ w2;
    let w4 = w2 ^ (sub_nibble(rot_nibble(w3)) ^ 48u);
    let w5 = w3 ^ w4;
    let k0 = (w0 << 8u) | w1;
    let k1 = (w2 << 8u) | w3;
    let k2 = (w4 << 8u) | w5;
    return vec3<u32>(k0, k1, k2);
}

fn nibble(word: u32, i: u32) -> u32 {
    return (word >> (12u - 4u * i)) & 15u;
}

fn pack(n0: u32, n1: u32, n2: u32, n3: u32) -> u32 {
    return (n0 << 12u) | (n1 << 8u) | (n2 << 4u) | n3;
}

fn substitute(word: u32) -> u32 {
    return pack(
        SBOX[nibble(word, 0u)],
        SBOX[nibble(word, 1u)],
        SBOX[nibble(word, 2u)],
        SBOX[nibble(word, 3u)],
    );
}

fn shift_rows(word: u32) -> u32 {
    return pack(nibble(word, 0u), nibble(word, 3u), nibble(word, 2u), nibble(word, 1u));
}

fn mix_columns(word: u32, a: u32, b: u32) -> u32 {
    let n0 = nibble(word, 0u);
    let n1 = nibble(word, 1u);
    let n2 = nibble(word, 2u);
    let n3 = nibble(word, 3u);
    return pack(
        gf_mul(a, n0) ^ gf_mul(b, n1),
        gf_mul(b, n0) ^ gf_mul(a, n1),
        gf_mul(a, n2) ^ gf_mul(b, n3),
        gf_mul(b, n2) ^ gf_mul(a, n3),
    );
}

fn saes_encrypt(plaintext: u32, key: u32) -> u32 {
    let ks = key_expansion(key);
    let x = mix_columns(shift_rows(substitute(plaintext ^ ks.x)), 1u, 4u) ^ ks.y;
    return shift_rows(substitute(x)) ^ ks.z;
}

fn double_encrypt(plaintext: u32, ka: u32, kb: u32) -> u32 {
    return saes_encrypt(saes_encrypt(plaintext, ka), kb);
}

struct Params {
    p: u32,
    c: u32,
}

struct Out {
    hits: atomic<u32>,
    found_packed: atomic<u32>,
}

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read_write> outb: Out;

// One thread per 16-bit master key. Total 2^16.
@compute @workgroup_size(256)
fn exhaustive_saes(@builtin(global_invocation_id) gid: vec3<u32>) {
    let k = gid.x;
    if (k >= 65536u) {
        return;
    }
    if (saes_encrypt(params.p, k) == params.c) {
        atomicAdd(&outb.hits, 1u);
        atomicStore(&outb.found_packed, k);
    }
}

// 65536 threads (one KA each). Each thread tries all 65536 KB. Total 2^32.
@compute @workgroup_size(256)
fn exhaustive(@builtin(global_invocation_id) gid: vec3<u32>) {
    let ka = gid.x;
    if (ka >= 65536u) {
        return;
    }
    let p = params.p;
    let c = params.c;
    for (var kb = 0u; kb < 65536u; kb++) {
        if (double_encrypt(p, ka, kb) == c) {
            atomicAdd(&outb.hits, 1u);
            atomicStore(&outb.found_packed, (ka << 16u) | kb);
        }
    }
}
