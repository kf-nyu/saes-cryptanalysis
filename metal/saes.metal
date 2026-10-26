#include <metal_stdlib>
using namespace metal;

constant uint SBOX[16] = {9u, 4u, 10u, 11u, 13u, 1u, 8u, 5u, 6u, 2u, 0u, 3u, 12u, 14u, 15u, 7u};

uint gf_mul(uint a_in, uint b_in) {
    uint a = a_in & 15u;
    uint b = b_in & 15u;
    uint product = 0u;
    for (uint i = 0u; i < 4u; i++) {
        if ((b & 1u) == 1u) {
            product ^= a;
        }
        uint carry = a & 8u;
        a = (a << 1u) & 15u;
        if (carry != 0u) {
            a ^= 3u;
        }
        b >>= 1u;
    }
    return product;
}

uint rot_nibble(uint byte) {
    return ((byte << 4u) | (byte >> 4u)) & 255u;
}

uint sub_nibble(uint byte) {
    uint hi = SBOX[(byte >> 4u) & 15u];
    uint lo = SBOX[byte & 15u];
    return (hi << 4u) | lo;
}

void key_expansion(uint key, thread uint& k0, thread uint& k1, thread uint& k2) {
    uint w0 = (key >> 8u) & 255u;
    uint w1 = key & 255u;
    uint w2 = w0 ^ (sub_nibble(rot_nibble(w1)) ^ 128u);
    uint w3 = w1 ^ w2;
    uint w4 = w2 ^ (sub_nibble(rot_nibble(w3)) ^ 48u);
    uint w5 = w3 ^ w4;
    k0 = (w0 << 8u) | w1;
    k1 = (w2 << 8u) | w3;
    k2 = (w4 << 8u) | w5;
}

uint nibble(uint word, uint i) {
    return (word >> (12u - 4u * i)) & 15u;
}

uint pack(uint n0, uint n1, uint n2, uint n3) {
    return (n0 << 12u) | (n1 << 8u) | (n2 << 4u) | n3;
}

uint substitute(uint word) {
    return pack(SBOX[nibble(word, 0u)], SBOX[nibble(word, 1u)], SBOX[nibble(word, 2u)],
                SBOX[nibble(word, 3u)]);
}

uint shift_rows(uint word) {
    return pack(nibble(word, 0u), nibble(word, 3u), nibble(word, 2u), nibble(word, 1u));
}

uint mix_columns(uint word, uint a, uint b) {
    uint n0 = nibble(word, 0u);
    uint n1 = nibble(word, 1u);
    uint n2 = nibble(word, 2u);
    uint n3 = nibble(word, 3u);
    return pack(gf_mul(a, n0) ^ gf_mul(b, n1), gf_mul(b, n0) ^ gf_mul(a, n1),
                gf_mul(a, n2) ^ gf_mul(b, n3), gf_mul(b, n2) ^ gf_mul(a, n3));
}

uint saes_encrypt(uint plaintext, uint key) {
    uint k0, k1, k2;
    key_expansion(key, k0, k1, k2);
    uint x = mix_columns(shift_rows(substitute(plaintext ^ k0)), 1u, 4u) ^ k1;
    return shift_rows(substitute(x)) ^ k2;
}

uint double_encrypt(uint plaintext, uint ka, uint kb) {
    return saes_encrypt(saes_encrypt(plaintext, ka), kb);
}

struct Params {
    uint p;
    uint c;
};

struct Out {
    atomic_uint hits;
    atomic_uint found_packed;
};

kernel void exhaustive_saes(uint gid [[thread_position_in_grid]],
                            constant Params& params [[buffer(0)]],
                            device Out& outb [[buffer(1)]]) {
    uint k = gid;
    if (k >= 65536u) {
        return;
    }
    if (saes_encrypt(params.p, k) == params.c) {
        atomic_fetch_add_explicit(&outb.hits, 1u, memory_order_relaxed);
        atomic_store_explicit(&outb.found_packed, k, memory_order_relaxed);
    }
}

kernel void exhaustive(uint gid [[thread_position_in_grid]],
                       constant Params& params [[buffer(0)]],
                       device Out& outb [[buffer(1)]]) {
    uint ka = gid;
    if (ka >= 65536u) {
        return;
    }
    uint p = params.p;
    uint c = params.c;
    for (uint kb = 0u; kb < 65536u; kb++) {
        if (double_encrypt(p, ka, kb) == c) {
            atomic_fetch_add_explicit(&outb.hits, 1u, memory_order_relaxed);
            atomic_store_explicit(&outb.found_packed, (ka << 16u) | kb, memory_order_relaxed);
        }
    }
}
