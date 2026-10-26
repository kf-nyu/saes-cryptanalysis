// S-AES and Double S-AES, same as python/saes.py and rust-cpu.
// Each S-AES includes the initial AddRoundKey.

#pragma once

#include <cstdint>

inline constexpr uint8_t SBOX[16] = {
    0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7};
inline constexpr uint8_t INV_SBOX[16] = {
    0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE};

inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t product = 0;
    for (int i = 0; i < 4; ++i) {
        if (b & 1) {
            product ^= a;
        }
        uint8_t carry = a & 0x8;
        a = static_cast<uint8_t>((a << 1) & 0xF);
        if (carry) {
            a ^= 0b0011;
        }
        b >>= 1;
    }
    return product;
}

inline uint8_t rot_nibble(uint8_t byte) {
    return static_cast<uint8_t>(((byte << 4) | (byte >> 4)) & 0xFF);
}

inline uint8_t sub_nibble(uint8_t byte) {
    return static_cast<uint8_t>((SBOX[(byte >> 4) & 0xF] << 4) | SBOX[byte & 0xF]);
}

inline void key_expansion(uint16_t key, uint16_t& k0, uint16_t& k1, uint16_t& k2) {
    uint8_t w0 = static_cast<uint8_t>((key >> 8) & 0xFF);
    uint8_t w1 = static_cast<uint8_t>(key & 0xFF);
    uint8_t w2 = static_cast<uint8_t>(w0 ^ (sub_nibble(rot_nibble(w1)) ^ 0x80));
    uint8_t w3 = static_cast<uint8_t>(w1 ^ w2);
    uint8_t w4 = static_cast<uint8_t>(w2 ^ (sub_nibble(rot_nibble(w3)) ^ 0x30));
    uint8_t w5 = static_cast<uint8_t>(w3 ^ w4);
    k0 = static_cast<uint16_t>((w0 << 8) | w1);
    k1 = static_cast<uint16_t>((w2 << 8) | w3);
    k2 = static_cast<uint16_t>((w4 << 8) | w5);
}

inline uint8_t nibble(uint16_t word, int i) {
    return static_cast<uint8_t>((word >> (12 - 4 * i)) & 0xF);
}

inline uint16_t pack(uint8_t n0, uint8_t n1, uint8_t n2, uint8_t n3) {
    return static_cast<uint16_t>((n0 << 12) | (n1 << 8) | (n2 << 4) | n3);
}

inline uint16_t substitute(uint16_t word, const uint8_t box[16]) {
    return pack(box[nibble(word, 0)], box[nibble(word, 1)], box[nibble(word, 2)],
                box[nibble(word, 3)]);
}

inline uint16_t shift_rows(uint16_t word) {
    return pack(nibble(word, 0), nibble(word, 3), nibble(word, 2), nibble(word, 1));
}

inline uint16_t mix_columns(uint16_t word, uint8_t a, uint8_t b) {
    uint8_t n0 = nibble(word, 0);
    uint8_t n1 = nibble(word, 1);
    uint8_t n2 = nibble(word, 2);
    uint8_t n3 = nibble(word, 3);
    return pack(static_cast<uint8_t>(gf_mul(a, n0) ^ gf_mul(b, n1)),
                static_cast<uint8_t>(gf_mul(b, n0) ^ gf_mul(a, n1)),
                static_cast<uint8_t>(gf_mul(a, n2) ^ gf_mul(b, n3)),
                static_cast<uint8_t>(gf_mul(b, n2) ^ gf_mul(a, n3)));
}

inline uint16_t saes_encrypt(uint16_t plaintext, uint16_t key) {
    uint16_t k0, k1, k2;
    key_expansion(key, k0, k1, k2);
    uint16_t x = static_cast<uint16_t>(
        mix_columns(shift_rows(substitute(static_cast<uint16_t>(plaintext ^ k0), SBOX)), 1, 4) ^ k1);
    return static_cast<uint16_t>(shift_rows(substitute(x, SBOX)) ^ k2);
}

inline uint16_t saes_decrypt(uint16_t ciphertext, uint16_t key) {
    uint16_t k0, k1, k2;
    key_expansion(key, k0, k1, k2);
    uint16_t x = substitute(shift_rows(static_cast<uint16_t>(ciphertext ^ k2)), INV_SBOX);
    return static_cast<uint16_t>(
        substitute(shift_rows(mix_columns(static_cast<uint16_t>(x ^ k1), 9, 2)), INV_SBOX) ^ k0);
}

inline uint16_t double_encrypt(uint16_t plaintext, uint16_t ka, uint16_t kb) {
    return saes_encrypt(saes_encrypt(plaintext, ka), kb);
}
