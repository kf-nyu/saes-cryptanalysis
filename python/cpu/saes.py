"""S-AES [2] and Double S-AES: exhaustive and MITM wall-clock benchmarks.
Each S-AES includes the initial AddRoundKey.
"""

from __future__ import annotations

import time

SBOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]
INV_SBOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE]


def gf_mul(a: int, b: int) -> int:
    product = 0
    for _ in range(4):
        if b & 1:
            product ^= a
        carry = a & 0x8
        a = (a << 1) & 0xF
        if carry:
            a ^= 0b0011
        b >>= 1
    return product


def rot_nibble(byte: int) -> int:
    return ((byte << 4) | (byte >> 4)) & 0xFF


def sub_nibble(byte: int) -> int:
    return (SBOX[(byte >> 4) & 0xF] << 4) | SBOX[byte & 0xF]


def key_expansion(key: int) -> tuple[int, int, int]:
    w0, w1 = (key >> 8) & 0xFF, key & 0xFF
    w2 = w0 ^ (sub_nibble(rot_nibble(w1)) ^ 0x80)
    w3 = w1 ^ w2
    w4 = w2 ^ (sub_nibble(rot_nibble(w3)) ^ 0x30)
    w5 = w3 ^ w4
    return ((w0 << 8) | w1, (w2 << 8) | w3, (w4 << 8) | w5)


def nibble(word: int, i: int) -> int:
    return (word >> (12 - 4 * i)) & 0xF


def pack(n0: int, n1: int, n2: int, n3: int) -> int:
    return (n0 << 12) | (n1 << 8) | (n2 << 4) | n3


def substitute(word: int, box: list[int]) -> int:
    return pack(box[nibble(word, 0)], box[nibble(word, 1)], box[nibble(word, 2)], box[nibble(word, 3)])


def shift(word: int) -> int:
    return pack(nibble(word, 0), nibble(word, 3), nibble(word, 2), nibble(word, 1))


def mix_columns(word: int, a: int, b: int) -> int:
    n0, n1, n2, n3 = nibble(word, 0), nibble(word, 1), nibble(word, 2), nibble(word, 3)
    return pack(
        gf_mul(a, n0) ^ gf_mul(b, n1),
        gf_mul(b, n0) ^ gf_mul(a, n1),
        gf_mul(a, n2) ^ gf_mul(b, n3),
        gf_mul(b, n2) ^ gf_mul(a, n3),
    )


def encrypt_round1(state: int, k1: int) -> int:
    return mix_columns(shift(substitute(state, SBOX)), 1, 4) ^ k1


def encrypt_round2(state: int, k2: int) -> int:
    return shift(substitute(state, SBOX)) ^ k2


def decrypt_round2(state: int, k2: int) -> int:
    return substitute(shift(state ^ k2), INV_SBOX)


def decrypt_round1(state: int, k1: int) -> int:
    return substitute(shift(mix_columns(state ^ k1, 9, 2)), INV_SBOX)


def saes_encrypt(plaintext: int, key: int) -> int:
    k0, k1, k2 = key_expansion(key)
    return encrypt_round2(encrypt_round1(plaintext ^ k0, k1), k2)


def saes_decrypt(ciphertext: int, key: int) -> int:
    k0, k1, k2 = key_expansion(key)
    return decrypt_round1(decrypt_round2(ciphertext, k2), k1) ^ k0


def double_encrypt(plaintext: int, ka: int, kb: int) -> int:
    return saes_encrypt(saes_encrypt(plaintext, ka), kb)


def saes_exhaustive(plaintext: int, ciphertext: int) -> tuple[list[int], float]:
    t0 = time.perf_counter()
    hits = [k for k in range(0x10000) if saes_encrypt(plaintext, k) == ciphertext]
    return hits, time.perf_counter() - t0


def mitm_double(plaintext: int, ciphertext: int) -> tuple[list[tuple[int, int]], int, float]:
    t0 = time.perf_counter()
    by_middle: list[list[int]] = [[] for _ in range(0x10000)]
    enc_calls = 0
    for ka in range(0x10000):
        x = saes_encrypt(plaintext, ka)
        by_middle[x].append(ka)
        enc_calls += 1
    hits: list[tuple[int, int]] = []
    for kb in range(0x10000):
        xp = saes_decrypt(ciphertext, kb)
        enc_calls += 1
        for ka in by_middle[xp]:
            hits.append((ka, kb))
    return hits, enc_calls, time.perf_counter() - t0


def exhaustive_rate(plaintext: int, trials: int) -> float:
    t0 = time.perf_counter()
    acc = 0
    for i in range(trials):
        ka = i & 0xFFFF
        kb = (i >> 16) & 0xFFFF
        acc ^= double_encrypt(plaintext, ka, kb)
    if acc == 0xFFFF:
        print("", end="")
    return time.perf_counter() - t0


def main() -> None:
    p, k = 0x6F6B, 0xA73B
    c_saes = 0x0738
    assert saes_encrypt(p, k) == c_saes
    assert saes_decrypt(c_saes, k) == p

    ka, kb = 0xA73B, 0x1337
    c_double = double_encrypt(p, ka, kb)
    assert c_double == 0xD62C
    assert saes_decrypt(saes_decrypt(c_double, kb), ka) == p

    print("S-AES and Double S-AES (Python)")
    print(f"  S-AES [2]     P={p:04X}  K={k:04X}  C={c_saes:04X}")
    print(f"  Double S-AES  P={p:04X}  KA={ka:04X}  KB={kb:04X}  C={c_double:04X}")
    print()

    saes_hits, saes_s = saes_exhaustive(p, c_saes)
    print("S-AES exhaustive  (2^16 master keys)")
    print(f"  hits on one pair   {len(saes_hits)}")
    print(f"  published K in list  {k in saes_hits}")
    print(f"  time               {saes_s:.4f} s")
    print(f"  per trial          {saes_s / 0x10000 * 1e9:.2f} ns")
    print()

    hits, mitm_ops, mitm_s = mitm_double(p, c_double)
    found = any(a == ka and b == kb for a, b in hits)
    print("Double S-AES MITM  (2^16 + 2^16 = 2^17 S-AES calls)")
    print(f"  candidates on one pair  {len(hits)}")
    print(f"  true (KA, KB) in list   {found}")
    print(f"  operations {mitm_ops}")
    print(f"  time       {mitm_s:.4f} s")
    print()

    sample = 1 << 18
    sample_s = exhaustive_rate(p, sample)
    per = sample_s / sample
    est = per * (1 << 32)
    print(f"Double S-AES exhaustive rate ({sample} trials, then scale to 2^32)")
    print(f"  sample time     {sample_s:.4f} s")
    print(f"  per trial       {per * 1e9:.2f} ns")
    print(f"  estimate 2^32   {est:.1f} s  ({est / 3600:.2f} h)")
    print()

    print("Compare (this Python run)")
    print(f"  S-AES 2^16              {saes_s:.4f} s")
    print(f"  Double MITM 2^17        {mitm_s:.4f} s")
    print(f"  Double exhaustive 2^32  {est:.1f} s  (scaled)")
    print(f"  2^32 / 2^16             {(1 << 32) / (1 << 16):.0f}x more trials")


if __name__ == "__main__":
    main()
