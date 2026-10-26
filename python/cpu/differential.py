"""Differential cryptanalysis of S-AES [2], from the S-box (not copied tables).

First-round characteristic: one active nibble, DDT entry 4/16.
Peel the last round, score K2, invert the key schedule, check a known pair.
The same pairs through Double S-AES do not rank the outer key.
"""

from __future__ import annotations

import time

from saes import (
    SBOX,
    decrypt_round2,
    double_encrypt,
    key_expansion,
    rot_nibble,
    saes_encrypt,
    sub_nibble,
)

# One-nibble first-round characteristic (computed from the DDT + MixColumns).
DELTA_P = 0x1000
DELTA_X = 0xD100  # after SubNibbles, ShiftRows, MixColumns; K1 cancels
CHAR_NUM, CHAR_DEN = 4, 16


def ddt() -> list[list[int]]:
    table = [[0] * 16 for _ in range(16)]
    for x in range(16):
        for din in range(16):
            table[din][SBOX[x] ^ SBOX[x ^ din]] += 1
    return table


def invert_from_k2(k2: int) -> int:
    w4, w5 = (k2 >> 8) & 0xFF, k2 & 0xFF
    w3 = w5 ^ w4
    w2 = w4 ^ (sub_nibble(rot_nibble(w3)) ^ 0x30)
    w1 = w3 ^ w2
    w0 = w2 ^ (sub_nibble(rot_nibble(w1)) ^ 0x80)
    return (w0 << 8) | w1


def chosen_pairs(n: int, delta: int, encrypt) -> list[tuple[int, int, int, int]]:
    pairs = []
    used = set()
    i = 0
    while len(pairs) < n:
        # Walk the 16-bit space so the active nibble takes many values.
        p = (i * 0x9E37) & 0xFFFF
        i += 1
        q = p ^ delta
        if p in used or q in used:
            continue
        used.add(p)
        used.add(q)
        pairs.append((p, encrypt(p), q, encrypt(q)))
    return pairs


def score_k2(pairs: list[tuple[int, int, int, int]], delta_x: int) -> list[int]:
    scores = [0] * 0x10000
    for _, c, __, cc in pairs:
        for k2 in range(0x10000):
            if decrypt_round2(c, k2) ^ decrypt_round2(cc, k2) == delta_x:
                scores[k2] += 1
    return scores


def main() -> None:
    table = ddt()
    max_off = max(table[i][j] for i in range(1, 16) for j in range(16))
    assert table[0x1][0xD] == 4
    assert max_off == 4

    k = 0xA73B
    _, _, k2_true = key_expansion(k)
    assert invert_from_k2(k2_true) == k
    assert saes_encrypt(0x6F6B, k) == 0x0738

    n_pairs = 32
    print("S-AES differential (Python)")
    print(f"  DDT max (Δin ≠ 0)     {max_off}/16")
    print(f"  characteristic        ΔP={DELTA_P:04X} → ΔX={DELTA_X:04X}  p={CHAR_NUM}/{CHAR_DEN}")
    print(f"  secret K              {k:04X}   (K2={k2_true:04X})")
    print(f"  chosen pairs          {n_pairs}  ({2 * n_pairs} plaintexts)")
    print()

    t0 = time.perf_counter()
    pairs = chosen_pairs(n_pairs, DELTA_P, lambda p: saes_encrypt(p, k))
    scores = score_k2(pairs, DELTA_X)
    top = max(scores)
    winners = [k2 for k2, s in enumerate(scores) if s == top]
    recovered = None
    for k2 in winners:
        cand = invert_from_k2(k2)
        if saes_encrypt(0x6F6B, cand) == 0x0738:
            recovered = cand
            break
    dc_s = time.perf_counter() - t0

    print("Last-round score (S-AES)")
    print(f"  true K2 score         {scores[k2_true]} / {n_pairs}")
    print(f"  max score             {top}  ({len(winners)} keys)")
    print(f"  recovered K           {recovered:04X}" if recovered is not None else "  recovered K           none")
    print(f"  time                  {dc_s:.4f} s")
    print()

    ka, kb = 0xA73B, 0x1337
    _, _, kb2 = key_expansion(kb)
    t1 = time.perf_counter()
    dpairs = chosen_pairs(n_pairs, DELTA_P, lambda p: double_encrypt(p, ka, kb))
    dscores = score_k2(dpairs, DELTA_X)
    dtop = max(dscores)
    double_s = time.perf_counter() - t1
    print("Same peel on Double S-AES (outer last round)")
    print(f"  true outer K2 score   {dscores[kb2]} / {n_pairs}")
    print(f"  max score             {dtop}  ({sum(1 for s in dscores if s == dtop)} keys)")
    print("  true outer key ranked  no" if dscores[kb2] < dtop else "  true outer key ranked  tied at max")
    print(f"  time                  {double_s:.4f} s")
    print()
    print("Compare")
    print(f"  S-AES DC              {dc_s:.4f} s   recovered={recovered == k}")
    print("  Double S-AES DC       does not isolate (KA, KB); MITM is the right tool")


if __name__ == "__main__":
    main()
