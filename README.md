# Exhaustive search, MITM, and differential cryptanalysis of S-AES

## Summary

This repo times **exhaustive search** and **meet-in-the-middle (MITM)** on S-AES [1] and Double S-AES, plus a short **differential** check on S-AES. The same searches are implemented in **Python**, **Rust**, and **C++**, on **CPU** and on **GPU**.

S-AES is a 16-bit block cipher with a 16-bit key (including the initial AddRoundKey). Double S-AES is that cipher run twice, with two independent keys:

$$
C = \mathrm{SAES}_{K_B}(\mathrm{SAES}_{K_A}(P)).
$$

| symbol | meaning |
|---|---|
| P | plaintext (16-bit block we encrypt) |
| K | S-AES master key (16-bit) |
| C | ciphertext (16-bit block we observe) |
| K<sub>A</sub> | first Double S-AES key (encrypts P) |
| K<sub>B</sub> | second Double S-AES key (encrypts the inner result) |

Check values used everywhere:

- S-AES [1]: P = 6F6B<sub>16</sub>, K = A73B<sub>16</sub>, C = 0738<sub>16</sub>
- Double S-AES: P = 6F6B<sub>16</sub>, K<sub>A</sub> = A73B<sub>16</sub>, K<sub>B</sub> = 1337<sub>16</sub>, C = D62C<sub>16</sub>

On one pair, exhaustive S-AES finds **2** keys (A73B is one). Double S-AES MITM and full 2<sup>32</sup> search both report **64,894** (K<sub>A</sub>, K<sub>B</sub>) hits.

## Folder layout

Four top-level folders. CPU / wgpu / Metal sit under the language that hosts them. The shared GPU kernel is under `metal/`.

```
saes-study/
├── python/
│   ├── cpu/                 S-AES, MITM, scaled 2^32, differential (CPU)
│   └── metal/               Python host for metal/saes.metal (PyObjC [9])
├── rust/
│   ├── cpu/                 one core and all cores (Rayon [5])
│   ├── wgpu/                GPU via wgpu [6] (WGSL [8])
│   └── metal/               GPU host for metal/saes.metal
├── cpp/
│   ├── cpu/                 one core, std::thread, and oneTBB [10]
│   └── metal/               GPU host for metal/saes.metal
└── metal/
    └── saes.metal           shared Metal shader [7]
```

`python/metal`, `rust/metal`, and `cpp/metal` are three hosts. They load the same shader. They do not start each other. The cipher search on GPU is in `metal/saes.metal`, not in the Python host.

## Shader

A shader is a small program that runs on the GPU. The host only loads it, passes P and C, and starts many threads.

`metal/saes.metal` (`exhaustive_saes`): one thread per 16-bit key (2<sup>16</sup>). `exhaustive`: one thread per K<sub>A</sub>, that thread tries every K<sub>B</sub> (2<sup>32</sup>).

`rust/wgpu` uses a second shader, `rust/wgpu/src/shader.wgsl`. Same search, different language. That is why wgpu and native Metal are two rows.

## How to run

Python CPU:

```bash
python python/cpu/saes.py
python python/cpu/differential.py
```

Python Metal host (not the C++ binary):

```bash
python3 -m venv python/.venv
python/.venv/bin/pip install -r python/requirements-metal.txt
python/.venv/bin/python python/metal/saes_metal.py
```

Rust:

```bash
cd rust/cpu && cargo run --release --bin double_mini_crack
cd rust/cpu && cargo run --release --bin differential
cd rust/wgpu && cargo run --release
cd rust/metal && cargo run --release
```

C++:

```bash
brew install tbb
cd cpp && make cpu && ./cpu/saes_cpu
cd cpp && make gpu && ./metal/saes_gpu
```

## Measured times

<small>Times below are from one MacBook Pro, M4 Max, 48 GB RAM.</small>

S-AES list: 2<sup>16</sup> = 65536 keys. Double S-AES list: 2<sup>32</sup> = 4294967296 pairs (K<sub>A</sub>, K<sub>B</sub>). Python 2<sup>32</sup> is a scaled estimate, not a full run.

| | S-AES 2<sup>16</sup> | Double MITM 2<sup>17</sup> | Double exhaustive 2<sup>32</sup> |
|---|---|---|---|
| Python CPU | 0.27 s (full) | 0.57 s | ~10.4 h (scaled) |
| Python host + Metal shader | 0.00057 s (full) | — | 0.18 s (full) |
| Rust CPU, 1 core | 0.00062 s (full) | 0.0059 s | 21.47 s (full) |
| Rust CPU, 16 cores | 0.00077 s (full) | — | 1.99 s (full) |
| Rust wgpu | 0.0014 s (full) | — | 1.13 s (full) |
| Rust Metal | 0.0017 s (full) | — | 0.18 s (full) |
| C++ CPU, 1 core | 0.0013 s (full) | 0.012 s | 72.03 s (full) |
| C++ CPU, 16 cores | 0.00052 s (full) | — | 6.56 s (full) |
| C++ Metal | 0.00027 s (full) | — | 0.18 s (full) |

C++ Metal, Rust Metal, and the Python Metal host all finished full 2<sup>32</sup> in 0.18 s (same `metal/saes.metal`). Rust wgpu was 1.13 s. Rust 16-core CPU was 1.99 s vs 21.47 s on one core. C++ 16-core was 6.56 s vs 72.03 s. The CPU 2<sup>32</sup> runs print 64,894 hits.

2<sup>16</sup> is short enough that launch cost can dominate. Multi-core and GPU matter on 2<sup>32</sup>.

A two-round MITM that treats K<sub>1</sub> and K<sub>2</sub> as independent does not apply to S-AES as written, because the first half also uses K<sub>0</sub> = K. That does not raise the master-key space above 2<sup>16</sup>.

## Differential cryptanalysis

Tables below are computed from the S-box, not copied from [1]. The attack is the last-round peel of Biham and Shamir [2].

The 4-bit S-box DDT has maximum 4 (for a nonzero input difference), so the best one-nibble S-box differential has probability 4/16 = 2<sup>-2</sup>. After ShiftRows and MixColumns, that is a first-round characteristic

$$
\Delta P = \mathrm{1000}_{16} \longrightarrow \Delta X = \mathrm{D100}_{16}
$$

with probability 1/4. K<sub>0</sub> and K<sub>1</sub> cancel in the difference. The last round is peeled with a guess of K<sub>2</sub>; the key schedule is then inverted and checked on the published pair

$$
\mathrm{6F6B}_{16} \mapsto \mathrm{0738}_{16}.
$$

32 chosen pairs (64 plaintexts), secret K = A73B<sub>16</sub>:

| | S-AES recovered? | true K<sub>2</sub> score | time |
|---|---|---|---|
| Python | yes (A73B) | 7/32 | 2.52 s |
| Rust, one CPU core | yes (A73B) | 7/32 | 0.0022 s |

256 values of K<sub>2</sub> tied at score 7; the published pair isolates the master key. Exhaustive 2<sup>16</sup> is still faster on this cipher (0.00062 s Rust): the differential loop also visits 2<sup>16</sup> last-round keys, once per pair. A GPU does not help.

The same 32 pairs and the same last-round peel on Double S-AES (K<sub>A</sub> = A73B<sub>16</sub>, K<sub>B</sub> = 1337<sub>16</sub>) give the true outer K<sub>2</sub> a score of 0. The inner S-AES randomizes the difference, so the first-round characteristic does not arrive at the outer last round. Two-round S-AES differentials exist at p = 2<sup>-6</sup>; they do not make Double S-AES easier than MITM (2<sup>17</sup>, one pair).

[1] studies linear and differential attacks on S-AES. AES-128 [4] has ten rounds and an 8-bit S-box whose best differential probability is 2<sup>-6</sup>; that is why a differential attack on AES-128 is a research problem and exhaustive search is not a substitute.

## AES-128: practical to use; exhaustive search is not

AES-128 is practical to **use**. Exhaustive **search** of AES-128 is not practical on this machine.

AES-128 has 2<sup>128</sup> keys. That is 2<sup>96</sup> times the measured Double S-AES 2<sup>32</sup> runs on the same machine:

$$
21.47 \times 2^{96}\ \mathrm{s} \approx 5.4 \times 10^{22}\ \mathrm{years}\ (\mathrm{one\ Rust\ CPU\ core})
$$

$$
0.18 \times 2^{96}\ \mathrm{s} \approx 4.5 \times 10^{20}\ \mathrm{years}\ (\mathrm{native\ Metal})
$$

Those figures treat one AES-128 encryption as no more work than one Double S-AES trial. A real AES-128 trial is heavier (ten rounds, 128-bit state), so the search would take longer, not shorter. A ~119× native-Metal speedup vs one Rust CPU core is a constant. It does not turn 2<sup>128</sup> into 2<sup>32</sup>.

## S-AES vs Double S-AES vs AES-128

| | master key | exhaustive list | on this machine |
|---|---|---|---|
| S-AES [1] | 16-bit K | 2<sup>16</sup> | 0.00062 s Rust CPU, 0.00027 s C++ Metal; DC 0.0022 s CPU |
| Double S-AES | 16-bit K<sub>A</sub> and 16-bit K<sub>B</sub> | 2<sup>32</sup> | 21.47 s Rust CPU, 0.18 s native Metal; MITM 0.0059 s; DC does not isolate |
| AES-128 [4] | 128-bit K | 2<sup>128</sup> | ≈ 5.4 × 10<sup>22</sup> y CPU, ≈ 4.5 × 10<sup>20</sup> y native Metal (scaled from 2<sup>32</sup>) |

Double S-AES is two independent 16-bit S-AES keys in a row. MITM on that composition is 2<sup>17</sup> operations, not 2<sup>32</sup> [3]. Two short ciphers in a row do not give 32-bit security against MITM (2DES at this size).

## References

[1] M. A. Musa, E. F. Schaefer, and S. Wedig, “A Simplified AES Algorithm and Its Linear and Differential Cryptanalyses,” *Cryptologia*, vol. 27, no. 2, pp. 148–177, 2003. https://doi.org/10.1080/0161-110391891838

[2] E. Biham and A. Shamir, “Differential Cryptanalysis of DES-like Cryptosystems,” *Journal of Cryptology*, vol. 4, no. 1, pp. 3–72, 1991. https://doi.org/10.1007/BF00630563

[3] W. Diffie and M. E. Hellman, “Exhaustive Cryptanalysis of the NBS Data Encryption Standard,” *Computer*, vol. 10, no. 6, pp. 74–84, 1977. https://doi.org/10.1109/C-M.1977.217750

[4] National Institute of Standards and Technology, *Advanced Encryption Standard (AES)*, FIPS PUB 197, 2001. https://doi.org/10.6028/NIST.FIPS.197

[5] N. Matsakis and the Rayon contributors, *Rayon: A data parallelism library for Rust*. https://github.com/rayon-rs/rayon

[6] gfx-rs, *wgpu: Cross-platform, safe GPU API in Rust* (WebGPU in Rust). https://wgpu.rs https://github.com/gfx-rs/wgpu

[7] Apple Inc., *Metal Shading Language Specification*. https://developer.apple.com/metal/Metal-Shading-Language-Specification.pdf

[8] World Wide Web Consortium, *WebGPU Shading Language (WGSL)*, W3C. https://www.w3.org/TR/WGSL/

[9] Ronald Oussoren and contributors, *PyObjC: Python bindings for the Objective-C runtime* (including Metal). https://pyobjc.readthedocs.io/

[10] Intel Corporation, *oneAPI Threading Building Blocks (oneTBB)*. https://github.com/uxlfoundation/oneTBB
