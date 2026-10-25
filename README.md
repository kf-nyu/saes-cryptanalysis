# Exhaustive search, MITM, and differential cryptanalysis of S-AES

S-AES [1] is a 16-bit block cipher with a 16-bit master key, including the initial AddRoundKey. Double S-AES is that cipher run twice, with independent keys $K\_A$ and $K\_B$:

$$
C = \mathrm{SAES}\_{K\_B}(\mathrm{SAES}\_{K\_A}(P)).
$$

This repo times exhaustive search of S-AES ($2^{16}$) against meet-in-the-middle and exhaustive search of Double S-AES ($2^{17}$ and $2^{32}$), and a differential attack on S-AES.

Published single-cipher check from [1]:

$$
P = \mathrm{6F6B}\_{16},\quad K = \mathrm{A73B}\_{16},\quad C = \mathrm{0738}\_{16}
$$

Double S-AES test vector used here:

$$
P = \mathrm{6F6B}\_{16},\quad K\_A = \mathrm{A73B}\_{16},\quad K\_B = \mathrm{1337}\_{16},\quad C = \mathrm{D62C}\_{16}
$$

## What is in here

| path | what it does |
|---|---|
| `python/saes.py` | S-AES $2^{16}$, Double MITM $2^{17}$, Double exhaustive **sample** (scale to $2^{32}$) |
| `python/differential.py` | S-box DDT, first-round characteristic, last-round key recovery |
| `rust-cpu/` | S-AES $2^{16}$, Double MITM $2^{17}$, **all** $2^{32}$ Double trials on one core and on all CPU cores (Rayon [5]) |
| `rust-cpu` `--bin differential` | same differential attack as the Python file |
| `rust-gpu/` | **all** $2^{16}$ S-AES and **all** $2^{32}$ Double trials on GPU (wgpu [6] → Metal) |

## How to run

Python:

```bash
python python/saes.py
python python/differential.py
```

Rust CPU (one core, then all cores via Rayon [5]; full $2^{32}$ on one core takes about one to two minutes):

```bash
cd rust-cpu && cargo run --release --bin double_mini_crack
cd rust-cpu && cargo run --release --bin differential
```

Cap threads with `RAYON_NUM_THREADS=4 cargo run --release --bin double_mini_crack` if you want a smaller run.

Rust + GPU (full $2^{16}$ and $2^{32}$, needs a wgpu [6] / Metal device):

```bash
cd rust-gpu && cargo run --release
```

## Measured times (MacBook Pro, M4 Max, 48 GB RAM)

S-AES exhaustive list: $2^{16} = 65536$ master keys.  
Double S-AES exhaustive list: $2^{32} = 4294967296$ pairs $(K\_A, K\_B)$.

| | S-AES $2^{16}$ | Double MITM $2^{17}$ | Double exhaustive $2^{32}$ |
|---|---|---|---|
| Python | 0.28 s (full) | 0.60 s | ~10.4 h (scaled, not a full run) |
| Rust, one CPU core | 0.00048 s (full) | 0.0040 s | 79.3 s (full) |
| Rust, all CPU cores (Rayon [5], 16) | 0.00040 s (full) | — | 4.50 s (full) |
| Rust + GPU (wgpu [6] / Metal) | 0.0013 s (full) | — | 1.13 s (full) |

On the published S-AES pair, exhaustive search found **2** keys (the published $K=\mathrm{A73B}\_{16}$ is one of them).  
On the Double S-AES pair, MITM and the GPU exhaustive run both reported **64,894** hits.

S-AES is crackable on a laptop CPU. A GPU is not required: the $2^{16}$ GPU run is slower than one Rust CPU core because launch overhead dominates a short list. Multi-core does not help $2^{16}$ either (0.00058 s one core vs 0.00040 s on 16 cores). The GPU helps on the $2^{32}$ Double list (~70× vs one Rust CPU core, ~4× vs 16 CPU cores). This machine's 16-core Rayon run was 4.50 s vs 78.46 s on one core (~17×).

A two-round MITM that treats $K\_1$ and $K\_2$ as independent does not apply to S-AES as written, because the first half also uses $K\_0=K$. That does not raise the master-key space above $2^{16}$.

## Differential cryptanalysis

Tables below are computed from the S-box, not copied from [1]. The attack is the last-round peel of Biham and Shamir [2].

The 4-bit S-box DDT has maximum $4$ (for $\Delta\_{\mathrm{in}}\neq 0$), so the best one-nibble S-box differential has probability $4/16=2^{-2}$. After ShiftRows and MixColumns, that is a first-round characteristic

$$
\Delta P = \mathrm{1000}\_{16} \longrightarrow \Delta X = \mathrm{D100}\_{16}
$$

with probability $1/4$. $K\_0$ and $K\_1$ cancel in the difference. The last round is peeled with a guess of $K\_2$; the key schedule is then inverted and checked on the published pair $\mathrm{6F6B}\_{16} \mapsto \mathrm{0738}\_{16}$.

32 chosen pairs (64 plaintexts), secret $K=\mathrm{A73B}\_{16}$:

| | S-AES recovered? | true $K\_2$ score | time |
|---|---|---|---|
| Python | yes ($\mathrm{A73B}$) | $7/32$ | 2.52 s |
| Rust, one CPU core | yes ($\mathrm{A73B}$) | $7/32$ | 0.0022 s |

256 values of $K\_2$ tied at score 7; the published pair isolates the master key. Exhaustive $2^{16}$ is still faster on this cipher (0.00048 s Rust): the differential loop also visits $2^{16}$ last-round keys, once per pair. A GPU does not help.

The same 32 pairs and the same last-round peel on Double S-AES ($K\_A=\mathrm{A73B}\_{16}$, $K\_B=\mathrm{1337}\_{16}$) give the true outer $K\_2$ a score of $0$. The inner S-AES randomizes the difference, so the first-round characteristic does not arrive at the outer last round. Two-round S-AES differentials exist at $p=2^{-6}$; they do not make Double S-AES easier than MITM ($2^{17}$, one pair).

[1] studies linear and differential attacks on S-AES. AES-128 [4] has ten rounds and an 8-bit S-box whose best differential probability is $2^{-6}$; that is why a differential attack on AES-128 is a research problem and exhaustive search is not a substitute.

## AES-128: practical to use; exhaustive search is not

AES-128 is practical to **use**. Exhaustive **search** of AES-128 is not practical on this MacBook Pro (M4 Max, 48 GB).

AES-128 has $2^{128}$ keys. That is $2^{96}$ times the measured Double S-AES $2^{32}$ runs on the same machine:

$$
79.3 \times 2^{96}\ \mathrm{s} \approx 2.0 \times 10^{23}\ \mathrm{years}\ (\mathrm{one\ Rust\ CPU\ core})
$$

$$
1.13 \times 2^{96}\ \mathrm{s} \approx 2.9 \times 10^{21}\ \mathrm{years}\ (\mathrm{GPU/Metal})
$$

Those figures treat one AES-128 encryption as no more work than one Double S-AES trial. A real AES-128 trial is heavier (ten rounds, 128-bit state), so the search would take longer, not shorter. A ~70× GPU speedup vs one CPU core is a constant. It does not turn $2^{128}$ into $2^{32}$.

## S-AES vs Double S-AES vs AES-128

| | master key | exhaustive list | on this MacBook Pro (M4 Max, 48 GB) |
|---|---|---|---|
| S-AES [1] | 16-bit $K$ | $2^{16}$ | 0.00048 s CPU, 0.0013 s GPU; DC 0.0022 s CPU |
| Double S-AES | 16-bit $K\_A$ and 16-bit $K\_B$ | $2^{32}$ | 79.3 s CPU, 1.13 s GPU; MITM 0.0040 s; DC does not isolate |
| AES-128 [4] | 128-bit $K$ | $2^{128}$ | $\approx 2.0 \times 10^{23}$ y CPU, $\approx 2.9 \times 10^{21}$ y GPU (same machine, scaled from $2^{32}$) |

Double S-AES is two independent 16-bit S-AES keys in a row. MITM on that composition is $2^{17}$ operations, not $2^{32}$ [3]. Two short ciphers in a row do not give 32-bit security against MITM (2DES at this size).

## References

[1] M. A. Musa, E. F. Schaefer, and S. Wedig, “A Simplified AES Algorithm and Its Linear and Differential Cryptanalyses,” *Cryptologia*, vol. 27, no. 2, pp. 148–177, 2003. https://doi.org/10.1080/0161-110391891838

[2] E. Biham and A. Shamir, “Differential Cryptanalysis of DES-like Cryptosystems,” *Journal of Cryptology*, vol. 4, no. 1, pp. 3–72, 1991. https://doi.org/10.1007/BF00630563

[3] W. Diffie and M. E. Hellman, “Exhaustive Cryptanalysis of the NBS Data Encryption Standard,” *Computer*, vol. 10, no. 6, pp. 74–84, 1977. https://doi.org/10.1109/C-M.1977.217750

[4] National Institute of Standards and Technology, *Advanced Encryption Standard (AES)*, FIPS PUB 197, 2001. https://doi.org/10.6028/NIST.FIPS.197

[5] N. Matsakis and the Rayon contributors, *Rayon: A data parallelism library for Rust*. https://github.com/rayon-rs/rayon

[6] gfx-rs, *wgpu: Cross-platform, safe GPU API in Rust* (WebGPU in Rust). https://wgpu.rs https://github.com/gfx-rs/wgpu
