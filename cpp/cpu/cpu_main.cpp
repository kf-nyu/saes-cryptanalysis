// S-AES 2^16, Double MITM 2^17, Double 2^32: one CPU core and all cores.

#include "saes.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <thread>
#include <vector>

#include <tbb/blocked_range.h>
#include <tbb/combinable.h>
#include <tbb/parallel_for.h>
#include <tbb/task_arena.h>

using Clock = std::chrono::steady_clock;

static double seconds_since(Clock::time_point t0) {
    return std::chrono::duration<double>(Clock::now() - t0).count();
}

static uint32_t saes_exhaustive_range(uint16_t p, uint16_t c, uint32_t k0, uint32_t k1,
                                      uint16_t published_k, bool* saw_published) {
    uint32_t hits = 0;
    bool saw = false;
    for (uint32_t k = k0; k < k1; ++k) {
        if (saes_encrypt(p, static_cast<uint16_t>(k)) == c) {
            ++hits;
            if (static_cast<uint16_t>(k) == published_k) {
                saw = true;
            }
        }
    }
    *saw_published = saw;
    return hits;
}

static uint32_t saes_exhaustive_parallel(uint16_t p, uint16_t c, unsigned nthreads,
                                         uint16_t published_k, bool* saw_published) {
    if (nthreads < 1) {
        nthreads = 1;
    }
    std::vector<std::thread> threads;
    std::vector<uint32_t> hits(nthreads, 0);
    std::vector<char> saw(nthreads, 0);
    uint32_t chunk = (0x10000u + nthreads - 1) / nthreads;
    for (unsigned t = 0; t < nthreads; ++t) {
        uint32_t a = t * chunk;
        uint32_t b = a + chunk;
        if (a > 0x10000u) {
            a = 0x10000u;
        }
        if (b > 0x10000u) {
            b = 0x10000u;
        }
        threads.emplace_back([=, &hits, &saw]() {
            bool local_saw = false;
            hits[t] = saes_exhaustive_range(p, c, a, b, published_k, &local_saw);
            saw[t] = local_saw ? 1 : 0;
        });
    }
    for (auto& th : threads) {
        th.join();
    }
    uint32_t total = 0;
    bool any = false;
    for (unsigned t = 0; t < nthreads; ++t) {
        total += hits[t];
        any = any || saw[t];
    }
    *saw_published = any;
    return total;
}

static uint32_t saes_exhaustive_tbb(uint16_t p, uint16_t c, uint16_t published_k,
                                    bool* saw_published) {
    tbb::combinable<uint32_t> hits;
    tbb::combinable<char> saw;
    tbb::parallel_for(tbb::blocked_range<uint32_t>(0, 0x10000),
                      [&](const tbb::blocked_range<uint32_t>& r) {
                          bool local_saw = false;
                          hits.local() += saes_exhaustive_range(p, c, r.begin(), r.end(),
                                                                published_k, &local_saw);
                          if (local_saw) {
                              saw.local() = 1;
                          }
                      });
    uint32_t total = 0;
    bool any = false;
    hits.combine_each([&](uint32_t h) { total += h; });
    saw.combine_each([&](char s) { any = any || s; });
    *saw_published = any;
    return total;
}

struct MitmResult {
    uint32_t hits;
    uint64_t ops;
    bool found_true;
};

static MitmResult mitm_double(uint16_t p, uint16_t c, uint16_t true_ka, uint16_t true_kb) {
    std::vector<std::vector<uint16_t>> by_middle(0x10000);
    uint64_t ops = 0;
    for (uint32_t ka = 0; ka < 0x10000; ++ka) {
        uint16_t x = saes_encrypt(p, static_cast<uint16_t>(ka));
        by_middle[x].push_back(static_cast<uint16_t>(ka));
        ++ops;
    }
    uint32_t hits = 0;
    bool found = false;
    for (uint32_t kb = 0; kb < 0x10000; ++kb) {
        uint16_t xp = saes_decrypt(c, static_cast<uint16_t>(kb));
        ++ops;
        for (uint16_t ka : by_middle[xp]) {
            ++hits;
            if (ka == true_ka && static_cast<uint16_t>(kb) == true_kb) {
                found = true;
            }
        }
    }
    return MitmResult{hits, ops, found};
}

struct ExhResult {
    uint64_t hits;
    uint32_t last_packed;
};

static ExhResult double_exhaustive_range(uint16_t p, uint16_t c, uint32_t ka0, uint32_t ka1) {
    uint64_t hits = 0;
    uint32_t last = 0;
    for (uint32_t ka = ka0; ka < ka1; ++ka) {
        for (uint32_t kb = 0; kb < 0x10000; ++kb) {
            if (double_encrypt(p, static_cast<uint16_t>(ka), static_cast<uint16_t>(kb)) == c) {
                ++hits;
                last = (ka << 16) | kb;
            }
        }
    }
    return ExhResult{hits, last};
}

static ExhResult double_exhaustive_parallel(uint16_t p, uint16_t c, unsigned nthreads) {
    if (nthreads < 1) {
        nthreads = 1;
    }
    std::vector<std::thread> threads;
    std::vector<ExhResult> parts(nthreads);
    uint32_t chunk = (0x10000u + nthreads - 1) / nthreads;
    for (unsigned t = 0; t < nthreads; ++t) {
        uint32_t a = t * chunk;
        uint32_t b = a + chunk;
        if (a > 0x10000u) {
            a = 0x10000u;
        }
        if (b > 0x10000u) {
            b = 0x10000u;
        }
        threads.emplace_back([=, &parts]() { parts[t] = double_exhaustive_range(p, c, a, b); });
    }
    for (auto& th : threads) {
        th.join();
    }
    ExhResult out{0, 0};
    for (auto& part : parts) {
        out.hits += part.hits;
        if (part.last_packed) {
            out.last_packed = part.last_packed;
        }
    }
    return out;
}

static ExhResult double_exhaustive_tbb(uint16_t p, uint16_t c) {
    tbb::combinable<ExhResult> parts;
    tbb::parallel_for(tbb::blocked_range<uint32_t>(0, 0x10000),
                      [&](const tbb::blocked_range<uint32_t>& r) {
                          ExhResult local = double_exhaustive_range(p, c, r.begin(), r.end());
                          ExhResult& acc = parts.local();
                          acc.hits += local.hits;
                          if (local.last_packed) {
                              acc.last_packed = local.last_packed;
                          }
                      });
    ExhResult out{0, 0};
    parts.combine_each([&](const ExhResult& part) {
        out.hits += part.hits;
        if (part.last_packed) {
            out.last_packed = part.last_packed;
        }
    });
    return out;
}

int main() {
    const uint16_t p = 0x6F6B;
    const uint16_t k = 0xA73B;
    const uint16_t c_saes = 0x0738;
    if (saes_encrypt(p, k) != c_saes || saes_decrypt(c_saes, k) != p) {
        std::fprintf(stderr, "S-AES test vector failed\n");
        return 1;
    }
    const uint16_t ka = 0xA73B;
    const uint16_t kb = 0x1337;
    const uint16_t c_double = double_encrypt(p, ka, kb);
    if (c_double != 0xD62C || saes_decrypt(saes_decrypt(c_double, kb), ka) != p) {
        std::fprintf(stderr, "Double S-AES test vector failed\n");
        return 1;
    }

    unsigned nthreads = std::thread::hardware_concurrency();
    if (nthreads < 1) {
        nthreads = 1;
    }

    std::printf("S-AES and Double S-AES (C++, release)\n");
    std::printf("  S-AES [2]     P=%04X  K=%04X  C=%04X\n", p, k, c_saes);
    std::printf("  Double S-AES  P=%04X  KA=%04X  KB=%04X  C=%04X\n", p, ka, kb, c_double);
    int tbb_workers = tbb::this_task_arena::max_concurrency();
    std::printf("  std::thread   %u cores\n", nthreads);
    std::printf("  oneTBB        %d workers (Rayon analog)\n\n", tbb_workers);

    bool saw = false;
    auto t0 = Clock::now();
    uint32_t saes_hits = saes_exhaustive_range(p, c_saes, 0, 0x10000, k, &saw);
    double saes_s = seconds_since(t0);
    t0 = Clock::now();
    bool saw_par = false;
    uint32_t saes_hits_par = saes_exhaustive_parallel(p, c_saes, nthreads, k, &saw_par);
    double saes_par_s = seconds_since(t0);
    t0 = Clock::now();
    bool saw_tbb = false;
    uint32_t saes_hits_tbb = saes_exhaustive_tbb(p, c_saes, k, &saw_tbb);
    double saes_tbb_s = seconds_since(t0);

    std::printf("S-AES exhaustive  (2^16 master keys)\n");
    std::printf("  hits on one pair     %u\n", saes_hits);
    std::printf("  published K in list  %s\n", saw ? "true" : "false");
    std::printf("  time, one core       %.6f s\n", saes_s);
    std::printf("  time, std::thread    %.6f s  (%u cores)\n", saes_par_s, nthreads);
    std::printf("  time, oneTBB         %.6f s  (%d workers)\n", saes_tbb_s, tbb_workers);
    std::printf("  per trial (1 core)   %.2f ns\n", saes_s / 65536.0 * 1e9);
    std::printf("  parallel hits match  %s\n\n",
                (saes_hits_par == saes_hits && saw_par == saw && saes_hits_tbb == saes_hits &&
                 saw_tbb == saw)
                    ? "true"
                    : "false");

    t0 = Clock::now();
    MitmResult mitm = mitm_double(p, c_double, ka, kb);
    double mitm_s = seconds_since(t0);
    std::printf("Double S-AES MITM  (2^16 + 2^16 = 2^17 S-AES calls)\n");
    std::printf("  candidates on one pair  %u\n", mitm.hits);
    std::printf("  true (KA, KB) in list   %s\n", mitm.found_true ? "true" : "false");
    std::printf("  operations %llu\n", static_cast<unsigned long long>(mitm.ops));
    std::printf("  time       %.4f s\n\n", mitm_s);

    const uint64_t full = 1ull << 32;
    std::printf("Double S-AES exhaustive FULL 2^32 (every trial)\n");
    t0 = Clock::now();
    ExhResult one = double_exhaustive_range(p, c_double, 0, 0x10000);
    double full_s = seconds_since(t0);
    std::printf("  hits, one core        %llu\n", static_cast<unsigned long long>(one.hits));
    std::printf("  last packed           %08X\n", one.last_packed);
    std::printf("  time, one core        %.2f s  (%.2f min)\n", full_s, full_s / 60.0);
    std::printf("  per trial (1 core)    %.2f ns\n", (full_s / static_cast<double>(full)) * 1e9);

    t0 = Clock::now();
    ExhResult par = double_exhaustive_parallel(p, c_double, nthreads);
    double full_par_s = seconds_since(t0);
    t0 = Clock::now();
    ExhResult tbb = double_exhaustive_tbb(p, c_double);
    double full_tbb_s = seconds_since(t0);
    std::printf("  hits, std::thread     %llu\n", static_cast<unsigned long long>(par.hits));
    std::printf("  time, std::thread     %.2f s  (%u cores, %.2fx)\n", full_par_s, nthreads,
                full_s / full_par_s);
    std::printf("  hits, oneTBB          %llu\n", static_cast<unsigned long long>(tbb.hits));
    std::printf("  time, oneTBB          %.2f s  (%d workers, %.2fx)\n", full_tbb_s, tbb_workers,
                full_s / full_tbb_s);
    std::printf("  per trial (oneTBB)    %.2f ns\n\n",
                (full_tbb_s / static_cast<double>(full)) * 1e9);

    std::printf("Compare (this C++ CPU run)\n");
    std::printf("  S-AES 2^16, one core           %.6f s\n", saes_s);
    std::printf("  S-AES 2^16, std::thread        %.6f s\n", saes_par_s);
    std::printf("  S-AES 2^16, oneTBB             %.6f s\n", saes_tbb_s);
    std::printf("  Double MITM 2^17               %.4f s\n", mitm_s);
    std::printf("  Double exhaustive 2^32, 1 core %.2f s\n", full_s);
    std::printf("  Double exhaustive 2^32, std::thread %.2f s\n", full_par_s);
    std::printf("  Double exhaustive 2^32, oneTBB %.2f s\n", full_tbb_s);
    std::printf("  2^32 / 2^16                    %.0fx more trials\n",
                static_cast<double>(full) / 65536.0);
    return 0;
}
