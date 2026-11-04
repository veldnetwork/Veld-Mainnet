#include "mining/chacha20_bulk.h"
#include <array>
#include <atomic>
#include <iostream>
#include <random>
#include <stdexcept>
#include <thread>
#include <vector>

// Compare the mining implementation directly with the preserved scalar stream.
// Include counter wrap, every SIMD/tail boundary, and unaligned destinations.
int main() {
    // Exercise concurrent first dispatch as well as per-call output isolation.
    std::atomic<bool> failed{false};
    std::vector<std::thread> workers;
    for (unsigned i = 0; i < 8; ++i)
        workers.emplace_back([&, i] {
            std::array<uint8_t, 32> key{};
            std::array<uint8_t, 16> iv{};
            key[0] = static_cast<uint8_t>(i);
            std::array<uint8_t, 4097> actual{}, expected{};
            veld::mining::MiningChaChaKeystream(key.data(), iv.data(), actual.data(),
                                                actual.size());
            veld::vendored_crypto::chacha20_keystream(key.data(), iv.data(), expected.data(),
                                                      expected.size());
            if (actual != expected)
                failed = true;
        });
    for (auto& worker : workers)
        worker.join();
    if (failed)
        throw std::runtime_error("concurrent first dispatch changed stream");
    std::mt19937_64 random(0x50e32206);
    size_t checks = 0;
    for (unsigned trial = 0; trial < 128; ++trial) {
        std::array<uint8_t, 32> key;
        std::array<uint8_t, 16> iv;
        for (auto& byte : key)
            byte = static_cast<uint8_t>(random());
        for (auto& byte : iv)
            byte = static_cast<uint8_t>(random());
        for (uint32_t counter :
             {0u, 1u, 0x7fffffffu, 0xfffffff8u, 0xfffffffbu, 0xfffffffcu, 0xffffffffu}) {
            veld::vendored_crypto::vc_store32_le(iv.data(), counter);
            for (size_t length :
                 {0u,   1u,   63u,  64u,  65u,  127u,  255u,  256u,  257u,  511u,
                  512u, 513u, 767u, 768u, 769u, 1023u, 1024u, 1025u, 4097u, 65539u}) {
                const size_t offset = 1 + trial % 31;
                std::vector<uint8_t> actual(length + offset + 32, 0xa5), expected(actual);
                veld::mining::MiningChaChaKeystream(key.data(), iv.data(), actual.data() + offset,
                                                    length);
                veld::vendored_crypto::chacha20_keystream(key.data(), iv.data(),
                                                          expected.data() + offset, length);
                if (actual != expected)
                    throw std::runtime_error("bulk stream or guard bytes changed");
                ++checks;
                std::fill(actual.begin(), actual.end(), 0xa5);
                veld::mining::MiningChaChaKeystreamSSE2(key.data(), iv.data(),
                                                        actual.data() + offset, length);
                if (actual != expected)
                    throw std::runtime_error("fallback stream or guard bytes changed");
                ++checks;
#if defined(VELD_MINING_CHACHA_AVX2)
                if (veld::mining::MiningChaChaAVX2Available()) {
                    std::fill(actual.begin(), actual.end(), 0xa5);
                    veld::mining::chacha_bulk_detail::KeystreamAVX2(key.data(), iv.data(),
                                                                    actual.data() + offset, length);
                    if (actual != expected)
                        throw std::runtime_error("AVX2 stream or guard bytes changed");
                    ++checks;
                }
#endif
            }
        }
    }
    std::cout << "PASS " << checks << " independent scalar comparisons; implementation="
#if defined(VELD_MINING_CHACHA_SSE2)
              << (veld::mining::MiningChaChaAVX2Available() ? "avx2-eight-block"
                                                            : "sse2-four-block")
              << '\n';
#else
              << "scalar\n";
#endif
}
