#include "mining/chacha20_bulk.h"
#include <array>
#include <iostream>
#include <random>
#include <stdexcept>
#include <vector>

// Compare the mining implementation directly with the preserved scalar stream.
// Include counter wrap, every SIMD/tail boundary, and unaligned destinations.
int main() {
    std::mt19937_64 random(0x50e32206);
    size_t checks = 0;
    for (unsigned trial = 0; trial < 128; ++trial) {
        std::array<uint8_t, 32> key;
        std::array<uint8_t, 16> iv;
        for (auto& byte : key) byte = static_cast<uint8_t>(random());
        for (auto& byte : iv) byte = static_cast<uint8_t>(random());
        for (uint32_t counter : {0u, 1u, 0x7fffffffu, 0xfffffffcu, 0xffffffffu}) {
            veld::vendored_crypto::vc_store32_le(iv.data(), counter);
            for (size_t length : {0u, 1u, 63u, 64u, 65u, 127u, 255u, 256u, 257u,
                                  511u, 512u, 513u, 1023u, 1024u, 4097u, 65539u}) {
                const size_t offset = 1 + trial % 31;
                std::vector<uint8_t> actual(length + offset + 32, 0xa5), expected(actual);
                veld::mining::MiningChaChaKeystream(key.data(), iv.data(), actual.data() + offset, length);
                veld::vendored_crypto::chacha20_keystream(key.data(), iv.data(), expected.data() + offset, length);
                if (actual != expected) throw std::runtime_error("bulk stream or guard bytes changed");
                ++checks;
            }
        }
    }
    std::cout << "PASS " << checks << " independent scalar comparisons; implementation="
#if defined(VELD_MINING_CHACHA_SSE2)
              << "sse2-four-block\n";
#else
              << "scalar\n";
#endif
}
