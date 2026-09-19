#include "mining/chacha20_bulk.h"
#include <chrono>
#include <iostream>
#include <vector>

// Alternating, same-process timings isolate the changed stream implementation.
// This is a microbenchmark, not a claim about whole-node mining throughput.
int main() {
    using Clock = std::chrono::steady_clock;
    uint8_t key[32]{}, iv[16]{};
    std::vector<uint8_t> output(2 * 1024 * 1024);
    uint64_t checksum = 0;
    for (unsigned trial = 0; trial < 10; ++trial) {
        for (unsigned order = 0; order < 2; ++order) {
            const bool bulk = (trial + order) % 2;
            const auto started = Clock::now();
            for (unsigned repeat = 0; repeat < 64; ++repeat) {
                iv[0] = static_cast<uint8_t>(repeat);
                if (bulk) veld::mining::MiningChaChaKeystream(key, iv, output.data(), output.size());
                else veld::vendored_crypto::chacha20_keystream(key, iv, output.data(), output.size());
                checksum += output[repeat * 13];
            }
            const auto ms = std::chrono::duration<double, std::milli>(Clock::now() - started).count();
            std::cout << "{\"trial\":" << trial << ",\"implementation\":\"" << (bulk ? "bulk" : "scalar")
                      << "\",\"ms\":" << ms << ",\"bytes\":" << 64 * output.size()
                      << ",\"checksum\":" << checksum << "}\n";
        }
    }
}
