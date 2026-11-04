#include "mining/nonce_search.h"

#include <algorithm>
#include <iostream>
#include <iterator>
#include <limits>
#include <set>
#include <stdexcept>
#include <vector>

namespace {
void Check(bool condition, const char* message) {
    if (!condition)
        throw std::runtime_error(message);
}

std::vector<uint64_t> SearchWindow(uint64_t base, unsigned workers, uint64_t hashes_per_worker) {
    std::vector<uint64_t> nonces;
    nonces.reserve(workers * hashes_per_worker);
    for (unsigned w = 0; w < workers; ++w) {
        uint64_t nonce = veld::mining::MiningWorkerNonceStart(base, w);
        for (uint64_t i = 0; i < hashes_per_worker; ++i, nonce += workers)
            nonces.push_back(nonce);
    }
    std::sort(nonces.begin(), nonces.end());
    Check(std::adjacent_find(nonces.begin(), nonces.end()) == nonces.end(),
          "workers repeated a nonce within one template");
    return nonces;
}
} // namespace

int main() {
    try {
        using veld::mining::TryCreateMiningNonceBase;
        uint64_t base = 123;
        size_t calls = 0;
        Check(TryCreateMiningNonceBase(base,
                                       [&](uint8_t* p, size_t n) {
                                           ++calls;
                                           Check(n == 8, "search origin must consume 64 bits");
                                           for (size_t i = 0; i < n; ++i)
                                               p[i] = static_cast<uint8_t>(i + 1);
                                           return true;
                                       }),
              "controlled entropy rejected");
        Check(base == 0x0807060504030201ULL && calls == 1,
              "search origin lost entropy or high nonce bits");
        Check(!TryCreateMiningNonceBase(base, [](uint8_t*, size_t) { return false; }),
              "entropy failure must fail search initialization");
        Check(base == 0x0807060504030201ULL,
              "entropy failure must not install a fallback search origin");

        // Unequal worker counts must remain independent throughout a complete
        // header-refresh interval.
        auto first = SearchWindow(0x1234567800000000ULL, 7, 65536);
        auto second = SearchWindow(0xcafebabe00000000ULL, 8, 65536);
        std::vector<uint64_t> common;
        std::set_intersection(first.begin(), first.end(), second.begin(), second.end(),
                              std::back_inserter(common));
        Check(common.empty(), "separate search origins overlap in the work window");

        for (unsigned workers : {1U, 7U, 8U, 64U}) {
            SearchWindow(0, workers, 4096);
            SearchWindow(std::numeric_limits<uint64_t>::max() - 3, workers, 4096);
        }

        std::set<uint64_t> origins;
        for (unsigned i = 0; i < 32; ++i) {
            uint64_t value = 0;
            Check(TryCreateMiningNonceBase(value), "system randomness unavailable");
            Check(origins.insert(value).second, "system randomness repeated a search origin");
        }
        std::cout << "PASS entropy failure, 64-bit origin, 7+8 worker separation, "
                     "worker bounds, wraparound, and system entropy smoke check\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        return 1;
    }
}
