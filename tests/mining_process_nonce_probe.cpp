#include "mining/nonce_search.h"
#include "mining/worker_policy.h"
#include <iostream>
#include <string>

// Subprocess fixture for exercising the production entropy provider and nonce
// partitioning independently of shared process state. No wallets or networking.
int main(int argc, char** argv) {
    using namespace veld::mining;
    if (argc != 2)
        return 2;
    try {
        size_t used = 0;
        const std::string argument(argv[1]);
        const auto workers = std::stoull(argument, &used);
        if (used != argument.size() || !ValidWorkerCount(workers))
            return 2;
        uint64_t origin = 0;
        if (!TryCreateMiningNonceBase(origin))
            return 1;
        std::cout << "{\"workers\":" << workers << ",\"origin\":" << origin << ",\"starts\":[";
        for (unsigned worker = 0; worker < workers; ++worker) {
            if (worker)
                std::cout << ',';
            std::cout << MiningWorkerNonceStart(origin, worker);
        }
        std::cout << "]}\n";
    } catch (...) {
        return 2;
    }
}
