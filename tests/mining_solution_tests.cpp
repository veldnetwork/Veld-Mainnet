#include "regtest_profile.h"
#define VELD_TEST_DATASET_BYTES (1024u * 1024u)
#include "node/node.h"
#include <iostream>
#include <stdexcept>

#if defined(VELD_PUBLIC_RELEASE) || defined(VELD_PUBLIC_MAINNET)
#error "Mining solution fixtures must never use a public-network profile"
#endif

int main() {
    using namespace veld;
    const auto check = [](bool condition, const char* message) {
        if (!condition)
            throw std::runtime_error(message);
    };
    try {
        Blockchain chain;
        Mempool mempool;
        const auto genesis = CreateGenesisBlock();
        check(chain
                  .AddBlockDirect(genesis, true, false, false,
                                  mining::PowAdmissionContext::Internal())
                  .IsAccepted(),
              "disposable test genesis rejected");
        RealKeyPair miner;
        miner.script_override = {0x76, 0xa9, 0x14};
        for (unsigned i = 0; i < 20; ++i)
            miner.script_override.push_back(uint8_t(i + 1));
        miner.script_override.push_back(0x88);
        miner.script_override.push_back(0xac);
        for (unsigned workers : {1u, 7u, 8u, 15u, 16u}) {
            uint64_t prepared_timestamp = 0;
            uint64_t search_started = 0;
            const auto delayed_preflight = [&](const Block& candidate) {
                prepared_timestamp = candidate.header.timestamp;
                // Slow template preparation must not leave the search hashing
                // a stale timestamp until a worker completes 65,536 hashes.
                std::this_thread::sleep_for(std::chrono::milliseconds(2100));
                search_started = static_cast<uint64_t>(std::time(nullptr));
                return true;
            };
            const auto found = MineOnly(chain, mempool, miner, 0, nullptr, {}, workers,
                                       nullptr, {}, nullptr, nullptr, {}, delayed_preflight);
            check(found.success && found.hashes_tried > 0, "fixture did not return a solution");
            check(search_started > prepared_timestamp &&
                      found.block.header.timestamp >= search_started,
                  "worker hashed the stale template timestamp after a slow start");
            check(found.block.header.timestamp <= static_cast<uint64_t>(std::time(nullptr)),
                  "worker advanced the timestamp beyond the wall clock");
            const auto verified =
                mining::VeldHash(found.block.header.Serialize(), found.new_height);
            check(found.hash == verified && verified < found.block.header.GetTarget(),
                  "solution is not the exact header that was hashed");
            check(found.block.transactions.front().TotalOutput() == BLOCK_REWARD_UNITS,
                  "mining changed the block subsidy");
            check(chain.ValidateCanonicalCoinbaseSplit(found.block),
                  "mining changed the canonical coinbase split");
            check(chain.Height() == 0 && chain.TipCopy().GetHash() == genesis.GetHash(),
                  "offline search committed a block");
        }
        std::cout << "PASS delayed 1/7/8/15/16-worker timestamp refresh, exact solution "
                     "verification and unchanged coinbase split\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
