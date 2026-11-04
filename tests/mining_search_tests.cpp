#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_DATASET_BYTES (1024u * 1024u)
#include "node/node.h"
#include <future>
#include <iostream>
#include <stdexcept>

#if defined(VELD_PUBLIC_RELEASE) || defined(VELD_PUBLIC_MAINNET)
#error "Mining search fixtures must never use a public-network profile"
#endif

namespace {
using namespace veld;
void Check(bool condition, const char* message) {
    if (!condition)
        throw std::runtime_error(message);
}

void Initialize(Blockchain& chain) {
    auto genesis = CreateGenesisBlock();
    Check(chain.AddBlockDirect(genesis, true, false, false, mining::PowAdmissionContext::Internal())
              .IsAccepted(),
          "disposable test genesis rejected");
}

RealKeyPair TestMiner() {
    RealKeyPair miner;
    miner.script_override = {0x76, 0xa9, 0x14};
    for (unsigned i = 0; i < 20; ++i)
        miner.script_override.push_back(uint8_t(i + 1));
    miner.script_override.push_back(0x88);
    miner.script_override.push_back(0xac);
    return miner;
}
} // namespace

int main() {
    try {
        using namespace veld;
        using Clock = std::chrono::steady_clock;
        Blockchain chain;
        Mempool mempool;
        const auto miner = TestMiner();
        Initialize(chain);
        const auto initial_tip = chain.TipCopy().GetHash();
        unsigned canceled_searches = 0;
        for (unsigned workers : {1u, 7u, 8u, 16u}) {
            std::atomic<bool> stop{false};
            std::atomic<uint64_t> progress{0};
            const auto before = mining::GlobalDataset().Stats();
            auto future = std::async(std::launch::async, [&]() {
                return MineOnly(chain, mempool, miner, 0, &stop, {}, workers, nullptr, {}, nullptr,
                                &progress);
            });
            const auto deadline = Clock::now() + std::chrono::seconds(20);
            while (mining::GlobalDataset().Stats().requests < before.requests + 6 &&
                   Clock::now() < deadline &&
                   future.wait_for(std::chrono::milliseconds(1)) != std::future_status::ready) {
            }
            stop.store(true);
            const auto result = future.get();
            const auto after = mining::GlobalDataset().Stats();
            Check(result.error.empty(), "search reported an error");
            if (!result.success)
                ++canceled_searches;
            Check(result.hashes_tried > 0, "canceled search lost its completed work");
            Check(after.requests - before.requests ==
                      result.hashes_tried + 1 + unsigned(result.success),
                  "reported hashes differ from actual per-hash dataset acquisitions");
            Check(progress.load() * 32 <= result.hashes_tried &&
                      result.hashes_tried - progress.load() * 32 < workers * 32ULL,
                  "partial progress batches are counted incorrectly");
            Check(result.elapsed_ms > 0, "canceled search lost its elapsed time");
        }
        // Two concurrent search groups use the same payout script and parent.
        // Each group's canceled result contributes its own complete work count.
        std::atomic<bool> stop{false};
        std::atomic<uint64_t> first_progress{0}, second_progress{0};
        const auto before = mining::GlobalDataset().Stats();
        auto first = std::async(std::launch::async, [&]() {
            return MineOnly(chain, mempool, miner, 0, &stop, {}, 7, nullptr, {}, nullptr,
                            &first_progress);
        });
        auto second = std::async(std::launch::async, [&]() {
            return MineOnly(chain, mempool, miner, 0, &stop, {}, 8, nullptr, {}, nullptr,
                            &second_progress);
        });
        const auto deadline = Clock::now() + std::chrono::seconds(30);
        while (((first_progress.load() == 0 &&
                 first.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) ||
                (second_progress.load() == 0 &&
                 second.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)) &&
               Clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        stop.store(true);
        const auto one = first.get();
        const auto two = second.get();
        const auto after = mining::GlobalDataset().Stats();
        Check(one.error.empty() && two.error.empty() && one.hashes_tried > 0 &&
                  two.hashes_tried > 0,
              "concurrent searches did not retain both work counts");
        Check(after.requests - before.requests == one.hashes_tried + two.hashes_tried + 2 +
                                                      unsigned(one.success) + unsigned(two.success),
              "combined work does not equal both independent search groups");
        Check(chain.Height() == 0 && chain.TipCopy().GetHash() == initial_tip,
              "offline searches changed the chain");

        Check(canceled_searches > 0, "test did not exercise an interrupted search");
        std::cout << "PASS active search cancellation, partial counts, concurrent 7+8 workers, "
                     "and unchanged chain state\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
