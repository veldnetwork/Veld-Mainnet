#include "mining/work_header.h"
#include "mining/nonce_search.h"
#include <iostream>
#include <thread>

int main() {
    using namespace veld;
    using namespace veld::mining;
    BlockHeader original;
    original.version = 1;
    original.timestamp = 1000;
    original.bits = GENESIS_BITS;
    original.prev_block_hash.fill(0x31);
    original.merkle_root.fill(0x79);
    MiningWorkHeader shared(original);
    const auto before = shared.Read();
    if (!shared.RefreshTimestamp(0, 1001) || shared.RefreshTimestamp(0, 2000))
        return 1;
    const auto after = shared.Read();
    if (before.header.timestamp != 1000 || after.header.timestamp != 1001 ||
        before.generation != 0 || after.generation != 1)
        return 1;
    if (before.WithNonce(UINT64_MAX).timestamp != 1000)
        return 1;

    std::atomic<bool> failed{false};
    std::vector<std::thread> workers;
    for (unsigned worker = 0; worker < 16; ++worker) {
        workers.emplace_back([&, worker]() {
            for (unsigned i = 0; i < 5000; ++i) {
                const auto snapshot = shared.Read();
                const uint64_t nonce = MiningWorkerNonceStart(UINT64_MAX - 7, worker) + i * 16ULL;
                const auto header = snapshot.WithNonce(nonce);
                auto expected = original;
                expected.timestamp = 1000 + snapshot.generation;
                expected.nonce = nonce;
                if (header.Serialize() != expected.Serialize())
                    failed = true;
                if (i % 31 == 0)
                    shared.RefreshTimestamp(snapshot.generation, 0);
                // Reporting a result from the prior generation must preserve its bytes.
                if (snapshot.WithNonce(nonce).Serialize() != header.Serialize())
                    failed = true;
            }
        });
    }
    for (auto& worker : workers)
        worker.join();
    original.timestamp = UINT64_MAX - 1;
    MiningWorkHeader boundary(original);
    if (!boundary.RefreshTimestamp(0, 0) || boundary.RefreshTimestamp(1, 0) ||
        boundary.Read().header.timestamp != UINT64_MAX)
        return 1;
    if (failed)
        return 1;
    std::cout << "PASS 80000 concurrent header snapshots, stale refreshes, nonce wraparound, "
                 "near-miss header identity and timestamp boundary\n";
}
