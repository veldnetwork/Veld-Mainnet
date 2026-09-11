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

    // Repeated or backward clock readings must not invent future seconds or
    // reset a worker onto nonces it already tried for this exact header.
    for (uint64_t now : {1001ULL, 1000ULL, 0ULL}) {
        if (shared.RefreshTimestamp(after.generation, now) ||
            shared.Read().header.Serialize() != after.header.Serialize() ||
            shared.Generation() != after.generation)
            return 1;
    }
    // A slow worker with one hash per second must see each new wall-clock
    // second, including after a suspension, without a hash-count threshold.
    MiningWorkHeader slow(original);
    for (uint64_t now : {1001ULL, 1002ULL, 1600ULL, 2200ULL}) {
        const auto snapshot = slow.Read();
        if (!slow.RefreshTimestamp(snapshot.generation, now) ||
            slow.Read().header.timestamp != now ||
            snapshot.header.timestamp >= now)
            return 1;
    }

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
                    shared.RefreshTimestamp(snapshot.generation, snapshot.header.timestamp + 1);
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
    if (!boundary.RefreshTimestamp(0, UINT64_MAX) || boundary.RefreshTimestamp(1, 0) ||
        boundary.RefreshTimestamp(1, UINT64_MAX) ||
        boundary.Read().header.timestamp != UINT64_MAX)
        return 1;
    if (failed)
        return 1;
    std::cout << "PASS clock rollback and equal-time guards, slow-worker clock changes, "
                 "80000 concurrent snapshots, stale refreshes, nonce wraparound, "
                 "near-miss header identity and timestamp boundary\n";
}
