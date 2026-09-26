#include "network/peer_state.h"

#include <atomic>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

size_t checks = 0;

void Check(bool condition, const char* label) {
    ++checks;
    if (!condition)
        throw std::runtime_error(std::string("FAIL: ") + label);
}

} // namespace

int main() {
    using namespace std::chrono_literals;
    using veld::net::IBD_GETBLOCKS_BATCH_BLOCKS;
    using veld::net::IBD_GETBLOCKS_RETRY_IDLE;
    using veld::net::IbdGetBlocksRetryDue;
    using veld::net::PeerState;

    Check(IBD_GETBLOCKS_BATCH_BLOCKS == 32,
          "wire batch stays inside the per-source orphan frontier");
    Check(IBD_GETBLOCKS_RETRY_IDLE == 30s, "IBD retry idle interval is exact");

    PeerState peer;
    const auto start = PeerState::tp_t{} + 1h;
    peer.last_getblocks = start;
    peer.last_ibd_progress = start;
    peer.ibd_observed_height = 48;

    Check(!IbdGetBlocksRetryDue(peer, 48, start + 29s),
          "no duplicate request while a response may be validating");
    Check(IbdGetBlocksRetryDue(peer, 48, start + 30s),
          "idle peer is retried at the bounded deadline");

    peer.last_getblocks = start + 30s;
    Check(!IbdGetBlocksRetryDue(peer, 49, start + 31s),
          "canonical progress suppresses duplicate suffix requests");
    Check(peer.ibd_observed_height == 49 && peer.last_ibd_progress == start + 31s,
          "canonical progress timestamp is recorded exactly");

    for (uint64_t height = 50; height <= 88; ++height) {
        const auto now = start + 31s + std::chrono::seconds((height - 49) * 2);
        Check(!IbdGetBlocksRetryDue(peer, height, now),
              "continuous expensive validation never floods GETBLOCKS");
    }
    const auto final_progress = peer.last_ibd_progress;
    Check(!IbdGetBlocksRetryDue(peer, 88, final_progress + 29s),
          "final batch receives a complete idle grace period");
    Check(IbdGetBlocksRetryDue(peer, 88, final_progress + 30s),
          "sync resumes after a genuine height stall");

    using veld::net::IbdGetBlocksRequestDue;
    using veld::net::IBD_GETBLOCKS_BUSY_RETRY_LIMIT;
    Check(IBD_GETBLOCKS_BUSY_RETRY_LIMIT == 60s, "busy validation has a bounded retry limit");
    peer.last_getblocks = start;
    peer.last_ibd_progress = start;
    peer.ibd_observed_height = 48;
    Check(!IbdGetBlocksRequestDue(peer, 48, true, start + 2s),
          "per-peer progress cannot duplicate the shared canonical batch");
    peer.last_getblocks = start;
    peer.last_ibd_progress = start;
    peer.ibd_observed_height = 48;
    Check(!IbdGetBlocksRequestDue(peer, 48, true, start + 10s),
          "in-flight validation suppresses duplicate suffix at idle deadline");
    Check(!IbdGetBlocksRequestDue(peer, 48, true, start + 59s),
          "in-flight validation remains protected below its bounded limit");
    Check(IbdGetBlocksRequestDue(peer, 48, true, start + 60s),
          "stuck in-flight work cannot suppress recovery forever");
    peer.last_getblocks = start;
    peer.last_ibd_progress = start;
    Check(IbdGetBlocksRequestDue(peer, 48, false, start + 30s),
          "silent source still retries at ordinary idle deadline");
    peer.last_getblocks = start;
    peer.last_ibd_progress = start;
    Check(!IbdGetBlocksRequestDue(peer, 49, false, start + 10s),
          "canonical advance resets retry despite previous idle time");

    using veld::net::IbdCanonicalBatchGate;
    IbdCanonicalBatchGate batch_gate(100, start);
    unsigned sends = 0;
    auto sent = [&] {
        ++sends;
        return true;
    };
    Check(!batch_gate.TryContinue(131, start + 2s, sent) && sends == 0,
          "split canonical progress below one batch cannot request early");
    Check(batch_gate.TryContinue(132, start + 2s, sent) && sends == 1,
          "aggregate canonical batch advances without a complete per-peer batch");
    Check(!batch_gate.TryContinue(132, start + 2s, sent) && sends == 1,
          "another peer cannot duplicate the same canonical batch request");
    Check(!batch_gate.TryContinue(164, start + 3s, [&] { return false; }),
          "failed enqueue does not consume aggregate continuation");
    Check(batch_gate.TryContinue(164, start + 3s, sent) && sends == 2,
          "another peer can retry a failed aggregate enqueue");
    IbdCanonicalBatchGate reorg_gate(200, start + 4s);
    Check(!reorg_gate.TryContinue(199, start + 5s, sent) && sends == 2,
          "canonical reorganization resets aggregate batch baseline");
    Check(reorg_gate.TryContinue(231, start + 6s, sent) && sends == 3,
          "replacement canonical branch may continue after a full batch");
    IbdCanonicalBatchGate concurrent_gate(100, start);
    std::atomic<unsigned> concurrent_sends{0};
    std::vector<std::thread> contenders;
    for (unsigned i = 0; i < 8; ++i) {
        contenders.emplace_back([&] {
            concurrent_gate.TryContinue(132, start + 2s, [&] {
                concurrent_sends.fetch_add(1, std::memory_order_relaxed);
                return true;
            });
        });
    }
    for (auto& contender : contenders)
        contender.join();
    Check(concurrent_sends.load(std::memory_order_relaxed) == 1,
          "concurrent peer loops enqueue exactly one aggregate continuation");

    std::cout << "IBD_SYNC_LIVENESS: PASS (" << checks << " checks)\n";
    return 0;
}
