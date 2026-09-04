#include "network/peer_state.h"

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>

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
    Check(IBD_GETBLOCKS_RETRY_IDLE == 10s, "IBD retry idle interval is exact");

    PeerState peer;
    const auto start = PeerState::tp_t{} + 1h;
    peer.last_getblocks = start;
    peer.last_ibd_progress = start;
    peer.ibd_observed_height = 48;

    Check(!IbdGetBlocksRetryDue(peer, 48, start + 9s),
          "no duplicate request while a response may be validating");
    Check(IbdGetBlocksRetryDue(peer, 48, start + 10s),
          "idle peer is retried at the bounded deadline");

    peer.last_getblocks = start + 10s;
    Check(!IbdGetBlocksRetryDue(peer, 49, start + 11s),
          "canonical progress suppresses duplicate suffix requests");
    Check(peer.ibd_observed_height == 49 && peer.last_ibd_progress == start + 11s,
          "canonical progress timestamp is recorded exactly");

    for (uint64_t height = 50; height <= 88; ++height) {
        const auto now = start + 11s + std::chrono::seconds((height - 49) * 2);
        Check(!IbdGetBlocksRetryDue(peer, height, now),
              "continuous expensive validation never floods GETBLOCKS");
    }
    const auto final_progress = peer.last_ibd_progress;
    Check(!IbdGetBlocksRetryDue(peer, 88, final_progress + 9s),
          "final batch receives a complete idle grace period");
    Check(IbdGetBlocksRetryDue(peer, 88, final_progress + 10s),
          "sync resumes after a genuine height stall");

    std::cout << "IBD_SYNC_LIVENESS: PASS (" << checks << " checks)\n";
    return 0;
}
