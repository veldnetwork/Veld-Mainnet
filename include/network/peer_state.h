// Per-peer handshake, request and liveness state.
//
// Connection owns this state so protocol progress does not depend on a
// handler's stack frame. HandlePeer reads and updates it through peer_state.
// Keep request tracking and timers bound to the connection lifecycle.

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>

namespace veld {
namespace net {

// A GETBLOCKS response must fit within the per-source orphan window. Sending
// thousands of blocks to a node that can retain only a small bounded frontier
// wastes the serving peer's response budget and can leave the downloader idle
// until that budget rolls over.
inline constexpr size_t IBD_GETBLOCKS_BATCH_BLOCKS = 32;
inline constexpr auto IBD_GETBLOCKS_RETRY_IDLE = std::chrono::seconds(30);
inline constexpr auto IBD_GETBLOCKS_BUSY_RETRY_LIMIT = std::chrono::seconds(60);

struct PeerState {
    bool version_sent = true;
    bool version_acked = false;
    bool their_version = false;
    bool handshake_done = false;

    bool getaddr_sent = false;
    using addr_clock_t = std::chrono::steady_clock;
    using addr_tp_t = addr_clock_t::time_point;
    addr_tp_t last_getaddr_sent;
    bool any_addr_received = false;
    // A GETADDR request authorizes one bounded ADDR response, not an
    // arbitrary stream for the whole response window.  This bit is reset only
    // when a new GETADDR is successfully queued/sent.
    bool addr_response_consumed = false;

    uint64_t their_start_height = 0;

    using clock_t = std::chrono::steady_clock;
    using tp_t = clock_t::time_point;

    tp_t conn_started = clock_t::now();
    tp_t last_ping = clock_t::now();
    // Connection-owned liveness, including independent background chainstates.
    tp_t last_tipsig{};
    tp_t last_getblocks = clock_t::now();
    tp_t last_ibd_progress = clock_t::now();
    tp_t last_mempool_req = clock_t::now();
    uint64_t ibd_observed_height = 0;
    uint64_t ibd_requested_download_count = 0;
    // Inbound MEMPOOL inventory requests are substantially more expensive than
    // their empty wire payload suggests: they revalidate stateful roots and can
    // walk a large fee index.  Zero means this peer has not yet been served.
    tp_t last_mempool_served{};
};

// Observe canonical progress from the peer event loop. While expensive block
// verification is advancing the chain, the former per-peer 500 ms retry cadence
// repeatedly requested the same suffix from every peer. Those duplicate streams
// exhausted the servers' reconnect-stable response-work buckets and produced
// long IBD stalls. Retry only after the canonical height itself is idle.
inline bool IbdGetBlocksRetryDue(PeerState& state, uint64_t canonical_height, PeerState::tp_t now) {
    if (canonical_height != state.ibd_observed_height) {
        state.ibd_observed_height = canonical_height;
        state.last_ibd_progress = now;
        return false;
    }
    return now - state.last_getblocks >= IBD_GETBLOCKS_RETRY_IDLE &&
           now - state.last_ibd_progress >= IBD_GETBLOCKS_RETRY_IDLE;
}

// Canonical batch continuation is shared across peers below. A per-peer
// download cursor can advance on bodies already committed from another peer;
// granting it a second continuation repeats the same suffix. Keep this path
// solely for bounded idle recovery while validation remains in flight.
inline bool IbdGetBlocksRequestDue(PeerState& state, uint64_t canonical_height,
                                   bool validation_work_pending, PeerState::tp_t now) {
    const bool retry = IbdGetBlocksRetryDue(state, canonical_height, now);
    return retry && (!validation_work_pending ||
                     now - state.last_getblocks >= IBD_GETBLOCKS_BUSY_RETRY_LIMIT);
}

// Canonical progress can be assembled from several serving peers, so no one
// connection necessarily receives a complete 32-body response. Coalesce the
// next-batch request across all peers instead of waiting for every peer's idle
// retry. Only a successful enqueue consumes the batch slot. This gate is a
// download scheduler hint; it does not trust a remote height or validate data.
class IbdCanonicalBatchGate {
  public:
    explicit IbdCanonicalBatchGate(uint64_t canonical_height = 0,
                                   PeerState::tp_t now = PeerState::tp_t{})
        : last_requested_height_(canonical_height), last_request_at_(now) {}

    template <typename Send>
    bool TryContinue(uint64_t canonical_height, PeerState::tp_t now, Send&& send) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (canonical_height < last_requested_height_) {
            last_requested_height_ = canonical_height;
            last_request_at_ = now;
            return false;
        }
        if (canonical_height - last_requested_height_ < IBD_GETBLOCKS_BATCH_BLOCKS ||
            (last_request_at_ != PeerState::tp_t{} &&
             now - last_request_at_ < std::chrono::seconds(1))) {
            return false;
        }
        if (!send())
            return false;
        last_requested_height_ = canonical_height;
        last_request_at_ = now;
        return true;
    }

  private:
    std::mutex mutex_;
    uint64_t last_requested_height_{0};
    PeerState::tp_t last_request_at_{};
};

using PeerStatePtr = std::shared_ptr<PeerState>;

}
}
