// Per-peer connection state.
//
// Previously every per-peer state field lived as a stack local inside
// HandlePeer (in tcp.h, ~2400-line function). That couples the state
// machine to the thread-per-connection model: the only way to drive
// progress on a peer is to wake its dedicated thread and re-enter its
// stack frame. At 10k peers that's 10k OS threads (20-80 GB virtual
// stack at default sizes, plus context-switch storms).
//
// PeerState moves all of those locals into a heap-allocated struct
// keyed by Connection. HandlePeer reads and writes through *peer_state,
// allowing connection state to survive across handler boundaries.
// can:
//   Phase A: drive the same state machine from a poll() loop on the
//            accept side.
//   Phase B: replace per-peer recv loop with non-blocking recv that
//            yields when no data is ready.
//   Phase C: replace thread-per-peer with single epoll/IOCP loop;
//            handlers become pure functions of (PeerState&, msg).
//
// All fields here have one-to-one semantic correspondents in the
// pre-refactor HandlePeer. The field comments cite the original
// HandlePeer line numbers (tcp.h ~2540-2630) and describe what each
// timer / state bit is for. Do NOT add new fields here without a
// matching plan to drive them from the future event-loop body —
// otherwise the whole refactor goal of "all per-peer state lives in
// one struct" gets eroded.

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace veld {
namespace net {

// A GETBLOCKS response must fit within the per-source orphan window. Sending
// thousands of blocks to a node that can retain only a small bounded frontier
// wastes the serving peer's response budget and can leave the downloader idle
// until that budget rolls over.
inline constexpr size_t IBD_GETBLOCKS_BATCH_BLOCKS = 32;
inline constexpr auto IBD_GETBLOCKS_RETRY_IDLE = std::chrono::seconds(10);

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
    tp_t last_getblocks = clock_t::now();
    tp_t last_ibd_progress = clock_t::now();
    tp_t last_mempool_req = clock_t::now();
    uint64_t ibd_observed_height = 0;
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

using PeerStatePtr = std::shared_ptr<PeerState>;

} // namespace net
} // namespace veld
