#pragma once

#include <cstddef>
#include <cstdint>

namespace veld {

// Pure startup/IBD decision shared by veld-node and veld-miner.  A TCP socket
// alone is not sync evidence: VERSION must have completed, and isolation is
// never allowed to turn mining on.  A peer's VERSION.start_height is an
// unauthenticated fetch hint and is deliberately absent from this interface.
// Only locally validated canonical block evidence may supply a peer height.
// At height zero, distinguish an actually loaded/validated genesis from an
// empty from-genesis chain.
inline bool IsInitialDownloadAtTip(bool regtest,
                                   uint64_t local_height,
                                   bool chain_empty,
                                   size_t current_version_peers,
                                   uint64_t verified_peer_height,
                                   size_t current_outbound_sync_peers,
                                   uint64_t outbound_sync_height) {
    if (regtest) return true;
    if (current_version_peers == 0) return false;
    // Locally accepted canonical evidence can never tell us how far ahead the
    // network still is: by construction it is at or below local_height.  Use
    // two current outbound peers' announcements only as a conservative sync
    // floor.  They may delay work, but they never validate blocks or select a
    // chain; every block through the floor is still accepted locally under
    // the normal consensus rules.
    if (current_outbound_sync_peers < 2) return false;
    if (local_height < outbound_sync_height) return false;
    if (local_height < verified_peer_height) return false;
    if (local_height > 0) return true;
    return !chain_empty;  // both sides are at a validated genesis block
}

// Conservative default for memory-hard mining.  hardware_concurrency reports
// logical CPUs, and affinity/cgroup masks can expose an odd subset of an SMT
// machine.  Estimate physical cores as ceil(logical/2), then reserve one whole
// estimated core for P2P, block validation, and the UI.  Applying the estimate
// to odd counts is important: treating seven visible logical CPUs as seven
// physical cores would start six memory-hard workers and recreate the socket
// starvation this default exists to prevent.  Tiny machines retain one worker
// because no positive mining count can leave additional headroom there.  A
// user may still make an explicit --threads choice at the CLI.
inline unsigned DefaultMiningThreads(unsigned hardware_threads) {
    if (hardware_threads == 0) hardware_threads = 1;
    const unsigned physical_est = hardware_threads == 1
        ? 1
        : (hardware_threads / 2) + (hardware_threads % 2);
    return physical_est > 1 ? physical_est - 1 : 1;
}

} // namespace veld
