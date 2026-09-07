#pragma once

// Bitcoin anchor activation and proof-admission bounds. Activation derives
// from retained finality state, never a per-node configuration flag.
// Anchoring requires an exact finalized target so competing proof-of-work
// branches cannot acquire conflicting permanent floors before finality.
// Minting and redemption have separate launch and liveness gates.

#include "core/constants.h"     // BTCVELD_ANCHOR_BTC_CONFS
#include "core/hash.h"
#include "finality_qc.h"
#include <cstdint>

namespace veld {

// Anchors require a retained, independently verified finalized height. The
// caller also enforces the chain-derived finality warm-up before admission.
inline bool BtcVeldAnchorActive(uint64_t finalized_height) {
    return finalized_height > 0;
}

// An anchor for Veld height H may be carried at height C when H <= C and
// C - H <= 1000. This allows time for Bitcoin inclusion and confirmations
// while bounding the age of accepted proofs. The proof must identify an
// exact finalized Veld block; the window does not grant finality.
constexpr uint64_t BTCVELD_ANCHOR_ACCEPT_WINDOW = 1000;

inline bool BtcVeldAnchorTargetInWindow(uint64_t target_height,
                                        uint64_t carrying_height) {
    if (target_height > carrying_height) return false;   // cannot precede its target
    return (carrying_height - target_height) <= BTCVELD_ANCHOR_ACCEPT_WINDOW;
}

// An anchor is valid only for an exactly identified finalized block. This keeps
// operational submission policy outside the consensus trust boundary and
// prevents unfinalized partition or secret-fork tips from being anchored.
inline bool BtcVeldAnchorTargetValid(const finality::qc::FinalizedRecord& rec,
                                     uint64_t target_height,
                                     const Hash256& target_hash,
                                     uint64_t carrying_height) {
    if (rec.IsNull())                      return false;   // nothing finalized yet
    if (!BtcVeldAnchorActive(rec.target.height)) return false;
    if (target_height == 0)                return false;   // genesis is not a checkpoint
    if (target_height > rec.target.height) return false;   // not yet finalized
    if (!BtcVeldAnchorTargetInWindow(target_height, carrying_height)) return false;
    // The target must BE the finalized block. Binding the exact hash is what
    // stops a fork satisfying the rule with a different block at that height.
    if (target_height == rec.target.height) return target_hash == rec.target.hash;
    return true;   // ancestor of a finalized block; caller proves canonicity
}

}  // namespace veld
