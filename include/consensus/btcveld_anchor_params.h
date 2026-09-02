#pragma once
// btcveld_anchor_params.h — btcVELD Layer-2 Bitcoin anchoring: activation.
//
// Activation is derived from chain state rather than a configured height.
//
// What this replaces, and why:
//
//   BTCVELD_ANCHOR_ACTIVATION_HEIGHT was 1 — "ARMED on fresh private-testnet
//   genesis (test anchoring E2E: small pool seed + small anchor
//   hot-wallet + low anchor frequency to bound real-BTC fees)" — while
//   BTCVELD_FINALITY_ACTIVATION_HEIGHT was 0. A July 5 private-testnet
//   convenience was sitting in the August 30 mainnet template, and both
//   platform code-readiness gates failed closed on exactly that pair.
//
//   The retired comment defended the pairing as "anti-front-run inert while
//   finality dormant". That is the defect, not a mitigation. With anchors live
//   and finality dormant every recordable anchor targets a block still inside
//   the reorg horizon; during a partition two valid Bitcoin proofs can bind
//   competing Veld hashes and each side then rejects the other regardless of
//   work. An anchor without finality does not merely fail to help — it cements
//   a split that work would otherwise resolve.
//
// This avoids profile drift and makes activation depend on an observable
// consensus condition:
//
//     anchors active       <=>  the chain has finalized a real block
//     security milestone  <=>  finality was active AND an anchor was promoted
//
// Both facts live in the consensus state digest, so the predicate is a pure
// function of chain state and replays identically on every node. This milestone
// does not authorize initial mint/redeem/AMM economics; those use the compiled
// fresh-genesis launch/liveness gate.
//
// A consensus rule is a pure function of chain state, never a per-node flag.

#include "core/constants.h"     // BTCVELD_ANCHOR_BTC_CONFS
#include "core/hash.h"
#include "finality_qc.h"
#include <cstdint>

namespace veld {

// R3: state-derived activation. `finalized_height` comes from the RETAINED
// certificate record (finality::qc::FinalizedRecord), never from recomputing the
// mark over currently-visible votes — a mark that can be recomputed can be
// erased by reorganizing whichever block carried the votes. Genesis is never
// finalizable, so > 0 is the honest test for "this chain has finalized
// something".
inline bool BtcVeldAnchorActive(uint64_t finalized_height) {
    return finalized_height > 0;
}

// R2: the accept window. An anchor targeting Veld height H carried at height C
// is accepted only if H >= C - BTCVELD_ANCHOR_ACCEPT_WINDOW.
//
// Was an effective 99 against MAX_REORG_DEPTH = 100: the entire accept window
// lay INSIDE the reorg horizon, so every recordable anchor targeted a
// reorganizable block.
//
// Widening is correct, not a loosening. Under R1 the safety property is
// FINALIZED, not RECENT — a finalized checkpoint 500 blocks back is exactly as
// immovable as one 30 blocks back. Recency never protected the anchor; under
// the old window recency was what endangered it.
//
// Widening is also necessary. The round trip is: finalize (up to one 20-block
// checkpoint interval) -> broadcast the BTC transaction -> wait
// BTCVELD_ANCHOR_BTC_CONFS confirmations -> a submitter carries the SPV proof
// back onto Veld. That is ~2 hours in good weather against a 99-block window
// only ~5 hours wide at the 180s target. veld_anchord.py was built to "anchor
// at cheap dips, bounded by a hard deadline"; under the old window that
// fee-patient strategy routinely produced a stale proof, rejected AFTER its
// Bitcoin fee was already spent. The old window and the shipped daemon were
// mutually incompatible.
//
// A window still exists so nobody spams anchors at ancient heights. 1,000
// blocks is ~50 hours: patience becomes affordable, spam does not.
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
