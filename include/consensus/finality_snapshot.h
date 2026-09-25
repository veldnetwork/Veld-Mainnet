#pragma once
// Build the immutable validator set used for an epoch's finality threshold.
// The canonical set is derived at epoch_start - 1, committed by root, and held
// constant for the entire epoch.
//
// Membership records retain historical activation state but not historical
// bond balances. Rebuilding an old snapshot after a withdrawal could therefore
// change its denominator. Construct each snapshot once at the boundary and
// retain it in consensus state. This function is pure with respect to registry
// state; the caller must invoke it at the required snapshot height.

#include "finality_qc.h"
#include "validators.h"

#include <algorithm>
#include <string>
#include <vector>

namespace veld {
namespace finality {
namespace qc {

// Commitment to an ML-DSA-65 public key. Matches the house convention already
// used for endorsements (ValidatorRegistry::EndorsementFieldCommitment): the
// digest is over the canonical HEX STRING bytes, domain-separated. Reusing it
// keeps one commitment scheme in the codebase rather than two that look alike.
// Is this record a qualified finality validator as of `snapshot_height`?
//
// Qualification rules:
//
//   maturity      — registration must predate the epoch by a full epoch, so a
//                   key cannot be registered and vote on the same checkpoint.
//   custodial     — vote weight is slashable bond, never liquid stake.
//   bond floor    — below the floor a key carries no weight at all. It is not
//                   scaled down; it is absent.
//   not slashed   — as of the snapshot height, using the record's own history.
//   not exited    — deregistration before the snapshot removes membership.
inline bool QualifiedAt(const ValidatorRecord& r, uint64_t snapshot_height) {
    if (!r.bond_custodial)
        return false;
    if (r.bond_units < BOND_PER_KEY_UNITS)
        return false;
    if (r.registered_height == 0)
        return false;
    if (r.registered_height > snapshot_height ||
        snapshot_height - r.registered_height < REGISTRATION_MATURITY)
        return false;
    if (r.slashed && r.slashed_at_height != 0 && r.slashed_at_height <= snapshot_height)
        return false;
    if (r.slashed && r.slashed_at_height == 0)
        return false; // slashed, height unknown: exclude
    if (r.deregistered_at_height != 0 && r.deregistered_at_height <= snapshot_height)
        return false;
    if (!r.active)
        return false;
    return true;
}

// Build the epoch snapshot while canonical state equals `snapshot_height`
// because bond_units is not historically reconstructible.
//
// Weight is fixed at BOND_PER_KEY_UNITS for every member: the bond is both the
// minimum and the cap, so all keys carry identical weight and over-bonding buys
// no influence. This makes quorum a simple count and removes any incentive to
// concentrate. Deliberate: with 7 equal keys, strictly-greater-than-two-thirds
// is 5, and fault tolerance is exactly 2.
inline EpochSnapshot BuildEpochSnapshot(const ValidatorRegistry& reg, uint64_t epoch_id,
                                        uint64_t snapshot_height) {
    EpochSnapshot s;
    s.epoch_id = epoch_id;
    s.snapshot_height = snapshot_height;

    // GetAllValidatorRecords, not GetValidators: the latter pre-filters on
    // `active`, and we need every record so QualifiedAt can apply the full
    // as-of-height rule rather than inheriting someone else's notion of
    // membership.
    for (const auto& r : reg.GetAllValidatorRecords()) {
        if (!QualifiedAt(r, snapshot_height))
            continue;
        SnapshotEntry e;
        e.pubkey_commit = PubkeyCommit(r.pubkey_hex);
        e.address = r.address;
        e.registered_height = r.registered_height;
        e.weight = BOND_PER_KEY_UNITS; // min == cap
        e.pubkey_hex = r.pubkey_hex;   // resolvable, not re-transmitted
        s.entries.push_back(e);
    }

    // Canonical order: by pubkey commitment. Sort-before-hash discipline —
    // unordered_map iteration order must never reach the root, or two honest
    // nodes compute different set roots from identical state. The bitmap in
    // every QC indexes THIS order, which is why it must be total and stable.
    std::sort(s.entries.begin(), s.entries.end(),
              [](const SnapshotEntry& a, const SnapshotEntry& b) {
                  return a.pubkey_commit < b.pubkey_commit;
              });

    // Duplicate keys would let one signer be counted twice. The registry is
    // keyed by pubkey so this should be impossible; assert it anyway, because
    // the cost of being wrong is a forged quorum.
    s.entries.erase(std::unique(s.entries.begin(), s.entries.end(),
                                [](const SnapshotEntry& a, const SnapshotEntry& b) {
                                    return a.pubkey_commit == b.pubkey_commit;
                                }),
                    s.entries.end());

    s.total_weight = 0;
    for (const auto& e : s.entries)
        s.total_weight += e.weight;
    s.root = SnapshotRoot(s.entries, s.epoch_id, s.snapshot_height, s.total_weight);
    return s;
}

// Would this snapshot qualify finality for its epoch?
//
// Note what this does NOT do: it does not activate anything. A qualified
// snapshot is necessary, not sufficient — the activation state machine
// additionally requires two consecutive qualified epochs (960 blocks) before
// finality goes live, and a further qualified epoch before anchors do. A single
// good snapshot after a bad one restarts that count; it does not resume it.
inline bool SnapshotQualifies(const EpochSnapshot& s) {
    return SnapshotWellFormed(s) && s.Qualified();
}

} // namespace qc
} // namespace finality
} // namespace veld
