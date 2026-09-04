#pragma once
// Retained locked-QC finality state. Finalized records and their carrier blocks
// are committed to the state digest and reconstructed byte-identically during
// replay. Mutations depend only on consensus state, never clocks, node-local
// flags, or orphan caches.

#include "finality_qc.h"
#include "finality_snapshot.h"
#include "finality_votes.h"
#include "state_digest.h"

#include <map>
#include <mutex>
#include <optional>
#include <vector>

namespace veld {
namespace finality {
namespace qc {

constexpr const char* DOMAIN_STATE = "VELD_FINALITY_STATE_v1|";

// How many epoch snapshots to retain. Votes are only countable inside their
// target's 20-block inclusion window, and an epoch is 480 blocks, so the
// previous epoch's set can still be needed while the current one is live.
// Two is sufficient; more is dead weight in the digest.
constexpr size_t SNAPSHOT_RETENTION = 2;

class FinalityState {
  public:
    // ---- activation state machine ---------------------------------------
    // Consecutive qualified epochs observed. Finality goes live at 2 (960
    // blocks / 48h); anchors follow one further qualified epoch.
    //
    // NOTE the reset semantics: a set that falls below the floor RESTARTS this
    // count. It does not resume. Two consecutive qualified epochs means two
    // consecutive, not two cumulative — a chain that flickers in and out of
    // qualification has not demonstrated the stability the warm-up is there to
    // measure.
    uint32_t consecutive_qualified_epochs = 0;
    // "Ever" is monotonic within one canonical branch, not process-lifetime
    // memory. Startup and accepted-reorg replay reconstruct it from the selected
    // branch, as required for branch-relative mint validity. Once a retained QC
    // exists its exact carrier gate prevents a reorg from erasing that history.
    bool finality_ever_active = false;
    bool ever_promoted_anchor = false;

    // ---- retained artifacts ---------------------------------------------
    std::map<uint64_t, EpochSnapshot> snapshots; // epoch_id -> frozen set
    FinalizedRecord record;                      // retained finality mark

    // Observe an epoch boundary. `snap` must have been built from canonical
    // state at epoch_start-1 (see finality_snapshot.h on why it cannot be
    // rebuilt retroactively).
    bool OnEpochBoundary(const EpochSnapshot& snap) {
        if (!SnapshotWellFormed(snap))
            return false;
        auto existing = snapshots.find(snap.epoch_id);
        if (existing != snapshots.end()) {
            const EpochSnapshot& prior = existing->second;
            // Exact duplicate delivery is an idempotent no-op. A conflicting
            // snapshot for an already-observed epoch is a consensus failure,
            // never an overwrite followed by a second warm-up increment.
            return prior.snapshot_height == snap.snapshot_height &&
                   prior.total_weight == snap.total_weight && prior.root == snap.root;
        }
        if (!snapshots.empty() && snap.epoch_id <= snapshots.rbegin()->first)
            return false;
        snapshots[snap.epoch_id] = snap;
        while (snapshots.size() > SNAPSHOT_RETENTION)
            snapshots.erase(snapshots.begin());

        if (SnapshotQualifies(snap)) {
            if (consecutive_qualified_epochs != UINT32_MAX)
                ++consecutive_qualified_epochs;
        } else {
            consecutive_qualified_epochs = 0; // restart, not pause
        }
        if (consecutive_qualified_epochs >= 2)
            finality_ever_active = true;
        return true;
    }

    bool FinalityActive() const {
        return consecutive_qualified_epochs >= 2;
    }

    // Anchors need one FURTHER qualified epoch beyond finality activation.
    bool AnchorWarmupComplete() const {
        return consecutive_qualified_epochs >= 3;
    }

    // Observe a precommit certificate carried by a canonical block.
    //
    // Returns true iff the retained record advanced. Any non-advancing
    // recertification — including the same certificate replayed in the same or
    // a later carrier — returns false and is consensus-invalid at the caller.
    // Startup/reorg replay restores the parent state before applying each
    // canonical carrier, so deterministic replay does not require accepting a
    // duplicate against an already-advanced record.
    bool OnCertificate(const QuorumCert& qc, const CheckpointRef& carrier,
                       const Hash256& canonical_target_hash) {
        auto it = snapshots.find(qc.epoch_id);
        if (it == snapshots.end())
            return false; // set not retained
        if (!FinalityActive())
            return false; // warm-up incomplete
        if (qc.target.hash != canonical_target_hash)
            return false;

        // Linear locked-QC transition.  The first certificate is round zero
        // with a null source.  Thereafter every certificate names the exact
        // retained target as its justified source.  Rounds are monotonic
        // inside an epoch and reset when the immutable snapshot changes.
        if (record.IsNull()) {
            if (!qc.source.IsNull())
                return false;
        } else {
            if (qc.source != record.target)
                return false;
            if (qc.target.height <= record.target.height)
                return false;
            if (qc.epoch_id < record.epoch_id)
                return false;
        }

        auto candidate = Finalize(qc, it->second, carrier);
        if (!candidate)
            return false;
        if (!RecordSupersedes(*candidate, record))
            return false;

        record = *candidate;
        return true;
    }

    // The finalized high-water mark. Zero means "this chain has finalized
    // nothing", which is the honest state for a chain that has not.
    uint64_t FinalizedHeight() const {
        return record.IsNull() ? 0 : record.target.height;
    }

    // May this reorg proceed? Delegates to the pure rule. `branch_has` must
    // resolve the COMPLETE side path: the delivered tip's height is
    // insufficient because a side branch can be registered while shorter and
    // become eligible only after a later extension.
    bool ReorgPermitted(uint64_t common_ancestor_height,
                        const std::function<bool(uint64_t, const Hash256&)>& branch_has) const {
        if (record.IsNull())
            return true;
        return ReorgAllowed(record, common_ancestor_height, branch_has);
    }

    // Additive finality+Bitcoin security milestone. Peg launch permission uses
    // the seven-validator activation latch but does not require an anchor.
    bool SecurityMilestoneComplete() const {
        return qc::SecurityMilestoneComplete(finality_ever_active, ever_promoted_anchor);
    }

    // Consensus digest of the finality state.
    //
    // Every field here changes subsequent validation behavior and therefore
    // cannot be omitted from a consensus-state measurement:
    //
    //   record        — the mark and its canonical carrier.
    //   snapshots     — the denominators. Two nodes with different retained
    //                   sets compute different quorums from identical votes.
    //   warm-up count — determines whether the NEXT certificate is accepted at
    //                   all, so two nodes disagreeing on it diverge on the
    //                   first certificate after a boundary.
    //   the ever_* flags — they gate the peg. They are monotonic, which makes
    //                   them cheap to commit and impossible to walk back.
    Hash256 Digest() const {
        namespace sd = ::veld::state_digest;
        std::vector<uint8_t> body;
        sd::put_u32_le(body, 1); // encoding version
        sd::put_u32_le(body, consecutive_qualified_epochs);
        sd::put_u8(body, finality_ever_active ? 1 : 0);
        sd::put_u8(body, ever_promoted_anchor ? 1 : 0);

        // std::map iterates in key order, so this is already canonical. Stated
        // explicitly because the moment it becomes an unordered container, two
        // honest nodes compute different digests from identical state.
        sd::put_u32_le(body, (uint32_t)snapshots.size());
        for (const auto& [epoch_id, s] : snapshots) {
            sd::put_u64_le(body, epoch_id);
            sd::put_u64_le(body, s.snapshot_height);
            sd::put_u64_le(body, s.total_weight);
            sd::put_bytes(body, s.root.data(), s.root.size());
        }

        sd::put_u8(body, record.IsNull() ? 0 : 1);
        if (!record.IsNull()) {
            sd::put_bytes(body, RecordDigest(record).data(), 32);
        }
        return sd::sha256_domain(DOMAIN_STATE, body);
    }

    // Rollback support. The whole struct is value-copyable, so a block-reject
    // or reorg restore is a verbatim assignment — the same discipline
    // StateSnapshot already uses for the token/AMM ledgers.
    void Reset() {
        consecutive_qualified_epochs = 0;
        finality_ever_active = false;
        ever_promoted_anchor = false;
        snapshots.clear();
        record = FinalizedRecord{};
    }
};

} // namespace qc
} // namespace finality
} // namespace veld
