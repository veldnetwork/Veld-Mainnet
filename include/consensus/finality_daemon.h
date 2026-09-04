#pragma once
// finality_daemon.h — the validator-side finality loop.
//
// finality_producer.h is the LIBRARY: a FinalityVoter that signs or refuses,
// and a CertAssembler that certifies. This is the DAEMON that drives them —
// the piece that turns "the node accepts certificates" into "certificates get
// produced". Without it the whole finality layer is enforced but unreachable.
//
// It is deliberately transport-agnostic. The loop takes function objects for
// "fetch the snapshot", "gossip a vote", and "persist the lock", so it can be
// unit-tested against in-memory fakes and wired to JSON-RPC in the binary
// without the loop knowing which. That separation is why this can be tested at
// all: a loop that hard-coded a socket could only be tested against a live
// node.
//
// The safety-critical property lives here, not in the transport: the lock is
// persisted (fsync) BEFORE a precommit leaves. If the process dies between
// signing and gossiping, the lock already reflects the strongest claim the
// validator might have made — losing a vote costs liveness, producing an
// unlocked conflicting vote costs the bond. This mirrors the endorsement
// daemon's journal-before-sign discipline (veld-validator.cpp) exactly,
// because it is the same hazard: a reorg that tempts a validator to re-vote a
// conflicting target.
//
// NOT consensus-critical. Nothing here is a validation rule; a daemon that
// misbehaves produces votes that fail verification and are ignored. This can be
// rewritten without a fork.

#include "consensus/finality_producer.h"
#include "consensus/finality_snapshot.h"

#include <functional>
#include <optional>
#include <string>
#include <chrono>

namespace veld {
namespace finality {
namespace qc {

// Atomic durable validator safety state. The last signed vote is retained in
// addition to the precommit lock because PREVOTE equivocation is slashable too:
// a crash between signing and gossip must not let restart sign a different
// target in the same (epoch,phase,round). Implementations persist this complete
// frame with write-temp + fsync + rename + directory-fsync.
struct DaemonJournal {
    uint32_t version = 1;
    Lock lock;
    std::optional<SignedVote> last_vote;
};

struct DaemonWorkGrant {
    std::string binding;
    std::string token;
    std::chrono::steady_clock::time_point deadline{};

    bool Live(std::chrono::milliseconds minimum_remaining =
                  std::chrono::milliseconds::zero()) const noexcept {
        if (binding.empty() || token.empty())
            return false;
        const auto now = std::chrono::steady_clock::now();
        return now < deadline && deadline - now >= minimum_remaining;
    }
};

// What the loop needs from the outside world. Each is a seam a test can fake.
struct DaemonHooks {
    // Fetch the retained snapshot for a specific target epoch.  The target
    // epoch can lag the newest snapshot for the final two blocks of an epoch's
    // +1..+20 inclusion window, so "newest snapshot" is not sufficient here.
    std::function<std::optional<EpochSnapshot>(uint64_t)> fetch_snapshot;
    // The height of the block currently at the tip, for checkpoint scheduling.
    std::function<uint64_t()> fetch_tip_height;
    // The hash of a scheduled checkpoint height, so the daemon votes for the
    // block the canonical chain actually has there — not a height in the
    // abstract. Returns nullopt if that height is not yet on this node's chain.
    std::function<std::optional<Hash256>(uint64_t)> fetch_block_hash;
    // Obtain an opaque, short-lived authorization for this exact canonical
    // target. Production hooks obtain it from the node's authoritative work
    // admission predicate. The daemon never persists or reuses the binding.
    // This hook is called before any vote signature or journal write and again
    // immediately before submission.
    std::function<std::optional<DaemonWorkGrant>(const CheckpointRef&)> authorize_work;
    // Release a node-held active grant when journaling/signing aborts before
    // gossip consumes it.  Expiry is still the hard crash bound, but normal
    // exception paths must not delay a safety transition until that bound.
    std::function<void(const DaemonWorkGrant&)> cancel_work;
    // Gossip a signed vote using the freshly issued authorization. The node
    // rechecks the binding immediately before vote verification/storage/gossip.
    std::function<bool(const SignedVote&, const DaemonWorkGrant&)> gossip_vote;
    // Persist the complete journal durably. MUST return only after the frame is
    // on stable storage. Called BEFORE every vote is gossiped.
    std::function<bool(const DaemonJournal&)> persist_journal;
    // Load a previously persisted journal at startup, or nullopt if none.
    std::function<std::optional<DaemonJournal>()> load_journal;
    // Current retained certificate, used as the justified source and to derive
    // the next round.  Source must come from chain state, never from a daemon's
    // optimistic memory of a vote it merely sent.
    std::function<std::optional<FinalizedRecord>()> fetch_finalized;
    // Latest assembled PREVOTE certificate for this snapshot, if the local
    // node has one. Production validators poll this authenticated RPC surface;
    // the daemon still verifies the complete QC before it can unlock a
    // precommit.
    std::function<std::optional<DecodedQc>(const EpochSnapshot&)> fetch_prevote_qc;
    // Validator-local safety policy. On public mainnet this must independently
    // authorize the Veld checkpoint before ANY finality vote (including an
    // exact crash-journal re-gossip) leaves the validator. The production
    // implementation verifies all Bitcoin-anchor observations covered by the
    // target against a local Bitcoin Core active-chain view.
    std::function<bool(const CheckpointRef&)> authorize_target;
};

class DaemonGrantRelease {
  public:
    DaemonGrantRelease(const std::function<void(const DaemonWorkGrant&)>& cancel,
                       const DaemonWorkGrant& grant)
        : cancel_(cancel), grant_(grant) {}
    DaemonGrantRelease(const DaemonGrantRelease&) = delete;
    DaemonGrantRelease& operator=(const DaemonGrantRelease&) = delete;
    ~DaemonGrantRelease() {
        if (!complete_ && cancel_) {
            try {
                cancel_(grant_);
            } catch (...) {
            }
        }
    }
    void Complete() noexcept {
        complete_ = true;
    }

  private:
    const std::function<void(const DaemonWorkGrant&)>& cancel_;
    const DaemonWorkGrant& grant_;
    bool complete_{false};
};

// One tick of the finality loop. Returns true if it did anything (voted or
// advanced). Pure with respect to its hooks: a test drives it tick by tick.
//
// The daemon prevotes for the newest scheduled checkpoint its chain has
// reached, then — once it observes a prevote QC for that target — precommits,
// taking its lock first. It NEVER precommits without a prevote QC (that is how
// two conflicting certificates get built), and it NEVER votes against its lock
// without an unlock proof (the lock rule in finality_qc.h).
class FinalityDaemon {
  public:
    FinalityDaemon(std::string pubkey_hex, dilithium::SecretKey sk, uint32_t network_id,
                   Hash256 genesis_hash, DaemonHooks hooks)
        : voter_(std::move(pubkey_hex), sk), network_id_(network_id), genesis_hash_(genesis_hash),
          hooks_(std::move(hooks)) {
        // Restore the lock before doing anything else. A daemon that starts
        // fresh after a crash and forgets its lock is indistinguishable from
        // one that is lying, and the chain slashes both.
        if (hooks_.load_journal) {
            if (auto j = hooks_.load_journal()) {
                if (j->version != 1 ||
                    (j->lock.held && (!IsScheduledCheckpoint(j->lock.target.height) ||
                                      EpochOf(j->lock.target.height) != j->lock.epoch_id ||
                                      CheckpointRound(j->lock.target.height) != j->lock.round)) ||
                    (j->last_vote &&
                     (!IsScheduledCheckpoint(j->last_vote->target.height) ||
                      EpochOf(j->last_vote->target.height) != j->last_vote->epoch_id ||
                      CheckpointRound(j->last_vote->target.height) != j->last_vote->round)) ||
                    (j->last_vote && j->last_vote->pubkey_hex != voter_.pubkey_hex()) ||
                    (j->last_vote && j->last_vote->phase == Phase::PRECOMMIT &&
                     (!j->lock.held || j->lock.epoch_id != j->last_vote->epoch_id ||
                      j->lock.round != j->last_vote->round ||
                      j->lock.target != j->last_vote->target))) {
                    journal_invalid_ = true;
                } else {
                    journal_ = std::move(*j);
                    voter_.RestoreLock(journal_.lock);
                }
            }
        }
    }

    // Feed a prevote QC the daemon observed (from the node's assembler, over
    // the same transport). Held until the daemon reaches the precommit step.
    bool ObservePrevoteQc(DecodedQc qc, const EpochSnapshot& snapshot) {
        if (!VerifyDecodedQc(qc, snapshot, network_id_, genesis_hash_) ||
            qc.qc.phase != Phase::PREVOTE)
            return false;
        latest_prevote_qc_ = std::move(qc);
        return true;
    }

    bool Tick() {
        if (!hooks_.fetch_snapshot || !hooks_.fetch_tip_height || !hooks_.fetch_block_hash ||
            !hooks_.authorize_work || !hooks_.gossip_vote || !hooks_.persist_journal ||
            journal_invalid_)
            return false;

        const uint64_t tip = hooks_.fetch_tip_height();
        // Newest scheduled checkpoint at or below the tip, inside the vote
        // window. A checkpoint is votable only after it is buried by the vote
        // window, so votes land where the certificate will.
        const uint64_t target_h = NewestVotableCheckpoint_(tip);
        if (target_h == 0)
            return false;

        auto snap = hooks_.fetch_snapshot(EpochOf(target_h));
        if (!snap || !SnapshotQualifies(*snap) || snap->epoch_id != EpochOf(target_h))
            return false;

        if (hooks_.fetch_prevote_qc) {
            if (auto observed = hooks_.fetch_prevote_qc(*snap))
                (void)ObservePrevoteQc(std::move(*observed), *snap);
        }

        auto target_hash = hooks_.fetch_block_hash(target_h);
        if (!target_hash)
            return false;
        CheckpointRef target{target_h, *target_hash};
        if (EpochOf(target.height) != snap->epoch_id || !InVoteWindow(target.height, tip))
            return false;
#if defined(VELD_PUBLIC_MAINNET)
        if (!hooks_.authorize_target || !hooks_.authorize_target(target))
            return false;
#else
        if (hooks_.authorize_target && !hooks_.authorize_target(target))
            return false;
#endif

        const auto finalized = hooks_.fetch_finalized ? hooks_.fetch_finalized() : std::nullopt;
        const CheckpointRef source = finalized ? finalized->target : CheckpointRef{};
        const uint32_t round = CheckpointRound(target.height);

        bool extends_lock = false;
        const Lock held = voter_.lock();
        if (held.held) {
            if (target != held.target && target.height > held.target.height) {
                auto locked_hash = hooks_.fetch_block_hash(held.target.height);
                extends_lock = locked_hash && *locked_hash == held.target.hash;
            }
        }

        // Validate and honor the crash journal before producing anything new.
        // The ordering is lexicographic across (epoch, round), not just within
        // one epoch.  Round resets to zero at an epoch boundary: after signing
        // epoch E+1/round 0, a bounded reorg can expose epoch E/round 23 again.
        // Treating the epochs as unrelated would overwrite the only durable
        // memory of the newer vote and could sign a slashable sibling in the
        // older frame.  Older frames always fail closed; an equal frame permits
        // only the exact claim and only the PREVOTE -> PRECOMMIT progression.
        if (journal_.last_vote) {
            const SignedVote& last = *journal_.last_vote;
            std::optional<EpochSnapshot> retained_last_snapshot;
            const EpochSnapshot* last_snapshot = &*snap;
            if (last.epoch_id != snap->epoch_id) {
                retained_last_snapshot = hooks_.fetch_snapshot(last.epoch_id);
                if (!retained_last_snapshot || !SnapshotQualifies(*retained_last_snapshot) ||
                    retained_last_snapshot->epoch_id != last.epoch_id) {
                    journal_invalid_ = true;
                    return false;
                }
                last_snapshot = &*retained_last_snapshot;
            }
            if (!VerifyVote(last, *last_snapshot, network_id_, genesis_hash_)) {
                journal_invalid_ = true;
                return false;
            }

            const bool same_frame = last.epoch_id == snap->epoch_id && last.round == round;
            if (!same_frame &&
                !ConsensusRoundNewer(snap->epoch_id, round, last.epoch_id, last.round))
                return false;

            const bool same_claim = same_frame && last.source == source && last.target == target;
            if (same_frame && !same_claim)
                return false;
            if (same_claim && last.phase == Phase::PRECOMMIT) {
                if (!journal_vote_delivered_) {
                    auto grant = hooks_.authorize_work(last.target);
                    if (!grant)
                        return false;
                    DaemonGrantRelease release(hooks_.cancel_work, *grant);
                    if (!grant->Live()) {
                        return false;
                    }
                    journal_vote_delivered_ = hooks_.gossip_vote(last, *grant);
                    if (journal_vote_delivered_)
                        release.Complete();
                    return journal_vote_delivered_;
                }
                return false; // already made the strongest vote for this claim
            }
            if (same_claim && last.phase == Phase::PREVOTE &&
                !(latest_prevote_qc_ && latest_prevote_qc_->qc.epoch_id == snap->epoch_id &&
                  latest_prevote_qc_->qc.source == source &&
                  latest_prevote_qc_->qc.target == target &&
                  latest_prevote_qc_->qc.round == round)) {
                // Crash may have happened after durable write and before send.
                // Re-gossip the exact signed bytes once; never sign a sibling.
                if (!journal_vote_delivered_) {
                    auto grant = hooks_.authorize_work(last.target);
                    if (!grant)
                        return false;
                    DaemonGrantRelease release(hooks_.cancel_work, *grant);
                    if (!grant->Live()) {
                        return false;
                    }
                    journal_vote_delivered_ = hooks_.gossip_vote(last, *grant);
                    if (journal_vote_delivered_)
                        release.Complete();
                    return journal_vote_delivered_;
                }
                return false;
            }
        }

        // ---- precommit step: only with a matching prevote QC --------------
        if (latest_prevote_qc_ && latest_prevote_qc_->qc.epoch_id == snap->epoch_id &&
            latest_prevote_qc_->qc.source == source && latest_prevote_qc_->qc.target == target &&
            latest_prevote_qc_->qc.round == round) {
            // Refresh immediately before the signing primitive. This closes
            // any state change that occurred while snapshots, QCs, and the
            // crash journal were being verified above.
            auto grant = hooks_.authorize_work(target);
            if (!grant)
                return false;
            DaemonGrantRelease release(hooks_.cancel_work, *grant);
            if (!grant->Live(std::chrono::milliseconds(1000))) {
                return false;
            }
            auto pc = voter_.Precommit(*snap, round, source, target, *latest_prevote_qc_,
                                       network_id_, genesis_hash_);
            if (pc) {
                if (!grant->Live()) {
                    return false;
                }
                // Persist the complete lock+vote frame BEFORE gossiping.
                DaemonJournal next{1, voter_.lock(), *pc};
                if (!hooks_.persist_journal(next)) {
                    return false;
                }
                journal_ = std::move(next);
                journal_vote_delivered_ = false;
                if (!grant->Live()) {
                    return false;
                }
                const bool sent = hooks_.gossip_vote(*pc, *grant);
                if (sent)
                    release.Complete();
                journal_vote_delivered_ = sent;
                latest_prevote_qc_.reset();
                return sent;
            }
            return false;
        }

        // ---- prevote step -------------------------------------------------
        auto grant = hooks_.authorize_work(target);
        if (!grant)
            return false;
        DaemonGrantRelease release(hooks_.cancel_work, *grant);
        if (!grant->Live(std::chrono::milliseconds(1000))) {
            return false;
        }
        auto pv =
            voter_.Prevote(*snap, round, source, target,
                           /*unlock_proof*/ std::nullopt, extends_lock, network_id_, genesis_hash_);
        if (!pv) {
            return false;
        }
        if (!grant->Live()) {
            return false;
        }
        DaemonJournal next{1, voter_.lock(), *pv};
        if (!hooks_.persist_journal(next)) {
            return false;
        }
        journal_ = std::move(next);
        journal_vote_delivered_ = false;
        if (!grant->Live()) {
            return false;
        }
        const bool sent = hooks_.gossip_vote(*pv, *grant);
        if (sent)
            release.Complete();
        journal_vote_delivered_ = sent;
        return sent;
    }

    const FinalityVoter& voter() const {
        return voter_;
    }

  private:
    // Newest checkpoint height <= tip that is buried by at least the vote
    // window (so the block is stable enough that honest nodes agree on its
    // hash). Zero if none qualifies yet.
    uint64_t NewestVotableCheckpoint_(uint64_t tip) const {
        if (tip == 0)
            return 0;
        // Inclusion is (target,target+20]. At an exact checkpoint height the
        // new checkpoint is not yet includable, so round down tip-1.
        const uint64_t cp = ((tip - 1) / CHECKPOINT_INTERVAL) * CHECKPOINT_INTERVAL;
        if (cp == 0)
            return 0;
        if (!IsScheduledCheckpoint(cp))
            return 0;
        return cp;
    }

    FinalityVoter voter_;
    uint32_t network_id_;
    Hash256 genesis_hash_;
    DaemonHooks hooks_;

    DaemonJournal journal_;
    bool journal_invalid_ = false;
    bool journal_vote_delivered_ = false;
    std::optional<DecodedQc> latest_prevote_qc_;
};

} // namespace qc
} // namespace finality
} // namespace veld
