#pragma once
// Locked-QC two-phase validator finality. Quorum certificates are committed to
// consensus state and remain authoritative across any reorganization that does
// not supply an equal-or-higher certificate.
//
// The compiled profile uses 480-block epochs, snapshots at epoch_start - 1,
// 480-block registration maturity, 20-block checkpoints and inclusion windows,
// seven keys capped at 10,000 VELD each, and a quorum strictly above two-thirds
// of snapshotted bond weight.
//
// Functions in this header are pure: node-local state, clocks, I/O, and orphan
// caches are not consensus inputs.

#include "../core/hash.h"
#include "../core/constants.h"
#include "state_digest.h"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

namespace veld {
namespace finality {
// Sub-namespace `qc` during migration. btcveld_finality.h still defines the
// REPLACED vote-derived design (finality::IsSupermajority with a non-strict
// >= bar, finality::ComputeFinalHeight which recomputes the mark from live
// votes and is therefore erasable). Both cannot occupy one namespace: the
// names collide and the SEMANTICS differ — this bar is strictly greater than
// two thirds, and this mark is an artifact rather than a derivation. Keeping
// them distinct makes every call site state which design it means, instead of
// silently binding to whichever header was included first.
namespace qc {

// ---------------------------------------------------------------- domains
// Domain separation is mandatory: a snapshot root, a vote preimage, a QC
// commitment and a finalized record must never collide even if their bodies
// serialise identically.
constexpr const char* DOMAIN_SNAPSHOT = "VELD_FINALITY_SNAPSHOT_v1|";
constexpr const char* DOMAIN_VOTE = "VELD_FINALITY_VOTE_v1|";
constexpr const char* DOMAIN_QC = "VELD_FINALITY_QC_v1|";
constexpr const char* DOMAIN_RECORD = "VELD_FINALITY_RECORD_v1|";
// Commitment to an ML-DSA-65 public key inside a snapshot entry. Distinct
// domain so a pubkey commitment can never be confused with a set root, a vote,
// a QC, or a finalized record even if their bodies serialise identically.
constexpr const char* DOMAIN_PUBKEY = "VELD_FINALITY_PUBKEY_v1|";

// ---------------------------------------------------------------- profile
constexpr uint64_t EPOCH_BLOCKS = BLOCKS_PER_DAY;             // 480 / 24h
constexpr uint64_t CHECKPOINT_INTERVAL = BLOCKS_PER_DAY / 24; // 20 / 1h
constexpr uint64_t VOTE_WINDOW_BLOCKS = CHECKPOINT_INTERVAL;  // +1 .. +20
constexpr uint64_t REGISTRATION_MATURITY = EPOCH_BLOCKS;      // one epoch
constexpr uint64_t MIN_VALIDATOR_COUNT = 7;
// Maximum equal-weight snapshot whose strict >2/3 ML-DSA QC fits the QB2
// 7.5MB block-carrier budget. This is a representability ceiling, not a
// selection rule: an epoch with more qualifying keys fails closed instead of
// claiming to be finalizable when no valid certificate can be carried.
constexpr uint64_t MAX_FINALITY_VALIDATOR_COUNT = 3398;
constexpr uint64_t BOND_PER_KEY_UNITS = 10000ULL * VELD_UNITS; // min AND cap
constexpr uint64_t TOTAL_BOND_FLOOR = MIN_VALIDATOR_COUNT * BOND_PER_KEY_UNITS;

// New btcVELD exposure pauses after three missed checkpoints. AMM swaps continue
// during a later finality stall; irreversible redemption payout waits for
// finality.
constexpr uint64_t FINALITY_LIVENESS_WINDOW = 60;
constexpr uint64_t FINALITY_EQUIV_EVIDENCE_WINDOW = 90 * EPOCH_BLOCKS;
constexpr uint64_t FINALITY_CLEAN_EXIT_WINDOW = FINALITY_EQUIV_EVIDENCE_WINDOW;
constexpr uint64_t FINALITY_MEMBERSHIP_RETENTION_EPOCHS = 92;

// Quorum is STRICTLY greater than two thirds. With 7 equal keys this is 5.
// Note the strictness: `>= 2/3` would admit exactly 2/3, and two disjoint
// exactly-2/3 sets can both exist over a 3-way partition of weight.
constexpr uint64_t THRESHOLD_NUM = 2;
constexpr uint64_t THRESHOLD_DEN = 3;

enum class Phase : uint8_t { PREVOTE = 1, PRECOMMIT = 2 };

// Chain identity for the vote preimage. Matches the endorsement V2 convention
// exactly (validators.h:1219): a compile-time network byte, 0x4D mainnet 'M' /
// 0x54 testnet 'T', paired with the ASCII genesis hash.
//
// Reusing it rather than inventing a parallel scheme is deliberate. That
// convention exists because V1 endorsements omitted chain binding, which let
// two legitimate testnet endorsements at height H be lifted into a mainnet
// SLASH — the mainnet branch verified them cryptographically because the
// preimages were byte-identical in shape. Finality votes are exactly the same
// hazard with a bigger blast radius: a validator registered on both chains
// would otherwise produce testnet votes liftable into mainnet equivocation
// evidence. Disjoint network bytes AND disjoint genesis hashes make that
// impossible in two independent ways.
#ifdef VELD_MAINNET_POW
constexpr uint32_t NETWORK_ID = 0x4D; // 'M'
#else
constexpr uint32_t NETWORK_ID = 0x54; // 'T'
#endif

// ---------------------------------------------------------------- types

// A checkpoint is always identified by both height and hash so a fork cannot
// substitute a different block at the finalized height.
struct CheckpointRef {
    uint64_t height = 0;
    Hash256 hash{};

    bool operator==(const CheckpointRef& o) const {
        return height == o.height && hash == o.hash;
    }
    bool operator!=(const CheckpointRef& o) const {
        return !(*this == o);
    }
    bool IsNull() const {
        if (height != 0)
            return false;
        for (uint8_t b : hash)
            if (b)
                return false;
        return true;
    }
};

struct SnapshotEntry {
    Hash256 pubkey_commit{}; // domain-separated hash of pubkey_hex
    std::string address;     // validator address (V-prefixed P2PKH)
    uint64_t registered_height = 0;
    uint64_t weight = 0; // CAPPED slashable bond, not stake

    // The full ML-DSA-65 key. Carried so the snapshot is self-sufficient for
    // verification: a vote must NOT repeat 3,904 hex bytes of public key —
    // that is exactly what "made the rolling finality/reward window grow by
    // gigabytes under otherwise-valid traffic" (validators.h:43). A vote names
    // its signer by the 32-byte commitment; the key is resolved here.
    //
    // Deliberately NOT in the snapshot root: the ROOT commits pubkey_commit,
    // and the commitment binds the key. A node holding a wrong key computes a
    // different commitment, fails the membership lookup, and cannot verify;
    // so the key needs no separate commitment of its own.
    std::string pubkey_hex;
};

// The immutable per-epoch validator set. Derived once at the epoch boundary
// from state at snapshot_height, then frozen. Joining, deregistering, adding
// or removing stake, and over-bonding during an epoch do not alter the active
// epoch's denominator.
struct EpochSnapshot {
    uint64_t epoch_id = 0;
    uint64_t snapshot_height = 0;
    std::vector<SnapshotEntry> entries; // canonical order: by pubkey_commit
    uint64_t total_weight = 0;
    Hash256 root{};

    bool Qualified() const {
        return entries.size() >= MIN_VALIDATOR_COUNT &&
               entries.size() <= MAX_FINALITY_VALIDATOR_COUNT && total_weight >= TOTAL_BOND_FLOOR;
    }
};

// A quorum certificate: the artifact. Once built and carried canonically, this
// is what consensus retains — not the votes it was built from.
struct QuorumCert {
    uint64_t epoch_id = 0;
    Hash256 set_root{};
    Phase phase = Phase::PREVOTE;
    uint32_t round = 0;
    CheckpointRef source;        // justified source (null at genesis of finality)
    CheckpointRef target;        // scheduled checkpoint
    std::vector<uint8_t> bitmap; // signer bitmap over snapshot entry order
    uint64_t weight = 0;         // summed snapshotted capped bond of signers

    bool IsNull() const {
        return weight == 0 && target.IsNull();
    }
};

// What consensus stores and digests. Every field is load-bearing:
//   target  — F and its EXACT hash
//   carrier — the canonical block that carried the certificate, and its hash.
//             This field prevents certificate erasure during reorganization.
struct FinalizedRecord {
    uint64_t epoch_id = 0;
    CheckpointRef target;
    Hash256 set_root{};
    uint32_t round = 0;
    Phase phase = Phase::PRECOMMIT;
    Hash256 cert_commit{}; // commitment to the QuorumCert
    CheckpointRef carrier; // C and its exact block hash
    uint64_t retention_floor = 0;

    bool IsNull() const {
        return target.IsNull();
    }
};

// A validator's persisted lock. The heart of the two-phase safety argument:
// having precommitted a target, a validator will not prevote a conflicting one
// unless it can prove the network moved on without it.
struct Lock {
    bool held = false;
    uint64_t epoch_id = 0;
    uint32_t round = 0;
    CheckpointRef target;
};

// ---------------------------------------------------------------- quorum

// Strictly greater than 2/3 of total weight. Overflow-safe via 128-bit; never
// divides. Zero total weight => nothing is ever final (fail-closed).
inline bool IsSupermajority(uint64_t weight, uint64_t total_weight) {
    if (total_weight == 0)
        return false;
    return (unsigned __int128)weight * THRESHOLD_DEN >
           (unsigned __int128)total_weight * THRESHOLD_NUM;
}

// Only exact multiples of the checkpoint interval are valid targets. Height 0
// is never a checkpoint.
inline bool IsScheduledCheckpoint(uint64_t height) {
    return height != 0 && (height % CHECKPOINT_INTERVAL) == 0;
}

// Round identity is consensus-derived from the target checkpoint, never from
// node-local progress. This gives every checkpoint in an epoch a unique round,
// resets naturally at the epoch boundary, and prevents a stalled daemon from
// signing two different checkpoint hashes in the same slashable round.
inline uint32_t CheckpointRound(uint64_t height) {
    return static_cast<uint32_t>((height % EPOCH_BLOCKS) / CHECKPOINT_INTERVAL);
}

// Epoch is the high-order part of a consensus round.  CheckpointRound resets
// to zero at every epoch boundary, so comparing the uint32 round alone can
// mistake a newer epoch for an older round and let a stale QC overwrite a
// newer lock.
inline bool ConsensusRoundNewer(uint64_t epoch, uint32_t round, uint64_t prior_epoch,
                                uint32_t prior_round) {
    return epoch > prior_epoch || (epoch == prior_epoch && round > prior_round);
}

// A justified source is either the unique null reference or an earlier,
// scheduled checkpoint.  In particular, height zero with a non-zero hash and
// an unscheduled/non-earlier source are not finality votes.  Keep this as one
// predicate so certificate intake and equivocation evidence cannot disagree
// over whether the signed bytes describe a valid claim.
inline bool SourceRefWellFormed(const CheckpointRef& source, const CheckpointRef& target) {
    if (source.IsNull())
        return true;
    return source.height != 0 && IsScheduledCheckpoint(source.height) &&
           source.height < target.height;
}

// A vote for checkpoint `target` must be included in (target, target+20].
// Outside that window it counts zero — it is not an error, it is not evidence,
// it simply has no weight.
inline bool InVoteWindow(uint64_t target_height, uint64_t inclusion_height) {
    return inclusion_height > target_height &&
           inclusion_height <= target_height + VOTE_WINDOW_BLOCKS;
}

// Which epoch owns a height, and where that epoch's snapshot is taken.
inline uint64_t EpochOf(uint64_t height) {
    return height / EPOCH_BLOCKS;
}
inline uint64_t EpochStart(uint64_t epoch_id) {
    return epoch_id * EPOCH_BLOCKS;
}
inline uint64_t SnapshotHeightFor(uint64_t epoch_id) {
    // "canonical state at epoch_start - 1" — avoids same-block
    // registration/vote ordering ambiguity. Epoch 0 has no prior state and
    // therefore no snapshot; finality cannot activate in epoch 0.
    const uint64_t start = EpochStart(epoch_id);
    return start == 0 ? 0 : start - 1;
}

// ---------------------------------------------------------------- roots

inline Hash256 PubkeyCommit(const std::string& pubkey_hex) {
    std::vector<uint8_t> body(pubkey_hex.begin(), pubkey_hex.end());
    return state_digest::sha256_domain(DOMAIN_PUBKEY, body);
}

// Canonical snapshot root. Sort entries before hashing;
// MUST already be sorted by pubkey_commit; unordered iteration must never
// reach the hash. Commits count and total weight so a set cannot be silently
// truncated or reweighted.
inline Hash256 SnapshotRoot(const std::vector<SnapshotEntry>& sorted_entries, uint64_t epoch_id,
                            uint64_t snapshot_height, uint64_t total_weight) {
    std::vector<uint8_t> buf;
    state_digest::put_u64_le(buf, epoch_id);
    state_digest::put_u64_le(buf, snapshot_height);
    state_digest::put_u64_le(buf, (uint64_t)sorted_entries.size());
    state_digest::put_u64_le(buf, total_weight);
    for (const auto& e : sorted_entries) {
        state_digest::put_bytes(buf, e.pubkey_commit.data(), e.pubkey_commit.size());
        state_digest::put_len_prefixed(buf, e.address);
        state_digest::put_u64_le(buf, e.registered_height);
        state_digest::put_u64_le(buf, e.weight);
    }
    return state_digest::sha256_domain(DOMAIN_SNAPSHOT, buf);
}

// Verify a snapshot is internally consistent: sorted, no duplicate keys, all
// weights exactly the cap, total matches, root matches. Cheap enough to assert
// on every use; the cost of a malformed snapshot is a wrong denominator.
inline bool SnapshotWellFormed(const EpochSnapshot& s) {
    uint64_t sum = 0;
    for (size_t i = 0; i < s.entries.size(); ++i) {
        const auto& e = s.entries[i];
        if (e.weight != BOND_PER_KEY_UNITS)
            return false; // min AND cap
        if (e.address.empty())
            return false;
        if (e.pubkey_hex.size() != 3904 || PubkeyCommit(e.pubkey_hex) != e.pubkey_commit)
            return false;
        if (i > 0 && !(s.entries[i - 1].pubkey_commit < e.pubkey_commit)) {
            return false; // unsorted or duplicate
        }
        sum += e.weight;
    }
    if (sum != s.total_weight)
        return false;
    return SnapshotRoot(s.entries, s.epoch_id, s.snapshot_height, s.total_weight) == s.root;
}

// Index of a signer within the snapshot, or npos. Bitmap positions are
// snapshot entry positions — which is why the snapshot must be canonically
// sorted before any vote is counted. Every consensus-retained snapshot enters
// FinalityState only through OnEpochBoundary -> SnapshotWellFormed, whose
// strict adjacent comparison rejects both disorder and duplicates. Builders
// sort+deduplicate before computing the root, daemon snapshots must satisfy
// SnapshotQualifies (which repeats SnapshotWellFormed), and rollback is a
// verbatim copy of that accepted state. The exact-match lower_bound therefore
// preserves linear lookup semantics on every admissible snapshot while
// removing a 3,398-entry scan from guarded finality intake.
inline size_t SignerIndex(const EpochSnapshot& s, const Hash256& pubkey_commit) {
    const auto it = std::lower_bound(s.entries.begin(), s.entries.end(), pubkey_commit,
                                     [](const SnapshotEntry& entry, const Hash256& wanted) {
                                         return entry.pubkey_commit < wanted;
                                     });
    if (it == s.entries.end() || it->pubkey_commit != pubkey_commit)
        return (size_t)-1;
    return (size_t)std::distance(s.entries.begin(), it);
}

// ---------------------------------------------------------------- vote

// The signed preimage is length-delimited and includes the network identifier
// and genesis hash to prevent cross-network vote replay.
inline std::vector<uint8_t> VotePreimage(uint32_t network_id, const Hash256& genesis_hash,
                                         uint64_t epoch_id, const Hash256& set_root, Phase phase,
                                         uint32_t round, const CheckpointRef& source,
                                         const CheckpointRef& target) {
    std::vector<uint8_t> buf;
    state_digest::put_bytes(buf, reinterpret_cast<const uint8_t*>(DOMAIN_VOTE),
                            strlen(DOMAIN_VOTE));
    state_digest::put_u32_le(buf, network_id);
    state_digest::put_bytes(buf, genesis_hash.data(), genesis_hash.size());
    state_digest::put_u64_le(buf, epoch_id);
    state_digest::put_bytes(buf, set_root.data(), set_root.size());
    state_digest::put_u8(buf, (uint8_t)phase);
    state_digest::put_u32_le(buf, round);
    state_digest::put_u64_le(buf, source.height);
    state_digest::put_bytes(buf, source.hash.data(), source.hash.size());
    state_digest::put_u64_le(buf, target.height);
    state_digest::put_bytes(buf, target.hash.data(), target.hash.size());
    return buf;
}

// ---------------------------------------------------------------- QC

inline uint64_t BitmapWeight(const EpochSnapshot& s, const std::vector<uint8_t>& bitmap) {
    uint64_t w = 0;
    for (size_t i = 0; i < s.entries.size(); ++i) {
        const size_t byte = i >> 3;
        if (byte >= bitmap.size())
            break;
        if (bitmap[byte] & (uint8_t)(1u << (i & 7)))
            w += s.entries[i].weight;
    }
    return w;
}

inline Hash256 QcCommitment(const QuorumCert& qc) {
    std::vector<uint8_t> buf;
    state_digest::put_u64_le(buf, qc.epoch_id);
    state_digest::put_bytes(buf, qc.set_root.data(), qc.set_root.size());
    state_digest::put_u8(buf, (uint8_t)qc.phase);
    state_digest::put_u32_le(buf, qc.round);
    state_digest::put_u64_le(buf, qc.source.height);
    state_digest::put_bytes(buf, qc.source.hash.data(), qc.source.hash.size());
    state_digest::put_u64_le(buf, qc.target.height);
    state_digest::put_bytes(buf, qc.target.hash.data(), qc.target.hash.size());
    state_digest::put_len_prefixed(buf, qc.bitmap);
    state_digest::put_u64_le(buf, qc.weight);
    return state_digest::sha256_domain(DOMAIN_QC, buf);
}

// Structural validity of a QC against its snapshot. Signature verification is
// the caller's job (it needs the PQC context); this checks everything else,
// and it recomputes the weight rather than trusting the claimed field.
inline bool QcWellFormed(const QuorumCert& qc, const EpochSnapshot& s) {
    if (!SnapshotWellFormed(s))
        return false;
    if (qc.epoch_id != s.epoch_id)
        return false;
    if (qc.set_root != s.root)
        return false;
    if (qc.phase != Phase::PREVOTE && qc.phase != Phase::PRECOMMIT)
        return false;
    if (!IsScheduledCheckpoint(qc.target.height))
        return false;
    if (EpochOf(qc.target.height) != qc.epoch_id)
        return false;
    if (qc.round != CheckpointRound(qc.target.height))
        return false;
    if (!SourceRefWellFormed(qc.source, qc.target))
        return false;
    if (qc.bitmap.size() != (s.entries.size() + 7) / 8)
        return false;
    for (size_t i = s.entries.size(); i < qc.bitmap.size() * 8; ++i)
        if (qc.bitmap[i >> 3] & (uint8_t)(1u << (i & 7)))
            return false;
    const uint64_t recomputed = BitmapWeight(s, qc.bitmap);
    if (recomputed != qc.weight)
        return false;
    return IsSupermajority(qc.weight, s.total_weight);
}

// ---------------------------------------------------------------- locking

// May this validator PREVOTE (round, target) given its persisted lock?
//
// Unlocked            -> yes.
// Locked on `target`  -> yes (re-voting the locked value is always safe).
// Locked on another   -> only when the new target is proven to descend from
//                        the lock, or with a verified PREVOTE QC for the new
//                        target in a lexicographically newer (epoch,round).
//                        The producer verifies the QC signatures before it
//                        calls this pure transition predicate.
//
// This is the proactive half of the safety argument. Slashing prices a
// violation after the fact; the lock prevents the honest majority from ever
// producing the conflict in the first place.
inline bool LockedPrevoteAllowed(const Lock& lock, uint64_t new_epoch, uint32_t new_round,
                                 const CheckpointRef& new_target,
                                 const std::optional<QuorumCert>& unlock_proof,
                                 bool extends_lock = false) {
    if (!lock.held)
        return true;
    if (lock.target == new_target)
        return true;
    if (!ConsensusRoundNewer(new_epoch, new_round, lock.epoch_id, lock.round))
        return false;
    // Moving to a checkpoint that the local canonical chain PROVES descends
    // from the lock is not a conflicting vote.  The caller must establish
    // ancestry by resolving lock.height on the branch containing new_target;
    // height ordering alone is deliberately insufficient.
    if (extends_lock && new_target.height > lock.target.height)
        return true;
    if (!unlock_proof.has_value())
        return false;

    const QuorumCert& p = *unlock_proof;
    if (p.phase != Phase::PREVOTE)
        return false;
    if (p.epoch_id != new_epoch)
        return false;
    if (p.target != new_target)
        return false;
    // A target has one deterministic consensus round.  Requiring p.round to
    // be *below* new_round made this path mathematically unreachable because
    // both values are CheckpointRound(new_target.height).  A valid QC for the
    // exact new claim is the proof; its (epoch,round) must simply be newer than
    // the held lock, which was checked above.
    return p.round == new_round;
}

// A precommit QC is what establishes the lock.
inline Lock LockFromPrecommit(const QuorumCert& qc) {
    Lock l;
    if (qc.phase == Phase::PRECOMMIT) {
        l.held = true;
        l.epoch_id = qc.epoch_id;
        l.round = qc.round;
        l.target = qc.target;
    }
    return l;
}

// ---------------------------------------------------------------- finalize

// Build the retained record from a precommit QC carried at `carrier`.
// `retention_floor` is the height below which the carrier need no longer be
// preserved because a later certificate supersedes it.
inline std::optional<FinalizedRecord> Finalize(const QuorumCert& qc, const EpochSnapshot& s,
                                               const CheckpointRef& carrier) {
    if (qc.phase != Phase::PRECOMMIT)
        return std::nullopt;
    if (!QcWellFormed(qc, s))
        return std::nullopt;
    if (!s.Qualified())
        return std::nullopt;
    if (!InVoteWindow(qc.target.height, carrier.height))
        return std::nullopt;

    FinalizedRecord r;
    r.epoch_id = qc.epoch_id;
    r.target = qc.target;
    r.set_root = qc.set_root;
    r.round = qc.round;
    r.phase = qc.phase;
    r.cert_commit = QcCommitment(qc);
    r.carrier = carrier;
    r.retention_floor = qc.target.height;
    return r;
}

inline Hash256 RecordDigest(const FinalizedRecord& r) {
    std::vector<uint8_t> buf;
    state_digest::put_u64_le(buf, r.epoch_id);
    state_digest::put_u64_le(buf, r.target.height);
    state_digest::put_bytes(buf, r.target.hash.data(), r.target.hash.size());
    state_digest::put_bytes(buf, r.set_root.data(), r.set_root.size());
    state_digest::put_u32_le(buf, r.round);
    state_digest::put_u8(buf, (uint8_t)r.phase);
    state_digest::put_bytes(buf, r.cert_commit.data(), r.cert_commit.size());
    state_digest::put_u64_le(buf, r.carrier.height);
    state_digest::put_bytes(buf, r.carrier.hash.data(), r.carrier.hash.size());
    state_digest::put_u64_le(buf, r.retention_floor);
    return state_digest::sha256_domain(DOMAIN_RECORD, buf);
}

// Monotonic: a record may only be replaced by one with a strictly higher
// target. A checkpoint has one consensus-derived round, so same-target
// "re-certification" is neither meaningful nor replay-safe.
inline bool RecordSupersedes(const FinalizedRecord& incoming, const FinalizedRecord& current) {
    if (current.IsNull())
        return true;
    if (incoming.target.height > current.target.height)
        return true;
    return false;
}

// ------------------------------------------------------- reorganization

// May a reorganization proceed, given the retained finalized record?
//
// `branch_has(height, hash)` must answer whether the candidate branch contains
// exactly that block by resolving the complete side path.
//
// Three conditions, all necessary:
//
//   1. The common ancestor is at or above the finalized target.
//   2. The candidate branch contains the finalized block at the same height
//      and hash. Height alone would let a fork substitute a different
//      block at the finalized height.
//   3. The certificate carrier itself survives.
inline bool ReorgAllowed(const FinalizedRecord& rec, uint64_t common_ancestor_height,
                         const std::function<bool(uint64_t, const Hash256&)>& branch_has) {
    if (rec.IsNull())
        return true; // nothing finalized yet

    // 1. necessary target-prefix condition
    if (common_ancestor_height < rec.target.height)
        return false;

    // 2. the finalized block itself must survive, by hash
    if (!branch_has(rec.target.height, rec.target.hash))
        return false;

    // A naked QC supplied out of band cannot prove that its bytes are carried
    // by the candidate branch, and accepting one makes clean replay erase the
    // retained mark. Replacement support is therefore intentionally absent:
    // branch-preserving reorgs keep the exact canonical carrier or fail closed.
    return branch_has(rec.carrier.height, rec.carrier.hash);
}

// ---------------------------------------------------------------- liveness

// Finality liveness after the one-time seven-validator activation latch. A
// sustained stale signal pauses only new btcVELD mint exposure; it does not
// close completion, redeem, or the configured AMM path. Irreversible BTC
// payout still waits for an actually finalized redeem.
inline bool FinalityLive(uint64_t current_height, uint64_t last_finalized_height) {
    if (last_finalized_height == 0)
        return false;
    if (current_height <= last_finalized_height)
        return true;
    return (current_height - last_finalized_height) <= FINALITY_LIVENESS_WINDOW;
}

// Historical security milestone: the chain has proven it can both finalize and
// notarize. This remains stronger than "peg unlocked": BtcVeldPegGateState
// unlocks after the seven-validator finality activation, while this milestone
// additionally requires a promoted Bitcoin anchor.
inline bool SecurityMilestoneComplete(bool finality_ever_active, bool ever_promoted_anchor) {
    return finality_ever_active && ever_promoted_anchor;
}

} // namespace qc
} // namespace finality
} // namespace veld
