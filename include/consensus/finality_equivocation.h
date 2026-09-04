#pragma once
// finality_equivocation.h — authenticated, durable finality-slash evidence.
//
// IMPORTANT SEPARATION: ordinary conflicting votes belong here, never in
// CertAssembler.  A quorum certificate may contain only one unanimous claim;
// this collector retains a completed, independently authenticated pair solely
// so an operator can construct the on-chain SLASH_EQUIV proof.
//
// The pair is slashable only when one snapshotted signer authenticated two
// different hashes for the SAME scheduled target height in the same
// (epoch,set-root,phase,round).  Re-signing one target, even with a different
// source reference or signature, is deliberately non-slashable.
//
// Persistence stores the exact canonical FVT1 wires, not expanded hex keys.
// Besides making restore byte-stable, this is what lets the completed-pair
// pool have a real fixed memory ceiling.

#include "finality_codec.h"
#include "validators.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

namespace veld {
namespace finality {
namespace qc {

constexpr const char* DOMAIN_EQUIVOCATION_PAIR = "VELD_FINALITY_EQUIVOCATION_PAIR_v1|";
constexpr const char* DOMAIN_EQUIVOCATION_JOURNAL = "VELD_FINALITY_EQUIVOCATION_JOURNAL_v1|";

class FinalityEquivocationCollector;

// A capability: this type cannot be constructed from two untrusted SignedVote
// values.  It is created only after both signatures and the exact retained
// snapshot member have been authenticated by one of Validate* below.
class ValidatedEquivocationEvidence {
  public:
    ValidatedEquivocationEvidence(const ValidatedEquivocationEvidence&) = default;
    ValidatedEquivocationEvidence(ValidatedEquivocationEvidence&&) = default;
    ValidatedEquivocationEvidence& operator=(const ValidatedEquivocationEvidence&) = default;
    ValidatedEquivocationEvidence& operator=(ValidatedEquivocationEvidence&&) = default;

    const SignedVote& First() const noexcept {
        return first_;
    }
    const SignedVote& Second() const noexcept {
        return second_;
    }
    const Hash256& Id() const noexcept {
        return id_;
    }
    const Hash256& SignerCommit() const noexcept {
        return signer_commit_;
    }
    uint64_t Epoch() const noexcept {
        return first_.epoch_id;
    }

  private:
    ValidatedEquivocationEvidence(SignedVote first, SignedVote second, const Hash256& id,
                                  const Hash256& signer_commit)
        : first_(std::move(first)), second_(std::move(second)), id_(id),
          signer_commit_(signer_commit) {}

    SignedVote first_;
    SignedVote second_;
    Hash256 id_{};
    Hash256 signer_commit_{};

    static std::optional<ValidatedEquivocationEvidence> MakeCanonical(const SignedVote& a,
                                                                      const SignedVote& b) {
        SignedVote first = a;
        SignedVote second = b;
        if (std::lexicographical_compare(second.target.hash.begin(), second.target.hash.end(),
                                         first.target.hash.begin(), first.target.hash.end()))
            std::swap(first, second);

        const std::vector<uint8_t> first_wire = EncodeSignedVoteWire(first);
        const std::vector<uint8_t> second_wire = EncodeSignedVoteWire(second);
        if (first_wire.size() != SIGNED_VOTE_WIRE_BYTES ||
            second_wire.size() != SIGNED_VOTE_WIRE_BYTES)
            return std::nullopt;

        std::vector<uint8_t> body;
        body.reserve(first_wire.size() + second_wire.size());
        body.insert(body.end(), first_wire.begin(), first_wire.end());
        body.insert(body.end(), second_wire.begin(), second_wire.end());
        const Hash256 id = state_digest::sha256_domain(DOMAIN_EQUIVOCATION_PAIR, body);
        return ValidatedEquivocationEvidence(std::move(first), std::move(second), id,
                                             PubkeyCommit(a.pubkey_hex));
    }

    friend std::optional<ValidatedEquivocationEvidence>
    ValidateAuthenticatedEquivocationPair(const AuthenticatedVote&, const AuthenticatedVote&,
                                          uint64_t);
    friend class FinalityEquivocationCollector;
};

static_assert(!std::is_default_constructible<ValidatedEquivocationEvidence>::value,
              "raw votes must not mint finality slash evidence");
static_assert(!std::is_constructible<ValidatedEquivocationEvidence, SignedVote, SignedVote, Hash256,
                                     Hash256>::value,
              "the authenticated evidence constructor must remain private");

// Cheap structural predicate.  This does not authenticate either signature;
// callers must use a Validate* function before retaining or publishing a pair.
inline bool EquivocationClaimsWellFormed(const SignedVote& a, const SignedVote& b,
                                         uint64_t canonical_tip_height) {
    if (a.pubkey_hex != b.pubkey_hex || a.epoch_id != b.epoch_id || a.set_root != b.set_root ||
        a.phase != b.phase || a.round != b.round)
        return false;

    // BuildSlashEquivOp must always emit a spelling the strict consensus
    // parser accepts.  AuthenticateVote's historical key decoder accepts
    // uppercase hex, so enforce the canonical lowercase snapshot spelling at
    // the evidence-capability boundary.
    std::vector<uint8_t> canonical_pubkey;
    if (a.pubkey_hex.size() != ::veld::dilithium::PUBKEY_BYTES * 2 ||
        !FromHexBytes(a.pubkey_hex, canonical_pubkey) ||
        canonical_pubkey.size() != ::veld::dilithium::PUBKEY_BYTES)
        return false;

    // A round maps to exactly one checkpoint height.  Differing heights are
    // malformed evidence, not a broader interpretation of equivocation.
    if (a.target.height != b.target.height || a.target.hash == b.target.hash)
        return false;

    if (!VoteClaimWellFormed(a, a.epoch_id, a.set_root) ||
        !VoteClaimWellFormed(b, b.epoch_id, b.set_root) || a.target.height > canonical_tip_height ||
        b.target.height > canonical_tip_height)
        return false;

    // The parser also rejects byte-identical signatures.  Correct signatures
    // for different target preimages cannot be identical in the normal ML-DSA
    // security model, but spelling the constraint here keeps construction and
    // on-chain acceptance exactly aligned.
    return a.signature != b.signature;
}

// One vote may enter the evidence detector even when its target is a sibling
// of the local canonical block.  It still must be an exact, structurally valid
// vote from a retained member, and it must arrive inside the same 90-day
// horizon the on-chain parser enforces.  This predicate intentionally does NOT
// require VoteMatchesCanonicalFrame: doing so would erase the very sibling
// needed to prove equivocation.
inline bool FinalityEvidenceVoteWellFormed(const SignedVote& vote, uint64_t snapshot_epoch,
                                           const Hash256& snapshot_root,
                                           uint64_t canonical_tip_height) {
    std::vector<uint8_t> canonical_pubkey;
    if (vote.pubkey_hex.size() != ::veld::dilithium::PUBKEY_BYTES * 2 ||
        !FromHexBytes(vote.pubkey_hex, canonical_pubkey) ||
        canonical_pubkey.size() != ::veld::dilithium::PUBKEY_BYTES ||
        !VoteClaimWellFormed(vote, snapshot_epoch, snapshot_root) ||
        vote.target.height > canonical_tip_height)
        return false;
    return canonical_tip_height - vote.target.height <= FINALITY_EQUIV_EVIDENCE_WINDOW;
}

// Validate two already-authenticated vote capabilities.  The capability
// constructors prove the ML-DSA signatures and member identity; this function
// proves they came from the same exact retained snapshot frame and form the
// narrowly defined slashable offense.
inline std::optional<ValidatedEquivocationEvidence>
ValidateAuthenticatedEquivocationPair(const AuthenticatedVote& a, const AuthenticatedVote& b,
                                      uint64_t canonical_tip_height) {
    if (a.SnapshotEpoch() != b.SnapshotEpoch() || a.SnapshotRoot() != b.SnapshotRoot() ||
        a.MemberCommit() != b.MemberCommit() || a.SnapshotEpoch() != a.Vote().epoch_id ||
        b.SnapshotEpoch() != b.Vote().epoch_id || a.SnapshotRoot() != a.Vote().set_root ||
        b.SnapshotRoot() != b.Vote().set_root ||
        a.MemberCommit() != PubkeyCommit(a.Vote().pubkey_hex) ||
        b.MemberCommit() != PubkeyCommit(b.Vote().pubkey_hex) ||
        !EquivocationClaimsWellFormed(a.Vote(), b.Vote(), canonical_tip_height))
        return std::nullopt;
    return ValidatedEquivocationEvidence::MakeCanonical(a.Vote(), b.Vote());
}

// Full retained-snapshot path.  SnapshotWellFormed is mandatory here: a list
// with a matching key is not membership unless its canonical root and weights
// reproduce the root carried by both signatures.
inline std::optional<ValidatedEquivocationEvidence>
ValidateEquivocationPair(const SignedVote& a, const SignedVote& b,
                         const EpochSnapshot& retained_snapshot, uint64_t canonical_tip_height,
                         uint32_t network_id, const Hash256& genesis_hash) {
    if (!EquivocationClaimsWellFormed(a, b, canonical_tip_height) ||
        !SnapshotWellFormed(retained_snapshot))
        return std::nullopt;
    const auto authenticated_a = AuthenticateVote(a, retained_snapshot, network_id, genesis_hash);
    if (!authenticated_a)
        return std::nullopt;
    const auto authenticated_b = AuthenticateVote(b, retained_snapshot, network_id, genesis_hash);
    if (!authenticated_b)
        return std::nullopt;
    return ValidateAuthenticatedEquivocationPair(*authenticated_a, *authenticated_b,
                                                 canonical_tip_height);
}

// Low-copy network path.  `retained_member` MUST be the exact SnapshotEntry
// copied from the canonical retained snapshot while the caller held its state
// guard; this mirrors AuthenticateVoteForMember and avoids copying a maximum
// 3,398-key snapshot for each candidate pair.
inline std::optional<ValidatedEquivocationEvidence> ValidateEquivocationPairForRetainedMember(
    const SignedVote& a, const SignedVote& b, uint64_t snapshot_epoch, const Hash256& snapshot_root,
    const SnapshotEntry& retained_member, uint64_t canonical_tip_height, uint32_t network_id,
    const Hash256& genesis_hash) {
    if (!EquivocationClaimsWellFormed(a, b, canonical_tip_height))
        return std::nullopt;
    const auto authenticated_a = AuthenticateVoteForMember(
        a, snapshot_epoch, snapshot_root, retained_member, network_id, genesis_hash);
    if (!authenticated_a)
        return std::nullopt;
    const auto authenticated_b = AuthenticateVoteForMember(
        b, snapshot_epoch, snapshot_root, retained_member, network_id, genesis_hash);
    if (!authenticated_b)
        return std::nullopt;
    return ValidateAuthenticatedEquivocationPair(*authenticated_a, *authenticated_b,
                                                 canonical_tip_height);
}

// Completed evidence only.  Pending single votes stay in the caller's bounded
// intake lanes; quorum-certificate assembly never calls this collector.
class FinalityEquivocationCollector {
  public:
    static constexpr size_t MAX_COMPLETED_PAIRS = 4096;
    static constexpr size_t MAX_COMPLETED_PAIR_BYTES = 48ULL * 1024ULL * 1024ULL;
    // Each record stores two fixed 5,390-byte wires plus identity metadata and
    // one ordered-map node.  Charging a full 12 KiB per record is deliberately
    // conservative and makes 4,096 records equal the hard 48 MiB ceiling.
    static constexpr size_t PAIR_STORAGE_CHARGE_BYTES = 12ULL * 1024ULL;
    static constexpr size_t MAX_ENCODED_JOURNAL_BYTES =
        8 + MAX_COMPLETED_PAIRS * 2 * SIGNED_VOTE_WIRE_BYTES + 32;
    static_assert(MAX_COMPLETED_PAIRS * PAIR_STORAGE_CHARGE_BYTES == MAX_COMPLETED_PAIR_BYTES,
                  "completed equivocation pool must stay inside 48 MiB");

    enum class OfferResult : uint8_t {
        INSERTED = 0,
        ALREADY_KNOWN,
        OFFENSE_ALREADY_STORED,
        FULL,
        STORAGE_ERROR
    };

    using PairValidator = std::function<std::optional<ValidatedEquivocationEvidence>(
        const SignedVote&, const SignedVote&)>;

    struct Summary {
        Hash256 id{};
        Hash256 signer_commit{};
        std::string pubkey_hex;
        uint64_t epoch = 0;
        Phase phase = Phase::PREVOTE;
        uint32_t round = 0;
        uint64_t target_height = 0;
        Hash256 target_a_hash{};
        Hash256 target_b_hash{};
    };

    explicit FinalityEquivocationCollector(size_t pair_limit = MAX_COMPLETED_PAIRS,
                                           size_t byte_limit = MAX_COMPLETED_PAIR_BYTES)
        : pair_limit_(std::min(pair_limit, MAX_COMPLETED_PAIRS)),
          byte_limit_(std::min(byte_limit, MAX_COMPLETED_PAIR_BYTES)) {}

    OfferResult Offer(const ValidatedEquivocationEvidence& evidence) {
        StoredPair stored;
        if (!StoredPair::FromEvidence(evidence, stored))
            return OfferResult::STORAGE_ERROR;
        const OffenseKey key{evidence.Epoch(), evidence.SignerCommit()};

        std::lock_guard<std::mutex> lock(mutex_);
        const auto existing = records_.find(key);
        if (existing != records_.end()) {
            return existing->second.id == evidence.Id() ? OfferResult::ALREADY_KNOWN
                                                        : OfferResult::OFFENSE_ALREADY_STORED;
        }
        if (records_.size() >= pair_limit_ ||
            PAIR_STORAGE_CHARGE_BYTES > byte_limit_ - std::min(bytes_charged_, byte_limit_))
            return OfferResult::FULL;
        try {
            records_.emplace(key, std::move(stored));
            bytes_charged_ += PAIR_STORAGE_CHARGE_BYTES;
            return OfferResult::INSERTED;
        } catch (...) {
            return OfferResult::STORAGE_ERROR;
        }
    }

    size_t PairCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return records_.size();
    }

    size_t BytesCharged() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return bytes_charged_;
    }

    bool HasOffense(uint64_t epoch, const Hash256& signer_commit) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return records_.find(OffenseKey{epoch, signer_commit}) != records_.end();
    }

    std::vector<Summary> ListSummaries(size_t limit = 256) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<Summary> out;
        out.reserve(std::min(limit, records_.size()));
        for (auto it = records_.rbegin(); it != records_.rend() && out.size() < limit; ++it) {
            const auto evidence = EvidenceFromStored(it->second);
            if (!evidence)
                continue;
            Summary summary;
            summary.id = evidence->Id();
            summary.signer_commit = evidence->SignerCommit();
            summary.pubkey_hex = evidence->First().pubkey_hex;
            summary.epoch = evidence->Epoch();
            summary.phase = evidence->First().phase;
            summary.round = evidence->First().round;
            summary.target_height = evidence->First().target.height;
            summary.target_a_hash = evidence->First().target.hash;
            summary.target_b_hash = evidence->Second().target.hash;
            out.push_back(std::move(summary));
        }
        return out;
    }

    std::vector<Summary> ListSummaryPage(size_t offset, size_t limit) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<Summary> out;
        if (offset >= records_.size() || limit == 0)
            return out;
        out.reserve(std::min(limit, records_.size() - offset));
        size_t skipped = 0;
        for (auto it = records_.rbegin(); it != records_.rend(); ++it) {
            if (skipped++ < offset)
                continue;
            if (out.size() >= limit)
                break;
            const auto evidence = EvidenceFromStored(it->second);
            if (!evidence)
                continue;
            Summary summary;
            summary.id = evidence->Id();
            summary.signer_commit = evidence->SignerCommit();
            summary.pubkey_hex = evidence->First().pubkey_hex;
            summary.epoch = evidence->Epoch();
            summary.phase = evidence->First().phase;
            summary.round = evidence->First().round;
            summary.target_height = evidence->First().target.height;
            summary.target_a_hash = evidence->First().target.hash;
            summary.target_b_hash = evidence->Second().target.hash;
            out.push_back(std::move(summary));
        }
        return out;
    }

    std::optional<ValidatedEquivocationEvidence> FindById(const Hash256& id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& item : records_) {
            if (item.second.id == id)
                return EvidenceFromStored(item.second);
        }
        return std::nullopt;
    }

    bool EraseById(const Hash256& id) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = records_.begin(); it != records_.end(); ++it) {
            if (it->second.id != id)
                continue;
            records_.erase(it);
            bytes_charged_ -= PAIR_STORAGE_CHARGE_BYTES;
            return true;
        }
        return false;
    }

    // Expired evidence is no longer accepted by the on-chain parser.  Removing
    // it cannot discard an actionable offense; callers persist the resulting
    // journal best-effort so an old file may contain harmless extra stale rows
    // after an I/O failure, never fewer live rows.
    size_t PruneExpired(uint64_t canonical_tip_height) {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t removed = 0;
        for (auto it = records_.begin(); it != records_.end();) {
            const uint64_t target = it->second.target_height;
            if (canonical_tip_height > target &&
                canonical_tip_height - target > FINALITY_EQUIV_EVIDENCE_WINDOW) {
                it = records_.erase(it);
                bytes_charged_ -= PAIR_STORAGE_CHARGE_BYTES;
                ++removed;
            } else {
                ++it;
            }
        }
        return removed;
    }

    void Clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        records_.clear();
        bytes_charged_ = 0;
    }

    // VEJ1 || u32le(count) || canonical FVT1 pair records || checksum.
    // Map order is (epoch, signer commitment), so insertion order cannot alter
    // the persisted bytes.  The checksum covers every preceding byte.
    std::vector<uint8_t> Encode() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<uint8_t> out;
        out.reserve(8 + records_.size() * 2 * SIGNED_VOTE_WIRE_BYTES + 32);
        static constexpr uint8_t MAGIC[4] = {'V', 'E', 'J', '1'};
        state_digest::put_bytes(out, MAGIC, sizeof(MAGIC));
        state_digest::put_u32_le(out, static_cast<uint32_t>(records_.size()));
        for (const auto& item : records_) {
            state_digest::put_bytes(out, item.second.first.data(), item.second.first.size());
            state_digest::put_bytes(out, item.second.second.data(), item.second.second.size());
        }
        const Hash256 checksum = state_digest::sha256_domain(DOMAIN_EQUIVOCATION_JOURNAL, out);
        state_digest::put_bytes(out, checksum.data(), checksum.size());
        return out;
    }

    // Atomically replaces the collector only after every pair has decoded,
    // re-authenticated through the caller's retained-snapshot resolver, and
    // reproduced its canonical stored order and checksum.  Failure leaves the
    // existing collector untouched.
    bool Restore(const std::vector<uint8_t>& encoded, const PairValidator& validate_pair) {
        if (!validate_pair || encoded.size() < 8 + 32)
            return false;
        static constexpr uint8_t MAGIC[4] = {'V', 'E', 'J', '1'};
        if (!std::equal(encoded.begin(), encoded.begin() + 4, MAGIC))
            return false;
        const uint32_t count =
            static_cast<uint32_t>(encoded[4]) | (static_cast<uint32_t>(encoded[5]) << 8) |
            (static_cast<uint32_t>(encoded[6]) << 16) | (static_cast<uint32_t>(encoded[7]) << 24);
        if (count > pair_limit_ || count > MAX_COMPLETED_PAIRS ||
            static_cast<size_t>(count) > byte_limit_ / PAIR_STORAGE_CHARGE_BYTES)
            return false;
        const size_t expected = 8 + static_cast<size_t>(count) * 2 * SIGNED_VOTE_WIRE_BYTES + 32;
        if (encoded.size() != expected)
            return false;

        const std::vector<uint8_t> body(encoded.begin(), encoded.end() - 32);
        const Hash256 expected_checksum =
            state_digest::sha256_domain(DOMAIN_EQUIVOCATION_JOURNAL, body);
        if (!std::equal(expected_checksum.begin(), expected_checksum.end(), encoded.end() - 32))
            return false;

        std::map<OffenseKey, StoredPair> restored;
        size_t offset = 8;
        OffenseKey previous_key;
        bool have_previous_key = false;
        try {
            for (uint32_t i = 0; i < count; ++i) {
                std::vector<uint8_t> first_wire(
                    encoded.begin() + static_cast<std::ptrdiff_t>(offset),
                    encoded.begin() + static_cast<std::ptrdiff_t>(offset + SIGNED_VOTE_WIRE_BYTES));
                offset += SIGNED_VOTE_WIRE_BYTES;
                std::vector<uint8_t> second_wire(
                    encoded.begin() + static_cast<std::ptrdiff_t>(offset),
                    encoded.begin() + static_cast<std::ptrdiff_t>(offset + SIGNED_VOTE_WIRE_BYTES));
                offset += SIGNED_VOTE_WIRE_BYTES;

                const auto first = DecodeSignedVoteWire(first_wire);
                const auto second = DecodeSignedVoteWire(second_wire);
                if (!first || !second)
                    return false;
                const auto evidence = validate_pair(*first, *second);
                if (!evidence)
                    return false;

                StoredPair stored;
                if (!StoredPair::FromEvidence(*evidence, stored) ||
                    !std::equal(stored.first.begin(), stored.first.end(), first_wire.begin()) ||
                    !std::equal(stored.second.begin(), stored.second.end(), second_wire.begin()))
                    return false; // journal pair itself was not canonical
                const OffenseKey key{evidence->Epoch(), evidence->SignerCommit()};
                if (have_previous_key && !(previous_key < key))
                    return false; // canonical journal order is strict
                if (!restored.emplace(key, std::move(stored)).second)
                    return false; // one offense per signer per epoch
                previous_key = key;
                have_previous_key = true;
            }
        } catch (...) {
            return false;
        }
        if (offset + 32 != encoded.size())
            return false;

        std::lock_guard<std::mutex> lock(mutex_);
        records_.swap(restored);
        bytes_charged_ = static_cast<size_t>(count) * PAIR_STORAGE_CHARGE_BYTES;
        return true;
    }

  private:
    struct OffenseKey {
        uint64_t epoch = 0;
        Hash256 signer_commit{};

        bool operator<(const OffenseKey& other) const {
            if (epoch != other.epoch)
                return epoch < other.epoch;
            return signer_commit < other.signer_commit;
        }
    };

    struct StoredPair {
        Hash256 id{};
        Hash256 signer_commit{};
        uint64_t epoch = 0;
        uint64_t target_height = 0;
        std::array<uint8_t, SIGNED_VOTE_WIRE_BYTES> first{};
        std::array<uint8_t, SIGNED_VOTE_WIRE_BYTES> second{};

        static bool FromEvidence(const ValidatedEquivocationEvidence& evidence, StoredPair& out) {
            const std::vector<uint8_t> first_wire = EncodeSignedVoteWire(evidence.First());
            const std::vector<uint8_t> second_wire = EncodeSignedVoteWire(evidence.Second());
            if (first_wire.size() != out.first.size() || second_wire.size() != out.second.size())
                return false;
            out.id = evidence.Id();
            out.signer_commit = evidence.SignerCommit();
            out.epoch = evidence.Epoch();
            out.target_height = evidence.First().target.height;
            std::copy(first_wire.begin(), first_wire.end(), out.first.begin());
            std::copy(second_wire.begin(), second_wire.end(), out.second.begin());
            return true;
        }
    };

    static std::optional<ValidatedEquivocationEvidence>
    EvidenceFromStored(const StoredPair& stored) {
        const std::vector<uint8_t> first_wire(stored.first.begin(), stored.first.end());
        const std::vector<uint8_t> second_wire(stored.second.begin(), stored.second.end());
        const auto first = DecodeSignedVoteWire(first_wire);
        const auto second = DecodeSignedVoteWire(second_wire);
        if (!first || !second)
            return std::nullopt;
        const auto evidence = ValidatedEquivocationEvidence::MakeCanonical(*first, *second);
        if (!evidence || evidence->Id() != stored.id ||
            evidence->SignerCommit() != stored.signer_commit || evidence->Epoch() != stored.epoch)
            return std::nullopt;
        return evidence;
    }

    static_assert(sizeof(StoredPair) + sizeof(OffenseKey) + 512 <= PAIR_STORAGE_CHARGE_BYTES,
                  "12 KiB charge must cover compact pair and map overhead");

    const size_t pair_limit_;
    const size_t byte_limit_;
    mutable std::mutex mutex_;
    std::map<OffenseKey, StoredPair> records_;
    size_t bytes_charged_ = 0;
};

static_assert(sizeof(FinalityEquivocationCollector) <
                  FinalityEquivocationCollector::MAX_COMPLETED_PAIR_BYTES,
              "empty collector has bounded fixed state");

// Bounded, evidence-only intake for authenticated votes.  This is deliberately
// separate from CertAssembler: a sibling vote can prove equivocation, but it
// must never contribute to a locally assembled quorum certificate or be
// relayed as an ordinary canonical vote.
//
// Pending singles are process-local.  Completed pairs move to the durable
// collector above.  Persisting every unmatched ML-DSA vote would require an
// atomic multi-gigabyte journal in the maximum validator/round envelope, while
// a bounded live detector preserves the safety property without turning
// untrusted traffic into unbounded disk I/O.
class FinalityEquivocationDetector {
  public:
    static constexpr size_t MAX_PENDING_VOTES = 8192;
    static constexpr size_t MAX_PENDING_BYTES = 48ULL * 1024ULL * 1024ULL;
    static constexpr size_t PENDING_STORAGE_CHARGE_BYTES = 6ULL * 1024ULL;
    static_assert(MAX_PENDING_VOTES * PENDING_STORAGE_CHARGE_BYTES == MAX_PENDING_BYTES,
                  "pending evidence pool must stay inside 48 MiB");

    enum class ObserveResult : uint8_t {
        STORED_NEW = 0,
        SAME_TARGET,
        COMPLETED_EVIDENCE,
        REJECTED,
        STORAGE_ERROR
    };

    struct Observation {
        ObserveResult result = ObserveResult::REJECTED;
        std::optional<ValidatedEquivocationEvidence> evidence;
    };

    explicit FinalityEquivocationDetector(size_t vote_limit = MAX_PENDING_VOTES,
                                          size_t byte_limit = MAX_PENDING_BYTES)
        : vote_limit_(std::min(vote_limit, MAX_PENDING_VOTES)),
          byte_limit_(std::min(byte_limit, MAX_PENDING_BYTES)) {}

    Observation ObserveAuthenticated(const AuthenticatedVote& authenticated,
                                     const SnapshotEntry& retained_member,
                                     uint64_t canonical_tip_height, uint32_t network_id,
                                     const Hash256& genesis_hash) {
        const SignedVote& vote = authenticated.Vote();
        const Hash256 signer_commit = PubkeyCommit(vote.pubkey_hex);
        if (authenticated.SnapshotEpoch() != vote.epoch_id ||
            authenticated.SnapshotRoot() != vote.set_root ||
            authenticated.MemberCommit() != signer_commit ||
            retained_member.pubkey_commit != signer_commit ||
            retained_member.pubkey_hex != vote.pubkey_hex ||
            !FinalityEvidenceVoteWellFormed(vote, authenticated.SnapshotEpoch(),
                                            authenticated.SnapshotRoot(), canonical_tip_height))
            return {ObserveResult::REJECTED, std::nullopt};

        const std::vector<uint8_t> wire = EncodeSignedVoteWire(vote);
        if (wire.size() != SIGNED_VOTE_WIRE_BYTES)
            return {ObserveResult::STORAGE_ERROR, std::nullopt};

        const FrameKey key{vote.epoch_id, vote.set_root,      static_cast<uint8_t>(vote.phase),
                           vote.round,    vote.target.height, signer_commit};
        std::lock_guard<std::mutex> lock(mutex_);
        const auto existing = pending_.find(key);
        if (existing != pending_.end()) {
            if (existing->second.target_hash == vote.target.hash)
                return {ObserveResult::SAME_TARGET, std::nullopt};

            const std::vector<uint8_t> first_wire(existing->second.wire.begin(),
                                                  existing->second.wire.end());
            const auto first = DecodeSignedVoteWire(first_wire);
            if (!first || !FinalityEvidenceVoteWellFormed(*first, vote.epoch_id, vote.set_root,
                                                          canonical_tip_height))
                return {ObserveResult::STORAGE_ERROR, std::nullopt};
            const auto first_authenticated = AuthenticateVoteForMember(
                *first, vote.epoch_id, vote.set_root, retained_member, network_id, genesis_hash);
            if (!first_authenticated)
                return {ObserveResult::STORAGE_ERROR, std::nullopt};
            auto evidence = ValidateAuthenticatedEquivocationPair(
                *first_authenticated, authenticated, canonical_tip_height);
            if (!evidence)
                return {ObserveResult::REJECTED, std::nullopt};
            return {ObserveResult::COMPLETED_EVIDENCE, std::move(evidence)};
        }

        if (vote_limit_ == 0 || PENDING_STORAGE_CHARGE_BYTES > byte_limit_) {
            return {ObserveResult::STORAGE_ERROR, std::nullopt};
        }
        EvictUntilRoomLocked_();
        if (pending_.size() >= vote_limit_ ||
            PENDING_STORAGE_CHARGE_BYTES > byte_limit_ - std::min(bytes_charged_, byte_limit_))
            return {ObserveResult::STORAGE_ERROR, std::nullopt};

        StoredVote stored;
        stored.target_hash = vote.target.hash;
        stored.sequence = next_sequence_++;
        std::copy(wire.begin(), wire.end(), stored.wire.begin());
        try {
            const uint64_t sequence = stored.sequence;
            if (!pending_.emplace(key, std::move(stored)).second)
                return {ObserveResult::STORAGE_ERROR, std::nullopt};
            fifo_.emplace_back(key, sequence);
            bytes_charged_ += PENDING_STORAGE_CHARGE_BYTES;
        } catch (...) {
            const auto inserted = pending_.find(key);
            if (inserted != pending_.end() && inserted->second.sequence + 1 == next_sequence_)
                pending_.erase(inserted);
            return {ObserveResult::STORAGE_ERROR, std::nullopt};
        }
        return {ObserveResult::STORED_NEW, std::nullopt};
    }

    size_t EraseSignerEpoch(uint64_t epoch, const Hash256& signer_commit) {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t removed = 0;
        for (auto it = pending_.begin(); it != pending_.end();) {
            if (it->first.epoch == epoch && it->first.signer_commit == signer_commit) {
                it = pending_.erase(it);
                bytes_charged_ -= PENDING_STORAGE_CHARGE_BYTES;
                ++removed;
            } else {
                ++it;
            }
        }
        TrimFifoLocked_();
        return removed;
    }

    size_t PruneExpired(uint64_t canonical_tip_height) {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t removed = 0;
        for (auto it = pending_.begin(); it != pending_.end();) {
            const uint64_t target = it->first.target_height;
            if (canonical_tip_height > target &&
                canonical_tip_height - target > FINALITY_EQUIV_EVIDENCE_WINDOW) {
                it = pending_.erase(it);
                bytes_charged_ -= PENDING_STORAGE_CHARGE_BYTES;
                ++removed;
            } else {
                ++it;
            }
        }
        TrimFifoLocked_();
        return removed;
    }

    size_t PendingCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return pending_.size();
    }

    size_t BytesCharged() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return bytes_charged_;
    }

    void Clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_.clear();
        fifo_.clear();
        bytes_charged_ = 0;
    }

  private:
    struct FrameKey {
        uint64_t epoch = 0;
        Hash256 set_root{};
        uint8_t phase = 0;
        uint32_t round = 0;
        uint64_t target_height = 0;
        Hash256 signer_commit{};

        bool operator<(const FrameKey& other) const {
            if (epoch != other.epoch)
                return epoch < other.epoch;
            if (set_root != other.set_root)
                return set_root < other.set_root;
            if (phase != other.phase)
                return phase < other.phase;
            if (round != other.round)
                return round < other.round;
            if (target_height != other.target_height)
                return target_height < other.target_height;
            return signer_commit < other.signer_commit;
        }
    };

    struct StoredVote {
        Hash256 target_hash{};
        uint64_t sequence = 0;
        std::array<uint8_t, SIGNED_VOTE_WIRE_BYTES> wire{};
    };

    void TrimFifoLocked_() {
        while (!fifo_.empty()) {
            const auto found = pending_.find(fifo_.front().first);
            if (found != pending_.end() && found->second.sequence == fifo_.front().second)
                break;
            fifo_.pop_front();
        }
    }

    void EvictUntilRoomLocked_() {
        TrimFifoLocked_();
        while (!pending_.empty() && (pending_.size() >= vote_limit_ ||
                                     PENDING_STORAGE_CHARGE_BYTES >
                                         byte_limit_ - std::min(bytes_charged_, byte_limit_))) {
            if (fifo_.empty())
                break;
            const FrameKey key = fifo_.front().first;
            const uint64_t sequence = fifo_.front().second;
            fifo_.pop_front();
            const auto found = pending_.find(key);
            if (found == pending_.end() || found->second.sequence != sequence)
                continue;
            pending_.erase(found);
            bytes_charged_ -= PENDING_STORAGE_CHARGE_BYTES;
            TrimFifoLocked_();
        }
    }

    static_assert(sizeof(StoredVote) + sizeof(FrameKey) + 512 <= PENDING_STORAGE_CHARGE_BYTES,
                  "6 KiB charge must cover compact vote and map/FIFO overhead");

    const size_t vote_limit_;
    const size_t byte_limit_;
    mutable std::mutex mutex_;
    std::map<FrameKey, StoredVote> pending_;
    std::deque<std::pair<FrameKey, uint64_t>> fifo_;
    size_t bytes_charged_ = 0;
    uint64_t next_sequence_ = 1;
};

static_assert(sizeof(FinalityEquivocationDetector) <
                  FinalityEquivocationDetector::MAX_PENDING_BYTES,
              "empty evidence detector has bounded fixed state");

} // namespace qc
} // namespace finality

// Exact-type, pure serializer.  Validation remains the parser's authority,
// but accepting only a ValidatedEquivocationEvidence capability prevents RPC
// or operator code from accidentally publishing an unverified raw pair.
inline std::string
ValidatorRegistry::BuildSlashEquivOp(const finality::qc::ValidatedEquivocationEvidence& pair) {
    const auto& a = pair.First();
    const auto& b = pair.Second();
    return std::string(VAL_PREFIX) + "SLASH_EQUIV|" + a.pubkey_hex + "|" +
           std::to_string(a.epoch_id) + "|" + HashToHex(a.set_root) + "|" +
           std::to_string(static_cast<uint8_t>(a.phase)) + "|" + std::to_string(a.round) + "|" +
           std::to_string(a.source.height) + "|" + HashToHex(a.source.hash) + "|" +
           std::to_string(a.target.height) + "|" + HashToHex(a.target.hash) + "|" +
           BytesToHex(a.signature) + "|" + std::to_string(b.source.height) + "|" +
           HashToHex(b.source.hash) + "|" + std::to_string(b.target.height) + "|" +
           HashToHex(b.target.hash) + "|" + BytesToHex(b.signature) + "|v1";
}

} // namespace veld
