#pragma once
// Signed finality votes and quorum-certificate assembly. A finality vote is a
// distinct, domain-separated, chain-bound object with an explicit epoch, round,
// phase, and justified source.
//
// It cannot be replayed onto another chain (network id + genesis hash are in
// the preimage), onto another epoch, or into another round or phase.
//
// This header adds the SIGNATURE layer that finality_qc.h deliberately omits:
// the pure core recomputes weight from the bitmap and checks structure, but a
// bitmap is only a claim about who signed. Without verification a QC is an
// assertion; with it, a QC is evidence.
//
// Functions in this header depend only on their arguments.

#include "finality_qc.h"
#include "finality_snapshot.h"
#include "crypto/dilithium.h"
#include "core/hash.h"

#include <map>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

namespace veld {
namespace finality {
namespace qc {

// A vote as it travels: the fields that enter the preimage, plus the signer's
// identity and detached signature. Nothing here is trusted until verified.
struct SignedVote {
    uint64_t epoch_id = 0;
    Hash256 set_root{};
    Phase phase = Phase::PREVOTE;
    uint32_t round = 0;
    CheckpointRef source;
    CheckpointRef target;
    std::string pubkey_hex; // signer's ML-DSA-65 public key
    std::vector<uint8_t> signature;
};

// Cheap claim validation shared by the network precheck and the cryptographic
// verifier.  Keeping it separate lets a node reject stale/malformed traffic
// while holding its short consensus-state guard, then pay ML-DSA cost only
// after releasing that guard.
inline bool VoteClaimWellFormed(const SignedVote& v, uint64_t snapshot_epoch,
                                const Hash256& snapshot_root) {
    return v.epoch_id == snapshot_epoch && v.set_root == snapshot_root &&
           (v.phase == Phase::PREVOTE || v.phase == Phase::PRECOMMIT) &&
           IsScheduledCheckpoint(v.target.height) && EpochOf(v.target.height) == v.epoch_id &&
           v.round == CheckpointRound(v.target.height) && SourceRefWellFormed(v.source, v.target) &&
           v.signature.size() == ::veld::dilithium::SIG_MAX_BYTES;
}

// A vote can enter CertAssembler's no-crypto storage path only through this
// capability.  There is intentionally no default/public SignedVote
// constructor: AuthenticateVote* below is the sole creator and performs the
// ML-DSA verification first.  Copy/move preserve an already-authenticated
// capability but cannot manufacture one.
class AuthenticatedVote {
  public:
    AuthenticatedVote(const AuthenticatedVote&) = default;
    AuthenticatedVote(AuthenticatedVote&&) = default;
    AuthenticatedVote& operator=(const AuthenticatedVote&) = default;
    AuthenticatedVote& operator=(AuthenticatedVote&&) = default;

    const SignedVote& Vote() const noexcept {
        return vote_;
    }
    uint64_t SnapshotEpoch() const noexcept {
        return snapshot_epoch_;
    }
    const Hash256& SnapshotRoot() const noexcept {
        return snapshot_root_;
    }
    const Hash256& MemberCommit() const noexcept {
        return member_commit_;
    }

  private:
    AuthenticatedVote(const SignedVote& vote, uint64_t snapshot_epoch, const Hash256& snapshot_root,
                      const Hash256& member_commit)
        : vote_(vote), snapshot_epoch_(snapshot_epoch), snapshot_root_(snapshot_root),
          member_commit_(member_commit) {}

    SignedVote vote_;
    uint64_t snapshot_epoch_ = 0;
    Hash256 snapshot_root_{};
    Hash256 member_commit_{};

    friend std::optional<AuthenticatedVote> AuthenticateVoteForMember(const SignedVote&, uint64_t,
                                                                      const Hash256&,
                                                                      const SnapshotEntry&,
                                                                      uint32_t, const Hash256&);
};

static_assert(!std::is_default_constructible<AuthenticatedVote>::value,
              "authenticated votes must not have a forgeable default token");
static_assert(!std::is_constructible<AuthenticatedVote, SignedVote>::value,
              "a SignedVote alone must not mint an authentication token");

// Hex -> ML-DSA public key. Rejects anything that is not exactly the expected
// length: a short key that happened to parse would silently verify nothing.
inline bool HexToPublicKey(const std::string& hex, ::veld::dilithium::PublicKey& out) {
    if (hex.size() != out.size() * 2)
        return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < out.size(); ++i) {
        const int hi = nib(hex[2 * i]), lo = nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

// Authenticate against one member copied from the canonical epoch snapshot.
// This is the out-of-lock network path: the caller resolves `member` while its
// state guard is held, copies only that one ~2 KiB key record plus epoch/root,
// releases the guard, and calls here.  A 3,398-member snapshot is therefore not
// copied once per untrusted packet.
inline std::optional<AuthenticatedVote>
AuthenticateVoteForMember(const SignedVote& v, uint64_t snapshot_epoch,
                          const Hash256& snapshot_root, const SnapshotEntry& member,
                          uint32_t network_id, const Hash256& genesis_hash) {
    if (!VoteClaimWellFormed(v, snapshot_epoch, snapshot_root))
        return std::nullopt;
    const Hash256 commit = PubkeyCommit(v.pubkey_hex);
    if (commit != member.pubkey_commit || v.pubkey_hex != member.pubkey_hex)
        return std::nullopt;

    const std::vector<uint8_t> msg = VotePreimage(network_id, genesis_hash, v.epoch_id, v.set_root,
                                                  v.phase, v.round, v.source, v.target);
    ::veld::dilithium::PublicKey pk{};
    if (!HexToPublicKey(v.pubkey_hex, pk) || !::veld::dilithium::Verify(pk, msg, v.signature))
        return std::nullopt;

    AuthenticatedVote authenticated(v, snapshot_epoch, snapshot_root, commit);
    return authenticated;
}

// General caller path: resolve the member from a complete retained snapshot,
// then produce the same typed capability as the one-member network path.
inline std::optional<AuthenticatedVote> AuthenticateVote(const SignedVote& v,
                                                         const EpochSnapshot& s,
                                                         uint32_t network_id,
                                                         const Hash256& genesis_hash) {
    if (!VoteClaimWellFormed(v, s.epoch_id, s.root))
        return std::nullopt;
    const size_t idx = SignerIndex(s, PubkeyCommit(v.pubkey_hex));
    if (idx == (size_t)-1)
        return std::nullopt;
    return AuthenticateVoteForMember(v, s.epoch_id, s.root, s.entries[idx], network_id,
                                     genesis_hash);
}

// Verify one vote against the epoch snapshot.
//
// Order matters and is deliberate: cheap structural rejects run before the
// ~1ms ML-DSA verification, so a flood of malformed votes cannot be turned
// into a CPU exhaustion vector against block validation.
inline bool VerifyVote(const SignedVote& v, const EpochSnapshot& s, uint32_t network_id,
                       const Hash256& genesis_hash) {
    return AuthenticateVote(v, s, network_id, genesis_hash).has_value();
}

// Recheck the canonical frame after out-of-lock signature verification.  The
// target hash is supplied from the candidate chain under its transition guard;
// height-only checks would admit a valid signature for an orphan sibling.
inline bool VoteMatchesCanonicalFrame(const SignedVote& v, const EpochSnapshot& s,
                                      uint64_t tip_height, const CheckpointRef& canonical_target,
                                      const FinalizedRecord& record) {
    if (!VoteClaimWellFormed(v, s.epoch_id, s.root) || !InVoteWindow(v.target.height, tip_height) ||
        v.target != canonical_target)
        return false;
    if (record.IsNull())
        return v.source.IsNull();
    return v.source == record.target && v.target.height > record.target.height;
}

// Assemble a quorum certificate from verified votes.
//
// Every vote must agree on epoch, set root, phase, round, source AND target: a
// certificate is a claim that a supermajority said the SAME thing, not that a
// supermajority said something. Votes that disagree belong to different
// certificates (and, if from one signer, are equivocation evidence).
//
// Returns nullopt unless the verified weight clears a strict two-thirds. The
// caller must have already established that each vote landed inside its
// target's inclusion window; a vote outside the window carries zero weight and
// is not an error.
inline std::optional<QuorumCert> AssembleQc(const std::vector<SignedVote>& votes,
                                            const EpochSnapshot& s, uint32_t network_id,
                                            const Hash256& genesis_hash) {
    if (votes.empty())
        return std::nullopt;
    if (!SnapshotWellFormed(s))
        return std::nullopt;

    const SignedVote& first = votes.front();
    QuorumCert qc;
    qc.epoch_id = s.epoch_id;
    qc.set_root = s.root;
    qc.phase = first.phase;
    qc.round = first.round;
    qc.source = first.source;
    qc.target = first.target;
    qc.bitmap.assign((s.entries.size() + 7) / 8, 0);

    for (const auto& v : votes) {
        // Unanimity of CLAIM, not of signer.
        if (v.phase != qc.phase || v.round != qc.round)
            return std::nullopt;
        if (v.source != qc.source || v.target != qc.target)
            return std::nullopt;
        if (!VerifyVote(v, s, network_id, genesis_hash))
            return std::nullopt;

        const size_t idx = SignerIndex(s, PubkeyCommit(v.pubkey_hex));
        if (idx == (size_t)-1)
            return std::nullopt;
        // Setting an already-set bit is a duplicate signer. Reject rather than
        // Ignore duplicates; they cannot increase certificate weight.
        // and neither should produce a certificate.
        const uint8_t mask = (uint8_t)(1u << (idx & 7));
        if (qc.bitmap[idx >> 3] & mask)
            return std::nullopt;
        qc.bitmap[idx >> 3] |= mask;
    }

    qc.weight = BitmapWeight(s, qc.bitmap);
    if (!IsSupermajority(qc.weight, s.total_weight))
        return std::nullopt;
    return qc;
}

// ---------------------------------------------------------------- evidence

// Two votes are equivocation iff one signer made two DIFFERENT claims in the
// same (epoch, phase, round). Same signer + same round + different target is
// the offense finality equivocation slashing prices at 0% principal return.
//
// This is the SAME-ROUND case. Cross-round conflicts (a precommit at round R
// followed by a prevote for a conflicting target at R' > R without the
// required unlock proof) are prevented proactively by the lock rule in
// finality_qc.h rather than punished after the fact — which is the point of
// choosing locked-QC over single-phase-plus-surround-evidence. Slashing prices
// a disaster; the lock stops honest validators ever producing one.
inline bool IsEquivocation(const SignedVote& a, const SignedVote& b) {
    if (a.pubkey_hex != b.pubkey_hex)
        return false;
    if (a.epoch_id != b.epoch_id)
        return false;
    if (a.phase != b.phase)
        return false;
    if (a.round != b.round)
        return false;
    return a.target != b.target; // same round, different claim
}

// Find any equivocating pair among a set of verified votes. Deterministic
// order: consensus must agree not only THAT there was an offense but on which
// exact pair evidences it, since the pair is what a slash transaction carries.
inline std::optional<std::pair<size_t, size_t>>
FindEquivocation(const std::vector<SignedVote>& votes) {
    for (size_t i = 0; i < votes.size(); ++i)
        for (size_t j = i + 1; j < votes.size(); ++j)
            if (IsEquivocation(votes[i], votes[j]))
                return std::make_pair(i, j);
    return std::nullopt;
}

} // namespace qc
} // namespace finality
} // namespace veld
