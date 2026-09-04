#pragma once
// finality_producer.h — the OPERATOR side of locked-QC finality.
//
// Everything else in the finality layer is a consensus RULE: what a node will
// accept. This is the only piece that EMITS. Without it the rules are live but
// unreachable — a node correctly refuses to erase a certificate and correctly
// refuses to anchor before one exists, but no certificate can ever be produced,
// so the retained record stays null and the gates stay open forever.
//
// TWO ROLES, deliberately separated:
//
//   FinalityVoter    — a validator operator. Holds a secret key, decides what
//                      to vote for, persists a LOCK across restarts. This is
//                      the piece that can get an operator slashed, so its only
//                      job is refusing to sign anything unsafe.
//
//   CertAssembler    — a block producer. Holds no secrets. Collects gossiped
//                      votes and assembles a QC when a supermajority agrees.
//                      Assembling is permissionless: a certificate carries its
//                      own proof, so nothing is trusted about who built it.
//
// The split matters because the failure modes are different. A voter that
// misbehaves loses its bond. An assembler that misbehaves produces a
// certificate that simply fails verification and is ignored.
//
// NOT consensus-critical: nothing here is a validation rule. A node that
// disagrees with everything in this header still converges, because it accepts
// certificates on their proof, not their provenance. That is why this can be
// written, changed, or replaced without a fork.

#include "finality_qc.h"
#include "finality_votes.h"
#include "finality_codec.h"
#include "crypto/dilithium.h"

#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <functional>
#include <vector>

namespace veld {
namespace finality {
namespace qc {

// ---------------------------------------------------------------- voter

class FinalityVoter {
  public:
#ifdef VELD_TEST_HOOKS
    static void TestResetSignatureCount() noexcept {
        test_signature_count_.store(0, std::memory_order_release);
    }
    static uint64_t TestSignatureCount() noexcept {
        return test_signature_count_.load(std::memory_order_acquire);
    }
#endif
    FinalityVoter(std::string pubkey_hex, dilithium::SecretKey sk)
        : pubkey_hex_(std::move(pubkey_hex)), sk_(sk) {
        ::veld::compat::SecureLockMemory(sk_.data(), sk_.size());
    }
    ~FinalityVoter() {
        ::veld::compat::SecureZero(sk_.data(), sk_.size());
        ::veld::compat::SecureUnlockMemory(sk_.data(), sk_.size());
    }
    FinalityVoter(const FinalityVoter&) = delete;
    FinalityVoter& operator=(const FinalityVoter&) = delete;

    // The persisted lock. MUST survive restart: a validator that forgets its
    // lock and re-votes a conflicting target has equivocated, and equivocation
    // is the 0%-principal-return offense. Forgetting is indistinguishable from
    // lying, and the chain cannot tell the difference — nor should it have to.
    Lock lock() const {
        std::lock_guard<std::mutex> g(mu_);
        return lock_;
    }
    std::string pubkey_hex() const {
        std::lock_guard<std::mutex> g(mu_);
        return pubkey_hex_;
    }
    void RestoreLock(const Lock& l) {
        std::lock_guard<std::mutex> g(mu_);
        lock_ = l;
    }

    // Produce a PREVOTE, or refuse.
    //
    // Refusing is the whole point. This returns nullopt far more often than it
    // returns a vote, and every refusal is a slashing event that did not
    // happen.
    std::optional<SignedVote> Prevote(const EpochSnapshot& s, uint32_t round,
                                      const CheckpointRef& source, const CheckpointRef& target,
                                      const std::optional<DecodedQc>& unlock_proof,
                                      bool extends_lock, uint32_t network_id,
                                      const Hash256& genesis_hash) {
        std::lock_guard<std::mutex> g(mu_);
        if (!MemberOf_(s))
            return std::nullopt;
        if (!IsScheduledCheckpoint(target.height))
            return std::nullopt;
        if (round != CheckpointRound(target.height))
            return std::nullopt;
        if (target.IsNull())
            return std::nullopt;
        if (!SourceRefWellFormed(source, target))
            return std::nullopt;
        std::optional<QuorumCert> verified_unlock;
        if (unlock_proof) {
            DecodedQc proof = *unlock_proof;
            if (!VerifyDecodedQc(proof, s, network_id, genesis_hash) ||
                proof.qc.phase != Phase::PREVOTE)
                return std::nullopt;
            verified_unlock = std::move(proof.qc);
        }
        // The lock rule. This is the proactive half of the safety argument:
        // slashing prices a violation after the fact; the lock stops an honest
        // validator ever producing one.
        if (!LockedPrevoteAllowed(lock_, s.epoch_id, round, target, verified_unlock, extends_lock))
            return std::nullopt;
        return Sign_(s, Phase::PREVOTE, round, source, target, network_id, genesis_hash);
    }

    // Produce a PRECOMMIT, or refuse.
    //
    // A precommit is only safe once a PREVOTE QC for this exact target at this
    // exact round exists. Precommitting without one is precisely how two
    // conflicting certificates get built, so the proof is a required argument
    // rather than an optional courtesy — the type system refuses the unsafe
    // call.
    std::optional<SignedVote> Precommit(const EpochSnapshot& s, uint32_t round,
                                        const CheckpointRef& source, const CheckpointRef& target,
                                        DecodedQc prevote, uint32_t network_id,
                                        const Hash256& genesis_hash) {
        std::lock_guard<std::mutex> g(mu_);
        if (!MemberOf_(s))
            return std::nullopt;
        if (round != CheckpointRound(target.height))
            return std::nullopt;
        if (!VerifyDecodedQc(prevote, s, network_id, genesis_hash))
            return std::nullopt;
        const QuorumCert& prevote_qc = prevote.qc;
        if (prevote_qc.phase != Phase::PREVOTE)
            return std::nullopt;
        if (prevote_qc.round != round)
            return std::nullopt;
        if (prevote_qc.source != source)
            return std::nullopt;
        if (prevote_qc.target != target)
            return std::nullopt;
        // A valid QC can move a lock, but a stale/lower QC cannot overwrite a
        // newer conflicting lock.  Check (epoch,round) lexicographically
        // because the uint32 round resets at every epoch boundary.
        if (lock_.held && lock_.target != target &&
            !ConsensusRoundNewer(s.epoch_id, round, lock_.epoch_id, lock_.round))
            return std::nullopt;

        auto v = Sign_(s, Phase::PRECOMMIT, round, source, target, network_id, genesis_hash);
        if (v) {
            // Take the lock BEFORE the vote leaves. If the process dies between
            // signing and persisting, the lock must already reflect the
            // strongest claim we might have made — a lock that is too strong
            // costs liveness; one that is too weak costs the bond.
            lock_.held = true;
            lock_.epoch_id = s.epoch_id;
            lock_.round = round;
            lock_.target = target;
        }
        return v;
    }

  private:
    bool MemberOf_(const EpochSnapshot& s) const {
        return SignerIndex(s, PubkeyCommit(pubkey_hex_)) != (size_t)-1;
    }

    std::optional<SignedVote> Sign_(const EpochSnapshot& s, Phase phase, uint32_t round,
                                    const CheckpointRef& source, const CheckpointRef& target,
                                    uint32_t network_id, const Hash256& genesis_hash) const {
        SignedVote v;
        v.epoch_id = s.epoch_id;
        v.set_root = s.root;
        v.phase = phase;
        v.round = round;
        v.source = source;
        v.target = target;
        v.pubkey_hex = pubkey_hex_;
        const auto msg = VotePreimage(network_id, genesis_hash, v.epoch_id, v.set_root, phase,
                                      round, source, target);
#ifdef VELD_TEST_HOOKS
        test_signature_count_.fetch_add(1, std::memory_order_acq_rel);
#endif
        const auto sig = dilithium::Sign(sk_, msg);
        v.signature.assign(sig.begin(), sig.end());
        return v;
    }

    mutable std::mutex mu_;
    std::string pubkey_hex_;
    dilithium::SecretKey sk_{};
    Lock lock_;
#ifdef VELD_TEST_HOOKS
    inline static std::atomic<uint64_t> test_signature_count_{0};
#endif
};

// ---------------------------------------------------------------- assembler

class CertAssembler {
  public:
    static constexpr size_t MAX_POOL_VOTES = 8192;
    static constexpr size_t MAX_POOL_BYTES = 64u * 1024u * 1024u;
    // One honest progress frame needs a PREVOTE and PRECOMMIT quorum while as
    // many as N-quorum faulty members retain one slashable conflict pair each.
    // Those terms sum to exactly two votes per maximum-set member.  Keep both
    // hard pool limits large enough for that safety/liveness envelope.
    static constexpr size_t MAX_ACCOUNTED_VOTE_BYTES = sizeof(SignedVote) +
                                                       2u * ::veld::dilithium::PUBKEY_BYTES +
                                                       ::veld::dilithium::SIG_MAX_BYTES;
    static constexpr size_t MAX_LIVE_ENVELOPE_VOTES = 2u * MAX_FINALITY_VALIDATOR_COUNT;
    static_assert(MAX_LIVE_ENVELOPE_VOTES <= MAX_POOL_VOTES,
                  "finality pool cannot hold fault evidence plus two quorums");
    static_assert(MAX_LIVE_ENVELOPE_VOTES * MAX_ACCOUNTED_VOTE_BYTES <= MAX_POOL_BYTES,
                  "finality byte pool cannot hold fault evidence plus two quorums");

    // Take a gossiped vote. Verifies before storing — an unverified vote pool
    // is a memory-exhaustion surface, and storing junk to verify later just
    // moves the cost.
    bool Offer(const SignedVote& v, const EpochSnapshot& s, uint32_t network_id,
               const Hash256& genesis_hash) {
        auto authenticated = AuthenticateVote(v, s, network_id, genesis_hash);
        if (!authenticated)
            return false;
        return OfferAuthenticated(*authenticated, s);
    }

    // Store a vote whose ML-DSA signature has already been checked outside a
    // caller's consensus-transition critical section.  The unforgeable token
    // carries the snapshot identity used for that check; membership and root
    // are re-resolved against the current retained snapshot before any pool
    // mutation, but the expensive signature is never repeated here.
    bool OfferAuthenticated(const AuthenticatedVote& authenticated, const EpochSnapshot& s) {
        const SignedVote& v = authenticated.Vote();
        if (authenticated.SnapshotEpoch() != s.epoch_id || authenticated.SnapshotRoot() != s.root ||
            !VoteClaimWellFormed(v, s.epoch_id, s.root))
            return false;
        const size_t member_index = SignerIndex(s, authenticated.MemberCommit());
        if (member_index == (size_t)-1 || s.entries[member_index].pubkey_hex != v.pubkey_hex)
            return false;

        return StoreAuthenticatedVote_(v, s);
    }

#ifdef VELD_TEST_HOOKS
    // Capacity-only regression seam.  Production has no signature-bypass
    // entry point; test builds may exercise the exact bounded storage/eviction
    // machinery at MAX_FINALITY_VALIDATOR_COUNT without generating thousands
    // of ML-DSA keypairs and signatures.
    bool OfferAuthenticatedCapacityFixture(const SignedVote& v, const EpochSnapshot& s) {
        if (!VoteClaimWellFormed(v, s.epoch_id, s.root))
            return false;
        const size_t member_index = SignerIndex(s, PubkeyCommit(v.pubkey_hex));
        if (member_index == (size_t)-1 || s.entries[member_index].pubkey_hex != v.pubkey_hex)
            return false;
        return StoreAuthenticatedVote_(v, s);
    }
#endif

  private:
    bool StoreAuthenticatedVote_(const SignedVote& v, const EpochSnapshot& s) {

        std::lock_guard<std::mutex> g(mu_);

        if (!have_epoch_ || v.epoch_id > highest_epoch_) {
            highest_epoch_ = v.epoch_id;
            have_epoch_ = true;
            PruneBelowEpochLocked_(highest_epoch_ == 0 ? 0 : highest_epoch_ - 1);
        }
        if (have_epoch_ && v.epoch_id + 1 < highest_epoch_)
            return false;

        const SignerRoundKey srk{v.epoch_id, v.set_root, (uint8_t)v.phase, v.round,
                                 PubkeyCommit(v.pubkey_hex)};
        auto sr = signer_rounds_.find(srk);
        if (sr != signer_rounds_.end()) {
            if (SameVoteClaim_(sr->second.first, v))
                return false;
            // One slashable pair per signer per epoch is complete authority:
            // later sibling conflicts add no new penalty or safety evidence.
            // Bounding at epoch (not round) prevents fewer than one-third
            // Byzantine members from filling the pool with a fresh pair at
            // every checkpoint while honest weight still has a quorum.
            const EvidenceKey ek{v.epoch_id, PubkeyCommit(v.pubkey_hex)};
            if (evidence_signers_.find(ek) != evidence_signers_.end())
                return false;
            if (sr->second.conflict)
                return false;
            const size_t bytes = VoteBytes_(v);
            if (vote_count_ >= MAX_POOL_VOTES ||
                bytes > MAX_POOL_BYTES - std::min(pool_bytes_, MAX_POOL_BYTES))
                return false;
            sr->second.conflict = v;
            evidence_signers_.emplace(ek, srk);
            ++vote_count_;
            pool_bytes_ += bytes;
            return true;
        }

        const size_t bytes = VoteBytes_(v);
        if (vote_count_ >= MAX_POOL_VOTES ||
            bytes > MAX_POOL_BYTES - std::min(pool_bytes_, MAX_POOL_BYTES))
            return false;

        const Key k{v.epoch_id, v.set_root, (uint8_t)v.phase, v.round, v.source, v.target};
        auto& bucket = pool_[k];
        bucket.push_back(v);
        signer_rounds_.emplace(srk, SignerRoundVotes{v, std::nullopt});
        ++vote_count_;
        pool_bytes_ += bytes;
        return true;
    }

  public:
    // RPC retries are deliberately idempotent. A validator persists a vote
    // before sending it and must resend those exact bytes after a crash; that
    // retry is success, not a new pool entry. Conflicting siblings remain
    // rejected by Offer() and retained as equivocation evidence.
    bool HasExactVote(const SignedVote& v) const {
        std::lock_guard<std::mutex> g(mu_);
        const SignerRoundKey srk{v.epoch_id, v.set_root, (uint8_t)v.phase, v.round,
                                 PubkeyCommit(v.pubkey_hex)};
        const auto it = signer_rounds_.find(srk);
        if (it == signer_rounds_.end())
            return false;
        return SameSignedVote_(it->second.first, v) ||
               (it->second.conflict && SameSignedVote_(*it->second.conflict, v));
    }

    // Signature encodings may be randomized.  Network idempotency therefore
    // needs a same-claim query in addition to HasExactVote: re-signing an
    // unchanged target is not equivocation and must not consume another lane
    // or be treated as an invalid state transition.
    bool HasVoteClaim(const SignedVote& v) const {
        std::lock_guard<std::mutex> g(mu_);
        const SignerRoundKey srk{v.epoch_id, v.set_root, (uint8_t)v.phase, v.round,
                                 PubkeyCommit(v.pubkey_hex)};
        const auto it = signer_rounds_.find(srk);
        if (it == signer_rounds_.end())
            return false;
        return SameVoteClaim_(it->second.first, v) ||
               (it->second.conflict && SameVoteClaim_(*it->second.conflict, v));
    }

    // Once a completed pair exists, neither sibling may remain eligible for a
    // locally assembled QC.  Remove every vote by that signer in the offense
    // epoch, including a legacy conflict retained by older intake code.
    size_t RemoveSignerEpoch(uint64_t epoch, const Hash256& signer_commit) {
        std::lock_guard<std::mutex> g(mu_);
        size_t removed = 0;
        for (auto bucket = pool_.begin(); bucket != pool_.end();) {
            if (bucket->first.epoch != epoch) {
                ++bucket;
                continue;
            }
            auto& votes = bucket->second;
            const size_t before = votes.size();
            votes.erase(std::remove_if(votes.begin(), votes.end(),
                                       [&](const SignedVote& vote) {
                                           return PubkeyCommit(vote.pubkey_hex) == signer_commit;
                                       }),
                        votes.end());
            removed += before - votes.size();
            if (votes.empty())
                bucket = pool_.erase(bucket);
            else
                ++bucket;
        }
        for (auto it = signer_rounds_.begin(); it != signer_rounds_.end();) {
            if (it->first.epoch == epoch && it->first.signer == signer_commit) {
                if (it->second.conflict)
                    ++removed;
                it = signer_rounds_.erase(it);
            } else {
                ++it;
            }
        }
        evidence_signers_.erase(EvidenceKey{epoch, signer_commit});
        RecomputeAccountingLocked_();
        return removed;
    }

    // Assemble a certificate if a supermajority now agrees on some claim.
    // Returns the first that clears, in deterministic bucket order.
    std::optional<DecodedQc> TryAssemble(const EpochSnapshot& s, uint32_t network_id,
                                         const Hash256& genesis_hash,
                                         std::optional<Phase> phase = std::nullopt,
                                         const std::function<bool(const DecodedQc&)>& accept = {}) {
        std::lock_guard<std::mutex> g(mu_);
        for (auto& [k, votes] : pool_) {
            if (k.epoch != s.epoch_id)
                continue;
            if (phase && k.phase != (uint8_t)*phase)
                continue;
            // Offer() already paid the ML-DSA verification cost exactly once.
            // Polling the miner/RPC must never reverify an entire bucket.
            auto qc = AssembleVerifiedBucket_(k, votes, s);
            if (!qc)
                continue;

            DecodedQc d;
            d.qc = *qc;
            // Signatures in ascending SNAPSHOT INDEX order — the order
            // VerifyDecodedQc walks the bitmap. Any other order verifies as
            // garbage even though every signature is individually genuine.
            for (size_t i = 0; i < s.entries.size(); ++i) {
                if (!(d.qc.bitmap[i >> 3] & (uint8_t)(1u << (i & 7))))
                    continue;
                for (const auto& v : votes) {
                    if (PubkeyCommit(v.pubkey_hex) != s.entries[i].pubkey_commit)
                        continue;
                    d.sigs.push_back(v.signature);
                    break;
                }
            }
            if (accept && !accept(d))
                continue;
            return d;
        }
        return std::nullopt;
    }

    // Any equivocation visible in the pool. Same signer, same epoch/phase/round,
    // two targets — which means scanning ACROSS buckets, since conflicting
    // claims are what the bucket key separates.
    std::optional<std::pair<SignedVote, SignedVote>> FindConflict() const {
        std::lock_guard<std::mutex> g(mu_);
        for (const auto& [k, votes] : signer_rounds_) {
            (void)k;
            if (votes.conflict && IsEquivocation(votes.first, *votes.conflict))
                return std::make_pair(votes.first, *votes.conflict);
        }
        return std::nullopt;
    }

    // Drop everything for epochs below `keep_from`. The pool is unbounded
    // otherwise, and an unbounded operator-side pool is a slow memory leak that
    // only shows up after the chain has been running a while.
    void PruneBelowEpoch(uint64_t keep_from) {
        std::lock_guard<std::mutex> g(mu_);
        PruneBelowEpochLocked_(keep_from);
    }

    void Remove(const QuorumCert& qc) {
        std::lock_guard<std::mutex> g(mu_);
        const Key k{qc.epoch_id, qc.set_root, (uint8_t)qc.phase, qc.round, qc.source, qc.target};
        RemoveBucketLocked_(k);
    }

    // A carried PRECOMMIT certificate completes the claim's two-phase
    // lifecycle. Reclaim both ordinary vote buckets together; keeping the
    // PREVOTE half until epoch pruning exhausts the bounded pool at the third
    // maximum-set checkpoint. Actual equivocation pairs remain in
    // signer_rounds_ and evidence_signers_ until epoch pruning.
    void RemoveFinalizedClaim(const QuorumCert& qc) {
        if (qc.phase != Phase::PRECOMMIT)
            return;
        std::lock_guard<std::mutex> g(mu_);
        const Key precommit{qc.epoch_id, qc.set_root, (uint8_t)Phase::PRECOMMIT,
                            qc.round,    qc.source,   qc.target};
        const Key prevote{qc.epoch_id, qc.set_root, (uint8_t)Phase::PREVOTE,
                          qc.round,    qc.source,   qc.target};
        RemoveBucketLocked_(precommit);
        RemoveBucketLocked_(prevote);
    }

    size_t PoolSize() const {
        std::lock_guard<std::mutex> g(mu_);
        return vote_count_;
    }

    size_t PoolBytes() const {
        std::lock_guard<std::mutex> g(mu_);
        return pool_bytes_;
    }

  private:
    struct Key {
        uint64_t epoch;
        Hash256 set_root;
        uint8_t phase;
        uint32_t round;
        CheckpointRef source;
        CheckpointRef target;
        bool operator<(const Key& o) const {
            if (epoch != o.epoch)
                return epoch < o.epoch;
            if (set_root != o.set_root)
                return set_root < o.set_root;
            if (phase != o.phase)
                return phase < o.phase;
            if (round != o.round)
                return round < o.round;
            if (source.height != o.source.height)
                return source.height < o.source.height;
            if (source.hash != o.source.hash)
                return source.hash < o.source.hash;
            if (target.height != o.target.height)
                return target.height < o.target.height;
            return target.hash < o.target.hash;
        }
    };

    struct SignerRoundKey {
        uint64_t epoch;
        Hash256 set_root;
        uint8_t phase;
        uint32_t round;
        Hash256 signer;
        bool operator<(const SignerRoundKey& o) const {
            if (epoch != o.epoch)
                return epoch < o.epoch;
            if (set_root != o.set_root)
                return set_root < o.set_root;
            if (phase != o.phase)
                return phase < o.phase;
            if (round != o.round)
                return round < o.round;
            return signer < o.signer;
        }
    };
    struct EvidenceKey {
        uint64_t epoch;
        Hash256 signer;
        bool operator<(const EvidenceKey& o) const {
            if (epoch != o.epoch)
                return epoch < o.epoch;
            return signer < o.signer;
        }
    };
    struct SignerRoundVotes {
        SignedVote first;
        std::optional<SignedVote> conflict;
    };

    void RemoveBucketLocked_(const Key& k) {
        auto bucket = pool_.find(k);
        if (bucket == pool_.end())
            return;
        for (const auto& v : bucket->second) {
            const SignerRoundKey srk{v.epoch_id, v.set_root, (uint8_t)v.phase, v.round,
                                     PubkeyCommit(v.pubkey_hex)};
            auto sr = signer_rounds_.find(srk);
            // Preserve an actual conflict pair for evidence; ordinary votes
            // are reclaimed immediately so completed checkpoints return pool
            // capacity instead of leaking it until the epoch boundary.
            if (sr != signer_rounds_.end() && !sr->second.conflict) {
                --vote_count_;
                pool_bytes_ -= VoteBytes_(sr->second.first);
                signer_rounds_.erase(sr);
            }
        }
        pool_.erase(bucket);
    }

    static bool SameVoteClaim_(const SignedVote& a, const SignedVote& b) {
        return a.epoch_id == b.epoch_id && a.set_root == b.set_root && a.phase == b.phase &&
               a.round == b.round && a.source == b.source && a.target == b.target &&
               a.pubkey_hex == b.pubkey_hex;
    }
    static bool SameSignedVote_(const SignedVote& a, const SignedVote& b) {
        return SameVoteClaim_(a, b) && a.signature == b.signature;
    }
    static size_t VoteBytes_(const SignedVote& v) {
        return sizeof(SignedVote) + v.pubkey_hex.size() + v.signature.size();
    }
    static std::optional<QuorumCert> AssembleVerifiedBucket_(const Key& k,
                                                             const std::vector<SignedVote>& votes,
                                                             const EpochSnapshot& s) {
        if (votes.empty() || !SnapshotWellFormed(s) || k.epoch != s.epoch_id ||
            k.set_root != s.root)
            return std::nullopt;
        QuorumCert qc;
        qc.epoch_id = k.epoch;
        qc.set_root = k.set_root;
        qc.phase = (Phase)k.phase;
        qc.round = k.round;
        qc.source = k.source;
        qc.target = k.target;
        qc.bitmap.assign((s.entries.size() + 7) / 8, 0);
        for (const auto& v : votes) {
            const size_t idx = SignerIndex(s, PubkeyCommit(v.pubkey_hex));
            if (idx == (size_t)-1)
                return std::nullopt;
            const uint8_t mask = (uint8_t)(1u << (idx & 7));
            if (qc.bitmap[idx >> 3] & mask)
                return std::nullopt;
            qc.bitmap[idx >> 3] |= mask;
        }
        qc.weight = BitmapWeight(s, qc.bitmap);
        if (!QcWellFormed(qc, s))
            return std::nullopt;
        return qc;
    }
    void PruneBelowEpochLocked_(uint64_t keep_from) {
        for (auto it = pool_.begin(); it != pool_.end();) {
            if (it->first.epoch < keep_from)
                it = pool_.erase(it);
            else
                ++it;
        }
        for (auto it = signer_rounds_.begin(); it != signer_rounds_.end();) {
            if (it->first.epoch < keep_from)
                it = signer_rounds_.erase(it);
            else
                ++it;
        }
        for (auto it = evidence_signers_.begin(); it != evidence_signers_.end();) {
            if (it->first.epoch < keep_from)
                it = evidence_signers_.erase(it);
            else
                ++it;
        }
        // Recompute the hard accounting after the bounded prune. This path is
        // infrequent (once per epoch) and avoids fragile subtract bookkeeping.
        RecomputeAccountingLocked_();
    }
    void RecomputeAccountingLocked_() {
        vote_count_ = 0;
        pool_bytes_ = 0;
        for (const auto& [k, votes] : signer_rounds_) {
            (void)k;
            ++vote_count_;
            pool_bytes_ += VoteBytes_(votes.first);
            if (votes.conflict) {
                ++vote_count_;
                pool_bytes_ += VoteBytes_(*votes.conflict);
            }
        }
    }
    mutable std::mutex mu_;
    std::map<Key, std::vector<SignedVote>> pool_;
    std::map<SignerRoundKey, SignerRoundVotes> signer_rounds_;
    std::map<EvidenceKey, SignerRoundKey> evidence_signers_;
    size_t vote_count_ = 0;
    size_t pool_bytes_ = 0;
    uint64_t highest_epoch_ = 0;
    bool have_epoch_ = false;
};

// The OP_RETURN payload a block producer embeds to carry a certificate.
inline std::string BuildCertOpReturn(const DecodedQc& d) {
    return EncodeQc(d.qc, d.sigs);
}

} // namespace qc
} // namespace finality
} // namespace veld
