#pragma once
// btcVELD Layer-2 Bitcoin checkpoint anchoring.
//
// Permissionless finality anchor. Anyone may post an ANCHOR_SPV operation carrying
// an SPV proof that a Bitcoin tx committed a VELD block hash at a VELD height, via an
//   OP_RETURN:  "VELD_ANCHOR:" | veld_height(u64 LE) | veld_block_hash(32)
// Once that BTC tx is >= BTCVELD_ANCHOR_BTC_CONFS deep on the best Bitcoin chain,
// consensus stages the proof in its exact Veld carrier. It gains fork-choice authority
// only when a later retained QC finalizes a prefix containing that carrier and the BTC
// block is still k-deep. Consensus then REJECTS any permitted Veld rewrite whose block
// at H differs. Staging avoids permissionless partition self-pinning; carrier-finalized
// promotion prevents a reorg from erasing an already authoritative proof.
//
// Reuses the SPV verification substrate: BtcHeaderChain::VerifyMerkle /
// IsFinal + the btc_deposit_verify.h tx parsers — the same trust-minimized path that
// gates MINT. Read-only verify, fail-closed everywhere. The resident anchor
// window plus a rolling commitment to retired anchors join the
// ConsensusStateDigest so every node agrees (replay-exact) without retaining
// one map/set entry for every historical block.
//
// STATUS: the wiring is complete, but activation is state-derived rather than
// height-gated. Anchors become admissible only after this chain retains a real
// finalized checkpoint; there is no BTCVELD_ANCHOR_ACTIVATION_HEIGHT constant.

#include "core/btc_header_chain.h"
#include "core/btc_deposit_verify.h"   // ParseBtcTxOutputs, ExtractOpReturn, BtcTxOut, ::veld::Hash256d
#include "core/block.h"                // candidate-branch binding for the applying Veld block
#include "core/constants.h"            // chain-depth gate remains independent of anchor admission
#include "consensus/btcveld_anchor_params.h" // advertised proof-admission horizon
#include "consensus/finality_qc.h"     // full promotion record retained by permanent floor
#include "consensus/state_digest.h"
#include <unordered_map>
#include <vector>
#include <string>
#include <set>
#include <mutex>
#include <algorithm>
#include <cstring>
#include <optional>

namespace veld {
namespace btcanchor {

using ::veld::btcspv::H256;              // std::array<uint8_t,32> — Bitcoin-side hashes
using ::veld::btcspv::BtcHeaderChain;
using ::veld::btcspv::BtcTxOut;
using ::veld::btcspv::ParseBtcTxOutputs;
using ::veld::btcspv::ExtractOpReturn;

// ANCHOR_SPV v1 payload. Unlike fresh-genesis MINT_SPV MSP2, anchors retain the
// legacy remainder-is-transaction layout because they carry no mint nullifier:
//   "ANCH" | btc_block_hash(32) | merkle_dirs(u32 LE) | merkle_len(u8) | len×branch(32) | legacy_anchor_tx
inline bool ParseAnchorSpvOp(const uint8_t* p, size_t len, H256& btc_block_hash,
                             uint64_t& dirs, std::vector<H256>& branch,
                             std::vector<uint8_t>& legacy_tx) {
    if (len < 4 + 32 + 4 + 1) return false;
    if (p[0] != 'A' || p[1] != 'N' || p[2] != 'C' || p[3] != 'H') return false;
    size_t off = 4;
    std::memcpy(btc_block_hash.data(), p + off, 32); off += 32;
    dirs = ::veld::btcspv::rd_le32(p + off); off += 4;
    uint8_t mlen = p[off++];
    if (mlen > 32) return false;                              // a BTC block's Merkle depth is <= 32
    if (off + (size_t)mlen * 32 > len) return false;
    branch.clear();
    for (int i = 0; i < mlen; ++i) { branch.push_back(::veld::btcspv::rd_hash(p + off)); off += 32; }
    legacy_tx.assign(p + off, p + len);
    return !legacy_tx.empty();
}

struct AnchorResult {
    bool        ok = false;
    std::string reason;                 // diagnostic on reject
    uint64_t    veld_height = 0;
    ::veld::Hash256 veld_block_hash{};   // the committed VELD block hash (VELD-side type)
    H256        btc_block_hash{};        // exact best-chain block proven by the SPV payload
    H256        btc_txid{};             // idempotency key (BTC-side)
};

// A Bitcoin proof authenticates the bytes carried by the anchor transaction;
// it does not, by itself, prove that those bytes name the Veld branch which is
// currently being applied.  Bind the proven claim to that exact branch before
// it may enter AnchorSet.  The applying block is supplied directly because a
// linear precommit validates it before it has been appended to chain_.  Older
// heights are resolved by the caller so live precommit (chain mutex already
// held), startup replay, and accepted-reorg replay can each use their correct
// candidate-branch view without accidentally consulting the displaced branch.
//
// `resolve_ancestor(height, out_hash)` must return true only for a block on the
// branch ending in `applying_block`.  This helper is pure and records nothing.
template <typename ResolveAncestor>
inline bool MatchesAppliedVeldBranch(const AnchorResult& anchor,
                                     const ::veld::Block& applying_block,
                                     ResolveAncestor&& resolve_ancestor) {
    if (!anchor.ok || anchor.veld_height > applying_block.height) return false;

    ::veld::Hash256 expected{};
    if (anchor.veld_height == applying_block.height) {
        expected = applying_block.GetHash();
    } else if (!resolve_ancestor(anchor.veld_height, expected)) {
        return false;
    }
    return anchor.veld_block_hash == expected;
}

// Read-only verify: proves the anchor tx sits in a >= k_btc-final Bitcoin block and reads
// (veld_height, veld_block_hash) from its single VELD_ANCHOR OP_RETURN. Fail-closed —
// structurally identical to VerifyDepositMint (the proven MINT gate).
inline AnchorResult VerifyAnchor(const BtcHeaderChain& ch, const uint8_t* payload,
                                 size_t len, uint32_t k_btc) {
    AnchorResult r;
    H256 blk; uint64_t dirs = 0; std::vector<H256> branch; std::vector<uint8_t> tx;
    if (!ParseAnchorSpvOp(payload, len, blk, dirs, branch, tx)) { r.reason = "malformed ANCHOR_SPV op"; return r; }

    // Merkle-ambiguity guard (CVE-2012-2459 class) — a 64-byte "tx" can masquerade as two
    // interior nodes. A real anchor tx (>= one output + one OP_RETURN) is always larger.
    if (tx.size() <= 64) { r.reason = "anchor tx implausibly short (merkle-ambiguity guard)"; return r; }

    H256 txid = ::veld::Hash256d(tx);
    if (!ch.VerifyMerkle(blk, txid, branch, dirs)) { r.reason = "merkle proof invalid"; return r; }
    if (!ch.IsFinal(blk, k_btc))                   { r.reason = "btc block not final / not on best chain"; return r; }

    std::vector<BtcTxOut> outs;
    if (!ParseBtcTxOutputs(tx.data(), tx.size(), outs)) { r.reason = "anchor tx unparseable"; return r; }

    // exactly one "VELD_ANCHOR:" OP_RETURN carrying height(8 LE) + veld_block_hash(32)
    static const std::string TAG = "VELD_ANCHOR:";
    int n = 0; uint64_t h = 0; ::veld::Hash256 vh{};
    for (const auto& o : outs) {
        std::vector<uint8_t> d = ExtractOpReturn(o.spk);
        if (d.size() == TAG.size() + 8 + 32 && std::equal(TAG.begin(), TAG.end(), d.begin())) {
            const uint8_t* q = d.data() + TAG.size();
            uint64_t hv = 0; for (int i = 0; i < 8; ++i) hv |= (uint64_t)q[i] << (8 * i);
            h = hv;
            std::memcpy(vh.data(), q + 8, 32);
            ++n;
        }
    }
    if (n != 1) { r.reason = "anchor must have exactly one VELD_ANCHOR OP_RETURN"; return r; }

    r.ok = true;
    r.veld_height = h;
    r.veld_block_hash = vh;
    r.btc_block_hash = blk;
    r.btc_txid = txid;
    return r;
}

// Consensus anchor set. First-seen in canonical Veld block-processing order wins for a
// given Veld height; later or conflicting anchors are ignored. Digest-included so every
// node agrees. Only records what VerifyAnchor already proved.
class AnchorSet {
public:
    struct Entry {
        ::veld::Hash256 veld_block_hash{};
        uint64_t carrying_veld_height = 0;
        ::veld::Hash256 carrying_veld_hash{};
        H256 btc_block_hash{};
        H256 btc_txid{};
        // Filled only on promotion. This is the retained-QC carrier which
        // first covered the proof carrier, not the ANCHOR_SPV carrier itself.
        // Preserving it makes the permanent checkpoint transition replayable.
        uint64_t authorization_veld_height = 0;
        ::veld::Hash256 authorization_veld_hash{};
        ::veld::Hash256 authorization_finality_digest{};
    };

    struct PermanentCheckpoint {
        uint64_t target_height = 0;
        Entry entry{};
        // The exact retained-QC record that first authorized this permanent
        // floor.  Keeping only RecordDigest(record) was enough to compare
        // state, but not enough for an offline signer or a cold replay auditor
        // to inspect what was actually authorized.  Direct Record() test
        // fixtures leave this null and are deliberately not exportable.
        ::veld::finality::qc::FinalizedRecord authorization_record{};
    };

    struct PromotionResult {
        bool ok = true;
        size_t promoted = 0;
        size_t dropped_btc_reorg = 0;
    };

    // Advance the canonical Veld height even when a block carries no anchor.
    //
    // The public proof-admission window is also the bounded state-retention
    // window. After processing H, only promoted targets
    //
    //     target >= H - BTCVELD_ANCHOR_ACCEPT_WINDOW
    //
    // remain active. This exactly honors the advertised inclusive 1,000-block
    // window. Entries older than MAX_REORG_DEPTH are harmless in Allows(): the
    // chain-depth gate rejects such forks first. Retired promoted entries are
    // folded into a constant-size history commitment before erasure.
    //
    // Pending entries are deliberately not aged out here. Admission was fixed
    // at their carrier, and they must survive until the exact carrier is
    // finalized. If the target is older than this window at promotion, it is
    // folded directly into retired history. Consensus admission plus first-per-
    // target bounds pending state to the same finite window; Stage also applies
    // a defensive hard cap.
    void AdvanceHeight(uint64_t canonical_height) {
        std::lock_guard<std::mutex> lk(m_);
        AdvanceHeightLocked_(canonical_height);
    }

    // Stage a VERIFIED proof in the unfinalized Veld block which first carries
    // it.  A staged proof is digest-committed but does not affect Allows().  It
    // becomes an active checkpoint only after a later locked QC finalizes a
    // prefix containing the exact carrier.  This prevents a two-stage erasure
    // (drop the proof carrier while sharing its target, then rewrite the now-
    // forgotten target) without making two competing, unfinalized proof
    // carriers permanently freeze opposite sides of a partition.
    bool Stage(uint64_t veld_height,
               const ::veld::Hash256& veld_block_hash,
               uint64_t carrying_veld_height,
               const ::veld::Hash256& carrying_veld_hash,
               const H256& btc_block_hash,
               const H256& btc_txid) {
        std::lock_guard<std::mutex> lk(m_);
        if (veld_height > carrying_veld_height ||
            carrying_veld_hash == ::veld::Hash256{} ||
            btc_block_hash == H256{}) return false;
        AdvanceHeightLocked_(carrying_veld_height);
        if (veld_height < retain_from_) return false;
        if (anchored_.count(veld_height) || pending_.count(veld_height))
            return false;
        if (used_.count(btc_txid)) return false;
        constexpr size_t kPendingCap =
            static_cast<size_t>(BTCVELD_ANCHOR_ACCEPT_WINDOW) + 1u;
        if (pending_.size() >= kPendingCap) return false;
        used_.insert(btc_txid);
        pending_[veld_height] = Entry{veld_block_hash,
                                      carrying_veld_height,
                                      carrying_veld_hash,
                                      btc_block_hash,
                                      btc_txid};
        return true;
    }

    // Promote staged proofs whose exact carrier lies in the finalized prefix.
    // Validate the complete eligible set before mutating anything so a missing
    // or substituted carrier fails atomically rather than publishing a partial
    // anchor set.
    template <typename ResolveCarrier, typename IsBtcFinal>
    PromotionResult PromoteFinalized(uint64_t finalized_height,
                                     ResolveCarrier&& resolve_carrier,
                                     IsBtcFinal&& is_btc_final,
                                     const ::veld::finality::qc::FinalizedRecord&
                                         authorization_record) {
        std::lock_guard<std::mutex> lk(m_);
        std::vector<uint64_t> eligible;
        eligible.reserve(pending_.size());
        for (const auto& [target_height, entry] : pending_) {
            if (entry.carrying_veld_height <= finalized_height)
                eligible.push_back(target_height);
        }
        std::sort(eligible.begin(), eligible.end());
        if (!eligible.empty()) {
            if (authorization_record.IsNull() ||
                authorization_record.phase !=
                    ::veld::finality::qc::Phase::PRECOMMIT ||
                authorization_record.target.height != finalized_height ||
                authorization_record.carrier.height <
                    authorization_record.target.height ||
                authorization_record.carrier.hash == ::veld::Hash256{} ||
                ::veld::finality::qc::RecordDigest(authorization_record) ==
                    ::veld::Hash256{})
                return PromotionResult{false, 0, 0};

            // A superseding floor is authorized only on a canonical branch
            // which still contains the prior floor's exact QC carrier.  The
            // online reorg gate already enforces this; repeat the ancestry
            // check at the state transition so isolated/replay callers cannot
            // accidentally replace a floor after consulting the wrong branch.
            if (permanent_ &&
                !permanent_->authorization_record.IsNull()) {
                ::veld::Hash256 prior_carrier{};
                const auto& prior =
                    permanent_->authorization_record.carrier;
                if (!resolve_carrier(prior.height, prior_carrier) ||
                    prior_carrier != prior.hash)
                    return PromotionResult{false, 0, 0};
            }
        }
        for (uint64_t target_height : eligible) {
            const auto it = pending_.find(target_height);
            if (it == pending_.end()) return PromotionResult{false, 0, 0};
            ::veld::Hash256 canonical{};
            if (!resolve_carrier(it->second.carrying_veld_height, canonical) ||
                canonical != it->second.carrying_veld_hash)
                return PromotionResult{false, 0, 0};
        }
        size_t promoted = 0;
        size_t dropped_btc_reorg = 0;
        for (uint64_t target_height : eligible) {
            const auto it = pending_.find(target_height);
            if (it == pending_.end())
                return PromotionResult{false, 0, 0};
            // Promotion is a one-shot transition tied to the first retained QC
            // which covers the exact Veld carrier. If Bitcoin reorganized the
            // proven block off its best chain before that point, discard the
            // pending proof and require a fresh proof in a later carrier.
            if (!is_btc_final(it->second.btc_block_hash)) {
                used_.erase(it->second.btc_txid);
                pending_.erase(it);
                ++dropped_btc_reorg;
                continue;
            }
            Entry entry = it->second;
            if (authorization_record.target.height <
                    entry.carrying_veld_height ||
                authorization_record.carrier.height <
                    entry.carrying_veld_height)
                return PromotionResult{false, 0, 0};
            entry.authorization_veld_height =
                authorization_record.carrier.height;
            entry.authorization_veld_hash =
                authorization_record.carrier.hash;
            entry.authorization_finality_digest =
                ::veld::finality::qc::RecordDigest(
                    authorization_record);
            pending_.erase(it);
            if (target_height < retain_from_) {
                // Admission was valid in the earlier carrier, but a prolonged
                // finality delay moved the target outside the public window.
                // Count the authenticated milestone exactly once without
                // retaining a fork-choice entry that no future proof can name.
                FoldRetiredLocked_(target_height, entry);
                used_.erase(entry.btc_txid);
            } else {
                anchored_[target_height] = entry;
            }
            if (target_height > high_water_) high_water_ = target_height;
            if (!permanent_ || target_height > permanent_->target_height)
                permanent_ = PermanentCheckpoint{
                    target_height, entry, authorization_record};
            ++promoted;
        }
        return PromotionResult{true, promoted, dropped_btc_reorg};
    }

    // Direct finalized-record insertion retained for isolated AnchorSet
    // fixtures. Production consensus uses Stage()+PromoteFinalized(); callers
    // must never use this helper for an unfinalized carrier. Idempotent; never
    // overwrites. Rejected redundant proofs MUST NOT consume txids.
    bool Record(uint64_t veld_height, const ::veld::Hash256& veld_block_hash,
                uint64_t carrying_veld_height, const H256& btc_txid) {
        std::lock_guard<std::mutex> lk(m_);
        if (veld_height > carrying_veld_height) return false;
        // Record() is a defense-in-depth boundary as well as an internal API:
        // a verified anchor cannot commit a future Veld block, and callers
        // which forgot the per-block AdvanceHeight() still cannot grow state
        // beyond the public admission/retention horizon.
        AdvanceHeightLocked_(carrying_veld_height);
        if (veld_height < retain_from_) return false;
        if (anchored_.count(veld_height) || pending_.count(veld_height))
            return false;                                   // first-seen wins — no state change
        if (used_.count(btc_txid)) return false;             // same anchor tx replayed
        used_.insert(btc_txid);
        anchored_[veld_height] = Entry{veld_block_hash, carrying_veld_height,
                                       ::veld::Hash256{}, H256{}, btc_txid,
                                       0, ::veld::Hash256{},
                                       ::veld::Hash256{}};
        if (veld_height > high_water_) high_water_ = veld_height;
        if (!permanent_ || veld_height > permanent_->target_height)
            permanent_ = PermanentCheckpoint{veld_height,
                                              anchored_.at(veld_height), {}};
        return true;
    }

    // Fork-choice gate: a candidate block at `veld_height` with hash `h` is allowed only if
    // it matches the anchored hash (or nothing is anchored there). A chain rewriting an
    // anchored height is invalid regardless of PoW work.
    bool Allows(uint64_t veld_height, const ::veld::Hash256& h) const {
        std::lock_guard<std::mutex> lk(m_);
        if (permanent_ && permanent_->target_height == veld_height &&
            permanent_->entry.veld_block_hash != h)
            return false;
        auto it = anchored_.find(veld_height);
        return it == anchored_.end() || it->second.veld_block_hash == h;
    }

    // The highest promoted checkpoint subsumes every older promoted target:
    // its Veld block hash commits the complete ancestor prefix. It never ages
    // out. Reorgs must also preserve the retained-QC carrier that authorized
    // promotion, otherwise replay could erase the checkpoint transition.
    bool PermanentReorgPermitted(uint64_t common_ancestor_height) const {
        std::lock_guard<std::mutex> lk(m_);
        if (!permanent_) return true;
        const uint64_t carrier =
            !permanent_->authorization_record.IsNull()
                ? permanent_->authorization_record.carrier.height
                : (permanent_->entry.authorization_veld_height != 0
                    ? permanent_->entry.authorization_veld_height
                    : permanent_->entry.carrying_veld_height);
        return common_ancestor_height >= carrier;
    }

    std::optional<PermanentCheckpoint> Permanent() const {
        std::lock_guard<std::mutex> lk(m_);
        return permanent_;
    }

    struct PendingObservation {
        uint64_t target_height = 0;
        Entry entry{};
    };
    std::vector<PendingObservation> PendingForObservation() const {
        std::lock_guard<std::mutex> lk(m_);
        std::vector<PendingObservation> out;
        out.reserve(pending_.size());
        for (const auto& [height, entry] : pending_)
            out.push_back(PendingObservation{height, entry});
        std::sort(out.begin(), out.end(),
                  [](const PendingObservation& a, const PendingObservation& b) {
                      return a.target_height < b.target_height;
                  });
        return out;
    }

    uint64_t HighWater() const { std::lock_guard<std::mutex> lk(m_); return high_water_; }
    uint64_t RetentionFloor() const { std::lock_guard<std::mutex> lk(m_); return retain_from_; }
    uint64_t RetiredCount() const { std::lock_guard<std::mutex> lk(m_); return retired_count_; }
    size_t ActiveSize() const { std::lock_guard<std::mutex> lk(m_); return anchored_.size(); }
    size_t PendingSize() const { std::lock_guard<std::mutex> lk(m_); return pending_.size(); }
    bool HasPermanentCheckpoint() const {
        std::lock_guard<std::mutex> lk(m_);
        return permanent_.has_value();
    }
    bool HasExportablePermanentFloor() const {
        std::lock_guard<std::mutex> lk(m_);
        if (!permanent_ || permanent_->authorization_record.IsNull())
            return false;
        const auto& p = *permanent_;
        const auto& r = p.authorization_record;
        return p.target_height < p.entry.carrying_veld_height &&
               p.entry.carrying_veld_height <= r.target.height &&
               r.target.height <= r.carrier.height &&
               p.entry.authorization_veld_height == r.carrier.height &&
               p.entry.authorization_veld_hash == r.carrier.hash &&
               p.entry.authorization_finality_digest ==
                   ::veld::finality::qc::RecordDigest(r);
    }
    void Reset() {
        std::lock_guard<std::mutex> lk(m_);
        anchored_.clear();
        pending_.clear();
        permanent_.reset();
        used_.clear();
        high_water_ = 0;
        retain_from_ = 0;
        retired_count_ = 0;
        retired_root_ = {};
    }

    // Atomic block-state snapshot and restore. Captures exactly the
    // state Reset() clears, so a rejected block which records or retires a BTC
    // checkpoint anchor is rolled back verbatim.
    struct StateSnapshot {
        std::unordered_map<uint64_t, Entry> anchored;
        std::unordered_map<uint64_t, Entry> pending;
        std::optional<PermanentCheckpoint>  permanent;
        std::set<H256>                      used;
        uint64_t                            high_water = 0;
        uint64_t                            retain_from = 0;
        uint64_t                            retired_count = 0;
        ::veld::Hash256                     retired_root{};
    };
    StateSnapshot SnapshotState() const {
        std::lock_guard<std::mutex> lk(m_);
        return StateSnapshot{ anchored_, pending_, permanent_, used_, high_water_,
                              retain_from_, retired_count_, retired_root_ };
    }
    void RestoreState(const StateSnapshot& s) {
        std::lock_guard<std::mutex> lk(m_);
        anchored_   = s.anchored;
        pending_    = s.pending;
        permanent_  = s.permanent;
        used_       = s.used;
        high_water_ = s.high_water;
        retain_from_ = s.retain_from;
        retired_count_ = s.retired_count;
        retired_root_ = s.retired_root;
    }

    // Domain-separated digest over every block-mutable AnchorSet field.
    // V7 commits every future-decision field, including staged proof carriers,
    // their exact Bitcoin proof blocks, and accepted anchor txids
    // (which prevent one BTC transaction from anchoring two Veld heights) and the
    // high-water/retention cursors. The rolling retired root binds all pruned
    // history without retaining it. Rejected redundant or retired-height proofs
    // never enter any container or accumulator.
    ::veld::Hash256 Digest() const {
        std::lock_guard<std::mutex> lk(m_);
        namespace sd = ::veld::state_digest;
        std::vector<uint64_t> keys; keys.reserve(anchored_.size());
        for (const auto& [k, _v] : anchored_) keys.push_back(k);
        std::sort(keys.begin(), keys.end());
        std::vector<uint8_t> body;
        sd::put_u32_le(body, 7);  // encoding version
        sd::put_u64_le(body, retain_from_);
        sd::put_u64_le(body, retired_count_);
        body.insert(body.end(), retired_root_.begin(), retired_root_.end());
        sd::put_u32_le(body, (uint32_t)keys.size());
        for (uint64_t k : keys) {
            const auto& e = anchored_.at(k);
            sd::put_u64_le(body, k);
            body.insert(body.end(), e.veld_block_hash.begin(), e.veld_block_hash.end());
            sd::put_u64_le(body, e.carrying_veld_height);
            body.insert(body.end(), e.carrying_veld_hash.begin(),
                        e.carrying_veld_hash.end());
            body.insert(body.end(), e.btc_block_hash.begin(),
                        e.btc_block_hash.end());
            body.insert(body.end(), e.btc_txid.begin(), e.btc_txid.end());
            sd::put_u64_le(body, e.authorization_veld_height);
            body.insert(body.end(), e.authorization_veld_hash.begin(),
                        e.authorization_veld_hash.end());
            body.insert(body.end(), e.authorization_finality_digest.begin(),
                        e.authorization_finality_digest.end());
        }
        keys.clear();
        keys.reserve(pending_.size());
        for (const auto& [k, _v] : pending_) keys.push_back(k);
        std::sort(keys.begin(), keys.end());
        sd::put_u32_le(body, (uint32_t)keys.size());
        for (uint64_t k : keys) {
            const auto& e = pending_.at(k);
            sd::put_u64_le(body, k);
            body.insert(body.end(), e.veld_block_hash.begin(),
                        e.veld_block_hash.end());
            sd::put_u64_le(body, e.carrying_veld_height);
            body.insert(body.end(), e.carrying_veld_hash.begin(),
                        e.carrying_veld_hash.end());
            body.insert(body.end(), e.btc_block_hash.begin(),
                        e.btc_block_hash.end());
            body.insert(body.end(), e.btc_txid.begin(), e.btc_txid.end());
            sd::put_u64_le(body, e.authorization_veld_height);
            body.insert(body.end(), e.authorization_veld_hash.begin(),
                        e.authorization_veld_hash.end());
            body.insert(body.end(), e.authorization_finality_digest.begin(),
                        e.authorization_finality_digest.end());
        }
        sd::put_u8(body, permanent_ ? 1 : 0);
        if (permanent_) {
            const auto& p = *permanent_;
            const auto& e = p.entry;
            sd::put_u64_le(body, p.target_height);
            body.insert(body.end(), e.veld_block_hash.begin(),
                        e.veld_block_hash.end());
            sd::put_u64_le(body, e.carrying_veld_height);
            body.insert(body.end(), e.carrying_veld_hash.begin(),
                        e.carrying_veld_hash.end());
            body.insert(body.end(), e.btc_block_hash.begin(),
                        e.btc_block_hash.end());
            body.insert(body.end(), e.btc_txid.begin(), e.btc_txid.end());
            sd::put_u64_le(body, e.authorization_veld_height);
            body.insert(body.end(), e.authorization_veld_hash.begin(),
                        e.authorization_veld_hash.end());
            body.insert(body.end(), e.authorization_finality_digest.begin(),
                        e.authorization_finality_digest.end());
            sd::put_u8(body,
                       p.authorization_record.IsNull() ? 0 : 1);
            if (!p.authorization_record.IsNull()) {
                const auto rd = ::veld::finality::qc::RecordDigest(
                    p.authorization_record);
                body.insert(body.end(), rd.begin(), rd.end());
            }
        }
        sd::put_u32_le(body, (uint32_t)used_.size());
        for (const auto& txid : used_)
            body.insert(body.end(), txid.begin(), txid.end());
        sd::put_u64_le(body, high_water_);
        return sd::sha256_domain(sd::tags::ANCHORS, body);
    }

private:
    void FoldRetiredLocked_(uint64_t height, const Entry& e) {
        namespace sd = ::veld::state_digest;
        std::vector<uint8_t> body;
        body.reserve(32 + 8 + 32 + 8 + 32 + 32 + 32 + 8 + 32 + 32);
        body.insert(body.end(), retired_root_.begin(), retired_root_.end());
        sd::put_u64_le(body, height);
        body.insert(body.end(), e.veld_block_hash.begin(),
                    e.veld_block_hash.end());
        sd::put_u64_le(body, e.carrying_veld_height);
        body.insert(body.end(), e.carrying_veld_hash.begin(),
                    e.carrying_veld_hash.end());
        body.insert(body.end(), e.btc_block_hash.begin(),
                    e.btc_block_hash.end());
        body.insert(body.end(), e.btc_txid.begin(), e.btc_txid.end());
        sd::put_u64_le(body, e.authorization_veld_height);
        body.insert(body.end(), e.authorization_veld_hash.begin(),
                    e.authorization_veld_hash.end());
        body.insert(body.end(), e.authorization_finality_digest.begin(),
                    e.authorization_finality_digest.end());
        retired_root_ = sd::sha256_domain("VELD_ANCHOR_RETIRED_v3|", body);
        ++retired_count_;
    }

    void AdvanceHeightLocked_(uint64_t canonical_height) {
        static_assert(BTCVELD_ANCHOR_ACCEPT_WINDOW > 0,
                      "anchor retention requires a non-zero admission window");
        uint64_t next_floor = 0;
        if (canonical_height > BTCVELD_ANCHOR_ACCEPT_WINDOW) {
            next_floor = canonical_height - BTCVELD_ANCHOR_ACCEPT_WINDOW;
        }
        if (next_floor <= retain_from_) return;

        std::vector<uint64_t> retiring;
        retiring.reserve(anchored_.size());
        for (const auto& [height, _entry] : anchored_) {
            if (height < next_floor) retiring.push_back(height);
        }
        std::sort(retiring.begin(), retiring.end());

        for (uint64_t height : retiring) {
            const auto it = anchored_.find(height);
            if (it == anchored_.end()) continue;
            const Entry& e = it->second;
            FoldRetiredLocked_(height, e);
            used_.erase(e.btc_txid);
            anchored_.erase(it);
        }
        retain_from_ = next_floor;
    }

    mutable std::mutex m_;
    std::unordered_map<uint64_t, Entry> anchored_;   // veld_height -> authoritative anchor
    std::unordered_map<uint64_t, Entry> pending_;    // target -> proof awaiting carrier finality
    std::optional<PermanentCheckpoint>  permanent_;  // highest promoted target, never pruned
    std::set<H256>                      used_;       // btc_txid idempotency set
    uint64_t                            high_water_ = 0;
    uint64_t                            retain_from_ = 0; // inclusive public admission/active floor
    uint64_t                            retired_count_ = 0;
    ::veld::Hash256                     retired_root_{};
};

// Consensus integration:
//  1. btcveld_anchor_params.h derives admission from retained finalized state.
//  2. state_digest.h commits AnchorSet::Digest() to the consensus state digest.
//  3. node.h validates and stages ANCHOR_SPV operations, then rechecks Bitcoin
//     before promoting a finalized carrier.
//  4. blockchain.h requires AnchorSet::Allows() during fork selection.
//  5. The target must already be validator-final, and a staged proof remains
//     non-authoritative until its exact carrier is finalized.

}  // namespace btcanchor
}  // namespace veld
