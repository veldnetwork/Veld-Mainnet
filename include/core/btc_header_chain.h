#pragma once
// Bitcoin header-chain state for the btcVELD SPV relay.
//
// The in-consensus Bitcoin header chain: ingest 80-byte headers, validate them
// EXACTLY as Bitcoin does (linkage, proof-of-work, 2016-block difficulty
// retarget, median-time-past, most-work selection), and verify a Merkle
// inclusion proof for a tx at K_btc depth on the best chain. Bootstraps from a
// compiled checkpoint at a retarget boundary (never from BTC genesis).
//
// accepting a forged header or a bad Merkle proof = a fake
// BTC deposit = an unbacked mint. All math is btc_pow.h (mainnet-proven). This
// The chain validates linkage, proof of work, median time past, retargets,
// most-work selection, reorganizations, and Merkle inclusion proofs.

#include "core/btc_pow.h"
#include <array>
#include <map>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cstdint>
#include <mutex>
#include <optional>

namespace veld {
namespace btcspv {

#if defined(VELD_PUBLIC_RELEASE) || defined(VELD_TEST_BTC_RELAY_FRESHNESS)
inline constexpr bool EXTERNAL_VALUE_FRESHNESS_REQUIRED = true;
#else
inline constexpr bool EXTERNAL_VALUE_FRESHNESS_REQUIRED = false;
#endif

// Public external-value transitions require more than local SPV depth: the
// proof block must also lie at or below a Bitcoin checkpoint independently
// observed by the validator finality quorum and promoted by Veld consensus.
#if defined(VELD_PUBLIC_RELEASE) || defined(VELD_TEST_BTC_OBSERVATION_FINALITY)
inline constexpr bool EXTERNAL_VALUE_OBSERVATION_REQUIRED = true;
#else
inline constexpr bool EXTERNAL_VALUE_OBSERVATION_REQUIRED = false;
#endif

using H256 = std::array<uint8_t, 32>;

inline uint32_t rd_le32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline H256 rd_hash(const uint8_t* p) {
    H256 h;
    std::memcpy(h.data(), p, 32);
    return h;
}

struct BtcHeaderRecord {
    std::array<uint8_t, 80> raw{};
    H256 block_hash{};
    H256 prev_hash{};
    H256 merkle_root{};
    uint32_t time = 0;
    uint32_t bits = 0;
    uint32_t height = 0;
    U256 chain_work;
};

// A pinned, deeply-buried BTC checkpoint. `height` MUST be a retarget boundary
// (height % retarget_interval == 0) so the first post-checkpoint retarget needs
// no pre-checkpoint headers. prev10_times = the 10 header times IMMEDIATELY
// BEFORE the checkpoint (oldest first) — seeds median-time-past for the first
// blocks after the checkpoint.
struct BtcCheckpoint {
    uint32_t height = 0;
    H256 hash{};
    uint32_t bits = 0;
    uint32_t time = 0;
    U256 chain_work;
    uint32_t prev10_times[10] = {0};
};

class BtcHeaderChain {
  public:
    // pow_limit = network's max target; retarget_interval/target_timespan are
    // 2016 / 1209600 on mainnet (overridable for tests). no_retarget = regtest.
    BtcHeaderChain(const BtcCheckpoint& cp, const U256& pow_limit,
                   uint32_t retarget_interval = 2016, int64_t target_timespan = 14 * 24 * 60 * 60,
                   bool no_retarget = false)
        : pow_limit_(pow_limit), retarget_interval_(retarget_interval),
          target_timespan_(target_timespan), no_retarget_(no_retarget), cp_(cp) {
        Init();
    }

    // Clear back to the compiled checkpoint. On a VELD reorg the node rebuilds
    // this object deterministically by Reset()-ing and replaying the new Veld
    // chain's BTC_HEADER ops — mirrors the token ledger's rebuild path.
    void Reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        by_hash_.clear();
        best_tip_ = H256{};
        observed_checkpoint_ = H256{};
        best_chain_.clear();
        Init();
    }

    // Atomic block-state snapshot and restore for the SPV header
    // chain. Captures the state Reset() clears (by_hash_ / best_tip_, NOT the
    // immutable retarget/checkpoint config), so a rejected block that relayed BTC
    // headers is rolled back verbatim. Mint replay identities live in the token
    // ledger's snapshot. RestoreState sets members directly — no Init().
    struct StateSnapshot {
        std::map<H256, BtcHeaderRecord> by_hash;
        H256 best_tip{};
        H256 observed_checkpoint{};
    };
    StateSnapshot SnapshotState() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return StateSnapshot{by_hash_, best_tip_, observed_checkpoint_};
    }
    void RestoreState(const StateSnapshot& s) {
        std::lock_guard<std::mutex> lock(mutex_);
        by_hash_ = s.by_hash;
        best_tip_ = s.best_tip;
        observed_checkpoint_ = s.observed_checkpoint;
        RebuildBestChainIndex();
        if (observed_checkpoint_ != H256{} &&
            (!by_hash_.count(observed_checkpoint_) || !OnBestChain(observed_checkpoint_)))
            throw std::invalid_argument(
                "restored BTC observation checkpoint is not on the selected chain");
    }

    // Deterministic consensus commitment that enters the Veld state digest so all
    // nodes agree on the complete BTC view.  Committing only best_tip_ was not
    // sufficient: two nodes could retain different validated side branches while
    // advertising the same digest, then accept the same child header differently
    // (or make a different fork-choice decision).  V2 therefore serializes every
    // retained record in std::map key order, the selected tip, and the immutable
    // validation parameters that give those records meaning. Exact-outpoint mint
    // replay state remains committed once by OnChainTokenLedger::Digest().
    H256 StateDigest() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<uint8_t> buf;
        static constexpr char DOMAIN[] = "VELD_D_SPV_v3_OBSERVED|";
        buf.insert(buf.end(), DOMAIN, DOMAIN + sizeof(DOMAIN) - 1);
        auto put_u8 = [&buf](uint8_t v) { buf.push_back(v); };
        auto put_u32 = [&buf](uint32_t v) {
            for (unsigned i = 0; i < 4; ++i)
                buf.push_back((uint8_t)(v >> (8 * i)));
        };
        auto put_u64 = [&buf](uint64_t v) {
            for (unsigned i = 0; i < 8; ++i)
                buf.push_back((uint8_t)(v >> (8 * i)));
        };
        auto put_h256 = [&buf](const H256& h) { buf.insert(buf.end(), h.begin(), h.end()); };
        auto put_u256 = [&put_u32](const U256& v) {
            for (uint32_t limb : v.w)
                put_u32(limb);
        };

        put_u256(pow_limit_);
        put_u32(retarget_interval_);
        put_u64((uint64_t)target_timespan_);
        put_u8(no_retarget_ ? 1 : 0);
        put_h256(cp_hash_);
        put_u32(cp_height_);
        for (uint32_t t : cp_prev10_)
            put_u32(t);
        put_h256(best_tip_);
        put_h256(observed_checkpoint_);
        put_u64((uint64_t)by_hash_.size());
        for (const auto& [key, rec] : by_hash_) {
            put_h256(key);
            buf.insert(buf.end(), rec.raw.begin(), rec.raw.end());
            put_h256(rec.block_hash);
            put_h256(rec.prev_hash);
            put_h256(rec.merkle_root);
            put_u32(rec.time);
            put_u32(rec.bits);
            put_u32(rec.height);
            put_u256(rec.chain_work);
        }
        return ::veld::Hash256d(buf);
    }

    // Ingest one 80-byte header. Returns true iff it is valid and now stored.
    // veld_block_time (if nonzero) bounds the header's future time to +2h against
    // the consensus-agreed Veld block that carries the relay op.
    bool SubmitHeader(const uint8_t raw[80], uint32_t veld_block_time = 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        H256 bh = BtcHeaderHash(raw);
        if (by_hash_.count(bh))
            return true; // idempotent
        H256 prev = rd_hash(raw + 4);
        auto pit = by_hash_.find(prev);
        if (pit == by_hash_.end())
            return false;                           // orphan — parent unknown
        const BtcHeaderRecord parent = pit->second; // copy (map may rehash on insert)

        uint32_t htime = rd_le32(raw + 68);
        uint32_t hbits = rd_le32(raw + 72);

        if (!CheckProofOfWork(raw, hbits, pow_limit_))
            return false; // PoW
        uint32_t want = ExpectedBits(parent);
        if (want == 0 || hbits != want)
            return false; // difficulty rule
        if (htime <= MedianTimePast(parent))
            return false;                                           // median-time-past
        if (veld_block_time != 0 && htime > veld_block_time + 7200) // future bound
            return false;

        BtcHeaderRecord r;
        std::memcpy(r.raw.data(), raw, 80);
        r.block_hash = bh;
        r.prev_hash = prev;
        r.merkle_root = rd_hash(raw + 36);
        r.time = htime;
        r.bits = hbits;
        r.height = parent.height + 1;
        bool neg = false, ov = false;
        r.chain_work = parent.chain_work + BlockWork(CompactToTarget(hbits, &neg, &ov));
        by_hash_[bh] = r;

        auto best_it = by_hash_.find(best_tip_);
        if (best_it == by_hash_.end()) {
            by_hash_.erase(bh); // corrupt local frame: fail closed
            return false;
        }
        if (r.chain_work > best_it->second.chain_work) {
            // A validator-finalized Bitcoin observation is an irreversible
            // rolling checkpoint. A later header branch may have more locally
            // visible work, but it cannot replace the selected branch if it
            // would rewrite that independently observed checkpoint.
            if (observed_checkpoint_ != H256{} && !DescendsFromLocked_(bh, observed_checkpoint_)) {
                by_hash_.erase(bh);
                return false;
            }
            const H256 old_tip = best_tip_;
            const uint32_t old_height = best_it->second.height;
            best_tip_ = bh;
            // The overwhelmingly common case is one new header extending the
            // selected tip.  Keep the canonical-height index O(1) here; only a
            // real Bitcoin reorg rebuilds its changed path.
            if (r.prev_hash == old_tip && r.height == old_height + 1 && r.height >= cp_height_ &&
                best_chain_.size() == static_cast<size_t>(r.height - cp_height_)) {
                best_chain_.push_back(bh);
            } else {
                RebuildBestChainIndex();
            }
        }
        return true;
    }

    uint32_t BestHeight() const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = by_hash_.find(best_tip_);
        return it == by_hash_.end() ? 0 : it->second.height;
    }
    H256 BestTip() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return best_tip_;
    }

    // Promote an independently observed Bitcoin block into the irreversible
    // rolling checkpoint. The caller is consensus code which has already
    // verified the anchor proof and the Veld validator QC covering its carrier.
    bool PromoteObservedCheckpoint(const H256& block_hash) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto candidate = by_hash_.find(block_hash);
        if (candidate == by_hash_.end() || !OnBestChain(block_hash))
            return false;
        if (observed_checkpoint_ == block_hash)
            return true;
        if (observed_checkpoint_ != H256{}) {
            auto prior = by_hash_.find(observed_checkpoint_);
            if (prior == by_hash_.end() || !OnBestChain(observed_checkpoint_))
                return false;
            if (candidate->second.height <= prior->second.height) {
                // Monotonic coverage, not monotonic anchor-arrival order: an
                // older best-chain block is already finalized by the newer
                // observation checkpoint iff the current checkpoint descends
                // from it. Treat that case as covered/idempotent.
                return DescendsFromLocked_(observed_checkpoint_, block_hash);
            }
        }
        observed_checkpoint_ = block_hash;
        return true;
    }

    H256 ObservedCheckpoint() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return observed_checkpoint_;
    }

    uint32_t ObservedCheckpointHeight() const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = by_hash_.find(observed_checkpoint_);
        return it == by_hash_.end() ? 0 : it->second.height;
    }
    // Consensus-only anti-staleness predicate for external-value admission.
    // It uses the candidate Veld timestamp plus the validated Bitcoin chain's
    // height/time; no node-local wall clock, peer count, or mutable operator
    // setting enters the decision.  A 48-hour deterministic tolerance absorbs
    // ordinary Bitcoin timestamp variance and relay outages, while the minimum
    // height schedule prevents a frozen/eclipsed checkpoint from permanently
    // reducing the private-work threshold.
    bool ExternalValueFresh(uint64_t veld_timestamp) const {
        if (!EXTERNAL_VALUE_FRESHNESS_REQUIRED)
            return true;
        if (veld_timestamp == 0)
            return false;
        std::lock_guard<std::mutex> lock(mutex_);
        auto best = by_hash_.find(best_tip_);
        if (best == by_hash_.end())
            return false;
        static constexpr uint64_t BTC_TARGET_SECONDS = 600;
        static constexpr uint64_t MAX_LAG_SECONDS = 48 * 60 * 60;
        static constexpr uint64_t MAX_LAG_BLOCKS = MAX_LAG_SECONDS / BTC_TARGET_SECONDS;
        if (static_cast<uint64_t>(best->second.time) > veld_timestamp &&
            static_cast<uint64_t>(best->second.time) - veld_timestamp > 2 * 60 * 60)
            return false;
        if (static_cast<uint64_t>(best->second.time) + MAX_LAG_SECONDS < veld_timestamp)
            return false;
        if (veld_timestamp <= cp_.time)
            return true;
        const uint64_t elapsed = veld_timestamp - cp_.time;
        const uint64_t expected_advance = elapsed / BTC_TARGET_SECONDS;
        const uint64_t required_advance =
            expected_advance > MAX_LAG_BLOCKS ? expected_advance - MAX_LAG_BLOCKS : 0;
        if (required_advance > UINT64_MAX - static_cast<uint64_t>(cp_height_))
            return false;
        return static_cast<uint64_t>(best->second.height) >=
               static_cast<uint64_t>(cp_height_) + required_advance;
    }
    bool Has(const H256& h) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return by_hash_.count(h) != 0;
    }
    // Return a copy: a pointer into by_hash_ would become unprotected as soon as
    // this method released the mutex and could race with SubmitHeader/Reset.
    std::optional<BtcHeaderRecord> Get(const H256& h) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = by_hash_.find(h);
        if (it == by_hash_.end())
            return std::nullopt;
        return it->second;
    }
    size_t Size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return by_hash_.size();
    }

    // Is `block_hash` on the best chain AND buried >= k deep?
    bool IsFinal(const H256& block_hash, uint32_t k) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = by_hash_.find(block_hash);
        if (it == by_hash_.end())
            return false;
        auto best = by_hash_.find(best_tip_);
        if (best == by_hash_.end())
            return false;
        if (!OnBestChain(block_hash))
            return false;
        return (uint64_t)it->second.height + k <= (uint64_t)best->second.height;
    }

    // External value is admitted only when BOTH ordinary SPV burial and the
    // independent validator-observation checkpoint cover the proof block. A
    // quorum without PoW/Merkle evidence cannot create value, and SPV evidence
    // without quorum observation remains inert.
    bool IsFinalForExternalValue(const H256& block_hash, uint32_t k) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = by_hash_.find(block_hash);
        auto best = by_hash_.find(best_tip_);
        if (it == by_hash_.end() || best == by_hash_.end() || !OnBestChain(block_hash) ||
            (uint64_t)it->second.height + k > (uint64_t)best->second.height)
            return false;
        if (!EXTERNAL_VALUE_OBSERVATION_REQUIRED)
            return true;
        auto observed = by_hash_.find(observed_checkpoint_);
        if (observed == by_hash_.end() || !OnBestChain(observed_checkpoint_))
            return false;
        return it->second.height <= observed->second.height;
    }

    // Verify a Merkle inclusion proof: folding `txid` up `branch` (dir bit i:
    // 1 = sibling on the LEFT, 0 = on the RIGHT) yields the header's merkle root.
    bool VerifyMerkle(const H256& block_hash, const H256& txid, const std::vector<H256>& branch,
                      uint64_t dirs) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = by_hash_.find(block_hash);
        if (it == by_hash_.end())
            return false;
        H256 h = txid;
        for (size_t i = 0; i < branch.size(); ++i) {
            uint8_t buf[64];
            if ((dirs >> i) & 1u) {
                std::memcpy(buf, branch[i].data(), 32);
                std::memcpy(buf + 32, h.data(), 32);
            } else {
                std::memcpy(buf, h.data(), 32);
                std::memcpy(buf + 32, branch[i].data(), 32);
            }
            h = ::veld::Hash256d(buf, 64);
        }
        return h == it->second.merkle_root;
    }

  private:
    mutable std::mutex mutex_;
    std::map<H256, BtcHeaderRecord> by_hash_;
    H256 best_tip_{};
    H256 observed_checkpoint_{}; // validator-QC-observed rolling BTC floor
    // Derived, non-consensus cache: entry i is the selected Bitcoin block at
    // height cp_height_ + i.  IsFinal used to walk backward from best_tip_ for
    // every SPV mint/anchor proof, making one Veld block's validation cost grow
    // as O(proofs * Bitcoin-chain-age).  The cache makes membership O(1).  It is
    // rebuilt from the digest-committed by_hash_/best_tip_ after restore/reorg,
    // so it adds no independently mutable consensus state.
    std::vector<H256> best_chain_;
    U256 pow_limit_;
    uint32_t retarget_interval_;
    int64_t target_timespan_;
    bool no_retarget_;
    BtcCheckpoint cp_{};
    H256 cp_hash_{};
    uint32_t cp_height_ = 0;
    uint32_t cp_prev10_[10] = {0};

    void Init() {
        cp_hash_ = cp_.hash;
        cp_height_ = cp_.height;
        std::memcpy(cp_prev10_, cp_.prev10_times, sizeof(cp_prev10_));
        BtcHeaderRecord r;
        r.block_hash = cp_.hash;
        r.time = cp_.time;
        r.bits = cp_.bits;
        r.height = cp_.height;
        r.chain_work = cp_.chain_work;
        // prev_hash/merkle_root/raw unknown for the checkpoint anchor — never used
        // (nothing links into the checkpoint's parent; MTP uses cp_prev10_).
        by_hash_[cp_.hash] = r;
        best_tip_ = cp_.hash;
        best_chain_.assign(1, cp_.hash);
    }

    // expected nBits for parent's child. 0 == "cannot determine" (reject).
    uint32_t ExpectedBits(const BtcHeaderRecord& parent) const {
        if (no_retarget_)
            return parent.bits;
        uint32_t next_h = parent.height + 1;
        if (next_h % retarget_interval_ != 0)
            return parent.bits;
        // retarget: walk back (interval-1) to the epoch's first header.
        const BtcHeaderRecord* first = &parent;
        for (uint32_t i = 0; i + 1 < retarget_interval_; ++i) {
            auto it = by_hash_.find(first->prev_hash);
            if (it == by_hash_.end())
                return 0; // missing ancestor — fail closed
            first = &it->second;
        }
        return CalcNextBits(parent.bits, (int64_t)parent.time - (int64_t)first->time, pow_limit_,
                            target_timespan_);
    }

    // median of parent + its 10 ancestors (drawing on the checkpoint seed if near it)
    uint32_t MedianTimePast(const BtcHeaderRecord& parent) const {
        std::vector<uint32_t> t;
        const BtcHeaderRecord* cur = &parent;
        int guard = 0;
        while (t.size() < 11) {
            t.push_back(cur->time);
            if (cur->block_hash == cp_hash_) {
                for (int j = 9; j >= 0 && t.size() < 11; --j)
                    t.push_back(cp_prev10_[j]);
                break;
            }
            auto it = by_hash_.find(cur->prev_hash);
            if (it == by_hash_.end())
                break;
            cur = &it->second;
            if (++guard > 24)
                break;
        }
        std::sort(t.begin(), t.end());
        return t.empty() ? 0 : t[t.size() / 2];
    }

    void RebuildBestChainIndex() {
        std::vector<H256> reversed;
        auto tip = by_hash_.find(best_tip_);
        if (tip == by_hash_.end() || tip->second.height < cp_height_) {
            best_chain_.clear();
            return;
        }
        reversed.reserve(static_cast<size_t>(tip->second.height - cp_height_) + 1);
        H256 cur = best_tip_;
        uint32_t expected_height = tip->second.height;
        for (size_t guard = 0; guard <= by_hash_.size(); ++guard) {
            auto it = by_hash_.find(cur);
            if (it == by_hash_.end() || it->second.height != expected_height) {
                best_chain_.clear();
                return;
            }
            reversed.push_back(cur);
            if (cur == cp_hash_) {
                if (expected_height != cp_height_) {
                    best_chain_.clear();
                    return;
                }
                std::reverse(reversed.begin(), reversed.end());
                best_chain_.swap(reversed);
                return;
            }
            if (expected_height == 0)
                break;
            cur = it->second.prev_hash;
            --expected_height;
        }
        best_chain_.clear();
    }

    bool DescendsFromLocked_(H256 child, const H256& ancestor) const {
        auto anc = by_hash_.find(ancestor);
        auto cur = by_hash_.find(child);
        if (anc == by_hash_.end() || cur == by_hash_.end() ||
            cur->second.height < anc->second.height)
            return false;
        uint32_t height = cur->second.height;
        for (size_t guard = 0; guard <= by_hash_.size(); ++guard) {
            if (child == ancestor)
                return true;
            if (height <= anc->second.height)
                return false;
            auto it = by_hash_.find(child);
            if (it == by_hash_.end())
                return false;
            child = it->second.prev_hash;
            --height;
        }
        return false;
    }

    // O(1) selected-chain membership after the hash lookup already performed
    // by callers.  A missing/corrupt derived index always fails closed.
    bool OnBestChain(const H256& h) const {
        auto it = by_hash_.find(h);
        if (it == by_hash_.end() || it->second.height < cp_height_)
            return false;
        const size_t offset = static_cast<size_t>(it->second.height - cp_height_);
        return offset < best_chain_.size() && best_chain_[offset] == h;
    }
};

} // namespace btcspv
} // namespace veld
