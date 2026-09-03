#pragma once

#include "block.h"
#include "chain_work.h"
#include "constants.h"
#include "script.h"
#include "marker_composition.h"
#include "stake_marker.h"
#include "pqc_script.h"
#include "../mining/veldhash.h"
#include "../crypto/veld_signing.h"
#include "../consensus/nms.h"
#include "../consensus/state_digest.h"
#ifdef VELD_TEST_PHASE_INTERLEAVE
#include "../test/phase_interleave.h"
#endif
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>
#include <optional>
#include <algorithm>
#include <queue>
#include <deque>
#include <functional>
#include <cmath>
#include <stdexcept>
#include <iostream>
#include <cstdint>
#include <chrono>
#include <mutex>
#include <shared_mutex>

namespace veld {

// Canonical value-bearing OP_RETURN destination for the A3 finality-
// equivocation burn. Blockchain::CommitBlock excludes every OP_RETURN from
// the UTXO set, so value sent here is provably unspendable and can never enter
// the distributable protocol vault. The fixed tag makes the destruction
// independently auditable from transaction bytes.
inline const std::vector<uint8_t>& FinalityEquivocationBurnScript() {
    static const std::vector<uint8_t> script = [] {
        const std::string tag = "VELD_BURN|FINALITY_EQUIVOCATION|v1";
        std::vector<uint8_t> out{0x6A, static_cast<uint8_t>(tag.size())};
        out.insert(out.end(), tag.begin(), tag.end());
        return out;
    }();
    return script;
}

struct UTXO {
    Hash256  tx_hash;
    uint32_t output_index;
    uint64_t value;
    std::vector<uint8_t> script_pubkey;
    uint64_t block_height;
    bool is_coinbase = false;

    UTXO() : output_index(0), value(0), block_height(0) {
        tx_hash = ZeroHash();
    }
};

inline std::string UTXOKey(const Hash256& hash, uint32_t index) {
    return HashToHex(hash) + ":" + std::to_string(index);
}

struct ChainIndexEntry {
    Hash256  hash;
    Hash256  prev_hash;
    uint64_t height;
    ChainWork cumulative_work;
    bool     on_main_chain;

    ChainIndexEntry() : height(0), cumulative_work(0), on_main_chain(false) {
        hash = ZeroHash(); prev_hash = ZeroHash();
    }
};

inline bool BetterChainScore(const ChainWork& candidate_work,
                             uint64_t candidate_height,
                             const std::string& candidate_hash,
                             const ChainWork& current_work,
                             uint64_t current_height,
                             const std::string& current_hash) {
    if (candidate_work != current_work) return candidate_work > current_work;
    if (candidate_height != current_height) return candidate_height > current_height;
    return candidate_hash < current_hash;
}

// Fork-aware engine-overlay declarations live at file scope so they refer to
// the consensus engine types rather than nested Blockchain types. The engines
// are defined in their respective consensus headers.
class ValidatorRegistry;
class StakingLedger;
class GovernanceEngine;
class OnChainTokenLedger;
class AmmLedger;

class Blockchain {
public:
    inline static thread_local std::string last_reject_tag_;
    static const std::string& GetLastRejectTag() { return last_reject_tag_; }

    enum class ReplayValidationDisposition : uint8_t {
        Valid,
        ConsensusInvalid,
        DeferredLocalWork,
    };

    enum class ReorgDisposition : uint8_t {
        Applied,
        ConsensusInvalid,
        DeferredLocalWork,
    };

    enum class BlockAdmissionDisposition : uint8_t {
        Accepted,
        ConsensusInvalid,
        DeferredLocalWork,
    };

    // Preserve source compatibility with existing boolean callers while
    // exposing the distinction required at relay/credit boundaries: a block
    // retained only in volatile side quarantine is not yet accepted.
    class BlockAdmissionResult {
    public:
        constexpr BlockAdmissionResult(bool accepted) noexcept
            : disposition_(accepted
                  ? BlockAdmissionDisposition::Accepted
                  : BlockAdmissionDisposition::ConsensusInvalid) {}
        constexpr explicit BlockAdmissionResult(
                BlockAdmissionDisposition disposition) noexcept
            : disposition_(disposition) {}
        static constexpr BlockAdmissionResult Accepted() noexcept {
            return BlockAdmissionResult(BlockAdmissionDisposition::Accepted);
        }
        static constexpr BlockAdmissionResult ConsensusInvalid() noexcept {
            return BlockAdmissionResult(
                BlockAdmissionDisposition::ConsensusInvalid);
        }
        static constexpr BlockAdmissionResult DeferredLocalWork() noexcept {
            return BlockAdmissionResult(
                BlockAdmissionDisposition::DeferredLocalWork);
        }
        constexpr bool IsAccepted() const noexcept {
            return disposition_ == BlockAdmissionDisposition::Accepted;
        }
        constexpr bool IsDeferred() const noexcept {
            return disposition_ ==
                BlockAdmissionDisposition::DeferredLocalWork;
        }
        constexpr BlockAdmissionDisposition Disposition() const noexcept {
            return disposition_;
        }
        constexpr operator bool() const noexcept { return IsAccepted(); }
    private:
        BlockAdmissionDisposition disposition_;
    };

    struct SpenderLocator {
        uint64_t block_height{0};
        uint32_t tx_index{0};
        Hash256  txid{};
    };

    struct CanonicalSpender {
        Transaction tx;
        uint64_t    block_height{0};
        Hash256     block_hash{};
    };

    struct UTXOMapBundle {
        std::unordered_map<std::string, UTXO> set;
        std::unordered_map<std::string, std::unordered_set<std::string>> index;
        std::unordered_map<std::string, SpenderLocator> spenders;
        uint64_t supply_units{0};
        uint64_t fees_collected_units{0};
    };

    // Exact bounded durable mutation set for a disconnect/reorg.  `value` is
    // the final canonical UTXO at `key`; nullopt means the key must be erased.
    // Every key comes from a block inside MAX_REORG_DEPTH, so persistence work
    // is proportional to the changed suffix rather than the lifetime UTXO set.
    struct UTXODeltaEntry {
        std::string key;
        std::optional<UTXO> value;
    };
    using UTXODelta = std::vector<UTXODeltaEntry>;

    // Exact canonical-frame comparator used by the reorg dual-construction
    // sentinel. Cardinality is not enough: two equal-size UTXO maps can name
    // different outpoints or carry different value/script/maturity metadata,
    // and would validate the next spend differently. Include both rebuildable
    // indexes and the accounting scalars for the same reason.
    static bool SameUTXOMapBundle(const UTXOMapBundle& a,
                                  const UTXOMapBundle& b) {
        if (a.supply_units != b.supply_units ||
            a.fees_collected_units != b.fees_collected_units ||
            a.set.size() != b.set.size() ||
            a.index != b.index ||
            a.spenders.size() != b.spenders.size()) {
            return false;
        }
        for (const auto& [key, left] : a.set) {
            auto it = b.set.find(key);
            if (it == b.set.end()) return false;
            const UTXO& right = it->second;
            if (left.tx_hash != right.tx_hash ||
                left.output_index != right.output_index ||
                left.value != right.value ||
                left.script_pubkey != right.script_pubkey ||
                left.block_height != right.block_height ||
                left.is_coinbase != right.is_coinbase) {
                return false;
            }
        }
        for (const auto& [key, left] : a.spenders) {
            auto it = b.spenders.find(key);
            if (it == b.spenders.end()) return false;
            const SpenderLocator& right = it->second;
            if (left.block_height != right.block_height ||
                left.tx_index != right.tx_index ||
                left.txid != right.txid) {
                return false;
            }
        }
        return true;
    }

    // Fork-aware engine overlay. Forward declarations let
    // AltEngineOverlay hold pointers without dragging
    // their full headers into blockchain.h's include surface. The
    // engines themselves remain in their respective consensus/*.h
    // headers; node.h includes both blockchain.h and the engine headers
    // before constructing the overlay.
    //
    // Reorganization overlay design:
    //   During Reorganize's alt-apply loop, the node's main validators,
    //   staking, token, AMM, BTC-header, and redeem-covenant engines still
    //   describe the pre-reorg main chain. Engine-dependent VBFR gates cannot
    //   safely consult those objects while validating a candidate branch.
    //
    //   The overlay solves this: VeldNode's BuildAltOverlay constructs side
    //   engines and replays them through the common ancestor; Reorganize then
    //   validates and advances them once per candidate block. Chain callbacks
    //   (bond_settlements_fn_, nms_stake_query_, etc.) consult the
    //   overlay when set, the main engines otherwise.
    //
    // RUNTIME STATUS: FULLY WIRED. WireDB installs build/advance/teardown
    // callbacks; Reorganize arms the overlay before VBFR, advances it only
    // after each block passes, and an RAII guard tears it down on success,
    // rejection, or exception. Standalone Blockchain harnesses that install no
    // callbacks retain the explicit fail-closed fallback below. Reorg/NMS/stake
    // and engine-equivalence regressions exercise the wired path.

    struct AltEngineOverlay {
        const ValidatorRegistry* validators = nullptr;
        const StakingLedger*     staking    = nullptr;
        const GovernanceEngine*  governance = nullptr;
        // btcVELD: non-const (the AMM guard dry-runs ValidateBlock, which moves
        // btcVELD through the token ledger). Fork-aware pool state during reorg
        // eval, so a pool-spend on an alt chain is judged against the ALT chain's
        // committed pool outpoint + reserves, not the main chain's.
        OnChainTokenLedger*      tokens     = nullptr;
        AmmLedger*               amm        = nullptr;
    };

    inline static thread_local const AltEngineOverlay* alt_engine_overlay_ = nullptr;

    class AltEngineOverlayGuard {
    public:
        explicit AltEngineOverlayGuard(const AltEngineOverlay* o)
            : prev_(alt_engine_overlay_) { alt_engine_overlay_ = o; }
        ~AltEngineOverlayGuard() { alt_engine_overlay_ = prev_; }
        AltEngineOverlayGuard(const AltEngineOverlayGuard&) = delete;
        AltEngineOverlayGuard& operator=(const AltEngineOverlayGuard&) = delete;
    private:
        const AltEngineOverlay* prev_;
    };

    inline static thread_local const UTXOMapBundle* validation_overlay_ = nullptr;
    class ValidationOverlayGuard {
    public:
        explicit ValidationOverlayGuard(const UTXOMapBundle* ovr)
            : prev_(validation_overlay_) { validation_overlay_ = ovr; }
        ~ValidationOverlayGuard() { validation_overlay_ = prev_; }
        ValidationOverlayGuard(const ValidationOverlayGuard&) = delete;
        ValidationOverlayGuard& operator=(const ValidationOverlayGuard&) = delete;
    private:
        const UTXOMapBundle* prev_;
    };

    struct ReorgProposal {
        std::string         old_tip_hash;
        std::string         new_tip_hash;
        std::string         ancestor;
        uint64_t            anc_height = 0;
        ChainWork           anc_cumulative_work = 0;
        std::vector<Block>  new_path_blocks;
        std::vector<Block>  orphaned_tail;
        UTXOMapBundle       side_utxo_set;
        uint64_t            prepare_started_at_height = 0;
    };

    size_t ClearBadAltTips() {
        std::unique_lock<std::shared_mutex> lk(chain_mutex_);
        size_t n = bad_alt_tips_.size();
        bad_alt_tips_.clear();
        return n;
    }
    size_t BadAltTipCount() const {
        std::shared_lock<std::shared_mutex> lk(chain_mutex_);
        return bad_alt_tips_.size();
    }

    Blockchain() {
        total_supply_units_.store(0);
        atomic_height_.store(0);
    }

    // Canonical block bodies are durable data, not lifetime in-memory state.
    // Keep only the exact consensus reorg horizon resident; older callers use
    // the node-installed loader below and validate the complete durable frame
    // before it is returned.  Headers/height/hash metadata remain resident for
    // fork choice, difficulty and locator construction.
    static constexpr uint64_t CANONICAL_BODY_RETENTION_BLOCKS =
        MAX_REORG_DEPTH;
    static_assert(CANONICAL_BODY_RETENTION_BLOCKS >= MAX_REORG_DEPTH,
                  "canonical body cache must cover every permitted reorg");

    // One maximum-budget candidate suffix (2*depth) plus the displaced
    // canonical suffix (depth) must coexist while a reorg is being made
    // durable.  This is also the hostile-network cardinality bound for all
    // non-canonical headers/bodies retained by one process.
    static constexpr size_t SIDE_BRANCH_HEADER_LIMIT =
        3 * MAX_REORG_DEPTH;
    static constexpr uint64_t SIDE_BRANCH_DURABLE_BYTE_LIMIT =
        SIDE_BRANCH_HEADER_LIMIT * static_cast<uint64_t>(MAX_BLOCK_SIZE);

    using HistoricalBlockLoader = std::function<
        std::optional<std::vector<uint8_t>>(const Hash256&)>;
    using DurableBlockBodyWriter = std::function<
        bool(const Hash256&, const std::vector<uint8_t>&)>;
    using DurableBlockBodyEraser = std::function<bool(const Hash256&)>;
    struct LocalWorkAdmissionTicket {
        std::shared_ptr<void> owner;
        std::function<bool(
            uint64_t, uint64_t, uint32_t, const Hash256&, const Hash256&)>
            claim_for_canonical_commit;
        std::function<bool()> live;

        Hash256 candidate_hash{};
        uint64_t candidate_height{0};
        Hash256 parent_hash{};
        mining::LocalWorkKind source{mining::LocalWorkKind::None};
        std::string work_binding;
        std::string work_authorization;
        Hash256 work_identity{};
        uint64_t validation_generation{0};
        uint64_t coordinator_generation{0};
        uint32_t network_magic{0};
        Hash256 genesis_hash{};
        Hash256 profile_digest{};
        std::chrono::steady_clock::time_point deadline{};

        explicit operator bool() const noexcept {
            return static_cast<bool>(owner) &&
                   static_cast<bool>(claim_for_canonical_commit) &&
                   static_cast<bool>(live) &&
                   source != mining::LocalWorkKind::None &&
                   candidate_height > 0 && !HashIsZero(candidate_hash) &&
                   !HashIsZero(parent_hash) && !work_binding.empty() &&
                   validation_generation > 0 && coordinator_generation > 0 &&
                   network_magic != 0 && !HashIsZero(genesis_hash) &&
                   !HashIsZero(profile_digest) &&
                   (source == mining::LocalWorkKind::SubmitBlock
                        ? (!work_authorization.empty() &&
                           !HashIsZero(work_identity))
                        : (work_authorization.empty() &&
                           HashIsZero(work_identity)));
        }
    };
    using CanonicalWorkTransitionFn = std::function<bool(const Block&)>;
    using LocalWorkAdmissionPrepareFn = std::function<
        std::optional<LocalWorkAdmissionTicket>(
            const Block&, const mining::PowAdmissionContext&)>;

    void SetHistoricalBlockLoader(HistoricalBlockLoader loader) {
        std::unique_lock<std::shared_mutex> lock(chain_mutex_);
        historical_block_loader_ = std::move(loader);
        PruneDurableCanonicalBodiesNoLock_();
    }

    void SetDurableBlockBodyWriter(DurableBlockBodyWriter writer) {
        std::unique_lock<std::shared_mutex> lock(chain_mutex_);
        durable_block_body_writer_ = std::move(writer);
    }
    void SetDurableBlockBodyEraser(DurableBlockBodyEraser eraser) {
        std::unique_lock<std::shared_mutex> lock(chain_mutex_);
        durable_block_body_eraser_ = std::move(eraser);
    }
    void SetCanonicalWorkTransitionFn(CanonicalWorkTransitionFn fn) {
        std::unique_lock<std::shared_mutex> lock(chain_mutex_);
        canonical_work_transition_fn_ = std::move(fn);
    }
    void SetLocalWorkAdmissionPrepareFn(LocalWorkAdmissionPrepareFn fn) {
        std::lock_guard<std::mutex> lock(local_work_admission_prepare_mutex_);
        local_work_admission_prepare_fn_ = std::move(fn);
    }
#ifdef VELD_TEST_HOOKS
    // Deterministic process-test barrier at the real local-block linearization
    // boundary: the authoritative admission lease is already claimed and live,
    // while CommitBlock/on_commit/durable publication have not begun. Public
    // release profiles compile-interlock VELD_TEST_HOOKS in constants.h.
    void TestSetLocalWorkPreCommitBarrier(std::function<void()> barrier) {
        std::unique_lock<std::shared_mutex> lock(chain_mutex_);
        test_local_work_pre_commit_barrier_ = std::move(barrier);
    }
#endif

    // Called only after the exact canonical block bytes and height mapping are
    // durable.  A failed/partial DB commit therefore cannot make the sole body
    // copy disappear.  Reorg replacements are inside the resident horizon, so
    // the monotonic high-water is safe even when an older height is rewritten.
    bool MarkCanonicalBlockDurable(uint64_t height, const Hash256& hash) {
        std::unique_lock<std::shared_mutex> lock(chain_mutex_);
        if (height >= chain_.size() || chain_[height].GetHash() != hash)
            return false;
        if ((!durable_canonical_height_ && height != 0) ||
            (durable_canonical_height_ &&
             height > *durable_canonical_height_ + 1))
            return false;
        if (!durable_canonical_height_ ||
            height > *durable_canonical_height_)
            durable_canonical_height_ = height;
        PruneDurableCanonicalBodiesNoLock_();
        return true;
    }

    size_t ResidentCanonicalBodyCount() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        size_t count = 0;
        for (const auto& block : chain_)
            if (!block.transactions.empty()) ++count;
        return count;
    }

    uint64_t ResidentCanonicalBodyBytes() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        uint64_t total = 0;
        for (const auto& block : chain_) {
            if (block.transactions.empty()) continue;
            const size_t n = block.SerializedSize();
            if (n > UINT64_MAX - total) return UINT64_MAX;
            total += static_cast<uint64_t>(n);
        }
        return total;
    }

    size_t SideBranchHeaderCount() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return side_branch_hashes_.size();
    }
    size_t SideBranchPowAdmissionCount() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return side_pow_admission_.size();
    }
    size_t VolatileSideQuarantineCount() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return volatile_side_quarantine_.size();
    }
    bool IsVolatileSideBlock(const Hash256& hash) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return volatile_side_quarantine_.count(HashToHex(hash)) != 0;
    }
    size_t SideBranchReplayPowVerifiedCount() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return reorg_pow_verified_.size();
    }
    size_t SideBranchResidentBodyCount() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        size_t count = 0;
        for (const auto& [hash, block] : block_store_) {
            auto it = block_tree_.find(hash);
            if (it != block_tree_.end() && !it->second.on_main_chain &&
                !block.transactions.empty()) ++count;
        }
        return count;
    }
    uint64_t SideBranchResidentBodyBytes() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        uint64_t total = 0;
        for (const auto& [hash, block] : block_store_) {
            auto it = block_tree_.find(hash);
            if (it == block_tree_.end() || it->second.on_main_chain ||
                block.transactions.empty()) continue;
            const size_t n = block.SerializedSize();
            if (n > UINT64_MAX - total) return UINT64_MAX;
            total += static_cast<uint64_t>(n);
        }
        return total;
    }

    void SetCoinbaseCapGrandfatherHeight(uint64_t h) {
        coinbase_cap_grandfather_height_.store(h, std::memory_order_relaxed);
    }
    uint64_t GetCoinbaseCapGrandfatherHeight() const {
        return coinbase_cap_grandfather_height_.load(std::memory_order_relaxed);
    }

    uint64_t Height() const {
        return atomic_height_.load();
    }

    void SetLocalValidationCeiling(uint64_t height) {
        local_validation_ceiling_.store(height, std::memory_order_release);
    }

    // Optional process-local admission lease. Production consensus does not
    // depend on this callback: it is an operational fail-closed boundary used
    // by disposable public testnets (and potentially other supervised
    // deployments). Install it before starting ingest and do not mutate it
    // while the node is running.
    using RuntimeAdmissionFn = std::function<bool(uint64_t candidate_height)>;
    void SetRuntimeAdmissionFn(RuntimeAdmissionFn fn) {
        runtime_admission_fn_ = std::move(fn);
    }
    bool RuntimeAdmissionPermits(uint64_t candidate_height) const noexcept {
        if (!runtime_admission_fn_) return true;
        try {
            return runtime_admission_fn_(candidate_height);
        } catch (...) {
            return false;
        }
    }

    class SnapshotSharedGuard {
    public:
        explicit SnapshotSharedGuard(std::shared_mutex& m) : lock_(m) {}
        SnapshotSharedGuard(SnapshotSharedGuard&&) = default;
        SnapshotSharedGuard(const SnapshotSharedGuard&) = delete;
        SnapshotSharedGuard& operator=(const SnapshotSharedGuard&) = delete;
    private:
        std::shared_lock<std::shared_mutex> lock_;
    };
    SnapshotSharedGuard AcquireSnapshotShared() const {
        return SnapshotSharedGuard(chain_mutex_);
    }

    class ConsistentDumpGuard {
    public:
        ConsistentDumpGuard(std::mutex& connect, std::shared_mutex& chain)
            : connect_lock_(connect), chain_lock_(chain) {}
        ConsistentDumpGuard(ConsistentDumpGuard&&) = default;
        ConsistentDumpGuard(const ConsistentDumpGuard&) = delete;
        ConsistentDumpGuard& operator=(const ConsistentDumpGuard&) = delete;
    private:
        // Same order as AddBlockDirect: transition sequencer, then chain view.
        std::unique_lock<std::mutex> connect_lock_;
        std::shared_lock<std::shared_mutex> chain_lock_;
    };
    ConsistentDumpGuard AcquireConsistentDumpGuard() const {
        return ConsistentDumpGuard(block_connect_mutex_, chain_mutex_);
    }

    // Quiesce the complete validation -> module apply -> canonical publication
    // transition without retaining chain_mutex_.  Multi-module readers such as
    // getstatedigest then call the normal per-subsystem snapshot methods while
    // holding this outer sequencer, obtaining one coherent pre- or post-block
    // view without recursively acquiring the chain shared mutex.
    class ConsensusTransitionGuard {
    public:
        explicit ConsensusTransitionGuard(std::mutex& connect)
            : connect_lock_(connect) {}
        ConsensusTransitionGuard(ConsensusTransitionGuard&&) = default;
        ConsensusTransitionGuard(const ConsensusTransitionGuard&) = delete;
        ConsensusTransitionGuard& operator=(
            const ConsensusTransitionGuard&) = delete;
    private:
        std::unique_lock<std::mutex> connect_lock_;
    };
    ConsensusTransitionGuard AcquireConsensusTransitionGuard() const {
        return ConsensusTransitionGuard(block_connect_mutex_);
    }

    bool IsEmpty() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return chain_.empty();
    }

    Block Tip() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        if (chain_.empty()) throw std::runtime_error("Chain is empty");
        return chain_.back();
    }

    Block TipCopy() const { return Tip(); }

    bool TryTip(Block& out) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        if (chain_.empty()) return false;
        out = chain_.back();
        return true;
    }
    bool HasTip() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return !chain_.empty();
    }

    bool HasBlockAtHeight(uint64_t height, const std::string& hash_hex) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        // Volatile side candidates have authenticated headers but have not yet
        // crossed the complete branch-state/VBFR boundary.  They are private
        // retry state, not publicly known blocks.
        if (volatile_side_quarantine_.count(hash_hex)) return false;
        auto it = block_tree_.find(hash_hex);
        if (it == block_tree_.end()) return false;
        return it->second.height == height;
    }

    Block GetBlock(uint64_t height) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        if (height >= chain_.size())
            throw std::out_of_range("Block height out of range");
        return LoadCanonicalBlockNoLock_(height);
    }

    Block GetBlockUnlocked(uint64_t height) const {
        if (height >= chain_.size())
            throw std::out_of_range("Block height out of range");
        return LoadCanonicalBlockNoLock_(height);
    }

    std::vector<Block> GetBlockRange(uint64_t from_height, size_t max_count) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        std::vector<Block> result;
        for (uint64_t h = from_height; h < chain_.size() && result.size() < max_count; ++h)
            result.push_back(LoadCanonicalBlockNoLock_(h));
        return result;
    }

    std::optional<Block> GetBlockByHash(const Hash256& hash) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        const std::string hash_hex = HashToHex(hash);
        // Keep deferred/quarantined bodies strictly inside the contextual
        // validation machinery.  P2P GETDATA, RPC and explorer callers all use
        // this public view and must not relay or expose an unvalidated body.
        if (volatile_side_quarantine_.count(hash_hex)) return std::nullopt;
        auto it = block_index_.find(hash_hex);
        if (it != block_index_.end()) {
            if (it->second >= chain_.size()) return std::nullopt;
            return LoadCanonicalBlockNoLock_(it->second);
        }
        auto tree_it = block_tree_.find(hash_hex);
        if (tree_it == block_tree_.end() || tree_it->second.on_main_chain)
            return std::nullopt;
        try {
            return LoadIndexedBlockNoLock_(hash_hex);
        } catch (...) {
            return std::nullopt;
        }
    }

    bool IsCanonicalBlock(const Hash256& hash) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        const std::string hash_hex = HashToHex(hash);
        auto it = block_tree_.find(hash_hex);
        return !volatile_side_quarantine_.count(hash_hex) &&
               it != block_tree_.end() && it->second.on_main_chain;
    }

    // Header/index-only membership for P2P inventory/locator handling.  These
    // callers need only existence/height; loading an entire disk-backed block
    // body for each of up to 1,000 advertised hashes is a remote I/O and memory
    // amplification vector.
    std::optional<uint64_t> GetKnownBlockHeightByHash(
            const Hash256& hash) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        const std::string hash_hex = HashToHex(hash);
        if (volatile_side_quarantine_.count(hash_hex)) return std::nullopt;
        auto main_it = block_index_.find(hash_hex);
        if (main_it != block_index_.end())
            return static_cast<uint64_t>(main_it->second);
        auto tree_it = block_tree_.find(hash_hex);
        if (tree_it == block_tree_.end()) return std::nullopt;
        return tree_it->second.height;
    }

#ifdef VELD_TEST_HOOKS
    // Test-only proof that index membership queries do not materialize block
    // bodies.  Count entry into either body-loading path (resident or durable)
    // so P2P regressions can distinguish a hash-index lookup from an accidental
    // GetBlock/GetBlockByHash call without changing production behavior.
    void TestResetBlockBodyLookupCount() const {
        test_block_body_lookup_count_.store(0, std::memory_order_release);
    }
    uint64_t TestBlockBodyLookupCount() const {
        return test_block_body_lookup_count_.load(std::memory_order_acquire);
    }
#endif

    uint64_t TotalSupplyUnits() const { return total_supply_units_; }

    // Mining tiers only inspect the last 1,095 BLOCKS_PER_DAY windows. Keep
    // older per-block observations and fully inactive identities out of the
    // hot consensus index. Lifetime totals and the display-only last-mined
    // height are deliberately NOT consensus state: the node supplies both
    // from one rebuildable disk-backed archive. A focused test build may
    // shorten the horizon; public binaries always use the protocol horizon.
#ifdef VELD_TEST_MINER_HISTORY_BLOCKS
    static constexpr uint64_t MAX_MINER_TIER_HISTORY_BLOCKS =
        VELD_TEST_MINER_HISTORY_BLOCKS;
#else
    static constexpr uint64_t MAX_MINER_TIER_HISTORY_BLOCKS =
        1'095ull * BLOCKS_PER_DAY;
#endif
    static_assert(MAX_MINER_TIER_HISTORY_BLOCKS > 0,
                  "miner tier history horizon must be non-zero");

    uint64_t GetActiveWindowCount(const std::string& script_hex,
                                   uint64_t total_windows,
                                   uint64_t current_height) const {
        static constexpr uint64_t WINDOW_BLOCKS = BLOCKS_PER_DAY;   // 1 "active" day (must match tiers.h)
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        auto it = miner_heights_.find(script_hex);
        if (it == miner_heights_.end()) return 0;
        const auto& heights = it->second;
        if (heights.empty()) return 0;

        uint64_t active = 0;
        for (uint64_t w = 0; w < total_windows; ++w) {
            if ((w + 1) * WINDOW_BLOCKS > current_height) break;
            uint64_t window_end   = (w == 0) ? current_height
                                              : current_height - w * WINDOW_BLOCKS;
            uint64_t window_start = current_height - (w + 1) * WINDOW_BLOCKS + 1;
            if (window_end < window_start) break;
            auto lo = std::lower_bound(heights.begin(), heights.end(), window_start);
            if (lo != heights.end() && *lo <= window_end) active++;
        }
        return active;
    }

    struct MinerArchiveRecord {
        uint64_t blocks_mined{0};
        uint64_t last_block_mined{0};
    };
    using MinerArchiveLookup = std::function<std::optional<MinerArchiveRecord>(
        const std::string& script_hex)>;

    void SetMinerArchiveLookup(MinerArchiveLookup lookup) {
        std::unique_lock<std::shared_mutex> lock(chain_mutex_);
        miner_archive_lookup_ = std::move(lookup);
    }

    std::optional<MinerArchiveRecord> GetMinerArchiveRecord(
            const std::string& script_hex) const {
        // Copy under the chain lock, then invoke after releasing it. The node's
        // archive lookup may touch LevelDB and must never be called while a
        // consensus lock is held. Archive failure remains distinguishable from
        // a real zero-row result; tier decisions use GetActiveWindowCount
        // exclusively and therefore never consult this optional display state.
        MinerArchiveLookup lookup;
        {
            std::shared_lock<std::shared_mutex> lock(chain_mutex_);
            lookup = miner_archive_lookup_;
        }
        if (!lookup) return std::nullopt;
        try { return lookup(script_hex); }
        catch (...) { return std::nullopt; }
    }

    uint64_t GetBlocksMined(const std::string& script_hex) const {
        const auto record = GetMinerArchiveRecord(script_hex);
        return record ? record->blocks_mined : 0;
    }

    uint64_t GetLastBlockMined(const std::string& script_hex) const {
        const auto record = GetMinerArchiveRecord(script_hex);
        return record ? record->last_block_mined : 0;
    }

    // Shared extractor for the rebuildable archival index. Keeping this as a
    // thin public mirror of the canonical hot-index extractor prevents the
    // node from crediting protocol custody outputs as miners.
    static std::vector<std::string>
    MinerScriptsForArchive(const Block& block) {
        return MinerScriptsForBlock_(block);
    }

    double TotalSupplyVeld() const {
        return (double)total_supply_units_ / VELD_UNITS;
    }

    void SetStakingActivationUnits(uint64_t units) {
        staking_activation_units_.store(units, std::memory_order_relaxed);
    }
    uint64_t GetStakingActivationUnits() const {
        return staking_activation_units_.load(std::memory_order_relaxed);
    }

    bool IsStakingActive() const {
        return total_supply_units_.load(std::memory_order_relaxed) >=
               staking_activation_units_.load(std::memory_order_relaxed);
    }

    uint32_t ComputeNextBits() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        if (chain_.empty()) return GENESIS_BITS;
        return ComputeNextBitsAtLocked(chain_.size() - 1);
    }

    uint32_t ComputeNextBitsAt(uint64_t after_height) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        if (chain_.empty()) return GENESIS_BITS;
        if (after_height >= chain_.size()) return GENESIS_BITS;
        return ComputeNextBitsAtLocked(after_height);
    }

    uint32_t ComputeNextBitsAtTip() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        if (chain_.empty()) return GENESIS_BITS;
        return ComputeNextBitsAtLocked(chain_.size() - 1);
    }

    std::optional<uint64_t> GetHeightByHash(const Hash256& h) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return GetHeightByHashLocked(h);
    }

    std::optional<uint64_t> GetHeightByHashLocked(const Hash256& h) const {
        auto it = block_index_.find(HashToHex(h));
        if (it == block_index_.end()) return std::nullopt;
        if (it->second >= chain_.size()) return std::nullopt;
        return it->second;
    }

    uint64_t GetBlockTimestampAtLocked(uint64_t height) const {
        if (height >= chain_.size()) return 0;
        return chain_[height].header.timestamp;
    }
    uint64_t HeightLocked() const {
        return chain_.empty() ? 0 : (uint64_t)(chain_.size() - 1);
    }

    // Pure consensus arithmetic used by ComputeNextBitsAtLocked and the
    // deterministic difficulty-liveness sentinel.  Keeping wall-clock and
    // block-construction concerns outside this helper lets tests cover severe
    // solve-time distributions without weakening timestamp validation.
    static uint32_t ComputeRetargetBitsForSolveTimes(
            uint32_t current_bits,
            const std::vector<int64_t>& solve_times,
            bool is_early_ramp,
            bool batch2_hardened) {
#ifdef VELD_MAINNET_POW
        constexpr size_t MAX_N = DIFFICULTY_ADJUSTMENT_INTERVAL;
#else
        constexpr size_t MAX_N = 20;
#endif
        if (solve_times.empty() || solve_times.size() > MAX_N) {
            return current_bits;
        }

        constexpr uint64_t T = TARGET_BLOCK_TIME;
        const uint64_t effective_N = solve_times.size();
        const uint64_t K = effective_N * (effective_N + 1) * T / 2;

        int64_t weighted_st = 0;
        uint64_t weight = 0;
        for (int64_t st : solve_times) {
            ++weight;
            int64_t st_lo, st_hi;
#ifdef VELD_MAINNET_POW
            if (is_early_ramp) {
                // The launch ramp is explicitly a 4x-per-window regime.  The
                // generic batch-2 0.5T..2T solve clamp used to narrow it back
                // to 2x, contradicting the compiled EARLY_CLAMP_DIVISOR and
                // making the documented four-order launch convergence
                // impossible in ten windows.  Bound each sample to the same
                // 4x envelope as the aggregate early-ramp clamp.
                st_lo = (int64_t)T / (int64_t)EARLY_CLAMP_DIVISOR;
                st_hi = (int64_t)T * (int64_t)EARLY_CLAMP_DIVISOR;
            } else
#endif
            if (batch2_hardened) {
                st_lo = (int64_t)T / 2;
                st_hi = 2 * (int64_t)T;
            } else {
                st_lo = (int64_t)T / 4;
                st_hi = 6 * (int64_t)T;
            }
            if (st < st_lo) st = st_lo;
            if (st > st_hi) st = st_hi;
            weighted_st += st * (int64_t)weight;
        }
#ifdef VELD_MAINNET_POW
        if (is_early_ramp) {
            const int64_t lo = (int64_t)(K / EARLY_CLAMP_DIVISOR);
            const int64_t hi = (int64_t)(K * EARLY_CLAMP_DIVISOR);
            if (weighted_st < lo) weighted_st = lo;
            if (weighted_st > hi) weighted_st = hi;
        } else
#else
        (void)is_early_ramp;
#endif
        {
            if (weighted_st < (int64_t)(K / 2)) weighted_st = (int64_t)(K / 2);
            if (weighted_st > (int64_t)(K * 3 / 2)) weighted_st = (int64_t)(K * 3 / 2);
        }

        uint32_t exponent = (current_bits >> 24) & 0xFF;
        uint32_t mantissa = current_bits & 0x007FFFFF;
        if (exponent < 3 || exponent > 32 || mantissa == 0) return current_bits;

        uint64_t new_mantissa = ((uint64_t)mantissa * (uint64_t)weighted_st) / K;

        while (new_mantissa > 0x7FFFFF) {
            new_mantissa >>= 8;
            exponent++;
            if (exponent > 32) { new_mantissa = 0x7FFFFF; exponent = 32; break; }
        }
        while (new_mantissa < 0x008000 && exponent > 3) {
            new_mantissa <<= 8;
            exponent--;
        }

        if (new_mantissa == 0) new_mantissa = 1;
        new_mantissa &= 0x7FFFFF;
        return (exponent << 24) | (uint32_t)new_mantissa;
    }

    static uint64_t DifficultyRetargetIntervalForNextHeight(
            uint64_t next_height) {
#ifdef VELD_MAINNET_POW
        return next_height <= EARLY_RAMP_END_HEIGHT
             ? EARLY_RETARGET_INTERVAL
             : DIFFICULTY_ADJUSTMENT_INTERVAL;
#else
        (void)next_height;
        return 20;
#endif
    }

    static bool IsDifficultyRetargetBoundary(uint64_t next_height) {
        const uint64_t interval =
            DifficultyRetargetIntervalForNextHeight(next_height);
        return next_height != 0 && interval != 0 &&
               next_height % interval == 0;
    }

    template <typename HeaderAt>
    static bool TryComputeNextBitsForParent_(
            uint64_t parent_height, HeaderAt&& header_at,
            uint32_t& out_bits) {
#ifdef VELD_REGTEST_FIXED_DIFF
        CanonicalPowTarget fixed;
        if (!DecodeCanonicalVeldTarget(VELD_POW_LIMIT_BITS, fixed)) return false;
        out_bits = fixed.bits;
        return true;
#else
#ifdef VELD_MAINNET_POW
        const bool is_early_ramp =
            (parent_height + 1) <= EARLY_RAMP_END_HEIGHT;
        const uint64_t retarget_interval =
            DifficultyRetargetIntervalForNextHeight(parent_height + 1);
        const uint64_t n_max = is_early_ramp
            ? EARLY_LWMA_WINDOW : DIFFICULTY_ADJUSTMENT_INTERVAL;
#else
        constexpr bool is_early_ramp = false;
        constexpr uint64_t retarget_interval = 20;
        constexpr uint64_t n_max = 20;
#endif
        const BlockHeader* genesis = header_at(0);
        const BlockHeader* parent = header_at(parent_height);
        if (!genesis || !parent) return false;
        uint32_t raw_bits = genesis->bits;
        if (parent_height == 0) {
            raw_bits = genesis->bits;
        } else {
            const uint64_t next_height = parent_height + 1;
            if (!IsDifficultyRetargetBoundary(next_height)) {
                raw_bits = parent->bits;
            } else {
                const uint64_t window_start_boundary =
                    (next_height / retarget_interval) * retarget_interval;
                if (window_start_boundary == 0 ||
                    window_start_boundary < BOOTSTRAP_BLOCKS) {
                    raw_bits = genesis->bits;
                } else {
                    const uint64_t window_end = window_start_boundary - 1;
                    const BlockHeader* end_header = header_at(window_end);
                    if (!end_header || window_end < BOOTSTRAP_BLOCKS)
                        return false;
                    uint64_t solve_start = BOOTSTRAP_BLOCKS + 1;
                    if (window_end < solve_start) {
                        raw_bits = genesis->bits;
                    } else {
                        uint64_t n = window_end - solve_start + 1;
                        if (n > n_max) {
                            n = n_max;
                            solve_start = window_end - n + 1;
                        }
                        if (n == 0 || !header_at(solve_start - 1))
                            return false;
                        std::vector<int64_t> solve_times;
                        solve_times.reserve(static_cast<size_t>(n));
                        for (uint64_t h = solve_start; h <= window_end; ++h) {
                            const BlockHeader* current = header_at(h);
                            const BlockHeader* previous = header_at(h - 1);
                            if (!current || !previous) return false;
                            solve_times.push_back(
                                static_cast<int64_t>(current->timestamp) -
                                static_cast<int64_t>(previous->timestamp));
                        }
                        raw_bits = ComputeRetargetBitsForSolveTimes(
                            end_header->bits, solve_times, is_early_ramp,
                            window_end >= BATCH2_HARDENING_HEIGHT);
                    }
                }
            }
        }
        bool negative = false, overflow = false;
        const auto target = btcspv::CompactToTarget(
            raw_bits, &negative, &overflow);
        if (negative || overflow || target.IsZero() ||
            target > VeldPowLimit()) return false;
        const uint32_t canonical = btcspv::TargetToCompact(target);
        CanonicalPowTarget decoded;
        if (!DecodeCanonicalVeldTarget(canonical, decoded)) return false;
        out_bits = canonical;
        return true;
#endif
    }

    struct BranchHeaderWindow {
        uint64_t first_height{0};
        std::vector<BlockHeader> headers;
        const BlockHeader* At(uint64_t height) const noexcept {
            if (height < first_height) return nullptr;
            const uint64_t offset = height - first_height;
            if (offset >= headers.size()) return nullptr;
            return &headers[static_cast<size_t>(offset)];
        }
    };

    struct PowParentContext {
        uint64_t parent_height{0};
        uint64_t candidate_height{0};
        uint64_t median_time_past{0};
        uint32_t expected_bits{0};
        CanonicalPowTarget expected_target{};
    };

    bool BuildBranchHeaderWindowNoLock_(
            const Hash256& parent_hash, BranchHeaderWindow& out) const {
        out = BranchHeaderWindow{};
        const std::string parent_hex = HashToHex(parent_hash);
        auto parent_it = block_tree_.find(parent_hex);
        if (parent_it == block_tree_.end()) return false;
        const uint64_t parent_height = parent_it->second.height;
        const uint64_t first = parent_height > 144 ? parent_height - 144 : 0;
        std::vector<BlockHeader> reverse;
        reverse.reserve(static_cast<size_t>(parent_height - first + 1));
        std::string cursor = parent_hex;
        for (uint64_t expected_height = parent_height;; --expected_height) {
            auto tree = block_tree_.find(cursor);
            if (tree == block_tree_.end() ||
                tree->second.height != expected_height) return false;
            BlockHeader header;
            if (expected_height < chain_.size() &&
                HashToHex(chain_[expected_height].GetHash()) == cursor) {
                header = chain_[expected_height].header;
            } else {
                auto stored = block_store_.find(cursor);
                if (stored == block_store_.end() ||
                    HashToHex(stored->second.GetHash()) != cursor ||
                    stored->second.height != expected_height) return false;
                header = stored->second.header;
            }
            if (header.prev_block_hash != tree->second.prev_hash)
                return false;
            reverse.push_back(header);
            if (expected_height == first) break;
            const std::string next = HashToHex(tree->second.prev_hash);
            auto predecessor = block_tree_.find(next);
            if (predecessor == block_tree_.end() ||
                predecessor->second.height + 1 != expected_height)
                return false;
            cursor = next;
        }
        std::reverse(reverse.begin(), reverse.end());
        out.first_height = first;
        out.headers = std::move(reverse);
        return true;
    }

    bool BuildPowParentContextNoLock_(
            const Hash256& parent_hash, PowParentContext& out) const {
        BranchHeaderWindow window;
        if (!BuildBranchHeaderWindowNoLock_(parent_hash, window) ||
            window.headers.empty()) return false;
        out = PowParentContext{};
        out.parent_height =
            window.first_height + window.headers.size() - 1;
        if (out.parent_height == UINT64_MAX) return false;
        out.candidate_height = out.parent_height + 1;
        auto at = [&](uint64_t height) -> const BlockHeader* {
            if (const auto* local = window.At(height)) return local;
            if (height < chain_.size()) return &chain_[height].header;
            return nullptr;
        };
        if (!TryComputeNextBitsForParent_(
                out.parent_height, at, out.expected_bits) ||
            !DecodeCanonicalVeldTarget(
                out.expected_bits, out.expected_target)) return false;
        std::vector<uint64_t> times;
        for (uint64_t h = out.parent_height + 1; h-- > 0 && times.size() < 11;) {
            const BlockHeader* header = at(h);
            if (!header) return false;
            times.push_back(header->timestamp);
            if (h == 0) break;
        }
        std::sort(times.begin(), times.end());
        out.median_time_past = times[times.size() / 2];
        return true;
    }

    uint32_t ComputeNextBitsAtLocked(uint64_t height) const {
        uint32_t canonical = GENESIS_BITS;
        auto at = [&](uint64_t h) -> const BlockHeader* {
            return h < chain_.size() ? &chain_[h].header : nullptr;
        };
        if (TryComputeNextBitsForParent_(height, at, canonical))
            return canonical;
        return GENESIS_BITS;
#if 0
#ifdef VELD_REGTEST_FIXED_DIFF
        // Test-only fixed difficulty. Pin difficulty to the genesis bits so a
        // single-node regtest NEVER retargets — blocks stay instant, letting a test mine
        // past COINBASE_MATURITY in seconds to exercise the funded-op posting path
        // (preparerawop). No production build sets this flag, so consensus is unchanged.
        // Return the regtest pow-limit that MineBlocks/generate stamps into every block, so
        // the chain is self-consistent (bits == expected at every height >= 1); the genesis
        // block keeps its own GENESIS_BITS and is never checked against this.
        return 0x207fffffu;
#endif
#ifdef VELD_MAINNET_POW
        const bool is_early_ramp = (height + 1) <= EARLY_RAMP_END_HEIGHT;
        const uint64_t RETARGET_INTERVAL =
            DifficultyRetargetIntervalForNextHeight(height + 1);
        const uint64_t N_MAX             = is_early_ramp
                                         ? EARLY_LWMA_WINDOW
                                         : DIFFICULTY_ADJUSTMENT_INTERVAL;
#else
        constexpr uint64_t RETARGET_INTERVAL = 20;
        constexpr uint64_t N_MAX             = 20;
        constexpr bool is_early_ramp = false;
#endif
        if (height == 0) return chain_[0].header.bits;

        uint64_t next_height           = height + 1;
        // Difficulty is fixed between explicit boundaries.  Recomputing a
        // fixed window happened to be equivalent inside one regime, but was
        // unsafe at the early-ramp -> standard transition: h=391 selected the
        // standard epoch whose window ended at h=287 and could abruptly undo
        // several later early-ramp adjustments.  Inherit through h=431 and
        // perform the first standard adjustment at the real h=432 boundary.
        if (!IsDifficultyRetargetBoundary(next_height)) {
            return chain_[height].header.bits;
        }
        uint64_t retarget_window_start = (next_height / RETARGET_INTERVAL) * RETARGET_INTERVAL;

        if (retarget_window_start == 0) return chain_[0].header.bits;

        if (retarget_window_start < BOOTSTRAP_BLOCKS) return chain_[0].header.bits;

        uint64_t lwma_window_end = retarget_window_start - 1;
        if (lwma_window_end >= chain_.size()) {
            return chain_[0].header.bits;
        }
        height = lwma_window_end;

        if (height < BOOTSTRAP_BLOCKS) return chain_[0].header.bits;

        uint64_t window_start = BOOTSTRAP_BLOCKS + 1;
        if (height < window_start) return chain_[0].header.bits;
        uint64_t N = height - window_start + 1;
        if (N > N_MAX) {
            N = N_MAX;
            window_start = height - N + 1;
        }
        if (N == 0) return chain_[0].header.bits;

        // Every observed solve interval contributes to the retarget. Timestamp outliers
        // remain bounded safely by the per-interval st_lo/st_hi clamps below
        // and the aggregate early/standard clamp after weighting; omission is
        // both unnecessary and a consensus-liveness hazard.
        std::vector<int64_t> solve_times;
        solve_times.reserve((size_t)N);
        for (uint64_t i = window_start; i <= height; ++i) {
            solve_times.push_back(
                (int64_t)chain_[i].header.timestamp -
                (int64_t)chain_[i - 1].header.timestamp);
        }
        return ComputeRetargetBitsForSolveTimes(
            chain_[height].header.bits, solve_times, is_early_ramp,
            height >= BATCH2_HARDENING_HEIGHT);
#endif
    }

public:
    struct NmsTally {
        std::map<std::string, uint64_t> nms_credits;

        std::unordered_map<std::string, uint64_t> seen_payloads;

        std::map<std::string, uint64_t> pre_flush_snapshot;
        uint64_t pre_flush_snapshot_height{0};

        void Clear() {
            nms_credits.clear();
            seen_payloads.clear();
            pre_flush_snapshot.clear();
            pre_flush_snapshot_height = 0;
        }
    };

    uint64_t NmsGetCredit(const std::string& script_hex) const {
        std::shared_lock<std::shared_mutex> lock(nms_tally_mutex_);
        auto it = nms_tally_.nms_credits.find(script_hex);
        return it == nms_tally_.nms_credits.end() ? 0ull : it->second;
    }

    std::vector<std::pair<std::string, uint64_t>> NmsSnapshot() const {
        std::shared_lock<std::shared_mutex> lock(nms_tally_mutex_);
        std::vector<std::pair<std::string, uint64_t>> out;
        out.reserve(nms_tally_.nms_credits.size());
        for (const auto& [k, v] : nms_tally_.nms_credits) {
            out.emplace_back(k, v);
        }
        return out;
    }

    // ── Canonical state digests ──────────
    // Read-only. Serializes `utxo_set_` in canonical binary-outpoint order.
    // D_utxo v2 commits every decision-relevant UTXO field. V1 omitted
    // block_height and is_coinbase because correct replay derives them from
    // history; that nevertheless allowed an implementation/state-corruption
    // divergence to report green while coinbase maturity or relative-locktime
    // validation made a different future spend decision.
    Hash256 UtxoDigest() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        namespace sd = ::veld::state_digest;
        // Collect (txid bytes, output_index, value, script) tuples and
        // canonical-sort. The string key stored in utxo_set_ is hex+":"+
        // decimal which is NOT byte-canonical (decimal lex-orders "10" <
        // "9"), so we cannot sort by the string key directly — must use
        // the binary (tx_hash, output_index).
        struct Row {
            Hash256 tx_hash;
            uint32_t output_index;
            uint64_t value;
            const std::vector<uint8_t>* script;
            uint64_t block_height;
            bool is_coinbase;
        };
        std::vector<Row> rows;
        rows.reserve(utxo_set_.size());
        for (const auto& [_k, u] : utxo_set_) {
            rows.push_back({u.tx_hash, u.output_index, u.value,
                            &u.script_pubkey, u.block_height, u.is_coinbase});
        }
        std::sort(rows.begin(), rows.end(),
                  [](const Row& a, const Row& b){
                      int c = std::memcmp(a.tx_hash.data(), b.tx_hash.data(), 32);
                      if (c != 0) return c < 0;
                      return a.output_index < b.output_index;
                  });
        std::vector<uint8_t> body;
        sd::put_u32_le(body, 2);  // encoding version
        sd::put_u32_le(body, (uint32_t)rows.size());
        for (const auto& r : rows) {
            sd::put_bytes(body, r.tx_hash.data(), 32);
            sd::put_u32_le(body, r.output_index);
            sd::put_u64_le(body, r.value);
            sd::put_len_prefixed(body, *r.script);
            sd::put_u64_le(body, r.block_height);
            sd::put_u8(body, r.is_coinbase ? 1 : 0);
        }
        return sd::sha256_domain(sd::tags::UTXO, body);
    }

    Hash256 NmsTallyDigest() const {
        std::shared_lock<std::shared_mutex> lock(nms_tally_mutex_);
        namespace sd = ::veld::state_digest;
        std::vector<uint8_t> body;
        sd::put_u32_le(body, (uint32_t)nms_tally_.nms_credits.size());
        for (const auto& [k, v] : nms_tally_.nms_credits) {
            sd::put_len_prefixed(body, k);
            sd::put_u64_le(body, v);
        }
        return sd::sha256_domain(sd::tags::NMSTALLY, body);
    }

    Hash256 SupplyDigest() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        namespace sd = ::veld::state_digest;
        std::vector<uint8_t> body;
        // Encoding v4 covers the complete chain-accounting frame used by
        // future consensus decisions. V1 committed total supply alone and
        // could therefore report green for nodes with different staking
        // activation, tier-window indexes, or fee accounting. V4 deliberately
        // removes rebuildable lifetime miner statistics from consensus state.
        sd::put_u32_le(body, 4);
        sd::put_u64_le(body,
            total_supply_units_.load(std::memory_order_relaxed));
        sd::put_u64_le(body,
            total_fees_collected_units_.load(std::memory_order_relaxed));
        sd::put_u64_le(body,
            staking_activation_units_.load(std::memory_order_relaxed));
        sd::put_u64_le(body,
            coinbase_cap_grandfather_height_.load(std::memory_order_relaxed));

        std::vector<std::string> height_keys;
        height_keys.reserve(miner_heights_.size());
        for (const auto& [key, _value] : miner_heights_)
            height_keys.push_back(key);
        std::sort(height_keys.begin(), height_keys.end());
        sd::put_u32_le(body, (uint32_t)height_keys.size());
        for (const auto& key : height_keys) {
            const auto& heights = miner_heights_.at(key);
            sd::put_len_prefixed(body, key);
            sd::put_u32_le(body, (uint32_t)heights.size());
            // Preserve the decision-bearing order: GetActiveWindowCount uses
            // lower_bound. Display-only last-mined height is archival and absent.
            for (uint64_t height : heights)
                sd::put_u64_le(body, height);
        }
        return sd::sha256_domain(sd::tags::SUPPLY, body);
    }

    Hash256 NmsExtendedDigest() const {
        std::shared_lock<std::shared_mutex> lock(nms_tally_mutex_);
        namespace sd = ::veld::state_digest;
        std::vector<uint8_t> body;
        sd::put_u32_le(body, (uint32_t)nms_tally_.nms_credits.size());
        for (const auto& [k, v] : nms_tally_.nms_credits) {
            sd::put_len_prefixed(body, k);
            sd::put_u64_le(body, v);
        }
        std::vector<std::pair<std::string, uint64_t>> sp_sorted;
        sp_sorted.reserve(nms_tally_.seen_payloads.size());
        for (const auto& [k, v] : nms_tally_.seen_payloads) {
            sp_sorted.emplace_back(k, v);
        }
        std::sort(sp_sorted.begin(), sp_sorted.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        sd::put_u32_le(body, (uint32_t)sp_sorted.size());
        for (const auto& [k, v] : sp_sorted) {
            sd::put_len_prefixed(body, k);
            sd::put_u64_le(body, v);
        }
        sd::put_u32_le(body, (uint32_t)nms_tally_.pre_flush_snapshot.size());
        for (const auto& [k, v] : nms_tally_.pre_flush_snapshot) {
            sd::put_len_prefixed(body, k);
            sd::put_u64_le(body, v);
        }
        sd::put_u64_le(body, nms_tally_.pre_flush_snapshot_height);
        return sd::sha256_domain(sd::tags::NMS_EXTENDED, body);
    }

    void NmsCreditScript(const std::string& script_hex) {
        if (script_hex.empty()) return;
        std::unique_lock<std::shared_mutex> lock(nms_tally_mutex_);
        nms_tally_.nms_credits[script_hex] += 1ull;
    }

    void NmsDebitScript(const std::string& script_hex) {
        if (script_hex.empty()) return;
        std::unique_lock<std::shared_mutex> lock(nms_tally_mutex_);
        auto it = nms_tally_.nms_credits.find(script_hex);
        if (it == nms_tally_.nms_credits.end()) return;
        if (it->second <= 1ull) nms_tally_.nms_credits.erase(it);
        else                    it->second -= 1ull;
    }

    void NmsClearOnFlush(uint64_t new_flush_height) {
        std::unique_lock<std::shared_mutex> lock(nms_tally_mutex_);
        nms_tally_.pre_flush_snapshot         = nms_tally_.nms_credits;
        nms_tally_.pre_flush_snapshot_height  = new_flush_height;
        nms_tally_.nms_credits.clear();
    }

    void NmsRestoreFromFlushSnapshot(uint64_t expected_flush_height) {
        std::unique_lock<std::shared_mutex> lock(nms_tally_mutex_);
        if (nms_tally_.pre_flush_snapshot_height == expected_flush_height) {
            nms_tally_.nms_credits = nms_tally_.pre_flush_snapshot;
        }
        nms_tally_.pre_flush_snapshot.clear();
        nms_tally_.pre_flush_snapshot_height = 0;
    }

    void NmsReset() {
        std::unique_lock<std::shared_mutex> lock(nms_tally_mutex_);
        nms_tally_.Clear();
    }

    NmsValidationDisposition ValidateNmsLocking(
                            const veld::NmsRecord& rec,
                            uint64_t enclosing_block_height,
                            mining::ExpensivePowBudget* source_pow_budget =
                                nullptr) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return veld::ValidateNmsWithDisposition<Blockchain>(
            rec, *this, enclosing_block_height, source_pow_budget);
    }

    using NmsStakeQueryFn = std::function<uint64_t(const std::string& address)>;
    void SetNmsStakeQuery(NmsStakeQueryFn fn) { nms_stake_query_ = std::move(fn); }

    uint64_t NmsQueryStakeUnits(const std::string& address) const {
        if (!nms_stake_query_) return 0;
        try { return nms_stake_query_(address); }
        catch (...) { return 0; }
    }

    bool NmsBondSatisfied(const std::vector<uint8_t>& miner_script) const {
        if (!nms_stake_query_) return true;
        std::string addr = ScriptToAddress(miner_script);
        if (addr.empty()) return false;
        return nms_stake_query_(addr) >= NMS_MIN_BOND_UNITS;
    }

    // ───────────────────────────────────────────────────────────────
    //  VALIDATOR REGISTRY / ACCEPTED-ENDORSEMENT FILTERS
    //
    //  ComputeExpectedEndorsementFlushOutputs scans block windows for
    //  VELD_VALIDATOR|ENDORSE OP_RETURN markers and credits each emitter
    //  for a pro-rata slice of the endorsement pool. Without a registry
    //  check, ANY address that emits the marker earns a payout — bypassing
    //  the MIN_VALIDATOR_STAKE bond and the REGISTER OP_RETURN flow.
    //
    //  Node registers this callback at startup:
    //
    //      chain_.SetValidatorFilter([this](const std::string& addr)
    //          -> bool {
    //          return validators_.IsValidatorByAddress(addr);
    //      });
    //
    //  When null (test / standalone), filter no-ops to preserve legacy
    //  behavior for unit tests. Production binaries always wire it.
    //  ValidatorRegistry is deterministically rebuilt from chain state
    //  on every node, so this filter is consensus-deterministic.
    // ───────────────────────────────────────────────────────────────
    using ValidatorFilterFn = std::function<bool(const std::string& address)>;
    void SetValidatorFilter(ValidatorFilterFn fn) { validator_filter_ = std::move(fn); }

    // A raw marker is payout-ineligible unless ValidatorRegistry accepted a
    // valid endorsement signature for this exact (address,height,hash) while
    // replaying its inclusion block.  The callback is overlay-aware in Node, so
    // main connect, cold replay, and candidate-branch validation all query the
    // matching registry frame.  A missing callback fails closed (no marker can
    // earn a validator payout).
    using AcceptedEndorsementFn = std::function<bool(
        const std::string& address, uint64_t height,
        const std::string& block_hash_hex, const std::string& sig_hex)>;
    void SetAcceptedEndorsementQuery(AcceptedEndorsementFn fn) {
        accepted_endorsement_fn_ = std::move(fn);
    }

    using StakeSnapshotFn = std::function<std::map<std::string, uint64_t>(uint64_t query_height)>;
    void SetStakeSnapshot(StakeSnapshotFn fn) { stake_snapshot_at_height_ = std::move(fn); }

    using BondSettlementsFn = std::function<
        std::vector<std::tuple<std::string,int,uint64_t,std::string>>(uint64_t boundary_height)>;
    void SetBondSettlementsFn(BondSettlementsFn fn) { bond_settlements_fn_ = std::move(fn); }

    using BondYieldWeightFn = std::function<uint64_t(uint64_t boundary_height)>;
    void SetBondYieldWeightFn(BondYieldWeightFn fn) { bond_yield_weight_fn_ = std::move(fn); }
    using BondYieldSettlementsFn = std::function<
        std::vector<std::tuple<std::string,int,uint64_t,std::string>>(uint64_t boundary_height)>;
    void SetBondYieldSettlementsFn(BondYieldSettlementsFn fn) { bond_yield_settlements_fn_ = std::move(fn); }

    using AltOverlayBuildFn    = std::function<void(uint64_t ancestor_height)>;
    using AltOverlayAdvanceFn  = std::function<void(const Block& block)>;
    using AltOverlayTeardownFn = std::function<void()>;
    void SetAltOverlayBuildFn(AltOverlayBuildFn fn)       { alt_overlay_build_fn_ = std::move(fn); }
    void SetAltOverlayAdvanceFn(AltOverlayAdvanceFn fn)   { alt_overlay_advance_fn_ = std::move(fn); }
    void SetAltOverlayTeardownFn(AltOverlayTeardownFn fn) { alt_overlay_teardown_fn_ = std::move(fn); }

    using CheckpointAtOrBelowFn = std::function<bool(
        uint64_t max_height, uint64_t& out_height, Hash256& out_hash)>;
    void SetCheckpointAtOrBelow(CheckpointAtOrBelowFn fn) {
        checkpoint_at_or_below_ = std::move(fn);
    }

    void UpdateNmsTallyAfterCommit_(const Block& block) {
        if constexpr (!OPTION_B_CONSENSUS_GATE_ENABLED) return;

        for (const auto& tx : block.transactions) {
            if (tx.IsCoinbase()) continue;
            auto nms_rec = ExtractNmsFromTx(tx);
            if (!nms_rec) continue;
            auto miner_script = ExtractNmsMinerScript(tx);
            if (miner_script.empty()) continue;
            Hash256 h = Hash256d(nms_rec->raw);
            std::string payload_hex = HashToHex(h);
            {
                std::unique_lock<std::shared_mutex> lock(nms_tally_mutex_);
                nms_tally_.seen_payloads[payload_hex] = block.height;
            }
            NmsCreditScript(BytesToHex(miner_script));
        }
        if (block.height > 0 && (block.height % COMINE_WINDOW_BLOCKS) == 0) {
            NmsClearOnFlush(block.height);
            std::unique_lock<std::shared_mutex> lock(nms_tally_mutex_);
            uint64_t cutoff = block.height > NMS_WINDOW_DEDUP_BLOCKS
                ? block.height - NMS_WINDOW_DEDUP_BLOCKS : 0;
            for (auto it = nms_tally_.seen_payloads.begin();
                 it != nms_tally_.seen_payloads.end(); ) {
                if (it->second <= cutoff) it = nms_tally_.seen_payloads.erase(it);
                else ++it;
            }
        }
        if ((block.height % COMINE_WINDOW_BLOCKS) == 0) {
            std::shared_lock<std::shared_mutex> lock(nms_tally_mutex_);
            nms_checkpoints_.push_back(
                NmsCheckpoint{block.height, block.GetHash(), nms_tally_});
            while (nms_checkpoints_.size() > 4)
                nms_checkpoints_.pop_front();
        }
    }

    // Reconstruct nms_tally_ at `anc_height` before alternate-branch apply.
    // Clear the tally, then replay the identical
    // per-block ingest (UpdateNmsTallyAfterCommit_) over the retained canonical prefix,
    // so nms_credits / seen_payloads / pre_flush_snapshot end byte-identical to what
    // forward ingest held at anc_height. Bounded: a boundary-aligned lookback that
    // precedes both the live credit window (COMINE_WINDOW_BLOCKS) and the seen-payload
    // retention (NMS_WINDOW_DEDUP_BLOCKS), so at most a few hundred blocks — all present
    // in the retained chain_ prefix. Paired with the per-alt-block advance in
    // Reorganize, this lets ComputeExpectedPoolOutputs draw the CORRECT alt-frame
    // winners on the reorg path, so the real recipient check can run there too.
    void RebuildNmsTallyToHeight_(uint64_t anc_height) {
        if (chain_.empty()) return;
        uint64_t start = 0;
        bool restored = false;
        for (auto it = nms_checkpoints_.rbegin();
             it != nms_checkpoints_.rend(); ++it) {
            if (it->height > anc_height || it->height >= chain_.size())
                continue;
            if (chain_[it->height].GetHash() != it->hash) continue;
            {
                std::unique_lock<std::shared_mutex> lock(nms_tally_mutex_);
                nms_tally_ = it->state;
            }
            start = it->height + 1;
            restored = true;
            break;
        }
        if (!restored) {
            std::unique_lock<std::shared_mutex> lock(nms_tally_mutex_);
            nms_tally_.Clear();
        }
        for (uint64_t h = start; h <= anc_height && h < chain_.size(); ++h) {
            UpdateNmsTallyAfterCommit_(LoadCanonicalBlockNoLock_(h));
        }
    }

    bool NmsPayloadSeen(const std::vector<uint8_t>& raw) const {
        Hash256 h = Hash256d(raw);
        std::string payload_hex = HashToHex(h);
        std::shared_lock<std::shared_mutex> lock(nms_tally_mutex_);
        return nms_tally_.seen_payloads.find(payload_hex) != nms_tally_.seen_payloads.end();
    }

#ifndef VELD_MAINNET_POW
    uint64_t legacy_replay_below_ = 0;
    void SetLegacyReplayBelow(uint64_t h) { legacy_replay_below_ = h; }
    uint64_t LegacyReplayBelow() const { return legacy_replay_below_; }
#endif

    // Canonical transaction/input binding shared by every all-input sigless
    // protocol settlement.  Set equality prevents partial/extra/duplicate
    // spends; explicit outpoint order removes a second encoding of the same
    // transition.  Because these inputs carry no signature, the ordinary
    // script path returns early and cannot canonicalize otherwise-ignored
    // scriptSig, sequence, version, or locktime fields for us.  Pin the exact
    // envelope emitted by every in-tree builder so txid/replay/reorg identity is
    // unique, not merely output-equivalent.
    static bool HasCanonicalProtocolInputs(
        const Transaction& tx, std::vector<UTXO> expected_utxos) {
        if (tx.version != 1 || tx.locktime != 0) return false;
        std::sort(expected_utxos.begin(), expected_utxos.end(),
                  [](const UTXO& a, const UTXO& b) {
                      if (a.tx_hash != b.tx_hash) return a.tx_hash < b.tx_hash;
                      return a.output_index < b.output_index;
                  });
        if (tx.inputs.size() != expected_utxos.size()) return false;
        for (size_t i = 0; i < expected_utxos.size(); ++i) {
            if (tx.inputs[i].prev_tx_hash != expected_utxos[i].tx_hash ||
                tx.inputs[i].prev_out_index !=
                    expected_utxos[i].output_index ||
                !tx.inputs[i].script_sig.empty() ||
                tx.inputs[i].sequence != 0xFFFFFFFFU) return false;
        }
        return true;
    }

    bool ValidateExpectedPoolPayout(const Block& block) const {
#ifndef VELD_MAINNET_POW
        if (legacy_replay_below_ > 0 && block.height < legacy_replay_below_) {
            return true;
        }
#endif
        if (block.height == 0) return true;

        std::vector<uint8_t> pool_script = AddressToScript(POOL_ADDRESS);
        if (pool_script.empty()) {
#ifdef VELD_MAINNET_POW
            throw std::runtime_error(
                "FATAL: AddressToScript(POOL_ADDRESS) returned empty in "
                "ValidateExpectedPoolPayout. Refusing to silently drop "
                "the pool-drain validation gate.");
#else
            return true;
#endif
        }

        if ((block.height % COMINE_WINDOW_BLOCKS) != 0) {
            for (const auto& tx : block.transactions) {
                if (tx.IsCoinbase()) continue;
                for (const auto& inp : tx.inputs) {
                    auto u = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
                    if (u && u->script_pubkey == pool_script) return false;
                }
            }
            return true;
        }

        auto pool_utxos = GetUTXOsForScriptLocked_(pool_script);
        uint64_t total_pool = 0;
        for (auto& u : pool_utxos) total_pool += u.value;

        auto expected = ComputeExpectedPoolOutputs_LockHeld(
            block.header.prev_block_hash, total_pool, block.height);

        const Transaction* payout_tx = nullptr;
        for (size_t i = 1; i < block.transactions.size(); ++i) {
            const auto& tx = block.transactions[i];
            if (tx.inputs.empty()) continue;
            const auto& in0 = tx.inputs[0];
            bool spends_pool = false;
            for (const auto& pu : pool_utxos) {
                if (pu.tx_hash == in0.prev_tx_hash
                    && pu.output_index == in0.prev_out_index) {
                    spends_pool = true;
                    break;
                }
            }
            if (spends_pool) {
#ifdef VELD_MAINNET_POW
                if (payout_tx != nullptr) return false;
                payout_tx = &tx;
#else
                payout_tx = &tx; break;
#endif
            }
        }

        // Validate recipients against the active chain frame on both forward
        // ingest and alternate-branch application. Reorganize rebuilds and
        // advances nms_tally_ from the fork point before this check.
        if (expected.empty()) {
            // Block must NOT contain a pool-payout TX. If it does, reject.
            return payout_tx == nullptr;
        }

        // Nonempty pool state has one canonical all-input payout/roll-forward
        // at each boundary.  It cannot be optional: repeated omissions would
        // eventually make the next settlement exceed the input limit.
        if (payout_tx == nullptr) return false;

        if (payout_tx->outputs.size() != expected.size()) return false;
        for (size_t i = 0; i < expected.size(); ++i) {
            if (payout_tx->outputs[i].value != expected[i].second) return false;
            if (payout_tx->outputs[i].script_pubkey != expected[i].first)
                return false;
        }
        // INPUT BINDING: the payout must CONSUME the entire
        // co-mine pool UTXO set the outputs were sized against. RHS is total_pool
        // (PRE-FEE sum of ALL pool UTXOs). The pool is the most exposed sigless
        // path on reorg (Gate 5's blanket ban deliberately excludes it), so this
        // binding is the only thing that stops a partial-input pool drain there.
        if (block.height >= BATCH3_HARDENING_HEIGHT &&
            !HasCanonicalProtocolInputs(*payout_tx, pool_utxos)) return false;
        return true;
    }

public:
    std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
    ComputeExpectedEndorsementFlushOutputs(
        uint64_t boundary_height,
        uint64_t endorsement_pool_balance_units,
        uint64_t tx_fee_reserve) const {
        std::vector<std::pair<std::vector<uint8_t>, uint64_t>> out;
        if (boundary_height == 0) return out;
        if (!IsStakingActive()) return out;
        if (endorsement_pool_balance_units <= tx_fee_reserve) return out;

        uint64_t window_size  = VAULT_DISTRIBUTION_INTERVAL;
        uint64_t window_start = boundary_height > window_size
                              ? boundary_height - window_size + 1 : 1;
        std::map<std::string, uint64_t> validator_counts;
        std::set<std::pair<std::string, uint64_t>> seen_endorsements;
        uint64_t total_endorsements = 0;
        for (uint64_t h = window_start; h <= boundary_height; ++h) {
            if (h >= chain_.size()) break;
            const Block blk = LoadCanonicalBlockNoLock_(h);
            for (const auto& btx : blk.transactions) {
                if (btx.IsCoinbase()) continue;
                bool is_endorse = false;
                bool canonical_endorsed_height = false;
                uint64_t endorsed_height = 0;
                std::string endorsed_hash;
                std::string endorsed_sig;
                for (const auto& op : btx.outputs) {
                    const auto& sp = op.script_pubkey;
                    if (sp.size() < 2 || sp[0] != 0x6A) continue;
                    size_t di = 1, dlen = 0;
                    if (sp[di] <= 75) { dlen = sp[di++]; }
                    else if (sp[di] == 0x4C && di + 1 < sp.size()) { di++; dlen = sp[di++]; }
                    else if (sp[di] == 0x4D && di + 2 < sp.size()) { di++; dlen = sp[di] | (sp[di+1]<<8); di+=2; }
                    if (dlen == 0 || di + dlen > sp.size()) continue;
                    std::string opd(sp.begin()+di, sp.begin()+di+dlen);
                    // Recognize the endorsement marker only at the payload prefix,
                    // never as an embedded substring. Anchoring
                    // to position 0 (matching BuildEndorseOp, which always emits the
                    // marker at the start, and ValidatorRegistry::ProcessOp, which
                    // already prefix-matches) prevents a marker embedded inside
                    // another family's payload from being credited an endorsement —
                    // a single-output cross-protocol composition. Honest-chain
                    // identical: every real endorsement is prefix-emitted.
                    if (opd.rfind("VELD_VALIDATOR|ENDORSE", 0) == 0) {
                        is_endorse = true;
                        auto ppos = opd.find("VELD_VALIDATOR|ENDORSE|");
                        if (ppos != std::string::npos) {
                            auto hstart = ppos + 23;
                            auto hend = opd.find('|', hstart);
                            if (hend != std::string::npos && hend > hstart) {
                                canonical_endorsed_height =
                                    ParseCanonicalUint64Text(
                                    std::string_view(opd).substr(
                                        hstart, hend - hstart),
                                        endorsed_height);
                                // the field after the height is the
                                // endorsed block hash (HashToHex form), used for
                                // the canonical-binding check below.
                                auto hash_start = hend + 1;
                                auto hash_end = opd.find('|', hash_start);
                                endorsed_hash = (hash_end != std::string::npos)
                                    ? opd.substr(hash_start, hash_end - hash_start)
                                    : opd.substr(hash_start);
                                if (hash_end != std::string::npos) {
                                    const auto sig_start = hash_end + 1;
                                    const auto sig_end = opd.find('|', sig_start);
                                    endorsed_sig = (sig_end != std::string::npos)
                                        ? opd.substr(sig_start, sig_end - sig_start)
                                        : opd.substr(sig_start);
                                }
                            }
                        }
                        break;
                    }
                }
                if (!is_endorse || !canonical_endorsed_height ||
                    btx.inputs.empty()) continue;
                std::vector<uint8_t> sig_unused;
                std::array<uint8_t, 1952> pk;
                if (!veld::pqc::ParseScriptSig(btx.inputs[0].script_sig, sig_unused, pk))
                    continue;
                Hash160 pkh = Hash160Compute(pk);
                std::vector<uint8_t> sender_script = {0x76,0xA9,0x14};
                sender_script.insert(sender_script.end(), pkh.begin(), pkh.end());
                sender_script.push_back(0x88); sender_script.push_back(0xAC);
                std::string addr = ScriptToAddress(sender_script);
                if (addr.empty()) continue;
                // Credit only addresses in the active validator set at this
                // height. The registry is deterministically rebuilt on replay.
                if (validator_filter_ && !validator_filter_(addr)) continue;
                // Count only endorsements naming a canonical block inside the
                // flush window: endorsed height in
                // [window_start, boundary] AND hash == the canonical block hash at
                // that height. Closes the pool-capture vector where a validator
                // self-signs endorsements over arbitrary / fake / out-of-window
                // (height, hash) pairs to inflate its pro-rata share. Compared
                // against chain_[h] directly — the caller holds chain_mutex_, so
                // the locking HasBlockAtHeight() would re-lock/deadlock here. The
                // marker hash is HashToHex(GetHash()) form (the emitter sources it
                // from getblockhash), identical to chain_[h].GetHash() hashed.
                if (boundary_height >= ENDORSE_CANONICAL_HEIGHT) {
                    if (endorsed_height < window_start || endorsed_height > boundary_height) continue;
                    if (endorsed_height >= chain_.size()) continue;
                    if (endorsed_hash != HashToHex(chain_[endorsed_height].GetHash())) continue;
                }
                // Active membership at the payout boundary is not evidence that
                // this marker was valid when included.  Require the registry's
                // signature-verified, inclusion-time acceptance for the exact
                // canonical tuple.  This closes both invalid-signature capture
                // and pre-seed-before-REGISTER / register-before-flush capture.
                if (!accepted_endorsement_fn_ ||
                    !accepted_endorsement_fn_(addr, endorsed_height,
                                              endorsed_hash,
                                              endorsed_sig)) continue;
                if (boundary_height >= ENDORSEMENT_DEDUP_HEIGHT) {
                    if (!seen_endorsements.insert({addr, endorsed_height}).second) continue;
                }
                validator_counts[addr]++;
                total_endorsements++;
            }
        }
        uint64_t distributable = endorsement_pool_balance_units - tx_fee_reserve;

        if (total_endorsements == 0 || validator_counts.empty()) {
            auto vault_script = AddressToScript(VaultAddressAtHeight(boundary_height));
            if (vault_script.empty()) {
                throw std::runtime_error(
                    "FATAL: AddressToScript(VaultAddressAtHeight) returned empty in empty-validator "
                    "endorsement sweep. VAULT_ADDRESS constant is corrupt or base58 decode broken. "
                    "Refusing to silently skip the sweep.");
            }
            out.emplace_back(vault_script, distributable);
            return out;
        }

        uint64_t distributed = 0;
        // Canonical sort contract: `validator_counts` is keyed by
        // base58-encoded address. std::map iterates in std::less<std::string>
        // order — strict lexicographic byte comparison of the UTF-8 bytes,
        // identical to std::string::operator<. Any third-party reimplementer
        // (explorer, indexer, fleet rebalance script) that derives the same
        // outputs MUST sort by `address.compare(b.address) < 0` (NOT memcmp
        // on raw script bytes, NOT locale-sensitive collation, NOT a
        // numeric/case-insensitive sort). The remainder at line 1242 is
        // routed to out[0] (the lexicographically-first eligible address),
        // making cross-host re-derivation byte-equal byte-for-byte.
        // Iteration in ASC address order — std::map guarantees this.
        for (const auto& [addr, count] : validator_counts) {
            auto vs = AddressToScript(addr);
            if (vs.empty()) continue;
            uint64_t share = (distributable * count) / total_endorsements;
            if (share > 0) {
                out.push_back({vs, share});
                distributed += share;
            }
        }
        if (out.empty()) return out;
        if (distributed < distributable)
            out[0].second += (distributable - distributed);
        return out;
    }

    // ───────────────────────────────────────────────────────────────
    //  OPTION B GATE — ValidateExpectedEndorsementFlush
    //  ( sigless redesign). Same pattern as
    //  ValidateExpectedPoolPayout but for the endorsement pool.
    //
    //  At h % VAULT_DISTRIBUTION_INTERVAL == 0:
    //    - identify flush TX (first non-coinbase TX whose first input
    //      spends an ENDORSEMENT_POOL_ADDRESS UTXO)
    //    - compute expected outputs via
    //      ComputeExpectedEndorsementFlushOutputs
    //    - if expected.empty() → block must NOT contain a flush TX
    //    - if expected non-empty → exactly one flush TX is mandatory and its
    //      ordered inputs/outputs must byte-equal the parent-state derivation
    //  At non-boundary heights: reject any TX spending endorsement-
    //  pool UTXOs.
    //
    //  Caller contract: must hold chain_mutex_ (shared or unique).
    // ───────────────────────────────────────────────────────────────
    bool ValidateExpectedEndorsementFlush(const Block& block) const {
        if (block.height == 0) return true;
        std::vector<uint8_t> ep_script = AddressToScript(ENDORSEMENT_POOL_ADDRESS);
        if (ep_script.empty()) {
#ifdef VELD_MAINNET_POW
            throw std::runtime_error(
                "FATAL: AddressToScript(ENDORSEMENT_POOL_ADDRESS) returned "
                "empty in ValidateExpectedEndorsementFlush. Refusing to "
                "silently drop the endorsement-pool-drain validation gate.");
#else
            return true;
#endif
        }

        if ((block.height % VAULT_DISTRIBUTION_INTERVAL) != 0) {
            for (const auto& tx : block.transactions) {
                if (tx.IsCoinbase()) continue;
                for (const auto& inp : tx.inputs) {
                    auto u = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
                    if (u && u->script_pubkey == ep_script) return false;
                }
            }
            return true;
        }

        auto ep_utxos = GetUTXOsForScriptLocked_(ep_script);
        uint64_t total_pool = 0;
        for (const auto& u : ep_utxos) total_pool += u.value;

        // Mandatory protocol settlements are consensus-zero-fee.  Charging a
        // synthetic fee out of custody is not principal-preserving after the
        // subsidy cap, where fee-only coinbase routing intentionally pays
        // miner/endorsement legs.  Zero keeps inputs == outputs at every era.
        auto expected = ComputeExpectedEndorsementFlushOutputs(
            block.height, total_pool, 0);

        const Transaction* flush_tx = nullptr;
        for (size_t i = 1; i < block.transactions.size(); ++i) {
            const auto& tx = block.transactions[i];
            if (tx.inputs.empty()) continue;
            bool spends_ep = false;
            for (const auto& input : tx.inputs) {
                for (const auto& u : ep_utxos) {
                    if (u.tx_hash == input.prev_tx_hash
                        && u.output_index == input.prev_out_index) {
                        spends_ep = true;
                        break;
                    }
                }
                if (spends_ep) break;
            }
            if (spends_ep) {
#ifdef VELD_MAINNET_POW
                if (flush_tx != nullptr) return false;
                flush_tx = &tx;
#else
                flush_tx = &tx; break;
#endif
            }
        }

        if (expected.empty()) {
            return flush_tx == nullptr;
        }
        // As with the co-mine pool, a derivable endorsement settlement is
        // mandatory.  Omission is not a harmless roll-forward when settlement
        // construction consumes the complete UTXO set.
        if (flush_tx == nullptr) return false;
        if (flush_tx->outputs.size() != expected.size()) return false;
        for (size_t i = 0; i < expected.size(); ++i) {
            if (flush_tx->outputs[i].value != expected[i].second) return false;
            if (flush_tx->outputs[i].script_pubkey != expected[i].first)
                return false;
        }
        // INPUT BINDING: the flush input set must byte-for-byte equal the
        // complete prior endorsement-pool UTXO set. A value-only comparison
        // allowed an extra non-pool input (or a pool input hidden after input
        // zero), which made the chain-derived paid-state detector disagree
        // with the transaction consensus accepted. Exact outpoint equality
        // gives forward connect, replay, and reorg one unambiguous flush event.
        if (block.height >= BATCH3_HARDENING_HEIGHT &&
            !HasCanonicalProtocolInputs(*flush_tx, ep_utxos)) return false;
        return true;
    }

    // ───────────────────────────────────────────────────────────────
    //  CANONICAL VAULT-DISTRIBUTION DERIVATION —
    //   (sigless vault distribution).
    //
    //  Replaces the off-chain `veld-distribute` daemon's signed-spend
    //  path with a consensus-deterministic on-chain rule. After
    //  VAULT_SIGLESS_ACTIVATION_HEIGHT, vault UTXOs are spendable ONLY
    //  in a flush TX whose outputs byte-equal what every node computes
    //  here. The vault private key becomes consensus-irrelevant — its
    //  compromise no longer drains the network.
    //
    //  Algorithm (deterministic, integer-only, matches the daemon's
    //  steady-state semantics modulo ramp/dust thresholds):
    //    1. distributable = (vault_balance − fee_reserve) × DIST_PPM/1e6
    //         where DIST_PPM = 80000 (8%) — see VAULT_DISTRIBUTION_PPM
    //         in constants.h. (Backstop cap; rarely binds post-.)
    //    1b. Inflow cap (VAULT-NEVER-DRAINS rule). If
    //         boundary_height ≥ VAULT_INFLOW_CAP_ACTIVATION_HEIGHT,
    //         distributable is further bounded:
    //             distributable = min(distributable,
    //                                 prev_cycle_inflow × VAULT_INFLOW_PAYOUT_PPM / 1e6)
    //         with VAULT_INFLOW_PAYOUT_PPM = 900_000 (90%). Vault retains
    //         (1 − K) × inflow per cycle. Eliminates the equilibrium-seeking
    //         8%-of-balance behavior the prior rule produced and prevents
    //         the mainnet activation drain (the ~50% supply-share reserve
    //         accumulated pre-activation decaying to the ~12.5×-cycle-inflow
    //         equilibrium that the prior rule would otherwise cause).
    //    2. If distributable < VAULT_MIN_DISTRIBUTABLE_UNITS or
    //       weighted_stake is empty → emit one vault consolidation output.
    //       The boundary always consumes the complete parent vault set, which
    //       keeps the next mandatory transaction below its input limit.
    //    3. total_weight = Σ weighted_stake[addr] (with overflow guard).
    //    4. per_staker_cap = distributable × CAP_PPM/1e6 (75% by default).
    //    5. For each (addr, weight) in canonical ASC sort (std::map
    //       guarantees this):
    //         share = (distributable × weight) / total_weight        // __uint128_t to avoid overflow
    //         if share > per_staker_cap: share = per_staker_cap      // excess stays in vault as change
    //         if share == 0:             skip                        // dust
    //         emit (script(addr), share)
    //    6. Change output: `vault_balance − total_paid − fee_reserve`
    //       routed back to VaultAddressAtHeight(boundary_height) so
    //       the next cycle's vault UTXO consolidates to one entry.
    //
    //  Determinism contract: every input is either a constant
    //  (VAULT_DISTRIBUTION_PPM, etc.), a chain-derived value
    //  (vault_balance from utxos, weighted_stake from chain replay,
    //  prev_cycle_inflow from chain replay), or computed via integer-only
    //  arithmetic (no floating point, no unordered_map iteration). Two
    //  nodes given the same chain state derive byte-identical output sets.
    //
    //  Caller contract: must hold chain_mutex_ (shared or unique). The
    //  `weighted_stake` map MUST be pre-built from state-at-(h−1) so
    //  the new block's effects don't leak into the snapshot.
    //  `prev_cycle_inflow_units` MUST be derived from
    //  ComputeVaultInflowSinceLastDistribution_Locked(boundary_height) so
    //  build + validate paths agree byte-for-byte.
    // ───────────────────────────────────────────────────────────────
    //  Helper for the VAULT-NEVER-DRAINS K-cap ().
    //
    //  Sums VELD that flowed INTO the vault address from coinbase
    //  transactions during the most-recent VAULT_DISTRIBUTION_INTERVAL
    //  blocks ending at boundary_height (inclusive). The boundary
    //  block's coinbase has already produced its outputs by the time
    //  the distribution TX runs in the same block, so it counts as
    //  inflow for THIS cycle's K-cap.
    //
    //  Determinism: walks chain_[start..boundary_height] in canonical
    //  order, sums fixed-script-match coinbase outputs. Pure function
    //  of chain state — every node returns the same value.
    //
    //  Caller must hold chain_mutex_ (shared or unique).
    //
    //  Returns 0 if boundary_height is 0 or strictly beyond chain tip+1
    //  (i.e. truly out of range). The boundary_height == chain_.size()
    //  case is the in-progress boundary block being built or validated:
    //  it is NOT in chain_ yet, but the prior distribution window ending at
    //  chain_.size()-1 is, and that's exactly what this helper needs to
    //  sum. A zero result would make
    //  every post-VAULT_INFLOW_CAP_ACTIVATION_HEIGHT boundary skip
    //  distribution because the cap would clamp distributable to
    //  0, the expected output set was empty, miners legitimately omitted
    //  the flush, and stakers got nothing. Live evidence: h=12528 was
    //  the first K-cap-active boundary and produced no payouts.
    // ───────────────────────────────────────────────────────────────
    uint64_t ComputeVaultInflowSinceLastDistribution_Locked(
        uint64_t boundary_height) const {
        if (boundary_height == 0) return 0;
        if (boundary_height > chain_.size()) return 0;

        auto vault_script =
            AddressToScript(VaultAddressAtHeight(boundary_height));
        if (vault_script.empty()) return 0;

        const uint64_t window = VAULT_DISTRIBUTION_INTERVAL;
        const uint64_t start =
            (boundary_height >= window) ? (boundary_height - window + 1) : 1;

        uint64_t total = 0;
        for (uint64_t h = start; h <= boundary_height; ++h) {
            if (h >= chain_.size()) break;
            const Block blk = LoadCanonicalBlockNoLock_(h);
            const auto& coinbase = blk.transactions[0];
            if (!coinbase.IsCoinbase()) continue;
            for (const auto& out : coinbase.outputs) {
                if (out.script_pubkey == vault_script) {
                    total += out.value;
                }
            }
        }
        return total;
    }

    uint64_t ComputeVaultInflowSinceLastDistribution(
        uint64_t boundary_height) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return ComputeVaultInflowSinceLastDistribution_Locked(boundary_height);
    }

    std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
    ComputeExpectedVaultDistribution(
        uint64_t boundary_height,
        uint64_t vault_balance_units,
        uint64_t fee_reserve,
        uint64_t prev_cycle_inflow_units,
        const std::map<std::string, uint64_t>& weighted_stake) const {
        std::vector<std::pair<std::vector<uint8_t>, uint64_t>> out;
        if (boundary_height == 0) return out;
        if ((boundary_height % VAULT_DISTRIBUTION_INTERVAL) != 0) return out;
        if (vault_balance_units <= fee_reserve) return out;

        uint64_t spendable = vault_balance_units - fee_reserve;
        // A boundary with no eligible payout must still consume the complete
        // prior vault UTXO set and roll it into one output.  Otherwise the
        // pre-staking phase alone creates ~31.8k coinbase UTXOs, exceeding the
        // 10k transaction-input limit before the first staker can ever be paid.
        // The canonical transition is zero-fee (fee_reserve=0 at every caller),
        // so input principal equals output principal exactly; coinbase reward
        // percentages and timing are untouched.  The boundary ends with at
        // most consolidation/change plus the current coinbase output.
        auto consolidation_only = [&]() {
            std::vector<std::pair<std::vector<uint8_t>, uint64_t>> c;
            auto script =
                AddressToScript(VaultAddressAtHeight(boundary_height));
            if (!script.empty() && spendable > 0)
                c.emplace_back(std::move(script), spendable);
            return c;
        };

        if (!IsStakingActive()) return consolidation_only();

        uint64_t distributable = (uint64_t)
            ((__uint128_t)spendable * (__uint128_t)VAULT_DISTRIBUTION_PPM
             / (__uint128_t)1'000'000ULL);

        //  Inflow cap (VAULT-NEVER-DRAINS rule). Activation-gated so
        // pre-activation chain history remains valid byte-for-byte. Once
        // active, distributable is bounded by VAULT_INFLOW_PAYOUT_PPM
        // fraction of the inflow during the cycle ending at boundary_height.
        // K = 0.90 → vault retains ≥10% of every cycle's inflow as principal,
        // guaranteeing monotone growth and eliminating the equilibrium
        // attractor (≈12.5× cycle inflow) that the pure 8%-of-balance rule
        // produces.
        if (boundary_height >= VAULT_INFLOW_CAP_ACTIVATION_HEIGHT) {
            uint64_t inflow_cap = (uint64_t)
                ((__uint128_t)prev_cycle_inflow_units
                 * (__uint128_t)VAULT_INFLOW_PAYOUT_PPM
                 / (__uint128_t)1'000'000ULL);
            if (distributable > inflow_cap) distributable = inflow_cap;
        }

        if (distributable < VAULT_MIN_DISTRIBUTABLE_UNITS)
            return consolidation_only();

        const std::map<std::string, uint64_t>* wsp = &weighted_stake;
        std::map<std::string, uint64_t> ws_local;
        // Activation height zero means active from genesis. Accrual and escrow
        // accounting must remain enabled together.
        if (boundary_height >= BOND_YIELD_ACTIVATION_HEIGHT
            && bond_yield_weight_fn_) {
            uint64_t byw = bond_yield_weight_fn_(boundary_height);
            if (byw > 0) {
                ws_local = weighted_stake;
                uint64_t& slot = ws_local[BOND_YIELD_ESCROW];
                if (UINT64_MAX - slot >= byw) slot += byw;
                else slot = UINT64_MAX;
                wsp = &ws_local;
            }
        }
        const std::map<std::string, uint64_t>& effective_stake = *wsp;

        uint64_t total_weight = 0;
        for (const auto& [_, w] : effective_stake) {
            if (UINT64_MAX - total_weight < w) return out;
            total_weight += w;
        }
        if (total_weight == 0) return consolidation_only();

        uint64_t per_staker_cap = (uint64_t)
            ((__uint128_t)distributable * (__uint128_t)VAULT_CONCENTRATION_CAP_PPM
             / (__uint128_t)1'000'000ULL);

        std::vector<std::pair<std::string, uint64_t>> staker_payouts;
        staker_payouts.reserve(effective_stake.size());
        uint64_t total_paid = 0;
        for (const auto& [addr, weight] : effective_stake) {
            __uint128_t share128 =
                (__uint128_t)distributable * (__uint128_t)weight
                / (__uint128_t)total_weight;
            uint64_t share = (uint64_t)share128;
            if (share > per_staker_cap) share = per_staker_cap;
            if (share == 0) continue;
            staker_payouts.emplace_back(addr, share);
            total_paid += share;
        }
        if (staker_payouts.empty()) return consolidation_only();

        out.reserve(staker_payouts.size() + 1);
        for (const auto& [addr, share] : staker_payouts) {
            auto script = AddressToScript(addr);
            if (script.empty()) continue;
            out.emplace_back(std::move(script), share);
        }
        if (out.empty()) return consolidation_only();

        if (vault_balance_units < total_paid + fee_reserve) {
            return {};
        }
        uint64_t change = vault_balance_units - total_paid - fee_reserve;
        if (change > 0) {
            auto vault_script = AddressToScript(VaultAddressAtHeight(boundary_height));
            if (!vault_script.empty()) {
                out.emplace_back(std::move(vault_script), change);
            }
        }

        return out;
    }

    bool ValidateExpectedVaultDistribution(const Block& block) const {
        if (block.height == 0) return true;
        // Activation height zero means active from genesis; the comparison also
        // handles a future nonzero activation height.
        if (block.height < VAULT_SIGLESS_ACTIVATION_HEIGHT) return true;

        std::vector<uint8_t> vault_script =
            AddressToScript(VaultAddressAtHeight(block.height));
        if (vault_script.empty()) {
#ifdef VELD_MAINNET_POW
            throw std::runtime_error(
                "FATAL: AddressToScript(VaultAddressAtHeight) returned empty "
                "in ValidateExpectedVaultDistribution. VAULT_ADDRESS is "
                "corrupt or base58 decode "
                "is broken — refusing to silently drop the vault-drain "
                "validation gate.");
#else
            return true;
#endif
        }

        if ((block.height % VAULT_DISTRIBUTION_INTERVAL) != 0) {
            for (const auto& tx : block.transactions) {
                if (tx.IsCoinbase()) continue;
                for (const auto& inp : tx.inputs) {
                    auto u = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
                    if (u && u->script_pubkey == vault_script) return false;
                }
            }
            return true;
        }

        auto vault_utxos = GetUTXOsForScriptLocked_(vault_script);
        uint64_t total_vault = 0;
        for (const auto& u : vault_utxos) total_vault += u.value;
        // Consensus-zero-fee roll-forward/distribution: vault principal is
        // neither burned nor temporarily redirected through coinbase fees.
        uint64_t fee_reserve = 0;

        // Snapshot stake state at block.height − 1 (the parent height).
        // The new block's effects are NOT yet applied, so the snapshot is
        // strictly state-at-parent — same view every node has during
        // pre-commit validation of this block.
        std::map<std::string, uint64_t> stake_snapshot;
        if (stake_snapshot_at_height_) {
            stake_snapshot = stake_snapshot_at_height_(block.height - 1);
        }

        uint64_t prev_cycle_inflow =
            ComputeVaultInflowSinceLastDistribution_Locked(block.height);

        auto expected = ComputeExpectedVaultDistribution(
            block.height, total_vault, fee_reserve,
            prev_cycle_inflow, stake_snapshot);

        const Transaction* flush_tx = nullptr;
        for (size_t i = 1; i < block.transactions.size(); ++i) {
            const auto& tx = block.transactions[i];
            if (tx.inputs.empty()) continue;
            bool spends_vault = false;
            for (const auto& inp : tx.inputs) {
                for (const auto& u : vault_utxos) {
                    if (u.tx_hash == inp.prev_tx_hash
                        && u.output_index == inp.prev_out_index) {
                        spends_vault = true; break;
                    }
                }
                if (spends_vault) break;
            }
            if (spends_vault) {
#ifdef VELD_MAINNET_POW
                if (flush_tx != nullptr) return false;
                flush_tx = &tx;
#else
                flush_tx = &tx; break;
#endif
            }
        }

        if (expected.empty()) {
            return flush_tx == nullptr;
        }
        // A nonempty canonical output set is mandatory so consolidation cannot
        // be deferred until the all-input transaction exceeds structural limits.
        if (flush_tx == nullptr) return false;
        if (flush_tx->outputs.size() != expected.size()) return false;
        for (size_t i = 0; i < expected.size(); ++i) {
            if (flush_tx->outputs[i].value != expected[i].second) return false;
            if (flush_tx->outputs[i].script_pubkey != expected[i].first)
                return false;
        }
        // INPUT BINDING: the flush must CONSUME the entire
        // vault UTXO set the outputs were sized against. RHS is total_vault (the
        // PRE-FEE sum of ALL vault UTXOs) — NOT the output sum (= total_vault −
        // fee_reserve), which the honest flush would fail (it spends total_vault,
        // letting fee_reserve fall through as miner fee) → chain halt. Closes the
        // partial-input mint on BOTH the main-chain and reorg (Step 6) paths.
        if (block.height >= BATCH3_HARDENING_HEIGHT &&
            !HasCanonicalProtocolInputs(*flush_tx, vault_utxos)) return false;
        return true;
    }

    std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
    ExpectedVaultDistributionOutputs(uint64_t height) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        std::vector<uint8_t> vault_script =
            AddressToScript(VaultAddressAtHeight(height));
        if (vault_script.empty()) return {};
        auto vault_utxos = GetUTXOsForScriptLocked_(vault_script);
        uint64_t total_vault = 0;
        for (const auto& u : vault_utxos) total_vault += u.value;
        uint64_t fee_reserve = 0;
        std::map<std::string, uint64_t> stake_snapshot;
        if (stake_snapshot_at_height_)
            stake_snapshot = stake_snapshot_at_height_(height - 1);
        uint64_t prev_cycle_inflow =
            ComputeVaultInflowSinceLastDistribution_Locked(height);
        return ComputeExpectedVaultDistribution(height, total_vault, fee_reserve,
                                                prev_cycle_inflow, stake_snapshot);
    }

    Transaction BuildVaultDistributionFlushTx(uint64_t height) const {
        Transaction tx; tx.version = 1;
        std::vector<uint8_t> vault_script =
            AddressToScript(VaultAddressAtHeight(height));
        if (vault_script.empty()) return tx;
        auto vault_utxos = GetUTXOsForScript(vault_script);
        if (vault_utxos.empty()) return tx;
        auto payouts = ExpectedVaultDistributionOutputs(height);
        if (payouts.empty()) return tx;
        std::sort(vault_utxos.begin(), vault_utxos.end(),
                  [](const UTXO& a, const UTXO& b) {
                      if (a.tx_hash != b.tx_hash) return a.tx_hash < b.tx_hash;
                      return a.output_index < b.output_index;
                  });
        for (const auto& u : vault_utxos) {
            TxInput inp;
            inp.prev_tx_hash   = u.tx_hash;
            inp.prev_out_index = u.output_index;
            tx.inputs.push_back(inp);
        }
        for (const auto& pr : payouts) {
            TxOutput o; o.value = pr.second; o.script_pubkey = pr.first;
            tx.outputs.push_back(o);
        }
        return tx;
    }

    std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
    ComputeExpectedBondMovements(uint64_t boundary_height,
                                 uint64_t stake_vault_balance_units,
                                 uint64_t fee_reserve) const {
        std::vector<std::pair<std::vector<uint8_t>, uint64_t>> out;
        // Activation height zero means active from genesis; the comparison also
        // handles a future nonzero activation height.
        if (boundary_height < STAKE_VAULT_ACTIVATION_HEIGHT) return out;
        if (boundary_height == 0) return out;
        if ((boundary_height % BOND_SETTLEMENT_INTERVAL) != 0) return out;
        if (!bond_settlements_fn_) return out;

        auto raw = bond_settlements_fn_(boundary_height);
        if (raw.empty()) return out;

        std::sort(raw.begin(), raw.end(),
                  [](const auto& a, const auto& b){
                      if (std::get<0>(a) != std::get<0>(b)) return std::get<0>(a) < std::get<0>(b);
                      if (std::get<1>(a) != std::get<1>(b)) return std::get<1>(a) < std::get<1>(b);
                      if (std::get<2>(a) != std::get<2>(b)) return std::get<2>(a) < std::get<2>(b);
                      return std::get<3>(a) < std::get<3>(b);
                  });

        auto vault_now = AddressToScript(VaultAddressAtHeight(boundary_height));

        uint64_t total_paid = 0;
        for (const auto& s : raw) {
            const std::string& vaddr   = std::get<0>(s);
            int                kind    = std::get<1>(s);
            uint64_t           bond    = std::get<2>(s);
            const std::string& slasher = std::get<3>(s);
            if (bond == 0) continue;
            auto vscript = AddressToScript(vaddr);
            if (vscript.empty()) continue;

            if (kind == 0) {
                out.emplace_back(vscript, bond);
                if (UINT64_MAX - total_paid < bond) return {};
                total_paid += bond;
            } else {
                // kind: 1 = ordinary slash (50% principal returned)
                //       2 = FINALITY EQUIVOCATION (0% returned)
                //
                // Equivocation is the one act that can finalize two
                // incompatible histories. The locked-QC safety argument prices
                // it at the WHOLE bond; returning half would price a
                // double-spend against the peg at half the bond. See
                // constants.h SLASH_EQUIV_*.
                const bool equivocation = (kind == 2);
                uint64_t eff_slasher_ppm;
                uint64_t eff_confiscation_ppm;
                if (equivocation) {
                    // The bounty is height-gated exactly like the ordinary
                    // slash: below SLASH_BOUNTY_HEIGHT no slasher is derivable,
                    // so the burn absorbs the whole bond. What never varies is
                    // that the offender receives nothing.
                    eff_slasher_ppm = (boundary_height >= SLASH_BOUNTY_HEIGHT)
                        ? SLASH_EQUIV_SLASHER_PPM : 0;
                    eff_confiscation_ppm =
                        (boundary_height >= SLASH_BOUNTY_HEIGHT)
                            ? SLASH_EQUIV_BURN_PPM
                            : (SLASH_EQUIV_SLASHER_PPM +
                               SLASH_EQUIV_BURN_PPM);
                } else {
                    eff_slasher_ppm = (boundary_height >= SLASH_BOUNTY_HEIGHT)
                        ? SLASH_SLASHER_PPM : 0;
                    eff_confiscation_ppm = (boundary_height >= SLASH_BOUNTY_HEIGHT)
                        ? SLASH_VAULT_PPM : (SLASH_SLASHER_PPM + SLASH_VAULT_PPM);
                }
                uint64_t slasher_share = (uint64_t)
                    ((__uint128_t)bond * (__uint128_t)eff_slasher_ppm
                     / (__uint128_t)1'000'000ULL);
                uint64_t confiscation_share = (uint64_t)
                    ((__uint128_t)bond * (__uint128_t)eff_confiscation_ppm
                     / (__uint128_t)1'000'000ULL);
                if (slasher.empty() && slasher_share > 0) {
                    confiscation_share += slasher_share;
                    slasher_share = 0;
                }
                uint64_t return_share =
                    bond - slasher_share - confiscation_share;
                // The whole point of the equivocation class, asserted rather
                // than assumed: integer ppm division rounds DOWN, so shares
                // summing to 1'000'000 ppm can still leave a remainder of a few
                // units. Those units must be burned, never returned to an
                // equivocator.
                if (equivocation && return_share > 0) {
                    confiscation_share += return_share;
                    return_share = 0;
                }
                if (slasher_share > 0) {
                    auto sscript = AddressToScript(slasher);
                    if (!sscript.empty())
                        out.emplace_back(std::move(sscript), slasher_share);
                    else { confiscation_share += slasher_share; }
                }
                if (confiscation_share > 0) {
                    if (equivocation) {
                        out.emplace_back(FinalityEquivocationBurnScript(),
                                         confiscation_share);
                    } else if (!vault_now.empty()) {
                        out.emplace_back(vault_now, confiscation_share);
                    }
                }
                if (return_share > 0)
                    out.emplace_back(vscript, return_share);
                if (UINT64_MAX - total_paid < bond) return {};
                total_paid += bond;
            }
        }
        if (out.empty()) return out;

        if (fee_reserve > UINT64_MAX - total_paid) return {};
        if (stake_vault_balance_units < total_paid + fee_reserve) return {};
        uint64_t change = stake_vault_balance_units - total_paid - fee_reserve;
        if (change > 0) {
            auto sv = AddressToScript(STAKE_VAULT_ADDRESS);
            if (!sv.empty()) out.emplace_back(std::move(sv), change);
        }
        return out;
    }

    bool ValidateExpectedBondMovements(const Block& block) const {
        if (block.height == 0) return true;
        // Activation height zero means active from genesis.
        if (block.height < STAKE_VAULT_ACTIVATION_HEIGHT) return true;

        std::vector<uint8_t> sv_script = AddressToScript(STAKE_VAULT_ADDRESS);
        if (sv_script.empty()) {
#ifdef VELD_MAINNET_POW
            throw std::runtime_error(
                "FATAL: AddressToScript(STAKE_VAULT_ADDRESS) returned empty "
                "in ValidateExpectedBondMovements. Refusing to silently "
                "drop the STAKE_VAULT-drain validation gate.");
#else
            return true;
#endif
        }

        if ((block.height % BOND_SETTLEMENT_INTERVAL) != 0) {
            for (const auto& tx : block.transactions) {
                if (tx.IsCoinbase()) continue;
                for (const auto& inp : tx.inputs) {
                    auto u = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
                    if (u && u->script_pubkey == sv_script) return false;
                }
            }
            return true;
        }

        auto sv_utxos = GetUTXOsForScriptLocked_(sv_script);
        uint64_t total_sv = 0;
        for (const auto& u : sv_utxos) total_sv += u.value;
        // Canonical stake-vault settlements are miner-built protocol
        // transactions, not mempool transactions.  Charging their fee out of
        // the custody vault made recorded liabilities exceed remaining assets:
        // every payout silently taxed other validators' principal and the last
        // exact-balance bond became unpayable.  They are consensus-zero-fee so
        // every bond unit remains fully backed and fully returnable.
        uint64_t fee_reserve = 0;

        bool principal_due = false;
        if (bond_settlements_fn_) {
            for (const auto& settlement :
                 bond_settlements_fn_(block.height)) {
                if (std::get<2>(settlement) > 0) {
                    principal_due = true;
                    break;
                }
            }
        }

        auto expected =
            ComputeExpectedBondMovements(block.height, total_sv, fee_reserve);

        const Transaction* settle_tx = nullptr;
        for (size_t i = 1; i < block.transactions.size(); ++i) {
            const auto& tx = block.transactions[i];
            if (tx.inputs.empty()) continue;
            bool spends_sv = false;
            for (const auto& inp : tx.inputs) {
                for (const auto& u : sv_utxos) {
                    if (u.tx_hash == inp.prev_tx_hash
                        && u.output_index == inp.prev_out_index) {
                        spends_sv = true; break;
                    }
                }
                if (spends_sv) break;
            }
            if (spends_sv) {
#ifdef VELD_MAINNET_POW
                if (settle_tx != nullptr) return false;
                settle_tx = &tx;
#else
                settle_tx = &tx; break;
#endif
            }
        }

        // An empty derivation is ambiguous: it can mean "nothing is due", or
        // it can mean a real liability was under-backed/overflowed/had an
        // invalid recipient. Only the empty-liability case may omit the one-shot canonical
        // transaction; the latter must fail closed rather than silently retire
        // an unpaid entitlement in the module replay.
        if (expected.empty())
            return !principal_due && settle_tx == nullptr;
        // Entitlements are keyed to one exact boundary and carry no mutable
        // "paid" bit.  Optional omission therefore does not roll forward; it
        // strands the bond forever.  A due canonical settlement is mandatory.
        if (settle_tx == nullptr) return false;
        if (settle_tx->outputs.size() != expected.size()) return false;
        for (size_t i = 0; i < expected.size(); ++i) {
            if (settle_tx->outputs[i].value != expected[i].second) return false;
            if (settle_tx->outputs[i].script_pubkey != expected[i].first)
                return false;
        }
        // INPUT BINDING: the settlement input set must equal the complete
        // stake-vault UTXO set byte-for-byte.  A value-only sum admits all vault
        // inputs plus an ordinary extra input, silently turning a transaction
        // documented as consensus-zero-fee into a fee-bearing transaction.
        // Exact outpoint equality also rejects duplicates and missing inputs.
        if (block.height >= BATCH3_HARDENING_HEIGHT &&
            !HasCanonicalProtocolInputs(*settle_tx, sv_utxos)) return false;
        return true;
    }

    std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
    ComputeExpectedBondYieldSettlement(uint64_t boundary_height,
                                       uint64_t escrow_balance_units,
                                       uint64_t fee_reserve) const {
        std::vector<std::pair<std::vector<uint8_t>, uint64_t>> out;
        // Activation height zero means active from genesis.
        if (boundary_height < BOND_YIELD_ACTIVATION_HEIGHT) return out;
        if (boundary_height == 0) return out;
        if ((boundary_height % BOND_SETTLEMENT_INTERVAL) != 0) return out;
        if (!bond_yield_settlements_fn_) return out;

        auto raw = bond_yield_settlements_fn_(boundary_height);
        if (raw.empty()) return out;

        std::sort(raw.begin(), raw.end(),
                  [](const auto& a, const auto& b){
                      if (std::get<0>(a) != std::get<0>(b)) return std::get<0>(a) < std::get<0>(b);
                      if (std::get<1>(a) != std::get<1>(b)) return std::get<1>(a) < std::get<1>(b);
                      if (std::get<2>(a) != std::get<2>(b)) return std::get<2>(a) < std::get<2>(b);
                      return std::get<3>(a) < std::get<3>(b);
                  });

        auto vault_now = AddressToScript(VaultAddressAtHeight(boundary_height));

        uint64_t total_paid = 0;
        for (const auto& s : raw) {
            const std::string& vaddr   = std::get<0>(s);
            int                kind    = std::get<1>(s);
            uint64_t           units   = std::get<2>(s);
            const std::string& slasher = std::get<3>(s);
            if (units == 0) continue;
            auto vscript = AddressToScript(vaddr);
            if (vscript.empty()) continue;

            if (kind == 0) {
                out.emplace_back(vscript, units);
                if (UINT64_MAX - total_paid < units) return {};
                total_paid += units;
            } else {
                // Both slash classes confiscate unvested yield in full.
                // Equivocation retains its separate 25/75/0 schedule so an
                // ordinary-slash policy change cannot alter finality penalties.
                const bool equivocation = (kind == 2);
                uint64_t eff_slasher_ppm =
                    (boundary_height >= SLASH_BOUNTY_HEIGHT)
                        ? (equivocation ? SLASH_EQUIV_SLASHER_PPM
                                        : SLASH_SLASHER_PPM)
                        : 0;
                uint64_t slasher_share = (uint64_t)
                    ((__uint128_t)units * (__uint128_t)eff_slasher_ppm
                     / (__uint128_t)1'000'000ULL);
                if (slasher.empty() && slasher_share > 0) slasher_share = 0;
                uint64_t confiscation_share = units - slasher_share;
                if (slasher_share > 0) {
                    auto sscript = AddressToScript(slasher);
                    if (!sscript.empty())
                        out.emplace_back(std::move(sscript), slasher_share);
                    else { confiscation_share += slasher_share; }
                }
                if (confiscation_share > 0) {
                    if (equivocation) {
                        out.emplace_back(FinalityEquivocationBurnScript(),
                                         confiscation_share);
                    } else if (!vault_now.empty()) {
                        out.emplace_back(vault_now, confiscation_share);
                    }
                }
                if (UINT64_MAX - total_paid < units) return {};
                total_paid += units;
            }
        }
        if (out.empty()) return out;

        if (fee_reserve > UINT64_MAX - total_paid) return {};
        if (escrow_balance_units < total_paid + fee_reserve) return {};
        uint64_t change = escrow_balance_units - total_paid - fee_reserve;
        if (change > 0) {
            auto esc = AddressToScript(BOND_YIELD_ESCROW);
            if (!esc.empty()) out.emplace_back(std::move(esc), change);
        }
        return out;
    }

    bool ValidateExpectedBondYieldSettlement(const Block& block) const {
        if (block.height == 0) return true;
        // Activation height zero means active from genesis.
        if (block.height < BOND_YIELD_ACTIVATION_HEIGHT) return true;

        std::vector<uint8_t> esc_script = AddressToScript(BOND_YIELD_ESCROW);
        if (esc_script.empty()) {
#ifdef VELD_MAINNET_POW
            throw std::runtime_error(
                "FATAL: AddressToScript(BOND_YIELD_ESCROW) returned empty "
                "in ValidateExpectedBondYieldSettlement. Refusing to "
                "silently drop the bond-yield-escrow-drain validation gate.");
#else
            return true;
#endif
        }

        if ((block.height % BOND_SETTLEMENT_INTERVAL) != 0) {
            for (const auto& tx : block.transactions) {
                if (tx.IsCoinbase()) continue;
                for (const auto& inp : tx.inputs) {
                    auto u = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
                    if (u && u->script_pubkey == esc_script) return false;
                }
            }
            return true;
        }

        auto esc_utxos = GetUTXOsForScriptLocked_(esc_script);
        uint64_t total_esc = 0;
        for (const auto& u : esc_utxos) total_esc += u.value;
        // As with principal, D' tranches are exact protocol liabilities.  A
        // fee charged from escrow makes the terminal tranche unpayable.  The
        // canonical sigless settlement is consensus-zero-fee.
        uint64_t fee_reserve = 0;

        bool yield_due = false;
        if (bond_yield_settlements_fn_) {
            for (const auto& settlement :
                 bond_yield_settlements_fn_(block.height)) {
                if (std::get<2>(settlement) > 0) {
                    yield_due = true;
                    break;
                }
            }
        }

        auto expected = ComputeExpectedBondYieldSettlement(
            block.height, total_esc, fee_reserve);

        const Transaction* settle_tx = nullptr;
        for (size_t i = 1; i < block.transactions.size(); ++i) {
            const auto& tx = block.transactions[i];
            if (tx.inputs.empty()) continue;
            bool spends_esc = false;
            for (const auto& inp : tx.inputs) {
                for (const auto& u : esc_utxos) {
                    if (u.tx_hash == inp.prev_tx_hash
                        && u.output_index == inp.prev_out_index) {
                        spends_esc = true; break;
                    }
                }
                if (spends_esc) break;
            }
            if (spends_esc) {
#ifdef VELD_MAINNET_POW
                if (settle_tx != nullptr) return false;
                settle_tx = &tx;
#else
                settle_tx = &tx; break;
#endif
            }
        }

        if (expected.empty())
            return !yield_due && settle_tx == nullptr;
        // Each tranche emits at one exact release/confiscation boundary; without
        // a paid cursor, omission cannot be retried safely.  Require the unique
        // canonical transaction whenever a tranche is due.
        if (settle_tx == nullptr) return false;
        if (settle_tx->outputs.size() != expected.size()) return false;
        for (size_t i = 0; i < expected.size(); ++i) {
            if (settle_tx->outputs[i].value != expected[i].second) return false;
            if (settle_tx->outputs[i].script_pubkey != expected[i].first)
                return false;
        }
        // INPUT BINDING: exact outpoint-set equality, matching principal above.
        // This makes the zero-fee D' settlement claim an enforced rule rather
        // than an output-only convention, and rejects extras/duplicates/missing.
        if (block.height >= BATCH3_HARDENING_HEIGHT &&
            !HasCanonicalProtocolInputs(*settle_tx, esc_utxos)) return false;
        return true;
    }

    // ───────────────────────────────────────────────────────────────
    //  CANONICAL POOL-PAYOUT DERIVATION
    //
    //  Deterministic function every node runs to compute the expected
    //  pool-payout output set for a block at an H%COMINE_WINDOW_BLOCKS==0
    //  boundary. Pure: reads only NmsTally snapshot + prev_block_hash +
    //  pool_balance. Used by:
    //    * ValidateExpectedPoolPayout (consensus gate)
    //    * Node::BuildPoolPayoutTx via Node::ComputeExpectedPoolPayoutOutputs
    //  Both callers MUST return byte-equal output lists or the chain
    //  forks — so they all delegate to this one function.
    //
    //  Algorithm (flat-uniform, adaptive-K, without replacement):
    //    1. Snapshot (script_hex → credit) from NmsTally (std::map →
    //       already byte-lexicographic).
    //    2. Build eligible list: any miner with credit > 0, excluding
    //       VAULT_ADDRESS / POOL_ADDRESS / ENDORSEMENT_POOL_ADDRESS
    //       scripts (system addresses never win the lottery they fund).
    //    3. If list empty → entire pool rolls forward to POOL_ADDRESS.
    //    4. K_eff = LOTTERY_K_LARGE_FLEET (20) when eligible >=
    //       LOTTERY_FLEET_SIZE_THRESHOLD (1000) else LOTTERY_K_SMALL_FLEET (5).
    //    5. Seed = aggregate SHA256d over the last LOTTERY_AGG_SEED_K
    //       block headers (post-activation) or Hash256d(prev_block_hash)
    //       (pre-activation / early-chain fallback). Seed bumps via
    //       Hash256d-on-prior-seed between slot draws.
    //    6. Draw K_eff slots without replacement (modular index into
    //       residual live list; winner removed from pool before next
    //       draw). Each miner wins at most one slot per flush.
    //    7. Pool split: at/after LOTTERY_KSLOT_DIVISOR_HEIGHT, pool_balance /
    //       K_eff per slot so a winner takes exactly ONE slot; below it, the
    //       legacy divide-by-winner-count (winners split the whole pool).
    //       Rounding remainder attaches to slot-0 winner. Winners emitted in
    //       canonical script_hex order (ascending winner-index).
    //    8. Unspent slots (winners < K_eff) roll forward as a final
    //       output to POOL_ADDRESS so inputs == outputs in the TX.
    // ───────────────────────────────────────────────────────────────
    //  // Public wrapper that acquires shared_lock(chain_mutex_) for
    // callers that do NOT already hold the lock (the mining loop).
    // AddBlockDirect ALREADY holds chain_mutex_ unique-mode and
    // cannot re-acquire shared (std::shared_mutex disallows
    // recursive shared acquisition from a thread holding unique).
    // Such callers MUST call ComputeExpectedPoolOutputs_LockHeld
    // directly. The two-overload pattern mirrors the *NoLock
    // accessors in this header (e.g. GetUTXONoLock).
    std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
    ComputeExpectedPoolOutputs(const Hash256& prev_block_hash,
                                uint64_t pool_balance_units,
                                uint64_t block_height) const {
        std::shared_lock<std::shared_mutex> chain_lock(chain_mutex_);
        return ComputeExpectedPoolOutputs_LockHeld(
            prev_block_hash, pool_balance_units, block_height);
    }

    std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
    ComputeExpectedPoolOutputs_LockHeld(const Hash256& prev_block_hash,
                                         uint64_t pool_balance_units,
                                         uint64_t block_height) const {
        std::vector<std::pair<std::vector<uint8_t>, uint64_t>> out;
        if (pool_balance_units == 0) return out;

        if (!IsStakingActive()) return out;

        std::vector<std::pair<std::string, uint64_t>> snapshot;
        {
            std::shared_lock<std::shared_mutex> lock(nms_tally_mutex_);
            snapshot.reserve(nms_tally_.nms_credits.size());
            for (const auto& [k, v] : nms_tally_.nms_credits) {
                snapshot.emplace_back(k, v);
            }
        }

        std::vector<uint8_t> vault_excl   = AddressToScript(VaultAddressAtHeight(block_height));
        std::vector<uint8_t> pool_excl    = AddressToScript(POOL_ADDRESS);
        std::vector<uint8_t> endorse_excl = AddressToScript(ENDORSEMENT_POOL_ADDRESS);

        struct UniformEntry {
            std::string          script_hex;
            std::vector<uint8_t> script;
        };
        std::vector<UniformEntry> uniform_eligible;
        uniform_eligible.reserve(snapshot.size());
        for (const auto& [script_hex, credit] : snapshot) {
            if (credit == 0) continue;
            std::vector<uint8_t> script = HexToBytes(script_hex);
            if (script.empty()) continue;
            if (script == vault_excl)   continue;
            if (script == pool_excl)    continue;
            if (script == endorse_excl) continue;
            if (block_height >= BATCH2_HARDENING_HEIGHT) {
                if (!NmsBondSatisfied(script)) continue;
            }
            uniform_eligible.push_back({script_hex, std::move(script)});
        }
        if (uniform_eligible.empty()) {
            if (pool_balance_units > 0) {
                out.emplace_back(pool_excl, pool_balance_units);
            }
            return out;
        }

        const size_t K_eff =
            (uniform_eligible.size() >= LOTTERY_FLEET_SIZE_THRESHOLD)
            ? LOTTERY_K_LARGE_FLEET
            : LOTTERY_K_SMALL_FLEET;

        Hash256 seed;
        if (LOTTERY_AGG_SEED_ACTIVATION_HEIGHT != 0
            && block_height >= LOTTERY_AGG_SEED_ACTIVATION_HEIGHT) {
            std::vector<uint8_t> agg;
            agg.reserve((size_t)LOTTERY_AGG_SEED_K * 88);
            uint64_t start = (block_height >= LOTTERY_AGG_SEED_K)
                ? block_height - LOTTERY_AGG_SEED_K
                : 0;
            bool fell_short = false;
            for (uint64_t h = start; h < block_height; ++h) {
                if (h >= chain_.size()) { fell_short = true; break; }
                auto hb = chain_[h].header.Serialize();
                agg.insert(agg.end(), hb.begin(), hb.end());
            }
            if (fell_short || agg.empty()) {
                seed = Hash256d(prev_block_hash.data(), prev_block_hash.size());
            } else {
                seed = Hash256d(agg);
            }
        } else {
            seed = Hash256d(prev_block_hash.data(), prev_block_hash.size());
        }
        auto seed_bump = [&]() { seed = Hash256d(seed.data(), seed.size()); };
        auto hash_to_u64 = [&](const Hash256& h) -> uint64_t {
            uint64_t v = 0;
            for (int i = 0; i < 8; ++i)
                v |= ((uint64_t)h[i]) << (i * 8);
            return v;
        };

        std::vector<size_t> winner_indices;
        winner_indices.reserve(K_eff);
        std::vector<bool> already_won(uniform_eligible.size(), false);
        size_t remaining_n = uniform_eligible.size();
        for (size_t slot = 0; slot < K_eff && remaining_n > 0; ++slot) {
            uint64_t r = hash_to_u64(seed) % remaining_n;
            size_t pick   = SIZE_MAX;
            size_t scan_i = 0;
            for (size_t i = 0; i < uniform_eligible.size(); ++i) {
                if (already_won[i]) continue;
                if (scan_i == r) { pick = i; break; }
                ++scan_i;
            }
            if (pick == SIZE_MAX) break;
            winner_indices.push_back(pick);
            already_won[pick] = true;
            --remaining_n;
            seed_bump();
        }
        if (winner_indices.empty()) {
            if (pool_balance_units > 0) {
                out.emplace_back(pool_excl, pool_balance_units);
            }
            return out;
        }

        //  DIVISOR (consensus, height-gated). At/after LOTTERY_KSLOT_DIVISOR_
        // HEIGHT the pool is split into K_eff slots and each winner takes ONE
        // slot (pool / K_eff); unfilled slots roll forward (steps 7-8 below).
        // Below it, the legacy BATCH2_HARDENING behaviour (divide by winner
        // count -> winners split the whole pool) is preserved so nodes agree
        // on history. The divisor path never ran before the first staked
        // miner's payout, so this gate changes no past block.
        const uint64_t lottery_divisor =
            (block_height >= LOTTERY_KSLOT_DIVISOR_HEIGHT)
                ? (uint64_t)K_eff
                : (uint64_t)winner_indices.size();
        uint64_t per_slot      = pool_balance_units / lottery_divisor;
        uint64_t remainder_amt = pool_balance_units - per_slot * lottery_divisor;
        size_t   slot0_idx     = winner_indices[0];

        std::sort(winner_indices.begin(), winner_indices.end());
        uint64_t total_winner_payout = 0;
        for (size_t idx : winner_indices) {
            uint64_t amount = per_slot + (idx == slot0_idx ? remainder_amt : 0);
            out.emplace_back(uniform_eligible[idx].script, amount);
            total_winner_payout += amount;
        }

        if (total_winner_payout < pool_balance_units) {
            uint64_t rollforward = pool_balance_units - total_winner_payout;
            out.emplace_back(pool_excl, rollforward);
        }
        return out;
    }

private:
    mutable std::shared_mutex nms_tally_mutex_;
    NmsTally nms_tally_;
    struct NmsCheckpoint {
        uint64_t height{0};
        Hash256 hash{};
        NmsTally state;
    };
    std::deque<NmsCheckpoint> nms_checkpoints_;
    NmsStakeQueryFn nms_stake_query_;
    ValidatorFilterFn validator_filter_;
    AcceptedEndorsementFn accepted_endorsement_fn_;
    CheckpointAtOrBelowFn checkpoint_at_or_below_;
    StakeSnapshotFn stake_snapshot_at_height_;
    BondSettlementsFn bond_settlements_fn_;
    BondYieldWeightFn bond_yield_weight_fn_;
    BondYieldSettlementsFn bond_yield_settlements_fn_;
    AltOverlayBuildFn    alt_overlay_build_fn_;
    AltOverlayAdvanceFn  alt_overlay_advance_fn_;
    AltOverlayTeardownFn alt_overlay_teardown_fn_;
    RuntimeAdmissionFn runtime_admission_fn_;
public:

#ifdef VELD_TEST_HOOKS
    inline static std::atomic<uint64_t> test_add_block_direct_calls_{0};
    inline static std::atomic<uint64_t> test_verify_block_pow_calls_{0};
    inline static thread_local int64_t
        test_pow_dataset_failure_countdown_{-1};
    static void TestResetAddBlockDirectCalls() {
        test_add_block_direct_calls_.store(0, std::memory_order_release);
    }
    static uint64_t TestAddBlockDirectCalls() {
        return test_add_block_direct_calls_.load(std::memory_order_acquire);
    }
    static void TestResetVerifyBlockPowCalls() {
        test_verify_block_pow_calls_.store(0, std::memory_order_release);
    }
    static uint64_t TestVerifyBlockPowCalls() {
        return test_verify_block_pow_calls_.load(std::memory_order_acquire);
    }
    static void TestForcePowDatasetUnavailableAfter(
            uint64_t successful_calls) {
        test_pow_dataset_failure_countdown_ =
            successful_calls > static_cast<uint64_t>(INT64_MAX)
                ? INT64_MAX : static_cast<int64_t>(successful_calls);
    }
#endif

    bool AddBlock(const Block& block) {
        return AddBlockDirect(
            block, false, false, false,
            mining::PowAdmissionContext::Internal());
    }

    // `dataset_unavailable` (optional) distinguishes a TRANSIENT local VeldHash
    // dataset failure from a real proof-of-work reject. Callers that treat a
    // false return as peer misbehaviour MUST pass it and branch on it; see F-4.
    static bool VerifyBlockPoW(const Block& block,
                               bool* dataset_unavailable = nullptr,
                               const CanonicalPowTarget* contextual_target = nullptr) {
#ifdef VELD_TEST_HOOKS
        test_verify_block_pow_calls_.fetch_add(1, std::memory_order_acq_rel);
        if (test_pow_dataset_failure_countdown_ >= 0) {
            if (test_pow_dataset_failure_countdown_ == 0) {
                test_pow_dataset_failure_countdown_ = -1;
                mining::g_veldhash_last_dataset_ok() = false;
                if (dataset_unavailable) *dataset_unavailable = true;
                return false;
            }
            --test_pow_dataset_failure_countdown_;
        }
#endif
#if defined(VELD_TEST_BRANCH_CONTEXT)
#if defined(VELD_PUBLIC_RELEASE)
#error "VELD_TEST_BRANCH_CONTEXT must never be enabled in a public release"
#endif
        // Focused fork-context regression hook.  The branch-MTP/LWMA harness
        // must drive multiple complete reorgs across a retarget boundary; doing
        // that with VeldHash would turn a deterministic consensus sentinel into
        // a slow, hardware-dependent mining benchmark.  The hook bypasses ONLY
        // the hash-vs-target comparison.  AddBlockDirect and
        // ValidateBlockForReplay still enforce the submitted compact bits,
        // branch-local LWMA result, MTP, UTXO, coinbase, and atomic reorg rules.
        (void)block;
        return true;
#else
        CanonicalPowTarget decoded;
        if (!DecodeCanonicalVeldTarget(block.header.bits, decoded)) return false;
        if (contextual_target &&
            (contextual_target->bits != decoded.bits ||
             contextual_target->value != decoded.value)) return false;

        // Compact-target syntax is a constant-time structural gate.  Decode it
        // before invoking the memory-hard hash so an invalid `bits` field cannot
        // force a full VeldHash verification merely to be rejected afterwards.
        std::vector<uint8_t> header = block.header.Serialize();
        const CanonicalPowTarget& target =
            contextual_target ? *contextual_target : decoded;
        Hash256 pow_hash = mining::VeldHash(header, block.height, target);

        // VerifyBlockPoW runs on every ingested block, including peer traffic.
        // AddBlockDirect records the bounded rejection reason.

        // when the 1 GB VeldHash dataset cannot be
        // produced for this epoch seed, VeldHash() returns an all-0xFF sentinel
        // that is larger than any valid target — indistinguishable from a
        // genuine sub-target reject by the comparison alone. That is exactly
        // why veldhash.h maintains the g_veldhash_last_dataset_ok()
        // side-channel; until now its only consumers were the genesis miner and
        // genesis_pow.h, so the block validator — the caller it was written for
        // — silently converted a TRANSIENT local resource failure into a
        // consensus verdict. Because "pow_verify_failed" is a member of both
        // IsHardBlockReject_ and IsHeaderHashCacheableBlockReject_, that
        // misclassification banned the honest peer serving the correct chain
        // and poisoned the valid block's hash for REJECT_TTL_SECONDS. Read the
        // side-channel BEFORE comparing, so a sentinel can never be reported as
        // a proof-of-work decision.
        if (!mining::g_veldhash_last_dataset_ok()) {
            if (dataset_unavailable) *dataset_unavailable = true;
            return false;
        }
        return pow_hash < target.bytes;
#endif
    }

    bool ValidateTransactionLocking(const Transaction& tx, bool allow_coinbase = false) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return ValidateTransaction(tx, allow_coinbase);
    }

    // Re-check only the parts of a previously authenticated mempool root that
    // can change when the canonical tip changes. P2PKH signatures and their
    // referenced scripts are committed by immutable tx/outpoint bytes, so an
    // entry admitted by Mempool::Add may cache that expensive result. Absolute
    // and relative lock-times, UTXO availability/confirmation height, and P2SH
    // covenant execution remain contextual and must be evaluated at every new
    // parent frame. This helper deliberately accepts no "allow coinbase" mode.
    bool ValidateCachedMempoolLockingContext(const Transaction& tx) const {
        if (tx.IsCoinbase() || tx.inputs.empty()) return false;
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);

        const uint64_t cov_height = Height() + 1;
        const bool covenants_active =
            cov_height >= COVENANTS_ACTIVATION_HEIGHT;
        const uint64_t cov_mtp = covenants_active ? MedianTimePast() : 0;
        if (covenants_active) {
            auto utxo_conf = [&](size_t idx, uint64_t& out_h,
                                 uint64_t& out_mtp) -> bool {
                if (idx >= tx.inputs.size()) return false;
                auto u = GetUTXONoLock(tx.inputs[idx].prev_tx_hash,
                                       tx.inputs[idx].prev_out_index);
                if (!u) return false;
                out_h = u->block_height;
                out_mtp = MedianTimePastAt(u->block_height);
                return true;
            };
            if (!::veld::CheckTxLockTimes(tx, cov_height, cov_mtp,
                                          utxo_conf))
                return false;
        }

        for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
            const auto& inp = tx.inputs[i];
            auto u = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
            if (!u) return false;
            if (u->is_coinbase &&
                u->block_height >= COINBASE_MATURITY_ACTIVATES_AT_HEIGHT &&
                Height() >= COINBASE_MATURITY_ACTIVATES_AT_HEIGHT &&
                (Height() < u->block_height ||
                 Height() - u->block_height < COINBASE_MATURITY))
                return false;
            const auto& script = u->script_pubkey;

            if (amm_pool_input_check_) {
                const int r = amm_pool_input_check_(
                    script, inp.prev_tx_hash, inp.prev_out_index);
                if (r > 0) {
                    if (!inp.script_sig.empty()) return false;
                    continue;
                }
                if (r < 0) return false;
            }

            if (covenants_active && script.size() == 23 &&
                script[0] == 0xA9 && script[1] == 0x14 &&
                script[22] == 0x87) {
                ScriptContext sctx;
                sctx.block_height = cov_height;
                sctx.mtp = cov_mtp;
                sctx.utxo_height = u->block_height;
                sctx.covenants_active = true;
                ScriptInterpreter interp;
                if (!interp.Execute(inp.script_sig, script, tx, i, sctx))
                    return false;
                continue;
            }

            // Only canonical P2PKH reaches the immutable-signature cache. Any
            // unfamiliar script shape fails closed and is eligible for a fresh
            // full admission attempt after it leaves the stale mempool.
            if (script.size() != 25 || script[0] != 0x76 ||
                script[1] != 0xA9 || script[2] != 0x14 ||
                script[23] != 0x88 || script[24] != 0xAC)
                return false;
        }
        return true;
    }

    // Mempool child transactions can mix an output created by an unconfirmed
    // parent with one or more outputs that already exist in the canonical UTXO
    // set.  ValidateTransaction() intentionally fails on the missing parent, so
    // Mempool cannot use the whole-transaction entry point for that shape.  It
    // must still verify EVERY canonical input, however: previously the mixed
    // path verified only the unconfirmed-parent inputs and blindly trusted the
    // canonical ones, admitting a forged signature that miners later rejected.
    //
    // This helper validates one already-resolved canonical input under the same
    // current-tip script/covenant context as ValidateTransaction.  Missing
    // (mempool-parent) inputs are skipped only by the elapsed-lock callback;
    // their scripts are validated separately by Mempool.  The current committed
    // AMM pool input retains its deliberate sigless exemption, whose stateful
    // half is enforced by Mempool::ValidateAmmMempoolCandidate immediately
    // before this helper is used.
    enum class MempoolCanonicalInputResult {
        VALID,
        INVALID,
        MISSING_OR_CHANGED
    };

    MempoolCanonicalInputResult ValidateMempoolCanonicalInput(
                                       const Transaction& tx,
                                       uint32_t input_index,
                                       const UTXO& observed_utxo) const {
        if (input_index >= tx.inputs.size() || tx.IsCoinbase())
            return MempoolCanonicalInputResult::INVALID;
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);

        // The caller's initial GetUTXO() and this validation are two lock
        // acquisitions.  A reorg can land between them, so never authenticate
        // against the stale object passed by the caller. Re-resolve the exact
        // outpoint while holding chain_mutex_ and require every field to match;
        // a disappearance/replacement is a transient missing-input race, not a
        // forged-signature verdict that should banscore the relaying peer.
        const auto& inp = tx.inputs[input_index];
        auto current = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
        if (!current || current->tx_hash != observed_utxo.tx_hash ||
            current->output_index != observed_utxo.output_index ||
            current->value != observed_utxo.value ||
            current->script_pubkey != observed_utxo.script_pubkey ||
            current->block_height != observed_utxo.block_height ||
            current->is_coinbase != observed_utxo.is_coinbase) {
            return MempoolCanonicalInputResult::MISSING_OR_CHANGED;
        }
        const UTXO& utxo = *current;

        const uint64_t cov_height = Height() + 1;
        const bool covenants_active =
            (cov_height >= COVENANTS_ACTIVATION_HEIGHT);
        const uint64_t cov_mtp = covenants_active ? MedianTimePast() : 0;
        if (covenants_active) {
            auto utxo_conf = [&](size_t idx, uint64_t& out_h,
                                 uint64_t& out_mtp) -> bool {
                auto u = GetUTXONoLock(tx.inputs[idx].prev_tx_hash,
                                       tx.inputs[idx].prev_out_index);
                if (!u) return false;  // unconfirmed parent: checked on its own
                out_h   = u->block_height;
                out_mtp = MedianTimePastAt(u->block_height);
                return true;
            };
            if (!::veld::CheckTxLockTimes(tx, cov_height, cov_mtp, utxo_conf))
                return MempoolCanonicalInputResult::INVALID;
        }

        const auto& script_pubkey = utxo.script_pubkey;
        if (amm_pool_input_check_) {
            int r = amm_pool_input_check_(script_pubkey, utxo.tx_hash,
                                          utxo.output_index);
            if (r > 0) return MempoolCanonicalInputResult::VALID;
            if (r < 0) return MempoolCanonicalInputResult::INVALID;
        }

        if (covenants_active && script_pubkey.size() == 23 &&
            script_pubkey[0] == 0xA9 && script_pubkey[1] == 0x14 &&
            script_pubkey[22] == 0x87) {
            ScriptContext sctx;
            sctx.block_height     = cov_height;
            sctx.mtp              = cov_mtp;
            sctx.utxo_height      = utxo.block_height;
            sctx.covenants_active = true;
            ScriptInterpreter interp;
            return interp.Execute(tx.inputs[input_index].script_sig,
                                  script_pubkey, tx, input_index, sctx)
                ? MempoolCanonicalInputResult::VALID
                : MempoolCanonicalInputResult::INVALID;
        }

        return VerifyInputAgainstScript(tx, input_index, script_pubkey)
            ? MempoolCanonicalInputResult::VALID
            : MempoolCanonicalInputResult::INVALID;
    }

    bool ValidateTransaction(const Transaction& tx, bool allow_coinbase = false) const {
        // Block validation must enforce the same context-free transaction
        // structure as mempool admission.  Without this, a zero-input,
        // zero-value OP_RETURN transaction (and malformed input/output/script
        // cardinalities) reached the 0-in == 0-out value check and was accepted
        // in a block despite being impossible to relay through the mempool.
        if (!tx.IsValid()) return false;
        if (tx.IsCoinbase()) return allow_coinbase;

        // Reject cross-protocol marker composition. A single
        // non-coinbase tx may carry OP_RETURN markers from at most one stateful
        // VELD_* protocol family; two or more distinct families would be applied
        // by two independent per-family state machines (onchain_tokens, amm_pool,
        // staking, validators, governance, btcVELD anchor/relay/redeem) from one
        // input + authorization set. Evaluated BEFORE the sigless-flush fast-paths
        // below: the canonical vault / endorsement-pool / co-mine flushes carry
        // only VELD_DIST| labels (not a stateful family), so they are unaffected.
        if (::veld::TxComposesMultipleProtocols(tx)) return false;
        if (::veld::TxHasInvalidTokenMarkerSet(tx)) return false;
#ifdef VELD_PUBLIC_TESTNET
        // The public testnet is valueless by consensus, not merely by UI or
        // daemon convention. Reject every external-asset protocol marker on
        // replay, direct block submission, and reorg validation. Operators
        // must restart the disposable testnet from its compiled genesis when
        // adopting this profile rule.
        if (::veld::TxUsesExternalValueProtocol(tx)) return false;
#endif

        // Ordinary transactions use the tight relay/consensus fanout bound.
        // The only exception is a transaction whose complete input set is one
        // of the protected protocol pools below.  Those branches return early
        // only for all-input system spends, and block validation separately
        // requires their exact, deterministic output set.  A mixed-input or
        // user-authored transaction reaches the final rejection below.
        const bool oversized_standard_fanout =
            tx.outputs.size() > MAX_STANDARD_TRANSACTION_OUTPUTS;

        std::vector<uint8_t> pool_script = AddressToScript(POOL_ADDRESS);
        if (!pool_script.empty()) {
            bool all_inputs_from_pool = !tx.inputs.empty();
            bool any_input_from_pool  = false;
            for (const auto& inp : tx.inputs) {
                auto utxo_opt = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
                if (!utxo_opt) { all_inputs_from_pool = false; continue; }
                if (utxo_opt->script_pubkey == pool_script) any_input_from_pool = true;
                else                                        all_inputs_from_pool = false;
            }
            if (any_input_from_pool && !all_inputs_from_pool) {
                return false;
            }
            if (all_inputs_from_pool) {
                return true;
            }
        }

        std::vector<uint8_t> ep_script = AddressToScript(ENDORSEMENT_POOL_ADDRESS);
        if (!ep_script.empty()) {
            bool all_inputs_from_ep = !tx.inputs.empty();
            bool any_input_from_ep  = false;
            for (const auto& inp : tx.inputs) {
                auto utxo_opt = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
                if (!utxo_opt) { all_inputs_from_ep = false; continue; }
                if (utxo_opt->script_pubkey == ep_script) any_input_from_ep = true;
                else                                      all_inputs_from_ep = false;
            }
            if (any_input_from_ep && !all_inputs_from_ep) {
                return false;
            }
            if (all_inputs_from_ep) {
                return true;
            }
        }

        //  (vault sigless).
        // Same sigless pattern as pool / endorsement-pool, BUT strictly
        // gated on VAULT_SIGLESS_ACTIVATION_HEIGHT.
        //
        // SECURITY-CRITICAL: this rule MUST be height-gated. Without the
        // gate, anyone could broadcast an unsigned vault-spending TX
        // pre-activation and the byte-equal validator (also pre-activation
        // dormant) would NOT catch the drain — vault would be open. The
        // activation gate ensures pre-activation vault still requires the
        // legacy P2PKH signature (the daemon's signed TXs continue to be
        // the only valid vault spends until coordinated cutover).
        //
        // Post-activation: ValidateExpectedVaultDistribution enforces
        // byte-equal canonical-flush output matching, so even though we
        // skip per-input scriptSig verification here, the OUTPUT side is
        // locked down. Only Node::BuildVaultDistributionTx produces a
        // matching set; arbitrary attackers cannot.
        // chain_.Height() at validation time is the parent height; the
        // block being validated is at chain_.Height()+1. Compare the
        // *block-being-validated's* height to the activation gate so this
        // sigless rule fires on the same block as ValidateExpectedVault-
        // Distribution (which checks block.height directly).
        // Activation height zero means active from genesis. Canonical distribution
        // validation prevents unauthorized keyless-vault spends.
        if ((Height() + 1) >= VAULT_SIGLESS_ACTIVATION_HEIGHT) {
            std::vector<uint8_t> vault_script =
                AddressToScript(VaultAddressAtHeight(Height() + 1));
            if (!vault_script.empty()) {
                bool all_inputs_from_vault = !tx.inputs.empty();
                bool any_input_from_vault  = false;
                for (const auto& inp : tx.inputs) {
                    auto utxo_opt = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
                    if (!utxo_opt) { all_inputs_from_vault = false; continue; }
                    if (utxo_opt->script_pubkey == vault_script) any_input_from_vault = true;
                    else                                          all_inputs_from_vault = false;
                }
                if (any_input_from_vault && !all_inputs_from_vault) {
                    return false;
                }
                if (all_inputs_from_vault) {
                    return true;
                }
            }
        }

        // Activation height zero means active from genesis. Canonical settlement
        // validation prevents unauthorized stake-vault spends.
        if ((Height() + 1) >= STAKE_VAULT_ACTIVATION_HEIGHT) {
            std::vector<uint8_t> sv_script = AddressToScript(STAKE_VAULT_ADDRESS);
            if (!sv_script.empty()) {
                bool all_inputs_from_sv = !tx.inputs.empty();
                bool any_input_from_sv  = false;
                for (const auto& inp : tx.inputs) {
                    auto utxo_opt = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
                    if (!utxo_opt) { all_inputs_from_sv = false; continue; }
                    if (utxo_opt->script_pubkey == sv_script) any_input_from_sv = true;
                    else                                       all_inputs_from_sv = false;
                }
                if (any_input_from_sv && !all_inputs_from_sv) {
                    return false;
                }
                if (all_inputs_from_sv) {
                    return true;
                }
            }
        }

        // Activation height zero means active from genesis. Canonical settlement
        // validation prevents unauthorized escrow spends.
        if ((Height() + 1) >= BOND_YIELD_ACTIVATION_HEIGHT) {
            std::vector<uint8_t> bye_script = AddressToScript(BOND_YIELD_ESCROW);
            if (!bye_script.empty()) {
                bool all_inputs_from_bye = !tx.inputs.empty();
                bool any_input_from_bye  = false;
                for (const auto& inp : tx.inputs) {
                    auto utxo_opt = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
                    if (!utxo_opt) { all_inputs_from_bye = false; continue; }
                    if (utxo_opt->script_pubkey == bye_script) any_input_from_bye = true;
                    else                                        all_inputs_from_bye = false;
                }
                if (any_input_from_bye && !all_inputs_from_bye) {
                    return false;
                }
                if (all_inputs_from_bye) {
                    return true;
                }
            }
        }

        if (oversized_standard_fanout) return false;

        // Covenant activation: enforce absolute (nLockTime) + relative
        // (nSequence) lock-times, and route P2SH redeem scripts through the
        // script interpreter. Inert below the activation height — legacy P2PKH
        // transactions (locktime 0, final sequences) are unaffected.
        const uint64_t cov_height = Height() + 1;
        const bool covenants_active = (cov_height >= COVENANTS_ACTIVATION_HEIGHT);
        const uint64_t cov_mtp = covenants_active ? MedianTimePast() : 0;
        if (covenants_active) {
            auto utxo_conf = [&](size_t idx, uint64_t& out_h, uint64_t& out_mtp) -> bool {
                auto u = GetUTXONoLock(tx.inputs[idx].prev_tx_hash,
                                       tx.inputs[idx].prev_out_index);
                if (!u) return false;
                out_h   = u->block_height;
                out_mtp = MedianTimePastAt(u->block_height);
                return true;
            };
            if (!::veld::CheckTxLockTimes(tx, cov_height, cov_mtp, utxo_conf))
                return false;
        }

        for (size_t i = 0; i < tx.inputs.size(); ++i) {
            const auto& inp = tx.inputs[i];

            auto utxo_opt = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
            if (!utxo_opt) return false;

            const auto& script_pubkey = utxo_opt->script_pubkey;

            // AMM pool covenant input (btcVELD). The pool VELD UTXO is spendable
            // ONLY via a consensus-checked AMM op; amm_block_validator_ is the
            // guard. Sigless-exempt the CURRENT committed pool outpoint; any other
            // pool-marker UTXO (attacker-created or same-block chained) is rejected.
            // Inert until a committed pool exists; non-pool scripts return 0.
            if (amm_pool_input_check_) {
                int r = amm_pool_input_check_(script_pubkey, inp.prev_tx_hash, inp.prev_out_index);
                // This covenant input has no signature or witness.  Requiring
                // the exact empty scriptSig is therefore its canonical
                // authorization form.  Without this check, any observer could
                // append up to the transaction script limit of arbitrary bytes:
                // user SIGHASH_ALL signatures remain valid (other scriptSigs
                // are blanked in the preimage), but the txid and successor pool
                // outpoint change under them.
                if (r > 0) {
                    if (!inp.script_sig.empty()) return false;
                    continue;
                }
                if (r < 0) return false;
            }

            // Covenant P2SH input — validate the redeem script via the
            // interpreter (handles multisig, HTLC, timelock, template spends).
            if (covenants_active && script_pubkey.size() == 23 &&
                script_pubkey[0] == 0xA9 && script_pubkey[1] == 0x14 &&
                script_pubkey[22] == 0x87) {
                ScriptContext sctx;
                sctx.block_height     = cov_height;
                sctx.mtp              = cov_mtp;
                sctx.utxo_height      = utxo_opt->block_height;
                sctx.covenants_active = true;
                ScriptInterpreter interp;
                if (!interp.Execute(inp.script_sig, script_pubkey, tx, (uint32_t)i, sctx))
                    return false;
                continue;
            }

            if (script_pubkey.size() != 25 ||
                script_pubkey[0]  != 0x76 ||
                script_pubkey[1]  != 0xA9 ||
                script_pubkey[2]  != 0x14 ||
                script_pubkey[23] != 0x88 ||
                script_pubkey[24] != 0xAC) {
                return false;
            }

            std::array<uint8_t,20> expected_hash;
            std::copy(script_pubkey.begin()+3, script_pubkey.begin()+23, expected_hash.begin());

            auto read_pushdata2 = [](const std::vector<uint8_t>& ss, size_t& pos,
                                     std::vector<uint8_t>& out) -> bool {
                if (pos + 3 > ss.size()) return false;
                if (ss[pos++] != 0x4D) return false;
                size_t len = (size_t)ss[pos] | ((size_t)ss[pos+1] << 8);
                pos += 2;
                if (pos + len > ss.size()) return false;
                out.assign(ss.begin() + pos, ss.begin() + pos + len);
                pos += len;
                return true;
            };

            const auto& ss = inp.script_sig;
            size_t pos = 0;
            std::vector<uint8_t> sig_bytes_with_hashtype;
            std::vector<uint8_t> pubkey_bytes;
            if (!read_pushdata2(ss, pos, sig_bytes_with_hashtype)) return false;
            if (!read_pushdata2(ss, pos, pubkey_bytes)) return false;
            if (pubkey_bytes.size() != 1952) return false;
            if (sig_bytes_with_hashtype.empty()) return false;
            if (pos != ss.size()) return false;

            // On-wire signature layout:
            //   [scheme_id (1B)] [raw 3309-byte ML-DSA-65 sig] [SIGHASH_ALL (1B)]
            // Validate length, isolate the raw signature, and dispatch using the
            // explicit scheme identifier. Unknown schemes fail closed.
            if (sig_bytes_with_hashtype.size() != 3311) return false;
            uint8_t scheme_id = sig_bytes_with_hashtype.front();
            if (scheme_id != ::veld::SCHEME_ID_MLDSA65) return false;
            if (sig_bytes_with_hashtype.back() != 0x01) return false;

            Secp256k1PubKey pubkey;
            std::copy(pubkey_bytes.begin(), pubkey_bytes.end(), pubkey.begin());

            Hash160 actual_hash = Hash160Compute(pubkey);
            for (int j = 0; j < 20; ++j)
                if (actual_hash[j] != expected_hash[j]) return false;

            Secp256k1SigDER sig_bytes(sig_bytes_with_hashtype.begin() + 1,
                                      sig_bytes_with_hashtype.end() - 1);

            // Compute sighash with the same scheme_id binding the
            // signer used (matches BuildScriptSig at signing time).
            Hash256 sighash = ComputeSighash(tx, (uint32_t)i, script_pubkey, scheme_id);
            if (!Verify(pubkey, sighash, sig_bytes)) return false;
        }

        {
            uint64_t input_total = 0, output_total = tx.TotalOutput();
            for (const auto& inp : tx.inputs) {
                auto utxo_opt = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
                if (!utxo_opt) continue;
                if (utxo_opt->value > MAX_SUPPLY_UNITS) return false;
                if (input_total > UINT64_MAX - utxo_opt->value) return false;
                input_total += utxo_opt->value;
            }
            if (output_total > input_total) return false;
        }
        return true;
    }

    static const std::unordered_map<uint64_t, std::string>& GetCheckpoints() {
        auto rev_hex = [](const std::string& be) -> std::string {
            if (be.size() != 64) return be;
            std::string le(64, '0');
            for (size_t i = 0; i < 32; ++i) {
                le[i * 2]     = be[62 - i * 2];
                le[i * 2 + 1] = be[63 - i * 2];
            }
            return le;
        };

        static const std::unordered_map<uint64_t, std::string> checkpoints = {
        };
        (void)rev_hex;
        return checkpoints;
    }

    std::string GetBlockHashAtHeight(uint64_t height) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        if (height >= chain_.size()) return "";
        return HashToHex(chain_[height].GetHash());
    }

#ifdef VELD_TEST_HOOKS
    // Test-only checkpoint overlay, compiled out of release binaries. Hashes use
    // the same little-endian HashToHex form as compiled checkpoints.
    static std::unordered_map<uint64_t, std::string>& TestCheckpointOverlay() {
        static std::unordered_map<uint64_t, std::string> overlay;
        return overlay;
    }
    static void TestInjectCheckpoint(uint64_t height, const std::string& le_hex) {
        TestCheckpointOverlay()[height] = le_hex;
    }
    static void TestClearCheckpoints() { TestCheckpointOverlay().clear(); }

    // Focused protocol-settlement sentinel seam.  Lets an isolated gate test
    // install an exact stake-vault / bond-yield-escrow UTXO without constructing
    // hundreds of unrelated blocks.  Compiled out of every public binary by the
    // VELD_TEST_HOOKS production interlock.
    void TestInjectUTXO(const UTXO& utxo) {
        std::unique_lock<std::shared_mutex> lock(chain_mutex_);
        InsertUTXO(utxo);
    }
    bool TestEraseUTXO(const Hash256& tx_hash, uint32_t index) {
        std::unique_lock<std::shared_mutex> lock(chain_mutex_);
        return EraseUTXO(tx_hash, index);
    }
    void TestForceNextRebuildUTXOMiss() {
        test_force_rebuild_utxo_miss_.store(true,
                                            std::memory_order_release);
    }
    bool TestRebuildUTXOSetFromTip(const Hash256& tip_hash) {
        std::unique_lock<std::shared_mutex> lock(chain_mutex_);
        return RebuildUTXOSet(HashToHex(tip_hash));
    }
#endif

    // Every checkpoint pin visible to this build: the compiled-in map plus,
    // under VELD_TEST_HOOKS only, the test overlay. LE/HashToHex hex form.
    static std::vector<std::pair<uint64_t, std::string>> AllCheckpointPins() {
        std::vector<std::pair<uint64_t, std::string>> pins;
        for (const auto& kv : GetCheckpoints()) pins.push_back(kv);
#ifdef VELD_TEST_HOOKS
        for (const auto& kv : TestCheckpointOverlay()) pins.push_back(kv);
#endif
        return pins;
    }

    static bool PassesCheckpoint(uint64_t height, const Hash256& hash) {
#ifdef VELD_TEST_HOOKS
        {
            const auto& ov = TestCheckpointOverlay();
            auto ovit = ov.find(height);
            if (ovit != ov.end()) return HashToHex(hash) == ovit->second;
        }
#endif
        const auto& cp = GetCheckpoints();
        auto it = cp.find(height);
        if (it == cp.end()) return true;
        return HashToHex(hash) == it->second;
    }

    // assumeUTXO anchor: verify an
    // ALREADY-LOADED chain against every checkpoint pin at or below its tip.
    // The per-block ingest/VBFR gates stop a pinned-height mismatch from
    // ENTERING the chain; this is the complementary whole-chain verdict for
    // state restored OUTSIDE live ingest ordering (disk replay / snapshot
    // bootstrap — see ReplayChain's pre-replay sweep in node.h) and for the
    // test overlay. Pins above the tip are not yet verifiable and pass
    // vacuously.
    bool VerifyCheckpointAnchors(uint64_t* bad_height = nullptr,
                                 std::string* stored_hex = nullptr,
                                 std::string* pinned_hex = nullptr) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        for (const auto& [cp_h, cp_hex] : AllCheckpointPins()) {
            if (cp_h >= chain_.size()) continue;
            std::string got = HashToHex(chain_[cp_h].GetHash());
            if (got == cp_hex) continue;
            if (bad_height) *bad_height = cp_h;
            if (stored_hex) *stored_hex = got;
            if (pinned_hex) *pinned_hex = cp_hex;
            return false;
        }
        return true;
    }

    static bool IsFinalityCoinbaseMetadata(const TxOutput& out) {
        if (out.value != 0) return false;
        const std::string payload =
            ::veld::MarkerOpReturnPayload(out.script_pubkey);
        return payload.rfind("VELD_FINALITY|", 0) == 0 &&
               ::veld::IsCanonicalMarkerOpReturn(out.script_pubkey, payload);
    }

    static bool ValidateCoinbaseOutputs(const Block& block) {
        if (block.transactions.empty()) return false;
        const auto& cb = block.transactions[0];
        if (!cb.IsCoinbase()) return false;
        if (cb.outputs.empty()) return false;

        size_t finality_metadata_count = 0;
        for (const auto& out : cb.outputs)
            if (IsFinalityCoinbaseMetadata(out)) ++finality_metadata_count;
        if (finality_metadata_count > MAX_FINALITY_MARKER_OUTPUTS) return false;

        uint64_t total_out   = cb.TotalOutput();
        if (total_out == 0) {
            if (cb.outputs.size() == 1 &&
                cb.outputs[0].script_pubkey ==
                    std::vector<uint8_t>({0x6A, 0x00})) return true;
            return !cb.outputs.empty() &&
                   finality_metadata_count == cb.outputs.size();
        }
        uint64_t vault_floor = (total_out * 10) / 100;
        auto     vault_script = AddressToScript(VaultAddressAtHeight(block.height));

        bool is_vault_block = (block.height > 0 && block.height % VAULT_BLOCK_INTERVAL == 0);
        if (is_vault_block) {
            uint64_t vault_received = 0;
            auto endorse_script = AddressToScript(ENDORSEMENT_POOL_ADDRESS);
            for (const auto& out : cb.outputs) {
                if (IsFinalityCoinbaseMetadata(out)) continue;
                if (out.script_pubkey == vault_script) vault_received += out.value;
                else if (!endorse_script.empty() && out.script_pubkey == endorse_script) {
                } else {
                    return false;
                }
            }
            if (vault_received < (total_out * 80) / 100) return false;
            return true;
        }

        uint64_t vault_received = 0;
        uint64_t max_single_out = 0;
        for (const auto& out : cb.outputs) {
            if (IsFinalityCoinbaseMetadata(out)) continue;
            if (out.script_pubkey == vault_script)
                vault_received += out.value;
            else
                max_single_out = std::max(max_single_out, out.value);
        }

        if (vault_received < vault_floor) return false;

        uint64_t winner_cap = total_out - vault_floor + 1;
        if (max_single_out > winner_cap) return false;

        return true;
    }

    // External transactions may not create spendable fragments at the four
    // protocol-only custody scripts.  Those scripts have no private-key spend
    // path: their complete UTXO sets are consumed by one canonical settlement,
    // so arbitrary deposits would let a cheap dust spray push that mandatory
    // transaction beyond MAX_TRANSACTION_INPUTS.  STAKE_VAULT is the sole
    // exception because a validator REGISTER deliberately funds it.  Require
    // one exact REGISTER marker, one bond-sized output, and leave the registry's
    // existing signature/state checks to decide whether the registration
    // itself applies.
    static bool ValidateExternalProtocolCustodyOutputs(
        const Transaction& tx, uint64_t height) {
        const auto pool_script =
            AddressToScript(PoolAddressAtHeight(height));
        const auto endorse_script =
            AddressToScript(EndorsementPoolAddressAtHeight(height));
        const auto vault_script =
            AddressToScript(VaultAddressAtHeight(height));
        const auto stake_vault_script =
            AddressToScript(StakeVaultAddressAtHeight(height));
        const auto bond_yield_script =
            AddressToScript(BondYieldEscrowAtHeight(height));
        if (pool_script.empty() || endorse_script.empty() ||
            vault_script.empty() || stake_vault_script.empty() ||
            bond_yield_script.empty()) return false;

        size_t stake_vault_outputs = 0;
        for (const auto& out : tx.outputs) {
            if (out.script_pubkey == pool_script ||
                out.script_pubkey == endorse_script ||
                out.script_pubkey == vault_script ||
                out.script_pubkey == bond_yield_script) {
                return false;
            }
            if (out.script_pubkey == stake_vault_script) {
                ++stake_vault_outputs;
                if (stake_vault_outputs > 1 ||
                    out.value < MIN_VALIDATOR_STAKE) return false;
            }
        }
        if (stake_vault_outputs == 0) return true;

        auto decode_canonical_op_return =
            [](const std::vector<uint8_t>& script,
               std::string& payload) -> bool {
                if (script.size() < 2 || script[0] != 0x6A) return false;
                size_t off = 1, len = 0;
                const uint8_t op = script[off++];
                if (op <= 75) {
                    len = op;
                } else if (op == 0x4C) {
                    if (off >= script.size()) return false;
                    len = script[off++];
                    if (len <= 75) return false; // non-minimal PUSHDATA1
                } else if (op == 0x4D) {
                    if (off + 2 > script.size()) return false;
                    len = (size_t)script[off] |
                          ((size_t)script[off + 1] << 8);
                    off += 2;
                    if (len <= 0xFF) return false; // non-minimal PUSHDATA2
                } else {
                    return false;
                }
                if (off + len != script.size()) return false;
                payload.assign(script.begin() + off, script.end());
                return true;
            };

        static const std::string REGISTER_PREFIX =
            "VELD_VALIDATOR|REGISTER|";
        size_t canonical_registers = 0;
        for (const auto& out : tx.outputs) {
            std::string payload;
            if (!decode_canonical_op_return(out.script_pubkey, payload))
                continue;
            if (payload.rfind(REGISTER_PREFIX, 0) != 0) continue;
            if (payload.size() != REGISTER_PREFIX.size() + 3904)
                return false;
            for (size_t i = REGISTER_PREFIX.size(); i < payload.size(); ++i) {
                const char c = payload[i];
                if (!((c >= '0' && c <= '9') ||
                      (c >= 'a' && c <= 'f'))) return false;
            }
            if (++canonical_registers > 1) return false;
        }
        return canonical_registers == 1;
    }

    // Caller holds chain_mutex_.  A transaction that consumes a protocol
    // custody UTXO is allowed to create the exact roll-forward/output set
    // derived by ValidateExpected* below.  Every other transaction is subject
    // to the external-funding rule above.  Also keep the stake-vault's projected
    // UTXO set representable in one canonical settlement in every build tier.
    bool ValidateProtocolCustodyFunding(const Block& block) const {
        if (block.height == 0) return true;
        const auto pool_script =
            AddressToScript(PoolAddressAtHeight(block.height));
        const auto endorse_script =
            AddressToScript(EndorsementPoolAddressAtHeight(block.height));
        const auto vault_script =
            AddressToScript(VaultAddressAtHeight(block.height));
        const auto stake_vault_script =
            AddressToScript(StakeVaultAddressAtHeight(block.height));
        const auto bond_yield_script =
            AddressToScript(BondYieldEscrowAtHeight(block.height));
        if (pool_script.empty() || endorse_script.empty() ||
            vault_script.empty() || stake_vault_script.empty() ||
            bond_yield_script.empty()) return false;

        auto is_reserved = [&](const std::vector<uint8_t>& script) {
            return script == pool_script || script == endorse_script ||
                   script == vault_script || script == stake_vault_script ||
                   script == bond_yield_script;
        };

        const auto stake_utxos =
            GetUTXOsForScriptLocked_(stake_vault_script);
        std::unordered_set<std::string> spent_stake_utxos;
        size_t created_stake_outputs = 0;

        for (size_t ti = 1; ti < block.transactions.size(); ++ti) {
            const auto& tx = block.transactions[ti];
            bool spends_reserved = false;
            for (const auto& input : tx.inputs) {
                auto utxo = GetUTXONoLock(input.prev_tx_hash,
                                          input.prev_out_index);
                if (!utxo) continue;
                if (is_reserved(utxo->script_pubkey))
                    spends_reserved = true;
                if (utxo->script_pubkey == stake_vault_script) {
                    spent_stake_utxos.insert(
                        UTXOKey(input.prev_tx_hash, input.prev_out_index));
                }
            }
            for (const auto& out : tx.outputs) {
                if (out.script_pubkey == stake_vault_script)
                    ++created_stake_outputs;
            }
            if (!spends_reserved &&
                !ValidateExternalProtocolCustodyOutputs(tx, block.height))
                return false;
        }

        if (spent_stake_utxos.size() > stake_utxos.size()) return false;
        const size_t projected_stake_utxos =
            stake_utxos.size() - spent_stake_utxos.size() +
            created_stake_outputs;
        return projected_stake_utxos <= MAX_TRANSACTION_INPUTS;
    }

    bool ValidateCanonicalCoinbaseSplit(const Block& block) const {
#ifndef VELD_MAINNET_POW
        (void)block;
        return true;
#else
        if (block.height == 0) return true;
        if (block.transactions.empty()) return false;
        const auto& cb = block.transactions[0];
        if (!cb.IsCoinbase()) return false;

        const uint64_t base_reward = ExpectedBlockSubsidy(block.height);
        const uint64_t total_supply_at_parent = total_supply_units_.load();
        const uint64_t remaining_to_cap =
            (MAX_SUPPLY_UNITS > total_supply_at_parent)
                ? (MAX_SUPPLY_UNITS - total_supply_at_parent) : 0;
        const uint64_t effective_reward = std::min(base_reward, remaining_to_cap);

        const uint64_t total_out = cb.TotalOutput();
        if (total_out < effective_reward) return false;

        uint64_t actual_tx_fees   = 0;
        bool     all_utxos_resolved = true;
        for (size_t ti = 1; ti < block.transactions.size(); ++ti) {
            const auto& tx = block.transactions[ti];
            if (tx.IsCoinbase()) continue;
            uint64_t tx_in = 0;
            const uint64_t tx_out = tx.TotalOutput();
            bool this_tx_resolved = true;
            for (const auto& inp : tx.inputs) {
                if (inp.IsCoinbase()) continue;
                auto utxo = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
                if (utxo) {
                    tx_in += utxo->value;
                } else {
                    this_tx_resolved   = false;
                    all_utxos_resolved = false;
                    break;
                }
            }
            if (this_tx_resolved && tx_in > tx_out)
                actual_tx_fees += (tx_in - tx_out);
        }

        // the permissive branch let a SINGLE
        // unresolvable input drop the emission equality check for the whole
        // block, after which the coinbase declared its own fee total — the
        // remaining checks only verify split RATIOS, which an attacker
        // satisfies trivially. Fail closed instead. This costs nothing on
        // honest blocks: ValidateTransaction already requires every non-
        // coinbase input to resolve against the UTXO set (it compares
        // utxo_opt->script_pubkey), so any input unresolvable here belongs to a
        // transaction the per-tx validator rejects regardless.
        if (!all_utxos_resolved) return false;
        const uint64_t tx_fees = actual_tx_fees;
        if (total_out != effective_reward + actual_tx_fees) return false;

        const auto vault_script =
            AddressToScript(VaultAddressAtHeight(block.height));
        const auto pool_script =
            AddressToScript(PoolAddressAtHeight(block.height));
        const auto endorse_script =
            AddressToScript(EndorsementPoolAddressAtHeight(block.height));
        const auto stake_vault_script =
            AddressToScript(StakeVaultAddressAtHeight(block.height));
        const auto bond_yield_script =
            AddressToScript(BondYieldEscrowAtHeight(block.height));
        if (vault_script.empty() || pool_script.empty() ||
            endorse_script.empty() || stake_vault_script.empty() ||
            bond_yield_script.empty()) {
            throw std::runtime_error(
                "FATAL: AddressToScript() returned empty in "
                "ValidateCanonicalCoinbaseSplit — a protocol custody "
                "address constant is corrupt or base58 decode is broken.");
        }
        if (vault_script == pool_script || vault_script == endorse_script
                || pool_script == endorse_script) {
            throw std::runtime_error(
                "FATAL: protocol-address scripts collide in "
                "ValidateCanonicalCoinbaseSplit — constants.h has two "
                "distinct address constants decoding to the same script.");
        }

        // The supply-cap era can legitimately have neither subsidy nor fees.
        // Its sole canonical output is the zero-value OP_RETURN shape already
        // required by ValidateCoinbaseOutputs; it is not a miner payout.
        if (total_out == 0) {
            if (cb.outputs.size() == 1 &&
                cb.outputs[0].script_pubkey ==
                    std::vector<uint8_t>({0x6A, 0x00})) return true;
            size_t metadata = 0;
            for (const auto& out : cb.outputs)
                if (IsFinalityCoinbaseMetadata(out)) ++metadata;
            return !cb.outputs.empty() &&
                   metadata == cb.outputs.size() &&
                   metadata <= MAX_FINALITY_MARKER_OUTPUTS;
        }

        size_t finality_metadata_count = 0;
        for (const auto& out : cb.outputs)
            if (IsFinalityCoinbaseMetadata(out)) ++finality_metadata_count;
        if (finality_metadata_count > MAX_FINALITY_MARKER_OUTPUTS) return false;

        uint64_t sum_vault = 0, sum_pool = 0, sum_endorse = 0, sum_other = 0;
        size_t count_vault = 0, count_pool = 0, count_endorse = 0,
               count_other = 0;
        bool other_is_canonical_p2pkh = true;
        for (const auto& out : cb.outputs) {
            if (IsFinalityCoinbaseMetadata(out)) continue;
            if (out.script_pubkey == stake_vault_script ||
                out.script_pubkey == bond_yield_script) return false;
            if (out.script_pubkey == vault_script) {
                ++count_vault; sum_vault += out.value;
            } else if (out.script_pubkey == pool_script) {
                ++count_pool; sum_pool += out.value;
            } else if (out.script_pubkey == endorse_script) {
                ++count_endorse; sum_endorse += out.value;
            } else {
                ++count_other;
                sum_other += out.value;
                const auto& s = out.script_pubkey;
                other_is_canonical_p2pkh = other_is_canonical_p2pkh &&
                    s.size() == 25 && s[0] == 0x76 && s[1] == 0xA9 &&
                    s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xAC;
            }
        }

        uint64_t exp_pool, exp_vault, exp_endorse, exp_miner;
        const bool is_pre_activation =
            (total_supply_at_parent < STAKING_UNLOCK_SUPPLY);

        if (effective_reward == 0) {
            const uint64_t v = (tx_fees * 40) / 100;
            const uint64_t e = (tx_fees * 10) / 100;
            const uint64_t m = tx_fees - v - e;
            exp_pool    = 0;
            exp_vault   = v;
            exp_endorse = e;
            exp_miner   = m;
        } else if (block.height > 0 &&
                   (block.height % VAULT_BLOCK_INTERVAL) == 0) {
            // every VAULT_BLOCK_INTERVAL-th block routes
            // the ENTIRE reward to the vault, ALWAYS — this MUST be checked BEFORE
            // is_pre_activation. The miner (node.h) and ValidateCoinbaseOutputs both
            // build and require the all-to-vault output before evaluating the
            // pre-activation branch.
            exp_pool    = 0;
            exp_vault   = effective_reward + tx_fees;
            exp_endorse = 0;
            exp_miner   = 0;
        } else if (is_pre_activation) {
            const uint64_t m = (effective_reward * 50) / 100;
            const uint64_t v = effective_reward - m;
            exp_pool    = 0;
            exp_vault   = v + tx_fees;
            exp_endorse = 0;
            exp_miner   = m;
        } else {
            const uint64_t p = (effective_reward * 20) / 100;
            const uint64_t v = (effective_reward * 20) / 100;
            const uint64_t e = (effective_reward * 10) / 100;
            const uint64_t m = effective_reward - p - v - e;
            exp_pool    = p;
            exp_vault   = v + tx_fees;
            exp_endorse = e;
            exp_miner   = m;
        }

        if (sum_pool    != exp_pool)    return false;
        if (sum_vault   != exp_vault)   return false;
        if (sum_endorse != exp_endorse) return false;
        if (sum_other   != exp_miner)   return false;
        // Category sums alone are insufficient: splitting a custody leg into
        // hundreds of outputs per block makes the next all-input settlement
        // structurally impossible even though every reward unit is conserved.
        if (count_pool != (exp_pool > 0 ? 1u : 0u)) return false;
        if (count_vault != (exp_vault > 0 ? 1u : 0u)) return false;
        if (count_endorse != (exp_endorse > 0 ? 1u : 0u)) return false;
        // One block earns one miner identity credit.  Category-sum validation
        // alone allowed the winner share to be split over as many as 197 fresh
        // P2PKH scripts, multiplying tier credits and growing both miner maps
        // at attacker-selected cardinality.  Every canonical builder already
        // emits exactly one P2PKH winner leg (or none when exp_miner is zero).
        if (count_other != (exp_miner > 0 ? 1u : 0u)) return false;
        if (exp_miner > 0 && !other_is_canonical_p2pkh) return false;
        return true;
#endif
    }

    // AddBlockDirect: verifies VeldHash PoW before committing.
    // Handles both main-chain extensions and fork blocks.
    // If a fork has more cumulative work than our tip, triggers a reorg.
    //
    //  Hardening. This function
    // is the SOLE, AUTHORITATIVE proof-of-work gate for every block that
    // enters the chain. The former `pow_already_verified` parameter let the
    // P2P BLOCK handler claim it had already PoW-verified an inbound block so
    // the VeldHash call here could be elided — but the handler's check was
    // dead: it gated on Block::height, which is 0 for every just-deserialized
    // wire block (Block::Deserialize never sets height), so VerifyBlockPoW was
    // never called on the peer path, and AddBlockDirect then trusted the false
    // "already verified" claim and skipped it too. Net: PoW was verified
    // NOWHERE on the dominant peer tip-extend path — a peer could append
    // zero-work blocks at the network difficulty, take all rewards, and reorg
    // to double-spend. The parameter is RETIRED: PoW is verified HERE whenever
    // !skip_pow, using the chain-derived height (correct VeldHash epoch), for
    // both extends-tip and alt blocks. NEVER reintroduce a caller-supplied
    // "already verified" shortcut on a consensus gate — that is exactly what
    // created the hole. `skip_pow` remains the trusted-replay path (loadchain /
    // pre-checkpoint IBD) where validity was already persisted; it elides PoW
    // and contextual coinbase reward/split, NMS, pool-payout, and endorsement
    // gates. Context-free transaction structure and the exactly-one-coinbase
    // invariant are still enforced unconditionally below.
    BlockAdmissionResult AddBlockDirect(
                        const Block& block,
                        bool skip_pow = false,
                        bool skip_scripts = false,
                        bool skip_pow_hash_only = false,
                        mining::PowAdmissionContext pow_admission = {}) {
        // Phase 1 of local-work admission is intentionally before both the
        // connect sequencer and chain_mutex_.  The node may sample peer height,
        // IBD, startup, role, and coordinator state here.  Only the immutable
        // one-use result crosses into canonical precommit.
        std::optional<LocalWorkAdmissionTicket> local_work_ticket;
        const bool local_work_required =
            pow_admission.RequiresLocalWorkAdmission();
        if (local_work_required && pow_admission.HasRequiredProvenance()) {
            LocalWorkAdmissionPrepareFn prepare;
            {
                std::lock_guard<std::mutex> lock(
                    local_work_admission_prepare_mutex_);
                prepare = local_work_admission_prepare_fn_;
            }
            if (prepare) {
                try {
                    local_work_ticket = prepare(block, pow_admission);
                } catch (...) {
                    local_work_ticket.reset();
                }
            }
        }
#ifdef VELD_TEST_HOOKS
        test_add_block_direct_calls_.fetch_add(1, std::memory_order_acq_rel);
#endif
#if defined(VELD_PUBLIC_RELEASE)
        // The narrow snapshot path may omit only the expensive historical
        // VeldHash comparison. It must never combine with the broad trusted
        // replay mode, which also suppresses contextual consensus checks.
        if (skip_pow && skip_pow_hash_only)
            throw std::logic_error("conflicting PoW replay modes");
#endif
        // Serialize the validation->preflight->canonical commit->persistence
        // lifecycle. chain_mutex_ is deliberately released around on_commit_,
        // so without this outer sequencer a second thread could publish the next
        // tip while the first block's module/persistence callback was still in
        // flight; a failure rollback could then disconnect the wrong block.
        std::lock_guard<std::mutex> connect_guard(block_connect_mutex_);
        struct LocalHandoffReset {
            std::shared_ptr<mining::LocalWorkLeaseHandoff> handoff;
            bool retain{false};
            ~LocalHandoffReset() {
                if (!retain && handoff) handoff->Reset();
            }
        } local_handoff_reset{pow_admission.local_work_handoff};
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        auto reject = [&](const char* tag) {
            last_reject_tag_ = tag;
            static std::mutex reject_counter_mu;
            static std::unordered_map<std::string, uint64_t> reject_counters;
            static int64_t last_summary_unix = 0;
            static std::unordered_map<std::string, uint64_t> last_summary_baseline;
            const std::string tag_str(tag);
            const bool suppressed =
                tag_str == "duplicate_block" ||
                tag_str == "orphan_parent_unknown" ||
                tag_str == "pow_orphan_parent_unknown" ||
                tag_str == "orphan_lwma_window_pending" ||
                tag_str == "local_validation_ceiling" ||
                tag_str == "side_branch_capacity" ||
                tag_str == "coinbase_exceeds_subsidy_cap" ||
                tag_str == "nms_validation_failed" ||
                tag_str == "bits_mismatch_lwma" ||
                // F-4: a dataset-regeneration storm can emit this for every
                // in-flight block; roll it into the 5-minute summary rather
                // than one stderr line per attempt.
                tag_str == "pow_dataset_unavailable" ||
                tag_str == "consensus_pool_payout_mismatch";
            if (suppressed) {
                if (veld::DiagVerbose().load()) {
                    std::lock_guard<std::mutex> g(reject_counter_mu);
                    reject_counters[tag_str] += 1;
                    int64_t now_unix = (int64_t)std::time(nullptr);
                    if (last_summary_unix == 0) last_summary_unix = now_unix;
                    if (now_unix - last_summary_unix >= 300) {
                        std::cerr << "  [block-rejects 5m]";
                        for (auto& [t, n] : reject_counters) {
                            uint64_t baseline = last_summary_baseline[t];
                            uint64_t delta = n - baseline;
                            if (delta > 0) std::cerr << " " << t << "=" << delta;
                            last_summary_baseline[t] = n;
                        }
                        std::cerr << "\n";
                        std::cerr.flush();
                        last_summary_unix = now_unix;
                    }
                }
            } else {
                std::cerr << "  [AddBlock reject h=" << block.height
                          << " hash=" << HashToHex(block.GetHash()).substr(0, 16) << "..."
                          << " prev=" << HashToHex(block.header.prev_block_hash).substr(0, 16) << "..."
                          << "] " << tag << "\n";
                std::cerr.flush();
            }
            return BlockAdmissionResult::ConsensusInvalid();
        };
        auto defer = [&](const char* tag) {
            last_reject_tag_ = tag;
            return BlockAdmissionResult::DeferredLocalWork();
        };

        // Every entry point, including trusted replay, must identify its
        // provenance explicitly.  The default context is intentionally
        // unwired so a new caller cannot silently inherit RPC privileges.
        if (!pow_admission.HasRequiredProvenance())
            return reject("pow_admission_context_unavailable");
        if (local_work_required &&
            (!local_work_ticket || !*local_work_ticket))
            return defer("local_work_ticket_prepare_refused");

        // A rollback/compensation failure means the in-memory canonical frame
        // can no longer be proven equivalent to the durable frame.  Continuing
        // to accept blocks would build on ambiguous state and may overwrite the
        // evidence needed for startup recovery.  This latch is deliberately
        // process-lifetime: a clean restart/replay is the only way to clear it.
        if (durability_compromised_.load(std::memory_order_acquire))
            return reject("durability_compromised_restart_required");
        if (block.transactions.empty()) return reject("empty_transactions");
        if (block.transactions.size() > MAX_TRANSACTIONS_PER_BLOCK)
            return reject("too_many_txs");
        if (!block.transactions[0].IsCoinbase()) return reject("tx0_not_coinbase");

        // Context-free transaction structure is consensus and is cheap enough
        // to enforce before every ingest fast path.  In particular this covers
        // tx0: IsCoinbase() only identifies its null outpoint and does not bound
        // its scriptSig, require an output, or enforce output/script limits.
        // Keeping this outside !skip_pow / !skip_scripts means local mining,
        // peer ingest, side-branch registration, and trusted startup replay all
        // accept exactly the same transaction envelope.
        for (size_t i = 0; i < block.transactions.size(); ++i) {
            if (i > 0 && block.transactions[i].IsCoinbase())
                return reject("extra_coinbase");
            if (!block.transactions[i].IsValid()) {
                return reject(i == 0 ? "coinbase_basic_invalid"
                                     : "transaction_basic_invalid");
            }
        }

        // MAX_BLOCK_SIZE is the complete canonical wire size.  Counting only
        // transaction bytes created a 92-byte local/P2P/RPC boundary mismatch:
        // an in-process miner could commit `MAX_BLOCK_SIZE + 92` bytes while
        // strict wire ingress rejected the same block.  Enforce this cheap
        // structural gate before the memory-hard PoW verification.
        if (block.SerializedSize() > (size_t)MAX_BLOCK_SIZE)
            return reject("block_too_large");

        // Body commitments are cheap relative to VeldHash and independent of
        // chain state.  Reject a forged/mismatched body before the memory-hard
        // proof check; previously any peer could vary a known parent header and
        // force VeldHash even when the Merkle root was trivially wrong.
        if (ComputeMerkleRoot(block.transactions) != block.header.merkle_root)
            return reject("merkle_mismatch");

        // ── GENESIS-IMMUTABILITY GUARD (anti-adoption) ──────────────────────
        // The ONLY block whose prev_block_hash is zero is a genesis. Our genesis
        // is constructed locally (block.h CreateGenesis, pinned + self-checked)
        // and is IMMUTABLE. We must never ingest a peer's genesis. Without this
        // guard, a fresh/short node connected to a peer whose chain has a
        // DIFFERENT genesis ingests that foreign genesis as block 0, the foreign
        // chain (greater cumulative work) wins the cumulative-work reorg, and the
        // node SILENTLY ADOPTS a foreign chain — the exact mechanism by which a
        // node carrying genesis A was observed to take on a peer's genesis-B
        // chain. Reject any zero-prev block that is not byte-identical to our own
        // genesis. Legitimate sync never delivers block 0 to a node that already
        // has it, and a reorg shares the genesis as its common ancestor, so this
        // never rejects a valid block. (chain_.size()==0 only at pre-network init
        // when the local genesis is first installed — allowed through.)
        if (HashIsZero(block.header.prev_block_hash)) {
            // Compare against the binary's OWN computed genesis (not chain_[0],
            // which is empty in the fresh-sync window where the foreign genesis
            // actually lands). CreateGenesisBlock() is the immutable, pinned +
            // self-checked genesis this binary was built for. Any zero-prev
            // block that isn't byte-identical to it is a foreign genesis and is
            // refused — closing adoption whether chain_ is empty or not. Our own
            // genesis passes through (init installs it; a duplicate delivery is
            // caught by the block_store_ duplicate-hash check downstream).
            static const std::string LOCAL_GENESIS_HEX =
                HashToHex(CreateGenesisBlock().GetHash());
            if (HashToHex(block.GetHash()) != LOCAL_GENESIS_HEX)
                return reject("foreign_genesis");
        }

        // Block::Serialize/Deserialize does not include `block.height` on
        // the wire — by design, `// height must be set by the caller based
        // on chain context.` But every receive-side validation in this
        // function used `block.height` BEFORE we derived it from the
        // parent's height. For wire-received blocks, block.height defaults
        // to 0; ExpectedBlockSubsidy(0) returns the genesis-only subsidy;
        // the coinbase_cap validation at the next block of `if (cb_total >
        // max_legal)` then trivially fails (cb_total = ~1.9 VELD subsidy >
        // genesis-tier cap), and the block is rejected with
        // `coinbase_exceeds_subsidy_cap`. The reject is technically correct
        // but the *wrong reason* — the block was an orphan to us, not a
        // miner cheating on the cap.
        //
        // The downstream effect: at every natural fork (two miners mine
        // the same height simultaneously), the lagging fleet hosts receive
        // the alt-chain's child block as `prev=alt-block` (which they
        // don't have on main), classify it as orphan-by-deserialize, hit
        // the misordered cap check, and reject. The rejected_blocks_ set
        // remembers the hash; subsequent re-broadcasts of that same block
        // (during reorg attempts) are silent-dropped. The cumulative-work
        // tiebreaker NEVER gets a chance to fire because the block never
        // makes it into the alt-chain block_tree_.
        //
        // Symptom seen : a fresh fork at h=418 leaves vultr-node3
        // permanently on its own chain. node1 + vultr-node2 + personal
        // mine the lex-tiebreaker-winning side and converge, but
        // vultr-node3 silently rejects the chain A blocks at h=419+ with
        // `coinbase_exceeds_subsidy_cap` and stays on its private chain B.
        //
        // Derive height from the parent first. If the parent is unknown,
        // reject with `orphan_parent_unknown` so the orphan
        // pool / re-fetch path engages correctly. Otherwise use
        // `effective_height` for all subsequent height-dependent checks.
        // Subsequent code that reads `block.height` is left in place
        // because the variable now refers to the same value (we set
        // block.height via const_cast — see the PRECONDITION below). The
        // mutation is load-bearing: callers read block.height post-return
        // (e.g. the peer handler's canonical verified-height evidence), so it
        // cannot be moved to a local copy.
        //
        //  CONCURRENCY PRECONDITION:
        // because this const_cast WRITES block.height, the CALLER MUST own
        // `block` EXCLUSIVELY for the duration of the call — never hand one
        // Block object to two concurrent AddBlockDirect calls. Every real
        // caller satisfies this: each ingest path (peer handler, event-loop
        // BlockIngestWorker, orphan re-apply, RPC submitblock, startup replay)
        // deserializes / holds its OWN Block, and the orphan pool is
        // mutex-serialized. TSan otherwise found NO race on the shared
        // consensus state (chain_ / utxo_set_ / block_tree_ / registries)
        // across concurrent ingest + reorg + reads — the lock graph is sound;
        // the only write it flagged was this height field, and only when the
        // (deliberately unrealistic) harness shared a single Block across
        // threads.
        // Names chosen to match the original block at line ~2310 below
        // (which we leave in place but turned into an assertion — the
        // values cannot change between the two computations).
        uint64_t derived_height = 0;
        bool     parent_known   = false;
        {
            std::string prev_hex = HashToHex(block.header.prev_block_hash);
            auto pit_h = block_tree_.find(prev_hex);
            if (pit_h != block_tree_.end()) {
                derived_height = pit_h->second.height + 1;
                parent_known = true;
            } else if (HashIsZero(block.header.prev_block_hash)) {
                derived_height = 0;
                parent_known   = true;
            }
        }
        if (!parent_known) {
            if (veld::DiagVerbose().load()) {
                static std::mutex orphan_diag_mu;
                static std::unordered_map<std::string, int64_t> last_log_for_prev;
                std::string prev_hex_diag = HashToHex(block.header.prev_block_hash);
                int64_t now_unix = (int64_t)std::time(nullptr);
                bool emit = false;
                {
                    std::lock_guard<std::mutex> g(orphan_diag_mu);
                    auto it = last_log_for_prev.find(prev_hex_diag);
                    if (it == last_log_for_prev.end() ||
                        (now_unix - it->second) >= 60) {
                        last_log_for_prev[prev_hex_diag] = now_unix;
                        emit = true;
                        if (last_log_for_prev.size() > 1024) {
                            last_log_for_prev.clear();
                        }
                    }
                }
                if (emit) {
                    bool in_block_index = (block_index_.find(prev_hex_diag) != block_index_.end());
                    std::string blk_hash = HashToHex(block.GetHash()).substr(0, 16);
                    std::cerr << "  [sync-buffer] block=" << blk_hash << "..."
                              << " missing_prev=" << prev_hex_diag.substr(0, 16) << "..."
                              << " in_block_index=" << (in_block_index ? "YES" : "no")
                              << " block_tree_size=" << block_tree_.size()
                              << " block_index_size=" << block_index_.size()
                              << " chain_size=" << chain_.size()
                              << (in_block_index
                                    ? " index_mismatch=YES"
                                    : " parent_pending_or_out_of_order=yes")
                              << "\n";
                    std::cerr.flush();
                }
            }
            return reject("orphan_parent_unknown");
        }
        const_cast<Block&>(block).height = derived_height;
        const uint64_t local_ceiling =
            local_validation_ceiling_.load(std::memory_order_acquire);
        if (local_ceiling != 0 && derived_height > local_ceiling)
            return reject("local_validation_ceiling");
        if (!RuntimeAdmissionPermits(derived_height)) {
            return reject("runtime_admission_closed");
        }

        //  ALT-CHAIN AWARENESS — skip UTXO-dependent validation
        // when this block is an alt-chain candidate, NOT extending our
        // current main-chain tip. The fees-headroom calc reads from the
        // CURRENT utxo_set_ (which reflects main-chain state at our tip).
        // For alt-chain blocks, that's the wrong UTXO context — inputs
        // they reference may have been double-spent on main, producing
        // false rejects (`coinbase_exceeds_subsidy_cap` for legitimate
        // alt-chain blocks during fork-resolve).
        //
        // Defer all UTXO-dependent validation (coinbase cap, miner caps,
        // pool/endorsement payouts, NMS bond) to `Reorganize()`'s block-
        // apply path, where `RebuildUTXOSet` first rebuilds the correct
        // alt-chain UTXO state. Alt-chain blocks still go through PoW,
        // timestamp, bits-LWMA, structural, and parent-known checks
        // here — those don't depend on current UTXO state.
        //
        // Detection: parent IS known (not orphan) AND parent is NOT our
        // tip (so this would form an alt-chain branch). Genesis path
        // (chain_ empty) extends "tip" trivially, so `is_alt_chain` is
        // false there.
        bool is_alt_chain = parent_known
                          && !chain_.empty()
                          && !(block.header.prev_block_hash == chain_.back().GetHash());
        const std::string bhash = HashToHex(block.GetHash());
        bool known_side_retry = false;

        std::optional<PowParentContext> pow_parent_context;
        CanonicalPowTarget submitted_target;
        if (!skip_pow) {
            CompactTargetError target_error = CompactTargetError::None;
            if (!DecodeCanonicalVeldTarget(
                    block.header.bits, submitted_target, &target_error)) {
                switch (target_error) {
                    case CompactTargetError::Negative:
                        return reject("pow_target_negative");
                    case CompactTargetError::Zero:
                        return reject("pow_target_zero");
                    case CompactTargetError::Overflow:
                        return reject("pow_target_overflow");
                    case CompactTargetError::AboveLimit:
                        return reject("pow_target_above_limit");
                    case CompactTargetError::NonCanonical:
                        return reject("pow_target_noncanonical");
                    case CompactTargetError::None: break;
                }
                return reject("pow_target_noncanonical");
            }
            if (derived_height > 0) {
                PowParentContext context;
                if (!BuildPowParentContextNoLock_(
                        block.header.prev_block_hash, context) ||
                    context.candidate_height != derived_height)
                    return reject("pow_branch_context_unavailable");
                if (block.header.bits != context.expected_bits)
                    return reject("bits_mismatch_lwma");
                if (block.header.timestamp <= context.median_time_past)
                    return reject("timestamp_before_branch_mtp");
                if (submitted_target.bits != context.expected_target.bits)
                    return reject("pow_target_context_mismatch");
                pow_parent_context = context;
            }
        }

        // Fresh-genesis custody-fragmentation interlock.  This needs the
        // candidate parent's UTXO view, so side branches defer it to VBFR after
        // their parent frame is reconstructed.  Linear ingress and trusted
        // replay both enforce it here.
        if (!is_alt_chain && derived_height > 0 &&
            !ValidateProtocolCustodyFunding(block))
            return reject("protocol_custody_funding_invalid");

        // Enforce fixed subsidy plus transaction fees on first ingress.
        // Side branches are checked after their parent UTXO frame is rebuilt;
        // trusted replay only consumes blocks that passed this check before
        // being committed.
        if (!is_alt_chain && !skip_pow) {
            uint64_t cb_total = block.transactions[0].TotalOutput();
            uint64_t subsidy  = ExpectedBlockSubsidy(block.height);
            uint64_t fees_headroom = 0;
            for (size_t ti = 1; ti < block.transactions.size(); ++ti) {
                const auto& tx = block.transactions[ti];
                if (tx.IsCoinbase()) continue;
                uint64_t tx_in = 0, tx_out = tx.TotalOutput();
                for (const auto& inp : tx.inputs) {
                    auto utxo = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
                    if (utxo) tx_in += utxo->value;
                }
                if (tx_in > tx_out) fees_headroom += (tx_in - tx_out);
            }

            uint64_t max_coinbase;
            const uint64_t grandfather_height =
                coinbase_cap_grandfather_height_.load(
                    std::memory_order_relaxed);
            if (grandfather_height > 0 &&
                block.height < grandfather_height) {
                max_coinbase = BLOCK_REWARD_UNITS * 3 + fees_headroom + 1;
            } else {
                max_coinbase = subsidy + fees_headroom + 1;
            }
            if (cb_total > max_coinbase) {
                if (cb_total > BLOCK_REWARD_UNITS * 3 + fees_headroom + 1)
                    return reject("coinbase_over_3x_absolute_cap");
                return reject("coinbase_exceeds_subsidy_cap");
            }

            //  FEES-TO-VAULT CONSENSUS RULE. All TX fees MUST be
            // credited to VAULT_ADDRESS in the coinbase, not to the miner.
            // The coinbase builder in node.h already does this
            // (`vault_cut += block_tx_fees` at node.h:3315), but without
            // a consensus gate a malicious miner could redirect fees to
            // their own output and any peer would still accept the block
            // because `max_coinbase` is only an upper bound. This rule
            // makes the fee-to-vault flow an enforced invariant:
            //
            //   vault_output(coinbase) >= floor(subsidy × protocol_vault_share)
            //                           + sum_of_non_coinbase_fees
            //
            // where protocol_vault_share = 20% on normal blocks (100% on
            // vault-boundary blocks handled by ValidateCoinbaseOutputs).
            // We verify the LOWER BOUND here so the fees-portion is
            // pinned to vault. Inequality, not equality, so any future
            // rounding-tolerance or per-height variance stays accepted.
            //
            // Gated behind block.height >= FEES_TO_VAULT_ACTIVATES_AT so
            // pre-activation blocks (where an honest miner's coinbase
            // may not follow this invariant exactly, e.g. legacy 10%
            // vault minima) don't force a chain split on replay.
            if (block.height >= FEES_TO_VAULT_ACTIVATES_AT
                && !(block.height > 0 && block.height % VAULT_BLOCK_INTERVAL == 0)) {
                auto vault_script = AddressToScript(VaultAddressAtHeight(block.height));
                uint64_t vault_in_coinbase = 0;
                for (const auto& out : block.transactions[0].outputs) {
                    if (out.script_pubkey == vault_script) vault_in_coinbase += out.value;
                }
                uint64_t remaining_to_cap =
                    (MAX_SUPPLY_UNITS > total_supply_units_.load())
                    ? (MAX_SUPPLY_UNITS - total_supply_units_.load()) : 0;
                uint64_t effective_subsidy_for_floor = std::min(subsidy, remaining_to_cap);

                uint64_t expected_vault_floor;
                if (effective_subsidy_for_floor > 0) {
                    expected_vault_floor =
                        (effective_subsidy_for_floor * PROTOCOL_VAULT_SHARE_PCT) / 100
                        + fees_headroom;
                } else {
                    expected_vault_floor = (fees_headroom * 40) / 100;
                }
                if (vault_in_coinbase + 4 < expected_vault_floor) {
                    return reject("vault_cut_below_fees_floor");
                }
            }
        }
        if (block.transactions[0].outputs.size() > 200) return reject("coinbase_too_many_outputs");
        {
            std::unordered_set<std::string> seen_txids;
            seen_txids.reserve(block.transactions.size());
            for (const auto& tx : block.transactions) {
                auto txid_hex = HashToHex(tx.GetTxID());
                if (!seen_txids.insert(txid_hex).second) {
                    return reject("duplicate_txid_in_block");
                }
            }
        }
        // Supply/fee accounting is branch-state dependent.  A side-branch
        // candidate is initially received while utxo_set_ and total supply
        // still describe the competing main chain; defer this check to VBFR,
        // after Reorganize() reconstructs the candidate parent frame.
        if (!is_alt_chain) {
            uint64_t cb_out = block.transactions[0].TotalOutput();
            uint64_t fees_in_block = 0;
            for (size_t ti = 1; ti < block.transactions.size(); ++ti) {
                const auto& tx = block.transactions[ti];
                if (tx.IsCoinbase()) continue;
                uint64_t tx_in = 0, tx_out = tx.TotalOutput();
                for (const auto& inp : tx.inputs) {
                    auto utxo = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
                    if (utxo) tx_in += utxo->value;
                }
                if (tx_in > tx_out) fees_in_block += (tx_in - tx_out);
            }
            uint64_t new_emission = (cb_out > fees_in_block) ? (cb_out - fees_in_block) : 0;
            if (new_emission > MAX_SUPPLY_UNITS ||
                total_supply_units_.load() > MAX_SUPPLY_UNITS - new_emission)
                return reject("supply_cap_overflow_pre_pow");
        }

        if (!skip_pow && !parent_known) {
            return reject("pow_orphan_parent_unknown");
        }

        if (parent_known && derived_height > 0) {
            uint64_t now = (uint64_t)std::time(nullptr);
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
            // The native D-state corpus compresses five years of block heights
            // into one qualification run. Keep MTP and every state transition
            // exact, but do not compare its synthetic timestamp to the host
            // wall clock. constants.h forbids this macro in public builds.
            (void)now;
#else
#if defined(VELD_TEST_HOOKS) && defined(VELD_TEST_CHAIN_BUILD)
            const bool staged_test_chain_time = GENESIS_HASH[0] == '\0';
#else
            constexpr bool staged_test_chain_time = false;
#endif
            if (!staged_test_chain_time && block.header.timestamp > now + 600)
                return reject("timestamp_in_future");
#endif
            if (!chain_.empty() && !is_alt_chain) {
                uint64_t mtp = MedianTimePast();
                if (block.header.timestamp <= mtp) return reject("timestamp_before_mtp");
            }
        }

        // Difficulty for an alt candidate cannot be derived from chain_: at
        // ingest time chain_ still describes the current main branch, not the
        // candidate parent's branch.  Defer alt difficulty validation to
        // ValidateBlockForReplay(), where Reorganize() has rolled chain_ back
        // to the common ancestor and appends each accepted alt predecessor
        // before validating its child.  Main-tip extensions continue to be
        // checked here before registration.
        if (!skip_pow && !is_alt_chain &&
            parent_known && derived_height > 0) {
#ifdef VELD_MAINNET_POW
            constexpr uint64_t RETARGET_INTERVAL_LOCAL =
                DIFFICULTY_ADJUSTMENT_INTERVAL;
#else
            constexpr uint64_t RETARGET_INTERVAL_LOCAL = 20;
#endif
            uint64_t next_h               = derived_height;
            uint64_t window_start_local   = (next_h / RETARGET_INTERVAL_LOCAL) * RETARGET_INTERVAL_LOCAL;
            if (window_start_local > 0) {
                uint64_t window_end_local = window_start_local - 1;
                if (window_end_local >= chain_.size()) {
                    // The LWMA window for this block isn't yet
                    // represented in chain_. Defer validation —
                    // caller treats this like a normal orphan and
                    // re-tries when more parents land. NOT a hard
                    // reject. (skip_pow paths e.g. loadchain don't
                    // hit this branch — they bypass the bits gate
                    // entirely above.)
                    return reject("orphan_lwma_window_pending");
                }
            }
            uint32_t expected_bits = ComputeNextBitsAtLocked(derived_height - 1);
            bool bits_ok = (block.header.bits == expected_bits);
#ifdef VELD_LOCAL_SIM
            if (!bits_ok && block.header.bits == 0x207fffff) {
                bits_ok = true;
            }
#endif

            if (!bits_ok) {
                std::cerr << "  [AddBlock reject h=" << derived_height
                          << "] bits_mismatch got=0x" << std::hex
                          << block.header.bits << " expected=0x"
                          << expected_bits << std::dec << "\n";
                std::cerr.flush();
                return reject("bits_mismatch_lwma");
            }
        }

        // All branch-position, checkpoint and anchor checks are cheap relative
        // to VeldHash.  Run them while the candidate is still only caller-owned
        // input, before acquiring any expensive-work lease or constructing a
        // dataset.
        if (!chain_.empty() && derived_height > 0) {
            const uint64_t tip_h = chain_.back().height;
            if (tip_h >= MAX_REORG_DEPTH &&
                derived_height + MAX_REORG_DEPTH <= tip_h + 1)
                return reject("reorg_beyond_max_depth");
        }
        if (!PassesCheckpoint(derived_height, block.GetHash()))
            return reject("checkpoint_mismatch");
        if (anchor_gate_ && !anchor_gate_(derived_height, block.GetHash()))
            return reject("anchor_conflict");

        if (is_alt_chain) {
            const std::string branch_parent =
                HashToHex(block.header.prev_block_hash);
            const std::string ancestor =
                FindCanonicalAncestorBoundedNoLock_(branch_parent);
            if (ancestor.empty())
                return reject("reorg_ancestor_unavailable");
            auto anc_it = block_tree_.find(ancestor);
            if (anc_it == block_tree_.end() || !anc_it->second.on_main_chain)
                return reject("reorg_ancestor_unavailable");
            const uint64_t ancestor_height = anc_it->second.height;
            const uint64_t old_tip_height = chain_.back().height;
            if (old_tip_height < ancestor_height ||
                old_tip_height - ancestor_height >= MAX_REORG_DEPTH)
                return reject("reorg_beyond_max_depth");
            if (anchor_reorg_gate_ &&
                !anchor_reorg_gate_(ancestor_height, old_tip_height))
                return reject("reorg_below_anchor_carrier");
            if (finality_reorg_gate_ &&
                !finality_reorg_gate_(ancestor_height))
                return reject("reorg_below_finality");
        }

        if (checkpoint_at_or_below_) {
            uint64_t cp_height = 0;
            Hash256 cp_hash{};
            bool found = false;
            try {
                found = checkpoint_at_or_below_(
                    derived_height, cp_height, cp_hash);
            } catch (...) {
                found = false;
            }
            if (found && cp_height <= derived_height) {
                Hash256 walk_hash = block.GetHash();
                uint64_t walk_height = derived_height;
                if (cp_height < derived_height) {
                    walk_hash = block.header.prev_block_hash;
                    --walk_height;
                    while (walk_height > cp_height) {
                        auto it = block_tree_.find(HashToHex(walk_hash));
                        if (it == block_tree_.end()) {
                            walk_hash = ZeroHash();
                            break;
                        }
                        walk_hash = it->second.prev_hash;
                        --walk_height;
                    }
                }
                if (!HashIsZero(walk_hash) && walk_height == cp_height &&
                    walk_hash != cp_hash &&
                    derived_height >=
                        CHECKPOINT_ENFORCEMENT_ACTIVATES_AT_HEIGHT)
                    return reject("checkpoint_violation");
            }
        }

        // A locally retained side body already passed its first contextual
        // PoW gate. A byte-exact retransmission is a bounded retry trigger,
        // not another free hash request. Keep the original per-block source
        // context for reorg replay and skip only this redundant ingress hash.
        // Canonical duplicates still stop here and never reach fork choice.
        {
            auto known = block_tree_.find(bhash);
            if (known != block_tree_.end()) {
                if (known->second.on_main_chain)
                    return reject("duplicate_block");
                try {
                    if (LoadIndexedBlockNoLock_(bhash).Serialize() !=
                        block.Serialize())
                        return reject("block_known_body_mismatch");
                } catch (...) {
                    return reject("side_branch_body_unavailable");
                }
                if (!volatile_side_quarantine_.count(bhash))
                    return reject("duplicate_block");
                known_side_retry = true;
            }
        }

        if (!skip_pow && !skip_pow_hash_only && !known_side_retry) {
            std::optional<mining::ExpensivePowLease> source_pow_lease;
            if (pow_admission.source_budget) {
                source_pow_lease = pow_admission.source_budget->TryAcquire(
                    pow_admission.InitialUse());
                if (!source_pow_lease)
                    return defer("pow_peer_budget_exhausted");
            }
            auto global_pow_lease =
                mining::GlobalExpensivePowBudget().TryAcquire(
                    pow_admission.InitialUse());
            if (!global_pow_lease)
                return defer("pow_global_budget_exhausted");
            Block tmp = block;
            tmp.height = derived_height;
            // F-4: a dataset-unavailable sentinel is a local transient, not a
            // consensus verdict. Report it under its own tag so the dispatcher
            // credits no ban and does not cache the (valid) block as rejected.
            bool pow_dataset_unavailable = false;
            const CanonicalPowTarget* expected_target =
                pow_parent_context
                    ? &pow_parent_context->expected_target
                    : &submitted_target;
            if (!VerifyBlockPoW(
                    tmp, &pow_dataset_unavailable, expected_target)) {
                if (pow_dataset_unavailable)
                    return defer("pow_dataset_unavailable");
                return reject("pow_verify_failed");
            }
        }

        //  Hardening. Intra-block
        // double-spend dedup MUST run on every non-replay path, INCLUDING the
        // peer path (skip_scripts=true). The per-tx ValidateTransaction calls
        // are read-only against the committed UTXO set, so two txs in one block
        // that each spend the same pre-existing UTXO both pass individually;
        // only this block-scoped outpoint set catches it. It previously lived
        // ONLY under `!skip_pow && !skip_scripts`, so peer blocks skipped it and
        // a crafted double-spend block half-applied utxo_set_ in CommitBlock
        // (outputs inserted, then the 2nd EraseUTXO fails mid-loop -> phantom
        // UTXOs + a node-restart advisory). A single set across all non-coinbase
        // inputs also catches duplicate outpoints within one transaction. Runs
        // UNCONDITIONALLY (every path, incl. trusted replay): a valid block can
        // never contain a duplicate outpoint, so this never rejects an honest
        // historical block on replay — it only ever catches an actual
        // double-spend, which must never have been committed in the first place.
        {
            std::unordered_set<std::string> block_spent_all;
            for (size_t i = 1; i < block.transactions.size(); ++i) {
                for (const auto& inp : block.transactions[i].inputs) {
                    if (inp.IsCoinbase()) continue;
                    std::string k = HashToHex(inp.prev_tx_hash) + ":"
                                  + std::to_string(inp.prev_out_index);
                    if (!block_spent_all.insert(k).second)
                        return reject("intra_block_double_spend");
                }
            }
        }

        // Dust is a consensus rule, not a script-verification optimization.
        // Peer linear ingest (`skip_scripts=true`) must reject exactly what
        // local production, startup replay, and reorg replay reject.
        if (!skip_pow) {
            for (size_t i = 1; i < block.transactions.size(); ++i) {
                const auto& tx = block.transactions[i];
                if (derived_height >= BATCH1_HARDENING_HEIGHT &&
                    tx.HasDustOutput(DUST_THRESHOLD_UNITS))
                    return reject("output_below_dust_threshold");
                for (const auto& out : tx.outputs) {
                    if (!out.script_pubkey.empty() &&
                        out.script_pubkey[0] == 0x6A &&
                        out.script_pubkey.size() >
                            MAX_OP_RETURN_SCRIPT_PUBKEY_BYTES)
                        return reject("op_return_too_large");
                }
            }
        }

        // Full transaction validation reads the current UTXO set.  Defer side
        // branches to VBFR so local/RPC and peer ingest use the same candidate
        // parent state during reorganization.
        if (!skip_pow && !skip_scripts && !is_alt_chain) {
            std::unordered_set<std::string> block_spent_outpoints;
            for (size_t i = 1; i < block.transactions.size(); ++i) {
                const auto& tx_i = block.transactions[i];
                // transactions[0] is coinbase (already validated above)
                // transactions[1..N] must NOT be coinbase-looking
                if (!ValidateTransaction(tx_i, false)) {
                    std::cerr << "  [AddBlock reject h=" << block.height << "] tx_validate_failed idx=" << i << "\n";
                    std::cerr.flush();
                    return false;
                }
                for (const auto& inp : tx_i.inputs) {
                    if (inp.IsCoinbase()) continue;
                    std::string key = HashToHex(inp.prev_tx_hash) + ":" + std::to_string(inp.prev_out_index);
                    if (!block_spent_outpoints.insert(key).second)
                        return reject("intra_block_double_spend");
                }
            }
        }

        if (!skip_pow && skip_scripts && !is_alt_chain
            && derived_height >= TX_FULL_VALIDATION_ACTIVATION_HEIGHT
            && derived_height <  TX_FULL_VALIDATION_V2_ACTIVATION_HEIGHT) {
            for (size_t i = 1; i < block.transactions.size(); ++i) {
                if (!ValidateTransaction(block.transactions[i], false))
                    return reject("consensus_tx_sig_or_value_invalid");
            }
        }

        // Coinbase maturity is enforced on the linear peer-accept path as well as
        // the local and reorg-replay paths: gate on !skip_pow (like the
        // unconditional double-spend dedup), not !skip_scripts, so peer-relayed
        // blocks are held to the same maturity rule. Honest blocks always pass —
        // the mempool already rejects immature-coinbase spends at admission.
        if (!skip_pow && !is_alt_chain
            && derived_height >= COINBASE_MATURITY_CONSENSUS_HEIGHT) {
            const auto v_script = AddressToScript(VaultAddressAtHeight(derived_height));
            const auto p_script = AddressToScript(POOL_ADDRESS);
            const auto e_script = AddressToScript(ENDORSEMENT_POOL_ADDRESS);
            for (size_t i = 1; i < block.transactions.size(); ++i) {
                for (const auto& inp : block.transactions[i].inputs) {
                    if (inp.IsCoinbase()) continue;
                    auto uit = utxo_set_.find(UTXOKey(inp.prev_tx_hash, inp.prev_out_index));
                    if (uit == utxo_set_.end()) continue;
                    const auto& utxo = uit->second;
                    if (utxo.script_pubkey == v_script
                     || utxo.script_pubkey == p_script
                     || utxo.script_pubkey == e_script) continue;
                    if (utxo.is_coinbase
                        && utxo.block_height >= COINBASE_MATURITY_ACTIVATES_AT_HEIGHT
                        && derived_height - utxo.block_height < COINBASE_MATURITY)
                        return reject("consensus_coinbase_immature");
                }
            }
        }

        if (!skip_pow
            && derived_height >= GAMING_GUARD_CONSENSUS_HEIGHT) {
            constexpr uint64_t COOLDOWN = 12;
            uint64_t pos = derived_height % VAULT_DISTRIBUTION_INTERVAL;
            if (pos > VAULT_DISTRIBUTION_INTERVAL - COOLDOWN) {
                static const std::string REG   = "VELD_VALIDATOR|REGISTER|";
                static const std::string DEREG = "VELD_VALIDATOR|DEREGISTER|";
                for (size_t i = 1; i < block.transactions.size(); ++i) {
                    for (const auto& out : block.transactions[i].outputs) {
                        if (out.script_pubkey.size() < 2 || out.script_pubkey[0] != 0x6A)
                            continue;
                        size_t off = 1, plen = 0;
                        if (out.script_pubkey[off] <= 75) { plen = out.script_pubkey[off++]; }
                        else if (out.script_pubkey[off] == 0x4C && out.script_pubkey.size() > off+1) {
                            off++; plen = out.script_pubkey[off++];
                        }
                        else if (out.script_pubkey[off] == 0x4D && out.script_pubkey.size() > off+2) {
                            off++;
                            plen = out.script_pubkey[off] | (out.script_pubkey[off+1] << 8);
                            off += 2;
                        }
                        if (off + plen > out.script_pubkey.size()) continue;
                        std::string payload(out.script_pubkey.begin()+off,
                                            out.script_pubkey.begin()+off+plen);
                        if (payload.rfind(REG, 0) == 0 || payload.rfind(DEREG, 0) == 0)
                            return reject("consensus_gaming_guard_cooldown");
                    }
                }
            }
        }

        // Stake backing is branch-state dependent.  On a side-branch candidate
        // utxo_set_ and the staking callbacks still describe the current main
        // branch, so evaluating here would make acceptance depend on which fork
        // the node happened to see first.  Linear blocks are checked now;
        // side-branch blocks are checked by ValidateBlockForReplay() after
        // Reorganize() reconstructs both the candidate UTXO set and staking
        // overlay through the candidate parent.
        if (!skip_pow && !is_alt_chain) {
            if (const char* why = StakeBackingViolation(block)) return reject(why);
        }

        std::string prev  = HashToHex(block.header.prev_block_hash);

        if (block_tree_.count(bhash) && !known_side_retry)
            return reject("duplicate_block");

        auto prev_it = block_tree_.find(prev);
        uint64_t expected_height;
        if (prev_it != block_tree_.end()) {
            expected_height = prev_it->second.height + 1;
        } else if (HashIsZero(block.header.prev_block_hash)) {
            expected_height = 0;
        } else {
            return reject("orphan_parent_unknown");
        }

        Block blk = block;
        blk.height = expected_height;

        if (blk.transactions.empty()) return reject("empty_after_copy");
        if (!is_alt_chain) {
            uint64_t cb_out = blk.transactions[0].TotalOutput();
            uint64_t fees_in_block_2 = 0;
            for (size_t ti = 1; ti < blk.transactions.size(); ++ti) {
                const auto& tx = blk.transactions[ti];
                if (tx.IsCoinbase()) continue;
                uint64_t tx_in = 0, tx_out = tx.TotalOutput();
                for (const auto& inp : tx.inputs) {
                    auto utxo = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
                    if (utxo) tx_in += utxo->value;
                }
                if (tx_in > tx_out) fees_in_block_2 += (tx_in - tx_out);
            }
            uint64_t new_emission_2 = (cb_out > fees_in_block_2) ? (cb_out - fees_in_block_2) : 0;
            if (new_emission_2 > MAX_SUPPLY_UNITS ||
                total_supply_units_.load() > MAX_SUPPLY_UNITS - new_emission_2)
                return reject("supply_cap_overflow");
        }

        if (!skip_pow && !is_alt_chain && blk.height > 0 &&
            !ValidateCoinbaseOutputs(blk))
            return reject("coinbase_outputs_invalid");
        if (!skip_pow && !is_alt_chain && blk.height > 0 &&
            !ValidateCanonicalCoinbaseSplit(blk))
            return reject("coinbase_split_not_canonical");

        if constexpr (OPTION_B_CONSENSUS_GATE_ENABLED) {
            if (!skip_pow) {
                std::unordered_set<std::string> intra_block_nms_seen;
                size_t nms_records = 0;
                for (const auto& tx : blk.transactions) {
                    if (tx.IsCoinbase()) continue;
                    auto nms_rec = ExtractNmsFromTx(tx);
                    if (!nms_rec) continue;
                    if (++nms_records > MAX_NMS_RECORDS_PER_BLOCK)
                        return reject("too_many_nms_records");
                    auto miner_script = ExtractNmsMinerScript(tx);
                    if (miner_script.empty())
                        return reject("nms_missing_miner_identification");
                    if (!ValidateNmsMinerIdentity(tx))
                        return reject("nms_miner_identity_mismatch");
                    if (!is_alt_chain) {
                        const auto nms_validation =
                            ValidateNmsWithDisposition(
                                *nms_rec, *this, blk.height,
                                pow_admission.source_budget.get(),
                                pow_admission.NmsUse());
                        if (nms_validation ==
                                NmsValidationDisposition::DeferredLocalWork) {
                            return defer("nms_local_work_deferred");
                        }
                        if (nms_validation !=
                                NmsValidationDisposition::Valid) {
                            return reject("nms_validation_failed");
                        }
                    }
                    std::string nkey(nms_rec->raw.begin(), nms_rec->raw.end());
                    if (!intra_block_nms_seen.insert(nkey).second)
                        return reject("nms_duplicate_in_block");
                    if (!is_alt_chain && NmsPayloadSeen(nms_rec->raw))
                        return reject("nms_duplicate_cross_block");
                    if (!is_alt_chain && !NmsBondSatisfied(miner_script))
                        return reject("nms_insufficient_bond");
                }
            }

            if (!skip_pow && !is_alt_chain && !ValidateExpectedPoolPayout(blk))
                return reject("consensus_pool_payout_mismatch");

            if (!skip_pow && !is_alt_chain && !ValidateExpectedEndorsementFlush(blk))
                return reject("consensus_endorse_flush_mismatch");
            if (!skip_pow && !is_alt_chain && !ValidateExpectedVaultDistribution(blk))
                return reject("consensus_vault_dist_mismatch");
            // AMM pool covenant (btcVELD): reject a block whose tx spends the pool
            // UTXO but is not a valid AMM op. Inert until a pool exists (regtest);
            // Alternate-chain validation uses the corresponding engine overlay.
            if (!skip_pow && !is_alt_chain && amm_block_validator_ && !amm_block_validator_(blk))
                return reject("consensus_amm_covenant_violation");
            if (!skip_pow && !is_alt_chain && !ValidateExpectedBondMovements(blk))
                return reject("consensus_bond_settlement_mismatch");
            if (!skip_pow && !is_alt_chain && !ValidateExpectedBondYieldSettlement(blk))
                return reject("consensus_bond_yield_mismatch");
        }

        if (!is_alt_chain) {
            std::unordered_set<std::string> intra_block_tx_ids;
            for (const auto& tx : blk.transactions)
                intra_block_tx_ids.insert(HashToHex(tx.GetTxID()));
            for (size_t ti = 0; ti < blk.transactions.size(); ++ti) {
                const auto& tx = blk.transactions[ti];
                if (tx.IsCoinbase()) continue;
                for (const auto& inp : tx.inputs) {
                    if (intra_block_tx_ids.count(HashToHex(inp.prev_tx_hash))) continue;
                    if (!GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index)) {
                        return reject("input_utxo_missing");
                    }
                }
            }
        }

#ifdef VELD_TEST_PHASE_INTERLEAVE
        ::veld::test::PhaseInterleaveHook(derived_height, bhash);
#endif
        lock.unlock();
        std::unique_lock<std::shared_mutex> wlock(chain_mutex_);

        enum class LocalTicketClaimResult : uint8_t {
            Accepted,
            Mismatch,
            StaleOrUsed,
            Expired,
        };
        auto claim_local_ticket = [&](const Block& candidate) {
            if (!local_work_required || !local_work_ticket)
                return LocalTicketClaimResult::Mismatch;
            const auto& ticket = *local_work_ticket;
            if (!ticket || ticket.candidate_hash != candidate.GetHash() ||
                ticket.candidate_height != candidate.height ||
                ticket.parent_hash != candidate.header.prev_block_hash ||
                ticket.source != pow_admission.local_work_kind ||
                ticket.work_binding != pow_admission.work_binding ||
                ticket.work_authorization !=
                    pow_admission.work_authorization)
                return LocalTicketClaimResult::Mismatch;
            if (ticket.source == mining::LocalWorkKind::SubmitBlock) {
                if (HashIsZero(ticket.work_identity) ||
                    ticket.work_identity !=
                        candidate.header.GetTemplateWorkIdentity())
                    return LocalTicketClaimResult::Mismatch;
            } else if (!HashIsZero(ticket.work_identity)) {
                return LocalTicketClaimResult::Mismatch;
            }
            if (std::chrono::steady_clock::now() >= ticket.deadline)
                return LocalTicketClaimResult::Expired;
            bool live = false;
            try { live = ticket.live(); }
            catch (...) { live = false; }
            if (!live) return LocalTicketClaimResult::Expired;
            pow_admission.local_work_handoff->Install(
                ticket.owner, ticket.live);
            bool claimed = false;
            try {
                claimed = ticket.claim_for_canonical_commit(
                    ticket.coordinator_generation,
                    ticket.validation_generation,
                    ticket.network_magic,
                    ticket.genesis_hash,
                    ticket.profile_digest);
            }
            catch (...) { claimed = false; }
            if (!claimed) return LocalTicketClaimResult::StaleOrUsed;
            try { live = ticket.live(); }
            catch (...) { live = false; }
            return live ? LocalTicketClaimResult::Accepted
                        : LocalTicketClaimResult::Expired;
        };
        if (block_tree_.count(bhash) && !known_side_retry) {
            return reject("duplicate_block");
        }
        if (!HashIsZero(block.header.prev_block_hash) &&
            block_tree_.find(prev) == block_tree_.end()) {
            return reject("orphan_parent_unknown");
        }

        // Execute the complete derived-module transition against snapshots
        // before this block is registered as canonical or mutates the UTXO set.
        // This catches cross-module apply failures that isolated validation
        // cannot see (notably token mutation followed by AMM balance failure).
        const bool extends_current_tip = chain_.empty()
            ? HashIsZero(blk.header.prev_block_hash)
            : (blk.header.prev_block_hash == chain_.back().GetHash());
        if (extends_current_tip && module_precommit_validator_) {
            uint64_t projected_supply = total_supply_units_.load();
            if (!AdvanceCanonicalSupply(blk, projected_supply))
                return reject("module_supply_projection_failed");
            bool modules_ok = false;
            try { modules_ok = module_precommit_validator_(blk, projected_supply); }
            catch (...) { modules_ok = false; }
            if (!modules_ok) return reject("module_apply_precommit_failed");
        }

        // Local/RPC production is never allowed to register a stale template
        // as a side branch.  Its exact parent binding must be consumed only at
        // the canonical precommit sink; ordinary peer side branches continue
        // through the bounded F2 quarantine independently.
        if (pow_admission.RequiresLocalWorkAdmission() &&
            !extends_current_tip) {
            return defer("local_work_parent_no_longer_canonical");
        }

        // A canonical-tip candidate remains stack-local until every
        // parent-state-dependent gate below has passed. Side branches need a
        // bounded private index for VBFR/retry, but that volatile index is
        // deliberately excluded from every public block/height/tip view.
        if (!known_side_retry && !extends_current_tip) {
            const bool registered =
                RegisterVolatileSideBlockNoLock_(blk, pow_admission);
            if (!registered) {
                const std::string tag = register_failure_tag_.empty()
                    ? "block_body_persist_failed" : register_failure_tag_;
                if (tag == "side_branch_capacity" ||
                    tag == "side_branch_cleanup_failed_restart_required")
                    return defer(tag.c_str());
                return reject(tag.c_str());
            }
        }
        if (known_side_retry && !side_pow_admission_.count(bhash)) {
            // A side body restored from a prior process has no safe borrowed
            // source pointer. Its byte-exact new trigger becomes the bounded
            // fallback provenance for this and any missing prefix entries.
            side_pow_admission_.emplace(bhash, pow_admission);
        }

        if (!extends_current_tip) {
            std::vector<Block> validation_scratch;
            const ReorgDisposition validation = ReorganizeBounded_(
                bhash, validation_scratch, pow_admission,
                /*validation_only=*/true);
            if (validation == ReorgDisposition::DeferredLocalWork) {
                if (last_reject_tag_.empty())
                    last_reject_tag_ = "side_validation_deferred_local_work";
                if (last_reject_tag_ != "reorg_retry_backoff")
                    NoteDeferredReorgNoLock_(bhash);
                return BlockAdmissionResult::DeferredLocalWork();
            }
            if (validation == ReorgDisposition::ConsensusInvalid) {
                if (last_reject_tag_.empty())
                    last_reject_tag_ = "side_contextual_validation_failed";
                return BlockAdmissionResult::ConsensusInvalid();
            }
            deferred_reorg_retry_.erase(bhash);
        }

        if (chain_.empty()) {
            if (!local_work_required && canonical_work_transition_fn_) {
                bool transition_ready = false;
                try { transition_ready = canonical_work_transition_fn_(blk); }
                catch (...) { transition_ready = false; }
                if (!transition_ready)
                    return defer("work_admission_transition_pending");
            }
            if (local_work_required) {
                const auto ticket_result = claim_local_ticket(blk);
                if (ticket_result == LocalTicketClaimResult::Mismatch)
                    return defer("local_work_ticket_mismatch");
                if (ticket_result == LocalTicketClaimResult::StaleOrUsed)
                    return defer("local_work_ticket_stale_or_used");
                if (ticket_result == LocalTicketClaimResult::Expired)
                    return defer("local_work_ticket_expired");
#ifdef VELD_TEST_HOOKS
                if (test_local_work_pre_commit_barrier_)
                    test_local_work_pre_commit_barrier_();
#endif
            }
            bool success = CommitBlock(blk);
            if (success && on_commit_) {
                if (wlock.owns_lock()) wlock.unlock();
                std::vector<std::pair<Hash256,uint32_t>> spent;
                std::vector<UTXO> created;
                for (const auto& tx : blk.transactions)
                    for (size_t i = 0; i < tx.outputs.size(); ++i) {
                        if (IsProvablyUnspendableOutput(tx.outputs[i]))
                            continue;
                        UTXO utxo;
                        utxo.tx_hash       = tx.GetTxID();
                        utxo.output_index  = (uint32_t)i;
                        utxo.value         = tx.outputs[i].value;
                        utxo.script_pubkey = tx.outputs[i].script_pubkey;
                        utxo.block_height  = blk.height;
                        utxo.is_coinbase   = tx.IsCoinbase();
                        created.push_back(utxo);
                    }
                bool callback_ok = false;
                try {
                    callback_ok = on_commit_(blk, spent, created, false);
                } catch (const std::exception& e) {
                    std::cerr << "  [on_commit genesis] exception: " << e.what() << "\n";
                } catch (...) {
                    std::cerr << "  [on_commit genesis] unknown exception\n";
                }
                if (!callback_ok) {
                    RollbackTip(/*allow_genesis=*/true);
                    last_reject_tag_ = "commit_callback_failed";
                    success = false;
                }
            }
            if (success) UpdateNmsTallyAfterCommit_(blk);
            if (success && pow_admission.RequiresLocalWorkAdmission())
                local_handoff_reset.retain = true;
            return success;
        }

        std::string tip_hash    = HashToHex(chain_.back().GetHash());
        auto tip_it             = block_tree_.find(tip_hash);
        auto new_it             = block_tree_.find(bhash);
        if (!extends_current_tip && new_it == block_tree_.end()) return false;

        ChainWork tip_work = tip_it != block_tree_.end()
            ? tip_it->second.cumulative_work : ChainWork(0);
        const ChainWork new_work = extends_current_tip
            ? AddChainWork(tip_work, BlockWork(blk.header.bits))
            : new_it->second.cumulative_work;

        bool success = false;
        std::vector<Block> blocks_to_persist;
        bool from_reorg_path = false;

        // Reorg rollback is a bounded undo frame populated by
        // ReorganizeBounded_; no lifetime chain/UTXO/index copies are taken.

        if (blk.header.prev_block_hash == chain_.back().GetHash()) {
            // Extends tip — standard single-block commit.
            // Re-run tip-dependent checks under the unique lock. Another thread
            // may have changed whether this block was classified as an extension
            // during the earlier lock-free validation pass.
            if (!ValidateMinerCaps(blk)) return false;
            // These deterministic gates depend on parent state and are safe to
            // evaluate twice. Persisted replay uses skip_pow=true and remains
            // outside this path.
            if (!skip_pow) {
                if (!ValidateExpectedPoolPayout(blk)) return false;
                if (!ValidateExpectedEndorsementFlush(blk)) return false;
                if (!ValidateExpectedVaultDistribution(blk)) return false;
                if (amm_block_validator_ && !amm_block_validator_(blk)) return false;   // btcVELD AMM covenant
                if (!ValidateExpectedBondMovements(blk)) return false;
                if (!ValidateExpectedBondYieldSettlement(blk)) return false;

                // Recheck emission against the consistent parent UTXO and supply
                // state before committing the block.
                if (blk.height > 0 && !ValidateCoinbaseOutputs(blk))
                    return false;
                if (blk.height > 0 && !ValidateCanonicalCoinbaseSplit(blk))
                    return false;
                {
                    uint64_t cb_out = blk.transactions[0].TotalOutput();
                    uint64_t fees_in_block = 0;
                    for (size_t ti = 1; ti < blk.transactions.size(); ++ti) {
                        const auto& tx = blk.transactions[ti];
                        if (tx.IsCoinbase()) continue;
                        uint64_t tx_in = 0, tx_out = tx.TotalOutput();
                        for (const auto& inp : tx.inputs) {
                            auto utxo = GetUTXONoLock(inp.prev_tx_hash,
                                                      inp.prev_out_index);
                            if (utxo) tx_in += utxo->value;
                        }
                        if (tx_in > tx_out) fees_in_block += (tx_in - tx_out);
                    }
                    uint64_t new_emission =
                        (cb_out > fees_in_block) ? (cb_out - fees_in_block) : 0;
                    if (new_emission > MAX_SUPPLY_UNITS ||
                        total_supply_units_.load() >
                            MAX_SUPPLY_UNITS - new_emission)
                        return false;
                }
            }
            // Validate peer transaction signatures and values against the
            // consistent parent UTXO set. PoW was verified before acquiring
            // this lock; persisted replay intentionally skips this path.
            if (!skip_pow && skip_scripts
                && derived_height >= TX_FULL_VALIDATION_V2_ACTIVATION_HEIGHT) {
                for (size_t i = 1; i < blk.transactions.size(); ++i) {
                    if (!ValidateTransaction(blk.transactions[i], false))
                        return reject("consensus_tx_sig_or_value_invalid_v2");
                }
            }
            if (!local_work_required && canonical_work_transition_fn_) {
                bool transition_ready = false;
                try { transition_ready = canonical_work_transition_fn_(blk); }
                catch (...) { transition_ready = false; }
                if (!transition_ready)
                    return defer("work_admission_transition_pending");
            }
            if (local_work_required) {
                const auto ticket_result = claim_local_ticket(blk);
                if (ticket_result == LocalTicketClaimResult::Mismatch)
                    return defer("local_work_ticket_mismatch");
                if (ticket_result == LocalTicketClaimResult::StaleOrUsed)
                    return defer("local_work_ticket_stale_or_used");
                if (ticket_result == LocalTicketClaimResult::Expired)
                    return defer("local_work_ticket_expired");
#ifdef VELD_TEST_HOOKS
                if (test_local_work_pre_commit_barrier_)
                    test_local_work_pre_commit_barrier_();
#endif
            }
            success = CommitBlock(blk);
            if (success) {
                blocks_to_persist.push_back(blk);
            }
        } else if (BetterChainScore(new_work, new_it->second.height, new_it->first,
                                    tip_work, tip_it->second.height, tip_it->first)) {
            bool ancestor_blacklisted = false;
            {
                std::string cursor = bhash;
                for (int hops = 0; hops < (int)MAX_REORG_DEPTH + 8; ++hops) {
                    if (bad_alt_tips_.count(cursor)) {
                        ancestor_blacklisted = true;
                        break;
                    }
                    auto cit = block_tree_.find(cursor);
                    if (cit == block_tree_.end()) break;
                    if (cit->second.on_main_chain) break;
                    cursor = HashToHex(cit->second.prev_hash);
                    if (cursor.empty()) break;
                }
            }
            if (ancestor_blacklisted) {
                static std::atomic<uint64_t> skip_log_counter{0};
                if ((skip_log_counter.fetch_add(1) & 0xFF) == 0) {
                    std::cerr << "  [fork-choice] skipping Reorganize for bhash="
                              << bhash.substr(0, 16)
                              << "... — ancestor in bad_alt_tips_ blacklist (count="
                              << bad_alt_tips_.size() << ")\n";
                    std::cerr.flush();
                }
                success = false;
            } else {
                if (canonical_work_transition_fn_) {
                    bool transition_ready = false;
                    try {
                        transition_ready = canonical_work_transition_fn_(blk);
                    } catch (...) {
                        transition_ready = false;
                    }
                    if (!transition_ready)
                        return defer("work_admission_transition_pending");
                }
                const ReorgDisposition reorg = Reorganize(
                    bhash, blocks_to_persist, pow_admission);
                success = reorg == ReorgDisposition::Applied;
                if (success) {
                    from_reorg_path = true;
                    deferred_reorg_retry_.erase(bhash);
                } else if (reorg == ReorgDisposition::DeferredLocalWork) {
                    // The fully contextualized side branch remains bounded and
                    // retryable. It is neither blacklisted nor published as a
                    // canonical acceptance while local work is unavailable.
                    if (last_reject_tag_.empty())
                        last_reject_tag_ = "reorg_deferred_local_work";
                    if (last_reject_tag_ != "reorg_retry_backoff")
                        NoteDeferredReorgNoLock_(bhash);
                    return BlockAdmissionResult::DeferredLocalWork();
                } else {
                    deferred_reorg_retry_.erase(bhash);
                }
            }
        } else {
            // A fully contextualized lower-work fork may now cross the durable
            // side-body boundary. Winning branches remain volatile until the
            // real reorg succeeds, so any later local-work deferral still has
            // zero persistence or relay effects.
            if (!PromoteValidatedSideSuffixNoLock_(bhash)) {
                const std::string tag = register_failure_tag_.empty()
                    ? "block_body_persist_failed" : register_failure_tag_;
                NoteDeferredReorgNoLock_(bhash);
                return defer(tag.c_str());
            }
            return BlockAdmissionResult::Accepted();
        }

        if (success && !blocks_to_persist.empty()) {
            if (wlock.owns_lock()) wlock.unlock();

            auto rollback_post_reorg = [&]() -> bool {
                if (!from_reorg_path || !pending_reorg_rollback_ ||
                    !pending_reorg_rollback_->valid) {
                    return false;
                }
                if (!wlock.owns_lock()) wlock.lock();
                const ReorgRollbackFrame frame = *pending_reorg_rollback_;
                UTXODelta old_delta;
                const bool memory_ok =
                    RestoreReorgFrameNoLock_(frame, old_delta);
                blocks_to_persist.clear();

                bool durable_ok = memory_ok;
                if (memory_ok && on_reorg_abort_ && !chain_.empty()) {
                    try {
                        durable_ok = on_reorg_abort_(
                            old_delta, chain_.back(),
                            total_supply_units_.load(),
                            frame.old_tail);
                    } catch (const std::exception& e) {
                        std::cerr << "  [reorg] abort-persistence exception: "
                                  << e.what() << "\n";
                        durable_ok = false;
                    } catch (...) {
                        std::cerr << "  [reorg] abort-persistence unknown exception\n";
                        durable_ok = false;
                    }
                }
                if (durable_ok) {
                    pending_reorg_rollback_.reset();
                    reorg_protected_side_hashes_.clear();
                    (void)PruneSideBranchStateNoLock_(/*force=*/true);
                } else {
                    // Keep the rollback frame and displaced bodies intact. A
                    // failed/uncertain abort must be resolved by startup, not
                    // by destructive in-process pruning.
                    durability_compromised_.store(true,
                                                  std::memory_order_release);
                    std::cerr << "  [reorg] CRITICAL: old in-memory canonical "
                                 "frame restored but durable rollback failed; "
                                 "restart required before accepting more blocks\n";
                    std::cerr.flush();
                }
                return durable_ok;
            };

            // Finalize the rollback frame before publishing its signed user
            // transactions.  Callers revalidate those transactions against
            // chain and mempool state, so release chain_mutex_ first.
            auto finalize_successful_reorg = [&]() {
                if (!from_reorg_path) return;

                std::vector<Transaction> orphan_txs;
                if (!wlock.owns_lock()) wlock.lock();
                if (pending_reorg_rollback_ &&
                    pending_reorg_rollback_->valid) {
                    for (const auto& old_block :
                         pending_reorg_rollback_->old_tail) {
                        for (const auto& tx : old_block.transactions) {
                            if (tx.IsCoinbase()) continue;
                            bool signed_input = false;
                            for (const auto& input : tx.inputs) {
                                if (!input.script_sig.empty()) {
                                    signed_input = true;
                                    break;
                                }
                            }
                            if (signed_input) orphan_txs.push_back(tx);
                        }
                    }
                }
                pending_reorg_rollback_.reset();
                reorg_protected_side_hashes_.clear();
                (void)PruneSideBranchStateNoLock_(/*force=*/true);
                wlock.unlock();

                // Also notify with an empty vector: a coinbase-only reorg still
                // requires post-commit mempool/pending-relay housekeeping.
                if (on_orphaned_txs_) {
                    try {
                        on_orphaned_txs_(orphan_txs);
                    } catch (const std::exception& e) {
                        std::cerr << "  [reorg] post-commit orphan callback: "
                                  << e.what() << "\n";
                    } catch (...) {
                        std::cerr << "  [reorg] post-commit orphan callback: "
                                     "unknown exception\n";
                    }
                }
            };

            const auto reorg_publication_uncertain = [&]() -> bool {
                if (!from_reorg_path ||
                    !reorg_publication_uncertain_fn_) {
                    return false;
                }
                bool uncertain = true;
                try {
                    uncertain = reorg_publication_uncertain_fn_();
                } catch (...) {
                    // A broken uncertainty query is itself unsafe to treat as
                    // a known publication outcome.
                    uncertain = true;
                }
                if (uncertain) {
                    durability_compromised_.store(
                        true, std::memory_order_release);
                    std::cerr
                        << "  [reorg] CRITICAL: canonical publication outcome "
                           "is uncertain; retaining rollback frame and all "
                           "displaced bodies until restart\n";
                    std::cerr.flush();
                }
                return uncertain;
            };

            if (!on_commit_) {
                if (!from_reorg_path) {
                    for (const auto& cb_block : blocks_to_persist)
                        UpdateNmsTallyAfterCommit_(cb_block);
                } else if (!reorg_publication_uncertain()) {
                    finalize_successful_reorg();
                }
                return success;
            }

            for (const auto& cb_block : blocks_to_persist) {
                std::vector<std::pair<Hash256,uint32_t>> spent;
                std::vector<UTXO> created;
                for (const auto& tx : cb_block.transactions) {
                    for (size_t i = 0; i < tx.outputs.size(); ++i) {
                        if (IsProvablyUnspendableOutput(tx.outputs[i]))
                            continue;
                        UTXO utxo;
                        utxo.tx_hash       = tx.GetTxID();
                        utxo.output_index  = (uint32_t)i;
                        utxo.value         = tx.outputs[i].value;
                        utxo.script_pubkey = tx.outputs[i].script_pubkey;
                        utxo.block_height  = cb_block.height;
                        utxo.is_coinbase   = tx.IsCoinbase();
                        created.push_back(utxo);
                    }
                    if (!tx.IsCoinbase()) {
                        for (const auto& inp : tx.inputs)
                            spent.emplace_back(inp.prev_tx_hash, inp.prev_out_index);
                    }
                }
                bool callback_ok = false;
                try {
                    callback_ok = on_commit_(cb_block, spent, created,
                                             from_reorg_path);
                } catch (const std::exception& e) {
                    std::cerr << "  [on_commit] exception at height " << cb_block.height
                              << ": " << e.what() << "\n";
                } catch (...) {
                    std::cerr << "  [on_commit] unknown exception at height "
                              << cb_block.height << "\n";
                }
                if (!callback_ok) {
                    last_reject_tag_ = "commit_callback_failed";
                    if (!from_reorg_path) {
                        RollbackTip();
                    } else {
                        const bool restored = rollback_post_reorg();
                        std::cerr << "  [reorg] post-reorg commit callback failed; "
                                  << (restored
                                          ? "restored the complete pre-reorg canonical frame\n"
                                          : "FAILED to restore the pre-reorg frame\n");
                        std::cerr.flush();
                    }
                    success = false;
                    break;
                }
            }

            // Credit NMS only after the complete module + persistence callback
            // succeeds. A rejected linear block therefore leaves no tally
            // residue for RollbackTip to reconstruct. Reorg already advanced
            // the tally inside Reorganize and must not be double-credited here.
            if (success && !from_reorg_path) {
                for (const auto& cb_block : blocks_to_persist)
                    UpdateNmsTallyAfterCommit_(cb_block);
            } else if (success && !reorg_publication_uncertain()) {
                finalize_successful_reorg();
            }
        }
        if (success && pow_admission.RequiresLocalWorkAdmission())
            local_handoff_reset.retain = true;
        return success;
    }

    static bool VerifyInputAgainstScript(const Transaction& tx,
                                          uint32_t input_index,
                                          const std::vector<uint8_t>& script_pubkey) {
        if (input_index >= tx.inputs.size()) return false;
        const auto& inp = tx.inputs[input_index];
        if (script_pubkey.size() != 25 ||
            script_pubkey[0]  != 0x76 ||
            script_pubkey[1]  != 0xA9 ||
            script_pubkey[2]  != 0x14 ||
            script_pubkey[23] != 0x88 ||
            script_pubkey[24] != 0xAC) {
            return false;
        }
        std::array<uint8_t, 20> expected_hash;
        std::copy(script_pubkey.begin() + 3, script_pubkey.begin() + 23,
                  expected_hash.begin());
        auto read_pushdata2 = [](const std::vector<uint8_t>& ss, size_t& pos,
                                  std::vector<uint8_t>& out) -> bool {
            if (pos + 3 > ss.size()) return false;
            if (ss[pos++] != 0x4D) return false;
            size_t len = (size_t)ss[pos] | ((size_t)ss[pos + 1] << 8);
            pos += 2;
            if (pos + len > ss.size()) return false;
            out.assign(ss.begin() + pos, ss.begin() + pos + len);
            pos += len;
            return true;
        };
        const auto& ss = inp.script_sig;
        size_t pos = 0;
        std::vector<uint8_t> sig_bytes_with_hashtype;
        std::vector<uint8_t> pubkey_bytes;
        if (!read_pushdata2(ss, pos, sig_bytes_with_hashtype)) return false;
        if (!read_pushdata2(ss, pos, pubkey_bytes)) return false;
        if (pubkey_bytes.size() != 1952) return false;
        if (sig_bytes_with_hashtype.empty()) return false;
        if (pos != ss.size()) return false;
        if (sig_bytes_with_hashtype.size() != 3311) return false;
        uint8_t scheme_id = sig_bytes_with_hashtype.front();
        if (scheme_id != ::veld::SCHEME_ID_MLDSA65) return false;
        if (sig_bytes_with_hashtype.back() != 0x01) return false;
        Secp256k1PubKey pubkey;
        std::copy(pubkey_bytes.begin(), pubkey_bytes.end(), pubkey.begin());
        Hash160 actual_hash = Hash160Compute(pubkey);
        for (int j = 0; j < 20; ++j) {
            if (actual_hash[j] != expected_hash[j]) return false;
        }
        Secp256k1SigDER sig_bytes(sig_bytes_with_hashtype.begin() + 1,
                                   sig_bytes_with_hashtype.end() - 1);
        // Compute sighash with the same scheme_id binding the signer used.
        Hash256 sighash = ComputeSighash(tx, input_index, script_pubkey, scheme_id);
        return Verify(pubkey, sighash, sig_bytes);
    }

    std::optional<UTXO> GetUTXO(const Hash256& tx_hash, uint32_t index) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return GetUTXONoLock(tx_hash, index);
    }

    // O(1) canonical prevout -> exact spender lookup. The locator is a
    // rebuildable derived index, never a source of consensus truth; validate
    // every locator against the current canonical chain and exact input before
    // returning transaction bytes to recovery/watchtower callers.
    std::optional<CanonicalSpender> GetCanonicalSpender(
        const Hash256& prev_tx_hash, uint32_t prev_out_index) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        const std::string key = UTXOKey(prev_tx_hash, prev_out_index);
        auto it = canonical_spenders_.find(key);
        if (it == canonical_spenders_.end()) return std::nullopt;
        const SpenderLocator& loc = it->second;
        if (loc.block_height >= chain_.size()) return std::nullopt;
        const Block block = LoadCanonicalBlockNoLock_(loc.block_height);
        if (block.height != loc.block_height ||
            loc.tx_index >= block.transactions.size()) {
            return std::nullopt;
        }
        const Transaction& tx = block.transactions[loc.tx_index];
        if (tx.GetTxID() != loc.txid) return std::nullopt;
        bool exact_input = false;
        for (const auto& input : tx.inputs) {
            if (!input.IsCoinbase() && input.prev_tx_hash == prev_tx_hash &&
                input.prev_out_index == prev_out_index) {
                exact_input = true;
                break;
            }
        }
        if (!exact_input) return std::nullopt;
        return CanonicalSpender{tx, loc.block_height, block.GetHash()};
    }

    std::optional<UTXO> GetUTXONoLock(const Hash256& tx_hash, uint32_t index) const {
        if (validation_overlay_) {
            auto it = validation_overlay_->set.find(UTXOKey(tx_hash, index));
            if (it == validation_overlay_->set.end()) return std::nullopt;
            return it->second;
        }
        auto it = utxo_set_.find(UTXOKey(tx_hash, index));
        if (it == utxo_set_.end()) return std::nullopt;
        return it->second;
    }

    uint64_t GetBalance(const std::vector<uint8_t>& script_pubkey) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        std::string sh = ScriptHex(script_pubkey);
        auto it = script_index_.find(sh);
        if (it == script_index_.end()) return 0;
        uint64_t balance = 0;
        for (const auto& ukey : it->second) {
            auto uit = utxo_set_.find(ukey);
            if (uit != utxo_set_.end()) balance += uit->second.value;
        }
        return balance;
    }

    std::vector<UTXO> GetUTXOsForScript(const std::vector<uint8_t>& script_pubkey) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return GetUTXOsForScriptLocked_(script_pubkey);
    }

    std::vector<UTXO> GetUTXOsForScriptLocked_(const std::vector<uint8_t>& script_pubkey) const {
        std::vector<UTXO> result;
        std::string sh = ScriptHex(script_pubkey);
        auto it = script_index_.find(sh);
        if (it != script_index_.end()) {
            for (const auto& ukey : it->second) {
                auto uit = utxo_set_.find(ukey);
                if (uit != utxo_set_.end()) result.push_back(uit->second);
            }
        }
        std::sort(result.begin(), result.end(),
                  [](const UTXO& a, const UTXO& b){ return a.value > b.value; });
        return result;
    }

    std::unordered_map<std::string, uint64_t> GetAllBalances() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        std::unordered_map<std::string, uint64_t> balances;
        for (const auto& [key, utxo] : utxo_set_) {
            std::string script_hex = BytesToHex(utxo.script_pubkey);
            balances[script_hex] += utxo.value;
        }
        return balances;
    }

    std::vector<std::pair<std::string, double>> GetTopHolders(size_t top_n = 50) const {
        auto balances = GetAllBalances();
        using Entry = std::pair<uint64_t, const std::string*>;
        struct MinFirst {
            bool operator()(const Entry& a, const Entry& b) const { return a.first > b.first; }
        };
        std::priority_queue<Entry, std::vector<Entry>, MinFirst> heap;
        for (const auto& kv : balances) {
            if (heap.size() < top_n) {
                heap.push({kv.second, &kv.first});
            } else if (kv.second > heap.top().first) {
                heap.pop();
                heap.push({kv.second, &kv.first});
            }
        }
        std::vector<std::pair<std::string, double>> result;
        result.reserve(heap.size());
        while (!heap.empty()) {
            const auto& [units, hex_ptr] = heap.top();
            const std::string& script_hex = *hex_ptr;
            std::vector<uint8_t> script;
            script.reserve(script_hex.size() / 2);
            for (size_t i = 0; i + 1 < script_hex.size(); i += 2) {
                auto hc = [](char c) -> uint8_t {
                    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
                    if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
                    return (uint8_t)(c - 'A' + 10);
                };
                script.push_back((hc(script_hex[i]) << 4) | hc(script_hex[i+1]));
            }
            std::string addr = ScriptToAddress(script);
            if (!addr.empty())
                result.emplace_back(std::move(addr), (double)units / VELD_UNITS);
            heap.pop();
        }
        std::reverse(result.begin(), result.end());
        return result;
    }

    // Test-only: fast-forward the supply counter so phase-transition tests
    // don't have to mine millions of blocks. Does NOT create UTXOs or blocks —
    // only updates the supply accumulator used by IsStakingActive().
    void SetTotalSupplyForTesting(uint64_t units) {
        total_supply_units_.store(units);
    }

    std::string GetChainInfo() const {
        std::string info;
        info += "Height:        " + std::to_string(Height()) + "\n";
        info += "Supply (VELD): " + std::to_string(TotalSupplyVeld()) + "\n";
        info += "Phase:         " + std::string(IsStakingActive()
                                    ? "Standard (PoW + PoS)"
                                    : "Bootstrap (PoW only)") + "\n";
        info += "Staking:       " + std::string(IsStakingActive() ? "Active" : "Inactive (staking not yet active)") + "\n";
        return info;
    }

    using OnCommitCallback = std::function<bool(const Block&,
        const std::vector<std::pair<Hash256,uint32_t>>&,
        const std::vector<UTXO>&,
        bool from_reorg)>;

    void SetOnCommit(OnCommitCallback cb) { on_commit_ = cb; }

    bool RollbackTip(bool allow_genesis = false) {
        std::unique_lock<std::shared_mutex> lock(chain_mutex_);
        if (chain_.empty() || (chain_.size() == 1 && !allow_genesis)) return false;

        if (canonical_undo_.empty()) return false;
        std::set<std::string> rollback_touched;
        CollectUndoTouchedKeys_(canonical_undo_.back(), rollback_touched);
        Block popped;
        if (!DisconnectCanonicalTipNoLock_(
                popped, /*retain_as_side_branch=*/true)) {
            durability_compromised_.store(true, std::memory_order_release);
            std::cerr << "  [rollback] CRITICAL: bounded undo record is "
                         "missing/corrupt; refusing a partial disconnect.\n";
            std::cerr.flush();
            return false;
        }

        {
            uint64_t new_tip_height = chain_.empty() ? 0 : chain_.size() - 1;
            std::unique_lock<std::shared_mutex> nms_lock(nms_tally_mutex_);
            for (auto it = nms_tally_.seen_payloads.begin();
                 it != nms_tally_.seen_payloads.end(); ) {
                if (it->second > new_tip_height) {
                    it = nms_tally_.seen_payloads.erase(it);
                } else {
                    ++it;
                }
            }
        }

        bool durable_callback_ok = true;
        if (on_rollback_) {
            try {
                on_rollback_(BuildUTXODeltaNoLock_(rollback_touched), popped);
            } catch (const std::exception& e) {
                durable_callback_ok = false;
                std::cerr << "  [rollback] on_rollback_ exception: " << e.what()
                          << " — durable state is unproven; refusing further "
                             "blocks until restart.\n";
                std::cerr.flush();
            } catch (...) {
                durable_callback_ok = false;
                std::cerr << "  [rollback] on_rollback_ unknown exception"
                          << " — durable state is unproven; refusing further "
                             "blocks until restart.\n";
                std::cerr.flush();
            }
        }
        if (!durable_callback_ok) {
            durability_compromised_.store(true, std::memory_order_release);
            return false;
        }
        return true;
    }

    bool DurabilityCompromised() const {
        return durability_compromised_.load(std::memory_order_acquire);
    }

#ifdef VELD_TEST_HOOKS
    bool ReorgRecoveryFramePending() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return pending_reorg_rollback_.has_value();
    }

    std::vector<std::string> ReorgRecoveryOldTailHashes() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        std::vector<std::string> hashes;
        if (!pending_reorg_rollback_) return hashes;
        hashes.reserve(pending_reorg_rollback_->old_tail.size());
        for (const auto& block : pending_reorg_rollback_->old_tail)
            hashes.push_back(HashToHex(block.GetHash()));
        return hashes;
    }

    size_t ReorgProtectedBodyCount() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return reorg_protected_side_hashes_.size();
    }

    bool IsReorgBodyProtected(const Hash256& hash) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return reorg_protected_side_hashes_.count(HashToHex(hash)) != 0;
    }

    void FailNextReorgFrameRestoreForTest() {
        std::unique_lock<std::shared_mutex> lock(chain_mutex_);
        test_fail_next_reorg_frame_restore_ = true;
    }
#endif

    using OnReorgCallback = std::function<void(
        const UTXODelta&, uint64_t ancestor_height,
        const Hash256& ancestor_hash, const Block& old_tip,
        uint64_t old_supply, const Block& intended_new_tip,
        uint64_t intended_new_supply)>;
    void SetOnReorg(OnReorgCallback cb) { on_reorg_ = cb; }

    // Compensation hook used only when a post-Reorganize commit callback
    // rejects after the in-memory reorg succeeded.  The canonical frame has
    // already been restored when this runs; implementations must restore the
    // durable UTXO/tip/per-height metadata to the supplied old canonical
    // suffix and return success.
    using OnReorgAbortCallback = std::function<bool(
        const UTXODelta&, const Block&, uint64_t,
        const std::vector<Block>&)>;
    void SetOnReorgAbort(OnReorgAbortCallback cb) {
        on_reorg_abort_ = std::move(cb);
    }

    // Queried after the complete per-block callback sequence but before the
    // reorg rollback frame and displaced bodies are released. A true result
    // means a durable write outcome is unknowable until restart; callers must
    // retain all recovery data and must not publish orphaned transactions.
    using ReorgPublicationUncertainFn = std::function<bool()>;
    void SetReorgPublicationUncertainFn(
            ReorgPublicationUncertainFn fn) {
        reorg_publication_uncertain_fn_ = std::move(fn);
    }

    using OnRollbackCallback =
        std::function<void(const UTXODelta&, const Block& popped)>;
    void SetOnRollback(OnRollbackCallback cb) { on_rollback_ = cb; }

    // Post-commit reorg notification. It runs only after every replacement
    // block's durable on_commit callback succeeds, without chain_mutex_ held.
    // The vector contains signed non-coinbase transactions in old canonical
    // height/transaction order and may be empty for a coinbase-only reorg;
    // consumers must still use that empty notification for stale-state cleanup.
    using OnOrphanedTxsCallback = std::function<void(
        const std::vector<Transaction>&)>;
    void SetOnOrphanedTxs(OnOrphanedTxsCallback cb) {
        on_orphaned_txs_ = std::move(cb);
    }

    // AMM pool covenant hooks (btcVELD) - wired by node.h to the AmmLedger.
    //   amm_pool_input_check_(prev_script, txid, vout): 1 = the CURRENT committed
    //     pool input (ValidateTransaction sigless-exempts it, trusting the block
    //     guard); -1 = a forged/stale pool-marker UTXO (reject); 0 = not a pool
    //     input (validate normally).
    //   amm_block_validator_(block): false => reject the block (a tx spends the
    //     pool UTXO but is not a valid AMM op). SOLE consensus guard once the
    //     input is exempt.
    //   amm_mempool_validator_(tx,height): the same pure covenant validation on
    //     a one-transaction next-block frame. Mempool admission MUST run this
    //     before accepting a sigless committed-pool spend; otherwise an arbitrary
    //     theft-shaped spend can lock the public outpoint in spent_outputs_ and
    //     poison every locally mined candidate even though block consensus later
    //     rejects it.
    std::function<int(const std::vector<uint8_t>&, const Hash256&, uint32_t)> amm_pool_input_check_;
    std::function<bool(const Block&)>                                         amm_block_validator_;
    using AmmMempoolValidator =
        std::function<bool(const Transaction&, uint64_t)>;
    void SetAmmMempoolValidator(AmmMempoolValidator fn) {
        amm_mempool_validator_ = std::move(fn);
    }
    bool ValidateAmmMempoolCandidate(const Transaction& tx,
                                     uint64_t candidate_height) const {
        // Fail closed for an AMM-shaped transaction if the node did not install
        // the stateful half of the sigless-covenant policy. Mempool calls this
        // only after cheaply proving that the tx carries an AMM marker or
        // touches an AMM pool-marker script, so ordinary payments remain inert.
        if (!amm_mempool_validator_) return false;
        try {
            return amm_mempool_validator_(tx, candidate_height);
        } catch (...) {
            return false;
        }
    }
    AmmMempoolValidator amm_mempool_validator_;

    // TOKEN/MSPV relay policy hook.  Consensus preserves the historical paid
    // no-op rule for a malformed/stale protocol request, but standard mempools
    // must not relay or mine one.  The node supplies an isolated token-ledger
    // dry run against the exact parent state and prospective difficulty.
    using TokenMempoolValidator =
        std::function<bool(const Transaction&, uint64_t, uint32_t)>;
    void SetTokenMempoolValidator(TokenMempoolValidator fn) {
        token_mempool_validator_ = std::move(fn);
    }
    bool ValidateTokenMempoolCandidate(const Transaction& tx,
                                       uint64_t candidate_height,
                                       uint32_t candidate_bits) const {
        if (!token_mempool_validator_) return false;
        try {
            return token_mempool_validator_(tx, candidate_height,
                                            candidate_bits);
        } catch (...) {
            return false;
        }
    }
    TokenMempoolValidator token_mempool_validator_;
    using TokenMempoolBatchFilter = std::function<std::vector<bool>(
        const std::vector<Transaction>&, const std::vector<bool>&,
        uint64_t, uint32_t)>;
    void SetTokenMempoolBatchFilter(TokenMempoolBatchFilter fn) {
        token_mempool_batch_filter_ = std::move(fn);
    }
    std::vector<bool> FilterTokenMempoolCandidates(
            const std::vector<Transaction>& candidates,
            const std::vector<bool>& token_authorization_prevalidated,
            uint64_t candidate_height, uint32_t candidate_bits) const {
        if (!token_mempool_batch_filter_ ||
            token_authorization_prevalidated.size() != candidates.size())
            return std::vector<bool>(candidates.size(), false);
        try {
            auto accepted = token_mempool_batch_filter_(
                candidates, token_authorization_prevalidated,
                candidate_height, candidate_bits);
            if (accepted.size() != candidates.size())
                return std::vector<bool>(candidates.size(), false);
            return accepted;
        } catch (...) {
            return std::vector<bool>(candidates.size(), false);
        }
    }
    TokenMempoolBatchFilter token_mempool_batch_filter_;
    // `candidates` are synchronous borrowed views into Mempool entries.  The
    // caller pins them with its mutex for this invocation; implementations must
    // neither retain the pointers nor dispatch asynchronous work that outlives
    // the callback.
    using TokenAwareMempoolSelector = std::function<std::vector<bool>(
        const std::vector<const Transaction*>&,
        const std::vector<size_t>&, const std::vector<bool>&,
        const std::vector<bool>&,
        size_t, size_t, size_t, size_t, uint64_t, uint32_t)>;
    void SetTokenAwareMempoolSelector(TokenAwareMempoolSelector fn) {
        token_aware_mempool_selector_ = std::move(fn);
    }
    std::vector<bool> SelectTokenAwareMempoolCandidates(
            const std::vector<const Transaction*>& candidates,
            const std::vector<size_t>& serialized_sizes,
            const std::vector<bool>& token_families,
            const std::vector<bool>& token_authorization_prevalidated,
            size_t initial_count, size_t initial_bytes,
            size_t max_count, size_t max_bytes,
            uint64_t candidate_height, uint32_t candidate_bits) const {
        if (!token_aware_mempool_selector_) {
            // Standalone/test chains without a token ledger retain ordinary
            // payment selection, but fail closed for stateful TOKEN/MSPV ops.
            std::vector<bool> selected(candidates.size(), false);
            if (serialized_sizes.size() != candidates.size() ||
                token_families.size() != candidates.size() ||
                token_authorization_prevalidated.size() != candidates.size() ||
                initial_count > max_count || initial_bytes > max_bytes)
                return selected;
            size_t count = initial_count, bytes = initial_bytes;
            for (size_t i = 0; i < candidates.size(); ++i) {
                if (!candidates[i] || token_families[i] ||
                    count >= max_count || bytes > max_bytes ||
                    serialized_sizes[i] > max_bytes - bytes)
                    continue;
                selected[i] = true;
                ++count;
                bytes += serialized_sizes[i];
            }
            return selected;
        }
        try {
            auto selected = token_aware_mempool_selector_(
                candidates, serialized_sizes, token_families,
                token_authorization_prevalidated,
                initial_count, initial_bytes, max_count, max_bytes,
                candidate_height, candidate_bits);
            if (selected.size() != candidates.size())
                return std::vector<bool>(candidates.size(), false);
            return selected;
        } catch (...) {
            return std::vector<bool>(candidates.size(), false);
        }
    }
    TokenAwareMempoolSelector token_aware_mempool_selector_;

    using ModulePrecommitValidator = std::function<bool(const Block&, uint64_t)>;
    void SetModulePrecommitValidator(ModulePrecommitValidator fn) {
        module_precommit_validator_ = std::move(fn);
    }
    // btcVELD Layer-2 anchor fork-choice gate (a DYNAMIC, Bitcoin-anchored checkpoint) —
    // wired by node.h to AnchorSet::Allows. false => this block is at a Bitcoin-anchored
    // height but its hash differs → reject regardless of PoW work. Inert (anchors_ empty)
    // until anchoring is armed, so consensus is byte-identical while dormant.
    std::function<bool(uint64_t, const Hash256&)>                             anchor_gate_;

    // Permanent-anchor carrier-preservation gate. ReorganizeBounded_ supplies
    // the actual common ancestor before any disconnect; false means the branch
    // would erase the retained-QC carrier which authorized the highest Bitcoin
    // checkpoint, even if it happens to share the checkpoint target itself.
    // Arguments are (actual common ancestor, current canonical tip).  The tip
    // lets a startup-imported future floor remain pending during IBD and begin
    // preserving its authorization carrier only after that carrier has
    // actually been reached on the canonical chain.
    std::function<bool(uint64_t, uint64_t)>                                   anchor_reorg_gate_;

    // btcVELD Layer-3 finalized-target gate.  ReorganizeBounded_ supplies the
    // ACTUAL canonical common ancestor after resolving the complete stored side
    // branch and before disconnecting a single block.  false means the branch
    // would rewrite the target. Necessary but insufficient for activation
    // until the engine also preserves its authenticated QC/carrier.
    std::function<bool(uint64_t)>                                             finality_reorg_gate_;

    //  #1:
    // *** NO LOCK. THE CALLER MUST ALREADY HOLD chain_mutex_ (unique). ***
    // Iterating utxo_set_ here concurrently with an AddBlockDirect / Reorganize
    // mutation is UNDEFINED BEHAVIOUR (unordered_map iteration during
    // insert/erase). Callers that do NOT hold the lock MUST call
    // SnapshotUTXOsForLevelDB_Locked() instead — it acquires shared_lock for
    // them. The `_NoLock` / `_Locked` suffix pair now states the contract at
    // every call site (previously the bare name hid it).
    std::vector<std::pair<std::string, std::string>> SnapshotUTXOsForLevelDB_NoLock() const {
        std::vector<std::pair<std::string, std::string>> kvs;
        kvs.reserve(utxo_set_.size());
        for (const auto& [key, utxo] : utxo_set_) {
            std::string lkey = "u:" + key;
            std::string lval(9 + utxo.script_pubkey.size(), '\0');
            for (int i = 0; i < 8; ++i) lval[i] = (char)((utxo.value >> (i*8)) & 0xff);
            lval[8] = (char)(utxo.script_pubkey.size() & 0xff);
            std::copy(utxo.script_pubkey.begin(), utxo.script_pubkey.end(), lval.begin() + 9);
            kvs.emplace_back(std::move(lkey), std::move(lval));
        }
        return kvs;
    }

    // Thread-safe snapshot for callers that do not already hold chain_mutex_.
    // Reorganization paths use the no-lock variant while holding the unique
    // lock; callback paths use this shared-lock wrapper.
    std::vector<std::pair<std::string, std::string>> SnapshotUTXOsForLevelDB_Locked() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return SnapshotUTXOsForLevelDB_NoLock();
    }

    struct UtxoSetProbe {
        size_t set_size;
        bool   has_target;
    };
    UtxoSetProbe ProbeUtxoSet(const Hash256& tx_hash, uint32_t index) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        UtxoSetProbe p;
        p.set_size = utxo_set_.size();
        p.has_target = (utxo_set_.find(UTXOKey(tx_hash, index)) != utxo_set_.end());
        return p;
    }

public:
    static uint64_t ExpectedBlockSubsidy(uint64_t height) noexcept {
        uint64_t s = BLOCK_REWARD_UNITS;
        if (height > 0 && (height % BLOCKS_PER_YEAR) == 0)
            s += ANNUAL_EMISSION_REMAINDER;
        return s;
    }

    // The single authoritative native-supply transition used by live commit,
    // precommit, UTXO rebuild, startup replay, reorg replay, and the alternate
    // module overlay.  Coinbase may include recycled transaction fees; only
    // the emission basis increases supply.  The update is fail-closed and
    // leaves `supply_units` untouched on malformed output-sum overflow or a
    // corrupt starting value above the cap.
    static bool AdvanceCanonicalSupply(const Block& block,
                                       uint64_t& supply_units) noexcept {
        if (supply_units > MAX_SUPPLY_UNITS) return false;
        if (block.transactions.empty()) return true;

        uint64_t coinbase_total = 0;
        for (const auto& out : block.transactions[0].outputs) {
            if (out.value > UINT64_MAX - coinbase_total) return false;
            coinbase_total += out.value;
        }
        const uint64_t subsidy = ExpectedBlockSubsidy(block.height);
        uint64_t emission = std::min(coinbase_total, subsidy);
        emission = std::min(emission, MAX_SUPPLY_UNITS - supply_units);
        supply_units += emission;
        return true;
    }

    uint64_t TotalFeesCollectedUnits() const { return total_fees_collected_units_.load(); }
    double   TotalFeesCollectedVeld()  const { return (double)total_fees_collected_units_.load() / VELD_UNITS; }
    void     AddFeesCollected(uint64_t units) { total_fees_collected_units_.fetch_add(units); }
    void     SetFeesCollected(uint64_t units) { total_fees_collected_units_.store(units); }

private:
    std::atomic<uint64_t>                   staking_activation_units_{STAKING_ACTIVATION_SUPPLY};
    mutable std::shared_mutex               chain_mutex_;
    mutable std::mutex                      block_connect_mutex_;
    std::atomic<uint64_t>                   atomic_height_{0};
    std::atomic<uint64_t>                   local_validation_ceiling_{0};
    std::atomic<uint64_t>                   total_supply_units_{0};
    std::atomic<uint64_t>                   total_fees_collected_units_{0};
    std::atomic<bool>                       durability_compromised_{false};
    std::vector<Block>                      chain_;
    std::unordered_map<std::string, size_t> block_index_;
    HistoricalBlockLoader                   historical_block_loader_;
    DurableBlockBodyWriter                  durable_block_body_writer_;
    DurableBlockBodyEraser                  durable_block_body_eraser_;
    std::optional<uint64_t>                 durable_canonical_height_;
    uint64_t                                next_body_prune_height_{0};
#ifdef VELD_TEST_HOOKS
    mutable std::atomic<uint64_t>           test_block_body_lookup_count_{0};
    mutable std::atomic<bool>               test_force_rebuild_utxo_miss_{false};
#endif

    Block LoadCanonicalBlockNoLock_(uint64_t height) const {
#ifdef VELD_TEST_HOOKS
        test_block_body_lookup_count_.fetch_add(1, std::memory_order_relaxed);
#endif
        if (height >= chain_.size())
            throw std::out_of_range("Block height out of range");
        const Block& skeleton = chain_[height];
        if (!skeleton.transactions.empty()) return skeleton;
        if (!historical_block_loader_) {
            throw std::runtime_error(
                "historical canonical block body is not resident and no "
                "durable loader is installed");
        }

        const Hash256 expected_hash = skeleton.GetHash();
        const BlockHeader expected_header = skeleton.header;
        auto raw = historical_block_loader_(expected_hash);
        if (!raw) {
            throw std::runtime_error(
                "historical canonical block body is missing for height " +
                std::to_string(height));
        }
        if (raw->size() > MAX_BLOCK_SIZE) {
            throw std::runtime_error(
                "historical canonical block exceeds MAX_BLOCK_SIZE at height " +
                std::to_string(height));
        }

        Block loaded;
        const size_t consumed = Block::Deserialize(*raw, 0, loaded);
        if (consumed == 0 || consumed != raw->size() ||
            loaded.Serialize() != *raw) {
            throw std::runtime_error(
                "historical canonical block has non-canonical/corrupt bytes at height " +
                std::to_string(height));
        }
        loaded.height = height;
        if (loaded.GetHash() != expected_hash ||
            loaded.header.Serialize() != expected_header.Serialize() ||
            loaded.transactions.empty() ||
            !loaded.transactions.front().IsCoinbase() ||
            ComputeMerkleRoot(loaded.transactions) != loaded.header.merkle_root ||
            loaded.SerializedSize() != raw->size()) {
            throw std::runtime_error(
                "historical canonical block fails header/hash/merkle binding at height " +
                std::to_string(height));
        }
        return loaded;
    }

    Block LoadIndexedBlockNoLock_(const std::string& hash_hex) const {
#ifdef VELD_TEST_HOOKS
        test_block_body_lookup_count_.fetch_add(1, std::memory_order_relaxed);
#endif
        auto tree_it = block_tree_.find(hash_hex);
        auto store_it = block_store_.find(hash_hex);
        if (tree_it == block_tree_.end() || store_it == block_store_.end())
            throw std::runtime_error("indexed side block is missing");
        const Block& skeleton = store_it->second;
        if (!skeleton.transactions.empty()) return skeleton;
        if (!historical_block_loader_)
            throw std::runtime_error(
                "side block body is evicted and no durable loader is installed");
        auto raw = historical_block_loader_(tree_it->second.hash);
        if (!raw || raw->size() > MAX_BLOCK_SIZE)
            throw std::runtime_error("durable side block body is missing/oversize");
        Block loaded;
        const size_t consumed = Block::Deserialize(*raw, 0, loaded);
        if (consumed == 0 || consumed != raw->size() ||
            loaded.Serialize() != *raw) {
            throw std::runtime_error(
                "durable side block has non-canonical/corrupt bytes");
        }
        loaded.height = tree_it->second.height;
        if (loaded.GetHash() != tree_it->second.hash ||
            loaded.header.Serialize() != skeleton.header.Serialize() ||
            loaded.transactions.empty() ||
            !loaded.transactions.front().IsCoinbase() ||
            ComputeMerkleRoot(loaded.transactions) != loaded.header.merkle_root ||
            loaded.SerializedSize() != raw->size()) {
            throw std::runtime_error(
                "durable side block fails header/hash/merkle binding");
        }
        return loaded;
    }

    void PruneDurableCanonicalBodiesNoLock_() {
        if (!historical_block_loader_ || !durable_canonical_height_ ||
            chain_.empty()) return;
        const uint64_t tip = static_cast<uint64_t>(chain_.size() - 1);
        if (tip + 1 <= CANONICAL_BODY_RETENTION_BLOCKS) return;
        const uint64_t keep_from =
            tip + 1 - CANONICAL_BODY_RETENTION_BLOCKS;
        const uint64_t prune_end =
            std::min<uint64_t>(keep_from,
                               *durable_canonical_height_ + 1);
        while (next_body_prune_height_ < prune_end) {
            Block& block = chain_[next_body_prune_height_++];
            if (block.transactions.empty()) continue;
            block.transactions.clear();
            block.transactions.shrink_to_fit();
        }
    }

    std::unordered_map<std::string, UTXO>   utxo_set_;
    std::unordered_map<std::string, std::unordered_set<std::string>> script_index_;
    std::unordered_map<std::string, SpenderLocator> canonical_spenders_;
    static std::string ScriptHex(const std::vector<uint8_t>& spk) {
        std::string h; h.reserve(spk.size()*2);
        static const char* hc = "0123456789abcdef";
        for (uint8_t b : spk) { h.push_back(hc[b>>4]); h.push_back(hc[b&0xF]); }
        return h;
    }
    void ScriptIndexAdd(const std::string& utxo_key, const std::vector<uint8_t>& spk) {
        script_index_[ScriptHex(spk)].insert(utxo_key);
    }
    void ScriptIndexRemove(const std::string& utxo_key, const std::vector<uint8_t>& spk) {
        auto it = script_index_.find(ScriptHex(spk));
        if (it != script_index_.end()) {
            it->second.erase(utxo_key);
            if (it->second.empty()) script_index_.erase(it);
        }
    }
    bool EraseUTXO(const Hash256& tx_hash, uint32_t index) {
        std::string key = UTXOKey(tx_hash, index);
        auto it = utxo_set_.find(key);
        if (it == utxo_set_.end()) return false;
        ScriptIndexRemove(key, it->second.script_pubkey);
        utxo_set_.erase(it);
        return true;
    }
    void InsertUTXO(const UTXO& utxo) {
        if (!utxo.script_pubkey.empty() && utxo.script_pubkey[0] == 0x6A)
            return;
        std::string key = UTXOKey(utxo.tx_hash, utxo.output_index);
        utxo_set_[key] = utxo;
        ScriptIndexAdd(key, utxo.script_pubkey);
    }

    struct CanonicalBlockUndo {
        uint64_t height{0};
        Hash256 hash{};
        uint64_t supply_before{0};
        uint64_t fees_before{0};
        std::vector<UTXO> parent_spent;
        std::vector<std::pair<Hash256, uint32_t>> created_outpoints;
        std::vector<std::pair<Hash256, uint32_t>> created_unspent_outpoints;
    };
    std::deque<CanonicalBlockUndo> canonical_undo_;

    static void CollectUndoTouchedKeys_(
            const CanonicalBlockUndo& undo,
            std::set<std::string>& keys) {
        for (const auto& u : undo.parent_spent)
            keys.insert(UTXOKey(u.tx_hash, u.output_index));
        for (const auto& [txid, vout] : undo.created_outpoints)
            keys.insert(UTXOKey(txid, vout));
    }

    UTXODelta BuildUTXODeltaNoLock_(
            const std::set<std::string>& touched) const {
        UTXODelta delta;
        delta.reserve(touched.size());
        for (const auto& key : touched) {
            auto it = utxo_set_.find(key);
            if (it == utxo_set_.end())
                delta.push_back(UTXODeltaEntry{key, std::nullopt});
            else
                delta.push_back(UTXODeltaEntry{key, it->second});
        }
        return delta;
    }

    bool DisconnectCanonicalTipNoLock_(Block& popped,
                                       bool retain_as_side_branch) {
        if (chain_.empty()) return false;
        popped = LoadCanonicalBlockNoLock_(chain_.size() - 1);
        if (canonical_undo_.empty()) return false;
        const CanonicalBlockUndo& undo = canonical_undo_.back();
        if (undo.height != popped.height || undo.hash != popped.GetHash())
            return false;
        if (miner_undo_.empty() ||
            miner_undo_.back().height != popped.height ||
            miner_undo_.back().hash != popped.GetHash()) return false;

        // Parent-spent outputs must not already exist in the post-block frame.
        // Check before mutating so corruption cannot create a half-disconnect.
        for (const auto& u : undo.parent_spent) {
            if (utxo_set_.count(UTXOKey(u.tx_hash, u.output_index)) != 0)
                return false;
        }
        // Every created output not consumed later in the same block must still
        // exist.  Missing one indicates a corrupt post-block frame; silently
        // ignoring EraseUTXO would otherwise publish a plausible but inexact
        // rollback.
        for (const auto& [txid, vout] : undo.created_unspent_outpoints) {
            if (utxo_set_.count(UTXOKey(txid, vout)) == 0) return false;
        }

        UnindexCanonicalSpendersForBlockNoLock(popped);
        for (const auto& [txid, vout] : undo.created_outpoints)
            (void)EraseUTXO(txid, vout); // an in-block child may already spend it
        for (const auto& u : undo.parent_spent) InsertUTXO(u);
        total_supply_units_.store(undo.supply_before);
        total_fees_collected_units_.store(undo.fees_before);

        if (!UndoMinerCoinbaseNoLock_(popped)) return false;

        const std::string hash_hex = HashToHex(popped.GetHash());
        block_index_.erase(hash_hex);
        chain_.pop_back();
        atomic_height_.store(chain_.empty() ? 0 : chain_.size() - 1);
        auto tree_it = block_tree_.find(hash_hex);
        if (tree_it != block_tree_.end()) tree_it->second.on_main_chain = false;
        if (retain_as_side_branch) {
            block_store_[hash_hex] = popped;
            if (durable_block_body_writer_ && historical_block_loader_ &&
                !volatile_side_quarantine_.count(hash_hex)) {
                block_store_[hash_hex].transactions.clear();
                block_store_[hash_hex].transactions.shrink_to_fit();
            }
            side_branch_hashes_.insert(hash_hex);
        }
        canonical_undo_.pop_back();
        return true;
    }

    using CanonicalSpenderAddition =
        std::pair<std::string, SpenderLocator>;

    // Caller holds chain_mutex_ in unique mode. Build the complete mutation
    // list without changing canonical state so this preflight can run before a
    // newly accepted body crosses the durable/publication boundary.
    bool PrepareCanonicalSpendersForBlockNoLock(
            const Block& block,
            std::vector<CanonicalSpenderAddition>& additions) const {
        additions.clear();
        std::unordered_set<std::string> seen;
        for (size_t ti = 0; ti < block.transactions.size(); ++ti) {
            if (ti > UINT32_MAX) return false;
            const Transaction& tx = block.transactions[ti];
            if (tx.IsCoinbase()) continue;
            const Hash256 txid = tx.GetTxID();
            for (const auto& input : tx.inputs) {
                const std::string key = UTXOKey(
                    input.prev_tx_hash, input.prev_out_index);
                if (!seen.insert(key).second ||
                    canonical_spenders_.count(key)) {
                    return false;
                }
                additions.push_back({
                    key,
                    SpenderLocator{block.height,
                                   static_cast<uint32_t>(ti), txid}
                });
            }
        }
        return true;
    }

    void ApplyCanonicalSpendersForBlockNoLock(
            std::vector<CanonicalSpenderAddition>& additions) {
        for (auto& addition : additions)
            canonical_spenders_.emplace(std::move(addition));
    }

    void UnindexCanonicalSpendersForBlockNoLock(const Block& block) {
        for (size_t ti = 0; ti < block.transactions.size(); ++ti) {
            const Transaction& tx = block.transactions[ti];
            if (tx.IsCoinbase()) continue;
            const Hash256 txid = tx.GetTxID();
            for (const auto& input : tx.inputs) {
                const std::string key = UTXOKey(
                    input.prev_tx_hash, input.prev_out_index);
                auto it = canonical_spenders_.find(key);
                if (it != canonical_spenders_.end() &&
                    it->second.block_height == block.height &&
                    it->second.txid == txid) {
                    canonical_spenders_.erase(it);
                }
            }
        }
    }

    // Extract only real miner payout identities; protocol custody scripts are
    // not mining identities.
    static std::vector<std::string> MinerScriptsForBlock_(const Block& block) {
        std::vector<std::string> scripts;
        if (block.transactions.empty()) return scripts;
        const auto vault_script =
            AddressToScript(VaultAddressAtHeight(block.height));
        const auto pool_script =
            AddressToScript(PoolAddressAtHeight(block.height));
        const auto endorse_script =
            AddressToScript(EndorsementPoolAddressAtHeight(block.height));
        const auto stake_vault_script =
            AddressToScript(StakeVaultAddressAtHeight(block.height));
        const auto bond_yield_script =
            AddressToScript(BondYieldEscrowAtHeight(block.height));
        std::unordered_set<std::string> counted;
        for (const auto& out : block.transactions[0].outputs) {
            const auto& s = out.script_pubkey;
            if (s == vault_script || s == pool_script ||
                s == endorse_script || s == stake_vault_script ||
                s == bond_yield_script) continue;
            if (s.size() != 25 || s[0] != 0x76 || s[1] != 0xA9 ||
                s[2] != 0x14 || s[23] != 0x88 || s[24] != 0xAC)
                continue;
            const auto hex = BytesToHex(s);
            if (counted.insert(hex).second) scripts.push_back(hex);
        }
        return scripts;
    }

    struct MinerBlockUndo {
        uint64_t height{0};
        Hash256 hash{};
        std::vector<std::string> incremented;
        std::map<std::string, std::vector<uint64_t>> pruned;
    };

    void PruneMinerHistoryKeyNoLock_(const std::string& script_hex,
                                     uint64_t cutoff_inclusive,
                                     std::vector<uint64_t>* removed = nullptr) {
        auto it = miner_heights_.find(script_hex);
        if (it == miner_heights_.end()) return;
        auto& heights = it->second;
        // No observation outside the longest tier window affects consensus.
        // Erase the key when its final hot observation retires; retaining one
        // stale height per lifetime identity would make consensus cardinality
        // linear under maximum payout-script rotation.
        while (!heights.empty() && heights.front() <= cutoff_inclusive) {
            if (removed) removed->push_back(heights.front());
            heights.pop_front();
        }
        if (heights.empty()) miner_heights_.erase(it);
    }

    // Caller holds chain_mutex_ in unique mode. Forward commits, ancestor
    // rebuilds, and alt-branch apply must share this exact implementation:
    // these indexes drive governance eligibility and miner tier windows.
    void IndexMinerCoinbaseNoLock(const Block& block) {
        MinerBlockUndo undo;
        undo.height = block.height;
        undo.hash = block.GetHash();
        const auto current_scripts = MinerScriptsForBlock_(block);
        for (const auto& hex : current_scripts) {
            miner_heights_[hex].push_back(block.height);
            undo.incremented.push_back(hex);
        }

        if (block.height >= MAX_MINER_TIER_HISTORY_BLOCKS) {
            const uint64_t cutoff =
                block.height - MAX_MINER_TIER_HISTORY_BLOCKS;
            // Forward CommitBlock indexes before pushing `block`.  The exact
            // cutoff body may already be evicted; the strict durable loader is
            // safe under the caller's unique chain lock.
            if (cutoff < chain_.size()) {
                for (const auto& hex : MinerScriptsForBlock_(
                         LoadCanonicalBlockNoLock_(cutoff))) {
                    PruneMinerHistoryKeyNoLock_(
                        hex, cutoff, &undo.pruned[hex]);
                }
            }
        }

        for (auto it = undo.pruned.begin(); it != undo.pruned.end(); ) {
            if (it->second.empty()) it = undo.pruned.erase(it);
            else ++it;
        }
        miner_undo_.push_back(std::move(undo));
        while (miner_undo_.size() > MAX_REORG_DEPTH + 1)
            miner_undo_.pop_front();
    }

    bool UndoMinerCoinbaseNoLock_(const Block& block) {
        if (miner_undo_.empty() ||
            miner_undo_.back().height != block.height ||
            miner_undo_.back().hash != block.GetHash()) {
            return false;
        }
        const MinerBlockUndo& undo = miner_undo_.back();
        for (const auto& hex : undo.incremented) {
            auto hit = miner_heights_.find(hex);
            if (hit == miner_heights_.end() || hit->second.empty() ||
                hit->second.back() != block.height) return false;
        }
        for (auto it = undo.incremented.rbegin();
             it != undo.incremented.rend(); ++it) {
            const std::string& hex = *it;
            auto hit = miner_heights_.find(hex);
            hit->second.pop_back();
            if (hit->second.empty()) miner_heights_.erase(hit);
        }
        for (const auto& [hex, removed] : undo.pruned) {
            auto& heights = miner_heights_[hex];
            for (auto it = removed.rbegin(); it != removed.rend(); ++it)
                heights.push_front(*it);
        }
        miner_undo_.pop_back();
        return true;
    }
    std::unordered_map<std::string, std::deque<uint64_t>> miner_heights_;
    std::deque<MinerBlockUndo> miner_undo_;
    MinerArchiveLookup miner_archive_lookup_;
#ifdef VELD_TEST_HOOKS
public:
    void TestSetMinerHeights(const std::string& script_hex,
                             std::vector<uint64_t> heights) {
        std::unique_lock<std::shared_mutex> lock(chain_mutex_);
        miner_heights_[script_hex] =
            std::deque<uint64_t>(heights.begin(), heights.end());
    }
    size_t TestMinerHistorySize(const std::string& script_hex) const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        auto it = miner_heights_.find(script_hex);
        return it == miner_heights_.end() ? 0u : it->second.size();
    }
    size_t TestMinerIdentityCount() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        return miner_heights_.size();
    }
private:
#endif
    OnCommitCallback                        on_commit_;
    OnReorgCallback                         on_reorg_;
    OnReorgAbortCallback                    on_reorg_abort_;
    ReorgPublicationUncertainFn             reorg_publication_uncertain_fn_;
    OnRollbackCallback                      on_rollback_;
    OnOrphanedTxsCallback                   on_orphaned_txs_;
    ModulePrecommitValidator                module_precommit_validator_;
    CanonicalWorkTransitionFn               canonical_work_transition_fn_;
    mutable std::mutex                      local_work_admission_prepare_mutex_;
    LocalWorkAdmissionPrepareFn             local_work_admission_prepare_fn_;
#ifdef VELD_TEST_HOOKS
    std::function<void()>                   test_local_work_pre_commit_barrier_;
#endif

    std::function<uint64_t(const std::string&)> staked_for_addr_;
    std::function<uint64_t(const std::string&, uint64_t)>
        mature_stake_for_addr_;
    std::function<uint64_t()> effective_min_stake_;
    std::function<std::unordered_map<std::string, uint64_t>()> all_active_stakes_;
    std::function<bool(const Block&)> stake_block_validator_;
public:
    void SetStakedForAddrFn(std::function<uint64_t(const std::string&)> fn) {
        staked_for_addr_ = std::move(fn);
    }
    void SetMatureStakeForAddrFn(
            std::function<uint64_t(const std::string&, uint64_t)> fn) {
        mature_stake_for_addr_ = std::move(fn);
    }
    void SetEffectiveMinStakeFn(std::function<uint64_t()> fn) {
        effective_min_stake_ = std::move(fn);
    }
    void SetAllActiveStakesFn(
            std::function<std::unordered_map<std::string, uint64_t>()> fn) {
        all_active_stakes_ = std::move(fn);
    }
    void SetStakeBlockValidatorFn(std::function<bool(const Block&)> fn) {
        stake_block_validator_ = std::move(fn);
    }
    bool StakeTransactionValid(const Transaction& tx, uint64_t height) const {
        if (!StakeOutpointBackingActive(height)) return true;
        if (!stake_block_validator_) return false;
        Block candidate;
        candidate.height = height;
        candidate.transactions.push_back(tx);
        return stake_block_validator_(candidate);
    }
    uint64_t GetStakedForAddr(const std::string& addr) const {
        return staked_for_addr_ ? staked_for_addr_(addr) : 0;
    }
    uint64_t GetMatureStakeForAddr(const std::string& addr,
                                   uint64_t height) const {
        return mature_stake_for_addr_
            ? mature_stake_for_addr_(addr, height) : 0;
    }
    uint64_t GetEffectiveMinStakeUnits() const {
        return effective_min_stake_
            ? effective_min_stake_() : MIN_STAKE_UNITS;
    }
    size_t GetActiveStakeAddressCount() const {
        if (!all_active_stakes_) return 0;
        return all_active_stakes_().size();
    }

    struct ChainTipInfo {
        uint64_t   height;
        Hash256    hash;
        uint64_t   branchlen;
        std::string cumulative_work;
        std::string status;
    };
    std::vector<ChainTipInfo> GetChainTips() const {
        std::shared_lock<std::shared_mutex> lock(chain_mutex_);
        std::vector<ChainTipInfo> tips;
        // Build a set of every prev_hash referenced — anything in
        // block_tree_ NOT in this set is a tip.
        std::unordered_set<std::string> referenced_as_prev;
        referenced_as_prev.reserve(block_tree_.size());
        for (const auto& kv : block_tree_) {
            if (volatile_side_quarantine_.count(kv.first)) continue;
            referenced_as_prev.insert(HashToHex(kv.second.prev_hash));
        }
        std::string main_tip_hex;
        if (!chain_.empty()) {
            main_tip_hex = HashToHex(chain_.back().GetHash());
        }
        for (const auto& kv : block_tree_) {
            const auto& entry = kv.second;
            const std::string& hex = kv.first;
            if (volatile_side_quarantine_.count(hex)) continue;
            if (referenced_as_prev.count(hex)) continue;
            ChainTipInfo info;
            info.height          = entry.height;
            info.hash            = entry.hash;
            info.cumulative_work = entry.cumulative_work.ToHex();
            uint64_t bl = 0;
            std::string cursor_hex = hex;
            const int MAX_BRANCH_WALK = 1024;
            for (int i = 0; i < MAX_BRANCH_WALK; ++i) {
                auto cit = block_tree_.find(cursor_hex);
                if (cit == block_tree_.end()) break;
                if (cit->second.on_main_chain) break;
                cursor_hex = HashToHex(cit->second.prev_hash);
                ++bl;
            }
            info.branchlen = bl;
            if (hex == main_tip_hex)            info.status = "active";
            else if (entry.on_main_chain)        info.status = "valid-fork";
            else if (block_store_.count(hex))   info.status = "valid-fork";
            else                                 info.status = "unknown";
            tips.push_back(std::move(info));
        }
        return tips;
    }
private:

    std::unordered_map<std::string, ChainIndexEntry> block_tree_;

    std::unordered_map<std::string, Block> block_store_;
    std::unordered_set<std::string> side_branch_hashes_;
    // Side bodies remain volatile until the complete candidate suffix has
    // passed VBFR against its reconstructed branch state.  This set is bounded
    // by the ordinary side-header/body caps and is never consulted as a
    // consensus validity cache.
    std::unordered_set<std::string> volatile_side_quarantine_;
    // Exactly one owning admission record per retained side block. Cardinality
    // is therefore bounded by MAX_SIDE_BRANCH_HEADERS and pruning erases the
    // context with the body/header. `reorg_pow_verified_` records only a
    // successful expensive replay check, allowing a later bounded retry to
    // make progress after a transient budget/dataset refusal.
    std::unordered_map<std::string, mining::PowAdmissionContext>
        side_pow_admission_;
    std::unordered_set<std::string> reorg_pow_verified_;
    struct DeferredReorgRetry {
        std::chrono::steady_clock::time_point retry_after{};
        uint8_t exponent{0};
    };
    std::unordered_map<std::string, DeferredReorgRetry>
        deferred_reorg_retry_;
    static constexpr uint64_t REORG_RETRY_BASE_MS = 1'000;
    static constexpr uint64_t REORG_RETRY_MAX_MS = 60'000;
    std::string register_failure_tag_;
    // Displaced canonical bodies remain crash-recovery data until the complete
    // replacement suffix has passed every durable callback.  Capacity pruning
    // must never delete them during that transaction window.
    std::unordered_set<std::string> reorg_protected_side_hashes_;

    static constexpr size_t MAX_SIDE_BRANCH_HEADERS =
        SIDE_BRANCH_HEADER_LIMIT;
    static constexpr uint64_t MAX_SIDE_BRANCH_RESIDENT_BYTES =
        SIDE_BRANCH_DURABLE_BYTE_LIMIT;

    bool PruneSideBranchStateNoLock_(bool force = false) {
        if (side_branch_hashes_.empty()) return true;
        bool cleanup_ok = true;
        bool changed = false;
        auto erase_durable_side_body = [&](const std::string& hash) -> bool {
            // Quarantined bytes have never crossed the durable-writer boundary.
            // Pruning them is an in-memory erase only.
            if (volatile_side_quarantine_.count(hash)) return true;
            if (!durable_block_body_eraser_) return true;
            try {
                return durable_block_body_eraser_(HexToHash(hash));
            } catch (...) {
                return false;
            }
        };
        auto resident_body_bytes = [&]() -> uint64_t {
            uint64_t total = 0;
            for (const auto& hash : side_branch_hashes_) {
                auto body = block_store_.find(hash);
                if (body == block_store_.end() ||
                    body->second.transactions.empty()) continue;
                const size_t n = body->second.SerializedSize();
                if (n > UINT64_MAX - total) return UINT64_MAX;
                total += static_cast<uint64_t>(n);
            }
            return total;
        };
        auto has_bad_ancestor = [&](const std::string& start) -> bool {
            std::unordered_set<std::string> seen;
            std::string cursor = start;
            for (size_t hops = 0; hops <= MAX_SIDE_BRANCH_HEADERS; ++hops) {
                if (bad_alt_tips_.count(cursor)) return true;
                if (!seen.insert(cursor).second) return true;
                auto tree = block_tree_.find(cursor);
                if (tree == block_tree_.end() ||
                    tree->second.on_main_chain) return false;
                cursor = HashToHex(tree->second.prev_hash);
            }
            return true;
        };

        uint64_t resident_bytes = resident_body_bytes();
        if (!force &&
            side_branch_hashes_.size() <= MAX_SIDE_BRANCH_HEADERS &&
            resident_bytes <= MAX_SIDE_BRANCH_RESIDENT_BYTES)
            return true;

        // Purge stale, corrupt and known-invalid suffixes before ranking live
        // candidates.  A failed durable deletion is a resource-safety failure:
        // retain the in-memory index for retry/evidence and latch admission.
        const uint64_t tip = chain_.empty() ? 0 : chain_.back().height;
        for (auto it = side_branch_hashes_.begin();
             it != side_branch_hashes_.end(); ) {
            const std::string hash = *it;
            if (reorg_protected_side_hashes_.count(hash)) {
                ++it;
                continue;
            }
            auto tree = block_tree_.find(hash);
            const bool inconsistent =
                tree == block_tree_.end() || tree->second.on_main_chain;
            const bool stale =
                tree != block_tree_.end() && !tree->second.on_main_chain &&
                !chain_.empty() && tip + 1 >= tree->second.height &&
                tip + 1 - tree->second.height >= MAX_REORG_DEPTH;
            const bool known_bad =
                tree != block_tree_.end() && !tree->second.on_main_chain &&
                has_bad_ancestor(hash);
            if (!inconsistent && !stale && !known_bad) {
                ++it;
                continue;
            }
            // Never delete durable bytes for an entry unexpectedly marked
            // canonical; only repair the redundant side bookkeeping.
            if (!inconsistent ||
                (tree != block_tree_.end() && !tree->second.on_main_chain)) {
                if (!erase_durable_side_body(hash)) {
                    cleanup_ok = false;
                    ++it;
                    continue;
                }
            }
            if (tree != block_tree_.end() && !tree->second.on_main_chain)
                block_tree_.erase(tree);
            block_store_.erase(hash);
            side_pow_admission_.erase(hash);
            reorg_pow_verified_.erase(hash);
            deferred_reorg_retry_.erase(hash);
            bad_alt_tips_.erase(hash);
            volatile_side_quarantine_.erase(hash);
            it = side_branch_hashes_.erase(it);
            changed = true;
        }

        resident_bytes = resident_body_bytes();
        if (side_branch_hashes_.size() <= MAX_SIDE_BRANCH_HEADERS &&
            resident_bytes <= MAX_SIDE_BRANCH_RESIDENT_BYTES) {
            if (!cleanup_ok)
                durability_compromised_.store(true,
                                              std::memory_order_release);
            return cleanup_ok;
        }

        std::unordered_set<std::string> referenced;
        referenced.reserve(side_branch_hashes_.size());
        for (const auto& hash : side_branch_hashes_) {
            auto tree = block_tree_.find(hash);
            if (tree != block_tree_.end())
                referenced.insert(HashToHex(tree->second.prev_hash));
        }
        std::vector<std::string> tips;
        for (const auto& hash : side_branch_hashes_) {
            if (!referenced.count(hash) && block_tree_.count(hash))
                tips.push_back(hash);
        }
        std::sort(tips.begin(), tips.end(),
            [&](const std::string& a, const std::string& b) {
                const auto& ea = block_tree_.at(a);
                const auto& eb = block_tree_.at(b);
                if (ea.cumulative_work != eb.cumulative_work)
                    return ea.cumulative_work > eb.cumulative_work;
                if (ea.height != eb.height) return ea.height > eb.height;
                return a < b;
            });

        std::unordered_set<std::string> keep;
        keep.reserve(std::min(side_branch_hashes_.size(),
                              MAX_SIDE_BRANCH_HEADERS));
        uint64_t kept_bytes = 0;
        for (const auto& hash : reorg_protected_side_hashes_) {
            if (!side_branch_hashes_.count(hash)) continue;
            keep.insert(hash);
            auto body = block_store_.find(hash);
            if (body != block_store_.end() &&
                !body->second.transactions.empty()) {
                const size_t n = body->second.SerializedSize();
                kept_bytes = n > UINT64_MAX - kept_bytes
                    ? UINT64_MAX
                    : kept_bytes + static_cast<uint64_t>(n);
            }
        }
        if (keep.size() > MAX_SIDE_BRANCH_HEADERS ||
            kept_bytes > MAX_SIDE_BRANCH_RESIDENT_BYTES) {
            durability_compromised_.store(true,
                                          std::memory_order_release);
            return false;
        }

        for (const auto& tip_hash : tips) {
            std::vector<std::string> branch;
            std::unordered_set<std::string> walk_seen;
            std::string cursor = tip_hash;
            bool reaches_main = false;
            while (!cursor.empty() && walk_seen.insert(cursor).second) {
                if (keep.count(cursor)) {
                    reaches_main = true;
                    break;
                }
                auto tree = block_tree_.find(cursor);
                if (tree == block_tree_.end()) break;
                if (tree->second.on_main_chain) {
                    reaches_main = true;
                    break;
                }
                branch.push_back(cursor);
                const std::string parent =
                    HashToHex(tree->second.prev_hash);
                auto parent_it = block_tree_.find(parent);
                if (parent_it != block_tree_.end() &&
                    parent_it->second.on_main_chain) {
                    reaches_main = true;
                    break;
                }
                cursor = parent;
            }
            if (!reaches_main ||
                branch.size() > MAX_SIDE_BRANCH_HEADERS - keep.size())
                continue;

            uint64_t extra_bytes = 0;
            for (const auto& hash : branch) {
                if (keep.count(hash)) continue;
                auto body = block_store_.find(hash);
                if (body == block_store_.end() ||
                    body->second.transactions.empty()) continue;
                const size_t n = body->second.SerializedSize();
                if (n > UINT64_MAX - extra_bytes) {
                    extra_bytes = UINT64_MAX;
                    break;
                }
                extra_bytes += static_cast<uint64_t>(n);
            }
            if (extra_bytes > MAX_SIDE_BRANCH_RESIDENT_BYTES - kept_bytes)
                continue;
            for (const auto& hash : branch) keep.insert(hash);
            kept_bytes += extra_bytes;
        }

        for (auto it = side_branch_hashes_.begin();
             it != side_branch_hashes_.end(); ) {
            if (keep.count(*it)) {
                ++it;
                continue;
            }
            const std::string hash = *it;
            if (!erase_durable_side_body(hash)) {
                cleanup_ok = false;
                ++it;
                continue;
            }
            block_store_.erase(hash);
            block_tree_.erase(hash);
            side_pow_admission_.erase(hash);
            reorg_pow_verified_.erase(hash);
            deferred_reorg_retry_.erase(hash);
            bad_alt_tips_.erase(hash);
            volatile_side_quarantine_.erase(hash);
            it = side_branch_hashes_.erase(it);
            changed = true;
        }
        if (!cleanup_ok ||
            side_branch_hashes_.size() > MAX_SIDE_BRANCH_HEADERS ||
            resident_body_bytes() > MAX_SIDE_BRANCH_RESIDENT_BYTES) {
            durability_compromised_.store(true,
                                          std::memory_order_release);
            cleanup_ok = false;
        }
        (void)changed;
        return cleanup_ok;
    }

    std::unordered_set<std::string> bad_alt_tips_;

    std::atomic<uint64_t> coinbase_cap_grandfather_height_{0};

    std::vector<std::string> GetAncestorChain(const std::string& tip_hash) const {
        std::vector<std::string> path;
        std::string cur = tip_hash;
        std::unordered_set<std::string> visited;
        bool reached_genesis = false;
        while (!cur.empty()) {
            if (!visited.insert(cur).second) {
                std::cerr << "  [chain] GetAncestorChain hit cycle at " << cur.substr(0,16)
                          << "; aborting walk (block_tree_ corrupt)\n";
                std::cerr.flush();
                break;
            }
            path.push_back(cur);
            auto it = block_tree_.find(cur);
            if (it == block_tree_.end()) break;
            std::string prev = HashToHex(it->second.prev_hash);
            if (HashIsZero(it->second.prev_hash)) { reached_genesis = true; break; }
            cur = prev;
        }
        (void)reached_genesis;
        return path;
    }

    std::string FindCommonAncestor(const std::string& hash_a,
                                    const std::string& hash_b) const {
        auto chain_a = GetAncestorChain(hash_a);
        auto chain_b = GetAncestorChain(hash_b);
        std::unordered_map<std::string, bool> set_a;
        for (const auto& h : chain_a) set_a[h] = true;
        for (const auto& h : chain_b)
            if (set_a.count(h)) return h;
        return "";
    }

    // Reorg fork discovery must be proportional to the retained side suffix,
    // never the age of the canonical chain.  A candidate entry already carries
    // its derived height, so compare each side ancestor directly with the
    // canonical hash at that height.  The side-tree cardinality cap is the hard
    // walk budget; cycles, gaps, and forged height links fail closed.
    std::string FindCanonicalAncestorBoundedNoLock_(
            const std::string& side_tip_hash) const {
        std::unordered_set<std::string> seen;
        std::string cursor = side_tip_hash;
        for (size_t hops = 0; hops <= MAX_SIDE_BRANCH_HEADERS; ++hops) {
            if (!seen.insert(cursor).second) return "";
            auto it = block_tree_.find(cursor);
            if (it == block_tree_.end()) return "";
            const ChainIndexEntry& entry = it->second;
            if (entry.height < chain_.size() &&
                HashToHex(chain_[entry.height].GetHash()) == cursor)
                return cursor;
            if (entry.height == 0 || HashIsZero(entry.prev_hash)) return "";
            const std::string parent = HashToHex(entry.prev_hash);
            auto parent_it = block_tree_.find(parent);
            if (parent_it == block_tree_.end() ||
                parent_it->second.height + 1 != entry.height)
                return "";
            cursor = parent;
        }
        return "";
    }

    bool BuildSideSuffixBoundedNoLock_(
            const std::string& side_tip_hash,
            const std::string& ancestor_hash,
            std::vector<std::string>& forward_suffix) const {
        forward_suffix.clear();
        std::unordered_set<std::string> seen;
        std::string cursor = side_tip_hash;
        for (size_t hops = 0; hops <= 2 * MAX_REORG_DEPTH; ++hops) {
            if (cursor == ancestor_hash) {
                std::reverse(forward_suffix.begin(), forward_suffix.end());
                return !forward_suffix.empty();
            }
            if (!seen.insert(cursor).second) return false;
            auto it = block_tree_.find(cursor);
            if (it == block_tree_.end() || it->second.on_main_chain)
                return false;
            forward_suffix.push_back(cursor);
            cursor = HashToHex(it->second.prev_hash);
        }
        forward_suffix.clear();
        return false;
    }

    // Pure builder: walks the chain ending at tip_hash and applies every
    // block's UTXO mutations into `out`. Does NOT touch class state.
    // Caller still must hold chain_mutex_ shared (we read chain_,
    // block_store_, block_tree_ via GetAncestorChain). Returns false if
    // any block in the path is missing from block_store_+chain_ (UTXO
    // map would be corrupt). The existing RebuildUTXOSet wraps this and
    // moves the result into class state.
    bool BuildUTXOSetInto(const std::string& tip_hash, UTXOMapBundle& out) const {
        auto insert = [&](const UTXO& u) {
            if (!u.script_pubkey.empty() && u.script_pubkey[0] == 0x6A)
                return;
            std::string key = UTXOKey(u.tx_hash, u.output_index);
            out.set[key] = u;
            out.index[ScriptHex(u.script_pubkey)].insert(key);
        };
        auto erase = [&](const Hash256& h, uint32_t i) -> bool {
#ifdef VELD_TEST_HOOKS
            if (test_force_rebuild_utxo_miss_.exchange(
                    false, std::memory_order_acq_rel))
                return false;
#endif
            std::string key = UTXOKey(h, i);
            auto it = out.set.find(key);
            if (it == out.set.end()) return false;
            auto idx_it = out.index.find(ScriptHex(it->second.script_pubkey));
            if (idx_it != out.index.end()) {
                idx_it->second.erase(key);
                if (idx_it->second.empty()) out.index.erase(idx_it);
            }
            out.set.erase(it);
            return true;
        };
        auto apply_block = [&](const Block& blk) -> bool {
            for (size_t tx_index = 0;
                 tx_index < blk.transactions.size(); ++tx_index) {
                if (tx_index > UINT32_MAX) return false;
                const auto& tx = blk.transactions[tx_index];
                for (size_t i = 0; i < tx.outputs.size(); ++i) {
                    if (IsProvablyUnspendableOutput(tx.outputs[i]))
                        continue;
                    UTXO utxo;
                    utxo.tx_hash       = tx.GetTxID();
                    utxo.output_index  = (uint32_t)i;
                    utxo.value         = tx.outputs[i].value;
                    utxo.script_pubkey = tx.outputs[i].script_pubkey;
                    utxo.block_height  = blk.height;
                    utxo.is_coinbase   = tx.IsCoinbase();
                    insert(utxo);
                }
                if (!tx.IsCoinbase()) {
                    for (const auto& inp : tx.inputs) {
                        const std::string spend_key =
                            UTXOKey(inp.prev_tx_hash, inp.prev_out_index);
                        if (!out.spenders.emplace(
                                spend_key,
                                SpenderLocator{
                                    blk.height,
                                    static_cast<uint32_t>(tx_index),
                                    tx.GetTxID()}).second) {
                            return false;
                        }
                        if (!erase(inp.prev_tx_hash, inp.prev_out_index)) {
                            std::cerr << "  [rebuild-fatal] EraseUTXO miss "
                                      << "tx=" << HashToHex(tx.GetTxID()).substr(0, 16)
                                      << " prev=" << HashToHex(inp.prev_tx_hash).substr(0, 16)
                                      << ":" << inp.prev_out_index
                                      << " block_h=" << blk.height
                                      << " — refusing partial UTXO reconstruction\n";
                            return false;
                        }
                    }
                }
            }
            if (!blk.transactions.empty()) {
                uint64_t cb_t = blk.transactions[0].TotalOutput();
                uint64_t subsidy = ExpectedBlockSubsidy(blk.height);
                if (!AdvanceCanonicalSupply(blk, out.supply_units))
                    return false;
                if (cb_t > subsidy)
                    out.fees_collected_units += (cb_t - subsidy);
            }
            return true;
        };

        out.set.clear();
        out.index.clear();
        out.spenders.clear();
        out.supply_units = 0;
        out.fees_collected_units = 0;

        auto path = GetAncestorChain(tip_hash);
        std::reverse(path.begin(), path.end());

        for (const auto& h : path) {
            auto it = block_store_.find(h);
            if (it == block_store_.end()) {
                bool found = false;
                auto tree_it = block_tree_.find(h);
                if (tree_it != block_tree_.end() &&
                    tree_it->second.on_main_chain &&
                    tree_it->second.height < chain_.size() &&
                    HashToHex(chain_[tree_it->second.height].GetHash()) == h) {
                    const Block blk =
                        LoadCanonicalBlockNoLock_(tree_it->second.height);
                    if (!apply_block(blk)) return false;
                    found = true;
                }
                if (!found) {
                    std::cerr << "  [ERROR] BuildUTXOSetInto: missing block "
                              << h.substr(0, 16) << "\n";
                    return false;
                }
                continue;
            }
            if (!apply_block(it->second)) return false;
        }
        return true;
    }

    bool RebuildUTXOSet(const std::string& tip_hash) {
        UTXOMapBundle tmp;
        if (!BuildUTXOSetInto(tip_hash, tmp)) return false;
        utxo_set_     = std::move(tmp.set);
        script_index_ = std::move(tmp.index);
        canonical_spenders_ = std::move(tmp.spenders);
        total_supply_units_.store(tmp.supply_units);
        total_fees_collected_units_.store(tmp.fees_collected_units);
        return true;
    }

    // Return nullptr when every active/new stake remains fully backed by the
    // address's post-block UTXO balance; otherwise return the stable consensus
    // reject tag.  This single implementation is used by forward ingest and
    // reorg replay so a block cannot be valid merely because it arrived on a
    // side branch first.
    const char* StakeBackingViolation(const Block& block) const {
        if (StakeOutpointBackingActive(block.height)) {
            if (!stake_block_validator_ || !stake_block_validator_(block))
                return "stake_outpoint_backing_invalid";
            // The exact-outpoint covenant above supersedes the legacy
            // aggregate-balance approximation.  Re-running the old rule would
            // see the parent ledger before a canonical UNLOCK is applied and
            // incorrectly require the released principal (plus its fee) to
            // remain staked after the block.
            return nullptr;
        }
        std::unordered_map<std::string, uint64_t> lock_claims;
        for (const auto& tx : block.transactions) {
            for (const auto& out : tx.outputs) {
                if (out.script_pubkey.size() < 2 || out.script_pubkey[0] != 0x6A)
                    continue;
                size_t off = 1, plen = 0;
                if (out.script_pubkey[off] <= 75) {
                    plen = out.script_pubkey[off++];
                } else if (out.script_pubkey[off] == 0x4C &&
                           out.script_pubkey.size() > off + 1) {
                    ++off;
                    plen = out.script_pubkey[off++];
                } else if (out.script_pubkey[off] == 0x4D &&
                           out.script_pubkey.size() > off + 2) {
                    ++off;
                    plen = out.script_pubkey[off] |
                           (out.script_pubkey[off + 1] << 8);
                    off += 2;
                }
                if (off + plen > out.script_pubkey.size()) continue;
                std::string payload(out.script_pubkey.begin() + off,
                                    out.script_pubkey.begin() + off + plen);
                CanonicalStakeOp op;
                if (!ParseCanonicalStakeOp(payload, op) ||
                    op.action != CanonicalStakeOp::Action::LOCK) continue;
                const std::string& addr = op.address;
                const uint64_t amount = op.amount_units;
                if (amount == 0 || amount > MAX_SUPPLY_UNITS)
                    return "stake_lock_amount_out_of_range";
                uint64_t& running = lock_claims[addr];
                if (running > UINT64_MAX - amount)
                    return "stake_lock_sum_overflow";
                running += amount;
            }
        }

        std::unordered_map<std::string, uint64_t> active_stakes;
        if (all_active_stakes_) active_stakes = all_active_stakes_();
        for (const auto& [addr, _claim] : lock_claims) {
            if (active_stakes.find(addr) == active_stakes.end()) {
                active_stakes.emplace(
                    addr, staked_for_addr_ ? staked_for_addr_(addr) : 0);
            }
        }

        std::unordered_map<std::string, uint64_t> spent_by_addr;
        for (const auto& tx : block.transactions) {
            if (tx.IsCoinbase()) continue;
            for (const auto& inp : tx.inputs) {
                auto utxo = GetUTXONoLock(inp.prev_tx_hash,
                                          inp.prev_out_index);
                if (!utxo) continue;
                std::string addr = ScriptToAddress(utxo->script_pubkey);
                if (addr.empty()) continue;
                uint64_t& amount = spent_by_addr[addr];
                if (amount > UINT64_MAX - utxo->value)
                    return "stake_phantom_spend_overflow";
                amount += utxo->value;
            }
        }

        std::unordered_map<std::string, uint64_t> received_by_addr;
        for (const auto& tx : block.transactions) {
            for (const auto& out : tx.outputs) {
                if (out.value == 0) continue;
                std::string addr = ScriptToAddress(out.script_pubkey);
                if (addr.empty()) continue;
                uint64_t& amount = received_by_addr[addr];
                if (amount > UINT64_MAX - out.value)
                    return "stake_phantom_receipt_overflow";
                amount += out.value;
            }
        }

        for (const auto& [addr, stake_before] : active_stakes) {
            auto claim_it = lock_claims.find(addr);
            const uint64_t claim = claim_it == lock_claims.end()
                ? 0 : claim_it->second;
            if (stake_before == 0 && claim == 0) continue;
            if (stake_before > UINT64_MAX - claim)
                return "stake_phantom_stake_overflow";
            const uint64_t stake_after = stake_before + claim;

            auto script = AddressToScript(addr);
            if (script.empty()) return "stake_lock_bad_address";
            uint64_t balance_before = 0;
            auto idx_it = script_index_.find(ScriptHex(script));
            if (idx_it != script_index_.end()) {
                for (const auto& key : idx_it->second) {
                    auto utxo_it = utxo_set_.find(key);
                    if (utxo_it == utxo_set_.end()) continue;
                    if (balance_before > UINT64_MAX - utxo_it->second.value)
                        return "stake_balance_overflow";
                    balance_before += utxo_it->second.value;
                }
            }

            // Preserve the original LOCK rule exactly: a new claim needs
            // headroom in the parent-state balance.  Outputs created by this
            // same block (including its coinbase) may maintain an existing
            // stake's backing, but cannot bootstrap a new stake claim.
            if (stake_before > balance_before)
                return "stake_ledger_corrupted_balance_below_stake";
            if (claim > balance_before - stake_before)
                return "stake_exceeds_balance";

            const auto spend_it = spent_by_addr.find(addr);
            const uint64_t spent = spend_it == spent_by_addr.end()
                ? 0 : spend_it->second;
            const auto receipt_it = received_by_addr.find(addr);
            const uint64_t received = receipt_it == received_by_addr.end()
                ? 0 : receipt_it->second;
            uint64_t balance_after = balance_before >= spent
                ? balance_before - spent : 0;
            if (balance_after > UINT64_MAX - received)
                return "stake_phantom_balance_overflow";
            balance_after += received;

            if (stake_after > balance_after) {
                return claim > 0
                    ? "stake_exceeds_balance"
                    : "stake_ledger_phantom_after_drain";
            }
        }
        return nullptr;
    }

    ReplayValidationDisposition ValidateBlockForReplay(
            const Block& blk,
            const mining::PowAdmissionContext& pow_admission,
            const UTXOMapBundle* overlay = nullptr,
            bool pow_already_verified = false,
            bool* pow_verified = nullptr) const {
        ValidationOverlayGuard ovr_guard(overlay);
        if (pow_verified) *pow_verified = pow_already_verified;
        // Each gate below rejects via reject_log("<reason>") so the call site
        // names WHICH consensus rule failed. The reason is intentionally not
        // emitted on the consensus path: a reorg replay legitimately probes
        // and rejects many candidate blocks, and per-reject console output
        // during validation is debug noise with no place in a mainnet node.
        auto reject_log = [&](const char* why) -> ReplayValidationDisposition {
            last_reject_tag_ = why;
            return ReplayValidationDisposition::ConsensusInvalid;
        };
        auto defer_log = [&](const char* why) -> ReplayValidationDisposition {
            last_reject_tag_ = why;
            return ReplayValidationDisposition::DeferredLocalWork;
        };
        if (blk.transactions.empty()) return reject_log("empty_transactions");
        if (blk.transactions.size() > MAX_TRANSACTIONS_PER_BLOCK)
            return reject_log("too_many_txs");
        if (!blk.transactions[0].IsCoinbase())
            return reject_log("tx0_not_coinbase");

        // Side candidates were checked when first registered, but re-check the
        // complete wire-size envelope before the second memory-hard PoW pass so
        // a persisted/pre-upgrade candidate cannot consume disproportionate
        // replay resources or receive a different size verdict.
        if (blk.SerializedSize() > (size_t)MAX_BLOCK_SIZE)
            return reject_log("block_size");

        if (ComputeMerkleRoot(blk.transactions) != blk.header.merkle_root)
            return reject_log("merkle_mismatch");

        CanonicalPowTarget replay_target;
        if (!DecodeCanonicalVeldTarget(blk.header.bits, replay_target))
            return reject_log("pow_target_noncanonical_vbfr");
        if (blk.height > 0) {
            if (chain_.empty() ||
                blk.header.prev_block_hash != chain_.back().GetHash())
                return reject_log("parent_linkage_vbfr");
            const uint32_t expected_bits =
                ComputeNextBitsAtLocked(blk.height - 1);
            if (blk.header.bits != expected_bits)
                return reject_log("bits_mismatch_lwma_vbfr");
            if (blk.header.timestamp <= MedianTimePast())
                return reject_log("timestamp_before_mtp_vbfr");
        }
        if (!PassesCheckpoint(blk.height, blk.GetHash()))
            return reject_log("checkpoint");
        if (anchor_gate_ && !anchor_gate_(blk.height, blk.GetHash()))
            return reject_log("anchor_conflict");

        // Replay work is charged to the exact source that first supplied each
        // retained side block. The source lease is deliberately scoped to the
        // block hash and released before NMS validation below, which acquires
        // source -> global -> dataset in the same order and cannot self-deadlock
        // a one-slot source budget.
        if (!pow_admission.HasRequiredProvenance())
            return defer_log("pow_reorg_provenance_unavailable");
        if (!pow_already_verified) {
            std::optional<mining::ExpensivePowLease> source_pow_lease;
            if (pow_admission.source_budget) {
                source_pow_lease =
                    pow_admission.source_budget->TryAcquire(
                        pow_admission.ReorgUse());
                if (!source_pow_lease)
                    return defer_log("pow_peer_reorg_budget_exhausted");
            }
            auto global_pow_lease =
                mining::GlobalExpensivePowBudget().TryAcquire(
                    pow_admission.ReorgUse());
            if (!global_pow_lease)
                return defer_log("pow_global_reorg_budget_exhausted");
            bool pow_dataset_unavailable = false;
            if (!VerifyBlockPoW(
                    blk, &pow_dataset_unavailable, &replay_target)) {
                if (pow_dataset_unavailable)
                    return defer_log("pow_reorg_dataset_unavailable");
                return reject_log("pow_reorg_invalid");
            }
            if (pow_verified) *pow_verified = true;
        }

        if (blk.height > 0 && !ValidateCoinbaseOutputs(blk)) return reject_log("coinbase_outputs");
        if (blk.height > 0 && !ValidateCanonicalCoinbaseSplit(blk))
            return reject_log("coinbase_split_not_canonical");
        if (blk.height > 0 && !ValidateProtocolCustodyFunding(blk))
            return reject_log("protocol_custody_funding_invalid");

        std::unordered_set<std::string> seen_txids;
        std::unordered_set<std::string> spent_outpoints;
        for (size_t i = 0; i < blk.transactions.size(); ++i) {
            const auto& tx = blk.transactions[i];

            // Defense in depth for candidate replay.  AddBlockDirect performs
            // this same unconditional pass before a side block enters the
            // block tree; retaining it here also makes replay validation safe
            // for any persisted/pre-upgrade candidate presented to the reorg
            // engine.
            if (i > 0 && tx.IsCoinbase())
                return reject_log("extra_coinbase");
            if (!tx.IsValid()) return reject_log(
                i == 0 ? "coinbase_basic_invalid"
                       : "transaction_basic_invalid");

            std::string txid_hex = HashToHex(tx.GetTxID());
            if (!seen_txids.insert(txid_hex).second) return reject_log("dup_txid");

            if (i == 0) {
                continue;
            }

            // ValidateTransaction is the authoritative per-transaction
            // consensus check for alternate-branch application.
            if (!ValidateTransaction(tx, false)) return reject_log("validate_tx");
            if (blk.height >= BATCH1_HARDENING_HEIGHT &&
                tx.HasDustOutput(DUST_THRESHOLD_UNITS))
                return reject_log("output_below_dust_threshold");

            for (const auto& inp : tx.inputs) {
                if (inp.IsCoinbase()) continue;
                std::string k = HashToHex(inp.prev_tx_hash) + ":" + std::to_string(inp.prev_out_index);
                if (!spent_outpoints.insert(k).second) return reject_log("intra_block_dspend");
            }

            for (const auto& out : tx.outputs) {
                if (!out.script_pubkey.empty() && out.script_pubkey[0] == 0x6A) {
                    if (out.script_pubkey.size() >
                            MAX_OP_RETURN_SCRIPT_PUBKEY_BYTES)
                        return reject_log("op_return_too_large");
                }
            }
        }

        if (blk.height >= COINBASE_MATURITY_CONSENSUS_HEIGHT) {
            std::vector<uint8_t> pool_excl    = AddressToScript(POOL_ADDRESS);
            std::vector<uint8_t> endorse_excl = AddressToScript(ENDORSEMENT_POOL_ADDRESS);
            for (size_t i = 1; i < blk.transactions.size(); ++i) {
                for (const auto& inp : blk.transactions[i].inputs) {
                    if (inp.IsCoinbase()) continue;
                    auto uit = utxo_set_.find(UTXOKey(inp.prev_tx_hash, inp.prev_out_index));
                    if (uit == utxo_set_.end()) continue;
                    const auto& utxo = uit->second;
                    if (!utxo.is_coinbase) continue;
                    if (utxo.script_pubkey == pool_excl
                        || utxo.script_pubkey == endorse_excl
                        || utxo.script_pubkey == AddressToScript(VaultAddressAtHeight(utxo.block_height)))
                        continue;
                    if (utxo.block_height >= COINBASE_MATURITY_ACTIVATES_AT_HEIGHT
                        && blk.height - utxo.block_height < COINBASE_MATURITY)
                        return reject_log("coinbase_maturity");
                }
            }
        }

        if (blk.height >= GAMING_GUARD_CONSENSUS_HEIGHT) {
            constexpr uint64_t COOLDOWN = 12;
            uint64_t pos = blk.height % VAULT_DISTRIBUTION_INTERVAL;
            if (pos > VAULT_DISTRIBUTION_INTERVAL - COOLDOWN) {
                static const std::string REG   = "VELD_VALIDATOR|REGISTER|";
                static const std::string DEREG = "VELD_VALIDATOR|DEREGISTER|";
                for (size_t i = 1; i < blk.transactions.size(); ++i) {
                    for (const auto& out : blk.transactions[i].outputs) {
                        if (out.script_pubkey.size() < 2 || out.script_pubkey[0] != 0x6A) continue;
                        size_t off = 1, plen = 0;
                        if (out.script_pubkey[off] <= 75) { plen = out.script_pubkey[off++]; }
                        else if (out.script_pubkey[off] == 0x4C && out.script_pubkey.size() > off+1) {
                            off++; plen = out.script_pubkey[off++];
                        }
                        else if (out.script_pubkey[off] == 0x4D && out.script_pubkey.size() > off+2) {
                            off++;
                            plen = out.script_pubkey[off] | (out.script_pubkey[off+1] << 8);
                            off += 2;
                        }
                        if (off + plen > out.script_pubkey.size()) continue;
                        std::string payload(out.script_pubkey.begin()+off,
                                            out.script_pubkey.begin()+off+plen);
                        if (payload.rfind(REG, 0) == 0 || payload.rfind(DEREG, 0) == 0)
                            return reject_log("gaming_guard");
                    }
                }
            }
        }

        // Branch-aware NMS validation.  Reorganize() has already rebuilt
        // chain_/block_index_ through this block's candidate parent,
        // reconstructed nms_tally_ to the common ancestor, and advanced it for
        // each preceding alt block.  The staking callback likewise dispatches
        // to the pre-block alt overlay.  Therefore the complete forward-ingest
        // NMS rule set is valid here and must run before this block can be
        // credited by UpdateNmsTallyAfterCommit_.
        if constexpr (OPTION_B_CONSENSUS_GATE_ENABLED) {
            std::unordered_set<std::string> intra_block_nms_seen;
            size_t nms_records = 0;
            for (const auto& tx : blk.transactions) {
                if (tx.IsCoinbase()) continue;
                auto nms_rec = ExtractNmsFromTx(tx);
                if (!nms_rec) continue;
                if (++nms_records > MAX_NMS_RECORDS_PER_BLOCK)
                    return reject_log("too_many_nms_records_vbfr");
                auto miner_script = ExtractNmsMinerScript(tx);
                if (miner_script.empty())
                    return reject_log("nms_missing_miner_identification_vbfr");
                if (!ValidateNmsMinerIdentity(tx))
                    return reject_log("nms_miner_identity_mismatch_vbfr");
                bool nms_local_work_deferred = false;
                if (!ValidateNms(
                        *nms_rec, *this, blk.height,
                        pow_admission.source_budget.get(),
                        &nms_local_work_deferred,
                        pow_admission.NmsUse())) {
                    if (nms_local_work_deferred)
                        return defer_log("nms_local_work_deferred_vbfr");
                    return reject_log("nms_validation_failed_vbfr");
                }
                std::string nkey(nms_rec->raw.begin(), nms_rec->raw.end());
                if (!intra_block_nms_seen.insert(nkey).second)
                    return reject_log("nms_duplicate_in_block_vbfr");
                if (NmsPayloadSeen(nms_rec->raw))
                    return reject_log("nms_duplicate_cross_block_vbfr");
                if (!NmsBondSatisfied(miner_script))
                    return reject_log("nms_insufficient_bond_vbfr");
            }
        }

        // Reorganize has reconstructed the candidate UTXO set through this
        // block's parent and the Node has armed its candidate staking overlay.
        // Evaluate the same backing invariant as linear ingest before either
        // state machine is advanced by this block.
        if (const char* why = StakeBackingViolation(blk)) {
            (void)why;
            return reject_log("stake_backing_vbfr");
        }

        // ---------------------------------------------------------------
        // Block-replay (VBFR) gate coverage.
        //
        // ValidateBlockForReplay (VBFR) is the single validation entry
        // point Reorganize() calls for every alt-chain block before it is
        // committed. It was historically an INCOMPLETE mirror of the main-
        // ingest gates in AddBlockDirect: a higher-cumulative-work alt
        // chain could carry blocks with wrong bits, an oversize coinbase, a
        // missing fees-to-vault floor, a mismatched pool payout, or a
        // drained protocol pool, and VBFR would wave them through on the
        // reorg path. That gap is now CLOSED by three layers below, each
        // gated on what state it can correctly observe during alt-apply:
        //
        //   1. Engine-INDEPENDENT gates (always run, height > 0): supply-
        //      cap, fees-to-vault floor, ValidateExpectedPoolPayout, and
        //      the bits-LWMA equality gate. These read only utxo_set_ +
        //      total_supply_units_ + nms_tally_, all of which the per-alt-
        //      block incremental apply keeps alt-chain-correct, so they are
        //      byte-deterministic on every node and cannot split the chain:
        //        - utxo_set_:           mutated per alt block already.
        //        - total_supply_units_: incremental tracking.
        //        - nms_tally_:          rebuilt to the ancestor frame
        //                               (RebuildNmsTallyToHeight_) then advanced
        //                               per alt block, same as forward ingest (F2).
        //
        //   2. Gate 5, blanket sigless-spend ban (runs when NO alt-engine
        //      overlay is armed): rejects any non-coinbase TX that spends an
        //      ENDORSEMENT_POOL / vault / STAKE_VAULT / BOND_YIELD_ESCROW
        //      UTXO on the reorg path. Pure function of utxo_set_, fail-
        //      closed: a frozen reorg across a distribution boundary is
        //      strictly preferable to a drained pool (policy: freeze > theft).
        //
        //   3. Step 6, engine-DEPENDENT distribution gates (run when the
        //      alternate-engine overlay is armed): the four
        //      ValidateExpected{EndorsementFlush,VaultDistribution,
        //      BondMovements,BondYieldSettlement} OUTPUT checks, evaluated
        //      against the alt chain's reconstructed engine state. This is
        //      strictly STRONGER than the Gate 5 input ban (it accepts the
        //      one canonical distribution and rejects every other spend), so
        //      when the overlay is present Gate 5 stands down and Step 6
        //      validates.
        //
        // MTP is enforced below against the reconstructed candidate branch.
        // Reorganize() rolls chain_ back to the common ancestor and appends
        // each accepted alt predecessor before validating its child, so
        // MedianTimePast() observes exactly the candidate parent's ancestry.
        // The co-mine pool payout IS recipient-
        // gated on reorg (F2): nms_tally_ is reconstructed to the alt frame and
        // advanced per alt block, so ValidateExpectedPoolPayout reproduces the
        // alt chain's winners and a redirected pool is rejected — not merely
        // bounded to conserved totals.
        //
        // Independent review confirmed this coverage GREEN (). The
        // reorg-replay drain is exercised end-to-end by equiv_c2
        // (EQUIV_C2_VDR) through the real Reorganize / VBFR Step 6 path in
        // scripts/run-regression.sh --full.
        // ---------------------------------------------------------------
        if (blk.height > 0) {
            // Branch-aware MTP.  The initial alt ingest deliberately defers
            // this rule because chain_ still represents the competing main
            // branch there.  At this point Reorganize() has reconstructed the
            // candidate branch through blk's parent, making this identical to
            // the forward-ingest MedianTimePast() rule.
            if (blk.header.timestamp <= MedianTimePast()) {
                return reject_log("timestamp_before_mtp_vbfr");
            }

            uint64_t cb_out_vbfr = blk.transactions[0].TotalOutput();
            uint64_t fees_vbfr   = 0;
            for (size_t ti = 1; ti < blk.transactions.size(); ++ti) {
                const auto& tx = blk.transactions[ti];
                if (tx.IsCoinbase()) continue;
                uint64_t tx_in = 0, tx_out = tx.TotalOutput();
                for (const auto& inp : tx.inputs) {
                    auto utxo = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
                    if (utxo) tx_in += utxo->value;
                }
                if (tx_in > tx_out) fees_vbfr += (tx_in - tx_out);
            }
            uint64_t new_emission_vbfr =
                (cb_out_vbfr > fees_vbfr) ? (cb_out_vbfr - fees_vbfr) : 0;
            if (new_emission_vbfr > MAX_SUPPLY_UNITS ||
                total_supply_units_.load() > MAX_SUPPLY_UNITS - new_emission_vbfr) {
                return reject_log("supply_cap_overflow_vbfr");
            }

            if ((blk.height % VAULT_BLOCK_INTERVAL) != 0) {
                auto vault_script_vbfr = AddressToScript(VaultAddressAtHeight(blk.height));
                uint64_t vault_in_cb_vbfr = 0;
                for (const auto& out : blk.transactions[0].outputs) {
                    if (out.script_pubkey == vault_script_vbfr)
                        vault_in_cb_vbfr += out.value;
                }
                uint64_t subsidy_vbfr = ExpectedBlockSubsidy(blk.height);
                uint64_t remaining_vbfr =
                    (MAX_SUPPLY_UNITS > total_supply_units_.load())
                        ? (MAX_SUPPLY_UNITS - total_supply_units_.load()) : 0;
                uint64_t eff_for_floor =
                    (subsidy_vbfr < remaining_vbfr) ? subsidy_vbfr : remaining_vbfr;
                uint64_t expected_vault_floor_vbfr;
                if (eff_for_floor > 0) {
                    expected_vault_floor_vbfr =
                        (eff_for_floor * PROTOCOL_VAULT_SHARE_PCT) / 100 + fees_vbfr;
                } else {
                    expected_vault_floor_vbfr = (fees_vbfr * 40) / 100;
                }
                if (vault_in_cb_vbfr + 4 < expected_vault_floor_vbfr) {
                    return reject_log("vault_cut_below_fees_floor_vbfr");
                }
            }

            if (!ValidateExpectedPoolPayout(blk)) {
                return reject_log("pool_payout_mismatch_vbfr");
            }

            uint32_t expected_bits_vbfr = ComputeNextBitsAtLocked(blk.height - 1);
            if (expected_bits_vbfr != blk.header.bits) {
                return reject_log("bits_mismatch_lwma_vbfr");
            }

            // Fail-closed fallback for standalone Blockchain users that install
            // no fork-aware engine callbacks. Without an overlay, VBFR cannot
            // derive canonical endorsement/vault/bond distribution outputs, so
            // reject every sigless spend from those protocol pools. The normal
            // VeldNode path always arms its reconstructed side-engine overlay;
            // Step 6 below then performs the stronger exact-output checks and
            // permits the one canonical distribution. POOL is excluded because
            // ValidateExpectedPoolPayout above is already engine-independent and
            // binds its complete input/output set in either mode.
            if (alt_engine_overlay_ == nullptr) {
                const auto ep_s    = AddressToScript(ENDORSEMENT_POOL_ADDRESS);
                const auto vault_s = AddressToScript(VaultAddressAtHeight(blk.height));
                const auto sv_s    = AddressToScript(STAKE_VAULT_ADDRESS);
                const auto bye_s   = AddressToScript(BOND_YIELD_ESCROW);
                for (size_t ti = 1; ti < blk.transactions.size(); ++ti) {
                    const auto& tx = blk.transactions[ti];
                    if (tx.IsCoinbase()) continue;
                    for (const auto& inp : tx.inputs) {
                        if (inp.IsCoinbase()) continue;
                        auto u = GetUTXONoLock(inp.prev_tx_hash, inp.prev_out_index);
                        if (!u) continue;
                        const auto& spk = u->script_pubkey;
                        if (spk == ep_s || spk == sv_s || spk == bye_s ||
                            (!vault_s.empty() && spk == vault_s)) {
                            return reject_log("sigless_pool_spend_in_reorg_vbfr");
                        }
                    }
                }
            }
        }

        //  Phase D Step 6: engine-dependent sigless-DISTRIBUTION gates,
        // run ONLY during Reorganize alt-apply (alt_engine_overlay_ armed by the
        // Node's BuildAltOverlay hook; null on main ingest, where AddBlockDirect's
        // !is_alt_chain branch validates these before commit). Without them a
        // transient majority-hashrate attacker
        // could mint unauthorized endorsement/vault/bond distributions on a
        // higher-work alt chain. Each gate early-returns true pre-activation /
        // when there's nothing to distribute, so sub-boundary reorgs are
        // unaffected. The gates read validators_/staking_ via the overlay-aware
        // callbacks, so they observe the ALT chain's engine state (built
        // genesis->ancestor + advanced per alt block) — byte-equal to a
        // from-genesis cold-start, which is what equiv_c2 / reorg-fuzz assert.
        //
        // NMS validation runs above, before the engine-dependent distribution
        // gates.  At this point each prior alt block is already present in
        // chain_/block_index_, so ValidateNms resolves candidate ancestry rather
        // than the orphaned main branch; nms_tally_ and the staking callback are
        // advanced in the same per-alt-block order.
        if (alt_engine_overlay_ != nullptr) {
            if (!ValidateExpectedEndorsementFlush(blk))
                return reject_log("endorse_flush_mismatch_vbfr");
            if (!ValidateExpectedVaultDistribution(blk))
                return reject_log("vault_dist_mismatch_vbfr");
            if (amm_block_validator_ && !amm_block_validator_(blk))
                return reject_log("amm_covenant_violation_vbfr");
            if (!ValidateExpectedBondMovements(blk))
                return reject_log("bond_settlement_mismatch_vbfr");
            if (!ValidateExpectedBondYieldSettlement(blk))
                return reject_log("bond_yield_mismatch_vbfr");
        }

        return ReplayValidationDisposition::Valid;
    }

    struct ReorgRollbackFrame {
        uint64_t ancestor_height{0};
        uint64_t old_supply{0};
        std::string ancestor_hash;
        std::string old_tip_hash;
        std::string new_tip_hash;
        std::vector<Block> old_tail;
        std::set<std::string> touched_keys;
        NmsTally nms_before;
        std::vector<std::pair<std::string, mining::PowAdmissionContext>>
            candidate_pow_admissions;
        std::unordered_set<std::string> candidate_replay_pow_verified;
        std::unordered_set<std::string> candidate_volatile_side_hashes;
        bool valid{false};
    };
    std::optional<ReorgRollbackFrame> pending_reorg_rollback_;
#ifdef VELD_TEST_HOOKS
    bool test_fail_next_reorg_frame_restore_{false};
#endif

    bool RestoreReorgFrameNoLock_(const ReorgRollbackFrame& frame,
                                   UTXODelta& durable_delta) {
#ifdef VELD_TEST_HOOKS
        if (test_fail_next_reorg_frame_restore_) {
            test_fail_next_reorg_frame_restore_ = false;
            return false;
        }
#endif
        // CommitBlock removes side/quarantine bookkeeping when temporarily
        // applying a candidate.  Re-arm volatile ownership before disconnect
        // so the body is retained in memory rather than assumed durable.
        for (const auto& hash : frame.candidate_volatile_side_hashes)
            volatile_side_quarantine_.insert(hash);
        while (!chain_.empty() &&
               chain_.back().height > frame.ancestor_height) {
            Block dropped;
            if (!DisconnectCanonicalTipNoLock_(
                    dropped, /*retain_as_side_branch=*/true)) return false;
        }
        if (chain_.empty() ||
            chain_.back().height != frame.ancestor_height ||
            HashToHex(chain_.back().GetHash()) != frame.ancestor_hash)
            return false;
        for (const auto& old_block : frame.old_tail) {
            if (!CommitBlock(old_block)) return false;
        }
        {
            std::unique_lock<std::shared_mutex> nlock(nms_tally_mutex_);
            nms_tally_ = frame.nms_before;
        }
        for (const auto& [hash, admission] :
             frame.candidate_pow_admissions) {
            if (side_branch_hashes_.count(hash))
                side_pow_admission_.emplace(hash, admission);
        }
        for (const auto& hash : frame.candidate_replay_pow_verified) {
            if (side_branch_hashes_.count(hash))
                reorg_pow_verified_.insert(hash);
        }
        for (const auto& hash : frame.candidate_volatile_side_hashes) {
            if (side_branch_hashes_.count(hash))
                volatile_side_quarantine_.insert(hash);
        }
        durable_delta = BuildUTXODeltaNoLock_(frame.touched_keys);
        return !chain_.empty() &&
               HashToHex(chain_.back().GetHash()) == frame.old_tip_hash;
    }

    bool ReorgRetryReadyNoLock_(const std::string& side_tip_hash) const {
        const auto now = std::chrono::steady_clock::now();
        std::string cursor = side_tip_hash;
        for (size_t hops = 0; hops <= MAX_SIDE_BRANCH_HEADERS; ++hops) {
            auto retry = deferred_reorg_retry_.find(cursor);
            if (retry != deferred_reorg_retry_.end() &&
                now < retry->second.retry_after)
                return false;
            auto tree = block_tree_.find(cursor);
            if (tree == block_tree_.end() || tree->second.on_main_chain)
                break;
            cursor = HashToHex(tree->second.prev_hash);
        }
        return true;
    }

    void NoteDeferredReorgNoLock_(const std::string& side_tip_hash) {
        auto& retry = deferred_reorg_retry_[side_tip_hash];
        const uint8_t exponent = std::min<uint8_t>(retry.exponent, 6);
        uint64_t delay = REORG_RETRY_BASE_MS << exponent;
        delay = std::min<uint64_t>(delay, REORG_RETRY_MAX_MS);
        retry.retry_after = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(delay);
        if (retry.exponent < 6) ++retry.exponent;
    }

    ReorgDisposition ReorganizeBounded_(
            const std::string& new_tip_hash,
            std::vector<Block>& out_applied_blocks,
            const mining::PowAdmissionContext& trigger_admission,
            bool validation_only = false) {
        if (!ReorgRetryReadyNoLock_(new_tip_hash)) {
            last_reject_tag_ = "reorg_retry_backoff";
            return ReorgDisposition::DeferredLocalWork;
        }
        if (pending_reorg_rollback_ ||
            !reorg_protected_side_hashes_.empty()) {
            durability_compromised_.store(true,
                                          std::memory_order_release);
            last_reject_tag_ =
                "prior_reorg_recovery_frame_still_pending";
            return ReorgDisposition::ConsensusInvalid;
        }
        last_reorg_disconnect_count_.store(0, std::memory_order_release);
        last_reorg_apply_count_.store(0, std::memory_order_release);
        out_applied_blocks.clear();
        if (chain_.empty()) return ReorgDisposition::ConsensusInvalid;

        const std::string old_tip_hash = HashToHex(chain_.back().GetHash());
        const std::string ancestor =
            FindCanonicalAncestorBoundedNoLock_(new_tip_hash);
        if (ancestor.empty()) return ReorgDisposition::ConsensusInvalid;
        auto anc_it = block_tree_.find(ancestor);
        if (anc_it == block_tree_.end() || !anc_it->second.on_main_chain)
            return ReorgDisposition::ConsensusInvalid;
        const uint64_t anc_height = anc_it->second.height;
        const uint64_t old_tip_height = chain_.back().height;
        if (old_tip_height < anc_height ||
            old_tip_height - anc_height >= MAX_REORG_DEPTH) {
            last_reject_tag_ = "reorg_beyond_max_depth";
            return ReorgDisposition::ConsensusInvalid;
        }
        if (anchor_reorg_gate_ &&
            !anchor_reorg_gate_(anc_height, old_tip_height)) {
            last_reject_tag_ = "reorg_below_anchor_carrier";
            return ReorgDisposition::ConsensusInvalid;
        }
        // [finality-reorg-boundary-gate] A height check on the newly received
        // tip cannot establish which canonical prefix the already-stored side
        // branch replaces.  Enforce finality against the resolved common
        // ancestor, before snapshots, disconnects, overlays, or durable writes.
        if (finality_reorg_gate_ && !finality_reorg_gate_(anc_height)) {
            last_reject_tag_ = "reorg_below_finality";
            return ReorgDisposition::ConsensusInvalid;
        }

        ReorgRollbackFrame frame;
        frame.ancestor_height = anc_height;
        frame.old_supply = total_supply_units_.load();
        frame.ancestor_hash = ancestor;
        frame.old_tip_hash = old_tip_hash;
        frame.new_tip_hash = new_tip_hash;
        for (uint64_t h = anc_height + 1; h <= old_tip_height; ++h)
            frame.old_tail.push_back(LoadCanonicalBlockNoLock_(h));
        {
            std::shared_lock<std::shared_mutex> nlock(nms_tally_mutex_);
            frame.nms_before = nms_tally_;
        }

        const size_t disconnect_count = frame.old_tail.size();
        if (canonical_undo_.size() < disconnect_count ||
            miner_undo_.size() < disconnect_count) {
            last_reject_tag_ = "reorg_undo_horizon_missing";
            return ReorgDisposition::ConsensusInvalid;
        }
        const size_t undo_start = canonical_undo_.size() - disconnect_count;
        for (size_t i = 0; i < disconnect_count; ++i) {
            const auto& undo = canonical_undo_[undo_start + i];
            const auto& old_block = frame.old_tail[i];
            if (undo.height != old_block.height ||
                undo.hash != old_block.GetHash()) {
                last_reject_tag_ = "reorg_undo_hash_mismatch";
                return ReorgDisposition::ConsensusInvalid;
            }
            CollectUndoTouchedKeys_(undo, frame.touched_keys);
        }

        std::vector<std::string> path;
        if (!BuildSideSuffixBoundedNoLock_(
                new_tip_hash, ancestor, path)) {
            bad_alt_tips_.insert(new_tip_hash);
            (void)PruneSideBranchStateNoLock_(/*force=*/true);
            last_reject_tag_ = "reorg_alt_apply_budget";
            return ReorgDisposition::ConsensusInvalid;
        }
        std::vector<Block> alt_blocks;
        Hash256 expected_prev = chain_[anc_height].GetHash();
        uint64_t expected_height = anc_height + 1;
        for (const auto& hash_hex : path) {
            auto tree_it = block_tree_.find(hash_hex);
            auto store_it = block_store_.find(hash_hex);
            if (tree_it == block_tree_.end() ||
                store_it == block_store_.end() ||
                tree_it->second.height != expected_height) {
                bad_alt_tips_.insert(new_tip_hash);
                (void)PruneSideBranchStateNoLock_(/*force=*/true);
                last_reject_tag_ = "reorg_alt_body_missing";
                return ReorgDisposition::ConsensusInvalid;
            }
            Block block;
            try {
                block = LoadIndexedBlockNoLock_(hash_hex);
            } catch (...) {
                bad_alt_tips_.insert(hash_hex);
                bad_alt_tips_.insert(new_tip_hash);
                (void)PruneSideBranchStateNoLock_(/*force=*/true);
                last_reject_tag_ = "reorg_alt_body_corrupt";
                return ReorgDisposition::ConsensusInvalid;
            }
            block.height = tree_it->second.height;
            if (block.GetHash() != tree_it->second.hash ||
                block.header.prev_block_hash != expected_prev) {
                bad_alt_tips_.insert(hash_hex);
                bad_alt_tips_.insert(new_tip_hash);
                (void)PruneSideBranchStateNoLock_(/*force=*/true);
                last_reject_tag_ = "reorg_alt_path_mismatch";
                return ReorgDisposition::ConsensusInvalid;
            }
            expected_prev = block.GetHash();
            ++expected_height;
            alt_blocks.push_back(std::move(block));
        }
        if (alt_blocks.empty() ||
            HashToHex(alt_blocks.back().GetHash()) != new_tip_hash) {
            bad_alt_tips_.insert(new_tip_hash);
            (void)PruneSideBranchStateNoLock_(/*force=*/true);
            last_reject_tag_ = "reorg_alt_path_incomplete";
            return ReorgDisposition::ConsensusInvalid;
        }
        // A branch whose common ancestor is still eligible can become longer
        // than the rollback suffix by only a bounded amount before it wins.
        // Refuse an accumulated side-body bomb and let normal locator sync
        // reconnect from the current tip instead.
        if (alt_blocks.size() > 2 * MAX_REORG_DEPTH) {
            bad_alt_tips_.insert(new_tip_hash);
            (void)PruneSideBranchStateNoLock_(/*force=*/true);
            last_reject_tag_ = "reorg_alt_apply_budget";
            return ReorgDisposition::ConsensusInvalid;
        }

        // Resolve every block's original provenance before mutating canonical
        // state. A newly received trigger may safely supply the fallback for a
        // side body restored from durable storage, but it must not overwrite a
        // retained original-source context. Missing peer budget ownership is a
        // local admission deferral, never evidence that the branch is invalid.
        std::vector<mining::PowAdmissionContext> alt_pow_admissions;
        alt_pow_admissions.reserve(alt_blocks.size());
        for (const auto& block : alt_blocks) {
            const std::string hash = HashToHex(block.GetHash());
            auto existing = side_pow_admission_.find(hash);
            mining::PowAdmissionContext resolved =
                existing != side_pow_admission_.end()
                    ? existing->second : trigger_admission;
            if (!resolved.HasRequiredProvenance()) {
                last_reject_tag_ = "pow_reorg_provenance_unavailable";
                return ReorgDisposition::DeferredLocalWork;
            }
            if (existing == side_pow_admission_.end())
                side_pow_admission_.emplace(hash, resolved);
            frame.candidate_pow_admissions.emplace_back(hash, resolved);
            if (volatile_side_quarantine_.count(hash))
                frame.candidate_volatile_side_hashes.insert(hash);
            alt_pow_admissions.push_back(std::move(resolved));
        }
        std::vector<bool> replay_pow_ok(alt_blocks.size(), false);
        for (size_t i = 0; i < alt_blocks.size(); ++i)
            replay_pow_ok[i] = reorg_pow_verified_.count(
                HashToHex(alt_blocks[i].GetHash())) != 0;

        for (const auto& block : frame.old_tail)
            reorg_protected_side_hashes_.insert(
                HashToHex(block.GetHash()));

        auto restore_after_failure = [&]() -> bool {
            UTXODelta ignored;
            const bool ok = RestoreReorgFrameNoLock_(frame, ignored);
            out_applied_blocks.clear();
            if (ok) {
                for (size_t i = 0; i < alt_blocks.size(); ++i) {
                    const std::string hash =
                        HashToHex(alt_blocks[i].GetHash());
                    if (!side_branch_hashes_.count(hash)) continue;
                    side_pow_admission_.emplace(
                        hash, alt_pow_admissions[i]);
                    if (replay_pow_ok[i])
                        reorg_pow_verified_.insert(hash);
                }
                reorg_protected_side_hashes_.clear();
                (void)PruneSideBranchStateNoLock_(/*force=*/true);
            } else {
                // A partial in-memory restore makes the displaced bodies the
                // only bounded recovery source. Never force-prune them.
                durability_compromised_.store(
                    true, std::memory_order_release);
                last_reject_tag_ = "reorg_restore_failed_restart_required";
            }
            return ok;
        };

        for (size_t i = 0; i < disconnect_count; ++i) {
            Block disconnected;
            if (!DisconnectCanonicalTipNoLock_(
                    disconnected, /*retain_as_side_branch=*/true)) {
                restore_after_failure();
                last_reject_tag_ = "reorg_disconnect_failed";
                return ReorgDisposition::ConsensusInvalid;
            }
            last_reorg_disconnect_count_.fetch_add(
                1, std::memory_order_relaxed);
            if (!PruneSideBranchStateNoLock_(/*force=*/true)) {
                restore_after_failure();
                last_reject_tag_ =
                    "reorg_side_cleanup_failed_restart_required";
                return ReorgDisposition::ConsensusInvalid;
            }
        }

        struct AltOvGuard {
            AltOverlayTeardownFn fn;
            bool armed{false};
            ~AltOvGuard() {
                if (armed && fn) {
                    try { fn(); } catch (...) {}
                }
            }
        } alt_guard{alt_overlay_teardown_fn_, false};
        if (alt_overlay_build_fn_) {
            alt_guard.armed = true;
            try {
                alt_overlay_build_fn_(anc_height);
            } catch (const std::exception& e) {
                std::cerr << "  [reorg] bounded alt checkpoint restore failed: "
                          << e.what() << "\n";
                std::cerr.flush();
                restore_after_failure();
                return ReorgDisposition::ConsensusInvalid;
            } catch (...) {
                restore_after_failure();
                return ReorgDisposition::ConsensusInvalid;
            }
        }

        RebuildNmsTallyToHeight_(anc_height);
        for (size_t i = 0; i < alt_blocks.size(); ++i) {
            Block block = alt_blocks[i];
            bool pow_verified = replay_pow_ok[i];
            const auto replay = ValidateBlockForReplay(
                block, alt_pow_admissions[i], nullptr,
                replay_pow_ok[i], &pow_verified);
            replay_pow_ok[i] = pow_verified;
            if (pow_verified)
                reorg_pow_verified_.insert(HashToHex(block.GetHash()));
            if (replay == ReplayValidationDisposition::DeferredLocalWork) {
                restore_after_failure();
                return ReorgDisposition::DeferredLocalWork;
            }
            if (replay == ReplayValidationDisposition::ConsensusInvalid) {
                bad_alt_tips_.insert(HashToHex(block.GetHash()));
                bad_alt_tips_.insert(new_tip_hash);
                restore_after_failure();
                return ReorgDisposition::ConsensusInvalid;
            }
            if (alt_overlay_advance_fn_) {
                try {
                    alt_overlay_advance_fn_(block);
                } catch (...) {
                    bad_alt_tips_.insert(HashToHex(block.GetHash()));
                    bad_alt_tips_.insert(new_tip_hash);
                    restore_after_failure();
                    return ReorgDisposition::ConsensusInvalid;
                }
            }
            // Side bodies remain private/volatile while the bounded replay is
            // validating or applying a reorg.  They cross the durable body
            // boundary only after the complete suffix succeeds below.
            if (!CommitBlock(block, /*persist_new_body=*/false)) {
                bad_alt_tips_.insert(HashToHex(block.GetHash()));
                bad_alt_tips_.insert(new_tip_hash);
                restore_after_failure();
                return ReorgDisposition::ConsensusInvalid;
            }
            CollectUndoTouchedKeys_(canonical_undo_.back(),
                                    frame.touched_keys);
            UpdateNmsTallyAfterCommit_(block);
            out_applied_blocks.push_back(block);
            last_reorg_apply_count_.fetch_add(
                1, std::memory_order_relaxed);
        }

        if (validation_only) {
            // The candidate suffix has now passed the exact VBFR/engine-overlay
            // path used by a real reorg.  Restore the canonical frame before
            // any durable writer, reorg callback, publication callback or
            // external acceptance can observe it.
            for (size_t i = 0; i < alt_blocks.size(); ++i) {
                if (replay_pow_ok[i])
                    frame.candidate_replay_pow_verified.insert(
                        HashToHex(alt_blocks[i].GetHash()));
            }
            if (!restore_after_failure())
                return ReorgDisposition::ConsensusInvalid;
            return ReorgDisposition::Applied;
        }

        // CommitBlock deliberately avoids publishing a side-branch body while
        // the replacement suffix is still being replay-validated.  It also
        // evicts the temporary resident copy after applying the candidate.
        // Persist every formerly-volatile candidate now, after the complete
        // suffix has passed replay but before BeginReorgUTXO/on_commit asks the
        // durable database to validate and atomically publish that suffix.
        //
        // A failed body write is an operational deferral, not a consensus
        // invalidity.  Restore the exact old frame and retain the branch for a
        // bounded retry.  Successfully written bodies may remain as harmless
        // non-canonical recovery data if a later publication step aborts.
        if (durable_block_body_writer_) {
            for (const auto& block : alt_blocks) {
                const std::string hash = HashToHex(block.GetHash());
                if (!frame.candidate_volatile_side_hashes.count(hash))
                    continue;
                const std::vector<uint8_t> raw = block.Serialize();
                bool written = raw.size() <= MAX_BLOCK_SIZE;
                try {
                    written = written && durable_block_body_writer_(
                        block.GetHash(), raw);
                } catch (...) {
                    written = false;
                }
                if (!written) {
                    restore_after_failure();
                    last_reject_tag_ =
                        "reorg_candidate_body_persist_failed";
                    return ReorgDisposition::DeferredLocalWork;
                }
            }
        }

        for (const auto& old_block : frame.old_tail) {
            auto it = block_tree_.find(HashToHex(old_block.GetHash()));
            if (it != block_tree_.end()) it->second.on_main_chain = false;
        }
        frame.valid = true;
        const UTXODelta new_delta =
            BuildUTXODeltaNoLock_(frame.touched_keys);

        bool durable_ok = true;
        if (on_reorg_) {
            try {
                on_reorg_(new_delta, frame.ancestor_height,
                          chain_[frame.ancestor_height].GetHash(),
                          frame.old_tail.back(), frame.old_supply,
                          chain_.back(), total_supply_units_.load());
            } catch (const std::exception& e) {
                std::cerr << "  [reorg] bounded durable delta failed: "
                          << e.what() << "\n";
                std::cerr.flush();
                durable_ok = false;
            } catch (...) {
                durable_ok = false;
            }
        }
        if (!durable_ok) {
            UTXODelta old_delta;
            const bool restored = RestoreReorgFrameNoLock_(frame, old_delta);
            bool durable_restored = restored;
            if (restored && on_reorg_abort_ && !chain_.empty()) {
                try {
                    durable_restored = on_reorg_abort_(
                        old_delta, chain_.back(),
                        total_supply_units_.load(), frame.old_tail);
                } catch (...) {
                    durable_restored = false;
                }
            }
            if (durable_restored) {
                reorg_protected_side_hashes_.clear();
                (void)PruneSideBranchStateNoLock_(/*force=*/true);
            } else {
                // Preserve every old body when either memory restoration or
                // its exact durable VUR1 compensation is not proven.
                durability_compromised_.store(
                    true, std::memory_order_release);
            }
            out_applied_blocks.clear();
            return ReorgDisposition::ConsensusInvalid;
        }

        // Keep displaced transactions in the rollback frame until every
        // per-block persistence callback has committed. Publishing them here
        // raced a later callback failure and could resurrect transactions from
        // a reorg that AddBlockDirect subsequently rolled back.
        for (size_t i = 0; i < alt_blocks.size(); ++i) {
            if (replay_pow_ok[i])
                frame.candidate_replay_pow_verified.insert(
                    HashToHex(alt_blocks[i].GetHash()));
        }
        pending_reorg_rollback_ = frame;
        reorg_harness_observed_count_.fetch_add(1);
        std::cout << "\n  *** [REORG] height=" << chain_.size() - 1
                  << "  new tip=" << new_tip_hash.substr(0, 16)
                  << "... (bounded undo/checkpoint path)\n\n";
        std::cout.flush();
        return ReorgDisposition::Applied;
    }

    ReorgDisposition Reorganize(
            const std::string& new_tip_hash,
            std::vector<Block>& out_applied_blocks,
            const mining::PowAdmissionContext& trigger_admission) {
        return ReorganizeBounded_(
            new_tip_hash, out_applied_blocks, trigger_admission);
    }

public:
    uint64_t GetReorgHarnessDivergenceCount() const {
        return reorg_harness_divergence_count_.load();
    }
    uint64_t GetReorgHarnessObservedCount() const {
        return reorg_harness_observed_count_.load();
    }
    uint64_t LastReorgDisconnectCount() const {
        return last_reorg_disconnect_count_.load(
            std::memory_order_acquire);
    }
    uint64_t LastReorgApplyCount() const {
        return last_reorg_apply_count_.load(
            std::memory_order_acquire);
    }
private:
    std::atomic<uint64_t> reorg_harness_divergence_count_{0};
    std::atomic<uint64_t> reorg_harness_observed_count_{0};
    std::atomic<uint64_t> last_reorg_disconnect_count_{0};
    std::atomic<uint64_t> last_reorg_apply_count_{0};
private:
    bool RegisterVolatileSideBlockNoLock_(
            const Block& block,
            const mining::PowAdmissionContext& pow_admission) {
        register_failure_tag_.clear();
        const std::string hash = HashToHex(block.GetHash());
        if (block_tree_.count(hash))
            return volatile_side_quarantine_.count(hash) != 0;
        if (!pow_admission.HasRequiredProvenance()) {
            register_failure_tag_ = "pow_admission_context_unavailable";
            return false;
        }

        // Deliberately do not call durable_block_body_writer_.  The candidate
        // has authenticated header work but has not yet been checked against
        // its reconstructed UTXO/NMS/module overlay.
        block_store_[hash] = block;
        ChainIndexEntry entry;
        entry.hash = block.GetHash();
        entry.prev_hash = block.header.prev_block_hash;
        entry.height = block.height;
        entry.on_main_chain = false;
        auto prev_it = block_tree_.find(
            HashToHex(block.header.prev_block_hash));
        const ChainWork prev_work = prev_it == block_tree_.end()
            ? ChainWork(0) : prev_it->second.cumulative_work;
        entry.cumulative_work = AddChainWork(
            prev_work, BlockWork(block.header.bits));
        block_tree_[hash] = entry;
        side_branch_hashes_.insert(hash);
        volatile_side_quarantine_.insert(hash);
        side_pow_admission_.emplace(hash, pow_admission);

        if (!PruneSideBranchStateNoLock_()) {
            register_failure_tag_ =
                "side_branch_cleanup_failed_restart_required";
            return false;
        }
        if (!block_tree_.count(hash) ||
            !volatile_side_quarantine_.count(hash)) {
            register_failure_tag_ = "side_branch_capacity";
            return false;
        }
        return true;
    }

    bool PromoteValidatedSideSuffixNoLock_(const std::string& tip_hash) {
        register_failure_tag_.clear();
        const std::string ancestor =
            FindCanonicalAncestorBoundedNoLock_(tip_hash);
        if (ancestor.empty()) {
            register_failure_tag_ = "reorg_ancestor_unavailable";
            return false;
        }
        std::vector<std::string> path;
        if (!BuildSideSuffixBoundedNoLock_(tip_hash, ancestor, path)) {
            register_failure_tag_ = "reorg_alt_apply_budget";
            return false;
        }
        for (const auto& hash : path) {
            if (!volatile_side_quarantine_.count(hash)) continue;
            auto body_it = block_store_.find(hash);
            if (body_it == block_store_.end() ||
                body_it->second.transactions.empty()) {
                register_failure_tag_ = "side_branch_body_unavailable";
                return false;
            }
            if (durable_block_body_writer_) {
                const std::vector<uint8_t> raw = body_it->second.Serialize();
                if (raw.size() > MAX_BLOCK_SIZE) {
                    register_failure_tag_ = "block_size";
                    return false;
                }
                if (!durable_block_body_writer_(
                        body_it->second.GetHash(), raw)) {
                    register_failure_tag_ = "block_body_persist_failed";
                    return false;
                }
            }
            volatile_side_quarantine_.erase(hash);
            if (durable_block_body_writer_ && historical_block_loader_) {
                body_it->second.transactions.clear();
                body_it->second.transactions.shrink_to_fit();
            }
        }
        return true;
    }

private:
    bool RegisterBlock(
            const Block& block,
            const mining::PowAdmissionContext* pow_admission = nullptr) {
        register_failure_tag_.clear();
        std::string h = HashToHex(block.GetHash());
        if (block_tree_.count(h)) return true;

        std::vector<uint8_t> raw;
        if (durable_block_body_writer_) {
            raw = block.Serialize();
            if (raw.size() > MAX_BLOCK_SIZE) {
                register_failure_tag_ = "block_size";
                return false;
            }
        }
        block_store_[h] = block;

        ChainIndexEntry entry;
        entry.hash     = block.GetHash();
        entry.prev_hash = block.header.prev_block_hash;
        entry.height   = block.height;
        entry.on_main_chain = false;

        auto prev_it = block_tree_.find(HashToHex(block.header.prev_block_hash));
        ChainWork prev_work = (prev_it != block_tree_.end())
            ? prev_it->second.cumulative_work : ChainWork(0);
        entry.cumulative_work = AddChainWork(
            prev_work, BlockWork(block.header.bits));

        block_tree_[h] = entry;
        side_branch_hashes_.insert(h);
        // Registration is a private commit-stage entry until the durable body
        // succeeds.  Besides keeping public readers fail-closed, this tells
        // capacity pruning not to invoke the durable eraser for bytes that have
        // not been written yet.
        volatile_side_quarantine_.insert(h);
        if (pow_admission)
            side_pow_admission_.emplace(h, *pow_admission);

        auto erase_new_entry = [&]() {
            block_store_.erase(h);
            block_tree_.erase(h);
            side_branch_hashes_.erase(h);
            side_pow_admission_.erase(h);
            reorg_pow_verified_.erase(h);
            deferred_reorg_retry_.erase(h);
            volatile_side_quarantine_.erase(h);
        };
        if (!PruneSideBranchStateNoLock_()) {
            register_failure_tag_ =
                "side_branch_cleanup_failed_restart_required";
            erase_new_entry();
            return false;
        }
        if (block_tree_.count(h) == 0) {
            register_failure_tag_ = "side_branch_capacity";
            erase_new_entry();
            return false;
        }

        // The caller has completed all contextual and commit preflights before
        // reaching this point.  The temporary tree entry is protected by the
        // unique chain lock, so no public reader can observe it before the
        // durable body succeeds and CommitBlock marks it canonical.
        if (durable_block_body_writer_ &&
            !durable_block_body_writer_(block.GetHash(), raw)) {
            register_failure_tag_ = "block_body_persist_failed";
            erase_new_entry();
            if (durable_block_body_eraser_) {
                bool erased = false;
                try { erased = durable_block_body_eraser_(block.GetHash()); }
                catch (...) { erased = false; }
                if (!erased) {
                    durability_compromised_.store(
                        true, std::memory_order_release);
                }
            }
            return false;
        }
        if (durable_block_body_writer_ && historical_block_loader_) {
            block_store_[h].transactions.clear();
            block_store_[h].transactions.shrink_to_fit();
        }
        volatile_side_quarantine_.erase(h);
        return true;
    }

    bool CommitBlock(const Block& block,
                     bool persist_new_body = true) {
        uint64_t next_supply = total_supply_units_.load();
        if (!AdvanceCanonicalSupply(block, next_supply)) return false;

        //  Hardening. Fail CLOSED
        // BEFORE mutating utxo_set_. The apply loop below inserts a tx's
        // outputs then erases its inputs in place with no rollback; if an
        // EraseUTXO fails mid-loop (double-spend / phantom input) the earlier
        // outputs are already inserted and the shared input already erased,
        // leaving utxo_set_ inconsistent (the old "operator should restart"
        // path). Pre-scan every non-coinbase input for spendability + intra-
        // block uniqueness, modelling apply order EXACTLY (a tx's outputs
        // become spendable by later txs in the same block), and only mutate
        // once the whole block is known-applicable. A consensus state mutator
        // must be all-or-nothing. This is defense-in-depth behind the
        // AddBlockDirect dedup above; valid blocks always pass (the model is
        // apply-equivalent), so it never rejects an honest block.
        {
            std::unordered_set<std::string> avail_in_block;  // outpoints created within this block
            std::unordered_set<std::string> spent_in_block;  // outpoints consumed within this block
            auto okey = [](const Hash256& h, uint32_t i) {
                return HashToHex(h) + ":" + std::to_string(i);
            };
            for (const auto& tx : block.transactions) {
                Hash256 txid = tx.GetTxID();
                for (size_t i = 0; i < tx.outputs.size(); ++i)
                    if (!IsProvablyUnspendableOutput(tx.outputs[i]))
                        avail_in_block.insert(okey(txid, (uint32_t)i));
                if (tx.IsCoinbase()) continue;
                for (const auto& in : tx.inputs) {
                    std::string k = okey(in.prev_tx_hash, in.prev_out_index);
                    if (!spent_in_block.insert(k).second) return false; // intra-block double-spend
                    bool present = (avail_in_block.count(k) != 0) ||
                        static_cast<bool>(GetUTXONoLock(in.prev_tx_hash, in.prev_out_index));
                    if (!present) return false;                         // missing / already-spent input
                }
            }
        }

        CanonicalBlockUndo undo;
        undo.height = block.height;
        undo.hash = block.GetHash();
        undo.supply_before = total_supply_units_.load();
        undo.fees_before = total_fees_collected_units_.load();
        std::unordered_set<std::string> created_keys;
        std::unordered_set<std::string> spent_keys;
        for (const auto& tx : block.transactions) {
            const Hash256 txid = tx.GetTxID();
            for (size_t i = 0; i < tx.outputs.size(); ++i) {
                if (IsProvablyUnspendableOutput(tx.outputs[i])) continue;
                const std::string key = UTXOKey(txid, (uint32_t)i);
                if (!created_keys.insert(key).second || utxo_set_.count(key))
                    return false;
                undo.created_outpoints.emplace_back(txid, (uint32_t)i);
            }
            if (tx.IsCoinbase()) continue;
            for (const auto& input : tx.inputs) {
                const std::string key =
                    UTXOKey(input.prev_tx_hash, input.prev_out_index);
                spent_keys.insert(key);
                auto parent = utxo_set_.find(key);
                // Inputs spending an output created earlier in this same block
                // have no parent-frame UTXO to restore on disconnect.
                if (parent != utxo_set_.end())
                    undo.parent_spent.push_back(parent->second);
            }
        }
        for (const auto& outpoint : undo.created_outpoints) {
            if (!spent_keys.count(UTXOKey(outpoint.first, outpoint.second)))
                undo.created_unspent_outpoints.push_back(outpoint);
        }

        std::vector<CanonicalSpenderAddition> spender_additions;
        if (!PrepareCanonicalSpendersForBlockNoLock(
                block, spender_additions)) return false;

        const std::string commit_hash = HashToHex(block.GetHash());
        const bool already_indexed = block_tree_.count(commit_hash) != 0;
        if (!already_indexed) {
            // Direct canonical extension: this is the first point at which the
            // body may become durable/indexed.  AddBlockDirect's complete
            // contextual checks and every non-mutating CommitBlock preflight
            // above have succeeded under the same transition/chain locks.
            if (!persist_new_body || !RegisterBlock(block)) return false;
        } else if (persist_new_body &&
                   volatile_side_quarantine_.count(commit_hash)) {
            // A previously deferred side body can become a direct extension
            // after its parent wins.  It has now passed the linear contextual
            // gates, so promote its validated suffix before canonical apply.
            if (!PromoteValidatedSideSuffixNoLock_(commit_hash)) return false;
        }

        ApplyCanonicalSpendersForBlockNoLock(spender_additions);

        std::vector<std::pair<Hash256,uint32_t>> spent;
        std::vector<UTXO> created;

        for (const auto& tx : block.transactions) {
            const bool tx_is_coinbase = tx.IsCoinbase();
            for (size_t i = 0; i < tx.outputs.size(); ++i) {
                if (IsProvablyUnspendableOutput(tx.outputs[i]))
                    continue;
                UTXO utxo;
                utxo.tx_hash       = tx.GetTxID();
                utxo.output_index  = (uint32_t)i;
                utxo.value         = tx.outputs[i].value;
                utxo.script_pubkey = tx.outputs[i].script_pubkey;
                utxo.block_height  = block.height;
                utxo.is_coinbase   = tx_is_coinbase;
                InsertUTXO(utxo);
                created.push_back(utxo);
            }
            if (!tx.IsCoinbase()) {
                for (const auto& input : tx.inputs) {
                    spent.emplace_back(input.prev_tx_hash, input.prev_out_index);
                    if (!EraseUTXO(input.prev_tx_hash, input.prev_out_index)) {
                        std::cerr << "  [CRITICAL] Blockchain::CommitBlock: phantom "
                                  << "spent UTXO at h=" << block.height
                                  << " hash=" << HashToHex(block.GetHash()).substr(0, 16)
                                  << " input=" << HashToHex(input.prev_tx_hash).substr(0, 16)
                                  << ":" << input.prev_out_index
                                  << " — AddBlockDirect should have rejected this. "
                                  << "utxo_set_ may be inconsistent; "
                                  << "operator should restart the node.\n";
                        std::cerr.flush();
                        UnindexCanonicalSpendersForBlockNoLock(block);
                        return false;
                    }
                }
            }
        }
        total_supply_units_.store(next_supply);
        if (!block.transactions.empty()) {
            uint64_t cb_total = block.transactions[0].TotalOutput();
            uint64_t subsidy_this_block = ExpectedBlockSubsidy(block.height);
            if (cb_total > subsidy_this_block)
                total_fees_collected_units_.fetch_add(cb_total - subsidy_this_block);
        }

        IndexMinerCoinbaseNoLock(block);

        block_index_[HashToHex(block.GetHash())] = chain_.size();
        chain_.push_back(block);
        canonical_undo_.push_back(std::move(undo));
        while (canonical_undo_.size() > MAX_REORG_DEPTH + 1)
            canonical_undo_.pop_front();
        atomic_height_.store(chain_.size() - 1);

        #ifdef VELD_DEBUG_UTXO
        {
            uint64_t utxo_total = 0;
            for (auto& [k, u] : utxo_set_) utxo_total += u.value;
            uint64_t supply = total_supply_units_.load();
            if (utxo_total != supply) {
                std::cerr << "  [UTXO MISMATCH] h=" << chain_.size()-1
                          << " utxo=" << utxo_total << " supply=" << supply
                          << " diff=" << (int64_t)utxo_total-(int64_t)supply
                          << " txcount=" << block.transactions.size() << "\n";
            }
        }
        #endif

        std::string h = HashToHex(block.GetHash());
        if (block_tree_.count(h)) block_tree_[h].on_main_chain = true;
        side_branch_hashes_.erase(h);
        side_pow_admission_.erase(h);
        reorg_pow_verified_.erase(h);
        deferred_reorg_retry_.erase(h);
        volatile_side_quarantine_.erase(h);
        block_store_.erase(h);
        (void)PruneSideBranchStateNoLock_();

        return true;
    }

public:
    uint64_t MedianTimePast() const {
        if (chain_.empty()) return 0;
        size_t count = std::min((size_t)11, chain_.size());
        std::vector<uint64_t> times;
        for (size_t i = chain_.size() - count; i < chain_.size(); ++i)
            times.push_back(chain_[i].header.timestamp);
        std::sort(times.begin(), times.end());
        return times[times.size() / 2];
    }

    // Median-time-past as of a specific height (the 11 blocks ending at that
    // height). Used by the relative time-locktime rule to date a spent output's
    // confirmation.
    uint64_t MedianTimePastAt(uint64_t height) const {
        if (chain_.empty()) return 0;
        if (height >= chain_.size()) height = chain_.size() - 1;
        size_t end = (size_t)height + 1;
        size_t count = std::min((size_t)11, end);
        std::vector<uint64_t> times;
        for (size_t i = end - count; i < end; ++i)
            times.push_back(chain_[i].header.timestamp);
        std::sort(times.begin(), times.end());
        return times[times.size() / 2];
    }

    // Defense-in-depth structural ceiling for coinbase output count and value.
    bool ValidateMinerCaps(const Block& block) const {
        if (block.transactions.empty()) return false;
        constexpr uint64_t COINBASE_BACKSTOP_MULTIPLE = 6;
        const uint64_t per_out_ceiling =
            BLOCK_REWARD_UNITS * COINBASE_BACKSTOP_MULTIPLE;
        // this bounded per-output value and NOTHING
        // else, so as the last-resort emission backstop it permitted an
        // unbounded number of at-ceiling coinbase outputs (coinbase skips the
        // standard MAX_STANDARD_TRANSACTION_OUTPUTS fanout check). Also bound
        // the output COUNT and the accumulated TOTAL so this is a real backstop
        // rather than a partial one.
        //
        // The count ceiling cannot reject a canonical block:
        // ValidateCanonicalCoinbaseSplit already requires at most ONE output
        // per category (pool, vault, endorsement, miner), and finality metadata
        // is independently capped at MAX_FINALITY_MARKER_OUTPUTS.
        constexpr uint64_t CANONICAL_VALUE_LEGS = 4;
        const size_t coinbase_output_ceiling =
            static_cast<size_t>(CANONICAL_VALUE_LEGS) +
            MAX_FINALITY_MARKER_OUTPUTS;
        const uint64_t total_ceiling =
            per_out_ceiling * (CANONICAL_VALUE_LEGS + 1);
        for (const auto& tx : block.transactions) {
            if (tx.IsCoinbase()) {
                if (tx.outputs.size() > coinbase_output_ceiling) return false;
                uint64_t coinbase_total = 0;
                for (const auto& out : tx.outputs) {
                    if (out.value > per_out_ceiling) return false;
                    // Overflow-checked accumulation: never wrap into a
                    // deceptively small total.
                    if (coinbase_total > UINT64_MAX - out.value) return false;
                    coinbase_total += out.value;
                }
                if (coinbase_total > total_ceiling) return false;
            }
        }
        return true;
    }
};

struct CoinSelection {
    std::vector<UTXO>  selected_utxos;
    uint64_t           total_input;
    uint64_t           change_amount;
    bool               sufficient;

    CoinSelection() : total_input(0), change_amount(0), sufficient(false) {}
};

inline CoinSelection SelectCoins(
    const Blockchain& chain,
    const std::vector<uint8_t>& script_pubkey,
    uint64_t target_units,
    uint64_t fee_units,
    const std::unordered_set<std::string>& mempool_spent = {},
    const std::vector<UTXO>& mempool_pending = {},
    const std::unordered_set<std::string>& excluded_outpoints = {}
) {
    CoinSelection result;

    auto utxos = chain.GetUTXOsForScript(script_pubkey);

    utxos.insert(utxos.end(), mempool_pending.begin(), mempool_pending.end());

    uint64_t tip = chain.Height();
    const bool enforce_maturity =
        (tip + 1) >= COINBASE_MATURITY_CONSENSUS_HEIGHT;

    std::sort(utxos.begin(), utxos.end(),
        [](const UTXO& a, const UTXO& b) { return a.value > b.value; });

    uint64_t accumulated = 0;
    for (const auto& utxo : utxos) {
        std::string ukey = HashToHex(utxo.tx_hash) + ":" + std::to_string(utxo.output_index);
        if (!mempool_spent.empty() && mempool_spent.count(ukey)) continue;
        if (!excluded_outpoints.empty() && excluded_outpoints.count(ukey))
            continue;
        if (enforce_maturity
            && utxo.is_coinbase
            && utxo.block_height <= tip
            && (tip - utxo.block_height) < COINBASE_MATURITY) {
            continue;
        }
        result.selected_utxos.push_back(utxo);
        accumulated += utxo.value;
        if (accumulated >= target_units + fee_units) break;
    }

    if (accumulated < target_units + fee_units) {
        result.sufficient = false;
        return result;
    }

    result.total_input   = accumulated;
    result.change_amount = accumulated - target_units - fee_units;
    result.sufficient    = true;
    return result;
}

class TransactionValidator {
public:
    explicit TransactionValidator(const Blockchain& chain) : chain_(chain) {}

    struct ValidationResult {
        bool    valid;
        std::string error;
        uint64_t fee_units;
    };

    ValidationResult Validate(const Transaction& tx) const {
        ValidationResult result{true, "", 0};

        if (!tx.IsValid()) {
            result.valid = false;
            result.error = "Basic validity check failed";
            return result;
        }

        if (tx.IsCoinbase()) {
            result.valid = false;
            result.error = "Coinbase transaction cannot be in mempool";
            return result;
        }

        uint64_t input_total  = 0;
        uint64_t output_total = tx.TotalOutput();
        ScriptInterpreter interpreter;

        const uint64_t cov_height = chain_.Height() + 1;
        const bool covenants_active = (cov_height >= COVENANTS_ACTIVATION_HEIGHT);
        const uint64_t cov_mtp = covenants_active ? chain_.MedianTimePast() : 0;
        if (covenants_active) {
            auto utxo_conf = [&](size_t idx, uint64_t& out_h, uint64_t& out_mtp) -> bool {
                auto u = chain_.GetUTXO(tx.inputs[idx].prev_tx_hash,
                                        tx.inputs[idx].prev_out_index);
                if (!u) return false;
                out_h   = u->block_height;
                out_mtp = chain_.MedianTimePastAt(u->block_height);
                return true;
            };
            if (!::veld::CheckTxLockTimes(tx, cov_height, cov_mtp, utxo_conf)) {
                result.valid = false;
                result.error = "Transaction locktime not satisfied";
                return result;
            }
        }

        for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
            const auto& input = tx.inputs[i];

            auto utxo = chain_.GetUTXO(input.prev_tx_hash, input.prev_out_index);
            if (!utxo) {
                result.valid = false;
                result.error = "Input references unknown UTXO";
                return result;
            }

            ScriptContext sctx;
            sctx.block_height     = cov_height;
            sctx.mtp              = cov_mtp;
            sctx.utxo_height      = utxo->block_height;
            sctx.covenants_active = covenants_active;
            bool script_valid = interpreter.Execute(
                input.script_sig,
                utxo->script_pubkey,
                tx,
                i,
                sctx
            );

            if (!script_valid) {
                result.valid = false;
                result.error = "Script validation failed for input " + std::to_string(i);
                return result;
            }

            if (utxo->value > MAX_SUPPLY_UNITS ||
                input_total > UINT64_MAX - utxo->value) {
                result.valid = false;
                result.error = "Input value overflow";
                return result;
            }
            input_total += utxo->value;
        }

        if (output_total > input_total) {
            result.valid = false;
            result.error = "Output total exceeds input total";
            return result;
        }

        result.fee_units = input_total - output_total;
        return result;
    }

private:
    const Blockchain& chain_;
};

}
