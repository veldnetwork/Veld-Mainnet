#pragma once

#include "../core/constants.h"
#include "../core/block.h"
#include "../core/hash.h"
#include "../core/pqc_script.h"
#include "../core/script.h"
#include "../core/op_authorization.h"
#include "../core/stake_marker.h"
#include "../crypto/veld_signing.h"
#include "state_digest.h"
#include <string>
#include <unordered_map>
#include <map>
#include <vector>
#include <deque>
#include <mutex>
#include <sstream>
#include <algorithm>
#include <optional>
#include <algorithm>
#include <atomic>
#include <functional>
#include <unordered_set>

namespace veld {

struct StakeRecord {
    std::string address;
    uint64_t amount_units;
    uint64_t locked_at_height;
    uint64_t unlock_height;
    bool active{true};
    uint8_t lockup_tier{1};
    // Exact spendable output that economically backs this tranche.  These
    // fields are consensus state once outpoint backing is active.
    Hash256 backing_txid{};
    uint32_t backing_vout{UINT32_MAX};
};

struct UnstakeRecord {
    std::string address;
    uint64_t amount_units;
    uint64_t block_height;
};

struct LockupTierConfig {
    uint64_t blocks;
    double multiplier;
    const char* label;
};

static constexpr LockupTierConfig LOCKUP_TIERS[4] = {
    {7ULL * BLOCKS_PER_DAY, 1.00, "Base"},    //  7 days
    {14ULL * BLOCKS_PER_DAY, 1.10, "Short"},  // 14 days
    {30ULL * BLOCKS_PER_DAY, 1.25, "Medium"}, // 30 days
    {90ULL * BLOCKS_PER_DAY, 1.50, "Long"},   // 90 days
};
static_assert(TARGET_BLOCK_TIME != 60 ||
                  (LOCKUP_TIERS[0].blocks == 10080 && LOCKUP_TIERS[1].blocks == 20160 &&
                   LOCKUP_TIERS[2].blocks == 43200 && LOCKUP_TIERS[3].blocks == 129600),
              "wall-clock re-expression must preserve the legacy 60s profile");
static_assert(LOCKUP_TIERS[3].blocks == BOND_YIELD_VEST_BLOCKS,
              "the custodial bond draws yield at the Long-tier rate, so its vest horizon "
              "must equal the Long lockup tier — move them together");
static constexpr double LOCKUP_MAX_MULTIPLIER = 3.0;
static constexpr double LOCKUP_REFERENCE_MIN_VELD = 1000.0;
static constexpr double LOCKUP_REFERENCE_MAX_VELD = 10000.0;

inline double ComputeStakeMultiplier(uint8_t tier, uint64_t) {
    if (tier < 1 || tier > 4)
        tier = 1;
    double mult = LOCKUP_TIERS[tier - 1].multiplier;
    if (mult > LOCKUP_MAX_MULTIPLIER)
        mult = LOCKUP_MAX_MULTIPLIER;
    return mult;
}

// Integer-ppm parallel of the float multiplier above. Used in
// deterministic on-chain weighted-stake computation (consensus must NOT
// depend on IEEE 754). Each tier's ppm value is an exact integer match to
// the double constant: 1.00 → 1_000_000, 1.10 → 1_100_000,
// 1.25 → 1_250_000, 1.50 → 1_500_000.
inline uint64_t LockupTierMultiplierPpm(uint8_t tier) {
    switch (tier) {
    case 1:
        return 1'000'000ULL;
    case 2:
        return 1'100'000ULL;
    case 3:
        return 1'250'000ULL;
    case 4:
        return 1'500'000ULL;
    default:
        return 1'000'000ULL;
    }
}

struct VaultDistribution {
    uint64_t block_height;
    uint64_t total_distributed;
};

class StakingLedger {
  public:
    StakingLedger() = default;
    StakingLedger(const StakingLedger& src) {
        std::lock_guard<std::mutex> lock(src.mutex_);
        staking_activation_units_ = src.staking_activation_units_;
        min_stake_override_ = src.min_stake_override_;
        total_supply_units_.store(src.total_supply_units_.load(std::memory_order_relaxed),
                                  std::memory_order_relaxed);
        stakes_ = src.stakes_;
        unstake_history_ = src.unstake_history_;
        total_stake_ = src.total_stake_;
        pending_distribution_height_.store(
            src.pending_distribution_height_.load(std::memory_order_relaxed),
            std::memory_order_relaxed);
    }
    StakingLedger& operator=(const StakingLedger&) = delete;
    static constexpr const char* STAKE_PREFIX = "VELD_STAKE|";

    bool ProcessBlock(const Block& block) {
        std::lock_guard<std::mutex> lock(mutex_);
        // Stake-bearing blocks are rare.  Snapshot only when one is present so
        // a capacity rejection is atomic without copying the full ledger on
        // every ordinary block.
        bool stake_snapshot_taken = false;
        decltype(stakes_) stakes_before;
        decltype(unstake_history_) unstake_before;
        uint64_t total_stake_before = 0;
        for (const auto& tx : block.transactions) {
            if (StakeOutpointBackingActive(block.height) &&
                !ValidateBackingSpendLocked(tx, block.height)) {
                if (stake_snapshot_taken) {
                    stakes_ = std::move(stakes_before);
                    unstake_history_ = std::move(unstake_before);
                    total_stake_ = total_stake_before;
                }
                return false;
            }
            for (const auto& out : tx.outputs) {
                auto data = ParseOpReturn(out.script_pubkey);
                if (data.empty())
                    continue;
                if (data.substr(0, std::string(STAKE_PREFIX).size()) != STAKE_PREFIX)
                    continue;
                if (!stake_snapshot_taken) {
                    stakes_before = stakes_;
                    unstake_before = unstake_history_;
                    total_stake_before = total_stake_;
                    stake_snapshot_taken = true;
                }
                if (!ProcessStakeOp(data, block.height, tx)) {
                    stakes_ = std::move(stakes_before);
                    unstake_history_ = std::move(unstake_before);
                    total_stake_ = total_stake_before;
                    return false;
                }
            }
        }
        if (block.height > 0 && block.height % VAULT_DISTRIBUTION_INTERVAL == 0) {
            pending_distribution_height_.store(block.height, std::memory_order_relaxed);
        }
        return true;
    }

    // Pure pre-commit validation.  The blockchain invokes this on a snapshot
    // before changing the canonical UTXO set, and ProcessBlock repeats the
    // same transition while applying module state.  This keeps forward ingest,
    // side-branch replay, reorg and restart semantics identical.
    bool ValidateBlock(const Block& block) const {
        StakingLedger candidate(*this);
        return candidate.ProcessBlock(block);
    }

    static std::string BuildLockOp(const std::string& address, uint64_t amount_units,
                                   uint64_t current_height, uint8_t tier = 1) {
        (void)current_height;
        if (tier < 1 || tier > 4)
            tier = 1;
        return std::string(STAKE_PREFIX) + "LOCK|" + address + "|" + std::to_string(amount_units) +
               "|" + "T" + std::to_string((int)tier);
    }

    static std::string BuildUnlockOp(const std::string& address, uint64_t amount_units) {
        return std::string(STAKE_PREFIX) + "UNLOCK|" + address + "|" + std::to_string(amount_units);
    }

    uint64_t GetStake(const std::string& address) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stakes_.find(address);
        if (it == stakes_.end())
            return 0;
        uint64_t total = 0;
        for (auto& r : it->second)
            if (RecordEconomicallyBacked(r))
                total += r.amount_units;
        return total;
    }

    std::unordered_map<std::string, uint64_t> GetAllActiveStakes() const {
        std::unordered_map<std::string, uint64_t> out;
        std::lock_guard<std::mutex> lock(mutex_);
        out.reserve(stakes_.size());
        for (const auto& [addr, recs] : stakes_) {
            uint64_t total = 0;
            for (const auto& r : recs)
                if (RecordEconomicallyBacked(r))
                    total += r.amount_units;
            if (total > 0)
                out.emplace(addr, total);
        }
        return out;
    }

    Hash256 StakingDigest() const {
        std::lock_guard<std::mutex> lock(mutex_);
        namespace sd = ::veld::state_digest;

        // Staking-state digest v4.  V1 committed only each address's aggregate
        // active amount.  That was not sufficient: two states with the same
        // aggregate could have different lockup tiers or unlock heights and
        // therefore make different future UNLOCK and vault-distribution
        // decisions while reporting an equal consensus digest.
        //
        // Encode every block-mutable StateSnapshot field.  Address-map order is
        // canonicalized, while the per-address record vector and unstake-history
        // vector deliberately retain their consensus insertion order.  Record
        // order affects which tranche a partial UNLOCK consumes first.
        std::vector<uint8_t> body;
        sd::put_u32_le(body, 4); // encoding version
        // Mutable instance configuration is not block rollback state, but it
        // directly changes whether/how a future LOCK is accepted.  Commit it
        // so two same-chain nodes cannot report green while applying different
        // staking rules to the next block.
        sd::put_u64_le(body, staking_activation_units_);
        sd::put_u64_le(body, min_stake_override_);
        std::vector<std::string> addrs;
        addrs.reserve(stakes_.size());
        for (const auto& [a, _r] : stakes_)
            addrs.push_back(a);
        std::sort(addrs.begin(), addrs.end());
        sd::put_u32_le(body, (uint32_t)addrs.size());
        for (const auto& a : addrs) {
            const auto& recs = stakes_.at(a);
            sd::put_len_prefixed(body, a);
            sd::put_u32_le(body, (uint32_t)recs.size());
            for (const auto& r : recs) {
                sd::put_len_prefixed(body, r.address);
                sd::put_u64_le(body, r.amount_units);
                sd::put_u64_le(body, r.locked_at_height);
                sd::put_u64_le(body, r.unlock_height);
                sd::put_u8(body, r.active ? 1 : 0);
                sd::put_u8(body, r.lockup_tier);
                body.insert(body.end(), r.backing_txid.begin(), r.backing_txid.end());
                sd::put_u32_le(body, r.backing_vout);
            }
        }
        sd::put_u64_le(body, total_stake_);
        sd::put_u64_le(body, pending_distribution_height_.load(std::memory_order_relaxed));

        sd::put_u32_le(body, (uint32_t)unstake_history_.size());
        for (const auto& r : unstake_history_) {
            sd::put_len_prefixed(body, r.address);
            sd::put_u64_le(body, r.amount_units);
            sd::put_u64_le(body, r.block_height);
        }
        sd::put_u64_le(body, total_supply_units_.load(std::memory_order_relaxed));
        return sd::sha256_domain(sd::tags::STAKING, body);
    }

    std::vector<StakeRecord> GetStakeRecords(const std::string& address) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stakes_.find(address);
        if (it == stakes_.end())
            return {};
        return it->second;
    }

    std::unordered_set<std::string> GetActiveBackingOutpoints() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::unordered_set<std::string> out;
        for (const auto& [address, records] : stakes_) {
            (void)address;
            for (const auto& record : records) {
                if (!RecordEconomicallyBacked(record))
                    continue;
                out.insert(OutpointKey(record.backing_txid, record.backing_vout));
            }
        }
        return out;
    }

    struct UnlockPlan {
        std::vector<StakeRecord> consumed;
        uint64_t requested_units{0};
        uint64_t backing_input_units{0};
        uint64_t residual_units{0};
        bool valid{false};
    };

    UnlockPlan PlanUnlock(const std::string& address, uint64_t requested_units,
                          uint64_t height) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return PlanUnlockLocked(address, requested_units, height);
    }

    std::vector<UnstakeRecord> GetUnstakeHistory(const std::string& address) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<UnstakeRecord> result;
        for (auto& r : unstake_history_)
            if (r.address == address)
                result.push_back(r);
        return result;
    }

    void ApplySlashBondLockup(const std::string& address, uint64_t min_unlock_height) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stakes_.find(address);
        if (it == stakes_.end())
            return;
        for (auto& r : it->second) {
            if (!RecordEconomicallyBacked(r))
                continue;
            if (r.unlock_height < min_unlock_height)
                r.unlock_height = min_unlock_height;
        }
    }

    uint64_t GetTotalStake() const {
        std::lock_guard<std::mutex> lock(mutex_);
        if constexpr (STAKE_OUTPOINT_BACKING_ACTIVATION_HEIGHT == 0)
            return total_stake_;
        uint64_t total = 0;
        for (const auto& [address, records] : stakes_) {
            (void)address;
            for (const auto& record : records) {
                if (!RecordEconomicallyBacked(record))
                    continue;
                if (total > UINT64_MAX - record.amount_units)
                    return UINT64_MAX;
                total += record.amount_units;
            }
        }
        return total;
    }

    bool IsStakingActive(uint64_t total_supply_units) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return total_supply_units >= staking_activation_units_;
    }
    void SetStakingActivationUnits(uint64_t units) {
        std::lock_guard<std::mutex> lock(mutex_);
        staking_activation_units_ = units;
    }
    void SetMinStakeUnits(uint64_t units) {
        std::lock_guard<std::mutex> lock(mutex_);
        min_stake_override_ = units;
    }
    uint64_t GetEffectiveMinStake() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return min_stake_override_ > 0 ? min_stake_override_ : MIN_STAKE_UNITS;
    }

    void SetTotalSupply(uint64_t units) noexcept {
        total_supply_units_.store(units, std::memory_order_relaxed);
    }

    bool IsStakingUnlocked() const noexcept {
        return total_supply_units_.load(std::memory_order_relaxed) >= STAKING_UNLOCK_SUPPLY;
    }

    // Deterministic integer-ppm weighted-stake snapshot for on-chain
    // vault distribution.
    //
    // Returns std::map<address, weighted_units> where:
    //   weighted_units = Σ (record.amount_units × LockupTierMultiplierPpm
    //                       (record.lockup_tier)) / 1_000_000
    // for every ACTIVE stake record on that address.
    //
    // std::map iteration order is canonical (lexicographic ASC on
    // base58-encoded address strings) which `ComputeExpectedVaultDist-
    // ribution` relies on for cross-platform byte-equal output sets.
    //
    // This is the consensus-deterministic stake weight. Floating point is
    // forbidden in this path. Mining-tier multipliers are NOT included
    // here — they're a separate redesign. Lockup tier alone gives
    // 1.00–1.50× per record; combined cap is the per-staker concentration
    // cap applied later in ComputeExpectedVaultDistribution.
    //
    // The `query_height` parameter is currently unused (every active
    // record contributes regardless of unlock_height) — vault distribution
    // pays mature AND immature active stakes ("vault distribution pays ALL
    // stakers"). Parameter retained for forward compatibility with future
    // per-height filtering rules.
    std::map<std::string, uint64_t> GetWeightedStakeSnapshot(uint64_t) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::map<std::string, uint64_t> out;
        std::vector<std::string> addrs;
        addrs.reserve(stakes_.size());
        for (const auto& [a, _] : stakes_)
            addrs.push_back(a);
        std::sort(addrs.begin(), addrs.end());
        for (const auto& addr : addrs) {
            auto it = stakes_.find(addr);
            if (it == stakes_.end())
                continue;
            uint64_t weighted_units = 0;
            for (const auto& r : it->second) {
                if (!RecordEconomicallyBacked(r))
                    continue;
                uint64_t ppm = LockupTierMultiplierPpm(r.lockup_tier);
                uint64_t add = (uint64_t)((__uint128_t)r.amount_units * (__uint128_t)ppm /
                                          (__uint128_t)1'000'000ULL);
                if (UINT64_MAX - weighted_units < add) {
                    weighted_units = UINT64_MAX;
                    break;
                }
                weighted_units += add;
            }
            if (weighted_units > 0) {
                out[addr] = weighted_units;
            }
        }
        return out;
    }

    bool HasPendingDistribution() const {
        return pending_distribution_height_.load(std::memory_order_relaxed) > 0;
    }
    uint64_t GetPendingDistributionHeight() const {
        return pending_distribution_height_.load(std::memory_order_relaxed);
    }
    void ClearPendingDistribution() {
        pending_distribution_height_.store(0, std::memory_order_relaxed);
    }

    uint64_t GetLatestStakeHeight(const std::string& address) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stakes_.find(address);
        if (it == stakes_.end())
            return 0;
        uint64_t latest = 0;
        for (const auto& r : it->second)
            if (r.locked_at_height > latest)
                latest = r.locked_at_height;
        return latest;
    }

    double GetEffectiveMultiplier(const std::string& address) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stakes_.find(address);
        if (it == stakes_.end())
            return 1.0;
        double weighted = 0.0;
        uint64_t total = 0;
        for (const auto& r : it->second) {
            if (!RecordEconomicallyBacked(r))
                continue;
            double m = ComputeStakeMultiplier(r.lockup_tier, r.amount_units);
            weighted += (double)r.amount_units * m;
            total += r.amount_units;
        }
        if (total == 0)
            return 1.0;
        double avg = weighted / (double)total;
        if (avg > LOCKUP_MAX_MULTIPLIER)
            avg = LOCKUP_MAX_MULTIPLIER;
        return avg;
    }

    uint64_t GetMatureStake(const std::string& address, uint64_t current_height) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stakes_.find(address);
        if (it == stakes_.end())
            return 0;
        uint64_t mature = 0;
        for (const auto& r : it->second)
            if (RecordEconomicallyBacked(r) && r.unlock_height <= current_height)
                mature += r.amount_units;
        return mature;
    }

    uint64_t GetNextUnlockHeight(const std::string& address, uint64_t current_height) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stakes_.find(address);
        if (it == stakes_.end())
            return UINT64_MAX;
        uint64_t earliest = UINT64_MAX;
        for (const auto& r : it->second)
            if (RecordEconomicallyBacked(r) && r.unlock_height > current_height)
                earliest = std::min(earliest, r.unlock_height);
        return earliest;
    }

    uint64_t GetEarliestUnlockHeight(const std::string& address) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stakes_.find(address);
        if (it == stakes_.end())
            return UINT64_MAX;
        uint64_t earliest = UINT64_MAX;
        for (const auto& r : it->second)
            if (RecordEconomicallyBacked(r))
                earliest = std::min(earliest, r.unlock_height);
        return earliest;
    }

    struct StakerSummary {
        std::string address;
        uint64_t staked_units;
        uint64_t earliest_unlock_height;
    };
    std::vector<StakerSummary> GetAllStakers() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<StakerSummary> result;
        for (const auto& [addr, records] : stakes_) {
            uint64_t total = 0;
            uint64_t earliest = UINT64_MAX;
            for (const auto& r : records) {
                if (RecordEconomicallyBacked(r)) {
                    total += r.amount_units;
                    earliest = std::min(earliest, r.unlock_height);
                }
            }
            if (total > 0)
                result.push_back({addr, total, earliest});
        }
        return result;
    }

    uint64_t GetReserveBlockPayout(uint64_t) const {
        return 0;
    }

    void Reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        stakes_.clear();
        total_stake_ = 0;
        pending_distribution_height_.store(0, std::memory_order_relaxed);
        unstake_history_.clear();
    }

    // Atomic block-state snapshot and restore. Captures exactly
    // the block-mutable state Reset() clears plus total_supply_units_, which the
    // block apply path updates before ProcessBlock. It is not merely config: a
    // failed block at the staking-activation boundary must not leave the next
    // block observing the rejected block's projected supply. Never captures the
    // mutex or node-set activation/min-stake configuration, so the
    // block-connect path can roll staking back verbatim on an all-or-nothing block
    // reject. Snapshot/restore must preserve Digest() byte-for-byte.
    struct StateSnapshot {
        std::unordered_map<std::string, std::vector<StakeRecord>> stakes;
        uint64_t total_stake = 0;
        uint64_t pending_distribution_height = 0;
        std::deque<UnstakeRecord> unstake_history;
        uint64_t total_supply_units = 0;
    };
    StateSnapshot SnapshotState() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return StateSnapshot{stakes_, total_stake_,
                             pending_distribution_height_.load(std::memory_order_relaxed),
                             unstake_history_, total_supply_units_.load(std::memory_order_relaxed)};
    }
    void RestoreState(const StateSnapshot& s) {
        std::lock_guard<std::mutex> lock(mutex_);
        stakes_ = s.stakes;
        total_stake_ = s.total_stake;
        pending_distribution_height_.store(s.pending_distribution_height,
                                           std::memory_order_relaxed);
        unstake_history_ = s.unstake_history;
        total_supply_units_.store(s.total_supply_units, std::memory_order_relaxed);
    }

  private:
    mutable std::mutex mutex_;
    uint64_t staking_activation_units_{STAKING_UNLOCK_SUPPLY};
    uint64_t min_stake_override_{0};
    std::atomic<uint64_t> total_supply_units_{0};
    std::unordered_map<std::string, std::vector<StakeRecord>> stakes_;
    std::deque<UnstakeRecord> unstake_history_;
    uint64_t total_stake_{0};
    std::atomic<uint64_t> pending_distribution_height_{0};

    static std::string OutpointKey(const Hash256& txid, uint32_t vout) {
        return HashToHex(txid) + ":" + std::to_string(vout);
    }

    static bool RecordEconomicallyBacked(const StakeRecord& record) {
        if (!record.active)
            return false;
        if constexpr (STAKE_OUTPOINT_BACKING_ACTIVATION_HEIGHT == 0)
            return true;
        return record.backing_vout != UINT32_MAX;
    }

    UnlockPlan PlanUnlockLocked(const std::string& address, uint64_t requested_units,
                                uint64_t height) const {
        UnlockPlan plan;
        plan.requested_units = requested_units;
        if (requested_units == 0)
            return plan;
        auto it = stakes_.find(address);
        if (it == stakes_.end())
            return plan;
        uint64_t remaining = requested_units;
        for (const auto& record : it->second) {
            if (!RecordEconomicallyBacked(record) || record.unlock_height > height)
                continue;
            if (plan.backing_input_units > UINT64_MAX - record.amount_units)
                return UnlockPlan{};
            plan.consumed.push_back(record);
            plan.backing_input_units += record.amount_units;
            if (record.amount_units >= remaining) {
                plan.residual_units = record.amount_units - remaining;
                remaining = 0;
                break;
            }
            remaining -= record.amount_units;
        }
        plan.valid = remaining == 0;
        return plan;
    }

    bool ValidateBackingSpendLocked(const Transaction& tx, uint64_t height) const {
        std::vector<CanonicalStakeOp> ops;
        for (const auto& out : tx.outputs) {
            const std::string data = ParseOpReturn(out.script_pubkey);
            if (data.rfind(STAKE_PREFIX, 0) != 0)
                continue;
            CanonicalStakeOp op;
            if (!ParseCanonicalStakeOp(data, op))
                return false;
            ops.push_back(std::move(op));
        }
        if (ops.size() > 1)
            return false;

        std::unordered_set<std::string> active;
        for (const auto& [address, records] : stakes_) {
            (void)address;
            for (const auto& record : records) {
                if (RecordEconomicallyBacked(record))
                    active.insert(OutpointKey(record.backing_txid, record.backing_vout));
            }
        }
        std::unordered_set<std::string> spent_backing;
        for (const auto& input : tx.inputs) {
            const std::string key = OutpointKey(input.prev_tx_hash, input.prev_out_index);
            if (active.count(key))
                spent_backing.insert(key);
        }

        if (ops.empty())
            return spent_backing.empty();
        const CanonicalStakeOp& op = ops.front();
        const auto owner_script = AddressToScript(op.address);
        if (owner_script.empty() || !TxInputMatchesAddress(tx, op.address))
            return false;

        if (op.action == CanonicalStakeOp::Action::LOCK) {
            // Output zero is the canonical stake principal.  It cannot be an
            // OP_RETURN or ordinary change output, and an existing principal
            // cannot be recycled into a fresh identity in the same tx.
            return spent_backing.empty() && !tx.outputs.empty() &&
                   tx.outputs[0].value == op.amount_units &&
                   tx.outputs[0].script_pubkey == owner_script;
        }

        const UnlockPlan plan = PlanUnlockLocked(op.address, op.amount_units, height);
        if (!plan.valid || plan.consumed.empty() || spent_backing.size() != plan.consumed.size())
            return false;
        for (const auto& record : plan.consumed) {
            if (!spent_backing.count(OutpointKey(record.backing_txid, record.backing_vout)))
                return false;
        }
        // A partial final tranche is rebound to output zero with the exact
        // residual value and original owner.  Whole-tranche exits have no
        // replacement backing output.
        if (plan.residual_units > 0) {
            return !tx.outputs.empty() && tx.outputs[0].value == plan.residual_units &&
                   tx.outputs[0].script_pubkey == owner_script;
        }
        return true;
    }

    // Require a verified signature; finding a public key in a sigless input is
    // not authorization. Delegates to the shared check in op_authorization.h.
    // must have actually signed an input of this transaction.
    static bool TxInputMatchesAddress(const Transaction& tx, const std::string& address) {
        return TxVerifiedSignedBy(tx, address);
    }

    // False has one precise meaning: accepting this otherwise-valid LOCK would
    // exceed the number of recipients a canonical vault transaction can emit.
    // All legacy malformed/unauthorized operations remain ignored (true), as
    // before; the caller rolls the whole stake transition back only on false.
    bool ProcessStakeOp(const std::string& data, uint64_t height, const Transaction& tx) {
        const bool fail_closed = StakeOutpointBackingActive(height);
        const auto invalid = [fail_closed]() noexcept { return !fail_closed; };
        CanonicalStakeOp op;
        if (!ParseCanonicalStakeOp(data, op))
            return invalid();

        const std::string& address = op.address;
        const uint64_t amount = op.amount_units;
        if (amount == 0 || amount > MAX_STAKE_UNITS)
            return invalid();

        uint64_t effective_min_stake =
            min_stake_override_ > 0 ? min_stake_override_ : MIN_STAKE_UNITS;
        if (op.action == CanonicalStakeOp::Action::LOCK && amount < effective_min_stake)
            return invalid();
        if (op.action == CanonicalStakeOp::Action::LOCK && amount >= effective_min_stake) {
            if (!TxInputMatchesAddress(tx, address))
                return invalid();
            if (total_supply_units_.load(std::memory_order_relaxed) < staking_activation_units_)
                return invalid();
            uint64_t current_stake = 0;
            auto sit = stakes_.find(address);
            if (sit != stakes_.end())
                for (auto& r : sit->second)
                    if (RecordEconomicallyBacked(r))
                        current_stake += r.amount_units;
            if (current_stake > MAX_STAKE_UNITS || amount > MAX_STAKE_UNITS - current_stake)
                return invalid();

            const uint8_t lockup_tier = op.lockup_tier;
            uint64_t tier_blocks = LOCKUP_TIERS[lockup_tier - 1].blocks;
            uint64_t unlock_height = height + tier_blocks;
            if (unlock_height > height + 10ULL * BLOCKS_PER_YEAR)
                return invalid();

            if (current_stake == 0 && stakes_.size() >= MAX_VAULT_PAYOUT_STAKERS) {
                return false;
            }

            StakeRecord rec;
            rec.address = address;
            rec.amount_units = amount;
            rec.locked_at_height = height;
            rec.unlock_height = unlock_height;
            rec.active = true;
            rec.lockup_tier = lockup_tier;
            if (StakeOutpointBackingActive(height)) {
                rec.backing_txid = tx.GetTxID();
                rec.backing_vout = 0;
            }
            if (total_stake_ > UINT64_MAX - amount)
                return invalid();
            stakes_[address].push_back(rec);
            total_stake_ += amount;
        } else if (op.action == CanonicalStakeOp::Action::UNLOCK) {
            if (!TxInputMatchesAddress(tx, address))
                return invalid();
            auto it = stakes_.find(address);
            if (it == stakes_.end())
                return invalid();

            // LOCK admission requires at least the already-selected effective
            // minimum.  Preserve that invariant after a partial exit as well:
            // without it, a matured stake can be reduced to one native unit and
            // permanently occupy one of the finite vault-recipient slots.  The
            // same capital can then be recycled through fresh addresses until
            // no honest staker can enter.  Full exit remains valid, as does an
            // exact-minimum residual; this introduces no new economic value.
            uint64_t current_stake = 0;
            uint64_t mature_stake = 0;
            for (const auto& r : it->second) {
                if (!RecordEconomicallyBacked(r))
                    continue;
                if (current_stake > UINT64_MAX - r.amount_units)
                    return invalid();
                current_stake += r.amount_units;
                if (r.unlock_height <= height) {
                    if (mature_stake > UINT64_MAX - r.amount_units)
                        return invalid();
                    mature_stake += r.amount_units;
                }
            }
            if (!StakeUnlockPreservesMinimum(current_stake, mature_stake, amount,
                                             effective_min_stake))
                return invalid();

            const UnlockPlan backing_plan = StakeOutpointBackingActive(height)
                                                ? PlanUnlockLocked(address, amount, height)
                                                : UnlockPlan{};
            if (StakeOutpointBackingActive(height) && !backing_plan.valid)
                return false;

            uint64_t remaining = amount;
            for (auto& r : it->second) {
                if (!RecordEconomicallyBacked(r) || r.unlock_height > height)
                    continue;
                if (remaining == 0)
                    break;
                if (r.amount_units <= remaining) {
                    remaining -= r.amount_units;
                    unstake_history_.push_back({address, r.amount_units, height});
                    total_stake_ =
                        (total_stake_ >= r.amount_units) ? total_stake_ - r.amount_units : 0;
                    r.active = false;
                } else {
                    unstake_history_.push_back({address, remaining, height});
                    total_stake_ = (total_stake_ >= remaining) ? total_stake_ - remaining : 0;
                    r.amount_units -= remaining;
                    if (StakeOutpointBackingActive(height)) {
                        r.backing_txid = tx.GetTxID();
                        r.backing_vout = 0;
                    }
                    remaining = 0;
                }
            }
            it->second.erase(std::remove_if(it->second.begin(), it->second.end(),
                                            [](const StakeRecord& r) { return !r.active; }),
                             it->second.end());
            if (it->second.empty())
                stakes_.erase(it);
            constexpr size_t UNSTAKE_HISTORY_CAP = 43'200;
            while (unstake_history_.size() > UNSTAKE_HISTORY_CAP)
                unstake_history_.pop_front();
        }
        return true;
    }

    static std::string ParseOpReturn(const std::vector<uint8_t>& script) {
        if (script.size() < 2 || script[0] != 0x6A)
            return "";
        size_t offset = 1;
        size_t len = 0;
        const uint8_t push = script[offset++];
        if (push <= 75) {
            len = push;
        } else if (push == 0x4C) {
            if (offset >= script.size())
                return "";
            len = script[offset++];
            if (len <= 75)
                return ""; // non-minimal PUSHDATA1
        } else if (push == 0x4D) {
            if (offset + 2 > script.size())
                return "";
            len = (size_t)script[offset] | ((size_t)script[offset + 1] << 8);
            offset += 2;
            if (len <= 0xFF)
                return ""; // non-minimal PUSHDATA2
        } else {
            return "";
        }
        // One marker has one byte encoding.  Trailing script bytes used to be
        // ignored here even though relay's canonical parser rejected them,
        // creating consensus/mempool aliases for the same apparent request.
        if (offset + len != script.size())
            return "";
        return std::string(script.begin() + offset, script.begin() + offset + len);
    }
};

} // namespace veld
