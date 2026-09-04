#pragma once

#include "../core/constants.h"
#include "../core/block.h"
#include "../core/hash.h"
#include "../core/script.h"
#include "../core/op_authorization.h"
#include "../core/canonical_numeric.h"
#include "finality_qc.h" // finality vote preimage (SLASH_EQUIV evidence)
#include "../core/pqc_script.h"
#include "../crypto/ripemd160.h"
#include "../crypto/veld_signing.h"
#include "state_digest.h"
#include <string>
#include <unordered_map>
#include <map>
#include <unordered_set>
#include <vector>
#include <mutex>
#include <sstream>
#include <atomic>
#include <algorithm>
#include <functional>
#include <cmath>
#include <optional>
#include <tuple>

namespace veld {

class StakingLedger;
namespace finality {
namespace qc {
class ValidatedEquivocationEvidence;
}
} // namespace finality

struct ValidatorRecord {
    std::string pubkey_hex;
    std::string address;
    uint64_t registered_height{0};
    bool active{true};
    bool slashed{false};
    // Finality equivocation, as opposed to an ordinary slashable fault. Settles
    // at 0% principal return (constants.h SLASH_EQUIV_*). Separate from
    // `slashed` so an equivocation can never be settled by the 50%-return path
    // through a merge, a default, or a future edit that forgets the class.
    bool slashed_equivocation{false};
    uint64_t slashed_at_height{0};
    bool bond_custodial{false};
    uint64_t bond_units{0};
    uint64_t deregistered_at_height{0};
    uint64_t last_finality_vote_height{0};
};

struct EndorsementRecord {
    // Consensus keeps only a SHA-256 commitment to the 1,952-byte ML-DSA
    // public key.  The full key already lives once in validators_ and the
    // canonical address is carried below.  Repeating 3,904 hex bytes in every
    // endorsement made the rolling finality/reward window grow by gigabytes
    // under otherwise-valid traffic.
    std::string pubkey_hex;
    std::string address;
    // Likewise this is the SHA-256 commitment to the canonical lowercase
    // 3,309-byte signature hex, not the signature itself.  Validation happens
    // before insertion; HasAcceptedEndorsement hashes the raw marker again.
    // No later consensus decision needs to retain all 6,618 text bytes.
    std::string sig_hex;
    // Exact block hash covered by sig_hex.  The endorsement-pool payout gate
    // binds raw on-chain markers back to this registry-accepted tuple; omitting
    // the hash would let an invalid marker borrow acceptance from a different
    // endorsement at the same (validator,height).
    std::string block_hash_hex;
    uint64_t block_height{0};
    bool reward_paid{false};
};

struct SlashEvidence {
    std::string pubkey_hex;
    std::string address;
    uint64_t height{0};
    std::string hash_a_hex;
    std::string hash_b_hex;
    std::string sig_a_hex;
    std::string sig_b_hex;
    std::string slasher_address;
    uint64_t evidence_block{0};
};

struct FinalityMembershipRecord {
    Hash256 root{};
    std::vector<Hash256> members; // sorted pubkey commitments
};

// Read-only reconstruction seam for the evidence verifier.  Historical
// membership stores compact commitments; the exact public key remains in the
// validator registry.  Weight/address are intentionally absent because
// authenticating one vote needs only the frozen root, commitment, and key.
struct RetainedFinalityMember {
    uint64_t epoch{0};
    Hash256 root{};
    Hash256 pubkey_commit{};
    std::string pubkey_hex;
};

struct FinalityEquivocationRecord {
    uint64_t epoch{0};
    uint8_t phase{0};
    uint32_t round{0};
    uint64_t target_a_height{0};
    Hash256 target_a_hash{};
    uint64_t target_b_height{0};
    Hash256 target_b_hash{};
    uint64_t evidence_block{0};
    std::string slasher_address;
    Hash256 evidence_commit{};
};

struct PendingReward {
    std::string address;
    uint64_t amount;
    uint64_t block_height;
};

struct BondSettlement {
    // SLASH_EQUIVOCATION is a distinct kind rather than a flag on
    // SLASH_CONFISCATE: it settles at 0% principal return where the ordinary
    // slash returns 50%, and a payout path that reads a boolean wrong is a
    // fund-safety ambiguity. Distinct kinds make the compiler carry the distinction.
    enum Kind { DEREGISTER_RETURN, SLASH_CONFISCATE, SLASH_EQUIVOCATION };
    std::string address;
    Kind kind{DEREGISTER_RETURN};
    uint64_t bond_units{0};
    std::string slasher_address;
};

struct BondYieldTranche {
    uint64_t accrual_height{0};
    uint64_t units{0};
};

class ValidatorRegistry {
  public:
    ValidatorRegistry() = default;
    ValidatorRegistry(const ValidatorRegistry& src)
        : total_staked_units_(src.total_staked_units_.load()),
          min_validator_stake_override_(src.min_validator_stake_override_),
          last_flush_reward_per_endorsement_(src.last_flush_reward_per_endorsement_.load()),
          block_known_at_height_fn_(src.block_known_at_height_fn_), validators_(src.validators_),
          address_to_pubkey_(src.address_to_pubkey_), endorsements_(src.endorsements_),
          endorsement_keys_(src.endorsement_keys_),
          endorsement_pool_outpoints_(src.endorsement_pool_outpoints_),
          last_canonical_endorsement_flush_height_(src.last_canonical_endorsement_flush_height_),
          last_op_height_(src.last_op_height_), bond_yield_escrow_(src.bond_yield_escrow_),
          slashed_evidence_(src.slashed_evidence_),
          slashed_evidence_keys_(src.slashed_evidence_keys_),
          evidence_per_pubkey_(src.evidence_per_pubkey_), slashed_pubkeys_(src.slashed_pubkeys_),
          finality_membership_(src.finality_membership_),
          finality_equivocations_(src.finality_equivocations_) {}
    ValidatorRegistry& operator=(const ValidatorRegistry&) = delete;

    static constexpr const char* VAL_PREFIX = "VELD_VALIDATOR|";

    void SetTotalStaked(uint64_t units) noexcept {
        total_staked_units_.store(units, std::memory_order_relaxed);
    }

    void SetMinValidatorStake(uint64_t units) {
        std::lock_guard<std::mutex> lk(mutex_);
        min_validator_stake_override_ = units;
    }
    uint64_t GetEffectiveMinStake() const {
        std::lock_guard<std::mutex> lk(mutex_);
        return min_validator_stake_override_ > 0 ? min_validator_stake_override_
                                                 : MIN_VALIDATOR_STAKE;
    }

    //  The SLASH branch verifies that both endorsement signatures
    // are valid against the validator's pubkey at the claimed sig_height,
    // but it does NOT check that hash_a / hash_b correspond to blocks
    // this node has actually seen at sig_height. Without that check, an
    // attacker who controls the validator's pubkey (or tricks the
    // validator into signing endorsements over attacker-chosen 32-byte
    // hashes that aren't blocks) could fabricate SLASH evidence.
    //
    // Callback returns true iff `hash_hex` is a known block in the
    // local block_tree at exactly `height` (canonical or alt-chain
    // within MAX_REORG_DEPTH). Wired from node.h to
    // Blockchain::HasBlockAtHeight. When the callback is unwired (legacy
    // call paths during snapshot bootstrap before SetBlockKnownAtHeight-
    // Query has fired), the SLASH branch falls back to legacy behaviour
    // (accept evidence without the existence check) so cold-IBD doesn't
    // mass-reject historical SLASH OP_RETURNs that the node has not yet
    // had time to back-fill block_tree for.
    using BlockKnownAtHeightFn = std::function<bool(uint64_t, const std::string&)>;
    void SetBlockKnownAtHeightQuery(BlockKnownAtHeightFn fn) noexcept {
        block_known_at_height_fn_ = std::move(fn);
    }

    bool IsValidatorSystemActive() const noexcept {
        // CONSENSUS-DETERMINISTIC: identical on every node regardless of local
        // flags (see VALIDATOR_SYSTEM_ALWAYS_ACTIVE in constants.h).
        if (VALIDATOR_SYSTEM_ALWAYS_ACTIVE)
            return true;
        return total_staked_units_.load(std::memory_order_relaxed) >= VALIDATOR_UNLOCK_STAKED;
    }

    // Σ of active, custodial, non-slashed validators' bonds, each counted UP TO
    // MIN_VALIDATOR_STAKE. This is the quantity the MAINNET governance-activation
    // gate compares against GOVERNANCE_ACTIVATION_BONDED_UNITS (= 5 ×
    // MIN_VALIDATOR_STAKE = 50,000 VELD). Capping per-validator at
    // MIN_VALIDATOR_STAKE makes the threshold reachable only by >= 5 DISTINCT
    // validators (an over-bonded whale contributes at most MIN_VALIDATOR_STAKE).
    // Eligibility mirrors GetBondYieldWeight (active && bond_custodial &&
    // bond_units>0 && !slashed). Deterministic: pure read of the replayed
    // validators_ set, so every node computes the same total at a given height.
    uint64_t GetGovernanceBondedTotal() const {
        std::lock_guard<std::mutex> lk(mutex_);
        uint64_t total = 0;
        for (const auto& [pk, rec] : validators_) {
            (void)pk;
            if (!rec.active || !rec.bond_custodial || rec.bond_units == 0 || rec.slashed)
                continue;
            uint64_t capped =
                rec.bond_units < MIN_VALIDATOR_STAKE ? rec.bond_units : MIN_VALIDATOR_STAKE;
            if (UINT64_MAX - total < capped)
                return UINT64_MAX; // saturate, never wrap
            total += capped;
        }
        return total;
    }

    // One REGISTER transaction may fund exactly one validator term.  Every
    // REGISTER parser reads the transaction's complete STAKE_VAULT output sum;
    // accepting two markers would therefore count the same coins twice.  Count
    // even malformed REGISTER payloads (the action token alone is enough), so
    // an attacker cannot hide a second allocation behind a bad pubkey field.
    static bool HasValidRegisterMultiplicity(const Block& block) {
        for (const auto& tx : block.transactions) {
            size_t registrations = 0;
            for (const auto& out : tx.outputs) {
                const std::string data = ParseOpReturn(out.script_pubkey);
                if (data.rfind(VAL_PREFIX, 0) != 0)
                    continue;
                const std::string rest = data.substr(std::string(VAL_PREFIX).size());
                const size_t pipe = rest.find('|');
                const std::string action = pipe == std::string::npos ? rest : rest.substr(0, pipe);
                if (action == "REGISTER" && ++registrations > 1)
                    return false;
            }
        }
        return true;
    }

    bool ProcessBlock(
        const Block& block, std::function<uint64_t(const std::string&)> staking_get_stake,
        std::function<void(const std::string&, uint64_t)> staking_apply_slash_lockup = nullptr) {
        // Must precede the lock and every mutation below.  Node preflight treats
        // false as a candidate-block rejection on linear, replay, and reorg paths.
        if (!HasValidRegisterMultiplicity(block))
            return false;
        std::lock_guard<std::mutex> lk(mutex_);

        // A boundary block's mandatory D' settlement is validated against the
        // PARENT registry.  Consume that exact parent-state schedule before
        // any operation in this block can register, deregister, or slash a
        // validator.  Besides making every paid/confiscated tranche terminal,
        // this ordering prevents a same-block SLASH from retroactively
        // reclassifying yield that the block has already released.
        BondYieldBoundaryPlan bond_yield_plan;
        uint64_t fresh_bond_yield_units = 0;
        std::vector<std::pair<std::string, uint64_t>> bond_yield_allocations;
        const bool bond_yield_boundary = block.height > 0 &&
                                         block.height >= BOND_YIELD_ACTIVATION_HEIGHT &&
                                         (block.height % BOND_SETTLEMENT_INTERVAL) == 0;
        if (bond_yield_boundary) {
            bond_yield_plan = BuildBondYieldBoundaryPlanLocked(block.height);
            if (!bond_yield_plan.valid || !ComputeFreshBondYieldAccrualLocked(
                                              block, bond_yield_plan, fresh_bond_yield_units)) {
                return false;
            }

            // Derive the complete allocation before mutating either the
            // terminal-tranche ledger or the endorsement paid/prune state.
            // This keeps every false return from ProcessBlock atomic even when
            // a hostile block sends value to the escrow with no eligible bond.
            // ProcessEndorsementPoolStateLocked only flips reward_paid and
            // prunes outside ENDORSEMENT_RETENTION_BLOCKS; neither can change
            // this boundary's shorter vault-distribution eligibility window.
            if (fresh_bond_yield_units > 0) {
                const auto ew = ComputeEligibleBondWeights_Locked(block.height);
                __uint128_t sumw = 0;
                for (const auto& kv : ew)
                    sumw += kv.second.second;
                if (sumw == 0)
                    return false;

                uint64_t assigned = 0;
                std::string first_pubkey;
                size_t first_allocation_index = 0;
                bool first_has_allocation = false;
                for (const auto& [addr, pkw] : ew) {
                    (void)addr;
                    if (first_pubkey.empty())
                        first_pubkey = pkw.first;
                    const uint64_t share = (uint64_t)((__uint128_t)fresh_bond_yield_units *
                                                      (__uint128_t)pkw.second / sumw);
                    if (share == 0)
                        continue;
                    if (assigned > fresh_bond_yield_units - share)
                        return false;
                    if (pkw.first == first_pubkey) {
                        first_allocation_index = bond_yield_allocations.size();
                        first_has_allocation = true;
                    }
                    bond_yield_allocations.emplace_back(pkw.first, share);
                    assigned += share;
                }
                if (assigned < fresh_bond_yield_units) {
                    const uint64_t rem = fresh_bond_yield_units - assigned;
                    if (first_pubkey.empty())
                        return false;
                    if (first_has_allocation) {
                        uint64_t& first_units =
                            bond_yield_allocations[first_allocation_index].second;
                        if (first_units > UINT64_MAX - rem)
                            return false;
                        first_units += rem;
                    } else {
                        // Preserve the original deterministic floor-remainder
                        // rule even when every pro-rata floor is zero: the
                        // lexicographically first eligible address receives the
                        // complete sub-weight unit remainder.
                        bond_yield_allocations.emplace_back(first_pubkey, rem);
                    }
                }
            }
            RetireBondYieldTranchesLocked(bond_yield_plan);
        }

        // Paid-through is consensus state, so derive it before any current-block
        // ENDORSE op is applied.  The detector consumes only the prior tracked
        // endorsement-pool outpoint set and this block's bytes; no LevelDB/RPC/
        // IBD cursor can advance it.
        ProcessEndorsementPoolStateLocked(block);

        if (bond_yield_boundary) {
            for (const auto& [pubkey, units] : bond_yield_allocations) {
                bond_yield_escrow_[pubkey].push_back(BondYieldTranche{block.height, units});
            }
        }
        for (const auto& tx : block.transactions) {
            for (const auto& out : tx.outputs) {
                auto data = ParseOpReturn(out.script_pubkey);
                if (data.empty())
                    continue;
                if (data.substr(0, std::string(VAL_PREFIX).size()) != VAL_PREFIX)
                    continue;
                ProcessOp(data, block, tx, staking_get_stake, staking_apply_slash_lockup);
            }
        }
        // Do not make retirement depend on a funded endorsement-pool flush.
        // Once subsidy/fees leave that pool empty there may be no future flush,
        // but old records are already outside every consensus consumer window.
        PruneEndorsementsLocked(block.height);
        PruneInactiveValidatorsLocked(block.height);
        return true;
    }

    std::vector<ValidatorRecord> GetValidators() const {
        std::lock_guard<std::mutex> lk(mutex_);
        std::vector<ValidatorRecord> out;
        for (auto& [pk, rec] : validators_)
            if (rec.active)
                out.push_back(rec);
        std::sort(out.begin(), out.end(), [](const ValidatorRecord& a, const ValidatorRecord& b) {
            if (a.address != b.address)
                return a.address < b.address;
            return a.pubkey_hex < b.pubkey_hex;
        });
        return out;
    }

    // Complete registry view for bond-lifecycle RPC/UI surfaces.  GetValidators
    // intentionally remains the active membership set; exit-pending custodial
    // records must nevertheless remain visible until their canonical return
    // boundary so operators do not mistake a still-slashable bond for a free
    // registration slot.  Canonical sorting also makes the JSON stable across
    // unordered_map implementations.
    std::vector<ValidatorRecord> GetAllValidatorRecords() const {
        std::lock_guard<std::mutex> lk(mutex_);
        std::vector<ValidatorRecord> out;
        out.reserve(validators_.size());
        for (const auto& [pk, rec] : validators_) {
            (void)pk;
            out.push_back(rec);
        }
        std::sort(out.begin(), out.end(), [](const ValidatorRecord& a, const ValidatorRecord& b) {
            if (a.address != b.address)
                return a.address < b.address;
            return a.pubkey_hex < b.pubkey_hex;
        });
        return out;
    }

    size_t GetActiveValidatorCount() const {
        std::lock_guard<std::mutex> lk(mutex_);
        size_t n = 0;
        for (auto& [pk, rec] : validators_)
            if (rec.active)
                n++;
        return n;
    }

    size_t GetRecentlyActiveValidatorCount(uint64_t current_height,
                                           uint64_t window = 7ULL * BLOCKS_PER_DAY) const {
        std::lock_guard<std::mutex> lk(mutex_);
        std::unordered_set<std::string> active_endorsers;
        uint64_t from_height = current_height > window ? current_height - window : 0;
        for (auto& [height, recs] : endorsements_) {
            if (height >= from_height && height <= current_height) {
                for (auto& rec : recs) {
                    if (!rec.pubkey_hex.empty())
                        active_endorsers.insert(rec.pubkey_hex);
                }
            }
        }
        return active_endorsers.size();
    }

    // Layer-3 finality (btcVELD 51%-defense §5): the STAKE-weighted analogues of the
    // active/endorsed counts above. Summation is order-independent (commutative), so both
    // are deterministic across nodes. `get_stake(address)` is the staking ledger's GetStake.
    //
    // Summed stake of the DISTINCT validators who endorsed the exact canonical
    // block at `height`.  Height alone is not an identity: a marker naming a
    // sibling/alt block may be recorded on the eventual canonical chain, but it
    // must never lend its stake to finalizing the canonical block at that same
    // height.
    uint64_t GetEndorsedStake(uint64_t height, const std::string& canonical_block_hash_hex,
                              const std::function<uint64_t(const std::string&)>& get_stake) const {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = endorsements_.find(height);
        if (it == endorsements_.end())
            return 0;
        std::unordered_set<std::string> seen; // dedup by pubkey (one vote per validator)
        uint64_t total = 0;
        for (const auto& r : it->second) {
            if (r.pubkey_hex.empty() || r.address.empty())
                continue;
            if (r.block_hash_hex != canonical_block_hash_hex)
                continue;
            if (!seen.insert(r.pubkey_hex).second)
                continue;
            const uint64_t stake = get_stake(r.address);
            if (stake > UINT64_MAX - total)
                return UINT64_MAX;
            total += stake;
        }
        return total;
    }

    // Summed stake of validators that endorsed within `window` of `current_height`
    // (the finality denominator — the "active stake" a supermajority is measured against).
    uint64_t GetActiveStake(uint64_t current_height, uint64_t window,
                            const std::function<uint64_t(const std::string&)>& get_stake) const {
        std::lock_guard<std::mutex> lk(mutex_);
        uint64_t from_height = current_height > window ? current_height - window : 0;
        std::unordered_map<std::string, std::string> pk_addr; // distinct active endorser -> address
        for (const auto& [height, recs] : endorsements_) {
            if (height < from_height || height > current_height)
                continue;
            for (const auto& r : recs)
                if (!r.pubkey_hex.empty() && !r.address.empty())
                    pk_addr[r.pubkey_hex] = r.address;
        }
        uint64_t total = 0;
        for (const auto& [pk, addr] : pk_addr)
            total += get_stake(addr);
        return total;
    }

    // High-impact proposals use hard_quorum so the requirement never collapses
    // below `quorum`. General signalling retains a majority-of-active floor.
    uint32_t GetDynamicMinVotes(uint64_t current_height, uint32_t pct = 51, uint32_t quorum = 3,
                                bool hard_quorum = false) const {
        size_t active = GetRecentlyActiveValidatorCount(current_height, 7ULL * BLOCKS_PER_DAY);
        // Consensus percentage arithmetic must be exact on every target.  The
        // Compute ceil(active*pct/100) in a wide integer and clamp before the
        // public uint32_t result conversion.
        const unsigned __int128 numerator = (unsigned __int128)active * (unsigned __int128)pct;
        const unsigned __int128 exact =
            (numerator + (unsigned __int128)99) / (unsigned __int128)100;
        const uint32_t threshold =
            exact > (unsigned __int128)UINT32_MAX ? UINT32_MAX : (uint32_t)exact;
        if (hard_quorum)
            return std::max(quorum, threshold); // never collapses
        if (active == 0)
            return 1;
        if (active < quorum)
            return std::max((uint32_t)1, threshold);
        return std::max(quorum, threshold);
    }

    bool IsValidatorByAddress(const std::string& address) const {
        std::lock_guard<std::mutex> lk(mutex_);
        auto ait = address_to_pubkey_.find(address);
        if (ait == address_to_pubkey_.end())
            return false;
        auto vit = validators_.find(ait->second);
        return vit != validators_.end() && vit->second.active;
    }

    // Payout eligibility is not inferred from a raw OP_RETURN.  It exists only
    // when ProcessOp accepted a real validator endorsement signature for this
    // exact canonical tuple while replaying the marker's inclusion block.
    bool HasAcceptedEndorsement(const std::string& address, uint64_t height,
                                const std::string& block_hash_hex,
                                const std::string& sig_hex) const {
        if (!IsCanonicalLowerHex(block_hash_hex, 64) || !IsCanonicalLowerHex(sig_hex, 6618))
            return false;
        const std::string canonical_hash = CanonicalHex(block_hash_hex);
        const std::string sig_commitment =
            EndorsementFieldCommitment("VELD_ENDORSE_SIG_v1|", sig_hex);
        std::lock_guard<std::mutex> lk(mutex_);
        const auto it = endorsements_.find(height);
        if (it == endorsements_.end())
            return false;
        for (const auto& rec : it->second) {
            if (rec.address == address && rec.block_hash_hex == canonical_hash &&
                rec.sig_hex == sig_commitment)
                return true;
        }
        return false;
    }

    // Slash status for an address (operator UX, e.g.
    // getminerinfo). Distinct from IsValidatorByAddress: a slashed record
    // is NOT erased from validators_ (the SLASH branch only flips
    // active=false + slashed=true), so it is still resolvable here even
    // though it no longer counts as an active validator. Returns
    // {slashed, slashed_at_height}; {false,0} if the address was never a
    // validator or was never slashed. Read-only; replay-deterministic
    // (mirrors the validators_ state every node rebuilds from chain).
    std::pair<bool, uint64_t> GetSlashStatusByAddress(const std::string& address) const {
        std::lock_guard<std::mutex> lk(mutex_);
        auto ait = address_to_pubkey_.find(address);
        if (ait == address_to_pubkey_.end())
            return {false, 0};
        auto vit = validators_.find(ait->second);
        if (vit == validators_.end())
            return {false, 0};
        return {vit->second.slashed, vit->second.slashed_at_height};
    }

    // Deterministic evidence hold and DEREGISTER_RETURN boundary for a clean
    // (non-slashed) deregister at `deregistered_at_height`.  The custodial
    // principal must remain slashable for the COMPLETE accepted evidence
    // window.  Using MIN_EVIDENCE_WINDOW here used to return the bond after
    // only 12–36 hours even though a valid double-sign proof remains admissible
    // for seven days; a validator could therefore deregister, wait for payout,
    // and submit/face evidence while no confiscatable bond remained.
    static uint64_t DeregEvidenceCooldown(uint64_t deregistered_at_height) {
        return (deregistered_at_height >= STAKE_VAULT_ACTIVATION_HEIGHT)
                   ? std::max<uint64_t>(VALIDATOR_OP_COOLDOWN_BLOCKS,
                                        ::veld::finality::qc::FINALITY_CLEAN_EXIT_WINDOW)
                   : VALIDATOR_OP_COOLDOWN_BLOCKS;
    }

    // SINGLE SOURCE OF TRUTH: GetBondSettlements (when the return fires), the
    // REGISTER fail-closed gate (whether the prior term is still pending), and
    // late-evidence admission all use this boundary/cooldown pair, so return,
    // slashability, and re-registration cannot drift apart. A divergence could
    // double-pay, orphan a bond, or create evidence without collateral.
    static uint64_t DeregReturnBoundary(uint64_t deregistered_at_height,
                                        uint64_t last_finality_vote_height = 0) {
        const uint64_t cooldown = DeregEvidenceCooldown(deregistered_at_height);
        __uint128_t evidence_end = (__uint128_t)deregistered_at_height + (__uint128_t)cooldown;
        if (last_finality_vote_height != 0) {
            const __uint128_t finality_end =
                (__uint128_t)last_finality_vote_height +
                (__uint128_t)::veld::finality::qc::FINALITY_EQUIV_EVIDENCE_WINDOW;
            if (finality_end > evidence_end)
                evidence_end = finality_end;
        }
        // Evidence at its applicable inclusive horizon is still admissible
        // (the slash paths reject only `age > window`).  Settlement validation
        // observes the PARENT registry and validator ops apply afterward, so a
        // return on that same block would necessarily beat/reject valid evidence.
        // Select the first boundary STRICTLY AFTER the inclusive evidence end.
        const __uint128_t interval = BOND_SETTLEMENT_INTERVAL;
        const __uint128_t boundary = ((evidence_end / interval) + 1) * interval;
        return boundary > UINT64_MAX ? UINT64_MAX : (uint64_t)boundary;
    }

    static uint64_t SlashSettlementBoundary(uint64_t slashed_at_height) {
        const __uint128_t earliest =
            (__uint128_t)slashed_at_height + (__uint128_t)VALIDATOR_OP_COOLDOWN_BLOCKS;
        const __uint128_t interval = BOND_SETTLEMENT_INTERVAL;
        const __uint128_t boundary = ((earliest + interval - 1) / interval) * interval;
        return boundary > UINT64_MAX ? UINT64_MAX : (uint64_t)boundary;
    }

    struct BondLifecycleStatus {
        bool found{false};
        bool active{false};
        bool slashed{false};
        bool bond_custodial{false};
        uint64_t bond_units{0};
        uint64_t registered_height{0};
        uint64_t slashed_at_height{0};
        uint64_t deregistered_at_height{0};
        uint64_t return_boundary{0};
        uint64_t settlement_boundary{0};
    };

    BondLifecycleStatus GetBondLifecycleStatus(const std::string& pubkey_hex) const {
        std::lock_guard<std::mutex> lk(mutex_);
        BondLifecycleStatus out;
        auto it = validators_.find(pubkey_hex);
        if (it == validators_.end())
            return out;
        const auto& rec = it->second;
        out.found = true;
        out.active = rec.active;
        out.slashed = rec.slashed;
        out.bond_custodial = rec.bond_custodial;
        out.bond_units = rec.bond_units;
        out.registered_height = rec.registered_height;
        out.slashed_at_height = rec.slashed_at_height;
        out.deregistered_at_height = rec.deregistered_at_height;
        if (rec.bond_custodial && !rec.slashed && rec.bond_units > 0 &&
            rec.deregistered_at_height > 0) {
            out.return_boundary =
                DeregReturnBoundary(rec.deregistered_at_height, rec.last_finality_vote_height);
            out.settlement_boundary = out.return_boundary;
        } else if (rec.bond_custodial && rec.slashed && rec.bond_units > 0 &&
                   rec.slashed_at_height > 0) {
            out.settlement_boundary = SlashSettlementBoundary(rec.slashed_at_height);
        }
        return out;
    }

    // A public key identifies one bond-yield
    // term at a time.  A prior term remains authoritative until every tranche in
    // its consensus escrow ledger has been released or confiscated.  This read
    // mirror lets transaction preparation fail with an actionable error; the
    // consensus-enforcing predicate remains in ProcessOp below.
    bool HasPendingBondYield(const std::string& pubkey_hex) const {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = bond_yield_escrow_.find(pubkey_hex);
        return it != bond_yield_escrow_.end() && !it->second.empty();
    }

    // Read-only RPC/preflight mirror of the chain-apply SLASH temporal gates.
    // In particular, an INACTIVE cleanly-deregistered validator remains a valid
    // target until (but not including) its return boundary.
    bool CanAcceptSlashEvidence(const std::string& pubkey_hex, uint64_t sig_height,
                                uint64_t inclusion_height) const {
        std::lock_guard<std::mutex> lk(mutex_);
        return CanAcceptSlashEvidenceLocked(pubkey_hex, sig_height, inclusion_height);
    }

    std::vector<BondSettlement> GetBondSettlements(uint64_t boundary_height) const {
        std::lock_guard<std::mutex> lk(mutex_);
        std::vector<BondSettlement> out;
        if (boundary_height == 0 || (boundary_height % BOND_SETTLEMENT_INTERVAL) != 0)
            return out;
        for (const auto& [pk, rec] : validators_) {
            if (!rec.bond_custodial || rec.bond_units == 0)
                continue;
            BondSettlement bs;
            bs.address = rec.address;
            bs.bond_units = rec.bond_units;
            if (rec.slashed && rec.slashed_at_height > 0) {
                if (SlashSettlementBoundary(rec.slashed_at_height) != boundary_height)
                    continue;
                bs.kind = rec.slashed_equivocation ? BondSettlement::SLASH_EQUIVOCATION
                                                   : BondSettlement::SLASH_CONFISCATE;
                bs.slasher_address = CanonicalSlasherForPubkeyLocked(pk);
            } else if (rec.deregistered_at_height > 0 && !rec.slashed) {
                // Single-source boundary (see DeregReturnBoundary) — keeps this
                // return and the REGISTER fail-closed gate in lockstep.
                if (DeregReturnBoundary(rec.deregistered_at_height,
                                        rec.last_finality_vote_height) != boundary_height)
                    continue;
                bs.kind = BondSettlement::DEREGISTER_RETURN;
            } else {
                continue;
            }
            out.push_back(std::move(bs));
        }
        return out;
    }

    // ── D′ (yield-bearing custodial bond) — ───────────────────
    // D_TOP_TIER_PPM MUST stay == LockupTierMultiplierPpm(4) in
    // consensus/staking.h. Both intentionally hardcode the consensus
    // integer 1'500'000 (tier 4 = 90-day lockup, 1.50×). validators.h does
    // not include staking.h (include-cycle avoidance), so this invariant
    // is review-enforced, NOT compiler-enforced. DO NOT diverge — a
    // mismatch silently mis-sizes every escrow accrual.
    static constexpr uint64_t D_TOP_TIER_PPM = 1'500'000ULL;

    std::map<std::string, std::pair<std::string, uint64_t>>
    ComputeEligibleBondWeights_Locked(uint64_t boundary) const {
        std::map<std::string, std::pair<std::string, uint64_t>> out;
        if (boundary == 0)
            return out;
        uint64_t lo =
            (boundary > VAULT_DISTRIBUTION_INTERVAL) ? (boundary - VAULT_DISTRIBUTION_INTERVAL) : 0;
        std::unordered_set<std::string> endorsed_addresses;
        for (const auto& [h, recs] : endorsements_) {
            if (h >= lo && h < boundary) {
                for (const auto& r : recs)
                    if (!r.address.empty())
                        endorsed_addresses.insert(r.address);
            }
        }
        for (const auto& [pk, rec] : validators_) {
            if (!rec.active || !rec.bond_custodial || rec.bond_units == 0)
                continue;
            if (rec.slashed)
                continue;
            if (boundary < BOND_YIELD_STAKED_POSITION_HEIGHT &&
                endorsed_addresses.find(rec.address) == endorsed_addresses.end())
                continue;
            uint64_t capped =
                rec.bond_units < MIN_VALIDATOR_STAKE ? rec.bond_units : MIN_VALIDATOR_STAKE;
            uint64_t w = (uint64_t)((__uint128_t)capped * (__uint128_t)D_TOP_TIER_PPM /
                                    (__uint128_t)1'000'000ULL);
            if (w == 0)
                continue;
            out[rec.address] = {pk, w};
        }
        return out;
    }

    uint64_t GetEligibleBondYieldWeight(uint64_t boundary) const {
        std::lock_guard<std::mutex> lk(mutex_);
        uint64_t total = 0;
        for (const auto& [_, pkw] : ComputeEligibleBondWeights_Locked(boundary)) {
            if (UINT64_MAX - total < pkw.second)
                return UINT64_MAX;
            total += pkw.second;
        }
        return total;
    }

    std::vector<BondSettlement> GetBondYieldSettlements(uint64_t boundary) const {
        std::lock_guard<std::mutex> lk(mutex_);
        const BondYieldBoundaryPlan plan = BuildBondYieldBoundaryPlanLocked(boundary);
        return plan.valid ? plan.settlements : std::vector<BondSettlement>{};
    }

#ifdef VELD_TEST_HOOKS
    // ── TEST-ONLY SEAM (bond-yield regression sentinel) ─────────────────────────────
    // Gated by VELD_TEST_HOOKS — NEVER defined in any shipped / fleet / fuzz /
    // dryrun build (no build script passes it). Lets a harness inject the exact
    // {validator record, slash-recording height, offence evidence, bond-yield
    // escrow tranches} state that GetBondYieldSettlements consumes, so the bond-yield
    // late-slash confiscation boundary can be exercised in isolation. Pure
    // state injection into the same
    // private members the production accrual/slash paths populate; introduces no
    // new consensus reader. Compiled out entirely in every real binary.
    void TestInjectBondYieldState(const std::string& pubkey_hex, const std::string& address,
                                  bool slashed, uint64_t slashed_at_height,
                                  uint64_t offence_evidence_height, // 0 ⇒ inject no evidence
                                  const std::string& slasher_address,
                                  const std::vector<BondYieldTranche>& tranches,
                                  bool slashed_equivocation = false,
                                  uint64_t deregistered_at_height = 0,
                                  uint64_t last_finality_vote_height = 0) {
        std::lock_guard<std::mutex> lk(mutex_);
        ValidatorRecord rec;
        rec.pubkey_hex = pubkey_hex;
        rec.address = address;
        rec.active = !slashed && deregistered_at_height == 0;
        rec.slashed = slashed;
        rec.slashed_equivocation = slashed && slashed_equivocation;
        rec.slashed_at_height = slashed_at_height;
        rec.deregistered_at_height = deregistered_at_height;
        rec.last_finality_vote_height = last_finality_vote_height;
        rec.bond_custodial = true;
        rec.bond_units = MIN_VALIDATOR_STAKE;
        rec.registered_height = 1;
        validators_[pubkey_hex] = rec;
        address_to_pubkey_[address] = pubkey_hex;
        bond_yield_escrow_[pubkey_hex] = tranches;
        if (offence_evidence_height > 0) {
            SlashEvidence e;
            e.pubkey_hex = pubkey_hex;
            e.address = address;
            e.height = offence_evidence_height;
            e.slasher_address = slasher_address;
            slashed_evidence_.push_back(e);
        }
        if (rec.slashed_equivocation) {
            FinalityEquivocationRecord e;
            e.target_a_height = offence_evidence_height;
            e.target_b_height = offence_evidence_height;
            e.evidence_block = slashed_at_height;
            e.slasher_address = slasher_address;
            finality_equivocations_[pubkey_hex] = std::move(e);
        }
    }

    // Governance-gate sentinel seam: inject an active custodial-bonded validator
    // (no escrow/slash machinery) for governance bond-gate tests.
    void TestInjectValidatorBond(const std::string& pubkey_hex, const std::string& address,
                                 uint64_t bond_units, bool slashed = false) {
        std::lock_guard<std::mutex> lk(mutex_);
        ValidatorRecord rec;
        rec.pubkey_hex = pubkey_hex;
        rec.address = address;
        rec.active = !slashed;
        rec.slashed = slashed;
        rec.bond_custodial = true;
        rec.bond_units = bond_units;
        validators_[pubkey_hex] = rec;
        address_to_pubkey_[address] = pubkey_hex;
    }

    // Quorum-floor test seam: record one recently active validator at `height`.
    void TestInjectEndorsement(uint64_t height, const std::string& pubkey_hex,
                               const std::string& address = "",
                               const std::string& block_hash_hex = "") {
        std::lock_guard<std::mutex> lk(mutex_);
        EndorsementRecord erec;
        erec.pubkey_hex = pubkey_hex;
        erec.address = address; // stake-weighted finality (GetEndorsedStake) needs the addr
        erec.block_hash_hex = block_hash_hex;
        erec.block_height = height;
        endorsements_[height].push_back(erec);
    }
#endif // VELD_TEST_HOOKS

    //  D′ — read-only per-validator escrow summary for the
    // getbondvaultinfo RPC + custody/escrow UI. Returns {address,
    // pubkey_hex, outstanding_escrow_units} (Σ of the validator's currently
    // unsettled tranche units; terminal tranches are retired). NON-consensus:
    // pure read, never mutates state, holds no determinism contract
    // (mirrors GetValidators / GetMisbehavior). The authoritative
    // "currently escrowed" total is the on-chain BOND_YIELD_ESCROW balance
    // (the RPC reads that separately); this only gives the per-validator
    // attribution for display.
    std::vector<std::tuple<std::string, std::string, uint64_t>> GetBondYieldEscrowSummary() const {
        std::lock_guard<std::mutex> lk(mutex_);
        std::vector<std::tuple<std::string, std::string, uint64_t>> out;
        for (const auto& [pk, tranches] : bond_yield_escrow_) {
            uint64_t total = 0;
            for (const auto& t : tranches) {
                if (UINT64_MAX - total < t.units) {
                    total = UINT64_MAX;
                    break;
                }
                total += t.units;
            }
            std::string addr;
            auto vit = validators_.find(pk);
            if (vit != validators_.end())
                addr = vit->second.address;
            out.emplace_back(addr, pk, total);
        }
        return out;
    }

    bool IsRegistered(const std::string& pubkey_hex) const {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = validators_.find(pubkey_hex);
        return it != validators_.end() && it->second.active;
    }

    // Validator-op cooldown introspection for the RPC pre-check layer.
    //
    // ProcessBlock's DEREGISTER gate (and REGISTER gate) rejects an op when
    //   block.height < last_op_height_[address] + VALIDATOR_OP_COOLDOWN_BLOCKS
    // where last_op_height_[address] is stamped on BOTH register and
    // deregister. To let preparederegistervalidator refuse to build a tx that
    // consensus would reject, we expose the authoritative inputs to that gate
    // for the validator owning pubkey_hex:
    //   found            — pubkey is a known (currently active) validator
    //   registered_height— the height the validator registered at (messaging)
    //   unlock_height    — earliest block.height at which a validator-op for
    //                      this address passes the cooldown gate. 0 means no
    //                      active cooldown entry (op already mineable now).
    // Mirrors ProcessBlock exactly: keyed on last_op_height_[address], not on
    // registered_height (they coincide for a freshly-registered validator but
    // diverge after any later op, so we must read the live cooldown map).
    struct ValidatorOpCooldown {
        bool found{false};
        uint64_t registered_height{0};
        uint64_t unlock_height{0};
    };
    ValidatorOpCooldown GetDeregisterCooldown(const std::string& pubkey_hex) const {
        std::lock_guard<std::mutex> lk(mutex_);
        ValidatorOpCooldown out;
        auto it = validators_.find(pubkey_hex);
        if (it == validators_.end() || !it->second.active)
            return out;
        out.found = true;
        out.registered_height = it->second.registered_height;
        auto lh = last_op_height_.find(it->second.address);
        if (lh != last_op_height_.end())
            out.unlock_height = lh->second + VALIDATOR_OP_COOLDOWN_BLOCKS;
        return out;
    }

    // Retain the canonical epoch membership needed to verify 90-day
    // SLASH_EQUIV evidence after FinalityState prunes its two live snapshots.
    // Only 32-byte key commitments are retained; full PQ keys already live in
    // validators_ and the original evidence bytes remain in block history.
    bool RecordFinalitySnapshot(const ::veld::finality::qc::EpochSnapshot& snapshot) {
        namespace fq = ::veld::finality::qc;
        if (!fq::SnapshotWellFormed(snapshot))
            return false;
        FinalityMembershipRecord rec;
        rec.root = snapshot.root;
        rec.members.reserve(snapshot.entries.size());
        for (const auto& e : snapshot.entries)
            rec.members.push_back(e.pubkey_commit);
        std::sort(rec.members.begin(), rec.members.end());
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = finality_membership_.find(snapshot.epoch_id);
        if (it != finality_membership_.end())
            return it->second.root == rec.root && it->second.members == rec.members;
        if (!finality_membership_.empty() &&
            snapshot.epoch_id <= finality_membership_.rbegin()->first)
            return false;
        finality_membership_.emplace(snapshot.epoch_id, std::move(rec));
        const uint64_t keep = snapshot.epoch_id > fq::FINALITY_MEMBERSHIP_RETENTION_EPOCHS
                                  ? snapshot.epoch_id - fq::FINALITY_MEMBERSHIP_RETENTION_EPOCHS
                                  : 0;
        while (!finality_membership_.empty() && finality_membership_.begin()->first < keep)
            finality_membership_.erase(finality_membership_.begin());
        return true;
    }

    std::optional<RetainedFinalityMember>
    ResolveRetainedFinalityMember(uint64_t epoch, const Hash256& root,
                                  const std::string& pubkey_hex) const {
        namespace fq = ::veld::finality::qc;
        if (!IsCanonicalLowerHex(pubkey_hex, 3904))
            return std::nullopt;
        const Hash256 signer_commit = fq::PubkeyCommit(pubkey_hex);
        std::lock_guard<std::mutex> lk(mutex_);
        const auto membership = finality_membership_.find(epoch);
        if (membership == finality_membership_.end() || membership->second.root != root ||
            !std::binary_search(membership->second.members.begin(),
                                membership->second.members.end(), signer_commit))
            return std::nullopt;
        const auto validator = validators_.find(pubkey_hex);
        if (validator == validators_.end() || validator->second.pubkey_hex != pubkey_hex)
            return std::nullopt;
        RetainedFinalityMember out;
        out.epoch = epoch;
        out.root = root;
        out.pubkey_commit = signer_commit;
        out.pubkey_hex = pubkey_hex;
        return out;
    }

    // Read-only preparation mirror of every non-cryptographic consensus gate
    // in the exact-17 SLASH_EQUIV parser.  The caller already holds an
    // authenticated evidence capability, so source/signature structure is not
    // repeated here.  Reporter authorization remains a transaction-input gate
    // and is therefore checked by the RPC/transaction builder separately.
    bool CanAcceptFinalityEquivocationEvidence(const std::string& pubkey_hex, uint64_t epoch,
                                               const Hash256& set_root, uint8_t phase,
                                               uint32_t round, uint64_t target_height,
                                               uint64_t inclusion_height) const {
        namespace fq = ::veld::finality::qc;
        if ((phase != static_cast<uint8_t>(fq::Phase::PREVOTE) &&
             phase != static_cast<uint8_t>(fq::Phase::PRECOMMIT)) ||
            !fq::IsScheduledCheckpoint(target_height) || fq::EpochOf(target_height) != epoch ||
            fq::CheckpointRound(target_height) != round || target_height > inclusion_height ||
            (inclusion_height > target_height &&
             inclusion_height - target_height > fq::FINALITY_EQUIV_EVIDENCE_WINDOW) ||
            !IsCanonicalLowerHex(pubkey_hex, 3904))
            return false;

        const Hash256 signer_commit = fq::PubkeyCommit(pubkey_hex);
        std::lock_guard<std::mutex> lk(mutex_);
        const auto membership = finality_membership_.find(epoch);
        if (membership == finality_membership_.end() || membership->second.root != set_root ||
            !std::binary_search(membership->second.members.begin(),
                                membership->second.members.end(), signer_commit))
            return false;

        const auto validator = validators_.find(pubkey_hex);
        if (validator == validators_.end() || validator->second.slashed_equivocation ||
            target_height < validator->second.registered_height)
            return false;
        if (validator->second.deregistered_at_height > 0 && !validator->second.slashed &&
            inclusion_height >= DeregReturnBoundary(validator->second.deregistered_at_height,
                                                    validator->second.last_finality_vote_height))
            return false;

        const std::string dedup_key =
            "EQ:" + pubkey_hex + ":" + std::to_string(epoch) + ":" + std::to_string(round);
        return slashed_evidence_keys_.find(dedup_key) == slashed_evidence_keys_.end() &&
               finality_equivocations_.find(pubkey_hex) == finality_equivocations_.end();
    }

    // A signature counted in a canonical certificate extends clean-exit
    // collateral through the complete finality evidence horizon.
    bool RecordFinalityQc(const ::veld::finality::qc::QuorumCert& qc,
                          const ::veld::finality::qc::EpochSnapshot& snapshot,
                          uint64_t carrier_height) {
        namespace fq = ::veld::finality::qc;
        if (!fq::QcWellFormed(qc, snapshot) || qc.phase != fq::Phase::PRECOMMIT)
            return false;
        std::lock_guard<std::mutex> lk(mutex_);
        for (size_t i = 0; i < snapshot.entries.size(); ++i) {
            if (!(qc.bitmap[i >> 3] & (uint8_t)(1u << (i & 7))))
                continue;
            auto vit = validators_.find(snapshot.entries[i].pubkey_hex);
            if (vit == validators_.end() ||
                fq::PubkeyCommit(vit->first) != snapshot.entries[i].pubkey_commit)
                return false;
            vit->second.last_finality_vote_height =
                std::max(vit->second.last_finality_vote_height, carrier_height);
        }
        return true;
    }

    Hash256 ValidatorsDigest() const {
        std::lock_guard<std::mutex> lk(mutex_);
        namespace sd = ::veld::state_digest;

        // Validator-state digest v6.  V1 covered only a subset of each record
        // and could therefore report equality for states that made different
        // future decisions (different deregistration/slash boundaries, cooldown
        // admission, tombstones, evidence, or endorsement eligibility).  This
        // serialization covers every block-mutable container except the D'
        // tranche ledger, which is intentionally committed by the separately
        // domain-separated BondYieldEscrowDigest below.  Unordered containers
        // are canonicalized before encoding.
        std::vector<uint8_t> body;
        // V5 added the exact endorsed block hash. V6 commits the canonical
        // public-key/signature commitments and the deterministically pruned
        // retention window rather than duplicating multi-kilobyte PQ material
        // in every live record.
        sd::put_u32_le(body, 7); // encoding version
        // This mutable instance rule directly controls REGISTER and ENDORSE
        // admission.  It is configuration rather than rollback state, but two
        // same-chain instances with different values must not report the same
        // next-block decision digest.
        sd::put_u64_le(body, min_validator_stake_override_);

        std::vector<std::string> pks;
        pks.reserve(validators_.size());
        for (const auto& [pk, _r] : validators_)
            pks.push_back(pk);
        std::sort(pks.begin(), pks.end());
        sd::put_u32_le(body, (uint32_t)pks.size());
        for (const auto& pk : pks) {
            const auto& rec = validators_.at(pk);
            sd::put_len_prefixed(body, pk);
            sd::put_len_prefixed(body, rec.pubkey_hex);
            sd::put_len_prefixed(body, rec.address);
            sd::put_u64_le(body, rec.registered_height);
            sd::put_u8(body, rec.active ? 1 : 0);
            sd::put_u8(body, rec.slashed ? 1 : 0);
            sd::put_u8(body, rec.slashed_equivocation ? 1 : 0);
            sd::put_u64_le(body, rec.slashed_at_height);
            sd::put_u8(body, rec.bond_custodial ? 1 : 0);
            sd::put_u64_le(body, rec.bond_units);
            sd::put_u64_le(body, rec.deregistered_at_height);
            sd::put_u64_le(body, rec.last_finality_vote_height);
        }

        std::vector<std::string> addresses;
        addresses.reserve(address_to_pubkey_.size());
        for (const auto& [address, _pk] : address_to_pubkey_)
            addresses.push_back(address);
        std::sort(addresses.begin(), addresses.end());
        sd::put_u32_le(body, (uint32_t)addresses.size());
        for (const auto& address : addresses) {
            sd::put_len_prefixed(body, address);
            sd::put_len_prefixed(body, address_to_pubkey_.at(address));
        }

        std::vector<uint64_t> endorsement_heights;
        endorsement_heights.reserve(endorsements_.size());
        for (const auto& [height, _records] : endorsements_)
            endorsement_heights.push_back(height);
        std::sort(endorsement_heights.begin(), endorsement_heights.end());
        sd::put_u32_le(body, (uint32_t)endorsement_heights.size());
        for (uint64_t height : endorsement_heights) {
            sd::put_u64_le(body, height);
            auto records = endorsements_.at(height);
            std::sort(records.begin(), records.end(),
                      [](const EndorsementRecord& a, const EndorsementRecord& b) {
                          return std::tie(a.pubkey_hex, a.address, a.sig_hex, a.block_hash_hex,
                                          a.block_height, a.reward_paid) <
                                 std::tie(b.pubkey_hex, b.address, b.sig_hex, b.block_hash_hex,
                                          b.block_height, b.reward_paid);
                      });
            sd::put_u32_le(body, (uint32_t)records.size());
            for (const auto& rec : records) {
                sd::put_len_prefixed(body, rec.pubkey_hex);
                sd::put_len_prefixed(body, rec.address);
                sd::put_len_prefixed(body, rec.sig_hex);
                sd::put_len_prefixed(body, rec.block_hash_hex);
                sd::put_u64_le(body, rec.block_height);
                sd::put_u8(body, rec.reward_paid ? 1 : 0);
            }
        }

        auto put_sorted_strings = [&body](const auto& values) {
            std::vector<std::string> sorted(values.begin(), values.end());
            std::sort(sorted.begin(), sorted.end());
            sd::put_u32_le(body, (uint32_t)sorted.size());
            for (const auto& value : sorted)
                sd::put_len_prefixed(body, value);
        };
        put_sorted_strings(endorsement_keys_);
        // These outpoints are consensus state: they define whether a future
        // boundary transaction consumed the complete prior endorsement pool.
        // Store canonical strings sorted byte-lexicographically so unordered
        // container bucket order can never affect the digest.
        put_sorted_strings(endorsement_pool_outpoints_);
        sd::put_u64_le(body, last_canonical_endorsement_flush_height_);

        std::vector<std::string> cooldown_addresses;
        cooldown_addresses.reserve(last_op_height_.size());
        for (const auto& [address, _height] : last_op_height_)
            cooldown_addresses.push_back(address);
        std::sort(cooldown_addresses.begin(), cooldown_addresses.end());
        sd::put_u32_le(body, (uint32_t)cooldown_addresses.size());
        for (const auto& address : cooldown_addresses) {
            sd::put_len_prefixed(body, address);
            sd::put_u64_le(body, last_op_height_.at(address));
        }

        auto evidence = slashed_evidence_;
        std::sort(
            evidence.begin(), evidence.end(), [](const SlashEvidence& a, const SlashEvidence& b) {
                return std::tie(a.pubkey_hex, a.height, a.evidence_block, a.hash_a_hex,
                                a.hash_b_hex, a.sig_a_hex, a.sig_b_hex, a.slasher_address,
                                a.address) < std::tie(b.pubkey_hex, b.height, b.evidence_block,
                                                      b.hash_a_hex, b.hash_b_hex, b.sig_a_hex,
                                                      b.sig_b_hex, b.slasher_address, b.address);
            });
        sd::put_u32_le(body, (uint32_t)evidence.size());
        for (const auto& ev : evidence) {
            sd::put_len_prefixed(body, ev.pubkey_hex);
            sd::put_len_prefixed(body, ev.address);
            sd::put_u64_le(body, ev.height);
            sd::put_len_prefixed(body, ev.hash_a_hex);
            sd::put_len_prefixed(body, ev.hash_b_hex);
            sd::put_len_prefixed(body, ev.sig_a_hex);
            sd::put_len_prefixed(body, ev.sig_b_hex);
            sd::put_len_prefixed(body, ev.slasher_address);
            sd::put_u64_le(body, ev.evidence_block);
        }
        put_sorted_strings(slashed_evidence_keys_);

        std::vector<std::string> evidence_count_pks;
        evidence_count_pks.reserve(evidence_per_pubkey_.size());
        for (const auto& [pk, _count] : evidence_per_pubkey_)
            evidence_count_pks.push_back(pk);
        std::sort(evidence_count_pks.begin(), evidence_count_pks.end());
        sd::put_u32_le(body, (uint32_t)evidence_count_pks.size());
        for (const auto& pk : evidence_count_pks) {
            sd::put_len_prefixed(body, pk);
            sd::put_u32_le(body, evidence_per_pubkey_.at(pk));
        }
        put_sorted_strings(slashed_pubkeys_);

        sd::put_u32_le(body, (uint32_t)finality_membership_.size());
        for (const auto& [epoch, membership] : finality_membership_) {
            sd::put_u64_le(body, epoch);
            sd::put_bytes(body, membership.root.data(), membership.root.size());
            sd::put_u32_le(body, (uint32_t)membership.members.size());
            for (const auto& member : membership.members)
                sd::put_bytes(body, member.data(), member.size());
        }
        sd::put_u32_le(body, (uint32_t)finality_equivocations_.size());
        for (const auto& [pk, ev] : finality_equivocations_) {
            sd::put_len_prefixed(body, pk);
            sd::put_u64_le(body, ev.epoch);
            sd::put_u8(body, ev.phase);
            sd::put_u32_le(body, ev.round);
            sd::put_u64_le(body, ev.target_a_height);
            sd::put_bytes(body, ev.target_a_hash.data(), ev.target_a_hash.size());
            sd::put_u64_le(body, ev.target_b_height);
            sd::put_bytes(body, ev.target_b_hash.data(), ev.target_b_hash.size());
            sd::put_u64_le(body, ev.evidence_block);
            sd::put_len_prefixed(body, ev.slasher_address);
            sd::put_bytes(body, ev.evidence_commit.data(), ev.evidence_commit.size());
        }
        sd::put_u64_le(body, total_staked_units_.load(std::memory_order_relaxed));

        return sd::sha256_domain(sd::tags::VALIDATORS, body);
    }

    Hash256 BondYieldEscrowDigest() const {
        std::lock_guard<std::mutex> lk(mutex_);
        namespace sd = ::veld::state_digest;
        std::vector<uint8_t> body;
        sd::put_u32_le(body, 2); // encoding version
        std::vector<std::string> pks;
        pks.reserve(bond_yield_escrow_.size());
        for (const auto& [pk, _tranches] : bond_yield_escrow_)
            pks.push_back(pk);
        std::sort(pks.begin(), pks.end());
        sd::put_u32_le(body, (uint32_t)pks.size());
        for (const auto& pk : pks) {
            sd::put_len_prefixed(body, pk);
            std::string address;
            auto vit = validators_.find(pk);
            if (vit != validators_.end())
                address = vit->second.address;
            sd::put_len_prefixed(body, address);
            auto tranches = bond_yield_escrow_.at(pk);
            std::sort(tranches.begin(), tranches.end(),
                      [](const BondYieldTranche& a, const BondYieldTranche& b) {
                          if (a.accrual_height != b.accrual_height)
                              return a.accrual_height < b.accrual_height;
                          return a.units < b.units;
                      });
            sd::put_u32_le(body, (uint32_t)tranches.size());
            for (const auto& tranche : tranches) {
                sd::put_u64_le(body, tranche.accrual_height);
                sd::put_u64_le(body, tranche.units);
            }
        }
        return sd::sha256_domain(sd::tags::BONDYIELD, body);
    }

    bool IsAlreadySlashed(const std::string& pubkey_hex, uint64_t height) const {
        std::lock_guard<std::mutex> lk(mutex_);
        return slashed_evidence_keys_.count(pubkey_hex + ":" + std::to_string(height)) > 0;
    }

    std::vector<EndorsementRecord> GetEndorsements(uint64_t height) const {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = endorsements_.find(height);
        if (it == endorsements_.end())
            return {};
        auto out = it->second;
        // Preserve the public RPC/API contract: callers receive the registered
        // full public key when it is still available, while the consensus
        // window stores only its compact commitment per endorsement.
        for (auto& rec : out) {
            auto ait = address_to_pubkey_.find(rec.address);
            if (ait != address_to_pubkey_.end())
                rec.pubkey_hex = ait->second;
        }
        return out;
    }

    size_t GetEndorsementCount(uint64_t height) const {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = endorsements_.find(height);
        if (it == endorsements_.end())
            return 0;
        return it->second.size();
    }

    std::vector<PendingReward> GetPendingEndorsementRewards() const {
        std::lock_guard<std::mutex> lk(mutex_);
        std::vector<PendingReward> out;
        for (auto& [height, recs] : endorsements_) {
            for (auto& rec : recs) {
                if (!rec.reward_paid) {
                    out.push_back({rec.address, 0, height});
                }
            }
        }
        return out;
    }

    // Canonical-chain-derived cursor for operator logging/persistence only.
    // There is intentionally no public mutator: disk/RPC/IBD state must never
    // be able to advance consensus reward state.
    uint64_t LastCanonicalEndorsementFlushHeight() const {
        std::lock_guard<std::mutex> lk(mutex_);
        return last_canonical_endorsement_flush_height_;
    }

    void Reset() {
        std::lock_guard<std::mutex> lk(mutex_);
        validators_.clear();
        endorsements_.clear();
        endorsement_keys_.clear();
        endorsement_pool_outpoints_.clear();
        last_canonical_endorsement_flush_height_ = 0;
        last_op_height_.clear();
        address_to_pubkey_.clear();
        slashed_evidence_.clear();
        slashed_evidence_keys_.clear();
        slashed_pubkeys_.clear();
        evidence_per_pubkey_.clear();
        bond_yield_escrow_.clear();
        finality_membership_.clear();
        finality_equivocations_.clear();
    }

    // Atomic block-state snapshot and restore. Captures every
    // block-mutable registry field Reset() clears plus total_staked_units_,
    // which the block apply path updates before ProcessBlock and therefore must
    // roll back with a rejected block. Never captures the mutex, node-set
    // minimum configuration, or the callback, so the
    // block-connect path can roll the validator registry back verbatim on an
    // all-or-nothing block reject — including bond_yield_escrow_, which a rejected
    // block's vault-boundary append must undo (the "rebuilt by replay" note refers
    // to disk snapshots, not this in-memory atomic rollback).
    struct StateSnapshot {
        std::unordered_map<std::string, ValidatorRecord> validators;
        std::unordered_map<uint64_t, std::vector<EndorsementRecord>> endorsements;
        std::unordered_set<std::string> endorsement_keys;
        std::unordered_set<std::string> endorsement_pool_outpoints;
        uint64_t last_canonical_endorsement_flush_height = 0;
        std::unordered_map<std::string, uint64_t> last_op_height;
        std::unordered_map<std::string, std::string> address_to_pubkey;
        std::vector<SlashEvidence> slashed_evidence;
        std::unordered_set<std::string> slashed_evidence_keys;
        std::unordered_set<std::string> slashed_pubkeys;
        std::unordered_map<std::string, uint32_t> evidence_per_pubkey;
        std::unordered_map<std::string, std::vector<BondYieldTranche>> bond_yield_escrow;
        std::map<uint64_t, FinalityMembershipRecord> finality_membership;
        std::map<std::string, FinalityEquivocationRecord> finality_equivocations;
        uint64_t total_staked_units = 0;
    };
    StateSnapshot SnapshotState() const {
        std::lock_guard<std::mutex> lk(mutex_);
        return StateSnapshot{validators_,
                             endorsements_,
                             endorsement_keys_,
                             endorsement_pool_outpoints_,
                             last_canonical_endorsement_flush_height_,
                             last_op_height_,
                             address_to_pubkey_,
                             slashed_evidence_,
                             slashed_evidence_keys_,
                             slashed_pubkeys_,
                             evidence_per_pubkey_,
                             bond_yield_escrow_,
                             finality_membership_,
                             finality_equivocations_,
                             total_staked_units_.load(std::memory_order_relaxed)};
    }
    void RestoreState(const StateSnapshot& s) {
        std::lock_guard<std::mutex> lk(mutex_);
        validators_ = s.validators;
        endorsements_ = s.endorsements;
        endorsement_keys_ = s.endorsement_keys;
        endorsement_pool_outpoints_ = s.endorsement_pool_outpoints;
        last_canonical_endorsement_flush_height_ = s.last_canonical_endorsement_flush_height;
        last_op_height_ = s.last_op_height;
        address_to_pubkey_ = s.address_to_pubkey;
        slashed_evidence_ = s.slashed_evidence;
        slashed_evidence_keys_ = s.slashed_evidence_keys;
        slashed_pubkeys_ = s.slashed_pubkeys;
        evidence_per_pubkey_ = s.evidence_per_pubkey;
        bond_yield_escrow_ = s.bond_yield_escrow;
        finality_membership_ = s.finality_membership;
        finality_equivocations_ = s.finality_equivocations;
        total_staked_units_.store(s.total_staked_units, std::memory_order_relaxed);
    }

    // ── Signature verification (static, used by daemon + node) ────────────────
    //
    // //
    //   V1 (legacy, height < BATCH2_HARDENING_HEIGHT):
    //     msg = Hash256d( uint64_le(height) || block_hash_bytes_32 )
    //
    //   V2 (height >= BATCH2_HARDENING_HEIGHT):
    //     msg = Hash256d( "VELD_ENDORSE\0\0\0\0" || network_byte
    //                   || ASCII(GENESIS_HASH) || uint64_le(height)
    //                   || block_hash_bytes_32 )
    //
    // The V1 format omits ALL chain-context binding. A testnet validator
    // who legitimately endorses two competing alternate-chain testnet
    // blocks at the same testnet height H (a normal fork-resolution
    // event, NOT a double-sign) produces two valid sigs whose preimages
    // are byte-identical-shape to a hypothetical mainnet endorsement
    // at mainnet height H. If the validator's pubkey is also registered
    // on mainnet, an attacker can lift those two testnet sigs into a
    // mainnet SLASH OP_RETURN — the mainnet SLASH branch verifies them
    // cryptographically (same pubkey, same message shape) and applies
    // Penalty: permanent ban + bond confiscation + 25% slasher
    // bounty to the attacker. Net: any cross-chain validator can be
    // permanently destroyed by harvesting their natural testnet
    // fork-endorsement traffic.
    //
    // V2 prepends a 16-byte ASCII domain tag, the network-id byte
    // (0x4D = mainnet 'M', 0x54 = testnet 'T'), and the 64-byte ASCII
    // hex of GENESIS_HASH — matching the chain-id binding discipline
    // that ComputeSighash already uses for spend-side ML-DSA sigs.
    // After activation, the cross-chain replay vector is closed because
    // testnet and mainnet have disjoint network bytes AND disjoint
    // GENESIS_HASH values.
    //
    // Activation is a hard fork: pre-V2 sigs DO NOT verify under V2
    // and vice-versa. Coordinated rollout to fleet + VEB + any external
    // validator endorser is mandatory before BATCH2_HARDENING_HEIGHT.
    static Hash256 BuildEndorseMessage(uint64_t height, const Hash256& block_hash) {
        std::vector<uint8_t> msg;
        if (height >= BATCH2_HARDENING_HEIGHT) {
            msg.reserve(128);
            static constexpr char DOMAIN_TAG[16] = {'V', 'E', 'L', 'D', '_',  'E',  'N',  'D',
                                                    'O', 'R', 'S', 'E', '\0', '\0', '\0', '\0'};
            msg.insert(msg.end(), DOMAIN_TAG, DOMAIN_TAG + sizeof(DOMAIN_TAG));
#ifdef VELD_MAINNET_POW
            msg.push_back(0x4D);
#else
            msg.push_back(0x54);
#endif
            for (const char* p = GENESIS_HASH; *p; ++p) {
                msg.push_back((uint8_t)*p);
            }
        }
        for (int i = 0; i < 8; i++)
            msg.push_back((uint8_t)((height >> (i * 8)) & 0xFF));
        msg.insert(msg.end(), block_hash.begin(), block_hash.end());
        return Hash256d(msg);
    }

    // Verify one finality vote signature for SLASH_EQUIV evidence.
    //
    // Reconstructs the EXACT preimage finality_qc.h::VotePreimage produces —
    // via that same function, not a reimplementation. A second copy of preimage
    // construction is a fork waiting for one of the copies to be edited: the
    // slash path and the finality path must agree byte-for-byte forever, and
    // the only way to guarantee that is to have one of them.
    static bool VerifyFinalityVoteSignature(const std::string& pubkey_hex, uint64_t epoch,
                                            const std::string& set_root_hex, uint64_t phase,
                                            uint64_t round, uint64_t src_h,
                                            const std::string& src_hash_hex, uint64_t tgt_h,
                                            const std::string& tgt_hash_hex,
                                            const std::string& sig_hex) {
        namespace fq = ::veld::finality::qc;
        if (!IsExactHex(pubkey_hex, 3904) || !IsExactHex(sig_hex, 6618))
            return false;

        auto hex_to_hash = [](const std::string& h, Hash256& out) -> bool {
            if (h.size() != 64)
                return false;
            const auto b = HexToBytes(h);
            if (b.size() != 32)
                return false;
            std::copy(b.begin(), b.end(), out.begin());
            return true;
        };
        Hash256 set_root{}, src_hash{}, tgt_hash{};
        if (!hex_to_hash(set_root_hex, set_root))
            return false;
        if (!hex_to_hash(src_hash_hex, src_hash))
            return false;
        if (!hex_to_hash(tgt_hash_hex, tgt_hash))
            return false;

        fq::CheckpointRef src;
        src.height = src_h;
        src.hash = src_hash;
        fq::CheckpointRef tgt;
        tgt.height = tgt_h;
        tgt.hash = tgt_hash;
        if ((phase != (uint64_t)fq::Phase::PREVOTE && phase != (uint64_t)fq::Phase::PRECOMMIT) ||
            round > UINT32_MAX || !fq::IsScheduledCheckpoint(tgt.height) ||
            fq::EpochOf(tgt.height) != epoch || fq::CheckpointRound(tgt.height) != round ||
            !fq::SourceRefWellFormed(src, tgt))
            return false;

        // GenesisHashBytes: the ASCII GENESIS_HASH this binary is built for.
        // Together with fq::NETWORK_ID this is the chain binding that stops a
        // testnet vote being lifted into mainnet evidence — the V1-endorsement
        // hazard documented above, which is the reason that convention exists.
        static const Hash256 genesis = [] {
            Hash256 g{};
            auto nib = [](char c) -> int {
                if (c >= '0' && c <= '9')
                    return c - '0';
                if (c >= 'a' && c <= 'f')
                    return c - 'a' + 10;
                if (c >= 'A' && c <= 'F')
                    return c - 'A' + 10;
                return 0;
            };
            for (size_t i = 0; i < 32 && GENESIS_HASH[2 * i] && GENESIS_HASH[2 * i + 1]; ++i)
                g[i] = (uint8_t)((nib(GENESIS_HASH[2 * i]) << 4) | nib(GENESIS_HASH[2 * i + 1]));
            return g;
        }();

        const auto msg = fq::VotePreimage(fq::NETWORK_ID, genesis, epoch, set_root,
                                          (fq::Phase)(uint8_t)phase, (uint32_t)round, src, tgt);

        const auto pubkey_bytes = HexToBytes(pubkey_hex);
        const auto sig_bytes = HexToBytes(sig_hex);
        if (pubkey_bytes.size() != 1952 || sig_bytes.size() != 3309)
            return false;
        ::veld::dilithium::PublicKey pk{};
        std::copy(pubkey_bytes.begin(), pubkey_bytes.end(), pk.begin());
        return ::veld::dilithium::Verify(pk, msg, sig_bytes);
    }

    static bool VerifyEndorseSignature(const std::string& pubkey_hex, uint64_t height,
                                       const Hash256& block_hash, const std::string& sig_hex) {
        if (!IsExactHex(pubkey_hex, 3904) || !IsExactHex(sig_hex, 6618))
            return false;
        auto pubkey_bytes = HexToBytes(pubkey_hex);
        auto sig_bytes = HexToBytes(sig_hex);
        if (pubkey_bytes.size() != 1952 || sig_bytes.size() != 3309)
            return false;

        Secp256k1PubKey pubkey;
        std::copy(pubkey_bytes.begin(), pubkey_bytes.end(), pubkey.begin());

        Hash256 msg = BuildEndorseMessage(height, block_hash);
        return Verify(pubkey, msg, sig_bytes);
    }

    static std::string BuildRegisterOp(const std::string& pubkey_hex) {
        return std::string(VAL_PREFIX) + "REGISTER|" + pubkey_hex;
    }

    static std::string BuildDeregisterOp(const std::string& pubkey_hex) {
        return std::string(VAL_PREFIX) + "DEREGISTER|" + pubkey_hex;
    }

    static std::string BuildSlashOp(const std::string& pubkey_hex, uint64_t height,
                                    const std::string& hash_a_hex, const std::string& sig_a_hex,
                                    const std::string& hash_b_hex, const std::string& sig_b_hex) {
        return std::string(VAL_PREFIX) + "SLASH|" + pubkey_hex + "|" + std::to_string(height) +
               "|" + hash_a_hex + "|" + sig_a_hex + "|" + hash_b_hex + "|" + sig_b_hex + "|v1";
    }

    // Defined in finality_equivocation.h after the authenticated evidence
    // capability is complete.  The exact type prevents construction from two
    // unverified raw votes; this function only serializes and has no state.
    static std::string BuildSlashEquivOp(const finality::qc::ValidatedEquivocationEvidence& pair);

    std::vector<SlashEvidence> GetMisbehavior() const {
        std::lock_guard<std::mutex> lk(mutex_);
        std::vector<SlashEvidence> out;
        out.reserve(slashed_evidence_.size());
        for (const auto& e : slashed_evidence_)
            out.push_back(e);
        return out;
    }

    static std::string BuildEndorseOp(uint64_t height, const std::string& block_hash_hex,
                                      const std::string& sig_hex) {
        return std::string(VAL_PREFIX) + "ENDORSE|" + std::to_string(height) + "|" +
               block_hash_hex + "|" + sig_hex;
    }

    void SetLastFlushRewardPerEndorsement(double veld) {
        last_flush_reward_per_endorsement_.store(veld, std::memory_order_relaxed);
    }
    double GetLastFlushRewardPerEndorsement() const {
        return last_flush_reward_per_endorsement_.load(std::memory_order_relaxed);
    }

  private:
    mutable std::mutex mutex_;
    std::atomic<uint64_t> total_staked_units_{0};
    uint64_t min_validator_stake_override_{0};
    std::atomic<double> last_flush_reward_per_endorsement_{0.0};

    BlockKnownAtHeightFn block_known_at_height_fn_{};

    std::unordered_map<std::string, ValidatorRecord> validators_;

    std::unordered_map<std::string, std::string> address_to_pubkey_;

    std::unordered_map<uint64_t, std::vector<EndorsementRecord>> endorsements_;
    std::unordered_set<std::string> endorsement_keys_;

    // Canonical endorsement-pool UTXO identity, rebuilt only by ProcessBlock.
    // Values are `<64 lowercase txid hex>:<decimal vout>` and are never loaded
    // from an index/database cursor.  A boundary marks rewards paid only when a
    // single transaction consumes this entire prior set exactly once.
    std::unordered_set<std::string> endorsement_pool_outpoints_;
    uint64_t last_canonical_endorsement_flush_height_{0};

    std::unordered_map<std::string, uint64_t> last_op_height_;

    // D′ yield escrow ledger.
    // pubkey_hex -> list of accrual tranches. Appended by ProcessBlock at
    // each vault-distribution boundary >= BOND_YIELD_ACTIVATION_HEIGHT
    // from the AUTHORITATIVE on-chain BOND_YIELD_ESCROW output value in
    // that block (split pro-rata by the same eligible weights fed to
    // ComputeExpectedVaultDistribution). Terminal tranches are erased at the
    // exact parent-state release/confiscation boundary before current-block
    // validator ops. NEVER persisted to disk; rebuilt solely by Reset()+replay
    // and captured by in-memory atomic/reorg snapshots. Consumed by
    // GetBondYieldSettlements (release/clawback) and summarised by the
    // getbondvaultinfo RPC.
    std::unordered_map<std::string, std::vector<BondYieldTranche>> bond_yield_escrow_;

    std::vector<SlashEvidence> slashed_evidence_;
    std::unordered_set<std::string> slashed_evidence_keys_;
    std::unordered_map<std::string, uint32_t> evidence_per_pubkey_;
    std::unordered_set<std::string> slashed_pubkeys_;
    std::map<uint64_t, FinalityMembershipRecord> finality_membership_;
    std::map<std::string, FinalityEquivocationRecord> finality_equivocations_;

    enum class BondYieldTerminalKind : uint8_t { NONE = 0, RELEASE = 1, CONFISCATE = 2 };

    // One immutable plan for a settlement boundary, derived entirely from the
    // parent validator/tranche state.  GetBondYieldSettlements publishes its
    // payouts and ProcessBlock consumes its terminal mask; keeping both sides
    // on this single representation prevents payout/retirement schedule drift.
    struct BondYieldBoundaryPlan {
        bool valid{true};
        uint64_t prior_units{0};
        uint64_t terminal_units{0};
        std::vector<BondSettlement> settlements;
        std::unordered_map<std::string, std::vector<uint8_t>> terminal_mask;
    };

    static uint64_t CeilBondYieldSettlementBoundary(__uint128_t height) {
        const __uint128_t interval = BOND_SETTLEMENT_INTERVAL;
        const __uint128_t boundary = ((height + interval - 1) / interval) * interval;
        return boundary > UINT64_MAX ? UINT64_MAX : (uint64_t)boundary;
    }

    static bool AddBondYieldUnits(uint64_t& total, uint64_t units) {
        if (total > UINT64_MAX - units)
            return false;
        total += units;
        return true;
    }

    BondYieldBoundaryPlan BuildBondYieldBoundaryPlanLocked(uint64_t boundary) const {
        BondYieldBoundaryPlan plan;
        if (boundary == 0 || (boundary % BOND_SETTLEMENT_INTERVAL) != 0)
            return plan;

        for (const auto& [pk, tranches] : bond_yield_escrow_) {
            auto& terminal = plan.terminal_mask[pk];
            terminal.assign(tranches.size(), 0);

            const auto vit = validators_.find(pk);
            if (vit == validators_.end()) {
                // A tranche without its validator record has no canonical
                // recipient or slash context.  Never silently drop or invent a
                // payout for corrupted/orphaned consensus state.
                plan.valid = false;
                return plan;
            }
            const ValidatorRecord& rec = vit->second;

            const bool slashed = rec.slashed && rec.slashed_at_height > 0;
            uint64_t slash_forfeit_boundary = 0;
            uint64_t confiscation_boundary = 0;
            if (slashed) {
                uint64_t offence_height = rec.slashed_at_height;
                if (boundary >= BATCH2_HARDENING_HEIGHT) {
                    uint64_t first_sig_height = UINT64_MAX;
                    for (const auto& evidence : slashed_evidence_) {
                        if (evidence.pubkey_hex != pk)
                            continue;
                        if (evidence.height > 0 && evidence.height < first_sig_height) {
                            first_sig_height = evidence.height;
                        }
                    }
                    auto fe = finality_equivocations_.find(pk);
                    if (fe != finality_equivocations_.end()) {
                        const uint64_t h =
                            std::min(fe->second.target_a_height, fe->second.target_b_height);
                        if (h > 0 && h < first_sig_height)
                            first_sig_height = h;
                    }
                    if (first_sig_height != UINT64_MAX)
                        offence_height = first_sig_height;
                }
                slash_forfeit_boundary = CeilBondYieldSettlementBoundary(
                    (__uint128_t)offence_height + (__uint128_t)VALIDATOR_OP_COOLDOWN_BLOCKS);
                confiscation_boundary = slash_forfeit_boundary;
                if (boundary >= BATCH3_HARDENING_HEIGHT) {
                    const uint64_t reachable = SlashSettlementBoundary(rec.slashed_at_height);
                    if (reachable > confiscation_boundary)
                        confiscation_boundary = reachable;
                }
            }

            uint64_t release_sum = 0;
            uint64_t confiscation_sum = 0;
            for (size_t i = 0; i < tranches.size(); ++i) {
                const BondYieldTranche& tranche = tranches[i];
                if (tranche.units == 0) {
                    // Production accrual never creates zero-unit entries, but
                    // canonical cleanup keeps a malformed restored fixture
                    // from becoming immortal state.
                    terminal[i] = 1;
                    continue;
                }
                if (!AddBondYieldUnits(plan.prior_units, tranche.units)) {
                    plan.valid = false;
                    return plan;
                }

                const uint64_t release_boundary = CeilBondYieldSettlementBoundary(
                    (__uint128_t)tranche.accrual_height + (__uint128_t)BOND_YIELD_VEST_BLOCKS);
                BondYieldTerminalKind kind = BondYieldTerminalKind::NONE;
                if (slashed && slash_forfeit_boundary <= release_boundary) {
                    if (confiscation_boundary == boundary)
                        kind = BondYieldTerminalKind::CONFISCATE;
                } else if (release_boundary == boundary) {
                    kind = BondYieldTerminalKind::RELEASE;
                }

                if (kind == BondYieldTerminalKind::NONE)
                    continue;
                terminal[i] = 1;
                if (!AddBondYieldUnits(plan.terminal_units, tranche.units)) {
                    plan.valid = false;
                    return plan;
                }
                uint64_t& sum =
                    kind == BondYieldTerminalKind::RELEASE ? release_sum : confiscation_sum;
                if (!AddBondYieldUnits(sum, tranche.units)) {
                    plan.valid = false;
                    return plan;
                }
            }

            if (release_sum > 0) {
                BondSettlement settlement;
                settlement.address = rec.address;
                settlement.kind = BondSettlement::DEREGISTER_RETURN;
                settlement.bond_units = release_sum;
                plan.settlements.push_back(std::move(settlement));
            }
            if (confiscation_sum > 0) {
                BondSettlement settlement;
                settlement.address = rec.address;
                // Unvested yield is confiscated in full for either offense,
                // but retain the finality-equivocation class all the way to
                // payout construction.  This prevents a future ordinary
                // slash split change from silently reclassifying an
                // equivocator's escrow and makes the 0%-offender rule
                // explicit for both principal and pending yield.
                settlement.kind = rec.slashed_equivocation ? BondSettlement::SLASH_EQUIVOCATION
                                                           : BondSettlement::SLASH_CONFISCATE;
                settlement.bond_units = confiscation_sum;
                settlement.slasher_address = CanonicalSlasherForPubkeyLocked(pk);
                plan.settlements.push_back(std::move(settlement));
            }
        }
        return plan;
    }

    // Current-boundary escrow outputs contain either:
    //   * only the new vault-distribution inflow (nothing was due), or
    //   * one exact carry output from the mandatory full-escrow settlement,
    //     plus at most one new vault-distribution inflow (something was due).
    // Subtracting the parent ledger's required carry prevents that rolled
    // balance from being booked again as fresh yield every day.
    bool ComputeFreshBondYieldAccrualLocked(const Block& block, const BondYieldBoundaryPlan& plan,
                                            uint64_t& fresh_units) const {
        fresh_units = 0;
        if (!plan.valid || plan.terminal_units > plan.prior_units)
            return false;
        const auto escrow_script = AddressToScript(BOND_YIELD_ESCROW);
        if (escrow_script.empty())
            return false;

        std::vector<uint64_t> escrow_outputs;
        uint64_t output_total = 0;
        for (const auto& tx : block.transactions) {
            for (const auto& output : tx.outputs) {
                if (output.script_pubkey != escrow_script)
                    continue;
                escrow_outputs.push_back(output.value);
                if (escrow_outputs.size() > 2 || !AddBondYieldUnits(output_total, output.value)) {
                    return false;
                }
            }
        }

        const uint64_t carry = plan.prior_units - plan.terminal_units;
        if (plan.terminal_units == 0) {
            // No settlement transaction is permitted when no tranche is due;
            // the sole possible escrow output is this cycle's fresh inflow.
            if (escrow_outputs.size() > 1)
                return false;
            fresh_units = output_total;
            return true;
        }

        if (carry > 0) {
            // ComputeExpectedBondYieldSettlement emits carry as one exact
            // output.  Requiring that value rejects a combined/split carry and
            // makes the subtraction unambiguous.  A fresh inflow may
            // coincidentally equal carry, so require at least one match rather
            // than exactly one.
            if (std::find(escrow_outputs.begin(), escrow_outputs.end(), carry) ==
                escrow_outputs.end())
                return false;
        } else if (escrow_outputs.size() > 1) {
            // With no carry, the settlement emits no escrow output.
            return false;
        }
        if (output_total < carry)
            return false;
        fresh_units = output_total - carry;
        return true;
    }

    void RetireBondYieldTranchesLocked(const BondYieldBoundaryPlan& plan) {
        for (auto it = bond_yield_escrow_.begin(); it != bond_yield_escrow_.end();) {
            const auto mask_it = plan.terminal_mask.find(it->first);
            if (mask_it == plan.terminal_mask.end() ||
                mask_it->second.size() != it->second.size()) {
                ++it;
                continue;
            }
            const std::vector<uint8_t>& terminal = mask_it->second;
            std::vector<BondYieldTranche> retained;
            retained.reserve(it->second.size());
            for (size_t i = 0; i < it->second.size(); ++i) {
                if (!terminal[i])
                    retained.push_back(it->second[i]);
            }
            if (retained.empty()) {
                it = bond_yield_escrow_.erase(it);
            } else {
                it->second.swap(retained);
                ++it;
            }
        }
    }

    // Retain every horizon that consumes endorsements.  The legacy operator
    // history kept 10,000 blocks; finality can be longer in the 60-second
    // compatibility profile, so take the maximum.  Entries older than this
    // cannot affect payout (one distribution window), active-validator quorum
    // (seven days), or btcVELD finality and are pruned even when the
    // endorsement pool has no UTXO to flush (notably subsidy exhaustion).
    static constexpr uint64_t ENDORSEMENT_RETENTION_BLOCKS =
        BTCVELD_FINALITY_WINDOW > 10'000 ? BTCVELD_FINALITY_WINDOW : 10'000;

    static std::string EndorsementFieldCommitment(const char* domain,
                                                  const std::string& canonical_hex) {
        std::vector<uint8_t> body(canonical_hex.begin(), canonical_hex.end());
        return HashToHex(state_digest::sha256_domain(domain, body));
    }

    void PruneEndorsementsLocked(uint64_t current_height) {
        const uint64_t min_keep = current_height > ENDORSEMENT_RETENTION_BLOCKS
                                      ? current_height - ENDORSEMENT_RETENTION_BLOCKS
                                      : 0;
        bool erased = false;
        for (auto it = endorsements_.begin(); it != endorsements_.end();) {
            if (it->first < min_keep) {
                it = endorsements_.erase(it);
                erased = true;
            } else {
                ++it;
            }
        }
        if (!erased)
            return;
        std::unordered_set<std::string> rebuilt;
        for (const auto& [h, recs] : endorsements_)
            for (const auto& r : recs)
                rebuilt.insert(std::to_string(h) + ":" + r.address);
        endorsement_keys_.swap(rebuilt);
    }

    static std::string EndorsementPoolOutpointKey(const Hash256& txid, uint32_t vout) {
        return HashToHex(txid) + ":" + std::to_string(vout);
    }

    // Must run first inside ProcessBlock while mutex_ is held.  Detection uses
    // the PRIOR tracked set.  State tracking is then advanced to this block by
    // removing every spent prior outpoint and adding every current output sent
    // to ENDORSEMENT_POOL_ADDRESS.
    void ProcessEndorsementPoolStateLocked(const Block& block) {
        bool canonical_flush = false;
        if (block.height > 0 && (block.height % VAULT_DISTRIBUTION_INTERVAL) == 0 &&
            !endorsement_pool_outpoints_.empty()) {
            const Transaction* candidate = nullptr;
            size_t touching_transactions = 0;

            for (const auto& tx : block.transactions) {
                bool touches_prior_pool = false;
                for (const auto& input : tx.inputs) {
                    const std::string key =
                        EndorsementPoolOutpointKey(input.prev_tx_hash, input.prev_out_index);
                    if (endorsement_pool_outpoints_.count(key) != 0) {
                        touches_prior_pool = true;
                        break;
                    }
                }
                if (touches_prior_pool) {
                    ++touching_transactions;
                    candidate = &tx;
                }
            }

            if (touching_transactions == 1 && candidate != nullptr && !candidate->inputs.empty()) {
                std::unordered_set<std::string> consumed;
                consumed.reserve(candidate->inputs.size());
                bool exact_only = true;
                for (const auto& input : candidate->inputs) {
                    const std::string key =
                        EndorsementPoolOutpointKey(input.prev_tx_hash, input.prev_out_index);
                    if (endorsement_pool_outpoints_.count(key) == 0 ||
                        !consumed.insert(key).second) {
                        // Mixed non-pool input or duplicate input: this is not
                        // the unique canonical full-pool transaction.
                        exact_only = false;
                        break;
                    }
                }
                canonical_flush =
                    exact_only && consumed.size() == endorsement_pool_outpoints_.size();
            }
        }

        if (canonical_flush) {
            // This executes before current-block ENDORSE ops, so a boundary
            // endorsement belongs to the next payout window and stays unpaid.
            MarkRewardsPaidLocked(block.height);
            last_canonical_endorsement_flush_height_ = block.height;
        }

        const auto pool_script = AddressToScript(ENDORSEMENT_POOL_ADDRESS);
        // Advance in transaction order.  This mirrors the block UTXO overlay:
        // if tx N creates an endorsement-pool output and tx N+1 spends it, the
        // latter erase sees the just-added outpoint and it is not retained as a
        // phantom member of the next boundary's required set.
        for (const auto& tx : block.transactions) {
            for (const auto& input : tx.inputs) {
                endorsement_pool_outpoints_.erase(
                    EndorsementPoolOutpointKey(input.prev_tx_hash, input.prev_out_index));
            }
            if (pool_script.empty())
                continue;
            bool creates_pool_output = false;
            for (const auto& output : tx.outputs) {
                if (output.script_pubkey == pool_script) {
                    creates_pool_output = true;
                    break;
                }
            }
            if (!creates_pool_output)
                continue;
            const Hash256 txid = tx.GetTxID();
            for (size_t vout = 0; vout < tx.outputs.size(); ++vout) {
                if (tx.outputs[vout].script_pubkey != pool_script)
                    continue;
                if (vout > UINT32_MAX)
                    continue; // structurally unreachable
                endorsement_pool_outpoints_.insert(
                    EndorsementPoolOutpointKey(txid, (uint32_t)vout));
            }
        }
    }

    // Private consensus transition.  The only caller is the canonical full-
    // endorsement-pool-spend detector above; external height/index cursors have
    // no mutator into paid state.
    void MarkRewardsPaidLocked(uint64_t paid_through_height) {
        for (auto& [height, recs] : endorsements_) {
            if (height <= paid_through_height) {
                for (auto& rec : recs)
                    rec.reward_paid = true;
            }
        }
        PruneEndorsementsLocked(paid_through_height);
    }

    // Inactive-record retirement is a height-derived consensus transition, not
    // a side effect of finding a funded endorsement-pool flush.  Running it on
    // every block bounds clean-exit churn even after that pool is empty.  A
    // record with any D' tranche is never evicted: its address and slash context
    // remain authoritative until the boundary planner retires the last tranche.
    void PruneInactiveValidatorsLocked(uint64_t current_height) {
        // Evict inactive validator records by terminal event height, never by
        // registration age.
        uint64_t evict_below = current_height > 10000 ? current_height - 10000 : 0;
        uint64_t custodial_window = BOND_YIELD_VEST_BLOCKS + 2 * BOND_SETTLEMENT_INTERVAL;
        uint64_t evict_below_custodial =
            current_height > custodial_window ? current_height - custodial_window : 0;
        const bool use_terminal_predicate = (current_height >= BATCH1_HARDENING_HEIGHT);
        for (auto it = validators_.begin(); it != validators_.end();) {
            bool should_evict = false;
            if (!it->second.active) {
                if (use_terminal_predicate) {
                    uint64_t terminal_h =
                        std::max(it->second.deregistered_at_height, it->second.slashed_at_height);
                    uint64_t threshold =
                        it->second.bond_custodial ? evict_below_custodial : evict_below;
                    should_evict = (terminal_h > 0) && (terminal_h < threshold);
                } else {
                    should_evict = (it->second.registered_height < evict_below);
                }
            }
            const auto yield_it = bond_yield_escrow_.find(it->first);
            if (yield_it != bond_yield_escrow_.end() && !yield_it->second.empty()) {
                should_evict = false;
            }
            if (should_evict) {
                last_op_height_.erase(it->second.address);
                address_to_pubkey_.erase(it->second.address);
                auto pubkey_bytes = HexToBytes(it->second.pubkey_hex);
                if (pubkey_bytes.size() == 1952) {
                    std::string derived = PubkeyToAddress(pubkey_bytes);
                    if (derived != it->second.address)
                        address_to_pubkey_.erase(derived);
                }
                it = validators_.erase(it);
            } else {
                ++it;
            }
        }
        uint64_t op_evict_below = current_height > VALIDATOR_OP_COOLDOWN_BLOCKS
                                      ? current_height - VALIDATOR_OP_COOLDOWN_BLOCKS
                                      : 0;
        for (auto it = last_op_height_.begin(); it != last_op_height_.end();) {
            if (it->second < op_evict_below)
                it = last_op_height_.erase(it);
            else
                ++it;
        }
    }

    static bool DeregisteredBondPendingAtLocked(const ValidatorRecord& rec,
                                                uint64_t inclusion_height) {
        return rec.bond_custodial && !rec.slashed && rec.bond_units > 0 &&
               rec.deregistered_at_height > 0 &&
               DeregReturnBoundary(rec.deregistered_at_height, rec.last_finality_vote_height) >=
                   inclusion_height;
    }

    bool CanAcceptSlashEvidenceLocked(const std::string& pubkey_hex, uint64_t sig_height,
                                      uint64_t inclusion_height) const {
        if (sig_height > inclusion_height)
            return false;
        if (inclusion_height > sig_height &&
            inclusion_height - sig_height > SLASH_EVIDENCE_WINDOW) {
            return false;
        }
        auto vit = validators_.find(pubkey_hex);
        if (vit == validators_.end())
            return false;
        if (inclusion_height >= BATCH2_HARDENING_HEIGHT) {
            const ValidatorRecord& rec = vit->second;
            if (rec.deregistered_at_height > 0 && !rec.slashed &&
                inclusion_height >= DeregReturnBoundary(rec.deregistered_at_height,
                                                        rec.last_finality_vote_height)) {
                return false;
            }
            if (sig_height < rec.registered_height)
                return false;
        }
        return true;
    }

    std::string CanonicalSlasherForPubkeyLocked(const std::string& pubkey_hex) const {
        auto vit = validators_.find(pubkey_hex);
        if (vit != validators_.end() && vit->second.slashed_equivocation) {
            auto eq = finality_equivocations_.find(pubkey_hex);
            return eq == finality_equivocations_.end() ? std::string() : eq->second.slasher_address;
        }
        const SlashEvidence* best = nullptr;
        for (const auto& e : slashed_evidence_) {
            if (e.pubkey_hex != pubkey_hex)
                continue;
            if (!best || std::tie(e.evidence_block, e.height, e.hash_a_hex, e.hash_b_hex,
                                  e.slasher_address) < std::tie(best->evidence_block, best->height,
                                                                best->hash_a_hex, best->hash_b_hex,
                                                                best->slasher_address)) {
                best = &e;
            }
        }
        return best ? best->slasher_address : std::string();
    }

    void ProcessOp(
        const std::string& data, const Block& block, const Transaction& tx,
        std::function<uint64_t(const std::string&)> staking_get_stake,
        std::function<void(const std::string&, uint64_t)> staking_apply_slash_lockup = nullptr) {
        // Validator activation is a pure function of the build profile and
        // chain-derived total stake.
        if (!VALIDATOR_SYSTEM_ALWAYS_ACTIVE &&
            total_staked_units_.load(std::memory_order_relaxed) < VALIDATOR_UNLOCK_STAKED)
            return;

        std::string rest = data.substr(std::string(VAL_PREFIX).size());
        std::vector<std::string> parts = Split(rest, '|');
        if (parts.empty())
            return;

        const std::string& action = parts[0];

        if (action == "REGISTER" && parts.size() == 2 &&
            std::count(rest.begin(), rest.end(), '|') == 1) {
            const std::string& pubkey_hex = parts[1];
            if (!IsCanonicalLowerHex(pubkey_hex, 3904))
                return;

            // Slashed public keys are permanently barred from re-registration.
            // A pubkey that was slashed (at/after VALIDATOR_SLASHING_HEIGHT)
            // can NEVER register again. slashed_pubkeys_ is empty until the
            // first post-gate slash, so this is inert pre-activation and
            // replay-deterministic afterward (the set is rebuilt in chain
            // order by the SLASH branch; a REGISTER replayed before its
            // banning SLASH still succeeds, one replayed after is refused —
            // identical on every node because block order is fixed). Scope
            // is per-pubkey per the design doc; the offender needs a fresh
            // ML-DSA key AND a fresh MIN_VALIDATOR_STAKE bond to re-enter,
            // while the old bond stays lockup-extended (real re-entry cost).
            if (slashed_pubkeys_.count(pubkey_hex))
                return;

            auto pubkey_bytes = HexToBytes(pubkey_hex);
            if (pubkey_bytes.size() != 1952)
                return;
            std::string address = PubkeyToAddress(pubkey_bytes);
            if (address.empty())
                return;

            if (!TxInputMatchesAddress(tx, address))
                return;

            {
                auto lh = last_op_height_.find(address);
                if (lh != last_op_height_.end() &&
                    block.height < lh->second + VALIDATOR_OP_COOLDOWN_BLOCKS) {
                    return;
                }
            }

            uint64_t effective_min = min_validator_stake_override_ > 0
                                         ? min_validator_stake_override_
                                         : MIN_VALIDATOR_STAKE;
            // Custodial bond regime.
            //   Pre-gate  (grandfathered): bond is a LOGICAL lock — require
            //     staking_get_stake(address) >= effective_min, as before.
            //     bond_custodial stays false; only the logical penalty can
            //     ever apply (no confiscation — coin not protocol-held).
            //   Post-gate (custodial): the REGISTER tx MUST physically send
            //     >= effective_min to STAKE_VAULT_ADDRESS in the SAME tx.
            //     That coin is now protocol-custodied and confiscatable.
            //     We do NOT also require logical stake (the bond replaces
            //     it). bond_units = the exact amount sent to the vault.
            bool reg_custodial = false;
            uint64_t reg_bond_units = 0;
            if (block.height >= STAKE_VAULT_ACTIVATION_HEIGHT) {
                auto sv_script = AddressToScript(STAKE_VAULT_ADDRESS);
                if (sv_script.empty())
                    return;
                uint64_t to_vault = 0;
                for (const auto& o : tx.outputs) {
                    if (o.script_pubkey == sv_script) {
                        if (to_vault > UINT64_MAX - o.value)
                            return;
                        to_vault += o.value;
                    }
                }
                if (to_vault < effective_min)
                    return;
                reg_custodial = true;
                reg_bond_units = to_vault;
            } else {
                if (staking_get_stake(address) < effective_min)
                    return;
            }

            if (validators_.count(pubkey_hex) && validators_[pubkey_hex].active)
                return;

            // A cleanly deregistered custodial bond is a term-specific slash
            // target through its entire evidence window and through the block
            // that performs its mandatory canonical return.  Re-attaching it to
            // a new term used to overwrite registered_height, which made still-
            // timely evidence from the old term fail `sig_height < registered`
            // and could also orphan the old principal if a miner omitted the
            // one-shot settlement.  Fail closed until AFTER the return boundary;
            // the new registration then starts with only its newly funded bond.
            auto prior_it = validators_.find(pubkey_hex);
            if (prior_it != validators_.end() &&
                DeregisteredBondPendingAtLocked(prior_it->second, block.height)) {
                return;
            }
            // An old term can retain
            // 90-day D' tranches after its principal return.  Replacing the
            // single validator record while any such tranche exists would let
            // the new term's slash/registration fields reclassify old-term
            // yield.  Fail closed until canonical settlement retires the last
            // tranche.  A returning operator may use a fresh ML-DSA key.
            const auto prior_yield = bond_yield_escrow_.find(pubkey_hex);
            if (prior_yield != bond_yield_escrow_.end() && !prior_yield->second.empty()) {
                return;
            }

            for (const auto& [other_pk, other_rec] : validators_) {
                if (!other_rec.active)
                    continue;
                if (other_rec.address == address)
                    return;
            }

            ValidatorRecord rec;
            rec.pubkey_hex = pubkey_hex;
            rec.address = address;
            rec.registered_height = block.height;
            rec.active = true;
            rec.bond_custodial = reg_custodial;
            rec.bond_units = reg_bond_units;
            validators_[pubkey_hex] = rec;
            last_op_height_[address] = block.height;
            address_to_pubkey_[address] = pubkey_hex;
            {
                auto pubkey_bytes = HexToBytes(pubkey_hex);
                if (pubkey_bytes.size() == 1952) {
                    std::string derived = PubkeyToAddress(pubkey_bytes);
                    if (derived != address)
                        address_to_pubkey_[derived] = pubkey_hex;
                }
            }
            TrimExpiredCooldownsLocked(block.height);
        }

        else if (action == "DEREGISTER" && parts.size() == 2 &&
                 std::count(rest.begin(), rest.end(), '|') == 1) {
            const std::string& pubkey_hex = parts[1];
            if (!IsCanonicalLowerHex(pubkey_hex, 3904))
                return;
            auto it = validators_.find(pubkey_hex);
            if (it == validators_.end() || !it->second.active)
                return;

            if (!TxInputMatchesAddress(tx, it->second.address))
                return;

            {
                auto lh = last_op_height_.find(it->second.address);
                if (lh != last_op_height_.end() &&
                    block.height < lh->second + VALIDATOR_OP_COOLDOWN_BLOCKS) {
                    return;
                }
            }

            it->second.active = false;
            last_op_height_[it->second.address] = block.height;
            if (it->second.bond_custodial && !it->second.slashed &&
                it->second.deregistered_at_height == 0) {
                it->second.deregistered_at_height = block.height;
            }
            TrimExpiredCooldownsLocked(block.height);
        }

        // ── SLASH ────────────────────────────────────────────────────────────
        // Double-sign evidence collection.
        //
        // Format: VELD_VALIDATOR|SLASH|<pk_hex>|<height>|<hash_a>|<sig_a>|<hash_b>|<sig_b>
        //
        // Validation gates (any failure → silently drop, like other ops):
        //   1. parts.size() == 8 (action + 7 fields)
        //   2. pubkey_hex format: 3904 valid hex chars
        //   3. height is a parseable uint
        //   4. hash_a != hash_b (distinct blocks)
        //   5. Both sigs verify against pubkey at the same height — proving
        //      the same key signed two different block-endorsements at h.
        //   6. The pubkey was a registered validator at some point (need not
        //      currently be active — slashing is retrospective and a
        //      misbehaving validator who already deregistered is still
        //      worth recording for reward + lookup).
        //   7. (pubkey, height) not already in slashed_evidence_keys_.
        //
        // We deliberately do not require TxInputMatchesAddress here:
        // the slasher's bounty doesn't pay yet, so requiring a sig from any
        // particular wallet adds friction without a real benefit. The penalty path
        // will gate the BOUNTY on slasher_address derived from input[0],
        // not the recording itself.
        //
        // Soft-fork-safe: nodes running an older binary that lacks this
        // branch ignore the OP_RETURN entirely. Block-validation outcomes
        // are unchanged regardless. Once mainnet binaries all parse SLASH,
        // operators can rely on getmisbehavior to surface real evidence.
        //  parts.size MUST equal exactly the expected
        // 8 fields (action + 7 payload). Earlier `>= 7` allowed trailing-
        // field tampering — a SLASH OP_RETURN with 9+ pipe-fields would be
        // accepted by some binaries and rejected by others, producing
        // per-node `slashed_evidence_` divergence on identical chains.
        // Tighten to strict equality, mirroring REGISTER's strict 2 and
        // ENDORSE's strict 4-field semantics.
        // ── SLASH_EQUIV: finality equivocation ─────────────────────────────
        //
        // VELD_VALIDATOR|SLASH_EQUIV|pubkey|epoch|set_root|phase|round
        //   |srcA_h|srcA_hash|tgtA_h|tgtA_hash|sigA
        //   |srcB_h|srcB_hash|tgtB_h|tgtB_hash|sigB|v1
        //
        // Settles at 0% principal return, unlike the 50%-return SLASH above.
        // Signing two conflicting targets in one round is the single act that
        // can finalize two incompatible histories; the locked-QC safety
        // argument is that it costs the whole bond.
        //
        // SELF-PROVING, exactly like SLASH and for the same reason. The
        // reverted block-existence check above is the precedent: slash
        // acceptance feeds the byte-equal bond-settlement gate, so it must be a
        // pure function of the canonical chain plus the op bytes. Two honest
        // nodes must never reach different verdicts.
        //
        // This op reads only replayed consensus state: the validator record and
        // the bounded epoch-membership history retained specifically for the
        // 90-day evidence horizon. It never queries the live chain tree, orphan
        // cache, or another node-local view. Both preimages are reconstructed
        // from the op's fields and verified against the registered public key;
        // the retained membership record additionally proves that key and
        // set_root belonged to the canonical frozen denominator for the epoch.
        else if (action == "SLASH_EQUIV" && parts.size() == 17) {
            const std::string& pubkey_hex = parts[1];
            uint64_t epoch = 0, round = 0, phase = 0;
            if (!ParseCanonicalUint64(parts[2], epoch))
                return;
            const std::string& set_root_hex = parts[3];
            if (!ParseCanonicalUint64(parts[4], phase))
                return;
            if (phase != 1 && phase != 2)
                return;
            if (!ParseCanonicalUint64(parts[5], round))
                return;
            if (round > UINT32_MAX)
                return;

            uint64_t srcA_h = 0, tgtA_h = 0, srcB_h = 0, tgtB_h = 0;
            if (!ParseCanonicalUint64(parts[6], srcA_h))
                return;
            const std::string& srcA_hash = parts[7];
            if (!ParseCanonicalUint64(parts[8], tgtA_h))
                return;
            const std::string& tgtA_hash = parts[9];
            const std::string& sigA_hex = parts[10];
            if (!ParseCanonicalUint64(parts[11], srcB_h))
                return;
            const std::string& srcB_hash = parts[12];
            if (!ParseCanonicalUint64(parts[13], tgtB_h))
                return;
            const std::string& tgtB_hash = parts[14];
            const std::string& sigB_hex = parts[15];
            if (parts[16] != "v1")
                return;

            // The OFFENSE: two DIFFERENT targets, same (epoch, phase, round).
            // Identical targets are not equivocation — a validator re-sending
            // its own vote is normal and must never be slashable.
            if (tgtA_h == tgtB_h && tgtA_hash == tgtB_hash)
                return;
            if (sigA_hex == sigB_hex)
                return;

            if (!IsCanonicalLowerHex(pubkey_hex, 3904) || !IsCanonicalLowerHex(set_root_hex, 64) ||
                !IsCanonicalLowerHex(srcA_hash, 64) || !IsCanonicalLowerHex(tgtA_hash, 64) ||
                !IsCanonicalLowerHex(srcB_hash, 64) || !IsCanonicalLowerHex(tgtB_hash, 64) ||
                !IsCanonicalLowerHex(sigA_hex, 6618) || !IsCanonicalLowerHex(sigB_hex, 6618))
                return;

            namespace fq = ::veld::finality::qc;
            if (!fq::IsScheduledCheckpoint(tgtA_h) || !fq::IsScheduledCheckpoint(tgtB_h) ||
                fq::EpochOf(tgtA_h) != epoch || fq::EpochOf(tgtB_h) != epoch ||
                fq::CheckpointRound(tgtA_h) != round || fq::CheckpointRound(tgtB_h) != round)
                return;
            // Evidence must prove two VALID finality claims, not merely two
            // signatures over bytes that use the finality domain tag.  The
            // live vote/QC path rejects a non-canonical null source, an
            // unscheduled source, or a source at/above its target; applying
            // the same predicate here prevents malformed non-votes from
            // confiscating a validator bond.  A vote target also cannot be in
            // the future relative to its evidence carrier.
            auto checkpoint = [](uint64_t height, const std::string& hex,
                                 fq::CheckpointRef& out) -> bool {
                const auto raw = HexToBytes(hex);
                if (raw.size() != out.hash.size())
                    return false;
                out.height = height;
                std::copy(raw.begin(), raw.end(), out.hash.begin());
                return true;
            };
            fq::CheckpointRef src_a, src_b, tgt_a, tgt_b;
            if (!checkpoint(srcA_h, srcA_hash, src_a) || !checkpoint(srcB_h, srcB_hash, src_b) ||
                !checkpoint(tgtA_h, tgtA_hash, tgt_a) || !checkpoint(tgtB_h, tgtB_hash, tgt_b) ||
                !fq::SourceRefWellFormed(src_a, tgt_a) || !fq::SourceRefWellFormed(src_b, tgt_b) ||
                tgtA_h > block.height || tgtB_h > block.height)
                return;

            // Measure the evidence horizon from the offense target. Measuring
            // from epoch end would extend early-round evidence by up to one
            // epoch and could overlap a completed bond return.
            if (tgtA_h != tgtB_h)
                return;
            const uint64_t offense_target_height = tgtA_h;
            if (block.height > offense_target_height &&
                block.height - offense_target_height > fq::FINALITY_EQUIV_EVIDENCE_WINDOW)
                return;

            // Membership is proven against the canonical bounded epoch-history
            // recorded when the snapshot was frozen; arbitrary signed preimages
            // cannot slash a key that was not in that denominator.

            Hash256 set_root_bytes{};
            {
                const auto raw = HexToBytes(set_root_hex);
                if (raw.size() != 32)
                    return;
                std::copy(raw.begin(), raw.end(), set_root_bytes.begin());
            }
            auto membership = finality_membership_.find(epoch);
            if (membership == finality_membership_.end() ||
                membership->second.root != set_root_bytes)
                return;
            const Hash256 signer_commit = fq::PubkeyCommit(pubkey_hex);
            if (!std::binary_search(membership->second.members.begin(),
                                    membership->second.members.end(), signer_commit))
                return;

            auto vit = validators_.find(pubkey_hex);
            if (vit == validators_.end())
                return;
            if (vit->second.slashed_equivocation)
                return; // already settled
            // A public key may begin a fresh bond term after the prior clean
            // return. Retained old-epoch membership is intentionally still
            // available for evidence, so bind the offense to the current term
            // by the same inclusive registration-height rule used by legacy
            // SLASH: a target before this term began cannot confiscate its new
            // principal. Equality is admissible; `<` is the old-term case.
            if (offense_target_height < vit->second.registered_height)
                return;
            // Principal settlement is derived from the PARENT registry and is
            // mandatory on DeregReturnBoundary. Evidence in that same block
            // must not reclassify a bond whose canonical return transaction has
            // already paid it, nor may later evidence attach to a fresh term.
            if (vit->second.deregistered_at_height > 0 && !vit->second.slashed &&
                block.height >= DeregReturnBoundary(vit->second.deregistered_at_height,
                                                    vit->second.last_finality_vote_height))
                return;

            // Structural rejects are done; now the two ~1ms ML-DSA verifies.
            // Ordering matters: a flood of malformed SLASH_EQUIV ops must not
            // become a CPU exhaustion vector against block validation.
            if (!VerifyFinalityVoteSignature(pubkey_hex, epoch, set_root_hex, phase, round, srcA_h,
                                             srcA_hash, tgtA_h, tgtA_hash, sigA_hex))
                return;
            if (!VerifyFinalityVoteSignature(pubkey_hex, epoch, set_root_hex, phase, round, srcB_h,
                                             srcB_hash, tgtB_h, tgtB_hash, sigB_hex))
                return;

            // A3 fixes the economic result at 25% evidence bounty / 75%
            // protocol confiscation / 0% offender.  Therefore evidence must
            // name a real, non-offender reporter before it can consume the
            // one-shot equivocation slot.  Accepting an anonymous/self report
            // and redirecting its bounty would both violate that split and
            // suppress a later valid reporter.
            std::string slasher_address;
            if (!tx.inputs.empty()) {
                std::vector<uint8_t> sig_unused;
                std::array<uint8_t, 1952> spk;
                if (veld::pqc::ParseScriptSig(tx.inputs[0].script_sig, sig_unused, spk)) {
                    Hash160 pkh = Hash160Compute(spk);
                    std::vector<uint8_t> script = {0x76, 0xA9, 0x14};
                    script.insert(script.end(), pkh.begin(), pkh.end());
                    script.push_back(0x88);
                    script.push_back(0xAC);
                    slasher_address = ScriptToAddress(script);
                }
            }
            if (slasher_address.empty() || slasher_address == vit->second.address)
                return;

            std::string dedup_key =
                "EQ:" + pubkey_hex + ":" + std::to_string(epoch) + ":" + std::to_string(round);
            if (!slashed_evidence_keys_.insert(dedup_key).second)
                return;

            FinalityEquivocationRecord equiv;
            equiv.epoch = epoch;
            equiv.phase = (uint8_t)phase;
            equiv.round = (uint32_t)round;
            equiv.target_a_height = tgtA_h;
            equiv.target_b_height = tgtB_h;
            {
                const auto a = HexToBytes(tgtA_hash);
                const auto b = HexToBytes(tgtB_hash);
                std::copy(a.begin(), a.end(), equiv.target_a_hash.begin());
                std::copy(b.begin(), b.end(), equiv.target_b_hash.begin());
            }
            equiv.evidence_block = block.height;
            equiv.slasher_address = slasher_address;
            const std::vector<uint8_t> ev_bytes(data.begin(), data.end());
            equiv.evidence_commit =
                state_digest::sha256_domain("VELD_FINALITY_EQUIV_EVIDENCE_v1|", ev_bytes);
            if (!finality_equivocations_.emplace(pubkey_hex, std::move(equiv)).second) {
                slashed_evidence_keys_.erase(dedup_key);
                return;
            }

            if (block.height >= VALIDATOR_SLASHING_HEIGHT) {
                vit->second.slashed = true;
                vit->second.slashed_equivocation = true; // 0% return class
                vit->second.active = false;
                if (vit->second.slashed_at_height == 0 ||
                    block.height < vit->second.slashed_at_height)
                    vit->second.slashed_at_height = block.height;
                slashed_pubkeys_.insert(pubkey_hex);
                last_op_height_[vit->second.address] = block.height;
                if (staking_apply_slash_lockup) {
                    staking_apply_slash_lockup(vit->second.address,
                                               block.height + SLASH_BOND_LOCKUP_BLOCKS);
                }
            }
            return;
        } else if (action == "SLASH" && parts.size() == 8) {
            const std::string& pubkey_hex = parts[1];
            uint64_t sig_height = 0;
            if (!ParseCanonicalUint64(parts[2], sig_height))
                return;
            const std::string& hash_a_hex = parts[3];
            const std::string& sig_a_hex = parts[4];
            const std::string& hash_b_hex = parts[5];
            const std::string& sig_b_hex = parts[6];
            if (parts[7] != "v1" && !parts[7].empty())
                return;

            if (sig_height > block.height)
                return;
            if (block.height > sig_height && block.height - sig_height > SLASH_EVIDENCE_WINDOW)
                return;

            if (!IsCanonicalLowerHex(pubkey_hex, 3904) || !IsCanonicalLowerHex(hash_a_hex, 64) ||
                !IsCanonicalLowerHex(hash_b_hex, 64))
                return;
            if (hash_a_hex == hash_b_hex)
                return;
            if (sig_a_hex.empty() || sig_b_hex.empty())
                return;
            if (sig_a_hex == sig_b_hex)
                return;
            // Slash acceptance must not consult node-local orphan or side-tip
            // indexes. The two authenticated ML-DSA-65 claims are sufficient;
            // every settlement decision remains a function of canonical state.
            //
            // Validate the canonical FIPS-204 ML-DSA-65 size before the
            // expensive signature check: 3309 bytes, or 6618 hex characters.
            if (!IsCanonicalLowerHex(sig_a_hex, 6618) || !IsCanonicalLowerHex(sig_b_hex, 6618))
                return;

            auto vit = validators_.find(pubkey_hex);
            if (vit == validators_.end())
                return;
            if (!CanAcceptSlashEvidenceLocked(pubkey_hex, sig_height, block.height))
                return;

            auto pubkey_bytes = HexToBytes(pubkey_hex);
            if (pubkey_bytes.size() != 1952)
                return;
            Hash256 hash_a, hash_b;
            auto a_bytes = HexToBytes(hash_a_hex);
            auto b_bytes = HexToBytes(hash_b_hex);
            if (a_bytes.size() != 32 || b_bytes.size() != 32)
                return;
            std::copy(a_bytes.begin(), a_bytes.end(), hash_a.begin());
            std::copy(b_bytes.begin(), b_bytes.end(), hash_b.begin());
            if (!VerifyEndorseSignature(pubkey_hex, sig_height, hash_a, sig_a_hex))
                return;
            if (!VerifyEndorseSignature(pubkey_hex, sig_height, hash_b, sig_b_hex))
                return;

            std::string dedup_key = pubkey_hex + ":" + std::to_string(sig_height);
            if (!slashed_evidence_keys_.insert(dedup_key).second)
                return;
            if (slashed_evidence_.size() >= MAX_SLASHED_EVIDENCE) {
                slashed_evidence_keys_.erase(dedup_key);
                return;
            }
            if (block.height >= BATCH2_HARDENING_HEIGHT) {
                auto evpit = evidence_per_pubkey_.find(pubkey_hex);
                uint32_t current = (evpit == evidence_per_pubkey_.end()) ? 0 : evpit->second;
                if (current >= MAX_EVIDENCE_PER_PUBKEY) {
                    slashed_evidence_keys_.erase(dedup_key);
                    return;
                }
                evidence_per_pubkey_[pubkey_hex] = current + 1;
            }

            std::string slasher_address;
            if (!tx.inputs.empty()) {
                std::vector<uint8_t> sig_unused;
                std::array<uint8_t, 1952> spk;
                if (veld::pqc::ParseScriptSig(tx.inputs[0].script_sig, sig_unused, spk)) {
                    Hash160 pkh = Hash160Compute(spk);
                    std::vector<uint8_t> script = {0x76, 0xA9, 0x14};
                    script.insert(script.end(), pkh.begin(), pkh.end());
                    script.push_back(0x88);
                    script.push_back(0xAC);
                    slasher_address = ScriptToAddress(script);
                }
            }
            if (block.height >= BATCH1_HARDENING_HEIGHT && !slasher_address.empty() &&
                slasher_address == vit->second.address) {
                slasher_address.clear();
            }

            SlashEvidence ev;
            ev.pubkey_hex = pubkey_hex;
            ev.address = vit->second.address;
            ev.height = sig_height;
            ev.hash_a_hex = hash_a_hex;
            ev.hash_b_hex = hash_b_hex;
            ev.sig_a_hex = sig_a_hex;
            ev.sig_b_hex = sig_b_hex;
            ev.slasher_address = slasher_address;
            ev.evidence_block = block.height;
            slashed_evidence_.push_back(std::move(ev));

            if (block.height >= VALIDATOR_SLASHING_HEIGHT) {
                vit->second.slashed = true;
                vit->second.active = false;
                if (vit->second.slashed_at_height == 0 ||
                    block.height < vit->second.slashed_at_height)
                    vit->second.slashed_at_height = block.height;
                slashed_pubkeys_.insert(pubkey_hex);
                last_op_height_[vit->second.address] = block.height;
                if (staking_apply_slash_lockup) {
                    staking_apply_slash_lockup(vit->second.address,
                                               block.height + SLASH_BOND_LOCKUP_BLOCKS);
                }
            }
        }

        else if (action == "ENDORSE") {
            // Exactly four fields and three separators.  Split() intentionally
            // serves legacy marker families and does not preserve a trailing
            // empty field, so count separators too: `...|sig|` is not another
            // spelling of the same endorsement.
            if (parts.size() != 4 || std::count(rest.begin(), rest.end(), '|') != 3)
                return;

            uint64_t height = 0;
            if (!ParseCanonicalUint64(parts[1], height))
                return;
            const std::string& hash_hex = parts[2];
            const std::string& sig_hex = parts[3];
            if (!IsCanonicalLowerHex(hash_hex, 64) || !IsCanonicalLowerHex(sig_hex, 6618))
                return;

            const auto hash_bytes = HexToBytes(hash_hex);
            if (hash_bytes.size() != 32)
                return;
            Hash256 block_hash;
            std::copy(hash_bytes.begin(), hash_bytes.end(), block_hash.begin());
            const std::string canonical_hash_hex = HashToHex(block_hash);

            if (height > block.height)
                return;
            if (block.height > height && block.height - height > ENDORSEMENT_RETENTION_BLOCKS)
                return;

            // Identify which registered validator sent this
            // First try: match by tx input address (for fee-paying endorsement txs)
            // Second try: match by verifying signature against each validator's pubkey
            //   (for coinbase-embedded endorsements that have no signed inputs)
            //
            // Canonical endorsement attribution. The legacy primary path below
            // iterates `validators_` (an
            // unordered_map) and breaks on the first
            // `TxInputMatchesAddress(tx, rec.address)` match. For an
            // adversarial ENDORSE tx whose inputs match ≥2 distinct
            // active-validator addresses, the choice of "first" depends
            // on the unordered_map's BUCKET ORDER — implementation-
            // defined, can drift across nodes (different libstdc++
            // versions, different hash seeds), and adversary-influenceable
            // (the attacker picks which validators' addresses appear in
            // the input set). Documented consensus-inert today because
            // current consumers are non-consensus, but a future re-use of
            // `endorsements_` as a consensus input would instantly
            // convert it into a chain-split.
            //
            // Mainnet canonicalization: derive the candidate validator
            // address from `tx.inputs[0]`'s pubkey-hash directly (matches
            // the flush's `blockchain.h:1448-1457` derivation), then
            // look up the registry via the O(1) reverse-index
            // `address_to_pubkey_`. Result is a function purely of
            // `tx.inputs[0].script_sig` — no map iteration, no bucket
            // order, no adversary-influence beyond which single pubkey
            // they choose to sign with. At most one active validator
            // matches (per-address uniqueness enforced at REGISTER,
            // validators.h:1085-1088).
            //
            // Testnet retains its replay-compatible attribution path. The
            // fallback is order-invariant because ML-DSA-65 verifies under exactly
            // one pubkey, so at most one match regardless of order).
            std::string validator_pubkey;
            std::string validator_address;
#ifdef VELD_MAINNET_POW
            if (!tx.inputs.empty()) {
                std::vector<uint8_t> sig_unused;
                std::array<uint8_t, 1952> pk_bytes;
                if (veld::pqc::ParseScriptSig(tx.inputs[0].script_sig, sig_unused, pk_bytes)) {
                    std::string candidate_addr =
                        PubkeyToAddress(std::vector<uint8_t>(pk_bytes.begin(), pk_bytes.end()));
                    auto ait = address_to_pubkey_.find(candidate_addr);
                    if (ait != address_to_pubkey_.end()) {
                        auto vit = validators_.find(ait->second);
                        if (vit != validators_.end() && vit->second.active) {
                            validator_pubkey = ait->second;
                            validator_address = vit->second.address;
                        }
                    }
                }
            }
#else
            for (auto& [pk, rec] : validators_) {
                if (!rec.active)
                    continue;
                if (TxInputMatchesAddress(tx, rec.address)) {
                    validator_pubkey = pk;
                    validator_address = rec.address;
                    break;
                }
            }
#endif
            if (validator_pubkey.empty()) {
                for (auto& [pk, rec] : validators_) {
                    if (!rec.active)
                        continue;
                    if (VerifyEndorseSignature(pk, height, block_hash, sig_hex)) {
                        validator_pubkey = pk;
                        validator_address = rec.address;
                        break;
                    }
                }
            }
            if (validator_pubkey.empty())
                return;

            {
                uint64_t effective_min = min_validator_stake_override_ > 0
                                             ? min_validator_stake_override_
                                             : MIN_VALIDATOR_STAKE;
                // Custodial-bond model: a validator qualifies via EITHER a logical
                // stake >= min OR a custodial bond >= min. The bond REPLACES the
                // logical stake (see the REGISTER path: "the bond replaces it").
                // The old check looked at logical stake ONLY, which silently dropped
                // every endorsement from a bond-only validator (bonded but never
                // staked) — the root cause of "registered but never endorsing".
                uint64_t logical_stake_ = staking_get_stake(validator_address);
                uint64_t custodial_bond_ = 0;
                {
                    auto vit = validators_.find(validator_pubkey);
                    if (vit != validators_.end() && vit->second.active &&
                        vit->second.bond_custodial && !vit->second.slashed)
                        custodial_bond_ = vit->second.bond_units;
                }
                if (logical_stake_ < effective_min && custodial_bond_ < effective_min) {
                    // Silently drop — do NOT set inactive yet (stake/bond may come
                    // back before the next endorsement; idempotent recovery).
                    return;
                }
            }

            if (!VerifyEndorseSignature(validator_pubkey, height, block_hash, sig_hex))
                return;

            // Invalid/malformed markers must not reserve the validator's one
            // vote slot and poison a later valid marker in the same block.
            std::string dedup_key = std::to_string(height) + ":" + validator_address;
            if (!endorsement_keys_.insert(dedup_key).second)
                return;
            auto& block_endorsements = endorsements_[height];

            EndorsementRecord erec;
            erec.pubkey_hex = EndorsementFieldCommitment("VELD_ENDORSE_PUBKEY_v1|",
                                                         CanonicalHex(validator_pubkey));
            erec.address = validator_address;
            erec.sig_hex = EndorsementFieldCommitment("VELD_ENDORSE_SIG_v1|", sig_hex);
            erec.block_hash_hex = canonical_hash_hex;
            erec.block_height = height;
            erec.reward_paid = false;
            block_endorsements.push_back(erec);
        }
    }

    void TrimExpiredCooldownsLocked(uint64_t current_height) {
        if (current_height < VALIDATOR_OP_COOLDOWN_BLOCKS)
            return;
        uint64_t cutoff = current_height - VALIDATOR_OP_COOLDOWN_BLOCKS;
        for (auto it = last_op_height_.begin(); it != last_op_height_.end();) {
            if (it->second < cutoff)
                it = last_op_height_.erase(it);
            else
                ++it;
        }
    }

    static std::vector<std::string> Split(const std::string& s, char delim) {
        std::vector<std::string> parts;
        std::istringstream ss(s);
        std::string part;
        while (std::getline(ss, part, delim))
            parts.push_back(part);
        return parts;
    }

    static bool ParseCanonicalUint64(const std::string& s, uint64_t& out) noexcept {
        return ParseCanonicalUint64Text(s, out);
    }

    static bool IsExactHex(const std::string& s, size_t exact_size) noexcept {
        if (s.size() != exact_size)
            return false;
        for (char c : s) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        }
        return true;
    }

    static bool IsCanonicalLowerHex(const std::string& s, size_t exact_size) noexcept {
        if (s.size() != exact_size)
            return false;
        for (char c : s) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                return false;
        }
        return true;
    }

    static std::string CanonicalHex(const std::string& s) {
        std::string out = s;
        for (char& c : out)
            if (c >= 'A' && c <= 'F')
                c = (char)(c - 'A' + 'a');
        return out;
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
        if (len > script.size() - offset || offset + len != script.size())
            return "";
        return std::string(script.begin() + offset, script.begin() + offset + len);
    }

    static std::vector<uint8_t> HexToBytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        if (hex.size() % 2 != 0)
            return bytes;
        bytes.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2) {
            uint8_t b = 0;
            for (int j = 0; j < 2; j++) {
                char c = hex[i + j];
                uint8_t nibble = 0;
                if (c >= '0' && c <= '9')
                    nibble = (uint8_t)(c - '0');
                else if (c >= 'a' && c <= 'f')
                    nibble = (uint8_t)(c - 'a' + 10);
                else if (c >= 'A' && c <= 'F')
                    nibble = (uint8_t)(c - 'A' + 10);
                else
                    return {};
                b = (uint8_t)(b * 16 + nibble);
            }
            bytes.push_back(b);
        }
        return bytes;
    }

    // Verify validator-operation signatures. Presence-only checks would let a
    // sigless input forge register/deregister operations for another public key.
    // Delegates
    // to the shared verified-signer check (op_authorization.h): the validator-control
    // actor must have actually signed an input of this transaction.
    static bool TxInputMatchesAddress(const Transaction& tx, const std::string& address) {
        return TxVerifiedSignedBy(tx, address);
    }

  public:
    static std::string PubkeyToAddress(const std::vector<uint8_t>& pubkey_bytes) {
        if (pubkey_bytes.size() != 1952)
            return "";
        Secp256k1PubKey pk;
        std::copy(pubkey_bytes.begin(), pubkey_bytes.end(), pk.begin());
        Hash160 h = Hash160Compute(pk);
        std::vector<uint8_t> script(25);
        script[0] = 0x76;
        script[1] = 0xA9;
        script[2] = 0x14;
        std::copy(h.begin(), h.end(), script.begin() + 3);
        script[23] = 0x88;
        script[24] = 0xAC;
        return ScriptToAddress(script);
    }
};

} // namespace veld
