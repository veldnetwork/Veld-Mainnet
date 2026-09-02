#pragma once
// btcVELD redemption signer bond and slash covenant.
//
// The redemption signer set controls Bitcoin custody and posts VELD collateral
// against its assigned share. Consensus evaluates slash conditions from the
// redemption queue and Bitcoin facts proven by the SPV relay, never operator
// assertions. The covenant remains dormant until those facts are provable.

#include "core/btc_deposit_verify.h"
#include "consensus/state_digest.h"
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <cstdint>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>

namespace veld {
namespace btcveld {

using btcspv::H256;

struct SignerBond {
    std::string veld_addr;
    uint64_t    bonded_sats = 0;
    uint64_t    locked_sats = 0;
    bool        active = false;
    uint64_t    free() const { return bonded_sats > locked_sats ? bonded_sats - locked_sats : 0; }
};

enum class ReqStatus : uint8_t { REQUESTED, LOCKED_IN, ASSIGNED, SIGNED, BROADCAST, FULFILLED, DEFAULTED };

struct RedeemRequest {
    H256                 request_id{};
    uint64_t             amount_sats = 0;
    std::vector<uint8_t> dest_spk;
    uint64_t             request_height = 0;
    uint64_t             deadline_height = 0;
    ReqStatus            status = ReqStatus::REQUESTED;
    H256                 fulfilled_txid{};
    std::string          veld_recipient;
    H256                 request_commitment{};
    uint64_t             btc_observed_height = 0;
};

#if defined(VELD_PUBLIC_RELEASE) || defined(VELD_BTCVELD_REGTEST) || \
    defined(VELD_TEST_BTC_REDEEM_BINDING)
inline constexpr bool REDEEM_PAYOUT_BINDING_REQUIRED = true;
#else
inline constexpr bool REDEEM_PAYOUT_BINDING_REQUIRED = false;
#endif

inline std::vector<uint8_t> RedeemRequestCommitmentScript(const H256& commitment) {
    static constexpr char DOMAIN[] = "VELD_REDEEM_V2|";
    constexpr size_t payload_size = sizeof(DOMAIN) - 1 + 32;
    static_assert(payload_size <= 75, "redeem commitment must use canonical direct push");
    std::vector<uint8_t> script{0x6a, static_cast<uint8_t>(payload_size)};
    script.insert(script.end(), DOMAIN, DOMAIN + sizeof(DOMAIN) - 1);
    script.insert(script.end(), commitment.begin(), commitment.end());
    return script;
}

enum class SlashReason : uint8_t { NONE, NON_PAYMENT, FRAUDULENT_SPEND, WRONG_PAYOUT, UNBACKED_MINT };

struct SlashVerdict {
    bool        slash = false;
    SlashReason reason = SlashReason::NONE;
    uint64_t    slash_sats = 0;
    uint64_t    compensate_sats = 0;
    std::string compensate_to;
    std::string diagnostic;
};

class SignerBondCovenant {
public:
    static H256 RequestCommitment(const RedeemRequest& request) {
        namespace sd = ::veld::state_digest;
        std::vector<uint8_t> body;
        sd::put_bytes(body, request.request_id.data(), request.request_id.size());
        sd::put_u64_le(body, request.amount_sats);
        sd::put_len_prefixed(body, request.dest_spk);
        sd::put_u64_le(body, request.request_height);
        sd::put_u64_le(body, request.deadline_height);
        sd::put_u64_le(body, request.btc_observed_height);
        sd::put_len_prefixed(body, request.veld_recipient);
        return sd::sha256_domain("VELD_BTCVELD_REDEEM_REQUEST_v2", body);
    }

    bool Register(const std::string& addr, uint64_t bond_sats) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (addr.empty() || bond_sats == 0) return false;
        SignerBond& s = signers_[addr];
        if (s.bonded_sats > UINT64_MAX - bond_sats) return false;
        s.veld_addr = addr; s.bonded_sats += bond_sats;
        return true;
    }
    bool Activate(const std::string& addr) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = signers_.find(addr);
        if (it == signers_.end() || it->second.bonded_sats == 0) return false;
        it->second.active = true; return true;
    }
    uint64_t TotalActiveBond() const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        unsigned __int128 total = 0;
        for (const auto& [_a, s] : signers_)
            if (s.active) total += s.bonded_sats;
        return total > UINT64_MAX ? UINT64_MAX : static_cast<uint64_t>(total);
    }
    int ActiveCount() const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        int n = 0;
        for (const auto& [_a, s] : signers_) if (s.active) ++n;
        return n;
    }
    bool CustodyWithinBond(uint64_t custody_sats) const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return custody_sats <= TotalActiveBond();
    }

    // Atomic request admission. Consensus callers intentionally let an
    // admission exception escape to the outer all-module snapshot boundary,
    // which restores every module and rejects the block. No request can become
    // visible unless its exact amount has first been reserved, and duplicate
    // replay cannot reserve twice.
    void AddRequest(const RedeemRequest& r,
                    bool reserve_backed_without_bond = false) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        RedeemRequest canonical = r;
        if (HashIsZero(canonical.request_id) ||
            canonical.amount_sats == 0 ||
            canonical.dest_spk.empty() ||
            canonical.veld_recipient.empty() ||
            canonical.deadline_height <= canonical.request_height ||
            canonical.status != ReqStatus::LOCKED_IN ||
            !HashIsZero(canonical.fulfilled_txid)) {
            throw std::runtime_error(
                "invalid btcVELD redemption request admission");
        }

        const H256 expected = RequestCommitment(canonical);
        if (!HashIsZero(canonical.request_commitment) &&
            canonical.request_commitment != expected) {
            throw std::runtime_error(
                "btcVELD redemption request commitment mismatch");
        }
        canonical.request_commitment = expected;

        auto existing = requests_.find(canonical.request_id);
        if (existing != requests_.end()) {
            if (SameRequest_(existing->second, canonical) &&
                (reserve_backed_requests_.count(canonical.request_id) != 0) ==
                    reserve_backed_without_bond)
                return; // exact idempotent replay; never lock twice
            throw std::runtime_error(
                "conflicting btcVELD redemption request replay");
        }

        if (reserve_backed_without_bond) {
            auto inserted = requests_.emplace(
                canonical.request_id, std::move(canonical));
            if (!inserted.second)
                throw std::runtime_error(
                    "btcVELD reserve request insertion race");
            const H256 request_id = inserted.first->first;
            try {
                if (!reserve_backed_requests_.insert(request_id).second)
                    throw std::runtime_error(
                        "btcVELD reserve request accounting conflict");
            } catch (...) {
                requests_.erase(request_id);
                throw;
            }
            return;
        }

        LockPlan lock_plan;
        if (!BuildLockPlan_(canonical.amount_sats, lock_plan)) {
            throw std::runtime_error(
                "insufficient free signer bond for btcVELD redemption");
        }

        ApplyLockPlan_(lock_plan);
        try {
            auto inserted = requests_.emplace(
                canonical.request_id, std::move(canonical));
            if (inserted.second)
                return;
        } catch (...) {
            RollbackLockPlan_(lock_plan);
            throw;
        }

        RollbackLockPlan_(lock_plan);
        throw std::runtime_error(
            "btcVELD redemption request insertion race");
    }

    std::vector<H256> DueForDefault(uint64_t current_height) const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        std::vector<H256> out;
        for (const auto& [id, r] : requests_)
            if (r.status >= ReqStatus::LOCKED_IN && r.status != ReqStatus::FULFILLED &&
                r.status != ReqStatus::DEFAULTED && current_height > r.deadline_height)
                out.push_back(id);
        std::sort(out.begin(), out.end());
        return out;
    }
    void SetStatus(const H256& id, ReqStatus st) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = requests_.find(id);
        if (it == requests_.end()) return;
        RedeemRequest& r = it->second;
        if (r.status == st) return;
        if (r.status == ReqStatus::FULFILLED ||
            r.status == ReqStatus::DEFAULTED)
            return;
        if (st == ReqStatus::FULFILLED)
            throw std::runtime_error(
                "use MarkFulfilled for btcVELD fulfillment");
        if (st == ReqStatus::DEFAULTED)
            ReleaseRequestLock_(id, r.amount_sats);
        r.status = st;
    }
    std::optional<RedeemRequest> GetCopy(const H256& id) const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        const auto it = requests_.find(id);
        return it == requests_.end()
            ? std::nullopt
            : std::optional<RedeemRequest>(it->second);
    }

    std::optional<RedeemRequest> FindOpenByCommitmentCopy(
            const H256& commitment) const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (HashIsZero(commitment)) return std::nullopt;
        const RedeemRequest* match = nullptr;
        for (const auto& [_id, request] : requests_) {
            const bool open = request.status == ReqStatus::LOCKED_IN ||
                request.status == ReqStatus::ASSIGNED ||
                request.status == ReqStatus::SIGNED ||
                request.status == ReqStatus::BROADCAST;
            if (!open || request.request_commitment != commitment) continue;
            if (match != nullptr)
                return std::nullopt; // commitments must be unique
            match = &request;
        }
        return match == nullptr
            ? std::nullopt
            : std::optional<RedeemRequest>(*match);
    }

    bool IsConsumedPayout(const H256& txid) const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return consumed_payouts_.count(txid) != 0;
    }
    bool IsConsumedFraudSpend(const H256& txid) const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return consumed_fraud_spends_.count(txid) != 0;
    }

    bool MarkFulfilled(const H256& id, const H256& payout_txid, uint64_t paid_sats,
                       const std::vector<uint8_t>& paid_spk) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = requests_.find(id);
        if (it == requests_.end()) return false;
        RedeemRequest& r = it->second;
        if (r.status == ReqStatus::FULFILLED || r.status == ReqStatus::DEFAULTED) return false;
        if (paid_sats != r.amount_sats || paid_spk != r.dest_spk) return false;
        ReleaseRequestLock_(id, r.amount_sats);
        r.status = ReqStatus::FULFILLED; r.fulfilled_txid = payout_txid;
        return true;
    }

    bool MarkAuthorizedReservePayout(
            const H256& id, const H256& payout_txid, uint64_t paid_sats,
            const std::vector<uint8_t>& paid_spk) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (HashIsZero(payout_txid) || IsConsumedPayout(payout_txid) ||
            IsConsumedFraudSpend(payout_txid))
            return false;
        if (!MarkFulfilled(id, payout_txid, paid_sats, paid_spk))
            return false;
        return consumed_payouts_.insert(payout_txid).second;
    }

    bool ResolveProvenPayout(const H256& id, const H256& payout_txid,
                             const std::vector<btcspv::BtcTxOut>& outs,
                             SlashVerdict& out_v,
                             const H256& request_commitment = H256{},
                             uint64_t payout_btc_height = UINT64_MAX,
                             bool spends_recognized_custody = false,
                             const std::vector<uint8_t>& custody_spk = {},
                             uint64_t proven_input_sats = 0) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto it = requests_.find(id);
        if (it == requests_.end()) { out_v.diagnostic = "unknown request"; return false; }
        RedeemRequest& r = it->second;
        if (r.status == ReqStatus::FULFILLED || r.status == ReqStatus::DEFAULTED) { out_v.diagnostic = "closed"; return false; }

        // Strict public payouts may mutate covenant state only after the caller
        // supplies the complete context returned by a successful PSP2 proof.
        // Missing context is not evidence of signer wrongdoing: fail closed
        // without consuming the txid, defaulting the request, releasing locks,
        // or constructing slash state.
        if (REDEEM_PAYOUT_BINDING_REQUIRED &&
            (HashIsZero(request_commitment) ||
             payout_btc_height == UINT64_MAX ||
             !spends_recognized_custody || custody_spk.empty() ||
             proven_input_sats == 0)) {
            out_v.diagnostic = "complete verified payout context is required";
            return false;
        }

        H256 supplied_commitment = request_commitment;
        if (!REDEEM_PAYOUT_BINDING_REQUIRED && HashIsZero(supplied_commitment))
            supplied_commitment = r.request_commitment;
        if (supplied_commitment != r.request_commitment) {
            out_v.diagnostic = "payout is not bound to the request commitment"; return false;
        }
        if (!spends_recognized_custody) {
            out_v.diagnostic = "payout does not spend recognized custody"; return false;
        }
        if (payout_btc_height <= r.btc_observed_height) {
            out_v.diagnostic = "payout predates the redemption request"; return false;
        }
        if (IsConsumedFraudSpend(payout_txid)) {
            out_v.diagnostic = "custody transaction already classified as fraudulent"; return false;
        }
        if (IsConsumedPayout(payout_txid)) {
            out_v.diagnostic = "payout transaction already consumed"; return false;
        }

        // Preserve historical non-public PSPV semantics exactly. Public-release
        // builds take the strict complete-accounting branch below.
        if (!REDEEM_PAYOUT_BINDING_REQUIRED) {
            uint64_t paid = 0;
            for (const auto& o : outs) {
                if (o.spk != r.dest_spk) continue;
                if (paid > UINT64_MAX - o.value) {
                    out_v.diagnostic = "payout amount overflow"; return false;
                }
                paid += o.value;
            }
            consumed_payouts_.insert(payout_txid);
            if (paid == r.amount_sats) {
                MarkFulfilled(id, payout_txid, paid, r.dest_spk); return true;
            }
            out_v = EvalWrongPayout(id, paid, r.dest_spk);
            ReleaseRequestLock_(id, r.amount_sats);
            r.status = ReqStatus::DEFAULTED;
            r.fulfilled_txid = payout_txid;
            return false;
        }

        uint64_t paid = 0, output_total = 0;
        size_t destination_outputs = 0, commitment_outputs = 0, change_outputs = 0;
        bool canonical_shape = true;
        const std::vector<uint8_t> expected_commitment = RedeemRequestCommitmentScript(r.request_commitment);
        for (const auto& o : outs) {
            if (output_total > UINT64_MAX - o.value) { canonical_shape = false; break; }
            output_total += o.value;
            if (o.spk == r.dest_spk && o.value > 0) {
                ++destination_outputs;
                if (paid > UINT64_MAX - o.value) { canonical_shape = false; break; }
                paid += o.value; continue;
            }
            if (o.value == 0 && o.spk == expected_commitment) { ++commitment_outputs; continue; }
            if (!custody_spk.empty() && o.spk == custody_spk && o.value > 0) { ++change_outputs; continue; }
            canonical_shape = false;
        }
        static constexpr uint64_t MAX_PROVEN_PAYOUT_FEE_SATS = 100'000;
        canonical_shape = canonical_shape && !custody_spk.empty() &&
            r.dest_spk != custody_spk && proven_input_sats > 0 &&
            destination_outputs == 1 && commitment_outputs == 1 &&
            change_outputs <= 1 && paid == r.amount_sats &&
            output_total <= proven_input_sats &&
            proven_input_sats - output_total <= MAX_PROVEN_PAYOUT_FEE_SATS;

        consumed_payouts_.insert(payout_txid);
        if (canonical_shape) {
            MarkFulfilled(id, payout_txid, paid, r.dest_spk); return true;
        }
        out_v.slash = true;
        out_v.reason = SlashReason::WRONG_PAYOUT;
        out_v.compensate_sats = r.amount_sats;
        out_v.compensate_to = r.veld_recipient;
        out_v.slash_sats = r.amount_sats;
        out_v.diagnostic = "payout violates the one-request complete custody accounting rule";
        ReleaseRequestLock_(id, r.amount_sats);
        r.status = ReqStatus::DEFAULTED;
        r.fulfilled_txid = payout_txid;
        return false;
    }

    SlashVerdict EvalNonPayment(const H256& id, uint64_t current_height, uint64_t penalty_bps = 2000) const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        SlashVerdict v;
        const auto it = requests_.find(id);
        if (it == requests_.end()) {
            v.diagnostic = "unknown request";
            return v;
        }
        const RedeemRequest& r = it->second;
        if (r.status == ReqStatus::FULFILLED) { v.diagnostic = "already fulfilled — no slash"; return v; }
        if (r.status == ReqStatus::DEFAULTED) { v.diagnostic = "already defaulted"; return v; }
        if (r.status < ReqStatus::LOCKED_IN) { v.diagnostic = "not yet LOCKED_IN"; return v; }
        if (current_height <= r.deadline_height) { v.diagnostic = "within honor window"; return v; }
        v.slash = true; v.reason = SlashReason::NON_PAYMENT;
        v.compensate_sats = r.amount_sats; v.compensate_to = r.veld_recipient;
        const uint64_t penalty = PctOf(r.amount_sats, penalty_bps);
        v.slash_sats = r.amount_sats > UINT64_MAX - penalty
            ? UINT64_MAX : r.amount_sats + penalty;
        v.diagnostic = "deadline passed, no fulfilled payout";
        return v;
    }

    SlashVerdict EvalFraudulentSpend(uint64_t spent_sats,
                                     const std::vector<btcspv::BtcTxOut>& outs,
                                     const std::vector<uint8_t>& custody_spk = {},
                                     uint64_t total_input_sats = 0) const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        SlashVerdict v;
        if (spent_sats == 0 || custody_spk.empty()) {
            v.diagnostic = "custody spend value/script unavailable"; return v;
        }
        const uint64_t accounting_input = total_input_sats == 0 ? spent_sats : total_input_sats;
        if (accounting_input < spent_sats) {
            v.diagnostic = "custody value exceeds proven input value"; return v;
        }
        uint64_t output_total = 0;
        std::set<H256> matched_requests, marked_requests;
        bool complete = true;
        for (const auto& o : outs) {
            if (output_total > UINT64_MAX - o.value) { complete = false; break; }
            output_total += o.value;
            if (o.spk == custody_spk) continue;
            if (REDEEM_PAYOUT_BINDING_REQUIRED && o.value == 0) {
                bool marked = false;
                for (const auto& [id, r] : requests_) {
                    const bool open = r.status == ReqStatus::LOCKED_IN || r.status == ReqStatus::ASSIGNED ||
                        r.status == ReqStatus::SIGNED || r.status == ReqStatus::BROADCAST;
                    if (open && o.spk == RedeemRequestCommitmentScript(r.request_commitment) &&
                        marked_requests.insert(id).second) { marked = true; break; }
                }
                if (!marked) complete = false;
                continue;
            }
            bool matched = false;
            for (const auto& [id, r] : requests_) {
                const bool open = r.status == ReqStatus::LOCKED_IN || r.status == ReqStatus::ASSIGNED ||
                    r.status == ReqStatus::SIGNED || r.status == ReqStatus::BROADCAST;
                if (open && o.value == r.amount_sats && o.spk == r.dest_spk &&
                    matched_requests.insert(id).second) { matched = true; break; }
            }
            if (!matched) complete = false;
        }
        if (REDEEM_PAYOUT_BINDING_REQUIRED && marked_requests != matched_requests) complete = false;
        // Zero matched requests is a pure custody consolidation and remains
        // authorized; one is a payout. Two or more is forbidden because PSP2
        // has a txid-global payout nullifier and intentionally supports one
        // redemption per Bitcoin transaction.
        if (REDEEM_PAYOUT_BINDING_REQUIRED && matched_requests.size() > 1) complete = false;
        static constexpr uint64_t MAX_PROVEN_PAYOUT_FEE_SATS = 100'000;
        if (complete && output_total <= accounting_input &&
            accounting_input - output_total <= MAX_PROVEN_PAYOUT_FEE_SATS) {
            v.diagnostic = matched_requests.empty()
                ? "complete custody consolidation with bounded fee"
                : "complete custody spend is bound to one open request and change";
            return v;
        }
        v.slash = true; v.reason = SlashReason::FRAUDULENT_SPEND;
        v.slash_sats = std::min(spent_sats, TotalActiveBond());
        v.compensate_sats = 0;
        v.diagnostic = "custody spend contains an unbound output or invalid conservation/fee";
        return v;
    }

    bool ConsumeFraudSpend(const H256& spend_txid) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return !HashIsZero(spend_txid) && !IsConsumedPayout(spend_txid) &&
               consumed_fraud_spends_.insert(spend_txid).second;
    }

    SlashVerdict EvalWrongPayout(const H256& id, uint64_t paid_sats,
                                 const std::vector<uint8_t>& paid_spk) const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        SlashVerdict v;
        const auto it = requests_.find(id);
        if (it == requests_.end()) {
            v.diagnostic = "unknown request";
            return v;
        }
        const RedeemRequest& r = it->second;
        if (paid_sats == r.amount_sats && paid_spk == r.dest_spk) {
            v.diagnostic = "payout matches the request — no slash"; return v;
        }
        v.slash = true; v.reason = SlashReason::WRONG_PAYOUT;
        v.compensate_sats = r.amount_sats; v.compensate_to = r.veld_recipient;
        v.slash_sats = r.amount_sats;
        v.diagnostic = "payout amount/spk != request";
        return v;
    }

    void ApplySlash(const SlashVerdict& v) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (!v.slash || v.slash_sats == 0) return;
        uint64_t total = TotalActiveBond();
        if (total == 0) return;
        uint64_t want = std::min(v.slash_sats, total), taken = 0;
        std::vector<std::string> keys; for (auto& [a, s] : signers_) if (s.active) keys.push_back(a);
        std::sort(keys.begin(), keys.end());
        for (const auto& a : keys) {
            SignerBond& s = signers_[a];
            uint64_t share = (uint64_t)((__uint128_t)want * s.bonded_sats / total);
            share = std::min(share, s.bonded_sats);
            s.bonded_sats -= share; taken += share;
        }
        if (taken < want && !keys.empty()) {
            uint64_t rem = want - taken;
            std::string big = keys[0];
            for (const auto& a : keys) if (signers_[a].bonded_sats > signers_[big].bonded_sats) big = a;
            uint64_t d = std::min(rem, signers_[big].bonded_sats);
            signers_[big].bonded_sats -= d; taken += d;
        }
        uint64_t to_insurance = taken > v.compensate_sats ? taken - v.compensate_sats : 0;
        insurance_fund_sats_ += to_insurance;
    }

    uint64_t InsuranceFund() const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return insurance_fund_sats_;
    }

    void Reset() {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        signers_.clear(); requests_.clear(); consumed_payouts_.clear();
        consumed_fraud_spends_.clear(); reserve_backed_requests_.clear();
        insurance_fund_sats_ = 0;
    }

    struct StateSnapshot {
        std::map<std::string, SignerBond> signers;
        std::map<H256, RedeemRequest> requests;
        std::set<H256> consumed_payouts;
        std::set<H256> consumed_fraud_spends;
        std::set<H256> reserve_backed_requests;
        uint64_t insurance_fund_sats = 0;
    };
    StateSnapshot SnapshotState() const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        return StateSnapshot{signers_, requests_, consumed_payouts_,
                             consumed_fraud_spends_,
                             reserve_backed_requests_,
                             insurance_fund_sats_};
    }
    void RestoreState(const StateSnapshot& s) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        signers_ = s.signers; requests_ = s.requests; consumed_payouts_ = s.consumed_payouts;
        consumed_fraud_spends_ = s.consumed_fraud_spends;
        reserve_backed_requests_ = s.reserve_backed_requests;
        insurance_fund_sats_ = s.insurance_fund_sats;
    }

    H256 Digest() const {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        namespace sd = ::veld::state_digest;
        std::vector<uint8_t> body;
#if defined(VELD_PUBLIC_MAINNET) || defined(VELD_BTCVELD_REGTEST)
        sd::put_u32_le(body, 3);
#else
        sd::put_u32_le(body, 2);
#endif
        sd::put_u32_le(body, static_cast<uint32_t>(signers_.size()));
        for (const auto& [addr, s] : signers_) {
            sd::put_len_prefixed(body, addr); sd::put_len_prefixed(body, s.veld_addr);
            sd::put_u64_le(body, s.bonded_sats); sd::put_u64_le(body, s.locked_sats); sd::put_u8(body, s.active ? 1 : 0);
        }
        sd::put_u32_le(body, static_cast<uint32_t>(requests_.size()));
        for (const auto& [id, r] : requests_) {
            sd::put_bytes(body, id.data(), id.size()); sd::put_bytes(body, r.request_id.data(), r.request_id.size());
            sd::put_u64_le(body, r.amount_sats); sd::put_len_prefixed(body, r.dest_spk);
            sd::put_u64_le(body, r.request_height); sd::put_u64_le(body, r.deadline_height);
            sd::put_u8(body, static_cast<uint8_t>(r.status)); sd::put_bytes(body, r.fulfilled_txid.data(), r.fulfilled_txid.size());
            sd::put_len_prefixed(body, r.veld_recipient); sd::put_bytes(body, r.request_commitment.data(), r.request_commitment.size());
            sd::put_u64_le(body, r.btc_observed_height);
        }
        sd::put_u32_le(body, static_cast<uint32_t>(consumed_payouts_.size()));
        for (const auto& payout : consumed_payouts_) sd::put_bytes(body, payout.data(), payout.size());
        sd::put_u32_le(body, static_cast<uint32_t>(consumed_fraud_spends_.size()));
        for (const auto& spend : consumed_fraud_spends_) sd::put_bytes(body, spend.data(), spend.size());
#if defined(VELD_PUBLIC_MAINNET) || defined(VELD_BTCVELD_REGTEST)
        sd::put_u32_le(body,
                      static_cast<uint32_t>(reserve_backed_requests_.size()));
        for (const auto& request : reserve_backed_requests_)
            sd::put_bytes(body, request.data(), request.size());
#endif
        sd::put_u64_le(body, insurance_fund_sats_);
        return sd::sha256_domain(sd::tags::REDEEM_BOND, body);
    }

private:
    using LockPlan = std::vector<std::pair<SignerBond*, uint64_t>>;

    mutable std::recursive_mutex mutex_;
    std::map<std::string, SignerBond> signers_;
    std::map<H256, RedeemRequest> requests_;
    std::set<H256> consumed_payouts_;
    std::set<H256> consumed_fraud_spends_;
    std::set<H256> reserve_backed_requests_;
    uint64_t insurance_fund_sats_ = 0;

    static uint64_t PctOf(uint64_t x, uint64_t bps) {
        const unsigned __int128 value =
            static_cast<unsigned __int128>(x) * bps / 10000;
        return value > UINT64_MAX ? UINT64_MAX
                                  : static_cast<uint64_t>(value);
    }

    static bool SameRequest_(const RedeemRequest& a,
                             const RedeemRequest& b) {
        return a.request_id == b.request_id &&
               a.amount_sats == b.amount_sats &&
               a.dest_spk == b.dest_spk &&
               a.request_height == b.request_height &&
               a.deadline_height == b.deadline_height &&
               a.status == b.status &&
               a.fulfilled_txid == b.fulfilled_txid &&
               a.veld_recipient == b.veld_recipient &&
               a.request_commitment == b.request_commitment &&
               a.btc_observed_height == b.btc_observed_height;
    }

    bool BuildLockPlan_(uint64_t amount_sats, LockPlan& plan) {
        plan.clear();
        if (amount_sats == 0) return false;
        uint64_t remaining = amount_sats;
        for (auto& [_addr, signer] : signers_) {
            if (!signer.active || remaining == 0) continue;
            const uint64_t amount = std::min(remaining, signer.free());
            if (amount == 0) continue;
            plan.emplace_back(&signer, amount);
            remaining -= amount;
        }
        return remaining == 0;
    }

    static void ApplyLockPlan_(const LockPlan& plan) noexcept {
        for (const auto& [signer, amount] : plan)
            signer->locked_sats += amount;
    }

    static void RollbackLockPlan_(const LockPlan& plan) noexcept {
        for (auto it = plan.rbegin(); it != plan.rend(); ++it)
            it->first->locked_sats -= it->second;
    }

    void ReleaseLock(uint64_t amount_sats) {
        unsigned __int128 total_locked = 0;
        for (const auto& [_addr, signer] : signers_)
            total_locked += signer.locked_sats;
        if (total_locked < amount_sats)
            throw std::runtime_error(
                "btcVELD redemption lock accounting underflow");

        uint64_t rem = amount_sats;
        for (auto& [_addr, signer] : signers_) {
            if (rem == 0) break;
            const uint64_t amount = std::min(rem, signer.locked_sats);
            signer.locked_sats -= amount;
            rem -= amount;
        }
    }

    void ReleaseRequestLock_(const H256& id, uint64_t amount_sats) {
        if (reserve_backed_requests_.erase(id) != 0) return;
        ReleaseLock(amount_sats);
    }
};

} // namespace btcveld
} // namespace veld
