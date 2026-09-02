#pragma once

#include "../core/transaction.h"
#include "../core/blockchain.h"
#include "../core/amm_pool.h"
#include "../core/onchain_tokens.h"
#include "../core/op_authorization.h"
#include "../core/stake_marker.h"
#include <map>
#include <unordered_map>
#include <vector>
#include <string>
#include <optional>
#include <mutex>
#include <chrono>
#include <unordered_set>
#include <deque>
#include <stdexcept>
#include <algorithm>
#include <functional>
#include <memory>

namespace veld {

class VeldNode;

struct MempoolEntry {
    Transaction tx;
    uint64_t    fee_units;
    uint64_t    fee_rate;
    uint64_t    added_time;
    uint64_t    tx_size_bytes;
    uint32_t    height_added;
    bool        is_rbf;
    // True when admission resolved at least one input through another mempool
    // entry.  Once those parents confirm, RemoveStale performs one authoritative
    // whole-transaction recheck before this entry may become a mineable root.
    bool        had_unconfirmed_parent;
    // Immutable admission proofs. Mempool entries are value-owned and never
    // mutated after insertion, while an outpoint's script is committed by its
    // txid. Therefore successful base locking and TOKEN authorizer checks do
    // not become false when the chain tip changes; only UTXO availability and
    // token balances/replay/caps require contextual re-evaluation.
    bool        base_locking_validated;
    bool        token_authorization_validated;

    MempoolEntry() : fee_units(0), fee_rate(0), added_time(0),
                     tx_size_bytes(0), height_added(0), is_rbf(false),
                     had_unconfirmed_parent(false),
                     base_locking_validated(false),
                     token_authorization_validated(false) {}

    MempoolEntry(const Transaction& t, uint64_t fee, uint32_t height)
        : tx(t), fee_units(fee), height_added(height), is_rbf(false),
          had_unconfirmed_parent(false), base_locking_validated(false),
          token_authorization_validated(false) {
        tx_size_bytes = t.Serialize().size();
        fee_rate      = tx_size_bytes > 0 ? (fee * 1000) / tx_size_bytes : 0;
        added_time    = (uint64_t)std::time(nullptr);
    }
};

class Mempool {
public:
    static constexpr size_t   MAX_MEMPOOL_BYTES = 500 * 1024 * 1024;
    static constexpr size_t   MAX_TX_COUNT      = 50000;
    static constexpr size_t   PAYMENT_SLOT_FLOOR = MAX_TX_COUNT / 10;
    // Stateful token requests are independently bounded to one full mining
    // template.  This keeps aggregate parent-state simulation bounded and
    // reserves the other 49,001 entries for ordinary payments/other protocols.
    static constexpr size_t   MAX_TOKEN_MEMPOOL_ENTRIES = 999;
    // Stateful TOKEN/MSPV requests trigger both PQ input verification and a
    // deterministic token-state replay. Match the already deployed AMM relay
    // envelope so one valid, fee-paying request cannot consume the generic
    // 1-MiB/10,000-input transaction allowance as a repeatable CPU amplifier.
    // This is standard relay/mining policy, not a consensus transaction limit;
    // fragmented wallets can use the ordinary consolidation path first.
    static constexpr size_t   MAX_TOKEN_TX_BYTES = 128 * 1024;
    static constexpr size_t   MAX_TOKEN_TX_INPUTS = 24;
    static constexpr size_t   MAX_TOKEN_TX_OUTPUTS =
        MAX_STANDARD_TRANSACTION_OUTPUTS;
    // Canonical ordinary-transaction relay envelope.  The P2P header parser
    // consumes this same constant so an oversized TX is rejected before body
    // reservation/read/hash work rather than only after deserialization.
    static constexpr size_t   MAX_RELAY_TX_BYTES = 1024 * 1024;
    static constexpr uint64_t TX_EXPIRY_SECONDS = 72 * 3600;
    static constexpr uint64_t MIN_FEE_RATE      = 1;

    Mempool() : total_bytes_(0) {}

    enum class AddResult {
        ACCEPTED,
        DUPLICATE,
        FEE_TOO_LOW,
        INVALID,
        // An authenticated candidate reached NMS verification, but a bounded
        // source/global work budget or the local dataset was unavailable.
        // This is retryable local state, not peer-authored invalid consensus.
        DEFERRED_LOCAL_WORK,
        // The referenced outpoint is absent from both the canonical UTXO set
        // and the current mempool.  This is an orphan/race classification, not
        // proof that the peer authored an intrinsically invalid transaction.
        MISSING_INPUT,
        FULL,
        DOUBLE_SPEND,
        STAKE_ALREADY_PENDING,
        STAKE_EXCEEDS_BALANCE,
        COINBASE_IMMATURE,
        VALIDATOR_STATE_COOLDOWN,
        MALFORMED_VALIDATOR_OP,
        PUBLIC_TESTNET_EXTERNAL_VALUE_DISABLED,
        RUNTIME_ADMISSION_CLOSED
    };

    static const char* ResultToString(AddResult r) {
        switch(r) {
            case AddResult::ACCEPTED: return "accepted";
            case AddResult::DUPLICATE: return "duplicate";
            case AddResult::FEE_TOO_LOW: return "fee_too_low";
            case AddResult::INVALID: return "invalid";
            case AddResult::DEFERRED_LOCAL_WORK: return "deferred_local_work";
            case AddResult::MISSING_INPUT: return "missing_input";
            case AddResult::FULL: return "full";
            case AddResult::DOUBLE_SPEND: return "double_spend";
            case AddResult::STAKE_ALREADY_PENDING: return "stake_already_pending";
            case AddResult::STAKE_EXCEEDS_BALANCE: return "stake_exceeds_balance";
            case AddResult::COINBASE_IMMATURE: return "coinbase_immature";
            case AddResult::VALIDATOR_STATE_COOLDOWN: return "validator_state_cooldown";
            case AddResult::MALFORMED_VALIDATOR_OP: return "malformed_validator_op";
            case AddResult::PUBLIC_TESTNET_EXTERNAL_VALUE_DISABLED:
                return "public_testnet_external_value_disabled";
            case AddResult::RUNTIME_ADMISSION_CLOSED:
                return "runtime_admission_closed";
            default: return "unknown";
        }
    }

    // Decode the one pushed payload carried by an OP_RETURN output.  `exact`
    // distinguishes an exact one-push script from an otherwise decodable
    // prefix with trailing opcodes/bytes.  Stake policy requires exact scripts:
    // accepting an alias here while the state engine interprets only the first
    // push lets one textual operation acquire a different mempool identity.
    static bool ExtractOpReturnPayload(const std::vector<uint8_t>& spk,
                                       std::string& payload,
                                       bool& exact) {
        payload.clear();
        exact = false;
        if (spk.size() < 2 || spk[0] != 0x6A) return false;
        size_t off = 1, plen = 0;
        if (spk[off] <= 75) { plen = spk[off++]; }
        else if (spk[off] == 0x4C && spk.size() > off + 1) { off++; plen = spk[off++]; }
        else if (spk[off] == 0x4D && spk.size() > off + 2) {
            off++; plen = (size_t)spk[off] | ((size_t)spk[off + 1] << 8); off += 2;
        } else {
            return false;
        }
        if (off + plen > spk.size()) return false;
        payload.assign(spk.begin() + off, spk.begin() + off + plen);
        exact = off + plen == spk.size();
        return true;
    }

    static bool ExtractCanonicalStakeOp(const std::vector<uint8_t>& spk,
                                        CanonicalStakeOp& op,
                                        bool& is_stake_family) {
        std::string payload;
        bool exact = false;
        if (!ExtractOpReturnPayload(spk, payload, exact)) {
            is_stake_family = false;
            return false;
        }
        static const std::string prefix = "VELD_STAKE|";
        is_stake_family = payload.compare(0, prefix.size(), prefix) == 0;
        // Consensus' staking decoder accepts exactly the shortest push opcode
        // and consumes the complete script.  Relay must reject every byte
        // alias of the same textual operation; otherwise a non-minimal marker
        // can reserve pending-staker state even though block application treats
        // it as an inert paid memo.
        if (!is_stake_family || !exact ||
            !IsCanonicalMarkerOpReturn(spk, payload)) return false;
        return ParseCanonicalStakeOp(payload, op);
    }

    static std::string ExtractStakeAddress(const std::vector<uint8_t>& spk) {
        CanonicalStakeOp op;
        bool is_stake_family = false;
        if (!ExtractCanonicalStakeOp(spk, op, is_stake_family)) return "";
        return op.address;
    }

    // Parse the sole canonical TOKEN/MSPV marker for stateful relay policy.
    // `is_family` is true even when malformed so callers can reject aliases
    // before any ML-DSA or SPV work.  Consensus' structural one-marker guard is
    // mirrored here because mixed-parent transactions do not reach the whole-
    // transaction chain validator until their parents confirm.
    static bool ExtractCanonicalTokenMarker(
            const Transaction& tx, bool& is_family,
            std::optional<TokenOpData>& token_op,
            bool& is_mspv,
            std::string* canonical_payload = nullptr) {
        is_family = false;
        is_mspv = false;
        token_op.reset();
        if (canonical_payload) canonical_payload->clear();
        size_t count = 0;
        for (const auto& out : tx.outputs) {
            std::string payload;
            bool exact = false;
            if (!ExtractOpReturnPayload(out.script_pubkey, payload, exact))
                continue;
            const bool token = payload.rfind(TOKEN_OP_RETURN_PREFIX, 0) == 0;
            const bool mspv  = payload.rfind("VELD_MSPV|", 0) == 0;
            const bool reserve =
                btcveld::reserve::TRANSITION_V1_REQUIRED &&
                payload.rfind("VELD_RSV", 0) == 0;
            if (!token && !mspv && !reserve) continue;
            is_family = true;
            if (++count != 1 || out.value != 0 || !exact ||
                !IsCanonicalMarkerOpReturn(out.script_pubkey, payload))
                return false;
            if (token) {
                if (payload.size() > MAX_TOKEN_OP_PAYLOAD_BYTES) return false;
                token_op = DecodeTokenOp(payload);
                if (!token_op) return false;
            } else {
                // Keep direct-raw transactions aligned with the parser's exact
                // worst-case branch/stripped-tx/nullifier envelope.
                const size_t direct_limit = reserve
                    ? MAX_TOKEN_OP_PAYLOAD_BYTES
                    : btcnull::MAX_MSPV_OP_PAYLOAD_BYTES;
                if (payload.size() > direct_limit)
                    return false;
                is_mspv = true;
            }
            if (canonical_payload) *canonical_payload = payload;
        }
        return !is_family || count == 1;
    }

    // Every issuer/SPV mint proof is a child of the one current sparse
    // nullifier root.  Once any child lands, every independently prepared
    // sibling proof is stale.  Serialize that unresolved child globally (not
    // merely by deposit outpoint) so the mempool cannot knowingly create an
    // MNP2 carrier that would become a strict-invalid block transaction and
    // strand a funded allocation. At the target cadence this still permits one
    // mint per block, well above the launch admission rate.
    static std::string TokenReplayReservationKey(
            const std::optional<TokenOpData>& token_op, bool is_mspv,
            const std::string& canonical_payload) {
        static constexpr const char* ROOT_CHILD =
            "btc-nullifier-root:one-unresolved-child";
        static constexpr const char* C1_CARRIER =
            "btc-c1-sequence:one-unresolved-carrier";
        if (!is_mspv) {
            if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED) {
                if (token_op &&
                    token_op->token_id == BTCVELD_TOKEN_ID &&
                    token_op->action == "MINT" &&
                    token_op->memo.rfind(
                        btcveld::reserve::ISSUER_MEMO_PREFIX, 0) == 0) {
                    const std::vector<uint8_t> proof = HexToBytes(
                        token_op->memo.substr(std::strlen(
                            btcveld::reserve::ISSUER_MEMO_PREFIX)));
                    btcveld::reserve::Claim claim;
                    if (proof.empty() ||
                        !btcveld::reserve::DecodeProof(
                            proof.data(), proof.size(), claim))
                        return {};
                    return "btc-reserve-transition:one-unresolved-child";
                }
            }
            if (token_op && token_op->token_id == BTCVELD_TOKEN_ID &&
                (token_op->action == "RESERVE" ||
                 token_op->action == "CANCEL" ||
                 token_op->action == "EXPOSE"))
                return C1_CARRIER;
            if (token_op && token_op->token_id == BTCVELD_TOKEN_ID &&
                token_op->action == "FUND")
                return ROOT_CHILD;
            std::string outpoint;
            btcnull::Proof nullifier_proof;
            std::string reservation_id;
            if (!token_op || token_op->token_id != BTCVELD_TOKEN_ID ||
                token_op->action != "MINT" ||
                !btcnull::ParseIssuerMemo(token_op->memo, outpoint,
                                          nullifier_proof,
                                          reservation_id) ||
                !IsValidBtcOutpointId(outpoint))
                return {};
            if (!reservation_id.empty())
                return std::string("btc-c1-credit:") + reservation_id;
            return ROOT_CHILD;
        }
        static const std::string RESERVE_PREFIX = "VELD_RSV1|";
        if (canonical_payload.rfind(RESERVE_PREFIX, 0) == 0) {
            const std::vector<uint8_t> proof = HexToBytes(
                canonical_payload.substr(RESERVE_PREFIX.size()));
            btcveld::reserve::Claim claim;
            if (proof.empty() ||
                !btcveld::reserve::DecodeProof(
                    proof.data(), proof.size(), claim))
                return {};
            return "btc-reserve-transition:one-unresolved-child";
        }
        static const std::string MSPV_PREFIX = "VELD_MSPV|";
        if (canonical_payload.rfind(MSPV_PREFIX, 0) != 0) return {};
        const std::vector<uint8_t> proof = HexToBytes(
            canonical_payload.substr(MSPV_PREFIX.size()));
        if (proof.empty()) return {};
        btcspv::H256 block_hash{};
        uint64_t dirs = 0;
        std::vector<btcspv::H256> branch;
        std::vector<uint8_t> legacy_tx;
        if (!btcspv::ParseMintSpvOp(proof.data(), proof.size(), block_hash,
                                    dirs, branch, legacy_tx))
            return {};
        std::vector<btcspv::BtcTxOut> outs;
        if (!btcspv::ParseBtcTxOutputs(legacy_tx.data(), legacy_tx.size(),
                                       outs))
            return {};
        const auto& custody = BtcVeldCustodySpk();
        if (custody.empty()) return {};
        size_t matches = 0;
        uint32_t custody_vout = 0;
        for (size_t i = 0; i < outs.size(); ++i) {
            if (outs[i].spk != custody) continue;
            ++matches;
            custody_vout = static_cast<uint32_t>(i);
        }
        if (matches != 1) return {};
        const btcspv::H256 txid = Hash256d(legacy_tx);
        if (!IsValidBtcOutpointId(
                btcspv::BtcDepositOutpointId(txid, custody_vout)))
            return {};
        return ROOT_CHILD;
    }

    static bool TokenTransactionEnvelopeWithinBounds(
            const Transaction& tx, size_t serialized_size) {
        return tx.inputs.size() <= MAX_TOKEN_TX_INPUTS &&
               tx.outputs.size() <= MAX_TOKEN_TX_OUTPUTS &&
               serialized_size <= MAX_TOKEN_TX_BYTES;
    }

    static std::pair<std::string, uint64_t> ExtractStakeLockAddrAmount(
        const std::vector<uint8_t>& spk)
    {
        CanonicalStakeOp op;
        bool is_stake_family = false;
        if (!ExtractCanonicalStakeOp(spk, op, is_stake_family) ||
            op.action != CanonicalStakeOp::Action::LOCK) return {"", 0};
        return {op.address, op.amount_units};
    }

    AddResult Add(
        const Transaction& tx,
        uint64_t fee_units,
        uint32_t current_height,
        const Blockchain& chain,
        mining::ExpensivePowBudget* source_pow_budget = nullptr
    ) {
        return AddImpl_(tx, fee_units, current_height, chain,
                        source_pow_budget, nullptr);
    }

private:
    // Only VeldNode may construct the final work-sink authorization.  Ordinary
    // P2P/mempool callers retain the public Add path above and cannot forge a
    // validator-work lease.  The callback is invoked after all expensive
    // validation and while the mempool insertion mutex is held, immediately
    // before the first eviction or entry mutation.
    friend class VeldNode;
    struct WorkSinkAuthorization {
        std::shared_ptr<void> owner;
        std::function<bool()> claim;
        std::function<bool()> live;

        explicit operator bool() const noexcept {
            return owner && claim && live;
        }
    };

    AddResult AddAuthorizedWork_(
        const Transaction& tx,
        uint64_t fee_units,
        uint32_t current_height,
        const Blockchain& chain,
        WorkSinkAuthorization authorization,
        mining::ExpensivePowBudget* source_pow_budget = nullptr
    ) {
        if (!authorization) return AddResult::DEFERRED_LOCAL_WORK;
        return AddImpl_(tx, fee_units, current_height, chain,
                        source_pow_budget, &authorization);
    }

    AddResult AddImpl_(
        const Transaction& tx,
        uint64_t fee_units,
        uint32_t current_height,
        const Blockchain& chain,
        mining::ExpensivePowBudget* source_pow_budget,
        WorkSinkAuthorization* work_authorization
    ) {
        const uint64_t canonical_height = chain.Height();
        if (canonical_height == UINT64_MAX ||
            !chain.RuntimeAdmissionPermits(canonical_height + 1))
            return AddResult::RUNTIME_ADMISSION_CLOSED;

        Hash256 txid = tx.GetTxID();
        std::string key = HashToHex(txid);

        if (!tx.IsValid()) return AddResult::INVALID;
        // Exact high-cardinality vault/system distributions are constructed
        // inside block assembly and validated contextually; they never belong
        // in the public mempool.  Bound every relayed transaction before any
        // signature, SPV, graph, or state-machine work.
        if (tx.outputs.size() > MAX_STANDARD_TRANSACTION_OUTPUTS)
            return AddResult::INVALID;
        if (TxComposesMultipleProtocols(tx) ||
            TxHasInvalidTokenMarkerSet(tx))
            return AddResult::INVALID;
#ifdef VELD_PUBLIC_TESTNET
        if (TxUsesExternalValueProtocol(tx))
            return AddResult::PUBLIC_TESTNET_EXTERNAL_VALUE_DISABLED;
#endif

        bool token_family = false;
        bool token_is_mspv = false;
        std::optional<TokenOpData> token_op;
        std::string token_marker_payload;
        if (!ExtractCanonicalTokenMarker(tx, token_family, token_op,
                                         token_is_mspv,
                                         &token_marker_payload))
            return AddResult::INVALID;
        const std::string token_replay_key = TokenReplayReservationKey(
            token_op, token_is_mspv, token_marker_payload);
        if (token_is_mspv && token_replay_key.empty())
            return AddResult::INVALID;
        if (token_op && token_op->token_id == BTCVELD_TOKEN_ID &&
            (token_op->action == "MINT" ||
             token_op->action == "FUND") &&
            token_replay_key.empty())
            return AddResult::INVALID;

        // Stake-family markers are state-changing protocol requests, not
        // ignorable memo text.  Reject malformed aliases and impossible
        // amounts before signature work.  Previously a canonical-looking
        // LOCK for another address (including amount=0) could enter the
        // mempool, reserve that victim in pending_stakers_, and make the
        // victim's real LOCK fail with STAKE_ALREADY_PENDING even though the
        // staking ledger would ignore the attacker's unauthorized request.
        std::vector<CanonicalStakeOp> stake_ops;
        for (const auto& out : tx.outputs) {
            CanonicalStakeOp op;
            bool is_stake_family = false;
            const bool valid =
                ExtractCanonicalStakeOp(out.script_pubkey, op,
                                        is_stake_family);
            if (is_stake_family && !valid) return AddResult::INVALID;
            if (!valid) continue;
            if (AddressToScript(op.address).size() != 25)
                return AddResult::INVALID;
            if (op.amount_units == 0 ||
                op.amount_units > MAX_STAKE_UNITS)
                return AddResult::INVALID;
            if (op.action == CanonicalStakeOp::Action::LOCK &&
                op.amount_units < MIN_STAKE_UNITS)
                return AddResult::INVALID;
            stake_ops.push_back(std::move(op));
        }

        // Mirror the staking ledger's post-UNLOCK minimum using its exact
        // parent-state aggregate, maturity view, and configured minimum.  A
        // block may still carry a non-applying paid request by consensus, but
        // standard relay/mining must not propagate one that tries to leave a
        // dust stake slot.  Aggregate same-address UNLOCK markers so splitting
        // one request inside a transaction cannot bypass the check.
        std::unordered_map<std::string, uint64_t> unlock_claims;
        for (const auto& op : stake_ops) {
            if (op.action != CanonicalStakeOp::Action::UNLOCK) continue;
            auto& requested = unlock_claims[op.address];
            if (requested > UINT64_MAX - op.amount_units)
                return AddResult::INVALID;
            requested += op.amount_units;
        }
        const uint64_t candidate_height = (uint64_t)current_height + 1;
        if (!chain.StakeTransactionValid(tx, candidate_height))
            return AddResult::INVALID;
        const uint64_t effective_min_stake =
            chain.GetEffectiveMinStakeUnits();
        for (const auto& [address, requested] : unlock_claims) {
            const uint64_t current = chain.GetStakedForAddr(address);
            const uint64_t mature =
                chain.GetMatureStakeForAddr(address, candidate_height);
            // Consensus keeps malformed/early protocol requests as paid
            // no-ops, but relay must not let a fresh signed address reserve a
            // pending-staker slot with an UNLOCK that cannot remove anything.
            // A real owner can resubmit once at least one tranche is mature.
            if (current == 0 || mature == 0)
                return AddResult::INVALID;
            if (!StakeUnlockPreservesMinimum(
                    current, mature, requested, effective_min_stake))
                return AddResult::INVALID;
        }

        //  #3: run the CHEAP, pure-tx
        // checks AND the recently-rejected cache BEFORE the expensive per-input
        // ML-DSA verification (ValidateTransactionLocking, below). Otherwise a
        // peer can force ~one signature verify per input by replaying a malformed
        // / over-budget tx. The per-peer byte budgets already bound this;
        // verifying-last plus the reject cache removes the wasted work entirely.
        // (The size/fee checks re-run under the mempool lock further down;
        // harmless and lock-correct — they only ever pass once we get here.)
        {
            size_t tx_size_pre = tx.Serialize().size();
            if (tx_size_pre > 1024 * 1024) return AddResult::INVALID;
            if (token_family &&
                !TokenTransactionEnvelopeWithinBounds(tx, tx_size_pre))
                return AddResult::INVALID;
            uint64_t fee_rate_pre = tx_size_pre > 0 ? (fee_units * 1000) / tx_size_pre : 0;
            if (fee_rate_pre < MIN_FEE_RATE) return AddResult::FEE_TOO_LOW;
            if (chain.Height() >= BATCH1_HARDENING_HEIGHT &&
                tx.HasDustOutput(DUST_THRESHOLD_UNITS)) return AddResult::INVALID;
            std::lock_guard<std::mutex> rl(recently_rejected_mtx_);
            if (recently_rejected_.count(key)) return AddResult::INVALID;
        }

        const AmmOpParseResult amm_parsed = ParseAmmOpDetailed(tx);
        {
            if (amm_parsed.status == AmmOpParseStatus::INVALID)
                return AddResult::INVALID;
            if (amm_parsed.status == AmmOpParseStatus::VALID &&
                !AmmTransactionEnvelopeWithinBounds(tx))
                return AddResult::INVALID;
            if (amm_parsed.status == AmmOpParseStatus::VALID &&
                ((amm_parsed.op.action == "SWAP_V2B" &&
                  amm_parsed.op.extra <= 0) ||
                 (amm_parsed.op.action == "SWAP_B2V" &&
                  amm_parsed.op.extra != 0)))
                return AddResult::INVALID;
            if (amm_parsed.status == AmmOpParseStatus::VALID &&
                (amm_parsed.op.action == "SWAP_V2B" || amm_parsed.op.action == "SWAP_B2V") &&
                !ammgate::SwapAllowed((uint64_t)current_height + 1)) {
                return AddResult::INVALID;
            }
        }

        // The AMM is a singleton state transition and a pending candidate has
        // already passed the expensive covenant and ML-DSA checks.  Reject a
        // competing candidate before any chain/signature work.  The old path
        // first verified the attacker transaction and then rebuilt/scanned the
        // complete (up to 50k-entry) mempool child graph while holding mutex_,
        // even though the answer was necessarily "slot occupied".  Canonical
        // block commit/reorg cleanup removes stale pending entries; the final
        // locked check below closes the race between this fast path and insert.
        if (amm_parsed.status == AmmOpParseStatus::VALID) {
            std::lock_guard<std::mutex> slot_lock(mutex_);
            if (!pending_amm_tx_.empty()) {
                if (entries_.count(pending_amm_tx_))
                    return AddResult::DOUBLE_SPEND;
                pending_amm_tx_.clear();
            }
        }

        if (!token_replay_key.empty()) {
            std::lock_guard<std::mutex> replay_lock(mutex_);
            auto it = pending_token_replay_counts_.find(token_replay_key);
            if (it != pending_token_replay_counts_.end() && it->second != 0)
                return AddResult::DOUBLE_SPEND;
        }

        {
            std::vector<uint8_t> pool_script = AddressToScript(POOL_ADDRESS);
            if (!pool_script.empty()) {
                for (const auto& inp : tx.inputs) {
                    if (inp.IsCoinbase()) continue;
                    auto u = chain.GetUTXO(inp.prev_tx_hash, inp.prev_out_index);
                    if (u && u->script_pubkey == pool_script) {
                        return AddResult::INVALID;
                    }
                }
            }
            std::vector<uint8_t> sv_script = AddressToScript(STAKE_VAULT_ADDRESS);
            if (!sv_script.empty()) {
                for (const auto& inp : tx.inputs) {
                    if (inp.IsCoinbase()) continue;
                    auto u = chain.GetUTXO(inp.prev_tx_hash, inp.prev_out_index);
                    if (u && u->script_pubkey == sv_script) {
                        return AddResult::INVALID;
                    }
                }
            }
            std::vector<uint8_t> bye_script = AddressToScript(BOND_YIELD_ESCROW);
            if (!bye_script.empty()) {
                for (const auto& inp : tx.inputs) {
                    if (inp.IsCoinbase()) continue;
                    auto u = chain.GetUTXO(inp.prev_tx_hash, inp.prev_out_index);
                    if (u && u->script_pubkey == bye_script) {
                        return AddResult::INVALID;
                    }
                }
            }
            std::vector<uint8_t> vault_script = AddressToScript(VAULT_ADDRESS);
            if (!vault_script.empty()) {
                for (const auto& inp : tx.inputs) {
                    if (inp.IsCoinbase()) continue;
                    auto u = chain.GetUTXO(inp.prev_tx_hash, inp.prev_out_index);
                    if (u && u->script_pubkey == vault_script) {
                        return AddResult::INVALID;
                    }
                }
            }
            std::vector<uint8_t> ep_script = AddressToScript(ENDORSEMENT_POOL_ADDRESS);
            if (!ep_script.empty()) {
                for (const auto& inp : tx.inputs) {
                    if (inp.IsCoinbase()) continue;
                    auto u = chain.GetUTXO(inp.prev_tx_hash, inp.prev_out_index);
                    if (u && u->script_pubkey == ep_script) {
                        return AddResult::INVALID;
                    }
                }
            }

            // Canonical protocol settlements are miner-built and never enter
            // the mempool.  Therefore every admitted transaction is an
            // external funder for output-policy purposes: reject donations to
            // keyless custody pools and require the one canonical REGISTER
            // shape for a stake-vault bond before doing expensive relay work.
            if (!Blockchain::ValidateExternalProtocolCustodyOutputs(
                    tx, (uint64_t)current_height + 1)) {
                return AddResult::INVALID;
            }
        }

        {
            if (!tx.inputs.empty() && !tx.outputs.empty()) {
                auto first_utxo = chain.GetUTXO(
                    tx.inputs[0].prev_tx_hash, tx.inputs[0].prev_out_index);
                if (first_utxo) {
                    const auto& input_script = first_utxo->script_pubkey;
                    bool homogeneous_inputs = true;
                    for (size_t i = 1; i < tx.inputs.size(); ++i) {
                        auto u = chain.GetUTXO(
                            tx.inputs[i].prev_tx_hash, tx.inputs[i].prev_out_index);
                        if (!u || u->script_pubkey != input_script) {
                            homogeneous_inputs = false;
                            break;
                        }
                    }
                    if (homogeneous_inputs) {
                        //  — PRECISE consolidation pattern.
                        // A TRUE self-consolidation is:
                        //   (a) >= 2 inputs            (combining UTXOs;
                        //       a 1-input self-spend is a normal txn, not
                        //       a consolidation)
                        //   (b) ZERO OP_RETURN outputs (an OP_RETURN means
                        //       this is a PROTOCOL tx — ENDORSE / STAKE /
                        //       REGISTER / DEREGISTER / SLASH / GOV-* —
                        //       which legitimately spends from self and
                        //       sends change back to self; NOT a
                        //       consolidation)
                        //   (c) every output goes back to the input script
                        // Earlier the gate skipped OP_RETURN outputs and so
                        // false-matched every smoke ENDORSE tx (1 input +
                        // change-to-self + OP_RETURN) as a "consolidation".
                        // Tightening (a)+(b) removes that whole class of
                        // false positives while still catching the real
                        // runaway-consolidation vector.
                        bool only_self_outputs = true;
                        bool has_any_self_output = false;
                        bool has_op_return       = false;
                        for (const auto& out : tx.outputs) {
                            if (!out.script_pubkey.empty() &&
                                out.script_pubkey[0] == 0x6A) {
                                has_op_return = true;
                                break;
                            }
                            if (out.script_pubkey == input_script) {
                                has_any_self_output = true;
                                continue;
                            }
                            only_self_outputs = false;
                            break;
                        }
                        if (only_self_outputs && has_any_self_output &&
                            !has_op_return && tx.inputs.size() >= 2) {
                            // Two inputs already prove an actual merge.  The old
                            // 200-UTXO floor created an unsatisfiable wallet
                            // state: 25 fragmented PQ inputs cannot fund a
                            // bounded AMM transaction, yet the wallet was also
                            // forbidden to consolidate them.  A self-only merge
                            // pays the normal fee and cannot repeat once one
                            // output remains, so no larger floor is needed.
                            constexpr size_t MIN_UTXOS_TO_CONSOLIDATE = 2;
                            auto utxos_for_addr = chain.GetUTXOsForScript(input_script);
                            std::string from_addr = ScriptToAddress(input_script);
                            const char* decision =
                                (utxos_for_addr.size() < MIN_UTXOS_TO_CONSOLIDATE)
                                    ? "REJECT" : "ACCEPT";
                            std::string op_return_preview;
                            for (const auto& out : tx.outputs) {
                                if (out.script_pubkey.empty() ||
                                    out.script_pubkey[0] != 0x6A) continue;
                                size_t off = 1, len = 0;
                                if (out.script_pubkey.size() < 2) continue;
                                if (out.script_pubkey[off] <= 75) {
                                    len = out.script_pubkey[off++];
                                } else if (out.script_pubkey[off] == 0x4C
                                        && out.script_pubkey.size() > off+1) {
                                    off++; len = out.script_pubkey[off++];
                                } else if (out.script_pubkey[off] == 0x4D
                                        && out.script_pubkey.size() > off+2) {
                                    off++;
                                    len = (size_t)out.script_pubkey[off]
                                        | ((size_t)out.script_pubkey[off+1] << 8);
                                    off += 2;
                                }
                                if (off + len > out.script_pubkey.size()) continue;
                                size_t take = len < 48 ? len : 48;
                                for (size_t k = 0; k < take; ++k) {
                                    char c = (char)out.script_pubkey[off + k];
                                    if (c >= 0x20 && c < 0x7F) op_return_preview += c;
                                    else op_return_preview += '.';
                                }
                                break;
                            }
                            std::cerr << "[self-consolidate] decision=" << decision
                                      << " txid=" << key.substr(0, 16)
                                      << " from=" << (from_addr.empty() ? "?" : from_addr.substr(0, 14))
                                      << " in=" << tx.inputs.size()
                                      << " out=" << tx.outputs.size()
                                      << " utxos=" << utxos_for_addr.size()
                                      << " floor=" << MIN_UTXOS_TO_CONSOLIDATE
                                      << " op_return='" << op_return_preview << "'"
                                      << "\n";
                            std::cerr.flush();
                            if (utxos_for_addr.size() < MIN_UTXOS_TO_CONSOLIDATE) {
                                return AddResult::INVALID;
                            }
                        }
                    }
                }
            }
        }

        std::optional<NmsRecord> nms_rec_for_admission;
        if constexpr (OPTION_B_CONSENSUS_GATE_ENABLED) {
            nms_rec_for_admission = ExtractNmsFromTx(tx);
            if (nms_rec_for_admission) {
                {
                    std::lock_guard<std::mutex> lk(mutex_);
                    if (nms_payload_hashes_.size() >=
                        MAX_NMS_RECORDS_PER_BLOCK) {
                        static uint64_t last_log_ts = 0;
                        uint64_t now_s = (uint64_t)std::time(nullptr);
                        if (now_s - last_log_ts > 10) {
                            last_log_ts = now_s;
                            std::cerr << "  [mempool-nms] reject: NMS quota full ("
                              << nms_payload_hashes_.size()
                                      << "/" << MAX_NMS_RECORDS_PER_BLOCK
                                      << "); reserving slots for payment TXs\n";
                            std::cerr.flush();
                        }
                        return AddResult::FULL;
                    }
                }
                auto miner_script = ExtractNmsMinerScript(tx);
                if (miner_script.empty()) {
                    std::cerr << "  [mempool-nms] reject: miner_script empty\n";
                    std::cerr.flush();
                    return AddResult::INVALID;
                }
                if (chain.NmsPayloadSeen(nms_rec_for_admission->raw)) {
                    std::cerr << "  [mempool-nms] reject: NMS payload "
                              << "already on canonical chain (dedup window)\n";
                    std::cerr.flush();
                    return AddResult::INVALID;
                }
                {
                    std::string new_key = HashToHex(Hash256d(
                        nms_rec_for_admission->raw));
                    std::lock_guard<std::mutex> lk(mutex_);
                    if (nms_payload_hashes_.count(new_key)) {
                        std::cerr << "  [mempool-nms] reject: NMS payload "
                                  << "duplicates an existing mempool entry "
                                  << "(prevents nms_duplicate_in_block at "
                                  << "block validation)\n";
                        std::cerr.flush();
                        return AddResult::INVALID;
                    }
                }
                if (!ValidateNmsMinerIdentity(tx)) {
                    std::cerr << "  [mempool-nms] reject: ValidateNmsMinerIdentity failed\n";
                    std::cerr.flush();
                    return AddResult::INVALID;
                }
                if (!chain.NmsBondSatisfied(miner_script)) {
                    std::cerr << "  [mempool-nms] reject: NmsBondSatisfied false\n";
                    std::cerr.flush();
                    return AddResult::INVALID;
                }
            }
        }

        bool all_inputs_on_chain_pre = true;
        bool token_policy_checked = false;
        {
            bool touches_amm_state =
                amm_parsed.status == AmmOpParseStatus::VALID;
            bool creates_pool_marker = false;
            for (const auto& out : tx.outputs) {
                if (!IsAmmPoolScript(out.script_pubkey)) continue;
                creates_pool_marker = true;
                touches_amm_state = true;
            }
            // A pool-marker output without a parsed AMM operation is guaranteed
            // to be unspendable (only the exact ledger-committed outpoint may use
            // the sigless exemption). Refuse it at policy rather than relaying a
            // permanent burn / future same-block-chain poison.
            if (creates_pool_marker &&
                amm_parsed.status != AmmOpParseStatus::VALID) {
                return AddResult::INVALID;
            }
            for (const auto& input : tx.inputs) {
                if (input.IsCoinbase()) continue;
                auto u = chain.GetUTXO(input.prev_tx_hash, input.prev_out_index);
                if (!u) {
                    all_inputs_on_chain_pre = false;
                    continue;
                }
                if (IsAmmPoolScript(u->script_pubkey))
                    touches_amm_state = true;
            }
            if (all_inputs_on_chain_pre) {
                if (!chain.ValidateTransactionLocking(tx, false)) {
                    std::cerr << "  [mempool] reject: ValidateTransactionLocking failed (sig/script verify)\n";
                    std::cerr.flush();
                    //  #3: remember this txid (permanent sig/value failure) so a
                    // replay is rejected by O(1) lookup above — no re-verify.
                    {
                        std::lock_guard<std::mutex> rl(recently_rejected_mtx_);
                        if (recently_rejected_.insert(key).second) {
                            recently_rejected_fifo_.push_back(key);
                            while (recently_rejected_fifo_.size() > RECENTLY_REJECTED_CAP) {
                                recently_rejected_.erase(recently_rejected_fifo_.front());
                                recently_rejected_fifo_.pop_front();
                            }
                        }
                    }
                    return AddResult::INVALID;
                }
                if (token_family) {
                    if (!chain.ValidateTokenMempoolCandidate(
                            tx, (uint64_t)current_height + 1,
                            chain.ComputeNextBits())) {
                        return AddResult::INVALID;
                    }
                    token_policy_checked = true;
                }
            }
            // The base transaction checker deliberately exempts the CURRENT
            // AMM pool input from signature verification. Close that exemption
            // here with the same pure reserve/LP/token covenant rules used by
            // block validation. State-dependent rejects are not added to the
            // permanent signature-failure cache: a quote can legitimately go
            // stale when the pool advances.
            if (touches_amm_state &&
                !chain.ValidateAmmMempoolCandidate(
                    tx, (uint64_t)chain.Height() + 1)) {
                return AddResult::INVALID;
            }
        }

        // Authenticate every referenced input before entering memory-hard NMS
        // verification.  A peer may name another wallet's public UTXO and
        // forge the cheap miner marker, but it cannot pass the signature check
        // above.  NMS claims are next-block only on fresh mainnet-v2, so stale
        // parents cannot rotate dataset identities.
        if (nms_rec_for_admission) {
            if (!all_inputs_on_chain_pre) return AddResult::MISSING_INPUT;
            const auto nms_validation = chain.ValidateNmsLocking(
                *nms_rec_for_admission,
                static_cast<uint64_t>(current_height) + 1,
                source_pow_budget);
            if (nms_validation != NmsValidationDisposition::Valid) {
                if (nms_validation ==
                        NmsValidationDisposition::DeferredLocalWork) {
                    return AddResult::DEFERRED_LOCAL_WORK;
                }
                std::cerr << "  [mempool-nms] reject: authenticated NMS "
                             "consensus validation failed at current_height="
                          << current_height << " enclosing="
                          << (static_cast<uint64_t>(current_height) + 1) << "\n";
                std::cerr.flush();
                return AddResult::INVALID;
            }
        }

        if (chain.Height() >= BATCH1_HARDENING_HEIGHT &&
            tx.HasDustOutput(DUST_THRESHOLD_UNITS)) {
            std::cerr << "  [mempool] reject: output_below_dust_threshold\n";
            std::cerr.flush();
            return AddResult::INVALID;
        }

        // Prove the immutable TOKEN authorizer before taking the global
        // mempool lock. The stateful callback already requires this, but the
        // local proof makes the later cache sound even if a future embedding
        // accidentally installs an over-permissive callback. The 24-input
        // stateful envelope bounds this one-time work.
        const bool token_authorization_proven =
            token_family && !token_is_mspv && token_op.has_value() &&
            !token_op->from.empty() &&
            TxVerifiedSignedBy(tx, token_op->from);

        std::lock_guard<std::mutex> lock(mutex_);

        // Final authorization linearization point for a locally produced
        // validator transaction.  The VeldNode caller holds Blockchain's
        // consensus-transition guard across this call and the eventual relay,
        // so a canonical/prerequisite transition cannot begin between this
        // claim and the bounded insertion/gossip sink.
        std::shared_ptr<void> work_owner;
        if (work_authorization) {
            work_owner = work_authorization->owner;
            bool claimed = false;
            try { claimed = work_authorization->claim(); }
            catch (...) { claimed = false; }
            bool live = false;
            try { live = claimed && work_authorization->live(); }
            catch (...) { live = false; }
            if (!live) return AddResult::DEFERRED_LOCAL_WORK;
        }

        if (entries_.count(key)) return AddResult::DUPLICATE;

        size_t tx_size = tx.Serialize().size();
        if (tx_size > MAX_RELAY_TX_BYTES) return AddResult::INVALID;
        uint64_t fee_rate = tx_size > 0 ? (fee_units * 1000) / tx_size : 0;
        if (fee_rate < MIN_FEE_RATE) return AddResult::FEE_TOO_LOW;

        // Consensus permits at most one AMM operation per block. Live-pool
        // operations naturally conflict on the committed pool outpoint, but two
        // first-seed candidates have disjoint user inputs and otherwise both fit
        // the empty parent state. Keep one deterministic mempool slot so a miner
        // never assembles a two-seed block that consensus must reject. Before
        // applying the slot, canonical commit/reorg cleanup has already purged
        // any quote/seed invalidated by a chain-state transition.  Keep this
        // final O(1) check under the insertion lock to close the concurrent-
        // arrival race; selection still performs defense-in-depth stateful
        // revalidation for test/imported or unexpectedly stale contents.
        if (amm_parsed.status == AmmOpParseStatus::VALID) {
            if (!pending_amm_tx_.empty() &&
                entries_.count(pending_amm_tx_)) {
                return AddResult::DOUBLE_SPEND;
            }
            if (!pending_amm_tx_.empty()) pending_amm_tx_.clear();
        }

        bool all_inputs_on_chain = true;
        uint64_t resolved_input_total = 0;
        std::unordered_set<std::string> candidate_spends;
        candidate_spends.reserve(tx.inputs.size());
        for (size_t input_index = 0; input_index < tx.inputs.size();
             ++input_index) {
            const auto& input = tx.inputs[input_index];
            if (input.IsCoinbase()) continue;
            std::string spend_key = HashToHex(input.prev_tx_hash)
                                  + ":" + std::to_string(input.prev_out_index);
            // A duplicate input inside one candidate is a double spend too.
            // Checking only spent_outputs_ misses it because that set is not
            // updated until admission completes, and would let value-accounting
            // count the same parent twice in mixed parent/child transactions.
            if (!candidate_spends.insert(spend_key).second)
                return AddResult::DOUBLE_SPEND;
            if (spent_outputs_.count(spend_key))
                return AddResult::DOUBLE_SPEND;
            auto utxo_opt = chain.GetUTXO(input.prev_tx_hash, input.prev_out_index);
            if (utxo_opt) {
                if (utxo_opt->is_coinbase
                    && utxo_opt->block_height >= COINBASE_MATURITY_ACTIVATES_AT_HEIGHT
                    && (uint64_t)current_height >= COINBASE_MATURITY_ACTIVATES_AT_HEIGHT) {
                    uint64_t mined_at = utxo_opt->block_height;
                    if (current_height < mined_at
                        || (uint64_t)current_height - mined_at < COINBASE_MATURITY) {
                        return AddResult::COINBASE_IMMATURE;
                    }
                }
                // Full validation above ran only when every input was already
                // canonical.  In a mixed child, verify this canonical input
                // explicitly; otherwise a valid unconfirmed-parent signature
                // could mask a forged signature for a real UTXO and poison
                // every peer/miner mempool until expiry.
                if (!all_inputs_on_chain_pre) {
                    const auto input_result =
                        chain.ValidateMempoolCanonicalInput(
                            tx, static_cast<uint32_t>(input_index),
                            *utxo_opt);
                    if (input_result == Blockchain::
                            MempoolCanonicalInputResult::MISSING_OR_CHANGED) {
                        return AddResult::MISSING_INPUT;
                    }
                    if (input_result != Blockchain::
                            MempoolCanonicalInputResult::VALID) {
                        return AddResult::INVALID;
                    }
                }
                if (resolved_input_total > UINT64_MAX - utxo_opt->value)
                    return AddResult::INVALID;
                resolved_input_total += utxo_opt->value;
                continue;
            }
            std::string parent_key = HashToHex(input.prev_tx_hash);
            auto pit = entries_.find(parent_key);
            // Re-check under the mempool lock.  A parent observed by the P2P
            // preflight can be confirmed/evicted before Add() acquires this
            // lock; preserving a distinct result closes the TOCTOU path where
            // that harmless orphan race was previously reported as INVALID
            // and charged to the relaying peer's ban score.
            if (pit == entries_.end()) return AddResult::MISSING_INPUT;
            if (input.prev_out_index >= pit->second.tx.outputs.size())
                return AddResult::INVALID;
            {
                const auto& parent_out =
                    pit->second.tx.outputs[input.prev_out_index];
                // The AMM explicitly forbids same-block covenant chaining: only
                // the parent-chain committed pool outpoint may be spent siglessly.
                // Reject a child of an unconfirmed seed/swap here even before the
                // generic script verifier (the pool marker is not a key script).
                if (IsAmmPoolScript(parent_out.script_pubkey))
                    return AddResult::INVALID;
                if (!Blockchain::VerifyInputAgainstScript(
                        tx, static_cast<uint32_t>(input_index),
                        parent_out.script_pubkey)) {
                    return AddResult::INVALID;
                }
                if (resolved_input_total > UINT64_MAX - parent_out.value)
                    return AddResult::INVALID;
                resolved_input_total += parent_out.value;
            }
            all_inputs_on_chain = false;
        }

        // An AMM transaction consumes the node's single state-transition slot.
        // Never let an unmineable child reserve that slot: because consensus
        // forbids same-block parent/child spends, an attacker could otherwise
        // hang a valid AMM operation from an arbitrarily long unconfirmed
        // payment chain and pin every swap/add/remove until the chain confirms
        // one transaction per block (or the 72-hour mempool expiry fires).
        // Ordinary descendants remain supported; stateful AMM callers must
        // retry once every funding input is in the canonical UTXO set.
        if (amm_parsed.status == AmmOpParseStatus::VALID &&
            !all_inputs_on_chain) {
            return AddResult::MISSING_INPUT;
        }

        // Stateful token authorization/balance/replay checks are defined
        // against the canonical parent frame.  Do not admit a TOKEN/MSPV child
        // that depends on an unconfirmed native transaction: it cannot be
        // selected in the same block and could otherwise reserve state for an
        // unbounded parent chain.
        if (token_family && !all_inputs_on_chain)
            return AddResult::MISSING_INPUT;

        // Mempool::Add is also used by local/RPC/reorg paths.  Do not rely on
        // the P2P caller to have performed value conservation for the mixed
        // parent shape.
        if (tx.TotalOutput() > resolved_input_total) return AddResult::INVALID;

        // A parent can confirm between the pre-lock probe and this locked pass.
        // In that race all inputs are now canonical, so run the authoritative
        // whole-transaction checker once instead of relying on per-input checks.
        if (all_inputs_on_chain && !all_inputs_on_chain_pre &&
            !chain.ValidateTransactionLocking(tx, false)) {
            return AddResult::INVALID;
        }
        if (token_family && all_inputs_on_chain && !token_policy_checked &&
            !chain.ValidateTokenMempoolCandidate(
                tx, (uint64_t)current_height + 1,
                chain.ComputeNextBits())) {
            return AddResult::INVALID;
        }
        if (token_family && all_inputs_on_chain && !token_policy_checked)
            token_policy_checked = true;

        // Base input validation proves that every spent outpoint is authorized;
        // protocol authorization additionally proves that the address named by
        // each stake operation actually supplied one of those valid signatures.
        // Verify once per named address even when a transaction carries several
        // LOCK/UNLOCK outputs.
        {
            std::unordered_set<std::string> verified_stakers;
            for (const auto& op : stake_ops) {
                if (!verified_stakers.insert(op.address).second) continue;
                if (!TxVerifiedSignedBy(tx, op.address))
                    return AddResult::INVALID;
            }
        }

        {
            static const std::string REG_PFX   = "VELD_VALIDATOR|REGISTER|";
            static const std::string DEREG_PFX = "VELD_VALIDATOR|DEREGISTER|";
            constexpr size_t PUBKEY_HEX_LEN = 3904;
            auto canonical_lower_hex = [](const std::string& value,
                                          size_t exact_size) {
                if (value.size() != exact_size) return false;
                for (const char c : value) {
                    if (!((c >= '0' && c <= '9') ||
                          (c >= 'a' && c <= 'f'))) return false;
                }
                return true;
            };
            for (const auto& out : tx.outputs) {
                if (out.script_pubkey.empty() || out.script_pubkey[0] != 0x6A) continue;
                size_t offset = 1, len = 0;
                bool canonical_push = true;
                if (out.script_pubkey.size() < 2) continue;
                if (out.script_pubkey[offset] <= 75) {
                    len = out.script_pubkey[offset++];
                } else if (out.script_pubkey[offset] == 0x4C
                        && out.script_pubkey.size() > offset + 1) {
                    offset++;
                    len = out.script_pubkey[offset++];
                    if (len <= 75) canonical_push = false;
                } else if (out.script_pubkey[offset] == 0x4D
                        && out.script_pubkey.size() > offset + 2) {
                    offset++;
                    len = (size_t)out.script_pubkey[offset]
                        | ((size_t)out.script_pubkey[offset+1] << 8);
                    offset += 2;
                    if (len <= 0xFF) canonical_push = false;
                } else if (out.script_pubkey[offset] == 0x4E
                        && out.script_pubkey.size() > offset + 4) {
                    offset++;
                    const uint64_t wide_len =
                        (uint64_t)out.script_pubkey[offset] |
                        ((uint64_t)out.script_pubkey[offset + 1] << 8) |
                        ((uint64_t)out.script_pubkey[offset + 2] << 16) |
                        ((uint64_t)out.script_pubkey[offset + 3] << 24);
                    offset += 4;
                    if (wide_len > SIZE_MAX) continue;
                    len = (size_t)wide_len;
                    canonical_push = false;
                } else {
                    continue;
                }
                if (offset > out.script_pubkey.size() ||
                    len > out.script_pubkey.size() - offset) continue;
                std::string data(out.script_pubkey.begin() + offset,
                                 out.script_pubkey.begin() + offset + len);
                static const std::string SLASH_PFX = "VELD_VALIDATOR|SLASH|";
                const bool validator_marker =
                    data.compare(0, SLASH_PFX.size(), SLASH_PFX) == 0 ||
                    data.compare(0, REG_PFX.size(), REG_PFX) == 0 ||
                    data.compare(0, DEREG_PFX.size(), DEREG_PFX) == 0;
                if (validator_marker &&
                    (!canonical_push || offset + len != out.script_pubkey.size())) {
                    return AddResult::MALFORMED_VALIDATOR_OP;
                }
                if (data.compare(0, SLASH_PFX.size(), SLASH_PFX) == 0) {
                    std::vector<std::string> parts;
                    size_t scan = 0;
                    while (scan <= data.size()) {
                        size_t pipe = data.find('|', scan);
                        size_t end = (pipe == std::string::npos) ? data.size() : pipe;
                        parts.push_back(data.substr(scan, end - scan));
                        if (pipe == std::string::npos) break;
                        scan = pipe + 1;
                    }
                    if (parts.size() != 9) return AddResult::MALFORMED_VALIDATOR_OP;
                    if (!canonical_lower_hex(parts[2], PUBKEY_HEX_LEN))
                        return AddResult::MALFORMED_VALIDATOR_OP;
                    if (!canonical_lower_hex(parts[4], 64) ||
                        !canonical_lower_hex(parts[6], 64))
                        return AddResult::MALFORMED_VALIDATOR_OP;
                    if (parts[4] == parts[6])
                        return AddResult::MALFORMED_VALIDATOR_OP;
                    if (!canonical_lower_hex(parts[5], 6618) ||
                        !canonical_lower_hex(parts[7], 6618) ||
                        parts[5] == parts[7])
                        return AddResult::MALFORMED_VALIDATOR_OP;
                    if (parts[8] != "v1")
                        return AddResult::MALFORMED_VALIDATOR_OP;
                    uint64_t slash_height = 0;
                    if (!ParseCanonicalUint64Text(parts[3], slash_height))
                        return AddResult::MALFORMED_VALIDATOR_OP;
                    continue;
                }
                size_t pfx_len = 0;
                if (data.compare(0, REG_PFX.size(), REG_PFX) == 0) {
                    pfx_len = REG_PFX.size();
                } else if (data.compare(0, DEREG_PFX.size(), DEREG_PFX) == 0) {
                    pfx_len = DEREG_PFX.size();
                } else {
                    continue;
                }
                if (data.size() != pfx_len + PUBKEY_HEX_LEN)
                    return AddResult::MALFORMED_VALIDATOR_OP;
                if (!canonical_lower_hex(data.substr(pfx_len),
                                         PUBKEY_HEX_LEN))
                    return AddResult::MALFORMED_VALIDATOR_OP;
            }
        }

        {
            constexpr uint64_t VALIDATOR_STATE_COOLDOWN = 12;
            uint64_t pos = (uint64_t)current_height % VAULT_DISTRIBUTION_INTERVAL;
            if (pos > VAULT_DISTRIBUTION_INTERVAL - VALIDATOR_STATE_COOLDOWN) {
                static const std::string REG    = "VELD_VALIDATOR|REGISTER|";
                static const std::string DEREG  = "VELD_VALIDATOR|DEREGISTER|";
                for (const auto& out : tx.outputs) {
                    if (out.script_pubkey.empty() || out.script_pubkey[0] != 0x6A)
                        continue;
                    size_t offset = 1, len = 0;
                    if (out.script_pubkey.size() < 2) continue;
                    if (out.script_pubkey[offset] <= 75) {
                        len = out.script_pubkey[offset++];
                    } else if (out.script_pubkey[offset] == 0x4C
                            && out.script_pubkey.size() > offset + 1) {
                        offset++;
                        len = out.script_pubkey[offset++];
                    } else if (out.script_pubkey[offset] == 0x4D
                            && out.script_pubkey.size() > offset + 2) {
                        offset++;
                        len = (size_t)out.script_pubkey[offset]
                            | ((size_t)out.script_pubkey[offset+1] << 8);
                        offset += 2;
                    }
                    if (offset + len > out.script_pubkey.size()) continue;
                    std::string data(out.script_pubkey.begin() + offset,
                                     out.script_pubkey.begin() + offset + len);
                    if (data.compare(0, REG.size(),   REG)   == 0 ||
                        data.compare(0, DEREG.size(), DEREG) == 0) {
                        return AddResult::VALIDATOR_STATE_COOLDOWN;
                    }
                }
            }
        }

        std::unordered_set<std::string> stake_addresses_in_tx;
        for (const auto& op : stake_ops) {
            if (!stake_addresses_in_tx.insert(op.address).second) continue;
            if (pending_stakers_.find(op.address) != pending_stakers_.end())
                return AddResult::STAKE_ALREADY_PENDING;
        }

        std::unordered_map<std::string, uint64_t> tx_running_claims;
        std::unordered_set<std::string> new_stakers_in_tx;
        for (const auto& op : stake_ops) {
            if (op.action != CanonicalStakeOp::Action::LOCK) continue;
            const std::string& staker = op.address;
            const uint64_t claim_units = op.amount_units;

            auto script = AddressToScript(staker);
            if (script.empty()) return AddResult::INVALID;
            uint64_t balance = chain.GetBalance(script);
            uint64_t already_staked = chain.GetStakedForAddr(staker);
            if (already_staked == 0) new_stakers_in_tx.insert(staker);
            if (already_staked > balance) {
                return AddResult::STAKE_EXCEEDS_BALANCE;
            }
            uint64_t headroom = balance - already_staked;
            uint64_t prior_in_tx = tx_running_claims[staker];
            if (prior_in_tx > UINT64_MAX - claim_units) {
                return AddResult::STAKE_EXCEEDS_BALANCE;
            }
            if (prior_in_tx + claim_units > headroom) {
                return AddResult::STAKE_EXCEEDS_BALANCE;
            }
            if (already_staked > MAX_STAKE_UNITS ||
                prior_in_tx > MAX_STAKE_UNITS - already_staked ||
                claim_units > MAX_STAKE_UNITS - already_staked - prior_in_tx) {
                return AddResult::STAKE_EXCEEDS_BALANCE;
            }
            tx_running_claims[staker] = prior_in_tx + claim_units;
        }

        if (!new_stakers_in_tx.empty()) {
            size_t pending_new_stakers = 0;
            for (const auto& [address, _txid] : pending_stakers_) {
                if (chain.GetStakedForAddr(address) == 0)
                    ++pending_new_stakers;
            }
            const size_t active_stakers =
                chain.GetActiveStakeAddressCount();
            if (active_stakers > MAX_VAULT_PAYOUT_STAKERS ||
                pending_new_stakers >
                    MAX_VAULT_PAYOUT_STAKERS - active_stakers ||
                new_stakers_in_tx.size() >
                    MAX_VAULT_PAYOUT_STAKERS - active_stakers -
                    pending_new_stakers) {
                return AddResult::INVALID;
            }
        }

        if (token_family &&
            token_marker_count_ >= MAX_TOKEN_MEMPOOL_ENTRIES)
            return AddResult::FULL;
        // Close the concurrent-arrival race left by the pre-validation fast
        // path. A second transaction for the same Bitcoin deposit is a state
        // conflict, not peer-misbehavior, so report the existing non-bannable
        // DOUBLE_SPEND classification.
        if (!token_replay_key.empty()) {
            auto it = pending_token_replay_counts_.find(token_replay_key);
            if (it != pending_token_replay_counts_.end() && it->second != 0)
                return AddResult::DOUBLE_SPEND;
        }

        // this was a single `if` with one Evict() call.
        // Evict() removes exactly one lowest-fee-rate root plus its descendants,
        // so when the ENTRY-COUNT branch alone satisfied the condition the byte
        // cap was never re-checked before `total_bytes_ +=` below. An attacker
        // fills MAX_TX_COUNT slots with tiny transactions, then replaces them
        // one at a time with MAX_RELAY_TX_BYTES transactions at monotonically
        // increasing fee rates: the count stays pinned at the cap, each cycle
        // nets ~1 MiB, and the real bound becomes MAX_TX_COUNT *
        // MAX_RELAY_TX_BYTES (~50 GB) rather than the intended
        // MAX_MEMPOOL_BYTES. Loop over BOTH caps instead.
        //
        // Termination: every Evict() that returns true strictly decreases
        // total_bytes_ (it returns total_bytes_ < bytes_before) and erases at
        // least one entry, and it returns false as soon as nothing cheaper than
        // the incoming fee rate remains — so the loop always makes progress or
        // exits FULL.
        while (entries_.size() >= MAX_TX_COUNT ||
               total_bytes_ + tx_size > MAX_MEMPOOL_BYTES) {
            // An authorized work item must never evict ordinary transactions
            // after its bounded lease has expired.  The transition guard makes
            // safety closes mutually exclusive; this check covers the lease's
            // independent hard deadline.
            if (work_authorization) {
                bool live = false;
                try { live = work_authorization->live(); }
                catch (...) { live = false; }
                if (!live) return AddResult::DEFERRED_LOCAL_WORK;
            }
            if (!Evict(fee_rate)) return AddResult::FULL;
        }

        if (work_authorization) {
            bool live = false;
            try { live = work_authorization->live(); }
            catch (...) { live = false; }
            if (!live) return AddResult::DEFERRED_LOCAL_WORK;
        }

        MempoolEntry entry(tx, fee_units, current_height);
        entry.had_unconfirmed_parent = !all_inputs_on_chain;
        entry.base_locking_validated = all_inputs_on_chain;
        entry.token_authorization_validated =
            token_family && !token_is_mspv && token_policy_checked &&
            token_authorization_proven;
        total_bytes_ += entry.tx_size_bytes;

        for (const auto& input : tx.inputs) {
            if (input.IsCoinbase()) continue;
            std::string spend_key = HashToHex(input.prev_tx_hash)
                                  + ":" + std::to_string(input.prev_out_index);
            spent_outputs_.insert(spend_key);
            spent_by_tx_.emplace(spend_key, key);
        }

        fee_index_.insert({entry.fee_rate, key});
        entries_[key] = entry;
        if (token_family) ++token_marker_count_;
        if (!token_replay_key.empty())
            ++pending_token_replay_counts_[token_replay_key];

        for (const auto& out : tx.outputs) {
            std::string staker = ExtractStakeAddress(out.script_pubkey);
            if (!staker.empty()) pending_stakers_[staker] = key;
        }

        if (amm_parsed.status == AmmOpParseStatus::VALID)
            pending_amm_tx_ = key;

        if (auto admitted_nms = ExtractNmsFromTx(tx); admitted_nms) {
            nms_payload_hashes_.insert(HashToHex(Hash256d(admitted_nms->raw)));
        }

        return AddResult::ACCEPTED;
    }

public:

    void RemoveConfirmed(const Block& block) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& tx : block.transactions) {
            RemoveInternal(HashToHex(tx.GetTxID()));
        }
    }

    template <typename UtxoCheckFn>
    size_t PurgeInvalidAgainst(UtxoCheckFn utxo_exists) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::unordered_map<std::string, std::vector<std::string>> children;
        children.reserve(entries_.size());
        std::unordered_set<std::string> dead;
        dead.reserve(entries_.size() / 4 + 1);

        for (const auto& kv : entries_) {
            const Transaction& tx = kv.second.tx;
            // Coinbase transactions are never valid public-mempool entries.
            // Admission rejects them, but old/imported/test state must not be
            // able to survive a reorg sweep and remain GETDATA-relayable.
            bool invalid = !tx.IsValid() || tx.IsCoinbase();
            for (const auto& inp : tx.inputs) {
                if (invalid) break;
                std::string parent_key = HashToHex(inp.prev_tx_hash);
                auto parent = entries_.find(parent_key);
                if (parent != entries_.end()) {
                    children[parent_key].push_back(kv.first);
                    // A matching txid is not enough: a legacy/corrupt child may
                    // name an output that the in-mempool parent never created.
                    // Treat it as the invalid root of its own descendant tree.
                    if (inp.prev_out_index >= parent->second.tx.outputs.size())
                        invalid = true;
                    continue;
                }
                if (!utxo_exists(inp.prev_tx_hash, inp.prev_out_index)) {
                    invalid = true;
                    break;
                }
            }
            if (invalid) dead.insert(kv.first);
        }

        // Reorg invalidation is transitive.  Removing only a stale root leaves
        // each in-mempool child looking locally connected until the next
        // periodic sweep, during which it can still be advertised to peers.
        std::vector<std::string> stack(dead.begin(), dead.end());
        while (!stack.empty()) {
            std::string parent = std::move(stack.back());
            stack.pop_back();
            auto it = children.find(parent);
            if (it == children.end()) continue;
            for (const auto& child : it->second) {
                if (dead.insert(child).second) stack.push_back(child);
            }
        }
        for (const auto& key : dead) RemoveInternal(key);

        if (!dead.empty()) {
            std::cerr << "  [mempool-purge] dropped " << dead.size()
                      << " stale TX(s) (inputs no longer in UTXO set after "
                      << "chain-state change); kept " << entries_.size()
                      << "\n";
            std::cerr.flush();
        }
        return dead.size();
    }

    std::vector<Transaction> GetAllTransactions() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<Transaction> out;
        out.reserve(entries_.size());
        for (auto it = fee_index_.rbegin(); it != fee_index_.rend(); ++it) {
            auto e = entries_.find(it->second);
            if (e != entries_.end()) out.push_back(e->second.tx);
        }
        return out;
    }

    std::vector<Transaction> GetBlockTransactions(
        size_t max_count = MAX_TRANSACTIONS_PER_BLOCK,
        size_t max_bytes = MAX_BLOCK_SIZE,
        const Blockchain* chain = nullptr
    ) {
        std::lock_guard<std::mutex> lock(mutex_);

        // Defense in depth for entries admitted by an older binary, a test
        // injector, or an AMM quote that became stale after a canonical state
        // change. Never hand a known block-invalid covenant spend to a miner.
        // Template construction must revalidate the singleton AMM covenant,
        // but TOKEN/MSPV requests are checked together against one token-state
        // snapshot by SelectBlockEntryKeysLocked().  Revalidating every token
        // here would copy the full ledger and verify signatures once per entry,
        // then repeat the same work in the resource-aware selector.
        if (chain) PurgeInvalidAmmEntriesLocked(*chain,
                                               /*validate_tokens=*/false);

        std::vector<Transaction> result;
        auto keys = SelectBlockEntryKeysLocked(max_count, max_bytes, chain);
        result.reserve(keys.size());
        for (const auto& key : keys) result.push_back(entries_.at(key).tx);

        return result;
    }

    void ForEachDiagnostic(std::function<void(const std::string&, const Transaction&)> fn) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [k, e] : entries_) fn(k, e.tx);
    }

    std::optional<Transaction> GetTransaction(const std::string& txid_hex) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = entries_.find(txid_hex);
        if (it == entries_.end()) return std::nullopt;
        return it->second.tx;
    }

    // O(1) exact lookup for the unique mempool transaction spending an
    // outpoint. Admission enforces uniqueness; verify both the mapped txid and
    // the transaction input before exposing bytes to security-critical callers.
    std::optional<Transaction> GetSpender(const Hash256& prev_tx_hash,
                                          uint32_t prev_out_index) const {
        std::lock_guard<std::mutex> lock(mutex_);
        const std::string spend_key = HashToHex(prev_tx_hash) + ":" +
                                      std::to_string(prev_out_index);
        auto sit = spent_by_tx_.find(spend_key);
        if (sit == spent_by_tx_.end()) return std::nullopt;
        auto eit = entries_.find(sit->second);
        if (eit == entries_.end() ||
            HashToHex(eit->second.tx.GetTxID()) != sit->second) {
            return std::nullopt;
        }
        for (const auto& input : eit->second.tx.inputs) {
            if (!input.IsCoinbase() && input.prev_tx_hash == prev_tx_hash &&
                input.prev_out_index == prev_out_index) {
                return eit->second.tx;
            }
        }
        return std::nullopt;
    }

    std::optional<std::pair<uint64_t, size_t>> GetFeeAndSize(const std::string& txid_hex) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = entries_.find(txid_hex);
        if (it == entries_.end()) return std::nullopt;
        return std::make_pair(it->second.fee_units, it->second.tx_size_bytes);
    }

    std::vector<std::pair<Transaction, uint64_t>> GetBlockTransactionsWithFees(
        size_t max_count = MAX_TRANSACTIONS_PER_BLOCK,
        size_t max_bytes = MAX_BLOCK_SIZE,
        const Blockchain* chain = nullptr
    ) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (chain) PurgeInvalidAmmEntriesLocked(*chain,
                                               /*validate_tokens=*/false);

        std::vector<std::pair<Transaction, uint64_t>> result;
        auto keys = SelectBlockEntryKeysLocked(max_count, max_bytes, chain);
        result.reserve(keys.size());
        for (const auto& key : keys) {
            const auto& entry = entries_.at(key);
            result.push_back({entry.tx, entry.fee_units});
        }

        return result;
    }

    size_t RemoveStale(const Blockchain& chain) {
        std::lock_guard<std::mutex> lock(mutex_);
        const size_t removed_amm = PurgeInvalidAmmEntriesLocked(chain);
        std::unordered_map<std::string, std::vector<std::string>> children;
        children.reserve(entries_.size());
        std::unordered_set<std::string> dead;
        dead.reserve(entries_.size() / 4 + 1);
        const uint64_t current_tip = chain.Height();

        for (auto& [key, entry] : entries_) {
            uint64_t input_total = 0;
            // A coinbase is consensus-valid only inside a block and can never
            // be a public mempool root.  This also cleans legacy/imported state
            // that predates the admission guard.
            bool invalid = !entry.tx.IsValid() || entry.tx.IsCoinbase();
            bool all_inputs_now_canonical = true;
            for (const auto& inp : entry.tx.inputs) {
                if (inp.IsCoinbase()) continue;
                uint64_t value = 0;
                auto chain_utxo = chain.GetUTXO(inp.prev_tx_hash, inp.prev_out_index);
                if (chain_utxo) {
                    value = chain_utxo->value;
                    // A shorter higher-work reorg can make a previously mature
                    // coinbase immature again.  Root entries also need this
                    // contextual recheck; otherwise they remain selectable and
                    // make the finished block fail after PoW.
                    if (chain_utxo->is_coinbase &&
                        chain_utxo->block_height >=
                            COINBASE_MATURITY_ACTIVATES_AT_HEIGHT &&
                        current_tip >= COINBASE_MATURITY_ACTIVATES_AT_HEIGHT &&
                        (current_tip < chain_utxo->block_height ||
                         current_tip - chain_utxo->block_height < COINBASE_MATURITY)) {
                        invalid = true;
                        break;
                    }
                } else {
                    all_inputs_now_canonical = false;
                    std::string parent_key = HashToHex(inp.prev_tx_hash);
                    auto parent = entries_.find(parent_key);
                    if (parent == entries_.end() ||
                        inp.prev_out_index >= parent->second.tx.outputs.size()) {
                        invalid = true;
                        break;
                    }
                    children[parent_key].push_back(key);
                    value = parent->second.tx.outputs[inp.prev_out_index].value;
                }
                if (value > UINT64_MAX - input_total) {
                    invalid = true;
                    break;
                }
                input_total += value;
            }
            if (!invalid && !entry.tx.IsCoinbase() &&
                input_total < entry.tx.TotalOutput()) invalid = true;
            // Entries admitted through an unconfirmed parent were checked
            // input-by-input.  Once every parent is canonical, perform the same
            // full validation a fresh root admission receives.  This purges any
            // invalid mixed-input entry instead of letting it become a
            // permanent mining candidate after its parent confirms.
            if (!invalid && all_inputs_now_canonical) {
                if (entry.base_locking_validated) {
                    if (!chain.ValidateCachedMempoolLockingContext(entry.tx))
                        invalid = true;
                } else if (entry.had_unconfirmed_parent) {
                    if (!chain.ValidateTransactionLocking(entry.tx, false)) {
                        invalid = true;
                    } else {
                        entry.base_locking_validated = true;
                    }
                }
            }
            if (invalid) dead.insert(key);
        }

        // If a parent is invalid, every descendant is invalid too.  Removing
        // only the root left a one-tick orphan that was still advertised to
        // peers and could trigger their old tx_input_invalid banscore path.
        std::vector<std::string> stack(dead.begin(), dead.end());
        while (!stack.empty()) {
            std::string parent = std::move(stack.back());
            stack.pop_back();
            auto it = children.find(parent);
            if (it == children.end()) continue;
            for (const auto& child : it->second) {
                if (dead.insert(child).second) stack.push_back(child);
            }
        }
        for (const auto& key : dead) RemoveInternal(key);
        return removed_amm + dead.size();
    }

    size_t SweepOrphans(const Blockchain& chain) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::unordered_map<std::string, std::vector<std::string>> children;
        children.reserve(entries_.size());
        std::vector<std::string> roots;

        for (const auto& [key, entry] : entries_) {
            for (const auto& inp : entry.tx.inputs) {
                if (inp.IsCoinbase()) continue;
                std::string parent_hex = HashToHex(inp.prev_tx_hash);
                if (entries_.count(parent_hex)) {
                    children[parent_hex].push_back(key);
                    continue;
                }
                // Parent is NOT in the mempool. If the chain doesn't
                // have the UTXO either, this TX is an orphan root.
                if (!chain.GetUTXO(inp.prev_tx_hash, inp.prev_out_index)) {
                    roots.push_back(key);
                    break;
                }
            }
        }

        std::unordered_set<std::string> dead;
        std::vector<std::string> stack = std::move(roots);
        while (!stack.empty()) {
            std::string k = std::move(stack.back());
            stack.pop_back();
            if (!dead.insert(k).second) continue;
            auto it = children.find(k);
            if (it != children.end()) {
                for (const auto& child : it->second) {
                    if (!dead.count(child)) stack.push_back(child);
                }
            }
        }

        for (const auto& key : dead) RemoveInternal(key);
        return dead.size();
    }

    size_t ExpireOld() {
        std::lock_guard<std::mutex> lock(mutex_);
        uint64_t now = (uint64_t)std::time(nullptr);

        std::vector<std::string> to_remove;
        for (const auto& [key, entry] : entries_) {
            // Wall-clock rollback must not underflow and instantly expire an
            // entry whose recorded admission time is now in the future.
            if (now >= entry.added_time &&
                now - entry.added_time > TX_EXPIRY_SECONDS)
                to_remove.push_back(key);
        }

        // A child cannot remain relayable after its unconfirmed parent ages
        // out.  Remove the complete closure in this same critical section so
        // GETDATA/INV readers never observe a parentless intermediate graph.
        return RemoveWithDescendantsInternal(to_remove);
    }

    std::optional<MempoolEntry> Get(const Hash256& txid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = entries_.find(HashToHex(txid));
        if (it == entries_.end()) return std::nullopt;
        return it->second;
    }

    // Resolve a candidate's input value across the canonical UTXO set and the
    // current mempool graph.  This is an advisory fee calculation for reorg/P2P
    // callers; Add() always repeats authoritative existence, uniqueness, value,
    // and signature checks under its admission lock.
    std::optional<uint64_t> ResolveInputTotal(
        const Transaction& tx, const Blockchain& chain) const {
        if (tx.IsCoinbase()) return std::nullopt;
        uint64_t total = 0;
        for (const auto& inp : tx.inputs) {
            if (inp.IsCoinbase()) return std::nullopt;
            uint64_t value = 0;
            auto canonical = chain.GetUTXO(inp.prev_tx_hash,
                                           inp.prev_out_index);
            if (canonical) {
                value = canonical->value;
            } else {
                auto parent = Get(inp.prev_tx_hash);
                if (!parent ||
                    inp.prev_out_index >= parent->tx.outputs.size())
                    return std::nullopt;
                value = parent->tx.outputs[inp.prev_out_index].value;
            }
            if (value > UINT64_MAX - total) return std::nullopt;
            total += value;
        }
        return total;
    }

    bool Contains(const Hash256& txid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.count(HashToHex(txid)) > 0;
    }

    size_t   Size()       const { std::lock_guard<std::mutex> l(mutex_); return entries_.size(); }
    size_t   Bytes()      const { std::lock_guard<std::mutex> l(mutex_); return total_bytes_; }
    bool     IsEmpty()    const { return Size() == 0; }

    std::vector<std::string> GetTxIds() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> out;
        out.reserve(entries_.size());
        for (const auto& [key, entry] : entries_) out.push_back(key);
        return out;
    }

    std::string GetInfo() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string info;
        info += "Mempool txs:   " + std::to_string(entries_.size()) + "\n";
        info += "Mempool bytes: " + std::to_string(total_bytes_ / 1024) + " KB\n";
        info += "Min fee rate:  " + std::to_string(MIN_FEE_RATE) + " units/byte\n";
        if (!fee_index_.empty()) {
            info += "Lowest rate:   " + std::to_string(fee_index_.begin()->first) + "\n";
            info += "Highest rate:  " + std::to_string(fee_index_.rbegin()->first) + "\n";
        }
        return info;
    }

private:
    // Revalidate AMM and TOKEN/MSPV entries against the exact current parent
    // modules, remove every invalid root and its descendants, and enforce the
    // one-AMM-op candidate policy for legacy/unchecked mempool contents. Caller
    // holds mutex_. Ordinary payments never invoke a stateful callback.
    size_t PurgeInvalidAmmEntriesLocked(const Blockchain& chain,
                                        bool validate_tokens = true) {
        if (entries_.empty()) {
            pending_amm_tx_.clear();
            return 0;
        }

        std::unordered_map<std::string, std::vector<std::string>> children;
        children.reserve(entries_.size());
        for (const auto& [key, entry] : entries_) {
            for (const auto& inp : entry.tx.inputs) {
                if (inp.IsCoinbase()) continue;
                const std::string parent = HashToHex(inp.prev_tx_hash);
                if (entries_.count(parent)) children[parent].push_back(key);
            }
        }

        std::unordered_set<std::string> dead;
        dead.reserve(entries_.size() / 8 + 1);
        std::string retained_amm;
        const uint64_t next_height = (uint64_t)chain.Height() + 1;
        const uint32_t next_bits = chain.ComputeNextBits();
        std::vector<std::string> token_validation_keys;
        std::vector<Transaction> token_validation_txs;
        std::vector<bool> token_validation_authorized;
        if (validate_tokens) {
            token_validation_keys.reserve(token_marker_count_);
            token_validation_txs.reserve(token_marker_count_);
            token_validation_authorized.reserve(token_marker_count_);
        }

        // Fee order matches block selection. If an old/unchecked mempool holds
        // multiple individually-valid pre-seed candidates, retain only the one
        // the miner would otherwise choose first.
        for (auto fit = fee_index_.rbegin(); fit != fee_index_.rend(); ++fit) {
            const std::string& key = fit->second;
            auto eit = entries_.find(key);
            if (eit == entries_.end()) continue;
            const Transaction& tx = eit->second.tx;
            const AmmOpParseResult parsed = ParseAmmOpDetailed(tx);
            bool token_family = false, token_is_mspv = false;
            std::optional<TokenOpData> token_op;
            const bool token_shape_ok = ExtractCanonicalTokenMarker(
                tx, token_family, token_op, token_is_mspv);

            bool invalid = parsed.status == AmmOpParseStatus::INVALID ||
                           (token_family && !token_shape_ok) ||
                           (token_family &&
                            !TokenTransactionEnvelopeWithinBounds(
                                tx, eit->second.tx_size_bytes)) ||
                           TxComposesMultipleProtocols(tx) ||
                           TxHasInvalidTokenMarkerSet(tx);
            bool touches = parsed.status == AmmOpParseStatus::VALID;
            bool all_inputs_canonical = true;
            bool has_pool_output = false;
            for (const auto& out : tx.outputs) {
                if (!IsAmmPoolScript(out.script_pubkey)) continue;
                has_pool_output = true;
                touches = true;
            }
            if (has_pool_output &&
                parsed.status != AmmOpParseStatus::VALID) {
                invalid = true;
            }

            for (const auto& inp : tx.inputs) {
                if (inp.IsCoinbase()) continue;
                auto u = chain.GetUTXO(inp.prev_tx_hash,
                                       inp.prev_out_index);
                if (u) {
                    if (IsAmmPoolScript(u->script_pubkey)) touches = true;
                    continue;
                }
                all_inputs_canonical = false;
                auto pit = entries_.find(HashToHex(inp.prev_tx_hash));
                if (pit == entries_.end() ||
                    inp.prev_out_index >= pit->second.tx.outputs.size()) {
                    continue; // generic stale/orphan sweep owns this case
                }
                if (IsAmmPoolScript(
                        pit->second.tx.outputs[inp.prev_out_index]
                            .script_pubkey)) {
                    // Same-block AMM covenant chaining is consensus-forbidden.
                    touches = true;
                    invalid = true;
                }
            }

            if (!invalid && touches &&
                (!chain.ValidateTransactionLocking(tx, false) ||
                 !chain.ValidateAmmMempoolCandidate(
                    tx, next_height))) {
                invalid = true;
            }

            // A token request that was valid when admitted may become stale
            // after a confirmed transfer, redeem, mint, SPV replay, AMM debit,
            // or reorg. Verify immutable base locking now, then replay all
            // surviving TOKEN/MSPV requests together against one isolated
            // parent-state snapshot below. The old per-entry callback copied
            // the complete token ledger once for every mempool entry.
            if (!invalid && token_family && all_inputs_canonical) {
                const bool base_ok = eit->second.base_locking_validated
                    ? chain.ValidateCachedMempoolLockingContext(tx)
                    : chain.ValidateTransactionLocking(tx, false);
                if (!base_ok) {
                    invalid = true;
                } else if (validate_tokens) {
                    token_validation_keys.push_back(key);
                    token_validation_txs.push_back(tx);
                    token_validation_authorized.push_back(
                        eit->second.token_authorization_validated);
                }
            }

            if (!invalid && parsed.status == AmmOpParseStatus::VALID) {
                if (retained_amm.empty()) retained_amm = key;
                else invalid = true;
            }
            if (invalid) dead.insert(key);
        }

        if (validate_tokens && !token_validation_txs.empty()) {
            const auto accepted = chain.FilterTokenMempoolCandidates(
                token_validation_txs, token_validation_authorized,
                next_height, next_bits);
            if (accepted.size() != token_validation_keys.size()) {
                // Missing/malformed node wiring is a fail-closed condition for
                // stateful requests; ordinary payments remain unaffected.
                dead.insert(token_validation_keys.begin(),
                            token_validation_keys.end());
            } else {
                for (size_t i = 0; i < accepted.size(); ++i) {
                    if (!accepted[i]) dead.insert(token_validation_keys[i]);
                }
            }
        }

        std::vector<std::string> stack(dead.begin(), dead.end());
        while (!stack.empty()) {
            std::string parent = std::move(stack.back());
            stack.pop_back();
            auto it = children.find(parent);
            if (it == children.end()) continue;
            for (const auto& child : it->second) {
                if (dead.insert(child).second) stack.push_back(child);
            }
        }

        const size_t removed = dead.size();
        for (const auto& key : dead) RemoveInternal(key);

        pending_amm_tx_.clear();
        if (!retained_amm.empty() && entries_.count(retained_amm)) {
            pending_amm_tx_ = retained_amm;
        } else {
            // Defensive rebuild for a retained entry reached outside fee_index_
            // (should be impossible, but keeps the slot fail-safe after a
            // malformed test/import frame).
            for (const auto& [key, entry] : entries_) {
                if (ParseAmmOpDetailed(entry.tx).status ==
                    AmmOpParseStatus::VALID) {
                    pending_amm_tx_ = key;
                    break;
                }
            }
        }
        return removed;
    }

    // Select a valid dependency-ordered view.  Without a chain argument this
    // can expose parent then child for diagnostics.  With a chain argument it
    // returns only canonical-input roots: current block consensus does not
    // permit same-block parent/child spends, so miners/templates/relay-root
    // inventory must withhold a child until its parent confirms.  Missing or
    // malformed roots are never emitted in either mode.
    std::vector<std::string> SelectBlockEntryKeysLocked(
        size_t max_count, size_t max_bytes, const Blockchain* chain) const
    {
        std::vector<std::string> result;
        if (max_count == 0 || max_bytes == 0) return result;

        // Determine whether the singleton AMM transition would reserve one
        // user's parent-frame btcVELD balance.  The reservation becomes active
        // only if the AMM itself fits this caller's count/byte budget.
        std::string pending_amm_token_user;
        if (chain && !pending_amm_tx_.empty()) {
            auto ait = entries_.find(pending_amm_tx_);
            if (ait != entries_.end()) {
                const AmmOpParseResult ap = ParseAmmOpDetailed(ait->second.tx);
                if (ap.status == AmmOpParseStatus::VALID &&
                    (ap.op.action == "SWAP_B2V" || ap.op.action == "ADD"))
                    pending_amm_token_user = ap.op.user;
            }
        }

        std::unordered_set<std::string> selected;
        size_t bytes = 0;

        auto try_select = [&](const std::string& key) -> bool {
            if (selected.count(key)) return false;
            auto entry_it = entries_.find(key);
            if (entry_it == entries_.end()) return false;

            const MempoolEntry& entry = entry_it->second;
            if (bytes > max_bytes ||
                entry.tx_size_bytes > max_bytes - bytes) return false;

            bool ready = true;
            bool invalid = false;
            for (const auto& inp : entry.tx.inputs) {
                if (inp.IsCoinbase()) continue;
                if (chain && chain->GetUTXO(inp.prev_tx_hash,
                                           inp.prev_out_index)) continue;

                const std::string parent_key = HashToHex(inp.prev_tx_hash);
                auto parent = entries_.find(parent_key);
                if (parent == entries_.end()) {
                    // Without a chain view the caller explicitly accepts
                    // responsibility for external inputs. With one, this is an
                    // orphan/stale root and must remain unselected.
                    if (chain) invalid = true;
                    continue;
                }
                if (inp.prev_out_index >= parent->second.tx.outputs.size()) {
                    invalid = true;
                    break;
                }
                // Current consensus validates every non-coinbase input against
                // the parent-chain UTXO set; it does not permit a same-block
                // parent/child spend. A chain-aware caller is a
                // miner/template/relay-root selector, so withhold the child
                // until its parent confirms. The nullptr diagnostic path can
                // still return a dependency-ordered package.
                if (chain) ready = false;
                else if (!selected.count(parent_key)) ready = false;
            }
            if (invalid || !ready) return false;
            if (chain) {
                const bool locking_ok = entry.base_locking_validated
                    ? chain->ValidateCachedMempoolLockingContext(entry.tx)
                    : chain->ValidateTransactionLocking(entry.tx, false);
                if (!locking_ok) return false;
            }

            result.push_back(key);
            selected.insert(key);
            bytes += entry.tx_size_bytes;
            return true;
        };

        // The AMM is a launch-live singleton state machine: one pending
        // transition reserves every later swap/add/remove candidate until the
        // parent pool outpoint advances. Pure fee ordering allowed a valid
        // low-rate AMM transaction to sit below an ordinary >999-entry backlog
        // while continuing to own that singleton slot for up to 72 hours.
        // Reserve one honest-miner/template position for the already fully
        // validated, canonical-input AMM root. This is ordering policy only;
        // PurgeInvalidAmmEntriesLocked() runs before every chain-aware call and
        // consensus still permits at most one AMM operation in the block.
        bool amm_selected = false;
        if (chain && !pending_amm_tx_.empty()) {
            amm_selected = try_select(pending_amm_tx_);
        }

        if (chain) {
            const std::string reserved_amm_token_user = amm_selected
                ? pending_amm_token_user : std::string{};
            std::vector<std::string> candidate_keys;
            std::vector<const Transaction*> candidate_txs;
            std::vector<size_t> candidate_sizes;
            std::vector<bool> candidate_is_token;
            std::vector<bool> candidate_token_authorized;
            candidate_keys.reserve(entries_.size());
            candidate_txs.reserve(entries_.size());
            candidate_sizes.reserve(entries_.size());
            candidate_is_token.reserve(entries_.size());
            candidate_token_authorized.reserve(entries_.size());

            for (auto fit = fee_index_.rbegin(); fit != fee_index_.rend(); ++fit) {
                const std::string& key = fit->second;
                if (selected.count(key)) continue;
                auto eit = entries_.find(key);
                if (eit == entries_.end()) continue;

                // A chain-aware template may include only canonical-input
                // roots; same-block native parent/child spends are consensus-
                // forbidden.  Pre-filter them before the one token-state pass.
                bool canonical_root = true;
                for (const auto& inp : eit->second.tx.inputs) {
                    if (inp.IsCoinbase()) continue;
                    if (!chain->GetUTXO(inp.prev_tx_hash,
                                        inp.prev_out_index)) {
                        canonical_root = false;
                        break;
                    }
                }
                if (!canonical_root) continue;
                const bool locking_ok = eit->second.base_locking_validated
                    ? chain->ValidateCachedMempoolLockingContext(
                          eit->second.tx)
                    : chain->ValidateTransactionLocking(eit->second.tx,
                                                        false);
                if (!locking_ok) continue;

                bool is_token = false, is_mspv = false;
                std::optional<TokenOpData> op;
                if (!ExtractCanonicalTokenMarker(eit->second.tx, is_token,
                                                 op, is_mspv))
                    continue;
                if (!reserved_amm_token_user.empty() && op &&
                    op->token_id == BTCVELD_TOKEN_ID &&
                    op->from == reserved_amm_token_user &&
                    (op->action == "TRANSFER" ||
                     op->action == "REDEEM"))
                    continue;

                candidate_keys.push_back(key);
                candidate_txs.push_back(&eit->second.tx);
                candidate_sizes.push_back(eit->second.tx_size_bytes);
                candidate_is_token.push_back(is_token);
                candidate_token_authorized.push_back(
                    is_token &&
                    eit->second.token_authorization_validated);
            }

            const auto choose = chain->SelectTokenAwareMempoolCandidates(
                candidate_txs, candidate_sizes, candidate_is_token,
                candidate_token_authorized,
                result.size(), bytes, max_count, max_bytes,
                (uint64_t)chain->Height() + 1, chain->ComputeNextBits());
            if (choose.size() != candidate_keys.size()) return result;
            for (size_t i = 0; i < choose.size(); ++i) {
                if (!choose[i]) continue;
                result.push_back(candidate_keys[i]);
                selected.insert(candidate_keys[i]);
                bytes += candidate_sizes[i];
            }
            return result;
        }

        bool progressed = true;

        while (progressed && result.size() < max_count) {
            progressed = false;
            for (auto it = fee_index_.rbegin(); it != fee_index_.rend(); ++it) {
                const std::string& key = it->second;
                if (!try_select(key)) continue;
                progressed = true;
                if (result.size() >= max_count || bytes >= max_bytes) break;
            }
        }
        return result;
    }

    mutable std::mutex mutex_;
    std::unordered_map<std::string, MempoolEntry> entries_;
    std::unordered_set<std::string> nms_payload_hashes_;
    std::unordered_map<std::string, std::string> pending_stakers_;
    std::string                                   pending_amm_tx_;
    std::multimap<uint64_t, std::string>          fee_index_;
    std::unordered_set<std::string>               spent_outputs_;
    // Canonical outpoint key -> unique mempool spender txid. This mirrors
    // spent_outputs_ but makes watchtower/recovery lookup independent of the
    // bounded-yet-large 50,000-transaction diagnostic enumeration path.
    std::unordered_map<std::string, std::string>  spent_by_tx_;
    size_t                                         token_marker_count_ = 0;
    std::unordered_map<std::string, size_t>         pending_token_replay_counts_;
    // #3: recently-rejected tx-hash cache. A tx that
    // failed a hard, tx-INTRINSIC mempool check (signature / value conservation)
    // is remembered by txid so a replay is rejected by O(1) lookup with no
    // re-verification. Only permanent failures are cached (never a transient
    // "input not yet present"), so a tx that could later become valid is not
    // poisoned.
    static constexpr size_t RECENTLY_REJECTED_CAP = 16384;
    mutable std::mutex                            recently_rejected_mtx_;
    std::unordered_set<std::string>               recently_rejected_;
    std::deque<std::string>                       recently_rejected_fifo_;
public:
    std::unordered_set<std::string> GetSpentOutputs() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return spent_outputs_;
    }

    std::vector<UTXO> GetPendingOutputsForScript(
        const std::vector<uint8_t>& script) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<UTXO> out;
        for (const auto& [txid_hex, entry] : entries_) {
            const Transaction& tx = entry.tx;
            Hash256 txid = tx.GetTxID();
            for (uint32_t i = 0; i < tx.outputs.size(); ++i) {
                const TxOutput& o = tx.outputs[i];
                if (o.value == 0) continue;
                if (!o.script_pubkey.empty() && o.script_pubkey[0] == 0x6A) continue;
                if (o.script_pubkey != script) continue;
                std::string key = HashToHex(txid) + ":" + std::to_string(i);
                if (spent_outputs_.count(key)) continue;
                UTXO u;
                u.tx_hash = txid;
                u.output_index = i;
                u.value = o.value;
                u.script_pubkey = o.script_pubkey;
                u.block_height = 0;
                out.push_back(u);
            }
        }
        return out;
    }

    bool HasPendingOpReturn(const std::string& prefix) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [key, entry] : entries_) {
            for (const auto& out : entry.tx.outputs) {
                if (out.script_pubkey.empty() || out.script_pubkey[0] != 0x6A) continue;
                size_t offset = 1; size_t len = 0;
                if (out.script_pubkey.size() < 2) continue;
                if (out.script_pubkey[offset] <= 75) { len = out.script_pubkey[offset++]; }
                else if (out.script_pubkey[offset] == 0x4C && out.script_pubkey.size() > offset+1) {
                    offset++; len = out.script_pubkey[offset++];
                }
                else if (out.script_pubkey[offset] == 0x4D && out.script_pubkey.size() > offset+2) {
                    offset++;
                    len = (size_t)out.script_pubkey[offset]
                        | ((size_t)out.script_pubkey[offset+1] << 8);
                    offset += 2;
                }
                if (offset + len > out.script_pubkey.size()) continue;
                std::string data(out.script_pubkey.begin()+offset,
                                 out.script_pubkey.begin()+offset+len);
                if (data.find(prefix) == 0) return true;
            }
        }
        return false;
    }

    uint64_t GetPendingStakeUnits(const std::string& address) const {
        std::lock_guard<std::mutex> lock(mutex_);
        uint64_t total = 0;
        for (const auto& [key, entry] : entries_) {
            for (const auto& out : entry.tx.outputs) {
                if (out.script_pubkey.empty() || out.script_pubkey[0] != 0x6A) continue;
                size_t offset = 1;
                size_t len = 0;
                if (out.script_pubkey.size() < 2) continue;
                if (out.script_pubkey[offset] <= 75) { len = out.script_pubkey[offset++]; }
                else if (out.script_pubkey[offset] == 0x4C && out.script_pubkey.size() > offset+1) {
                    offset++; len = out.script_pubkey[offset++];
                }
                else if (out.script_pubkey[offset] == 0x4D && out.script_pubkey.size() > offset+2) {
                    offset++;
                    len = (size_t)out.script_pubkey[offset]
                        | ((size_t)out.script_pubkey[offset+1] << 8);
                    offset += 2;
                }
                if (offset + len > out.script_pubkey.size()) continue;
                std::string data(out.script_pubkey.begin()+offset,
                                 out.script_pubkey.begin()+offset+len);
                CanonicalStakeOp op;
                if (!ParseCanonicalStakeOp(data, op) ||
                    op.action != CanonicalStakeOp::Action::LOCK ||
                    op.address != address) continue;
                if (total > UINT64_MAX - op.amount_units) return UINT64_MAX;
                total += op.amount_units;
            }
        }
        return total;
    }
    void Remove(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        RemoveInternal(key);
    }

#ifdef VELD_TESTING
    // Regression-only hook for constructing stale/orphan graphs that normal
    // admission correctly refuses.  It is absent from production binaries.
    void InsertUncheckedForTest(const Transaction& tx,
                                uint64_t fee_units = MIN_TX_FEE,
                                bool had_unconfirmed_parent = false,
                                bool assume_base_locking_validated = false) {
        std::lock_guard<std::mutex> lock(mutex_);
        const std::string key = HashToHex(tx.GetTxID());
        std::unordered_set<std::string> test_spends;
        for (const auto& input : tx.inputs) {
            if (input.IsCoinbase()) continue;
            const std::string spend_key = HashToHex(input.prev_tx_hash) + ":" +
                                          std::to_string(input.prev_out_index);
            if (!test_spends.insert(spend_key).second ||
                spent_by_tx_.count(spend_key))
                throw std::logic_error(
                    "InsertUncheckedForTest cannot violate unique-spender index");
        }
        MempoolEntry entry(tx, fee_units, 0);
        entry.had_unconfirmed_parent = had_unconfirmed_parent;
        entry.base_locking_validated =
            assume_base_locking_validated;
        total_bytes_ += entry.tx_size_bytes;
        fee_index_.insert({entry.fee_rate, key});
        entries_[key] = entry;
        bool token_family = false, token_is_mspv = false;
        std::optional<TokenOpData> token_op;
        std::string token_payload;
        (void)ExtractCanonicalTokenMarker(tx, token_family, token_op,
                                          token_is_mspv, &token_payload);
        if (token_family) ++token_marker_count_;
        const std::string replay_key = TokenReplayReservationKey(
            token_op, token_is_mspv, token_payload);
        if (!replay_key.empty())
            ++pending_token_replay_counts_[replay_key];
        for (const auto& input : tx.inputs) {
            if (input.IsCoinbase()) continue;
            const std::string spend_key = HashToHex(input.prev_tx_hash) + ":" +
                                          std::to_string(input.prev_out_index);
            spent_outputs_.insert(spend_key);
            spent_by_tx_.emplace(spend_key, key);
        }
    }

    bool EvictForTest(uint64_t incoming_fee_rate) {
        std::lock_guard<std::mutex> lock(mutex_);
        return Evict(incoming_fee_rate);
    }

    bool SetAddedTimeForTest(const std::string& key, uint64_t added_time) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = entries_.find(key);
        if (it == entries_.end()) return false;
        it->second.added_time = added_time;
        return true;
    }
#endif

private:
    size_t total_bytes_;

    // Remove roots and every transaction that depends on them while mutex_ is
    // held.  This is intentionally graph-based rather than inferred from
    // spent_outputs_: each live child owns the spent-output entry for its own
    // input, so consulting that set after deleting a parent falsely makes every
    // orphan appear connected during eviction.
    size_t RemoveWithDescendantsInternal(
        const std::vector<std::string>& roots) {
        if (roots.empty()) return 0;

        std::unordered_map<std::string, std::vector<std::string>> children;
        children.reserve(entries_.size());
        for (const auto& [child_key, entry] : entries_) {
            for (const auto& inp : entry.tx.inputs) {
                if (inp.IsCoinbase()) continue;
                children[HashToHex(inp.prev_tx_hash)].push_back(child_key);
            }
        }

        std::unordered_set<std::string> dead;
        dead.reserve(roots.size() * 2 + 1);
        std::vector<std::string> stack = roots;
        while (!stack.empty()) {
            std::string key = std::move(stack.back());
            stack.pop_back();
            if (!dead.insert(key).second) continue;
            auto it = children.find(key);
            if (it == children.end()) continue;
            for (const auto& child : it->second)
                if (!dead.count(child)) stack.push_back(child);
        }

        size_t removed = 0;
        for (const auto& key : dead) {
            if (!entries_.count(key)) continue;
            RemoveInternal(key);
            ++removed;
        }
        return removed;
    }

    void RemoveInternal(const std::string& key) {
        auto it = entries_.find(key);
        if (it == entries_.end()) return;

        const MempoolEntry& entry = it->second;

        if (auto removed_nms = ExtractNmsFromTx(entry.tx); removed_nms) {
            nms_payload_hashes_.erase(HashToHex(Hash256d(removed_nms->raw)));
        }

        if (pending_amm_tx_ == key) pending_amm_tx_.clear();

        bool token_family = false, token_is_mspv = false;
        std::optional<TokenOpData> token_op;
        std::string token_payload;
        (void)ExtractCanonicalTokenMarker(entry.tx, token_family, token_op,
                                          token_is_mspv, &token_payload);
        if (token_family && token_marker_count_ > 0)
            --token_marker_count_;
        const std::string replay_key = TokenReplayReservationKey(
            token_op, token_is_mspv, token_payload);
        if (!replay_key.empty()) {
            auto rit = pending_token_replay_counts_.find(replay_key);
            if (rit != pending_token_replay_counts_.end()) {
                if (rit->second <= 1) pending_token_replay_counts_.erase(rit);
                else --rit->second;
            }
        }

        auto range = fee_index_.equal_range(entry.fee_rate);
        for (auto fit = range.first; fit != range.second; ++fit) {
            if (fit->second == key) { fee_index_.erase(fit); break; }
        }

        for (const auto& input : entry.tx.inputs) {
            if (input.IsCoinbase()) continue;
            std::string spend_key = HashToHex(input.prev_tx_hash)
                                  + ":" + std::to_string(input.prev_out_index);
            auto sit = spent_by_tx_.find(spend_key);
            if (sit != spent_by_tx_.end() && sit->second == key) {
                spent_by_tx_.erase(sit);
                spent_outputs_.erase(spend_key);
            }
        }

        for (const auto& out : entry.tx.outputs) {
            std::string staker = ExtractStakeAddress(out.script_pubkey);
            if (staker.empty()) continue;
            auto sit = pending_stakers_.find(staker);
            if (sit != pending_stakers_.end() && sit->second == key)
                pending_stakers_.erase(sit);
        }

        total_bytes_ -= entry.tx_size_bytes;
        entries_.erase(it);
    }

    bool Evict(uint64_t incoming_fee_rate) {
        if (fee_index_.empty()) return false;

        auto lowest = fee_index_.begin();
        if (lowest->first >= incoming_fee_rate) return false;

        size_t bytes_before = total_bytes_;
        const std::vector<std::string> roots{lowest->second};
        (void)RemoveWithDescendantsInternal(roots);
        return total_bytes_ < bytes_before;
    }
};

}
