#pragma once

#include "../core/constants.h"
#include "../core/chain_work.h"
#include "../core/json_escape.h"
#include "../core/transaction.h"
#include "../core/op_authorization.h"
#include "../core/pqc_script.h"
#include "../crypto/ripemd160.h"
#include "../wallet/wallet.h"
#include "../consensus/state_digest.h"
#include "../consensus/btcveld_spv_params.h"
#include "../consensus/btcveld_mint_nullifier.h" // exact constant-state issuer/SPV replay domain
#include "../consensus/btcveld_c1_reservation.h" // issuer-signed public WRAP capacity leases
#include "../consensus/btcveld_redeem_spk.h"   // REDEEM dest scriptPubKey well-formedness
#include "../consensus/btcveld_redeem_guard.h" // §5b redeem drain guard (per-window outflow rate-limit)
#include "../consensus/btcveld_peg_gate.h"    // state-derived launch/liveness gate
#include "../consensus/btcveld_tier_ladder.h"  // §3.2 Layer-1 difficulty-tier custody-cap ladder
#include "../consensus/btcveld_reserve_transition.h" // single canonical rolling reserve
#include <deque>
#include <string>
#include <unordered_map>
#include <map>
#include <set>
#include <vector>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <optional>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace veld {

static const std::string TOKEN_OP_RETURN_PREFIX = "VELD_TOKEN|";
// Issuer RTP1 carries a bounded Bitcoin transaction, bounded direct parents,
// and a sparse-Merkle witness.  Its larger envelope is part of fresh reserve
// semantics only; legacy profiles keep their byte-exact historical limits.
#if defined(VELD_PUBLIC_MAINNET) || defined(VELD_BTCVELD_REGTEST)
inline constexpr size_t MAX_TOKEN_OP_PAYLOAD_BYTES = 65'535;
#else
inline constexpr size_t MAX_TOKEN_OP_PAYLOAD_BYTES = 42'000;
#endif
inline constexpr size_t MAX_TOKEN_ID_BYTES = 32;
inline constexpr size_t MAX_TOKEN_ACCOUNT_BYTES = 128;
inline constexpr size_t MAX_TOKEN_GENERAL_MEMO_BYTES = 512;
#if defined(VELD_PUBLIC_MAINNET) || defined(VELD_BTCVELD_REGTEST)
inline constexpr size_t MAX_TOKEN_MEMO_BYTES = 64'000;
#else
inline constexpr size_t MAX_TOKEN_MEMO_BYTES = 20'000;
#endif
inline constexpr size_t MAX_TOKEN_FUND_MEMO_BYTES = 40000;

// One-time BTC deposit outpoint identifier.
// A canonical funding-deposit outpoint is exactly "<64 lowercase hex txid>:<decimal vout>".
// The issuer-MINT gate (below) requires this in the op memo when armed and rejects reuse,
// so a stale/lost off-chain mint ledger can never re-mint a BTC deposit.
inline bool IsValidBtcOutpointId(const std::string& s) {
    if (s.size() < 66) return false;                 // 64 hex + ':' + >=1 digit
    if (s[64] != ':') return false;
    for (size_t i = 0; i < 64; ++i) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;   // lowercase hex only (canonical)
    }
    size_t nd = s.size() - 65;
    if (nd == 0 || nd > 10) return false;            // uint32 decimal vout
    uint64_t vout = 0;
    for (size_t i = 65; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
        vout = vout * 10 + static_cast<uint64_t>(s[i] - '0');
    }
    if (nd > 1 && s[65] == '0') return false;        // no leading-zero vout (one canonical encoding)
    if (vout > UINT32_MAX) return false;              // Bitcoin outpoints use a 32-bit index
    return true;
}
inline bool BtcVeldMintDepositIdActive(uint64_t height) {
    return BTCVELD_MINT_DEPOSIT_ID_ACTIVATION_HEIGHT != 0 &&
           height >= BTCVELD_MINT_DEPOSIT_ID_ACTIVATION_HEIGHT;
}

// An SPV mint must never become active before the exact-outpoint replay domain
// shared with issuer mints. Otherwise an SPV deposit accepted in the gap could
// later be presented to the issuer path as a fresh txid:vout. Both launch paths
// are active from height 1 in the production constants.
static_assert(BTCVELD_SPV_ACTIVATION_HEIGHT == 0 ||
              (BTCVELD_MINT_DEPOSIT_ID_ACTIVATION_HEIGHT != 0 &&
               BTCVELD_MINT_DEPOSIT_ID_ACTIVATION_HEIGHT <= BTCVELD_SPV_ACTIVATION_HEIGHT),
              "btcVELD SPV mint requires the shared exact-outpoint replay gate first");

// Token amounts are INTEGER satoshis of the token's smallest unit (`decimals`).
// A BTC-pegged asset (btcVELD) must never be represented in floating point:
// float dust would break the peg's supply==custody invariant and the state
// digest hashes the raw value bits. int64 sats is exact well past any real
// supply (21M BTC * 1e8 = 2.1e15 < 2^53).
struct TokenOpData {
    std::string action;       // MINT | TRANSFER | REDEEM | RESERVE | EXPOSE
    std::string token_id;
    std::string from;
    std::string to;
    int64_t     amount;       // satoshis of the token's smallest unit
    std::string memo;         // REDEEM: destination BTC scriptPubKey (hex)

    TokenOpData() : amount(0) {}
};

inline std::string EncodeTokenOp(const TokenOpData& d) {
    if (d.action == "RAW_OPRETURN") return d.memo;
    std::ostringstream ss;
    ss << TOKEN_OP_RETURN_PREFIX
       << d.action << "|"
       << d.token_id << "|"
       << d.from << "|"
       << d.to << "|"
       << d.amount << "|"
       << d.memo;
    return ss.str();
}

inline std::optional<TokenOpData> DecodeTokenOp(const std::string& data) {
    if (data.size() > MAX_TOKEN_OP_PAYLOAD_BYTES)
        return std::nullopt;
    if (data.substr(0, TOKEN_OP_RETURN_PREFIX.size()) != TOKEN_OP_RETURN_PREFIX)
        return std::nullopt;
    std::string rest = data.substr(TOKEN_OP_RETURN_PREFIX.size());
    std::vector<std::string> parts;
    std::istringstream ss(rest);
    std::string part;
    while (std::getline(ss, part, '|')) parts.push_back(part);
    if (parts.size() < 5) return std::nullopt;
    TokenOpData d;
    d.action   = parts[0];
    d.token_id = parts[1];
    d.from     = parts[2];
    d.to       = parts[3];
    if ((d.action != "MINT" && d.action != "TRANSFER" &&
         d.action != "REDEEM" && d.action != "RESERVE" &&
         d.action != "EXPOSE" && d.action != "CANCEL" &&
         d.action != "FUND") ||
        d.token_id.empty() || d.token_id.size() > MAX_TOKEN_ID_BYTES ||
        d.from.size() > MAX_TOKEN_ACCOUNT_BYTES ||
        d.to.size() > MAX_TOKEN_ACCOUNT_BYTES)
        return std::nullopt;
    // amount is a strict non-negative integer (satoshis) — reject decimals,
    // exponents, signs, or any trailing junk so two nodes never disagree.
    if (parts[4].empty()) return std::nullopt;
    if (parts[4].size() > 1 && parts[4][0] == '0') return std::nullopt;
    for (char c : parts[4]) {
        if (c < '0' || c > '9') return std::nullopt;
    }
    try {
        size_t consumed = 0;
        long long v = std::stoll(parts[4], &consumed);
        if (consumed != parts[4].size()) return std::nullopt;
        d.amount = (int64_t)v;
    } catch (...) { return std::nullopt; }
    if (d.amount <= 0) return std::nullopt;
    // memo is the final field; preserve any '|' it may contain (dest BTC
    // scriptPubKey hex never does, but be robust).
    if (parts.size() >= 6) {
        d.memo = parts[5];
        for (size_t i = 6; i < parts.size(); ++i) d.memo += "|" + parts[i];
    }
    const size_t memo_limit =
        (d.action == "FUND" && d.token_id == BTCVELD_TOKEN_ID)
            ? MAX_TOKEN_FUND_MEMO_BYTES
            : (d.action == "MINT" && d.token_id == BTCVELD_TOKEN_ID)
                ? MAX_TOKEN_MEMO_BYTES : MAX_TOKEN_GENERAL_MEMO_BYTES;
    if (d.memo.size() > memo_limit || EncodeTokenOp(d) != data)
        return std::nullopt;
    return d;
}

inline Transaction BuildTokenTransaction(
    const TokenOpData& op,
    const std::vector<UTXO>& input_utxos,
    const std::vector<uint8_t>& change_script,
    uint64_t fee_units = MIN_TX_FEE
) {
    Transaction tx;

    uint64_t total_in = 0;
    for (auto& u : input_utxos) {
        TxInput inp;
        inp.prev_tx_hash    = u.tx_hash;
        inp.prev_out_index  = u.output_index;
        inp.script_sig      = {};
        inp.sequence        = 0xFFFFFFFF;
        tx.inputs.push_back(inp);
        total_in += u.value;
    }

    if (total_in > fee_units) {
        tx.outputs.push_back(TxOutput(total_in - fee_units, change_script));
    }

    std::string op_data = EncodeTokenOp(op);
    tx.outputs.push_back(TxOutput(0, BuildOpReturnScript(op_data)));

    return tx;
}

struct OnChainTokenInfo {
    std::string id;
    std::string name;
    std::string issuer;
    uint8_t     decimals;
    std::string peg_asset;
};

struct TokenTransferRecord {
    std::string txid;
    uint32_t    vout = 0;      // OP_RETURN output index used in the redemption identifier
    std::string token_id;
    std::string from;
    std::string to;
    int64_t     amount = 0;
    uint64_t    block_height = 0;
    std::time_t timestamp = 0;
    std::string memo;          // REDEEM: destination BTC scriptPubKey (hex)
    bool        is_mint = false;
    bool        is_burn = false;       // retained for JSON compat; always false now
    bool        is_redeem = false;     // REDEEM: destroyed on Veld, BTC payout owed
};

// Constant-space commitment to every canonical btcVELD REDEEM obligation.
//
// The persistent RedeemObligationIndex is a derived disk view and can therefore
// be repaired by replay, but a completely deleted row cannot be distinguished
// from an honestly absent row by inspecting that index alone.  The token ledger
// maintains this independent replay-derived accumulator in canonical index
// order (height, then txid/vout within a block).  Payout consumers recompute the
// same root while walking the paginated index and require an exact count/root
// match.  This detects deletion, insertion, reordering, or field mutation
// without retaining a lifetime obligation list in RAM.
inline constexpr const char* BTCVELD_REDEEM_COMMITMENT_DOMAIN =
    "VELD_BTCVELD_REDEEM_COMMITMENT_v1|";

inline Hash256 EmptyBtcVeldRedeemCommitment() {
    return state_digest::sha256_domain(BTCVELD_REDEEM_COMMITMENT_DOMAIN, {});
}

inline Hash256 ExtendBtcVeldRedeemCommitment(
        const Hash256& previous, const TokenTransferRecord& r,
        const Hash256& block_hash) {
    if (!r.is_redeem || r.is_mint || r.is_burn || !r.to.empty() ||
        r.token_id != BTCVELD_TOKEN_ID || r.txid.empty() ||
        r.amount <= 0)
        throw std::invalid_argument("non-canonical btcVELD redeem commitment row");

    namespace sd = ::veld::state_digest;
    std::vector<uint8_t> body;
    body.reserve(128 + r.txid.size() + r.token_id.size() + r.from.size() +
                 r.to.size() + r.memo.size());
    sd::put_bytes(body, previous.data(), previous.size());
    sd::put_bytes(body, block_hash.data(), block_hash.size());
    sd::put_len_prefixed(body, r.txid);
    sd::put_u32_le(body, r.vout);
    sd::put_len_prefixed(body, r.token_id);
    sd::put_len_prefixed(body, r.from);
    sd::put_len_prefixed(body, r.to);
    sd::put_u64_le(body, static_cast<uint64_t>(r.amount));
    sd::put_u64_le(body, r.block_height);
    sd::put_len_prefixed(body, r.memo);
    sd::put_u8(body, r.is_mint ? 1 : 0);
    sd::put_u8(body, r.is_burn ? 1 : 0);
    sd::put_u8(body, r.is_redeem ? 1 : 0);
    return sd::sha256_domain(BTCVELD_REDEEM_COMMITMENT_DOMAIN, body);
}

struct BtcVeldRedeemCommitment {
    uint64_t count = 0;
    Hash256 root = EmptyBtcVeldRedeemCommitment();
    // Processing identity is not part of the rolling root.  It lets RPC reject
    // a transient candidate/reorg replay state that is not aligned with the
    // canonical chain snapshot whose index page it is returning.
    uint64_t processed_height = 0;
    Hash256 processed_block_hash{};
};

constexpr char BTCVELD_MINT_EFFECT_COMMITMENT_DOMAIN[] =
    "VELD/BTCVELD/MINT_ACCEPTED_EFFECT/v2";

inline Hash256 EmptyBtcVeldMintEffectCommitment() {
    return state_digest::sha256_domain(
        BTCVELD_MINT_EFFECT_COMMITMENT_DOMAIN, {});
}

struct BtcVeldMintAccumulator {
    Hash256 root = btcnull::EmptyRoot();
    uint64_t count = 0;
    // Consensus-authenticated ordering/locator commitment for every accepted
    // issuer/SPV mint effect.  Unlike the sparse-set root, this commits which
    // exact transaction marker caused each insertion.
    Hash256 effect_root = EmptyBtcVeldMintEffectCommitment();
    uint64_t effect_count = 0;
    uint64_t processed_height = 0;
    Hash256 processed_block_hash{};
};

struct BtcVeldMintProofStatus {
    bool consumed = false;
    // `minted` is intentionally distinct from `consumed`: C1F1 consumes the
    // Bitcoin outpoint while reserving, but does not credit btcVELD until the
    // later exact C1_MINT effect.
    bool minted = false;
    btcnull::Proof proof;
    Hash256 root = btcnull::EmptyRoot();
    uint64_t count = 0;
    uint64_t tip = 0;
    Hash256 tip_hash{};
    // Canonical effect identity from the rebuildable derived index.  The exact
    // locator stream is authenticated by consensus effect root/count; these
    // fields identify the exact accepted transition that consumed `outpoint`, so an
    // included but invalid paid-no-op carrier cannot be mistaken for a mint.
    // `accepted_txid` is empty iff `consumed` is false.
    std::string accepted_txid;
    uint64_t accepted_block_height = 0;
    Hash256 accepted_block_hash{};
    uint32_t accepted_tx_index = 0;
    uint32_t accepted_marker_vout = 0;
    std::string accepted_effect_kind;
    std::string c1_allocation_id;
    // The first insertion locator and the monetary-credit locator are exposed
    // separately so C1F1 cannot be mistaken for a completed mint.  For a
    // direct MINT both locators identify the same effect.
    std::string consumer_txid;
    uint64_t consumer_block_height = 0;
    Hash256 consumer_block_hash{};
    uint32_t consumer_tx_index = 0;
    uint32_t consumer_marker_vout = 0;
    std::string credit_txid;
    uint64_t credit_block_height = 0;
    Hash256 credit_block_hash{};
    uint32_t credit_tx_index = 0;
    uint32_t credit_marker_vout = 0;
};

// Transient per-block feed for the rebuildable, on-disk proof index.  The
// consensus authority is sparse root/count plus effect root/count. This locator
// lets RPC tooling find the exact accepted marker without treating raw marker presence
// as acceptance (invalid protocol requests are paid no-ops on this chain).
struct BtcVeldMintTransition {
    uint32_t tx_index = 0;
    uint32_t marker_vout = 0;
    std::string txid;
    std::string outpoint;
    std::vector<uint8_t> proof;
    Hash256 old_root{};
    Hash256 new_root{};
    // MINT and C1_FUND insert an outpoint (old_root != new_root, proof set).
    // C1_MINT is the later root-neutral credit/lease-erasure effect.
    std::string effect_kind;
    std::string c1_allocation_id;
};

// Transient handoff from the token/reserve verifier to the signer-bond module.
// The reserve state is already advanced atomically with the token ledger; the
// node consumes this record immediately afterward to close the exact request
// and release its signer-bond lock under the all-module rollback boundary.
struct BtcVeldReservePayoutTransition {
    btcveld::H256 request_id{};
    btcveld::H256 payout_txid{};
    uint64_t principal_sats = 0;
    std::vector<uint8_t> destination_spk;
};

inline constexpr char BTCVELD_C1_SEQUENCE_HISTORY_DOMAIN[] =
    "VELD/BTCVELD/C1_SEQUENCE_HISTORY/v2";

inline Hash256 EmptyBtcVeldC1SequenceHistory() {
    return state_digest::sha256_domain(
        BTCVELD_C1_SEQUENCE_HISTORY_DOMAIN, {});
}

inline Hash256 ExtendBtcVeldC1SequenceHistory(
        const Hash256& previous, const std::string& transition,
        uint64_t sequence,
        const std::string& request_id, const std::string& recipient,
        const std::string& allocation_commitment, int64_t amount_sats,
        uint64_t height) {
    if (sequence == 0 ||
        (transition != "RESERVE" && transition != "CANCEL"))
        throw std::invalid_argument("non-canonical C1 sequence history row");
    namespace sd = ::veld::state_digest;
    std::vector<uint8_t> body;
    sd::put_bytes(body, previous.data(), previous.size());
    sd::put_len_prefixed(body, transition);
    sd::put_u64_le(body, sequence);
    sd::put_len_prefixed(body, request_id);
    sd::put_len_prefixed(body, recipient);
    sd::put_len_prefixed(body, allocation_commitment);
    sd::put_u64_le(body, static_cast<uint64_t>(amount_sats));
    sd::put_u64_le(body, height);
    return sd::sha256_domain(
        BTCVELD_C1_SEQUENCE_HISTORY_DOMAIN, body);
}

struct BtcVeldC1SequenceState {
    uint64_t last_sequence = 0;
    uint64_t count = 0;
    Hash256 history_root = EmptyBtcVeldC1SequenceHistory();
};

// This domain is deliberately independent from the nullifier-set commitment.
// The launch configuration arms the underlying deposit-id rule at height 1,
// so adding this consensus field is a fresh-genesis change: existing networks
// must not activate this binary in place and every derived index must be rebuilt
// by replay from genesis.
inline Hash256 ExtendBtcVeldMintEffectCommitment(
        const Hash256& previous, uint64_t height,
        const BtcVeldMintTransition& t) {
    const bool insertion = t.effect_kind == "MINT" ||
                           t.effect_kind == "C1_FUND";
    const bool c1_mint = t.effect_kind == "C1_MINT";
    if (t.tx_index == UINT32_MAX || t.txid.size() != 64 ||
        !IsValidBtcOutpointId(t.outpoint) ||
        (!insertion && !c1_mint) ||
        (insertion && t.old_root == t.new_root) ||
        (c1_mint && t.old_root != t.new_root) ||
        ((t.effect_kind == "C1_FUND" || c1_mint) &&
         !c1reserve::IsAllocationId(t.c1_allocation_id)) ||
        (t.effect_kind == "MINT" && !t.c1_allocation_id.empty()))
        throw std::invalid_argument("non-canonical btcVELD mint effect row");
    namespace sd = ::veld::state_digest;
    std::vector<uint8_t> body;
    body.reserve(32 + 8 + 4 + 4 + 64 + 80 + 64);
    sd::put_bytes(body, previous.data(), previous.size());
    sd::put_u64_le(body, height);
    sd::put_u32_le(body, t.tx_index);
    sd::put_u32_le(body, t.marker_vout);
    sd::put_len_prefixed(body, t.txid);
    sd::put_len_prefixed(body, t.outpoint);
    sd::put_len_prefixed(body, t.effect_kind);
    sd::put_len_prefixed(body, t.c1_allocation_id);
    sd::put_bytes(body, t.old_root.data(), t.old_root.size());
    sd::put_bytes(body, t.new_root.data(), t.new_root.size());
    return sd::sha256_domain(BTCVELD_MINT_EFFECT_COMMITMENT_DOMAIN, body);
}

// Coherent, thread-safe issuer-mint capacity snapshot. `effective_ceiling_sats`
// is the exact aggregate ceiling ApplyTokenOp uses for `height`, evaluated from
// this ledger instance's current supply and trailing-work window. RPC preflight
// consumes the same snapshot so it cannot advertise the static 10 BTC ceiling
// while consensus is still clamped to the 0.001 BTC pilot tier.
struct BtcVeldIssuerMintCapacity {
    uint64_t height = 0;
    int64_t  current_supply_sats = 0;
    int64_t  static_ceiling_sats = BTCVELD_ISSUER_MAX_CUSTODY_SATS;
    int64_t  effective_ceiling_sats = 0;
    int64_t  reserved_sats = 0;
    int64_t  remaining_sats = 0;
    uint64_t sustained_work = 0;
    bool     tier_ladder_active = false;
    bool     includes_prospective_block = false;
    uint32_t prospective_block_bits = 0;
};

inline bool BtcVeldIssuerMintFitsCapacity(
        const BtcVeldIssuerMintCapacity& c, int64_t amount_sats) {
    if (amount_sats <= 0) return false;
    if (c.current_supply_sats < 0 || c.reserved_sats < 0 ||
        c.effective_ceiling_sats < c.current_supply_sats ||
        c.remaining_sats < 0) return false;
    // Subtract only after ordering proves it cannot underflow. Requiring the
    // coherent identity also fails closed if a caller fabricates/stales fields.
    if (c.current_supply_sats >
            c.effective_ceiling_sats - c.reserved_sats ||
        c.remaining_sats != c.effective_ceiling_sats -
                                c.current_supply_sats - c.reserved_sats)
        return false;
    return amount_sats <= c.remaining_sats;
}

struct BtcVeldC1Reservation {
    std::string allocation_id;
    uint64_t sequence = 0;
    std::string recipient;
    // C1R1/C1E1 never disclose the Bitcoin script. C1F1 opens this exact
    // domain-separated allocation commitment only after verified funding.
    std::string allocation_commitment;
    int64_t amount_sats = 0;
    uint64_t created_height = 0;
    uint64_t expires_height = 0;
    bool exposed = false;
    uint64_t exposed_height = 0;
    uint64_t funding_starts_height = 0;
    uint64_t funding_expires_height = 0;
    bool funded = false;
    uint64_t funded_height = 0;
    std::string funding_outpoint;
};

struct BtcVeldC1ReservationStatus {
    bool found = false;
    bool active = false;
    BtcVeldC1Reservation reservation;
    uint64_t query_height = 0;
};

class OnChainTokenLedger {
public:
    // ---- D-STATE-01: minimum positive account balance ----------------------
    // balances_ holds one consensus entry per positive token:address balance.
    // The SPV custody ceiling is 1,000,000,000 sats, so WITHOUT a floor a holder
    // can split into 1,000,000,000 one-sat accounts at fresh canonical addresses:
    // an unbounded RAM/digest/replay surface that a bounded money supply does
    // NOT bound. At 1,000 sats the live-account count is capped at 1,000,000.
    //
    // RULE: every balance touched by ANY path must end at exactly 0 or at or
    // above the floor. Enforced at the ledger write layer so every caller —
    // SPV mint, transfer, AMM leg, compensation — inherits it rather than
    // remembering to check.
    //
    // NOTE: if the custody ceiling is ever raised, the account bound scales
    // linearly with it. Re-derive this floor at the same time.
    static constexpr int64_t MIN_ACCOUNT_SATS = 1000;

    static bool BalanceAdmissible(int64_t b) {
        return b == 0 || b >= MIN_ACCOUNT_SATS;
    }
    OnChainTokenLedger() = default;

    // Protocol-blessed token registration. btcVELD is a single pegged asset,
    // not a general permissionless token platform, so there is deliberately NO
    // user-facing REGISTER OP_RETURN action (that would be spam/attack surface).
    // Registration is a pure function of (height, compile constants): node.h
    // calls this at BTCVELD_ACTIVATION_HEIGHT during ProcessBlock (see the
    // activation-gate wiring), and it is re-applied deterministically on reorg
    // replay because Reset() clears tokens_. Idempotent.
    void RegisterToken(const OnChainTokenInfo& info) {
        std::lock_guard<std::mutex> lock(mutex_);
        RegisterTokenLocked(info);
    }

    void ApplyOpImmediate(const TokenOpData& op, uint64_t height,
                          const BtcVeldPegGateState& peg_gate) {
        std::lock_guard<std::mutex> lock(mutex_);
        Transaction dummy;
        dummy.inputs.push_back(TxInput::Coinbase("immediate:" + op.action));
        ApplyTokenOp(op, dummy, height, peg_gate);
    }

    // The redeems ACCEPTED in the most recently processed block — a deterministic
    // per-block set (recomputed on replay), so node.h can feed the redeem
    // covenant its obligations WITHOUT depending on the capped `history_` log.
    const std::vector<TokenTransferRecord>& LastBlockRedeems() const { return last_block_redeems_; }
    std::vector<TokenTransferRecord> LastBlockRedeemsCopy() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return last_block_redeems_;
    }
    std::vector<BtcVeldMintTransition> LastBlockMintTransitionsCopy() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return last_block_mint_transitions_;
    }
    std::vector<BtcVeldReservePayoutTransition>
    LastBlockReservePayoutsCopy() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return last_block_reserve_payouts_;
    }
    bool ProcessBlock(const Block& block,
                      const BtcVeldPegGateState& peg_gate) {
        std::lock_guard<std::mutex> lock(mutex_);
        const Hash256 block_hash = block.GetHash();
        const uint64_t reserve_transition_count_before =
            reserve_state_.transition_count;
        size_t reserve_transition_count = 0;
        bool contains_reserve_sensitive = false;
        bool bitcoin_reorg_freeze = false;
        if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED) {
            const auto supply_it = supply_.find(BTCVELD_TOKEN_ID);
            const int64_t signed_supply = supply_it == supply_.end()
                ? 0 : supply_it->second;
            if (signed_supply < 0 ||
                !reserve_state_.AccountingHolds(
                    static_cast<uint64_t>(signed_supply)) ||
                block.height < reserve_state_.processed_veld_height ||
                (block.height == reserve_state_.processed_veld_height &&
                 !HashIsZero(reserve_state_.processed_veld_block_hash) &&
                 reserve_state_.processed_veld_block_hash != block_hash))
                return false;
            for (const auto& tx : block.transactions) {
                reserve_transition_count +=
                    CountReserveTransitionCarriersLocked_(tx);
                contains_reserve_sensitive = contains_reserve_sensitive ||
                    HasReserveSensitiveMarkerLocked_(tx);
            }
            // Version 1 has one linear state edge per Veld block.  Count
            // malformed family-prefixed carriers too, so a second encoding
            // cannot hide behind a paid no-op.
            if (reserve_transition_count > 1) return false;
            if (reserve_state_.status ==
                    btcveld::reserve::Status::ACTIVE) {
                if (btc_headers_ == nullptr) return false;
                bitcoin_reorg_freeze =
                    !btc_headers_->IsFinalForExternalValue(
                        reserve_state_.reserve_bitcoin_block,
                        BTCVELD_SPV_K_BTC);
                // A header-chain reorg consumes this block's one reserve-state
                // edge by freezing.  An ordinary transition must wait for a
                // later Veld block and will then fail closed against FROZEN.
                if (bitcoin_reorg_freeze &&
                    reserve_transition_count != 0)
                    return false;
                contains_reserve_sensitive =
                    contains_reserve_sensitive || bitcoin_reorg_freeze;
            }
        }
        // Gate-closed markers are rejected before any field changes.
        for (const auto& tx : block.transactions) {
            if (HasForbiddenBtcVeldMarkerLocked_(tx, peg_gate))
                return false;
        }
        // Preserve ProcessBlock's fail-without-mutation contract independently
        // of Node's wider module snapshot. A strict C1 rejection can occur
        // after an earlier transaction in this block applied, so every mutable
        // consensus field and transient feed must roll back before false
        // escapes to a standalone ledger caller. The copy is paid only by a
        // block that actually contains C1R1/C1E1/C1C1/C1F1/MNP2.
        struct RollbackState {
            decltype(tokens_) tokens;
            decltype(balances_) balances;
            decltype(supply_) supply;
            decltype(c1_reservations_) reservations;
            decltype(history_) history;
            decltype(last_block_redeems_) last_redeems;
            decltype(last_block_mint_transitions_) last_mints;
            decltype(last_block_reserve_payouts_) last_reserve_payouts;
            uint8_t last_reserve_edges;
            btcveld::reserve::State reserve_state;
            uint64_t redeem_window;
            int64_t redeemed;
            decltype(recent_work_) recent_work;
            bool needs_rebuild;
            Hash256 nullifier_root;
            uint64_t nullifier_count;
            Hash256 effect_root;
            uint64_t effect_count;
            uint64_t mint_height;
            Hash256 mint_hash;
            uint64_t c1_last_sequence;
            uint64_t c1_history_count;
            Hash256 c1_history_root;
            uint64_t redeem_count;
            Hash256 redeem_root;
            uint64_t redeem_height;
            Hash256 redeem_hash;
        };
        bool contains_strict_c1 = contains_reserve_sensitive;
        for (const auto& tx : block.transactions)
            contains_strict_c1 = contains_strict_c1 ||
                                 HasC1ReservationMarkerLocked_(tx);
        std::optional<RollbackState> before;
        if (contains_strict_c1) {
            before.emplace(RollbackState{
                tokens_, balances_, supply_, c1_reservations_, history_,
                last_block_redeems_, last_block_mint_transitions_,
                last_block_reserve_payouts_, last_block_reserve_edges_,
                reserve_state_,
                redeem_window_id_, redeemed_in_window_, recent_work_,
                needs_rebuild_, mint_nullifier_root_, mint_nullifier_count_,
                mint_effect_root_, mint_effect_count_,
                mint_accumulator_processed_height_,
                mint_accumulator_processed_block_hash_,
                c1_last_sequence_, c1_sequence_history_count_,
                c1_sequence_history_root_,
                redeem_commitment_count_, redeem_commitment_root_,
                redeem_commitment_processed_height_,
                redeem_commitment_processed_block_hash_});
        }
        auto rollback = [&]() {
            if (!before) return;
            tokens_ = before->tokens;
            balances_ = before->balances;
            supply_ = before->supply;
            c1_reservations_ = before->reservations;
            history_ = before->history;
            last_block_redeems_ = before->last_redeems;
            last_block_mint_transitions_ = before->last_mints;
            last_block_reserve_payouts_ = before->last_reserve_payouts;
            last_block_reserve_edges_ = before->last_reserve_edges;
            reserve_state_ = before->reserve_state;
            redeem_window_id_ = before->redeem_window;
            redeemed_in_window_ = before->redeemed;
            recent_work_ = before->recent_work;
            needs_rebuild_ = before->needs_rebuild;
            mint_nullifier_root_ = before->nullifier_root;
            mint_nullifier_count_ = before->nullifier_count;
            mint_effect_root_ = before->effect_root;
            mint_effect_count_ = before->effect_count;
            mint_accumulator_processed_height_ = before->mint_height;
            mint_accumulator_processed_block_hash_ = before->mint_hash;
            c1_last_sequence_ = before->c1_last_sequence;
            c1_sequence_history_count_ = before->c1_history_count;
            c1_sequence_history_root_ = before->c1_history_root;
            redeem_commitment_count_ = before->redeem_count;
            redeem_commitment_root_ = before->redeem_root;
            redeem_commitment_processed_height_ = before->redeem_height;
            redeem_commitment_processed_block_hash_ = before->redeem_hash;
        };
        if (bitcoin_reorg_freeze &&
            !btcveld::reserve::ApplyFreeze(
                reserve_state_, reserve_state_.reserve_txid,
                reserve_state_.reserve_bitcoin_block)) {
            rollback();
            return false;
        }
        last_block_redeems_.clear();
        last_block_mint_transitions_.clear();
        last_block_reserve_payouts_.clear();
        last_block_reserve_edges_ = 0;
        // A lease is active through its recorded expiry height.  Prune before
        // executing this block so canonical replay, reorg previews and the
        // mempool target frame all expose the same capacity at the boundary.
        PruneC1ReservationsLocked_(block.height);
        // §3.2 tier ladder: track this instance's own trailing window of per-block
        // work. Pushed for EVERY block (difficulty is a whole-chain property), so
        // each ledger (main or alt) measures its OWN chain — no external chain read,
        // no main/alt aliasing — and Reset()+replay rebuilds it identically.
        // The token digest commits the ordered window as well as the resulting mint
        // decision.  Although header-derived, it changes the next-block tier
        // verdict, so omitting it would permit equal digests followed by
        // different mint acceptance. Kept unconditionally so replay and
        // activation never depend on an uncommitted side cache.
        recent_work_.push_back(BlockWorkForTier(block.header.bits));
        if (recent_work_.size() > BTCVELD_TIER_WINDOW_BLOCKS) recent_work_.pop_front();
        MaybeRegisterBtcVeld(block.height);   // protocol activation gate (mainnet-inert if issuer unset)
        // MSPV always creates fresh exposure and therefore never consumes the
        // completion exception used by exact C1C1/C1F1/MNP2 transitions.
        const bool spv_on = peg_gate.MintAllowed() &&
                            BtcVeldSpvActive(block.height) &&
                            btc_headers_ != nullptr;
        for (size_t tx_index = 0; tx_index < block.transactions.size(); ++tx_index) {
            const auto& tx = block.transactions[tx_index];
            // Historical token operations retain the invalid paid-no-op rule.
            // C1R1/C1E1/C1C1/C1F1/MNP2 are deliberately stricter: a confirmed
            // issuer-signed reservation carrier must never be ambiguous about
            // whether it acquired capacity or minted. In particular, an MSPV
            // or issuer mint earlier in this same block cannot make a funded
            // MNP2's nullifier witness stale and leave the deposit stranded as
            // a confirmed, fee-paying no-op.
            // ProcessBlock's local snapshot below restores earlier mutations.
            const bool strict_c1 = HasC1ReservationMarkerLocked_(tx) ||
                (btcveld::reserve::TRANSITION_V1_REQUIRED &&
                 HasReserveSensitiveMarkerLocked_(tx));
            const bool applied = ApplyTransactionMarkersLocked_(
                tx, block.height, spv_on, peg_gate,
                /*require_marker=*/false,
                /*token_authorization_prevalidated=*/false,
                static_cast<uint32_t>(tx_index));
            if (strict_c1 && !applied) {
                rollback();
                return false;
            }
        }
        // RedeemObligationIndex orders rows by height, txid, then vout.  Block
        // transaction order is not necessarily txid order, so sort this block's
        // accepted set before extending the lifetime rolling commitment.
        std::vector<TokenTransferRecord> ordered_redeems =
            last_block_redeems_;
        std::sort(ordered_redeems.begin(), ordered_redeems.end(),
                  [](const TokenTransferRecord& a,
                     const TokenTransferRecord& b) {
                      if (a.txid != b.txid) return a.txid < b.txid;
                      return a.vout < b.vout;
                  });
        for (const auto& redeem : ordered_redeems) {
            if (redeem.token_id != BTCVELD_TOKEN_ID) continue;
            if (redeem_commitment_count_ == UINT64_MAX)
                throw std::overflow_error("btcVELD redeem commitment count overflow");
            redeem_commitment_root_ = ExtendBtcVeldRedeemCommitment(
                redeem_commitment_root_, redeem, block_hash);
            ++redeem_commitment_count_;
        }
        redeem_commitment_processed_height_ = block.height;
        redeem_commitment_processed_block_hash_ = block_hash;
        mint_accumulator_processed_height_ = block.height;
        mint_accumulator_processed_block_hash_ = block_hash;
        if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED) {
            const auto supply_it = supply_.find(BTCVELD_TOKEN_ID);
            const int64_t signed_supply = supply_it == supply_.end()
                ? 0 : supply_it->second;
            if (signed_supply < 0 ||
                !btcveld::reserve::SetProcessed(
                    reserve_state_, block.height, block_hash) ||
                !reserve_state_.AccountingHolds(
                    static_cast<uint64_t>(signed_supply))) {
                rollback();
                return false;
            }
            if (reserve_state_.transition_count !=
                    reserve_transition_count_before) {
                if (reserve_transition_count_before == UINT64_MAX ||
                    reserve_state_.transition_count !=
                        reserve_transition_count_before + 1) {
                    rollback();
                    return false;
                }
                last_block_reserve_edges_ = 1;
            }
        }
        return true;
    }

    // Build the exact token state visible to modules that execute after this
    // ledger for `block`, without publishing any mutation.  The AMM covenant
    // preflight uses this to mirror the canonical token-before-AMM module
    // order, including a valid issuer MINT that funds the block's sole seed.
    // The canonical launch/liveness gate is an explicit input and is deliberately not
    // inferred or advanced here.
    bool BuildPostBlockPreview(const Block& block,
                               const BtcVeldPegGateState& peg_gate,
                               OnChainTokenLedger& out) const;

    // Stateful relay/mining policy for one TOKEN/MSPV transaction against the
    // exact canonical parent frame.  It runs the same parser, authorization,
    // replay, supply, balance, redeem-window, and SPV checks as ProcessBlock on
    // an isolated snapshot.  The live ledger is never temporarily mutated, so
    // a concurrent block commit cannot be lost by a snapshot/restore race.
    //
    // This is policy, not a consensus semantic change: a non-standard miner may
    // still include an invalid marker as a fee-paying no-op, but standard nodes
    // will neither relay nor mine one and will purge one that becomes stale.
    bool ValidateMempoolCandidate(
        const Transaction& tx, uint64_t height,
        uint32_t prospective_block_bits,
        const BtcVeldPegGateState& peg_gate) const;
    std::vector<bool> FilterMempoolCandidates(
        const std::vector<Transaction>& candidates, uint64_t height,
        uint32_t prospective_block_bits,
        const BtcVeldPegGateState& peg_gate,
        const std::vector<bool>& token_authorization_prevalidated = {}) const;
    std::vector<bool> SelectResourceFeasibleMempoolCandidates(
        const std::vector<const Transaction*>& candidates,
        const std::vector<size_t>& serialized_sizes,
        const std::vector<bool>& token_families,
        const std::vector<bool>& token_authorization_prevalidated,
        size_t initial_count, size_t initial_bytes,
        size_t max_count, size_t max_bytes,
        uint64_t height, uint32_t prospective_block_bits,
        const BtcVeldPegGateState& peg_gate) const;

    // node.h points this at its BtcHeaderChain once at construction (mirrors
    // rpc_.SetOnChainTokens). nullptr => SPV mint disabled (also gated by
    // BtcVeldSpvActive). The header view is read-only during proof verification;
    // exact-outpoint replay state belongs to this token ledger.
    void SetBtcHeaderChain(btcspv::BtcHeaderChain* c) {
        std::lock_guard<std::mutex> lock(mutex_);
        btc_headers_ = c;
    }

    void SetBtcVeldRedeemCovenant(
            const btcveld::SignerBondCovenant* covenant) {
        std::lock_guard<std::mutex> lock(mutex_);
        redeem_covenant_ = covenant;
    }

    const btcveld::SignerBondCovenant* GetBtcVeldRedeemCovenant() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return redeem_covenant_;
    }

#ifdef VELD_TEST_HOOKS
    bool TestHasBtcVeldConsensusDependencies(
            const btcspv::BtcHeaderChain* headers,
            const btcveld::SignerBondCovenant* covenant) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return btc_headers_ == headers && redeem_covenant_ == covenant;
    }

    Hash256 TestBoundBtcHeaderDigest() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return btc_headers_ == nullptr ? Hash256{} :
            btc_headers_->StateDigest();
    }

    Hash256 TestBoundBtcVeldRedeemCovenantDigest() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return redeem_covenant_ == nullptr ? Hash256{} :
            redeem_covenant_->Digest();
    }
#endif

    btcveld::reserve::State GetBtcVeldReserveState() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return reserve_state_;
    }

    btcveld::reserve::SpendClassification ClassifyBtcVeldReserveSpend(
            const std::vector<uint8_t>& bitcoin_tx,
            const std::vector<std::vector<uint8_t>>& direct_parents) const {
        std::lock_guard<std::mutex> lock(mutex_);
        btcveld::reserve::SpendClassification failed;
        if constexpr (!btcveld::reserve::TRANSITION_V1_REQUIRED) {
            failed.reason = "rolling reserve semantics are inactive";
            return failed;
        }
        const auto supply_it = supply_.find(BTCVELD_TOKEN_ID);
        const int64_t signed_supply = supply_it == supply_.end()
            ? 0 : supply_it->second;
        if (signed_supply < 0) {
            failed.reason = "negative btcVELD supply";
            return failed;
        }
        auto valid_recipient = [](const std::string& address) {
            return IsCanonicalTokenCreditAddress(address);
        };
        const btcveld::reserve::PayoutLookup payout_lookup =
            [this](const Hash256& commitment,
                   btcveld::reserve::PayoutContext& payout) {
                if (redeem_covenant_ == nullptr) return false;
                const auto request =
                    redeem_covenant_->FindOpenByCommitmentCopy(commitment);
                if (!request) return false;
                payout.present = true;
                payout.request_id = request->request_id;
                payout.request_commitment = request->request_commitment;
                payout.principal_sats = request->amount_sats;
                payout.destination_spk = request->dest_spk;
                return true;
            };
        return btcveld::reserve::ClassifyBitcoinReserveSpend(
            reserve_state_, static_cast<uint64_t>(signed_supply),
            bitcoin_tx, direct_parents, BtcVeldCustodySpk(),
            valid_recipient, payout_lookup);
    }

    // FSP2 is permissionless proof relay, not merely a slashing channel.  If
    // the proven Bitcoin spend is the exact authorized PAYOUT, advance the
    // same canonical reserve edge even when no separate RTP1 carrier was
    // relayed.  Otherwise an RTP1-withholding signer could let the fulfilled
    // request default, trigger compensation, and leave supply backed by the
    // already-spent predecessor value.  Rebuild and run the complete RTP1
    // verifier here; the caller-supplied classification is never authority.
    bool ApplyFsp2AuthorizedReservePayout(
            const Hash256& bitcoin_block, uint64_t merkle_directions,
            const std::vector<Hash256>& merkle_branch,
            const std::vector<uint8_t>& bitcoin_tx,
            const std::vector<std::vector<uint8_t>>& direct_parents,
            BtcVeldReservePayoutTransition& applied) {
        std::lock_guard<std::mutex> lock(mutex_);
        applied = BtcVeldReservePayoutTransition{};
        if constexpr (!btcveld::reserve::TRANSITION_V1_REQUIRED) {
            (void)bitcoin_block;
            (void)merkle_directions;
            (void)merkle_branch;
            (void)bitcoin_tx;
            (void)direct_parents;
            return false;
        }
        if (btc_headers_ == nullptr || redeem_covenant_ == nullptr ||
            reserve_state_.status != btcveld::reserve::Status::ACTIVE ||
            merkle_branch.size() > 32 ||
            (merkle_branch.size() < 32 &&
             (merkle_directions >> merkle_branch.size()) != 0) ||
            last_block_reserve_edges_ != 0)
            return false;
        const auto supply_it = supply_.find(BTCVELD_TOKEN_ID);
        const int64_t signed_supply = supply_it == supply_.end()
            ? 0 : supply_it->second;
        if (signed_supply < 0) return false;
        const uint64_t supply = static_cast<uint64_t>(signed_supply);

        auto valid_recipient = [](const std::string& address) {
            return IsCanonicalTokenCreditAddress(address);
        };
        const btcveld::reserve::PayoutLookup payout_lookup =
            [this](const Hash256& commitment,
                   btcveld::reserve::PayoutContext& payout) {
                const auto request =
                    redeem_covenant_->FindOpenByCommitmentCopy(commitment);
                if (!request) return false;
                payout.present = true;
                payout.request_id = request->request_id;
                payout.request_commitment = request->request_commitment;
                payout.principal_sats = request->amount_sats;
                payout.destination_spk = request->dest_spk;
                return true;
            };
        const auto classification =
            btcveld::reserve::ClassifyBitcoinReserveSpend(
                reserve_state_, supply, bitcoin_tx, direct_parents,
                BtcVeldCustodySpk(), valid_recipient, payout_lookup);
        if (classification.disposition !=
                btcveld::reserve::SpendDisposition::AUTHORIZED_TRANSITION ||
            classification.operation != btcveld::reserve::Operation::PAYOUT ||
            !classification.payout.present)
            return false;

        btcveld::reserve::Claim claim;
        claim.operation = btcveld::reserve::Operation::PAYOUT;
        claim.network_binding = btcveld::reserve::NetworkBinding();
        claim.prior_commitment = reserve_state_.transition_commitment;
        claim.prior_reserve_txid = reserve_state_.reserve_txid;
        claim.prior_reserve_vout = reserve_state_.reserve_vout;
        claim.prior_reserve_value = reserve_state_.reserve_value_sats;
        claim.prior_transition_count = reserve_state_.transition_count;
        claim.new_reserve_txid = classification.new_reserve_txid;
        claim.new_reserve_vout = classification.new_reserve_vout;
        claim.new_reserve_value = classification.new_reserve_value;
        claim.bitcoin_txid = classification.bitcoin_txid;
        claim.bitcoin_block = bitcoin_block;
        claim.merkle_directions = merkle_directions;
        claim.merkle_branch = merkle_branch;
        claim.exact_commitment = classification.exact_commitment;
        claim.mint_amount = 0;
        claim.bitcoin_tx = bitcoin_tx;
        claim.direct_parents = direct_parents;
        const std::vector<uint8_t> proof =
            btcveld::reserve::EncodeProof(claim);
        if (proof.empty()) return false;
        const btcveld::reserve::Result verified =
            btcveld::reserve::Verify(
                *btc_headers_, reserve_state_, supply,
                proof.data(), proof.size(), BtcVeldCustodySpk(),
                BTCVELD_SPV_K_BTC, valid_recipient,
                classification.payout);
        if (!verified.ok || verified.claim.bitcoin_txid !=
                classification.bitcoin_txid)
            return false;
        btcveld::reserve::State next = reserve_state_;
        if (!btcveld::reserve::ApplyAuthorized(
                next, verified, supply, supply))
            return false;
        applied = BtcVeldReservePayoutTransition{
            verified.payout_request_id, verified.claim.bitcoin_txid,
            verified.payout_principal_sats,
            verified.payout_destination_spk};
        reserve_state_ = std::move(next);
        last_block_reserve_payouts_.push_back(applied);
        last_block_reserve_edges_ = 1;
        return true;
    }

    bool FreezeBtcVeldReserve(const Hash256& unauthorized_spend_txid,
                              const Hash256& bitcoin_block) {
        std::lock_guard<std::mutex> lock(mutex_);
        if constexpr (!btcveld::reserve::TRANSITION_V1_REQUIRED) {
            (void)unauthorized_spend_txid;
            (void)bitcoin_block;
            return false;
        }
        if (last_block_reserve_edges_ != 0) return false;
        const auto supply_it = supply_.find(BTCVELD_TOKEN_ID);
        const int64_t signed_supply = supply_it == supply_.end()
            ? 0 : supply_it->second;
        if (signed_supply < 0) return false;
        btcveld::reserve::State next = reserve_state_;
        if (!btcveld::reserve::ApplyFreeze(
                next, unauthorized_spend_txid, bitcoin_block) ||
            !next.AccountingHolds(static_cast<uint64_t>(signed_supply)))
            return false;
        reserve_state_ = std::move(next);
        last_block_reserve_edges_ = 1;
        return true;
    }

#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
    // Qualification-only in-band state carrier. The native D-STATE corpus
    // places the address in canonical serialized block bytes; VeldNode calls
    // this only from its ordinary ApplyBlockModules_ sequence. This seam is
    // compile-incompatible with VELD_PUBLIC_RELEASE and cannot be reached by a
    // shipping node. It models one admissible minimum-size account without a
    // synthetic history record, matching S1's worst live-balance state.
    bool ApplyDStateQualificationCredit(const std::string& recipient) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!IsCanonicalTokenCreditAddress(recipient)) return false;
        if (!tokens_.count(BTCVELD_TOKEN_ID)) {
            RegisterTokenLocked({BTCVELD_TOKEN_ID, "Wrapped Bitcoin",
                                 BTCVELD_ISSUER_ADDRESS, BTCVELD_DECIMALS,
                                 BTCVELD_PEG_ASSET});
        }
        const std::string key =
            std::string(BTCVELD_TOKEN_ID) + ":" + recipient;
        if (balances_.count(key)) return false;
        const int64_t old_supply = supply_.count(BTCVELD_TOKEN_ID)
            ? supply_.at(BTCVELD_TOKEN_ID) : 0;
        if (old_supply < 0 ||
            old_supply > static_cast<int64_t>(
                BTCVELD_SPV_MAX_CUSTODY_SATS) - MIN_ACCOUNT_SATS)
            return false;
        balances_.emplace(key, MIN_ACCOUNT_SATS);
        supply_[BTCVELD_TOKEN_ID] = old_supply + MIN_ACCOUNT_SATS;
        return true;
    }

    // CapacityV1 also carries the exact bounded 2,000-row token history used
    // by S1/S6 rollback measurement. The node constructs each deterministic
    // row from canonical carrier counts; this method rejects any deviation or
    // duplicate sequence before mutating the qualification-only history.
    bool ApplyDStateQualificationHistoryRecord(
            const TokenTransferRecord& record) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (history_.size() >= 2'000) return false;
        const uint64_t ordinal = history_.size();
        if (record.txid != HashToHex(Hash256d(
                "dstate-history:" + std::to_string(ordinal))) ||
            record.token_id != BTCVELD_TOKEN_ID ||
            !IsCanonicalTokenCreditAddress(record.from) ||
            !IsCanonicalTokenCreditAddress(record.to) ||
            record.amount != MIN_ACCOUNT_SATS ||
            record.block_height != ordinal + 1 ||
            record.timestamp !=
                static_cast<std::time_t>(1'700'000'000 + ordinal) ||
            record.memo != "dstate-bounded-history" ||
            record.is_mint || record.is_burn || record.is_redeem)
            return false;
        history_.push_back(record);
        return true;
    }
#endif

    // Redeem-covenant compensation: re-mint btcVELD to a
    // user who burned on redeem but was not paid (or was mis-paid). NOT signature-
    // gated — the covenant's proven slash verdict IS the authorization; node.h calls
    // this only after ApplySlash, and only when the redeem covenant is active. The
    // burned supply is restored toward its pre-redeem level. Deterministic (a pure
    // function of the chain's proven slashes), so it re-applies identically on replay.
    bool CompensateMint(const std::string& recipient, uint64_t amount,
                        uint64_t block_height = 0,
                        const std::string& source_txid = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!IsCanonicalTokenCreditAddress(recipient) || amount == 0)
            return false;
        if (!tokens_.count(BTCVELD_TOKEN_ID)) return false;
        if (amount > (uint64_t)INT64_MAX) return false;
        int64_t a = (int64_t)amount;
        auto supply_it = supply_.find(BTCVELD_TOKEN_ID);
        const int64_t sup = supply_it == supply_.end() ? 0 : supply_it->second;
        if (sup < 0) return false;
        if (sup > INT64_MAX - a) return false;                     // supply must never wrap
        const std::string key = std::string(BTCVELD_TOKEN_ID) + ":" + recipient;
        auto bit = balances_.find(key);
        const int64_t old_balance = bit == balances_.end() ? 0 : bit->second;
        if (old_balance < 0 || old_balance > INT64_MAX - a) return false;
        // D-STATE-01: compensation may not create a sub-floor account.
        if (!BalanceAdmissible(old_balance + a)) return false;
        btcveld::reserve::State reserve_next = reserve_state_;
        if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED) {
            if (!btcveld::reserve::ResolveDefaultOrCompensation(
                    reserve_next, amount,
                    static_cast<uint64_t>(sup + a)))
                return false;
        }
        balances_[key] = old_balance + a;
        supply_[BTCVELD_TOKEN_ID] = sup + a;
        if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED)
            reserve_state_ = std::move(reserve_next);
        TokenTransferRecord rec{};
        rec.txid         = source_txid;   // slash-verdict block/tx identity when supplied
        rec.vout         = 0;
        rec.token_id     = BTCVELD_TOKEN_ID;
        rec.from         = "redeem-slash-compensation";
        rec.to           = recipient;
        rec.amount       = a;
        rec.block_height = block_height;
        rec.timestamp    = std::time(nullptr);
        rec.memo         = "redeem-slash-compensation";
        rec.is_mint      = true;
        rec.is_burn      = false;
        rec.is_redeem    = false;
        history_.push_back(rec); if (history_.size() > 2000) history_.erase(history_.begin());
        return true;
    }

    bool NeedsRebuild() const { return false; }
    void ClearRebuildFlag()   {  }

    // Clear all token state for a full replay from genesis (called from node.h
    // on_commit_ when a same-or-lower-height block lands). tokens_ IS cleared:
    // registration is re-applied deterministically during replay by the
    // activation-height gate, so wiping it here keeps the replayed digest exact
    // (a token must not appear registered while replaying a pre-activation
    // block).
    void Reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        tokens_.clear();
        balances_.clear();
        supply_.clear();
        c1_reservations_.clear();
        history_.clear();
        last_block_redeems_.clear();
        last_block_mint_transitions_.clear();
        last_block_reserve_payouts_.clear();
        last_block_reserve_edges_ = 0;
        reserve_state_ = btcveld::reserve::State{};
        redeem_window_id_   = 0;   // §5b drain guard: re-derived by the replay
        redeemed_in_window_ = 0;
        recent_work_.clear();      // §3.2 tier ladder: re-filled per block by the replay
        mint_nullifier_root_ = btcnull::EmptyRoot();
        mint_nullifier_count_ = 0;
        mint_effect_root_ = EmptyBtcVeldMintEffectCommitment();
        mint_effect_count_ = 0;
        mint_accumulator_processed_height_ = 0;
        mint_accumulator_processed_block_hash_ = ZeroHash();
        c1_last_sequence_ = 0;
        c1_sequence_history_count_ = 0;
        c1_sequence_history_root_ = EmptyBtcVeldC1SequenceHistory();
        redeem_commitment_count_ = 0;
        redeem_commitment_root_ = EmptyBtcVeldRedeemCommitment();
        redeem_commitment_processed_height_ = 0;
        redeem_commitment_processed_block_hash_ = ZeroHash();
    }

    int64_t GetBalance(const std::string& token_id, const std::string& address) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto key = token_id + ":" + address;
        auto it  = balances_.find(key);
        return it != balances_.end() ? it->second : 0;
    }

    int64_t GetSupply(const std::string& token_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = supply_.find(token_id);
        return it != supply_.end() ? it->second : 0;
    }

    BtcVeldMintAccumulator GetBtcVeldMintAccumulator() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return BtcVeldMintAccumulator{
            mint_nullifier_root_, mint_nullifier_count_,
            mint_effect_root_, mint_effect_count_,
            mint_accumulator_processed_height_,
            mint_accumulator_processed_block_hash_};
    }

    BtcVeldC1SequenceState GetBtcVeldC1SequenceState() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return BtcVeldC1SequenceState{
            c1_last_sequence_, c1_sequence_history_count_,
            c1_sequence_history_root_};
    }

    BtcVeldRedeemCommitment GetBtcVeldRedeemCommitment() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return BtcVeldRedeemCommitment{
            redeem_commitment_count_, redeem_commitment_root_,
            redeem_commitment_processed_height_,
            redeem_commitment_processed_block_hash_};
    }

    // Exact issuer-mint ceiling for this ledger's current state at `height`.
    // The lock covers supply and recent_work_ together, so callers never combine
    // observations from different block states. If expected next-block bits are
    // supplied, the query simulates ProcessBlock's append/oldest-evict step; RPC
    // uses that form at tier-window boundaries. Consensus remains authoritative
    // when the transaction is eventually mined.
    BtcVeldIssuerMintCapacity GetBtcVeldIssuerMintCapacity(
            uint64_t height,
            std::optional<uint32_t> prospective_block_bits = std::nullopt) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return IssuerMintCapacityLocked_(height, prospective_block_bits);
    }

    BtcVeldC1ReservationStatus GetBtcVeldC1Reservation(
            const std::string& request_id, uint64_t height) const {
        std::lock_guard<std::mutex> lock(mutex_);
        BtcVeldC1ReservationStatus status;
        status.query_height = height;
        auto it = c1_reservations_.find(request_id);
        if (it == c1_reservations_.end()) return status;
        status.found = true;
        status.reservation = it->second;
        status.active = it->second.funded ||
            (it->second.exposed
                ? height <= it->second.funding_expires_height
                : height <= it->second.expires_height);
        return status;
    }

    std::vector<TokenTransferRecord> GetHistory(const std::string& address, int limit = 20) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<TokenTransferRecord> result;
        for (auto it = history_.rbegin(); it != history_.rend(); ++it) {
            if (it->from == address || it->to == address) {
                result.push_back(*it);
                if ((int)result.size() >= limit) break;
            }
        }
        return result;
    }

    std::vector<TokenTransferRecord> GetAllHistory(int limit = 50) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<TokenTransferRecord> result;
        int start = std::max(0, (int)history_.size() - limit);
        for (int i = (int)history_.size()-1; i >= start; --i)
            result.push_back(history_[i]);
        return result;
    }

    // Compatibility view for local token-ledger callers only.  Production
    // payout discovery MUST use the node's persistent RedeemObligationIndex:
    // history_ is intentionally bounded UI history and cannot be an
    // obligation authority.  Keeping this method bounded also prevents a
    // lifetime list of derived burns from inflating consensus memory/digests.
    std::vector<TokenTransferRecord> GetRedeems(uint64_t max_height) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<TokenTransferRecord> out;
        for (const auto& r : history_)
            if (r.is_redeem && r.token_id == BTCVELD_TOKEN_ID &&
                r.block_height <= max_height) out.push_back(r);
        std::sort(out.begin(), out.end(),
                  [](const TokenTransferRecord& a,
                     const TokenTransferRecord& b) {
                      if (a.block_height != b.block_height)
                          return a.block_height < b.block_height;
                      if (a.txid != b.txid) return a.txid < b.txid;
                      return a.vout < b.vout;
                  });
        return out;
    }

    std::vector<OnChainTokenInfo> ListTokens() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<OnChainTokenInfo> result;
        for (auto& [id, t] : tokens_) result.push_back(t);
        return result;
    }

    bool CanMint(const std::string& token_id, const std::string& address) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tokens_.find(token_id);
        return it != tokens_.end() && it->second.issuer == address;
    }

    Hash256 Digest() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<uint8_t> body;
        namespace sd = ::veld::state_digest;

        // Encoding v8 adds the fixed-width canonical reserve state.  Builds
        // without the fresh-genesis reserve profile retain byte-exact v7.
        // Encoding v7 commits every token-ledger field that can change a
        // future consensus decision plus the canonical redeem count/root used
        // to authenticate the derived payout index.  In particular, the
        // trailing work window drives the launch-active btcVELD issuer tier
        // ladder; two ledgers with equal balances/supply but different windows
        // must not report the same state digest.
        sd::put_u32_le(body,
            btcveld::reserve::TRANSITION_V1_REQUIRED ? 8u : 7u);

        {
            std::vector<std::string> keys;
            keys.reserve(tokens_.size());
            for (const auto& [k, _v] : tokens_) keys.push_back(k);
            std::sort(keys.begin(), keys.end());
            sd::put_u32_le(body, (uint32_t)keys.size());
            for (const auto& k : keys) {
                const auto& info = tokens_.at(k);
                sd::put_len_prefixed(body, k);
                sd::put_len_prefixed(body, info.id);
                sd::put_len_prefixed(body, info.name);
                sd::put_len_prefixed(body, info.issuer);
                sd::put_len_prefixed(body, info.peg_asset);
                sd::put_u8(body, info.decimals);
            }
        }
        {
            std::vector<std::string> keys;
            keys.reserve(supply_.size());
            for (const auto& [k, _v] : supply_) keys.push_back(k);
            std::sort(keys.begin(), keys.end());
            sd::put_u32_le(body, (uint32_t)keys.size());
            for (const auto& k : keys) {
                sd::put_len_prefixed(body, k);
                sd::put_u64_le(body, (uint64_t)supply_.at(k));   // int64 sats, always >= 0
            }
        }
        {
            std::vector<std::string> keys;
            keys.reserve(balances_.size());
            for (const auto& [k, _v] : balances_) keys.push_back(k);
            std::sort(keys.begin(), keys.end());
            sd::put_u32_le(body, (uint32_t)keys.size());
            for (const auto& k : keys) {
                sd::put_len_prefixed(body, k);
                sd::put_u64_le(body, (uint64_t)balances_.at(k));  // int64 sats, always >= 0
            }
        }
        // §5b drain-guard accumulator — ACTIVE-ONLY at compile time: while the
        // guard is dormant (ACTIVATION_HEIGHT == 0) nothing is serialized, so
        // this build's D_tokens is byte-identical to pre-guard binaries (the
        // ANCHORS active-only pattern). Once armed, every node serializes the
        // same replay-derived pair.
        if constexpr (BTCVELD_REDEEM_GUARD_ACTIVATION_HEIGHT != 0) {
            sd::put_u64_le(body, redeem_window_id_);
            sd::put_u64_le(body, (uint64_t)redeemed_in_window_);
        }
        // Canonical issuer/SPV exact-outpoint and accepted-effect replay
        // accumulators. The sparse root authenticates membership; the parallel
        // rolling root authenticates the exact height/tx/vout/txid locator and
        // ordering that caused each insertion. The fixed-size sparse root is
        // the exact set commitment; count is
        // independently advanced once per successful insertion and prevents a
        // malformed/recovery path from presenting an unexplained root alone.
        if constexpr (BTCVELD_MINT_DEPOSIT_ID_ACTIVATION_HEIGHT != 0) {
            sd::put_bytes(body, mint_nullifier_root_.data(),
                          mint_nullifier_root_.size());
            sd::put_u64_le(body, mint_nullifier_count_);
            sd::put_bytes(body, mint_effect_root_.data(),
                          mint_effect_root_.size());
            sd::put_u64_le(body, mint_effect_count_);
        }

        // Constant-state lifetime C1 replay authority. Every C1R1 must advance
        // the strict uint64 sequence by exactly one, so an expired or consumed
        // request can never be replayed without retaining an unbounded set.
        sd::put_u64_le(body, c1_last_sequence_);
        sd::put_u64_le(body, c1_sequence_history_count_);
        sd::put_bytes(body, c1_sequence_history_root_.data(),
                      c1_sequence_history_root_.size());

        // Active C1R1 leases are consensus capacity. Sort by request id so
        // creation order and unordered-map iteration cannot change D_tokens.
        // Neither marker stores the undisclosed P2TR script; only its exact
        // allocation commitment is consensus-visible until C1F1 opens it.
        {
            std::vector<std::string> keys;
            keys.reserve(c1_reservations_.size());
            for (const auto& [request_id, _r] : c1_reservations_)
                keys.push_back(request_id);
            std::sort(keys.begin(), keys.end());
            sd::put_u32_le(body, static_cast<uint32_t>(keys.size()));
            for (const auto& request_id : keys) {
                const auto& r = c1_reservations_.at(request_id);
                sd::put_len_prefixed(body, r.allocation_id);
                sd::put_u64_le(body, r.sequence);
                sd::put_len_prefixed(body, r.recipient);
                sd::put_len_prefixed(body, r.allocation_commitment);
                sd::put_u64_le(body, static_cast<uint64_t>(r.amount_sats));
                sd::put_u64_le(body, r.created_height);
                sd::put_u64_le(body, r.expires_height);
                sd::put_u8(body, r.exposed ? 1 : 0);
                sd::put_u64_le(body, r.exposed_height);
                sd::put_u64_le(body, r.funding_starts_height);
                sd::put_u64_le(body, r.funding_expires_height);
                sd::put_u8(body, r.funded ? 1 : 0);
                sd::put_u64_le(body, r.funded_height);
                sd::put_len_prefixed(body, r.funding_outpoint);
            }
        }

        // The order is consensus-relevant: the oldest element is evicted when
        // the next block arrives, so a sorted/multiset commitment would still
        // permit equal digests followed by different tier decisions.
        sd::put_u32_le(body, (uint32_t)recent_work_.size());
        for (uint64_t work : recent_work_)
            sd::put_u64_le(body, work);

        // Constant-space completeness authority for the derived redemption
        // index.  The processed tip identity is deliberately excluded: it is a
        // transient RPC race guard, while count/root are the replay-derived
        // state authenticated by D_tokens.
        sd::put_u64_le(body, redeem_commitment_count_);
        sd::put_bytes(body, redeem_commitment_root_.data(),
                      redeem_commitment_root_.size());

        if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED) {
            const std::vector<uint8_t> reserve_bytes =
                btcveld::reserve::EncodeState(reserve_state_);
            sd::put_bytes(body, reserve_bytes.data(), reserve_bytes.size());
        }

        // `history_`, `last_block_redeems_`, and the persistent btcVELD redeem
        // index remain derived/transient views rather than independent state.
        // Their lifetime contents are represented by the bounded count/root,
        // not serialized into consensus memory.
        return sd::sha256_domain(
            btcveld::reserve::TRANSITION_V1_REQUIRED
                ? sd::tags::TOKENS_RESERVE_V1
                : sd::tags::TOKENS,
            body);
    }

    static std::string JsonEscape(const std::string& s) {
        return json::EscapeStringBytes(s);
    }

    std::string TransferToJSON(const TokenTransferRecord& t) const {
        std::ostringstream j;
        j << "{\"txid\":\"" << JsonEscape(t.txid) << "\""
          << ",\"vout\":" << (uint64_t)t.vout
          << ",\"token\":\"" << JsonEscape(t.token_id) << "\""
          << ",\"from\":\"" << JsonEscape(t.from) << "\""
          << ",\"to\":\"" << JsonEscape(t.to) << "\""
          << ",\"amount_sats\":" << t.amount
          << ",\"block\":" << t.block_height
          << ",\"time\":" << (uint64_t)t.timestamp
          << ",\"memo\":\"" << JsonEscape(t.memo) << "\""
          << ",\"is_mint\":" << (t.is_mint ? "true" : "false")
          << ",\"is_burn\":" << (t.is_burn ? "true" : "false")
          << ",\"is_redeem\":" << (t.is_redeem ? "true" : "false")
          << "}";
        return j.str();
    }

    // Atomic block-state snapshot and restore. Captures every
    // block-mutable data member (never the mutex, never the node-owned btc_headers_
    // back-pointer) so the block-connect path can roll this ledger back verbatim
    // when a later module in the same block fails — all-or-nothing commit, no
    // partial state. Transient members (history_ / last_block_redeems_ /
    // recent_work_) are captured too, so a rejected block leaves ZERO residue.
    // Snapshot/restore must preserve Digest() byte-for-byte so every
    // consensus-visible member remains covered.
    struct StateSnapshot {
        std::unordered_map<std::string, OnChainTokenInfo> tokens;
        std::unordered_map<std::string, int64_t>          balances;
        std::unordered_map<std::string, int64_t>          supply;
        std::unordered_map<std::string, BtcVeldC1Reservation>
                                                          c1_reservations;
        std::vector<TokenTransferRecord>                  history;
        std::vector<TokenTransferRecord>                  last_block_redeems;
        std::vector<BtcVeldMintTransition>                last_block_mint_transitions;
        std::vector<BtcVeldReservePayoutTransition>       last_block_reserve_payouts;
        uint8_t                                           last_block_reserve_edges = 0;
        btcveld::reserve::State                           reserve_state;
        uint64_t                                          redeem_window_id   = 0;
        int64_t                                           redeemed_in_window = 0;
        std::deque<uint64_t>                              recent_work;
        bool                                              needs_rebuild      = false;
        Hash256                                           mint_nullifier_root = btcnull::EmptyRoot();
        uint64_t                                          mint_nullifier_count = 0;
        Hash256                                           mint_effect_root = EmptyBtcVeldMintEffectCommitment();
        uint64_t                                          mint_effect_count = 0;
        uint64_t                                          mint_accumulator_processed_height = 0;
        Hash256                                           mint_accumulator_processed_block_hash{};
        uint64_t                                          c1_last_sequence = 0;
        uint64_t                                          c1_sequence_history_count = 0;
        Hash256                                           c1_sequence_history_root = EmptyBtcVeldC1SequenceHistory();
        uint64_t                                          redeem_commitment_count = 0;
        Hash256                                           redeem_commitment_root = EmptyBtcVeldRedeemCommitment();
        uint64_t                                          redeem_commitment_processed_height = 0;
        Hash256                                           redeem_commitment_processed_block_hash{};
    };
    StateSnapshot SnapshotState() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return StateSnapshot{ tokens_, balances_, supply_, c1_reservations_,
                              history_,
                              last_block_redeems_,
                              last_block_mint_transitions_,
                              last_block_reserve_payouts_,
                              last_block_reserve_edges_,
                              reserve_state_,
                              redeem_window_id_,
                              redeemed_in_window_, recent_work_, needs_rebuild_,
                              mint_nullifier_root_, mint_nullifier_count_,
                              mint_effect_root_, mint_effect_count_,
                              mint_accumulator_processed_height_,
                              mint_accumulator_processed_block_hash_,
                              c1_last_sequence_,
                              c1_sequence_history_count_,
                              c1_sequence_history_root_,
                              redeem_commitment_count_, redeem_commitment_root_,
                              redeem_commitment_processed_height_,
                              redeem_commitment_processed_block_hash_ };
    }
    void RestoreState(const StateSnapshot& s) {
        std::lock_guard<std::mutex> lock(mutex_);
        tokens_             = s.tokens;
        balances_           = s.balances;
        supply_             = s.supply;
        c1_reservations_    = s.c1_reservations;
        history_            = s.history;
        last_block_redeems_ = s.last_block_redeems;
        last_block_mint_transitions_ = s.last_block_mint_transitions;
        last_block_reserve_payouts_ = s.last_block_reserve_payouts;
        last_block_reserve_edges_ = s.last_block_reserve_edges;
        reserve_state_ = s.reserve_state;
        redeem_window_id_   = s.redeem_window_id;
        redeemed_in_window_ = s.redeemed_in_window;
        recent_work_        = s.recent_work;
        needs_rebuild_      = s.needs_rebuild;
        mint_nullifier_root_ = s.mint_nullifier_root;
        mint_nullifier_count_ = s.mint_nullifier_count;
        mint_effect_root_ = s.mint_effect_root;
        mint_effect_count_ = s.mint_effect_count;
        mint_accumulator_processed_height_ =
            s.mint_accumulator_processed_height;
        mint_accumulator_processed_block_hash_ =
            s.mint_accumulator_processed_block_hash;
        c1_last_sequence_ = s.c1_last_sequence;
        c1_sequence_history_count_ = s.c1_sequence_history_count;
        c1_sequence_history_root_ = s.c1_sequence_history_root;
        redeem_commitment_count_ = s.redeem_commitment_count;
        redeem_commitment_root_ = s.redeem_commitment_root;
        redeem_commitment_processed_height_ =
            s.redeem_commitment_processed_height;
        redeem_commitment_processed_block_hash_ =
            s.redeem_commitment_processed_block_hash;
        // Node-owned BTC-header and redeem-covenant back-pointers are not
        // block state and remain bound across snapshot restoration.
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, OnChainTokenInfo>    tokens_;
    std::unordered_map<std::string, int64_t>             balances_;   // "token:addr" -> sats
    std::unordered_map<std::string, int64_t>             supply_;     // "token" -> sats
    std::unordered_map<std::string, BtcVeldC1Reservation>
                                                            c1_reservations_;
    std::vector<TokenTransferRecord>                     history_;
    std::vector<TokenTransferRecord>                     last_block_redeems_;     // transient redeem-covenant feed
    std::vector<BtcVeldMintTransition>                   last_block_mint_transitions_; // derived proof-index feed
    std::vector<BtcVeldReservePayoutTransition>          last_block_reserve_payouts_;
    uint8_t                                              last_block_reserve_edges_ = 0;
    btcveld::reserve::State                              reserve_state_{};
    uint64_t                                             redeem_window_id_   = 0; // §5b drain guard: window of the last guarded REDEEM (lazy-rolled on chain ops only)
    int64_t                                              redeemed_in_window_ = 0; // §5b drain guard: sats redeemed so far in that window
    std::deque<uint64_t>                                 recent_work_;            // §3.2 tier ladder: ordered trailing work window (committed by the token digest)
    bool                                                 needs_rebuild_ = false;
    Hash256                                              mint_nullifier_root_ = btcnull::EmptyRoot();
    uint64_t                                             mint_nullifier_count_ = 0;
    Hash256                                              mint_effect_root_ = EmptyBtcVeldMintEffectCommitment();
    uint64_t                                             mint_effect_count_ = 0;
    uint64_t                                             mint_accumulator_processed_height_ = 0;
    Hash256                                              mint_accumulator_processed_block_hash_{};
    uint64_t                                             c1_last_sequence_ = 0;
    uint64_t                                             c1_sequence_history_count_ = 0;
    Hash256                                              c1_sequence_history_root_ = EmptyBtcVeldC1SequenceHistory();
    uint64_t                                             redeem_commitment_count_ = 0;
    Hash256                                              redeem_commitment_root_ = EmptyBtcVeldRedeemCommitment();
    uint64_t                                             redeem_commitment_processed_height_ = 0;
    Hash256                                              redeem_commitment_processed_block_hash_{};
    btcspv::BtcHeaderChain*                              btc_headers_ = nullptr;  // node-owned SPV state
    const btcveld::SignerBondCovenant*                   redeem_covenant_ = nullptr; // node-owned read-only request view
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
    bool dstate_account_floor_baseline_for_benchmark_ = false;
#endif

    void RegisterTokenLocked(const OnChainTokenInfo& info) {
        tokens_[info.id] = info;
    }

    // §3.2 tier ladder: trailing-MINIMUM per-block work over the window — the
    // sustained-difficulty metric. A FULL window is required (a young/partial window
    // returns 0 => the pilot floor only): the security claim is "hashrate held for the
    // whole window," which a partial window cannot attest. `min` (not avg/sum) is what
    // makes a brief spike worthless — one low block vetoes the tier. Caller holds mutex_.
    uint64_t SustainedWorkLocked_(
            std::optional<uint32_t> prospective_block_bits = std::nullopt) const {
        const size_t extra = prospective_block_bits.has_value() ? 1u : 0u;
        const size_t total = recent_work_.size() + extra;
        if (total < BTCVELD_TIER_WINDOW_BLOCKS) return 0;
        // ProcessBlock appends then evicts the oldest element. Simulate that
        // exact ordering for RPC's expected next block without mutating state.
        const size_t skip = total - BTCVELD_TIER_WINDOW_BLOCKS;
        uint64_t m = UINT64_MAX;
        for (size_t i = skip; i < recent_work_.size(); ++i)
            if (recent_work_[i] < m) m = recent_work_[i];
        if (prospective_block_bits) {
            uint64_t w = BlockWorkForTier(*prospective_block_bits);
            if (w < m) m = w;
        }
        return m;
    }

    void PruneC1ReservationsLocked_(uint64_t height) {
        for (auto it = c1_reservations_.begin();
             it != c1_reservations_.end();) {
            const bool expired = it->second.exposed
                ? (!it->second.funded &&
                   it->second.funding_expires_height < height)
                : it->second.expires_height < height;
            if (expired)
                it = c1_reservations_.erase(it);
            else
                ++it;
        }
    }

    int64_t ReservedC1SatsLocked_(uint64_t height) const {
        int64_t total = 0;
        for (const auto& [request_id, reservation] : c1_reservations_) {
            (void)request_id;
            if (!reservation.funded &&
                (reservation.exposed
                    ? reservation.funding_expires_height < height
                    : reservation.expires_height < height))
                continue;
            if (reservation.amount_sats <= 0 ||
                total > INT64_MAX - reservation.amount_sats)
                return INT64_MAX;
            total += reservation.amount_sats;
        }
        return total;
    }

    BtcVeldIssuerMintCapacity IssuerMintCapacityLocked_(
            uint64_t height,
            std::optional<uint32_t> prospective_block_bits = std::nullopt) const {
        BtcVeldIssuerMintCapacity c;
        c.height = height;
        auto sit = supply_.find(BTCVELD_TOKEN_ID);
        c.current_supply_sats = (sit != supply_.end()) ? sit->second : 0;
        c.includes_prospective_block = prospective_block_bits.has_value();
        c.prospective_block_bits = prospective_block_bits.value_or(0);
        c.sustained_work = SustainedWorkLocked_(prospective_block_bits);
        c.tier_ladder_active = BtcVeldTierLadderActive(height);

        // A negative supply is impossible in valid state; fail closed rather
        // than allowing subtraction from it to manufacture apparent headroom.
        if (c.current_supply_sats < 0) return c;
        c.effective_ceiling_sats = c.tier_ladder_active
            ? tierladder::EffectiveMintCeiling(
                  c.static_ceiling_sats, c.current_supply_sats,
                  c.sustained_work)
            : c.static_ceiling_sats;
        c.reserved_sats = ReservedC1SatsLocked_(height);
        if (c.reserved_sats >= 0 &&
            c.current_supply_sats <= c.effective_ceiling_sats &&
            c.reserved_sats <=
                c.effective_ceiling_sats - c.current_supply_sats)
            c.remaining_sats =
                c.effective_ceiling_sats - c.current_supply_sats -
                c.reserved_sats;
        return c;
    }

public:
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
    // Qualification-only instance switch for S2's pre-floor comparison. The
    // setter and every reader take mutex_, so a benchmark cannot race a live
    // preflight/write. This is harness configuration rather than consensus
    // state and is intentionally absent from StateSnapshot.
    void SetDStateAccountFloorBaselineForBenchmark(bool enabled) {
        std::lock_guard<std::mutex> lock(mutex_);
        dstate_account_floor_baseline_for_benchmark_ = enabled;
    }
#endif

    // AMM-authorized btcVELD move (NO signature). Only the AMM consensus
    // validator calls this, and only after fully validating a pool op; it moves
    // reserve btcVELD between the pool address and a user for swap/add/remove
    // legs that no private key can sign (the pool holds btcVELD but owns no key).
    // Supply-neutral (a move, never mint/burn). Returns false if `from` is short.
    bool AmmMove(const std::string& token_id, const std::string& from,
                 const std::string& to, int64_t amount) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!AmmMoveAllowedLocked_(token_id, from, to, amount)) return false;
        const std::string fk = token_id + ":" + from;
        const std::string tk = token_id + ":" + to;
        auto from_it = balances_.find(fk);
        if (fk == tk) return true;
        auto to_it = balances_.find(tk);
        const int64_t from_balance = from_it->second;
        const int64_t to_balance = to_it == balances_.end() ? 0 : to_it->second;
        const int64_t remaining = from_balance - amount;
        if (remaining == 0) balances_.erase(from_it);
        else from_it->second = remaining;
        balances_[tk] = to_balance + amount;
        return true;
    }

    // Pure AMM preflight. ValidateBlock and ProcessBlock must agree on every
    // balance-floor and overflow decision; otherwise an unexecutable quote can
    // occupy the singleton AMM mempool slot.
    bool CanAmmMove(const std::string& token_id, const std::string& from,
                    const std::string& to, int64_t amount) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return AmmMoveAllowedLocked_(token_id, from, to, amount);
    }
private:

    static bool IsReservePublicFamilyLocked_(const std::string& data) {
        if constexpr (!btcveld::reserve::TRANSITION_V1_REQUIRED) {
            (void)data;
            return false;
        }
        // In the fresh profile, reserve-version lookalikes are strict too:
        // only the exact RSV1 carrier can execute, and an unknown/malformed
        // RSV family cannot hide beside another stateful token marker.
        return data.rfind("VELD_RSV", 0) == 0;
    }

    static bool IsReserveIssuerCarrierLocked_(const TokenOpData& op) {
        return op.token_id == BTCVELD_TOKEN_ID && op.action == "MINT" &&
               op.memo.rfind(btcveld::reserve::ISSUER_MEMO_PREFIX, 0) == 0;
    }

    static bool RawClaimsBtcVeldTokenFamilyLocked_(
            const std::string& data) {
        if (data.rfind(TOKEN_OP_RETURN_PREFIX, 0) != 0) return false;
        const size_t action_begin = TOKEN_OP_RETURN_PREFIX.size();
        const size_t action_end = data.find('|', action_begin);
        if (action_end == std::string::npos) return false;
        const size_t token_end = data.find('|', action_end + 1);
        return token_end != std::string::npos &&
               data.compare(action_end + 1,
                            token_end - action_end - 1,
                            BTCVELD_TOKEN_ID) == 0;
    }

    static size_t CountReserveTransitionCarriersLocked_(
            const Transaction& tx) {
        size_t count = 0;
        for (const auto& output : tx.outputs) {
            const std::string data = ParseOpReturn(output.script_pubkey);
            if (IsReservePublicFamilyLocked_(data)) {
                ++count;
                continue;
            }
            if (data.rfind(TOKEN_OP_RETURN_PREFIX, 0) != 0) continue;
            const auto op = DecodeTokenOp(data);
            if (op && IsReserveIssuerCarrierLocked_(*op)) ++count;
        }
        return count;
    }

    static bool HasReserveSensitiveMarkerLocked_(const Transaction& tx) {
        for (const auto& output : tx.outputs) {
            const std::string data = ParseOpReturn(output.script_pubkey);
            if (IsReservePublicFamilyLocked_(data) ||
                data.rfind("VELD_MSPV|", 0) == 0)
                return true;
            if (data.rfind(TOKEN_OP_RETURN_PREFIX, 0) != 0) continue;
            const auto op = DecodeTokenOp(data);
            if (!op || op->token_id != BTCVELD_TOKEN_ID) {
                if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED) {
                    if (RawClaimsBtcVeldTokenFamilyLocked_(data)) return true;
                }
                continue;
            }
            if (op->action == "MINT" || op->action == "REDEEM" ||
                op->action == "RESERVE" || op->action == "EXPOSE" ||
                op->action == "CANCEL" || op->action == "FUND")
                return true;
        }
        return false;
    }

    static bool HasC1ReservationMarkerLocked_(const Transaction& tx) {
        for (const auto& output : tx.outputs) {
            const std::string data = ParseOpReturn(output.script_pubkey);
            if (data.rfind(TOKEN_OP_RETURN_PREFIX, 0) != 0) continue;
            const auto op = DecodeTokenOp(data);
            if (!op || op->token_id != BTCVELD_TOKEN_ID) {
                if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED) {
                    if (RawClaimsBtcVeldTokenFamilyLocked_(data)) return true;
                }
                continue;
            }
            if (op->action == "RESERVE" || op->action == "EXPOSE" ||
                op->action == "CANCEL" || op->action == "FUND")
                return true;
            // MNP2 is an allocation's terminal consensus transition. Treat
            // every carrier claiming that namespace as strict, even when its
            // opening or sparse-nullifier proof is stale/malformed: a miner
            // must not confirm an issuer-signed funded carrier as a paid no-op.
            if (op->action == "MINT" &&
                op->memo.rfind(btcnull::RESERVED_ISSUER_MEMO_PREFIX, 0) == 0)
                return true;
        }
        return false;
    }

    bool AmmMoveAllowedLocked_(const std::string& token_id,
                               const std::string& from,
                               const std::string& to,
                               int64_t amount) const {
        if (amount <= 0 || from.empty() || to.empty() ||
            !tokens_.count(token_id)) return false;
        const std::string fk = token_id + ":" + from;
        const std::string tk = token_id + ":" + to;
        const auto from_it = balances_.find(fk);
        const int64_t from_balance =
            from_it == balances_.end() ? 0 : from_it->second;
        if (from_balance < amount) return false;
        if (fk == tk) return true;
        const auto to_it = balances_.find(tk);
        const int64_t to_balance =
            to_it == balances_.end() ? 0 : to_it->second;
        if (to_balance < 0 || to_balance > INT64_MAX - amount)
            return false;
        const int64_t from_after = from_balance - amount;
        const int64_t to_after = to_balance + amount;
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
        if (dstate_account_floor_baseline_for_benchmark_)
            return from_after >= 0 && to_after >= 0;
#endif
        return BalanceAdmissible(from_after) && BalanceAdmissible(to_after);
    }

    static bool IsC1CompletionMintLocked_(const TokenOpData& op) {
        return op.action == "MINT" &&
               op.memo.rfind(
                   btcnull::RESERVED_ISSUER_MEMO_PREFIX, 0) == 0;
    }

    static bool HasForbiddenBtcVeldMarkerLocked_(
            const Transaction& tx, const BtcVeldPegGateState& peg_gate) {
        for (const auto& output : tx.outputs) {
            const std::string data = ParseOpReturn(output.script_pubkey);
            if (data.rfind("VELD_MSPV|", 0) == 0) {
                if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED)
                    return true;
                if (!peg_gate.MintAllowed()) return true;
                // Keep scanning.  A permitted MSPV marker must not hide a
                // later forbidden btcVELD marker if the gate ever gains
                // independently controlled permissions.
                continue;
            }
            if (data.rfind(TOKEN_OP_RETURN_PREFIX, 0) != 0) continue;
            const auto op = DecodeTokenOp(data);
            if (!op || op->token_id != BTCVELD_TOKEN_ID) continue;
            if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED) {
                if (op->action == "RESERVE" || op->action == "EXPOSE" ||
                    op->action == "CANCEL" || op->action == "FUND")
                    return true;
                if (op->action == "MINT" &&
                    !IsReserveIssuerCarrierLocked_(*op))
                    return true;
            }
            const bool reserved_completion =
                IsC1CompletionMintLocked_(*op);
            if (((op->action == "RESERVE" || op->action == "EXPOSE" ||
                  (op->action == "MINT" && !reserved_completion)) &&
                 !peg_gate.MintAllowed()) ||
                (op->action == "FUND" && !peg_gate.FundingAllowed()) ||
                ((op->action == "CANCEL" || reserved_completion) &&
                 !peg_gate.CompletionAllowed()))
                return true;
            if (op->action == "REDEEM" && !peg_gate.RedeemAllowed())
                return true;
        }
        return false;
    }

    // Activation gate: register btcVELD from the compile constants at
    // BTCVELD_ACTIVATION_HEIGHT, IFF an issuer is configured. Empty issuer =>
    // launch profile inactive => no-op => state digest unchanged. Re-applied on
    // reorg replay because Reset() clears tokens_.
    void MaybeRegisterBtcVeld(uint64_t height) {   // caller holds mutex_
        if (BTCVELD_ISSUER_ADDRESS[0] == '\0') return;
        if (height < BTCVELD_ACTIVATION_HEIGHT) return;
        if (tokens_.count(BTCVELD_TOKEN_ID)) return;
        RegisterTokenLocked({BTCVELD_TOKEN_ID, "Wrapped Bitcoin",
                             BTCVELD_ISSUER_ADDRESS, BTCVELD_DECIMALS, BTCVELD_PEG_ASSET});
    }

    // Apply the at-most-one TOKEN/MSPV marker in a transaction.  Returning a
    // verdict (instead of relying on digest comparison) is important because a
    // valid self-transfer is intentionally state-neutral, while every block
    // advances the tier-work window even when a marker is invalid.
    bool ApplyTransactionMarkersLocked_(const Transaction& tx, uint64_t height,
                                        bool spv_on,
                                        const BtcVeldPegGateState& peg_gate,
                                        bool require_marker = false,
                                        bool token_authorization_prevalidated =
                                            false,
                                        uint32_t tx_index = UINT32_MAX) {
        // Establish the transaction grammar before invoking either stateful
        // transition.  Consensus deliberately treats an invalid TOKEN/MSPV
        // request as a paid no-op, so discovering a second marker after a
        // valid first marker has already moved balances/supply/nullifiers would
        // violate that whole-transaction no-op rule.  It also made mempool
        // simulation reject the carrier while retaining its first marker's
        // mutation in the trial frame, corrupting later candidate decisions.
        // Count both valid and malformed family-prefixed carriers: malformed
        // prefixes cannot be used to hide an executable suffix marker.
        size_t marker_count = 0;
        for (const auto& out : tx.outputs) {
            const std::string data = ParseOpReturn(out.script_pubkey);
            if (data.rfind("VELD_MSPV|", 0) != 0 &&
                !IsReservePublicFamilyLocked_(data) &&
                data.rfind(TOKEN_OP_RETURN_PREFIX, 0) != 0)
                continue;
            if (++marker_count != 1) return false;
        }
        if (require_marker && marker_count != 1) return false;

        // At most one stateful call is now reachable.  Every false verdict is
        // therefore mutation-free; successful transitions publish exactly
        // once.  Keep a separate `applied` flag rather than incrementing the
        // already-established grammar count during execution.
        bool applied = false;
        std::unordered_map<std::string, bool> signer_cache;
        for (uint32_t vout = 0; vout < tx.outputs.size(); ++vout) {
            const auto& out = tx.outputs[vout];
            const std::string data = ParseOpReturn(out.script_pubkey);
            if (IsReservePublicFamilyLocked_(data)) {
                if constexpr (!btcveld::reserve::TRANSITION_V1_REQUIRED) {
                    return false;
                } else {
                    if (applied || data.rfind(
                            btcveld::reserve::PUBLIC_CARRIER_PREFIX, 0) != 0)
                        return false;
                    const std::vector<uint8_t> proof = BtcVeldHex_(
                        data.c_str() + std::strlen(
                            btcveld::reserve::PUBLIC_CARRIER_PREFIX));
                    if (proof.empty() || data !=
                            std::string(btcveld::reserve::PUBLIC_CARRIER_PREFIX) +
                            BytesToHex(proof) ||
                        !MaybeApplyReserveTransitionLocked_(
                            proof, nullptr, tx, height, peg_gate, tx_index,
                            vout, &signer_cache,
                            token_authorization_prevalidated))
                        return false;
                    applied = true;
                    continue;
                }
            }
            if (data.rfind("VELD_MSPV|", 0) == 0) {
                if (applied || !spv_on ||
                    !MaybeApplySpvMint(data, tx, height, tx_index, vout))
                    return false;
                applied = true;
                continue;
            }
            if (data.rfind(TOKEN_OP_RETURN_PREFIX, 0) != 0) continue;
            if (applied) return false;
            const auto op = DecodeTokenOp(data);
            if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED) {
                if (op && IsReserveIssuerCarrierLocked_(*op)) {
                    const char* encoded = op->memo.c_str() +
                        std::strlen(btcveld::reserve::ISSUER_MEMO_PREFIX);
                    const std::vector<uint8_t> proof = BtcVeldHex_(encoded);
                    if (proof.empty() || op->memo !=
                            std::string(btcveld::reserve::ISSUER_MEMO_PREFIX) +
                            BytesToHex(proof) ||
                        !MaybeApplyReserveTransitionLocked_(
                            proof, &*op, tx, height, peg_gate, tx_index,
                            vout, &signer_cache,
                            token_authorization_prevalidated))
                        return false;
                    applied = true;
                    continue;
                }
            }
            if (!op || !ApplyTokenOp(*op, tx, height, peg_gate, vout,
                                     &signer_cache,
                                     token_authorization_prevalidated,
                                     tx_index))
                return false;
            applied = true;
        }
        return marker_count == 0 || applied;
    }

    bool MaybeApplyReserveTransitionLocked_(
            const std::vector<uint8_t>& proof,
            const TokenOpData* issuer_wrapper,
            const Transaction& veld_tx, uint64_t height,
            const BtcVeldPegGateState& peg_gate, uint32_t tx_index,
            uint32_t marker_vout,
            std::unordered_map<std::string, bool>* signer_cache,
            bool authorization_prevalidated) {
        if (!btcveld::reserve::TRANSITION_V1_REQUIRED ||
            proof.empty() || btc_headers_ == nullptr ||
            !tokens_.count(BTCVELD_TOKEN_ID))
            return false;

        // The issuer carrier is only an authenticated relay interface.  It
        // supplies no monetary facts: recipient, amount, prior state, and
        // Bitcoin transaction all come from the same RTP1 verifier used by
        // the permissionless public carrier.
        if (issuer_wrapper != nullptr) {
            const auto token = tokens_.find(BTCVELD_TOKEN_ID);
            if (issuer_wrapper->action != "MINT" ||
                issuer_wrapper->token_id != BTCVELD_TOKEN_ID ||
                issuer_wrapper->from.empty() || issuer_wrapper->to.empty() ||
                issuer_wrapper->amount <= 0 ||
                token == tokens_.end() ||
                token->second.issuer != issuer_wrapper->from ||
                (!authorization_prevalidated &&
                 !TxSignerAuthorized(veld_tx, issuer_wrapper->from,
                                     signer_cache)))
                return false;
        }

        btcveld::reserve::Claim decoded;
        if (!btcveld::reserve::DecodeProof(
                proof.data(), proof.size(), decoded))
            return false;
        const bool creates_exposure =
            decoded.operation == btcveld::reserve::Operation::OPEN ||
            decoded.operation == btcveld::reserve::Operation::DEPOSIT;
        if ((creates_exposure && !peg_gate.MintAllowed()) ||
            (!creates_exposure && !peg_gate.CompletionAllowed()))
            return false;

        btcveld::reserve::PayoutContext payout;
        if (decoded.operation == btcveld::reserve::Operation::PAYOUT) {
            if (redeem_covenant_ == nullptr) return false;
            const auto request =
                redeem_covenant_->FindOpenByCommitmentCopy(
                    decoded.exact_commitment);
            if (!request) return false;
            payout.present = true;
            payout.request_id = request->request_id;
            payout.request_commitment = request->request_commitment;
            payout.principal_sats = request->amount_sats;
            payout.destination_spk = request->dest_spk;
        }

        auto valid_recipient = [](const std::string& address) {
            return IsCanonicalTokenCreditAddress(address);
        };
        const auto supply_it = supply_.find(BTCVELD_TOKEN_ID);
        const int64_t supply_before_signed = supply_it == supply_.end()
            ? 0 : supply_it->second;
        if (supply_before_signed < 0) return false;
        const uint64_t supply_before =
            static_cast<uint64_t>(supply_before_signed);
        btcveld::reserve::Result verified = btcveld::reserve::Verify(
            *btc_headers_, reserve_state_, supply_before,
            proof.data(), proof.size(),
            BtcVeldCustodySpk(), BTCVELD_SPV_K_BTC,
            valid_recipient, payout);
        if (!verified.ok) return false;

        if (issuer_wrapper != nullptr &&
            ((verified.claim.operation != btcveld::reserve::Operation::OPEN &&
              verified.claim.operation != btcveld::reserve::Operation::DEPOSIT) ||
             verified.claim.mint_amount !=
                 static_cast<uint64_t>(issuer_wrapper->amount) ||
             verified.recipient != issuer_wrapper->to))
            return false;

        if (verified.claim.mint_amount > static_cast<uint64_t>(INT64_MAX) ||
            verified.claim.mint_amount >
                static_cast<uint64_t>(INT64_MAX - supply_before_signed))
            return false;
        const uint64_t supply_after = supply_before +
            verified.claim.mint_amount;

        int64_t balance_before = 0;
        std::string balance_key;
        if (verified.claim.mint_amount != 0) {
            balance_key = std::string(BTCVELD_TOKEN_ID) + ":" +
                          verified.recipient;
            const auto balance_it = balances_.find(balance_key);
            balance_before = balance_it == balances_.end()
                ? 0 : balance_it->second;
            const int64_t mint_signed =
                static_cast<int64_t>(verified.claim.mint_amount);
            if (balance_before < 0 ||
                balance_before > INT64_MAX - mint_signed ||
                !BalanceAdmissible(balance_before + mint_signed))
                return false;
        }

        const bool consumes_deposit =
            verified.claim.operation == btcveld::reserve::Operation::OPEN ||
            verified.claim.operation == btcveld::reserve::Operation::DEPOSIT;
        btcnull::InsertResult nullifier_insert;
        std::vector<uint8_t> nullifier_proof_bytes;
        if (consumes_deposit) {
            if (!verified.claim.has_nullifier_proof ||
                !IsValidBtcOutpointId(verified.pending_outpoint) ||
                mint_nullifier_count_ == UINT64_MAX ||
                (tx_index != UINT32_MAX &&
                 mint_effect_count_ == UINT64_MAX))
                return false;
            nullifier_insert = btcnull::Insert(
                mint_nullifier_root_, verified.pending_outpoint,
                verified.claim.nullifier_proof);
            if (!nullifier_insert.ok) return false;
            nullifier_proof_bytes = btcnull::EncodeProof(
                verified.claim.nullifier_proof);
            if (nullifier_proof_bytes.empty()) return false;
        }

        btcveld::reserve::State reserve_next = reserve_state_;
        if (!btcveld::reserve::ApplyAuthorized(
                reserve_next, verified, supply_before, supply_after))
            return false;

        if (verified.claim.mint_amount != 0) {
            const int64_t mint_signed =
                static_cast<int64_t>(verified.claim.mint_amount);
            balances_[balance_key] = balance_before + mint_signed;
            supply_[BTCVELD_TOKEN_ID] =
                static_cast<int64_t>(supply_after);

            TokenTransferRecord record{};
            record.txid = HashToHex(veld_tx.GetTxID());
            record.vout = marker_vout;
            record.token_id = BTCVELD_TOKEN_ID;
            record.from = "btc-reserve-transition";
            record.to = verified.recipient;
            record.amount = mint_signed;
            record.block_height = height;
            record.timestamp = std::time(nullptr);
            record.memo = verified.pending_outpoint;
            record.is_mint = true;
            history_.push_back(std::move(record));
            if (history_.size() > 2000) history_.erase(history_.begin());
        }

        if (consumes_deposit) {
            mint_nullifier_root_ = nullifier_insert.new_root;
            ++mint_nullifier_count_;
            BtcVeldMintTransition transition;
            transition.tx_index = tx_index;
            transition.marker_vout = marker_vout;
            transition.txid = HashToHex(veld_tx.GetTxID());
            transition.outpoint = verified.pending_outpoint;
            transition.proof = std::move(nullifier_proof_bytes);
            transition.old_root = nullifier_insert.old_root;
            transition.new_root = nullifier_insert.new_root;
            transition.effect_kind = "MINT";
            if (tx_index != UINT32_MAX) {
                mint_effect_root_ = ExtendBtcVeldMintEffectCommitment(
                    mint_effect_root_, height, transition);
                ++mint_effect_count_;
            }
            last_block_mint_transitions_.push_back(
                std::move(transition));
        }

        if (verified.claim.operation ==
                btcveld::reserve::Operation::PAYOUT) {
            last_block_reserve_payouts_.push_back(
                BtcVeldReservePayoutTransition{
                    verified.payout_request_id,
                    verified.claim.bitcoin_txid,
                    verified.payout_principal_sats,
                    verified.payout_destination_spk});
        }
        reserve_state_ = std::move(reserve_next);
        return true;
    }

    // A VELD_MSPV operation carries a hex-encoded MSP3 proof
    // (Bitcoin inclusion + canonical MNP1 nonmembership witness). The recipient + amount
    // are read FROM the proven deposit tx (never from the submitter), so a mint
    // can only credit the address its depositor committed on Bitcoin. NO issuer
    // signature. Caller holds mutex_ and has verified: gate active + btc_headers_
    // set + "VELD_MSPV|" prefix. Deterministic (pure fn of the header chain, the
    // op bytes, and compile constants) => identical on every node.
    bool MaybeApplySpvMint(const std::string& data, const Transaction& tx,
                           uint64_t height, uint32_t tx_index,
                           uint32_t marker_vout) {
        if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED) {
            (void)data; (void)tx; (void)height; (void)tx_index;
            (void)marker_vout;
            return false;
        }
        if (!tokens_.count(BTCVELD_TOKEN_ID) || btc_headers_ == nullptr)
            return false;                                          // btcVELD/header view unavailable
        std::vector<uint8_t> proof = BtcVeldHex_(data.c_str() + 10);   // after "VELD_MSPV|"
        if (proof.empty()) return false;                            // bad hex / empty
        // The binary MSP3/lineage/MNP1 proof is canonical, and its text carrier must be
        // canonical too.  BtcVeldHex_ deliberately accepts uppercase for other
        // legacy hex fields; requiring the exact lowercase re-encoding here
        // prevents two transaction encodings for the same mint witness.
        if (data != std::string("VELD_MSPV|") + BytesToHex(proof))
            return false;
        const auto supply_it = supply_.find(BTCVELD_TOKEN_ID);
        const int64_t signed_supply = supply_it == supply_.end() ? 0 : supply_it->second;
        if (signed_supply < 0) return false;
        const int64_t reserved_sats = ReservedC1SatsLocked_(height);
        if (reserved_sats < 0 || signed_supply > INT64_MAX - reserved_sats)
            return false;
        // VerifyDepositMint's custody-cap input is a prospective occupancy
        // value.  Active C1 leases are already promised capacity even though
        // they have not increased circulating supply yet.
        const uint64_t occupied_capacity =
            static_cast<uint64_t>(signed_supply + reserved_sats);
        auto valid_recipient = [](const std::string& a) {
            return IsCanonicalTokenCreditAddress(a);
        };
        btcspv::DepositResult r = btcspv::VerifyDepositMint(
            *btc_headers_, proof.data(), proof.size(),
            BtcVeldCustodySpk(), BTCVELD_SPV_K_BTC, occupied_capacity,
            BTCVELD_SPV_MAX_CUSTODY_SATS,
            valid_recipient);
        if (!r.ok) return false;                                   // fail-closed
        // Cross-path replay gate. VerifyDepositMint derives this exact txid:vout
        // from the proven transaction's unique custody output. Issuer MINT uses
        // the same canonical bitcoind-display identity in its memo, so whichever
        // path consumes it first makes the other a no-op. Credit and consume while
        // holding mutex_: supply and its replay identity change atomically.
        if (!BtcVeldMintDepositIdActive(height)) return false;       // fail closed on unsafe parameters
        if (!IsValidBtcOutpointId(r.outpoint_id)) return false;       // canonicalization invariant
        if (mint_nullifier_count_ == UINT64_MAX ||
            (tx_index != UINT32_MAX && mint_effect_count_ == UINT64_MAX))
            return false;
        const btcnull::InsertResult nullifier_insert = btcnull::Insert(
            mint_nullifier_root_, r.outpoint_id, r.nullifier_proof);
        if (!nullifier_insert.ok) return false; // stale witness or either path consumed it
        std::vector<uint8_t> nullifier_proof_bytes =
            btcnull::EncodeProof(r.nullifier_proof);
        if (nullifier_proof_bytes.empty()) return false;
        if (r.amount == 0 || r.amount > (uint64_t)INT64_MAX) return false;
        const int64_t amount = (int64_t)r.amount;
        const std::string balance_key =
            std::string(BTCVELD_TOKEN_ID) + ":" + r.recipient;
        const auto balance_it = balances_.find(balance_key);
        const int64_t old_balance =
            balance_it == balances_.end() ? 0 : balance_it->second;
        if (old_balance < 0 || old_balance > INT64_MAX - amount ||
            signed_supply > INT64_MAX - amount)
            return false;
        // D-STATE-01: a mint may not create a sub-floor account.
        if (!BalanceAdmissible(old_balance + (int64_t)amount)) return false;
        balances_[balance_key] = old_balance + amount;
        supply_[BTCVELD_TOKEN_ID] = signed_supply + amount;
        mint_nullifier_root_ = nullifier_insert.new_root;
        ++mint_nullifier_count_;
        TokenTransferRecord rec{};
        std::ostringstream hx;
        for (auto b : tx.GetTxID()) hx << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        rec.txid = hx.str(); rec.vout = 0; rec.token_id = BTCVELD_TOKEN_ID; rec.from = "btc-spv-deposit";
        rec.to = r.recipient; rec.amount = (int64_t)r.amount; rec.block_height = height;
        rec.timestamp = std::time(nullptr); rec.memo = r.outpoint_id;
        rec.is_mint = true; rec.is_burn = false; rec.is_redeem = false;
        history_.push_back(rec);
        if (history_.size() > 2000) history_.erase(history_.begin());
        BtcVeldMintTransition transition;
        transition.tx_index = tx_index;
        transition.marker_vout = marker_vout;
        transition.txid = HashToHex(tx.GetTxID());
        transition.outpoint = r.outpoint_id;
        transition.proof = std::move(nullifier_proof_bytes);
        transition.old_root = nullifier_insert.old_root;
        transition.new_root = nullifier_insert.new_root;
        transition.effect_kind = "MINT";
        // Candidate-policy simulations have no final block transaction index;
        // only ProcessBlock's accepted canonical transition advances the
        // locator commitment.
        if (tx_index != UINT32_MAX) {
            mint_effect_root_ = ExtendBtcVeldMintEffectCommitment(
                mint_effect_root_, height, transition);
            ++mint_effect_count_;
        }
        last_block_mint_transitions_.push_back(std::move(transition));
        return true;
    }

    // Require a verified signature; finding a public key in a sigless input is
    // not authorization. Delegates to the shared check in op_authorization.h.
    // op's `op.from` must have actually signed an input of this transaction.
    static bool TxInputMatchesAddress(const Transaction& tx,
                                       const std::string& address) {
        return TxVerifiedSignedBy(tx, address);
    }

    static bool TxSignerAuthorized(
            const Transaction& tx, const std::string& address,
            std::unordered_map<std::string, bool>* cache) {
        if (!cache) return TxInputMatchesAddress(tx, address);
        auto it = cache->find(address);
        if (it != cache->end()) return it->second;
        const bool valid = TxInputMatchesAddress(tx, address);
        cache->emplace(address, valid);
        return valid;
    }

    bool ApplyTokenOp(
            const TokenOpData& op, const Transaction& tx, uint64_t height,
            const BtcVeldPegGateState& peg_gate,
            uint32_t vout = 0,
            std::unordered_map<std::string, bool>* signer_cache = nullptr,
            bool authorization_prevalidated = false,
            uint32_t tx_index = UINT32_MAX) {
        auto tok_it = tokens_.find(op.token_id);
        if (tok_it == tokens_.end()) return false;    // unregistered token: ignore

        if (op.amount <= 0) return false;

        const bool is_mint     = (op.action == "MINT");
        const bool is_transfer = (op.action == "TRANSFER");
        const bool is_redeem   = (op.action == "REDEEM");
        const bool is_reserve  = (op.action == "RESERVE");
        const bool is_expose   = (op.action == "EXPOSE");
        const bool is_cancel   = (op.action == "CANCEL");
        const bool is_fund     = (op.action == "FUND");
        if (!is_mint && !is_transfer && !is_redeem && !is_reserve &&
            !is_expose && !is_cancel && !is_fund)
            return false;
        if (op.token_id == BTCVELD_TOKEN_ID) {
            if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED) {
                // Every launch-v1 mint, public or issuer-carried, is routed
                // through MaybeApplyReserveTransitionLocked_.  The old direct
                // outpoint, C1, and MSP3 paths have no hidden fallback here.
                if (is_mint || is_reserve || is_expose || is_cancel || is_fund)
                    return false;
            }
            // A later finality stall closes every path that creates new BTC
            // exposure. Only exact lifecycle completion remains open. Merely
            // spelling an MNP2 prefix is not authority: the canonical MNP2
            // parser, issuer authorization, funded-allocation opening, amount,
            // recipient, and outpoint checks below must all still succeed.
            const bool reserved_completion =
                IsC1CompletionMintLocked_(op);
            if (((is_reserve || is_expose ||
                  (is_mint && !reserved_completion)) &&
                 !peg_gate.MintAllowed()) ||
                (is_fund && !peg_gate.FundingAllowed()) ||
                ((is_cancel || reserved_completion) &&
                 !peg_gate.CompletionAllowed()))
                return false;
            if (is_redeem && !peg_gate.RedeemAllowed()) return false;
        }
        std::string mint_outpoint;
        std::string mint_reservation_request_id;
        std::string mint_reservation_script_pubkey_hex;
        std::string mint_reservation_commitment_blind_hex;
        btcnull::Proof mint_nullifier_proof;
        btcnull::InsertResult mint_nullifier_insert;
        std::vector<uint8_t> mint_nullifier_proof_bytes;
        std::string reserve_request_id;
        uint64_t reserve_sequence = 0;
        std::string reserve_allocation_commitment;
        uint64_t reserve_expires_height = 0;
        std::string expose_request_id;
        std::string expose_allocation_commitment;
        std::string cancel_request_id;
        uint64_t cancel_sequence = 0;
        std::string cancel_allocation_commitment;
        uint64_t expose_funding_starts_height = 0;
        uint64_t expose_funding_expires_height = 0;
        std::string fund_request_id;
        std::string fund_script_pubkey_hex;
        std::string fund_blind_hex;
        std::string fund_outpoint;
        std::string fund_proof_hex;
        uint64_t fund_accepts_through_height = 0;
        btcspv::C1FundingResult fund_verification;
        btcnull::InsertResult fund_nullifier_insert;
        std::vector<uint8_t> fund_nullifier_proof_bytes;

        // MINT and TRANSFER create a balance at `to`.  Require the exact
        // P2PKH account shape the later authorization primitive can spend;
        // otherwise a valid operation could irreversibly strand token supply.
        if ((is_mint || is_transfer || is_reserve || is_expose || is_cancel ||
             is_fund) &&
            !IsCanonicalTokenCreditAddress(op.to)) return false;

        if (is_reserve) {
            if (op.token_id != BTCVELD_TOKEN_ID || op.from.empty() ||
                op.to.empty() || tok_it->second.issuer != op.from ||
                op.amount < c1reserve::MIN_SATS ||
                op.amount > BTCVELD_ISSUER_MAX_CUSTODY_SATS ||
                c1_reservations_.size() >= c1reserve::MAX_ACTIVE ||
                !c1reserve::ParseMemo(op.memo, reserve_request_id,
                                     reserve_allocation_commitment) ||
                !c1reserve::AllocationSequence(
                    reserve_request_id, reserve_sequence) ||
                c1_sequence_history_count_ != c1_last_sequence_ ||
                c1_last_sequence_ == UINT64_MAX ||
                reserve_sequence != c1_last_sequence_ + 1 ||
                c1_sequence_history_count_ == UINT64_MAX ||
                c1_reservations_.count(reserve_request_id) != 0 ||
                !c1reserve::ExpiryHeight(height, reserve_expires_height))
                return false;
            if (!authorization_prevalidated &&
                !TxSignerAuthorized(tx, op.from, signer_cache))
                return false;
            // A lease may only be admitted against issuer capacity earned at
            // this height.  Existing leases are already subtracted by the
            // coherent helper, preventing allocation overbooking.
            const BtcVeldIssuerMintCapacity cap =
                IssuerMintCapacityLocked_(height);
            if (!BtcVeldIssuerMintFitsCapacity(cap, op.amount))
                return false;
        }

        if (is_expose) {
            if (op.token_id != BTCVELD_TOKEN_ID || op.from.empty() ||
                op.to.empty() || tok_it->second.issuer != op.from ||
                !c1reserve::ParseExposureMemo(
                    op.memo, expose_request_id,
                    expose_allocation_commitment))
                return false;
            const auto reservation =
                c1_reservations_.find(expose_request_id);
            if (reservation == c1_reservations_.end() ||
                reservation->second.exposed ||
                reservation->second.expires_height < height ||
                !c1reserve::HasFinalityDepth(
                    reservation->second.created_height, height) ||
                reservation->second.recipient != op.to ||
                reservation->second.amount_sats != op.amount ||
                reservation->second.allocation_commitment !=
                    expose_allocation_commitment ||
                !c1reserve::FundingWindow(
                    height, expose_funding_starts_height,
                    expose_funding_expires_height))
                return false;
            if (!authorization_prevalidated &&
                !TxSignerAuthorized(tx, op.from, signer_cache))
                return false;
        }

        if (is_cancel) {
            // C1C1 is only a gap-closing transition for a descriptor whose
            // C1R1 never became canonical. It advances the exact next sequence
            // and history commitment but creates no capacity lease. Once it
            // lands, stale signed C1R1 bytes for this id are forever invalid.
            if (op.token_id != BTCVELD_TOKEN_ID || op.from.empty() ||
                op.to.empty() || tok_it->second.issuer != op.from ||
                op.amount < c1reserve::MIN_SATS ||
                op.amount > BTCVELD_ISSUER_MAX_CUSTODY_SATS ||
                !c1reserve::ParseCancellationMemo(
                    op.memo, cancel_request_id,
                    cancel_allocation_commitment) ||
                !c1reserve::AllocationSequence(
                    cancel_request_id, cancel_sequence) ||
                c1_sequence_history_count_ != c1_last_sequence_ ||
                c1_last_sequence_ == UINT64_MAX ||
                cancel_sequence != c1_last_sequence_ + 1 ||
                c1_sequence_history_count_ == UINT64_MAX ||
                c1_reservations_.count(cancel_request_id) != 0)
                return false;
            if (!authorization_prevalidated &&
                !TxSignerAuthorized(tx, op.from, signer_cache))
                return false;
        }

        if (is_fund) {
            if (op.token_id != BTCVELD_TOKEN_ID || op.from.empty() ||
                op.to.empty() || tok_it->second.issuer != op.from ||
                btc_headers_ == nullptr ||
                !c1reserve::ParseFundingMemo(
                    op.memo, fund_request_id, fund_script_pubkey_hex,
                    fund_blind_hex, fund_outpoint, fund_proof_hex))
                return false;
            const auto reservation = c1_reservations_.find(fund_request_id);
            if (reservation == c1_reservations_.end() ||
                !reservation->second.exposed || reservation->second.funded ||
                reservation->second.recipient != op.to ||
                reservation->second.amount_sats != op.amount ||
                height < reservation->second.funding_starts_height ||
                !c1reserve::LatestFundingAcceptanceHeight(
                    reservation->second.funding_expires_height,
                    fund_accepts_through_height) ||
                height > fund_accepts_through_height ||
                c1reserve::AllocationCommitment(
                    fund_request_id, op.to, op.amount,
                    fund_script_pubkey_hex, fund_blind_hex) !=
                    reservation->second.allocation_commitment)
                return false;
            // Authenticate the issuer before bounded but comparatively
            // expensive hex decode, Merkle hashing and Bitcoin tx parsing.
            if (!authorization_prevalidated &&
                !TxSignerAuthorized(tx, op.from, signer_cache))
                return false;
            const std::vector<uint8_t> funding_proof =
                HexToBytes(fund_proof_hex);
            const std::vector<uint8_t> funding_script =
                HexToBytes(fund_script_pubkey_hex);
            if (funding_proof.empty() || funding_script.empty())
                return false;
            fund_verification = btcspv::VerifyC1Funding(
                *btc_headers_, funding_proof.data(), funding_proof.size(),
                funding_script, static_cast<uint64_t>(op.amount),
                fund_outpoint, BTCVELD_SPV_K_BTC);
            if (!fund_verification.ok || mint_nullifier_count_ == UINT64_MAX ||
                (tx_index != UINT32_MAX &&
                 mint_effect_count_ == UINT64_MAX))
                return false;
            fund_nullifier_insert = btcnull::Insert(
                mint_nullifier_root_, fund_outpoint,
                fund_verification.nullifier_proof);
            if (!fund_nullifier_insert.ok) return false;
            fund_nullifier_proof_bytes = btcnull::EncodeProof(
                fund_verification.nullifier_proof);
            if (fund_nullifier_proof_bytes.empty()) return false;
        }

        // ---- authorization ----
        if (is_mint) {
            // Issuer-authorized fallback: only the configured issuer
            // may use this VELD_TOKEN|MINT branch, and the spending transaction
            // must be signed by that issuer key. The trust-minimized SPV mint path
            // is separately live in MaybeApplySpvMint above; it proves Bitcoin
            // custody and does not enter this signature-authorized branch.
            if (op.from.empty() || op.to.empty()) return false;
            if (tok_it->second.issuer != op.from) return false;
            if (!authorization_prevalidated &&
                !TxSignerAuthorized(tx, op.from, signer_cache)) return false;
            // The shared custody ceiling bounds the issuer fallback. Both mint
            // paths share the node-level validator gate, and a compromised issuer key cannot
            // create btcVELD beyond remaining aggregate custody headroom. The
            // work-tier clamp may reduce issuer headroom below the SPV path's
            // remaining shared-cap headroom; peg token only.
            if (op.token_id == BTCVELD_TOKEN_ID) {
                // Effective remaining custody headroom is authoritative. RPC
                // and consensus use the same coherent snapshot.
                BtcVeldIssuerMintCapacity cap =
                    IssuerMintCapacityLocked_(height);
                // An active mint must carry a well-formed, unused BTC deposit
                // outpoint. Consensus rejects missing, malformed, or reused ids.
                if (BtcVeldMintDepositIdActive(height)) {
                    if (!btcnull::ParseIssuerMemo(
                            op.memo, mint_outpoint, mint_nullifier_proof,
                            mint_reservation_request_id,
                            mint_reservation_script_pubkey_hex,
                            mint_reservation_commitment_blind_hex) ||
                        !IsValidBtcOutpointId(mint_outpoint) ||
                        (mint_reservation_request_id.empty() &&
                         mint_nullifier_count_ == UINT64_MAX) ||
                        (tx_index != UINT32_MAX &&
                         mint_effect_count_ == UINT64_MAX))
                        return false;
                    if (mint_reservation_request_id.empty()) {
                        if (btcnull::CUSTODY_LINEAGE_REQUIRED)
                            return false; // public issuer MNP1 disabled: MSP3 or funded MNP2 only
                        mint_nullifier_insert = btcnull::Insert(
                            mint_nullifier_root_, mint_outpoint,
                            mint_nullifier_proof);
                        if (!mint_nullifier_insert.ok) return false;
                        mint_nullifier_proof_bytes =
                            btcnull::EncodeProof(mint_nullifier_proof);
                        if (mint_nullifier_proof_bytes.empty()) return false;
                    }
                }
                if (!mint_reservation_request_id.empty()) {
                    const auto reservation =
                        c1_reservations_.find(mint_reservation_request_id);
                    if (reservation == c1_reservations_.end() ||
                        !reservation->second.exposed ||
                        !reservation->second.funded ||
                        reservation->second.funding_outpoint != mint_outpoint ||
                        reservation->second.recipient != op.to ||
                        reservation->second.amount_sats != op.amount ||
                        c1reserve::AllocationCommitment(
                            mint_reservation_request_id, op.to, op.amount,
                            mint_reservation_script_pubkey_hex,
                            mint_reservation_commitment_blind_hex) !=
                            reservation->second.allocation_commitment)
                        return false;
                    // MSPV has already treated this lease as occupied against
                    // the shared absolute ceiling.  Honor the promise even if
                    // an independent SPV mint moved circulating supply above
                    // the issuer work tier after reservation admission.
                    const auto supply_it = supply_.find(BTCVELD_TOKEN_ID);
                    const int64_t supply = supply_it == supply_.end()
                        ? 0 : supply_it->second;
                    if (supply < 0 ||
                        supply > BTCVELD_ISSUER_MAX_CUSTODY_SATS - op.amount)
                        return false;
                } else if (!BtcVeldIssuerMintFitsCapacity(cap, op.amount)) {
                    return false;
                }
            }
        }
        if (is_transfer) {
            if (op.from.empty() || op.to.empty()) return false;
            if (!authorization_prevalidated &&
                !TxSignerAuthorized(tx, op.from, signer_cache)) return false;
        }
        if (is_redeem) {
            // REDEEM has no token-account recipient: `to` is canonically empty
            // and `memo` is the destination Bitcoin scriptPubKey.  Allowing an
            // ignored arbitrary `to` string lets an otherwise valid burn place
            // non-UTF-8 bytes in the lifetime payout RPC, permanently denying
            // every coordinator/watchtower a parseable obligation feed.
            if (op.from.empty() || !op.to.empty() || op.memo.empty()) return false;
            if (!authorization_prevalidated &&
                !TxSignerAuthorized(tx, op.from, signer_cache)) return false;
            // Reject an UNPAYABLE destination : a burn to a garbage/non-standard
            // BTC spk would destroy btcVELD that no honest custodian can pay out. Gated above
            // tip so it grandfathers history; inert until armed (0 == dormant).
            if (BTCVELD_REDEEM_SPK_CHECK_ACTIVATION_HEIGHT != 0 &&
                height >= BTCVELD_REDEEM_SPK_CHECK_ACTIVATION_HEIGHT) {
                std::vector<uint8_t> spk = BtcVeldHex_(op.memo.c_str());
                if (spk.empty() || !IsStandardBtcRedeemSpk(spk)) return false;
            }
            // §5b drain guard (peg token only): per-window outflow rate-limit. An
            // over-budget redeem is REJECTED WHOLE — nothing is burned, the funds
            // stay with the redeemer (resubmit next window) — so no btcVELD is
            // ever trapped (the unpayable-burn lesson). The window id is a pure
            // function of height and the accumulator rolls lazily HERE, on
            // accepted chain ops only, so every replaying node computes the
            // identical (window, accumulator) pair at every block.
            if (op.token_id == BTCVELD_TOKEN_ID && BtcVeldRedeemGuardActive(height)) {
                uint64_t wid = redeemguard::WindowId(height);
                // Evaluate a rolled window prospectively. Do not mutate the
                // accumulator until every authorization/balance check passes and
                // the burn is applied; an invalid first op in a new window must
                // be a complete consensus-state no-op.
                int64_t used = (wid == redeem_window_id_) ? redeemed_in_window_ : 0;
                // Redemption capacity follows the launch-wide SPV/shared custody
                // ceiling, not the smaller issuer-only inflow cap. Otherwise
                // trustless SPV-backed supply could be stranded for 100× longer.
                int64_t ceiling = redeemguard::LaunchWindowCeilingSats();
                if (!redeemguard::FitsWindow(used, op.amount, ceiling)) return false;
            }
        }

        // spend authorization: transfer/redeem must have the balance to move
        if (is_transfer || is_redeem) {
            auto from_key = op.token_id + ":" + op.from;
            auto bit = balances_.find(from_key);
            int64_t bal = (bit != balances_.end()) ? bit->second : 0;
            if (bal < op.amount) return false;
        }

        // ---- state transition ----
        if (is_fund) {
            auto reservation = c1_reservations_.find(fund_request_id);
            if (reservation == c1_reservations_.end()) return false;
            reservation->second.funded = true;
            reservation->second.funded_height = height;
            reservation->second.funding_outpoint = fund_outpoint;
            mint_nullifier_root_ = fund_nullifier_insert.new_root;
            ++mint_nullifier_count_;
            BtcVeldMintTransition transition;
            transition.tx_index = tx_index;
            transition.marker_vout = vout;
            transition.txid = HashToHex(tx.GetTxID());
            transition.outpoint = fund_outpoint;
            transition.proof = std::move(fund_nullifier_proof_bytes);
            transition.old_root = fund_nullifier_insert.old_root;
            transition.new_root = fund_nullifier_insert.new_root;
            transition.effect_kind = "C1_FUND";
            transition.c1_allocation_id = fund_request_id;
            if (tx_index != UINT32_MAX) {
                mint_effect_root_ = ExtendBtcVeldMintEffectCommitment(
                    mint_effect_root_, height, transition);
                ++mint_effect_count_;
            }
            last_block_mint_transitions_.push_back(std::move(transition));
            return true;
        } else if (is_cancel) {
            c1_last_sequence_ = cancel_sequence;
            c1_sequence_history_root_ = ExtendBtcVeldC1SequenceHistory(
                c1_sequence_history_root_, "CANCEL", cancel_sequence,
                cancel_request_id, op.to,
                cancel_allocation_commitment, op.amount, height);
            ++c1_sequence_history_count_;
            return true;
        } else if (is_expose) {
            auto reservation = c1_reservations_.find(expose_request_id);
            if (reservation == c1_reservations_.end()) return false;
            reservation->second.exposed = true;
            reservation->second.exposed_height = height;
            reservation->second.funding_starts_height =
                expose_funding_starts_height;
            reservation->second.funding_expires_height =
                expose_funding_expires_height;
            return true;
        } else if (is_reserve) {
            BtcVeldC1Reservation reservation;
            reservation.allocation_id = reserve_request_id;
            reservation.sequence = reserve_sequence;
            reservation.recipient = op.to;
            reservation.allocation_commitment =
                reserve_allocation_commitment;
            reservation.amount_sats = op.amount;
            reservation.created_height = height;
            reservation.expires_height = reserve_expires_height;
            if (!c1_reservations_.emplace(
                    reserve_request_id, std::move(reservation)).second)
                return false;
            c1_last_sequence_ = reserve_sequence;
            c1_sequence_history_root_ = ExtendBtcVeldC1SequenceHistory(
                c1_sequence_history_root_, "RESERVE", reserve_sequence,
                reserve_request_id, op.to, reserve_allocation_commitment,
                op.amount, height);
            ++c1_sequence_history_count_;
            return true;
        } else if (is_mint) {
            auto supply_it = supply_.find(op.token_id);
            const int64_t sup =
                supply_it == supply_.end() ? 0 : supply_it->second;
            const std::string to_key = op.token_id + ":" + op.to;
            auto to_it = balances_.find(to_key);
            const int64_t to_balance =
                to_it == balances_.end() ? 0 : to_it->second;
            if (sup < 0 || sup > INT64_MAX - op.amount ||
                to_balance < 0 || to_balance > INT64_MAX - op.amount)
                return false;
            // D-STATE-01: a mint may not create a sub-floor account.
            if (!BalanceAdmissible(to_balance + op.amount)) return false;
            balances_[to_key] = to_balance + op.amount;
            supply_[op.token_id] = sup + op.amount;
            if (!mint_reservation_request_id.empty())
                c1_reservations_.erase(mint_reservation_request_id);
            // Exact shared issuer/SPV insertion, already proven against the
            // current root above.  Root/count and the monetary credit advance
            // in the same locked state transition.
            if (op.token_id == BTCVELD_TOKEN_ID &&
                BtcVeldMintDepositIdActive(height)) {
                BtcVeldMintTransition transition;
                transition.tx_index = tx_index;
                transition.marker_vout = vout;
                transition.txid = HashToHex(tx.GetTxID());
                transition.outpoint = mint_outpoint;
                if (mint_reservation_request_id.empty()) {
                    mint_nullifier_root_ = mint_nullifier_insert.new_root;
                    ++mint_nullifier_count_;
                    transition.proof =
                        std::move(mint_nullifier_proof_bytes);
                    transition.old_root = mint_nullifier_insert.old_root;
                    transition.new_root = mint_nullifier_insert.new_root;
                    transition.effect_kind = "MINT";
                } else {
                    transition.old_root = mint_nullifier_root_;
                    transition.new_root = mint_nullifier_root_;
                    transition.effect_kind = "C1_MINT";
                    transition.c1_allocation_id =
                        mint_reservation_request_id;
                }
                if (tx_index != UINT32_MAX) {
                    mint_effect_root_ = ExtendBtcVeldMintEffectCommitment(
                        mint_effect_root_, height, transition);
                    ++mint_effect_count_;
                }
                last_block_mint_transitions_.push_back(std::move(transition));
            }
        } else if (is_transfer) {
            const std::string from_key = op.token_id + ":" + op.from;
            const std::string to_key = op.token_id + ":" + op.to;
            if (from_key != to_key) {
                auto from_it = balances_.find(from_key);
                auto to_it = balances_.find(to_key);
                const int64_t from_balance =
                    from_it == balances_.end() ? 0 : from_it->second;
                const int64_t to_balance =
                    to_it == balances_.end() ? 0 : to_it->second;
                if (from_balance < op.amount || to_balance < 0 ||
                    to_balance > INT64_MAX - op.amount)
                    return false;
                const int64_t remaining = from_balance - op.amount;
                // D-STATE-01: both legs land on 0 or >= floor. This is the
                // path an account-splitting attacker would use.
                if (!BalanceAdmissible(remaining))            return false;
                if (!BalanceAdmissible(to_balance + op.amount)) return false;
                if (remaining == 0) balances_.erase(from_key);
                else from_it->second = remaining;
                balances_[to_key] = to_balance + op.amount;
            }
        } else { // is_redeem — destroy on Veld; BTC payout owed off-chain
            const std::string from_key = op.token_id + ":" + op.from;
            auto from_it = balances_.find(from_key);
            auto supply_it = supply_.find(op.token_id);
            if (from_it == balances_.end() ||
                from_it->second < op.amount ||
                supply_it == supply_.end() ||
                supply_it->second < op.amount)
                return false;
            const int64_t remaining = from_it->second - op.amount;
            // D-STATE-01: a partial redeem may not leave a sub-floor dust
            // account behind. Redeem everything, or leave a real balance.
            if (!BalanceAdmissible(remaining)) return false;
            btcveld::reserve::State reserve_next = reserve_state_;
            if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED) {
                if (op.token_id == BTCVELD_TOKEN_ID &&
                    !btcveld::reserve::OpenRedemption(
                        reserve_next, static_cast<uint64_t>(op.amount),
                        static_cast<uint64_t>(
                            supply_it->second - op.amount)))
                    return false;
            }
            if (remaining == 0) balances_.erase(from_it);
            else from_it->second = remaining;
            supply_it->second -= op.amount;
            if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED) {
                if (op.token_id == BTCVELD_TOKEN_ID)
                    reserve_state_ = std::move(reserve_next);
            }
            // §5b accumulator: the guard above already proved the budget fits.
            if (op.token_id == BTCVELD_TOKEN_ID && BtcVeldRedeemGuardActive(height)) {
                uint64_t wid = redeemguard::WindowId(height);
                if (wid != redeem_window_id_) {
                    redeem_window_id_   = wid;
                    redeemed_in_window_ = 0;
                }
                redeemed_in_window_ += op.amount;
            }
        }

        // ---- bounded UI history (not part of the state digest) ----
        TokenTransferRecord r{};
        std::ostringstream hex;
        for (auto b : tx.GetTxID()) hex << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        r.txid         = hex.str();
        r.vout         = vout;
        r.token_id     = op.token_id;
        r.from         = op.from;
        r.to           = op.to;
        r.amount       = op.amount;
        r.block_height = height;
        r.timestamp    = std::time(nullptr);
        r.memo         = (is_mint && op.token_id == BTCVELD_TOKEN_ID &&
                          !mint_outpoint.empty()) ? mint_outpoint : op.memo;
        r.is_mint      = is_mint;
        r.is_burn      = false;
        r.is_redeem    = is_redeem;
        history_.push_back(r);
        if (history_.size() > 2000) history_.erase(history_.begin());
        if (is_redeem) {
            last_block_redeems_.push_back(r);   // deterministic per-block feed for the redeem covenant
        }
        return true;
    }
};

inline bool OnChainTokenLedger::ValidateMempoolCandidate(
        const Transaction& tx, uint64_t height,
        uint32_t prospective_block_bits,
        const BtcVeldPegGateState& peg_gate) const {
    const auto accepted = FilterMempoolCandidates(
        std::vector<Transaction>{tx}, height, prospective_block_bits,
        peg_gate);
    return accepted.size() == 1 && accepted[0];
}

inline bool OnChainTokenLedger::BuildPostBlockPreview(
        const Block& block, const BtcVeldPegGateState& peg_gate,
        OnChainTokenLedger& out) const {
    if (&out == this) return false;
    const StateSnapshot snapshot = SnapshotState();
    btcspv::BtcHeaderChain* headers = nullptr;
    const btcveld::SignerBondCovenant* redeem_covenant = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        headers = btc_headers_;  // node-owned; installed once at startup
        redeem_covenant = redeem_covenant_;
    }
    out.RestoreState(snapshot);
    out.SetBtcHeaderChain(headers);
    out.SetBtcVeldRedeemCovenant(redeem_covenant);
    return out.ProcessBlock(block, peg_gate);
}

inline std::vector<bool> OnChainTokenLedger::FilterMempoolCandidates(
        const std::vector<Transaction>& candidates, uint64_t height,
        uint32_t prospective_block_bits,
        const BtcVeldPegGateState& peg_gate,
        const std::vector<bool>& token_authorization_prevalidated) const {
    if (!token_authorization_prevalidated.empty() &&
        token_authorization_prevalidated.size() != candidates.size())
        return std::vector<bool>(candidates.size(), false);
    StateSnapshot snapshot = SnapshotState();
    btcspv::BtcHeaderChain* headers = nullptr;
    const btcveld::SignerBondCovenant* redeem_covenant = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        headers = btc_headers_;  // node-owned; installed once at startup
        redeem_covenant = redeem_covenant_;
    }

    OnChainTokenLedger trial;
    trial.RestoreState(snapshot);
    trial.SetBtcHeaderChain(headers);
    trial.SetBtcVeldRedeemCovenant(redeem_covenant);
    std::lock_guard<std::mutex> trial_lock(trial.mutex_);
    trial.last_block_redeems_.clear();
    trial.last_block_reserve_payouts_.clear();
    trial.PruneC1ReservationsLocked_(height);
    trial.recent_work_.push_back(BlockWorkForTier(prospective_block_bits));
    if (trial.recent_work_.size() > BTCVELD_TIER_WINDOW_BLOCKS)
        trial.recent_work_.pop_front();
    trial.MaybeRegisterBtcVeld(height);
    // MSPV is a new mint, never a C1 completion transition.
    const bool spv_on = peg_gate.MintAllowed() &&
                        BtcVeldSpvActive(height) && headers != nullptr;
    std::vector<bool> accepted;
    accepted.reserve(candidates.size());
    for (size_t i = 0; i < candidates.size(); ++i) {
        const auto& tx = candidates[i];
        if (trial.HasForbiddenBtcVeldMarkerLocked_(tx, peg_gate)) {
            accepted.push_back(false);
            continue;
        }
        const bool preauthorized =
            !token_authorization_prevalidated.empty() &&
            token_authorization_prevalidated[i];
        accepted.push_back(trial.ApplyTransactionMarkersLocked_(
            tx, height, spv_on, peg_gate, /*require_marker=*/true,
            preauthorized));
    }
    return accepted;
}

inline std::vector<bool>
OnChainTokenLedger::SelectResourceFeasibleMempoolCandidates(
        const std::vector<const Transaction*>& candidates,
        const std::vector<size_t>& serialized_sizes,
        const std::vector<bool>& token_families,
        const std::vector<bool>& token_authorization_prevalidated,
        size_t initial_count, size_t initial_bytes,
        size_t max_count, size_t max_bytes,
        uint64_t height, uint32_t prospective_block_bits,
        const BtcVeldPegGateState& peg_gate) const {
    std::vector<bool> selected(candidates.size(), false);
    if (serialized_sizes.size() != candidates.size() ||
        token_families.size() != candidates.size() ||
        token_authorization_prevalidated.size() != candidates.size() ||
        initial_count > max_count || initial_bytes > max_bytes)
        return selected;

    StateSnapshot snapshot = SnapshotState();
    btcspv::BtcHeaderChain* headers = nullptr;
    const btcveld::SignerBondCovenant* redeem_covenant = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        headers = btc_headers_;
        redeem_covenant = redeem_covenant_;
    }
    OnChainTokenLedger trial;
    trial.RestoreState(snapshot);
    trial.SetBtcHeaderChain(headers);
    trial.SetBtcVeldRedeemCovenant(redeem_covenant);
    std::lock_guard<std::mutex> trial_lock(trial.mutex_);
    trial.last_block_redeems_.clear();
    trial.last_block_reserve_payouts_.clear();
    trial.PruneC1ReservationsLocked_(height);
    trial.recent_work_.push_back(BlockWorkForTier(prospective_block_bits));
    if (trial.recent_work_.size() > BTCVELD_TIER_WINDOW_BLOCKS)
        trial.recent_work_.pop_front();
    trial.MaybeRegisterBtcVeld(height);
    // MSPV is a new mint, never a C1 completion transition.
    const bool spv_on = peg_gate.MintAllowed() &&
                        BtcVeldSpvActive(height) && headers != nullptr;

    size_t count = initial_count;
    size_t bytes = initial_bytes;
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (!candidates[i] || count >= max_count || bytes > max_bytes ||
            serialized_sizes[i] > max_bytes - bytes)
            continue;
        if (token_families[i] &&
            (trial.HasForbiddenBtcVeldMarkerLocked_(*candidates[i], peg_gate) ||
             !trial.ApplyTransactionMarkersLocked_(
                *candidates[i], height, spv_on, peg_gate,
                /*require_marker=*/true,
                token_authorization_prevalidated[i])))
            continue;
        selected[i] = true;
        ++count;
        bytes += serialized_sizes[i];
    }
    return selected;
}

}
