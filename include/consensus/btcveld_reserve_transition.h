#pragma once

// Canonical rolling Bitcoin reserve for btcVELD.
//
// The bridge has exactly one represented Bitcoin outpoint.  A direct deposit
// after OPEN is pending collateral until a DEPOSIT transaction consumes both
// that pending outpoint and the current reserve.  This removes ancestry from
// the consensus question: represented value is identified by one exact
// outpoint in state, never by a script match or an unbounded history walk.

#include "core/btc_deposit_verify.h"
#include "core/constants.h"
#include "core/script.h"
#include "core/version.h"
#include "consensus/btcveld_spv_params.h"
#include "consensus/btcveld_signer_bond.h"
#include "consensus/state_digest.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace veld {
namespace btcveld {
namespace reserve {

#if defined(VELD_PUBLIC_MAINNET) || defined(VELD_BTCVELD_REGTEST)
inline constexpr bool TRANSITION_V1_REQUIRED = true;
#else
inline constexpr bool TRANSITION_V1_REQUIRED = false;
#endif

inline constexpr char PROOF_MAGIC[] = "RTP1";
inline constexpr char AUTH_MAGIC[] = "RVS1";
inline constexpr char PUBLIC_CARRIER_PREFIX[] = "VELD_RSV1|";
inline constexpr char ISSUER_MEMO_PREFIX[] = "RTP1:";
inline constexpr uint32_t NO_VOUT = UINT32_MAX;
inline constexpr size_t MAX_DIRECT_INPUTS = 8;
// Bitcoin Core 28.x standard relay admits one null-data output whose complete
// script is at most 83 bytes.  The operation-specific RVS1 encodings below
// keep the sole authorization carrier within that policy boundary.
inline constexpr size_t MAX_STANDARD_NULL_DATA_SCRIPT_BYTES = 83;
inline constexpr size_t OPEN_AUTH_RECIPIENT_BYTES = 34;
inline constexpr size_t OPEN_AUTH_PAYLOAD_BYTES =
    4 + 1 + 32 + OPEN_AUTH_RECIPIENT_BYTES + 8;
inline constexpr size_t STANDARD_AUTH_PAYLOAD_BYTES = 4 + 1 + 32 + 32 + 8;
static_assert(1 + 2 + OPEN_AUTH_PAYLOAD_BYTES <=
                  MAX_STANDARD_NULL_DATA_SCRIPT_BYTES,
              "OPEN RVS1 must be standard-relay compatible");
static_assert(1 + 2 + STANDARD_AUTH_PAYLOAD_BYTES <=
                  MAX_STANDARD_NULL_DATA_SCRIPT_BYTES,
              "RVS1 must be standard-relay compatible");
// The complete binary proof must still fit, after lowercase-hex encoding and
// the largest issuer wrapper, in one canonical PUSHDATA2 OP_RETURN.  Direct
// parent bytes are bounded independently and never form an ancestry walk.
inline constexpr size_t MAX_PROOF_BYTES =
    4 + 1 + 7 * 32 + 4 + 8 + 8 + 4 + 8 + 4 + 1 + 32 * 32 + 8 + 4 +
    btcnull::MAX_MSPV_STRIPPED_TX_BYTES + 2 + MAX_DIRECT_INPUTS * 4 +
    btcnull::MAX_MSPV_PARENT_TOTAL_BYTES + 4 + btcnull::MAX_PROOF_BYTES;
static_assert(2 * MAX_PROOF_BYTES + 512 <= 65'535,
              "RTP1 must fit one canonical issuer or public carrier");

enum class Status : uint8_t { EMPTY = 0, ACTIVE = 1, FROZEN = 2 };
enum class Operation : uint8_t {
    OPEN = 1,
    DEPOSIT = 2,
    ROLLOVER = 3,
    PAYOUT = 4,
    CLOSE = 5,
    FREEZE = 6,
};

inline const char* StatusName(Status status) {
    switch (status) {
        case Status::EMPTY: return "EMPTY";
        case Status::ACTIVE: return "ACTIVE";
        case Status::FROZEN: return "FROZEN";
    }
    return "INVALID";
}

inline const char* OperationName(Operation operation) {
    switch (operation) {
        case Operation::OPEN: return "OPEN";
        case Operation::DEPOSIT: return "DEPOSIT";
        case Operation::ROLLOVER: return "ROLLOVER";
        case Operation::PAYOUT: return "PAYOUT";
        case Operation::CLOSE: return "CLOSE";
        case Operation::FREEZE: return "FREEZE";
    }
    return "INVALID";
}

inline Hash256 NetworkBinding() {
    namespace sd = ::veld::state_digest;
    std::vector<uint8_t> body;
    sd::put_len_prefixed(body, std::string(GENESIS_HASH));
    sd::put_len_prefixed(body, std::string(DEPLOYMENT_PROFILE_ID));
    sd::put_len_prefixed(body, std::string("btcveld-reserve-outpoint-v1"));
    return sd::sha256_domain("VELD/BTCVELD/RESERVE_NETWORK/v1", body);
}

inline Hash256 EmptyTransitionCommitment() {
    const Hash256 binding = NetworkBinding();
    return state_digest::sha256_domain(
        "VELD/BTCVELD/RESERVE_TRANSITIONS/v1/EMPTY",
        std::vector<uint8_t>(binding.begin(), binding.end()));
}

struct State {
    Status status = Status::EMPTY;
    Hash256 reserve_txid{};
    uint32_t reserve_vout = NO_VOUT;
    uint64_t reserve_value_sats = 0;
    Hash256 reserve_bitcoin_block{};
    uint64_t transition_count = 0;
    Hash256 transition_commitment = EmptyTransitionCommitment();
    uint64_t surplus_sats = 0;
    uint64_t open_redemption_principal = 0;
    uint64_t processed_veld_height = 0;
    Hash256 processed_veld_block_hash{};

    bool HasOutpoint() const {
        return status != Status::EMPTY && !HashIsZero(reserve_txid) &&
               reserve_vout != NO_VOUT && reserve_value_sats != 0;
    }

    bool Canonical() const {
        if (status != Status::EMPTY && status != Status::ACTIVE &&
            status != Status::FROZEN)
            return false;
        if (HashIsZero(transition_commitment)) return false;
        if (status == Status::EMPTY) {
            return HashIsZero(reserve_txid) && reserve_vout == NO_VOUT &&
                   reserve_value_sats == 0 &&
                   HashIsZero(reserve_bitcoin_block) &&
                   surplus_sats == 0 &&
                   open_redemption_principal == 0;
        }
        return HasOutpoint() && !HashIsZero(reserve_bitcoin_block);
    }

    bool AccountingHolds(uint64_t circulating_supply) const {
        if (!Canonical()) return false;
        if (circulating_supply > UINT64_MAX - open_redemption_principal)
            return false;
        const uint64_t liabilities = circulating_supply +
                                     open_redemption_principal;
        if (liabilities > UINT64_MAX - surplus_sats) return false;
        return reserve_value_sats == liabilities + surplus_sats;
    }
};

inline std::vector<uint8_t> EncodeState(const State& state) {
    namespace sd = ::veld::state_digest;
    std::vector<uint8_t> body;
    body.reserve(1 + 32 + 4 + 8 * 5 + 32 * 3);
    sd::put_u8(body, static_cast<uint8_t>(state.status));
    sd::put_bytes(body, state.reserve_txid.data(), state.reserve_txid.size());
    sd::put_u32_le(body, state.reserve_vout);
    sd::put_u64_le(body, state.reserve_value_sats);
    sd::put_bytes(body, state.reserve_bitcoin_block.data(),
                  state.reserve_bitcoin_block.size());
    sd::put_u64_le(body, state.transition_count);
    sd::put_bytes(body, state.transition_commitment.data(),
                  state.transition_commitment.size());
    sd::put_u64_le(body, state.surplus_sats);
    sd::put_u64_le(body, state.open_redemption_principal);
    sd::put_u64_le(body, state.processed_veld_height);
    sd::put_bytes(body, state.processed_veld_block_hash.data(),
                  state.processed_veld_block_hash.size());
    return body;
}

inline Hash256 Digest(const State& state) {
    std::vector<uint8_t> body;
    state_digest::put_u32_le(body, 1);
    const Hash256 binding = NetworkBinding();
    state_digest::put_bytes(body, binding.data(), binding.size());
    const std::vector<uint8_t> encoded = EncodeState(state);
    state_digest::put_bytes(body, encoded.data(), encoded.size());
    return state_digest::sha256_domain(
        "VELD_D_BTCVELD_RESERVE_v1|", body);
}

struct Claim {
    Operation operation = Operation::OPEN;
    Hash256 network_binding{};
    Hash256 prior_commitment{};
    Hash256 prior_reserve_txid{};
    uint32_t prior_reserve_vout = NO_VOUT;
    uint64_t prior_reserve_value = 0;
    uint64_t prior_transition_count = 0;
    Hash256 new_reserve_txid{};
    uint32_t new_reserve_vout = NO_VOUT;
    uint64_t new_reserve_value = 0;
    Hash256 bitcoin_txid{};
    Hash256 bitcoin_block{};
    uint64_t merkle_directions = 0;
    std::vector<Hash256> merkle_branch;
    Hash256 exact_commitment{};
    uint64_t mint_amount = 0;
    std::vector<uint8_t> bitcoin_tx;
    std::vector<std::vector<uint8_t>> direct_parents;
    btcnull::Proof nullifier_proof;
    bool has_nullifier_proof = false;
};

struct PayoutContext {
    bool present = false;
    H256 request_id{};
    H256 request_commitment{};
    uint64_t principal_sats = 0;
    std::vector<uint8_t> destination_spk;
};

struct Result {
    bool ok = false;
    std::string reason;
    Claim claim;
    std::string recipient;
    std::string pending_outpoint;
    uint64_t pending_value = 0;
    H256 payout_request_id{};
    uint64_t payout_principal_sats = 0;
    std::vector<uint8_t> payout_destination_spk;
    bool terminal = false;
};

namespace detail {

class Reader {
public:
    Reader(const uint8_t* data, size_t size) : data_(data), size_(size) {}

    bool U8(uint8_t& out) {
        if (offset_ >= size_) return false;
        out = data_[offset_++];
        return true;
    }
    bool U16(uint16_t& out) {
        if (Remaining() < 2) return false;
        out = static_cast<uint16_t>(data_[offset_]) |
              static_cast<uint16_t>(data_[offset_ + 1] << 8);
        offset_ += 2;
        return true;
    }
    bool U32(uint32_t& out) {
        if (Remaining() < 4) return false;
        out = btcspv::rd_le32(data_ + offset_);
        offset_ += 4;
        return true;
    }
    bool U64(uint64_t& out) {
        if (Remaining() < 8) return false;
        out = 0;
        for (unsigned i = 0; i < 8; ++i)
            out |= static_cast<uint64_t>(data_[offset_ + i]) << (8 * i);
        offset_ += 8;
        return true;
    }
    bool Hash(Hash256& out) {
        if (Remaining() < out.size()) return false;
        std::memcpy(out.data(), data_ + offset_, out.size());
        offset_ += out.size();
        return true;
    }
    bool Bytes(size_t amount, std::vector<uint8_t>& out) {
        if (amount > Remaining()) return false;
        out.assign(data_ + offset_, data_ + offset_ + amount);
        offset_ += amount;
        return true;
    }
    const uint8_t* Current() const {
        return offset_ <= size_ ? data_ + offset_ : nullptr;
    }
    size_t Remaining() const { return size_ - offset_; }
    bool Done() const { return offset_ == size_; }

private:
    const uint8_t* data_ = nullptr;
    size_t size_ = 0;
    size_t offset_ = 0;
};

inline bool DecodeState(const uint8_t* payload, size_t size, State& out) {
    out = State{};
    if (payload == nullptr) return false;
    Reader reader(payload, size);
    uint8_t status = 0;
    State decoded;
    if (!reader.U8(status) || status > static_cast<uint8_t>(Status::FROZEN) ||
        !reader.Hash(decoded.reserve_txid) ||
        !reader.U32(decoded.reserve_vout) ||
        !reader.U64(decoded.reserve_value_sats) ||
        !reader.Hash(decoded.reserve_bitcoin_block) ||
        !reader.U64(decoded.transition_count) ||
        !reader.Hash(decoded.transition_commitment) ||
        !reader.U64(decoded.surplus_sats) ||
        !reader.U64(decoded.open_redemption_principal) ||
        !reader.U64(decoded.processed_veld_height) ||
        !reader.Hash(decoded.processed_veld_block_hash) ||
        !reader.Done())
        return false;
    decoded.status = static_cast<Status>(status);
    if (!decoded.Canonical() || EncodeState(decoded) !=
            std::vector<uint8_t>(payload, payload + size))
        return false;
    out = decoded;
    return true;
}

inline bool ValidOperation(uint8_t raw) {
    return raw >= static_cast<uint8_t>(Operation::OPEN) &&
           raw <= static_cast<uint8_t>(Operation::FREEZE);
}

inline bool DecodeProof(const uint8_t* payload, size_t size, Claim& out) {
    out = Claim{};
    if (payload == nullptr || size > MAX_PROOF_BYTES || size < 300 ||
        std::memcmp(payload, PROOF_MAGIC, 4) != 0)
        return false;
    Reader reader(payload + 4, size - 4);
    uint8_t operation = 0;
    if (!reader.U8(operation) || !ValidOperation(operation)) return false;
    out.operation = static_cast<Operation>(operation);
    if (!reader.Hash(out.network_binding) ||
        !reader.Hash(out.prior_commitment) ||
        !reader.Hash(out.prior_reserve_txid) ||
        !reader.U32(out.prior_reserve_vout) ||
        !reader.U64(out.prior_reserve_value) ||
        !reader.U64(out.prior_transition_count) ||
        !reader.Hash(out.new_reserve_txid) ||
        !reader.U32(out.new_reserve_vout) ||
        !reader.U64(out.new_reserve_value) ||
        !reader.Hash(out.bitcoin_txid) ||
        !reader.Hash(out.bitcoin_block))
        return false;
    uint32_t directions = 0;
    uint8_t branch_size = 0;
    if (!reader.U32(directions) || !reader.U8(branch_size) ||
        branch_size > 32 ||
        (branch_size < 32 && (directions >> branch_size) != 0))
        return false;
    out.merkle_directions = directions;
    out.merkle_branch.reserve(branch_size);
    for (uint8_t i = 0; i < branch_size; ++i) {
        Hash256 sibling{};
        if (!reader.Hash(sibling)) return false;
        out.merkle_branch.push_back(sibling);
    }
    if (!reader.Hash(out.exact_commitment) || !reader.U64(out.mint_amount))
        return false;
    uint32_t tx_size = 0;
    if (!reader.U32(tx_size) || tx_size <= 64 ||
        tx_size > btcnull::MAX_MSPV_STRIPPED_TX_BYTES ||
        !reader.Bytes(tx_size, out.bitcoin_tx))
        return false;
    uint16_t parent_count = 0;
    if (!reader.U16(parent_count) || parent_count == 0 ||
        parent_count > MAX_DIRECT_INPUTS)
        return false;
    size_t parent_total = 0;
    out.direct_parents.reserve(parent_count);
    for (uint16_t i = 0; i < parent_count; ++i) {
        uint32_t parent_size = 0;
        if (!reader.U32(parent_size) || parent_size < 10 ||
            parent_size > btcnull::MAX_MSPV_PARENT_TX_BYTES ||
            parent_total > btcnull::MAX_MSPV_PARENT_TOTAL_BYTES - parent_size)
            return false;
        std::vector<uint8_t> parent;
        if (!reader.Bytes(parent_size, parent)) return false;
        parent_total += parent_size;
        out.direct_parents.push_back(std::move(parent));
    }
    uint32_t nullifier_size = 0;
    if (!reader.U32(nullifier_size) || nullifier_size > reader.Remaining())
        return false;
    if (nullifier_size != 0) {
        if (nullifier_size < btcnull::MIN_PROOF_BYTES ||
            nullifier_size > btcnull::MAX_PROOF_BYTES ||
            !btcnull::DecodeProof(reader.Current(), nullifier_size,
                                  out.nullifier_proof))
            return false;
        out.has_nullifier_proof = true;
        std::vector<uint8_t> ignored;
        if (!reader.Bytes(nullifier_size, ignored)) return false;
    }
    return reader.Done();
}

struct AuthMarker {
    Operation operation = Operation::OPEN;
    Hash256 prior_commitment{};
    Hash256 exact_commitment{};
    uint64_t mint_amount = 0;
    std::string open_recipient;
};

inline bool ParseAuthMarker(const btcspv::BtcTxOut& output, AuthMarker& marker) {
    const std::vector<uint8_t> bytes = btcspv::ExtractOpReturn(output.spk);
    if ((bytes.size() != OPEN_AUTH_PAYLOAD_BYTES &&
         bytes.size() != STANDARD_AUTH_PAYLOAD_BYTES) ||
        output.spk.size() != bytes.size() + 3 ||
        output.spk[0] != 0x6a || output.spk[1] != 0x4c ||
        output.spk[2] != static_cast<uint8_t>(bytes.size()) ||
        output.spk.size() > MAX_STANDARD_NULL_DATA_SCRIPT_BYTES ||
        std::memcmp(bytes.data(), AUTH_MAGIC, 4) != 0)
        return false;
    const uint8_t operation = bytes[4];
    if (!ValidOperation(operation) ||
        operation == static_cast<uint8_t>(Operation::FREEZE))
        return false;
    marker.operation = static_cast<Operation>(operation);
    std::memcpy(marker.prior_commitment.data(), bytes.data() + 5, 32);
    marker.exact_commitment = Hash256{};
    marker.open_recipient.clear();
    marker.mint_amount = 0;
    if (marker.operation == Operation::OPEN) {
        if (bytes.size() != OPEN_AUTH_PAYLOAD_BYTES) return false;
        marker.open_recipient.assign(
            bytes.begin() + 37,
            bytes.begin() + 37 + OPEN_AUTH_RECIPIENT_BYTES);
        if (!IsCanonicalTokenCreditAddress(marker.open_recipient) ||
            marker.open_recipient.size() != OPEN_AUTH_RECIPIENT_BYTES)
            return false;
        for (unsigned i = 0; i < 8; ++i)
            marker.mint_amount |=
                static_cast<uint64_t>(bytes[71 + i]) << (8 * i);
    } else {
        if (bytes.size() != STANDARD_AUTH_PAYLOAD_BYTES) return false;
        std::memcpy(marker.exact_commitment.data(), bytes.data() + 37, 32);
        for (unsigned i = 0; i < 8; ++i)
            marker.mint_amount |=
                static_cast<uint64_t>(bytes[69 + i]) << (8 * i);
    }
    return true;
}

inline std::vector<uint8_t> AuthScript(Operation operation,
                                       const Hash256& prior_commitment,
                                       const Hash256& exact_commitment,
                                       uint64_t mint_amount) {
    if (operation == Operation::OPEN || operation == Operation::FREEZE)
        return {};
    std::vector<uint8_t> payload(AUTH_MAGIC, AUTH_MAGIC + 4);
    payload.push_back(static_cast<uint8_t>(operation));
    payload.insert(payload.end(), prior_commitment.begin(),
                   prior_commitment.end());
    payload.insert(payload.end(), exact_commitment.begin(),
                   exact_commitment.end());
    for (unsigned i = 0; i < 8; ++i)
        payload.push_back(static_cast<uint8_t>(mint_amount >> (8 * i)));
    std::vector<uint8_t> script{0x6a, 0x4c,
                                static_cast<uint8_t>(payload.size())};
    script.insert(script.end(), payload.begin(), payload.end());
    if (script.size() > MAX_STANDARD_NULL_DATA_SCRIPT_BYTES) return {};
    return script;
}

// OPEN binds the complete canonical Veld recipient directly into the sole
// Bitcoin null-data output.  The derived exact commitment still includes the
// reserve vout and value, while a relayer or signer cannot redirect the mint.
// This operation-specific 79-byte payload replaces the old, non-relayable
// combination of an RVS1 output plus a second btcVELD recipient OP_RETURN.
inline std::vector<uint8_t> OpenAuthScript(
        const Hash256& prior_commitment, const std::string& recipient,
        uint64_t mint_amount) {
    if (recipient.size() != OPEN_AUTH_RECIPIENT_BYTES ||
        !IsCanonicalTokenCreditAddress(recipient))
        return {};
    std::vector<uint8_t> payload(AUTH_MAGIC, AUTH_MAGIC + 4);
    payload.push_back(static_cast<uint8_t>(Operation::OPEN));
    payload.insert(payload.end(), prior_commitment.begin(),
                   prior_commitment.end());
    payload.insert(payload.end(), recipient.begin(), recipient.end());
    for (unsigned i = 0; i < 8; ++i)
        payload.push_back(static_cast<uint8_t>(mint_amount >> (8 * i)));
    if (payload.size() != OPEN_AUTH_PAYLOAD_BYTES) return {};
    std::vector<uint8_t> script{0x6a, 0x4c,
                                static_cast<uint8_t>(payload.size())};
    script.insert(script.end(), payload.begin(), payload.end());
    if (script.size() > MAX_STANDARD_NULL_DATA_SCRIPT_BYTES) return {};
    return script;
}

inline bool ExtractRecipient(const std::vector<btcspv::BtcTxOut>& outputs,
                             std::string& recipient) {
    static const std::string TAG = "btcVELD:";
    size_t matches = 0;
    recipient.clear();
    for (const auto& output : outputs) {
        const std::vector<uint8_t> data = btcspv::ExtractOpReturn(output.spk);
        if (data.size() <= TAG.size() ||
            !std::equal(TAG.begin(), TAG.end(), data.begin()))
            continue;
        ++matches;
        recipient.assign(data.begin() + static_cast<std::ptrdiff_t>(TAG.size()),
                         data.end());
    }
    return matches == 1;
}

inline Hash256 OpenDepositCommitment(uint32_t reserve_vout,
                                     uint64_t reserve_value,
                                     const std::string& recipient) {
    std::vector<uint8_t> body;
    state_digest::put_u32_le(body, reserve_vout);
    state_digest::put_u64_le(body, reserve_value);
    state_digest::put_len_prefixed(body, recipient);
    return state_digest::sha256_domain(
        "VELD/BTCVELD/PENDING_DEPOSIT/v1/OPEN", body);
}

inline Hash256 PendingDepositCommitment(const Hash256& txid, uint32_t vout,
                                        uint64_t value,
                                        const std::string& recipient) {
    std::vector<uint8_t> body;
    state_digest::put_bytes(body, txid.data(), txid.size());
    state_digest::put_u32_le(body, vout);
    state_digest::put_u64_le(body, value);
    state_digest::put_len_prefixed(body, recipient);
    return state_digest::sha256_domain(
        "VELD/BTCVELD/PENDING_DEPOSIT/v1", body);
}

inline Hash256 TransitionCommitment(const Claim& claim) {
    std::vector<uint8_t> body;
    state_digest::put_bytes(body, claim.network_binding.data(), 32);
    state_digest::put_bytes(body, claim.prior_commitment.data(), 32);
    state_digest::put_bytes(body, claim.prior_reserve_txid.data(), 32);
    state_digest::put_u32_le(body, claim.prior_reserve_vout);
    state_digest::put_u64_le(body, claim.prior_reserve_value);
    state_digest::put_u64_le(body, claim.prior_transition_count);
    state_digest::put_bytes(body, claim.new_reserve_txid.data(), 32);
    state_digest::put_u32_le(body, claim.new_reserve_vout);
    state_digest::put_u64_le(body, claim.new_reserve_value);
    state_digest::put_bytes(body, claim.bitcoin_txid.data(), 32);
    state_digest::put_bytes(body, claim.bitcoin_block.data(), 32);
    state_digest::put_u8(body, static_cast<uint8_t>(claim.operation));
    state_digest::put_bytes(body, claim.exact_commitment.data(), 32);
    state_digest::put_u64_le(body, claim.mint_amount);
    return state_digest::sha256_domain(
        "VELD/BTCVELD/RESERVE_TRANSITION/v1", body);
}

struct InputFacts {
    std::vector<btcspv::BtcPrevout> prevouts;
    std::vector<btcspv::BtcTxOut> spent_outputs;
    uint64_t input_total = 0;
};

inline bool ReadInputFacts(const Claim& claim, InputFacts& facts,
                           std::string& reason) {
    facts = InputFacts{};
    btcspv::WitnessAwareBtcTx spend;
    if (!btcspv::ParseWitnessAwareBtcTx(
            claim.bitcoin_tx, spend, MAX_DIRECT_INPUTS)) {
        reason = "Bitcoin input serialization is non-canonical";
        return false;
    }
    facts.prevouts = spend.prevouts;
    if (facts.prevouts.size() != claim.direct_parents.size() ||
        facts.prevouts.empty() || facts.prevouts.size() > MAX_DIRECT_INPUTS) {
        reason = "direct parent set does not match Bitcoin inputs";
        return false;
    }
    facts.spent_outputs.reserve(facts.prevouts.size());
    for (size_t i = 0; i < facts.prevouts.size(); ++i) {
        if ((HashIsZero(facts.prevouts[i].txid) &&
             facts.prevouts[i].vout == UINT32_MAX)) {
            reason = "reserve transaction cannot spend a coinbase marker";
            return false;
        }
        btcspv::WitnessAwareBtcTx parent;
        if (!btcspv::ParseWitnessAwareBtcTx(
                claim.direct_parents[i], parent) ||
            parent.txid != facts.prevouts[i].txid) {
            reason = "direct parent hash mismatch";
            return false;
        }
        if (facts.prevouts[i].vout >= parent.outputs.size()) {
            reason = "direct parent output is unavailable";
            return false;
        }
        const btcspv::BtcTxOut spent = parent.outputs[facts.prevouts[i].vout];
        if (facts.input_total > UINT64_MAX - spent.value) {
            reason = "Bitcoin input value overflow";
            return false;
        }
        facts.input_total += spent.value;
        facts.spent_outputs.push_back(spent);
    }
    return true;
}

inline bool SumOutputs(const std::vector<btcspv::BtcTxOut>& outputs,
                       uint64_t& total) {
    total = 0;
    for (const auto& output : outputs) {
        if (total > UINT64_MAX - output.value) return false;
        total += output.value;
    }
    return true;
}

inline bool MatchesPrior(const State& state, const Claim& claim) {
    return claim.network_binding == NetworkBinding() &&
           claim.prior_commitment == state.transition_commitment &&
           claim.prior_reserve_txid == state.reserve_txid &&
           claim.prior_reserve_vout == state.reserve_vout &&
           claim.prior_reserve_value == state.reserve_value_sats &&
           claim.prior_transition_count == state.transition_count;
}

} // namespace detail

inline bool DecodeProof(const uint8_t* payload, size_t size, Claim& out) {
    return detail::DecodeProof(payload, size, out);
}

inline bool DecodeState(const uint8_t* payload, size_t size, State& out) {
    return detail::DecodeState(payload, size, out);
}

// Canonical proof producer used by the coordinator and the isolated consensus
// harness.  All integers are little-endian and every variable-length field is
// bounded before narrowing its length.  DecodeProof is applied to the result so
// encoder and verifier can never drift into two wire grammars.
inline std::vector<uint8_t> EncodeProof(const Claim& claim) {
    const uint8_t operation = static_cast<uint8_t>(claim.operation);
    if (!detail::ValidOperation(operation) ||
        claim.merkle_branch.size() > 32 ||
        claim.merkle_directions > UINT32_MAX ||
        (claim.merkle_branch.size() < 32 &&
         (claim.merkle_directions >> claim.merkle_branch.size()) != 0) ||
        claim.bitcoin_tx.size() <= 64 ||
        claim.bitcoin_tx.size() > btcnull::MAX_MSPV_STRIPPED_TX_BYTES ||
        claim.direct_parents.empty() ||
        claim.direct_parents.size() > MAX_DIRECT_INPUTS)
        return {};

    size_t parent_total = 0;
    for (const auto& parent : claim.direct_parents) {
        if (parent.size() < 10 ||
            parent.size() > btcnull::MAX_MSPV_PARENT_TX_BYTES ||
            parent_total > btcnull::MAX_MSPV_PARENT_TOTAL_BYTES -
                               parent.size())
            return {};
        parent_total += parent.size();
    }
    std::vector<uint8_t> nullifier;
    if (claim.has_nullifier_proof) {
        nullifier = btcnull::EncodeProof(claim.nullifier_proof);
        btcnull::Proof decoded;
        if (nullifier.size() < btcnull::MIN_PROOF_BYTES ||
            nullifier.size() > btcnull::MAX_PROOF_BYTES ||
            !btcnull::DecodeProof(nullifier, decoded))
            return {};
    }

    std::vector<uint8_t> out(PROOF_MAGIC, PROOF_MAGIC + 4);
    auto put_u8 = [&out](uint8_t value) { out.push_back(value); };
    auto put_u16 = [&out](uint16_t value) {
        out.push_back(static_cast<uint8_t>(value));
        out.push_back(static_cast<uint8_t>(value >> 8));
    };
    auto put_u32 = [&out](uint32_t value) {
        for (unsigned i = 0; i < 4; ++i)
            out.push_back(static_cast<uint8_t>(value >> (8 * i)));
    };
    auto put_u64 = [&out](uint64_t value) {
        for (unsigned i = 0; i < 8; ++i)
            out.push_back(static_cast<uint8_t>(value >> (8 * i)));
    };
    auto put_hash = [&out](const Hash256& hash) {
        out.insert(out.end(), hash.begin(), hash.end());
    };
    auto put_bytes = [&out](const std::vector<uint8_t>& bytes) {
        out.insert(out.end(), bytes.begin(), bytes.end());
    };

    put_u8(operation);
    put_hash(claim.network_binding);
    put_hash(claim.prior_commitment);
    put_hash(claim.prior_reserve_txid);
    put_u32(claim.prior_reserve_vout);
    put_u64(claim.prior_reserve_value);
    put_u64(claim.prior_transition_count);
    put_hash(claim.new_reserve_txid);
    put_u32(claim.new_reserve_vout);
    put_u64(claim.new_reserve_value);
    put_hash(claim.bitcoin_txid);
    put_hash(claim.bitcoin_block);
    put_u32(static_cast<uint32_t>(claim.merkle_directions));
    put_u8(static_cast<uint8_t>(claim.merkle_branch.size()));
    for (const Hash256& sibling : claim.merkle_branch) put_hash(sibling);
    put_hash(claim.exact_commitment);
    put_u64(claim.mint_amount);
    put_u32(static_cast<uint32_t>(claim.bitcoin_tx.size()));
    put_bytes(claim.bitcoin_tx);
    put_u16(static_cast<uint16_t>(claim.direct_parents.size()));
    for (const auto& parent : claim.direct_parents) {
        put_u32(static_cast<uint32_t>(parent.size()));
        put_bytes(parent);
    }
    put_u32(static_cast<uint32_t>(nullifier.size()));
    put_bytes(nullifier);

    Claim decoded;
    if (out.size() > MAX_PROOF_BYTES ||
        !detail::DecodeProof(out.data(), out.size(), decoded))
        return {};
    return out;
}

enum class SpendDisposition : uint8_t {
    NOT_CURRENT_RESERVE = 0,
    AUTHORIZED_TRANSITION = 1,
    UNAUTHORIZED_SPEND = 2,
};

struct SpendClassification {
    SpendDisposition disposition = SpendDisposition::UNAUTHORIZED_SPEND;
    std::string reason;
    Operation operation = Operation::FREEZE;
    Hash256 bitcoin_txid{};
    Hash256 new_reserve_txid{};
    uint32_t new_reserve_vout = NO_VOUT;
    uint64_t new_reserve_value = 0;
    Hash256 exact_commitment{};
    uint64_t mint_amount = 0;
    std::string recipient;
    std::string pending_outpoint;
    PayoutContext payout;
};

using PayoutLookup =
    std::function<bool(const Hash256&, PayoutContext&)>;

// One order-independent Bitcoin spend classifier is shared by RTP1 public and
// issuer submissions and by the FSP2 path.  It decides from the current
// canonical reserve, complete direct parents, and the Bitcoin transaction
// itself.  FSP2 cannot manufacture authority by being submitted first, while a
// transaction lacking the exact RVS1 marker and operation shape cannot evade
// FREEZE merely by looking like custody change.
inline SpendClassification ClassifyBitcoinReserveSpend(
        const State& state, uint64_t circulating_supply,
        const std::vector<uint8_t>& bitcoin_tx,
        const std::vector<std::vector<uint8_t>>& direct_parents,
        const std::vector<uint8_t>& custody_spk,
        const std::function<bool(const std::string&)>& valid_recipient,
        const PayoutLookup& payout_lookup = {}) {
    SpendClassification out;
    if (!state.Canonical() || custody_spk.empty() ||
        !state.AccountingHolds(circulating_supply)) {
        out.reason = "reserve state or accounting is non-canonical";
        return out;
    }

    Claim facts_claim;
    facts_claim.bitcoin_tx = bitcoin_tx;
    facts_claim.direct_parents = direct_parents;
    detail::InputFacts inputs;
    btcspv::WitnessAwareBtcTx parsed_tx;
    if (!btcspv::ParseWitnessAwareBtcTx(
            bitcoin_tx, parsed_tx, MAX_DIRECT_INPUTS) ||
        !detail::ReadInputFacts(facts_claim, inputs, out.reason))
        return out;
    const std::vector<btcspv::BtcTxOut>& outputs = parsed_tx.outputs;
    uint64_t output_total = 0;
    if (!detail::SumOutputs(outputs, output_total) ||
        output_total > inputs.input_total) {
        out.reason = "Bitcoin transaction value conservation failed";
        return out;
    }
    out.bitcoin_txid = parsed_tx.txid;

    size_t auth_count = 0;
    size_t null_data_output_count = 0;
    detail::AuthMarker auth;
    size_t custody_output_count = 0;
    uint32_t custody_output_vout = NO_VOUT;
    uint64_t custody_output_value = 0;
    for (size_t i = 0; i < outputs.size(); ++i) {
        if (!outputs[i].spk.empty() && outputs[i].spk.front() == 0x6a)
            ++null_data_output_count;
        detail::AuthMarker candidate;
        if (detail::ParseAuthMarker(outputs[i], candidate)) {
            ++auth_count;
            auth = candidate;
        }
        if (outputs[i].spk == custody_spk) {
            ++custody_output_count;
            custody_output_vout = static_cast<uint32_t>(i);
            custody_output_value = outputs[i].value;
        }
    }

    size_t current_inputs = 0;
    size_t other_custody_inputs = 0;
    size_t current_input_index = std::numeric_limits<size_t>::max();
    for (size_t i = 0; i < inputs.prevouts.size(); ++i) {
        const bool current = state.status != Status::EMPTY &&
            inputs.prevouts[i].txid == state.reserve_txid &&
            inputs.prevouts[i].vout == state.reserve_vout;
        if (current) {
            ++current_inputs;
            current_input_index = i;
            if (inputs.spent_outputs[i].spk != custody_spk ||
                inputs.spent_outputs[i].value != state.reserve_value_sats) {
                out.reason = "current reserve parent differs from canonical state";
                return out;
            }
        } else if (inputs.spent_outputs[i].spk == custody_spk) {
            ++other_custody_inputs;
        }
    }

    if (state.status == Status::FROZEN) {
        out.disposition = SpendDisposition::NOT_CURRENT_RESERVE;
        out.reason = "reserve is already frozen";
        return out;
    }
    // EMPTY has no current reserve to steal.  A malformed attempted OPEN or a
    // spend of pending collateral is invalid as RTP1, but it is never FSP2
    // evidence capable of freezing the bridge.
    if (state.status == Status::EMPTY)
        out.disposition = SpendDisposition::NOT_CURRENT_RESERVE;
    if (state.status == Status::ACTIVE && current_inputs == 0) {
        out.disposition = SpendDisposition::NOT_CURRENT_RESERVE;
        out.reason = "transaction does not spend the current reserve";
        return out;
    }
    if (auth_count != 1 || null_data_output_count != 1 ||
        auth.prior_commitment !=
            state.transition_commitment) {
        out.reason =
            "reserve spend must carry exactly one state-bound RVS1 null-data output";
        return out;
    }
    out.operation = auth.operation;
    out.mint_amount = auth.mint_amount;

    if (state.status == Status::EMPTY) {
        out.recipient = auth.open_recipient;
        if (auth.operation != Operation::OPEN || current_inputs != 0 ||
            other_custody_inputs != 0 || custody_output_count != 1 ||
            custody_output_value == 0 ||
            custody_output_value > BTCVELD_SPV_MAX_CUSTODY_SATS ||
            auth.mint_amount > custody_output_value ||
            out.recipient.empty() ||
            !valid_recipient(out.recipient) ||
            out.recipient.size() != OPEN_AUTH_RECIPIENT_BYTES) {
            out.reason = "EMPTY reserve transaction is not a canonical OPEN";
            return out;
        }
        out.exact_commitment = detail::OpenDepositCommitment(
            custody_output_vout, custody_output_value, out.recipient);
        out.new_reserve_txid = out.bitcoin_txid;
        out.new_reserve_vout = custody_output_vout;
        out.new_reserve_value = custody_output_value;
        out.pending_outpoint = btcspv::BtcDepositOutpointId(
            out.bitcoin_txid, custody_output_vout);
        out.disposition = SpendDisposition::AUTHORIZED_TRANSITION;
        return out;
    }

    if (current_inputs != 1 ||
        current_input_index == std::numeric_limits<size_t>::max() ||
        auth.operation == Operation::OPEN ||
        auth.operation == Operation::FREEZE) {
        out.reason = "ACTIVE transition does not consume current reserve once";
        return out;
    }
    out.exact_commitment = auth.exact_commitment;

    if (auth.operation == Operation::DEPOSIT) {
        if (inputs.prevouts.size() != 2 || other_custody_inputs != 1 ||
            custody_output_count != 1 ||
            custody_output_value <= state.reserve_value_sats ||
            custody_output_value > BTCVELD_SPV_MAX_CUSTODY_SATS) {
            out.reason = "DEPOSIT input or successor shape is invalid";
            return out;
        }
        const size_t pending_index = current_input_index == 0 ? 1 : 0;
        btcspv::WitnessAwareBtcTx pending_parent;
        if (!btcspv::ParseWitnessAwareBtcTx(
                direct_parents[pending_index], pending_parent) ||
            !detail::ExtractRecipient(
                pending_parent.outputs, out.recipient) ||
            !valid_recipient(out.recipient)) {
            out.reason = "DEPOSIT original recipient is unavailable";
            return out;
        }
        size_t pending_custody_outputs = 0;
        for (const auto& output : pending_parent.outputs)
            if (output.spk == custody_spk) ++pending_custody_outputs;
        const auto& pending_prevout = inputs.prevouts[pending_index];
        const auto& pending_spent = inputs.spent_outputs[pending_index];
        const uint64_t increase = custody_output_value -
                                  state.reserve_value_sats;
        if (pending_custody_outputs != 1 ||
            increase > pending_spent.value || auth.mint_amount > increase ||
            auth.exact_commitment != detail::PendingDepositCommitment(
                pending_prevout.txid, pending_prevout.vout,
                pending_spent.value, out.recipient)) {
            out.reason = "DEPOSIT value or recipient commitment is invalid";
            return out;
        }
        for (const auto& output : outputs) {
            detail::AuthMarker ignored;
            if (output.spk == custody_spk ||
                (output.value == 0 &&
                 detail::ParseAuthMarker(output, ignored)))
                continue;
            out.reason = "DEPOSIT carries a mixed payout/value output";
            return out;
        }
        out.new_reserve_txid = out.bitcoin_txid;
        out.new_reserve_vout = custody_output_vout;
        out.new_reserve_value = custody_output_value;
        out.pending_outpoint = btcspv::BtcDepositOutpointId(
            pending_prevout.txid, pending_prevout.vout);
    } else if (auth.operation == Operation::ROLLOVER) {
        if (other_custody_inputs != 0 || custody_output_count != 1 ||
            custody_output_value != state.reserve_value_sats ||
            auth.mint_amount != 0 || !HashIsZero(auth.exact_commitment)) {
            out.reason = "ROLLOVER does not preserve the exact reserve";
            return out;
        }
        out.new_reserve_txid = out.bitcoin_txid;
        out.new_reserve_vout = custody_output_vout;
        out.new_reserve_value = custody_output_value;
    } else if (auth.operation == Operation::PAYOUT) {
        if (!payout_lookup ||
            !payout_lookup(auth.exact_commitment, out.payout) ||
            !out.payout.present || out.payout.principal_sats == 0 ||
            out.payout.destination_spk.empty() ||
            other_custody_inputs != 0 || inputs.prevouts.size() < 2 ||
            auth.mint_amount != 0 ||
            state.open_redemption_principal < out.payout.principal_sats ||
            state.reserve_value_sats < out.payout.principal_sats) {
            out.reason = "PAYOUT context or external fee input is invalid";
            return out;
        }
        size_t destination_count = 0;
        uint64_t destination_paid = 0;
        for (const auto& output : outputs) {
            if (output.value > 0 &&
                output.spk == out.payout.destination_spk) {
                ++destination_count;
                destination_paid = output.value;
            }
        }
        const uint64_t successor = state.reserve_value_sats -
                                   out.payout.principal_sats;
        if (destination_count != 1 ||
            destination_paid != out.payout.principal_sats ||
            (successor == 0 && custody_output_count != 0) ||
            (successor != 0 &&
             (custody_output_count != 1 ||
              custody_output_value != successor))) {
            out.reason = "PAYOUT does not reduce reserve by exact principal";
            return out;
        }
        if (successor != 0) {
            out.new_reserve_txid = out.bitcoin_txid;
            out.new_reserve_vout = custody_output_vout;
            out.new_reserve_value = custody_output_value;
        }
    } else if (auth.operation == Operation::CLOSE) {
        if (other_custody_inputs != 0 || custody_output_count != 0 ||
            auth.mint_amount != 0 || !HashIsZero(auth.exact_commitment) ||
            circulating_supply != 0 ||
            state.open_redemption_principal != 0 ||
            state.reserve_value_sats != state.surplus_sats) {
            out.reason = "CLOSE has liabilities or a reserve successor";
            return out;
        }
    } else {
        out.reason = "unknown ACTIVE reserve operation";
        return out;
    }

    out.disposition = SpendDisposition::AUTHORIZED_TRANSITION;
    return out;
}

inline Result Verify(const btcspv::BtcHeaderChain& headers,
                     const State& state,
                     uint64_t circulating_supply,
                     const uint8_t* payload, size_t payload_size,
                     const std::vector<uint8_t>& custody_spk,
                     uint32_t finality_depth,
                     const std::function<bool(const std::string&)>& valid_recipient,
                     const PayoutContext& payout = {}) {
    Result result;
    if (!detail::DecodeProof(payload, payload_size, result.claim)) {
        result.reason = "malformed RTP1 reserve-transition proof";
        return result;
    }
    Claim& claim = result.claim;
    if (!state.Canonical() || custody_spk.empty() ||
        !detail::MatchesPrior(state, claim)) {
        result.reason = "stale or incompatible reserve prior state";
        return result;
    }
    if ((state.status == Status::EMPTY && claim.operation != Operation::OPEN) ||
        (state.status == Status::ACTIVE && claim.operation == Operation::OPEN) ||
        state.status == Status::FROZEN) {
        result.reason = "reserve operation is invalid for current status";
        return result;
    }
    btcspv::WitnessAwareBtcTx parsed_tx;
    if (!btcspv::ParseWitnessAwareBtcTx(
            claim.bitcoin_tx, parsed_tx, MAX_DIRECT_INPUTS)) {
        result.reason = "reserve Bitcoin transaction is non-canonical";
        return result;
    }
    const Hash256 txid = parsed_tx.txid;
    if (claim.bitcoin_txid != txid ||
        !headers.VerifyMerkle(claim.bitcoin_block, txid,
                              claim.merkle_branch,
                              claim.merkle_directions) ||
        !headers.IsFinalForExternalValue(claim.bitcoin_block,
                                         finality_depth)) {
        result.reason = "reserve transaction is not final on the Bitcoin best chain";
        return result;
    }

    const PayoutLookup payout_lookup =
        [&payout](const Hash256& commitment, PayoutContext& found) {
            if (!payout.present ||
                payout.request_commitment != commitment)
                return false;
            found = payout;
            return true;
        };
    const SpendClassification classification =
        ClassifyBitcoinReserveSpend(
            state, circulating_supply, claim.bitcoin_tx,
            claim.direct_parents, custody_spk, valid_recipient,
            payout_lookup);
    if (classification.disposition !=
            SpendDisposition::AUTHORIZED_TRANSITION ||
        classification.operation != claim.operation ||
        classification.bitcoin_txid != claim.bitcoin_txid ||
        classification.new_reserve_txid != claim.new_reserve_txid ||
        classification.new_reserve_vout != claim.new_reserve_vout ||
        classification.new_reserve_value != claim.new_reserve_value ||
        classification.exact_commitment != claim.exact_commitment ||
        classification.mint_amount != claim.mint_amount) {
        result.reason = classification.reason.empty()
            ? "RTP1 claim differs from classified Bitcoin transition"
            : classification.reason;
        return result;
    }

    const std::vector<btcspv::BtcTxOut>& outputs = parsed_tx.outputs;
    detail::InputFacts inputs;
    if (!detail::ReadInputFacts(claim, inputs, result.reason))
        return result;
    uint64_t output_total = 0;
    if (!detail::SumOutputs(outputs, output_total) ||
        output_total > inputs.input_total) {
        result.reason = "Bitcoin transaction value conservation failed";
        return result;
    }

    size_t auth_count = 0;
    size_t null_data_output_count = 0;
    detail::AuthMarker auth;
    size_t custody_output_count = 0;
    uint32_t custody_output_vout = NO_VOUT;
    uint64_t custody_output_value = 0;
    for (size_t i = 0; i < outputs.size(); ++i) {
        if (!outputs[i].spk.empty() && outputs[i].spk.front() == 0x6a)
            ++null_data_output_count;
        detail::AuthMarker candidate;
        if (detail::ParseAuthMarker(outputs[i], candidate)) {
            ++auth_count;
            auth = candidate;
        }
        if (outputs[i].spk == custody_spk) {
            ++custody_output_count;
            custody_output_vout = static_cast<uint32_t>(i);
            custody_output_value = outputs[i].value;
        }
    }
    if (claim.operation == Operation::FREEZE) {
        result.reason = "FREEZE uses the FSP2 current-reserve classifier";
        return result;
    }
    if (auth_count != 1 || null_data_output_count != 1 ||
        auth.operation != claim.operation ||
        auth.prior_commitment != claim.prior_commitment ||
        (claim.operation == Operation::OPEN
             ? auth.open_recipient != classification.recipient
             : auth.exact_commitment != claim.exact_commitment) ||
        auth.mint_amount != claim.mint_amount) {
        result.reason = "Bitcoin reserve authorization marker mismatch";
        return result;
    }

    size_t current_inputs = 0;
    size_t other_custody_inputs = 0;
    size_t current_input_index = std::numeric_limits<size_t>::max();
    for (size_t i = 0; i < inputs.prevouts.size(); ++i) {
        const bool current = state.status == Status::ACTIVE &&
            inputs.prevouts[i].txid == state.reserve_txid &&
            inputs.prevouts[i].vout == state.reserve_vout;
        if (current) {
            ++current_inputs;
            current_input_index = i;
            if (inputs.spent_outputs[i].spk != custody_spk ||
                inputs.spent_outputs[i].value != state.reserve_value_sats) {
                result.reason = "current reserve parent does not match state";
                return result;
            }
        } else if (inputs.spent_outputs[i].spk == custody_spk) {
            ++other_custody_inputs;
        }
    }

    const bool successor_expected =
        claim.operation != Operation::CLOSE &&
        !(claim.operation == Operation::PAYOUT &&
          claim.new_reserve_vout == NO_VOUT);
    if (successor_expected) {
        if (custody_output_count != 1 ||
            claim.new_reserve_txid != txid ||
            claim.new_reserve_vout != custody_output_vout ||
            claim.new_reserve_value != custody_output_value ||
            claim.new_reserve_vout == NO_VOUT ||
            claim.new_reserve_value == 0) {
            result.reason = "reserve successor output mismatch";
            return result;
        }
    } else if (custody_output_count != 0 ||
               !HashIsZero(claim.new_reserve_txid) ||
               claim.new_reserve_vout != NO_VOUT ||
               claim.new_reserve_value != 0) {
        result.reason = "terminal transition must not create a reserve successor";
        return result;
    }

    if (claim.operation == Operation::OPEN) {
        result.recipient = classification.recipient;
        if (current_inputs != 0 || other_custody_inputs != 0 ||
            claim.prior_reserve_vout != NO_VOUT ||
            !HashIsZero(claim.prior_reserve_txid) ||
            claim.prior_reserve_value != 0 ||
            claim.new_reserve_value > BTCVELD_SPV_MAX_CUSTODY_SATS ||
            claim.mint_amount > claim.new_reserve_value ||
            !claim.has_nullifier_proof ||
            result.recipient.empty() ||
            !valid_recipient(result.recipient) ||
            claim.exact_commitment != detail::OpenDepositCommitment(
                claim.new_reserve_vout, claim.new_reserve_value,
                result.recipient)) {
            result.reason = "OPEN does not prove one genuine external deposit";
            return result;
        }
        result.pending_outpoint = btcspv::BtcDepositOutpointId(
            txid, claim.new_reserve_vout);
        result.pending_value = claim.new_reserve_value;
    } else {
        if (current_inputs != 1 ||
            current_input_index == std::numeric_limits<size_t>::max()) {
            result.reason = "transition does not consume the exact current reserve once";
            return result;
        }
        if (claim.operation == Operation::DEPOSIT) {
            if (inputs.prevouts.size() != 2 || other_custody_inputs != 1 ||
                claim.new_reserve_value <= state.reserve_value_sats ||
                claim.new_reserve_value > BTCVELD_SPV_MAX_CUSTODY_SATS ||
                !claim.has_nullifier_proof) {
                result.reason = "DEPOSIT must consume current reserve and one pending deposit";
                return result;
            }
            const size_t pending_index = current_input_index == 0 ? 1 : 0;
            btcspv::WitnessAwareBtcTx pending_parent;
            if (!btcspv::ParseWitnessAwareBtcTx(
                    claim.direct_parents[pending_index], pending_parent) ||
                !detail::ExtractRecipient(
                    pending_parent.outputs, result.recipient) ||
                !valid_recipient(result.recipient)) {
                result.reason = "pending deposit commitment is unavailable";
                return result;
            }
            size_t pending_custody_outputs = 0;
            for (const auto& output : pending_parent.outputs)
                if (output.spk == custody_spk) ++pending_custody_outputs;
            const auto& pending_prevout = inputs.prevouts[pending_index];
            const auto& pending_spent = inputs.spent_outputs[pending_index];
            const uint64_t increase = claim.new_reserve_value -
                                      state.reserve_value_sats;
            if (pending_custody_outputs != 1 ||
                increase > pending_spent.value ||
                claim.mint_amount > increase ||
                claim.exact_commitment != detail::PendingDepositCommitment(
                    pending_prevout.txid, pending_prevout.vout,
                    pending_spent.value, result.recipient)) {
                result.reason = "DEPOSIT amount or original recipient commitment mismatch";
                return result;
            }
            // Launch v1 forbids a DEPOSIT transaction from carrying a payout or
            // unrelated value output: it has one reserve successor and one
            // zero-value authorization marker.  Any unused pending value is a
            // Bitcoin fee, never minted value.
            for (const auto& output : outputs) {
                detail::AuthMarker ignored;
                if (output.spk == custody_spk ||
                    (output.value == 0 &&
                     detail::ParseAuthMarker(output, ignored)))
                    continue;
                result.reason = "mixed DEPOSIT and payout/value output is forbidden";
                return result;
            }
            result.pending_outpoint = btcspv::BtcDepositOutpointId(
                pending_prevout.txid, pending_prevout.vout);
            result.pending_value = pending_spent.value;
        } else if (claim.operation == Operation::ROLLOVER) {
            if (other_custody_inputs != 0 ||
                claim.new_reserve_value != state.reserve_value_sats ||
                claim.mint_amount != 0 || !HashIsZero(claim.exact_commitment) ||
                claim.has_nullifier_proof) {
                result.reason = "ROLLOVER must preserve the exact reserve value";
                return result;
            }
        } else if (claim.operation == Operation::PAYOUT) {
            if (!payout.present || payout.principal_sats == 0 ||
                payout.destination_spk.empty() || other_custody_inputs != 0 ||
                inputs.prevouts.size() < 2 || claim.mint_amount != 0 ||
                claim.has_nullifier_proof ||
                claim.exact_commitment != payout.request_commitment ||
                payout.principal_sats > state.reserve_value_sats) {
                result.reason = "PAYOUT context or external fee input is missing";
                return result;
            }
            size_t destination_count = 0;
            uint64_t destination_paid = 0;
            for (const auto& output : outputs) {
                if (output.value > 0 &&
                    output.spk == payout.destination_spk) {
                    ++destination_count;
                    destination_paid = output.value;
                }
            }
            const uint64_t expected_successor = state.reserve_value_sats -
                                                payout.principal_sats;
            const bool terminal = expected_successor == 0;
            if (destination_count != 1 ||
                destination_paid != payout.principal_sats ||
                claim.new_reserve_value != expected_successor ||
                terminal != (claim.new_reserve_vout == NO_VOUT)) {
                result.reason = "PAYOUT does not reduce reserve by exact principal";
                return result;
            }
            // successor + destination consumes the prior reserve exactly.  All
            // remaining outputs and the Bitcoin fee are therefore funded only
            // by the separately proven non-reserve inputs.
            result.payout_request_id = payout.request_id;
            result.payout_principal_sats = payout.principal_sats;
            result.payout_destination_spk = payout.destination_spk;
            result.terminal = terminal;
        } else if (claim.operation == Operation::CLOSE) {
            if (other_custody_inputs != 0 || claim.mint_amount != 0 ||
                !HashIsZero(claim.exact_commitment) ||
                claim.has_nullifier_proof) {
                result.reason = "CLOSE has non-canonical fields";
                return result;
            }
            result.terminal = true;
        }
    }
    result.ok = true;
    return result;
}

inline bool SetProcessed(State& state, uint64_t height,
                         const Hash256& block_hash) {
    if (!state.Canonical() || HashIsZero(block_hash) ||
        height < state.processed_veld_height)
        return false;
    if (height == state.processed_veld_height &&
        !HashIsZero(state.processed_veld_block_hash) &&
        state.processed_veld_block_hash != block_hash)
        return false;
    state.processed_veld_height = height;
    state.processed_veld_block_hash = block_hash;
    return true;
}

inline bool ApplyAuthorized(State& state, const Result& verified,
                            uint64_t circulating_supply_before,
                            uint64_t circulating_supply_after) {
    if (!verified.ok || verified.claim.operation == Operation::FREEZE ||
        !state.AccountingHolds(circulating_supply_before) ||
        !detail::MatchesPrior(state, verified.claim) ||
        state.transition_count == UINT64_MAX)
        return false;
    const Claim& claim = verified.claim;
    State next = state;
    switch (claim.operation) {
        case Operation::OPEN:
            if (state.status != Status::EMPTY ||
                circulating_supply_after < circulating_supply_before ||
                circulating_supply_after - circulating_supply_before !=
                    claim.mint_amount)
                return false;
            next.status = Status::ACTIVE;
            next.reserve_txid = claim.new_reserve_txid;
            next.reserve_vout = claim.new_reserve_vout;
            next.reserve_value_sats = claim.new_reserve_value;
            next.reserve_bitcoin_block = claim.bitcoin_block;
            next.surplus_sats = claim.new_reserve_value - claim.mint_amount;
            break;
        case Operation::DEPOSIT: {
            if (state.status != Status::ACTIVE ||
                circulating_supply_after < circulating_supply_before ||
                circulating_supply_after - circulating_supply_before !=
                    claim.mint_amount ||
                claim.new_reserve_value <= state.reserve_value_sats)
                return false;
            const uint64_t increase = claim.new_reserve_value -
                                      state.reserve_value_sats;
            if (claim.mint_amount > increase ||
                next.surplus_sats > UINT64_MAX -
                    (increase - claim.mint_amount))
                return false;
            next.reserve_txid = claim.new_reserve_txid;
            next.reserve_vout = claim.new_reserve_vout;
            next.reserve_value_sats = claim.new_reserve_value;
            next.reserve_bitcoin_block = claim.bitcoin_block;
            next.surplus_sats += increase - claim.mint_amount;
            break;
        }
        case Operation::ROLLOVER:
            if (state.status != Status::ACTIVE ||
                circulating_supply_after != circulating_supply_before)
                return false;
            next.reserve_txid = claim.new_reserve_txid;
            next.reserve_vout = claim.new_reserve_vout;
            next.reserve_value_sats = claim.new_reserve_value;
            next.reserve_bitcoin_block = claim.bitcoin_block;
            break;
        case Operation::PAYOUT: {
            if (state.status != Status::ACTIVE ||
                circulating_supply_after != circulating_supply_before ||
                claim.new_reserve_value > state.reserve_value_sats ||
                state.open_redemption_principal <
                    state.reserve_value_sats - claim.new_reserve_value ||
                verified.payout_principal_sats !=
                    state.reserve_value_sats - claim.new_reserve_value)
                return false;
            const uint64_t principal = state.reserve_value_sats -
                                       claim.new_reserve_value;
            next.open_redemption_principal -= principal;
            next.reserve_value_sats = claim.new_reserve_value;
            if (verified.terminal) {
                if (circulating_supply_after != 0 ||
                    next.open_redemption_principal != 0 ||
                    next.surplus_sats != 0)
                    return false;
                next.status = Status::EMPTY;
                next.reserve_txid = Hash256{};
                next.reserve_vout = NO_VOUT;
                next.reserve_bitcoin_block = Hash256{};
            } else {
                next.reserve_txid = claim.new_reserve_txid;
                next.reserve_vout = claim.new_reserve_vout;
                next.reserve_bitcoin_block = claim.bitcoin_block;
            }
            break;
        }
        case Operation::CLOSE:
            if (state.status != Status::ACTIVE ||
                circulating_supply_before != 0 ||
                circulating_supply_after != 0 ||
                state.open_redemption_principal != 0 ||
                state.reserve_value_sats != state.surplus_sats)
                return false;
            next.status = Status::EMPTY;
            next.reserve_txid = Hash256{};
            next.reserve_vout = NO_VOUT;
            next.reserve_value_sats = 0;
            next.reserve_bitcoin_block = Hash256{};
            next.surplus_sats = 0;
            break;
        case Operation::FREEZE:
            return false;
    }
    ++next.transition_count;
    next.transition_commitment = detail::TransitionCommitment(claim);
    if (!next.AccountingHolds(circulating_supply_after)) return false;
    state = std::move(next);
    return true;
}

inline bool OpenRedemption(State& state, uint64_t amount,
                           uint64_t circulating_supply_after_burn) {
    if (state.status != Status::ACTIVE || amount == 0 ||
        state.open_redemption_principal > UINT64_MAX - amount)
        return false;
    State next = state;
    next.open_redemption_principal += amount;
    if (!next.AccountingHolds(circulating_supply_after_burn)) return false;
    state = std::move(next);
    return true;
}

inline bool ResolveDefaultOrCompensation(
        State& state, uint64_t amount,
        uint64_t circulating_supply_after_compensation) {
    if (amount == 0 || state.open_redemption_principal < amount)
        return false;
    State next = state;
    next.open_redemption_principal -= amount;
    if (!next.AccountingHolds(circulating_supply_after_compensation))
        return false;
    state = std::move(next);
    return true;
}

inline bool CancelRedemption(State&, uint64_t) {
    // A Veld REDEEM burns supply atomically when its obligation is admitted.
    // Launch v1 has no post-burn cancellation: expiry follows the deterministic
    // DEFAULTED + exact compensation path instead.
    return false;
}

inline bool ApplyFreeze(State& state, const Hash256& unauthorized_spend_txid,
                        const Hash256& bitcoin_block) {
    if (!state.Canonical() || state.status != Status::ACTIVE ||
        HashIsZero(unauthorized_spend_txid) || HashIsZero(bitcoin_block) ||
        state.transition_count == UINT64_MAX)
        return false;
    Claim claim;
    claim.operation = Operation::FREEZE;
    claim.network_binding = NetworkBinding();
    claim.prior_commitment = state.transition_commitment;
    claim.prior_reserve_txid = state.reserve_txid;
    claim.prior_reserve_vout = state.reserve_vout;
    claim.prior_reserve_value = state.reserve_value_sats;
    claim.prior_transition_count = state.transition_count;
    // FROZEN retains the last authorized outpoint/value as an accounting record;
    // status says it is no longer an ordinary spendable reserve.
    claim.new_reserve_txid = state.reserve_txid;
    claim.new_reserve_vout = state.reserve_vout;
    claim.new_reserve_value = state.reserve_value_sats;
    claim.bitcoin_txid = unauthorized_spend_txid;
    claim.bitcoin_block = bitcoin_block;
    State next = state;
    next.status = Status::FROZEN;
    ++next.transition_count;
    next.transition_commitment = detail::TransitionCommitment(claim);
    state = std::move(next);
    return true;
}

} // namespace reserve
} // namespace btcveld
} // namespace veld
