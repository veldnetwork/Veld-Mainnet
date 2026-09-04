#include "consensus/btcveld_mint_policy.h"
#include "consensus/btcveld_relay_policy.h"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace veld;
namespace reserve = veld::btcveld::reserve;

namespace {

constexpr const char* RECIPIENT = "VUjD1JoewGkiGxRqJ52FkK1UiMotjsp9Tg";
constexpr uint64_t MINT_SATS = 10'000;
constexpr uint64_t DEPOSIT_SATS = 4'000;

int g_checks = 0;

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        ++g_checks;                                                                                \
        if (!(condition)) {                                                                        \
            throw std::runtime_error(std::string("check failed at line ") +                        \
                                     std::to_string(__LINE__) + ": " #condition);                  \
        }                                                                                          \
    } while (false)

Hash256 TaggedHash(const std::string& tag) {
    return Hash256d(std::vector<uint8_t>(tag.begin(), tag.end()));
}

std::vector<uint8_t> OpReturn(const std::string& payload) {
    std::vector<uint8_t> script{0x6a};
    const size_t size = payload.size();
    if (size <= 75) {
        script.push_back(static_cast<uint8_t>(size));
    } else if (size <= 255) {
        script.push_back(0x4c);
        script.push_back(static_cast<uint8_t>(size));
    } else if (size <= 65'535) {
        script.push_back(0x4d);
        script.push_back(static_cast<uint8_t>(size));
        script.push_back(static_cast<uint8_t>(size >> 8));
    } else {
        throw std::runtime_error("test payload exceeds PUSHDATA2");
    }
    script.insert(script.end(), payload.begin(), payload.end());
    return script;
}

TxInput Input(const Hash256& txid, uint32_t vout) {
    TxInput input;
    input.prev_tx_hash = txid;
    input.prev_out_index = vout;
    return input;
}

std::vector<uint8_t> BitcoinTx(const std::vector<std::pair<Hash256, uint32_t>>& inputs,
                               const std::vector<btcspv::BtcTxOut>& outputs) {
    Transaction tx;
    for (const auto& input : inputs)
        tx.inputs.push_back(Input(input.first, input.second));
    for (const auto& output : outputs)
        tx.outputs.emplace_back(output.value, output.spk);
    return tx.Serialize();
}

Hash256 BitcoinTxid(const std::vector<uint8_t>& tx) {
    btcspv::WitnessAwareBtcTx parsed;
    if (!btcspv::ParseWitnessAwareBtcTx(tx, parsed))
        throw std::runtime_error("test Bitcoin transaction is non-canonical");
    return parsed.txid;
}

std::vector<uint8_t> WitnessBitcoinTx(const std::vector<std::pair<Hash256, uint32_t>>& inputs,
                                      const std::vector<btcspv::BtcTxOut>& outputs) {
    const std::vector<uint8_t> stripped = BitcoinTx(inputs, outputs);
    std::vector<uint8_t> tx;
    tx.insert(tx.end(), stripped.begin(), stripped.begin() + 4);
    tx.insert(tx.end(), {0x00, 0x01});
    tx.insert(tx.end(), stripped.begin() + 4, stripped.end() - 4);
    for (size_t i = 0; i < inputs.size(); ++i)
        tx.insert(tx.end(), {0x01, 0x01, static_cast<uint8_t>(i + 1)});
    tx.insert(tx.end(), stripped.end() - 4, stripped.end());
    btcspv::WitnessAwareBtcTx parsed;
    if (!btcspv::ParseWitnessAwareBtcTx(tx, parsed) || !parsed.has_witness ||
        parsed.txid != Hash256d(stripped) || parsed.txid == Hash256d(tx))
        throw std::runtime_error("witness test transaction is non-canonical");
    return tx;
}

std::vector<uint8_t> OpenProof(bool witness_serialization = false) {
    const std::vector<uint8_t> parent =
        BitcoinTx({{TaggedHash("signer-open-funding"), 0}}, {{MINT_SATS + 1'000, {0x51}}});

    reserve::Claim claim;
    claim.operation = reserve::Operation::OPEN;
    claim.network_binding = reserve::NetworkBinding();
    claim.prior_commitment = reserve::EmptyTransitionCommitment();
    claim.prior_reserve_txid = ZeroHash();
    claim.prior_reserve_vout = reserve::NO_VOUT;
    claim.new_reserve_vout = 0;
    claim.new_reserve_value = MINT_SATS;
    claim.mint_amount = MINT_SATS;
    claim.exact_commitment = reserve::detail::OpenDepositCommitment(
        claim.new_reserve_vout, claim.new_reserve_value, RECIPIENT);
    claim.direct_parents = {parent};
    claim.has_nullifier_proof = true;
    claim.nullifier_proof = btcnull::EmptyProof();
    claim.bitcoin_block = TaggedHash("signer-open-bitcoin-block");
    const std::vector<std::pair<Hash256, uint32_t>> inputs{{BitcoinTxid(parent), 0}};
    const std::vector<btcspv::BtcTxOut> outputs{
        {MINT_SATS, BtcVeldCustodySpk()},
        {0, reserve::detail::OpenAuthScript(claim.prior_commitment, RECIPIENT, claim.mint_amount)}};
    claim.bitcoin_tx =
        witness_serialization ? WitnessBitcoinTx(inputs, outputs) : BitcoinTx(inputs, outputs);
    claim.bitcoin_txid = BitcoinTxid(claim.bitcoin_tx);
    claim.new_reserve_txid = claim.bitcoin_txid;
    const std::vector<uint8_t> proof = reserve::EncodeProof(claim);
    CHECK(!proof.empty());
    return proof;
}

std::vector<uint8_t> DepositProof() {
    const Hash256 prior_commitment = TaggedHash("signer-prior-reserve-state");
    const std::vector<uint8_t> current = BitcoinTx(
        {{TaggedHash("signer-current-reserve-funding"), 0}}, {{MINT_SATS, BtcVeldCustodySpk()}});
    const std::vector<uint8_t> pending = BitcoinTx(
        {{TaggedHash("signer-pending-deposit-funding"), 0}},
        {{DEPOSIT_SATS, BtcVeldCustodySpk()}, {0, OpReturn(std::string("btcVELD:") + RECIPIENT)}});

    reserve::Claim claim;
    claim.operation = reserve::Operation::DEPOSIT;
    claim.network_binding = reserve::NetworkBinding();
    claim.prior_commitment = prior_commitment;
    claim.prior_reserve_txid = Hash256d(current);
    claim.prior_reserve_vout = 0;
    claim.prior_reserve_value = MINT_SATS;
    claim.prior_transition_count = 1;
    claim.new_reserve_vout = 0;
    claim.new_reserve_value = MINT_SATS + DEPOSIT_SATS;
    claim.mint_amount = DEPOSIT_SATS;
    claim.exact_commitment =
        reserve::detail::PendingDepositCommitment(Hash256d(pending), 0, DEPOSIT_SATS, RECIPIENT);
    claim.direct_parents = {current, pending};
    claim.has_nullifier_proof = true;
    claim.nullifier_proof = btcnull::EmptyProof();
    claim.bitcoin_block = TaggedHash("signer-deposit-bitcoin-block");
    claim.bitcoin_tx = BitcoinTx(
        {{Hash256d(current), 0}, {Hash256d(pending), 0}},
        {{MINT_SATS + DEPOSIT_SATS, BtcVeldCustodySpk()},
         {0, reserve::detail::AuthScript(reserve::Operation::DEPOSIT, claim.prior_commitment,
                                         claim.exact_commitment, claim.mint_amount)}});
    claim.bitcoin_txid = Hash256d(claim.bitcoin_tx);
    claim.new_reserve_txid = claim.bitcoin_txid;
    const std::vector<uint8_t> proof = reserve::EncodeProof(claim);
    CHECK(!proof.empty());
    return proof;
}

Transaction Carrier(const std::string& payload, const std::vector<uint8_t>& change_script) {
    Transaction tx;
    tx.inputs.push_back(Input(TaggedHash("veld-fee-input"), 0));
    tx.outputs.emplace_back(0, OpReturn(payload));
    tx.outputs.emplace_back(1'000, change_script);
    return tx;
}

std::string MintPayload(const std::string& recipient, uint64_t amount, const std::string& memo) {
    return std::string("VELD_TOKEN|MINT|btcVELD|issuer|") + recipient + "|" +
           std::to_string(amount) + "|" + memo;
}

void CheckRelayPolicy(const std::vector<uint8_t>& proof, const std::vector<uint8_t>& fee_script,
                      const std::vector<uint8_t>& redirected_script) {
    const std::string canonical = std::string(reserve::PUBLIC_CARRIER_PREFIX) + BytesToHex(proof);
    std::string family;
    const Transaction carrier = Carrier(canonical, fee_script);
#if defined(VELD_PUBLIC_MAINNET) || defined(VELD_BTCVELD_REGTEST)
    CHECK(BtcVeldRelayTemplatePolicy(carrier, fee_script, family).empty());
    CHECK(family == reserve::PUBLIC_CARRIER_PREFIX);

    std::vector<uint8_t> truncated = proof;
    truncated.pop_back();
    Transaction malformed =
        Carrier(std::string(reserve::PUBLIC_CARRIER_PREFIX) + BytesToHex(truncated), fee_script);
    CHECK(!BtcVeldRelayTemplatePolicy(malformed, fee_script, family).empty());

    Transaction uppercase = carrier;
    std::string upper = canonical;
    for (char& c : upper)
        if (c >= 'a' && c <= 'f')
            c = static_cast<char>(c - 'a' + 'A');
    uppercase.outputs[0].script_pubkey = OpReturn(upper);
    CHECK(!BtcVeldRelayTemplatePolicy(uppercase, fee_script, family).empty());

    Transaction redirected = carrier;
    redirected.outputs[1].script_pubkey = redirected_script;
    CHECK(!BtcVeldRelayTemplatePolicy(redirected, fee_script, family).empty());
#else
    CHECK(!BtcVeldRelayTemplatePolicy(carrier, fee_script, family).empty());
#endif
}

void CheckIssuerPolicy(const std::vector<uint8_t>& proof, uint64_t expected_amount,
                       const std::vector<uint8_t>& issuer_script,
                       const std::vector<uint8_t>& redirected_script) {
    const std::string memo = std::string(reserve::ISSUER_MEMO_PREFIX) + BytesToHex(proof);
    const Transaction canonical =
        Carrier(MintPayload(RECIPIENT, expected_amount, memo), issuer_script);
    std::string from;
    std::string to;
    std::string decoded_memo;
    uint64_t amount = 0;
#if defined(VELD_PUBLIC_MAINNET) || defined(VELD_BTCVELD_REGTEST)
    reserve::Claim policy_claim;
    CHECK(reserve::DecodeProof(proof.data(), proof.size(), policy_claim));
    BtcVeldReserveMintPolicyContext reserve_context;
    reserve_context.prior_state.status = policy_claim.operation == reserve::Operation::OPEN
                                             ? reserve::Status::EMPTY
                                             : reserve::Status::ACTIVE;
    reserve_context.prior_state.reserve_txid = policy_claim.prior_reserve_txid;
    reserve_context.prior_state.reserve_vout = policy_claim.prior_reserve_vout;
    reserve_context.prior_state.reserve_value_sats = policy_claim.prior_reserve_value;
    reserve_context.prior_state.transition_count = policy_claim.prior_transition_count;
    reserve_context.prior_state.transition_commitment = policy_claim.prior_commitment;
    // Header relays can advance the processed Veld cursor between Bitcoin
    // transaction construction and issuer preparation. It is rollback state,
    // not part of the rolling reserve prior tuple.
    reserve_context.prior_state.processed_veld_height = 1444;
    reserve_context.prior_state.processed_veld_block_hash =
        TaggedHash("signer-policy-processed-veld-tip");
    if (reserve_context.prior_state.status == reserve::Status::ACTIVE) {
        reserve_context.prior_state.reserve_bitcoin_block =
            TaggedHash("signer-policy-prior-bitcoin-block");
        reserve_context.circulating_supply = reserve_context.prior_state.reserve_value_sats;
    }
    CHECK(reserve_context.prior_state.AccountingHolds(reserve_context.circulating_supply));
    CHECK(BtcVeldMintTemplatePolicy(canonical, issuer_script, from, to, amount, decoded_memo,
                                    &reserve_context)
              .empty());
    CHECK(from == "issuer");
    CHECK(to == RECIPIENT);
    CHECK(amount == expected_amount);
    CHECK(decoded_memo == memo);

    Transaction recipient_redirect = Carrier(
        MintPayload("VV6pcrLQvxq7uBZEFtc4qxCizQ26azxTtK", expected_amount, memo), issuer_script);
    CHECK(!BtcVeldMintTemplatePolicy(recipient_redirect, issuer_script, from, to, amount,
                                     decoded_memo, &reserve_context)
               .empty());

    Transaction amount_change =
        Carrier(MintPayload(RECIPIENT, expected_amount - 1, memo), issuer_script);
    CHECK(!BtcVeldMintTemplatePolicy(amount_change, issuer_script, from, to, amount, decoded_memo,
                                     &reserve_context)
               .empty());

    std::vector<uint8_t> truncated = proof;
    truncated.pop_back();
    Transaction malformed =
        Carrier(MintPayload(RECIPIENT, expected_amount,
                            std::string(reserve::ISSUER_MEMO_PREFIX) + BytesToHex(truncated)),
                issuer_script);
    CHECK(!BtcVeldMintTemplatePolicy(malformed, issuer_script, from, to, amount, decoded_memo,
                                     &reserve_context)
               .empty());

    Transaction redirected = canonical;
    redirected.outputs[1].script_pubkey = redirected_script;
    CHECK(!BtcVeldMintTemplatePolicy(redirected, issuer_script, from, to, amount, decoded_memo,
                                     &reserve_context)
               .empty());
#else
    CHECK(!BtcVeldMintTemplatePolicy(canonical, issuer_script, from, to, amount, decoded_memo)
               .empty());
#endif
}

} // namespace

int main() {
    try {
        const std::vector<uint8_t> fee_script{0x76, 0xa9, 0x14, 1, 1, 1, 1, 1, 1, 1, 1, 1,    1,
                                              1,    1,    1,    1, 1, 1, 1, 1, 1, 1, 1, 0x88, 0xac};
        const std::vector<uint8_t> issuer_script{0x76, 0xa9, 0x14, 2, 2, 2, 2,    2,   2,
                                                 2,    2,    2,    2, 2, 2, 2,    2,   2,
                                                 2,    2,    2,    2, 2, 2, 0x88, 0xac};
        const std::vector<uint8_t> redirected_script{0x76, 0xa9, 0x14, 3, 3, 3, 3,    3,   3,
                                                     3,    3,    3,    3, 3, 3, 3,    3,   3,
                                                     3,    3,    3,    3, 3, 3, 0x88, 0xac};
        const std::vector<uint8_t> open_proof = OpenProof();
        const std::vector<uint8_t> witness_open_proof = OpenProof(true);
        const std::vector<uint8_t> deposit_proof = DepositProof();
        CheckRelayPolicy(open_proof, fee_script, redirected_script);
        CheckRelayPolicy(witness_open_proof, fee_script, redirected_script);
        CheckRelayPolicy(deposit_proof, fee_script, redirected_script);
        CheckIssuerPolicy(open_proof, MINT_SATS, issuer_script, redirected_script);
        CheckIssuerPolicy(witness_open_proof, MINT_SATS, issuer_script, redirected_script);
        CheckIssuerPolicy(deposit_proof, DEPOSIT_SATS, issuer_script, redirected_script);
        std::cout << "PASS signing_policy_tests checks=" << g_checks << " profile="
#if defined(VELD_PUBLIC_MAINNET)
                  << "public-mainnet";
#elif defined(VELD_BTCVELD_REGTEST)
                  << "reserve-regtest";
#else
                  << "generic";
#endif
        std::cout << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL signing_policy_tests: " << error.what() << '\n';
        return 1;
    }
}
