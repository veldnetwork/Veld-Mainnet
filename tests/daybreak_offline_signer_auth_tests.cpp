#include "wallet/wallet.h"
#include "wallet/offline_signing.h"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace veld;

namespace {

int g_checks = 0;
#define CHECK(condition) do {                                                   \
    ++g_checks;                                                                 \
    if (!(condition)) throw std::runtime_error(                                 \
        std::string("check failed at line ") + std::to_string(__LINE__) +      \
        ": " #condition);                                                      \
} while (false)

std::string Q(const std::string& value) { return "\"" + value + "\""; }

std::vector<uint8_t> OwnedScript() {
    std::vector<uint8_t> script{0x76, 0xa9, 0x14};
    for (uint8_t i = 0; i < 20; ++i) script.push_back(i + 1);
    script.push_back(0x88); script.push_back(0xac);
    return script;
}

std::string ValidBhdrIdentity() {
    std::vector<uint8_t> payload{'B', 'H', 'D', 'R', 1};
    payload.resize(5 + 80, 0);
    return "VELD_BHDR|" + BytesToHex(payload);
}

Transaction Parent(uint64_t value, const std::vector<uint8_t>& script,
                   const std::string& tag = "parent") {
    Transaction parent;
    parent.inputs.push_back(TxInput::Coinbase(tag));
    parent.outputs.emplace_back(value, script);
    return parent;
}

Transaction Spend(const Transaction& parent, uint32_t vout,
                  const std::vector<TxOutput>& outputs,
                  bool duplicate = false) {
    Transaction tx;
    TxInput input;
    input.prev_tx_hash = parent.GetTxID();
    input.prev_out_index = vout;
    tx.inputs.push_back(input);
    if (duplicate) tx.inputs.push_back(input);
    tx.outputs = outputs;
    return tx;
}

std::string Proposal(const Transaction& tx,
                     const std::vector<Transaction>& parents,
                     const std::vector<uint8_t>& owned,
                     uint64_t claimed_input,
                     uint64_t claimed_output,
                     uint64_t claimed_fee,
                     uint64_t claimed_change,
                     bool omit_first_parent = false,
                     uint64_t first_claimed_value = UINT64_MAX) {
    std::string inputs = "[";
    for (size_t i = 0; i < tx.inputs.size(); ++i) {
        if (i) inputs += ",";
        const Transaction& parent = parents.at(i);
        const uint32_t vout = tx.inputs[i].prev_out_index;
        const uint64_t actual = vout < parent.outputs.size()
            ? parent.outputs[vout].value : 0;
        const uint64_t claim = (i == 0 && first_claimed_value != UINT64_MAX)
            ? first_claimed_value : actual;
        inputs += "{";
        inputs += "\"index\":" + std::to_string(i) + ",";
        inputs += "\"sighash_hex\":" +
            Q(BytesToHex(ComputeSighash(tx, static_cast<uint32_t>(i), owned))) + ",";
        inputs += "\"prev_script_hex\":" + Q(BytesToHex(owned)) + ",";
        inputs += "\"value\":" + std::to_string(claim);
        if (!(omit_first_parent && i == 0))
            inputs += ",\"parent_tx_hex\":" + Q(BytesToHex(parent.Serialize()));
        inputs += "}";
    }
    inputs += "]";
    return "{" +
        std::string("\"unsigned_tx_hex\":") + Q(BytesToHex(tx.Serialize())) + "," +
        "\"inputs\":" + inputs + "," +
        "\"total_input\":" + std::to_string(claimed_input) + "," +
        "\"total_output\":" + std::to_string(claimed_output) + "," +
        "\"fee\":" + std::to_string(claimed_fee) + "," +
        "\"change\":" + std::to_string(claimed_change) + "}";
}

bool Authenticate(const std::string& json, const std::vector<uint8_t>& owned,
                  offline_signing::VerifiedPrepared* result = nullptr) {
    btc_buy::JsonValue root;
    std::string error;
    btc_buy::StrictJsonParser parser(json, offline_signing::kMaxPreparedJsonBytes,
                                     true);
    if (!parser.Parse(root, error)) return false;
    offline_signing::VerifiedPrepared local;
    const bool ok = offline_signing::AuthenticatePrepared(root, owned, local, error);
    if (ok && result) *result = std::move(local);
    return ok;
}

std::string IntentJson(const offline_signing::Intent& intent) {
    return "{" +
        std::string("\"version\":") + Q(intent.version) + "," +
        "\"operation_type\":" + Q(intent.operation_type) + "," +
        "\"intended_recipient\":" + Q(intent.intended_recipient) + "," +
        "\"intended_amount\":" + std::to_string(intent.intended_amount) + "," +
        "\"expected_change_destination\":" +
            Q(intent.expected_change_destination) + "," +
        "\"expected_change\":" + std::to_string(intent.expected_change) + "," +
        "\"maximum_absolute_fee\":" +
            std::to_string(intent.maximum_absolute_fee) + "," +
        "\"maximum_fee_rate\":" +
            std::to_string(intent.maximum_fee_rate) + "," +
        "\"source_transactions_digest\":" +
            Q(intent.source_transactions_digest) + "," +
        "\"complete_output_digest\":" + Q(intent.complete_output_digest) + "," +
        "\"operation_identity_digest\":" +
            Q(intent.operation_identity_digest) + "," +
        "\"intent_digest\":" + Q(intent.intent_digest) + "}";
}

bool VerifyAgainst(const offline_signing::VerifiedPrepared& verified,
                   const offline_signing::Intent& intent,
                   uint64_t expected_change = 100000) {
    std::string error;
    return offline_signing::VerifyIntent(
        intent, verified, "VELD_BHDR|", "", 0, "issuer-address",
        expected_change, ValidBhdrIdentity(), error);
}

} // namespace

int main() {
    try {
        const auto owned = OwnedScript();
        const auto marker = BuildOpReturnScript(ValidBhdrIdentity());
        const Transaction parent = Parent(200000, owned);
        const Transaction valid_tx = Spend(
            parent, 0, {TxOutput(100000, owned), TxOutput(0, marker)});
        const std::string valid_json = Proposal(
            valid_tx, {parent}, owned, 200000, 100000, 100000, 100000);
        offline_signing::VerifiedPrepared valid;
        CHECK(Authenticate(valid_json, owned, &valid));
        CHECK(valid.total_input == 200000);
        CHECK(valid.total_output == 100000);
        CHECK(valid.fee == offline_signing::kHardAbsoluteFeeUnits);
        CHECK(valid.fee_rate <= offline_signing::kHardFeeRateUnitsPerByte);

        const auto canonical_intent = offline_signing::MakeIntent(
            valid_tx, {parent.Serialize()}, "VELD_BHDR|", "", 0,
            "issuer-address", 100000, ValidBhdrIdentity());
        CHECK(VerifyAgainst(valid, canonical_intent));

        // The production signer accepts only the exact canonical fees-only
        // envelope.  Owning a destination does not make an extra or split
        // output permissible.
        std::string envelope_error;
        CHECK(offline_signing::VerifyExactFeesOnlyEnvelope(
            valid, owned, envelope_error));
        auto split_change = valid;
        split_change.tx.outputs = {
            TxOutput(50000, owned), TxOutput(50000, owned), TxOutput(0, marker)};
        CHECK(!offline_signing::VerifyExactFeesOnlyEnvelope(
            split_change, owned, envelope_error));
        auto marker_first = valid;
        marker_first.tx.outputs = {TxOutput(0, marker), TxOutput(100000, owned)};
        CHECK(!offline_signing::VerifyExactFeesOnlyEnvelope(
            marker_first, owned, envelope_error));
        auto extra_output = valid;
        extra_output.tx.outputs.insert(extra_output.tx.outputs.begin() + 1,
                                      TxOutput(0, std::vector<uint8_t>{0x51}));
        CHECK(!offline_signing::VerifyExactFeesOnlyEnvelope(
            extra_output, owned, envelope_error));
        auto wrong_fee = valid;
        wrong_fee.fee = MIN_TX_FEE - 1;
        CHECK(!offline_signing::VerifyExactFeesOnlyEnvelope(
            wrong_fee, owned, envelope_error));
        auto wrong_change_claim = valid;
        wrong_change_claim.claimed_change--;
        CHECK(!offline_signing::VerifyExactFeesOnlyEnvelope(
            wrong_change_claim, owned, envelope_error));

        // A detached intent is authorized with a real ML-DSA signature bound
        // to the exact intent, authorizer key, public release network, and
        // genesis.  Recomputed unkeyed intent digests are insufficient.
        Secp256k1PrivKey authorizer_seed{};
        for (size_t i = 0; i < authorizer_seed.size(); ++i)
            authorizer_seed[i] = static_cast<uint8_t>(i + 1U);
        const auto authorizer_pubkey = DerivePublicKey(authorizer_seed);
        offline_signing::IntentAuthorization authorization;
        authorization.intent_digest = canonical_intent.intent_digest;
        authorization.network_identity = DEPLOYMENT_PROFILE_ID;
        authorization.genesis_hash = GENESIS_HASH;
        authorization.authorizer_pubkey_digest =
            offline_signing::AuthorizerPubkeyDigest(authorizer_pubkey);
        authorization.signature_hex = BytesToHex(Sign(
            authorizer_seed,
            offline_signing::IntentAuthorizationHash(
                canonical_intent, authorization.authorizer_pubkey_digest)));
        std::string authorization_error;
        CHECK(offline_signing::VerifyIntentAuthorization(
            canonical_intent, authorization, authorizer_pubkey,
            authorization_error));
        auto wrong_authorized_intent = canonical_intent;
        wrong_authorized_intent.intended_amount = 1;
        wrong_authorized_intent.intent_digest =
            offline_signing::IntentDigest(wrong_authorized_intent);
        CHECK(!offline_signing::VerifyIntentAuthorization(
            wrong_authorized_intent, authorization, authorizer_pubkey,
            authorization_error));
        auto altered_authorization = authorization;
        altered_authorization.signature_hex[0] =
            altered_authorization.signature_hex[0] == '0' ? '1' : '0';
        CHECK(!offline_signing::VerifyIntentAuthorization(
            canonical_intent, altered_authorization, authorizer_pubkey,
            authorization_error));
        auto other_seed = authorizer_seed;
        other_seed[0] ^= 0x5a;
        CHECK(!offline_signing::VerifyIntentAuthorization(
            canonical_intent, authorization, DerivePublicKey(other_seed),
            authorization_error));
        veld::compat::SecureZero(authorizer_seed.data(), authorizer_seed.size());
        veld::compat::SecureZero(other_seed.data(), other_seed.size());

        // Parent txid mismatch.
        const Transaction wrong_parent = Parent(200000, owned, "different-parent");
        CHECK(!Authenticate(Proposal(valid_tx, {wrong_parent}, owned,
                                     200000, 100000, 100000, 100000), owned));
        // Incorrect caller-supplied value.
        CHECK(!Authenticate(Proposal(valid_tx, {parent}, owned,
                                     200000, 100000, 100000, 100000,
                                     false, 199999), owned));
        // Missing parent.
        CHECK(!Authenticate(Proposal(valid_tx, {parent}, owned,
                                     200000, 100000, 100000, 100000,
                                     true), owned));
        // Wrong vout.
        const Transaction wrong_vout = Spend(
            parent, 1, {TxOutput(100000, owned), TxOutput(0, marker)});
        CHECK(!Authenticate(Proposal(wrong_vout, {parent}, owned,
                                     200000, 100000, 100000, 100000), owned));
        // A valid alternate vout with the same value and script must still
        // invalidate the original source/input intent.
        Transaction twin_parent;
        twin_parent.inputs.push_back(TxInput::Coinbase("twin-parent"));
        twin_parent.outputs = {TxOutput(200000, owned),
                               TxOutput(200000, owned)};
        const Transaction twin_original = Spend(
            twin_parent, 0,
            {TxOutput(100000, owned), TxOutput(0, marker)});
        const Transaction twin_switched = Spend(
            twin_parent, 1,
            {TxOutput(100000, owned), TxOutput(0, marker)});
        const auto twin_intent = offline_signing::MakeIntent(
            twin_original, {twin_parent.Serialize()}, "VELD_BHDR|", "", 0,
            "issuer-address", 100000, ValidBhdrIdentity());
        offline_signing::VerifiedPrepared twin_verified;
        CHECK(Authenticate(Proposal(twin_switched, {twin_parent}, owned,
                                    200000, 100000, 100000, 100000),
                           owned, &twin_verified));
        CHECK(!VerifyAgainst(twin_verified, twin_intent));
        // Duplicate input.
        const Transaction duplicate = Spend(
            parent, 0, {TxOutput(300000, owned), TxOutput(0, marker)}, true);
        CHECK(!Authenticate(Proposal(duplicate, {parent, parent}, owned,
                                     400000, 300000, 100000, 300000), owned));

        // Hidden output: parent authentication succeeds, original output intent fails.
        const Transaction hidden = Spend(parent, 0, {
            TxOutput(100000, owned), TxOutput(1, std::vector<uint8_t>{0x51}),
            TxOutput(0, marker)});
        offline_signing::VerifiedPrepared hidden_verified;
        CHECK(Authenticate(Proposal(hidden, {parent}, owned,
                                    200000, 100001, 99999, 100000),
                           owned, &hidden_verified));
        CHECK(!VerifyAgainst(hidden_verified, canonical_intent));

        // Redirected and omitted change both differ from the committed output set.
        const Transaction redirected = Spend(parent, 0, {
            TxOutput(100000, std::vector<uint8_t>{0x51}), TxOutput(0, marker)});
        offline_signing::VerifiedPrepared redirected_verified;
        CHECK(Authenticate(Proposal(redirected, {parent}, owned,
                                    200000, 100000, 100000, 0),
                           owned, &redirected_verified));
        CHECK(!VerifyAgainst(redirected_verified, canonical_intent));

        const Transaction exact_fee_parent = Parent(100000, owned, "no-change-parent");
        const Transaction omitted = Spend(
            exact_fee_parent, 0, {TxOutput(0, marker)});
        offline_signing::VerifiedPrepared omitted_verified;
        CHECK(Authenticate(Proposal(omitted, {exact_fee_parent}, owned,
                                    100000, 0, 100000, 0),
                           owned, &omitted_verified));
        CHECK(!VerifyAgainst(omitted_verified, canonical_intent));

        // Fee immediately above the absolute ceiling.
        const Transaction fee_parent = Parent(200001, owned, "fee-parent");
        const Transaction fee_high = Spend(
            fee_parent, 0, {TxOutput(100000, owned), TxOutput(0, marker)});
        CHECK(!Authenticate(Proposal(fee_high, {fee_parent}, owned,
                                     200001, 100000, 100001, 100000), owned));

        // Independent fee-rate ceiling recheck at intent binding.
        auto rate_high = valid;
        rate_high.fee_rate = offline_signing::kHardFeeRateUnitsPerByte + 1;
        CHECK(!VerifyAgainst(rate_high, canonical_intent));

        // Negative fee.
        const Transaction negative_fee = Spend(
            parent, 0, {TxOutput(200001, owned), TxOutput(0, marker)});
        CHECK(!Authenticate(Proposal(negative_fee, {parent}, owned,
                                     200000, 200001, 0, 200001), owned));

        // Output and input overflow attempts are rejected before wraparound.
        const Transaction output_overflow = Spend(parent, 0, {
            TxOutput(UINT64_MAX, owned), TxOutput(1, owned), TxOutput(0, marker)});
        CHECK(!Authenticate(Proposal(output_overflow, {parent}, owned,
                                     200000, 0, 0, 0), owned));
        const Transaction huge_parent = Parent(UINT64_MAX, owned, "huge");
        const Transaction tiny_parent = Parent(1, owned, "tiny");
        Transaction input_overflow;
        TxInput a; a.prev_tx_hash = huge_parent.GetTxID(); a.prev_out_index = 0;
        TxInput b; b.prev_tx_hash = tiny_parent.GetTxID(); b.prev_out_index = 0;
        input_overflow.inputs = {a, b}; input_overflow.outputs = {TxOutput(0, marker)};
        CHECK(!Authenticate(Proposal(input_overflow, {huge_parent, tiny_parent},
                                     owned, 0, 0, 0, 0), owned));

        // Altered operation marker.
        const Transaction altered = Spend(parent, 0, {
            TxOutput(100000, owned),
            TxOutput(0, BuildOpReturnScript("VELD_ANCHOR|abcd"))});
        offline_signing::VerifiedPrepared altered_verified;
        CHECK(Authenticate(Proposal(altered, {parent}, owned,
                                    200000, 100000, 100000, 100000),
                           owned, &altered_verified));
        CHECK(!VerifyAgainst(altered_verified, canonical_intent));

        // Intent self-digest alteration is rejected by strict intent parsing.
        auto bad_intent = canonical_intent;
        bad_intent.intent_digest[0] = bad_intent.intent_digest[0] == '0' ? '1' : '0';
        btc_buy::JsonValue intent_root;
        std::string error;
        const std::string bad_intent_json = IntentJson(bad_intent);
        btc_buy::StrictJsonParser intent_parser(bad_intent_json, 65536, true);
        if (!intent_parser.Parse(intent_root, error))
            throw std::runtime_error("intent fixture parse failed: " + error +
                                     " json=" + bad_intent_json);
        ++g_checks;
        offline_signing::Intent parsed_intent;
        CHECK(!offline_signing::ParseIntent(intent_root, parsed_intent, error));

        std::cout << "PASS daybreak_offline_signer_auth_tests checks="
                  << g_checks << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL daybreak_offline_signer_auth_tests: "
                  << e.what() << "\n";
        return 1;
    }
}
