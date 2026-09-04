#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1

#include "network/rpc.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

using namespace veld;

namespace {

size_t checks = 0;

constexpr uint64_t VALIDATOR_FUNDING_TOTAL = MIN_VALIDATOR_STAKE + 2U * MIN_TX_FEE;
constexpr uint32_t VALIDATOR_FUNDING_OUTPUTS = 4U;

static_assert(!btcveld::reserve::TRANSITION_V1_REQUIRED,
              "the direct mint case covers the generic test profile; public "
              "mainnet RTP1 uses the source-equivalent construction path");

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        ++checks;                                                                                  \
        if (!(condition))                                                                          \
            throw std::runtime_error(std::string("check failed at line ") +                        \
                                     std::to_string(__LINE__) + ": " #condition);                  \
    } while (false)

std::string JsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8U);
    for (const char c : value) {
        switch (c) {
        case '\\':
            out += "\\\\";
            break;
        case '"':
            out += "\\\"";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            out += c;
            break;
        }
    }
    return out;
}

std::string MakeRpcRequest(const std::string& method, const std::vector<std::string>& params) {
    std::string request = "{\"jsonrpc\":\"2.0\",\"method\":\"" + method + "\",\"params\":[";
    for (size_t i = 0; i < params.size(); ++i) {
        if (i != 0U)
            request += ',';
        request += '"' + JsonEscape(params[i]) + '"';
    }
    return request + "],\"id\":1}";
}

btc_buy::JsonValue ParseResponse(const std::string& response) {
    btc_buy::JsonValue root;
    std::string error;
    btc_buy::StrictJsonParser parser(response, offline_signing::kMaxPreparedJsonBytes, true);
    CHECK(parser.Parse(root, error));
    CHECK(root.kind == btc_buy::JsonValue::Kind::Object);
    return root;
}

const btc_buy::JsonValue& RequireObject(const btc_buy::JsonValue& object, const char* name) {
    const auto* value = object.Get(name);
    CHECK(value != nullptr);
    CHECK(value->kind == btc_buy::JsonValue::Kind::Object);
    return *value;
}

const btc_buy::JsonValue& RequireArray(const btc_buy::JsonValue& object, const char* name) {
    const auto* value = object.Get(name);
    CHECK(value != nullptr);
    CHECK(value->kind == btc_buy::JsonValue::Kind::Array);
    return *value;
}

std::string RequireString(const btc_buy::JsonValue& object, const char* name) {
    const auto* value = object.Get(name);
    CHECK(value != nullptr);
    CHECK(value->kind == btc_buy::JsonValue::Kind::String);
    CHECK(!value->string_had_escape);
    return value->text;
}

uint64_t RequireUint(const btc_buy::JsonValue& object, const char* name) {
    const auto* value = object.Get(name);
    uint64_t parsed = 0;
    CHECK(value != nullptr);
    CHECK(btc_buy::ParseUint(*value, parsed));
    return parsed;
}

std::string RequireNumberText(const btc_buy::JsonValue& object, const char* name) {
    const auto* value = object.Get(name);
    CHECK(value != nullptr);
    CHECK(value->kind == btc_buy::JsonValue::Kind::Number);
    return value->text;
}

std::vector<uint8_t> P2pkhScript(uint8_t tag) {
    std::vector<uint8_t> script{0x76, 0xa9, 0x14};
    for (uint8_t i = 0; i < 20; ++i)
        script.push_back(static_cast<uint8_t>(tag + i));
    script.push_back(0x88);
    script.push_back(0xac);
    return script;
}

std::string ValidBhdrIdentity() {
    std::vector<uint8_t> payload{'B', 'H', 'D', 'R', 1};
    payload.resize(85U, 0U);
    return "VELD_BHDR|" + BytesToHex(payload);
}

Block ParentBlock(Blockchain& chain, const std::vector<uint8_t>& fund_script,
                  const std::vector<uint8_t>& issuer_script, Transaction& parent) {
    parent = Transaction::CreateCoinbase(VALIDATOR_FUNDING_TOTAL / VALIDATOR_FUNDING_OUTPUTS,
                                         fund_script, "rpc-preparer-parent-auth");
    for (uint32_t i = 1; i < VALIDATOR_FUNDING_OUTPUTS; ++i) {
        const uint64_t value =
            i + 1U == VALIDATOR_FUNDING_OUTPUTS
                ? VALIDATOR_FUNDING_TOTAL - (VALIDATOR_FUNDING_TOTAL / VALIDATOR_FUNDING_OUTPUTS) *
                                                (VALIDATOR_FUNDING_OUTPUTS - 1U)
                : VALIDATOR_FUNDING_TOTAL / VALIDATOR_FUNDING_OUTPUTS;
        parent.outputs.emplace_back(value, fund_script);
    }
    parent.outputs.emplace_back(2U * MIN_TX_FEE, issuer_script);
    Block block;
    block.height = 1;
    block.header.version = PROTOCOL_VERSION;
    block.header.prev_block_hash = chain.TipCopy().GetHash();
    block.header.timestamp = chain.TipCopy().header.timestamp + 1U;
    block.header.bits = chain.ComputeNextBits();
    block.header.nonce = 1U;
    block.transactions.push_back(parent);
    block.UpdateMerkleRoot();
    return block;
}

void InstallSpendableCanonicalParent(Blockchain& chain, const std::vector<uint8_t>& fund_script,
                                     const std::vector<uint8_t>& issuer_script, Transaction& parent,
                                     UTXO& funding, UTXO& issuer_funding) {
    CHECK(chain
              .AddBlockDirect(CreateGenesisBlock(), true, true, false,
                              mining::PowAdmissionContext::Internal())
              .IsAccepted());
    Block block = ParentBlock(chain, fund_script, issuer_script, parent);
    const auto parent_admission =
        chain.AddBlockDirect(block, true, true, false, mining::PowAdmissionContext::Internal());
    if (!parent_admission.IsAccepted())
        throw std::runtime_error("canonical parent fixture rejected: " + chain.GetLastRejectTag());
    CHECK(parent_admission.IsAccepted());
    const auto canonical = chain.GetUTXO(parent.GetTxID(), 0);
    CHECK(canonical.has_value());
    CHECK(canonical->is_coinbase);
    CHECK(canonical->block_height == 1U);
    CHECK(canonical->value == VALIDATOR_FUNDING_TOTAL / VALIDATOR_FUNDING_OUTPUTS);
    CHECK(canonical->script_pubkey == fund_script);
    const auto canonical_issuer = chain.GetUTXO(parent.GetTxID(), VALIDATOR_FUNDING_OUTPUTS);
    CHECK(canonical_issuer.has_value());
    CHECK(canonical_issuer->is_coinbase);
    CHECK(canonical_issuer->block_height == 1U);
    CHECK(canonical_issuer->value == 2U * MIN_TX_FEE);
    CHECK(canonical_issuer->script_pubkey == issuer_script);

    // Keep the parent transaction and its exact block position canonical, but
    // mature this one fixture outpoint without constructing 100 unrelated
    // blocks. The RPC must still recover and authenticate the raw parent from
    // block 1; only ordinary coinbase-maturity selection is bypassed here.
    CHECK(chain.TestEraseUTXO(parent.GetTxID(), 0));
    funding = *canonical;
    funding.is_coinbase = false;
    chain.TestInjectUTXO(funding);
    for (uint32_t i = 1; i < VALIDATOR_FUNDING_OUTPUTS; ++i) {
        const auto canonical_part = chain.GetUTXO(parent.GetTxID(), i);
        CHECK(canonical_part.has_value());
        CHECK(canonical_part->is_coinbase);
        CHECK(canonical_part->block_height == 1U);
        CHECK(canonical_part->script_pubkey == fund_script);
        CHECK(chain.TestEraseUTXO(parent.GetTxID(), i));
        UTXO spendable_part = *canonical_part;
        spendable_part.is_coinbase = false;
        chain.TestInjectUTXO(spendable_part);
    }
    CHECK(chain.TestEraseUTXO(parent.GetTxID(), VALIDATOR_FUNDING_OUTPUTS));
    issuer_funding = *canonical_issuer;
    issuer_funding.is_coinbase = false;
    chain.TestInjectUTXO(issuer_funding);
}

void CheckIntentEqual(const offline_signing::Intent& actual,
                      const offline_signing::Intent& expected) {
    CHECK(actual.version == expected.version);
    CHECK(actual.operation_type == expected.operation_type);
    CHECK(actual.intended_recipient == expected.intended_recipient);
    CHECK(actual.intended_amount == expected.intended_amount);
    CHECK(actual.expected_change_destination == expected.expected_change_destination);
    CHECK(actual.expected_change == expected.expected_change);
    CHECK(actual.maximum_absolute_fee == expected.maximum_absolute_fee);
    CHECK(actual.maximum_fee_rate == expected.maximum_fee_rate);
    CHECK(actual.source_transactions_digest == expected.source_transactions_digest);
    CHECK(actual.complete_output_digest == expected.complete_output_digest);
    CHECK(actual.operation_identity_digest == expected.operation_identity_digest);
    CHECK(actual.intent_digest == expected.intent_digest);
}

void CheckCanonicalPreparation(
    const btc_buy::JsonValue& root, const std::vector<uint8_t>& owned_script,
    const std::string& change_address, const std::string& operation_identity,
    const Transaction& canonical_parent, const std::string& operation_type,
    const std::string& intended_recipient, uint64_t intended_amount, uint32_t expected_vout) {
    const auto* rpc_error = root.Get("error");
    CHECK(rpc_error != nullptr);
    CHECK(rpc_error->kind == btc_buy::JsonValue::Kind::Null);
    const auto& result = RequireObject(root, "result");
    CHECK(result.Get("intent_authorization") == nullptr);

    std::vector<uint8_t> unsigned_raw;
    CHECK(offline_signing::DecodeLowerHex(RequireString(result, "unsigned_tx_hex"),
                                          offline_signing::kMaxUnsignedTransactionBytes,
                                          unsigned_raw));
    Transaction tx;
    CHECK(Transaction::Deserialize(unsigned_raw, 0, tx) == unsigned_raw.size());
    CHECK(tx.Serialize() == unsigned_raw);

    const auto& inputs = RequireArray(result, "inputs");
    CHECK(inputs.array.size() == tx.inputs.size());
    CHECK(!inputs.array.empty());
    std::vector<std::vector<uint8_t>> authenticated_parents;
    uint64_t total_input = 0;
    for (size_t i = 0; i < inputs.array.size(); ++i) {
        const auto& evidence = inputs.array[i];
        CHECK(evidence.kind == btc_buy::JsonValue::Kind::Object);
        CHECK(RequireUint(evidence, "index") == i);

        std::vector<uint8_t> parent_raw;
        CHECK(offline_signing::DecodeLowerHex(RequireString(evidence, "parent_tx_hex"),
                                              offline_signing::kMaxParentTransactionBytes,
                                              parent_raw));
        Transaction parent;
        CHECK(Transaction::Deserialize(parent_raw, 0, parent) == parent_raw.size());
        CHECK(parent.Serialize() == parent_raw);
        CHECK(parent.GetTxID() == tx.inputs[i].prev_tx_hash);
        CHECK(tx.inputs[i].prev_out_index < parent.outputs.size());
        const auto& prevout = parent.outputs[tx.inputs[i].prev_out_index];
        CHECK(RequireUint(evidence, "value") == prevout.value);
        CHECK(RequireString(evidence, "prev_script_hex") == BytesToHex(prevout.script_pubkey));
        CHECK(prevout.script_pubkey == owned_script);
        CHECK(RequireString(evidence, "sighash_hex") ==
              BytesToHex(ComputeSighash(tx, static_cast<uint32_t>(i), prevout.script_pubkey)));
        CHECK(total_input <= std::numeric_limits<uint64_t>::max() - prevout.value);
        total_input += prevout.value;
        authenticated_parents.push_back(std::move(parent_raw));
    }
    CHECK(authenticated_parents.size() == 1U);
    CHECK(authenticated_parents.front() == canonical_parent.Serialize());
    if (expected_vout != std::numeric_limits<uint32_t>::max())
        CHECK(tx.inputs.front().prev_out_index == expected_vout);

    uint64_t total_output = 0;
    for (const auto& output : tx.outputs) {
        CHECK(total_output <= std::numeric_limits<uint64_t>::max() - output.value);
        total_output += output.value;
    }
    CHECK(total_input >= total_output);
    const uint64_t fee = total_input - total_output;
    const uint64_t expected_change = total_input - MIN_TX_FEE;
    CHECK(RequireUint(result, "total_input") == total_input);
    CHECK(RequireUint(result, "total_output") == total_output);
    CHECK(RequireUint(result, "fee") == fee);
    CHECK(RequireUint(result, "change") == expected_change);
    CHECK(fee == MIN_TX_FEE);
    CHECK(tx.outputs.size() == 2U);
    CHECK(tx.outputs.front().value == expected_change);
    CHECK(tx.outputs.front().script_pubkey == owned_script);
    std::string extracted_identity;
    std::string error;
    CHECK(offline_signing::ExtractCanonicalOperationIdentity(tx.outputs.back(), extracted_identity,
                                                             error));
    CHECK(extracted_identity == operation_identity);

    offline_signing::VerifiedPrepared verified;
    CHECK(offline_signing::AuthenticatePrepared(root, owned_script, verified, error));
    CHECK(verified.total_input == total_input);
    CHECK(verified.total_output == total_output);
    CHECK(verified.fee == fee);
    CHECK(verified.claimed_change == expected_change);
    CHECK(verified.parent_raw == authenticated_parents);
    CHECK(verified.source_transactions_digest ==
          offline_signing::SourceTransactionsDigest(tx, authenticated_parents));
    CHECK(verified.complete_output_digest == offline_signing::CompleteOutputDigest(tx));
    CHECK(offline_signing::VerifyExactFeesOnlyEnvelope(verified, owned_script, error));

    offline_signing::Intent actual_intent;
    CHECK(offline_signing::ParseIntent(result, actual_intent, error));
    const auto expected_intent = offline_signing::MakeIntent(
        tx, authenticated_parents, operation_type, intended_recipient, intended_amount,
        change_address, expected_change, operation_identity);
    CheckIntentEqual(actual_intent, expected_intent);
    CHECK(actual_intent.maximum_absolute_fee == offline_signing::kHardAbsoluteFeeUnits);
    CHECK(actual_intent.maximum_fee_rate == offline_signing::kHardFeeRateUnitsPerByte);
    CHECK(actual_intent.source_transactions_digest ==
          offline_signing::SourceTransactionsDigest(tx, authenticated_parents));
    CHECK(actual_intent.complete_output_digest == offline_signing::CompleteOutputDigest(tx));
    CHECK(actual_intent.operation_identity_digest ==
          offline_signing::OperationIdentityDigest(operation_identity));
    CHECK(actual_intent.intent_digest == offline_signing::IntentDigest(actual_intent));
    CHECK(offline_signing::VerifyIntent(actual_intent, verified, operation_type, intended_recipient,
                                        intended_amount, change_address, expected_change,
                                        operation_identity, error));
}

void CheckCanonicalParentFailure(RpcServer& rpc, const std::string& fund_address,
                                 const std::string& operation_identity) {
    const auto root = ParseResponse(
        rpc.Handle(MakeRpcRequest("preparerawop", {fund_address, operation_identity})));
    const auto* result = root.Get("result");
    CHECK(result != nullptr);
    CHECK(result->kind == btc_buy::JsonValue::Kind::Null);
    const auto& error = RequireObject(root, "error");
    CHECK(RequireNumberText(error, "code") == "-32603");
    CHECK(RequireString(error, "message") ==
          "selected funding output has no authenticated canonical parent transaction");
}

void CheckValidatorPreparerTotal(const btc_buy::JsonValue& root, const std::string& address,
                                 const std::string& pubkey_hex, const Transaction& canonical_parent,
                                 bool registration) {
    const auto* rpc_error = root.Get("error");
    CHECK(rpc_error != nullptr);
    CHECK(rpc_error->kind == btc_buy::JsonValue::Kind::Null);
    const auto& result = RequireObject(root, "result");

    std::vector<uint8_t> raw;
    CHECK(
        offline_signing::DecodeLowerHex(RequireString(result, "unsigned_tx_hex"), 1'000'000U, raw));
    Transaction tx;
    CHECK(Transaction::Deserialize(raw, 0, tx) == raw.size());
    CHECK(tx.Serialize() == raw);
    CHECK(tx.inputs.size() == (registration ? VALIDATOR_FUNDING_OUTPUTS : 1U));

    uint64_t expected_input = 0;
    for (const auto& input : tx.inputs) {
        CHECK(input.prev_tx_hash == canonical_parent.GetTxID());
        CHECK(input.prev_out_index < canonical_parent.outputs.size());
        const auto& prevout = canonical_parent.outputs[input.prev_out_index];
        CHECK(prevout.script_pubkey == AddressToScript(address));
        CHECK(expected_input <= MAX_SUPPLY_UNITS - prevout.value);
        expected_input += prevout.value;
    }

    const auto self_script = AddressToScript(address);
    const auto marker = registration ? ValidatorRegistry::BuildRegisterOp(pubkey_hex)
                                     : ValidatorRegistry::BuildDeregisterOp(pubkey_hex);
    CHECK(!self_script.empty());
    CHECK(tx.outputs.size() == (registration ? 3U : 2U));
    size_t change_index = 0;
    if (registration) {
        CHECK(tx.outputs[0].value == MIN_VALIDATOR_STAKE);
        CHECK(tx.outputs[0].script_pubkey == AddressToScript(STAKE_VAULT_ADDRESS));
        change_index = 1U;
    }
    const uint64_t expected_change =
        expected_input - (registration ? MIN_VALIDATOR_STAKE : 0U) - MIN_TX_FEE;
    CHECK(expected_change > 0U);
    CHECK(tx.outputs[change_index].value == expected_change);
    CHECK(tx.outputs[change_index].script_pubkey == self_script);
    CHECK(tx.outputs.back().value == 0U);
    CHECK(tx.outputs.back().script_pubkey == BuildOpReturnScript(marker));

    uint64_t output_sum = 0;
    for (const auto& output : tx.outputs) {
        CHECK(output.value <= MAX_SUPPLY_UNITS);
        CHECK(output_sum <= MAX_SUPPLY_UNITS - output.value);
        output_sum += output.value;
    }
    CHECK(output_sum == (registration ? MIN_VALIDATOR_STAKE : 0U) + expected_change);
    CHECK(RequireUint(result, "total_input") == expected_input);
    CHECK(RequireUint(result, "total_output") == output_sum);
    CHECK(RequireUint(result, "fee") == MIN_TX_FEE);
    CHECK(RequireUint(result, "change") == expected_change);
    CHECK(expected_input - output_sum == MIN_TX_FEE);
}

} // namespace

int main() {
    try {
        const auto suffix =
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        const std::filesystem::path storage_path =
            std::filesystem::temp_directory_path() /
            ("veld-security-test-rpc-preparer-auth-" + suffix);

        {
            const std::string validator_pubkey_hex(3904U, '1');
            const auto validator_pubkey = HexToBytes(validator_pubkey_hex);
            CHECK(validator_pubkey.size() == 1952U);
            const std::string fund_address = ValidatorRegistry::PubkeyToAddress(validator_pubkey);
            const auto fund_script = AddressToScript(fund_address);
            CHECK(!fund_address.empty());
            CHECK(!fund_script.empty());
            CHECK(AddressToScript(fund_address) == fund_script);
            const std::string issuer_address = BTCVELD_ISSUER_ADDRESS;
            const auto issuer_script = AddressToScript(issuer_address);
            CHECK(!issuer_address.empty());
            CHECK(!issuer_script.empty());
            CHECK(ScriptToAddress(issuer_script) == issuer_address);
            CHECK(issuer_script != fund_script);

            Blockchain chain;
            Transaction canonical_parent;
            UTXO funding;
            UTXO issuer_funding;
            InstallSpendableCanonicalParent(chain, fund_script, issuer_script, canonical_parent,
                                            funding, issuer_funding);
            Mempool mempool;
            StorageEngine storage(storage_path.string(), MAINNET_MAGIC);
            OnChainTokenLedger token_ledger;
            RpcServer rpc(chain, mempool, storage);
            const std::string operation_identity = ValidBhdrIdentity();

            const auto positive = ParseResponse(
                rpc.Handle(MakeRpcRequest("preparerawop", {fund_address, operation_identity})));
            CheckCanonicalPreparation(positive, fund_script, fund_address, operation_identity,
                                      canonical_parent, "VELD_BHDR|", "", 0,
                                      std::numeric_limits<uint32_t>::max());

            // The standalone validator authenticates the complete transaction
            // output sum before signing. Exercise both real preparers with
            // nonzero self-change so a protocol-output-only claim fails.
            const auto register_positive = ParseResponse(rpc.Handle(
                MakeRpcRequest("prepareregistervalidator", {fund_address, validator_pubkey_hex})));
            CheckValidatorPreparerTotal(register_positive, fund_address, validator_pubkey_hex,
                                        canonical_parent, true);
            const auto deregister_positive = ParseResponse(rpc.Handle(MakeRpcRequest(
                "preparederegistervalidator", {fund_address, validator_pubkey_hex})));
            CheckValidatorPreparerTotal(deregister_positive, fund_address, validator_pubkey_hex,
                                        canonical_parent, false);

            // Exercise the independent issuer/C1 preparer through the same
            // direct dispatcher. Its operation metadata differs, but its fee
            // input must be authenticated from the same complete parent bytes.
            rpc.SetOnChainTokens(&token_ledger);
            rpc.SetBtcVeldPegStatusFn([] {
                BtcVeldPegStatus status;
                status.gate = BtcVeldPegGateState{true, true, true};
                status.reason = "fixture-open";
                return status;
            });
            const std::string allocation_id = c1reserve::AllocationId(1U);
            const std::string allocation_commitment(64U, 'a');
            constexpr uint64_t reservation_sats = c1reserve::MIN_SATS;
            TokenOpData c1_operation;
            c1_operation.action = "RESERVE";
            c1_operation.token_id = BTCVELD_TOKEN_ID;
            c1_operation.from = issuer_address;
            c1_operation.to = fund_address;
            c1_operation.amount = static_cast<int64_t>(reservation_sats);
            c1_operation.memo = c1reserve::EncodeMemo(allocation_id, allocation_commitment);
            const std::string encoded_c1_operation = EncodeTokenOp(c1_operation);
            CHECK(!encoded_c1_operation.empty());
            const auto c1_positive = ParseResponse(rpc.Handle(
                MakeRpcRequest("preparebtcveldc1reservation",
                               {issuer_address, fund_address, std::to_string(reservation_sats),
                                allocation_id, allocation_commitment})));
            const auto& c1_result = RequireObject(c1_positive, "result");
            CHECK(RequireString(c1_result, "allocation_id") == allocation_id);
            CHECK(RequireString(c1_result, "action") == "RESERVE");
            CHECK(RequireString(c1_result, "recipient") == fund_address);
            CHECK(RequireUint(c1_result, "amount_sats") == reservation_sats);
            CHECK(RequireString(c1_result, "allocation_commitment") == allocation_commitment);
            CHECK(RequireUint(c1_result, "sequence") == 1U);
            CHECK(RequireUint(c1_result, "sequence_parent") == 0U);
            CheckCanonicalPreparation(c1_positive, issuer_script, issuer_address,
                                      encoded_c1_operation, canonical_parent, "BTCVELD_C1_RESERVE",
                                      fund_address, reservation_sats, VALIDATOR_FUNDING_OUTPUTS);

            // The non-public generic profile can also execute the legacy mint
            // preparer without forging a rolling-reserve transition. Public
            // mainnet first requires a genuine RTP1 OPEN/DEPOSIT proof, then
            // reaches the same AuthenticatedParentRaw/MakeIntent construction.
            const std::string deposit_outpoint = std::string(64U, 'b') + ":0";
            size_t mint_proof_calls = 0;
            rpc.SetBtcVeldMintProofFn([&](const std::string& requested_outpoint) {
                CHECK(requested_outpoint == deposit_outpoint);
                ++mint_proof_calls;
                BtcVeldMintProofStatus status;
                status.proof = btcnull::EmptyProof();
                return status;
            });
            TokenOpData mint_operation;
            mint_operation.action = "MINT";
            mint_operation.token_id = BTCVELD_TOKEN_ID;
            mint_operation.from = issuer_address;
            mint_operation.to = fund_address;
            mint_operation.amount = static_cast<int64_t>(reservation_sats);
            mint_operation.memo =
                btcnull::EncodeIssuerMemo(deposit_outpoint, btcnull::EmptyProof());
            const std::string encoded_mint_operation = EncodeTokenOp(mint_operation);
            CHECK(!mint_operation.memo.empty());
            CHECK(!encoded_mint_operation.empty());
            const auto mint_positive = ParseResponse(rpc.Handle(MakeRpcRequest(
                "preparetokenmint", {issuer_address, fund_address, std::to_string(reservation_sats),
                                     deposit_outpoint})));
            CHECK(mint_proof_calls == 1U);
            const auto& mint_result = RequireObject(mint_positive, "result");
            CHECK(RequireUint(mint_result, "mint_sats") == reservation_sats);
            CHECK(RequireString(mint_result, "recipient") == fund_address);
            CHECK(RequireString(mint_result, "deposit_outpoint") == deposit_outpoint);
            CheckCanonicalPreparation(mint_positive, issuer_script, issuer_address,
                                      encoded_mint_operation, canonical_parent, "BTCVELD_MINT",
                                      fund_address, reservation_sats, VALIDATOR_FUNDING_OUTPUTS);

            // Isolate the original vout for the four malformed-index records
            // below; otherwise coin selection could correctly fall through to
            // another authenticated funding output from the same parent.
            for (uint32_t i = 1; i < VALIDATOR_FUNDING_OUTPUTS; ++i)
                CHECK(chain.TestEraseUTXO(canonical_parent.GetTxID(), i));

            // A selectable outpoint whose txid is absent from its claimed
            // canonical block must never be converted into parent_tx_hex.
            CHECK(chain.TestEraseUTXO(funding.tx_hash, funding.output_index));
            UTXO missing = funding;
            missing.tx_hash[0] ^= 0x80U;
            chain.TestInjectUTXO(missing);
            CheckCanonicalParentFailure(rpc, fund_address, operation_identity);
            CHECK(chain.TestEraseUTXO(missing.tx_hash, missing.output_index));

            // A real txid/vout is insufficient: its indexed value must match
            // the value authenticated by the complete canonical parent.
            UTXO wrong_value = funding;
            ++wrong_value.value;
            chain.TestInjectUTXO(wrong_value);
            CheckCanonicalParentFailure(rpc, fund_address, operation_identity);
            CHECK(chain.TestEraseUTXO(wrong_value.tx_hash, wrong_value.output_index));

            // An out-of-range vout cannot borrow the real parent's identity.
            UTXO wrong_vout = funding;
            wrong_vout.output_index = VALIDATOR_FUNDING_OUTPUTS + 1U;
            chain.TestInjectUTXO(wrong_vout);
            CheckCanonicalParentFailure(rpc, fund_address, operation_identity);
            CHECK(chain.TestEraseUTXO(wrong_vout.tx_hash, wrong_vout.output_index));

            // Script binding is also sourced from the canonical parent. A
            // caller-selected address cannot reinterpret the same outpoint.
            UTXO wrong_script = funding;
            wrong_script.script_pubkey = P2pkhScript(0x40U);
            const std::string wrong_address = ScriptToAddress(wrong_script.script_pubkey);
            CHECK(!wrong_address.empty());
            chain.TestInjectUTXO(wrong_script);
            CheckCanonicalParentFailure(rpc, wrong_address, operation_identity);
            CHECK(chain.TestEraseUTXO(wrong_script.tx_hash, wrong_script.output_index));
        }

        std::error_code cleanup_error;
        std::filesystem::remove_all(storage_path, cleanup_error);
        CHECK(!cleanup_error);
        CHECK(!std::filesystem::exists(storage_path));

        std::cout << "PASS rpc_preparer_auth_tests checks=" << checks
                  << " direct_rpc_preparers=5 canonical_parent=1 c1=1"
                  << " generic_mint=1"
                  << " validator_nonzero_change=2"
                  << " rejected_parent_variants=4 intent_fields=12\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL rpc_preparer_auth_tests checks=" << checks << " error=" << e.what()
                  << '\n';
        return 1;
    }
}
