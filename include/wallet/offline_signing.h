#pragma once

// Offline signing authentication shared by the online transaction preparer,
// the air-gapped signer, and adversarial tests.  Every value used for fee or
// sighash decisions comes from a complete, txid-bound raw parent transaction.

#include "../core/constants.h"
#include "../core/hash.h"
#include "../core/transaction.h"
#include "../core/version.h"
#include "../crypto/veld_signing.h"
#include "../network/strict_json.h"

#include <cstdint>
#include <limits>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace veld::offline_signing {

inline constexpr const char* kIntentVersion = "VELD_SIGNING_INTENT_V1";
inline constexpr uint64_t kHardAbsoluteFeeUnits = MIN_TX_FEE;
// A canonical ML-DSA-65 input script is two PUSHDATA2 items: the scheme-tagged
// 3309-byte signature plus SIGHASH_ALL, and the 1952-byte public key.
inline constexpr size_t kCanonicalInputScriptBytes = 3U + 1U + 3309U + 1U + 3U + 1952U;
inline constexpr uint64_t kHardFeeRateUnitsPerByte = 19;
inline constexpr size_t kMaxPreparedJsonBytes = 64U * 1024U * 1024U;
inline constexpr size_t kMaxParentTransactionBytes = 8U * 1024U * 1024U;
inline constexpr size_t kMaxUnsignedTransactionBytes = 8U * 1024U * 1024U;

static_assert(kCanonicalInputScriptBytes == 5269U);
static_assert(kCanonicalInputScriptBytes <= MAX_TRANSACTION_SCRIPT_SIG_BYTES);

struct Intent {
    std::string version{kIntentVersion};
    std::string operation_type;
    std::string intended_recipient;
    uint64_t intended_amount{0};
    std::string expected_change_destination;
    uint64_t expected_change{0};
    uint64_t maximum_absolute_fee{kHardAbsoluteFeeUnits};
    uint64_t maximum_fee_rate{kHardFeeRateUnitsPerByte};
    std::string source_transactions_digest;
    std::string complete_output_digest;
    std::string operation_identity_digest;
    std::string intent_digest;
};

inline constexpr const char* kIntentAuthorizationVersion = "VELD_INTENT_AUTHORIZATION_V1";

struct IntentAuthorization {
    std::string version{kIntentAuthorizationVersion};
    std::string intent_digest;
    std::string network_identity;
    std::string genesis_hash;
    std::string authorizer_pubkey_digest;
    std::string signature_hex;
};

struct VerifiedPrepared {
    Transaction tx;
    std::vector<std::vector<uint8_t>> parent_raw;
    std::vector<std::vector<uint8_t>> prev_scripts;
    uint64_t total_input{0};
    uint64_t total_output{0};
    uint64_t fee{0};
    uint64_t claimed_change{0};
    size_t signed_size{0};
    uint64_t fee_rate{0};
    std::string source_transactions_digest;
    std::string complete_output_digest;
};

inline bool VerifyExactFeesOnlyEnvelope(const VerifiedPrepared& prepared,
                                        const std::vector<uint8_t>& owned_script,
                                        std::string& error) {
    if (prepared.fee != MIN_TX_FEE) {
        error = "operation fee differs from the canonical preparer fee";
        return false;
    }
    if (prepared.total_input < MIN_TX_FEE) {
        error = "operation input cannot fund the canonical fee";
        return false;
    }
    const uint64_t expected_change = prepared.total_input - MIN_TX_FEE;
    if (prepared.claimed_change != expected_change) {
        error = "claimed change differs from authenticated input minus fee";
        return false;
    }
    const auto& outputs = prepared.tx.outputs;
    const size_t expected_outputs = expected_change == 0 ? 1U : 2U;
    if (outputs.size() != expected_outputs) {
        error = "fees-only operation has an extra, omitted, or split output";
        return false;
    }
    if (expected_change != 0 && (outputs.front().value != expected_change ||
                                 outputs.front().script_pubkey != owned_script)) {
        error = "operation change is not one exact owned output";
        return false;
    }
    const auto& marker = outputs.back();
    if (marker.value != 0 || marker.script_pubkey.size() < 2U ||
        marker.script_pubkey.front() != 0x6a) {
        error = "operation marker is not the final zero-valued OP_RETURN";
        return false;
    }
    return true;
}

inline bool ExtractCanonicalOperationIdentity(const TxOutput& output, std::string& identity,
                                              std::string& error) {
    identity.clear();
    const auto& script = output.script_pubkey;
    if (output.value != 0 || script.size() < 2U || script[0] != 0x6a) {
        error = "operation output is not a zero-valued OP_RETURN";
        return false;
    }

    size_t cursor = 1U;
    size_t pushed = 0U;
    const uint8_t opcode = script[cursor++];
    if (opcode <= 75U) {
        pushed = opcode;
    } else if (opcode == 0x4c) {
        if (cursor >= script.size()) {
            error = "operation OP_PUSHDATA1 is truncated";
            return false;
        }
        pushed = script[cursor++];
        if (pushed <= 75U) {
            error = "operation OP_PUSHDATA1 is non-canonical";
            return false;
        }
    } else if (opcode == 0x4d) {
        if (cursor > script.size() || script.size() - cursor < 2U) {
            error = "operation OP_PUSHDATA2 is truncated";
            return false;
        }
        pushed =
            static_cast<size_t>(script[cursor]) | (static_cast<size_t>(script[cursor + 1U]) << 8);
        cursor += 2U;
        if (pushed <= 255U) {
            error = "operation OP_PUSHDATA2 is non-canonical";
            return false;
        }
    } else {
        error = "operation OP_RETURN uses an unsupported push opcode";
        return false;
    }
    if (pushed == 0U || cursor > script.size() || pushed != script.size() - cursor) {
        error = "operation OP_RETURN push length or trailing bytes differ";
        return false;
    }
    identity.assign(script.begin() + static_cast<ptrdiff_t>(cursor), script.end());
    return true;
}

inline void AppendU64(std::vector<uint8_t>& out, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i)
        out.push_back(static_cast<uint8_t>(value >> (i * 8)));
}

inline void AppendField(std::vector<uint8_t>& out, const std::string& value) {
    AppendU64(out, static_cast<uint64_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

inline std::string TaggedDigest(const char* domain, const std::vector<std::string>& fields) {
    std::vector<uint8_t> preimage;
    const std::string tag(domain);
    AppendField(preimage, tag);
    AppendU64(preimage, static_cast<uint64_t>(fields.size()));
    for (const auto& field : fields)
        AppendField(preimage, field);
    return HashToHex(Hash256d(preimage));
}

inline std::string SourceTransactionsDigest(const Transaction& tx,
                                            const std::vector<std::vector<uint8_t>>& parents) {
    std::vector<uint8_t> preimage;
    AppendField(preimage, "VELD_OFFLINE_SOURCE_INPUTS_V2");
    AppendU64(preimage, static_cast<uint64_t>(parents.size()));
    for (size_t i = 0; i < parents.size(); ++i) {
        if (i < tx.inputs.size()) {
            preimage.insert(preimage.end(), tx.inputs[i].prev_tx_hash.begin(),
                            tx.inputs[i].prev_tx_hash.end());
            AppendU64(preimage, tx.inputs[i].prev_out_index);
        } else {
            preimage.insert(preimage.end(), 32U, 0U);
            AppendU64(preimage, UINT64_MAX);
        }
        const auto& parent = parents[i];
        AppendU64(preimage, static_cast<uint64_t>(parent.size()));
        preimage.insert(preimage.end(), parent.begin(), parent.end());
    }
    return HashToHex(Hash256d(preimage));
}

inline std::string CompleteOutputDigest(const Transaction& tx) {
    std::vector<uint8_t> preimage;
    AppendField(preimage, "VELD_OFFLINE_OUTPUT_SET_V1");
    AppendU64(preimage, static_cast<uint64_t>(tx.outputs.size()));
    for (const auto& output : tx.outputs) {
        const auto encoded = output.Serialize();
        AppendU64(preimage, static_cast<uint64_t>(encoded.size()));
        preimage.insert(preimage.end(), encoded.begin(), encoded.end());
    }
    return HashToHex(Hash256d(preimage));
}

inline std::string OperationIdentityDigest(const std::string& identity) {
    return TaggedDigest("VELD_OFFLINE_OPERATION_IDENTITY_V1", {identity});
}

inline std::string IntentDigest(const Intent& intent) {
    return TaggedDigest("VELD_OFFLINE_SIGNING_INTENT_V1",
                        {
                            intent.version,
                            intent.operation_type,
                            intent.intended_recipient,
                            std::to_string(intent.intended_amount),
                            intent.expected_change_destination,
                            std::to_string(intent.expected_change),
                            std::to_string(intent.maximum_absolute_fee),
                            std::to_string(intent.maximum_fee_rate),
                            intent.source_transactions_digest,
                            intent.complete_output_digest,
                            intent.operation_identity_digest,
                        });
}

inline std::string AuthorizerPubkeyDigest(const Secp256k1PubKey& pubkey) {
    return HashToHex(Hash256d(std::vector<uint8_t>(pubkey.begin(), pubkey.end())));
}

inline Hash256 IntentAuthorizationHash(const Intent& intent,
                                       const std::string& authorizer_pubkey_digest) {
    const std::string commitment =
        TaggedDigest("VELD_OFFLINE_INTENT_AUTHORIZATION_V1", {
                                                                 kIntentAuthorizationVersion,
                                                                 intent.intent_digest,
                                                                 DEPLOYMENT_PROFILE_ID,
                                                                 GENESIS_HASH,
                                                                 authorizer_pubkey_digest,
                                                             });
    return Hash256d(std::vector<uint8_t>(commitment.begin(), commitment.end()));
}

inline Intent MakeIntent(const Transaction& tx, const std::vector<std::vector<uint8_t>>& parents,
                         std::string operation_type, std::string intended_recipient,
                         uint64_t intended_amount, std::string expected_change_destination,
                         uint64_t expected_change, const std::string& operation_identity) {
    Intent intent;
    intent.operation_type = std::move(operation_type);
    intent.intended_recipient = std::move(intended_recipient);
    intent.intended_amount = intended_amount;
    intent.expected_change_destination = std::move(expected_change_destination);
    intent.expected_change = expected_change;
    intent.source_transactions_digest = SourceTransactionsDigest(tx, parents);
    intent.complete_output_digest = CompleteOutputDigest(tx);
    intent.operation_identity_digest = OperationIdentityDigest(operation_identity);
    intent.intent_digest = IntentDigest(intent);
    return intent;
}

inline bool DecodeLowerHex(const std::string& hex, size_t max_bytes, std::vector<uint8_t>& out) {
    if (hex.empty() || (hex.size() & 1U) || hex.size() / 2U > max_bytes)
        return false;
    out.clear();
    out.reserve(hex.size() / 2U);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2U) {
        const int high = nibble(hex[i]);
        const int low = nibble(hex[i + 1U]);
        if (high < 0 || low < 0) {
            out.clear();
            return false;
        }
        out.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return true;
}

inline const btc_buy::JsonValue* SelectObject(const btc_buy::JsonValue& root, const char* nested) {
    if (root.kind != btc_buy::JsonValue::Kind::Object)
        return nullptr;
    if (const auto* value = root.Get(nested))
        return value->kind == btc_buy::JsonValue::Kind::Object ? value : nullptr;
    if (const auto* result = root.Get("result"))
        return result->kind == btc_buy::JsonValue::Kind::Object ? result : nullptr;
    return &root;
}

inline bool ParseStringField(const btc_buy::JsonValue& object, const char* name, std::string& out) {
    const auto* field = object.Get(name);
    if (!field || field->kind != btc_buy::JsonValue::Kind::String || field->string_had_escape)
        return false;
    out = field->text;
    return true;
}

inline bool ParseUintField(const btc_buy::JsonValue& object, const char* name, uint64_t& out) {
    const auto* field = object.Get(name);
    return field && btc_buy::ParseUint(*field, out);
}

inline bool AuthenticatePrepared(const btc_buy::JsonValue& prepared,
                                 const std::vector<uint8_t>& owned_script, VerifiedPrepared& out,
                                 std::string& error) {
    const auto* proposal = SelectObject(prepared, "prepared_transaction");
    if (!proposal) {
        error = "prepared transaction is not an object";
        return false;
    }
    std::string unsigned_hex;
    if (!ParseStringField(*proposal, "unsigned_tx_hex", unsigned_hex) ||
        !btc_buy::IsLowerHex(unsigned_hex)) {
        error = "unsigned_tx_hex is missing or non-canonical";
        return false;
    }
    std::vector<uint8_t> raw;
    if (!DecodeLowerHex(unsigned_hex, kMaxUnsignedTransactionBytes, raw)) {
        error = "unsigned transaction exceeds policy or has invalid hex";
        return false;
    }
    Transaction tx;
    const size_t consumed = Transaction::Deserialize(raw, 0, tx);
    if (consumed != raw.size() || tx.Serialize() != raw || tx.version != 1 || tx.locktime != 0 ||
        tx.inputs.empty() || tx.inputs.size() > 180 || tx.outputs.empty()) {
        error = "unsigned transaction is non-canonical";
        return false;
    }
    const auto* inputs = proposal->Get("inputs");
    if (!inputs || inputs->kind != btc_buy::JsonValue::Kind::Array ||
        inputs->array.size() != tx.inputs.size()) {
        error = "input evidence cardinality differs from transaction";
        return false;
    }

    VerifiedPrepared verified;
    verified.tx = tx;
    std::set<std::pair<std::string, uint32_t>> seen;
    for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
        const auto& input = tx.inputs[i];
        const std::string txid = HashToHex(input.prev_tx_hash);
        if (!input.script_sig.empty() || input.sequence != 0xffffffffU ||
            !seen.emplace(txid, input.prev_out_index).second) {
            error = "input is signed, non-final, or duplicated";
            return false;
        }
        const auto& meta = inputs->array[i];
        if (meta.kind != btc_buy::JsonValue::Kind::Object) {
            error = "input evidence is not an object";
            return false;
        }
        uint64_t claimed_index = 0, claimed_value = 0;
        std::string claimed_script, claimed_sighash, parent_hex;
        if (!ParseUintField(meta, "index", claimed_index) || claimed_index != i ||
            !ParseUintField(meta, "value", claimed_value) ||
            !ParseStringField(meta, "prev_script_hex", claimed_script) ||
            !ParseStringField(meta, "sighash_hex", claimed_sighash) ||
            !ParseStringField(meta, "parent_tx_hex", parent_hex) ||
            !btc_buy::IsLowerHex(claimed_script) || !btc_buy::IsLowerHex(claimed_sighash, 64) ||
            !btc_buy::IsLowerHex(parent_hex)) {
            error = "input evidence is incomplete or non-canonical";
            return false;
        }
        std::vector<uint8_t> parent_raw, claimed_script_bytes;
        if (!DecodeLowerHex(parent_hex, kMaxParentTransactionBytes, parent_raw) ||
            !DecodeLowerHex(claimed_script, MAX_SPENDABLE_SCRIPT_PUBKEY_BYTES,
                            claimed_script_bytes)) {
            error = "parent transaction or script exceeds policy";
            return false;
        }
        Transaction parent;
        const size_t parent_consumed = Transaction::Deserialize(parent_raw, 0, parent);
        if (parent_consumed != parent_raw.size() || parent.Serialize() != parent_raw ||
            parent.GetTxID() != input.prev_tx_hash) {
            error = "parent transaction is non-canonical or txid-mismatched";
            return false;
        }
        if (input.prev_out_index >= parent.outputs.size()) {
            error = "referenced parent vout does not exist";
            return false;
        }
        const auto& prevout = parent.outputs[input.prev_out_index];
        if (prevout.value != claimed_value || prevout.script_pubkey != claimed_script_bytes ||
            prevout.script_pubkey != owned_script) {
            error = "authenticated parent value/script differs from proposal or key";
            return false;
        }
        if (verified.total_input > std::numeric_limits<uint64_t>::max() - prevout.value) {
            error = "input-total overflow";
            return false;
        }
        verified.total_input += prevout.value;
        if (verified.total_input > MAX_SUPPLY_UNITS) {
            error = "input total exceeds network supply";
            return false;
        }
        const std::string actual_sighash = BytesToHex(ComputeSighash(tx, i, prevout.script_pubkey));
        if (actual_sighash != claimed_sighash) {
            error = "input sighash differs from authenticated parent";
            return false;
        }
        verified.parent_raw.push_back(std::move(parent_raw));
        verified.prev_scripts.push_back(prevout.script_pubkey);
    }

    for (const auto& output : tx.outputs) {
        if (verified.total_output > std::numeric_limits<uint64_t>::max() - output.value) {
            error = "output-total overflow";
            return false;
        }
        verified.total_output += output.value;
        if (verified.total_output > MAX_SUPPLY_UNITS) {
            error = "output total exceeds network supply";
            return false;
        }
    }
    if (verified.total_input < verified.total_output) {
        error = "fee is negative";
        return false;
    }
    verified.fee = verified.total_input - verified.total_output;
    uint64_t claimed_input = 0, claimed_output = 0, claimed_fee = 0;
    if (!ParseUintField(*proposal, "total_input", claimed_input) ||
        !ParseUintField(*proposal, "total_output", claimed_output) ||
        !ParseUintField(*proposal, "fee", claimed_fee) ||
        !ParseUintField(*proposal, "change", verified.claimed_change) ||
        claimed_input != verified.total_input || claimed_output != verified.total_output ||
        claimed_fee != verified.fee) {
        error = "proposal totals differ from authenticated transaction";
        return false;
    }
    if (verified.fee > kHardAbsoluteFeeUnits) {
        error = "fee exceeds canonical absolute ceiling";
        return false;
    }
    Transaction size_probe = tx;
    for (auto& input : size_probe.inputs)
        input.script_sig.assign(kCanonicalInputScriptBytes, 0);
    verified.signed_size = size_probe.Serialize().size();
    if (verified.signed_size == 0 || verified.signed_size > kMaxUnsignedTransactionBytes ||
        verified.signed_size > std::numeric_limits<uint64_t>::max() / kHardFeeRateUnitsPerByte ||
        verified.fee > static_cast<uint64_t>(verified.signed_size) * kHardFeeRateUnitsPerByte) {
        error = "fee rate exceeds canonical ceiling";
        return false;
    }
    verified.fee_rate = (verified.fee + verified.signed_size - 1U) / verified.signed_size;
    verified.source_transactions_digest =
        SourceTransactionsDigest(verified.tx, verified.parent_raw);
    verified.complete_output_digest = CompleteOutputDigest(tx);
    out = std::move(verified);
    return true;
}

inline bool ParseIntent(const btc_buy::JsonValue& root, Intent& out, std::string& error) {
    const auto* object = SelectObject(root, "signing_intent");
    if (!object || object->object.size() != 12U) {
        error = "intent is missing fields or has unrecognized fields";
        return false;
    }
    Intent intent;
    if (!ParseStringField(*object, "version", intent.version) ||
        !ParseStringField(*object, "operation_type", intent.operation_type) ||
        !ParseStringField(*object, "intended_recipient", intent.intended_recipient) ||
        !ParseUintField(*object, "intended_amount", intent.intended_amount) ||
        !ParseStringField(*object, "expected_change_destination",
                          intent.expected_change_destination) ||
        !ParseUintField(*object, "expected_change", intent.expected_change) ||
        !ParseUintField(*object, "maximum_absolute_fee", intent.maximum_absolute_fee) ||
        !ParseUintField(*object, "maximum_fee_rate", intent.maximum_fee_rate) ||
        !ParseStringField(*object, "source_transactions_digest",
                          intent.source_transactions_digest) ||
        !ParseStringField(*object, "complete_output_digest", intent.complete_output_digest) ||
        !ParseStringField(*object, "operation_identity_digest", intent.operation_identity_digest) ||
        !ParseStringField(*object, "intent_digest", intent.intent_digest)) {
        error = "intent field types are non-canonical";
        return false;
    }
    if (intent.version != kIntentVersion || intent.operation_type.empty() ||
        intent.operation_type.size() > 64U || intent.intended_recipient.size() > 256U ||
        intent.expected_change_destination.size() > 256U ||
        !btc_buy::IsLowerHex(intent.source_transactions_digest, 64) ||
        !btc_buy::IsLowerHex(intent.complete_output_digest, 64) ||
        !btc_buy::IsLowerHex(intent.operation_identity_digest, 64) ||
        !btc_buy::IsLowerHex(intent.intent_digest, 64) ||
        intent.intent_digest != IntentDigest(intent)) {
        error = "intent values or digest are non-canonical";
        return false;
    }
    out = std::move(intent);
    return true;
}

inline bool ParseIntentAuthorization(const btc_buy::JsonValue& root, IntentAuthorization& out,
                                     std::string& error) {
    if (root.kind != btc_buy::JsonValue::Kind::Object || root.object.size() != 2U) {
        error = "authorized intent must be one detached two-object document";
        return false;
    }
    const auto* signing_intent = root.Get("signing_intent");
    const auto* object = root.Get("intent_authorization");
    if (!signing_intent || signing_intent->kind != btc_buy::JsonValue::Kind::Object || !object ||
        object->kind != btc_buy::JsonValue::Kind::Object || object->object.size() != 6U) {
        error = "authorized intent requires exact signing_intent and "
                "intent_authorization objects";
        return false;
    }
    IntentAuthorization auth;
    if (!ParseStringField(*object, "version", auth.version) ||
        !ParseStringField(*object, "intent_digest", auth.intent_digest) ||
        !ParseStringField(*object, "network_identity", auth.network_identity) ||
        !ParseStringField(*object, "genesis_hash", auth.genesis_hash) ||
        !ParseStringField(*object, "authorizer_pubkey_digest", auth.authorizer_pubkey_digest) ||
        !ParseStringField(*object, "signature_hex", auth.signature_hex)) {
        error = "intent authorization fields are non-canonical";
        return false;
    }
    if (auth.version != kIntentAuthorizationVersion ||
        auth.network_identity != DEPLOYMENT_PROFILE_ID || auth.genesis_hash != GENESIS_HASH ||
        !btc_buy::IsLowerHex(auth.intent_digest, 64) ||
        !btc_buy::IsLowerHex(auth.authorizer_pubkey_digest, 64) ||
        !btc_buy::IsLowerHex(auth.signature_hex) ||
        auth.signature_hex.size() > 2U * dilithium::SIG_MAX_BYTES) {
        error = "intent authorization values are invalid for this release";
        return false;
    }
    out = std::move(auth);
    return true;
}

inline bool VerifyIntentAuthorization(const Intent& intent,
                                      const IntentAuthorization& authorization,
                                      const Secp256k1PubKey& authorizer, std::string& error) {
    const std::string pubkey_digest = AuthorizerPubkeyDigest(authorizer);
    if (authorization.intent_digest != intent.intent_digest ||
        authorization.network_identity != DEPLOYMENT_PROFILE_ID ||
        authorization.genesis_hash != GENESIS_HASH ||
        authorization.authorizer_pubkey_digest != pubkey_digest) {
        error = "intent authorization is not bound to this intent, key, or network";
        return false;
    }
    std::vector<uint8_t> signature;
    if (!DecodeLowerHex(authorization.signature_hex, dilithium::SIG_MAX_BYTES, signature) ||
        !Verify(authorizer, IntentAuthorizationHash(intent, pubkey_digest), signature)) {
        error = "intent authorization signature is invalid";
        return false;
    }
    return true;
}

inline bool VerifyIntent(const Intent& intent, const VerifiedPrepared& prepared,
                         const std::string& operation_type, const std::string& intended_recipient,
                         uint64_t intended_amount, const std::string& expected_change_destination,
                         uint64_t expected_change, const std::string& operation_identity,
                         std::string& error) {
    if (intent.maximum_absolute_fee == 0 || intent.maximum_absolute_fee > kHardAbsoluteFeeUnits ||
        intent.maximum_fee_rate == 0 || intent.maximum_fee_rate > kHardFeeRateUnitsPerByte) {
        error = "intent fee ceilings are empty or exceed canonical policy";
        return false;
    }
    if (prepared.fee > intent.maximum_absolute_fee || prepared.fee_rate > intent.maximum_fee_rate) {
        error = "prepared fee exceeds intent ceiling";
        return false;
    }
    if (intent.operation_type != operation_type ||
        intent.intended_recipient != intended_recipient ||
        intent.intended_amount != intended_amount ||
        intent.expected_change_destination != expected_change_destination ||
        intent.expected_change != expected_change || prepared.claimed_change != expected_change ||
        intent.source_transactions_digest != prepared.source_transactions_digest ||
        intent.complete_output_digest != prepared.complete_output_digest ||
        intent.operation_identity_digest != OperationIdentityDigest(operation_identity)) {
        error = "intent differs from authenticated transaction or operation";
        return false;
    }
    return true;
}

} // namespace veld::offline_signing
