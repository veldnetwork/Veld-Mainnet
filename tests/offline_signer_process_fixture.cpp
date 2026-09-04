#include "wallet/wallet.h"
#include "wallet/offline_signing.h"
#include "wallet/secure_channel_file.h"
#include "consensus/btcveld_mint_policy.h"
#include "consensus/btcveld_relay_policy.h"
#include "core/pqc_script.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace veld;
namespace fs = std::filesystem;

namespace {

namespace reserve = btcveld::reserve;
constexpr const char* TOKEN_RECIPIENT = "VUjD1JoewGkiGxRqJ52FkK1UiMotjsp9Tg";
constexpr uint64_t MINT_SATS = 10'000;

std::string Quote(const std::string& value) {
    return "\"" + value + "\"";
}

std::string ValidBhdrIdentity() {
    std::vector<uint8_t> payload{'B', 'H', 'D', 'R', 1};
    payload.resize(5 + 80, 0);
    return "VELD_BHDR|" + BytesToHex(payload);
}

std::string ValidAnchorIdentity() {
    std::vector<uint8_t> payload{'A', 'N', 'C', 'H'};
    payload.resize(40, 0); // block hash plus zero merkle-direction bitmap
    payload.push_back(0);  // empty merkle branch
    payload.push_back(0);  // nonempty trailing Bitcoin transaction fixture
    return "VELD_ANCHOR|" + BytesToHex(payload);
}

Hash256 TaggedHash(const std::string& tag) {
    return Hash256d(std::vector<uint8_t>(tag.begin(), tag.end()));
}

std::vector<uint8_t> BitcoinTx(const std::vector<std::pair<Hash256, uint32_t>>& inputs,
                               const std::vector<btcspv::BtcTxOut>& outputs) {
    Transaction tx;
    for (const auto& [txid, vout] : inputs) {
        TxInput input;
        input.prev_tx_hash = txid;
        input.prev_out_index = vout;
        tx.inputs.push_back(input);
    }
    for (const auto& output : outputs)
        tx.outputs.emplace_back(output.value, output.spk);
    return tx.Serialize();
}

Hash256 BitcoinTxid(const std::vector<uint8_t>& tx) {
    btcspv::WitnessAwareBtcTx parsed;
    if (!btcspv::ParseWitnessAwareBtcTx(tx, parsed))
        throw std::runtime_error("fixture Bitcoin transaction is noncanonical");
    return parsed.txid;
}

std::vector<uint8_t> OpenReserveProof() {
    const std::vector<uint8_t> parent =
        BitcoinTx({{TaggedHash("process-open-funding"), 0}}, {{MINT_SATS + 1'000, {0x51}}});
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
        claim.new_reserve_vout, claim.new_reserve_value, TOKEN_RECIPIENT);
    claim.direct_parents = {parent};
    claim.has_nullifier_proof = true;
    claim.nullifier_proof = btcnull::EmptyProof();
    claim.bitcoin_block = TaggedHash("process-open-bitcoin-block");
    claim.bitcoin_tx =
        BitcoinTx({{BitcoinTxid(parent), 0}},
                  {{MINT_SATS, BtcVeldCustodySpk()},
                   {0, reserve::detail::OpenAuthScript(claim.prior_commitment, TOKEN_RECIPIENT,
                                                       claim.mint_amount)}});
    claim.bitcoin_txid = BitcoinTxid(claim.bitcoin_tx);
    claim.new_reserve_txid = claim.bitcoin_txid;
    const auto proof = reserve::EncodeProof(claim);
    if (proof.empty())
        throw std::runtime_error("cannot encode canonical RTP1 fixture");
    return proof;
}

Transaction Parent(uint64_t value, const std::vector<uint8_t>& script, const std::string& tag) {
    Transaction parent;
    parent.inputs.push_back(TxInput::Coinbase(tag));
    parent.outputs.emplace_back(value, script);
    return parent;
}

Transaction Spend(const Transaction& parent, uint32_t vout, std::vector<TxOutput> outputs) {
    Transaction tx;
    TxInput input;
    input.prev_tx_hash = parent.GetTxID();
    input.prev_out_index = vout;
    tx.inputs.push_back(input);
    tx.outputs = std::move(outputs);
    return tx;
}

std::string Proposal(const Transaction& tx, const std::vector<Transaction>& parents,
                     const std::vector<uint8_t>& owned, uint64_t total_input, uint64_t total_output,
                     uint64_t fee, uint64_t change, bool omit_parent = false,
                     uint64_t first_claimed_value = UINT64_MAX,
                     const std::vector<uint8_t>* first_claimed_script = nullptr,
                     const std::string& reserve_state_hex = {},
                     const std::string& reserve_supply_sats = {}) {
    std::string inputs = "[";
    for (size_t i = 0; i < tx.inputs.size(); ++i) {
        if (i)
            inputs += ",";
        const auto& parent = parents.at(i);
        const uint32_t vout = tx.inputs[i].prev_out_index;
        const uint64_t actual = vout < parent.outputs.size() ? parent.outputs[vout].value : 0;
        const uint64_t claim =
            i == 0 && first_claimed_value != UINT64_MAX ? first_claimed_value : actual;
        const auto& claimed_script = i == 0 && first_claimed_script ? *first_claimed_script : owned;
        inputs += "{\"index\":" + std::to_string(i) + ",\"sighash_hex\":" +
                  Quote(BytesToHex(ComputeSighash(tx, static_cast<uint32_t>(i), owned))) +
                  ",\"prev_script_hex\":" + Quote(BytesToHex(claimed_script)) +
                  ",\"value\":" + std::to_string(claim);
        if (!(omit_parent && i == 0))
            inputs += ",\"parent_tx_hex\":" + Quote(BytesToHex(parent.Serialize()));
        inputs += "}";
    }
    inputs += "]";
    std::string proposal =
        "{\"unsigned_tx_hex\":" + Quote(BytesToHex(tx.Serialize())) + ",\"inputs\":" + inputs +
        ",\"total_input\":" + std::to_string(total_input) +
        ",\"total_output\":" + std::to_string(total_output) + ",\"fee\":" + std::to_string(fee) +
        ",\"change\":" + std::to_string(change);
    if (!reserve_state_hex.empty() || !reserve_supply_sats.empty())
        proposal += ",\"reserve_prior_state_hex\":" + Quote(reserve_state_hex) +
                    ",\"reserve_prior_supply_sats\":" + reserve_supply_sats;
    return proposal + "}";
}

std::string IntentJson(const offline_signing::Intent& intent) {
    return "{\"version\":" + Quote(intent.version) +
           ",\"operation_type\":" + Quote(intent.operation_type) +
           ",\"intended_recipient\":" + Quote(intent.intended_recipient) +
           ",\"intended_amount\":" + std::to_string(intent.intended_amount) +
           ",\"expected_change_destination\":" + Quote(intent.expected_change_destination) +
           ",\"expected_change\":" + std::to_string(intent.expected_change) +
           ",\"maximum_absolute_fee\":" + std::to_string(intent.maximum_absolute_fee) +
           ",\"maximum_fee_rate\":" + std::to_string(intent.maximum_fee_rate) +
           ",\"source_transactions_digest\":" + Quote(intent.source_transactions_digest) +
           ",\"complete_output_digest\":" + Quote(intent.complete_output_digest) +
           ",\"operation_identity_digest\":" + Quote(intent.operation_identity_digest) +
           ",\"intent_digest\":" + Quote(intent.intent_digest) + "}";
}

void Write(const fs::path& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.good())
        throw std::runtime_error("cannot write " + path.string());
    out << text;
}

std::string Read(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.good())
        throw std::runtime_error("cannot read " + path.string());
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

int VerifySigned(const std::string& address, const fs::path& prepared_path,
                 const fs::path& signed_path) {
    const auto owned = AddressToScript(address);
    btc_buy::JsonValue prepared_root;
    std::string error;
    const std::string prepared_json = Read(prepared_path);
    btc_buy::StrictJsonParser parser(prepared_json, offline_signing::kMaxPreparedJsonBytes, true);
    offline_signing::VerifiedPrepared verified;
    if (!parser.Parse(prepared_root, error) ||
        !offline_signing::AuthenticatePrepared(prepared_root, owned, verified, error))
        throw std::runtime_error("prepared verification failed: " + error);
    std::string signed_hex = Read(signed_path);
    while (!signed_hex.empty() && (signed_hex.back() == '\r' || signed_hex.back() == '\n'))
        signed_hex.pop_back();
    std::vector<uint8_t> signed_raw;
    if (!offline_signing::DecodeLowerHex(signed_hex, offline_signing::kMaxUnsignedTransactionBytes,
                                         signed_raw))
        throw std::runtime_error("signed artifact is not canonical hex");
    Transaction signed_tx;
    if (Transaction::Deserialize(signed_raw, 0, signed_tx) != signed_raw.size() ||
        signed_tx.Serialize() != signed_raw || signed_tx.inputs.size() != verified.tx.inputs.size())
        throw std::runtime_error("signed transaction is noncanonical");
    Transaction unsigned_tx = signed_tx;
    for (auto& input : unsigned_tx.inputs)
        input.script_sig.clear();
    if (unsigned_tx.Serialize() != verified.tx.Serialize())
        throw std::runtime_error("signed transaction changed unsigned bytes");
    for (size_t i = 0; i < signed_tx.inputs.size(); ++i) {
        std::vector<uint8_t> encoded_signature;
        Secp256k1PubKey pubkey{};
        if (!pqc::ParseScriptSig(signed_tx.inputs[i].script_sig, encoded_signature, pubkey) ||
            encoded_signature.size() != 3311U || encoded_signature.front() != SCHEME_ID_MLDSA65 ||
            encoded_signature.back() != 0x01)
            throw std::runtime_error("signed input script is noncanonical");
        const Hash160 pkh = Hash160Compute(pubkey);
        std::vector<uint8_t> pubkey_script{0x76, 0xa9, 0x14};
        pubkey_script.insert(pubkey_script.end(), pkh.begin(), pkh.end());
        pubkey_script.push_back(0x88);
        pubkey_script.push_back(0xac);
        const Secp256k1SigDER raw_signature(encoded_signature.begin() + 1,
                                            encoded_signature.end() - 1);
        if (pubkey_script != owned ||
            !Verify(pubkey,
                    ComputeSighash(verified.tx, static_cast<uint32_t>(i), verified.prev_scripts[i]),
                    raw_signature))
            throw std::runtime_error("signed input signature does not verify");
    }
    std::cout << "PASS signed-inputs=" << signed_tx.inputs.size() << "\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 3 && std::string(argv[1]) == "--prepare-dir") {
            std::string error;
            if (!channel::secure_file::EnsurePrivateDirectory(argv[2], &error)) {
                std::cerr << "private directory preparation failed: " << error << "\n";
                return 1;
            }
            std::cout << "PASS private-dir\n";
            return 0;
        }
        if (argc == 5 && std::string(argv[1]) == "--verify-signed")
            return VerifySigned(argv[2], argv[3], argv[4]);
        if (argc != 3) {
            std::cerr << "usage: fixture <signer-address> <output-dir>\n"
                      << "       fixture --prepare-dir <directory>\n";
            return 2;
        }
        const std::string address = argv[1];
        const fs::path output = argv[2];
        fs::create_directories(output);
        const auto owned = AddressToScript(address);
        if (owned.size() != 25)
            throw std::runtime_error("signer address is not canonical P2PKH");
        const std::string identity = ValidBhdrIdentity();
        std::string family;
        if (!BtcVeldRelayPayloadShape(identity, family) || family != "VELD_BHDR|")
            throw std::runtime_error("BHDR fixture is not canonical");
        const auto marker = BuildOpReturnScript(identity);
        const Transaction parent = Parent(200000, owned, "canonical-parent");
        const Transaction valid = Spend(parent, 0, {TxOutput(100000, owned), TxOutput(0, marker)});
        const auto intent = offline_signing::MakeIntent(valid, {parent.Serialize()}, "VELD_BHDR|",
                                                        "", 0, address, 100000, identity);
        Write(output / "canonical.intent.json", IntentJson(intent));
        Write(output / "canonical.identity-digest.txt",
              offline_signing::OperationIdentityDigest(identity));

        struct ValidOperation {
            std::string name;
            std::string command;
            std::string operation_type;
            std::string recipient;
            uint64_t amount;
            std::string identity;
            std::string proposal;
        };
        std::vector<ValidOperation> valid_operations;
        valid_operations.push_back(
            {"bhdr", "sign-op", "VELD_BHDR|", "", 0, identity,
             Proposal(valid, {parent}, owned, 200000, 100000, 100000, 100000)});

        const std::string anchor_identity = ValidAnchorIdentity();
        const Transaction anchor_tx =
            Spend(parent, 0,
                  {TxOutput(100000, owned), TxOutput(0, BuildOpReturnScript(anchor_identity))});
        valid_operations.push_back(
            {"anchor", "sign-op", "VELD_ANCHOR|", "", 0, anchor_identity,
             Proposal(anchor_tx, {parent}, owned, 200000, 100000, 100000, 100000)});

        const std::vector<uint8_t> reserve_proof = OpenReserveProof();
        const std::string reserve_identity =
            std::string(reserve::PUBLIC_CARRIER_PREFIX) + BytesToHex(reserve_proof);
        std::string reserve_family;
        if (!BtcVeldRelayPayloadShape(reserve_identity, reserve_family) ||
            reserve_family != reserve::PUBLIC_CARRIER_PREFIX)
            throw std::runtime_error("RSV1 fixture is not canonical");
        const Transaction reserve_tx =
            Spend(parent, 0,
                  {TxOutput(100000, owned), TxOutput(0, BuildOpReturnScript(reserve_identity))});
        valid_operations.push_back(
            {"rsv1", "sign-op", reserve::PUBLIC_CARRIER_PREFIX, "", 0, reserve_identity,
             Proposal(reserve_tx, {parent}, owned, 200000, 100000, 100000, 100000)});

        const std::string mint_identity = std::string("VELD_TOKEN|MINT|btcVELD|") + address + "|" +
                                          TOKEN_RECIPIENT + "|" + std::to_string(MINT_SATS) + "|" +
                                          reserve::ISSUER_MEMO_PREFIX + BytesToHex(reserve_proof);
        const Transaction mint_tx = Spend(
            parent, 0, {TxOutput(100000, owned), TxOutput(0, BuildOpReturnScript(mint_identity))});
        const reserve::State empty_reserve_state{};
        valid_operations.push_back(
            {"rtp1_mint", "sign-tx", "BTCVELD_MINT", TOKEN_RECIPIENT, MINT_SATS, mint_identity,
             Proposal(mint_tx, {parent}, owned, 200000, 100000, 100000, 100000, false, UINT64_MAX,
                      nullptr, BytesToHex(reserve::EncodeState(empty_reserve_state)), "0")});

        const std::string allocation_id = c1reserve::AllocationId(1);
        const std::string allocation_commitment(64, '4');
        const std::string c1_memo = c1reserve::EncodeMemo(allocation_id, allocation_commitment);
        const std::string c1_identity = std::string("VELD_TOKEN|RESERVE|btcVELD|") + address + "|" +
                                        TOKEN_RECIPIENT + "|" + std::to_string(MINT_SATS) + "|" +
                                        c1_memo;
        const Transaction c1_tx = Spend(
            parent, 0, {TxOutput(100000, owned), TxOutput(0, BuildOpReturnScript(c1_identity))});
        valid_operations.push_back(
            {"c1_reserve", "sign-tx", "BTCVELD_C1_RESERVE", TOKEN_RECIPIENT, MINT_SATS, c1_identity,
             Proposal(c1_tx, {parent}, owned, 200000, 100000, 100000, 100000)});

        std::ofstream valid_manifest(output / "valid-operations.tsv",
                                     std::ios::binary | std::ios::trunc);
        if (!valid_manifest.good())
            throw std::runtime_error("cannot write valid-operation manifest");
        for (const auto& operation : valid_operations) {
            const std::string prepared_name = "valid-" + operation.name + ".prepared.json";
            Write(output / prepared_name, operation.proposal);
            valid_manifest << operation.name << '\t' << operation.command << '\t'
                           << operation.operation_type << '\t'
                           << (operation.recipient.empty() ? "-" : operation.recipient) << '\t'
                           << operation.amount << '\t'
                           << offline_signing::OperationIdentityDigest(operation.identity) << '\t'
                           << prepared_name << '\n';
        }

        struct Case {
            std::string name;
            std::string proposal;
            bool pass;
        };
        std::vector<Case> cases;
        cases.push_back(
            {"canonical", Proposal(valid, {parent}, owned, 200000, 100000, 100000, 100000), true});
        cases.push_back(
            {"wrong_value",
             Proposal(valid, {parent}, owned, 200000, 100000, 100000, 100000, false, 199999),
             false});
        cases.push_back({"missing_parent",
                         Proposal(valid, {parent}, owned, 200000, 100000, 100000, 100000, true),
                         false});
        const Transaction different = Parent(200000, owned, "different-parent");
        cases.push_back({"parent_txid_mismatch",
                         Proposal(valid, {different}, owned, 200000, 100000, 100000, 100000),
                         false});
        const Transaction wrong_vout =
            Spend(parent, 1, {TxOutput(100000, owned), TxOutput(0, marker)});
        cases.push_back({"wrong_vout",
                         Proposal(wrong_vout, {parent}, owned, 200000, 100000, 100000, 100000),
                         false});

        Transaction duplicate = valid;
        duplicate.inputs.push_back(duplicate.inputs.front());
        cases.push_back(
            {"duplicate_input",
             Proposal(duplicate, {parent, parent}, owned, 400000, 300000, 100000, 300000), false});

        const Transaction hidden = Spend(
            parent, 0,
            {TxOutput(99999, owned), TxOutput(1, std::vector<uint8_t>{0x51}), TxOutput(0, marker)});
        cases.push_back({"hidden_output",
                         Proposal(hidden, {parent}, owned, 200000, 100000, 100000, 100000), false});
        const Transaction split_change =
            Spend(parent, 0, {TxOutput(50000, owned), TxOutput(50000, owned), TxOutput(0, marker)});
        cases.push_back({"split_change",
                         Proposal(split_change, {parent}, owned, 200000, 100000, 100000, 100000),
                         false});
        const Transaction marker_before_change =
            Spend(parent, 0, {TxOutput(0, marker), TxOutput(100000, owned)});
        cases.push_back(
            {"marker_before_change",
             Proposal(marker_before_change, {parent}, owned, 200000, 100000, 100000, 100000),
             false});
        std::vector<uint8_t> redirected_script(25, 0x42);
        redirected_script[0] = 0x76;
        redirected_script[1] = 0xa9;
        redirected_script[2] = 0x14;
        redirected_script[23] = 0x88;
        redirected_script[24] = 0xac;
        const Transaction redirected =
            Spend(parent, 0, {TxOutput(100000, redirected_script), TxOutput(0, marker)});
        cases.push_back({"redirected_change",
                         Proposal(redirected, {parent}, owned, 200000, 100000, 100000, 0), false});
        cases.push_back({"wrong_claimed_script",
                         Proposal(valid, {parent}, owned, 200000, 100000, 100000, 100000, false,
                                  UINT64_MAX, &redirected_script),
                         false});
        const Transaction foreign_parent =
            Parent(200000, redirected_script, "foreign-script-parent");
        const Transaction foreign_spend =
            Spend(foreign_parent, 0, {TxOutput(100000, owned), TxOutput(0, marker)});
        cases.push_back(
            {"parent_script_not_owned",
             Proposal(foreign_spend, {foreign_parent}, owned, 200000, 100000, 100000, 100000),
             false});
        const Transaction exact_fee_parent = Parent(100000, owned, "omitted-change-parent");
        const Transaction omitted = Spend(exact_fee_parent, 0, {TxOutput(0, marker)});
        cases.push_back({"omitted_change",
                         Proposal(omitted, {exact_fee_parent}, owned, 100000, 0, 100000, 0),
                         false});
        const Transaction high_parent = Parent(200001, owned, "fee-high-parent");
        const Transaction fee_high =
            Spend(high_parent, 0, {TxOutput(100000, owned), TxOutput(0, marker)});
        cases.push_back({"fee_above_cap",
                         Proposal(fee_high, {high_parent}, owned, 200001, 100000, 100001, 100000),
                         false});
        const std::string alternate_identity = ValidAnchorIdentity();
        std::string alternate_family;
        if (!BtcVeldRelayPayloadShape(alternate_identity, alternate_family) ||
            alternate_family != "VELD_ANCHOR|")
            throw std::runtime_error("ANCHOR fixture is not canonical");
        const Transaction altered =
            Spend(parent, 0,
                  {TxOutput(100000, owned), TxOutput(0, BuildOpReturnScript(alternate_identity))});
        cases.push_back({"altered_marker",
                         Proposal(altered, {parent}, owned, 200000, 100000, 100000, 100000),
                         false});

        // Every malformed push reaches the real keygen process with an
        // authenticated parent, exact fee, and exact owned change.  The
        // renderer must consume only the already-validated identity and return
        // a controlled refusal rather than indexing beyond the script.
        auto add_malformed_marker = [&](const std::string& name, std::vector<uint8_t> script) {
            const Transaction candidate =
                Spend(parent, 0, {TxOutput(100000, owned), TxOutput(0, std::move(script))});
            cases.push_back({name,
                             Proposal(candidate, {parent}, owned, 200000, 100000, 100000, 100000),
                             false});
        };
        add_malformed_marker("marker_truncated_pushdata1", {0x6a, 0x4c});
        add_malformed_marker("marker_truncated_pushdata2", {0x6a, 0x4d});
        add_malformed_marker("marker_truncated_pushdata2_length", {0x6a, 0x4d, 0x00});
        std::vector<uint8_t> declared_too_long{0x6a, 0x4c, 76};
        declared_too_long.insert(declared_too_long.end(), 75U, 'A');
        add_malformed_marker("marker_declared_length_too_long", std::move(declared_too_long));
        std::vector<uint8_t> declared_too_short{0x6a, 0x4c, 76};
        declared_too_short.insert(declared_too_short.end(), 77U, 'A');
        add_malformed_marker("marker_declared_length_too_short", std::move(declared_too_short));
        add_malformed_marker("marker_direct_push_trailing", {0x6a, 0x01, 'A', 'B'});
        add_malformed_marker("marker_unsupported_pushdata4", {0x6a, 0x4e});

        Transaction twin_parent;
        twin_parent.inputs.push_back(TxInput::Coinbase("twin-parent"));
        twin_parent.outputs = {TxOutput(200000, owned), TxOutput(200000, owned)};
        const Transaction twin_original =
            Spend(twin_parent, 0, {TxOutput(100000, owned), TxOutput(0, marker)});
        const Transaction twin_switched =
            Spend(twin_parent, 1, {TxOutput(100000, owned), TxOutput(0, marker)});
        const auto twin_intent =
            offline_signing::MakeIntent(twin_original, {twin_parent.Serialize()}, "VELD_BHDR|", "",
                                        0, address, 100000, identity);
        Write(output / "alternate_vout.intent.json", IntentJson(twin_intent));
        cases.push_back(
            {"alternate_valid_vout",
             Proposal(twin_switched, {twin_parent}, owned, 200000, 100000, 100000, 100000), false});

        std::ofstream manifest(output / "cases.tsv", std::ios::binary | std::ios::trunc);
        if (!manifest.good())
            throw std::runtime_error("cannot write manifest");
        for (const auto& test : cases) {
            Write(output / (test.name + ".prepared.json"), test.proposal);
            const std::string intent_name = test.name == "alternate_valid_vout"
                                                ? "alternate_vout.intent.json"
                                                : "canonical.intent.json";
            manifest << test.name << '\t' << test.name << ".prepared.json" << '\t' << intent_name
                     << '\t' << (test.pass ? "pass" : "reject") << '\n';
        }
        std::cout << "PASS cases=" << cases.size() << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << "\n";
        return 1;
    }
}
