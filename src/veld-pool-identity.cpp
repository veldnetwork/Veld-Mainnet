// Restricted operator-funded identity operations. No arbitrary transaction,
// destination, unlock, governance, validator, or message signing interface.
#include "pool/signing_policy.h"
#include "consensus/staking.h"
#include "consensus/nms.h"
#include "pool/build_identity.h"
#include <iostream>

int main(int argc, char** argv) {
    using namespace veld;
    using namespace veld::pool_signing;
    try {
        if (pool::PrintBuildIdentity(argc, argv, "pool-identity-signer", true))
            return 0;
        Require(argc == 3, "requires protected seed and authorized-input manifest paths");
        std::array<char, 65538> frame{};
        Require(bool(std::cin.getline(frame.data(), frame.size())), "bounded request frame");
        Json request, policy;
        std::string error;
        Require(btc_buy::StrictJsonParser(frame.data(), 65536, true).Parse(request, error),
                "request JSON");
        Fields(request, {"chain", "action", "height", "header", "stake_units", "tier", "inputs"});

        std::vector<uint8_t> raw_policy;
        Require(channel::secure_file::Read(argv[2], raw_policy, &error, 1024 * 1024, true) ==
                    channel::secure_file::ReadResult::Ok,
                "protected input manifest unavailable");
        const std::string policy_text(raw_policy.begin(), raw_policy.end());
        Require(btc_buy::StrictJsonParser(policy_text, 1024 * 1024, true).Parse(policy, error),
                "input policy JSON");
        Fields(policy, {"chain", "script", "allowed_inputs"});
        auto genesis = HexToBytes(GENESIS_HASH);
        std::reverse(genesis.begin(), genesis.end());
        Require(Text(*request.Get("chain")) == BytesToHex(genesis) &&
                    Text(*policy.Get("chain")) == BytesToHex(genesis),
                "wrong chain");
        const auto action = Text(*request.Get("action"));
        Require(action == "nms" || action == "stake" || action == "consolidate",
                "operation not permitted");
        const uint64_t height = Amount(*request.Get("height"), UINT64_MAX - 1);
        Require(height > 0, "inclusion height");
        const auto& allowed = *policy.Get("allowed_inputs");
        const auto& inputs = *request.Get("inputs");
        Require(allowed.kind == Json::Kind::Array && allowed.array.size() <= 10000,
                "authorized input bound");
        Require(inputs.kind == Json::Kind::Array && !inputs.array.empty() &&
                    inputs.array.size() <= 64,
                "input bound");

        std::map<std::pair<std::string, uint32_t>, uint64_t> authorizations;
        auto coin = [](const Json& input) {
            Fields(input, {"txid", "vout", "units"});
            const auto txid = Text(*input.Get("txid"));
            Require(txid.size() == 64 &&
                        txid.find_first_not_of("0123456789abcdef") == std::string::npos,
                    "txid encoding");
            return std::pair{
                txid, static_cast<uint32_t>(Amount(*input.Get("vout"), UINT32_MAX - 1))};
        };
        for (const auto& input : allowed.array) {
            const auto point = coin(input);
            const auto amount = Amount(*input.Get("units"));
            Require(amount > 0 && authorizations.emplace(point, amount).second,
                    "authorization duplicate");
        }
        Transaction tx;
        uint64_t total = 0;
        std::set<std::pair<std::string, uint32_t>> used;
        for (const auto& input : inputs.array) {
            const auto point = coin(input);
            const auto amount = Amount(*input.Get("units"));
            Require(authorizations.contains(point) && authorizations.at(point) == amount &&
                        used.insert(point).second,
                    "funding not explicitly operator-authorized");
            total = Add(total, amount);
            TxInput in;
            in.prev_tx_hash = HexToHash(point.first);
            in.prev_out_index = point.second;
            tx.inputs.push_back(in);
        }
        Require(total > MIN_TX_FEE, "operator funds insufficient");
        const auto key = Key(argv[1]);
        const auto script = key.GetP2PKHScript();
        Require(BytesToHex(script) == Text(*policy.Get("script")), "operator identity mismatch");
        const auto stake = Amount(*request.Get("stake_units"));
        const auto tier = Amount(*request.Get("tier"), 4);

        std::vector<uint8_t> operation;
        if (action == "nms") {
            Require(stake == 0 && tier == 0 && inputs.array.size() == 1 &&
                        height % COMINE_WINDOW_BLOCKS != 0,
                    "near-miss operation policy");
            const auto encoded = Text(*request.Get("header"));
            Require(encoded.size() == 176 &&
                        encoded.find_first_not_of("0123456789abcdef") == std::string::npos,
                    "header encoding");
            const auto bytes = HexToBytes(encoded);
            BlockHeader header;
            Require(header.Deserialize(bytes), "near-miss header");
            CanonicalPowTarget target;
            Require(DecodeCanonicalVeldTarget(header.bits, target), "near-miss target");
            const auto proof = mining::VeldHashForVerification(bytes, height, target);
            Require(mining::g_veldhash_last_dataset_ok() && IsNmsProofInRange(proof, target),
                    "genuine near miss required");
            Require(total >= 2 * MIN_TX_FEE, "near-miss fee funding");
            tx.outputs.emplace_back(MIN_TX_FEE, script);
            operation = BuildNmsOpReturnScript(EncodeNmsPayload(header));
            if (total > 2 * MIN_TX_FEE)
                tx.outputs.emplace_back(total - 2 * MIN_TX_FEE, script);
        } else {
            Require(Text(*request.Get("header")).empty(), "unexpected proof");
            if (action == "stake") {
                Require(stake == NMS_MIN_BOND_UNITS && tier >= 1 && total >= stake + MIN_TX_FEE,
                        "fixed co-mining principal and tier");
                tx.outputs.emplace_back(stake, script);
                if (total > stake + MIN_TX_FEE)
                    tx.outputs.emplace_back(total - stake - MIN_TX_FEE, script);
                const auto marker = StakingLedger::BuildLockOp(
                    ScriptToAddress(script), stake, height - 1, static_cast<uint8_t>(tier));
                Require(marker.size() <= 255, "stake marker bound");
                operation.push_back(0x6a);
                if (marker.size() > 75)
                    operation.push_back(0x4c);
                operation.push_back(static_cast<uint8_t>(marker.size()));
                operation.insert(operation.end(), marker.begin(), marker.end());
            } else {
                Require(stake == 0 && tier == 0 && inputs.array.size() >= 2,
                        "consolidation policy");
                tx.outputs.emplace_back(total - MIN_TX_FEE, script);
            }
        }
        if (!operation.empty())
            tx.outputs.emplace_back(0, operation);
        Require(!tx.HasDustOutput(DUST_THRESHOLD_UNITS),
                "operator change below native dust policy");

        std::vector<std::vector<uint8_t>> signatures;
        for (uint32_t i = 0; i < tx.inputs.size(); ++i)
            signatures.push_back(key.SignInput(tx, i, script).script_sig);
        for (size_t i = 0; i < signatures.size(); ++i)
            tx.inputs[i].script_sig = std::move(signatures[i]);
        tx.InvalidateTxIDCache();
        for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
            ScriptInterpreter verifier;
            Require(verifier.Execute(tx.inputs[i].script_sig, script, tx, i),
                    "signature verification");
        }
        const auto raw = tx.Serialize();
        Require(raw.size() <= 1024 * 1024 && tx.IsValid(), "signed transaction bounds");
        std::cout << HashToHex(tx.GetTxID()) << ' ' << BytesToHex(raw) << '\n';
    } catch (const std::exception& error) {
        std::cerr << "identity operation refused: " << error.what() << '\n';
        return 1;
    }
}
