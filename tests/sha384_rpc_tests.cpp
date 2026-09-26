// Isolated native RPC calls: no listener/network. Synthetic funds, height=3,
// PoW skipped explicitly. Transactions and canonical block rules are real.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_SHA384_DESTINATION_TEST_HEIGHT 3
#include "network/rpc.h"
#include <iostream>

int main() {
    using namespace veld;
    unsigned checks = 0;
    auto check = [&](bool value, const char* text) {
        ++checks;
        if (!value)
            throw std::runtime_error(text);
    };
    const auto directory =
        std::filesystem::temp_directory_path() /
        ("veld-sha384-rpc-" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    try {
        {
            Blockchain chain;
            Mempool mempool;
            StorageEngine storage(directory.string(), MAINNET_MAGIC);
            RpcServer rpc(chain, mempool, storage);
            check(chain
                      .AddBlockDirect(CreateGenesisBlock(), true, true, false,
                                      mining::PowAdmissionContext::Internal())
                      .IsAccepted(),
                  "genesis");
            auto owner = GenerateKeyPair(), recipient = GenerateKeyPair(),
                 miner = GenerateKeyPair();
            owner.address = Sha384KeyAddress(owner.public_key);
            recipient.address = Sha384KeyAddress(recipient.public_key);
            UTXO funding;
            funding.tx_hash.fill(91);
            funding.output_index = 0;
            funding.value = 20 * VELD_UNITS;
            funding.script_pubkey = owner.GetP2PKHScript();
            funding.block_height = 0;
            funding.is_coinbase = false;
            chain.TestInjectUTXO(funding);
            auto call = [&](const std::string& method, const std::vector<std::string>& params) {
                std::vector<std::string> values;
                for (const auto& value : params)
                    values.push_back(JsonBuilder::String(value));
                auto response = rpc.Handle(
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":" + JsonBuilder::String(method) +
                    ",\"params\":" + JsonBuilder::Array(values) + "}");
                btc_buy::JsonValue root;
                std::string error;
                btc_buy::StrictJsonParser parser(response, 8 * 1024 * 1024, true);
                check(parser.Parse(root, error), "strict RPC JSON");
                return root;
            };
            auto ok = [](const btc_buy::JsonValue& value) {
                const auto* error = value.Get("error");
                return error && error->kind == btc_buy::JsonValue::Kind::Null;
            };
            auto candidate = [&](const std::vector<Transaction>& transactions, uint64_t nonce) {
                Block block;
                block.height = chain.Height() + 1;
                block.header.version = PROTOCOL_VERSION;
                block.header.prev_block_hash = chain.TipCopy().GetHash();
                block.header.timestamp = chain.TipCopy().header.timestamp + 1;
                block.header.bits = chain.ComputeNextBits();
                block.header.nonce = nonce;
                block.transactions.push_back(Blockchain::BuildCanonicalCoinbase(
                    block.height, chain.TotalSupplyUnits(), transactions.size() * MIN_TX_FEE,
                    miner.GetP2PKHScript()));
                block.transactions.insert(block.transactions.end(), transactions.begin(),
                                          transactions.end());
                block.UpdateMerkleRoot();
                return block;
            };
            auto add = [&](const Block& block) {
                return chain
                    .AddBlockDirect(block, false, false, true,
                                    mining::PowAdmissionContext::Internal())
                    .IsAccepted();
            };
            const std::vector<std::string> request{owner.address, recipient.address, "2"};
            check(!ok(call("preparerawtransaction", request)), "prepare before activation");
            const auto pubhex = BytesToHex(owner.public_key.data(), owner.public_key.size());
            check(!ok(call("getaddressfrompubkey", {pubhex, "sha384-v1"})),
                  "derive before activation");
            check(add(candidate({}, 1)) && add(candidate({}, 2)),
                  "advance to next-height activation");
            auto derived = call("getaddressfrompubkey", {pubhex, "sha384-v1"});
            check(ok(derived), "derive at activation");
            check(!ok(call("getaddressfrompubkey", {pubhex, "sha384-v2"})),
                  "unknown version refused");
            auto prepared = call("preparerawtransaction", request);
            check(ok(prepared), "prepare at activation");
            const auto* result = prepared.Get("result");
            check(result && result->Get("unsigned_tx_hex"), "prepared unsigned transaction");
            const auto raw = HexToBytes(result->Get("unsigned_tx_hex")->text);
            Transaction tx;
            check(Transaction::Deserialize(raw, 0, tx) == raw.size(), "decode prepared bytes");
            check(tx.inputs.size() == 1 && tx.outputs.size() == 2, "exact inputs and outputs");
            check(tx.outputs[0].value == 2 * VELD_UNITS &&
                      tx.outputs[0].script_pubkey == recipient.GetP2PKHScript(),
                  "exact recipient");
            check(tx.outputs[1].value == 18 * VELD_UNITS - MIN_TX_FEE &&
                      tx.outputs[1].script_pubkey == funding.script_pubkey,
                  "exact change and fee");
            tx.inputs[0].script_sig = owner.SignInput(tx, 0, funding.script_pubkey).script_sig;
            check(chain.ValidateTransactionLocking(tx), "prepared signature accepted");
            check(chain.RollbackTip(), "rollback before signing inclusion");
            check(!ok(call("preparerawtransaction", request)), "preparer rechecks after rollback");
            check(!chain.ValidateTransactionLocking(tx),
                  "prepared transaction cannot bypass reverted activation");
            check(add(candidate({}, 22)) && add(candidate({tx}, 3)),
                  "activate and include signed prepared transaction");
            check(chain.GetBalance(recipient.GetP2PKHScript()) == 2 * VELD_UNITS,
                  "recipient independently reconciled");
            check(chain.GetBalance(funding.script_pubkey) == 18 * VELD_UNITS - MIN_TX_FEE,
                  "sender independently reconciled");
        }
        std::filesystem::remove_all(directory);
        std::cout
            << "PASS " << checks
            << " native RPC, real signature and funded transaction checks; synthetic funds and accelerated height; no network\n";
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << checks << " " << e.what() << "\n";
        return 1;
    }
}
