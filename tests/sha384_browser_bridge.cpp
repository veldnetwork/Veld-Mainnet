// Native half of an offline browser/native signing integration. Synthetic
// funding and activation=3; only PoW skipped. No listener or public RPC.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_SHA384_DESTINATION_TEST_HEIGHT 3
#include "network/rpc.h"
#include <fstream>
#include <iostream>
int main(int argc, char** argv) {
    using namespace veld;
    if (argc < 2)
        return 2;
    const auto dir = std::filesystem::temp_directory_path() /
                     ("veld-browser-bridge-" +
                      std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    unsigned checks = 0;
    auto check = [&](bool good, const char* name) {
        ++checks;
        if (!good)
            throw std::runtime_error(name);
    };
    try {
        {
            Blockchain chain;
            Mempool mempool;
            StorageEngine storage(dir.string(), MAINNET_MAGIC);
            RpcServer rpc(chain, mempool, storage);
            check(chain
                      .AddBlockDirect(CreateGenesisBlock(), true, true, false,
                                      mining::PowAdmissionContext::Internal())
                      .IsAccepted(),
                  "genesis");
            auto fixture = [](uint8_t value, bool wide) {
                RealKeyPair key;
                key.private_key.fill(value);
                key.public_key = DerivePublicKey(key.private_key);
                key.address =
                    wide ? Sha384KeyAddress(key.public_key) : PubKeyToAddress(key.public_key);
                return key;
            };
            auto owner = fixture(73, argc < 4 || std::string(argv[3]) != "legacy"),
                 recipient = fixture(74, true), miner = fixture(75, false);
            Transaction fundingTx;
            TxInput initial;
            initial.prev_tx_hash.fill(88);
            fundingTx.inputs.push_back(initial);
            fundingTx.outputs.emplace_back(20 * VELD_UNITS, owner.GetP2PKHScript());
            UTXO funding;
            funding.tx_hash = fundingTx.GetTxID();
            funding.output_index = 0;
            funding.value = 20 * VELD_UNITS;
            funding.script_pubkey = owner.GetP2PKHScript();
            funding.block_height = 0;
            funding.is_coinbase = false;
            chain.TestInjectUTXO(funding);
            auto candidate = [&](const std::vector<Transaction>& transactions, uint64_t nonce) {
                Block b;
                b.height = chain.Height() + 1;
                b.header.version = PROTOCOL_VERSION;
                b.header.prev_block_hash = chain.TipCopy().GetHash();
                b.header.timestamp = chain.TipCopy().header.timestamp + 1;
                b.header.bits = chain.ComputeNextBits();
                b.header.nonce = nonce;
                b.transactions.push_back(Blockchain::BuildCanonicalCoinbase(
                    b.height, chain.TotalSupplyUnits(), transactions.size() * MIN_TX_FEE,
                    miner.GetP2PKHScript()));
                b.transactions.insert(b.transactions.end(), transactions.begin(),
                                      transactions.end());
                b.UpdateMerkleRoot();
                return b;
            };
            auto add = [&](const Block& b) {
                return chain
                    .AddBlockDirect(b, false, false, true, mining::PowAdmissionContext::Internal())
                    .IsAccepted();
            };
            check(add(candidate({}, 1)) && add(candidate({}, 2)), "next height activates");
            if (std::string(argv[1]) == "--prepare") {
                const auto response = rpc.Handle(
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"preparerawtransaction\",\"params\":[" +
                    JsonBuilder::String(owner.address) + "," +
                    JsonBuilder::String(recipient.address) + ",\"2\"]}");
                btc_buy::JsonValue value;
                std::string error;
                btc_buy::StrictJsonParser parser(response, 8 * 1024 * 1024, true);
                check(parser.Parse(value, error) && value.Get("result"), "prepare RPC");
                std::cout
                    << JsonBuilder::Object(
                           {{"rpc", response},
                            {"seed", JsonBuilder::String(BytesToHex(owner.private_key.data(), 32))},
                            {"public_key",
                             JsonBuilder::String(BytesToHex(owner.public_key.data(), 1952))},
                            {"address", JsonBuilder::String(owner.address)},
                            {"recipient", JsonBuilder::String(recipient.address)},
                            {"genesis", JsonBuilder::String(GENESIS_HASH)},
                            {"parent_hex", JsonBuilder::String(BytesToHex(fundingTx.Serialize()))}})
                    << '\n';
            } else if (std::string(argv[1]) == "--verify" && argc >= 3) {
                std::ifstream file(argv[2]);
                std::string hex;
                std::getline(file, hex);
                check(file.good() || file.eof(), "read signed fixture");
                check(hex.size() < 1024 * 1024, "signed size");
                auto raw = HexToBytes(hex);
                Transaction tx;
                check(Transaction::Deserialize(raw, 0, tx) == raw.size(), "signed decode");
                check(tx.inputs.size() == 1 && tx.outputs.size() == 2, "shape");
                check(tx.outputs[0].value == 2 * VELD_UNITS &&
                          tx.outputs[0].script_pubkey == recipient.GetP2PKHScript(),
                      "recipient");
                check(tx.outputs[1].value == 18 * VELD_UNITS - MIN_TX_FEE &&
                          tx.outputs[1].script_pubkey == funding.script_pubkey,
                      "change and exact fee");
                check(chain.ValidateTransactionLocking(tx), "browser ML-DSA signature");
                auto altered = tx;
                altered.outputs[0].value++;
                check(!chain.ValidateTransactionLocking(altered), "changed payout rejected");
                check(chain.RollbackTip(), "rollback activation");
                // Historical consensus permitted outputs containing unknown scripts.
                // Preserve that history: the new opcode's SPENDING authorization activates
                // here; wallet preparation also refuses early funding as a safety policy.
                check(chain.ValidateTransactionLocking(tx) == (owner.address.size() < 50),
                      "historical output creation versus new input activation");
                check(add(candidate({}, 22)) && add(candidate({tx}, 3)),
                      "browser signed inclusion");
                check(chain.GetBalance(recipient.GetP2PKHScript()) == 2 * VELD_UNITS,
                      "recipient balance");
                check(chain.GetBalance(funding.script_pubkey) == 18 * VELD_UNITS - MIN_TX_FEE,
                      "sender balance");
                check(!chain.ValidateTransactionLocking(tx), "double spend refused");
                std::cout
                    << "PASS " << checks
                    << " native checks of browser-signed bytes, activation, accounting and mutation refusal\n";
            } else
                throw std::runtime_error("unknown mode");
        }
        std::filesystem::remove_all(dir);
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << checks << ' ' << e.what() << '\n';
        return 1;
    }
}
