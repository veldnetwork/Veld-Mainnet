#include "appchain_bridge_fixture.h"
#include "wallet/appchain_deposit.h"
#include "network/rpc.h"

using Json = veld::btc_buy::JsonValue;
using JB = veld::JsonBuilder;
Json parse(const std::string& text) {
    Json out;
    std::string error;
    veld::btc_buy::StrictJsonParser parser(text, veld::offline_signing::kMaxPreparedJsonBytes,
                                           true);
    need(parser.Parse(out, error), "strict fixture JSON");
    return out;
}
std::string request(veld::RpcServer& rpc, const std::string& method,
                    const std::vector<std::string>& params = {}) {
    std::vector<std::string> encoded;
    for (const auto& p : params)
        encoded.push_back(JB::String(p));
    return rpc.Handle("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":" + JB::String(method) +
                      ",\"params\":" + JB::Array(encoded) + "}");
}
void write(const fs::path& path, const std::string& text) {
    need(!fs::exists(path), "fresh fixture output required");
    std::ofstream out(path, std::ios::binary);
    out << text;
    out.close();
    need(bool(out), "fixture write");
    fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write);
}
std::string read(const fs::path& path) {
    need(fs::is_regular_file(path) && fs::file_size(path) <= 64U * 1024U * 1024U,
         "bounded fixture input");
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), {}};
}
std::string field(const Json& value, const std::string& name) {
    const auto* f = value.Get(name);
    need(f && f->kind == Json::Kind::String, "fixture string field");
    return f->text;
}
app::Id id(const Json& value, const std::string& name) {
    auto bytes = app::unhex(field(value, name), 48);
    need(bytes.size() == 48, "fixture identity");
    app::Id out{};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}
int main(int argc, char** argv) {
    try {
        need(argc >= 3, "prepare DIR, serve INPUT OUTPUT, or settle INPUT SIGNED OUTPUT");
        const std::string mode = argv[1];
        const bool serve = mode == "serve" || mode == "serve-confirmed";
        need((mode == "prepare" && argc == 3) || (mode == "settle" && argc == 5) ||
                 (serve && argc == 4),
             "fixture arguments");
        if (serve)
            std::cout.rdbuf(std::cerr.rdbuf());
        Fixture f;
        f.path = fs::absolute(mode == "prepare" ? argv[2] : serve ? argv[3] : argv[4]);
        need(fs::create_directory(f.path), "fresh browser deposit history");
        if (serve) {
            const fs::path input = fs::absolute(argv[2]);
            for (uint64_t h = 0; h <= 102; ++h) {
                auto b = load(input / (std::to_string(h) + ".block"), h);
                admit(f.chain, b);
                save(f.path / (std::to_string(h) + ".block"), b);
            }
            veld::Mempool pool;
            veld::StorageEngine storage((f.path / "storage").string(), veld::MAINNET_MAGIC);
            veld::RpcServer rpc(f.chain, pool, storage);
            std::string line;
            bool mined = false;
            while (std::getline(std::cin, line)) {
                need(line.size() <= 2U * 1024U * 1024U, "bounded local RPC request");
                auto req = parse(line);
                auto method = field(req, "method");
                need(method == "getappchainbridgeinfo" || method == "prepareappchaindeposit" ||
                         method == "gettxout" || method == "gettransaction" ||
                         method == "sendrawtransaction" || method == "gettransactionrecent" ||
                         method == "getmempoolentry" || method == "getrawtransaction",
                     "local qualification RPC allowlist");
                const auto result = rpc.Handle(line) + "\n";
                if (mode == "serve-confirmed" && method == "sendrawtransaction" && !mined &&
                    parse(result).Get("result")) {
                    auto transactions = pool.GetAllTransactions();
                    check(transactions.size() == 1, "one deposit before lost acknowledgement");
                    auto block = f.block(transactions);
                    pool.RemoveConfirmed(block);
                    mined = true;
                }
                need(std::fwrite(result.data(), 1, result.size(), stdout) == result.size() &&
                         std::fflush(stdout) == 0,
                     "RPC response");
            }
            auto transactions = pool.GetAllTransactions();
            check(transactions.size() == (mined ? 0U : 1U),
                  "one actual browser deposit accepted without duplicate state");
            if (!mined)
                f.block(transactions);
            check(f.chain.Height() == 103, "exactly one deposit block");
            summary(f.path / "http-settled.json", f.chain);
            veld::Blockchain replay;
            for (uint64_t h = 0; h <= 103; ++h)
                admit(replay, load(f.path / (std::to_string(h) + ".block"), h));
            check(replay.AppBridgeDigest() == f.chain.AppBridgeDigest() &&
                      replay.UtxoDigest() == f.chain.UtxoDigest(),
                  "actual RPC deposit mined and replayed exactly");
        } else if (mode == "prepare") {
            auto genesis = veld::CreateGenesisBlock();
            admit(f.chain, genesis);
            save(f.path / "0.block", genesis);
            f.until(101);
            std::array<Key, 10> signers;
            Committee c;
            c.parentGenesis = genesis.GetHash();
            c.bridge = name("browser-deposit-bridge");
            c.childGenesis = name("browser-deposit-child");
            for (unsigned i = 0; i < 10; ++i)
                c.keys[i] = signers[i].pub;
            Writer registration;
            registration.str(c.encode(), 20000);
            f.block({f.fund(br::marker(0, registration.b))});
            veld::Mempool pool;
            veld::StorageEngine storage((f.path / "storage").string(), veld::MAINNET_MAGIC);
            veld::RpcServer rpc(f.chain, pool, storage);
            const auto beneficiary = name("browser-child-account");
            const auto address = veld::ScriptToAddress(f.key.GetP2PKHScript());
            const auto response = request(rpc, "prepareappchaindeposit",
                                          {address, hex(c.bridge), hex(c.id()), hex(c.childGenesis),
                                           hex(beneficiary), "0.15", "0.05"});
            const auto prepared = parse(response);
            const auto* result = prepared.Get("result");
            need(result, "prepared result");
            std::vector<std::string> prevouts;
            veld::Transaction tx;
            auto raw = app::unhex(field(*result, "unsigned_tx_hex"));
            need(veld::Transaction::Deserialize(raw, 0, tx) == raw.size(),
                 "fixture unsigned decode");
            for (const auto& in : tx.inputs) {
                const auto txid = veld::HashToHex(in.prev_tx_hash);
                auto live = request(rpc, "gettxout", {txid, std::to_string(in.prev_out_index)});
                auto parsed = parse(live);
                const auto* coin = parsed.Get("result");
                need(coin && coin->Get("block_height"), "live fixture coin");
                auto parent =
                    request(rpc, "gettransaction", {txid, coin->Get("block_height")->text});
                prevouts.push_back(JB::Object({{"txid", JB::String(txid)},
                                               {"vout", JB::Number(uint64_t(in.prev_out_index))},
                                               {"live", live},
                                               {"parent", parent}}));
            }
            auto selected =
                JB::Object({{"parent_genesis", JB::String(veld::HashToHex(genesis.GetHash()))},
                            {"bridge_id", JB::String(hex(c.bridge))},
                            {"descriptor_id", JB::String(hex(c.id()))},
                            {"child_genesis", JB::String(hex(c.childGenesis))},
                            {"beneficiary_id", JB::String(hex(beneficiary))},
                            {"trading_atoms", JB::String("15000000")},
                            {"fuel_backing_atoms", JB::String("5000000")}});
            // Disposable test seed only; never log or use a production wallet.
            write(f.path / "browser-input.json",
                  JB::Object({{"selected", selected},
                              {"signature_genesis", JB::String(veld::GENESIS_HASH)},
                              {"address", JB::String(address)},
                              {"seed", JB::String(app::hex(f.key.private_key))},
                              {"public_key", JB::String(app::hex(f.key.public_key))},
                              {"prepared", response},
                              {"network", request(rpc, "getappchainbridgeinfo", {hex(c.bridge)})},
                              {"prevouts", JB::Array(prevouts)}}));
            summary(f.path / "prepared.json", f.chain);
        } else {
            const fs::path input = fs::absolute(argv[2]);
            auto document = parse(read(input / "browser-input.json"));
            const auto* selected = document.Get("selected");
            need(selected, "selected identity");
            for (uint64_t h = 0; h <= 102; ++h) {
                auto b = load(input / (std::to_string(h) + ".block"), h);
                admit(f.chain, b);
                save(f.path / (std::to_string(h) + ".block"), b);
            }
            const auto funding = veld::AddressToScript(field(document, "address"));
            veld::AppchainDepositSelection selection{load(input / "0.block", 0).GetHash(),
                                                     id(*selected, "bridge_id"),
                                                     id(*selected, "descriptor_id"),
                                                     id(*selected, "child_genesis"),
                                                     id(*selected, "beneficiary_id"),
                                                     15000000,
                                                     5000000};
            veld::offline_signing::VerifiedPrepared verified;
            std::string error;
            const auto* response = document.Get("prepared");
            need(response && response->Get("result"), "saved prepare response");
            check(veld::AuthenticateAppchainDeposit(*response->Get("result"), funding, selection,
                                                    verified, error),
                  "independent native authentication of browser review");
            for (unsigned caseId = 0; caseId < 7; ++caseId) {
                auto wrong = selection;
                if (caseId == 0)
                    wrong.parentGenesis[0] ^= 1;
                if (caseId == 1)
                    wrong.bridge[0] ^= 1;
                if (caseId == 2)
                    wrong.descriptor[0] ^= 1;
                if (caseId == 3)
                    wrong.child[0] ^= 1;
                if (caseId == 4)
                    wrong.beneficiary[0] ^= 1;
                if (caseId == 5)
                    ++wrong.trading;
                if (caseId == 6)
                    ++wrong.fuel;
                veld::offline_signing::VerifiedPrepared denied;
                check(!veld::AuthenticateAppchainDeposit(*response->Get("result"), funding, wrong,
                                                         denied, error),
                      "native verifier refuses changed selection " + std::to_string(caseId));
            }
            auto text = read(argv[3]);
            while (!text.empty() && (text.back() == '\n' || text.back() == '\r'))
                text.pop_back();
            auto raw = app::unhex(text, 1024 * 1024);
            veld::Transaction signedTx;
            need(veld::Transaction::Deserialize(raw, 0, signedTx) == raw.size() &&
                     signedTx.Serialize() == raw,
                 "canonical signed bytes");
            auto stripped = signedTx;
            for (auto& in : stripped.inputs)
                in.script_sig.clear();
            stripped.InvalidateTxIDCache();
            check(stripped.Serialize() == verified.tx.Serialize(),
                  "browser signs the exact authenticated review");
            check(raw.size() == verified.signed_size,
                  "browser signed size matches exact fee projection");
            check(f.chain.ValidateTransactionLocking(signedTx),
                  "native validator accepts actual browser ML-DSA signatures");
            veld::Mempool pool;
            check(pool.Add(signedTx, veld::MIN_TX_FEE, f.chain.Height(), f.chain) ==
                      veld::Mempool::AddResult::ACCEPTED,
                  "browser deposit accepted by native mempool");
            f.block({signedTx});
            const auto state = f.chain.AppBridgeState();
            const auto& deposit =
                state->records.at(selection.bridge).deposits.at({signedTx.GetTxID(), 1});
            check(deposit.owner == selection.beneficiary && deposit.trading == selection.trading &&
                      deposit.fuel == selection.fuel,
                  "mined browser deposit retains exact child owner and backed allocation");
            const auto digest = f.chain.AppBridgeDigest();
            auto rollback = f.chain.TipCopy();
            // Replay persisted blocks into a second state without wallet keys.
            summary(f.path / "settled.json", f.chain);
            veld::Blockchain replay;
            for (uint64_t h = 0; h <= 103; ++h)
                admit(replay, load(f.path / (std::to_string(h) + ".block"), h));
            check(replay.AppBridgeDigest() == digest &&
                      replay.UtxoDigest() == f.chain.UtxoDigest() &&
                      replay.TipCopy().GetHash() == rollback.GetHash(),
                  "persisted browser deposit full replay equality");
        }
        std::cout << "RESULT {\"passed\":" << checks << ",\"failed\":0}\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        return 1;
    }
}
