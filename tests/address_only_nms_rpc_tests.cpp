#include "network/rpc.h"
#include "core/blockchain.h"
#include "core/mempool.h"
#include "crypto/veld_signing.h"
#include "mining/nms_submission.h"
#include "mining/nms_proof_file.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
using namespace veld;
namespace fs = std::filesystem;
unsigned checks = 0;
void check(bool ok, const std::string& label) {
    if (!ok)
        throw std::runtime_error(label + " reject=" + Blockchain::GetLastRejectTag());
    ++checks;
}
void mine(Block& b) {
    CanonicalPowTarget t;
    check(DecodeCanonicalVeldTarget(b.header.bits, t), "target");
    for (uint64_t n = 0; n < 65536; ++n) {
        b.header.nonce = n;
        auto proof = mining::VeldHash(b.header.Serialize(), b.height, t);
        check(mining::g_veldhash_last_dataset_ok(), "actual VeldHash dataset");
        if (proof < t.bytes)
            return;
    }
    throw std::runtime_error("mining budget");
}
Block candidate(Blockchain& c, const RealKeyPair& k, const std::vector<Transaction>& txs = {}) {
    Block b;
    b.height = c.Height() + 1;
    b.header.version = PROTOCOL_VERSION;
    b.header.prev_block_hash = c.TipCopy().GetHash();
    b.header.timestamp = c.TipCopy().header.timestamp + TARGET_BLOCK_TIME;
    b.header.bits = c.ComputeNextBits();
    uint64_t fees = 0;
    for (const auto& t : txs) {
        uint64_t in = 0;
        for (const auto& i : t.inputs) {
            auto u = c.GetUTXO(i.prev_tx_hash, i.prev_out_index);
            check(bool(u), "funding input");
            in += u->value;
        }
        check(in >= t.TotalOutput(), "positive fee");
        fees += in - t.TotalOutput();
    }
    b.transactions.push_back(Blockchain::BuildCanonicalCoinbase(b.height, c.TotalSupplyUnits(),
                                                                fees, k.GetP2PKHScript()));
    b.transactions.insert(b.transactions.end(), txs.begin(), txs.end());
    if (b.height % COMINE_WINDOW_BLOCKS == 0) {
        auto inputs = c.GetUTXOsForScript(AddressToScript(POOL_ADDRESS));
        uint64_t sum = 0;
        for (const auto& u : inputs)
            sum += u.value;
        auto outputs = c.ComputeExpectedPoolOutputs(b.header.prev_block_hash, sum, b.height);
        if (!outputs.empty()) {
            std::sort(inputs.begin(), inputs.end(), [](const UTXO& a, const UTXO& z) {
                return a.tx_hash != z.tx_hash ? a.tx_hash < z.tx_hash
                                              : a.output_index < z.output_index;
            });
            Transaction payout;
            for (const auto& u : inputs) {
                TxInput i;
                i.prev_tx_hash = u.tx_hash;
                i.prev_out_index = u.output_index;
                payout.inputs.push_back(i);
            }
            for (const auto& [s, v] : outputs)
                payout.outputs.emplace_back(v, s);
            b.transactions.push_back(payout);
        }
    }
    b.UpdateMerkleRoot();
    return b;
}
void store(const fs::path& root, const Block& b) {
    auto bytes = b.Serialize();
    std::ofstream f(root / (std::to_string(b.height) + ".block"), std::ios::binary);
    f.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    check(bool(f), "write block");
}
Block commit(Blockchain& c, const RealKeyPair& k, const fs::path& root,
             const std::vector<Transaction>& txs = {}) {
    auto b = candidate(c, k, txs);
    mine(b);
    check(c.AddBlockDirect(b, false, false, false, mining::PowAdmissionContext::Internal())
              .IsAccepted(),
          "actual mined block");
    store(root, b);
    return b;
}
BlockHeader claim(Blockchain& c, unsigned unique) {
    auto h = candidate(c, GenerateKeyPair(false)).header;
    h.merkle_root.fill(uint8_t(unique));
    CanonicalPowTarget t;
    check(DecodeCanonicalVeldTarget(h.bits, t), "claim target");
    for (uint64_t n = 0; n < 65536; ++n) {
        h.nonce = n;
        auto p = mining::VeldHash(h.Serialize(), c.Height() + 1, t);
        check(mining::g_veldhash_last_dataset_ok(), "NMS dataset");
        if (IsNmsProofInRange(p, t))
            return h;
    }
    throw std::runtime_error("NMS proof budget");
}
Transaction nms(const UTXO& u, const RealKeyPair& k, const BlockHeader& h) {
    Transaction t;
    TxInput i;
    i.prev_tx_hash = u.tx_hash;
    i.prev_out_index = u.output_index;
    t.inputs.push_back(i);
    t.outputs.emplace_back(MIN_TX_FEE, u.script_pubkey);
    t.outputs.emplace_back(0, BuildNmsOpReturnScript(EncodeNmsPayload(h)));
    t.outputs.emplace_back(u.value - 2 * MIN_TX_FEE, u.script_pubkey);
    t.inputs[0].script_sig = k.SignInput(t, 0, u.script_pubkey).script_sig;
    return t;
}

btc_buy::JsonValue call(RpcServer& rpc, const std::string& method,
                        const std::vector<std::string>& params, bool expect_error = false) {
    std::vector<std::string> items;
    for (const auto& p : params)
        items.push_back(JsonBuilder::String(p));
    const auto raw =
        rpc.Handle("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":" + JsonBuilder::String(method) +
                   ",\"params\":" + JsonBuilder::Array(items) + "}");
    btc_buy::JsonValue value;
    std::string error;
    btc_buy::StrictJsonParser parser(raw, 1024 * 1024, true);
    check(parser.Parse(value, error), "RPC JSON parse");
    const auto* failure = value.Get("error");
    const bool failed = failure && failure->kind != btc_buy::JsonValue::Kind::Null;
    if (expect_error) {
        check(failed, "RPC must refuse " + method);
        return value;
    }
    if (failed)
        throw std::runtime_error(method + " failed: " + raw);
    check(value.Get("result") != nullptr, "RPC result");
    return *value.Get("result");
}
Transaction prepared(const btc_buy::JsonValue& result, const RealKeyPair& key) {
    const auto* raw = result.Get("unsigned_tx_hex");
    check(raw && raw->kind == btc_buy::JsonValue::Kind::String, "unsigned transaction provided");
    auto bytes = HexToBytes(raw->text);
    Transaction tx;
    check(Transaction::Deserialize(bytes, 0, tx) == bytes.size(), "canonical unsigned bytes");
    check(tx.inputs.size() == 1 && tx.inputs[0].script_sig.empty(), "preparer never signs");
    tx.inputs[0].script_sig = key.SignInput(tx, 0, key.GetP2PKHScript()).script_sig;
    return tx;
}
int main(int argc, char** argv) {
    try {
        check(argc == 2, "disposable output directory");
        fs::path root = fs::absolute(argv[1]);
        check(fs::create_directory(root), "fresh fixture");
        Blockchain c;
        auto genesis = CreateGenesisBlock();
        check(
            c.AddBlockDirect(genesis, false, false, false, mining::PowAdmissionContext::Internal())
                .IsAccepted(),
            "real genesis");
        store(root, genesis);
        const auto producer = GenerateKeyPair(false), owner = GenerateKeyPair(false),
                   other = GenerateKeyPair(false);
        const auto address = ScriptToAddress(owner.GetP2PKHScript());
        uint64_t stake = NMS_MIN_BOND_UNITS;
        c.SetNmsStakeQuery([&](const std::string& a) { return a == address ? stake : 0; });
        while (c.Height() < 101)
            commit(c, producer, root);
        auto coins = c.GetUTXOsForScript(producer.GetP2PKHScript());
        auto u = std::find_if(coins.begin(), coins.end(), [&](const auto& x) {
            return x.value > VELD_UNITS &&
                   (!x.is_coinbase || c.Height() >= x.block_height + COINBASE_MATURITY);
        });
        check(u != coins.end(), "mature mined funding");
        Transaction funding;
        TxInput in;
        in.prev_tx_hash = u->tx_hash;
        in.prev_out_index = u->output_index;
        funding.inputs.push_back(in);
        funding.outputs.emplace_back(VELD_UNITS / 10, owner.GetP2PKHScript());
        funding.outputs.emplace_back(u->value - VELD_UNITS / 10 - MIN_TX_FEE,
                                     producer.GetP2PKHScript());
        funding.inputs[0].script_sig = producer.SignInput(funding, 0, u->script_pubkey).script_sig;
        commit(c, producer, root, {funding});
        Mempool pool;
        StorageEngine storage((root / "rpc-storage").string(), MAINNET_MAGIC);
        RpcServer rpc(c, pool, storage);
        rpc.SetIBDCompleteFn([] { return true; });
        const auto sha384_address = Sha384KeyAddress(owner.public_key, false);
        const auto unsupported = call(rpc, "getaddressnmsproof", {sha384_address});
        check(!unsupported.Get("supported")->boolean && !unsupported.Get("eligible")->boolean &&
                  !unsupported.Get("needed")->boolean && unsupported.Get("payload")->text.empty() &&
                  unsupported.Get("reason")->text.find("SHA-384") != std::string::npos,
              "SHA-384 mining payout reports unsupported NMS explicitly");
        auto h = claim(c, 11);
        rpc.OfferAddressOnlyNmsProof(owner.GetP2PKHScript(), h);
        auto proof = call(rpc, "getaddressnmsproof", {address});
        check(proof.Get("payload")->text == BytesToHex(EncodeNmsPayload(h)),
              "keyless public proof round trip");
        const auto proof_dir = root / "proof-export";
        std::string export_error;
        check(channel::secure_file::EnsurePrivateDirectory(proof_dir.string(), &export_error),
              "private public-proof directory");
        mining::NmsProofFile exporter;
        const auto packet = rpc.AddressOnlyNmsProofJson(address);
        check(exporter.Update((proof_dir / "address-only-nms.json").string(), packet, 1,
                              export_error) == mining::NmsProofFile::Result::Written,
              "export actual mined public proof");
        std::ifstream exported(proof_dir / "address-only-nms.json");
        std::string imported((std::istreambuf_iterator<char>(exported)), {});
        check(imported == packet, "exact exported proof readback");
        btc_buy::JsonValue imported_proof;
        btc_buy::StrictJsonParser imported_parser(imported, 1200, true);
        check(imported_parser.Parse(imported_proof, export_error) &&
                  imported_proof.Get("payload")->text == proof.Get("payload")->text,
              "exported proof parses for wallet");
        auto wrong = call(rpc, "getaddressnmsproof", {ScriptToAddress(other.GetP2PKHScript())});
        check(wrong.Get("payload")->text.empty(), "proof is identity bound");
        call(rpc, "preparenmstx", {address, "00"}, true);
        stake = 999 * VELD_UNITS;
        call(rpc, "preparenmstx", {address, proof.Get("payload")->text}, true);
        stake = NMS_MIN_BOND_UNITS;
        auto invalid = h;
        invalid.bits ^= 1;
        call(rpc, "preparenmstx", {address, BytesToHex(EncodeNmsPayload(invalid))}, true);
        const auto prep = call(rpc, "preparenmstx", {address, imported_proof.Get("payload")->text});
        const auto original = prepared(prep, owner);
        check(c.ValidateTransactionLocking(original), "real wallet signature valid");
        check(pool.Add(original, MIN_TX_FEE, c.Height(), c) == Mempool::AddResult::ACCEPTED,
              "actual signed NMS mempool admission");
        call(rpc, "preparenmstx", {address, proof.Get("payload")->text}, true);
        call(rpc, "preparenmsrecovery", {address, BytesToHex(original.Serialize())}, true);
        // A competing mined block expires the claim; no credit is fabricated.
        commit(c, producer, root);
        pool.RemoveStale(c);
        check(c.NmsGetCredit(BytesToHex(owner.GetP2PKHScript())) == 0,
              "expired proof earns no entry");
        check(call(rpc, "getaddressnmsproof", {address}).Get("payload")->text.empty(),
              "stale mailbox hidden");
        call(rpc, "preparenmstx", {address, proof.Get("payload")->text}, true);
        const auto recover = prepared(
            call(rpc, "preparenmsrecovery", {address, BytesToHex(original.Serialize())}), owner);
        check(recover.inputs[0].prev_tx_hash == original.inputs[0].prev_tx_hash &&
                  recover.inputs[0].prev_out_index == original.inputs[0].prev_out_index,
              "recovery uses exact same input");
        check(recover.TotalOutput() == original.TotalOutput(), "recovery fee unchanged");
        check(recover.outputs.size() == 1 &&
                  recover.outputs[0].script_pubkey == owner.GetP2PKHScript(),
              "recovery returns funds only to owner");
        check(pool.Add(recover, MIN_TX_FEE, c.Height(), c) == Mempool::AddResult::ACCEPTED,
              "recovery admitted");
        commit(c, producer, root, {recover});
        pool.RemoveStale(c);
        h = claim(c, 29);
        rpc.OfferAddressOnlyNmsProof(owner.GetP2PKHScript(), h);
        proof = call(rpc, "getaddressnmsproof", {address});
        const auto accepted =
            prepared(call(rpc, "preparenmstx", {address, proof.Get("payload")->text}), owner);
        check(pool.Add(accepted, MIN_TX_FEE, c.Height(), c) == Mempool::AddResult::ACCEPTED,
              "fresh real near miss admitted");
        commit(c, producer, root, {accepted});
        pool.RemoveStale(c);
        check(c.NmsGetCredit(BytesToHex(owner.GetP2PKHScript())) == 1, "one confirmed entry");
        check(call(rpc, "getaddressnmsproof", {address}).Get("payload")->text.empty(),
              "credited identity has no new claim");
        call(rpc, "preparenmstx", {address, proof.Get("payload")->text}, true);
        Blockchain replay;
        replay.SetNmsStakeQuery([&](const std::string& a) { return a == address ? stake : 0; });
        g_nms_verify_cache.Clear();
        for (uint64_t height = 0; height <= c.Height(); ++height) {
            std::ifstream file(root / (std::to_string(height) + ".block"), std::ios::binary);
            std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), {});
            Block b;
            check(Block::Deserialize(bytes, 0, b) == bytes.size(), "persistent block decode");
            b.height = height;
            check(
                replay
                    .AddBlockDirect(b, false, false, false, mining::PowAdmissionContext::Internal())
                    .IsAccepted(),
                "independent full replay");
        }
        check(c.NmsSnapshot() == replay.NmsSnapshot() && c.UtxoDigest() == replay.UtxoDigest() &&
                  c.SupplyDigest() == replay.SupplyDigest(),
              "independent credit and state agreement");
        std::ofstream out(root / "result.json");
        out << "{\"status\":\"PASS_REAL_SIGNED_WALLET_NMS_AND_EXPIRED_RECOVERY\",\"checks\":"
            << checks << ",\"height\":" << c.Height()
            << ",\"actual_pow\":true,\"utxos_injected\":false,\"stake_eligibility_fixture\":true,\"p2p_tested\":false}\n";
        std::cout << "PASS real signed wallet NMS, expired recovery, persistent replay; checks="
                  << checks << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << std::endl;
        return 1;
    }
}
