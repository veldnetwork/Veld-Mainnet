#pragma once
// Disposable chain only: actual signatures, funding, VeldHash and replay.
#define VELD_APPCHAIN_BRIDGE_DEVNET 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_ASERT_TESTCHAIN 1
#define VELD_LIGHT_VERIFY 1
#include "core/blockchain.h"
#include "core/mempool.h"
#include "wallet/wallet.h"
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace app;
namespace br = app::bridge;
namespace fs = std::filesystem;
unsigned checks = 0;
void check(bool ok, const std::string& what) {
    need(ok, what.c_str());
    ++checks;
    std::cout << "PASS " << what << std::endl;
}
Id name(const std::string& s) {
    return hash("VAPP/parent-bridge-fixture/1", Bytes(s.begin(), s.end()));
}
void mine(veld::Block& b) {
    veld::CanonicalPowTarget target;
    need(veld::DecodeCanonicalVeldTarget(b.header.bits, target), "canonical target");
    for (uint64_t n = 0; n < 65536; ++n) {
        b.header.nonce = n;
        auto proof =
            veld::mining::VeldHashWithDataset<true>(b.header.Serialize(), b.height, target);
        need(veld::mining::g_veldhash_last_dataset_ok(), "full VeldHash dataset");
        if (proof < target.bytes)
            return;
    }
    throw Invalid("bounded mining exhausted");
}
void admit(veld::Blockchain& c, const veld::Block& b) {
    bool ok =
        c.AddBlockDirect(b, false, false, false, veld::mining::PowAdmissionContext::Internal())
            .IsAccepted();
    check(ok, "full parent validation h=" + std::to_string(b.height) +
                  (ok ? "" : " " + veld::Blockchain::GetLastRejectTag()));
}
void save(const fs::path& path, const veld::Block& b) {
    auto bytes = b.Serialize();
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    f.close();
    need(bool(f), "block file write");
}
veld::Block load(const fs::path& path, uint64_t height) {
    std::ifstream f(path, std::ios::binary);
    need(bool(f), "missing block file");
    Bytes data((std::istreambuf_iterator<char>(f)), {});
    need(data.size() <= veld::MAX_BLOCK_SIZE, "block cap");
    veld::Block b;
    need(veld::Block::Deserialize(data, 0, b) == data.size(), "block decode");
    b.height = height;
    return b;
}
struct Fixture {
    veld::Blockchain chain;
    veld::RealKeyPair key = veld::GenerateKeyPair(true);
    fs::path path;
    uint64_t fees(const std::vector<veld::Transaction>& txs) {
        uint64_t total = 0;
        for (auto& tx : txs) {
            uint64_t in = 0;
            for (auto& p : tx.inputs) {
                auto u = chain.GetUTXO(p.prev_tx_hash, p.prev_out_index);
                need(u.has_value(), "fixture input");
                credit(in, u->value);
            }
            debit(in, tx.TotalOutput());
            credit(total, in);
        }
        return total;
    }
    veld::Block candidate(const std::vector<veld::Transaction>& txs = {}) {
        veld::Block b;
        b.height = chain.Height() + 1;
        b.header.version = veld::PROTOCOL_VERSION;
        b.header.prev_block_hash = chain.TipCopy().GetHash();
        b.header.timestamp = chain.TipCopy().header.timestamp + veld::TARGET_BLOCK_TIME;
        b.header.bits = chain.ComputeNextBits();
        auto all = txs;
        if (b.height % veld::VAULT_DISTRIBUTION_INTERVAL == 0) {
            auto flush = chain.BuildVaultDistributionFlushTx(b.height);
            if (!flush.inputs.empty())
                all.push_back(flush);
        }
        b.transactions.push_back(veld::Blockchain::BuildCanonicalCoinbase(
            b.height, chain.TotalSupplyUnits(), fees(all), key.GetP2PKHScript()));
        b.transactions.insert(b.transactions.end(), all.begin(), all.end());
        b.UpdateMerkleRoot();
        return b;
    }
    veld::Block block(const std::vector<veld::Transaction>& txs = {}) {
        auto b = candidate(txs);
        mine(b);
        admit(chain, b);
        save(path / (std::to_string(b.height) + ".block"), b);
        return b;
    }
    void until(uint64_t h) {
        while (chain.Height() < h)
            block();
    }
    void sign(veld::Transaction& tx) {
        tx.InvalidateTxIDCache();
        for (size_t i = 0; i < tx.inputs.size(); ++i) {
            auto& p = tx.inputs[i];
            auto u = chain.GetUTXO(p.prev_tx_hash, p.prev_out_index);
            need(u.has_value(), "sign input");
            if (!br::reserve(u->script_pubkey))
                p.script_sig = key.SignInput(tx, i, u->script_pubkey).script_sig;
        }
        tx.InvalidateTxIDCache();
    }
    veld::Transaction fund(const Bytes& marker, const std::vector<veld::TxOutput>& extra = {},
                           uint64_t fee = veld::MIN_TX_FEE) {
        auto coins = chain.GetUTXOsForScript(key.GetP2PKHScript());
        uint64_t amount = fee;
        for (auto& o : extra)
            credit(amount, o.value);
        auto u = std::find_if(coins.begin(), coins.end(), [&](auto& coin) {
            return coin.value > amount &&
                   (!coin.is_coinbase ||
                    chain.Height() >= coin.block_height + veld::COINBASE_MATURITY);
        });
        need(u != coins.end(), "real mature funding available");
        veld::Transaction tx;
        veld::TxInput in;
        in.prev_tx_hash = u->tx_hash;
        in.prev_out_index = u->output_index;
        tx.inputs.push_back(in);
        tx.outputs.emplace_back(0, marker);
        tx.outputs.insert(tx.outputs.end(), extra.begin(), extra.end());
        tx.outputs.emplace_back(u->value - amount, key.GetP2PKHScript());
        sign(tx);
        return tx;
    }
    void refused(const veld::Transaction& tx, const std::string& label, bool actualBlock = true) {
        auto u = chain.UtxoDigest();
        auto s = chain.SupplyDigest();
        auto state = chain.AppBridgeDigest();
        check(!chain.ValidateTransactionLocking(tx), label + " native admission");
        check(!chain.ValidateCachedMempoolLockingContext(tx), label + " cached admission");
        veld::Mempool pool;
        check(pool.Add(tx, veld::MIN_TX_FEE, chain.Height(), chain) !=
                  veld::Mempool::AddResult::ACCEPTED,
              label + " mempool");
        if (actualBlock) {
            auto b = candidate({tx});
            mine(b);
            check(!chain
                       .AddBlockDirect(b, false, false, false,
                                       veld::mining::PowAdmissionContext::Internal())
                       .IsAccepted(),
                  label + " mined block");
        }
        check(chain.UtxoDigest() == u && chain.SupplyDigest() == s &&
                  chain.AppBridgeDigest() == state,
              label + " no mutation");
    }
};
Certificate certificate(Checkpoint cp, const std::array<Key, 10>& keys) {
    Certificate cert;
    cert.checkpoint = cp;
    auto id = cp.id();
    for (unsigned i = 0; i < 7; ++i) {
        IndexedSignature s;
        s.index = i;
        size_t size = s.bytes.size();
        need(PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(s.bytes.data(), &size, id.data(),
                                                         id.size(), keys[i].secret.data()) == 0 &&
                 size == s.bytes.size(),
             "actual attestor signature");
        cert.signatures.push_back(s);
    }
    return cert;
}
Bytes command(uint8_t op, const Id& id, const Bytes& tail = {}) {
    Writer w;
    w.raw(id);
    w.raw(tail);
    return br::marker(op, w.b);
}
void summary(const fs::path& path, const veld::Blockchain& c) {
    std::ofstream f(path);
    f << "{\"status\":\"PASS\",\"checks\":" << checks << ",\"height\":" << c.Height()
      << ",\"tip\":\"" << veld::HashToHex(c.TipCopy().GetHash()) << "\",\"utxo_digest\":\""
      << veld::HashToHex(c.UtxoDigest()) << "\",\"supply_digest\":\""
      << veld::HashToHex(c.SupplyDigest()) << "\",\"bridge_digest\":\"" << hex(c.AppBridgeDigest())
      << "\",\"reserve\":" << c.AppBridgeState()->totalReserve
      << ",\"pow_bypassed\":false,\"scripts_bypassed\":false,\"injected_utxos\":"
         "false,\"network_started\":false,\"scope\":\"parent bridge kernel; "
         "quorum signs fixture child commitments, no child replay service\"}\n";
    f.close();
    need(bool(f), "receipt write");
}
