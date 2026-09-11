#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#include "network/rpc.h"

#include <iostream>
#include <stdexcept>

using namespace veld;

namespace {
unsigned checks = 0;
void Check(bool value, const char* message) {
    ++checks;
    if (!value) throw std::runtime_error(message);
}

btc_buy::JsonValue Call(RpcServer& rpc, const std::string& method,
                       const std::vector<std::string>& params) {
    std::vector<std::string> items;
    for (const auto& param : params) items.push_back(JsonBuilder::String(param));
    const auto response = rpc.Handle(JsonBuilder::Object({
        {"jsonrpc", "\"2.0\""}, {"id", "1"},
        {"method", JsonBuilder::String(method)}, {"params", JsonBuilder::Array(items)}}));
    btc_buy::JsonValue value;
    std::string error;
    Check(btc_buy::StrictJsonParser(response).Parse(value, error), "RPC response parse");
    return value;
}

Transaction Prepared(const btc_buy::JsonValue& response) {
    const auto* result = response.Get("result");
    Check(result && result->Get("unsigned_tx_hex"), "prepared transaction missing");
    const auto raw = HexToBytes(result->Get("unsigned_tx_hex")->text);
    Transaction tx;
    Check(Transaction::Deserialize(raw, 0, tx) == raw.size() && tx.Serialize() == raw,
          "prepared transaction roundtrip");
    return tx;
}

void SignAndAdmit(Transaction& tx, const RealKeyPair& key, Blockchain& chain, Mempool& pool) {
    const size_t expected = tx.Serialize().size() + tx.inputs.size() *
        (offline_signing::kCanonicalInputScriptBytes + 2U);
    std::vector<std::vector<uint8_t>> scripts;
    for (uint32_t i = 0; i < tx.inputs.size(); ++i)
        scripts.push_back(BuildScriptSig(key.private_key, key.public_key, tx, i,
                                        key.GetP2PKHScript()).script_sig);
    for (size_t i = 0; i < scripts.size(); ++i) tx.inputs[i].script_sig = scripts[i];
    tx.InvalidateTxIDCache();
    Check(tx.Serialize().size() == expected, "real signature size differs from preflight");
    Check(expected <= Mempool::MAX_RELAY_TX_BYTES, "signed transaction exceeds relay cap");
    Check(chain.ValidateTransactionLocking(tx, false), "real ML-DSA signatures rejected");
    Check(pool.Add(tx, MIN_TX_FEE, 4601, chain) == Mempool::AddResult::ACCEPTED,
          "post-activation mempool admission failed");
}
}

int main(int argc, char** argv) {
    try {
        Check(argc == 2, "fresh isolated storage path required");
        Blockchain chain;
        Check(chain.AddBlockDirect(CreateGenesisBlock(), true, true, false,
            mining::PowAdmissionContext::Internal()).IsAccepted(), "fixture genesis");
        Mempool pool;
        StorageEngine storage(argv[1], MAINNET_MAGIC);
        RpcServer rpc(chain, pool, storage);
        StakingLedger staking;
        staking.SetStakingActivationUnits(0);
        staking.SetMinStakeUnits(500 * VELD_UNITS);
        rpc.SetStaking(&staking);
        const auto key = GenerateKeyPair(false);
        for (uint32_t i = 0; i < 319; ++i) {
            UTXO coin;
            coin.tx_hash = Hash256d(std::vector<uint8_t>{0x79, uint8_t(i), uint8_t(i >> 8)});
            coin.output_index = 0;
            coin.value = 157 * VELD_UNITS / 100;
            coin.script_pubkey = key.GetP2PKHScript();
            coin.block_height = 0;
            coin.is_coinbase = false;
            chain.TestInjectUTXO(coin);
        }
        const auto before = rpc.ComputeWalletState(key.address);
        const auto rejected = Call(rpc, "preparestake", {key.address, "500", "1"});
        const auto* error = rejected.Get("error");
        Check(error && error->Get("message") &&
              error->Get("message")->text.find("Combine my outputs") != std::string::npos,
              "fragmented stake needs actionable pre-sign rejection");
        Check(rpc.ComputeWalletState(key.address).spendable_units == before.spendable_units &&
              pool.GetPendingStakeUnits(key.address) == 0,
              "rejected preparation changed funds or reservations");

        // Model two confirmed cleanup batches using disposable in-memory coins.
        for (int batch = 0; batch < 2; ++batch) {
            auto cleanup = Prepared(Call(rpc, "prepareconsolidatetx", {key.address, "150", "10"}));
            Check(cleanup.inputs.size() == 150 && cleanup.outputs.size() == 1, "cleanup shape");
            SignAndAdmit(cleanup, key, chain, pool);
            pool.Remove(HashToHex(cleanup.GetTxID()));
            for (const auto& input : cleanup.inputs)
                Check(chain.TestEraseUTXO(input.prev_tx_hash, input.prev_out_index), "cleanup spend");
            UTXO combined;
            combined.tx_hash = cleanup.GetTxID();
            combined.output_index = 0;
            combined.value = cleanup.outputs[0].value;
            combined.script_pubkey = key.GetP2PKHScript();
            combined.block_height = 0;
            combined.is_coinbase = false;
            chain.TestInjectUTXO(combined);
        }
        auto stake = Prepared(Call(rpc, "preparestake", {key.address, "500", "1"}));
        Check(stake.inputs.size() == 21, "cleanup did not reduce stake to 21 inputs");
        Check(stake.outputs[0].value == 500 * VELD_UNITS &&
              stake.outputs[0].script_pubkey == key.GetP2PKHScript(), "stake principal changed");
        SignAndAdmit(stake, key, chain, pool);
        Check(pool.GetPendingStakeUnits(key.address) == 500 * VELD_UNITS, "stake not admitted");
        const auto after = rpc.ComputeWalletState(key.address);
        Check(before.total_units - after.total_units == 2 * MIN_TX_FEE, "cleanup fee accounting");
        std::cout << "PASS checks=" << checks << " original_inputs=319 cleanup_batches=2"
                  << " stake_inputs=" << stake.inputs.size()
                  << " signed_stake_bytes=" << stake.Serialize().size() << '\n';
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
