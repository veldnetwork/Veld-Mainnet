#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#include "network/rpc.h"
#include <cassert>
#include <iostream>
#include <future>

// Direct dispatcher controls on a one-block in-memory chain. No listener,
// traffic generation, transaction signing or broadcast.
int main(int argc, char** argv) {
    using namespace veld;
    assert(argc == 2);
    Blockchain chain;
    const auto genesis = CreateGenesisBlock();
    assert(chain.AddBlockDirect(genesis, true, true, false,
        mining::PowAdmissionContext::Internal()).IsAccepted());
    const auto body_size = genesis.SerializedSize();
    assert(chain.GetBlock(0, body_size).GetHash() == genesis.GetHash());
    bool display_limited = false;
    try { (void)chain.GetBlockByHash(genesis.GetHash(), body_size - 1); }
    catch (const std::length_error&) { display_limited = true; }
    assert(display_limited);
    Mempool mempool;
    StorageEngine storage(argv[1], MAINNET_MAGIC);
    RpcServer rpc(chain, mempool, storage);
    const auto txid = HashToHex(genesis.transactions.at(0).GetTxID());
    auto call = [&](const char* method, const std::string& id) {
        return rpc.Handle(std::string("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"") +
            method + "\",\"params\":[\"" + id + "\"]}");
    };
    assert(call("gettransactionrecent", txid).find("\"block_height\":0") != std::string::npos);
    assert(call("getrawtransaction", txid).find("\"raw_hex\"") != std::string::npos);
    size_t lookups = 0;
    rpc.SetTxIndexLookupFn([&](const std::string& id, uint64_t tip, const std::string& hash) {
        ++lookups;
        assert(tip == 0 && hash == HashToHex(genesis.GetHash()));
        return RpcServer::TxIndexLookup{true, id == txid ? std::optional<uint64_t>(0) : std::nullopt};
    });
    assert(call("gettransactionrecent", txid).find("\"block_height\":0") != std::string::npos);
    assert(call("getrawtransaction", txid).find("\"raw_hex\"") != std::string::npos);
    const auto absent = HashToHex(ZeroHash());
    assert(call("getrawtransaction", absent).find("-32602") != std::string::npos);
    assert(lookups == 3);
    rpc.SetTxIndexLookupFn([](const auto&, uint64_t, const auto&) -> RpcServer::TxIndexLookup {
        throw std::runtime_error("fixture index temporarily unavailable");
    });
    assert(call("gettransactionrecent", txid).find("-32005") != std::string::npos);
    StakingLedger staking;
    staking.SetStakingActivationUnits(0);
    staking.SetMinStakeUnits(1);
    rpc.SetStaking(&staking);
    std::vector<uint8_t> script{0x76, 0xa9, 0x14};
    script.insert(script.end(), 20, 0x19);
    script.insert(script.end(), {0x88, 0xac});
    const auto address = ScriptToAddress(script);
    UTXO spendable;
    spendable.tx_hash.fill(0x12);
    spendable.output_index = 0;
    spendable.value = 10 * VELD_UNITS;
    spendable.script_pubkey = script;
    spendable.block_height = 0;
    spendable.is_coinbase = false;
    chain.TestInjectUTXO(spendable);
    UTXO principal = spendable;
    principal.tx_hash.fill(0x34);
    principal.value = 2 * VELD_UNITS;
    chain.TestInjectUTXO(principal);
    StakeRecord record;
    record.address = address;
    record.amount_units = principal.value;
    record.locked_at_height = 0;
    record.unlock_height = 0;
    record.backing_txid = principal.tx_hash;
    record.backing_vout = 0;
    StakingLedger::StateSnapshot stake_state;
    stake_state.stakes[address].push_back(record);
    stake_state.total_stake = record.amount_units;
    staking.RestoreState(stake_state);
    const auto digest = staking.StakingDigest();
    auto prepare = [&](const char* method) {
        return rpc.Handle(std::string("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"") +
            method + "\",\"params\":[\"" + address + "\",\"1\"]}");
    };
    const auto first_stake = prepare("preparestake");
    assert(first_stake.find("\"unsigned_tx_hex\"") != std::string::npos);
    assert(prepare("preparestake") == first_stake);
    auto pending_unstake = std::async(std::launch::async, [&] { return prepare("prepareunstake"); });
    const auto unstake = prepare("prepareunstake");
    assert(unstake.find("\"unsigned_tx_hex\"") != std::string::npos);
    assert(pending_unstake.get() == unstake);
    assert(staking.StakingDigest() == digest);
    assert(mempool.GetPendingStakeUnits(address) == 0);
    assert(chain.GetUTXO(principal.tx_hash, 0)->value == principal.value);
    std::cout << "PASS: direct RPC lookup and unchanged unsigned stake/unstake state\n";
}
