#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#include "network/rpc.h"

#include <atomic>
#include <iostream>
#include <stdexcept>
#include <thread>

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
Transaction Prepare(RpcServer& rpc, const RealKeyPair& owner,
                    const std::string& recipient, const std::string& amount) {
    const auto response = Call(rpc, "preparerawtransaction", {owner.address, recipient, amount});
    const auto* result = response.Get("result");
    Check(result && result->Get("unsigned_tx_hex"), "prepared transaction missing");
    const auto raw = HexToBytes(result->Get("unsigned_tx_hex")->text);
    Transaction tx;
    Check(Transaction::Deserialize(raw, 0, tx) == raw.size(), "prepared transaction decode");
    std::vector<std::vector<uint8_t>> signatures;
    for (uint32_t i = 0; i < tx.inputs.size(); ++i)
        signatures.push_back(owner.SignInput(tx, i, owner.GetP2PKHScript()).script_sig);
    for (size_t i = 0; i < signatures.size(); ++i) tx.inputs[i].script_sig = signatures[i];
    tx.InvalidateTxIDCache();
    return tx;
}
bool Failed(const btc_buy::JsonValue& response) {
    const auto* error = response.Get("error");
    return error && error->kind == btc_buy::JsonValue::Kind::Object && error->Get("message");
}
void Accepted(RpcServer& rpc, const Transaction& tx) {
    const auto response = Call(rpc, "sendrawtransaction", {BytesToHex(tx.Serialize())});
    if (const auto* error = response.Get("error"))
        if (const auto* message = error->Get("message")) std::cerr << message->text << '\n';
    Check(!Failed(response) && response.Get("result") &&
          response.Get("result")->text == HashToHex(tx.GetTxID()), "signed RPC broadcast refused");
}
Block Candidate(Blockchain& chain, const RealKeyPair& miner,
                const std::vector<Transaction>& transactions, uint64_t nonce) {
    Block block;
    block.height = chain.Height() + 1;
    block.header.version = PROTOCOL_VERSION;
    block.header.prev_block_hash = chain.TipCopy().GetHash();
    block.header.timestamp = chain.TipCopy().header.timestamp + 1;
    block.header.bits = chain.ComputeNextBits();
    block.header.nonce = nonce;
    block.transactions.push_back(Blockchain::BuildCanonicalCoinbase(block.height,
        chain.TotalSupplyUnits(), transactions.size() * MIN_TX_FEE, miner.GetP2PKHScript()));
    for (const auto& tx : transactions) block.transactions.push_back(tx);
    block.UpdateMerkleRoot();
    return block;
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
        rpc.SetStaking(&staking);
        const auto owner = GenerateKeyPair(false), recipient = GenerateKeyPair(false);
        for (uint8_t i = 1; i <= 3; ++i) {
            UTXO coin;
            coin.tx_hash.fill(i);
            coin.output_index = 0;
            coin.value = i * 100 * VELD_UNITS;
            coin.script_pubkey = owner.GetP2PKHScript();
            coin.block_height = 0;
            coin.is_coinbase = false;
            chain.TestInjectUTXO(coin);
        }
        const auto initial = rpc.ComputeWalletState(owner.address);
        Check(initial.spendable_units == 600 * VELD_UNITS, "initial spendable balance");
        const auto first = Prepare(rpc, owner, recipient.address, "50");
        const auto conflict = Prepare(rpc, owner, recipient.address, "60");
        Check(first.inputs[0].prev_tx_hash == conflict.inputs[0].prev_tx_hash,
              "simultaneous preparations must share the same initial funding");
        Accepted(rpc, first);
        const auto after_first = rpc.ComputeWalletState(owner.address);
        Check(after_first.spendable_units == 300 * VELD_UNITS &&
              after_first.pending_out_units == 300 * VELD_UNITS &&
              after_first.total_units == initial.total_units,
              "accepted send must immediately reserve its entire confirmed input");
        const auto balance = Call(rpc, "getbalance", {owner.address});
        Check(balance.Get("result") && balance.Get("result")->Get("spendable_veld") &&
              balance.Get("result")->Get("spendable_veld")->text == "300.00000000",
              "public balance RPC must reflect the pending reservation");
        const auto rejected = Call(rpc, "sendrawtransaction", {BytesToHex(conflict.Serialize())});
        Check(Failed(rejected), "second signed spend of pending input must fail");
        Check(pool.Add(first, MIN_TX_FEE, chain.Height(), chain) == Mempool::AddResult::DUPLICATE,
              "identical rebroadcast must not create a second spend");
        const auto second = Prepare(rpc, owner, recipient.address, "75");
        Check(first.inputs[0].prev_tx_hash != second.inputs[0].prev_tx_hash,
              "subsequent preparation reused a reserved input");
        Accepted(rpc, second);
        Check(rpc.ComputeWalletState(owner.address).spendable_units == 100 * VELD_UNITS,
              "second accepted send must update spendable balance again");
        Check(Failed(Call(rpc, "preparerawtransaction", {owner.address, recipient.address, "100"})),
              "unconfirmed change must not be offered as spendable funding");
        const auto third = Prepare(rpc, owner, recipient.address, "10");
        const auto racing = Prepare(rpc, owner, recipient.address, "20");
        std::atomic<unsigned> ready{0};
        Mempool::AddResult results[2];
        auto admit = [&](size_t i, const Transaction& tx) {
            ready.fetch_add(1);
            while (ready.load() != 2) std::this_thread::yield();
            results[i] = pool.Add(tx, MIN_TX_FEE, chain.Height(), chain);
        };
        std::thread a(admit, 0, std::cref(third)), b(admit, 1, std::cref(racing));
        a.join(); b.join();
        Check((results[0] == Mempool::AddResult::ACCEPTED) !=
              (results[1] == Mempool::AddResult::ACCEPTED), "racing spends admitted twice");
        Check(results[0] == Mempool::AddResult::DOUBLE_SPEND ||
              results[1] == Mempool::AddResult::DOUBLE_SPEND, "race did not reject conflicting input");
        Check(rpc.ComputeWalletState(owner.address).spendable_units == 0, "pending sends leave no spendable inputs");
        const auto tip_before = chain.TipCopy().GetHash();
        for (unsigned mode = 0; mode < 2; ++mode) {
            const auto block = Candidate(chain, recipient, {first, conflict}, 100 + mode);
            Check(!chain.AddBlockDirect(block, true, bool(mode), false,
                mining::PowAdmissionContext::Internal()).IsAccepted(), "block included conflicting spends");
            Check(Blockchain::GetLastRejectTag() == "intra_block_double_spend",
                  "conflicting block must reach the duplicate-input guard");
            Check(chain.TipCopy().GetHash() == tip_before &&
                  rpc.ComputeWalletState(owner.address).total_units == initial.total_units,
                  "rejected conflicting block changed canonical funds");
        }
        Transaction duplicate = first;
        duplicate.inputs.push_back(duplicate.inputs.front());
        duplicate.InvalidateTxIDCache();
        Check(!chain.ValidateTransactionLocking(duplicate, false), "duplicate inputs validated");
        Check(pool.Add(duplicate, MIN_TX_FEE, chain.Height(), chain) != Mempool::AddResult::ACCEPTED,
              "duplicate-input transaction admitted");
        pool.Remove(HashToHex(first.GetTxID()));
        Check(rpc.ComputeWalletState(owner.address).spendable_units == 300 * VELD_UNITS,
              "removed pending transaction did not release its input");
        Accepted(rpc, first);
        const auto block = Candidate(chain, recipient, {first}, 200);
        Check(chain.AddBlockDirect(block, true, true, false,
            mining::PowAdmissionContext::Internal()).IsAccepted(), "valid confirmation failed");
        pool.Remove(HashToHex(first.GetTxID()));
        Check(!chain.ValidateTransactionLocking(conflict, false), "confirmed input can be spent again");
        Check(Failed(Call(rpc, "sendrawtransaction", {BytesToHex(conflict.Serialize())})),
              "RPC admitted a spend of an already-confirmed input");
        const auto confirmed = rpc.ComputeWalletState(owner.address);
        Check(confirmed.total_units == initial.total_units - 50 * VELD_UNITS - MIN_TX_FEE,
              "confirmed balance does not deduct sent amount plus fee");
        Check(confirmed.spendable_units == 250 * VELD_UNITS - MIN_TX_FEE,
              "confirmed change did not become spendable exactly once");
        std::cout << "PASS checks=" << checks << " real_signatures=true live_broadcasts=0\n";
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
