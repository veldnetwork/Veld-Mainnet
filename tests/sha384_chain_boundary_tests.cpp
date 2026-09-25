// Disposable state and accelerated height ONLY. PoW is skipped explicitly;
// this tests native transaction, block, mempool and rollback integration.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_SHA384_DESTINATION_TEST_HEIGHT 3
#include "core/blockchain.h"
#include "core/mempool.h"
#include "wallet/wallet.h"
#include <iostream>
#include <stdexcept>

int main() {
    using namespace veld;
    unsigned checks = 0;
    auto check = [&](bool value, const char* label) {
        ++checks;
        if (!value)
            throw std::runtime_error(label);
    };
    try {
        Blockchain chain;
        const auto genesis = CreateGenesisBlock();
        check(
            chain
                .AddBlockDirect(genesis, true, true, false, mining::PowAdmissionContext::Internal())
                .IsAccepted(),
            "genesis");
        auto owner = GenerateKeyPair(), recipient = GenerateKeyPair(), miner = GenerateKeyPair();
        owner.address = Sha384KeyAddress(owner.public_key);
        UTXO funding;
        funding.tx_hash.fill(77);
        funding.output_index = 0;
        funding.value = 20 * VELD_UNITS;
        funding.script_pubkey = owner.GetP2PKHScript();
        funding.block_height = 0;
        funding.is_coinbase = false;
        chain.TestInjectUTXO(funding);
        Transaction tx;
        TxInput input;
        input.prev_tx_hash = funding.tx_hash;
        input.prev_out_index = 0;
        tx.inputs.push_back(input);
        tx.outputs.emplace_back(funding.value - MIN_TX_FEE, recipient.GetP2PKHScript());
        tx.inputs[0].script_sig = owner.SignInput(tx, 0, funding.script_pubkey).script_sig;
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
                .AddBlockDirect(block, false, false, true, mining::PowAdmissionContext::Internal())
                .IsAccepted();
        };
        bool permanent = false;
        check(!chain.ValidateTransactionLocking(tx, false, &permanent) && !permanent,
              "pre-activation refusal must be contextual");
        const auto b1 = candidate({}, 1);
        check(add(b1), "height 1");
        Mempool mempool;
        check(mempool.Add(tx, MIN_TX_FEE, chain.Height(), chain) != Mempool::AddResult::ACCEPTED,
              "mempool below activation");
        const auto invalid = candidate({tx}, 2);
        check(!add(invalid), "block below activation");
        check(chain.Height() == 1 && chain.GetBalance(funding.script_pubkey) == funding.value,
              "failed block atomicity");
        auto b2 = candidate({}, 3);
        check(add(b2), "height 2");
        check(chain.ValidateTransactionLocking(tx), "next block activates spending");
        check(mempool.Add(tx, MIN_TX_FEE, chain.Height(), chain) == Mempool::AddResult::ACCEPTED,
              "mempool at activation");
        check(chain.ValidateCachedMempoolLockingContext(tx), "cached entry at activation");
        check(chain.RollbackTip(), "rollback across next-height admission");
        check(!chain.ValidateCachedMempoolLockingContext(tx),
              "cached signature must not bypass activation after rollback");
        check(!chain.ValidateTransactionLocking(tx), "rollback restores pre-activation validation");
        b2 = candidate({}, 33);
        check(add(b2), "connect alternative parent");
        auto b3 = candidate({tx}, 4);
        check(add(b3), "funded signed spend at activation");
        check(chain.GetBalance(funding.script_pubkey) == 0, "input spent exactly once");
        check(chain.GetBalance(recipient.GetP2PKHScript()) == funding.value - MIN_TX_FEE,
              "recipient exact balance");
        check(!chain.ValidateTransactionLocking(tx), "confirmed double spend rejected");
        check(chain.RollbackTip(), "disconnect activated spend");
        check(chain.GetBalance(funding.script_pubkey) == funding.value &&
                  chain.GetBalance(recipient.GetP2PKHScript()) == 0,
              "rollback exact accounting");
        check(chain.ValidateTransactionLocking(tx), "disconnected spend valid again");
        b3 = candidate({tx}, 5);
        check(add(b3), "alternate block inclusion");
        Blockchain replay;
        check(
            replay
                .AddBlockDirect(genesis, true, true, false, mining::PowAdmissionContext::Internal())
                .IsAccepted(),
            "replay genesis");
        replay.TestInjectUTXO(funding);
        for (const auto& block : {b1, b2, b3})
            check(replay
                      .AddBlockDirect(block, false, false, true,
                                      mining::PowAdmissionContext::Internal())
                      .IsAccepted(),
                  "historical replay");
        check(replay.TipCopy().GetHash() == chain.TipCopy().GetHash() &&
                  replay.GetBalance(recipient.GetP2PKHScript()) ==
                      chain.GetBalance(recipient.GetP2PKHScript()),
              "replay exact tip and recipient balance");
        std::cout
            << "PASS " << checks
            << " native funded/mempool/rollback/replay checks; synthetic funding and accelerated height; PoW skipped; no network\n";
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << checks << " " << error.what() << '\n';
        return 1;
    }
}
