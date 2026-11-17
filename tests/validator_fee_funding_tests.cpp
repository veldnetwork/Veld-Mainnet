#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_TEST_STAKE_OUTPOINT_BACKING 1
#include "network/rpc.h"

#include <filesystem>
#include <iostream>
#include <stdexcept>

using namespace veld;

int main(int argc, char** argv) {
    unsigned checks = 0;
    const auto check = [&](bool value, const char* message) {
        ++checks;
        if (!value)
            throw std::runtime_error(message);
    };
    try {
        check(argc == 2 && !std::filesystem::exists(argv[1]), "fresh fixture path required");
        Blockchain chain;
        check(chain
                  .AddBlockDirect(CreateGenesisBlock(), true, true, false,
                                  mining::PowAdmissionContext::Internal())
                  .IsAccepted(),
              "fixture genesis");
        Mempool pool;
        StorageEngine storage(argv[1], MAINNET_MAGIC);
        RpcServer rpc(chain, pool, storage);
        StakingLedger staking;
        rpc.SetStaking(&staking);
        const auto owner = GenerateKeyPair(false);
        Block block;
        block.height = 1;
        block.header.version = PROTOCOL_VERSION;
        block.header.prev_block_hash = chain.TipCopy().GetHash();
        block.header.timestamp = chain.TipCopy().header.timestamp + TARGET_BLOCK_TIME;
        block.header.bits = chain.ComputeNextBits();
        block.transactions.push_back(Blockchain::BuildCanonicalCoinbase(1, chain.TotalSupplyUnits(),
                                                                        0, owner.GetP2PKHScript()));
        block.UpdateMerkleRoot();
        check(
            chain.AddBlockDirect(block, true, true, false, mining::PowAdmissionContext::Internal())
                .IsAccepted(),
            "fixture first block");
        auto coin = [&](uint8_t id, uint64_t amount) {
            UTXO output;
            output.tx_hash.fill(id);
            output.output_index = 0;
            output.value = amount;
            output.script_pubkey = owner.GetP2PKHScript();
            output.block_height = 0;
            output.is_coinbase = false;
            chain.TestInjectUTXO(output);
            return output;
        };
        const auto backing = coin(1, 1000 * VELD_UNITS);
        const auto available = coin(2, 149 * VELD_UNITS);
        StakingLedger::StateSnapshot snapshot;
        snapshot.stakes[owner.address].push_back(
            StakeRecord{owner.address, backing.value, 0, 10000, true, 1, backing.tx_hash, 0});
        snapshot.total_stake = backing.value;
        staking.RestoreState(snapshot);
        chain.SetStakeBlockValidatorFn(
            [&](const Block& candidate) { return staking.ValidateBlock(candidate); });
        const auto stake_digest = staking.StakingDigest();
        const auto raw = SelectCoins(chain, owner.GetP2PKHScript(), 0, MIN_TX_FEE);
        check(raw.sufficient && raw.selected_utxos.front().tx_hash == backing.tx_hash,
              "regression did not reproduce raw selection of locked principal");
        const auto selected = rpc.SelectSpendableCoins(owner.address, 0, MIN_TX_FEE);
        check(rpc.ComputeWalletState(owner.address).immature_coinbase_units > 0,
              "immature coinbase fixture missing");
        check(selected.sufficient && selected.selected_utxos.size() == 1 &&
                  selected.selected_utxos.front().tx_hash == available.tx_hash,
              "automatic fee funding must select free balance instead of the larger stake");
        check(selected.total_input == available.value &&
                  selected.change_amount + MIN_TX_FEE == available.value,
              "fee and change accounting changed");
        check(!rpc.SelectSpendableCoins(owner.address, available.value, MIN_TX_FEE).sufficient,
              "selection borrowed locked principal");
        check(!rpc.SelectSpendableCoins(owner.address, UINT64_MAX, MIN_TX_FEE).sufficient,
              "overflow admitted");
        check(!rpc.SelectSpendableCoins("invalid", 0, MIN_TX_FEE).sufficient,
              "invalid address selected funding");

        // Real signatures and normal mempool admission exercise the selected
        // inputs. The marker is deliberately ordinary metadata: validator
        // work-admission and anti-equivocation are covered separately.
        Transaction fee;
        TxInput input;
        input.prev_tx_hash = selected.selected_utxos.front().tx_hash;
        input.prev_out_index = 0;
        fee.inputs.push_back(input);
        fee.outputs.emplace_back(selected.change_amount, owner.GetP2PKHScript());
        fee.outputs.emplace_back(0, BuildOpReturnScript("validator funding regression"));
        fee.inputs[0].script_sig = owner.SignInput(fee, 0, owner.GetP2PKHScript()).script_sig;
        check(chain.ValidateTransactionLocking(fee, false), "funding signature failed");
        Transaction locked = fee;
        locked.inputs[0].prev_tx_hash = backing.tx_hash;
        locked.outputs[0].value = backing.value - MIN_TX_FEE;
        locked.inputs[0].script_sig.clear();
        locked.inputs[0].script_sig = owner.SignInput(locked, 0, owner.GetP2PKHScript()).script_sig;
        locked.InvalidateTxIDCache();
        check(!chain.StakeTransactionValid(locked, 2), "old selection spent locked principal");
        check(pool.Add(locked, MIN_TX_FEE, 1, chain) != Mempool::AddResult::ACCEPTED,
              "old fee funding was not rejected by normal admission");
        const auto admitted = pool.Add(fee, MIN_TX_FEE, 1, chain);
        if (admitted != Mempool::AddResult::ACCEPTED)
            std::cerr << "Funding admission: " << Mempool::ResultToString(admitted) << '\n';
        check(admitted == Mempool::AddResult::ACCEPTED, "spendable fee transaction rejected");
        check(!rpc.SelectSpendableCoins(owner.address, 0, MIN_TX_FEE).sufficient,
              "pending spend reused its input or spent the stake");
        pool.Remove(HashToHex(fee.GetTxID()));
        check(rpc.SelectSpendableCoins(owner.address, 0, MIN_TX_FEE).sufficient,
              "released pending input stayed unavailable");
        check(chain.TestEraseUTXO(available.tx_hash, 0), "remove available fixture coin");
        check(!rpc.SelectSpendableCoins(owner.address, 0, MIN_TX_FEE).sufficient,
              "stake-only wallet funded a fee");
        coin(3, MIN_TX_FEE);
        const auto exact = rpc.SelectSpendableCoins(owner.address, 0, MIN_TX_FEE);
        check(exact.sufficient && exact.change_amount == 0, "exact fee coin rejected");
        check(chain.TestEraseUTXO(backing.tx_hash, 0), "remove fixture backing");
        bool refused = false;
        try {
            (void)rpc.SelectSpendableCoins(owner.address, 0, MIN_TX_FEE);
        } catch (const std::exception&) {
            refused = true;
        }
        check(refused, "inconsistent backing must fail closed");
        check(staking.StakingDigest() == stake_digest, "selection changed stake state");
        std::cout << "PASS validator_fee_funding_tests checks=" << checks
                  << " disposable_keys=true public_transactions=0 network=0\n";
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
