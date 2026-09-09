// Differential transcript against the preserved source; no chain or network I/O.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_PROTOCOL_UPGRADE_TEST_HEIGHT 3360
#include "core/blockchain.h"
#include <iostream>

using namespace veld;
int main() {
    const auto owner=GenerateKeyPair(true);
    Blockchain chain;
    const uint64_t r=BLOCK_REWARD_UNITS;
    size_t rows=0;
    for (uint64_t h : {1ULL,99ULL,100ULL,479ULL,480ULL,2879ULL,2880ULL,
                       2881ULL,3299ULL,3300ULL,3359ULL,3360ULL,3361ULL,
                       3399ULL,3400ULL,3839ULL,3840ULL}) {
        for (uint64_t supply : {STAKING_UNLOCK_SUPPLY-1,STAKING_UNLOCK_SUPPLY,
                MAX_SUPPLY_UNITS-3*r,MAX_SUPPLY_UNITS-17,MAX_SUPPLY_UNITS-1,MAX_SUPPLY_UNITS}) {
            for (uint64_t fee : {uint64_t(0),uint64_t(1),uint64_t(9),uint64_t(10),
                    MIN_TX_FEE,5*r,6*r-1,6*r,6*r+1,30*r-1,30*r,30*r+1}) {
                chain.SetTotalSupplyForTesting(supply);
                UTXO input;
                input.tx_hash=Hash256d("compatibility-transcript");
                input.value=fee+VELD_UNITS;
                input.script_pubkey=owner.GetP2PKHScript();
                chain.TestInjectUTXO(input);
                const uint64_t reward=std::min(Blockchain::ExpectedBlockSubsidy(h),MAX_SUPPLY_UNITS-supply);
                uint64_t miner=0,pool=0,vault=0,endorse=0;
                if (!reward) {vault=fee*4/10;endorse=fee/10;miner=fee-vault-endorse;}
                else if (h%100==0) vault=reward+fee;
                else if (supply<STAKING_UNLOCK_SUPPLY) {miner=reward/2;vault=reward-miner+fee;}
                else {pool=reward/5;vault=reward/5+fee;endorse=reward/10;miner=reward-pool-(vault-fee)-endorse;}
                Block original;original.height=h;
                original.transactions.push_back(Transaction::CreateProportionalCoinbase({
                    {owner.GetP2PKHScript(),miner},{AddressToScript(PoolAddressAtHeight(h)),pool},
                    {AddressToScript(VaultAddressAtHeight(h)),vault},
                    {AddressToScript(EndorsementPoolAddressAtHeight(h)),endorse}},"compatibility"));
                if (fee) {
                    Transaction tx;TxInput in;in.prev_tx_hash=input.tx_hash;tx.inputs.push_back(in);
                    tx.outputs.emplace_back(VELD_UNITS,input.script_pubkey);
                    tx.inputs[0].script_sig=owner.SignInput(tx,0,input.script_pubkey).script_sig;
                    original.transactions.push_back(tx);
                }
                for (unsigned variant=0;variant<5;++variant) {
                    Block b=original;
                    auto& outputs=b.transactions[0].outputs;
                    if (variant==1) ++outputs[0].value;
                    if (variant==2) outputs.clear();
                    if (variant==3) outputs.emplace_back(0,owner.GetP2PKHScript());
                    if (variant==4) outputs[0].value=UINT64_MAX;
                    const bool shape=chain.ValidateCoinbaseOutputs(b);
                    const bool exact=chain.ValidateCanonicalCoinbaseSplit(b);
#ifdef VELD_COINBASE_LEGACY_POLICY_CONTROL
                    const bool direct=shape && exact && chain.ValidateMinerCaps(b);
                    const bool replay=shape && exact;
#else
                    const bool direct=chain.ValidateCoinbasePolicy(b);
                    const bool replay=chain.ValidateCoinbasePolicy(b,Blockchain::CoinbaseAdmissionPath::Replay);
#endif
                    std::cout << h << ',' << supply << ',' << fee << ',' << variant << ','
                              << shape << ',' << exact << ',' << direct << ',' << replay << '\n';
                    ++rows;
                }
            }
        }
    }
    std::cerr << "TRANSCRIPT rows=" << rows << " private_activation=3360\n";
}
