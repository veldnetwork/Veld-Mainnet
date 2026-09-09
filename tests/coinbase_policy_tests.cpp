// In-memory monetary-policy fixtures. No listeners, peer traffic or wallet files.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_PROTOCOL_UPGRADE_TEST_HEIGHT 3360
#define VELD_TEST_BRANCH_CONTEXT 1
#include "node/node.h"
#include <iostream>
#include <stdexcept>

using namespace veld;
namespace {
size_t checks=0, cases=0, disagreement=0, boundary_conflicts=0;
void Require(bool ok,const char* message) {
    ++checks;
    if(!ok) throw std::runtime_error(message);
}
struct Amounts {uint64_t miner=0,pool=0,vault=0,endorse=0;};
Amounts Oracle(uint64_t height,uint64_t supply,uint64_t fees) {
    const uint64_t reward=std::min(Blockchain::ExpectedBlockSubsidy(height),MAX_SUPPLY_UNITS-supply);
    Amounts out;
    if(!reward) {out.vault=fees*4/10;out.endorse=fees/10;out.miner=fees-out.vault-out.endorse;}
    else if(height%VAULT_BLOCK_INTERVAL==0)out.vault=reward+fees;
    else if(supply<STAKING_UNLOCK_SUPPLY){out.miner=reward/2;out.vault=reward-out.miner+fees;}
    else {out.pool=reward/5;out.vault=reward/5+fees;out.endorse=reward/10;out.miner=reward-out.pool-(out.vault-fees)-out.endorse;}
    return out;
}
Transaction OracleCoinbase(uint64_t h,uint64_t supply,uint64_t fee,const RealKeyPair& owner) {
    const auto a=Oracle(h,supply,fee);
    return Transaction::CreateProportionalCoinbase({{owner.GetP2PKHScript(),a.miner},
        {AddressToScript(PoolAddressAtHeight(h)),a.pool},{AddressToScript(VaultAddressAtHeight(h)),a.vault},
        {AddressToScript(EndorsementPoolAddressAtHeight(h)),a.endorse}},"Veld block "+std::to_string(h));
}
}
int main() {
    try {
        const auto owner=GenerateKeyPair(true);
        Blockchain chain;
        const uint64_t r=BLOCK_REWARD_UNITS;
        const std::vector<uint64_t> fees={0,1,2,3,9,10,99,100,MIN_TX_FEE,5*r,6*r-1,6*r,6*r+1,30*r,30*r+1};
        const std::vector<uint64_t> heights={3359,3360,3361,3400,3840,4800,BLOCKS_PER_YEAR};
        const std::vector<uint64_t> supplies={STAKING_UNLOCK_SUPPLY-1,STAKING_UNLOCK_SUPPLY,
            MAX_SUPPLY_UNITS-3*r,MAX_SUPPLY_UNITS-17,MAX_SUPPLY_UNITS-1,MAX_SUPPLY_UNITS};
        for(auto height:heights) for(auto supply:supplies) for(auto fee:fees) {
            ++cases;
            chain.SetTotalSupplyForTesting(supply);
            UTXO input;input.tx_hash=Hash256d("coinbase-policy-fixture");
            input.value=fee+1000000;input.script_pubkey=owner.GetP2PKHScript();input.block_height=0;
            chain.TestInjectUTXO(input);
            Block block;block.height=height;
            block.transactions.push_back(OracleCoinbase(height,supply,fee,owner));
            if(fee) {
                Transaction tx;TxInput in;in.prev_tx_hash=input.tx_hash;in.prev_out_index=0;tx.inputs.push_back(in);
                tx.outputs.emplace_back(1000000,input.script_pubkey);
                tx.inputs[0].script_sig=owner.SignInput(tx,0,input.script_pubkey).script_sig;
                block.transactions.push_back(tx);
            }
            Require(block.transactions[0].IsValid(),"canonical coinbase representation invalid");
            Require(chain.ValidateCanonicalCoinbaseSplit(block),"independent canonical split rejected");
            const bool shape=chain.ValidateCoinbaseOutputs(block);
#ifdef VELD_COINBASE_LEGACY_POLICY_CONTROL
            const bool caps=chain.ValidateMinerCaps(block);
            if(!caps)++disagreement;
            if(!shape)++boundary_conflicts;
#else
            const bool active=ProtocolUpgradeActive(height);
            const bool caps=chain.ValidateLegacyMinerCaps(block);
            const bool direct=chain.ValidateCoinbasePolicy(block,Blockchain::CoinbaseAdmissionPath::Direct);
            const bool replay=chain.ValidateCoinbasePolicy(block,Blockchain::CoinbaseAdmissionPath::Replay);
            if(active) {
                Require(shape && direct && replay,"upgraded paths disagree on canonical coinbase");
                const auto built=Blockchain::BuildCanonicalCoinbase(height,supply,fee,owner.GetP2PKHScript());
                Require(built.Serialize()==block.transactions[0].Serialize(),"production builder differs from independent oracle");
                const auto metadata=BuildOpReturnScript("VELD_FINALITY|coinbase-shape-fixture");
                auto annotated=block;
                annotated.transactions[0]=Blockchain::BuildCanonicalCoinbase(
                    height,supply,fee,owner.GetP2PKHScript(),{metadata});
                Require(chain.ValidateCoinbasePolicy(annotated),"canonical metadata representation refused");
                Require(chain.ValidateCoinbasePolicy(annotated,Blockchain::CoinbaseAdmissionPath::Replay),"metadata replay differs");
                if(!built.TotalOutput()) {
                    Require(annotated.transactions[0].outputs.size()==1,"zero-value metadata mixed with empty marker");
                    annotated.transactions[0].outputs.emplace_back(0,std::vector<uint8_t>{0x6a,0});
                    Require(!chain.ValidateCoinbasePolicy(annotated),"mixed zero-value representation accepted");
                }
                annotated.transactions[0]=built;
                for(size_t i=0;i<=MAX_FINALITY_MARKER_OUTPUTS;++i)
                    annotated.transactions[0].outputs.emplace_back(0,metadata);
                Require(!chain.ValidateCoinbasePolicy(annotated),"excess metadata outputs accepted");
            } else {
                Require(direct==(shape && caps),"historical direct policy changed");
                Require(replay==shape,"historical replay policy changed");
            }
            const auto reject=[&](Block bad) {
                Require(!chain.ValidateCoinbasePolicy(bad),"malformed direct coinbase accepted");
                Require(!chain.ValidateCoinbasePolicy(bad,Blockchain::CoinbaseAdmissionPath::Replay),"malformed replay coinbase accepted");
            };
            auto bad=block;bad.transactions[0].outputs[0].value++;reject(bad);
            bad=block;bad.transactions[0].outputs.clear();reject(bad);
            bad=block;bad.transactions[0].outputs[0].value=UINT64_MAX;reject(bad);
            bad=block;bad.transactions[0].outputs.emplace_back(0,owner.GetP2PKHScript());reject(bad);
            bad=block;
            for(auto& out:bad.transactions[0].outputs) {
                if(out.value>1) {
                    auto other=out;other.value=1;--out.value;
                    bad.transactions[0].outputs.push_back(other);reject(bad);break;
                }
            }
            if(block.transactions[0].outputs.size()>1) {
                bad=block;auto& out=bad.transactions[0].outputs;
                if(out[0].value){--out[0].value;++out[1].value;reject(bad);}
            }
            if(fee) {
                Require(chain.TestEraseUTXO(input.tx_hash,0),"fixture input not removed");
                Require(!chain.ValidateCoinbasePolicy(block),"unresolved fee input accepted");
                Require(!chain.ValidateCoinbasePolicy(block,Blockchain::CoinbaseAdmissionPath::Replay),"unresolved replay input accepted");
            }
            Require(chain.TotalSupplyUnits()==supply,"validation changed supply");
#endif
        }
#ifdef VELD_COINBASE_LEGACY_POLICY_CONTROL
        std::cout<<"BASELINE_POLICY_OBSERVATION cases="<<cases<<" exact_split_passed="<<cases
                 <<" fixed_backstop_rejections="<<disagreement<<" structural_conflicts="<<boundary_conflicts<<'\n';
        Require(disagreement>0 && boundary_conflicts>0,"historical policy disagreements not confirmed");
        std::cerr<<"EXPECTED INVARIANT FAILURE: canonical coinbases do not satisfy all mandatory predicates\n";
        return 1;
#else
        Require(!ComputeCoinbaseAllocation(3400,r,MAX_SUPPLY_UNITS+1,0),"invalid parent supply accepted");
        Require(!ComputeCoinbaseAllocation(3400,r,0,MAX_SUPPLY_UNITS),"fee plus subsidy overflow accepted");
        std::cout<<"PASS coinbase policy cases="<<cases<<" checks="<<checks
                 <<" activation=3360 (private fixture), production height unchanged\n";
#endif
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 2;}
}
