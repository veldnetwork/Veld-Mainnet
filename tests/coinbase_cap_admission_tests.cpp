// Synthetic cap parent; genuine descendant admission and LevelDB callbacks.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_ASERT_TESTCHAIN 1
#define VELD_TEST_BRANCH_CONTEXT 1
#define VELD_TEST_STAKE_OUTPOINT_BACKING 1
#define VELD_PROTOCOL_UPGRADE_TEST_HEIGHT 3360
#define VELD_LIGHT_VERIFY 1
#include "node/node.h"
#include <fstream>
#include <iostream>
#include <stdexcept>

#include "coinbase_admission_test_support.h"
using namespace coinbase_test;

void RejectAlternativeCoinbases(VeldNode& node,const Block& canonical) {
    const auto before=node.TestObserveDStateQualificationState();
    for(unsigned variant=0;variant<2;++variant) {
        auto bad=canonical;
        auto& coinbase=bad.transactions[0];
        if(variant==0) {
            ++coinbase.outputs[0].value;
        } else {
            bool vault=false,endorse=false;
            for(auto& output:coinbase.outputs) {
                if(output.script_pubkey==AddressToScript(VaultAddressAtHeight(bad.height))) {
                    Check(output.value>0,"missing positive vault allocation");
                    --output.value;vault=true;
                } else if(output.script_pubkey==AddressToScript(EndorsementPoolAddressAtHeight(bad.height))) {
                    ++output.value;endorse=true;
                }
            }
            Check(vault && endorse,"missing required fee-only categories");
        }
        coinbase.InvalidateTxIDCache();bad.UpdateMerkleRoot();
        Check(!node.TestIngestDStateQualificationFrame(bad.Serialize(),bad.height),
            "malformed alternate branch accepted");
        Check(Blockchain::GetLastRejectTag()=="coinbase_policy_invalid" &&
            node.GetChain().LastReorgDisconnectCount()==2 &&
            node.GetChain().LastReorgApplyCount()==0,
            "alternate branch did not reach candidate-parent coinbase validation");
        const auto after=node.TestObserveDStateQualificationState();
        Check(before.tip_hash==after.tip_hash && before.utxo_digest==after.utxo_digest &&
            before.supply_digest==after.supply_digest &&
            before.consensus_state_digest==after.consensus_state_digest &&
            before.miner_archive_digest==after.miner_archive_digest,
            "alternate-branch rejection changed canonical state");
        Coherent(node,MAX_SUPPLY_UNITS);
    }
    std::cout<<"PASS overpayment and incorrect distribution rejected during alternate-branch replay"<<std::endl;
}

int main(int argc,char** argv) {
    try {
        Check(argc==2,"fresh fixture root required");const fs::path root=fs::absolute(argv[1]);
        Check(!fs::exists(root),"preserve previous fixture");fs::create_directories(root);
        auto owner=GenerateKeyPair(true);
        auto partial=Fresh(root/"partial-boundary");std::vector<Block> prefix{CreateGenesisBlock()};
        for(uint64_t h=1;h<=3399;++h) {
            auto b=Build(*partial,owner,h);Admit(*partial,b);prefix.push_back(b);
            if(h%480==0)std::cout<<"PREFIX "<<h<<std::endl;
        }
        const auto parent=[&](const char* name,uint64_t end) {
            auto node=Fresh(root/name);for(uint64_t h=1;h<=end;++h)Admit(*node,prefix[h]);return node;
        };
        Seed(*partial,17);Fee(*partial,owner,MIN_TX_FEE+1);
        auto clipped=Build(*partial,owner,900001);Check(clipped.height==3400,"partial boundary height");
        Check(clipped.transactions[0].TotalOutput()==17+MIN_TX_FEE+1,"clipped subsidy accounting");
        Malformed(*partial,clipped);Admit(*partial,clipped);Coherent(*partial,MAX_SUPPLY_UNITS);
        auto empty=Build(*partial,owner,900002);
        Check(empty.transactions[0].outputs.size()==1 && empty.transactions[0].outputs[0].script_pubkey==std::vector<uint8_t>({0x6a,0}),"canonical zero marker");
        Admit(*partial,empty);Coherent(*partial,MAX_SUPPLY_UNITS);
        std::cout<<"PASS partial subsidy on vault boundary and zero-fee ordinary admission\n";

        auto ordinary=parent("partial-ordinary",3398);Seed(*ordinary,1);
        auto last=Build(*ordinary,owner,900003);Check(last.height==3399 && last.transactions[0].TotalOutput()==1,"final ordinary subsidy");
        Admit(*ordinary,last);Fee(*ordinary,owner,MIN_TX_FEE+1);
        auto boundary=Build(*ordinary,owner,900004);Check(boundary.height==3400,"fee-only boundary height");
        Check(boundary.transactions[0].TotalOutput()==MIN_TX_FEE+1,"fee-only exact total");
        Malformed(*ordinary,boundary);Admit(*ordinary,boundary);Coherent(*ordinary,MAX_SUPPLY_UNITS);
        std::cout<<"PASS final ordinary subsidy followed by fee-only vault boundary\n";

        auto direct=parent("direct",3399),branch=parent("branch",3399),replay=parent("independent",3399);
        Seed(*direct,0);Seed(*branch,0);Seed(*replay,0);Equal(*direct,*branch);Equal(*branch,*replay);
        Admit(*direct,Build(*direct,owner,910000));Admit(*direct,Build(*direct,owner,910001));
        Fee(*branch,owner,30*BLOCK_REWARD_UNITS+1);
        uint64_t reorg_applied=0;
        for(uint64_t h=3400;h<=3402;++h) {
            if(h==3402)Fee(*branch,owner,MIN_TX_FEE+1);
            auto block=Build(*branch,owner,920000+h);
            if(h==3400)Check(!branch->GetChain().ValidateLegacyMinerCaps(block),"high-fee control below old limit");
            Malformed(*branch,block);Admit(*branch,block);Admit(*replay,block);
            if(h==3400)RejectAlternativeCoinbases(*direct,block);
            Admit(*direct,block);
            if(reorg_applied==0 && direct->GetChain().TipCopy().GetHash()==block.GetHash()) {
                reorg_applied=direct->GetChain().LastReorgApplyCount();
                Check(direct->GetChain().LastReorgDisconnectCount()==2 && reorg_applied==h-3399,
                    "reorganization did not traverse the expected branch");
            }
            Equal(*branch,*replay);
        }
        Check(reorg_applied>=2 && reorg_applied<=3,"actual reorganization was not executed");
        std::cout<<"REORG disconnected=2 applied="<<reorg_applied<<std::endl;
        Equal(*direct,*branch);Equal(*replay,*branch);
        std::ofstream receipt(root/"result.json");
        receipt<<"{\"status\":\"passed\",\"checks\":"<<checks<<",\"height\":3402,\"synthetic_accounting_parent\":true,\"genesis_to_cap_replay\":false,\"network_started\":false,\"hash_comparison_bypassed\":true}\n";
        std::cout<<"PASS cap-state direct/reorg/independent descendant replay and durable equality checks="<<checks<<std::endl;
    } catch(const std::exception& e) {std::cerr<<"FAIL "<<e.what()<<std::endl;return 1;}
}
