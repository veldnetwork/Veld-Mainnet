// Native candidate construction only. No sockets, hashing campaign or funds.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_SHA384_DESTINATION_TEST_HEIGHT 3
#include "node/node.h"
#include <iostream>

int main(){
    using namespace veld;unsigned checks=0;
    auto check=[&](bool value,const char* text){++checks;if(!value)throw std::runtime_error(text);};
    try {
        Blockchain chain;Mempool mempool;
        check(chain.AddBlockDirect(CreateGenesisBlock(),true,true,false,mining::PowAdmissionContext::Internal()).IsAccepted(),"genesis");
        auto wide=GenerateKeyPair(),legacy=GenerateKeyPair();wide.address=Sha384KeyAddress(wide.public_key);
        auto build=[&](const RealKeyPair& key){return MineOnly(chain,mempool,key,0,nullptr,{},1,nullptr,{},nullptr,nullptr,{},nullptr,{},true);};
        check(build(wide).error.find("SHA-384")!=std::string::npos,"pre-activation candidate refused before expensive work");
        check(MineAndCommit(chain,mempool,wide).error.find("SHA-384")!=std::string::npos,"standalone miner refuses before work");
        for(unsigned i=0;i<2;++i){auto candidate=build(legacy);check(candidate.success,"legacy candidate");
            check(chain.AddBlockDirect(candidate.block,false,false,true,mining::PowAdmissionContext::Internal()).IsAccepted(),"synthetic history: explicit PoW skip only");}
        auto candidate=build(wide);check(candidate.success&&candidate.block.height==3,"new destination candidate at activation");
        check(candidate.block.transactions[0].outputs[0].script_pubkey==wide.GetP2PKHScript(),"exact new miner script");
        check(chain.RollbackTip(),"rollback parent");
        check(build(wide).error.find("SHA-384")!=std::string::npos,"no work after rollback below activation");
        check(build(legacy).success,"legacy mining unchanged below activation");
        std::cout<<"PASS "<<checks<<" native mining candidate boundary checks; no mining, networking or real funds\n";
    }catch(const std::exception& error){std::cerr<<"FAIL "<<checks<<" "<<error.what()<<'\n';return 1;}
}
