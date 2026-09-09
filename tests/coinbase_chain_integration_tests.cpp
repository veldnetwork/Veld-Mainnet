// Disk-backed node/module regression with a separate genesis and no listeners.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_ASERT_TESTCHAIN 1
#define VELD_TEST_BRANCH_CONTEXT 1
#define VELD_TEST_STAKE_OUTPOINT_BACKING 1
#ifndef VELD_PROTOCOL_UPGRADE_TEST_HEIGHT
#define VELD_PROTOCOL_UPGRADE_TEST_HEIGHT 3360
#endif
#include "node/node.h"
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace veld;
namespace fs=std::filesystem;
namespace {
size_t checks=0;
constexpr uint64_t activation=PROTOCOL_UPGRADE_HEIGHT;
constexpr uint64_t settlement=(activation/VAULT_BLOCK_INTERVAL+1)*VAULT_BLOCK_INTERVAL;
static_assert(activation > CONSENSUS_SECURITY_UPGRADE_HEIGHT);
void Require(bool value,const std::string& message) {++checks;if(!value)throw std::runtime_error(message);}
std::unique_ptr<VeldNode> Open(const fs::path& data,bool fresh) {
    if(fresh)Require(!fs::exists(data),"fresh disposable directory required");
    auto config=RegtestConfig();config.port=31349;
    auto node=std::make_unique<VeldNode>(config,data.string());node->SetQuietBoot(true);
    if(fresh) {
        node->TestPrepareDStateQualificationIngest();
        Require(node->TestIngestDStateQualificationFrame(CreateGenesisBlock().Serialize(),0),"genesis refused");
    }
    Require(node->GetTCPServer()==nullptr,"offline fixture opened P2P");
    return node;
}
Block Candidate(VeldNode& node,const RealKeyPair& owner,uint64_t nonce) {
    auto& chain=node.GetChainMut();const auto h=chain.Height()+1;
    return node.TestBuildDStateQualificationBlock(h,owner.GetP2PKHScript(),"-","-",
        chain.TipCopy().header.timestamp+180,nonce);
}
void Accept(VeldNode& node,const Block& block) {
    Require(node.TestIngestDStateQualificationFrame(block.Serialize(),block.height),
        "canonical admission failed at "+std::to_string(block.height)+": "+Blockchain::GetLastRejectTag());
}
void Fee(VeldNode& node,const RealKeyPair& owner,uint64_t amount) {
    auto& chain=node.GetChainMut();auto coins=chain.GetUTXOsForScript(owner.GetP2PKHScript());
    std::sort(coins.begin(),coins.end(),[](const UTXO& a,const UTXO& b) {
        return a.block_height<b.block_height || (a.block_height==b.block_height && UTXOKey(a.tx_hash,a.output_index)<UTXOKey(b.tx_hash,b.output_index));
    });
    uint64_t sum=0;Transaction tx;
    for(const auto& coin:coins) {
        if(coin.is_coinbase && chain.Height()+1<coin.block_height+COINBASE_MATURITY)continue;
        TxInput input;input.prev_tx_hash=coin.tx_hash;input.prev_out_index=coin.output_index;
        tx.inputs.push_back(input);sum+=coin.value;
        if(sum>amount+MIN_TX_FEE)break;
    }
    Require(sum>amount+MIN_TX_FEE,"insufficient mature fixture rewards");
    tx.outputs.emplace_back(sum-amount,owner.GetP2PKHScript());
    for(size_t i=0;i<tx.inputs.size();++i)
        tx.inputs[i].script_sig=owner.SignInput(tx,static_cast<uint32_t>(i),owner.GetP2PKHScript()).script_sig;
    const auto result=node.GetMempoolMut().Add(tx,amount,static_cast<uint32_t>(chain.Height()),chain);
    Require(result==Mempool::AddResult::ACCEPTED,
        std::string("signed fee transaction refused by mempool: ")+Mempool::ResultToString(result));
}
void Equal(VeldNode& a,VeldNode& b,const char* label) {
    const auto x=a.TestObserveDStateQualificationState(),y=b.TestObserveDStateQualificationState();
    Require(x.tip_hash==y.tip_hash && x.canonical_supply_units==y.canonical_supply_units &&
        x.utxo_digest==y.utxo_digest && x.supply_digest==y.supply_digest &&
        x.consensus_state_digest==y.consensus_state_digest && x.token_digest==y.token_digest &&
        x.amm_digest==y.amm_digest && x.miner_archive_digest==y.miner_archive_digest,label);
    Require(!x.durable_publication_pending && !x.utxo_recovery_required && !x.reorg_recovery_frame_pending &&
        !x.durability_compromised && !x.durable_commit_fail_stop && !x.fail_stop_required && x.module_cursor_matches,
        "node has unresolved durability or module state");
}
}
int main(int argc,char** argv) {
    try {
        Require(argc==2,"supply a fresh disposable directory");
        const auto root=fs::absolute(argv[1]).lexically_normal();
        Require(!fs::exists(root),"existing fixture must be preserved");fs::create_directories(root);
        auto owner=GenerateKeyPair(true);
        auto direct=Open(root/"direct",true);
        std::vector<Block> history;history.push_back(CreateGenesisBlock());
        for(uint64_t h=1;h<activation;++h) {
            const auto block=Candidate(*direct,owner,h);Accept(*direct,block);history.push_back(block);
            if(h%480==0)std::cout<<"PROGRESS durable height="<<h<<std::endl;
        }
        auto branch=Open(root/"branch",true);
        for(size_t h=1;h<history.size();++h)Accept(*branch,history[h]);
        Equal(*direct,*branch,"same parent state differs");
        for(uint64_t h=activation;h<=activation+1;++h)Accept(*direct,Candidate(*direct,owner,100000+h));
        Fee(*branch,owner,6*BLOCK_REWARD_UNITS+1);
        for(uint64_t h=activation;h<=activation+2;++h) {
            auto block=Candidate(*branch,owner,200000+h);
            Require(branch->GetChain().ValidateMiningCoinbase(block),"mining policy rejected canonical candidate");
            if(h==activation) {
                Require(!branch->GetChain().ValidateLegacyMinerCaps(block),"fee fixture did not exceed old backstop");
                Require(block.transactions.size()>1,"fee or mandatory settlement omitted");
            }
            Accept(*branch,block);history.push_back(block);
            Accept(*direct,block);
        }
        Equal(*direct,*branch,"direct versus reorg state differs across activation");
        std::cout<<"PASS activation reorganization and exact UTXO/supply/module/archive equality\n";

        auto independent=Open(root/"independent",true);
        for(size_t h=1;h<history.size();++h)Accept(*independent,history[h]);
        Equal(*branch,*independent,"independent full admission replay differs");
        for(uint64_t h=activation+3;h<=settlement+1;++h) {
            if(h==settlement)Fee(*branch,owner,30*BLOCK_REWARD_UNITS+1);
            auto block=Candidate(*branch,owner,h);
            if(h==settlement)Require(!branch->GetChain().ValidateLegacyMinerCaps(block),"vault fee fixture missed old total boundary");
            Accept(*branch,block);Accept(*independent,block);Accept(*direct,block);history.push_back(block);
        }
        Equal(*direct,*branch,"ordinary and vault fee histories differ");
        Equal(*independent,*branch,"independent accepted state differs");
        auto bad=Candidate(*branch,owner,999999);++bad.transactions.front().outputs.front().value;
        bad.transactions.front().InvalidateTxIDCache();bad.UpdateMerkleRoot();
        const auto digest=branch->ConsensusStateDigest();
        Require(!branch->GetChain().ValidateMiningCoinbase(bad),"overpayment preflight accepted");
        Require(!branch->TestIngestDStateQualificationFrame(bad.Serialize(),bad.height),"overpayment admission accepted");
        Require(branch->ConsensusStateDigest()==digest,"rejected coinbase changed module state");
        const auto height=branch->GetChain().Height();branch.reset();
        branch=Open(root/"branch",false);branch->TestReplayDStateQualificationCorpus(height);
        Equal(*direct,*branch,"disk restart replay differs from accepted state");
        Require(branch->GetTCPServer()==nullptr,"restart fixture opened a listener");
        std::ofstream receipt(root/"result.json");
        receipt<<"{\"status\":\"passed\",\"height\":"<<height<<",\"checks\":"<<checks
            <<",\"tip\":\""<<HashToHex(branch->GetChain().TipCopy().GetHash())<<"\",\"digest\":\""
            <<HashToHex(digest)<<"\",\"network_started\":false,\"hash_work_bypassed\":true}\n";
        std::cout<<"PASS disk-backed direct/reorg/independent replay/restart checks="<<checks<<" height="<<height<<'\n';
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
}
