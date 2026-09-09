#pragma once
#include "node/node.h"
#include <fstream>
#include <iostream>
#include <stdexcept>
using namespace veld;
namespace fs=std::filesystem;
namespace coinbase_test {
inline size_t checks=0;
inline void Check(bool value,const std::string& text) {++checks;if(!value)throw std::runtime_error(text);}
using Node=std::unique_ptr<VeldNode>;
inline Node Fresh(const fs::path& path) {
    Check(!fs::exists(path),"existing fixture directory");
    auto config=RegtestConfig();config.port=31359;
    auto node=std::make_unique<VeldNode>(config,path.string());node->SetQuietBoot(true);
    node->TestPrepareDStateQualificationIngest();
    Check(node->TestIngestDStateQualificationFrame(CreateGenesisBlock().Serialize(),0),"genesis");
    Check(node->GetTCPServer()==nullptr,"unexpected listener");
    return node;
}
inline void Admit(VeldNode& node,const Block& block) {
    Check(node.TestIngestDStateQualificationFrame(block.Serialize(),block.height),
          "admission h="+std::to_string(block.height)+" "+Blockchain::GetLastRejectTag());
}
inline void Coherent(VeldNode& node,uint64_t supply) {
    const auto state=node.TestObserveDStateQualificationState();
    Check(state.canonical_supply_units==supply && state.module_cursor_matches,"supply/module cursor differs");
    Check(node.GetStaking().SnapshotState().total_supply_units==supply,"staking supply differs");
    Check(!state.durable_publication_pending && !state.utxo_recovery_required &&
        !state.reorg_recovery_frame_pending && !state.durability_compromised &&
        !state.durable_commit_fail_stop && !state.fail_stop_required && state.miner_archive_ready,
        "unresolved durability/archive state");
    Check(node.TestGetMinerArchiveRaw("chain:supply")==std::optional<std::string>(std::to_string(supply)),"durable supply differs");
    Check(node.TestGetMinerArchiveRaw("chain:height")==std::optional<std::string>(std::to_string(state.height)),"durable height differs");
    Check(node.TestGetMinerArchiveRaw("chain:tip")==std::optional<std::string>(HashToHex(state.tip_hash)),"durable hash differs");
}
inline void Equal(VeldNode& a,VeldNode& b) {
    const auto x=a.TestObserveDStateQualificationState(),y=b.TestObserveDStateQualificationState();
    Check(x.tip_hash==y.tip_hash && x.utxo_digest==y.utxo_digest && x.supply_digest==y.supply_digest &&
        x.consensus_state_digest==y.consensus_state_digest && x.token_digest==y.token_digest &&
        x.amm_digest==y.amm_digest && x.miner_archive_digest==y.miner_archive_digest,"history state differs");
    Coherent(a,x.canonical_supply_units);Coherent(b,x.canonical_supply_units);
}
inline Block Build(VeldNode& node,const RealKeyPair& owner,uint64_t nonce) {
    const auto before=node.TestObserveDStateQualificationState();
    const auto block=node.TestBuildDStateQualificationBlock(node.GetChain().Height()+1,
        owner.GetP2PKHScript(),"-","-",node.GetChain().TipCopy().header.timestamp+180,nonce);
    Check(node.GetChain().ValidateMiningCoinbase(block),"builder coinbase preflight");
    const auto after=node.TestObserveDStateQualificationState();
    Check(before.consensus_state_digest==after.consensus_state_digest &&
          before.utxo_digest==after.utxo_digest && before.supply_digest==after.supply_digest &&
          before.module_cursor_matches==after.module_cursor_matches,"construction mutated parent");
    return block;
}
inline void Fee(VeldNode& node,const RealKeyPair& owner,uint64_t fee) {
    auto coins=node.GetChain().GetUTXOsForScript(owner.GetP2PKHScript());
    std::sort(coins.begin(),coins.end(),[](const UTXO& a,const UTXO& b) {
        return a.block_height<b.block_height || (a.block_height==b.block_height && UTXOKey(a.tx_hash,a.output_index)<UTXOKey(b.tx_hash,b.output_index));
    });
    Transaction tx;uint64_t value=0;
    for (const auto& coin:coins) {
        if(coin.is_coinbase && node.GetChain().Height()+1<coin.block_height+COINBASE_MATURITY)continue;
        TxInput in;in.prev_tx_hash=coin.tx_hash;in.prev_out_index=coin.output_index;tx.inputs.push_back(in);value+=coin.value;
        if(value>fee+VELD_UNITS)break;
    }
    Check(value>fee+VELD_UNITS,"insufficient earned mature inputs");
    tx.outputs.emplace_back(value-fee,owner.GetP2PKHScript());
    for(size_t i=0;i<tx.inputs.size();++i)
        tx.inputs[i].script_sig=owner.SignInput(tx,static_cast<uint32_t>(i),owner.GetP2PKHScript()).script_sig;
    Check(node.GetMempoolMut().Add(tx,fee,node.GetChain().Height(),node.GetChain())==Mempool::AddResult::ACCEPTED,"authenticated fee transaction refused");
}
inline void Seed(VeldNode& node,uint64_t headroom) {
    const auto before=node.ConsensusStateDigest();
    Check(!node.TestSetCoinbaseAccountingParent(MAX_SUPPLY_UNITS+1),"above-cap parent installed");
    Check(node.ConsensusStateDigest()==before,"invalid seed mutated parent");
    Check(node.TestSetCoinbaseAccountingParent(MAX_SUPPLY_UNITS-headroom),"coherent accounting parent refused");
    Coherent(node,MAX_SUPPLY_UNITS-headroom);
}
inline void Malformed(VeldNode& node,const Block& canonical) {
    const auto before=node.ConsensusStateDigest();
    for(unsigned variant=0;variant<4;++variant) {
        auto bad=canonical;auto& cb=bad.transactions[0];
        if(variant==0)++cb.outputs[0].value;
        if(variant==1)cb.outputs.emplace_back(0,AddressToScript(VaultAddressAtHeight(bad.height)));
        if(variant==2)cb.outputs.clear();
        if(variant==3)cb.outputs.emplace_back(0,BuildOpReturnScript("VELD_FINALITY|invalid-certificate"));
        cb.InvalidateTxIDCache();bad.UpdateMerkleRoot();
        Check(!node.TestIngestDStateQualificationFrame(bad.Serialize(),bad.height),"malformed full admission accepted");
        Check(node.ConsensusStateDigest()==before,"rejection changed state");
    }
}
}
