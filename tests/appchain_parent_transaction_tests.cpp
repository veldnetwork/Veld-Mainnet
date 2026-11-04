#include "appchain_bridge_fixture.h"
#include "node/appchain_parent_transaction.h"

template<class F> void refuses(F&& call,const std::string& what) {
    try { call(); } catch (const app::Invalid&) { check(true,what); return; }
    throw app::Invalid("expected refusal: "+what);
}

int main(int argc,char** argv) { try {
    need(argc==3,"closed bridge corpus and fresh artifact directory required");
    const fs::path corpus=fs::absolute(argv[1]),out=fs::absolute(argv[2]);
    need(fs::create_directory(out),"fresh relay artifacts required");
    veld::Blockchain chain;
    std::map<unsigned,unsigned> operations;
    for(uint64_t height=0;height<=703;++height){
        const auto block=load(corpus/(std::to_string(height)+".block"),height);
        std::vector<veld::AppchainParentTransaction> admitted;
        if(height>0)for(const auto& transaction:block.transactions){
            if(transaction.IsCoinbase() || transaction.outputs.empty())continue;
            const auto payload=veld::MarkerOpReturnPayload(transaction.outputs.front().script_pubkey);
            if(!payload.starts_with(br::PREFIX))continue;
            const Bytes marker(payload.begin()+br::PREFIX.size(),payload.end());Reader command{marker};
            const auto operation=command.n(1);
            if(operation!=2 && operation!=3 && operation!=5)continue;
            const auto bridge=command.id();
            const auto view=chain.AppBridgeReadView();
            veld::AppchainParentTransaction request{view.genesis(),view.anchor(),
                view.state().records.at(bridge).committee.id(),bridge,veld::MIN_TX_FEE,transaction.Serialize()};
            const auto raw=request.Encode();
            check(veld::AppchainParentTransaction::Decode(raw).Encode()==raw,"canonical transaction relay frame roundtrip");
            refuses([&]{auto bad=raw;bad.push_back(0);veld::AppchainParentTransaction::Decode(bad);},"trailing transaction frame refused");
            refuses([&]{veld::AppchainParentTransaction::Decode(Bytes(180));},"empty transaction frame refused");
            refuses([&]{veld::AppchainParentTransaction::Decode(Bytes(181+veld::Mempool::MAX_RELAY_TX_BYTES));},"oversized transaction frame refused");
            const auto state=chain.AppBridgeDigest();const auto utxo=chain.UtxoDigest();
            veld::Mempool pool;
            {
                auto guard=chain.AcquireConsensusTransitionGuard();
                auto admitRequest=[&](const auto& value){return veld::AdmitAppchainParentTransaction(guard,chain,pool,value);};
                auto bad=request;bad.genesis[0]^=1;
                refuses([&]{admitRequest(bad);},"wrong parent genesis refused");
                bad=request;bad.parent.hash[0]^=1;
                refuses([&]{admitRequest(bad);},"same-height changed parent anchor refused");
                bad=request;++bad.parent.height;
                refuses([&]{admitRequest(bad);},"wrong parent height refused");
                bad=request;bad.descriptor[0]^=1;
                refuses([&]{admitRequest(bad);},"wrong registered bridge descriptor refused");
                bad=request;bad.bridge[0]^=1;
                refuses([&]{admitRequest(bad);},"wrong bridge identifier refused");
                bad=request;++bad.fee;
                refuses([&]{admitRequest(bad);},"unbounded settlement fee refused");
                bad=request;bad.bytes.push_back(0);
                refuses([&]{admitRequest(bad);},"noncanonical signed transaction bytes refused");
                auto corrupt=transaction;
                corrupt.outputs.front().script_pubkey=br::marker(4,Bytes(marker.begin()+1,marker.end()));
                corrupt.InvalidateTxIDCache();bad=request;bad.bytes=corrupt.Serialize();
                refuses([&]{admitRequest(bad);},"non-settlement bridge operation refused before admission");
                corrupt=transaction;
                auto signedInput=std::find_if(corrupt.inputs.begin(),corrupt.inputs.end(),[](const auto& input){return !input.script_sig.empty();});
                if(signedInput!=corrupt.inputs.end()){
                    signedInput->script_sig.back()^=1;corrupt.InvalidateTxIDCache();bad=request;bad.bytes=corrupt.Serialize();
                    refuses([&]{admitRequest(bad);},"corrupted real ML-DSA signature refused");
                }else{
                    need(operation==5&&!corrupt.inputs.empty(),"only finalized reserve proof payout may lack ordinary signatures");
                    corrupt.inputs.front().script_sig={0};corrupt.InvalidateTxIDCache();bad=request;bad.bytes=corrupt.Serialize();
                    refuses([&]{admitRequest(bad);},"finalized reserve proof payout refuses a noncanonical input authorization");
                }
                corrupt=transaction;
                auto change=std::find_if(corrupt.outputs.begin(),corrupt.outputs.end(),[](const auto& output){return output.value>0;});
                need(change!=corrupt.outputs.end(),"nonzero settlement output required");
                --change->value;corrupt.InvalidateTxIDCache();bad=request;bad.bytes=corrupt.Serialize();
                refuses([&]{admitRequest(bad);},"actual native fee differs from fixed reviewed fee");
                auto result=admitRequest(request);
                check(!result.duplicate && result.transaction.Serialize()==request.bytes,"real signed settlement admitted through normal native mempool");
                result=admitRequest(request);
                check(result.duplicate && result.transaction.Serialize()==request.bytes,"exact duplicate is fully revalidated and reported");
                check(pool.GetTransaction(veld::HashToHex(transaction.GetTxID()))->Serialize()==request.bytes,
                      "exact signed bytes retained for ordinary peer relay");
                check(chain.AppBridgeDigest()==state && chain.UtxoDigest()==utxo,
                      "local admission and refusals do not settle canonical state");
            }
            admitted.push_back(request);++operations[operation];
        }
        admit(chain,block);
        for(const auto& request:admitted){
            veld::Mempool pool;auto guard=chain.AcquireConsensusTransitionGuard();
            refuses([&]{veld::AdmitAppchainParentTransaction(guard,chain,pool,request);},"mined transaction cannot be submitted under stale reviewed context");
        }
    }
    check(operations[2]>0 && operations[3]>0 && operations[5]>0,"actual proposal, finalization and payout all covered");
    std::ofstream result(out/"result.json");
    result<<"{\"status\":\"PASS_NATIVE_PARENT_TRANSACTION_ADMISSION\",\"checks\":"<<checks
          <<",\"proposals\":"<<operations[2]<<",\"finalizations\":"<<operations[3]<<",\"payouts\":"<<operations[5]
          <<",\"height\":"<<chain.Height()<<",\"real_signatures\":true,\"real_veldhash\":true,\"real_funds\":false,\"network_broadcast\":false}\n";
    result.close();need(bool(result),"native admission result saved");
    std::cout<<"RESULT "<<checks<<" checks passed\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}}
