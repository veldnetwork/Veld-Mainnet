// Full native admission with earned funds and the real 43,200-block evidence window.
// Only PoW and activation height are private test-profile substitutions.
#define main registration_fixture_main
#include "validator_registration_admission_tests.cpp"
#undef main

namespace {
using Json = btc_buy::JsonValue;
Json Call(VeldNode& node, const std::string& method, const std::vector<std::string>& params = {}, bool stale=false) {
    // In-process ingest intentionally skips network startup and its RPC wiring.
    // Bind the real modules and a verified single-threaded cursor without listeners.
    const auto observation=node.TestObserveDStateQualificationState();
    Check(observation.module_cursor_matches,"RPC fixture module cursor mismatch");
    node.GetRPC().SetValidators(&node.GetValidators());
    node.GetRPC().SetStaking(&node.GetStaking());
    node.GetRPC().SetModuleCursorFn([observation,stale]{return std::make_pair(
        observation.height-(stale?1:0),observation.canonical_supply_units);});
    std::string request = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" + method + "\",\"params\":[";
    for (size_t i=0;i<params.size();++i) request += (i?",":"") + std::string("\"") + params[i] + "\"";
    request += "]}";
    const auto response=node.GetRPC().Handle(request);
    Json parsed; std::string error;
    btc_buy::StrictJsonParser parser(response,offline_signing::kMaxPreparedJsonBytes,true);
    Check(parser.Parse(parsed,error),"RPC JSON: "+error);
    return parsed;
}
bool Failed(const Json& j) { auto e=j.Get("error");return e && e->kind!=Json::Kind::Null; }
Transaction Prepare(VeldNode& node,const RealKeyPair& owner) {
    auto response=Call(node,"preparereducevalidatorbond",{owner.address,KeyHex(owner)});
    Check(!Failed(response),"fee preparer refused: "+node.GetRPC().Handle(
        "{\"method\":\"preparereducevalidatorbond\",\"params\":[\""+owner.address+"\",\""+KeyHex(owner)+"\"],\"id\":1}"));
    auto result=response.Get("result");Check(result!=nullptr,"missing prepared result");
    auto hex=result->Get("unsigned_tx_hex");Check(hex&&hex->kind==Json::Kind::String,"missing unsigned transaction");
    auto raw=HexToBytes(hex->text);Transaction tx;
    Check(Transaction::Deserialize(raw,0,tx)==raw.size(),"prepared transaction decode");
    uint64_t inputs=0,outputs=0;size_t markers=0;
    for(const auto& in:tx.inputs){
        Check(in.script_sig.empty(),"preparer signed a transaction");
        auto coin=node.GetChain().GetUTXO(in.prev_tx_hash,in.prev_out_index);
        Check(coin&&coin->script_pubkey==owner.GetP2PKHScript(),"preparer selected non-owner funding");inputs+=coin->value;
    }
    const auto expected=BuildOpReturnScript(ValidatorRegistry::BuildReduceBondOp(KeyHex(owner),6601,5000*VELD_UNITS));
    for(const auto& out:tx.outputs){
        outputs+=out.value;
        if(out.script_pubkey==expected){++markers;Check(out.value==0,"nonzero request marker");}
        else Check(out.script_pubkey==owner.GetP2PKHScript(),"request redirected self-change");
    }
    Check(markers==1&&inputs==outputs+MIN_TX_FEE,"request moved principal or wrong fee");
    return tx;
}
void Refuse(VeldNode& node,Block block,const std::string& reason){
    for(auto& tx:block.transactions)tx.InvalidateTxIDCache();block.UpdateMerkleRoot();
    auto before=node.TestObserveDStateQualificationState();
    Check(!node.TestIngestDStateQualificationFrame(block.Serialize(),block.height),reason+" accepted");
    auto after=node.TestObserveDStateQualificationState();
    Check(before.utxo_digest==after.utxo_digest&&before.consensus_state_digest==after.consensus_state_digest&&
          before.supply_digest==after.supply_digest&&before.durable_tip_hash==after.durable_tip_hash,
          reason+" changed live or durable state");
}
}
int main(int argc,char** argv){
 try{
    using namespace coinbase_test;
    static_assert(VALIDATOR_POLICY_ACTIVATION_HEIGHT==7000);
    Check(argc==2,"one absent fixture directory required");const auto root=fs::absolute(argv[1]);
    Check(!fs::exists(root),"preserve existing fixture");fs::create_directories(root);
    const auto owner=GenerateKeyPair(false),miner=GenerateKeyPair(false);
    auto node=Fresh(root/"primary");std::vector<Block> history;
    for(uint64_t h=1;h<=6600;++h){
        if(h%128==0)Consolidate(*node,owner);
        auto block=Build(*node,owner,h);Admit(*node,block);history.push_back(block);
        if(h%1920==0)std::cout<<"PROGRESS funded height="<<h<<std::endl;
    }
    auto registration=Register(*node,owner);auto block=Build(*node,miner,6601);Admit(*node,block);history.push_back(block);
    Check(node->GetValidators().GetBondReductionStatus(KeyHex(owner),6602).bond_units==10000*VELD_UNITS,"earned old bond missing");
    Check(Failed(Call(*node,"preparereducevalidatorbond",{owner.address,KeyHex(owner)})),"inactive RPC allowed request");
    while(node->GetChain().Height()<7000){auto b=Build(*node,miner,node->GetChain().Height()+1);Admit(*node,b);history.push_back(b);}
    auto branch=Fresh(root/"branch");for(const auto& b:history)Admit(*branch,b);Equal(*node,*branch);
    Check(Failed(Call(*node,"preparereducevalidatorbond",{miner.address,KeyHex(owner)})),"wrong owner accepted");
    Check(Failed(Call(*node,"preparereducevalidatorbond",{owner.address,KeyHex(miner)})),"wrong key accepted");
    Check(Failed(Call(*node,"preparereducevalidatorbond",{owner.address,KeyHex(owner)},true)),"stale module cursor accepted");
    auto request=Prepare(*node,owner);SignAndQueue(*node,request,owner);
    Check(Failed(Call(*node,"preparereducevalidatorbond",{owner.address,KeyHex(owner)})),"pending duplicate accepted");
    auto requested=Build(*node,miner,71001);Admit(*node,requested);
    Check(node->GetValidators().GetBondReductionStatus(KeyHex(owner),7002).pending,"request not recorded");
    uint64_t disconnected=0;
    for(uint64_t h=7001;h<=7003;++h){auto b=Build(*branch,miner,h+90000);Admit(*branch,b);Admit(*node,b);history.push_back(b);disconnected+=node->GetChain().LastReorgDisconnectCount();}
    Check(disconnected>0,"request reorg never disconnected");Equal(*node,*branch);
    Check(node->GetValidators().GetBondReductionStatus(KeyHex(owner),7004).eligible,"orphaned request survived reorg");
    request=Prepare(*branch,owner);SignAndQueue(*branch,request,owner);
    auto canonical=Build(*branch,miner,71004);Admit(*branch,canonical);Admit(*node,canonical);history.push_back(canonical);
    const uint64_t owner_pending=Balance(*node,owner);
    auto status=node->GetValidators().GetBondReductionStatus(KeyHex(owner),7005);
    const auto due=status.return_boundary;Check(status.pending&&due==50400,"wrong full-window settlement boundary");
    node.reset();node=Reopen(root/"primary",7004);Equal(*node,*branch);
    std::cout<<"PASS actual RPC, owner signing, request reorg and restart; return at "<<due<<std::endl;
    branch.reset();
    while(node->GetChain().Height()+1<due){
        auto h=node->GetChain().Height()+1;auto b=Build(*node,miner,h);Admit(*node,b);history.push_back(b);
        if(h%4800==0)std::cout<<"PROGRESS full evidence window height="<<h<<std::endl;
    }
    Check(Balance(*node,owner)==owner_pending,"principal returned before boundary");
    Check(node->GetValidators().GetBondReductionStatus(KeyHex(owner),due).bond_units==10000*VELD_UNITS,"early bond reduction");
    auto settlement=Build(*node,miner,due);size_t index=settlement.transactions.size(),output_index=0;
    for(size_t i=1;i<settlement.transactions.size();++i)for(size_t j=0;j<settlement.transactions[i].outputs.size();++j){
        auto& out=settlement.transactions[i].outputs[j];
        if(out.script_pubkey==owner.GetP2PKHScript()&&out.value==5000*VELD_UNITS){index=i;output_index=j;}
    }
    Check(index<settlement.transactions.size(),"builder omitted mandatory excess payment");
    const auto payment=settlement.transactions[index];uint64_t ins=0,outs=0;
    for(auto& in:payment.inputs){auto u=node->GetChain().GetUTXO(in.prev_tx_hash,in.prev_out_index);Check(u.has_value(),"settlement missing input");ins+=u->value;}
    for(auto& out:payment.outputs)outs+=out.value;
    Check(ins==outs,"settlement minted or destroyed principal");
    auto missing=settlement;missing.transactions.erase(missing.transactions.begin()+index);Refuse(*node,missing,"missing partial return");
    auto excess=settlement;++excess.transactions[index].outputs[output_index].value;Refuse(*node,excess,"overpaid partial return");
    auto redirected=settlement;redirected.transactions[index].outputs[output_index].script_pubkey=miner.GetP2PKHScript();Refuse(*node,redirected,"redirected partial return");
    auto duplicate=settlement;duplicate.transactions.push_back(payment);Refuse(*node,duplicate,"duplicate partial return");
    auto pre=node->TestObserveDStateQualificationState();
    node->GetChainMut().SetDurableBlockBodyWriter([](const Hash256&,const std::vector<uint8_t>&){return false;});
    Refuse(*node,settlement,"settlement persistence failure");node.reset();node=Reopen(root/"primary",due-1);
    Check(node->TestObserveDStateQualificationState().utxo_digest==pre.utxo_digest,"failed settlement changed reopened funds");
    auto replay=Fresh(root/"replay");for(const auto& b:history)Admit(*replay,b);Equal(*node,*replay);
    std::cout<<"PASS full evidence window, malformed payments and persistence failure; independent replay"<<std::endl;
    const auto supply=node->GetChain().TotalSupplyUnits();Admit(*node,settlement);
    Check(Balance(*node,owner)==owner_pending+5000*VELD_UNITS,"wrong actual returned balance");
    status=node->GetValidators().GetBondReductionStatus(KeyHex(owner),due+1);
    Check(status.settled_at==due&&status.bond_units==5000*VELD_UNITS&&!status.pending,"settled state wrong");
    Coherent(*node,supply+BLOCK_REWARD_UNITS);
    Check(node->TestReadDurableUTXO(payment.GetTxID(),output_index).has_value(),"returned output not durable");
    disconnected=0;
    for(uint64_t h=due;h<=due+2;++h){auto b=Build(*replay,miner,h+90000);Admit(*replay,b);Admit(*node,b);disconnected+=node->GetChain().LastReorgDisconnectCount();}
    Check(disconnected>0,"settlement reorg not exercised");Equal(*node,*replay);
    Check(Balance(*node,owner)==owner_pending+5000*VELD_UNITS,"settlement reorg paid twice");
    node.reset();node=Reopen(root/"primary",due+2);Equal(*node,*replay);
    auto record=node->GetValidators().SnapshotState().validators.at(KeyHex(owner));
    Check(record.active&&!record.slashed&&record.registered_height==6601&&record.principal_settled_at==0&&record.bond_units==5000*VELD_UNITS,"retained validator changed term or exited");
    Check(Failed(Call(*node,"preparereducevalidatorbond",{owner.address,KeyHex(owner)})),"second return allowed");
    std::ofstream receipt(root/"result.json");receipt<<"{\"status\":\"passed\",\"checks\":"<<checks<<",\"return_height\":"<<due<<",\"final_height\":"<<due+2<<",\"injected_funds\":false,\"injected_registry\":false,\"network_started\":false,\"hash_work_bypassed\":true,\"evidence_window\":43200}\n";
    std::cout<<"PASS funded excess return admission, reorganization, replay and restart checks="<<checks<<std::endl;
 }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<std::endl;return 1;}
}
