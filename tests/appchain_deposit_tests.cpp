#include "appchain_bridge_fixture.h"
#include "wallet/appchain_deposit.h"
#include "network/rpc.h"

veld::btc_buy::JsonValue call(veld::RpcServer& rpc, const std::string& method,
                             const std::vector<std::string>& params = {}) {
    std::vector<std::string> encoded;
    for (const auto& p : params) encoded.push_back(veld::JsonBuilder::String(p));
    const auto response = rpc.Handle("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":" +
        veld::JsonBuilder::String(method) + ",\"params\":" + veld::JsonBuilder::Array(encoded) + "}");
    veld::btc_buy::JsonValue parsed; std::string error;
    veld::btc_buy::StrictJsonParser parser(response, veld::offline_signing::kMaxPreparedJsonBytes, true);
    need(parser.Parse(parsed,error),"parse actual RPC response"); return parsed;
}

int main(int argc, char** argv) { try {
    need(argc == 2, "fresh artifact path required");
    Fixture f; f.path = fs::absolute(argv[1]);
    need(fs::create_directory(f.path), "fresh native deposit history");
    auto genesis = veld::CreateGenesisBlock(); admit(f.chain, genesis); save(f.path/"0.block",genesis);
    veld::Mempool mempool;
    veld::StorageEngine storage((f.path/"storage").string(),veld::MAINNET_MAGIC);
    veld::RpcServer rpc(f.chain,mempool,storage);
    const auto inactive=call(rpc,"prepareappchaindeposit",std::vector<std::string>(7,"0"));
    check(inactive.Get("error") && inactive.Get("error")->Get("message") &&
          inactive.Get("error")->Get("message")->text=="native appchain bridge is not activated",
          "deposit RPC refuses before activation");
    veld::Hash256 prior{}; prior[0]=17;
    const auto bridgeDigest = name("digest-binding");
    check(veld::state_digest::WithAppchainBridge(4,prior,bridgeDigest)==prior,
          "preactivation digest byte identity retained");
    const auto activated=veld::state_digest::WithAppchainBridge(5,prior,bridgeDigest);
    check(activated!=prior && activated!=veld::state_digest::WithAppchainBridge(5,prior,name("different-state")),
          "activated digest commits to native reserve ledger");
    auto priorOther=prior; priorOther[1]=42;
    check(activated!=veld::state_digest::WithAppchainBridge(5,priorOther,bridgeDigest),
          "activated digest retains all previous component commitments");
    f.until(101);
    std::array<Key,10> keys; Committee c;
    c.parentGenesis = genesis.GetHash(); c.childGenesis = name("deposit-child");
    c.bridge = name("deposit-bridge");
    for(unsigned i=0;i<10;++i)c.keys[i]=keys[i].pub;
    Writer registration; registration.str(c.encode(),20000);
    f.block({f.fund(br::marker(0,registration.b))});
    auto unsignedReference = f.fund(command(1,c.bridge), {{20000000,br::reserveScript(c.bridge)}});
    const br::Outpoint funding{unsignedReference.inputs[0].prev_tx_hash,unsignedReference.inputs[0].prev_out_index};
    const auto script=f.key.GetP2PKHScript();
    const auto ownerId=name("real-beneficiary");
    auto before=f.chain.AppBridgeDigest();
    auto prepared=veld::PrepareAppchainDeposit(f.chain,c.bridge,ownerId,15000000,5000000,script,{funding});
    check(prepared.child==c.childGenesis && prepared.descriptor==c.id() &&
          prepared.parent==f.chain.AppBridgeReadView().anchor(), "deposit binds exact child descriptor and canonical parent");
    check(prepared.transaction.inputs[0].script_sig.empty() && f.chain.AppBridgeDigest()==before,
          "preparation never signs or mutates funds");
    check(prepared.transaction.outputs[1].value==20000000 &&
          prepared.transaction.outputs[1].script_pubkey==br::reserveScript(c.bridge) &&
          prepared.totalInput-prepared.transaction.TotalOutput()==veld::MIN_TX_FEE,
          "deposit locks exact native atoms and only canonical fee");
    auto denied=[&](auto fn,const std::string& label){bool failed=false;try{fn();}catch(const std::exception&){failed=true;}
        check(failed && f.chain.AppBridgeDigest()==before,label+" without mutation");};
    denied([&]{veld::PrepareAppchainDeposit(f.chain,c.bridge,{},1,0,script,{funding});},"missing beneficiary refused");
    denied([&]{veld::PrepareAppchainDeposit(f.chain,name("unknown"),ownerId,1,0,script,{funding});},"unregistered bridge refused");
    denied([&]{veld::PrepareAppchainDeposit(f.chain,c.bridge,ownerId,1,0,script,{funding,funding});},"duplicate input refused");
    denied([&]{veld::PrepareAppchainDeposit(f.chain,c.bridge,ownerId,1,0,script,
                std::vector<br::Outpoint>(veld::MAX_APPCHAIN_DEPOSIT_INPUTS+1,funding));},"excess signer inputs refused");
    denied([&]{veld::PrepareAppchainDeposit(f.chain,c.bridge,ownerId,0,0,script,{funding});},"zero allocation refused");
    denied([&]{veld::PrepareAppchainDeposit(f.chain,c.bridge,ownerId,MAX,1,script,{funding});},"integer overflow refused");
    denied([&]{veld::PrepareAppchainDeposit(f.chain,c.bridge,ownerId,1,0,veld::GenerateKeyPair(true).GetP2PKHScript(),{funding});},"other wallet input refused");
    const auto tip=f.chain.TipCopy();
    denied([&]{veld::PrepareAppchainDeposit(f.chain,c.bridge,ownerId,1,0,script,{{tip.transactions[0].GetTxID(),0}});},"immature funding refused");
    const auto address=veld::ScriptToAddress(script);
    std::vector<std::string> args{address,hex(c.bridge),hex(c.id()),hex(c.childGenesis),hex(ownerId),"0.15","0.05"};
    auto response=call(rpc,"prepareappchaindeposit",args);
    const auto* result=response.Get("result");
    need(result && result->kind==veld::btc_buy::JsonValue::Kind::Object,"RPC deposit result");
    veld::offline_signing::VerifiedPrepared verified; std::string error;
    check(veld::offline_signing::AuthenticatePrepared(*result,script,verified,error),
          "RPC funding parents, amounts, sighashes and bounded fees authenticated");
    check(veld::VerifyAppchainDepositEnvelope(verified,script,c.bridge,ownerId,15000000,5000000,error),
          "RPC reserve, beneficiary and trading/FUEL allocation authenticated");
    veld::offline_signing::Intent intent;
    check(veld::offline_signing::ParseIntent(*result,intent,error),"RPC signing intent is complete");
    const std::string expectedIdentity="VELD_APPCHAIN_DEPOSIT_V1|"+veld::HashToHex(genesis.GetHash())+
        "|"+hex(c.bridge)+"|"+hex(c.id())+"|"+hex(c.childGenesis)+"|"+hex(ownerId)+"|15000000|5000000";
    check(veld::offline_signing::VerifyIntent(intent,verified,"APPCHAIN_DEPOSIT",hex(ownerId),20000000,
          address,verified.claimed_change,expectedIdentity,error),"signing intent binds child chain and canonical descriptor");
    for (int tamper=0;tamper<5;++tamper) {
        auto altered=verified;
        if(tamper==0)altered.tx.outputs[1].script_pubkey=script;
        if(tamper==1)altered.tx.outputs[0].script_pubkey=veld::AppchainDepositMarker(c.bridge,name("attacker"),15000000,5000000);
        if(tamper==2)altered.tx.outputs[0].script_pubkey=veld::AppchainDepositMarker(c.bridge,ownerId,0,20000000);
        if(tamper==3)altered.tx.outputs[2].script_pubkey=veld::GenerateKeyPair(true).GetP2PKHScript();
        if(tamper==4)altered.tx.outputs.emplace_back(1,script);
        check(!veld::VerifyAppchainDepositEnvelope(altered,script,c.bridge,ownerId,15000000,5000000,error),
              "wallet rejects altered deposit envelope case="+std::to_string(tamper));
    }
    for(unsigned field : {2U,3U,5U,6U}) {
        auto altered=args; altered[field]=field<4?hex(name("wrong-selected-network")):"0.000000001";
        const auto failed=call(rpc,"prepareappchaindeposit",altered);
        const auto* issue=failed.Get("error");
        check(issue && issue->kind==veld::btc_buy::JsonValue::Kind::Object,
              "RPC refuses network mismatch or fractional atoms field="+std::to_string(field));
    }
    const auto info=call(rpc,"getappchainbridgeinfo",{hex(c.bridge)});
    check(info.Get("result") && info.Get("result")->Get("bridges") &&
          info.Get("result")->Get("bridges")->array.size()==1 &&
          info.Get("result")->Get("bridges")->array[0].Get("can_deposit")->boolean,
          "canonical active bridge status exposed");
    rpc.SetModuleCursorFn([&]{return std::make_pair(f.chain.Height(),f.chain.TotalSupplyUnits());});
    const auto stateInfo=call(rpc,"getstatedigest");
    need(stateInfo.Get("result") && stateInfo.Get("result")->Get("sub"),"canonical state digest RPC");
    check(stateInfo.Get("result")->Get("spec_version")->text=="VELD_STATE_DIGEST_v9" &&
          stateInfo.Get("result")->Get("sub")->Get("appchain_bridge")->text==hex(f.chain.AppBridgeDigest()),
          "state RPC reports the native bridge commitment after activation");
    prepared.transaction=verified.tx;
    f.refused(prepared.transaction,"unsigned deposit cannot be broadcast");
    f.sign(prepared.transaction);
    prepared.transaction.InvalidateTxIDCache();
    check(f.chain.ValidateTransactionLocking(prepared.transaction),"wallet signed deposit accepted by native validation");
    const auto mined=f.block({prepared.transaction});
    const auto state=f.chain.AppBridgeState();
    const auto deposited=state->records.at(c.bridge).deposits.at({prepared.transaction.GetTxID(),1});
    check(state->totalReserve==20000000 && deposited.owner==ownerId &&
          deposited.trading==15000000 && deposited.fuel==5000000 && deposited.height==mined.height,
          "mined deposit records exact beneficiary and allocation");
    summary(f.path/"created.json",f.chain);
    std::cout<<"RESULT {\"passed\":"<<checks<<",\"failed\":0}\n";return 0;
} catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;} }
