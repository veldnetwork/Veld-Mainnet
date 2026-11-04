#include "appchain_bridge_fixture.h"
#include "wallet/appchain_payout.h"
#include "wallet/appchain_payout_signing.h"

template<class F> void refuses(F&& call,const std::string& what) {
    try { call(); } catch (const app::Invalid&) { check(true,what); return; }
    throw app::Invalid("expected refusal: "+what);
}

int main(int argc,char** argv) { try {
    need(argc==3,"closed bridge corpus and fresh payout artifact directory required");
    const fs::path corpus=fs::absolute(argv[1]),out=fs::absolute(argv[2]);
    need(fs::create_directory(out),"fresh payout artifacts required");
    Fixture f; f.path=out;
    for(uint64_t h=0;h<=702;++h) admit(f.chain,load(corpus/(std::to_string(h)+".block"),h));
    const auto original=load(corpus/"703.block",703).transactions.at(1);
    auto payload=veld::MarkerOpReturnPayload(original.outputs.at(0).script_pubkey);
    Bytes body(payload.begin()+br::PREFIX.size(),payload.end()); Reader r{body};
    need(r.n(1)==5,"retained real payout operation");
    const auto bridge=r.id(); (void)r.n(8); const auto checkpoint=r.id();
    (void)r.n(8); need(r.n(1)==1,"one retained finalized withdrawal");
    const auto proof=br::Proof::read(r); r.end();
    auto selection=[&] {
        const auto view=f.chain.AppBridgeReadView(); const auto& rec=view.state().records.at(bridge);
        return veld::AppchainPayoutSelection{view.genesis(),bridge,rec.committee.id(),
            rec.committee.childGenesis,checkpoint,view.anchor(),rec.transition+1};
    };
    const auto recipient=proof.leaf.recipient;
    const auto sponsor=f.key.GetP2PKHScript();
    auto prepare=[&](const auto& sel,const std::vector<br::Proof>& proofs,
                     const Bytes& script,const std::vector<br::Outpoint>& inputs,uint64_t fee) {
        return veld::PrepareAppchainPayout(f.chain,sel,proofs,script,inputs,fee);
    };
    auto selected=selection();
    const auto originalState=f.chain.AppBridgeDigest();
    const auto originalUtxo=f.chain.UtxoDigest();
    refuses([&]{prepare(selected,{proof},sponsor,{},veld::MIN_TX_FEE);},"unfunded fee sponsor refused");
    check(f.chain.AppBridgeDigest()==originalState && f.chain.UtxoDigest()==originalUtxo,
          "unfunded plan preserves the initial parent state");
    auto first=f.block();
    br::Outpoint feeCoin{first.transactions.front().GetTxID(),0};
    selected=selection();
    refuses([&]{prepare(selected,{proof},sponsor,{feeCoin},veld::MIN_TX_FEE);},"immature sponsor coinbase refused");
    f.until(first.height+veld::COINBASE_MATURITY);
    for(unsigned i=0;i<34;++i) {
        Writer allocation; allocation.raw(proof.leaf.owner); allocation.n(veld::DUST_THRESHOLD_UNITS,8); allocation.n(0,8);
        f.block({f.fund(command(1,bridge,allocation.b),{{veld::DUST_THRESHOLD_UNITS,br::reserveScript(bridge)}})});
    }
    auto sponsorCoins=f.chain.GetUTXOsForScript(sponsor);
    const auto funded=std::find_if(sponsorCoins.begin(),sponsorCoins.end(),[&](const auto& coin){
        return coin.value>veld::MIN_TX_FEE && (!coin.is_coinbase || f.chain.Height()>=coin.block_height+veld::COINBASE_MATURITY);
    });
    need(funded!=sponsorCoins.end(),"remaining mature disposable sponsor coin");
    feeCoin={funded->tx_hash,funded->output_index};
    selected=selection();
    auto plan=prepare(selected,{proof},sponsor,{feeCoin},veld::MIN_TX_FEE);
    const auto plannedState=f.chain.AppBridgeDigest();
    const auto plannedUtxo=f.chain.UtxoDigest();
    check(plan.fee==veld::MIN_TX_FEE && plan.transaction.outputs.at(1).value==proof.leaf.gross &&
          plan.transaction.outputs.at(1).script_pubkey==recipient,"full authorized recipient amount without user fee deduction");
    check(plan.sponsorInput-plan.sponsorChange==plan.fee &&
          plan.reserveInput-plan.reserveChange==proof.leaf.gross,"separate sponsor fee and exact backing conservation");
    check(std::all_of(plan.transaction.inputs.begin(),plan.transaction.inputs.end(),
                      [](const auto& in){return in.script_sig.empty();}),"planner exports no signatures");
    check(plan.transaction.outputs.back().script_pubkey==sponsor,"all sponsor change returns to sponsor");
    check(f.chain.AppBridgeState()->records.at(bridge).reserves.size()==35 && plan.reserveInputs.size()==1,
          "34 small reserve deposits do not prevent a single-input funded payout");
    veld::RecheckAppchainPayout(f.chain,plan,{proof});
    check(prepare(selected,{proof},sponsor,{feeCoin},veld::MIN_TX_FEE).id()==plan.id(),"identical context produces identical plan");
    refuses([&]{prepare(selected,{proof},sponsor,{feeCoin},veld::MIN_TX_FEE-1);},"insufficient explicit fee budget refused");
    refuses([&]{prepare(selected,{proof},sponsor,{feeCoin,feeCoin},veld::MIN_TX_FEE);},"duplicate sponsor coin refused");
    refuses([&]{prepare(selected,{proof},recipient,{feeCoin},veld::MIN_TX_FEE);},"another wallet cannot use sponsor coin");
    refuses([&]{prepare(selected,{proof},br::reserveScript(bridge),plan.reserveInputs,veld::MIN_TX_FEE);},"bridge backing cannot pay sponsorship fees");
    refuses([&]{prepare(selected,{proof},veld::AddressToScript(veld::VAULT_ADDRESS),{feeCoin},veld::MIN_TX_FEE);},"protocol vault cannot sponsor");
    refuses([&]{prepare(selected,{proof,proof},sponsor,{feeCoin},veld::MIN_TX_FEE);},"duplicate withdrawal cannot be scheduled twice");
    refuses([&]{prepare(selected,std::vector<br::Proof>(33,proof),sponsor,{feeCoin},veld::MIN_TX_FEE);},"oversized withdrawal batch refused");
    refuses([&]{prepare(selected,{proof},sponsor,std::vector<br::Outpoint>(33,feeCoin),veld::MIN_TX_FEE);},"oversized sponsorship batch refused");
    auto changed=proof; changed.leaf.recipient=sponsor;
    refuses([&]{prepare(selected,{changed},sponsor,{feeCoin},veld::MIN_TX_FEE);},"recipient substitution invalidates finalized proof");
    changed=proof; ++changed.leaf.gross;
    refuses([&]{prepare(selected,{changed},sponsor,{feeCoin},veld::MIN_TX_FEE);},"amount substitution invalidates finalized proof");
    changed=proof; changed.siblings.at(0)[0]^=1;
    refuses([&]{prepare(selected,{changed},sponsor,{feeCoin},veld::MIN_TX_FEE);},"altered Merkle path refused");
    auto bad=selected; bad.parentGenesis[0]^=1;
    refuses([&]{prepare(bad,{proof},sponsor,{feeCoin},veld::MIN_TX_FEE);},"wrong native chain refused");
    bad=selected; bad.child[0]^=1;
    refuses([&]{prepare(bad,{proof},sponsor,{feeCoin},veld::MIN_TX_FEE);},"wrong child chain refused");
    bad=selected; bad.descriptor[0]^=1;
    refuses([&]{prepare(bad,{proof},sponsor,{feeCoin},veld::MIN_TX_FEE);},"wrong committee descriptor refused");
    bad=selected; bad.checkpoint[0]^=1;
    refuses([&]{prepare(bad,{proof},sponsor,{feeCoin},veld::MIN_TX_FEE);},"unfinalized checkpoint refused");
    bad=selected; ++bad.transition;
    refuses([&]{prepare(bad,{proof},sponsor,{feeCoin},veld::MIN_TX_FEE);},"wrong payout transition refused");
    auto tampered=plan; --tampered.transaction.outputs.at(1).value;
    refuses([&]{veld::RecheckAppchainPayout(f.chain,tampered,{proof});},"modified unsigned payout fails renewed review");
    tampered=plan; tampered.sponsorChange++;
    refuses([&]{veld::RecheckAppchainPayout(f.chain,tampered,{proof});},"modified review metadata refused");
    check(f.chain.AppBridgeDigest()==plannedState && f.chain.UtxoDigest()==plannedUtxo,"planning and all refusals preserve canonical accounting");
    const auto raw=plan.transaction.Serialize();
    { std::ofstream file(out/"unsigned-payout.bin",std::ios::binary);
      file.write(reinterpret_cast<const char*>(raw.data()),raw.size()); file.close(); need(bool(file),"unsigned export saved"); }
    { veld::Blockchain restarted;
      for(uint64_t h=0;h<=f.chain.Height();++h)
          admit(restarted,load((h<=702?corpus:out)/(std::to_string(h)+".block"),h));
      auto restored=veld::PrepareAppchainPayout(restarted,selected,{proof},sponsor,{feeCoin},veld::MIN_TX_FEE);
      check(restored.id()==plan.id() && restored.transaction.Serialize()==raw,"full disk replay reproduces exact unsigned payout plan"); }
    check(!f.chain.ValidateTransactionLocking(plan.transaction),"unsigned sponsor cannot authorize a native spend");
    const auto unsignedId=plan.transaction.GetTxID();
    auto wrongApproval=plan.id();wrongApproval[0]^=1;
    refuses([&]{veld::SignReviewedAppchainPayout(f.chain,plan,{proof},wrongApproval,plan.feeBudget,f.key);},"signer refuses another approved plan");
    refuses([&]{veld::SignReviewedAppchainPayout(f.chain,plan,{proof},plan.id(),plan.feeBudget+1,f.key);},"signer refuses changed approved fee budget");
    const auto otherKey=veld::GenerateKeyPair(true);
    refuses([&]{veld::SignReviewedAppchainPayout(f.chain,plan,{proof},plan.id(),plan.feeBudget,otherKey);},"signer refuses another sponsor key");
    auto signedTx=veld::SignReviewedAppchainPayout(f.chain,plan,{proof},plan.id(),plan.feeBudget,f.key);
    check(signedTx.GetTxID()!=unsignedId&&signedTx.GetTxID()==veld::Hash256d(signedTx.Serialize()),
          "signing invalidates warmed unsigned transaction identity");
    check(f.chain.ValidateTransactionLocking(signedTx),"actual ML-DSA sponsor signature authorizes finalized payout");
    veld::RecheckSignedAppchainPayout(f.chain,plan,{proof},plan.id(),plan.feeBudget,signedTx);
    check(true,"reviewed signer result passes fresh native prebroadcast verification");
    check(plan.transaction.Serialize()==raw&&f.chain.AppBridgeDigest()==plannedState&&f.chain.UtxoDigest()==plannedUtxo,
          "reviewed signing preserves unsigned plan and all chain state");
    auto badSigned=signedTx;badSigned.inputs.back().script_sig.back()^=1;badSigned.InvalidateTxIDCache();
    refuses([&]{veld::RecheckSignedAppchainPayout(f.chain,plan,{proof},plan.id(),plan.feeBudget,badSigned);},"prebroadcast refuses corrupted ML-DSA signature");
    badSigned=signedTx;badSigned.outputs.at(1).value--;badSigned.InvalidateTxIDCache();
    refuses([&]{veld::RecheckSignedAppchainPayout(f.chain,plan,{proof},plan.id(),plan.feeBudget,badSigned);},"prebroadcast refuses changed signed recipient amount");
    badSigned=signedTx;badSigned.inputs.front().script_sig={1};badSigned.InvalidateTxIDCache();
    refuses([&]{veld::RecheckSignedAppchainPayout(f.chain,plan,{proof},plan.id(),plan.feeBudget,badSigned);},"prebroadcast refuses reserve script substitution");
    auto redirect=signedTx; redirect.outputs.at(1).script_pubkey=sponsor; f.sign(redirect);
    f.refused(redirect,"signed sponsor cannot redirect recipient",false);
    auto theft=signedTx; --theft.outputs.at(2).value; f.sign(theft);
    f.refused(theft,"signed sponsor cannot deduct extra backing",false);
    veld::Mempool pool;
    check(pool.Add(signedTx,plan.fee,f.chain.Height(),f.chain)==veld::Mempool::AddResult::ACCEPTED,"planned signed payout accepted by real mempool");
    auto paid=f.block({signedTx});
    check(f.chain.GetUTXO(signedTx.GetTxID(),1)->value==proof.leaf.gross,"mined payout credits recipient full amount");
    check(f.chain.AppBridgeState()->records.at(bridge).paid.contains(proof.leaf.id()),"mined payout consumes withdrawal nullifier");
    refuses([&]{veld::RecheckAppchainPayout(f.chain,plan,{proof});},"saved plan refuses changed parent context");
    refuses([&]{veld::RecheckSignedAppchainPayout(f.chain,plan,{proof},plan.id(),plan.feeBudget,signedTx);},"prebroadcast refuses signed transaction after payment");
    refuses([&]{veld::SignReviewedAppchainPayout(f.chain,plan,{proof},plan.id(),plan.feeBudget,f.key);},"reviewed signer refuses consumed or stale plan");
    selected=selection();
    refuses([&]{prepare(selected,{proof},sponsor,{feeCoin},veld::MIN_TX_FEE);},"paid withdrawal cannot be replanned");
    check(!f.chain.ValidateTransactionLocking(signedTx),"payout transaction replay refused");
    const auto paidState=f.chain.AppBridgeDigest();
    const auto paidUtxo=f.chain.UtxoDigest();
    check(f.chain.RollbackTip(),"payout branch can be disconnected");
    veld::RecheckAppchainPayout(f.chain,plan,{proof});
    check(f.chain.AppBridgeDigest()==plannedState && f.chain.UtxoDigest()==plannedUtxo,"rollback restores exact unpaid reserve and sponsor context");
    ++paid.header.timestamp; mine(paid); admit(f.chain,paid); save(out/(std::to_string(paid.height)+".block"),paid);
    check(f.chain.AppBridgeDigest()==paidState && f.chain.UtxoDigest()==paidUtxo,"alternate mined inclusion pays once with identical accounting");
    { veld::Blockchain restarted;
      for(uint64_t h=0;h<=f.chain.Height();++h)
          admit(restarted,load((h<=702?corpus:out)/(std::to_string(h)+".block"),h));
      check(restarted.AppBridgeDigest()==paidState&&restarted.UtxoDigest()==paidUtxo&&
            restarted.GetUTXO(signedTx.GetTxID(),1)->value==proof.leaf.gross,
            "cold replay authenticates serialized payout and exact paid state"); }
    std::ofstream result(out/"result.json");
    result<<"{\"status\":\"PASS_UNSIGNED_NATIVE_PAYOUT_PLANNER\",\"checks\":"<<checks
          <<",\"plan\":\""<<hex(plan.id())<<"\",\"gross\":"<<plan.gross<<",\"fee\":"<<plan.fee
          <<",\"parent_height\":"<<plan.selected.parent.height<<",\"paid_height\":"<<paid.height
          <<",\"paid_tx\":\""<<hex(signedTx.GetTxID())<<"\",\"real_signatures\":true,\"real_veldhash\":true,\"real_funds\":false}\n";
    result.close(); need(bool(result),"payout receipt saved");
    std::cout<<"RESULT "<<checks<<" checks passed\n"; return 0;
} catch(const std::exception& e) { std::cerr<<"FAIL "<<e.what()<<'\n'; return 1; } }
