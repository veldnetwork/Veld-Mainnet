#pragma once
#include "core/mempool.h"

namespace veld {
// Private relay transport. Only already signed checkpoint/payout transactions
// enter ordinary native validation and the ordinary mempool here.
struct AppchainParentTransaction {
    Hash256 genesis{};
    app::bridge::Anchor parent;
    app::Id descriptor{}, bridge{};
    uint64_t fee = 0;
    app::Bytes bytes;
    static constexpr size_t PREFIX_BYTES = 32 + 40 + 48 + 48 + 8 + 4;

    app::Bytes Encode() const {
        app::Writer out;out.raw(genesis);parent.write(out);out.raw(descriptor);out.raw(bridge);
        out.n(fee,8);out.str(bytes,Mempool::MAX_RELAY_TX_BYTES);return out.b;
    }
    static AppchainParentTransaction Decode(const app::Bytes& raw) {
        app::need(raw.size()>PREFIX_BYTES && raw.size()<=PREFIX_BYTES+Mempool::MAX_RELAY_TX_BYTES,
                  "bounded parent transaction request required");
        app::Reader in{raw};AppchainParentTransaction value;const auto genesis=in.raw(32);
        std::copy(genesis.begin(),genesis.end(),value.genesis.begin());
        value.parent=app::bridge::Anchor::read(in);value.descriptor=in.id();value.bridge=in.id();
        value.fee=in.n(8);value.bytes=in.str(Mempool::MAX_RELAY_TX_BYTES);in.end();
        app::need(value.Encode()==raw,"canonical parent transaction request required");return value;
    }
};

struct AppchainParentTransactionAdmission {
    Transaction transaction;
    bool duplicate = false;
};

// The caller retains the native consensus sequencer through admission and
// network handoff. There is no signing, skipped validation or fee estimation.
inline AppchainParentTransactionAdmission AdmitAppchainParentTransaction(
    const Blockchain::ConsensusTransitionGuard&, Blockchain& chain, Mempool& pool,
    const AppchainParentTransaction& request) {
    using namespace app;
    const auto view=chain.AppBridgeReadView();
    need(request.genesis==view.genesis() && request.parent==view.anchor() &&
         request.parent.height<UINT32_MAX && AppchainBridgeActive(request.parent.height+1),
         "current activated native parent required for settlement relay");
    need(request.descriptor!=Id{} && request.bridge!=Id{} && request.fee==MIN_TX_FEE &&
         AppchainBridgeDescriptorAllowed(request.descriptor),"exact active bridge identity and fee required");
    const auto found=view.state().records.find(request.bridge);
    need(found!=view.state().records.end() && found->second.committee.id()==request.descriptor &&
         found->second.committee.parentGenesis==request.genesis,"registered native bridge descriptor differs");
    Transaction tx;
    need(!request.bytes.empty() && request.bytes.size()<=Mempool::MAX_RELAY_TX_BYTES &&
         Transaction::Deserialize(request.bytes,0,tx)==request.bytes.size() && tx.Serialize()==request.bytes &&
         tx.GetTxID()==Hash256d(request.bytes) && !tx.IsCoinbase() && !tx.outputs.empty() &&
         tx.outputs.front().value==0,"canonical signed native settlement transaction required");
    const auto payload=MarkerOpReturnPayload(tx.outputs.front().script_pubkey);
    need(payload.starts_with(bridge::PREFIX) &&
         IsCanonicalMarkerOpReturn(tx.outputs.front().script_pubkey,payload),"canonical native bridge marker required");
    Bytes marker(payload.begin()+bridge::PREFIX.size(),payload.end());Reader command{marker};
    const auto operation=command.n(1);
    need((operation==2 || operation==3 || operation==5) && command.id()==request.bridge,
         "only exact checkpoint proposal, finalization or payout may be relayed");
    uint64_t inputs=0,outputs=0;
    for(const auto& input:tx.inputs){
        const auto coin=chain.GetUTXO(input.prev_tx_hash,input.prev_out_index);
        need(coin.has_value(),"settlement input must exist on the canonical parent");credit(inputs,coin->value);
    }
    for(const auto& output:tx.outputs)credit(outputs,output.value);
    need(inputs>=outputs && inputs-outputs==request.fee,"exact actual settlement fee differs");
    // Add returns DUPLICATE before expensive validation; independently check
    // the current canonical transition and real signatures on that path too.
    need(chain.ValidateTransactionLocking(tx),"signed settlement failed full native validation");
    const auto result=pool.Add(tx,request.fee,static_cast<uint32_t>(request.parent.height),chain);
    need(result==Mempool::AddResult::ACCEPTED || result==Mempool::AddResult::DUPLICATE,
         "native settlement mempool admission refused");
    const auto retained=pool.GetTransaction(HashToHex(tx.GetTxID()));
    if(!retained || retained->Serialize()!=request.bytes)
        throw std::runtime_error("admitted settlement readback failed; outcome review required");
    return {tx,result==Mempool::AddResult::DUPLICATE};
}
} // namespace veld
