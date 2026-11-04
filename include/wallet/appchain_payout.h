#pragma once
#include "appchain_deposit.h"

namespace veld {
// Local operator planning only. Keys, coin reservations and broadcasting are
// deliberately outside this interface; callers must recheck before signing.
struct AppchainPayoutSelection {
    Hash256 parentGenesis{};
    app::Id bridge{}, descriptor{}, child{}, checkpoint{};
    app::bridge::Anchor parent;
    uint64_t transition = 0;
};

struct PreparedAppchainPayout {
    Transaction transaction;
    AppchainPayoutSelection selected;
    app::Id state{};
    std::vector<app::Id> withdrawals;
    std::vector<app::bridge::Outpoint> reserveInputs, sponsorInputs;
    app::Bytes sponsorScript;
    uint64_t gross = 0, fee = 0, feeBudget = 0;
    uint64_t reserveInput = 0, reserveChange = 0, sponsorInput = 0, sponsorChange = 0;

    app::Id id() const {
        app::Writer w;
        w.raw(selected.parentGenesis); w.raw(selected.bridge); w.raw(selected.descriptor);
        w.raw(selected.child); w.raw(selected.checkpoint); selected.parent.write(w);
        w.n(selected.transition,8); w.raw(state);
        for (auto amount : {gross,fee,feeBudget,reserveInput,reserveChange,sponsorInput,sponsorChange})
            w.n(amount,8);
        w.str(sponsorScript,51); w.n(withdrawals.size(),1);
        for (const auto& withdrawal : withdrawals) w.raw(withdrawal);
        for (const auto* points : {&reserveInputs,&sponsorInputs}) {
            w.n(points->size(),1);
            for (const auto& point : *points) point.write(w);
        }
        w.str(transaction.Serialize(),Mempool::MAX_RELAY_TX_BYTES);
        return app::hash("VAPP/native-payout-plan/1",w.b);
    }
};

namespace appchain_payout_detail {
inline bool OrdinaryScript(const app::Bytes& script, uint64_t height) {
    if (!app::bridge::ordinary(script)) return false;
    for (const auto& reserved : {
             AddressToScript(POOL_ADDRESS), AddressToScript(ENDORSEMENT_POOL_ADDRESS),
             AddressToScript(VAULT_ADDRESS), AddressToScript(STAKE_VAULT_ADDRESS),
             AddressToScript(BOND_YIELD_ESCROW), AddressToScript(PoolAddressAtHeight(height)),
             AddressToScript(EndorsementPoolAddressAtHeight(height)),
             AddressToScript(VaultAddressAtHeight(height)),
             AddressToScript(StakeVaultAddressAtHeight(height)),
             AddressToScript(BondYieldEscrowAtHeight(height))})
        if (script == reserved) return false;
    return true;
}

inline PreparedAppchainPayout PrepareLocked(
    const Blockchain::ConsensusTransitionGuard&, const Blockchain& chain,
    const AppchainPayoutSelection& selected, std::vector<app::bridge::Proof> proofs,
    const app::Bytes& sponsorScript, const std::vector<app::bridge::Outpoint>& funding,
    uint64_t feeBudget, const std::vector<app::bridge::Outpoint>* retainedReserves = nullptr) {
    using namespace app;
    const auto view = chain.AppBridgeReadView();
    const auto height = add(view.anchor().height,1);
    need(AppchainBridgeActive(height),"native appchain bridge is not activated");
    need(selected.parentGenesis == view.genesis() && selected.parent == view.anchor(),
         "payout selected parent changed");
    need(selected.bridge != Id{} && selected.descriptor != Id{} && selected.child != Id{} &&
         selected.checkpoint != Id{},"complete payout network selection required");
    const auto found = view.state().records.find(selected.bridge);
    need(found != view.state().records.end(),"payout bridge is not registered");
    const auto& record = found->second;
    need(record.committee.parentGenesis == selected.parentGenesis &&
         record.committee.childGenesis == selected.child &&
         record.committee.id() == selected.descriptor &&
         AppchainBridgeDescriptorAllowed(selected.descriptor),"payout descriptor differs");
    need(selected.transition == add(record.transition,1),"payout transition changed");
    const auto finalized = record.finalized.find(selected.checkpoint);
    need(finalized != record.finalized.end(),"payout checkpoint is not finalized");
    need(!proofs.empty() && proofs.size() <= 32,"bounded withdrawal batch required");
    need(!funding.empty() && funding.size() <= 32 && feeBudget >= MIN_TX_FEE && feeBudget <= MAX,
         "separate bounded fee sponsorship required");
    need(OrdinaryScript(sponsorScript,height),"protocol or reserve funds cannot sponsor payouts");

    PreparedAppchainPayout result;
    result.selected = selected; result.state = view.state().digest();
    result.sponsorScript = sponsorScript; result.sponsorInputs = funding;
    result.fee = MIN_TX_FEE; result.feeBudget = feeBudget;
    std::sort(proofs.begin(),proofs.end(),[](const auto& a,const auto& b){return a.leaf.id()<b.leaf.id();});
    for (const auto& proof : proofs) {
        const auto& leaf = proof.leaf;
        const auto id = leaf.id();
        need((result.withdrawals.empty() || result.withdrawals.back() < id) &&
             !record.paid.contains(id),"duplicate or already paid withdrawal");
        need(leaf.chain == selected.child && leaf.bridge == selected.bridge &&
             leaf.version == record.committee.version && OrdinaryScript(leaf.recipient,height) &&
             proof.root() == finalized->second.checkpoint.withdrawalsRoot,
             "withdrawal proof or recipient differs");
        credit(result.gross,leaf.gross); result.withdrawals.push_back(id);
    }
    std::map<bridge::Outpoint,bridge::Coin> coins;
    auto input = [&](const bridge::Outpoint& point,const app::Bytes& script) {
        const auto coin = chain.GetUTXO(point.tx,point.index);
        need(coin && coin->value > 0 && coin->script_pubkey == script,
             "payout input is unavailable or belongs to another wallet");
        need(coins.emplace(point,bridge::Coin{coin->value,coin->block_height,
                         coin->script_pubkey,coin->is_coinbase}).second,"duplicate payout input");
        TxInput in; in.prev_tx_hash = point.tx; in.prev_out_index = point.index;
        result.transaction.inputs.push_back(in);
        return coin->value;
    };
    const auto reserveScript = bridge::reserveScript(selected.bridge);
    if (retainedReserves) {
        need(!retainedReserves->empty() && retainedReserves->size() <= 32,
             "bounded retained reserve inputs required");
        for (const auto& point : *retainedReserves) {
            const auto found = record.reserves.find(point);
            need(found != record.reserves.end() && input(point,reserveScript) == found->second,
                 "retained payout reserve is unavailable or changed");
            credit(result.reserveInput,found->second); result.reserveInputs.push_back(point);
        }
    } else {
        // Keep only the largest 32 candidates. Small deposits must not prevent
        // an otherwise fundable payout from fitting the reserve-input limit.
        std::set<std::pair<uint64_t,bridge::Outpoint>> candidates;
        for (const auto& [point,value] : record.reserves) {
            candidates.emplace(value,point);
            if (candidates.size() > 32) candidates.erase(candidates.begin());
        }
        for (auto at=candidates.rbegin();at!=candidates.rend();++at) {
            const auto& [value,point] = *at;
            if (result.reserveInput >= result.gross) break;
            need(input(point,reserveScript) == value,"registered reserve amount differs");
            credit(result.reserveInput,value); result.reserveInputs.push_back(point);
        }
    }
    need(result.reserveInput >= result.gross,"payout reserve is insufficient");
    for (const auto& point : funding) credit(result.sponsorInput,input(point,sponsorScript));
    need(result.sponsorInput >= result.fee,"sponsor cannot fund canonical fee");
    result.reserveChange = result.reserveInput-result.gross;
    result.sponsorChange = result.sponsorInput-result.fee;

    Writer command; command.raw(selected.bridge); command.n(selected.transition,8);
    command.raw(selected.checkpoint); command.n(0,8); command.n(proofs.size(),1);
    for (const auto& proof : proofs) proof.write(command);
    result.transaction.outputs.emplace_back(0,bridge::marker(5,command.b));
    for (const auto& proof : proofs)
        result.transaction.outputs.emplace_back(proof.leaf.gross,proof.leaf.recipient);
    if (result.reserveChange) result.transaction.outputs.emplace_back(result.reserveChange,reserveScript);
    if (result.sponsorChange) result.transaction.outputs.emplace_back(result.sponsorChange,sponsorScript);

    bridge::Context context;
    context.height = height; context.genesis = view.genesis();
    context.coin = [&](const bridge::Outpoint& point) -> std::optional<bridge::Coin> {
        const auto at = coins.find(point);
        return at == coins.end() ? std::nullopt : std::optional(at->second);
    };
    context.ordinaryFunding = [&](const app::Bytes& script){return OrdinaryScript(script,height);};
    auto proposed = view.state();
    // Preview may hash the transaction. Keep that cache on a disposable copy,
    // not on the unsigned object which the separate signing step will mutate.
    const auto previewTransaction = result.transaction;
    proposed.apply(previewTransaction,context);
    need(result.transaction.IsValid(),"payout exceeds native transaction bounds");
    need(height < BATCH1_HARDENING_HEIGHT || !result.transaction.HasDustOutput(DUST_THRESHOLD_UNITS),
         "payout or change is below native dust threshold; regroup inputs or withdrawals");
    const auto raw = result.transaction.Serialize().size();
    constexpr size_t growth = offline_signing::kCanonicalInputScriptBytes+2;
    need(raw <= Mempool::MAX_RELAY_TX_BYTES &&
         funding.size() <= (Mempool::MAX_RELAY_TX_BYTES-raw)/growth,"signed payout exceeds relay bounds");
    need(add(result.reserveInput,result.sponsorInput)-result.transaction.TotalOutput() == result.fee,
         "payout fee accounting differs");
    return result;
}
} // namespace appchain_payout_detail

inline PreparedAppchainPayout PrepareAppchainPayout(
    const Blockchain& chain, const AppchainPayoutSelection& selected,
    const std::vector<app::bridge::Proof>& proofs, const app::Bytes& sponsorScript,
    const std::vector<app::bridge::Outpoint>& funding, uint64_t feeBudget) {
    auto guard = chain.AcquireConsensusTransitionGuard();
    return appchain_payout_detail::PrepareLocked(guard,chain,selected,proofs,sponsorScript,funding,feeBudget);
}

inline void RecheckAppchainPayout(const Blockchain& chain, const PreparedAppchainPayout& plan,
                                const std::vector<app::bridge::Proof>& proofs) {
    const auto current = PrepareAppchainPayout(chain,plan.selected,proofs,plan.sponsorScript,
                                             plan.sponsorInputs,plan.feeBudget);
    app::need(current.id() == plan.id(),"payout plan changed; renewed review required");
}
} // namespace veld
