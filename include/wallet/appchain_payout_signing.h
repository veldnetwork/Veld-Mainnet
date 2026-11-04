#pragma once
#include "appchain_payout.h"
#include "../crypto/veld_signing.h"

namespace veld {
namespace appchain_payout_detail {
inline PreparedAppchainPayout CurrentReviewedLocked(
    const Blockchain::ConsensusTransitionGuard& guard, const Blockchain& chain,
    const PreparedAppchainPayout& original, const std::vector<app::bridge::Proof>& proofs,
    const app::Id& approvedPlan, uint64_t approvedFeeBudget) {
    using namespace app;
    need(approvedPlan != Id{} && approvedPlan == original.id() &&
         approvedFeeBudget == original.feeBudget, "exact original payout authorization required");
    need(chain.AppBridgeCanonical(original.selected.parent,original.selected.parentGenesis),
         "original payout planning parent is no longer canonical");
    auto selected = original.selected;
    selected.parent = chain.AppBridgeReadView().anchor();
    const auto current = PrepareLocked(guard,chain,selected,proofs,original.sponsorScript,
                                       original.sponsorInputs,original.feeBudget,&original.reserveInputs);
    // Advancing the parent may change the plan's observation digest. It cannot
    // authorize any replacement spend or a different bridge transition.
    need(current.transaction.Serialize() == original.transaction.Serialize() &&
         current.withdrawals == original.withdrawals &&
         current.reserveInputs == original.reserveInputs && current.sponsorInputs == original.sponsorInputs &&
         current.gross == original.gross && current.fee == original.fee &&
         current.reserveInput == original.reserveInput && current.reserveChange == original.reserveChange &&
         current.sponsorInput == original.sponsorInput && current.sponsorChange == original.sponsorChange,
         "current payout differs from original recipients, inputs, reserves, change or fee");
    return current;
}

inline void VerifySignedLocked(const Blockchain& chain, const PreparedAppchainPayout& plan,
                               const Transaction& signedTransaction) {
    using namespace app;
    const auto raw = signedTransaction.Serialize();
    need(raw.size() <= Mempool::MAX_RELAY_TX_BYTES &&
         signedTransaction.GetTxID() == Hash256d(raw), "signed payout identity or relay size differs");
    auto unsignedCopy = signedTransaction;
    need(unsignedCopy.inputs.size() == plan.transaction.inputs.size(), "signed payout input count differs");
    for (size_t i = 0; i < unsignedCopy.inputs.size(); ++i) {
        const auto& script = unsignedCopy.inputs[i].script_sig;
        need(i < plan.reserveInputs.size() ? script.empty() : !script.empty(),
             "signed payout reserve or sponsor authorization differs");
        unsignedCopy.inputs[i].script_sig.clear();
    }
    unsignedCopy.InvalidateTxIDCache();
    need(unsignedCopy.Serialize() == plan.transaction.Serialize(),
         "signed payout differs from reviewed inputs, outputs or operation");
    need(chain.ValidateTransactionLocking(signedTransaction),
         "signed payout failed current native transaction validation");
}
} // namespace appchain_payout_detail

// A caller must hold its durable reservation and supply the explicitly reviewed
// plan identity and fee budget. This function has no key loading, listener,
// scheduler or broadcast path; the supplied sponsor key signs ordinary inputs
// only. The finalized withdrawal proofs authorize the protected reserve inputs.
inline Transaction SignReviewedAppchainPayout(
    const Blockchain& chain, const PreparedAppchainPayout& plan,
    const std::vector<app::bridge::Proof>& proofs, const app::Id& approvedPlan,
    uint64_t approvedFeeBudget, const RealKeyPair& sponsor) {
    using namespace app;
    need(approvedPlan != Id{} && approvedPlan == plan.id() && approvedFeeBudget == plan.feeBudget,
         "exact payout plan and fee approval required");
    need(sponsor.GetP2PKHScript() == plan.sponsorScript, "selected sponsor key differs");
    auto guard = chain.AcquireConsensusTransitionGuard();
    const auto current = appchain_payout_detail::PrepareLocked(
        guard,chain,plan.selected,proofs,plan.sponsorScript,plan.sponsorInputs,plan.feeBudget);
    need(current.id() == approvedPlan, "payout changed before signing; renewed review required");
    auto transaction = current.transaction;
    transaction.InvalidateTxIDCache();
    for (size_t i = current.reserveInputs.size(); i < transaction.inputs.size(); ++i)
        transaction.inputs[i].script_sig = sponsor.SignInput(transaction,i,current.sponsorScript).script_sig;
    transaction.InvalidateTxIDCache();
    appchain_payout_detail::VerifySignedLocked(chain,current,transaction);
    return transaction;
}

// Repeat immediately before a separately authorized broadcast. A saved signed
// transaction does not authorize a changed parent, checkpoint, payout or fee.
inline void RecheckSignedAppchainPayout(
    const Blockchain& chain, const PreparedAppchainPayout& plan,
    const std::vector<app::bridge::Proof>& proofs, const app::Id& approvedPlan,
    uint64_t approvedFeeBudget, const Transaction& transaction) {
    using namespace app;
    need(approvedPlan != Id{} && approvedPlan == plan.id() && approvedFeeBudget == plan.feeBudget,
         "exact signed payout approval required");
    auto guard = chain.AcquireConsensusTransitionGuard();
    const auto current = appchain_payout_detail::PrepareLocked(
        guard,chain,plan.selected,proofs,plan.sponsorScript,plan.sponsorInputs,plan.feeBudget);
    need(current.id() == approvedPlan, "signed payout context changed; renewed review required");
    appchain_payout_detail::VerifySignedLocked(chain,current,transaction);
}

// This separate path preserves the original reviewed spend during ordinary
// canonical parent advancement. The strict exact-parent APIs above retain
// their existing behavior. A changed transition or input still stops signing.
inline Transaction SignReviewedAppchainPayoutAtCurrentParent(
    const Blockchain& chain, const PreparedAppchainPayout& plan,
    const std::vector<app::bridge::Proof>& proofs, const app::Id& approvedPlan,
    uint64_t approvedFeeBudget, const RealKeyPair& sponsor) {
    app::need(sponsor.GetP2PKHScript() == plan.sponsorScript, "selected payout sponsor key differs");
    auto guard = chain.AcquireConsensusTransitionGuard();
    const auto current = appchain_payout_detail::CurrentReviewedLocked(
        guard,chain,plan,proofs,approvedPlan,approvedFeeBudget);
    auto transaction = current.transaction;transaction.InvalidateTxIDCache();
    for (size_t i = current.reserveInputs.size(); i < transaction.inputs.size(); ++i)
        transaction.inputs[i].script_sig = sponsor.SignInput(transaction,i,current.sponsorScript).script_sig;
    transaction.InvalidateTxIDCache();
    appchain_payout_detail::VerifySignedLocked(chain,current,transaction);
    return transaction;
}

inline void RecheckSignedAppchainPayoutAtCurrentParent(
    const Blockchain& chain, const PreparedAppchainPayout& plan,
    const std::vector<app::bridge::Proof>& proofs, const app::Id& approvedPlan,
    uint64_t approvedFeeBudget, const Transaction& transaction) {
    auto guard = chain.AcquireConsensusTransitionGuard();
    const auto current = appchain_payout_detail::CurrentReviewedLocked(
        guard,chain,plan,proofs,approvedPlan,approvedFeeBudget);
    appchain_payout_detail::VerifySignedLocked(chain,current,transaction);
}
} // namespace veld
