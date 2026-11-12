#include "consensus/validators.h"
#include "consensus/finality_state.h"
#include "wallet/wallet.h"
#include <iostream>
#include <stdexcept>
using namespace veld;
namespace fq = veld::finality::qc;
static unsigned checks = 0;
static void Check(bool value, const char* reason) {
    ++checks;
    if (!value)
        throw std::runtime_error(reason);
}
static std::string Pk(const RealKeyPair& k) {
    return BytesToHex(std::vector<uint8_t>(k.public_key.begin(), k.public_key.end()));
}
static Block Operation(const RealKeyPair& key, uint64_t height, const std::string& marker) {
    Block b;
    b.height = height;
    Transaction tx;
    TxInput input;
    input.prev_tx_hash = Hash256d("module bond fixture " + std::to_string(height));
    tx.inputs.push_back(input);
    tx.outputs.emplace_back(0, BuildOpReturnScript(marker));
    tx.inputs[0].script_sig = key.SignInput(tx, 0, key.GetP2PKHScript()).script_sig;
    Check(TxVerifiedSignedBy(tx, key.address), "real owner signature");
    b.transactions.push_back(tx);
    return b;
}
static void Apply(ValidatorRegistry& r, const Block& b) {
    Check(r.ProcessBlock(b, [](const auto&) { return uint64_t{0}; }), "module transition");
}
static Block Empty(uint64_t height) {
    Block b;
    b.height = height;
    return b;
}
static std::string Equivocation(const RealKeyPair& key, const Hash256& root, uint64_t target) {
    const auto epoch = fq::EpochOf(target);
    const auto round = fq::CheckpointRound(target);
    dilithium::PublicKey pub{};
    dilithium::SecretKey secret{};
    Check(veld_mldsa65_keypair_from_seed(key.private_key.data(), pub.data(), secret.data()) == 0,
          "evidence signing seed");
    fq::CheckpointRef source{}, a{target, Hash256d("disposable conflict A")},
        b{target, Hash256d("disposable conflict B")};
    const auto sa =
        dilithium::Sign(secret, fq::VotePreimage(fq::NETWORK_ID, HexToHash(GENESIS_HASH), epoch,
                                                 root, fq::Phase::PREVOTE, round, source, a));
    const auto sb =
        dilithium::Sign(secret, fq::VotePreimage(fq::NETWORK_ID, HexToHash(GENESIS_HASH), epoch,
                                                 root, fq::Phase::PREVOTE, round, source, b));
    compat::SecureZero(secret.data(), secret.size());
    Check(ValidatorRegistry::VerifyFinalityVoteSignature(Pk(key), epoch, HashToHex(root), 1, round,
                                                         0, HashToHex(source.hash), target,
                                                         HashToHex(a.hash), BytesToHex(sa)),
          "real conflicting vote signature");
    return std::string(ValidatorRegistry::VAL_PREFIX) + "SLASH_EQUIV|" + Pk(key) + "|" +
           std::to_string(epoch) + "|" + HashToHex(root) + "|1|" + std::to_string(round) + "|0|" +
           HashToHex(source.hash) + "|" + std::to_string(target) + "|" + HashToHex(a.hash) + "|" +
           BytesToHex(sa) + "|0|" + HashToHex(source.hash) + "|" + std::to_string(target) + "|" +
           HashToHex(b.hash) + "|" + BytesToHex(sb) + "|v1";
}
int main() {
    try {
        const auto key = GenerateKeyPair(false), other = GenerateKeyPair(false);
        const auto pk = Pk(key);
        ValidatorRegistry r;
        auto original = r.SnapshotState();
        ValidatorRecord rec;
        rec.pubkey_hex = pk;
        rec.address = key.address;
        rec.registered_height = 1;
        rec.bond_custodial = true;
        rec.bond_units = 10000ULL * VELD_UNITS;
        original.validators[pk] = rec;
        original.address_to_pubkey[key.address] = pk;
        original.total_staked_units = VALIDATOR_UNLOCK_STAKED;
        original.last_op_height[key.address] = 1;
        r.RestoreState(original);
        const bool active = ValidatorBondPolicyActive(4000);
        const auto marker = ValidatorRegistry::BuildReduceBondOp(pk, 1, 5000ULL * VELD_UNITS);
        Apply(r, Operation(key, 3999, marker));
        Check(r.SnapshotState().validators.at(pk).bond_reduction_requested_at == 0,
              "historical request inactive");
        for (const auto& bad : std::vector<std::string>{
                 ValidatorRegistry::BuildReduceBondOp(pk, 2, 5000ULL * VELD_UNITS),
                 ValidatorRegistry::BuildReduceBondOp(pk, 1, 4999ULL * VELD_UNITS),
                 ValidatorRegistry::BuildReduceBondOp(pk, 1, 6000ULL * VELD_UNITS), marker + "|",
                 marker + "|extra",
                 std::string(ValidatorRegistry::VAL_PREFIX) + "REDUCE_BOND|" + pk +
                     "|01|500000000000"}) {
            r.RestoreState(original);
            Apply(r, Operation(key, 4000, bad));
            Check(r.SnapshotState().validators.at(pk).bond_reduction_requested_at == 0,
                  "malformed or wrong term/retained amount refused");
        }
        r.RestoreState(original);
        Apply(r, Operation(other, 4000, marker));
        Check(r.SnapshotState().validators.at(pk).bond_reduction_requested_at == 0,
              "different owner refused");
        r.RestoreState(original);
        Apply(r, Operation(key, 4000, marker));
        Check((r.SnapshotState().validators.at(pk).bond_reduction_requested_at == 4000) == active,
              "inclusion-height gate");
        if (!active) {
            Check(r.GetBondSettlements(47520).empty(),
                  "public inactive candidate cannot pay excess");
            std::cout << "PASS_BOND_REDUCTION_INACTIVE checks=" << checks << '\n';
            return 0;
        }
        const auto pending = r.SnapshotState();
        const auto pending_digest = r.ValidatorsDigest();
        const uint64_t due = 47520;
        Check(ValidatorRegistry::BondReductionBoundary(4000) == due,
              "independent full epoch plus ninety-epoch evidence horizon");
        Check(ValidatorRegistry::BondReductionBoundary(4319) == due,
              "inclusive current epoch last block");
        Check(ValidatorRegistry::BondReductionBoundary(4320) == due + 480,
              "next epoch adds full accountability");
        Check(ValidatorRegistry::BondReductionBoundary(UINT64_MAX) == UINT64_MAX,
              "overflow cannot schedule early return");
        auto status = r.GetBondReductionStatus(pk, 4001);
        Check(status.pending && !status.eligible && status.return_boundary == due &&
                  status.reduction_units == 5000ULL * VELD_UNITS,
              "pending return status");
        Check(pending.validators.at(pk).bond_units == 10000ULL * VELD_UNITS,
              "full collateral remains held");
        Apply(r, Operation(key, 4001, marker));
        Check(r.ValidatorsDigest() == pending_digest,
              "duplicate request cannot extend hold or alter amount");
        Check(r.GetBondSettlements(due - 480).empty() && r.GetBondSettlements(due - 1).empty(),
              "no early payout");
        // Later frozen epochs must preserve evidence but cannot keep extending the
        // old excess forever. Their weight is already capped at the retained bond.
        auto with_later = pending;
        FinalityMembershipRecord membership;
        membership.root = Hash256d("fixture membership");
        membership.members.push_back(fq::PubkeyCommit(pk));
        with_later.finality_membership[80] = membership;
        r.RestoreState(with_later);
        auto payouts = r.GetBondSettlements(due);
        Check(payouts.size() == 1 && payouts[0].kind == BondSettlement::EXCESS_RETURN &&
                  payouts[0].bond_units == 5000ULL * VELD_UNITS &&
                  payouts[0].address == key.address,
              "exact excess to original owner only");
        Apply(r, Empty(due));
        auto returned = r.SnapshotState();
        const auto returned_digest = r.ValidatorsDigest();
        const auto& after = returned.validators.at(pk);
        Check(after.active && !after.slashed && after.bond_units == 5000ULL * VELD_UNITS &&
                  after.registered_height == 1 && after.principal_settled_at == 0 &&
                  after.bond_reduction_settled_at == due,
              "active retained principal and term survive partial settlement");
        Check(r.GetBondSettlements(due).empty() && r.GetBondSettlements(due + 480).empty(),
              "return exactly once");
        Check(r.GetBondLifecycleStatus(pk, due).principal_held,
              "partial return is not a terminal full settlement");
        Check(fq::QualifiedAt(after, due), "retained mature bond still qualifies for finality");
        r.RestoreState(with_later);
        Apply(r, Empty(due));
        Check(r.ValidatorsDigest() == returned_digest, "settlement replay exact");
        r.RestoreState(pending);
        Check(r.ValidatorsDigest() == pending_digest, "rollback restores full held bond");
        auto changed = pending;
        changed.validators[pk].bond_reduction_units -= 1;
        r.RestoreState(changed);
        Check(r.ValidatorsDigest() != pending_digest, "digest commits exact excess");
        changed = pending;
        changed.validators[pk].bond_reduction_requested_at += 1;
        r.RestoreState(changed);
        Check(r.ValidatorsDigest() != pending_digest, "digest commits request height");
        r.RestoreState(pending);
        Apply(r, Operation(key, 4000 + VALIDATOR_OP_COOLDOWN_BLOCKS,
                           ValidatorRegistry::BuildDeregisterOp(pk)));
        Check(r.GetBondReductionStatus(pk, 4300).cancelled,
              "full exit supersedes pending partial return");
        payouts = r.GetBondSettlements(due);
        Check(std::none_of(payouts.begin(), payouts.end(),
                           [](const auto& p) { return p.kind == BondSettlement::EXCESS_RETURN; }),
              "full exit cannot also pay pending partial return");
        const auto full_due = r.GetBondLifecycleStatus(pk).return_boundary;
        payouts = r.GetBondSettlements(full_due);
        Check(payouts.size() == 1 && payouts[0].bond_units == 10000ULL * VELD_UNITS &&
                  payouts[0].kind == BondSettlement::DEREGISTER_RETURN,
              "exit retains full original liability");
        // Actual signed earlier-epoch evidence remains admissible at its inclusive
        // 43,200-block horizon, before the proposed excess can leave custody.
        auto evidence_state = pending;
        evidence_state.finality_membership[8] = membership;
        const auto proof = Equivocation(key, membership.root, 4300);
        r.RestoreState(evidence_state);
        Apply(r, Operation(other, 47500, proof));
        Check(r.SnapshotState().validators.at(pk).slashed_equivocation,
              "earlier vote evidence accepted at inclusive horizon");
        Check(r.SnapshotState().validators.at(pk).bond_units == 10000ULL * VELD_UNITS &&
                  r.GetBondReductionStatus(pk, 47500).cancelled,
              "real evidence preserves full penalty collateral");
        r.RestoreState(evidence_state);
        Apply(r, Operation(other, 47501, proof));
        Check(!r.SnapshotState().validators.at(pk).slashed,
              "expired earlier proof cannot change bond after evidence horizon");
        r.RestoreState(evidence_state);
        Apply(r, Operation(other, due, proof));
        Check(!r.SnapshotState().validators.at(pk).slashed &&
                  r.SnapshotState().validators.at(pk).bond_units == 5000ULL * VELD_UNITS,
              "settlement strictly follows valid earlier evidence");
        for (bool equivocation : {false, true}) {
            auto slashed = pending;
            auto& s = slashed.validators[pk];
            s.active = false;
            s.slashed = true;
            s.slashed_equivocation = equivocation;
            s.slashed_at_height = due - 1;
            r.RestoreState(slashed);
            Check(r.GetBondReductionStatus(pk, due).cancelled,
                  "slash cancels pending partial return");
            Check(r.GetBondSettlements(due).empty(), "no excess return ahead of slash settlement");
            payouts = r.GetBondSettlements(r.GetBondLifecycleStatus(pk).settlement_boundary);
            Check(payouts.size() == 1 && payouts[0].bond_units == 10000ULL * VELD_UNITS &&
                      payouts[0].kind == (equivocation ? BondSettlement::SLASH_EQUIVOCATION
                                                       : BondSettlement::SLASH_CONFISCATE),
                  "whole held collateral remains accountable");
        }
        // Parent-scheduled return precedes a same-block new-period exit. Its later
        // clean exit must return only the retained 5,000, never the old 10,000.
        r.RestoreState(pending);
        Apply(r, Operation(key, due, ValidatorRegistry::BuildDeregisterOp(pk)));
        Check(r.SnapshotState().validators.at(pk).bond_units == 5000ULL * VELD_UNITS,
              "same-boundary exit uses retained collateral");
        payouts = r.GetBondSettlements(r.GetBondLifecycleStatus(pk).return_boundary);
        Check(payouts.size() == 1 && payouts[0].bond_units == 5000ULL * VELD_UNITS,
              "no later full-principal double return");
        r.RestoreState(original);
        auto cooldown = original;
        cooldown.last_op_height[key.address] = 3999;
        r.RestoreState(cooldown);
        Apply(r, Operation(key, 4000, marker));
        Check(!r.GetBondReductionStatus(pk, 4001).pending,
              "request respects existing operation cooldown");
        r.RestoreState(returned);
        Apply(r, Operation(key, due + 480, marker));
        Check(!r.GetBondReductionStatus(pk, due + 480).pending,
              "already returned term cannot request again");
        std::cout << "PASS_BOND_REDUCTION_MODULE checks=" << checks
                  << " registry=injected owner_signatures=real full_evidence_window=43200\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        return 1;
    }
}
