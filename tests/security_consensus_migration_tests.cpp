#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#include "consensus/governance.h"
#include "consensus/finality_state.h"
#include <cassert>
#include <iostream>

// Tiny module-state controls only: no node Start, signatures, keys, network,
// mined blocks or exploit reproduction. Fixtures enter the same value snapshot
// boundaries used by canonical rollback.
using namespace veld;
namespace fq = veld::finality::qc;
Hash256 Tag(uint8_t b) { Hash256 h{}; h.fill(b); return h; }
int main() {
    constexpr uint64_t H = CONSENSUS_SECURITY_UPGRADE_HEIGHT;
    static_assert(H >= 2 * BOND_SETTLEMENT_INTERVAL);
    constexpr uint64_t epoch = H / fq::EPOCH_BLOCKS;
    assert(!ConsensusSecurityUpgradeActive(H-1));
    assert(ConsensusSecurityUpgradeActive(H));
    assert(ConsensusSecurityUpgradeActive(H+1));
    for (const auto* op : {"DEREGISTER", "SLASH", "SLASH_EQUIV", "ENDORSE"}) {
        assert(!ValidatorRegistry::RegistrationFloorPermits(true, op, H-1));
        assert(ValidatorRegistry::RegistrationFloorPermits(true, op, H));
        assert(ValidatorRegistry::RegistrationFloorPermits(false, op, H-1));
    }
    assert(!ValidatorRegistry::RegistrationFloorPermits(true, "REGISTER", H));
    assert(ValidatorRegistry::RegistrationFloorPermits(false, "REGISTER", H));

    const std::string pk(3904, '1');
    ValidatorRecord rec;
    rec.pubkey_hex = pk; rec.address = "ordinary-fixture";
    rec.registered_height = 1; rec.active = false;
    rec.bond_custodial = true; rec.bond_units = MIN_VALIDATOR_STAKE;
    rec.slashed = true; rec.slashed_at_height = H - 10;
    ValidatorRegistry registry;
    ValidatorRegistry::StateSnapshot state;
    state.validators[pk] = rec;
    state.address_to_pubkey[rec.address] = pk;
    FinalityMembershipRecord membership;
    membership.root = Tag(3);
    membership.members.push_back(fq::PubkeyCommit(pk));
    state.finality_membership[epoch - 1] = membership;
    registry.RestoreState(state);
    const auto before = registry.ValidatorsDigest();
    const auto legacy_due = ValidatorRegistry::SlashSettlementBoundary(H - 10);
    assert(legacy_due >= H);
    assert(registry.GetBondSettlements(legacy_due).empty());
    assert(registry.CanAcceptSlashEvidence(pk, H - 10, H));
    Block transition; transition.height = H;
    assert(registry.ProcessBlock(transition, [](const auto&){return uint64_t{0};}));
    const auto migrated = registry.SnapshotState();
    assert(migrated.security_upgrade_active);
    assert(migrated.validators.at(pk).principal_settled_at == 0);
    const auto due = registry.GetBondLifecycleStatus(pk).settlement_boundary;
    const auto last_epoch_height = H - 1;
    assert(due > last_epoch_height + fq::FINALITY_EQUIV_EVIDENCE_WINDOW);
    assert(due % BOND_SETTLEMENT_INTERVAL == 0);
    assert(registry.GetBondSettlements(due).size() == 1);
    assert(registry.GetBondSettlements(due - BOND_SETTLEMENT_INTERVAL).empty());
    assert(!registry.CanAcceptSlashEvidence(pk, due, due));
    Block payment; payment.height = due;
    assert(registry.ProcessBlock(payment, [](const auto&){return uint64_t{0};}));
    const auto paid_state = registry.SnapshotState();
    assert(!paid_state.validators.count(pk) || paid_state.validators.at(pk).principal_settled_at == due);
    assert(registry.GetBondSettlements(due).empty());
    const auto after = registry.ValidatorsDigest();
    registry.RestoreState(migrated);
    assert(registry.GetBondSettlements(due).size() == 1);
    assert(registry.ProcessBlock(payment, [](const auto&){return uint64_t{0};}));
    assert(registry.ValidatorsDigest() == after);
    registry.RestoreState(state);
    assert(registry.ValidatorsDigest() == before);
    state.validators[pk].slashed_at_height = 1;
    registry.RestoreState(state);
    assert(registry.GetBondSettlements(H).empty());
    assert(!registry.CanAcceptSlashEvidence(pk, 1, H));
    assert(registry.ProcessBlock(transition, [](const auto&){return uint64_t{0};}));
    assert(registry.SnapshotState().validators.at(pk).principal_settled_at ==
           ValidatorRegistry::SlashSettlementBoundary(1));

    // Migration distinguishes payouts strictly before H from obligations due
    // exactly at or after H. All offense heights in these value fixtures are
    // before H; no future slash or future frozen membership is injected.
    for (const auto slash_at : {H - BOND_SETTLEMENT_INTERVAL - VALIDATOR_OP_COOLDOWN_BLOCKS,
                                H - VALIDATOR_OP_COOLDOWN_BLOCKS, H - 2}) {
        auto boundary_state = state;
        boundary_state.validators[pk].slashed_at_height = slash_at;
        boundary_state.finality_membership.clear();
        boundary_state.finality_membership[slash_at / fq::EPOCH_BLOCKS] = membership;
        registry.RestoreState(boundary_state);
        const auto old_due = ValidatorRegistry::SlashSettlementBoundary(slash_at);
        Block before_activation; before_activation.height = H - 1;
        assert(registry.ProcessBlock(before_activation, [](const auto&) { return uint64_t{0}; }));
        const auto parent = registry.SnapshotState();
        assert(!parent.security_upgrade_active && parent.validators.at(pk).principal_settled_at == 0);
        assert(registry.ProcessBlock(transition, [](const auto&) { return uint64_t{0}; }));
        const auto active = registry.SnapshotState();
        assert(active.security_upgrade_active);
        assert(active.validators.at(pk).principal_settled_at == (old_due < H ? old_due : 0));
        if (old_due >= H)
            assert(registry.GetBondLifecycleStatus(pk).settlement_boundary > old_due);
        const auto active_digest = registry.ValidatorsDigest();
        Block after_activation; after_activation.height = H + 1;
        assert(registry.ProcessBlock(after_activation, [](const auto&) { return uint64_t{0}; }));
        assert(registry.ValidatorsDigest() == active_digest);
        registry.RestoreState(parent);
        assert(registry.ProcessBlock(transition, [](const auto&) { return uint64_t{0}; }));
        assert(registry.ValidatorsDigest() == active_digest);
    }

    // Multiple retained memberships use the latest liability horizon. Reporter
    // entitlement remains the existing deterministic order, independent of the
    // evidence vector's arrival order; mixed classes retain the equivocation
    // record's reporter. These are value fixtures, not signed evidence.
    auto liability = state;
    liability.security_upgrade_active = true;
    liability.validators[pk].slashed_at_height = H + 1000;
    liability.finality_membership.clear();
    liability.finality_membership[epoch] = membership;
    SlashEvidence first_report, second_report;
    first_report.pubkey_hex = second_report.pubkey_hex = pk;
    first_report.evidence_block = H + 1000;
    second_report.evidence_block = H + 1001;
    first_report.slasher_address = "first-fixture";
    second_report.slasher_address = "second-fixture";
    liability.slashed_evidence = {second_report, first_report};
    registry.RestoreState(liability);
    const auto earlier_due = registry.GetBondLifecycleStatus(pk).settlement_boundary;
    liability.finality_membership[epoch + 1] = membership;
    registry.RestoreState(liability);
    const auto later_due = registry.GetBondLifecycleStatus(pk).settlement_boundary;
    assert(later_due == earlier_due + fq::EPOCH_BLOCKS);
    assert(registry.GetBondSettlements(earlier_due).empty());
    auto settlement = registry.GetBondSettlements(later_due);
    assert(settlement.size() == 1 && settlement[0].slasher_address == "first-fixture");
    std::reverse(liability.slashed_evidence.begin(), liability.slashed_evidence.end());
    registry.RestoreState(liability);
    assert(registry.GetBondSettlements(later_due)[0].slasher_address == "first-fixture");
    liability.validators[pk].slashed_equivocation = true;
    liability.finality_equivocations[pk].slasher_address = "equivocation-fixture";
    registry.RestoreState(liability);
    settlement = registry.GetBondSettlements(later_due);
    assert(settlement.size() == 1 && settlement[0].kind == BondSettlement::SLASH_EQUIVOCATION);
    assert(settlement[0].slasher_address == "equivocation-fixture");

    Blockchain chain;
    StakingLedger staking;
    GovernanceEngine governance(chain, staking);
    Proposal p; p.id = 1; p.title = "Ordinary proposal";
    p.description = "A small lifecycle fixture"; p.proposer = "fixture";
    p.created_at = H - 60; p.expires_at = H + 8000;
    p.status = ProposalStatus::TIMELOCKED; p.timelock_until = H + 1000;
    p.votes["fixture"] = VoteChoice::YES; p.votes_yes = 1;
    p.creation_identity = GovernanceEngine::ProposalCreationIdentity(Tag(5), 0);
    GovernanceEngine::StateSnapshot gs;
    gs.next_id = 3; gs.proposals[1] = p;
    Proposal terminal = p; terminal.id = 2; terminal.status = ProposalStatus::PASSED;
    gs.proposals[2] = terminal; gs.last_vote_block["fixture:1"] = H - 2;
    governance.RestoreState(gs);
    const auto old_gov = governance.GovernanceDigest();
    Block before_activation; before_activation.height = H - 1;
    governance.ProcessBlock(before_activation, H - 1, false);
    assert(governance.GovernanceDigest() == old_gov);
    governance.ProcessBlock(transition, H, false);
    auto restarted = governance.SnapshotState();
    const auto& round = restarted.proposals.at(1);
    assert(round.status == ProposalStatus::OPEN && round.votes.empty());
    assert(round.votes_yes == 0 && round.timelock_until == 0);
    assert(round.created_at == p.created_at && round.vote_round_start == H);
    assert(round.expires_at == H + GOV_VOTE_DURATION_DAYS * BLOCKS_PER_DAY);
    assert(restarted.proposals.at(2).votes_yes == 1);
    assert(restarted.proposals.at(2).status == ProposalStatus::PASSED);
    assert(restarted.last_vote_block.empty());
    const auto identity = GovernanceEngine::VoteIdentity(round);
    assert(GovernanceEngine::CanonicalIdentity(identity));
    assert(governance.VoteIdentityFor(1, H) == identity);
    assert(GovernanceEngine::ProposalCreationIdentity(Tag(5), 1) != p.creation_identity);
    assert(GovernanceEngine::ProposalCreationIdentity(Tag(6), 0) != p.creation_identity);
    Proposal decoded;
    const auto serialized = GovernanceEngine::SerializeProposal(round);
    assert(GovernanceEngine::DeserializeProposal(serialized, decoded));
    assert(GovernanceEngine::VoteIdentity(decoded) == identity);
    auto next_round = decoded; ++next_round.vote_round_start;
    assert(GovernanceEngine::VoteIdentity(next_round) != identity);
    auto incomplete = serialized;
    const auto version = incomplete.find("\"identity_version\":1");
    assert(version != std::string::npos);
    incomplete.replace(version, std::string("\"identity_version\":1").size(),
                       "\"identity_version\":2");
    assert(!GovernanceEngine::DeserializeProposal(incomplete, decoded));
    const auto bound_challenge = GovernanceEngine::BuildVoteChallenge(
        1, VoteChoice::YES, H, identity);
    assert(bound_challenge == GovernanceEngine::GovChainIdPrefix() +
        "GOV_VOTE_V2:1:" + identity + ":yes:@" + std::to_string(H));
    assert(bound_challenge != GovernanceEngine::BuildVoteChallenge(1, VoteChoice::YES, H));
    const auto new_gov = governance.GovernanceDigest();
    governance.RestoreState(gs);
    assert(governance.GovernanceDigest() == old_gov);
    governance.ProcessBlock(transition, H, false);
    assert(governance.GovernanceDigest() == new_gov);
    governance.ProcessBlock(transition, H, false);
    assert(governance.GovernanceDigest() == new_gov);
    Block after_activation; after_activation.height = H + 1;
    governance.ProcessBlock(after_activation, H + 1, false);
    assert(governance.GovernanceDigest() == new_gov);

    fq::FinalityState canonical;
    canonical.record.target = {H - 40, Tag(7)};
    canonical.record.carrier = {H - 20, Tag(8)};
    canonical.OnBlockHeight(H - 1);
    assert(!canonical.security_upgrade_active);
    canonical.OnBlockHeight(H);
    assert(canonical.security_upgrade_active);
    canonical.record.target = {H + 60, Tag(7)};
    canonical.record.carrier = {H + 65, Tag(8)};
    assert(canonical.RequiredReorgAncestor() == H + 60);
    fq::FinalityState candidate = canonical;
    candidate.record.carrier = {H + 66, Tag(9)};
    auto target_present = [&](uint64_t h, const Hash256& hash) {
        return h == H + 60 && hash == Tag(7);
    };
    assert(canonical.CandidateRetainsFinality(candidate, target_present));
    candidate.record = {};
    assert(!canonical.CandidateRetainsFinality(candidate, target_present));
    candidate.record.target = {H + 40, Tag(6)};
    assert(!canonical.CandidateRetainsFinality(candidate, target_present));
    candidate.record.target = {H + 60, Tag(6)};
    assert(!canonical.CandidateRetainsFinality(candidate, target_present));
    candidate = canonical;
    assert(!canonical.CandidateRetainsFinality(candidate,
        [](uint64_t, const Hash256&){return false;}));
    auto legacy = canonical;
    legacy.record.target = {H - 40, Tag(7)}; legacy.record.carrier = {H - 20, Tag(8)};
    assert(legacy.RequiredReorgAncestor() == H - 20);
    assert(!legacy.CandidateRetainsFinality(candidate, target_present));
    const auto finality_digest = canonical.Digest();
    canonical.OnBlockHeight(H + 1);
    assert(canonical.Digest() == finality_digest);
    candidate = canonical;
    candidate.certified_carrier_record = {};
    assert(candidate.Digest() != finality_digest);
    canonical.Reset();
    assert(!canonical.security_upgrade_active && canonical.AnchorAuthorizationRecord().IsNull());
    std::cout << "PASS: consensus migration, terminal principal, registration-only floor, bound governance and finality retention controls H=" << H << '\n';
    std::cout << "module_digests=" << HashToHex(registry.ValidatorsDigest()) << ':'
              << HashToHex(new_gov) << ':' << HashToHex(finality_digest) << '\n';
}
