#define VELD_MAINNET_POW 1
#define VELD_PUBLIC_RELEASE 1
#define VELD_PUBLIC_MAINNET 1
#include "consensus/governance.h"
#include "consensus/finality_state.h"
#include <iostream>
using namespace veld;
int main() {
    Blockchain chain;
    StakingLedger staking;
    GovernanceEngine governance(chain, staking);
    ValidatorRegistry validators;
    finality::qc::FinalityState finality;
    std::cout << HashToHex(governance.GovernanceDigest()) << '\n'
              << HashToHex(validators.ValidatorsDigest()) << '\n'
              << HashToHex(finality.Digest()) << '\n';
    ValidatorRegistry::StateSnapshot vs;
    ValidatorRecord rec;
    rec.pubkey_hex = std::string(3904, '1'); rec.address = "fixture";
    rec.bond_custodial = true; rec.bond_units = MIN_VALIDATOR_STAKE;
    rec.registered_height = 10; rec.slashed = true; rec.active = false;
    rec.slashed_at_height = 30; rec.last_finality_vote_height = 25;
    vs.validators[rec.pubkey_hex] = rec;
    vs.address_to_pubkey[rec.address] = rec.pubkey_hex;
    validators.RestoreState(vs);
    GovernanceEngine::StateSnapshot gs;
    Proposal p; p.id = 1; p.proposer = "fixture"; p.title = "Ordinary";
    p.description = "Canonical legacy control"; p.created_at = 10; p.expires_at = 100;
    p.votes["fixture"] = VoteChoice::YES; p.votes_yes = 1;
    gs.next_id = 2; gs.proposals[1] = p; gs.last_vote_block["fixture:1"] = 20;
    governance.RestoreState(gs);
    finality.record.target.height = 20; finality.record.target.hash.fill(2);
    finality.record.carrier.height = 25; finality.record.carrier.hash.fill(3);
    std::cout << HashToHex(governance.GovernanceDigest()) << '\n'
              << HashToHex(validators.ValidatorsDigest()) << '\n'
              << HashToHex(finality.Digest()) << '\n'
              << GovernanceEngine::SerializeProposal(p) << '\n'
              << GovernanceEngine::BuildVoteOp(1, "fixture", VoteChoice::YES, 25, "", "") << '\n';
    // Shared audited/candidate path immediately before the proposed activation.
    // Keep this independent of the candidate-only activation header.
    Block before_upgrade; before_upgrade.height = 1919;
    if (!validators.ProcessBlock(before_upgrade, [](const auto&) { return uint64_t{0}; })) return 1;
    governance.ProcessBlock(before_upgrade, 1919, false);
    std::cout << HashToHex(validators.ValidatorsDigest()) << '\n'
              << HashToHex(governance.GovernanceDigest()) << '\n';
}
