// Read-only diagnosis of released rules. Module-level synthetic block, with a
// real ephemeral signature. No node, network, storage, or real funds are used.
#include "consensus/validators.h"
#include "consensus/staking.h"
#include <cassert>
#include <iostream>

using namespace veld;
int main() {
    static_assert(!VALIDATOR_SYSTEM_ALWAYS_ACTIVE);
    static_assert(MIN_VALIDATOR_STAKE == 10000ULL * VELD_UNITS);
    const auto key = GenerateKeyPair(false);
    const std::vector<uint8_t> public_key(key.public_key.begin(), key.public_key.end());
    const std::string pubkey = BytesToHex(public_key);
    const auto script = AddressToScript(key.address);
    assert(!script.empty());
    const auto operation = ValidatorRegistry::BuildRegisterOp(pubkey);
    std::vector<uint8_t> marker{0x6a, 0x4d,
        static_cast<uint8_t>(operation.size() & 255),
        static_cast<uint8_t>(operation.size() >> 8)};
    marker.insert(marker.end(), operation.begin(), operation.end());
    Transaction tx;
    TxInput input; input.prev_tx_hash.fill(1); input.prev_out_index = 0;
    tx.inputs.push_back(input);
    tx.outputs.emplace_back(MIN_VALIDATOR_STAKE, AddressToScript(STAKE_VAULT_ADDRESS));
    tx.outputs.emplace_back(0, marker);
    tx.inputs[0].script_sig = key.SignInput(tx, 0, script).script_sig;
    assert(TxVerifiedSignedBy(tx, key.address));
    Block block;
    block.height = CONSENSUS_SECURITY_UPGRADE_HEIGHT + 1;
    block.transactions.push_back(tx);
    StakingLedger staking;
    assert(staking.ProcessBlock(block));
    assert(staking.GetTotalStake() == 0);
    ValidatorRegistry no_stake;
    no_stake.SetTotalStaked(staking.GetTotalStake());
    assert(no_stake.ProcessBlock(block, [](const auto&) { return uint64_t{0}; }));
    assert(no_stake.GetActiveValidatorCount() == 0 && !no_stake.IsRegistered(pubkey));
    assert(!no_stake.IsValidatorSystemActive() && no_stake.ExistingValidatorOperationsActive());
    ValidatorRegistry activated;
    activated.SetTotalStaked(VALIDATOR_UNLOCK_STAKED);
    assert(activated.ProcessBlock(block, [](const auto&) { return uint64_t{0}; }));
    assert(activated.IsRegistered(pubkey));
    const auto state = activated.SnapshotState();
    assert(state.validators.at(pubkey).bond_custodial);
    assert(state.validators.at(pubkey).bond_units == MIN_VALIDATOR_STAKE);
    std::cout << "CONFIRMED: signed 10000 VELD bond does not increase ordinary stake; "
              << "registration is ignored at zero ordinary network stake.\n"
              << "CONTROL: identical signed bond registers when ordinary network stake reaches 10000 VELD; "
              << "individual logical stake remains zero.\n"
              << "Scope: public-profile module transition; no mainnet transaction submitted.\n";
}
