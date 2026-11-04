#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1

#include "consensus/validators.h"
#include <cassert>
#include <iostream>

using namespace veld;

int main() {
    static_assert(!VALIDATOR_SYSTEM_ALWAYS_ACTIVE);
    const std::string key(3904, 'a');
    const auto address = ValidatorRegistry::PubkeyToAddress(HexToBytes(key));
    ValidatorRegistry registry;
    const auto empty = registry.SnapshotState();
    auto reason = [&](uint64_t height, uint64_t total) {
        return registry.RegistrationPreparationError(key, address, height, total);
    };
    for (uint64_t height :
         {CONSENSUS_SECURITY_UPGRADE_HEIGHT - 1, CONSENSUS_SECURITY_UPGRADE_HEIGHT,
          CONSENSUS_SECURITY_UPGRADE_HEIGHT + 1}) {
        assert(!reason(height, VALIDATOR_UNLOCK_STAKED - 1).empty());
        assert(reason(height, VALIDATOR_UNLOCK_STAKED).empty());
        assert(reason(height, VALIDATOR_UNLOCK_STAKED + 1).empty());
    }
    assert(!registry
                .RegistrationPreparationError(std::string(3904, 'A'), address, 5000,
                                              VALIDATOR_UNLOCK_STAKED)
                .empty());
    auto state = empty;
    state.last_op_height[address] = 5000;
    registry.RestoreState(state);
    assert(!reason(5000 + VALIDATOR_OP_COOLDOWN_BLOCKS - 1, VALIDATOR_UNLOCK_STAKED).empty());
    assert(reason(5000 + VALIDATOR_OP_COOLDOWN_BLOCKS, VALIDATOR_UNLOCK_STAKED).empty());
    state = empty;
    state.slashed_pubkeys.insert(key);
    registry.RestoreState(state);
    assert(!reason(6000, VALIDATOR_UNLOCK_STAKED).empty());
    registry.RestoreState(empty);
    registry.TestInjectValidatorBond(key, address, MIN_VALIDATOR_STAKE);
    assert(!reason(6000, VALIDATOR_UNLOCK_STAKED).empty());
    registry.RestoreState(empty);
    assert(reason(6000, VALIDATOR_UNLOCK_STAKED).empty());
    state = empty;
    ValidatorRecord prior;
    prior.pubkey_hex = key;
    prior.address = address;
    prior.active = false;
    prior.bond_custodial = true;
    prior.bond_units = MIN_VALIDATOR_STAKE;
    prior.deregistered_at_height = 5900;
    prior.principal_settled_at = 6000;
    state.validators[key] = prior;
    registry.RestoreState(state);
    assert(!reason(6000, VALIDATOR_UNLOCK_STAKED).empty());
    assert(reason(6001, VALIDATOR_UNLOCK_STAKED).empty());
    state.bond_yield_escrow[key].push_back({5900, 1});
    registry.RestoreState(state);
    assert(!reason(6001, VALIDATOR_UNLOCK_STAKED).empty());
    registry.RestoreState(empty);
    std::cout << "PASS validator_registration_readiness_tests\n";
}
