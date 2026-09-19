#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_PROTOCOL_UPGRADE_TEST_HEIGHT 3840
#define VELD_VALIDATOR_REGISTRATION_FORK_TEST_HEIGHT 9000

#include "consensus/validators.h"
#include "wallet/wallet.h"
#include <cassert>
#include <iostream>

using namespace veld;

static Block Operation(const RealKeyPair& key, uint64_t height,
                       const std::string& action, uint64_t bond = 0) {
    Block block;
    block.height = height;
    Transaction tx;
    TxInput input;
    input.prev_tx_hash = Hash256d("disposable fixture " + std::to_string(height));
    tx.inputs.push_back(input);
    const std::string public_key = BytesToHex(
        std::vector<uint8_t>(key.public_key.begin(), key.public_key.end()));
    tx.outputs.emplace_back(0, BuildOpReturnScript(
        std::string(ValidatorRegistry::VAL_PREFIX) + action + "|" + public_key));
    if (bond) tx.outputs.emplace_back(bond, AddressToScript(STAKE_VAULT_ADDRESS));
    tx.inputs[0].script_sig = key.SignInput(tx, 0, key.GetP2PKHScript()).script_sig;
    block.transactions.push_back(tx);
    return block;
}

int main() {
    constexpr uint64_t H = VALIDATOR_REGISTRATION_FORK_HEIGHT;
    static_assert(H == 9000);
    static_assert(MIN_VALIDATOR_STAKE == 10000ULL * VELD_UNITS);
    static_assert(MIN_STAKE_UNITS == 1000ULL * VELD_UNITS);
    static_assert(MinimumStakeAtHeight(H) == 500ULL * VELD_UNITS);
    static_assert(GOVERNANCE_ACTIVATION_BONDED_UNITS == 50000ULL * VELD_UNITS);
    static_assert(ValidatorRegistrationNetworkStakeFloor(H - 1) == 10000ULL * VELD_UNITS);
    static_assert(ValidatorRegistrationNetworkStakeFloor(H) == 0);
    auto zero_stake = [](const std::string&) { return uint64_t{0}; };
    const auto key = GenerateKeyPair(false);
    const auto public_key = BytesToHex(
        std::vector<uint8_t>(key.public_key.begin(), key.public_key.end()));
    ValidatorRegistry registry;
    const auto empty = registry.SnapshotState();
    // Isolated module fixtures: real signatures, synthetic input references.
    // Full UTXO funding and block admission are exercised by the native chain
    // qualification; these cases establish the exact height/floor contract.
    for (uint64_t height : {H - 1, H, H + 1}) {
        for (uint64_t total : {uint64_t{0}, VALIDATOR_UNLOCK_STAKED - 1,
                               VALIDATOR_UNLOCK_STAKED, VALIDATOR_UNLOCK_STAKED + 1}) {
            ValidatorRegistry boundary;
            boundary.SetTotalStaked(total);
            const bool permitted = height >= H || total >= VALIDATOR_UNLOCK_STAKED;
            assert(boundary.RegistrationPreparationError(public_key, key.address, height, total).empty() == permitted);
            assert(boundary.IsValidatorSystemActive(height) == permitted);
            assert(boundary.ProcessBlock(Operation(key, height, "REGISTER", MIN_VALIDATOR_STAKE), zero_stake));
            const auto applied = boundary.SnapshotState();
            assert(applied.validators.contains(public_key) == permitted);
            if (permitted) {
                assert(applied.validators.at(public_key).bond_units == MIN_VALIDATOR_STAKE);
                assert(applied.validators.at(public_key).bond_custodial);
            }
        }
    }
    assert(!registry.RegistrationPreparationError(public_key, key.address, H - 1, 0).empty());
    assert(registry.RegistrationPreparationError(public_key, key.address, H, 0).empty());
    assert(!registry.IsValidatorSystemActive(H - 1));
    assert(registry.IsValidatorSystemActive(H));

    const auto register_at_fork = Operation(key, H, "REGISTER", MIN_VALIDATOR_STAKE);
    assert(registry.ProcessBlock(register_at_fork, zero_stake));
    const auto registered = registry.SnapshotState();
    const auto record = registered.validators.at(public_key);
    assert(record.active && record.bond_custodial && record.bond_units == MIN_VALIDATOR_STAKE);
    assert(registered.total_staked_units == 0);
    const auto digest = registry.ValidatorsDigest();
    const auto yield_digest = registry.BondYieldEscrowDigest();

    const auto repeat = Operation(key, H + 1, "REGISTER", MIN_VALIDATOR_STAKE);
    assert(!registry.ProcessBlock(repeat, zero_stake));
    assert(registry.ValidatorsDigest() == digest);
    assert(registry.BondYieldEscrowDigest() == yield_digest);
    assert(registry.SnapshotState().total_staked_units == 0);

    registry.RestoreState(empty);
    const auto unfunded = Operation(key, H, "REGISTER", MIN_VALIDATOR_STAKE - 1);
    const auto before = registry.ValidatorsDigest();
    assert(!registry.ProcessBlock(unfunded, zero_stake));
    assert(registry.ValidatorsDigest() == before);
    auto barred = empty;
    barred.slashed_pubkeys.insert(public_key);
    registry.RestoreState(barred);
    const auto barred_digest = registry.ValidatorsDigest();
    assert(!registry.ProcessBlock(register_at_fork, zero_stake));
    assert(registry.ValidatorsDigest() == barred_digest);

    registry.RestoreState(registered);
    const uint64_t dereg_height = H + VALIDATOR_OP_COOLDOWN_BLOCKS;
    assert(registry.ProcessBlock(Operation(key, dereg_height, "DEREGISTER"), zero_stake));
    auto deregistered = registry.SnapshotState();
    assert(!deregistered.validators.at(public_key).active);
    assert(deregistered.validators.at(public_key).bond_units == MIN_VALIDATOR_STAKE);
    assert(deregistered.validators.at(public_key).deregistered_at_height == dereg_height);
    const auto dereg_digest = registry.ValidatorsDigest();
    assert(!registry.ProcessBlock(Operation(key, dereg_height + 1, "REGISTER", MIN_VALIDATOR_STAKE), zero_stake));
    assert(registry.ValidatorsDigest() == dereg_digest);

    registry.RestoreState(empty);
    registry.SetTotalStaked(VALIDATOR_UNLOCK_STAKED);
    assert(registry.ProcessBlock(Operation(key, H - 1, "REGISTER", MIN_VALIDATOR_STAKE), zero_stake));
    const auto legacy_digest = registry.ValidatorsDigest();
    ValidatorRegistry replay;
    replay.SetTotalStaked(VALIDATOR_UNLOCK_STAKED);
    assert(replay.ProcessBlock(Operation(key, H - 1, "REGISTER", MIN_VALIDATOR_STAKE), zero_stake));
    assert(replay.ValidatorsDigest() == legacy_digest);

    registry.RestoreState(empty);
    assert(registry.ProcessBlock(register_at_fork, zero_stake));
    assert(registry.ValidatorsDigest() == digest);
    registry.RestoreState(empty);
    const auto other = GenerateKeyPair(false);
    assert(registry.ProcessBlock(Operation(other, H, "REGISTER", MIN_VALIDATOR_STAKE), zero_stake));
    assert(registry.ValidatorsDigest() != digest);
    registry.RestoreState(empty);
    assert(registry.ProcessBlock(register_at_fork, zero_stake));
    assert(registry.ValidatorsDigest() == digest);
    std::cout << "PASS validator_registration_fork_tests height=9000 module-boundary-only\n";
}
