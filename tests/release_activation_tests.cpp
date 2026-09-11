// Execute the production profile's inclusion-height contract without a node.
#include "consensus/security_state_migration.h"
#include "consensus/finality_qc.h"
#include "core/version.h"
#include <iostream>
#include <string_view>

#if !defined(VELD_PUBLIC_RELEASE) || !defined(VELD_MAINNET_POW)
#error "This test requires a public release consensus profile"
#endif

using namespace veld;
static_assert(std::string_view(CLIENT_VERSION) == "3.1.8");
static_assert(CONSENSUS_SECURITY_UPGRADE_HEIGHT == 2880);
static_assert(!ConsensusSecurityUpgradeActive(2879));
static_assert(ConsensusSecurityUpgradeActive(2880));
static_assert(BOND_SETTLEMENT_INTERVAL == 480);
static_assert(TARGET_BLOCK_TIME == 180 && ASERT_HALF_LIFE == 2700);
static_assert(MIN_STAKE_UNITS == 1000 * VELD_UNITS);
static_assert(NMS_MIN_BOND_UNITS == 1000 * VELD_UNITS);
static_assert(MAX_STAKE_UNITS == 10000 * VELD_UNITS);
static_assert(MIN_VALIDATOR_STAKE == 10000 * VELD_UNITS);
static_assert(COINBASE_MATURITY == 100);
static_assert(STAKE_LOCKUP_BLOCKS == 7 * BLOCKS_PER_DAY);
static_assert(finality::qc::BOND_PER_KEY_UNITS == 10000 * VELD_UNITS);
static_assert(finality::qc::REGISTRATION_MATURITY == 480);
static_assert(finality::qc::MIN_VALIDATOR_COUNT == 7);

#ifdef VELD_PUBLIC_MAINNET
static_assert(PROTOCOL_UPGRADE_HEIGHT == 3840);
static_assert(ASERT_ACTIVATION_HEIGHT == 3840);
static_assert(SECURITY_STATE_MIGRATION_HEIGHT == 3840);
#else
static_assert(PROTOCOL_UPGRADE_HEIGHT == 0);
static_assert(ASERT_ACTIVATION_HEIGHT == 0);
static_assert(SECURITY_STATE_MIGRATION_HEIGHT == 0);
#endif

int main() {
    unsigned checks = 0;
    for (uint64_t height : {uint64_t{0}, uint64_t{2879}, uint64_t{2880},
                           uint64_t{3839}, uint64_t{3840}, uint64_t{3841}}) {
#ifdef VELD_PUBLIC_MAINNET
        const bool expected = height >= 3840;
#else
        const bool expected = false;
#endif
        const uint64_t minimum = (expected ? 500 : 1000) * VELD_UNITS;
        if (ProtocolUpgradeActive(height) != expected ||
            SecurityStateMigrationActive(height) != expected ||
            MinimumStakeAtHeight(height) != minimum ||
            (ASERT_ACTIVATION_HEIGHT != 0 && height >= ASERT_ACTIVATION_HEIGHT) != expected) {
            std::cerr << "FAIL coordinated inclusion rules at " << height << '\n';
            return 1;
        }
        checks += 4;
    }
    if (MinimumStakeAtHeight(NextInclusionHeight(3838)) != 1000 * VELD_UNITS ||
        MinimumStakeAtHeight(NextInclusionHeight(3839)) !=
            (PROTOCOL_UPGRADE_HEIGHT ? 500 : 1000) * VELD_UNITS) {
        std::cerr << "FAIL next-inclusion boundary\n";
        return 1;
    }
    std::cout << "PASS release activation height=" << PROTOCOL_UPGRADE_HEIGHT
              << " checks=" << checks + 2 << '\n';
}
