#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1

#include "consensus/validators.h"
#include "consensus/finality_state.h"
#include "consensus/btcveld_peg_gate.h"
#include <iostream>
#include <stdexcept>

using namespace veld;
namespace fq = veld::finality::qc;
namespace {
size_t checks = 0;
void Check(bool condition, const char* message) {
    ++checks;
    if (!condition) throw std::runtime_error(message);
}
std::string PublicKey(const RealKeyPair& key) {
    return BytesToHex(std::vector<uint8_t>(key.public_key.begin(), key.public_key.end()));
}
}

int main() {
    try {
        static_assert(MIN_VALIDATOR_STAKE == 10000ULL * VELD_UNITS);
        static_assert(fq::MIN_VALIDATOR_COUNT == 7);
        static_assert(fq::BOND_PER_KEY_UNITS == MIN_VALIDATOR_STAKE);
        ValidatorRegistry registry;
        std::vector<RealKeyPair> keys;
        auto state = registry.SnapshotState();
        for (size_t i = 0; i < 7; ++i) {
            keys.push_back(GenerateKeyPair(false));
            const auto key = PublicKey(keys.back());
            ValidatorRecord record;
            record.pubkey_hex = key;
            record.address = keys.back().address;
            record.active = true;
            record.bond_custodial = true;
            record.bond_units = MIN_VALIDATOR_STAKE;
            record.registered_height = 1;
            state.validators.emplace(key, record);
            state.address_to_pubkey.emplace(record.address, key);
        }
        registry.RestoreState(state);
        Check(registry.GetActiveValidatorCount() == 7, "component registry lost a member");
        Check(registry.SnapshotState().total_staked_units == 0, "bonds altered ordinary staking");
        const auto snapshot = [&](uint64_t epoch, bool six) {
            auto selected = state;
            if (six) selected.validators.at(PublicKey(keys.back())).active = false;
            registry.RestoreState(selected);
            return fq::BuildEpochSnapshot(registry, epoch, fq::SnapshotHeightFor(epoch));
        };
        fq::FinalityState finality, replay;
        std::vector<fq::EpochSnapshot> history;
        for (const auto [epoch, six] : std::vector<std::pair<uint64_t,bool>>{
                {20,true}, {21,false}, {22,false}, {23,true}, {24,false}, {25,false}}) {
            const auto current = snapshot(epoch, six);
            Check(fq::SnapshotWellFormed(current), "ordinary snapshot is not canonical");
            Check(fq::SnapshotQualifies(current) == !six, "seven-member threshold changed");
            Check(current.total_weight == (six ? 6 : 7) * MIN_VALIDATOR_STAKE,
                  "snapshot weight differs from bond principal");
            const auto prior = finality.Digest();
            Check(finality.OnEpochBoundary(current), "ordinary epoch refused");
            const auto after = finality.Digest();
            Check(finality.OnEpochBoundary(current) && finality.Digest() == after,
                  "duplicate epoch changed warm-up state");
            Check(prior != after, "new epoch was not committed to state");
            const bool active = epoch == 22 || epoch == 25;
            Check(finality.FinalityActive() == active, "consecutive warm-up changed");
            const auto gate = DeriveBtcVeldPegGate(true, finality.finality_ever_active,
                                                  active, true);
            Check(gate.MintAllowed() == active, "mint gate differs from finality state");
            Check(gate.RedeemAllowed() == (epoch >= 22), "activation latch or completion changed");
            history.push_back(current);
        }
        for (const auto& current : history) Check(replay.OnEpochBoundary(current), "epoch replay failed");
        Check(replay.Digest() == finality.Digest(), "replayed finality digest differs");

        const auto offender = PublicKey(keys.front());
        const auto reporter = keys.back().address;
        constexpr uint64_t slash_height = 60000;
        constexpr uint64_t accrued_height = 59040;
        constexpr uint64_t yield_units = 123456789;
        for (bool equivocation : {false, true}) {
            ValidatorRegistry slashed;
            slashed.TestInjectBondYieldState(offender, keys.front().address, true,
                slash_height, slash_height - 1, reporter, {{accrued_height, yield_units}}, equivocation);
            auto current = slashed.SnapshotState();
            current.security_upgrade_active = true;
            current.state_migration_active = SecurityStateMigrationActive(slash_height);
            slashed.RestoreState(current);
            const auto lifecycle = slashed.GetBondLifecycleStatus(offender, slash_height);
            const auto boundary = lifecycle.settlement_boundary;
            Check(boundary > slash_height + SLASH_EVIDENCE_WINDOW,
                  "principal escaped the complete evidence interval");
            Check(slashed.GetBondSettlements(boundary - 1).empty(), "principal settled early");
            const auto principal = slashed.GetBondSettlements(boundary);
            Check(principal.size() == 1 && principal.front().bond_units == MIN_VALIDATOR_STAKE,
                  "slash principal amount differs");
            const auto kind = equivocation ? BondSettlement::SLASH_EQUIVOCATION
                                           : BondSettlement::SLASH_CONFISCATE;
            Check(principal.front().kind == kind && principal.front().slasher_address == reporter,
                  "slash type or reporter attribution differs");
            const auto yield_boundary = ValidatorRegistry::SlashSettlementBoundary(slash_height);
            Check(slashed.GetBondYieldSettlements(yield_boundary - 1).empty(), "yield confiscated early");
            const auto yield = slashed.GetBondYieldSettlements(yield_boundary);
            Check(yield.size() == 1 && yield.front().kind == kind &&
                  yield.front().bond_units == yield_units && yield.front().slasher_address == reporter,
                  "pending yield lost the slash type, amount or recipient");
            auto settled = slashed.SnapshotState();
            settled.validators.at(offender).principal_settled_at = boundary;
            settled.validators.at(offender).bond_units = 0;
            settled.bond_yield_escrow.erase(offender);
            ValidatorRegistry restored;
            restored.RestoreState(settled);
            Check(restored.GetBondSettlements(boundary).empty() &&
                  restored.GetBondYieldSettlements(yield_boundary).empty(),
                  "restored terminal state can schedule a second settlement");
            Check(!restored.RegistrationPreparationError(offender, keys.front().address,
                  boundary + 1, 0).empty(), "slashed key became eligible for registration");
        }
        std::cout << "{\"status\":\"PASS\",\"checks\":" << checks
                  << ",\"scope\":\"component state, not funded admission or real operators\","
                     "\"production_parameters\":true,\"network_requests\":0,"
                     "\"evidence_signatures_created\":0,\"production_state_used\":false}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
