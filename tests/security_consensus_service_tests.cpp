#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define main veld_validator_unused_entry
#include "../src/veld-validator.cpp"
#undef main
#include "network/rpc.h"
#include <cassert>

// Direct local dispatch and the actual daemon admission parser only. The daemon
// entry point, RPC listener, signer and transport are never invoked. Registry
// snapshots are synthetic module fixtures, not a claimed full-chain replay.
int main(int argc, char** argv) {
    assert(argc == 2);
    static_assert(!VALIDATOR_SYSTEM_ALWAYS_ACTIVE);
    constexpr uint64_t H = CONSENSUS_SECURITY_UPGRADE_HEIGHT;
    Blockchain chain;
    Mempool mempool;
    StorageEngine storage(argv[1], MAINNET_MAGIC);
    ValidatorRegistry registry;
    RpcServer rpc(chain, mempool, storage);
    rpc.SetValidators(&registry);
    auto call = [&](const char* method) {
        return rpc.Handle(std::string("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"") +
            method + "\",\"params\":[]}");
    };
    auto info = call("getvalidators");
    assert(jstr(info, "system_active") == "false");
    assert(!validator_operations_available(info));
    registry.SetTotalStaked(VALIDATOR_UNLOCK_STAKED);
    assert(validator_operations_available(call("getvalidators")));
    registry.SetTotalStaked(0);
    Block transition; transition.height = H;
    assert(registry.ProcessBlock(transition, [](const auto&) { return uint64_t{0}; }));
    info = call("getvalidators");
    assert(jstr(info, "system_active") == "false");
    assert(validator_operations_available(info));
    assert(!ValidatorRegistry::RegistrationFloorPermits(true, "REGISTER", H));
    assert(validator_operations_available("{\"system_active\":true}"));
    assert(!validator_operations_available("{\"system_active\":false}"));
    assert(!validator_operations_available("{}"));
    registry.Reset();
    assert(!validator_operations_available(call("getvalidators")));

    namespace fq = veld::finality::qc;
    const std::string pk(3904, '1');
    ValidatorRecord rec;
    rec.pubkey_hex = pk; rec.address = "ordinary-fixture";
    rec.registered_height = 1; rec.active = false;
    rec.bond_custodial = true; rec.bond_units = MIN_VALIDATOR_STAKE;
    for (bool slashed : {false, true}) {
        rec.slashed = slashed;
        rec.slashed_at_height = slashed ? H - 10 : 0;
        rec.deregistered_at_height = slashed ? 0 : H - 10;
        ValidatorRegistry::StateSnapshot state;
        state.validators[pk] = rec;
        state.address_to_pubkey[rec.address] = pk;
        FinalityMembershipRecord membership;
        membership.members.push_back(fq::PubkeyCommit(pk));
        state.finality_membership[H / fq::EPOCH_BLOCKS - 1] = membership;
        registry.RestoreState(state);
        const auto legacy = slashed ? ValidatorRegistry::SlashSettlementBoundary(H - 10) :
            ValidatorRegistry::DeregReturnBoundary(H - 10);
        assert(registry.GetBondLifecycleStatus(pk, legacy - 1).principal_held);
        assert(!registry.GetBondLifecycleStatus(pk, legacy).principal_held);
        assert(registry.ProcessBlock(transition, [](const auto&) { return uint64_t{0}; }));
        const auto upgraded = registry.SnapshotState();
        const auto lifecycle = registry.GetBondLifecycleStatus(pk, legacy);
        assert(lifecycle.principal_held && lifecycle.settlement_boundary >= legacy);
        // Clean exits already use the long evidence window; epoch/settlement
        // alignment can leave their boundary unchanged. First-slash principal
        // is the shortened legacy path that must acquire an extended hold.
        if (slashed) {
            assert(lifecycle.settlement_boundary > legacy);
            assert(registry.GetBondSettlements(legacy).empty());
        }
        assert(registry.GetBondSettlements(lifecycle.settlement_boundary).size() == 1);
        const auto vault = call("getbondvaultinfo");
        assert(jstr(vault, "principal_held") == "true");
        assert(juint(vault, "settlement_boundary") == lifecycle.settlement_boundary);
        assert(jstr(vault, "pending_return") == (slashed ? "false" : "true"));
        Block payment; payment.height = lifecycle.settlement_boundary;
        assert(registry.ProcessBlock(payment, [](const auto&) { return uint64_t{0}; }));
        assert(!registry.GetBondLifecycleStatus(pk, payment.height).principal_held);
        assert(registry.GetBondSettlements(payment.height).empty());
        assert(jstr(call("getbondvaultinfo"), "principal_held") != "true");
        registry.RestoreState(upgraded);
        assert(call("getbondvaultinfo") == vault);
    }
    rec.slashed = true; rec.slashed_at_height = 1; rec.deregistered_at_height = 0;
    ValidatorRegistry::StateSnapshot paid;
    paid.validators[pk] = rec; paid.address_to_pubkey[rec.address] = pk;
    registry.RestoreState(paid);
    assert(registry.ProcessBlock(transition, [](const auto&) { return uint64_t{0}; }));
    assert(jstr(call("getbondvaultinfo"), "principal_held") == "false");
    assert(registry.GetBondSettlements(H).empty());
    std::cout << "PASS: public-floor daemon capability and collateral RPC lifecycle controls\n";
}
