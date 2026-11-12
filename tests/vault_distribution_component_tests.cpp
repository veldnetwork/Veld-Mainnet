#include "core/blockchain.h"
#include <iostream>
#include <stdexcept>
using namespace veld;
int main() {
    size_t checks = 0;
    auto check = [&](bool ok) {
        if (++checks && !ok)
            throw std::runtime_error("vault distribution case " + std::to_string(checks));
    };
    try {
        static_assert(VAULT_RESERVE_ACTIVATION_HEIGHT != 0);
        Blockchain chain;
        chain.SetStakingActivationUnits(
            0); // Component-only activation, not an earned-funds fixture.
        const auto first = GenerateKeyPair(false), second = GenerateKeyPair(false);
        const auto boundary = (VAULT_RESERVE_ACTIVATION_HEIGHT / VAULT_DISTRIBUTION_INTERVAL + 1) *
                              VAULT_DISTRIBUTION_INTERVAL;
        const auto vault_script = AddressToScript(VaultAddressAtHeight(boundary));
        const uint64_t balance = 21'000 * VELD_UNITS, budget = 1000 * VELD_UNITS;
        auto outputs = [&](uint64_t available, uint64_t fee,
                           std::map<std::string, uint64_t> weights) {
            return chain.ComputeExpectedVaultDistribution(boundary, available, fee,
                                                          300 * VELD_UNITS, weights);
        };
        auto paid = [](const auto& out, const auto& script) {
            uint64_t sum = 0;
            for (const auto& row : out)
                if (row.first == script)
                    sum += row.second;
            return sum;
        };
        auto sum = [](const auto& out) {
            uint64_t total = 0;
            for (const auto& row : out)
                total += row.second;
            return total;
        };
        auto equal = outputs(balance, 0, {{first.address, 1}, {second.address, 1}});
        check(paid(equal, first.GetP2PKHScript()) == budget / 2);
        check(paid(equal, second.GetP2PKHScript()) == budget / 2);
        check(paid(equal, vault_script) == balance - budget && sum(equal) == balance);
        auto whale = outputs(balance, 0, {{first.address, 1}});
        check(paid(whale, first.GetP2PKHScript()) == 750 * VELD_UNITS);
        check(paid(whale, vault_script) == balance - 750 * VELD_UNITS && sum(whale) == balance);
        auto absent = outputs(balance, 0, {});
        check(absent.size() == 1 && paid(absent, vault_script) == balance);
        auto fee = outputs(balance + 111, 111, {{first.address, 1}, {second.address, 1}});
        check(fee == equal && sum(fee) + 111 == balance + 111);
        check(outputs(balance, balance, {{first.address, 1}}).empty());
        check(outputs(10, 0, {{first.address, 1}}) == (decltype(equal){{vault_script, 10}}));
        auto rounded = outputs(balance + 1, 0, {{first.address, 1}, {second.address, 2}});
        check(sum(rounded) == balance + 1);
        check(paid(rounded, vault_script) >= VAULT_RESERVE_TARGET_UNITS);
        chain.SetBondYieldWeightFn([](uint64_t) { return 1; });
        auto escrow = outputs(balance, 0, {{first.address, 1}});
        check(paid(escrow, first.GetP2PKHScript()) == budget / 2);
        check(paid(escrow, AddressToScript(BOND_YIELD_ESCROW)) == budget / 2);
        check(paid(escrow, AddressToScript(STAKE_VAULT_ADDRESS)) == 0 && sum(escrow) == balance);
        chain.SetStakingActivationUnits(UINT64_MAX);
        check(outputs(balance, 0, {{first.address, 1}}) ==
              (decltype(equal){{vault_script, balance}}));
        std::cout << "PASS vault recipient/conservation/escrow checks=" << checks << '\n';
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
