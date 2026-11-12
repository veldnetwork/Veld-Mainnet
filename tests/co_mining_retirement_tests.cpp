// Isolated monetary/sunset checks; injected state is used only for the final
// lottery payout oracle. Durable funded replay is qualified separately.
#include "core/blockchain.h"
#include "network/subsidy_view.h"
#include <iostream>
#include <stdexcept>
using namespace veld;
static unsigned checks = 0;
static void Check(bool value, const char* message) {
    ++checks;
    if (!value)
        throw std::runtime_error(message);
}
int main() {
    try {
        constexpr bool enabled = SUBSIDY_ACTIVATION_HEIGHT != 0;
        static_assert(NMS_MIN_BOND_UNITS == 1000ULL * VELD_UNITS);
        for (uint64_t height :
             std::vector<uint64_t>{0ULL, 3999ULL, 4000ULL, 700799ULL, 700800ULL, 700801ULL,
                                   700900ULL, 1401600ULL, 1401601ULL, 2102401ULL, UINT64_MAX}) {
            const bool retired = enabled && height >= 700801;
            Check(CoMiningRetired(height) == retired,
                  "retirement boundary or inactive public policy");
            Check(CoMiningPayoutDue(height) == (height > 0 && height % 100 == 0 && !retired),
                  "final draw boundary");
            for (uint64_t headroom : {0ULL, 1ULL, 2ULL, 3ULL, 17ULL, 1000000000ULL})
                for (uint64_t fees : {0ULL, 1ULL, 17ULL, 100000ULL, 10000000000ULL}) {
                    const auto value = ComputeCoinbaseAllocation(
                        height, ScheduledBlockSubsidy(height), MAX_SUPPLY_UNITS - headroom, fees);
                    Check(value.has_value(), "valid reward refused");
                    const auto& a = *value;
                    Check(a.miner + a.pool + a.vault + a.endorsement == a.subsidy + fees,
                          "reward conservation");
                    Check(a.subsidy <= headroom, "supply cap exceeded");
                    if (retired) {
                        Check(a.pool == 0, "retired co-mining received issuance");
                        if (headroom == 0)
                            Check(a.miner == fees && a.vault == 0 && a.endorsement == 0,
                                  "post-cap miner fees");
                        else if (height % 100 == 0)
                            Check(a.vault == a.subsidy && a.miner == fees && a.endorsement == 0,
                                  "vault subsidy and miner fee separation");
                        else
                            Check(a.vault == a.subsidy / 5 && a.endorsement == a.subsidy / 5 &&
                                      a.miner == a.subsidy - 2 * (a.subsidy / 5) + fees,
                                  "60/20/20 with integer remainder to miner");
                    }
                }
        }
        Check(CoMiningRetirementHeight() == (enabled ? 700801 : 0),
              "inactive schedule advertised as activated");
        if (enabled) {
            Blockchain chain;
            chain.SetTotalSupplyForTesting(STAKING_UNLOCK_SUPPLY);
            const auto key = GenerateKeyPair(false);
            const auto script = key.GetP2PKHScript();
            chain.SetNmsStakeQuery([](const std::string&) { return NMS_MIN_BOND_UNITS; });
            chain.NmsCreditScript(BytesToHex(script));
            UTXO reserve;
            reserve.tx_hash = Hash256d("isolated sunset reserve");
            reserve.script_pubkey = AddressToScript(POOL_ADDRESS);
            reserve.value = 123456789;
            chain.TestInjectUTXO(reserve);
            const auto before = chain.NmsExtendedDigest();
            const auto outputs = chain.ComputeExpectedPoolOutputs(Hash256{}, reserve.value, 700800);
            Check(outputs.size() == 2, "final draw must preserve one winner and unused slots");
            Check(outputs[0].first == script && outputs[0].second == 24691361,
                  "last earned winning payout changed");
            Check(outputs[1].first == reserve.script_pubkey && outputs[1].second == 98765428,
                  "unassigned reserve changed");
            Block last;
            last.height = 700800;
            last.transactions.push_back(
                Blockchain::BuildCanonicalCoinbase(last.height, STAKING_UNLOCK_SUPPLY, 0, script));
            Transaction payout;
            TxInput input;
            input.prev_tx_hash = reserve.tx_hash;
            input.prev_out_index = reserve.output_index;
            payout.inputs.push_back(input);
            for (const auto& [recipient, amount] : outputs)
                payout.outputs.emplace_back(amount, recipient);
            last.transactions.push_back(payout);
            Check(chain.ValidateExpectedPoolPayout(last),
                  "final normal lottery settlement refused");
            Block after = last;
            after.height = 700900;
            Check(!chain.ValidateExpectedPoolPayout(after), "retired pool reserve could be spent");
            after.transactions.resize(1);
            Check(chain.ValidateExpectedPoolPayout(after),
                  "retirement still requires a redundant roll-forward");
            Check(chain.ComputeExpectedPoolOutputs(Hash256{}, reserve.value, 700900).empty(),
                  "new draw after retirement");
            Check(chain.NmsExtendedDigest() == before &&
                      chain.GetUTXO(reserve.tx_hash, 0)->value == reserve.value,
                  "sunset queries changed earned credits or funds");
            NmsRecord rec;
            Check(chain.ValidateNmsLocking(rec, 700801) ==
                      NmsValidationDisposition::ConsensusInvalid,
                  "new near-miss accepted after retirement");
            const auto view = SubsidyView::Next(700800, STAKING_UNLOCK_SUPPLY);
            Check(view.allocation.endorsement == 31392694 && view.allocation.miner == 94178082,
                  "first halving monetary view");
            Check(view.Fields().find("\"co_mining_retired\":true") != std::string::npos,
                  "missing retirement RPC state");
        }
        std::cout << "PASS_CO_MINING_RETIREMENT checks=" << checks
                  << " activated_fixture=" << enabled << '\n';
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        return 1;
    }
}
