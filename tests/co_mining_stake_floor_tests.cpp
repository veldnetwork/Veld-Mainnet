// In-memory eligibility and payout fixtures; no sockets or persistent data.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_PROTOCOL_UPGRADE_TEST_HEIGHT 3840
#include "core/blockchain.h"
#include "consensus/staking.h"
#include <iostream>
#include <stdexcept>

using namespace veld;
static_assert(MIN_STAKE_UNITS == 1000 * VELD_UNITS);
static_assert(NMS_MIN_BOND_UNITS == 1000 * VELD_UNITS);
namespace {
unsigned checks = 0;
void Check(bool value, const std::string& message) {
    ++checks;
    if (!value) throw std::runtime_error(message);
}
}

int main() {
    try {
        Blockchain chain;
        StakingLedger staking;
        std::vector<uint8_t> script{0x76,0xa9,0x14};
        script.insert(script.end(),20,0x42);
        script.push_back(0x88);script.push_back(0xac);
        const auto address=ScriptToAddress(script);
        Check(!address.empty(),"valid disposable payout script");
        uint64_t stake=0;
        chain.SetNmsStakeQuery([&](const std::string& owner) {
            Check(owner==address,"eligibility resolves the expected owner");
            return stake;
        });
        chain.SetTotalSupplyForTesting(STAKING_UNLOCK_SUPPLY);
        chain.NmsCreditScript(BytesToHex(script));
        Hash256 previous{};previous[0]=0x53;
        const auto pool_script=AddressToScript(POOL_ADDRESS);
        const uint64_t pool_amount=10*VELD_UNITS+3;
        const auto digest=chain.NmsExtendedDigest();
        for (const uint64_t height:{2879ULL,2880ULL,3839ULL,3840ULL,3841ULL,3900ULL}) {
            const uint64_t ordinary=(height>=3840?500:1000)*VELD_UNITS;
            Check(staking.GetEffectiveMinStake(height)==ordinary,
                  "ordinary stake minimum must follow its own activation");
            for (const uint64_t amount:{0ULL,499ULL*VELD_UNITS,500ULL*VELD_UNITS,
                                       1000ULL*VELD_UNITS-1,1000ULL*VELD_UNITS,
                                       1000ULL*VELD_UNITS+1}) {
                stake=amount;
                const bool eligible=amount>=1000*VELD_UNITS;
                Check(chain.NmsBondSatisfied(script,height)==eligible,
                      "co-mining stake verdict at height "+std::to_string(height)+
                      " for "+std::to_string(amount)+" units");
                const auto outputs=chain.ComputeExpectedPoolOutputs(previous,pool_amount,height);
                uint64_t paid=0,total=0;
                for (const auto& [recipient,value]:outputs) {
                    Check(recipient==script || recipient==pool_script,"payout category");
                    total+=value;if(recipient==script)paid+=value;
                }
                Check(total==pool_amount,"payout conservation");
                Check((paid>0)==eligible,"lottery payout uses the same 1000 VELD floor");
                Check(chain.NmsExtendedDigest()==digest,"eligibility reads preserve credits");
            }
        }
        Check(!chain.NmsBondSatisfied({0x6a},3840),"malformed payout script rejected");
        std::cout<<"PASS co_mining_stake_floor_tests checks="<<checks
                 <<" ordinary_after=500 lottery_before=1000 lottery_after=1000\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr<<"FAIL "<<error.what()<<'\n';return 1;
    }
}
