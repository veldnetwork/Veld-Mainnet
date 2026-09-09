// Predicate boundaries complement the authenticated full-node QC fixture.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_PROTOCOL_UPGRADE_TEST_HEIGHT 3360
#include "core/blockchain.h"
#include <iostream>
#include <stdexcept>

using namespace veld;
int main() {
    size_t checks=0;
    const auto check=[&](bool value,const char* message) {
        ++checks;
        if(!value)throw std::runtime_error(message);
    };
    try {
        auto owner=GenerateKeyPair(true);
        Blockchain chain;
        for(uint64_t height:{3359ULL,3360ULL,3361ULL,3400ULL}) {
            for(uint64_t supply:{STAKING_UNLOCK_SUPPLY,MAX_SUPPLY_UNITS-1,MAX_SUPPLY_UNITS}) {
                chain.SetTotalSupplyForTesting(supply);
                for(size_t count:{0U,1U,195U,196U,197U,199U,200U,201U,234U,235U,236U,240U}) {
                    const std::string payload="VELD_FINALITY|predicate-only";
                    std::vector<uint8_t> marker{0x6a,static_cast<uint8_t>(payload.size())};
                    marker.insert(marker.end(),payload.begin(),payload.end());
                    std::vector<std::vector<uint8_t>> metadata(count,marker);
                    Block block;block.height=height;
                    block.transactions.push_back(Blockchain::BuildCanonicalCoinbase(height,supply,0,owner.GetP2PKHScript(),metadata));
                    const bool canonical=count<=MAX_FINALITY_MARKER_OUTPUTS;
                    const bool old_ingress=block.transactions[0].outputs.size()<=200;
                    const bool direct=chain.ValidateCoinbasePolicy(block);
                    const bool replay=chain.ValidateCoinbasePolicy(block,Blockchain::CoinbaseAdmissionPath::Replay);
                    check(direct==(canonical && (height>=3360 || old_ingress)),"direct output envelope");
                    check(replay==canonical,"historical or upgraded replay envelope");
                    if(height>=3360)check(direct==replay,"activated paths disagree");
                    if(!metadata.empty()) {
                        auto bad=block;
                        ++bad.transactions[0].outputs.back().value;
                        check(!chain.ValidateCoinbasePolicy(bad),"value-bearing finality output accepted");
                        check(!chain.ValidateCoinbasePolicy(bad,Blockchain::CoinbaseAdmissionPath::Replay),"replay accepted value-bearing metadata");
                    }
                }
            }
        }
        std::cout<<"PASS historical/activated output and category boundaries checks="<<checks<<'\n';
    }catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}
