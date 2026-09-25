#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_VALIDATOR_REGISTRATION_FORK_TEST_HEIGHT 9500
#include "network/explorer.h"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>

int main(int argc, char** argv) {
    using namespace veld;
    Blockchain chain;
    Mempool mempool;
    ValidatorRegistry registry;
    explorer::BlockExplorer service(chain, mempool);
    explorer::HttpRequest request;
    request.method="GET"; request.path="/validators"; request.path_parts={"validators"};
    auto missing=service.Route(request);
    assert(missing.status_code==200 && missing.body.find(">Unknown</div>")!=std::string::npos);
    service.SetValidators(&registry);
    for (auto stake : {uint64_t{0},VALIDATOR_UNLOCK_STAKED-1}) {
        registry.SetTotalStaked(stake);
        auto response=service.Route(request);
        assert(response.status_code==200 && response.body.find("Validator Registration")!=std::string::npos);
        assert(response.body.find(">Paused</div>")!=std::string::npos);
        assert(response.body.find("Validators are endorsing blocks")==std::string::npos);
        assert(!registry.IsValidatorSystemActive(9499));
        assert(registry.IsValidatorSystemActive(9500));
    }
    registry.SetTotalStaked(VALIDATOR_UNLOCK_STAKED);
    auto open=service.Route(request);
    assert(open.body.find(">Open</div>")!=std::string::npos);
    assert(open.body.find("Individual bond and eligibility checks apply")!=std::string::npos);
    assert(open.body.find("Validators are endorsing blocks")==std::string::npos);
    request.path="/rules";request.path_parts={"rules"};auto rules=service.Route(request);
    assert(rules.body.find("flat 0.30% fee")!=std::string::npos);
    assert(rules.body.find("Before block 9,500")==std::string::npos);
    assert(rules.body.find("aggregate ordinary stake")==std::string::npos);
    assert(rules.body.find("Bond the minimum")!=std::string::npos);
    if(argc==2){std::ofstream(std::filesystem::path(argv[1])/"validator-open.html")<<open.body;}
    std::cout<<"PASS real Explorer registration display: unknown, zero and below-floor, open with zero validators, and unchanged 9500 boundary\n";
}
