#include "gui/node_gui_model.h"
#include "node/client_exit_policy.h"
#include <iostream>
#include <stdexcept>
#ifdef _WIN32
#include <windows.h>
#endif

int checks=0;
void check(bool value) { ++checks; if(!value) throw std::runtime_error("check " + std::to_string(checks)); }
int main(int argc,char** argv) {
    if(argc==2) return std::stoi(argv[1]); // Disposable process exit fixture.
    using namespace veld::node_gui;
    using namespace veld::node_client;
    const std::string base=R"({"mining_configured":true,"mining_ready":false,"mining_active":false,"snapshot_bootstrap_compiled":true,"snapshot_fast_start_eligible":false,"full_ibd":true,"total_hashes":0,"threads":0,"blocks_mined_session":0,"progress_counter":0,"updated_at":100,"hashrate":0,"work_state":"verifying","miner_address":"disposable-fixture-address"})";
    const std::string daemon=R"("daemon":{"version":"3.1.1","profile":"mainnet-v2","pid":123,"network_magic":1234,"protocol_height":0,"asert_height":0,"migration_height":0,"security_height":2880,"verification_height":12,"verification_target":64,"ibd_complete":false,"historical_validated":false})";
    MiningStats stats;std::string error;
    check(ParseMiningStats(base,stats,error));
    check(!stats.daemon_identity_known && stats.total_hashes==0 && !stats.mining_active);
    const auto body=base.substr(0,base.size()-1)+","+daemon+"}";
    check(ParseMiningStats(body,stats,error));
    check(stats.daemon_identity_known && stats.daemon_version=="3.1.1" && stats.daemon_pid==123);
    check(stats.verification_height==12 && stats.verification_target==64 && !stats.historical_validated);
    check(stats.security_height==2880 && stats.asert_height==0 && stats.protocol_height==0);
    for(const auto& fragment : {"null","0","[]","{}","true"}) {
        check(!ParseMiningStats(base.substr(0,base.size()-1)+",\"daemon\":"+fragment+"}",stats,error));
    }
    for(const auto& bad : {"-1","0","1.5","true","\"123\""}) {
        auto value=body;auto pos=value.find("\"pid\":123");value.replace(pos,9,std::string("\"pid\":")+bad);
        check(!ParseMiningStats(value,stats,error));
    }
    auto node_only=base;
    node_only.replace(node_only.find("\"mining_configured\":true"),24,"\"mining_configured\":false");
    node_only.replace(node_only.find("disposable-fixture-address"),std::string("disposable-fixture-address").size(),"");
    check(ParseMiningStats(node_only,stats,error));
    check(!ParseMiningStats(base.substr(0,base.size()-1)+",\"hashrate\":1}",stats,error));
    for(unsigned retries=0;retries<5;++retries) {
        check(ClassifyExit(75,false,retries)==(retries<3?ExitAction::Restart:ExitAction::Inspect));
        check(ClassifyExit(76,false,retries)==ExitAction::Inspect);
        check(ClassifyExit(0,false,retries)==ExitAction::Stop);
        for(auto code:{0U,75U,76U,1U})check(ClassifyExit(code,true,retries)==ExitAction::Stop);
    }
#ifdef _WIN32
    wchar_t exe[32768];check(GetModuleFileNameW(nullptr,exe,32768)>0);
    for(unsigned code : {0U,75U,76U,1U}) {
        std::wstring command=L"\""+std::wstring(exe)+L"\" "+std::to_wstring(code);
        STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION process{};
        check(CreateProcessW(exe,command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&process));
        CloseHandle(process.hThread);
        check(WaitForSingleObject(process.hProcess,10000)==WAIT_OBJECT_0);
        DWORD actual=STILL_ACTIVE;check(GetExitCodeProcess(process.hProcess,&actual));CloseHandle(process.hProcess);
        check(actual==code);
        check(ClassifyExit(actual,false,0)==ClassifyExit(code,false,0));
    }
#endif
    std::cout<<"PASS client diagnostics checks="<<checks<<"\n";
}
