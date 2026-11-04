#include "gui/pool_monitor.h"
#include <iostream>
using namespace veld;
void Check(bool value,const char* name){if(!value)throw std::runtime_error(name);std::cout<<"PASS "<<name<<'\n';}
int main()try {
    node_gui::PoolMonitor monitor;
    auto fixture=pool::Parse(R"({"status":"Mining","active_workers":"9","hashes":"1000","accepted":"2","verified_shares":"4","retry_count":"0","updated_at":"100","view_token":"DO_NOT_EXPORT","address":"DO_NOT_EXPORT"})");
    auto first=monitor.Report(true,14,&fixture,100,1);
    Check(first.find("DO_NOT_EXPORT")==std::string::npos,"tokens and wallet details never enter portal telemetry");
    Check(first.find("\"state\":\"hashing\"")!=std::string::npos,"pool work is independent of the solo daemon");
    fixture=pool::Parse(R"({"status":"Mining","active_workers":"8","hashes":"11000","accepted":"3","verified_shares":"5","retry_count":"0","updated_at":"110"})");
    auto next=pool::Parse(monitor.Report(true,14,&fixture,110,11));
    Check(pool::Field(next,"hashrate").text=="1000","hashrate is measured from counters and elapsed time");
    Check(pool::Field(next,"configured_workers").text=="14"&&pool::Field(next,"active_workers").text=="8","configured count stays distinct from active count");
    auto stale=monitor.Report(true,14,&fixture,126,27);
    Check(stale.find("\"current\":false")!=std::string::npos&&stale.find("\"hashrate\":0")!=std::string::npos,"stale reports never claim live hashing");
    auto stopped=monitor.Report(false,14,&fixture,111,28);
    Check(stopped.find("\"state\":\"stopped\"")!=std::string::npos&&stopped.find("\"active_workers\":0")!=std::string::npos,"process exit overrides a recent status file");
    auto future=monitor.Report(true,14,&fixture,109,29);
    Check(future.find("\"current\":false")!=std::string::npos,"future status time is unavailable");
    auto legacy=pool::Parse(R"({"status":"Mining"})");
    Check(monitor.Report(true,14,&legacy,110,30).find("\"current\":false")!=std::string::npos,"incomplete legacy status is not invented");
    Check(monitor.Report(true,14,nullptr,110,31).find("\"state\":\"unavailable\"")!=std::string::npos,"missing status is explicit");
    return 0;
}catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
