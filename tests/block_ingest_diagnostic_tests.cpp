// An inert server object exercises diagnostics without binding or connecting.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#include "network/tcp.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
int main() {
    using namespace veld;
    try {
        Blockchain chain;Mempool pool;
        net::NodeServer server(0,0x54525341,chain,pool);
        std::ostringstream captured;
        auto* previous=std::cerr.rdbuf(captured.rdbuf());
        for(size_t i=0;i<9;++i)server.RecordViolation("192.0.2.1",0,"block_ingest_overflow");
        std::cerr.rdbuf(previous);
        const auto text=captured.str();
        if(std::count(text.begin(),text.end(),'\n')!=5 || text.find("[violation]")!=std::string::npos ||
            text.find("Block validation queue busy")==std::string::npos ||
            text.find("No peer penalty.")==std::string::npos)
            throw std::runtime_error("queue diagnostic wording or throttle differs");
        if(server.TestViolationTableSize()!=0 || server.TestViolationScore("192.0.2.1")!=0 ||
            server.TestBanPersistCount()!=0 || server.TestBansDirty() || server.TestViolationLogRateTableSize()!=1)
            throw std::runtime_error("flow control changed penalty or bounded log state");
        captured.str("");previous=std::cerr.rdbuf(captured.rdbuf());
        server.RecordViolation("192.0.2.2",1,"ordinary-diagnostic-control");
        server.RecordViolation("192.0.2.3",0,"tx_input_missing");
        std::cerr.rdbuf(previous);
        if(server.TestViolationScore("192.0.2.2")!=1 || captured.str().find("[violation]")==std::string::npos)
            throw std::runtime_error("unrelated diagnostic or scoring changed");
        std::cout<<"PASS queue message, per-source throttle, zero penalty, unchanged other diagnostics; no network started\n";
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
}
