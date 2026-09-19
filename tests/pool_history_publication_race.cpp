// Native, deterministic read/commit interleaving. The hook is absent from all
// packaged artifacts. Neither block admission nor the history reader is copied.
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>
namespace {
std::mutex probe_mutex;
std::condition_variable probe_cv;
bool entered=false,release=false;
std::atomic<bool> armed{false};
void PauseHistoryRead() {
    if(!armed.exchange(false))return;
    std::unique_lock<std::mutex> lock(probe_mutex);
    entered=true;probe_cv.notify_all();
    probe_cv.wait(lock,[]{return release;});
}
}
#define VELD_TEST_ADDRESS_HISTORY_READ_HOOK() PauseHistoryRead()
#include "node/node.h"

int main(int argc,char** argv) {
    using namespace veld;
    if(argc!=3)return 2;
    compat::InitNetwork();
    auto config=RegtestConfig();config.port=32841;config.rpc_port=32842;
    VeldNode node(config,argv[1]);node.SetQuietBoot(true);node.SetP2PPort(config.port);
    node.Start();
    const std::string address=argv[2];
    RealKeyPair miner;miner.script_override=AddressToScript(address);
    if(miner.script_override.size()!=25){node.Stop();return 2;}
    asert_qualification::candidate_time.store(1767225780);
    auto initial=node.MineBlocks(miner,1,0);
    if(initial.size()!=1 || !initial[0].success){node.Stop();return 3;}
    const auto request=std::string("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getaddresshistory\",\"params\":[\"")+address+"\",\"50\"]}";
    std::string first;
    armed.store(true);
    std::thread reader([&]{first=node.GetRPC().Handle(request);});
    {
        std::unique_lock<std::mutex> lock(probe_mutex);
        if(!probe_cv.wait_for(lock,std::chrono::seconds(10),[]{return entered;})) {
            release=true;probe_cv.notify_all();lock.unlock();reader.join();node.Stop();return 4;
        }
    }
    asert_qualification::candidate_time.store(1767225960);
    std::vector<MineBlockResult> blocks;std::atomic<bool> committed{false};
    std::thread producer([&]{blocks=node.MineBlocks(miner,1,0);committed.store(true);probe_cv.notify_all();});
    {
        std::unique_lock<std::mutex> lock(probe_mutex);
        // On the old reader, a new tip/index can publish after tip capture.
        // The fixed reader pins a coherent view, so the producer waits here.
        probe_cv.wait_for(lock,std::chrono::seconds(10),[&]{return committed.load();});
        release=true;probe_cv.notify_all();
    }
    reader.join();producer.join();
    const auto after=node.GetRPC().Handle(request);
    std::cout<<"FIRST "<<first<<"\nAFTER "<<after<<'\n';
    const bool success=blocks.size()==1 && blocks[0].success &&
        first.find("\"error\":null")!=std::string::npos &&
        after.find("\"error\":null")!=std::string::npos;
    node.Stop();
    if(!success){std::cerr<<"FAIL history remains unavailable after canonical publication\n";return 1;}
    std::cout<<"PASS native history remains readable after read/commit interleaving\n";
    return 0;
}
