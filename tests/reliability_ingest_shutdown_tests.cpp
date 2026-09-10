#include "regtest_profile.h"
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_LOCAL_TEST_NETWORK 1
#define VELD_ENABLE_SNAPSHOT_BOOTSTRAP 1
#include "node/node.h"
#include <future>
#include <iostream>

using namespace veld;

int CheckStop(const std::filesystem::path& directory, bool background) {
    auto config = RegtestConfig();
    config.port = 0;
    VeldNode node(config, directory.string());
    node.SetQuietBoot(true);
    node.SetFullIbd(true);
    node.SetBackgroundValidationOnly(background);
    node.Start();
    auto* server = node.GetTCPServer();
    std::future<void> stopped;
    std::promise<void> entering_stop;
    auto entered = entering_stop.get_future();
    net::NodeServer::IngestEnqueueResult observed;
    {
        // Hold the real commit sequencer so shutdown must wait for an active
        // transition. Incoming peer work must already be closed during that wait.
        auto in_flight_commit = node.GetChain().AcquireConsensusTransitionGuard();
        stopped = std::async(std::launch::async, [&] {
            entering_stop.set_value();
            node.Stop();
        });
        entered.wait();
        std::this_thread::sleep_for(std::chrono::seconds(1));
        Block incoming;
        incoming.height = 1;
        incoming.header.nonce = 41;
        observed = server->TestEnqueueBlockIngest(
            incoming, 128, "127.0.0.1:12001");
    }
    if (stopped.wait_for(std::chrono::seconds(2)) != std::future_status::ready)
        return 1;
    stopped.get();
    if (observed != net::NodeServer::IngestEnqueueResult::Full) return 2;
    node.Stop();
    Block after_stop;
    after_stop.height = 1;
    after_stop.header.nonce = 42;
    if (server->TestEnqueueBlockIngest(after_stop, 128, "127.0.0.1:12001") !=
        net::NodeServer::IngestEnqueueResult::Full) return 3;
    if (server->TestPendingBlockIngestCount() != 0 ||
        server->TestPendingBlockIngestBytes() != 0) return 4;
    return 0;
}

int main(int argc, char** argv) {
    if (argc != 2 || std::filesystem::exists(argv[1])) return 10;
    for (int i = 0; i < 4; ++i) {
        const int result = CheckStop(
            std::filesystem::path(argv[1]) / std::to_string(i), i % 2 != 0);
        if (result) {
            std::cerr << "FAIL shutdown admission round=" << i
                      << " result=" << result << '\n';
            return result;
        }
    }
    std::cout << "PASS: full/background shutdown rejects incoming block work "
                 "before waiting for the active commit; repeated stop stays closed\n";
}
