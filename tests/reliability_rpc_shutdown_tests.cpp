#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#include "network/rpc_http.h"
#include <future>
#include <iostream>

using namespace veld;
using Clock = std::chrono::steady_clock;

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const std::filesystem::path root(argv[1]);
    if (std::filesystem::exists(root)) return 2;
    std::filesystem::create_directories(root);
    compat::InitNetwork();
    Blockchain chain;
    Mempool mempool;
    StorageEngine storage((root / "storage").string(), MAINNET_MAGIC);
    RpcServer rpc(chain, mempool, storage);
    RpcHttpServer service(rpc, 0, "", "disposable-lifecycle-fixture");
    for (int round = 0; round < 12; ++round) {
        if (!service.Start()) return 3;
        const auto fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(service.TestListeningPort());
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address))) return 4;
        // Incomplete HTTP traffic must not make stopping wait on receive timeout.
        const std::string partial = round % 2 ?
            "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1024\r\n\r\nx" : "GET / HTTP/1.1\r\n";
        ::send(fd, partial.data(), static_cast<int>(partial.size()), 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        const auto start = Clock::now();
        auto stopped = std::async(std::launch::async, [&] { service.Stop(); });
        const bool bounded = stopped.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
#ifdef VELD_RELIABILITY_PHASE_DIAGNOSTIC
        if (!bounded) std::cout << "blocked_phase=" << service.ShutdownPhase() << std::endl;
#endif
        // Release only this fixture socket so the baseline can finish and report.
#ifdef _WIN32
        ::shutdown(fd, SD_BOTH);
#else
        ::shutdown(fd, SHUT_RDWR);
#endif
        VELD_CLOSE_SOCKET(fd);
        stopped.get();
        std::cout << "round=" << round << " stop_ms="
                  << std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-start).count()
                  << " bounded=" << bounded << std::endl;
        if (!bounded) return 1;
        service.Stop(); // repeated stop must remain harmless
    }
    std::cout << "PASS: 12 RPC incomplete-request stop/restart cycles\n";
}
