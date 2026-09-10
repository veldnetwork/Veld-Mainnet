#define VELD_TEST_HOOKS 1
#include "isolated_regtest_profile.h"
#include "network/tcp.h"

#include <iostream>
#include <stdexcept>

using namespace veld;
using namespace std::chrono_literals;
using Server = net::NodeServer;

namespace {
constexpr uint32_t magic = 0xF17ED1A1;
size_t checks = 0;
void Check(bool value, const char* message) {
    ++checks;
    if (!value) throw std::runtime_error(message);
}
void InitChain(Blockchain& chain) {
    Check(chain.AddBlockDirect(CreateGenesisBlock(), true, false, false,
        mining::PowAdmissionContext::Internal()).IsAccepted(), "genesis admission");
}
template<class Predicate> void Wait(Predicate predicate, const char* message) {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!predicate() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(10ms);
    Check(predicate(), message);
}
}

int main() {
    try {
        compat::InitNetwork();
        Blockchain chain, other_chain, background_chain;
        InitChain(chain); InitChain(other_chain); InitChain(background_chain);
        Mempool pool, other_pool, background_pool;
        Server node(0, magic, chain, pool), other(0, magic, other_chain, other_pool);
        Check(node.Start(), "start listener with OS-assigned port");
        const uint16_t port = node.TestListeningPort();
        Check(port != 0, "actual listener port");
        Check(node.IsLocalListenerEndpoint("127.0.0.1", port), "recognize local listener");
        Check(node.IsLocalListenerEndpoint("127.0.0.2", port), "recognize loopback alias");
        Check(!node.IsLocalListenerEndpoint("203.0.113.7", port), "remote address is not local");
        Check(!node.IsLocalListenerEndpoint("127.0.0.1", 0), "zero port is not a listener");

        uint64_t cursor = 0;
        uint64_t lost = 0;
        (void)net::connection_diagnostics::Since(cursor, lost);
        Check(!node.ConnectTo("127.0.0.1", port), "reject direct self dial");
        Check(!node.ConnectTo("localhost", port), "reject resolved self dial");
        Check(!node.ConnectTo("127.0.0.2", port), "reject self dial through alias");
        if (const char* local_ip = std::getenv("VELD_TEST_LOCAL_IP")) {
            Check(node.IsLocalListenerEndpoint(local_ip, port), "recognize assigned interface address");
            Check(!node.ConnectTo(local_ip, port), "reject self dial through assigned interface");
        }
        Check(node.AddFleetAnchorIp("127.0.0.1"), "retain configured anchor authority");
        Check(!node.ConnectTo("127.0.0.1", port, true, true), "anchor authority cannot bypass self exclusion");
        std::atomic<bool> rejected{true};
        std::vector<std::thread> retries;
        for (int i = 0; i < 8; ++i) retries.emplace_back([&] {
            for (int j = 0; j < 8; ++j)
                if (node.ConnectTo("127.0.0.1", port)) rejected.store(false);
        });
        for (auto& thread : retries) thread.join();
        Check(rejected.load(), "concurrent retries stay excluded");
        std::this_thread::sleep_for(200ms);
        Check(node.GetPeerInfoList().empty(), "self dial creates no peers");
        Check(node.TestPendingDialCount() == 0, "self dial leaves no pending lease");
        const auto events = net::connection_diagnostics::Since(cursor, lost);
        Check(!lost && events.empty(), "self retries create no connection events");

        Check(other.Start(), "start a different node on the same machine");
        const uint16_t other_port = other.TestListeningPort();
        Check(port != other_port && !node.IsLocalListenerEndpoint("127.0.0.1", other_port),
            "different local port is a different endpoint");
        Check(node.ConnectTo("localhost", other_port), "dial a different local node by hostname");
        Wait([&] { return other.VersionReadyPeers() == 1 && node.VersionReadyPeers() == 1; },
            "different local node completes handshake");
        const auto connection = node.GetPeerInfoList().front().connection_id;
        Check(node.ConnectTo("127.0.0.1", other_port), "remote retry remains idempotent");
        Check(node.GetPeerInfoList().front().connection_id == connection, "remote retry retains connection identity");

        Server background(port, magic, background_chain, background_pool);
        Check(background.Start({}, false), "start outbound-only background chainstate");
        Check(!background.IsLocalListenerEndpoint("127.0.0.1", port), "background chainstate has no own listener");
        Check(background.ConnectTo("127.0.0.1", port), "background chainstate can reach local foreground node");
        Wait([&] { return background.VersionReadyPeers() == 1; }, "background connection completes handshake");
        background.Stop();

        other.Stop();
        Wait([&] { return node.GetPeerInfoList().empty(); }, "dropped peer is retired");
        Check(other.Start(), "restart remote peer");
        Check(node.ConnectTo("127.0.0.1", other.TestListeningPort()), "reconnect dropped peer");
        Wait([&] { return node.VersionReadyPeers() == 1; }, "reconnected peer completes handshake");
        Check(node.GetPeerInfoList().front().connection_id != connection, "reconnect has a new identity");
        other.Stop(); node.Stop();
        Check(!node.IsLocalListenerEndpoint("127.0.0.1", port), "stopped node owns no active listener");
        Check(node.Start(), "restart local listener");
        Check(node.IsLocalListenerEndpoint("127.0.0.1", node.TestListeningPort()), "restart publishes the actual new port");
        Check(!node.ConnectTo("localhost", node.TestListeningPort()), "resolved self exclusion survives restart");
        node.Stop();
        std::cout << "PASS self_dial_tests checks=" << checks << "\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL self_dial_tests: " << error.what() << "\n";
        return 1;
    }
}
