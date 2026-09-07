#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#include "network/explorer.h"
#include <cassert>
#include <future>
#include <iostream>

int main() {
    using namespace veld;
    compat::InitNetwork();
    auto make_pair = [] {
    compat::SocketHandle receiver, sender;
#ifdef _WIN32
    // One ordinary loopback pair. No Explorer listener, public bind, peer data,
    // peer frames, traffic workload or live-node connection is involved.
    auto listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(compat::IsValidSocket(listener));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    assert(::listen(listener, 1) == 0);
    int address_size = sizeof(address);
    assert(::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_size) == 0);
    sender = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(compat::IsValidSocket(sender));
    assert(::connect(sender, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    receiver = ::accept(listener, nullptr, nullptr);
    assert(compat::IsValidSocket(receiver));
    VELD_CLOSE_SOCKET(listener);
#else
    int pair[2];
    assert(::socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    receiver = pair[0]; sender = pair[1];
#endif
    return std::pair{receiver, sender};
    };
    auto [receiver, sender] = make_pair();
    Blockchain chain;
    Mempool mempool;
    explorer::BlockExplorer service(chain, mempool);
    using Clock = std::chrono::steady_clock;
    const auto deadline = Clock::now() + std::chrono::seconds(2);
    assert(service.TestSetReceiveDeadline(receiver, deadline));
    assert(!service.TestSetReceiveDeadline(receiver, Clock::now() - std::chrono::seconds(1)));
    service.TestTrackReceiptSocket(receiver, "127.0.0.1");
    auto ordinary = std::async(std::launch::async, [&] {
        service.TestHandleReceipt(receiver, deadline);
    });
    // A normal delayed request remains valid across the short polling tick.
    assert(ordinary.wait_for(std::chrono::milliseconds(300)) == std::future_status::timeout);
    const std::string request = "GET /manifest.json HTTP/1.1\r\nHost: localhost\r\n\r\n";
    assert(::send(sender, request.data(), static_cast<int>(request.size()), 0) == static_cast<int>(request.size()));
    assert(ordinary.wait_for(std::chrono::seconds(1)) == std::future_status::ready);
    ordinary.get();
    char response[4096];
    const int received = ::recv(sender, response, sizeof(response), 0);
    assert(received > 0 && std::string(response, received).find("200 OK") != std::string::npos);
    service.TestCloseReceiptSocket(receiver);
    VELD_CLOSE_SOCKET(sender);

    const auto idle_pair = make_pair();
    receiver = idle_pair.first; sender = idle_pair.second;
    service.TestTrackReceiptSocket(receiver, "127.0.0.1");
    auto idle = std::async(std::launch::async, [&] {
        service.TestHandleReceipt(receiver, Clock::now() + std::chrono::seconds(2));
    });
    assert(idle.wait_for(std::chrono::milliseconds(300)) == std::future_status::timeout);
    service.Stop();
    assert(idle.wait_for(std::chrono::seconds(1)) == std::future_status::ready);
    idle.get();
    service.TestCloseReceiptSocket(receiver);
    VELD_CLOSE_SOCKET(sender);
    std::cout << "PASS: receipt deadline setup and ordinary shutdown cancellation\n";
}
