#ifdef VELD_RELIABILITY_IDENTITY_PROFILE
#include "regtest_profile.h"
#else
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#endif
#define VELD_TEST_HOOKS 1
#include "network/tcp.h"
#include <iostream>

using namespace veld;
using Clock = std::chrono::steady_clock;

int main(int argc, char** argv) {
    // The shared CI runner supplies an unused disposable output path first.
    const auto numeric = [](const char* value) {
        return value && *value && std::all_of(value, value + std::strlen(value),
            [](unsigned char c) { return c >= '0' && c <= '9'; });
    };
    const int duration = argc > 1 && numeric(argv[1]) ? std::stoi(argv[1]) :
        (argc > 2 && numeric(argv[2]) ? std::stoi(argv[2]) : 110);
    const bool bad_identity = argc > 2 && std::string(argv[2]) == "bad-identity";
    if (bad_identity && MessageType::REQUIRED_NETWORK_IDENTITY_SERVICES == 0) {
        std::cerr << "Identity rejection requires the isolated identity profile\n";
        return 2;
    }
    compat::InitNetwork();
    Blockchain chain;
    const Block genesis = CreateGenesisBlock();
    const Hash256 genesis_hash = genesis.GetHash();
    if (!chain.AddBlockDirect(genesis, true, false, false,
            mining::PowAdmissionContext::Internal()).IsAccepted()) return 2;
    Mempool mempool;
    net::NodeServer verifier(0, MAINNET_MAGIC, chain, mempool);
    if (!verifier.Start({}, false)) return 3; // actual outbound-only background protocol
    const auto listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ||
        ::listen(listener, 1)) return 4;
    socklen_t size = sizeof(address);
    ::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &size);
    if (!verifier.ConnectTo("127.0.0.1", ntohs(address.sin_port))) return 5;
    const auto peer = ::accept(listener, nullptr, nullptr);
    VELD_CLOSE_SOCKET(listener);
    if (!compat::IsValidSocket(peer)) return 6;
#ifdef _WIN32
    DWORD timeout = 500;
    ::setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
#else
    timeval timeout{0, 500000};
    ::setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
#endif
    auto send_message = [&](const P2PMessage& message) {
        const auto wire = message.Serialize();
        return ::send(peer, reinterpret_cast<const char*>(wire.data()),
                      static_cast<int>(wire.size()), 0) == static_cast<int>(wire.size());
    };
    VersionPayload version;
    version.nonce = 0x1234567812345678;
    version.services = MessageType::NODE_FULL | MessageType::REQUIRED_NETWORK_IDENTITY_SERVICES;
    if (bad_identity) version.services = MessageType::NODE_FULL;
    version.start_height = 0;
    if (!send_message(P2PMessage(MAINNET_MAGIC, MessageType::VERSION, version.Serialize()))) return 7;
    if (!bad_identity && !send_message(P2PMessage(MAINNET_MAGIC, MessageType::VERACK))) return 7;
    PeerManager manager(MAINNET_MAGIC, 0);
    if (!bad_identity) send_message(manager.BuildTipsigMessage(0, genesis_hash));
    const auto expected_tip = manager.BuildTipsigMessage(0, genesis_hash).Serialize();
    std::vector<uint8_t> buffered;
    int tips = 0;
    bool valid = true, connected = true;
    const auto start = Clock::now();
    auto last_tip = start;
    char incoming[16384];
    while (Clock::now() - start < std::chrono::seconds(duration)) {
        const int got = ::recv(peer, incoming, sizeof(incoming), 0);
        if (got == 0) { connected = false; break; }
        if (got < 0) {
#ifdef _WIN32
            const int error = WSAGetLastError();
            if (error != WSAETIMEDOUT && error != WSAEWOULDBLOCK && error != WSAEINTR) {
#else
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
#endif
                connected = false; break;
            }
        }
        if (got > 0) buffered.insert(buffered.end(), incoming, incoming + got);
        while (buffered.size() >= 24) {
            uint32_t length = 0;
            for (int i = 0; i < 4; ++i) length |= uint32_t(buffered[16+i]) << (8*i);
            if (length > 1024*1024) return 8;
            if (buffered.size() < 24 + length) break;
            const std::string command(reinterpret_cast<const char*>(buffered.data()+4),
                strnlen(reinterpret_cast<const char*>(buffered.data()+4), 12));
            if (command == MessageType::TIPSIG) {
                if (tips == 0)
                    valid = valid && Clock::now() - start <= std::chrono::seconds(5);
                if (tips > 0) {
                    const auto gap = std::chrono::duration_cast<std::chrono::seconds>(Clock::now()-last_tip).count();
                    valid = valid && gap >= 25 && gap <= 40;
                }
                ++tips;
                valid = valid && length == 44 &&
                    std::equal(expected_tip.begin(), expected_tip.end(), buffered.begin());
                std::cout << "tip=" << tips << " elapsed_s="
                    << std::chrono::duration_cast<std::chrono::seconds>(Clock::now()-start).count() << std::endl;
                last_tip = Clock::now();
            }
            if (command == MessageType::PING)
                send_message(P2PMessage(MAINNET_MAGIC, MessageType::PONG,
                    std::vector<uint8_t>(buffered.begin()+24, buffered.begin()+24+length)));
            buffered.erase(buffered.begin(), buffered.begin()+24+length);
        }
        // Receiver policy is unchanged: VERSION alone does not satisfy TIPSIG.
        if (Clock::now() - last_tip > std::chrono::seconds(90)) break;
    }
    const auto stop = Clock::now();
    verifier.Stop();
    VELD_CLOSE_SOCKET(peer);
    const auto stop_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-stop).count();
    const bool pass = (bad_identity ? (!connected && tips == 0) :
        (connected && valid && tips >= (duration >= 90 ? 4 : 1))) && stop_ms < 2000;
    std::cout << "background=" << true << " tips=" << tips << " valid=" << valid
              << " connected=" << connected << " stop_ms=" << stop_ms << " pass=" << pass << std::endl;
    return pass ? 0 : 1;
}
