#include "network/tcp.h"

#include <cstdint>
#include <iostream>
#include <memory>

using namespace veld;

namespace {

size_t checks = 0;

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        ++checks;                                                                                  \
        if (!(expr)) {                                                                             \
            std::cerr << "FAIL " << __FILE__ << ':' << __LINE__ << " " #expr "\n";                 \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

std::shared_ptr<net::Connection> MakeConnection(const std::string& address, uint16_t port) {
    const auto fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!compat::IsValidSocket(fd))
        return {};
    return std::make_shared<net::Connection>(fd, address, port, true);
}

} // namespace

int main() {
    compat::InitNetwork();
    CHECK(MessageType::REQUIRED_NETWORK_IDENTITY_SERVICES == MessageType::NODE_BTCVELD_RESERVE_V1);

    Blockchain chain;
    Mempool mempool;
    net::NodeServer server(0, MAINNET_MAGIC, chain, mempool);

    auto legacy_connection = MakeConnection("127.0.0.2", 31001);
    CHECK(legacy_connection != nullptr);
    net::PeerState legacy_state;
    legacy_state.version_sent = true;
    legacy_state.version_acked = true;
    VersionPayload legacy;
    legacy.services = MessageType::NODE_FULL | MessageType::NODE_HOLE_PUNCH;
    legacy.nonce = 11;
    server.TestDispatchPeerMessageWithState(
        legacy_state, *legacy_connection,
        P2PMessage(MAINNET_MAGIC, MessageType::VERSION, legacy.Serialize()));
    CHECK(!legacy_state.their_version);
    CHECK(!legacy_state.handshake_done);

    auto current_connection = MakeConnection("127.0.0.3", 31002);
    CHECK(current_connection != nullptr);
    net::PeerState current_state;
    current_state.version_sent = true;
    current_state.version_acked = true;
    PeerManager current_peer(MAINNET_MAGIC, 0);
    const P2PMessage current = current_peer.BuildVersionMessage(0, 12);
    CHECK((current.payload[4] & MessageType::NODE_BTCVELD_RESERVE_V1) != 0);
    server.TestDispatchPeerMessageWithState(current_state, *current_connection, current);
    CHECK(current_state.their_version);
    CHECK(current_state.handshake_done);

    std::cout << "PASS network_identity_tests checks=" << checks
              << " legacy_reserve_peer_rejected=1\n";
    return 0;
}
