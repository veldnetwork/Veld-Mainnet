#include "network/tcp.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace veld::net {
using ::veld::P2PMessage;
namespace MessageType = ::veld::MessageType;
} // namespace veld::net

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

using veld::net::Connection;
using veld::net::NodeServer;
using veld::net::P2PMessage;
using veld::net::PeerState;

std::shared_ptr<Connection> MakeConnection(const std::string& ip, uint16_t port,
                                           bool capable = true) {
    const auto fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!veld::compat::IsValidSocket(fd))
        return {};
    auto conn = std::make_shared<Connection>(fd, ip, port, true);
    conn->EnableEventLoopIO();
    conn->MarkHandshakeReady();
    conn->MarkAdvertisedServices(veld::net::MessageType::NODE_FULL |
                                 (capable ? veld::net::MessageType::NODE_HOLE_PUNCH : 0));
    return conn;
}

PeerState ReadyPeerState() {
    PeerState ps;
    ps.version_sent = true;
    ps.version_acked = true;
    ps.their_version = true;
    ps.handshake_done = true;
    return ps;
}

template <size_t N> std::vector<uint8_t> Bytes(const std::array<uint8_t, N>& value) {
    return std::vector<uint8_t>(value.begin(), value.end());
}

template <size_t N> void Append(std::vector<uint8_t>& out, const std::array<uint8_t, N>& value) {
    out.insert(out.end(), value.begin(), value.end());
}

void AppendEndpoint(std::vector<uint8_t>& out, const std::string& endpoint) {
    out.push_back(static_cast<uint8_t>(endpoint.size()));
    out.insert(out.end(), endpoint.begin(), endpoint.end());
}

} // namespace

int main() {
    veld::compat::InitNetwork();

    const auto hello_bounds = Connection::BoundsForCommand(veld::net::MessageType::PUNCHHELLO);
    const auto get_bounds = Connection::BoundsForCommand(veld::net::MessageType::GETPUNCH);
    const auto req_bounds = Connection::BoundsForCommand(veld::net::MessageType::PUNCHREQ);
    const auto fwd_bounds = Connection::BoundsForCommand(veld::net::MessageType::PUNCHFWD);
    const auto list_bounds = Connection::BoundsForCommand(veld::net::MessageType::PUNCHLIST);
    CHECK(hello_bounds.minimum == 0 && hello_bounds.maximum == 16);
    CHECK(get_bounds.minimum == 0 && get_bounds.maximum == 16);
    CHECK(req_bounds.minimum == 1 && req_bounds.maximum == 97);
    CHECK(fwd_bounds.minimum == 1 && fwd_bounds.maximum == 81);
    CHECK(list_bounds.minimum == 1 && list_bounds.maximum == 1313);

    veld::Blockchain chain;
    veld::Mempool mempool;
    NodeServer server(0, veld::MAINNET_MAGIC, chain, mempool);
    server.EnableHolePunch();
    server.TestSuppressPunchNetworkDials(true);

    auto requester = MakeConnection("8.8.8.8", 4000);
    auto target = MakeConnection("1.1.1.1", 5000);
    auto coordinator = MakeConnection("9.9.9.9", 6000);
    auto attacker = MakeConnection("4.2.2.2", 7000);
    auto incapable = MakeConnection("208.67.222.222", 8000, false);
    CHECK(requester && target && coordinator && attacker && incapable);

    PeerState requester_state = ReadyPeerState();
    PeerState target_state = ReadyPeerState();
    PeerState coordinator_state = ReadyPeerState();
    PeerState attacker_state = ReadyPeerState();
    PeerState incapable_state = ReadyPeerState();

    const std::array<uint8_t, 16> target_nonce{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                               0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    const std::array<uint8_t, 16> request_nonce{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                                                0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
    const std::array<uint8_t, 16> other_nonce{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                              0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};

    server.TestRegisterAdmittedConnection("1.1.1.1:5000", target);
    server.TestDispatchPeerMessageWithState(
        target_state, *target,
        P2PMessage(veld::MAINNET_MAGIC, veld::net::MessageType::PUNCHHELLO, Bytes(target_nonce)));
    CHECK(server.TestPunchRegistrationCount() == 1);

    server.TestDispatchPeerMessageWithState(
        requester_state, *requester,
        P2PMessage(veld::MAINNET_MAGIC, veld::net::MessageType::GETPUNCH, Bytes(request_nonce)));
    CHECK(server.TestPunchSeedRequestCount() == 1);
    CHECK(requester->QueuedSendFrames() == 1);

    std::vector<uint8_t> req;
    Append(req, request_nonce);
    Append(req, target_nonce);
    AppendEndpoint(req, "1.1.1.1:5000");
    const size_t target_frames_before = target->QueuedSendFrames();
    server.TestDispatchPeerMessageWithState(
        requester_state, *requester,
        P2PMessage(veld::MAINNET_MAGIC, veld::net::MessageType::PUNCHREQ, req));
    CHECK(target->QueuedSendFrames() == target_frames_before + 1);
    CHECK(server.TestPunchRegistrationCount() == 0);
    CHECK(server.TestPunchSeedRequestCount() == 0);
    server.TestDispatchPeerMessageWithState(
        requester_state, *requester,
        P2PMessage(veld::MAINNET_MAGIC, veld::net::MessageType::PUNCHREQ, req));
    CHECK(target->QueuedSendFrames() == target_frames_before + 1);

    const uint64_t now = veld::compat::MonotonicSeconds();
    server.TestPrimePunchClientExchange(coordinator, other_nonce, request_nonce, now + 60,
                                        now + 60);
    std::vector<uint8_t> list;
    Append(list, request_nonce);
    list.push_back(1);
    AppendEndpoint(list, "1.0.0.1:8333");
    Append(list, target_nonce);
    server.TestDispatchPeerMessageWithState(
        coordinator_state, *coordinator,
        P2PMessage(veld::MAINNET_MAGIC, veld::net::MessageType::PUNCHLIST, list));
    CHECK(server.TestPunchCandidateCount() == 1);
    server.TestDispatchPeerMessageWithState(
        coordinator_state, *coordinator,
        P2PMessage(veld::MAINNET_MAGIC, veld::net::MessageType::PUNCHLIST, list));
    CHECK(server.TestPunchCandidateCount() == 1);

    server.TestPrimePunchClientExchange(coordinator, other_nonce, other_nonce, now + 60, now + 60);
    server.TestDispatchPeerMessageWithState(
        coordinator_state, *coordinator,
        P2PMessage(veld::MAINNET_MAGIC, veld::net::MessageType::PUNCHLIST, list));
    CHECK(server.TestPunchCandidateCount() == 1);
    server.TestPrimePunchClientExchange(coordinator, other_nonce, request_nonce, now + 60,
                                        now + 60);
    server.TestDispatchPeerMessageWithState(
        attacker_state, *attacker,
        P2PMessage(veld::MAINNET_MAGIC, veld::net::MessageType::PUNCHLIST, list));
    CHECK(server.TestPunchCandidateCount() == 1);
    server.TestPrimePunchClientExchange(coordinator, other_nonce, request_nonce, now - 1, now - 1);
    server.TestDispatchPeerMessageWithState(
        coordinator_state, *coordinator,
        P2PMessage(veld::MAINNET_MAGIC, veld::net::MessageType::PUNCHLIST, list));
    CHECK(server.TestPunchCandidateCount() == 1);

    server.TestPrimePunchClientExchange(coordinator, other_nonce, request_nonce, now + 60, now + 60,
                                        true, false);
    std::vector<uint8_t> fwd;
    Append(fwd, other_nonce);
    AppendEndpoint(fwd, "8.8.4.4:8333");
    server.TestDispatchPeerMessageWithState(
        coordinator_state, *coordinator,
        P2PMessage(veld::MAINNET_MAGIC, veld::net::MessageType::PUNCHFWD, fwd));
    CHECK(server.TestAuthorizedPunchDialCount() == 1);
    server.TestDispatchPeerMessageWithState(
        coordinator_state, *coordinator,
        P2PMessage(veld::MAINNET_MAGIC, veld::net::MessageType::PUNCHFWD, fwd));
    CHECK(server.TestAuthorizedPunchDialCount() == 1);

    server.TestPrimePunchClientExchange(coordinator, target_nonce, request_nonce, now + 60,
                                        now + 60, true, false);
    server.TestDispatchPeerMessageWithState(
        coordinator_state, *coordinator,
        P2PMessage(veld::MAINNET_MAGIC, veld::net::MessageType::PUNCHFWD, fwd));
    CHECK(server.TestAuthorizedPunchDialCount() == 1);
    server.TestDispatchPeerMessageWithState(
        attacker_state, *attacker,
        P2PMessage(veld::MAINNET_MAGIC, veld::net::MessageType::PUNCHFWD, fwd));
    CHECK(server.TestAuthorizedPunchDialCount() == 1);

    const size_t registrations_before = server.TestPunchRegistrationCount();
    server.TestDispatchPeerMessageWithState(
        incapable_state, *incapable,
        P2PMessage(veld::MAINNET_MAGIC, veld::net::MessageType::PUNCHHELLO, Bytes(target_nonce)));
    CHECK(server.TestPunchRegistrationCount() == registrations_before);
    // A legacy peer's old empty control frame passes the bounded structural
    // envelope, then is ignored at the capability gate without fragmenting
    // the otherwise healthy connection.
    server.TestDispatchPeerMessageWithState(
        incapable_state, *incapable,
        P2PMessage(veld::MAINNET_MAGIC, veld::net::MessageType::PUNCHHELLO, {}));
    CHECK(server.TestPunchRegistrationCount() == registrations_before);
    PeerState incomplete_state = ReadyPeerState();
    incomplete_state.handshake_done = false;
    server.TestDispatchPeerMessageWithState(
        incomplete_state, *attacker,
        P2PMessage(veld::MAINNET_MAGIC, veld::net::MessageType::PUNCHHELLO, Bytes(target_nonce)));
    CHECK(server.TestPunchRegistrationCount() == registrations_before);

    veld::Blockchain budget_chain;
    veld::Mempool budget_mempool;
    NodeServer budget_server(0, veld::MAINNET_MAGIC, budget_chain, budget_mempool);
    for (size_t i = 0; i < 8; ++i)
        CHECK(budget_server.TestTakePunchDialBudget());
    CHECK(!budget_server.TestTakePunchDialBudget());

    std::cout << "PASS punch_tests checks=" << checks
              << " authorized_dials=" << server.TestAuthorizedPunchDialCount() << '\n';
    return 0;
}
