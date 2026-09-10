#define VELD_LOCAL_TEST_NETWORK 1
#define VELD_TEST_HOOKS 1
#include "isolated_regtest_profile.h"
#include "network/tcp.h"

#include <iostream>
#include <stdexcept>

using namespace veld;
using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;
using Server = net::NodeServer;
using Connection = net::Connection;

namespace {
constexpr uint32_t MAGIC = 0xF17EBA6C;
size_t checks = 0;
void Check(bool value, const char* label) {
    ++checks;
    if (!value) throw std::runtime_error(label);
}

void InitChain(Blockchain& chain) {
    Check(chain.AddBlockDirect(CreateGenesisBlock(), true, false, false,
        mining::PowAdmissionContext::Internal()).IsAccepted(), "genesis admission");
}

uint16_t AvailableLoopbackPort() {
    auto socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Check(compat::IsValidSocket(socket), "port reservation socket");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Check(::bind(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0,
        "reserve loopback port");
    socklen_t length = sizeof(address);
    Check(::getsockname(socket, reinterpret_cast<sockaddr*>(&address), &length) == 0,
        "read reserved port");
    const auto port = ntohs(address.sin_port);
    VELD_CLOSE_SOCKET(socket);
    return port;
}

std::string PeerId(Server& receiver, uint64_t nonce) {
    for (const auto& peer : receiver.GetPeerInfoList())
        if (peer.node_id == nonce) return peer.connection_id;
    return {};
}

struct RawPeer {
    std::unique_ptr<Connection> connection;
    uint64_t nonce;
    bool malformed;
    bool sent_malformed = false;
    int64_t closed_at = -1;

    RawPeer(uint16_t port, uint64_t id, bool invalid_tip) : nonce(id), malformed(invalid_tip) {
        const auto socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        Check(compat::IsValidSocket(socket), "raw peer socket");
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(port);
        Check(::connect(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0,
            "raw peer loopback connect");
        connection = std::make_unique<Connection>(socket, "127.0.0.1", port, false);
        VersionPayload version;
        version.nonce = nonce;
        version.services = MessageType::NODE_FULL |
            MessageType::REQUIRED_NETWORK_IDENTITY_SERVICES;
        Check(connection->Send(P2PMessage(MAGIC, MessageType::VERSION, version.Serialize())),
            "raw VERSION");
        Check(connection->Send(P2PMessage(MAGIC, MessageType::VERACK)), "raw VERACK");
    }

    void Poll(int64_t elapsed) {
        if (!connection->IsConnected()) {
            if (closed_at < 0) closed_at = elapsed;
            return;
        }
        for (int i = 0; i < 32; ++i) {
            const auto result = connection->TryRecvMessage(MAGIC);
            if (result.status != Connection::TryRecvStatus::MessageReady) break;
            if (result.msg.command == MessageType::PING)
                connection->Send(P2PMessage(MAGIC, MessageType::PONG, result.msg.payload));
            if (malformed && !sent_malformed && result.msg.command == MessageType::VERACK) {
                // Correct frame length and version, but an invalid zero hash.
                // A short frame is rejected earlier by the framing guard.
                std::vector<uint8_t> payload(44, 0);
                for (int byte = 0; byte < 4; ++byte)
                    payload[byte] = (PROTOCOL_VERSION >> (byte * 8)) & 0xff;
                connection->Send(P2PMessage(MAGIC, MessageType::TIPSIG, std::move(payload)));
                sent_malformed = true;
            }
        }
    }
};
}

int main() {
    try {
        compat::InitNetwork();
        Blockchain receiver_chain, first_chain, second_chain, foreground_chain;
        for (auto* chain : {&receiver_chain, &first_chain, &second_chain, &foreground_chain})
            InitChain(*chain);
        Mempool receiver_pool, first_pool, second_pool, foreground_pool;
        std::unique_ptr<Server> receiver;
        uint16_t port = 0;
        for (int attempt = 0; attempt < 8; ++attempt) {
            port = AvailableLoopbackPort();
            auto candidate = std::make_unique<Server>(port, MAGIC, receiver_chain, receiver_pool);
            if (candidate->Start()) { receiver = std::move(candidate); break; }
        }
        Check(bool(receiver), "real receiving NodeServer listener");
        Server first(0, MAGIC, first_chain, first_pool);
        Server second(0, MAGIC, second_chain, second_pool);
        Server foreground(0, MAGIC, foreground_chain, foreground_pool);
        Check(first.Start({}, false), "first background start");
        Check(second.Start({}, false), "second background start");
        Check(foreground.Start({}, false), "foreground peer start");
        Check(first.ConnectTo("127.0.0.1", port), "first background connect");
        RawPeer missing(port, 0x1700000001, false);
        RawPeer malformed(port, 0x1700000002, true);

        const auto start = Clock::now();
        int64_t last_receiver_tip = -30, last_foreground_tip = -30, last_report = -1;
        bool second_connected = false, foreground_connected = false, restarted = false;
        std::string old_first_id, new_first_id;
        uint64_t cursor = 0, lost = 0;
        int timeout_events = 0;
        int64_t first_missing_at = -1, second_missing_at = -1;
        while (Clock::now() - start < 245s) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                Clock::now() - start).count();
            // These are the receiving node's real maintenance methods. The
            // background peers get no foreground BroadcastTipsig assistance.
            receiver->ReapStuckHandshakes();
            receiver->ReapIdlePeers();
            if (elapsed - last_receiver_tip >= 30) {
                receiver->BroadcastTipsig();
                last_receiver_tip = elapsed;
            }
            if (!second_connected && elapsed >= 8) {
                Check(second.ConnectTo("127.0.0.1", port), "second same-IP connect");
                second_connected = true;
            }
            if (!foreground_connected && elapsed >= 16) {
                Check(foreground.ConnectTo("127.0.0.1", port), "foreground same-IP connect");
                foreground_connected = true;
            }
            // Deliberately suspend foreground supervision for one minute.
            if (foreground_connected && !(elapsed >= 45 && elapsed < 105) &&
                    elapsed - last_foreground_tip >= 30) {
                foreground.BroadcastTipsig();
                last_foreground_tip = elapsed;
            }
            missing.Poll(elapsed);
            malformed.Poll(elapsed);
            for (const auto& event : net::connection_diagnostics::Since(cursor, lost)) {
                if (event.reason == Connection::CloseReason::HandshakeTimeout)
                    ++timeout_events;
            }
            Check(lost == 0, "connection diagnostic capture is complete");
            if (elapsed >= 25) {
                if (PeerId(*receiver, first.TopologyId()).empty() && !restarted && first_missing_at < 0)
                    first_missing_at = elapsed;
                if (PeerId(*receiver, second.TopologyId()).empty() && second_missing_at < 0)
                    second_missing_at = elapsed;
                if (old_first_id.empty()) old_first_id = PeerId(*receiver, first.TopologyId());
            }
            if (elapsed >= 115 && !restarted) {
                const bool first_live = !PeerId(*receiver, first.TopologyId()).empty();
                const bool second_live = !PeerId(*receiver, second.TopologyId()).empty();
                std::cout << "deadline_check first=" << first_live << " second=" << second_live
                    << " first_missing_s=" << first_missing_at << " second_missing_s=" << second_missing_at
                    << " missing_tip_closed_s=" << missing.closed_at
                    << " malformed_tip_closed_s=" << malformed.closed_at
                    << " handshake_timeouts=" << timeout_events << std::endl;
                Check(first_live && second_live, "background connections were reaped after handshake grace");
                Check(missing.closed_at >= 85 && missing.closed_at <= 110, "missing TIPSIG remains rejected");
                Check(malformed.sent_malformed && malformed.closed_at >= 85 &&
                    malformed.closed_at <= 110, "malformed TIPSIG cannot bypass the reaper");
                Check(receiver->VersionReadyPeers() == 1, "same-IP connections remain one quorum source");
                const auto before_stop = Clock::now();
                first.Stop();
                Check(Clock::now() - before_stop < 2s, "background stop remains bounded");
                Check(first.Start({}, false), "same object restart");
                Check(first.ConnectTo("127.0.0.1", port), "restarted background reconnect");
                restarted = true;
            }
            if (restarted && elapsed >= 120) {
                if (new_first_id.empty()) new_first_id = PeerId(*receiver, first.TopologyId());
                Check(!new_first_id.empty() && new_first_id != old_first_id,
                    "reconnect owns a new connection identity");
                Check(PeerId(*receiver, first.TopologyId()) == new_first_id,
                    "reconnected background remains attached");
                Check(!PeerId(*receiver, second.TopologyId()).empty(),
                    "same-IP neighbor remains connected");
                Check(!PeerId(*receiver, foreground.TopologyId()).empty(),
                    "foreground connection remains attached");
            }
            if (elapsed / 30 != last_report) {
                last_report = elapsed / 30;
                std::cout << "elapsed_s=" << elapsed << " peers=" << receiver->ConnectedPeers()
                    << " handshake_timeouts=" << timeout_events << std::endl;
            }
            std::this_thread::sleep_for(20ms);
        }
        Check(restarted && !new_first_id.empty(), "restart scenario completed");
        // Both intentionally incomplete peers were checked at the real
        // deadline above. Valid peers retain the same connection identities.
        // Concurrent socket cleanup may record a close before the reaper's
        // diagnostic reason, so event-label counts are informational.
        const auto before_stop = Clock::now();
        first.Stop(); second.Stop(); foreground.Stop(); receiver->Stop();
        Check(Clock::now() - before_stop < 3s, "all peers stop cleanly");
        std::cout << "PASS background peer liveness checks=" << checks
            << " duration_s=245 same_ip=1 reconnect_survived_s=130 reaper_unchanged=1" << std::endl;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL background peer liveness: " << error.what() << std::endl;
        return 1;
    }
}
