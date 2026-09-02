#include "consensus/state_digest.h"
#include "network/tcp.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

using namespace veld;

namespace {

size_t checks = 0;

#define CHECK(expr)                                                          \
    do {                                                                     \
        ++checks;                                                            \
        if (!(expr)) {                                                       \
            std::cerr << "FAIL " << __FILE__ << ':' << __LINE__             \
                      << " " #expr "\n";                                    \
            return 1;                                                        \
        }                                                                    \
    } while (false)

Hash256 Tagged(const std::string& value) {
    return Hash256d(std::vector<uint8_t>(value.begin(), value.end()));
}

Hash256 Envelope(bool v8, const Hash256& finality) {
    const Hash256 tip = Tagged("tip");
    const Hash256 component = Tagged("unchanged-component");
    if (v8) {
        return state_digest::ComposeV8(
            91, tip,
            component, component, component, component,
            component, component, component, component,
            component, component, component, component,
            finality, component);
    }
    return state_digest::ComposeV7(
        91, tip,
        component, component, component, component,
        component, component, component, component,
        component, component, component, component,
        finality, component);
}

} // namespace

int main() {
    CHECK(std::string(MessageType::FINVOTE) == "finvote");
    CHECK(P2P_FINALITY_VOTE_WIRE_BYTES ==
          finality::wire::SIGNED_VOTE_BYTES);

    const auto bounds =
        net::Connection::BoundsForCommand(MessageType::FINVOTE);
    CHECK(bounds.minimum == P2P_FINALITY_VOTE_WIRE_BYTES);
    CHECK(bounds.maximum == P2P_FINALITY_VOTE_WIRE_BYTES);

    std::vector<uint8_t> canonical_vote(P2P_FINALITY_VOTE_WIRE_BYTES, 0);
    canonical_vote[0] = 'F';
    canonical_vote[1] = 'V';
    canonical_vote[2] = 'T';
    canonical_vote[3] = '1';
    PeerManager peer_manager(MAINNET_MAGIC, 91);
    const P2PMessage message =
        peer_manager.BuildFinalityVoteMessage(canonical_vote);
    CHECK(message.magic == MAINNET_MAGIC);
    CHECK(message.command == MessageType::FINVOTE);
    CHECK(message.payload == canonical_vote);
    const auto wire = message.Serialize();
    CHECK(wire.size() == 24 + P2P_FINALITY_VOTE_WIRE_BYTES);
    CHECK(std::equal(canonical_vote.begin(), canonical_vote.end(),
                     wire.begin() + 24));

    CHECK(net::NodeServer::FinalityCryptoWorkerCount(1) == 1);
    CHECK(net::NodeServer::FinalityCryptoWorkerCount(3) == 1);
    CHECK(net::NodeServer::FinalityCryptoWorkerCount(4) == 2);
    CHECK(net::NodeServer::FinalityCryptoWorkerCount(64) == 2);

    const Hash256 finality_a =
        state_digest::FinalityDigest(77, 1, 64);
    const Hash256 finality_b =
        state_digest::FinalityDigest(78, 1, 64);
    CHECK(finality_a != finality_b);
    CHECK(Envelope(false, finality_a) != Envelope(false, finality_b));
    CHECK(Envelope(true, finality_a) != Envelope(true, finality_b));
    CHECK(Envelope(false, finality_a) != Envelope(true, finality_a));

    std::cout << "PASS daybreak_finality_compat_tests checks=" << checks
              << " wire_bytes=" << P2P_FINALITY_VOTE_WIRE_BYTES
              << " v7_v8_domain_separated=1\n";
    return 0;
}
