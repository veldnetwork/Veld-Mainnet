#pragma once
#include "node/appchain_parent_feed_core.h"
#include <charconv>
#include <thread>

namespace veld {
// Outbound-only acquisition for the dedicated appchain validator. This owns no
// wallet, mining admission, signer or inbound listener.
class AppchainParentNetworkCore {
    VeldNode& node_;
    net::NodeServer server_;
    std::vector<std::pair<std::string, uint16_t>> peers_;
    std::jthread connector_;
    std::atomic<bool> running_{false};

  public:
    static std::pair<std::string, uint16_t> Endpoint(const std::string& text) {
        const auto colon = text.find(':');
        app::need(colon != std::string::npos && text.find(':', colon + 1) == std::string::npos,
                  "explicit IPv4 peer and port required");
        const auto host = text.substr(0, colon), portText = text.substr(colon + 1);
        in_addr address{};
        app::need(inet_pton(AF_INET, host.c_str(), &address) == 1, "canonical IPv4 peer required");
        char canonical[INET_ADDRSTRLEN]{};
        app::need(inet_ntop(AF_INET, &address, canonical, sizeof(canonical)) && host == canonical &&
                      ntohl(address.s_addr) != 0 && ntohl(address.s_addr) < 0xe0000000U,
                  "unicast peer address required");
        unsigned port = 0;
        const auto result =
            std::from_chars(portText.data(), portText.data() + portText.size(), port);
        app::need(result.ec == std::errc{} && result.ptr == portText.data() + portText.size() &&
                      port > 0 && port <= 65535 && std::to_string(port) == portText,
                  "canonical peer port required");
        return {host, uint16_t(port)};
    }
    AppchainParentNetworkCore(VeldNode& node, const std::filesystem::path& directory,
                              const std::vector<std::string>& peers)
        : node_(node), server_(0, MainnetConfig().magic, node.GetChainMut(), node.GetMempoolMut()) {
        app::need(peers.size() >= 2 && peers.size() <= 4,
                  "two to four explicit parent peers required");
        std::set<std::string> addresses;
        for (const auto& endpoint : peers) {
            auto parsed = Endpoint(endpoint);
            app::need(addresses.insert(parsed.first).second,
                      "distinct parent peer addresses required");
            peers_.push_back(parsed);
        }
        server_.SetBanFilePath((directory / "parent-bans.dat").string());
        server_.SetPeerCachePath((directory / "parent-peers.dat").string());
        server_.SetAnchorsPath((directory / "parent-anchors.dat").string());
        server_.SetPeerWorkViewTransitionFn(
            [this]() -> net::NodeServer::PeerWorkViewTransitionPermit {
                return std::make_shared<Blockchain::ConsensusTransitionGuard>(
                    node_.GetChainMut().AcquireConsensusTransitionGuard());
            });
        server_.SetValidatedOutboundServeFn(
            [this]() -> net::NodeServer::ValidatedOutboundServePermit {
                auto permit = std::make_shared<Blockchain::ConsensusTransitionGuard>(
                    node_.GetChainMut().AcquireConsensusTransitionGuard());
                if (!node_.ChainFullyValidated() || node_.FailStopRequired())
                    return {};
                return permit;
            });
        app::need(server_.Start({}, false), "outbound parent acquisition failed to start");
        running_ = true;
        connector_ = std::jthread([this](std::stop_token stop) {
            try {
                while (!stop.stop_requested()) {
                    for (const auto& [host, port] : peers_) {
                        if (stop.stop_requested())
                            break;
                        if (!server_.IsPeerConnected(host + ":" + std::to_string(port), true))
                            server_.ConnectTo(host, port);
                    }
                    // An outbound-only validator has no foreground mining
                    // supervisor to repair a missed inventory announcement.
                    // Retry its exact fully validated tip at most once per
                    // connector interval while peer evidence is behind. This
                    // does not grant freshness or bypass remote validation.
                    {
                        auto permit = node_.GetChainMut().AcquireConsensusTransitionGuard();
                        const auto tip = node_.GetChain().TipCopy();
                        const auto view = server_.GetPeerHeightView();
                        if (node_.ChainFullyValidated() && !node_.FailStopRequired() &&
                            view.distinct_outbound_sync_ips >= 2 &&
                            view.verified_height < tip.height) {
                            server_.BroadcastBlock(tip);
                            server_.BroadcastTipsig();
                        }
                    }
                    for (unsigned i = 0; i < 120 && !stop.stop_requested(); ++i)
                        std::this_thread::sleep_for(std::chrono::milliseconds(250));
                }
            } catch (...) {
                running_ = false;
            }
        });
    }
    ~AppchainParentNetworkCore() {
        running_ = false;
        connector_.request_stop();
        if (connector_.joinable())
            connector_.join();
        server_.Stop();
    }
    // Only the private feed calls this after full durable block admission,
    // while holding the native consensus-transition guard.
    void RelayValidated(const Block& block) {
        app::need(running_ && node_.ChainFullyValidated() && !node_.FailStopRequired() &&
                      node_.GetChain().HasBlockAtHeight(block.height, HashToHex(block.GetHash())) &&
                      node_.GetChain().GetBlock(block.height).Serialize() == block.Serialize(),
                  "only a durably validated canonical parent can be relayed");
        // Fresh locally validated work must carry its body, as the foreground
        // miner does. Peers still in initial download intentionally ignore
        // unsolicited inbound inventory; inventory alone delayed this path
        // until their next locator request. The normal remote BLOCK handler
        // still performs complete consensus admission.
        server_.BroadcastMessage(
            P2PMessage(MainnetConfig().magic, MessageType::BLOCK, block.Serialize()));
        server_.BroadcastTipsig();
    }
    void RelayAdmittedTransaction(const Transaction& transaction) {
        const auto retained =
            node_.GetMempoolMut().GetTransaction(HashToHex(transaction.GetTxID()));
        const auto health = Status();
        app::need(running_ && node_.ChainFullyValidated() && !node_.FailStopRequired() &&
                      health.size() == 105 && health[78] == 1 && retained &&
                      retained->Serialize() == transaction.Serialize(),
                  "only an exactly admitted settlement can be relayed on a ready parent network");
        server_.BroadcastTransaction(transaction);
    }
    // The caller holds the native consensus-transition guard. Peer evidence
    // uses that same sequencer, so the returned tip and freshness are coherent.
    app::Bytes Status() const {
        const auto tip = node_.GetChain().TipCopy();
        const auto view = server_.GetPeerHeightView();
        const bool ready =
            running_ && view.work_view_stable && view.work_sequencer_wired &&
            view.distinct_outbound_sync_ips >= 2 && view.verified_height >= tip.height &&
            view.outbound_sync_height <= tip.height && view.freshness_valid_for_ms > 5000 &&
            view.freshness_valid_for_ms != UINT64_MAX;
        app::Writer out;
        out.raw(app::Bytes{'V', 'P', 'N', 'H', 1});
        out.raw(CreateGenesisBlock().GetHash());
        out.n(tip.height, 8);
        out.raw(tip.GetHash());
        out.n(running_, 1);
        out.n(ready, 1);
        out.n(std::min<size_t>(view.distinct_outbound_sync_ips, 65535), 2);
        out.n(view.verified_height, 8);
        out.n(view.outbound_sync_height, 8);
        out.n(view.freshness_valid_for_ms, 8);
        return out.b;
    }
};
} // namespace veld
