// Public-profile transport qualification with authenticated historical blocks.
#include "node/node.h"
#include <fstream>
#include <iostream>
#include <set>
#include <thread>

namespace fs = std::filesystem;
using namespace veld;
static void Require(bool ok, const char* text) {
    if (!ok)
        throw std::runtime_error(text);
    std::cout << "PASS " << text << std::endl;
}
static std::string Read(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f)
        throw std::runtime_error("fixture input missing");
    return {std::istreambuf_iterator<char>(f), {}};
}
static void Write(const fs::path& p, const std::string& s) {
    if (fs::exists(p))
        throw std::runtime_error("result exists");
    std::ofstream f(p, std::ios::binary);
    f << s;
    if (!f)
        throw std::runtime_error("result write failed");
}
template <class F>
static void Await(F f, const char* label,
                  std::chrono::seconds allowance = std::chrono::seconds(120)) {
    const auto started = std::chrono::steady_clock::now();
    const auto deadline = started + allowance;
    while (!f()) {
        if (std::chrono::steady_clock::now() > deadline)
            throw std::runtime_error(label);
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    Require(true, label);
    std::cout << "ELAPSED_MS " << label << " "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now() - started)
                     .count()
              << std::endl;
}
struct QualificationPeer {
    net::Connection conn;
    uint32_t magic;
    std::jthread receiver;
    std::atomic<bool> acknowledged{false};
    static int Dial(uint16_t port) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            throw std::runtime_error("peer socket failed");
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            close(fd);
            throw std::runtime_error("peer connect failed");
        }
        const int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            close(fd);
            throw std::runtime_error("nonblocking socket failed");
        }
        return fd;
    }
    QualificationPeer(uint16_t port, uint32_t m) : conn(Dial(port), "127.0.0.1", port), magic(m) {
        receiver = std::jthread([this](std::stop_token stop) {
            while (!stop.stop_requested() && conn.IsConnected()) {
                auto msg = conn.RecvMessage(magic);
                if (!msg)
                    break;
                if (msg->command == MessageType::VERSION)
                    conn.Send(P2PMessage(magic, MessageType::VERACK, {}));
                if (msg->command == MessageType::VERACK)
                    acknowledged = true;
                if (msg->command == MessageType::PING)
                    conn.Send(P2PMessage(magic, MessageType::PONG, msg->payload));
            }
        });
        VersionPayload v;
        v.start_height = 19612;
        v.nonce = 0x56454c4451545031ULL;
        v.services = MessageType::NODE_FULL | MessageType::REQUIRED_NETWORK_IDENTITY_SERVICES;
        conn.Send(P2PMessage(magic, MessageType::VERSION, v.Serialize()));
        Await([&] { return acknowledged.load(); }, "public VERSION/VERACK handshake");
    }
    ~QualificationPeer() {
        receiver.request_stop();
        conn.Close();
        if (receiver.joinable())
            receiver.join();
    }
    void Send(const Block& block) {
        Require(conn.Send(P2PMessage(magic, MessageType::BLOCK, block.Serialize())),
                "historical block sent through TCP");
    }
};

int main(int argc, char** argv) {
    try {
        Require(argc == 3, "mode and disposable root supplied");
        const std::string mode = argv[1];
        const auto root = fs::canonical(argv[2]);
        Require(Read(root / ".qualification-only") == "public-p2p-reorg\n", "isolated test marker");
        Require(!APPCHAIN_BRIDGE_ENABLED, "public bridge remains inactive");
        const auto basehash = Read(root / "base-tip");
        const auto basedigest = Read(root / "base-digest");
        const auto data = root / "data";
        std::vector<Block> blocks;
        Block fork;
        {
            db::VeldDB disk((root / "donor/db").string());
            for (uint64_t h = 19562; h <= 19612; ++h) {
                auto hash = disk.GetHashAtHeight(h);
                Require(hash.has_value(), "authenticated successor index");
                auto raw = disk.ReadBlock(HexToHash(*hash));
                Require(raw.has_value(), "authenticated successor body");
                Block b;
                Require(Block::Deserialize(*raw, 0, b) == raw->size() && b.Serialize() == *raw &&
                            HashToHex(b.GetHash()) == *hash,
                        "successor encoding and identity");
                b.height = h;
                blocks.push_back(b);
            }
        }
        const auto raw = Read(root / "orphan.block");
        std::vector<uint8_t> bytes(raw.begin(), raw.end());
        Require(Block::Deserialize(bytes, 0, fork) == bytes.size() && fork.Serialize() == bytes,
                "orphan canonical encoding");
        fork.height = 19606;
        Require(HashToHex(fork.GetHash()) ==
                    "ada6eb556e12d3d569b48b03ca95acba5f679a428ac8fb56861642d65f87897c",
                "orphan source identity");
        vendored_crypto::vendored_crypto_selftest();
        VeldNode node(MainnetConfig(), data.string());
        node.SetStakingActivation(STAKING_ACTIVATION_SUPPLY);
        if (mode == "network") {
            // The driver verifies the prior completed full-PoW receipt and exact
            // immutable source/chain bytes before reusing this historical prefix.
            // New peer blocks always undergo normal production PoW verification.
            node.PrepareSnapshotCandidateReplay(19561, basehash);
            node.ValidateStoredChainOnly(19561, basehash, false);
            Require(HashToHex(node.ConsensusStateDigest()) == basedigest,
                    "replayed prefix matches prior fully verified state");
            Require(!node.IsMiningReady(), "qualification opens no mining admission");
            std::mutex accepted_mutex;
            std::set<std::string> accepted;
            net::NodeServer server(58461, MainnetConfig().magic, node.GetChainMut(),
                                   node.GetMempoolMut());
            server.SetBanFilePath((root / "bans").string());
            server.SetPeerCachePath((root / "peers").string());
            server.SetAnchorsPath((root / "anchors").string());
            server.SetBlockCallback([&](const Block& b, const std::string&) {
                std::lock_guard lock(accepted_mutex);
                accepted.insert(HashToHex(b.GetHash()));
            });
            Require(server.Start(), "production event-loop transport started");
            {
                QualificationPeer peer(58461, MainnetConfig().magic);
                auto send = [&](const Block& b) {
                    peer.Send(b);
                    const auto hash = HashToHex(b.GetHash());
                    // A completed reorg also rebuilds display indexes over the
                    // historical prefix. Measure that cost without confusing a
                    // two-minute transport deadline with a validation failure.
                    // The production validator and persistence hooks are unchanged.
                    Await(
                        [&] {
                            std::lock_guard lock(accepted_mutex);
                            return accepted.contains(hash);
                        },
                        "peer block passed native consensus admission", std::chrono::seconds(900));
                };
                for (const auto& b : blocks) {
                    if (b.height == 19606) {
                        Require(
                            HashToHex(node.GetChain().TipCopy().GetHash()) ==
                                "d6e1a0a557bbe00e57d6454165037180c37c1b53b766e2dc932b68de97f2bcde",
                            "fork parent reached");
                        send(fork);
                        Require(node.GetChain().TipCopy().GetHash() == fork.GetHash(),
                                "actual historical orphan selected before competing branch");
                    }
                    send(b);
                    if (b.height == 19607)
                        Require(node.GetChain().TipCopy().GetHash() == b.GetHash(),
                                "higher-work historical branch replaces orphan over TCP");
                }
                Require(node.GetChain().Height() == 19612 &&
                            node.GetChain().TipCopy().GetHash() == blocks.back().GetHash(),
                        "canonical public tip restored");
                const auto digest = node.ConsensusStateDigest();
                peer.Send(fork);
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                Require(node.ConsensusStateDigest() == digest &&
                            node.GetChain().TipCopy().GetHash() == blocks.back().GetHash(),
                        "duplicate losing branch cannot alter canonical state");
                Require(server.GetPeerInfoList().size() == 1, "exactly one isolated peer");
                Write(root / "final-digest", HashToHex(digest));
                Write(root / "final-tip", HashToHex(blocks.back().GetHash()));
            }
            server.Stop();
            Require(server.ConnectedPeers() == 0, "owned transport stopped");
        } else if (mode == "restart") {
            node.SetSnapshotFastStartEligible(true, 19561, basehash);
            node.ValidateStoredChainOnly(19612, Read(root / "final-tip"), false);
            Require(HashToHex(node.ConsensusStateDigest()) == Read(root / "final-digest"),
                    "cold replay preserves exact post-reorg state");
            Require(
                node.GetChain().HasBlockAtHeight(19606, HashToHex(blocks[19606 - 19562].GetHash())),
                "cold replay selects canonical fork height");
            Require(node.GetTCPServer() == nullptr && !node.IsMiningReady(),
                    "restart opens neither networking nor mining");
        } else
            throw std::runtime_error("unknown mode");
        std::cout << "PASS_PUBLIC_P2P_REORG mode=" << mode
                  << " tip=" << HashToHex(node.GetChain().TipCopy().GetHash())
                  << " digest=" << HashToHex(node.ConsensusStateDigest()) << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL_PUBLIC_P2P_REORG " << e.what() << std::endl;
        return 1;
    }
}
