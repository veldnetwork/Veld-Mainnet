#pragma once
#include "../compat/platform.h"

#include "../core/constants.h"
#include "../core/version.h"
#include "../core/hash.h"
#include "../core/block.h"
#include "../core/transaction.h"
#include "../consensus/finality_wire_profile.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <memory>
#include <cstdint>
#include <ctime>
#include <sstream>

namespace veld {

// Exact compact FINVOTE payload envelope.  Keep the transport bound derived
// from the ML-DSA profile instead of duplicating the current numeric size in
// tcp.h; finality_codec.h statically locks its encoder/decoder layout to this
// transport constant.
constexpr size_t P2P_FINALITY_VOTE_WIRE_BYTES =
    ::veld::finality::wire::SIGNED_VOTE_BYTES;

namespace MessageType {
    constexpr const char* VERSION     = "version";
    constexpr const char* VERACK      = "verack";
    constexpr const char* PING        = "ping";
    constexpr const char* PONG        = "pong";
    constexpr const char* GETBLOCKS   = "getblocks";
    constexpr const char* TX          = "tx";
    constexpr const char* BLOCK       = "block";
    constexpr const char* GETDATA     = "getdata";
    constexpr const char* INV         = "inv";
    constexpr const char* ADDR        = "addr";
    constexpr const char* GETADDR     = "getaddr";
    constexpr const char* REJECT      = "reject";
    constexpr const char* MEMPOOL     = "mempool";
    constexpr const char* SOLUTION    = "solution";
    constexpr const char* COMINE      = "comine";
    constexpr const char* TIPSIG      = "tipsig";
    constexpr const char* STATSIG     = "statsig";
    constexpr const char* FINVOTE     = "finvote"; // verified locked-QC vote relay
    // ---- NAT hole-punch v2. Every command is capability-gated and carries a
    //      connection-bound, one-use random correlation value. Peers that do
    //      not advertise NODE_HOLE_PUNCH are never sent these payloads. ----
    constexpr const char* PUNCHHELLO  = "punchhello"; // client -> coordinator: target nonce
    constexpr const char* GETPUNCH    = "getpunch";   // client -> coordinator: request nonce
    constexpr const char* PUNCHLIST   = "punchlist";  // coordinator -> client: correlated offers
    constexpr const char* PUNCHREQ    = "punchreq";   // client -> coordinator: correlated selection
    constexpr const char* PUNCHFWD    = "punchfwd";   // coordinator -> target: correlated requester
    // ---- Tor. Clearnet-only peers ignore this (they
    //      can't dial .onion anyway); Tor-capable peers dial the advertised
    //      hidden service through SOCKS5. ----
    constexpr const char* ONIONADV    = "onionadv";   // node -> peers: "my .onion is <addr>"

    // ---- RESERVED: compact-block relay (BIP152-style). Wired now so the
    //      future codec lands as a PURE ADDITIVE DROP-IN — no protocol-version
    //      bump, no flag day, no fork risk, and auto-engaging by block size.
    //      Current nodes ignore these commands (PeerProtocolStep ->
    //      NotHandled), so a mixed network never splits. Activation contract:
    //        1. A compact-capable node sets services bit NODE_COMPACT_BLOCKS
    //           (0x02) in VERSION. Compact relay is used ONLY between two peers
    //           that BOTH advertise it; with anyone else, fall back to the
    //           existing INV/GETDATA/direct-push path.
    //        2. For blocks >= COMPACT_BLOCK_MIN_BYTES the sender relays a
    //           CMPCTBLOCK (header + 6-byte short TXIDs); the peer rebuilds
    //           from its mempool and pulls any missing txs via GETBLOCKTXN ->
    //           BLOCKTXN. Smaller blocks keep the direct-push fast path.
    //      Effect: shrinks the over-Tor block payload ~100x once blocks grow,
    //      cutting propagation latency / orphan rate at scale. Until the codec
    //      ships, NO node sets bit 0x02, so this reservation is inert.
    constexpr const char* SENDCMPCT   = "sendcmpct";   // negotiate compact-block relay
    constexpr const char* CMPCTBLOCK  = "cmpctblock";  // header + short TXIDs (<=12B cmd)
    constexpr const char* GETBLOCKTXN = "getblocktxn"; // request missing txs by index
    constexpr const char* BLOCKTXN    = "blocktxn";    // supply requested txs

    // ---- Service-capability bits (VERSION `services` bitfield).
    //      0x01 = NODE_FULL is live + advisory. Unknown bits remain
    //      forward-compatible because older nodes ignore them.
    constexpr uint64_t NODE_FULL           = 0x01;
    constexpr uint64_t NODE_COMPACT_BLOCKS = 0x02; // reserved (see above)
    constexpr uint64_t NODE_ONION          = 0x04; // node is reachable via .onion
    // Advisory display roles. These bits never grant protocol privileges and
    // are not consensus inputs; they let peer UIs describe the direct mesh
    // without exposing addresses. Older peers simply omit them.
    constexpr uint64_t NODE_MINER          = 0x08;
    constexpr uint64_t NODE_VALIDATOR      = 0x10;
    constexpr uint64_t NODE_FLEET          = 0x20;
    constexpr uint64_t NODE_HOLE_PUNCH     = 0x40;
    // Consensus-compatibility bit for the fresh-mainnet rolling-reserve
    // semantics. Unlike advisory role bits, an activated reserve profile
    // requires this during VERSION so an old empty-datadir binary cannot join
    // and interpret RTP1 carriers as paid no-ops.
    constexpr uint64_t NODE_BTCVELD_RESERVE_V1 = 0x80;
#if defined(VELD_PUBLIC_MAINNET) || defined(VELD_BTCVELD_REGTEST)
    constexpr uint64_t REQUIRED_NETWORK_IDENTITY_SERVICES =
        NODE_BTCVELD_RESERVE_V1;
#else
    constexpr uint64_t REQUIRED_NETWORK_IDENTITY_SERVICES = 0;
#endif
}

enum class InvType : uint32_t {
    INV_ERROR   = 0,
    TX          = 1,
    BLOCK       = 2,
};

struct InvItem {
    InvType type;
    Hash256 hash;

    InvItem(InvType t, const Hash256& h) : type(t), hash(h) {}
};

struct P2PMessage {
    uint32_t magic;
    std::string command;
    std::vector<uint8_t> payload;

    P2PMessage() : magic(MAINNET_MAGIC) {}
    P2PMessage(uint32_t m, const std::string& cmd, std::vector<uint8_t> p = {})
        : magic(m), command(cmd), payload(std::move(p)) {}

    std::vector<uint8_t> Serialize() const {
        std::vector<uint8_t> wire;

        wire.push_back(magic & 0xFF);
        wire.push_back((magic >> 8) & 0xFF);
        wire.push_back((magic >> 16) & 0xFF);
        wire.push_back((magic >> 24) & 0xFF);

        char cmd[12] = {0};
        size_t len = std::min(command.size(), (size_t)12);
        for (size_t i = 0; i < len; ++i) cmd[i] = command[i];
        wire.insert(wire.end(), cmd, cmd + 12);

        uint32_t plen = (uint32_t)payload.size();
        wire.push_back(plen & 0xFF);
        wire.push_back((plen >> 8) & 0xFF);
        wire.push_back((plen >> 16) & 0xFF);
        wire.push_back((plen >> 24) & 0xFF);

        Hash256 chk = Hash256d(payload);
        wire.push_back(chk[0]);
        wire.push_back(chk[1]);
        wire.push_back(chk[2]);
        wire.push_back(chk[3]);

        wire.insert(wire.end(), payload.begin(), payload.end());
        return wire;
    }
};

// ─────────────────────────────────────────────
//  VERSION MESSAGE PAYLOAD
//  First message sent when connecting to a peer
//
//   — PEER IDENTITY TRUST MODEL:
//  Peer identity (user_agent, services, start_height) is self-declared
//  and NOT cryptographically bound. Veld intentionally operates under a
//  Sybil-tolerant PoW consensus model: nothing in the on-wire protocol
//  gates capabilities on peer identity — every peer is treated as an
//  untrusted speaker. Validator status is an on-chain property derived
//  from stake ledger and REGISTER ops, not from a wire claim. Full-node
//  flag (services & 0x01) is advisory only, used for relay selection,
//  never consensus gating. If you add a future capability that consumes
//  peer-declared state, gate it on-chain, not at the VERSION payload.
// ─────────────────────────────────────────────
struct VersionPayload {
    uint32_t version;
    uint64_t services;
    uint64_t timestamp;
    std::string user_agent;
    uint64_t start_height;
    bool     relay;
    uint64_t nonce;
    Hash256 genesis_hash;

    VersionPayload()
        : version(PROTOCOL_VERSION)
        , services(0x01)
        , timestamp((uint64_t)std::time(nullptr))
        , user_agent(CLIENT_USER_AGENT)
        , start_height(0)
        , relay(true)
        , nonce(0)
        , genesis_hash{} {
        auto bytes = HexToBytes(GENESIS_HASH);
        if (bytes.size() == 32) {
            std::copy(bytes.begin(), bytes.end(), genesis_hash.begin());
        }
    }

    std::vector<uint8_t> Serialize() const {
        std::vector<uint8_t> data;
        data.push_back(version & 0xFF);
        data.push_back((version >> 8) & 0xFF);
        data.push_back((version >> 16) & 0xFF);
        data.push_back((version >> 24) & 0xFF);
        for (int i = 0; i < 8; ++i) data.push_back((services >> (i*8)) & 0xFF);
        for (int i = 0; i < 8; ++i) data.push_back((timestamp >> (i*8)) & 0xFF);
        for (int i = 0; i < 8; ++i) data.push_back((start_height >> (i*8)) & 0xFF);
        data.push_back((uint8_t)user_agent.size());
        data.insert(data.end(), user_agent.begin(), user_agent.end());
        data.push_back(relay ? 1 : 0);
        for (int i = 0; i < 8; ++i) data.push_back((nonce >> (i*8)) & 0xFF);
        data.insert(data.end(), genesis_hash.begin(), genesis_hash.end());
        return data;
    }
};

enum class PeerState {
    DISCONNECTED,
    CONNECTING,
    VERSION_SENT,
    VERSION_RECEIVED,
    CONNECTED,
    BANNED
};

struct Peer {
    std::string  address;
    uint16_t     port;
    PeerState    state;
    uint32_t     protocol_version;
    std::string  user_agent;
    uint64_t     services;
    uint64_t     best_height;
    uint64_t     connected_time;
    uint64_t     last_seen;
    uint64_t     last_ping;
    uint64_t     ping_nonce;
    uint64_t     ping_latency_ms;
    bool         is_inbound;
    uint32_t     ban_score;
    std::unordered_set<std::string> known_inv;

    Peer()
        : port(0), state(PeerState::DISCONNECTED)
        , protocol_version(0), services(0), best_height(0)
        , connected_time(0), last_seen(0), last_ping(0)
        , ping_nonce(0), ping_latency_ms(0)
        , is_inbound(false), ban_score(0) {}

    explicit Peer(const std::string& addr, uint16_t p = MAINNET_PORT)
        : address(addr), port(p), state(PeerState::DISCONNECTED)
        , protocol_version(0), services(0), best_height(0)
        , connected_time((uint64_t)std::time(nullptr))
        , last_seen((uint64_t)std::time(nullptr))
        , last_ping(0), ping_nonce(0), ping_latency_ms(0)
        , is_inbound(false), ban_score(0) {}

    bool IsConnected()  const { return state == PeerState::CONNECTED; }
    bool IsBanned()     const { return state == PeerState::BANNED; }
    bool IsFullNode()   const { return services & 0x01; }

    void AddBanScore(uint32_t score) {
        auto now = std::chrono::steady_clock::now();
        if (last_ban_event != std::chrono::steady_clock::time_point{}) {
            auto mins = std::chrono::duration_cast<std::chrono::minutes>(now - last_ban_event).count();
            if (mins > 0) {
                uint32_t decay = (uint32_t)std::min<int64_t>(mins, (int64_t)ban_score);
                ban_score -= decay;
            }
        }
        last_ban_event = now;
        ban_score += score;
        if (ban_score >= 100) state = PeerState::BANNED;
    }
    std::chrono::steady_clock::time_point last_ban_event{};

    std::string GetInfo() const {
        std::ostringstream oss;
        oss << address << ":" << port
            << " [" << (is_inbound ? "in" : "out") << "]"
            << " height=" << best_height
            << " ping=" << ping_latency_ms << "ms"
            << " agent=" << user_agent;
        return oss.str();
    }
};

using OnBlockReceived = std::function<void(const std::string& peer_addr, const std::vector<uint8_t>& block_data)>;
using OnTxReceived    = std::function<void(const std::string& peer_addr, const std::vector<uint8_t>& tx_data)>;
using OnPeerConnected = std::function<void(const std::string& peer_addr)>;
using OnPeerDropped   = std::function<void(const std::string& peer_addr)>;

class PeerManager {
public:
    PeerManager(uint32_t magic, uint64_t local_height,
                uint64_t local_services = MessageType::NODE_FULL)
        : magic_(magic), local_height_(local_height),
          local_services_(local_services | MessageType::NODE_FULL |
                          MessageType::NODE_HOLE_PUNCH |
                          MessageType::REQUIRED_NETWORK_IDENTITY_SERVICES) {}

    bool AddPeer(const std::string& address, uint16_t port = MAINNET_PORT, bool inbound = false) {
        if (peers_.size() >= MAX_PEER_CONNECTIONS) return false;

        std::string key = address + ":" + std::to_string(port);
        if (peers_.count(key)) return false;

        Peer peer(address, port);
        peer.is_inbound = inbound;
        peer.state = PeerState::CONNECTING;
        peers_[key] = peer;
        return true;
    }

    void DropPeer(const std::string& key, const std::string& reason = "") {
        auto it = peers_.find(key);
        if (it == peers_.end()) return;
        it->second.state = PeerState::DISCONNECTED;
        if (on_peer_dropped_cb_) on_peer_dropped_cb_(key);
    }

    void BanPeer(const std::string& key) {
        auto it = peers_.find(key);
        if (it == peers_.end()) return;
        it->second.state = PeerState::BANNED;
        banned_.insert(it->second.address);
        peers_.erase(it);
    }

    P2PMessage BuildVersionMessage(uint64_t current_height, uint64_t self_nonce) const {
        VersionPayload payload;
        payload.start_height = current_height;
        payload.nonce        = self_nonce;
        payload.services     = local_services_;
        return P2PMessage(magic_, MessageType::VERSION, payload.Serialize());
    }
    P2PMessage BuildVersionMessage(uint64_t current_height) const {
        return BuildVersionMessage(current_height, 0);
    }

    P2PMessage BuildVerackMessage() const {
        return P2PMessage(magic_, MessageType::VERACK);
    }

    P2PMessage BuildPingMessage(uint64_t nonce) const {
        std::vector<uint8_t> payload(8);
        for (int i = 0; i < 8; ++i) payload[i] = (nonce >> (i*8)) & 0xFF;
        return P2PMessage(magic_, MessageType::PING, payload);
    }

    P2PMessage BuildPongMessage(uint64_t nonce) const {
        std::vector<uint8_t> payload(8);
        for (int i = 0; i < 8; ++i) payload[i] = (nonce >> (i*8)) & 0xFF;
        return P2PMessage(magic_, MessageType::PONG, payload);
    }

    P2PMessage BuildInvMessage(const std::vector<InvItem>& items) const {
        std::vector<uint8_t> payload;
        uint16_t cnt = (uint16_t)std::min(items.size(), (size_t)65535);
        payload.push_back(cnt & 0xFF);
        payload.push_back((cnt >> 8) & 0xFF);
        for (const auto& item : items) {
            uint32_t type = (uint32_t)item.type;
            payload.push_back(type & 0xFF);
            payload.push_back((type >> 8) & 0xFF);
            payload.push_back((type >> 16) & 0xFF);
            payload.push_back((type >> 24) & 0xFF);
            payload.insert(payload.end(), item.hash.begin(), item.hash.end());
        }
        return P2PMessage(magic_, MessageType::INV, payload);
    }

    P2PMessage BuildGetDataMessage(const std::vector<InvItem>& items) const {
        return P2PMessage(magic_, MessageType::GETDATA,
                          BuildInvMessage(items).payload);
    }

    P2PMessage BuildGetBlocksMessage(
        const Hash256& our_tip,
        const Hash256& stop_hash = {}
    ) const {
        return BuildGetBlocksMessage(our_tip, {}, stop_hash);
    }

    P2PMessage BuildGetBlocksMessage(
        const Hash256& our_tip,
        const std::vector<Hash256>& extra_locators,
        const Hash256& stop_hash = {}
    ) const {
        std::vector<uint8_t> payload;
        payload.push_back(PROTOCOL_VERSION & 0xFF);
        payload.push_back((PROTOCOL_VERSION >> 8) & 0xFF);
        payload.push_back((PROTOCOL_VERSION >> 16) & 0xFF);
        payload.push_back((PROTOCOL_VERSION >> 24) & 0xFF);

        std::vector<Hash256> locators;
        locators.push_back(our_tip);
        for (const auto& h : extra_locators)
            if (locators.size() < 32) locators.push_back(h);

        payload.push_back((uint8_t)locators.size());
        for (const auto& h : locators)
            payload.insert(payload.end(), h.begin(), h.end());

        Hash256 stop = HashIsZero(stop_hash) ? ZeroHash() : stop_hash;
        payload.insert(payload.end(), stop.begin(), stop.end());
        return P2PMessage(magic_, MessageType::GETBLOCKS, payload);
    }

    P2PMessage BuildSolutionMessage(
        const Hash256& prev_hash,
        uint64_t height,
        uint64_t nonce,
        const std::vector<uint8_t>& miner_script
    ) const {
        std::vector<uint8_t> payload;
        payload.insert(payload.end(), prev_hash.begin(), prev_hash.end());
        for (int i = 0; i < 8; ++i) payload.push_back((height >> (i*8)) & 0xFF);
        for (int i = 0; i < 8; ++i) payload.push_back((nonce  >> (i*8)) & 0xFF);
        payload.push_back((uint8_t)miner_script.size());
        payload.insert(payload.end(), miner_script.begin(), miner_script.end());
        return P2PMessage(magic_, MessageType::SOLUTION, payload);
    }

    P2PMessage BuildAddrMessage(
        const std::vector<std::pair<std::string, uint16_t>>& peers) const {
        auto looks_routable = [](uint32_t ip_be) -> bool {
            uint8_t o1 = (uint8_t)(ip_be & 0xFF);
            uint8_t o2 = (uint8_t)((ip_be >> 8) & 0xFF);
            if (o1 == 0 || o1 == 127) return false;
            if (o1 == 169 && o2 == 254) return false;
            if (o1 >= 224) return false;
            if (o1 == 10) return false;
            if (o1 == 172 && (o2 & 0xF0) == 16) return false;
            if (o1 == 192 && o2 == 168) return false;
            if (o1 == 100 && (o2 & 0xC0) == 64) return false;
            return true;
        };
        std::vector<uint8_t> payload;
        std::vector<std::pair<uint32_t, uint16_t>> filtered;
        filtered.reserve(std::min(peers.size(), (size_t)30));
        for (const auto& p : peers) {
            struct in_addr addr{};
            if (::inet_pton(AF_INET, p.first.c_str(), &addr) != 1) continue;
            if (!looks_routable(addr.s_addr)) continue;
            filtered.emplace_back(addr.s_addr, p.second);
            if (filtered.size() >= 30) break;
        }
        uint8_t count = (uint8_t)filtered.size();
        payload.push_back(count);
        for (const auto& [ip, port] : filtered) {
            payload.push_back((ip)       & 0xFF);
            payload.push_back((ip >> 8)  & 0xFF);
            payload.push_back((ip >> 16) & 0xFF);
            payload.push_back((ip >> 24) & 0xFF);
            payload.push_back((port)       & 0xFF);
            payload.push_back((port >> 8)  & 0xFF);
        }
        return P2PMessage(magic_, MessageType::ADDR, payload);
    }

    P2PMessage BuildGetAddrMessage() const {
        return P2PMessage(magic_, MessageType::GETADDR);
    }

    P2PMessage BuildCOMineMessage(
        const Hash256& prev_hash,
        uint64_t height,
        uint64_t best_nonce,
        const Hash256& best_hash,
        const std::vector<uint8_t>& miner_script,
        const std::vector<uint8_t>& comine_pubkey,
        const std::vector<uint8_t>& comine_sig
    ) const {
        std::vector<uint8_t> payload;
        payload.insert(payload.end(), prev_hash.begin(), prev_hash.end());
        for (int i = 0; i < 8; ++i) payload.push_back((height >> (i*8)) & 0xFF);
        for (int i = 0; i < 8; ++i) payload.push_back((best_nonce >> (i*8)) & 0xFF);
        payload.insert(payload.end(), best_hash.begin(), best_hash.end());
        payload.push_back((uint8_t)miner_script.size());
        payload.insert(payload.end(), miner_script.begin(), miner_script.end());
        uint16_t pkl = (uint16_t)comine_pubkey.size();
        payload.push_back((uint8_t)(pkl & 0xFF));
        payload.push_back((uint8_t)((pkl >> 8) & 0xFF));
        payload.insert(payload.end(), comine_pubkey.begin(), comine_pubkey.end());
        uint16_t sl = (uint16_t)comine_sig.size();
        payload.push_back((uint8_t)(sl & 0xFF));
        payload.push_back((uint8_t)((sl >> 8) & 0xFF));
        payload.insert(payload.end(), comine_sig.begin(), comine_sig.end());
        return P2PMessage(magic_, MessageType::COMINE, payload);
    }

    //  LAYER-3 (chain-state attestation). Encodes our current
    // chain-tip claim for periodic broadcast. Payload layout:
    //   offset 0:  uint32 LE  protocol_version  (mirrors PROTOCOL_VERSION)
    //   offset 4:  uint64 LE  height
    //   offset 12: 32 bytes   tip_hash (raw, NOT hex)
    // Total: 44 bytes. No signature: a malicious peer can already lie
    // about anything; cheap-attestation-without-sig is acceptable
    // because an unknown claim is fetch-only: it cannot enter peer-tip or
    // peer-best voting state until the receiver obtains the block and validates
    // it against PoW + chain rules. A liar wastes only a throttled fetch.
    P2PMessage BuildTipsigMessage(uint64_t height, const Hash256& tip_hash) const {
        std::vector<uint8_t> payload;
        payload.reserve(44);
        for (int i = 0; i < 4; ++i)
            payload.push_back((PROTOCOL_VERSION >> (i*8)) & 0xFF);
        for (int i = 0; i < 8; ++i)
            payload.push_back((height >> (i*8)) & 0xFF);
        payload.insert(payload.end(), tip_hash.begin(), tip_hash.end());
        return P2PMessage(magic_, MessageType::TIPSIG, payload);
    }

    P2PMessage BuildStatsigMessage(uint64_t mempool_size, uint32_t peer_count) const {
        std::vector<uint8_t> payload;
        payload.reserve(16);
        for (int i = 0; i < 4; ++i)
            payload.push_back((PROTOCOL_VERSION >> (i*8)) & 0xFF);
        for (int i = 0; i < 8; ++i)
            payload.push_back((mempool_size >> (i*8)) & 0xFF);
        for (int i = 0; i < 4; ++i)
            payload.push_back((peer_count >> (i*8)) & 0xFF);
        return P2PMessage(magic_, MessageType::STATSIG, payload);
    }

    P2PMessage BuildFinalityVoteMessage(
            const std::vector<uint8_t>& canonical_vote) const {
        return P2PMessage(magic_, MessageType::FINVOTE, canonical_vote);
    }

    void BroadcastBlockInv(const Hash256& block_hash) {
        InvItem item(InvType::BLOCK, block_hash);
        auto msg = BuildInvMessage({item});
        for (auto& [key, peer] : peers_) {
            if (!peer.IsConnected()) continue;
            if (peer.known_inv.count(HashToHex(block_hash))) continue;
            SendMessage(key, msg);
        }
    }

    void BroadcastTxInv(const Hash256& tx_hash) {
        InvItem item(InvType::TX, tx_hash);
        auto msg = BuildInvMessage({item});
        for (auto& [key, peer] : peers_) {
            if (!peer.IsConnected()) continue;
            if (peer.known_inv.count(HashToHex(tx_hash))) continue;
            SendMessage(key, msg);
        }
    }

    size_t ConnectedCount() const {
        size_t count = 0;
        for (const auto& [k, p] : peers_)
            if (p.IsConnected()) ++count;
        return count;
    }

    size_t TotalCount()     const { return peers_.size(); }
    bool   IsBanned(const std::string& addr) const { return banned_.count(addr) > 0; }

    std::vector<Peer> GetConnectedPeers() const {
        std::vector<Peer> result;
        for (const auto& [k, p] : peers_)
            if (p.IsConnected()) result.push_back(p);
        return result;
    }

    void OnBlockReceived(OnBlockReceived cb) { on_block_received_cb_ = cb; }
    void OnTxReceived(OnTxReceived cb)       { on_tx_received_cb_ = cb; }
    void OnPeerConnected(OnPeerConnected cb) { on_peer_connected_cb_ = cb; }
    void OnPeerDropped(OnPeerDropped cb)     { on_peer_dropped_cb_ = cb; }

    void AddSeedNodes(const std::vector<std::string>& seeds) {
        for (const auto& seed : seeds) {
            AddPeer(seed, MAINNET_PORT, false);
        }
    }

    std::string GetPeerInfo() const {
        std::string info;
        info += "Connected peers: " + std::to_string(ConnectedCount()) + "\n";
        info += "Known peers:     " + std::to_string(TotalCount()) + "\n";
        info += "Banned:          " + std::to_string(banned_.size()) + "\n";
        for (const auto& [k, p] : peers_) {
            if (p.IsConnected())
                info += "  " + p.GetInfo() + "\n";
        }
        return info;
    }

private:
    uint32_t magic_;
    uint64_t local_height_;
    uint64_t local_services_;
    std::unordered_map<std::string, Peer> peers_;
    std::unordered_set<std::string>       banned_;

    std::function<void(const std::string&, const std::vector<uint8_t>&)> on_block_received_cb_;
    std::function<void(const std::string&, const std::vector<uint8_t>&)> on_tx_received_cb_;
    std::function<void(const std::string&)> on_peer_connected_cb_;
    std::function<void(const std::string&)> on_peer_dropped_cb_;

    void SendMessage(const std::string& peer_key, const P2PMessage& msg) {
        auto it = peers_.find(peer_key);
        if (it == peers_.end() || !it->second.IsConnected()) return;
        it->second.last_seen = (uint64_t)std::time(nullptr);
        (void)msg;
    }
};

}
