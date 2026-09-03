#pragma once

#include "../network/chainparams.h"
#include "../network/p2p.h"
#include "../compat/platform.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <ctime>
#include <sstream>
#include <algorithm>
#include <random>
#include <functional>
#include <list>
#include <condition_variable>
#include <limits>

#include "../compat/platform.h"

namespace veld {
namespace seeder {

using SocketHandle = veld::compat::SocketHandle;

struct PeerRecord {
    std::string  ip;
    uint16_t     port;
    uint64_t     last_seen;
    uint64_t     first_seen;
    uint32_t     protocol_version;
    std::string  user_agent;
    uint64_t     best_height;
    uint32_t     services;
    bool         is_reachable;
    uint32_t     fail_count;

    PeerRecord() : port(CompiledPublicP2PPort()), last_seen(0), first_seen(0),
                   protocol_version(0), best_height(0), services(0x01),
                   is_reachable(false), fail_count(0) {
        first_seen = veld::compat::MonotonicSeconds();
    }

    explicit PeerRecord(const std::string& ip_addr,
                        uint16_t p = CompiledPublicP2PPort())
        : ip(ip_addr), port(p), last_seen(0), first_seen(veld::compat::MonotonicSeconds()),
          protocol_version(0), best_height(0), services(0x01),
          is_reachable(false), fail_count(0) {}

    bool IsGood() const {
        uint64_t now = veld::compat::MonotonicSeconds();
        return is_reachable
            && fail_count < 3
            && (now - last_seen) < 24 * 3600;
    }

    std::string Key() const { return ip + ":" + std::to_string(port); }
};

class PeerDB {
public:
    static constexpr size_t MAX_PEERDB_ENTRIES = 100000;

    void Add(const PeerRecord& peer) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto key = peer.Key();
        if (!peers_.count(key)) {
            if (peers_.size() >= MAX_PEERDB_ENTRIES) {
                auto worst = peers_.end();
                uint32_t worst_fail = 0;
                uint64_t worst_age  = UINT64_MAX;
                for (auto it = peers_.begin(); it != peers_.end(); ++it) {
                    if (worst == peers_.end() ||
                        it->second.fail_count > worst_fail ||
                        (it->second.fail_count == worst_fail &&
                         it->second.last_seen  < worst_age)) {
                        worst = it;
                        worst_fail = it->second.fail_count;
                        worst_age  = it->second.last_seen;
                    }
                }
                if (worst != peers_.end()) {
                    RemoveGoodKeyLocked(worst->first);
                    peers_.erase(worst);
                }
            }
            peers_[key] = peer;
            SyncGoodKeyLocked(key, peers_[key]);
        } else {
            auto& existing = peers_[key];
            if (peer.is_reachable) {
                existing.last_seen        = peer.last_seen;
                existing.protocol_version = peer.protocol_version;
                existing.user_agent       = peer.user_agent;
                existing.best_height      = peer.best_height;
                existing.services         = peer.services;
                existing.is_reachable     = true;
                existing.fail_count       = 0;
            } else {
                ++existing.fail_count;
                if (existing.fail_count >= 10)
                    existing.is_reachable = false;
            }
            SyncGoodKeyLocked(key, existing);
        }
    }

    void MarkFailed(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = peers_.find(key);
        if (it != peers_.end()) {
            ++it->second.fail_count;
            it->second.is_reachable = false;
            RemoveGoodKeyLocked(key);
        }
    }

    std::vector<PeerRecord> GetGoodPeers(size_t count = 25) const {
        std::lock_guard<std::mutex> lock(mutex_);

        std::vector<PeerRecord> good;
        if (count == 0 || good_keys_.empty()) {
            last_selection_inspected_ = 0;
            return good;
        }
        good.reserve(std::min(count, good_keys_.size()));

        std::mt19937_64 rng;
        {
            uint8_t seed_bytes[8];
            if (veld::compat::SecureRandom(seed_bytes, 8)) {
                uint64_t seed = 0;
                for (int i = 0; i < 8; ++i) seed |= ((uint64_t)seed_bytes[i] << (i*8));
                rng.seed(seed);
            } else {
                rng.seed((uint64_t)std::chrono::high_resolution_clock::now()
                         .time_since_epoch().count());
            }
        }
        // Do not scan/copy/shuffle the complete (up to 100k) PeerDB for each
        // spoofable UDP query.  Start at a random candidate and inspect a
        // strict O(requested-count) window.  Stale candidates are removed as
        // encountered; cleanup is therefore bounded per query as well as
        // amortized over the candidate's lifetime.
        const size_t requested = std::min(count, MAX_PEERDB_ENTRIES);
        const size_t max_window = requested > (MAX_PEERDB_ENTRIES / 8)
            ? MAX_PEERDB_ENTRIES
            : std::max<size_t>(64, requested * 8);
        const size_t inspection_budget =
            std::min(good_keys_.size(), max_window);
        size_t cursor = good_keys_.empty()
            ? 0
            : static_cast<size_t>(rng() % good_keys_.size());
        size_t inspected = 0;
        std::unordered_set<std::string> selected;
        selected.reserve(std::min(requested, inspection_budget));
        while (inspected < inspection_budget && !good_keys_.empty() &&
               good.size() < requested) {
            cursor %= good_keys_.size();
            const std::string key = good_keys_[cursor];
            ++inspected;
            auto peer = peers_.find(key);
            if (peer == peers_.end() || !peer->second.IsGood()) {
                RemoveGoodKeyLocked(key);
                continue;
            }
            if (selected.insert(key).second)
                good.push_back(peer->second);
            ++cursor;
        }
        last_selection_inspected_ = inspected;
        return good;
    }

#ifdef VELD_TEST_HOOKS
    size_t LastSelectionInspectedForTesting() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return last_selection_inspected_;
    }

    static size_t MaxSelectionInspectionsForTesting(size_t count) {
        const size_t requested = std::min(count, MAX_PEERDB_ENTRIES);
        return requested > (MAX_PEERDB_ENTRIES / 8)
            ? MAX_PEERDB_ENTRIES
            : std::max<size_t>(64, requested * 8);
    }
#endif

    size_t TotalCount()    const { std::lock_guard<std::mutex> l(mutex_); return peers_.size(); }
    size_t ReachableCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        for (const auto& [k, p] : peers_) if (p.IsGood()) ++count;
        return count;
    }

    std::string GetStats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t good = 0;
        for (const auto& [k, p] : peers_) if (p.IsGood()) ++good;
        std::string s;
        s += "Total peers:     " + std::to_string(peers_.size()) + "\n";
        s += "Reachable peers: " + std::to_string(good) + "\n";
        return s;
    }

private:
    void RemoveGoodKeyLocked(const std::string& key) const {
        auto pos = good_positions_.find(key);
        if (pos == good_positions_.end()) return;
        const size_t index = pos->second;
        const size_t last = good_keys_.size() - 1;
        if (index != last) {
            good_keys_[index] = std::move(good_keys_[last]);
            good_positions_.at(good_keys_[index]) = index;
        }
        good_keys_.pop_back();
        good_positions_.erase(key);
    }

    void SyncGoodKeyLocked(const std::string& key, const PeerRecord& peer) {
        if (peer.IsGood()) {
            if (good_positions_.find(key) == good_positions_.end()) {
                good_positions_[key] = good_keys_.size();
                good_keys_.push_back(key);
            }
        } else {
            RemoveGoodKeyLocked(key);
        }
    }

    mutable std::mutex mutex_;
    std::unordered_map<std::string, PeerRecord> peers_;
    mutable std::vector<std::string> good_keys_;
    mutable std::unordered_map<std::string, size_t> good_positions_;
    mutable size_t last_selection_inspected_{0};
};

class NetworkCrawler {
public:
    NetworkCrawler(PeerDB& db, uint32_t magic)
        : db_(db), magic_(magic), running_(false), stop_requested_(false) {}

    ~NetworkCrawler() { Stop(); }

    bool Start(const std::vector<std::string>& bootstrap_ips) {
        std::lock_guard<std::mutex> lifecycle_lock(lifecycle_mutex_);
        if (running_.load() || crawl_thread_.joinable()) return false;

        stop_requested_ = false;

        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            to_crawl_.clear();
            for (const auto& ip : bootstrap_ips) {
                if (to_crawl_.size() >= MAX_CRAWL_QUEUE_ENTRIES) break;
                struct in_addr parsed{};
                if (::inet_pton(AF_INET, ip.c_str(), &parsed) != 1) continue;
                PeerRecord peer(ip);
                db_.Add(peer);
                to_crawl_.push_back(peer.Key());
            }
        }

        running_ = true;
        try {
            crawl_thread_ = std::thread(&NetworkCrawler::CrawlLoop, this);
        } catch (...) {
            running_ = false;
            stop_requested_ = true;
            return false;
        }
        return true;
    }

    void Stop() {
        std::lock_guard<std::mutex> lifecycle_lock(lifecycle_mutex_);
        running_ = false;
        stop_requested_ = true;
        queue_cv_.notify_all();
        if (crawl_thread_.joinable()) crawl_thread_.join();
    }

    PeerRecord ProbePeer(const std::string& ip, uint16_t port) {
        PeerRecord record(ip, port);

        SocketHandle fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (!veld::compat::IsValidSocket(fd)) return record;

#ifdef _WIN32
        DWORD tv = 250;
#else
        struct timeval tv{0, 250000};
#endif
        if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                         reinterpret_cast<const char*>(&tv), sizeof(tv)) != 0 ||
            ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                         reinterpret_cast<const char*>(&tv), sizeof(tv)) != 0) {
            VELD_CLOSE_SOCKET(fd);
            return record;
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);

        if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
            VELD_CLOSE_SOCKET(fd);
            return record;
        }

        bool connect_ok = false;
#ifdef _WIN32
        u_long nonblocking = 1;
        if (::ioctlsocket((SOCKET)fd, FIONBIO, &nonblocking) != 0) {
            VELD_CLOSE_SOCKET(fd);
            return record;
        }
#else
        const int original_flags = ::fcntl(fd, F_GETFL, 0);
        if (original_flags < 0 ||
            ::fcntl(fd, F_SETFL, original_flags | O_NONBLOCK) != 0) {
            VELD_CLOSE_SOCKET(fd);
            return record;
        }
#endif

        const int connect_result =
            ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        if (connect_result == 0) {
            connect_ok = true;
        } else {
#ifdef _WIN32
            const int connect_error = ::WSAGetLastError();
            const bool in_progress = connect_error == WSAEWOULDBLOCK ||
                                     connect_error == WSAEINPROGRESS;
#else
            const bool in_progress = errno == EINPROGRESS;
#endif
            if (in_progress) {
                constexpr int CONNECT_SLICE_MS = 100;
                constexpr int CONNECT_BUDGET_MS = 3000;
                int waited_ms = 0;
                while (!stop_requested_.load() &&
                       waited_ms < CONNECT_BUDGET_MS) {
#ifdef _WIN32
                    WSAPOLLFD poll_fd{(SOCKET)fd, POLLOUT, 0};
                    const int poll_result =
                        ::WSAPoll(&poll_fd, 1, CONNECT_SLICE_MS);
#else
                    struct pollfd poll_fd{fd, POLLOUT, 0};
                    const int poll_result =
                        ::poll(&poll_fd, 1, CONNECT_SLICE_MS);
#endif
                    if (poll_result < 0) {
#ifndef _WIN32
                        if (errno == EINTR) continue;
#endif
                        break;
                    }
                    if (poll_result == 0) {
                        waited_ms += CONNECT_SLICE_MS;
                        continue;
                    }
                    if (poll_fd.revents & (POLLERR | POLLHUP | POLLNVAL))
                        break;
                    if (poll_fd.revents & POLLOUT) {
                        int socket_error = 0;
                        socklen_t error_len = sizeof(socket_error);
                        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR,
                                         reinterpret_cast<char*>(&socket_error),
                                         &error_len) == 0 && socket_error == 0) {
                            connect_ok = true;
                        }
                        break;
                    }
                }
            }
        }

        if (!connect_ok || stop_requested_.load()) {
            VELD_CLOSE_SOCKET(fd);
            return record;
        }

#ifdef _WIN32
        u_long blocking = 0;
        if (::ioctlsocket((SOCKET)fd, FIONBIO, &blocking) != 0) {
            VELD_CLOSE_SOCKET(fd);
            return record;
        }
#else
        if (::fcntl(fd, F_SETFL, original_flags) != 0) {
            VELD_CLOSE_SOCKET(fd);
            return record;
        }
#endif

        PeerManager pm(magic_, 0);
        auto ver_msg = pm.BuildVersionMessage(0);
        auto wire = ver_msg.Serialize();
        if (!SendExact(fd, wire.data(), wire.size())) {
            VELD_CLOSE_SOCKET(fd);
            return record;
        }

        uint8_t header[24] = {0};
        if (RecvExact(fd, header, sizeof(header)) &&
            IsCanonicalVersionHeader(header)) {
            const uint32_t payload_len = ReadLE32(header + 16);
            std::vector<uint8_t> payload(payload_len);
            if (!RecvExact(fd, payload.data(), payload.size()) ||
                !IsCanonicalVersionPayload(header, payload)) {
                VELD_CLOSE_SOCKET(fd);
                return record;
            }
            record.is_reachable = true;
            record.last_seen    = veld::compat::MonotonicSeconds();
            record.protocol_version = ReadLE32(payload.data());
            record.services = static_cast<uint32_t>(ReadLE64(payload.data() + 4));
            record.best_height = ReadLE64(payload.data() + 20);
            const size_t user_agent_len = payload[28];
            record.user_agent.assign(
                reinterpret_cast<const char*>(payload.data() + 29),
                user_agent_len);
        }

        VELD_CLOSE_SOCKET(fd);
        return record;
    }

private:
    PeerDB&              db_;
    uint32_t             magic_;
    std::atomic<bool>    running_;
    std::atomic<bool>    stop_requested_;
    std::thread          crawl_thread_;
    std::vector<std::string> to_crawl_;
    std::mutex           queue_mutex_;
    std::condition_variable queue_cv_;
    std::mutex           lifecycle_mutex_;

    static constexpr size_t MAX_CRAWL_QUEUE_ENTRIES = 100'000;

    static uint32_t ReadLE32(const uint8_t* bytes) {
        return static_cast<uint32_t>(bytes[0]) |
               (static_cast<uint32_t>(bytes[1]) << 8) |
               (static_cast<uint32_t>(bytes[2]) << 16) |
               (static_cast<uint32_t>(bytes[3]) << 24);
    }

    static uint64_t ReadLE64(const uint8_t* bytes) {
        uint64_t value = 0;
        for (int i = 0; i < 8; ++i)
            value |= static_cast<uint64_t>(bytes[i]) << (i * 8);
        return value;
    }

    bool SendExact(SocketHandle fd, const uint8_t* data, size_t size) const {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(3);
        size_t sent = 0;
        while (sent < size && !stop_requested_.load() &&
               std::chrono::steady_clock::now() < deadline) {
            const size_t remaining = size - sent;
            const int chunk = remaining >
                    static_cast<size_t>(std::numeric_limits<int>::max())
                ? std::numeric_limits<int>::max()
                : static_cast<int>(remaining);
            const ssize_t n = ::send(fd,
                reinterpret_cast<const char*>(data + sent),
                chunk, MSG_NOSIGNAL);
            if (n > 0) {
                sent += static_cast<size_t>(n);
                continue;
            }
            if (n == 0) return false;
#ifdef _WIN32
            const int error = ::WSAGetLastError();
            if (error == WSAEINTR || error == WSAEWOULDBLOCK ||
                error == WSAETIMEDOUT) continue;
#else
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
#endif
            return false;
        }
        return sent == size;
    }

    bool RecvExact(SocketHandle fd, uint8_t* data, size_t size) const {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(3);
        size_t received = 0;
        while (received < size && !stop_requested_.load() &&
               std::chrono::steady_clock::now() < deadline) {
            const size_t remaining = size - received;
            const int chunk = remaining >
                    static_cast<size_t>(std::numeric_limits<int>::max())
                ? std::numeric_limits<int>::max()
                : static_cast<int>(remaining);
            const ssize_t n = ::recv(fd,
                reinterpret_cast<char*>(data + received),
                chunk, 0);
            if (n > 0) {
                received += static_cast<size_t>(n);
                continue;
            }
            if (n == 0) return false;
#ifdef _WIN32
            const int error = ::WSAGetLastError();
            if (error == WSAEINTR || error == WSAEWOULDBLOCK ||
                error == WSAETIMEDOUT) continue;
#else
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
#endif
            return false;
        }
        return received == size;
    }

    bool IsCanonicalVersionHeader(const uint8_t* header) const {
        if (ReadLE32(header) != magic_) return false;
        static constexpr uint8_t version_command[12] = {
            'v', 'e', 'r', 's', 'i', 'o', 'n', 0, 0, 0, 0, 0
        };
        if (!std::equal(version_command, version_command + 12, header + 4))
            return false;
        const uint32_t payload_len = ReadLE32(header + 16);
        return payload_len >= 70 && payload_len <= 325;
    }

    bool IsCanonicalVersionPayload(
        const uint8_t* header,
        const std::vector<uint8_t>& payload
    ) const {
        if (payload.size() < 70) return false;
        const size_t user_agent_len = payload[28];
        if (payload.size() != 70 + user_agent_len) return false;
        const Hash256 checksum = Hash256d(payload);
        if (!std::equal(checksum.begin(), checksum.begin() + 4, header + 20))
            return false;
        const auto expected_genesis = HexToBytes(GENESIS_HASH);
        if (expected_genesis.size() != 32) return false;
        const size_t genesis_offset = 38 + user_agent_len;
        return std::equal(expected_genesis.begin(), expected_genesis.end(),
                          payload.begin() + genesis_offset);
    }

    void CrawlLoop() {
        while (running_) {
            std::string key;
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                if (to_crawl_.empty()) {
                    auto peers = db_.GetGoodPeers(50);
                    for (const auto& p : peers)
                        to_crawl_.push_back(p.Key());

                    if (to_crawl_.empty()) {
                        queue_cv_.wait_for(lock, std::chrono::seconds(30),
                                           [this] { return !running_.load(); });
                        continue;
                    }
                }
                key = to_crawl_.back();
                to_crawl_.pop_back();
            }

            auto colon = key.rfind(':');
            if (colon == std::string::npos) continue;
            std::string ip = key.substr(0, colon);
            uint16_t port;
            try { port = (uint16_t)std::stoi(key.substr(colon + 1)); } catch (...) { continue; }

            PeerRecord result = ProbePeer(ip, port);
            if (!running_) break;
            db_.Add(result);

            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait_for(lock, std::chrono::milliseconds(500),
                               [this] { return !running_.load(); });
        }
    }
};

// A process-secret hash prevents a source-address spray from deliberately
// collapsing the unordered_map into one long bucket.  The map is bounded too,
// but predictable uint32_t hashing would otherwise leave a 10,000-step hot
// path per UDP packet on common standard-library implementations.
struct DnsRateIpHash {
    static uint64_t Salt() {
        static const uint64_t salt = [] {
            uint8_t bytes[8]{};
            uint64_t value = 0;
            if (veld::compat::SecureRandom(bytes, sizeof(bytes))) {
                for (size_t i = 0; i < sizeof(bytes); ++i)
                    value |= static_cast<uint64_t>(bytes[i]) << (i * 8);
            } else {
                value = static_cast<uint64_t>(
                    std::chrono::high_resolution_clock::now()
                        .time_since_epoch().count());
            }
            return value ^ 0x9e3779b97f4a7c15ULL;
        }();
        return salt;
    }

    size_t operator()(uint32_t ip) const noexcept {
        uint64_t x = static_cast<uint64_t>(ip) + Salt();
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
        x ^= x >> 31;
        return static_cast<size_t>(x);
    }
};

class DNSSeeder {
public:
    DNSSeeder(PeerDB& db, uint16_t dns_port = 53)
        : db_(db), dns_port_(dns_port), running_(false),
          fd_(veld::compat::kInvalidSocket) {
        // Keep the bucket array fixed after construction.  Besides avoiding a
        // rehash pause in the UDP receive loop, this makes the memory envelope
        // independent of an attacker's stream of spoofed source addresses.
        dns_rate_map_.reserve(MAX_DNS_RATE_ENTRIES);
    }

    ~DNSSeeder() { Stop(); }

    bool Start() {
        std::lock_guard<std::mutex> lifecycle_lock(lifecycle_mutex_);
        if (running_.load() || dns_thread_.joinable() ||
            veld::compat::IsValidSocket(fd_)) {
            return false;
        }

        fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (!veld::compat::IsValidSocket(fd_)) return false;

        // Closing a datagram socket from another thread is not a portable way
        // to interrupt recvfrom().  A short receive timeout lets Stop() signal,
        // join, and only then close the descriptor without a race or hang.
#ifdef _WIN32
        DWORD recv_timeout_ms = 250;
        if (::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO,
                         reinterpret_cast<const char*>(&recv_timeout_ms),
                         sizeof(recv_timeout_ms)) != 0) {
#else
        struct timeval recv_timeout{0, 250000};
        if (::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO,
                         reinterpret_cast<const char*>(&recv_timeout),
                         sizeof(recv_timeout)) != 0) {
#endif
            VELD_CLOSE_SOCKET(fd_);
            fd_ = veld::compat::kInvalidSocket;
            return false;
        }

        struct sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons(dns_port_);

        if (::bind(fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            VELD_CLOSE_SOCKET(fd_);
            fd_ = veld::compat::kInvalidSocket;
            return false;
        }

        running_ = true;
        try {
            dns_thread_ = std::thread(&DNSSeeder::ServeLoop, this);
        } catch (...) {
            running_ = false;
            VELD_CLOSE_SOCKET(fd_);
            fd_ = veld::compat::kInvalidSocket;
            return false;
        }
        return true;
    }

    void Stop() {
        std::lock_guard<std::mutex> lifecycle_lock(lifecycle_mutex_);
        running_ = false;
        if (dns_thread_.joinable()) dns_thread_.join();
        if (veld::compat::IsValidSocket(fd_)) {
            VELD_CLOSE_SOCKET(fd_);
            fd_ = veld::compat::kInvalidSocket;
        }
    }

    static std::vector<uint8_t> BuildDNSResponse(
        const std::vector<uint8_t>& query,
        const std::vector<std::string>& ips
    ) {
        if (query.size() < 12) return {};

        std::vector<uint8_t> response;
        std::vector<struct in_addr> valid_addresses;
        valid_addresses.reserve(std::min(ips.size(), static_cast<size_t>(255)));
        for (const auto& ip : ips) {
            if (valid_addresses.size() == 255) break;
            struct in_addr address{};
            if (::inet_pton(AF_INET, ip.c_str(), &address) == 1)
                valid_addresses.push_back(address);
        }

        response.push_back(query[0]);
        response.push_back(query[1]);

        response.push_back(0x84);
        response.push_back(0x00);

        response.push_back(0x00); response.push_back(0x01);
        response.push_back(0x00);
        response.push_back(static_cast<uint8_t>(valid_addresses.size()));
        response.push_back(0x00); response.push_back(0x00);
        response.push_back(0x00); response.push_back(0x00);

        for (size_t i = 12; i < query.size(); ++i)
            response.push_back(query[i]);

        for (const auto& address : valid_addresses) {
            response.push_back(0xC0); response.push_back(0x0C);
            response.push_back(0x00); response.push_back(0x01);
            response.push_back(0x00); response.push_back(0x01);
            response.push_back(0x00); response.push_back(0x00);
            response.push_back(0x00); response.push_back(0x3C);
            response.push_back(0x00); response.push_back(0x04);
            const auto* octets = reinterpret_cast<const uint8_t*>(&address.s_addr);
            response.insert(response.end(), octets, octets + 4);
        }

        return response;
    }

    static std::vector<uint8_t> BuildBoundedDNSResponse(
        const std::vector<uint8_t>& query,
        const std::vector<std::string>& ips
    ) {
        if (query.size() > (std::numeric_limits<size_t>::max() / 2))
            return {};
        const size_t max_response = query.size() * 2;
        std::vector<std::string> bounded_ips = ips;
        auto response = BuildDNSResponse(query, bounded_ips);
        while (response.size() > max_response && !bounded_ips.empty()) {
            bounded_ips.pop_back();
            response = BuildDNSResponse(query, bounded_ips);
        }
        if (response.size() > max_response) return {};
        return response;
    }

    std::string GetStats() const {
        return "DNS Seeder: port " + std::to_string(dns_port_)
             + ", " + std::to_string(queries_answered_.load()) + " queries answered\n";
    }

#ifdef VELD_TEST_HOOKS
    bool TakeDnsRateTokenForTesting(uint32_t client_ip_be,
                                    uint64_t monotonic_millis) {
        return TakeDnsRateTokenAt(
            client_ip_be,
            std::chrono::steady_clock::time_point(
                std::chrono::milliseconds(monotonic_millis)));
    }

    size_t DnsRateStateSizeForTesting() {
        std::lock_guard<std::mutex> lk(dns_rate_mutex_);
        return dns_rate_map_.size();
    }

    bool DnsRateStateConsistentForTesting() {
        std::lock_guard<std::mutex> lk(dns_rate_mutex_);
        if (dns_rate_map_.size() != dns_rate_lru_.size() ||
            dns_rate_map_.size() > MAX_DNS_RATE_ENTRIES) {
            return false;
        }
        for (auto it = dns_rate_lru_.begin(); it != dns_rate_lru_.end(); ++it) {
            auto found = dns_rate_map_.find(*it);
            if (found == dns_rate_map_.end() || found->second.lru_it != it)
                return false;
        }
        return true;
    }

    static constexpr size_t DnsRateCapacityForTesting() {
        return MAX_DNS_RATE_ENTRIES;
    }

    static constexpr uint64_t DnsRateTtlMillisForTesting() {
        return DNS_RATE_IDLE_TTL_SECONDS * 1000ULL;
    }

    static constexpr size_t DnsGlobalBurstForTesting() {
        return static_cast<size_t>(DNS_GLOBAL_BURST);
    }

    static constexpr size_t DnsGlobalPerSecondForTesting() {
        return static_cast<size_t>(DNS_GLOBAL_REFILL_PER_SECOND);
    }
#endif

private:
    PeerDB&           db_;
    uint16_t          dns_port_;
    std::atomic<bool> running_;
    SocketHandle      fd_;
    std::thread       dns_thread_;
    std::mutex        lifecycle_mutex_;
    std::atomic<uint64_t> queries_answered_{0};

    static constexpr size_t MAX_DNS_RATE_ENTRIES = 10'000;
    static constexpr uint64_t DNS_RATE_IDLE_TTL_SECONDS = 60;
    // The response envelope is already <=2x the request.  This aggregate
    // bucket additionally bounds spoof-driven response work/bandwidth while
    // retaining generous headroom for a public seed under normal bursts.
    static constexpr double DNS_GLOBAL_REFILL_PER_SECOND = 1000.0;
    static constexpr double DNS_GLOBAL_BURST = 2000.0;

    struct DnsRateBucket {
        double tokens;
        std::chrono::steady_clock::time_point last_refill;
        std::chrono::steady_clock::time_point last_seen;
        std::list<uint32_t>::iterator lru_it;

        DnsRateBucket(double initial_tokens,
                      std::chrono::steady_clock::time_point now,
                      std::list<uint32_t>::iterator it)
            : tokens(initial_tokens), last_refill(now), last_seen(now),
              lru_it(it) {}
    };
    std::mutex                                         dns_rate_mutex_;
    std::unordered_map<uint32_t, DnsRateBucket,
                       DnsRateIpHash>                   dns_rate_map_;
    // Oldest last_seen is at the front.  Each bucket owns exactly one list
    // node, so expiry is amortized O(1): an entry can be removed only once for
    // each successful insertion.  At capacity, a new source replaces exactly
    // one least-recently-seen source; the aggregate bucket bounds churn and
    // response work without locking all new legitimate resolvers out.
    std::list<uint32_t>                                dns_rate_lru_;
    double                                             dns_global_tokens_{DNS_GLOBAL_BURST};
    std::chrono::steady_clock::time_point              dns_global_last_refill_{
        std::chrono::steady_clock::now()};

    bool TakeDnsRateToken(uint32_t client_ip_be) {
        return TakeDnsRateTokenAt(client_ip_be,
                                  std::chrono::steady_clock::now());
    }

    bool TakeDnsRateTokenAt(
        uint32_t client_ip_be,
        std::chrono::steady_clock::time_point now
    ) {
        constexpr double REFILL_PER_SECOND = 1.0;
        constexpr double BURST              = 5.0;
        std::lock_guard<std::mutex> lk(dns_rate_mutex_);

        double global_elapsed = 0.0;
        if (now >= dns_global_last_refill_) {
            global_elapsed = std::chrono::duration<double>(
                now - dns_global_last_refill_).count();
        }
        dns_global_tokens_ = std::min(
            DNS_GLOBAL_BURST,
            dns_global_tokens_ +
                global_elapsed * DNS_GLOBAL_REFILL_PER_SECOND);
        dns_global_last_refill_ = now;
        // Do not churn per-source state when no aggregate response capacity is
        // available.  A single over-rate source also cannot drain this bucket,
        // because it is debited only after the per-source check succeeds.
        if (dns_global_tokens_ < 1.0)
            return false;

        const auto idle_ttl =
            std::chrono::seconds(DNS_RATE_IDLE_TTL_SECONDS);
        while (!dns_rate_lru_.empty()) {
            const uint32_t oldest_ip = dns_rate_lru_.front();
            auto oldest = dns_rate_map_.find(oldest_ip);
            if (oldest == dns_rate_map_.end()) {
                // Defensive repair: this cannot occur through the normal
                // insertion/erase paths, but never let a stale list node pin
                // expiry if state was corrupted by a future change.
                dns_rate_lru_.pop_front();
                continue;
            }
            if (now < oldest->second.last_seen ||
                now - oldest->second.last_seen < idle_ttl) {
                break;
            }
            dns_rate_lru_.pop_front();
            dns_rate_map_.erase(oldest);
        }

        auto found = dns_rate_map_.find(client_ip_be);
        if (found == dns_rate_map_.end()) {
            if (dns_rate_map_.size() >= MAX_DNS_RATE_ENTRIES) {
                const uint32_t oldest_ip = dns_rate_lru_.front();
                dns_rate_lru_.pop_front();
                dns_rate_map_.erase(oldest_ip);
            }
            dns_rate_lru_.push_back(client_ip_be);
            auto lru_it = std::prev(dns_rate_lru_.end());
            auto inserted = dns_rate_map_.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(client_ip_be),
                std::forward_as_tuple(BURST, now, lru_it));
            if (!inserted.second) {
                dns_rate_lru_.erase(lru_it);
                return false;
            }
            found = inserted.first;
        } else {
            found->second.last_seen = now;
            dns_rate_lru_.splice(dns_rate_lru_.end(), dns_rate_lru_,
                                 found->second.lru_it);
            found->second.lru_it = std::prev(dns_rate_lru_.end());
        }

        auto& b = found->second;
        double elapsed = 0.0;
        if (now >= b.last_refill)
            elapsed = std::chrono::duration<double>(now - b.last_refill).count();
        b.tokens = std::min(BURST, b.tokens + elapsed * REFILL_PER_SECOND);
        b.last_refill = now;
        if (b.tokens < 1.0) return false;
        b.tokens -= 1.0;
        dns_global_tokens_ -= 1.0;
        return true;
    }

    static bool IsSaneDnsQuery(const uint8_t* buf, size_t n) {
        if (n < 12) return false;
        if (buf[2] & 0x80) return false;
        uint16_t qdcount = ((uint16_t)buf[4] << 8) | buf[5];
        if (qdcount != 1) return false;
        return true;
    }

    void ServeLoop() {
        uint8_t buf[512];
        struct sockaddr_in client{};
        socklen_t client_len = sizeof(client);

        while (running_) {
            client_len = sizeof(client);
            ssize_t n = ::recvfrom(fd_, (char*)buf, sizeof(buf), 0,
                (struct sockaddr*)&client, &client_len);
            if (n < 12) continue;

            if (!IsSaneDnsQuery(buf, (size_t)n)) continue;
            if (!TakeDnsRateToken(client.sin_addr.s_addr)) continue;

            auto peers = db_.GetGoodPeers(25);
            std::vector<std::string> ips;
            for (const auto& p : peers) ips.push_back(p.ip);

            auto query = std::vector<uint8_t>(buf, buf + n);
            auto response = BuildBoundedDNSResponse(query, ips);

            if (!response.empty()) {
                const int response_size = static_cast<int>(response.size());
                const ssize_t sent = ::sendto(
                    fd_, reinterpret_cast<const char*>(response.data()),
                    response_size, 0,
                    reinterpret_cast<struct sockaddr*>(&client), client_len);
                if (sent == response_size) ++queries_answered_;
            }
        }
    }
};

class SeedNodeClient {
public:
    static constexpr size_t MAX_SEED_HOSTNAMES = 64;
    static constexpr size_t MAX_RESOLVED_SEED_ADDRESSES = 256;
    static constexpr size_t MAX_RESOLVED_ADDRESSES_PER_HOST = 64;

    static std::vector<std::string> ResolveSeedNodes(
        const std::vector<std::string>& seed_hostnames
    ) {
        std::vector<std::string> ips;
        ips.reserve(MAX_RESOLVED_SEED_ADDRESSES);

        size_t hosts_visited = 0;
        for (const auto& hostname : seed_hostnames) {
            if (hosts_visited++ >= MAX_SEED_HOSTNAMES) break;
            if (ips.size() >= MAX_RESOLVED_SEED_ADDRESSES) break;
            struct addrinfo hints{}, *res = nullptr;
            hints.ai_family   = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            if (::getaddrinfo(hostname.c_str(), nullptr, &hints, &res) != 0)
                continue;

            size_t retained_for_host = 0;
            for (auto* p = res; p != nullptr &&
                 retained_for_host < MAX_RESOLVED_ADDRESSES_PER_HOST &&
                 ips.size() < MAX_RESOLVED_SEED_ADDRESSES;
                 p = p->ai_next) {
                char ip[INET_ADDRSTRLEN];
                auto* sin = (struct sockaddr_in*)p->ai_addr;
                if (::inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip))) {
                    ips.emplace_back(ip);
                    ++retained_for_host;
                }
            }
            ::freeaddrinfo(res);
        }

        std::sort(ips.begin(), ips.end());
        ips.erase(std::unique(ips.begin(), ips.end()), ips.end());
        return ips;
    }

    static std::vector<std::string> GetHardcodedBootstrap() {
#ifdef VELD_PUBLIC_TESTNET
        // No final-mainnet DNS authority is valid for the disposable chain.
        // Operators must provide a testnet-only inventory through
        // explicit --connect entries; an absent inventory is a startup error.
        return {};
#else
        // Connect to the three currently operated public fleet relays. Offline
        // historical hosts are intentionally absent so normal bootstrap does
        // not spend every watchdog cycle retrying retired infrastructure.
        static const std::vector<std::string> kSeedHosts = {
            "node1.veld.network",
            "node2.veld.network",
            "node3.veld.network",
        };
        return kSeedHosts;
#endif
    }

    // Signed canonical addresses for the three operated mainnet fleet anchors.
    // Discovery still uses replaceable DNS names, but anchor authority is
    // assigned only from this release-bound exact-IP inventory. This prevents
    // a DNS response from granting clock-anchor status.
    static std::vector<std::string> GetHardcodedFleetAnchorIps() {
#ifdef VELD_PUBLIC_TESTNET
        return {};
#else
        return {
            "5.78.107.166",
            "5.78.97.56",
            "5.78.127.51",
        };
#endif
    }

    // Tor-only bootstrap: the fleet hubs' persistent v3 hidden services
    // (front-doors to their compiled-role P2P listeners). A Tor-only miner dials these
    // through SOCKS5 so it reaches the network with ZERO clearnet IP exposure.
    // Plain .onion strings (no DNS) — ConnectTo routes them via Tor. Tombstone
    // discipline: a hub's .onion changes only if its /var/lib/tor/veld_p2p/
    // HiddenServiceDir is regenerated, so keep these in lockstep with
    // `cat /var/lib/tor/veld_p2p/hostname` on h1/h2. Add more hub onions here
    // as the Tor backbone grows (more onions = more resilient onion mesh).
    static std::vector<std::string> GetTorBootstrap() {
#ifdef VELD_PUBLIC_TESTNET
        // The final fleet's onions and DNS-through-Tor handles are separate
        // authorities.  Testnet Tor bootstrap remains unconfigured/fail-closed.
        return {};
#else
        // The three-node published fleet. Every entry is a rotation-proof
        // handle (onion or
        // DNS) so an OCI micro changing its IP on restart is a one-line DNS edit,
        // never a rebuild. A --tor-only client reaches all of them with ZERO IP/
        // DNS exposure: ConnectTo() routes EVERY dial through Socks5Connect, which
        // uses SOCKS5 domain addressing (ATYP=0x03) — tor resolves the hostname
        // REMOTELY and connects via an exit, so onions ride end-to-end Tor and the
        // DNS-named clearnet seeds ride Tor→exit. Entries whose DNS record does
        // not yet exist simply NXDOMAIN-skip (graceful); the others + ADDR gossip
        // still cover the fleet. Keep node*.veld.network DNS-only (grey cloud) on
        // Cloudflare — proxying would hand out web IPs and break P2P.
        return {
            // n1/n2 are the Ubuntu hubs via their persistent v3 hidden services
            // (end-to-end Tor, no exit hop). n3 is reached through a Tor exit
            // with remote DNS resolution until it has a dedicated onion service.
            "wii2qlhlxsxufavkxpo2aqxszuwxnriv6aaxly3vyzfr2tiymykdwjad.onion", // n1, 5.78.107.166
            "sduu6rrra4k6wvwyp33qz5te5c3s4jhkdj2gbvs2zuv73dhiv4dtktad.onion", // n2, 5.78.97.56
            "node3.veld.network", // n3, 5.78.127.51
        };
#endif
    }
};

class SeederService {
public:
    SeederService(uint32_t magic, uint16_t dns_port = 5353)
        : db_()
        , crawler_(db_, magic)
        , dns_(db_, dns_port)
        , magic_(magic) {}

    bool Start(const std::vector<std::string>& bootstrap_ips) {
        if (!crawler_.Start(bootstrap_ips)) return false;
        if (!dns_.Start()) {
            crawler_.Stop();
            return false;
        }
        std::cout << "Veld Seeder started\n";
        std::cout << dns_.GetStats();
        return true;
    }

    void Stop() {
        crawler_.Stop();
        dns_.Stop();
    }

    std::string GetFullStats() const {
        std::string s;
        s += db_.GetStats();
        s += dns_.GetStats();
        return s;
    }

    PeerDB& GetDB() { return db_; }

private:
    PeerDB          db_;
    NetworkCrawler  crawler_;
    DNSSeeder       dns_;
    uint32_t        magic_;
};

}
}
