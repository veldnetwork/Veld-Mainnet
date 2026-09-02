#pragma once
#include "../network/rpc.h"
#include "../compat/platform.h"
#include "listener_activation_guard.h"
#include <algorithm>
#include <thread>
#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <cstring>
#include <unordered_map>
#include <cctype>
#include <cstdlib>
#include <cstdio>
#include <climits>
#include <limits>
#include <memory>
#include <sstream>
#include <vector>
#include <functional>

namespace veld {

using SocketHandle = compat::SocketHandle;

// This listener is deliberately a small one-request-per-connection HTTP
// endpoint, not a general-purpose web server.  Keep its framing rules in a
// dependency-light helper so focused tests can exercise the exact parser.
namespace rpc_http_detail {

enum class ParseStatus : uint8_t {
    OK = 0,
    INCOMPLETE,
    BAD_REQUEST,
    HEADER_TOO_LARGE,
    BODY_TOO_LARGE,
};

struct Request {
    std::string method;
    std::string target;
    std::string version;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
    size_t expected_wire_bytes{0};
};

inline bool IsTokenChar(unsigned char c) {
    if ((c >= '0' && c <= '9') ||
        (c >= 'A' && c <= 'Z') ||
        (c >= 'a' && c <= 'z')) return true;
    switch (c) {
        case '!': case '#': case '$': case '%': case '&': case '\'':
        case '*': case '+': case '-': case '.': case '^': case '_':
        case '`': case '|': case '~':
            return true;
        default:
            return false;
    }
}

inline std::string LowerAscii(std::string value) {
    for (char& c : value)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}

inline bool ParseCanonicalSize(const std::string& value, size_t* out) {
    if (!out || value.empty()) return false;
    // Multiple decimal encodings of one length have caused request-smuggling
    // differentials in real proxy stacks.  Accept one canonical spelling.
    if (value.size() > 1 && value.front() == '0') return false;
    size_t parsed = 0;
    for (unsigned char c : value) {
        if (c < '0' || c > '9') return false;
        const size_t digit = static_cast<size_t>(c - '0');
        if (parsed > (std::numeric_limits<size_t>::max() - digit) / 10)
            return false;
        parsed = parsed * 10 + digit;
    }
    *out = parsed;
    return true;
}

inline ParseStatus ParseRequest(const std::string& raw,
                                size_t max_header_bytes,
                                size_t max_body_bytes,
                                Request* out) {
    if (!out || max_header_bytes < 16) return ParseStatus::BAD_REQUEST;
    const size_t head_end = raw.find("\r\n\r\n");
    if (head_end == std::string::npos) {
        return raw.size() >= max_header_bytes
            ? ParseStatus::HEADER_TOO_LARGE : ParseStatus::INCOMPLETE;
    }
    const size_t body_offset = head_end + 4;
    if (body_offset > max_header_bytes) return ParseStatus::HEADER_TOO_LARGE;
    if (raw.find('\0') != std::string::npos) return ParseStatus::BAD_REQUEST;

    const size_t first_eol = raw.find("\r\n");
    if (first_eol == std::string::npos || first_eol == 0 ||
        first_eol > head_end)
        return ParseStatus::BAD_REQUEST;
    const std::string request_line = raw.substr(0, first_eol);
    const size_t sp1 = request_line.find(' ');
    if (sp1 == std::string::npos || sp1 == 0) return ParseStatus::BAD_REQUEST;
    const size_t sp2 = request_line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos || sp2 == sp1 + 1 ||
        request_line.find(' ', sp2 + 1) != std::string::npos)
        return ParseStatus::BAD_REQUEST;

    Request parsed;
    parsed.method = request_line.substr(0, sp1);
    parsed.target = request_line.substr(sp1 + 1, sp2 - sp1 - 1);
    parsed.version = request_line.substr(sp2 + 1);
    // HTTP/1.0 remains accepted because the shipped validator, distributor,
    // and desktop clients intentionally use a close-delimited 1.0 request.
    if ((parsed.version != "HTTP/1.0" && parsed.version != "HTTP/1.1") ||
        parsed.target.empty() || parsed.target.front() != '/')
        return ParseStatus::BAD_REQUEST;
    for (unsigned char c : parsed.method)
        if (c < 'A' || c > 'Z') return ParseStatus::BAD_REQUEST;
    for (unsigned char c : parsed.target)
        if (c <= 0x20 || c == 0x7f) return ParseStatus::BAD_REQUEST;

    size_t pos = first_eol + 2;
    while (pos < head_end) {
        const size_t eol = raw.find("\r\n", pos);
        if (eol == std::string::npos || eol > head_end || eol == pos)
            return ParseStatus::BAD_REQUEST;
        if (raw[pos] == ' ' || raw[pos] == '\t')
            return ParseStatus::BAD_REQUEST; // obsolete line folding
        const size_t colon = raw.find(':', pos);
        if (colon == std::string::npos || colon == pos || colon >= eol)
            return ParseStatus::BAD_REQUEST;
        std::string name = raw.substr(pos, colon - pos);
        for (unsigned char c : name)
            if (!IsTokenChar(c)) return ParseStatus::BAD_REQUEST;
        name = LowerAscii(std::move(name));

        size_t begin = colon + 1;
        while (begin < eol && (raw[begin] == ' ' || raw[begin] == '\t'))
            ++begin;
        size_t end = eol;
        while (end > begin && (raw[end - 1] == ' ' || raw[end - 1] == '\t'))
            --end;
        std::string value = raw.substr(begin, end - begin);
        for (unsigned char c : value)
            if (c < 0x20 || c == 0x7f) return ParseStatus::BAD_REQUEST;
        // Never comma-merge duplicate fields.  In particular, Content-Length,
        // Authorization, and forwarding headers must have one wire authority.
        if (!parsed.headers.emplace(std::move(name), std::move(value)).second)
            return ParseStatus::BAD_REQUEST;
        pos = eol + 2;
    }

    if (parsed.headers.count("transfer-encoding") != 0)
        return ParseStatus::BAD_REQUEST;
    size_t content_length = 0;
    const auto cl = parsed.headers.find("content-length");
    if (cl != parsed.headers.end()) {
        if (!ParseCanonicalSize(cl->second, &content_length))
            return ParseStatus::BAD_REQUEST;
    } else if (parsed.method == "POST") {
        return ParseStatus::BAD_REQUEST;
    }
    if (content_length > max_body_bytes)
        return ParseStatus::BODY_TOO_LARGE;
    if (body_offset > std::numeric_limits<size_t>::max() - content_length)
        return ParseStatus::BODY_TOO_LARGE;
    const size_t expected = body_offset + content_length;
    parsed.expected_wire_bytes = expected;
    if (raw.size() < expected) {
        *out = std::move(parsed);
        return ParseStatus::INCOMPLETE;
    }
    if (raw.size() != expected)
        return ParseStatus::BAD_REQUEST; // pipelining, trailer, or CL mismatch
    parsed.body.assign(raw.data() + body_offset, content_length);
    *out = std::move(parsed);
    return ParseStatus::OK;
}

inline const std::string* Header(const Request& request,
                                 const char* lower_name) {
    const auto it = request.headers.find(lower_name);
    return it == request.headers.end() ? nullptr : &it->second;
}

} // namespace rpc_http_detail

class RpcHttpServer {
public:
    RpcHttpServer(RpcServer& rpc, uint16_t port = 8334, const std::string& ui_html = "",
                  const std::string& auth_token = "")
        : rpc_(rpc), port_(port), running_(false),
          listen_fd_(compat::kInvalidSocket),
          ui_html_(ui_html), auth_token_(auth_token) {}

    ~RpcHttpServer() { Stop(); }

    bool Start(const std::function<bool()>& activation_guard = {}) {
        activation_guard_refused_.store(false, std::memory_order_release);
        if (running_.load(std::memory_order_acquire) || thread_.joinable())
            return false;
        // H-02 fail-closed: a mutating loopback JSON-RPC must never run unauthenticated — an
        // empty token gates nothing. Refuse to bind unless a token is set.  An
        // isolated test binary may compile VELD_RPC_TEST_NO_AUTH and then opt in
        // at runtime; public-release identity compile-bans that capability.
        bool allow_test_no_auth = false;
#ifdef VELD_RPC_TEST_NO_AUTH
        if (const char* value = std::getenv("VELD_RPC_ALLOW_NO_AUTH")) {
            const std::string setting(value);
            allow_test_no_auth = setting == "1" || setting == "true" ||
                                 setting == "yes";
        }
#endif
        if (auth_token_.empty() && !allow_test_no_auth) {
            std::fprintf(stderr, "  [rpc-http] REFUSING to start on port %u: no RPC auth token "
                         "(unauthenticated mode is compiled only into isolated test binaries).\n",
                         (unsigned)port_);
            return false;
        }
        if (!net::ListenerActivationPermitted(activation_guard)) {
            activation_guard_refused_.store(true, std::memory_order_release);
            return false;
        }
        listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (!compat::IsValidSocket(listen_fd_)) return false;
        int opt = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
        struct sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(port_);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            VELD_CLOSE_SOCKET(listen_fd_); listen_fd_ = compat::kInvalidSocket; return false;
        }
        if (!net::ListenerActivationPermitted(activation_guard)) {
            activation_guard_refused_.store(true, std::memory_order_release);
            VELD_CLOSE_SOCKET(listen_fd_); listen_fd_ = compat::kInvalidSocket; return false;
        }
        if (::listen(listen_fd_, 16) < 0) {
            VELD_CLOSE_SOCKET(listen_fd_); listen_fd_ = compat::kInvalidSocket; return false;
        }
        if (!net::ListenerActivationPermitted(activation_guard)) {
            activation_guard_refused_.store(true, std::memory_order_release);
            VELD_CLOSE_SOCKET(listen_fd_); listen_fd_ = compat::kInvalidSocket; return false;
        }
        running_ = true;
        try {
            thread_ = std::thread(&RpcHttpServer::AcceptLoop, this);
        } catch (...) {
            running_ = false;
            VELD_CLOSE_SOCKET(listen_fd_);
            listen_fd_ = compat::kInvalidSocket;
            return false;
        }
        return true;
    }

    bool ActivationGuardRefused() const noexcept {
        return activation_guard_refused_.load(std::memory_order_acquire);
    }

    void Stop() {
        running_ = false;
        if (compat::IsValidSocket(listen_fd_)) {
#ifdef _WIN32
            ::shutdown((SOCKET)listen_fd_, SD_BOTH);
#else
            ::shutdown(listen_fd_, SHUT_RDWR);
#endif
            VELD_CLOSE_SOCKET(listen_fd_);
        }
        if (thread_.joinable()) thread_.join();
        listen_fd_ = compat::kInvalidSocket;
        JoinConnectionWorkers();
    }

    uint16_t Port() const { return port_; }

private:
    RpcServer&        rpc_;
    uint16_t          port_;
    std::atomic<bool> running_;
    std::atomic<bool> activation_guard_refused_{false};
    SocketHandle      listen_fd_;
    std::thread       thread_;
    std::string       ui_html_;
    std::string       auth_token_;

    static bool SendAll(SocketHandle fd, const char* bytes, size_t size) {
        size_t sent = 0;
        while (sent < size) {
            const size_t remaining = size - sent;
            const int chunk = static_cast<int>(std::min<size_t>(
                remaining, static_cast<size_t>(INT_MAX)));
            const int wrote = ::send(fd, bytes + sent, chunk, MSG_NOSIGNAL);
            if (wrote < 0) {
#ifdef _WIN32
                if (WSAGetLastError() == WSAEINTR) continue;
#else
                if (errno == EINTR) continue;
#endif
                return false;
            }
            if (wrote == 0) return false;
            sent += static_cast<size_t>(wrote);
        }
        return true;
    }

    static bool SendAll(SocketHandle fd, const std::string& value) {
        return SendAll(fd, value.data(), value.size());
    }

    static void SendEmptyError(SocketHandle fd, const char* status) {
        const std::string response = std::string("HTTP/1.1 ") + status +
            "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        (void)SendAll(fd, response);
    }

    static constexpr int MAX_INFLIGHT_RPC_CONNS = 64;
    std::atomic<int> inflight_conns_{0};

    struct ConnectionWorker {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };
    std::mutex connection_workers_mutex_;
    std::vector<ConnectionWorker> connection_workers_;

    void ReapConnectionWorkers() {
        std::vector<std::thread> finished;
        {
            std::lock_guard<std::mutex> lk(connection_workers_mutex_);
            for (auto it = connection_workers_.begin();
                 it != connection_workers_.end();) {
                if (it->done->load(std::memory_order_acquire)) {
                    finished.emplace_back(std::move(it->thread));
                    it = connection_workers_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (auto& worker : finished)
            if (worker.joinable()) worker.join();
    }

    void JoinConnectionWorkers() {
        std::vector<std::thread> workers;
        {
            std::lock_guard<std::mutex> lk(connection_workers_mutex_);
            workers.reserve(connection_workers_.size());
            for (auto& worker : connection_workers_)
                workers.emplace_back(std::move(worker.thread));
            connection_workers_.clear();
        }
        for (auto& worker : workers)
            if (worker.joinable()) worker.join();
    }

    mutable std::mutex rpc_clients_mutex_;
    std::unordered_map<std::string, time_t> rpc_clients_;
    void RecordRpcClient(const std::string& ip) {
        std::lock_guard<std::mutex> lk(rpc_clients_mutex_);
        const time_t now = time(nullptr);
        if (rpc_clients_.find(ip) == rpc_clients_.end() &&
            rpc_clients_.size() >= TRACKED_CLIENTS_MAX) {
            const time_t cutoff = now - 240;
            for (auto it = rpc_clients_.begin(); it != rpc_clients_.end(); ) {
                if (it->second < cutoff) it = rpc_clients_.erase(it);
                else ++it;
            }
            if (rpc_clients_.size() >= TRACKED_CLIENTS_MAX) return;
        }
        rpc_clients_[ip] = now;
    }
public:
    size_t ActiveRpcClients() const {
        std::lock_guard<std::mutex> lk(rpc_clients_mutex_);
        size_t count = 0;
        time_t now = time(nullptr);
        for (auto& [ip, ts] : rpc_clients_)
            if (now - ts < 120) ++count;
        return count;
    }
#ifdef VELD_TEST_HOOKS
    uint16_t TestListeningPort() const {
        if (!compat::IsValidSocket(listen_fd_)) return 0;
        struct sockaddr_in addr{};
        socklen_t len = sizeof(addr);
        if (::getsockname(listen_fd_,
                          reinterpret_cast<struct sockaddr*>(&addr),
                          &len) != 0)
            return 0;
        return ntohs(addr.sin_port);
    }

    size_t TestAuthIdentityCount() const {
        std::lock_guard<std::mutex> lock(auth_fail_mutex_);
        return auth_fails_.size();
    }

    size_t TestRateIdentityCount() const {
        std::lock_guard<std::mutex> lock(rate_limit_mutex_);
        return rate_buckets_.size();
    }

    int TestGlobalAuthFailureCount() const {
        std::lock_guard<std::mutex> lock(auth_fail_mutex_);
        return global_auth_fails_.count;
    }
#endif
private:

    mutable std::mutex            auth_fail_mutex_;
    struct AuthFailure {
        int count = 0;
        std::chrono::steady_clock::time_point first{};
        std::chrono::steady_clock::time_point last{};
    };
    std::unordered_map<std::string, AuthFailure> auth_fails_;
    AuthFailure global_auth_fails_;
    static constexpr int    MAX_FAIL_AUTH = 10;
    static constexpr int    MAX_GLOBAL_FAIL_AUTH = 100;
    static constexpr auto   BLOCK_SECS = std::chrono::seconds(300);
    static constexpr size_t TRACKED_CLIENTS_MAX = 256;

    static bool AuthFailureBlocked_(
            AuthFailure& failure,
            std::chrono::steady_clock::time_point now,
            int maximum) {
        if (failure.count == 0) return false;
        if (failure.first.time_since_epoch().count() == 0 ||
            now - failure.first > BLOCK_SECS) {
            failure = AuthFailure{};
            return false;
        }
        return failure.count >= maximum;
    }

    bool IsRateLimited(const std::string& ip) {
        std::lock_guard<std::mutex> lk(auth_fail_mutex_);
        const auto now = std::chrono::steady_clock::now();
        if (AuthFailureBlocked_(global_auth_fails_, now,
                                MAX_GLOBAL_FAIL_AUTH))
            return true;
        auto it = auth_fails_.find(ip);
        if (it == auth_fails_.end()) return false;
        if (!AuthFailureBlocked_(it->second, now, MAX_FAIL_AUTH)) {
            if (it->second.count == 0)
                auth_fails_.erase(it);
            return false;
        }
        return true;
    }

    static void RecordAuthFailure_(
            AuthFailure& failure,
            std::chrono::steady_clock::time_point now) {
        if (failure.count == 0 ||
            failure.first.time_since_epoch().count() == 0 ||
            now - failure.first > BLOCK_SECS) {
            failure = AuthFailure{};
            failure.first = now;
        }
        failure.last = now;
        if (failure.count < std::numeric_limits<int>::max())
            ++failure.count;
    }

    void RecordFailedAuth(const std::string& ip) {
        std::lock_guard<std::mutex> lk(auth_fail_mutex_);
        const auto now = std::chrono::steady_clock::now();
        RecordAuthFailure_(global_auth_fails_, now);
        if (auth_fails_.find(ip) == auth_fails_.end() &&
            auth_fails_.size() >= TRACKED_CLIENTS_MAX) {
            for (auto it = auth_fails_.begin(); it != auth_fails_.end();) {
                if (it->second.last.time_since_epoch().count() == 0 ||
                    now - it->second.last > BLOCK_SECS)
                    it = auth_fails_.erase(it);
                else
                    ++it;
            }
            if (auth_fails_.size() >= TRACKED_CLIENTS_MAX) return;
        }
        RecordAuthFailure_(auth_fails_[ip], now);
    }

    void RecordSuccessAuth(const std::string& ip) {
        std::lock_guard<std::mutex> lk(auth_fail_mutex_);
        // A successful caller may clear only its canonical socket identity.
        // It cannot reset the unspoofable global failure budget for attackers.
        auto it = auth_fails_.find(ip);
        if (it != auth_fails_.end())
            auth_fails_.erase(it);
    }

    struct TokenBucket {
        double                                 tokens = 0.0;
        std::chrono::steady_clock::time_point  last{};
    };
    mutable std::mutex                         rate_limit_mutex_;
    std::unordered_map<std::string, TokenBucket> rate_buckets_;
    TokenBucket global_rate_bucket_;
    static constexpr double RATE_LIMIT_RPS   = 30.0;
    static constexpr double RATE_LIMIT_BURST = 30.0;
    static constexpr size_t RATE_MAP_MAX     = 256;

    static bool TakeBucketToken_(
            TokenBucket& bucket,
            std::chrono::steady_clock::time_point now) {
        if (bucket.last.time_since_epoch().count() == 0) {
            bucket.tokens = RATE_LIMIT_BURST;
        } else {
            const double elapsed =
                std::chrono::duration<double>(now - bucket.last).count();
            bucket.tokens = std::min(
                RATE_LIMIT_BURST,
                bucket.tokens + elapsed * RATE_LIMIT_RPS);
        }
        bucket.last = now;
        if (bucket.tokens < 1.0) return false;
        bucket.tokens -= 1.0;
        return true;
    }

    bool TakeRateToken(const std::string& ip) {
        std::lock_guard<std::mutex> lk(rate_limit_mutex_);
        const auto now = std::chrono::steady_clock::now();

        if (!TakeBucketToken_(global_rate_bucket_, now)) return false;

        if (rate_buckets_.size() >= RATE_MAP_MAX) {
            for (auto it = rate_buckets_.begin(); it != rate_buckets_.end();) {
                // Idle lifetime, not a stale stored token count, controls
                // eviction.  A one-shot identity therefore cannot persist.
                if (it->second.last.time_since_epoch().count() == 0 ||
                    now - it->second.last > std::chrono::seconds(60))
                    it = rate_buckets_.erase(it);
                else
                    ++it;
            }
        }

        auto existing = rate_buckets_.find(ip);
        if (existing == rate_buckets_.end() &&
            rate_buckets_.size() >= RATE_MAP_MAX) return false;
        auto& b = (existing == rate_buckets_.end())
                    ? rate_buckets_.emplace(ip, TokenBucket{}).first->second
                    : existing->second;
        return TakeBucketToken_(b, now);
    }

    std::string ExtractClientIp(SocketHandle fd) const {
        // This server is a direct loopback control plane, not an authenticated
        // reverse-proxy endpoint.  X-Real-IP and X-Forwarded-For are therefore
        // untrusted request data and never become map keys or log identities.
        struct sockaddr_in peer{};
        socklen_t peer_len = sizeof(peer);
        char text[INET_ADDRSTRLEN]{};
        if (::getpeername(fd, reinterpret_cast<struct sockaddr*>(&peer),
                          &peer_len) != 0 ||
            ::inet_ntop(AF_INET, &peer.sin_addr, text, sizeof(text)) == nullptr)
            return "unknown";
        const std::string identity(text);
        return identity.size() <= 15 ? identity : "unknown";
    }

    void AcceptLoop() {
        while (running_) {
            ReapConnectionWorkers();
            struct sockaddr_in client{};
            socklen_t len = sizeof(client);
            SocketHandle fd = ::accept(listen_fd_, (struct sockaddr*)&client, &len);
            if (!compat::IsValidSocket(fd)) {
                if (running_) std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            if (inflight_conns_.load(std::memory_order_acquire)
                >= MAX_INFLIGHT_RPC_CONNS) {
                const char* busy =
                    "HTTP/1.1 503 Service Unavailable\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n\r\n";
                (void)SendAll(fd, busy, std::strlen(busy));
                VELD_CLOSE_SOCKET(fd);
                continue;
            }

#ifdef _WIN32
            DWORD to_ms = 10000;
            const bool timeouts_ok =
                ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                             (const char*)&to_ms, sizeof(to_ms)) == 0 &&
                ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                             (const char*)&to_ms, sizeof(to_ms)) == 0;
#else
            struct timeval tv{10, 0};
            const bool timeouts_ok =
                ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0 &&
                ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
#endif
            if (!timeouts_ok) {
                VELD_CLOSE_SOCKET(fd);
                continue;
            }

            bool worker_started = false;
            try {
                inflight_conns_.fetch_add(1, std::memory_order_acq_rel);
                auto done = std::make_shared<std::atomic<bool>>(false);
                std::thread worker([this, fd, done]() {
                    struct Guard {
                        std::atomic<int>* c;
                        std::atomic<bool>* done;
                        ~Guard(){
                            c->fetch_sub(1, std::memory_order_acq_rel);
                            done->store(true, std::memory_order_release);
                        }
                    } g{&inflight_conns_, done.get()};
                    try { HandleConnection(fd); }
                    catch (...) { VELD_CLOSE_SOCKET(fd); }
                });
                worker_started = true;
                try {
                    std::lock_guard<std::mutex> lk(connection_workers_mutex_);
                    connection_workers_.push_back(
                        ConnectionWorker{std::move(worker), std::move(done)});
                } catch (...) {
                    if (worker.joinable()) worker.join();
                    throw;
                }
            } catch (const std::system_error& e) {
                if (!worker_started)
                    inflight_conns_.fetch_sub(1, std::memory_order_acq_rel);
                std::cerr << "  [rpc-http] thread spawn failed (" << e.what()
                          << ") — dropping request, socket fd=" << fd << "\n";
                std::cerr.flush();
                if (!worker_started) VELD_CLOSE_SOCKET(fd);
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            } catch (const std::exception& e) {
                if (!worker_started)
                    inflight_conns_.fetch_sub(1, std::memory_order_acq_rel);
                std::cerr << "  [rpc-http] unexpected thread-spawn error: "
                          << e.what() << "\n";
                std::cerr.flush();
                if (!worker_started) VELD_CLOSE_SOCKET(fd);
            }
        }
        ReapConnectionWorkers();
    }

    void HandleConnection(SocketHandle fd) {
        struct sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        if (::getpeername(fd, (struct sockaddr*)&peer, &plen) == 0) {
            uint32_t ip = ntohl(peer.sin_addr.s_addr);
            if ((ip >> 24) != 127) {
                VELD_CLOSE_SOCKET(fd);
                return;
            }
        }

        constexpr size_t MAX_HEADERS = 64 * 1024;
        constexpr size_t MAX_BODY = 16 * 1024 * 1024 + 4096;
        std::string raw;
        raw.reserve(8192);
        char buf[8192];
        size_t header_end = std::string::npos;
        while ((header_end = raw.find("\r\n\r\n")) == std::string::npos &&
               raw.size() < MAX_HEADERS) {
            const size_t room = MAX_HEADERS - raw.size();
            const int want = static_cast<int>(std::min(room, sizeof(buf)));
            const int got = ::recv(fd, buf, want, 0);
            if (got <= 0) break;
            raw.append(buf, static_cast<size_t>(got));
        }
        if (header_end == std::string::npos) {
            SendEmptyError(fd, raw.size() >= MAX_HEADERS
                               ? "431 Request Header Fields Too Large"
                               : "400 Bad Request");
            VELD_CLOSE_SOCKET(fd);
            return;
        }

        rpc_http_detail::Request parsed;
        auto parse_status = rpc_http_detail::ParseRequest(
            raw, MAX_HEADERS, MAX_BODY, &parsed);
        if (parse_status == rpc_http_detail::ParseStatus::INCOMPLETE) {
            const size_t target = parsed.expected_wire_bytes;
            while (raw.size() < target) {
                const size_t room = target - raw.size();
                const int want = static_cast<int>(std::min(room, sizeof(buf)));
                const int got = ::recv(fd, buf, want, 0);
                if (got <= 0) break;
                raw.append(buf, static_cast<size_t>(got));
            }
            parse_status = rpc_http_detail::ParseRequest(
                raw, MAX_HEADERS, MAX_BODY, &parsed);
        }
        if (parse_status != rpc_http_detail::ParseStatus::OK) {
            const char* status =
                parse_status == rpc_http_detail::ParseStatus::HEADER_TOO_LARGE
                    ? "431 Request Header Fields Too Large" :
                parse_status == rpc_http_detail::ParseStatus::BODY_TOO_LARGE
                    ? "413 Payload Too Large" : "400 Bad Request";
            SendEmptyError(fd, status);
            VELD_CLOSE_SOCKET(fd);
            return;
        }

        const std::string* host =
            rpc_http_detail::Header(parsed, "host");
        const std::string canonical_host_with_port =
            "127.0.0.1:" + std::to_string(port_);
        const bool canonical_host = host &&
            (*host == "127.0.0.1" || *host == canonical_host_with_port);
        const std::string* origin =
            rpc_http_detail::Header(parsed, "origin");
        const std::string* fetch_site =
            rpc_http_detail::Header(parsed, "sec-fetch-site");
#ifdef VELD_PUBLIC_TESTNET
        const bool canonical_origin = !origin || *origin == "null";
#else
        const bool canonical_origin =
            !origin || *origin == "https://wallet.veld.network";
#endif
        const bool canonical_fetch_site =
            !fetch_site || *fetch_site == "same-origin" ||
            *fetch_site == "same-site" || *fetch_site == "none";
        if (parsed.target != "/" || !canonical_host || !canonical_origin ||
            !canonical_fetch_site) {
            SendEmptyError(fd, "400 Bad Request");
            VELD_CLOSE_SOCKET(fd);
            return;
        }

        const std::string& method = parsed.method;
        const std::string& body = parsed.body;

        std::string cors =
#ifdef VELD_PUBLIC_TESTNET
            "Access-Control-Allow-Origin: null\r\n"
#else
            "Access-Control-Allow-Origin: https://wallet.veld.network\r\n"
#endif
            "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type, Authorization\r\n";

        const std::string client_ip = ExtractClientIp(fd);
        bool authed = false;
        if (!auth_token_.empty() && method == "POST") {
            const std::string* authorization =
                rpc_http_detail::Header(parsed, "authorization");
            static const std::string prefix = "Bearer ";
            if (authorization &&
                authorization->size() == prefix.size() + auth_token_.size() &&
                authorization->compare(0, prefix.size(), prefix) == 0) {
                const std::string token = authorization->substr(prefix.size());
                authed = veld::compat::ConstantTimeEqual(token, auth_token_);
            }
        }

        if (!authed) {
            if (!TakeRateToken(client_ip)) {
                std::cerr << "[rate-limit] 429 -> " << client_ip
                          << " (" << method << ")\n";
                std::string err = R"({"jsonrpc":"2.0","error":{"code":-32005,"message":"Rate limit exceeded"},"id":null})";
                std::string resp = "HTTP/1.1 429 Too Many Requests\r\n"
                    "Retry-After: 1\r\n"
                    "Content-Type: application/json\r\n"
                    + cors + "Content-Length: " + std::to_string(err.size())
                    + "\r\nConnection: close\r\n\r\n" + err;
                (void)SendAll(fd, resp);
                VELD_CLOSE_SOCKET(fd);
                return;
            }
        }

        // Token gate. GET is INTENTIONALLY exempt: the GET handler
        // below serves ONLY the static UI shell (ui_html_, with a per-request
        // CSP nonce) or a "Use POST for JSON-RPC" string — it returns NO
        // chain/wallet data and performs NO mutation. EVERY JSON-RPC method
        // (balances, sends, key ops, ...) is POST-only (the method=="POST"
        // branch) and is gated here. Gating GET would only break the browser UI,
        // which loads via GET and cannot carry a Bearer token. INVARIANT for
        // future maintainers: never add a data-returning or mutating GET route;
        // any such route MUST be POST and therefore token-gated.
        if (!auth_token_.empty() && method != "OPTIONS" && method != "GET") {
            if (authed) {
                RecordSuccessAuth(client_ip);
                RecordRpcClient(client_ip);
            } else {
                if (IsRateLimited(client_ip)) {
                    std::string err = R"({"jsonrpc":"2.0","error":{"code":-32001,"message":"Too many failed attempts — try again later"},"id":null})";
                    std::string resp = "HTTP/1.1 429 Too Many Requests\r\n"
                        "Retry-After: 300\r\n"
                        "Content-Type: application/json\r\n"
                        + cors + "Content-Length: " + std::to_string(err.size())
                        + "\r\nConnection: close\r\n\r\n" + err;
                    (void)SendAll(fd, resp);
                    VELD_CLOSE_SOCKET(fd);
                    return;
                }
                RecordFailedAuth(client_ip);
                std::string err = R"({"jsonrpc":"2.0","error":{"code":-32001,"message":"Unauthorized"},"id":null})";
                std::string resp = "HTTP/1.1 401 Unauthorized\r\n"
                    "WWW-Authenticate: Bearer realm=\"veld\"\r\n"
                    "Content-Type: application/json\r\n"
                    + cors + "Content-Length: " + std::to_string(err.size())
                    + "\r\nConnection: close\r\n\r\n" + err;
                (void)SendAll(fd, resp);
                VELD_CLOSE_SOCKET(fd);
                return;
            }
        }

        std::string response;

        if (method == "OPTIONS") {
            response = "HTTP/1.1 200 OK\r\n" + cors + "Content-Length: 0\r\n\r\n";
        } else if (method == "GET") {
            if (!ui_html_.empty()) {
                uint8_t nbuf[16];
                if (!veld::compat::SecureRandom(nbuf, sizeof(nbuf))) {
                    std::string err = "Server random unavailable";
                    std::string resp = "HTTP/1.1 500 Internal Server Error\r\n"
                        "Content-Type: text/plain\r\n"
                        + cors + "Content-Length: " + std::to_string(err.size())
                        + "\r\nConnection: close\r\n\r\n" + err;
                    (void)SendAll(fd, resp);
                    VELD_CLOSE_SOCKET(fd);
                    return;
                }
                static const char* hex = "0123456789abcdef";
                std::string nonce;
                nonce.reserve(32);
                for (size_t i = 0; i < sizeof(nbuf); ++i) {
                    nonce.push_back(hex[nbuf[i] >> 4]);
                    nonce.push_back(hex[nbuf[i] & 0xF]);
                }

                std::string html = std::string(ui_html_);
                {
                    const std::string placeholder = "__CSP_NONCE__";
                    size_t pos = 0;
                    while ((pos = html.find(placeholder, pos)) != std::string::npos) {
                        html.replace(pos, placeholder.size(), nonce);
                        pos += nonce.size();
                    }
                }

                response = std::string("HTTP/1.1 200 OK\r\n")
                         + "Content-Type: text/html; charset=utf-8\r\n"
                         + "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                         + "Pragma: no-cache\r\n"
                         + "Content-Security-Policy: default-src 'self'; "
                             "script-src 'self' 'wasm-unsafe-eval' 'nonce-" + nonce + "'; "
                             "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                             "font-src 'self' https://fonts.gstatic.com; "
                             "img-src 'self' data:; "
                             "connect-src 'self' /rpc; "
                             "object-src 'none'; "
                             "frame-ancestors 'self'; "
                             "base-uri 'self'\r\n"
                         + cors
                         + "Content-Length: " + std::to_string(html.size()) + "\r\n"
                         + "Connection: close\r\n\r\n"
                         + html;
            } else {
                std::string msg = "Use POST for JSON-RPC";
                response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                         + cors + "Content-Length: " + std::to_string(msg.size()) + "\r\nConnection: close\r\n\r\n" + msg;
            }
        } else if (method == "POST") {
            std::string result = body.empty()
                ? R"({"jsonrpc":"2.0","error":{"code":-32700,"message":"Empty request"},"id":null})"
                : rpc_.Handle(body);
            response = std::string("HTTP/1.1 200 OK\r\n")
                     + "Content-Type: application/json\r\n"
                     + cors
                     + "Content-Length: " + std::to_string(result.size()) + "\r\n"
                     + "Connection: close\r\n\r\n"
                     + result;
        } else {
            std::string err = R"({"jsonrpc":"2.0","error":{"code":-32600,"message":"Method Not Allowed"},"id":null})";
            response = "HTTP/1.1 405 Method Not Allowed\r\n"
                       "Allow: OPTIONS, GET, POST\r\n"
                       "Content-Type: application/json\r\n"
                     + cors
                     + "Content-Length: " + std::to_string(err.size()) + "\r\n"
                     + "Connection: close\r\n\r\n"
                     + err;
        }

        (void)SendAll(fd, response);
        VELD_CLOSE_SOCKET(fd);
    }
};

}
