#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <filesystem>
#include <csignal>
#include <ctime>
#include <cstdlib>
#include <cstdio>
#include <memory>
#include <functional>
#include <algorithm>
#include <limits>
#include <condition_variable>
#include <mutex>

#ifdef VELD_FLEET_NO_MINE
#error "VELD_FLEET_NO_MINE is a node/validator role; a mining-capable desktop artifact is forbidden"
#endif
#if defined(VELD_PUBLIC_MAINNET) && !defined(VELD_USE_LEVELDB)
#error "A public mainnet desktop node must use the canonical LevelDB storage backend"
#endif

#include "compat/platform.h"
#include "compat/process.h"
#include "core/constants.h"
#include "core/version.h"
#include "core/hash.h"
#include "core/transaction.h"
#include "core/block.h"
#include "core/blockchain.h"
#include "core/mempool.h"
#include "core/storage.h"
#include "core/script.h"
#include "core/leveldb.h"
#include "mining/miner.h"
#include "mining/veldhash.h"
#include "wallet/wallet.h"
#include "wallet/wallet_crypto.h"
#include "wallet/secure_channel_file.h"
#include "consensus/staking.h"
#include "network/chainparams.h"
#include "network/p2p.h"
#include "network/rpc.h"
#include "network/rpc_http.h"
#include "network/seeder.h"
#include "network/rpc_method_extract.h"
#include "network/explorer.h"
// Use one wallet surface for every profile. External-value features stay hidden
// way they are everywhere else: ui_desktop.h branches on
// DEPLOYMENT_EXTERNAL_VALUE, which the testnet profile compiles as false.
#include "network/ui_desktop.h"
#include "network/dilithium_wasm_js.h"
#include "network/jsqr_js.h"
#include "network/covenant_client_js.h"
#include "crypto/veld_signing.h"
#include "crypto/ripemd160.h"
#include "node/ibd_policy.h"
#include "node/node.h"

#ifdef _WIN32
#include <winhttp.h>
#elif defined(VELD_DESKTOP_OPENSSL_TLS)
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#endif

using namespace veld;
using namespace veld::mining;
namespace fs = std::filesystem;
using SocketHandle = veld::compat::SocketHandle;

// Shared by the UI supervisor and the bounded remote-wallet transport.  Keep
// it visible before the transport helpers so a stalled TLS request observes
// process shutdown instead of waiting out its full request deadline.
static std::atomic<bool> g_shutdown{false};

#if defined(_WIN32) && defined(VELD_PUBLIC_TESTNET)
extern "C" __attribute__((used, visibility("default")))
const char veld_public_testnet_windows_capability_v1[] =
    "VELD_PUBLIC_TESTNET_WINDOWS_CAPABILITY_V1:"
    "full-p2p-mining-client:mining-compile-enabled";
#endif

struct DesktopHttpHeader {
    bool present{false};
    bool duplicate{false};
    bool malformed{false};
    std::string value;
};

// Strict, header-section-only lookup.  Security decisions must not be made by
// searching an entire request string: attacker-controlled JSON can contain
// text that looks like a header, and duplicate headers create proxy/backend
// interpretation differences.
static DesktopHttpHeader desktop_http_header(const std::string& raw,
                                              size_t header_end,
                                              const char* wanted) {
    DesktopHttpHeader out;
    const size_t request_line_end = raw.find("\r\n");
    if (request_line_end == std::string::npos || request_line_end > header_end) {
        out.malformed = true;
        return out;
    }
    const std::string target(wanted);
    size_t pos = request_line_end + 2;
    while (pos < header_end) {
        const size_t eol = raw.find("\r\n", pos);
        if (eol == std::string::npos || eol > header_end || eol == pos) {
            out.malformed = true;
            return out;
        }
        if (raw[pos] == ' ' || raw[pos] == '\t') {
            out.malformed = true; // obsolete folded header
            return out;
        }
        const size_t colon = raw.find(':', pos);
        if (colon == std::string::npos || colon >= eol || colon == pos) {
            out.malformed = true;
            return out;
        }
        for (size_t i = pos; i < colon; ++i) {
            const unsigned char c = (unsigned char)raw[i];
            const bool token = std::isalnum(c) || c == '!' || c == '#' || c == '$' ||
                c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' ||
                c == '-' || c == '.' || c == '^' || c == '_' || c == '`' ||
                c == '|' || c == '~';
            if (!token) { out.malformed = true; return out; }
        }
        bool match = (colon - pos == target.size());
        for (size_t i = 0; match && i < target.size(); ++i) {
            const char a = (char)std::tolower((unsigned char)raw[pos + i]);
            const char b = (char)std::tolower((unsigned char)target[i]);
            if (a != b) match = false;
        }
        if (match) {
            size_t first = colon + 1;
            while (first < eol && (raw[first] == ' ' || raw[first] == '\t')) ++first;
            size_t last = eol;
            while (last > first && (raw[last - 1] == ' ' || raw[last - 1] == '\t')) --last;
            if (out.present) out.duplicate = true;
            else {
                out.present = true;
                out.value = raw.substr(first, last - first);
            }
        }
        pos = eol + 2;
    }
    return out;
}

static std::string read_rpc_token_file(const std::string& token_file) {
    // A bearer token is equivalent to full RPC authority.  Apply the same
    // anti-link / ownership / parent-directory checks used for the router
    // cookie, then reject anything except the node's canonical 32-byte hex
    // encoding.  In particular, never copy arbitrary file contents into an
    // HTTP Authorization header.
    std::vector<uint8_t> raw;
    std::string why;
    if (veld::channel::secure_file::Read(token_file, raw, &why, 256,
                                          /*require_private_parent=*/true)
        != veld::channel::secure_file::ReadResult::Ok)
        return "";
    // The node writes rpc.token ENCRYPTED whenever a vault passphrase is in
    // use, so a raw read yields ~127 bytes of ciphertext and the 64-hex check
    // below rejected it -- leaving this proxy with no bearer token at all and
    // every allow-listed wallet call answered "Unauthorized".  Decrypt with the
    // same primitive the node uses.  The passphrase is cached once from the
    // environment, exactly as veld-node does, so a later reload still works.
    if (!raw.empty() && !(raw.size() == 64 || raw.size() == 65 ||
                          raw.size() == 66)) {
        static std::string cached_pass = [] {
            const char* env = std::getenv("VELD_VAULT_PASSPHRASE");
            std::string p = env ? std::string(env) : std::string();
            while (!p.empty() && (p.back() == '\n' || p.back() == '\r' ||
                                  p.back() == ' ' || p.back() == '\t'))
                p.pop_back();
            return p;
        }();
        if (!cached_pass.empty()) {
            try {
                std::string plain =
                    veld::wallet_crypto::DecryptWallet(raw, cached_pass);
                if (!plain.empty()) {
                    veld::compat::SecureZero(raw.data(), raw.size());
                    raw.assign(plain.begin(), plain.end());
                }
            } catch (...) {
                // Fall through: an undecryptable token is simply no token.
            }
        }
    }
    std::string tok(raw.begin(), raw.end());
    if (!tok.empty() && tok.back() == '\n') tok.pop_back();
    if (!tok.empty() && tok.back() == '\r') tok.pop_back();
    if (tok.size() != 64) return "";
    for (char c : tok)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return "";
    return tok;
}

static std::string load_rpc_token(const std::string& datadir) {
    return read_rpc_token_file(datadir + "/rpc.token");
}

struct DesktopRpcEndpoint {
    std::string host;
    uint16_t port{0};
    bool secure{false};
    bool may_use_local_bearer{false};
};

// Parse only an exact HTTP(S) authority. Plaintext is intentionally restricted
// to the two loopback spellings used by the co-located node. Remote RPC must use
// authenticated TLS; no path, userinfo, fragment, IPv6-literal ambiguity, or
// unsafe downgrade mode is accepted.
static bool parse_desktop_rpc_endpoint(const std::string& url,
                                       DesktopRpcEndpoint& out) {
    out = DesktopRpcEndpoint{};
    size_t scheme_size = 0;
    if (url.rfind("https://", 0) == 0) {
        out.secure = true;
        scheme_size = sizeof("https://") - 1;
    } else if (url.rfind("http://", 0) == 0) {
        out.secure = false;
        scheme_size = sizeof("http://") - 1;
    } else {
        return false;
    }
    const std::string authority = url.substr(scheme_size);
    if (authority.empty() || authority.size() > 260 ||
        authority.find_first_of("/?#@") != std::string::npos)
        return false;

    std::string host = authority;
    std::string port_text;
    const size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
        // IPv6 literals are not supported by the AF_INET transport.  Reject
        // them rather than parsing one of their colons as a port separator.
        if (authority.find(':') != colon) return false;
        host = authority.substr(0, colon);
        port_text = authority.substr(colon + 1);
    }
    if (host.empty() || host.size() > 253) return false;
    for (unsigned char c : host) {
        if (!(std::isalnum(c) || c == '.' || c == '-')) return false;
    }
    if (host.front() == '.' || host.back() == '.' ||
        host.front() == '-' || host.back() == '-')
        return false;

    uint32_t port = out.secure ? 443u : CompiledPublicRpcPort();
    if (!port_text.empty()) {
        port = 0;
        for (unsigned char c : port_text) {
            if (c < '0' || c > '9') return false;
            port = port * 10u + static_cast<uint32_t>(c - '0');
            if (port > 65535u) return false;
        }
        if (port == 0) return false;
    } else if (colon != std::string::npos) {
        return false;
    }

    std::string lower_host = host;
    for (char& c : lower_host)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    out.host = std::move(lower_host);
    out.port = static_cast<uint16_t>(port);
    out.may_use_local_bearer =
        out.host == "127.0.0.1" || out.host == "localhost";
    if (!out.secure && !out.may_use_local_bearer) return false;
    return true;
}

static std::string desktop_rpc_transport_error(const char* message) {
    return std::string("{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,"
                       "\"message\":\"") + message + "\"},\"id\":null}";
}

static std::string desktop_parse_tls_rpc_response(const std::string& response) {
    constexpr size_t MAX_HEADERS = 64 * 1024;
    constexpr size_t MAX_BODY = 32 * 1024 * 1024;
    const size_t header_end = response.find("\r\n\r\n");
    if (header_end == std::string::npos || header_end > MAX_HEADERS)
        return desktop_rpc_transport_error("Malformed TLS node response");
    const size_t status_end = response.find("\r\n");
    if (status_end == std::string::npos || status_end > header_end) {
        return desktop_rpc_transport_error("Malformed TLS node status");
    }
    const std::string status = response.substr(0, status_end);
    if (!((status.rfind("HTTP/1.0 200 ", 0) == 0) ||
          (status.rfind("HTTP/1.1 200 ", 0) == 0))) {
        return desktop_rpc_transport_error("TLS node rejected request");
    }
    const DesktopHttpHeader content_length =
        desktop_http_header(response, header_end, "Content-Length");
    const DesktopHttpHeader transfer_encoding =
        desktop_http_header(response, header_end, "Transfer-Encoding");
    if (content_length.malformed || content_length.duplicate ||
        transfer_encoding.malformed || transfer_encoding.present) {
        return desktop_rpc_transport_error("Ambiguous TLS node response framing");
    }
    const size_t body_start = header_end + 4;
    if (response.size() < body_start || response.size() - body_start > MAX_BODY)
        return desktop_rpc_transport_error("TLS node response too large");
    if (content_length.present) {
        if (content_length.value.empty())
            return desktop_rpc_transport_error("Malformed TLS node response length");
        size_t expected = 0;
        for (unsigned char c : content_length.value) {
            if (c < '0' || c > '9')
                return desktop_rpc_transport_error("Malformed TLS node response length");
            const size_t digit = static_cast<size_t>(c - '0');
            if (expected > (MAX_BODY - digit) / 10)
                return desktop_rpc_transport_error("TLS node response too large");
            expected = expected * 10 + digit;
        }
        if (response.size() - body_start != expected)
            return desktop_rpc_transport_error("Truncated or overlong TLS node response");
    }
    return response.substr(body_start);
}

#ifdef _WIN32
// The public source tree intentionally carries no platform build manifest.
// Resolve the Windows system TLS transport at runtime so the wallet remains
// compatible with the established self-contained link line and cannot
// accidentally acquire a redistributable DLL dependency.
struct DesktopWinHttpApi {
    HMODULE module{nullptr};
    decltype(&::WinHttpOpen) open{nullptr};
    decltype(&::WinHttpSetTimeouts) set_timeouts{nullptr};
    decltype(&::WinHttpSetOption) set_option{nullptr};
    decltype(&::WinHttpConnect) connect{nullptr};
    decltype(&::WinHttpOpenRequest) open_request{nullptr};
    decltype(&::WinHttpSendRequest) send_request{nullptr};
    decltype(&::WinHttpReceiveResponse) receive_response{nullptr};
    decltype(&::WinHttpQueryHeaders) query_headers{nullptr};
    decltype(&::WinHttpQueryDataAvailable) query_available{nullptr};
    decltype(&::WinHttpReadData) read_data{nullptr};
    decltype(&::WinHttpCloseHandle) close_handle{nullptr};

    DesktopWinHttpApi() {
        module = ::LoadLibraryW(L"winhttp.dll");
        if (!module) return;
#define VELD_WINHTTP_RESOLVE(member, symbol)                                  \
        member = reinterpret_cast<decltype(member)>(                          \
            ::GetProcAddress(module, symbol))
        VELD_WINHTTP_RESOLVE(open, "WinHttpOpen");
        VELD_WINHTTP_RESOLVE(set_timeouts, "WinHttpSetTimeouts");
        VELD_WINHTTP_RESOLVE(set_option, "WinHttpSetOption");
        VELD_WINHTTP_RESOLVE(connect, "WinHttpConnect");
        VELD_WINHTTP_RESOLVE(open_request, "WinHttpOpenRequest");
        VELD_WINHTTP_RESOLVE(send_request, "WinHttpSendRequest");
        VELD_WINHTTP_RESOLVE(receive_response, "WinHttpReceiveResponse");
        VELD_WINHTTP_RESOLVE(query_headers, "WinHttpQueryHeaders");
        VELD_WINHTTP_RESOLVE(query_available,
                             "WinHttpQueryDataAvailable");
        VELD_WINHTTP_RESOLVE(read_data, "WinHttpReadData");
        VELD_WINHTTP_RESOLVE(close_handle, "WinHttpCloseHandle");
#undef VELD_WINHTTP_RESOLVE
    }

    ~DesktopWinHttpApi() {
        if (module) ::FreeLibrary(module);
    }

    DesktopWinHttpApi(const DesktopWinHttpApi&) = delete;
    DesktopWinHttpApi& operator=(const DesktopWinHttpApi&) = delete;

    explicit operator bool() const {
        return module && open && set_timeouts && set_option && connect &&
               open_request && send_request && receive_response &&
               query_headers && query_available && read_data && close_handle;
    }
};

static std::string proxy_rpc_https(const DesktopRpcEndpoint& endpoint,
                                   const std::string& body,
                                   const std::string& auth_token) {
    if (!endpoint.secure || body.empty() || body.size() > 32U * 1024U * 1024U)
        return desktop_rpc_transport_error("Invalid TLS node request");
    DesktopWinHttpApi api;
    if (!api)
        return desktop_rpc_transport_error("Windows TLS transport unavailable");
    const std::wstring host(endpoint.host.begin(), endpoint.host.end());
    HINTERNET session = api.open(
        L"VeldDesktopWallet/2.9", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return desktop_rpc_transport_error("TLS session unavailable");
    api.set_timeouts(session, 30000, 30000, 30000, 30000);
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
#ifdef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
    protocols |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
#endif
    if (!api.set_option(session, WINHTTP_OPTION_SECURE_PROTOCOLS,
                        &protocols, sizeof(protocols))) {
        api.close_handle(session);
        return desktop_rpc_transport_error("TLS policy unavailable");
    }
    HINTERNET connect = api.connect(session, host.c_str(), endpoint.port, 0);
    if (!connect) {
        api.close_handle(session);
        return desktop_rpc_transport_error("TLS node connection unavailable");
    }
    HINTERNET request = api.open_request(
        connect, L"POST", L"/", nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!request) {
        api.close_handle(connect);
        api.close_handle(session);
        return desktop_rpc_transport_error("TLS node request unavailable");
    }
    DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if (!api.set_option(request, WINHTTP_OPTION_REDIRECT_POLICY,
                        &redirect_policy, sizeof(redirect_policy))) {
        api.close_handle(request);
        api.close_handle(connect);
        api.close_handle(session);
        return desktop_rpc_transport_error("TLS redirect policy unavailable");
    }
    std::wstring headers =
        L"Accept: application/json\r\nContent-Type: application/json\r\n";
    if (endpoint.may_use_local_bearer && !auth_token.empty()) {
        headers += L"Authorization: Bearer ";
        headers.append(auth_token.begin(), auth_token.end());
        headers += L"\r\n";
    }
    const BOOL sent = api.send_request(
        request, headers.c_str(), static_cast<DWORD>(headers.size()),
        const_cast<char*>(body.data()), static_cast<DWORD>(body.size()),
        static_cast<DWORD>(body.size()), 0);
    std::string result;
    if (!sent || !api.receive_response(request, nullptr)) {
        result = desktop_rpc_transport_error(
            "TLS authentication or node request failed");
    } else {
        DWORD status = 0;
        DWORD status_size = sizeof(status);
        if (!api.query_headers(
                request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                WINHTTP_NO_HEADER_INDEX) || status != 200) {
            result = desktop_rpc_transport_error("TLS node rejected request");
        } else {
            constexpr size_t MAX_RESPONSE = 32U * 1024U * 1024U;
            for (;;) {
                DWORD available = 0;
                if (!api.query_available(request, &available)) {
                    result = desktop_rpc_transport_error("TLS node response failed");
                    break;
                }
                if (available == 0) break;
                if (result.size() + available > MAX_RESPONSE) {
                    result = desktop_rpc_transport_error("TLS node response too large");
                    break;
                }
                const size_t offset = result.size();
                result.resize(offset + available);
                DWORD received = 0;
                if (!api.read_data(request, result.data() + offset,
                                   available, &received) || received == 0) {
                    result = desktop_rpc_transport_error("TLS node response failed");
                    break;
                }
                result.resize(offset + received);
            }
        }
    }
    api.close_handle(request);
    api.close_handle(connect);
    api.close_handle(session);
    return result;
}
#elif defined(VELD_DESKTOP_OPENSSL_TLS)
enum class DesktopTlsWaitResult {
    READY,
    DEADLINE,
    SHUTDOWN,
    SOCKET_ERROR,
};

using DesktopTlsClock = std::chrono::steady_clock;
static constexpr std::chrono::seconds DESKTOP_TLS_REQUEST_LIMIT{30};

static DesktopTlsWaitResult desktop_tls_wait_ready(
        SocketHandle fd, short events,
        const DesktopTlsClock::time_point& deadline) {
    for (;;) {
        if (g_shutdown.load(std::memory_order_acquire))
            return DesktopTlsWaitResult::SHUTDOWN;
        const auto now = DesktopTlsClock::now();
        if (now >= deadline) return DesktopTlsWaitResult::DEADLINE;

        // Poll in short slices so Ctrl+C/service shutdown interrupts a stalled
        // request promptly, while the absolute deadline (never a per-progress
        // timeout) remains the sole request budget.
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - now);
        if (remaining.count() <= 0) remaining = std::chrono::milliseconds(1);
        const auto slice = std::min(remaining, std::chrono::milliseconds(250));
        struct pollfd descriptor{};
        descriptor.fd = fd;
        descriptor.events = events;
        const int ready = ::poll(
            &descriptor, 1, static_cast<int>(slice.count()));
        if (ready > 0) {
            if ((descriptor.revents & POLLNVAL) != 0)
                return DesktopTlsWaitResult::SOCKET_ERROR;
            // POLLHUP/POLLERR still require one SSL call so OpenSSL can
            // distinguish authenticated close_notify from abrupt EOF.
            if ((descriptor.revents & (events | POLLHUP | POLLERR)) != 0)
                return DesktopTlsWaitResult::READY;
        } else if (ready < 0 && errno != EINTR) {
            return DesktopTlsWaitResult::SOCKET_ERROR;
        }
    }
}

static const char* desktop_tls_wait_error(DesktopTlsWaitResult result) {
    switch (result) {
        case DesktopTlsWaitResult::DEADLINE:
            return "TLS node request total deadline exceeded";
        case DesktopTlsWaitResult::SHUTDOWN:
            return "TLS node request interrupted by shutdown";
        case DesktopTlsWaitResult::SOCKET_ERROR:
            return "TLS node request socket readiness failed";
        case DesktopTlsWaitResult::READY:
            break;
    }
    return "TLS node request failed";
}

struct DesktopTlsResolveState {
    std::mutex mutex;
    std::condition_variable ready;
    std::string host;
    std::string service;
    struct addrinfo hints{};
    struct addrinfo* result{nullptr};
    int error{EAI_FAIL};
    bool done{false};
    bool abandoned{false};
};

static std::atomic<bool>& desktop_tls_resolver_busy() {
    // Intentionally process-lifetime storage: a resolver abandoned during
    // shutdown may finish after ordinary static destruction has begun.
    static auto* busy = new std::atomic<bool>(false);
    return *busy;
}

static bool desktop_tls_resolve(
        const std::string& host, const std::string& service,
        const DesktopTlsClock::time_point& deadline,
        struct addrinfo*& resolved, std::string& failure) {
    resolved = nullptr;
    for (;;) {
        bool expected = false;
        if (desktop_tls_resolver_busy().compare_exchange_strong(
                expected, true, std::memory_order_acq_rel))
            break;
        if (g_shutdown.load(std::memory_order_acquire) ||
            DesktopTlsClock::now() >= deadline) {
            failure = g_shutdown.load(std::memory_order_acquire)
                ? "TLS node request interrupted by shutdown"
                : "TLS node request total deadline exceeded";
            return false;
        }
        // A prior resolver may be finishing or may still be blocked in the
        // operating-system resolver.  Preserve the one-worker resource bound
        // without turning normal concurrent wallet calls into an immediate
        // availability failure; every waiter retains its own absolute budget.
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::shared_ptr<DesktopTlsResolveState> state;
    try {
        state = std::make_shared<DesktopTlsResolveState>();
        state->host = host;
        state->service = service;
        state->hints.ai_family = AF_UNSPEC;
        state->hints.ai_socktype = SOCK_STREAM;
    } catch (...) {
        desktop_tls_resolver_busy().store(false, std::memory_order_release);
        failure = "TLS node resolver could not start";
        return false;
    }
    std::thread worker;
    try {
        worker = std::thread([state] {
            struct addrinfo* answer = nullptr;
            const int error = ::getaddrinfo(
                state->host.c_str(), state->service.c_str(),
                &state->hints, &answer);
            bool discard = false;
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                state->error = error;
                state->done = true;
                if (state->abandoned) {
                    discard = true;
                } else {
                    state->result = answer;
                }
            }
            desktop_tls_resolver_busy().store(
                false, std::memory_order_release);
            state->ready.notify_all();
            if (discard && answer) ::freeaddrinfo(answer);
        });
    } catch (...) {
        desktop_tls_resolver_busy().store(false, std::memory_order_release);
        failure = "TLS node resolver could not start";
        return false;
    }

    std::unique_lock<std::mutex> lock(state->mutex);
    while (!state->done) {
        const bool shutdown =
            g_shutdown.load(std::memory_order_acquire);
        const auto now = DesktopTlsClock::now();
        if (shutdown || now >= deadline) {
            state->abandoned = true;
            failure = shutdown
                ? "TLS node request interrupted by shutdown"
                : "TLS node request total deadline exceeded";
            lock.unlock();
            worker.detach();
            return false;
        }
        state->ready.wait_until(
            lock, std::min(deadline, now + std::chrono::milliseconds(250)));
    }
    resolved = state->result;
    const int error = state->error;
    lock.unlock();
    worker.join();
    if (error != 0 || !resolved) {
        if (resolved) {
            ::freeaddrinfo(resolved);
            resolved = nullptr;
        }
        failure = "Cannot resolve TLS node";
        return false;
    }
    return true;
}

static void desktop_tls_shutdown(
        SSL* tls, SocketHandle fd,
        const DesktopTlsClock::time_point& deadline) {
    short wait_for = POLLOUT;
    for (;;) {
        if (g_shutdown.load(std::memory_order_acquire) ||
            DesktopTlsClock::now() >= deadline)
            return;
        const int stopped = SSL_shutdown(tls);
        if (stopped == 1) return;
        const int error = SSL_get_error(tls, stopped);
        if (stopped == 0) {
            // close_notify was sent; wait only within the same total budget
            // for the peer's authenticated close_notify.
            wait_for = POLLIN;
        } else if (error == SSL_ERROR_WANT_READ ||
                   error == SSL_ERROR_WANT_WRITE) {
            wait_for = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
        } else {
            return;
        }
        if (desktop_tls_wait_ready(fd, wait_for, deadline) !=
            DesktopTlsWaitResult::READY)
            return;
    }
}

static std::string proxy_rpc_https_until(
        const DesktopRpcEndpoint& endpoint,
        const std::string& body,
        const std::string& auth_token,
        const DesktopTlsClock::time_point& request_deadline) {
    if (!endpoint.secure || body.empty() || body.size() > 32U * 1024U * 1024U)
        return desktop_rpc_transport_error("Invalid TLS node request");
    if (g_shutdown.load(std::memory_order_acquire) ||
        DesktopTlsClock::now() >= request_deadline)
        return desktop_rpc_transport_error(
            g_shutdown.load(std::memory_order_acquire)
                ? "TLS node request interrupted by shutdown"
                : "TLS node request total deadline exceeded");
    SSL_CTX* context = SSL_CTX_new(TLS_client_method());
    if (!context) return desktop_rpc_transport_error("TLS session unavailable");
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION) != 1 ||
        SSL_CTX_set_default_verify_paths(context) != 1) {
        SSL_CTX_free(context);
        return desktop_rpc_transport_error("TLS trust store unavailable");
    }
    if (g_shutdown.load(std::memory_order_acquire) ||
        DesktopTlsClock::now() >= request_deadline) {
        SSL_CTX_free(context);
        return desktop_rpc_transport_error(
            g_shutdown.load(std::memory_order_acquire)
                ? "TLS node request interrupted by shutdown"
                : "TLS node request total deadline exceeded");
    }

    struct addrinfo* resolved = nullptr;
    const std::string service = std::to_string(endpoint.port);
    std::string resolve_failure;
    if (!desktop_tls_resolve(
            endpoint.host, service, request_deadline,
            resolved, resolve_failure)) {
        SSL_CTX_free(context);
        return desktop_rpc_transport_error(resolve_failure.c_str());
    }
    SocketHandle fd = veld::compat::kInvalidSocket;
    const char* setup_error = nullptr;
    for (auto* address = resolved; address; address = address->ai_next) {
        if (g_shutdown.load(std::memory_order_acquire) ||
            DesktopTlsClock::now() >= request_deadline) {
            setup_error = g_shutdown.load(std::memory_order_acquire)
                ? "TLS node request interrupted by shutdown"
                : "TLS node request total deadline exceeded";
            break;
        }
        fd = ::socket(address->ai_family, address->ai_socktype,
                      address->ai_protocol);
        if (!veld::compat::IsValidSocket(fd)) continue;
        const int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            VELD_CLOSE_SOCKET(fd);
            fd = veld::compat::kInvalidSocket;
            continue;
        }
        const int connected = ::connect(
            fd, address->ai_addr,
            static_cast<socklen_t>(address->ai_addrlen));
        if (connected == 0) break;
        if (errno == EINPROGRESS) {
            const DesktopTlsWaitResult wait = desktop_tls_wait_ready(
                fd, POLLOUT, request_deadline);
            int socket_error = 0;
            socklen_t socket_error_size = sizeof(socket_error);
            if (wait == DesktopTlsWaitResult::READY &&
                ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error,
                             &socket_error_size) == 0 &&
                socket_error == 0)
                break;
            if (wait != DesktopTlsWaitResult::READY)
                setup_error = desktop_tls_wait_error(wait);
        }
        VELD_CLOSE_SOCKET(fd);
        fd = veld::compat::kInvalidSocket;
    }
    ::freeaddrinfo(resolved);
    if (!veld::compat::IsValidSocket(fd)) {
        SSL_CTX_free(context);
        return desktop_rpc_transport_error(
            setup_error ? setup_error : "Cannot connect to TLS node");
    }

    SSL* tls = SSL_new(context);
    bool configured = tls != nullptr;
    struct in_addr numeric_ipv4{};
    if (configured && ::inet_pton(AF_INET, endpoint.host.c_str(),
                                  &numeric_ipv4) == 1) {
        configured = X509_VERIFY_PARAM_set1_ip_asc(
            SSL_get0_param(tls), endpoint.host.c_str()) == 1;
    } else if (configured) {
        configured = SSL_set_tlsext_host_name(tls, endpoint.host.c_str()) == 1 &&
                     SSL_set1_host(tls, endpoint.host.c_str()) == 1;
    }
    if (configured) configured = SSL_set_fd(tls, fd) == 1;
    while (configured) {
        if (g_shutdown.load(std::memory_order_acquire) ||
            DesktopTlsClock::now() >= request_deadline) {
            setup_error = g_shutdown.load(std::memory_order_acquire)
                ? "TLS node request interrupted by shutdown"
                : "TLS node request total deadline exceeded";
            configured = false;
            break;
        }
        const int connected = SSL_connect(tls);
        if (connected == 1) break;
        const int error = SSL_get_error(tls, connected);
        if (error != SSL_ERROR_WANT_READ &&
            error != SSL_ERROR_WANT_WRITE) {
            configured = false;
            break;
        }
        const DesktopTlsWaitResult wait = desktop_tls_wait_ready(
            fd, error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT,
            request_deadline);
        if (wait != DesktopTlsWaitResult::READY) {
            setup_error = desktop_tls_wait_error(wait);
            configured = false;
            break;
        }
    }
    if (configured &&
        (g_shutdown.load(std::memory_order_acquire) ||
         DesktopTlsClock::now() >= request_deadline)) {
        setup_error = g_shutdown.load(std::memory_order_acquire)
            ? "TLS node request interrupted by shutdown"
            : "TLS node request total deadline exceeded";
        configured = false;
    }
    X509* peer = configured ? SSL_get1_peer_certificate(tls) : nullptr;
    configured = configured && peer != nullptr &&
                 SSL_get_verify_result(tls) == X509_V_OK;
    if (peer) X509_free(peer);
    if (!configured) {
        if (tls) SSL_free(tls);
        VELD_CLOSE_SOCKET(fd);
        SSL_CTX_free(context);
        return desktop_rpc_transport_error(
            setup_error ? setup_error :
                "TLS certificate or hostname verification failed");
    }

    std::string request = "POST / HTTP/1.0\r\nHost: " + endpoint.host + ":" +
        std::to_string(endpoint.port) +
        "\r\nAccept: application/json\r\nContent-Type: application/json\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n";
    if (endpoint.may_use_local_bearer && !auth_token.empty())
        request += "Authorization: Bearer " + auth_token + "\r\n";
    request += "Connection: close\r\n\r\n" + body;
    size_t sent = 0;
    short write_wait = POLLOUT;
    while (sent < request.size()) {
        const DesktopTlsWaitResult wait = desktop_tls_wait_ready(
            fd, write_wait, request_deadline);
        if (wait != DesktopTlsWaitResult::READY) {
            SSL_free(tls);
            VELD_CLOSE_SOCKET(fd);
            SSL_CTX_free(context);
            return desktop_rpc_transport_error(desktop_tls_wait_error(wait));
        }
        const int chunk = static_cast<int>(std::min(
            request.size() - sent,
            static_cast<size_t>(std::numeric_limits<int>::max())));
        const int wrote = SSL_write(tls, request.data() + sent, chunk);
        if (wrote > 0) {
            sent += static_cast<size_t>(wrote);
            write_wait = POLLOUT;
            continue;
        }
        const int error = SSL_get_error(tls, wrote);
        if (error == SSL_ERROR_WANT_READ ||
            error == SSL_ERROR_WANT_WRITE) {
            write_wait = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
            continue;
        } else {
            SSL_free(tls);
            VELD_CLOSE_SOCKET(fd);
            SSL_CTX_free(context);
            return desktop_rpc_transport_error("TLS node request failed");
        }
    }
    std::string response;
    char buffer[4096];
    constexpr size_t MAX_WIRE_RESPONSE = 64U * 1024U + 32U * 1024U * 1024U;
    short read_wait = POLLIN;
    const char* response_error = nullptr;
    for (;;) {
        if (SSL_pending(tls) == 0) {
            const DesktopTlsWaitResult wait = desktop_tls_wait_ready(
                fd, read_wait, request_deadline);
            if (wait != DesktopTlsWaitResult::READY) {
                response_error = desktop_tls_wait_error(wait);
                response.clear();
                break;
            }
        } else if (g_shutdown.load(std::memory_order_acquire) ||
                   DesktopTlsClock::now() >= request_deadline) {
            response_error = g_shutdown.load(std::memory_order_acquire)
                ? "TLS node request interrupted by shutdown"
                : "TLS node request total deadline exceeded";
            response.clear();
            break;
        }
        const int received = SSL_read(tls, buffer, sizeof(buffer));
        if (received > 0) {
            if (response.size() + static_cast<size_t>(received) >
                MAX_WIRE_RESPONSE) {
                response_error = "TLS node response too large";
                response.clear();
                break;
            }
            response.append(buffer, static_cast<size_t>(received));
            read_wait = POLLIN;
            continue;
        }
        const int error = SSL_get_error(tls, received);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
            read_wait = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
            continue;
        }
        // A TLS peer must close with authenticated close_notify.  Accepting an
        // abrupt EOF can turn a truncated response into a successful one when
        // no Content-Length was supplied.
        if (error != SSL_ERROR_ZERO_RETURN) {
            response_error = "TLS node response failed";
            response.clear();
        }
        break;
    }
    // close_notify is driven nonblocking and shares the same absolute budget.
    desktop_tls_shutdown(tls, fd, request_deadline);
    SSL_free(tls);
    VELD_CLOSE_SOCKET(fd);
    SSL_CTX_free(context);
    if (response.empty())
        return desktop_rpc_transport_error(
            response_error ? response_error : "TLS node response failed");
    return desktop_parse_tls_rpc_response(response);
}

static std::string proxy_rpc_https(const DesktopRpcEndpoint& endpoint,
                                   const std::string& body,
                                   const std::string& auth_token) {
    // Production callers receive one fixed absolute request budget.  Tests may
    // call the private _until primitive with a shorter deadline, without a
    // compile-time seam or any operator-controlled timeout override.
    return proxy_rpc_https_until(
        endpoint, body, auth_token,
        DesktopTlsClock::now() + DESKTOP_TLS_REQUEST_LIMIT);
}
#else
static std::string proxy_rpc_https(const DesktopRpcEndpoint& endpoint,
                                   const std::string& body,
                                   const std::string& auth_token) {
    (void)endpoint;
    (void)body;
    (void)auth_token;
    // A non-Windows package must explicitly opt into and link the reviewed
    // OpenSSL transport.  Until then, remote HTTPS fails closed; plaintext
    // remote HTTP remains rejected by parse_desktop_rpc_endpoint().
    return desktop_rpc_transport_error(
        "Authenticated HTTPS is unavailable in this client build");
}
#endif

static std::string proxy_rpc(const std::string& url, const std::string& body,
                               const std::string& auth_token = "") {
    DesktopRpcEndpoint endpoint;
    if (!parse_desktop_rpc_endpoint(url, endpoint))
        return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Invalid RPC endpoint\"},\"id\":null}";
    if (endpoint.secure) return proxy_rpc_https(endpoint, body, auth_token);
    const std::string& host = endpoint.host;
    const uint16_t port = endpoint.port;

    SocketHandle fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (!veld::compat::IsValidSocket(fd)) return "{\"error\":\"socket failed\"}";

#ifdef _WIN32
    DWORD tv = 30000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
    struct timeval tv{30,0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    // The distributable wallet's compiled default is a DNS name.  inet_pton
    // accepts only numeric literals and otherwise leaves 0.0.0.0 behind,
    // making the documented/default wallet mode silently unusable. Resolve
    // the configured IPv4 endpoint through the platform resolver first.
    struct addrinfo hints{}, *resolved = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    const std::string service = std::to_string(port);
    if (::getaddrinfo(host.c_str(), service.c_str(), &hints, &resolved) != 0 ||
        !resolved) {
        VELD_CLOSE_SOCKET(fd);
        return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Cannot resolve node\"},\"id\":null}";
    }
    const int connect_rc = ::connect(fd, resolved->ai_addr,
                                     (int)resolved->ai_addrlen);
    ::freeaddrinfo(resolved);
    if (connect_rc < 0) {
        VELD_CLOSE_SOCKET(fd);
        return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Cannot connect to node\"},\"id\":null}";
    }

    std::string req = "POST / HTTP/1.0\r\n"
        "Host: " + host + ":" + std::to_string(port) + "\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n";
    // A token loaded from ~/.veld-wallet is scoped to this machine.  Remote
    // wallet mode remains supported, but remote endpoints are always called
    // without silently exfiltrating that local bearer credential.
    if (endpoint.may_use_local_bearer && !auth_token.empty())
        req += "Authorization: Bearer " + auth_token + "\r\n";
    req += "Connection: close\r\n\r\n" + body;
    size_t sent = 0;
    while (sent < req.size()) {
        const int wrote = ::send(fd, req.data() + sent,
                                 (int)(req.size() - sent), 0);
        if (wrote <= 0) {
            VELD_CLOSE_SOCKET(fd);
            return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Node request failed\"},\"id\":null}";
        }
        sent += (size_t)wrote;
    }

    std::string resp;
    char buf[4096];
    int n;
    constexpr size_t MAX_PROXY_HEADERS = 64 * 1024;
    constexpr size_t MAX_PROXY_RESPONSE = 32 * 1024 * 1024;
    while ((n = ::recv(fd, buf, sizeof(buf)-1, 0)) > 0) {
        resp.append(buf, (size_t)n);
        if (resp.find("\r\n\r\n") != std::string::npos) break;
        if (resp.size() >= MAX_PROXY_HEADERS) {
            VELD_CLOSE_SOCKET(fd);
            return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Node response headers too large\"},\"id\":null}";
        }
    }
    size_t hdr_end = resp.find("\r\n\r\n");
    if (hdr_end == std::string::npos || hdr_end > MAX_PROXY_HEADERS) {
        VELD_CLOSE_SOCKET(fd);
        return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Malformed node response\"},\"id\":null}";
    }
    size_t body_start = hdr_end + 4;
    size_t content_length = 0;
    const DesktopHttpHeader response_cl =
        desktop_http_header(resp, hdr_end, "Content-Length");
    const DesktopHttpHeader response_te =
        desktop_http_header(resp, hdr_end, "Transfer-Encoding");
    if (response_cl.malformed || response_te.malformed || response_cl.duplicate ||
        response_te.present) {
        VELD_CLOSE_SOCKET(fd);
        return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Ambiguous node response framing\"},\"id\":null}";
    }
    if (response_cl.present) {
        if (response_cl.value.empty()) {
            VELD_CLOSE_SOCKET(fd);
            return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Malformed node response length\"},\"id\":null}";
        }
        for (char c : response_cl.value) {
            if (c < '0' || c > '9') {
                VELD_CLOSE_SOCKET(fd);
                return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Malformed node response length\"},\"id\":null}";
            }
            const size_t digit = (size_t)(c - '0');
            if (content_length > (MAX_PROXY_RESPONSE - digit) / 10) {
                VELD_CLOSE_SOCKET(fd);
                return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Node response too large\"},\"id\":null}";
            }
            content_length = content_length * 10 + digit;
        }
    }
    const size_t target = response_cl.present ? body_start + content_length : 0;
    while ((!response_cl.present || resp.size() < target) &&
           (n = ::recv(fd, buf, sizeof(buf), 0)) > 0) {
        if (resp.size() + (size_t)n > body_start + MAX_PROXY_RESPONSE) {
            VELD_CLOSE_SOCKET(fd);
            return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Node response too large\"},\"id\":null}";
        }
        resp.append(buf, (size_t)n);
    }
    if (response_cl.present && resp.size() != target) {
        // Extra bytes are also rejected: this proxy never pipelines requests,
        // so they can only represent ambiguous framing.
        VELD_CLOSE_SOCKET(fd);
        return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Truncated or overlong node response\"},\"id\":null}";
    }
    if (!response_cl.present && resp.size() > body_start + MAX_PROXY_RESPONSE) {
        VELD_CLOSE_SOCKET(fd);
        return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Node response too large\"},\"id\":null}";
    }
    VELD_CLOSE_SOCKET(fd);
    return resp.substr(body_start);
}

static std::string base64_decode(const std::string& in) {
    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[(unsigned char)chars[i]] = i;
    int val = 0, bits = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) continue;
        val = (val << 6) + T[c];
        bits += 6;
        if (bits >= 0) { out += (char)((val >> bits) & 0xFF); bits -= 8; }
    }
    return out;
}

static bool is_local_signer_bootstrap_token(const std::string& token) {
    return token.size() == 43 &&
        std::all_of(token.begin(), token.end(), [](unsigned char c) {
            return std::isalnum(c) || c == '-' || c == '_';
        });
}

static std::string new_local_signer_session_token() {
    uint8_t random[32]{};
    if (!veld::compat::SecureRandom(random, sizeof(random))) return {};
    static constexpr char hex[] = "0123456789abcdef";
    std::string token(sizeof(random) * 2, '0');
    for (size_t i = 0; i < sizeof(random); ++i) {
        token[i * 2] = hex[random[i] >> 4];
        token[i * 2 + 1] = hex[random[i] & 0x0f];
    }
    veld::compat::SecureZero(random, sizeof(random));
    return token;
}

class DesktopServer {
public:
    explicit DesktopServer(uint16_t port, RpcServer& rpc,
                           const std::string& rpc_url = "",
                           const std::string& rpc_token = "",
                           const std::string& datadir = "",
                           const std::string& local_signer_bootstrap_token = "")
        : port_(port), running_(false), fd_(veld::compat::kInvalidSocket), rpc_(&rpc),
          rpc_url_(rpc_url), rpc_token_(rpc_token), datadir_(datadir),
          local_signer_bootstrap_token_(local_signer_bootstrap_token),
          local_signer_session_token_(local_signer_bootstrap_token.empty()
              ? std::string{} : new_local_signer_session_token()) {}
    explicit DesktopServer(uint16_t port, const std::string& rpc_url,
                           const std::string& rpc_token = "",
                           const std::string& datadir = "",
                           const std::string& local_signer_bootstrap_token = "")
        : port_(port), running_(false), fd_(veld::compat::kInvalidSocket), rpc_(nullptr),
          rpc_url_(rpc_url), rpc_token_(rpc_token), datadir_(datadir),
          local_signer_bootstrap_token_(local_signer_bootstrap_token),
          local_signer_session_token_(local_signer_bootstrap_token.empty()
              ? std::string{} : new_local_signer_session_token()) {}

    bool ReloadRpcToken_() {
        if (datadir_.empty()) return false;
        DesktopRpcEndpoint endpoint;
        if (!parse_desktop_rpc_endpoint(rpc_url_, endpoint) ||
            !endpoint.may_use_local_bearer)
            return false;
        std::string tok = read_rpc_token_file(datadir_ + "/rpc.token");
        if (tok.empty()) return false;
        std::lock_guard<std::mutex> lk(token_mutex_);
        if (tok == rpc_token_) return false;
        rpc_token_ = tok;
        return true;
    }
    ~DesktopServer() {
        Stop();
        ClearLocalSignerTokens();
    }

    bool Start(const std::function<bool()>& activation_guard = {}) {
        activation_guard_refused_.store(false, std::memory_order_release);
        if (running_.load(std::memory_order_acquire) || thread_.joinable())
            return false;
        {
            std::lock_guard<std::mutex> lock(local_signer_mutex_);
            if (!local_signer_bootstrap_token_.empty() &&
                local_signer_session_token_.empty()) return false;
        }
        if (!veld::net::ListenerActivationPermitted(activation_guard)) {
            activation_guard_refused_.store(true, std::memory_order_release);
            return false;
        }
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (!veld::compat::IsValidSocket(fd_)) return false;
        int opt = 1;
#ifdef _WIN32
        // SO_REUSEADDR permits a second Windows process to bind the same local
        // endpoint and is therefore unsafe for a signer origin. Claim the
        // loopback wallet port exclusively or fail closed.
        if (::setsockopt(fd_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                (const char*)&opt, sizeof(opt)) != 0) {
            VELD_CLOSE_SOCKET(fd_);
            fd_ = veld::compat::kInvalidSocket;
            return false;
        }
#else
        if (::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR,
                (const char*)&opt, sizeof(opt)) != 0) {
            VELD_CLOSE_SOCKET(fd_);
            fd_ = veld::compat::kInvalidSocket;
            return false;
        }
#endif
        ::setsockopt(fd_, SOL_SOCKET, SO_KEEPALIVE, (const char*)&opt, sizeof(opt));
        struct sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port        = htons(port_);
        if (::bind(fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            VELD_CLOSE_SOCKET(fd_);
            fd_ = veld::compat::kInvalidSocket;
            return false;
        }
        if (!veld::net::ListenerActivationPermitted(activation_guard)) {
            activation_guard_refused_.store(true, std::memory_order_release);
            VELD_CLOSE_SOCKET(fd_);
            fd_ = veld::compat::kInvalidSocket;
            return false;
        }
        if (::listen(fd_, 16) < 0) {
            VELD_CLOSE_SOCKET(fd_);
            fd_ = veld::compat::kInvalidSocket;
            return false;
        }
        if (!veld::net::ListenerActivationPermitted(activation_guard)) {
            activation_guard_refused_.store(true, std::memory_order_release);
            VELD_CLOSE_SOCKET(fd_);
            fd_ = veld::compat::kInvalidSocket;
            return false;
        }
        running_ = true;
        try {
            thread_ = std::thread(&DesktopServer::Loop, this);
        } catch (...) {
            running_ = false;
            VELD_CLOSE_SOCKET(fd_);
            fd_ = veld::compat::kInvalidSocket;
            return false;
        }
        return true;
    }

    bool ActivationGuardRefused() const noexcept {
        return activation_guard_refused_.load(std::memory_order_acquire);
    }

    void Stop() {
        running_ = false;
        if (veld::compat::IsValidSocket(fd_)) {
#ifdef _WIN32
            ::shutdown((SOCKET)fd_, SD_BOTH);
#else
            ::shutdown(fd_, SHUT_RDWR);
#endif
            VELD_CLOSE_SOCKET(fd_);
        }
        if (thread_.joinable()) thread_.join();
        fd_ = veld::compat::kInvalidSocket;
        JoinConnectionWorkers();
    }

private:
    uint16_t          port_;
    std::atomic<bool> running_;
    std::atomic<bool> activation_guard_refused_{false};
    SocketHandle      fd_;
    std::thread       thread_;
    RpcServer*        rpc_;
    std::string       rpc_url_;
    std::string       rpc_token_;
    std::string       datadir_;
    mutable std::mutex token_mutex_;

    static constexpr int MAX_INFLIGHT_DESKTOP_CONNS = 128;
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

    struct RateBucket {
        uint32_t count{0};
        std::chrono::steady_clock::time_point window_start{std::chrono::steady_clock::now()};
    };
    mutable std::mutex rate_mutex_;
    std::unordered_map<std::string, RateBucket> rate_map_;
    mutable std::mutex local_signer_mutex_;
    std::string local_signer_bootstrap_token_;
    std::string local_signer_session_token_;

    bool LocalSignerCookieValid(const std::string& cookie) const {
        std::lock_guard<std::mutex> lock(local_signer_mutex_);
        return !local_signer_session_token_.empty() &&
            veld::compat::ConstantTimeEqual(
                cookie, local_signer_session_token_);
    }

    bool ConsumeLocalSignerBootstrap(const std::string& token) {
        std::lock_guard<std::mutex> lock(local_signer_mutex_);
        if (local_signer_bootstrap_token_.empty() ||
            local_signer_session_token_.empty() ||
            !veld::compat::ConstantTimeEqual(
                token, local_signer_bootstrap_token_)) return false;
        veld::compat::SecureZero(local_signer_bootstrap_token_.data(),
                                 local_signer_bootstrap_token_.size());
        local_signer_bootstrap_token_.clear();
        return true;
    }

    std::string LocalSignerSessionToken() const {
        std::lock_guard<std::mutex> lock(local_signer_mutex_);
        return local_signer_session_token_;
    }

    void ClearLocalSignerTokens() {
        std::lock_guard<std::mutex> lock(local_signer_mutex_);
        if (!local_signer_bootstrap_token_.empty())
            veld::compat::SecureZero(local_signer_bootstrap_token_.data(),
                                     local_signer_bootstrap_token_.size());
        if (!local_signer_session_token_.empty())
            veld::compat::SecureZero(local_signer_session_token_.data(),
                                     local_signer_session_token_.size());
        local_signer_bootstrap_token_.clear();
        local_signer_session_token_.clear();
    }

    void Loop() {
        while (running_) {
            ReapConnectionWorkers();
            struct sockaddr_in client{};
            socklen_t len = sizeof(client);
            SocketHandle cfd = ::accept(fd_, (struct sockaddr*)&client, &len);
            if (!veld::compat::IsValidSocket(cfd)) { if (running_) std::this_thread::sleep_for(std::chrono::milliseconds(10)); continue; }

            if (inflight_conns_.load(std::memory_order_acquire)
                >= MAX_INFLIGHT_DESKTOP_CONNS) {
                const char* busy =
                    "HTTP/1.1 503 Service Unavailable\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n";
                ::send(cfd, busy, (int)std::strlen(busy), 0);
                VELD_CLOSE_SOCKET(cfd);
                continue;
            }
#ifdef _WIN32
            DWORD to_ms = 15000;
            const bool timeouts_ok =
                ::setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO,
                             (const char*)&to_ms, sizeof(to_ms)) == 0 &&
                ::setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO,
                             (const char*)&to_ms, sizeof(to_ms)) == 0;
#else
            struct timeval tv{15, 0};
            const bool timeouts_ok =
                ::setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0 &&
                ::setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
#endif
            if (!timeouts_ok) {
                VELD_CLOSE_SOCKET(cfd);
                continue;
            }

            bool worker_started = false;
            try {
                inflight_conns_.fetch_add(1, std::memory_order_acq_rel);
                auto done = std::make_shared<std::atomic<bool>>(false);
                std::thread worker([this, cfd, done]() {
                    struct Guard {
                        std::atomic<int>* c;
                        std::atomic<bool>* done;
                        ~Guard(){
                            c->fetch_sub(1, std::memory_order_acq_rel);
                            done->store(true, std::memory_order_release);
                        }
                    } g{&inflight_conns_, done.get()};
                    try { Handle(cfd); }
                    catch (...) { VELD_CLOSE_SOCKET(cfd); }
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
                std::cerr << "  [desktop] thread spawn failed (" << e.what()
                          << ") — dropping request, fd=" << cfd << "\n";
                std::cerr.flush();
                if (!worker_started) VELD_CLOSE_SOCKET(cfd);
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            } catch (const std::exception& e) {
                if (!worker_started)
                    inflight_conns_.fetch_sub(1, std::memory_order_acq_rel);
                std::cerr << "  [desktop] unexpected thread-spawn error: "
                          << e.what() << "\n";
                std::cerr.flush();
                if (!worker_started) VELD_CLOSE_SOCKET(cfd);
            }
        }
        ReapConnectionWorkers();
    }

    void Handle(SocketHandle cfd) {
        int ka = 1;
        ::setsockopt(cfd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&ka, sizeof(ka));
        struct sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        bool is_local = true;
        std::string remote_ip = "127.0.0.1";
        if (::getpeername(cfd, (struct sockaddr*)&peer, &plen) == 0) {
            char ipbuf[INET_ADDRSTRLEN] = {};
            ::inet_ntop(AF_INET, &peer.sin_addr, ipbuf, sizeof(ipbuf));
            remote_ip = ipbuf;
            uint32_t ip = ntohl(peer.sin_addr.s_addr);
            is_local = ((ip >> 24) == 127);
        }

#ifdef _WIN32
        DWORD tv_ms = 5000;
        ::setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_ms, sizeof(tv_ms));
#else
        struct timeval tv; tv.tv_sec = 5; tv.tv_usec = 0;
        ::setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
        char buf[65536] = {};
        int n = ::recv(cfd, buf, sizeof(buf)-1, 0);
        if (n <= 0) { VELD_CLOSE_SOCKET(cfd); return; }
        std::string raw(buf, n);
        auto reject_http = [&](const char* status) {
            const std::string err = std::string("HTTP/1.1 ") + status +
                "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            ::send(cfd, err.data(), (int)err.size(), 0);
            VELD_CLOSE_SOCKET(cfd);
        };
        constexpr size_t MAX_HEADERS = 64 * 1024;
        size_t hdr_end = raw.find("\r\n\r\n");
        while (hdr_end == std::string::npos && raw.size() < MAX_HEADERS) {
            char more[4096];
            const size_t room = MAX_HEADERS - raw.size();
            const int got = ::recv(cfd, more, (int)std::min(room, sizeof(more)), 0);
            if (got <= 0) break;
            raw.append(more, (size_t)got);
            hdr_end = raw.find("\r\n\r\n");
        }
        if (hdr_end == std::string::npos) { reject_http("400 Bad Request"); return; }

        std::string method, path, http_version, request_extra;
        auto line_end = raw.find("\r\n");
        if (line_end == std::string::npos || line_end > hdr_end) {
            reject_http("400 Bad Request"); return;
        }
        std::istringstream ls(raw.substr(0, line_end));
        if (!(ls >> method >> path >> http_version) || (ls >> request_extra) ||
            (http_version != "HTTP/1.0" && http_version != "HTTP/1.1") ||
            path.empty() || path[0] != '/') {
            reject_http("400 Bad Request"); return;
        }
        std::string raw_query;
        auto q = path.find('?');
        if (q != std::string::npos) {
            raw_query = path.substr(q + 1);
            path = path.substr(0, q);
        }

        const DesktopHttpHeader host_h = desktop_http_header(raw, hdr_end, "Host");
        const DesktopHttpHeader cl_h = desktop_http_header(raw, hdr_end, "Content-Length");
        const DesktopHttpHeader te_h = desktop_http_header(raw, hdr_end, "Transfer-Encoding");
        const DesktopHttpHeader xri_h = desktop_http_header(raw, hdr_end, "X-Real-IP");
        const DesktopHttpHeader origin_h = desktop_http_header(raw, hdr_end, "Origin");
        const DesktopHttpHeader ct_h = desktop_http_header(raw, hdr_end, "Content-Type");
        const DesktopHttpHeader sfs_h = desktop_http_header(raw, hdr_end, "Sec-Fetch-Site");
        const DesktopHttpHeader cookie_h = desktop_http_header(raw, hdr_end, "Cookie");
        if (host_h.malformed || cl_h.malformed || te_h.malformed || xri_h.malformed ||
            origin_h.malformed || ct_h.malformed || sfs_h.malformed ||
            cookie_h.malformed ||
            !host_h.present || host_h.duplicate || cl_h.duplicate || te_h.duplicate ||
            xri_h.duplicate || origin_h.duplicate || ct_h.duplicate || sfs_h.duplicate ||
            cookie_h.duplicate || te_h.present) {
            reject_http("400 Bad Request"); return;
        }

        std::string host = host_h.value;
        for (char& c : host) c = (char)std::tolower((unsigned char)c);
        const std::string local_host_v4 = "127.0.0.1:" + std::to_string(port_);
        const std::string local_host_name = "localhost:" + std::to_string(port_);
        const bool exact_local_wallet_host = host == local_host_v4 ||
            host == local_host_name ||
            (port_ == 80 && (host == "127.0.0.1" || host == "localhost"));
        // The hosted wallet hostnames are accepted on every profile. Excluding
        // them for the testnet is what made
        // wallet.veld.network answer 421 once its backend was finally running:
        // nginx forwards the real Host, and the guard rejected it.
        // DNS-rebinding protection is unchanged -- this remains an exact
        // allowlist of loopback plus the two operator-owned names.
        const bool allowed_host = host == local_host_v4 || host == local_host_name ||
            (port_ == 80 && (host == "127.0.0.1" || host == "localhost")) ||
            host == "wallet.veld.network" || host == "wallet.veld.network:443" ||
            host == "veld.network" || host == "veld.network:443";
        if (!allowed_host) { reject_http("421 Misdirected Request"); return; }

        // A loopback reverse proxy obscures the actual socket peer.  Parse its
        // source header before rate limiting or body allocation, and never
        // allow any asserted value to retain local privilege.
        if (xri_h.present) {
            is_local = false;
            struct in_addr v4{};
            struct in6_addr v6{};
            if (xri_h.value.size() <= INET6_ADDRSTRLEN &&
                (::inet_pton(AF_INET, xri_h.value.c_str(), &v4) == 1 ||
                 ::inet_pton(AF_INET6, xri_h.value.c_str(), &v6) == 1))
                remote_ip = xri_h.value;
            else
                remote_ip = "invalid-proxy-source";
        }

        const std::string local_origin_v4 =
            "http://127.0.0.1:" + std::to_string(port_);
        const std::string local_origin_name =
            "http://localhost:" + std::to_string(port_);
        const bool exact_local_ui_origin = origin_h.present &&
            (origin_h.value == local_origin_v4 || origin_h.value == local_origin_name);
        if (origin_h.present && !exact_local_ui_origin) is_local = false;
        // This is a signing boundary, not a display hint. A loopback socket and
        // exact Host are necessary but not sufficient: signer authority also
        // requires the fresh launch capability handed to this process by the
        // signed Veld Node GUI. This prevents a process already occupying the
        // wallet port from being mistaken for the trusted signer.
        const bool trusted_local_socket =
            is_local && !xri_h.present && exact_local_wallet_host;
        std::string signer_cookie;
        bool signer_cookie_seen = false;
        bool duplicate_signer_cookie = false;
        if (cookie_h.present) {
            size_t start = 0;
            while (start <= cookie_h.value.size()) {
                size_t end = cookie_h.value.find(';', start);
                if (end == std::string::npos) end = cookie_h.value.size();
                std::string field = cookie_h.value.substr(start, end - start);
                while (!field.empty() && (field.front() == ' ' || field.front() == '\t'))
                    field.erase(field.begin());
                while (!field.empty() && (field.back() == ' ' || field.back() == '\t'))
                    field.pop_back();
                const size_t equals = field.find('=');
                if (equals != std::string::npos &&
                    field.substr(0, equals) == "veld_local_signer") {
                    if (signer_cookie_seen) duplicate_signer_cookie = true;
                    signer_cookie_seen = true;
                    signer_cookie = field.substr(equals + 1);
                }
                if (end == cookie_h.value.size()) break;
                start = end + 1;
            }
        }
        const bool signer_cookie_valid = !duplicate_signer_cookie &&
            LocalSignerCookieValid(signer_cookie);
        const std::string signer_prefix = "signer=";
        const bool signer_query_present = path == "/" &&
            raw_query.rfind(signer_prefix, 0) == 0;
        const std::string signer_query = signer_query_present
            ? raw_query.substr(signer_prefix.size()) : std::string{};
        const bool signer_bootstrap = method == "GET" && trusted_local_socket &&
            signer_query_present && ConsumeLocalSignerBootstrap(signer_query);
        if (signer_query_present && !signer_bootstrap) {
            reject_http("403 Forbidden");
            return;
        }
        const bool trusted_local_wallet =
            trusted_local_socket && signer_cookie_valid;
        // The public wallet remains a self-custody application: its exact
        // HTTPS origin may load the in-browser ML-DSA signer, while arbitrary
        // loopback pages and the marketing origin may not.  X-Real-IP is set
        // by the wallet nginx vhost and also forces `is_local` false above, so
        // this grant never inherits local-only RPC authority.
        const bool hosted_self_custody_wallet = xri_h.present &&
            (host == "wallet.veld.network" ||
             host == "wallet.veld.network:443");
        const bool browser_self_custody_wallet =
            trusted_local_wallet || hosted_self_custody_wallet;

        bool rate_allowed = true;
        {
            std::lock_guard<std::mutex> rl(rate_mutex_);
            auto now = std::chrono::steady_clock::now();
            static constexpr size_t kMaxDesktopRateEntries = 10'000;
            if (rate_map_.size() >= kMaxDesktopRateEntries) {
                for (auto it = rate_map_.begin(); it != rate_map_.end(); ) {
                    if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second.window_start).count() > 120)
                        it = rate_map_.erase(it);
                    else ++it;
                }
            }
            auto entry_it = rate_map_.find(remote_ip);
            if (entry_it == rate_map_.end() &&
                rate_map_.size() >= kMaxDesktopRateEntries) {
                rate_allowed = false;
            } else {
                auto& entry = entry_it == rate_map_.end()
                    ? rate_map_.emplace(remote_ip, RateBucket{}).first->second
                    : entry_it->second;
                if (std::chrono::duration_cast<std::chrono::seconds>(
                        now - entry.window_start).count() >= 60) {
                    entry.count = 0;
                    entry.window_start = now;
                }
                // A single household can legitimately have several installed
                // wallets polling through one public address. Keep the bucket
                // bounded, but size it for concurrent desktop, phone and tablet
                // sessions instead of treating normal polling as abuse.
                if (++entry.count > 1200 && !is_local)
                    rate_allowed = false;
            }
        }
        if (!rate_allowed) {
            const std::string limited =
                "HTTP/1.1 429 Too Many Requests\r\n"
                "Content-Length: 0\r\n"
                "Retry-After: 10\r\n"
                "Cache-Control: no-store\r\n"
                "Connection: close\r\n\r\n";
            ::send(cfd, limited.data(), (int)limited.size(), 0);
            VELD_CLOSE_SOCKET(cfd);
            return;
        }

        // Reject hostile browser metadata before accepting a potentially
        // 16-MiB PQ transaction body.  This closes the localhost allocation
        // DoS as well as the privileged RPC/CSRF path in browsers that omit
        // Sec-Fetch-Site.
        if (method == "POST" && path != "/rpc") {
            reject_http("405 Method Not Allowed"); return;
        }
        if (path == "/rpc") {
            if (method != "POST" && method != "OPTIONS") {
                reject_http("405 Method Not Allowed"); return;
            }
            if (method == "POST") {
                std::string content_type = ct_h.value;
                const size_t semi = content_type.find(';');
                if (semi != std::string::npos) content_type.resize(semi);
                while (!content_type.empty() &&
                       (content_type.back() == ' ' || content_type.back() == '\t'))
                    content_type.pop_back();
                for (char& c : content_type)
                    c = (char)std::tolower((unsigned char)c);
                // Accepted on EVERY profile.  The public testnet wallet is
                // served from these exact hosts too, so gating them off left the
                // browser's own same-origin POST /rpc answered 403 while curl
                // (which sends no Origin) succeeded -- the wallet sat on
                // "Connecting..." forever.  This is an origin allow-list, not a
                // capability grant: the chain's valuelessness is enforced in
                // consensus, and the wallet RPC allow-list is unchanged.
                const bool allowed_origin = !origin_h.present ||
                    exact_local_ui_origin ||
                    origin_h.value == "https://wallet.veld.network" ||
                    origin_h.value == "https://veld.network";
                std::string fetch_site = sfs_h.value;
                for (char& c : fetch_site) c = (char)std::tolower((unsigned char)c);
                if (content_type != "application/json") {
                    reject_http("415 Unsupported Media Type"); return;
                }
                if (!allowed_origin || (sfs_h.present && fetch_site != "same-origin" &&
                                        fetch_site != "none")) {
                    reject_http("403 Forbidden"); return;
                }
            }
        }

        constexpr size_t MAX_BODY = 16 * 1024 * 1024 + 4096;
        size_t content_length = 0;
        if (cl_h.present) {
            if (cl_h.value.empty()) { reject_http("400 Bad Request"); return; }
            for (char c : cl_h.value) {
                if (c < '0' || c > '9') { reject_http("400 Bad Request"); return; }
                const size_t digit = (size_t)(c - '0');
                if (content_length > (MAX_BODY - digit) / 10) {
                    reject_http("413 Payload Too Large"); return;
                }
                content_length = content_length * 10 + digit;
            }
        } else if (method == "POST") {
            reject_http("411 Length Required"); return;
        }
        if (content_length > MAX_BODY) { reject_http("413 Payload Too Large"); return; }
        if (method != "POST" && content_length != 0) {
            reject_http("400 Bad Request"); return;
        }

        const size_t body_start = hdr_end + 4;
        const size_t expected_size = body_start + content_length;
        if (raw.size() > expected_size) { reject_http("400 Bad Request"); return; }
        while (raw.size() < expected_size) {
            char buf2[4096];
            const size_t remaining = expected_size - raw.size();
            const int n2 = ::recv(cfd, buf2, (int)std::min(remaining, sizeof(buf2)), 0);
            if (n2 <= 0) { VELD_CLOSE_SOCKET(cfd); return; }
            raw.append(buf2, (size_t)n2);
        }
        const std::string body = raw.substr(body_start, content_length);

        std::string cors =
            // Matches the origin allow-list above on every profile; the
            // testnet build previously sent "null" here, which the browser
            // treats as a mismatch for its own origin.
            "Access-Control-Allow-Origin: https://wallet.veld.network\r\n"
            "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type\r\n"
            "X-Content-Type-Options: nosniff\r\n"
            "Referrer-Policy: no-referrer\r\n"
            "X-Frame-Options: DENY\r\n"
            "Cross-Origin-Opener-Policy: same-origin\r\n"
            "Cross-Origin-Resource-Policy: same-origin\r\n"
            "Permissions-Policy: camera=(self), geolocation=(), microphone=(), payment=(), usb=()\r\n"
            "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
;

        auto build_csp_for_html = [](const std::string& nonce) -> std::string {
            return std::string("Content-Security-Policy: default-src 'self'; ")
                 + "script-src 'self' 'wasm-unsafe-eval' 'nonce-" + nonce + "'; "
                 + "style-src 'self' 'unsafe-inline'; "
                 + "img-src 'self' data:; "
#ifdef VELD_PUBLIC_TESTNET
                 + "connect-src 'self'; "
#else
                 + "connect-src 'self' wss://wallet.veld.network; "
#endif
                 + "object-src 'none'; "
                 + "frame-src 'none'; "
                 + "frame-ancestors 'none'; "
                 + "form-action 'none'; "
                 + "worker-src 'self'; "
                 + "manifest-src 'self'; "
                 + "base-uri 'none'\r\n";
        };
        auto make_nonce = []() -> std::string {
            uint8_t nbuf[16];
            if (!veld::compat::SecureRandom(nbuf, sizeof(nbuf))) return "";
            static const char* hex = "0123456789abcdef";
            std::string n; n.reserve(32);
            for (size_t i = 0; i < sizeof(nbuf); ++i) {
                n.push_back(hex[nbuf[i] >> 4]);
                n.push_back(hex[nbuf[i] & 0xF]);
            }
            return n;
        };
        auto subst_nonce = [](std::string s, const std::string& nonce) {
            const std::string tag = "__CSP_NONCE__";
            size_t pos = 0;
            while ((pos = s.find(tag, pos)) != std::string::npos) {
                s.replace(pos, tag.size(), nonce);
                pos += nonce.size();
            }
            return s;
        };

        std::string resp;
        if (signer_bootstrap) {
            const std::string signer_session = LocalSignerSessionToken();
            resp = "HTTP/1.1 303 See Other\r\nLocation: /\r\n"
                 + cors
                 + "Set-Cookie: veld_local_signer=" + signer_session
                 + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200\r\n"
                   "Cache-Control: no-store\r\nContent-Length: 0\r\n\r\n";
        } else if (method == "OPTIONS") {
            resp = "HTTP/1.1 200 OK\r\n" + cors + "Content-Length: 0\r\n\r\n";
        } else if (path == "/" || path.empty()) {
            std::string html = DESKTOP_HTML;
            {
                auto pos = html.find("var RPC_URL = ");
                if (pos != std::string::npos) {
                    auto end = html.find(";", pos);
                    if (end != std::string::npos)
                        html = html.substr(0, pos) + "var RPC_URL = '/rpc'" + html.substr(end);
                }
            }
            {
                // Inject the build's genesis hash + network byte so the client
                // computes sighashes with the exact domain-separation constants
                // this node validates against (drift-proof: same constants.h;
                // cutover-proof: a redeploy carries the new genesis).
                auto subst_all = [&](const char* tag, const std::string& val) {
                    size_t p = 0; const size_t tn = std::strlen(tag);
                    while ((p = html.find(tag, p)) != std::string::npos) { html.replace(p, tn, val); p += val.size(); }
                };
                subst_all("__VELD_GENESIS_HASH__", std::string(GENESIS_HASH));
                subst_all("__VELD_DEPLOYMENT_ROLE__", std::string(DEPLOYMENT_ROLE));
                subst_all("__VELD_DEPLOYMENT_PROFILE_ID__", std::string(DEPLOYMENT_PROFILE_ID));
                subst_all("__VELD_DEPLOYMENT_DISPLAY_NAME__", std::string(DEPLOYMENT_DISPLAY_NAME));
                subst_all("__VELD_DEPLOYMENT_DISPOSABLE__", DEPLOYMENT_DISPOSABLE ? "true" : "false");
                subst_all("__VELD_DEPLOYMENT_EXTERNAL_VALUE__", DEPLOYMENT_EXTERNAL_VALUE ? "true" : "false");
                subst_all("__VELD_TRUSTED_LOCAL_SIGNER__",
                          trusted_local_wallet ? "true" : "false");
                subst_all("__VELD_BROWSER_SELF_CUSTODY__",
                          browser_self_custody_wallet ? "true" : "false");
                subst_all("__VELD_SIGNER_SCRIPT_TAG__",
                          browser_self_custody_wallet
                              ? "<script src=\"/dilithium.js\"></script>"
                              : "");
                subst_all("__VELD_WALLET_UI_PORT__", std::to_string(port_));
                // Deployment identity is carried by version metadata, launcher
                // startup output, and signed package evidence. The wallet does
                // not duplicate that status as a persistent page banner.
                subst_all("__VELD_DEPLOYMENT_BANNER_HTML__", "");
                subst_all("__VELD_MIN_TX_FEE_UNITS__", std::to_string(MIN_TX_FEE));
                subst_all("__VELD_DUST_THRESHOLD_UNITS__", std::to_string(DUST_THRESHOLD_UNITS));
                subst_all("__VELD_MIN_VALIDATOR_STAKE_UNITS__", std::to_string(MIN_VALIDATOR_STAKE));
                subst_all("__VELD_STAKE_VAULT_ADDRESS__", std::string(STAKE_VAULT_ADDRESS));
                subst_all("__VELD_AMM_MARKET_SEED_ANCHOR_ACTIVE__",
                          AmmLedger::MarketSeedAnchorActive(1)
                              ? "true" : "false");
#ifdef VELD_MAINNET_POW
                subst_all("__VELD_NETWORK_BYTE__", "0x4D");
                subst_all("__VELD_ADDRESS_VERSION__", "0x46");
#else
                subst_all("__VELD_NETWORK_BYTE__", "0x54");
                subst_all("__VELD_ADDRESS_VERSION__", "0x6F");
#endif
            }
            std::string nonce_ = make_nonce();
            if (nonce_.empty()) {
                resp = "HTTP/1.1 500 Internal Server Error\r\n" + cors
                     + "Content-Length: 0\r\nConnection: close\r\n\r\n";
            } else {
                html = subst_nonce(std::move(html), nonce_);
                resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                     + cors + build_csp_for_html(nonce_)
                     + "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                     + "Pragma: no-cache\r\n"
                     + "Expires: 0\r\n"
                     + "Content-Length: " + std::to_string(html.size()) + "\r\n\r\n" + html;
            }
        } else if (path == "/rpc") {
            std::string rpc_cors;
            {
                rpc_cors = cors;
#ifndef VELD_PUBLIC_TESTNET
                const std::string old_acao =
                    "Access-Control-Allow-Origin: https://wallet.veld.network\r\n";
                size_t p = rpc_cors.find(old_acao);
                if (p != std::string::npos) {
                    rpc_cors.replace(p, old_acao.size(),
                                     "Access-Control-Allow-Origin: null\r\n");
                }
#endif
            }
            std::string result;
            if (body.empty()) {
                result = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,\"message\":\"Empty\"},\"id\":null}";
            } else {
                // ── SECURITY : CSRF defenses on POST /rpc ──
                // Prior code accepted any Content-Type, any Origin, and extracted
                // the method name with a literal-colon substring search that a
                // single JSON whitespace defeats ({"method" : "x"}). Combined
                // with the deny-list gate below, a browser tab visiting any
                // untrusted page could POST cross-origin with Content-Type:
                // text/plain (simple-request, no CORS preflight) and drive
                // privileged RPC calls through the operator's bearer token.
                //
                // Accept POST /rpc only when all of the following hold:
                //   (1) Content-Type is exactly application/json (forces
                //       browsers to send a CORS preflight that our OPTIONS
                //       handler answers restrictively).
                //   (2) Sec-Fetch-Site is `same-origin` or `none` (same-origin
                //       proves the request originated from wallet UI itself,
                //       `none` is Chromium's value for non-browser-initiated
                //       requests like curl — we keep those working).
                //   (3) Origin, if present, is one of our allowed origins.
                //       (Origin is set by browsers; curl omits it.)
                // This blocks every known browser-based CSRF pattern. Non-
                // browser local callers (veld-distribute and operator scripts)
                // still work because they don't set Origin or
                // Sec-Fetch-Site, and they use Content-Type: application/json.
                if (method == "POST") {
                    auto header_lower = [&](const char* name) -> std::string {
                        std::string lname = name;
                        auto lraw = raw;
                        size_t start = 0;
                        size_t body_sep = lraw.find("\r\n\r\n");
                        size_t scan_end = (body_sep == std::string::npos) ? lraw.size() : body_sep;
                        while (start < scan_end) {
                            size_t eol = lraw.find("\r\n", start);
                            if (eol == std::string::npos || eol > scan_end) eol = scan_end;
                            size_t name_len = lname.size();
                            if (eol > start + name_len + 1 &&
                                lraw[start + name_len] == ':') {
                                bool match = true;
                                for (size_t i = 0; i < name_len; ++i) {
                                    char a = (char)std::tolower((unsigned char)lraw[start + i]);
                                    char b = (char)std::tolower((unsigned char)lname[i]);
                                    if (a != b) { match = false; break; }
                                }
                                if (match) {
                                    size_t v = start + name_len + 1;
                                    while (v < eol && (lraw[v] == ' ' || lraw[v] == '\t')) ++v;
                                    return lraw.substr(v, eol - v);
                                }
                            }
                            start = eol + 2;
                        }
                        return "";
                    };

                    std::string ct = header_lower("Content-Type");
                    size_t semi = ct.find(';');
                    if (semi != std::string::npos) ct = ct.substr(0, semi);
                    while (!ct.empty() && (ct.back() == ' ' || ct.back() == '\t'))
                        ct.pop_back();
                    std::string ct_lower = ct;
                    for (auto& c : ct_lower) c = (char)std::tolower((unsigned char)c);
                    if (ct_lower != "application/json") {
                        std::string err = "HTTP/1.1 415 Unsupported Media Type\r\n"
                                         + rpc_cors +
                                         "Content-Type: application/json\r\n"
                                         "Content-Length: 87\r\n\r\n"
                                         "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,"
                                         "\"message\":\"application/json required\"},\"id\":null}";
                        ::send(cfd, err.data(), (int)err.size(), 0);
                        VELD_CLOSE_SOCKET(cfd);
                        return;
                    }

                    std::string sfs = header_lower("Sec-Fetch-Site");
                    if (!sfs.empty() && sfs != "same-origin" && sfs != "none") {
                        std::string err = "HTTP/1.1 403 Forbidden\r\n"
                                         + rpc_cors +
                                         "Content-Type: application/json\r\n"
                                         "Content-Length: 78\r\n\r\n"
                                         "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,"
                                         "\"message\":\"cross-site blocked\"},\"id\":null}";
                        ::send(cfd, err.data(), (int)err.size(), 0);
                        VELD_CLOSE_SOCKET(cfd);
                        return;
                    }

                    std::string origin = header_lower("Origin");
                    if (!origin.empty()) {
                        const std::string local_origin_v4 =
                            "http://127.0.0.1:" + std::to_string(port_);
                        const std::string local_origin_name =
                            "http://localhost:" + std::to_string(port_);
                        const bool exact_local_ui_origin =
                            origin == local_origin_v4 || origin == local_origin_name;
                        // A hosted page reaches this server through a loopback
                        // reverse proxy (and older browsers may omit
                        // Sec-Fetch-Site).  Treat every browser origin except
                        // this exact local UI instance as remote authority.
                        if (!exact_local_ui_origin) is_local = false;
                        // Same allow-list as the generic HTTP guard above, and
                        // for the same reason: the hosted testnet wallet is
                        // served from these origins, so gating them off made
                        // the page's own POST /rpc fail "origin blocked" while
                        // a curl with no Origin header succeeded.  Remote
                        // authority is still reduced (is_local is false above)
                        // and REMOTE_ALLOWED_METHODS still bounds what a hosted
                        // origin may call.
                        bool allowed_origin =
                            origin == "https://wallet.veld.network" ||
                            origin == "https://veld.network" ||
                            exact_local_ui_origin;
                        if (!allowed_origin) {
                            std::string err = "HTTP/1.1 403 Forbidden\r\n"
                                             + rpc_cors +
                                             "Content-Type: application/json\r\n"
                                             "Content-Length: 75\r\n\r\n"
                                             "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,"
                                             "\"message\":\"origin blocked\"},\"id\":null}";
                            ::send(cfd, err.data(), (int)err.size(), 0);
                            VELD_CLOSE_SOCKET(cfd);
                            return;
                        }
                    }
                }

                // ── SECURITY : POSITIVE allow-list ──
                // Prior code was a deny-list — anything not explicitly blocked
                // was callable remotely. That silently exposed sendrawtransaction,
                // submitblock, submitproposal, vote, flushpools, endorseblock,
                // and any future method the maintainer didn't think
                // to block. Flipped to a strict allow-list of read-only + a few
                // narrowly-safe write methods. Local browser traffic obeys
                // the same list; removed chain-wide history and earnings
                // scanners have no local exception.
                // Operator tools that need node-admin RPC must use
                // the authenticated node RPC port, not this browser gateway.
                //
                // Parse method names with RFC-8259 whitespace handling instead
                // of relying on a whitespace-sensitive literal search.
                // state machine that tolerates any RFC-8259 whitespace between
                // the key, colon, and value.
                // Use one method allow-list for every profile. The
                // testnet build previously exposed only three read methods,
                // so the hosted wallet could render a dashboard but could not
                // show history, list UTXOs, or send anything -- it looked
                // broken because it effectively was.  Nothing here holds a
                // server-side key: every write is a client-signed payload
                // submitted via sendrawtransaction, and the testnet chain's
                // valuelessness is enforced in consensus, not by hiding RPCs.
                static const std::vector<std::string> REMOTE_ALLOWED_METHODS = {
                    "getblockchaininfo", "getblock", "getblockbyheight",
                    "getblockfull",
                    "getblockhash", "getbestblockhash",
                    "getcompiledgenesis", "estimatefee",
                    "gettransaction", "gettransactionrecent",
                    "getrawtransaction", "gettxout", "getmempoolinfo",
                    "getrawmempool", "getmempoolentry",
                    "getbalance", "getaddressbalance",
                    "getblockcount", "gettips", "getchaintips",
                    "getpeerinfo", "getnetworkinfo", "getminerinfo", "getmininginfo",
                    "getvaultinfo", "getbondvaultinfo",
                    "getvalidators", "getvalidatorinfo",
                    "getvalidatorhistory",
                    "getstakers", "getstakinginfo", "getstakesforaddress",
                    "getstake", "getstakehistory", "getlockuptiers",
                    "gettierstatus",
                    "getpoolstats", "getpoolinfo",
                    "getnmstally", "getcomineinfo",
                    "getendorsementinfo", "listproposals", "getproposals", "getproposal",
                    "getgovernanceinfo", "governancestats",
                    "gettokeninfo", "listtokens", "gettokenbalance",
                    "gettokenholders", "gettokensforaddress",
                    // read-only token event log — the Activity tab's btcVELD filter
                    // (mints/redeems/transfers for an address). Without this the
                    // proxy rejected the call and the tab silently showed empty.
                    "gettokenhistory",
                    // btcVELD peg (wrap/redeem) + on-chain AMM — read side.
                    "getpeginfo", "getbtcveldsupply", "getbtcveldredeems",
                    "getammpool", "getammlp",
                    "listunspent", "getaddressfrompubkey",
                    // Recipient-address checking in the Send tab.  This lived
                    // only in the old testnet-only list, so unifying the two
                    // lists would have dropped it from every profile.
                    "validateaddress",
                    "getuptime", "getversion", "getnodeinfo",
                    // Write methods that do NOT involve server-held keys —
                    // the signed payload is built client-side in the wallet
                    // UI and submitted for broadcast. The "prepare*" methods
                    // build unsigned TX templates; the client signs and
                    // returns via sendrawtransaction.
                    "sendrawtransaction",
                    "preparestaketx", "preparenmstx", "preparetokentx",
                    "preparetokentransfer", "prepareregistertx",
                    "preparederegistertx", "prepareproposaltx", "preparevotetx",
                    "preparerawtransaction", "preparestake", "prepareunstake",
                    "preparegovproposal", "preparegovvote",
                    "prepareregistervalidator", "preparederegistervalidator",
                    "rebroadcasttx", "getminerstatus", "getdustutxocount",
                    "prepareconsolidatetx",
                    // btcVELD peg + AMM — client-signed build methods (server holds
                    // no key; the wallet re-verifies + signs the unsigned tx, then
                    // submits via sendrawtransaction — same trust model as prepare*).
                    "preparetokenredeem",
                    "prepareammswap", "prepareammadd", "prepareammremove", "prepareammseed",
                    "getmisbehavior",
                };

                std::string called = veld::rpc_proxy::ExtractMethodFromJson(body);
                bool method_ok = false;
                for (auto& allowed : REMOTE_ALLOWED_METHODS) {
                    if (called == allowed) { method_ok = true; break; }
                }
                if (!method_ok) {
                    result = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,"
                             "\"message\":\"Method not in wallet allow-list\"},\"id\":null}";
                    goto send_rpc_resp;
                }
                if (!rpc_url_.empty()) {
                    std::string token_snapshot;
                    {
                        std::lock_guard<std::mutex> lk(token_mutex_);
                        token_snapshot = rpc_token_;
                    }
                    result = proxy_rpc(rpc_url_, body, token_snapshot);
                    if (result.find("\"code\":-32001") != std::string::npos
                        && result.find("Unauthorized") != std::string::npos) {
                        if (ReloadRpcToken_()) {
                            std::string new_tok;
                            {
                                std::lock_guard<std::mutex> lk(token_mutex_);
                                new_tok = rpc_token_;
                            }
                            result = proxy_rpc(rpc_url_, body, new_tok);
                        }
                    }
                } else {
                    result = rpc_->Handle(body);
                }
                send_rpc_resp:;
            }
            resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                 + rpc_cors + "Content-Length: " + std::to_string(result.size()) + "\r\n\r\n" + result;
        } else if (path == "/manifest.json") {
            std::string manifest = R"({
  "id": "/",
  "name": "Veld Wallet",
  "short_name": "VELD",
  "description": "Veld peer-to-peer cryptocurrency wallet",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "background_color": "#070B08",
  "theme_color": "#070B08",
  "orientation": "portrait-primary",
  "icons": [
    {"src": "/icon-192.png?v=20260819veldgradient1", "sizes": "192x192", "type": "image/png", "purpose": "any"},
    {"src": "/icon-512.png?v=20260819veldgradient1", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"}
  ],
  "categories": ["finance"],
  "lang": "en"
})";
            resp = "HTTP/1.1 200 OK\r\nContent-Type: application/manifest+json\r\n"
                 + cors + "Content-Length: " + std::to_string(manifest.size()) + "\r\n\r\n" + manifest;
        } else if (path == "/sw.js") {
            #ifndef VELD_BUILD_ID
            #define VELD_BUILD_ID "dev"
            #endif
            // The cache key must change whenever the served wallet changes.
            // Keying it on VELD_BUILD_ID alone meant every rebuild of the same
            // version reused one name, so a browser that had cached a broken
            // wallet kept serving it forever and never refetched -- a fix could
            // be live and still invisible.  Hash the actual UI template: stable
            // for identical content (reproducible builds keep matching) and
            // different the moment the page changes.
            static const std::string ui_revision = [] {
                const std::string body(DESKTOP_HTML);
                uint8_t digest[32];
                veld::vendored_crypto::Sha256 h;
                h.update(reinterpret_cast<const uint8_t*>(body.data()),
                         body.size());
                h.finalize(digest);
                return veld::BytesToHex(digest, sizeof(digest)).substr(0, 12);
            }();
            std::string sw = std::string(R"(
const CACHE = 'veld-wallet-)") + VELD_BUILD_ID + "-" +
                DEPLOYMENT_ROLE + "-" + DEPLOYMENT_PROFILE_ID + "-" +
                GENESIS_HASH + "-" + ui_revision + R"(';
const CACHE_PREFIX = 'veld-wallet-';
self.addEventListener('install', e => {
  // The wallet is an online signing client. Do not retain a signer-capable
  // HTML shell or crypto bundle in Cache Storage; every launch must obtain
  // the current origin response and its fresh CSP nonce.
  e.waitUntil(self.skipWaiting());
});
self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    // Remove every cache created by older wallet service workers, including
    // the old offline root document. Existing clients are not navigated.
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k.startsWith(CACHE_PREFIX)).map(k => caches.delete(k)));
    await self.clients.claim();
  })());
});
self.addEventListener('fetch', e => {
  // All wallet documents, signer assets, and RPC reads are network-only.
  // If the origin is unavailable, fail closed instead of serving stale code.
  if (e.request.method === 'GET') e.respondWith(fetch(e.request));
});
)";
            resp = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n"
                 + cors
                 + "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                 + "Pragma: no-cache\r\n"
                 + "Content-Length: " + std::to_string(sw.size()) + "\r\n\r\n" + sw;
        // The ML-DSA bundle is a signer capability. Serve it only to the exact
        // public wallet origin or to a capability-authenticated local wallet;
        // never to the marketing host or an untrusted loopback page.
        } else if (path == "/dilithium.js") {
            if (!browser_self_custody_wallet) {
                resp = "HTTP/1.1 404 Not Found\r\n" + cors
                     + "Cache-Control: no-store\r\nContent-Length: 0\r\n\r\n";
            } else {
                const std::string& js = veld::GetDilithiumWasmJS();
                resp = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n"
                     + cors + "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                     + "Content-Length: " + std::to_string(js.size()) + "\r\n\r\n" + js;
            }
        } else if (path == "/jsQR.min.js") {
            const std::string& js = veld::GetJsQrJS();
            resp = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n"
                 + cors + "Cache-Control: public, max-age=31536000, immutable\r\n"
                 + "Content-Length: " + std::to_string(js.size()) + "\r\n\r\n" + js;
        } else if (path == "/covenant_client.js") {
            const std::string& js = veld::GetCovenantClientJS();
            resp = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n"
                 + cors + "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                 + "Content-Length: " + std::to_string(js.size()) + "\r\n\r\n" + js;
        } else if (path == "/favicon.png") {
            static const std::string png = base64_decode("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");
            resp = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n"
                 + cors + "Cache-Control: public, max-age=31536000, immutable\r\n"
                 + "Content-Length: " + std::to_string(png.size()) + "\r\n\r\n" + png;
        } else if (path == "/apple-touch-icon.png") {
            static const std::string png = base64_decode("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");
            resp = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n"
                 + cors + "Cache-Control: public, max-age=31536000, immutable\r\n"
                 + "Content-Length: " + std::to_string(png.size()) + "\r\n\r\n" + png;
        } else if (path == "/icon-192.png") {
            static const std::string b64_192 = "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";
            static const std::string png_192 = base64_decode(b64_192);
            resp = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n"
                 + cors + "Content-Length: " + std::to_string(png_192.size()) + "\r\n\r\n" + png_192;
        } else if (path == "/icon-512.png") {
            static const std::string b64_512 = "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";
            static const std::string png_512 = base64_decode(b64_512);
            resp = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n"
                 + cors + "Content-Length: " + std::to_string(png_512.size()) + "\r\n\r\n" + png_512;
        } else {
            static const std::string not_found = "Not Found\n";
            resp = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\n"
                 + cors + "Cache-Control: no-store\r\n"
                 + "Content-Length: " + std::to_string(not_found.size())
                 + "\r\n\r\n" + not_found;
        }
        // Send the whole response — a single ::send() can do a partial write and
        // truncate large embedded assets at the socket buffer; loop until every
        // byte is out.
        {
            size_t sent = 0; const char* sp = resp.data(); size_t stotal = resp.size();
            while (sent < stotal) {
                int sn = ::send(cfd, sp + sent, (int)(stotal - sent), 0);
                if (sn <= 0) break;
                sent += (size_t)sn;
            }
        }
        VELD_CLOSE_SOCKET(cfd);
    }
};

static void OpenBrowser(const std::string& url) {
    for (char c : url) {
        if (c == '\'' || c == '"' || c == ';' || c == '|' || c == '&'
            || c == '$' || c == '`' || c == '\n' || c == '\r') return;
    }
#ifdef _WIN32
    veld::compat::RunDetached({"rundll32.exe", "url.dll,FileProtocolHandler", url});
#else
    veld::compat::RunDetached({"xdg-open", url});
#endif
}

static bool AppendFleetAnchorEnvironment(std::vector<std::string>& anchors,
                                         std::string& error) {
    const char* raw = std::getenv("VELD_FLEET_ANCHOR_IPS");
    if (!raw) return true;
    const std::string value(raw);
    if (value.empty()) {
        error = "VELD_FLEET_ANCHOR_IPS is empty";
        return false;
    }
    size_t begin = 0;
    while (begin <= value.size()) {
        const size_t comma = value.find(',', begin);
        const size_t length = (comma == std::string::npos)
            ? value.size() - begin : comma - begin;
        const std::string field = value.substr(begin, length);
        const size_t first = field.find_first_not_of(" \t\r\n");
        const size_t last = field.find_last_not_of(" \t\r\n");
        if (first == std::string::npos) {
            error = "VELD_FLEET_ANCHOR_IPS contains an empty entry";
            return false;
        }
        anchors.push_back(field.substr(first, last - first + 1));
        if (comma == std::string::npos) break;
        begin = comma + 1;
    }
    return true;
}

#ifdef _WIN32
static BOOL WINAPI DesktopConsoleHandler(DWORD control_type) {
    switch (control_type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            g_shutdown.store(true, std::memory_order_release);
            return TRUE;
        default:
            return FALSE;
    }
}
#endif

static void PrintDeploymentInfoJson() {
    const veld::NetworkConfig config = veld::MainnetConfig();
    std::ostringstream magic;
    magic << "0x" << std::hex << std::setw(8) << std::setfill('0')
          << config.magic;
    std::cout << "VELD_DEPLOYMENT_INFO_V1_JSON {"
              << "\"binary_role\":\"desktop-client\","
              << "\"client_version\":\"" << veld::CLIENT_VERSION << "\","
              << "\"default_datadir\":\""
              << veld::DefaultDataDirForNetwork(veld::NetworkKind::Mainnet)
              << "\","
              << "\"display_name\":\"" << veld::DEPLOYMENT_DISPLAY_NAME << "\","
              << "\"disposable\":"
              << (veld::DEPLOYMENT_DISPOSABLE ? "true" : "false") << ","
              << "\"external_value\":"
              << (veld::DEPLOYMENT_EXTERNAL_VALUE ? "true" : "false") << ","
#ifdef VELD_USE_LEVELDB
              << "\"storage_backend\":\"leveldb\","
#else
              << "\"storage_backend\":\"flatfile\","
#endif
              << "\"explorer_port\":" << veld::CompiledPublicExplorerPort() << ","
              << "\"genesis_fingerprint\":\"" << veld::GENESIS_HASH << "\","
              << "\"network_magic\":\"" << magic.str() << "\","
              << "\"p2p_port\":" << config.port << ","
              << "\"profile_id\":\"" << veld::DEPLOYMENT_PROFILE_ID << "\","
#ifdef _WIN32
              << "\"remote_tls_backend\":\"winhttp\","
#elif defined(VELD_DESKTOP_OPENSSL_TLS)
              << "\"remote_tls_backend\":\"openssl\","
#else
              << "\"remote_tls_backend\":\"unavailable\","
#endif
              << "\"role\":\"" << veld::DEPLOYMENT_ROLE << "\","
              << "\"rpc_port\":" << config.rpc_port << ","
              << "\"wallet_ui_port\":" << veld::CompiledPublicWalletUiPort() << ","
              << "\"warning\":\"" << veld::DEPLOYMENT_WARNING << "\""
              << "}\n";
}

int main(int argc, char* argv[]) {
    veld::compat::HardenDllSearchPath();
    if (argc == 2 &&
        (std::string(argv[1]) == "--version" ||
         std::string(argv[1]) == "-V")) {
        std::cout << "Veld Desktop " << CLIENT_VERSION << "\n";
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--deployment-info") {
        PrintDeploymentInfoJson();
        return 0;
    }
    veld::mining::VeldIntegerDeterminismCheck();
    veld::vendored_crypto::vendored_crypto_selftest();
    veld::compat::InitNetwork();

#ifdef _WIN32
    if (!::SetConsoleCtrlHandler(DesktopConsoleHandler, TRUE)) {
        std::cerr << "FATAL: could not install Windows console shutdown handler\n";
        return 1;
    }
#else
    auto stop_signal = [](int){ g_shutdown.store(true, std::memory_order_release); };
    ::signal(SIGINT, stop_signal);
    ::signal(SIGTERM, stop_signal);
    ::signal(SIGPIPE, SIG_IGN);
#endif

    std::string opt_datadir;
    std::string opt_miner;
    bool        opt_mine = false;
    unsigned    opt_mining_threads = 1;
    bool        opt_wallet_only = false;
    const NetworkConfig compiled_config = MainnetConfig();
    uint16_t    opt_p2p  = compiled_config.port;
    uint16_t    opt_rpc  = compiled_config.rpc_port;
    std::string opt_rpcurl;
    std::string opt_local_signer_bootstrap_token;
    if (const char* signer_token = std::getenv("VELD_LOCAL_SIGNER_TOKEN"))
        opt_local_signer_bootstrap_token = signer_token;
    veld::compat::UnsetEnv("VELD_LOCAL_SIGNER_TOKEN");
    if (!opt_local_signer_bootstrap_token.empty() &&
        !is_local_signer_bootstrap_token(opt_local_signer_bootstrap_token)) {
        veld::compat::SecureZero(opt_local_signer_bootstrap_token.data(),
                                 opt_local_signer_bootstrap_token.size());
        std::cerr << "veld-desktop: invalid local signer launch capability\n";
        return 2;
    }
    uint16_t    opt_ui   = CompiledPublicWalletUiPort();
    std::vector<std::string> opt_connect;
    std::vector<std::string> opt_fleet_anchor_ips;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--mine")                    opt_mine = true;
        else if (a == "--wallet")                  opt_wallet_only = true;
        else if (a == "--miner"   && i+1 < argc) { opt_miner   = argv[++i]; }
        else if (a == "--threads") {
            if (i + 1 >= argc) {
                std::cerr << "veld-desktop: --threads requires an integer from 1 to 64\n";
                return 2;
            }
            try {
                size_t consumed = 0;
                const unsigned long parsed = std::stoul(argv[++i], &consumed, 10);
                if (consumed != std::string(argv[i]).size() ||
                    parsed < 1 || parsed > 64) {
                    throw std::out_of_range("mining thread count");
                }
                opt_mining_threads = static_cast<unsigned>(parsed);
            } catch (const std::exception&) {
                std::cerr << "veld-desktop: --threads requires an integer from 1 to 64\n";
                return 2;
            }
        }
        else if (a == "--datadir" && i+1 < argc) { opt_datadir = argv[++i]; }
        else if (a == "--connect" && i+1 < argc) { opt_connect.push_back(argv[++i]); }
        else if (a == "--fleet-anchor") {
            if (i + 1 >= argc) {
                std::cerr << "veld-desktop: --fleet-anchor requires an exact IPv4 literal\n";
                return 2;
            }
            opt_fleet_anchor_ips.push_back(argv[++i]);
        }
        else if (a == "--rpcport" && i+1 < argc) { opt_rpc = (uint16_t)std::stoi(argv[++i]); }
        else if (a == "--rpcurl"  && i+1 < argc) { opt_rpcurl = argv[++i]; }
        else if (a == "--p2pport" && i+1 < argc) { opt_p2p = (uint16_t)std::stoi(argv[++i]); }
        else if (a == "--uiport"  && i+1 < argc) { opt_ui  = (uint16_t)std::stoi(argv[++i]); }
        else if (a == "--help" || a == "-h") {
            std::cout << "Veld Desktop Wallet\n\n"
                      << "Usage:\n"
#ifdef VELD_PUBLIC_TESTNET
                      << "  veld-desktop --datadir <path> --connect <IPv4:19333> "
                         "--fleet-anchor <IPv4> (exactly four matching pairs)\n"
                      << "                                      Run the role-bound disposable full node + wallet\n"
#else
                      << "  veld-desktop --wallet                          Distributable wallet mode (recommended)\n"
                      << "  veld-desktop --wallet --rpcurl <url>           Wallet against a specific node\n"
                      << "  veld-desktop --datadir <path>                  Run a full node + wallet\n"
#endif
                      << "\nOptions:\n"
#ifdef VELD_PUBLIC_TESTNET
                      << "  --connect <IPv4:19333>     Reviewed relay (exactly four, sorted, repeatable)\n"
#else
                      << "  --wallet                   Wallet-only mode (no local node, uses public infra)\n"
                      << "  --rpcurl <url>             Override RPC endpoint (remote requires https://; "
                         "http:// is loopback-only)\n"
#endif
                      << "  --uiport <N>               Wallet UI port (default "
                      << CompiledPublicWalletUiPort() << ")\n"
                      << "  --datadir <path>           Local chain data (full-node mode only)\n"
                      << "  --mine                     Enable mining (full-node mode only)\n"
                      << "  --miner <address>          Mining reward address\n"
                      << "  --threads <1..64>          Mining worker threads (default 1)\n"
                      << "  --fleet-anchor <IPv4>      Matching relay clock anchor (exactly four, sorted, repeatable)\n"
                      << "                             Exact IPv4 only; VELD_FLEET_ANCHOR_IPS accepts a comma-separated list\n";
            return 0;
        }
    }

    if (!opt_local_signer_bootstrap_token.empty()) {
        if (!opt_wallet_only || opt_rpcurl.empty()) {
            veld::compat::SecureZero(opt_local_signer_bootstrap_token.data(),
                                     opt_local_signer_bootstrap_token.size());
            opt_local_signer_bootstrap_token.clear();
            std::cerr << "veld-desktop: FATAL: local signer authority requires "
                         "wallet-only RPC-proxy mode\n";
            return 2;
        }
    }

#ifdef VELD_PUBLIC_TESTNET
    if (!CompiledRoleAllowsPort(opt_p2p, CompiledPublicP2PPort())
            || !CompiledRoleAllowsPort(opt_rpc, CompiledPublicRpcPort())
            || !CompiledRoleAllowsPort(opt_ui, CompiledPublicWalletUiPort())) {
        std::cerr << "veld-desktop: FATAL: PUBLIC TESTNET ports are immutable; "
                  << "required p2p=" << CompiledPublicP2PPort()
                  << " rpc=" << CompiledPublicRpcPort()
                  << " ui=" << CompiledPublicWalletUiPort()
                  << ", requested p2p=" << opt_p2p
                  << " rpc=" << opt_rpc << " ui=" << opt_ui << "\n";
        return 2;
    }
    // Wallet-only / remote-RPC mode is available on every profile (owner
    // decision, ). Blocking it here is what left wallet.veld.network
    // with no backend: the hosted wallet proxies to the node already running on
    // the same box, and a second full node would only contend for that node's
    // datadir lock. The endpoint still proves role/profile/genesis at runtime
    // through the deployment identity it serves.
    if (opt_wallet_only || !opt_rpcurl.empty()) {
        // Remote/wallet-only mode has no local P2P, so the relay-quorum
        // requirement below does not apply to it.
    } else if (opt_connect.size() != 4 || opt_fleet_anchor_ips.size() != 4) {
        std::cerr << "veld-desktop: FATAL: PUBLIC TESTNET requires exactly "
                     "three --connect IPv4:19333 endpoints and the same three "
                     "--fleet-anchor IPv4 identities\n";
        return 2;
    }
    if (!std::is_sorted(opt_connect.begin(), opt_connect.end()) ||
        std::adjacent_find(opt_connect.begin(), opt_connect.end()) !=
            opt_connect.end() ||
        !std::is_sorted(opt_fleet_anchor_ips.begin(),
                        opt_fleet_anchor_ips.end()) ||
        std::adjacent_find(opt_fleet_anchor_ips.begin(),
                           opt_fleet_anchor_ips.end()) !=
            opt_fleet_anchor_ips.end()) {
        std::cerr << "veld-desktop: FATAL: testnet relay identities must be "
                     "sorted and unique\n";
        return 2;
    }
    for (size_t peer_index = 0; peer_index < opt_connect.size(); ++peer_index) {
        const auto& peer = opt_connect[peer_index];
        std::string host;
        uint16_t port = 0;
        const bool valid = veld::net::NodeServer::ParsePublicIPv4Endpoint(
                               peer, host, port) &&
            veld::net::NodeServer::IsCanonicalIPv4Literal(host) &&
            port == CompiledPublicP2PPort() &&
            host == opt_fleet_anchor_ips[peer_index];
        if (!valid) {
            std::cerr << "veld-desktop: FATAL: invalid, non-global, or "
                         "unmatched testnet relay target '" << peer << "'\n";
            return 2;
        }
    }
#endif

    std::string fleet_anchor_error;
    if (!AppendFleetAnchorEnvironment(opt_fleet_anchor_ips,
                                      fleet_anchor_error)) {
        std::cerr << "veld-desktop: FATAL: " << fleet_anchor_error << "\n";
        return 2;
    }
    for (const auto& ip : opt_fleet_anchor_ips) {
        if (!veld::net::NodeServer::IsCanonicalIPv4Literal(ip)) {
            std::cerr << "veld-desktop: FATAL: fleet anchor '" << ip
                      << "' is not an exact canonical IPv4 literal\n";
            return 2;
        }
    }
#ifndef VELD_PUBLIC_TESTNET
    if (opt_fleet_anchor_ips.empty() &&
        !opt_wallet_only && opt_rpcurl.empty()) {
        opt_fleet_anchor_ips =
            veld::seeder::SeedNodeClient::GetHardcodedFleetAnchorIps();
    }
#endif
    if (!opt_fleet_anchor_ips.empty() &&
            (opt_wallet_only || !opt_rpcurl.empty())) {
        std::cerr << "veld-desktop: FATAL: fleet anchors require full-node mode; "
                     "wallet-only/RPC-proxy mode has no local P2P node\n";
        return 2;
    }

    #ifndef VELD_PUBLIC_TESTNET
    if (opt_wallet_only && opt_rpcurl.empty()) {
        opt_rpcurl = "https://node1.veld.network";
    }
#endif

    if (opt_datadir.empty()) {
        const char* h = std::getenv("USERPROFILE");
        if (!h) h = std::getenv("HOME");
        if (!h || !*h) {
            std::cerr << "  FATAL: USERPROFILE/HOME is unavailable; provide an explicit "
                         "owner-only --datadir (temporary shared directories are forbidden)\n";
            return 2;
        }
        if (!opt_rpcurl.empty()) {
#ifdef VELD_PUBLIC_TESTNET
            opt_datadir = std::string(h) + "/.veld-wallet-public-testnet-v1";
#else
            opt_datadir = std::string(h) + "/.veld-wallet";
#endif
        } else {
#ifdef VELD_PUBLIC_TESTNET
            opt_datadir = DefaultDataDirForNetwork(NetworkKind::Mainnet);
#else
            opt_datadir = std::string(h) + "/veld-data";
#endif
        }
    }
    std::replace(opt_datadir.begin(), opt_datadir.end(), '\\', '/');
    try {
        opt_datadir = fs::absolute(opt_datadir).lexically_normal().string();
        std::replace(opt_datadir.begin(), opt_datadir.end(), '\\', '/');
    } catch (const std::exception& e) {
        std::cerr << "  FATAL: invalid data directory: " << e.what() << "\n";
        return 2;
    }
    std::string datadir_error;
    if (!veld::channel::secure_file::EnsurePrivateDirectory(
            opt_datadir, &datadir_error)) {
        std::cerr << "  FATAL: refusing unsafe desktop data directory: "
                  << datadir_error << "\n";
        return 2;
    }
#ifdef VELD_PUBLIC_RELEASE
    std::string identity_error;
    if (!ValidateOrCreatePublicNetworkIdentity(opt_datadir, &identity_error)) {
        std::cerr << "  FATAL: public datadir identity refusal: "
                  << identity_error << "\n";
        return 2;
    }
#endif

#ifdef VELD_PUBLIC_TESTNET
    // Resolve the compiled testnet lease before VeldNode construction can
    // create a P2P/RPC/UI listener.  Two reviewed constants -- no credential
    // files, no signature verification, no per-launch authorization.
    public_testnet::RuntimeLimits testnet_runtime_limits;
    std::string testnet_runtime_error;
    const int64_t testnet_local_now = public_testnet::CurrentUnixTime();
    if (!public_testnet::CompiledRuntimeLimits(
            testnet_local_now, testnet_runtime_limits,
            &testnet_runtime_error)) {
        std::cerr << "veld-desktop: FATAL: public-testnet lease refusal: "
                  << testnet_runtime_error << "\n";
        return 78;
    }
#endif

    #ifdef VELD_PUBLIC_TESTNET
    std::cout << "\n  " << DEPLOYMENT_WARNING << "\n"
              << "  Role:  " << DEPLOYMENT_ROLE << " (" << DEPLOYMENT_PROFILE_ID << ")\n"
              << "  Genesis: " << GENESIS_HASH << "\n";
    #endif

    std::cout << "\n"
              << "  +-----------------------------------------------+\n"
              << "  |  V\\   /V  EEEEE  L      DDDD                 |\n"
              << "  |  -\\   /-  E      L      D   D                |\n"
              << "  |   \\   /   EEEE   L      D   D                |\n"
              << "  |  --\\ /--  E      L      D   D                |\n"
              << "  |    V V    EEEEE  LLLLL  DDDD                 |\n"
              << "  |                                               |\n"
              << "  |    Veld Desktop release v" << CLIENT_VERSION
#ifdef VELD_PUBLIC_TESTNET
              << " -- Disposable; no value.   |\n"
#else
              << " -- Where value is earned. |\n"
#endif
              << "  +-----------------------------------------------+\n\n"
              << "  Network: " << compiled_config.name << "\n"
              << "  Data:  " << opt_datadir << "\n"
              << "  UI:    http://localhost:" << opt_ui << " (wallet)\n"
              << "  RPC:   http://127.0.0.1:" << opt_rpc << "\n\n";

    if (!opt_rpcurl.empty()) {
#ifdef VELD_PUBLIC_TESTNET
        const int64_t listener_local_now =
            public_testnet::CurrentUnixTime();
        const uint64_t listener_monotonic_now =
            public_testnet::SuspendAwareMonotonicSeconds();
        if (!testnet_runtime_limits.TimePermitted(listener_local_now) ||
            listener_monotonic_now ==
                public_testnet::INVALID_SUSPEND_AWARE_SECONDS) {
            std::cerr << "veld-desktop: FATAL: the public testnet has ended; "
                         "not opening the remote UI listener\n";
            return 78;
        }
#endif
        DesktopRpcEndpoint endpoint;
        if (!parse_desktop_rpc_endpoint(opt_rpcurl, endpoint)) {
            std::cerr << "  FATAL: --rpcurl must be an exact "
                         "https://IPv4-or-DNS-name[:port] authority, or "
                         "http://127.0.0.1|localhost[:port]\n";
            return 2;
        }
        const std::string proxy_token = endpoint.may_use_local_bearer
            ? load_rpc_token(opt_datadir) : std::string();
        DesktopServer desktop_srv(opt_ui, opt_rpcurl, proxy_token, opt_datadir,
                                  opt_local_signer_bootstrap_token);
        if (!opt_local_signer_bootstrap_token.empty()) {
            veld::compat::SecureZero(opt_local_signer_bootstrap_token.data(),
                                     opt_local_signer_bootstrap_token.size());
            opt_local_signer_bootstrap_token.clear();
        }
#ifdef VELD_PUBLIC_TESTNET
        if (desktop_srv.Start([&]() noexcept {
                const int64_t local_now = public_testnet::CurrentUnixTime();
                const uint64_t monotonic_now =
                    public_testnet::SuspendAwareMonotonicSeconds();
                return testnet_runtime_limits.TimePermitted(local_now) &&
                    monotonic_now !=
                        public_testnet::INVALID_SUSPEND_AWARE_SECONDS;
            })) {
#else
        if (desktop_srv.Start()) {
#endif
            std::cout << "  [OK] Wallet UI on port " << opt_ui << "\n";
#ifdef VELD_PUBLIC_TESTNET
        } else if (desktop_srv.ActivationGuardRefused()) {
            std::cerr << "veld-desktop: FATAL: public-testnet restart "
                         "authority refused at remote UI activation\n";
            return 78;
#endif
        } else {
            std::cerr << "veld-desktop: FATAL: wallet UI listener could not be opened\n";
            return 2;
        }
        std::cout << "  Wallet UI: http://127.0.0.1:" << opt_ui << " -- Press Ctrl+C to stop.\n";
        while (!g_shutdown.load(std::memory_order_acquire))
            std::this_thread::sleep_for(std::chrono::seconds(1));
        return 0;
    }
    NetworkConfig config = compiled_config;
    config.port = opt_p2p;
    VeldNode node(config, opt_datadir);
#ifdef VELD_PUBLIC_TESTNET
    try {
        node.SetPublicTestnetCompiledLease(testnet_runtime_limits);
        if (!public_testnet::BindOrVerifySession(
                opt_datadir, testnet_runtime_limits,
                std::max(testnet_local_now,
                         public_testnet::CurrentUnixTime()),
                &testnet_runtime_error)) {
            throw std::runtime_error(
                "public-testnet session refusal: " +
                testnet_runtime_error);
        }
    } catch (const std::exception& e) {
        std::cerr << "veld-desktop: FATAL: public-testnet runtime refusal: "
                  << e.what() << "\n";
        return 78;
    }
    node.SetFullIbd(true);
#endif
#ifdef VELD_PUBLIC_TESTNET
    try {
        node.Start();
    } catch (const public_testnet::ListenerActivationAuthorityRefusal& e) {
        std::cerr << "veld-desktop: FATAL: " << e.what() << "\n";
        return 78;
    } catch (const std::exception& e) {
        std::cerr << "veld-desktop: FATAL: public-testnet P2P startup "
                     "failed: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "veld-desktop: FATAL: public-testnet P2P startup "
                     "failed with an unknown error\n";
        return 1;
    }
#else
    node.Start();
#endif

    for (size_t anchor_index = 0;
         anchor_index < opt_fleet_anchor_ips.size(); ++anchor_index) {
        const auto& ip = opt_fleet_anchor_ips[anchor_index];
        if (node.AddFleetAnchorIp(ip)) {
            std::cout << "  [network] Seed node " << (anchor_index + 1)
                      << " connected\n";
            if (veld::DiagVerbose().load())
                std::cout << "  [network-detail] endpoint=" << ip << ":"
                          << config.port << "\n";
        } else {
            std::cerr << "  [network] WARN: Seed node "
                      << (anchor_index + 1)
                      << " is temporarily unavailable; retrying\n";
            if (veld::DiagVerbose().load())
                std::cerr << "  [network-detail] endpoint=" << ip << ":"
                          << config.port << "\n";
        }
    }

    // Building the 1 GiB memory-hard mining dataset is useful only when this
    // process was explicitly started as a miner. A wallet/full-node desktop
    // must not consume that CPU/RAM while servicing P2P and the UI.
    if (opt_mine) {
        node.SetMiningThreads(opt_mining_threads);
        node.PrewarmHashDataset();
    }
    node.PrewarmRichList();

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const std::vector<std::string> bootstrap_peers = opt_connect.empty()
        ? veld::seeder::SeedNodeClient::GetHardcodedBootstrap()
        : opt_connect;
    for (const auto& peer : bootstrap_peers) {
        auto colon = peer.find(':');
        std::string host = (colon != std::string::npos) ? peer.substr(0, colon) : peer;
        uint16_t    port = (colon != std::string::npos)
            ? (uint16_t)std::stoi(peer.substr(colon+1)) : config.port;
        if (node.ConnectTo(host, port))
            std::cout << "  [OK] Connected to " << host << ":" << port << "\n";
    }

    if (opt_mine) {
        //  (silent burn bug): previous code created
        // a *fresh random* RealKeyPair via GenerateKeyPair(false), then
        // if miner.key existed, overwrote ONLY the .address string from
        // line 3 of the file — private_key and public_key remained the
        // random fresh keypair. GetP2PKHScript() hashes public_key (NOT
        // address), so without --miner every coinbase was paid to
        // Hash160(random_pubkey), whose private key the process never
        // persisted. Every block mined this way was an unspendable burn.
        //
        // Require --miner explicitly. Mining through veld-desktop
        // never unlocks an encrypted key anyway (the unlock flow is in
        // veld-node --setup / wizard, not here), so the only correct
        // behaviour is to require the operator to name the reward
        // address. `script_override` then bypasses the random-pubkey
        // path entirely and coinbase outputs go to the real address.
        //
        // Operators who want to use the encrypted miner.key should launch
        // `veld-node --mine ...` directly; veld-desktop is a UI host, not
        // a signing host.
        if (opt_miner.empty()) {
            std::cerr << "\n  FATAL: --mine requires --miner <VELD-address>.\n"
                      << "  veld-desktop cannot unlock an encrypted miner.key and\n"
                      << "  would silently mine to an unrecoverable random address\n"
                      << "  without this flag. Either:\n"
                      << "    (a) re-run with --miner <your-VELD-address>, OR\n"
                      << "    (b) launch `veld-node --mine --datadir " << opt_datadir
                      << "` instead, which prompts for the miner.key passphrase.\n\n";
            std::cerr.flush();
            return 1;
        }
        auto reward_script = AddressToScript(opt_miner);
        if (reward_script.size() != 25) {
            std::cerr << "\n  FATAL: --miner address is invalid: " << opt_miner << "\n\n";
            std::cerr.flush();
            return 1;
        }
        RealKeyPair miner_kp = GenerateKeyPair(false);
        miner_kp.script_override = reward_script;
        miner_kp.address = opt_miner;
        std::cout << "  Mining to: " << opt_miner
                  << " using " << opt_mining_threads
                  << " thread(s) (reward routed via script_override)\n";
        node.StartMining(miner_kp);
    }

    node.GetRPC().SetTxBroadcast([&node](const Transaction& tx) {
        if (auto* tcp = node.GetTCPServer()) tcp->BroadcastTransaction(tx);
    });
    node.GetRPC().SetPeerCount([&node]() -> size_t {
        return node.ConnectedPeers();
    });

    // H-02: the desktop's own loopback JSON-RPC (8334) is MUTATING (tx submission, admin
    // methods) — it must NEVER be served unauthenticated. Generate a strong ephemeral token
    // for THIS process (CSPRNG, same as the node) and require it on the RPC; the wallet UI,
    // running in the same process, uses the same token to call it. An external local process
    // without the token cannot reach a single mutating method. Fail closed on CSPRNG failure.
    std::string desktop_token;
    {
        static const char* hexd = "0123456789abcdef";
        uint8_t rb[32];
        if (!veld::compat::SecureRandom(rb, 32)) {
            std::cerr << "\n  FATAL: CSPRNG failure — cannot secure the wallet RPC. Not starting.\n\n";
            std::cerr.flush();
            return 1;
        }
        for (int i = 0; i < 32; ++i) { desktop_token += hexd[(rb[i] >> 4) & 0xF]; desktop_token += hexd[rb[i] & 0xF]; }
        veld::compat::SecureZero(rb, 32);
    }
    RpcHttpServer rpc_http(node.GetRPC(), opt_rpc, "", desktop_token);
#ifdef VELD_PUBLIC_TESTNET
    if (!node.PublicTestnetRestartAuthorityFreshNow()) {
        std::cerr << "\n  FATAL: public-testnet restart authority expired "
                     "before RPC listener.\n\n";
        node.Stop();
        return 78;
    }
#endif
#ifdef VELD_PUBLIC_TESTNET
    const auto listener_activation_guard = [&node]() noexcept {
        return node.PublicTestnetRestartAuthorityFreshNow();
    };
    if (!rpc_http.Start(listener_activation_guard)) {
#else
    if (!rpc_http.Start()) {
#endif
#ifdef VELD_PUBLIC_TESTNET
        if (rpc_http.ActivationGuardRefused()) {
            std::cerr << "\n  FATAL: public-testnet restart authority "
                         "refused at RPC activation.\n\n";
            node.Stop();
            return 78;
        }
#endif
        std::cerr << "\n  FATAL: authenticated RPC failed to start on port " << opt_rpc << ". Not starting.\n\n";
        std::cerr.flush();
        return 1;
    }
    std::cout << "  [OK] RPC (authenticated, loopback-only) on port " << opt_rpc << "\n";

    std::string rpc_url = opt_rpcurl.empty()
        ? ("http://127.0.0.1:" + std::to_string(opt_rpc))
        : opt_rpcurl;
    DesktopServer desktop_srv(opt_ui, node.GetRPC(), rpc_url, desktop_token, opt_datadir);
#ifdef VELD_PUBLIC_TESTNET
    if (!node.PublicTestnetRestartAuthorityFreshNow()) {
        std::cerr << "\n  FATAL: public-testnet restart authority expired "
                     "before wallet UI listener.\n\n";
        rpc_http.Stop();
        node.Stop();
        return 78;
    }
#endif
#ifdef VELD_PUBLIC_TESTNET
    if (desktop_srv.Start(listener_activation_guard))
#else
    if (desktop_srv.Start())
#endif
        std::cout << "  [OK] Wallet UI on port " << opt_ui << "\n";
    else {
#ifdef VELD_PUBLIC_TESTNET
        if (desktop_srv.ActivationGuardRefused()) {
            std::cerr << "\n  FATAL: public-testnet restart authority "
                         "refused at wallet UI activation.\n\n";
            rpc_http.Stop();
            node.Stop();
            return 78;
        }
#endif
        std::cout << "  [WARN] Could not start wallet UI on port " << opt_ui << "\n";
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    std::string ui_url = "http://localhost:" + std::to_string(opt_ui);
    OpenBrowser(ui_url);
    std::cout << "\n  Wallet UI: " << ui_url << " — Press Ctrl+C to stop.\n\n";

    uint64_t last_h = 0;
    uint64_t stable_ticks = 0;
    int stale_tip_secs = 0;
    int tick = 0;
    bool fail_stop_exit = false;
    bool testnet_expiry_exit = false;
    while (!g_shutdown) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        ++tick;

#ifdef VELD_PUBLIC_TESTNET
        if (node.PublicTestnetRuntimeStopRequired()) {
            std::cerr << "  [PUBLIC-TESTNET-EXPIRED] immutable START-index "
                         "not-after height/UTC reached; stopping wallet UI, "
                         "RPC/P2P/explorer/mining and exiting.\n";
            std::cerr.flush();
            testnet_expiry_exit = true;
            g_shutdown.store(true);
            break;
        }
#endif

        // Poll from the outer supervisor rather than stopping services inside
        // the commit callback.  That avoids callback-thread shutdown joins and
        // guarantees the wallet RPC/UI cannot remain live after a post-durable
        // invariant or anchor-floor persistence failure.
        if (node.FailStopRequired()) {
            if (node.DurableCommitFailStop()) {
                std::cerr << "  [durable-commit] the authoritative DB tip is "
                             "durable but its in-memory durability marker was "
                             "not published; stopping wallet RPC/P2P/mining "
                             "for mandatory restart replay repair.\n";
            } else {
                std::cerr << "  [anchor-floor] security persistence is uncertain; "
                             "stopping wallet RPC/P2P/mining for mandatory "
                             "replay repair.\n";
            }
            std::cerr.flush();
            fail_stop_exit = true;
            g_shutdown.store(true);
            break;
        }
        uint64_t h = node.GetChain().Height();

        if (!opt_fleet_anchor_ips.empty() && (tick % 30) == 0) {
            for (size_t anchor_index = 0;
                 anchor_index < opt_fleet_anchor_ips.size(); ++anchor_index) {
                const auto& ip = opt_fleet_anchor_ips[anchor_index];
                if (!node.AddFleetAnchorIp(ip)) {
                    std::cerr << "  [network] WARN: Seed node "
                              << (anchor_index + 1)
                              << " is temporarily unavailable; retrying\n";
                    if (veld::DiagVerbose().load())
                        std::cerr << "  [network-detail] endpoint=" << ip << ":"
                                  << config.port << "\n";
                }
            }
        }

        // Desktop full-node mining follows the same IBD safety contract as
        // veld-node and veld-miner. Merely having a TCP socket is not sync
        // evidence: current peers must have completed the handshake. Two
        // current outbound announcements provide only a conservative floor;
        // locally accepted blocks remain the sole source of chain authority.
        const auto peer_heights = node.GetPeerHeightView();
        const uint64_t verified_peer_height =
            peer_heights.verified_height;
        // Re-IBD follows the greater of locally verified peer evidence and the
        // conservative two-outbound-peer sync floor.
        const uint64_t peer_best = std::max(
            verified_peer_height, peer_heights.outbound_sync_height);
        const bool at_tip = IsInitialDownloadAtTip(
            false, h, node.GetChain().IsEmpty(),
            peer_heights.distinct_version_ips, verified_peer_height,
            peer_heights.distinct_outbound_sync_ips,
            peer_heights.outbound_sync_height);
        if (at_tip) {
            ++stable_ticks;
            if (stable_ticks >= 3 && !node.IsIBDComplete()) {
                node.SetIBDComplete(true);
                node.SyncTCPIBDFlag();
                // The anchor-security floor may refuse the transition. Never
                // run IBD backfill or tell the desktop user mining is active
                // until the node confirms the latch actually closed.
                if (node.IsIBDComplete()) {
                    node.TryBackfillFlushes();
                    std::cout << "  [IBD complete] height=" << h
                              << (node.IsMining()
                                      ? ". Mining active.\n"
                                      : ". Mining disabled.\n");
                    std::cout.flush();
                } else {
                    stable_ticks = 2;
                }
            }
        } else {
            stable_ticks = 0;
        }

        // A desktop that was at tip can later fall behind. Pause its
        // memory-hard workers after a sustained gap so P2P validation gets
        // the CPU headroom needed to catch up instead of recreating the
        // slow-VERSION/reaper loop.
        constexpr uint64_t STALE_TIP_TOLERANCE = 1;
        constexpr int STALE_TIP_GRACE_SECS = 30;
        if (node.IsIBDComplete()
            && peer_best > h
            && peer_best - h > STALE_TIP_TOLERANCE) {
            ++stale_tip_secs;
            if (stale_tip_secs >= STALE_TIP_GRACE_SECS) {
                node.SetIBDComplete(false);
                node.SyncTCPIBDFlag();
                stable_ticks = 0;
                stale_tip_secs = 0;
                std::cout << "  [re-IBD] peer tip=" << peer_best
                          << " ahead of ours=" << h
                          << " for " << STALE_TIP_GRACE_SECS
                          << "s — mining paused while catching up\n";
                std::cout.flush();
            }
        } else {
            stale_tip_secs = 0;
        }

        if (h != last_h) {
            last_h = h;
            char tbuf[16];
            std::time_t t = std::time(nullptr);
            std::strftime(tbuf, sizeof(tbuf), "%H:%M:%S", std::localtime(&t));
            std::cout << "  [" << tbuf << "] height=" << h
                      << "  supply=" << std::fixed << std::setprecision(2)
                      << node.GetChain().TotalSupplyVeld() << " VELD\n";
        }
        if (tick % 15 == 0 && node.VersionReadyPeers() == 0) {
            for (const auto& peer : bootstrap_peers) {
                auto colon = peer.find(':');
                std::string host = (colon != std::string::npos) ? peer.substr(0, colon) : peer;
                uint16_t    port = (colon != std::string::npos)
                    ? (uint16_t)std::stoi(peer.substr(colon+1)) : config.port;
                node.ConnectTo(host, port);
            }
        }
    }

    std::cout << "\n  Shutting down...\n";
    desktop_srv.Stop();
    rpc_http.Stop();
    node.Stop();
    std::cout << "  Done.\n\n";
    return testnet_expiry_exit ? 78 : (fail_stop_exit ? 75 : 0);
}
