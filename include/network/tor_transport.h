#pragma once
// ============================================================================
// Privacy-preserving reachability via Tor.
// ============================================================================
//  Lets a node be reachable as a v3 .onion hidden service — dialable with ZERO
//  IP exposure and no router config — and dial other .onion peers. This is the
//  privacy track of the mesh-hardening plan: a residential operator who wants to
//  contribute a reachable node without publishing their home IP runs a local Tor
//  daemon and `--tor`.
//
//  TorController : connects to Tor's control port, authenticates, and ADD_ONIONs
//                  a fresh v3 service mapping <onion>:<p2p> -> 127.0.0.1:<p2p>.
//                  Tor accepts inbound on the .onion and forwards to the node's
//                  existing listener — so NO listener change is needed.
//  Socks5Connect : dials host:port (incl. .onion) through Tor's SOCKS5 proxy,
//                  returning a connected socket the caller treats as any peer.
//
//  Safety:
//   * Opt-in (--tor) and requires a local Tor daemon; default-off, so the fleet
//     and every existing node are unaffected.
//   * CONSENSUS-INERT — pure transport; touches no chain/validation state.
//   * P2P-WIRE-TRANSPARENT — the .onion forwards to the existing listener and an
//     outbound .onion is a normal peer connection over the SOCKS tunnel. No
//     protocol change; the veld message format is identical on Tor or clearnet.
//   * Talks only to LOCALHOST Tor (control 9051 / SOCKS 9050). Hard timeouts on
//     every call; failure degrades to "no Tor" (the node runs clearnet as
//     before). No thread_local non-trivial objects.
// ============================================================================

#include "../compat/platform.h"
#include "../wallet/secure_channel_file.h"
#include "../wallet/wallet_crypto.h"

#include <array>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <algorithm>
#include <filesystem>
#include <iostream>

#ifndef _WIN32
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

namespace veld {
namespace net {

using SocketHandle = veld::compat::SocketHandle;

namespace _tor {

inline void EnsureNet() {
#ifdef _WIN32
    veld::compat::InitNetwork();
#endif
}

inline void SetTimeouts(SocketHandle s, int ms) {
#ifdef _WIN32
    DWORD tv = (DWORD)ms;
    ::setsockopt((SOCKET)s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    ::setsockopt((SOCKET)s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
    struct timeval tv; tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#endif
}

inline SocketHandle DialLocal(const std::string& ip, uint16_t port, int timeout_ms) {
    EnsureNet();
    SocketHandle s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (!veld::compat::IsValidSocket(s)) return veld::compat::kInvalidSocket;
    SetTimeouts(s, timeout_ms);
    struct sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port   = htons(port);
    if (::inet_pton(AF_INET, ip.c_str(), &a.sin_addr) != 1) { VELD_CLOSE_SOCKET(s); return veld::compat::kInvalidSocket; }
    if (::connect(s, (struct sockaddr*)&a, sizeof(a)) != 0) { VELD_CLOSE_SOCKET(s); return veld::compat::kInvalidSocket; }
    return s;
}

inline bool SendAll(SocketHandle s, const char* p, size_t n) {
    size_t off = 0;
    while (off < n) {
        int w = (int)::send(s, p + off, (int)(n - off), 0);
        if (w <= 0) return false;
        off += (size_t)w;
    }
    return true;
}

// Read until "\r\n250 OK" / a final "250 " line, or timeout. Bounded.
inline std::string ReadControlReply(SocketHandle s) {
    std::string out;
    char buf[1024];
    for (int i = 0; i < 64; ++i) {
        int n = (int)::recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.append(buf, (size_t)n);
        if (out.size() > 64 * 1024) break;
        // A control reply ends with a "<code> <text>\r\n" final line (space,
        // not dash, after the code).
        size_t lastnl = out.rfind("\r\n");
        if (lastnl != std::string::npos) {
            size_t ls = out.rfind("\r\n", lastnl == 0 ? 0 : lastnl - 1);
            size_t line_start = (ls == std::string::npos) ? 0 : ls + 2;
            if (out.size() >= line_start + 4 && out[line_start + 3] == ' ') break;
        }
    }
    return out;
}

template <typename Container>
struct ScopedWipe {
    Container& value;
    ~ScopedWipe() {
        if (!value.empty())
            veld::compat::SecureZero(value.data(), value.size());
    }
};

template <size_t N>
inline std::string Hex(const std::array<uint8_t, N>& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.resize(N * 2U);
    for (size_t i = 0; i < N; ++i) {
        output[i * 2U] = digits[bytes[i] >> 4U];
        output[i * 2U + 1U] = digits[bytes[i] & 0x0fU];
    }
    return output;
}

inline int HexNibble(char character) {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

template <size_t N>
inline bool DecodeExactHex(const std::string& encoded,
                           std::array<uint8_t, N>& output) {
    if (encoded.size() != N * 2U) return false;
    for (size_t i = 0; i < N; ++i) {
        const int high = HexNibble(encoded[i * 2U]);
        const int low = HexNibble(encoded[i * 2U + 1U]);
        if (high < 0 || low < 0) {
            veld::compat::SecureZero(output.data(), output.size());
            return false;
        }
        output[i] = static_cast<uint8_t>((high << 4U) | low);
    }
    return true;
}

inline bool StrictControlLines(const std::string& reply,
                               std::vector<std::string>& lines) {
    lines.clear();
    if (reply.empty() || reply.size() > 64U * 1024U ||
        reply.size() < 2U || reply.substr(reply.size() - 2U) != "\r\n")
        return false;
    size_t cursor = 0;
    while (cursor < reply.size()) {
        const size_t end = reply.find("\r\n", cursor);
        if (end == std::string::npos || end == cursor) return false;
        const std::string line = reply.substr(cursor, end - cursor);
        for (const unsigned char character : line) {
            if (character < 0x20U || character > 0x7eU) return false;
        }
        lines.push_back(line);
        cursor = end + 2U;
    }
    return !lines.empty();
}

inline bool ProtocolSupportsSafeCookie(const std::string& reply) {
    std::vector<std::string> lines;
    if (!StrictControlLines(reply, lines) || lines.size() < 3U ||
        lines.front() != "250-PROTOCOLINFO 1" || lines.back() != "250 OK")
        return false;
    bool found_auth = false;
    for (size_t i = 1; i + 1U < lines.size(); ++i) {
        const auto& line = lines[i];
        if (line.rfind("250-", 0) != 0) return false;
        static constexpr char auth_prefix[] = "250-AUTH METHODS=";
        if (line.rfind(auth_prefix, 0) != 0) continue;
        if (found_auth) return false;
        found_auth = true;
        const size_t begin = sizeof(auth_prefix) - 1U;
        const size_t end = line.find(' ', begin);
        const std::string methods = line.substr(begin, end - begin);
        if (methods.empty()) return false;
        bool safe_cookie = false;
        size_t cursor = 0;
        while (cursor < methods.size()) {
            const size_t comma = methods.find(',', cursor);
            const size_t token_end = comma == std::string::npos
                ? methods.size() : comma;
            if (token_end == cursor) return false;
            const std::string token = methods.substr(cursor,
                                                     token_end - cursor);
            for (const unsigned char character : token) {
                if (!(character >= 'A' && character <= 'Z') &&
                    !(character >= '0' && character <= '9') &&
                    character != '_') return false;
            }
            if (token == "SAFECOOKIE") safe_cookie = true;
            if (comma == std::string::npos) break;
            if (comma + 1U == methods.size()) return false;
            cursor = comma + 1U;
        }
        if (!safe_cookie) return false;
    }
    return found_auth;
}

inline bool ParseSafeCookieChallenge(
        const std::string& reply, std::array<uint8_t, 32>& server_hash,
        std::array<uint8_t, 32>& server_nonce) {
    std::vector<std::string> lines;
    if (!StrictControlLines(reply, lines) || lines.size() != 1U)
        return false;
    static constexpr char prefix[] =
        "250 AUTHCHALLENGE SERVERHASH=";
    const std::string& line = lines.front();
    if (line.rfind(prefix, 0) != 0) return false;
    const size_t hash_begin = sizeof(prefix) - 1U;
    const size_t nonce_label = line.find(" SERVERNONCE=", hash_begin);
    if (nonce_label == std::string::npos ||
        line.find(' ', nonce_label + 1U) != std::string::npos)
        return false;
    const std::string encoded_hash =
        line.substr(hash_begin, nonce_label - hash_begin);
    const std::string encoded_nonce =
        line.substr(nonce_label + std::strlen(" SERVERNONCE="));
    return DecodeExactHex(encoded_hash, server_hash) &&
           DecodeExactHex(encoded_nonce, server_nonce);
}

inline std::array<uint8_t, 32> SafeCookieHmac(
        const char* key, const std::array<uint8_t, 32>& cookie,
        const std::array<uint8_t, 32>& client_nonce,
        const std::array<uint8_t, 32>& server_nonce) {
    std::array<uint8_t, 96> message{};
    ScopedWipe<std::array<uint8_t, 96>> wipe_message{message};
    std::copy(cookie.begin(), cookie.end(), message.begin());
    std::copy(client_nonce.begin(), client_nonce.end(), message.begin() + 32);
    std::copy(server_nonce.begin(), server_nonce.end(), message.begin() + 64);
    return veld::wallet_crypto::HMAC_SHA256(
        reinterpret_cast<const uint8_t*>(key), std::strlen(key),
        message.data(), message.size());
}

inline bool ReadTrustedCookie(const std::string& data_directory,
                              std::array<uint8_t, 32>& cookie,
                              std::string& error) {
    namespace fs = std::filesystem;
    const fs::path root(data_directory);
    if (data_directory.empty() || !root.is_absolute() ||
        root.relative_path().empty()) {
        error = "Tor data directory must be an absolute local directory";
        return false;
    }
    for (const auto& component : root.relative_path()) {
        if (component == "." || component == ".." || component.empty()) {
            error = "Tor data directory must not contain traversal components";
            return false;
        }
    }

#ifdef _WIN32
    const std::wstring native = root.native();
    if (native.rfind(L"\\\\", 0) == 0) {
        error = "Tor data directory must be on a local volume";
        return false;
    }
    veld::channel::secure_file::WinOwnerSecurity owner;
    if (!owner.Initialize(&error)) return false;
    fs::path current = root.root_path();
    bool opened_component = false;
    for (const auto& component : root.relative_path()) {
        current /= component;
        veld::channel::secure_file::WinHandle handle(::CreateFileW(
            current.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr));
        BY_HANDLE_FILE_INFORMATION information{};
        if (!handle || ::GetFileType(handle.value) != FILE_TYPE_DISK ||
            !::GetFileInformationByHandle(handle.value, &information) ||
            !(information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            error = "Tor data directory traverses a missing or reparse component";
            return false;
        }
        opened_component = true;
        if (current == root &&
            !veld::channel::secure_file::HandleHasCurrentOwner(
                handle.value, owner.sid(), true, &error,
                "Tor data directory")) return false;
    }
    if (!opened_component) return false;
#else
    int directory = ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) {
        error = "cannot open Tor data-directory root";
        return false;
    }
    for (const auto& component : root.relative_path()) {
        const std::string name = component.string();
        const int next = ::openat(directory, name.c_str(),
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                  O_CLOEXEC);
        ::close(directory);
        directory = next;
        if (directory < 0) {
            error = "Tor data directory traverses a missing or symlink component";
            return false;
        }
    }
    struct stat directory_status{};
    if (::fstat(directory, &directory_status) != 0 ||
        !S_ISDIR(directory_status.st_mode) ||
        directory_status.st_uid != ::geteuid() ||
        (directory_status.st_mode & 0077) != 0) {
        ::close(directory);
        error = "Tor data directory must be owner-only";
        return false;
    }
    const int file = ::openat(directory, "control_auth_cookie",
                              O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    ::close(directory);
    if (file < 0) {
        error = "cannot securely open Tor control cookie";
        return false;
    }
    struct stat file_status{};
    if (::fstat(file, &file_status) != 0 ||
        !S_ISREG(file_status.st_mode) || file_status.st_nlink != 1 ||
        file_status.st_uid != ::geteuid() ||
        (file_status.st_mode & 0077) != 0) {
        ::close(file);
        error = "Tor control cookie must be owner-only, regular, and unlinked";
        return false;
    }
    size_t offset = 0;
    while (offset < cookie.size()) {
        const ssize_t count = ::read(file, cookie.data() + offset,
                                     cookie.size() - offset);
        if (count <= 0) {
            ::close(file);
            veld::compat::SecureZero(cookie.data(), cookie.size());
            error = "Tor control cookie must be exactly 32 bytes";
            return false;
        }
        offset += static_cast<size_t>(count);
    }
    uint8_t extra = 0;
    const ssize_t extra_count = ::read(file, &extra, 1);
    ::close(file);
    if (extra_count != 0) {
        veld::compat::SecureZero(cookie.data(), cookie.size());
        error = "Tor control cookie must be exactly 32 bytes";
        return false;
    }
    return true;
#endif

#ifdef _WIN32
    std::vector<uint8_t> bytes;
    const fs::path cookie_path = root / "control_auth_cookie";
    const auto result = veld::channel::secure_file::Read(
        cookie_path.string(), bytes, &error, cookie.size(), true);
    ScopedWipe<std::vector<uint8_t>> wipe_bytes{bytes};
    if (result != veld::channel::secure_file::ReadResult::Ok ||
        bytes.size() != cookie.size()) {
        error = "Tor control cookie must be exactly 32 protected bytes";
        return false;
    }
    std::copy(bytes.begin(), bytes.end(), cookie.begin());
    return true;
#endif
}

} // namespace _tor

// ---------------------------------------------------------------------------
//  SOCKS5 CONNECT through Tor (default 127.0.0.1:9050). Supports a hostname
//  target (domain type 0x03) so Tor resolves .onion. Returns a connected fd
//  the caller uses as a peer socket, or kInvalidSocket.
// ---------------------------------------------------------------------------
inline SocketHandle Socks5Connect(const std::string& host, uint16_t port,
                                  const std::string& proxy_ip = "127.0.0.1",
                                  uint16_t proxy_port = 9050, int timeout_ms = 12000) {
    if (host.size() > 255) return veld::compat::kInvalidSocket;
    SocketHandle s = _tor::DialLocal(proxy_ip, proxy_port, timeout_ms);
    if (!veld::compat::IsValidSocket(s)) return veld::compat::kInvalidSocket;

    // greeting: ver=5, 1 method, 0x00 (no-auth)
    const uint8_t greet[3] = {0x05, 0x01, 0x00};
    if (!_tor::SendAll(s, (const char*)greet, 3)) { VELD_CLOSE_SOCKET(s); return veld::compat::kInvalidSocket; }
    uint8_t gresp[2] = {0};
    if ((int)::recv(s, (char*)gresp, 2, 0) != 2 || gresp[0] != 0x05 || gresp[1] != 0x00) {
        VELD_CLOSE_SOCKET(s); return veld::compat::kInvalidSocket;
    }
    // CONNECT request: ver=5, cmd=1(connect), rsv=0, atyp=3(domain), len, host, port
    std::vector<uint8_t> req;
    req.push_back(0x05); req.push_back(0x01); req.push_back(0x00);
    req.push_back(0x03); req.push_back((uint8_t)host.size());
    req.insert(req.end(), host.begin(), host.end());
    req.push_back((uint8_t)(port >> 8)); req.push_back((uint8_t)(port & 0xFF));
    if (!_tor::SendAll(s, (const char*)req.data(), req.size())) { VELD_CLOSE_SOCKET(s); return veld::compat::kInvalidSocket; }
    // reply: ver, rep, rsv, atyp, bnd.addr, bnd.port. rep==0 => success.
    uint8_t rhdr[4] = {0};
    if ((int)::recv(s, (char*)rhdr, 4, 0) != 4 || rhdr[0] != 0x05 || rhdr[1] != 0x00) {
        VELD_CLOSE_SOCKET(s); return veld::compat::kInvalidSocket;
    }
    // drain the bound address per atyp (4=IPv4 / 16=IPv6 / 1+len=domain) + 2 port
    int skip = 0;
    if (rhdr[3] == 0x01) skip = 4 + 2;
    else if (rhdr[3] == 0x04) skip = 16 + 2;
    else if (rhdr[3] == 0x03) { uint8_t l = 0; if ((int)::recv(s, (char*)&l, 1, 0) != 1) { VELD_CLOSE_SOCKET(s); return veld::compat::kInvalidSocket; } skip = l + 2; }
    else { VELD_CLOSE_SOCKET(s); return veld::compat::kInvalidSocket; }
    char drain[300];
    while (skip > 0) {
        int n = (int)::recv(s, drain, std::min(skip, (int)sizeof(drain)), 0);
        if (n <= 0) { VELD_CLOSE_SOCKET(s); return veld::compat::kInvalidSocket; }
        skip -= n;
    }
    return s;   // tunnel established; caller proceeds with the veld handshake
}

class TorController {
public:
    TorController() = default;
    ~TorController() { Stop(); }
    TorController(const TorController&)            = delete;
    TorController& operator=(const TorController&) = delete;

    // Connect to the control port, authenticate, and publish a v3 onion that
    // forwards <onion>:p2p_port -> 127.0.0.1:p2p_port. Returns true on success
    // (OnionAddress() then holds "<id>.onion"). The control connection is kept
    // open for the node's lifetime — the ephemeral onion lives while it is open.
    bool Start(uint16_t p2p_port, const std::string& tor_data_directory,
               const std::string& control_ip = "127.0.0.1",
               uint16_t control_port = 9051) {
        std::lock_guard<std::mutex> lk(mu_);
        if (active_) return true;
        SocketHandle s = _tor::DialLocal(control_ip, control_port, 6000);
        if (!veld::compat::IsValidSocket(s)) {
            std::cout << "  [tor] no control port at " << control_ip << ":" << control_port
                      << " — is Tor running with ControlPort enabled? (clearnet unaffected)\n";
            return false;
        }
        if (!Authenticate(s, tor_data_directory)) {
            std::cout << "  [tor] SAFECOOKIE control authentication failed; "
                         "verify the configured owner-only Tor data directory.\n";
            VELD_CLOSE_SOCKET(s);
            return false;
        }
        // ADD_ONION: new ed25519-v3 key, map the P2P port.
        std::string cmd = "ADD_ONION NEW:ED25519-V3 Port=" + std::to_string(p2p_port) +
                          ",127.0.0.1:" + std::to_string(p2p_port) + "\r\n";
        if (!_tor::SendAll(s, cmd.c_str(), cmd.size())) { VELD_CLOSE_SOCKET(s); return false; }
        std::string reply = _tor::ReadControlReply(s);
        std::string sid = Extract(reply, "ServiceID=");
        if (sid.empty()) {
            std::cout << "  [tor] ADD_ONION failed: " << FirstLine(reply) << "\n";
            VELD_CLOSE_SOCKET(s);
            return false;
        }
        control_fd_ = s;          // keep open -> the onion persists
        onion_ = sid + ".onion";
        active_ = true;
        std::cout << "  [tor] reachable as " << onion_ << ":" << p2p_port
                  << " (v3 hidden service; zero IP exposure).\n";
        return true;
    }

    void Stop() {
        std::lock_guard<std::mutex> lk(mu_);
        if (veld::compat::IsValidSocket(control_fd_)) {
            VELD_CLOSE_SOCKET(control_fd_);
            control_fd_ = veld::compat::kInvalidSocket;
        }
        active_ = false;
    }

    bool        Active()       const { std::lock_guard<std::mutex> lk(mu_); return active_; }
    std::string OnionAddress() const { std::lock_guard<std::mutex> lk(mu_); return onion_; }

private:
    static std::string FirstLine(const std::string& s) {
        size_t e = s.find("\r\n");
        return s.substr(0, e == std::string::npos ? s.size() : e);
    }
    static std::string Extract(const std::string& s, const std::string& key) {
        size_t p = s.find(key);
        if (p == std::string::npos) return "";
        p += key.size();
        size_t e = p;
        while (e < s.size() && s[e] != '\r' && s[e] != '\n' && s[e] != ' ') ++e;
        return s.substr(p, e - p);
    }

    bool Authenticate(SocketHandle s, const std::string& tor_data_directory) {
        // PROTOCOLINFO is advisory only for method negotiation.  In
        // particular, never open the server-supplied COOKIEFILE path.
        const char* pi = "PROTOCOLINFO 1\r\n";
        std::string proto;
        if (!_tor::SendAll(s, pi, std::strlen(pi))) return false;
        proto = _tor::ReadControlReply(s);
        if (!_tor::ProtocolSupportsSafeCookie(proto)) return false;

        std::array<uint8_t, 32> cookie{};
        std::array<uint8_t, 32> client_nonce{};
        std::array<uint8_t, 32> server_nonce{};
        std::array<uint8_t, 32> server_hash{};
        std::array<uint8_t, 32> expected_server_hash{};
        std::array<uint8_t, 32> controller_hash{};
        _tor::ScopedWipe<std::array<uint8_t, 32>> wipe_cookie{cookie};
        _tor::ScopedWipe<std::array<uint8_t, 32>> wipe_client{client_nonce};
        _tor::ScopedWipe<std::array<uint8_t, 32>> wipe_server_nonce{server_nonce};
        _tor::ScopedWipe<std::array<uint8_t, 32>> wipe_server_hash{server_hash};
        _tor::ScopedWipe<std::array<uint8_t, 32>> wipe_expected{expected_server_hash};
        _tor::ScopedWipe<std::array<uint8_t, 32>> wipe_controller{controller_hash};
        std::string cookie_error;
        if (!_tor::ReadTrustedCookie(tor_data_directory, cookie,
                                     cookie_error) ||
            !veld::compat::SecureRandom(client_nonce.data(),
                                        client_nonce.size()))
            return false;

        std::string command = "AUTHCHALLENGE SAFECOOKIE " +
                              _tor::Hex(client_nonce) + "\r\n";
        _tor::ScopedWipe<std::string> wipe_command{command};
        if (!_tor::SendAll(s, command.data(), command.size())) return false;
        const std::string challenge = _tor::ReadControlReply(s);
        if (!_tor::ParseSafeCookieChallenge(challenge, server_hash,
                                             server_nonce)) return false;
        if (have_last_server_nonce_ &&
            veld::compat::ConstantTimeEqual(
                last_server_nonce_.data(), server_nonce.data(),
                server_nonce.size())) return false;

        static constexpr char server_key[] =
            "Tor safe cookie authentication server-to-controller hash";
        static constexpr char controller_key[] =
            "Tor safe cookie authentication controller-to-server hash";
        expected_server_hash = _tor::SafeCookieHmac(
            server_key, cookie, client_nonce, server_nonce);
        if (!veld::compat::ConstantTimeEqual(
                expected_server_hash.data(), server_hash.data(),
                server_hash.size())) return false;
        controller_hash = _tor::SafeCookieHmac(
            controller_key, cookie, client_nonce, server_nonce);

        command.assign("AUTHENTICATE ");
        command += _tor::Hex(controller_hash);
        command += "\r\n";
        if (!_tor::SendAll(s, command.data(), command.size()) ||
            _tor::ReadControlReply(s) != "250 OK\r\n") return false;
        last_server_nonce_ = server_nonce;
        have_last_server_nonce_ = true;
        return true;
    }

    mutable std::mutex mu_;
    SocketHandle      control_fd_ = veld::compat::kInvalidSocket;
    bool              active_ = false;
    std::string       onion_;
    std::array<uint8_t, 32> last_server_nonce_{};
    bool              have_last_server_nonce_ = false;
};

} // namespace net
} // namespace veld
