#pragma once

// Authenticated reverse-proxy identity boundary shared by public HTTP
// services.  Ordinary forwarding headers are deliberately not accepted:
// only an explicitly configured socket peer may attach a client identity,
// and it must authenticate that metadata with an owner-only token.

#include "../compat/platform.h"
#include "../wallet/secure_channel_file.h"

#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace veld::net::trusted_proxy {

inline constexpr const char* kAuthorizationHeader = "x-veld-proxy-authorization";
inline constexpr const char* kClientIpHeader = "x-veld-client-ip";

inline int HexNibble(char c) noexcept {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

inline bool DecodeToken(std::string_view text, std::array<uint8_t, 32>& out) noexcept {
    if (text.size() != 64)
        return false;
    std::array<uint8_t, 32> parsed{};
    for (size_t i = 0; i < parsed.size(); ++i) {
        const int hi = HexNibble(text[i * 2]);
        const int lo = HexNibble(text[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            veld::compat::SecureZero(parsed.data(), parsed.size());
            return false;
        }
        parsed[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    out = parsed;
    veld::compat::SecureZero(parsed.data(), parsed.size());
    return true;
}

inline bool ConstantTimeEqual(const std::array<uint8_t, 32>& a,
                              const std::array<uint8_t, 32>& b) noexcept {
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

// Canonicalize a single address literal.  IPv4-mapped IPv6 is folded into
// the IPv4 key so one client cannot acquire two quota identities.
inline bool CanonicalIp(const std::string& input, std::string& out) {
    if (input.empty() || input.size() > 64)
        return false;
    for (unsigned char c : input)
        if (c <= 0x20 || c == 0x7f || c == '%' || c == ',' || c == '[' || c == ']')
            return false;

    in_addr v4{};
    char buf[INET6_ADDRSTRLEN]{};
    if (::inet_pton(AF_INET, input.c_str(), &v4) == 1) {
        if (!::inet_ntop(AF_INET, &v4, buf, sizeof(buf)))
            return false;
        out.assign(buf);
        return out.size() <= 45;
    }

    in6_addr v6{};
    if (::inet_pton(AF_INET6, input.c_str(), &v6) != 1)
        return false;
    const uint8_t* b = reinterpret_cast<const uint8_t*>(&v6);
    bool mapped = true;
    for (size_t i = 0; i < 10; ++i)
        mapped &= b[i] == 0;
    mapped &= b[10] == 0xff && b[11] == 0xff;
    if (mapped) {
        std::memcpy(&v4, b + 12, sizeof(v4));
        if (!::inet_ntop(AF_INET, &v4, buf, sizeof(buf)))
            return false;
    } else if (!::inet_ntop(AF_INET6, &v6, buf, sizeof(buf))) {
        return false;
    }
    out.assign(buf);
    return out.size() <= 45;
}

struct Configuration {
    bool enabled = false;
    std::string peer;
    std::array<uint8_t, 32> token{};

    ~Configuration() {
        veld::compat::SecureZero(token.data(), token.size());
    }
};

inline bool LoadTokenFile(const std::string& path, std::array<uint8_t, 32>& token,
                          std::string* error = nullptr) {
    std::vector<uint8_t> bytes;
    const auto status = channel::secure_file::Read(path, bytes, error, 66, true);
    if (status != channel::secure_file::ReadResult::Ok)
        return false;
    while (!bytes.empty() && (bytes.back() == '\n' || bytes.back() == '\r'))
        bytes.pop_back();
    std::string encoded(bytes.begin(), bytes.end());
    const bool ok = DecodeToken(encoded, token);
    channel::secure_file::WipeAndClear(bytes);
    if (!encoded.empty())
        veld::compat::SecureZero(encoded.data(), encoded.size());
    if (!ok && error)
        *error = "proxy token must be exactly 64 lowercase hex characters";
    return ok;
}

inline bool Configure(Configuration& out, const std::string& peer, const std::string& token_file,
                      std::string* error = nullptr) {
    std::string canonical_peer;
    if (!CanonicalIp(peer, canonical_peer)) {
        if (error)
            *error = "trusted proxy peer must be one canonical IP literal";
        return false;
    }
    std::array<uint8_t, 32> token{};
    if (!LoadTokenFile(token_file, token, error))
        return false;
    out.peer = std::move(canonical_peer);
    out.token = token;
    out.enabled = true;
    veld::compat::SecureZero(token.data(), token.size());
    return true;
}

struct Resolution {
    bool accepted = false;
    bool forwarded = false;
    std::string identity;
    std::string error;
};

inline Resolution Resolve(const Configuration& config, const std::string& socket_peer,
                          const std::unordered_map<std::string, std::string>& headers,
                          bool ambiguous_headers = false) {
    Resolution result;
    std::string peer;
    if (ambiguous_headers || !CanonicalIp(socket_peer, peer)) {
        result.error = "ambiguous or invalid proxy metadata";
        return result;
    }
    const auto auth_it = headers.find(kAuthorizationHeader);
    const auto ip_it = headers.find(kClientIpHeader);
    const bool has_auth = auth_it != headers.end();
    const bool has_client = ip_it != headers.end();
    const bool has_legacy = headers.count("x-forwarded-for") != 0 ||
                            headers.count("x-real-ip") != 0 || headers.count("forwarded") != 0;

    if (has_legacy || has_auth != has_client) {
        result.error = "untrusted forwarding metadata";
        return result;
    }
    if (!has_auth) {
        result.accepted = true;
        result.identity = "peer:" + peer;
        return result;
    }
    if (!config.enabled || peer != config.peer) {
        result.error = "forwarding metadata from an untrusted peer";
        return result;
    }
    static constexpr const char kPrefix[] = "VeldProxy v1=";
    const std::string& authorization = auth_it->second;
    if (authorization.size() != sizeof(kPrefix) - 1 + 64 ||
        authorization.compare(0, sizeof(kPrefix) - 1, kPrefix) != 0) {
        result.error = "proxy authentication failed";
        return result;
    }
    std::array<uint8_t, 32> supplied{};
    if (!DecodeToken(std::string_view(authorization).substr(sizeof(kPrefix) - 1), supplied) ||
        !ConstantTimeEqual(config.token, supplied)) {
        veld::compat::SecureZero(supplied.data(), supplied.size());
        result.error = "proxy authentication failed";
        return result;
    }
    veld::compat::SecureZero(supplied.data(), supplied.size());
    std::string client;
    if (!CanonicalIp(ip_it->second, client)) {
        result.error = "invalid forwarded client identity";
        return result;
    }
    result.accepted = true;
    result.forwarded = true;
    result.identity = "client:" + client;
    return result;
}

} // namespace veld::net::trusted_proxy
