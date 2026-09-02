#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#include "../crypto/vendored.h"

namespace veld {

using Hash256 = std::array<uint8_t, 32>;

inline Hash256 ZeroHash() {
    Hash256 h{};
    h.fill(0);
    return h;
}

inline std::string BytesToHex(const uint8_t* data, size_t len) {
    static constexpr char HEX[] = "0123456789abcdef";
    std::string result(len * 2, '0');
    for (size_t i = 0; i < len; ++i) {
        result[i*2    ] = HEX[(data[i] >> 4) & 0xF];
        result[i*2 + 1] = HEX[ data[i]       & 0xF];
    }
    return result;
}

inline std::string BytesToHex(const std::vector<uint8_t>& v) {
    return BytesToHex(v.data(), v.size());
}

inline std::string BytesToHex(const Hash256& h) {
    return BytesToHex(h.data(), h.size());
}

inline std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> out;
    if (hex.size() % 2 != 0) return out;
    out.reserve(hex.size() / 2);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nibble(hex[i]);
        int lo = nibble(hex[i+1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return out;
}

inline std::string HashToHex(const Hash256& hash) {
    static constexpr char HEX[] = "0123456789abcdef";
    std::string result(64, '0');
    for (size_t i = 0; i < 32; ++i) {
        result[i*2    ] = HEX[(hash[i] >> 4) & 0xF];
        result[i*2 + 1] = HEX[ hash[i]       & 0xF];
    }
    return result;
}

inline Hash256 HexToHash(const std::string& hex) {
    Hash256 hash{};
    auto hc = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
        if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
        return 0;
    };
    for (size_t i = 0; i < 32 && i * 2 + 1 < hex.size(); ++i)
        hash[i] = (hc(hex[i*2]) << 4) | hc(hex[i*2+1]);
    return hash;
}

inline bool HashLessThan(const Hash256& a, const Hash256& b) {
    return a < b;
}

inline bool HashIsZero(const Hash256& h) {
    for (auto byte : h) if (byte != 0) return false;
    return true;
}

class SHA256 {
public:
    static constexpr size_t DIGEST_SIZE = 32;

    SHA256() { reset(); }

    void reset() { sha_.reset(); }

    void update(const uint8_t* data, size_t len) {
        if (len > 0) sha_.update(data, len);
    }

    void update(const std::vector<uint8_t>& data) {
        update(data.data(), data.size());
    }

    void update(const std::string& s) {
        update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    Hash256 digest() {
        Hash256 result{};
        sha_.finalize(result.data());
        sha_.reset();
        return result;
    }

private:
    ::veld::vendored_crypto::Sha256 sha_;
};

inline Hash256 Hash256d(const uint8_t* data, size_t len) {
    SHA256 h1;
    h1.update(data, len);
    Hash256 first = h1.digest();

    SHA256 h2;
    h2.update(first.data(), first.size());
    return h2.digest();
}

inline Hash256 Hash256d(const std::vector<uint8_t>& data) {
    return Hash256d(data.data(), data.size());
}

inline Hash256 Hash256d(const std::string& s) {
    return Hash256d(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

}
