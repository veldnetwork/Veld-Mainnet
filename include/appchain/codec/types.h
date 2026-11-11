#pragma once
#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>
namespace app {
using Bytes = std::vector<uint8_t>;
using Id = std::array<uint8_t, 48>;
constexpr uint64_t MAX = 9223372036854775807ULL;
struct Invalid : std::runtime_error {
    using std::runtime_error::runtime_error;
};
inline void need(bool ok, const char* error) {
    if (!ok)
        throw Invalid(error);
}
inline uint64_t add(uint64_t a, uint64_t b) {
    need(a <= MAX && b <= MAX - a, "amount overflow");
    return a + b;
}
inline void debit(uint64_t& a, uint64_t b) {
    need(a >= b, "insufficient balance");
    a -= b;
}
inline void credit(uint64_t& a, uint64_t b) {
    a = add(a, b);
}
struct Writer {
    Bytes b;
    void n(uint64_t v, unsigned width) {
        need(width > 0 && width <= 8 && (width == 8 || v < (uint64_t(1) << (width * 8))),
             "integer width or overflow");
        for (unsigned i = 0; i < width; i++)
            b.push_back(uint8_t(v >> (i * 8)));
    }
    void raw(std::span<const uint8_t> v) {
        b.insert(b.end(), v.begin(), v.end());
    }
    void str(std::span<const uint8_t> v, size_t limit) {
        need(v.size() <= limit, "field bound");
        n(v.size(), 4);
        raw(v);
    }
};
struct Reader {
    std::span<const uint8_t> b;
    size_t pos = 0;
    uint64_t n(unsigned width) {
        need(width <= 8 && width <= b.size() - pos, "truncated integer");
        uint64_t v = 0;
        for (unsigned i = 0; i < width; i++)
            v |= uint64_t(b[pos++]) << (8 * i);
        return v;
    }
    Bytes raw(size_t size) {
        need(size <= b.size() - pos, "truncated bytes");
        Bytes v(b.begin() + pos, b.begin() + pos + size);
        pos += size;
        return v;
    }
    Id id() {
        auto v = raw(48);
        Id x{};
        std::copy(v.begin(), v.end(), x.begin());
        return x;
    }
    Bytes str(size_t limit) {
        auto size = n(4);
        need(size <= limit, "field bound");
        return raw(size);
    }
    void end() {
        need(pos == b.size(), "trailing bytes");
    }
};
inline Id hash(const std::string& domain, std::span<const uint8_t> bytes) {
    Writer w;
    w.str(std::span(reinterpret_cast<const uint8_t*>(domain.data()), domain.size()), 128);
    w.str(bytes, 1ULL << 30);
    Id out{};
    SHA384(w.b.data(), w.b.size(), out.data());
    return out;
}
inline std::string hex(std::span<const uint8_t> b) {
    std::string s;
    for (auto n : b) {
        s += "0123456789abcdef"[n >> 4];
        s += "0123456789abcdef"[n & 15];
    }
    return s;
}
inline Bytes unhex(const std::string& s, size_t max = 1048576) {
    need(s.size() % 2 == 0 && s.size() / 2 <= max, "hex size");
    Bytes b;
    for (size_t i = 0; i < s.size(); i += 2) {
        unsigned n = 0;
        for (size_t j = i; j < i + 2; j++) {
            auto p = std::string("0123456789abcdef").find(s[j]);
            need(p < 16, "canonical lowercase hex");
            n = n * 16 + p;
        }
        b.push_back(n);
    }
    return b;
}
using BNPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
inline BNPtr bn(uint64_t x = 0) {
    BNPtr n(BN_new(), BN_free);
    need(bool(n), "bignum allocation");
    uint8_t b[8];
    for (int i = 0; i < 8; i++)
        b[7 - i] = uint8_t(x >> (8 * i));
    need(BN_bin2bn(b, 8, n.get()) != nullptr, "bignum decode");
    return n;
}
inline uint64_t narrow(const BIGNUM* n) {
    need(!BN_is_negative(n) && BN_num_bits(n) <= 63, "integer narrowing");
    uint8_t b[8];
    need(BN_bn2binpad(n, b, 8) == 8, "integer encoding");
    uint64_t x = 0;
    for (auto v : b)
        x = (x << 8) | v;
    return x;
}
inline uint64_t muldiv(uint64_t a, uint64_t b, uint64_t c, bool ceil = false) {
    need(c > 0, "zero divisor");
    auto A = bn(a), B = bn(b), C = bn(c), P = bn(), Q = bn(), R = bn();
    auto ctx = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>(BN_CTX_new(), BN_CTX_free);
    need(bool(ctx), "BN context");
    need(BN_mul(P.get(), A.get(), B.get(), ctx.get()) && BN_num_bits(P.get()) <= 256 &&
             BN_div(Q.get(), R.get(), P.get(), C.get(), ctx.get()),
         "wide arithmetic");
    auto q = narrow(Q.get());
    return ceil && !BN_is_zero(R.get()) ? add(q, 1) : q;
}
inline uint64_t parseDecimal(const std::string& s, unsigned digits) {
    need(!s.empty() && s.size() <= 32 && digits <= 8, "decimal format");
    auto point = s.find('.');
    auto whole = s.substr(0, point);
    auto fraction = point == std::string::npos ? std::string{} : s.substr(point + 1);
    need(!whole.empty() && (whole.size() == 1 || whole[0] != '0') && fraction.size() <= digits &&
             (point == std::string::npos || !fraction.empty()),
         "decimal syntax");
    uint64_t value = 0;
    for (char c : whole + fraction) {
        need(c >= '0' && c <= '9', "decimal character");
        need(value <= (MAX - uint64_t(c - '0')) / 10, "decimal overflow");
        value = value * 10 + (c - '0');
    }
    for (size_t i = fraction.size(); i < digits; i++) {
        need(value <= MAX / 10, "decimal overflow");
        value *= 10;
    }
    return value;
}
inline std::string display(uint64_t x, unsigned digits) {
    need(x <= MAX && digits <= 8, "display bound");
    if (digits == 0)
        return std::to_string(x);
    uint64_t scale = 1;
    for (unsigned i = 0; i < digits; i++)
        scale *= 10;
    auto f = std::to_string(x % scale);
    return std::to_string(x / scale) + "." + std::string(digits - f.size(), '0') + f;
}
inline uint64_t fuelAtoms(const std::string& s) {
    return parseDecimal(s, 5);
}
inline std::string fuelDisplay(uint64_t x) {
    return display(x, 5);
}
inline uint64_t fee(uint64_t gas, uint64_t ppm) {
    return muldiv(gas, ppm, 1000000, true);
}
} // namespace app
