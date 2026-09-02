#pragma once
// Pure Bitcoin proof-of-work arithmetic for the btcVELD SPV relay.
//
// The 80-byte-header SHA256d hash, the compact-target (nBits) codec, 256-bit
// target arithmetic, the PoW check, cumulative block work, and the 2016-block
// difficulty retarget, all matching Bitcoin mainnet consensus. This is the most consensus-critical
// arithmetic in the peg: a wrong target comparison would accept a forged BTC
// header, hence a fake deposit, hence an unbacked mint.
//
// The 256-bit type is modeled bit-for-bit on Bitcoin Core's arith_uint256
// (little-endian uint32 words, pn[0] = least significant) so the retarget and
// SetCompact/GetCompact match Bitcoin consensus exactly. No deps beyond a
// SHA-256 primitive.
//
#include <cstdint>
#include <cstring>
#include <array>
#include <vector>
#include "core/hash.h"   // veld::Hash256 (== std::array<uint8_t,32>), veld::Hash256d (SHA256d)

namespace veld {
namespace btcspv {

// ─────────────────────────────────────────────────────────────────────────────
//  U256 — 256-bit unsigned integer, little-endian 32-bit limbs (w[0] = LSB).
//  Mirrors Bitcoin Core base_uint<256>.
// ─────────────────────────────────────────────────────────────────────────────
struct U256 {
    uint32_t w[8];

    U256() { std::memset(w, 0, sizeof(w)); }
    static U256 Zero() { return U256(); }
    static U256 FromU64(uint64_t v) {
        U256 r; r.w[0] = (uint32_t)(v & 0xffffffffu); r.w[1] = (uint32_t)(v >> 32); return r;
    }

    bool IsZero() const { for (int i = 0; i < 8; ++i) if (w[i]) return false; return true; }

    // three-way compare
    int cmp(const U256& o) const {
        for (int i = 7; i >= 0; --i) { if (w[i] < o.w[i]) return -1; if (w[i] > o.w[i]) return 1; }
        return 0;
    }
    bool operator< (const U256& o) const { return cmp(o) <  0; }
    bool operator<=(const U256& o) const { return cmp(o) <= 0; }
    bool operator> (const U256& o) const { return cmp(o) >  0; }
    bool operator>=(const U256& o) const { return cmp(o) >= 0; }
    bool operator==(const U256& o) const { return cmp(o) == 0; }
    bool operator!=(const U256& o) const { return cmp(o) != 0; }

    U256 operator~() const { U256 r; for (int i = 0; i < 8; ++i) r.w[i] = ~w[i]; return r; }

    // addition mod 2^256; *carry_out set to the 257th bit if provided
    U256 operator+(const U256& o) const {
        U256 r; uint64_t carry = 0;
        for (int i = 0; i < 8; ++i) { uint64_t s = (uint64_t)w[i] + o.w[i] + carry; r.w[i] = (uint32_t)s; carry = s >> 32; }
        return r;
    }
    U256 addCarry(const U256& o, bool* carry_out) const {
        U256 r; uint64_t carry = 0;
        for (int i = 0; i < 8; ++i) { uint64_t s = (uint64_t)w[i] + o.w[i] + carry; r.w[i] = (uint32_t)s; carry = s >> 32; }
        if (carry_out) *carry_out = (carry != 0);
        return r;
    }
    // subtraction mod 2^256 (assumes *this >= o for exact results)
    U256 operator-(const U256& o) const {
        U256 r; int64_t borrow = 0;
        for (int i = 0; i < 8; ++i) { int64_t d = (int64_t)w[i] - o.w[i] - borrow; if (d < 0) { d += (int64_t)1 << 32; borrow = 1; } else borrow = 0; r.w[i] = (uint32_t)d; }
        return r;
    }

    // multiply by a 32-bit scalar; *overflow set if the product exceeds 256 bits
    U256 mulU32(uint32_t m, bool* overflow = nullptr) const {
        U256 r; uint64_t carry = 0;
        for (int i = 0; i < 8; ++i) { uint64_t p = (uint64_t)w[i] * m + carry; r.w[i] = (uint32_t)p; carry = p >> 32; }
        if (overflow) *overflow = (carry != 0);
        return r;
    }
    // divide by a 32-bit scalar (m != 0); returns quotient, *rem set to remainder
    U256 divU32(uint32_t m, uint32_t* rem = nullptr) const {
        U256 q; uint64_t r = 0;
        for (int i = 7; i >= 0; --i) { uint64_t cur = (r << 32) | w[i]; q.w[i] = (uint32_t)(cur / m); r = cur % m; }
        if (rem) *rem = (uint32_t)r;
        return q;
    }

    // bit helpers
    int getbit(int i) const { return (w[i >> 5] >> (i & 31)) & 1u; }
    void setbit(int i)      { w[i >> 5] |= (1u << (i & 31)); }
    // index of the highest set bit + 1 (0 for zero)
    int bitLength() const {
        for (int i = 7; i >= 0; --i) if (w[i]) { uint32_t x = w[i]; int b = 0; while (x) { x >>= 1; ++b; } return i * 32 + b; }
        return 0;
    }
    uint64_t low64() const { return (uint64_t)w[0] | ((uint64_t)w[1] << 32); }

    U256 shlBits(unsigned n) const {
        U256 r; if (n >= 256) return r;
        unsigned wordShift = n >> 5, bitShift = n & 31;
        for (int i = 7; i >= 0; --i) {
            int src = i - (int)wordShift;
            uint64_t v = 0;
            if (src >= 0)       v  |= (uint64_t)w[src] << bitShift;
            if (bitShift && src - 1 >= 0) v |= (uint64_t)w[src - 1] >> (32 - bitShift);
            r.w[i] = (uint32_t)v;
        }
        return r;
    }
    U256 shrBits(unsigned n) const {
        U256 r; if (n >= 256) return r;
        unsigned wordShift = n >> 5, bitShift = n & 31;
        for (int i = 0; i < 8; ++i) {
            int src = i + (int)wordShift;
            uint64_t v = 0;
            if (src < 8)        v |= (uint64_t)w[src] >> bitShift;
            if (bitShift && src + 1 < 8) v |= (uint64_t)w[src + 1] << (32 - bitShift);
            r.w[i] = (uint32_t)v;
        }
        return r;
    }

    // full 256/256 division (shift-subtract long division). divisor != 0.
    U256 div(const U256& divisor, U256* remainder = nullptr) const {
        U256 q, r;
        int n = bitLength();
        for (int i = n - 1; i >= 0; --i) {
            r = r.shlBits(1);
            if (getbit(i)) r.w[0] |= 1u;
            if (r >= divisor) { r = r - divisor; q.setbit(i); }
        }
        if (remainder) *remainder = r;
        return q;
    }
};

// ── compact target (nBits) codec — exact Bitcoin SetCompact/GetCompact ──
inline U256 CompactToTarget(uint32_t bits, bool* negative = nullptr, bool* overflow = nullptr) {
    int      size = bits >> 24;
    uint32_t word = bits & 0x007fffffu;
    U256 r;
    if (size <= 3) { word >>= 8 * (3 - size); r = U256::FromU64(word); }
    else           { r = U256::FromU64(word); r = r.shlBits(8 * (size - 3)); }
    if (negative) *negative = (word != 0) && ((bits & 0x00800000u) != 0);
    if (overflow) *overflow = (word != 0) && ((size > 34) ||
                              (word > 0xffu   && size > 33) ||
                              (word > 0xffffu && size > 32));
    return r;
}

inline uint32_t TargetToCompact(const U256& t) {
    int size = (t.bitLength() + 7) / 8;
    uint32_t compact;
    if (size <= 3) compact = (uint32_t)(t.low64() << (8 * (3 - size)));
    else           compact = (uint32_t)(t.shrBits(8 * (size - 3)).low64());
    // the mantissa is signed in the compact form; if bit 23 is set, bump the exponent
    if (compact & 0x00800000u) { compact >>= 8; ++size; }
    compact |= (uint32_t)size << 24;
    return compact;   // sign bit (0x00800000) left clear — PoW targets are positive
}

// ── SHA256d over the 80-byte header → 32-byte block hash (internal/LE order) ──
inline std::array<uint8_t,32> BtcHeaderHash(const uint8_t hdr[80]) {
    return ::veld::Hash256d(hdr, 80);   // Hash256 == std::array<uint8_t,32>
}

// interpret a 32-byte block hash as a little-endian 256-bit integer
inline U256 HashToU256(const std::array<uint8_t,32>& h) {
    U256 r;
    for (int i = 0; i < 8; ++i)
        r.w[i] = (uint32_t)h[i*4] | ((uint32_t)h[i*4+1] << 8) |
                 ((uint32_t)h[i*4+2] << 16) | ((uint32_t)h[i*4+3] << 24);
    return r;
}

// ── PoW gate: SHA256d(header) ≤ target(nBits), with the same sanity bounds
//    Bitcoin's CheckProofOfWork enforces (target in (0, pow_limit]). ──
inline bool CheckProofOfWork(const uint8_t hdr[80], uint32_t bits, const U256& pow_limit) {
    bool neg = false, over = false;
    U256 target = CompactToTarget(bits, &neg, &over);
    if (neg || over || target.IsZero() || target > pow_limit) return false;
    return HashToU256(BtcHeaderHash(hdr)) <= target;
}

// ── cumulative work of a block: 2^256 / (target+1) == (~target / (target+1)) + 1 ──
inline U256 BlockWork(const U256& target) {
    // (~target / (target+1)) + 1 — avoids the 2^256 that doesn't fit in 256 bits.
    U256 tp1 = target + U256::FromU64(1);
    if (tp1.IsZero()) return U256::Zero();          // target == max → work 0 (never on mainnet)
    U256 num = ~target;                              // = 2^256 - 1 - target
    return num.div(tp1) + U256::FromU64(1);
}

// ── 2016-block difficulty retarget — exact Bitcoin CalculateNextWorkRequired ──
//    actual_timespan = last_block_time - first_block_time (of the 2016-block epoch),
//    clamped to [T/4, 4T]; new_target = old_target * clamped / T, capped at pow_limit.
inline uint32_t CalcNextBits(uint32_t old_bits, int64_t actual_timespan,
                             const U256& pow_limit,
                             int64_t target_timespan = 14 * 24 * 60 * 60 /* 1209600 */) {
    if (actual_timespan < target_timespan / 4) actual_timespan = target_timespan / 4;
    if (actual_timespan > target_timespan * 4) actual_timespan = target_timespan * 4;
    U256 t = CompactToTarget(old_bits);
    // actual_timespan (≤ 4·1209600 ≈ 2^23) and target_timespan both fit in uint32.
    t = t.mulU32((uint32_t)actual_timespan);
    t = t.divU32((uint32_t)target_timespan);
    if (t > pow_limit) t = pow_limit;
    return TargetToCompact(t);
}

// mainnet proof-of-work limit (difficulty-1 target, nBits 0x1d00ffff)
inline U256 MainnetPowLimit() { return CompactToTarget(0x1d00ffffu); }

}  // namespace btcspv
}  // namespace veld
