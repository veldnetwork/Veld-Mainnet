#pragma once
#include "../compat/platform.h"
#include "../core/hash.h"
#include "../crypto/vendored.h"
#include <array>
#include <vector>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <limits>
#include <stdexcept>

namespace veld {
namespace wallet_crypto {

template <typename ByteContainer> struct ScopedByteWipe {
    ByteContainer& value;
    ~ScopedByteWipe() {
        if (!value.empty())
            veld::compat::SecureZero(value.data(), value.size());
    }
};

inline std::array<uint8_t, 32> HMAC_SHA256(const uint8_t* key, size_t klen, const uint8_t* msg,
                                           size_t mlen) {
    if ((klen != 0 && key == nullptr) || (mlen != 0 && msg == nullptr))
        throw std::invalid_argument("HMAC-SHA256 received a null input");
    constexpr size_t B = 64;
    uint8_t k[B] = {};
    if (klen > B) {
        SHA256 h;
        h.update(key, klen);
        auto d = h.digest();
        memcpy(k, d.data(), 32);
    } else if (klen != 0) {
        memcpy(k, key, klen);
    }
    uint8_t ipad[B], opad[B];
    for (size_t i = 0; i < B; ++i) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    SHA256 inner;
    inner.update(ipad, B);
    inner.update(msg, mlen);
    auto ih = inner.digest();
    SHA256 outer;
    outer.update(opad, B);
    outer.update(ih.data(), 32);
    auto out = outer.digest();
    veld::compat::SecureZero(ih.data(), ih.size());
    veld::compat::SecureZero(ipad, B);
    veld::compat::SecureZero(opad, B);
    veld::compat::SecureZero(k, B);
    return out;
}

inline std::vector<uint8_t> PBKDF2_SHA256(const std::string& password, const uint8_t* salt,
                                          size_t slen, uint32_t iterations, uint32_t dklen) {
    if (iterations == 0)
        throw std::invalid_argument("PBKDF2 iteration count must be non-zero");
    if (slen != 0 && salt == nullptr)
        throw std::invalid_argument("PBKDF2 salt pointer is null");
    if (slen > std::numeric_limits<size_t>::max() - 4)
        throw std::length_error("PBKDF2 salt is too large");
    std::vector<uint8_t> dk;
    dk.reserve(dklen);
    for (uint32_t blk = 1; dk.size() < dklen; ++blk) {
        std::vector<uint8_t> input(slen + 4);
        if (slen != 0)
            memcpy(input.data(), salt, slen);
        input[slen + 0] = (blk >> 24) & 0xFF;
        input[slen + 1] = (blk >> 16) & 0xFF;
        input[slen + 2] = (blk >> 8) & 0xFF;
        input[slen + 3] = (blk) & 0xFF;

        auto u = HMAC_SHA256((const uint8_t*)password.data(), password.size(), input.data(),
                             input.size());
        std::array<uint8_t, 32> t = u;
        for (uint32_t i = 1; i < iterations; ++i) {
            u = HMAC_SHA256((const uint8_t*)password.data(), password.size(), u.data(), 32);
            for (int j = 0; j < 32; ++j)
                t[j] ^= u[j];
        }
        size_t need = std::min((size_t)32, (size_t)(dklen - dk.size()));
        dk.insert(dk.end(), t.begin(), t.begin() + need);
        // Clear intermediate HMAC state before the next iteration or return.
        veld::compat::SecureZero(u.data(), 32);
        veld::compat::SecureZero(t.data(), 32);
    }
    return dk;
}

// Browser-exported .veld-keys files use a distinct envelope from the native VW
// wallet format. Version 2 remains readable with PBKDF2-HMAC-SHA256. Version 3
// uses scrypt and authenticates its format parameters as AES-GCM AAD. Keep the
// parameters in checked native helpers so browser and native importers agree.
inline constexpr size_t BROWSER_KEYSTORE_SALT_BYTES = 16;
inline constexpr uint32_t BROWSER_KEYSTORE_PBKDF2_ITERS = 600000;
inline constexpr uint32_t BROWSER_KEYSTORE_VERSION_V2 = 2;
inline constexpr uint32_t BROWSER_KEYSTORE_VERSION_V3 = 3;
inline constexpr uint64_t BROWSER_KEYSTORE_SCRYPT_N = (uint64_t)1 << 16;
inline constexpr uint32_t BROWSER_KEYSTORE_SCRYPT_R = 8;
inline constexpr uint32_t BROWSER_KEYSTORE_SCRYPT_P = 2;
inline constexpr char BROWSER_KEYSTORE_V3_AAD[] =
    "Veld browser keystore|v=3|kdf=scrypt|n=65536|r=8|p=2|cipher=AES-256-GCM";

inline std::vector<uint8_t> DeriveBrowserKeystoreKey(const std::string& password,
                                                     const uint8_t* salt, size_t salt_len) {
    if (!salt || salt_len != BROWSER_KEYSTORE_SALT_BYTES)
        throw std::invalid_argument("browser keystore salt must be exactly 16 bytes");
    return PBKDF2_SHA256(password, salt, salt_len, BROWSER_KEYSTORE_PBKDF2_ITERS, 32);
}

struct ChaCha20 {
    uint32_t st[16]{};

    ~ChaCha20() {
        veld::compat::SecureZero(st, sizeof(st));
    }

    static uint32_t rotl(uint32_t v, int n) {
        return (v << n) | (v >> (32 - n));
    }

    static void qr(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b;
        d ^= a;
        d = rotl(d, 16);
        c += d;
        b ^= c;
        b = rotl(b, 12);
        a += b;
        d ^= a;
        d = rotl(d, 8);
        c += d;
        b ^= c;
        b = rotl(b, 7);
    }

    void init(const uint8_t* key32, const uint8_t* nonce12, uint32_t ctr) {
        auto le32 = [](const uint8_t* p) -> uint32_t {
            return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
                   ((uint32_t)p[3] << 24);
        };
        st[0] = 0x61707865;
        st[1] = 0x3320646e;
        st[2] = 0x79622d32;
        st[3] = 0x6b206574;
        for (int i = 0; i < 8; ++i)
            st[4 + i] = le32(key32 + i * 4);
        st[12] = ctr;
        st[13] = le32(nonce12);
        st[14] = le32(nonce12 + 4);
        st[15] = le32(nonce12 + 8);
    }

    void block(uint8_t out[64]) {
        uint32_t w[16];
        memcpy(w, st, 64);
        for (int i = 0; i < 10; ++i) {
            qr(w[0], w[4], w[8], w[12]);
            qr(w[1], w[5], w[9], w[13]);
            qr(w[2], w[6], w[10], w[14]);
            qr(w[3], w[7], w[11], w[15]);
            qr(w[0], w[5], w[10], w[15]);
            qr(w[1], w[6], w[11], w[12]);
            qr(w[2], w[7], w[8], w[13]);
            qr(w[3], w[4], w[9], w[14]);
        }
        for (int i = 0; i < 16; ++i) {
            uint32_t v = w[i] + st[i];
            out[i * 4 + 0] = v & 0xFF;
            out[i * 4 + 1] = (v >> 8) & 0xFF;
            out[i * 4 + 2] = (v >> 16) & 0xFF;
            out[i * 4 + 3] = (v >> 24) & 0xFF;
        }
        uint32_t prev = st[12];
        ++st[12];
        if (st[12] < prev) {
            throw std::runtime_error("ChaCha20 block counter wrapped — refusing to reuse keystream "
                                     "block 0 (Poly1305 one-time key). Use a fresh nonce/key per "
                                     "≤256 GiB message.");
        }
    }

    void keystream(const uint8_t* in, uint8_t* out, size_t len) {
        uint8_t buf[64];
        size_t i = 0;
        while (i < len) {
            block(buf);
            size_t chunk = (len - i < 64) ? len - i : 64;
            for (size_t j = 0; j < chunk; ++j)
                out[i + j] = in[i + j] ^ buf[j];
            i += chunk;
        }
    }
};

struct Poly1305 {
    uint32_t r[5]{}, h[5]{}, pad[4]{};

    ~Poly1305() {
        veld::compat::SecureZero(r, sizeof(r));
        veld::compat::SecureZero(h, sizeof(h));
        veld::compat::SecureZero(pad, sizeof(pad));
    }

    void init(const uint8_t key[32]) {
        r[0] = ((uint32_t)key[0] | ((uint32_t)key[1] << 8) | ((uint32_t)key[2] << 16) |
                ((uint32_t)key[3] << 24)) &
               0x0fffffff;
        r[1] = ((uint32_t)key[4] | ((uint32_t)key[5] << 8) | ((uint32_t)key[6] << 16) |
                ((uint32_t)key[7] << 24)) &
               0x0ffffffc;
        r[2] = ((uint32_t)key[8] | ((uint32_t)key[9] << 8) | ((uint32_t)key[10] << 16) |
                ((uint32_t)key[11] << 24)) &
               0x0ffffffc;
        r[3] = ((uint32_t)key[12] | ((uint32_t)key[13] << 8) | ((uint32_t)key[14] << 16) |
                ((uint32_t)key[15] << 24)) &
               0x0ffffffc;
        r[4] = 0;
        h[0] = h[1] = h[2] = h[3] = h[4] = 0;
        pad[0] = (uint32_t)key[16] | ((uint32_t)key[17] << 8) | ((uint32_t)key[18] << 16) |
                 ((uint32_t)key[19] << 24);
        pad[1] = (uint32_t)key[20] | ((uint32_t)key[21] << 8) | ((uint32_t)key[22] << 16) |
                 ((uint32_t)key[23] << 24);
        pad[2] = (uint32_t)key[24] | ((uint32_t)key[25] << 8) | ((uint32_t)key[26] << 16) |
                 ((uint32_t)key[27] << 24);
        pad[3] = (uint32_t)key[28] | ((uint32_t)key[29] << 8) | ((uint32_t)key[30] << 16) |
                 ((uint32_t)key[31] << 24);
    }

    void block(const uint8_t* m, size_t len, bool final_block) {
        uint8_t buf[17] = {};
        memcpy(buf, m, len);
        buf[len] = final_block ? 1 : 0x01;

        uint32_t m0 = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) |
                      ((uint32_t)buf[3] << 24);
        uint32_t m1 = (uint32_t)buf[4] | ((uint32_t)buf[5] << 8) | ((uint32_t)buf[6] << 16) |
                      ((uint32_t)buf[7] << 24);
        uint32_t m2 = (uint32_t)buf[8] | ((uint32_t)buf[9] << 8) | ((uint32_t)buf[10] << 16) |
                      ((uint32_t)buf[11] << 24);
        uint32_t m3 = (uint32_t)buf[12] | ((uint32_t)buf[13] << 8) | ((uint32_t)buf[14] << 16) |
                      ((uint32_t)buf[15] << 24);
        uint32_t m4 = final_block ? 0 : (uint32_t)buf[16];

        uint64_t f;
        f = (uint64_t)h[0] + m0;
        h[0] = (uint32_t)f;
        f = (uint64_t)h[1] + m1 + (f >> 32);
        h[1] = (uint32_t)f;
        f = (uint64_t)h[2] + m2 + (f >> 32);
        h[2] = (uint32_t)f;
        f = (uint64_t)h[3] + m3 + (f >> 32);
        h[3] = (uint32_t)f;
        f = (uint64_t)h[4] + m4 + (f >> 32);
        h[4] = (uint32_t)f;

        uint64_t s1 = r[1] * 5, s2 = r[2] * 5, s3 = r[3] * 5;
        uint64_t d0 =
            (uint64_t)h[0] * r[0] + (uint64_t)h[1] * s3 + (uint64_t)h[2] * s2 + (uint64_t)h[3] * s1;
        uint64_t d1 = (uint64_t)h[0] * r[1] + (uint64_t)h[1] * r[0] + (uint64_t)h[2] * s3 +
                      (uint64_t)h[3] * s2;
        uint64_t d2 = (uint64_t)h[0] * r[2] + (uint64_t)h[1] * r[1] + (uint64_t)h[2] * r[0] +
                      (uint64_t)h[3] * s3;
        uint64_t d3 = (uint64_t)h[0] * r[3] + (uint64_t)h[1] * r[2] + (uint64_t)h[2] * r[1] +
                      (uint64_t)h[3] * r[0];
        uint64_t d4 = (uint64_t)h[4];

        uint32_t c;
        c = (uint32_t)(d0 >> 32);
        h[0] = (uint32_t)d0;
        d1 += c;
        c = (uint32_t)(d1 >> 32);
        h[1] = (uint32_t)d1;
        d2 += c;
        c = (uint32_t)(d2 >> 32);
        h[2] = (uint32_t)d2;
        d3 += c;
        c = (uint32_t)(d3 >> 32);
        h[3] = (uint32_t)d3;
        d4 += c;
        h[4] = (uint32_t)d4;

        c = (h[4] >> 2) * 5;
        h[4] &= 3;
        f = (uint64_t)h[0] + c;
        h[0] = (uint32_t)f;
        c = (uint32_t)(f >> 32);
        f = (uint64_t)h[1] + c;
        h[1] = (uint32_t)f;
        c = (uint32_t)(f >> 32);
        f = (uint64_t)h[2] + c;
        h[2] = (uint32_t)f;
        c = (uint32_t)(f >> 32);
        f = (uint64_t)h[3] + c;
        h[3] = (uint32_t)f;
        c = (uint32_t)(f >> 32);
        h[4] += c;
    }

    void update(const uint8_t* data, size_t len) {
        size_t i = 0;
        for (; i + 16 <= len; i += 16)
            block(data + i, 16, false);
        if (i < len)
            block(data + i, len - i, true);
    }

    std::array<uint8_t, 16> final_tag() {
        uint32_t g[5];
        uint64_t f;
        f = (uint64_t)h[0] + 5;
        g[0] = (uint32_t)f;
        f = (uint64_t)h[1] + (f >> 32);
        g[1] = (uint32_t)f;
        f = (uint64_t)h[2] + (f >> 32);
        g[2] = (uint32_t)f;
        f = (uint64_t)h[3] + (f >> 32);
        g[3] = (uint32_t)f;
        f = (uint64_t)h[4] + (f >> 32) - 4;
        g[4] = (uint32_t)f;

        uint32_t mask = ~(0u - (g[4] >> 31));
        h[0] = (h[0] & ~mask) | (g[0] & mask);
        h[1] = (h[1] & ~mask) | (g[1] & mask);
        h[2] = (h[2] & ~mask) | (g[2] & mask);
        h[3] = (h[3] & ~mask) | (g[3] & mask);

        f = (uint64_t)h[0] + pad[0];
        h[0] = (uint32_t)f;
        f = (uint64_t)h[1] + pad[1] + (f >> 32);
        h[1] = (uint32_t)f;
        f = (uint64_t)h[2] + pad[2] + (f >> 32);
        h[2] = (uint32_t)f;
        f = (uint64_t)h[3] + pad[3] + (f >> 32);
        h[3] = (uint32_t)f;

        std::array<uint8_t, 16> tag;
        for (int i = 0; i < 4; ++i) {
            tag[i] = (h[0] >> (i * 8)) & 0xFF;
            tag[i + 4] = (h[1] >> (i * 8)) & 0xFF;
            tag[i + 8] = (h[2] >> (i * 8)) & 0xFF;
            tag[i + 12] = (h[3] >> (i * 8)) & 0xFF;
        }
        return tag;
    }
};

inline std::array<uint8_t, 16> poly1305_tag(const uint8_t poly_key[32], const uint8_t* cipher,
                                            size_t clen) {
    Poly1305 p;
    p.init(poly_key);
    p.update(cipher, clen);
    return p.final_tag();
}

struct CipherResult {
    std::vector<uint8_t> data;
    std::array<uint8_t, 16> tag;
};

inline CipherResult ChaCha20Poly1305_Encrypt(const uint8_t* key32, const uint8_t* nonce12,
                                             const uint8_t* plaintext, size_t plen) {
    ChaCha20 c0;
    c0.init(key32, nonce12, 0);
    uint8_t poly_key[64]{};
    uint8_t zeros[64]{};
    c0.keystream(zeros, poly_key, 64);

    CipherResult res;
    res.data.resize(plen);
    ChaCha20 enc;
    enc.init(key32, nonce12, 1);
    enc.keystream(plaintext, res.data.data(), plen);

    res.tag = poly1305_tag(poly_key, res.data.data(), plen);
    veld::compat::SecureZero(poly_key, sizeof(poly_key));
    veld::compat::SecureZero(zeros, sizeof(zeros));
    return res;
}

inline std::vector<uint8_t> ChaCha20Poly1305_Decrypt(const uint8_t* key32, const uint8_t* nonce12,
                                                     const uint8_t* cipher, size_t clen,
                                                     const uint8_t* expected_tag) {
    ChaCha20 c0;
    c0.init(key32, nonce12, 0);
    uint8_t poly_key[64]{};
    uint8_t zeros[64]{};
    c0.keystream(zeros, poly_key, 64);

    auto tag = poly1305_tag(poly_key, cipher, clen);
    volatile uint8_t diff = 0;
    for (int i = 0; i < 16; ++i)
        diff |= (uint8_t)(tag[i] ^ expected_tag[i]);
    veld::compat::SecureZero(poly_key, sizeof(poly_key));
    veld::compat::SecureZero(zeros, sizeof(zeros));
    if (diff != 0) {
        veld::compat::SecureZero(tag.data(), tag.size());
        throw std::runtime_error("Wallet decryption failed — wrong password or file corrupted");
    }

    std::vector<uint8_t> plain(clen);
    ChaCha20 dec;
    dec.init(key32, nonce12, 1);
    dec.keystream(cipher, plain.data(), clen);
    veld::compat::SecureZero(tag.data(), tag.size());
    return plain;
}

inline CipherResult ChaCha20Poly1305_EVP_Encrypt(const uint8_t* key32, const uint8_t* nonce12,
                                                 const uint8_t* aad, size_t aad_len,
                                                 const uint8_t* plaintext, size_t plen) {
    CipherResult res;
    res.data.resize(plen);
    if (!::veld::vendored_crypto::chacha20_poly1305_encrypt(
            key32, nonce12, aad, aad_len, plaintext, plen, res.data.data(), res.tag.data())) {
        throw std::runtime_error("ChaCha20-Poly1305 encrypt failed");
    }
    return res;
}

inline std::vector<uint8_t> ChaCha20Poly1305_EVP_Decrypt(const uint8_t* key32,
                                                         const uint8_t* nonce12, const uint8_t* aad,
                                                         size_t aad_len, const uint8_t* cipher,
                                                         size_t clen, const uint8_t* expected_tag) {
    std::vector<uint8_t> plain(clen);
    if (!::veld::vendored_crypto::chacha20_poly1305_decrypt(key32, nonce12, aad, aad_len, cipher,
                                                            clen, expected_tag, plain.data())) {
        if (!plain.empty())
            veld::compat::SecureZero(plain.data(), plain.size());
        throw std::runtime_error("Wallet decryption failed — wrong password or file corrupted");
    }
    return plain;
}

// ── M-10: vendored scrypt (RFC 7914) — memory-HARD wallet KDF for v5. PBKDF2-SHA256 is CPU-hard
// but memoryless, so GPU/ASIC offline guessing of weak passwords scales cheaply. scrypt forces
// ~128*N*r bytes of fast memory per guess. Implemented on the existing vendored PBKDF2/HMAC — NO
// OpenSSL/Argon2 dependency, so the crypto stays vendored + reproducible. Correctness is PINNED
// against the RFC 7914 test vectors.
inline void _salsa20_8(uint8_t B[64]) {
    auto R = [](uint32_t a, uint32_t b) -> uint32_t { return (a << b) | (a >> (32 - b)); };
    uint32_t x[16], in[16];
    for (int i = 0; i < 16; ++i)
        in[i] = x[i] = (uint32_t)B[4 * i] | ((uint32_t)B[4 * i + 1] << 8) |
                       ((uint32_t)B[4 * i + 2] << 16) | ((uint32_t)B[4 * i + 3] << 24);
    for (int i = 8; i > 0; i -= 2) {
        x[4] ^= R(x[0] + x[12], 7);
        x[8] ^= R(x[4] + x[0], 9);
        x[12] ^= R(x[8] + x[4], 13);
        x[0] ^= R(x[12] + x[8], 18);
        x[9] ^= R(x[5] + x[1], 7);
        x[13] ^= R(x[9] + x[5], 9);
        x[1] ^= R(x[13] + x[9], 13);
        x[5] ^= R(x[1] + x[13], 18);
        x[14] ^= R(x[10] + x[6], 7);
        x[2] ^= R(x[14] + x[10], 9);
        x[6] ^= R(x[2] + x[14], 13);
        x[10] ^= R(x[6] + x[2], 18);
        x[3] ^= R(x[15] + x[11], 7);
        x[7] ^= R(x[3] + x[15], 9);
        x[11] ^= R(x[7] + x[3], 13);
        x[15] ^= R(x[11] + x[7], 18);
        x[1] ^= R(x[0] + x[3], 7);
        x[2] ^= R(x[1] + x[0], 9);
        x[3] ^= R(x[2] + x[1], 13);
        x[0] ^= R(x[3] + x[2], 18);
        x[6] ^= R(x[5] + x[4], 7);
        x[7] ^= R(x[6] + x[5], 9);
        x[4] ^= R(x[7] + x[6], 13);
        x[5] ^= R(x[4] + x[7], 18);
        x[11] ^= R(x[10] + x[9], 7);
        x[8] ^= R(x[11] + x[10], 9);
        x[9] ^= R(x[8] + x[11], 13);
        x[10] ^= R(x[9] + x[8], 18);
        x[12] ^= R(x[15] + x[14], 7);
        x[13] ^= R(x[12] + x[15], 9);
        x[14] ^= R(x[13] + x[12], 13);
        x[15] ^= R(x[14] + x[13], 18);
    }
    for (int i = 0; i < 16; ++i) {
        uint32_t v = x[i] + in[i];
        B[4 * i] = (uint8_t)v;
        B[4 * i + 1] = (uint8_t)(v >> 8);
        B[4 * i + 2] = (uint8_t)(v >> 16);
        B[4 * i + 3] = (uint8_t)(v >> 24);
    }
    veld::compat::SecureZero(x, sizeof(x));
    veld::compat::SecureZero(in, sizeof(in));
}
inline void _scrypt_blockmix(const uint8_t* B, uint8_t* Y, size_t r) {
    uint8_t X[64];
    std::memcpy(X, B + (2 * r - 1) * 64, 64);
    for (size_t i = 0; i < 2 * r; ++i) {
        for (int k = 0; k < 64; ++k)
            X[k] ^= B[i * 64 + k];
        _salsa20_8(X);
        size_t dst = (i % 2 == 0) ? (i / 2) : (r + (i - 1) / 2); // even blocks then odd (RFC 7914)
        std::memcpy(Y + dst * 64, X, 64);
    }
    veld::compat::SecureZero(X, sizeof(X));
}
inline uint64_t _scrypt_integerify(const uint8_t* B, size_t r) {
    const uint8_t* p = B + (2 * r - 1) * 64; // last 64-byte block, LE
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= (uint64_t)p[i] << (8 * i);
    return v;
}
inline void _scrypt_romix(uint8_t* B, size_t r, uint64_t N) {
    size_t blen = 128 * r;
    std::vector<uint8_t> V((size_t)N * blen), Y(blen);
    ScopedByteWipe<std::vector<uint8_t>> wipe_v{V};
    ScopedByteWipe<std::vector<uint8_t>> wipe_y{Y};
    for (uint64_t i = 0; i < N; ++i) {
        std::memcpy(V.data() + (size_t)i * blen, B, blen);
        _scrypt_blockmix(B, Y.data(), r);
        std::memcpy(B, Y.data(), blen);
    }
    for (uint64_t i = 0; i < N; ++i) {
        uint64_t j = _scrypt_integerify(B, r) & (N - 1); // N is a power of 2
        const uint8_t* Vj = V.data() + (size_t)j * blen;
        for (size_t k = 0; k < blen; ++k)
            B[k] ^= Vj[k];
        _scrypt_blockmix(B, Y.data(), r);
        std::memcpy(B, Y.data(), blen);
    }
}
inline std::vector<uint8_t> Scrypt(const std::string& P, const uint8_t* S, size_t slen, uint64_t N,
                                   uint32_t r, uint32_t p, size_t dkLen) {
    if (N < 2 || (N & (N - 1)) != 0 || r == 0 || p == 0)
        throw std::invalid_argument("invalid scrypt work parameters");
    if ((slen != 0 && S == nullptr) || dkLen > std::numeric_limits<uint32_t>::max())
        throw std::invalid_argument("invalid scrypt input length");
    const uint64_t block_len64 = 128ull * static_cast<uint64_t>(r);
    if (static_cast<uint64_t>(p) > std::numeric_limits<uint64_t>::max() / block_len64)
        throw std::length_error("scrypt parameters overflow addressable memory");
    const uint64_t b_len64 = block_len64 * static_cast<uint64_t>(p);
    if (block_len64 > std::numeric_limits<size_t>::max() ||
        b_len64 > std::numeric_limits<uint32_t>::max() ||
        N > std::numeric_limits<size_t>::max() / static_cast<size_t>(block_len64))
        throw std::length_error("scrypt parameters overflow addressable memory");
    std::vector<uint8_t> B = PBKDF2_SHA256(P, S, slen, 1, static_cast<uint32_t>(b_len64));
    ScopedByteWipe<std::vector<uint8_t>> wipe_b{B};
    for (uint32_t i = 0; i < p; ++i)
        _scrypt_romix(B.data() + (size_t)i * 128 * r, r, N);
    auto dk = PBKDF2_SHA256(P, B.data(), B.size(), 1, (uint32_t)dkLen);
    return dk;
}
// v5 remains readable with p=1. New v6 files use p=2.
inline constexpr uint64_t VELD_WALLET_SCRYPT_N_V5 = (uint64_t)1 << 16;
inline constexpr uint32_t VELD_WALLET_SCRYPT_R_V5 = 8;
inline constexpr uint32_t VELD_WALLET_SCRYPT_P_V5 = 1;
inline constexpr uint64_t VELD_WALLET_SCRYPT_N = (uint64_t)1 << 16;
inline constexpr uint32_t VELD_WALLET_SCRYPT_R = 8;
inline constexpr uint32_t VELD_WALLET_SCRYPT_P = 2;

inline std::vector<uint8_t> DeriveBrowserKeystoreKeyV3(const std::string& password,
                                                       const uint8_t* salt, size_t salt_len) {
    if (!salt || salt_len != BROWSER_KEYSTORE_SALT_BYTES)
        throw std::invalid_argument("browser keystore salt must be exactly 16 bytes");
    return Scrypt(password, salt, salt_len, BROWSER_KEYSTORE_SCRYPT_N, BROWSER_KEYSTORE_SCRYPT_R,
                  BROWSER_KEYSTORE_SCRYPT_P, 32);
}

inline constexpr int VELD_WALLET_PBKDF2_ITERS_V4 = 1300000;
inline constexpr int VELD_WALLET_PBKDF2_ITERS_CURRENT = VELD_WALLET_PBKDF2_ITERS_V4;
inline constexpr int VELD_WALLET_PBKDF2_ITERS_V1_V3 = 600000;
inline constexpr int VELD_WALLET_PBKDF2_ITERS_LEGACY = 300000;

inline constexpr uint8_t VELD_WALLET_MAGIC[2] = {'V', 'W'};
inline constexpr uint8_t VELD_WALLET_VERSION_V1 = 0x01;
inline constexpr uint8_t VELD_WALLET_VERSION_LEGACY = 0x02;
inline constexpr uint8_t VELD_WALLET_VERSION_V3 = 0x03;
inline constexpr uint8_t VELD_WALLET_VERSION_V4 = 0x04;
inline constexpr uint8_t VELD_WALLET_VERSION_V5 =
    0x05; // M-10: scrypt (memory-hard) KDF, ChaCha20-Poly1305 AEAD
inline constexpr uint8_t VELD_WALLET_VERSION_V6 = 0x06;
inline constexpr uint8_t VELD_WALLET_VERSION_CURRENT = VELD_WALLET_VERSION_V6;

inline bool IsCurrentWalletEnvelope(const std::vector<uint8_t>& encrypted) {
    return encrypted.size() >= 3 && encrypted[0] == VELD_WALLET_MAGIC[0] &&
           encrypted[1] == VELD_WALLET_MAGIC[1] && encrypted[2] == VELD_WALLET_VERSION_CURRENT;
}

inline std::vector<uint8_t> EncryptWallet(const std::string& plaintext,
                                          const std::string& password) {
    uint8_t salt[32], nonce[12];
    if (!veld::compat::SecureRandom(salt, 32) || !veld::compat::SecureRandom(nonce, 12)) {
        std::cerr << "FATAL: CSPRNG failure during wallet encryption "
                  << "(salt/nonce generation). Refusing to continue with "
                  << "potentially predictable randomness." << std::endl;
        std::abort();
    }

    // v6 derives the AEAD key with memory-hard scrypt. The AAD
    // binds the version byte, so the AEAD tag itself refuses a downgrade to a weaker-KDF version.
    auto key = Scrypt(password, salt, 32, VELD_WALLET_SCRYPT_N, VELD_WALLET_SCRYPT_R,
                      VELD_WALLET_SCRYPT_P, 32);
    ScopedByteWipe<std::vector<uint8_t>> wipe_key{key};

    uint8_t aad[2 + 1 + 32 + 12];
    aad[0] = VELD_WALLET_MAGIC[0];
    aad[1] = VELD_WALLET_MAGIC[1];
    aad[2] = VELD_WALLET_VERSION_CURRENT;
    std::memcpy(aad + 3, salt, 32);
    std::memcpy(aad + 35, nonce, 12);

    auto result = ChaCha20Poly1305_EVP_Encrypt(key.data(), nonce, aad, sizeof(aad),
                                               (const uint8_t*)plaintext.data(), plaintext.size());

    std::vector<uint8_t> out;
    out.push_back(VELD_WALLET_MAGIC[0]);
    out.push_back(VELD_WALLET_MAGIC[1]);
    out.push_back(VELD_WALLET_VERSION_CURRENT);
    out.insert(out.end(), salt, salt + 32);
    out.insert(out.end(), nonce, nonce + 12);
    out.insert(out.end(), result.tag.begin(), result.tag.end());
    out.insert(out.end(), result.data.begin(), result.data.end());
    return out;
}

inline std::string DecryptWallet(const std::vector<uint8_t>& encrypted,
                                 const std::string& password) {
    if (encrypted.size() >= 63 && encrypted[0] == VELD_WALLET_MAGIC[0] &&
        encrypted[1] == VELD_WALLET_MAGIC[1]) {
        uint8_t version = encrypted[2];
        const uint8_t* salt = encrypted.data() + 3;
        const uint8_t* nonce = encrypted.data() + 35;
        const uint8_t* tag = encrypted.data() + 47;
        const uint8_t* ciph = encrypted.data() + 63;
        size_t clen = encrypted.size() - 63;

        int iters = 0;
        bool use_evp_aad = false, use_scrypt = false;
        uint64_t scrypt_n = 0;
        uint32_t scrypt_r = 0, scrypt_p = 0;
        switch (version) {
        case VELD_WALLET_VERSION_V1:
        case VELD_WALLET_VERSION_LEGACY:
            throw std::runtime_error(
                "Wallet file version 0x" + std::to_string(version) +
                " is deprecated because its AEAD construction is forgeable. Re-encrypt to "
                "v3+ via the wallet upgrade tool, or restore from "
                "your seed phrase into a fresh v4 wallet. See "
                "README §wallet-upgrade.");
        case VELD_WALLET_VERSION_V3:
            iters = VELD_WALLET_PBKDF2_ITERS_V1_V3;
            use_evp_aad = true;
            break;
        case VELD_WALLET_VERSION_V4:
            iters = VELD_WALLET_PBKDF2_ITERS_V4;
            use_evp_aad = true;
            break;
        case VELD_WALLET_VERSION_V5:
            use_scrypt = true;
            scrypt_n = VELD_WALLET_SCRYPT_N_V5;
            scrypt_r = VELD_WALLET_SCRYPT_R_V5;
            scrypt_p = VELD_WALLET_SCRYPT_P_V5;
            use_evp_aad = true;
            break;
        case VELD_WALLET_VERSION_V6:
            use_scrypt = true;
            scrypt_n = VELD_WALLET_SCRYPT_N;
            scrypt_r = VELD_WALLET_SCRYPT_R;
            scrypt_p = VELD_WALLET_SCRYPT_P;
            use_evp_aad = true;
            break;
        default:
            throw std::runtime_error("Unknown wallet file version 0x" + std::to_string(version) +
                                     " — this binary does not know how to decrypt it");
        }
        auto key = use_scrypt ? Scrypt(password, salt, 32, scrypt_n, scrypt_r, scrypt_p, 32)
                              : PBKDF2_SHA256(password, salt, 32, iters, 32);
        ScopedByteWipe<std::vector<uint8_t>> wipe_key{key};
        std::vector<uint8_t> plain;
        if (use_evp_aad) {
            uint8_t aad[2 + 1 + 32 + 12];
            aad[0] = VELD_WALLET_MAGIC[0];
            aad[1] = VELD_WALLET_MAGIC[1];
            aad[2] = version;
            std::memcpy(aad + 3, salt, 32);
            std::memcpy(aad + 35, nonce, 12);
            plain =
                ChaCha20Poly1305_EVP_Decrypt(key.data(), nonce, aad, sizeof(aad), ciph, clen, tag);
        } else {
            plain = ChaCha20Poly1305_Decrypt(key.data(), nonce, ciph, clen, tag);
        }
        ScopedByteWipe<std::vector<uint8_t>> wipe_plain{plain};
        return std::string(plain.begin(), plain.end());
    }

    if (encrypted.size() < 60)
        throw std::runtime_error("Invalid wallet file — too small");
    throw std::runtime_error("Pre-v1 (magic-less) wallet format is deprecated because its AEAD "
                             "construction is forgeable (the same "
                             "construction class refused for v1/v2 above). Restore from your "
                             "seed phrase into a fresh v4 wallet. See README §wallet-upgrade.");
}

} // namespace wallet_crypto
} // namespace veld
