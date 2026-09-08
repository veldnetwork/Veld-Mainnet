#include "mining/veldhash.h"
#include <algorithm>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace {
using U128 = unsigned __int128;
size_t checks = 0;

void Check(bool condition, const char* message) {
    ++checks;
    if (!condition)
        throw std::runtime_error(message);
}

// Preserved block-at-a-time reader provides an independent buffering oracle.
class ReferenceStream {
  public:
    ReferenceStream(const uint8_t* key, const uint8_t* nonce, uint32_t counter)
        : counter_(counter) {
        std::memcpy(key_, key, sizeof(key_));
        std::memcpy(nonce_, nonce, sizeof(nonce_));
    }

    void Fill(uint8_t* out, size_t length) {
        while (length != 0) {
            if (offset_ == 64) {
                uint8_t iv[16];
                for (unsigned i = 0; i < 4; ++i)
                    iv[i] = static_cast<uint8_t>(counter_ >> (i * 8));
                std::memcpy(iv + 4, nonce_, sizeof(nonce_));
                veld::vendored_crypto::chacha20_keystream(key_, iv, block_, 64);
                ++counter_;
                offset_ = 0;
            }
            const auto count = std::min(length, 64 - offset_);
            std::memcpy(out, block_ + offset_, count);
            offset_ += count;
            out += count;
            length -= count;
        }
    }

  private:
    uint8_t key_[32], nonce_[12], block_[64]{};
    uint32_t counter_;
    size_t offset_{64};
};

uint64_t ReferenceSqrt(U128 value) {
    U128 result = 0;
    U128 bit = U128(1) << 126;
    while (bit > value)
        bit >>= 2;
    while (bit != 0) {
        if (value >= result + bit) {
            value -= result + bit;
            result = (result >> 1) + bit;
        } else {
            result >>= 1;
        }
        bit >>= 2;
    }
    return static_cast<uint64_t>(result);
}

void CheckSqrt(U128 value) {
    const U128 root = veld::mining::VeldIntegerSqrt128(value);
    Check(root == ReferenceSqrt(value), "integer square root differs from released implementation");
    Check(root == 0 || root <= value / root, "square root exceeds input");
    Check(root + 1 > value / (root + 1), "square root is not maximal");
}

void CheckStreams() {
    using veld::mining::ChaCha20;
    uint8_t key[32], nonce[12];
    for (unsigned i = 0; i < 32; ++i)
        key[i] = static_cast<uint8_t>(i);
    const uint8_t rfc_nonce[12] = {0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0};
    const auto expected =
        veld::HexToBytes("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                         "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
    std::vector<uint8_t> actual(64);
    ChaCha20 known(key, rfc_nonce, 1);
    known.fill(actual.data(), actual.size());
    Check(actual == expected, "RFC 7539 block vector changed");

    for (unsigned i = 0; i < 12; ++i)
        nonce[i] = static_cast<uint8_t>(i * 17 + 3);
    for (uint32_t counter : {0u, 1u, 0x7fffffffu, 0xfffffffeu, 0xffffffffu}) {
        for (size_t prefix = 0; prefix < 64; ++prefix) {
            ChaCha20 stream(key, nonce, counter);
            ReferenceStream reference(key, nonce, counter);
            const auto compare = [&](size_t count) {
                std::vector<uint8_t> got(count + 2, 0x5a), want(count + 2, 0x5a);
                stream.fill(got.data() + 1, count);
                reference.Fill(want.data() + 1, count);
                Check(got == want, "stream changed at a partial, bulk or counter boundary");
                Check(got.front() == 0x5a && got.back() == 0x5a, "stream wrote outside output");
            };
            stream.fill(nullptr, 0);
            compare(prefix);
            for (size_t count : {0u, 1u, 7u, 8u, 31u, 63u, 64u, 65u, 127u, 128u, 129u, 255u, 256u,
                                 257u, 1024u, 4097u}) {
                compare(count);
                uint8_t bytes[8];
                reference.Fill(bytes, 8);
                uint64_t word = 0;
                for (unsigned i = 0; i < 8; ++i)
                    word |= uint64_t(bytes[i]) << (i * 8);
                Check(stream.next64() == word, "next64 lost stream position after a bulk fill");
            }
        }
    }
    ChaCha20 stream(key, nonce);
    ReferenceStream reference(key, nonce, 0);
    std::vector<uint8_t> got(2 * 1024 * 1024 + 97), want(got.size());
    stream.fill(got.data(), got.size());
    reference.Fill(want.data(), want.size());
    Check(got == want, "production scratchpad stream changed");
}
} // namespace

int main() {
    try {
        CheckStreams();
        for (uint64_t value = 0; value < 65536; ++value)
            CheckSqrt(value);
        for (unsigned bit = 0; bit < 128; ++bit) {
            const auto value = U128(1) << bit;
            CheckSqrt(value - 1);
            CheckSqrt(value);
            CheckSqrt(value + 1);
        }
        CheckSqrt(~U128(0));
        uint64_t random = 0x159a55e57e5a1234ULL;
        const auto next = [&]() {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            return random;
        };
        for (unsigned i = 0; i < 50000; ++i) {
            const uint64_t high = next();
            const uint64_t low = next();
            const U128 value = (U128(high) << 64) | low;
            CheckSqrt(value >> (i % 128));
        }
        veld::mining::VeldIntegerDeterminismCheck();
        veld::mining::VeldDatasetLightKat();
        std::cout << "PASS " << checks << " stream, integer and startup checks\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
