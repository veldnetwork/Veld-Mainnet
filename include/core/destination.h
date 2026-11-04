#pragma once

// Version-one ML-DSA-65 key destinations. Legacy HASH160 scripts are unchanged.
// SHA-384 is the full FIPS 180-4 digest supplied by the existing OpenSSL runtime.
#include "constants.h"
#include "hash.h"
#include <openssl/sha.h>
#include <array>
#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace veld {
using DestinationCommitment384 = std::array<uint8_t, 48>;
constexpr uint8_t SHA384_DESTINATION_MAINNET = 0x47;
constexpr uint8_t SHA384_DESTINATION_TESTNET = 0x70;
constexpr uint8_t SHA384_DESTINATION_OPCODE = 0xc0;
constexpr uint8_t SHA384_DESTINATION_VERSION = 1;
#ifdef VELD_MAINNET_POW
constexpr bool SHA384_DESTINATION_TEST_NETWORK = false;
#else
constexpr bool SHA384_DESTINATION_TEST_NETWORK = true;
#endif

inline DestinationCommitment384 PublicKeyCommitment384(const uint8_t* public_key, size_t length,
                                                       bool testnet = false) {
    if (!public_key || length != 1952)
        throw std::invalid_argument("SHA-384 destination requires a complete ML-DSA-65 public key");
    // Fixed domain, scheme, format, chain and explicit payload length prevent
    // this key commitment from being reinterpreted as a policy or other key type.
    const std::string domain = "VELD:DESTINATION:MLDSA65:KEY:V1";
    std::vector<uint8_t> preimage(domain.begin(), domain.end());
    preimage.push_back(0);
    preimage.push_back(testnet ? 1 : 0);
    const std::string genesis = GENESIS_HASH;
    preimage.insert(preimage.end(), genesis.begin(), genesis.end());
    for (unsigned i = 0; i < 4; ++i)
        preimage.push_back(static_cast<uint8_t>(length >> (8 * i)));
    preimage.insert(preimage.end(), public_key, public_key + length);
    DestinationCommitment384 digest{};
    if (!SHA384(preimage.data(), preimage.size(), digest.data()))
        throw std::runtime_error("SHA-384 destination digest failed");
    return digest;
}

template <size_t N>
inline DestinationCommitment384 PublicKeyCommitment384(const std::array<uint8_t, N>& public_key,
                                                       bool testnet = false) {
    static_assert(N == 1952, "complete ML-DSA-65 public key required");
    return PublicKeyCommitment384(public_key.data(), N, testnet);
}

inline std::vector<uint8_t> BuildSha384KeyScript(const DestinationCommitment384& digest) {
    std::vector<uint8_t> script = {SHA384_DESTINATION_OPCODE, SHA384_DESTINATION_VERSION, 48};
    script.insert(script.end(), digest.begin(), digest.end());
    return script;
}

inline bool IsSha384KeyScript(const std::vector<uint8_t>& script) noexcept {
    return script.size() == 51 && script[0] == SHA384_DESTINATION_OPCODE &&
           script[1] == SHA384_DESTINATION_VERSION && script[2] == 48;
}

inline bool MatchesSha384Key(const std::vector<uint8_t>& script,
                             const std::array<uint8_t, 1952>& public_key, bool testnet = false) {
    if (!IsSha384KeyScript(script))
        return false;
    const auto digest = PublicKeyCommitment384(public_key, testnet);
    return std::equal(digest.begin(), digest.end(), script.begin() + 3);
}

inline std::string Sha384KeyAddress(const std::array<uint8_t, 1952>& public_key,
                                    bool testnet = false) {
    const auto digest = PublicKeyCommitment384(public_key, testnet);
    std::vector<uint8_t> data = {testnet ? SHA384_DESTINATION_TESTNET : SHA384_DESTINATION_MAINNET};
    data.insert(data.end(), digest.begin(), digest.end());
    const auto checksum = Hash256d(data);
    data.insert(data.end(), checksum.begin(), checksum.begin() + 4);
    constexpr char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::vector<uint8_t> digits(1, 0);
    for (auto byte : data) {
        unsigned carry = byte;
        for (auto& digit : digits) {
            carry += 256u * digit;
            digit = carry % 58;
            carry /= 58;
        }
        while (carry) {
            digits.push_back(carry % 58);
            carry /= 58;
        }
    }
    std::string address;
    for (auto it = digits.rbegin(); it != digits.rend(); ++it)
        address += alphabet[*it];
    return address;
}
}
