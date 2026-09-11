#include "consensus/checkpoints.h"
#include "wallet/wallet_crypto.h"

#include <ctime>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace {
std::string ReadBounded(const char* path, size_t limit) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) throw std::runtime_error("input unavailable");
    const auto length = file.tellg();
    if (length <= 0 || static_cast<uint64_t>(length) > limit)
        throw std::runtime_error("input size rejected");
    std::string value(static_cast<size_t>(length), '\0');
    file.seekg(0);
    if (!file.read(value.data(), length)) throw std::runtime_error("input read failed");
    return value;
}

uint64_t Number(const char* text) {
    uint64_t value = 0;
    if (!veld::ParseCanonicalUint64Text(text, value) || value == 0)
        throw std::runtime_error("invalid number");
    return value;
}
}

int main(int argc, char** argv) {
    try {
        if (argc == 4 && std::string(argv[1]) == "verify") {
            const auto document = ReadBounded(argv[2], veld::kMaxCheckpointDocumentBytes);
            const auto entries = veld::ParseCheckpointsJson(document);
            if (entries.size() != Number(argv[3])) return 3;
            uint64_t previous = 0;
            for (const auto& checkpoint : entries) {
                if (checkpoint.height <= previous || !veld::VerifyCheckpoint(checkpoint) ||
                    checkpoint.signed_at > static_cast<uint64_t>(std::time(nullptr)) + 300)
                    return 4;
                previous = checkpoint.height;
            }
            std::cout << "{\"verified\":" << entries.size()
                      << ",\"latest_height\":" << previous << "}\n";
            return 0;
        }
        const bool identity = argc == 3 && std::string(argv[1]) == "identity";
        if (!identity && (argc != 5 || std::string(argv[1]) != "sign")) return 2;
        const uint64_t height = identity ? 1 : Number(argv[3]);
        const std::string hash_hex = identity ? std::string(63, '0') + "1" : argv[4];
        if (hash_hex.size() != 64 ||
            hash_hex.find_first_not_of("0123456789abcdef") != std::string::npos)
            return 5;
        const auto hash = veld::HexToHash(hash_hex);
        if (veld::HashIsZero(hash)) return 5;
        const auto encoded = ReadBounded(argv[2], 65536);
        std::vector<uint8_t> encrypted(encoded.begin(), encoded.end());
        std::string password;
        std::getline(std::cin, password);
        veld::wallet_crypto::ScopedByteWipe<std::string> wipe_password{password};
        if (password.empty() || password.size() > 1024) return 6;
        std::string plain = veld::wallet_crypto::DecryptWallet(encrypted, password);
        veld::wallet_crypto::ScopedByteWipe<std::string> wipe_plain{plain};
        if (plain.find('\n') != 64) return 7;
        std::string seed_hex = plain.substr(0, 64);
        veld::wallet_crypto::ScopedByteWipe<std::string> wipe_hex{seed_hex};
        if (seed_hex.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
            return 7;
        auto seed = veld::HexToHash(seed_hex);
        veld::wallet_crypto::ScopedByteWipe<veld::Secp256k1PrivKey> wipe_seed{seed};
        veld::Secp256k1PubKey expected{};
        if (!veld::LoadFleetCheckpointPubKey(expected) || veld::DerivePublicKey(seed) != expected)
            return 8;
        if (identity) {
            veld::SHA256 fingerprint;
            fingerprint.update(expected.data(), expected.size());
            std::cout << "{\"public_key_sha256\":\"" << veld::HashToHex(fingerprint.digest()) << "\"}\n";
            return 0;
        }
        const uint64_t signed_at = static_cast<uint64_t>(std::time(nullptr));
        const auto signature = veld::Sign(seed, veld::ComputeCheckpointDigest(height, hash, signed_at));
        if (!veld::VerifyCheckpoint(veld::Checkpoint(height, hash, signature, signed_at))) return 9;
        constexpr char hex[] = "0123456789abcdef";
        std::string sig_hex;
        for (const uint8_t byte : signature) {
            sig_hex.push_back(hex[byte >> 4]);
            sig_hex.push_back(hex[byte & 15]);
        }
        std::cout << "{\"height\":" << height << ",\"hash\":\"" << hash_hex
                  << "\",\"signed_at\":" << signed_at << ",\"sig\":\"" << sig_hex << "\"}\n";
        return 0;
    } catch (...) {
        std::cerr << "Checkpoint operation failed validation\n";
        return 1;
    }
}
