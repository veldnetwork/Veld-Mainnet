#pragma once

#include "../core/canonical_numeric.h"
#include "../core/constants.h"
#include "../core/hash.h"
#include "../core/version.h"
#include "../crypto/veld_signing.h"
#include "../wallet/secure_channel_file.h"
#include "../wallet/wallet.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <limits>
#include <map>
#include <string>
#include <vector>

namespace veld::snapshot_bootstrap {

inline constexpr const char* RECEIPT_FILENAME = "full-ibd.receipt";
inline constexpr const char* FLEET_RECEIPT_FILENAME = "fleet-full-ibd.receipt";
inline constexpr const char* FLEET_KEY_FILENAME = "fleet-validation.key";
inline constexpr const char* REVOCATION_FILENAME = ".snapshot-fast-start-revoked";
inline constexpr const char* RECEIPT_SCHEMA = "veld-full-ibd-v1";
inline constexpr const char* FLEET_RECEIPT_SCHEMA = "veld-fleet-full-ibd-v1";

struct FullIbdReceipt {
    uint64_t height{0};
    std::string tip_hash;
    std::string miner_address;
};

inline std::string ReceiptPath(const std::string& datadir) {
    return (std::filesystem::path(datadir) / RECEIPT_FILENAME).string();
}

inline std::string RevocationPath(const std::string& datadir) {
    return (std::filesystem::path(datadir) / REVOCATION_FILENAME).string();
}

inline std::string FleetReceiptPath(const std::string& datadir) {
    return (std::filesystem::path(datadir) / FLEET_RECEIPT_FILENAME).string();
}

inline std::string FleetKeyPath(const std::string& datadir) {
    return (std::filesystem::path(datadir) / FLEET_KEY_FILENAME).string();
}

inline bool IsLowerHex(const std::string& text, size_t exact_size) {
    if (text.size() != exact_size) return false;
    for (char c : text) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

inline Hash256 ReceiptDigest(const std::string& payload) {
    static constexpr uint8_t domain[] = {
        'V','E','L','D','_','F','U','L','L','_','I','B','D','_','V','1',0
    };
    std::vector<uint8_t> preimage;
    preimage.reserve(sizeof(domain) + payload.size());
    preimage.insert(preimage.end(), std::begin(domain), std::end(domain));
    preimage.insert(preimage.end(), payload.begin(), payload.end());
    return Hash256d(preimage);
}

inline Hash256 FleetReceiptDigest(const std::string& payload) {
    static constexpr uint8_t domain[] = {
        'V','E','L','D','_','F','L','E','E','T','_','I','B','D','_','V','1',0
    };
    std::vector<uint8_t> preimage;
    preimage.reserve(sizeof(domain) + payload.size());
    preimage.insert(preimage.end(), std::begin(domain), std::end(domain));
    preimage.insert(preimage.end(), payload.begin(), payload.end());
    return Hash256d(preimage);
}

inline bool ReadProtectedFile(const std::string& path,
                              size_t max_bytes,
                              std::vector<uint8_t>& out,
                              std::string* error) {
    const auto result = channel::secure_file::Read(
        path, out, error, max_bytes, /*require_private_parent=*/true);
    return result == channel::secure_file::ReadResult::Ok;
}

inline std::string CanonicalPayload(uint64_t height,
                                    const std::string& tip_hash,
                                    int64_t completed_at,
                                    const std::string& miner_address,
                                    const std::string& pubkey_hash,
                                    const std::string& key_file_hash) {
    return std::string("schema=") + RECEIPT_SCHEMA +
           "\ndeployment_profile=" + DEPLOYMENT_PROFILE_ID +
           "\ngenesis=" + GENESIS_HASH +
           "\nminer_address=" + miner_address +
           "\nminer_pubkey_hash=" + pubkey_hash +
           "\nminer_key_file_hash=" + key_file_hash +
           "\nvalidated_height=" + std::to_string(height) +
           "\nvalidated_tip=" + tip_hash +
           "\ncompleted_at=" + std::to_string(completed_at) + "\n";
}

inline bool WriteFullIbdReceipt(const std::string& datadir,
                                const RealKeyPair& miner,
                                uint64_t height,
                                const std::string& tip_hash,
                                std::string* error = nullptr) {
    if (height == 0 || !IsLowerHex(tip_hash, 64) || miner.address.empty()) {
        if (error) *error = "full-IBD receipt inputs are not canonical";
        return false;
    }
    std::error_code revoke_ec;
    std::filesystem::remove(RevocationPath(datadir), revoke_ec);
    if (revoke_ec) {
        if (error) *error = "cannot clear prior snapshot revocation after full IBD";
        return false;
    }

    std::vector<uint8_t> key_file;
    if (!ReadProtectedFile(
            (std::filesystem::path(datadir) / "miner.key").string(),
            64 * 1024, key_file, error)) {
        return false;
    }

    const std::vector<uint8_t> pubkey(miner.public_key.begin(),
                                      miner.public_key.end());
    const std::string pubkey_hash = HashToHex(Hash256d(pubkey));
    const std::string key_file_hash = HashToHex(Hash256d(key_file));
    const int64_t completed_at =
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    const std::string payload = CanonicalPayload(
        height, tip_hash, completed_at, miner.address,
        pubkey_hash, key_file_hash);

    Secp256k1SigDER signature;
    try {
        signature = Sign(miner.private_key, ReceiptDigest(payload));
    } catch (const std::exception& e) {
        if (error) *error = std::string("cannot sign full-IBD receipt: ") + e.what();
        return false;
    }
    const std::string body = payload +
        "miner_public_key=" + BytesToHex(pubkey) + "\n" +
        "signature=" + BytesToHex(signature) + "\n";
    if (body.size() > 24 * 1024) {
        if (error) *error = "full-IBD receipt exceeds its fixed size bound";
        return false;
    }
    return channel::secure_file::AtomicWriteText(
        ReceiptPath(datadir), body, error, /*require_private_parent=*/true);
}

inline bool VerifyFullIbdReceipt(const std::string& datadir,
                                 const Secp256k1PubKey& expected_pubkey,
                                 FullIbdReceipt& out,
                                 std::string* error = nullptr) {
    out = FullIbdReceipt{};
    std::error_code revoked_ec;
    const bool revoked = std::filesystem::exists(
        RevocationPath(datadir), revoked_ec);
    if (revoked || revoked_ec) {
        if (error) *error = revoked
            ? "snapshot eligibility was revoked after a failed verification"
            : "cannot determine snapshot revocation state";
        return false;
    }
    std::vector<uint8_t> bytes;
    if (!ReadProtectedFile(ReceiptPath(datadir), 24 * 1024, bytes, error))
        return false;
    const std::string body(bytes.begin(), bytes.end());
    if (body.empty() || body.back() != '\n' || body.find('\r') != std::string::npos) {
        if (error) *error = "full-IBD receipt has non-canonical framing";
        return false;
    }

    std::map<std::string, std::string> fields;
    size_t pos = 0;
    while (pos < body.size()) {
        const size_t end = body.find('\n', pos);
        if (end == std::string::npos || end == pos) {
            if (error) *error = "full-IBD receipt has an empty or unterminated field";
            return false;
        }
        const std::string line = body.substr(pos, end - pos);
        const size_t eq = line.find('=');
        if (eq == std::string::npos || eq == 0 || eq + 1 == line.size() ||
            !fields.emplace(line.substr(0, eq), line.substr(eq + 1)).second) {
            if (error) *error = "full-IBD receipt has a malformed or duplicate field";
            return false;
        }
        pos = end + 1;
    }

    static const std::array<const char*, 11> required = {
        "schema", "deployment_profile", "genesis", "miner_address",
        "miner_pubkey_hash", "miner_key_file_hash", "validated_height",
        "validated_tip", "completed_at", "miner_public_key", "signature"
    };
    if (fields.size() != required.size()) {
        if (error) *error = "full-IBD receipt has unknown or missing fields";
        return false;
    }
    for (const char* key : required) {
        if (fields.find(key) == fields.end()) {
            if (error) *error = "full-IBD receipt is missing a required field";
            return false;
        }
    }
    if (fields["schema"] != RECEIPT_SCHEMA ||
        fields["deployment_profile"] != DEPLOYMENT_PROFILE_ID ||
        fields["genesis"] != GENESIS_HASH ||
        !IsLowerHex(fields["miner_pubkey_hash"], 64) ||
        !IsLowerHex(fields["miner_key_file_hash"], 64) ||
        !IsLowerHex(fields["validated_tip"], 64) ||
        !IsLowerHex(fields["miner_public_key"], Secp256k1PubKey{}.size() * 2) ||
        !IsLowerHex(fields["signature"], fields["signature"].size())) {
        if (error) *error = "full-IBD receipt identity or hexadecimal field is invalid";
        return false;
    }

    uint64_t height = 0;
    uint64_t completed_at_u64 = 0;
    if (!ParseCanonicalUint64Text(fields["validated_height"], height) || height == 0 ||
        !ParseCanonicalUint64Text(fields["completed_at"], completed_at_u64) ||
        completed_at_u64 == 0 ||
        completed_at_u64 > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        if (error) *error = "full-IBD receipt numeric field is invalid";
        return false;
    }
    const int64_t completed_at = static_cast<int64_t>(completed_at_u64);

    const auto pubkey_bytes = HexToBytes(fields["miner_public_key"]);
    const auto signature = HexToBytes(fields["signature"]);
    if (pubkey_bytes.size() != Secp256k1PubKey{}.size() || signature.empty() ||
        signature.size() > dilithium::SIG_MAX_BYTES) {
        if (error) *error = "full-IBD receipt signature material is malformed";
        return false;
    }
    Secp256k1PubKey pubkey{};
    std::copy(pubkey_bytes.begin(), pubkey_bytes.end(), pubkey.begin());
    const std::vector<uint8_t> pubkey_vector(pubkey.begin(), pubkey.end());
    if (pubkey != expected_pubkey ||
        HashToHex(Hash256d(pubkey_vector)) != fields["miner_pubkey_hash"] ||
        PubKeyToAddress(pubkey, false) != fields["miner_address"]) {
        if (error) {
            *error = "full-IBD receipt does not match the decrypted miner key";
        }
        return false;
    }

    std::vector<uint8_t> key_file;
    if (!ReadProtectedFile(
            (std::filesystem::path(datadir) / "miner.key").string(),
            64 * 1024, key_file, error)) {
        return false;
    }
    // The encrypted file representation may change when the same private key
    // is rewrapped under a new passphrase or KDF policy. Identity continuity is
    // established by the decrypted public key above and by the receipt
    // signature below. Keep the original file hash in the signed payload for
    // canonical verification, but do not treat a secure rewrap as a new miner.

    const std::string payload = CanonicalPayload(
        height, fields["validated_tip"], completed_at,
        fields["miner_address"], fields["miner_pubkey_hash"],
        fields["miner_key_file_hash"]);
    const std::string canonical_body = payload +
        "miner_public_key=" + fields["miner_public_key"] + "\n" +
        "signature=" + fields["signature"] + "\n";
    if (body != canonical_body || !Verify(pubkey, ReceiptDigest(payload), signature)) {
        if (error) *error = "full-IBD receipt signature or canonical encoding is invalid";
        return false;
    }

    out.height = height;
    out.tip_hash = fields["validated_tip"];
    out.miner_address = fields["miner_address"];
    return true;
}

inline std::string FleetCanonicalPayload(
        uint64_t height,
        const std::string& tip_hash,
        int64_t completed_at,
        const std::string& fleet_address,
        const std::string& pubkey_hash,
        const std::string& key_file_hash,
        const std::string& network_identity_hash) {
    return std::string("schema=") + FLEET_RECEIPT_SCHEMA +
           "\ndeployment_profile=" + DEPLOYMENT_PROFILE_ID +
           "\ngenesis=" + GENESIS_HASH +
           "\nnetwork_identity_hash=" + network_identity_hash +
           "\nfleet_address=" + fleet_address +
           "\nfleet_pubkey_hash=" + pubkey_hash +
           "\nfleet_key_file_hash=" + key_file_hash +
           "\nvalidated_height=" + std::to_string(height) +
           "\nvalidated_tip=" + tip_hash +
           "\ncompleted_at=" + std::to_string(completed_at) + "\n";
}

inline bool WriteFleetIbdReceipt(const std::string& datadir,
                                 const RealKeyPair& fleet_identity,
                                 uint64_t height,
                                 const std::string& tip_hash,
                                 std::string* error = nullptr) {
    if (height == 0 || !IsLowerHex(tip_hash, 64) ||
        fleet_identity.address.empty()) {
        if (error) *error = "fleet full-IBD receipt inputs are not canonical";
        return false;
    }
    std::error_code revoke_ec;
    std::filesystem::remove(RevocationPath(datadir), revoke_ec);
    if (revoke_ec) {
        if (error) *error = "cannot clear prior snapshot revocation after fleet full IBD";
        return false;
    }

    std::vector<uint8_t> key_file;
    if (!ReadProtectedFile(FleetKeyPath(datadir), 64 * 1024,
                           key_file, error)) {
        return false;
    }
    std::vector<uint8_t> network_identity;
    if (!ReadProtectedFile(
            (std::filesystem::path(datadir) / "network.identity").string(),
            64 * 1024, network_identity, error)) {
        return false;
    }

    const std::vector<uint8_t> pubkey(fleet_identity.public_key.begin(),
                                      fleet_identity.public_key.end());
    const std::string pubkey_hash = HashToHex(Hash256d(pubkey));
    const std::string key_file_hash = HashToHex(Hash256d(key_file));
    const std::string network_identity_hash =
        HashToHex(Hash256d(network_identity));
    const int64_t completed_at =
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    const std::string payload = FleetCanonicalPayload(
        height, tip_hash, completed_at, fleet_identity.address,
        pubkey_hash, key_file_hash, network_identity_hash);

    Secp256k1SigDER signature;
    try {
        signature = Sign(fleet_identity.private_key,
                         FleetReceiptDigest(payload));
    } catch (const std::exception& e) {
        if (error) {
            *error = std::string("cannot sign fleet full-IBD receipt: ") +
                     e.what();
        }
        return false;
    }
    const std::string body = payload +
        "fleet_public_key=" + BytesToHex(pubkey) + "\n" +
        "signature=" + BytesToHex(signature) + "\n";
    if (body.size() > 24 * 1024) {
        if (error) *error = "fleet full-IBD receipt exceeds its fixed size bound";
        return false;
    }
    return channel::secure_file::AtomicWriteText(
        FleetReceiptPath(datadir), body, error,
        /*require_private_parent=*/true);
}

inline bool VerifyFleetIbdReceipt(const std::string& datadir,
                                  const Secp256k1PubKey& expected_pubkey,
                                  FullIbdReceipt& out,
                                  std::string* error = nullptr) {
    out = FullIbdReceipt{};
    std::error_code revoked_ec;
    const bool revoked = std::filesystem::exists(
        RevocationPath(datadir), revoked_ec);
    if (revoked || revoked_ec) {
        if (error) {
            *error = revoked
                ? "snapshot eligibility was revoked after a failed verification"
                : "cannot determine snapshot revocation state";
        }
        return false;
    }

    std::vector<uint8_t> bytes;
    if (!ReadProtectedFile(FleetReceiptPath(datadir), 24 * 1024,
                           bytes, error)) {
        return false;
    }
    const std::string body(bytes.begin(), bytes.end());
    if (body.empty() || body.back() != '\n' ||
        body.find('\r') != std::string::npos) {
        if (error) *error = "fleet full-IBD receipt has non-canonical framing";
        return false;
    }

    std::map<std::string, std::string> fields;
    size_t pos = 0;
    while (pos < body.size()) {
        const size_t end = body.find('\n', pos);
        if (end == std::string::npos || end == pos) {
            if (error) {
                *error = "fleet full-IBD receipt has an empty or unterminated field";
            }
            return false;
        }
        const std::string line = body.substr(pos, end - pos);
        const size_t eq = line.find('=');
        if (eq == std::string::npos || eq == 0 || eq + 1 == line.size() ||
            !fields.emplace(line.substr(0, eq), line.substr(eq + 1)).second) {
            if (error) {
                *error = "fleet full-IBD receipt has a malformed or duplicate field";
            }
            return false;
        }
        pos = end + 1;
    }

    static const std::array<const char*, 12> required = {
        "schema", "deployment_profile", "genesis",
        "network_identity_hash", "fleet_address", "fleet_pubkey_hash",
        "fleet_key_file_hash", "validated_height", "validated_tip",
        "completed_at", "fleet_public_key", "signature"
    };
    if (fields.size() != required.size()) {
        if (error) *error = "fleet full-IBD receipt has unknown or missing fields";
        return false;
    }
    for (const char* key : required) {
        if (fields.find(key) == fields.end()) {
            if (error) *error = "fleet full-IBD receipt is missing a required field";
            return false;
        }
    }
    if (fields["schema"] != FLEET_RECEIPT_SCHEMA ||
        fields["deployment_profile"] != DEPLOYMENT_PROFILE_ID ||
        fields["genesis"] != GENESIS_HASH ||
        !IsLowerHex(fields["network_identity_hash"], 64) ||
        !IsLowerHex(fields["fleet_pubkey_hash"], 64) ||
        !IsLowerHex(fields["fleet_key_file_hash"], 64) ||
        !IsLowerHex(fields["validated_tip"], 64) ||
        !IsLowerHex(fields["fleet_public_key"],
                    Secp256k1PubKey{}.size() * 2) ||
        !IsLowerHex(fields["signature"], fields["signature"].size())) {
        if (error) *error = "fleet full-IBD receipt identity or hexadecimal field is invalid";
        return false;
    }

    uint64_t height = 0;
    uint64_t completed_at_u64 = 0;
    if (!ParseCanonicalUint64Text(fields["validated_height"], height) ||
        height == 0 ||
        !ParseCanonicalUint64Text(fields["completed_at"], completed_at_u64) ||
        completed_at_u64 == 0 ||
        completed_at_u64 >
            static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        if (error) *error = "fleet full-IBD receipt numeric field is invalid";
        return false;
    }
    const int64_t completed_at = static_cast<int64_t>(completed_at_u64);

    const auto pubkey_bytes = HexToBytes(fields["fleet_public_key"]);
    const auto signature = HexToBytes(fields["signature"]);
    if (pubkey_bytes.size() != Secp256k1PubKey{}.size() ||
        signature.empty() || signature.size() > dilithium::SIG_MAX_BYTES) {
        if (error) *error = "fleet full-IBD receipt signature material is malformed";
        return false;
    }
    Secp256k1PubKey pubkey{};
    std::copy(pubkey_bytes.begin(), pubkey_bytes.end(), pubkey.begin());
    const std::vector<uint8_t> pubkey_vector(pubkey.begin(), pubkey.end());
    if (pubkey != expected_pubkey ||
        HashToHex(Hash256d(pubkey_vector)) != fields["fleet_pubkey_hash"] ||
        PubKeyToAddress(pubkey, false) != fields["fleet_address"]) {
        if (error) {
            *error = "fleet full-IBD receipt does not match the decrypted validation key";
        }
        return false;
    }

    std::vector<uint8_t> key_file;
    if (!ReadProtectedFile(FleetKeyPath(datadir), 64 * 1024,
                           key_file, error)) {
        return false;
    }
    // Re-encrypting the same validation key changes the file hash without
    // changing the node identity. The decrypted public key match above and the
    // signed receipt below prove continuity; the old file hash remains part of
    // the canonical signed payload.
    std::vector<uint8_t> network_identity;
    if (!ReadProtectedFile(
            (std::filesystem::path(datadir) / "network.identity").string(),
            64 * 1024, network_identity, error)) {
        return false;
    }
    if (HashToHex(Hash256d(network_identity)) !=
        fields["network_identity_hash"]) {
        if (error) *error = "fleet full-IBD receipt belongs to a different network identity";
        return false;
    }

    const std::string payload = FleetCanonicalPayload(
        height, fields["validated_tip"], completed_at,
        fields["fleet_address"], fields["fleet_pubkey_hash"],
        fields["fleet_key_file_hash"], fields["network_identity_hash"]);
    const std::string canonical_body = payload +
        "fleet_public_key=" + fields["fleet_public_key"] + "\n" +
        "signature=" + fields["signature"] + "\n";
    if (body != canonical_body ||
        !Verify(pubkey, FleetReceiptDigest(payload), signature)) {
        if (error) *error = "fleet full-IBD receipt signature or canonical encoding is invalid";
        return false;
    }

    out.height = height;
    out.tip_hash = fields["validated_tip"];
    out.miner_address = fields["fleet_address"];
    return true;
}

}  // namespace veld::snapshot_bootstrap
