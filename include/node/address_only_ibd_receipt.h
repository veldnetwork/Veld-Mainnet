#pragma once

#include "full_ibd_receipt.h"
#include "../mining/address_only.h"

namespace veld::snapshot_bootstrap {

inline constexpr const char* ADDRESS_RECEIPT_FILENAME = "address-only-full-ibd.receipt";
inline constexpr const char* ADDRESS_KEY_FILENAME = "address-only-validation.key";
inline constexpr const char* ADDRESS_RECEIPT_SCHEMA = "veld-address-only-full-ibd-v1";

inline std::string AddressReceiptPath(const std::string& datadir) {
    return (std::filesystem::path(datadir) / ADDRESS_RECEIPT_FILENAME).string();
}
inline std::string AddressKeyPath(const std::string& datadir) {
    return (std::filesystem::path(datadir) / ADDRESS_KEY_FILENAME).string();
}

inline Hash256 AddressReceiptDigest(const std::string& payload) {
    static constexpr uint8_t domain[] = {'V', 'E', 'L', 'D', '_', 'A', 'D', 'D', 'R', 'E',
                                         'S', 'S', '_', 'I', 'B', 'D', '_', 'V', '1', 0};
    std::vector<uint8_t> wire(std::begin(domain), std::end(domain));
    wire.insert(wire.end(), payload.begin(), payload.end());
    return Hash256d(wire);
}

inline std::string AddressReceiptPayload(uint64_t height, const std::string& tip, int64_t when,
                                         const std::string& payout, const std::string& pub_hash,
                                         const std::string& key_hash,
                                         const std::string& network_hash) {
    return std::string("schema=") + ADDRESS_RECEIPT_SCHEMA +
           "\ndeployment_profile=" + DEPLOYMENT_PROFILE_ID + "\ngenesis=" + GENESIS_HASH +
           "\nnetwork_identity_hash=" + network_hash + "\npayout_address=" + payout +
           "\nvalidation_pubkey_hash=" + pub_hash + "\nvalidation_key_file_hash=" + key_hash +
           "\nvalidated_height=" + std::to_string(height) + "\nvalidated_tip=" + tip +
           "\ncompleted_at=" + std::to_string(when) + "\n";
}

inline bool WriteAddressIbdReceipt(const std::string& datadir, const RealKeyPair& identity,
                                   const std::string& payout, uint64_t height,
                                   const std::string& tip, std::string* error = nullptr,
                                   bool testnet = false) {
    if (!mining::ValidAddressOnlyDestination(payout, testnet) || height == 0 ||
        !IsLowerHex(tip, 64) || identity.address != PubKeyToAddress(identity.public_key, testnet)) {
        if (error)
            *error = "address-only receipt inputs are not canonical";
        return false;
    }
    std::vector<uint8_t> key_file, network;
    if (!ReadProtectedFile(AddressKeyPath(datadir), 64 * 1024, key_file, error) ||
        !ReadProtectedFile((std::filesystem::path(datadir) / "network.identity").string(),
                           64 * 1024, network, error))
        return false;
    const std::vector<uint8_t> pub(identity.public_key.begin(), identity.public_key.end());
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    const auto payload =
        AddressReceiptPayload(height, tip, now, payout, HashToHex(Hash256d(pub)),
                              HashToHex(Hash256d(key_file)), HashToHex(Hash256d(network)));
    Secp256k1SigDER sig;
    try {
        sig = Sign(identity.private_key, AddressReceiptDigest(payload));
    } catch (const std::exception& e) {
        if (error)
            *error = std::string("address-only receipt signing failed: ") + e.what();
        return false;
    }
    const auto body = payload + "validation_public_key=" + BytesToHex(pub) +
                      "\nsignature=" + BytesToHex(sig) + "\n";
    if (body.size() > 24 * 1024) {
        if (error)
            *error = "address-only receipt exceeds size limit";
        return false;
    }
    return channel::secure_file::AtomicWriteText(AddressReceiptPath(datadir), body, error, true);
}

inline bool VerifyAddressIbdReceipt(const std::string& datadir,
                                    const Secp256k1PubKey& expected_pubkey,
                                    const std::string& expected_payout, FullIbdReceipt& out,
                                    std::string* error = nullptr, bool verify_for_recovery = false,
                                    bool testnet = false) {
    out = FullIbdReceipt{};
    std::error_code ec;
    const bool revoked = std::filesystem::exists(RevocationPath(datadir), ec);
    if (ec || (revoked && !verify_for_recovery)) {
        if (error)
            *error = "snapshot eligibility revoked or unreadable";
        return false;
    }
    std::vector<uint8_t> bytes, key_file, network;
    if (!ReadProtectedFile(AddressReceiptPath(datadir), 24 * 1024, bytes, error) ||
        !ReadProtectedFile(AddressKeyPath(datadir), 64 * 1024, key_file, error) ||
        !ReadProtectedFile((std::filesystem::path(datadir) / "network.identity").string(),
                           64 * 1024, network, error))
        return false;
    const std::string body(bytes.begin(), bytes.end());
    if (body.empty() || body.back() != '\n' || body.find('\r') != std::string::npos) {
        if (error)
            *error = "address-only receipt framing is not canonical";
        return false;
    }
    std::map<std::string, std::string> f;
    for (size_t pos = 0; pos < body.size();) {
        const size_t end = body.find('\n', pos);
        if (end == std::string::npos || end == pos) {
            if (error)
                *error = "address-only receipt field is malformed";
            return false;
        }
        const auto line = body.substr(pos, end - pos);
        const auto eq = line.find('=');
        if (eq == std::string::npos || eq == 0 || eq + 1 == line.size() ||
            !f.emplace(line.substr(0, eq), line.substr(eq + 1)).second) {
            if (error)
                *error = "address-only receipt has malformed or duplicate field";
            return false;
        }
        pos = end + 1;
    }
    static const std::array<const char*, 12> required = {"schema",
                                                         "deployment_profile",
                                                         "genesis",
                                                         "network_identity_hash",
                                                         "payout_address",
                                                         "validation_pubkey_hash",
                                                         "validation_key_file_hash",
                                                         "validated_height",
                                                         "validated_tip",
                                                         "completed_at",
                                                         "validation_public_key",
                                                         "signature"};
    if (f.size() != required.size()) {
        if (error)
            *error = "address-only receipt field set differs";
        return false;
    }
    for (const auto* name : required)
        if (!f.contains(name)) {
            if (error)
                *error = "address-only receipt field is missing";
            return false;
        }
    uint64_t height = 0, when = 0;
    if (f["schema"] != ADDRESS_RECEIPT_SCHEMA || f["deployment_profile"] != DEPLOYMENT_PROFILE_ID ||
        f["genesis"] != GENESIS_HASH || f["payout_address"] != expected_payout ||
        !mining::ValidAddressOnlyDestination(expected_payout, testnet) ||
        f["network_identity_hash"] != HashToHex(Hash256d(network)) ||
        !IsLowerHex(f["validation_pubkey_hash"], 64) ||
        !IsLowerHex(f["validation_key_file_hash"], 64) || !IsLowerHex(f["validated_tip"], 64) ||
        !IsLowerHex(f["validation_public_key"], expected_pubkey.size() * 2) ||
        !IsLowerHex(f["signature"], f["signature"].size()) ||
        !ParseCanonicalUint64Text(f["validated_height"], height) || height == 0 ||
        !ParseCanonicalUint64Text(f["completed_at"], when) || when == 0 ||
        when > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        if (error)
            *error = "address-only receipt identity or field is invalid";
        return false;
    }
    const auto pub_bytes = HexToBytes(f["validation_public_key"]);
    const auto sig = HexToBytes(f["signature"]);
    if (pub_bytes.size() != expected_pubkey.size() || sig.empty() ||
        sig.size() > dilithium::SIG_MAX_BYTES) {
        if (error)
            *error = "address-only receipt signature material is malformed";
        return false;
    }
    Secp256k1PubKey pub{};
    std::copy(pub_bytes.begin(), pub_bytes.end(), pub.begin());
    if (pub != expected_pubkey || HashToHex(Hash256d(pub_bytes)) != f["validation_pubkey_hash"]) {
        if (error)
            *error = "address-only receipt validation key differs";
        return false;
    }
    const auto payload = AddressReceiptPayload(
        height, f["validated_tip"], static_cast<int64_t>(when), f["payout_address"],
        f["validation_pubkey_hash"], f["validation_key_file_hash"], f["network_identity_hash"]);
    if (body != payload + "validation_public_key=" + f["validation_public_key"] +
                    "\nsignature=" + f["signature"] + "\n" ||
        !Verify(pub, AddressReceiptDigest(payload), sig)) {
        if (error)
            *error = "address-only receipt signature or encoding is invalid";
        return false;
    }
    out.height = height;
    out.tip_hash = f["validated_tip"];
    out.miner_address = expected_payout;
    return true;
}
} // namespace veld::snapshot_bootstrap
