#pragma once

#include "../core/hash.h"
#include "../core/constants.h"
#include "../core/canonical_numeric.h"
#include "../crypto/veld_signing.h"
#include <cstdint>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace veld {

// The transfer boundary and parser share this exact ceiling.  Keeping the
// value here prevents a downloader from accepting a body the parser would
// later reject only after allocating it in full.
inline constexpr size_t kMaxCheckpointDocumentBytes = 8U * 1024U * 1024U;

struct Checkpoint {
    uint64_t              height;
    Hash256               block_hash;
    std::vector<uint8_t>  signature;
    // Wall-clock Unix seconds at signing time. Mainnet-only: folded into the
    // signed digest and gated `>= GENESIS_TIME` so a stale TEST-chain
    // checkpoint (signed before the genesis instant) can
    // NEVER verify on a mainnet binary — the launch-brick becomes
    // structurally impossible, not merely a runbook step. On the
    // testnet build this field exists but is NOT in the digest (the
    // live fleet checkpoint pipeline is byte-identical — zero
    // coordination hazard, same containment pattern as the §D-2
    // mainnet-only lottery excision).
    uint64_t              signed_at{0};

    Checkpoint() : height(0), block_hash{}, signed_at(0) {}
    Checkpoint(uint64_t h, const Hash256& bh, std::vector<uint8_t> sig,
               uint64_t sat = 0)
        : height(h), block_hash(bh), signature(std::move(sig)),
          signed_at(sat) {}
};

inline Hash256 ComputeCheckpointDigest(uint64_t height,
                                       const Hash256& block_hash,
                                       uint64_t signed_at = 0) {
    std::vector<uint8_t> msg;
#if defined(VELD_PUBLIC_MAINNET)
    // Fresh public mainnet uses a structurally chain-bound checkpoint domain.
    // The public testnet deliberately retains V1 for its clean disposable
    // lineage; a final-mainnet binary can never verify testnet checkpoints
    // because it requires this V2 frame and a fresh compiled genesis.
    static constexpr char DOMAIN[] = "VELD_CHECKPOINT_V2|";
    msg.insert(msg.end(), DOMAIN, DOMAIN + sizeof(DOMAIN) - 1);
    for (int i = 0; i < 4; ++i)
        msg.push_back((uint8_t)((MAINNET_MAGIC >> (i * 8)) & 0xFF));
    msg.push_back(0x4D);  // final-mainnet signing domain, matching sighash/QC
    const Hash256 genesis = HexToHash(GENESIS_HASH);
    msg.insert(msg.end(), genesis.begin(), genesis.end());
#else
    static constexpr char DOMAIN[] = "VELD_CHECKPOINT|";
    msg.insert(msg.end(), DOMAIN, DOMAIN + sizeof(DOMAIN) - 1);
#endif
    for (int i = 0; i < 8; ++i)
        msg.push_back((uint8_t)((height >> (i * 8)) & 0xFF));
    msg.insert(msg.end(), block_hash.begin(), block_hash.end());
#ifdef VELD_MAINNET_POW
    // Chain-scoped signature binding prevents checkpoints from another network
    // profile from being accepted on mainnet.
    for (int i = 0; i < 8; ++i)
        msg.push_back((uint8_t)((signed_at >> (i * 8)) & 0xFF));
#else
    if (height >= BATCH2_HARDENING_HEIGHT) {
        for (int i = 0; i < 8; ++i)
            msg.push_back((uint8_t)((signed_at >> (i * 8)) & 0xFF));
    } else {
        (void)signed_at;
    }
#endif
    SHA256 h;
    h.update(msg.data(), msg.size());
    return h.digest();
}

inline bool LoadFleetCheckpointPubKey(Secp256k1PubKey& out_pubkey) {
    const std::string hex = FLEET_CHECKPOINT_PUBKEY_HEX;
    if (hex.size() != 1952 * 2) return false;
    auto hex_nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < 1952; ++i) {
        int hi = hex_nibble(hex[i*2]);
        int lo = hex_nibble(hex[i*2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out_pubkey[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

inline bool VerifyCheckpoint(const Checkpoint& cp) {
    if (cp.signature.empty()) return false;
    if (HashIsZero(cp.block_hash)) return false;
#ifdef VELD_MAINNET_POW
    if (cp.signed_at < GENESIS_TIME) return false;
#endif
    Secp256k1PubKey pubkey{};
    if (!LoadFleetCheckpointPubKey(pubkey)) return false;
    Hash256 digest = ComputeCheckpointDigest(cp.height, cp.block_hash,
                                             cp.signed_at);
    return Verify(pubkey, digest, cp.signature);
}

class CheckpointStore {
public:
    bool Add(const Checkpoint& cp) {
        if (!VerifyCheckpoint(cp)) return false;
        std::unique_lock lock(mtx_);
        auto it = by_height_.find(cp.height);
        if (it != by_height_.end()) {
            return it->second.block_hash == cp.block_hash;
        }
        by_height_[cp.height] = cp;
        return true;
    }

    std::optional<Checkpoint> Get(uint64_t height) const {
        std::shared_lock lock(mtx_);
        auto it = by_height_.find(height);
        if (it == by_height_.end()) return std::nullopt;
        return it->second;
    }

    std::optional<Checkpoint> Latest() const {
        std::shared_lock lock(mtx_);
        if (by_height_.empty()) return std::nullopt;
        return by_height_.rbegin()->second;
    }

    std::vector<Checkpoint> SinceHeight(uint64_t min_height) const {
        std::shared_lock lock(mtx_);
        std::vector<Checkpoint> out;
        for (auto it = by_height_.lower_bound(min_height);
             it != by_height_.end(); ++it) {
            out.push_back(it->second);
        }
        return out;
    }

    std::vector<Checkpoint> UpToHeight(uint64_t max_height) const {
        std::shared_lock lock(mtx_);
        std::vector<Checkpoint> out;
        for (auto it = by_height_.begin();
             it != by_height_.end() && it->first <= max_height; ++it) {
            out.push_back(it->second);
        }
        return out;
    }

    size_t Size() const {
        std::shared_lock lock(mtx_);
        return by_height_.size();
    }

private:
    mutable std::shared_mutex            mtx_;
    std::map<uint64_t, Checkpoint>       by_height_;
};

inline std::vector<Checkpoint> ParseCheckpointsJson(const std::string& json) {
    std::vector<Checkpoint> out;
    if (json.size() > kMaxCheckpointDocumentBytes) return out;
    auto hex_to_bytes = [](const std::string& h) -> std::vector<uint8_t> {
        if (h.size() % 2) return {};
        std::vector<uint8_t> b;
        b.reserve(h.size() / 2);
        for (size_t i = 0; i < h.size(); i += 2) {
            int hi = -1, lo = -1;
            char c1 = h[i], c2 = h[i+1];
            if (c1 >= '0' && c1 <= '9') hi = c1 - '0';
            else if (c1 >= 'a' && c1 <= 'f') hi = c1 - 'a' + 10;
            else if (c1 >= 'A' && c1 <= 'F') hi = c1 - 'A' + 10;
            if (c2 >= '0' && c2 <= '9') lo = c2 - '0';
            else if (c2 >= 'a' && c2 <= 'f') lo = c2 - 'a' + 10;
            else if (c2 >= 'A' && c2 <= 'F') lo = c2 - 'A' + 10;
            if (hi < 0 || lo < 0) return {};
            b.push_back((uint8_t)((hi << 4) | lo));
        }
        return b;
    };

    size_t cursor = 0;
    while (cursor < json.size()) {
        size_t obj_start = json.find('{', cursor);
        if (obj_start == std::string::npos) break;
        size_t obj_end = json.find('}', obj_start);
        if (obj_end == std::string::npos) break;
        const std::string_view obj(
            json.data() + obj_start, obj_end - obj_start + 1);
        cursor = obj_end + 1;
        std::string h_str, hash_hex, sig_hex;
        auto find_in_obj = [&](const std::string& name, size_t max_length,
                               std::string& value) -> bool {
            std::string needle = "\"" + name + "\"";
            size_t pos = obj.find(needle);
            if (pos == std::string_view::npos) return false;
            if (obj.find(needle, pos + needle.size()) !=
                std::string_view::npos)
                return false;
            pos += needle.size();
            while (pos < obj.size() && (obj[pos] == ' ' ||
                   obj[pos] == '\t' || obj[pos] == '\n' ||
                   obj[pos] == '\r')) ++pos;
            if (pos >= obj.size() || obj[pos] != ':') return false;
            ++pos;
            while (pos < obj.size() && (obj[pos] == ' ' ||
                   obj[pos] == '\t' || obj[pos] == '\n' ||
                   obj[pos] == '\r')) ++pos;
            if (pos >= obj.size()) return false;
            if (obj[pos] == '"') {
                ++pos;
                size_t end = obj.find('"', pos);
                if (end == std::string_view::npos ||
                    end - pos > max_length) return false;
                value.assign(obj.data() + pos, end - pos);
                ++end;
                while (end < obj.size() && (obj[end] == ' ' ||
                       obj[end] == '\t' || obj[end] == '\n' ||
                       obj[end] == '\r')) ++end;
                if (end >= obj.size() ||
                    (obj[end] != ',' && obj[end] != '}')) return false;
            } else {
                size_t end = pos;
                while (end < obj.size() && (obj[end] >= '0' && obj[end] <= '9')) ++end;
                if (end == pos || end - pos > max_length) return false;
                value.assign(obj.data() + pos, end - pos);
                while (end < obj.size() && (obj[end] == ' ' ||
                       obj[end] == '\t' || obj[end] == '\n' ||
                       obj[end] == '\r')) ++end;
                if (end >= obj.size() ||
                    (obj[end] != ',' && obj[end] != '}')) return false;
            }
            return true;
        };
        if (!find_in_obj("height", 20, h_str)) continue;
        if (!find_in_obj("hash", 64, hash_hex)) continue;
        if (!find_in_obj("sig", 6618, sig_hex)) continue;
        Checkpoint cp;
        if (!ParseCanonicalUint64Text(h_str, cp.height)) continue;
        auto canonical_hex = [](const std::string& text, size_t size) {
            if (text.size() != size) return false;
            for (const char c : text) {
                if (!((c >= '0' && c <= '9') ||
                      (c >= 'a' && c <= 'f'))) return false;
            }
            return true;
        };
        if (!canonical_hex(hash_hex, 64) ||
            !canonical_hex(sig_hex, 6618)) continue;
        auto hash_bytes = hex_to_bytes(hash_hex);
        if (hash_bytes.size() != 32) continue;
        std::copy(hash_bytes.begin(), hash_bytes.end(), cp.block_hash.begin());
        cp.signature = hex_to_bytes(sig_hex);
        if (cp.signature.empty()) continue;
        std::string sat_str;
        const bool has_signed_at =
            obj.find("\"signed_at\"") != std::string_view::npos;
        if (has_signed_at) {
            if (!find_in_obj("signed_at", 20, sat_str) ||
                !ParseCanonicalUint64Text(sat_str, cp.signed_at)) continue;
        }
        out.push_back(std::move(cp));
    }
    return out;
}

}
