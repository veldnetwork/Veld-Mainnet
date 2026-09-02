#pragma once

// Persistent, derived btcVELD redemption index.
//
// Accepted burns must remain discoverable after they leave the token ledger's
// bounded UI history, but they are not independent consensus state: the burn is
// already committed in its canonical block.  Keeping a lifetime map in the
// token digest made every node's consensus memory, hashing work, and one-shot
// RPC response grow without bound.  This index instead stores accepted records
// in the node's on-disk index database and exposes exclusive-cursor pages.
// Reorg-stale rows are harmless and filtered against the canonical block hash.

#include "leveldb.h"
#include "onchain_tokens.h"
#include "blockchain.h"

#include <algorithm>
#include <climits>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace veld {

class RedeemObligationIndex {
public:
    static constexpr const char* PREFIX = "btcvr:";
    // A completeness marker is metadata about this derived index, not an
    // obligation row.  Keeping it outside PREFIX makes every PREFIX scan a
    // strict sequence of decodable obligations (there are no magic sentinel
    // exceptions in payout/accounting code).
    static constexpr const char* CLEANUP_COMPLETE_KEY =
        "derived:btcvr:canonical-cleanup-complete:v1";
    static constexpr size_t DEFAULT_PAGE_SIZE = 256;
    static constexpr size_t MAX_PAGE_SIZE = 1000;

    struct Item {
        std::string key;
        TokenTransferRecord record;
        Hash256 block_hash{};
    };
    struct Page {
        std::vector<Item> items;
        std::string next_cursor;
        bool has_more = false;
        uint64_t tip = 0;
        Hash256 tip_hash{};
    };

    explicit RedeemObligationIndex(db::KVStore& store) : store_(store) {}

    // Exact ordered prefix for every row at one height.  The fixed 20-digit
    // decimal width is part of the on-disk schema; callers must not construct
    // a shorter textual alias when pruning a reorg suffix.
    static std::string HeightPrefix(uint64_t height) {
        std::ostringstream out;
        out << PREFIX << std::setw(20) << std::setfill('0') << height << ':';
        return out.str();
    }

    // Validate the complete key grammar, including fixed-width decimal
    // fields and lowercase 256-bit identifiers.  If requested, return the
    // exact block hash named by the key.
    static bool ValidateHeightKey(const std::string& key, uint64_t height,
                                  Hash256* block_hash = nullptr) noexcept {
        try {
            const std::string hp = HeightPrefix(height);
            // hp + txid(64) + ':' + vout(10) + ':' + block-hash(64)
            if (key.size() != hp.size() + 64 + 1 + 10 + 1 + 64 ||
                key.compare(0, hp.size(), hp) != 0)
                return false;
            const size_t txid_pos = hp.size();
            const size_t vout_pos = txid_pos + 65;
            const size_t hash_pos = vout_pos + 11;
            if (key[txid_pos + 64] != ':' || key[vout_pos + 10] != ':' ||
                !db::IsCanonicalHash256Text(
                    std::string_view(key).substr(txid_pos, 64)) ||
                !db::IsCanonicalHash256Text(
                    std::string_view(key).substr(hash_pos, 64)) ||
                !ParseFixedWidthUint32_(
                    std::string_view(key).substr(vout_pos, 10)))
                return false;
            if (block_hash)
                *block_hash = HexToHash(key.substr(hash_pos, 64));
            return true;
        } catch (...) {
            return false;
        }
    }

    // Add accepted rows to a caller-owned atomic batch.  Validation happens
    // in a private staging batch first, so a malformed late record cannot
    // leave half of its operations appended to the caller's transaction.
    bool AppendAcceptedToBatch(
            db::WriteBatch& destination, const Block& block,
            const std::vector<TokenTransferRecord>& records) const {
        db::WriteBatch staged;
        try {
            const Hash256 bh = block.GetHash();
            const std::string bh_hex = HashToHex(bh);
            for (const auto& r : records) {
                if (!r.is_redeem || r.token_id != BTCVELD_TOKEN_ID ||
                    r.txid.empty() || r.block_height != block.height)
                    return false;
                if (!IsCanonicalRecord_(r))
                    return false;
                const std::string key = Key(r, bh_hex);
                if (!ValidateHeightKey(key, block.height)) return false;
                const std::string value = Encode(r, bh);
                TokenTransferRecord decoded;
                Hash256 decoded_hash{};
                if (!Decode(value, decoded, decoded_hash) ||
                    decoded_hash != bh ||
                    Key(decoded, HashToHex(decoded_hash)) != key)
                    return false;
                staged.Put(key, value);
            }
        } catch (...) {
            return false;
        }
        destination.ops.insert(destination.ops.end(), staged.ops.begin(),
                               staged.ops.end());
        return true;
    }

    // Append deletion of every noncanonical row at `height`.  Passing nullopt
    // deletes all rows at that height (used for old suffix heights above a
    // shorter replacement tip).  Every present key AND value must decode and
    // agree before any delete is appended; corruption therefore fails closed
    // without mutating the caller's batch.
    bool AppendCanonicalHeightCleanupToBatch(
            db::WriteBatch& destination, uint64_t height,
            const std::optional<Hash256>& canonical_hash) const {
        db::WriteBatch staged;
        bool valid = true;
        try {
            store_.Iterate(HeightPrefix(height),
                [&](const std::string& key, const std::string& value) {
                    Hash256 key_hash{};
                    TokenTransferRecord record;
                    Hash256 value_hash{};
                    if (!ValidateHeightKey(key, height, &key_hash) ||
                        !Decode(value, record, value_hash) ||
                        !IsCanonicalRecord_(record) ||
                        record.block_height != height || value_hash != key_hash ||
                        Key(record, HashToHex(value_hash)) != key) {
                        valid = false;
                        return false;
                    }
                    if (!canonical_hash || value_hash != *canonical_hash)
                        staged.Delete(key);
                    return true;
                });
        } catch (...) {
            return false;
        }
        if (!valid) return false;
        destination.ops.insert(destination.ops.end(), staged.ops.begin(),
                               staged.ops.end());
        return true;
    }

    bool PutAccepted(const Block& block,
                     const std::vector<TokenTransferRecord>& records) {
        db::WriteBatch batch;
        if (!AppendAcceptedToBatch(batch, block, records)) return false;
        return batch.IsEmpty() || store_.Write(batch);
    }

    Page ReadPage(const Blockchain& chain, const std::string& cursor,
                  size_t requested_limit) {
        if (!cursor.empty() &&
            (cursor.size() > 256 || cursor.compare(0, std::char_traits<char>::length(PREFIX), PREFIX) != 0))
            throw std::invalid_argument("invalid btcVELD redeem cursor");
        const size_t limit = std::max<size_t>(1, std::min(requested_limit, MAX_PAGE_SIZE));

        Page out;
        out.items.reserve(limit);
        auto chain_guard = chain.AcquireSnapshotShared();
        out.tip = chain.Height();
        try {
            out.tip_hash = chain.GetBlockUnlocked(out.tip).GetHash();
        } catch (...) {
            // A production payout feed is never valid on an empty chain.  Leave
            // the zero hash for the caller to reject/retry rather than inventing
            // a snapshot identity.
        }
        store_.IterateFrom(PREFIX, cursor,
            [&](const std::string& key, const std::string& value) {
                Item item;
                item.key = key;
                // This feed controls whether an accepted burn remains counted as
                // unpaid backing liability.  A corrupt present row is never
                // equivalent to absence: silently skipping it could manufacture
                // mint headroom.  Key/value disagreement is likewise corruption,
                // not a harmless stale-fork row.
                if (!Decode(value, item.record, item.block_hash))
                    throw std::runtime_error(
                        "corrupt btcVELD redeem-index value");
                if (Key(item.record, HashToHex(item.block_hash)) != key)
                    throw std::runtime_error(
                        "btcVELD redeem-index key/value mismatch");
                if (item.record.block_height > out.tip) return true;
                try {
                    const Block canonical = chain.GetBlockUnlocked(item.record.block_height);
                    if (canonical.GetHash() != item.block_hash) return true;
                } catch (...) {
                    throw std::runtime_error(
                        "btcVELD redeem-index references a missing canonical height");
                }
                if (out.items.size() == limit) {
                    out.has_more = true;
                    return false;
                }
                out.items.push_back(std::move(item));
                return true;
            });
        if (!out.items.empty()) out.next_cursor = out.items.back().key;
        return out;
    }

private:
    db::KVStore& store_;

    static bool ParseFixedWidthUint32_(std::string_view text) noexcept {
        if (text.size() != 10) return false;
        uint64_t value = 0;
        for (const char c : text) {
            if (c < '0' || c > '9') return false;
            value = value * 10 + static_cast<uint64_t>(c - '0');
        }
        return value <= std::numeric_limits<uint32_t>::max();
    }

    static bool IsCanonicalRecord_(const TokenTransferRecord& r) noexcept {
        return r.is_redeem && !r.is_mint && !r.is_burn && r.to.empty() &&
               r.token_id == BTCVELD_TOKEN_ID && r.amount > 0 &&
               db::IsCanonicalHash256Text(r.txid);
    }

    static std::string Key(const TokenTransferRecord& r,
                           const std::string& block_hash_hex) {
        std::ostringstream k;
        k << PREFIX << std::setw(20) << std::setfill('0') << r.block_height
          << ':' << r.txid << ':' << std::setw(10) << std::setfill('0') << r.vout
          << ':' << block_hash_hex;
        return k.str();
    }

    static void PutU32(std::string& out, uint32_t v) {
        for (int i = 0; i < 4; ++i) out.push_back((char)((v >> (8 * i)) & 0xff));
    }
    static void PutU64(std::string& out, uint64_t v) {
        for (int i = 0; i < 8; ++i) out.push_back((char)((v >> (8 * i)) & 0xff));
    }
    static void PutString(std::string& out, const std::string& s) {
        if (s.size() > UINT32_MAX) throw std::length_error("redeem index field too large");
        PutU32(out, (uint32_t)s.size());
        out.append(s);
    }
    static bool GetU32(const std::string& in, size_t& p, uint32_t& v) {
        if (p + 4 > in.size()) return false;
        v = 0;
        for (int i = 0; i < 4; ++i) v |= (uint32_t)(uint8_t)in[p++] << (8 * i);
        return true;
    }
    static bool GetU64(const std::string& in, size_t& p, uint64_t& v) {
        if (p + 8 > in.size()) return false;
        v = 0;
        for (int i = 0; i < 8; ++i) v |= (uint64_t)(uint8_t)in[p++] << (8 * i);
        return true;
    }
    static bool GetString(const std::string& in, size_t& p, std::string& s) {
        uint32_t n = 0;
        if (!GetU32(in, p, n) || n > 1024 * 1024 || p + n > in.size()) return false;
        s.assign(in.data() + p, n);
        p += n;
        return true;
    }

    static std::string Encode(const TokenTransferRecord& r, const Hash256& bh) {
        std::string out;
        out.reserve(160 + r.from.size() + r.memo.size());
        out.push_back((char)1);
        out.append((const char*)bh.data(), bh.size());
        PutString(out, r.txid);
        PutU32(out, r.vout);
        PutString(out, r.token_id);
        PutString(out, r.from);
        PutString(out, r.to);
        PutU64(out, (uint64_t)r.amount);
        PutU64(out, r.block_height);
        PutString(out, r.memo);
        out.push_back(r.is_mint ? 1 : 0);
        out.push_back(r.is_burn ? 1 : 0);
        out.push_back(r.is_redeem ? 1 : 0);
        return out;
    }

    static bool Decode(const std::string& in, TokenTransferRecord& r,
                       Hash256& bh) {
        size_t p = 0;
        if (in.size() < 1 + bh.size() || (uint8_t)in[p++] != 1) return false;
        std::copy_n((const uint8_t*)in.data() + p, bh.size(), bh.begin());
        p += bh.size();
        uint32_t vout = 0;
        uint64_t amount = 0, height = 0;
        if (!GetString(in, p, r.txid) || !GetU32(in, p, vout) ||
            !GetString(in, p, r.token_id) || !GetString(in, p, r.from) ||
            !GetString(in, p, r.to) || !GetU64(in, p, amount) ||
            !GetU64(in, p, height) || !GetString(in, p, r.memo) ||
            p + 3 != in.size() || amount > (uint64_t)INT64_MAX) return false;
        r.vout = vout;
        r.amount = (int64_t)amount;
        r.block_height = height;
        r.timestamp = 0;  // wall-clock metadata is not part of this index
        r.is_mint = in[p++] != 0;
        r.is_burn = in[p++] != 0;
        r.is_redeem = in[p++] != 0;
        return r.is_redeem && r.token_id == BTCVELD_TOKEN_ID;
    }
};

} // namespace veld
