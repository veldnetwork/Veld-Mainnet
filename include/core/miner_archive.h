#pragma once

// Rebuildable lifetime-miner archive (Package A).
//
// This component deliberately owns the on-disk schema and every state
// transition for the non-consensus lifetime index.  VeldNode and the native
// D-STATE qualification executable both call these functions; the benchmark
// therefore cannot manufacture archive rows that production would never
// create.  Completion markers are written last, so interruption always leaves
// an archive which fails closed and can be rebuilt from canonical block bodies.

#include "blockchain.h"
#include "leveldb.h"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace veld::miner_archive {

inline constexpr const char* COUNT_PREFIX = "miner:count:";
inline constexpr const char* LAST_PREFIX = "miner:last:";
inline constexpr const char* UNDO_PREFIX = "miner:undo:";
inline constexpr const char* HEIGHT_KEY = "miner:archive:tip_height";
inline constexpr const char* HASH_KEY = "miner:archive:tip_hash";
inline constexpr size_t REBUILD_BATCH_BLOCKS = 4096;

using Record = Blockchain::MinerArchiveRecord;
using BlockAt = std::function<Block(uint64_t)>;
using TipStill = std::function<bool(uint64_t, const Hash256&)>;

enum class AdvanceResult : uint8_t {
    Ok,
    ParentMismatch,
    Error,
};

inline bool ParseUint64(const std::string& text, uint64_t& out) {
    if (text.empty() || (text.size() > 1 && text.front() == '0'))
        return false;
    uint64_t value = 0;
    for (const unsigned char c : text) {
        if (c < '0' || c > '9') return false;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (value > (UINT64_MAX - digit) / 10) return false;
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

inline bool IsCanonicalScript(const std::string& script_hex) {
    if (script_hex.size() != 50 ||
        script_hex.compare(0, 6, "76a914") != 0 ||
        script_hex.compare(46, 4, "88ac") != 0)
        return false;
    return std::all_of(
        script_hex.begin(), script_hex.end(), [](unsigned char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        });
}

inline std::string UndoHeightPrefix(uint64_t height) {
    std::ostringstream out;
    out << UNDO_PREFIX << std::setw(20) << std::setfill('0') << height << ':';
    return out.str();
}

inline std::string UndoKey(uint64_t height, const std::string& script_hex) {
    return UndoHeightPrefix(height) + script_hex;
}

inline std::string EncodeUndo(const Record& prior) {
    return std::to_string(prior.blocks_mined) + "," +
           std::to_string(prior.last_block_mined);
}

inline bool ParseUndo(const std::string& text, Record& prior) {
    const size_t comma = text.find(',');
    if (comma == std::string::npos || comma == 0 ||
        comma + 1 >= text.size() ||
        text.find(',', comma + 1) != std::string::npos)
        return false;
    uint64_t count = 0, last = 0;
    if (!ParseUint64(text.substr(0, comma), count) ||
        !ParseUint64(text.substr(comma + 1), last) ||
        (count == 0 && last != 0))
        return false;
    prior = Record{count, last};
    return true;
}

inline bool ReadRaw(db::KVStore& store, const std::string& script_hex,
                    Record& record) {
    const auto count_raw = store.Get(std::string(COUNT_PREFIX) + script_hex);
    const auto last_raw = store.Get(std::string(LAST_PREFIX) + script_hex);
    if (!count_raw && !last_raw) {
        record = Record{};
        return true;
    }
    return count_raw && last_raw &&
           ParseUint64(*count_raw, record.blocks_mined) &&
           ParseUint64(*last_raw, record.last_block_mined) &&
           record.blocks_mined > 0;
}

inline bool DeletePrefixBatched(db::KVStore& store,
                                const std::string& prefix) {
    std::string cursor;
    for (;;) {
        std::vector<std::string> keys;
        keys.reserve(REBUILD_BATCH_BLOCKS);
        store.IterateFrom(prefix, cursor,
            [&](const std::string& key, const std::string&) {
                keys.push_back(key);
                return keys.size() < REBUILD_BATCH_BLOCKS;
            });
        if (keys.empty()) return true;
        cursor = keys.back();
        db::WriteBatch batch;
        for (const auto& key : keys) batch.Delete(key);
        if (!store.Write(batch)) return false;
    }
}

inline bool MarkersMatch(db::KVStore& store, uint64_t height,
                         const Hash256& hash) {
    try {
        const auto stored_height = store.Get(HEIGHT_KEY);
        const auto stored_hash = store.Get(HASH_KEY);
        uint64_t parsed_height = 0;
        return stored_height && stored_hash &&
               ParseUint64(*stored_height, parsed_height) &&
               parsed_height == height &&
               *stored_hash == HashToHex(hash);
    } catch (...) {
        return false;
    }
}

inline std::optional<Record> Read(db::KVStore& store,
                                  const std::string& script_hex) {
    try {
        const auto height_raw = store.Get(HEIGHT_KEY);
        const auto hash_raw = store.Get(HASH_KEY);
        const auto count_raw = store.Get(std::string(COUNT_PREFIX) + script_hex);
        const auto last_raw = store.Get(std::string(LAST_PREFIX) + script_hex);
        if (!height_raw && !hash_raw && !count_raw && !last_raw)
            return Record{};
        uint64_t tip_height = 0, count = 0, last = 0;
        if (!height_raw || !hash_raw ||
            !ParseUint64(*height_raw, tip_height) ||
            !db::IsCanonicalHash256Text(*hash_raw) ||
            (count_raw.has_value() != last_raw.has_value()) ||
            (count_raw && (!ParseUint64(*count_raw, count) ||
                           !ParseUint64(*last_raw, last) || count == 0 ||
                           last > tip_height)))
            return std::nullopt;
        if (!count_raw) return Record{};
        return Record{count, last};
    } catch (...) {
        return std::nullopt;
    }
}

inline std::optional<Hash256> LogicalDigest(db::KVStore& store) {
    try {
        const auto height_raw = store.Get(HEIGHT_KEY);
        const auto hash_raw = store.Get(HASH_KEY);
        uint64_t tip_height = 0;
        if (!height_raw || !hash_raw ||
            !ParseUint64(*height_raw, tip_height) ||
            !db::IsCanonicalHash256Text(*hash_raw))
            return std::nullopt;

        uint64_t count_rows = 0, last_rows = 0;
        bool overflow = false;
        store.Iterate(COUNT_PREFIX,
            [&](const std::string&, const std::string&) {
                if (count_rows == UINT64_MAX) { overflow = true; return false; }
                ++count_rows;
                return true;
            });
        store.Iterate(LAST_PREFIX,
            [&](const std::string&, const std::string&) {
                if (last_rows == UINT64_MAX) { overflow = true; return false; }
                ++last_rows;
                return true;
            });
        if (overflow || count_rows != last_rows) return std::nullopt;

        SHA256 hash;
        hash.update("VELD_MINER_ARCHIVE_v1|");
        auto hash_u32 = [&hash](uint32_t value) {
            uint8_t bytes[4];
            for (size_t i = 0; i < 4; ++i)
                bytes[i] = static_cast<uint8_t>(value >> (8 * i));
            hash.update(bytes, sizeof(bytes));
        };
        auto hash_u64 = [&hash](uint64_t value) {
            uint8_t bytes[8];
            for (size_t i = 0; i < 8; ++i)
                bytes[i] = static_cast<uint8_t>(value >> (8 * i));
            hash.update(bytes, sizeof(bytes));
        };
        hash_u32(1);
        hash_u64(tip_height);
        const Hash256 tip_hash = HexToHash(*hash_raw);
        hash.update(tip_hash.data(), tip_hash.size());
        hash_u64(count_rows);

        const size_t count_prefix_len =
            std::char_traits<char>::length(COUNT_PREFIX);
        const size_t last_prefix_len =
            std::char_traits<char>::length(LAST_PREFIX);
        std::string count_cursor, last_cursor;
        uint64_t hashed_rows = 0;
        for (;;) {
            std::vector<std::pair<std::string, std::string>> counts, lasts;
            counts.reserve(REBUILD_BATCH_BLOCKS);
            lasts.reserve(REBUILD_BATCH_BLOCKS);
            store.IterateFrom(COUNT_PREFIX, count_cursor,
                [&](const std::string& key, const std::string& value) {
                    counts.emplace_back(key, value);
                    return counts.size() < REBUILD_BATCH_BLOCKS;
                });
            store.IterateFrom(LAST_PREFIX, last_cursor,
                [&](const std::string& key, const std::string& value) {
                    lasts.emplace_back(key, value);
                    return lasts.size() < REBUILD_BATCH_BLOCKS;
                });
            if (counts.empty() && lasts.empty()) break;
            if (counts.size() != lasts.size()) return std::nullopt;
            count_cursor = counts.back().first;
            last_cursor = lasts.back().first;
            for (size_t i = 0; i < counts.size(); ++i) {
                const std::string script =
                    counts[i].first.substr(count_prefix_len);
                uint64_t count = 0, last = 0;
                if (!IsCanonicalScript(script) ||
                    lasts[i].first.substr(last_prefix_len) != script ||
                    script.size() > UINT32_MAX ||
                    !ParseUint64(counts[i].second, count) ||
                    !ParseUint64(lasts[i].second, last) || count == 0 ||
                    last > tip_height)
                    return std::nullopt;
                hash_u32(static_cast<uint32_t>(script.size()));
                hash.update(script);
                hash_u64(count);
                hash_u64(last);
                ++hashed_rows;
            }
        }
        if (hashed_rows != count_rows) return std::nullopt;
        return hash.digest();
    } catch (...) {
        return std::nullopt;
    }
}

inline bool Rebuild(db::KVStore& store,
                    const std::optional<std::pair<uint64_t, Hash256>>& tip,
                    const BlockAt& block_at,
                    const TipStill& tip_still = {}) {
    try {
        db::WriteBatch invalidate;
        invalidate.Delete(HEIGHT_KEY);
        invalidate.Delete(HASH_KEY);
        if (!store.Write(invalidate) ||
            !DeletePrefixBatched(store, COUNT_PREFIX) ||
            !DeletePrefixBatched(store, LAST_PREFIX) ||
            !DeletePrefixBatched(store, UNDO_PREFIX))
            return false;
        if (!tip) return true;

        const uint64_t tip_height = tip->first;
        const Hash256 tip_hash = tip->second;
        std::unordered_map<std::string, Record> pending;
        std::vector<std::pair<std::string, std::string>> pending_undo;
        size_t blocks_buffered = 0;
        auto flush = [&]() -> bool {
            if (pending.empty() && pending_undo.empty()) {
                blocks_buffered = 0;
                return true;
            }
            std::vector<std::string> scripts;
            scripts.reserve(pending.size());
            for (const auto& [script, _] : pending) scripts.push_back(script);
            std::sort(scripts.begin(), scripts.end());
            std::sort(pending_undo.begin(), pending_undo.end());
            db::WriteBatch page;
            for (const auto& script : scripts) {
                const auto& record = pending.at(script);
                page.Put(std::string(COUNT_PREFIX) + script,
                         std::to_string(record.blocks_mined));
                page.Put(std::string(LAST_PREFIX) + script,
                         std::to_string(record.last_block_mined));
            }
            for (const auto& [key, value] : pending_undo)
                page.Put(key, value);
            if (!store.Write(page)) return false;
            pending.clear();
            pending_undo.clear();
            blocks_buffered = 0;
            return true;
        };

        for (uint64_t h = 0; h <= tip_height; ++h) {
            const Block block = block_at(h);
            if (block.height != h) return false;
            for (const auto& script : Blockchain::MinerScriptsForArchive(block)) {
                auto found = pending.find(script);
                if (found == pending.end()) {
                    Record current;
                    if (!ReadRaw(store, script, current)) return false;
                    found = pending.emplace(script, current).first;
                }
                auto& record = found->second;
                if (record.blocks_mined == UINT64_MAX) return false;
                const Record prior = record;
                ++record.blocks_mined;
                record.last_block_mined = h;
                if (tip_height - h <= MAX_REORG_DEPTH)
                    pending_undo.emplace_back(UndoKey(h, script),
                                              EncodeUndo(prior));
            }
            ++blocks_buffered;
            if (blocks_buffered >= REBUILD_BATCH_BLOCKS && !flush())
                return false;
        }
        if (!flush() || (tip_still && !tip_still(tip_height, tip_hash)))
            return false;
        db::WriteBatch complete;
        complete.Put(HEIGHT_KEY, std::to_string(tip_height));
        complete.Put(HASH_KEY, HashToHex(tip_hash));
        return store.Write(complete);
    } catch (...) {
        return false;
    }
}

inline AdvanceResult Advance(db::KVStore& store, const Block& block) {
    try {
        const auto stored_height = store.Get(HEIGHT_KEY);
        const auto stored_hash = store.Get(HASH_KEY);
        bool parent_matches = false;
        if (block.height == 0) {
            parent_matches = !stored_height && !stored_hash;
        } else if (stored_height && stored_hash) {
            uint64_t parsed_height = 0;
            parent_matches = ParseUint64(*stored_height, parsed_height) &&
                             parsed_height == block.height - 1 &&
                             *stored_hash ==
                                 HashToHex(block.header.prev_block_hash);
        }
        if (!parent_matches) return AdvanceResult::ParentMismatch;

        db::WriteBatch batch;
        for (const auto& script : Blockchain::MinerScriptsForArchive(block)) {
            const std::string count_key = std::string(COUNT_PREFIX) + script;
            const std::string last_key = std::string(LAST_PREFIX) + script;
            const auto count_raw = store.Get(count_key);
            const auto last_raw = store.Get(last_key);
            Record prior;
            if (count_raw || last_raw) {
                if (!count_raw || !last_raw ||
                    !ParseUint64(*count_raw, prior.blocks_mined) ||
                    !ParseUint64(*last_raw, prior.last_block_mined) ||
                    prior.blocks_mined == 0 ||
                    prior.blocks_mined == UINT64_MAX ||
                    prior.last_block_mined >= block.height)
                    return AdvanceResult::Error;
            }
            batch.Put(UndoKey(block.height, script), EncodeUndo(prior));
            batch.Put(count_key, std::to_string(prior.blocks_mined + 1));
            batch.Put(last_key, std::to_string(block.height));
        }
        if (block.height > MAX_REORG_DEPTH) {
            const std::string expired =
                UndoHeightPrefix(block.height - MAX_REORG_DEPTH - 1);
            store.Iterate(expired,
                [&](const std::string& key, const std::string&) {
                    batch.Delete(key);
                    return true;
                });
        }
        batch.Put(HEIGHT_KEY, std::to_string(block.height));
        batch.Put(HASH_KEY, HashToHex(block.GetHash()));
        return store.Write(batch) ? AdvanceResult::Ok : AdvanceResult::Error;
    } catch (...) {
        return AdvanceResult::Error;
    }
}

inline bool Rollback(db::KVStore& store, const Block& popped) {
    try {
        const auto stored_height = store.Get(HEIGHT_KEY);
        const auto stored_hash = store.Get(HASH_KEY);
        uint64_t parsed_height = 0;
        if (!stored_height && !stored_hash)
            return popped.height == 0;
        if (!stored_height || !stored_hash ||
            !ParseUint64(*stored_height, parsed_height))
            return false;
        if (popped.height > 0 && parsed_height == popped.height - 1 &&
            *stored_hash == HashToHex(popped.header.prev_block_hash))
            return true;
        if (parsed_height != popped.height ||
            *stored_hash != HashToHex(popped.GetHash()))
            return false;

        db::WriteBatch batch;
        for (const auto& script : Blockchain::MinerScriptsForArchive(popped)) {
            const std::string count_key = std::string(COUNT_PREFIX) + script;
            const std::string last_key = std::string(LAST_PREFIX) + script;
            const std::string undo_key = UndoKey(popped.height, script);
            const auto count_raw = store.Get(count_key);
            const auto last_raw = store.Get(last_key);
            const auto undo_raw = store.Get(undo_key);
            uint64_t count = 0, last = 0;
            Record prior;
            if (!count_raw || !last_raw || !undo_raw ||
                !ParseUint64(*count_raw, count) ||
                !ParseUint64(*last_raw, last) ||
                !ParseUndo(*undo_raw, prior) || count == 0 ||
                last != popped.height || prior.blocks_mined + 1 != count ||
                (prior.blocks_mined > 0 &&
                 prior.last_block_mined >= popped.height))
                return false;
            if (prior.blocks_mined == 0) {
                batch.Delete(count_key);
                batch.Delete(last_key);
            } else {
                batch.Put(count_key, std::to_string(prior.blocks_mined));
                batch.Put(last_key, std::to_string(prior.last_block_mined));
            }
            batch.Delete(undo_key);
        }
        if (popped.height == 0) {
            batch.Delete(HEIGHT_KEY);
            batch.Delete(HASH_KEY);
        } else {
            batch.Put(HEIGHT_KEY, std::to_string(popped.height - 1));
            batch.Put(HASH_KEY, HashToHex(popped.header.prev_block_hash));
        }
        return store.Write(batch);
    } catch (...) {
        return false;
    }
}

} // namespace veld::miner_archive
