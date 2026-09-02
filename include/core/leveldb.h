#pragma once

#include <cstdio>
#include <algorithm>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

#include "../core/hash.h"
#include "../core/block.h"
#include "../core/chain_work.h"
#include "../core/canonical_numeric.h"
#include "../core/constants.h"
#include <chrono>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <fstream>
#include <iterator>
#include <filesystem>
#include <stdexcept>
#include <functional>
#include <memory>
#include <sstream>
#include <mutex>
#include <tuple>

#ifdef VELD_USE_LEVELDB
#include <leveldb/db.h>
#include <leveldb/write_batch.h>
#include <leveldb/filter_policy.h>
#include <leveldb/cache.h>
#endif

namespace veld {
namespace db {

namespace fs = std::filesystem;

inline bool IsCanonicalHash256Text(std::string_view text) noexcept {
    if (text.size() != 64) return false;
    for (const char c : text) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

// ─────────────────────────────────────────────
//  WRITE BATCH
//  Atomic multi-key write — all or nothing
// ─────────────────────────────────────────────
struct WriteBatch {
    enum class Kind : uint8_t { Put, Delete };
    struct Op { Kind kind; std::string key; std::string value; };
    std::vector<Op> ops;

    void Put(const std::string& key, const std::string& value) {
        ops.push_back({Kind::Put, key, value});
    }
    void Delete(const std::string& key) {
        ops.push_back({Kind::Delete, key, {}});
    }
    void Clear() { ops.clear(); }
    bool IsEmpty() const { return ops.empty(); }
};

class KVStore {
public:
    virtual ~KVStore() = default;
    virtual bool         Put(const std::string& key, const std::string& value) = 0;
    virtual bool         Delete(const std::string& key) = 0;
    virtual std::optional<std::string> Get(const std::string& key) = 0;
    virtual bool         Has(const std::string& key) = 0;
    virtual bool         Write(const WriteBatch& batch) = 0;
    virtual void         Iterate(const std::string& prefix,
                                 std::function<bool(const std::string&, const std::string&)> fn) = 0;
    // Ordered, exclusive-cursor iteration for bounded RPC/index pages.  The
    // production LevelDB implementation seeks directly to `start_after`; the
    // flat-file fallback sorts matching keys before invoking the callback.
    // Returning false stops immediately, so callers never need to materialize
    // an unbounded response just to discover whether another item exists.
    virtual void         IterateFrom(const std::string& prefix,
                                     const std::string& start_after,
                                     std::function<bool(const std::string&, const std::string&)> fn) = 0;
    virtual std::string  GetPath() const = 0;
    virtual std::string  GetStats() const = 0;
};

#ifdef VELD_USE_LEVELDB

// LevelDB may recover a damaged WAL by dropping the unreadable record and
// continuing with an apparently empty database.  That behavior is appropriate
// for a cache, but the canonical index is authoritative startup state: losing
// its first record must never make an intact chain look like a fresh node.
// Validate physical log records before DB::Open gets a chance to recover or
// create files.  LevelDB log checksums are masked CRC32C over type || payload.
inline uint32_t LevelDBLogCrc32c(const uint8_t* data, size_t size) noexcept {
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0x82f63b78u &
                                (0u - (crc & 1u)));
    }
    return ~crc;
}

inline uint32_t MaskLevelDBLogCrc32c(uint32_t crc) noexcept {
    return ((crc >> 15) | (crc << 17)) + 0xa282ead8u;
}

inline bool ValidateLevelDBLogFile(const fs::path& path,
                                   std::string* error = nullptr) {
    constexpr size_t LOG_BLOCK_SIZE = 32768;
    constexpr size_t LOG_HEADER_SIZE = 7;
    auto fail = [&](const std::string& why) {
        if (error) *error = path.string() + ": " + why;
        return false;
    };

    std::ifstream in(path, std::ios::binary);
    if (!in) return fail("cannot open LevelDB log for preflight");

    std::vector<uint8_t> block(LOG_BLOCK_SIZE);
    bool fragmented = false;
    for (;;) {
        in.read(reinterpret_cast<char*>(block.data()),
                static_cast<std::streamsize>(block.size()));
        const size_t got = static_cast<size_t>(in.gcount());
        if (got == 0) break;

        size_t pos = 0;
        while (pos < got) {
            const size_t remaining = got - pos;
            if (remaining < LOG_HEADER_SIZE) {
                for (size_t i = pos; i < got; ++i) {
                    if (block[i] != 0)
                        return fail("nonzero truncated physical-record header");
                }
                pos = got;
                break;
            }

            const uint32_t stored_crc =
                static_cast<uint32_t>(block[pos]) |
                (static_cast<uint32_t>(block[pos + 1]) << 8) |
                (static_cast<uint32_t>(block[pos + 2]) << 16) |
                (static_cast<uint32_t>(block[pos + 3]) << 24);
            const uint16_t length =
                static_cast<uint16_t>(block[pos + 4]) |
                (static_cast<uint16_t>(block[pos + 5]) << 8);
            const uint8_t type = block[pos + 6];

            // LevelDB leaves zero-filled trailers when a record cannot fit in
            // the current 32 KiB physical block.
            if (stored_crc == 0 && length == 0 && type == 0) {
                for (size_t i = pos; i < got; ++i) {
                    if (block[i] != 0)
                        return fail("nonzero bytes after zero log trailer");
                }
                pos = got;
                break;
            }
            if (type < 1 || type > 4)
                return fail("invalid physical-record type");
            if (static_cast<size_t>(length) > remaining - LOG_HEADER_SIZE)
                return fail("truncated physical-record payload");

            std::vector<uint8_t> checksum_input;
            checksum_input.reserve(static_cast<size_t>(length) + 1);
            checksum_input.push_back(type);
            checksum_input.insert(
                checksum_input.end(), block.begin() + pos + LOG_HEADER_SIZE,
                block.begin() + pos + LOG_HEADER_SIZE + length);
            const uint32_t actual_crc = MaskLevelDBLogCrc32c(
                LevelDBLogCrc32c(checksum_input.data(), checksum_input.size()));
            if (stored_crc != actual_crc)
                return fail("physical-record checksum mismatch");

            if (type == 1) {
                if (fragmented)
                    return fail("full record encountered inside fragment");
            } else if (type == 2) {
                if (fragmented)
                    return fail("nested first fragment");
                fragmented = true;
            } else if (type == 3) {
                if (!fragmented)
                    return fail("middle fragment without first fragment");
            } else {
                if (!fragmented)
                    return fail("last fragment without first fragment");
                fragmented = false;
            }

            pos += LOG_HEADER_SIZE + static_cast<size_t>(length);
        }
        if (got < block.size()) {
            if (!in.eof() && in.fail())
                return fail("I/O failure while reading LevelDB log");
            break;
        }
    }
    if (fragmented)
        return fail("unterminated fragmented logical record");
    return true;
}

inline bool ValidateLevelDBLogsInDirectory(const fs::path& directory,
                                           std::string* error = nullptr) {
    std::error_code ec;
    for (fs::directory_iterator it(directory, ec), end; it != end;
         it.increment(ec)) {
        if (ec) {
            if (error) *error = directory.string() +
                ": cannot enumerate LevelDB directory: " + ec.message();
            return false;
        }
        if (!it->is_regular_file(ec)) {
            if (ec) {
                if (error) *error = it->path().string() +
                    ": cannot inspect LevelDB entry: " + ec.message();
                return false;
            }
            continue;
        }
        if (it->path().extension() == ".log" &&
            !ValidateLevelDBLogFile(it->path(), error))
            return false;
    }
    if (ec) {
        if (error) *error = directory.string() +
            ": cannot enumerate LevelDB directory: " + ec.message();
        return false;
    }
    return true;
}

inline bool ValidateLevelDBCurrentManifest(const fs::path& directory,
                                           std::string* error = nullptr) {
    auto fail = [&](const std::string& why) {
        if (error) *error = directory.string() + ": " + why;
        return false;
    };
    const fs::path current = directory / "CURRENT";
    std::error_code ec;
    if (!fs::is_regular_file(current, ec) || ec)
        return fail("CURRENT is missing or is not a regular file");

    std::ifstream in(current, std::ios::binary);
    if (!in) return fail("cannot read CURRENT");
    std::string manifest_name(
        (std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>());
    if (!in.eof() && in.fail()) return fail("I/O failure while reading CURRENT");
    if (manifest_name.empty() || manifest_name.back() != '\n')
        return fail("CURRENT is not newline terminated");
    manifest_name.pop_back();
    static constexpr std::string_view prefix = "MANIFEST-";
    if (manifest_name.size() <= prefix.size() ||
        manifest_name.compare(0, prefix.size(), prefix) != 0)
        return fail("CURRENT does not name a canonical manifest");
    for (size_t i = prefix.size(); i < manifest_name.size(); ++i) {
        if (manifest_name[i] < '0' || manifest_name[i] > '9')
            return fail("CURRENT manifest name is not canonical");
    }

    const fs::path manifest = directory / manifest_name;
    if (!fs::is_regular_file(manifest, ec) || ec)
        return fail("CURRENT names a missing or non-regular manifest");
    std::string manifest_error;
    if (!ValidateLevelDBLogFile(manifest, &manifest_error)) {
        if (error) *error = "index manifest preflight failed: " + manifest_error;
        return false;
    }
    return true;
}

class LevelDBStore : public KVStore {
public:
    explicit LevelDBStore(const std::string& path,
                          bool create_if_missing = true) : path_(path) {
        leveldb::Options opts;
        opts.create_if_missing = create_if_missing;
        opts.paranoid_checks = true;
        size_t write_buffer_mb = 64;
        size_t block_cache_mb  = 128;
        if (const char* w = std::getenv("VELD_LEVELDB_WRITE_BUFFER_MB")) {
            uint64_t v = 0;
            if (ParseCanonicalUint64Text(w, v) && v >= 1 && v <= 4096)
                write_buffer_mb = static_cast<size_t>(v);
        }
        if (const char* c = std::getenv("VELD_LEVELDB_BLOCK_CACHE_MB")) {
            uint64_t v = 0;
            if (ParseCanonicalUint64Text(c, v) && v >= 1 && v <= 4096)
                block_cache_mb = static_cast<size_t>(v);
        }
        opts.write_buffer_size = write_buffer_mb * 1024 * 1024;
        block_cache_.reset(leveldb::NewLRUCache(block_cache_mb * 1024 * 1024));
        filter_policy_.reset(leveldb::NewBloomFilterPolicy(10));
        opts.block_cache = block_cache_.get();
        opts.filter_policy = filter_policy_.get();
        opts.compression = leveldb::kNoCompression;

        leveldb::DB* db = nullptr;
        leveldb::Status s = leveldb::DB::Open(opts, path, &db);
        if (!s.ok() || !db)
            throw std::runtime_error("LevelDB open failed at " + path + ": " + s.ToString());
        db_.reset(db);
    }

    bool Put(const std::string& key, const std::string& value) override {
        leveldb::WriteOptions opts;
        opts.sync = true;
        auto s = db_->Put(opts, key, value);
        return s.ok();
    }

    bool Delete(const std::string& key) override {
        leveldb::WriteOptions opts;
        opts.sync = true;
        auto s = db_->Delete(opts, key);
        return s.ok();
    }

    std::optional<std::string> Get(const std::string& key) override {
        std::string value;
        auto s = db_->Get(leveldb::ReadOptions(), key, &value);
        if (s.IsNotFound()) return std::nullopt;
        if (!s.ok()) throw std::runtime_error("LevelDB get error: " + s.ToString());
        return value;
    }

    bool Has(const std::string& key) override {
        return Get(key).has_value();
    }

    bool Write(const WriteBatch& batch) override {
        leveldb::WriteBatch ldb_batch;
        for (const auto& op : batch.ops) {
            if (op.kind == WriteBatch::Kind::Put) ldb_batch.Put(op.key, op.value);
            else                                  ldb_batch.Delete(op.key);
        }
        leveldb::WriteOptions opts;
        opts.sync = true;
        return db_->Write(opts, &ldb_batch).ok();
    }

    void Iterate(const std::string& prefix,
                 std::function<bool(const std::string&, const std::string&)> fn) override {
        leveldb::ReadOptions opts;
        opts.snapshot = db_->GetSnapshot();
        auto it = db_->NewIterator(opts);
        struct Guard {
            leveldb::DB* db; leveldb::Iterator* it; const leveldb::Snapshot* snap;
            ~Guard() { delete it; db->ReleaseSnapshot(snap); }
        } guard{db_.get(), it, opts.snapshot};

        for (it->Seek(prefix); it->Valid(); it->Next()) {
            const std::string key = it->key().ToString();
            if (key.size() < prefix.size() || key.substr(0, prefix.size()) != prefix) break;
            if (!fn(key, it->value().ToString())) break;
        }
        const leveldb::Status status = it->status();
        if (!status.ok())
            throw std::runtime_error(
                "LevelDB prefix iteration failed: " + status.ToString());
    }

    void IterateFrom(const std::string& prefix, const std::string& start_after,
                     std::function<bool(const std::string&, const std::string&)> fn) override {
        leveldb::ReadOptions opts;
        opts.snapshot = db_->GetSnapshot();
        auto it = db_->NewIterator(opts);
        struct Guard {
            leveldb::DB* db; leveldb::Iterator* it; const leveldb::Snapshot* snap;
            ~Guard() { delete it; db->ReleaseSnapshot(snap); }
        } guard{db_.get(), it, opts.snapshot};

        const std::string seek = start_after.empty() ? prefix : start_after;
        for (it->Seek(seek); it->Valid(); it->Next()) {
            const std::string key = it->key().ToString();
            if (!start_after.empty() && key == start_after) continue;
            if (key.size() < prefix.size() || key.compare(0, prefix.size(), prefix) != 0) break;
            if (!fn(key, it->value().ToString())) break;
        }
        const leveldb::Status status = it->status();
        if (!status.ok())
            throw std::runtime_error(
                "LevelDB ordered prefix iteration failed: " +
                status.ToString());
    }

    std::string GetPath() const override { return path_; }

    std::string GetStats() const override {
        std::string stats;
        db_->GetProperty("leveldb.stats", &stats);
        return stats;
    }

    // Write a read-consistent copy to a fresh LevelDB. A pinned source
    // snapshot prevents MANIFEST, table, and WAL state from being captured at
    // different points while live writes continue. The caller provides
    // cross-database atomicity, normally by holding chain_mutex_ shared across
    // all database copies. On failure, target_path may contain a partial dump
    // and must be removed before retry.
    bool DumpToFreshLevelDB(const std::string& target_path) {
        leveldb::Options dst_opts;
        dst_opts.create_if_missing = true;
        dst_opts.error_if_exists = true;
        dst_opts.compression = leveldb::kNoCompression;
        leveldb::DB* dst_db_raw = nullptr;
        leveldb::Status s = leveldb::DB::Open(dst_opts, target_path, &dst_db_raw);
        if (!s.ok() || !dst_db_raw) return false;
        std::unique_ptr<leveldb::DB> dst_db(dst_db_raw);

        leveldb::ReadOptions ropts;
        ropts.snapshot = db_->GetSnapshot();
        struct SnapGuard {
            leveldb::DB* db; const leveldb::Snapshot* snap;
            ~SnapGuard() { if (snap) db->ReleaseSnapshot(snap); }
        } guard{db_.get(), ropts.snapshot};

        std::unique_ptr<leveldb::Iterator> it(db_->NewIterator(ropts));
        leveldb::WriteOptions wopts;
        wopts.sync = false;
        leveldb::WriteBatch batch;
        constexpr size_t FLUSH_BYTES = 4 * 1024 * 1024;
        size_t pending_bytes = 0;
        for (it->SeekToFirst(); it->Valid(); it->Next()) {
            batch.Put(it->key(), it->value());
            pending_bytes += it->key().size() + it->value().size();
            if (pending_bytes >= FLUSH_BYTES) {
                if (!dst_db->Write(wopts, &batch).ok()) return false;
                batch.Clear();
                pending_bytes = 0;
            }
        }
        // Invalid() is also LevelDB's terminal error signal.  Never promote a
        // truncated snapshot copy as a clean end-of-database traversal.
        if (!it->status().ok()) return false;
        if (pending_bytes > 0) {
            if (!dst_db->Write(wopts, &batch).ok()) return false;
        }

        leveldb::WriteOptions fsync_opts;
        fsync_opts.sync = true;
        leveldb::WriteBatch empty;
        if (!dst_db->Write(fsync_opts, &empty).ok()) return false;

        return true;
    }

private:
    // Declared before db_ so reverse member destruction closes the database
    // before releasing policies referenced by its Options.
    std::unique_ptr<leveldb::Cache> block_cache_;
    std::unique_ptr<const leveldb::FilterPolicy> filter_policy_;
    std::unique_ptr<leveldb::DB> db_;
    std::string path_;
};

#endif

class FlatFileStore : public KVStore {
public:
    explicit FlatFileStore(const std::string& path) : path_(path) {
        fs::create_directories(path);
        LoadFromDisk();
    }

    ~FlatFileStore() {
        FlushToDisk();
    }

    bool Put(const std::string& key, const std::string& value) override {
        std::lock_guard<std::mutex> lock(mutex_);
        store_[key] = value;
        dirty_ = true;
        return true;
    }

    bool Delete(const std::string& key) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = store_.find(key);
        if (it == store_.end()) return false;
        store_.erase(it);
        dirty_ = true;
        return true;
    }

    std::optional<std::string> Get(const std::string& key) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = store_.find(key);
        if (it == store_.end()) return std::nullopt;
        return it->second;
    }

    bool Has(const std::string& key) override {
        std::lock_guard<std::mutex> lock(mutex_);
        return store_.count(key) > 0;
    }

    bool Write(const WriteBatch& batch) override {
        std::lock_guard<std::mutex> lock(mutex_);
        AppendWAL(batch);
        for (const auto& op : batch.ops) {
            if (op.kind == WriteBatch::Kind::Put) store_[op.key] = op.value;
            else                                  store_.erase(op.key);
        }
        dirty_ = true;
        FlushToDiskNoLock();
        return true;
    }

    void Iterate(const std::string& prefix,
                 std::function<bool(const std::string&, const std::string&)> fn) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [key, value] : store_) {
            if (key.substr(0, prefix.size()) == prefix) {
                if (!fn(key, value)) break;
            }
        }
    }

    void IterateFrom(const std::string& prefix, const std::string& start_after,
                     std::function<bool(const std::string&, const std::string&)> fn) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> keys;
        keys.reserve(store_.size());
        for (const auto& [key, _value] : store_)
            if (key.size() >= prefix.size() && key.compare(0, prefix.size(), prefix) == 0 &&
                (start_after.empty() || key > start_after))
                keys.push_back(key);
        std::sort(keys.begin(), keys.end());
        for (const auto& key : keys) {
            auto it = store_.find(key);
            if (it != store_.end() && !fn(it->first, it->second)) break;
        }
    }

    std::string GetPath() const override { return path_; }

    std::string GetStats() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return "FlatFileStore: " + std::to_string(store_.size()) + " keys at " + path_;
    }

    size_t KeyCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return store_.size();
    }

private:
    std::string path_;
    std::unordered_map<std::string, std::string> store_;
    mutable std::mutex mutex_;
    bool dirty_ = false;

    std::string DataFile()   const { return path_ + "/store.dat"; }
    std::string TempFile()   const { return path_ + "/store.tmp"; }
    std::string WalFile()    const { return path_ + "/wal.log";   }

    void AppendWAL(const WriteBatch& batch) {
        FILE* f = std::fopen(WalFile().c_str(), "ab");
        if (!f) return;
        auto w = [&](const void* p, size_t n){ std::fwrite(p, 1, n, f); };
        auto wle32 = [&](uint32_t v){
            uint8_t b[4] = {(uint8_t)(v), (uint8_t)(v>>8), (uint8_t)(v>>16), (uint8_t)(v>>24)};
            w(b, 4);
        };
        for (const auto& op : batch.ops) {
            char tag = op.kind == WriteBatch::Kind::Put ? 'P' : 'D';
            w(&tag, 1);
            wle32((uint32_t)op.key.size()); w(op.key.data(), op.key.size());
            wle32(op.kind == WriteBatch::Kind::Put ? (uint32_t)op.value.size() : 0);
            if (op.kind == WriteBatch::Kind::Put) w(op.value.data(), op.value.size());
        }
        std::fflush(f);
#ifdef _WIN32
        int fd = _fileno(f);
        if (fd >= 0) _commit(fd);
#else
        int fd = fileno(f);
        if (fd >= 0) ::fsync(fd);
#endif
        std::fclose(f);
    }

    void ReplayWAL() {
        std::ifstream wal(WalFile(), std::ios::binary);
        if (!wal) return;
        auto rle32 = [&](uint32_t& out) -> bool {
            uint8_t b[4];
            wal.read(reinterpret_cast<char*>(b), 4);
            if (!wal) return false;
            out = (uint32_t)b[0] | ((uint32_t)b[1]<<8) | ((uint32_t)b[2]<<16) | ((uint32_t)b[3]<<24);
            return true;
        };
        while (wal.peek() != EOF) {
            char type = 0;
            wal.get(type);
            if (type != 'P' && type != 'D') break;
            uint32_t klen = 0;
            if (!rle32(klen) || klen > 1024 * 1024) break;
            std::string key(klen, '\0');
            wal.read(&key[0], klen);
            uint32_t vlen = 0;
            if (!rle32(vlen) || vlen > 64 * 1024 * 1024) break;
            std::string val(vlen, '\0');
            if (vlen > 0) wal.read(&val[0], vlen);
            if (!wal) break;
            if (type == 'P') store_[key] = val;
            else             store_.erase(key);
        }
    }

    void LoadFromDisk() {
        std::ifstream ifs(DataFile(), std::ios::binary);
        if (!ifs) {
            ReplayWAL();
            return;
        }

        auto rle64 = [&](uint64_t& out) -> bool {
            uint8_t b[8];
            ifs.read(reinterpret_cast<char*>(b), 8);
            if (!ifs) return false;
            out = 0;
            for (int i = 0; i < 8; ++i) out |= (uint64_t)b[i] << (i * 8);
            return true;
        };
        auto rle32 = [&](uint32_t& out) -> bool {
            uint8_t b[4];
            ifs.read(reinterpret_cast<char*>(b), 4);
            if (!ifs) return false;
            out = (uint32_t)b[0] | ((uint32_t)b[1]<<8) | ((uint32_t)b[2]<<16) | ((uint32_t)b[3]<<24);
            return true;
        };

        uint64_t count = 0;
        if (!rle64(count)) return;

        for (uint64_t i = 0; i < count; ++i) {
            uint32_t klen = 0, vlen = 0;
            if (!rle32(klen)) break;
            std::string key(klen, '\0');
            ifs.read(&key[0], klen);
            if (!rle32(vlen)) break;
            std::string val(vlen, '\0');
            if (vlen > 0) ifs.read(&val[0], vlen);
            if (!ifs) break;
            store_[key] = val;
        }

        ReplayWAL();
    }

    void FlushToDisk() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!dirty_) return;
        FlushToDiskNoLock();
    }

    void FlushToDiskNoLock() {
        std::ofstream ofs(TempFile(), std::ios::binary | std::ios::trunc);
        if (!ofs) return;

        auto wle64 = [&](uint64_t v){
            uint8_t b[8];
            for (int i = 0; i < 8; ++i) b[i] = (uint8_t)(v >> (i * 8));
            ofs.write(reinterpret_cast<const char*>(b), 8);
        };
        auto wle32 = [&](uint32_t v){
            uint8_t b[4] = {(uint8_t)v, (uint8_t)(v>>8), (uint8_t)(v>>16), (uint8_t)(v>>24)};
            ofs.write(reinterpret_cast<const char*>(b), 4);
        };

        wle64((uint64_t)store_.size());

        for (const auto& [key, val] : store_) {
            wle32((uint32_t)key.size());
            ofs.write(key.data(), key.size());
            wle32((uint32_t)val.size());
            ofs.write(val.data(), val.size());
        }
        ofs.close();

        // Atomically replace store.dat with temp file
        // If rename fails, temp file remains and WAL is NOT cleared (safe recovery)
        std::error_code ec;
        fs::rename(TempFile(), DataFile(), ec);
        if (ec) return;

        {
            std::ofstream wal(WalFile(), std::ios::binary | std::ios::trunc);
        }
        dirty_ = false;
    }
};

// A durable write reporting false (or throwing) is not proof that it did not
// reach the WAL.  Callers must never compensate an in-memory canonical change
// after receiving this exception; they must fail-stop and let startup recovery
// select the old or new journaled frame.
class DurableWriteUncertain : public std::runtime_error {
public:
    explicit DurableWriteUncertain(const std::string& message)
        : std::runtime_error(message) {}
};

class VeldDB {
public:
    // Opaque node-security memory carried in the authoritative index DB.  The
    // node owns the VLF1 codec; VeldDB only bounds the value and, critically,
    // publishes it in the same atomic WriteBatch as chain:tip.  This closes
    // the power-loss window between a durable anchor-promoting block and the
    // external owner-only VLF1 mirror.
    static constexpr const char* ANCHOR_SECURITY_FLOOR_KEY =
        "security:anchor-floor:v1";
    static constexpr size_t MAX_ANCHOR_SECURITY_FLOOR_BYTES = 4096;
    static constexpr const char* DURABLE_PUBLICATION_PENDING_KEY =
        "security:durable-publication-pending:v1";
    static constexpr size_t DURABLE_PUBLICATION_PENDING_SIZE = 44;
    // Retained across the entire pre-publication portion of a multi-block
    // reorg.  This is deliberately a different key from the short-lived
    // `reorg:utxo:rebuilding` marker used by generic UTXO reconciliation:
    // reconciliation must never overwrite the exact identity needed to decide
    // which canonical chain is authoritative after a crash.
    static constexpr const char* REORG_UTXO_PENDING_KEY =
        "reorg:utxo:pending:v1";
    static constexpr size_t REORG_UTXO_PENDING_SIZE = 140;

    struct OfflineReindexResult {
        uint64_t height{0};
        uint64_t scanned_blocks{0};
        uint64_t reachable_blocks{0};
        std::string tip_hash;
        std::string backup_path;
    };

    // Explicit, stopped-node recovery for a damaged canonical index. Block
    // bodies and the UTXO store are verified and left intact. The replacement
    // index contains only the deterministic most-work canonical path; normal
    // startup must subsequently replay every block through full consensus and
    // rebuild derived state. The prior index directory is retained verbatim.
    static bool RebuildCanonicalIndexOffline(
            const std::string& base_dir,
            OfflineReindexResult& result,
            std::string* error = nullptr) {
#ifndef VELD_USE_LEVELDB
        (void)base_dir;
        (void)result;
        if (error) *error = "offline canonical reindex requires LevelDB";
        return false;
#else
        struct ReindexNode {
            std::string parent;
            uint32_t bits{0};
            uint64_t height{0};
            ChainWork work{};
            bool reachable{false};
        };

        fs::path candidate_path;
        fs::path backup_path;
        bool old_index_moved = false;
        auto fail = [&](const std::string& why) {
            if (error) *error = why;
            return false;
        };
        try {
            result = OfflineReindexResult{};
            const fs::path root = fs::path(base_dir);
            const fs::path blocks_path = root / "blocks";
            const fs::path utxo_path = root / "utxo";
            const fs::path index_path = root / "index";
            std::error_code ec;
            for (const auto& path : {blocks_path, utxo_path, index_path}) {
                if (!fs::is_directory(path, ec) || ec) {
                    return fail(
                        "offline reindex requires an existing blocks/utxo/index "
                        "LevelDB layout; missing or invalid path: " +
                        path.string());
                }
            }

            // Validate the stores we must trust before opening blocks. A live
            // node already owns the blocks LOCK, so LevelDBStore::Open below
            // also makes this operation stopped-node-only and prevents a node
            // from starting until the index swap is complete.
            std::string physical_error;
            for (const auto& path : {blocks_path, utxo_path}) {
                if (!ValidateLevelDBCurrentManifest(path, &physical_error) ||
                    !ValidateLevelDBLogsInDirectory(path, &physical_error)) {
                    return fail("offline reindex refused damaged retained store: " +
                                physical_error);
                }
            }

            LevelDBStore blocks(blocks_path.string(), false);
            std::unordered_map<std::string, ReindexNode> nodes;
            std::unordered_map<std::string, std::vector<std::string>> children;
            blocks.Iterate("b:", [&](const std::string& key,
                                      const std::string& value) {
                if (key.size() != 66 || key.compare(0, 2, "b:") != 0 ||
                    !IsCanonicalHash256Text(
                        std::string_view(key).substr(2))) {
                    throw std::runtime_error(
                        "blocks database contains a non-canonical block key");
                }
                if (value.size() > static_cast<size_t>(MAX_BLOCK_SIZE)) {
                    throw std::runtime_error(
                        "blocks database contains an oversized block body");
                }
                const std::vector<uint8_t> raw(value.begin(), value.end());
                Block block;
                const size_t consumed = Block::Deserialize(raw, 0, block);
                if (consumed == 0 || consumed != raw.size() ||
                    block.Serialize() != raw) {
                    throw std::runtime_error(
                        "blocks database contains non-canonical block bytes");
                }
                const std::string hash = key.substr(2);
                if (HashToHex(block.GetHash()) != hash) {
                    throw std::runtime_error(
                        "block key does not match its serialized header hash");
                }
                ReindexNode node;
                node.parent = HashToHex(block.header.prev_block_hash);
                node.bits = block.header.bits;
                if (!nodes.emplace(hash, std::move(node)).second) {
                    throw std::runtime_error(
                        "blocks database contains a duplicate block key");
                }
                children[HashToHex(block.header.prev_block_hash)].push_back(hash);
                ++result.scanned_blocks;
                return true;
            });

            const Block genesis = CreateGenesisBlock();
            const std::string genesis_hash = HashToHex(genesis.GetHash());
            const auto genesis_it = nodes.find(genesis_hash);
            if (genesis_it == nodes.end()) {
                return fail(
                    "compiled genesis block is absent from the retained block store");
            }
            auto genesis_raw = blocks.Get("b:" + genesis_hash);
            if (!genesis_raw ||
                std::vector<uint8_t>(genesis_raw->begin(), genesis_raw->end()) !=
                    genesis.Serialize()) {
                return fail(
                    "retained genesis bytes do not exactly match this binary");
            }

            ReindexNode& genesis_node = genesis_it->second;
            genesis_node.height = 0;
            genesis_node.work = BlockWork(genesis.header.bits);
            if (genesis_node.work == ChainWork(0)) {
                return fail("compiled genesis has zero work");
            }
            genesis_node.reachable = true;
            result.reachable_blocks = 1;

            std::vector<std::string> queue{genesis_hash};
            size_t cursor = 0;
            std::string best_hash = genesis_hash;
            while (cursor < queue.size()) {
                const std::string parent_hash = queue[cursor++];
                const ReindexNode& parent = nodes.at(parent_hash);
                auto child_it = children.find(parent_hash);
                if (child_it == children.end()) continue;
                for (const std::string& child_hash : child_it->second) {
                    ReindexNode& child = nodes.at(child_hash);
                    if (child.reachable) {
                        throw std::runtime_error(
                            "reachable block graph contains a cycle");
                    }
                    const ChainWork block_work = BlockWork(child.bits);
                    if (block_work == ChainWork(0)) {
                        throw std::runtime_error(
                            "reachable block has an invalid compact work target");
                    }
                    if (parent.height == std::numeric_limits<uint64_t>::max()) {
                        throw std::runtime_error(
                            "reachable block height overflows uint64");
                    }
                    child.height = parent.height + 1;
                    child.work = AddChainWork(parent.work, block_work);
                    child.reachable = true;
                    ++result.reachable_blocks;
                    queue.push_back(child_hash);

                    const ReindexNode& best = nodes.at(best_hash);
                    if (child.work > best.work ||
                        (child.work == best.work &&
                         (child.height > best.height ||
                          (child.height == best.height &&
                           child_hash < best_hash)))) {
                        best_hash = child_hash;
                    }
                }
            }

            const ReindexNode& best = nodes.at(best_hash);
            std::vector<std::string> canonical(best.height + 1);
            std::string walk = best_hash;
            for (;;) {
                const ReindexNode& node = nodes.at(walk);
                canonical.at(static_cast<size_t>(node.height)) = walk;
                if (node.height == 0) break;
                const auto parent = nodes.find(node.parent);
                if (parent == nodes.end() || !parent->second.reachable ||
                    parent->second.height + 1 != node.height) {
                    throw std::runtime_error(
                        "reachable canonical path has a missing parent");
                }
                walk = node.parent;
            }
            if (canonical.front() != genesis_hash) {
                throw std::runtime_error(
                    "reconstructed canonical path does not begin at genesis");
            }

            const std::string nonce = std::to_string(
                std::chrono::system_clock::now().time_since_epoch().count());
            candidate_path = root / ("index.reindex-candidate-" + nonce);
            backup_path = root / ("index.recovery-backup-" + nonce);
            if (fs::exists(candidate_path, ec) || fs::exists(backup_path, ec) || ec)
                return fail("offline reindex staging path already exists");

            {
                LevelDBStore candidate(candidate_path.string(), true);
                WriteBatch batch;
                batch.Put("db:schema_version",
                          std::to_string(CURRENT_SCHEMA_VERSION));
                size_t batched_blocks = 0;
                for (uint64_t height = 0; height < canonical.size(); ++height) {
                    const std::string& hash = canonical[static_cast<size_t>(height)];
                    const ReindexNode& node = nodes.at(hash);
                    batch.Put("idx:" + hash + ":height",
                              std::to_string(height));
                    batch.Put("idx:" + hash + ":bits",
                              std::to_string(node.bits));
                    batch.Put("idx:height:" + std::to_string(height), hash);
                    if (++batched_blocks == 4096) {
                        if (!candidate.Write(batch))
                            throw std::runtime_error(
                                "cannot write staged canonical index rows");
                        batch.Clear();
                        batched_blocks = 0;
                    }
                }
                if (!batch.IsEmpty() && !candidate.Write(batch)) {
                    throw std::runtime_error(
                        "cannot write final staged canonical index rows");
                }
                WriteBatch tip;
                tip.Put("chain:tip", best_hash);
                tip.Put("chain:height", std::to_string(best.height));
                // Supply is consensus-derived. Startup ReplayChain replaces
                // this seed with the exact recomputed value before serving.
                tip.Put("chain:supply", "0");
                if (!candidate.Write(tip)) {
                    throw std::runtime_error(
                        "cannot write staged canonical tip");
                }
            }

            physical_error.clear();
            if (!ValidateLevelDBCurrentManifest(candidate_path,
                                                &physical_error) ||
                !ValidateLevelDBLogsInDirectory(candidate_path,
                                                &physical_error)) {
                throw std::runtime_error(
                    "staged canonical index failed physical verification: " +
                    physical_error);
            }

            fs::rename(index_path, backup_path, ec);
            if (ec) {
                throw std::runtime_error(
                    "cannot preserve prior index before replacement: " +
                    ec.message());
            }
            old_index_moved = true;
            fs::rename(candidate_path, index_path, ec);
            if (ec) {
                const std::string promote_error = ec.message();
                std::error_code restore_ec;
                fs::rename(backup_path, index_path, restore_ec);
                old_index_moved = false;
                if (restore_ec) {
                    throw std::runtime_error(
                        "cannot promote staged index (" + promote_error +
                        ") and cannot restore prior index (" +
                        restore_ec.message() + ")");
                }
                throw std::runtime_error(
                    "cannot promote staged canonical index: " +
                    promote_error + "; prior index restored");
            }
            old_index_moved = false;

            result.height = best.height;
            result.tip_hash = best_hash;
            result.backup_path = backup_path.string();
            if (error) error->clear();
            return true;
        } catch (const std::exception& e) {
            std::error_code cleanup_ec;
            if (!candidate_path.empty())
                fs::remove_all(candidate_path, cleanup_ec);
            if (old_index_moved) {
                const fs::path index_path = fs::path(base_dir) / "index";
                if (!fs::exists(index_path, cleanup_ec)) {
                    cleanup_ec.clear();
                    fs::rename(backup_path, index_path, cleanup_ec);
                }
            }
            return fail(std::string("offline canonical reindex failed: ") +
                        e.what());
        }
#endif
    }

    struct DurablePublicationPending {
        uint64_t height{0};
        Hash256 hash{};
    };

    // VUR1 binds the complete reorg decision, not merely the two tips.  The
    // common ancestor prevents a caller from publishing a stitched suffix;
    // both supplies make the intended final accounting part of the durable
    // identity as well.  While this record exists, the old chain triplet and
    // height index remain authoritative even if utxo_db already contains the
    // candidate branch's state.
    struct ReorgUtxoPending {
        uint64_t ancestor_height{0};
        Hash256 ancestor_hash{};
        uint64_t old_height{0};
        Hash256 old_hash{};
        uint64_t old_supply{0};
        uint64_t new_height{0};
        Hash256 new_hash{};
        uint64_t new_supply{0};
    };

    static bool SameReorgUtxoPending(const ReorgUtxoPending& a,
                                     const ReorgUtxoPending& b) noexcept {
        return a.ancestor_height == b.ancestor_height &&
               a.ancestor_hash == b.ancestor_hash &&
               a.old_height == b.old_height && a.old_hash == b.old_hash &&
               a.old_supply == b.old_supply &&
               a.new_height == b.new_height && a.new_hash == b.new_hash &&
               a.new_supply == b.new_supply;
    }

    static std::vector<uint8_t> EncodeReorgUtxoPending(
            const ReorgUtxoPending& pending) {
        std::vector<uint8_t> out;
        out.reserve(REORG_UTXO_PENDING_SIZE);
        out.insert(out.end(), {'V', 'U', 'R', '1'});
        auto put_u64 = [&](uint64_t value) {
            for (unsigned i = 0; i < 8; ++i)
                out.push_back(static_cast<uint8_t>(value >> (8 * i)));
        };
        auto put_hash = [&](const Hash256& hash) {
            out.insert(out.end(), hash.begin(), hash.end());
        };
        put_u64(pending.ancestor_height);
        put_hash(pending.ancestor_hash);
        put_u64(pending.old_height);
        put_hash(pending.old_hash);
        put_u64(pending.old_supply);
        put_u64(pending.new_height);
        put_hash(pending.new_hash);
        put_u64(pending.new_supply);
        return out;
    }

    static std::optional<ReorgUtxoPending> DecodeReorgUtxoPending(
            const std::vector<uint8_t>& wire) {
        if (wire.size() != REORG_UTXO_PENDING_SIZE ||
            wire[0] != 'V' || wire[1] != 'U' ||
            wire[2] != 'R' || wire[3] != '1')
            return std::nullopt;
        size_t offset = 4;
        auto get_u64 = [&]() {
            uint64_t value = 0;
            for (unsigned i = 0; i < 8; ++i)
                value |= static_cast<uint64_t>(wire[offset + i]) << (8 * i);
            offset += 8;
            return value;
        };
        auto get_hash = [&]() {
            Hash256 hash{};
            std::copy(wire.begin() + offset, wire.begin() + offset + 32,
                      hash.begin());
            offset += 32;
            return hash;
        };
        ReorgUtxoPending out;
        out.ancestor_height = get_u64();
        out.ancestor_hash = get_hash();
        out.old_height = get_u64();
        out.old_hash = get_hash();
        out.old_supply = get_u64();
        out.new_height = get_u64();
        out.new_hash = get_hash();
        out.new_supply = get_u64();
        if (offset != wire.size() ||
            out.ancestor_height >= out.old_height ||
            out.ancestor_height >= out.new_height ||
            out.old_height - out.ancestor_height >= MAX_REORG_DEPTH ||
            out.new_height - out.ancestor_height >
                2 * MAX_REORG_DEPTH ||
            HashIsZero(out.ancestor_hash) || HashIsZero(out.old_hash) ||
            HashIsZero(out.new_hash) ||
            out.old_supply > MAX_SUPPLY_UNITS ||
            out.new_supply > MAX_SUPPLY_UNITS)
            return std::nullopt;
        return out;
    }

    static std::vector<uint8_t> EncodeDurablePublicationPending(
            uint64_t height, const Hash256& hash) {
        std::vector<uint8_t> out;
        out.reserve(DURABLE_PUBLICATION_PENDING_SIZE);
        out.insert(out.end(), {'V', 'D', 'P', '1'});
        for (unsigned i = 0; i < 8; ++i)
            out.push_back(static_cast<uint8_t>(height >> (8 * i)));
        out.insert(out.end(), hash.begin(), hash.end());
        return out;
    }

    static std::optional<DurablePublicationPending>
    DecodeDurablePublicationPending(const std::vector<uint8_t>& wire) {
        if (wire.size() != DURABLE_PUBLICATION_PENDING_SIZE ||
            wire[0] != 'V' || wire[1] != 'D' ||
            wire[2] != 'P' || wire[3] != '1')
            return std::nullopt;
        DurablePublicationPending out;
        for (unsigned i = 0; i < 8; ++i)
            out.height |= static_cast<uint64_t>(wire[4 + i]) << (8 * i);
        std::copy(wire.begin() + 12, wire.end(), out.hash.begin());
        return out;
    }

    explicit VeldDB(const std::string& base_dir) {
#ifdef VELD_USE_LEVELDB
        const fs::path blocks_path = fs::path(base_dir) / "blocks";
        const fs::path utxo_path   = fs::path(base_dir) / "utxo";
        const fs::path index_path  = fs::path(base_dir) / "index";
        std::error_code ec;
        const bool blocks_existed = fs::exists(blocks_path, ec);
        if (ec) throw std::runtime_error(
            "FATAL: cannot inspect blocks database path: " + ec.message());
        const bool utxo_existed = fs::exists(utxo_path, ec);
        if (ec) throw std::runtime_error(
            "FATAL: cannot inspect UTXO database path: " + ec.message());
        const bool index_existed = fs::exists(index_path, ec);
        if (ec) throw std::runtime_error(
            "FATAL: cannot inspect index database path: " + ec.message());

        const unsigned existing_count =
            static_cast<unsigned>(blocks_existed) +
            static_cast<unsigned>(utxo_existed) +
            static_cast<unsigned>(index_existed);
        if (existing_count != 0 && existing_count != 3) {
            throw std::runtime_error(
                "FATAL: incomplete LevelDB layout (blocks/utxo/index must all "
                "exist or all be absent). Refusing to synthesize missing "
                "canonical state; restore a coherent snapshot or run the "
                "explicit offline recovery operation.");
        }
        const bool fresh_layout = existing_count == 0;
        if (!fresh_layout) {
            for (const auto& path : {blocks_path, utxo_path, index_path}) {
                if (!fs::is_directory(path, ec) || ec) {
                    throw std::runtime_error(
                        "FATAL: LevelDB path is not a directory: " +
                        path.string());
                }
            }
            // The index is authoritative for canonical height/order.  Check
            // its physical journal and manifest without opening any database,
            // so corruption cannot be auto-recovered into a height-zero view.
            std::string preflight_error;
            if (!ValidateLevelDBCurrentManifest(
                    index_path, &preflight_error) ||
                !ValidateLevelDBLogsInDirectory(
                    index_path, &preflight_error)) {
                throw std::runtime_error(
                    "FATAL: canonical index preflight failed: " +
                    preflight_error +
                    ". Refusing normal startup; restore a coherent snapshot "
                    "or run the explicit offline recovery operation.");
            }
        }
#endif
        fs::create_directories(base_dir + "/blocks");
        fs::create_directories(base_dir + "/utxo");
        fs::create_directories(base_dir + "/index");
#ifndef _WIN32
        for (const char* sub : {"/blocks", "/utxo", "/index"}) {
            std::string p = base_dir + sub;
            ::chmod(p.c_str(), 0700);
        }
        std::error_code perms_ec;
        if (fs::exists(base_dir, perms_ec)) ::chmod(base_dir.c_str(), 0700);
#endif
#ifdef VELD_USE_LEVELDB
        blocks_db_ = std::make_unique<LevelDBStore>(
            base_dir + "/blocks", fresh_layout);
        utxo_db_   = std::make_unique<LevelDBStore>(
            base_dir + "/utxo", fresh_layout);
        index_db_  = std::make_unique<LevelDBStore>(
            base_dir + "/index", fresh_layout);
#else
        blocks_db_ = std::make_unique<FlatFileStore>(base_dir + "/blocks");
        utxo_db_   = std::make_unique<FlatFileStore>(base_dir + "/utxo");
        index_db_  = std::make_unique<FlatFileStore>(base_dir + "/index");
#endif
        RecoverFromJournal();
        CheckOrInitSchemaVersion_();
    }

    static constexpr uint32_t CURRENT_SCHEMA_VERSION = 1;

    void CheckOrInitSchemaVersion_() {
        if (!index_db_) return;
        auto raw = index_db_->Get("db:schema_version");
        if (!raw) {
            bool index_has_any_row = false;
            index_db_->Iterate("", [&](const std::string&, const std::string&) {
                index_has_any_row = true;
                return false;
            });
            bool blocks_have_chain = false;
            blocks_db_->Iterate("b:",
                [&](const std::string&, const std::string&) {
                    blocks_have_chain = true;
                    return false;
                });
            if (index_has_any_row || blocks_have_chain) {
                throw std::runtime_error(
                    "FATAL: canonical index schema marker is missing while "
                    "durable state exists. Refusing to initialize a fresh "
                    "height-zero index over retained chain data; restore a "
                    "coherent snapshot or run explicit offline recovery.");
            }
            if (!index_db_->Put(
                    "db:schema_version",
                    std::to_string(CURRENT_SCHEMA_VERSION))) {
                throw std::runtime_error(
                    "FATAL: cannot initialize canonical index schema marker");
            }
            return;
        }
        uint32_t on_disk = 0;
        uint64_t parsed_schema = 0;
        if (!ParseCanonicalUint64Text(*raw, parsed_schema) ||
            parsed_schema > UINT32_MAX) {
            throw std::runtime_error(
                "FATAL: index_db db:schema_version is not parseable as a "
                "uint32 ('" + *raw + "'). Datadir is corrupted or pre-"
                "release. Restore from backup or wipe + IBD.");
        }
        on_disk = static_cast<uint32_t>(parsed_schema);
        if (on_disk > CURRENT_SCHEMA_VERSION) {
            throw std::runtime_error(
                "FATAL: datadir was written by a NEWER binary "
                "(schema_version=" + std::to_string(on_disk) +
                ", this binary supports up to " +
                std::to_string(CURRENT_SCHEMA_VERSION) + "). Refusing to "
                "read forward-incompatible data — would silently "
                "misinterpret unrecognised rows. Upgrade veld-node to "
                "the same or newer build, or restore an older backup.");
        }
        if (on_disk < CURRENT_SCHEMA_VERSION) {
            throw std::runtime_error(
                "FATAL: datadir was written by an OLDER binary "
                "(schema_version=" + std::to_string(on_disk) +
                "). No migration path defined. Either downgrade veld-"
                "node to a matching version or wipe + IBD.");
        }
    }

    void Close() {
        blocks_db_.reset();
        utxo_db_.reset();
        index_db_.reset();
    }

    bool WriteBlock(const Hash256& hash, const std::vector<uint8_t>& data) {
        std::string key = "b:" + HashToHex(hash);
        std::string val(data.begin(), data.end());
        return blocks_db_->Put(key, val);
    }

    std::optional<std::vector<uint8_t>> ReadBlock(const Hash256& hash) {
        auto val = blocks_db_->Get("b:" + HashToHex(hash));
        if (!val) return std::nullopt;
        return std::vector<uint8_t>(val->begin(), val->end());
    }

    bool HasBlock(const Hash256& hash) {
        return blocks_db_->Has("b:" + HashToHex(hash));
    }

    bool DeleteBlock(const Hash256& hash) {
        return blocks_db_->Delete("b:" + HashToHex(hash));
    }

    // Delete a body only when the current canonical height index does not
    // point at it.  Reorg pruning calls this while displaced old-canonical
    // bodies may still carry reverse-index rows; checking the authoritative
    // per-height mapping prevents a crash window from deleting recovery data.
    bool DeleteNonCanonicalBlock(const Hash256& hash) {
        const std::string hex = HashToHex(hash);
        auto height_text = index_db_->Get("idx:" + hex + ":height");
        if (height_text) {
            uint64_t height = 0;
            if (ParseCanonicalUint64Text(*height_text, height)) {
                auto canonical = index_db_->Get(
                    "idx:height:" + std::to_string(height));
                if (canonical && *canonical == hex) return false;
            }
        }
        WriteBatch reverse;
        reverse.Delete("idx:" + hex + ":height");
        reverse.Delete("idx:" + hex + ":bits");
        if (!index_db_->Write(reverse)) return false;
        return blocks_db_->Delete("b:" + hex);
    }

    struct NonCanonicalBodyPruneStats {
        uint64_t canonical{0};
        uint64_t deleted{0};
    };

    // Startup-only sweep after complete consensus replay.  Side bodies are a
    // bounded runtime cache and are not reconstructed after restart; without
    // this sweep, each restart could strand another full cache budget on disk.
    // The just-validated idx:height namespace is the sole keep set.
    bool PruneNonCanonicalBlockBodies(
            NonCanonicalBodyPruneStats* stats = nullptr) {
        NonCanonicalBodyPruneStats local;
        std::unordered_set<std::string> canonical_hashes;
        index_db_->Iterate("idx:height:",
            [&](const std::string& key, const std::string& value) {
                static constexpr std::string_view prefix = "idx:height:";
                if (key.compare(0, prefix.size(), prefix) == 0 &&
                    IsCanonicalHash256Text(value))
                    canonical_hashes.insert(value);
                return true;
            });
        local.canonical = canonical_hashes.size();

        std::vector<std::string> stale;
        blocks_db_->Iterate("b:",
            [&](const std::string& key, const std::string&) {
                if (key.size() == 66 && key.compare(0, 2, "b:") == 0) {
                    const std::string hex = key.substr(2);
                    if (IsCanonicalHash256Text(hex) &&
                        !canonical_hashes.count(hex))
                        stale.push_back(hex);
                }
                return true;
            });
        std::sort(stale.begin(), stale.end());
        for (const auto& hex : stale) {
            WriteBatch reverse;
            reverse.Delete("idx:" + hex + ":height");
            reverse.Delete("idx:" + hex + ":bits");
            if (!index_db_->Write(reverse) ||
                !blocks_db_->Delete("b:" + hex)) {
                if (stats) *stats = local;
                return false;
            }
            ++local.deleted;
        }
        if (stats) *stats = local;
        return true;
    }

    bool WriteUTXO(const Hash256& tx_hash, uint32_t index, const std::string& utxo_data) {
        std::string key = "u:" + HashToHex(tx_hash) + ":" + std::to_string(index);
        return utxo_db_->Put(key, utxo_data);
    }

    // Reconcile every u:* row to an authoritative in-memory snapshot using a
    // single UTXO-store batch.  The cross-database recovery marker is written
    // first and cleared only after that batch succeeds, so a process death at
    // any point leaves startup an explicit instruction to replay the canonical
    // block index and repeat this operation.  Diffing against existing rows
    // keeps normal work proportional to changed UTXOs rather than lifetime set
    // size; atomicity within utxo_db does not substitute for the retained index
    // marker that protects the cross-database boundary.
    // Stats from a single rebuild — observable so the operator log can
    // show "actually wrote N ops" instead of "snapshot was N entries".
    // Without this distinction the [reorg-leveldb] line is misleading
    // post- optimization (it printed snapshot size which is
    // unchanged but actual writes dropped from ~30k to ~10-100).
    struct UTXORebuildStats {
        size_t deletes_emitted = 0;
        size_t puts_emitted    = 0;
        size_t puts_skipped    = 0;
        size_t snapshot_size   = 0;
    };

    bool RebuildUTXOsFromSnapshot(const std::vector<std::pair<std::string, std::string>>& kvs,
                                  UTXORebuildStats* stats_out = nullptr) {
        // If startup inherited this marker, retain its recovery meaning until
        // the complete UTXO batch succeeds.  The final marker deletion also
        // retires any superseded single-block journal.  A live reconciliation
        // creates its own marker but leaves pending:commit for the caller's
        // later canonical publication batch.
        const auto inherited_marker =
            index_db_->Get("reorg:utxo:rebuilding");
        if (inherited_marker && *inherited_marker != "1" &&
            *inherited_marker != "delta-v1")
            throw std::runtime_error(
                "unknown reorg:utxo:rebuilding marker version");
        std::unordered_map<std::string, std::string> existing_kv;
        existing_kv.reserve(kvs.size() + 16);
        utxo_db_->Iterate("u:", [&](const std::string& k, const std::string& v) {
            existing_kv.emplace(k, v);
            return true;
        });
        std::unordered_set<std::string> new_keys;
        new_keys.reserve(kvs.size());
        for (const auto& [k, _v] : kvs) new_keys.insert(k);

        {
            WriteBatch intent;
            intent.Put("reorg:utxo:rebuilding", "1");
            if (!index_db_->Write(intent)) return false;
        }
        WriteBatch combined;
        size_t deletes = 0, puts = 0, skipped = 0;
        for (const auto& [k, _v] : existing_kv) {
            if (new_keys.find(k) == new_keys.end()) {
                combined.Delete(k);
                ++deletes;
            }
        }
        for (const auto& [k, v] : kvs) {
            auto it = existing_kv.find(k);
            if (it != existing_kv.end() && it->second == v) {
                ++skipped;
                continue;
            }
            combined.Put(k, v);
            ++puts;
        }
        if (stats_out) {
            stats_out->deletes_emitted = deletes;
            stats_out->puts_emitted    = puts;
            stats_out->puts_skipped    = skipped;
            stats_out->snapshot_size   = kvs.size();
        }
        if (!utxo_db_->Write(combined)) {
            return false;
        }
        {
            WriteBatch clear;
            clear.Delete("reorg:utxo:rebuilding");
            if (inherited_marker) clear.Delete(PENDING_COMMIT_KEY);
            // A retained VUR1 (on its separate key) deliberately survives
            // this generic reconciliation.  Do not claim success if even the
            // transient marker could not be durably cleared: the VUR startup
            // path must acknowledge reconciliation only after every write is
            // known complete.
            if (!index_db_->Write(clear)) return false;
        }
        return true;
    }

    // Crash-detectable bounded UTXO mutation used by canonical disconnects and
    // reorgs.  Callers provide only keys touched by the suffix (already reduced
    // to their final canonical value), so work is O(changed block bytes) rather
    // than O(lifetime UTXO cardinality).  The same recovery marker as the legacy
    // full reconciliation makes an interrupted batch fail closed into startup's
    // authoritative chain replay.
    bool ApplyUTXODelta(
        const std::vector<std::pair<
            std::string, std::optional<std::string>>>& delta) {
        std::unordered_set<std::string> seen;
        seen.reserve(delta.size());
        for (const auto& [key, _value] : delta) {
            if (key.rfind("u:", 0) != 0 || !seen.insert(key).second)
                return false;
        }
        {
            WriteBatch intent;
            intent.Put("reorg:utxo:rebuilding", "delta-v1");
            if (!index_db_->Write(intent)) return false;
        }
        WriteBatch batch;
        for (const auto& [key, value] : delta) {
            if (value) batch.Put(key, *value);
            else batch.Delete(key);
        }
        if (!utxo_db_->Write(batch)) return false;
        WriteBatch clear;
        clear.Delete("reorg:utxo:rebuilding");
        return index_db_->Write(clear);
    }

    bool DeleteUTXO(const Hash256& tx_hash, uint32_t index) {
        std::string key = "u:" + HashToHex(tx_hash) + ":" + std::to_string(index);
        return utxo_db_->Delete(key);
    }

    std::optional<std::string> ReadUTXO(const Hash256& tx_hash, uint32_t index) {
        std::string key = "u:" + HashToHex(tx_hash) + ":" + std::to_string(index);
        return utxo_db_->Get(key);
    }

    bool WriteChainTip(const Hash256& tip, uint64_t height, uint64_t supply) {
        WriteBatch batch;
        batch.Put("chain:tip",    HashToHex(tip));
        batch.Put("chain:height", std::to_string(height));
        batch.Put("chain:supply", std::to_string(supply));
        return index_db_->Write(batch);
    }

    struct ChainTip {
        std::string tip_hash;
        uint64_t    height;
        uint64_t    supply_units;
    };

    // Strict view of the authoritative triplet written in one index batch.
    // Unlike ReadChainTip(), this never synthesizes a recovered tip from
    // reverse indexes; security journals use it to prove exact batch identity.
    std::optional<ChainTip> ReadChainTipExact() {
        auto tip    = index_db_->Get("chain:tip");
        auto height = index_db_->Get("chain:height");
        auto supply = index_db_->Get("chain:supply");
        uint64_t parsed_height = 0;
        uint64_t parsed_supply = 0;
        if (!tip || !height || !supply ||
            !IsCanonicalHash256Text(*tip) ||
            !ParseCanonicalUint64Text(*height, parsed_height) ||
            !ParseCanonicalUint64Text(*supply, parsed_supply) ||
            parsed_supply > MAX_SUPPLY_UNITS)
            return std::nullopt;
        return ChainTip{*tip, parsed_height, parsed_supply};
    }

    std::optional<ChainTip> ReadChainTip() {
        if (auto exact = ReadChainTipExact()) {
            if (exact->height == 0) {
                uint64_t recovered = FindHighestIndexedHeight();
                if (recovered > 0) {
                    auto hash_at = index_db_->Get(
                        "idx:height:" + std::to_string(recovered));
                    if (hash_at && IsCanonicalHash256Text(*hash_at)) {
                        std::cerr << "  [tip-recover] Stored tip was genesis but index has "
                                     "blocks up to height " << recovered
                                  << ". Recovering from block index.\n";
                        std::cerr.flush();
                        return ChainTip{*hash_at, recovered, 0};
                    }
                }
            }
            return exact;
        }
        uint64_t recovered = FindHighestIndexedHeight();
        if (recovered > 0) {
            auto hash_at = index_db_->Get("idx:height:" + std::to_string(recovered));
            if (hash_at && IsCanonicalHash256Text(*hash_at)) {
                std::cerr << "  [tip-recover] chain:tip keys missing. Recovered tip at "
                             "height " << recovered << " from block index.\n";
                std::cerr.flush();
                return ChainTip{*hash_at, recovered, 0};
            }
        }
        return std::nullopt;
    }

    std::optional<std::vector<uint8_t>> ReadAnchorSecurityFloor() {
        auto value = index_db_->Get(ANCHOR_SECURITY_FLOOR_KEY);
        if (!value) return std::nullopt;
        return std::vector<uint8_t>(value->begin(), value->end());
    }

    bool WriteAnchorSecurityFloor(const std::vector<uint8_t>& wire) {
        if (wire.empty() ||
            wire.size() > MAX_ANCHOR_SECURITY_FLOOR_BYTES)
            return false;
        WriteBatch batch;
        batch.Put(ANCHOR_SECURITY_FLOOR_KEY,
                  std::string(wire.begin(), wire.end()));
        return index_db_->Write(batch);
    }

    std::optional<std::vector<uint8_t>>
    ReadDurablePublicationPendingWire() {
        auto value = index_db_->Get(DURABLE_PUBLICATION_PENDING_KEY);
        if (!value) return std::nullopt;
        std::vector<uint8_t> wire(value->begin(), value->end());
        if (!DecodeDurablePublicationPending(wire))
            throw std::runtime_error(
                "durable publication pending identity is malformed");
        return wire;
    }

    std::optional<DurablePublicationPending>
    ReadDurablePublicationPending() {
        const auto wire = ReadDurablePublicationPendingWire();
        if (!wire) return std::nullopt;
        return DecodeDurablePublicationPending(*wire);
    }

    std::optional<std::vector<uint8_t>> ReadReorgUtxoPendingWire() {
        auto value = index_db_->Get(REORG_UTXO_PENDING_KEY);
        if (!value) return std::nullopt;
        std::vector<uint8_t> wire(value->begin(), value->end());
        if (!DecodeReorgUtxoPending(wire))
            throw std::runtime_error(
                "FATAL: retained VUR1 reorg identity is malformed; "
                "refusing ambiguous UTXO recovery");
        return wire;
    }

    std::optional<ReorgUtxoPending> ReadReorgUtxoPending() {
        const auto wire = ReadReorgUtxoPendingWire();
        if (!wire) return std::nullopt;
        return DecodeReorgUtxoPending(*wire);
    }

    bool UtxoRecoveryRequired() {
        if (ReadReorgUtxoPending()) return true;
        const auto transient = index_db_->Get("reorg:utxo:rebuilding");
        if (!transient) return false;
        if (*transient != "1" && *transient != "delta-v1")
            throw std::runtime_error(
                "unknown reorg:utxo:rebuilding marker version");
        return true;
    }

    bool ClearDurablePublicationPending(
            uint64_t expected_height, const Hash256& expected_hash) {
        const auto current = ReadDurablePublicationPending();
        if (!current || current->height != expected_height ||
            current->hash != expected_hash)
            return false;
        const auto tip = ReadChainTipExact();
        const std::string expected_hex = HashToHex(expected_hash);
        if (!tip || tip->height != expected_height ||
            tip->tip_hash != expected_hex)
            return false;
        const auto indexed = GetHashAtHeight(expected_height);
        if (!indexed || *indexed != expected_hex || !HasBlock(expected_hash))
            return false;
        WriteBatch batch;
        batch.Delete(DURABLE_PUBLICATION_PENDING_KEY);
        return index_db_->Write(batch);
    }

    uint64_t FindHighestIndexedHeight() {
        uint64_t max_h = 0;
        index_db_->Iterate("idx:height:", [&](const std::string& key, const std::string&) {
            static constexpr std::string_view prefix = "idx:height:";
            if (key.size() <= prefix.size() ||
                key.compare(0, prefix.size(), prefix) != 0) return true;
            uint64_t h = 0;
            if (ParseCanonicalUint64Text(
                    std::string_view(key).substr(prefix.size()), h) &&
                h > max_h) max_h = h;
            return true;
        });
        return max_h;
    }

    bool WriteBlockIndex(const std::string& hash_hex, uint64_t height, uint32_t bits) {
        WriteBatch batch;
        batch.Put("idx:" + hash_hex + ":height", std::to_string(height));
        batch.Put("idx:" + hash_hex + ":bits",   std::to_string(bits));
        batch.Put("idx:height:" + std::to_string(height), hash_hex);
        return index_db_->Write(batch);
    }

    std::optional<std::string> GetHashAtHeight(uint64_t height) {
        return index_db_->Get("idx:height:" + std::to_string(height));
    }

    std::string FindBlockHashByHeight(uint64_t target_height) {
        std::string target_str = std::to_string(target_height);
        std::string found;
        index_db_->Iterate("idx:", [&](const std::string& key,
                                       const std::string& val) {
            if (key.compare(0, 11, "idx:height:") == 0) return true;
            if (key.size() != 4 + 64 + 7) return true;
            if (key.compare(key.size() - 7, 7, ":height") != 0) return true;
            if (val != target_str) return true;
            found = key.substr(4, 64);
            return false;
        });
        return found;
    }

    bool RepairHeightHashMapping(uint64_t height,
                                 const std::string& hash_hex) {
        WriteBatch b;
        b.Put("idx:height:" + std::to_string(height), hash_hex);
        return index_db_->Write(b);
    }

    static constexpr const char* PENDING_COMMIT_KEY = "pending:commit";

    using UTXODelta = std::vector<std::pair<
        std::string, std::optional<std::string>>>;
    using ReorgCanonicalSuffix =
        std::vector<std::tuple<uint64_t, Hash256, uint32_t>>;

    static void WriteOrThrowUncertain(KVStore& store,
                                      const WriteBatch& batch,
                                      const std::string& context) {
        try {
            if (!store.Write(batch))
                throw DurableWriteUncertain(
                    context + " reported failure");
        } catch (const DurableWriteUncertain&) {
            throw;
        } catch (const std::exception& e) {
            throw DurableWriteUncertain(
                context + " threw: " + e.what());
        } catch (...) {
            throw DurableWriteUncertain(context + " threw");
        }
    }

    static bool ValidateUTXODelta(const UTXODelta& delta) {
        std::unordered_set<std::string> seen;
        seen.reserve(delta.size());
        for (const auto& [key, _value] : delta) {
            if (key.rfind("u:", 0) != 0 || !seen.insert(key).second)
                return false;
        }
        return true;
    }

    bool ReorgOldCanonicalMatches(const ReorgUtxoPending& pending) {
        const auto valid = DecodeReorgUtxoPending(
            EncodeReorgUtxoPending(pending));
        if (!valid || !SameReorgUtxoPending(*valid, pending)) return false;
        const auto tip = ReadChainTipExact();
        const std::string old_hex = HashToHex(pending.old_hash);
        const std::string ancestor_hex = HashToHex(pending.ancestor_hash);
        if (!tip || tip->height != pending.old_height ||
            tip->tip_hash != old_hex ||
            tip->supply_units != pending.old_supply)
            return false;
        const auto old_index = GetHashAtHeight(pending.old_height);
        const auto ancestor_index = GetHashAtHeight(pending.ancestor_height);
        auto reverse_row_matches = [&](const std::string& hex,
                                       uint64_t height) {
            const auto reverse_height =
                index_db_->Get("idx:" + hex + ":height");
            const auto reverse_bits =
                index_db_->Get("idx:" + hex + ":bits");
            uint64_t parsed_bits = 0;
            return reverse_height &&
                   *reverse_height == std::to_string(height) &&
                   reverse_bits &&
                   ParseCanonicalUint64Text(*reverse_bits, parsed_bits) &&
                   parsed_bits <= UINT32_MAX;
        };
        return old_index && *old_index == old_hex &&
               ancestor_index && *ancestor_index == ancestor_hex &&
               reverse_row_matches(old_hex, pending.old_height) &&
               reverse_row_matches(ancestor_hex,
                                   pending.ancestor_height) &&
               HasBlock(pending.old_hash) && HasBlock(pending.ancestor_hash);
    }

    // Establish the retained VUR1 identity before changing utxo_db.  The old
    // canonical tip/index/VLF remain untouched.  A healthy live reorg refuses
    // every pre-existing recovery obligation, including pending:commit: the
    // node must restart and complete that exact repair before starting another
    // cross-database transaction.  Startup's VUR1 recovery still tolerates a
    // coexisting legacy journal defensively and clears both only after an
    // authoritative replay/reconciliation succeeds.
    bool BeginReorgUTXO(const UTXODelta& delta,
                        const ReorgUtxoPending& pending) {
        if (!ValidateUTXODelta(delta) ||
            !ReorgOldCanonicalMatches(pending) ||
            pending.old_hash == pending.new_hash)
            return false;
        if (ReadReorgUtxoPending() ||
            index_db_->Has("reorg:utxo:rebuilding") ||
            index_db_->Has(PENDING_COMMIT_KEY) ||
            ReadDurablePublicationPending())
            return false;

        const auto wire = EncodeReorgUtxoPending(pending);
        WriteBatch intent;
        intent.Put(REORG_UTXO_PENDING_KEY,
                   std::string(wire.begin(), wire.end()));
        try {
            if (!index_db_->Write(intent))
                throw DurableWriteUncertain(
                    "VUR1 intent write reported failure");
        } catch (const DurableWriteUncertain&) {
            throw;
        } catch (const std::exception& e) {
            throw DurableWriteUncertain(
                std::string("VUR1 intent write threw: ") + e.what());
        } catch (...) {
            throw DurableWriteUncertain("VUR1 intent write threw");
        }

        WriteBatch utxo_batch;
        for (const auto& [key, value] : delta) {
            if (value) utxo_batch.Put(key, *value);
            else utxo_batch.Delete(key);
        }
        try {
            if (!utxo_db_->Write(utxo_batch))
                throw DurableWriteUncertain(
                    "VUR1 candidate UTXO write reported failure");
        } catch (const DurableWriteUncertain&) {
            throw;
        } catch (const std::exception& e) {
            throw DurableWriteUncertain(
                std::string("VUR1 candidate UTXO write threw: ") + e.what());
        } catch (...) {
            throw DurableWriteUncertain(
                "VUR1 candidate UTXO write threw");
        }
        return true;
    }

    // Reverse a rejected pre-publication reorg.  The VUR1 remains present
    // while utxo_db is restored, making an interruption self-healing.  Do not
    // delete pending:commit here: it may predate the reorg transaction.
    bool AbortReorgUTXO(const UTXODelta& reverse_delta,
                        const ReorgUtxoPending& expected) {
        if (!ValidateUTXODelta(reverse_delta)) return false;
        const auto current = ReadReorgUtxoPending();
        if (!current) {
            // Begin's intent write may have reported an uncertain failure
            // without reaching the WAL.  Blockchain still runs its abort
            // callback; an exact old frame plus no VUR means no candidate UTXO
            // write was attempted, so compensation is an idempotent no-op.
            return ReorgOldCanonicalMatches(expected) &&
                   !ReadDurablePublicationPending();
        }
        if (!SameReorgUtxoPending(*current, expected) ||
            !ReorgOldCanonicalMatches(expected) ||
            ReadDurablePublicationPending())
            return false;

        WriteBatch utxo_batch;
        for (const auto& [key, value] : reverse_delta) {
            if (value) utxo_batch.Put(key, *value);
            else utxo_batch.Delete(key);
        }
        try {
            if (!utxo_db_->Write(utxo_batch))
                throw DurableWriteUncertain(
                    "VUR1 abort UTXO write reported failure");
        } catch (const DurableWriteUncertain&) {
            throw;
        } catch (const std::exception& e) {
            throw DurableWriteUncertain(
                std::string("VUR1 abort UTXO write threw: ") + e.what());
        } catch (...) {
            throw DurableWriteUncertain("VUR1 abort UTXO write threw");
        }

        WriteBatch clear;
        clear.Delete(REORG_UTXO_PENDING_KEY);
        try {
            if (!index_db_->Write(clear))
                throw DurableWriteUncertain(
                    "VUR1 abort acknowledgement reported failure");
        } catch (const DurableWriteUncertain&) {
            throw;
        } catch (const std::exception& e) {
            throw DurableWriteUncertain(
                std::string("VUR1 abort acknowledgement threw: ") + e.what());
        } catch (...) {
            throw DurableWriteUncertain(
                "VUR1 abort acknowledgement threw");
        }
        return true;
    }

    // Called only after startup replay and full UTXO reconciliation to the old
    // authoritative tip.  Clearing VUR1 and the superseded linear journal in
    // one index batch prevents a crash from resurrecting a pending commit
    // whose UTXO effects the reconciliation has already removed.  This is
    // valid at genesis as well as at non-zero heights.
    bool CompleteReorgUtxoRecoveryAfterReplay(
            const ReorgUtxoPending& expected) {
        const auto current = ReadReorgUtxoPending();
        if (!current || !SameReorgUtxoPending(*current, expected) ||
            !ReorgOldCanonicalMatches(expected) ||
            index_db_->Has("reorg:utxo:rebuilding") ||
            ReadDurablePublicationPending())
            return false;
        WriteBatch clear;
        clear.Delete(REORG_UTXO_PENDING_KEY);
        clear.Delete(PENDING_COMMIT_KEY);
        try {
            if (!index_db_->Write(clear))
                throw DurableWriteUncertain(
                    "VUR1 startup acknowledgement reported failure");
        } catch (const DurableWriteUncertain&) {
            throw;
        } catch (const std::exception& e) {
            throw DurableWriteUncertain(
                std::string("VUR1 startup acknowledgement threw: ") +
                e.what());
        } catch (...) {
            throw DurableWriteUncertain(
                "VUR1 startup acknowledgement threw");
        }
        return true;
    }

    // Publish a validated replacement suffix in one authoritative index
    // batch.  No intermediate height/tip/VLF is ever visible.  Each retained
    // block body is checked against its tuple and previous link, then stale
    // height rows above the shorter new tip and displaced reverse rows are
    // removed in the same commit.  VDP1 is armed atomically at the commit
    // point; the node clears it only after all required public/module mirrors
    // have completed.
    bool CommitReorgMetadata(
            const ReorgCanonicalSuffix& new_suffix,
            const ReorgUtxoPending& expected,
            const std::vector<uint8_t>* anchor_security_floor = nullptr) {
        if (anchor_security_floor &&
            (anchor_security_floor->empty() ||
             anchor_security_floor->size() >
                 MAX_ANCHOR_SECURITY_FLOOR_BYTES))
            return false;
        const auto current = ReadReorgUtxoPending();
        if (!current || !SameReorgUtxoPending(*current, expected) ||
            !ReorgOldCanonicalMatches(expected) ||
            index_db_->Has("reorg:utxo:rebuilding") ||
            ReadDurablePublicationPending())
            return false;
        if (new_suffix.empty() ||
            expected.new_height - expected.ancestor_height !=
                new_suffix.size())
            return false;

        std::unordered_set<std::string> new_hashes;
        new_hashes.reserve(new_suffix.size());
        Hash256 prior_hash = expected.ancestor_hash;
        uint64_t wanted_height = expected.ancestor_height + 1;
        for (const auto& [height, hash, bits] : new_suffix) {
            if (height != wanted_height || HashIsZero(hash) || bits == 0 ||
                !new_hashes.insert(HashToHex(hash)).second)
                return false;
            const auto body = ReadBlock(hash);
            if (!body || body->size() < 88 ||
                Hash256d(body->data(), 88) != hash)
                return false;
            Hash256 body_prev{};
            std::copy(body->begin() + 4, body->begin() + 36,
                      body_prev.begin());
            const uint32_t body_bits =
                static_cast<uint32_t>((*body)[76]) |
                (static_cast<uint32_t>((*body)[77]) << 8) |
                (static_cast<uint32_t>((*body)[78]) << 16) |
                (static_cast<uint32_t>((*body)[79]) << 24);
            if (body_prev != prior_hash || body_bits != bits) return false;
            prior_hash = hash;
            if (wanted_height == UINT64_MAX &&
                height != expected.new_height)
                return false;
            ++wanted_height;
        }
        if (std::get<0>(new_suffix.back()) != expected.new_height ||
            std::get<1>(new_suffix.back()) != expected.new_hash)
            return false;

        // Validate the complete displaced canonical suffix before building the
        // batch.  This also supplies the exact reverse-index rows to remove.
        std::vector<std::pair<uint64_t, std::string>> old_suffix;
        old_suffix.reserve(static_cast<size_t>(
            expected.old_height - expected.ancestor_height));
        Hash256 prior_old_hash = expected.ancestor_hash;
        for (uint64_t height = expected.ancestor_height + 1;; ++height) {
            const auto old_hash = GetHashAtHeight(height);
            if (!old_hash || !IsCanonicalHash256Text(*old_hash)) return false;
            const Hash256 old_hash_bytes = HexToHash(*old_hash);
            const auto reverse_height =
                index_db_->Get("idx:" + *old_hash + ":height");
            const auto reverse_bits =
                index_db_->Get("idx:" + *old_hash + ":bits");
            uint64_t parsed_bits = 0;
            const auto body = ReadBlock(old_hash_bytes);
            if (!reverse_height ||
                *reverse_height != std::to_string(height) ||
                !reverse_bits ||
                !ParseCanonicalUint64Text(*reverse_bits, parsed_bits) ||
                parsed_bits > UINT32_MAX || !body || body->size() < 88 ||
                Hash256d(body->data(), 88) != old_hash_bytes)
                return false;
            Hash256 body_prev{};
            std::copy(body->begin() + 4, body->begin() + 36,
                      body_prev.begin());
            const uint32_t body_bits =
                static_cast<uint32_t>((*body)[76]) |
                (static_cast<uint32_t>((*body)[77]) << 8) |
                (static_cast<uint32_t>((*body)[78]) << 16) |
                (static_cast<uint32_t>((*body)[79]) << 24);
            if (body_prev != prior_old_hash ||
                body_bits != static_cast<uint32_t>(parsed_bits))
                return false;
            old_suffix.emplace_back(height, *old_hash);
            prior_old_hash = old_hash_bytes;
            if (height == expected.old_height) break;
            if (height == UINT64_MAX) return false;
        }

        WriteBatch batch;
        bool height_namespace_valid = true;
        index_db_->Iterate("idx:height:",
            [&](const std::string& key, const std::string& value) {
                static constexpr std::string_view prefix = "idx:height:";
                uint64_t height = 0;
                if (key.size() <= prefix.size() ||
                    key.compare(0, prefix.size(), prefix) != 0 ||
                    !ParseCanonicalUint64Text(
                        std::string_view(key).substr(prefix.size()), height) ||
                    !IsCanonicalHash256Text(value)) {
                    height_namespace_valid = false;
                    return false;
                }
                if (height > expected.new_height) {
                    batch.Delete(key);
                    batch.Delete("idx:" + value + ":height");
                    batch.Delete("idx:" + value + ":bits");
                }
                return true;
            });
        if (!height_namespace_valid) return false;

        for (const auto& [height, old_hex] : old_suffix) {
            const uint64_t offset = height -
                                    (expected.ancestor_height + 1);
            const bool retained_same = offset < new_suffix.size() &&
                HashToHex(std::get<1>(new_suffix[offset])) == old_hex;
            if (!retained_same) {
                batch.Delete("idx:" + old_hex + ":height");
                batch.Delete("idx:" + old_hex + ":bits");
            }
        }
        for (const auto& [height, hash, bits] : new_suffix) {
            const std::string hex = HashToHex(hash);
            batch.Put("idx:" + hex + ":height", std::to_string(height));
            batch.Put("idx:" + hex + ":bits", std::to_string(bits));
            batch.Put("idx:height:" + std::to_string(height), hex);
        }
        const std::string new_hex = HashToHex(expected.new_hash);
        batch.Put("chain:tip", new_hex);
        batch.Put("chain:height", std::to_string(expected.new_height));
        batch.Put("chain:supply", std::to_string(expected.new_supply));
        batch.Put("tip:hash", new_hex);
        batch.Put("tip:height", std::to_string(expected.new_height));
        batch.Put("tip:supply", std::to_string(expected.new_supply));
        if (anchor_security_floor) {
            batch.Put(ANCHOR_SECURITY_FLOOR_KEY,
                      std::string(anchor_security_floor->begin(),
                                  anchor_security_floor->end()));
        }
        const auto publication = EncodeDurablePublicationPending(
            expected.new_height, expected.new_hash);
        batch.Put(DURABLE_PUBLICATION_PENDING_KEY,
                  std::string(publication.begin(), publication.end()));
        batch.Delete(REORG_UTXO_PENDING_KEY);
        batch.Delete(PENDING_COMMIT_KEY);

        // Once this write is attempted, false/throw is durability-uncertain:
        // the WAL may be recoverable even if the current process cannot observe
        // it.  Never return false and invite a pre-publication rollback.
        try {
            if (!index_db_->Write(batch))
                throw DurableWriteUncertain(
                    "VUR1 final canonical batch reported failure");
        } catch (const DurableWriteUncertain&) {
            throw;
        } catch (const std::exception& e) {
            throw DurableWriteUncertain(
                std::string("VUR1 final canonical batch threw: ") + e.what());
        } catch (...) {
            throw DurableWriteUncertain(
                "VUR1 final canonical batch threw");
        }
        return true;
    }

    static std::string SerializePendingCommit(
        const Hash256& block_hash,
        uint64_t height,
        uint64_t supply_units,
        uint32_t bits,
        const std::vector<std::string>& new_utxo_keys,
        const std::vector<std::pair<std::string, std::string>>& spent_utxo_kvs)
    {
        std::string out;
        auto put_u32 = [&](uint32_t v) {
            char b[4];
            b[0] = (char)( v        & 0xFF);
            b[1] = (char)((v >>  8) & 0xFF);
            b[2] = (char)((v >> 16) & 0xFF);
            b[3] = (char)((v >> 24) & 0xFF);
            out.append(b, 4);
        };
        auto put_u64 = [&](uint64_t v) {
            char b[8];
            for (int i = 0; i < 8; ++i) b[i] = (char)((v >> (i * 8)) & 0xFF);
            out.append(b, 8);
        };
        auto put_bytes = [&](const char* p, size_t n) { put_u32((uint32_t)n); out.append(p, n); };
        put_u64(height);
        put_u32(bits);
        put_u64(supply_units);
        out.append(reinterpret_cast<const char*>(block_hash.data()), 32);
        put_u32((uint32_t)new_utxo_keys.size());
        for (const auto& k : new_utxo_keys) put_bytes(k.data(), k.size());
        put_u32((uint32_t)spent_utxo_kvs.size());
        for (const auto& [k, v] : spent_utxo_kvs) {
            put_bytes(k.data(), k.size());
            put_bytes(v.data(), v.size());
        }
        return out;
    }

    struct PendingCommitRecord {
        uint64_t                                              height = 0;
        uint32_t                                              bits   = 0;
        uint64_t                                              supply_units = 0;
        Hash256                                               block_hash{};
        std::vector<std::string>                              new_utxo_keys;
        std::vector<std::pair<std::string, std::string>>      spent_utxo_kvs;
        bool                                                  ok = false;
    };

    static PendingCommitRecord DeserializePendingCommit(const std::string& blob) {
        PendingCommitRecord r;
        size_t p = 0;
        auto need = [&](size_t n) { return p + n <= blob.size(); };
        auto get_u32 = [&](uint32_t& out) -> bool {
            if (!need(4)) return false;
            const uint8_t* b = reinterpret_cast<const uint8_t*>(blob.data() + p);
            out = (uint32_t)b[0]
                | ((uint32_t)b[1] << 8)
                | ((uint32_t)b[2] << 16)
                | ((uint32_t)b[3] << 24);
            p += 4; return true;
        };
        auto get_u64 = [&](uint64_t& out) -> bool {
            if (!need(8)) return false;
            const uint8_t* b = reinterpret_cast<const uint8_t*>(blob.data() + p);
            out = 0;
            for (int i = 0; i < 8; ++i) out |= ((uint64_t)b[i]) << (i * 8);
            p += 8; return true;
        };
        auto get_str = [&](std::string& out) -> bool {
            uint32_t n; if (!get_u32(n)) return false;
            if (!need(n)) return false;
            out.assign(blob.data() + p, n); p += n; return true;
        };
        if (!get_u64(r.height)) return r;
        if (!get_u32(r.bits)) return r;
        if (!get_u64(r.supply_units)) return r;
        if (!need(32)) return r;
        std::memcpy(r.block_hash.data(), blob.data() + p, 32); p += 32;
        uint32_t n_new = 0; if (!get_u32(n_new)) return r;
        r.new_utxo_keys.reserve(n_new);
        for (uint32_t i = 0; i < n_new; ++i) {
            std::string k; if (!get_str(k)) return r;
            r.new_utxo_keys.push_back(std::move(k));
        }
        uint32_t n_spent = 0; if (!get_u32(n_spent)) return r;
        r.spent_utxo_kvs.reserve(n_spent);
        for (uint32_t i = 0; i < n_spent; ++i) {
            std::string k, v;
            if (!get_str(k) || !get_str(v)) return r;
            r.spent_utxo_kvs.emplace_back(std::move(k), std::move(v));
        }
        r.ok = true;
        return r;
    }

    void RecoverFromJournal() {
        // A VUR1 transaction deliberately survives process death.  The old
        // metadata frame remains authoritative; startup ReplayChain must first
        // rebuild modules and reconcile utxo_db to that frame, then call
        // CompleteReorgUtxoRecoveryAfterReplay().  Do not consume a coexisting
        // pending:commit here: the full reconciliation supersedes it, and both
        // identities are cleared atomically only after recovery succeeds.
        if (auto retained_wire = index_db_->Get(REORG_UTXO_PENDING_KEY)) {
            const std::vector<uint8_t> wire(retained_wire->begin(),
                                            retained_wire->end());
            const auto retained = DecodeReorgUtxoPending(wire);
            if (!retained)
                throw std::runtime_error(
                    "FATAL: retained VUR1 reorg identity is malformed; "
                    "refusing ambiguous UTXO recovery");
            if (!ReorgOldCanonicalMatches(*retained))
                throw std::runtime_error(
                    "FATAL: retained VUR1 old-tip identity does not match "
                    "the authoritative chain frame");
            if (ReadDurablePublicationPending())
                throw std::runtime_error(
                    "FATAL: VUR1 and VDP1 coexist; canonical publication "
                    "state is ambiguous");
            if (auto transient =
                    index_db_->Get("reorg:utxo:rebuilding")) {
                if (*transient != "1" && *transient != "delta-v1")
                    throw std::runtime_error(
                        "FATAL: VUR1 coexists with an unknown UTXO rebuild "
                        "marker version");
            }
            std::cerr
                << "\n  [recover] retained VUR1 reorg transaction found "
                << "(old h=" << retained->old_height
                << ", intended h=" << retained->new_height << ").\n"
                << "  [recover] Keeping the exact identity and any "
                   "pending:commit until startup replay + UTXO "
                   "reconciliation complete.\n\n";
            std::cerr.flush();
            return;
        }

        auto rebuild_marker = index_db_->Get("reorg:utxo:rebuilding");
        if (rebuild_marker) {
            if (*rebuild_marker != "1" &&
                *rebuild_marker != "delta-v1")
                throw std::runtime_error(
                    "FATAL: unknown reorg:utxo:rebuilding marker version");
            // A generic UTXO rebuild was interrupted, so utxo_db may be
            // partially old/partially new.  Keep both this marker and any
            // pending:commit until startup ReplayChain performs a complete
            // authoritative reconciliation.  Clearing either identity in the
            // constructor would create a second-crash window where a snapshot
            // could publish the mixed UTXO namespace as healthy.
            std::cerr << "\n  [recover] reorg:utxo:rebuilding marker present — a UTXO rebuild\n"
                      << "  [recover] was interrupted (crash/kill mid-Reorganize). AUTO-RECOVERING:\n"
                      << "  [recover] retaining the marker until startup chain replay rebuilds the\n"
                      << "  [recover] UTXO set and a checked reconciliation clears it. No manual\n"
                      << "  [recover] cleanup required.\n\n";
            std::cerr.flush();
            return;
        }

        auto blob = index_db_->Get(PENDING_COMMIT_KEY);
        if (!blob) return;
        // Do not deserialize or execute a linear journal during construction.
        // It is neither an authenticated canonical identity nor sufficient to
        // distinguish the Step-3 and Step-4 crash cuts.  In particular, a
        // malformed/truncated record must not be deleted and a valid-looking
        // record must not be allowed to erase an arbitrary block body or
        // rewrite arbitrary u:* keys.
        //
        // The index frame is still authoritative when pending:commit exists:
        // Step 5 deletes this key in the same atomic batch that publishes the
        // new tip and VDP1.  Arm the generic recovery obligation first, retain
        // the journal byte-for-byte as evidence, and let socket-free startup
        // ReplayChain reconstruct consensus state from the canonical index.
        // Its checked full UTXO reconciliation clears both this marker and the
        // superseded journal in one batch.  This is valid at height zero, and
        // is also safe if a VDP1 happens to coexist: the published VDP1 frame
        // remains authoritative and is independently identity-checked.
        WriteBatch intent;
        intent.Put("reorg:utxo:rebuilding", "1");
        WriteOrThrowUncertain(
            *index_db_, intent,
            "linear pending:commit recovery-marker write");
        std::cerr
            << "\n  [recover] retained linear pending:commit found.\n"
            << "  [recover] Keeping the journal and deferring all UTXO "
               "correction to\n"
            << "  [recover] full canonical startup replay + checked UTXO "
               "reconciliation.\n\n";
        std::cerr.flush();
    }

    bool CommitBlock(
        const Hash256& block_hash,
        const std::vector<uint8_t>& block_data,
        uint64_t height,
        uint64_t supply_units,
        uint32_t bits,
        const std::vector<std::pair<Hash256, uint32_t>>& spent_utxos,
        const std::vector<std::tuple<Hash256, uint32_t, std::string>>& new_utxos,
        const std::vector<uint8_t>* anchor_security_floor = nullptr
    ) {
        if (anchor_security_floor &&
            (anchor_security_floor->empty() ||
             anchor_security_floor->size() >
                 MAX_ANCHOR_SECURITY_FLOOR_BYTES))
            return false;
        {
            WriteBatch blk_batch;
            blk_batch.Put("b:" + HashToHex(block_hash),
                          std::string(block_data.begin(), block_data.end()));
            if (!blocks_db_->Write(blk_batch)) {
                std::cerr << "  [commit-fail] Step 1 (blocks_db Put) failed at "
                          << "h=" << height
                          << " hash=" << HashToHex(block_hash).substr(0, 16)
                          << " — likely disk full or IO error; check df -h "
                          << "and disk health.\n";
                std::cerr.flush();
                return false;
            }
        }

        std::unordered_set<std::string> intra_block_transients;
        {
            std::unordered_set<std::string> created_keys;
            for (const auto& [hash, idx, data] : new_utxos)
                created_keys.insert("u:" + HashToHex(hash) + ":" + std::to_string(idx));
            for (const auto& [hash, idx] : spent_utxos) {
                std::string k = "u:" + HashToHex(hash) + ":" + std::to_string(idx);
                if (created_keys.count(k)) intra_block_transients.insert(k);
            }
        }

        std::vector<std::pair<std::string, std::string>> spent_utxo_kvs;
        spent_utxo_kvs.reserve(spent_utxos.size());
        for (const auto& [hash, idx] : spent_utxos) {
            std::string k = "u:" + HashToHex(hash) + ":" + std::to_string(idx);
            if (intra_block_transients.count(k)) continue;
            auto v = utxo_db_->Get(k);
            if (!v) {
                std::cerr << "  [commit-fail] missing spent UTXO: " << k
                          << " block_h=" << height
                          << " block=" << HashToHex(block_hash).substr(0, 16)
                          << " spent_count=" << spent_utxos.size()
                          << " new_count=" << new_utxos.size()
                          << " transients=" << intra_block_transients.size()
                          << "\n";
                std::cerr.flush();
                return false;
            }
            spent_utxo_kvs.emplace_back(std::move(k), std::move(*v));
        }
        std::vector<std::string> new_utxo_keys;
        new_utxo_keys.reserve(new_utxos.size());
        for (const auto& [hash, idx, data] : new_utxos)
            new_utxo_keys.push_back("u:" + HashToHex(hash) + ":" + std::to_string(idx));

        {
            WriteBatch jb;
            jb.Put(PENDING_COMMIT_KEY,
                   SerializePendingCommit(block_hash, height, supply_units, bits,
                                          new_utxo_keys, spent_utxo_kvs));
            // A false/sync error does not prove the journal missed the WAL.
            // Continuing or compensating in-process could overwrite a
            // recoverable intent, so force the caller into fail-stop recovery.
            WriteOrThrowUncertain(*index_db_, jb,
                "CommitBlock Step 3 journal write at h=" +
                std::to_string(height));
        }

        {
            WriteBatch utxo_batch;
            for (const auto& [k, _] : spent_utxo_kvs) utxo_batch.Delete(k);
            for (size_t i = 0; i < new_utxos.size(); ++i) {
                if (intra_block_transients.count(new_utxo_keys[i])) continue;
                utxo_batch.Put(new_utxo_keys[i], std::get<2>(new_utxos[i]));
            }
            WriteOrThrowUncertain(*utxo_db_, utxo_batch,
                "CommitBlock Step 4 UTXO write at h=" +
                std::to_string(height));
        }

        {
            WriteBatch ib;
            std::string h_hex = HashToHex(block_hash);
            ib.Put("idx:" + h_hex + ":height", std::to_string(height));
            ib.Put("idx:" + h_hex + ":bits",   std::to_string(bits));
            ib.Put("idx:height:" + std::to_string(height), h_hex);
            ib.Put("chain:tip",    h_hex);
            ib.Put("chain:height", std::to_string(height));
            ib.Put("chain:supply", std::to_string(supply_units));
            ib.Put("tip:hash",     h_hex);
            ib.Put("tip:height",   std::to_string(height));
            ib.Put("tip:supply",   std::to_string(supply_units));
            if (anchor_security_floor) {
                ib.Put(ANCHOR_SECURITY_FLOOR_KEY,
                       std::string(anchor_security_floor->begin(),
                                   anchor_security_floor->end()));
            }
            const auto pending = EncodeDurablePublicationPending(
                height, block_hash);
            ib.Put(DURABLE_PUBLICATION_PENDING_KEY,
                   std::string(pending.begin(), pending.end()));
            ib.Delete(PENDING_COMMIT_KEY);
            // This is the canonical cut point.  Once attempted, false/throw is
            // inherently uncertain: the WAL may become authoritative on
            // restart even when the current process reports a sync failure.
            WriteOrThrowUncertain(*index_db_, ib,
                "CommitBlock Step 5 canonical index write at h=" +
                std::to_string(height));
        }
        return true;
    }

    size_t CountUTXOsInLevelDB() const {
        size_t count = 0;
        utxo_db_->Iterate("u:", [&](const std::string&, const std::string&) {
            ++count;
            return true;
        });
        return count;
    }

    bool PersistBlockMetadata(
        const Hash256& block_hash,
        const std::vector<uint8_t>& block_data,
        uint64_t height,
        uint64_t supply_units,
        uint32_t bits,
        const std::vector<uint8_t>* anchor_security_floor = nullptr)
    {
        if (anchor_security_floor &&
            (anchor_security_floor->empty() ||
             anchor_security_floor->size() >
                 MAX_ANCHOR_SECURITY_FLOOR_BYTES))
            return false;
        {
            WriteBatch blk_batch;
            blk_batch.Put("b:" + HashToHex(block_hash),
                          std::string(block_data.begin(), block_data.end()));
            if (!blocks_db_->Write(blk_batch)) return false;
        }
        {
            WriteBatch ib;
            std::string h_hex = HashToHex(block_hash);
            ib.Put("idx:" + h_hex + ":height", std::to_string(height));
            ib.Put("idx:" + h_hex + ":bits",   std::to_string(bits));
            ib.Put("idx:height:" + std::to_string(height), h_hex);
            ib.Put("chain:tip",    h_hex);
            ib.Put("chain:height", std::to_string(height));
            ib.Put("chain:supply", std::to_string(supply_units));
            ib.Put("tip:hash",     h_hex);
            ib.Put("tip:height",   std::to_string(height));
            ib.Put("tip:supply",   std::to_string(supply_units));
            if (anchor_security_floor) {
                ib.Put(ANCHOR_SECURITY_FLOOR_KEY,
                       std::string(anchor_security_floor->begin(),
                                   anchor_security_floor->end()));
            }
            const auto pending = EncodeDurablePublicationPending(
                height, block_hash);
            ib.Put(DURABLE_PUBLICATION_PENDING_KEY,
                   std::string(pending.begin(), pending.end()));
            // PersistBlockMetadata is also the final step of the linear
            // CommitBlock self-heal path.  If CommitBlock failed after writing
            // its journal, the rebuilt UTXO snapshot and this metadata batch
            // make the block fully durable; retaining pending:commit would
            // make startup recovery undo that already-healed block.  Delete it
            // in the same atomic index batch that publishes the authoritative
            // tip.  Reorg callers are safe: their UTXO rebuild completes before
            // metadata publication and any older linear journal is obsolete.
            ib.Delete(PENDING_COMMIT_KEY);
            WriteOrThrowUncertain(*index_db_, ib,
                "PersistBlockMetadata canonical index write at h=" +
                std::to_string(height));
        }
        return true;
    }

    // Restore the authoritative per-height index after a multi-block reorg
    // transaction is compensated.  PersistBlockMetadata may already have
    // overwritten a prefix of idx:height:* with alt-branch hashes before a
    // later callback rejects.  Rewriting only chain:tip is insufficient:
    // ReplayChain walks idx:height:* and would stitch together two branches on
    // restart.  Restore the complete replaced old suffix, remove any alt-only
    // heights above the old tip, and publish the old tip in one index batch.
    bool RestoreCanonicalMetadata(
        const std::vector<std::tuple<uint64_t, Hash256, uint32_t>>& canonical_tail,
        const Hash256& tip_hash,
        uint64_t tip_height,
        uint64_t supply_units,
        // Optional tri-state restore instruction for the node's opaque local
        // anchor floor.  A null pointer leaves the key untouched (legacy
        // callers); a pointer to nullopt deletes an alt-branch-only floor; a
        // pointer containing bytes restores the exact pre-reorg floor.  The
        // selected operation lands in the same atomic batch as the old tip.
        const std::optional<std::vector<uint8_t>>*
            anchor_security_floor_restore = nullptr,
        const std::optional<std::vector<uint8_t>>*
            durable_publication_pending_restore = nullptr)
    {
        if (anchor_security_floor_restore &&
            anchor_security_floor_restore->has_value() &&
            ((**anchor_security_floor_restore).empty() ||
             (**anchor_security_floor_restore).size() >
                 MAX_ANCHOR_SECURITY_FLOOR_BYTES))
            return false;
        if (durable_publication_pending_restore &&
            durable_publication_pending_restore->has_value()) {
            const auto pending = DecodeDurablePublicationPending(
                **durable_publication_pending_restore);
            if (!pending || pending->height != tip_height ||
                pending->hash != tip_hash)
                return false;
        }
        if (canonical_tail.empty()) return false;
        bool first = true;
        uint64_t prior_height = 0;
        for (const auto& [height, hash, bits] : canonical_tail) {
            (void)hash;
            (void)bits;
            if (height > tip_height) return false;
            if (!first &&
                (prior_height == UINT64_MAX || height != prior_height + 1))
                return false;
            first = false;
            prior_height = height;
        }
        if (std::get<0>(canonical_tail.back()) != tip_height ||
            std::get<1>(canonical_tail.back()) != tip_hash) return false;

        WriteBatch batch;
        index_db_->Iterate("idx:height:",
            [&](const std::string& key, const std::string&) {
                static constexpr std::string_view prefix = "idx:height:";
                uint64_t height = 0;
                if (key.size() > prefix.size() &&
                    key.compare(0, prefix.size(), prefix) == 0 &&
                    ParseCanonicalUint64Text(
                        std::string_view(key).substr(prefix.size()), height) &&
                    height > tip_height) {
                    batch.Delete(key);
                }
                return true;
            });

        for (const auto& [height, hash, bits] : canonical_tail) {
            const std::string hex = HashToHex(hash);
            batch.Put("idx:" + hex + ":height", std::to_string(height));
            batch.Put("idx:" + hex + ":bits", std::to_string(bits));
            batch.Put("idx:height:" + std::to_string(height), hex);
        }
        const std::string tip_hex = HashToHex(tip_hash);
        batch.Put("chain:tip",    tip_hex);
        batch.Put("chain:height", std::to_string(tip_height));
        batch.Put("chain:supply", std::to_string(supply_units));
        batch.Put("tip:hash",     tip_hex);
        batch.Put("tip:height",   std::to_string(tip_height));
        batch.Put("tip:supply",   std::to_string(supply_units));
        if (anchor_security_floor_restore) {
            if (anchor_security_floor_restore->has_value()) {
                const auto& wire = **anchor_security_floor_restore;
                batch.Put(ANCHOR_SECURITY_FLOOR_KEY,
                          std::string(wire.begin(), wire.end()));
            } else {
                batch.Delete(ANCHOR_SECURITY_FLOOR_KEY);
            }
        }
        if (durable_publication_pending_restore &&
            durable_publication_pending_restore->has_value()) {
            const auto& wire = **durable_publication_pending_restore;
            batch.Put(DURABLE_PUBLICATION_PENDING_KEY,
                      std::string(wire.begin(), wire.end()));
        } else {
            // A normal pre-reorg frame has no pending publication. Legacy
            // callers therefore safely clear an alt-only obligation too.
            batch.Delete(DURABLE_PUBLICATION_PENDING_KEY);
        }
        batch.Delete(PENDING_COMMIT_KEY);
        return index_db_->Write(batch);
    }

    std::string GetStats() const {
        std::string s;
        s += "blocks_db: " + blocks_db_->GetStats() + "\n";
        s += "utxo_db:   " + utxo_db_->GetStats()   + "\n";
        s += "index_db:  " + index_db_->GetStats()   + "\n";
        return s;
    }

    bool DumpConsistentSnapshot(const std::string& target_dir,
                                std::string* out_error = nullptr) {
        namespace fs = std::filesystem;
        auto set_err = [&](const std::string& m) {
            if (out_error) *out_error = m;
        };

        // A snapshot must never turn an explicitly recoverable cross-database
        // frame into an apparently clean bootstrap artifact.  The caller holds
        // the chain lock, so this preflight remains stable through all three
        // per-database dumps.
        if (UtxoRecoveryRequired() ||
            index_db_->Has(PENDING_COMMIT_KEY)) {
            set_err("durability journal/UTXO recovery is still pending");
            return false;
        }

#ifndef VELD_USE_LEVELDB
        (void)target_dir;
        set_err("dump requires a build with the LevelDB backend");
        return false;
#else
        std::error_code ec;
        fs::remove_all(target_dir, ec);
        if (ec) {
            set_err("cannot clean target_dir: " + ec.message());
            return false;
        }
        fs::create_directories(target_dir, ec);
        if (ec) {
            set_err("cannot create target_dir: " + ec.message());
            return false;
        }

        auto* src_blocks = dynamic_cast<LevelDBStore*>(blocks_db_.get());
        auto* src_utxo   = dynamic_cast<LevelDBStore*>(utxo_db_.get());
        auto* src_index  = dynamic_cast<LevelDBStore*>(index_db_.get());
        if (!src_blocks || !src_utxo || !src_index) {
            set_err("dump requires LevelDB backend (got non-LevelDB store)");
            fs::remove_all(target_dir, ec);
            return false;
        }

        const std::string p_blocks = target_dir + "/blocks";
        const std::string p_utxo   = target_dir + "/utxo";
        const std::string p_index  = target_dir + "/index";

        if (!src_blocks->DumpToFreshLevelDB(p_blocks)) {
            set_err("blocks dump failed");
            fs::remove_all(target_dir, ec);
            return false;
        }
        if (!src_utxo->DumpToFreshLevelDB(p_utxo)) {
            set_err("utxo dump failed");
            fs::remove_all(target_dir, ec);
            return false;
        }
        if (!src_index->DumpToFreshLevelDB(p_index)) {
            set_err("index dump failed");
            fs::remove_all(target_dir, ec);
            return false;
        }
        return true;
#endif
    }

private:
    std::unique_ptr<KVStore> blocks_db_;
    std::unique_ptr<KVStore> utxo_db_;
    std::unique_ptr<KVStore> index_db_;

public:
    KVStore& GetIndexDB() { return *index_db_; }
};

}
}
