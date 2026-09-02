// include/compat/endorse_guard.h
//
//  Hardening: persistent validator anti-equivocation
//  guard, shared by both endorsers (src/veld-node.cpp and src/veld-validator.cpp)
//  so the invariant has one implementation.
//
//  Reorg safety
//  A validator that endorsed block X at height H and then — after a natural
//  reorg replaced the canonical block at H with Y — re-endorses Y at the SAME
//  height emits two validator-signed endorsements at one height for two
//  different block hashes. That is precisely the equivocation evidence
//  `include/consensus/validators.h` slashes on: permanent re-registration ban
//  + custodial-bond confiscation + a 25% bounty to whoever submits the SLASH.
//  Both pre-existing dedup mechanisms are reorg-defeatable:
//    * getblockendorsements(H) / GetEndorsements(H) is CHAIN-DERIVED — a reorg
//      that orphans the prior endorsement removes it, so "already?" is false
//      again;
//    * the retry-throttle key embeds the block hash, so a new canonical hash
//      yields a fresh key and the throttle does not suppress the re-sign;
//    * last_endorsed_height is a non-persistent counter.
//
//  THE GUARD
//  ─────────
//  Records, on disk, EXACTLY ONE block hash per (height, pubkey) the validator
//  ever signs, and refuses to sign a DIFFERENT hash at a height it already
//  endorsed — across reorgs AND process restarts. A missed endorsement reward
//  is recoverable; a slashed bond is not, so the trade is always correct.
//
//  CRASH SAFETY: record() writes + fsyncs BEFORE the caller produces the
//  signature and returns false on ANY open/write/flush/sync/close failure.  A
//  caller MUST refuse to sign on false.  The map is updated only after durable
//  success, so an I/O failure cannot be mistaken for a protected vote.  A crash
//  between a successful record() and broadcast can only ever LOSE an
//  endorsement, never create an equivocating second one.
//
//  RETENTION: append-only (~80 bytes per endorsement). Never pruned — dropping
//  a height still inside MAX_REORG_DEPTH would re-open the hole; the slow growth
//  is an acceptable cost for an unforgeable safety property.

#ifndef VELD_COMPAT_ENDORSE_GUARD_H
#define VELD_COMPAT_ENDORSE_GUARD_H

#include <string>
#include <mutex>
#include <unordered_map>
#include <fstream>
#include <cstdio>
#ifdef _WIN32
#  include <io.h>
#else
#  include <unistd.h>
#endif

struct EndorseAntiEquivGuard {
    std::mutex                                   mu_;
    std::unordered_map<std::string, std::string> map_;   // "height:pubkey_hex" -> block_hash_hex
    std::string                                  path_;

    // Load the persisted records once at startup. Safe to call before the
    // endorse loop; idempotent if the file is absent.
    void load(const std::string& p) {
        std::lock_guard<std::mutex> lk(mu_);
        path_ = p;
        std::ifstream f(path_);
        std::string line;
        while (std::getline(f, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                line.pop_back();
            auto eq = line.rfind('=');
            if (eq == std::string::npos) continue;
            map_[line.substr(0, eq)] = line.substr(eq + 1);   // last write wins
        }
    }

    // True iff signing `hash_hex` at `key` would equivocate: a DIFFERENT hash
    // was already recorded for this (height,pubkey). Re-signing the SAME hash
    // is fine (idempotent retry after a transient broadcast failure).
    bool would_equivocate(const std::string& key, const std::string& hash_hex) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = map_.find(key);
        return it != map_.end() && it->second != hash_hex;
    }

    // Commit (key -> hash_hex) to disk (fsync) and then memory. MUST return true
    // BEFORE the endorsement is signed.  The conflict check lives inside this
    // same critical section as persistence; a separate would_equivocate()
    // advisory check is not an atomic authorization to sign.
    bool record(const std::string& key, const std::string& hash_hex) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = map_.find(key);
        if (it != map_.end()) {
            if (it->second == hash_hex) return true;   // idempotent retry
            return false;                              // conflicting vote
        }
        if (path_.empty()) return false;
        FILE* fp = std::fopen(path_.c_str(), "ab");
        if (!fp) return false;
        std::string rec = key + "=" + hash_hex + "\n";
        bool ok = std::fwrite(rec.data(), 1, rec.size(), fp) == rec.size();
        if (ok) ok = std::fflush(fp) == 0;
#ifdef _WIN32
        if (ok) {
            const int fd = _fileno(fp);
            ok = fd >= 0 && _commit(fd) == 0;
        }
#else
        if (ok) {
            const int fd = fileno(fp);
            ok = fd >= 0 && ::fsync(fd) == 0;
        }
#endif
        if (std::fclose(fp) != 0) ok = false;
        if (!ok) return false;
        map_[key] = hash_hex;
        return true;
    }
};

#endif // VELD_COMPAT_ENDORSE_GUARD_H
