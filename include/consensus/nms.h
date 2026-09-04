#pragma once

#include "../core/constants.h"
#include "../core/block.h"
#include "../core/hash.h"
#include "../core/pqc_script.h"
#include "../core/pow_target.h"
#include "../mining/veldhash.h"
#include "../crypto/ripemd160.h"
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>
#include <string>
#include <array>
#include <unordered_map>
#include <deque>
#include <mutex>

namespace veld {

class NmsVerifyCache {
  public:
    bool Lookup(const std::string& key, bool& out_result) const {
        std::lock_guard<std::mutex> lk(m_);
        auto it = map_.find(key);
        if (it == map_.end())
            return false;
        out_result = it->second;
        return true;
    }
    void Insert(const std::string& key, bool result) {
        std::lock_guard<std::mutex> lk(m_);
        if (map_.size() >= CAP) {
            for (size_t i = 0; i < CAP / 10 && !fifo_.empty(); ++i) {
                map_.erase(fifo_.front());
                fifo_.pop_front();
            }
        }
        auto [it, inserted] = map_.try_emplace(key, result);
        if (inserted)
            fifo_.push_back(key);
    }
    size_t Clear() {
        std::lock_guard<std::mutex> lk(m_);
        size_t n = map_.size();
        map_.clear();
        fifo_.clear();
        return n;
    }
    size_t Size() const {
        std::lock_guard<std::mutex> lk(m_);
        return map_.size();
    }

  private:
    static constexpr size_t CAP = 1'000'000;
    mutable std::mutex m_;
    std::unordered_map<std::string, bool> map_;
    std::deque<std::string> fifo_;
};
inline NmsVerifyCache g_nms_verify_cache;

struct NmsRecord {
    BlockHeader header;
    std::vector<uint8_t> raw;
};

// Keep local resource exhaustion distinct from a permanent consensus result.
// Every caller which can score a peer, cache a rejection, or discard a block
// must preserve this tri-state through its own admission boundary.
enum class NmsValidationDisposition : uint8_t {
    Valid,
    ConsensusInvalid,
    DeferredLocalWork,
};

// Parse a raw OP_RETURN payload (the bytes AFTER the OP_RETURN opcode, NOT
// including the push-data length prefix). Returns nullopt on any format fault.
//
// This function is deliberately free of chain dependencies — callers feed it
// a bare byte span and it returns the decoded header, or nothing. It does NOT
// verify PoW, prev-block freshness, difficulty, or the signing input. All of
// those are chain-state checks and live in the future `ValidateNms` function.
inline std::optional<NmsRecord> ParseNmsPayload(const uint8_t* data, size_t len) {
    if (data == nullptr)
        return std::nullopt;
    if (len != NMS_PAYLOAD_LEN)
        return std::nullopt;

    if (std::memcmp(data, NMS_MAGIC, NMS_MAGIC_LEN) != 0)
        return std::nullopt;

    if (data[NMS_MAGIC_LEN] != NMS_VERSION)
        return std::nullopt;

    const uint8_t* hdr_bytes = data + NMS_MAGIC_LEN + 1;
    std::vector<uint8_t> hdr_buf(hdr_bytes, hdr_bytes + NMS_HEADER_LEN);

    BlockHeader hdr;
    if (!hdr.Deserialize(hdr_buf, 0))
        return std::nullopt;

    NmsRecord rec;
    rec.header = hdr;
    rec.raw.assign(data, data + len);
    return rec;
}

inline std::optional<NmsRecord> ParseNmsPayload(const std::vector<uint8_t>& v) {
    return ParseNmsPayload(v.data(), v.size());
}

inline std::vector<uint8_t> EncodeNmsPayload(const BlockHeader& hdr) {
    std::vector<uint8_t> hdr_bytes = hdr.Serialize();
    if (hdr_bytes.size() != NMS_HEADER_LEN) {
        return {};
    }
    std::vector<uint8_t> out;
    out.reserve(NMS_PAYLOAD_LEN);
    out.insert(out.end(), NMS_MAGIC, NMS_MAGIC + NMS_MAGIC_LEN);
    out.push_back(NMS_VERSION);
    out.insert(out.end(), hdr_bytes.begin(), hdr_bytes.end());
    return out;
}

inline bool LooksLikeNms(const uint8_t* data, size_t len) {
    if (data == nullptr)
        return false;
    if (len != NMS_PAYLOAD_LEN)
        return false;
    return std::memcmp(data, NMS_MAGIC, NMS_MAGIC_LEN) == 0;
}

inline bool LooksLikeNms(const std::vector<uint8_t>& v) {
    return LooksLikeNms(v.data(), v.size());
}

inline std::optional<NmsRecord> ExtractNmsFromTx(const Transaction& tx) {
    std::optional<NmsRecord> found;
    for (const auto& out : tx.outputs) {
        const auto& spk = out.script_pubkey;
        constexpr size_t kNmsScriptLen = 3 + NMS_PAYLOAD_LEN;
        if (spk.size() != kNmsScriptLen)
            continue;
        if (spk[0] != 0x6A)
            continue;
        if (spk[1] != 0x4C)
            continue;
        if (spk[2] != NMS_PAYLOAD_LEN)
            continue;
        auto parsed = ParseNmsPayload(spk.data() + 3, NMS_PAYLOAD_LEN);
        if (!parsed)
            continue;
        if (found)
            return std::nullopt;
        found = parsed;
    }
    return found;
}

inline std::vector<uint8_t> BuildNmsOpReturnScript(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> s;
    s.reserve(3 + payload.size());
    s.push_back(0x6A);
    s.push_back(0x4C);
    s.push_back((uint8_t)payload.size());
    s.insert(s.end(), payload.begin(), payload.end());
    return s;
}

inline std::vector<uint8_t> ExtractNmsMinerScript(const Transaction& tx) {
    for (const auto& out : tx.outputs) {
        const auto& spk = out.script_pubkey;
        if (spk.empty())
            continue;
        if (spk[0] == 0x6A)
            continue;
        if (spk.size() != 25)
            continue;
        if (spk[0] != 0x76)
            continue;
        if (spk[1] != 0xA9)
            continue;
        if (spk[2] != 0x14)
            continue;
        if (spk[23] != 0x88)
            continue;
        if (spk[24] != 0xAC)
            continue;
        return spk;
    }
    return {};
}

inline bool ValidateNmsMinerIdentity(const Transaction& tx) {
    auto miner_script = ExtractNmsMinerScript(tx);
    if (miner_script.size() != 25)
        return false;
    std::array<uint8_t, 20> expected_hash;
    for (int i = 0; i < 20; ++i)
        expected_hash[i] = miner_script[3 + i];

    for (const auto& inp : tx.inputs) {
        std::vector<uint8_t> sig_unused;
        std::array<uint8_t, 1952> pubkey;
        if (!veld::pqc::ParseScriptSig(inp.script_sig, sig_unused, pubkey))
            continue;
        Hash160 actual = Hash160Compute(pubkey);
        bool match = true;
        for (int i = 0; i < 20; ++i) {
            if (actual[i] != expected_hash[i]) {
                match = false;
                break;
            }
        }
        if (match)
            return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────
//  VALIDATE NMS (consensus gates, design §2.2 gates 1–6)
//
//  Gate (7) — resolving the signing input to a unique miner_script — is
//  outside this function because it needs the Blockchain's UTXO set to
//  look up each input's prev-script. That check lives at the call site
//  (mempool admission + block validation).
//
//  Returns true only if ALL of:
//    1. The TX's extracted NMS payload is well-formed (caller typically
//       invokes this AFTER ExtractNmsFromTx returned a value).
//    2. The header's prev_block_hash exists in the chain AND is within
//       the last NMS_MAX_PREV_HEIGHT_GAP blocks of the enclosing block.
//    3. The header's bits exactly match ComputeNextBits() at the claim
//       height (i.e. the difficulty this miner would have been solving).
//    4. VeldHash(header) ≤ 4 × target decoded from header.bits.
//    5. VeldHash(header) >  target — i.e. NOT a full solution (which
//       should have been submitted as a block).
//
//  The `enclosing_block_height` argument is the height of the block
//  that would CONTAIN this NMS transaction; it's always 1 higher than
//  chain.Height() at mempool-admission time, and for block validation
//  it's the block being validated.
// ─────────────────────────────────────────────────────────────────────
template <typename ChainT>
inline bool ValidateNms(const NmsRecord& rec, const ChainT& chain, uint64_t enclosing_block_height,
                        mining::ExpensivePowBudget* source_pow_budget = nullptr,
                        bool* local_work_deferred = nullptr,
                        mining::ExpensivePowUse pow_use = mining::ExpensivePowUse::PeerNms) {
    if (local_work_deferred)
        *local_work_deferred = false;
    auto prev_height_opt = chain.GetHeightByHashLocked(rec.header.prev_block_hash);
    if (!prev_height_opt)
        return false;
    uint64_t claim_height = *prev_height_opt + 1;
    if (enclosing_block_height == 0)
        return false;
    // Fresh public-mainnet-v2 rule: an NMS claim is useful only for the next
    // block on the exact branch it was mining.  Accepting any of the prior 100
    // parents let an unauthenticated transaction alternate dataset identities
    // even after block-header aliases were closed.
    if (claim_height != enclosing_block_height)
        return false;

    uint32_t expected_bits = chain.ComputeNextBitsAtLocked(*prev_height_opt);
    CanonicalPowTarget canonical_target;
    if (!DecodeExpectedVeldTarget(rec.header.bits, expected_bits, canonical_target))
        return false;

#if defined(VELD_TEST_NMS_BRANCH_CONTEXT)
#if defined(VELD_PUBLIC_RELEASE)
#error "VELD_TEST_NMS_BRANCH_CONTEXT must never be enabled in a public release"
#endif
    // Focused reorg-context sentinel: preserve payload parsing, candidate
    // ancestry/gap, and exact compact-bits validation above, but bypass the
    // expensive probabilistic near-miss hash search.  Miner identity, duplicate
    // suppression, and stake-bond gates remain in Blockchain and are exercised
    // by the harness.  No shipped build defines this macro.
#endif

    std::string cache_key = HashToHex(Hash256d(rec.raw));
    {
        bool cached_result;
        if (g_nms_verify_cache.Lookup(cache_key, cached_result)) {
            return cached_result;
        }
    }

    std::vector<uint8_t> hdr_bytes = rec.header.Serialize();
    if (hdr_bytes.size() != NMS_HEADER_LEN) {
        g_nms_verify_cache.Insert(cache_key, false);
        return false;
    }
    std::optional<mining::ExpensivePowLease> source_pow_lease;
    if (source_pow_budget) {
        source_pow_lease = source_pow_budget->TryAcquire(pow_use);
        if (!source_pow_lease) {
            if (local_work_deferred)
                *local_work_deferred = true;
            return false;
        }
    }
    auto global_pow_lease = mining::GlobalExpensivePowBudget().TryAcquire(pow_use);
    if (!global_pow_lease) {
        if (local_work_deferred)
            *local_work_deferred = true;
        return false;
    }
#if defined(VELD_TEST_NMS_BRANCH_CONTEXT)
    // Keep the real source/global admission ordering in the focused harness;
    // bypass only the probabilistic near-miss hash comparison itself.
    return true;
#endif
    Hash256 pow = mining::VeldHash(hdr_bytes, claim_height, canonical_target);
    if (!mining::g_veldhash_last_dataset_ok()) {
        // Dataset allocation/generation is local work state, never a negative
        // consensus result and never eligible for the negative NMS cache.
        if (local_work_deferred)
            *local_work_deferred = true;
        return false;
    }

    const std::vector<uint8_t> target(canonical_target.bytes.begin(), canonical_target.bytes.end());
    std::vector<uint8_t> four_target(32, 0);
    uint32_t carry = 0;
    for (int i = 31; i >= 0; --i) {
        uint32_t v = (uint32_t)target[i] * 4u + carry;
        four_target[i] = (uint8_t)(v & 0xFF);
        carry = v >> 8;
    }
    if (carry != 0) {
        g_nms_verify_cache.Insert(cache_key, false);
        return false;
    }

    bool pow_le_4tgt = false;
    for (int i = 0; i < 32; ++i) {
        if (pow[i] < four_target[i]) {
            pow_le_4tgt = true;
            break;
        }
        if (pow[i] > four_target[i]) {
            pow_le_4tgt = false;
            break;
        }
        if (i == 31)
            pow_le_4tgt = true;
    }
    if (!pow_le_4tgt) {
        g_nms_verify_cache.Insert(cache_key, false);
        return false;
    }

    bool pow_gt_tgt = false;
    for (int i = 0; i < 32; ++i) {
        if (pow[i] > target[i]) {
            pow_gt_tgt = true;
            break;
        }
        if (pow[i] < target[i]) {
            pow_gt_tgt = false;
            break;
        }
    }
    if (!pow_gt_tgt) {
        g_nms_verify_cache.Insert(cache_key, false);
        return false;
    }

    g_nms_verify_cache.Insert(cache_key, true);
    return true;
}

template <typename ChainT>
inline NmsValidationDisposition
ValidateNmsWithDisposition(const NmsRecord& rec, const ChainT& chain,
                           uint64_t enclosing_block_height,
                           mining::ExpensivePowBudget* source_pow_budget = nullptr,
                           mining::ExpensivePowUse pow_use = mining::ExpensivePowUse::PeerNms) {
    bool local_work_deferred = false;
    if (ValidateNms(rec, chain, enclosing_block_height, source_pow_budget, &local_work_deferred,
                    pow_use)) {
        return NmsValidationDisposition::Valid;
    }
    return local_work_deferred ? NmsValidationDisposition::DeferredLocalWork
                               : NmsValidationDisposition::ConsensusInvalid;
}

} // namespace veld
