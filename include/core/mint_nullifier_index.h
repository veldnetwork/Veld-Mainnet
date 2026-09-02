#pragma once

// Rebuildable on-disk index for btcVELD sparse-Merkle proof production.
//
// This is deliberately NOT consensus state.  OnChainTokenLedger commits only
// the constant-size accumulator root/count.  Accepted transition rows are
// written to the ordinary derived index DB so an RPC can reconstruct an exact
// membership/nonmembership witness for any outpoint in bounded RAM.  Missing,
// corrupt, reordered, or fork-stale rows can never manufacture an answer: the
// complete replay must end at the ledger's authenticated root/count and tip.

#include "blockchain.h"
#include "leveldb.h"
#include "onchain_tokens.h"

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace veld {

class MintNullifierTipRace : public std::runtime_error {
public:
    explicit MintNullifierTipRace(const std::string& what)
        : std::runtime_error(what) {}
};

class MintNullifierIndexError : public std::runtime_error {
public:
    explicit MintNullifierIndexError(const std::string& what)
        : std::runtime_error(what) {}
};

class MintNullifierIndex {
public:
    static constexpr const char* PREFIX = "btcmn:";
    // Completion metadata must never be mistaken for a nullifier transition
    // during the strict PREFIX lifetime scan.
    static constexpr const char* CLEANUP_COMPLETE_KEY =
        "derived:btcmn:canonical-cleanup-complete:v1";

    using Status = BtcVeldMintProofStatus;

    explicit MintNullifierIndex(db::KVStore& store) : store_(store) {}

    static std::string HeightPrefix(uint64_t height) {
        std::ostringstream out;
        out << PREFIX << std::setw(20) << std::setfill('0') << height << ':';
        return out.str();
    }

    // Validate the exact on-disk key grammar and optionally return the block
    // hash suffix.  In particular, decimal components are exactly ten digits
    // and hashes use lowercase canonical hex.
    static bool ValidateHeightKey(const std::string& key, uint64_t height,
                                  Hash256* block_hash = nullptr) noexcept {
        try {
            const std::string hp = HeightPrefix(height);
            // hp + tx-index(10) + ':' + marker-vout(10) + ':' + hash(64)
            if (key.size() != hp.size() + 10 + 1 + 10 + 1 + 64 ||
                key.compare(0, hp.size(), hp) != 0)
                return false;
            const size_t tx_pos = hp.size();
            const size_t vout_pos = tx_pos + 11;
            const size_t hash_pos = vout_pos + 11;
            if (key[tx_pos + 10] != ':' || key[vout_pos + 10] != ':' ||
                !ParseFixedWidthUint32_(
                    std::string_view(key).substr(tx_pos, 10)) ||
                !ParseFixedWidthUint32_(
                    std::string_view(key).substr(vout_pos, 10)) ||
                !db::IsCanonicalHash256Text(
                    std::string_view(key).substr(hash_pos, 64)))
                return false;
            if (block_hash)
                *block_hash = HexToHash(key.substr(hash_pos, 64));
            return true;
        } catch (...) {
            return false;
        }
    }

    // Compose accepted transition rows into a larger caller-owned atomic
    // transaction.  No operation is appended until every transition passes
    // the same structural/proof validation as direct PutAccepted.
    bool AppendAcceptedToBatch(
            db::WriteBatch& destination, const Block& block,
            const std::vector<BtcVeldMintTransition>& transitions) const {
        db::WriteBatch staged;
        try {
            const Hash256 block_hash = block.GetHash();
            const std::string block_hash_hex = HashToHex(block_hash);
            for (const auto& t : transitions) {
                if (t.tx_index >= block.transactions.size() ||
                    t.marker_vout >= block.transactions[t.tx_index].outputs.size() ||
                    t.txid != HashToHex(block.transactions[t.tx_index].GetTxID()) ||
                    !ValidateTransition_(t))
                    return false;
                const std::string key = Key(
                    block.height, t.tx_index, t.marker_vout, block_hash_hex);
                if (!ValidateHeightKey(key, block.height)) return false;
                const std::string value = Encode(block.height, block_hash, t);
                Item item;
                if (!Decode(value, item) || item.height != block.height ||
                    item.block_hash != block_hash ||
                    Key(item.height, item.transition.tx_index,
                        item.transition.marker_vout,
                        HashToHex(item.block_hash)) != key)
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

    // Append deletion of stale rows at one affected reorg height.  nullopt
    // means delete the complete height (for heights above a shortened tip).
    // Key/value corruption aborts before the destination batch is modified.
    bool AppendCanonicalHeightCleanupToBatch(
            db::WriteBatch& destination, uint64_t height,
            const std::optional<Hash256>& canonical_hash) const {
        db::WriteBatch staged;
        bool valid = true;
        try {
            store_.Iterate(HeightPrefix(height),
                [&](const std::string& key, const std::string& value) {
                    Hash256 key_hash{};
                    Item item;
                    if (!ValidateHeightKey(key, height, &key_hash) ||
                        !Decode(value, item) || !ValidateDecodedItem_(item) ||
                        item.height != height ||
                        item.block_hash != key_hash ||
                        Key(item.height, item.transition.tx_index,
                            item.transition.marker_vout,
                            HashToHex(item.block_hash)) != key) {
                        valid = false;
                        return false;
                    }
                    if (!canonical_hash || item.block_hash != *canonical_hash)
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

    // Sample the consensus accumulator only while the complete block/module
    // transition sequencer is quiescent.  The guard's scope MUST end before
    // BuildStatus: the lifetime proof scan takes brief chain shared locks via
    // GetBlock, and retaining block_connect_mutex_ here would both stall block
    // publication and invite lock-order inversion.  The fixed order is:
    //
    //   block_connect_mutex_ -> token-ledger mutex; release both;
    //   then brief chain_mutex_ shared locks during the derived-index scan.
    template <typename SnapshotFn>
    Status BuildStatusFromQuiescentSample(
            const Blockchain& chain, const std::string& target_outpoint,
            SnapshotFn&& snapshot_fn) {
        BtcVeldMintAccumulator expected;
        {
            auto transition = chain.AcquireConsensusTransitionGuard();
            expected = std::forward<SnapshotFn>(snapshot_fn)();
        }
        return BuildStatus(chain, target_outpoint, expected);
    }

    bool PutAccepted(const Block& block,
                     const std::vector<BtcVeldMintTransition>& transitions) {
        db::WriteBatch batch;
        if (!AppendAcceptedToBatch(batch, block, transitions)) return false;
        return batch.IsEmpty() || store_.Write(batch);
    }

    Status BuildStatus(const Blockchain& chain,
                       const std::string& target_outpoint,
                       const BtcVeldMintAccumulator& expected) {
        if (!IsValidBtcOutpointId(target_outpoint))
            throw std::invalid_argument("invalid btcVELD nullifier outpoint");

        Status out;
        out.proof = btcnull::EmptyProof();
        Block start_tip;
        if (!chain.TryTip(start_tip))
            throw MintNullifierTipRace(
                "btcVELD nullifier proof requested without a canonical tip");
        out.tip = start_tip.height;
        out.tip_hash = start_tip.GetHash();
        const bool genesis_empty =
            out.tip == 0 && expected.processed_height == 0 &&
            HashIsZero(expected.processed_block_hash) && expected.count == 0 &&
            expected.root == btcnull::EmptyRoot() &&
            expected.effect_count == 0 &&
            expected.effect_root == EmptyBtcVeldMintEffectCommitment();
        if (!genesis_empty &&
            (expected.processed_height != out.tip ||
             expected.processed_block_hash != out.tip_hash))
            throw MintNullifierTipRace(
                "btcVELD nullifier accumulator/tip race; retry");

        Hash256 running_root = btcnull::EmptyRoot();
        uint64_t running_count = 0;
        Hash256 running_effect_root = EmptyBtcVeldMintEffectCommitment();
        uint64_t running_effect_count = 0;
        // Only unresolved C1_FUND effects are retained while replaying.  This
        // bounds auxiliary memory by active funded capacity, not lifetime
        // history, while enforcing the exact FUND -> MINT phase relation.
        std::unordered_map<std::string, std::string> funded_by_outpoint;
        std::unordered_map<std::string, std::string> outpoint_by_allocation;
        uint64_t cached_height = UINT64_MAX;
        Block cached_canonical;
        auto tip_still_matches = [&]() {
            Block now;
            return chain.TryTip(now) && now.height == out.tip &&
                   now.GetHash() == out.tip_hash;
        };
        try {
            store_.Iterate(PREFIX,
              [&](const std::string& key, const std::string& value) {
                Item item;
                if (!Decode(value, item))
                    throw MintNullifierIndexError(
                        "corrupt btcVELD nullifier-index value");
                if (Key(item.height, item.transition.tx_index,
                        item.transition.marker_vout,
                        HashToHex(item.block_hash)) != key)
                    throw MintNullifierIndexError(
                        "btcVELD nullifier-index key/value mismatch");
                if (item.height > out.tip) return true;
                // Do not retain Blockchain's shared mutex for the lifetime-log
                // scan: proof generation is O(mints) and must not stall block
                // connection/IBD.  Cache at most one canonical body and take
                // only the normal brief GetBlock lock when the height changes.
                // A start/end tip check below invalidates any mixed reorg view.
                if (cached_height != item.height) {
                    cached_canonical = chain.GetBlock(item.height);
                    cached_height = item.height;
                }
                if (cached_canonical.GetHash() != item.block_hash)
                    return true; // stale fork
                if (item.transition.tx_index >= cached_canonical.transactions.size() ||
                    item.transition.marker_vout >=
                        cached_canonical.transactions[item.transition.tx_index].outputs.size() ||
                    item.transition.txid != HashToHex(
                        cached_canonical.transactions[item.transition.tx_index].GetTxID()))
                    throw MintNullifierIndexError(
                        "btcVELD nullifier index locator is corrupt");
                const auto& t = item.transition;
                if (!ValidateTransition_(t) || t.old_root != running_root)
                    throw MintNullifierIndexError(
                        "btcVELD nullifier/effect transition is non-canonical");

                const bool insertion = IsInsertionKind_(t.effect_kind);
                if (insertion) {
                    btcnull::Proof insertion_proof;
                    if (!btcnull::DecodeProof(t.proof, insertion_proof))
                        throw MintNullifierIndexError(
                            "btcVELD nullifier transition proof is corrupt");
                    const btcnull::InsertResult inserted = btcnull::Insert(
                        running_root, t.outpoint, insertion_proof);
                    if (!inserted.ok || inserted.new_root != t.new_root)
                        throw MintNullifierIndexError(
                            "btcVELD nullifier transition proof is corrupt");
                    if (!btcnull::UpdateWitnessAfterInsert(
                            running_root, inserted.new_root, target_outpoint,
                            out.consumed, out.proof, t.outpoint,
                            insertion_proof))
                        throw MintNullifierIndexError(
                            "btcVELD nullifier target-witness update failed");
                    if (t.effect_kind == "C1_FUND") {
                        if (!funded_by_outpoint.emplace(
                                t.outpoint, t.c1_allocation_id).second ||
                            !outpoint_by_allocation.emplace(
                                t.c1_allocation_id, t.outpoint).second)
                            throw MintNullifierIndexError(
                                "duplicate unresolved C1 funding effect");
                    } else if (funded_by_outpoint.count(t.outpoint) != 0) {
                        throw MintNullifierIndexError(
                            "direct mint overlaps a funded C1 allocation");
                    }
                    if (t.outpoint == target_outpoint) {
                        if (!out.consumer_txid.empty())
                            throw MintNullifierIndexError(
                                "btcVELD nullifier target inserted twice");
                        out.consumer_txid = t.txid;
                        out.consumer_block_height = item.height;
                        out.consumer_block_hash = item.block_hash;
                        out.consumer_tx_index = t.tx_index;
                        out.consumer_marker_vout = t.marker_vout;
                        if (t.effect_kind == "MINT") {
                            out.minted = true;
                            out.credit_txid = t.txid;
                            out.credit_block_height = item.height;
                            out.credit_block_hash = item.block_hash;
                            out.credit_tx_index = t.tx_index;
                            out.credit_marker_vout = t.marker_vout;
                        }
                        out.accepted_txid = t.txid;
                        out.accepted_block_height = item.height;
                        out.accepted_block_hash = item.block_hash;
                        out.accepted_tx_index = t.tx_index;
                        out.accepted_marker_vout = t.marker_vout;
                        out.accepted_effect_kind = t.effect_kind;
                        out.c1_allocation_id = t.c1_allocation_id;
                    }
                    running_root = inserted.new_root;
                    if (running_count == UINT64_MAX)
                        throw MintNullifierIndexError(
                            "btcVELD nullifier transition count overflow");
                    ++running_count;
                } else {
                    const auto funded = funded_by_outpoint.find(t.outpoint);
                    const auto allocation =
                        outpoint_by_allocation.find(t.c1_allocation_id);
                    if (funded == funded_by_outpoint.end() ||
                        funded->second != t.c1_allocation_id ||
                        allocation == outpoint_by_allocation.end() ||
                        allocation->second != t.outpoint)
                        throw MintNullifierIndexError(
                            "C1 mint has no exact preceding funding effect");
                    funded_by_outpoint.erase(funded);
                    outpoint_by_allocation.erase(t.c1_allocation_id);
                    if (t.outpoint == target_outpoint) {
                        if (!out.consumed || out.minted ||
                            out.accepted_effect_kind != "C1_FUND" ||
                            out.c1_allocation_id != t.c1_allocation_id)
                            throw MintNullifierIndexError(
                                "C1 target credit does not follow its funding effect");
                        out.minted = true;
                        out.credit_txid = t.txid;
                        out.credit_block_height = item.height;
                        out.credit_block_hash = item.block_hash;
                        out.credit_tx_index = t.tx_index;
                        out.credit_marker_vout = t.marker_vout;
                        out.accepted_txid = t.txid;
                        out.accepted_block_height = item.height;
                        out.accepted_block_hash = item.block_hash;
                        out.accepted_tx_index = t.tx_index;
                        out.accepted_marker_vout = t.marker_vout;
                        out.accepted_effect_kind = t.effect_kind;
                        out.c1_allocation_id = t.c1_allocation_id;
                    }
                }
                if (running_effect_count == UINT64_MAX)
                    throw MintNullifierIndexError(
                        "btcVELD mint-effect transition count overflow");
                try {
                    running_effect_root = ExtendBtcVeldMintEffectCommitment(
                        running_effect_root, item.height, t);
                } catch (const std::exception&) {
                    throw MintNullifierIndexError(
                        "btcVELD mint-effect transition is non-canonical");
                }
                ++running_effect_count;
                return true;
              });
        } catch (const MintNullifierIndexError&) {
            if (!tip_still_matches())
                throw MintNullifierTipRace(
                    "btcVELD nullifier canonical tip changed during proof rebuild");
            throw;
        } catch (const std::exception& e) {
            if (!tip_still_matches())
                throw MintNullifierTipRace(
                    "btcVELD nullifier canonical tip changed during proof rebuild");
            throw MintNullifierIndexError(
                std::string("btcVELD nullifier-index scan failed: ") + e.what());
        }

        if (!tip_still_matches())
            throw MintNullifierTipRace(
                "btcVELD nullifier canonical tip changed during proof rebuild");

        // A start/end tip equality check alone cannot see A->B->A while the
        // lifetime scan is in progress. Re-read both phase locators from the
        // final canonical view.  This preserves the C1F1 consumer identity even
        // after the later root-neutral MNP2 becomes the latest effect.
        auto recheck_locator = [&](const std::string& txid, uint64_t height,
                                   const Hash256& block_hash,
                                   uint32_t tx_index,
                                   uint32_t marker_vout) {
            if (txid.empty()) return;
            Block final_carrier;
            try {
                final_carrier = chain.GetBlock(height);
            } catch (const std::exception&) {
                throw MintNullifierTipRace(
                    "btcVELD mint-effect canonical carrier changed during proof rebuild");
            }
            if (!tip_still_matches() ||
                final_carrier.GetHash() != block_hash ||
                tx_index >= final_carrier.transactions.size() ||
                marker_vout >= final_carrier.transactions[
                    tx_index].outputs.size() ||
                HashToHex(final_carrier.transactions[
                    tx_index].GetTxID()) != txid)
                throw MintNullifierTipRace(
                    "btcVELD mint-effect canonical carrier changed during proof rebuild");
        };
        recheck_locator(out.consumer_txid, out.consumer_block_height,
                        out.consumer_block_hash, out.consumer_tx_index,
                        out.consumer_marker_vout);
        if (out.credit_txid != out.consumer_txid)
            recheck_locator(out.credit_txid, out.credit_block_height,
                            out.credit_block_hash, out.credit_tx_index,
                            out.credit_marker_vout);

        if (running_count != expected.count || running_root != expected.root ||
            running_effect_count != expected.effect_count ||
            running_effect_root != expected.effect_root ||
            !btcnull::Verify(running_root, target_outpoint, out.consumed,
                             out.proof) ||
            out.consumed != !out.consumer_txid.empty() ||
            out.minted != !out.credit_txid.empty() ||
            out.consumed != !out.accepted_txid.empty() ||
            (out.consumed && out.accepted_effect_kind.empty()))
            throw MintNullifierIndexError(
                "btcVELD nullifier/effect index incomplete; restart/replay required");
        out.root = running_root;
        out.count = running_count;
        return out;
    }

private:
    struct Item {
        uint64_t height = 0;
        Hash256 block_hash{};
        BtcVeldMintTransition transition;
    };

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

    static bool IsInsertionKind_(const std::string& kind) noexcept {
        return kind == "MINT" || kind == "C1_FUND";
    }

    static bool ValidateTransition_(
            const BtcVeldMintTransition& transition) noexcept {
        try {
            if (!db::IsCanonicalHash256Text(transition.txid) ||
                !IsValidBtcOutpointId(transition.outpoint))
                return false;
            const bool insertion = IsInsertionKind_(transition.effect_kind);
            const bool c1_mint = transition.effect_kind == "C1_MINT";
            if (!insertion && !c1_mint) return false;
            if ((transition.effect_kind == "MINT" &&
                 !transition.c1_allocation_id.empty()) ||
                ((transition.effect_kind == "C1_FUND" || c1_mint) &&
                 !c1reserve::IsAllocationId(
                     transition.c1_allocation_id)))
                return false;
            if (c1_mint)
                return transition.proof.empty() &&
                       transition.old_root == transition.new_root;
            if (transition.proof.empty() ||
                transition.proof.size() > btcnull::MAX_PROOF_BYTES ||
                transition.old_root == transition.new_root)
                return false;
            btcnull::Proof proof;
            if (!btcnull::DecodeProof(transition.proof, proof)) return false;
            const btcnull::InsertResult inserted = btcnull::Insert(
                transition.old_root, transition.outpoint, proof);
            return inserted.ok &&
                   inserted.new_root == transition.new_root;
        } catch (...) {
            return false;
        }
    }

    static bool ValidateDecodedItem_(const Item& item) noexcept {
        return ValidateTransition_(item.transition);
    }

    static std::string Key(uint64_t height, uint32_t tx_index,
                           uint32_t marker_vout,
                           const std::string& block_hash_hex) {
        std::ostringstream out;
        out << PREFIX << std::setw(20) << std::setfill('0') << height
            << ':' << std::setw(10) << std::setfill('0') << tx_index
            << ':' << std::setw(10) << std::setfill('0') << marker_vout
            << ':' << block_hash_hex;
        return out.str();
    }

    static void PutU32(std::string& out, uint32_t v) {
        for (int i = 0; i < 4; ++i)
            out.push_back(static_cast<char>((v >> (8 * i)) & 0xff));
    }
    static void PutU64(std::string& out, uint64_t v) {
        for (int i = 0; i < 8; ++i)
            out.push_back(static_cast<char>((v >> (8 * i)) & 0xff));
    }
    static void PutString(std::string& out, const std::string& s) {
        if (s.size() > UINT32_MAX)
            throw std::length_error("btcVELD nullifier-index field too large");
        PutU32(out, static_cast<uint32_t>(s.size()));
        out.append(s);
    }
    static bool GetU32(const std::string& in, size_t& pos, uint32_t& v) {
        if (pos + 4 > in.size()) return false;
        v = 0;
        for (int i = 0; i < 4; ++i)
            v |= static_cast<uint32_t>(static_cast<uint8_t>(in[pos++]))
                 << (8 * i);
        return true;
    }
    static bool GetU64(const std::string& in, size_t& pos, uint64_t& v) {
        if (pos + 8 > in.size()) return false;
        v = 0;
        for (int i = 0; i < 8; ++i)
            v |= static_cast<uint64_t>(static_cast<uint8_t>(in[pos++]))
                 << (8 * i);
        return true;
    }
    static bool GetString(const std::string& in, size_t& pos,
                          std::string& out, size_t max) {
        uint32_t n = 0;
        if (!GetU32(in, pos, n) || n > max || pos + n > in.size())
            return false;
        out.assign(in.data() + pos, n);
        pos += n;
        return true;
    }

    static std::string Encode(uint64_t height, const Hash256& block_hash,
                              const BtcVeldMintTransition& t) {
        std::string out;
        out.reserve(1 + 8 + 32 + 4 + 4 + 4 + t.txid.size() +
                    t.outpoint.size() + t.effect_kind.size() +
                    t.c1_allocation_id.size() + t.proof.size() + 64);
        out.push_back(static_cast<char>(2));
        PutU64(out, height);
        out.append(reinterpret_cast<const char*>(block_hash.data()),
                   block_hash.size());
        PutU32(out, t.tx_index);
        PutU32(out, t.marker_vout);
        PutString(out, t.txid);
        PutString(out, t.outpoint);
        PutString(out, t.effect_kind);
        PutString(out, t.c1_allocation_id);
        PutU32(out, static_cast<uint32_t>(t.proof.size()));
        out.append(reinterpret_cast<const char*>(t.proof.data()),
                   t.proof.size());
        out.append(reinterpret_cast<const char*>(t.old_root.data()),
                   t.old_root.size());
        out.append(reinterpret_cast<const char*>(t.new_root.data()),
                   t.new_root.size());
        return out;
    }

    static bool Decode(const std::string& in, Item& item) {
        item = Item{};
        size_t pos = 0;
        if (in.empty() || static_cast<uint8_t>(in[pos++]) != 2 ||
            !GetU64(in, pos, item.height) ||
            pos + item.block_hash.size() > in.size())
            return false;
        std::copy_n(reinterpret_cast<const uint8_t*>(in.data()) + pos,
                    item.block_hash.size(), item.block_hash.begin());
        pos += item.block_hash.size();
        if (!GetU32(in, pos, item.transition.tx_index) ||
            !GetU32(in, pos, item.transition.marker_vout) ||
            !GetString(in, pos, item.transition.txid, 64) ||
            !GetString(in, pos, item.transition.outpoint, 80) ||
            !GetString(in, pos, item.transition.effect_kind, 16) ||
            !GetString(in, pos, item.transition.c1_allocation_id, 32))
            return false;
        uint32_t proof_len = 0;
        if (!GetU32(in, pos, proof_len) ||
            proof_len > btcnull::MAX_PROOF_BYTES ||
            pos + proof_len + 64 != in.size())
            return false;
        item.transition.proof.assign(
            reinterpret_cast<const uint8_t*>(in.data()) + pos,
            reinterpret_cast<const uint8_t*>(in.data()) + pos + proof_len);
        pos += proof_len;
        std::copy_n(reinterpret_cast<const uint8_t*>(in.data()) + pos, 32,
                    item.transition.old_root.begin());
        pos += 32;
        std::copy_n(reinterpret_cast<const uint8_t*>(in.data()) + pos, 32,
                    item.transition.new_root.begin());
        pos += 32;
        return pos == in.size() && ValidateDecodedItem_(item);
    }
};

} // namespace veld
