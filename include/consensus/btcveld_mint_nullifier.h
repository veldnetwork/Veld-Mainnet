#pragma once

// btcveld_mint_nullifier.h -- stateless, exact btcVELD mint replay protection.
//
// Every issuer and MSPV mint consumes one Bitcoin outpoint forever.  Retaining
// those outpoints in a process-resident std::set makes consensus RAM, snapshots,
// and state-digest work grow with lifetime mint volume.  This module replaces
// that set with a fixed-depth sparse-Merkle set commitment.  Consensus retains
// only (root,count); each mint carries a canonical non-membership witness which
// deterministically advances the root.  The representation has:
//
//   * exact membership (no probabilistic false positives),
//   * 256-bit collision/preimage security,
//   * constant consensus memory and snapshot size,
//   * a hard 8,224-byte proof bound, and
//   * compressed normal proofs (32-byte bitmap plus non-default siblings).
//
// Proof producers are derived infrastructure, not consensus authorities. A
// node can rebuild them from canonical mint transitions, and every returned
// witness is independently checked against the consensus root.

#include "state_digest.h"
#include "../core/hash.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace veld::btcnull {

#if defined(VELD_PUBLIC_RELEASE) || defined(VELD_TEST_BTC_CUSTODY_LINEAGE)
inline constexpr bool CUSTODY_LINEAGE_REQUIRED = true;
#else
inline constexpr bool CUSTODY_LINEAGE_REQUIRED = false;
#endif

inline constexpr size_t TREE_DEPTH = 256;
inline constexpr size_t BITMAP_BYTES = TREE_DEPTH / 8;
inline constexpr size_t HASH_BYTES = 32;
inline constexpr size_t MIN_PROOF_BYTES = BITMAP_BYTES;
inline constexpr size_t MAX_PROOF_BYTES = BITMAP_BYTES + TREE_DEPTH * HASH_BYTES;
inline constexpr size_t MAX_MSPV_MERKLE_BRANCH_HASHES = 32;
inline constexpr size_t MAX_MSPV_STRIPPED_TX_BYTES = 12'000;
inline constexpr size_t MAX_MSPV_PARENT_TX_BYTES = 12'000;
inline constexpr size_t MAX_MSPV_PARENT_TOTAL_BYTES = 10'000;
inline constexpr size_t MAX_MSPV_PARENT_COUNT = 128;
// "MSP3" + block hash + directions + branch length/max branch + tx length +
// stripped transaction + one hash-bound parent transaction per input + sparse
// proof, then lowercase hex plus VELD_MSPV|.
inline constexpr size_t MAX_MSPV_BINARY_PROOF_BYTES =
    4 + 32 + 4 + 1 + MAX_MSPV_MERKLE_BRANCH_HASHES * 32 + 4 + MAX_MSPV_STRIPPED_TX_BYTES + 2 +
    MAX_MSPV_PARENT_COUNT * 4 + MAX_MSPV_PARENT_TOTAL_BYTES + MAX_PROOF_BYTES;
inline constexpr size_t MAX_MSPV_OP_PAYLOAD_BYTES =
    sizeof("VELD_MSPV|") - 1 + 2 * MAX_MSPV_BINARY_PROOF_BYTES;
static_assert(MAX_MSPV_OP_PAYLOAD_BYTES < 65'535,
              "MSP3 carrier must fit the canonical OP_RETURN envelope");

inline constexpr const char* KEY_DOMAIN = "VELD_BTCVELD_MINT_NULLIFIER_KEY_v1|";
inline constexpr const char* EMPTY_LEAF_DOMAIN = "VELD_BTCVELD_MINT_NULLIFIER_EMPTY_LEAF_v1|";
inline constexpr const char* OCCUPIED_LEAF_DOMAIN = "VELD_BTCVELD_MINT_NULLIFIER_OCCUPIED_LEAF_v1|";
inline constexpr const char* NODE_DOMAIN = "VELD_BTCVELD_MINT_NULLIFIER_NODE_v1|";
inline constexpr const char* ISSUER_MEMO_PREFIX = "MNP1;";
inline constexpr const char* RESERVED_ISSUER_MEMO_PREFIX = "MNP2;";

struct Proof {
    std::array<uint8_t, BITMAP_BYTES> bitmap{};
    // Ascending tree depth (root=0 .. leaf-parent=255), for set bitmap bits.
    std::vector<Hash256> siblings;
};

inline bool Bit(const Hash256& key, size_t depth) {
    return ((key[depth / 8] >> (7u - (depth % 8))) & 1u) != 0;
}

inline bool BitmapBit(const std::array<uint8_t, BITMAP_BYTES>& bitmap, size_t depth) {
    return ((bitmap[depth / 8] >> (7u - (depth % 8))) & 1u) != 0;
}

inline void SetBitmapBit(std::array<uint8_t, BITMAP_BYTES>& bitmap, size_t depth, bool value) {
    const uint8_t mask = static_cast<uint8_t>(1u << (7u - (depth % 8)));
    if (value)
        bitmap[depth / 8] |= mask;
    else
        bitmap[depth / 8] &= static_cast<uint8_t>(~mask);
}

inline size_t BitmapPopcount(const std::array<uint8_t, BITMAP_BYTES>& bitmap) {
    size_t n = 0;
    for (uint8_t b : bitmap) {
        for (; b != 0; b &= static_cast<uint8_t>(b - 1))
            ++n;
    }
    return n;
}

inline Hash256 KeyForOutpoint(const std::string& canonical_outpoint) {
    std::vector<uint8_t> body;
    state_digest::put_len_prefixed(body, canonical_outpoint);
    return state_digest::sha256_domain(KEY_DOMAIN, body);
}

inline Hash256 EmptyLeaf() {
    return state_digest::sha256_domain(EMPTY_LEAF_DOMAIN, {});
}

inline Hash256 OccupiedLeaf(const Hash256& key) {
    std::vector<uint8_t> body;
    state_digest::put_bytes(body, key.data(), key.size());
    return state_digest::sha256_domain(OCCUPIED_LEAF_DOMAIN, body);
}

inline Hash256 Node(const Hash256& left, const Hash256& right) {
    std::vector<uint8_t> body;
    body.reserve(left.size() + right.size());
    state_digest::put_bytes(body, left.data(), left.size());
    state_digest::put_bytes(body, right.data(), right.size());
    return state_digest::sha256_domain(NODE_DOMAIN, body);
}

// empty[d] is the root of an entirely empty subtree whose root is at depth d.
// empty[256] is the empty leaf; empty[0] is the empty-set commitment.
inline const std::array<Hash256, TREE_DEPTH + 1>& EmptyHashes() {
    static const std::array<Hash256, TREE_DEPTH + 1> hashes = [] {
        std::array<Hash256, TREE_DEPTH + 1> out{};
        out[TREE_DEPTH] = EmptyLeaf();
        for (size_t d = TREE_DEPTH; d-- > 0;)
            out[d] = Node(out[d + 1], out[d + 1]);
        return out;
    }();
    return hashes;
}

inline Hash256 EmptyRoot() {
    return EmptyHashes()[0];
}

inline bool DecodeProof(const uint8_t* data, size_t len, Proof& out) {
    out = Proof{};
    if (data == nullptr || len < MIN_PROOF_BYTES || len > MAX_PROOF_BYTES ||
        ((len - BITMAP_BYTES) % HASH_BYTES) != 0)
        return false;
    for (size_t i = 0; i < BITMAP_BYTES; ++i)
        out.bitmap[i] = data[i];
    const size_t count = BitmapPopcount(out.bitmap);
    if (len != BITMAP_BYTES + count * HASH_BYTES)
        return false;
    out.siblings.reserve(count);
    size_t off = BITMAP_BYTES;
    size_t sibling_index = 0;
    const auto& empty = EmptyHashes();
    for (size_t depth = 0; depth < TREE_DEPTH; ++depth) {
        if (!BitmapBit(out.bitmap, depth))
            continue;
        Hash256 sibling{};
        for (size_t j = 0; j < HASH_BYTES; ++j)
            sibling[j] = data[off++];
        // A default sibling MUST be omitted.  Rejecting an explicitly encoded
        // default gives every mathematical proof exactly one wire encoding.
        if (sibling == empty[depth + 1])
            return false;
        out.siblings.push_back(sibling);
        ++sibling_index;
    }
    return off == len && sibling_index == count;
}

inline bool DecodeProof(const std::vector<uint8_t>& bytes, Proof& out) {
    return DecodeProof(bytes.data(), bytes.size(), out);
}

inline bool IsCanonicalProof(const Proof& proof) {
    if (proof.siblings.size() != BitmapPopcount(proof.bitmap))
        return false;
    const auto& empty = EmptyHashes();
    size_t i = 0;
    for (size_t depth = 0; depth < TREE_DEPTH; ++depth) {
        if (!BitmapBit(proof.bitmap, depth))
            continue;
        if (i >= proof.siblings.size() || proof.siblings[i] == empty[depth + 1])
            return false;
        ++i;
    }
    return i == proof.siblings.size();
}

inline std::vector<uint8_t> EncodeProof(const Proof& proof) {
    if (!IsCanonicalProof(proof))
        return {};
    std::vector<uint8_t> out;
    out.reserve(BITMAP_BYTES + proof.siblings.size() * HASH_BYTES);
    out.insert(out.end(), proof.bitmap.begin(), proof.bitmap.end());
    for (const auto& sibling : proof.siblings)
        out.insert(out.end(), sibling.begin(), sibling.end());
    return out;
}

inline Proof EmptyProof() {
    return Proof{};
}

inline bool ExpandSiblings(const Proof& proof, std::array<Hash256, TREE_DEPTH>& out) {
    if (!IsCanonicalProof(proof))
        return false;
    const auto& empty = EmptyHashes();
    size_t i = 0;
    for (size_t depth = 0; depth < TREE_DEPTH; ++depth) {
        if (BitmapBit(proof.bitmap, depth))
            out[depth] = proof.siblings[i++];
        else
            out[depth] = empty[depth + 1];
    }
    return i == proof.siblings.size();
}

inline Proof CompressSiblings(const std::array<Hash256, TREE_DEPTH>& siblings) {
    Proof out;
    const auto& empty = EmptyHashes();
    for (size_t depth = 0; depth < TREE_DEPTH; ++depth) {
        if (siblings[depth] == empty[depth + 1])
            continue;
        SetBitmapBit(out.bitmap, depth, true);
        out.siblings.push_back(siblings[depth]);
    }
    return out;
}

// Computes every subtree hash on key's path. path[256] is the leaf and
// path[d] is the root of the subtree beginning at depth d.
inline bool ComputePath(const Hash256& key, bool occupied, const Proof& proof,
                        std::array<Hash256, TREE_DEPTH + 1>& path) {
    std::array<Hash256, TREE_DEPTH> siblings{};
    if (!ExpandSiblings(proof, siblings))
        return false;
    path[TREE_DEPTH] = occupied ? OccupiedLeaf(key) : EmptyLeaf();
    for (size_t depth = TREE_DEPTH; depth-- > 0;) {
        path[depth] = Bit(key, depth) ? Node(siblings[depth], path[depth + 1])
                                      : Node(path[depth + 1], siblings[depth]);
    }
    return true;
}

inline bool Verify(const Hash256& root, const std::string& canonical_outpoint, bool occupied,
                   const Proof& proof) {
    std::array<Hash256, TREE_DEPTH + 1> path{};
    return ComputePath(KeyForOutpoint(canonical_outpoint), occupied, proof, path) &&
           path[0] == root;
}

struct InsertResult {
    bool ok = false;
    Hash256 old_root{};
    Hash256 new_root{};
};

inline InsertResult Insert(const Hash256& current_root, const std::string& canonical_outpoint,
                           const Proof& nonmembership_proof) {
    InsertResult out;
    out.old_root = current_root;
    const Hash256 key = KeyForOutpoint(canonical_outpoint);
    std::array<Hash256, TREE_DEPTH + 1> old_path{};
    if (!ComputePath(key, false, nonmembership_proof, old_path) || old_path[0] != current_root)
        return out;
    std::array<Hash256, TREE_DEPTH + 1> new_path{};
    if (!ComputePath(key, true, nonmembership_proof, new_path))
        return out;
    out.ok = true;
    out.new_root = new_path[0];
    return out;
}

// Advance a witness for any target through one independently verified
// insertion.  This is what lets a bounded-memory proof rebuilder scan the
// canonical transition stream without holding the lifetime key set.
inline bool UpdateWitnessAfterInsert(const Hash256& old_root, const Hash256& new_root,
                                     const std::string& target_outpoint, bool& target_occupied,
                                     Proof& target_proof, const std::string& inserted_outpoint,
                                     const Proof& insertion_nonmembership_proof) {
    const InsertResult transition =
        Insert(old_root, inserted_outpoint, insertion_nonmembership_proof);
    if (!transition.ok || transition.new_root != new_root ||
        !Verify(old_root, target_outpoint, target_occupied, target_proof))
        return false;

    const Hash256 target_key = KeyForOutpoint(target_outpoint);
    const Hash256 inserted_key = KeyForOutpoint(inserted_outpoint);
    if (target_key == inserted_key) {
        if (target_occupied)
            return false; // stream attempted a duplicate insert
        target_occupied = true;
        target_proof = insertion_nonmembership_proof;
        return Verify(new_root, target_outpoint, true, target_proof);
    }

    size_t divergence = 0;
    while (divergence < TREE_DEPTH && Bit(target_key, divergence) == Bit(inserted_key, divergence))
        ++divergence;
    if (divergence == TREE_DEPTH)
        return false; // SHA-256 key collision

    std::array<Hash256, TREE_DEPTH> target_siblings{};
    if (!ExpandSiblings(target_proof, target_siblings))
        return false;
    std::array<Hash256, TREE_DEPTH + 1> inserted_new_path{};
    if (!ComputePath(inserted_key, true, insertion_nonmembership_proof, inserted_new_path))
        return false;
    target_siblings[divergence] = inserted_new_path[divergence + 1];
    target_proof = CompressSiblings(target_siblings);
    return Verify(new_root, target_outpoint, target_occupied, target_proof);
}

inline std::string EncodeIssuerMemo(const std::string& canonical_outpoint, const Proof& proof) {
    const std::vector<uint8_t> bytes = EncodeProof(proof);
    if (bytes.empty())
        return {};
    return std::string(ISSUER_MEMO_PREFIX) + canonical_outpoint + ";" + BytesToHex(bytes);
}

// A reserved issuer mint carries the exact C1 allocation id and opens
// its undisclosed P2TR script commitment. Keeping MNP1 as the unreserved form
// preserves the ordinary operator issuer path; consensus charges that path
// against only unreserved headroom. MNP2 is the sole form that may consume a
// funded C1 lease. C1F1 already atomically inserted the exact outpoint into the
// shared nullifier accumulator, so MNP2 is deliberately root/proof independent.
inline std::string EncodeReservedIssuerMemo(const std::string& request_id,
                                            const std::string& script_pubkey_hex,
                                            const std::string& commitment_blind_hex,
                                            const std::string& canonical_outpoint) {
    auto lowercase_hex = [](const std::string& value, size_t size) {
        if (value.size() != size)
            return false;
        for (char c : value)
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                return false;
        return true;
    };
    if (!lowercase_hex(request_id, 32) || request_id.compare(0, 16, "0000000000000000") != 0 ||
        request_id == std::string(32, '0') || script_pubkey_hex.rfind("5120", 0) != 0 ||
        !lowercase_hex(script_pubkey_hex, 68) || !lowercase_hex(commitment_blind_hex, 64))
        return {};
    return std::string(RESERVED_ISSUER_MEMO_PREFIX) + request_id + ";" + script_pubkey_hex + ";" +
           commitment_blind_hex + ";" + canonical_outpoint;
}

inline bool ParseIssuerMemo(const std::string& memo, std::string& canonical_outpoint,
                            Proof& proof) {
    canonical_outpoint.clear();
    proof = Proof{};
    const std::string prefix = ISSUER_MEMO_PREFIX;
    if (memo.rfind(prefix, 0) != 0)
        return false;
    const size_t split = memo.find(';', prefix.size());
    if (split == std::string::npos || split == prefix.size() || split + 1 >= memo.size())
        return false;
    canonical_outpoint = memo.substr(prefix.size(), split - prefix.size());
    const std::string hex = memo.substr(split + 1);
    if (hex.size() < MIN_PROOF_BYTES * 2 || hex.size() > MAX_PROOF_BYTES * 2 ||
        (hex.size() & 1u) != 0)
        return false;
    // Consensus has one textual encoding too: lowercase hex only.
    for (char c : hex)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    const std::vector<uint8_t> bytes = HexToBytes(hex);
    return !bytes.empty() && DecodeProof(bytes, proof) &&
           EncodeIssuerMemo(canonical_outpoint, proof) == memo;
}

inline bool ParseIssuerMemo(const std::string& memo, std::string& canonical_outpoint, Proof& proof,
                            std::string& reservation_request_id,
                            std::string& reservation_script_pubkey_hex,
                            std::string& reservation_commitment_blind_hex) {
    reservation_request_id.clear();
    reservation_script_pubkey_hex.clear();
    reservation_commitment_blind_hex.clear();
    if (memo.rfind(ISSUER_MEMO_PREFIX, 0) == 0)
        return ParseIssuerMemo(memo, canonical_outpoint, proof);
    canonical_outpoint.clear();
    proof = Proof{};
    const std::string prefix = RESERVED_ISSUER_MEMO_PREFIX;
    if (memo.rfind(prefix, 0) != 0)
        return false;
    const size_t request_split = memo.find(';', prefix.size());
    if (request_split == std::string::npos)
        return false;
    reservation_request_id = memo.substr(prefix.size(), request_split - prefix.size());
    if (reservation_request_id.size() != 32)
        return false;
    for (char c : reservation_request_id)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    if (reservation_request_id.compare(0, 16, "0000000000000000") != 0 ||
        reservation_request_id == std::string(32, '0'))
        return false;
    const size_t script_split = memo.find(';', request_split + 1);
    if (script_split == std::string::npos || script_split == request_split + 1)
        return false;
    reservation_script_pubkey_hex =
        memo.substr(request_split + 1, script_split - request_split - 1);
    if (reservation_script_pubkey_hex.size() != 68 ||
        reservation_script_pubkey_hex.rfind("5120", 0) != 0)
        return false;
    for (char c : reservation_script_pubkey_hex)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    const size_t blind_split = memo.find(';', script_split + 1);
    if (blind_split == std::string::npos || blind_split == script_split + 1)
        return false;
    reservation_commitment_blind_hex =
        memo.substr(script_split + 1, blind_split - script_split - 1);
    if (reservation_commitment_blind_hex.size() != 64)
        return false;
    for (char c : reservation_commitment_blind_hex)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    if (memo.find(';', blind_split + 1) != std::string::npos)
        return false;
    canonical_outpoint = memo.substr(blind_split + 1);
    return EncodeReservedIssuerMemo(reservation_request_id, reservation_script_pubkey_hex,
                                    reservation_commitment_blind_hex, canonical_outpoint) == memo;
}

// Callers interested only in nullifier replay identity may deliberately ignore
// the MNP2 opening. Consensus acceptance uses the five-output overload above.
inline bool ParseIssuerMemo(const std::string& memo, std::string& canonical_outpoint, Proof& proof,
                            std::string& reservation_request_id) {
    std::string ignored_script_pubkey_hex;
    std::string ignored_commitment_blind_hex;
    return ParseIssuerMemo(memo, canonical_outpoint, proof, reservation_request_id,
                           ignored_script_pubkey_hex, ignored_commitment_blind_hex);
}

} // namespace veld::btcnull
