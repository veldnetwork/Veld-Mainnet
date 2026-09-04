#pragma once
// Canonical consensus-state digest (v1).
//
// The exact byte-level definition is versioned and must not change without
// bumping the spec version and re-baselining every prior comparison.
//
// Structure:
//   ConsensusStateDigest(H) = SHA256(
//       "VELD_STATE_DIGEST_v1|"
//       || u64le(H) || best_block_hash_32
//       || D_utxo || D_validators || D_staking
//       || D_bondyield || D_nmstally || D_tokens
//   )
//
// Each D_* is itself a SHA256 over the named container serialised in
// canonical key order; unordered iteration must never reach the hash. Per-class
// no unordered iteration may reach the hash). Per-class digest
// methods (Blockchain::UtxoDigest, ValidatorRegistry::ValidatorsDigest,
// …) live in their respective consensus headers and use the helpers
// in this file.
//
// Read-only by construction — no class state is mutated by any digest
// method; safe to call from any context including const refs and
// concurrent readers (each class's existing mutex_ guards the read).

#include "../core/hash.h"
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace veld {
namespace state_digest {

inline void put_u8(std::vector<uint8_t>& buf, uint8_t v) {
    buf.push_back(v);
}

inline void put_u32_le(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back((uint8_t)(v & 0xFF));
    buf.push_back((uint8_t)((v >> 8) & 0xFF));
    buf.push_back((uint8_t)((v >> 16) & 0xFF));
    buf.push_back((uint8_t)((v >> 24) & 0xFF));
}

inline void put_u64_le(std::vector<uint8_t>& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        buf.push_back((uint8_t)((v >> (i * 8)) & 0xFF));
}

inline void put_bytes(std::vector<uint8_t>& buf, const uint8_t* p, size_t n) {
    if (n)
        buf.insert(buf.end(), p, p + n);
}

inline void put_bytes(std::vector<uint8_t>& buf, const std::vector<uint8_t>& v) {
    put_bytes(buf, v.data(), v.size());
}

inline void put_len_prefixed(std::vector<uint8_t>& buf, const uint8_t* p, size_t n) {
    put_u32_le(buf, (uint32_t)n);
    put_bytes(buf, p, n);
}

inline void put_len_prefixed(std::vector<uint8_t>& buf, const std::vector<uint8_t>& v) {
    put_len_prefixed(buf, v.data(), v.size());
}

inline void put_len_prefixed(std::vector<uint8_t>& buf, const std::string& s) {
    put_len_prefixed(buf, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

inline void put_double_bits_le(std::vector<uint8_t>& buf, double v) {
    static_assert(sizeof(double) == 8, "double must be 8 bytes for spec v1");
    uint64_t u = 0;
    std::memcpy(&u, &v, 8);
    put_u64_le(buf, u);
}

inline Hash256 sha256_of(const std::vector<uint8_t>& buf) {
    SHA256 h;
    h.update(buf.data(), buf.size());
    return h.digest();
}

inline Hash256 sha256_domain(const char* tag, const std::vector<uint8_t>& body) {
    std::vector<uint8_t> buf;
    buf.reserve(strlen(tag) + body.size());
    put_bytes(buf, reinterpret_cast<const uint8_t*>(tag), strlen(tag));
    put_bytes(buf, body);
    return sha256_of(buf);
}

// Empty-container digest. Per spec v1: "Empty container ⇒ its `D_* =
// SHA256("")`-domain-tagged constant (NOT skipped — absence must be
// distinguishable and stable)." Returned by per-class Digest() methods when
// the container has zero entries.
inline Hash256 empty_container_digest(const char* tag) {
    return sha256_domain(tag, {});
}

inline Hash256 Compose(uint64_t height, const Hash256& best_block_hash, const Hash256& d_utxo,
                       const Hash256& d_validators, const Hash256& d_staking,
                       const Hash256& d_bondyield, const Hash256& d_nmstally,
                       const Hash256& d_tokens, const Hash256& d_supply,
                       const Hash256& d_governance, const Hash256& d_nms_extended) {
    std::vector<uint8_t> buf;
    static constexpr char DOMAIN[] = "VELD_STATE_DIGEST_v2|";
    put_bytes(buf, reinterpret_cast<const uint8_t*>(DOMAIN), sizeof(DOMAIN) - 1);
    put_u64_le(buf, height);
    put_bytes(buf, best_block_hash.data(), best_block_hash.size());
    put_bytes(buf, d_utxo.data(), d_utxo.size());
    put_bytes(buf, d_validators.data(), d_validators.size());
    put_bytes(buf, d_staking.data(), d_staking.size());
    put_bytes(buf, d_bondyield.data(), d_bondyield.size());
    put_bytes(buf, d_nmstally.data(), d_nmstally.size());
    put_bytes(buf, d_tokens.data(), d_tokens.size());
    put_bytes(buf, d_supply.data(), d_supply.size());
    put_bytes(buf, d_governance.data(), d_governance.size());
    put_bytes(buf, d_nms_extended.data(), d_nms_extended.size());
    return sha256_of(buf);
}

inline Hash256 ComposeV1(uint64_t height, const Hash256& best_block_hash, const Hash256& d_utxo,
                         const Hash256& d_validators, const Hash256& d_staking,
                         const Hash256& d_bondyield, const Hash256& d_nmstally,
                         const Hash256& d_tokens) {
    std::vector<uint8_t> buf;
    static constexpr char DOMAIN[] = "VELD_STATE_DIGEST_v1|";
    put_bytes(buf, reinterpret_cast<const uint8_t*>(DOMAIN), sizeof(DOMAIN) - 1);
    put_u64_le(buf, height);
    put_bytes(buf, best_block_hash.data(), best_block_hash.size());
    put_bytes(buf, d_utxo.data(), d_utxo.size());
    put_bytes(buf, d_validators.data(), d_validators.size());
    put_bytes(buf, d_staking.data(), d_staking.size());
    put_bytes(buf, d_bondyield.data(), d_bondyield.size());
    put_bytes(buf, d_nmstally.data(), d_nmstally.size());
    put_bytes(buf, d_tokens.data(), d_tokens.size());
    return sha256_of(buf);
}

// v3 == v2 (11 components) + D_spv (the btcVELD SPV header-chain view). Used ONLY
// when the SPV relay is ACTIVE (BTCVELD_SPV_ACTIVATION_HEIGHT reached); dormant
// nodes keep computing v1/v2 so their determinism baselines stay byte-identical.
// D_spv = BtcHeaderChain::StateDigest() (v2 commits the selected tip plus every
// canonically sorted retained header/fork record and its validation parameters).
// The sole exact-outpoint mint replay domain is committed by D_tokens, shared by
// issuer and SPV mints. Additive: this does NOT alter ComposeV1/Compose, so no
// existing baseline moves.
inline Hash256 ComposeV3(uint64_t height, const Hash256& best_block_hash, const Hash256& d_utxo,
                         const Hash256& d_validators, const Hash256& d_staking,
                         const Hash256& d_bondyield, const Hash256& d_nmstally,
                         const Hash256& d_tokens, const Hash256& d_supply,
                         const Hash256& d_governance, const Hash256& d_nms_extended,
                         const Hash256& d_spv) {
    std::vector<uint8_t> buf;
    static constexpr char DOMAIN[] = "VELD_STATE_DIGEST_v3|";
    put_bytes(buf, reinterpret_cast<const uint8_t*>(DOMAIN), sizeof(DOMAIN) - 1);
    put_u64_le(buf, height);
    put_bytes(buf, best_block_hash.data(), best_block_hash.size());
    put_bytes(buf, d_utxo.data(), d_utxo.size());
    put_bytes(buf, d_validators.data(), d_validators.size());
    put_bytes(buf, d_staking.data(), d_staking.size());
    put_bytes(buf, d_bondyield.data(), d_bondyield.size());
    put_bytes(buf, d_nmstally.data(), d_nmstally.size());
    put_bytes(buf, d_tokens.data(), d_tokens.size());
    put_bytes(buf, d_supply.data(), d_supply.size());
    put_bytes(buf, d_governance.data(), d_governance.size());
    put_bytes(buf, d_nms_extended.data(), d_nms_extended.size());
    put_bytes(buf, d_spv.data(), d_spv.size());
    return sha256_of(buf);
}

// v4 == v3 (12 components) + D_anchors (the Layer-2 Bitcoin checkpoint anchor set,
// consensus/btcveld_anchor.h::AnchorSet::Digest). Used when state-derived anchoring
// is active after a real finalized record; pre-anchor nodes keep computing v1/v2/v3
// so their determinism baselines stay byte-identical. Additive: does NOT alter any
// prior Compose*, so no existing baseline moves.
inline Hash256 ComposeV4(uint64_t height, const Hash256& best_block_hash, const Hash256& d_utxo,
                         const Hash256& d_validators, const Hash256& d_staking,
                         const Hash256& d_bondyield, const Hash256& d_nmstally,
                         const Hash256& d_tokens, const Hash256& d_supply,
                         const Hash256& d_governance, const Hash256& d_nms_extended,
                         const Hash256& d_spv, const Hash256& d_anchors) {
    std::vector<uint8_t> buf;
    static constexpr char DOMAIN[] = "VELD_STATE_DIGEST_v4|";
    put_bytes(buf, reinterpret_cast<const uint8_t*>(DOMAIN), sizeof(DOMAIN) - 1);
    put_u64_le(buf, height);
    put_bytes(buf, best_block_hash.data(), best_block_hash.size());
    put_bytes(buf, d_utxo.data(), d_utxo.size());
    put_bytes(buf, d_validators.data(), d_validators.size());
    put_bytes(buf, d_staking.data(), d_staking.size());
    put_bytes(buf, d_bondyield.data(), d_bondyield.size());
    put_bytes(buf, d_nmstally.data(), d_nmstally.size());
    put_bytes(buf, d_tokens.data(), d_tokens.size());
    put_bytes(buf, d_supply.data(), d_supply.size());
    put_bytes(buf, d_governance.data(), d_governance.size());
    put_bytes(buf, d_nms_extended.data(), d_nms_extended.size());
    put_bytes(buf, d_spv.data(), d_spv.size());
    put_bytes(buf, d_anchors.data(), d_anchors.size());
    return sha256_of(buf);
}

// v5 == v2 (11 components) + D_amm (the btcVELD AMM pool ledger: pools_, LP
// shares, and each pool's immutable opening-ratio anchor; AmmLedger::Digest).
// Additive: does not alter Compose/ComposeV1..V4. AMM internal state is included
// directly so a divergence in LP shares or the opening anchor is detected before
// it affects the token or UTXO digests through a later operation.
inline Hash256 ComposeV5(uint64_t height, const Hash256& best_block_hash, const Hash256& d_utxo,
                         const Hash256& d_validators, const Hash256& d_staking,
                         const Hash256& d_bondyield, const Hash256& d_nmstally,
                         const Hash256& d_tokens, const Hash256& d_supply,
                         const Hash256& d_governance, const Hash256& d_nms_extended,
                         const Hash256& d_amm) {
    std::vector<uint8_t> buf;
    static constexpr char DOMAIN[] = "VELD_STATE_DIGEST_v5|";
    put_bytes(buf, reinterpret_cast<const uint8_t*>(DOMAIN), sizeof(DOMAIN) - 1);
    put_u64_le(buf, height);
    put_bytes(buf, best_block_hash.data(), best_block_hash.size());
    put_bytes(buf, d_utxo.data(), d_utxo.size());
    put_bytes(buf, d_validators.data(), d_validators.size());
    put_bytes(buf, d_staking.data(), d_staking.size());
    put_bytes(buf, d_bondyield.data(), d_bondyield.size());
    put_bytes(buf, d_nmstally.data(), d_nmstally.size());
    put_bytes(buf, d_tokens.data(), d_tokens.size());
    put_bytes(buf, d_supply.data(), d_supply.size());
    put_bytes(buf, d_governance.data(), d_governance.size());
    put_bytes(buf, d_nms_extended.data(), d_nms_extended.size());
    put_bytes(buf, d_amm.data(), d_amm.size());
    return sha256_of(buf);
}

// v6 is the frozen launch measurement that combined v4's SPV header-chain and
// Bitcoin-anchor commitments plus v5's AMM ledger commitment.  The earlier
// versions remain frozen for historical differential evidence.  Omitting any
// one of these domains could otherwise let two
// equal-height nodes advertise the same top digest while making different
// future consensus decisions.
inline Hash256 ComposeV6(uint64_t height, const Hash256& best_block_hash, const Hash256& d_utxo,
                         const Hash256& d_validators, const Hash256& d_staking,
                         const Hash256& d_bondyield, const Hash256& d_nmstally,
                         const Hash256& d_tokens, const Hash256& d_supply,
                         const Hash256& d_governance, const Hash256& d_nms_extended,
                         const Hash256& d_spv, const Hash256& d_anchors, const Hash256& d_amm) {
    std::vector<uint8_t> buf;
    static constexpr char DOMAIN[] = "VELD_STATE_DIGEST_v6|";
    put_bytes(buf, reinterpret_cast<const uint8_t*>(DOMAIN), sizeof(DOMAIN) - 1);
    put_u64_le(buf, height);
    put_bytes(buf, best_block_hash.data(), best_block_hash.size());
    put_bytes(buf, d_utxo.data(), d_utxo.size());
    put_bytes(buf, d_validators.data(), d_validators.size());
    put_bytes(buf, d_staking.data(), d_staking.size());
    put_bytes(buf, d_bondyield.data(), d_bondyield.size());
    put_bytes(buf, d_nmstally.data(), d_nmstally.size());
    put_bytes(buf, d_tokens.data(), d_tokens.size());
    put_bytes(buf, d_supply.data(), d_supply.size());
    put_bytes(buf, d_governance.data(), d_governance.size());
    put_bytes(buf, d_nms_extended.data(), d_nms_extended.size());
    put_bytes(buf, d_spv.data(), d_spv.size());
    put_bytes(buf, d_anchors.data(), d_anchors.size());
    put_bytes(buf, d_amm.data(), d_amm.size());
    return sha256_of(buf);
}

// v7 == v6 + D_finality + D_redeem_bond.  Both states participate in the
// same atomic module snapshot/replay boundary as the v6 engines and can alter
// future consensus decisions once their compile-time activation gates are
// armed.  They therefore must not be invisible to the operator-facing
// determinism measurement.  Prior Compose* layouts remain frozen.
inline Hash256 ComposeV7(uint64_t height, const Hash256& best_block_hash, const Hash256& d_utxo,
                         const Hash256& d_validators, const Hash256& d_staking,
                         const Hash256& d_bondyield, const Hash256& d_nmstally,
                         const Hash256& d_tokens, const Hash256& d_supply,
                         const Hash256& d_governance, const Hash256& d_nms_extended,
                         const Hash256& d_spv, const Hash256& d_anchors, const Hash256& d_amm,
                         const Hash256& d_finality, const Hash256& d_redeem_bond) {
    std::vector<uint8_t> buf;
    static constexpr char DOMAIN[] = "VELD_STATE_DIGEST_v7|";
    put_bytes(buf, reinterpret_cast<const uint8_t*>(DOMAIN), sizeof(DOMAIN) - 1);
    put_u64_le(buf, height);
    put_bytes(buf, best_block_hash.data(), best_block_hash.size());
    put_bytes(buf, d_utxo.data(), d_utxo.size());
    put_bytes(buf, d_validators.data(), d_validators.size());
    put_bytes(buf, d_staking.data(), d_staking.size());
    put_bytes(buf, d_bondyield.data(), d_bondyield.size());
    put_bytes(buf, d_nmstally.data(), d_nmstally.size());
    put_bytes(buf, d_tokens.data(), d_tokens.size());
    put_bytes(buf, d_supply.data(), d_supply.size());
    put_bytes(buf, d_governance.data(), d_governance.size());
    put_bytes(buf, d_nms_extended.data(), d_nms_extended.size());
    put_bytes(buf, d_spv.data(), d_spv.size());
    put_bytes(buf, d_anchors.data(), d_anchors.size());
    put_bytes(buf, d_amm.data(), d_amm.size());
    put_bytes(buf, d_finality.data(), d_finality.size());
    put_bytes(buf, d_redeem_bond.data(), d_redeem_bond.size());
    return sha256_of(buf);
}

// v8 is the fresh-mainnet reserve-semantics envelope.  Its component order is
// intentionally identical to v7; D_tokens uses its own new domain and embeds
// the complete fixed-width reserve state.  A distinct top-level domain makes
// the semantic boundary explicit even at deterministic EMPTY genesis state.
inline Hash256 ComposeV8(uint64_t height, const Hash256& best_block_hash, const Hash256& d_utxo,
                         const Hash256& d_validators, const Hash256& d_staking,
                         const Hash256& d_bondyield, const Hash256& d_nmstally,
                         const Hash256& d_tokens, const Hash256& d_supply,
                         const Hash256& d_governance, const Hash256& d_nms_extended,
                         const Hash256& d_spv, const Hash256& d_anchors, const Hash256& d_amm,
                         const Hash256& d_finality, const Hash256& d_redeem_bond) {
    std::vector<uint8_t> buf;
    static constexpr char DOMAIN[] = "VELD_STATE_DIGEST_v8|";
    put_bytes(buf, reinterpret_cast<const uint8_t*>(DOMAIN), sizeof(DOMAIN) - 1);
    put_u64_le(buf, height);
    put_bytes(buf, best_block_hash.data(), best_block_hash.size());
    put_bytes(buf, d_utxo.data(), d_utxo.size());
    put_bytes(buf, d_validators.data(), d_validators.size());
    put_bytes(buf, d_staking.data(), d_staking.size());
    put_bytes(buf, d_bondyield.data(), d_bondyield.size());
    put_bytes(buf, d_nmstally.data(), d_nmstally.size());
    put_bytes(buf, d_tokens.data(), d_tokens.size());
    put_bytes(buf, d_supply.data(), d_supply.size());
    put_bytes(buf, d_governance.data(), d_governance.size());
    put_bytes(buf, d_nms_extended.data(), d_nms_extended.size());
    put_bytes(buf, d_spv.data(), d_spv.size());
    put_bytes(buf, d_anchors.data(), d_anchors.size());
    put_bytes(buf, d_amm.data(), d_amm.size());
    put_bytes(buf, d_finality.data(), d_finality.size());
    put_bytes(buf, d_redeem_bond.data(), d_redeem_bond.size());
    return sha256_of(buf);
}

namespace tags {
inline constexpr const char* UTXO = "VELD_D_UTXO_v2|";
inline constexpr const char* VALIDATORS =
    "VELD_D_VALIDATORS_v5|"; // complete registry + admission config + exact endorsed hash
inline constexpr const char* STAKING =
    "VELD_D_STAKING_v3|"; // complete state + mutable validation config
inline constexpr const char* BONDYIELD =
    "VELD_D_BONDYIELD_v2|"; // complete ordered escrow tranche state
inline constexpr const char* NMSTALLY = "VELD_D_NMSTALLY_v1|";
inline constexpr const char* TOKENS =
    "VELD_D_TOKENS_v2|"; // includes ordered btcVELD tier-work window
inline constexpr const char* TOKENS_RESERVE_V1 = "VELD_D_TOKENS_RESERVE_v1|";
inline constexpr const char* SUPPLY =
    "VELD_D_SUPPLY_v4|"; // accounting, mutable cap/activation config, bounded miner window
inline constexpr const char* GOVERNANCE = "VELD_D_GOVERNANCE_v1|";
inline constexpr const char* NMS_EXTENDED = "VELD_D_NMS_EXTENDED_v1|";
inline constexpr const char* SPV = "VELD_D_SPV_v2|"; // complete active BTC header/fork view
inline constexpr const char* ANCHORS =
    "VELD_D_ANCHORS_v7|"; // staged proof + full permanent BTC/finality floor
inline constexpr const char* AMM = "VELD_D_AMM_v3|"; // complete btcVELD AMM pool record + LP ledger
inline constexpr const char* FINALITY =
    "VELD_D_FINALITY_v1|"; // raw high-water + immutable activation/window inputs
inline constexpr const char* REDEEM_BOND =
    "VELD_D_REDEEM_BOND_v1|"; // complete signer-bond/redeem covenant snapshot
} // namespace tags

// Canonical commitment for the Layer-3 finality state.  Commit the raw stored
// high-water (not the dormant RPC convenience value of chain tip) and both
// compile-time inputs that govern how the next block advances it.
inline Hash256 FinalityDigest(uint64_t final_height, uint64_t activation_height,
                              uint64_t finality_window) {
    std::vector<uint8_t> body;
    put_u32_le(body, 1); // encoding version
    put_u64_le(body, final_height);
    put_u64_le(body, activation_height);
    put_u64_le(body, finality_window);
    return sha256_domain(tags::FINALITY, body);
}

} // namespace state_digest
} // namespace veld
