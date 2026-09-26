#pragma once

// Consensus-visible capacity leases for the public issuer-assisted WRAP path.
//
// An off-chain Bitcoin address allocation is not a capacity guarantee.  A C1R1
// marker, signed by the compiled btcVELD issuer, reserves the exact amount for
// one allocation before the address may be shown to its depositor. C1R1 and
// C1E1 carry only a domain-separated commitment: publishing either marker must
// not disclose the Bitcoin deposit script during the 101-block wait. C1F1
// opens the exact P2TR script only after independently proving the matching
// Bitcoin funding transaction and atomically consumes its nullifier. The later
// MNP2 credits the recipient and releases the funded lease without touching
// the nullifier root again. Unfunded exposure is bounded by the configured
// public funding window; funded capacity remains occupied until exact MNP2.

#include "../core/constants.h"
#include "state_digest.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace veld::c1reserve {

inline constexpr const char* MEMO_PREFIX = "C1R1;";
inline constexpr const char* EXPOSE_MEMO_PREFIX = "C1E1;";
inline constexpr const char* CANCEL_MEMO_PREFIX = "C1C1;";
inline constexpr const char* FUND_MEMO_PREFIX = "C1F1;";
inline constexpr const char* COMMITMENT_DOMAIN = "VELD_BTCVELD_C1_ALLOCATION_COMMITMENT_v2|";
inline constexpr int64_t MIN_SATS = 10'000;
inline constexpr uint64_t LIFETIME_BLOCKS = 7 * BLOCKS_PER_DAY;
inline constexpr uint64_t FINALITY_DEPTH = MAX_REORG_DEPTH + 1;
inline constexpr size_t MAX_ACTIVE =
    static_cast<size_t>(BTCVELD_ISSUER_MAX_CUSTODY_SATS / MIN_SATS);

static_assert(TARGET_BLOCK_TIME * BLOCKS_PER_DAY == 86'400,
              "C1 reservation lifetime must remain exactly seven target days");
static_assert(LIFETIME_BLOCKS > FINALITY_DEPTH,
              "C1 lease must outlive its canonical-depth publication gate");
static_assert(LIFETIME_BLOCKS > 2 * FINALITY_DEPTH - 1,
              "C1 funding term must include settlement and finality buffers");

inline bool HasFinalityDepth(uint64_t accepted_height, uint64_t current_height) {
    static_assert(FINALITY_DEPTH > 0, "C1 finality depth cannot be zero");
    constexpr uint64_t offset = FINALITY_DEPTH - 1;
    return accepted_height <= std::numeric_limits<uint64_t>::max() - offset &&
           current_height >= accepted_height + offset;
}

inline bool FundingWindow(uint64_t exposed_height, uint64_t& starts, uint64_t& expires) {
    constexpr uint64_t finality_offset = FINALITY_DEPTH - 1;
    constexpr uint64_t lifetime_offset = LIFETIME_BLOCKS - 1;
    if (exposed_height > std::numeric_limits<uint64_t>::max() - finality_offset)
        return false;
    starts = exposed_height + finality_offset;
    if (starts > std::numeric_limits<uint64_t>::max() - lifetime_offset)
        return false;
    expires = starts + lifetime_offset;
    return true;
}

inline bool LatestFundingAcceptanceHeight(uint64_t capacity_expires, uint64_t& latest) {
    constexpr uint64_t finality_offset = FINALITY_DEPTH - 1;
    if (capacity_expires < finality_offset)
        return false;
    latest = capacity_expires - finality_offset;
    return true;
}

inline bool RecommendedSendCutoffHeight(uint64_t capacity_expires, uint64_t& send_cutoff) {
    uint64_t latest_funding = 0;
    if (!LatestFundingAcceptanceHeight(capacity_expires, latest_funding) ||
        latest_funding < FINALITY_DEPTH)
        return false;
    // Reserve another full 101 Veld heights for K_BTC burial, relay and C1F1
    // inclusion. The remaining 100 heights let that final C1F1 become 101-deep
    // before an unfunded lease can be pruned.
    send_cutoff = latest_funding - FINALITY_DEPTH;
    return true;
}

inline bool IsAllocationId(const std::string& value) {
    if (value.size() != 32)
        return false;
    for (char c : value)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    // Canonical injective uint64 allocation sequence: 8 zero bytes followed by
    // the 8-byte sequence in big-endian display hex. Sequence zero is reserved
    // as the pre-genesis sentinel.
    if (value.compare(0, 16, "0000000000000000") != 0)
        return false;
    bool nonzero = false;
    for (size_t i = 16; i < value.size(); ++i)
        nonzero = nonzero || value[i] != '0';
    return nonzero;
}

inline bool AllocationSequence(const std::string& value, uint64_t& sequence) {
    sequence = 0;
    if (!IsAllocationId(value))
        return false;
    for (size_t i = 16; i < value.size(); ++i) {
        const char c = value[i];
        const uint64_t nibble =
            c <= '9' ? static_cast<uint64_t>(c - '0') : static_cast<uint64_t>(c - 'a' + 10);
        sequence = (sequence << 4) | nibble;
    }
    return sequence != 0;
}

inline std::string AllocationId(uint64_t sequence) {
    if (sequence == 0)
        return {};
    static constexpr char HEX[] = "0123456789abcdef";
    std::string out(32, '0');
    for (size_t i = 0; i < 16; ++i) {
        const unsigned shift = static_cast<unsigned>((15 - i) * 4);
        out[16 + i] = HEX[(sequence >> shift) & 0x0f];
    }
    return out;
}

inline bool IsP2trScriptHex(const std::string& value) {
    if (value.size() != 68 || value.rfind("5120", 0) != 0)
        return false;
    for (char c : value)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}

inline bool IsCommitmentHex(const std::string& value) {
    if (value.size() != 64)
        return false;
    for (char c : value)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}

inline bool IsBlindHex(const std::string& value) {
    if (!IsCommitmentHex(value))
        return false;
    for (char c : value)
        if (c != '0')
            return true;
    return false; // zero is not a hiding factor
}

inline bool IsCanonicalOutpoint(const std::string& value) {
    const size_t split = value.find(':');
    if (split != 64 || value.find(':', split + 1) != std::string::npos)
        return false;
    for (size_t i = 0; i < 64; ++i)
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f')))
            return false;
    const std::string vout = value.substr(split + 1);
    if (vout.empty() || (vout.size() > 1 && vout[0] == '0') || vout.size() > 10)
        return false;
    uint64_t parsed = 0;
    for (char c : vout) {
        if (c < '0' || c > '9')
            return false;
        parsed = parsed * 10 + static_cast<uint64_t>(c - '0');
    }
    return parsed <= 0xffffffffULL;
}

// Bind every consensus-visible allocation identity field plus the undisclosed
// P2TR script. Length prefixes and little-endian amount make the byte encoding
// injective and independently reproducible by the coordinator/signer daemons.
inline std::string AllocationCommitment(const std::string& allocation_id,
                                        const std::string& recipient, int64_t amount_sats,
                                        const std::string& script_pubkey_hex,
                                        const std::string& blind_hex) {
    if (!IsAllocationId(allocation_id) || recipient.empty() || amount_sats <= 0 ||
        !IsP2trScriptHex(script_pubkey_hex) || !IsBlindHex(blind_hex))
        return {};
    std::vector<uint8_t> body;
    state_digest::put_len_prefixed(body, allocation_id);
    state_digest::put_len_prefixed(body, recipient);
    state_digest::put_u64_le(body, static_cast<uint64_t>(amount_sats));
    state_digest::put_len_prefixed(body, script_pubkey_hex);
    state_digest::put_len_prefixed(body, blind_hex);
    return HashToHex(state_digest::sha256_domain(COMMITMENT_DOMAIN, body));
}

inline std::string EncodeMemo(const std::string& allocation_id,
                              const std::string& allocation_commitment) {
    if (!IsAllocationId(allocation_id) || !IsCommitmentHex(allocation_commitment))
        return {};
    return std::string(MEMO_PREFIX) + allocation_id + ";" + allocation_commitment;
}

inline std::string EncodeExposureMemo(const std::string& allocation_id,
                                      const std::string& allocation_commitment) {
    if (!IsAllocationId(allocation_id) || !IsCommitmentHex(allocation_commitment))
        return {};
    return std::string(EXPOSE_MEMO_PREFIX) + allocation_id + ";" + allocation_commitment;
}

// A descriptor may already have advanced when signing/broadcasting C1R1
// fails. C1C1 consumes that exact next allocation sequence without reserving
// capacity, permanently invalidating every stale C1R1 byte string for the same
// sequence. It carries the same blinded commitment and never reveals the
// descriptor script or blind.
inline std::string EncodeCancellationMemo(const std::string& allocation_id,
                                          const std::string& allocation_commitment) {
    if (!IsAllocationId(allocation_id) || !IsCommitmentHex(allocation_commitment))
        return {};
    return std::string(CANCEL_MEMO_PREFIX) + allocation_id + ";" + allocation_commitment;
}

inline bool ParseMemo(const std::string& memo, std::string& allocation_id,
                      std::string& allocation_commitment) {
    allocation_id.clear();
    allocation_commitment.clear();
    const std::string prefix = MEMO_PREFIX;
    if (memo.rfind(prefix, 0) != 0)
        return false;
    const size_t split = memo.find(';', prefix.size());
    if (split == std::string::npos || memo.find(';', split + 1) != std::string::npos)
        return false;
    allocation_id = memo.substr(prefix.size(), split - prefix.size());
    allocation_commitment = memo.substr(split + 1);
    return IsAllocationId(allocation_id) && IsCommitmentHex(allocation_commitment) &&
           EncodeMemo(allocation_id, allocation_commitment) == memo;
}

inline bool ParseExposureMemo(const std::string& memo, std::string& allocation_id,
                              std::string& allocation_commitment) {
    allocation_id.clear();
    allocation_commitment.clear();
    const std::string prefix = EXPOSE_MEMO_PREFIX;
    if (memo.rfind(prefix, 0) != 0)
        return false;
    const size_t split = memo.find(';', prefix.size());
    if (split == std::string::npos || memo.find(';', split + 1) != std::string::npos)
        return false;
    allocation_id = memo.substr(prefix.size(), split - prefix.size());
    allocation_commitment = memo.substr(split + 1);
    return IsAllocationId(allocation_id) && IsCommitmentHex(allocation_commitment) &&
           EncodeExposureMemo(allocation_id, allocation_commitment) == memo;
}

inline bool ParseCancellationMemo(const std::string& memo, std::string& allocation_id,
                                  std::string& allocation_commitment) {
    allocation_id.clear();
    allocation_commitment.clear();
    const std::string prefix = CANCEL_MEMO_PREFIX;
    if (memo.rfind(prefix, 0) != 0)
        return false;
    const size_t split = memo.find(';', prefix.size());
    if (split == std::string::npos || memo.find(';', split + 1) != std::string::npos)
        return false;
    allocation_id = memo.substr(prefix.size(), split - prefix.size());
    allocation_commitment = memo.substr(split + 1);
    return IsAllocationId(allocation_id) && IsCommitmentHex(allocation_commitment) &&
           EncodeCancellationMemo(allocation_id, allocation_commitment) == memo;
}

inline std::string EncodeFundingMemo(const std::string& allocation_id,
                                     const std::string& script_pubkey_hex,
                                     const std::string& blind_hex,
                                     const std::string& canonical_outpoint,
                                     const std::string& funding_proof_hex) {
    bool proof_ok = funding_proof_hex.size() >= 174 && funding_proof_hex.size() <= 38000 &&
                    (funding_proof_hex.size() & 1u) == 0;
    for (char c : funding_proof_hex)
        proof_ok = proof_ok && ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    if (!IsAllocationId(allocation_id) || !IsP2trScriptHex(script_pubkey_hex) ||
        !IsBlindHex(blind_hex) || !IsCanonicalOutpoint(canonical_outpoint) || !proof_ok)
        return {};
    return std::string(FUND_MEMO_PREFIX) + allocation_id + ";" + script_pubkey_hex + ";" +
           blind_hex + ";" + canonical_outpoint + ";" + funding_proof_hex;
}

inline bool ParseFundingMemo(const std::string& memo, std::string& allocation_id,
                             std::string& script_pubkey_hex, std::string& blind_hex,
                             std::string& canonical_outpoint, std::string& funding_proof_hex) {
    allocation_id.clear();
    script_pubkey_hex.clear();
    blind_hex.clear();
    canonical_outpoint.clear();
    funding_proof_hex.clear();
    const std::string prefix = FUND_MEMO_PREFIX;
    if (memo.rfind(prefix, 0) != 0)
        return false;
    const size_t a = memo.find(';', prefix.size());
    const size_t b = a == std::string::npos ? std::string::npos : memo.find(';', a + 1);
    const size_t c = b == std::string::npos ? std::string::npos : memo.find(';', b + 1);
    const size_t d = c == std::string::npos ? std::string::npos : memo.find(';', c + 1);
    if (a == std::string::npos || b == std::string::npos || c == std::string::npos ||
        d == std::string::npos || memo.find(';', d + 1) != std::string::npos)
        return false;
    allocation_id = memo.substr(prefix.size(), a - prefix.size());
    script_pubkey_hex = memo.substr(a + 1, b - a - 1);
    blind_hex = memo.substr(b + 1, c - b - 1);
    canonical_outpoint = memo.substr(c + 1, d - c - 1);
    funding_proof_hex = memo.substr(d + 1);
    return EncodeFundingMemo(allocation_id, script_pubkey_hex, blind_hex, canonical_outpoint,
                             funding_proof_hex) == memo;
}

inline bool ExpiryHeight(uint64_t accepted_height, uint64_t& expiry) {
    static_assert(LIFETIME_BLOCKS > 0, "C1 lifetime cannot be zero");
    // `expiry` is the inclusive final eligible block. Counting the creation
    // block as eligibility one yields exactly LIFETIME_BLOCKS (3,360) block
    // heights, not 3,361.
    constexpr uint64_t offset = LIFETIME_BLOCKS - 1;
    if (accepted_height > std::numeric_limits<uint64_t>::max() - offset)
        return false;
    expiry = accepted_height + offset;
    return true;
}

} // namespace veld::c1reserve
