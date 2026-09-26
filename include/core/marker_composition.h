#pragma once
// Cross-protocol marker-composition guard.
//
// Every VELD_* OP_RETURN family below drives an INDEPENDENT consensus state
// machine — onchain_tokens (TOKEN / MSPV), amm_pool (AMM), staking (STAKE),
// validators (VALIDATOR), governance (GOV), and the btcVELD peg daemons
// (ANCHOR / BHDR / FRAUD / SBOND / PAYOUT). Each of those scans a block's
// transactions for ITS OWN marker with no awareness of the others, so a single
// transaction bearing two different family markers is applied by BOTH state
// machines from one input / authorization set — the cross-protocol composition
// attack . Honest transactions are single-purpose: every rpc.h
// builder and every node.h daemon emitter writes exactly one family per tx.
//
// This guard rejects any tx carrying markers from >= 2 DISTINCT families.
// Same-family batching remains available where the protocol defines it (for
// example BTC header relay), but token state is deliberately one operation per
// transaction: each token marker can otherwise trigger another post-validation
// ML-DSA authorization and permanent balance-map mutation. Deliberately NOT
// families:
//   * VELD_DIST|       — a reward-distribution LABEL on the value-only canonical
//                        vault / endorsement-pool / co-mine flushes; triggers no
//                        state machine (those flushes are output-locked by
//                        ValidateExpected*Distribution).
//   * VELD_CHECKPOINT| — a signature DOMAIN string (ComputeCheckpointDigest),
//                        never emitted as a transaction output.
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <string>
#include "transaction.h"

namespace veld {

// A single logical finality QC may be split across this many canonical
// zero-value outputs to respect the 32,768-byte per-script ceiling. The
// finality block parser binds/reassembles them and rejects mixed/duplicate or
// incomplete sequences before state mutation.
inline constexpr size_t MAX_FINALITY_MARKER_OUTPUTS = 235;

// The stateful protocol families, keyed by their OP_RETURN prefix (up to and
// including the family delimiter '|'). Order is irrelevant; the count must fit
// in the seen-mask (uint32_t) below.
inline constexpr const char* const kStatefulMarkerFamilies[] = {
    "VELD_TOKEN|", // custodial btcVELD mint / transfer / redeem  (onchain_tokens)
    "VELD_MSPV|",  // trust-min SPV mint                          (onchain_tokens)
#if defined(VELD_PUBLIC_MAINNET) || defined(VELD_BTCVELD_REGTEST)
    "VELD_RSV1|", // rolling reserve transition                  (onchain_tokens)
#endif
    "VELD_AMM|",       // pool swap / add / remove                    (amm_pool)
    "VELD_STAKE|",     // stake lock / unlock                         (staking)
    "VELD_VALIDATOR|", // register / deregister / endorse / slash     (validators)
    "VELD_GOV|",       // governance proposal / vote                  (governance)
    "VELD_ANCHOR|",    // btcVELD L2 anchor post                      (btcveld anchor)
    "VELD_BHDR|",      // BTC header relay                            (btc relay)
    "VELD_FRAUD|",     // fraudulent-spend SPV proof / slash          (btcveld redeem)
    "VELD_SBOND|",     // signer bond register / activate             (btcveld redeem)
    "VELD_PAYOUT|",    // SPV-proven payout fulfil / wrong-payout slash(btcveld redeem)
    "VELD_FINALITY|",  // locked-QC certificate carrier              (finality)
};
inline constexpr int kNumStatefulMarkerFamilies =
    (int)(sizeof(kStatefulMarkerFamilies) / sizeof(kStatefulMarkerFamilies[0]));
static_assert(kNumStatefulMarkerFamilies <= 32,
              "seen-mask is a uint32_t; widen it if more families are added");

// Returns the OP_RETURN payload of `script_pubkey`, or "" if the script is not
// a well-formed OP_RETURN push. Mirrors the canonical ParseOpReturn decoder
// (direct length <= 75, OP_PUSHDATA1 0x4C, OP_PUSHDATA2 0x4D) byte-for-byte so
// this guard sees exactly what the per-family state machines see.
inline std::string MarkerOpReturnPayload(const std::vector<uint8_t>& script_pubkey) {
    if (script_pubkey.size() < 2 || script_pubkey[0] != 0x6A)
        return "";
    size_t off = 1, plen = 0;
    if (script_pubkey[off] <= 75) {
        plen = script_pubkey[off++];
    } else if (script_pubkey[off] == 0x4C && script_pubkey.size() > off + 1) {
        off++;
        plen = script_pubkey[off++];
    } else if (script_pubkey[off] == 0x4D && script_pubkey.size() > off + 2) {
        off++;
        plen = (size_t)script_pubkey[off] | ((size_t)script_pubkey[off + 1] << 8);
        off += 2;
    } else {
        return "";
    }
    if (off + plen > script_pubkey.size())
        return "";
    return std::string(script_pubkey.begin() + off, script_pubkey.begin() + off + plen);
}

// Stateful token markers have one script encoding: the shortest push opcode,
// no trailing bytes.  The generic decoder above is intentionally permissive
// for display/legacy consumers, so consensus callers must ask this separately.
inline bool IsCanonicalMarkerOpReturn(const std::vector<uint8_t>& script_pubkey,
                                      const std::string& payload) {
    const size_t n = payload.size();
    if (script_pubkey.empty() || script_pubkey[0] != 0x6A || n > 0xFFFF)
        return false;
    size_t off = 1;
    if (n <= 75) {
        if (script_pubkey.size() < 2 || script_pubkey[off++] != (uint8_t)n)
            return false;
    } else if (n <= 0xFF) {
        if (script_pubkey.size() < 3 || script_pubkey[off++] != 0x4C ||
            script_pubkey[off++] != (uint8_t)n)
            return false;
    } else {
        if (script_pubkey.size() < 4 || script_pubkey[off++] != 0x4D ||
            script_pubkey[off++] != (uint8_t)(n & 0xFF) ||
            script_pubkey[off++] != (uint8_t)(n >> 8))
            return false;
    }
    return script_pubkey.size() == off + n &&
           std::equal(payload.begin(), payload.end(), script_pubkey.begin() + (ptrdiff_t)off,
                      [](char payload_byte, uint8_t script_byte) {
                          return static_cast<uint8_t>(static_cast<unsigned char>(payload_byte)) ==
                                 script_byte;
                      });
}

// TOKEN and MSPV are ingress paths into the legacy balance/supply state
// machine.  RSV1 joins that family only in the fresh public-mainnet profile or
// the isolated reserve regtest profile; treating RSV1 as stateful in a legacy
// profile would retroactively change marker composition.  Exactly one active
// token mutation is allowed per tx, using a canonical zero-value marker.
inline bool TxHasInvalidTokenMarkerSet(const Transaction& tx) {
    size_t token_markers = 0;
    for (const auto& out : tx.outputs) {
        const std::string payload = MarkerOpReturnPayload(out.script_pubkey);
        if (payload.rfind("VELD_TOKEN|", 0) != 0 && payload.rfind("VELD_MSPV|", 0) != 0
#if defined(VELD_PUBLIC_MAINNET) || defined(VELD_BTCVELD_REGTEST)
            && payload.rfind("VELD_RSV1|", 0) != 0
#endif
        )
            continue;
        if (++token_markers > 1 || out.value != 0 ||
            !IsCanonicalMarkerOpReturn(out.script_pubkey, payload))
            return true;
    }
    return false;
}

// A disposable public testnet may exercise native Veld consensus, mining,
// staking, governance, and finality, but it must never create an obligation on
// Bitcoin, Ethereum, Litecoin, or Dogecoin. These marker families are the
// complete on-chain ingress for btcVELD custody, Bitcoin header/anchor proofs,
// payout/slashing machinery, and the btcVELD AMM. Keep this classifier shared
// by consensus validation and mempool admission so a forbidden operation
// cannot enter through raw RPC, P2P relay, or direct block construction.
//
// This function is intentionally profile-neutral. Callers decide whether the
// policy is active; final mainnet continues to validate these protocols.
inline bool TxUsesExternalValueProtocol(const Transaction& tx) {
    constexpr const char* kExternalValueFamilies[] = {
        "VELD_TOKEN|",
        "VELD_MSPV|",
        // Always recognize the new carrier here so VELD_PUBLIC_TESTNET rejects
        // it even though that profile deliberately does not activate RSV1.
        "VELD_RSV1|",
        "VELD_AMM|",
        "VELD_ANCHOR|",
        "VELD_BHDR|",
        "VELD_FRAUD|",
        "VELD_SBOND|",
        "VELD_PAYOUT|",
    };
    for (const auto& out : tx.outputs) {
        const std::string payload = MarkerOpReturnPayload(out.script_pubkey);
        if (payload.empty())
            continue;
        for (const char* prefix : kExternalValueFamilies) {
            if (payload.rfind(prefix, 0) == 0)
                return true;
        }
    }
    return false;
}

// Returns true iff `tx` carries OP_RETURN markers from two or more DISTINCT
// stateful protocol families — a forbidden cross-protocol composition.
inline bool TxComposesMultipleProtocols(const Transaction& tx) {
    uint32_t seen_mask = 0;
    int distinct = 0;
    for (const auto& out : tx.outputs) {
        std::string payload = MarkerOpReturnPayload(out.script_pubkey);
        if (payload.empty())
            continue;
        for (int f = 0; f < kNumStatefulMarkerFamilies; ++f) {
            if (payload.rfind(kStatefulMarkerFamilies[f], 0) == 0) {
                if (!(seen_mask & (1u << f))) {
                    seen_mask |= (1u << f);
                    if (++distinct >= 2)
                        return true;
                }
                break; // a payload belongs to at most one family
            }
        }
    }
    return false;
}

} // namespace veld
