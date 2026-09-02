#pragma once
// btcveld_relay_policy.h -- strict fee-key signing policy for permissionless
// btcVELD relay transactions.
//
// The relay key is deliberately a fees-only hot key.  It may sign exactly one
// canonical BHDR, ANCHOR, or MSPV OP_RETURN transaction whose only spendable
// outputs are change back to that same key.  Keeping this policy separate from
// BtcVeldMintTemplatePolicy is important: `veld-keygen sign-tx` remains an
// issuer-mint-only command, while `sign-op` cannot authorize an issuer mint or
// an arbitrary payment.

#include "../core/transaction.h"
#include "btcveld_mint_nullifier.h"
#include "btcveld_reserve_transition.h"

#include <cstdint>
#include <string>
#include <vector>

namespace veld {

inline bool BtcVeldRelayHex(const std::string& text,
                            std::vector<uint8_t>& out) {
    out.clear();
    if (text.empty() || (text.size() & 1u)) return false;
    out.reserve(text.size() / 2);
    auto nybble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < text.size(); i += 2) {
        const int hi = nybble(text[i]);
        const int lo = nybble(text[i + 1]);
        if (hi < 0 || lo < 0) {
            out.clear();
            return false;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

inline bool BtcVeldRelayPayloadShape(const std::string& op,
                                     std::string& family) {
    struct PrefixMagic {
        const char* prefix;
        const char* magic;
    };
    static constexpr PrefixMagic allowed[] = {
        {"VELD_BHDR|",   "BHDR"},
        {"VELD_ANCHOR|", "ANCH"},
        {"VELD_MSPV|",   btcnull::CUSTODY_LINEAGE_REQUIRED ? "MSP3" : "MSP2"},
#if defined(VELD_PUBLIC_MAINNET) || defined(VELD_BTCVELD_REGTEST)
        {btcveld::reserve::PUBLIC_CARRIER_PREFIX,
         btcveld::reserve::PROOF_MAGIC},
#endif
    };

    const PrefixMagic* match = nullptr;
    for (const auto& item : allowed) {
        if (op.rfind(item.prefix, 0) == 0) {
            match = &item;
            family = item.prefix;
            break;
        }
    }
    if (!match || op.size() < 12) return false;
    const size_t op_max = family == "VELD_MSPV|"
        ? btcnull::MAX_MSPV_OP_PAYLOAD_BYTES
        : (family == btcveld::reserve::PUBLIC_CARRIER_PREFIX
               ? std::char_traits<char>::length(
                     btcveld::reserve::PUBLIC_CARRIER_PREFIX) +
                     2 * btcveld::reserve::MAX_PROOF_BYTES
               : 24000);
    if (op.size() > op_max) return false;

    const std::string encoded = op.substr(std::char_traits<char>::length(match->prefix));
    std::vector<uint8_t> raw;
    if (!BtcVeldRelayHex(encoded, raw) || raw.size() < 4) return false;
    if (encoded != BytesToHex(raw)) return false; // lowercase, one text form
    for (size_t i = 0; i < 4; ++i)
        if (raw[i] != static_cast<uint8_t>(match->magic[i])) return false;

    if (family == "VELD_BHDR|") {
        if (raw.size() < 5 || raw[4] == 0) return false;
        return raw.size() == 5u + static_cast<size_t>(raw[4]) * 80u;
    }

    if (family == btcveld::reserve::PUBLIC_CARRIER_PREFIX) {
        btcveld::reserve::Claim claim;
        return btcveld::reserve::DecodeProof(
                   raw.data(), raw.size(), claim) &&
               btcveld::reserve::EncodeProof(claim) == raw;
    }

    // ANCH/MSP3 share the fixed Merkle prefix.
    if (raw.size() < 4u + 32u + 4u + 1u) return false;
    const size_t branch_len = raw[40];
    if (branch_len > 32) return false;
    const size_t tx_offset = 41u + branch_len * 32u;
    if (tx_offset >= raw.size()) return false;
    const uint32_t dirs = static_cast<uint32_t>(raw[36]) |
                          (static_cast<uint32_t>(raw[37]) << 8) |
                          (static_cast<uint32_t>(raw[38]) << 16) |
                          (static_cast<uint32_t>(raw[39]) << 24);
    if (branch_len < 32 && (dirs >> branch_len) != 0) return false;
    if (family == "VELD_MSPV|") {
        if (tx_offset + 4u > raw.size()) return false;
        const uint32_t tx_len = static_cast<uint32_t>(raw[tx_offset]) |
            (static_cast<uint32_t>(raw[tx_offset + 1]) << 8) |
            (static_cast<uint32_t>(raw[tx_offset + 2]) << 16) |
            (static_cast<uint32_t>(raw[tx_offset + 3]) << 24);
        const size_t tx_begin = tx_offset + 4u;
        if (tx_len <= 64 ||
            tx_len > btcnull::MAX_MSPV_STRIPPED_TX_BYTES ||
            tx_begin + static_cast<size_t>(tx_len) > raw.size())
            return false;
        size_t off = tx_begin + static_cast<size_t>(tx_len);
        if (!btcnull::CUSTODY_LINEAGE_REQUIRED) {
            const size_t nullifier_len = raw.size() - off;
            btcnull::Proof nullifier;
            return nullifier_len >= btcnull::MIN_PROOF_BYTES &&
                   nullifier_len <= btcnull::MAX_PROOF_BYTES &&
                   btcnull::DecodeProof(raw.data() + off,
                                        nullifier_len, nullifier);
        }
        if (off + 2 > raw.size()) return false;
        const uint16_t parent_count = static_cast<uint16_t>(raw[off]) |
            (static_cast<uint16_t>(raw[off + 1]) << 8);
        off += 2;
        if (parent_count == 0 ||
            parent_count > btcnull::MAX_MSPV_PARENT_COUNT) return false;
        size_t parent_total = 0;
        for (uint16_t i = 0; i < parent_count; ++i) {
            if (off + 4 > raw.size()) return false;
            const uint32_t parent_len = static_cast<uint32_t>(raw[off]) |
                (static_cast<uint32_t>(raw[off + 1]) << 8) |
                (static_cast<uint32_t>(raw[off + 2]) << 16) |
                (static_cast<uint32_t>(raw[off + 3]) << 24);
            off += 4;
            if (parent_len < 10 ||
                parent_len > btcnull::MAX_MSPV_PARENT_TX_BYTES ||
                parent_total > btcnull::MAX_MSPV_PARENT_TOTAL_BYTES - parent_len ||
                off + parent_len > raw.size()) return false;
            off += parent_len;
            parent_total += parent_len;
        }
        const size_t nullifier_len = raw.size() - off;
        btcnull::Proof nullifier;
        return nullifier_len >= btcnull::MIN_PROOF_BYTES &&
               nullifier_len <= btcnull::MAX_PROOF_BYTES &&
               btcnull::DecodeProof(raw.data() + off,
                                    nullifier_len, nullifier);
    }
    return true;
}

// Returns "" iff `tx` is a canonical fee-funded relay transaction.  On
// success `family_out` is the exact allowlisted prefix including its '|'.
inline std::string BtcVeldRelayTemplatePolicy(
        const Transaction& tx, const std::vector<uint8_t>& fee_key_p2pkh,
        std::string& family_out) {
    if (tx.inputs.empty()) return "relay transaction has no inputs";
    int relay_markers = 0;
    int change_outputs = 0;
    for (size_t oi = 0; oi < tx.outputs.size(); ++oi) {
        const auto& output = tx.outputs[oi];
        const auto& script = output.script_pubkey;
        if (!script.empty() && script[0] == 0x6a) {
            if (output.value != 0)
                return "OP_RETURN output [" + std::to_string(oi) + "] carries value";
            if (++relay_markers != 1)
                return "expected exactly one relay OP_RETURN";

            size_t off = 1, pushed = 0;
            if (off >= script.size()) return "relay OP_RETURN has no push";
            const uint8_t push = script[off++];
            if (push <= 75) {
                pushed = push;
            } else if (push == 0x4c) {
                if (off >= script.size()) return "truncated OP_PUSHDATA1";
                pushed = script[off++];
                if (pushed <= 75) return "non-canonical OP_PUSHDATA1";
            } else if (push == 0x4d) {
                if (off + 2 > script.size()) return "truncated OP_PUSHDATA2";
                pushed = static_cast<size_t>(script[off]) |
                         (static_cast<size_t>(script[off + 1]) << 8);
                off += 2;
                if (pushed <= 255) return "non-canonical OP_PUSHDATA2";
            } else {
                return "unsupported relay OP_RETURN push opcode";
            }
            if (off + pushed != script.size())
                return "relay OP_RETURN push length/trailing bytes mismatch";
            const std::string op(script.begin() + off, script.end());
            std::string family;
            if (!BtcVeldRelayPayloadShape(op, family))
                return "OP_RETURN is not a well-formed allowlisted btcVELD relay op";
            family_out = family;
        } else {
            if (script != fee_key_p2pkh)
                return "output [" + std::to_string(oi) +
                       "] pays a non-fee-key script (relay may only return change)";
            if (++change_outputs != 1)
                return "relay transaction has more than one change output";
        }
    }
    if (relay_markers != 1)
        return "expected exactly one allowlisted relay OP_RETURN, found " +
               std::to_string(relay_markers);
    return "";
}

}  // namespace veld
