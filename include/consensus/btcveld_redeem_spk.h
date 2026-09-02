#pragma once
// btcveld_redeem_spk.h — on-chain well-formedness check for a btcVELD REDEEM destination
// scriptPubKey .
//
// A REDEEM burns btcVELD on the Veld chain and owes BTC to the destination committed in the
// op memo (a hex-encoded Bitcoin scriptPubKey). Consensus previously required only that the
// memo be NON-EMPTY, so a garbage / non-standard spk would burn btcVELD to a destination no
// honest custodian can ever pay — destroying it with no payout and no restore (CompensateMint
// is gated behind the dormant redeem covenant). This validator lets consensus reject an
// UNPAYABLE burn: the decoded memo must be a STANDARD, payable Bitcoin output.
//
// Pure + dependency-free (unit-testable in isolation). when armed.

#include <vector>
#include <cstdint>
#include <cstddef>

namespace veld {

// True iff `s` is a STANDARD, payable Bitcoin scriptPubKey:
//   P2PKH   : OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG   (25B)
//   P2SH    : OP_HASH160 <20> OP_EQUAL                            (23B)
//   SegWit  : <version OP_0 | OP_1..OP_16> <push 2..40> <program> (v0 => 20 or 32; v1..v16 any 2..40)
// Rejects empty, OP_RETURN, bare data pushes, oversized, and any malformed script — so a
// REDEEM can never burn btcVELD to an address that cannot be paid.
inline bool IsStandardBtcRedeemSpk(const std::vector<uint8_t>& s) {
    // P2PKH
    if (s.size() == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac)
        return true;
    // P2SH
    if (s.size() == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87)
        return true;
    // SegWit v0..v16
    if (s.size() >= 4 && s.size() <= 42) {
        uint8_t v = s[0];
        bool ver_ok = (v == 0x00) || (v >= 0x51 && v <= 0x60);   // OP_0, or OP_1..OP_16
        uint8_t plen = s[1];
        if (ver_ok && plen >= 2 && plen <= 40 && (size_t)plen + 2 == s.size()) {
            if (v == 0x00) return plen == 20 || plen == 32;      // v0: P2WPKH(20) / P2WSH(32) only
            return true;                                          // v1..v16 (taproot program = 32; future-proof)
        }
    }
    return false;
}

}  // namespace veld
