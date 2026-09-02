#pragma once
// Canonical parser for the post-PQC scriptSig layout:
//   OP_PUSHDATA2 <sig_len:u16> <sig||0x01 sighash type>
//   OP_PUSHDATA2 <1952:u16>    <pubkey>
// produced by BuildScriptSig in crypto/veld_signing.h. All consensus,
// mempool, and display code paths that need to recover the sender
// pubkey from a signed scriptSig go through this function.
//
// Usage:
//   std::vector<uint8_t> sig; std::array<uint8_t,1952> pubkey;
//   if (veld::pqc::ParseScriptSig(ss, sig, pubkey)) { ... }

#include <array>
#include <cstdint>
#include <vector>

namespace veld { namespace pqc {

inline bool ParseScriptSig(const std::vector<uint8_t>& ss,
                           std::vector<uint8_t>& sig_out,
                           std::array<uint8_t, 1952>& pubkey_out) {
    if (ss.size() < 6) return false;
    size_t pos = 0;
    if (ss[pos++] != 0x4D) return false;
    if (pos + 2 > ss.size()) return false;
    size_t siglen = (size_t)ss[pos] | ((size_t)ss[pos+1] << 8);
    pos += 2;
    if (siglen != 3311) return false;
    if (pos + siglen > ss.size()) return false;
    sig_out.assign(ss.begin() + pos, ss.begin() + pos + siglen);
    pos += siglen;
    if (pos + 3 > ss.size() || ss[pos++] != 0x4D) return false;
    size_t pklen = (size_t)ss[pos] | ((size_t)ss[pos+1] << 8);
    pos += 2;
    if (pklen != 1952 || pos + pklen > ss.size()) return false;
    std::copy(ss.begin() + pos, ss.begin() + pos + 1952, pubkey_out.begin());
    pos += pklen;
    // Reject trailing bytes after the canonical two pushes. Otherwise an
    // attacker can
    // append arbitrary bytes to a valid scriptSig — the signature still
    // verifies (sighash doesn't cover scriptSig), but the TxID changes.
    // That is classic third-party TX malleability and breaks wallet pending
    // lookups + chained child TXs.
    if (pos != ss.size()) return false;
    return true;
}

}}
