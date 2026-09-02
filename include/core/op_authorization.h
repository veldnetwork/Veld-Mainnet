#pragma once
// Shared consensus authorization checks for state-changing operations.
//
// Authorization for AMM operations, token operations, staking, and validator
// registration must come from a verified signature, not merely from a public
// key present in transaction bytes. Covenant inputs can be signature-exempt,
// so presence-only checks would allow an unrelated public key to be attached
// without proving control of it.
//
// This header provides the single authorization primitive used everywhere:
// `TxVerifiedSignedBy(tx, address)` returns true IFF some input of `tx` carries
// `address`'s public key WITH a valid ML-DSA signature over the correct sighash.
// A public key sitting in a sigless / covenant input (empty or attacker-crafted
// scriptSig) does NOT authorize, because no valid signature exists for it — closing
// the forgery at the root while leaving every legitimate op (which always funds
// from an actor-signed P2PKH input) unaffected.

#include "transaction.h"
#include "hash.h"
#include "script.h"
#include "../crypto/veld_signing.h"
#include <array>
#include <string>
#include <vector>

namespace veld {

// Verify one input's ML-DSA-65 signature against a standard 25-byte P2PKH
// script_pubkey. This is the CANONICAL single-input signature verifier; it is the
// exact logic previously inlined as Blockchain::VerifyInputAgainstScript
// (blockchain.h) and in the ValidateTransaction per-input loop. Those paths now
// delegate here so block validation and op authorization can never diverge.
//
// For any input the block validator accepted as P2PKH, its prevout scriptPubKey is
// exactly this reconstructed script, so computing the sighash over `script_pubkey`
// reproduces the block validator's own verification bit-for-bit.
inline bool VerifyP2PKHInputSig(const Transaction& tx, uint32_t input_index,
                                const std::vector<uint8_t>& script_pubkey) {
    if (input_index >= tx.inputs.size()) return false;
    const auto& inp = tx.inputs[input_index];
    if (script_pubkey.size() != 25 ||
        script_pubkey[0]  != 0x76 || script_pubkey[1]  != 0xA9 ||
        script_pubkey[2]  != 0x14 || script_pubkey[23] != 0x88 ||
        script_pubkey[24] != 0xAC) {
        return false;
    }
    std::array<uint8_t, 20> expected_hash;
    std::copy(script_pubkey.begin() + 3, script_pubkey.begin() + 23, expected_hash.begin());

    auto read_pushdata2 = [](const std::vector<uint8_t>& ss, size_t& pos,
                             std::vector<uint8_t>& out) -> bool {
        if (pos + 3 > ss.size()) return false;
        if (ss[pos++] != 0x4D) return false;
        size_t len = (size_t)ss[pos] | ((size_t)ss[pos + 1] << 8);
        pos += 2;
        if (pos + len > ss.size()) return false;
        out.assign(ss.begin() + pos, ss.begin() + pos + len);
        pos += len;
        return true;
    };

    const auto& ss = inp.script_sig;
    size_t pos = 0;
    std::vector<uint8_t> sig_bytes_with_hashtype;
    std::vector<uint8_t> pubkey_bytes;
    if (!read_pushdata2(ss, pos, sig_bytes_with_hashtype)) return false;
    if (!read_pushdata2(ss, pos, pubkey_bytes)) return false;
    if (pubkey_bytes.size() != 1952) return false;
    if (sig_bytes_with_hashtype.empty()) return false;
    if (pos != ss.size()) return false;
    if (sig_bytes_with_hashtype.size() != 3311) return false;
    uint8_t scheme_id = sig_bytes_with_hashtype.front();
    if (scheme_id != SCHEME_ID_MLDSA65) return false;
    if (sig_bytes_with_hashtype.back() != 0x01) return false;

    Secp256k1PubKey pubkey;
    std::copy(pubkey_bytes.begin(), pubkey_bytes.end(), pubkey.begin());
    Hash160 actual_hash = Hash160Compute(pubkey);
    for (int j = 0; j < 20; ++j) {
        if (actual_hash[j] != expected_hash[j]) return false;
    }
    Secp256k1SigDER sig_bytes(sig_bytes_with_hashtype.begin() + 1,
                              sig_bytes_with_hashtype.end() - 1);
    Hash256 sighash = ComputeSighash(tx, input_index, script_pubkey, scheme_id);
    return Verify(pubkey, sighash, sig_bytes);
}

// AUTHORIZATION PRIMITIVE — the single check that replaces every presence-only
// AmmTxSignedBy / TxInputMatchesAddress. True IFF `tx` carries a VALID signature
// from `address`. The reconstructed P2PKH subscript equals the prevout script the
// base validator uses for any accepted P2PKH input, so this is exactly the block
// validator's own verification — a forger who lacks the victim's private key cannot
// produce a passing signature, so a victim key in a sigless input authorizes nothing.
inline bool TxVerifiedSignedBy(const Transaction& tx, const std::string& address) {
    if (address.size() < 2) return false;
    std::vector<uint8_t> script = AddressToScript(address);
    if (script.size() != 25) return false;
    for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
        if (VerifyP2PKHInputSig(tx, i, script)) return true;
    }
    return false;
}

} // namespace veld
