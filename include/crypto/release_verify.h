#pragma once
// Shared detached ML-DSA-65 release-signature verification. Callers verify the
// double-SHA-256 payload digest against the pinned release public key. Signature
// files contain the raw ML-DSA-65 signature bytes produced by veld-keygen.
#include "release_pubkey.h"
#include "veld_signing.h"
#include <cstdint>
#include <string>
#include <vector>

namespace veld {

// Decode the compile-time pinned release pubkey. Returns false (instead of
// throwing) on a malformed pin so callers can fail closed.
inline bool LoadPinnedReleasePubkey(Secp256k1PubKey& out) {
    const std::string ph = RELEASE_SIGNING_PUBKEY_HEX;
    if (ph.size() != out.size() * 2) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < out.size(); ++i) {
        int hi = nib(ph[i * 2]), lo = nib(ph[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

// Decode the compile-time pinned SNAPSHOT-signing pubkey (a SEPARATE key from
// the release key; retained only for non-public offline snapshot fixtures —
// see release_pubkey.h). Fails closed on a malformed pin.
inline bool LoadPinnedSnapshotPubkey(Secp256k1PubKey& out) {
    const std::string ph = SNAPSHOT_SIGNING_PUBKEY_HEX;
    if (ph.size() != out.size() * 2) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < out.size(); ++i) {
        int hi = nib(ph[i * 2]), lo = nib(ph[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

// Detached release-signature check against an EXPLICIT pubkey (the seam the
// regression sentinel exercises with a throwaway keypair).
inline bool VerifyReleaseSignatureBytes(const std::vector<uint8_t>& payload,
                                        const std::vector<uint8_t>& sig,
                                        const Secp256k1PubKey&      pub) {
    Hash256 h = Hash256d(payload);
    return Verify(pub, h, sig);
}

// Production path: payload + raw signature against the PINNED release pubkey.
inline bool VerifyReleaseSignaturePinned(const std::vector<uint8_t>& payload,
                                         const std::vector<uint8_t>& sig) {
    Secp256k1PubKey pub{};
    if (!LoadPinnedReleasePubkey(pub)) return false;
    return VerifyReleaseSignatureBytes(payload, sig, pub);
}

}  // namespace veld
