#pragma once
// Signed snapshot-manifest verification for authenticated recovery. The pinned
// ML-DSA-65 release key authenticates the archive digest, height, canonical tip,
// and genesis identity before any manifest field is used. Compiled checkpoints
// independently verify extracted block history.
#include "../crypto/release_verify.h"
#include "../core/canonical_numeric.h"
#include <cctype>
#include <cstdint>
#include <string>
#include <vector>

namespace veld {

struct SnapshotManifest {
    uint64_t    height = 0;    // publisher tip the snapshot was cut at
    std::string tip_hash;      // mandatory lowercase 64-hex hash at `height`
    std::string sha256;        // lowercase 64-hex sha256 of the tarball
    std::string genesis;       // mandatory lowercase 64-hex genesis id
    std::string published_at;  // informational timestamp ("" if absent)
    bool        syntax_valid = false; // exact-one critical fields, no bad value
};

// Parse `key=value` lines (CR/LF and trailing-whitespace tolerant; unknown
// keys ignored for forward compatibility). Purely syntactic — trust comes
// from VerifySignedSnapshotManifest below.
inline SnapshotManifest ParseSnapshotManifest(const std::string& text) {
    SnapshotManifest m;
    size_t height_count = 0;
    size_t tip_hash_count = 0;
    size_t sha256_count = 0;
    size_t genesis_count = 0;
    size_t published_at_count = 0;
    bool malformed = false;
    size_t pos = 0;
    while (pos <= text.size()) {
        std::string line;
        size_t nl = text.find('\n', pos);
        if (nl == std::string::npos) { line = text.substr(pos); pos = text.size() + 1; }
        else                         { line = text.substr(pos, nl - pos); pos = nl + 1; }
        while (!line.empty() &&
               (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
            line.pop_back();
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq);
        std::string v = line.substr(eq + 1);
        if (k == "height") {
            ++height_count;
            if (!ParseCanonicalUint64Text(v, m.height)) {
                m.height = 0;
                malformed = true;
            }
        } else if (k == "tip_hash") {
            ++tip_hash_count;
            m.tip_hash = v;
        } else if (k == "sha256") {
            ++sha256_count;
            m.sha256 = v;
        } else if (k == "genesis") {
            ++genesis_count;
            m.genesis = v;
        } else if (k == "published_at") {
            ++published_at_count;
            m.published_at = v;
        }
    }
    m.syntax_valid = !malformed && height_count == 1 && tip_hash_count == 1 &&
                     sha256_count == 1 &&
                     genesis_count == 1 && published_at_count <= 1;
    return m;
}

inline bool SnapshotManifestIsHex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

// Verify `sig` (raw ML-DSA-65 bytes, exactly as `veld-keygen sign-release`
// writes them) over the EXACT manifest bytes against `pub`, then parse.
// FAIL-CLOSED: returns true ONLY if the signature verifies AND the manifest
// carries a well-formed sha256 (64-hex), a height > 0, an exact tip hash, and
// a mandatory well-formed genesis (all lowercase 64-hex) — a signed-but-
// defective manifest confers no authority. `out` is populated only on success.
inline bool VerifySignedSnapshotManifest(const std::vector<uint8_t>& manifest_bytes,
                                         const std::vector<uint8_t>& sig,
                                         const Secp256k1PubKey&      pub,
                                         SnapshotManifest&           out) {
    out = SnapshotManifest{};
    if (manifest_bytes.empty()) return false;
    if (!VerifyReleaseSignatureBytes(manifest_bytes, sig, pub)) return false;
    SnapshotManifest m = ParseSnapshotManifest(
        std::string(manifest_bytes.begin(), manifest_bytes.end()));
    if (!m.syntax_valid) return false;
    if (m.height == 0) return false;
    if (!SnapshotManifestIsHex64(m.tip_hash)) return false;
    if (!SnapshotManifestIsHex64(m.sha256)) return false;
    if (!SnapshotManifestIsHex64(m.genesis)) return false;
    out = m;
    return true;
}

// Production path: accept EITHER the pinned SNAPSHOT-signing key (the dedicated
// key the hourly publisher uses) OR the pinned RELEASE key (back-compat:
// snapshots cut before the dedicated snapshot key were release-signed). Either
// valid signature authenticates the manifest; both keys are compile-time pinned.
inline bool VerifySignedSnapshotManifestPinned(const std::vector<uint8_t>& manifest_bytes,
                                               const std::vector<uint8_t>& sig,
                                               SnapshotManifest&           out) {
    Secp256k1PubKey pub{};
    if (LoadPinnedSnapshotPubkey(pub) &&
        VerifySignedSnapshotManifest(manifest_bytes, sig, pub, out)) {
        return true;
    }
    if (LoadPinnedReleasePubkey(pub) &&
        VerifySignedSnapshotManifest(manifest_bytes, sig, pub, out)) {
        return true;
    }
    out = SnapshotManifest{};
    return false;
}

}  // namespace veld
