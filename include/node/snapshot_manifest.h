#pragma once
// Signed snapshot-manifest verification for authenticated recovery. The pinned
// ML-DSA-65 release key authenticates the archive digest, height, canonical tip,
// and genesis identity before any manifest field is used. Compiled checkpoints
// independently verify extracted block history.
#include "../crypto/release_verify.h"
#include "../core/canonical_numeric.h"
#include <cctype>
#include <cstdint>
#include <iterator>
#include <string>
#include <vector>

namespace veld {

struct SnapshotManifest {
    std::string format;
    std::string network;
    std::string state_digest;
    std::string archive_format;
    std::string archive_file;
    uint64_t    anchor_height = 0;
    std::string anchor_hash;
    uint64_t    height = 0;    // publisher tip the snapshot was cut at
    std::string tip_hash;      // mandatory lowercase 64-hex hash at `height`
    std::string sha256;        // lowercase 64-hex SHA-256 of the tarball
    std::string genesis;       // mandatory lowercase 64-hex internal genesis id
    std::string published_at;
    bool        syntax_valid = false;
};

inline constexpr const char* SNAPSHOT_MANIFEST_FORMAT =
    "VELD_SNAPSHOT_MANIFEST_V2";
inline constexpr const char* SNAPSHOT_ARCHIVE_FORMAT =
    "leveldb-tar-gzip-v1";

// Parse the version-2 snapshot manifest.  This format is intentionally closed:
// an unknown, duplicate, empty, whitespace-normalized, or out-of-order field
// is rejected.  Snapshot manifests are trust inputs, so forward extensions
// require a new explicit format instead of being silently ignored by old
// clients.
inline SnapshotManifest ParseSnapshotManifest(const std::string& text) {
    SnapshotManifest m;
    if (text.empty() || text.back() != '\n' ||
        text.find('\r') != std::string::npos ||
        text.find('\0') != std::string::npos) {
        return m;
    }
    static constexpr const char* keys[] = {
        "format", "network", "state_digest", "archive_format",
        "archive_file", "genesis", "anchor_height", "anchor_hash",
        "height", "tip_hash", "sha256", "published_at",
    };
    size_t field = 0;
    size_t pos = 0;
    while (pos < text.size()) {
        const size_t nl = text.find('\n', pos);
        if (nl == std::string::npos || nl == pos || field >= std::size(keys))
            return SnapshotManifest{};
        const std::string line = text.substr(pos, nl - pos);
        pos = nl + 1;
        const size_t eq = line.find('=');
        if (eq == std::string::npos || eq == 0 || eq + 1 == line.size() ||
            line.find_first_of(" \t") != std::string::npos ||
            line.substr(0, eq) != keys[field]) {
            return SnapshotManifest{};
        }
        const std::string value = line.substr(eq + 1);
        switch (field) {
        case 0: m.format = value; break;
        case 1: m.network = value; break;
        case 2: m.state_digest = value; break;
        case 3: m.archive_format = value; break;
        case 4: m.archive_file = value; break;
        case 5: m.genesis = value; break;
        case 6:
            if (!ParseCanonicalUint64Text(value, m.anchor_height))
                return SnapshotManifest{};
            break;
        case 7: m.anchor_hash = value; break;
        case 8:
            if (!ParseCanonicalUint64Text(value, m.height))
                return SnapshotManifest{};
            break;
        case 9: m.tip_hash = value; break;
        case 10: m.sha256 = value; break;
        case 11: m.published_at = value; break;
        default: return SnapshotManifest{};
        }
        ++field;
    }
    m.syntax_valid = field == std::size(keys) &&
                     m.format == SNAPSHOT_MANIFEST_FORMAT &&
                     m.archive_format == SNAPSHOT_ARCHIVE_FORMAT &&
                     m.anchor_height > 0 && m.height >= m.anchor_height;
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
// FAIL-CLOSED: returns true only when the signature and every closed-schema
// identity field validate. `out` is populated only on success.
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
    if (m.format != SNAPSHOT_MANIFEST_FORMAT ||
        m.archive_format != SNAPSHOT_ARCHIVE_FORMAT ||
        m.network.empty() || m.state_digest.empty() ||
        m.archive_file.empty() || m.published_at.empty() ||
        m.anchor_height == 0 || m.height < m.anchor_height) return false;
    if (!SnapshotManifestIsHex64(m.tip_hash)) return false;
    if (!SnapshotManifestIsHex64(m.sha256)) return false;
    if (!SnapshotManifestIsHex64(m.genesis)) return false;
    if (!SnapshotManifestIsHex64(m.anchor_hash)) return false;
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
