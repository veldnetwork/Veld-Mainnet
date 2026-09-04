#pragma once

// Authenticated public-mainnet snapshot acquisition and publication.
//
// A snapshot is an availability optimization, never a consensus authority.
// The signed v2 manifest binds the public deployment, state schema, compiled
// genesis, and launch-chain block 1. Extracted bytes are replayed through the
// normal consensus engine before publication, and the resulting state remains
// quarantined from RPC, inbound P2P, explorer, and mining until an independent
// genesis-to-snapshot IBD reaches the exact same tip and state digest.

#include "snapshot_manifest.h"
#include "../compat/process.h"
#include "../compat/platform.h"
#include "../core/block.h"
#include "../core/constants.h"
#include "../core/hash.h"
#include "../core/version.h"
#include "../wallet/secure_channel_file.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace veld::snapshot_bootstrap {

inline constexpr const char* PUBLIC_SNAPSHOT_BASE = "https://veld.network/downloads/";
inline constexpr const char* PUBLIC_SNAPSHOT_MANIFEST = "veld-chain-snapshot.manifest";
inline constexpr const char* PUBLIC_SNAPSHOT_SIGNATURE = "veld-chain-snapshot.manifest.sig";
inline constexpr const char* PUBLIC_SNAPSHOT_STATE_DIGEST = "v8";
inline constexpr uint64_t PUBLIC_SNAPSHOT_MAX_ARCHIVE_BYTES = 16ULL * 1024ULL * 1024ULL * 1024ULL;
inline constexpr uint64_t PUBLIC_SNAPSHOT_MAX_EXPANDED_BYTES = 64ULL * 1024ULL * 1024ULL * 1024ULL;
inline constexpr size_t PUBLIC_SNAPSHOT_MAX_MEMBERS = 16384;

struct PreparedPublicSnapshot {
    std::filesystem::path scratch_root;
    std::filesystem::path archive_path;
    std::filesystem::path manifest_path;
    std::filesystem::path signature_path;
    SnapshotManifest manifest;
    std::string manifest_sha256;
    std::string signature_sha256;
};

struct SnapshotCandidateValidation {
    bool passed{false};
    std::string consensus_state_sha256;
    std::string error;
};

inline bool IsReparsePoint(const std::filesystem::path& path) {
#ifdef _WIN32
    const DWORD attributes = ::GetFileAttributesW(path.c_str());
    return attributes == INVALID_FILE_ATTRIBUTES ||
           (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    (void)path;
    return false;
#endif
}

inline bool IsPlainNlinkOneFile(const std::filesystem::path& path, uint64_t maximum_bytes,
                                uint64_t* size_out = nullptr) {
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(path, ec);
    if (ec || !std::filesystem::is_regular_file(status) || std::filesystem::is_symlink(status) ||
        IsReparsePoint(path))
        return false;
    const uint64_t size = std::filesystem::file_size(path, ec);
    if (ec || size == 0 || size > maximum_bytes)
        return false;
    const uintmax_t links = std::filesystem::hard_link_count(path, ec);
    if (ec || links != 1)
        return false;
    if (size_out)
        *size_out = size;
    return true;
}

inline std::optional<std::vector<uint8_t>> ReadBoundedPlainFile(const std::filesystem::path& path,
                                                                uint64_t maximum_bytes) {
    uint64_t size = 0;
    if (!IsPlainNlinkOneFile(path, maximum_bytes, &size))
        return std::nullopt;
    std::ifstream input(path, std::ios::binary);
    if (!input)
        return std::nullopt;
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    if (!input.read(reinterpret_cast<char*>(bytes.data()),
                    static_cast<std::streamsize>(bytes.size())) ||
        input.peek() != std::char_traits<char>::eof())
        return std::nullopt;
    return bytes;
}

inline std::optional<std::string> Sha256File(const std::filesystem::path& path,
                                             uint64_t maximum_bytes) {
    uint64_t size = 0;
    if (!IsPlainNlinkOneFile(path, maximum_bytes, &size))
        return std::nullopt;
    std::ifstream input(path, std::ios::binary);
    if (!input)
        return std::nullopt;
    SHA256 hasher;
    std::array<uint8_t, 64 * 1024> buffer{};
    uint64_t total = 0;
    while (input) {
        input.read(reinterpret_cast<char*>(buffer.data()),
                   static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count < 0 || total > maximum_bytes - static_cast<uint64_t>(count))
            return std::nullopt;
        if (count != 0) {
            hasher.update(buffer.data(), static_cast<size_t>(count));
            total += static_cast<uint64_t>(count);
        }
    }
    if (!input.eof() || total != size)
        return std::nullopt;
    return HashToHex(hasher.digest());
}

inline bool IsCanonicalPublishedAt(const std::string& value) {
    if (value.size() != 20 || value[4] != '-' || value[7] != '-' || value[10] != 'T' ||
        value[13] != ':' || value[16] != ':' || value[19] != 'Z')
        return false;
    for (size_t i = 0; i < value.size(); ++i) {
        if (i == 4 || i == 7 || i == 10 || i == 13 || i == 16 || i == 19)
            continue;
        if (value[i] < '0' || value[i] > '9')
            return false;
    }
    const auto two = [&](size_t offset) {
        return static_cast<unsigned>((value[offset] - '0') * 10 + (value[offset + 1] - '0'));
    };
    return two(5) >= 1 && two(5) <= 12 && two(8) >= 1 && two(8) <= 31 && two(11) <= 23 &&
           two(14) <= 59 && two(17) <= 60;
}

inline bool IsCanonicalArchiveName(const SnapshotManifest& manifest) {
    if (manifest.archive_file.size() > 128 ||
        manifest.archive_file.find("..") != std::string::npos ||
        manifest.archive_file.find_first_of("/\\:\0\r\n\t ") != std::string::npos)
        return false;
    for (char c : manifest.archive_file) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.'))
            return false;
    }
    return manifest.archive_file == "veld-chain-snapshot-h" + std::to_string(manifest.height) +
                                        "-" + manifest.sha256.substr(0, 16) + ".tar.gz";
}

inline bool ManifestMatchesCompiledPublicChain(const SnapshotManifest& manifest,
                                               std::string* error = nullptr) {
    const std::string internal_genesis = HashToHex(CreateGenesisBlock().GetHash());
    if (!manifest.syntax_valid || manifest.network != DEPLOYMENT_PROFILE_ID ||
        manifest.state_digest != PUBLIC_SNAPSHOT_STATE_DIGEST ||
        manifest.genesis != internal_genesis ||
        manifest.anchor_height != SNAPSHOT_LAUNCH_ANCHOR_HEIGHT ||
        manifest.anchor_hash != SNAPSHOT_LAUNCH_ANCHOR_HASH ||
        !SnapshotManifestIsHex64(manifest.tip_hash) || !SnapshotManifestIsHex64(manifest.sha256) ||
        !IsCanonicalPublishedAt(manifest.published_at) || !IsCanonicalArchiveName(manifest)) {
        if (error)
            *error = "signed manifest does not match the compiled public launch chain";
        return false;
    }
    return true;
}

inline bool SafeArchiveMemberName(std::string name) {
    if (name.size() > 240 || name.empty() || name.front() == '/' || name.front() == '\\' ||
        name.find('\\') != std::string::npos || name.find(':') != std::string::npos ||
        name.find_first_of("\0\r\n\t ") != std::string::npos)
        return false;
    while (!name.empty() && name.back() == '/')
        name.pop_back();
    if (name.empty())
        return false;
    std::filesystem::path path(name);
    if (path.is_absolute() || path.has_root_name() || path.has_root_directory())
        return false;
    size_t components = 0;
    for (const auto& component : path) {
        const std::string value = component.string();
        if (value.empty() || value == "." || value == "..")
            return false;
        ++components;
    }
    if (components == 1)
        return name == "db";
    const std::string normalized = path.generic_string();
    if (components == 2) {
        return normalized == "db/blocks" || normalized == "db/index" || normalized == "db/utxo";
    }
    if (components != 3)
        return false;
    auto it = path.begin();
    if (it++->string() != "db")
        return false;
    const std::string database = it++->string();
    if (database != "blocks" && database != "index" && database != "utxo")
        return false;
    const std::string leaf = it->string();
    if (leaf.empty() || leaf.size() > 96)
        return false;
    for (char c : leaf) {
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '-' || c == '.'))
            return false;
    }
    if (leaf == "CURRENT" || leaf == "LOCK" || leaf == "LOG" || leaf == "LOG.old")
        return true;
    const auto digits_after = [&](const std::string& prefix, const std::string& suffix) {
        if (leaf.size() <= prefix.size() + suffix.size() || leaf.rfind(prefix, 0) != 0 ||
            leaf.substr(leaf.size() - suffix.size()) != suffix)
            return false;
        for (size_t i = prefix.size(); i < leaf.size() - suffix.size(); ++i)
            if (leaf[i] < '0' || leaf[i] > '9')
                return false;
        return true;
    };
    return digits_after("MANIFEST-", "") || digits_after("OPTIONS-", "") ||
           digits_after("", ".log") || digits_after("", ".ldb");
}

inline bool ValidateArchiveListings(const std::filesystem::path& names_path,
                                    const std::filesystem::path& detail_path,
                                    std::string* error = nullptr) {
    auto names_bytes = ReadBoundedPlainFile(names_path, 4U * 1024U * 1024U);
    auto detail_bytes = ReadBoundedPlainFile(detail_path, 8U * 1024U * 1024U);
    if (!names_bytes || !detail_bytes) {
        if (error)
            *error = "archive member listing is missing or oversized";
        return false;
    }
    const std::string names(names_bytes->begin(), names_bytes->end());
    const std::string details(detail_bytes->begin(), detail_bytes->end());
    if (names.find('\0') != std::string::npos || details.find('\0') != std::string::npos) {
        if (error)
            *error = "archive member listing contains NUL";
        return false;
    }
    std::istringstream names_in(names);
    std::istringstream details_in(details);
    std::string name;
    std::string detail;
    std::vector<std::string> seen;
    while (std::getline(names_in, name)) {
        if (!name.empty() && name.back() == '\r')
            name.pop_back();
        if (!std::getline(details_in, detail)) {
            if (error)
                *error = "archive type listing is shorter than name listing";
            return false;
        }
        if (!detail.empty() && detail.back() == '\r')
            detail.pop_back();
        if (detail.empty() || (detail.front() != '-' && detail.front() != 'd') ||
            !SafeArchiveMemberName(name)) {
            if (error)
                *error = "archive contains an unsafe member";
            return false;
        }
        std::string canonical = name;
        while (!canonical.empty() && canonical.back() == '/')
            canonical.pop_back();
        if (std::find(seen.begin(), seen.end(), canonical) != seen.end() ||
            seen.size() >= PUBLIC_SNAPSHOT_MAX_MEMBERS) {
            if (error)
                *error = "archive contains duplicate or excessive members";
            return false;
        }
        seen.push_back(std::move(canonical));
    }
    if (std::getline(details_in, detail) || seen.empty()) {
        if (error)
            *error = "archive member listings do not match";
        return false;
    }
    return true;
}

inline bool ValidateExtractedLevelDbTree(const std::filesystem::path& root,
                                         std::string* error = nullptr) {
    std::error_code ec;
    const auto absolute_root = std::filesystem::absolute(root, ec).lexically_normal();
    if (ec || IsReparsePoint(absolute_root)) {
        if (error)
            *error = "snapshot staging root is invalid";
        return false;
    }
    size_t members = 0;
    uint64_t expanded = 0;
    std::array<bool, 3> current{{false, false, false}};
    std::array<bool, 3> manifest{{false, false, false}};
    for (std::filesystem::recursive_directory_iterator it(absolute_root, ec), end; !ec && it != end;
         it.increment(ec)) {
        if (++members > PUBLIC_SNAPSHOT_MAX_MEMBERS || IsReparsePoint(it->path())) {
            if (error)
                *error = "snapshot staging tree has unsafe objects";
            return false;
        }
        const auto relative = it->path().lexically_relative(absolute_root);
        if (relative.empty() || !SafeArchiveMemberName(relative.generic_string())) {
            if (error)
                *error = "snapshot staging tree escapes the expected layout";
            return false;
        }
        const auto status = it->symlink_status(ec);
        if (ec || std::filesystem::is_symlink(status))
            return false;
        if (std::filesystem::is_directory(status))
            continue;
        if (!std::filesystem::is_regular_file(status)) {
            if (error)
                *error = "snapshot contains a special file";
            return false;
        }
        const uintmax_t links = std::filesystem::hard_link_count(it->path(), ec);
        const uint64_t size = std::filesystem::file_size(it->path(), ec);
        if (ec || links != 1 || size > PUBLIC_SNAPSHOT_MAX_EXPANDED_BYTES - expanded) {
            if (error)
                *error = "snapshot file identity or expanded-size limit failed";
            return false;
        }
        expanded += size;
        const auto parts = relative;
        auto p = parts.begin();
        if (p == parts.end() || p++->string() != "db" || p == parts.end())
            return false;
        const std::string database = p++->string();
        const size_t index = database == "blocks" ? 0 : database == "utxo" ? 1 : 2;
        if (p == parts.end())
            return false;
        const std::string leaf = p->string();
        if (leaf == "CURRENT")
            current[index] = true;
        if (leaf.rfind("MANIFEST-", 0) == 0)
            manifest[index] = true;
    }
    if (ec || !std::all_of(current.begin(), current.end(), [](bool v) { return v; }) ||
        !std::all_of(manifest.begin(), manifest.end(), [](bool v) { return v; })) {
        if (error)
            *error = "snapshot LevelDB layout is incomplete";
        return false;
    }
    return true;
}

inline std::optional<std::filesystem::path>
CreateExclusiveScratchRoot(const std::filesystem::path& data_dir) {
    std::array<uint8_t, 16> random{};
    if (!compat::SecureRandom(random.data(), random.size()))
        return std::nullopt;
    const auto root = data_dir / (".snapshot-stage-" + BytesToHex(random.data(), random.size()));
    std::error_code ec;
    if (!std::filesystem::create_directory(root, ec) || ec)
        return std::nullopt;
#ifndef _WIN32
    if (::chmod(root.c_str(), 0700) != 0) {
        std::filesystem::remove(root, ec);
        return std::nullopt;
    }
#endif
    return root;
}

inline bool DownloadFixedHttpsObject(const std::string& url,
                                     const std::filesystem::path& destination,
                                     uint64_t maximum_bytes, std::chrono::milliseconds deadline) {
    const std::string curl = compat::TrustedSystemCurlExecutable();
    if (curl.empty())
        return false;
    const auto result = compat::RunProcessToBoundedFile(
        {curl, "--disable", "--fail", "--silent", "--show-error", "--proto", "=https", "--tlsv1.2",
         "--max-time", std::to_string(std::max<int64_t>(1, deadline.count() / 1000)),
         "--max-filesize", std::to_string(maximum_bytes), url},
        destination.string(), maximum_bytes, deadline);
    return static_cast<bool>(result);
}

inline bool PreparePublicSnapshot(const std::filesystem::path& data_dir, uint64_t local_height,
                                  PreparedPublicSnapshot& out, std::string* error = nullptr) {
    out = PreparedPublicSnapshot{};
    auto scratch = CreateExclusiveScratchRoot(data_dir);
    if (!scratch) {
        if (error)
            *error = "cannot create exclusive snapshot staging directory";
        return false;
    }
    auto fail = [&](const std::string& reason) {
        if (error)
            *error = reason;
        std::error_code remove_error;
        std::filesystem::remove_all(*scratch, remove_error);
        return false;
    };
    out.scratch_root = *scratch;
    out.manifest_path = *scratch / PUBLIC_SNAPSHOT_MANIFEST;
    out.signature_path = *scratch / PUBLIC_SNAPSHOT_SIGNATURE;
    if (!DownloadFixedHttpsObject(std::string(PUBLIC_SNAPSHOT_BASE) + PUBLIC_SNAPSHOT_MANIFEST,
                                  out.manifest_path, 64U * 1024U, std::chrono::seconds(20)) ||
        !DownloadFixedHttpsObject(std::string(PUBLIC_SNAPSHOT_BASE) + PUBLIC_SNAPSHOT_SIGNATURE,
                                  out.signature_path, 64U * 1024U, std::chrono::seconds(20))) {
        return fail("signed snapshot manifest is unavailable");
    }
    auto manifest_bytes = ReadBoundedPlainFile(out.manifest_path, 64U * 1024U);
    auto signature_bytes = ReadBoundedPlainFile(out.signature_path, 64U * 1024U);
    if (!manifest_bytes || !signature_bytes ||
        !VerifySignedSnapshotManifestPinned(*manifest_bytes, *signature_bytes, out.manifest) ||
        !ManifestMatchesCompiledPublicChain(out.manifest, error)) {
        return fail(error && !error->empty()
                        ? *error
                        : "snapshot manifest signature or identity is invalid");
    }
    if (out.manifest.height <= local_height) {
        return fail("published snapshot is not ahead of the local chain");
    }
    const auto manifest_hash = Sha256File(out.manifest_path, 64U * 1024U);
    const auto signature_hash = Sha256File(out.signature_path, 64U * 1024U);
    if (!manifest_hash || !signature_hash)
        return fail("snapshot manifest files changed after signature verification");
    out.manifest_sha256 = *manifest_hash;
    out.signature_sha256 = *signature_hash;
    out.archive_path = *scratch / out.manifest.archive_file;
    if (!DownloadFixedHttpsObject(std::string(PUBLIC_SNAPSHOT_BASE) + out.manifest.archive_file,
                                  out.archive_path, PUBLIC_SNAPSHOT_MAX_ARCHIVE_BYTES,
                                  std::chrono::hours(2))) {
        return fail("snapshot archive download failed or exceeded its bound");
    }
    const auto archive_hash = Sha256File(out.archive_path, PUBLIC_SNAPSHOT_MAX_ARCHIVE_BYTES);
    if (!archive_hash || *archive_hash != out.manifest.sha256) {
        return fail("snapshot archive SHA-256 does not match the signed manifest");
    }
    const std::string tar = compat::TrustedSystemTarExecutable();
    if (tar.empty())
        return fail("trusted operating-system tar is unavailable");
    const auto names = *scratch / "members.names";
    const auto details = *scratch / "members.details";
    const auto names_result = compat::RunProcessToBoundedFile(
        {tar, "-tzf", out.manifest.archive_file}, names.string(), 4U * 1024U * 1024U,
        std::chrono::seconds(60), scratch->string());
    const auto detail_result = compat::RunProcessToBoundedFile(
        {tar, "-tvzf", out.manifest.archive_file}, details.string(), 8U * 1024U * 1024U,
        std::chrono::seconds(60), scratch->string());
    if (!names_result || !detail_result || !ValidateArchiveListings(names, details, error)) {
        return fail(error && !error->empty() ? *error
                                             : "snapshot archive listing validation failed");
    }
    const auto extract = *scratch / "extract";
    std::error_code ec;
    if (!std::filesystem::create_directory(extract, ec) || ec)
        return fail("cannot create exclusive archive extraction directory");
#ifndef _WIN32
    if (::chmod(extract.c_str(), 0700) != 0)
        return fail("cannot make archive extraction directory private");
#endif
    const auto extraction_log = *scratch / "extract.stdout";
    const auto extract_result = compat::RunProcessToBoundedFile(
        {tar, "-xzf", out.manifest.archive_file, "-C", "extract", "-k"}, extraction_log.string(),
        64U * 1024U, std::chrono::minutes(30), scratch->string());
    if (!extract_result || !ValidateExtractedLevelDbTree(extract, error)) {
        return fail(error && !error->empty() ? *error
                                             : "snapshot archive extraction validation failed");
    }
    const auto final_archive_hash = Sha256File(out.archive_path, PUBLIC_SNAPSHOT_MAX_ARCHIVE_BYTES);
    if (!final_archive_hash || *final_archive_hash != out.manifest.sha256)
        return fail("snapshot archive changed during extraction");
    return true;
}

inline std::string SnapshotHandoffReceiptBody(const PreparedPublicSnapshot& prepared,
                                              const SnapshotCandidateValidation& validation) {
    return "schema=VELD_SNAPSHOT_HANDOFF_V2\nnetwork=" + prepared.manifest.network +
           "\nmanifest_sha256=" + prepared.manifest_sha256 +
           "\nsignature_sha256=" + prepared.signature_sha256 +
           "\narchive_sha256=" + prepared.manifest.sha256 +
           "\nheight=" + std::to_string(prepared.manifest.height) +
           "\ntip_hash=" + prepared.manifest.tip_hash +
           "\nanchor_height=" + std::to_string(prepared.manifest.anchor_height) +
           "\nanchor_hash=" + prepared.manifest.anchor_hash +
           "\nstate_digest_schema=" + prepared.manifest.state_digest +
           "\nconsensus_state_sha256=" + validation.consensus_state_sha256 + "\n";
}

inline bool CommitPreparedPublicSnapshot(const std::filesystem::path& data_dir,
                                         const PreparedPublicSnapshot& prepared,
                                         const SnapshotCandidateValidation& validation,
                                         std::string* error = nullptr) {
    if (!validation.passed || !SnapshotManifestIsHex64(validation.consensus_state_sha256)) {
        if (error)
            *error = "snapshot candidate consensus validation did not pass";
        return false;
    }
    const auto extracted = prepared.scratch_root / "extract";
    const auto staged_db = extracted / "db";
    const auto staged_background = extracted / ".background-chainstate-required";
    std::error_code marker_error;
    if (!std::filesystem::is_regular_file(staged_background, marker_error) || marker_error ||
        IsReparsePoint(staged_background)) {
        if (error && error->empty())
            *error = "validated snapshot markers are absent";
        return false;
    }
    const auto handoff = extracted / ".snapshot-handoff";
    std::error_code ec;
    if (!std::filesystem::create_directory(handoff, ec) || ec) {
        if (error)
            *error = "cannot create staged snapshot handoff directory";
        return false;
    }
#ifndef _WIN32
    if (::chmod(handoff.c_str(), 0700) != 0) {
        if (error)
            *error = "cannot make staged snapshot handoff private";
        return false;
    }
#endif
    const auto manifest_bytes = ReadBoundedPlainFile(prepared.manifest_path, 64U * 1024U);
    const auto signature_bytes = ReadBoundedPlainFile(prepared.signature_path, 64U * 1024U);
    std::string write_error;
    if (!manifest_bytes || !signature_bytes ||
        !channel::secure_file::AtomicWriteNew((handoff / "manifest").string(), *manifest_bytes,
                                              &write_error, true) ||
        !channel::secure_file::AtomicWriteNew((handoff / "manifest.sig").string(), *signature_bytes,
                                              &write_error, true) ||
        !channel::secure_file::AtomicWriteText((handoff / "receipt").string(),
                                               SnapshotHandoffReceiptBody(prepared, validation),
                                               &write_error, true)) {
        if (error)
            *error = "cannot stage snapshot handoff: " + write_error;
        return false;
    }
    const auto live_db = data_dir / "db";
    const auto live_background = data_dir / ".background-chainstate-required";
    const auto live_handoff = data_dir / ".snapshot-handoff";
    std::array<uint8_t, 12> random{};
    if (!compat::SecureRandom(random.data(), random.size())) {
        if (error)
            *error = "cannot create snapshot quarantine identity";
        return false;
    }
    const auto quarantine =
        data_dir / (".snapshot-preimport-" + BytesToHex(random.data(), random.size()));
    if (!std::filesystem::create_directory(quarantine, ec) || ec) {
        if (error)
            *error = "cannot create snapshot rollback directory";
        return false;
    }
    bool old_db_moved = false;
    bool old_handoff_moved = false;
    bool new_db_moved = false;
    bool background_moved = false;
    try {
        if (std::filesystem::exists(live_background))
            throw std::runtime_error("a background-validation marker already exists");
        if (std::filesystem::exists(live_db)) {
            std::filesystem::rename(live_db, quarantine / "db");
            old_db_moved = true;
        }
        if (std::filesystem::exists(live_handoff)) {
            std::filesystem::rename(live_handoff, quarantine / "handoff");
            old_handoff_moved = true;
        }
        std::filesystem::rename(staged_db, live_db);
        new_db_moved = true;
        std::filesystem::rename(staged_background, live_background);
        background_moved = true;
        std::filesystem::rename(handoff, live_handoff);
    } catch (const std::exception& exception) {
        std::error_code rollback_error;
        if (background_moved)
            std::filesystem::rename(live_background, staged_background, rollback_error);
        if (new_db_moved)
            std::filesystem::rename(live_db, staged_db, rollback_error);
        if (old_handoff_moved)
            std::filesystem::rename(quarantine / "handoff", live_handoff, rollback_error);
        if (old_db_moved)
            std::filesystem::rename(quarantine / "db", live_db, rollback_error);
        if (error)
            *error = std::string("snapshot publication failed: ") + exception.what();
        return false;
    }
    std::filesystem::remove_all(prepared.scratch_root, ec);
    return true;
}

inline std::optional<SnapshotManifest>
VerifyInstalledSnapshotHandoff(const std::filesystem::path& data_dir,
                               std::string* error = nullptr) {
    const auto handoff = data_dir / ".snapshot-handoff";
    const auto manifest_path = handoff / "manifest";
    const auto signature_path = handoff / "manifest.sig";
    const auto receipt_path = handoff / "receipt";
    auto manifest_bytes = ReadBoundedPlainFile(manifest_path, 64U * 1024U);
    auto signature_bytes = ReadBoundedPlainFile(signature_path, 64U * 1024U);
    auto receipt_bytes = ReadBoundedPlainFile(receipt_path, 8U * 1024U);
    if (!manifest_bytes || !signature_bytes || !receipt_bytes) {
        if (error)
            *error = "snapshot handoff files are missing or unsafe";
        return std::nullopt;
    }
    SnapshotManifest manifest;
    if (!VerifySignedSnapshotManifestPinned(*manifest_bytes, *signature_bytes, manifest) ||
        !ManifestMatchesCompiledPublicChain(manifest, error))
        return std::nullopt;
    const auto manifest_hash = Sha256File(manifest_path, 64U * 1024U);
    const auto signature_hash = Sha256File(signature_path, 64U * 1024U);
    const std::string receipt(receipt_bytes->begin(), receipt_bytes->end());
    const std::array<std::string, 11> expected{{
        "schema=VELD_SNAPSHOT_HANDOFF_V2",
        "network=" + manifest.network,
        "manifest_sha256=" + (manifest_hash ? *manifest_hash : ""),
        "signature_sha256=" + (signature_hash ? *signature_hash : ""),
        "archive_sha256=" + manifest.sha256,
        "height=" + std::to_string(manifest.height),
        "tip_hash=" + manifest.tip_hash,
        "anchor_height=" + std::to_string(manifest.anchor_height),
        "anchor_hash=" + manifest.anchor_hash,
        "state_digest_schema=" + manifest.state_digest,
        "consensus_state_sha256=",
    }};
    std::istringstream input(receipt);
    std::string line;
    for (size_t i = 0; i < expected.size(); ++i) {
        if (!std::getline(input, line) ||
            (i + 1 == expected.size()
                 ? line.rfind(expected[i], 0) != 0 ||
                       !SnapshotManifestIsHex64(line.substr(expected[i].size()))
                 : line != expected[i])) {
            if (error)
                *error = "snapshot handoff receipt is not canonical";
            return std::nullopt;
        }
    }
    if (std::getline(input, line)) {
        if (error)
            *error = "snapshot handoff receipt has trailing fields";
        return std::nullopt;
    }
    return manifest;
}

} // namespace veld::snapshot_bootstrap
