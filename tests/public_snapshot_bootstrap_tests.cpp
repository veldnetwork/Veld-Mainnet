#include "../include/node/public_snapshot_bootstrap.h"
#include "../include/network/p2p.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#if !defined(VELD_PUBLIC_MAINNET) || \
    !defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP) || \
    !defined(VELD_USE_LEVELDB)
#error "public snapshot tests require the production snapshot profile"
#endif

namespace {

size_t checks = 0;
size_t failures = 0;

void Check(bool condition, const char* label) {
    ++checks;
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << label << "\n";
    }
}

void Write(const std::filesystem::path& path, const std::string& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (!output) throw std::runtime_error("fixture write failed");
}

std::string CanonicalManifest() {
    const std::string archive_hash(64, 'a');
    return std::string("format=VELD_SNAPSHOT_MANIFEST_V2\n") +
        "network=veld-public-mainnet-v2\n" +
        "state_digest=v8\n" +
        "archive_format=leveldb-tar-gzip-v1\n" +
        "archive_file=veld-chain-snapshot-h223-" +
        archive_hash.substr(0, 16) + ".tar.gz\n" +
        "genesis=" + veld::HashToHex(veld::CreateGenesisBlock().GetHash()) +
        "\nanchor_height=1\nanchor_hash=" +
        std::string(veld::SNAPSHOT_LAUNCH_ANCHOR_HASH) +
        "\nheight=223\ntip_hash=" + std::string(64, 'b') +
        "\nsha256=" + archive_hash +
        "\npublished_at=2026-09-02T23:59:59Z\n";
}

}  // namespace

int main() {
    using namespace veld;
    using namespace veld::snapshot_bootstrap;

    const std::string canonical = CanonicalManifest();
    SnapshotManifest manifest = ParseSnapshotManifest(canonical);
    std::string error;
    Check(manifest.syntax_valid, "canonical v2 manifest parses");
    Check(ManifestMatchesCompiledPublicChain(manifest, &error),
          "canonical v2 manifest binds compiled launch chain");
    Check(IsCanonicalArchiveName(manifest),
          "archive name binds height and digest");

    Check(!ParseSnapshotManifest(
        "height=8377\ntip_hash=" + std::string(64, '0') + "\nsha256=" +
        std::string(64, '1') + "\ngenesis=" +
        HashToHex(CreateGenesisBlock().GetHash()) +
        "\npublished_at=2026-09-02T14:03:08Z\n").syntax_valid,
        "legacy public v1 manifest is rejected");
    Check(!ParseSnapshotManifest(canonical.substr(0, canonical.size() - 1))
               .syntax_valid,
          "unterminated manifest is rejected");
    Check(!ParseSnapshotManifest(canonical + "height=223\n").syntax_valid,
          "duplicate or trailing field is rejected");
    std::string reordered = canonical;
    const auto network = reordered.find("network=");
    const auto state = reordered.find("state_digest=");
    reordered.replace(network, state - network,
                      "state_digest=v8\n");
    Check(!ParseSnapshotManifest(reordered).syntax_valid,
          "reordered fields are rejected");
    std::string whitespace = canonical;
    whitespace.replace(whitespace.find("height=223"), 10, "height= 223");
    Check(!ParseSnapshotManifest(whitespace).syntax_valid,
          "hidden whitespace is rejected");
    std::string carriage = canonical;
    carriage.insert(carriage.find('\n'), 1, '\r');
    Check(!ParseSnapshotManifest(carriage).syntax_valid,
          "carriage returns are rejected");
    std::string leading_zero = canonical;
    leading_zero.replace(leading_zero.find("height=223"), 10, "height=0223");
    Check(!ParseSnapshotManifest(leading_zero).syntax_valid,
          "noncanonical height is rejected");

    SnapshotManifest wrong = manifest;
    wrong.anchor_hash[0] = wrong.anchor_hash[0] == '0' ? '1' : '0';
    Check(!ManifestMatchesCompiledPublicChain(wrong, &error),
          "wrong launch-chain anchor is rejected");
    wrong = manifest;
    wrong.network = "veld-public-testnet-v1";
    Check(!ManifestMatchesCompiledPublicChain(wrong, &error),
          "wrong network is rejected");
    wrong = manifest;
    wrong.archive_file = "other.tar.gz";
    Check(!ManifestMatchesCompiledPublicChain(wrong, &error),
          "unbound archive filename is rejected");
    wrong = manifest;
    wrong.sha256[0] = 'A';
    Check(!ManifestMatchesCompiledPublicChain(wrong, &error),
          "noncanonical digest is rejected");

    Check(SafeArchiveMemberName("db/blocks/MANIFEST-000001"),
          "canonical LevelDB manifest member accepted");
    Check(SafeArchiveMemberName("db/utxo/000123.ldb"),
          "canonical LevelDB table member accepted");
    Check(!SafeArchiveMemberName("../db/blocks/CURRENT"),
          "parent traversal rejected");
    Check(!SafeArchiveMemberName("db/blocks/../../escape"),
          "nested traversal rejected");
    Check(!SafeArchiveMemberName("db/blocks/link target"),
          "whitespace member rejected");
    Check(!SafeArchiveMemberName("db/other/CURRENT"),
          "unexpected database rejected");
    Check(!SafeArchiveMemberName("db/blocks/CURRENT/extra"),
          "unexpected member depth rejected");

    const auto suffix = std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count());
    const auto root = std::filesystem::temp_directory_path() /
        ("veld-public-snapshot-tests-" + suffix);
    std::filesystem::create_directories(root);
    const auto names = root / "names";
    const auto details = root / "details";
    const std::string members =
        "db/\ndb/blocks/\ndb/blocks/CURRENT\n"
        "db/blocks/MANIFEST-000001\ndb/index/\ndb/index/CURRENT\n"
        "db/index/MANIFEST-000001\ndb/utxo/\ndb/utxo/CURRENT\n"
        "db/utxo/MANIFEST-000001\n";
    const std::string types =
        "drwx------\ndrwx------\n-rw-------\n-rw-------\n"
        "drwx------\n-rw-------\n-rw-------\ndrwx------\n"
        "-rw-------\n-rw-------\n";
    Write(names, members);
    Write(details, types);
    Check(ValidateArchiveListings(names, details, &error),
          "canonical archive listing accepted");
    Write(names, members + "db/blocks/CURRENT\n");
    Write(details, types + "-rw-------\n");
    Check(!ValidateArchiveListings(names, details, &error),
          "duplicate archive member rejected");
    Write(names, members);
    std::string link_types = types;
    link_types[link_types.find("-rw-------")] = 'l';
    Write(details, link_types);
    Check(!ValidateArchiveListings(names, details, &error),
          "archive symlink member rejected");

    const auto extracted = root / "extract";
    for (const char* database : {"blocks", "index", "utxo"}) {
        const auto directory = extracted / "db" / database;
        std::filesystem::create_directories(directory);
        Write(directory / "CURRENT", "MANIFEST-000001\n");
        Write(directory / "MANIFEST-000001", "fixture\n");
    }
    Check(ValidateExtractedLevelDbTree(extracted, &error),
          "canonical extracted LevelDB tree accepted");
    Write(extracted / "db" / "blocks" / "unexpected.bin", "x");
    Check(!ValidateExtractedLevelDbTree(extracted, &error),
          "unexpected extracted file rejected");
    std::filesystem::remove(extracted / "db" / "blocks" / "unexpected.bin");
    std::filesystem::create_hard_link(
        extracted / "db" / "blocks" / "CURRENT",
        extracted / "db" / "blocks" / "000001.ldb");
    Check(!ValidateExtractedLevelDbTree(extracted, &error),
          "external hardlink identity rejected");

    Check(IsBackgroundValidationInboundCommand(MessageType::VERSION) &&
          IsBackgroundValidationInboundCommand(MessageType::BLOCK) &&
          IsBackgroundValidationInboundCommand(MessageType::PING),
          "background validator accepts only sync primitives");
    for (const char* command : {
             MessageType::TX, MessageType::GETDATA, MessageType::GETBLOCKS,
             MessageType::MEMPOOL, MessageType::SOLUTION,
             MessageType::FINVOTE, MessageType::PUNCHREQ,
             MessageType::ONIONADV}) {
        Check(!IsBackgroundValidationInboundCommand(command),
              "background validator rejects active protocol surface");
    }

    std::error_code cleanup_error;
    std::filesystem::remove_all(root, cleanup_error);
    Check(!cleanup_error && !std::filesystem::exists(root),
          "snapshot fixtures cleaned up");

    std::cout << (failures == 0 ? "PASS " : "FAIL ")
              << "public_snapshot_bootstrap_tests checks=" << checks << "\n";
    return failures == 0 ? 0 : 1;
}
