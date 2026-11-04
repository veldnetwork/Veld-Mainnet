// Exercise the production fixed-HTTPS acquisition path in disposable storage.
#include "node/public_snapshot_bootstrap.h"
#include <filesystem>
#include <iostream>

#if !defined(VELD_PUBLIC_RELEASE) || !defined(VELD_PUBLIC_MAINNET) || \
    !defined(VELD_MAINNET_POW) || !defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
#error "This qualification requires the public snapshot profile"
#endif

namespace fs = std::filesystem;
namespace sb = veld::snapshot_bootstrap;

int main(int argc, char** argv) {
    try {
        if (argc != 2 || fs::exists(argv[1]))
            throw std::runtime_error("new disposable root required");
        const auto root = fs::absolute(argv[1]);
        if (root.parent_path() != "/var/tmp" ||
            !root.filename().string().starts_with("veld-native-snapshot-acquire-"))
            throw std::runtime_error("unexpected qualification path");
        std::string error;
        if (!veld::channel::secure_file::EnsurePrivateDirectory(root.string(), &error))
            throw std::runtime_error(error);
        const auto data = root / "client";
        sb::PreparedPublicSnapshot prepared;
        if (!sb::PreparePublicSnapshot(data, 0, prepared, &error))
            throw std::runtime_error(error);
        const auto extract = prepared.scratch_root / "extract";
        if (!fs::is_regular_file(extract / "network.identity") || fs::exists(data / "db") ||
            !veld::ValidateOrCreatePublicNetworkIdentity(extract.string(), &error))
            throw std::runtime_error("staging identity or publication boundary differs");
        sb::SnapshotCandidateValidation incomplete;
        if (sb::CommitPreparedPublicSnapshot(data, prepared, incomplete, &error) ||
            error != "snapshot candidate consensus validation did not pass" || fs::exists(data / "db"))
            throw std::runtime_error("unvalidated snapshot was admitted");
        std::cout << "PASS PUBLIC_SNAPSHOT_ACQUISITION height=" << prepared.manifest.height
                  << " tip=" << prepared.manifest.tip_hash
                  << " archive_sha256=" << prepared.manifest.sha256
                  << " scratch=" << prepared.scratch_root.string()
                  << " unvalidated_publish_refused=1 network_services=0\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL PUBLIC_SNAPSHOT_ACQUISITION " << error.what() << '\n';
        return 1;
    }
}
