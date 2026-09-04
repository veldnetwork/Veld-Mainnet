#include "../include/node/node.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#if !defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
#error "this fixture requires the explicit generic snapshot profile"
#endif
#if defined(VELD_PUBLIC_RELEASE) || defined(VELD_PUBLIC_MAINNET)
#error "generic snapshot support must be incompatible with public releases"
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

} // namespace

int main() {
    using namespace veld;
    const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const std::filesystem::path datadir = std::filesystem::temp_directory_path() /
                                          ("veld-security-test-generic-snapshot-profile-" + suffix);

    {
        VeldNode node(MainnetConfig(), datadir.string());
        std::string public_marker;
        Check(!node.PublicSnapshotDatadirRefusal(&public_marker),
              "generic non-public profile does not impersonate public refusal");

        node.SetSnapshotFastStartEligible(true, 42, std::string(64, '0'));
        Check(node.SnapshotFastStartEligible(),
              "generic snapshot eligibility API is compiled and live");
        node.SetBackgroundValidationOnly(true);
        node.SetBackgroundValidationTarget(42);
        node.SetIndependentValidationProgress(17);
        Check(!node.IndependentValidationBase().has_value(),
              "generic empty fixture has no fabricated validation base");
        const auto observation = node.BackgroundValidationResult();
        Check(observation.height == 0 && !observation.reached && !observation.passed_target,
              "generic background observation begins fail-closed");
        Check(!node.SnapshotBackgroundVerificationFailed(),
              "generic empty fixture has no fabricated verification failure");

        const std::string dump_response =
            node.GetRPC().Handle(R"({"jsonrpc":"2.0","method":"dumpsnapshot","params":[],"id":1})");
        Check(dump_response.find("dump-snapshot not wired") != std::string::npos &&
                  dump_response.find("\"code\":-32601") == std::string::npos,
              "generic profile registers the bounded snapshot RPC surface");

        bool malformed_refused = false;
        try {
            node.ValidateStoredChainOnly(0, "", true);
        } catch (const std::runtime_error& e) {
            malformed_refused =
                std::string(e.what()).find(
                    "snapshot candidate has malformed signed tip identity") != std::string::npos;
        }
        Check(malformed_refused, "generic offline validator rejects malformed snapshot identity");

        std::ofstream marker(datadir / ".snapshot-fast-start-revoked",
                             std::ios::binary | std::ios::trunc);
        marker << "generic-test-only\n";
        marker.close();
        Check(marker.good(), "generic marker fixture was written");
        Check(!node.PublicSnapshotDatadirRefusal(&public_marker),
              "generic profile remains distinct from public marker policy");
    }

    std::error_code cleanup_error;
    std::filesystem::remove_all(datadir, cleanup_error);
    Check(!cleanup_error && !std::filesystem::exists(datadir),
          "generic snapshot fixture cleaned up");

    std::cout << (failures == 0 ? "PASS " : "FAIL ")
              << "generic_snapshot_profile_tests checks=" << checks
              << " profile=VELD_ENABLE_SNAPSHOT_BOOTSTRAP\n";
    return failures == 0 ? 0 : 1;
}
