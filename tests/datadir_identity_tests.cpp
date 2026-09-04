#include "network/network_identity.h"
#include "wallet/secure_channel_file.h"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {

size_t checks = 0;

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        ++checks;                                                                                  \
        if (!(expr)) {                                                                             \
            std::cerr << "FAIL " << __FILE__ << ':' << __LINE__ << " " #expr "\n";                 \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

struct TempDirectory {
    std::filesystem::path path;
    ~TempDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
};

} // namespace

int main() {
#if !defined(VELD_PUBLIC_MAINNET)
    std::cerr << "FAIL test requires the public-mainnet profile\n";
    return 1;
#else
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    TempDirectory temp{std::filesystem::temp_directory_path() /
                       ("veld-security-test-identity-" + std::to_string(nonce))};
    std::string error;
    CHECK(veld::channel::secure_file::EnsurePrivateDirectory(temp.path.string(), &error));
    CHECK(veld::ValidateOrCreatePublicNetworkIdentity(temp.path.string(), &error));

    std::vector<uint8_t> bytes;
    CHECK(veld::channel::secure_file::Read((temp.path / "network.identity").string(), bytes, &error,
                                           4096,
                                           true) == veld::channel::secure_file::ReadResult::Ok);
    const std::string created(bytes.begin(), bytes.end());
    CHECK(created == veld::CompiledPublicNetworkIdentityText());
    CHECK(created.rfind("VELD_NETWORK_IDENTITY_V2\n", 0) == 0);
    CHECK(created.find("profile_id=veld-public-mainnet-v2\n") != std::string::npos);
    CHECK(created.find("btcveld_reserve_semantics=rolling-outpoint-v1\n") != std::string::npos);

    std::string legacy = created;
    const std::string current_header = "VELD_NETWORK_IDENTITY_V2";
    const std::string legacy_header = "VELD_NETWORK_IDENTITY_V1";
    legacy.replace(legacy.find(current_header), current_header.size(), legacy_header);
    const std::string current_profile = "veld-public-mainnet-v2";
    const std::string legacy_profile = "veld-public-mainnet-v1";
    legacy.replace(legacy.find(current_profile), current_profile.size(), legacy_profile);
    CHECK(veld::channel::secure_file::AtomicWriteText((temp.path / "network.identity").string(),
                                                      legacy, &error, true));
    error.clear();
    CHECK(!veld::ValidateOrCreatePublicNetworkIdentity(temp.path.string(), &error));
    CHECK(error.find("does not exactly match") != std::string::npos);

    TempDirectory missing{std::filesystem::temp_directory_path() /
                          ("veld-security-test-identity-missing-" + std::to_string(nonce))};
    CHECK(veld::channel::secure_file::EnsurePrivateDirectory(missing.path.string(), &error));
    const std::string occupied = "historical-state";
    CHECK(veld::channel::secure_file::AtomicWriteText((missing.path / "blocks.dat").string(),
                                                      occupied, &error, true));
    error.clear();
    CHECK(!veld::ValidateOrCreatePublicNetworkIdentity(missing.path.string(), &error));
    CHECK(error.find("absent from a nonempty public datadir") != std::string::npos);

    std::cout << "PASS datadir_identity_tests checks=" << checks
              << " v1_refused=1 missing_identity_nonempty_refused=1\n";
    return 0;
#endif
}
