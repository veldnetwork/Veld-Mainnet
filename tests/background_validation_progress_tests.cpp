// Native filesystem regression; never starts RPC, peers, mining or a wallet.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_ASERT_TESTCHAIN 1
#define VELD_ENABLE_SNAPSHOT_BOOTSTRAP 1
#include "node/node.h"
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace veld;
namespace fs = std::filesystem;
unsigned checks = 0;
void Require(bool ok, const char* message) {
    ++checks;
    if (!ok) throw std::runtime_error(message);
}
int main(int argc, char** argv) {
    try {
        Require(argc == 2, "disposable output directory required");
        const fs::path root = fs::absolute(argv[1]);
        Require(!fs::exists(root), "output must be new; existing data preserved");
        fs::create_directories(root);
#ifdef _WIN32
        Require(compat::RestrictFileToOwner(root.string()), "private directory permissions failed");
#else
        fs::permissions(root, fs::perms::owner_all);
#endif
        VeldNode node(RegtestConfig(), root.string());
        Hash256 first{}, second{};
        first.fill(0x41); second.fill(0x42);
        const auto marker = root / ".validated-background-prefix";
        const auto temporary = root / ".validated-background-prefix.new";
        std::string error;
        const auto save = [&](uint64_t height, const Hash256& tip) {
            error.clear();
#ifdef VELD_BACKGROUND_PROGRESS_BASELINE
            return node.WriteValidatedBackgroundPrefix_(height, tip);
#else
            return node.WriteValidatedBackgroundPrefix_(height, tip, &error);
#endif
        };
        Require(!save(0, first) && !fs::exists(marker), "zero height persisted");
        Require(!save(1, Hash256{}) && !fs::exists(marker), "zero tip persisted");
#ifdef _WIN32
        // A concurrent callback can still own the old shared temporary name.
        HANDLE concurrent = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0,
            nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        Require(concurrent != INVALID_HANDLE_VALUE, "temporary collision fixture failed");
        const bool wrote = save(25, first);
        CloseHandle(concurrent);
        Require(wrote, "another writer's shared temporary file blocked progress");
#else
        std::ofstream(temporary) << "another writer owns this temporary name\n";
        Require(save(25, first), "unrelated temporary blocked progress");
#endif
        Require(fs::exists(temporary), "another writer's temporary file was removed");
        auto restored = node.ReadValidatedBackgroundPrefix_();
        Require(restored && restored->first == 25 && restored->second == HashToHex(first),
                "saved prefix does not round-trip exactly");
        Require(save(26, second), "normal progress replacement failed");
        restored = node.ReadValidatedBackgroundPrefix_();
        Require(restored && restored->first == 26 && restored->second == HashToHex(second),
                "replacement did not preserve its matching height and hash");
#ifdef _WIN32
        HANDLE reader = CreateFileW(marker.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        Require(reader != INVALID_HANDLE_VALUE, "sharing fault fixture failed");
        const bool blocked = save(27, first);
        CloseHandle(reader);
        Require(!blocked && !error.empty(), "failed publication has no diagnostic reason");
#else
        fs::permissions(root, fs::perms::owner_read | fs::perms::owner_exec);
        const bool blocked = save(27, first);
        fs::permissions(root, fs::perms::owner_all);
        Require(!blocked && !error.empty(), "failed publication has no diagnostic reason");
#endif
        restored = node.ReadValidatedBackgroundPrefix_();
        Require(restored && restored->first == 26 && restored->second == HashToHex(second),
                "failed replacement damaged the last saved prefix");
        Require(save(27, first), "progress could not resume after transient failure");
        restored = node.ReadValidatedBackgroundPrefix_();
        Require(restored && restored->first == 27 && restored->second == HashToHex(first),
                "retry saved an incorrect prefix");
        Require(node.GetTCPServer() == nullptr && !node.IsMiningReady(),
                "filesystem regression opened production work");
        std::cout << "PASS background progress checks=" << checks << " network_services=0\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
