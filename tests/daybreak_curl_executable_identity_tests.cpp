#include "../include/compat/process.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

namespace fs = std::filesystem;

bool MaybeRunFakeCurl(int argc, char** argv) {
    const char* sentinel = std::getenv("VELD_FAKE_CURL_SENTINEL");
    if (sentinel == nullptr || sentinel[0] == '\0' || argc < 2 ||
        std::string(argv[1]) != "--version") {
        return false;
    }
    std::string name = fs::path(argv[0]).filename().string();
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char value) {
                       return static_cast<char>(std::tolower(value));
                   });
    if (name != "curl" && name != "curl.exe") return false;
    std::ofstream output(sentinel, std::ios::binary | std::ios::trunc);
    output << "executed";
    output.close();
    std::cout << "fake curl\n";
    return true;
}

struct TestState {
    size_t checks{0};
    void Check(bool condition, const char* message) {
        if (!condition) throw std::runtime_error(message);
        ++checks;
    }
};

struct CleanupDirectory {
    fs::path path;
    ~CleanupDirectory() {
        std::error_code ignored;
        fs::remove_all(path, ignored);
    }
};

struct HostileProcessEnvironment {
    fs::path original_directory{fs::current_path()};
    std::string original_path;
    bool had_path{false};
    bool active{false};

    HostileProcessEnvironment(const fs::path& directory,
                              const fs::path& sentinel) {
        if (const char* path = std::getenv("PATH")) {
            original_path = path;
            had_path = true;
        }
#ifdef _WIN32
        if (::_putenv_s("PATH", directory.string().c_str()) != 0 ||
            ::_putenv_s("VELD_FAKE_CURL_SENTINEL",
                        sentinel.string().c_str()) != 0) {
            throw std::runtime_error("could not install hostile environment");
        }
#else
        if (::setenv("PATH", directory.string().c_str(), 1) != 0 ||
            ::setenv("VELD_FAKE_CURL_SENTINEL",
                     sentinel.string().c_str(), 1) != 0) {
            throw std::runtime_error("could not install hostile environment");
        }
#endif
        fs::current_path(directory);
        active = true;
    }

    ~HostileProcessEnvironment() {
        if (!active) return;
        std::error_code ignored;
        fs::current_path(original_directory, ignored);
#ifdef _WIN32
        ::_putenv_s("PATH", had_path ? original_path.c_str() : "");
        ::_putenv_s("VELD_FAKE_CURL_SENTINEL", "");
#else
        if (had_path) ::setenv("PATH", original_path.c_str(), 1);
        else ::unsetenv("PATH");
        ::unsetenv("VELD_FAKE_CURL_SENTINEL");
#endif
    }
};

}  // namespace

int main(int argc, char** argv) try {
    if (MaybeRunFakeCurl(argc, argv)) return 0;
    if (argc == 2 && std::string(argv[1]) == "--expect-unavailable") {
        if (!veld::compat::TrustedSystemCurlExecutable().empty()) {
            throw std::runtime_error(
                "trusted resolver accepted curl outside the system allowlist");
        }
        std::cout << "PASS trusted-system-curl-unavailable-fail-closed\n";
        return 0;
    }
    if (argc != 1) return 2;

    TestState test;
    const std::string self = veld::compat::ExecutablePath();
    test.Check(!self.empty() && fs::path(self).is_absolute(),
               "test executable identity is unavailable");
    const auto nonce = std::chrono::steady_clock::now()
                           .time_since_epoch().count();
    const fs::path root = fs::temp_directory_path() /
        ("veld-f8-curl-identity-" + std::to_string(nonce));
    test.Check(fs::create_directory(root),
               "could not create curl identity fixture directory");
    CleanupDirectory cleanup{root};

#ifdef _WIN32
    const fs::path fake_curl = root / "curl.exe";
#else
    const fs::path fake_curl = root / "curl";
#endif
    fs::copy_file(self, fake_curl, fs::copy_options::none);
#ifndef _WIN32
    fs::permissions(fake_curl,
                    fs::perms::owner_read | fs::perms::owner_write |
                    fs::perms::owner_exec | fs::perms::group_read |
                    fs::perms::group_exec | fs::perms::others_read |
                    fs::perms::others_exec,
                    fs::perm_options::replace);
#endif
    const fs::path sentinel = root / "fake-curl-executed";
    HostileProcessEnvironment hostile(root, sentinel);

    // Prove the fixture is capable of substituting an unqualified child.
    auto negative_control = veld::compat::RunProcess(
        {"curl", "--version"}, true, {}, true, 4096);
    test.Check(negative_control.exit_code == 0 && fs::exists(sentinel),
               "hostile CWD/PATH negative control did not execute fake curl");
    fs::remove(sentinel);

    const std::string trusted =
        veld::compat::TrustedSystemCurlExecutable();
    test.Check(!trusted.empty(), "trusted system curl is unavailable");
    test.Check(fs::path(trusted).is_absolute(),
               "trusted curl path is not absolute");
    std::error_code equivalent_error;
    const bool fake_selected = fs::equivalent(
        fs::path(trusted), fake_curl, equivalent_error);
    test.Check(!equivalent_error && !fake_selected,
               "trusted resolver selected the hostile curl");

    const auto result = veld::compat::RunProcess(
        {trusted, "--version"}, true, {}, true, 64U * 1024U);
    test.Check(result.exit_code == 0 && !result.output_truncated &&
                   result.output.find("curl") != std::string::npos,
               "trusted absolute curl could not be executed");
    test.Check(!fs::exists(sentinel),
               "trusted curl execution reached hostile CWD/PATH binary");

    std::cout << "PASS daybreak_curl_executable_identity_tests checks="
              << test.checks << " trusted=" << trusted << "\n";
    return 0;
} catch (const std::exception& exception) {
    std::cerr << "FAIL daybreak_curl_executable_identity_tests: "
              << exception.what() << "\n";
    return 1;
}
