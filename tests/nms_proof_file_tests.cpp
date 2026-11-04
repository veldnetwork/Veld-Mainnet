#include "mining/nms_proof_file.h"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
namespace fs = std::filesystem;
void require(bool ok, const char* what) {
    if (!ok)
        throw std::runtime_error(what);
}
std::string read(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), {}};
}
int main() {
    const auto root = fs::temp_directory_path() /
                      ("veld-nms-export-" +
                       std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    try {
        require(fs::create_directory(root), "fresh test directory");
        std::string error;
        require(veld::channel::secure_file::EnsurePrivateDirectory(root.string(), &error),
                "private directory");
        const auto path = root / "address-only-nms.json";
        using Export = veld::mining::NmsProofFile;
        Export file;
        require(file.Update(path.string(), "null", 1, error) == Export::Result::Written,
                "initial invalidation");
        const auto before = fs::last_write_time(path);
        require(file.Update(path.string(), "null", 2, error) == Export::Result::Unchanged &&
                    fs::last_write_time(path) == before,
                "unchanged status avoids disk writes");
        const std::string proof = "{\"payload\":\"public-test-proof\"}";
        require(file.Update(path.string(), proof, 3, error) == Export::Result::Written &&
                    read(path) == proof,
                "atomic changed proof readback");
#ifndef _WIN32
        struct stat st {};
        require(::stat(path.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600 &&
                    st.st_uid == ::geteuid(),
                "owner-only Linux file");
        const auto other = root / "other.json";
        std::ofstream(other) << "preserve";
        fs::remove(path);
        fs::create_symlink(other, path);
        require(file.Update(path.string(), "null", 4, error) == Export::Result::Failed &&
                    read(other) == "preserve",
                "symlink target untouched");
        require(file.Update(path.string(), "null", 5, error) == Export::Result::Deferred,
                "failed export bounded retry");
        fs::remove(path);
        require(file.Update(path.string(), "null", 34, error) == Export::Result::Written,
                "retry recovers after unsafe link removed");
#endif
        require(file.Update(path.string(), std::string(1201, 'x'), 40, error) ==
                    Export::Result::Failed,
                "oversized export refused");
        Export restart;
        require(restart.Update(path.string(), "null", 1, error) == Export::Result::Written &&
                    read(path) == "null",
                "restart clears previous proof");
        fs::remove_all(root);
        std::cout
            << "PASS public proof export, private persistence, expiry, restart and bounded failure\n";
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << "; retained fixture: " << root << '\n';
        return 1;
    }
}
