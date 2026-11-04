#define main veld_node_program_entry
#include "../src/veld-node.cpp"
#undef main

static void require(bool value, const char* message) {
    if (!value)
        throw std::runtime_error(message);
}

int main(int argc, char** argv) {
    require(argc == 2, "provide a fresh disposable directory");
    const std::string dir = argv[1];
    require(!std::filesystem::exists(dir), "test directory must not exist");
    std::string error, address, portable;
    require(veld::channel::secure_file::EnsurePrivateDirectory(dir, &error),
            "private directory creation");
    const std::string pass = "Disposable-Keyfile-Regression-Only-2026!";
    auto key = veld::GenerateKeyPair(false);
    auto other = veld::GenerateKeyPair(false);
    require(_wiz_create_portable_key_bundle(dir, key.private_key, pass, false, address, portable,
                                            error),
            "create portable bundle");
    const auto read = [](const std::string& path) {
        std::vector<uint8_t> bytes;
        std::string why;
        require(_wiz_read_private_bytes(path, bytes, WIZ_MAX_OPERATIONAL_SECRET_BYTES, &why),
                "private read");
        return bytes;
    };
    const auto original = read(portable);
    bool created = true;
    std::string output;
    auto ensure = [&](const std::string& password, const std::string& expected) {
        return _wiz_ensure_portable_keyfile(dir, expected, output, created, error, password, false);
    };
    require(ensure(pass, address) && !created, "identical bundle must resume");

    std::string imported;
    require(
        _wiz_import_encrypted_keyfile(portable, dir + "/miner.key", pass, false, imported, error),
        "same-key import");
    require(imported == address, "import identity");
    const auto reencrypted = read(dir + "/miner.key");
    require(reencrypted != original, "import must exercise randomized encryption");
    require(ensure(pass, address) && !created, "same identity with different ciphertext resumes");
    require(read(portable) == original && read(dir + "/miner.key") == reencrypted,
            "successful resume preserves both existing files");
    require(!ensure("Wrong-Disposable-Password-Only!", address), "wrong password refused");
    require(!_wiz_same_encrypted_identity(reencrypted, original, pass, other.address, false),
            "different expected address refused");

    std::vector<uint8_t> conflicting;
    require(_wiz_encrypt_key_record(other.private_key, pass, false, conflicting),
            "encrypt different identity");
    require(veld::channel::secure_file::AtomicWrite(portable, conflicting, &error, true),
            "install disposable conflict");
    require(!ensure(pass, address), "different private key refused");
    require(read(portable) == conflicting && read(dir + "/miner.key") == reencrypted,
            "refused conflict preserves both files");
    auto corrupted = original;
    corrupted.back() ^= 1;
    require(veld::channel::secure_file::AtomicWrite(portable, corrupted, &error, true),
            "install disposable corruption");
    require(!ensure(pass, address), "corruption refused");
    require(read(portable) == corrupted, "corrupt original preserved");

    std::filesystem::remove(portable);
    require(ensure(pass, address) && created, "missing portable recovery copy created");
    require(read(portable) == reencrypted, "new recovery copy has exact bytes");
    require(ensure(pass, address) && !created, "creation is idempotent");
#ifndef _WIN32
    require(::chmod(portable.c_str(), 0644) == 0, "fixture permissions");
    require(!ensure(pass, address), "unsafe permissions refused");
    require(::chmod(portable.c_str(), 0600) == 0, "restore fixture permissions");
    std::filesystem::remove(portable);
    std::filesystem::create_symlink(dir + "/miner.key", portable);
    require(!ensure(pass, address), "symlink refused");
#endif
    veld::compat::SecureZero(key.private_key.data(), key.private_key.size());
    veld::compat::SecureZero(other.private_key.data(), other.private_key.size());
    std::cout << "PASS portable identity: same-key reimport, unchanged originals, conflict, "
                 "password, address, corruption, creation, permissions and symlink checks\n";
}
