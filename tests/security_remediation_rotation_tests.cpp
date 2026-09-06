#define main veld_keygen_test_entry
#include "../src/veld-keygen.cpp"
#undef main
#include <cassert>

int main(int argc, char** argv) {
    assert(argc == 2);
    if (std::getenv("VELD_OLD_PASSPHRASE") || std::getenv("VELD_NEW_PASSPHRASE"))
        return 2; // never use a pre-existing credential environment
    std::string error;
    if (!secure_file::EnsurePrivateDirectory(argv[1], &error)) {
        std::cerr << error << '\n';
        return 2;
    }
    const auto path = (fs::path(argv[1]) / "ordinary-rotation-fixture.dat").string();
    const std::string old_pass = "Z8!fQ2@xM7#tN4$pR9%uK6&vS3*wL5";
    const std::string new_pass = "T5^bH8!sD2@mV7#kF4$qP9%zC6&nG3";
    const std::string plaintext = "not-a-private-key\nnot-a-public-key\nfixture-address\n";
    const auto before = veld::wallet_crypto::EncryptWallet(plaintext, old_pass);
    assert(secure_file::AtomicWriteNew(path, before, &error, true));
#ifdef _WIN32
    assert(_putenv_s("VELD_OLD_PASSPHRASE", old_pass.c_str()) == 0);
    assert(_putenv_s("VELD_NEW_PASSPHRASE", new_pass.c_str()) == 0);
#else
    assert(setenv("VELD_OLD_PASSPHRASE", old_pass.c_str(), 1) == 0);
    assert(setenv("VELD_NEW_PASSPHRASE", new_pass.c_str(), 1) == 0);
#endif
    std::string command = "rotate-pass", name = "fixture-keygen", argument = path;
    char* args[] = {name.data(), command.data(), argument.data()};
    assert(veld_keygen_test_entry(3, args) == 0);
    assert(!std::getenv("VELD_OLD_PASSPHRASE"));
    assert(!std::getenv("VELD_NEW_PASSPHRASE"));
    std::vector<uint8_t> after;
    assert(secure_file::Read(path, after, &error, 1024 * 1024, true) == secure_file::ReadResult::Ok);
    assert(veld::wallet_crypto::DecryptWallet(after, new_pass) == plaintext);
    bool old_pass_rejected = false;
    try { (void)veld::wallet_crypto::DecryptWallet(after, old_pass); }
    catch (...) { old_pass_rejected = true; }
    assert(old_pass_rejected);
    assert(fs::remove(path)); // exact fixture only
    std::cout << "PASS: real rotation entry point with non-key plaintext\n";
}
