#if defined(VELD_PUBLIC_TESTNET)
#error                                                                                             \
    "PUBLIC TESTNET forbids veld-keygen external/release signing utilities; use node/desktop wallet generation"
#endif
#if defined(VELD_FLEET_NO_MINE)
#error "VELD_FLEET_NO_MINE is a node/validator runtime role, not a keygen artifact profile"
#endif

// Standalone ML-DSA-65 key generation, inspection and signing utility.
// Private key files use the same authenticated encryption format as the node.

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <algorithm>
#include <charconv>
#include <limits>
#include <cstdio>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "../include/compat/platform.h"
#include "../include/core/hash.h"
#include "../include/core/version.h"
#include "../include/crypto/veld_signing.h"
#include "../include/crypto/ripemd160.h"
#include "../include/crypto/vendored.h"
#include "../include/wallet/wallet.h"
#include "../include/wallet/wallet_crypto.h"
#include "../include/wallet/passphrase_policy.h"
#include "../include/wallet/secure_channel_file.h"
#include "../include/wallet/offline_signing.h"
#include "../include/consensus/btcveld_mint_policy.h"
#include "../include/consensus/btcveld_relay_policy.h"

namespace fs = std::filesystem;

struct SensitiveString {
    std::string value;
    SensitiveString() = default;
    explicit SensitiveString(std::string input) : value(std::move(input)) {}
    SensitiveString(const SensitiveString&) = delete;
    SensitiveString& operator=(const SensitiveString&) = delete;
    void Clear() noexcept {
        if (!value.empty())
            veld::compat::SecureZero(value.data(), value.size());
        value.clear();
    }
    ~SensitiveString() {
        Clear();
    }
};

struct LockedSeed {
    std::array<uint8_t, 32> bytes{};
    bool locked = false;
    LockedSeed() {
        veld::compat::SecureZero(bytes.data(), bytes.size());
        locked = veld::compat::SecureLockMemory(bytes.data(), bytes.size());
    }
    LockedSeed(const LockedSeed&) = delete;
    LockedSeed& operator=(const LockedSeed&) = delete;
    void Clear() noexcept {
        veld::compat::SecureZero(bytes.data(), bytes.size());
    }
    ~LockedSeed() {
        Clear();
        if (locked)
            veld::compat::SecureUnlockMemory(bytes.data(), bytes.size());
    }
};

static std::string HexOf(const uint8_t* d, size_t n) {
    std::ostringstream o;
    for (size_t i = 0; i < n; ++i)
        o << std::hex << std::setw(2) << std::setfill('0') << (int)d[i];
    return o.str();
}

static void AppendHex(std::string& output, const uint8_t* data, size_t size) {
    static constexpr char kHex[] = "0123456789abcdef";
    for (size_t i = 0; i < size; ++i) {
        output.push_back(kHex[data[i] >> 4]);
        output.push_back(kHex[data[i] & 0x0f]);
    }
}

static bool ParseHex32(const std::string& s, std::array<uint8_t, 32>& out) {
    if (s.size() != 64)
        return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < out.size(); ++i) {
        const int high = nibble(s[i * 2]);
        const int low = nibble(s[i * 2 + 1]);
        if (high < 0 || low < 0) {
            veld::compat::SecureZero(out.data(), out.size());
            return false;
        }
        out[i] = static_cast<uint8_t>((high << 4) | low);
    }
    bool all_zero = true;
    for (auto b : out)
        if (b != 0) {
            all_zero = false;
            break;
        }
    return !all_zero;
}

static bool ParseCanonicalU64Arg(const std::string& text, uint64_t& out) {
    if (text.empty() || (text.size() > 1U && text.front() == '0'))
        return false;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), out, 10);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}

class ExactEchoGuard {
  public:
    ExactEchoGuard() = default;
    ExactEchoGuard(const ExactEchoGuard&) = delete;
    ExactEchoGuard& operator=(const ExactEchoGuard&) = delete;

    bool DisableIfTerminal(bool& terminal, std::string& error) {
#ifdef _WIN32
        handle_ = ::GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        if (handle_ == INVALID_HANDLE_VALUE || handle_ == nullptr ||
            !::GetConsoleMode(handle_, &mode)) {
            terminal = false;
            return true;
        }
        terminal = true;
        original_mode_ = mode;
        // Disable processed/line input while the secret is being read so
        // Ctrl-C is delivered as a byte to this scope instead of terminating
        // the process with echo disabled.  The guard restores the exact mode
        // on success, cancellation, malformed input, and EOF.
        const DWORD hidden =
            mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
        if (!::SetConsoleMode(handle_, hidden)) {
            error = "cannot disable terminal echo";
            return false;
        }
#else
        terminal = (::isatty(STDIN_FILENO) == 1);
        if (!terminal)
            return true;
        if (::tcgetattr(STDIN_FILENO, &original_mode_) != 0) {
            error = "cannot read terminal mode";
            return false;
        }
        struct termios hidden = original_mode_;
        // Noncanonical/no-ISIG makes terminal Ctrl-C an ordinary 0x03 byte,
        // allowing the normal return path to restore termios reliably.
        hidden.c_lflag &= static_cast<tcflag_t>(~(ECHO | ICANON | ISIG));
        hidden.c_cc[VMIN] = 1;
        hidden.c_cc[VTIME] = 0;
        if (::tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) {
            error = "cannot disable terminal echo";
            return false;
        }
#endif
        active_ = true;
        return true;
    }

    ~ExactEchoGuard() {
        if (!active_)
            return;
#ifdef _WIN32
        (void)::SetConsoleMode(handle_, original_mode_);
#else
        (void)::tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_mode_);
#endif
    }

  private:
    bool active_{false};
#ifdef _WIN32
    HANDLE handle_{INVALID_HANDLE_VALUE};
    DWORD original_mode_{0};
#else
    struct termios original_mode_{};
#endif
};

static bool ReadSeedWithoutArgv(SensitiveString& seed_hex, std::string& error) {
    ExactEchoGuard echo;
    bool terminal = false;
    if (!echo.DisableIfTerminal(terminal, error))
        return false;
    if (!terminal) {
        error = "seed import requires a hidden interactive terminal";
        return false;
    }
    std::cerr << "Seed (64 hex characters; input hidden): " << std::flush;

    std::string value;
    value.reserve(64);
    bool ended_by_newline = false;
    char c = 0;
    while (std::cin.get(c)) {
        if (c == '\x03' || c == '\x1a') {
            if (!value.empty())
                veld::compat::SecureZero(value.data(), value.size());
            std::cerr << "\n";
            error = "seed import cancelled";
            return false;
        }
        if (c == '\n') {
            ended_by_newline = true;
            break;
        }
        if (c == '\r') {
            ended_by_newline = true;
            break;
        }
        if (value.size() >= 64U) {
            veld::compat::SecureZero(value.data(), value.size());
            error = "seed input exceeds 64 characters";
            if (terminal)
                std::cerr << "\n";
            return false;
        }
        value.push_back(c);
    }
    std::cerr << "\n";
    if (value.empty() && !ended_by_newline) {
        error = "seed input ended before any data";
        return false;
    }
    seed_hex.value = std::move(value);
    return true;
}

// An inherited anonymous pipe is a capability, not seed material.  This is
// the noninteractive production import path for automation that cannot
// provide a real hidden terminal.  The argv contains only the numeric handle
// or descriptor; the exact 64 raw hex bytes travel solely through the pipe
// and the writer must close it to delimit the secret.
static bool ReadSeedFromProtectedHandle(uint64_t raw_handle, SensitiveString& seed_hex,
                                        std::string& error) {
    std::string value;
    value.reserve(64);
    auto accept = [&](const char* bytes, size_t count) -> bool {
        for (size_t i = 0; i < count; ++i) {
            const unsigned char byte = static_cast<unsigned char>(bytes[i]);
            if (byte == 0x03 || byte == 0x1a) {
                if (!value.empty())
                    veld::compat::SecureZero(value.data(), value.size());
                error = "seed import cancelled";
                return false;
            }
            if (value.size() >= 64U) {
                veld::compat::SecureZero(value.data(), value.size());
                error = "seed input exceeds 64 characters";
                return false;
            }
            value.push_back(static_cast<char>(byte));
        }
        return true;
    };

#ifdef _WIN32
    if (raw_handle == 0 ||
        raw_handle > static_cast<uint64_t>(std::numeric_limits<uintptr_t>::max())) {
        error = "protected seed handle is invalid";
        return false;
    }
    const HANDLE handle = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(raw_handle));
    DWORD inherit_flags = 0;
    if (handle == INVALID_HANDLE_VALUE || !::GetHandleInformation(handle, &inherit_flags) ||
        (inherit_flags & HANDLE_FLAG_INHERIT) == 0 || ::GetFileType(handle) != FILE_TYPE_PIPE) {
        error = "protected seed handle must be an inherited anonymous pipe";
        return false;
    }
    char buffer[65]{};
    for (;;) {
        DWORD count = 0;
        if (!::ReadFile(handle, buffer, static_cast<DWORD>(sizeof(buffer)), &count, nullptr)) {
            const DWORD code = ::GetLastError();
            if (code == ERROR_BROKEN_PIPE)
                break;
            if (!value.empty())
                veld::compat::SecureZero(value.data(), value.size());
            error = "protected seed handle read failed";
            return false;
        }
        if (count == 0)
            break;
        if (!accept(buffer, count)) {
            veld::compat::SecureZero(buffer, sizeof(buffer));
            return false;
        }
        veld::compat::SecureZero(buffer, sizeof(buffer));
    }
    veld::compat::SecureZero(buffer, sizeof(buffer));
#else
    if (raw_handle > static_cast<uint64_t>(INT_MAX)) {
        error = "protected seed descriptor is invalid";
        return false;
    }
    const int descriptor = static_cast<int>(raw_handle);
    struct stat status{};
    if (descriptor < 3 || ::fstat(descriptor, &status) != 0 ||
        !(S_ISFIFO(status.st_mode) || S_ISSOCK(status.st_mode))) {
        error = "protected seed descriptor must be an inherited pipe or socket";
        return false;
    }
    const int descriptor_flags = ::fcntl(descriptor, F_GETFD);
    if (descriptor_flags < 0 || ::fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) {
        error = "cannot protect inherited seed descriptor";
        return false;
    }
    char buffer[65]{};
    for (;;) {
        const ssize_t count = ::read(descriptor, buffer, sizeof(buffer));
        if (count == 0)
            break;
        if (count < 0) {
            if (errno == EINTR)
                continue;
            if (!value.empty())
                veld::compat::SecureZero(value.data(), value.size());
            error = "protected seed descriptor read failed";
            return false;
        }
        if (!accept(buffer, static_cast<size_t>(count))) {
            veld::compat::SecureZero(buffer, sizeof(buffer));
            return false;
        }
        veld::compat::SecureZero(buffer, sizeof(buffer));
    }
    veld::compat::SecureZero(buffer, sizeof(buffer));
#endif
    if (value.empty()) {
        error = "seed input ended before any data";
        return false;
    }
    seed_hex.value = std::move(value);
    return true;
}

static std::string ReadPassphrase(const char* reason) {
    if (const char* env = std::getenv("VELD_VAULT_PASSPHRASE")) {
        std::string p(env);
        veld::compat::UnsetEnv("VELD_VAULT_PASSPHRASE");
        return p;
    }
    std::cerr << reason << " (VELD_VAULT_PASSPHRASE not set; prompting)\n"
              << "Passphrase: " << std::flush;
    veld::compat::ConsoleEchoOff();
    std::string p;
    std::getline(std::cin, p);
    veld::compat::ConsoleEchoOn();
    std::cerr << "\n";
    return p;
}

static int ValidateNewOutputPath(const std::string& out_path) {
    if (out_path.empty()) {
        std::cerr << "error: --out FILE is required\n";
        return 2;
    }
    if (fs::exists(out_path)) {
        std::cerr << "error: refusing to overwrite existing file: " << out_path << "\n";
        return 2;
    }
    return 0;
}

static int CmdNew(const std::string& out_path, bool testnet, LockedSeed* seed_opt,
                  SensitiveString& pass) {
    // Recheck after the passphrase/seed prompts. AtomicWriteNew below remains
    // authoritative for a destination created after this race-safe preflight.
    const int output_status = ValidateNewOutputPath(out_path);
    if (output_status != 0)
        return output_status;

    LockedSeed generated_seed;
    LockedSeed* seed = seed_opt;
    if (!seed) {
        seed = &generated_seed;
    }
    if (!seed->locked) {
        std::cerr << "error: cannot lock new key seed memory\n";
        return 1;
    }
    if (seed_opt) {
        if (!veld::key_entropy::CandidateLooksSane(seed->bytes)) {
            std::cerr << "error: supplied seed fails key-entropy policy\n";
            return 1;
        }
    } else {
        try {
            seed->bytes = veld::GeneratePrivateKey();
        } catch (const std::exception& e) {
            std::cerr << "error: " << e.what() << "\n";
            return 1;
        }
    }

    veld::Secp256k1PubKey pub{};
    try {
        pub = veld::DerivePublicKey(seed->bytes);
    } catch (const std::exception& e) {
        std::cerr << "error: ML-DSA public-key derivation failed: " << e.what() << "\n";
        return 1;
    }
    auto addr = veld::PubKeyToAddress(pub, testnet);

    // Reserve once so appending the secret cannot leave an abandoned plaintext
    // allocation during growth. Do not create a temporary std::string copy of
    // the seed: append directly, then wipe the only seed buffer immediately.
    SensitiveString plaintext;
    plaintext.value.reserve(seed->bytes.size() * 2U + 1U + pub.size() * 2U + 1U + addr.size() + 1U);
    AppendHex(plaintext.value, seed->bytes.data(), seed->bytes.size());
    seed->Clear();
    plaintext.value.push_back('\n');
    AppendHex(plaintext.value, pub.data(), pub.size());
    plaintext.value.push_back('\n');
    plaintext.value.append(addr);
    plaintext.value.push_back('\n');
    std::vector<uint8_t> encrypted;
    try {
        encrypted = veld::wallet_crypto::EncryptWallet(plaintext.value, pass.value);
    } catch (const std::exception& e) {
        plaintext.Clear();
        pass.Clear();
        std::cerr << "error: key encryption failed: " << e.what() << "\n";
        return 1;
    }
    plaintext.Clear();
    pass.Clear();

    std::string write_error;
    if (!veld::channel::secure_file::AtomicWriteNew(out_path, encrypted, &write_error,
                                                    /*require_private_parent=*/true)) {
        std::cerr << "error: secure no-overwrite key write failed: " << write_error << "\n";
        return 1;
    }

    std::cout << "address: " << addr << "\n"
              << "file:    " << out_path << " (" << encrypted.size() << " bytes, encrypted)\n";
    return 0;
}

static int CmdShow(const std::string& path, bool full_pubkey = false) {
    if (!fs::exists(path)) {
        std::cerr << "error: no such file: " << path << "\n";
        return 2;
    }
    std::ifstream f(path, std::ios::binary);
    if (!f.good()) {
        std::cerr << "error: cannot read: " << path << "\n";
        return 1;
    }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
    f.close();

    std::string pass = ReadPassphrase("decrypting key");
    std::string plaintext;
    try {
        plaintext = veld::wallet_crypto::DecryptWallet(data, pass);
    } catch (const std::exception& e) {
        veld::compat::SecureZero(pass.data(), pass.size());
        std::cerr << "error: decrypt failed: " << e.what() << "\n";
        return 1;
    }
    veld::compat::SecureZero(pass.data(), pass.size());

    std::istringstream ss(plaintext);
    std::string priv_hex, pub_hex, addr;
    std::getline(ss, priv_hex);
    std::getline(ss, pub_hex);
    std::getline(ss, addr);
    veld::compat::SecureZero(plaintext.data(), plaintext.size());

    if (priv_hex.size() != 64 || pub_hex.size() != 1952 * 2) {
        veld::compat::SecureZero(priv_hex.data(), priv_hex.size());
        std::cerr << "error: key file format unrecognized (not post-PQC?)\n";
        return 1;
    }

    std::cout << "address: " << addr << "\n"
              << "pubkey:  " << pub_hex.substr(0, 32) << "..."
              << pub_hex.substr(pub_hex.size() - 32) << " (1952 bytes)\n";
    if (full_pubkey) {
        std::cout << "pubkey-full-hex: " << pub_hex << "\n";
    }
    veld::compat::SecureZero(priv_hex.data(), priv_hex.size());
    return 0;
}

static std::vector<uint8_t> ReadAllBytes(const std::string& path, bool& ok) {
    ok = false;
    std::ifstream f(path, std::ios::binary);
    if (!f.good())
        return {};
    std::vector<uint8_t> d((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    ok = true;
    return d;
}

// veld-keygen sign-release <keyfile> <input> <outsig>
//   Offline release signing. Decrypts the release key (VELD_VAULT_PASSPHRASE),
//   signs Hash256d(input-bytes) with ML-DSA-65 (the chain's own scheme), and
//   writes the raw signature bytes. Prints the 1952-byte pubkey for pinning
//   into the shipped client. The PRIVATE key never leaves this machine.
static int CmdSignRelease(const std::string& keyfile, const std::string& input,
                          const std::string& outsig) {
    if (!fs::exists(keyfile)) {
        std::cerr << "error: no such key file: " << keyfile << "\n";
        return 2;
    }
    bool kok = false;
    std::vector<uint8_t> kdata = ReadAllBytes(keyfile, kok);
    if (!kok) {
        std::cerr << "error: cannot read key file\n";
        return 1;
    }
    std::string pass = ReadPassphrase("decrypting release key");
    std::string plaintext;
    try {
        plaintext = veld::wallet_crypto::DecryptWallet(kdata, pass);
    } catch (const std::exception& e) {
        veld::compat::SecureZero(pass.data(), pass.size());
        std::cerr << "error: decrypt failed: " << e.what() << "\n";
        return 1;
    }
    veld::compat::SecureZero(pass.data(), pass.size());
    std::istringstream ss(plaintext);
    std::string priv_hex, pub_hex, addr;
    std::getline(ss, priv_hex);
    std::getline(ss, pub_hex);
    std::getline(ss, addr);
    veld::compat::SecureZero(plaintext.data(), plaintext.size());
    std::array<uint8_t, 32> seed{};
    if (!ParseHex32(priv_hex, seed)) {
        veld::compat::SecureZero(priv_hex.data(), priv_hex.size());
        std::cerr << "error: key file format unrecognized\n";
        return 1;
    }
    veld::compat::SecureZero(priv_hex.data(), priv_hex.size());
    bool iok = false;
    std::vector<uint8_t> in = ReadAllBytes(input, iok);
    if (!iok) {
        veld::compat::SecureZero(seed.data(), 32);
        std::cerr << "error: cannot read input: " << input << "\n";
        return 1;
    }
    veld::Hash256 h = veld::Hash256d(in);
    veld::Secp256k1SigDER sig;
    try {
        sig = veld::Sign(seed, h);
    } catch (const std::exception& e) {
        veld::compat::SecureZero(seed.data(), 32);
        std::cerr << "error: sign failed: " << e.what() << "\n";
        return 1;
    }
    veld::compat::SecureZero(seed.data(), 32);
    FILE* fp = std::fopen(outsig.c_str(), "wb");
    if (!fp) {
        std::cerr << "error: cannot write sig: " << outsig << "\n";
        return 1;
    }
    if (std::fwrite(sig.data(), 1, sig.size(), fp) != sig.size()) {
        std::fclose(fp);
        std::cerr << "error: short write\n";
        return 1;
    }
    std::fclose(fp);
    std::cout << "signed " << input << " -> " << outsig << " (" << sig.size()
              << " bytes, ML-DSA-65)\n";
    std::cout << "release pubkey to pin (" << pub_hex.size() << " hex chars):\n" << pub_hex << "\n";
    return 0;
}

// veld-keygen verify-release <pubhex|@file> <input> <sigfile>
//   Offline verification check (the shipped client verifies against a PINNED
//   pubkey via `veld-node --verify-release`). Exit 0 = valid, 1 = invalid.
static int CmdVerifyRelease(const std::string& pubarg, const std::string& input,
                            const std::string& sigfile) {
    std::string pub_hex = pubarg;
    if (!pub_hex.empty() && pub_hex[0] == '@') {
        std::ifstream pf(pub_hex.substr(1));
        if (!pf.good()) {
            std::cerr << "error: cannot read pubkey file\n";
            return 1;
        }
        std::getline(pf, pub_hex);
    }
    while (!pub_hex.empty() &&
           (pub_hex.back() == '\n' || pub_hex.back() == '\r' || pub_hex.back() == ' '))
        pub_hex.pop_back();
    if (pub_hex.size() != 1952 * 2) {
        std::cerr << "error: pubkey must be 3904 hex chars\n";
        return 1;
    }
    veld::Secp256k1PubKey pub{};
    for (size_t i = 0; i < 1952; ++i)
        pub[i] = (uint8_t)std::stoul(pub_hex.substr(i * 2, 2), nullptr, 16);
    bool iok = false, sok = false;
    std::vector<uint8_t> in = ReadAllBytes(input, iok);
    std::vector<uint8_t> sig = ReadAllBytes(sigfile, sok);
    if (!iok || !sok) {
        std::cerr << "error: cannot read input/sig\n";
        return 1;
    }
    veld::Hash256 h = veld::Hash256d(in);
    bool ok = veld::Verify(pub, h, sig);
#ifdef _WIN32
    // This command is a machine oracle.  Native Windows text streams translate
    // LF to CRLF, which would violate the release gate's byte-exact contract.
    if (::_setmode(::_fileno(stdout), _O_BINARY) == -1) {
        std::cerr << "error: cannot set verifier stdout to binary mode\n";
        return 1;
    }
#endif
    std::cout << (ok ? "VALID" : "INVALID") << "\n";
    return ok ? 0 : 1;
}

// Mint signing and decoding share BtcVeldMintTemplatePolicy. The signer also
// requires every input to belong to the selected key.

static bool ParseReserveMintPolicyContext(const std::string& state_hex,
                                          const std::string& supply_text,
                                          veld::BtcVeldReserveMintPolicyContext& out) {
    using namespace veld;
    if (state_hex.empty() || supply_text.empty() ||
        (supply_text.size() > 1 && supply_text.front() == '0'))
        return false;
    uint64_t supply = 0;
    for (const char c : supply_text) {
        if (c < '0' || c > '9')
            return false;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (supply > (UINT64_MAX - digit) / 10)
            return false;
        supply = supply * 10 + digit;
    }
    const std::vector<uint8_t> encoded = HexToBytes(state_hex);
    btcveld::reserve::State state;
    if (encoded.empty() || state_hex != BytesToHex(encoded) ||
        !btcveld::reserve::DecodeState(encoded.data(), encoded.size(), state) ||
        !state.AccountingHolds(supply))
        return false;
    out.prior_state = state;
    out.circulating_supply = supply;
    return true;
}

static bool WritePrivateFile(const std::string& path, const std::vector<uint8_t>& bytes,
                             const char* label);

struct IntentAuthorizationRequest {
    std::string operation_type;
    std::string intended_recipient;
    uint64_t intended_amount{0};
    std::string expected_change_destination;
    std::string operation_identity_digest;
    uint64_t maximum_absolute_fee{0};
    uint64_t maximum_fee_rate{0};
};

// veld-keygen sign-tx <keyfile> <prepared-json> --intent FILE [--out FILE]
//   OFFLINE transaction signer for an air-gapped key (e.g. the btcVELD issuer).
//   Input is the JSON an ONLINE node's `preparerawtransaction` returned, saved
//   to a file and carried across on removable media. This tool decrypts the key
//   (VELD_VAULT_PASSPHRASE), verifies every input is a P2PKH owned by THIS key
//   (fail-closed), decodes the outputs for human review, signs each input with
//   ML-DSA-65 via the exact consensus BuildScriptSig, and writes the signed raw
//   tx hex to broadcast with `sendrawtransaction`. The private key never leaves
//   this machine. stdout carries ONLY the signed hex; review goes to stderr.
static int CmdSignTx(const std::string& keyfile, const std::string& prepared,
                     const std::string& intent_path, const std::string& outpath,
                     bool relay_op = false, const IntentAuthorizationRequest* authorize = nullptr) {
    using namespace veld;
    if (!fs::exists(keyfile)) {
        std::cerr << "error: no such key file: " << keyfile << "\n";
        return 2;
    }
    if (!fs::exists(prepared)) {
        std::cerr << "error: no such prepared file: " << prepared << "\n";
        return 2;
    }
    if (!authorize && (intent_path.empty() || !fs::exists(intent_path))) {
        std::cerr << "error: --intent FILE is required and must exist\n";
        return 2;
    }
    if (authorize && outpath.empty()) {
        std::cerr << "error: authorize-intent requires --out NEW_FILE\n";
        return 2;
    }
    if (!authorize) {
        std::error_code same_error;
        if (fs::equivalent(prepared, intent_path, same_error) && !same_error) {
            std::cerr
                << "error: prepared transaction and detached intent must be different files\n";
            return 2;
        }
    }

    bool kok = false;
    std::vector<uint8_t> kdata = ReadAllBytes(keyfile, kok);
    if (!kok) {
        std::cerr << "error: cannot read key file\n";
        return 1;
    }
    std::string pass = ReadPassphrase("decrypting signing key");
    std::string plaintext;
    try {
        plaintext = veld::wallet_crypto::DecryptWallet(kdata, pass);
    } catch (const std::exception& e) {
        veld::compat::SecureZero(pass.data(), pass.size());
        std::cerr << "error: decrypt failed: " << e.what() << "\n";
        return 1;
    }
    veld::compat::SecureZero(pass.data(), pass.size());
    std::istringstream ss(plaintext);
    std::string priv_hex, pub_hex, addr;
    std::getline(ss, priv_hex);
    std::getline(ss, pub_hex);
    std::getline(ss, addr);
    veld::compat::SecureZero(plaintext.data(), plaintext.size());
    if (priv_hex.size() != 64 || pub_hex.size() != 1952 * 2) {
        veld::compat::SecureZero(priv_hex.data(), priv_hex.size());
        std::cerr << "error: key file format unrecognized\n";
        return 1;
    }
    std::array<uint8_t, 32> seedarr{};
    if (!ParseHex32(priv_hex, seedarr)) {
        veld::compat::SecureZero(priv_hex.data(), priv_hex.size());
        std::cerr << "error: bad private key in file\n";
        return 1;
    }
    veld::compat::SecureZero(priv_hex.data(), priv_hex.size());
    Secp256k1PrivKey priv{};
    std::copy(seedarr.begin(), seedarr.end(), priv.begin());
    veld::compat::SecureZero(seedarr.data(), seedarr.size());
    std::vector<uint8_t> pub_bytes;
    if (!offline_signing::DecodeLowerHex(pub_hex, 1952U, pub_bytes) || pub_bytes.size() != 1952U) {
        veld::compat::SecureZero(priv.data(), priv.size());
        std::cerr << "error: public key encoding is non-canonical\n";
        return 1;
    }
    Secp256k1PubKey pub{};
    std::copy(pub_bytes.begin(), pub_bytes.end(), pub.begin());

    bool pok = false;
    std::vector<uint8_t> pbytes = ReadAllBytes(prepared, pok);
    if (!pok) {
        veld::compat::SecureZero(priv.data(), priv.size());
        std::cerr << "error: cannot read prepared file\n";
        return 1;
    }
    if (pbytes.size() > offline_signing::kMaxPreparedJsonBytes) {
        veld::compat::SecureZero(priv.data(), priv.size());
        std::cerr << "error: prepared file exceeds offline signing policy\n";
        return 1;
    }
    const std::string prep(pbytes.begin(), pbytes.end());
    btc_buy::JsonValue prep_root;
    std::string parse_error;
    btc_buy::StrictJsonParser prep_parser(prep, offline_signing::kMaxPreparedJsonBytes,
                                          /*reject_escaped_object_keys=*/true);
    if (!prep_parser.Parse(prep_root, parse_error)) {
        veld::compat::SecureZero(priv.data(), priv.size());
        std::cerr << "error: prepared JSON is not strict: " << parse_error << "\n";
        return 1;
    }

    Hash160 h160 = Hash160Compute(pub);
    std::vector<uint8_t> our_p2pkh = {0x76, 0xA9, 0x14};
    our_p2pkh.insert(our_p2pkh.end(), h160.begin(), h160.end());
    our_p2pkh.push_back(0x88);
    our_p2pkh.push_back(0xAC);

    offline_signing::VerifiedPrepared verified;
    if (!offline_signing::AuthenticatePrepared(prep_root, our_p2pkh, verified, parse_error)) {
        veld::compat::SecureZero(priv.data(), priv.size());
        std::cerr << "REFUSED (parent authentication): " << parse_error
                  << ". Nothing was signed.\n";
        return 1;
    }
    if (!offline_signing::VerifyExactFeesOnlyEnvelope(verified, our_p2pkh, parse_error)) {
        veld::compat::SecureZero(priv.data(), priv.size());
        std::cerr << "REFUSED (output envelope): " << parse_error << ". Nothing was signed.\n";
        return 1;
    }
    Transaction tx = verified.tx;

    std::string operation_identity;
    if (!offline_signing::ExtractCanonicalOperationIdentity(tx.outputs.back(), operation_identity,
                                                            parse_error)) {
        veld::compat::SecureZero(priv.data(), priv.size());
        std::cerr << "REFUSED (operation marker): " << parse_error << ". Nothing was signed.\n";
        return 1;
    }

    const auto* proposal = offline_signing::SelectObject(prep_root, "prepared_transaction");
    if (!proposal) {
        veld::compat::SecureZero(priv.data(), priv.size());
        std::cerr << "error: prepared transaction object is unavailable\n";
        return 1;
    }
    std::string reserve_prior_state_hex, reserve_prior_supply_sats;
    const auto* reserve_state = proposal->Get("reserve_prior_state_hex");
    const auto* reserve_supply = proposal->Get("reserve_prior_supply_sats");
    if (reserve_state || reserve_supply) {
        uint64_t supply = 0;
        if (!reserve_state || reserve_state->kind != btc_buy::JsonValue::Kind::String ||
            reserve_state->string_had_escape || !reserve_supply ||
            !btc_buy::ParseUint(*reserve_supply, supply)) {
            veld::compat::SecureZero(priv.data(), priv.size());
            std::cerr << "error: prepared reserve context is incomplete\n";
            return 1;
        }
        reserve_prior_state_hex = reserve_state->text;
        reserve_prior_supply_sats = std::to_string(supply);
    }
    veld::BtcVeldReserveMintPolicyContext reserve_context;
    const veld::BtcVeldReserveMintPolicyContext* reserve_context_ptr = nullptr;
    if (!reserve_prior_state_hex.empty() || !reserve_prior_supply_sats.empty()) {
        if (!ParseReserveMintPolicyContext(reserve_prior_state_hex, reserve_prior_supply_sats,
                                           reserve_context)) {
            veld::compat::SecureZero(priv.data(), priv.size());
            std::cerr << "error: prepared file has malformed reserve prior-state context\n";
            return 1;
        }
        reserve_context_ptr = &reserve_context;
    }

    //  Human review — decode outputs so the operator confirms intent BEFORE
    // the signed tx exists. For a btcVELD MINT the credited token amount +
    // recipient live in the OP_RETURN op, printed here as ASCII.
    std::cerr << "\n== Review the transaction you are signing ==\n"
              << "  signing key : " << addr << "\n"
              << "  inputs      : " << tx.inputs.size()
              << " (raw parents txid/vout/value/script authenticated)\n"
              << "  total input : " << verified.total_input << " base units\n"
              << "  total output: " << verified.total_output << " base units\n"
              << "  fee         : " << verified.fee << " base units\n"
              << "  signed size : " << verified.signed_size << " bytes\n"
              << "  fee rate    : " << verified.fee_rate << " base units/byte\n"
              << "  source digest: " << verified.source_transactions_digest << "\n"
              << "  output digest: " << verified.complete_output_digest << "\n"
              << "  outputs:\n";
    for (size_t i = 0; i < tx.outputs.size(); ++i) {
        const std::vector<uint8_t>& s = tx.outputs[i].script_pubkey;
        std::string kind, detail;
        if (!s.empty() && s[0] == 0x6A) {
            kind = "OP_RETURN";
            std::string ascii;
            for (const unsigned char byte : operation_identity) {
                const char c = static_cast<char>(byte);
                ascii += (c >= 32 && c < 127) ? c : '.';
            }
            if (ascii.size() > 256)
                ascii = ascii.substr(0, 256) + "... (" + std::to_string(operation_identity.size()) +
                        " payload bytes)";
            detail = "\"" + ascii + "\"; identity_digest=" +
                     offline_signing::OperationIdentityDigest(operation_identity);
        } else if (s.size() == 25 && s[0] == 0x76 && s[1] == 0xA9) {
            kind = "P2PKH";
            detail =
                (s == our_p2pkh) ? "change back to this address" : "-> hash160 " + HexOf(&s[3], 20);
        } else {
            kind = "script";
            detail = HexOf(s.data(), s.size());
        }
        std::cerr << "    [" << i << "] " << tx.outputs[i].value << " base units (" << std::fixed
                  << std::setprecision(8) << ((double)tx.outputs[i].value / 100000000.0)
                  << " VELD)  " << kind << "  " << detail << "\n";
    }
    std::cerr << "  If anything above is unexpected, DISCARD the output — do not broadcast.\n\n";

    uint64_t expected_change = 0;
    for (const auto& output : tx.outputs) {
        if (output.script_pubkey == our_p2pkh) {
            if (expected_change > UINT64_MAX - output.value) {
                veld::compat::SecureZero(priv.data(), priv.size());
                std::cerr << "REFUSED: change arithmetic overflow. Nothing was signed.\n";
                return 1;
            }
            expected_change += output.value;
        }
    }
    std::string operation_type, intended_recipient;
    uint64_t intended_amount = 0;

    // AUTHORITATIVE output-template policy. The human review above is advisory;
    // this is the signing gate. `sign-tx` remains issuer-mint-only. `sign-op`
    // accepts only the three permissionless btcVELD relay families and likewise
    // permits no spendable output except change to this key.
    if (relay_op) {
        std::string family;
        const std::string refusal = BtcVeldRelayTemplatePolicy(tx, our_p2pkh, family);
        if (!refusal.empty()) {
            veld::compat::SecureZero(priv.data(), priv.size());
            std::cerr << "REFUSED (relay policy): " << refusal << ". Nothing was signed.\n";
            return 1;
        }
        operation_type = family;
        intended_recipient.clear();
        intended_amount = 0;
        std::cerr << "  [policy] canonical fees-only relay verified: " << family << "\n\n";
    } else {
        std::string mint_from, mint_to, mint_memo;
        uint64_t mint_sats = 0;
        std::string mint_refusal = BtcVeldMintTemplatePolicy(
            tx, our_p2pkh, mint_from, mint_to, mint_sats, mint_memo, reserve_context_ptr);
        if (mint_refusal.empty()) {
            if (mint_from != addr)
                mint_refusal = "MINT 'from' (" + mint_from + ") != this issuer key (" + addr + ")";
            if (mint_refusal.empty())
                std::cerr << "  [policy] canonical mint verified: " << mint_sats
                          << " sats btcVELD -> " << mint_to << "\n\n";
            if (mint_refusal.empty()) {
                operation_type = "BTCVELD_MINT";
                intended_recipient = mint_to;
                intended_amount = mint_sats;
            }
        }
        if (!mint_refusal.empty()) {
            BtcVeldC1CarrierPolicyResult c1;
            std::string reserve_refusal = BtcVeldC1ReservationTemplatePolicy(tx, our_p2pkh, c1);
            if (reserve_refusal.empty() && c1.from != addr)
                reserve_refusal = c1.action + " 'from' differs from this issuer key";
            if (!reserve_refusal.empty()) {
                veld::compat::SecureZero(priv.data(), priv.size());
                std::cerr << "REFUSED (issuer policy): mint=" << mint_refusal
                          << "; C1=" << reserve_refusal << ". Nothing was signed.\n";
                return 1;
            }
            std::cerr << "  [policy] canonical " << c1.action << " C1 carrier verified: " << c1.sats
                      << " sats btcVELD -> " << c1.to << " allocation=" << c1.allocation_id
                      << "\n\n";
            operation_type = "BTCVELD_C1_" + c1.action;
            intended_recipient = c1.to;
            intended_amount = c1.sats;
        }
    }

    offline_signing::Intent intent;
    if (authorize) {
        if (authorize->operation_type != operation_type ||
            authorize->intended_recipient != intended_recipient ||
            authorize->intended_amount != intended_amount ||
            authorize->expected_change_destination != addr ||
            authorize->operation_identity_digest !=
                offline_signing::OperationIdentityDigest(operation_identity)) {
            veld::compat::SecureZero(priv.data(), priv.size());
            std::cerr << "REFUSED (authorization semantics): independently "
                         "supplied operation facts differ from the authenticated "
                         "transaction. Nothing was signed.\n";
            return 1;
        }
        intent = offline_signing::MakeIntent(verified.tx, verified.parent_raw, operation_type,
                                             intended_recipient, intended_amount, addr,
                                             expected_change, operation_identity);
        intent.maximum_absolute_fee = authorize->maximum_absolute_fee;
        intent.maximum_fee_rate = authorize->maximum_fee_rate;
        intent.intent_digest = offline_signing::IntentDigest(intent);
        if (!offline_signing::VerifyIntent(intent, verified, operation_type, intended_recipient,
                                           intended_amount, addr, expected_change,
                                           operation_identity, parse_error)) {
            veld::compat::SecureZero(priv.data(), priv.size());
            std::cerr << "REFUSED (authorization policy): " << parse_error
                      << ". Nothing was signed.\n";
            return 1;
        }
    } else {
        bool iok = false;
        const std::vector<uint8_t> ibytes = ReadAllBytes(intent_path, iok);
        if (!iok || ibytes.empty() || ibytes.size() > 64U * 1024U) {
            veld::compat::SecureZero(priv.data(), priv.size());
            std::cerr << "error: intent file is unreadable or exceeds 64 KiB\n";
            return 1;
        }
        const std::string intent_json(ibytes.begin(), ibytes.end());
        btc_buy::JsonValue intent_root;
        btc_buy::StrictJsonParser intent_parser(intent_json, 64U * 1024U,
                                                /*reject_escaped_object_keys=*/true);
        offline_signing::IntentAuthorization authorization;
        if (!intent_parser.Parse(intent_root, parse_error) ||
            !offline_signing::ParseIntent(intent_root, intent, parse_error) ||
            !offline_signing::ParseIntentAuthorization(intent_root, authorization, parse_error) ||
            !offline_signing::VerifyIntentAuthorization(intent, authorization, pub, parse_error) ||
            !offline_signing::VerifyIntent(intent, verified, operation_type, intended_recipient,
                                           intended_amount, addr, expected_change,
                                           operation_identity, parse_error)) {
            veld::compat::SecureZero(priv.data(), priv.size());
            std::cerr << "REFUSED (intent): " << parse_error << ". Nothing was signed.\n";
            return 1;
        }
    }
    std::cerr << "  [intent] version      : " << intent.version << "\n"
              << "  [intent] digest       : " << intent.intent_digest << "\n"
              << "  [intent] operation    : " << operation_type << "\n"
              << "  [intent] recipient    : "
              << (intended_recipient.empty() ? "(none)" : intended_recipient) << "\n"
              << "  [intent] amount       : " << intended_amount << " base units\n"
              << "  [intent] change       : " << expected_change << " -> " << addr << "\n"
              << "  [intent] marker family: "
              << operation_identity.substr(0, operation_identity.find('|')) << "\n"
              << "  [intent] identity bytes: " << operation_identity.size() << "\n"
              << "  [intent] identity digest: "
              << offline_signing::OperationIdentityDigest(operation_identity) << "\n\n";

    if (authorize) {
        const std::string pubkey_digest = offline_signing::AuthorizerPubkeyDigest(pub);
        Secp256k1SigDER authorization_signature;
        try {
            authorization_signature =
                Sign(priv, offline_signing::IntentAuthorizationHash(intent, pubkey_digest));
        } catch (const std::exception& e) {
            veld::compat::SecureZero(priv.data(), priv.size());
            std::cerr << "error: intent authorization failed: " << e.what() << "\n";
            return 1;
        }
        veld::compat::SecureZero(priv.data(), priv.size());
        auto q = [](const std::string& value) { return std::string("\"") + value + "\""; };
        const std::string document =
            "{\"signing_intent\":{"
            "\"version\":" +
            q(intent.version) + ",\"operation_type\":" + q(intent.operation_type) +
            ",\"intended_recipient\":" + q(intent.intended_recipient) +
            ",\"intended_amount\":" + std::to_string(intent.intended_amount) +
            ",\"expected_change_destination\":" + q(intent.expected_change_destination) +
            ",\"expected_change\":" + std::to_string(intent.expected_change) +
            ",\"maximum_absolute_fee\":" + std::to_string(intent.maximum_absolute_fee) +
            ",\"maximum_fee_rate\":" + std::to_string(intent.maximum_fee_rate) +
            ",\"source_transactions_digest\":" + q(intent.source_transactions_digest) +
            ",\"complete_output_digest\":" + q(intent.complete_output_digest) +
            ",\"operation_identity_digest\":" + q(intent.operation_identity_digest) +
            ",\"intent_digest\":" + q(intent.intent_digest) +
            "},\"intent_authorization\":{"
            "\"version\":" +
            q(offline_signing::kIntentAuthorizationVersion) +
            ",\"intent_digest\":" + q(intent.intent_digest) +
            ",\"network_identity\":" + q(DEPLOYMENT_PROFILE_ID) +
            ",\"genesis_hash\":" + q(GENESIS_HASH) +
            ",\"authorizer_pubkey_digest\":" + q(pubkey_digest) + ",\"signature_hex\":" +
            q(HexOf(authorization_signature.data(), authorization_signature.size())) + "}}";
        const std::vector<uint8_t> document_bytes(document.begin(), document.end());
        if (!WritePrivateFile(outpath, document_bytes, "authorized signing intent"))
            return 1;
        std::cerr << "authorized intent written: " << outpath
                  << "\n  detached intent digest: " << intent.intent_digest
                  << "\n  authorizer pubkey digest: " << pubkey_digest
                  << "\nNo transaction input was signed.\n";
        return 0;
    }

    for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
        SignedInput si = BuildScriptSig(priv, pub, tx, i, verified.prev_scripts[i]);
        tx.inputs[i].script_sig = si.script_sig;
    }
    veld::compat::SecureZero(priv.data(), priv.size());

    std::vector<uint8_t> sraw = tx.Serialize();
    if (sraw.size() != verified.signed_size) {
        std::cerr << "error: signed size differs from authenticated fee-rate projection\n";
        return 1;
    }
    std::string signed_hex = HexOf(sraw.data(), sraw.size());

    if (outpath.empty()) {
        std::cout << signed_hex << "\n";
    } else {
        std::ofstream of(outpath, std::ios::binary | std::ios::trunc);
        if (!of.good()) {
            std::cerr << "error: cannot write " << outpath << "\n";
            return 1;
        }
        of << signed_hex << "\n";
        std::cerr << "signed tx written: " << outpath << " (" << sraw.size() << " bytes)\n";
    }
    std::cerr << "broadcast online with: sendrawtransaction <hex>\n";
    return 0;
}

// veld-keygen decode-mint <issuer_p2pkh_hex> <unsigned_tx_hex>
//   KEYLESS strict decoder: applies the SAME canonical-mint policy as sign-tx to a
//   fully deserialized tx and, on success, prints compact JSON {from,to,sats,memo}.
//   Exits 2 with a stderr reason on ANY policy violation. The signer daemon uses this
//   instead of a byte-substring search so its independent parameter derivation cannot be
//   fooled by a marker smuggled into an unrelated (non-OP_RETURN) script.
static int CmdDecodeMint(const std::string& issuer_p2pkh_hex, const std::string& tx_hex,
                         const std::string& reserve_state_hex = {},
                         const std::string& reserve_supply_sats = {}) {
    using namespace veld;
    auto hex2b = [](const std::string& h, bool& ok) {
        std::vector<uint8_t> o;
        o.reserve(h.size() / 2);
        ok = (h.size() % 2 == 0);
        auto hc = [](char c) -> int {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return -1;
        };
        for (size_t i = 0; ok && i + 1 < h.size(); i += 2) {
            int a = hc(h[i]), b = hc(h[i + 1]);
            if (a < 0 || b < 0) {
                ok = false;
                break;
            }
            o.push_back((uint8_t)((a << 4) | b));
        }
        return o;
    };
    bool ok1 = false, ok2 = false;
    std::vector<uint8_t> issuer_p2pkh = hex2b(issuer_p2pkh_hex, ok1);
    std::vector<uint8_t> raw = hex2b(tx_hex, ok2);
    if (!ok1 || issuer_p2pkh.size() != 25) {
        std::cerr << "error: issuer_p2pkh_hex must be a 25-byte P2PKH\n";
        return 2;
    }
    if (!ok2 || raw.empty()) {
        std::cerr << "error: unsigned_tx_hex invalid\n";
        return 2;
    }
    Transaction tx;
    size_t consumed = Transaction::Deserialize(raw, 0, tx);
    if (!consumed || tx.inputs.empty()) {
        std::cerr << "error: cannot deserialize tx\n";
        return 2;
    }
    std::string from, to, memo;
    uint64_t sats = 0;
    BtcVeldReserveMintPolicyContext reserve_context;
    const BtcVeldReserveMintPolicyContext* reserve_context_ptr = nullptr;
    if (!reserve_state_hex.empty() || !reserve_supply_sats.empty()) {
        if (!ParseReserveMintPolicyContext(reserve_state_hex, reserve_supply_sats,
                                           reserve_context)) {
            std::cerr << "error: malformed reserve prior-state context\n";
            return 2;
        }
        reserve_context_ptr = &reserve_context;
    }
    std::string refusal =
        BtcVeldMintTemplatePolicy(tx, issuer_p2pkh, from, to, sats, memo, reserve_context_ptr);
    if (!refusal.empty()) {
        std::cerr << "REFUSED (mint policy): " << refusal << "\n";
        return 2;
    }
    uint64_t total_out = 0;
    for (const auto& o : tx.outputs)
        total_out += o.value;
    auto esc = [](const std::string& s) {
        std::string o;
        for (char c : s) {
            if (c == '"' || c == '\\')
                o += '\\';
            if ((unsigned char)c >= 32)
                o += c;
        }
        return o;
    };
    std::cout << "{\"from\":\"" << esc(from) << "\",\"to\":\"" << esc(to) << "\",\"sats\":" << sats
              << ",\"memo\":\"" << esc(memo) << "\",\"total_out_sats\":" << total_out
              << ",\"num_inputs\":" << tx.inputs.size() << "}\n";
    return 0;
}

// Keyless strict decoder for the issuer-signed C1 capacity carrier.  It shares
// the exact deserialized transaction policy used by sign-tx.
static int CmdDecodeC1Reservation(const std::string& issuer_p2pkh_hex, const std::string& tx_hex) {
    using namespace veld;
    auto hex2b = [](const std::string& h, bool& ok) {
        std::vector<uint8_t> out;
        out.reserve(h.size() / 2);
        ok = (h.size() % 2 == 0);
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return -1;
        };
        for (size_t i = 0; ok && i + 1 < h.size(); i += 2) {
            const int high = nibble(h[i]);
            const int low = nibble(h[i + 1]);
            if (high < 0 || low < 0) {
                ok = false;
                break;
            }
            out.push_back(static_cast<uint8_t>((high << 4) | low));
        }
        return out;
    };
    bool script_ok = false;
    bool tx_ok = false;
    const std::vector<uint8_t> issuer_p2pkh = hex2b(issuer_p2pkh_hex, script_ok);
    const std::vector<uint8_t> raw = hex2b(tx_hex, tx_ok);
    if (!script_ok || issuer_p2pkh.size() != 25 || !tx_ok || raw.empty()) {
        std::cerr << "error: invalid issuer script or transaction hex\n";
        return 2;
    }
    Transaction tx;
    const size_t consumed = Transaction::Deserialize(raw, 0, tx);
    if (!consumed || consumed != raw.size() || tx.inputs.empty()) {
        std::cerr << "error: cannot deserialize reservation transaction\n";
        return 2;
    }
    BtcVeldC1CarrierPolicyResult result;
    const std::string refusal = BtcVeldC1ReservationTemplatePolicy(tx, issuer_p2pkh, result);
    if (!refusal.empty()) {
        std::cerr << "REFUSED (C1 reservation policy): " << refusal << "\n";
        return 2;
    }
    uint64_t total_out = 0;
    for (const auto& output : tx.outputs) {
        if (total_out > UINT64_MAX - output.value) {
            std::cerr << "error: output sum overflow\n";
            return 2;
        }
        total_out += output.value;
    }
    auto esc = [](const std::string& s) {
        std::string out;
        for (char c : s) {
            if (c == '"' || c == '\\')
                out += '\\';
            if (static_cast<unsigned char>(c) >= 32)
                out += c;
        }
        return out;
    };
    auto optional_json_string = [&](const std::string& value) {
        return value.empty() ? std::string("null") : std::string("\"") + esc(value) + "\"";
    };
    std::cout << "{\"action\":\"" << result.action << "\",\"from\":\"" << esc(result.from)
              << "\",\"to\":\"" << esc(result.to) << "\",\"sats\":" << result.sats
              << ",\"allocation_id\":\"" << result.allocation_id
              << "\",\"allocation_commitment\":\"" << result.allocation_commitment
              << "\",\"fund_script_pubkey_hex\":"
              << optional_json_string(result.fund_script_pubkey_hex)
              << ",\"fund_commitment_blind_hex\":"
              << optional_json_string(result.fund_commitment_blind_hex)
              << ",\"fund_outpoint\":" << optional_json_string(result.fund_outpoint)
              << ",\"funding_proof_hex\":" << optional_json_string(result.funding_proof_hex)
              << ",\"total_out_sats\":" << total_out << ",\"num_inputs\":" << tx.inputs.size()
              << "}\n";
    return 0;
}

namespace secure_file = veld::channel::secure_file;

static veld::Hash256 Sha256Bytes(const std::vector<uint8_t>& bytes) {
    veld::SHA256 hash;
    hash.update(bytes.data(), bytes.size());
    return hash.digest();
}

static std::string Sha256Hex(const std::vector<uint8_t>& bytes) {
    return veld::HashToHex(Sha256Bytes(bytes));
}

static bool ReadPrivateFile(const std::string& path, size_t max_size, std::vector<uint8_t>& out,
                            const char* label) {
    std::string error;
    const auto result = secure_file::Read(path, out, &error, max_size,
                                          /*require_private_parent=*/true);
    if (result != secure_file::ReadResult::Ok) {
        std::cerr << "error: cannot securely read " << label << " " << path << ": "
                  << (result == secure_file::ReadResult::NotFound ? "not found" : error) << "\n";
        return false;
    }
    return true;
}

static bool WritePrivateFile(const std::string& path, const std::vector<uint8_t>& bytes,
                             const char* label) {
    std::string error;
    if (!secure_file::AtomicWriteNew(path, bytes, &error,
                                     /*require_private_parent=*/true)) {
        std::cerr << "error: cannot publish " << label << " without overwrite: " << error << "\n";
        return false;
    }
    return true;
}

static int CmdExportPublicKeyRaw(const std::string& keyfile, const std::string& output) {
    if (keyfile.empty() || output.empty()) {
        std::cerr << "Usage: veld-keygen export-public-key-raw "
                     "<keyfile> <new-output>\n";
        return 2;
    }
    if (fs::exists(output)) {
        std::cerr << "error: refusing to overwrite existing public-key file\n";
        return 2;
    }
    std::vector<uint8_t> encrypted;
    if (!ReadPrivateFile(keyfile, 1024u * 1024u, encrypted, "encrypted key"))
        return 1;

    SensitiveString pass(ReadPassphrase("decrypting key for raw public export"));
    if (pass.value.empty()) {
        std::cerr << "error: empty passphrase rejected\n";
        return 1;
    }
    SensitiveString plaintext;
    try {
        plaintext.value = veld::wallet_crypto::DecryptWallet(encrypted, pass.value);
    } catch (const std::exception& e) {
        std::cerr << "error: decrypt failed: " << e.what() << "\n";
        return 1;
    }
    const size_t first = plaintext.value.find('\n');
    const size_t second =
        first == std::string::npos ? std::string::npos : plaintext.value.find('\n', first + 1);
    const size_t third =
        second == std::string::npos ? std::string::npos : plaintext.value.find('\n', second + 1);
    if (first == std::string::npos || second == std::string::npos || third == std::string::npos ||
        third + 1 != plaintext.value.size()) {
        std::cerr << "error: key file format is not canonical\n";
        return 1;
    }
    SensitiveString seed_hex(plaintext.value.substr(0, first));
    const std::string stored_pub_hex = plaintext.value.substr(first + 1, second - first - 1);
    const std::string address = plaintext.value.substr(second + 1, third - second - 1);
    if (address.empty() || address.find_first_of("\r\n") != std::string::npos) {
        std::cerr << "error: key file identity field is not canonical\n";
        return 1;
    }
    LockedSeed seed;
    if (!seed.locked || !ParseHex32(seed_hex.value, seed.bytes)) {
        std::cerr << "error: key file has no canonical private seed\n";
        return 1;
    }
    veld::dilithium::PublicKey derived{};
    const std::vector<uint8_t> stored_pub = veld::HexToBytes(stored_pub_hex);
    if (stored_pub.size() != derived.size() || veld::BytesToHex(stored_pub) != stored_pub_hex) {
        std::cerr << "error: key file has no canonical 1952-byte public key\n";
        return 1;
    }
    try {
        derived = veld::DerivePublicKey(seed.bytes);
    } catch (const std::exception& e) {
        std::cerr << "error: ML-DSA public-key derivation failed: " << e.what() << "\n";
        return 1;
    }
    if (!veld::compat::ConstantTimeEqual(derived.data(), stored_pub.data(), derived.size())) {
        std::cerr << "error: stored public key does not match private seed\n";
        return 1;
    }
    const std::vector<uint8_t> raw(derived.begin(), derived.end());
    if (!WritePrivateFile(output, raw, "raw ML-DSA-65 public key"))
        return 1;
    std::cout << "public-key-bytes: " << raw.size() << "\n"
              << "public-key-sha256: " << Sha256Hex(raw) << "\n"
              << "file: " << output << "\n";
    return 0;
}

static void PrintUsage() {
    std::cerr << "veld-keygen — post-quantum (ML-DSA-65) keypair tool\n"
                 "\n"
                 "Usage:\n"
#ifdef VELD_PUBLIC_RELEASE
                 "  veld-keygen new --out FILE\n"
                 "  veld-keygen from-seed --out FILE [--seed-input-handle DECIMAL]\n"
#else
                 "  veld-keygen new --out FILE [--testnet]\n"
                 "  veld-keygen from-seed --out FILE [--testnet] "
                 "[--seed-input-handle DECIMAL]\n"
#endif
                 "  veld-keygen show FILE [--full-pubkey-hex]\n"
                 "  veld-keygen export-public-key-raw <keyfile> <new-output>\n"
                 "  veld-keygen sign-release <keyfile> <input> <outsig>\n"
                 "  veld-keygen verify-release <pubhex|@file> <input> <sigfile>\n"
                 "  veld-keygen authorize-intent <keyfile> <prepared-json> "
                 "--operation-type TYPE --recipient ADDRESS|- --amount UNITS "
                 "--change-destination ADDRESS --operation-identity-digest HEX "
                 "--maximum-absolute-fee UNITS --maximum-fee-rate UNITS_PER_BYTE "
                 "--out NEW_FILE\n"
                 "  veld-keygen sign-tx <keyfile> <prepared-json> --intent FILE [--out FILE]\n"
                 "  veld-keygen sign-op <keyfile> <prepared-json> --intent FILE [--out FILE]\n"
                 "  veld-keygen decode-mint <issuer_p2pkh_hex> <unsigned_tx_hex> "
                 "[<reserve_prior_state_hex> <reserve_prior_supply_sats>]\n"
                 "  veld-keygen decode-c1-reservation <issuer_p2pkh_hex> <unsigned_tx_hex>\n"
                 "\n"
                 "Generic commands take VELD_VAULT_PASSPHRASE when set. Key outputs\n"
                 "require a real, owner-controlled private directory and are atomic,\n"
                 "mode 0600, and write-once. Seed input handles must be inherited\n"
                 "anonymous pipes carrying exactly 64 raw hex bytes followed by EOF.\n";
}

static void PrintDeploymentInfoJson() {
    std::cout << "VELD_DEPLOYMENT_INFO_V1_JSON {"
              << "\"binary_role\":\"keygen\","
              << "\"client_version\":\"" << veld::CLIENT_VERSION << "\","
              << "\"display_name\":\"" << veld::DEPLOYMENT_DISPLAY_NAME << "\","
              << "\"disposable\":" << (veld::DEPLOYMENT_DISPOSABLE ? "true" : "false") << ","
              << "\"external_value\":" << (veld::DEPLOYMENT_EXTERNAL_VALUE ? "true" : "false")
              << ","
              << "\"fleet_no_mine\":false,"
              << "\"profile_id\":\"" << veld::DEPLOYMENT_PROFILE_ID << "\","
              << "\"role\":\"" << veld::DEPLOYMENT_ROLE << "\","
              << "\"warning\":\"" << veld::DEPLOYMENT_WARNING << "\""
              << "}\n";
}

int main(int argc, char** argv) {
    veld::compat::HardenDllSearchPath();

    // Pure identity probes precede crypto self-tests and file handling so
    // build/package controllers can attest this exact artifact safely.
    if (argc == 2 && (std::string(argv[1]) == "--version" || std::string(argv[1]) == "-V")) {
        std::cout << "Veld Keygen " << veld::CLIENT_VERSION << "\n";
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--deployment-info") {
        PrintDeploymentInfoJson();
        return 0;
    }

#ifdef VELD_PUBLIC_RELEASE
    // A public package emits only addresses for its compiled mainnet identity.
    // Reject the developer address format before usage/crypto/subcommand early
    // exits so argument ordering cannot re-enable it.
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--testnet") {
            std::cerr << "veld-keygen: FATAL: --testnet is unavailable in "
                         "VELD_PUBLIC_RELEASE; use an explicitly non-public "
                         "developer build\n";
            return 2;
        }
    }
#endif

    veld::vendored_crypto::vendored_crypto_selftest();

    if (argc < 2) {
        PrintUsage();
        return 2;
    }
    std::string cmd = argv[1];

    if (cmd == "new" || cmd == "from-seed") {
        std::string out_path;
        bool testnet = false;
        bool have_seed_input_handle = false;
        uint64_t seed_input_handle = 0;
        int first_opt = 2;
        if (cmd == "from-seed" && argc >= 3 && argv[2][0] != '-') {
            std::cerr << "error: legacy positional seed import is rejected; "
                         "seed material must never appear in process arguments\n";
            return 2;
        }
        for (int i = first_opt; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--out" && i + 1 < argc) {
                out_path = argv[++i];
            } else if (a == "--testnet") {
                testnet = true;
            } else if (a == "--seed-input-handle" && i + 1 < argc && cmd == "from-seed" &&
                       !have_seed_input_handle &&
                       ParseCanonicalU64Arg(argv[i + 1], seed_input_handle)) {
                have_seed_input_handle = true;
                ++i;
            } else {
                std::cerr << "error: unknown or incomplete option at argument " << i
                          << " (argument value suppressed)\n";
                return 2;
            }
        }

        // Validate the destination and passphrase before any seed is imported
        // or generated. In particular, no seed representation remains live
        // while an operator may be waiting at the passphrase prompt.
        const int output_status = ValidateNewOutputPath(out_path);
        if (output_status != 0)
            return output_status;
        SensitiveString pass(ReadPassphrase("encrypting new key"));
        std::string policy_error;
        if (!veld::wallet_crypto::ValidateNewPassphrase(pass.value, &policy_error)) {
            std::cerr << "error: " << policy_error << "\n";
            return 1;
        }

        if (cmd == "from-seed") {
            LockedSeed seed;
            if (!seed.locked) {
                std::cerr << "error: cannot lock imported seed memory\n";
                return 1;
            }
            SensitiveString seed_hex;
            std::string input_error;
            const bool input_ok =
                have_seed_input_handle
                    ? ReadSeedFromProtectedHandle(seed_input_handle, seed_hex, input_error)
                    : ReadSeedWithoutArgv(seed_hex, input_error);
            if (!input_ok) {
                std::cerr << "error: " << input_error << "\n";
                return 2;
            }
            const bool parsed = ParseHex32(seed_hex.value, seed.bytes);
            seed_hex.Clear();
            if (!parsed) {
                std::cerr << "error: seed must be 64 hex chars, nonzero\n";
                return 2;
            }
            return CmdNew(out_path, testnet, &seed, pass);
        }
        return CmdNew(out_path, testnet, nullptr, pass);
    }

    if (cmd == "show") {
        if (argc < 3) {
            PrintUsage();
            return 2;
        }
        bool full_pubkey = false;
        for (int i = 3; i < argc; ++i) {
            if (std::string(argv[i]) == "--full-pubkey-hex")
                full_pubkey = true;
        }
        return CmdShow(argv[2], full_pubkey);
    }

    if (cmd == "export-public-key-raw") {
        if (argc != 4) {
            std::cerr << "Usage: veld-keygen export-public-key-raw "
                         "<keyfile> <new-output>\n";
            return 2;
        }
        return CmdExportPublicKeyRaw(argv[2], argv[3]);
    }

    if (cmd == "sign-release") {
        if (argc < 5) {
            std::cerr << "Usage: veld-keygen sign-release <keyfile> <input> <outsig>\n";
            return 2;
        }
        return CmdSignRelease(argv[2], argv[3], argv[4]);
    }

    if (cmd == "verify-release") {
        if (argc < 5) {
            std::cerr << "Usage: veld-keygen verify-release <pubhex|@file> <input> <sigfile>\n";
            return 2;
        }
        return CmdVerifyRelease(argv[2], argv[3], argv[4]);
    }

    if (cmd == "decode-mint") {
        if (argc != 4 && argc != 6) {
            std::cerr << "Usage: veld-keygen decode-mint <issuer_p2pkh_hex> "
                         "<unsigned_tx_hex> [<reserve_prior_state_hex> "
                         "<reserve_prior_supply_sats>]\n";
            return 2;
        }
        return CmdDecodeMint(argv[2], argv[3], argc == 6 ? argv[4] : "", argc == 6 ? argv[5] : "");
    }

    if (cmd == "decode-c1-reservation") {
        if (argc < 4) {
            std::cerr << "Usage: veld-keygen decode-c1-reservation "
                         "<issuer_p2pkh_hex> <unsigned_tx_hex>\n";
            return 2;
        }
        return CmdDecodeC1Reservation(argv[2], argv[3]);
    }

    if (cmd == "authorize-intent") {
        if (argc < 4) {
            std::cerr << "Usage: veld-keygen authorize-intent <keyfile> "
                         "<prepared-json> --operation-type TYPE "
                         "--recipient ADDRESS|- --amount UNITS "
                         "--change-destination ADDRESS "
                         "--operation-identity-digest HEX "
                         "--maximum-absolute-fee UNITS "
                         "--maximum-fee-rate UNITS_PER_BYTE --out NEW_FILE\n";
            return 2;
        }
        IntentAuthorizationRequest request;
        std::string output;
        bool have_operation = false, have_recipient = false, have_amount = false,
             have_change = false, have_identity = false, have_absolute = false, have_rate = false,
             have_output = false;
        auto take = [&](int& i, std::string& value) {
            if (i + 1 >= argc)
                return false;
            value = argv[++i];
            return true;
        };
        for (int i = 4; i < argc; ++i) {
            const std::string option = argv[i];
            std::string value;
            bool ok = true;
            if (option == "--operation-type" && !have_operation) {
                ok = take(i, request.operation_type);
                have_operation = ok;
            } else if (option == "--recipient" && !have_recipient) {
                ok = take(i, request.intended_recipient);
                have_recipient = ok;
                if (ok && request.intended_recipient == "-")
                    request.intended_recipient.clear();
            } else if (option == "--amount" && !have_amount) {
                ok = take(i, value) && ParseCanonicalU64Arg(value, request.intended_amount);
                have_amount = ok;
            } else if (option == "--change-destination" && !have_change) {
                ok = take(i, request.expected_change_destination);
                have_change = ok;
            } else if (option == "--operation-identity-digest" && !have_identity) {
                ok = take(i, request.operation_identity_digest) &&
                     veld::btc_buy::IsLowerHex(request.operation_identity_digest, 64);
                have_identity = ok;
            } else if (option == "--maximum-absolute-fee" && !have_absolute) {
                ok = take(i, value) && ParseCanonicalU64Arg(value, request.maximum_absolute_fee);
                have_absolute = ok;
            } else if (option == "--maximum-fee-rate" && !have_rate) {
                ok = take(i, value) && ParseCanonicalU64Arg(value, request.maximum_fee_rate);
                have_rate = ok;
            } else if (option == "--out" && !have_output) {
                ok = take(i, output);
                have_output = ok;
            } else {
                ok = false;
            }
            if (!ok) {
                std::cerr << "unknown, duplicate, malformed, or incomplete "
                             "authorization option: "
                          << option << "\n";
                return 2;
            }
        }
        if (!have_operation || !have_recipient || !have_amount || !have_change || !have_identity ||
            !have_absolute || !have_rate || !have_output || request.operation_type.empty() ||
            output.empty()) {
            std::cerr << "authorize-intent requires every authoritative "
                         "semantic, fee, and output option\n";
            return 2;
        }
        const bool relay = request.operation_type == "VELD_BHDR|" ||
                           request.operation_type == "VELD_ANCHOR|" ||
                           request.operation_type == "VELD_RSV1|";
        return CmdSignTx(argv[2], argv[3], "", output, relay, &request);
    }

    if (cmd == "sign-tx" || cmd == "sign-op") {
        if (argc < 4) {
            std::cerr << "Usage: veld-keygen " << cmd
                      << " <keyfile> <prepared-json> --intent FILE [--out FILE]\n";
            return 2;
        }
        std::string outp, intent;
        for (int i = 4; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--out" && i + 1 < argc)
                outp = argv[++i];
            else if (a == "--intent" && i + 1 < argc)
                intent = argv[++i];
            else {
                std::cerr << "unknown or incomplete signing option: " << a << "\n";
                return 2;
            }
        }
        return CmdSignTx(argv[2], argv[3], intent, outp, cmd == "sign-op");
    }

    if (cmd == "rotate-pass") {
        if (argc < 3) {
            std::cerr << "Usage: VELD_OLD_PASSPHRASE=... VELD_NEW_PASSPHRASE=... veld-keygen "
                         "rotate-pass FILE\n";
            return 2;
        }
        std::string path = argv[2];
        const char* old_e = std::getenv("VELD_OLD_PASSPHRASE");
        const char* new_e = std::getenv("VELD_NEW_PASSPHRASE");
        if (!old_e || !*old_e || !new_e || !*new_e) {
            std::cerr << "error: VELD_OLD_PASSPHRASE and VELD_NEW_PASSPHRASE must both be set\n";
            return 2;
        }
        std::string old_pass(old_e), new_pass(new_e);
        veld::compat::UnsetEnv("VELD_OLD_PASSPHRASE");
        veld::compat::UnsetEnv("VELD_NEW_PASSPHRASE");
        std::string policy_error;
        if (!veld::wallet_crypto::ValidateNewPassphrase(new_pass, &policy_error)) {
            veld::compat::SecureZero(old_pass.data(), old_pass.size());
            veld::compat::SecureZero(new_pass.data(), new_pass.size());
            std::cerr << "error: " << policy_error << "\n";
            return 2;
        }
        if (!fs::exists(path)) {
            std::cerr << "error: no such file: " << path << "\n";
            return 2;
        }
        std::ifstream f(path, std::ios::binary);
        if (!f.good()) {
            std::cerr << "error: cannot read: " << path << "\n";
            return 1;
        }
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                                  std::istreambuf_iterator<char>());
        f.close();
        std::string plaintext;
        try {
            plaintext = veld::wallet_crypto::DecryptWallet(data, old_pass);
        } catch (const std::exception& e) {
            veld::compat::SecureZero(old_pass.data(), old_pass.size());
            veld::compat::SecureZero(new_pass.data(), new_pass.size());
            std::cerr << "error: decrypt failed (wrong VELD_OLD_PASSPHRASE?): " << e.what() << "\n";
            return 1;
        }
        veld::compat::SecureZero(old_pass.data(), old_pass.size());
        std::vector<uint8_t> blob;
        try {
            blob = veld::wallet_crypto::EncryptWallet(plaintext, new_pass);
        } catch (const std::exception& e) {
            veld::compat::SecureZero(plaintext.data(), plaintext.size());
            veld::compat::SecureZero(new_pass.data(), new_pass.size());
            std::cerr << "error: re-encrypt failed: " << e.what() << "\n";
            return 1;
        }
        veld::compat::SecureZero(new_pass.data(), new_pass.size());
        std::istringstream ss(plaintext);
        std::string seed_hex, pub_hex, addr;
        std::getline(ss, seed_hex);
        std::getline(ss, pub_hex);
        std::getline(ss, addr);
        veld::compat::SecureZero(plaintext.data(), plaintext.size());
        std::string tmp_path = path + ".tmp";
        {
            std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
            if (!out.good()) {
                std::cerr << "error: cannot open " << tmp_path << " for write\n";
                return 1;
            }
            out.write(reinterpret_cast<const char*>(blob.data()), (std::streamsize)blob.size());
            out.flush();
            if (!out.good()) {
                std::cerr << "error: write failed on " << tmp_path << "\n";
                return 1;
            }
        }
        std::error_code ec;
        fs::rename(tmp_path, path, ec);
        if (ec) {
            std::cerr << "error: rename " << tmp_path << " -> " << path << ": " << ec.message()
                      << "\n";
            return 1;
        }
        std::cout << "rotated: " << path << "\n";
        std::cout << "address: " << addr << "\n";
        return 0;
    }

    PrintUsage();
    return 2;
}
