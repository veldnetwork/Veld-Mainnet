#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif
#endif
#include <csignal>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <cctype>

#if defined(VELD_PUBLIC_MAINNET) && !defined(VELD_USE_LEVELDB)
#error "A public mainnet node must use the canonical LevelDB storage backend"
#endif

#include "compat/platform.h"
#include "compat/base64.h"
#include "compat/secure_string.h"

#include "../include/core/constants.h"
#include "../include/core/version.h"
#include "../include/core/hash.h"
#include "../include/core/transaction.h"
#include "../include/core/block.h"
#include "../include/core/blockchain.h"
#include "../include/core/mempool.h"
#include "../include/core/script.h"
#include "../include/core/leveldb.h"
#include "../include/mining/miner.h"
#include "../include/mining/veldhash.h"
#include "../include/mining/genesis_pow.h"
#include "../include/wallet/wallet.h"
#include "../include/wallet/wallet_crypto.h"
#include "../include/wallet/passphrase_policy.h"
#ifndef VELD_PUBLIC_TESTNET
#include "../include/wallet/browser_keystore.h"
#include "../include/wallet/cli.h"
#endif
#include "../include/wallet/secure_channel_file.h"
#include "../include/consensus/staking.h"
#include "../include/network/chainparams.h"
#include "../include/network/p2p.h"
#include "../include/network/rpc.h"
#include "../include/network/explorer.h"
#include "../include/network/seeder.h"
#include "../include/network/operational_key_identity.h"
#ifdef VELD_PUBLIC_TESTNET
#endif
#include "../include/crypto/veld_signing.h"
#include "../include/crypto/release_verify.h"
#ifdef _WIN32
#include "../include/crypto/vendored.h"
#endif
#include "../include/node/node.h"
#include "../include/node/ibd_policy.h"
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
#include "../include/node/public_snapshot_bootstrap.h"
#endif
#include "../include/network/rpc_http.h"

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((LONG)0x00000000L)
#endif
#else
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

using namespace veld;
using namespace veld::mining;

#define GOLD  "\033[38;5;220m"
#define GREEN "\033[32m"
#define RED   "\033[31m"
#define CYAN  "\033[36m"
#define GRAY  "\033[90m"
#define PURPLE "\033[38;5;141m"
#define YEL   "\033[33m"
#define BOLD  "\033[1m"
#define RESET "\033[0m"

void PrintStatus(const VeldNode& node, const std::string& miner_addr, bool mining, bool endorse_mode) {
    std::time_t t = std::time(nullptr);
    char timebuf[20];
    struct tm tm_info{};
#ifdef _WIN32
    localtime_s(&tm_info, &t);
#else
    localtime_r(&t, &tm_info);
#endif
    std::strftime(timebuf, sizeof(timebuf), "%H:%M:%S", &tm_info);

    std::lock_guard<std::mutex> lk(veld::net::g_stdout_mtx);
    std::cout << GRAY << "[" << timebuf << "] " << RESET
              << "height=" << BOLD << node.GetChain().Height() << RESET
              << "  supply=" << GOLD
              << std::fixed << std::setprecision(2)
              << node.GetChain().TotalSupplyVeld() << " VELD" << RESET
              << "  mempool=" << node.GetMempool().Size()
              << "  phase=" << (node.GetChain().TotalSupplyUnits() < node.GetChain().GetStakingActivationUnits()
                               ? "bootstrap" : CYAN "standard" RESET)
              << ((!mining && !endorse_mode)
                     ? (GRAY "  [fleet]" RESET)
                     : (!node.IsIBDComplete() || !node.ChainFullyValidated())
                         ? (GRAY "  [sync]" RESET)
                         : mining && node.IsMining()
                             ? (node.IsAddressRegisteredValidator(miner_addr)
                                   ? ("  [" GREEN "mining" RESET "+" PURPLE "endorsing" RESET "]")
                                   : (GREEN "  [mining]" RESET))
                             : mining
                                 ? (GRAY "  [mining stopped]" RESET)
                                 : (PURPLE "  [endorsing]" RESET))
              << "  peers=" << node.ConnectedPeers()
              << "\n";
    std::cout.flush();
}

static std::atomic<bool> g_shutdown{false};

// Fleet clock anchors are operator identities, not discovery hints.  Keep the
// environment grammar deliberately small: a comma-separated list of exact,
// canonical IPv4 literals.  Canonical-IP validation is performed by the shared
// NodeServer policy immediately after argument parsing and again when each
// anchor is registered/dialed after Start().
static bool AppendFleetAnchorEnvironment(std::vector<std::string>& anchors,
                                         std::string& error) {
    const char* raw = std::getenv("VELD_FLEET_ANCHOR_IPS");
    if (!raw) return true;
    const std::string value(raw);
    if (value.empty()) {
        error = "VELD_FLEET_ANCHOR_IPS is empty";
        return false;
    }
    size_t begin = 0;
    while (begin <= value.size()) {
        const size_t comma = value.find(',', begin);
        const size_t length = (comma == std::string::npos)
            ? value.size() - begin : comma - begin;
        const std::string field = value.substr(begin, length);
        const size_t first = field.find_first_not_of(" \t\r\n");
        const size_t last = field.find_last_not_of(" \t\r\n");
        if (first == std::string::npos) {
            error = "VELD_FLEET_ANCHOR_IPS contains an empty entry";
            return false;
        }
        anchors.push_back(field.substr(first, last - first + 1));
        if (comma == std::string::npos) break;
        begin = comma + 1;
    }
    return true;
}

static void handle_signal(int) {
    g_shutdown.store(true);
#ifndef _WIN32
    constexpr unsigned HARD_ESCAPE_SEC = 25;
    static std::atomic<bool> escape_armed{false};
    if (!escape_armed.exchange(true)) {
        alarm(HARD_ESCAPE_SEC);
    }
#endif
}

#ifdef _WIN32
static BOOL WINAPI ConsoleHandler(DWORD event) {
    if (event == CTRL_CLOSE_EVENT || event == CTRL_C_EVENT ||
        event == CTRL_BREAK_EVENT || event == CTRL_LOGOFF_EVENT ||
        event == CTRL_SHUTDOWN_EVENT) {
        g_shutdown.store(true);
        Sleep(5000);
        return TRUE;
    }
    return FALSE;
}

// The desktop GUI launches the node without a console window, so console
// control events are not a reliable shutdown mechanism for that process.
// Expose a per-process, same-session event that lets the GUI request the same
// orderly shutdown path used by Ctrl+C.  The event carries no authority beyond
// what the local Windows account already has over its own process.
class WindowsGuiShutdownEvent {
public:
    WindowsGuiShutdownEvent() {
        const std::wstring name = L"Local\\VeldNodeShutdown-" +
            std::to_wstring(GetCurrentProcessId());
        event_ = CreateEventW(nullptr, TRUE, FALSE, name.c_str());
        if (!event_) return;
        waiter_ = std::thread([this]() {
            if (WaitForSingleObject(event_, INFINITE) == WAIT_OBJECT_0)
                g_shutdown.store(true, std::memory_order_release);
        });
    }

    ~WindowsGuiShutdownEvent() {
        if (!event_) return;
        SetEvent(event_);
        if (waiter_.joinable()) waiter_.join();
        CloseHandle(event_);
    }

    WindowsGuiShutdownEvent(const WindowsGuiShutdownEvent&) = delete;
    WindowsGuiShutdownEvent& operator=(const WindowsGuiShutdownEvent&) = delete;

private:
    HANDLE event_{nullptr};
    std::thread waiter_;
};
#endif

// ── Interactive mining-identity wizard ─────────────────────────────────
//
// Fired when the user runs `veld-node --mine` on a fresh machine (no
// miner.key on disk) OR passes `--setup` explicitly. Offers the 4 login
// paths the user expects from the desktop mining client:
//
//   [1] Resume previous session  (reuse existing miner.key if present)
//   [2] Log in from a keyfile    (.veld-keys with plaintext privkey field)
//   [3] Log in with a different VELD wallet (paste raw privkey)
//   [4] Create a brand-new wallet
//
// The chosen identity is written to <datadir>/miner.key in the 3-line
// format (privhex / pubhex / address) that the normal mining-setup
// block immediately below consumes, so from there the miner just starts.
//
// This function DOES NOT touch P2P, RPC, or the chain. It's purely a
// console prompt that ends with a file on disk.

static std::string _wiz_trim(std::string s) {
    while (!s.empty() && (s.back()=='\n'||s.back()=='\r'||s.back()==' '||s.back()=='\t')) s.pop_back();
    size_t i=0; while (i<s.size() && (s[i]==' '||s[i]=='\t')) ++i;
    std::string trimmed = s.substr(i);
    veld::WipeString(s);
    return trimmed;
}

static std::string _wiz_unquote_path(std::string path) {
    path = _wiz_trim(std::move(path));
    if (path.size() >= 2 &&
        ((path.front() == '"' && path.back() == '"') ||
         (path.front() == '\'' && path.back() == '\''))) {
        path = path.substr(1, path.size() - 2);
    }
    return _wiz_trim(std::move(path));
}

static bool _wiz_resolve_keyfile_input(const std::string& entered,
                                       std::string& resolved,
                                       bool& ignored_miner_key) {
    namespace fs = std::filesystem;
    ignored_miner_key = false;
    std::string input = _wiz_unquote_path(entered);
    if (input.empty()) return false;

    std::error_code ec;
    fs::path exact = fs::absolute(input, ec).lexically_normal();
    if (!ec && fs::is_regular_file(exact, ec) && !ec) {
        resolved = exact.string();
        return true;
    }

    std::string lower = input;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    const size_t suffix = lower.find(".veld-keys");
    if (suffix == std::string::npos) return false;
    const size_t keyfile_end = suffix + std::string(".veld-keys").size();
    size_t candidate_end = keyfile_end;
    if (candidate_end < input.size() &&
        (input[candidate_end] == '"' || input[candidate_end] == '\''))
        ++candidate_end;
    std::string candidate = _wiz_unquote_path(input.substr(0, candidate_end));
    std::string trailing = _wiz_unquote_path(input.substr(candidate_end));
    std::string trailing_lower = trailing;
    std::transform(trailing_lower.begin(), trailing_lower.end(), trailing_lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (!trailing.empty() &&
        (trailing_lower.size() < 9 ||
         trailing_lower.compare(trailing_lower.size() - 9, 9, "miner.key") != 0)) {
        return false;
    }

    ec.clear();
    fs::path parsed = fs::absolute(candidate, ec).lexically_normal();
    if (ec || !fs::is_regular_file(parsed, ec) || ec) return false;
    resolved = parsed.string();
    ignored_miner_key = !trailing.empty();
    return true;
}
static bool _wiz_is_hex64(std::string_view s) {
    if (s.size() != 64) return false;
    for (char c : s)
        if (!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'))) return false;
    return true;
}
struct _WizWipingString : std::string {
    using std::string::string;
    using std::string::operator=;
    ~_WizWipingString() { veld::WipeString(*this); }
};
static _WizWipingString g_passphrase;

static constexpr size_t WIZ_MAX_OPERATIONAL_SECRET_BYTES = 1024u * 1024u;
#ifndef VELD_PUBLIC_TESTNET
static constexpr size_t WIZ_MAX_EXPLICIT_IMPORT_BYTES = 4u * 1024u * 1024u;
#endif
static constexpr size_t WIZ_MAX_RPC_TOKEN_BYTES = 64u * 1024u;

static bool _wiz_read_private_bytes(const std::string& path,
                                    std::vector<uint8_t>& out,
                                    size_t max_size,
                                    std::string* error = nullptr) {
    return veld::channel::secure_file::Read(
               path, out, error, max_size,
               /*require_private_parent=*/true)
        == veld::channel::secure_file::ReadResult::Ok;
}

static bool _wiz_read_private_text(const std::string& path,
                                   std::string& out,
                                   size_t max_size,
                                   std::string* error = nullptr) {
    std::vector<uint8_t> bytes;
    if (!_wiz_read_private_bytes(path, bytes, max_size, error)) {
        out.clear();
        return false;
    }
    struct ReadBytesWiper {
        std::vector<uint8_t>& value;
        ~ReadBytesWiper() {
            if (!value.empty())
                veld::compat::SecureZero(value.data(), value.size());
        }
    } wipe_bytes{bytes};
    out.assign(bytes.begin(), bytes.end());
    return true;
}

// Explicit user-selected imports may come from an owner-controlled Downloads
// directory rather than the private node datadir.  Open the selected file
// itself without following a final symlink, bind validation and reads to one
// handle, require a single regular inode owned by this user, and cap allocation.
#ifndef VELD_PUBLIC_TESTNET
static bool _wiz_read_explicit_import(const std::string& path,
                                      std::string& out,
                                      std::string* error = nullptr) {
    veld::WipeString(out);
    std::vector<uint8_t> bytes;
    const auto result = veld::channel::secure_file::ReadExplicitImport(
        path, bytes, error, WIZ_MAX_EXPLICIT_IMPORT_BYTES);
    if (result != veld::channel::secure_file::ReadResult::Ok)
        return false;
    struct ImportBytesWiper {
        std::vector<uint8_t>& value;
        ~ImportBytesWiper() {
            if (!value.empty())
                veld::compat::SecureZero(value.data(), value.size());
        }
    } wipe_bytes{bytes};
    out.assign(bytes.begin(), bytes.end());
    return true;
}
#endif

static bool _wiz_content_is_encrypted(std::string_view content) {
    if (content.size() >= 3 && content[0] == 'V' && content[1] == 'W')
        return true;
    if (content.empty()) return false;
    for (unsigned char c : content) {
        if (c == 0 || (c < 0x20 && c != '\n' && c != '\r' && c != '\t'))
            return true;
    }
    return false;
}

static std::string _wiz_prompt_passphrase(bool confirm) {
    std::string pass, pass2;
    pass.reserve(256);
    pass2.reserve(256);
    std::cout << "\n  Set a passphrase to protect your mining key: " << std::flush;
    veld::compat::ConsoleEchoOff();
    if (!std::getline(std::cin, pass)) { veld::compat::ConsoleEchoOn(); return ""; }
    veld::compat::ConsoleEchoOn();
    std::cout << "(hidden)\n";
    std::string policy_error;
    if (!veld::wallet_crypto::ValidateNewPassphrase(pass, &policy_error)) {
        std::cerr << "  " << policy_error << "\n";
        veld::WipeString(pass);
        return "";
    }
    if (confirm) {
        std::cout << "  Confirm passphrase: " << std::flush;
        veld::compat::ConsoleEchoOff();
        if (!std::getline(std::cin, pass2)) { veld::compat::ConsoleEchoOn(); return ""; }
        veld::compat::ConsoleEchoOn();
        std::cout << "(hidden)\n";
        bool match = veld::ConstantTimeEqualsString(
            pass.data(), pass.size(), pass2.data(), pass2.size());
        if (!match) {
            veld::WipeString(pass);
            veld::WipeString(pass2);
            std::cerr << "  Passphrases do not match.\n";
            return "";
        }
        veld::WipeString(pass2);
    }
    return pass;
}

static std::string _wiz_ask_passphrase() {
    static _WizWipingString cached_pass;
    static bool cache_loaded = false;
    if (!cache_loaded) {
        if (const char* env = std::getenv("VELD_VAULT_PASSPHRASE")) {
            cached_pass = std::string(env);
        }
        veld::compat::UnsetEnv("VELD_VAULT_PASSPHRASE");
        cache_loaded = true;
    }
    if (!cached_pass.empty()) {
        std::string pass = std::move(cached_pass);
        veld::WipeString(cached_pass);
        return pass; // consume the environment secret exactly once
    }

    static int attempt_count = 0;
    ++attempt_count;
    if (attempt_count > 4) {
        std::cerr << "\n  Too many passphrase attempts. Please close this window\n"
                     "  and try again from a fresh launch.\n\n";
        return "";
    }
    if (attempt_count == 2) std::this_thread::sleep_for(std::chrono::seconds(1));
    else if (attempt_count == 3) std::this_thread::sleep_for(std::chrono::seconds(2));
    else if (attempt_count == 4) std::this_thread::sleep_for(std::chrono::seconds(5));

    std::string pass;
    pass.reserve(256);
    std::cout << "  Enter passphrase: " << std::flush;
    veld::compat::ConsoleEchoOff();
    if (!std::getline(std::cin, pass)) { veld::compat::ConsoleEchoOn(); return ""; }
    veld::compat::ConsoleEchoOn();
    std::cout << "(hidden)\n";
    return pass;
}

#ifndef VELD_PUBLIC_TESTNET
static std::vector<uint8_t> _wiz_b64_decode(const std::string& s) {
    std::vector<uint8_t> out;
    static constexpr size_t MAX_BROWSER_KEYSTORE_FIELD = 1024u * 1024u;
    if (!veld::compat::DecodeBase64Canonical(
            s, out, MAX_BROWSER_KEYSTORE_FIELD)) return {};
    return out;
}

static std::string _wiz_json_str(const std::string& src, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    auto pos = src.find(needle);
    if (pos == std::string::npos) return "";
    pos = src.find(":", pos + needle.size());
    if (pos == std::string::npos) return "";
    pos = src.find("\"", pos);
    if (pos == std::string::npos) return "";
    size_t i = pos + 1;
    while (i < src.size()) {
        if (src[i] == '\\' && i + 1 < src.size()) { i += 2; continue; }
        if (src[i] == '"') return src.substr(pos + 1, i - pos - 1);
        ++i;
    }
    return "";
}

static bool _wiz_json_u32(const std::string& src, const std::string& key,
                          uint32_t& value) {
    std::string needle = "\"" + key + "\"";
    auto pos = src.find(needle);
    if (pos == std::string::npos) return false;
    pos = src.find(':', pos + needle.size());
    if (pos == std::string::npos) return false;
    ++pos;
    while (pos < src.size() && std::isspace(
            static_cast<unsigned char>(src[pos]))) ++pos;
    if (pos == src.size() || !std::isdigit(
            static_cast<unsigned char>(src[pos]))) return false;
    uint64_t parsed = 0;
    while (pos < src.size() && std::isdigit(
            static_cast<unsigned char>(src[pos]))) {
        parsed = parsed * 10 + static_cast<unsigned>(src[pos++] - '0');
        if (parsed > std::numeric_limits<uint32_t>::max()) return false;
    }
    value = static_cast<uint32_t>(parsed);
    return true;
}

static std::string _wiz_json_unescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char n = s[i + 1];
            if (n == '"' || n == '\\' || n == '/') { out.push_back(n); ++i; continue; }
            if (n == 'n') { out.push_back('\n'); ++i; continue; }
            if (n == 't') { out.push_back('\t'); ++i; continue; }
        }
        out.push_back(s[i]);
    }
    return out;
}

static bool _wiz_looks_like_walletui_keystore(const std::string& content) {
    if (content.find("\"keystore\"") == std::string::npos) return false;
    if (content.find("\\\"salt\\\"") == std::string::npos) return false;
    if (content.find("\\\"iv\\\"") == std::string::npos) return false;
    if (content.find("\\\"data\\\"") == std::string::npos) return false;
    return true;
}

static std::string _wiz_decrypt_walletui_keystore(const std::string& content,
                                                  const std::string& passphrase,
                                                  std::string* out_address) {
    std::string inner_escaped = _wiz_json_str(content, "keystore");
    if (inner_escaped.empty()) return "";
    std::string inner = _wiz_json_unescape(inner_escaped);

    uint32_t version = 0;
    if (!_wiz_json_u32(inner, "v", version)
        || (version != veld::wallet_crypto::BROWSER_KEYSTORE_VERSION_V2
            && version != veld::wallet_crypto::BROWSER_KEYSTORE_VERSION_V3))
        return "";
    if (version == veld::wallet_crypto::BROWSER_KEYSTORE_VERSION_V3) {
        uint32_t n = 0, r = 0, p = 0;
        if (_wiz_json_str(inner, "name") != "scrypt"
            || _wiz_json_str(inner, "cipher") != "AES-256-GCM"
            || !_wiz_json_u32(inner, "n", n)
            || !_wiz_json_u32(inner, "r", r)
            || !_wiz_json_u32(inner, "p", p)
            || n != veld::wallet_crypto::BROWSER_KEYSTORE_SCRYPT_N
            || r != veld::wallet_crypto::BROWSER_KEYSTORE_SCRYPT_R
            || p != veld::wallet_crypto::BROWSER_KEYSTORE_SCRYPT_P)
            return "";
    }

    std::string salt_b64 = _wiz_json_str(inner, "salt");
    std::string iv_b64   = _wiz_json_str(inner, "iv");
    std::string ct_b64   = _wiz_json_str(inner, "data");
    if (salt_b64.empty() || iv_b64.empty() || ct_b64.empty()) return "";

    auto salt = _wiz_b64_decode(salt_b64);
    auto iv   = _wiz_b64_decode(iv_b64);
    auto ct   = _wiz_b64_decode(ct_b64);
    if (salt.size() != 16 || iv.size() != 12 || ct.size() < 17) return "";

    std::string plaintext;
    if (!veld::wallet_crypto::DecryptBrowserKeystoreCiphertext(
            version, passphrase, salt, iv, ct, plaintext)) return "";

    std::string priv_hex, authenticated_address;
    if (!veld::wallet_crypto::ParseBrowserKeystoreIdentity(
            plaintext, priv_hex, authenticated_address)) {
        veld::WipeString(plaintext);
        return "";
    }
    if (out_address) *out_address = std::move(authenticated_address);
    veld::WipeString(plaintext);
    return priv_hex;
}
#endif

static bool _wiz_parse_privkey(std::string_view hex,
                               veld::Secp256k1PrivKey& out);

static bool _wiz_is_encrypted(const std::string& file) {
    std::string content, error;
    if (!_wiz_read_private_text(
            file, content, WIZ_MAX_OPERATIONAL_SECRET_BYTES, &error))
        return false;
    const bool encrypted = _wiz_content_is_encrypted(content);
    veld::WipeString(content);
    return encrypted;
}

static bool _wiz_encrypt_key_record(const veld::Secp256k1PrivKey& priv,
                                    const std::string& passphrase,
                                    bool testnet,
                                    std::vector<uint8_t>& encrypted,
                                    std::string* address = nullptr) {
    encrypted.clear();
    auto pub  = veld::DerivePublicKey(priv);
    auto addr = veld::PubKeyToAddress(pub, testnet);
    static constexpr char hex[] = "0123456789abcdef";
    std::string priv_hex;
    std::string pub_hex;
    priv_hex.reserve(priv.size() * 2);
    pub_hex.reserve(pub.size() * 2);
    auto append_hex = [&](std::string& out, const uint8_t* data, size_t size) {
        for (size_t i = 0; i < size; ++i) {
            out.push_back(hex[data[i] >> 4]);
            out.push_back(hex[data[i] & 0x0f]);
        }
    };
    append_hex(priv_hex, priv.data(), priv.size());
    append_hex(pub_hex, pub.data(), pub.size());
    std::string plaintext = veld::operational_key::FormatRecord(
        priv_hex, pub_hex, addr);
    veld::WipeString(priv_hex);
    veld::WipeString(pub_hex);
    encrypted = veld::wallet_crypto::EncryptWallet(plaintext, passphrase);
    veld::WipeString(plaintext);
    if (address) *address = std::move(addr);
    return !encrypted.empty();
}

static bool _wiz_save_key_encrypted(const std::string& key_file,
                                     const veld::Secp256k1PrivKey& priv,
                                     const std::string& passphrase,
                                     bool testnet = false) {
    std::vector<uint8_t> encrypted;
    if (!_wiz_encrypt_key_record(
            priv, passphrase, testnet, encrypted)) return false;
    std::string error;
    const bool ok = veld::channel::secure_file::AtomicWrite(
        key_file, encrypted, &error, /*require_private_parent=*/true);
    if (!encrypted.empty())
        veld::compat::SecureZero(encrypted.data(), encrypted.size());
    return ok;
}

#ifndef VELD_PUBLIC_TESTNET
static bool _wiz_create_portable_key_bundle(
        const std::string& datadir,
        const veld::Secp256k1PrivKey& private_key,
        const std::string& passphrase,
        bool testnet,
        std::string& address,
        std::string& portable_path,
        std::string& error) {
    address.clear();
    portable_path.clear();
    error.clear();

    std::vector<uint8_t> encrypted;
    struct EncryptedWiper {
        std::vector<uint8_t>& value;
        ~EncryptedWiper() {
            if (!value.empty())
                veld::compat::SecureZero(value.data(), value.size());
        }
    } wipe_encrypted{encrypted};
    try {
        if (!_wiz_encrypt_key_record(
                private_key, passphrase, testnet, encrypted, &address)) {
            error = "could not encrypt the mining identity";
            return false;
        }
    } catch (const std::exception& e) {
        error = std::string("could not encrypt the mining identity: ") + e.what();
        return false;
    }

    const std::string operational_path = datadir + "/miner.key";
    portable_path = datadir + "/veld-wallet-" + address.substr(0, 8)
        + ".veld-keys";
    if (std::filesystem::exists(operational_path)) {
        error = "refusing to replace an existing miner.key";
        return false;
    }
    if (std::filesystem::exists(portable_path)) {
        error = "refusing to replace an existing portable Veld keyfile";
        return false;
    }

    // Publish the portable recovery copy first. If the second write fails, the
    // encrypted identity remains recoverable and can be imported through the
    // ordinary node or wallet importer. Both names receive the exact same
    // versioned ciphertext bytes; no format conversion or re-encryption occurs.
    if (!veld::channel::secure_file::AtomicWriteNew(
            portable_path, encrypted, &error,
            /*require_private_parent=*/true)) {
        return false;
    }
    if (!veld::channel::secure_file::AtomicWriteNew(
            operational_path, encrypted, &error,
            /*require_private_parent=*/true)) {
        error = "portable Veld keyfile was created, but miner.key could not be "
            "published: " + error;
        return false;
    }

    std::vector<uint8_t> operational_bytes;
    std::vector<uint8_t> portable_bytes;
    struct ReadbackWiper {
        std::vector<uint8_t>& first;
        std::vector<uint8_t>& second;
        ~ReadbackWiper() {
            if (!first.empty())
                veld::compat::SecureZero(first.data(), first.size());
            if (!second.empty())
                veld::compat::SecureZero(second.data(), second.size());
        }
    } wipe_readback{operational_bytes, portable_bytes};
    std::string read_error;
    if (!_wiz_read_private_bytes(
            operational_path, operational_bytes,
            WIZ_MAX_OPERATIONAL_SECRET_BYTES, &read_error)
        || !_wiz_read_private_bytes(
            portable_path, portable_bytes,
            WIZ_MAX_OPERATIONAL_SECRET_BYTES, &read_error)
        || operational_bytes.size() != encrypted.size()
        || portable_bytes.size() != encrypted.size()
        || !std::equal(encrypted.begin(), encrypted.end(),
                       operational_bytes.begin())
        || !std::equal(encrypted.begin(), encrypted.end(),
                       portable_bytes.begin())) {
        error = "mining identity readback did not match its portable keyfile";
        return false;
    }
    return true;
}

// Once an encrypted mining identity has been authenticated, keep exactly one
// portable copy beside miner.key.  This migrates identities created by older
// clients without generating a replacement wallet or re-encrypting the key.
// Existing matching bytes are accepted; conflicting bytes fail closed.
static bool _wiz_ensure_portable_keyfile(
        const std::string& datadir,
        const std::string& address,
        std::string& portable_path,
        bool& created,
        std::string& error) {
    portable_path.clear();
    created = false;
    error.clear();
    if (address.size() < 8) {
        error = "mining identity has no canonical address";
        return false;
    }

    const std::string operational_path = datadir + "/miner.key";
    portable_path = datadir + "/veld-wallet-" + address.substr(0, 8)
        + ".veld-keys";
    if (!_wiz_is_encrypted(operational_path)) {
        error = "portable keyfile requires an encrypted miner.key";
        return false;
    }

    std::vector<uint8_t> operational_bytes;
    std::vector<uint8_t> portable_bytes;
    struct KeyfileBytesWiper {
        std::vector<uint8_t>& first;
        std::vector<uint8_t>& second;
        ~KeyfileBytesWiper() {
            if (!first.empty())
                veld::compat::SecureZero(first.data(), first.size());
            if (!second.empty())
                veld::compat::SecureZero(second.data(), second.size());
        }
    } wipe_bytes{operational_bytes, portable_bytes};

    if (!_wiz_read_private_bytes(
            operational_path, operational_bytes,
            WIZ_MAX_OPERATIONAL_SECRET_BYTES, &error)) {
        return false;
    }

    std::error_code exists_error;
    const bool portable_exists = std::filesystem::exists(
        portable_path, exists_error);
    if (exists_error) {
        error = "cannot determine portable keyfile state";
        return false;
    }
    if (portable_exists) {
        if (!_wiz_read_private_bytes(
                portable_path, portable_bytes,
                WIZ_MAX_OPERATIONAL_SECRET_BYTES, &error)) {
            return false;
        }
        if (portable_bytes.size() != operational_bytes.size() ||
            !std::equal(operational_bytes.begin(), operational_bytes.end(),
                        portable_bytes.begin())) {
            error = "existing portable keyfile differs from miner.key";
            return false;
        }
        return true;
    }

    if (!veld::channel::secure_file::AtomicWriteNew(
            portable_path, operational_bytes, &error,
            /*require_private_parent=*/true)) {
        return false;
    }
    if (!_wiz_read_private_bytes(
            portable_path, portable_bytes,
            WIZ_MAX_OPERATIONAL_SECRET_BYTES, &error) ||
        portable_bytes.size() != operational_bytes.size() ||
        !std::equal(operational_bytes.begin(), operational_bytes.end(),
                    portable_bytes.begin())) {
        error = "portable keyfile readback differs from miner.key";
        return false;
    }
    created = true;
    return true;
}
#endif

static bool _wiz_parse_key_record(std::string_view content,
                                  veld::RealKeyPair& kp,
                                  bool testnet = false) {
    veld::operational_key::RecordFields fields;
    if (!veld::operational_key::ParseRecord(content, fields)) return false;
    const std::string_view priv_hex = fields.private_key_hex;
    const std::string_view pub_hex = fields.public_key_hex;
    const std::string_view stored_addr = fields.address;

    veld::Secp256k1PrivKey priv{};
    struct PrivWiper {
        veld::Secp256k1PrivKey& value;
        ~PrivWiper() { veld::compat::SecureZero(value.data(), value.size()); }
    } wipe_priv{priv};
    if (!_wiz_parse_privkey(priv_hex, priv)) return false;
    try {
        const auto pub = veld::DerivePublicKey(priv);
        const std::string derived_addr = veld::PubKeyToAddress(pub, testnet);
        if (pub_hex.size() != pub.size() * 2 || stored_addr != derived_addr)
            return false;
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        for (size_t i = 0; i < pub.size(); ++i) {
            const int hi = nibble(pub_hex[i * 2]);
            const int lo = nibble(pub_hex[i * 2 + 1]);
            if (hi < 0 || lo < 0
                || static_cast<uint8_t>((hi << 4) | lo) != pub[i])
                return false;
        }
        veld::RealKeyPair verified;
        verified.testnet = testnet;
        verified.private_key = priv;
        verified.public_key = pub;
        verified.address = derived_addr;
        kp = std::move(verified);
        return true;
    } catch (...) {
        return false;
    }
}

#ifndef VELD_PUBLIC_TESTNET
static bool _wiz_import_encrypted_keyfile(
        const std::string& source_path,
        const std::string& destination_path,
        const std::string& passphrase,
        bool testnet,
        std::string& imported_address,
        std::string& error) {
    imported_address.clear();
    error.clear();
    if (passphrase.empty()) {
        error = "passphrase is empty";
        return false;
    }

    std::string content;
    if (!_wiz_read_explicit_import(source_path, content, &error))
        return false;
    struct ContentWiper {
        std::string& value;
        ~ContentWiper() { veld::WipeString(value); }
    } wipe_content{content};

    veld::Secp256k1PrivKey private_key{};
    struct PrivateKeyWiper {
        veld::Secp256k1PrivKey& value;
        ~PrivateKeyWiper() {
            veld::compat::SecureZero(value.data(), value.size());
        }
    } wipe_private_key{private_key};
    bool have_private_key = false;
    std::string authenticated_browser_address;
    const bool browser_keystore = _wiz_looks_like_walletui_keystore(content);

    if (browser_keystore) {
        std::string private_hex = _wiz_decrypt_walletui_keystore(
            content, passphrase, &authenticated_browser_address);
        struct PrivateTextWiper {
            std::string& value;
            ~PrivateTextWiper() { veld::WipeString(value); }
        } wipe_private_hex{private_hex};
        have_private_key = _wiz_parse_privkey(private_hex, private_key);
    } else if (_wiz_content_is_encrypted(content)) {
        try {
            std::vector<uint8_t> encrypted(content.begin(), content.end());
            struct EncryptedWiper {
                std::vector<uint8_t>& value;
                ~EncryptedWiper() {
                    if (!value.empty())
                        veld::compat::SecureZero(value.data(), value.size());
                }
            } wipe_encrypted{encrypted};
            std::string decrypted = veld::wallet_crypto::DecryptWallet(
                encrypted, passphrase);
            struct DecryptedWiper {
                std::string& value;
                ~DecryptedWiper() { veld::WipeString(value); }
            } wipe_decrypted{decrypted};
            veld::RealKeyPair imported;
            if (_wiz_parse_key_record(decrypted, imported, testnet)) {
                private_key = imported.private_key;
                veld::compat::SecureZero(imported.private_key.data(),
                                         imported.private_key.size());
                have_private_key = true;
            } else {
                std::string private_hex = _wiz_json_str(decrypted, "privkey");
                struct PrivateTextWiper {
                    std::string& value;
                    ~PrivateTextWiper() { veld::WipeString(value); }
                } wipe_private_hex{private_hex};
                have_private_key = _wiz_parse_privkey(private_hex, private_key);
            }
        } catch (...) {
            have_private_key = false;
        }
    } else {
        error = "plaintext keyfiles are not accepted by the GUI importer";
        return false;
    }

    if (!have_private_key) {
        error = "wrong passphrase or invalid encrypted Veld keyfile";
        return false;
    }
    try {
        const auto public_key = veld::DerivePublicKey(private_key);
        imported_address = veld::PubKeyToAddress(public_key, testnet);
    } catch (...) {
        error = "keyfile contains an invalid private key";
        return false;
    }
    if (browser_keystore
        && (authenticated_browser_address.empty()
            || authenticated_browser_address != imported_address)) {
        error = "authenticated key/address mismatch";
        imported_address.clear();
        return false;
    }
    if (!_wiz_save_key_encrypted(
            destination_path, private_key, passphrase, testnet)) {
        error = "could not write the protected mining identity";
        imported_address.clear();
        return false;
    }
    return true;
}
#endif

static bool _wiz_load_key_encrypted(const std::string& key_file,
                                     const std::string& passphrase,
                                     veld::RealKeyPair& kp,
                                     bool testnet = false) {
    std::vector<uint8_t> data;
    if (!_wiz_read_private_bytes(
            key_file, data, WIZ_MAX_OPERATIONAL_SECRET_BYTES))
        return false;
    try {
        std::string plaintext = veld::wallet_crypto::DecryptWallet(data, passphrase);
        struct PlainWiper {
            std::string& value;
            ~PlainWiper() { veld::WipeString(value); }
        } wipe_plain{plaintext};
        if (!_wiz_parse_key_record(plaintext, kp, testnet)) return false;

        // A successful authenticated unlock is the only point where an older
        // envelope may be replaced. The same verified private key is written
        // through the owner-only atomic writer, so the address cannot change
        // and a failed rewrite leaves the original keyfile intact.
        if (!veld::wallet_crypto::IsCurrentWalletEnvelope(data)
                && !_wiz_save_key_encrypted(
                    key_file, kp.private_key, passphrase, testnet)) {
            std::cerr << "[keyfile] warning: unlocked an older protected "
                         "keyfile but could not upgrade its encryption; "
                         "the original file remains usable\n";
        }
        return true;
    } catch (...) {
        return false;
    }
}

static bool _wiz_save_key(const std::string& key_file,
                          const veld::Secp256k1PrivKey& priv,
                          bool testnet = false) {
    std::string pass = _wiz_prompt_passphrase(true);
    if (pass.empty()) return false;
    bool ok = _wiz_save_key_encrypted(key_file, priv, pass, testnet);
    if (ok) g_passphrase = pass;
    veld::WipeString(pass);
    return ok;
}
static bool _wiz_parse_privkey(std::string_view hex, veld::Secp256k1PrivKey& out) {
    if (!_wiz_is_hex64(hex)) return false;
    auto nibble = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
        return static_cast<uint8_t>(c - 'A' + 10);
    };
    for (size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<uint8_t>((nibble(hex[i * 2]) << 4)
                                      | nibble(hex[i * 2 + 1]));
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) if (out[i] != 0) { all_zero = false; break; }
    return !all_zero;
}

static bool _wiz_load_plain_key(const std::string& path,
                                veld::RealKeyPair& kp,
                                bool testnet = false) {
    std::string content, error;
    if (!_wiz_read_private_text(
            path, content, WIZ_MAX_OPERATIONAL_SECRET_BYTES, &error))
        return false;
    struct TextWiper {
        std::string& value;
        ~TextWiper() { veld::WipeString(value); }
    } _wipe_content{content};
    return _wiz_parse_key_record(content, kp, testnet);
}

static bool _wiz_load_rpc_token(const std::string& path,
                                const std::string& passphrase,
                                std::string& token) {
    token.clear();
    std::vector<uint8_t> data;
    if (!_wiz_read_private_bytes(path, data, WIZ_MAX_RPC_TOKEN_BYTES))
        return false;
    struct TokenBytesWiper {
        std::vector<uint8_t>& value;
        ~TokenBytesWiper() {
            if (!value.empty())
                veld::compat::SecureZero(value.data(), value.size());
        }
    } wipe_token_bytes{data};
    try {
        const std::string_view view(
            reinterpret_cast<const char*>(data.data()), data.size());
        if (_wiz_content_is_encrypted(view)) {
            if (passphrase.empty()) return false;
            token = veld::wallet_crypto::DecryptWallet(data, passphrase);
        } else {
            token.assign(view.begin(), view.end());
        }
    } catch (...) {
        veld::WipeString(token);
        return false;
    }
    size_t first = 0, last = token.size();
    while (first < last && (token[first] == ' ' || token[first] == '\t')) ++first;
    while (last > first && (token[last - 1] == '\n' || token[last - 1] == '\r'
           || token[last - 1] == ' ' || token[last - 1] == '\t')) --last;
    const std::string_view candidate(token.data() + first, last - first);
    const bool canonical = candidate.size() == 64
        && std::all_of(candidate.begin(), candidate.end(), [](unsigned char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
    if (!canonical) {
        veld::WipeString(token);
    } else if (first != 0 || last != token.size()) {
        std::string normalized(candidate);
        veld::WipeString(token);
        token = std::move(normalized);
    }
    return canonical;
}

static bool _wiz_save_rpc_token(const std::string& path,
                                const std::string& token,
                                const std::string& passphrase,
                                std::string* error = nullptr) {
    if (token.size() != 64 || passphrase.empty()) return false;
    auto encrypted = veld::wallet_crypto::EncryptWallet(token, passphrase);
    const bool ok = veld::channel::secure_file::AtomicWrite(
        path, encrypted, error, /*require_private_parent=*/true);
    if (!encrypted.empty())
        veld::compat::SecureZero(encrypted.data(), encrypted.size());
    return ok;
}

static bool _wiz_shred_file(const std::string& path) {
    std::vector<uint8_t> buf(4096);
    bool ok = true;
#ifdef _WIN32
    const std::filesystem::path p(path);
    HANDLE h = ::CreateFileW(
        p.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH
            | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    ok = ::GetFileInformationByHandle(h, &info)
        && !(info.dwFileAttributes
             & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
        && info.nNumberOfLinks == 1
        && ::GetFileSizeEx(h, &size) && size.QuadPart >= 0
        && static_cast<unsigned long long>(size.QuadPart)
               <= WIZ_MAX_OPERATIONAL_SECRET_BYTES;
    for (int pass = 0; ok && pass < 3; ++pass) {
        LARGE_INTEGER zero{};
        ok = veld::compat::SecureRandom(buf.data(), buf.size())
            && ::SetFilePointerEx(h, zero, nullptr, FILE_BEGIN);
        unsigned long long left = static_cast<unsigned long long>(size.QuadPart);
        while (ok && left != 0) {
            const DWORD want = static_cast<DWORD>(
                std::min<unsigned long long>(buf.size(), left));
            DWORD wrote = 0;
            ok = ::WriteFile(h, buf.data(), want, &wrote, nullptr)
                && wrote == want;
            left -= wrote;
        }
        if (ok) ok = ::FlushFileBuffers(h) != 0;
    }
    if (!::CloseHandle(h)) ok = false;
    if (ok) ok = ::DeleteFileW(p.c_str()) != 0;
#else
    int flags = O_RDWR | O_CLOEXEC;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int fd = ::open(path.c_str(), flags);
    if (fd < 0) return false;
    struct stat st{};
    ok = ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode)
        && st.st_uid == ::geteuid() && st.st_nlink == 1 && st.st_size >= 0
        && static_cast<unsigned long long>(st.st_size)
               <= WIZ_MAX_OPERATIONAL_SECRET_BYTES;
    for (int pass = 0; ok && pass < 3; ++pass) {
        ok = veld::compat::SecureRandom(buf.data(), buf.size())
            && ::lseek(fd, 0, SEEK_SET) == 0;
        off_t left = st.st_size;
        while (ok && left > 0) {
            const size_t want = static_cast<size_t>(
                std::min<off_t>(static_cast<off_t>(buf.size()), left));
            const ssize_t wrote = ::write(fd, buf.data(), want);
            if (wrote < 0 && errno == EINTR) continue;
            if (wrote <= 0) { ok = false; break; }
            left -= wrote;
        }
        if (ok) ok = ::fsync(fd) == 0;
    }
    if (::close(fd) != 0) ok = false;
    if (ok) ok = ::unlink(path.c_str()) == 0;
#endif
    veld::compat::SecureZero(buf.data(), buf.size());
    return ok;
}

static void _wiz_offer_shred_disabled_keys(const std::string& datadir) {
    namespace fs = std::filesystem;
    std::error_code ec;
    std::vector<std::string> candidates;
    for (auto& ent : fs::directory_iterator(datadir, ec)) {
        if (ec) return;
        auto n = ent.path().filename().string();
        if (n.rfind("miner.key.disabled.", 0) == 0 ||
            n.rfind("validator.key.disabled.", 0) == 0) {
            candidates.push_back(ent.path().string());
        }
    }
    if (candidates.empty()) return;
    std::cout << "\n  Found " << candidates.size()
              << " rotated key file(s) on disk. Each is still recoverable with its old passphrase:\n";
    for (auto& p : candidates) std::cout << "    " << p << "\n";
    std::cout << "  Shred and delete them now? [y/n]: " << std::flush;
    std::string yn; std::getline(std::cin, yn); yn = _wiz_trim(yn);
    if (yn != "y" && yn != "Y") return;
    for (auto& p : candidates) {
        if (_wiz_shred_file(p))
            std::cout << "    shredded: " << p << "\n";
        else
            std::cerr << "    failed:   " << p << "\n";
    }
}

static int run_mining_wizard(const std::string& datadir, bool testnet = false) {
    namespace fs = std::filesystem;
    static thread_local int s_wizard_depth = 0;
    ++s_wizard_depth;
    struct DepthGuard {
        int& d;
        DepthGuard(int& v) : d(v) {}
        ~DepthGuard() { --d; }
    } _dg(s_wizard_depth);
    if (s_wizard_depth > 5) {
        std::cerr << "\n  [setup] Wizard recursion depth exceeded (5). "
                  << "Stdin likely broken. Aborting.\n\n";
        return 1;
    }
    const std::string key_file = datadir + "/miner.key";
    std::string dir_error;
    if (!veld::channel::secure_file::EnsurePrivateDirectory(
            datadir, &dir_error)) {
        std::cerr << "\n  [setup] Refusing unsafe data directory: "
                  << dir_error << "\n\n";
        return 1;
    }
#ifdef VELD_PUBLIC_TESTNET
    // This warning must precede every identity prompt.  Testnet identities
    // are disposable operational keys, not wallets to import into mainnet.
    std::cerr << RED << BOLD << "\n  " << DEPLOYMENT_WARNING << RESET << "\n"
              << "  Role:       " << DEPLOYMENT_ROLE
              << " (" << DEPLOYMENT_PROFILE_ID << ")\n"
              << "  Genesis:    " << GENESIS_HASH << "\n"
              << "  Create or resume only a role-bound testnet identity.\n\n";
#endif
    _wiz_offer_shred_disabled_keys(datadir);

#ifndef _WIN32
    if (!::isatty(STDIN_FILENO) || !::isatty(STDERR_FILENO)) {
        std::cerr << "\n  [setup] "
#ifdef VELD_FLEET_NO_MINE
                  << "Validator identity setup requires an interactive terminal.\n"
#else
                  << "Mining identity setup requires an interactive terminal.\n"
#endif
                  << "  [setup] Run once manually:\n\n"
#ifdef VELD_FLEET_NO_MINE
                  << "    veld-node --setup --datadir " << datadir << "\n\n"
#else
                  << "    veld-node --mine --setup --datadir " << datadir << "\n\n"
#endif
                  << "  [setup] After the wizard completes, miner.key will be saved and\n"
                  << "  [setup] future non-interactive runs will auto-resume silently.\n\n"
                  << "  [setup] Exiting with status 78 (EX_CONFIG) so systemd stops\n"
                  << "  [setup] the service instead of looping (unit must set\n"
                  << "  [setup] RestartPreventExitStatus=78 — shipped by default).\n\n";
        return 78;
    }
#endif

    std::string saved_addr;
    bool has_saved = false;
    {
        if (std::filesystem::exists(key_file)) {
            if (_wiz_is_encrypted(key_file)) {
                has_saved = true;
                saved_addr = "(encrypted)";
            } else {
                veld::RealKeyPair saved;
                if (_wiz_load_plain_key(key_file, saved, testnet)) {
                    has_saved = true;
                    saved_addr = saved.address;
                }
            }
        }
    }

    std::cout << "\n"
              << "  ============================================================\n"
#ifdef VELD_FLEET_NO_MINE
              << "    VELD FLEET VALIDATOR IDENTITY\n"
#elif defined(VELD_PUBLIC_TESTNET)
              << "    VELD PUBLIC TESTNET MINING CLIENT\n"
#else
              << "    VELD DESKTOP MINING + VALIDATOR CLIENT\n"
#endif
#ifdef VELD_FLEET_NO_MINE
              << "    Validator identity setup\n"
#else
              << "    Mining identity setup\n"
#endif
              << "  ============================================================\n\n"
#ifdef VELD_FLEET_NO_MINE
              << "  How would you like to set up your validator identity?\n\n"
#else
              << "  How would you like to set up your mining reward address?\n\n"
#endif
              << "    [1] Resume previous session  ("
              << (has_saved ? saved_addr : std::string("no saved session found"))
              << ")\n"
#ifdef VELD_PUBLIC_TESTNET
              << "    [2] Create a brand-new PUBLIC TESTNET identity\n\n"
              << "  Importing .veld-keys files or raw private keys is disabled.\n"
              << "  Choice [1-2]: " << std::flush;
#else
              << "    [2] Log in from a keyfile    (.veld-keys file)\n"
              << "    [3] Log in with a different VELD wallet\n"
              << "    [4] Create a brand-new wallet\n\n"
              << "  Choice [1-4]: " << std::flush;
#endif

    std::string choice;
    if (!std::getline(std::cin, choice)) return 1;
    choice = _wiz_trim(choice);
#ifdef VELD_PUBLIC_TESTNET
    if (choice == "2") {
        choice = "4"; // reuse the generate-new implementation below
    } else if (choice != "1") {
        std::cerr << "\n  Public testnet permits only a role-bound resume or a new identity.\n\n";
        return run_mining_wizard(datadir, testnet);
    }
#endif

    if (choice == "1") {
        if (!has_saved) {
#ifdef VELD_PUBLIC_TESTNET
            std::cerr << "\n  No role-bound testnet session found. Pick [2] to create one.\n\n";
#else
            std::cerr << "\n  No previous session found. Pick [2], [3], or [4].\n\n";
#endif
            return run_mining_wizard(datadir, testnet);
        }
        if (_wiz_is_encrypted(key_file)) {
            std::string pass = _wiz_ask_passphrase();
            if (pass.empty() || g_shutdown.load()) return 1;
            veld::RealKeyPair test_kp;
            if (!_wiz_load_key_encrypted(key_file, pass, test_kp, testnet)) {
                veld::WipeString(pass);
                if (g_shutdown.load()) return 1;
                std::cerr << "\n  Wrong passphrase or corrupted key file.\n\n";
                return run_mining_wizard(datadir, testnet);
            }
            g_passphrase = pass;
            veld::WipeString(pass);
            std::cout << "\n  Unlocked miner address: " << test_kp.address << "\n\n";
        } else {
            std::cout << "\n  Using saved miner address: " << saved_addr << "\n\n";
        }
        return 0;
    }
#ifndef VELD_PUBLIC_TESTNET
    if (choice == "2") {
        std::cout << "\n  Enter one .veld-keys path (or drag & drop)."
                     " miner.key is not needed here.\n  Path: " << std::flush;
        std::string path; if (!std::getline(std::cin, path)) return 1;
        bool ignored_miner_key = false;
        if (!_wiz_resolve_keyfile_input(path, path, ignored_miner_key)) {
            std::cerr << "\n  ERROR: select exactly one existing .veld-keys file.\n\n";
            return run_mining_wizard(datadir, testnet);
        }
        if (ignored_miner_key)
            std::cout << "  Using the .veld-keys file; the extra miner.key path was ignored.\n";
        std::string content, import_error;
        if (!_wiz_read_explicit_import(path, content, &import_error)) {
            std::cerr << "\n  ERROR: refusing key import " << path << ": "
                      << import_error << "\n\n";
            return run_mining_wizard(datadir, testnet);
        }
        struct ImportWiper {
            std::string& value;
            ~ImportWiper() { veld::WipeString(value); }
        } wipe_import{content};
        std::string priv_hex;
        struct ImportedPrivateTextWiper {
            std::string& value;
            ~ImportedPrivateTextWiper() { veld::WipeString(value); }
        } wipe_imported_private{priv_hex};
        std::string authenticated_browser_addr;
        const bool browser_keystore = _wiz_looks_like_walletui_keystore(content);
        if (browser_keystore) {
            std::cout << "\n  Wallet keyfile detected. Enter passphrase: " << std::flush;
            veld::compat::ConsoleEchoOff();
            std::string pass;
            if (!std::getline(std::cin, pass)) { veld::compat::ConsoleEchoOn(); return 1; }
            veld::compat::ConsoleEchoOn();
            std::cout << "(hidden)\n";
            priv_hex = _wiz_decrypt_walletui_keystore(
                content, pass, &authenticated_browser_addr);
            if (priv_hex.empty()) {
                veld::WipeString(pass);
                std::cerr << "\n  Wrong passphrase or corrupted keyfile.\n\n";
                return run_mining_wizard(datadir, testnet);
            }
            g_passphrase = pass;
            veld::WipeString(pass);
        } else if (_wiz_content_is_encrypted(content)) {
            std::cout << "\n  Keyfile is encrypted. Enter passphrase: " << std::flush;
            veld::compat::ConsoleEchoOff();
            std::string pass;
            if (!std::getline(std::cin, pass)) { veld::compat::ConsoleEchoOn(); return 1; }
            veld::compat::ConsoleEchoOn();
            std::cout << "(hidden)\n";
            try {
                std::vector<uint8_t> enc_data(content.begin(), content.end());
                std::string decrypted = veld::wallet_crypto::DecryptWallet(enc_data, pass);
                struct DecryptedWiper {
                    std::string& value;
                    ~DecryptedWiper() { veld::WipeString(value); }
                } wipe_decrypted{decrypted};
                auto find_in = [&](const std::string& src, const std::string& key) -> std::string {
                    auto pos = src.find("\"" + key + "\"");
                    if (pos == std::string::npos) return "";
                    pos = src.find(":", pos); if (pos == std::string::npos) return "";
                    pos = src.find("\"", pos); if (pos == std::string::npos) return "";
                    auto end = src.find("\"", pos + 1); if (end == std::string::npos) return "";
                    return src.substr(pos + 1, end - pos - 1);
                };
                priv_hex = find_in(decrypted, "privkey");
                g_passphrase = pass;
                veld::WipeString(pass);
                if (priv_hex.empty()) {
                    std::cerr << "\n  Decrypted but no private key found.\n\n";
                    return run_mining_wizard(datadir, testnet);
                }
            } catch (...) {
                veld::WipeString(pass);
                std::cerr << "\n  Wrong passphrase or corrupted keyfile.\n\n";
                return run_mining_wizard(datadir, testnet);
            }
        } else {
            auto find_str = [&](const std::string& key) -> std::string {
                auto pos = content.find("\"" + key + "\"");
                if (pos == std::string::npos) return "";
                pos = content.find(":", pos); if (pos == std::string::npos) return "";
                pos = content.find("\"", pos); if (pos == std::string::npos) return "";
                auto end = content.find("\"", pos + 1); if (end == std::string::npos) return "";
                return content.substr(pos + 1, end - pos - 1);
            };
            priv_hex = find_str("privkey");
            if (priv_hex.empty()) {
                std::cout << "\n  No private key found in keyfile. Paste your 64-hex-char key:\n  > " << std::flush;
                veld::compat::ConsoleEchoOff();
                if (!std::getline(std::cin, priv_hex)) { veld::compat::ConsoleEchoOn(); return 1; }
                veld::compat::ConsoleEchoOn();
                std::cout << "(hidden)\n";
                priv_hex = _wiz_trim(std::move(priv_hex));
            }
        }
        veld::WipeString(content);
        veld::Secp256k1PrivKey priv{};
        struct ImportedPrivateKeyWiper {
            veld::Secp256k1PrivKey& value;
            ~ImportedPrivateKeyWiper() {
                veld::compat::SecureZero(value.data(), value.size());
            }
        } wipe_imported_key{priv};
        if (!_wiz_parse_privkey(priv_hex, priv)) {
            veld::WipeString(priv_hex);
            std::cerr << "\n  ERROR: not a valid 64-char private key.\n\n";
            return run_mining_wizard(datadir, testnet);
        }
        const auto derived_addr =
            veld::PubKeyToAddress(veld::DerivePublicKey(priv), testnet);
        if (!authenticated_browser_addr.empty()
            && authenticated_browser_addr != derived_addr) {
            veld::compat::SecureZero(priv.data(), priv.size());
            veld::WipeString(priv_hex);
            veld::WipeString(authenticated_browser_addr);
            std::cerr << "\n  ERROR: authenticated browser key/address mismatch.\n\n";
            return run_mining_wizard(datadir, testnet);
        }
        if (browser_keystore && authenticated_browser_addr.empty()) {
            veld::compat::SecureZero(priv.data(), priv.size());
            veld::WipeString(priv_hex);
            std::cerr << "\n  ERROR: browser keystore has no authenticated address.\n\n";
            return run_mining_wizard(datadir, testnet);
        }
        bool save_ok;
        if (!g_passphrase.empty()) {
            save_ok = _wiz_save_key_encrypted(
                key_file, priv, g_passphrase, testnet);
        } else {
            save_ok = _wiz_save_key(key_file, priv, testnet);
        }
        if (!save_ok) {
            veld::compat::SecureZero(priv.data(), 32);
            veld::WipeString(priv_hex);
            std::cerr << "\n  ERROR: write failed: " << key_file << "\n\n"; return 1;
        }
        veld::compat::SecureZero(priv.data(), 32);
        veld::WipeString(priv_hex);
        std::cout << "\n  Imported: " << derived_addr << " -> " << key_file << "\n\n";
        return 0;
    }
    if (choice == "3") {
        std::cout << "\n  Paste your private key (64 hex chars):\n  > " << std::flush;
        veld::compat::ConsoleEchoOff();
        std::string priv_hex;
        if (!std::getline(std::cin, priv_hex)) { veld::compat::ConsoleEchoOn(); return 1; }
        veld::compat::ConsoleEchoOn();
        std::cout << "(hidden)\n";
        priv_hex = _wiz_trim(std::move(priv_hex));
        veld::Secp256k1PrivKey priv{};
        if (!_wiz_parse_privkey(priv_hex, priv)) {
            veld::WipeString(priv_hex);
            std::cerr << "\n  ERROR: not a valid 64-char private key.\n\n";
            return run_mining_wizard(datadir, testnet);
        }
        auto addr = veld::PubKeyToAddress(veld::DerivePublicKey(priv), testnet);
        std::cout << "  Derived address: " << addr << "\n  Save as mining identity? [y/n]: " << std::flush;
        std::string y; std::getline(std::cin, y); y = _wiz_trim(y);
        if (y != "y" && y != "Y") {
            veld::compat::SecureZero(priv.data(), 32);
            veld::WipeString(priv_hex);
            std::cout << "\n  Cancelled.\n\n"; return run_mining_wizard(datadir, testnet);
        }
        if (!_wiz_save_key(key_file, priv, testnet)) {
            veld::compat::SecureZero(priv.data(), 32);
            veld::WipeString(priv_hex);
            std::cerr << "\n  ERROR: write failed\n\n"; return 1;
        }
        veld::compat::SecureZero(priv.data(), 32);
        veld::WipeString(priv_hex);
        std::cout << "\n  Saved " << addr << " -> " << key_file << "\n\n";
        return 0;
    }
#endif
    if (choice == "4") {
        auto kp = veld::GenerateKeyPair(testnet);
        auto hex = [](const uint8_t* d, int n) {
            std::ostringstream o;
            for (int i=0;i<n;i++) o<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)d[i];
            return o.str();
        };
        std::string priv_hex = hex(kp.private_key.data(), 32);
        std::string pub_hex = hex(
            kp.public_key.data(), static_cast<int>(kp.public_key.size()));
        std::cout << "\n"
#ifdef VELD_PUBLIC_TESTNET
                  << "  Generated new PUBLIC TESTNET identity:\n\n"
                  << "    Address    : " << kp.address << "\n\n"
                  << "  This disposable operational key stays encrypted in this\n"
                  << "  role-bound datadir. It is not exported or shown for reuse.\n\n"
#else
                  << "  Generated new wallet:\n\n"
                  << "    Address    : " << kp.address << "\n"
                  << "    Private key: " << priv_hex << "\n\n"
                  << "  !! CRITICAL: Write down the private key NOW. It will not\n"
                  << "     be shown again. Without it you lose access if miner.key\n"
                  << "     is ever deleted. Store it offline in a safe place.\n\n"
#endif
                  << "  Save and continue? [y/n]: " << std::flush;
        std::string y; std::getline(std::cin, y); y = _wiz_trim(y);
        if (y != "y" && y != "Y") {
            veld::compat::SecureZero(kp.private_key.data(), 32);
            veld::WipeString(priv_hex);
            std::cout << "\n  Cancelled.\n\n"; return run_mining_wizard(datadir, testnet);
        }
        std::string pass = _wiz_prompt_passphrase(true);
        if (pass.empty()) {
            veld::compat::SecureZero(kp.private_key.data(), 32);
            veld::WipeString(priv_hex);
            std::cerr << "\n  Passphrase required.\n\n"; return run_mining_wizard(datadir, testnet);
        }
        if (!_wiz_save_key_encrypted(
                key_file, kp.private_key, pass, testnet)) {
            veld::WipeString(pass);
            veld::compat::SecureZero(kp.private_key.data(), 32);
            veld::WipeString(priv_hex);
            std::cerr << "\n  ERROR: write failed\n\n"; return 1;
        }
        // Written on EVERY profile. Gating this to non-testnet left a public
        // testnet miner with no keyfile to import into the wallet, even though
        // the line below tells them to do exactly that. The file is encrypted
        // with the operator's passphrase; withholding it protected nothing.
        {
            std::string plaintext = "{\n"
                "  \"version\": 1,\n"
                "  \"address\": \"" + kp.address + "\",\n"
                "  \"privkey\": \"" + priv_hex + "\",\n"
                "  \"pubkey\": \"" + pub_hex + "\",\n"
                "  \"created\": \"miner-generated\"\n"
                "}\n";
            std::string keys_file = datadir + "/veld-wallet-" + kp.address.substr(0,8) + ".veld-keys";
            auto enc = veld::wallet_crypto::EncryptWallet(plaintext, pass);
            std::string write_error;
            const bool keyfile_ok = veld::channel::secure_file::AtomicWrite(
                    keys_file, enc, &write_error,
                    /*require_private_parent=*/true);
            if (keyfile_ok) {
                std::cout << "  Keyfile:    " << keys_file << "\n";
                std::cout << "              (encrypted — import into wallet.veld.network)\n";
            } else {
                std::cerr << "  ERROR: secure keyfile write failed: "
                          << write_error << "\n";
            }
            if (!enc.empty())
                veld::compat::SecureZero(enc.data(), enc.size());
            veld::WipeString(plaintext);
            if (!keyfile_ok) return 1;
        }
        g_passphrase = pass;
        veld::WipeString(pass);
        veld::compat::SecureZero(kp.private_key.data(), 32);
        veld::WipeString(priv_hex);
        std::cout << "\n  Saved -> " << key_file << "\n\n";
        return 0;
    }
    std::cerr << "\n  Invalid choice.\n\n";
    return run_mining_wizard(datadir, testnet);
}

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
typedef BOOL (WINAPI* MiniDumpWriteDump_t)(
    HANDLE hProc, DWORD pid, HANDLE hFile, ULONG dumpType,
    PVOID exceptionParam, PVOID userStreamParam, PVOID callbackParam);
static LONG WINAPI VeldCrashFilter_(EXCEPTION_POINTERS* ep) {
    HMODULE dbghelp = LoadLibraryA("dbghelp.dll");
    if (!dbghelp) return EXCEPTION_CONTINUE_SEARCH;
    auto MDW = (MiniDumpWriteDump_t)GetProcAddress(dbghelp, "MiniDumpWriteDump");
    if (!MDW) { FreeLibrary(dbghelp); return EXCEPTION_CONTINUE_SEARCH; }
    char path[MAX_PATH] = {};
    std::snprintf(path, sizeof(path), "veld-node.crash.%lu.dmp",
                  static_cast<unsigned long>(GetCurrentProcessId()));
    HANDLE fh = CreateFileA(path, GENERIC_WRITE, 0, nullptr,
                            CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH
                                | FILE_FLAG_OPEN_REPARSE_POINT,
                            nullptr);
    if (fh == INVALID_HANDLE_VALUE) { FreeLibrary(dbghelp); return EXCEPTION_CONTINUE_SEARCH; }
    // Crash dumps can contain stack-resident passphrases/private keys.  Refuse
    // to emit one unless the brand-new no-reparse file is owner-only before
    // MiniDumpWriteDump receives the handle.
    if (!veld::compat::RestrictFileToOwner(path)) {
        CloseHandle(fh);
        DeleteFileA(path);
        FreeLibrary(dbghelp);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    MINIDUMP_EXCEPTION_INFORMATION info{};
    info.ThreadId = GetCurrentThreadId();
    info.ExceptionPointers = ep;
    info.ClientPointers = FALSE;
    DWORD dump_type = (DWORD)(MiniDumpNormal | MiniDumpWithThreadInfo);
    MDW(GetCurrentProcess(), GetCurrentProcessId(), fh, dump_type, &info, nullptr, nullptr);
    FlushFileBuffers(fh);
    CloseHandle(fh);
    FreeLibrary(dbghelp);
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

//  Hardening: the persistent validator
// anti-equivocation guard (EndorseAntiEquivGuard) is shared with
// src/veld-validator.cpp via this header so the slashing-safety logic lives in
// exactly one place. See the header for the full rationale.
#include "../include/compat/endorse_guard.h"

static void PrintDeploymentInfoJson() {
    const veld::NetworkConfig config = veld::MainnetConfig();
    std::ostringstream magic;
    magic << "0x" << std::hex << std::setw(8) << std::setfill('0')
          << config.magic;
    std::cout << "VELD_DEPLOYMENT_INFO_V1_JSON {"
              << "\"binary_role\":\"node\","
              << "\"client_version\":\"" << veld::CLIENT_VERSION << "\","
              << "\"default_datadir\":\""
              << veld::DefaultDataDirForNetwork(veld::NetworkKind::Mainnet)
              << "\","
              << "\"display_name\":\"" << veld::DEPLOYMENT_DISPLAY_NAME << "\","
              << "\"disposable\":"
              << (veld::DEPLOYMENT_DISPOSABLE ? "true" : "false") << ","
              << "\"external_value\":"
              << (veld::DEPLOYMENT_EXTERNAL_VALUE ? "true" : "false") << ","
#ifdef VELD_USE_LEVELDB
              << "\"storage_backend\":\"leveldb\","
#else
              << "\"storage_backend\":\"flatfile\","
#endif
#ifdef VELD_FLEET_NO_MINE
              << "\"fleet_no_mine\":true,"
#else
              << "\"fleet_no_mine\":false,"
#endif
              << "\"explorer_port\":"
              << veld::CompiledPublicExplorerPort() << ","
              << "\"genesis_fingerprint\":\"" << veld::GENESIS_HASH << "\","
              << "\"miner_ui_port\":"
              << veld::CompiledPublicMinerUiPort() << ","
              << "\"network_magic\":\"" << magic.str() << "\","
#ifdef VELD_FLEET_NO_MINE
              << "\"mining_compiled\":false,"
              << "\"mining_rpc_methods_compiled\":false,"
#else
              << "\"mining_compiled\":true,"
              << "\"mining_rpc_methods_compiled\":true,"
#endif
              << "\"p2p_port\":" << config.port << ","
              << "\"profile_id\":\"" << veld::DEPLOYMENT_PROFILE_ID << "\","
#if defined(VELD_PUBLIC_MAINNET) || defined(VELD_BTCVELD_REGTEST)
              << "\"legacy_direct_mint_formats_accepted\":false,"
              << "\"reserve_proof_semantics\":\"RTP1/RVS1\","
              << "\"reserve_service_capability_required\":true,"
              << "\"state_digest_version\":8,"
#else
              << "\"legacy_direct_mint_formats_accepted\":true,"
              << "\"reserve_proof_semantics\":\"legacy-or-inactive\","
              << "\"reserve_service_capability_required\":false,"
              << "\"state_digest_version\":7,"
#endif
#ifdef VELD_ENABLE_SNAPSHOT_BOOTSTRAP
              << "\"snapshot_bootstrap_compiled\":true,"
              << "\"snapshot_validation_mode\":\"quarantined-independent-genesis-ibd\","
#else
              << "\"snapshot_bootstrap_compiled\":false,"
#endif
              << "\"role\":\"" << veld::DEPLOYMENT_ROLE << "\","
              << "\"rpc_port\":" << config.rpc_port << ","
              << "\"wallet_ui_port\":"
              << veld::CompiledPublicWalletUiPort() << ","
              << "\"warning\":\"" << veld::DEPLOYMENT_WARNING << "\""
              << "}\n";
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetUnhandledExceptionFilter(VeldCrashFilter_);
#endif
    veld::compat::HardenDllSearchPath();
#ifdef VELD_FLEET_NO_MINE
    // Refuse mining-only flags before every early-return utility path.  A
    // caller cannot smuggle a forbidden role request behind --help,
    // --version, --deployment-info, or another ordering-dependent option.
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        const bool mining_flag =
            arg == "--mine" || arg.rfind("--mine=", 0) == 0 ||
            arg == "--miner" || arg.rfind("--miner=", 0) == 0 ||
            arg == "--threads" || arg.rfind("--threads=", 0) == 0;
        if (mining_flag) {
            std::cerr << "veld-node: " << arg
                      << " is unavailable in a VELD_FLEET_NO_MINE build\n";
            return 78;
        }
    }
#endif
    // Version probes are pure utility calls.  Handle them before network
    // initialization, crypto/dataset self-tests, or any datadir access so
    // service inventories and package checks cannot accidentally start a node.
    if (argc == 2 &&
        (std::string(argv[1]) == "--version" ||
         std::string(argv[1]) == "-V")) {
        std::cout << "Veld Node " << CLIENT_VERSION << "\n";
        return 0;
    }
    veld::compat::InitNetwork();

#ifdef VELD_PUBLIC_RELEASE
    // Public artifacts have exactly one compiled chain identity.  Pre-scan the
    // complete argv before any early-return utility path (--wallet,
    // --verify-release, --verify-snapshot, --help) so merely reordering flags
    // cannot bypass the production profile boundary.
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "--testnet" || arg == "--regtest") {
            std::cerr << "veld-node: FATAL: " << arg
                      << " is unavailable in VELD_PUBLIC_RELEASE; use an "
                         "explicitly non-public developer build with its "
                         "isolated datadir\n";
            return 2;
        }
#ifdef VELD_PUBLIC_MAINNET
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        const bool allowed_snapshot_control =
            arg == "--snapshot-bootstrap" || arg == "--no-snapshot" ||
            arg == "--full-ibd" || arg == "--verify-snapshot";
#else
        constexpr bool allowed_snapshot_control = false;
#endif
        // The public client exposes only a boolean use/opt-out choice and the
        // pinned signature verifier. It never accepts an operator-controlled
        // URL, mirror, archive path, trust key, or alternate snapshot profile.
        const bool snapshot_control =
            (arg.rfind("--", 0) == 0 &&
             arg.find("snapshot") != std::string_view::npos) ||
             arg == "--bootstrap-only" ||
             arg.rfind("--bootstrap-only=", 0) == 0;
        if (snapshot_control && !allowed_snapshot_control) {
            std::cerr << "veld-node: FATAL: " << arg
                      << " is not an accepted public snapshot control\n";
            return 2;
        }
        if (arg == "--upnp" || arg.rfind("--upnp=", 0) == 0 ||
            arg.rfind("--upnp-", 0) == 0) {
            std::cerr << "veld-node: FATAL: " << arg
                      << " is not supported in the "
                         "Veld public release\n";
            return 2;
        }
#endif
#ifdef VELD_PUBLIC_TESTNET
        if (!veld::CompiledRoleAllowsFinalMainnetTrustUtility(arg)) {
            std::cerr << "veld-node: FATAL: " << arg
                      << " is a final-mainnet trust/control utility and is "
                         "unavailable in PUBLIC TESTNET; the separate testnet "
                         "trust scheme/key is owner-approval-pending, Bitcoin "
                         "anchoring is external value, and snapshots are disabled\n";
            return 78;
        }
#endif
    }
#endif

    // Fast, read-only package/deployment identity probe.  It runs before the
    // memory-hard dataset KAT and before any datadir resolution, creation, or
    // quarantine, so a package gate can authenticate the compiled role without
    // mutating host state.  Consensus identity is reported, never rewritten.
    if (argc == 2 && std::string(argv[1]) == "--deployment-info") {
        PrintDeploymentInfoJson();
        return 0;
    }

#ifndef VELD_PUBLIC_TESTNET
    // --verify-release <manifest> <sigfile> : verify a release manifest's
    // ML-DSA-65 signature against the PINNED release pubkey, then exit. The
    // launcher's mandatory-update step calls this BEFORE installing a new
    // client, so a hijacked download server / DNS / CDN cannot push an
    // unsigned or attacker-signed binary to the fleet. Placed before the slow
    // PoW-dataset KAT so the check is fast.
    if (argc >= 2 && std::string(argv[1]) == "--verify-release") {
        if (argc != 4) {
            std::cerr << "verify-release: expected exactly <manifest> <sigfile>\n";
            return 2;
        }
        veld::vendored_crypto::vendored_crypto_selftest();   // crypto integrity first
        auto rd = [](const char* p, size_t ceiling, bool& ok) -> std::vector<uint8_t> {
            std::vector<uint8_t> d;
            std::string error;
            ok = veld::channel::secure_file::ReadExplicitImport(
                     p, d, &error, ceiling)
                == veld::channel::secure_file::ReadResult::Ok;
            return d;
        };
        // Shared verifier (include/crypto/release_verify.h). The local
        // non-public snapshot fixture verifier uses the same pinned release
        // signature primitive; no snapshot network acquisition exists.
        veld::Secp256k1PubKey pub{};
        if (!veld::LoadPinnedReleasePubkey(pub)) { std::cerr << "verify-release: bad pinned key\n"; return 2; }
        bool iok = false, sok = false;
        std::vector<uint8_t> in  = rd(argv[2], 8u * 1024u * 1024u, iok);
        std::vector<uint8_t> sig = rd(argv[3], 64u * 1024u, sok);
        if (!iok || !sok) { std::cerr << "verify-release: cannot read manifest/sig\n"; return 2; }
        bool ok = veld::VerifyReleaseSignatureBytes(in, sig, pub);
        std::cout << (ok ? "RELEASE-SIGNATURE-VALID" : "RELEASE-SIGNATURE-INVALID") << "\n";
        return ok ? 0 : 1;
    }
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    // --verify-snapshot <manifest> <sigfile> : verify a SNAPSHOT manifest's
    // signature against EITHER the pinned snapshot-signing key OR the pinned
    // release key (snapshot_manifest.h::VerifySignedSnapshotManifestPinned).
    // Used by veld-snapshot.sh's publish roundtrip so the hourly publisher can
    // self-check a snapshot-key signature before serving it. Prints the same
    // RELEASE-SIGNATURE-VALID/INVALID token the script greps for.
    if (argc >= 2 && std::string(argv[1]) == "--verify-snapshot") {
        if (argc != 4) {
            std::cerr << "verify-snapshot: expected exactly <manifest> <sigfile>\n";
            return 2;
        }
        veld::vendored_crypto::vendored_crypto_selftest();
        auto rd = [](const char* p, size_t ceiling, bool& ok) -> std::vector<uint8_t> {
            std::vector<uint8_t> d;
            std::string error;
            ok = veld::channel::secure_file::ReadExplicitImport(
                     p, d, &error, ceiling)
                == veld::channel::secure_file::ReadResult::Ok;
            return d;
        };
        bool iok = false, sok = false;
        std::vector<uint8_t> in  = rd(argv[2], 1024u * 1024u, iok);
        std::vector<uint8_t> sig = rd(argv[3], 64u * 1024u, sok);
        if (!iok || !sok) { std::cerr << "verify-snapshot: cannot read manifest/sig\n"; return 2; }
        veld::SnapshotManifest m{};
        bool ok = veld::VerifySignedSnapshotManifestPinned(in, sig, m);
        if (ok) {
            std::string compiled = veld::HashToHex(veld::CreateGenesisBlock().GetHash());
            for (char& c : compiled) c = (char)std::tolower((unsigned char)c);
            std::string compiled_be;
            if (compiled.size() == 64) {
                compiled_be.reserve(64);
                for (int b = 31; b >= 0; --b) {
                    compiled_be.push_back(compiled[2*b]);
                    compiled_be.push_back(compiled[2*b + 1]);
                }
            }
            ok = compiled.size() == 64 &&
                 (m.genesis == compiled || m.genesis == compiled_be);
        }
        std::cout << (ok ? "RELEASE-SIGNATURE-VALID" : "RELEASE-SIGNATURE-INVALID") << "\n";
        return ok ? 0 : 1;
    }
#endif
#endif

#if defined(__linux__)
    ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif

    veld::mining::VeldIntegerDeterminismCheck();
#ifdef VELD_MAINNET_POW
    veld::mining::VeldDatasetLightKat();   // light-verify recompute == full dataset (fail-closed)
#endif

    veld::vendored_crypto::vendored_crypto_selftest();

    // Release qualification executes this mode against each final candidate
    // artifact.  It performs the same strict startup verification without
    // opening a datadir or touching network state, and emits one parseable
    // record bound to the exact compiled header.
    if (argc == 2 && std::string(argv[1]) == "--verify-compiled-genesis") {
        const veld::Block genesis = veld::CreateGenesisBlock();
        const auto proof = veld::mining::VerifyGenesisPoW(genesis);
        const auto header = genesis.header.Serialize();
        const veld::Hash256 block_id = genesis.header.GetHash();
        std::string display_hash;
        display_hash.reserve(64);
        static constexpr char HEX[] = "0123456789abcdef";
        for (int i = 31; i >= 0; --i) {
            display_hash.push_back(HEX[(block_id[i] >> 4) & 0x0f]);
            display_hash.push_back(HEX[block_id[i] & 0x0f]);
        }
        std::ostringstream bits_stream;
        bits_stream << "0x" << std::hex << std::setw(8) << std::setfill('0')
                    << genesis.header.bits;
        std::cout << "VELD_COMPILED_GENESIS_POW_V1_JSON {"
                  << "\"block_id_internal_hex\":\"" << veld::HashToHex(block_id) << "\","
                  << "\"dataset_ok\":" << (proof.dataset_ok ? "true" : "false") << ","
                  << "\"genesis_bits\":\"" << bits_stream.str() << "\","
                  << "\"genesis_hash\":\"" << display_hash << "\","
                  << "\"header_hex\":\"" << veld::BytesToHex(header) << "\","
                  << "\"nonce\":" << genesis.header.nonce << ","
                  << "\"pow_hash_internal_hex\":\"" << veld::HashToHex(proof.pow_hash) << "\","
                  << "\"pow_target_comparison\":\"strict-less-than\","
                  << "\"pow_target_passed\":" << (proof.passed ? "true" : "false") << ","
                  << "\"target_internal_hex\":\"" << veld::HashToHex(proof.target) << "\","
                  << "\"target_valid\":" << (proof.target_valid ? "true" : "false")
                  << "}\n";
        return proof.target_valid && proof.dataset_ok && proof.passed ? 0 : 1;
    }

    bool       opt_setup    = false;
    bool       opt_no_prompt = false;
    bool       opt_print_rpc_token = false;
    bool       opt_regtest  = false;
    uint64_t   opt_staking_supply = 0;
    bool       opt_verbose  = false;
    bool       opt_quiet    = false;
    bool       opt_txindex  = false;
    bool       opt_testnet  = false;
    bool       opt_mine     = false;
    bool       opt_nomine   = false;
    bool       opt_endorse  = false;
    bool       opt_reachable = false;
    bool       opt_tor      = false;
    bool       opt_tor_only = false;
    bool       opt_tor_data_directory_set = false;
    std::string opt_tor_data_directory;
    std::string opt_datadir = "";
    std::string opt_miner_addr = "";
    std::string opt_import_miner_key = "";
    bool       opt_create_miner_key = false;
#ifdef VELD_PUBLIC_MAINNET
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    bool       opt_full_ibd  = false;
    bool       opt_snapshot_bootstrap = true;
#else
    bool       opt_full_ibd  = true;
    bool       opt_snapshot_bootstrap = false;
#endif
#else
    bool       opt_full_ibd  = false;   // explicit non-public snapshot opt-out
    bool       opt_snapshot_bootstrap = false;
#endif
    bool       opt_verify_pow = false;  // --verify-pow: background re-verify PoW of the on-disk chain
    bool       opt_reindex_canonical = false;
    uint16_t   opt_rpc_port = MainnetConfig().rpc_port;
    uint16_t   opt_p2p_port = 0;
    std::vector<std::string> opt_connect;
    std::vector<std::string> opt_trusted_ips;
    std::vector<std::string> opt_fleet_anchor_ips;
    bool       opt_allow_plaintext_miner_key = false;
    unsigned   opt_mining_threads = 0;
#ifndef VELD_MAINNET_POW
    uint64_t   opt_allow_legacy_replay_below = 0;
#endif

    auto parse_uint_arg = [](const char* flag, const char* val) -> uint64_t {
        try {
            size_t pos = 0;
            unsigned long long v = std::stoull(val, &pos);
            if (pos != std::string(val).size())
                throw std::invalid_argument("trailing garbage");
            return (uint64_t)v;
        } catch (const std::exception& e) {
            std::cerr << "veld-node: bad value for " << flag << " '" << val
                      << "': " << e.what() << "\n";
            std::exit(2);
        }
    };

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--wallet") {
            if (i != 1 || argc > 3 ||
                (argc == 3 && argv[2][0] == '-')) {
                std::cerr << "veld-node: --wallet accepts at most one wallet path\n";
                return 2;
            }
#ifdef VELD_PUBLIC_TESTNET
            // The legacy CLI wallet uses the final-compatible VELDWALLET2
            // schema and has no role/profile/genesis binding.  Refuse before
            // parsing a following path or asking for a password so a testnet
            // process cannot read, create, or modify a generic/final wallet.
            std::cerr << "veld-node: " << veld::DEPLOYMENT_WARNING << "\n"
                      << "veld-node: --wallet is disabled in PUBLIC TESTNET; "
                         "use the role-bound local desktop wallet\n";
            return 78;
#else
            std::string path = (i+1 < argc && argv[i+1][0] != '-') ? argv[++i] : "wallet.veld";
            veld::cli::RunWalletCLI(path);
            return 0;
#endif
        }
        else if (arg == "--regtest")   { opt_regtest = true; }
        else if (arg == "--staking-supply") {
#if defined(VELD_MAINNET_POW) && defined(VELD_PUBLIC_RELEASE)
            std::cerr << "veld-node: FATAL: --staking-supply is a non-public "
                         "bringup override and is forbidden in a production "
                         "mainnet build; staking thresholds are compiled consensus\n";
            return 2;
#else
            if (i + 1 >= argc) {
                std::cerr << "veld-node: --staking-supply requires an integer value\n";
                return 2;
            }
            opt_staking_supply = parse_uint_arg("--staking-supply", argv[++i]);
#endif
        }
        else if (arg == "--verbose")   { opt_verbose = true; }
        else if (arg == "--quiet")     { opt_quiet   = true; }
        else if (arg == "--txindex")   { opt_txindex = true; }
        else if (arg == "--testnet") { opt_testnet = true; }
        else if (arg == "--mine") {
#ifdef VELD_FLEET_NO_MINE
            std::cerr << "veld-node: --mine is unavailable in a VELD_FLEET_NO_MINE build\n";
            return 78;
#else
            opt_mine = true;
#endif
        }
        else if (arg == "--endorse") { opt_endorse = true; }
        else if (arg == "--reachable") { opt_reachable = true; }
        else if (arg == "--tor")       { opt_tor = true; }
        else if (arg == "--tor-only")  { opt_tor_only = true; opt_tor = false; opt_reachable = false; }
        else if (arg == "--tor-data-dir") {
            if (i + 1 >= argc || opt_tor_data_directory_set) {
                std::cerr << "veld-node: --tor-data-dir requires one absolute "
                             "owner-only directory\n";
                return 2;
            }
            opt_tor_data_directory = argv[++i];
            opt_tor_data_directory_set = true;
        }
        else if (arg == "--setup") {
            opt_setup = true;
#ifdef VELD_FLEET_NO_MINE
            // Fleet setup is identity-only.  Validator activation remains an
            // explicit --endorse choice; setup must not smuggle either mining
            // or endorsement into the role.
#else
            opt_mine = true;
#endif
        }
        else if (arg == "--no-prompt" || arg == "--auto") { opt_no_prompt = true; }
        else if (arg == "--print-rpc-token") { opt_print_rpc_token = true; opt_no_prompt = true; }
        else if (arg == "--nomine")  { opt_nomine = true; }
        else if (arg == "--datadir" && i+1 < argc) { opt_datadir = argv[++i]; }
        else if (arg == "--miner") {
#ifdef VELD_FLEET_NO_MINE
            std::cerr << "veld-node: --miner is unavailable in a VELD_FLEET_NO_MINE build\n";
            return 78;
#else
            if (i + 1 >= argc) {
                std::cerr << "veld-node: --miner requires an address\n";
                return 2;
            }
            opt_miner_addr = argv[++i];
#endif
        }
        else if (arg == "--import-miner-key") {
            if (i + 1 >= argc) {
                std::cerr << "veld-node: --import-miner-key requires a file path\n";
                return 2;
            }
#ifdef VELD_PUBLIC_TESTNET
            std::cerr << "veld-node: keyfile import is disabled in PUBLIC TESTNET\n";
            return 78;
#else
            opt_import_miner_key = argv[++i];
#endif
        }
        else if (arg == "--create-miner-key") {
#ifdef VELD_PUBLIC_TESTNET
            std::cerr << "veld-node: generic identity creation is disabled in PUBLIC TESTNET\n";
            return 78;
#else
            opt_create_miner_key = true;
#endif
        }
        else if (arg == "--bootstrap-only") {
            std::cerr << "veld-node: --bootstrap-only is unavailable: "
                         "snapshot validation continues in the running node\n";
            return 2;
        }
        else if (arg == "--snapshot-bootstrap") {
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
            opt_snapshot_bootstrap = true;
            opt_full_ibd = false;
#else
            std::cerr << "veld-node: snapshot bootstrap is not compiled in this build\n";
            return 2;
#endif
        }
        else if (arg == "--full-ibd") {
            opt_full_ibd = true;
            opt_snapshot_bootstrap = false;
        }
        else if (arg == "--no-snapshot") {
            opt_full_ibd = true;
            opt_snapshot_bootstrap = false;
        }
        else if (arg == "--verify-pow") { opt_verify_pow = true; }
        else if (arg == "--reindex-canonical") { opt_reindex_canonical = true; }
        else if (arg == "--rpcport" && i+1 < argc) { opt_rpc_port = (uint16_t)parse_uint_arg("--rpcport", argv[++i]); }
        else if (arg == "--p2pport" && i+1 < argc) { opt_p2p_port = (uint16_t)parse_uint_arg("--p2pport", argv[++i]); }
        else if (arg == "--connect" && i+1 < argc) { opt_connect.push_back(argv[++i]); }
        else if (arg == "--trust"   && i+1 < argc) { opt_trusted_ips.push_back(argv[++i]); }
        else if (arg == "--fleet-anchor") {
            if (i + 1 >= argc) {
                std::cerr << "veld-node: --fleet-anchor requires an exact IPv4 literal\n";
                return 2;
            }
            opt_fleet_anchor_ips.push_back(argv[++i]);
        }
        else if (arg == "--allow-plaintext-miner-key") { opt_allow_plaintext_miner_key = true; }
#ifndef VELD_MAINNET_POW
        else if (arg == "--allow-legacy-replay-below" && i+1 < argc) {
            opt_allow_legacy_replay_below = parse_uint_arg("--allow-legacy-replay-below", argv[++i]);
        }
#else
        else if (arg == "--allow-legacy-replay-below") {
            std::cerr << "ERROR: --allow-legacy-replay-below is forbidden in mainnet builds.\n";
            std::cerr << "       The flag exists only for test-chain rescue and is compiled out for mainnet.\n";
            return 78;
        }
#endif
        else if (arg == "--threads") {
#ifdef VELD_FLEET_NO_MINE
            std::cerr << "veld-node: --threads is a mining option and is unavailable in a VELD_FLEET_NO_MINE build\n";
            return 78;
#else
            if (i + 1 >= argc) {
                std::cerr << "veld-node: --threads requires an integer value\n";
                return 2;
            }
            opt_mining_threads =
                static_cast<unsigned>(parse_uint_arg("--threads", argv[++i]));
#endif
        }
        else if (arg == "--help" || arg == "-h") {
            if (argc != 2) {
                std::cerr << "veld-node: help does not accept additional "
                             "arguments\n";
                return 2;
            }
            std::cout << "\nUsage: veld-node [options]\n\n";
#ifndef VELD_PUBLIC_RELEASE
            std::cout << "  --regtest            Regtest mode (isolated transport + datadir)\n"
                      << "  --testnet            Developer testnet mode (isolated transport + datadir)\n";
#endif
            std::cout
#ifndef VELD_FLEET_NO_MINE
                      << "  --mine               Enable mining\n"
#endif
                      << "  --endorse            Endorse blocks as a registered validator without mining (lighter; no 1 GB dataset)\n"
                      << "  --reachable          Auto-open the P2P port via NAT-PMP/PCP so peers can dial you (publishes your IP; no-op on a public IP)\n"
                      << "  --tor                Be reachable as a Tor v3 .onion (zero IP exposure; needs a local Tor daemon with ControlPort)\n"
                      << "  --tor-data-dir DIR   Required with --tor; trusted owner-only Tor directory containing control_auth_cookie\n"
                      << "  --tor-only           Route ALL traffic through Tor (onion-only, real IP never exposed); reads .onion from <datadir>/tor/hs/hostname\n"
#ifndef VELD_PUBLIC_TESTNET
                      << "  --verify-release M S Verify release manifest M against signature S using the pinned release key; exit 0=valid (used by the updater)\n"
#endif
                      << "  --deployment-info    Print compiled role/transport/genesis identity without opening a datadir; exit\n"
                      << "  --verify-compiled-genesis  Verify the compiled memory-hard genesis PoW and exit\n"
#ifndef VELD_FLEET_NO_MINE
                      << "  --threads <N>        Parallel mining threads (default: estimated physical cores minus one)\n"
#endif
                      << "  --datadir <path>     Data directory\n"
#ifndef VELD_FLEET_NO_MINE
                      << "  --miner <addr>       Mining reward address\n"
#endif
#ifndef VELD_PUBLIC_TESTNET
#ifdef VELD_FLEET_NO_MINE
                      << "  --import-miner-key <file>  Validate and install an encrypted validator identity\n"
                      << "  --create-miner-key  Create encrypted miner.key and portable .veld-keys files, then exit\n"
#else
                      << "  --import-miner-key <file>  Validate an encrypted .veld-keys file and atomically install it as this datadir's mining/validator identity\n"
                      << "  --create-miner-key  Create encrypted miner.key and portable .veld-keys files, then exit\n"
#endif
#endif
                      << "  --rpcport <port>     RPC port (default: " << MainnetConfig().rpc_port << ")\n"
                      << "  --p2pport <port>     P2P port (default: " << MainnetConfig().port << ")\n"
                      << "  --connect <host:port> Connect to a peer on startup\n"
                      << "  --fleet-anchor <IPv4> Configure and dial one authoritative outbound clock anchor. Repeatable.\n"
                      << "                       Exact canonical IPv4 literals only; hostnames and ports are rejected.\n"
                      << "                       Also accepts VELD_FLEET_ANCHOR_IPS (comma-separated exact IPv4 list).\n"
                      << "  --txindex            Maintain a txid->height index for O(1) getrawtransaction\n"
                      << "                       (off by default; non-consensus; one-time backfill on enable)\n"
#ifdef VELD_PUBLIC_MAINNET
                      << "  --snapshot-bootstrap Use the official signed snapshot when it is newer, then independently validate from genesis in the background (default).\n"
                      << "  --full-ibd           Refuse snapshot import and perform ordinary peer IBD.\n"
                      << "  --no-snapshot        Alias for --full-ibd.\n"
#else
                      << "  --full-ibd           Refuse snapshot bootstrap and perform ordinary peer IBD.\n"
#endif
                      << "  --verify-pow         Background re-verify PoW of the ordinary on-disk chain.\n"
                      << "  --reindex-canonical  Offline recovery: rebuild the canonical index from retained\n"
                      << "                       block bodies, preserve the prior index, and exit\n"
                      << "  --trust <ip>         Trust an IP — exempt from per-IP cap, never banned. Repeatable.\n"
                      << "                       Also accepts VELD_TRUSTED_IPS env var (comma-separated list).\n"
                      << "                       Use for multi-device home-NAT setups (PC+laptop one WAN IP).\n"
                      << "  --setup              Force the 4-option login wizard (same as every-launch default)\n"
#ifdef VELD_FLEET_NO_MINE
                      << "  --no-prompt, --auto  Skip the validator identity wizard (automation only; needs miner.key to exist)\n\n";
#else
                      << "  --no-prompt, --auto  Skip the login wizard (automation only; needs miner.key to exist)\n\n";
#endif
#if !defined(VELD_PUBLIC_RELEASE) && !defined(VELD_FLEET_NO_MINE)
            std::cout << "  Two-node developer example:\n"
                      << "    Node A:  veld-node --regtest --mine --rpcport 8334\n"
                      << "    Node B:  veld-node --regtest --rpcport 8335 --p2pport 28334 --connect 127.0.0.1:28333\n\n";
#endif
            return 0;
        }
        else {
            // Command-line controls are security-sensitive production input.
            // Unknown options must never be silently reinterpreted as an
            // ordinary mainnet start (including misspelled retired flags).
            std::cerr << "veld-node: unknown option '" << arg << "'\n";
            return 2;
        }
    }

    if (opt_tor && (!opt_tor_data_directory_set ||
                    opt_tor_data_directory.empty())) {
        std::cerr << "veld-node: FATAL: --tor requires --tor-data-dir with an "
                     "absolute owner-only Tor data directory for SAFECOOKIE\n";
        return 2;
    }
    if (!opt_tor && opt_tor_data_directory_set) {
        std::cerr << "veld-node: FATAL: --tor-data-dir is valid only with "
                     "--tor control-port mode\n";
        return 2;
    }

    std::string fleet_anchor_error;
    if (!AppendFleetAnchorEnvironment(opt_fleet_anchor_ips,
                                      fleet_anchor_error)) {
        std::cerr << "veld-node: FATAL: " << fleet_anchor_error << "\n";
        return 2;
    }
    for (const auto& ip : opt_fleet_anchor_ips) {
        if (!veld::net::NodeServer::IsCanonicalIPv4Literal(ip)) {
            std::cerr << "veld-node: FATAL: fleet anchor '" << ip
                      << "' is not an exact canonical IPv4 literal\n";
            return 2;
        }
    }

    NetworkConfig config;
    if (opt_regtest)       config = RegtestConfig();
    else if (opt_testnet)  config = TestnetConfig();
    else                   config = MainnetConfig();

    if (opt_regtest && opt_testnet) {
        std::cerr << "veld-node: FATAL: --regtest and --testnet are mutually exclusive\n";
        return 2;
    }
#ifdef VELD_REGTEST_FIXED_DIFF
    if (!opt_regtest) {
        std::cerr <<
            "veld-node: FATAL: this l3-regtest-fixed-difficulty-v1 artifact "
            "must be started with --regtest; refusing to open a variable-"
            "difficulty network or datadir\n";
        return 2;
    }
#else
    if (opt_regtest) {
        std::cerr <<
            "veld-node: FATAL: --regtest requires an artifact compiled with "
            "VELD_REGTEST_FIXED_DIFF; refusing miner/verifier profile "
            "divergence before networking or datadir use\n";
        return 2;
    }
#endif
    if (!RuntimeNetworkAllowed(config.kind)) {
        // A public-test deployment intentionally uses the production/mainnet
        // profile on its current prelaunch genesis. It is not a runtime
        // testnet identity.  Reject alternate modes before resolving, creating,
        // reading, or quarantining any data directory.
        std::cerr << "veld-node: FATAL: --"
                  << (config.kind == NetworkKind::Regtest ? "regtest" : "testnet")
                  << " is unavailable in VELD_PUBLIC_RELEASE; use an explicitly "
                     "non-public developer build with its isolated datadir\n";
        return 2;
    }

    // Stock clearnet clients use the release-signed exact-IP fleet inventory.
    // Explicit operator anchors remain an override. Tor-only clients retain
    // their separate privacy-preserving bootstrap and never receive clearnet
    // anchor authority as a side effect of local DNS.
    if (opt_fleet_anchor_ips.empty() &&
        config.kind == NetworkKind::Mainnet && !opt_tor_only) {
        opt_fleet_anchor_ips =
            veld::seeder::SeedNodeClient::GetHardcodedFleetAnchorIps();
    }
#ifdef VELD_PUBLIC_TESTNET
    const uint16_t requested_p2p_port = opt_p2p_port ? opt_p2p_port : config.port;
    if (!CompiledRoleAllowsPort(requested_p2p_port, CompiledPublicP2PPort())
            || !CompiledRoleAllowsPort(opt_rpc_port, CompiledPublicRpcPort())) {
        std::cerr << "veld-node: FATAL: PUBLIC TESTNET ports are immutable; "
                  << "required p2p=" << CompiledPublicP2PPort()
                  << " rpc=" << CompiledPublicRpcPort()
                  << ", requested p2p=" << requested_p2p_port
                  << " rpc=" << opt_rpc_port << "\n";
        return 2;
    }
    if (opt_connect.empty()) {
        std::cerr << "veld-node: FATAL: PUBLIC TESTNET has no compiled "
                     "final-mainnet seed fallback; provide at least one reviewed "
                     "testnet-only --connect <host[:19333]> entry\n";
        return 2;
    }
    for (const auto& peer : opt_connect) {
        std::string lower = peer;
        for (char& c : lower) c = (char)std::tolower((unsigned char)c);
        const auto colon = peer.rfind(':');
        const std::string host = colon == std::string::npos
            ? peer : peer.substr(0, colon);
        uint16_t port = CompiledPublicP2PPort();
        bool valid = !host.empty() && peer.find_first_of(" \t\r\n") == std::string::npos
            && peer.find("://") == std::string::npos
            && lower.find(".veld.network") == std::string::npos;
        if (colon != std::string::npos) {
            try {
                size_t consumed = 0;
                const unsigned long parsed = std::stoul(peer.substr(colon + 1), &consumed);
                valid = valid && consumed == peer.size() - colon - 1
                    && parsed <= 65535;
                port = static_cast<uint16_t>(parsed);
            } catch (...) {
                valid = false;
            }
        }
        if (!valid || !CompiledRoleAllowsPort(port, CompiledPublicP2PPort())) {
            std::cerr << "veld-node: FATAL: invalid/cross-role PUBLIC TESTNET "
                         "--connect target '" << peer << "'; require a testnet-only "
                      << "host with port " << CompiledPublicP2PPort() << "\n";
            return 2;
        }
    }
#endif

    // Route per-block engine diagnostics through veld::vcerr(); ON via
    // --verbose or VELD_VERBOSE=1, otherwise suppressed so the public miner
    // console shows only user-facing lines.
    veld::DiagVerbose().store(opt_verbose || std::getenv("VELD_VERBOSE") != nullptr,
                              std::memory_order_relaxed);

    std::signal(SIGINT,  handle_signal);
    std::signal(SIGTERM, handle_signal);

    if (opt_regtest && !opt_nomine) {
#ifdef VELD_FLEET_NO_MINE
        std::cerr << "veld-node: regtest auto-mining is unavailable in a VELD_FLEET_NO_MINE build; pass --nomine\n";
        return 78;
#else
        opt_mine = true;
#endif
    }

    if (opt_datadir.empty()) {
        opt_datadir = DefaultDataDirForNetwork(config.kind);
    }
    std::replace(opt_datadir.begin(), opt_datadir.end(), '\\', '/');
    try {
        auto abs = std::filesystem::absolute(opt_datadir).lexically_normal().string();
        std::replace(abs.begin(), abs.end(), '\\', '/');
        opt_datadir = abs;
    } catch (const std::exception& e) {
        std::cerr << "  FATAL: invalid data directory: " << e.what() << "\n";
        return 2;
    }
    std::string datadir_error;
    if (!veld::channel::secure_file::EnsurePrivateDirectory(
            opt_datadir, &datadir_error)) {
        std::cerr << "  FATAL: data directory is not a real owner-only directory: "
                  << datadir_error << "\n";
        return 2;
    }
#ifdef VELD_PUBLIC_RELEASE
    std::string identity_error;
    if (!veld::ValidateOrCreatePublicNetworkIdentity(
            opt_datadir, &identity_error)) {
        std::cerr << "  FATAL: public datadir identity refusal: "
                  << identity_error << "\n";
        return 2;
    }
#endif

#ifndef VELD_PUBLIC_TESTNET
    if (opt_create_miner_key && !opt_import_miner_key.empty()) {
        std::cerr << "veld-node: --create-miner-key and --import-miner-key are mutually exclusive\n";
        return 2;
    }
    if (opt_create_miner_key) {
        const std::string destination = opt_datadir + "/miner.key";
        if (std::filesystem::exists(destination)) {
            std::cerr << "veld-node: refusing to replace an existing miner.key\n";
            return 1;
        }
        std::string passphrase = _wiz_ask_passphrase();
        struct CreatePassphraseWiper {
            std::string& value;
            ~CreatePassphraseWiper() { veld::WipeString(value); }
        } wipe_passphrase{passphrase};
        if (passphrase.empty()) {
            std::cerr << "veld-node: identity passphrase is empty\n";
            return 1;
        }
        std::string policy_error;
        if (!veld::wallet_crypto::ValidateNewPassphrase(
                passphrase, &policy_error)) {
            std::cerr << "veld-node: " << policy_error << "\n";
            return 1;
        }
        veld::RealKeyPair created = veld::GenerateKeyPair(
            config.IsTestNetwork());
        struct CreatedPrivateKeyWiper {
            veld::RealKeyPair& value;
            ~CreatedPrivateKeyWiper() {
                veld::compat::SecureZero(
                    value.private_key.data(), value.private_key.size());
            }
        } wipe_created{created};
        std::string address;
        std::string portable_path;
        std::string create_error;
        if (!_wiz_create_portable_key_bundle(
                opt_datadir, created.private_key, passphrase,
                config.IsTestNetwork(), address, portable_path,
                create_error)) {
            std::cerr << "veld-node: could not create the protected mining "
                         "identity bundle: " << create_error << "\n";
            return 1;
        }
        std::cout << "MINER-KEY-CREATE-COMPLETE address="
                  << address << " keyfile=" << portable_path << "\n";
        return 0;
    }

    if (!opt_import_miner_key.empty()) {
        std::string passphrase = _wiz_ask_passphrase();
        struct ImportPassphraseWiper {
            std::string& value;
            ~ImportPassphraseWiper() { veld::WipeString(value); }
        } wipe_passphrase{passphrase};
        std::string imported_address;
        std::string import_error;
        const std::string destination = opt_datadir + "/miner.key";
        if (!_wiz_import_encrypted_keyfile(
                opt_import_miner_key, destination, passphrase,
                config.IsTestNetwork(), imported_address, import_error)) {
            std::cerr << "veld-node: keyfile import failed: "
                      << import_error << "\n";
            return 1;
        }
        std::cout << "MINER-KEY-IMPORT-COMPLETE address="
                  << imported_address << "\n";
        return 0;
    }
#endif

    if (opt_reindex_canonical) {
        veld::db::VeldDB::OfflineReindexResult result;
        std::string recovery_error;
        if (!veld::db::VeldDB::RebuildCanonicalIndexOffline(
                opt_datadir + "/db", result, &recovery_error)) {
            std::cerr << "veld-node: FATAL: " << recovery_error << "\n";
            return 1;
        }
        std::cout << "CANONICAL-REINDEX-COMPLETE height=" << result.height
                  << " tip=" << result.tip_hash
                  << " scanned=" << result.scanned_blocks
                  << " reachable=" << result.reachable_blocks << "\n"
                  << "Prior index preserved at: " << result.backup_path << "\n"
                  << "Restart veld-node normally to run full consensus replay "
                     "before serving.\n";
        return 0;
    }

#ifdef VELD_PUBLIC_TESTNET
    // The disposable testnet's lease is compiled in, so there is nothing to
    // authorize at launch: no credential files, no signature checks, and no
    // once-per-datadir consume marker.  Resolving it here keeps the original
    // ordering guarantee -- the lease is established before VeldNode
    // construction and therefore before any listener -- while an ordinary user
    // just runs the client.
    public_testnet::RuntimeLimits testnet_runtime_limits;
    std::string testnet_runtime_error;
    int64_t testnet_lease_local_now = 0;
    auto admit_testnet_lease = [&]() -> bool {
        if (testnet_lease_local_now > 0) return true;
        const int64_t local_now = public_testnet::CurrentUnixTime();
        if (!public_testnet::CompiledRuntimeLimits(
                local_now, testnet_runtime_limits, &testnet_runtime_error)) {
            std::cerr << "veld-node: FATAL: public-testnet lease refusal: "
                      << testnet_runtime_error << "\n";
            return false;
        }
        testnet_lease_local_now = local_now;
        return true;
    };
#endif

    // --print-rpc-token: a trusted LOCAL utility path for the peg daemons, which
    // cannot read the ENCRYPTED rpc.token. Decrypt it (same crypto the node uses),
    // print the plaintext token, and exit BEFORE any chain/LevelDB init — so it works
    // even while the node is running (no DB-lock contention).
    if (opt_print_rpc_token) {
#ifdef VELD_PUBLIC_TESTNET
        // A local secret-export utility must not bypass launch authority. It
        // consumes this datadir's restart authorization before reading/output.
        if (!admit_testnet_lease()) return 78;
#endif
        std::string pass = _wiz_ask_passphrase();
        std::string tf_path = opt_datadir + "/rpc.token";
        std::string tok;
        (void)_wiz_load_rpc_token(tf_path, pass, tok);
        if (tok.empty()) {
            std::cerr << "veld-node --print-rpc-token: cannot read/decrypt " << tf_path
                      << " (missing, or wrong VELD_VAULT_PASSPHRASE)\n";
            return 1;
        }
        std::cout << tok << "\n";
        return 0;
    }
    if ((opt_mine || opt_endorse || opt_setup) && opt_miner_addr.empty()) {
        std::string kp_check = opt_datadir + "/miner.key";
        // Interactive launches use the mining setup wizard.  A supervised
        // non-interactive process with an existing miner key must resume
        // without prompting; otherwise the TTY guard exits with status 78 and
        // systemd leaves the service stopped.  Fresh non-interactive installs
        // still fail with status 78 so an operator must complete setup first.
        bool is_interactive_tty;
#ifdef _WIN32
        is_interactive_tty = true;
#else
        is_interactive_tty = (::isatty(STDIN_FILENO) && ::isatty(STDERR_FILENO));
#endif
        bool have_key  = std::filesystem::exists(kp_check);
        bool have_pass = (std::getenv("VELD_VAULT_PASSPHRASE") != nullptr);
        bool need_wizard;
        if (opt_no_prompt) {
            need_wizard = false;
        } else if (have_key && (!is_interactive_tty || have_pass)) {
            // Implicit auto-resume: reuse an existing miner.key silently instead of
            // blocking on the identity menu when EITHER stdin is non-interactive OR a
            // VELD_VAULT_PASSPHRASE env is set (the operator's explicit "run unattended"
            // signal; the passphrase prompt itself is already satisfied from that env).
            // The passphrase clause is the ONLY auto-resume path on Windows, where
            // is_interactive_tty is forced true above — so a Windows miner that exports
            // VELD_VAULT_PASSPHRASE and already has a key no longer freezes at the menu
            // after a crash-restart (the "freezes for hours" outage).
            need_wizard = false;
        } else {
            need_wizard = true;
        }
        if (opt_no_prompt && !std::filesystem::exists(kp_check)) {
            std::cerr << "  [setup] --no-prompt was set but no miner.key exists; "
                      << "forcing the wizard anyway (first-launch bootstrap).\n";
            need_wizard = true;
        }
        if (need_wizard) {
            int rc = run_mining_wizard(opt_datadir, config.IsTestNetwork());
            if (rc != 0) {
                // PUBLIC_TESTNET_MISSING_MINER_KEY_NON_TTY_EXITS_WITHOUT_AUTHORITY_CONSUME
                // Authority admission is deliberately below this return.
                std::cerr << RED << "  [setup] "
#ifdef VELD_FLEET_NO_MINE
                          << "Validator identity setup failed. Exiting.\n"
#else
                          << "Mining identity setup failed. Exiting.\n"
#endif
                          << RESET;
                return rc;
            }
#ifdef _WIN32
            HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
            DWORD mode; GetConsoleMode(hOut, &mode);
            SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif
            std::cout << "\033[2J\033[3J\033[H" << std::flush;
        }
    }

#ifdef VELD_PUBLIC_TESTNET
    // PUBLIC_TESTNET_MINER_PREFLIGHT_BEFORE_AUTHORITY_CONSUME:
    // a missing miner.key on a non-TTY exits from the wizard above without
    // consuming the fleet restart bundle. Fleet/non-mining paths arrive here
    // directly. Every continuing path consumes once for this datadir before
    // VeldNode construction or any listener.
    if (!admit_testnet_lease()) return 78;
    // PUBLIC_TESTNET_AUTHORITY_CONSUMED_BEFORE_VELDNODE_CONSTRUCTION
#endif

#ifdef _WIN32
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    WindowsGuiShutdownEvent gui_shutdown_event;
#endif

#ifdef VELD_PUBLIC_TESTNET
    std::cout << RED << BOLD << "\n  " << DEPLOYMENT_WARNING << RESET << "\n"
              << "  Role:       " << DEPLOYMENT_ROLE
              << " (" << DEPLOYMENT_PROFILE_ID << ")\n"
              << "  Genesis:    " << GENESIS_HASH << "\n\n";
#endif

    std::cout << "\n"
              << GOLD << BOLD
              << "  ============================================================\n"
              << "\n"
              << "    |   |   |===   |      |==\\\n"
              << "    |   |   |      |      |   \\\n"
              << "     | |    |==    |      |   |\n"
              << "     | |    |      |      |   /\n"
              << "      |     |===   |===   |==/\n"
              << "\n"
              << "      Where value is earned.\n"
              << "                                              v" << CLIENT_VERSION << "\n"
              << "\n"
              << "  ============================================================\n"
              << RESET << "\n";

    std::cout << "  Network: " << BOLD << config.name << RESET << "\n";
    std::cout << "  Mode:    "
              << (opt_mine ? GREEN "Mining (starts after sync)" RESET
                           : (opt_endorse ? GREEN "Validator" RESET
                                          : GRAY "Node" RESET))
              << "\n";
    if (veld::DiagVerbose().load()) {
        std::cout << "  Data dir:   " << opt_datadir << "\n";
        std::cout << "  P2P port:   " << (opt_p2p_port ? opt_p2p_port : config.port) << "\n";
        std::cout << "  RPC:        " << CYAN << "http://127.0.0.1:" << opt_rpc_port << RESET << "\n";
        if (opt_endorse && !opt_mine)
            std::cout << "  Endorsing:  " << GREEN "enabled" RESET << GRAY " (validator endorse-only)" RESET << "\n";
        else if (opt_mine)
            std::cout << "  Endorsing:  " << GRAY "automatic when registered" RESET << "\n";
        std::cout << "  Signing:    " << GREEN << "ML-DSA-65" << RESET << "\n";
#ifdef VELD_USE_LEVELDB
        std::cout << "  DB:         " << GREEN << "LevelDB" << RESET << "\n";
#else
        std::cout << "  DB:         " << GRAY << "FlatFileStore" << RESET << "\n";
#endif
    }
    std::cout << "\n";

#if defined(VELD_PUBLIC_MAINNET) && \
    defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    // Acquire and validate a snapshot before constructing the live node, while
    // no RPC, P2P, explorer, or mining surface exists. An invalid/unavailable
    // signed snapshot is an availability miss and falls back to ordinary IBD.
    if (opt_snapshot_bootstrap && !opt_regtest &&
        !std::filesystem::exists(
            std::filesystem::path(opt_datadir) /
            "db/.snapshot-consensus-replay-required")) {
        uint64_t local_height = 0;
        try {
            const auto db_root = std::filesystem::path(opt_datadir) / "db";
            const bool any_existing = std::filesystem::exists(db_root / "blocks") ||
                                      std::filesystem::exists(db_root / "utxo") ||
                                      std::filesystem::exists(db_root / "index");
            if (any_existing) {
                db::VeldDB existing(db_root.string());
                const auto tip = existing.ReadChainTipExact();
                if (!tip) throw std::runtime_error(
                    "existing chain has no exact durable tip");
                local_height = tip->height;
            }
        } catch (const std::exception& e) {
            std::cerr << "  [snapshot] existing chain preflight failed: "
                      << e.what() << "\n";
            return 1;
        }

        snapshot_bootstrap::PreparedPublicSnapshot prepared;
        std::string snapshot_error;
        if (snapshot_bootstrap::PreparePublicSnapshot(
                opt_datadir, local_height, prepared, &snapshot_error)) {
            snapshot_bootstrap::SnapshotCandidateValidation validation;
            try {
                const std::string candidate_root =
                    (prepared.scratch_root / "extract").string();
                {
                    VeldNode candidate(config, candidate_root);
                    candidate.SetQuietBoot(true);
                    candidate.SetStakingActivation(STAKING_ACTIVATION_SUPPLY);
                    candidate.PrepareSnapshotCandidateReplay(
                        prepared.manifest.height,
                        prepared.manifest.tip_hash);
                    candidate.ValidateStoredChainOnly(
                        prepared.manifest.height,
                        prepared.manifest.tip_hash,
                        /*verify_historical_pow=*/false);
                    const Block anchor = candidate.GetChain().GetBlock(
                        prepared.manifest.anchor_height);
                    if (HashToHex(anchor.GetHash()) !=
                        prepared.manifest.anchor_hash) {
                        throw std::runtime_error(
                            "snapshot launch-chain anchor does not match replay");
                    }
                    validation.consensus_state_sha256 =
                        HashToHex(candidate.ConsensusStateDigest());
                    validation.passed = true;
                }
                if (!snapshot_bootstrap::CommitPreparedPublicSnapshot(
                        opt_datadir, prepared, validation, &snapshot_error)) {
                    throw std::runtime_error(snapshot_error);
                }
                std::cout << "  [snapshot] authenticated snapshot h="
                          << prepared.manifest.height
                          << " installed; services remain quarantined while "
                             "the same chain is independently rebuilt from genesis.\n";
            } catch (const std::exception& e) {
                std::error_code cleanup_error;
                std::filesystem::remove_all(
                    prepared.scratch_root, cleanup_error);
                std::cerr << "  [snapshot] candidate rejected: " << e.what()
                          << "; continuing with ordinary peer IBD.\n";
            }
        } else {
            std::cerr << "  [snapshot] official snapshot not used: "
                      << snapshot_error
                      << "; continuing with ordinary peer IBD.\n";
        }
    }
#endif

    std::unique_ptr<VeldNode> node_owner;
    try {
        node_owner = std::make_unique<VeldNode>(config, opt_datadir);
    } catch (const std::exception& e) {
        std::cerr << "\n  [FATAL] Node init failed: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "\n  [FATAL] Node init failed (unknown error)\n";
        return 1;
    }
    VeldNode& node = *node_owner;
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    std::unique_ptr<VeldNode> background_chainstate;
    std::optional<VeldNode::SnapshotValidationBase>
        background_validation_base;
    std::vector<std::string> background_validation_peers;
#endif
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    bool full_ibd_receipt_valid = false;
    snapshot_bootstrap::FullIbdReceipt full_ibd_receipt;
    std::optional<SnapshotManifest> installed_snapshot_handoff;
#if defined(VELD_PUBLIC_MAINNET)
    if (std::filesystem::exists(
            std::filesystem::path(opt_datadir) /
            "db/.snapshot-consensus-replay-required")) {
        if (!opt_full_ibd) {
            std::string handoff_error;
            installed_snapshot_handoff =
                snapshot_bootstrap::VerifyInstalledSnapshotHandoff(
                    opt_datadir, &handoff_error);
            if (!installed_snapshot_handoff) {
                std::cerr << "  [snapshot] FATAL: imported snapshot handoff "
                             "verification failed: "
                          << handoff_error << "\n";
                return 1;
            }
        }
    }
#endif
#endif
    RealKeyPair miner_kp;
    bool miner_key_ready = false;
#if defined(VELD_FLEET_NO_MINE) && \
    defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    RealKeyPair fleet_validation_kp;
    bool fleet_validation_key_ready = false;
#endif
#if defined(VELD_PUBLIC_MAINNET) && defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    // A full-IBD receipt authenticates work this datadir already performed. It
    // is valid for accelerating local restart replay even when snapshot import
    // is disabled. --full-ibd / --no-snapshot controls external bootstrap; it
    // must not turn every ordinary restart into another historical PoW pass.
    if (!opt_regtest) {
        std::string receipt_error;
#if defined(VELD_FLEET_NO_MINE) && \
    defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        const std::string fleet_key_file =
            snapshot_bootstrap::FleetKeyPath(opt_datadir);
        if (std::filesystem::exists(fleet_key_file)) {
            if (g_passphrase.empty()) {
                std::string env_pass = _wiz_ask_passphrase();
                if (!env_pass.empty()) g_passphrase = env_pass;
            }
            fleet_validation_key_ready = _wiz_load_key_encrypted(
                fleet_key_file, g_passphrase, fleet_validation_kp,
                config.IsTestNetwork());
            if (!fleet_validation_key_ready) {
                std::cerr << "  [snapshot] cannot decrypt the fleet validation "
                             "key; recovery remains locked.\n";
                return 1;
            }
            full_ibd_receipt_valid =
                snapshot_bootstrap::VerifyFleetIbdReceipt(
                    opt_datadir, fleet_validation_kp.public_key,
                    full_ibd_receipt, &receipt_error);
        }
        const bool receipt_present = std::filesystem::exists(
            snapshot_bootstrap::FleetReceiptPath(opt_datadir));
#else
        const bool receipt_present = std::filesystem::exists(
            snapshot_bootstrap::ReceiptPath(opt_datadir));
        if (receipt_present) {
            const std::string miner_key_file =
                (std::filesystem::path(opt_datadir) / "miner.key").string();
            if (std::filesystem::exists(miner_key_file)) {
                if (_wiz_is_encrypted(miner_key_file)) {
                    if (g_passphrase.empty()) {
                        std::string env_pass = _wiz_ask_passphrase();
                        if (!env_pass.empty()) g_passphrase = env_pass;
                    }
                    miner_key_ready = _wiz_load_key_encrypted(
                        miner_key_file, g_passphrase, miner_kp,
                        config.IsTestNetwork());
                } else {
                    miner_key_ready = _wiz_load_plain_key(
                        miner_key_file, miner_kp, config.IsTestNetwork());
                }
            }
            if (!miner_key_ready) {
                std::cerr << "  [snapshot] cannot load the miner key bound to "
                             "the recovery receipt; recovery remains locked.\n";
                return 1;
            }
            full_ibd_receipt_valid =
                snapshot_bootstrap::VerifyFullIbdReceipt(
                    opt_datadir, miner_kp.public_key,
                    full_ibd_receipt, &receipt_error);
        }
#endif
        if (full_ibd_receipt_valid) {
#ifdef VELD_FLEET_NO_MINE
            std::cout << "  [snapshot] fleet datadir qualified by a prior full "
                         "IBD for this genesis (validated through h="
                      << full_ibd_receipt.height << ").\n";
#else
            std::cout << "  [snapshot] qualified by a prior full IBD for this "
                         "genesis and miner identity (validated through h="
                      << full_ibd_receipt.height << ").\n";
#endif
        } else if (receipt_present) {
            std::cerr << "  [snapshot] invalid full-IBD receipt: "
                      << receipt_error
                      << "; snapshot fast-start remains locked.\n";
        }
    }
#endif
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    if (installed_snapshot_handoff && !opt_full_ibd) {
        node.SetSnapshotFastStartEligible(
            true, installed_snapshot_handoff->height,
            installed_snapshot_handoff->tip_hash);
        node.SetSnapshotQuarantineOnly(true);
    } else {
        node.SetSnapshotFastStartEligible(
            full_ibd_receipt_valid,
            full_ibd_receipt_valid ? full_ibd_receipt.height : 0,
            full_ibd_receipt_valid ? full_ibd_receipt.tip_hash : std::string{});
    }
#endif
#ifdef VELD_PUBLIC_TESTNET
    try {
        node.SetPublicTestnetCompiledLease(testnet_runtime_limits);
        if (!public_testnet::BindOrVerifySession(
                opt_datadir, testnet_runtime_limits,
                std::max(testnet_lease_local_now,
                         public_testnet::CurrentUnixTime()),
                &testnet_runtime_error)) {
            throw std::runtime_error(
                "public-testnet session refusal: " +
                testnet_runtime_error);
        }
    } catch (const std::exception& e) {
        std::cerr << "veld-node: FATAL: public-testnet runtime refusal: "
                  << e.what() << "\n";
        return 78;
    }
#endif
    if (opt_p2p_port) node.SetP2PPort(opt_p2p_port);
    node.SetTxIndexEnabled(opt_txindex);

#ifndef VELD_MAINNET_POW
    if (opt_allow_legacy_replay_below > 0) {
        node.GetChainMut().SetLegacyReplayBelow(opt_allow_legacy_replay_below);
        std::cout << GRAY
                  << "  [bridge] legacy-replay bridge ACTIVE: blocks with "
                     "height < " << opt_allow_legacy_replay_below
                  << " will skip canonical pool-payout byte-equal check.\n"
                  << "  [bridge] This is a TEST-CHAIN RESCUE only. Mainnet "
                     "build strips this flag entirely.\n" << RESET;
    }
#endif

    {
#if defined(VELD_MAINNET_POW) && defined(VELD_PUBLIC_RELEASE)
        // Public nodes use one compiled staking identity regardless of local
        // NetworkConfig contents. The CLI override was rejected during parsing,
        // and the VeldNode setter independently clamps internal callers too.
        node.SetStakingActivation(STAKING_ACTIVATION_SUPPLY);
#else
        uint64_t activation = opt_staking_supply > 0
            ? opt_staking_supply * VELD_UNITS
            : config.bootstrap_phase_end_units;
        node.SetStakingActivation(activation);
        if (opt_staking_supply > 0) {
            std::cout << GRAY << "  Staking activates at: " << opt_staking_supply << " VELD (bringup override)\n" << RESET;
            node.GetStaking().SetMinStakeUnits(10 * VELD_UNITS);
            node.GetValidators().SetMinValidatorStake(50 * VELD_UNITS);
            std::cout << GRAY << "  Validators: force-active (bringup override)\n" << RESET;
            std::cout << GRAY << "  Bringup minimums: stake=10 VELD, validator=50 VELD staked\n" << RESET;
        }
        else if (activation != STAKING_ACTIVATION_SUPPLY)
            std::cout << GRAY << "  Staking activates at: " << (double)activation/VELD_UNITS << " VELD (config)\n" << RESET;
#endif
    }

    if (opt_mine) veld::net::g_suppress_sync.store(true);
    uint64_t advertised_services = veld::MessageType::NODE_FULL;
#ifdef VELD_FLEET_NO_MINE
    advertised_services |= veld::MessageType::NODE_FLEET;
#else
    if (opt_mine)
        advertised_services |= veld::MessageType::NODE_MINER;
    if (opt_endorse)
        advertised_services |= veld::MessageType::NODE_VALIDATOR;
#endif
    if (opt_tor || opt_tor_only)
        advertised_services |= veld::MessageType::NODE_ONION;
    node.SetAdvertisedServices(advertised_services);

    // Complete ordinary local replay before Start opens RPC, P2P, explorer,
    // mining, or background threads.
    try {
#ifdef VELD_PUBLIC_TESTNET
        // The disposable chain has no shared snapshot namespace and always
        // replays from genesis.
        opt_full_ibd = true;
#endif
        node.SetFullIbd(opt_full_ibd);

        node.Start();
    }
#ifdef VELD_PUBLIC_TESTNET
    catch (const public_testnet::ListenerActivationAuthorityRefusal& e) {
        std::cerr << "  [FATAL] " << e.what() << "\n";
        return 78;
    }
#endif
    catch (const std::exception& e) {
        std::cerr << "  [FATAL] Offline startup qualification failed: "
                  << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "  [FATAL] Offline startup qualification failed "
                     "(unknown error)\n";
        return 1;
    }

    if (!miner_kp.address.empty() &&
        node.IsAddressRegisteredValidator(miner_kp.address)) {
        advertised_services |= veld::MessageType::NODE_VALIDATOR;
        node.SetAdvertisedServices(advertised_services);
    }

    if (opt_reachable && node.GetTCPServer()
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        && !node.SnapshotQuarantineOnly()
#endif
    ) {
        if (veld::DiagVerbose().load())
            std::cout << CYAN << "  [nat] automatic inbound mapping enabled"
                      << RESET << "\n";
        node.GetTCPServer()->EnablePortMapping();
        node.GetTCPServer()->EnableHolePunch();   // fallback if the router declines port-mapping
    }
    std::string tor_only_onion;
    if (opt_tor_only && node.GetTCPServer()) {
        // Tor-only: the launcher already started a fetched+pinned Tor with a
        // static v3 hidden service. Read our .onion from its hostname file and
        // route ALL traffic through Tor's SOCKS5 (zero clearnet IP exposure).
        {
            std::vector<uint8_t> hostname;
            std::string hostname_error;
            if (veld::channel::secure_file::Read(
                    opt_datadir + "/tor/hs/hostname", hostname,
                    &hostname_error, 4096,
                    /*require_private_parent=*/true)
                == veld::channel::secure_file::ReadResult::Ok) {
                tor_only_onion.assign(hostname.begin(), hostname.end());
            }
            if (tor_only_onion.empty()) {
                std::cerr << RED
                          << "  [FATAL] --tor-only requires a readable owner-only "
                             "datadir/tor/hs/hostname file"
                          << (hostname_error.empty() ? "" : ": " + hostname_error)
                          << ".\n  Re-run tor-setup.ps1 and restart; refusing outbound-only "
                             "Tor mode because this node would not be dialable.\n"
                          << RESET;
                return 1;
            }
        }
        while (!tor_only_onion.empty() &&
               (tor_only_onion.back()=='\n'||tor_only_onion.back()=='\r'||
                tor_only_onion.back()==' '||tor_only_onion.back()=='\t'))
            tor_only_onion.pop_back();
        node.GetTCPServer()->EnableTorOnly(tor_only_onion);   // all dials via SOCKS regardless
        std::cout << CYAN << "  [tor] --tor-only: reachable as " << tor_only_onion
                  << " — all traffic via Tor, zero IP exposure." << RESET << "\n";
    } else if (opt_tor && node.GetTCPServer()) {
        std::cout << CYAN << "  [tor] --tor: publishing a v3 .onion hidden service "
                     "(needs a local Tor daemon w/ ControlPort; zero IP exposure)."
                  << RESET << "\n";
        node.GetTCPServer()->EnableTor(opt_tor_data_directory);
    }

    for (size_t anchor_index = 0;
         anchor_index < opt_fleet_anchor_ips.size(); ++anchor_index) {
        const auto& ip = opt_fleet_anchor_ips[anchor_index];
        if (node.AddFleetAnchorIp(ip)) {
            if (veld::DiagVerbose().load())
                std::cout << GREEN << "  [network] " << RESET
                          << "Seed node " << (anchor_index + 1)
                          << " connected endpoint=" << ip << ":"
                          << config.port << "\n";
        } else {
            std::cerr << YEL << "  [network] WARN: " << RESET
                      << "Seed node " << (anchor_index + 1)
                      << " is temporarily unavailable; retrying";
            if (veld::DiagVerbose().load())
                std::cerr << " endpoint=" << ip << ":" << config.port;
            std::cerr << "\n";
        }
    }

    if (opt_mine
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        && !node.SnapshotQuarantineOnly()
#endif
    ) node.PrewarmHashDataset();

    // Optional operator diagnostic. Full consensus replay already completed
    // synchronously before Start() opened any network service.
    if (opt_verify_pow) node.ForcePowVerification();

    if (opt_connect.empty() && !opt_regtest) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        const auto seeds = opt_tor_only
            ? veld::seeder::SeedNodeClient::GetTorBootstrap()
            : veld::seeder::SeedNodeClient::GetHardcodedBootstrap();
        size_t connected = 0;
        for (const auto& seed : seeds) {
            if (node.ConnectTo(seed, config.port)) {
                ++connected;
                if (veld::DiagVerbose().load())
                    std::cout << "  [peer] " << seed << ":" << config.port
                              << " connected\n";
            } else {
                if (veld::DiagVerbose().load())
                    std::cout << "  [peer] " << seed << ":" << config.port
                              << " unavailable\n";
            }
        }
        if (connected == 0) {
            std::cout << "  Peer discovery is active; initial connections are still pending.\n";
        } else {
            std::cout << GREEN << "  Peers:   " << RESET << connected
                      << " connected\n";
        }
    }

    {
        if (const char* env_trust = std::getenv("VELD_TRUSTED_IPS")) {
            std::string s(env_trust);
            std::string cur;
            auto flush = [&]() {
                size_t a = cur.find_first_not_of(" \t");
                size_t b = cur.find_last_not_of(" \t");
                if (a == std::string::npos) { cur.clear(); return; }
                std::string v = cur.substr(a, b - a + 1);
                if (!v.empty()) opt_trusted_ips.push_back(v);
                cur.clear();
            };
            for (char c : s) { if (c == ',') flush(); else cur.push_back(c); }
            flush();
        }
        for (const auto& ip : opt_trusted_ips) {
            node.AddTrustedIP(ip);
            if (veld::DiagVerbose().load())
                std::cout << GREEN << "  [trusted-ip] " << RESET
                          << ip << " added\n";
        }
    }

    if (!opt_connect.empty()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        for (const auto& peer : opt_connect) {
            auto colon = peer.rfind(':');
            std::string host = (colon != std::string::npos) ? peer.substr(0, colon) : peer;
            uint16_t port = config.port;
            if (colon != std::string::npos) {
                try { port = (uint16_t)std::stoi(peer.substr(colon+1)); }
                catch (...) { port = config.port; }
            }
            if (node.ConnectTo(host, port))
                std::cout << GREEN << "  [OK] " << RESET << "Connected to " << host << ":" << port << "\n";
            else
                std::cout << RED << "  [ERR] " << RESET << "Could not connect to " << host << ":" << port << "\n";
        }
    }

#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    background_validation_base = node.IndependentValidationBase();
    if (background_validation_base) {
        try {
            const std::string background_dir =
                opt_datadir + "/background-ibd";
            background_chainstate =
                std::make_unique<VeldNode>(config, background_dir);
            background_chainstate->SetQuietBoot(true);
            background_chainstate->SetFullIbd(true);
            background_chainstate->SetBackgroundValidationOnly(true);
            background_chainstate->SetBackgroundValidationTarget(
                background_validation_base->height);
            background_chainstate->GetChainMut().SetLocalValidationCeiling(
                background_validation_base->height);
#if defined(VELD_MAINNET_POW) && defined(VELD_PUBLIC_RELEASE)
            background_chainstate->SetStakingActivation(
                STAKING_ACTIVATION_SUPPLY);
#else
            background_chainstate->SetStakingActivation(
                config.bootstrap_phase_end_units);
#endif
            std::cout << "  [background-ibd] opening independent validation "
                         "state; verified restart progress will be reused.\n";
            std::cout.flush();
            background_chainstate->Start();
            node.SetIndependentValidationProgress(
                background_chainstate->GetChain().Height());

            if (opt_tor_only && background_chainstate->GetTCPServer()) {
                background_chainstate->GetTCPServer()->EnableTorOnly(
                    tor_only_onion);
            }

            if (!opt_connect.empty()) {
                background_validation_peers = opt_connect;
            } else if (!opt_regtest) {
                background_validation_peers = opt_tor_only
                    ? veld::seeder::SeedNodeClient::GetTorBootstrap()
                    : veld::seeder::SeedNodeClient::GetHardcodedBootstrap();
            }
            for (const auto& peer : background_validation_peers) {
                const auto colon = peer.rfind(':');
                const std::string host = colon == std::string::npos
                    ? peer : peer.substr(0, colon);
                uint16_t port = config.port;
                if (colon != std::string::npos) {
                    try {
                        port = static_cast<uint16_t>(
                            std::stoul(peer.substr(colon + 1)));
                    } catch (...) {
                        port = config.port;
                    }
                }
                background_chainstate->ConnectTo(host, port);
            }
            std::cout << "  [background-ibd] independent genesis sync started "
                         "toward snapshot base h="
                      << background_validation_base->height << ".\n";
            std::cout.flush();
        } catch (const std::exception& e) {
            if (background_chainstate) background_chainstate->Stop();
            node.RejectIndependentBackgroundValidation(
                "background-chainstate-start-failed");
            std::cerr << "  [snapshot] FATAL: independent background "
                         "chainstate could not start: "
                      << e.what() << "\n";
            node.Stop();
            return 76;
        }
    }
#endif

    node.GetRPC().SetPeerCount([&node]() -> size_t { return node.ConnectedPeers(); });
    node.GetRPC().SetDataDir(opt_datadir);

    std::string rpc_token;
    struct RpcTokenWiper {
        std::string& value;
        ~RpcTokenWiper() { veld::WipeString(value); }
    } wipe_rpc_token{rpc_token};
    std::string token_file = opt_datadir + "/rpc.token";
    {
        if (g_passphrase.empty()) {
            std::string env_pass = _wiz_ask_passphrase();
            if (!env_pass.empty()) g_passphrase = env_pass;
        }
#ifdef VELD_LOCAL_SIM
        if (const char* sim_tok = std::getenv("VELD_SIM_RPC_TOKEN")) {
            rpc_token = _wiz_trim(std::string(sim_tok));
        }
#endif
        if (rpc_token.empty() && std::filesystem::exists(token_file))
            (void)_wiz_load_rpc_token(token_file, g_passphrase, rpc_token);
        if (rpc_token.size() != 64) {
            veld::WipeString(rpc_token);
            static const char* hex = "0123456789abcdef";
            uint8_t rand_bytes[32];
            if (!veld::compat::SecureRandom(rand_bytes, 32))
                throw std::runtime_error("CSPRNG failure — cannot generate RPC token safely");
            for (int i = 0; i < 32; ++i) {
                rpc_token += hex[(rand_bytes[i] >> 4) & 0xF];
                rpc_token += hex[rand_bytes[i] & 0xF];
            }
            veld::compat::SecureZero(rand_bytes, 32);
            if (g_passphrase.empty()) {
                throw std::runtime_error(
                    "Cannot issue RPC token without a wallet passphrase. "
                    "Re-run the setup wizard so miner.key + g_passphrase are "
                    "established before token generation. Plaintext RPC "
                    "token storage is not supported.");
            }
            std::string token_error;
            if (!_wiz_save_rpc_token(
                    token_file, rpc_token, g_passphrase, &token_error))
                throw std::runtime_error(
                    "cannot atomically write owner-only RPC token: " + token_error);
            if (veld::DiagVerbose().load())
                std::cout << GRAY << "  RPC token: " << RESET << "generated (encrypted)\n";
        }
#if defined(VELD_FLEET_NO_MINE) && \
    defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        const std::string fleet_key_file =
            snapshot_bootstrap::FleetKeyPath(opt_datadir);
        if (!fleet_validation_key_ready &&
            std::filesystem::exists(fleet_key_file)) {
            fleet_validation_key_ready = _wiz_load_key_encrypted(
                fleet_key_file, g_passphrase, fleet_validation_kp,
                config.IsTestNetwork());
            if (!fleet_validation_key_ready) {
                throw std::runtime_error(
                    "cannot decrypt the fleet validation key");
            }
        } else if (!fleet_validation_key_ready) {
            fleet_validation_kp = GenerateKeyPair(config.IsTestNetwork());
            fleet_validation_key_ready = _wiz_save_key_encrypted(
                fleet_key_file, fleet_validation_kp.private_key,
                g_passphrase, config.IsTestNetwork());
            if (!fleet_validation_key_ready) {
                throw std::runtime_error(
                    "cannot create the encrypted fleet validation key");
            }
        }
#endif
    }

    auto try_bind_rpc = [&]() -> std::unique_ptr<RpcHttpServer> {
#ifdef VELD_PUBLIC_TESTNET
        uint16_t candidates[1] = {opt_rpc_port};
#else
        uint16_t candidates[5] = {
            opt_rpc_port,
            (uint16_t)(opt_rpc_port + 10),
            (uint16_t)(opt_rpc_port + 20),
            (uint16_t)(opt_rpc_port + 30),
            (uint16_t)(opt_rpc_port + 40),
        };
#endif
        for (uint16_t p : candidates) {
            auto srv = std::make_unique<RpcHttpServer>(node.GetRPC(), p, "", rpc_token);
#ifdef VELD_PUBLIC_TESTNET
            if (srv->Start([&node]() noexcept {
                    return node.PublicTestnetRestartAuthorityFreshNow();
                })) {
#else
            if (srv->Start()) {
#endif
                if (p != opt_rpc_port) {
                    std::cout << CYAN << "  [INFO] " << RESET
                              << "RPC port " << opt_rpc_port
                              << " was busy; bound on " << p << " instead.\n";
                    std::cout << CYAN << "         " << RESET
                              << "Wallets / explorer that hardcode :" << opt_rpc_port
                              << " will need to connect to :" << p << ".\n";
                }
                opt_rpc_port = p;
                return srv;
            }
            if (srv->ActivationGuardRefused()) return srv;
        }
        return nullptr;
    };
#ifdef VELD_PUBLIC_TESTNET
    // The loopback RPC socket is a listener too.  Recheck the original signed
    // restart window after replay/P2P setup and immediately before binding it.
    if (!node.PublicTestnetRestartAuthorityFreshNow()) {
        std::cerr << "veld-node: FATAL: public-testnet restart authority "
                     "expired before RPC listener\n";
        node.Stop();
        return 78;
    }
#endif
    std::unique_ptr<RpcHttpServer> rpc_http_owned;
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    if (!node.SnapshotQuarantineOnly()) rpc_http_owned = try_bind_rpc();
#else
    rpc_http_owned = try_bind_rpc();
#endif
    if (rpc_http_owned && rpc_http_owned->ActivationGuardRefused()) {
        std::cerr << "veld-node: FATAL: public-testnet restart authority "
                     "refused at RPC activation\n";
        node.Stop();
        return 78;
    }
    if (rpc_http_owned) {
        std::cout << GREEN << "  Local services ready.\n" << RESET;
        if (veld::DiagVerbose().load()) {
            std::cout << "  RPC:     127.0.0.1:" << opt_rpc_port << "\n";
            std::cout << GRAY << "  Token:   " << RESET << token_file << "\n";
        }
        try {
            std::string port_file = opt_datadir + "/rpc.port";
            const std::string port_text = std::to_string(opt_rpc_port);
            std::string port_error;
            (void)veld::channel::secure_file::AtomicWriteText(
                port_file, port_text, &port_error,
                /*require_private_parent=*/true);
        } catch (...) {
        }
    } else {
#ifdef VELD_PUBLIC_TESTNET
        std::cout << RED << "  [WARN] " << RESET
                  << "Could not bind immutable PUBLIC TESTNET RPC port "
                  << opt_rpc_port
                  << " — wallet/explorer cannot connect. Free the port and restart.\n";
#else
        std::cout << RED << "  [WARN] " << RESET
                  << "Could not bind RPC on any of "
                  << opt_rpc_port << ", " << (opt_rpc_port+10) << ", "
                  << (opt_rpc_port+20) << ", " << (opt_rpc_port+30) << ", "
                  << (opt_rpc_port+40)
                  << " — wallet/explorer cannot connect. Free a port and restart.\n";
#endif
    }

    std::string kp_file = opt_datadir + "/miner.key";

    // ── Pool & endorsement-pool keypairs (LOAD-ONLY from disk) ─────
    //
    // SECURITY: these are SHARED keys that sign pool flush transactions
    // for the entire network. They must NEVER be auto-created on a
    // user's machine — only infrastructure operators manually deploy
    // Pool keys are operator-provisioned and never generated or embedded by
    // the node. A missing key leaves pool-flush authority disabled locally.
    {
        std::string pool_kp_file = opt_datadir + "/pool.key";
        if (std::filesystem::exists(pool_kp_file)) {
            RealKeyPair pool_kp;
            if (_wiz_is_encrypted(pool_kp_file)) {
                if (g_passphrase.empty()) g_passphrase = _wiz_ask_passphrase();
                if (g_shutdown.load()) return 0;
                if (!_wiz_load_key_encrypted(
                        pool_kp_file, g_passphrase, pool_kp, config.IsTestNetwork())) {
                    std::cerr << RED << "  Wrong passphrase or corrupted pool.key\n" << RESET;
                    return 1;
                }
                node.SetPoolKeypair(pool_kp);
                std::cout << GRAY << "  Pool key:   " << RESET << "loaded (encrypted)\n";
            } else {
                if (!_wiz_load_plain_key(pool_kp_file, pool_kp, config.IsTestNetwork())) {
                    std::cerr << RED
                              << "  FATAL: pool.key is unsafe, malformed, or inconsistent.\n"
                              << RESET;
                    return 1;
                }
                node.SetPoolKeypair(pool_kp);
                if (g_passphrase.empty()) g_passphrase = _wiz_ask_passphrase();
                if (!g_passphrase.empty() && g_passphrase.size() >= 8) {
                    veld::Secp256k1PrivKey priv;
                    std::copy(pool_kp.private_key.begin(), pool_kp.private_key.end(), priv.begin());
                    if (_wiz_save_key_encrypted(
                            pool_kp_file, priv, g_passphrase, config.IsTestNetwork())) {
                        std::cout << GRAY << "  Pool key:   " << RESET << "auto-upgraded plaintext → encrypted\n";
                    } else {
                        std::cerr << RED << "  [FATAL] Failed to encrypt pool.key. Refusing to run with plaintext.\n" << RESET;
                        return 1;
                    }
                } else {
                    std::cerr << RED << "\n  FATAL: pool.key is in PLAINTEXT and no VELD_VAULT_PASSPHRASE is set.\n"
                              << "  Set VELD_VAULT_PASSPHRASE env var to auto-encrypt on startup.\n\n" << RESET;
                    return 1;
                }
            }
        }
    }

    {
        std::string ep_kp_file = opt_datadir + "/endorsement_pool.key";
        std::string pool_kp_file = opt_datadir + "/pool.key";
        bool is_infra_node = std::filesystem::exists(pool_kp_file);

        if (std::filesystem::exists(ep_kp_file)) {
            RealKeyPair ep_kp;
            if (!_wiz_is_encrypted(ep_kp_file)) {
                std::cerr << RED << "\n  FATAL: endorsement_pool.key is in PLAINTEXT.\n"
                          << "  Delete it and restart with VELD_VAULT_PASSPHRASE set to auto-generate a new encrypted key.\n\n"
                          << RESET;
                return 1;
            }
            if (g_passphrase.empty()) g_passphrase = _wiz_ask_passphrase();
            if (g_shutdown.load()) return 0;
            if (!_wiz_load_key_encrypted(ep_kp_file, g_passphrase, ep_kp)) {
                std::cerr << RED << "  Wrong passphrase or corrupted endorsement_pool.key\n" << RESET;
                return 1;
            }
            if (ep_kp.address != ENDORSEMENT_POOL_ADDRESS) {
                std::cerr << RED << "\n  FATAL: endorsement_pool.key address mismatch.\n"
                          << "  File:     " << ep_kp.address << "\n"
                          << "  Expected: " << ENDORSEMENT_POOL_ADDRESS << "\n"
                          << "  Update ENDORSEMENT_POOL_ADDRESS in constants.h or delete the key file.\n\n"
                          << RESET;
                return 1;
            }
            node.SetEndorsementPoolKeypair(ep_kp);
            if (veld::DiagVerbose().load())
                std::cout << GRAY << "  Endorse key: " << RESET << "loaded (encrypted)\n";
        } else if (is_infra_node) {
            if (g_passphrase.empty()) g_passphrase = _wiz_ask_passphrase();
            if (g_passphrase.empty() || g_passphrase.size() < 8) {
                std::cerr << RED << "  [WARN] endorsement_pool.key missing and no passphrase to auto-generate.\n"
                          << "  Set VELD_VAULT_PASSPHRASE env var to auto-create one.\n" << RESET;
            } else {
                veld::Secp256k1PrivKey priv{};
                try {
                    priv = veld::GeneratePrivateKey();
                } catch (const std::exception& e) {
                    std::cerr << RED
                              << "  Secure endorsement key generation failed: "
                              << e.what() << "\n" << RESET;
                    return 1;
                }
                auto pub  = veld::DerivePublicKey(priv);
                auto addr = veld::PubKeyToAddress(pub, false);
                if (!_wiz_save_key_encrypted(ep_kp_file, priv, g_passphrase)) {
                    std::cerr << RED << "  Failed to write " << ep_kp_file << "\n" << RESET;
                    return 1;
                }
                RealKeyPair ep_kp;
                std::copy(priv.begin(), priv.end(), ep_kp.private_key.begin());
                ep_kp.public_key = pub;
                ep_kp.address = addr;
                if (addr != ENDORSEMENT_POOL_ADDRESS) {
                    std::cout << "\n  ╔═══════════════════════════════════════════════════════════╗\n"
                              << "  ║  NEW ENDORSEMENT POOL ADDRESS GENERATED                    ║\n"
                              << "  ║  Update ENDORSEMENT_POOL_ADDRESS in include/core/constants.h:\n"
                              << "  ║  " << addr << "\n"
                              << "  ║  Then rebuild and restart.                                 ║\n"
                              << "  ╚═══════════════════════════════════════════════════════════╝\n\n";
                }
                node.SetEndorsementPoolKeypair(ep_kp);
                if (veld::DiagVerbose().load())
                    std::cout << GRAY << "  Endorse key: " << RESET << "generated (encrypted)\n";
            }
        }
    }

    bool bind_existing_regtest_generation_identity = false;
#ifndef VELD_FLEET_NO_MINE
    bind_existing_regtest_generation_identity =
        opt_regtest && std::filesystem::exists(kp_file);
#endif
    if (opt_mine || opt_endorse ||
        bind_existing_regtest_generation_identity) {
        if (std::filesystem::exists(kp_file)) {
            if (_wiz_is_encrypted(kp_file)) {
                if (!miner_key_ready) {
                    if (g_passphrase.empty()) {
                        g_passphrase = _wiz_ask_passphrase();
                    }
                    if (g_shutdown.load()) return 0;
                    miner_key_ready = _wiz_load_key_encrypted(
                        kp_file, g_passphrase, miner_kp,
                        config.IsTestNetwork());
                    if (!miner_key_ready) {
                        if (g_shutdown.load()) return 0;
                        std::cerr << RED << "  Wrong passphrase or corrupted miner.key.\n" << RESET;
                        return 1;
                    }
                }
                std::cout << GREEN << "  Mining wallet unlocked.\n" << RESET;
                if (veld::DiagVerbose().load())
                    std::cout << "  Address: " << GOLD << miner_kp.address << RESET << "\n";
            } else {
                if (!miner_key_ready) {
                    miner_key_ready = _wiz_load_plain_key(
                        kp_file, miner_kp, config.IsTestNetwork());
                }
                if (!miner_key_ready) {
                    std::cerr << RED
                              << "  Malformed, inconsistent, or unsafe plaintext miner.key.\n"
                              << "  Refusing to start with an untrusted key file.\n" << RESET;
                    return 1;
                }
                if (veld::DiagVerbose().load())
                    std::cout << "  Address: " << GOLD << miner_kp.address << RESET
                              << " (plaintext import)\n";
                std::string pass = _wiz_ask_passphrase();
                if (!pass.empty() && pass.size() >= 8) {
                    if (!_wiz_save_key_encrypted(
                            kp_file, miner_kp.private_key, pass, config.IsTestNetwork())) {
                        std::cerr << RED << "  FATAL: auto-encryption failed.\n" << RESET;
                        return 1;
                    }
                    g_passphrase = pass;
                    std::cout << GREEN << "  Miner key auto-upgraded to encrypted.\n" << RESET;
                } else if (opt_allow_plaintext_miner_key) {
                    std::cout << YEL << "  [WARN] --allow-plaintext-miner-key set — continuing with plaintext (INSECURE).\n" << RESET;
                } else {
                    std::cout << "  Your miner.key is stored in PLAINTEXT.\n";
                    std::cout << "  Encrypt it now? [y/n]: " << std::flush;
                    std::string yn; std::getline(std::cin, yn); yn = _wiz_trim(yn);
                    if (yn != "y" && yn != "Y") {
                        std::cerr << RED << "  FATAL: refusing to run with plaintext miner.key.\n"
                                  << "         Set VELD_VAULT_PASSPHRASE env var for auto-encryption.\n" << RESET;
                        return 1;
                    }
                    std::string ipass = _wiz_prompt_passphrase(true);
                    if (ipass.empty() || !_wiz_save_key_encrypted(
                            kp_file, miner_kp.private_key, ipass, config.IsTestNetwork())) {
                        std::cerr << RED << "  FATAL: encryption failed.\n" << RESET;
                        return 1;
                    }
                    g_passphrase = ipass;
                    std::cout << GREEN << "  Encrypted and saved.\n" << RESET;
                    veld::WipeString(ipass);
                }
            }
        } else {
            miner_kp = GenerateKeyPair(config.IsTestNetwork());
            miner_key_ready = true;
            bool saved = false;
            if (g_passphrase.empty()) {
                std::string pass = _wiz_prompt_passphrase(true);
                if (!pass.empty()) {
                    saved = _wiz_save_key_encrypted(
                        kp_file, miner_kp.private_key, pass, config.IsTestNetwork());
                    if (saved) g_passphrase = pass;
                    veld::WipeString(pass);
                }
            } else {
                saved = _wiz_save_key_encrypted(
                    kp_file, miner_kp.private_key, g_passphrase, config.IsTestNetwork());
            }
            if (!saved) {
                std::cerr << RED
                          << "  FATAL: could not atomically persist owner-only miner.key.\n"
                          << RESET;
                return 1;
            }
            std::cout << GREEN << "  New mining wallet created. Back up veld-data\\miner.key.\n" << RESET;
            if (veld::DiagVerbose().load()) {
                std::cout << "  Address: " << GOLD << miner_kp.address << RESET << "\n";
                std::cout << GRAY << "  Saved:   " << kp_file << RESET << "\n";
            }
        }

#ifndef VELD_PUBLIC_TESTNET
        // A successful sign-in must leave one wallet/node-compatible portable
        // keyfile for this identity.  This is an exact encrypted-byte copy,
        // never a second key generation, and is idempotent on every restart.
        if (miner_key_ready && !g_passphrase.empty()) {
            std::string portable_path;
            std::string portable_error;
            bool portable_created = false;
            if (!_wiz_ensure_portable_keyfile(
                    opt_datadir, miner_kp.address, portable_path,
                    portable_created, portable_error)) {
                std::cerr << RED
                          << "  FATAL: portable mining keyfile verification failed: "
                          << portable_error << "\n" << RESET;
                return 1;
            }
            if (portable_created) {
                std::cout << GREEN
                          << "  Portable wallet keyfile created: "
                          << portable_path << "\n" << RESET;
            }
        }
#endif

        if (!opt_miner_addr.empty()) {
            auto override_script = AddressToScript(opt_miner_addr);
            if (override_script.empty()) {
                std::cout << RED << "  [ERR] Invalid --miner address: " << opt_miner_addr << RESET << "\n";
            } else {
                miner_kp.script_override = override_script;
                miner_kp.address = opt_miner_addr;
                std::cout << "  Mining to:  " << GOLD << opt_miner_addr << RESET << "  (--miner override)\n";
            }
        }

        std::cout << "\n";

        veld::net::g_suppress_sync.store(false);

#ifndef VELD_FLEET_NO_MINE
        if (opt_regtest) {
            std::string generation_identity_error;
            if (!node.BindGenerationIdentity(
                    miner_kp, &generation_identity_error)) {
                std::cerr << RED
                          << "  FATAL: could not bind the validated regtest "
                             "generation identity: "
                          << generation_identity_error << "\n"
                          << RESET;
                return 1;
            }
        }
#endif

        if (opt_mine) {
            unsigned hw_threads = std::max(1u, std::thread::hardware_concurrency());

            unsigned physical_est = (hw_threads >= 4 && (hw_threads % 2) == 0)
                                  ? (hw_threads / 2)
                                  : hw_threads;
            unsigned mine_threads;
            const char* tune_reason;
            if (opt_mining_threads > 0) {
                mine_threads = opt_mining_threads;
                tune_reason = "user --threads override";
            } else {
                mine_threads = veld::DefaultMiningThreads(hw_threads);
                tune_reason = "auto-tuned (physical_cores - 1 for memory-hard hashing)";
            }
            node.SetMiningThreads(mine_threads);
            std::cout << GREEN << "  Mining ready; hashing starts after sync.\n" << RESET;
            if (veld::DiagVerbose().load())
                std::cout << "  Threads: " << mine_threads
                          << " of ~" << physical_est << " physical / "
                          << hw_threads << " logical (" << tune_reason << ")\n";
#ifdef VELD_REGTEST_FIXED_DIFF
            constexpr uint32_t mining_bits = 0x207fffff;
#else
            constexpr uint32_t mining_bits = 0;
#endif
            node.StartMining(miner_kp, mining_bits);
        } else if (opt_endorse) {
            // --endorse without --mine: validator endorse-only. Endorses
            // recent blocks as fee-paying mempool TXs (see the endorse loop
            // below) but never produces blocks and never builds the 1 GB
            // VeldHash dataset, so it stays light.
            std::cout << CYAN << "  [Endorse-only: endorsing blocks as a validator; mining disabled]\n" << RESET;
        } else {
            std::cout << CYAN
                      << "  [Regtest generation identity ready; background mining disabled]\n"
                      << RESET;
        }
    }

    // No startup path needs the vault passphrase after RPC/key material has
    // been decrypted.  This also covers non-mining fleet nodes, which used to
    // retain it for the entire process lifetime.
    veld::WipeString(g_passphrase);

    std::cout << "\n" << node.GetNodeInfo() << "\n";
    std::cout << GRAY << "  Press Ctrl+C to stop.\n" << RESET << "\n";

    std::thread heartbeat_thread([&]{
        while (!g_shutdown.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            if (g_shutdown.load()) break;
            std::time_t t = std::time(nullptr);
            if (veld::DiagVerbose().load()) veld::vcerr() << "  [hb] ts=" << t
                      << " height=" << node.GetChain().Height()
                      << " peers=" << node.ConnectedPeers()
                      << " mempool=" << node.GetMempool().Size()
                      << "\n";
            std::cerr.flush();
        }
    });
    heartbeat_thread.detach();

    uint64_t last_height          = 0;
    uint64_t stable_ticks         = 0;
    int      tick                 = 0;
    int64_t  last_seed_redial_ms  = 0;
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    uint64_t background_last_reported_height = UINT64_MAX;
#endif
    bool     fail_stop_exit = false;
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    bool     snapshot_verification_exit = false;
    bool     snapshot_activation_restart = false;
#endif
    bool     testnet_expiry_exit = false;

    bool force_update_present_at_start = false;
    if (!opt_datadir.empty()) {
        std::error_code _fu_ec;
        force_update_present_at_start =
            std::filesystem::exists(opt_datadir + "/.force-update", _fu_ec);
    }

    while (!g_shutdown) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        ++tick;

        if ((opt_mine || opt_endorse) && !opt_datadir.empty()) {
            auto peers = node.GetTCPServer()
                ? node.GetTCPServer()->GetPeerInfoList()
                : std::vector<veld::net::NodeServer::PeerInfo>{};
            std::sort(peers.begin(), peers.end(),
                      [](const auto& a, const auto& b) {
                          return a.addr < b.addr;
                      });
            const auto tip_snapshots = node.SnapshotPeerTips();
            std::unordered_map<std::string,
                const veld::net::NodeServer::PeerTipSnapshot*> tips_by_ip;
            tips_by_ip.reserve(tip_snapshots.size());
            for (const auto& peer_tip : tip_snapshots)
                tips_by_ip[peer_tip.ip] = &peer_tip;

            const uint64_t local_height = node.GetChain().Height();
            Hash256 local_tip{};
            bool have_local_tip = false;
            try {
                local_tip = node.GetChain().TipCopy().GetHash();
                have_local_tip = true;
            } catch (...) {}
            const int64_t now_seconds = static_cast<int64_t>(std::time(nullptr));

            std::ostringstream status;
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
            const bool snapshot_bootstrap_compiled = true;
            const bool snapshot_fast_start_eligible =
                node.SnapshotFastStartEligible();
#else
            const bool snapshot_bootstrap_compiled = false;
            const bool snapshot_fast_start_eligible = false;
#endif
            status << std::fixed << std::setprecision(2)
                   << "{\"mining_configured\":"
                   << (node.IsMiningConfigured() ? "true" : "false")
                   << ",\"mining_ready\":"
                   << (node.IsMiningReady() ? "true" : "false")
                   << ",\"mining_active\":"
                   << (node.IsMiningActive() ? "true" : "false")
                   << ",\"snapshot_bootstrap_compiled\":"
                   << (snapshot_bootstrap_compiled ? "true" : "false")
                   << ",\"snapshot_fast_start_eligible\":"
                   << (snapshot_fast_start_eligible ? "true" : "false")
                   << ",\"full_ibd\":"
                   << (node.IsFullIbd() ? "true" : "false")
                   << ",\"work_state\":\""
                   << node.GetMiningWorkStateName() << "\""
                   << ",\"hashrate\":" << node.GetHashrate()
                   << ",\"total_hashes\":" << node.GetTotalHashes()
                   << ",\"threads\":" << node.GetMiningThreads()
                   << ",\"blocks_mined_session\":"
                   << node.GetSessionBlocksMined()
                   << ",\"progress_counter\":"
                   << node.GetMiningProgressCounter()
                   << ",\"updated_at\":"
                   << static_cast<uint64_t>(std::time(nullptr))
                   << ",\"miner_address\":\"" << miner_kp.address
                   << "\",\"known_peer_count\":"
                   << (node.GetTCPServer()
                           ? node.GetTCPServer()->GetKnownPeerCount() : 0)
                   << ",\"topology_id\":"
                   << (node.GetTCPServer()
                           ? node.GetTCPServer()->TopologyId() : 0)
                   << ",\"topology_role\":\""
                   << (node.GetTCPServer()
                           ? node.GetTCPServer()->TopologyRole() : "node")
                   << "\""
                   << ",\"port_mapped\":"
                   << ((node.GetTCPServer() &&
                        node.GetTCPServer()->PortMapped()) ? "true" : "false")
                   << ",\"peer_details\":[";
            for (size_t peer_index = 0; peer_index < peers.size(); ++peer_index) {
                const auto& peer = peers[peer_index];
                const auto tip_it = tips_by_ip.find(peer.ip);
                const bool have_tip = tip_it != tips_by_ip.end();
                const uint64_t peer_height = have_tip
                    ? tip_it->second->height : 0;
                const int64_t peer_tip_age = have_tip
                    ? now_seconds - tip_it->second->updated_at : -1;
                const int64_t lag_blocks = have_tip
                    ? static_cast<int64_t>(local_height) -
                      static_cast<int64_t>(peer_height)
                    : 0;
                const bool exact_tip = have_tip && have_local_tip &&
                    peer_height == local_height &&
                    tip_it->second->hash == local_tip;
                if (peer_index != 0) status << ',';
                const bool peer_identified = peer.node_id != 0;
                const uint64_t topology_peer_id = peer_identified
                    ? peer.node_id : static_cast<uint64_t>(peer_index + 1);
                status << "{\"id\":" << topology_peer_id
                       << ",\"identified\":"
                       << (peer_identified ? "true" : "false")
                       << ",\"role_index\":" << peer.role_index
                       << ",\"inbound\":"
                       << (peer.inbound ? "true" : "false")
                       << ",\"role\":\"" << peer.role << "\""
                       << ",\"services\":" << peer.services
                       << ",\"exact_tip\":"
                       << (exact_tip ? "true" : "false")
                       << ",\"bytes_sent\":" << peer.bytes_sent
                       << ",\"bytes_recv\":" << peer.bytes_recv
                       << ",\"peer_height\":" << peer_height
                       << ",\"peer_tip_age_s\":" << peer_tip_age
                       << ",\"lag_blocks\":" << lag_blocks
                       << '}';
            }
            status << "]}";
            std::string status_error;
            (void)veld::channel::secure_file::AtomicWriteText(
                opt_datadir + "/gui-status.json", status.str(),
                &status_error, true);
        }

#ifdef VELD_PUBLIC_TESTNET
        if (node.PublicTestnetRuntimeStopRequired()) {
            std::cerr << "  [PUBLIC-TESTNET-EXPIRED] immutable START-index "
                         "not-after height/UTC reached; stopping "
                         "RPC/P2P/explorer/mining and exiting.\n";
            std::cerr.flush();
            testnet_expiry_exit = true;
            g_shutdown.store(true);
            break;
        }
#endif

        if (node.FailStopRequired()) {
            if (node.DurableCommitFailStop()) {
                std::cerr << "  [durable-commit] the authoritative DB tip is "
                             "durable but its in-memory durability marker was "
                             "not published; stopping RPC/P2P/mining for "
                             "mandatory restart replay repair.\n";
            } else {
                std::cerr << "  [anchor-floor] security persistence is uncertain; "
                             "stopping RPC/P2P/mining for mandatory replay repair.\n";
            }
            std::cerr.flush();
            fail_stop_exit = true;
            g_shutdown.store(true);
            break;
        }
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        if (node.SnapshotBackgroundVerificationFailed()) {
            std::cerr << "  [snapshot] mandatory background verification "
                         "failed; stopping every service and forcing a new "
                         "full IBD. Snapshot eligibility has been revoked.\n";
            std::cerr.flush();
            snapshot_verification_exit = true;
            g_shutdown.store(true);
            break;
        }

        if (background_chainstate && background_validation_base) {
            if (background_chainstate->FailStopRequired() ||
                background_chainstate->SnapshotBackgroundVerificationFailed()) {
                node.RejectIndependentBackgroundValidation(
                    "background-chainstate-runtime-failed");
                std::cerr << "  [snapshot] FATAL: independent background "
                             "chainstate entered fail-stop.\n";
                snapshot_verification_exit = true;
                g_shutdown.store(true);
                break;
            }

            const auto observation =
                background_chainstate->BackgroundValidationResult();
            if (observation.passed_target || observation.reached) {
                // Freeze peer ingest before comparing. A same-height reorg
                // arriving after the first target observation must not let a
                // stale, transient match retire snapshot trust.
                background_chainstate->Stop();
                VeldNode::BackgroundValidationObservation frozen;
                frozen.height =
                    background_chainstate->GetChain().Height();
                if (!background_chainstate->GetChain().IsEmpty()) {
                    frozen.tip_hash = background_chainstate->GetChain()
                                          .TipCopy().GetHash();
                }
                if (frozen.height == background_validation_base->height) {
                    frozen.state_digest =
                        background_chainstate->ConsensusStateDigest();
                    frozen.reached = true;
                } else {
                    frozen.passed_target = true;
                }
                std::string validation_error;
                if (!node.FinalizeIndependentBackgroundValidation(
                        frozen, &validation_error)) {
                    node.RejectIndependentBackgroundValidation(
                        "background-chainstate-mismatch");
                    std::cerr << "  [snapshot] FATAL: independent background "
                                 "chainstate comparison failed: "
                              << validation_error << "\n";
                    snapshot_verification_exit = true;
                    g_shutdown.store(true);
                    break;
                }
                background_chainstate.reset();
                background_validation_base.reset();
                std::cout << "  [background-ibd] independent reconstruction "
                             "matched the snapshot base; snapshot trust retired.\n";
                std::cout.flush();
                if (node.SnapshotQuarantineOnly()) {
                    const uint64_t validated_height = node.GetChain().Height();
                    std::string validated_tip;
                    try {
                        validated_tip = HashToHex(
                            node.GetChain().Tip().GetHash());
                    } catch (...) {
                        validated_tip.clear();
                    }
                    std::string receipt_error;
                    bool receipt_written = false;
#ifdef VELD_FLEET_NO_MINE
                    if (fleet_validation_key_ready) {
                        receipt_written =
                            snapshot_bootstrap::WriteFleetIbdReceipt(
                                opt_datadir, fleet_validation_kp,
                                validated_height, validated_tip,
                                &receipt_error);
                    }
#else
                    if (miner_key_ready) {
                        receipt_written =
                            snapshot_bootstrap::WriteFullIbdReceipt(
                                opt_datadir, miner_kp, validated_height,
                                validated_tip, &receipt_error);
                    }
#endif
                    if (!receipt_written) {
                        std::cerr << "  [snapshot] FATAL: independent IBD "
                                     "matched, but its authenticated restart "
                                     "receipt could not be persisted: "
                                  << (receipt_error.empty()
                                          ? "role identity is unavailable"
                                          : receipt_error)
                                  << "\n";
                        snapshot_verification_exit = true;
                        g_shutdown.store(true);
                        break;
                    }
                    full_ibd_receipt_valid = true;
                    full_ibd_receipt.height = validated_height;
                    full_ibd_receipt.tip_hash = validated_tip;
                    std::cout << "  [snapshot] independent validation complete; "
                                 "authenticated restart receipt persisted; "
                                 "restarting once to activate RPC, inbound P2P, "
                                 "explorer, and mining.\n";
                    std::cout.flush();
                    snapshot_activation_restart = true;
                    g_shutdown.store(true);
                    break;
                }
            } else {
                const uint64_t background_height =
                    background_chainstate->GetChain().Height();
                node.SetIndependentValidationProgress(background_height);
                if (background_height != background_last_reported_height &&
                    (background_height <= 10 ||
                     background_height % 100 == 0 || tick % 60 == 0)) {
                    background_last_reported_height = background_height;
                    std::cout << "  [background-ibd] verified "
                              << background_height << "/"
                              << background_validation_base->height
                              << " from genesis\n";
                    std::cout.flush();
                }
                if (tick % 30 == 0) {
                    for (const auto& peer : background_validation_peers) {
                        const auto colon = peer.rfind(':');
                        const std::string host = colon == std::string::npos
                            ? peer : peer.substr(0, colon);
                        uint16_t port = config.port;
                        if (colon != std::string::npos) {
                            try {
                                port = static_cast<uint16_t>(
                                    std::stoul(peer.substr(colon + 1)));
                            } catch (...) {
                                port = config.port;
                            }
                        }
                        background_chainstate->ConnectTo(host, port);
                    }
                }
            }
        }
#endif

        if ((tick % 3) == 0 && !opt_datadir.empty() && !force_update_present_at_start) {
            std::error_code _fu_ec;
            if (std::filesystem::exists(opt_datadir + "/.force-update", _fu_ec)) {
                std::cerr << "  [update] mandatory-update sentinel detected; "
                             "shutting down gracefully to install.\n";
                std::cerr.flush();
                g_shutdown.store(true);
                break;
            }
        }

        uint64_t cur_height = node.GetChain().Height();

        if (!opt_fleet_anchor_ips.empty() && (tick % 30) == 0) {
            for (size_t anchor_index = 0;
                 anchor_index < opt_fleet_anchor_ips.size(); ++anchor_index) {
                const auto& ip = opt_fleet_anchor_ips[anchor_index];
                if (!node.AddFleetAnchorIp(ip)) {
                    std::cerr << YEL << "  [network] WARN: " << RESET
                              << "Seed node " << (anchor_index + 1)
                              << " is temporarily unavailable; retrying";
                    if (veld::DiagVerbose().load())
                        std::cerr << " endpoint=" << ip << ":" << config.port;
                    std::cerr << "\n";
                }
            }
        }

        if (!opt_connect.empty()) {
            for (const auto& peer : opt_connect) {
                auto colon = peer.rfind(':');
                std::string host = (colon != std::string::npos) ? peer.substr(0, colon) : peer;
                uint16_t port = config.port;
                if (colon != std::string::npos) {
                    try { port = (uint16_t)std::stoi(peer.substr(colon+1)); }
                    catch (...) { port = config.port; }
                }
                std::string key = host + ":" + std::to_string(port);
                bool need_connect = !node.IsPeerConnected(key);
                if (need_connect) node.ConnectTo(host, port);
            }
        }

        // Re-dial the complete hardcoded seed set every 30 seconds, independent
        // of peer count. ConnectTo is idempotent, so connected seeds are no-ops
        // and dropped seeds reconnect. (The per-seed IsPeerConnected
        // skip was also broken — it keyed on hostname, not resolved IP.)
        if (opt_connect.empty() && !opt_regtest) {
            int64_t now_ms = (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            if (now_ms - last_seed_redial_ms >= 30000) {
                last_seed_redial_ms = now_ms;
                const auto seeds = opt_tor_only
                    ? veld::seeder::SeedNodeClient::GetTorBootstrap()
                    : veld::seeder::SeedNodeClient::GetHardcodedBootstrap();
                // Gate the log on how many SEEDS are actually connected, not on
                // total peer count. ConnectedPeers() counts inbound miners too,
                // so at scale (or with the PC miner inbound) it never drops below
                // seeds.size() even when a seed is genuinely down — masking the
                // signal. CountConnectedSeeds() resolves each seed and matches it
                // against connected peers in either direction, so simultaneous
                // cross-dials cannot turn a retained inbound leg into false
                // seed loss and repeated reconnect churn.
                size_t connected_seeds = node.CountConnectedSeeds(seeds);
                if (connected_seeds < seeds.size()) {
                    std::cout << "  [seed-watchdog] connected seeds=" << connected_seeds
                              << "/" << seeds.size() << " ("
                              << (seeds.size() - connected_seeds)
                              << " missing) — re-dialing dropped seed(s)\n";
                    std::cout.flush();
                }
                for (const auto& seed : seeds) {
                    const std::string key =
                        seed + ":" + std::to_string(config.port);
                    if (!node.IsPeerConnected(key))
                        node.ConnectTo(seed, config.port);
                }
            }
        }

        const auto peer_heights = node.GetPeerHeightView();
        const uint64_t verified_peer_height =
            peer_heights.verified_height;
        // Re-IBD follows the greater of locally verified peer evidence and the
        // conservative two-outbound-peer sync floor.
        const uint64_t peer_best = std::max(
            verified_peer_height, peer_heights.outbound_sync_height);
        // Isolation, a half-open TCP socket, and elapsed wall time are never
        // evidence of synchronization. Require a CURRENT connection that has
        // delivered a valid VERSION; a cumulative counter from a disconnected
        // peer cannot combine with a different half-open socket. The shared
        // policy also distinguishes an empty chain from validated genesis.
        bool at_tip = IsInitialDownloadAtTip(
            opt_regtest, cur_height, node.GetChain().IsEmpty(),
            peer_heights.distinct_version_ips, verified_peer_height,
            peer_heights.distinct_outbound_sync_ips,
            peer_heights.outbound_sync_height);

        if (at_tip && cur_height > 0) {
            auto tips = node.SnapshotPeerTips();
            int64_t now_s = (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            ::veld::Hash256 our_tip_hash{};
            try { our_tip_hash = node.GetChain().Tip().GetHash(); } catch (...) {}
            int agree = 0, disagree = 0, fresh_tips = 0;
            for (const auto& t : tips) {
                if (now_s - t.updated_at > 180) continue;
                if (::veld::HashIsZero(t.hash)) continue;
                ++fresh_tips;
                if (t.hash == our_tip_hash) {
                    ++agree;
                } else if (node.GetChain().GetBlockByHash(t.hash).has_value()) {
                    ++agree;
                } else {
                    ++disagree;
                }
            }
            if (fresh_tips >= 2 && disagree >= 1 && agree <= disagree) {
                at_tip = false;
            }
        }

        if (at_tip) {
            ++stable_ticks;
            if (stable_ticks >= 3 && !node.IsIBDComplete()) {
                node.SetIBDComplete(true);
                node.SyncTCPIBDFlag();
                // The verified VLF1 floor may reject completion. Only the
                // authoritative post-call state can unlock backfill or mining.
                if (node.IsIBDComplete()) {
                    node.TryBackfillFlushes();
#if defined(VELD_PUBLIC_MAINNET) && defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
                    bool receipt_role_ready = opt_mine;
#ifdef VELD_FLEET_NO_MINE
                    receipt_role_ready = fleet_validation_key_ready;
#endif
                    if (receipt_role_ready && node.ChainFullyValidated() &&
                        (!full_ibd_receipt_valid ||
                         cur_height > full_ibd_receipt.height)) {
                        const bool first_receipt = !full_ibd_receipt_valid;
                        std::string receipt_error;
                        std::string validated_tip;
                        try {
                            validated_tip = HashToHex(
                                node.GetChain().Tip().GetHash());
                        } catch (...) {
                            validated_tip.clear();
                        }
                        bool receipt_written = false;
#ifdef VELD_FLEET_NO_MINE
                        receipt_written =
                            snapshot_bootstrap::WriteFleetIbdReceipt(
                                opt_datadir, fleet_validation_kp, cur_height,
                                validated_tip, &receipt_error);
#else
                        receipt_written =
                            snapshot_bootstrap::WriteFullIbdReceipt(
                                opt_datadir, miner_kp, cur_height,
                                validated_tip, &receipt_error);
#endif
                        if (receipt_written) {
                            full_ibd_receipt_valid = true;
                            full_ibd_receipt.height = cur_height;
                            full_ibd_receipt.tip_hash = validated_tip;
#ifdef VELD_FLEET_NO_MINE
                            full_ibd_receipt.miner_address =
                                fleet_validation_kp.address;
#else
                            full_ibd_receipt.miner_address = miner_kp.address;
#endif
                            if (first_receipt) {
#ifdef VELD_FLEET_NO_MINE
                                std::cout << "  [snapshot] qualified fleet "
                                             "restart and explicit recovery "
                                             "are now unlocked for this "
                                             "datadir and genesis.\n";
#else
                                std::cout << "  [snapshot] future authenticated "
                                             "snapshot recovery is now unlocked for "
                                             "this genesis and miner identity.\n";
#endif
                            } else if (veld::DiagVerbose().load()) {
                                std::cout << "  [snapshot] full-IBD receipt refreshed "
                                             "through h=" << cur_height << ".\n";
                            }
                        } else {
                            std::cerr << "  [snapshot] WARN: full IBD completed, "
                                         "but its recovery receipt could not be "
                                         "persisted: "
                                      << receipt_error << "\n";
                        }
                    }
#endif
                    std::cout << "  [IBD complete] height=" << cur_height;
                    if (!node.ChainFullyValidated()) {
                        std::cout << ". Independent background IBD active; "
                                     "mining and endorsing paused.\n";
                    } else if (node.IsMining()) {
                        std::cout << ". Mining active.\n";
                    } else if (opt_endorse) {
                        std::cout << ". Endorsing active; mining disabled.\n";
                    } else {
                        std::cout << ". Mining disabled.\n";
                    }
                    std::cout.flush();
                } else {
                    // Retry after another stable observation without allowing
                    // an ever-growing counter or emitting a false completion.
                    stable_ticks = 2;
                }
            }
        } else {
            stable_ticks = 0;
        }

#if defined(VELD_PUBLIC_MAINNET) && defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        // Keep the signed local PoW cache close to the live tip without
        // rewriting it for every block. A restart therefore verifies at most a
        // small recent suffix, while the full-IBD anchor remains exact and
        // owner-bound. Any write failure leaves the older valid receipt intact.
        constexpr uint64_t FULL_IBD_RECEIPT_REFRESH_BLOCKS = 16;
        bool receipt_refresh_role_ready = opt_mine;
#ifdef VELD_FLEET_NO_MINE
        receipt_refresh_role_ready = fleet_validation_key_ready;
#endif
        const bool first_receipt_needed = !full_ibd_receipt_valid;
        const bool receipt_refresh_due =
            full_ibd_receipt_valid &&
            cur_height > full_ibd_receipt.height &&
            cur_height - full_ibd_receipt.height >=
                FULL_IBD_RECEIPT_REFRESH_BLOCKS &&
            (tick % 60) == 0;
        if (receipt_refresh_role_ready && at_tip && stable_ticks >= 3 &&
            node.IsIBDComplete() && node.ChainFullyValidated() &&
            (first_receipt_needed || receipt_refresh_due)) {
            std::string receipt_error;
            std::string validated_tip;
            try {
                validated_tip = HashToHex(node.GetChain().Tip().GetHash());
            } catch (...) {
                validated_tip.clear();
            }
            bool receipt_written = false;
#ifdef VELD_FLEET_NO_MINE
            receipt_written = snapshot_bootstrap::WriteFleetIbdReceipt(
                opt_datadir, fleet_validation_kp, cur_height,
                validated_tip, &receipt_error);
#else
            receipt_written = snapshot_bootstrap::WriteFullIbdReceipt(
                opt_datadir, miner_kp, cur_height,
                validated_tip, &receipt_error);
#endif
            if (receipt_written) {
                full_ibd_receipt_valid = true;
                full_ibd_receipt.height = cur_height;
                full_ibd_receipt.tip_hash = validated_tip;
#ifdef VELD_FLEET_NO_MINE
                full_ibd_receipt.miner_address =
                    fleet_validation_kp.address;
#else
                full_ibd_receipt.miner_address = miner_kp.address;
#endif
                if (first_receipt_needed) {
#ifdef VELD_FLEET_NO_MINE
                    std::cout << "  [snapshot] qualified fleet restart and "
                                 "explicit recovery are now unlocked for this "
                                 "datadir and genesis.\n";
#else
                    std::cout << "  [snapshot] future authenticated snapshot "
                                 "recovery is now unlocked for this genesis "
                                 "and miner identity.\n";
#endif
                } else if (veld::DiagVerbose().load()) {
                    std::cout << "  [snapshot] full-IBD receipt refreshed "
                                 "through h=" << cur_height << ".\n";
                }
            } else {
                std::cerr << "  [snapshot] WARN: verified-tip receipt refresh "
                             "failed; the prior receipt remains valid: "
                          << receipt_error << "\n";
            }
        }
#endif

        constexpr uint64_t STALE_TIP_TOLERANCE  = 1;
        constexpr int      STALE_TIP_GRACE_SECS = 30;
        static int stale_tip_secs = 0;
        if (node.IsIBDComplete()
            && peer_best > cur_height
            && peer_best - cur_height > STALE_TIP_TOLERANCE) {
            ++stale_tip_secs;
            if (stale_tip_secs >= STALE_TIP_GRACE_SECS) {
                std::cout << "  [re-IBD] peer tip=" << peer_best
                          << " ahead of ours=" << cur_height
                          << " for " << stale_tip_secs
                          << "s — re-entering IBD to catch up\n";
                std::cout.flush();
                node.SetIBDComplete(false);
                node.SyncTCPIBDFlag();
                stable_ticks = 0;
                stale_tip_secs = 0;
            }
        } else {
            stale_tip_secs = 0;
        }

        constexpr uint64_t DEEP_FORK_THRESHOLD =
            ::veld::MAX_REORG_DEPTH + 50;
        constexpr int DEEP_FORK_GRACE_SECS = 120;
        static int deep_fork_secs = 0;
        if (node.IsIBDComplete()
            && peer_best > cur_height
            && peer_best - cur_height > DEEP_FORK_THRESHOLD) {
            ++deep_fork_secs;
            if (deep_fork_secs % 30 == 0) {
                std::cerr << "  [deep-fork-watch] peer_best=" << peer_best
                          << " cur=" << cur_height
                          << " gap=" << (peer_best - cur_height)
                          << " (> MAX_REORG_DEPTH+50); "
#if defined(VELD_PUBLIC_TESTNET) || defined(VELD_PUBLIC_RELEASE) || \
    !defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
                          << "bounded full-IBD recovery in "
#else
                          << "offline recovery restart in "
#endif
                          << (DEEP_FORK_GRACE_SECS - deep_fork_secs) << "s\n";
                std::cerr.flush();
            }
            if (deep_fork_secs >= DEEP_FORK_GRACE_SECS) {
#if defined(VELD_PUBLIC_TESTNET) || defined(VELD_PUBLIC_RELEASE) || \
    !defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
                // Public profiles are compiled full-IBD-only and have no snapshot
                // namespace. Never persist a snapshot-recovery request that
                // the next startup is required to reject. Treat even a
                // quorum height claim as untrusted availability input: close
                // mining/admission, clear volatile catch-up state, and ask
                // connected peers for canonical blocks again. Repeated false
                // claims can keep this node safely in IBD, but cannot brick
                // its official datadir or manufacture a trusted snapshot.
                std::cerr << "  [deep-fork-watch] public-profile grace expired "
                          << "(cur=" << cur_height
                          << " peer_best=" << peer_best
                          << " gap=" << (peer_best - cur_height)
                          << "). Re-entering bounded full IBD; snapshot "
                             "recovery is unavailable.\n";
                std::cerr.flush();
                node.SetIBDComplete(false);
                node.SyncTCPIBDFlag();
                node.ClearRejectCache();
                node.ClearOrphanPool();
                node.TriggerTipReconcile();
                stable_ticks = 0;
                deep_fork_secs = 0;
#else
                std::cerr << "  [deep-fork-watch] grace expired "
                          << "(cur=" << cur_height
                          << " peer_best=" << peer_best
                          << " gap=" << (peer_best - cur_height)
                          << "). Requesting offline snapshot recovery and restart.\n";
                std::cerr.flush();
                if (!node.RequestSnapshotRecoveryOnRestart("deep-fork-watch")) {
                    std::cerr << "  [deep-fork-watch] FATAL: could not durably "
                              << "write recovery request; exiting fail-closed.\n";
                }
                std::cerr.flush();
                ::_exit(75);
#endif
            }
        } else {
            deep_fork_secs = 0;
        }

        constexpr int CHECKPOINT_REFRESH_INTERVAL_S = 300;
        static int checkpoint_refresh_secs = CHECKPOINT_REFRESH_INTERVAL_S;
        ++checkpoint_refresh_secs;
        if (checkpoint_refresh_secs >= CHECKPOINT_REFRESH_INTERVAL_S) {
            checkpoint_refresh_secs = 0;
            try { node.LoadCheckpointsFromUrl(); }
            catch (const std::exception& e) {
                std::cerr << "  [checkpoint-fetch] exception: " << e.what() << "\n";
                std::cerr.flush();
            } catch (...) {
                std::cerr << "  [checkpoint-fetch] unknown exception\n";
                std::cerr.flush();
            }
        }

        // (gap=49, well below the deep-fork threshold). Symptoms:
        //   * peer_best > cur_height for an extended period
        //   * cur_height does NOT change (chain not advancing)
        //   * no [AddBlock reject] logs (peer blocks aren't being
        //     attempted at all — orphan-pool / GETBLOCKS pipeline
        //     stalled in some intermediate state)
        // Standard re-IBD won't help (it's already in [sync] mode
        // when this happens) and Reorganize won't fire because it
        // requires AddBlockDirect to RECEIVE the alt-chain blocks
        // first.
        //
        // Detection: track our tip height across status ticks. If
        // peer_best > cur_height continuously for STUCK_GRACE_SECS
        // AND cur_height has not advanced during that window,
        // trigger snapshot recovery. The threshold is gap-agnostic —
        // a node that's not making progress while peers ARE is by
        // definition stuck, regardless of how big the gap is.
        constexpr int STUCK_GRACE_SECS = 300;
        constexpr int STUCK_HEIGHT_TOLERANCE = 0;
        static uint64_t stuck_anchor_height = UINT64_MAX;
        static int stuck_secs = 0;
        if (peer_best > cur_height && peer_best > 0) {
            if (stuck_anchor_height == UINT64_MAX) {
                stuck_anchor_height = cur_height;
                stuck_secs = 1;
            } else if (cur_height > stuck_anchor_height + STUCK_HEIGHT_TOLERANCE) {
                stuck_anchor_height = cur_height;
                stuck_secs = 1;
            } else {
                ++stuck_secs;
                if (stuck_secs % 60 == 0) {
                    std::cerr << "  [stuck-watch] cur=" << cur_height
                              << " peer_best=" << peer_best
                              << " gap=" << (peer_best - cur_height)
                              << " no-advance for " << stuck_secs
                              << "s; bounded peer recovery in "
                              << (STUCK_GRACE_SECS - stuck_secs) << "s\n";
                    std::cerr.flush();
                    node.TriggerTipReconcile();

                    if (stuck_secs == 180) {
                        size_t n = node.ClearRejectCache();
                        std::cerr << "  [stuck-watch] in-process recovery: cleared "
                                  << n << " reject-cache entries (escalation @180s)\n";
                        std::cerr.flush();
                    }
                    if (stuck_secs == 240) {
                        size_t n = node.ClearOrphanPool();
                        std::cerr << "  [stuck-watch] in-process recovery: cleared "
                                  << n << " orphan-pool entries (escalation @240s)\n";
                        std::cerr.flush();
                        node.TriggerTipReconcile();
                    }
                }
                if (stuck_secs >= STUCK_GRACE_SECS) {
                    uint64_t gap = (peer_best > cur_height)
                                 ? (peer_best - cur_height) : 0;
                    std::cerr << "  [stuck-watch] no chain advance for "
                              << stuck_secs << "s while peers advanced "
                              << "(cur=" << cur_height << " peer_best="
                              << peer_best << " gap=" << gap << ").\n";
                    std::cerr.flush();
                    const char* disable_restart = std::getenv("VELD_DISABLE_STUCK_RESTART");
                    bool restart_suppressed = disable_restart
                        && (*disable_restart == '1' || *disable_restart == 'y'
                            || *disable_restart == 'Y' || *disable_restart == 't'
                            || *disable_restart == 'T');
                    if (restart_suppressed) {
                        std::cerr << "  [stuck-watch] auto-restart suppressed by "
                                  << "VELD_DISABLE_STUCK_RESTART=1; manual "
                                  << "intervention required.\n";
                        std::cerr.flush();
                        stuck_secs = -STUCK_GRACE_SECS;
                    } else if (gap <= ::veld::MAX_REORG_DEPTH) {
                        std::cerr.flush();
                        ::_exit(75);
                    } else {
#if defined(VELD_PUBLIC_TESTNET) || defined(VELD_PUBLIC_RELEASE) || \
    !defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
                        // Public profiles are full-IBD-only. Writing the generic
                        // snapshot recovery marker here would make every later
                        // startup reject the same datadir. Recover only through
                        // canonical peer replay, without any durable snapshot
                        // request or restart loop.
                        std::cerr << "  [stuck-watch] public-profile deep gap: "
                                     "re-entering bounded full IBD; snapshot "
                                     "recovery is unavailable.\n";
                        std::cerr.flush();
                        node.SetIBDComplete(false);
                        node.SyncTCPIBDFlag();
                        node.ClearRejectCache();
                        node.ClearOrphanPool();
                        node.TriggerTipReconcile();
                        stable_ticks = 0;
                        stuck_anchor_height = cur_height;
                        stuck_secs = 0;
#else
                        if (!node.RequestSnapshotRecoveryOnRestart("stuck-watch")) {
                            std::cerr << "  [stuck-watch] FATAL: could not durably "
                                      << "write recovery request; exiting fail-closed.\n";
                        }
                        std::cerr.flush();
                        ::_exit(75);
#endif
                    }
                }
            }
        } else {
            stuck_anchor_height = UINT64_MAX;
            stuck_secs = 0;
        }

        // Detect sustained sibling-fork disagreement from fresh, locally
        // verified peer tips. Recovery is eligible only when peers are ahead;
        // cumulative work and full consensus validation select the branch.
        constexpr int DIVERGED_TIP_GRACE_SECS = 60;
        static int diverged_tip_secs = 0;
        // Sustained-divergence escalation state. The 60s re-IBD soft recovery
        // below assumes peers advertise a tip we can actually FETCH. When they
        // hold a tip we can't pull (an orphan they no longer serve, or a tip
        // stuck behind a dead/stale Tor circuit that keeps re-advertising it),
        // reconcile never converges and we sit diverged at the SAME height
        // indefinitely. The peer_best>cur_height stuck-watchdog can't catch that
        // (we are not behind), so track divergence-without-advance separately and
        // escalate: clear caches in-process, then hard-restart to drop stale
        // peer-tip records and re-handshake — the only thing that breaks the
        // deadlock when a peer keeps re-advertising a tip we cannot fetch.
        static uint64_t diverged_anchor_height = UINT64_MAX;
        static int diverged_stuck_secs = 0;
        if (node.IsIBDComplete() && cur_height > 0) {
            {
                auto tips = node.SnapshotPeerTips();
                int64_t now_s = (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                ::veld::Hash256 our_tip_hash{};
                try { our_tip_hash = node.GetChain().Tip().GetHash(); } catch (...) {}
                int agree = 0, disagree = 0, fresh_tips = 0;
                for (const auto& t : tips) {
                    if (now_s - t.updated_at > 180) continue;
                    if (::veld::HashIsZero(t.hash)) continue;
                    ++fresh_tips;
                    if (t.hash == our_tip_hash) {
                        ++agree;
                    } else if (node.GetChain().GetBlockByHash(t.hash).has_value()) {
                        ++agree;
                    } else {
                        ++disagree;
                    }
                }
                // Require at least two fresh observations and accept a tied or
                // larger disagreeing set. Equal-height miners continue working
                // so cumulative work can break the tie; re-IBD begins only when
                // the verified peer height is greater than the local height.
                if (fresh_tips >= 2 && disagree >= 1 && agree <= disagree
                    && peer_best > cur_height) {
                    ++diverged_tip_secs;
                    if (diverged_tip_secs >= DIVERGED_TIP_GRACE_SECS) {
                        std::cout << "  [diverged-tip] re-entering IBD ("
                                  << "agree=" << agree
                                  << " disagree=" << disagree
                                  << " fresh=" << fresh_tips << ")\n";
                        std::cout.flush();
                        node.SetIBDComplete(false);
                        node.SyncTCPIBDFlag();
                        node.TriggerTipReconcile();
                        stable_ticks = 0;
                        diverged_tip_secs = 0;
                    }
                    // ESCALATION when soft recovery can't converge. Anchor on our
                    // height: any real advance means we ARE making progress (a
                    // normal reorg resolving), so reset. Only sustained divergence
                    // with NO height advance is the dead wedge.
                    if (diverged_anchor_height == UINT64_MAX
                        || cur_height > diverged_anchor_height) {
                        diverged_anchor_height = cur_height;
                        diverged_stuck_secs = 1;
                    } else {
                        ++diverged_stuck_secs;
                        if (diverged_stuck_secs == 180) {
                            size_t r = node.ClearRejectCache();
                            size_t o = node.ClearOrphanPool();
                            std::cerr << "  [diverged-tip] in-process recovery @180s:"
                                      << " cleared " << r << " reject + " << o
                                      << " orphan entries; reconciling.\n";
                            std::cerr.flush();
                            node.TriggerTipReconcile();
                        }
                        if (diverged_stuck_secs >= STUCK_GRACE_SECS) {
                            std::cerr << "  [diverged-tip] no advance for "
                                      << diverged_stuck_secs << "s while peers hold a"
                                      << " tip we can't fetch (cur=" << cur_height
                                      << " agree=" << agree << " disagree="
                                      << disagree << "). Restarting to resync.\n";
                            std::cerr.flush();
                            const char* disable_restart =
                                std::getenv("VELD_DISABLE_STUCK_RESTART");
                            bool restart_suppressed = disable_restart
                                && (*disable_restart == '1' || *disable_restart == 'y'
                                    || *disable_restart == 'Y' || *disable_restart == 't'
                                    || *disable_restart == 'T');
                            if (restart_suppressed) {
                                std::cerr << "  [diverged-tip] auto-restart suppressed"
                                          << " by VELD_DISABLE_STUCK_RESTART=1; manual"
                                          << " intervention required.\n";
                                std::cerr.flush();
                                diverged_stuck_secs = -STUCK_GRACE_SECS;
                            } else {
                                std::cerr.flush();
                                ::_exit(75);
                            }
                        }
                    }
                } else {
                    diverged_tip_secs = 0;
                    diverged_anchor_height = UINT64_MAX;
                    diverged_stuck_secs = 0;
                }
            }
        } else {
            diverged_tip_secs = 0;
        }

        static uint64_t last_endorsed_height = 0;
        static std::vector<std::pair<Secp256k1PrivKey, std::string>> endorser_keys;
        static bool endorser_keys_loaded = false;
        if (!endorser_keys_loaded) {
            endorser_keys_loaded = true;
            {
                std::string pk_hex;
                static const char* hx = "0123456789abcdef";
                for (int i = 0; i < 1952; ++i) {
                    pk_hex += hx[(miner_kp.public_key[i]>>4)&0xF];
                    pk_hex += hx[miner_kp.public_key[i]&0xF];
                }
                endorser_keys.push_back({miner_kp.private_key, pk_hex});
            }
            // Mining uses miner.key for endorsements. An optional second
            // identity must be supplied explicitly through
            // VELD_EXTRA_ENDORSER_KEY; the datadir is never searched for
            // additional signing keys.
            {
                const char* extra_key_path = std::getenv("VELD_EXTRA_ENDORSER_KEY");
                if (extra_key_path && extra_key_path[0]) {
                    bool extra_optional = false;
                    if (const char* opt = std::getenv("VELD_EXTRA_ENDORSER_KEY_OPTIONAL")) {
                        extra_optional = (opt[0] == '1' || opt[0] == 't' || opt[0] == 'T');
                    }
                    std::cout << "  [validator] VELD_EXTRA_ENDORSER_KEY set: " << extra_key_path << "\n";
                    if (_wiz_is_encrypted(extra_key_path)) {
                        std::string pass = _wiz_ask_passphrase();
                        if (g_shutdown.load()) return 0;
                        RealKeyPair extra_kp;
                        if (_wiz_load_key_encrypted(
                                extra_key_path, pass, extra_kp, config.IsTestNetwork())) {
                            std::string wpk_hex;
                            static const char* hx = "0123456789abcdef";
                            for (int i = 0; i < 1952; ++i) {
                                wpk_hex += hx[(extra_kp.public_key[i]>>4)&0xF];
                                wpk_hex += hx[extra_kp.public_key[i]&0xF];
                            }
                            endorser_keys.push_back({extra_kp.private_key, wpk_hex});
                            std::cout << "  [validator] Loaded extra endorser key " << extra_kp.address << "\n";
                        } else {
                            std::cerr << RED << "  [validator] FATAL: failed to decrypt extra endorser key — wrong passphrase?" << RESET << "\n";
                            veld::WipeString(pass);
                            if (!extra_optional) {
                                std::cerr << RED << "  [validator] Set VELD_EXTRA_ENDORSER_KEY_OPTIONAL=1 to tolerate this and continue without the extra key." << RESET << "\n";
                                return 1;
                            }
                        }
                        veld::WipeString(pass);
                    } else {
                        std::cerr << RED << "  [validator] FATAL: VELD_EXTRA_ENDORSER_KEY must point to an ENCRYPTED key file. Refusing to load plaintext key." << RESET << "\n";
                        if (!extra_optional) return 1;
                    }
                }
            }
            if (veld::DiagVerbose().load()) {
                for (auto& [epriv, epub] : endorser_keys) {
                    (void)epriv;
                    std::string preview = epub.size() >= 32
                        ? (epub.substr(0, 16) + "..." + epub.substr(epub.size() - 16))
                        : epub;
                    bool reg = node.GetValidators().IsRegistered(epub);
                    std::string addr = "(invalid pubkey hex)";
                    if (epub.size() == 3904) {
                        auto bytes = HexToBytes(epub);
                        if (bytes.size() == 1952) {
                            Secp256k1PubKey tmp_pub;
                            std::copy(bytes.begin(), bytes.end(), tmp_pub.begin());
                            addr = PubKeyToAddress(tmp_pub, false);
                        }
                    }
                    std::cout << "  [validator] address=" << addr
                              << " pubkey=" << preview
                              << " registered=" << (reg ? "yes" : "no") << "\n";
                }
                std::cout.flush();
            }
        }
        if ((opt_mine || opt_endorse) &&
            cur_height > last_endorsed_height + 1 && cur_height > 2 &&
            node.IsIBDComplete() && node.ChainFullyValidated()) {
            static uint64_t last_diag_height = 0;
            bool log_this_round = (cur_height != last_diag_height);
            last_diag_height = cur_height;

            constexpr uint64_t ENDORSE_WINDOW_BLOCKS = 10;
            constexpr uint64_t PRUNE_HEIGHT_LOOKBACK = 100;
            constexpr uint64_t MIN_RETRY_INTERVAL_SEC = 90;
            static std::unordered_map<std::string, uint64_t> local_attempt_ts_;
            static std::mutex local_attempt_ts_mu_;
            //  persistent per-(height,pubkey) anti-equivocation record.
            static EndorseAntiEquivGuard endorse_guard_;
            static std::once_flag endorse_guard_init_;
            std::call_once(endorse_guard_init_, [&]{
                endorse_guard_.load(opt_datadir + "/endorsed_heights.dat");
            });
            const uint64_t now_sec = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            uint64_t end_h = cur_height - 1;
            uint64_t start_h = (end_h > ENDORSE_WINDOW_BLOCKS)
                               ? end_h - ENDORSE_WINDOW_BLOCKS + 1 : 1;
            {
                std::lock_guard<std::mutex> lk(local_attempt_ts_mu_);
                uint64_t prune_below = (cur_height > PRUNE_HEIGHT_LOOKBACK)
                                       ? cur_height - PRUNE_HEIGHT_LOOKBACK : 0;
                for (auto it = local_attempt_ts_.begin(); it != local_attempt_ts_.end(); ) {
                    size_t colon = it->first.find(':');
                    if (colon == std::string::npos) { it = local_attempt_ts_.erase(it); continue; }
                    uint64_t h = 0;
                    try { h = std::stoull(it->first.substr(0, colon)); } catch (...) { h = 0; }
                    if (h < prune_below) it = local_attempt_ts_.erase(it);
                    else ++it;
                }
            }

            int total_endorsed = 0;
            int total_unregistered = 0, total_already = 0, total_no_coins = 0,
                total_mp_reject = 0;
            const char* last_mp_reject = "";
            std::vector<uint64_t> endorsed_heights;

            for (uint64_t eh = start_h; eh <= end_h; ++eh) {
                Block eblk = node.GetChain().GetBlock(eh);
                Hash256 ehash = eblk.GetHash();
                std::string ehash_hex = HashToHex(ehash);
                auto existing = node.GetValidators().GetEndorsements(eh);
                int round_endorsed = 0;
                for (auto& [epriv, epub] : endorser_keys) {
                    if (!node.GetValidators().IsRegistered(epub)) { ++total_unregistered; continue; }
                    bool already = false;
                    for (auto& e : existing) if (e.pubkey_hex == epub) { already = true; break; }
                    if (already) { ++total_already; continue; }

                    std::string attempt_key = std::to_string(eh) + ":"
                                            + epub.substr(0, 32) + ":"
                                            + ehash_hex.substr(0, 16);
                    {
                        std::lock_guard<std::mutex> lk(local_attempt_ts_mu_);
                        auto it = local_attempt_ts_.find(attempt_key);
                        if (it != local_attempt_ts_.end() &&
                            now_sec - it->second < MIN_RETRY_INTERVAL_SEC) {
                            ++total_already;
                            continue;
                        }
                    }

                    // Bind this validator operation to the exact canonical
                    // target, current tip, network/profile, and validation
                    // generation before creating any durable or signed work.
                    work_admission::Subject endorse_subject;
                    {
                        Block current_tip;
                        if (!node.GetChain().TryTip(current_tip)) {
                            ++total_mp_reject;
                            last_mp_reject = "WORK_ADMISSION_TIP";
                            continue;
                        }
                        endorse_subject.purpose =
                            work_admission::Purpose::ValidatorEndorsement;
                        endorse_subject.height = eh;
                        endorse_subject.target_hash = ehash;
                        endorse_subject.parent_height = current_tip.height;
                        endorse_subject.parent_hash = current_tip.GetHash();
                    }
                    auto endorsement_permit =
                        node.AcquireLocalValidatorEndorsementPermit(
                            endorse_subject);
                    if (!endorsement_permit) {
                        ++total_mp_reject;
                        last_mp_reject = "WORK_ADMISSION_CLOSED";
                        continue;
                    }

                    //  persistent anti-equivocation guard. Refuse to
                    // sign height `eh` if we already signed a DIFFERENT block
                    // hash there (reorg changed the canonical block) — that pair
                    // is slashable equivocation. Record the hash (fsync) BEFORE
                    // signing so a crash can only lose this endorsement, never
                    // create an equivocating second one. Same-hash re-sign is OK.
                    {
                        std::string eq_key = std::to_string(eh) + ":" + epub;
                        if (endorse_guard_.would_equivocate(eq_key, ehash_hex)) {
                            ++total_already;
                            if (log_this_round) {
                                std::cerr << "  [endorse] SKIP h=" << eh
                                          << " — already endorsed a different block hash here "
                                          << "(reorg); refusing to equivocate (would be slashable).\n";
                                std::cerr.flush();
                            }
                            continue;
                        }
                        if (!endorse_guard_.record(eq_key, ehash_hex)) {
                            ++total_mp_reject;
                            last_mp_reject = "ENDORSE_JOURNAL_IO";
                            if (log_this_round) {
                                std::cerr << "  [endorse] REFUSE h=" << eh
                                          << " — anti-equivocation journal could not "
                                             "durably record this vote (or records a "
                                             "conflict); no signature produced.\n";
                                std::cerr.flush();
                            }
                            continue;
                        }
                    }

                    // The journal write above can include an fsync. Recheck
                    // the exact authorization immediately before producing
                    // the validator signature.
                    if (!endorsement_permit->IsLive()) {
                        ++total_mp_reject;
                        last_mp_reject = "WORK_ADMISSION_STALE";
                        continue;
                    }

                    // Build endorsement as a proper fee-paying mempool TX (NOT coinbase-embedded)
                    // This ensures endorsements go through the mempool like any other TX,
                    // preventing miner censorship of validator endorsements.
                    RealKeyPair ekp;
                    ekp.private_key = epriv;
                    ekp.public_key = DerivePublicKey(epriv);
                    ekp.address = PubKeyToAddress(ekp.public_key, false);
                    auto ekp_script = ekp.GetP2PKHScript();

                    Hash256 emsg = ValidatorRegistry::BuildEndorseMessage(eh, ehash);
                    if (!endorsement_permit->IsLive()) {
                        ++total_mp_reject;
                        last_mp_reject = "WORK_ADMISSION_STALE";
                        continue;
                    }
                    auto esig = Sign(epriv, emsg);
                    std::string eop = ValidatorRegistry::BuildEndorseOp(eh, HashToHex(ehash), BytesToHex(esig));

                    std::vector<uint8_t> eop_bytes(eop.begin(), eop.end());
                    std::vector<uint8_t> eop_script;
                    eop_script.push_back(0x6A);
                    if (eop_bytes.size() <= 75) {
                        eop_script.push_back((uint8_t)eop_bytes.size());
                    } else if (eop_bytes.size() <= 255) {
                        eop_script.push_back(0x4C); eop_script.push_back((uint8_t)eop_bytes.size());
                    } else {
                        eop_script.push_back(0x4D);
                        eop_script.push_back((uint8_t)(eop_bytes.size() & 0xFF));
                        eop_script.push_back((uint8_t)((eop_bytes.size() >> 8) & 0xFF));
                    }
                    eop_script.insert(eop_script.end(), eop_bytes.begin(), eop_bytes.end());

                    uint64_t fee = MIN_TX_FEE;
                    auto coins = SelectCoins(node.GetChain(), ekp_script, 0, fee, node.GetMempoolMut().GetSpentOutputs());
                    if (!coins.sufficient) {
                        coins = SelectCoins(node.GetChain(), miner_kp.GetP2PKHScript(), 0, fee, node.GetMempool().GetSpentOutputs());
                        if (coins.sufficient) ekp_script = miner_kp.GetP2PKHScript();
                    }
                    if (!coins.sufficient) {
                        // Fail closed.  Endorsements must be funded and signed
                        // like every other non-coinbase transaction.  The old
                        // fallback queued an extra coinbase-like OP_RETURN tx;
                        // a local skip-validation commit accepted it while all
                        // peers correctly rejected it and forked the miner.
                        ++total_no_coins;
                        {
                            std::lock_guard<std::mutex> lk(local_attempt_ts_mu_);
                            local_attempt_ts_[attempt_key] = now_sec;
                        }
                        continue;
                    }

                    Transaction tx;
                    for (auto& utxo : coins.selected_utxos) {
                        TxInput inp; inp.prev_tx_hash = utxo.tx_hash; inp.prev_out_index = utxo.output_index;
                        tx.inputs.push_back(inp);
                    }
                    if (coins.change_amount > 0) tx.outputs.push_back(TxOutput(coins.change_amount, ekp_script));
                    tx.outputs.push_back(TxOutput(0, eop_script));
                    RealKeyPair& sign_kp = (ekp_script == miner_kp.GetP2PKHScript()) ? miner_kp : ekp;
                    if (!endorsement_permit->IsLive()) {
                        ++total_mp_reject;
                        last_mp_reject = "WORK_ADMISSION_STALE";
                        continue;
                    }
                    for (uint32_t i = 0; i < (uint32_t)tx.inputs.size(); ++i) {
                        auto si = sign_kp.SignInput(tx, i, ekp_script);
                        tx.inputs[i].script_sig = si.script_sig;
                    }
                    // Submission must consume the same authorization issued
                    // before signing; a new tip or validation generation makes
                    // it stale and the signed bytes are discarded, never queued.
                    if (!endorsement_permit->IsLive()) {
                        ++total_mp_reject;
                        last_mp_reject = "WORK_ADMISSION_STALE";
                        continue;
                    }
                    const auto sink =
                        node.SubmitLocalValidatorEndorsement(
                            tx, fee, std::move(*endorsement_permit));
                    if (sink.accepted) {
                        round_endorsed++;
                        {
                            std::lock_guard<std::mutex> lk(local_attempt_ts_mu_);
                            local_attempt_ts_[attempt_key] = now_sec;
                        }
                    } else if (sink.reason == "duplicate") {
                        {
                            std::lock_guard<std::mutex> lk(local_attempt_ts_mu_);
                            local_attempt_ts_[attempt_key] = now_sec;
                        }
                    } else {
                        ++total_mp_reject;
                        last_mp_reject = sink.deferred
                            ? "WORK_ADMISSION_DEFERRED"
                            : "INVALID";
                    }
                }
                if (round_endorsed > 0) {
                    total_endorsed += round_endorsed;
                    endorsed_heights.push_back(eh);
                }
            }
            if (total_endorsed > 0) {
                last_endorsed_height = end_h;
                std::cout << "  [endorse]";
                if (endorsed_heights.size() == 1) {
                    std::cout << " block " << endorsed_heights[0];
                } else {
                    std::cout << " heights=";
                    for (size_t i = 0; i < endorsed_heights.size(); ++i) {
                        if (i) std::cout << ",";
                        std::cout << endorsed_heights[i];
                    }
                }
                std::cout << " (" << total_endorsed << " emit"
                          << (total_endorsed > 1 ? "s)" : ")")
                          << "\n";
                std::cout.flush();
            } else if (log_this_round) {
                if (veld::DiagVerbose().load()) veld::vcerr() << "  [endorse-diag] window=" << start_h << "-" << end_h
                          << " keys=" << endorser_keys.size()
                          << " unregistered=" << total_unregistered
                          << " already=" << total_already
                          << " no-coins=" << total_no_coins
                          << " mp-reject=" << total_mp_reject
                          << (total_mp_reject ? std::string("(") + last_mp_reject + ")" : std::string(""))
                          << "\n";
                std::cerr.flush();
            }
        }

        if (node.IsIBDComplete() && opt_mine && node.ForkSuspected()) {
            node.TriggerForkRecovery();
        }

        node.BroadcastSupervisorTick();

        if (node.IsIBDComplete() && tick > 0 && tick % 60 == 0) {
            node.TriggerTipReconcile();
        }

        if (tick > 0 && tick % 30 == 0) {
            // Mempool validity can change on a reorg or when a parent disappears,
            // even if no new local block is committed.  Periodic cleanup keeps a
            // stale orphan from being advertised forever by every fleet seed.
            size_t stale_mp = node.GetMempoolMut().RemoveStale(node.GetChain());
            size_t orphan_mp = node.GetMempoolMut().SweepOrphans(node.GetChain());
            size_t expired_mp = node.GetMempoolMut().ExpireOld();
            if (stale_mp + orphan_mp + expired_mp > 0) {
                std::cerr << "  [mempool-maint] removed stale=" << stale_mp
                          << " orphan=" << orphan_mp
                          << " expired=" << expired_mp << "\n";
                std::cerr.flush();
            }
            node.BroadcastTipsig();
            node.ReapStuckHandshakes();
            node.ReapIdlePeers();
            node.BroadcastStatsig();
        }

        if (node.IsIBDComplete() && tick > 0 && tick % 300 == 0) {
            node.OracleSyncCheck();
        }

        if (node.IsIBDComplete() && tick > 60 && (tick - 60) % 300 == 0) {
            node.PersistPeerTipsCache();
        }

        if (node.IsIBDComplete() && tick > 120 && (tick - 120) % 300 == 0) {
            node.PersistPeerCache();
        }
        if (node.IsIBDComplete() && tick > 180 && (tick - 180) % 300 == 0) {
            node.PersistAnchors();
        }

        //  // Hour-cadence outbound peer rotation. Closes one random
        // non-trusted non-anchor outbound peer and dials a replacement
        // from the known-peer address book. Without rotation, an
        // attacker who seats 8 outbound peers at startup holds the
        // eclipse forever; with rotation, the eclipse decays one
        // peer per cycle as the organic address book swaps attackers
        // out for honest peers.
        //
        // Per-process jitter offset: the rotation_offset_s value is
        // sampled once at startup from the process's monotonic clock
        // — different fleet hosts pick different offsets, so the
        // entire fleet does NOT rotate simultaneously (which would
        // create a brief network-wide outbound-peer churn window).
        // Even if every host picked the same offset, the only effect
        // would be a momentary mesh disturbance — there is no
        // consensus dependency on rotation timing.
        //
        // Gated on IBD-complete: rotating an outbound peer mid-IBD
        // is counterproductive (we're still depending on that peer
        // for blocks). Post-IBD, the mesh is settled and rotation
        // gives us organic eclipse-defense churn.
        static const uint32_t rotation_offset_s =
            (uint32_t)((std::chrono::steady_clock::now().time_since_epoch().count()
                        / 1000000000ULL) % 3600);
        if (node.IsIBDComplete()
            && tick > (long long)rotation_offset_s
            && ((long long)tick - (long long)rotation_offset_s) % 3600 == 0) {
            node.RotateOutboundPeers();
        }

        // Drive NAT hole-punch every ~30s (no-op unless --reachable +
        // not already reachable via port-mapping). Self-gated in HolePunchTick.
        if (opt_reachable && (tick % 30 == 0) && node.GetTCPServer()) {
            node.GetTCPServer()->HolePunchTick();
        }
        if ((opt_tor || opt_tor_only) && (tick % 30 == 0) && node.GetTCPServer()) {
            node.GetTCPServer()->TorTick();
        }

        if (cur_height != last_height) {
            last_height = cur_height;
            PrintStatus(node, miner_kp.address, opt_mine, opt_endorse);
        } else if (tick % 10 == 0) {
            PrintStatus(node, miner_kp.address, opt_mine, opt_endorse);
        }
    }

    std::cout << "\n  Shutting down...\n" << std::flush;
    auto shutdown_start = std::chrono::steady_clock::now();
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    const int shutdown_exit_code = testnet_expiry_exit ? 78 :
                                   (snapshot_activation_restart ? 75 :
                                   (snapshot_verification_exit ? 76 :
                                   (fail_stop_exit ? 75 : 0)));
#else
    const int shutdown_exit_code = testnet_expiry_exit ? 78 :
                                   (fail_stop_exit ? 75 : 0);
#endif

    constexpr int SHUTDOWN_DEADLINE_SEC = 20;
    std::thread watchdog([shutdown_start, SHUTDOWN_DEADLINE_SEC,
                          shutdown_exit_code]() {
        std::this_thread::sleep_for(std::chrono::seconds(SHUTDOWN_DEADLINE_SEC));
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - shutdown_start).count();
        std::cerr << "\n  [shutdown-watchdog] Stop() did not return in "
                  << elapsed << "s — force-exiting (LevelDB WAL is durable,\n"
                     "  see leveldb.h CommitBlock sync=true batches).\n";
        std::cerr.flush();
        ::_exit(shutdown_exit_code);
    });
    watchdog.detach();

    if (rpc_http_owned) rpc_http_owned->Stop();
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    if (background_chainstate) background_chainstate->Stop();
#endif
    node.Stop();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - shutdown_start).count();
    std::cout << "  Done in " << elapsed << "ms.\n\n";
    return shutdown_exit_code;
}
