#if defined(VELD_PUBLIC_TESTNET)
#error "PUBLIC TESTNET forbids standalone veld-validator; use veld-node --endorse"
#endif

#include "../include/core/constants.h"
#include "../include/core/version.h"
#include "../include/core/hash.h"
#include "../include/crypto/ripemd160.h"
#include "../include/crypto/veld_signing.h"
#include "../include/core/script.h"
#include "../include/consensus/validators.h"
#include "../include/consensus/finality_daemon.h"
#include "../include/consensus/finality_codec.h"
#include "../include/consensus/btcveld_anchor_params.h"
#include "../include/wallet/wallet.h"
#include "../include/wallet/wallet_crypto.h"
#include "../include/wallet/passphrase_policy.h"
#include "../include/wallet/secure_channel_file.h"
#include "../include/compat/platform.h"
#include "../include/compat/process.h"
#include "../include/compat/endorse_guard.h" //  shared anti-equivocation guard
#include "../include/network/strict_json.h"
#include "../include/network/finality_rpc_limits.h"
#include "../include/node/work_admission.h"
#include "../include/node/work_admission_coordinator.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <csignal>
#include <atomic>
#include <iomanip>
#include <cstring>
#include <filesystem>
#include <functional>
#include <set>
#include <memory>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#define CLOSE_SOCK(s) closesocket(s)
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/mman.h>
#include <cerrno>
#define CLOSE_SOCK(s) close(s)
#endif

using namespace veld;

static const char* GRN = "\033[32m";
static const char* RED = "\033[31m";
static const char* YEL = "\033[33m";
static const char* CYN = "\033[36m";
static const char* GRAY = "\033[90m";
static const char* RST = "\033[0m";

static std::atomic<bool> g_running{true};
static std::string g_rpc_token;
static std::string g_datadir{"./veld-data"};
static std::string g_node_binary{"veld-node"};
static std::string g_bitcoin_cli{"bitcoin-cli"};

void handle_signal(int) {
    g_running = false;
}

static std::string now_str() {
    auto t = std::time(nullptr);
    char buf[20];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&t));
    return buf;
}

static void log(const char* color, const std::string& msg) {
    std::cout << GRAY << "[" << now_str() << "] " << RST << color << msg << RST << "\n"
              << std::flush;
}

static std::string rpc_call(const std::string& host, uint16_t port, const std::string& body,
                            size_t max_response_bytes = veld::btc_buy::kMaxExplorerResponseBytes) {
    if (host != "127.0.0.1")
        throw std::runtime_error("authenticated validator RPC is restricted to 127.0.0.1");
    if (g_rpc_token.size() != 64)
        throw std::runtime_error("RPC token is unavailable");
    struct sockaddr_in rpc_addr{};
    rpc_addr.sin_family = AF_INET;
    rpc_addr.sin_port = htons(port);
    rpc_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    veld::compat::SocketHandle fd = socket(AF_INET, SOCK_STREAM, 0);
    if (!veld::compat::IsValidSocket(fd)) {
        throw std::runtime_error("socket() failed");
    }

#ifdef _WIN32
    DWORD tv = 5000;
#else
    struct timeval tv{5, 0};
#endif
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));

    if (connect(fd, reinterpret_cast<struct sockaddr*>(&rpc_addr), sizeof(rpc_addr)) != 0) {
        CLOSE_SOCK(fd);
        throw std::runtime_error("Cannot connect to node at " + host + ":" + std::to_string(port));
    }

    std::string req = "POST / HTTP/1.0\r\n"
                      "Host: " +
                      host +
                      "\r\n"
                      "Content-Type: application/json\r\n";
    req += "Authorization: Bearer " + g_rpc_token + "\r\n";
    req += "Content-Length: " + std::to_string(body.size()) +
           "\r\n"
           "Connection: close\r\n\r\n" +
           body;

    size_t sent = 0;
    while (sent < req.size()) {
        int wrote =
            send(fd, req.data() + sent,
                 static_cast<int>(std::min<size_t>(req.size() - sent, 1U << 20)), MSG_NOSIGNAL);
        if (wrote <= 0) {
            CLOSE_SOCK(fd);
            throw std::runtime_error("RPC send failed");
        }
        sent += static_cast<size_t>(wrote);
    }

    std::string response;
    char buf[4096];
    int n;
    while ((n = recv(fd, buf, sizeof(buf) - 1, 0)) > 0) {
        if (!veld::finality::rpc_limits::AppendBoundedResponse(
                response, buf, static_cast<size_t>(n), max_response_bytes)) {
            CLOSE_SOCK(fd);
            throw std::runtime_error("RPC response exceeds method-specific policy");
        }
    }
    CLOSE_SOCK(fd);

    if (response.rfind("HTTP/1.1 200 ", 0) != 0 && response.rfind("HTTP/1.0 200 ", 0) != 0)
        throw std::runtime_error("RPC returned a non-200 HTTP status");
    auto pos = response.find("\r\n\r\n");
    if (pos == std::string::npos)
        throw std::runtime_error("malformed RPC HTTP response");
    std::string http_body = response.substr(pos + 4);

    bool chunked = response.find("Transfer-Encoding: chunked") != std::string::npos ||
                   response.find("transfer-encoding: chunked") != std::string::npos;
    if (!chunked)
        return http_body;

    std::string decoded;
    size_t p = 0;
    while (p < http_body.size()) {
        auto crlf = http_body.find("\r\n", p);
        if (crlf == std::string::npos)
            break;
        size_t chunk_size = 0;
        try {
            chunk_size = std::stoul(http_body.substr(p, crlf - p), nullptr, 16);
        } catch (...) {
            break;
        }
        if (chunk_size == 0)
            break;
        p = crlf + 2;
        if (p + chunk_size > http_body.size())
            break;
        decoded += http_body.substr(p, chunk_size);
        p += chunk_size + 2;
    }
    return decoded.empty() ? http_body : decoded;
}

static std::string json_rpc(const std::string& host, uint16_t port, const std::string& method,
                            const std::string& params = "[]") {
    std::string body = "{\"jsonrpc\":\"2.0\",\"id\":\"val1\","
                       "\"method\":\"" +
                       method +
                       "\","
                       "\"params\":" +
                       params + "}";
    const auto policy = veld::finality::rpc_limits::PolicyForMethod(method);
    return rpc_call(host, port, body, policy.max_http_response_bytes);
}

static std::string jstr(const std::string& json, const std::string& key) {
    auto pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos)
        return "";
    pos = json.find(":", pos);
    if (pos == std::string::npos)
        return "";
    pos++;
    while (pos < json.size() && json[pos] == ' ')
        pos++;
    if (pos >= json.size())
        return "";
    if (json[pos] == '"') {
        pos++;
        auto end = json.find('"', pos);
        return end == std::string::npos ? "" : json.substr(pos, end - pos);
    }
    auto end = json.find_first_of(",}\n", pos);
    std::string val = json.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
    while (!val.empty() && (val.back() == ' ' || val.back() == '\r'))
        val.pop_back();
    return val;
}

static uint64_t juint(const std::string& json, const std::string& key) {
    auto s = jstr(json, key);
    if (s.empty())
        return 0;
    try {
        return std::stoull(s);
    } catch (...) {
        return 0;
    }
}

static std::string bytes_to_hex(const uint8_t* data, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::string out(len * 2, '0');
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[data[i] >> 4];
        out[i * 2 + 1] = hex[data[i] & 0xF];
    }
    return out;
}

template <size_t N> static std::string to_hex(const std::array<uint8_t, N>& a) {
    return bytes_to_hex(a.data(), N);
}

static std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (hex.size() % 2 != 0)
        return bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t b = 0;
        for (int j = 0; j < 2; j++) {
            char c = hex[i + j];
            int n = c >= '0' && c <= '9'   ? c - '0'
                    : c >= 'a' && c <= 'f' ? c - 'a' + 10
                    : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                           : -1;
            if (n < 0) {
                bytes.clear();
                return bytes;
            }
            b = static_cast<uint8_t>(b * 16 + n);
        }
        bytes.push_back(b);
    }
    return bytes;
}

struct ValidatorKey {
    Secp256k1PrivKey privkey;
    Secp256k1PubKey pubkey;
    std::string address;
    std::string pubkey_hex;

    bool HasExactIdentityBinding() const {
        bool nonzero = false;
        for (uint8_t b : privkey)
            if (b != 0) {
                nonzero = true;
                break;
            }
        if (!nonzero)
            return false;
        Secp256k1PubKey derived{};
        try {
            derived = DerivePublicKey(privkey);
        } catch (...) {
            return false;
        }
        if (derived != pubkey)
            return false;
        std::vector<uint8_t> pub(pubkey.begin(), pubkey.end());
        return ValidatorRegistry::PubkeyToAddress(pub) == address;
    }

    static bool IsEncrypted(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f.good())
            return false;
        uint8_t header[3]{};
        f.read(reinterpret_cast<char*>(header), sizeof(header));
        return f.gcount() == static_cast<std::streamsize>(sizeof(header)) &&
               header[0] == veld::wallet_crypto::VELD_WALLET_MAGIC[0] &&
               header[1] == veld::wallet_crypto::VELD_WALLET_MAGIC[1];
    }

    bool Load(const std::string& path, const std::string& passphrase) {
        if (IsEncrypted(path)) {
            std::ifstream f(path, std::ios::binary);
            if (!f.good())
                return false;
            std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                                      std::istreambuf_iterator<char>());
            try {
                std::string plaintext = veld::wallet_crypto::DecryptWallet(data, passphrase);
                std::istringstream ss(plaintext);
                std::string priv_hex, pub_hex;
                std::getline(ss, priv_hex);
                std::getline(ss, pub_hex);
                std::getline(ss, address);
                veld::compat::SecureZero(plaintext.data(), plaintext.size());
                while (!address.empty() &&
                       (address.back() == '\r' || address.back() == '\n' || address.back() == ' '))
                    address.pop_back();
                auto priv_bytes = from_hex(priv_hex);
                auto pub_bytes = from_hex(pub_hex);
                veld::compat::SecureZero(priv_hex.data(), priv_hex.size());
                if (priv_bytes.size() != 32 || pub_bytes.size() != 1952)
                    return false;
                std::copy(priv_bytes.begin(), priv_bytes.end(), privkey.begin());
                std::copy(pub_bytes.begin(), pub_bytes.end(), pubkey.begin());
                veld::compat::SecureZero(priv_bytes.data(), priv_bytes.size());
#ifdef _WIN32
                VirtualLock(privkey.data(), privkey.size());
#else
                ::mlock(privkey.data(), privkey.size());
#endif
                pubkey_hex = pub_hex;
                if (!HasExactIdentityBinding())
                    return false;

                // Upgrade only after AEAD authentication and exact
                // private/public/address binding succeed. Save uses an atomic
                // owner-only replacement, preserving this validator identity.
                if (!veld::wallet_crypto::IsCurrentWalletEnvelope(data) &&
                    !Save(path, passphrase)) {
                    std::cerr << YEL
                              << "[WARNING] Validator identity unlocked, but "
                                 "its older encryption could not be upgraded. "
                                 "The original keyfile remains usable."
                              << RST << "\n";
                }
                return true;
            } catch (...) {
                return false;
            }
        }
        std::cerr << YEL << "[WARNING] " << path
                  << " is a PLAINTEXT key file. Re-create with --genkey to "
                  << "encrypt with a passphrase." << RST << "\n";
        std::ifstream f(path);
        if (!f.good())
            return false;
        std::string priv_hex, pub_hex;
        std::getline(f, priv_hex);
        std::getline(f, pub_hex);
        std::getline(f, address);
        for (auto* s : {&priv_hex, &pub_hex, &address})
            while (!s->empty() && (s->back() == '\r' || s->back() == '\n' || s->back() == ' '))
                s->pop_back();
        auto priv_bytes = from_hex(priv_hex);
        auto pub_bytes = from_hex(pub_hex);
        if (priv_bytes.size() != 32 || pub_bytes.size() != 1952)
            return false;
        std::copy(priv_bytes.begin(), priv_bytes.end(), privkey.begin());
        std::copy(pub_bytes.begin(), pub_bytes.end(), pubkey.begin());
        veld::compat::SecureZero(priv_bytes.data(), priv_bytes.size());
#ifdef _WIN32
        VirtualLock(privkey.data(), privkey.size());
#else
        ::mlock(privkey.data(), privkey.size());
#endif
        pubkey_hex = pub_hex;
        return HasExactIdentityBinding();
    }

    bool Save(const std::string& path, const std::string& passphrase) const {
        std::string plaintext = to_hex(privkey) + "\n" + to_hex(pubkey) + "\n" + address + "\n";
        auto encrypted = veld::wallet_crypto::EncryptWallet(plaintext, passphrase);
        veld::compat::SecureZero(plaintext.data(), plaintext.size());
        std::string error;
        const bool ok = veld::channel::secure_file::AtomicWrite(path, encrypted, &error,
                                                                /*require_private_parent=*/true);
        if (!encrypted.empty())
            veld::compat::SecureZero(encrypted.data(), encrypted.size());
        return ok;
    }
};

static std::string ask_passphrase(bool confirm) {
    auto read_once = [](const char* prompt) -> std::string {
        std::cout << prompt << std::flush;
        veld::compat::ConsoleEchoOff();
        std::string p;
        std::getline(std::cin, p);
        veld::compat::ConsoleEchoOn();
        std::cout << "(hidden)\n";
        return p;
    };
    while (true) {
        std::string p = read_once("  Passphrase: ");
        if (p.empty())
            return "";
        if (!confirm)
            return p;
        std::string c = read_once("  Confirm:    ");
        std::string policy_error;
        const bool policy_ok = wallet_crypto::ValidateNewPassphrase(p, &policy_error);
        if (p == c && policy_ok)
            return p;
        if (p == c)
            std::cerr << RED << "  Passphrase rejected: " << policy_error << "\n" << RST;
        else
            std::cerr << RED << "  Passphrases do not match. Try again.\n" << RST;
        veld::compat::SecureZero(p.data(), p.size());
        veld::compat::SecureZero(c.data(), c.size());
    }
}

static int cmd_genkey(const std::string& keyfile, const std::string& wallet_address) {
    ValidatorKey vk;
    vk.privkey = GeneratePrivateKey();
    vk.pubkey = DerivePublicKey(vk.privkey);
    std::vector<uint8_t> pub(vk.pubkey.begin(), vk.pubkey.end());
    vk.address = ValidatorRegistry::PubkeyToAddress(pub);
    vk.pubkey_hex = to_hex(vk.pubkey);
    if (vk.address.empty() || (!wallet_address.empty() && wallet_address != vk.address)) {
        std::cerr << RED
                  << "Error: --address does not match the generated validator "
                     "public key. The validator funding address is derived locally: "
                  << vk.address << "\n"
                  << RST;
        veld::compat::SecureZero(vk.privkey.data(), vk.privkey.size());
        return 1;
    }

    // Encrypt validator keys at rest with wallet_crypto. The daemon requires
    // the passphrase before loading the key or signing.
    std::cout << "Set a passphrase for the new validator key (used to decrypt\n"
              << "the keyfile every time the daemon starts).\n";
    std::string pass = ask_passphrase(true);
    if (pass.empty()) {
        std::cerr << RED << "Aborted: empty passphrase.\n" << RST;
        return 1;
    }

    bool saved = vk.Save(keyfile, pass);
    veld::compat::SecureZero(pass.data(), pass.size());
    if (!saved) {
        std::cerr << RED << "Error: cannot write to " << keyfile << "\n" << RST;
        return 1;
    }

    std::cout << GRN << "Validator keypair generated (encrypted at rest)\n" << RST;
    std::cout << "  Keyfile:     " << keyfile << "\n";
    std::cout << "  Public key:  " << vk.pubkey_hex << "\n";
    std::cout << "  Wallet addr: " << vk.address << "\n";
    std::cout << "\n";
    std::cout << YEL << "Keep " << keyfile << " AND the passphrase secret.\n"
              << "Anyone with BOTH can submit endorsements on your behalf.\n"
              << RST;
    std::cout << "\n";
    std::cout << "Next steps:\n";
    std::cout << "  1. Ensure " << vk.address << " has >= 10,000 VELD staked (mainnet target)\n";
    std::cout << "  2. Run: veld-validator --keyfile " << keyfile << " --register\n";
    std::cout << "  3. Run: veld-validator --keyfile " << keyfile << " (daemon mode)\n";
    return 0;
}

static const veld::btc_buy::JsonValue*
strict_rpc_result(const std::string& response, veld::btc_buy::JsonValue& root, std::string& error,
                  size_t max_json_response_bytes = veld::btc_buy::kMaxExplorerResponseBytes) {
    veld::btc_buy::StrictJsonParser parser(response, max_json_response_bytes);
    if (!parser.Parse(root, error) || root.kind != veld::btc_buy::JsonValue::Kind::Object) {
        error = "malformed RPC envelope";
        return nullptr;
    }
    const auto* result = root.Get("result");
    const auto* rpc_error = root.Get("error");
    if (!result || (rpc_error && rpc_error->kind != veld::btc_buy::JsonValue::Kind::Null)) {
        error = "RPC returned an error";
        return nullptr;
    }
    return result;
}

static bool decode_lower_hex(const std::string& hex, size_t max_bytes, std::vector<uint8_t>& out) {
    if (!veld::btc_buy::IsLowerHex(hex) || hex.size() / 2 > max_bytes)
        return false;
    out = from_hex(hex);
    return out.size() * 2 == hex.size();
}

namespace fq = veld::finality::qc;

static bool json_u64(const veld::btc_buy::JsonValue& object, const char* key, uint64_t& out) {
    const auto* value = object.Get(key);
    return value && veld::btc_buy::ParseUint(*value, out);
}

static bool json_bool(const veld::btc_buy::JsonValue& object, const char* key, bool& out) {
    const auto* value = object.Get(key);
    if (!value || value->kind != veld::btc_buy::JsonValue::Kind::Bool)
        return false;
    out = value->boolean;
    return true;
}

static bool json_string(const veld::btc_buy::JsonValue& object, const char* key, std::string& out) {
    const auto* value = object.Get(key);
    if (!value || value->kind != veld::btc_buy::JsonValue::Kind::String)
        return false;
    out = value->text;
    return true;
}

static bool lower_hex_hash(const std::string& hex, Hash256& out) {
    if (!veld::btc_buy::IsLowerHex(hex, 64))
        return false;
    const auto raw = from_hex(hex);
    if (raw.size() != out.size())
        return false;
    std::copy(raw.begin(), raw.end(), out.begin());
    return true;
}

static Hash256 compiled_genesis_bytes() {
    Hash256 out{};
    return lower_hex_hash(GENESIS_HASH, out) ? out : Hash256{};
}

static bool validate_work_binding(const std::string& encoded, veld::work_admission::Purpose purpose,
                                  uint64_t target_height, const Hash256& target_hash) {
    const auto binding = veld::work_admission::DecodeBinding(encoded);
    return binding && veld::work_admission::EncodeBinding(*binding) == encoded &&
           binding->subject.purpose == purpose && binding->subject.height == target_height &&
           binding->subject.target_hash == target_hash &&
           binding->subject.parent_height >= target_height &&
           !HashIsZero(binding->subject.parent_hash) && binding->validation_generation != 0 &&
           binding->network_magic == MAINNET_MAGIC &&
           binding->genesis_hash == compiled_genesis_bytes() &&
           binding->profile_digest == Hash256d(std::string(DEPLOYMENT_PROFILE_ID));
}

struct WorkAdmissionGrant {
    std::string binding;
    std::string token;
    std::chrono::steady_clock::time_point deadline{};

    bool Live(std::chrono::milliseconds minimum_remaining =
                  std::chrono::milliseconds::zero()) const noexcept {
        if (binding.empty() || token.empty())
            return false;
        const auto now = std::chrono::steady_clock::now();
        return now < deadline && deadline - now >= minimum_remaining;
    }
};

static bool cancel_work_signing(const std::string& host, uint16_t port, const std::string& token) {
    if (!veld::btc_buy::IsLowerHex(token, 64))
        return false;
    std::string error;
    veld::btc_buy::JsonValue root;
    const auto* result = strict_rpc_result(
        json_rpc(host, port, "cancelworksigning", "[\"" + token + "\"]"), root, error);
    bool released = false;
    return result && result->kind == veld::btc_buy::JsonValue::Kind::Object &&
           json_bool(*result, "released", released) && released;
}

class WorkGrantCancelGuard {
  public:
    WorkGrantCancelGuard(const std::string& host, uint16_t port, const WorkAdmissionGrant& grant)
        : host_(host), port_(port), token_(grant.token) {}
    WorkGrantCancelGuard(const WorkGrantCancelGuard&) = delete;
    WorkGrantCancelGuard& operator=(const WorkGrantCancelGuard&) = delete;
    ~WorkGrantCancelGuard() {
        // Submission consumes the active lease first, making this a harmless
        // no-op on success.  On every earlier return/exception it promptly
        // releases the node-held reservation.
        if (armed_)
            (void)cancel_work_signing(host_, port_, token_);
    }
    void Disarm() noexcept {
        armed_ = false;
    }

  private:
    const std::string& host_;
    uint16_t port_{0};
    std::string token_;
    bool armed_{true};
};

static std::optional<WorkAdmissionGrant>
fetch_work_admission(const std::string& host, uint16_t port, veld::work_admission::Purpose purpose,
                     uint64_t target_height, const Hash256& target_hash) {
    const char* purpose_name = nullptr;
    switch (purpose) {
    case veld::work_admission::Purpose::ValidatorEndorsement:
        purpose_name = "validator_endorsement";
        break;
    case veld::work_admission::Purpose::FinalityVote:
        purpose_name = "finality_vote";
        break;
    default:
        return std::nullopt;
    }

    std::string error, binding_text, tip_hash_text, token_text;
    uint64_t ttl_ms = 0;
    veld::btc_buy::JsonValue root;
    const auto* result = strict_rpc_result(json_rpc(host, port, "getworkadmission",
                                                    "[\"" + std::string(purpose_name) + "\",\"" +
                                                        std::to_string(target_height) + "\",\"" +
                                                        HashToHex(target_hash) + "\"]"),
                                           root, error);
    bool allowed = false;
    uint64_t tip_height = 0;
    if (!result || result->kind != veld::btc_buy::JsonValue::Kind::Object ||
        !json_bool(*result, "allowed", allowed) || !allowed ||
        !json_string(*result, "binding", binding_text) ||
        !json_string(*result, "signing_token", token_text) ||
        !json_u64(*result, "ttl_ms", ttl_ms) || ttl_ms == 0 ||
        ttl_ms > static_cast<uint64_t>(
                     veld::work_admission::AdmissionCoordinator::ABSOLUTE_MAX_LEASE.count()) ||
        !json_u64(*result, "tip_height", tip_height) ||
        !json_string(*result, "tip_hash", tip_hash_text) ||
        !validate_work_binding(binding_text, purpose, target_height, target_hash))
        return std::nullopt;
    if (!veld::btc_buy::IsLowerHex(token_text, 64) || token_text == std::string(64, '0'))
        return std::nullopt;
    WorkAdmissionGrant pending_release_grant;
    pending_release_grant.binding = binding_text;
    pending_release_grant.token = token_text;
    pending_release_grant.deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(ttl_ms);
    WorkGrantCancelGuard pending_release(host, port, pending_release_grant);
    Hash256 tip_hash{};
    const auto decoded = veld::work_admission::DecodeBinding(binding_text);
    if (!decoded || !lower_hex_hash(tip_hash_text, tip_hash) ||
        decoded->subject.parent_height != tip_height || decoded->subject.parent_hash != tip_hash)
        return std::nullopt;
    // Consume the pending grant into a node-held active lease before the
    // standalone process can journal or sign.  The returned ttl is the
    // earlier operation deadline; the node retains a safety margin before the
    // coordinator's hard transition-release deadline.
    const auto activation_started = std::chrono::steady_clock::now();
    veld::btc_buy::JsonValue activation_root;
    uint64_t operation_ttl_ms = 0;
    bool started = false;
    const auto* activation =
        strict_rpc_result(json_rpc(host, port, "beginworksigning",
                                   "[\"" + std::string(purpose_name) + "\",\"" + binding_text +
                                       "\",\"" + token_text + "\"]"),
                          activation_root, error);
    if (!activation || activation->kind != veld::btc_buy::JsonValue::Kind::Object ||
        !json_bool(*activation, "started", started) || !started ||
        !json_u64(*activation, "ttl_ms", operation_ttl_ms) || operation_ttl_ms == 0 ||
        operation_ttl_ms >
            static_cast<uint64_t>(
                veld::work_admission::AdmissionCoordinator::ABSOLUTE_MAX_LEASE.count())) {
        return std::nullopt;
    }

    WorkAdmissionGrant grant;
    grant.binding = std::move(binding_text);
    grant.token = std::move(token_text);
    // Anchoring to request start is conservative across transport latency and
    // independent steady clocks.
    grant.deadline = activation_started + std::chrono::milliseconds(operation_ttl_ms);
    if (!grant.Live()) {
        return std::nullopt;
    }
    pending_release.Disarm();
    return grant;
}

struct FinalityRpcFrame {
    fq::EpochSnapshot snapshot;
    std::optional<fq::FinalizedRecord> finalized;
};

static std::optional<FinalityRpcFrame> fetch_finality_frame(const std::string& host, uint16_t port,
                                                            uint64_t target_epoch) {
    std::string error;
    veld::btc_buy::JsonValue root;
    const auto* result = strict_rpc_result(
        json_rpc(host, port, "getfinalitysnapshot", "[\"" + std::to_string(target_epoch) + "\"]"),
        root, error, veld::finality::rpc_limits::kSnapshotJsonResponseMaxBytes);
    if (!result || result->kind != veld::btc_buy::JsonValue::Kind::Object)
        throw std::runtime_error("getfinalitysnapshot: " + error);
    const auto* snap = result->Get("snapshot");
    if (!snap || snap->kind == veld::btc_buy::JsonValue::Kind::Null)
        return std::nullopt;
    if (snap->kind != veld::btc_buy::JsonValue::Kind::Object)
        throw std::runtime_error("getfinalitysnapshot returned malformed snapshot");

    FinalityRpcFrame frame;
    uint64_t epoch = 0, snapshot_height = 0, total_weight = 0;
    std::string root_hex;
    bool active = false;
    if (!json_u64(*snap, "epoch", epoch) || epoch != target_epoch ||
        !json_u64(*snap, "snapshot_height", snapshot_height) ||
        !json_u64(*snap, "total_weight", total_weight) ||
        !json_string(*snap, "set_root", root_hex) || !json_bool(*snap, "active", active) ||
        !lower_hex_hash(root_hex, frame.snapshot.root))
        throw std::runtime_error("getfinalitysnapshot omitted canonical fields");
    if (!active)
        return std::nullopt;
    frame.snapshot.epoch_id = epoch;
    frame.snapshot.snapshot_height = snapshot_height;
    frame.snapshot.total_weight = total_weight;

    const auto* members = snap->Get("members");
    if (!members || members->kind != veld::btc_buy::JsonValue::Kind::Array ||
        members->array.size() > fq::MAX_FINALITY_VALIDATOR_COUNT)
        throw std::runtime_error("getfinalitysnapshot returned invalid members");
    frame.snapshot.entries.reserve(members->array.size());
    for (size_t i = 0; i < members->array.size(); ++i) {
        const auto& member = members->array[i];
        if (member.kind != veld::btc_buy::JsonValue::Kind::Object)
            throw std::runtime_error("getfinalitysnapshot member is not an object");
        uint64_t index = 0, registered = 0, weight = 0;
        std::string pubkey, commit, address;
        fq::SnapshotEntry entry;
        if (!json_u64(member, "index", index) || index != i ||
            !json_u64(member, "registered_height", registered) ||
            !json_u64(member, "weight", weight) || !json_string(member, "pubkey", pubkey) ||
            !json_string(member, "commit", commit) || !json_string(member, "address", address) ||
            registered > UINT64_MAX || weight != fq::BOND_PER_KEY_UNITS ||
            !veld::btc_buy::IsLowerHex(pubkey, 3904) || address.empty() ||
            address.size() > veld::finality::rpc_limits::kMaxValidatorAddressChars ||
            !lower_hex_hash(commit, entry.pubkey_commit))
            throw std::runtime_error("getfinalitysnapshot member is malformed");
        entry.pubkey_hex = std::move(pubkey);
        entry.address = std::move(address);
        entry.registered_height = registered;
        entry.weight = weight;
        frame.snapshot.entries.push_back(std::move(entry));
    }
    if (!fq::SnapshotWellFormed(frame.snapshot))
        throw std::runtime_error("getfinalitysnapshot failed local root/order validation");

    const auto* finalized = snap->Get("finalized");
    if (finalized && finalized->kind != veld::btc_buy::JsonValue::Kind::Null) {
        if (finalized->kind != veld::btc_buy::JsonValue::Kind::Object)
            throw std::runtime_error("getfinalitysnapshot finalized is malformed");
        fq::FinalizedRecord record;
        uint64_t record_epoch = 0, height = 0, round = 0;
        std::string hash;
        if (!json_u64(*finalized, "epoch", record_epoch) ||
            !json_u64(*finalized, "height", height) || !json_u64(*finalized, "round", round) ||
            round > UINT32_MAX || !json_string(*finalized, "hash", hash) ||
            !lower_hex_hash(hash, record.target.hash))
            throw std::runtime_error("getfinalitysnapshot finalized fields invalid");
        record.epoch_id = record_epoch;
        record.target.height = height;
        record.round = static_cast<uint32_t>(round);
        record.phase = fq::Phase::PRECOMMIT;
        record.set_root = frame.snapshot.root;
        frame.finalized = record;
    }
    return frame;
}

static uint64_t fetch_rpc_tip(const std::string& host, uint16_t port) {
    std::string error;
    veld::btc_buy::JsonValue root;
    const auto* result = strict_rpc_result(json_rpc(host, port, "getblockchaininfo"), root, error);
    uint64_t tip = 0;
    if (!result || result->kind != veld::btc_buy::JsonValue::Kind::Object ||
        !json_u64(*result, "blocks", tip))
        throw std::runtime_error("getblockchaininfo omitted blocks");
    return tip;
}

static std::optional<Hash256> fetch_rpc_block_hash(const std::string& host, uint16_t port,
                                                   uint64_t height) {
    std::string error;
    veld::btc_buy::JsonValue root;
    const auto* result = strict_rpc_result(
        json_rpc(host, port, "getblockhash", "[\"" + std::to_string(height) + "\"]"), root, error);
    Hash256 hash{};
    if (!result || result->kind != veld::btc_buy::JsonValue::Kind::String ||
        !lower_hex_hash(result->text, hash))
        return std::nullopt;
    return hash;
}

static bool bitcoin_core_observes_block(const std::string& hash_hex) {
    if (!veld::btc_buy::IsLowerHex(hash_hex, 64))
        return false;
    auto result = veld::compat::RunProcess({g_bitcoin_cli, "getblockheader", hash_hex, "true"},
                                           true, {}, false, 256u * 1024u);
    if (result.exit_code != 0 || result.output_truncated || result.output.empty())
        return false;
    veld::btc_buy::JsonValue root;
    std::string error;
    veld::btc_buy::StrictJsonParser parser(result.output, 256u * 1024u);
    if (!parser.Parse(root, error) || root.kind != veld::btc_buy::JsonValue::Kind::Object)
        return false;
    std::string returned_hash;
    uint64_t confirmations = 0;
    return json_string(root, "hash", returned_hash) && returned_hash == hash_hex &&
           json_u64(root, "confirmations", confirmations) &&
           confirmations >= BTCVELD_ANCHOR_BTC_CONFS;
}

// Finality safety policy: a Veld checkpoint may finalize a pending Bitcoin
// observation only if this validator independently sees that exact BTC block on
// its own Bitcoin Core active chain. Re-read the Veld target hash afterwards to
// close the RPC/reorg race. A missing/unreachable Bitcoin Core fails closed.
static bool authorize_finality_target_observations(const std::string& host, uint16_t port,
                                                   const fq::CheckpointRef& target) {
    auto before = fetch_rpc_block_hash(host, port, target.height);
    if (!before || *before != target.hash)
        return false;

    std::string error;
    veld::btc_buy::JsonValue root;
    const auto* result = strict_rpc_result(json_rpc(host, port, "getanchorinfo"), root, error);
    if (!result || result->kind != veld::btc_buy::JsonValue::Kind::Object)
        return false;
    const auto* pending = result->Get("pending_observations");
    if (!pending || pending->kind != veld::btc_buy::JsonValue::Kind::Array ||
        pending->array.size() > BTCVELD_ANCHOR_ACCEPT_WINDOW + 1)
        return false;

    for (const auto& item : pending->array) {
        if (item.kind != veld::btc_buy::JsonValue::Kind::Object)
            return false;
        uint64_t carrier_height = 0;
        bool btc_final = false;
        std::string btc_hash;
        if (!json_u64(item, "proof_carrier_height", carrier_height) ||
            !json_bool(item, "btc_final", btc_final) ||
            !json_string(item, "btc_block_hash", btc_hash) ||
            !veld::btc_buy::IsLowerHex(btc_hash, 64))
            return false;
        // Only observations whose exact Veld carrier would enter the finalized
        // prefix are relevant to this vote. A BTC-reorged pending proof is
        // ignored here because consensus will deterministically drop it during
        // promotion instead of turning it into an observation checkpoint.
        if (carrier_height <= target.height && btc_final && !bitcoin_core_observes_block(btc_hash))
            return false;
    }

    auto after = fetch_rpc_block_hash(host, port, target.height);
    return after && *after == target.hash;
}

static std::optional<fq::DecodedQc> fetch_prevote_qc(const std::string& host, uint16_t port) {
    std::string error, hex;
    veld::btc_buy::JsonValue root;
    const auto* result =
        strict_rpc_result(json_rpc(host, port, "getfinalityqc", "[\"1\"]"), root, error,
                          veld::finality::rpc_limits::kQcJsonResponseMaxBytes);
    if (!result || result->kind != veld::btc_buy::JsonValue::Kind::Object ||
        !json_string(*result, "qc_hex", hex) || hex.empty())
        return std::nullopt;
    std::vector<uint8_t> raw;
    if (!decode_lower_hex(hex, fq::MAX_FINALITY_QC_BYTES, raw))
        throw std::runtime_error("getfinalityqc returned malformed hex");
    const std::string wire(reinterpret_cast<const char*>(raw.data()), raw.size());
    return fq::DecodeQc(wire);
}

static bool submit_finality_vote(const std::string& host, uint16_t port, const fq::SignedVote& vote,
                                 const WorkAdmissionGrant& grant) {
    const auto wire = fq::EncodeSignedVoteWire(vote);
    if (wire.size() != fq::SIGNED_VOTE_WIRE_BYTES || !grant.Live() ||
        !validate_work_binding(grant.binding, veld::work_admission::Purpose::FinalityVote,
                               vote.target.height, vote.target.hash))
        return false;
    const std::string hex = bytes_to_hex(wire.data(), wire.size());
    std::string error;
    veld::btc_buy::JsonValue root;
    const auto* result = strict_rpc_result(
        json_rpc(host, port, "submitfinalityvote",
                 "[\"" + hex + "\",\"" + grant.binding + "\",\"" + grant.token + "\"]"),
        root, error);
    bool accepted = false;
    return result && result->kind == veld::btc_buy::JsonValue::Kind::Object &&
           json_bool(*result, "accepted", accepted) && accepted;
}

static std::vector<uint8_t> encode_finality_journal(const fq::DaemonJournal& journal) {
    std::vector<uint8_t> out{'V', 'F', 'J', '1'};
    state_digest::put_u32_le(out, journal.version);
    state_digest::put_u8(out, journal.lock.held ? 1 : 0);
    state_digest::put_u64_le(out, journal.lock.epoch_id);
    state_digest::put_u32_le(out, journal.lock.round);
    state_digest::put_u64_le(out, journal.lock.target.height);
    state_digest::put_bytes(out, journal.lock.target.hash.data(), 32);
    state_digest::put_u8(out, journal.last_vote ? 1 : 0);
    if (journal.last_vote) {
        const auto vote = fq::EncodeSignedVoteWire(*journal.last_vote);
        if (vote.size() != fq::SIGNED_VOTE_WIRE_BYTES)
            return {};
        state_digest::put_bytes(out, vote.data(), vote.size());
    }
    const Hash256 checksum = state_digest::sha256_domain("VELD_FINALITY_DAEMON_JOURNAL_v1|", out);
    state_digest::put_bytes(out, checksum.data(), checksum.size());
    return out;
}

static std::optional<fq::DaemonJournal> decode_finality_journal(const std::vector<uint8_t>& in) {
    constexpr size_t BASE = 4 + 4 + 1 + 8 + 4 + 8 + 32 + 1;
    if (in.size() != BASE + 32 && in.size() != BASE + fq::SIGNED_VOTE_WIRE_BYTES + 32)
        return std::nullopt;
    if (!std::equal(in.begin(), in.begin() + 4, std::array<uint8_t, 4>{'V', 'F', 'J', '1'}.begin()))
        return std::nullopt;
    const size_t checksum_at = in.size() - 32;
    std::vector<uint8_t> body(in.begin(), in.begin() + (ptrdiff_t)checksum_at);
    const Hash256 checksum = state_digest::sha256_domain("VELD_FINALITY_DAEMON_JOURNAL_v1|", body);
    if (!std::equal(checksum.begin(), checksum.end(), in.begin() + (ptrdiff_t)checksum_at))
        return std::nullopt;
    size_t p = 4;
    auto u8 = [&]() -> uint8_t { return in[p++]; };
    auto u32 = [&]() {
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i)
            v |= (uint32_t)in[p++] << (8 * i);
        return v;
    };
    auto u64 = [&]() {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
            v |= (uint64_t)in[p++] << (8 * i);
        return v;
    };
    fq::DaemonJournal journal;
    journal.version = u32();
    const uint8_t held = u8();
    if (held > 1)
        return std::nullopt;
    journal.lock.held = held != 0;
    journal.lock.epoch_id = u64();
    journal.lock.round = u32();
    journal.lock.target.height = u64();
    std::copy_n(in.begin() + (ptrdiff_t)p, 32, journal.lock.target.hash.begin());
    p += 32;
    const uint8_t has_vote = u8();
    if (has_vote > 1)
        return std::nullopt;
    if (has_vote) {
        if (p + fq::SIGNED_VOTE_WIRE_BYTES != checksum_at)
            return std::nullopt;
        std::vector<uint8_t> vote(in.begin() + (ptrdiff_t)p,
                                  in.begin() + (ptrdiff_t)(p + fq::SIGNED_VOTE_WIRE_BYTES));
        auto decoded = fq::DecodeSignedVoteWire(vote);
        if (!decoded)
            return std::nullopt;
        journal.last_vote = std::move(*decoded);
        p += fq::SIGNED_VOTE_WIRE_BYTES;
    }
    if (p != checksum_at)
        return std::nullopt;
    return journal;
}

static bool broadcast_op_return(const std::string& host, uint16_t port,
                                const std::string& from_address, const std::string& op_return_data,
                                const ValidatorKey& vk,
                                const WorkAdmissionGrant* endorse_work_grant = nullptr) {
    const std::string register_prefix = "VELD_VALIDATOR|REGISTER|";
    const std::string deregister_prefix = "VELD_VALIDATOR|DEREGISTER|";
    const std::string endorse_prefix = "VELD_VALIDATOR|ENDORSE|";
    const bool is_register = op_return_data.rfind(register_prefix, 0) == 0;
    const bool is_deregister = op_return_data.rfind(deregister_prefix, 0) == 0;
    const bool is_endorse = op_return_data.rfind(endorse_prefix, 0) == 0;
    if ((!is_register && !is_deregister && !is_endorse) || !vk.HasExactIdentityBinding() ||
        from_address != vk.address) {
        log(RED, "Refusing an unrecognized or identity-unbound validator operation");
        return false;
    }
    if (is_endorse &&
        (!endorse_work_grant || !endorse_work_grant->Live(std::chrono::milliseconds(1000)))) {
        log(RED, "Refusing endorsement without authoritative work admission");
        return false;
    }

    std::string method;
    std::string params;
    if (is_register) {
        method = "prepareregistervalidator";
        params = "[\"" + from_address + "\",\"" + vk.pubkey_hex + "\"]";
    } else if (is_deregister) {
        method = "preparederegistervalidator";
        params = "[\"" + from_address + "\",\"" + vk.pubkey_hex + "\"]";
    } else {
        method = "preparerawop";
        params = "[\"" + from_address + "\",\"" + op_return_data + "\"]";
    }

    std::string error;
    veld::btc_buy::JsonValue prep_root;
    const auto* prep = strict_rpc_result(json_rpc(host, port, method, params), prep_root, error);
    if (!prep || prep->kind != veld::btc_buy::JsonValue::Kind::Object) {
        log(RED, "Validator transaction preparation failed: " + error);
        return false;
    }
    if (const auto* status = prep->Get("status")) {
        if (status->kind == veld::btc_buy::JsonValue::Kind::String &&
            ((is_register && status->text == "already_registered") ||
             (is_deregister && status->text == "not_registered"))) {
            log(GRAY, "Validator operation is already in the requested state");
            return true;
        }
    }

    const auto* unsigned_hex = prep->Get("unsigned_tx_hex");
    const auto* input_meta = prep->Get("inputs");
    const auto* total_input_meta = prep->Get("total_input");
    const auto* total_output_meta = prep->Get("total_output");
    const auto* fee_meta = prep->Get("fee");
    const auto* change_meta = prep->Get("change");
    uint64_t claimed_total_input = 0, claimed_total_output = 0, claimed_fee = 0, claimed_change = 0;
    if (!unsigned_hex || unsigned_hex->kind != veld::btc_buy::JsonValue::Kind::String ||
        !input_meta || input_meta->kind != veld::btc_buy::JsonValue::Kind::Array ||
        !total_input_meta || !veld::btc_buy::ParseUint(*total_input_meta, claimed_total_input) ||
        !total_output_meta || !veld::btc_buy::ParseUint(*total_output_meta, claimed_total_output) ||
        !fee_meta || !veld::btc_buy::ParseUint(*fee_meta, claimed_fee) || !change_meta ||
        !veld::btc_buy::ParseUint(*change_meta, claimed_change)) {
        log(RED, "Prepared validator transaction omitted required policy facts");
        return false;
    }

    std::vector<uint8_t> raw;
    if (!decode_lower_hex(unsigned_hex->text, 1000000, raw))
        return false;
    Transaction tx;
    const size_t consumed = Transaction::Deserialize(raw, 0, tx);
    if (consumed != raw.size() || tx.Serialize() != raw || tx.version != 1 || tx.locktime != 0 ||
        tx.inputs.empty() || tx.inputs.size() > 180 ||
        tx.inputs.size() != input_meta->array.size()) {
        log(RED, "Prepared validator transaction is non-canonical");
        return false;
    }

    const std::vector<uint8_t> from_script = AddressToScript(from_address);
    const std::vector<uint8_t> expected_op = BuildOpReturnScript(op_return_data);
    const std::vector<uint8_t> vault_script = AddressToScript(STAKE_VAULT_ADDRESS);
    if (from_script.empty() || expected_op.empty() || expected_op.size() > 32768 ||
        tx.outputs.empty() || tx.outputs.back().value != 0 ||
        tx.outputs.back().script_pubkey != expected_op) {
        log(RED, "Prepared validator transaction changed the exact operation payload");
        return false;
    }

    size_t cursor = 0;
    const uint64_t expected_protocol_output = is_register ? MIN_VALIDATOR_STAKE : 0;
    if (is_register) {
        if (vault_script.empty() || (tx.outputs.size() != 2 && tx.outputs.size() != 3) ||
            tx.outputs[0].value != MIN_VALIDATOR_STAKE ||
            tx.outputs[0].script_pubkey != vault_script) {
            log(RED, "Registration proposal changed the exact validator bond");
            return false;
        }
        cursor = 1;
    } else if (tx.outputs.size() != 1 && tx.outputs.size() != 2) {
        log(RED, "Validator operation has unexpected outputs");
        return false;
    }
    const uint64_t actual_protocol_output =
        is_register ? tx.outputs[0].value : tx.outputs.back().value;
    if (actual_protocol_output != expected_protocol_output)
        return false;
    uint64_t actual_change = 0;
    if (cursor + 1 < tx.outputs.size()) {
        const TxOutput& change = tx.outputs[cursor++];
        if (change.value == 0 || change.script_pubkey != from_script) {
            log(RED, "Validator operation change is not exact self-change");
            return false;
        }
        actual_change = change.value;
    }
    if (cursor != tx.outputs.size() - 1)
        return false;

    uint64_t output_sum = 0;
    for (const auto& output : tx.outputs) {
        if (output.value > MAX_SUPPLY_UNITS || output_sum > MAX_SUPPLY_UNITS - output.value)
            return false;
        output_sum += output.value;
    }
    uint64_t input_sum = 0;
    std::set<std::pair<std::string, uint32_t>> seen;
    const std::string from_script_hex = bytes_to_hex(from_script.data(), from_script.size());
    for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
        const auto& input = tx.inputs[i];
        const std::string prev_txid = HashToHex(input.prev_tx_hash);
        if (!input.script_sig.empty() || input.sequence != 0xffffffffU ||
            !veld::btc_buy::IsLowerHex(prev_txid, 64) ||
            !seen.emplace(prev_txid, input.prev_out_index).second)
            return false;

        const auto& meta = input_meta->array[i];
        if (meta.kind != veld::btc_buy::JsonValue::Kind::Object)
            return false;
        const auto* index = meta.Get("index");
        const auto* sighash = meta.Get("sighash_hex");
        const auto* prev_script = meta.Get("prev_script_hex");
        uint64_t index_n = 0;
        if (!index || !veld::btc_buy::ParseUint(*index, index_n) || index_n != i || !sighash ||
            sighash->kind != veld::btc_buy::JsonValue::Kind::String ||
            !veld::btc_buy::IsLowerHex(sighash->text, 64) || !prev_script ||
            prev_script->kind != veld::btc_buy::JsonValue::Kind::String ||
            prev_script->text != from_script_hex)
            return false;

        veld::btc_buy::JsonValue utxo_root;
        const auto* utxo = strict_rpc_result(
            json_rpc(host, port, "gettxout",
                     "[\"" + prev_txid + "\",\"" + std::to_string(input.prev_out_index) + "\"]"),
            utxo_root, error);
        if (!utxo || utxo->kind != veld::btc_buy::JsonValue::Kind::Object)
            return false;
        const auto* utxo_txid = utxo->Get("txid");
        const auto* utxo_vout = utxo->Get("vout");
        const auto* utxo_value = utxo->Get("value_units");
        const auto* utxo_script = utxo->Get("script_pubkey_hex");
        const auto* utxo_height = utxo->Get("block_height");
        uint64_t vout_n = 0, value_n = 0, height_n = 0;
        if (!utxo_txid || utxo_txid->kind != veld::btc_buy::JsonValue::Kind::String ||
            utxo_txid->text != prev_txid || !utxo_vout ||
            !veld::btc_buy::ParseUint(*utxo_vout, vout_n) || vout_n != input.prev_out_index ||
            !utxo_value || !veld::btc_buy::ParseUint(*utxo_value, value_n) || value_n == 0 ||
            !utxo_script || utxo_script->kind != veld::btc_buy::JsonValue::Kind::String ||
            utxo_script->text != from_script_hex || !utxo_height ||
            !veld::btc_buy::ParseUint(*utxo_height, height_n))
            return false;

        veld::btc_buy::JsonValue prev_root;
        const auto* prev_result = strict_rpc_result(
            json_rpc(host, port, "gettransaction",
                     "[\"" + prev_txid + "\",\"" + std::to_string(height_n) + "\"]"),
            prev_root, error);
        if (!prev_result || prev_result->kind != veld::btc_buy::JsonValue::Kind::Object)
            return false;
        const auto* raw_hex = prev_result->Get("raw_hex");
        const auto* returned_txid = prev_result->Get("txid");
        if (!raw_hex || raw_hex->kind != veld::btc_buy::JsonValue::Kind::String || !returned_txid ||
            returned_txid->kind != veld::btc_buy::JsonValue::Kind::String ||
            returned_txid->text != prev_txid)
            return false;
        std::vector<uint8_t> prev_bytes;
        if (!decode_lower_hex(raw_hex->text, 1000000, prev_bytes))
            return false;
        Transaction prev_tx;
        const size_t prev_consumed = Transaction::Deserialize(prev_bytes, 0, prev_tx);
        if (prev_consumed != prev_bytes.size() || prev_tx.Serialize() != prev_bytes ||
            prev_tx.GetTxID() != input.prev_tx_hash ||
            input.prev_out_index >= prev_tx.outputs.size())
            return false;
        const TxOutput& prevout = prev_tx.outputs[input.prev_out_index];
        if (prevout.value != value_n || prevout.script_pubkey != from_script ||
            prevout.value > MAX_SUPPLY_UNITS || input_sum > MAX_SUPPLY_UNITS - prevout.value)
            return false;
        input_sum += prevout.value;
        if (bytes_to_hex(ComputeSighash(tx, i, from_script).data(), 32) != sighash->text)
            return false;
    }

    if (input_sum < output_sum || input_sum - output_sum != MIN_TX_FEE ||
        claimed_total_input != input_sum || claimed_total_output != output_sum ||
        claimed_fee != MIN_TX_FEE || claimed_change != actual_change) {
        log(RED, "Validator proposal failed the exact value/fee policy");
        return false;
    }

    // Recheck immediately before creating transaction signatures. A closed
    // gate emits no signed transaction and cannot cache it for later use.
    if (is_endorse &&
        (!endorse_work_grant || !endorse_work_grant->Live(std::chrono::milliseconds(250)))) {
        log(YEL, "Endorsement held: work admission closed before transaction signing");
        return false;
    }
    for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
        if (is_endorse && (!endorse_work_grant || !endorse_work_grant->Live())) {
            log(YEL, "Endorsement held: signing deadline reached");
            return false;
        }
        tx.inputs[i].script_sig =
            BuildScriptSig(vk.privkey, vk.pubkey, tx, i, from_script).script_sig;
    }
    tx.InvalidateTxIDCache();
    const std::vector<uint8_t> signed_bytes = tx.Serialize();
    if (signed_bytes.size() > 1000000)
        return false;
    const std::string signed_hex = bytes_to_hex(signed_bytes.data(), signed_bytes.size());
    const std::string expected_txid = HashToHex(tx.GetTxID());
    // Refresh once more at the submission boundary. The signed bytes are kept
    // only on this stack and are discarded on refusal; they are never queued.
    if (is_endorse && (!endorse_work_grant || !endorse_work_grant->Live())) {
        log(YEL, "Endorsement held: work admission closed before submission");
        return false;
    }
    veld::btc_buy::JsonValue send_root;
    const std::string submit_params = is_endorse ? "[\"" + signed_hex + "\",\"" +
                                                       endorse_work_grant->binding + "\",\"" +
                                                       endorse_work_grant->token + "\"]"
                                                 : "[\"" + signed_hex + "\"]";
    const auto* sent = strict_rpc_result(json_rpc(host, port, "sendrawtransaction", submit_params),
                                         send_root, error);
    if (!sent || sent->kind != veld::btc_buy::JsonValue::Kind::String ||
        sent->text != expected_txid || !veld::btc_buy::IsLowerHex(sent->text, 64))
        return false;
    log(GRN, "Transaction broadcast: " + sent->text);
    return true;
}

static int cmd_register(const std::string& host, uint16_t port, const ValidatorKey& vk) {
    log(CYN, "Registering validator...");
    log(GRAY, "  Pubkey:  " + vk.pubkey_hex);
    log(GRAY, "  Address: " + vk.address);

    std::string vi = json_rpc(host, port, "getvalidators");
    bool sys_active = jstr(vi, "system_active") == "true";
    if (!sys_active) {
        double threshold = 0;
        try {
            threshold = std::stod(jstr(vi, "unlock_threshold_veld"));
        } catch (...) {
        }
        double staked = 0;
        try {
            staked = std::stod(jstr(vi, "total_staked_veld"));
        } catch (...) {
        }
        log(YEL, "Validator system not yet active.");
        log(GRAY, "  Required: " + std::to_string(threshold) + " VELD staked network-wide");
        log(GRAY, "  Current:  " + std::to_string(staked) + " VELD staked");
        log(GRAY, "  Registration transaction will be submitted anyway and will");
        log(GRAY, "  activate automatically once the threshold is reached.");
    }

    std::string si = json_rpc(host, port, "getstakingaddr", "[\"" + vk.address + "\"]");
    double staked_veld = 0;
    try {
        staked_veld = std::stod(jstr(si, "staked_veld"));
    } catch (...) {
    }
    double min_stake = (double)MIN_VALIDATOR_STAKE / VELD_UNITS;
    if (staked_veld < min_stake) {
        log(RED, "Insufficient stake at " + vk.address);
        log(GRAY, "  Required: " + std::to_string(min_stake) + " VELD staked");
        log(GRAY, "  Current:  " + std::to_string(staked_veld) + " VELD staked");
        return 1;
    }

    std::string op = ValidatorRegistry::BuildRegisterOp(vk.pubkey_hex);
    if (!broadcast_op_return(host, port, vk.address, op, vk)) {
        log(RED, "Registration failed.");
        return 1;
    }
    log(GRN, "Registration transaction broadcast successfully.");
    log(GRAY, "  The network will confirm your validator registration in the next block.");
    return 0;
}

static int cmd_deregister(const std::string& host, uint16_t port, const ValidatorKey& vk) {
    log(CYN, "Deregistering validator...");
    std::string op = ValidatorRegistry::BuildDeregisterOp(vk.pubkey_hex);
    if (!broadcast_op_return(host, port, vk.address, op, vk)) {
        log(RED, "Deregistration failed.");
        return 1;
    }
    log(GRN, "Deregistration transaction broadcast successfully.");
    return 0;
}

static int cmd_status(const std::string& host, uint16_t port, const ValidatorKey& vk) {
    std::string ci = json_rpc(host, port, "getblockchaininfo");
    uint64_t height = juint(ci, "blocks");
    double supply = 0;
    try {
        supply = std::stod(jstr(ci, "supply_veld"));
    } catch (...) {
    }

    std::string vi = json_rpc(host, port, "getvalidators");
    bool sys_active = jstr(vi, "system_active") == "true";
    double threshold = 0, net_staked = 0;
    try {
        threshold = std::stod(jstr(vi, "unlock_threshold_veld"));
    } catch (...) {
    }
    try {
        net_staked = std::stod(jstr(vi, "total_staked_veld"));
    } catch (...) {
    }
    uint64_t val_count = juint(vi, "validator_count");

    std::string myvi = json_rpc(host, port, "getvalidatorinfo", "[\"" + vk.pubkey_hex + "\"]");
    bool registered = jstr(myvi, "registered") == "true";

    std::string si = json_rpc(host, port, "getstakingaddr", "[\"" + vk.address + "\"]");
    double our_stake = 0;
    try {
        our_stake = std::stod(jstr(si, "staked_veld"));
    } catch (...) {
    }

    std::cout << "\n";
    std::cout << CYN << "── Veld Validator Status ─────────────────\n" << RST;
    std::cout << "  Node height:       " << height << "\n";
    std::cout << "  Supply:            " << std::fixed << std::setprecision(2) << supply
              << " VELD\n";
    std::cout << "\n";
    std::cout << "  Validator system:  "
              << (sys_active ? (std::string(GRN) + "ACTIVE") : (std::string(YEL) + "LOCKED")) << RST
              << "\n";
    std::cout << "  Network staked:    " << net_staked << " / " << threshold << " VELD required\n";
    std::cout << "  Active validators: " << val_count << "\n";
    std::cout << "\n";
    std::cout << "  Our pubkey:        " << vk.pubkey_hex.substr(0, 20) << "...\n";
    std::cout << "  Our address:       " << vk.address << "\n";
    std::cout << "  Our stake:         " << our_stake << " VELD";
    if (our_stake < (double)MIN_VALIDATOR_STAKE / VELD_UNITS)
        std::cout << RED << "  (below 10,000 VELD mainnet minimum)" << RST;
    std::cout << "\n";
    std::cout << "  Registration:      "
              << (registered ? (std::string(GRN) + "REGISTERED")
                             : (std::string(RED) + "NOT REGISTERED"))
              << RST << "\n";
    std::cout << "\n";
    return 0;
}

static std::string sign_block(const Secp256k1PrivKey& privkey, uint64_t height,
                              const std::string& block_hash_hex) {
    auto hash_bytes = from_hex(block_hash_hex);
    if (hash_bytes.size() != 32)
        return "";
    Hash256 block_hash;
    std::copy(hash_bytes.begin(), hash_bytes.end(), block_hash.begin());

    Hash256 msg = ValidatorRegistry::BuildEndorseMessage(height, block_hash);
    auto sig = Sign(privkey, msg);
    return bytes_to_hex(sig.data(), sig.size());
}

static int run_daemon(const std::string& host, uint16_t port, const ValidatorKey& vk,
                      const std::string& keyfile) {
    log(GRN, "Validator daemon started");
    log(GRAY, "  Pubkey:  " + vk.pubkey_hex);
    log(GRAY, "  Address: " + vk.address);
    log(GRAY, "  Node:    " + host + ":" + std::to_string(port));
    std::cout << "\n";

    //  persistent anti-equivocation guard, co-located with the keyfile so
    // it survives restarts. Refuses to sign a second (different-hash)
    // endorsement at a height already endorsed — the slashable pattern a reorg
    // would otherwise trigger. See include/compat/endorse_guard.h.
    EndorseAntiEquivGuard endorse_guard;
    endorse_guard.load(keyfile + ".endorsed");

    // The same 32-byte validator seed deterministically expands to the full
    // ML-DSA secret key used by finality votes. Refuse startup unless the
    // derived public key is byte-for-byte the registered validator identity.
    veld::dilithium::PublicKey finality_pk{};
    veld::dilithium::SecretKey finality_sk{};
    veld::compat::SecureLockMemory(finality_sk.data(), finality_sk.size());
    if (veld_mldsa65_keypair_from_seed(vk.privkey.data(), finality_pk.data(), finality_sk.data()) !=
            0 ||
        !std::equal(finality_pk.begin(), finality_pk.end(), vk.pubkey.begin())) {
        veld::compat::SecureZero(finality_sk.data(), finality_sk.size());
        veld::compat::SecureUnlockMemory(finality_sk.data(), finality_sk.size());
        log(RED, "Finality key derivation does not match validator identity");
        return 1;
    }

    const std::string finality_dir = keyfile + ".finality-state";
    const std::string finality_journal =
        (std::filesystem::path(finality_dir) / "journal.bin").string();
    std::string journal_error;
    if (!veld::channel::secure_file::EnsurePrivateDirectory(finality_dir, &journal_error)) {
        veld::compat::SecureZero(finality_sk.data(), finality_sk.size());
        veld::compat::SecureUnlockMemory(finality_sk.data(), finality_sk.size());
        log(RED, "Cannot create private finality journal directory: " + journal_error);
        return 1;
    }

    std::optional<fq::FinalizedRecord> cached_finalized;
    fq::DaemonHooks finality_hooks;
    finality_hooks.fetch_snapshot = [&](uint64_t target_epoch) -> std::optional<fq::EpochSnapshot> {
        auto frame = fetch_finality_frame(host, port, target_epoch);
        if (!frame) {
            cached_finalized.reset();
            return std::nullopt;
        }
        cached_finalized = frame->finalized;
        return std::move(frame->snapshot);
    };
    finality_hooks.fetch_tip_height = [&]() { return fetch_rpc_tip(host, port); };
    finality_hooks.fetch_block_hash = [&](uint64_t height) {
        return fetch_rpc_block_hash(host, port, height);
    };
    finality_hooks.authorize_work = [&](const fq::CheckpointRef& target) {
        auto grant = fetch_work_admission(host, port, veld::work_admission::Purpose::FinalityVote,
                                          target.height, target.hash);
        if (!grant)
            log(YEL, "Finality vote held: authoritative work admission closed");
        if (!grant)
            return std::optional<fq::DaemonWorkGrant>{};
        fq::DaemonWorkGrant daemon_grant;
        daemon_grant.binding = std::move(grant->binding);
        daemon_grant.token = std::move(grant->token);
        daemon_grant.deadline = grant->deadline;
        return std::optional<fq::DaemonWorkGrant>(std::move(daemon_grant));
    };
    finality_hooks.cancel_work = [&](const fq::DaemonWorkGrant& grant) {
        (void)cancel_work_signing(host, port, grant.token);
    };
    finality_hooks.gossip_vote = [&](const fq::SignedVote& vote, const fq::DaemonWorkGrant& grant) {
        WorkAdmissionGrant transport_grant;
        transport_grant.binding = grant.binding;
        transport_grant.token = grant.token;
        transport_grant.deadline = grant.deadline;
        return submit_finality_vote(host, port, vote, transport_grant);
    };
    finality_hooks.persist_journal = [&](const fq::DaemonJournal& journal) {
        auto bytes = encode_finality_journal(journal);
        std::string why;
        const bool ok = !bytes.empty() && veld::channel::secure_file::AtomicWrite(
                                              finality_journal, bytes, &why, true);
        veld::compat::SecureZero(bytes.data(), bytes.size());
        if (!ok)
            log(RED, "Finality journal durable write failed: " + why);
        return ok;
    };
    finality_hooks.load_journal = [&]() -> std::optional<fq::DaemonJournal> {
        std::vector<uint8_t> bytes;
        std::string why;
        const auto result =
            veld::channel::secure_file::Read(finality_journal, bytes, &why, 64u * 1024u, true);
        if (result == veld::channel::secure_file::ReadResult::NotFound)
            return std::nullopt;
        if (result == veld::channel::secure_file::ReadResult::Error) {
            log(RED, "Finality journal read failed: " + why);
            fq::DaemonJournal invalid;
            invalid.version = 0; // constructor latches fail-closed
            return invalid;
        }
        auto journal = decode_finality_journal(bytes);
        veld::compat::SecureZero(bytes.data(), bytes.size());
        if (!journal) {
            log(RED, "Finality journal is malformed; voting disabled");
            fq::DaemonJournal invalid;
            invalid.version = 0;
            return invalid;
        }
        return journal;
    };
    finality_hooks.fetch_finalized = [&]() { return cached_finalized; };
    finality_hooks.fetch_prevote_qc = [&](const fq::EpochSnapshot&) {
        return fetch_prevote_qc(host, port);
    };
    finality_hooks.authorize_target = [&](const fq::CheckpointRef& target) {
        const bool ok = authorize_finality_target_observations(host, port, target);
        if (!ok)
            log(YEL, "Finality vote held: Bitcoin observation not independently confirmed");
        return ok;
    };

    std::unique_ptr<fq::FinalityDaemon> finality_daemon;
    try {
        finality_daemon = std::make_unique<fq::FinalityDaemon>(
            vk.pubkey_hex, finality_sk, fq::NETWORK_ID, compiled_genesis_bytes(),
            std::move(finality_hooks));
    } catch (const std::exception& e) {
        veld::compat::SecureZero(finality_sk.data(), finality_sk.size());
        veld::compat::SecureUnlockMemory(finality_sk.data(), finality_sk.size());
        log(RED, "Finality daemon initialization failed: " + std::string(e.what()));
        return 1;
    }
    veld::compat::SecureZero(finality_sk.data(), finality_sk.size());
    veld::compat::SecureUnlockMemory(finality_sk.data(), finality_sk.size());

    uint64_t last_endorsed_height = 0;
    uint64_t consecutive_errors = 0;

    while (g_running) {
        try {
            std::string ci = json_rpc(host, port, "getblockchaininfo");
            uint64_t height = juint(ci, "blocks");
            std::string block_hash = jstr(ci, "best_block_hash");
            if (block_hash.empty())
                block_hash = jstr(ci, "bestblockhash");

            if (height == 0 || block_hash.empty()) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                continue;
            }

            std::string vi = json_rpc(host, port, "getvalidators");
            bool sys_active = jstr(vi, "system_active") == "true";
            if (!sys_active) {
                double threshold = 0, current = 0;
                try {
                    threshold = std::stod(jstr(vi, "unlock_threshold_veld"));
                } catch (...) {
                }
                try {
                    current = std::stod(jstr(vi, "total_staked_veld"));
                } catch (...) {
                }
                log(GRAY, "Validator system locked. Network: " + std::to_string((int)current) +
                              " / " + std::to_string((int)threshold) + " VELD staked.");
                std::this_thread::sleep_for(std::chrono::seconds(30));
                consecutive_errors = 0;
                continue;
            }

            std::string myvi =
                json_rpc(host, port, "getvalidatorinfo", "[\"" + vk.pubkey_hex + "\"]");
            bool registered = jstr(myvi, "registered") == "true";
            if (!registered) {
                log(YEL, "Not registered as validator. Run --register first.");
                std::this_thread::sleep_for(std::chrono::seconds(30));
                continue;
            }

            // Drives PREVOTE/PRECOMMIT production. The daemon persists its
            // complete lock+last-vote frame before submitfinalityvote, and the
            // node treats exact retry bytes as idempotent success.
            if (finality_daemon->Tick())
                log(GRN, "Finality vote accepted by local node");

            {
                std::string ei = json_rpc(host, port, "getblockendorsements",
                                          "[\"" + std::to_string(height) + "\"]");
                bool already_endorsed = ei.find(vk.pubkey_hex) != std::string::npos;

                //  refuse to sign a DIFFERENT block hash at a height we
                // already endorsed (reorg) — that pair is slashable equivocation.
                // Record (fsync) BEFORE signing so a crash only loses an
                // endorsement, never creates an equivocating one.
                std::string eq_key = std::to_string(height) + ":" + vk.pubkey_hex;
                if (endorse_guard.would_equivocate(eq_key, block_hash)) {
                    log(YEL, "Skipping h=" + std::to_string(height) +
                                 " — already endorsed a different block hash here (reorg); "
                                 "refusing to equivocate (would be slashable).");
                    last_endorsed_height = height;
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    continue;
                }

                if (!already_endorsed) {
                    Hash256 endorsement_hash{};
                    const auto endorsement_work =
                        lower_hex_hash(block_hash, endorsement_hash)
                            ? fetch_work_admission(
                                  host, port, veld::work_admission::Purpose::ValidatorEndorsement,
                                  height, endorsement_hash)
                            : std::nullopt;
                    if (!endorsement_work) {
                        log(YEL, "Endorsement held: authoritative work admission closed");
                        std::this_thread::sleep_for(std::chrono::seconds(5));
                        continue;
                    }
                    WorkGrantCancelGuard endorsement_release(host, port, *endorsement_work);
                    if (!endorse_guard.record(eq_key, block_hash)) {
                        ++consecutive_errors;
                        log(RED, "Refusing to sign block " + std::to_string(height) +
                                     " because the anti-equivocation journal could not "
                                     "durably record it (or already records a conflict).");
                        std::this_thread::sleep_for(std::chrono::seconds(5));
                        continue;
                    }
                    // The acquired-first node reservation remains live across
                    // journal -> signature -> submission. Canonical/state
                    // transitions defer until this one-use grant is consumed
                    // or reaches its bounded deadline.
                    if (!endorsement_work->Live(std::chrono::milliseconds(1000))) {
                        log(YEL, "Endorsement held: signing lease expired before signing");
                        std::this_thread::sleep_for(std::chrono::seconds(5));
                        continue;
                    }
                    std::string sig_hex = sign_block(vk.privkey, height, block_hash);
                    if (sig_hex.empty()) {
                        log(RED, "Failed to sign block " + std::to_string(height));
                    } else {
                        std::string op =
                            ValidatorRegistry::BuildEndorseOp(height, block_hash, sig_hex);

                        if (broadcast_op_return(host, port, vk.address, op, vk,
                                                &*endorsement_work)) {
                            log(GRN, "Endorsed block #" + std::to_string(height) + " | " +
                                         block_hash.substr(0, 16) + "...");
                            last_endorsed_height = height;
                        } else {

                            consecutive_errors++;
                            log(RED, "Failed to broadcast endorsement for block " +
                                         std::to_string(height));
                        }
                    }
                } else {
                    last_endorsed_height = height;
                }
            }

            consecutive_errors = 0;

        } catch (const std::exception& e) {
            consecutive_errors++;
            log(RED, "Error: " + std::string(e.what()));
            if (consecutive_errors >= 5)
                log(YEL, "Multiple consecutive errors — check node connection");
        }

        int sleep_secs = 5;
        if (consecutive_errors > 10) {
            int shift = consecutive_errors - 10;
            if (shift > 6)
                shift = 6;
            int backoff = 5 * (1 << shift);
            if (backoff > 300)
                backoff = 300;
            sleep_secs = backoff;
        }
        std::this_thread::sleep_for(std::chrono::seconds(sleep_secs));
    }

    log(GRAY, "Validator daemon stopped.");
    return 0;
}

static bool load_rpc_token_via_node() {
    try {
        const std::string executable = veld::compat::ExecutablePath();
        if (executable.empty())
            return false;
        const auto self = std::filesystem::path(executable);
        const auto sibling = self.parent_path() /
#ifdef _WIN32
                             "veld-node.exe";
#else
                             "veld-node";
#endif
        if (!std::filesystem::exists(sibling) || std::filesystem::is_directory(sibling))
            return false;
        g_node_binary = sibling.string();
        g_datadir = std::filesystem::absolute(g_datadir).lexically_normal().string();
    } catch (...) {
        return false;
    }
    auto result = veld::compat::RunProcess(
        {g_node_binary, "--print-rpc-token", "--datadir", g_datadir}, true, {}, false, 65536);
    if (result.exit_code != 0 || result.output_truncated || result.output.empty() ||
        result.output.size() > 65536) {
        veld::compat::SecureZero(result.output.data(), result.output.size());
        return false;
    }
    while (!result.output.empty() &&
           (result.output.back() == '\r' || result.output.back() == '\n' ||
            result.output.back() == ' ' || result.output.back() == '\t'))
        result.output.pop_back();
    size_t line = result.output.rfind('\n');
    std::string token = line == std::string::npos ? result.output : result.output.substr(line + 1);
    if (!token.empty() && token.back() == '\r')
        token.pop_back();
    bool valid = token.size() == 64;
    for (char c : token)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            valid = false;
    if (valid)
        g_rpc_token = token;
    veld::compat::SecureZero(token.data(), token.size());
    veld::compat::SecureZero(result.output.data(), result.output.size());
    return valid;
}

static void PrintDeploymentInfoJson() {
    std::cout << "VELD_DEPLOYMENT_INFO_V1_JSON {"
              << "\"binary_role\":\"validator-finality-daemon\","
              << "\"client_version\":\"" << CLIENT_VERSION << "\","
              << "\"display_name\":\"" << DEPLOYMENT_DISPLAY_NAME << "\","
              << "\"disposable\":" << (DEPLOYMENT_DISPOSABLE ? "true" : "false") << ","
              << "\"external_value\":" << (DEPLOYMENT_EXTERNAL_VALUE ? "true" : "false") << ","
              << "\"finality_bond_units\":" << veld::finality::qc::BOND_PER_KEY_UNITS << ","
              << "\"finality_min_validators\":" << veld::finality::qc::MIN_VALIDATOR_COUNT << ","
              << "\"fleet_no_mine\":false,"
              << "\"genesis_fingerprint\":\"" << GENESIS_HASH << "\","
              << "\"mainnet_magic\":" << MAINNET_MAGIC << ","
              << "\"profile_id\":\"" << DEPLOYMENT_PROFILE_ID << "\","
              << "\"protocol_version\":" << PROTOCOL_VERSION << ","
              << "\"remote_rpc_transport\":\"loopback-bearer-via-node-helper\","
              << "\"role\":\"" << DEPLOYMENT_ROLE << "\","
              << "\"storage_backend\":\"private-files\","
              << "\"warning\":\"" << DEPLOYMENT_WARNING << "\""
              << "}\n";
}

int main(int argc, char* argv[]) {
    veld::compat::HardenDllSearchPath();

    // Pure identity probes precede socket setup, signal handlers, key access,
    // datadir access, and RPC so build/package controllers can safely attest
    // the exact standalone daemon artifact.
    if (argc == 2 && (std::string(argv[1]) == "--version" || std::string(argv[1]) == "-V")) {
        std::cout << "Veld Validator " << CLIENT_VERSION << "\n";
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--deployment-info") {
        PrintDeploymentInfoJson();
        return 0;
    }
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    std::string keyfile = "validator.key";
    std::string rpc_host = "127.0.0.1";
    uint16_t rpc_port = 8334;
    std::string wallet_address;
    std::string cmd;
    bool allow_plaintext_key = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--keyfile" && i + 1 < argc)
            keyfile = argv[++i];
        else if (arg == "--rpchost" && i + 1 < argc)
            rpc_host = argv[++i];
        else if (arg == "--rpcport" && i + 1 < argc) {
            try {
                std::string value = argv[++i];
                size_t consumed = 0;
                unsigned long parsed = std::stoul(value, &consumed);
                if (consumed != value.size() || parsed == 0 || parsed > 65535)
                    throw std::out_of_range("port");
                rpc_port = static_cast<uint16_t>(parsed);
            } catch (...) {
                std::cerr << RED << "FATAL: --rpcport must be an integer in 1..65535\n" << RST;
                return 2;
            }
        } else if (arg == "--datadir" && i + 1 < argc)
            g_datadir = argv[++i];
        else if (arg == "--bitcoin-cli" && i + 1 < argc)
            g_bitcoin_cli = argv[++i];
        else if (arg == "--address" && i + 1 < argc)
            wallet_address = argv[++i];
        else if (arg == "--genkey")
            cmd = "genkey";
        else if (arg == "--register")
            cmd = "register";
        else if (arg == "--deregister")
            cmd = "deregister";
        else if (arg == "--status")
            cmd = "status";
        else if (arg == "--allow-plaintext-key")
            allow_plaintext_key = true;
        else if (arg == "--help" || arg == "-h") {
            std::cout
                << "Usage: veld-validator [options] [command]\n\n"
                << "Options:\n"
                << "  --keyfile <path>          Validator key file (default: validator.key)\n"
                << "  --rpchost 127.0.0.1       Authenticated RPC is loopback-only\n"
                << "  --rpcport <port>          Node RPC port (default: 8334)\n"
                << "  --datadir <path>          Node data directory (default: ./veld-data)\n"
                << "  --bitcoin-cli <path>      Bitcoin Core bitcoin-cli (default: bitcoin-cli)\n"
                << "  --allow-plaintext-key     (INSECURE) allow loading a plaintext key.\n"
                << "                            Use only for migration; re-create with --genkey "
                   "ASAP.\n\n"
                << "  --version                 Print the client release version\n"
                << "  --deployment-info         Print compiled role/network identity; exit\n\n"
                << "Commands (default: run endorsement daemon):\n"
                << "  --genkey [--address <V...>] Generate a keypair and its bound funding "
                   "address\n"
                << "  --register                  Register as a validator on-chain\n"
                << "  --deregister                Deregister from the validator set\n"
                << "  --status                    Print registration and stake status\n";
            return 0;
        }
    }

    if (cmd == "genkey")
        return cmd_genkey(keyfile, wallet_address);

    if (rpc_host != "127.0.0.1") {
        std::cerr << RED
                  << "FATAL: bearer-authenticated validator RPC is restricted "
                     "to 127.0.0.1; remote/plaintext RPC is forbidden.\n"
                  << RST;
        return 1;
    }
    if (!load_rpc_token_via_node()) {
        std::cerr << RED
                  << "FATAL: cannot obtain RPC token via veld-node --print-rpc-token. "
                     "Check --datadir and VELD_VAULT_PASSPHRASE.\n"
                  << RST;
        return 1;
    }
    log(GRAY, "RPC token loaded via local node helper");

    ValidatorKey vk;
    std::string pass;
    if (ValidatorKey::IsEncrypted(keyfile)) {
        if (const char* env = std::getenv("VELD_VAULT_PASSPHRASE")) {
            pass = env;
            veld::compat::UnsetEnv("VELD_VAULT_PASSPHRASE");
        } else {
            std::cout << "  Keyfile is encrypted. Enter passphrase to unlock.\n";
            pass = ask_passphrase(false);
        }
        if (pass.empty()) {
            std::cerr << RED << "Aborted: empty passphrase.\n" << RST;
            return 1;
        }
    } else {
        std::ifstream probe(keyfile);
        if (probe.good() && !allow_plaintext_key) {
            std::cerr << RED << "FATAL: " << keyfile << " is a PLAINTEXT key file.\n"
                      << "       Re-create with --genkey (encrypts with a passphrase),\n"
                      << "       or pass --allow-plaintext-key to load it anyway (INSECURE).\n"
                      << RST;
            return 1;
        }
    }
    bool loaded = vk.Load(keyfile, pass);
    veld::compat::SecureZero(pass.data(), pass.size());
    if (!loaded) {
        std::cerr << RED << "Error: cannot load keyfile: " << keyfile << "\n"
                  << "Wrong passphrase, corrupted file, or missing — run --genkey to create one.\n"
                  << RST;
        return 1;
    }

    if (cmd == "register")
        return cmd_register(rpc_host, rpc_port, vk);
    else if (cmd == "deregister")
        return cmd_deregister(rpc_host, rpc_port, vk);
    else if (cmd == "status")
        return cmd_status(rpc_host, rpc_port, vk);
    else {
        return run_daemon(rpc_host, rpc_port, vk, keyfile);
    }
}
