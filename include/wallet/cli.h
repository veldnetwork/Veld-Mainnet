#pragma once
#include "wallet_crypto.h"
#include "passphrase_policy.h"
#include "secure_channel_file.h"
#include "../crypto/veld_signing.h"
#include "../core/blockchain.h"
#include "../core/mempool.h"
#include "../core/constants.h"
#include "../core/version.h"
#include "../network/chainparams.h"
#include "../wallet/wallet.h"
#include "../compat/secure_string.h"
#include <string>
#include <algorithm>
#include <vector>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <thread>
#include <chrono>
#include <cerrno>
#include <limits>
#include <optional>
#include <string_view>
#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace veld {
namespace cli {

namespace fs = std::filesystem;

#ifndef _WIN32
struct TermiosNoEchoGuard {
    struct termios saved_;
    bool           active_;
    explicit TermiosNoEchoGuard() : saved_{}, active_(false) {
        if (tcgetattr(STDIN_FILENO, &saved_) != 0) return;
        struct termios noecho = saved_;
        noecho.c_lflag &= ~(tcflag_t)(ECHO | ECHOE | ECHOK | ECHONL);
        if (tcsetattr(STDIN_FILENO, TCSANOW, &noecho) != 0) return;
        active_ = true;
    }
    ~TermiosNoEchoGuard() {
        if (active_) tcsetattr(STDIN_FILENO, TCSANOW, &saved_);
    }
    TermiosNoEchoGuard(const TermiosNoEchoGuard&)            = delete;
    TermiosNoEchoGuard& operator=(const TermiosNoEchoGuard&) = delete;
};
#endif

inline SecureString ReadPassword(const std::string& prompt) {
    std::cout << prompt << std::flush;
    SecureString pw;
    pw.reserve(128);
#ifdef _WIN32
    int c;
    while ((c = _getch()) != 13) {
        if (c == 8) { if (!pw.empty()) { pw.pop_back(); std::cout << "\b \b" << std::flush; } }
        else if (c >= 32) { pw += (char)c; std::cout << '*' << std::flush; }
    }
    std::cout << "\n";
#else
    {
        TermiosNoEchoGuard guard;
        int ch;
        while ((ch = std::getchar()) != EOF && ch != '\n' && ch != '\r') {
            if (ch == 127 || ch == 8) { if (!pw.empty()) pw.pop_back(); }
            else if (ch >= 32 && pw.size() < pw.capacity()) pw += (char)ch;
        }
    }
    std::cout << "\n";
#endif
    return pw;
}

struct SecureStringBridge {
    std::string value;
    SecureStringBridge() = default;
    explicit SecureStringBridge(const SecureString& s) : value(s.data(), s.size()) {}
    SecureStringBridge(SecureStringBridge&& o) noexcept : value(std::move(o.value)) { o.value.clear(); }
    SecureStringBridge& operator=(SecureStringBridge&& o) noexcept {
        veld::WipeString(value);
        value = std::move(o.value);
        o.value.clear();
        return *this;
    }
    SecureStringBridge(const SecureStringBridge&) = delete;
    SecureStringBridge& operator=(const SecureStringBridge&) = delete;
    ~SecureStringBridge() { veld::WipeString(value); }
};

inline SecureStringBridge SecureToStdString(const SecureString& s) {
    return SecureStringBridge(s);
}

struct WalletFile {
    static constexpr size_t MAX_WALLET_FILE_BYTES = 8u * 1024u * 1024u;
    static constexpr size_t MAX_WALLET_KEYS = 4096;

    std::vector<RealKeyPair> keys;
    bool testnet = false;

    std::string Serialize() const {
        std::ostringstream ss;
        ss << "veld_wallet_v2\n";
        ss << "testnet=" << (testnet ? "1" : "0") << "\n";
        ss << "keys=" << keys.size() << "\n";
        for (size_t i = 0; i < keys.size(); ++i) {
            ss << "key" << i << "_priv=";
            for (auto b : keys[i].private_key)
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
            ss << "\n";
            ss << "key" << i << "_addr=" << keys[i].address << "\n";
        }
        return ss.str();
    }

    bool Save(const std::string& path, const std::string& password) const {
        if (keys.size() > MAX_WALLET_KEYS) return false;
        std::string plain = Serialize();
        if (plain.size() > MAX_WALLET_FILE_BYTES - 12) {
            veld::WipeString(plain);
            return false;
        }
        auto encrypted = wallet_crypto::EncryptWallet(plain, password);
        veld::WipeString(plain);
        static constexpr char magic[] = "VELDWALLET2\n";
        std::vector<uint8_t> payload;
        payload.reserve((sizeof(magic) - 1) + encrypted.size());
        payload.insert(payload.end(), magic, magic + sizeof(magic) - 1);
        payload.insert(payload.end(), encrypted.begin(), encrypted.end());
        if (!encrypted.empty())
            VELD_SECURE_BZERO(encrypted.data(), encrypted.size());
        std::string error;
        // Wallets may live directly in an owner-controlled 0755 home/cwd;
        // require owner control of the parent and an owner-only 0600 file, but
        // reserve mandatory 0700 parents for node operational secret dirs.
        const bool ok = channel::secure_file::AtomicWrite(
            path, payload, &error, /*require_private_parent=*/false);
        if (!payload.empty()) VELD_SECURE_BZERO(payload.data(), payload.size());
        return ok;
    }

    // Strict, allocation-bounded plaintext parser.  Keeping this separate from
    // decryption makes the grammar directly regression-testable and avoids the
    // old vector-of-lines amplification (an 8 MiB file containing only newlines
    // could allocate hundreds of MiB before it was rejected).
    static std::optional<WalletFile> ParsePlaintext(std::string_view plain) {
        if (plain.size() > MAX_WALLET_FILE_BYTES) return std::nullopt;

        size_t cursor = 0;
        auto next_line = [&](std::string_view& line) -> bool {
            if (cursor >= plain.size()) return false;
            const size_t nl = plain.find('\n', cursor);
            if (nl == std::string_view::npos) {
                line = plain.substr(cursor);
                cursor = plain.size() + 1; // no terminal newline
            } else {
                line = plain.substr(cursor, nl - cursor);
                cursor = nl + 1;
            }
            if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
            return true;
        };

        std::string_view header, network, count_line;
        if (!next_line(header) || !next_line(network) || !next_line(count_line)
            || header != "veld_wallet_v2"
            || (network != "testnet=0" && network != "testnet=1")
            || count_line.substr(0, 5) != "keys=")
            return std::nullopt;

        const std::string_view count_text = count_line.substr(5);
        if (count_text.empty() || (count_text.size() > 1 && count_text[0] == '0'))
            return std::nullopt;
        size_t count = 0;
        for (char c : count_text) {
            if (c < '0' || c > '9') return std::nullopt;
            const size_t digit = static_cast<size_t>(c - '0');
            if (count > (MAX_WALLET_KEYS - digit) / 10) return std::nullopt;
            count = count * 10 + digit;
        }
        if (count > MAX_WALLET_KEYS) return std::nullopt;

        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        WalletFile wf;
        wf.testnet = network.back() == '1';
        wf.keys.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            std::string_view priv_line, addr_line;
            if (!next_line(priv_line) || !next_line(addr_line)) return std::nullopt;
            const std::string priv_prefix = "key" + std::to_string(i) + "_priv=";
            const std::string addr_prefix = "key" + std::to_string(i) + "_addr=";
            if (priv_line.substr(0, priv_prefix.size()) != priv_prefix
                || addr_line.substr(0, addr_prefix.size()) != addr_prefix)
                return std::nullopt;
            const std::string_view hex = priv_line.substr(priv_prefix.size());
            const std::string_view file_addr = addr_line.substr(addr_prefix.size());
            if (hex.size() != 64 || file_addr.empty() || file_addr.size() > 128)
                return std::nullopt;

            Secp256k1PrivKey priv{};
            struct PrivWiper {
                Secp256k1PrivKey& value;
                ~PrivWiper() { veld::compat::SecureZero(value.data(), value.size()); }
            } wipe_priv{priv};
            for (size_t b = 0; b < priv.size(); ++b) {
                const int hi = nibble(hex[b * 2]);
                const int lo = nibble(hex[b * 2 + 1]);
                if (hi < 0 || lo < 0) return std::nullopt;
                priv[b] = static_cast<uint8_t>((hi << 4) | lo);
            }
            try {
                const auto pub = DerivePublicKey(priv);
                const std::string derived = PubKeyToAddress(pub, wf.testnet);
                if (derived != file_addr) return std::nullopt;
                RealKeyPair kp;
                kp.testnet = wf.testnet;
                kp.private_key = priv;
                kp.public_key = pub;
                kp.address = derived;
                wf.keys.push_back(std::move(kp));
            } catch (...) {
                return std::nullopt;
            }
        }

        // Accept either EOF immediately after the final address or one final
        // LF/CRLF, but reject blank lines, appended records, and hidden data.
        if (cursor < plain.size()) return std::nullopt;
        return wf;
    }

    static std::optional<WalletFile> Load(const std::string& path, const std::string& password) {
        std::vector<uint8_t> raw;
        std::string error;
        if (channel::secure_file::Read(
                path, raw, &error, MAX_WALLET_FILE_BYTES,
                /*require_private_parent=*/false)
            != channel::secure_file::ReadResult::Ok)
            return std::nullopt;
        static constexpr char magic[] = "VELDWALLET2\n";
        if (raw.size() < sizeof(magic) - 1
            || !std::equal(magic, magic + sizeof(magic) - 1, raw.begin()))
            return std::nullopt;
        std::vector<uint8_t> encrypted(
            raw.begin() + static_cast<std::ptrdiff_t>(sizeof(magic) - 1), raw.end());

        std::string plain;
        try {
            plain = wallet_crypto::DecryptWallet(encrypted, password);
        } catch (...) {
            return std::nullopt;
        }
        struct PlainWiper {
            std::string& s;
            ~PlainWiper() { veld::WipeString(s); }
        } wipe_plain{plain};
        return ParsePlaintext(plain);
    }
};

inline void RunWalletCLI(const std::string& wallet_path) {
    std::cout << "\n";
    std::cout << "  ╔══════════════════════════════════════╗\n";
    std::cout << "  ║         VELD WALLET MANAGER          ║\n";
    std::cout << "  ╚══════════════════════════════════════╝\n";
    std::cout << "  Wallet: " << wallet_path << "\n\n";

    bool exists = fs::exists(wallet_path);

    if (!exists) {
        std::cout << "  No wallet found. Creating a new one.\n\n";

        SecureString pw, pw2;
        while (true) {
            pw  = ReadPassword("  Set wallet password: ");
            pw2 = ReadPassword("  Confirm password:    ");
            auto policy_bridge = SecureToStdString(pw);
            std::string policy_error;
            const bool policy_ok = wallet_crypto::ValidateNewPassphrase(
                policy_bridge.value, &policy_error);
            if (veld::ConstantTimeEquals(pw, pw2) && policy_ok) break;
            if (!veld::ConstantTimeEquals(pw, pw2))
                std::cout << "  ✗ Passwords don't match. Try again.\n\n";
            else
                std::cout << "  Password rejected: " << policy_error << "\n\n";
        }

        RealKeyPair kp = GenerateKeyPair(false);

        WalletFile wf;
        wf.keys.push_back(kp);

        std::cout << "\n  Encrypting wallet (this takes a moment)...\n";
        bool saved;
        {
            auto pw_bridge = SecureToStdString(pw);
            saved = wf.Save(wallet_path, pw_bridge.value);
        }
        if (!saved) {
            std::cout << "  ✗ Failed to save wallet file.\n";
            return;
        }

        std::cout << "\n  ✓ Wallet created and encrypted.\n\n";
        std::cout << "  ┌─────────────────────────────────────────┐\n";
        std::cout << "  │  Address:  " << kp.address << "  │\n";
        std::cout << "  └─────────────────────────────────────────┘\n\n";
        std::cout << "  ⚠  Your wallet is encrypted with your password.\n";
        std::cout << "     If you forget your password, your funds are UNRECOVERABLE.\n";
        std::cout << "     Back up your wallet file: " << wallet_path << "\n\n";

    } else {
        std::cout << "  Wallet file found. Enter password to unlock.\n\n";

        std::optional<WalletFile> wf_opt;
        SecureString unlock_pw;

        constexpr int MAX_ATTEMPTS = 5;
        int fail_count = 0;
        for (int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
            if (fail_count > 0) {
                int backoff_sec = (1 << fail_count) - 1;
                if (backoff_sec > 30) backoff_sec = 30;
                std::cout << "  [retry-backoff] waiting " << backoff_sec
                          << "s before next attempt...\n";
                std::cout.flush();
                std::this_thread::sleep_for(std::chrono::seconds(backoff_sec));
            }
            auto pw = ReadPassword("  Password: ");
            std::cout << "  Decrypting...\n";
            {
                auto bridge = SecureToStdString(pw);
                wf_opt = WalletFile::Load(wallet_path, bridge.value);
            }
            if (wf_opt) { unlock_pw = std::move(pw); break; }
            ++fail_count;
            int remaining = MAX_ATTEMPTS - 1 - attempt;
            if (remaining > 0) {
                std::cout << "  ✗ Wrong password. " << remaining
                          << " attempt(s) remaining.\n\n";
            } else {
                std::cout << "  ✗ Wrong password. Too many failed attempts; "
                          << "exiting. Re-run to try again.\n\n";
            }
        }

        if (wf_opt) {
            // Re-open with the same bounded/no-follow/owner-only policy as
            // Load.  A plain ifstream here reintroduced a post-unlock symlink
            // race solely to inspect one version byte.
            std::vector<uint8_t> header;
            std::string header_error;
            if (channel::secure_file::Read(
                    wallet_path, header, &header_error,
                    WalletFile::MAX_WALLET_FILE_BYTES,
                    /*require_private_parent=*/false)
                    == channel::secure_file::ReadResult::Ok
                && header.size() > 14) {
                const bool is_current =
                    header[14] == veld::wallet_crypto::VELD_WALLET_VERSION_CURRENT;
                if (!is_current) {
                    std::cout << "  [upgrade] re-encrypting wallet to v6 "
                                 "(memory-hard scrypt)...\n";
                    auto bridge = SecureToStdString(unlock_pw);
                    if (wf_opt->Save(wallet_path, bridge.value)) {
                        std::cout << "  [upgrade] OK\n";
                    } else {
                        std::cerr << "  [upgrade] failed — original wallet remains intact\n";
                    }
                }
            }
        }

        if (!wf_opt) {
            std::cout << "  ✗ Too many failed attempts. Exiting.\n";
            return;
        }

        auto& wf = *wf_opt;
        std::cout << "  ✓ Wallet unlocked. " << wf.keys.size() << " address(es).\n\n";

        for (size_t i = 0; i < wf.keys.size(); ++i) {
            std::cout << "  [" << i << "] " << wf.keys[i].address << "\n";
        }
        std::cout << "\n";

        while (true) {
            std::cout << "  ┌─────────────────────────────────────────┐\n";
            std::cout << "  │  [n] New address                        │\n";
            std::cout << "  │  [s] Show all addresses                 │\n";
            std::cout << "  │  [h] Transaction history                │\n";
            std::cout << "  │  [e] Export private key (dangerous)     │\n";
            std::cout << "  │  [q] Quit                               │\n";
            std::cout << "  └─────────────────────────────────────────┘\n";
            std::cout << "  > " << std::flush;
            std::string cmd;
            std::getline(std::cin, cmd);

            if (cmd == "q" || cmd == "Q") break;

            else if (cmd == "s" || cmd == "S") {
                std::cout << "\n  Addresses in this wallet:\n";
                for (size_t i = 0; i < wf.keys.size(); ++i) {
                    std::cout << "  [" << i << "] " << wf.keys[i].address << "\n";
                }
                std::cout << "\n";
            }

            else if (cmd == "n" || cmd == "N") {
                auto pw = ReadPassword("  Confirm password to add address: ");
                auto bridge = SecureToStdString(pw);
                auto check = WalletFile::Load(wallet_path, bridge.value);
                if (!check) { std::cout << "  ✗ Wrong password.\n\n"; continue; }
                RealKeyPair kp = GenerateKeyPair(wf.testnet);
                wf.keys.push_back(kp);
                if (!wf.Save(wallet_path, bridge.value)) {
                    wf.keys.pop_back();
                    std::cout << "  ✗ Failed to persist new address; wallet unchanged.\n\n";
                    continue;
                }
                std::cout << "  ✓ New address added: " << kp.address << "\n\n";
            }

            else if (cmd == "h" || cmd == "H") {
                std::cout << "  Transaction history is unavailable in the "
                          << "Veld " << CLIENT_VERSION << " public release.\n\n";
            }

            else if (cmd == "e" || cmd == "E") {
                std::cout << "  ⚠  WARNING: Exporting private key exposes your funds!\n";
                std::cout << "  Which address index? > " << std::flush;
                std::string idx_str;
                std::getline(std::cin, idx_str);
                size_t idx = 0;
                try { idx = std::stoull(idx_str); } catch (...) { continue; }
                if (idx >= wf.keys.size()) { std::cout << "  ✗ Invalid index.\n\n"; continue; }
                auto pw = ReadPassword("  Confirm password: ");
                auto bridge = SecureToStdString(pw);
                auto check = WalletFile::Load(wallet_path, bridge.value);
                if (!check) { std::cout << "  ✗ Wrong password.\n\n"; continue; }
                std::cout << "\n  Address: " << wf.keys[idx].address << "\n";
                std::cout << "  Private key (hex): ";
                for (auto b : wf.keys[idx].private_key)
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
                std::cout << "\n\n  Store this SAFELY. Delete this terminal session after.\n\n";
            }
        }
    }
}

}
}
