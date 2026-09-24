#pragma once
#include "core/script.h"
#include "compat/secure_string.h"
#include "wallet/secure_channel_file.h"
#include <filesystem>
#include <cstdlib>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

namespace veld::mining {
// A public payout destination grants no wallet or validator signing authority.
inline bool ValidAddressOnlyDestination(const std::string& address, bool testnet) {
    if (address.empty() || address.size() > 96) return false;
    const auto payload = Base58CheckDecode_(address);
    const bool version = payload.size() == 21
        ? payload[0] == (testnet ? VELD_ADDR_VERSION_TESTNET : VELD_ADDR_VERSION_MAINNET)
        : payload.size() == 49 && payload[0] ==
            (testnet ? SHA384_DESTINATION_TESTNET : SHA384_DESTINATION_MAINNET);
    if (!version) return false;
    const auto script = AddressToScript(address);
    return script.size() == 25 || IsSha384KeyScript(script);
}

// This secret protects local RPC authentication only. It is never a mining key,
// is never sent to peers, and is kept separate from wallet-mode rpc.token.
inline bool AddressOnlyRpcSecret(const std::filesystem::path& directory,
                                 std::string& secret, std::string* error,
                                 bool create = true) {
    WipeString(secret);
#ifdef _WIN32
    using namespace channel::secure_file;
    if (!EnsurePrivateDirectory(directory.string(), error)) return false;
    const auto path = (directory / "address-only-rpc-unlock.dat").string();
    std::vector<uint8_t> protected_bytes;
    auto result = Read(path, protected_bytes, error, 16384);
    if (result == ReadResult::Error) return false;
    if (result != ReadResult::Ok) {
        if (!create) { if (error) *error = "address-only RPC credential is missing"; return false; }
        uint8_t random[32]{};
        if (!compat::SecureRandom(random, sizeof(random))) {
            if (error) *error = "RPC credential random generation failed";
            return false;
        }
        DATA_BLOB clear{sizeof(random), random}, encoded{};
        const bool ok = CryptProtectData(&clear, L"Veld address-only RPC", nullptr,
            nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &encoded) != FALSE;
        compat::SecureZero(random, sizeof(random));
        if (!ok) { if (error) *error = "Windows RPC credential protection failed"; return false; }
        const bool written = AtomicWriteNew(path, encoded.pbData, encoded.cbData, error);
        LocalFree(encoded.pbData);
        // A concurrent creator may have won. Always read and validate the file;
        // never replace an existing credential, including a corrupt one.
        (void)written;
        if (Read(path, protected_bytes, error, 16384) != ReadResult::Ok) return false;
    }
    DATA_BLOB encoded{static_cast<DWORD>(protected_bytes.size()), protected_bytes.data()}, clear{};
    if (!CryptUnprotectData(&encoded, nullptr, nullptr, nullptr, nullptr,
                           CRYPTPROTECT_UI_FORBIDDEN, &clear)) {
        if (error) *error = "Windows cannot unlock the address-only RPC credential";
        return false;
    }
    if (clear.cbData == 32) {
        static constexpr char hex[] = "0123456789abcdef";
        for (DWORD i=0; i<clear.cbData; ++i) {
            secret += hex[clear.pbData[i] >> 4]; secret += hex[clear.pbData[i] & 15];
        }
    }
    SecureZeroMemory(clear.pbData, clear.cbData); LocalFree(clear.pbData);
    if (secret.size() != 64) { if (error) *error = "invalid RPC credential length"; return false; }
    return true;
#else
    (void)directory; (void)create;
    const char* configured = std::getenv("VELD_ADDRESS_RPC_PASSPHRASE");
    if (!configured || std::string_view(configured).size() < 16) {
        if (error) *error = "set VELD_ADDRESS_RPC_PASSPHRASE to a private local RPC secret of at least 16 characters";
        return false;
    }
    secret = configured;
    return true;
#endif
}
}
