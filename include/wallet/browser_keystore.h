#pragma once

// Native half of the browser .veld-keys envelope. Version 2 uses PBKDF2 and
// version 3 uses scrypt with authenticated format parameters. Both use a
// 16-byte salt, a 12-byte AES-GCM IV, and an appended 16-byte GCM tag. Keep the
// checks and platform decryptors shared with the interoperability regression.

#include "wallet_crypto.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((LONG)0x00000000L)
#endif
#else
#include <openssl/evp.h>
#endif

namespace veld {
namespace wallet_crypto {

inline constexpr size_t BROWSER_KEYSTORE_IV_BYTES = 12;
inline constexpr size_t BROWSER_KEYSTORE_TAG_BYTES = 16;
inline constexpr size_t BROWSER_KEYSTORE_MAX_PLAINTEXT_BYTES = 1024u * 1024u;

inline void WipeBrowserPlaintext(std::string& value) {
    const size_t allocated = value.capacity();
    if (allocated != 0) {
        value.resize(allocated, '\0');
        veld::compat::SecureZero(value.data(), value.size());
    }
    value.clear();
    value.shrink_to_fit();
}

inline bool DecryptBrowserKeystoreCiphertext(uint32_t version, const std::string& password,
                                             const uint8_t* salt, size_t salt_len,
                                             const uint8_t* iv, size_t iv_len,
                                             const uint8_t* sealed, size_t sealed_len,
                                             std::string& plaintext) {
    WipeBrowserPlaintext(plaintext);
    if (!salt || salt_len != BROWSER_KEYSTORE_SALT_BYTES || !iv ||
        iv_len != BROWSER_KEYSTORE_IV_BYTES || !sealed ||
        sealed_len <= BROWSER_KEYSTORE_TAG_BYTES ||
        sealed_len - BROWSER_KEYSTORE_TAG_BYTES > BROWSER_KEYSTORE_MAX_PLAINTEXT_BYTES)
        return false;

    const size_t ciphertext_len = sealed_len - BROWSER_KEYSTORE_TAG_BYTES;
    const uint8_t* tag = sealed + ciphertext_len;
    std::vector<uint8_t> key;
    try {
        if (version == BROWSER_KEYSTORE_VERSION_V2) {
            key = DeriveBrowserKeystoreKey(password, salt, salt_len);
        } else if (version == BROWSER_KEYSTORE_VERSION_V3) {
            key = DeriveBrowserKeystoreKeyV3(password, salt, salt_len);
        } else {
            return false;
        }
    } catch (...) {
        return false;
    }
    ScopedByteWipe<std::vector<uint8_t>> wipe_key{key};
    plaintext.resize(ciphertext_len);
    bool ok = false;

#ifdef _WIN32
    if (ciphertext_len > std::numeric_limits<ULONG>::max()) {
        WipeBrowserPlaintext(plaintext);
        return false;
    }
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE aes_key = nullptr;
    if (::BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0) ==
        STATUS_SUCCESS) {
        do {
            if (::BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                    sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != STATUS_SUCCESS)
                break;
            if (::BCryptGenerateSymmetricKey(algorithm, &aes_key, nullptr, 0, key.data(),
                                             static_cast<ULONG>(key.size()), 0) != STATUS_SUCCESS)
                break;
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info{};
            BCRYPT_INIT_AUTH_MODE_INFO(info);
            info.pbNonce = const_cast<PUCHAR>(iv);
            info.cbNonce = static_cast<ULONG>(iv_len);
            info.pbTag = const_cast<PUCHAR>(tag);
            info.cbTag = BROWSER_KEYSTORE_TAG_BYTES;
            if (version == BROWSER_KEYSTORE_VERSION_V3) {
                info.pbAuthData =
                    reinterpret_cast<PUCHAR>(const_cast<char*>(BROWSER_KEYSTORE_V3_AAD));
                info.cbAuthData = static_cast<ULONG>(sizeof(BROWSER_KEYSTORE_V3_AAD) - 1);
            }
            ULONG produced = 0;
            if (::BCryptDecrypt(
                    aes_key, const_cast<PUCHAR>(sealed), static_cast<ULONG>(ciphertext_len), &info,
                    nullptr, 0, reinterpret_cast<PUCHAR>(plaintext.data()),
                    static_cast<ULONG>(plaintext.size()), &produced, 0) != STATUS_SUCCESS)
                break;
            plaintext.resize(produced);
            ok = produced == ciphertext_len;
        } while (false);
    }
    if (aes_key)
        ::BCryptDestroyKey(aes_key);
    if (algorithm)
        ::BCryptCloseAlgorithmProvider(algorithm, 0);
#else
    if (ciphertext_len > static_cast<size_t>(std::numeric_limits<int>::max())) {
        WipeBrowserPlaintext(plaintext);
        return false;
    }
    EVP_CIPHER_CTX* ctx = ::EVP_CIPHER_CTX_new();
    if (ctx) {
        int produced = 0;
        int aad_bytes = 0;
        if (::EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
            ::EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, BROWSER_KEYSTORE_IV_BYTES,
                                  nullptr) == 1 &&
            ::EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv) == 1) {
            bool aad_ok = true;
            if (version == BROWSER_KEYSTORE_VERSION_V3) {
                aad_ok =
                    ::EVP_DecryptUpdate(ctx, nullptr, &aad_bytes,
                                        reinterpret_cast<const uint8_t*>(BROWSER_KEYSTORE_V3_AAD),
                                        static_cast<int>(sizeof(BROWSER_KEYSTORE_V3_AAD) - 1)) == 1;
            }
            if (aad_ok &&
                ::EVP_DecryptUpdate(ctx, reinterpret_cast<uint8_t*>(plaintext.data()), &produced,
                                    sealed, static_cast<int>(ciphertext_len)) == 1 &&
                ::EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, BROWSER_KEYSTORE_TAG_BYTES,
                                      const_cast<uint8_t*>(tag)) == 1) {
                int final_bytes = 0;
                if (::EVP_DecryptFinal_ex(ctx,
                                          reinterpret_cast<uint8_t*>(plaintext.data()) + produced,
                                          &final_bytes) == 1) {
                    plaintext.resize(static_cast<size_t>(produced + final_bytes));
                    ok = plaintext.size() == ciphertext_len;
                }
            }
        }
        ::EVP_CIPHER_CTX_free(ctx);
    }
#endif

    if (!ok)
        WipeBrowserPlaintext(plaintext);
    return ok;
}

inline bool ParseBrowserKeystoreIdentity(std::string_view json, std::string& private_key_hex,
                                         std::string& address) {
    WipeBrowserPlaintext(private_key_hex);
    address.clear();
    bool success = false;
    struct OutputGuard {
        std::string& key;
        std::string& addr;
        bool& success;
        ~OutputGuard() {
            if (!success) {
                WipeBrowserPlaintext(key);
                addr.clear();
            }
        }
    } output_guard{private_key_hex, address, success};
    size_t pos = 0;
    auto skip_ws = [&] {
        while (pos < json.size() &&
               (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n'))
            ++pos;
    };
    auto parse_string = [&](std::string& out, size_t ceiling) -> bool {
        out.clear();
        if (pos >= json.size() || json[pos++] != '"')
            return false;
        while (pos < json.size() && json[pos] != '"') {
            const unsigned char c = static_cast<unsigned char>(json[pos++]);
            // The browser's key/address alphabet never needs JSON escapes.
            // Reject them instead of accepting ambiguous alternate encodings.
            if (c == '\\' || c < 0x20 || out.size() == ceiling)
                return false;
            out.push_back(static_cast<char>(c));
        }
        if (pos >= json.size() || json[pos++] != '"')
            return false;
        return true;
    };

    skip_ws();
    if (pos >= json.size() || json[pos++] != '{')
        return false;
    bool have_key = false, have_address = false;
    for (;;) {
        skip_ws();
        if (pos < json.size() && json[pos] == '}') {
            ++pos;
            break;
        }
        std::string field, value;
        if (!parse_string(field, 32))
            return false;
        skip_ws();
        if (pos >= json.size() || json[pos++] != ':')
            return false;
        skip_ws();
        if (!parse_string(value, 128))
            return false;
        if (field == "key" && !have_key) {
            private_key_hex = std::move(value);
            have_key = true;
        } else if (field == "address" && !have_address) {
            address = std::move(value);
            have_address = true;
        } else {
            WipeBrowserPlaintext(private_key_hex);
            address.clear();
            return false;
        }
        skip_ws();
        if (pos < json.size() && json[pos] == ',') {
            ++pos;
            continue;
        }
        if (pos < json.size() && json[pos] == '}') {
            ++pos;
            break;
        }
        WipeBrowserPlaintext(private_key_hex);
        address.clear();
        return false;
    }
    skip_ws();
    const bool key_is_hex =
        private_key_hex.size() == 64 &&
        std::all_of(private_key_hex.begin(), private_key_hex.end(), [](unsigned char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        });
    if (pos != json.size() || !have_key || !have_address || !key_is_hex || address.empty()) {
        return false;
    }
    success = true;
    return true;
}

inline bool DecryptBrowserKeystoreCiphertext(uint32_t version, const std::string& password,
                                             const std::vector<uint8_t>& salt,
                                             const std::vector<uint8_t>& iv,
                                             const std::vector<uint8_t>& sealed,
                                             std::string& plaintext) {
    return DecryptBrowserKeystoreCiphertext(version, password, salt.data(), salt.size(), iv.data(),
                                            iv.size(), sealed.data(), sealed.size(), plaintext);
}

inline bool DecryptBrowserKeystoreCiphertext(const std::string& password, const uint8_t* salt,
                                             size_t salt_len, const uint8_t* iv, size_t iv_len,
                                             const uint8_t* sealed, size_t sealed_len,
                                             std::string& plaintext) {
    return DecryptBrowserKeystoreCiphertext(BROWSER_KEYSTORE_VERSION_V2, password, salt, salt_len,
                                            iv, iv_len, sealed, sealed_len, plaintext);
}

inline bool DecryptBrowserKeystoreCiphertext(const std::string& password,
                                             const std::vector<uint8_t>& salt,
                                             const std::vector<uint8_t>& iv,
                                             const std::vector<uint8_t>& sealed,
                                             std::string& plaintext) {
    return DecryptBrowserKeystoreCiphertext(BROWSER_KEYSTORE_VERSION_V2, password, salt, iv, sealed,
                                            plaintext);
}

} // namespace wallet_crypto
} // namespace veld
