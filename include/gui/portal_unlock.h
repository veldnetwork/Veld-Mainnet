#pragma once
#ifdef _WIN32
#include "state_file.h"
#include "../core/hash.h"
#include <bcrypt.h>
#include <wincrypt.h>
#include <array>
#include <algorithm>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace veld::node_gui {

inline std::string PortalBase64(const std::vector<uint8_t>& bytes) {
    DWORD size = 0;
    if (!CryptBinaryToStringA(bytes.data(), static_cast<DWORD>(bytes.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &size)) return {};
    std::string value(size, '\0');
    if (!CryptBinaryToStringA(bytes.data(), static_cast<DWORD>(bytes.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, value.data(), &size)) return {};
    while (!value.empty() && (value.back() == '\0' || value.back() == '=')) value.pop_back();
    for (char& c : value) { if (c == '+') c = '-'; else if (c == '/') c = '_'; }
    return value;
}

inline bool PortalDecode(const std::string& value, size_t minimum, size_t maximum,
                         std::vector<uint8_t>& bytes) {
    bytes.clear();
    if (value.empty() || value.size() > (maximum * 4 + 2) / 3 ||
        value.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != std::string::npos)
        return false;
    std::string padded = value;
    for (char& c : padded) { if (c == '-') c = '+'; else if (c == '_') c = '/'; }
    while (padded.size() % 4) padded.push_back('=');
    DWORD size = 0;
    if (!CryptStringToBinaryA(padded.data(), static_cast<DWORD>(padded.size()),
            CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr) || size < minimum || size > maximum) return false;
    bytes.resize(size);
    return CryptStringToBinaryA(padded.data(), static_cast<DWORD>(padded.size()),
        CRYPT_STRING_BASE64, bytes.data(), &size, nullptr, nullptr) && PortalBase64(bytes) == value;
}

inline std::string PortalDigest(const std::string& value) {
    veld::SHA256 hash;
    hash.update(value);
    const auto bytes = hash.digest();
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (uint8_t byte : bytes) { result.push_back(hex[byte >> 4]); result.push_back(hex[byte & 15]); }
    return result;
}

struct PortalUnlockPayload {
    std::string ciphertext, identity, iv, key_id, wrapped_key;

    bool Valid() const {
        std::vector<uint8_t> decoded;
        const auto digest = [](const std::string& value) {
            return value.size() == 64 && value.find_first_not_of("0123456789abcdef") == std::string::npos;
        };
        return digest(identity) && digest(key_id) && PortalDecode(iv, 12, 12, decoded) &&
            PortalDecode(wrapped_key, 256, 256, decoded) && PortalDecode(ciphertext, 17, 1040, decoded);
    }

    std::string Canonical() const {
        if (!Valid()) return {};
        return "{\"ciphertext\":\"" + ciphertext + "\",\"identity\":\"" + identity +
            "\",\"iv\":\"" + iv + "\",\"key_id\":\"" + key_id +
            "\",\"wrapped_key\":\"" + wrapped_key + "\"}";
    }
};

class PortalUnlockKey {
    BCRYPT_ALG_HANDLE rsa_{nullptr};
    BCRYPT_KEY_HANDLE key_{nullptr};
    std::string modulus_, exponent_, id_;
    mutable std::mutex mutex_;

    static DATA_BLOB Entropy() {
        static BYTE bytes[] = "VELD_PORTAL_UNLOCK_PRIVATE_V1";
        return {sizeof(bytes) - 1, bytes};
    }

    bool PublicInfo() {
        ULONG size = 0;
        if (BCryptExportKey(key_, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &size, 0) < 0 || size > 1024) return false;
        std::vector<uint8_t> blob(size);
        if (BCryptExportKey(key_, nullptr, BCRYPT_RSAPUBLIC_BLOB, blob.data(), size, &size, 0) < 0 || size < sizeof(BCRYPT_RSAKEY_BLOB)) return false;
        BCRYPT_RSAKEY_BLOB header{};
        std::memcpy(&header, blob.data(), sizeof(header));
        if (header.Magic != BCRYPT_RSAPUBLIC_MAGIC || header.BitLength != 2048 ||
            header.cbModulus != 256 || header.cbPublicExp != 3 ||
            size != sizeof(header) + header.cbPublicExp + header.cbModulus) return false;
        exponent_ = PortalBase64(std::vector<uint8_t>(blob.begin() + sizeof(header), blob.begin() + sizeof(header) + 3));
        modulus_ = PortalBase64(std::vector<uint8_t>(blob.begin() + sizeof(header) + 3, blob.end()));
        if (exponent_ != "AQAB") return false;
        id_ = PortalDigest("VELD_PORTAL_UNLOCK_KEY_V1\n" + modulus_ + "\n" + exponent_);
        return true;
    }

public:
    PortalUnlockKey() = default;
    PortalUnlockKey(const PortalUnlockKey&) = delete;
    PortalUnlockKey& operator=(const PortalUnlockKey&) = delete;
    ~PortalUnlockKey() { if (key_) BCryptDestroyKey(key_); if (rsa_) BCryptCloseAlgorithmProvider(rsa_, 0); }

    bool Ensure(const std::filesystem::path& path) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (key_) return !id_.empty();
        struct Attempt {
            PortalUnlockKey& owner;
            bool ready{false};
            ~Attempt() {
                if (ready) return;
                if (owner.key_) BCryptDestroyKey(owner.key_);
                owner.key_ = nullptr;
                owner.modulus_.clear(); owner.exponent_.clear(); owner.id_.clear();
            }
        } attempt{*this};
        if (!rsa_ && BCryptOpenAlgorithmProvider(&rsa_, BCRYPT_RSA_ALGORITHM, nullptr, 0) < 0) return false;
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (file != INVALID_HANDLE_VALUE) {
            FILE_ATTRIBUTE_TAG_INFO tag{};
            LARGE_INTEGER size{};
            const bool safe = GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag, sizeof(tag)) &&
                !(tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
                GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart <= 8192;
            std::vector<uint8_t> protected_bytes(safe ? static_cast<size_t>(size.QuadPart) : 0);
            DWORD count = 0;
            const bool read = safe && ReadFile(file, protected_bytes.data(), static_cast<DWORD>(protected_bytes.size()), &count, nullptr) && count == protected_bytes.size();
            CloseHandle(file);
            if (!read) return false;
            DATA_BLOB encrypted{count, protected_bytes.data()}, plain{}, entropy = Entropy();
            if (!CryptUnprotectData(&encrypted, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &plain)) return false;
            const bool imported = plain.cbData <= 4096 && BCryptImportKeyPair(rsa_, nullptr,
                BCRYPT_RSAFULLPRIVATE_BLOB, &key_, plain.pbData, plain.cbData, 0) >= 0;
            SecureZeroMemory(plain.pbData, plain.cbData);
            LocalFree(plain.pbData);
            if (!imported) return false;
        } else {
            if (GetLastError() != ERROR_FILE_NOT_FOUND) return false;
            if (BCryptGenerateKeyPair(rsa_, &key_, 2048, 0) < 0 || BCryptFinalizeKeyPair(key_, 0) < 0) return false;
            ULONG size = 0;
            if (BCryptExportKey(key_, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, nullptr, 0, &size, 0) < 0 || size > 4096) return false;
            std::vector<uint8_t> bytes(size);
            if (BCryptExportKey(key_, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, bytes.data(), size, &size, 0) < 0) return false;
            DATA_BLOB plain{size, bytes.data()}, encrypted{}, entropy = Entropy();
            const bool protected_ok = CryptProtectData(&plain, L"Veld remote unlock key", &entropy,
                nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &encrypted) != FALSE;
            SecureZeroMemory(bytes.data(), bytes.size());
            if (!protected_ok) return false;
            const bool written = WriteStateFile(path, encrypted.pbData, encrypted.cbData, nullptr, false);
            SecureZeroMemory(encrypted.pbData, encrypted.cbData);
            LocalFree(encrypted.pbData);
            if (!written) return false;
        }
        attempt.ready = PublicInfo();
        return attempt.ready;
    }

    std::string PublicJson(const std::string& identity) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (id_.empty() || identity.size() != 64) return "null";
        return "{\"alg\":\"RSA-OAEP-256\",\"n\":\"" + modulus_ + "\",\"e\":\"" + exponent_ +
            "\",\"id\":\"" + id_ + "\",\"identity\":\"" + identity + "\"}";
    }

    bool Decrypt(const PortalUnlockPayload& payload, uint64_t device, const std::string& nonce,
                 const std::string& identity, std::wstring& passphrase) const {
        std::lock_guard<std::mutex> lock(mutex_);
        passphrase.clear();
        if (!key_ || !payload.Valid() || payload.key_id != id_ || payload.identity != identity || !device) return false;
        std::vector<uint8_t> wrapped, iv, ciphertext, decoded_nonce;
        if (!PortalDecode(payload.wrapped_key, 256, 256, wrapped) || !PortalDecode(payload.iv, 12, 12, iv) ||
            !PortalDecode(payload.ciphertext, 17, 1040, ciphertext) || !PortalDecode(nonce, 16, 16, decoded_nonce)) return false;
        BCRYPT_OAEP_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM, nullptr, 0};
        std::array<uint8_t, 256> secret{};
        ULONG size = 0;
        bool ok = BCryptDecrypt(key_, wrapped.data(), static_cast<ULONG>(wrapped.size()), &padding,
            nullptr, 0, secret.data(), static_cast<ULONG>(secret.size()), &size, BCRYPT_PAD_OAEP) >= 0 && size == 32;
        BCRYPT_ALG_HANDLE aes = nullptr;
        BCRYPT_KEY_HANDLE aes_key = nullptr;
        if (ok) ok = BCryptOpenAlgorithmProvider(&aes, BCRYPT_AES_ALGORITHM, nullptr, 0) >= 0;
        if (ok) ok = BCryptSetProperty(aes, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)), sizeof(BCRYPT_CHAIN_MODE_GCM), 0) >= 0;
        if (ok) ok = BCryptGenerateSymmetricKey(aes, &aes_key, nullptr, 0, secret.data(), 32, 0) >= 0;
        SecureZeroMemory(secret.data(), secret.size());
        const std::string context = "VELD_PORTAL_UNLOCK_V1\n" + std::to_string(device) + "\n" + nonce + "\n" + id_ + "\n" + identity;
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = iv.data(); info.cbNonce = static_cast<ULONG>(iv.size());
        info.pbAuthData = reinterpret_cast<PUCHAR>(const_cast<char*>(context.data())); info.cbAuthData = static_cast<ULONG>(context.size());
        info.pbTag = ciphertext.data() + ciphertext.size() - 16; info.cbTag = 16;
        std::vector<uint8_t> plain(ciphertext.size() - 16);
        if (ok) ok = BCryptDecrypt(aes_key, ciphertext.data(), static_cast<ULONG>(plain.size()), &info,
            nullptr, 0, plain.data(), static_cast<ULONG>(plain.size()), &size, 0) >= 0 && size == plain.size();
        if (aes_key) BCryptDestroyKey(aes_key);
        if (aes) BCryptCloseAlgorithmProvider(aes, 0);
        if (ok && std::find(plain.begin(), plain.end(), 0) == plain.end()) {
            const int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                reinterpret_cast<const char*>(plain.data()), static_cast<int>(plain.size()), nullptr, 0);
            if (chars > 0 && chars <= 512) {
                passphrase.resize(chars);
                ok = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                    reinterpret_cast<const char*>(plain.data()), static_cast<int>(plain.size()), passphrase.data(), chars) == chars;
            } else ok = false;
        } else ok = false;
        SecureZeroMemory(plain.data(), plain.size());
        if (!ok) { SecureZeroMemory(passphrase.data(), passphrase.size() * sizeof(wchar_t)); passphrase.clear(); }
        return ok;
    }
};
} // namespace veld::node_gui
#endif
