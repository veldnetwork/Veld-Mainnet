#pragma once
#include <windows.h>
#include <wincred.h>
#include <shellapi.h>
#include <filesystem>
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace veld::node_gui {
enum class StartupMode { App, Solo, Pool, Node };
inline const char* StartupModeName(StartupMode mode) {
    switch (mode) {
    case StartupMode::Solo:
        return "solo";
    case StartupMode::Pool:
        return "pool";
    case StartupMode::Node:
        return "node";
    default:
        return "app";
    }
}
inline StartupMode ParseStartupMode(const std::string& name) {
    return name == "solo"   ? StartupMode::Solo
           : name == "pool" ? StartupMode::Pool
           : name == "node" ? StartupMode::Node
                            : StartupMode::App;
}
inline constexpr const wchar_t* StartupRunKey =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
// Registry strings are command lines, never shell commands. Quote according to
// CommandLineToArgvW, including a directory ending in a backslash.
inline std::wstring StartupQuote(const std::wstring& value) {
    if (value.empty() || value.find(L'\0') != std::wstring::npos ||
        value.find(L'"') != std::wstring::npos)
        return {};
    std::wstring out = L"\"" + value;
    for (size_t i = value.size(); i && value[i - 1] == L'\\'; --i)
        out += L'\\';
    return out + L'"';
}
inline std::wstring StartupCommand(const std::filesystem::path& executable,
                                   const std::filesystem::path& data) {
    if (!executable.is_absolute() || !data.is_absolute())
        return {};
    const auto e = StartupQuote(executable.wstring()), d = StartupQuote(data.wstring());
    if (e.empty() || d.empty())
        return {};
    auto command = e + L" --windows-startup --datadir " + d;
    // Windows Run entries have a 260-character command-line limit.
    return command.size() <= 260 ? command : std::wstring{};
}
inline bool ReadStartupCommand(std::wstring& value, const wchar_t* key = StartupRunKey) {
    value.clear();
    DWORD type = 0, size = 0;
    LSTATUS result =
        RegGetValueW(HKEY_CURRENT_USER, key, L"VeldNode", RRF_RT_REG_SZ, &type, nullptr, &size);
    if (result == ERROR_FILE_NOT_FOUND)
        return true;
    if (result != ERROR_SUCCESS || size < sizeof(wchar_t) || size > 8192 || size % sizeof(wchar_t))
        return false;
    std::vector<wchar_t> buffer(size / sizeof(wchar_t));
    result = RegGetValueW(HKEY_CURRENT_USER, key, L"VeldNode", RRF_RT_REG_SZ, &type, buffer.data(),
                          &size);
    if (result != ERROR_SUCCESS || buffer.back() != L'\0')
        return false;
    value.assign(buffer.data());
    return value.size() + 1 == size / sizeof(wchar_t);
}
inline bool WriteStartupCommand(const std::wstring& value, const wchar_t* key = StartupRunKey) {
    if (value.size() > 260 || value.find(L'\0') != std::wstring::npos)
        return false;
    HKEY handle = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, key, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &handle,
                        nullptr) != ERROR_SUCCESS)
        return false;
    const LSTATUS result =
        value.empty() ? RegDeleteValueW(handle, L"VeldNode")
                      : RegSetValueExW(handle, L"VeldNode", 0, REG_SZ,
                                       reinterpret_cast<const BYTE*>(value.c_str()),
                                       static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(handle);
    return result == ERROR_SUCCESS || (value.empty() && result == ERROR_FILE_NOT_FOUND);
}
// Opt-in Windows Credential Manager storage, local to this Windows account.
// The caller scopes target to installation and datadir; identity rotation
// invalidates the stored unlock. Never store a wallet seed or a node key here.
inline bool StartupIdentityValid(const std::wstring& identity) {
    return identity.size() == 64 && std::all_of(identity.begin(), identity.end(), [](wchar_t c) {
               return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f');
           });
}
inline bool SaveStartupUnlock(const std::wstring& target, const std::wstring& identity,
                              const std::wstring& passphrase) {
    if (target.empty() || !StartupIdentityValid(identity) || passphrase.empty() ||
        passphrase.size() > CRED_MAX_CREDENTIAL_BLOB_SIZE / sizeof(wchar_t) - 65 ||
        passphrase.find(L'\0') != std::wstring::npos)
        return false;
    const size_t bytes = (65 + passphrase.size()) * sizeof(wchar_t);
    std::vector<BYTE> plain(bytes);
    std::memcpy(plain.data(), identity.data(), 64 * sizeof(wchar_t));
    const wchar_t separator = L'\n';
    std::memcpy(plain.data() + 64 * sizeof(wchar_t), &separator, sizeof(separator));
    std::memcpy(plain.data() + 65 * sizeof(wchar_t), passphrase.data(),
                passphrase.size() * sizeof(wchar_t));
    CREDENTIALW credential{};
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = const_cast<wchar_t*>(target.c_str());
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    credential.CredentialBlob = plain.data();
    credential.CredentialBlobSize = static_cast<DWORD>(bytes);
    credential.UserName = const_cast<wchar_t*>(L"Veld local startup unlock");
    const bool ok = CredWriteW(&credential, 0) != FALSE;
    SecureZeroMemory(plain.data(), bytes);
    return ok;
}
inline bool ReadStartupUnlock(const std::wstring& target, const std::wstring& identity,
                              std::wstring& passphrase) {
    if (!passphrase.empty())
        SecureZeroMemory(passphrase.data(), passphrase.size() * sizeof(wchar_t));
    passphrase.clear();
    PCREDENTIALW credential = nullptr;
    if (target.empty() || !StartupIdentityValid(identity) ||
        !CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &credential))
        return false;
    struct Release {
        PCREDENTIALW value;
        ~Release() {
            if (value->CredentialBlob)
                SecureZeroMemory(value->CredentialBlob, value->CredentialBlobSize);
            CredFree(value);
        }
    } release{credential};
    const auto bytes = credential->CredentialBlobSize;
    bool ok = bytes > 65 * sizeof(wchar_t) && bytes <= CRED_MAX_CREDENTIAL_BLOB_SIZE &&
              bytes % sizeof(wchar_t) == 0;
    if (ok) {
        const auto* value = reinterpret_cast<const wchar_t*>(credential->CredentialBlob);
        const size_t chars = bytes / sizeof(wchar_t);
        ok = std::equal(identity.begin(), identity.end(), value) && value[64] == L'\n' &&
             std::find(value, value + chars, L'\0') == value + chars;
        if (ok)
            passphrase.assign(value + 65, chars - 65);
    }
    return ok;
}
inline bool RemoveStartupUnlock(const std::wstring& target) {
    return !target.empty() &&
           (CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0) || GetLastError() == ERROR_NOT_FOUND);
}
inline bool ShouldHideInTray(bool enabled, bool icon_available, WPARAM size) {
    return enabled && icon_available && size == SIZE_MINIMIZED;
}
} // namespace veld::node_gui
