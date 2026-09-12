#pragma once
#include "state_file.h"
#include <windows.h>
#include <wincrypt.h>
#include <algorithm>
#include <cstring>
#include <ctime>
#include <vector>

namespace veld::node_gui {

struct UpdateResume {
    uint64_t created{0};
    std::wstring data_directory;
    std::wstring identity;
    std::wstring previous_manifest;
    std::wstring target_manifest;
    std::wstring passphrase;

    ~UpdateResume() { Wipe(); }
    void Wipe() {
        if (!passphrase.empty()) SecureZeroMemory(passphrase.data(), passphrase.size() * sizeof(wchar_t));
        passphrase.clear();
    }
    bool Valid(uint64_t now) const {
        const auto digest = [](const std::wstring& s) {
            return s.size() == 64 && std::all_of(s.begin(), s.end(), [](wchar_t c) {
                return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f');
            });
        };
        return created != 0 && now >= created && now - created <= 3600 &&
            !data_directory.empty() && data_directory.size() <= 32767 && data_directory.find(L'\0') == std::wstring::npos &&
            std::filesystem::path(data_directory).is_absolute() &&
            digest(identity) && digest(previous_manifest) && digest(target_manifest) &&
            previous_manifest != target_manifest && !passphrase.empty() && passphrase.size() <= 4096 &&
            passphrase.find(L'\0') == std::wstring::npos;
    }
};

inline std::wstring UpdateInstallContext(const std::filesystem::path& root) {
    std::error_code error;
    auto path = std::filesystem::weakly_canonical(root, error);
    if (error || !path.is_absolute()) return {};
    auto text = path.wstring();
    CharLowerBuffW(text.data(), static_cast<DWORD>(text.size()));
    return L"Veld update resume v1|" + text;
}

inline bool SaveUpdateResume(const std::filesystem::path& path,
                             const std::wstring& context, const UpdateResume& resume,
                             uint64_t now) {
    if (context.empty() || !resume.Valid(now)) return false;
    size_t total = sizeof(uint64_t);
    for (const auto* field : {&resume.data_directory, &resume.identity,
            &resume.previous_manifest, &resume.target_manifest, &resume.passphrase})
        total += sizeof(uint32_t) + field->size() * sizeof(wchar_t);
    if (total > 96 * 1024) return false;
    std::vector<BYTE> bytes(total);
    size_t at = 0;
    auto put = [&](const void* source, size_t count) {
        std::memcpy(bytes.data() + at, source, count); at += count;
    };
    put(&resume.created, sizeof(resume.created));
    for (const auto* field : {&resume.data_directory, &resume.identity,
            &resume.previous_manifest, &resume.target_manifest, &resume.passphrase}) {
        const auto chars = static_cast<uint32_t>(field->size());
        put(&chars, sizeof(chars)); put(field->data(), chars * sizeof(wchar_t));
    }
    DATA_BLOB plain{static_cast<DWORD>(bytes.size()), bytes.data()}, sealed{};
    DATA_BLOB entropy{static_cast<DWORD>(context.size() * sizeof(wchar_t)),
        reinterpret_cast<BYTE*>(const_cast<wchar_t*>(context.data()))};
    const bool protected_ok = CryptProtectData(&plain, L"Veld one-use update resume", &entropy,
        nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &sealed) != FALSE;
    SecureZeroMemory(bytes.data(), bytes.size());
    const bool saved = protected_ok && WriteStateFile(path, sealed.pbData, sealed.cbData, nullptr, false);
    if (sealed.pbData) { SecureZeroMemory(sealed.pbData, sealed.cbData); LocalFree(sealed.pbData); }
    return saved;
}

// Consume the same owner-only file handle that was validated. A failed delete
// cannot release an unlock, and no second process can consume this handoff.
inline bool ConsumeUpdateResume(const std::filesystem::path& path,
                                const std::wstring& context, UpdateResume& resume,
                                uint64_t now) {
    resume.Wipe();
    namespace sf = channel::secure_file;
    sf::WinOwnerSecurity owner;
    sf::WinParent parent;
    if (context.empty() || !owner.Initialize(nullptr) ||
        !sf::OpenParent(path, false, owner, parent, nullptr)) return false;
    sf::WinHandle file(CreateFileW((parent.canonical / parent.leaf).c_str(),
        GENERIC_READ | DELETE | READ_CONTROL, 0, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!file) return false;
    LARGE_INTEGER size{};
    if (!sf::RegularSingleLink(file.value, nullptr, nullptr, "update resume") ||
        !sf::HandleHasCurrentOwner(file.value, owner.sid(), true, nullptr, "update resume") ||
        !GetFileSizeEx(file.value, &size) || size.QuadPart <= 0 || size.QuadPart > 128 * 1024) return false;
    std::vector<BYTE> bytes(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    if (!ReadFile(file.value, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) || read != bytes.size()) return false;
    FILE_DISPOSITION_INFO disposition{TRUE};
    if (!SetFileInformationByHandle(file.value, FileDispositionInfo, &disposition, sizeof(disposition))) return false;
    if (!CloseHandle(file.release())) return false;
    DATA_BLOB sealed{static_cast<DWORD>(bytes.size()), bytes.data()}, plain{};
    DATA_BLOB entropy{static_cast<DWORD>(context.size() * sizeof(wchar_t)),
        reinterpret_cast<BYTE*>(const_cast<wchar_t*>(context.data()))};
    if (!CryptUnprotectData(&sealed, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &plain)) return false;
    size_t at = 0;
    auto take = [&](void* destination, size_t count) {
        if (at > plain.cbData || count > plain.cbData - at) return false;
        std::memcpy(destination, plain.pbData + at, count); at += count; return true;
    };
    bool ok = take(&resume.created, sizeof(resume.created));
    for (auto* field : {&resume.data_directory, &resume.identity,
            &resume.previous_manifest, &resume.target_manifest, &resume.passphrase}) {
        uint32_t chars = 0;
        if (!ok || !take(&chars, sizeof(chars)) || chars > 32767 ||
            chars * sizeof(wchar_t) > plain.cbData - at) { ok = false; break; }
        field->resize(chars);
        ok = take(field->data(), chars * sizeof(wchar_t));
    }
    ok = ok && at == plain.cbData && resume.Valid(now);
    SecureZeroMemory(plain.pbData, plain.cbData); LocalFree(plain.pbData);
    if (!ok) resume.Wipe();
    return ok;
}

} // namespace veld::node_gui
