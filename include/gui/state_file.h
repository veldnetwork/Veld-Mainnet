#pragma once
#include "../wallet/secure_channel_file.h"
#include <filesystem>
#include <string>

namespace veld::node_gui {

inline void NormalizeSettingsLine(std::string& line) {
    if (line.starts_with("\xef\xbb\xbf")) line.erase(0, 3);
    if (!line.empty() && line.back() == '\r') line.pop_back();
}

#ifdef _WIN32
// Reuse the handle-validated, owner-only persistence primitive with a native
// UTF-16 path. Do not narrow Windows user/profile names through the ANSI code
// page. Flush the new bytes before publishing one complete namespace change.
inline bool WriteStateFile(const std::filesystem::path& path,
                           const uint8_t* data, size_t size,
                           std::string* error = nullptr, bool replace = true) {
    namespace sf = channel::secure_file;
    sf::WinOwnerSecurity owner;
    sf::WinParent parent;
    if (!owner.Initialize(error) || !sf::OpenParent(path, false, owner, parent, error)) return false;
    const auto target = parent.canonical / parent.leaf;
    const auto existing = sf::InspectExistingTarget(target, owner, error);
    if (existing == sf::ExistingTarget::Unsafe ||
        (!replace && existing != sf::ExistingTarget::Missing)) return false;
    std::filesystem::path pending;
    sf::WinHandle handle;
    if (!sf::CreateOwnerOnlyTemporary(target, owner, pending, handle, error, "GUI state")) return false;
    bool ok = sf::WriteAndFlush(handle.value, data, size, error, "GUI state");
    if (!::CloseHandle(handle.release())) ok = false;
    if (ok) ok = ::MoveFileExW(pending.c_str(), target.c_str(),
        MOVEFILE_WRITE_THROUGH | (replace ? MOVEFILE_REPLACE_EXISTING : 0)) != 0;
    if (ok) ok = sf::ValidatePrivateFilePath(target, owner, error);
    if (!ok) {
        ::DeleteFileW(pending.c_str());
        if (error && error->empty()) *error = "Windows could not save the settings file";
    }
    return ok;
}

inline bool WriteStateText(const std::filesystem::path& path,
                          const std::string& text, std::string* error = nullptr) {
    return WriteStateFile(path, reinterpret_cast<const uint8_t*>(text.data()), text.size(), error);
}
#endif
} // namespace veld::node_gui
