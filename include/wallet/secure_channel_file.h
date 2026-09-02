#pragma once
// Durable, owner-only persistence for payment-channel material.
//
// Channel snapshots contain counterparty revocation secrets.  Treat them like
// private keys: never follow a link, never truncate the live file in place, and
// do not report success until both the new bytes and the directory entry are
// durable.  The helpers live in a small header so the standalone channel tools
// and router use exactly the same file discipline.

#include "../compat/platform.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <limits>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace veld {
namespace channel {
namespace secure_file {

enum class ReadResult { Ok, NotFound, Error };

inline void SetError(std::string* out, const std::string& what) {
    if (out) *out = what;
}

inline void WipeAndClear(std::vector<uint8_t>& value) {
    if (!value.empty()) veld::compat::SecureZero(value.data(), value.size());
    value.clear();
}

inline bool ValidTarget(const std::filesystem::path& target, std::string* error) {
    const auto base = target.filename();
    if (base.empty() || base == "." || base == "..") {
        SetError(error, "target must name a file");
        return false;
    }
    return true;
}

#ifdef _WIN32

struct WinHandle {
    HANDLE value = INVALID_HANDLE_VALUE;

    WinHandle() = default;
    explicit WinHandle(HANDLE h) : value(h) {}
    WinHandle(const WinHandle&) = delete;
    WinHandle& operator=(const WinHandle&) = delete;
    WinHandle(WinHandle&& other) noexcept : value(other.value) {
        other.value = INVALID_HANDLE_VALUE;
    }
    WinHandle& operator=(WinHandle&& other) noexcept {
        if (this != &other) {
            if (value != INVALID_HANDLE_VALUE) ::CloseHandle(value);
            value = other.value;
            other.value = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    ~WinHandle() {
        if (value != INVALID_HANDLE_VALUE) ::CloseHandle(value);
    }
    explicit operator bool() const { return value != INVALID_HANDLE_VALUE; }
    HANDLE release() {
        const HANDLE out = value;
        value = INVALID_HANDLE_VALUE;
        return out;
    }
};

struct WinLocalSecurityDescriptor {
    PSECURITY_DESCRIPTOR value = nullptr;
    ~WinLocalSecurityDescriptor() {
        if (value) ::LocalFree(value);
    }
};

// Owns every pointer referenced by `attributes`.  Passing this descriptor to
// CREATE_NEW is important: repairing a default/inherited DACL after CloseHandle
// leaves a disclosure and pathname-replacement window in a permissive parent.
struct WinOwnerSecurity {
    std::vector<uint8_t> token_user;
    std::vector<DWORD> acl_storage;
    SECURITY_DESCRIPTOR descriptor{};
    SECURITY_ATTRIBUTES attributes{};

    PSID sid() {
        return token_user.empty()
            ? nullptr : reinterpret_cast<TOKEN_USER*>(token_user.data())->User.Sid;
    }
    PACL acl() {
        return acl_storage.empty()
            ? nullptr : reinterpret_cast<PACL>(acl_storage.data());
    }

    bool Initialize(std::string* error, DWORD ace_flags = 0) {
        WinHandle token;
        HANDLE raw_token = INVALID_HANDLE_VALUE;
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &raw_token)) {
            SetError(error, "cannot query current Windows token");
            return false;
        }
        token = WinHandle(raw_token);
        DWORD bytes = 0;
        if (::GetTokenInformation(token.value, TokenUser, nullptr, 0, &bytes)
                || ::GetLastError() != ERROR_INSUFFICIENT_BUFFER
                || bytes < sizeof(TOKEN_USER)) {
            SetError(error, "cannot size current Windows user SID");
            return false;
        }
        token_user.resize(bytes);
        if (!::GetTokenInformation(token.value, TokenUser, token_user.data(),
                                   bytes, &bytes)
                || !::IsValidSid(sid())) {
            SetError(error, "cannot read current Windows user SID");
            return false;
        }

        const DWORD sid_bytes = ::GetLengthSid(sid());
        const size_t acl_bytes = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE)
            - sizeof(DWORD) + sid_bytes;
        if (acl_bytes > (std::numeric_limits<DWORD>::max)()) {
            SetError(error, "Windows owner ACL is too large");
            return false;
        }
        acl_storage.assign((acl_bytes + sizeof(DWORD) - 1) / sizeof(DWORD), 0);
        if (!::InitializeAcl(acl(), static_cast<DWORD>(acl_bytes), ACL_REVISION)
                || !::AddAccessAllowedAceEx(acl(), ACL_REVISION, ace_flags,
                                            FILE_ALL_ACCESS, sid())
                || !::InitializeSecurityDescriptor(
                    &descriptor, SECURITY_DESCRIPTOR_REVISION)
                || !::SetSecurityDescriptorOwner(&descriptor, sid(), FALSE)
                || !::SetSecurityDescriptorDacl(&descriptor, TRUE, acl(), FALSE)
                || !::SetSecurityDescriptorControl(
                    &descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
            SetError(error, "cannot build protected owner-only Windows ACL");
            return false;
        }
        attributes.nLength = sizeof(attributes);
        attributes.lpSecurityDescriptor = &descriptor;
        attributes.bInheritHandle = FALSE;
        return true;
    }
};

inline bool ValidWindowsTarget(const std::filesystem::path& target,
                               std::string* error) {
    if (!ValidTarget(target, error)) return false;
    const std::wstring leaf = target.filename().native();
    // A colon in the final component selects an NTFS alternate data stream;
    // that stream shares the base file's security descriptor.  Win32 also
    // aliases trailing dots/spaces, defeating exact no-overwrite checks.
    if (leaf.find(L':') != std::wstring::npos || leaf.back() == L'.'
            || leaf.back() == L' ') {
        SetError(error, "target filename must not use an alternate stream or a trailing dot/space");
        return false;
    }
    return true;
}

inline bool HandleHasCurrentOwner(HANDLE handle, PSID current_sid,
                                  bool require_private,
                                  std::string* error, const char* label) {
    PSID object_owner = nullptr;
    PACL returned_dacl = nullptr;
    WinLocalSecurityDescriptor holder;
    const SECURITY_INFORMATION requested = OWNER_SECURITY_INFORMATION
        | (require_private ? DACL_SECURITY_INFORMATION : 0);
    const DWORD status = ::GetSecurityInfo(
        handle, SE_FILE_OBJECT, requested, &object_owner, nullptr,
        require_private ? &returned_dacl : nullptr, nullptr, &holder.value);
    if (status != ERROR_SUCCESS || !holder.value || !object_owner
            || !::IsValidSid(object_owner)
            || !::EqualSid(object_owner, current_sid)) {
        SetError(error, std::string(label) + " must be owned by the current Windows user");
        return false;
    }
    if (!require_private) return true;

    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (!::GetSecurityDescriptorDacl(holder.value, &present, &dacl, &defaulted)
            || !present || !dacl || dacl != returned_dacl || !::IsValidAcl(dacl)
            || !::GetSecurityDescriptorControl(holder.value, &control, &revision)
            || !(control & SE_DACL_PROTECTED)) {
        SetError(error, std::string(label)
            + " must have a present protected owner-only DACL");
        return false;
    }

    bool usable_owner_allow = false;
    for (DWORD index = 0; index < dacl->AceCount; ++index) {
        void* raw_ace = nullptr;
        if (!::GetAce(dacl, index, &raw_ace) || !raw_ace) {
            SetError(error, std::string(label) + " has a malformed DACL");
            return false;
        }
        const auto* header = static_cast<const ACE_HEADER*>(raw_ace);
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE
                || header->AceSize < sizeof(ACCESS_ALLOWED_ACE)) {
            SetError(error, std::string(label)
                + " has an unsupported or non-owner allow ACE");
            return false;
        }
        const auto* allow = static_cast<const ACCESS_ALLOWED_ACE*>(raw_ace);
        PSID ace_sid = const_cast<DWORD*>(&allow->SidStart);
        if (!::IsValidSid(ace_sid) || !::EqualSid(ace_sid, current_sid)) {
            SetError(error, std::string(label)
                + " grants access to a principal other than the current user");
            return false;
        }
        if (!(header->AceFlags & INHERIT_ONLY_ACE)) usable_owner_allow = true;
    }
    if (!usable_owner_allow) {
        SetError(error, std::string(label) + " does not grant access to its owner");
        return false;
    }
    return true;
}

inline bool RegularSingleLink(HANDLE handle, BY_HANDLE_FILE_INFORMATION* out,
                              std::string* error, const char* label) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!::GetFileInformationByHandle(handle, &info)
            || (info.dwFileAttributes
                & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
            || info.nNumberOfLinks != 1) {
        SetError(error, std::string(label)
            + " must be a regular, non-reparse, single-link file");
        return false;
    }
    if (out) *out = info;
    return true;
}

inline bool FinalPathForHandle(HANDLE handle, std::filesystem::path& out,
                               std::string* error) {
    const DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    const DWORD needed = ::GetFinalPathNameByHandleW(handle, nullptr, 0, flags);
    if (needed == 0) {
        SetError(error, "cannot canonicalize Windows parent directory");
        return false;
    }
    std::vector<wchar_t> buffer(static_cast<size_t>(needed) + 1, L'\0');
    const DWORD written = ::GetFinalPathNameByHandleW(
        handle, buffer.data(), static_cast<DWORD>(buffer.size()), flags);
    if (written == 0 || written >= buffer.size()) {
        SetError(error, "cannot canonicalize Windows parent directory");
        return false;
    }
    out = std::filesystem::path(std::wstring(buffer.data(), written));
    return true;
}

struct WinParent {
    WinHandle handle;
    std::filesystem::path canonical;
    std::filesystem::path leaf;
};

inline bool OpenParent(const std::filesystem::path& target,
                       bool require_private_parent, WinOwnerSecurity& owner,
                       WinParent& out, std::string* error) {
    if (!ValidWindowsTarget(target, error)) return false;
    const auto parent = target.parent_path().empty()
        ? std::filesystem::path(L".") : target.parent_path();
    WinHandle handle(::CreateFileW(
        parent.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    BY_HANDLE_FILE_INFORMATION info{};
    if (!handle || ::GetFileType(handle.value) != FILE_TYPE_DISK
            || !::GetFileInformationByHandle(handle.value, &info)
            || !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        SetError(error, "parent is missing, not a directory, or a reparse point");
        return false;
    }
    if (!HandleHasCurrentOwner(handle.value, owner.sid(),
                               require_private_parent, error,
                               "parent directory")) return false;
    if (!FinalPathForHandle(handle.value, out.canonical, error)) return false;
    out.handle = std::move(handle);
    out.leaf = target.filename();
    return true;
}

enum class ExistingTarget { Missing, Safe, Unsafe };

inline ExistingTarget InspectExistingTarget(
        const std::filesystem::path& target, WinOwnerSecurity& owner,
        std::string* error) {
    WinHandle handle(::CreateFileW(
        target.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!handle) {
        const DWORD code = ::GetLastError();
        if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
            return ExistingTarget::Missing;
        SetError(error, "cannot safely inspect existing Windows target");
        return ExistingTarget::Unsafe;
    }
    if (!RegularSingleLink(handle.value, nullptr, error, "existing target")
            || !HandleHasCurrentOwner(handle.value, owner.sid(), false,
                                      error, "existing target"))
        return ExistingTarget::Unsafe;
    return ExistingTarget::Safe;
}

inline bool ValidatePrivateFilePath(const std::filesystem::path& target,
                                    WinOwnerSecurity& owner,
                                    std::string* error) {
    WinHandle handle(::CreateFileW(
        target.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    return handle
        && RegularSingleLink(handle.value, nullptr, error, "published file")
        && HandleHasCurrentOwner(handle.value, owner.sid(), true,
                                 error, "published file");
}

inline bool CreateOwnerOnlyTemporary(
        const std::filesystem::path& target, WinOwnerSecurity& owner,
        std::filesystem::path& tmp, WinHandle& handle, std::string* error,
        const char* label) {
    for (unsigned i = 0; i < 128 && !handle; ++i) {
        tmp = target;
        tmp += L".tmp." + std::to_wstring(::GetCurrentProcessId()) + L"."
            + std::to_wstring(i);
        handle = WinHandle(::CreateFileW(
            tmp.c_str(), GENERIC_WRITE | FILE_READ_ATTRIBUTES | READ_CONTROL,
            0, &owner.attributes, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH
                | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!handle && ::GetLastError() != ERROR_FILE_EXISTS) break;
    }
    if (!handle) {
        SetError(error, std::string("cannot create exclusive ") + label);
        return false;
    }
    if (!RegularSingleLink(handle.value, nullptr, error, label)
            || !HandleHasCurrentOwner(handle.value, owner.sid(), true,
                                      error, label)) {
        const HANDLE raw = handle.release();
        ::CloseHandle(raw);
        ::DeleteFileW(tmp.c_str());
        return false;
    }
    return true;
}

inline bool WriteAndFlush(HANDLE handle, const uint8_t* data, size_t size,
                          std::string* error, const char* label) {
    const uint8_t* cursor = data;
    size_t left = size;
    while (left) {
        DWORD wrote = 0;
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(left, 1u << 30));
        if (!::WriteFile(handle, cursor, chunk, &wrote, nullptr) || wrote == 0) {
            SetError(error, std::string(label) + " write failed");
            return false;
        }
        cursor += wrote;
        left -= wrote;
    }
    if (!::FlushFileBuffers(handle)
            || !RegularSingleLink(handle, nullptr, error, label)) {
        if (error && error->empty()) SetError(error, std::string(label) + " flush failed");
        return false;
    }
    return true;
}

// Windows has no portable directory-fsync equivalent.  The parent directory
// is opened without FILE_SHARE_DELETE and validated by handle.  The temporary
// file receives its final protected DACL at CREATE_NEW (not after close), then
// MOVEFILE_WRITE_THROUGH requests durable same-directory publication.  For
// require_private_parent=false, POSIX-compatible owner checking remains, but a
// deliberately permissive parent can still permit same-directory denial races;
// the protected file DACL prevents disclosure and final validation fails closed.
inline bool AtomicWrite(const std::string& path, const uint8_t* data, size_t size,
                        std::string* error = nullptr,
                        bool require_private_parent = true) {
    WinOwnerSecurity owner;
    if (!owner.Initialize(error)) return false;
    WinParent parent;
    if (!OpenParent(std::filesystem::path(path), require_private_parent,
                    owner, parent, error)) return false;
    const std::filesystem::path target = parent.canonical / parent.leaf;
    if (InspectExistingTarget(target, owner, error) == ExistingTarget::Unsafe)
        return false;

    std::filesystem::path tmp;
    WinHandle handle;
    if (!CreateOwnerOnlyTemporary(target, owner, tmp, handle, error,
                                  "temporary file")) return false;
    bool ok = WriteAndFlush(handle.value, data, size, error, "temporary file");
    const HANDLE raw = handle.release();
    if (!::CloseHandle(raw)) ok = false;
    if (ok) {
        ok = ::MoveFileExW(tmp.c_str(), target.c_str(),
                           MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
    }
    if (ok) ok = ValidatePrivateFilePath(target, owner, error);
    if (!ok) {
        ::DeleteFileW(tmp.c_str());
        if (error && error->empty()) SetError(error, "secure write/flush/replace failed");
    }
    return ok;
}

// Create one immutable journal entry.  Unlike AtomicWrite this never replaces
// an existing name: sequence files are write-once evidence, and allowing a
// retry to overwrite one would destroy rollback detection.
inline bool AtomicWriteNew(const std::string& path, const uint8_t* data, size_t size,
                           std::string* error = nullptr,
                           bool require_private_parent = true) {
    WinOwnerSecurity owner;
    if (!owner.Initialize(error)) return false;
    WinParent parent;
    if (!OpenParent(std::filesystem::path(path), require_private_parent,
                    owner, parent, error)) return false;
    const std::filesystem::path target = parent.canonical / parent.leaf;
    if (InspectExistingTarget(target, owner, error) != ExistingTarget::Missing) {
        if (error && error->empty()) SetError(error, "immutable target already exists");
        return false;
    }

    std::filesystem::path tmp;
    WinHandle handle;
    if (!CreateOwnerOnlyTemporary(target, owner, tmp, handle, error,
                                  "immutable temporary file")) return false;
    bool ok = WriteAndFlush(handle.value, data, size, error,
                            "immutable temporary file");
    const HANDLE raw = handle.release();
    if (!::CloseHandle(raw)) ok = false;
    // Omitting MOVEFILE_REPLACE_EXISTING makes publication fail atomically if
    // another process already committed this sequence number.
    if (ok) ok = ::MoveFileExW(tmp.c_str(), target.c_str(),
                               MOVEFILE_WRITE_THROUGH) != 0;
    if (ok) ok = ValidatePrivateFilePath(target, owner, error);
    if (!ok) {
        ::DeleteFileW(tmp.c_str());
        if (error && error->empty())
            SetError(error, "secure immutable write/flush/publish failed");
    }
    return ok;
}

inline ReadResult Read(const std::string& path, std::vector<uint8_t>& out,
                       std::string* error = nullptr, size_t max_size = 64u * 1024u * 1024u,
                       bool require_private_parent = true) {
    WipeAndClear(out);
    WinOwnerSecurity owner;
    if (!owner.Initialize(error)) return ReadResult::Error;
    WinParent parent;
    if (!OpenParent(std::filesystem::path(path), require_private_parent,
                    owner, parent, error)) return ReadResult::Error;
    const std::filesystem::path target = parent.canonical / parent.leaf;

    WinHandle handle(::CreateFileW(
        target.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!handle) {
        const DWORD code = ::GetLastError();
        if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
            return ReadResult::NotFound;
        SetError(error, "cannot open owner-only file");
        return ReadResult::Error;
    }
    BY_HANDLE_FILE_INFORMATION before{};
    LARGE_INTEGER n{};
    bool ok = RegularSingleLink(handle.value, &before, error, "private file")
        && HandleHasCurrentOwner(handle.value, owner.sid(), true,
                                 error, "private file")
        && ::GetFileSizeEx(handle.value, &n) && n.QuadPart >= 0
        && static_cast<unsigned long long>(n.QuadPart) <= max_size;
    if (ok) out.resize(static_cast<size_t>(n.QuadPart));
    size_t got = 0;
    while (ok && got < out.size()) {
        DWORD nr = 0;
        const DWORD want = static_cast<DWORD>(
            std::min<size_t>(out.size() - got, 1u << 30));
        ok = ::ReadFile(handle.value, out.data() + got, want, &nr, nullptr)
            && nr != 0;
        got += nr;
    }
    BY_HANDLE_FILE_INFORMATION after{};
    LARGE_INTEGER final_size{};
    if (ok) {
        ok = RegularSingleLink(handle.value, &after, error, "private file")
            && ::GetFileSizeEx(handle.value, &final_size)
            && final_size.QuadPart == n.QuadPart
            && after.dwVolumeSerialNumber == before.dwVolumeSerialNumber
            && after.nFileIndexHigh == before.nFileIndexHigh
            && after.nFileIndexLow == before.nFileIndexLow;
    }
    const HANDLE raw = handle.release();
    if (!::CloseHandle(raw)) ok = false;
    if (!ok) {
        WipeAndClear(out);
        if (error && error->empty())
            SetError(error, "unsafe owner-only file or read failure");
        return ReadResult::Error;
    }
    return ReadResult::Ok;
}

inline bool EnsurePrivateDirectory(const std::string& path, std::string* error = nullptr) {
    WinOwnerSecurity owner;
    // Keep the datadir private while allowing ordinary files and directories
    // created beneath it to inherit the owner's full-control ACE. Without
    // these inheritance flags Explorer can treat an extracted client tree as
    // a collection of isolated protected objects and fail recursive cleanup.
    if (!owner.Initialize(error, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE))
        return false;
    const std::filesystem::path directory(path);
    if (directory.empty()) {
        SetError(error, "private directory path is empty");
        return false;
    }

    DWORD attrs = ::GetFileAttributesW(directory.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        const DWORD code = ::GetLastError();
        if (code != ERROR_FILE_NOT_FOUND && code != ERROR_PATH_NOT_FOUND) {
            SetError(error, "cannot inspect private directory");
            return false;
        }
        std::error_code ec;
        const auto parent = directory.parent_path();
        if (!parent.empty()) std::filesystem::create_directories(parent, ec);
        if (ec || (!::CreateDirectoryW(directory.c_str(), &owner.attributes)
                   && ::GetLastError() != ERROR_ALREADY_EXISTS)) {
            SetError(error, "cannot create private directory");
            return false;
        }
    }

    WinHandle handle(::CreateFileW(
        directory.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    BY_HANDLE_FILE_INFORMATION info{};
    if (!handle || ::GetFileType(handle.value) != FILE_TYPE_DISK
            || !::GetFileInformationByHandle(handle.value, &info)
            || !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            || !HandleHasCurrentOwner(handle.value, owner.sid(), false,
                                      error, "private directory")) {
        if (error && error->empty())
            SetError(error, "directory must be real and owned by the current Windows user");
        return false;
    }
    const DWORD status = ::SetSecurityInfo(
        handle.value, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, owner.acl(), nullptr);
    if (status != ERROR_SUCCESS
            || !HandleHasCurrentOwner(handle.value, owner.sid(), true,
                                      error, "private directory")) {
        if (error && error->empty())
            SetError(error, "cannot apply protected owner-only directory DACL");
        return false;
    }
    return true;
}

#else

struct ParentFd {
    int fd = -1;
    std::string base;
};

inline bool OpenParent(const std::filesystem::path& target, bool require_private_parent,
                       ParentFd& out, std::string* error) {
    if (!ValidTarget(target, error)) return false;
    const auto parent = target.parent_path().empty()
        ? std::filesystem::path(".") : target.parent_path();
    int flags = O_RDONLY | O_CLOEXEC;
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int fd = ::open(parent.c_str(), flags);
    if (fd < 0) {
        SetError(error, std::string("cannot open parent directory: ") + std::strerror(errno));
        return false;
    }
    struct stat st{};
    const bool safe = ::fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)
        && st.st_uid == ::geteuid()
        && (!require_private_parent || (st.st_mode & 0077) == 0);
    if (!safe) {
        ::close(fd);
        SetError(error, require_private_parent
            ? "parent directory must be owned by this uid and mode 0700"
            : "parent directory must be owned by this uid");
        return false;
    }
    out.fd = fd;
    out.base = target.filename().string();
    return true;
}

inline bool ExistingTargetIsSafe(int dfd, const std::string& base, std::string* error) {
    struct stat st{};
    if (::fstatat(dfd, base.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(st.st_mode) || st.st_uid != ::geteuid()) {
            SetError(error, "refusing to replace a link, non-regular file, or foreign-owned file");
            return false;
        }
        return true;
    }
    if (errno == ENOENT) return true;
    SetError(error, std::string("cannot inspect target: ") + std::strerror(errno));
    return false;
}

inline bool AtomicWrite(const std::string& path, const uint8_t* data, size_t size,
                        std::string* error = nullptr, bool require_private_parent = true) {
    ParentFd parent;
    if (!OpenParent(std::filesystem::path(path), require_private_parent, parent, error)) return false;
    if (!ExistingTargetIsSafe(parent.fd, parent.base, error)) {
        ::close(parent.fd);
        return false;
    }

    std::string tmp;
    int fd = -1;
    for (unsigned i = 0; i < 128 && fd < 0; ++i) {
        tmp = parent.base + ".tmp." + std::to_string(static_cast<unsigned long>(::getpid()))
            + "." + std::to_string(i);
        int flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC;
#ifdef O_NOFOLLOW
        flags |= O_NOFOLLOW;
#endif
        fd = ::openat(parent.fd, tmp.c_str(), flags, 0600);
        if (fd < 0 && errno != EEXIST) break;
    }
    if (fd < 0) {
        SetError(error, std::string("cannot create exclusive temporary file: ") + std::strerror(errno));
        ::close(parent.fd);
        return false;
    }

    struct stat st{};
    bool ok = ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == ::geteuid()
        && st.st_nlink == 1 && ::fchmod(fd, 0600) == 0;
    const uint8_t* p = data;
    size_t left = size;
    while (ok && left) {
        const ssize_t wrote = ::write(fd, p, left);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) { ok = false; break; }
        p += static_cast<size_t>(wrote);
        left -= static_cast<size_t>(wrote);
    }
    if (ok) ok = ::fsync(fd) == 0;
    if (::close(fd) != 0) ok = false;

    bool renamed = false;
    if (ok) {
        ok = ::renameat(parent.fd, tmp.c_str(), parent.fd, parent.base.c_str()) == 0;
        renamed = ok;
    }
    if (ok) ok = ::fsync(parent.fd) == 0;
    if (!renamed) ::unlinkat(parent.fd, tmp.c_str(), 0);
    if (::close(parent.fd) != 0) ok = false;
    if (!ok) SetError(error, std::string("secure write/flush/rename failed: ") + std::strerror(errno));
    return ok;
}

inline bool AtomicWriteNew(const std::string& path, const uint8_t* data, size_t size,
                           std::string* error = nullptr,
                           bool require_private_parent = true) {
    ParentFd parent;
    if (!OpenParent(std::filesystem::path(path), require_private_parent, parent, error))
        return false;
    struct stat existing{};
    if (::fstatat(parent.fd, parent.base.c_str(), &existing,
                  AT_SYMLINK_NOFOLLOW) == 0) {
        ::close(parent.fd);
        SetError(error, "immutable target already exists");
        return false;
    }
    if (errno != ENOENT) {
        const int saved = errno; ::close(parent.fd);
        SetError(error, std::string("cannot inspect immutable target: ")
            + std::strerror(saved));
        return false;
    }
    std::string tmp; int fd = -1;
    for (unsigned i = 0; i < 128 && fd < 0; ++i) {
        tmp = parent.base + ".tmp." + std::to_string(
            static_cast<unsigned long>(::getpid())) + "." + std::to_string(i);
        int flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC;
#ifdef O_NOFOLLOW
        flags |= O_NOFOLLOW;
#endif
        fd = ::openat(parent.fd, tmp.c_str(), flags, 0600);
        if (fd < 0 && errno != EEXIST) break;
    }
    if (fd < 0) {
        SetError(error, std::string("cannot create immutable temporary file: ")
            + std::strerror(errno));
        ::close(parent.fd); return false;
    }
    struct stat st{};
    bool ok = ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode)
        && st.st_uid == ::geteuid() && st.st_nlink == 1
        && ::fchmod(fd, 0600) == 0;
    const uint8_t* p = data; size_t left = size;
    while (ok && left) {
        const ssize_t wrote = ::write(fd, p, left);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) { ok = false; break; }
        p += static_cast<size_t>(wrote);
        left -= static_cast<size_t>(wrote);
    }
    if (ok) ok = ::fsync(fd) == 0;
    if (::close(fd) != 0) ok = false;

    bool published = false;
    if (ok) {
        // linkat is the portable no-replace publication primitive: it fails
        // with EEXIST rather than replacing an immutable sequence file.
        ok = ::linkat(parent.fd, tmp.c_str(), parent.fd, parent.base.c_str(), 0) == 0;
        published = ok;
    }
    if (published) {
        // Remove the staging name before the directory fsync so the durable
        // state contains exactly one link to the owner-only inode.
        if (::unlinkat(parent.fd, tmp.c_str(), 0) != 0) {
            ::unlinkat(parent.fd, parent.base.c_str(), 0);
            ok = false;
        }
    } else {
        ::unlinkat(parent.fd, tmp.c_str(), 0);
    }
    if (ok) ok = ::fsync(parent.fd) == 0;
    if (::close(parent.fd) != 0) ok = false;
    if (!ok) SetError(error, "secure immutable write/flush/publish failed");
    return ok;
}

inline ReadResult Read(const std::string& path, std::vector<uint8_t>& out,
                       std::string* error = nullptr, size_t max_size = 64u * 1024u * 1024u,
                       bool require_private_parent = true) {
    WipeAndClear(out);
    ParentFd parent;
    if (!OpenParent(std::filesystem::path(path), require_private_parent, parent, error))
        return ReadResult::Error;
    int flags = O_RDONLY | O_CLOEXEC;
#ifdef O_NONBLOCK
    flags |= O_NONBLOCK; // reject FIFOs/devices after open without ever blocking
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int fd = ::openat(parent.fd, parent.base.c_str(), flags);
    if (fd < 0) {
        const int saved = errno;
        ::close(parent.fd);
        if (saved == ENOENT) return ReadResult::NotFound;
        SetError(error, std::string("cannot open owner-only file: ") + std::strerror(saved));
        return ReadResult::Error;
    }
    struct stat st{};
    bool ok = ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == ::geteuid()
        && st.st_nlink == 1 && (st.st_mode & 0077) == 0 && st.st_size >= 0
        && static_cast<unsigned long long>(st.st_size) <= max_size;
    if (ok) out.resize(static_cast<size_t>(st.st_size));
    size_t got = 0;
    while (ok && got < out.size()) {
        const ssize_t nr = ::read(fd, out.data() + got, out.size() - got);
        if (nr < 0 && errno == EINTR) continue;
        if (nr <= 0) { ok = false; break; }
        got += static_cast<size_t>(nr);
    }
    if (::close(fd) != 0) ok = false;
    ::close(parent.fd);
    if (!ok) {
        WipeAndClear(out);
        SetError(error, "file must be regular, single-link, owner-only, owner-matched, and bounded");
        return ReadResult::Error;
    }
    return ReadResult::Ok;
}

inline bool EnsurePrivateDirectory(const std::string& path, std::string* error = nullptr) {
    std::error_code ec;
    const std::filesystem::path p(path);
    std::filesystem::create_directories(p, ec);
    if (ec) {
        SetError(error, std::string("cannot create private directory: ") + ec.message());
        return false;
    }
    struct stat lst{};
    if (::lstat(p.c_str(), &lst) != 0 || !S_ISDIR(lst.st_mode) || S_ISLNK(lst.st_mode)
        || lst.st_uid != ::geteuid() || ::chmod(p.c_str(), 0700) != 0) {
        SetError(error, "directory must be a real owner-controlled directory");
        return false;
    }
    struct stat st{};
    if (::stat(p.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != ::geteuid()
        || (st.st_mode & 0077) != 0) {
        SetError(error, "directory is not owner-only mode 0700");
        return false;
    }
    return true;
}

#endif

// Explicit, user-selected imports often live in Downloads (0755 parent, 0644
// file), so they cannot use the operational-secret mode policy above.  They
// still need a handle-bound, bounded, no-final-link read and must never block
// on a FIFO/device.  On Unix the selected inode must also belong to this uid.
inline ReadResult ReadExplicitImport(
    const std::string& path, std::vector<uint8_t>& out,
    std::string* error = nullptr, size_t max_size = 4u * 1024u * 1024u)
{
    WipeAndClear(out);
#ifdef _WIN32
    const std::filesystem::path target(path);
    if (!ValidTarget(target, error)) return ReadResult::Error;
    HANDLE h = ::CreateFileW(
        target.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        if (::GetLastError() == ERROR_FILE_NOT_FOUND
            || ::GetLastError() == ERROR_PATH_NOT_FOUND) return ReadResult::NotFound;
        SetError(error, "cannot open explicit import");
        return ReadResult::Error;
    }
    BY_HANDLE_FILE_INFORMATION before{};
    LARGE_INTEGER size{};
    bool ok = ::GetFileInformationByHandle(h, &before)
        && !(before.dwFileAttributes
             & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
        && before.nNumberOfLinks == 1
        && ::GetFileSizeEx(h, &size) && size.QuadPart >= 0
        && static_cast<unsigned long long>(size.QuadPart) <= max_size;
    if (ok) out.resize(static_cast<size_t>(size.QuadPart));
    size_t got = 0;
    while (ok && got < out.size()) {
        DWORD nr = 0;
        const DWORD want = static_cast<DWORD>(
            std::min<size_t>(out.size() - got, 1u << 30));
        ok = ::ReadFile(h, out.data() + got, want, &nr, nullptr) && nr != 0;
        got += nr;
    }
    BY_HANDLE_FILE_INFORMATION after{};
    LARGE_INTEGER final_size{};
    if (ok) {
        ok = ::GetFileInformationByHandle(h, &after)
            && ::GetFileSizeEx(h, &final_size)
            && final_size.QuadPart == size.QuadPart
            && after.dwVolumeSerialNumber == before.dwVolumeSerialNumber
            && after.nFileIndexHigh == before.nFileIndexHigh
            && after.nFileIndexLow == before.nFileIndexLow
            && after.nNumberOfLinks == 1;
    }
    if (!::CloseHandle(h)) ok = false;
#else
    int flags = O_RDONLY | O_CLOEXEC;
#ifdef O_NONBLOCK
    flags |= O_NONBLOCK;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int fd = ::open(path.c_str(), flags);
    if (fd < 0) {
        if (errno == ENOENT) return ReadResult::NotFound;
        SetError(error, std::string("cannot open explicit import: ") + std::strerror(errno));
        return ReadResult::Error;
    }
    struct stat before{};
    bool ok = ::fstat(fd, &before) == 0 && S_ISREG(before.st_mode)
        && before.st_uid == ::geteuid() && before.st_nlink == 1
        && before.st_size >= 0
        && static_cast<unsigned long long>(before.st_size) <= max_size;
    if (ok) out.resize(static_cast<size_t>(before.st_size));
    size_t got = 0;
    while (ok && got < out.size()) {
        const ssize_t nr = ::read(fd, out.data() + got, out.size() - got);
        if (nr < 0 && errno == EINTR) continue;
        if (nr <= 0) { ok = false; break; }
        got += static_cast<size_t>(nr);
    }
    struct stat after{};
    if (ok) {
        ok = ::fstat(fd, &after) == 0 && S_ISREG(after.st_mode)
            && after.st_uid == before.st_uid && after.st_nlink == 1
            && after.st_dev == before.st_dev && after.st_ino == before.st_ino
            && after.st_size == before.st_size;
    }
    if (::close(fd) != 0) ok = false;
#endif
    if (!ok) {
        WipeAndClear(out);
        SetError(error, "import must be a stable, bounded, single-link regular file");
        return ReadResult::Error;
    }
    return ReadResult::Ok;
}

inline bool AtomicWrite(const std::string& path, const std::vector<uint8_t>& data,
                        std::string* error = nullptr, bool require_private_parent = true) {
    return AtomicWrite(path, data.data(), data.size(), error, require_private_parent);
}

inline bool AtomicWriteNew(const std::string& path,
                           const std::vector<uint8_t>& data,
                           std::string* error = nullptr,
                           bool require_private_parent = true) {
    return AtomicWriteNew(path, data.data(), data.size(), error,
                          require_private_parent);
}

inline bool AtomicWriteText(const std::string& path, const std::string& data,
                            std::string* error = nullptr, bool require_private_parent = true) {
    return AtomicWrite(path, reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                       error, require_private_parent);
}

} // namespace secure_file
} // namespace channel
} // namespace veld
