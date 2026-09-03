#pragma once

// Small shell-free process launcher.  Every caller supplies an argv vector, so
// untrusted values are never re-parsed by cmd.exe or /bin/sh.
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <limits>

#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace veld::compat {

struct ProcessResult {
    int exit_code = -1;
    std::string output;
    // True when the child produced more bytes than the caller authorized us
    // to retain.  Callers parsing security-sensitive output must reject this
    // instead of accidentally accepting a valid-looking truncated prefix.
    bool output_truncated = false;
};

enum class BoundedFileStatus : uint8_t {
    Success = 0,
    InvalidArgument,
    OpenFailed,
    SpawnFailed,
    DeadlineExceeded,
    ByteLimitExceeded,
    WriteFailed,
    FlushFailed,
    ChildFailed,
};

struct BoundedFileResult {
    BoundedFileStatus status{BoundedFileStatus::InvalidArgument};
    int exit_code{-1};
    uint64_t bytes_written{0};

    explicit operator bool() const noexcept {
        return status == BoundedFileStatus::Success;
    }
};

inline constexpr size_t kDefaultProcessCaptureBytes = 1024U * 1024U;

inline void AppendBoundedProcessOutput(ProcessResult& result,
                                       const char* data,
                                       size_t size,
                                       size_t maximum) {
    const size_t retained = result.output.size();
    const size_t available = retained < maximum ? maximum - retained : 0;
    const size_t take = size < available ? size : available;
    if (take != 0) result.output.append(data, take);
    if (take != size) result.output_truncated = true;
}

// Resolve the running image itself instead of trusting argv[0] or PATH.  The
// funds-bearing launch daemons use this to invoke only the veld-node shipped
// beside them when asking the node to decrypt its RPC token.
inline std::string ExecutablePath() {
#ifdef _WIN32
    std::vector<char> buffer(32768);
    const DWORD n = ::GetModuleFileNameA(
        nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (n == 0 || n >= buffer.size()) return {};
    return std::string(buffer.data(), static_cast<size_t>(n));
#else
    std::vector<char> buffer(4096);
    while (buffer.size() <= 1024 * 1024) {
        const ssize_t n = ::readlink("/proc/self/exe", buffer.data(), buffer.size());
        if (n < 0) return {};
        if (static_cast<size_t>(n) < buffer.size())
            return std::string(buffer.data(), static_cast<size_t>(n));
        buffer.resize(buffer.size() * 2);
    }
    return {};
#endif
}

// Resolve curl only from an operating-system location whose identity is
// independent of the process current directory and PATH.  Node download and
// oracle callers must refuse their operation when this returns empty.
inline std::string TrustedSystemCurlExecutable() {
#ifdef _WIN32
    std::vector<char> windows_buffer(32768);
    std::vector<char> system_buffer(32768);
    const UINT windows_length = ::GetWindowsDirectoryA(
        windows_buffer.data(), static_cast<UINT>(windows_buffer.size()));
    const UINT system_length = ::GetSystemDirectoryA(
        system_buffer.data(), static_cast<UINT>(system_buffer.size()));
    if (windows_length == 0 || windows_length >= windows_buffer.size() ||
        system_length == 0 || system_length >= system_buffer.size()) {
        return {};
    }

    auto canonicalize = [](const std::string& path) -> std::string {
        if (path.empty()) return {};
        std::vector<char> buffer(32768);
        const DWORD length = ::GetFullPathNameA(
            path.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(),
            nullptr);
        if (length == 0 || length >= buffer.size()) return {};
        std::string result(buffer.data(), static_cast<size_t>(length));
        while (result.size() > 3 &&
               (result.back() == '\\' || result.back() == '/')) {
            result.pop_back();
        }
        return result;
    };
    auto is_absolute_drive_path = [](const std::string& path) {
        return path.size() >= 3 &&
               ((path[0] >= 'A' && path[0] <= 'Z') ||
                (path[0] >= 'a' && path[0] <= 'z')) &&
               path[1] == ':' && (path[2] == '\\' || path[2] == '/');
    };
    auto same_path = [](const std::string& left, const std::string& right) {
        return ::_stricmp(left.c_str(), right.c_str()) == 0;
    };
    auto safe_component = [](const std::string& path, bool directory) {
        const DWORD attributes = ::GetFileAttributesA(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES ||
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            return false;
        }
        const bool is_directory =
            (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        return is_directory == directory;
    };

    const std::string windows_directory = canonicalize(std::string(
        windows_buffer.data(), static_cast<size_t>(windows_length)));
    const std::string system_directory = canonicalize(std::string(
        system_buffer.data(), static_cast<size_t>(system_length)));
    if (!is_absolute_drive_path(windows_directory) ||
        !is_absolute_drive_path(system_directory)) {
        return {};
    }
    const size_t system_separator = system_directory.find_last_of("\\/");
    if (system_separator == std::string::npos ||
        !same_path(system_directory.substr(0, system_separator),
                   windows_directory) ||
        !safe_component(windows_directory, true) ||
        !safe_component(system_directory, true)) {
        return {};
    }

    const std::string candidate = canonicalize(
        system_directory + "\\curl.exe");
    if (!is_absolute_drive_path(candidate) ||
        candidate.find_last_of("\\/") == std::string::npos ||
        !same_path(candidate.substr(0, candidate.find_last_of("\\/")),
                   system_directory) ||
        !safe_component(candidate, false)) {
        return {};
    }

    HANDLE file = ::CreateFileA(
        candidate.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    BY_HANDLE_FILE_INFORMATION information{};
    LARGE_INTEGER file_size{};
    const bool regular_nonempty =
        ::GetFileType(file) == FILE_TYPE_DISK &&
        ::GetFileInformationByHandle(file, &information) != FALSE &&
        (information.dwFileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
        ::GetFileSizeEx(file, &file_size) != FALSE && file_size.QuadPart > 0;
    std::vector<char> final_buffer(32768);
    const DWORD final_length = regular_nonempty
        ? ::GetFinalPathNameByHandleA(
              file, final_buffer.data(), static_cast<DWORD>(final_buffer.size()),
              FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)
        : 0;
    ::CloseHandle(file);
    if (final_length == 0 || final_length >= final_buffer.size()) return {};

    std::string final_path(
        final_buffer.data(), static_cast<size_t>(final_length));
    constexpr const char* extended_prefix = "\\\\?\\";
    if (final_path.rfind(extended_prefix, 0) == 0) {
        final_path.erase(0, std::strlen(extended_prefix));
    }
    final_path = canonicalize(final_path);
    if (!same_path(final_path, candidate)) return {};
    return candidate;
#else
    static constexpr const char* candidates[] = {
        "/usr/bin/curl", "/bin/curl", "/usr/local/bin/curl"};
    static constexpr const char* canonical_allowlist[] = {
        "/usr/bin/curl", "/bin/curl", "/usr/local/bin/curl"};

    auto secure_root_owned_directory = [](const std::string& path) {
        struct stat status{};
        return ::lstat(path.c_str(), &status) == 0 &&
               S_ISDIR(status.st_mode) && status.st_uid == 0 &&
               (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
    };
    for (const char* candidate : candidates) {
        char* resolved = ::realpath(candidate, nullptr);
        if (resolved == nullptr) continue;
        const std::string canonical(resolved);
        std::free(resolved);

        bool allowed = false;
        for (const char* expected : canonical_allowlist) {
            if (canonical == expected) {
                allowed = true;
                break;
            }
        }
        if (!allowed || canonical.empty() || canonical.front() != '/' ||
            !secure_root_owned_directory("/")) {
            continue;
        }

        bool secure_parents = true;
        size_t component_start = 1;
        while (component_start < canonical.size()) {
            const size_t separator = canonical.find('/', component_start);
            if (separator == std::string::npos) break;
            if (!secure_root_owned_directory(
                    canonical.substr(0, separator))) {
                secure_parents = false;
                break;
            }
            component_start = separator + 1;
        }
        if (!secure_parents) continue;

        struct stat status{};
        if (::lstat(canonical.c_str(), &status) != 0 ||
            !S_ISREG(status.st_mode) || status.st_uid != 0 ||
            status.st_size <= 0 ||
            (status.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
            (status.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0 ||
            ::access(canonical.c_str(), X_OK) != 0) {
            continue;
        }
        return canonical;
    }
    return {};
#endif
}

// Resolve the operating-system archive reader without consulting PATH.  The
// snapshot bootstrap uses this only after a signed archive digest and a
// bounded member listing have been verified.  Refuse reparse/symlinked tools
// and writable non-system locations.
inline std::string TrustedSystemTarExecutable() {
#ifdef _WIN32
    std::vector<char> windows_buffer(32768);
    std::vector<char> system_buffer(32768);
    const UINT windows_length = ::GetWindowsDirectoryA(
        windows_buffer.data(), static_cast<UINT>(windows_buffer.size()));
    const UINT system_length = ::GetSystemDirectoryA(
        system_buffer.data(), static_cast<UINT>(system_buffer.size()));
    if (windows_length == 0 || windows_length >= windows_buffer.size() ||
        system_length == 0 || system_length >= system_buffer.size()) return {};

    auto canonicalize = [](const std::string& path) -> std::string {
        std::vector<char> buffer(32768);
        const DWORD length = ::GetFullPathNameA(
            path.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(),
            nullptr);
        if (length == 0 || length >= buffer.size()) return {};
        return std::string(buffer.data(), static_cast<size_t>(length));
    };
    auto same_path = [](const std::string& left, const std::string& right) {
        return ::_stricmp(left.c_str(), right.c_str()) == 0;
    };
    auto safe_component = [](const std::string& path, bool directory) {
        const DWORD attributes = ::GetFileAttributesA(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES ||
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) return false;
        return ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) == directory;
    };

    const std::string windows_directory = canonicalize(std::string(
        windows_buffer.data(), static_cast<size_t>(windows_length)));
    const std::string system_directory = canonicalize(std::string(
        system_buffer.data(), static_cast<size_t>(system_length)));
    const size_t separator = system_directory.find_last_of("\\/");
    if (windows_directory.empty() || system_directory.empty() ||
        separator == std::string::npos ||
        !same_path(system_directory.substr(0, separator), windows_directory) ||
        !safe_component(windows_directory, true) ||
        !safe_component(system_directory, true)) return {};

    const std::string candidate = canonicalize(system_directory + "\\tar.exe");
    if (candidate.empty() || !safe_component(candidate, false)) return {};
    HANDLE file = ::CreateFileA(
        candidate.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    BY_HANDLE_FILE_INFORMATION information{};
    LARGE_INTEGER size{};
    const bool regular_nonempty =
        ::GetFileType(file) == FILE_TYPE_DISK &&
        ::GetFileInformationByHandle(file, &information) != FALSE &&
        (information.dwFileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
        ::GetFileSizeEx(file, &size) != FALSE && size.QuadPart > 0;
    std::vector<char> final_buffer(32768);
    const DWORD final_length = regular_nonempty
        ? ::GetFinalPathNameByHandleA(
              file, final_buffer.data(), static_cast<DWORD>(final_buffer.size()),
              FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)
        : 0;
    ::CloseHandle(file);
    if (final_length == 0 || final_length >= final_buffer.size()) return {};
    std::string final_path(final_buffer.data(), final_length);
    if (final_path.rfind("\\\\?\\", 0) == 0) final_path.erase(0, 4);
    final_path = canonicalize(final_path);
    if (!same_path(final_path, candidate)) return {};
    return candidate;
#else
    static constexpr const char* candidates[] = {"/usr/bin/tar", "/bin/tar"};
    auto secure_directory = [](const std::string& path) {
        struct stat status{};
        return ::lstat(path.c_str(), &status) == 0 &&
               S_ISDIR(status.st_mode) && status.st_uid == 0 &&
               (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
    };
    for (const char* candidate : candidates) {
        char* resolved = ::realpath(candidate, nullptr);
        if (!resolved) continue;
        const std::string canonical(resolved);
        std::free(resolved);
        if (canonical != "/usr/bin/tar" && canonical != "/bin/tar") continue;
        bool parents_ok = secure_directory("/");
        size_t start = 1;
        while (parents_ok && start < canonical.size()) {
            const size_t slash = canonical.find('/', start);
            if (slash == std::string::npos) break;
            parents_ok = secure_directory(canonical.substr(0, slash));
            start = slash + 1;
        }
        struct stat status{};
        if (parents_ok && ::lstat(canonical.c_str(), &status) == 0 &&
            S_ISREG(status.st_mode) && status.st_uid == 0 && status.st_size > 0 &&
            (status.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
            (status.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0 &&
            ::access(canonical.c_str(), X_OK) == 0) return canonical;
    }
    return {};
#endif
}

#ifdef _WIN32
inline std::string QuoteWindowsArg(const std::string& arg) {
    if (arg.empty()) return "\"\"";
    if (arg.find_first_of(" \t\n\v\"") == std::string::npos) return arg;
    std::string out = "\""; unsigned slashes = 0;
    for (char c : arg) {
        if (c == '\\') { ++slashes; continue; }
        if (c == '"') { out.append(slashes * 2 + 1, '\\'); out += '"'; slashes = 0; continue; }
        out.append(slashes, '\\'); slashes = 0; out += c;
    }
    out.append(slashes * 2, '\\'); out += '"'; return out;
}

inline ProcessResult RunProcess(const std::vector<std::string>& argv, bool capture_stdout = false,
                                const std::string& working_dir = {}, bool capture_stderr = false,
                                size_t max_output_bytes = kDefaultProcessCaptureBytes) {
    ProcessResult result; if (argv.empty()) return result;
    std::string command;
    for (const auto& a : argv) { if (!command.empty()) command += ' '; command += QuoteWindowsArg(a); }
    HANDLE read_h = nullptr, write_h = nullptr;
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    if (capture_stdout && (!CreatePipe(&read_h, &write_h, &sa, 0) ||
                           !SetHandleInformation(read_h, HANDLE_FLAG_INHERIT, 0))) return result;
    STARTUPINFOA si{}; si.cb = sizeof(si);
    if (capture_stdout) {
        si.dwFlags = STARTF_USESTDHANDLES; si.hStdOutput = write_h;
        si.hStdError = capture_stderr ? write_h : GetStdHandle(STD_ERROR_HANDLE);
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    }
    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessA(nullptr, command.data(), nullptr, nullptr, capture_stdout ? TRUE : FALSE,
                             CREATE_NO_WINDOW, nullptr, working_dir.empty() ? nullptr : working_dir.c_str(), &si, &pi);
    if (write_h) CloseHandle(write_h);
    if (!ok) { if (read_h) CloseHandle(read_h); return result; }
    if (capture_stdout) {
        char buf[8192]; DWORD n = 0;
        while (ReadFile(read_h, buf, sizeof(buf), &n, nullptr) && n)
            AppendBoundedProcessOutput(
                result, buf, static_cast<size_t>(n), max_output_bytes);
        CloseHandle(read_h);
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1; GetExitCodeProcess(pi.hProcess, &code); result.exit_code = static_cast<int>(code);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return result;
}

// Launch a shell-free child and copy its stdout into a parent-owned file while
// enforcing both a byte ceiling and a wall-clock deadline.  The destination is
// created exclusively, is never inherited by the child, and is removed on
// every failure.  This is the transfer-boundary primitive used by downloads:
// command-specific controls such as curl --max-filesize can reject a declared
// oversized Content-Length early, while this independent counter also stops
// chunked or otherwise undeclared bodies.
inline BoundedFileResult RunProcessToBoundedFile(
        const std::vector<std::string>& argv,
        const std::string& destination,
        uint64_t maximum_bytes,
        std::chrono::milliseconds deadline,
        const std::string& working_dir = {}) {
    BoundedFileResult result;
    if (argv.empty() || destination.empty() || maximum_bytes == 0 ||
        deadline.count() <= 0) {
        return result;
    }

    HANDLE file_h = ::CreateFileA(
        destination.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file_h == INVALID_HANDLE_VALUE) {
        result.status = BoundedFileStatus::OpenFailed;
        return result;
    }
    bool keep_file = false;
    auto close_and_cleanup = [&]() {
        if (file_h != INVALID_HANDLE_VALUE) {
            ::CloseHandle(file_h);
            file_h = INVALID_HANDLE_VALUE;
        }
        if (!keep_file) ::DeleteFileA(destination.c_str());
    };

    HANDLE read_h = nullptr;
    HANDLE write_h = nullptr;
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    if (!::CreatePipe(&read_h, &write_h, &sa, 0) ||
        !::SetHandleInformation(read_h, HANDLE_FLAG_INHERIT, 0)) {
        if (read_h) ::CloseHandle(read_h);
        if (write_h) ::CloseHandle(write_h);
        result.status = BoundedFileStatus::SpawnFailed;
        close_and_cleanup();
        return result;
    }

    std::string command;
    for (const auto& a : argv) {
        if (!command.empty()) command += ' ';
        command += QuoteWindowsArg(a);
    }
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = write_h;
    si.hStdError = ::GetStdHandle(STD_ERROR_HANDLE);
    si.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi{};
    const BOOL spawned = ::CreateProcessA(
        nullptr, command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
        nullptr, working_dir.empty() ? nullptr : working_dir.c_str(), &si, &pi);
    ::CloseHandle(write_h);
    write_h = nullptr;
    if (!spawned) {
        ::CloseHandle(read_h);
        result.status = BoundedFileStatus::SpawnFailed;
        close_and_cleanup();
        return result;
    }

    result.status = BoundedFileStatus::ChildFailed;
    const auto expires = std::chrono::steady_clock::now() + deadline;
    bool child_done = false;
    bool pipe_done = false;
    char buffer[8192];
    while (!(child_done && pipe_done)) {
        if (std::chrono::steady_clock::now() >= expires) {
            result.status = BoundedFileStatus::DeadlineExceeded;
            break;
        }

        DWORD available = 0;
        if (!::PeekNamedPipe(read_h, nullptr, 0, nullptr, &available, nullptr)) {
            const DWORD error = ::GetLastError();
            if (error == ERROR_BROKEN_PIPE) {
                pipe_done = true;
            } else {
                result.status = BoundedFileStatus::WriteFailed;
                break;
            }
        }
        while (available != 0) {
            const DWORD request = available < sizeof(buffer)
                                      ? available
                                      : static_cast<DWORD>(sizeof(buffer));
            DWORD received = 0;
            if (!::ReadFile(read_h, buffer, request, &received, nullptr)) {
                if (::GetLastError() == ERROR_BROKEN_PIPE) {
                    pipe_done = true;
                    available = 0;
                    break;
                }
                result.status = BoundedFileStatus::WriteFailed;
                available = 0;
                break;
            }
            if (received == 0) {
                pipe_done = true;
                available = 0;
                break;
            }
            if (result.bytes_written > maximum_bytes ||
                received > maximum_bytes - result.bytes_written) {
                result.status = BoundedFileStatus::ByteLimitExceeded;
                available = 0;
                break;
            }
            DWORD offset = 0;
            while (offset != received) {
                DWORD written = 0;
                if (!::WriteFile(file_h, buffer + offset, received - offset,
                                 &written, nullptr) || written == 0) {
                    result.status = BoundedFileStatus::WriteFailed;
                    break;
                }
                offset += written;
            }
            if (offset != received) {
                available = 0;
                break;
            }
            result.bytes_written += received;
            if (!::PeekNamedPipe(read_h, nullptr, 0, nullptr, &available,
                                 nullptr)) {
                if (::GetLastError() == ERROR_BROKEN_PIPE) pipe_done = true;
                available = 0;
            }
        }
        if (result.status == BoundedFileStatus::ByteLimitExceeded ||
            result.status == BoundedFileStatus::WriteFailed) {
            break;
        }

        const DWORD wait = ::WaitForSingleObject(pi.hProcess, 20);
        child_done = wait == WAIT_OBJECT_0;
        if (child_done && !pipe_done) {
            DWORD after = 0;
            if (!::PeekNamedPipe(read_h, nullptr, 0, nullptr, &after, nullptr) &&
                ::GetLastError() == ERROR_BROKEN_PIPE) {
                pipe_done = true;
            }
        }
    }

    if (!(child_done && pipe_done)) {
        ::TerminateProcess(pi.hProcess, 1);
    }
    ::WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 1;
    ::GetExitCodeProcess(pi.hProcess, &exit_code);
    result.exit_code = static_cast<int>(exit_code);
    ::CloseHandle(read_h);
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);

    if (result.status != BoundedFileStatus::DeadlineExceeded &&
        result.status != BoundedFileStatus::ByteLimitExceeded &&
        result.status != BoundedFileStatus::WriteFailed) {
        if (result.exit_code != 0) {
            result.status = BoundedFileStatus::ChildFailed;
        } else if (!::FlushFileBuffers(file_h)) {
            result.status = BoundedFileStatus::FlushFailed;
        } else {
            result.status = BoundedFileStatus::Success;
            keep_file = true;
        }
    }
    close_and_cleanup();
    return result;
}

inline bool RunDetached(const std::vector<std::string>& argv) {
    if (argv.empty()) return false;
    std::string command;
    for (const auto& a : argv) { if (!command.empty()) command += ' '; command += QuoteWindowsArg(a); }
    STARTUPINFOA si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessA(nullptr, command.data(), nullptr, nullptr, FALSE,
                             DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP, nullptr, nullptr, &si, &pi);
    if (ok) { CloseHandle(pi.hThread); CloseHandle(pi.hProcess); }
    return ok != FALSE;
}
#else
inline ProcessResult RunProcess(const std::vector<std::string>& argv, bool capture_stdout = false,
                                const std::string& working_dir = {}, bool capture_stderr = false,
                                size_t max_output_bytes = kDefaultProcessCaptureBytes) {
    ProcessResult result; if (argv.empty()) return result;
    int p[2] = {-1, -1};
    if (capture_stdout && ::pipe(p) != 0) return result;
    pid_t pid = ::fork();
    if (pid < 0) { if (capture_stdout) { ::close(p[0]); ::close(p[1]); } return result; }
    if (pid == 0) {
        if (capture_stdout) {
            ::dup2(p[1], STDOUT_FILENO);
            if (capture_stderr) ::dup2(p[1], STDERR_FILENO);
            ::close(p[0]); ::close(p[1]);
        }
        if (!working_dir.empty() && ::chdir(working_dir.c_str()) != 0) _exit(126);
        std::vector<char*> av; av.reserve(argv.size() + 1);
        for (const auto& s : argv) av.push_back(const_cast<char*>(s.c_str()));
        av.push_back(nullptr); ::execvp(av[0], av.data()); _exit(127);
    }
    if (capture_stdout) {
        ::close(p[1]); char buf[8192];
        for (;;) { ssize_t n = ::read(p[0], buf, sizeof(buf));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            AppendBoundedProcessOutput(
                result, buf, static_cast<size_t>(n), max_output_bytes); }
        ::close(p[0]);
    }
    int status = 0; while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return result;
}

inline BoundedFileResult RunProcessToBoundedFile(
        const std::vector<std::string>& argv,
        const std::string& destination,
        uint64_t maximum_bytes,
        std::chrono::milliseconds deadline,
        const std::string& working_dir = {}) {
    BoundedFileResult result;
    if (argv.empty() || destination.empty() || maximum_bytes == 0 ||
        deadline.count() <= 0) {
        return result;
    }

    int file_fd = ::open(destination.c_str(), O_WRONLY | O_CREAT | O_EXCL |
#ifdef O_NOFOLLOW
                                                O_NOFOLLOW |
#endif
#ifdef O_CLOEXEC
                                                O_CLOEXEC |
#endif
                                                0,
                         0600);
    if (file_fd < 0) {
        result.status = BoundedFileStatus::OpenFailed;
        return result;
    }
    bool keep_file = false;
    auto close_and_cleanup = [&]() {
        if (file_fd >= 0) {
            ::close(file_fd);
            file_fd = -1;
        }
        if (!keep_file) ::unlink(destination.c_str());
    };

    int pipe_fds[2] = {-1, -1};
    if (::pipe(pipe_fds) != 0) {
        result.status = BoundedFileStatus::SpawnFailed;
        close_and_cleanup();
        return result;
    }
    const int current_flags = ::fcntl(pipe_fds[0], F_GETFL, 0);
    if (current_flags < 0 ||
        ::fcntl(pipe_fds[0], F_SETFL, current_flags | O_NONBLOCK) != 0) {
        ::close(pipe_fds[0]);
        ::close(pipe_fds[1]);
        result.status = BoundedFileStatus::SpawnFailed;
        close_and_cleanup();
        return result;
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(pipe_fds[0]);
        ::close(pipe_fds[1]);
        result.status = BoundedFileStatus::SpawnFailed;
        close_and_cleanup();
        return result;
    }
    if (pid == 0) {
        ::dup2(pipe_fds[1], STDOUT_FILENO);
        ::close(pipe_fds[0]);
        ::close(pipe_fds[1]);
        ::close(file_fd);
        if (!working_dir.empty() && ::chdir(working_dir.c_str()) != 0) _exit(126);
        std::vector<char*> av;
        av.reserve(argv.size() + 1);
        for (const auto& s : argv) av.push_back(const_cast<char*>(s.c_str()));
        av.push_back(nullptr);
        ::execvp(av[0], av.data());
        _exit(127);
    }
    ::close(pipe_fds[1]);
    pipe_fds[1] = -1;

    result.status = BoundedFileStatus::ChildFailed;
    const auto expires = std::chrono::steady_clock::now() + deadline;
    bool child_done = false;
    bool pipe_done = false;
    int child_status = 0;
    char buffer[8192];
    while (!(child_done && pipe_done)) {
        if (std::chrono::steady_clock::now() >= expires) {
            result.status = BoundedFileStatus::DeadlineExceeded;
            break;
        }

        struct pollfd pfd{};
        pfd.fd = pipe_fds[0];
        pfd.events = POLLIN | POLLHUP;
        const int polled = ::poll(&pfd, 1, 20);
        if (polled < 0 && errno != EINTR) {
            result.status = BoundedFileStatus::WriteFailed;
            break;
        }
        if (polled > 0 && (pfd.revents & (POLLIN | POLLHUP))) {
            for (;;) {
                const ssize_t received = ::read(pipe_fds[0], buffer, sizeof(buffer));
                if (received > 0) {
                    const uint64_t amount = static_cast<uint64_t>(received);
                    if (result.bytes_written > maximum_bytes ||
                        amount > maximum_bytes - result.bytes_written) {
                        result.status = BoundedFileStatus::ByteLimitExceeded;
                        break;
                    }
                    ssize_t offset = 0;
                    while (offset != received) {
                        const ssize_t written = ::write(
                            file_fd, buffer + offset,
                            static_cast<size_t>(received - offset));
                        if (written < 0 && errno == EINTR) continue;
                        if (written <= 0) {
                            result.status = BoundedFileStatus::WriteFailed;
                            break;
                        }
                        offset += written;
                    }
                    if (offset != received) break;
                    result.bytes_written += amount;
                    continue;
                }
                if (received == 0) pipe_done = true;
                if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                    errno != EINTR) {
                    result.status = BoundedFileStatus::WriteFailed;
                }
                break;
            }
        }
        if (result.status == BoundedFileStatus::ByteLimitExceeded ||
            result.status == BoundedFileStatus::WriteFailed) {
            break;
        }
        if (!child_done) {
            const pid_t waited = ::waitpid(pid, &child_status, WNOHANG);
            if (waited == pid) child_done = true;
            else if (waited < 0 && errno != EINTR) {
                result.status = BoundedFileStatus::ChildFailed;
                break;
            }
        }
    }

    if (!child_done) {
        ::kill(pid, SIGKILL);
        while (::waitpid(pid, &child_status, 0) < 0 && errno == EINTR) {}
        child_done = true;
    }
    ::close(pipe_fds[0]);
    result.exit_code = WIFEXITED(child_status) ? WEXITSTATUS(child_status) : -1;

    if (result.status != BoundedFileStatus::DeadlineExceeded &&
        result.status != BoundedFileStatus::ByteLimitExceeded &&
        result.status != BoundedFileStatus::WriteFailed) {
        if (result.exit_code != 0) {
            result.status = BoundedFileStatus::ChildFailed;
        } else if (::fsync(file_fd) != 0) {
            result.status = BoundedFileStatus::FlushFailed;
        } else {
            result.status = BoundedFileStatus::Success;
            keep_file = true;
        }
    }
    close_and_cleanup();
    return result;
}

inline bool RunDetached(const std::vector<std::string>& argv) {
    if (argv.empty()) return false;
    pid_t first = ::fork(); if (first < 0) return false;
    if (first == 0) {
        pid_t second = ::fork(); if (second < 0) _exit(1); if (second > 0) _exit(0);
        ::setsid(); int devnull = ::open("/dev/null", O_RDWR);
        if (devnull >= 0) { ::dup2(devnull, 0); ::dup2(devnull, 1); ::dup2(devnull, 2); if (devnull > 2) ::close(devnull); }
        std::vector<char*> av; av.reserve(argv.size() + 1);
        for (const auto& s : argv) av.push_back(const_cast<char*>(s.c_str()));
        av.push_back(nullptr); ::execvp(av[0], av.data()); _exit(127);
    }
    int status = 0; while (::waitpid(first, &status, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
#endif

} // namespace veld::compat
