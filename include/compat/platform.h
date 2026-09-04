#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>
#include <aclapi.h>
#include <vector>
#include <string>
#include <cstdint>
#include <limits>

typedef SSIZE_T ssize_t;

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#define VELD_CLOSE_SOCKET(fd) ::closesocket(fd)

#include <filesystem>
inline std::string VeldTmpDir() {
    return std::filesystem::temp_directory_path().string() + "/";
}

namespace veld {
namespace compat {

// Winsock SOCKET is an unsigned pointer-sized handle (UINT_PTR), not a POSIX
// file descriptor.  Storing it in int truncates valid handles on 64-bit
// Windows even though MinGW may only warn about the conversion.  Network code
// uses this cross-platform type so the native handle width is preserved while
// POSIX continues to use int exactly as before.
using SocketHandle = SOCKET;
inline constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
inline constexpr bool IsValidSocket(SocketHandle socket) noexcept {
    return socket != kInvalidSocket;
}
static_assert(sizeof(SocketHandle) >= sizeof(uintptr_t),
              "Windows socket handles must remain pointer-width");

inline void InitNetwork() {
    static bool done = false;
    if (!done) {
        WSADATA w;
        WSAStartup(MAKEWORD(2, 2), &w);
        done = true;
    }
}

inline void UnsetEnv(const char* name) {
    _putenv_s(name, "");
}

inline void HardenDllSearchPath() {
    static bool done = false;
    if (done)
        return;
    done = true;
    typedef BOOL(WINAPI * PFN_SetDefaultDllDirectories)(DWORD);
    HMODULE k32 = ::GetModuleHandleA("kernel32.dll");
    if (!k32)
        return;
    PFN_SetDefaultDllDirectories p =
        (PFN_SetDefaultDllDirectories)::GetProcAddress(k32, "SetDefaultDllDirectories");
    if (p) {
        p(0x00000800);
    } else {
        ::SetDllDirectoryA("");
    }
}

inline bool SecureRandom(uint8_t* buf, size_t len) {
    if (len == 0)
        return true;
    if (!buf || len > static_cast<size_t>(std::numeric_limits<ULONG>::max()))
        return false;
    NTSTATUS status = ::BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (status == 0);
}

inline constexpr const char* SecureRandomBackendName() noexcept {
    return "Windows BCryptGenRandom system provider";
}

inline void SecureZero(void* ptr, size_t len) {
    ::SecureZeroMemory(ptr, len);
}

inline bool SecureLockMemory(void* ptr, size_t len) {
    if (!ptr || len == 0)
        return false;
    return ::VirtualLock(ptr, len) != 0;
}
inline void SecureUnlockMemory(void* ptr, size_t len) {
    if (!ptr || len == 0)
        return;
    ::VirtualUnlock(ptr, len);
}

inline bool RestrictFileToOwner(const std::string& path) {
    HANDLE token = NULL;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;

    DWORD len = 0;
    ::GetTokenInformation(token, TokenUser, NULL, 0, &len);
    std::vector<uint8_t> buf(len);
    if (!::GetTokenInformation(token, TokenUser, buf.data(), len, &len)) {
        ::CloseHandle(token);
        return false;
    }
    ::CloseHandle(token);

    TOKEN_USER* user = (TOKEN_USER*)buf.data();
    PSID owner_sid = user->User.Sid;

    EXPLICIT_ACCESS_A ea{};
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = (LPSTR)owner_sid;

    PACL acl = NULL;
    if (::SetEntriesInAclA(1, &ea, NULL, &acl) != ERROR_SUCCESS)
        return false;

    DWORD result = ::SetNamedSecurityInfoA(
        (LPSTR)path.c_str(), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, acl, NULL);

    ::LocalFree(acl);
    return (result == ERROR_SUCCESS);
}

inline bool ConsoleEchoOff() {
    HANDLE h = ::GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (!::GetConsoleMode(h, &mode))
        return false;
    return ::SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);
}
inline bool ConsoleEchoOn() {
    HANDLE h = ::GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (!::GetConsoleMode(h, &mode))
        return false;
    return ::SetConsoleMode(h, mode | ENABLE_ECHO_INPUT);
}

inline bool ConstantTimeEqual(const std::string& a, const std::string& b) {
    size_t n = a.size() > b.size() ? a.size() : b.size();
    volatile uint8_t diff = (uint8_t)((a.size() ^ b.size()) != 0);
    for (size_t i = 0; i < n; ++i) {
        uint8_t ai = (i < a.size()) ? (uint8_t)a[i] : 0;
        uint8_t bi = (i < b.size()) ? (uint8_t)b[i] : 0;
        diff |= ai ^ bi;
    }
    return diff == 0;
}

inline bool ConstantTimeEqual(const uint8_t* a, const uint8_t* b, size_t n) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

} // namespace compat
} // namespace veld

#else

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <sys/stat.h>
#include <sys/mman.h>
#include <poll.h>
#if !defined(__EMSCRIPTEN__)
#include <termios.h>
#endif

#define VELD_CLOSE_SOCKET(fd) ::close(fd)

inline std::string VeldTmpDir() {
    return "/tmp/";
}

namespace veld {
namespace compat {

using SocketHandle = int;
inline constexpr SocketHandle kInvalidSocket = -1;
inline constexpr bool IsValidSocket(SocketHandle socket) noexcept {
    return socket != kInvalidSocket;
}

inline void InitNetwork() {}

inline void HardenDllSearchPath() {}

inline void UnsetEnv(const char* name) {
    ::unsetenv(name);
}

// Cryptographic random-byte generation.
// Previously this function used `/dev/urandom` raw with no entropy-
// availability check. On a freshly-booted device with thin entropy at
// first wallet-create, the wallet salt/nonce could be drawn from a
// not-yet-seeded RNG → password-cracking cost drops dramatically. PQClean's
// own `randombytes()` is much more careful (prefers getrandom(); aborts
// on failure since ). This routine now matches that pattern.
//
// Uses getrandom(2) (Linux 3.17+) with flags=0 — blocks until the kernel
// pool is initialised, which is the right behavior at process start. If
// getrandom is unavailable (very old kernels, alternate libcs), falls back
// to /dev/urandom with O_CLOEXEC so the fd doesn't leak across exec.
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#if defined(__linux__) && defined(SYS_getrandom)
#define VELD_HAS_GETRANDOM 1
#endif

#if defined(__EMSCRIPTEN__)
extern "C" int PQCLEAN_randombytes(uint8_t* output, size_t n);
#endif

inline bool SecureRandom(uint8_t* buf, size_t len) {
    if (len == 0)
        return true;
    if (!buf)
        return false;
#if defined(__EMSCRIPTEN__)
    // The WASM build links vendor/pqc/randombytes.c, whose Emscripten branch
    // uses browser/Node Web Crypto and aborts on failure.  Do not fall through
    // to the POSIX /dev/urandom or getrandom shims: those are not host entropy
    // sources inside a browser sandbox.
    return PQCLEAN_randombytes(buf, len) == 0;
#else
    size_t got = 0;
#ifdef VELD_HAS_GETRANDOM
    while (got < len) {
        long r = ::syscall(SYS_getrandom, buf + got, len - got, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        got += (size_t)r;
    }
    if (got == len)
        return true;
#endif
    int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    while (got < len) {
        ssize_t r = ::read(fd, buf + got, len - got);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            ::close(fd);
            return false;
        }
        if (r == 0) {
            ::close(fd);
            return false;
        }
        got += (size_t)r;
    }
    ::close(fd);
    return true;
#endif
}

inline constexpr const char* SecureRandomBackendName() noexcept {
#if defined(__EMSCRIPTEN__)
    return "Web Crypto through PQClean randombytes";
#elif defined(VELD_HAS_GETRANDOM)
    return "Linux getrandom with kernel urandom fallback";
#else
    return "kernel urandom device";
#endif
}

inline void SecureZero(void* ptr, size_t len) {
#if defined(__EMSCRIPTEN__)
    volatile uint8_t* out = static_cast<volatile uint8_t*>(ptr);
    while (len-- != 0)
        *out++ = 0;
#else
    explicit_bzero(ptr, len);
#endif
}

inline bool SecureLockMemory(void* ptr, size_t len) {
    if (!ptr || len == 0)
        return false;
#if defined(__EMSCRIPTEN__)
    // WebAssembly exposes no mlock equivalent.  The key buffers are still
    // explicitly wiped, and the browser process owns the linear-memory pages.
    return true;
#else
    return ::mlock(ptr, len) == 0;
#endif
}
inline void SecureUnlockMemory(void* ptr, size_t len) {
    if (!ptr || len == 0)
        return;
#if !defined(__EMSCRIPTEN__)
    ::munlock(ptr, len);
#endif
}

inline bool RestrictFileToOwner(const std::string& path) {
    return (::chmod(path.c_str(), 0600) == 0);
}

inline bool ConsoleEchoOff() {
#if defined(__EMSCRIPTEN__)
    return true;
#else
    struct termios mode{};
    if (::tcgetattr(STDIN_FILENO, &mode) != 0)
        return false;
    mode.c_lflag &= static_cast<tcflag_t>(~ECHO);
    return ::tcsetattr(STDIN_FILENO, TCSANOW, &mode) == 0;
#endif
}
inline bool ConsoleEchoOn() {
#if defined(__EMSCRIPTEN__)
    return true;
#else
    struct termios mode{};
    if (::tcgetattr(STDIN_FILENO, &mode) != 0)
        return false;
    mode.c_lflag |= ECHO;
    return ::tcsetattr(STDIN_FILENO, TCSANOW, &mode) == 0;
#endif
}

inline bool ConstantTimeEqual(const std::string& a, const std::string& b) {
    size_t n = a.size() > b.size() ? a.size() : b.size();
    volatile uint8_t diff = (uint8_t)((a.size() ^ b.size()) != 0);
    for (size_t i = 0; i < n; ++i) {
        uint8_t ai = (i < a.size()) ? (uint8_t)a[i] : 0;
        uint8_t bi = (i < b.size()) ? (uint8_t)b[i] : 0;
        diff |= ai ^ bi;
    }
    return diff == 0;
}

inline bool ConstantTimeEqual(const uint8_t* a, const uint8_t* b, size_t n) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

} // namespace compat
} // namespace veld

#endif

#include <chrono>

namespace veld {
namespace compat {

// Process-monotonic clock for security timeouts and internal durations.
// Use wall time only for consensus timestamps, peer clock-skew checks, and
// operator-facing log timestamps. Monotonic values are process-local and must
// never be persisted.
inline uint64_t MonotonicSeconds() {
    using namespace std::chrono;
    return (uint64_t)duration_cast<seconds>(steady_clock::now().time_since_epoch()).count();
}

} // namespace compat
} // namespace veld
