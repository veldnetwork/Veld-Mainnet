#pragma once
#include "network/developer_testnet_profile.h"
#include "compat/platform.h"
#include "compat/secure_string.h"
#include <string>
#if defined(VELD_DEVELOPER_TESTNET) && defined(__linux__)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>

namespace veld::developer_testnet {
// The service manager passes a read-only credential inode, never secret text
// in arguments or environment. Consume it before opening any chain state.
inline bool ReadServiceSecret(int fd, std::string& out) {
    WipeString(out);
    if (fd < 3)
        return false;
    struct Close {
        int fd;
        ~Close() {
            ::close(fd);
        }
    } close{fd};
    struct stat before {
    }, after{};
    const int flags = ::fcntl(fd, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY || ::fstat(fd, &before) != 0 ||
        !S_ISREG(before.st_mode) || before.st_nlink != 1 || before.st_uid != ::geteuid() ||
        (before.st_mode & 0777) != 0400 || before.st_size != 64)
        return false;
    char value[64]{};
    struct Erase {
        char* value;
        ~Erase() {
            compat::SecureZero(value, 64);
        }
    } erase{value};
    size_t offset = 0;
    while (offset < sizeof(value)) {
        const auto n = ::pread(fd, value + offset, sizeof(value) - offset, offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        offset += size_t(n);
    }
    for (unsigned char c : value)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    if (::fstat(fd, &after) != 0 || before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
        return false;
    out.assign(value, sizeof(value));
    return true;
}
} // namespace veld::developer_testnet
#endif
