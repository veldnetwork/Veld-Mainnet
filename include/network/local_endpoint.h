#pragma once

#include "../compat/platform.h"
#include <memory>
#include <vector>

#ifdef _WIN32
#include <iphlpapi.h>
#elif defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#else
#include <ifaddrs.h>
#endif

namespace veld::net {

// Use operating-system interface ownership, never peer announcements or DNS,
// to decide whether a resolved IPv4 address belongs to this machine.
inline bool IsLocalIPv4Address(const in_addr& address) {
    const uint32_t host_address = ntohl(address.s_addr);
    if (host_address == INADDR_ANY || (host_address >> 24) == 127) return true;
#ifdef _WIN32
    ULONG size = 16384;
    constexpr ULONG max_size = 1024 * 1024;
    for (int attempt = 0; attempt < 3 && size <= max_size; ++attempt) {
        std::vector<unsigned char> buffer(size);
        auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        const ULONG status = ::GetAdaptersAddresses(AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr, adapters, &size);
        if (status == ERROR_BUFFER_OVERFLOW) continue;
        if (status != NO_ERROR) return false;
        for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
            for (auto* item = adapter->FirstUnicastAddress; item; item = item->Next) {
                if (!item->Address.lpSockaddr ||
                    item->Address.lpSockaddr->sa_family != AF_INET) continue;
                const auto* local = reinterpret_cast<const sockaddr_in*>(item->Address.lpSockaddr);
                if (local->sin_addr.s_addr == address.s_addr) return true;
            }
        }
        return false;
    }
#elif defined(__linux__)
    // Hardened services can prohibit AF_NETLINK, which glibc getifaddrs uses.
    // SIOCGIFCONF reads the same IPv4 interface ownership through AF_INET.
    struct SocketGuard {
        int fd;
        ~SocketGuard() { if (fd >= 0) ::close(fd); }
    } socket{::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)};
    if (socket.fd < 0) return false;
    for (size_t count = 32; count <= 16384; count *= 2) {
        std::vector<ifreq> interfaces(count);
        ifconf config{};
        config.ifc_len = static_cast<int>(interfaces.size() * sizeof(ifreq));
        config.ifc_req = interfaces.data();
        if (::ioctl(socket.fd, SIOCGIFCONF, &config) != 0 || config.ifc_len < 0 ||
            static_cast<size_t>(config.ifc_len) > interfaces.size() * sizeof(ifreq))
            return false;
        const size_t returned = static_cast<size_t>(config.ifc_len) / sizeof(ifreq);
        for (size_t i = 0; i < returned; ++i) {
            if (interfaces[i].ifr_addr.sa_family != AF_INET) continue;
            const auto* local = reinterpret_cast<const sockaddr_in*>(&interfaces[i].ifr_addr);
            if (local->sin_addr.s_addr == address.s_addr) return true;
        }
        if (returned < interfaces.size()) return false;
    }
#else
    ifaddrs* raw = nullptr;
    if (::getifaddrs(&raw) != 0) return false;
    const std::unique_ptr<ifaddrs, decltype(&::freeifaddrs)> interfaces(raw, ::freeifaddrs);
    for (auto* item = interfaces.get(); item; item = item->ifa_next) {
        if (!item->ifa_addr || item->ifa_addr->sa_family != AF_INET) continue;
        const auto* local = reinterpret_cast<const sockaddr_in*>(item->ifa_addr);
        if (local->sin_addr.s_addr == address.s_addr) return true;
    }
#endif
    return false;
}

} // namespace veld::net
