#pragma once

#include "../compat/platform.h"
#include <memory>
#include <vector>

#ifdef _WIN32
#include <iphlpapi.h>
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
