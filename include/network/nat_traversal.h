#pragma once
// ============================================================================
//  nat_traversal.h — residential reachability without manual port-forwarding
// ============================================================================
//  Veld's vision is open participation on commodity hardware. Most miners run
//  behind residential NAT, where being *reachable* (dialable) normally means
//  manually forwarding a port — friction + IP exposure most users won't do, so
//  the mesh degenerates into a star around whoever does listen. This module
//  removes that friction by auto-mapping the P2P port via the router.
//
//  PortMapper: NAT-PMP (RFC 6886) -> PCP (RFC 6887).  Experimental UPnP-IGD
//  exists only in an explicit non-public VELD_ENABLE_UPNP profile.
//
//  Safety:
//   * CONSENSUS-INERT. This file is pure transport. It never touches block
//     validation, reward math, sighash, the mempool, or any consensus state.
//     It cannot fork the chain.
//   * P2P-WIRE-TRANSPARENT. It speaks NAT-PMP/PCP/UPnP to the LAN ROUTER only,
//     never to veld peers. The veld P2P protocol is byte-for-byte unchanged, so
//     a node running this interoperates identically with every other node.
//   * FLEET-SAFE NO-OP. It auto-detects a public local IP (cloud / the fleet)
//     and returns immediately without contacting anything. Cloud nodes that run
//     this binary are completely unaffected.
//   * ROBUST-OR-INERT. Every router call has a hard timeout. All work happens on
//     one background thread that is cleanly joined on Stop(). Any failure (no
//     router, declined, malformed reply) degrades silently to outbound-only —
//     it can never hang, block startup, or crash the node. No thread_local
//     objects with non-trivial destructors (the MinGW mining-thread-exit crash
//     lesson). Opt-out via SetEnabled(false) / VELD_NO_NAT=1.
// ============================================================================

#include "../compat/platform.h"

#include <string>
#include <vector>
#include <array>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <iostream>
#include <sstream>

#if defined(VELD_ENABLE_UPNP) && defined(VELD_PUBLIC_RELEASE)
#error "VELD_ENABLE_UPNP is incompatible with VELD_PUBLIC_RELEASE"
#endif

#ifdef _WIN32
#  include <iphlpapi.h>   // GetAdaptersInfo (precise default-gateway detection)
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <fstream>
#endif

namespace veld {
namespace net {

using SocketHandle = veld::compat::SocketHandle;

// ---------------------------------------------------------------------------
//  Result of a reachability attempt. method ∈ {"NAT-PMP","PCP","UPnP",
//  "public",""}. "public" means the host already has a routable IP (no mapping
//  was needed). ok=false means outbound-only (a normal, fully-functional state).
// ---------------------------------------------------------------------------
struct NatMapping {
    bool        ok            = false;
    std::string method;
    std::string external_ip;
    uint16_t    external_port = 0;
    uint32_t    lifetime      = 0;   // seconds; 0 = router-default / N/A
};

class PortMapper {
public:
    PortMapper() = default;
    ~PortMapper() { Stop(); }

    PortMapper(const PortMapper&)            = delete;
    PortMapper& operator=(const PortMapper&) = delete;

    // Opt-out hook (fleet / --connect / privacy users). Default ON, but the
    // env var VELD_NO_NAT=1 also disables it. Must be set before Start().
    void SetEnabled(bool e) { enabled_ = e; }

    // Non-blocking. Spawns one background thread that detects NAT, maps the
    // port (cascade), and renews until Stop(). Safe to call once.
    void Start(uint16_t internal_port) {
        if (thread_.joinable()) return;            // already started
        if (!enabled_) return;
        if (const char* nn = std::getenv("VELD_NO_NAT"); nn && nn[0] && nn[0] != '0') {
            std::cout << "  [nat] VELD_NO_NAT set — auto port-mapping disabled "
                         "(outbound-only).\n";
            return;
        }
        internal_port_ = internal_port;
        running_.store(true, std::memory_order_release);
        thread_ = std::thread(&PortMapper::RunLoop, this, internal_port);
    }

    void Stop() {
        if (!running_.exchange(false)) {
            if (thread_.joinable()) thread_.join();
            return;
        }
        { std::lock_guard<std::mutex> lk(cv_mu_); }
        cv_.notify_all();
        if (thread_.joinable()) thread_.join();
    }

    bool        Reachable()    const { std::lock_guard<std::mutex> lk(mu_); return mapping_.ok; }
    std::string ExternalIp()   const { std::lock_guard<std::mutex> lk(mu_); return mapping_.external_ip; }
    uint16_t    ExternalPort() const { std::lock_guard<std::mutex> lk(mu_); return mapping_.external_port; }
    std::string Method()       const { std::lock_guard<std::mutex> lk(mu_); return mapping_.method; }
    NatMapping  Snapshot()     const { std::lock_guard<std::mutex> lk(mu_); return mapping_; }

private:
    // -- big-endian field helpers (all NAT-PMP/PCP fields are network order) --
    static void put16(uint8_t* p, uint16_t v) { p[0] = uint8_t(v >> 8); p[1] = uint8_t(v); }
    static void put32(uint8_t* p, uint32_t v) { p[0]=uint8_t(v>>24); p[1]=uint8_t(v>>16); p[2]=uint8_t(v>>8); p[3]=uint8_t(v); }
    static uint16_t get16(const uint8_t* p) { return uint16_t(uint16_t(p[0]) << 8 | p[1]); }
    static uint32_t get32(const uint8_t* p) { return uint32_t(p[0])<<24 | uint32_t(p[1])<<16 | uint32_t(p[2])<<8 | uint32_t(p[3]); }

    static bool IsNonzeroIpv4(const uint8_t* p) {
        return p[0] != 0 || p[1] != 0 || p[2] != 0 || p[3] != 0;
    }

    static bool ValidateNatPmpAddressResponse_(const uint8_t* resp) {
        return resp[0] == 0 && resp[1] == 128 &&
               get16(resp + 2) == 0 && IsNonzeroIpv4(resp + 8);
    }

    static bool ValidateNatPmpMapResponse_(const uint8_t* resp,
                                           uint16_t internal_port) {
        return resp[0] == 0 && resp[1] == 130 &&
               get16(resp + 2) == 0 &&
               get16(resp + 8) == internal_port &&
               get16(resp + 10) != 0 && get32(resp + 12) != 0;
    }

    static bool ValidatePcpMapResponse_(const uint8_t* resp,
                                        const uint8_t* nonce,
                                        uint16_t internal_port) {
        // RFC 6887 common response header: exact response bit/opcode, zero
        // reserved byte, SUCCESS, and a nonzero mapping lifetime.  The MAP
        // body must echo the session nonce, protocol, and internal port.  This
        // prevents a stale or unrelated gateway response from being accepted
        // as authority for reachability.
        if (resp[0] != 2 || resp[1] != 0x81 || resp[2] != 0 ||
            resp[3] != 0 || get32(resp + 4) == 0)
            return false;
        const uint8_t* map = resp + 24;
        if (std::memcmp(map, nonce, 12) != 0 || map[12] != 6 ||
            map[13] != 0 || map[14] != 0 || map[15] != 0 ||
            get16(map + 16) != internal_port ||
            get16(map + 18) == 0)
            return false;
        // This implementation advertises IPv4 only, so require the exact
        // IPv4-mapped IPv6 response form instead of silently truncating an
        // arbitrary IPv6 address to its last four bytes.
        for (size_t i = 0; i < 10; ++i)
            if (map[20 + i] != 0) return false;
        return map[30] == 0xff && map[31] == 0xff &&
               IsNonzeroIpv4(map + 32);
    }

#ifdef VELD_TEST_HOOKS
public:
    static bool TestValidateNatPmpAddressResponse(const uint8_t* resp) {
        return resp && ValidateNatPmpAddressResponse_(resp);
    }
    static bool TestValidateNatPmpMapResponse(const uint8_t* resp,
                                              uint16_t internal_port) {
        return resp && ValidateNatPmpMapResponse_(resp, internal_port);
    }
    static bool TestValidatePcpMapResponse(const uint8_t* resp,
                                           const uint8_t* nonce,
                                           uint16_t internal_port) {
        return resp && nonce &&
               ValidatePcpMapResponse_(resp, nonce, internal_port);
    }
private:
#endif

    // Interruptible sleep — wakes immediately on Stop().
    void SleepSeconds(uint32_t s) {
        std::unique_lock<std::mutex> lk(cv_mu_);
        cv_.wait_for(lk, std::chrono::seconds(s),
                     [this]{ return !running_.load(std::memory_order_acquire); });
    }

    static void EnsureNet() {
#ifdef _WIN32
        veld::compat::InitNetwork();
#endif
    }

    static void SetRecvTimeout(SocketHandle sock, int ms) {
#ifdef _WIN32
        DWORD tv = (DWORD)ms;
        ::setsockopt((SOCKET)sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#else
        struct timeval tv; tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
        ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif
    }

    // ----------------------------------------------------------------------
    //  Detection
    // ----------------------------------------------------------------------

    // Local primary IPv4 via a connectionless UDP "connect" to a public addr
    // (no packets are sent; the kernel just resolves the egress interface).
    static bool DetectLocalIp(std::string& out) {
        EnsureNet();
        SocketHandle s = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (!veld::compat::IsValidSocket(s)) return false;
        struct sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port   = htons(53);
        ::inet_pton(AF_INET, "8.8.8.8", &a.sin_addr);
        bool ok = false;
        if (::connect(s, (struct sockaddr*)&a, sizeof(a)) == 0) {
            struct sockaddr_in local{};
#ifdef _WIN32
            int len = sizeof(local);
#else
            socklen_t len = sizeof(local);
#endif
            if (::getsockname(s, (struct sockaddr*)&local, &len) == 0) {
                char buf[INET_ADDRSTRLEN] = {0};
                if (::inet_ntop(AF_INET, &local.sin_addr, buf, sizeof(buf))) {
                    out = buf; ok = true;
                }
            }
        }
        VELD_CLOSE_SOCKET(s);
        return ok;
    }

    static bool IsPrivateIp(const std::string& ip) {
        unsigned a=0,b=0,c=0,d=0;
        if (std::sscanf(ip.c_str(), "%u.%u.%u.%u", &a,&b,&c,&d) != 4) return false;
        if (a == 10) return true;                          // 10.0.0.0/8
        if (a == 172 && b >= 16 && b <= 31) return true;   // 172.16.0.0/12
        if (a == 192 && b == 168) return true;             // 192.168.0.0/16
        if (a == 100 && b >= 64 && b <= 127) return true;  // 100.64.0.0/10 CGNAT
        if (a == 169 && b == 254) return true;             // 169.254/16 link-local
        if (a == 127) return true;                         // loopback
        return false;
    }

    // Default-gateway IPv4. Exact on each OS; heuristic fallback (x.x.x.1).
    static bool DetectGateway(const std::string& localip, std::string& out) {
#ifdef _WIN32
        ULONG sz = 0;
        if (GetAdaptersInfo(nullptr, &sz) == ERROR_BUFFER_OVERFLOW && sz > 0) {
            std::vector<uint8_t> buf(sz);
            auto* ai = reinterpret_cast<IP_ADAPTER_INFO*>(buf.data());
            if (GetAdaptersInfo(ai, &sz) == NO_ERROR) {
                for (auto* p = ai; p; p = p->Next) {
                    const char* gw = p->GatewayList.IpAddress.String;
                    if (gw && gw[0] && std::strcmp(gw, "0.0.0.0") != 0) {
                        out = gw; return true;
                    }
                }
            }
        }
#else
        // /proc/net/route: the default route has Destination 00000000; the
        // Gateway column is little-endian hex of the IPv4 address.
        std::ifstream f("/proc/net/route");
        std::string line;
        std::getline(f, line); // header
        while (std::getline(f, line)) {
            std::istringstream ss(line);
            std::string iface, dest, gwhex;
            ss >> iface >> dest >> gwhex;
            if (dest == "00000000" && gwhex.size() == 8) {
                unsigned long g = std::strtoul(gwhex.c_str(), nullptr, 16);
                unsigned char o0 = (g) & 0xFF, o1 = (g >> 8) & 0xFF,
                              o2 = (g >> 16) & 0xFF, o3 = (g >> 24) & 0xFF;
                char b[INET_ADDRSTRLEN];
                std::snprintf(b, sizeof(b), "%u.%u.%u.%u", o0, o1, o2, o3);
                out = b; return true;
            }
        }
#endif
        // Heuristic fallback: gateway is commonly the .1 of the local /24.
        unsigned a=0,b=0,c=0,d=0;
        if (std::sscanf(localip.c_str(), "%u.%u.%u.%u", &a,&b,&c,&d) == 4) {
            char buf[INET_ADDRSTRLEN];
            std::snprintf(buf, sizeof(buf), "%u.%u.%u.1", a, b, c);
            out = buf; return true;
        }
        return false;
    }

    // ----------------------------------------------------------------------
    //  NAT-PMP (RFC 6886) — UDP to <gateway>:5351
    // ----------------------------------------------------------------------
    bool TryNatPmp(const std::string& gw, uint16_t intport, NatMapping& out) {
        EnsureNet();
        SocketHandle s = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (!veld::compat::IsValidSocket(s)) return false;
        SetRecvTimeout(s, 250);
        struct sockaddr_in ga{};
        ga.sin_family = AF_INET;
        ga.sin_port   = htons(5351);
        if (::inet_pton(AF_INET, gw.c_str(), &ga.sin_addr) != 1) { VELD_CLOSE_SOCKET(s); return false; }

        // 1) external address request: [version=0, op=0]
        std::string extip;
        {
            uint8_t req[2] = {0, 0};
            uint8_t resp[16] = {0};
            if (SendRecvUdp(s, &ga, req, sizeof(req), resp, 12, /*retries*/3)) {
                if (ValidateNatPmpAddressResponse_(resp)) {
                    char b[INET_ADDRSTRLEN];
                    std::snprintf(b, sizeof(b), "%u.%u.%u.%u", resp[8], resp[9], resp[10], resp[11]);
                    extip = b;
                }
            }
        }
        if (extip.empty()) { VELD_CLOSE_SOCKET(s); return false; }   // no NAT-PMP here

        // 2) map TCP intport -> same external port, lifetime 3600s
        //    [version=0, op=2(TCP), reserved(2)=0, intport(2), extport(2), lifetime(4)]
        uint8_t req[12] = {0};
        req[0] = 0; req[1] = 2;
        put16(req + 4, intport);
        put16(req + 6, intport);          // suggest same external port
        put32(req + 8, 3600);
        uint8_t resp[16] = {0};
        bool ok = SendRecvUdp(s, &ga, req, sizeof(req), resp, 16, 3);
        VELD_CLOSE_SOCKET(s);
        if (!ok) return false;
        if (!ValidateNatPmpMapResponse_(resp, intport)) return false;
        out.ok = true; out.method = "NAT-PMP"; out.external_ip = extip;
        out.external_port = get16(resp + 10);
        out.lifetime = get32(resp + 12);
        return true;
    }

    // ----------------------------------------------------------------------
    //  PCP (RFC 6887) — UDP to <gateway>:5351, MAP opcode. Tried after NAT-PMP.
    // ----------------------------------------------------------------------
    bool TryPcp(const std::string& gw, const std::string& localip, uint16_t intport, NatMapping& out) {
        if (!pcp_nonce_ready_) return false;
        EnsureNet();
        SocketHandle s = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (!veld::compat::IsValidSocket(s)) return false;
        SetRecvTimeout(s, 250);
        struct sockaddr_in ga{};
        ga.sin_family = AF_INET;
        ga.sin_port   = htons(5351);
        if (::inet_pton(AF_INET, gw.c_str(), &ga.sin_addr) != 1) { VELD_CLOSE_SOCKET(s); return false; }

        // Request: 24-byte common header + 36-byte MAP body = 60 bytes.
        uint8_t req[60] = {0};
        req[0] = 2;          // version 2
        req[1] = 1;          // R=0 (request), opcode=1 (MAP)
        // req[2..3] reserved = 0
        put32(req + 4, 3600);                 // requested lifetime
        // client IP (16): IPv4-mapped IPv6 ::ffff:a.b.c.d
        {
            struct in_addr ia{}; ::inet_pton(AF_INET, localip.c_str(), &ia);
            req[8 + 10] = 0xff; req[8 + 11] = 0xff;
            std::memcpy(req + 8 + 12, &ia, 4);
        }
        // MAP body @24: nonce(12), protocol(1)=6 TCP, reserved(3), intport(2),
        //               suggested extport(2), suggested ext IP(16, ::=any)
        uint8_t* m = req + 24;
        for (int i = 0; i < 12; ++i) m[i] = pcp_nonce_[i];
        m[12] = 6;                            // TCP
        put16(m + 16, intport);               // internal port
        put16(m + 18, intport);               // suggested external port
        // suggested external IP left as all-zero (router chooses)

        uint8_t resp[60] = {0};
        bool ok = SendRecvUdp(s, &ga, req, sizeof(req), resp, 60, 3);
        VELD_CLOSE_SOCKET(s);
        if (!ok) return false;
        if (!ValidatePcpMapResponse_(resp, pcp_nonce_, intport)) return false;
        // response MAP body @24: nonce(12), proto(1), rsv(3), intport(2),
        //   assigned extport(2)@40, assigned ext IP(16)@42
        const uint8_t* rm = resp + 24;
        uint16_t extport = get16(rm + 18);
        // assigned external IP is IPv4-mapped IPv6 -> last 4 bytes
        const uint8_t* eip = rm + 20 + 12;
        char b[INET_ADDRSTRLEN];
        std::snprintf(b, sizeof(b), "%u.%u.%u.%u", eip[0], eip[1], eip[2], eip[3]);
        out.ok = true; out.method = "PCP"; out.external_ip = b;
        out.external_port = extport;
        out.lifetime = get32(resp + 4);
        return true;
    }

    // Send a UDP request and wait for a reply, with retries (RFC-style backoff).
    bool SendRecvUdp(SocketHandle s, struct sockaddr_in* ga,
                     const uint8_t* req, size_t reqlen,
                     uint8_t* resp, size_t expectlen, int retries) {
        if (!ga || !req || !resp || reqlen == 0 || expectlen == 0 ||
            expectlen > 2048)
            return false;
        // A connected UDP socket accepts datagrams only from the exact gateway
        // address and port.  The old sendto()+recv() pair accepted a forged LAN
        // reply from any source that won the race.
        if (::connect(s, reinterpret_cast<struct sockaddr*>(ga),
                      sizeof(*ga)) != 0)
            return false;
        std::array<uint8_t, 2048> packet{};
        for (int attempt = 0; attempt < retries && running_.load(std::memory_order_acquire); ++attempt) {
            if (::send(s, reinterpret_cast<const char*>(req),
                       static_cast<int>(reqlen), 0) < 0)
                return false;
            const int n = static_cast<int>(::recv(
                s, reinterpret_cast<char*>(packet.data()),
                static_cast<int>(packet.size()), 0));
            if (n == static_cast<int>(expectlen)) {
                std::memcpy(resp, packet.data(), expectlen);
                return true;
            }
            // timeout -> retry (doubling handled implicitly by the 250ms SO_RCVTIMEO)
        }
        return false;
    }

#if defined(VELD_ENABLE_UPNP)
    // ----------------------------------------------------------------------
    //  UPnP-IGD — SSDP discovery -> device description -> SOAP AddPortMapping.
    //  No gateway IP needed (SSDP is multicast). Most-supported on consumer gear.
    // ----------------------------------------------------------------------
    bool TryUpnp(const std::string& localip, uint16_t intport, NatMapping& out) {
        std::string location = SsdpDiscover();
        if (location.empty()) return false;
        std::string host, ctrl, svc;
        if (!FetchIgdControlUrl(location, host, ctrl, svc)) return false;
        // AddPortMapping
        std::string body =
            "<u:AddPortMapping xmlns:u=\"" + svc + "\">"
            "<NewRemoteHost></NewRemoteHost>"
            "<NewExternalPort>" + std::to_string(intport) + "</NewExternalPort>"
            "<NewProtocol>TCP</NewProtocol>"
            "<NewInternalPort>" + std::to_string(intport) + "</NewInternalPort>"
            "<NewInternalClient>" + localip + "</NewInternalClient>"
            "<NewEnabled>1</NewEnabled>"
            "<NewPortMappingDescription>veld</NewPortMappingDescription>"
            "<NewLeaseDuration>0</NewLeaseDuration>"
            "</u:AddPortMapping>";
        std::string resp;
        if (!SoapCall(host, ctrl, svc, "AddPortMapping", body, resp)) return false;
        if (resp.find("AddPortMappingResponse") == std::string::npos &&
            resp.find("200 OK") == std::string::npos) {
            // some IGDs return 500 if the mapping already exists with same params;
            // treat an existing identical mapping as success below via GetExternalIP.
            if (resp.find("ConflictInMapping") == std::string::npos &&
                resp.find("718") == std::string::npos)
                return false;
        }
        // GetExternalIPAddress
        std::string ip;
        {
            std::string gbody = "<u:GetExternalIPAddress xmlns:u=\"" + svc + "\"></u:GetExternalIPAddress>";
            std::string gresp;
            if (SoapCall(host, ctrl, svc, "GetExternalIPAddress", gbody, gresp)) {
                ip = XmlTag(gresp, "NewExternalIPAddress");
            }
        }
        out.ok = true; out.method = "UPnP";
        out.external_ip = ip.empty() ? std::string("(unknown)") : ip;
        out.external_port = intport;
        out.lifetime = 0;                 // we requested an indefinite lease
        // remember for clean deletion on Stop()
        { std::lock_guard<std::mutex> lk(mu_); upnp_host_ = host; upnp_ctrl_ = ctrl; upnp_svc_ = svc; }
        return true;
    }

    // SSDP M-SEARCH (multicast 239.255.255.250:1900) -> first IGD LOCATION URL.
    std::string SsdpDiscover() {
        EnsureNet();
        SocketHandle s = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (!veld::compat::IsValidSocket(s)) return "";
        SetRecvTimeout(s, 800);
        static const char* targets[] = {
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:service:WANPPPConnection:1",
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        };
        struct sockaddr_in mc{};
        mc.sin_family = AF_INET;
        mc.sin_port   = htons(1900);
        ::inet_pton(AF_INET, "239.255.255.250", &mc.sin_addr);
        std::string location;
        for (const char* tgt : targets) {
            std::string msearch =
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                "MX: 2\r\n"
                "ST: " + std::string(tgt) + "\r\n\r\n";
            ::sendto(s, msearch.data(), (int)msearch.size(), 0, (struct sockaddr*)&mc, sizeof(mc));
            // collect a couple of replies
            for (int i = 0; i < 4 && running_.load(std::memory_order_acquire); ++i) {
                char buf[2048] = {0};
                int n = (int)::recv(s, buf, sizeof(buf) - 1, 0);
                if (n <= 0) break;
                std::string r(buf, (size_t)n);
                std::string loc = HttpHeader(r, "location");
                if (!loc.empty()) { location = loc; break; }
            }
            if (!location.empty()) break;
        }
        VELD_CLOSE_SOCKET(s);
        return location;
    }

    // GET the IGD device description and extract (host, controlURL, serviceType)
    // of the WANIP/WANPPP connection service.
    bool FetchIgdControlUrl(const std::string& location, std::string& host_out,
                            std::string& ctrl_out, std::string& svc_out) {
        std::string host, path; uint16_t port = 80;
        if (!ParseHttpUrl(location, host, port, path)) return false;
        std::string resp;
        if (!HttpGet(host, port, path, resp)) return false;
        // Find a service block for WANIPConnection or WANPPPConnection and pull
        // its <serviceType> + <controlURL>.
        for (const char* want : {"WANIPConnection", "WANPPPConnection"}) {
            size_t sp = resp.find(want);
            if (sp == std::string::npos) continue;
            // controlURL nearest after the serviceType
            size_t svcpos = resp.rfind("<serviceType>", sp);
            std::string svc = (svcpos != std::string::npos)
                ? Between(resp, "<serviceType>", "</serviceType>", svcpos) : "";
            std::string ctrl = Between(resp, "<controlURL>", "</controlURL>", sp);
            if (svc.empty() || ctrl.empty()) continue;
            // controlURL may be relative -> resolve against host:port
            if (!ctrl.empty() && ctrl[0] != '/' && ctrl.rfind("http", 0) != 0)
                ctrl = "/" + ctrl;
            std::string chost = host; uint16_t cport = port; std::string cpath = ctrl;
            if (ctrl.rfind("http", 0) == 0) ParseHttpUrl(ctrl, chost, cport, cpath);
            host_out = chost + ":" + std::to_string(cport);
            ctrl_out = cpath;
            svc_out  = svc;
            return true;
        }
        return false;
    }

    bool SoapCall(const std::string& hostport, const std::string& ctrl,
                  const std::string& svc, const std::string& action,
                  const std::string& innerXml, std::string& resp) {
        std::string host = hostport; uint16_t port = 80;
        size_t colon = hostport.rfind(':');
        if (colon != std::string::npos) {
            host = hostport.substr(0, colon);
            port = (uint16_t)std::strtoul(hostport.c_str() + colon + 1, nullptr, 10);
        }
        std::string env =
            "<?xml version=\"1.0\"?>"
            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
            "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
            "<s:Body>" + innerXml + "</s:Body></s:Envelope>";
        std::string req =
            "POST " + ctrl + " HTTP/1.1\r\n"
            "HOST: " + host + ":" + std::to_string(port) + "\r\n"
            "CONTENT-TYPE: text/xml; charset=\"utf-8\"\r\n"
            "SOAPACTION: \"" + svc + "#" + action + "\"\r\n"
            "CONTENT-LENGTH: " + std::to_string(env.size()) + "\r\n"
            "CONNECTION: close\r\n\r\n" + env;
        return HttpRaw(host, port, req, resp);
    }

    // -- tiny blocking HTTP/1.0-ish client over TCP, hard-timeout-bounded --
    bool HttpGet(const std::string& host, uint16_t port, const std::string& path, std::string& resp) {
        std::string req = "GET " + path + " HTTP/1.1\r\nHOST: " + host + ":" +
                          std::to_string(port) + "\r\nCONNECTION: close\r\n\r\n";
        return HttpRaw(host, port, req, resp);
    }

    bool HttpRaw(const std::string& host, uint16_t port, const std::string& req, std::string& resp) {
        EnsureNet();
        SocketHandle s = ::socket(AF_INET, SOCK_STREAM, 0);
        if (!veld::compat::IsValidSocket(s)) return false;
        SetRecvTimeout(s, 1500);
#ifdef _WIN32
        DWORD sndtv = 1500; ::setsockopt((SOCKET)s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&sndtv, sizeof(sndtv));
#else
        struct timeval sndtv{1, 500000}; ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&sndtv, sizeof(sndtv));
#endif
        struct sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port   = htons(port);
        if (::inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) { VELD_CLOSE_SOCKET(s); return false; }
        if (::connect(s, (struct sockaddr*)&a, sizeof(a)) != 0) { VELD_CLOSE_SOCKET(s); return false; }
        if (::send(s, req.data(), (int)req.size(), 0) < 0) { VELD_CLOSE_SOCKET(s); return false; }
        resp.clear();
        char buf[4096];
        for (int i = 0; i < 64 && running_.load(std::memory_order_acquire); ++i) {
            int n = (int)::recv(s, buf, sizeof(buf), 0);
            if (n <= 0) break;
            resp.append(buf, (size_t)n);
            if (resp.size() > 256 * 1024) break;   // bound memory
        }
        VELD_CLOSE_SOCKET(s);
        return !resp.empty();
    }

    // -- small string helpers (no regex; bounded, exception-free) --
    static std::string HttpHeader(const std::string& r, const std::string& name) {
        std::string lower = ToLower(r), key = ToLower(name) + ":";
        size_t p = lower.find(key);
        if (p == std::string::npos) return "";
        p += key.size();
        size_t e = r.find("\r\n", p);
        std::string v = r.substr(p, (e == std::string::npos ? r.size() : e) - p);
        return Trim(v);
    }
    static std::string ToLower(std::string s) { for (auto& c : s) c = (char)std::tolower((unsigned char)c); return s; }
    static std::string Trim(const std::string& s) {
        size_t a = s.find_first_not_of(" \t\r\n");
        size_t b = s.find_last_not_of(" \t\r\n");
        return (a == std::string::npos) ? "" : s.substr(a, b - a + 1);
    }
    static std::string Between(const std::string& s, const std::string& open,
                               const std::string& close, size_t from) {
        size_t a = s.find(open, from);
        if (a == std::string::npos) return "";
        a += open.size();
        size_t b = s.find(close, a);
        if (b == std::string::npos) return "";
        return Trim(s.substr(a, b - a));
    }
    static std::string XmlTag(const std::string& s, const std::string& tag) {
        return Between(s, "<" + tag + ">", "</" + tag + ">", 0);
    }
    static bool ParseHttpUrl(const std::string& url, std::string& host, uint16_t& port, std::string& path) {
        std::string u = url;
        if (u.rfind("http://", 0) == 0) u = u.substr(7);
        else if (u.rfind("https://", 0) == 0) u = u.substr(8);
        size_t slash = u.find('/');
        std::string hostport = (slash == std::string::npos) ? u : u.substr(0, slash);
        path = (slash == std::string::npos) ? "/" : u.substr(slash);
        size_t colon = hostport.find(':');
        if (colon == std::string::npos) { host = hostport; port = 80; }
        else { host = hostport.substr(0, colon); port = (uint16_t)std::strtoul(hostport.c_str() + colon + 1, nullptr, 10); }
        return !host.empty();
    }
#endif

    void DeleteMappingBestEffort() {
        NatMapping m = Snapshot();
        if (!m.ok) return;
        if (m.method == "NAT-PMP" || m.method == "PCP") {
            // re-send a map with lifetime 0 = delete (NAT-PMP §3.4 / PCP)
            std::string gw, localip;
            if (DetectLocalIp(localip) && DetectGateway(localip, gw)) {
                SocketHandle s = ::socket(AF_INET, SOCK_DGRAM, 0);
                if (veld::compat::IsValidSocket(s)) {
                    SetRecvTimeout(s, 250);
                    struct sockaddr_in ga{}; ga.sin_family = AF_INET; ga.sin_port = htons(5351);
                    if (::inet_pton(AF_INET, gw.c_str(), &ga.sin_addr) == 1) {
                        running_.store(true, std::memory_order_release); // allow one send
                        if (m.method == "NAT-PMP") {
                            uint8_t req[12] = {0};
                            req[1] = 2;
                            put16(req + 4, internal_port_);
                            put16(req + 6, m.external_port);
                            put32(req + 8, 0);
                            uint8_t resp[16] = {0};
                            SendRecvUdp(
                                s, &ga, req, sizeof(req), resp, 16, 1);
                        } else if (pcp_nonce_ready_) {
                            uint8_t req[60] = {0};
                            req[0] = 2;
                            req[1] = 1;
                            // lifetime 0 deletes this exact MAP request.
                            struct in_addr local_addr{};
                            if (::inet_pton(AF_INET, localip.c_str(),
                                            &local_addr) == 1) {
                                req[18] = 0xff;
                                req[19] = 0xff;
                                std::memcpy(req + 20, &local_addr, 4);
                                uint8_t* map = req + 24;
                                std::memcpy(map, pcp_nonce_, 12);
                                map[12] = 6;
                                put16(map + 16, internal_port_);
                                put16(map + 18, m.external_port);
                                struct in_addr external_addr{};
                                if (::inet_pton(AF_INET,
                                                m.external_ip.c_str(),
                                                &external_addr) == 1) {
                                    map[30] = 0xff;
                                    map[31] = 0xff;
                                    std::memcpy(map + 32,
                                                &external_addr, 4);
                                }
                                uint8_t resp[60] = {0};
                                SendRecvUdp(
                                    s, &ga, req, sizeof(req), resp, 60, 1);
                            }
                        }
                        running_.store(false, std::memory_order_release);
                    }
                    VELD_CLOSE_SOCKET(s);
                }
            }
        }
#if defined(VELD_ENABLE_UPNP)
        else if (m.method == "UPnP") {
            std::string host, ctrl, svc;
            { std::lock_guard<std::mutex> lk(mu_); host = upnp_host_; ctrl = upnp_ctrl_; svc = upnp_svc_; }
            if (!host.empty()) {
                std::string body =
                    "<u:DeletePortMapping xmlns:u=\"" + svc + "\">"
                    "<NewRemoteHost></NewRemoteHost>"
                    "<NewExternalPort>" + std::to_string(internal_port_) + "</NewExternalPort>"
                    "<NewProtocol>TCP</NewProtocol></u:DeletePortMapping>";
                std::string resp;
                running_.store(true, std::memory_order_release);
                SoapCall(host, ctrl, svc, "DeletePortMapping", body, resp);
                running_.store(false, std::memory_order_release);
            }
        }
#endif
    }

    // ----------------------------------------------------------------------
    //  Worker
    // ----------------------------------------------------------------------
    void RunLoop(uint16_t intport) {
      try {
        // PCP uses the nonce as response identity, so generate it with the
        // project CSPRNG.  A randomness failure disables PCP for this run but
        // still permits authenticated-source NAT-PMP.
        pcp_nonce_ready_ =
            veld::compat::SecureRandom(pcp_nonce_, sizeof(pcp_nonce_));

        std::string localip;
        if (!DetectLocalIp(localip)) {
            std::cout << "  Inbound mapping unavailable; continuing outbound-only.\n";
            return;
        }
        if (!IsPrivateIp(localip)) {
            { std::lock_guard<std::mutex> lk(mu_); mapping_ = {true, "public", localip, intport, 0}; }
            std::cout << "  Inbound peer connections enabled.\n";
            if (veld::DiagVerbose().load())
                std::cout << "  [nat] public endpoint " << localip << ":" << intport << "\n";
            return;   // cloud / fleet: nothing to do, thread exits
        }

        std::string gw;
        DetectGateway(localip, gw);
        std::cout << "  Checking inbound peer reachability...\n";
        if (veld::DiagVerbose().load())
            std::cout << "  [nat] local=" << localip
                      << (gw.empty() ? "" : (" gateway=" + gw))
                      << " port=" << intport << "\n";

        bool announced_fail = false;
        while (running_.load(std::memory_order_acquire)) {
            NatMapping m;
            bool ok = false;
            if (!gw.empty() && TryNatPmp(gw, intport, m)) ok = true;
            else if (!gw.empty() && TryPcp(gw, localip, intport, m)) ok = true;
#if defined(VELD_ENABLE_UPNP)
            else if (TryUpnp(localip, intport, m)) ok = true;
#endif

            if (ok) {
                { std::lock_guard<std::mutex> lk(mu_); mapping_ = m; mapping_.ok = true; }
                announced_fail = false;
                std::cout << "  Inbound peer connections enabled.\n";
                if (veld::DiagVerbose().load())
                    std::cout << "  [nat] method=" << m.method
                              << " endpoint=" << m.external_ip << ":" << m.external_port
                              << (m.lifetime ? (" lease=" + std::to_string(m.lifetime) + "s") : "")
                              << "\n";
                uint32_t life = m.lifetime ? m.lifetime : 3600;
                uint32_t half = life / 2; if (half < 60) half = 60;
                SleepSeconds(half);           // renew before expiry
            } else {
                { std::lock_guard<std::mutex> lk(mu_); mapping_.ok = false; }
                if (!announced_fail) {
                    std::cout << "  Inbound mapping unavailable; continuing outbound-only.\n";
                    announced_fail = true;
                }
                SleepSeconds(1800);           // retry every 30 min
            }
        }
        DeleteMappingBestEffort();
      } catch (...) {
        // The NAT thread must NEVER crash the node. Any exception here (incl.
        // std::bad_alloc) is swallowed -> the node continues outbound-only.
        std::lock_guard<std::mutex> lk(mu_); mapping_.ok = false;
      }
    }

    // ----------------------------------------------------------------------
    std::atomic<bool>       enabled_{true};
    std::atomic<bool>       running_{false};
    std::thread             thread_;
    std::condition_variable cv_;
    std::mutex              cv_mu_;
    mutable std::mutex      mu_;
    NatMapping              mapping_;
    uint16_t                internal_port_ = 0;
    uint8_t                 pcp_nonce_[12] = {0};
    bool                    pcp_nonce_ready_ = false;
#if defined(VELD_ENABLE_UPNP)
    std::string             upnp_host_, upnp_ctrl_, upnp_svc_;  // for clean delete
#endif
};

} // namespace net
} // namespace veld
