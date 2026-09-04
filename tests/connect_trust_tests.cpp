#include "network/tcp.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace {
size_t checks = 0;
#define CHECK(expr)                                                                                \
    do {                                                                                           \
        ++checks;                                                                                  \
        if (!(expr)) {                                                                             \
            std::cerr << "FAIL " << __FILE__ << ':' << __LINE__ << " " #expr "\n";                 \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)
} // namespace

int main() {
    veld::Blockchain chain;
    veld::Mempool mempool;
    veld::net::NodeServer server(0, veld::MAINNET_MAGIC, chain, mempool);

    CHECK(!server.IsTrustedIPForTesting("203.0.113.10"));
    CHECK(!server.ConnectTo("203.0.113.10", 19333,
                            /*explicitly_trusted=*/false,
                            /*fleet_anchor=*/false));
    CHECK(!server.IsTrustedIPForTesting("203.0.113.10"));

    CHECK(!server.ConnectTo("198.51.100.20", 19333,
                            /*explicitly_trusted=*/true,
                            /*fleet_anchor=*/false));
    CHECK(server.IsTrustedIPForTesting("198.51.100.20"));
    CHECK(!server.IsFleetAnchorIpForTesting("198.51.100.20"));

    CHECK(!server.ConnectTo("192.0.2.30", 19333,
                            /*explicitly_trusted=*/true,
                            /*fleet_anchor=*/true));
    CHECK(server.IsTrustedIPForTesting("192.0.2.30"));
    CHECK(server.IsFleetAnchorIpForTesting("192.0.2.30"));
    CHECK(!server.ConnectTo("not-a-canonical-ip", 19333,
                            /*explicitly_trusted=*/true,
                            /*fleet_anchor=*/true));
    CHECK(!server.IsTrustedIPForTesting("not-a-canonical-ip"));

    const std::filesystem::path node_header =
        std::filesystem::path(__FILE__).parent_path().parent_path() / "include" / "node" / "node.h";
    std::ifstream input(node_header, std::ios::binary);
    CHECK(static_cast<bool>(input));
    std::ostringstream buffer;
    buffer << input.rdbuf();
    const std::string source = buffer.str();
    const size_t wrapper = source.find("bool ConnectTo(const std::string& host, uint16_t port)");
    CHECK(wrapper != std::string::npos);
    const size_t wrapper_end = source.find("\n    }", wrapper);
    CHECK(wrapper_end != std::string::npos);
    const std::string body = source.substr(wrapper, wrapper_end - wrapper);
    CHECK(body.find("/*explicitly_trusted=*/false") != std::string::npos);
    CHECK(body.find("/*fleet_anchor=*/false") != std::string::npos);
    CHECK(body.find("/*explicitly_trusted=*/true") == std::string::npos);

    std::cout << "PASS connect_trust_tests checks=" << checks
              << " ordinary_connect_trust_grants=0\n";
    return 0;
}
