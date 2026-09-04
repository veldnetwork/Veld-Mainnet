#define main veld_desktop_unreferenced_program_main
#include "../src/veld-desktop.cpp"
#undef main

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
    DesktopRpcEndpoint endpoint;
    CHECK(parse_desktop_rpc_endpoint("https://node1.veld.network", endpoint));
    CHECK(endpoint.secure);
    CHECK(endpoint.host == "node1.veld.network");
    CHECK(endpoint.port == 443);
    CHECK(!endpoint.may_use_local_bearer);

    CHECK(parse_desktop_rpc_endpoint("HTTPS://node1.veld.network", endpoint) == false);
    CHECK(parse_desktop_rpc_endpoint("https://NODE1.VELD.NETWORK:8443", endpoint));
    CHECK(endpoint.host == "node1.veld.network" && endpoint.port == 8443);
    CHECK(!parse_desktop_rpc_endpoint("http://node1.veld.network:8334", endpoint));
    CHECK(parse_desktop_rpc_endpoint("http://127.0.0.1:8334", endpoint));
    CHECK(!endpoint.secure && endpoint.may_use_local_bearer && endpoint.port == 8334);
    CHECK(parse_desktop_rpc_endpoint("http://localhost", endpoint));
    CHECK(endpoint.may_use_local_bearer);
    CHECK(!parse_desktop_rpc_endpoint("http://127.0.0.2:8334", endpoint));
    CHECK(!parse_desktop_rpc_endpoint("https://user@node1.veld.network", endpoint));
    CHECK(!parse_desktop_rpc_endpoint("https://node1.veld.network/path", endpoint));
    CHECK(!parse_desktop_rpc_endpoint("https://node1.veld.network?x=1", endpoint));
    CHECK(!parse_desktop_rpc_endpoint("https://node1.veld.network#fragment", endpoint));
    CHECK(!parse_desktop_rpc_endpoint("https://[::1]:443", endpoint));
    CHECK(!parse_desktop_rpc_endpoint("https://node1.veld.network:0", endpoint));
    CHECK(!parse_desktop_rpc_endpoint("https://node1.veld.network:65536", endpoint));
    CHECK(!parse_desktop_rpc_endpoint("https://node1.veld.network:", endpoint));

    const std::string body = R"({"jsonrpc":"2.0","result":1,"id":1})";
    const std::string good =
        "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    CHECK(desktop_parse_tls_rpc_response(good) == body);
    CHECK(desktop_parse_tls_rpc_response("HTTP/1.0 200 OK\r\n\r\n" + body) == body);
    CHECK(desktop_parse_tls_rpc_response("HTTP/1.1 500 Nope\r\nContent-Length: 0\r\n\r\n")
              .find("rejected") != std::string::npos);
    CHECK(desktop_parse_tls_rpc_response(
              "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
              .find("Ambiguous") != std::string::npos);
    CHECK(desktop_parse_tls_rpc_response("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n"
                                         "Content-Length: 1\r\n\r\nx")
              .find("Ambiguous") != std::string::npos);
    CHECK(desktop_parse_tls_rpc_response("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx")
              .find("Truncated") != std::string::npos);
    CHECK(desktop_parse_tls_rpc_response("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nxx")
              .find("overlong") != std::string::npos);

    const std::filesystem::path source_path =
        std::filesystem::path(__FILE__).parent_path().parent_path() / "src" / "veld-desktop.cpp";
    std::ifstream input(source_path, std::ios::binary);
    CHECK(static_cast<bool>(input));
    std::ostringstream buffer;
    buffer << input.rdbuf();
    const std::string source = buffer.str();
    CHECK(source.find("WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2") != std::string::npos);
    CHECK(source.find("WINHTTP_FLAG_SECURE") != std::string::npos);
    CHECK(source.find("WINHTTP_OPTION_REDIRECT_POLICY_NEVER") != std::string::npos);
    CHECK(source.find("SECURITY_FLAG_IGNORE_UNKNOWN_CA") == std::string::npos);
    CHECK(source.find("SECURITY_FLAG_IGNORE_CERT_CN_INVALID") == std::string::npos);
    CHECK(source.find("SSL_CTX_set_verify(context, SSL_VERIFY_PEER") != std::string::npos);
    CHECK(source.find("SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION)") !=
          std::string::npos);
    CHECK(source.find("SSL_CTX_set_default_verify_paths(context)") != std::string::npos);
    CHECK(source.find("SSL_set1_host(tls, endpoint.host.c_str())") != std::string::npos);
    CHECK(source.find("SSL_get_verify_result(tls) == X509_V_OK") != std::string::npos);
    CHECK(source.find("using DesktopTlsClock = std::chrono::steady_clock") != std::string::npos);
    CHECK(source.find("DESKTOP_TLS_REQUEST_LIMIT{30}") != std::string::npos);
    CHECK(source.find("proxy_rpc_https_until(") != std::string::npos);
    CHECK(source.find("desktop_tls_wait_ready(") != std::string::npos);
    CHECK(source.find("desktop_tls_resolve(") != std::string::npos);
    CHECK(source.find("worker.detach()") != std::string::npos);
    CHECK(source.find("O_NONBLOCK") != std::string::npos);
    CHECK(source.find("::poll(") != std::string::npos);
    CHECK(source.find("SSL_ERROR_WANT_READ") != std::string::npos);
    CHECK(source.find("SSL_ERROR_WANT_WRITE") != std::string::npos);
    CHECK(source.find("TLS node request total deadline exceeded") != std::string::npos);
    CHECK(source.find("TLS node request interrupted by shutdown") != std::string::npos);
    CHECK(source.find("desktop_tls_shutdown(tls, fd, request_deadline)") != std::string::npos);
    CHECK(source.find("endpoint.may_use_local_bearer && !auth_token.empty()") != std::string::npos);
    CHECK(source.find("opt_rpcurl = \"https://node1.veld.network\"") != std::string::npos);

    bool self_signed_rejected = false;
    if (const char* port = std::getenv("VELD_TEST_SELF_SIGNED_TLS_PORT")) {
        const std::string result = proxy_rpc(std::string("https://localhost:") + port,
                                             R"({"jsonrpc":"2.0","method":"getblockcount","id":1})",
                                             "must-not-authorize-an-untrusted-peer");
        self_signed_rejected =
            result.find("TLS authentication or node request failed") != std::string::npos ||
            result.find("TLS certificate or hostname verification failed") != std::string::npos;
        CHECK(self_signed_rejected);
    }

    std::cout << "PASS desktop_rpc_transport_tests checks=" << checks
              << " remote_plaintext_endpoints=0 self_signed_rejected="
              << (self_signed_rejected ? 1 : 0) << "\n";
    return 0;
}
