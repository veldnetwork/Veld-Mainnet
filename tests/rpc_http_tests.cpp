#include "network/rpc_http.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
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

std::string Request(uint16_t port, const std::string& method, const std::string& authorization,
                    const std::string& forwarded_identity, const std::string& body = {}) {
    const auto fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!veld::compat::IsValidSocket(fd))
        return {};
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        VELD_CLOSE_SOCKET(fd);
        return {};
    }
    std::string request = method + " / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n";
    if (!authorization.empty())
        request += "Authorization: Bearer " + authorization + "\r\n";
    if (!forwarded_identity.empty()) {
        request += "X-Real-IP: " + forwarded_identity + "\r\n";
        request += "X-Forwarded-For: " + forwarded_identity + ", 127.0.0.1\r\n";
    }
    if (method == "POST") {
        request +=
            "Content-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
            "\r\n";
    }
    request += "\r\n" + body;
    size_t sent = 0;
    while (sent < request.size()) {
        const int wrote =
            ::send(fd, request.data() + sent, static_cast<int>(request.size() - sent), 0);
        if (wrote <= 0) {
            VELD_CLOSE_SOCKET(fd);
            return {};
        }
        sent += static_cast<size_t>(wrote);
    }
    std::string response;
    char buffer[4096];
    for (;;) {
        const int received = ::recv(fd, buffer, sizeof(buffer), 0);
        if (received <= 0)
            break;
        response.append(buffer, static_cast<size_t>(received));
    }
    VELD_CLOSE_SOCKET(fd);
    return response;
}

int Status(const std::string& response) {
    const size_t first_space = response.find(' ');
    if (first_space == std::string::npos || response.size() < first_space + 4)
        return 0;
    try {
        return std::stoi(response.substr(first_space + 1, 3));
    } catch (...) {
        return 0;
    }
}

} // namespace

int main() {
    veld::compat::InitNetwork();
    const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const std::filesystem::path storage_path =
        std::filesystem::temp_directory_path() / ("veld-security-test-rpc-http-test-" + suffix);

    {
        veld::Blockchain chain;
        veld::Mempool mempool;
        veld::StorageEngine storage(storage_path.string(), veld::MAINNET_MAGIC);
        veld::RpcServer rpc(chain, mempool, storage);
        const std::string token = "security-test-test-token";
        veld::RpcHttpServer server(rpc, 0, "", token);
        CHECK(server.Start());
        const uint16_t port = server.TestListeningPort();
        CHECK(port != 0);
        const std::string body = R"({"jsonrpc":"2.0","method":"doesnotexist","params":[],"id":1})";
        for (int i = 0; i < 10; ++i) {
            const std::string spoof = "198.51.100." + std::to_string(i + 1);
            const std::string response =
                Request(port, "POST", "wrong-" + std::to_string(i), spoof, body);
            const int status = Status(response);
            if (status != 401)
                std::cerr << "auth iteration=" << i << " status=" << status
                          << " response=" << response << '\n';
            CHECK(status == 401);
        }
        CHECK(server.TestAuthIdentityCount() == 1);
        CHECK(server.TestRateIdentityCount() == 1);
        CHECK(server.TestGlobalAuthFailureCount() == 10);
        CHECK(Status(Request(port, "POST", "wrong-eleven", "203.0.113.250", body)) == 429);
        CHECK(server.TestAuthIdentityCount() == 1);
        CHECK(Status(Request(port, "POST", token, "192.0.2.77", body)) == 200);
        CHECK(server.TestAuthIdentityCount() == 0);
        CHECK(server.TestGlobalAuthFailureCount() == 10);
        const std::string removed_history_body =
            R"({"jsonrpc":"2.0","method":"getearnings","params":["address"],"id":2})";
        const std::string removed_history_response =
            Request(port, "POST", token, "192.0.2.78", removed_history_body);
        CHECK(Status(removed_history_response) == 200);
        CHECK(removed_history_response.find("\"code\":-32601") != std::string::npos);
        CHECK(removed_history_response.find("Method not found") != std::string::npos);
        CHECK(Status(Request(port, "POST", "wrong-after-success", "198.18.0.1", body)) == 401);
        CHECK(server.TestAuthIdentityCount() == 1);
        server.Stop();

        veld::RpcHttpServer burst_server(rpc, 0, "", token);
        CHECK(burst_server.Start());
        const uint16_t burst_port = burst_server.TestListeningPort();
        CHECK(burst_port != 0);
        for (int i = 0; i < 30; ++i) {
            const std::string spoof = "203.0.113." + std::to_string((i % 250) + 1);
            CHECK(Status(Request(burst_port, "GET", "", spoof)) == 200);
        }
        CHECK(Status(Request(burst_port, "GET", "", "192.0.2.251")) == 429);
        CHECK(burst_server.TestRateIdentityCount() == 1);
        burst_server.Stop();
    }

    std::error_code cleanup_error;
    std::filesystem::remove_all(storage_path, cleanup_error);
    CHECK(!cleanup_error);
    CHECK(!std::filesystem::exists(storage_path));

    std::cout << "PASS rpc_http_tests checks=" << checks
              << " forwarded_identities_ignored=41 removed_history_method=1\n";
    return 0;
}
