#ifndef VELD_DESKTOP_OPENSSL_TLS
#define VELD_DESKTOP_OPENSSL_TLS 1
#endif

#define main unreferenced_desktop_main
#include "../src/veld-desktop.cpp"
#undef main

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

int main(int argc, char** argv) {
    if (argc != 5) {
        std::cerr << "usage: tls-harness MODE HOST PORT DEADLINE_MS\n";
        return 2;
    }
    const std::string mode = argv[1];
    const std::string host = argv[2];
    const unsigned long port_value = std::strtoul(argv[3], nullptr, 10);
    const unsigned long deadline_ms = std::strtoul(argv[4], nullptr, 10);
    if (port_value == 0 || port_value > 65535 || deadline_ms == 0 || deadline_ms > 5000) {
        std::cerr << "invalid port/deadline\n";
        return 2;
    }

    DesktopRpcEndpoint endpoint;
    endpoint.host = host;
    endpoint.port = static_cast<uint16_t>(port_value);
    endpoint.secure = true;
    endpoint.may_use_local_bearer = false;

    std::string body = R"({"jsonrpc":"2.0","method":"getblockcount","id":1})";
    if (mode == "plaintext") {
        const auto started = DesktopTlsClock::now();
        const std::string result = proxy_rpc("http://example.com:80", body, "");
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(DesktopTlsClock::now() - started)
                .count();
        std::cout << "elapsed_ms=" << elapsed << "\n"
                  << "result=" << result << "\n";
        return 0;
    }
    if (mode == "write-stall")
        body.assign(32U * 1024U * 1024U, 'x');

    g_shutdown.store(false, std::memory_order_release);
    if (mode == "resolver-busy")
        desktop_tls_resolver_busy().store(true, std::memory_order_release);
    std::thread interrupter;
    if (mode == "shutdown") {
        interrupter = std::thread([] {
            std::this_thread::sleep_for(std::chrono::milliseconds(75));
            g_shutdown.store(true, std::memory_order_release);
        });
    }

    const auto started = DesktopTlsClock::now();
    const std::string result =
        proxy_rpc_https_until(endpoint, body, "", started + std::chrono::milliseconds(deadline_ms));
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(DesktopTlsClock::now() - started)
            .count();
    if (interrupter.joinable())
        interrupter.join();
    if (mode == "resolver-busy")
        desktop_tls_resolver_busy().store(false, std::memory_order_release);
    g_shutdown.store(false, std::memory_order_release);

    std::cout << "elapsed_ms=" << elapsed << "\n"
              << "result=" << result << "\n";
    return 0;
}
