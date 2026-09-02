#include "network/trusted_proxy.h"

#include <chrono>
#include <filesystem>
#include <iostream>

using namespace veld::net::trusted_proxy;

int main() {
    size_t checks = 0;
    auto check = [&](bool value) {
        ++checks;
        if (!value) {
            std::cerr << "check " << checks << " failed\n";
            std::exit(1);
        }
    };

    std::string canonical;
    check(CanonicalIp("127.0.0.1", canonical) && canonical == "127.0.0.1");
    check(CanonicalIp("2001:0db8::1", canonical) && canonical == "2001:db8::1");
    check(CanonicalIp("::ffff:192.0.2.7", canonical) && canonical == "192.0.2.7");
    for (const std::string bad : {"", "127.000.000.001", "[::1]", "fe80::1%3",
                                  "192.0.2.1,198.51.100.1", "not-an-ip"})
        check(!CanonicalIp(bad, canonical));

    std::array<uint8_t, 32> token{};
    check(DecodeToken(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f", token));
    std::array<uint8_t, 32> invalid{};
    check(!DecodeToken(std::string(64, 'A'), invalid));
    check(!DecodeToken(std::string(63, '0'), invalid));

    Configuration config;
    config.enabled = true;
    config.peer = "127.0.0.1";
    config.token = token;
    std::unordered_map<std::string, std::string> headers;
    auto result = Resolve(config, "127.0.0.1", headers);
    check(result.accepted && !result.forwarded
          && result.identity == "peer:127.0.0.1");

    headers[kAuthorizationHeader] =
        "VeldProxy v1=000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f";
    headers[kClientIpHeader] = "2001:0db8::1";
    result = Resolve(config, "127.0.0.1", headers);
    check(result.accepted && result.forwarded
          && result.identity == "client:2001:db8::1");
    result = Resolve(config, "127.0.0.2", headers);
    check(!result.accepted);
    result = Resolve(config, "127.0.0.1", headers, true);
    check(!result.accepted);

    headers[kAuthorizationHeader] = "VeldProxy v1=" + std::string(64, '0');
    check(!Resolve(config, "127.0.0.1", headers).accepted);
    headers.erase(kAuthorizationHeader);
    check(!Resolve(config, "127.0.0.1", headers).accepted);
    headers.clear();
    headers["x-forwarded-for"] = "198.51.100.9";
    check(!Resolve(config, "127.0.0.1", headers).accepted);
    headers.clear();
    headers["x-real-ip"] = "198.51.100.9";
    check(!Resolve(config, "127.0.0.1", headers).accepted);

    // Exercise the same owner-only descriptor reader used by production.
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto directory = std::filesystem::temp_directory_path()
        / ("veld-proxy-fixture-" + std::to_string(nonce));
    std::string error;
    check(veld::channel::secure_file::EnsurePrivateDirectory(
        directory.string(), &error));
    const auto token_path = directory / "proxy.token";
    const std::string encoded =
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f\n";
    check(veld::channel::secure_file::AtomicWriteNew(
        token_path.string(), reinterpret_cast<const uint8_t*>(encoded.data()),
        encoded.size(), &error, true));
    Configuration loaded;
    check(Configure(loaded, "127.0.0.1", token_path.string(), &error));
    check(loaded.enabled && loaded.peer == "127.0.0.1"
          && ConstantTimeEqual(loaded.token, token));
    std::error_code cleanup_error;
    std::filesystem::remove_all(directory, cleanup_error);
    check(!cleanup_error);

    std::cout << "PASS daybreak_trusted_proxy_tests checks=" << checks
              << " canonical_authenticated_owner_only=1\n";
    return 0;
}
