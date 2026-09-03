#include "network/explorer.h"

#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

using veld::compat::SocketHandle;

static uint16_t FreePort() {
    SocketHandle fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (!veld::compat::IsValidSocket(fd)) return 0;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        VELD_CLOSE_SOCKET(fd);
        return 0;
    }
    socklen_t length = sizeof(address);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        VELD_CLOSE_SOCKET(fd);
        return 0;
    }
    const uint16_t port = ntohs(address.sin_port);
    VELD_CLOSE_SOCKET(fd);
    return port;
}

struct TestResponse {
    int status = 0;
    std::string body;
};

static TestResponse RequestWithBody(uint16_t port, const std::string& path,
                                    const std::string& headers = {}) {
    SocketHandle fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (!veld::compat::IsValidSocket(fd)) return {};
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        VELD_CLOSE_SOCKET(fd);
        return {};
    }
    const std::string wire = "GET " + path + " HTTP/1.1\r\n"
        "Host: explorer.test\r\nConnection: close\r\n" + headers + "\r\n";
    size_t offset = 0;
    while (offset < wire.size()) {
        const int sent = ::send(fd, wire.data() + offset,
            static_cast<int>(wire.size() - offset), 0);
        if (sent <= 0) { VELD_CLOSE_SOCKET(fd); return {}; }
        offset += static_cast<size_t>(sent);
    }
    std::string response;
    char buffer[4096];
    while (response.size() < 1024 * 1024) {
        const int got = ::recv(fd, buffer, sizeof(buffer), 0);
        if (got <= 0) break;
        response.append(buffer, static_cast<size_t>(got));
    }
    VELD_CLOSE_SOCKET(fd);
    const auto first_space = response.find(' ');
    if (first_space == std::string::npos || first_space + 4 > response.size()) return {};
    TestResponse result;
    try { result.status = std::stoi(response.substr(first_space + 1, 3)); }
    catch (...) { return {}; }
    const auto separator = response.find("\r\n\r\n");
    if (separator != std::string::npos) result.body = response.substr(separator + 4);
    return result;
}

static int Request(uint16_t port, const std::string& path,
                   const std::string& headers = {}) {
    return RequestWithBody(port, path, headers).status;
}

static std::string ProxyHeaders(const std::string& client,
                                const std::string& token) {
    return "X-Veld-Proxy-Authorization: VeldProxy v1=" + token + "\r\n"
           "X-Veld-Client-IP: " + client + "\r\n";
}

static veld::Block RewardBlock(veld::Blockchain& chain,
                               const std::vector<uint8_t>& miner_script) {
    using namespace veld;
    Block block;
    block.height = chain.Height() + 1;
    block.header.version = PROTOCOL_VERSION;
    block.header.prev_block_hash = chain.TipCopy().GetHash();
    block.header.timestamp = chain.TipCopy().header.timestamp + 1;
    block.header.bits = chain.ComputeNextBits();
    block.header.nonce = 1;
    const uint64_t effective = std::min(
        Blockchain::ExpectedBlockSubsidy(block.height),
        MAX_SUPPLY_UNITS - chain.TotalSupplyUnits());
    const uint64_t miner_cut = (effective * 50) / 100;
    const uint64_t vault_cut = effective - miner_cut;
    block.transactions.push_back(Transaction::CreateProportionalCoinbase(
        {{miner_script, miner_cut},
         {AddressToScript(VaultAddressAtHeight(block.height)), vault_cut}},
        "explorer-richlist-cache"));
    block.UpdateMerkleRoot();
    return block;
}

int main() {
    veld::compat::InitNetwork();
    size_t checks = 0;
    auto check = [&](bool value) {
        ++checks;
        if (!value) {
            std::cerr << "check " << checks << " failed\n";
            std::exit(1);
        }
    };

    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto directory = std::filesystem::temp_directory_path()
        / ("veld-explorer-proxy-" + std::to_string(nonce));
    std::string error;
    check(veld::channel::secure_file::EnsurePrivateDirectory(
        directory.string(), &error));
    const std::string token(64, '1');
    const std::string token_file_bytes = token + "\n";
    const auto token_path = directory / "proxy.token";
    check(veld::channel::secure_file::AtomicWriteNew(
        token_path.string(),
        reinterpret_cast<const uint8_t*>(token_file_bytes.data()),
        token_file_bytes.size(), &error, true));
    const std::string proxy_config = "VELD_EXPLORER_PROXY_V1\n"
        "peer=127.0.0.1\n"
        "token_file=" + token_path.string() + "\n";
    check(veld::channel::secure_file::AtomicWriteNew(
        (directory / "explorer-proxy.conf").string(),
        reinterpret_cast<const uint8_t*>(proxy_config.data()),
        proxy_config.size(), &error, true));

    veld::Blockchain chain;
    veld::Mempool mempool;
    check(chain.AddBlockDirect(
              veld::CreateGenesisBlock(), true, true, false,
              veld::mining::PowAdmissionContext::Internal()).IsAccepted());
    const uint16_t port = FreePort();
    check(port != 0);
    veld::explorer::BlockExplorer explorer(chain, mempool, port);
    explorer.SetCacheDir(directory.string());
    check(explorer.ProxyConfigurationError().empty());
    check(explorer.Start());
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    const auto page_headers = ProxyHeaders("198.51.100.40", token);
    const auto block_page = RequestWithBody(
        port, "/api/v1/blocks/latest/25", page_headers);
    check(block_page.status == 200);
    check(block_page.body.find("\"tip_height\":0") != std::string::npos);
    check(block_page.body.find("\"start\":0,\"end\":0") != std::string::npos);
    check(block_page.body.find("\"blocks\":[{\"height\":0") != std::string::npos);
    check(Request(port, "/api/v1/blocks/0/0", page_headers) == 400);
    check(Request(port, "/api/v1/blocks/0/51", page_headers) == 400);
    check(Request(port, "/api/v1/blocks/0x/25", page_headers) == 400);
    check(Request(port, "/api/v1/blocks/1/25", page_headers) == 409);
    const auto blocks_html = RequestWithBody(port, "/blocks", page_headers);
    check(blocks_html.status == 200);
    check(blocks_html.body.find("/api/v1/blocks/") != std::string::npos);
    check(blocks_html.body.find("Promise.all(ps)") == std::string::npos);
    check(blocks_html.body.find("if(!r.ok)") != std::string::npos);

    // Both rich-list representations must invalidate immediately at a new
    // chain height and preserve the protocol's full eight-decimal precision.
    const auto rich_before = RequestWithBody(
        port, "/api/v1/richlist", page_headers);
    const auto rich_page_before = RequestWithBody(port, "/rich", page_headers);
    check(rich_before.status == 200);
    check(rich_page_before.status == 200);
    const auto miner_script = veld::AddressToScript(veld::POOL_ADDRESS);
    const uint64_t miner_reward =
        (veld::Blockchain::ExpectedBlockSubsidy(1) * 50) / 100;
    auto reward = RewardBlock(chain, miner_script);
    check(chain.AddBlockDirect(
              reward, true, true, false,
              veld::mining::PowAdmissionContext::Internal()).IsAccepted());
    std::ostringstream exact_balance;
    exact_balance << std::fixed << std::setprecision(8)
                  << static_cast<double>(miner_reward) / veld::VELD_UNITS;
    const auto rich_after = RequestWithBody(
        port, "/api/v1/richlist", page_headers);
    const auto rich_page_after = RequestWithBody(port, "/rich", page_headers);
    check(rich_after.status == 200);
    check(rich_page_after.status == 200);
    check(rich_after.body != rich_before.body);
    check(rich_page_after.body != rich_page_before.body);
    check(rich_after.body.find(
              "\"address\":\"" + std::string(veld::POOL_ADDRESS) +
              "\",\"balance_veld\":" + exact_balance.str()) !=
          std::string::npos);
    check(rich_page_after.body.find(exact_balance.str()) != std::string::npos);

    check(Request(port, "/notfound", "X-Forwarded-For: 198.51.100.9\r\n") == 403);
    check(Request(port, "/notfound", "X-Real-IP: 198.51.100.9\r\n") == 403);
    check(Request(port, "/notfound", "X-Veld-Client-IP: 198.51.100.9\r\n") == 403);
    check(Request(port, "/notfound", ProxyHeaders(
        "198.51.100.9", std::string(64, '0'))) == 403);
    check(Request(port, "/notfound", ProxyHeaders("198.51.100.10", token)
        + "X-Veld-Client-IP: 198.51.100.11\r\n") == 403);
    for (size_t i = 5; i < 60; ++i)
        check(Request(port, "/notfound", ProxyHeaders(
            "198.51.100.9", std::string(64, '0'))) == 403);
    check(Request(port, "/notfound", ProxyHeaders(
        "198.51.100.9", std::string(64, '0'))) == 429);
    check(Request(port, "/notfound", ProxyHeaders("198.51.100.9", token)) == 404);
    check(Request(port, "/notfound", ProxyHeaders("2001:0db8::9", token)) == 404);
    check(Request(port, "/api/txhistory?address=invalid",
                  ProxyHeaders("198.51.100.20", token)) == 404);

    const auto history_headers = ProxyHeaders("198.51.100.30", token);
    for (size_t i = 0; i < 8; ++i)
        check(Request(port, "/address/invalid", history_headers) == 200);
    check(Request(port, "/address/invalid", history_headers) == 429);
    check(Request(port, "/address/invalid",
                  ProxyHeaders("::ffff:198.51.100.30", token)) == 429);
    check(Request(port, "/address/invalid",
                  ProxyHeaders("198.51.100.31", token)) == 200);

    // Client 198.51.100.9 consumed one ordinary token above.
    for (size_t i = 1; i < 60; ++i)
        check(Request(port, "/notfound", ProxyHeaders("198.51.100.9", token)) == 404);
    check(Request(port, "/notfound", ProxyHeaders("198.51.100.9", token)) == 429);
    check(Request(port, "/notfound", ProxyHeaders("198.51.100.12", token)) == 404);

    // Direct loopback is one bounded shared identity rather than an exemption.
    for (size_t i = 0; i < 60; ++i)
        check(Request(port, "/notfound") == 404);
    check(Request(port, "/notfound") == 429);

    explorer.Stop();

    // A fresh backend proves the non-bypassable global request budget using
    // distinct authenticated clients and six route buckets, so neither a
    // client nor route cap is the reason for the final refusal.
    const uint16_t global_port = FreePort();
    check(global_port != 0);
    veld::explorer::BlockExplorer global_explorer(chain, mempool, global_port);
    check(global_explorer.ConfigureTrustedProxy(
        "127.0.0.1", token_path.string(), &error));
    check(global_explorer.Start());
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    const std::array<std::string, 5> routes = {
        "/api/blocks", "/api/supply", "/api/validators",
        "/api/topology", "/api/not-a-route"
    };
    for (size_t i = 0; i < 6000; ++i) {
        const std::string client = "198.18." + std::to_string(i / 256)
            + "." + std::to_string(i % 256);
        const int status = Request(global_port, routes[i % routes.size()],
                                   ProxyHeaders(client, token));
        check(status != 0 && status != 429 && status != 503);
    }
    check(Request(global_port, "/api/topology",
                  ProxyHeaders("198.19.0.1", token)) == 429);
    global_explorer.Stop();

    // A second fresh backend exercises the shared strict history/route cap
    // with independent clients (each is well below its personal history cap).
    const uint16_t history_port = FreePort();
    check(history_port != 0);
    veld::explorer::BlockExplorer history_explorer(chain, mempool, history_port);
    check(history_explorer.ConfigureTrustedProxy(
        "127.0.0.1", token_path.string(), &error));
    check(history_explorer.Start());
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    for (size_t i = 0; i < 60; ++i) {
        const std::string client = "203.0.113." + std::to_string(i + 1);
        check(Request(history_port, "/address/invalid",
                      ProxyHeaders(client, token)) == 200);
    }
    check(Request(history_port, "/address/invalid",
                  ProxyHeaders("203.0.113.200", token)) == 429);
    history_explorer.Stop();

    std::error_code cleanup_error;
    std::filesystem::remove_all(directory, cleanup_error);
    check(!cleanup_error);
    std::cout << "PASS daybreak_explorer_proxy_process_tests checks=" << checks
              << " actual_loopback_history_client_shared_proxy=1\n";
    return 0;
}
