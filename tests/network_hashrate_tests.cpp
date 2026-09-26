#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#include "network/explorer.h"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>

int main(int argc, char** argv) {
    using namespace veld;
    std::vector<BlockHeader> headers(145);
    for (size_t i = 0; i < headers.size(); ++i) {
        headers[i].bits = 0x1f00ffff;
        headers[i].timestamp = 5000000000ULL + i * 180;
        if (i)
            headers[i].prev_block_hash = headers[i - 1].GetHash();
    }
    auto rate = EstimateNetworkHashrate(headers);
    const auto work = BlockWork(headers[1].bits).ToUint64Saturated();
    assert(rate.available && rate.intervals == 144 && rate.seconds == 144 * 180);
    assert(std::abs(rate.hashes_per_second - double(work) / 180) < 1e-9);
    for (size_t i = 0; i < headers.size(); ++i) {
        headers[i].timestamp = 5000000000ULL + i * 360;
        if (i)
            headers[i].prev_block_hash = headers[i - 1].GetHash();
    }
    assert(std::abs(EstimateNetworkHashrate(headers).hashes_per_second -
                    rate.hashes_per_second / 2) < 1e-9);
    headers.resize(3);
    headers[1].bits = 0x1e00ffff;
    headers[2].prev_block_hash = headers[1].GetHash();
    auto mixed = EstimateNetworkHashrate(headers);
    assert(std::abs(mixed.hashes_per_second -
                    double(BlockWork(headers[1].bits).ToUint64Saturated() + work) / 720) < 1e-9);
    headers[1].bits = 0;
    assert(!EstimateNetworkHashrate(headers).available);
    assert(!EstimateNetworkHashrate({}).available);
    assert(!EstimateNetworkHashrate(std::vector<BlockHeader>(146)).available);
    headers.resize(2);
    headers[1] = headers[0];
    headers[1].prev_block_hash = headers[0].GetHash();
    assert(!EstimateNetworkHashrate(headers).available);
    headers[1].timestamp++;
    headers[1].prev_block_hash.fill(0);
    assert(!EstimateNetworkHashrate(headers).available);
    Blockchain chain;
    Mempool mempool;
    explorer::BlockExplorer service(chain, mempool);
    uint64_t height = 99;
    assert(chain.RecentCanonicalHeaders(height).empty() && height == 0);
    explorer::HttpRequest request;
    request.method = "GET";
    request.path = "/pool";
    request.path_parts = {"pool"};
    auto pool = service.Route(request);
    assert(pool.status_code == 200 &&
           pool.body.find("id=\"pool-public-status\"") != std::string::npos);
    request.path = "/mempool";
    request.path_parts = {"mempool"};
    auto page = service.Route(request);
    assert(page.status_code == 200 && page.body.find("pending fees") == std::string::npos);
    assert(page.body.find("&middot; shown") == std::string::npos);
    assert(page.body.find("href=\"/pool\"") != std::string::npos);
    request.path = "/api/stats";
    request.path_parts = {"api", "stats"};
    auto stats = service.Route(request);
    assert(stats.body.find("canonical_work_over_observed_time") != std::string::npos);
    assert(stats.body.find("\"hashrate\":null") != std::string::npos);
    if (argc == 2) {
        std::filesystem::path out(argv[1]);
        std::ofstream(out / "explorer-pool.html") << pool.body;
        std::ofstream(out / "explorer-mempool.html") << page.body;
    }
    std::cout
        << "PASS native observed-work estimate, timestamps above 32 bits, difficulty changes, invalid/empty samples, and real Explorer routes\n";
}
