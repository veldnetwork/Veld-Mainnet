#include "regtest_profile.h"
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_LOCAL_TEST_NETWORK 1
#define VELD_ENABLE_SNAPSHOT_BOOTSTRAP 1
#include "node/node.h"
#include <algorithm>
#include <future>
#include <iostream>
#include <vector>

using namespace veld;
int main(int argc, char** argv) {
    const bool stress = argc == 3 && std::string(argv[2]) == "--stress";
    if ((argc != 2 && !stress) || std::filesystem::exists(argv[1])) return 2;
    std::vector<std::jthread> load;
    if (stress) {
        const unsigned workers = std::min(32u,
            std::max(2u, std::thread::hardware_concurrency()));
        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::seconds(30);
        for (unsigned i = 0; i < workers; ++i) {
            load.emplace_back([deadline](std::stop_token stop) {
                while (!stop.stop_requested() &&
                       std::chrono::steady_clock::now() < deadline)
                    std::atomic_signal_fence(std::memory_order_seq_cst);
            });
        }
        std::cout << "bounded CPU load workers=" << workers << std::endl;
    }
    auto config = RegtestConfig(); config.port = 0;
    const std::filesystem::path root(argv[1]);
    for (int i = 0; i < 8; ++i) {
        VeldNode node(config, (root / std::to_string(i)).string());
        node.SetQuietBoot(true);
        node.SetFullIbd(true);
        node.SetBackgroundValidationOnly(i % 2 != 0);
        node.Start();
        node.PrewarmHashDataset(); // waiting prewarm worker must be cancelled
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        const auto start = std::chrono::steady_clock::now();
        std::cout << "stopping round=" << i << " background=" << (i%2!=0) << std::endl;
        node.Stop();
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now()-start).count();
        std::cout << "stop_ms=" << ms << std::endl;
        if (ms >= 2000) return 1;
        node.Stop();
    }
    std::cout << "PASS: 8 full/background node lifecycle cycles\n";
}
