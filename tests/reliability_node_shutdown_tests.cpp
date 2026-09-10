#include "regtest_profile.h"
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_LOCAL_TEST_NETWORK 1
#define VELD_ENABLE_SNAPSHOT_BOOTSTRAP 1
#include "node/node.h"
#include <future>
#include <iostream>

using namespace veld;
int main(int argc, char** argv) {
    if (argc != 2 || std::filesystem::exists(argv[1])) return 2;
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
