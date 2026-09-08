#include "mining/worker_policy.h"
#include "node/ibd_policy.h"
#include <iostream>
#include <limits>
#include <stdexcept>

int main() {
    using namespace veld::mining;
    unsigned checks = 0;
    const auto check = [&](bool condition) {
        ++checks;
        if (!condition)
            throw std::runtime_error("worker policy check " + std::to_string(checks));
    };
    try {
        for (unsigned logical = 0; logical <= 512; ++logical) {
            const auto fallback = EstimatedCpuCapacity(logical);
            check(DefaultWorkerCount(fallback) ==
                  ClampWorkerCount(veld::DefaultMiningThreads(logical)));
            for (int preset = 0; preset < 3; ++preset)
                check(ValidWorkerCount(PresetWorkerCount(fallback, preset)));
        }
        check(!ValidWorkerCount(0) && ValidWorkerCount(1) && ValidWorkerCount(64));
        check(!ValidWorkerCount(65) && !ValidWorkerCount(256));
        check(!ValidWorkerCount(UINT64_MAX) && ClampWorkerCount(UINT64_MAX) == 64);
        check(ClampWorkerCount(0) == 1 && ClampWorkerCount(7) == 7);

        const std::vector<uint64_t> non_smt{1, 2, 4, 8, 16, 32, 64, 128};
        const auto eight_cores = CapacityFromCoreMasks(non_smt, 255);
        check(eight_cores.topology_detected && eight_cores.logical == 8 &&
              eight_cores.physical == 8);
        check(DefaultWorkerCount(eight_cores) == 7 && PresetWorkerCount(eight_cores, 2) == 8);
        const std::vector<uint64_t> smt{3, 12, 48, 192};
        const auto four_cores = CapacityFromCoreMasks(smt, 255);
        check(four_cores.topology_detected && four_cores.logical == 8 && four_cores.physical == 4);
        check(DefaultWorkerCount(four_cores) == 3 && PresetWorkerCount(four_cores, 2) == 4);
        const auto sparse = CapacityFromCoreMasks(smt, 0x55);
        check(sparse.topology_detected && sparse.logical == 4 && sparse.physical == 4);
        const auto one_sibling = CapacityFromCoreMasks(smt, 2);
        check(one_sibling.topology_detected && one_sibling.logical == 1 &&
              one_sibling.physical == 1);
        const std::vector<uint64_t> hybrid{3, 12, 16, 32, 64, 128};
        const auto mixed = CapacityFromCoreMasks(hybrid, 255);
        check(mixed.topology_detected && mixed.logical == 8 && mixed.physical == 6);
        check(DefaultWorkerCount(mixed) == 5 && PresetWorkerCount(mixed, 2) == 6);
        check(!CapacityFromCoreMasks(std::vector<uint64_t>{3, 3}, 3).topology_detected);
        check(!CapacityFromCoreMasks(std::vector<uint64_t>{1}, 3).topology_detected);
        check(!CapacityFromCoreMasks({}, 0).topology_detected);
        const CpuCapacity huge{std::numeric_limits<unsigned>::max(),
                               std::numeric_limits<unsigned>::max(), true};
        for (int preset = 0; preset < 3; ++preset)
            check(PresetWorkerCount(huge, preset) == 64);

        const auto live = DetectCpuCapacity();
        check(live.logical >= live.physical && live.physical > 0);
        check(ValidWorkerCount(DefaultWorkerCount(live)));
#ifdef _WIN32
        DWORD_PTR original_mask = 0, system_mask = 0;
        if (GetActiveProcessorGroupCount() == 1 &&
            GetProcessAffinityMask(GetCurrentProcess(), &original_mask, &system_mask) &&
            original_mask) {
            check(live.topology_detected);
            check(live.logical == std::popcount(static_cast<uint64_t>(original_mask)));
            const auto single = original_mask & (~original_mask + 1);
            check(SetProcessAffinityMask(GetCurrentProcess(), single) != 0);
            const auto restricted = DetectCpuCapacity();
            const bool restored = SetProcessAffinityMask(GetCurrentProcess(), original_mask) != 0;
            check(restored);
            check(restricted.topology_detected && restricted.logical == 1 &&
                  restricted.physical == 1);
        }
#endif
        std::cout << "PASS worker policy checks=" << checks
                  << " detected=" << live.topology_detected << " logical=" << live.logical
                  << " physical=" << live.physical << " default=" << DefaultWorkerCount(live)
                  << '\n';
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
