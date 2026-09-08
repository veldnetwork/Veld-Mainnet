#include "mining/veldhash.h"
#include <chrono>
#include <iomanip>
#include <iostream>
#include <thread>

// Offline production-size workload. No node, wallet, sockets or block submission.
int main(int argc, char** argv) {
    using namespace veld;
    using namespace veld::mining;
    using Clock = std::chrono::steady_clock;
    unsigned workers = 1;
    unsigned hashes = 128;
    unsigned trials = 1;
    bool profile = false;
    try {
        for (int i = 1; i < argc; ++i) {
            const std::string option = argv[i];
            if (option == "--profile") {
                profile = true;
            } else if ((option == "--workers" || option == "--hashes" || option == "--trials") &&
                       i + 1 < argc) {
                const std::string value = argv[++i];
                size_t used = 0;
                const auto count = std::stoul(value, &used);
                if (used != value.size() || count == 0 || count > 4096)
                    throw std::invalid_argument("invalid count");
                if (option == "--workers")
                    workers = static_cast<unsigned>(count);
                if (option == "--hashes")
                    hashes = static_cast<unsigned>(count);
                if (option == "--trials")
                    trials = static_cast<unsigned>(count);
            } else {
                throw std::invalid_argument("unknown argument");
            }
        }
        if (workers > 64 || trials > 20)
            throw std::invalid_argument("count exceeds limit");
    } catch (const std::exception& error) {
        std::cerr << error.what()
                  << "\nusage: mining_benchmark [--workers 1..64] [--hashes 1..4096] "
                     "[--trials 1..20] [--profile]\n";
        return 2;
    }
#if !defined(VELD_MAINNET_POW) || defined(VELD_LIGHT_VERIFY) || defined(VELD_TEST_DATASET_BYTES)
    std::cerr << "Benchmark requires full production VeldHash parameters\n";
    return 2;
#else
    VeldIntegerDeterminismCheck();
    VeldDatasetLightKat();
    constexpr uint64_t height = 2880;
    constexpr uint32_t bits = GENESIS_BITS;
    Hash256 parent{};
    for (size_t i = 0; i < parent.size(); ++i)
        parent[i] = static_cast<uint8_t>(i * 7 + 3);
    const auto dataset_seed = ComputeEpochSeed(parent, height, bits);
    const auto dataset_start = Clock::now();
    {
        auto dataset = GlobalDataset().get_for_seed(dataset_seed);
        if (!dataset)
            return 1;
    }
    const double dataset_ms =
        std::chrono::duration<double, std::milli>(Clock::now() - dataset_start).count();
    struct Sample {
        double initialize_ms{0};
        double execute_ms{0};
        double finalize_ms{0};
        std::vector<Hash256> outputs;
        bool ok{true};
    };
    for (unsigned trial = 0; trial < trials; ++trial) {
        std::vector<Sample> samples(workers);
        std::vector<std::thread> threads;
        const auto start = Clock::now();
        for (unsigned worker = 0; worker < workers; ++worker) {
            threads.emplace_back([&, worker]() {
                try {
                    auto& sample = samples[worker];
                    sample.outputs.resize(hashes);
                    VeldHashVM vm;
                    std::vector<uint8_t> header(88);
                    header[0] = 1;
                    std::copy(parent.begin(), parent.end(), header.begin() + 4);
                    for (size_t i = 36; i < 68; ++i)
                        header[i] = static_cast<uint8_t>(i * 11 + 5);
                    const auto write = [&](size_t offset, uint64_t value, size_t bytes) {
                        for (size_t i = 0; i < bytes; ++i)
                            header[offset + i] = static_cast<uint8_t>(value >> (i * 8));
                    };
                    write(68, 1'788'134'400ULL, 8);
                    write(76, bits, 4);
                    for (unsigned n = 0; n < hashes; ++n) {
                        write(80, 0xfedcba9876540000ULL + worker + uint64_t(n) * workers, 8);
                        SHA256 sha;
                        sha.update(header.data(), header.size());
                        const auto seed = sha.digest();
                        auto before = profile ? Clock::now() : Clock::time_point{};
                        vm.Initialize(seed);
                        if (profile)
                            sample.initialize_ms +=
                                std::chrono::duration<double, std::milli>(Clock::now() - before)
                                    .count();
                        // Match the active miner's per-hash dataset acquisition and lifetime.
                        auto dataset =
                            GlobalDataset().get_for_seed(ComputeEpochSeed(parent, height, bits));
                        if (!dataset) {
                            sample.ok = false;
                            return;
                        }
                        vm.SetDataset(dataset.get());
                        before = profile ? Clock::now() : Clock::time_point{};
                        vm.Execute();
                        if (profile)
                            sample.execute_ms +=
                                std::chrono::duration<double, std::milli>(Clock::now() - before)
                                    .count();
                        before = profile ? Clock::now() : Clock::time_point{};
                        const auto state = vm.FinalizeRaw();
                        sample.outputs[n] = Blake2b256(state.data(), state.size());
                        if (profile)
                            sample.finalize_ms +=
                                std::chrono::duration<double, std::milli>(Clock::now() - before)
                                    .count();
                    }
                } catch (...) {
                    samples[worker].ok = false;
                }
            });
        }
        for (auto& thread : threads)
            thread.join();
        const double seconds = std::chrono::duration<double>(Clock::now() - start).count();
        SHA256 checksum;
        double initialize_ms = 0, execute_ms = 0, finalize_ms = 0;
        for (const auto& sample : samples) {
            if (!sample.ok)
                return 1;
            for (const auto& output : sample.outputs)
                checksum.update(output.data(), output.size());
            initialize_ms += sample.initialize_ms;
            execute_ms += sample.execute_ms;
            finalize_ms += sample.finalize_ms;
        }
        std::cout << std::fixed << std::setprecision(3) << "{\"trial\":" << trial
                  << ",\"workers\":" << workers << ",\"hashes\":" << uint64_t(workers) * hashes
                  << ",\"seconds\":" << seconds
                  << ",\"hashes_per_second\":" << (uint64_t(workers) * hashes / seconds)
                  << ",\"dataset_build_ms\":" << dataset_ms << ",\"dataset_bytes\":" << DATASET_SIZE
                  << ",\"scratchpad_bytes\":" << SCRATCHPAD_SIZE
                  << ",\"initialize_ms\":" << initialize_ms << ",\"execute_ms\":" << execute_ms
                  << ",\"finalize_ms\":" << finalize_ms << ",\"checksum\":\""
                  << HashToHex(checksum.digest()) << "\"}\n"
                  << std::flush;
    }
#endif
}
