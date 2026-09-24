#include "mining/veldhash.h"
#include <iostream>

int main() try {
    using namespace veld;
    using namespace veld::mining;
    VeldIntegerDeterminismCheck();
    VeldDatasetLightKat();
    constexpr uint64_t height = 512;
    CanonicalPowTarget target;
    if (!DecodeCanonicalVeldTarget(GENESIS_BITS, target))
        throw std::runtime_error("target fixture");
    Hash256 parent{};
    for (size_t i = 0; i < parent.size(); ++i)
        parent[i] = static_cast<uint8_t>(i * 13 + 5);
    std::vector<uint8_t> header(88);
    header[0] = 1;
    std::copy(parent.begin(), parent.end(), header.begin() + 4);
    for (size_t i = 36; i < 68; ++i) header[i] = static_cast<uint8_t>(i * 7 + 3);
    for (size_t i = 0; i < 4; ++i)
        header[76 + i] = static_cast<uint8_t>(target.bits >> (8 * i));
    const auto cached = ComputeEpochSeed(parent, height, target.bits);
    {
        auto warm = GlobalDataset().get_for_seed(cached);
        if (!warm) throw std::runtime_error("dataset fixture unavailable");
    }
    VeldHashVM canonical_workspace, cached_workspace;
    for (uint64_t n = 0; n < 12; ++n) {
        const uint64_t timestamp = 1788134400ULL + n / 4;
        for (size_t i = 0; i < 8; ++i) {
            header[68 + i] = static_cast<uint8_t>(timestamp >> (8 * i));
            header[80 + i] = static_cast<uint8_t>(n >> (8 * i));
        }
        const auto canonical = VeldHashWithDataset<false>(
            header, height, target, &canonical_workspace);
        if (!g_veldhash_last_dataset_ok())
            throw std::runtime_error("canonical dataset failed");
        SHA256 sha;
        sha.update(header.data(), header.size());
        cached_workspace.Initialize(sha.digest());
        auto dataset = GlobalDataset().get_for_seed(cached);
        if (!dataset) throw std::runtime_error("cached dataset unavailable");
        cached_workspace.SetDataset(dataset.get());
        cached_workspace.Execute();
        const auto state = cached_workspace.FinalizeRaw();
        const auto optimized = Blake2b256(state.data(), state.size());
        if (canonical != optimized ||
            cached != ComputeEpochSeed(parent, height, target.bits))
            throw std::runtime_error("cached epoch seed changed canonical proof");
    }
    std::cout << "PASS_CACHED_EPOCH_SEED_12_CANONICAL_PROOFS\n";
} catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
}
