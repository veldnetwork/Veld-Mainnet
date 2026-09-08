#include "consensus/checkpoints.h"

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) return 1;
    std::ifstream file(argv[1], std::ios::binary);
    if (!file) return 2;
    const std::string document((std::istreambuf_iterator<char>(file)), {});
    const auto entries = veld::ParseCheckpointsJson(document);
    if (entries.size() != 1 || entries[0].height != 2800) return 3;
    auto checkpoint = entries[0];
#if !defined(VELD_PUBLIC_MAINNET)
    if (veld::VerifyCheckpoint(checkpoint)) return 4;
    std::cout << "PASS public-mainnet checkpoint is rejected by the other network profile\n";
    return 0;
#else
    if (argc == 3 && std::string(argv[2]) == "--legacy-key") {
        if (veld::VerifyCheckpoint(checkpoint)) return 5;
        std::cout << "PASS replacement authority is rejected by the released client's key\n";
        return 0;
    }
    if (!veld::VerifyCheckpoint(checkpoint)) return 6;
    veld::CheckpointStore store;
    if (!store.Add(checkpoint) || !store.Get(2800).has_value()) return 7;
    for (int change = 0; change < 5; ++change) {
        auto changed = checkpoint;
        switch (change) {
            case 0: ++changed.height; break;
            case 1: changed.block_hash[0] ^= 1; break;
            case 2: ++changed.signed_at; break;
            case 3: changed.signature[0] ^= 1; break;
            case 4: changed.signed_at = veld::GENESIS_TIME - 1; break;
        }
        if (veld::VerifyCheckpoint(changed) || store.Add(changed)) return 8 + change;
    }
    if (store.Size() != 1 || store.Latest()->block_hash != checkpoint.block_hash) return 13;
    std::cout << "PASS checkpoint authority, signature binding, and store validation\n";
#endif
}
