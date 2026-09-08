#include "../include/core/blockchain.h"

#include <algorithm>
#include <iostream>

int main() {
    using namespace veld;
    const auto expected = HexToHash(
        "cca5e8f37cfcf63cd2f9a9393e5bc90dd545ef65394a1d4d1aecceffa25e25fc");
    const auto& pins = Blockchain::GetCheckpoints();
#if defined(VELD_PUBLIC_MAINNET)
    if (pins.size() != 1 || pins.at(2800) != HashToHex(expected)) return 1;
    if (!Blockchain::PassesCheckpoint(2800, expected)) return 2;
    for (size_t byte = 0; byte < expected.size(); ++byte) {
        auto changed = expected;
        changed[byte] ^= 1;
        if (Blockchain::PassesCheckpoint(2800, changed)) return 3;
    }
    auto reversed = expected;
    std::reverse(reversed.begin(), reversed.end());
    if (Blockchain::PassesCheckpoint(2800, reversed)) return 4;
    const auto anchors = Blockchain::AllCheckpointPins();
    if (anchors.size() != 1 || anchors.front().first != 2800 ||
        anchors.front().second != HashToHex(expected)) return 5;
#else
    if (!pins.empty() || !Blockchain::AllCheckpointPins().empty()) return 6;
    if (!Blockchain::PassesCheckpoint(2800, expected)) return 7;
#endif
    // A pin applies at its own height; normal consensus handles other blocks.
    if (!Blockchain::PassesCheckpoint(2799, Hash256{}) ||
        !Blockchain::PassesCheckpoint(2801, Hash256{})) return 8;
    std::cout << "PASS compiled checkpoint profile, hash order, and mismatch rejection\n";
}
