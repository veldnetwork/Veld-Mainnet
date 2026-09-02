#include "core/marker_composition.h"
#include "mining/preflight_selector.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

using namespace veld;

namespace {

size_t checks = 0;

#define CHECK(expr)                                                          \
    do {                                                                     \
        ++checks;                                                            \
        if (!(expr)) {                                                       \
            std::cerr << "FAIL " << __FILE__ << ':' << __LINE__            \
                      << " " #expr "\n";                                  \
            return 1;                                                        \
        }                                                                    \
    } while (false)

std::vector<uint8_t> Marker(const std::string& payload) {
    std::vector<uint8_t> script{0x6a, static_cast<uint8_t>(payload.size())};
    script.insert(script.end(), payload.begin(), payload.end());
    return script;
}

Transaction WithMarkers(const std::vector<std::string>& payloads) {
    Transaction tx;
    for (const auto& payload : payloads)
        tx.outputs.emplace_back(0, Marker(payload));
    return tx;
}

} // namespace

int main() {
#if defined(VELD_PUBLIC_MAINNET) || defined(VELD_BTCVELD_REGTEST)
    constexpr bool reserve_stateful = true;
#else
    constexpr bool reserve_stateful = false;
#endif

    const Transaction reserve = WithMarkers({"VELD_RSV1|proof"});
    const Transaction duplicate =
        WithMarkers({"VELD_RSV1|one", "VELD_RSV1|two"});
    const Transaction composed =
        WithMarkers({"VELD_RSV1|proof", "VELD_AMM|proof"});

    // All profiles classify RSV1 as external value so public testnet can
    // reject it.  Only fresh mainnet and the isolated reserve test profile
    // activate it as a stateful token marker.
    CHECK(TxUsesExternalValueProtocol(reserve));
    CHECK(TxHasInvalidTokenMarkerSet(duplicate) == reserve_stateful);
    CHECK(TxComposesMultipleProtocols(composed) == reserve_stateful);
    CHECK(mining::MiningTxTouchesStatefulProtocol(reserve) ==
          reserve_stateful);

    std::cout << "PASS daybreak_marker_profile_tests checks=" << checks
              << " reserve_stateful=" << (reserve_stateful ? 1 : 0)
              << " external_rejected=1\n";
    return 0;
}
