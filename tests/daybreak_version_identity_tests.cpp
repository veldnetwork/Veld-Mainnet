#include "core/constants.h"
#include "core/version.h"

#include <iostream>
#include <string_view>

using namespace veld;

int main() {
#if !defined(VELD_MAINNET_POW) || !defined(VELD_PUBLIC_RELEASE) || \
    !defined(VELD_PUBLIC_MAINNET)
#error "daybreak_version_identity_tests requires the public-mainnet profile"
#endif

    static_assert(std::string_view(CLIENT_VERSION) == "3.0.2",
                  "public release version changed");
    static_assert(std::string_view(CLIENT_USER_AGENT) == "/Veld:3.0.2/",
                  "P2P client identity changed independently");

    // Release identity is intentionally separate from consensus identity.
    static_assert(PROTOCOL_VERSION == 2,
                  "release version update changed the wire protocol");
    static_assert(MAINNET_MAGIC == 0x56454C44,
                  "release version update changed mainnet magic");
    static_assert(std::string_view(GENESIS_HASH) ==
                      "880a0057852ffcfa35119a83e556802848ed5cb469b260fb9fbd20e8b97ae77b",
                  "release version update changed genesis identity");
    static_assert(std::string_view(DEPLOYMENT_PROFILE_ID) ==
                      "veld-public-mainnet-v2",
                  "release version update changed network identity");

    std::cout << "PASS daybreak_version_identity_tests version="
              << CLIENT_VERSION << " protocol=" << PROTOCOL_VERSION
              << " profile=" << DEPLOYMENT_PROFILE_ID << "\n";
    return 0;
}
