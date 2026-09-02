#pragma once

#include <string_view>

namespace veld {

#if defined(VELD_PUBLIC_TESTNET) && defined(VELD_PUBLIC_MAINNET)
#error "a public artifact cannot be both testnet and final mainnet"
#endif
#if defined(VELD_PUBLIC_RELEASE) && !defined(VELD_PUBLIC_TESTNET) && \
    !defined(VELD_PUBLIC_MAINNET)
#error "VELD_PUBLIC_RELEASE requires exactly one explicit deployment role"
#endif
#if defined(VELD_PUBLIC_TESTNET) && !defined(VELD_PUBLIC_RELEASE)
#error "VELD_PUBLIC_TESTNET requires VELD_PUBLIC_RELEASE"
#endif
#if defined(VELD_PUBLIC_MAINNET) && !defined(VELD_PUBLIC_RELEASE)
#error "VELD_PUBLIC_MAINNET requires VELD_PUBLIC_RELEASE"
#endif
#if defined(VELD_PUBLIC_TESTNET) && !defined(VELD_MAINNET_POW)
#error "VELD_PUBLIC_TESTNET requires VELD_MAINNET_POW"
#endif
#if defined(VELD_PUBLIC_MAINNET) && !defined(VELD_MAINNET_POW)
#error "VELD_PUBLIC_MAINNET requires VELD_MAINNET_POW"
#endif

// Canonical runtime/package release identity. The signed package-manifest
// generator reads CLIENT_VERSION directly from this header, and the release
// gate requires every launcher/RPC/P2P identity to agree with it.
inline constexpr const char* CLIENT_VERSION = "3.0.1";
inline constexpr const char* CLIENT_USER_AGENT = "/Veld:3.0.1/";

// Deployment-role identity is deliberately separate from consensus identity.
// VELD_PUBLIC_TESTNET preserves the July genesis, address encoding, and
// transaction sighash domain so native consensus behavior remains comparable.
// It deliberately does NOT replay the old value-bearing history: the testnet
// role rejects every external-value marker and must start from a clean,
// role-bound datadir. Transport/storage identity and user-facing labels are
// separate as well.
inline constexpr const char* PUBLIC_TESTNET_WARNING =
    "PUBLIC TESTNET — DISPOSABLE — NO VALUE — NO BALANCE/KEY MIGRATION";

#if defined(VELD_PUBLIC_TESTNET)
inline constexpr const char* DEPLOYMENT_ROLE = "public-testnet";
inline constexpr const char* DEPLOYMENT_PROFILE_ID = "veld-public-testnet-v1";
inline constexpr const char* DEPLOYMENT_DISPLAY_NAME = "Veld Public Testnet v1";
inline constexpr const char* DEPLOYMENT_WARNING = PUBLIC_TESTNET_WARNING;
inline constexpr bool DEPLOYMENT_DISPOSABLE = true;
inline constexpr bool DEPLOYMENT_EXTERNAL_VALUE = false;
#elif defined(VELD_PUBLIC_MAINNET)
inline constexpr const char* DEPLOYMENT_ROLE = "public-mainnet";
inline constexpr const char* DEPLOYMENT_PROFILE_ID = "veld-public-mainnet-v2";
inline constexpr const char* DEPLOYMENT_DISPLAY_NAME = "Veld Mainnet v2";
inline constexpr const char* DEPLOYMENT_WARNING = "";
inline constexpr bool DEPLOYMENT_DISPOSABLE = false;
inline constexpr bool DEPLOYMENT_EXTERNAL_VALUE = true;
#else
inline constexpr const char* DEPLOYMENT_ROLE = "developer";
inline constexpr const char* DEPLOYMENT_PROFILE_ID = "veld-developer-v1";
inline constexpr const char* DEPLOYMENT_DISPLAY_NAME = "Veld Developer";
inline constexpr const char* DEPLOYMENT_WARNING = "";
inline constexpr bool DEPLOYMENT_DISPOSABLE = true;
inline constexpr bool DEPLOYMENT_EXTERNAL_VALUE = false;
#endif

constexpr bool CompiledRoleAllowsFinalMainnetTrustUtility(
        std::string_view argument) {
#if defined(VELD_PUBLIC_TESTNET)
    return argument != "--verify-release" &&
           argument != "--verify-snapshot" &&
           argument != "--import-anchor-ws";
#else
    (void)argument;
    return true;
#endif
}

} // namespace veld
