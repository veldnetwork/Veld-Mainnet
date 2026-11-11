#pragma once

// A separately mined, valueless developer network. This is a shipping-profile
// selector, never a validation bypass or a runtime genesis override.
#if defined(VELD_DEVELOPER_TESTNET)
#if !defined(VELD_PUBLIC_TESTNET) || !defined(VELD_PUBLIC_RELEASE) ||                              \
    !defined(VELD_MAINNET_POW) || !defined(VELD_USE_LEVELDB) ||                                    \
    !defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
#error "Developer testnet requires the persistent full public-testnet validator"
#endif
#if defined(VELD_PUBLIC_MAINNET) || defined(VELD_APPCHAIN_PUBLIC_CHILD) ||                         \
    defined(VELD_ASERT_TESTCHAIN) || defined(VELD_APPCHAIN_BRIDGE_DEVNET) ||                       \
    defined(VELD_APPCHAIN_FULL_QUALIFICATION) || defined(VELD_LIGHT_VERIFY) ||                     \
    defined(VELD_TEST_DATASET_BYTES) || defined(VELD_TEST_CHAIN_BUILD) ||                          \
    defined(VELD_DSTATE_QUALIFICATION) || defined(VELD_TEST_HOOKS) ||                              \
    defined(VELD_REGTEST_FIXED_DIFF) || defined(VELD_LOCAL_SIM) || defined(VELD_FUZZ_BUILD)
#error "Developer testnet cannot contain mainnet or qualification validation"
#endif
#endif

#include <cstdint>
namespace veld::developer_testnet {
inline constexpr const char* PROFILE = "veld-developer-testnet-v1";
inline constexpr const char* DISPLAY_NAME = "Veld Developer Testnet v1";
inline constexpr const char* DATA_DIR = "./veld-developer-testnet-v1-data";
inline constexpr uint32_t MAGIC = 0x31544456u;
inline constexpr uint16_t P2P_PORT = 20333, RPC_PORT = 20334;
inline constexpr uint16_t EXPLORER_PORT = 20080, WALLET_PORT = 20090, MINER_PORT = 20095;
inline constexpr const char* TIMESTAMP = "2026-10-25T00:00:00Z";
inline constexpr uint64_t TIME = 1792886400;
inline constexpr const char* MESSAGE =
    "Veld Developer Testnet v1 - valueless native applications - 2026-10-25";
inline constexpr uint32_t BITS = 0x200fffffu;
// Mined with the full 1 GiB VeldHash dataset; verified independently against
// the canonical target. HASH is display byte order, not wire byte order.
inline constexpr uint64_t NONCE = 5;
inline constexpr const char* HASH =
    "f2d4b2081a2bcc29a123082ee3126c964dc90a7f6462d496876a0a19f7851e53";
inline constexpr uint64_t ASERT_HEIGHT = 1;
inline constexpr uint64_t LEASE_HEIGHT = 20000;
inline constexpr const char* LEASE_UTC = "2027-01-31T00:00:00Z";
} // namespace veld::developer_testnet
