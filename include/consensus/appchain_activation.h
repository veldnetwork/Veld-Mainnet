#pragma once
#include <array>
#include <cstdint>
#include <limits>

// The development activation is confined to a distinct, disposable genesis.
// Public activation and its descriptor must be pinned together in reviewed source.
#if defined(VELD_APPCHAIN_BRIDGE_DEVNET) &&                                                        \
    (!defined(VELD_ASERT_TESTCHAIN) || !defined(VELD_TEST_CHAIN_BUILD) ||                          \
     !defined(VELD_DSTATE_QUALIFICATION) || defined(VELD_PUBLIC_RELEASE) ||                        \
     defined(VELD_PUBLIC_MAINNET) || defined(VELD_PUBLIC_TESTNET) || defined(VELD_TEST_HOOKS))
#error "Appchain bridge development activation requires the isolated qualification profile"
#endif
#if defined(VELD_APPCHAIN_BRIDGE_ACTIVATION_HEIGHT) || defined(VELD_APPCHAIN_BRIDGE_DESCRIPTOR)
#error "Appchain activation is source-pinned; compiler overrides are not supported"
#endif

namespace veld {
// The previous unpublished schedule missed its release lead window. Keep this
// integrated candidate inactive until a new coordinated schedule is qualified.
#ifdef VELD_DEVELOPER_TESTNET
#if !defined(VELD_PUBLIC_TESTNET) || !defined(VELD_PUBLIC_RELEASE) ||                              \
    defined(VELD_PUBLIC_MAINNET) || defined(VELD_APPCHAIN_BRIDGE_DEVNET)
#error "Developer bridge activation requires the distinct public valueless testnet"
#endif
inline constexpr std::array<uint8_t, 48> APPCHAIN_BRIDGE_DESCRIPTOR{
    0x65, 0x3d, 0x93, 0x94, 0x45, 0x16, 0x7c, 0xfe, 0x6f, 0x8a, 0x5b, 0xc6, 0xaf, 0x8c, 0x92, 0x97,
    0xab, 0xe4, 0x7f, 0x4a, 0x2f, 0x27, 0x20, 0x85, 0x6c, 0x9d, 0x8b, 0x53, 0x7d, 0xe1, 0x61, 0x00,
    0x48, 0x8c, 0xc4, 0xdc, 0x3f, 0x9b, 0x99, 0x7f, 0x21, 0xe2, 0xe0, 0x9c, 0x37, 0xd7, 0x39, 0x2a};
inline constexpr bool APPCHAIN_BRIDGE_ENABLED = true;
inline constexpr uint64_t APPCHAIN_BRIDGE_ACTIVATION_HEIGHT = 3;
#else
inline constexpr std::array<uint8_t, 48> APPCHAIN_BRIDGE_DESCRIPTOR{};
#ifdef VELD_APPCHAIN_BRIDGE_DEVNET
inline constexpr bool APPCHAIN_BRIDGE_ENABLED = true;
inline constexpr uint64_t APPCHAIN_BRIDGE_ACTIVATION_HEIGHT = 5;
#else
inline constexpr bool APPCHAIN_BRIDGE_ENABLED = false;
inline constexpr uint64_t APPCHAIN_BRIDGE_ACTIVATION_HEIGHT = std::numeric_limits<uint64_t>::max();
#endif
#endif
inline constexpr bool AppchainBridgeActive(uint64_t height) {
    return APPCHAIN_BRIDGE_ENABLED && height >= APPCHAIN_BRIDGE_ACTIVATION_HEIGHT;
}
inline bool AppchainBridgeDescriptorAllowed(const std::array<uint8_t, 48>& id) {
#ifdef VELD_APPCHAIN_BRIDGE_DEVNET
    return id != std::array<uint8_t, 48>{};
#else
    return APPCHAIN_BRIDGE_DESCRIPTOR != std::array<uint8_t, 48>{} &&
           id == APPCHAIN_BRIDGE_DESCRIPTOR;
#endif
}
static_assert(!APPCHAIN_BRIDGE_ENABLED || APPCHAIN_BRIDGE_ACTIVATION_HEIGHT > 0);
#ifndef VELD_APPCHAIN_BRIDGE_DEVNET
static_assert(!APPCHAIN_BRIDGE_ENABLED || APPCHAIN_BRIDGE_DESCRIPTOR != std::array<uint8_t, 48>{},
              "An enabled public bridge requires a pinned descriptor");
#endif
} // namespace veld
