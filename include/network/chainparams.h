#pragma once

#include "../core/constants.h"
#include "../core/block.h"
#include <string>

namespace veld {

// Transport-only namespace for the existing July public testnet.  These
// values MUST NOT be moved into consensus constants. Final mainnet and the
// disposable testnet retain the same native signing/address machinery, but
// testnet consensus rejects every external-value protocol and the two roles
// cannot share P2P sockets, RPC defaults, or datadirs.
inline constexpr uint32_t PUBLIC_TESTNET_MAGIC = 0x52564C44u;
inline constexpr uint16_t PUBLIC_TESTNET_P2P_PORT = 19333;
inline constexpr uint16_t PUBLIC_TESTNET_RPC_PORT = 19334;
inline constexpr uint16_t PUBLIC_TESTNET_EXPLORER_PORT = 19080;
inline constexpr uint16_t PUBLIC_TESTNET_WALLET_UI_PORT = 19090;
inline constexpr uint16_t PUBLIC_TESTNET_MINER_UI_PORT = 19095;
inline constexpr const char* PUBLIC_TESTNET_DATA_DIR =
    "./veld-public-testnet-data";
inline constexpr uint16_t PUBLIC_MAINNET_RPC_PORT = 8334;
inline constexpr uint16_t PUBLIC_MAINNET_EXPLORER_PORT = 8080;
inline constexpr uint16_t PUBLIC_MAINNET_WALLET_UI_PORT = 8090;
inline constexpr uint16_t PUBLIC_MAINNET_MINER_UI_PORT = 8095;

constexpr uint16_t CompiledPublicP2PPort() {
#if defined(VELD_PUBLIC_TESTNET)
    return PUBLIC_TESTNET_P2P_PORT;
#else
    return MAINNET_PORT;
#endif
}

constexpr uint16_t CompiledPublicRpcPort() {
#if defined(VELD_PUBLIC_TESTNET)
    return PUBLIC_TESTNET_RPC_PORT;
#else
    return PUBLIC_MAINNET_RPC_PORT;
#endif
}

constexpr uint16_t CompiledPublicExplorerPort() {
#if defined(VELD_PUBLIC_TESTNET)
    return PUBLIC_TESTNET_EXPLORER_PORT;
#else
    return PUBLIC_MAINNET_EXPLORER_PORT;
#endif
}

constexpr uint16_t CompiledPublicWalletUiPort() {
#if defined(VELD_PUBLIC_TESTNET)
    return PUBLIC_TESTNET_WALLET_UI_PORT;
#else
    return PUBLIC_MAINNET_WALLET_UI_PORT;
#endif
}

constexpr uint16_t CompiledPublicMinerUiPort() {
#if defined(VELD_PUBLIC_TESTNET)
    return PUBLIC_TESTNET_MINER_UI_PORT;
#else
    return PUBLIC_MAINNET_MINER_UI_PORT;
#endif
}

constexpr bool CompiledRoleAllowsPort(uint16_t actual, uint16_t expected) {
#if defined(VELD_PUBLIC_TESTNET)
    return actual == expected;
#else
    (void)actual;
    (void)expected;
    return true;
#endif
}

// Runtime network selection is a transport/developer concern, never a second
// source of genesis or consensus identity. Production-semantics builds,
// including the nonshipping D-state qualification executable, are bound to
// the one compiled mainnet identity; isolated test transports remain
// available only in ordinary development builds.
enum class NetworkKind : uint8_t {
    Mainnet,
    Testnet,
    Regtest,
};

constexpr bool RuntimeNetworkAllowed(NetworkKind kind) {
#if defined(VELD_PUBLIC_RELEASE) || defined(VELD_DSTATE_QUALIFICATION)
    return kind == NetworkKind::Mainnet;
#else
    (void)kind;
    return true;
#endif
}

constexpr const char* DefaultDataDirForNetwork(NetworkKind kind) {
    switch (kind) {
        case NetworkKind::Mainnet:
#if defined(VELD_PUBLIC_TESTNET)
            return PUBLIC_TESTNET_DATA_DIR;
#else
            return "./veld-data";
#endif
        case NetworkKind::Testnet: return "./veld-data-testnet";
        case NetworkKind::Regtest: return "./veld-data-regtest";
    }
    return "./veld-data-invalid";
}

struct NetworkConfig {
    NetworkKind kind{NetworkKind::Mainnet};
    std::string name;
    uint32_t    magic;
    uint16_t    port;
    uint16_t    rpc_port{PUBLIC_MAINNET_RPC_PORT};

    uint64_t bootstrap_phase_end_units = STAKING_ACTIVATION_SUPPLY;

    bool validator_system_always_active{false};

    bool IsTestNetwork() const noexcept {
        return kind != NetworkKind::Mainnet;
    }
};

inline NetworkConfig MainnetConfig() {
    NetworkConfig config;
    config.kind              = NetworkKind::Mainnet;
#if defined(VELD_PUBLIC_TESTNET)
    config.name              = "Veld Public Testnet v1";
    config.magic             = PUBLIC_TESTNET_MAGIC;
    config.port              = CompiledPublicP2PPort();
    config.rpc_port          = CompiledPublicRpcPort();
#else
    config.name              = "Veld Mainnet";
    config.magic             = MAINNET_MAGIC;
    config.port              = CompiledPublicP2PPort();
    config.rpc_port          = CompiledPublicRpcPort();
#endif
    return config;
}

inline NetworkConfig TestnetConfig() {
    NetworkConfig config;
    config.kind              = NetworkKind::Testnet;
    config.name              = "Veld Testnet";
    config.magic             = TESTNET_MAGIC;
    config.port              = TESTNET_PORT;

    config.validator_system_always_active = true;

    config.bootstrap_phase_end_units = 10'000 * VELD_UNITS;
    return config;
}

inline NetworkConfig RegtestConfig() {
    NetworkConfig config;
    config.kind              = NetworkKind::Regtest;
    config.name              = "Veld Regtest";
    config.magic             = 0x72564C44;
    config.port              = 28333;

    config.validator_system_always_active = true;

    config.bootstrap_phase_end_units = 100 * VELD_UNITS;
    return config;
}

}
