#pragma once

// Byte-exact public datadir identity.  A caller-selected --datadir must not be
// able to collapse the testnet and final-mainnet storage namespaces.  Public
// binaries create this immutable marker only before any chain state exists.
// A few network-neutral first-start artifacts may already be present because
// the launcher and updater start alongside the node; everything else remains
// a hard stop. No quarantine/rename path is provided because moving a live
// chain directory is itself a dangerous implicit migration operation.

#include "chainparams.h"
#include "../core/constants.h"
#include "../core/version.h"
#include "../wallet/secure_channel_file.h"

#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace veld {

inline std::string CompiledPublicNetworkIdentityText() {
    const NetworkConfig config = MainnetConfig();
    std::ostringstream magic;
    magic << "0x" << std::hex << std::nouppercase << std::setw(8)
          << std::setfill('0') << config.magic;
    std::ostringstream out;
#if defined(VELD_PUBLIC_MAINNET)
    out << "VELD_NETWORK_IDENTITY_V2\n"
#else
    out << "VELD_NETWORK_IDENTITY_V1\n"
#endif
        << "role=" << DEPLOYMENT_ROLE << "\n"
        << "profile_id=" << DEPLOYMENT_PROFILE_ID << "\n"
        << "genesis_fingerprint=" << GENESIS_HASH << "\n"
        << "network_magic=" << magic.str() << "\n"
        << "p2p_port=" << config.port << "\n"
        << "rpc_port=" << config.rpc_port << "\n"
        << "explorer_port=" << CompiledPublicExplorerPort() << "\n"
        << "wallet_ui_port=" << CompiledPublicWalletUiPort() << "\n"
        << "miner_ui_port=" << CompiledPublicMinerUiPort() << "\n"
        << "disposable=" << (DEPLOYMENT_DISPOSABLE ? "true" : "false") << "\n"
        << "external_value=" << (DEPLOYMENT_EXTERNAL_VALUE ? "true" : "false")
        << "\n";
#if defined(VELD_PUBLIC_MAINNET)
    out << "btcveld_reserve_semantics=rolling-outpoint-v1\n";
#endif
    return out.str();
}

inline bool ValidateOrCreatePublicNetworkIdentity(
        const std::string& data_dir, std::string* error = nullptr) {
#if !defined(VELD_PUBLIC_RELEASE)
    (void)data_dir;
    if (error) error->clear();
    return true;
#else
    namespace fs = std::filesystem;
    const fs::path directory(data_dir);
    const fs::path marker = directory / "network.identity";
    const std::string expected = CompiledPublicNetworkIdentityText();

    auto read_exact = [&](bool* missing) -> bool {
        std::vector<uint8_t> bytes;
        std::string why;
        const auto result = channel::secure_file::Read(
            marker.string(), bytes, &why, 4096,
            /*require_private_parent=*/true);
        if (result == channel::secure_file::ReadResult::NotFound) {
            if (missing) *missing = true;
            return false;
        }
        if (missing) *missing = false;
        if (result != channel::secure_file::ReadResult::Ok) {
            if (error) *error = "cannot securely read network.identity: " + why;
            return false;
        }
        const bool exact = bytes.size() == expected.size()
            && std::equal(bytes.begin(), bytes.end(), expected.begin());
        channel::secure_file::WipeAndClear(bytes);
        if (!exact && error) {
            *error = "network.identity does not exactly match compiled role/profile/"
                     "genesis/magic/ports; refusing datadir without migration or quarantine";
        }
        return exact;
    };

    bool missing = false;
    if (read_exact(&missing)) return true;
    if (!missing) return false;

    auto is_network_neutral_first_start_entry = [](const fs::directory_entry& entry,
                                                    std::error_code& ec) {
        const std::string name = entry.path().filename().string();
        const fs::file_status status = entry.symlink_status(ec);
        if (ec || fs::is_symlink(status)) return false;
        if (fs::is_regular_file(status)) {
            static constexpr std::string_view wallet_suffix = ".veld-keys";
            const bool wallet_keyfile = name.size() > wallet_suffix.size() &&
                name.compare(name.size() - wallet_suffix.size(),
                             wallet_suffix.size(), wallet_suffix) == 0;
            return name == "miner.key" || wallet_keyfile ||
                   name == ".force-update" ||
                   name.rfind(".force-update.applied-", 0) == 0;
        }
        // Tor's client identity and cache do not contain Veld chain identity.
        return fs::is_directory(status) && name == "tor";
    };

    std::error_code ec;
    const fs::directory_iterator end;
    fs::directory_iterator first(directory, ec);
    if (ec) {
        if (error) *error = "cannot enumerate datadir before network.identity: "
                          + ec.message();
        return false;
    }
    for (auto it = first; it != end; it.increment(ec)) {
        if (ec) break;
        std::error_code status_ec;
        if (!is_network_neutral_first_start_entry(*it, status_ec)) {
            if (error) {
                *error = "network.identity is absent from a nonempty public datadir; "
                         "refusing implicit testnet/mainnet migration";
            }
            return false;
        }
    }
    if (ec) {
        if (error) {
            *error = "cannot enumerate datadir before network.identity: " + ec.message();
        }
        return false;
    }

    std::vector<uint8_t> bytes(expected.begin(), expected.end());
    std::string why;
    const bool wrote = channel::secure_file::AtomicWriteNew(
        marker.string(), bytes, &why, /*require_private_parent=*/true);
    channel::secure_file::WipeAndClear(bytes);
    if (!wrote) {
        // A concurrent first-start may have published the same immutable
        // marker.  Accept only after a fresh, byte-exact secure read.
        bool still_missing = false;
        if (read_exact(&still_missing)) return true;
        if (error && error->empty()) {
            *error = "cannot create immutable network.identity: " + why;
        }
        return false;
    }

    bool unexpectedly_missing = false;
    if (!read_exact(&unexpectedly_missing)) {
        if (error && error->empty())
            *error = "new network.identity did not verify byte-for-byte";
        return false;
    }
    return true;
#endif
}

} // namespace veld
