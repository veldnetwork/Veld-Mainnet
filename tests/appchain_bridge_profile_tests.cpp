#include "core/blockchain.h"
#include "wallet/appchain_deposit.h"
#include "wallet/appchain_payout.h"
#include "consensus/state_digest.h"
#include <iostream>
#include <limits>

int main() {
    static_assert(!veld::APPCHAIN_BRIDGE_ENABLED);
    static_assert(!veld::AppchainBridgeActive(0));
    static_assert(!veld::AppchainBridgeActive(std::numeric_limits<uint64_t>::max()));
    app::Id arbitrary{};
    arbitrary[0] = 1;
    if (veld::AppchainBridgeDescriptorAllowed(arbitrary) ||
        veld::AppchainBridgeDescriptorAllowed({})) return 1;
    veld::Blockchain chain;
    if (!chain.AppBridgeState()->records.empty() || chain.AppBridgeState()->totalReserve) return 1;
    auto genesis = veld::CreateGenesisBlock();
    veld::Hash256 previous{}; previous[0] = 42;
    for (auto height : {uint64_t{0}, uint64_t{5}, std::numeric_limits<uint64_t>::max()})
        if (veld::state_digest::WithAppchainBridge(height, previous, arbitrary) != previous) return 1;
    if (!chain.AddBlockDirect(genesis, false, false, false,
                              veld::mining::PowAdmissionContext::Internal()).IsAccepted()) return 1;
    if (chain.AppAuxiliaryTemplate(genesis)) return 1;
    try {
        veld::PrepareAppchainDeposit(chain, arbitrary, arbitrary, 1, 0, {}, {});
        return 1;
    } catch (const std::exception& e) {
        if (std::string(e.what()).find("not activated") == std::string::npos) return 1;
    }
    try {
        veld::PrepareAppchainPayout(chain, {}, {}, {}, {}, veld::MIN_TX_FEE);
        return 1;
    } catch (const std::exception& e) {
        if (std::string(e.what()).find("not activated") == std::string::npos) return 1;
    }
    std::cout << "{\"status\":\"PASS_PUBLIC_BRIDGE_INACTIVE\",\"genesis\":\""
              << veld::HashToHex(genesis.GetHash()) << "\",\"activation_enabled\":false,"
                 "\"descriptor_pinned\":false,\"reserve_atoms\":0}\n";
}
