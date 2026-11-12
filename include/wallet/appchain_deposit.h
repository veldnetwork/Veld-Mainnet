#pragma once
#include "../core/blockchain.h"
#include "../core/mempool.h"
#include "offline_signing.h"

namespace veld {
inline constexpr size_t MAX_APPCHAIN_DEPOSIT_INPUTS = 180;

inline std::vector<uint8_t> AppchainDepositMarker(const app::Id& bridge, const app::Id& beneficiary,
                                                  uint64_t trading, uint64_t fuel) {
    app::need(bridge != app::Id{} && beneficiary != app::Id{} && app::add(trading, fuel),
              "positive deposit and bound identities required");
    app::Writer body;
    body.raw(bridge);
    body.raw(beneficiary);
    body.n(trading, 8);
    body.n(fuel, 8);
    return app::bridge::marker(1, body.b);
}

// Expected identities and amounts come from the user's selected network and
// destination, never from the preparer's untrusted response.
inline bool VerifyAppchainDepositEnvelope(const offline_signing::VerifiedPrepared& prepared,
                                          const std::vector<uint8_t>& fundingScript,
                                          const app::Id& bridge, const app::Id& beneficiary,
                                          uint64_t trading, uint64_t fuel, std::string& error) {
    try {
        const auto amount = app::add(trading, fuel);
        const auto required = app::add(amount, MIN_TX_FEE);
        app::need(prepared.total_input >= required && prepared.fee == MIN_TX_FEE,
                  "deposit must fund exact allocation and canonical fee");
        const auto change = prepared.total_input - required;
        const auto& tx = prepared.tx;
        app::need(tx.version == 1 && tx.locktime == 0 && !tx.inputs.empty() &&
                      tx.inputs.size() <= MAX_APPCHAIN_DEPOSIT_INPUTS &&
                      prepared.signed_size <= Mempool::MAX_RELAY_TX_BYTES &&
                      prepared.claimed_change == change && tx.outputs.size() == (change ? 3U : 2U),
                  "deposit envelope or change differs");
        app::need(tx.outputs[0].value == 0 &&
                      tx.outputs[0].script_pubkey ==
                          AppchainDepositMarker(bridge, beneficiary, trading, fuel) &&
                      tx.outputs[1].value == amount &&
                      tx.outputs[1].script_pubkey == app::bridge::reserveScript(bridge),
                  "deposit beneficiary, allocation or reserve differs");
        app::need(!change || (tx.outputs[2].value == change &&
                              tx.outputs[2].script_pubkey == fundingScript),
                  "deposit change must return to the funding wallet");
        return true;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}

// Supplied by the wallet's selected network and reviewed account, not copied
// from the transaction preparer. No private key is needed for this check.
struct AppchainDepositSelection {
    Hash256 parentGenesis{};
    app::Id bridge{}, descriptor{}, child{}, beneficiary{};
    uint64_t trading = 0, fuel = 0;

    std::string Identity() const {
        app::need(parentGenesis != Hash256{} && bridge != app::Id{} && descriptor != app::Id{} &&
                      child != app::Id{} && beneficiary != app::Id{},
                  "complete selected bridge identity required");
        app::need(app::add(trading, fuel) > 0, "positive backed allocation required");
        return "VELD_APPCHAIN_DEPOSIT_V1|" + HashToHex(parentGenesis) + "|" + app::hex(bridge) +
               "|" + app::hex(descriptor) + "|" + app::hex(child) + "|" + app::hex(beneficiary) +
               "|" + std::to_string(trading) + "|" + std::to_string(fuel);
    }
};

inline bool AuthenticateAppchainDeposit(const btc_buy::JsonValue& response,
                                        const std::vector<uint8_t>& fundingScript,
                                        const AppchainDepositSelection& selected,
                                        offline_signing::VerifiedPrepared& out,
                                        std::string& error) {
    try {
        const auto identity = selected.Identity();
        app::need(selected.parentGenesis == CreateGenesisBlock().GetHash(),
                  "selected deposit belongs to another native network");
        offline_signing::VerifiedPrepared checked;
        offline_signing::Intent intent;
        if (!offline_signing::AuthenticatePrepared(response, fundingScript, checked, error) ||
            !VerifyAppchainDepositEnvelope(checked, fundingScript, selected.bridge,
                                           selected.beneficiary, selected.trading, selected.fuel,
                                           error) ||
            !offline_signing::ParseIntent(response, intent, error) ||
            !offline_signing::VerifyIntent(
                intent, checked, "APPCHAIN_DEPOSIT", app::hex(selected.beneficiary),
                app::add(selected.trading, selected.fuel), ScriptToAddress(fundingScript),
                checked.claimed_change, identity, error))
            return false;
        out = std::move(checked);
        return true;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}

struct PreparedAppchainDeposit {
    Transaction transaction;
    app::bridge::Anchor parent;
    app::Id descriptor{}, child{}, bridge{}, owner{};
    uint64_t trading = 0, fuel = 0, totalInput = 0, change = 0;
};

namespace appchain_deposit_detail {
// The caller retains the transition guard across coin selection, construction
// and authenticated parent export. The explicit token prevents accidental use
// as a standalone unlocked helper.
inline PreparedAppchainDeposit PrepareLocked(const Blockchain::ConsensusTransitionGuard&,
                                             const Blockchain& chain, const app::Id& bridge,
                                             const app::Id& beneficiary, uint64_t trading,
                                             uint64_t fuel,
                                             const std::vector<uint8_t>& fundingScript,
                                             const std::vector<app::bridge::Outpoint>& funding) {
    app::need(!chain.IsEmpty(), "parent chain unavailable");
    const auto view = chain.AppBridgeReadView();
    const auto height = app::add(view.anchor().height, 1);
    app::need(AppchainBridgeActive(height), "native appchain bridge is not activated");
    app::need(beneficiary != app::Id{}, "child beneficiary required");
    app::need(!funding.empty() && funding.size() <= MAX_APPCHAIN_DEPOSIT_INPUTS,
              "bounded funding inputs required");
    const auto amount = app::add(trading, fuel);
    app::need(amount > 0, "positive backed allocation required");
    app::need(app::bridge::ordinary(fundingScript), "ordinary funding script required");
    for (const auto& reserved :
         {AddressToScript(POOL_ADDRESS), AddressToScript(ENDORSEMENT_POOL_ADDRESS),
          AddressToScript(VAULT_ADDRESS), AddressToScript(STAKE_VAULT_ADDRESS),
          AddressToScript(BOND_YIELD_ESCROW), AddressToScript(PoolAddressAtHeight(height)),
          AddressToScript(EndorsementPoolAddressAtHeight(height)),
          AddressToScript(VaultAddressAtHeight(height)),
          AddressToScript(StakeVaultAddressAtHeight(height)),
          AddressToScript(BondYieldEscrowAtHeight(height))})
        app::need(fundingScript != reserved, "protocol funds cannot back a user deposit");
    const auto record = view.state().records.find(bridge);
    app::need(record != view.state().records.end(), "native bridge is not registered");
    app::need(AppchainBridgeDescriptorAllowed(record->second.committee.id()),
              "bridge descriptor is not approved by this network");

    PreparedAppchainDeposit result;
    result.parent = view.anchor();
    result.descriptor = record->second.committee.id();
    result.child = record->second.committee.childGenesis;
    result.bridge = bridge;
    result.owner = beneficiary;
    result.trading = trading;
    result.fuel = fuel;
    std::map<app::bridge::Outpoint, app::bridge::Coin> coins;
    for (const auto& point : funding) {
        const auto coin = chain.GetUTXO(point.tx, point.index);
        app::need(coin && coin->script_pubkey == fundingScript,
                  "canonical funding input must belong to the funding wallet");
        app::need(coins
                      .emplace(point, app::bridge::Coin{coin->value, coin->block_height,
                                                        coin->script_pubkey, coin->is_coinbase})
                      .second,
                  "duplicate deposit input");
        app::credit(result.totalInput, coin->value);
        TxInput input;
        input.prev_tx_hash = point.tx;
        input.prev_out_index = point.index;
        result.transaction.inputs.push_back(std::move(input));
    }
    app::need(result.totalInput >= app::add(amount, MIN_TX_FEE),
              "deposit inputs cannot fund allocation and network fee");
    result.change = result.totalInput - amount - MIN_TX_FEE;
    result.transaction.outputs.emplace_back(
        0, AppchainDepositMarker(bridge, beneficiary, trading, fuel));
    result.transaction.outputs.emplace_back(amount, app::bridge::reserveScript(bridge));
    if (result.change)
        result.transaction.outputs.emplace_back(result.change, fundingScript);

    app::bridge::Context context;
    context.height = height;
    context.genesis = view.genesis();
    context.coin = [&](const app::bridge::Outpoint& point) -> std::optional<app::bridge::Coin> {
        const auto it = coins.find(point);
        return it == coins.end() ? std::nullopt : std::optional(it->second);
    };
    context.ordinaryFunding = [&](const app::Bytes& script) { return script == fundingScript; };
    auto proposed = view.state();
    proposed.apply(result.transaction, context);
    app::need(result.transaction.IsValid(), "deposit exceeds native transaction bounds");
    const size_t rawSize = result.transaction.Serialize().size();
    constexpr size_t growth = offline_signing::kCanonicalInputScriptBytes + 2U;
    app::need(rawSize <= Mempool::MAX_RELAY_TX_BYTES &&
                  funding.size() <= (Mempool::MAX_RELAY_TX_BYTES - rawSize) / growth,
              "signed deposit exceeds relay bounds");
    return result;
}
} // namespace appchain_deposit_detail

// This function never reserves, signs or broadcasts funds.
inline PreparedAppchainDeposit
PrepareAppchainDeposit(const Blockchain& chain, const app::Id& bridge, const app::Id& beneficiary,
                       uint64_t trading, uint64_t fuel, const std::vector<uint8_t>& fundingScript,
                       const std::vector<app::bridge::Outpoint>& funding) {
    auto guard = chain.AcquireConsensusTransitionGuard();
    return appchain_deposit_detail::PrepareLocked(guard, chain, bridge, beneficiary, trading, fuel,
                                                  fundingScript, funding);
}
} // namespace veld
