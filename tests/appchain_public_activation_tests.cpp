// Public-profile activation and descriptor checks with an explicit kernel context.
// This does not validate funding signatures, mine a chain, or qualify custody.
#include "core/transaction.h"
#include "appchain/bridge/parent.h"
#include "consensus/state_digest.h"
#include <fstream>
#include <iostream>

#if !defined(VELD_PUBLIC_RELEASE) || !defined(VELD_PUBLIC_MAINNET) || !defined(VELD_MAINNET_POW)
#error "This test requires the actual public mainnet build profile"
#endif
#if defined(VELD_APPCHAIN_BRIDGE_DEVNET) || defined(VELD_TEST_HOOKS) || defined(VELD_TEST_CHAIN_BUILD)
#error "The public activation test cannot use development activation or test hooks"
#endif

namespace br = app::bridge;
static unsigned checks = 0;
static void check(bool ok, const char* reason) {
    app::need(ok, reason);
    ++checks;
}

int main(int argc, char** argv) {
    try {
        app::need(argc == 2, "One public committee file required");
        std::ifstream input(argv[1], std::ios::binary);
        app::need(bool(input), "Public committee unavailable");
        app::Bytes encoded((std::istreambuf_iterator<char>(input)), {});
        app::need(encoded.size() <= 20000, "Bounded public committee required");
        const auto committee = br::decodeCommittee(encoded);
        const auto identity = committee.id();
        veld::Hash256 previous{};
        previous[0] = 17;
        const br::State empty;
        if constexpr (!veld::APPCHAIN_BRIDGE_ENABLED) {
            check(!veld::AppchainBridgeActive(0), "Disabled source activated at zero");
            check(!veld::AppchainBridgeActive(UINT64_MAX), "Disabled source activated at max height");
            check(!veld::AppchainBridgeDescriptorAllowed(identity), "Disabled source accepted a descriptor");
            check(veld::state_digest::WithAppchainBridge(UINT64_MAX, previous, empty.digest()) == previous,
                  "Disabled source changed the historical digest");
        } else {
            const auto height = veld::APPCHAIN_BRIDGE_ACTIVATION_HEIGHT;
            app::need(height > 1 && height < UINT64_MAX, "Bounded test activation required");
            check(!veld::AppchainBridgeActive(height - 1), "Activation occurred before the source height");
            check(veld::AppchainBridgeActive(height), "Activation missing at the source height");
            check(veld::AppchainBridgeActive(height + 1), "Activation missing after the source height");
            check(veld::AppchainBridgeDescriptorAllowed(identity), "Selected public descriptor refused");
            check(!veld::AppchainBridgeDescriptorAllowed({}), "Empty descriptor accepted");
            for (size_t byte = 0; byte < identity.size(); ++byte) {
                auto other = identity;
                other[byte] ^= 1;
                check(!veld::AppchainBridgeDescriptorAllowed(other), "Different descriptor accepted");
            }
            const app::Bytes ordinary = [] {
                app::Bytes bytes{0xc0, 1, 48};
                bytes.insert(bytes.end(), 48, 0x37);
                return bytes;
            }();
            br::Context context;
            context.height = height - 1;
            context.genesis = committee.parentGenesis;
            context.coin = [&](const br::Outpoint&) -> std::optional<br::Coin> {
                return br::Coin{1000000, height - 2, ordinary, false};
            };
            context.ordinaryFunding = [](const app::Bytes& script) { return veld::IsSha384KeyScript(script); };
            auto registration = [&](const app::Committee& selected) {
                app::Writer payload;
                payload.str(selected.encode(), 20000);
                veld::Transaction tx;
                veld::TxInput spend;
                spend.prev_tx_hash[0] = 1;
                spend.prev_out_index = 0;
                tx.inputs.push_back(spend);
                tx.outputs.emplace_back(0, br::marker(0, payload.b));
                tx.outputs.emplace_back(900000, ordinary);
                return tx;
            };
            const auto valid = registration(committee);
            auto state = empty;
            state.apply(valid, context);
            check(state.digest() == empty.digest(), "Pre-activation kernel state changed");
            check(veld::state_digest::WithAppchainBridge(height - 1, previous, empty.digest()) == previous,
                  "Pre-activation historical digest changed");
            context.height = height;
            state.apply(valid, context);
            check(state.records.size() == 1 && state.records.at(committee.bridge).committee.id() == identity,
                  "Selected descriptor registration missing");
            check(state.totalReserve == 0, "Registration fabricated backing");
            const auto before = state.digest();
            auto refuses = [&](const veld::Transaction& tx, const br::Context& selected, const char* reason) {
                auto trial = empty;
                bool refused = false;
                try { trial.apply(tx, selected); } catch (const std::exception&) { refused = true; }
                check(refused && trial.digest() == empty.digest(), reason);
            };
            auto other = committee;
            other.bridge[0] ^= 1;
            refuses(registration(other), context, "Different bridge registered or mutated state");
            other = committee;
            other.childGenesis[0] ^= 1;
            refuses(registration(other), context, "Different child registered or mutated state");
            auto wrongParent = context;
            wrongParent.genesis[0] ^= 1;
            refuses(valid, wrongParent, "Different parent registered or mutated state");
            bool duplicateRefused = false;
            try { state.apply(valid, context); } catch (const std::exception&) { duplicateRefused = true; }
            check(duplicateRefused && state.digest() == before, "Duplicate registration changed state");
            const auto activeDigest = veld::state_digest::WithAppchainBridge(height, previous, before);
            check(activeDigest != previous, "Active state omitted bridge commitment");
            check(activeDigest != veld::state_digest::WithAppchainBridge(height, previous, empty.digest()),
                  "Active digest did not bind the bridge state");
            app::Bytes preimage(previous.begin(), previous.end());
            preimage.insert(preimage.end(), before.begin(), before.end());
            for (unsigned i = 0; i < 8; ++i) preimage.push_back(uint8_t(height >> (i * 8)));
            preimage.insert(preimage.end(), identity.begin(), identity.end());
            check(activeDigest == veld::state_digest::sha256_domain("VELD_STATE_DIGEST_v9|", preimage),
                  "Active state digest differs from explicit encoding");
        }
        std::cout << "{\"status\":\"PASS_PUBLIC_ACTIVATION_KERNEL\",\"checks\":" << checks
                  << ",\"enabled\":" << (veld::APPCHAIN_BRIDGE_ENABLED ? "true" : "false")
                  << ",\"full_chain_qualification\":false,\"signatures_tested\":false,\"network_started\":false}\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
