#define VELD_TEST_HOOKS 1
#include "daybreak_regtest_profile.h"

#include "../include/node/node.h"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

size_t g_checks = 0;

#define CHECK(expr) do {                                                     \
    ++g_checks;                                                              \
    if (!(expr)) {                                                           \
        throw std::runtime_error(                                            \
            std::string("check failed: ") + #expr + " at line " +          \
            std::to_string(__LINE__));                                       \
    }                                                                        \
} while (false)

class ScopedTempDir {
public:
    ScopedTempDir() {
        const auto suffix = std::chrono::steady_clock::now()
            .time_since_epoch().count();
        path_ = std::filesystem::temp_directory_path() /
            ("veld-daybreak-token-dependencies-" + std::to_string(suffix));
        if (!std::filesystem::create_directory(path_))
            throw std::runtime_error("failed to create isolated test directory");
    }

    ~ScopedTempDir() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

}  // namespace

int main() {
    try {
        veld::OnChainTokenLedger standalone;
        CHECK(standalone.TestHasBtcVeldConsensusDependencies(
            nullptr, nullptr));

        ScopedTempDir data_dir;
        veld::VeldNode node(
            veld::RegtestConfig(), data_dir.path().string());

        // The main ledger must be safe before Start(), WireDB(), ReplayChain(),
        // RPC wiring, or any direct block-ingest helper can run.
        CHECK(node.TestMainTokenConsensusDependenciesBound());

        auto& tokens = node.GetTokens();
        const auto token_snapshot = tokens.SnapshotState();
        tokens.Reset();
        CHECK(node.TestMainTokenConsensusDependenciesBound());
        tokens.RestoreState(token_snapshot);
        CHECK(node.TestMainTokenConsensusDependenciesBound());

        // The ledger keeps aliases to the stable node-owned member objects;
        // state replacement on either object is immediately visible through
        // the already-installed bindings.
        const auto header_digest_before =
            tokens.TestBoundBtcHeaderDigest();
        auto header_state = node.TestMainBtcHeaderChain().SnapshotState();
        veld::btcspv::H256 side_hash{};
        side_hash[0] = 0x5a;
        veld::btcspv::BtcHeaderRecord side_record{};
        side_record.block_hash = side_hash;
        side_record.height = 1;
        header_state.by_hash.emplace(side_hash, side_record);
        node.TestMainBtcHeaderChain().RestoreState(header_state);
        CHECK(node.TestMainBtcHeaderChain().StateDigest() !=
              header_digest_before);
        CHECK(tokens.TestBoundBtcHeaderDigest() ==
              node.TestMainBtcHeaderChain().StateDigest());

        const auto covenant_digest_before =
            tokens.TestBoundBtcVeldRedeemCovenantDigest();
        auto covenant_state =
            node.TestMainBtcVeldRedeemCovenant().SnapshotState();
        covenant_state.insurance_fund_sats = 17;
        node.TestMainBtcVeldRedeemCovenant().RestoreState(covenant_state);
        CHECK(node.TestMainBtcVeldRedeemCovenant().Digest() !=
              covenant_digest_before);
        CHECK(tokens.TestBoundBtcVeldRedeemCovenantDigest() ==
              node.TestMainBtcVeldRedeemCovenant().Digest());

        // Post-block copies explicitly inherit the source ledger's stable
        // dependency pair even when the supplied block is rejected.
        veld::OnChainTokenLedger preview;
        veld::Block invalid_block;
        const veld::BtcVeldPegGateState closed_gate{};
        (void)tokens.BuildPostBlockPreview(
            invalid_block, closed_gate, preview);
        CHECK(preview.TestHasBtcVeldConsensusDependencies(
            &node.TestMainBtcHeaderChain(),
            &node.TestMainBtcVeldRedeemCovenant()));

        // An independently owned preview pair can be rebound without aliasing
        // the main node's objects.
        veld::btcspv::BtcHeaderChain preview_headers(
            veld::BtcVeldCheckpoint(), veld::BtcVeldPowLimit(),
            2016, 1209600, veld::BtcVeldNoRetarget());
        veld::btcveld::SignerBondCovenant preview_covenant;
        preview.SetBtcHeaderChain(&preview_headers);
        preview.SetBtcVeldRedeemCovenant(&preview_covenant);
        CHECK(preview.TestHasBtcVeldConsensusDependencies(
            &preview_headers, &preview_covenant));
        CHECK(!preview.TestHasBtcVeldConsensusDependencies(
            &node.TestMainBtcHeaderChain(),
            &node.TestMainBtcVeldRedeemCovenant()));

        std::cout << "PASS daybreak_node_token_dependency_tests checks="
                  << g_checks << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL daybreak_node_token_dependency_tests: "
                  << error.what() << '\n';
        return 1;
    }
}
