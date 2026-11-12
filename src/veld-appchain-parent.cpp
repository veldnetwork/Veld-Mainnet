#include "node/appchain_parent_feed.h"
#include "node/appchain_parent_network.h"
#include "node/appchain_parent_restart.h"
#include <charconv>
#include <cstdio>

int main(int argc, char** argv) {
    try {
        // The pipe is the protocol; native diagnostics belong on stderr.
        std::cout.rdbuf(std::cerr.rdbuf());
#ifdef _WIN32
        _setmode(_fileno(stdin), _O_BINARY);
        _setmode(_fileno(stdout), _O_BINARY);
#endif
        app::need((argc == 5 || (argc >= 9 && argc <= 13 && argc % 2 == 1)) &&
                      std::string_view(argv[1]) == "--public-parent",
                  "expected --public-parent dedicated-datadir height tip-hash");
        std::vector<std::string> peers;
        for (int i = 5; i < argc; i += 2) {
            app::need(std::string_view(argv[i]) == "--peer",
                      "explicit outbound parent peer option required");
            veld::AppchainParentNetwork::Endpoint(argv[i + 1]);
            peers.emplace_back(argv[i + 1]);
        }
        const std::string_view height_text(argv[3]);
        uint64_t height = 0;
        const auto parsed =
            std::from_chars(height_text.data(), height_text.data() + height_text.size(), height);
        app::need(parsed.ec == std::errc{} &&
                      parsed.ptr == height_text.data() + height_text.size() && height > 0 &&
                      height < UINT64_MAX && std::to_string(height) == height_text,
                  "invalid public parent height");
        const std::string tip(argv[4]);
        const auto tip_bytes = app::unhex(tip, 32);
        app::need(tip_bytes.size() == 32, "invalid public parent hash");
        const auto data = std::filesystem::canonical(argv[2]);
        app::need(std::filesystem::is_regular_file(data / "appchain-parent-reader"),
                  "dedicated parent-reader directory required");
        veld::vendored_crypto::vendored_crypto_selftest();
        const auto durable_tip = veld::ReadAppchainParentReplayTip(data, height, tip);
        veld::VeldNode node(veld::MainnetConfig(), data.string());
        node.SetStakingActivation(veld::STAKING_ACTIVATION_SUPPLY);
        veld::ValidateAppchainParentFromAnchor(node, durable_tip, height, tip);
        std::unique_ptr<veld::AppchainParentNetwork> network;
        if (!peers.empty())
            network = std::make_unique<veld::AppchainParentNetwork>(node, data, peers);
        veld::AppchainPublicParentFeed feed(
            node,
            network ? std::function<app::Bytes()>([&] { return network->Status(); })
                    : std::function<app::Bytes()>{},
            network ? std::function<void(const veld::Block&)>(
                          [&](const auto& block) { network->RelayValidated(block); })
                    : std::function<void(const veld::Block&)>{},
            network ? std::function<void(const veld::Transaction&)>(
                          [&](const auto& tx) { network->RelayAdmittedTransaction(tx); })
                    : std::function<void(const veld::Transaction&)>{});
        veld::ServeAppchainParentFeed(stdin, stdout, node, feed);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "public parent stopped: " << e.what() << '\n';
        return 1;
    }
}
