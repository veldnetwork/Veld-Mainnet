#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#include "network/explorer.h"
#include <cassert>
#include <iostream>

using namespace veld;

static std::vector<uint8_t> AddressScript(uint8_t id) {
    std::vector<uint8_t> script{0x76, 0xA9, 0x14};
    script.insert(script.end(), 20, id);
    script.insert(script.end(), {0x88, 0xAC});
    return script;
}

static UTXO Insert(Blockchain& chain, const std::vector<uint8_t>& script, uint64_t units) {
    static uint32_t next_output = 0;
    UTXO output;
    output.output_index = ++next_output;
    output.script_pubkey = script;
    output.value = units;
    chain.TestInjectUTXO(output);
    return output;
}

static void CheckPage(Blockchain& chain, size_t expected) {
    Mempool mempool;
    explorer::BlockExplorer service(chain, mempool);
    const auto request = explorer::HttpRequest::Parse("GET /rich HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const auto response = service.Route(request);
    const std::string counter = "Unique Holders</div><div class=\"stat-value em\">" +
                                std::to_string(expected) + "</div>";
    if (response.body.find(counter) == std::string::npos) {
        std::cerr << "Wrong rendered holder count; expected " << expected << '\n';
        std::abort();
    }
    assert(response.body.find("Top 50 holders") != std::string::npos);
    assert(service.Route(request).body == response.body); // Same-tip cache keeps the full count.
    const size_t ranked = std::min(expected, size_t{50});
    const auto api = service.Route(explorer::HttpRequest::Parse(
        "GET /api/v1/richlist HTTP/1.1\r\nHost: localhost\r\n\r\n"));
    auto count = [](const std::string& text, const std::string& needle) {
        size_t total = 0;
        for (size_t pos = 0; (pos = text.find(needle, pos)) != std::string::npos;
             pos += needle.size())
            ++total;
        return total;
    };
    assert(count(response.body, "class=\"rl-ic ic-h\"") == ranked);
    assert(count(response.body, "class=\"rl-ic ic-s\"") == 5);
    assert(count(api.body, "\"rank\":") == ranked + 5);
    assert(count(api.body, "\"is_system\":true") == 5);
    if (ranked != 0)
        assert(api.body.find("\"rank\":" + std::to_string(ranked) + ",") != std::string::npos);
    assert(api.body.find("\"rank\":" + std::to_string(ranked + 1) + ",") == std::string::npos);
}

int main() {
    Blockchain chain;
    CheckPage(chain, 0);
    std::vector<UTXO> outputs;
    for (uint8_t id = 1; id <= 70; ++id)
        outputs.push_back(Insert(chain, AddressScript(id), (1000 - id) * VELD_UNITS));
    std::vector<UTXO> system;
    for (const auto& address : {VAULT_ADDRESS, STAKE_VAULT_ADDRESS, BOND_YIELD_ESCROW,
                               POOL_ADDRESS, ENDORSEMENT_POOL_ADDRESS})
        system.push_back(Insert(chain, AddressToScript(address), 10000 * VELD_UNITS));

    // Regression: five system entries in a capped top 50 used to report only 45.
    CheckPage(chain, 70);
#ifndef VELD_HOLDER_BASELINE_TEST
    const auto summary = chain.GetHolderSummary();
    assert(summary.non_system_count == 70);
    assert(summary.top_holders.size() == 50);
    assert(chain.GetTopHolders() == summary.top_holders);
    assert(chain.GetHolderSummary(1).non_system_count == 70);
    assert(chain.GetHolderSummary(0).non_system_count == 70);
    assert(chain.GetHolderSummary(0).top_holders.empty());
    assert(chain.GetTopHolders(1000).size() == 70);
    for (size_t i = 1; i < summary.top_holders.size(); ++i)
        assert(summary.top_holders[i - 1].second >= summary.top_holders[i].second);
#endif

    // Additional outputs do not create another holder; zero and non-address
    // scripts do not count or displace valid addresses from the ranking.
    const auto duplicate = Insert(chain, AddressScript(70), VELD_UNITS);
    Insert(chain, AddressScript(71), 0);
    Insert(chain, {0x51}, 1000000 * VELD_UNITS);
    CheckPage(chain, 70);
#ifndef VELD_HOLDER_BASELINE_TEST
    assert(chain.GetTopHolders(1000).size() == 70);
#endif

    DestinationCommitment384 digest{};
    digest[0] = 1;
    Insert(chain, BuildSha384KeyScript(digest), 1);
    CheckPage(chain, 71); // One base unit, below the visible ranking, still counts.

    // A system balance moving below the cutoff must not change the total.
    for (auto output : system) {
        assert(chain.TestEraseUTXO(output.tx_hash, output.output_index));
        output.value = 1;
        chain.TestInjectUTXO(output);
    }
    CheckPage(chain, 71);
    assert(chain.TestEraseUTXO(outputs.back().tx_hash, outputs.back().output_index));
    CheckPage(chain, 71); // Another output still funds that address.
    assert(chain.TestEraseUTXO(duplicate.tx_hash, duplicate.output_index));
    CheckPage(chain, 70); // Fully spent addresses leave the current-holder count.
    chain.TestInjectUTXO(outputs.back());
    CheckPage(chain, 71); // Restoring the balance restores the holder.
    std::cout << "PASS: full holder count, bounded ranking, script types, balances and rendered page\n";
}
