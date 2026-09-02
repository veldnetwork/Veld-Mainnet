#include "daybreak_regtest_profile.h"
#include "mining/preflight_selector.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using veld::Block;
using veld::HashToHex;
using veld::Transaction;
using veld::TxInput;
using veld::TxOutput;
using veld::mining::ConstructivePreflightSelection;
using veld::mining::MiningTxTouchesStatefulProtocol;
using veld::mining::SelectConstructivePreflightCandidate;

size_t g_checks = 0;

void Check(bool condition, const char* expression, int line) {
    ++g_checks;
    if (!condition) {
        throw std::runtime_error(
            std::string("check failed: ") + expression + " at line " +
            std::to_string(line));
    }
}

#define CHECK(expression) Check((expression), #expression, __LINE__)

std::vector<uint8_t> MarkerScript(const std::string& payload) {
    std::vector<uint8_t> script{0x6a};
    if (payload.size() <= 75) {
        script.push_back(static_cast<uint8_t>(payload.size()));
    } else if (payload.size() <= 255) {
        script.push_back(0x4c);
        script.push_back(static_cast<uint8_t>(payload.size()));
    } else if (payload.size() <= 65'535) {
        script.push_back(0x4d);
        script.push_back(static_cast<uint8_t>(payload.size() & 0xff));
        script.push_back(static_cast<uint8_t>((payload.size() >> 8) & 0xff));
    } else {
        throw std::runtime_error("test marker is too large");
    }
    script.insert(script.end(), payload.begin(), payload.end());
    return script;
}

Transaction MarkerTx(const std::string& payload, uint8_t identity) {
    Transaction tx;
    TxInput input;
    input.prev_tx_hash.fill(identity);
    input.prev_out_index = identity;
    input.script_sig = {identity};
    tx.inputs.push_back(input);
    tx.outputs.emplace_back(1, MarkerScript(payload));
    return tx;
}

Transaction OrdinaryTx(uint8_t identity) {
    Transaction tx;
    TxInput input;
    input.prev_tx_hash.fill(identity);
    input.prev_out_index = identity;
    input.script_sig = {identity};
    tx.inputs.push_back(input);
    tx.outputs.emplace_back(1, std::vector<uint8_t>{0x51, identity});
    return tx;
}

Transaction BuildCoinbase(uint64_t fees) {
    std::vector<std::pair<std::vector<uint8_t>, uint64_t>> outputs{
        {{0x51}, 5'000'000 + fees},
    };
    return Transaction::CreateProportionalCoinbase(outputs, "selector-test");
}

Block Skeleton() {
    Block block;
    block.height = 1474;
    block.header.version = 1;
    block.header.timestamp = 1;
    block.header.bits = 0x207fffff;
    return block;
}

std::filesystem::path FixturePath(const std::string& name) {
    const std::filesystem::path source(__FILE__);
    std::vector<std::filesystem::path> candidates{
        source.parent_path() / "fixtures" / name,
        std::filesystem::current_path() / "tests" / "fixtures" / name,
    };
    for (const auto& candidate : candidates) {
        if (std::filesystem::exists(candidate)) return candidate;
    }
    throw std::runtime_error("missing selector fixture: " + name);
}

Transaction LoadTransactionFixture(const std::string& name) {
    std::ifstream input(FixturePath(name), std::ios::binary);
    if (!input) throw std::runtime_error("failed to open fixture: " + name);
    std::ostringstream contents;
    contents << input.rdbuf();
    std::string hex = contents.str();
    hex.erase(std::remove_if(hex.begin(), hex.end(), [](unsigned char c) {
        return std::isspace(c) != 0;
    }), hex.end());
    const std::vector<uint8_t> bytes = veld::HexToBytes(hex);
    if (bytes.empty() || bytes.size() * 2 != hex.size())
        throw std::runtime_error("malformed fixture hex: " + name);
    Transaction tx;
    const size_t consumed = Transaction::Deserialize(bytes, 0, tx);
    if (consumed != bytes.size() || tx.Serialize() != bytes)
        throw std::runtime_error("noncanonical transaction fixture: " + name);
    return tx;
}

std::string Txid(const Transaction& tx) {
    return HashToHex(tx.GetTxID());
}

bool Contains(const Block& block, const std::string& txid) {
    for (size_t i = 1; i < block.transactions.size(); ++i) {
        if (Txid(block.transactions[i]) == txid) return true;
    }
    return false;
}

std::vector<std::string> NonCoinbaseTxids(const Block& block) {
    std::vector<std::string> result;
    for (size_t i = 1; i < block.transactions.size(); ++i)
        result.push_back(Txid(block.transactions[i]));
    return result;
}

void ExactPreservedThreeCandidateRegression() {
    static const std::string kA =
        "31e1c78033356d7c79e245078930cd7c55d0b6a754914212492a140e56b9714d";
    static const std::string kB =
        "9b5dffb85cd0ed57463e2dd102350de541574832eadced3f73806299ca299d31";
    static const std::string kC =
        "fd65154ba4c5134762ee833d3318f68cb2cbedaefa519b741524e510fc4e8370";

    const Transaction a = LoadTransactionFixture(
        "rsv_rtp1_inclusion_01_A.hex");
    const Transaction b = LoadTransactionFixture(
        "rsv_rtp1_inclusion_01_B.hex");
    const Transaction c = LoadTransactionFixture(
        "rsv_rtp1_inclusion_01_C.hex");
    CHECK(Txid(a) == kA);
    CHECK(Txid(b) == kB);
    CHECK(Txid(c) == kC);
    CHECK(MiningTxTouchesStatefulProtocol(a));
    CHECK(MiningTxTouchesStatefulProtocol(b));
    CHECK(MiningTxTouchesStatefulProtocol(c));

    const Transaction payment = OrdinaryTx(0x71);
    const Transaction mandatory = OrdinaryTx(0x72);
    const std::string payment_id = Txid(payment);
    const std::string mandatory_id = Txid(mandatory);
    const std::vector<std::pair<Transaction, uint64_t>> ordered{
        {a, 100'000}, {b, 100'000}, {c, 100'000}, {payment, 700},
    };
    const std::vector<Transaction> mandatory_txs{mandatory};
    std::vector<std::vector<uint8_t>> before;
    for (const auto& entry : ordered) before.push_back(entry.first.Serialize());

    size_t mandatory_observations = 0;
    auto preflight = [&](const Block& block) {
        CHECK(!block.transactions.empty());
        CHECK(Txid(block.transactions.back()) == mandatory_id);
        ++mandatory_observations;
        return !Contains(block, kA) && !Contains(block, kB);
    };

    ConstructivePreflightSelection selected =
        SelectConstructivePreflightCandidate(
            Skeleton(), ordered, mandatory_txs, BuildCoinbase, preflight);

    CHECK(selected.success);
    CHECK(selected.used_fallback);
    CHECK(selected.preflight_calls == 5);
    CHECK(mandatory_observations == selected.preflight_calls);
    CHECK(selected.retained_mempool.size() == 4);
    CHECK(!selected.retained_mempool[0]);
    CHECK(!selected.retained_mempool[1]);
    CHECK(selected.retained_mempool[2]);
    CHECK(selected.retained_mempool[3]);
    CHECK(!Contains(selected.candidate, kA));
    CHECK(!Contains(selected.candidate, kB));
    CHECK(Contains(selected.candidate, kC));
    CHECK(Contains(selected.candidate, payment_id));
    CHECK(selected.retained_fees == 100'700);
    CHECK(selected.candidate.transactions.front().TotalOutput() ==
          5'100'700);
    CHECK(NonCoinbaseTxids(selected.candidate) ==
          std::vector<std::string>({kC, payment_id, mandatory_id}));
    CHECK(preflight(selected.candidate));

    for (size_t i = 0; i < ordered.size(); ++i)
        CHECK(ordered[i].first.Serialize() == before[i]);
}

void PriorityAndProtocolCases() {
    const Transaction invalid_high =
        MarkerTx("VELD_FRAUD|stale-fsp2", 0x10);
    const Transaction valid_low =
        MarkerTx("VELD_RSV1|valid-rtp1", 0x11);
    const std::string invalid_high_id = Txid(invalid_high);
    const std::string valid_low_id = Txid(valid_low);
    std::vector<std::pair<Transaction, uint64_t>> ordered{
        {invalid_high, 900}, {valid_low, 100},
    };
    const std::vector<Transaction> no_mandatory;
    auto selected = SelectConstructivePreflightCandidate(
        Skeleton(), ordered, no_mandatory, BuildCoinbase,
        [&](const Block& block) { return !Contains(block, invalid_high_id); });
    CHECK(selected.success);
    CHECK(!Contains(selected.candidate, invalid_high_id));
    CHECK(Contains(selected.candidate, valid_low_id));
    CHECK(selected.retained_fees == 100);

    const Transaction first = MarkerTx("VELD_RSV1|first", 0x20);
    const Transaction second = MarkerTx("VELD_RSV1|second", 0x21);
    const std::string first_id = Txid(first);
    const std::string second_id = Txid(second);
    ordered = {{first, 500}, {second, 400}};
    selected = SelectConstructivePreflightCandidate(
        Skeleton(), ordered, no_mandatory, BuildCoinbase,
        [&](const Block& block) {
            return !(Contains(block, first_id) && Contains(block, second_id));
        });
    CHECK(selected.success);
    CHECK(Contains(selected.candidate, first_id));
    CHECK(!Contains(selected.candidate, second_id));

    // Mempool policy has already put the valid AMM request first. The shared
    // selector must honor that order rather than assigning a second priority.
    const Transaction amm = MarkerTx("VELD_AMM|valid", 0x30);
    const Transaction rtp = MarkerTx("VELD_RSV1|rollover", 0x31);
    const std::string amm_id = Txid(amm);
    const std::string rtp_id = Txid(rtp);
    ordered = {{amm, 10}, {rtp, 1'000}};
    selected = SelectConstructivePreflightCandidate(
        Skeleton(), ordered, no_mandatory, BuildCoinbase,
        [&](const Block& block) {
            return !(Contains(block, amm_id) && Contains(block, rtp_id));
        });
    CHECK(selected.success);
    CHECK(Contains(selected.candidate, amm_id));
    CHECK(!Contains(selected.candidate, rtp_id));

    const Transaction invalid_amm = MarkerTx("VELD_AMM|stale", 0x32);
    const std::string invalid_amm_id = Txid(invalid_amm);
    ordered = {{invalid_amm, 2'000}, {rtp, 1'000}};
    selected = SelectConstructivePreflightCandidate(
        Skeleton(), ordered, no_mandatory, BuildCoinbase,
        [&](const Block& block) {
            return !Contains(block, invalid_amm_id);
        });
    CHECK(selected.success);
    CHECK(!Contains(selected.candidate, invalid_amm_id));
    CHECK(Contains(selected.candidate, rtp_id));

    // StableDependencyOrderBtcHeaderTransactions runs before this helper. Its
    // parent-before-child order must survive both construction and preflight.
    const Transaction parent = MarkerTx("VELD_BHDR|parent", 0x40);
    const Transaction child = MarkerTx("VELD_BHDR|child", 0x41);
    const std::string parent_id = Txid(parent);
    const std::string child_id = Txid(child);
    ordered = {{parent, 10}, {child, 20}};
    selected = SelectConstructivePreflightCandidate(
        Skeleton(), ordered, no_mandatory, BuildCoinbase,
        [&](const Block& block) {
            return NonCoinbaseTxids(block) ==
                std::vector<std::string>({parent_id, child_id});
        });
    CHECK(selected.success);
    CHECK(!selected.used_fallback);
    CHECK(selected.preflight_calls == 1);

    // Preserve the complete-set fast path for mutually enabling operations
    // such as a TOKEN mint followed by a same-block AMM add.
    const Transaction mint = MarkerTx("VELD_TOKEN|mint", 0x42);
    const Transaction add = MarkerTx("VELD_AMM|add", 0x43);
    const std::string mint_id = Txid(mint);
    const std::string add_id = Txid(add);
    ordered = {{mint, 30}, {add, 20}};
    selected = SelectConstructivePreflightCandidate(
        Skeleton(), ordered, no_mandatory, BuildCoinbase,
        [&](const Block& block) {
            return Contains(block, mint_id) == Contains(block, add_id);
        });
    CHECK(selected.success);
    CHECK(!selected.used_fallback);
    CHECK(selected.preflight_calls == 1);
    CHECK(NonCoinbaseTxids(selected.candidate) ==
          std::vector<std::string>({mint_id, add_id}));
}

void BaselineParityDeterminismAndBounds() {
    const Transaction ordinary = OrdinaryTx(0x50);
    const Transaction stateful = MarkerTx("VELD_RSV1|candidate", 0x51);
    const Transaction mandatory = OrdinaryTx(0x52);
    const std::string ordinary_id = Txid(ordinary);
    const std::string stateful_id = Txid(stateful);
    const std::string mandatory_id = Txid(mandatory);
    const std::vector<std::pair<Transaction, uint64_t>> ordered{
        {ordinary, 7}, {stateful, 11},
    };
    const std::vector<Transaction> mandatory_txs{mandatory};

    auto baseline_failure = SelectConstructivePreflightCandidate(
        Skeleton(), ordered, mandatory_txs, BuildCoinbase,
        [&](const Block& block) { return !Contains(block, ordinary_id); });
    CHECK(!baseline_failure.success);
    CHECK(baseline_failure.used_fallback);
    CHECK(baseline_failure.preflight_calls == 2);
    CHECK(baseline_failure.error ==
          "non-stateful/mandatory baseline failed module preflight");
    CHECK(Contains(baseline_failure.candidate, ordinary_id));
    CHECK(!Contains(baseline_failure.candidate, stateful_id));
    CHECK(Contains(baseline_failure.candidate, mandatory_id));

    int modeled_consensus_state = 73;
    auto restoring_preflight = [&](const Block& block) {
        const int snapshot = modeled_consensus_state;
        ++modeled_consensus_state;
        const bool valid = !Contains(block, stateful_id);
        modeled_consensus_state = snapshot;
        return valid;
    };
    // This is the shared-helper determinism check. The production MineOnly
    // and getblocktemplate wrappers are exercised separately by the required
    // real-process gate with the same preserved transactions.
    auto first_selection = SelectConstructivePreflightCandidate(
        Skeleton(), ordered, mandatory_txs, BuildCoinbase,
        restoring_preflight);
    auto second_selection = SelectConstructivePreflightCandidate(
        Skeleton(), ordered, mandatory_txs, BuildCoinbase,
        restoring_preflight);
    CHECK(first_selection.success);
    CHECK(second_selection.success);
    CHECK(modeled_consensus_state == 73);
    CHECK(first_selection.candidate.Serialize() ==
          second_selection.candidate.Serialize());
    CHECK(first_selection.retained_fees ==
          second_selection.retained_fees);
    CHECK(first_selection.retained_mempool ==
          second_selection.retained_mempool);
    CHECK(first_selection.preflight_calls ==
          second_selection.preflight_calls);
    CHECK(first_selection.preflight_calls == 3); // 2 + one stateful request

    auto repeat = SelectConstructivePreflightCandidate(
        Skeleton(), ordered, mandatory_txs, BuildCoinbase,
        restoring_preflight);
    CHECK(repeat.candidate.Serialize() ==
          first_selection.candidate.Serialize());
    CHECK(repeat.retained_mempool ==
          first_selection.retained_mempool);

    size_t full_calls = 0;
    auto fast = SelectConstructivePreflightCandidate(
        Skeleton(), ordered, mandatory_txs, BuildCoinbase,
        [&](const Block&) { ++full_calls; return true; });
    CHECK(fast.success);
    CHECK(!fast.used_fallback);
    CHECK(full_calls == 1);
    CHECK(fast.preflight_calls == 1);
    CHECK(fast.retained_fees == 18);
    CHECK(fast.candidate.transactions.front().TotalOutput() == 5'000'018);
    CHECK(NonCoinbaseTxids(fast.candidate) ==
          std::vector<std::string>({ordinary_id, stateful_id, mandatory_id}));

    const std::vector<std::pair<Transaction, uint64_t>> overflow{
        {ordinary, std::numeric_limits<uint64_t>::max()},
        {stateful, 1},
    };
    size_t overflow_calls = 0;
    auto overflow_result = SelectConstructivePreflightCandidate(
        Skeleton(), overflow, mandatory_txs, BuildCoinbase,
        [&](const Block&) { ++overflow_calls; return true; });
    CHECK(!overflow_result.success);
    CHECK(overflow_result.error == "mempool fee accounting overflow");
    CHECK(overflow_calls == 0);
    CHECK(overflow_result.preflight_calls == 0);
}

void SharedClassifierCases() {
    for (int family = 0; family < veld::kNumStatefulMarkerFamilies; ++family) {
        const std::string prefix = veld::kStatefulMarkerFamilies[family];
        CHECK(MiningTxTouchesStatefulProtocol(
            MarkerTx(prefix + "payload", static_cast<uint8_t>(0x80 + family))));
        CHECK(!MiningTxTouchesStatefulProtocol(
            MarkerTx("X" + prefix + "payload",
                     static_cast<uint8_t>(0xa0 + family))));
    }
    CHECK(!MiningTxTouchesStatefulProtocol(OrdinaryTx(0xf0)));
    CHECK(!MiningTxTouchesStatefulProtocol(
        MarkerTx("VELD_DIST|ordinary-distribution", 0xf2)));

    CHECK(MiningTxTouchesStatefulProtocol(
        MarkerTx("VELD_RSV1|" + std::string(80, 'a'), 0xf3)));
    CHECK(MiningTxTouchesStatefulProtocol(
        MarkerTx("VELD_RSV1|" + std::string(300, 'b'), 0xf4)));

    Transaction malformed = MarkerTx("VELD_RSV1|payload", 0xf1);
    malformed.outputs[0].script_pubkey[1] += 1;
    CHECK(!MiningTxTouchesStatefulProtocol(malformed));
}

} // namespace

int main() {
    try {
        ExactPreservedThreeCandidateRegression();
        PriorityAndProtocolCases();
        BaselineParityDeterminismAndBounds();
        SharedClassifierCases();
        std::cout << "PASS daybreak_mining_preflight_selector_tests checks="
                  << g_checks
                  << " exact_case=31e1c780,9b5dffb8,fd65154b"
                  << " fast_path_preflights=1 fallback_bound=2_plus_stateful"
                  << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL daybreak_mining_preflight_selector_tests: "
                  << error.what() << '\n';
        return 1;
    }
}
