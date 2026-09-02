#include "daybreak_regtest_profile.h"
#include "../include/node/node.h"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <unordered_map>
#include <string>
#include <thread>
#include <vector>

#if !defined(VELD_MAINNET_POW)
#error "This regression must exercise branch-local mainnet-v2 target rules"
#endif
#if !defined(VELD_TEST_CHAIN_BUILD) || !defined(VELD_TEST_DATASET_BYTES)
#error "Use only the bounded non-public fresh-chain test profile"
#endif

namespace {

int checks = 0;
int failures = 0;

void Check(bool condition, const char* name) {
    ++checks;
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << name << "\n";
    }
}

veld::RealKeyPair TestMiner(uint8_t tag) {
    veld::RealKeyPair out;
    out.script_override = {0x76, 0xa9, 0x14};
    for (uint8_t i = 0; i < 20; ++i)
        out.script_override.push_back(static_cast<uint8_t>(tag + i));
    out.script_override.push_back(0x88);
    out.script_override.push_back(0xac);
    return out;
}

void Init(veld::Blockchain& chain) {
    veld::Block genesis = veld::CreateGenesisBlock();
    if (!chain.AddBlockDirect(
            genesis, true, false, false,
            veld::mining::PowAdmissionContext::Internal()))
        throw std::runtime_error("test genesis rejected");
}

std::vector<veld::Block> MineFresh(uint8_t tag, size_t count) {
    veld::Blockchain chain;
    veld::Mempool mempool;
    Init(chain);
    const auto miner = TestMiner(tag);
    std::vector<veld::Block> out;
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        auto mined = veld::MineAndCommit(chain, mempool, miner);
        if (!mined.success)
            throw std::runtime_error("test mining failed: " + mined.error);
        out.push_back(mined.block);
    }
    return out;
}

}  // namespace

int main() {
    using namespace veld;
    using namespace veld::mining;

    Blockchain chain;
    Init(chain);
    Mempool main_mempool;
    const auto main_miner = TestMiner(0x21);
    for (size_t i = 0; i < 3; ++i) {
        auto mined = MineAndCommit(chain, main_mempool, main_miner);
        Check(mined.success, "main branch block mined and committed");
        if (!mined.success) return 1;
    }
    const Hash256 original_tip = chain.Tip().GetHash();
    const std::string original_tip_hex = HashToHex(original_tip);
    size_t published_reorg_blocks = 0;
    size_t durable_side_writes = 0;
    size_t peer_credit_events = 0;
    size_t relay_events = 0;
    size_t on_block_events = 0;
    std::unordered_map<std::string, std::vector<uint8_t>> durable_bodies;
    chain.SetDurableBlockBodyWriter(
        [&](const Hash256& hash, const std::vector<uint8_t>& raw) {
            ++durable_side_writes;
            durable_bodies[HashToHex(hash)] = raw;
            return true;
        });
    chain.SetHistoricalBlockLoader([&](const Hash256& hash)
            -> std::optional<std::vector<uint8_t>> {
        auto it = durable_bodies.find(HashToHex(hash));
        if (it == durable_bodies.end()) return std::nullopt;
        return it->second;
    });
    auto observe_peer_boundary = [&](const Blockchain::BlockAdmissionResult& r) {
        if (!r.IsAccepted()) return;
        ++peer_credit_events;
        ++relay_events;
        ++on_block_events;
    };
    chain.SetOnCommit(
        [&](const Block&,
            const std::vector<std::pair<Hash256, uint32_t>>&,
            const std::vector<UTXO>&, bool from_reorg) {
            if (from_reorg) ++published_reorg_blocks;
            return true;
        });

    // At equal work the smaller header hash wins. Select a deterministic test
    // fork whose height-3 hash loses the tie so only height 4 can trigger the
    // reorg under test.
    std::vector<Block> fork;
    bool found_losing_tie = false;
    for (uint16_t tag = 0x51; tag < 0xf0; ++tag) {
        auto candidate = MineFresh(static_cast<uint8_t>(tag), 4);
        if (HashToHex(candidate[2].GetHash()) > original_tip_hex) {
            fork = std::move(candidate);
            found_losing_tie = true;
            break;
        }
    }
    Check(found_losing_tie, "constructed side branch loses equal-work tie");
    if (!found_losing_tie) return 1;

    // Force a transient dataset refusal on the replay pass (after the ingress
    // hash succeeds). The body must remain volatile, unblacklisted and
    // retryable, with no durable side write before the successful retry.
    {
        Blockchain dataset_chain;
        Init(dataset_chain);
        Mempool dataset_mempool;
        const auto dataset_miner = TestMiner(0x31);
        for (size_t i = 0; i < 3; ++i) {
            auto mined = MineAndCommit(
                dataset_chain, dataset_mempool, dataset_miner);
            if (!mined.success)
                throw std::runtime_error("dataset fixture mining failed");
        }
        size_t dataset_writer_calls = 0;
        dataset_chain.SetDurableBlockBodyWriter(
            [&](const Hash256&, const std::vector<uint8_t>&) {
                ++dataset_writer_calls;
                return true;
            });
        Blockchain::TestForcePowDatasetUnavailableAfter(1);
        auto dataset_candidate = fork.front();
        const auto dataset_deferred = dataset_chain.AddBlockDirect(
            dataset_candidate, false, true, false,
            PowAdmissionContext::Internal());
        Check(dataset_deferred.IsDeferred() &&
                  Blockchain::GetLastRejectTag() ==
                      "pow_reorg_dataset_unavailable",
              "replay dataset refusal returns deferred tri-state");
        Check(dataset_chain.VolatileSideQuarantineCount() == 1 &&
                  dataset_chain.BadAltTipCount() == 0 &&
                  dataset_writer_calls == 0,
              "dataset-deferred side body stays volatile and unblacklisted");
        const Hash256 dataset_hash = dataset_candidate.GetHash();
        const std::string dataset_hash_hex = HashToHex(dataset_hash);
        bool deferred_tip_exposed = false;
        for (const auto& tip : dataset_chain.GetChainTips()) {
            if (tip.hash == dataset_hash) deferred_tip_exposed = true;
        }
        Check(!dataset_chain.GetBlockByHash(dataset_hash).has_value() &&
                  !dataset_chain.GetKnownBlockHeightByHash(
                      dataset_hash).has_value() &&
                  !dataset_chain.HasBlockAtHeight(
                      dataset_candidate.height, dataset_hash_hex) &&
                  !deferred_tip_exposed,
              "dataset-deferred body is absent from every public block height and tip view");
        const auto dataset_backoff = dataset_chain.AddBlockDirect(
            dataset_candidate, false, true, false,
            PowAdmissionContext::Internal());
        Check(dataset_backoff.IsDeferred() &&
                  Blockchain::GetLastRejectTag() == "reorg_retry_backoff" &&
                  dataset_writer_calls == 0,
              "dataset-deferred known retransmit observes bounded backoff");
        std::this_thread::sleep_for(std::chrono::milliseconds(1'100));
        const auto dataset_retry = dataset_chain.AddBlockDirect(
            dataset_candidate, false, true, false,
            PowAdmissionContext::Internal());
        Check(dataset_retry.IsAccepted() && dataset_writer_calls == 1 &&
                  dataset_chain.VolatileSideQuarantineCount() == 0 &&
                  dataset_chain.BadAltTipCount() == 0,
              "dataset-deferred side block retries and promotes exactly once");
        bool validated_tip_visible = false;
        for (const auto& tip : dataset_chain.GetChainTips()) {
            if (tip.hash == dataset_hash) validated_tip_visible = true;
        }
        Check(dataset_chain.GetBlockByHash(dataset_hash).has_value() &&
                  dataset_chain.GetKnownBlockHeightByHash(
                      dataset_hash).has_value() &&
                  dataset_chain.HasBlockAtHeight(
                      dataset_candidate.height, dataset_hash_hex) &&
                  validated_tip_visible,
              "fully validated side block becomes publicly retrievable after promotion");
    }

    constexpr auto retry_window = std::chrono::milliseconds(2'500);
    auto source_a = std::make_shared<ExpensivePowBudget>(1, 2, retry_window);
    auto source_b = std::make_shared<ExpensivePowBudget>(1, 5, retry_window);
    const auto context_a = PowAdmissionContext::Peer("198.51.100.10", source_a);
    const auto context_b = PowAdmissionContext::Peer("2001:db8::20", source_b);

    bool saw_deferred = false;
    for (size_t i = 0; i < fork.size(); ++i) {
        const auto& context = i == 0 ? context_a : context_b;
        const auto admission = chain.AddBlockDirect(
            fork[i], false, true, false, context);
        observe_peer_boundary(admission);
        if (admission.IsDeferred()) {
            const std::string tag = Blockchain::GetLastRejectTag();
            saw_deferred =
                tag == "pow_peer_reorg_budget_exhausted" ||
                tag == "pow_global_reorg_budget_exhausted" ||
                tag == "pow_reorg_dataset_unavailable";
        }
    }

    Check(saw_deferred, "winning side branch defers on local work budget");
    Check(chain.Tip().GetHash() == original_tip && chain.Height() == 3,
          "deferred reorg publishes no canonical state");
    Check(published_reorg_blocks == 0,
          "deferred reorg invokes no durable publication callback");
    Check(durable_side_writes == 3 &&
              peer_credit_events == 3 && relay_events == 3 &&
              on_block_events == 3,
          "only fully contextualized lower-work side blocks cross durable and peer effects");
    Check(chain.VolatileSideQuarantineCount() == 1,
          "unfinished side tip remains only in bounded volatile quarantine");
    Check(chain.BadAltTipCount() == 0,
          "deferred branch is not consensus-blacklisted");
    Check(chain.SideBranchHeaderCount() >= 4 &&
              chain.SideBranchPowAdmissionCount() >= 4,
          "bounded side branch retains owning per-block provenance");
    Check(chain.SideBranchReplayPowVerifiedCount() >= 2,
          "successful replay prefix is retained for bounded progress");

    const auto a_before_retry = source_a->Stats();
    const auto b_before_retry = source_b->Stats();
    auto source_c = std::make_shared<ExpensivePowBudget>(1, 8, retry_window);
    const auto context_c = PowAdmissionContext::Peer("203.0.113.30", source_c);
    const size_t effects_before_retry = durable_side_writes +
        peer_credit_events + relay_events + on_block_events;
    const auto immediate_retry = chain.AddBlockDirect(
        fork.back(), false, true, false, context_c);
    observe_peer_boundary(immediate_retry);
    Check(immediate_retry.IsDeferred() &&
              Blockchain::GetLastRejectTag() ==
                  "reorg_retry_backoff",
          "exact side-body retry is bounded before state rollback");
    Check(durable_side_writes + peer_credit_events + relay_events +
              on_block_events == effects_before_retry,
          "known deferred retransmit causes no writer credit relay or on-block effect");
    const auto a_after_retry = source_a->Stats();
    const auto b_after_retry = source_b->Stats();
    Check(a_after_retry.attempts == a_before_retry.attempts,
          "backoff avoids recharging cached source A");
    Check(b_after_retry.attempts == b_before_retry.attempts,
          "backoff avoids repeated unfinished-source work");
    Check(source_c->Stats().attempts == 0,
          "new trigger cannot shift stored work onto a different source");
    Check(chain.BadAltTipCount() == 0 &&
              chain.Tip().GetHash() == original_tip &&
              published_reorg_blocks == 0,
          "second transient refusal remains non-publishing and non-blacklisting");

    std::this_thread::sleep_for(std::chrono::milliseconds(1'100));
    const auto pre_refill_retry = chain.AddBlockDirect(
        fork.back(), false, true, false, context_c);
    observe_peer_boundary(pre_refill_retry);
    Check(pre_refill_retry.IsDeferred() &&
              Blockchain::GetLastRejectTag() ==
                  "pow_peer_reorg_budget_exhausted",
          "eligible retry resumes at unfinished original-source block");
    Check(source_a->Stats().attempts == a_before_retry.attempts,
          "verified prefix remains cached across eligible retry");
    Check(source_b->Stats().attempts == b_before_retry.attempts + 1,
          "eligible retry charges only unfinished original source");
    Check(durable_side_writes + peer_credit_events + relay_events +
              on_block_events == effects_before_retry,
          "eligible but budget-deferred retry remains externally invisible");

    std::this_thread::sleep_for(retry_window +
                                std::chrono::milliseconds(100));
    const auto completed = chain.AddBlockDirect(
        fork.back(), false, true, false, context_c);
    observe_peer_boundary(completed);
    Check(completed.IsAccepted(),
          "retained side branch succeeds after bounded refill");
    Check(chain.Height() == 4 &&
              chain.Tip().GetHash() == fork.back().GetHash(),
          "retry applies the exact higher-work branch");
    Check(published_reorg_blocks == fork.size(),
          "durable publication begins only after complete replay validation");
    Check(durable_side_writes == fork.size() - 1 &&
              peer_credit_events == fork.size() &&
              relay_events == fork.size() &&
              on_block_events == fork.size() &&
              chain.VolatileSideQuarantineCount() == 0,
          "winning volatile tip becomes canonical without a premature side-body write");
    Check(chain.BadAltTipCount() == 0,
          "successful retry leaves no false bad-tip residue");
    Check(source_c->Stats().attempts == 0,
          "completed retry still charges original per-block sources");
    Check(chain.SideBranchPowAdmissionCount() <=
              chain.SideBranchHeaderCount(),
          "admission provenance cardinality stays side-index bounded");

    const size_t effects_before_known = durable_side_writes +
        peer_credit_events + relay_events + on_block_events;
    const auto known_retransmit = chain.AddBlockDirect(
        fork.back(), false, true, false, context_c);
    observe_peer_boundary(known_retransmit);
    Check(!known_retransmit.IsAccepted() && !known_retransmit.IsDeferred() &&
              Blockchain::GetLastRejectTag() == "duplicate_block",
          "known fully validated retransmit is a non-accepted duplicate");
    Check(durable_side_writes + peer_credit_events + relay_events +
              on_block_events == effects_before_known,
          "known validated retransmit repeats no durable or P2P effect");

    if (failures == 0) {
        std::cout << "PASS checks=" << checks << "\n";
        return 0;
    }
    std::cerr << "FAIL checks=" << checks
              << " failures=" << failures << "\n";
    return 1;
}
