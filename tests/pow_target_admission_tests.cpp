#include "../include/core/block.h"
#include "../include/core/pow_target.h"
#include "../include/mining/veldhash.h"
#define VELD_TEST_NMS_BRANCH_CONTEXT 1
#include "../include/consensus/nms.h"

#include <atomic>
#include <cstdint>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

#if !defined(VELD_MAINNET_POW)
#error "This regression must exercise the public-mainnet VeldHash dataset path"
#endif
#if !defined(VELD_TEST_DATASET_BYTES)
#error "Use a bounded non-public test dataset"
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

std::vector<uint8_t> HeaderWithBits(uint32_t bits) {
    veld::BlockHeader header;
    header.version = veld::PROTOCOL_VERSION;
    for (size_t i = 0; i < header.prev_block_hash.size(); ++i)
        header.prev_block_hash[i] = static_cast<uint8_t>(i * 7U + 3U);
    for (size_t i = 0; i < header.merkle_root.size(); ++i)
        header.merkle_root[i] = static_cast<uint8_t>(i * 11U + 5U);
    header.timestamp = 1'788'134'400ULL;
    header.bits = bits;
    header.nonce = 9;
    return header.Serialize();
}

void ExpectError(uint32_t bits, veld::CompactTargetError expected,
                 const char* name) {
    veld::CanonicalPowTarget decoded;
    veld::CompactTargetError error = veld::CompactTargetError::None;
    Check(!veld::DecodeCanonicalVeldTarget(bits, decoded, &error) &&
              error == expected,
          name);
}

struct FakeNmsChain {
    veld::Hash256 parent{};
    uint64_t parent_height{0};
    uint32_t expected_bits{veld::GENESIS_BITS};

    std::optional<uint64_t> GetHeightByHashLocked(
            const veld::Hash256& hash) const {
        if (hash == parent) return parent_height;
        return std::nullopt;
    }
    uint32_t ComputeNextBitsAtLocked(uint64_t height) const {
        return height == parent_height ? expected_bits : 0;
    }
};

}  // namespace

int main() {
    using namespace veld;
    using namespace veld::mining;

    CanonicalPowTarget limit;
    Check(DecodeCanonicalVeldTarget(VELD_POW_LIMIT_BITS, limit) &&
              limit.bits == VELD_POW_LIMIT_BITS,
          "canonical 0x207fffff accepted");
    ExpectError(0x20ffffffu, CompactTargetError::Negative,
                "0x20ffffff alias rejected");
    ExpectError(0x1e800001u, CompactTargetError::Negative,
                "negative compact rejected");
    ExpectError(0x00000000u, CompactTargetError::Zero,
                "zero compact rejected");
    ExpectError(0x23000001u, CompactTargetError::Overflow,
                "overflow compact rejected");
    ExpectError(0x2100ffffu, CompactTargetError::AboveLimit,
                "above-limit compact rejected");
    ExpectError(0x1e000001u, CompactTargetError::NonCanonical,
                "noncanonical positive compact rejected");

    CanonicalPowTarget genesis_target;
    Check(DecodeCanonicalVeldTarget(GENESIS_BITS, genesis_target) &&
              btcspv::TargetToCompact(genesis_target.value) == GENESIS_BITS,
          "genesis/internal target round-trips canonically");
    CanonicalPowTarget internal_target;
    Check(DecodeExpectedVeldTarget(
              GENESIS_BITS, GENESIS_BITS, internal_target),
          "internal miner accepts exact canonical branch bits");
    Check(!DecodeExpectedVeldTarget(
              VELD_POW_LIMIT_BITS, GENESIS_BITS, internal_target),
          "internal miner refuses non-branch override");

    FakeNmsChain nms_chain;
    nms_chain.parent.fill(0x42);
    nms_chain.parent_height = 10;
    NmsRecord nms;
    nms.header.prev_block_hash = nms_chain.parent;
    nms.header.bits = GENESIS_BITS;
    nms.raw = EncodeNmsPayload(nms.header);
    Check(ValidateNms(nms, nms_chain, 11),
          "NMS accepts exact next-block canonical parent");
    Check(!ValidateNms(nms, nms_chain, 12),
          "NMS rejects historical-parent dataset rotation");
    nms.header.bits = 0x20ffffffu;
    nms.raw = EncodeNmsPayload(nms.header);
    Check(!ValidateNms(nms, nms_chain, 11),
          "NMS rejects compact alias before work");
    nms.header.bits = GENESIS_BITS;
    nms.raw = EncodeNmsPayload(nms.header);
    ExpensivePowBudget nms_defer_budget(
        1, 1, std::chrono::minutes(1));
    auto consume_nms_start = nms_defer_budget.TryAcquire(
        ExpensivePowUse::PeerNms);
    consume_nms_start.reset();
    bool nms_deferred = false;
    Check(!ValidateNms(
              nms, nms_chain, 11, &nms_defer_budget,
              &nms_deferred, ExpensivePowUse::PeerNms) &&
              nms_deferred,
          "NMS budget refusal is deferred local work, not invalid consensus");
    Check(ValidateNmsWithDisposition(
              nms, nms_chain, 11, &nms_defer_budget,
              ExpensivePowUse::PeerNms) ==
              NmsValidationDisposition::DeferredLocalWork,
          "NMS disposition preserves transient local-work refusal");
    nms.header.bits = 0x20ffffffu;
    nms.raw = EncodeNmsPayload(nms.header);
    Check(ValidateNmsWithDisposition(nms, nms_chain, 11) ==
              NmsValidationDisposition::ConsensusInvalid,
          "NMS disposition preserves consensus-invalid target alias");
    nms.header.bits = GENESIS_BITS;
    nms.raw = EncodeNmsPayload(nms.header);

    // Reproduce the exact alias sequence from the finding. Only the canonical
    // expected identity reaches the cache; attacker-selected sign-bit aliases
    // return before a dataset request or regeneration.
    auto before_alias = GlobalDataset().Stats();
    Hash256 seed = ComputeEpochSeed(
        limit.bytes, DATASET_EPOCH_BLOCKS + 1, limit);
    for (int i = 0; i < 8; ++i) {
        {
            DatasetHandle held = GlobalDataset().get_for_seed(seed);
            Check(held.get() != nullptr,
                  "canonical alternating request obtains dataset");
        }
        auto before_bad = GlobalDataset().Stats();
        Hash256 rejected = VeldHash(HeaderWithBits(0x20ffffffu),
                                    DATASET_EPOCH_BLOCKS + 1);
        auto after_bad = GlobalDataset().Stats();
        bool sentinel = true;
        for (uint8_t byte : rejected) sentinel &= byte == 0xff;
        Check(sentinel && !g_veldhash_last_dataset_ok(),
              "alias rejected before hashing");
        Check(after_bad.requests == before_bad.requests &&
                  after_bad.builds == before_bad.builds,
              "rejected alias generates no dataset work");
    }
    auto after_alias = GlobalDataset().Stats();
    Check(after_alias.builds == before_alias.builds + 1,
          "alternating valid/alias sequence builds one identity");

    // Identical concurrent cache misses are serialized behind one builder.
    DatasetCache isolated_cache;
    Hash256 concurrent_seed{};
    for (size_t i = 0; i < concurrent_seed.size(); ++i)
        concurrent_seed[i] = static_cast<uint8_t>(0xa5U ^ i);
    std::atomic<bool> go{false};
    std::atomic<unsigned> ready{0};
    std::atomic<unsigned> obtained{0};
    std::vector<std::thread> workers;
    for (unsigned i = 0; i < 8; ++i) {
        workers.emplace_back([&]() {
            ready.fetch_add(1, std::memory_order_release);
            while (!go.load(std::memory_order_acquire))
                std::this_thread::yield();
            DatasetHandle held = isolated_cache.get_for_seed(concurrent_seed);
            if (held.get()) obtained.fetch_add(1, std::memory_order_relaxed);
        });
    }
    while (ready.load(std::memory_order_acquire) != workers.size())
        std::this_thread::yield();
    go.store(true, std::memory_order_release);
    for (auto& worker : workers) worker.join();
    const auto singleflight = isolated_cache.Stats();
    Check(obtained.load() == workers.size(),
          "all concurrent identical requests obtain dataset");
    Check(singleflight.builds == 1 && singleflight.hits == workers.size() - 1,
          "concurrent identical requests perform one dataset build");
    Check(DatasetCache::CapacityIdentities() == 1,
          "dataset identity cache is bounded");

    ExpensivePowBudget peer_budget(1);
    auto peer_first = peer_budget.TryAcquire(ExpensivePowUse::PeerBlock);
    auto peer_second = peer_budget.TryAcquire(ExpensivePowUse::PeerBlock);
    Check(peer_first.has_value() && !peer_second.has_value(),
          "peer expensive-PoW budget fails closed");
    peer_first.reset();
    Check(peer_budget.TryAcquire(ExpensivePowUse::PeerBlock).has_value(),
          "peer expensive-PoW budget releases through RAII");

    ExpensivePowBudget rate_budget(
        1, 2, std::chrono::minutes(1));
    auto rate_one = rate_budget.TryAcquire(ExpensivePowUse::PeerNms);
    rate_one.reset();
    auto rate_two = rate_budget.TryAcquire(ExpensivePowUse::PeerBlock);
    rate_two.reset();
    auto rate_three = rate_budget.TryAcquire(ExpensivePowUse::PeerNms);
    Check(!rate_three.has_value(),
          "sequential external work budget fails closed");
    Check(rate_budget.TryAcquire(
              ExpensivePowUse::InternalMine).has_value(),
          "external rate exhaustion preserves internal mining lane");

    auto owned_source_budget = std::make_shared<ExpensivePowBudget>(1, 2);
    std::weak_ptr<ExpensivePowBudget> retained_source = owned_source_budget;
    auto peer_context = PowAdmissionContext::Peer(
        "2001:db8::17", owned_source_budget);
    owned_source_budget.reset();
    Check(peer_context.HasRequiredProvenance() &&
              !retained_source.expired(),
          "peer admission context owns source budget lifetime");
    Check(peer_context.InitialUse() == ExpensivePowUse::PeerBlock &&
              peer_context.ReorgUse() == ExpensivePowUse::PeerReorg &&
              peer_context.NmsUse() == ExpensivePowUse::PeerNms,
          "peer context preserves external classification on every path");
    Check(PowAdmissionContext::Rpc("submitblock").ReorgUse() ==
              ExpensivePowUse::RpcReorg,
          "RPC reorg remains globally external");
    Check(PowAdmissionContext::Internal().ReorgUse() ==
              ExpensivePowUse::InternalReorg,
          "internal reorg has an explicit non-peer classification");
    Check(!PowAdmissionContext::Peer("", retained_source.lock())
               .HasRequiredProvenance() &&
              !PowAdmissionContext::Peer("198.51.100.7", {})
               .HasRequiredProvenance(),
          "missing peer identity or owning budget fails closed");
    Check(!PowAdmissionContext{}.HasRequiredProvenance(),
          "default PoW admission context is explicitly unwired");

    ExpensivePowBudget reorg_rate_budget(
        1, 1, std::chrono::minutes(1));
    auto peer_reorg = reorg_rate_budget.TryAcquire(
        ExpensivePowUse::PeerReorg);
    Check(peer_reorg.has_value(),
          "first peer reorg enters external budget");
    peer_reorg.reset();
    Check(!reorg_rate_budget.TryAcquire(
              ExpensivePowUse::RpcReorg).has_value(),
          "peer and RPC reorg share the external rate envelope");
    Check(reorg_rate_budget.TryAcquire(
              ExpensivePowUse::InternalReorg).has_value(),
          "external reorg exhaustion preserves internal recovery lane");

    auto global_first = GlobalExpensivePowBudget().TryAcquire(
        ExpensivePowUse::PeerBlock);
    auto global_second = GlobalExpensivePowBudget().TryAcquire(
        ExpensivePowUse::InternalMine);
    auto global_third = GlobalExpensivePowBudget().TryAcquire(
        ExpensivePowUse::RpcSubmit);
    Check(global_first.has_value() && global_second.has_value() &&
              !global_third.has_value(),
          "global expensive-PoW budget fails closed");

    if (failures == 0) {
        std::cout << "PASS checks=" << checks << "\n";
        return 0;
    }
    std::cerr << "FAIL checks=" << checks
              << " failures=" << failures << "\n";
    return 1;
}
