#ifndef VELD_TEST_HOOKS
#error "local-work ticket tests require VELD_TEST_HOOKS"
#endif
#if defined(VELD_PUBLIC_RELEASE) || defined(VELD_PUBLIC_MAINNET)
#error "local-work ticket tests must never compile in a public profile"
#endif

#define VELD_TEST_DATASET_BYTES (1024u * 1024u)
#include "daybreak_regtest_profile.h"
#include "../include/node/node.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace veld;

namespace {

size_t checks = 0;

void Check(bool condition, const char* label) {
    ++checks;
    if (!condition) {
        std::cerr << "FAIL: " << label << "\n";
        std::exit(1);
    }
}

Hash256 Filled(uint8_t value) {
    Hash256 out{};
    out.fill(value);
    return out;
}

void InstallGenesis(Blockchain& chain) {
    Check(chain.AddBlockDirect(
              CreateGenesisBlock(), true, true, false,
              mining::PowAdmissionContext::Internal()).IsAccepted(),
          "fixture genesis accepted");
}

Block SolvedHeightOne(Blockchain& chain, Mempool& mempool) {
    const RealKeyPair miner = GenerateKeyPair(false);
    auto solved = MineOnly(chain, mempool, miner);
    Check(solved.success && solved.block.height == 1,
          "fixture height-one candidate solved");
    return solved.block;
}

struct Snapshot {
    uint64_t height{0};
    Hash256 tip{};
    uint64_t supply{0};
    Hash256 utxo{};
};

Snapshot Observe(const Blockchain& chain) {
    return Snapshot{chain.Height(), chain.TipCopy().GetHash(),
                    chain.TotalSupplyUnits(), chain.UtxoDigest()};
}

bool Same(const Snapshot& a, const Snapshot& b) {
    return a.height == b.height && a.tip == b.tip &&
           a.supply == b.supply && a.utxo == b.utxo;
}

struct TicketControl {
    std::atomic<bool> live{true};
    std::atomic<bool> claimed{false};
    std::atomic<uint64_t> claim_calls{0};
};

struct TicketIdentity {
    uint64_t validation_generation{17};
    uint64_t coordinator_generation{23};
    uint32_t network_magic{MAINNET_MAGIC};
    Hash256 genesis_hash{CreateGenesisBlock().GetHash()};
    Hash256 profile_digest{Hash256d(std::string(DEPLOYMENT_PROFILE_ID))};
};

using TicketMutation =
    std::function<void(Blockchain::LocalWorkAdmissionTicket&)>;

Blockchain::LocalWorkAdmissionTicket MakeTicket(
        const Block& block,
        const mining::PowAdmissionContext& context,
        const std::shared_ptr<TicketControl>& control,
        const TicketIdentity& identity,
        TicketMutation mutate = {}) {
    Blockchain::LocalWorkAdmissionTicket ticket;
    ticket.owner = control;
    ticket.claim_for_canonical_commit =
        [control, identity](uint64_t coordinator_generation,
                            uint64_t validation_generation,
                            uint32_t network_magic,
                            const Hash256& genesis_hash,
                            const Hash256& profile_digest) {
            control->claim_calls.fetch_add(1, std::memory_order_acq_rel);
            if (!control->live.load(std::memory_order_acquire) ||
                coordinator_generation != identity.coordinator_generation ||
                validation_generation != identity.validation_generation ||
                network_magic != identity.network_magic ||
                genesis_hash != identity.genesis_hash ||
                profile_digest != identity.profile_digest)
                return false;
            return !control->claimed.exchange(
                true, std::memory_order_acq_rel);
        };
    ticket.live = [control] {
        return control->live.load(std::memory_order_acquire);
    };
    ticket.candidate_hash = block.GetHash();
    ticket.candidate_height = 1;
    ticket.parent_hash = block.header.prev_block_hash;
    ticket.source = context.local_work_kind;
    ticket.work_binding = context.work_binding;
    ticket.work_identity = context.local_work_kind ==
            mining::LocalWorkKind::SubmitBlock
        ? block.header.GetTemplateWorkIdentity() : ZeroHash();
    ticket.validation_generation = identity.validation_generation;
    ticket.coordinator_generation = identity.coordinator_generation;
    ticket.network_magic = identity.network_magic;
    ticket.genesis_hash = identity.genesis_hash;
    ticket.profile_digest = identity.profile_digest;
    ticket.deadline = std::chrono::steady_clock::now() +
                      std::chrono::seconds(10);
    if (mutate) mutate(ticket);
    return ticket;
}

void RunRefusal(const char* label, TicketMutation mutate,
                bool starts_live = true, bool starts_claimed = false,
                bool expect_claim = false) {
    Blockchain chain;
    Mempool mempool;
    InstallGenesis(chain);
    Block candidate = SolvedHeightOne(chain, mempool);
    const Snapshot before = Observe(chain);
    auto context = mining::PowAdmissionContext::InternalMiningWork(
        std::string("ticket-refusal-") + label);
    auto control = std::make_shared<TicketControl>();
    control->live.store(starts_live, std::memory_order_release);
    control->claimed.store(starts_claimed, std::memory_order_release);
    const TicketIdentity identity;
    chain.SetLocalWorkAdmissionPrepareFn(
        [control, identity, mutate](
                const Block& block,
                const mining::PowAdmissionContext& prepared_context)
            -> std::optional<Blockchain::LocalWorkAdmissionTicket> {
            return MakeTicket(
                block, prepared_context, control, identity, mutate);
        });
    const auto result = chain.AddBlockDirect(
        candidate, false, false, false, context);
    Check(result.IsDeferred(), label);
    Check(Same(before, Observe(chain)),
          "ticket refusal leaves canonical supply and UTXO state unchanged");
    Check(mempool.IsEmpty(),
          "ticket refusal leaves mempool unchanged");
    Check(control->claim_calls.load(std::memory_order_acquire) ==
              (expect_claim ? 1U : 0U),
          "ticket refusal occurs at its expected preclaim or claim boundary");
    Check(!context.local_work_handoff->IsLive(),
          "refused ticket leaves no live post-commit handoff");
}

}  // namespace

int main() {
    RunRefusal("candidate hash mismatch", [](auto& ticket) {
        ticket.candidate_hash = Filled(0x31);
    });
    RunRefusal("candidate parent mismatch", [](auto& ticket) {
        ticket.parent_hash = Filled(0x32);
    });
    RunRefusal("work binding mismatch", [](auto& ticket) {
        ticket.work_binding += "-altered";
    });
    RunRefusal("work source mismatch", [](auto& ticket) {
        ticket.source = mining::LocalWorkKind::SynchronousGeneration;
    });
    RunRefusal("internal work identity mismatch", [](auto& ticket) {
        ticket.work_identity = Filled(0x33);
    });
    RunRefusal("expired ticket", [](auto& ticket) {
        ticket.deadline = std::chrono::steady_clock::now() -
                          std::chrono::milliseconds(1);
    });
    RunRefusal("shutdown canceled ticket", {}, false);
    RunRefusal("reused ticket", {}, true, true, true);
    RunRefusal("validation generation mismatch", [](auto& ticket) {
        ++ticket.validation_generation;
    }, true, false, true);
    RunRefusal("coordinator generation mismatch", [](auto& ticket) {
        ++ticket.coordinator_generation;
    }, true, false, true);
    RunRefusal("network identity mismatch", [](auto& ticket) {
        ++ticket.network_magic;
    }, true, false, true);
    RunRefusal("genesis identity mismatch", [](auto& ticket) {
        ticket.genesis_hash = Filled(0x34);
    }, true, false, true);
    RunRefusal("profile identity mismatch", [](auto& ticket) {
        ticket.profile_digest = Filled(0x35);
    }, true, false, true);

    {
        Blockchain chain;
        Mempool mempool;
        InstallGenesis(chain);
        Block candidate = SolvedHeightOne(chain, mempool);
        const Snapshot before = Observe(chain);
        auto context = mining::PowAdmissionContext::InternalMiningWork(
            "ticket-prepare-exception");
        chain.SetLocalWorkAdmissionPrepareFn(
            [](const Block&, const mining::PowAdmissionContext&)
                -> std::optional<Blockchain::LocalWorkAdmissionTicket> {
                throw std::runtime_error("injected preparation failure");
            });
        const auto result = chain.AddBlockDirect(
            candidate, false, false, false, context);
        Check(result.IsDeferred() && Same(before, Observe(chain)) &&
                  mempool.IsEmpty(),
              "preparation exception fails closed with zero mutation");
    }

    {
        Blockchain chain;
        Mempool mempool;
        InstallGenesis(chain);
        Block candidate = SolvedHeightOne(chain, mempool);
        auto context = mining::PowAdmissionContext::InternalMiningWork(
            "ticket-claim-exception");
        auto control = std::make_shared<TicketControl>();
        const TicketIdentity identity;
        chain.SetLocalWorkAdmissionPrepareFn(
            [control, identity](
                    const Block& block,
                    const mining::PowAdmissionContext& prepared_context)
                -> std::optional<Blockchain::LocalWorkAdmissionTicket> {
                auto ticket = MakeTicket(
                    block, prepared_context, control, identity);
                ticket.claim_for_canonical_commit =
                    [](uint64_t, uint64_t, uint32_t,
                       const Hash256&, const Hash256&) -> bool {
                        throw std::runtime_error("injected claim failure");
                    };
                return ticket;
            });
        const Snapshot before = Observe(chain);
        const auto result = chain.AddBlockDirect(
            candidate, false, false, false, context);
        Check(result.IsDeferred() && Same(before, Observe(chain)),
              "claim exception fails closed with zero mutation");
    }

    {
        Blockchain chain;
        Mempool mempool;
        InstallGenesis(chain);
        Block local = SolvedHeightOne(chain, mempool);
        Block competing = SolvedHeightOne(chain, mempool);
        Check(local.GetHash() != competing.GetHash(),
              "tip-change candidates are distinct");
        auto context = mining::PowAdmissionContext::InternalMiningWork(
            "ticket-tip-change");
        auto control = std::make_shared<TicketControl>();
        const TicketIdentity identity;
        bool competitor_committed = false;
        chain.SetLocalWorkAdmissionPrepareFn(
            [&](const Block& block,
                const mining::PowAdmissionContext& prepared_context)
                -> std::optional<Blockchain::LocalWorkAdmissionTicket> {
                competitor_committed = chain.AddBlockDirect(
                    competing, false, false, false,
                    mining::PowAdmissionContext::Internal()).IsAccepted();
                return MakeTicket(
                    block, prepared_context, control, identity);
            });
        const auto result = chain.AddBlockDirect(
            local, false, false, false, context);
        Check(competitor_committed && result.IsDeferred(),
              "canonical tip change between prepare and claim refuses local work");
        Check(chain.Height() == 1 &&
                  chain.TipCopy().GetHash() == competing.GetHash() &&
                  !chain.IsCanonicalBlock(local.GetHash()) &&
                  control->claim_calls.load() == 0,
              "tip-change refusal preserves only the independently committed tip");
    }

    {
        Blockchain chain;
        Mempool mempool;
        InstallGenesis(chain);
        Block first = SolvedHeightOne(chain, mempool);
        Block second = SolvedHeightOne(chain, mempool);
        Check(first.GetHash() != second.GetHash(),
              "simultaneous candidates are distinct");
        std::mutex barrier_mutex;
        std::condition_variable barrier_cv;
        size_t prepared = 0;
        bool release = false;
        std::atomic<uint64_t> claims{0};
        const TicketIdentity identity;
        chain.SetLocalWorkAdmissionPrepareFn(
            [&](const Block& block,
                const mining::PowAdmissionContext& prepared_context)
                -> std::optional<Blockchain::LocalWorkAdmissionTicket> {
                auto control = std::make_shared<TicketControl>();
                auto ticket = MakeTicket(
                    block, prepared_context, control, identity);
                ticket.claim_for_canonical_commit =
                    [control, identity, &claims](
                            uint64_t coordinator_generation,
                            uint64_t validation_generation,
                            uint32_t network_magic,
                            const Hash256& genesis_hash,
                            const Hash256& profile_digest) {
                        if (coordinator_generation !=
                                identity.coordinator_generation ||
                            validation_generation !=
                                identity.validation_generation ||
                            network_magic != identity.network_magic ||
                            genesis_hash != identity.genesis_hash ||
                            profile_digest != identity.profile_digest ||
                            control->claimed.exchange(true))
                            return false;
                        claims.fetch_add(1);
                        return true;
                    };
                {
                    std::unique_lock<std::mutex> lock(barrier_mutex);
                    ++prepared;
                    barrier_cv.notify_all();
                    barrier_cv.wait(lock, [&] { return release; });
                }
                return ticket;
            });
        auto first_context = mining::PowAdmissionContext::InternalMiningWork(
            "ticket-simultaneous-first");
        auto second_context = mining::PowAdmissionContext::InternalMiningWork(
            "ticket-simultaneous-second");
        Blockchain::BlockAdmissionResult first_result(false);
        Blockchain::BlockAdmissionResult second_result(false);
        std::thread first_thread([&] {
            first_result = chain.AddBlockDirect(
                first, false, false, false, first_context);
        });
        std::thread second_thread([&] {
            second_result = chain.AddBlockDirect(
                second, false, false, false, second_context);
        });
        {
            std::unique_lock<std::mutex> lock(barrier_mutex);
            Check(barrier_cv.wait_for(
                      lock, std::chrono::seconds(3),
                      [&] { return prepared == 2; }),
                  "both simultaneous tickets prepare before either claim");
            release = true;
            barrier_cv.notify_all();
        }
        first_thread.join();
        second_thread.join();
        Check(first_result.IsAccepted() != second_result.IsAccepted(),
              "simultaneous local blocks commit exactly one winner");
        Check(chain.Height() == 1 && claims.load() == 1,
              "simultaneous tickets consume exactly one canonical claim");
        first_context.local_work_handoff->Reset();
        second_context.local_work_handoff->Reset();
    }

    {
        Blockchain chain;
        Mempool mempool;
        InstallGenesis(chain);
        Block candidate = SolvedHeightOne(chain, mempool);
        const Snapshot before = Observe(chain);
        std::mutex pending_mutex;
        std::condition_variable pending_cv;
        bool entered = false;
        bool release = false;
        auto control = std::make_shared<TicketControl>();
        const TicketIdentity identity;
        chain.SetLocalWorkAdmissionPrepareFn(
            [&](const Block& block,
                const mining::PowAdmissionContext& prepared_context)
                -> std::optional<Blockchain::LocalWorkAdmissionTicket> {
                {
                    std::unique_lock<std::mutex> lock(pending_mutex);
                    entered = true;
                    pending_cv.notify_all();
                    pending_cv.wait(lock, [&] { return release; });
                }
                return MakeTicket(
                    block, prepared_context, control, identity);
            });
        auto context = mining::PowAdmissionContext::InternalMiningWork(
            "ticket-shutdown-pending");
        Blockchain::BlockAdmissionResult result(false);
        std::thread pending([&] {
            result = chain.AddBlockDirect(
                candidate, false, false, false, context);
        });
        {
            std::unique_lock<std::mutex> lock(pending_mutex);
            Check(pending_cv.wait_for(
                      lock, std::chrono::seconds(3), [&] { return entered; }),
                  "shutdown observes pending admission preparation");
            control->live.store(false, std::memory_order_release);
            release = true;
            pending_cv.notify_all();
        }
        pending.join();
        Check(result.IsDeferred() && Same(before, Observe(chain)) &&
                  !context.local_work_handoff->IsLive(),
              "shutdown cancellation releases pending admission without hang");
    }

    std::cout << "PASS daybreak_local_work_ticket_tests checks="
              << checks
              << " mismatch=13 exceptions=2 tip_change=1 simultaneous=1"
                 " shutdown=1 zero_mutation=1\n";
    return 0;
}
