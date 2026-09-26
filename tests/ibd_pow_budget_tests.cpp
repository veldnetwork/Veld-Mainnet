#include "mining/veldhash.h"
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <type_traits>

using namespace veld::mining;
using namespace std::chrono_literals;
static unsigned checks = 0;
static void Check(bool good, const char* message) {
    ++checks;
    if (!good)
        throw std::runtime_error(message);
}

int main() {
    static_assert(!std::is_copy_constructible_v<ExpensivePowCharge>);
    static_assert(!std::is_copy_assignable_v<ExpensivePowCharge>);
    ExpensivePowBudget source(1, 8, 1min);
    for (uint64_t height = 1; height <= 1000; ++height) {
        auto lease = source.TryAcquire(ExpensivePowUse::PeerBlock);
        Check(lease.has_value(), "validated forward history is not rate-stalled");
        auto charge = lease->TakeForwardCharge();
        Check(!source.TryAcquire(ExpensivePowUse::PeerBlock), "concurrency remains bounded");
        lease.reset();
        Check(source.Stats().in_flight == 0, "nested checks do not inherit a held slot");
        Check(charge.CreditValidatedForwardBlock(height), "exact charged proof credited");
        Check(!charge.CreditValidatedForwardBlock(height + 1), "receipt cannot be reused");
    }
    for (unsigned i = 0; i < 8; ++i) {
        auto lease = source.TryAcquire(ExpensivePowUse::PeerBlock);
        Check(lease.has_value(), "original unproductive work envelope remains");
        auto charge = lease->TakeForwardCharge();
        lease.reset();
        Check(!charge.CreditValidatedForwardBlock(1000 - i),
              "replay and reorg heights never refill");
    }
    Check(!source.TryAcquire(ExpensivePowUse::PeerBlock),
          "unproductive work exhausts eight-start limit");
    Check(source.TryAcquire(ExpensivePowUse::InternalMine).has_value(),
          "internal lane remains usable");

    for (const auto use : {ExpensivePowUse::PeerNms, ExpensivePowUse::PeerReorg,
                           ExpensivePowUse::RpcSubmit, ExpensivePowUse::RpcReorg}) {
        ExpensivePowBudget other(1, 1, 1min);
        auto lease = other.TryAcquire(use);
        Check(lease.has_value(), "external lane initial admission");
        auto charge = lease->TakeForwardCharge();
        lease.reset();
        Check(!charge.CreditValidatedForwardBlock(2000),
              "other external lanes cannot mint forward credit");
        Check(!other.TryAcquire(use), "other external lanes retain their original rate limit");
    }
    ExpensivePowBudget dropped(1, 1, 1min);
    {
        auto lease = dropped.TryAcquire(ExpensivePowUse::PeerBlock);
        auto charge = lease->TakeForwardCharge();
    }
    Check(!dropped.TryAcquire(ExpensivePowUse::PeerBlock),
          "failed validation and abandoned receipts stay charged");

    ExpensivePowBudget moving(1, 1, 1min);
    auto lease = moving.TryAcquire(ExpensivePowUse::PeerBlock);
    auto moved_lease = std::move(*lease);
    lease.reset();
    Check(!lease.has_value() && moving.Stats().in_flight == 1, "moving keeps one active slot");
    auto charge = moved_lease.TakeForwardCharge();
    Check(!moved_lease.TakeForwardCharge().CreditValidatedForwardBlock(1),
          "lease produces one receipt only");
    ExpensivePowCharge moved_charge(std::move(charge));
    Check(!charge.CreditValidatedForwardBlock(1), "moved receipt is inert");
    Check(moved_charge.CreditValidatedForwardBlock(1), "new receipt owner can credit");
    Check(!moving.TryAcquire(ExpensivePowUse::PeerBlock),
          "returning rate credit cannot release a held slot");
    moved_lease = {};
    Check(moving.TryAcquire(ExpensivePowUse::PeerBlock).has_value(),
          "slot and rate accounting remain independent");

    ExpensivePowBudget rolling(1, 1, 20ms);
    auto old = rolling.TryAcquire(ExpensivePowUse::PeerBlock);
    auto old_charge = old->TakeForwardCharge();
    old.reset();
    std::this_thread::sleep_for(30ms);
    auto fresh = rolling.TryAcquire(ExpensivePowUse::PeerBlock);
    Check(fresh.has_value(), "window renews normally");
    fresh.reset();
    Check(!old_charge.CreditValidatedForwardBlock(1), "old window cannot refund a new charge");
    Check(!rolling.TryAcquire(ExpensivePowUse::PeerBlock), "new window remains exhausted");

    static_assert(!std::is_copy_constructible_v<ExpensivePowProgress>);
    static_assert(!std::is_move_constructible_v<ExpensivePowProgress>);
    auto& shared = GlobalExpensivePowBudget();
    ExpensivePowProgress foreground, background;
    auto credit = [&](uint64_t height, ExpensivePowProgress& progress) {
        auto acquired = shared.TryAcquire(ExpensivePowUse::PeerBlock);
        Check(acquired.has_value(), "shared production budget admits valid history");
        auto charged = acquired->TakeForwardCharge();
        acquired.reset();
        Check(charged.CreditValidatedForwardBlock(height, progress),
              "each local chainstate credits its own committed forward progress");
        Check(!charged.CreditValidatedForwardBlock(height + 1, progress),
              "scoped receipt remains single use");
    };
    credit(11773, foreground);
    for (uint64_t height = 1; height <= 1000; ++height) {
        credit(height, background);
        if (height % 16 == 0)
            credit(11773 + height, foreground);
    }
    for (unsigned i = 0; i < 32; ++i) {
        auto acquired = shared.TryAcquire(ExpensivePowUse::PeerBlock);
        Check(acquired.has_value(), "original global non-progress allowance remains");
        auto charged = acquired->TakeForwardCharge();
        acquired.reset();
        Check(!charged.CreditValidatedForwardBlock(1000 - i, background),
              "same-chain replay and rollback cannot mint progress credit");
    }
    Check(!shared.TryAcquire(ExpensivePowUse::PeerBlock),
          "independent chainstates still share the original global rate limit");
    Check(shared.TryAcquire(ExpensivePowUse::InternalMine).has_value(),
          "background exhaustion does not consume the internal allowance");
    std::cout << "IBD_POW_BUDGET: PASS (" << checks << " checks)\n";
}
