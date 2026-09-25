#include "mining/nms_submission.h"
#include <atomic>
#include <iostream>
#include <map>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {
struct Chain {
    uint64_t tip{4584};
    std::map<unsigned, unsigned> credits;
    bool NmsNeedsSubmission(unsigned wallet, uint64_t parent) const {
        const auto found = credits.find(wallet);
        return parent == tip && (tip + 1) % 100 != 0 &&
               (found == credits.end() || found->second == 0);
    }
};
struct Pool {
    std::map<unsigned, uint64_t> pending;
    bool HasNmsSubmission(unsigned wallet, uint64_t parent) const {
        const auto found = pending.find(wallet);
        return found != pending.end() && found->second == parent;
    }
};
}

int main() {
    using namespace veld::mining;
    unsigned checks = 0;
    const auto check = [&](bool condition, const char* message) {
        ++checks;
        if (!condition)
            throw std::runtime_error(message);
    };
    try {
        Chain chain;
        Pool pool;
        NmsSubmissionGate gate;
        {
            auto failed = gate.TryBegin();
            check(bool(failed), "first attempt blocked");
        }
        {
            auto retry = gate.TryBegin();
            check(bool(retry), "failed signing consumed eligibility");
        }
        std::atomic<unsigned> accepted{0}, ready{0};
        std::atomic<bool> start{false};
        std::vector<std::thread> workers;
        for (unsigned i = 0; i < 32; ++i) {
            workers.emplace_back([&] {
                ready.fetch_add(1);
                while (!start.load())
                    std::this_thread::yield();
                auto attempt = gate.TryBegin();
                if (attempt && NeedsNmsSubmission(chain, pool, 1u, chain.tip)) {
                    pool.pending[1] = chain.tip;
                    accepted.fetch_add(1);
                }
            });
        }
        while (ready.load() != 32)
            std::this_thread::yield();
        start.store(true);
        for (auto& worker : workers)
            worker.join();
        check(accepted == 1, "concurrent workers submitted duplicate claims");
        check(!NeedsNmsSubmission(chain, pool, 1u, chain.tip), "pending claim duplicated");
        ++chain.tip;
        check(NeedsNmsSubmission(chain, pool, 1u, chain.tip),
              "unconfirmed expired claim consumed window");
        chain.credits[1] = 1;
        pool.pending.clear();
        NmsSubmissionGate restarted;
        {
            auto attempt = restarted.TryBegin();
            check(attempt && !NeedsNmsSubmission(chain, pool, 1u, chain.tip),
                  "restart forgot a confirmed entry");
        }
        check(NeedsNmsSubmission(chain, pool, 2u, chain.tip), "another wallet inherited an entry");
        chain.credits.clear();
        check(NeedsNmsSubmission(chain, pool, 1u, chain.tip),
              "disconnected entry blocked replacement");
        check(!NeedsNmsSubmission(chain, pool, 1u, chain.tip - 1), "stale parent submitted");
        chain.tip = 4599;
        check(!NeedsNmsSubmission(chain, pool, 1u, chain.tip),
              "payout-block claim would waste a fee");
        chain.tip = 4600;
        check(NeedsNmsSubmission(chain, pool, 1u, chain.tip), "new window blocked");
        check(!NmsTemplateRefreshNeeded(1, 1, 10000, 0, 4), "unchanged template refreshed");
        check(!NmsTemplateRefreshNeeded(1, 2, 4999, 0, 4), "refresh rate limit bypassed");
        check(NmsTemplateRefreshNeeded(1, 2, 5000, 0, 4), "new claim did not refresh template");
        check(!NmsTemplateRefreshNeeded(1, 2, 10000, 4, 4),
              "full claim slots needlessly refreshed");
        std::cout << "PASS nms_submission_tests checks=" << checks << '\n';
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
