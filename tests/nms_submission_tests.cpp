#include "mining/nms_submission.h"
#include <atomic>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

int main() {
    using veld::mining::NmsSubmissionGate;
    const auto check = [](bool condition, const char* message) {
        if (!condition) throw std::runtime_error(message);
    };
    try {
        NmsSubmissionGate gate;
        // An ineligible miner at 4503 becomes eligible after staking at 4584.
        // Both belong to window 45; the failed attempt must not consume it.
        {
            auto failed = gate.TryBegin(4503 / 100);
            check(bool(failed), "first attempt blocked");
        }
        {
            auto retry = gate.TryBegin(4584 / 100);
            check(bool(retry), "failed eligibility check consumed the window");
            retry.CommitAccepted();
        }
        check(!gate.TryBegin(45), "accepted submission was counted twice");
        check(!gate.TryBegin(44), "older window bypassed the submission limit");
        bool began = false;
        try {
            auto failed = gate.TryBegin(46);
            began = bool(failed);
            throw std::runtime_error("simulated signing failure");
        } catch (const std::runtime_error&) {}
        check(began, "next window blocked");
        std::atomic<unsigned> accepted{0};
        std::atomic<unsigned> ready{0};
        std::atomic<bool> start{false};
        std::vector<std::thread> workers;
        for (unsigned i=0; i<32; ++i) {
            workers.emplace_back([&] {
                ready.fetch_add(1);
                while (!start.load()) std::this_thread::yield();
                auto attempt = gate.TryBegin(46);
                if (attempt) {
                    accepted.fetch_add(1);
                    attempt.CommitAccepted();
                }
            });
        }
        while (ready.load()!=32) std::this_thread::yield();
        start.store(true);
        for (auto& worker:workers) worker.join();
        check(accepted.load()==1, "concurrent submissions exceeded the window limit");
        auto next = gate.TryBegin(47);
        check(bool(next), "later window blocked");
        NmsSubmissionGate genesis;
        { auto zero=genesis.TryBegin(0); check(bool(zero), "window zero blocked"); zero.CommitAccepted(); }
        check(!genesis.TryBegin(0), "window zero has no duplicate protection");
        std::cout << "PASS failed eligibility and signing retries, 32 concurrent attempts, "
                     "one accepted submission per window and window-zero protection\n";
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
