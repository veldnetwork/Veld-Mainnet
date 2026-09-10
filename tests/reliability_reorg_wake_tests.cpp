#include "regtest_profile.h"
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_LOCAL_TEST_NETWORK 1
#include "node/node.h"
#include <future>
#include <iostream>

int main(int argc, char** argv) {
    using namespace veld;
    using namespace std::chrono_literals;
    if (argc != 2 || std::filesystem::exists(argv[1])) return 2;
    auto config = RegtestConfig(); config.port = 0;
    VeldNode node(config, argv[1]);
    node.SetQuietBoot(true);
    node.SetFullIbd(true);
    std::promise<void> predicate_checked, release_predicate, notify_attempted;
    auto checked = predicate_checked.get_future();
    auto release = release_predicate.get_future().share();
    auto notifying = notify_attempted.get_future();
    std::atomic<bool> announced{false};
    node.TestSetReorgWaitHooks([&] {
        predicate_checked.set_value();
        release.wait();
    }, [&] {
        if (!announced.exchange(true)) notify_attempted.set_value();
    });
    node.Start();
    if (checked.wait_for(2s) != std::future_status::ready) {
        release_predicate.set_value();
        node.Stop();
        node.TestSetReorgWaitHooks({}, {});
        return 3;
    }
    auto stopped = std::async(std::launch::async, [&] { node.Stop(); });
    if (notifying.wait_for(2s) != std::future_status::ready) {
        release_predicate.set_value();
        node.TestNotifyReorg();
        stopped.get();
        node.TestSetReorgWaitHooks({}, {});
        return 4;
    }
    std::this_thread::sleep_for(100ms);
    release_predicate.set_value();
    const bool completed = stopped.wait_for(2s) == std::future_status::ready;
    if (!completed) node.TestNotifyReorg();
    stopped.get();
    node.TestSetReorgWaitHooks({}, {});
    if (!completed) {
        std::cerr << "FAIL: reorg worker lost the shutdown notification\n";
        return 1;
    }
    std::cout << "PASS: shutdown wakes the reorg worker across the predicate-to-wait boundary\n";
}
