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
    node.Start();
    std::promise<void> predicate_checked, release_predicate, notify_attempted;
    auto checked=predicate_checked.get_future();
    auto release=release_predicate.get_future().share();
    auto notifying=notify_attempted.get_future();
    std::atomic<bool> announced{false};
    node.TestSetPrewarmWaitHooks([&] {
        predicate_checked.set_value();
        release.wait();
    }, [&] {
        if (!announced.exchange(true)) notify_attempted.set_value();
    });
    node.PrewarmHashDataset();
    if (checked.wait_for(2s)!=std::future_status::ready) {
        release_predicate.set_value();
        node.Stop();
        node.TestSetPrewarmWaitHooks({}, {});
        return 3;
    }
    auto stopped=std::async(std::launch::async, [&] { node.Stop(); });
    if (notifying.wait_for(2s)!=std::future_status::ready) {
        release_predicate.set_value();
        node.TestNotifyPrewarm();
        stopped.get();
        node.TestSetPrewarmWaitHooks({}, {});
        return 4;
    }
    // Put shutdown's notification inside the old predicate-to-wait race.
    // A correct notifier waits for the predicate mutex before sending it.
    std::this_thread::sleep_for(100ms);
    release_predicate.set_value();
    const bool completed=stopped.wait_for(2s)==std::future_status::ready;
    if (!completed) node.TestNotifyPrewarm(); // release the negative control
    stopped.get();
    node.TestSetPrewarmWaitHooks({}, {});
    if (!completed) {
        std::cerr << "FAIL: prewarm lost the shutdown notification\n";
        return 1;
    }
    std::cout << "PASS: shutdown wakes prewarm across the predicate-to-wait boundary\n";
}
