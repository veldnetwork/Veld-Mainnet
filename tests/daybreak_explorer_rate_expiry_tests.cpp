#ifndef VELD_TEST_HOOKS
#error "daybreak_explorer_rate_expiry_tests requires VELD_TEST_HOOKS"
#endif

#include "network/explorer.h"

#include <cstdlib>
#include <iostream>
#include <string>

int main() {
    size_t checks = 0;
    auto check = [&](bool value) {
        ++checks;
        if (!value) {
            std::cerr << "check " << checks << " failed\n";
            std::exit(1);
        }
    };

    veld::Blockchain chain;
    veld::Mempool mempool;
    veld::explorer::BlockExplorer explorer(chain, mempool);

    using State = veld::explorer::BlockExplorer::TestExplorerRateSlotState;
    const auto state = [&](const std::string& identity,
                           const std::string& bucket) -> State {
        return explorer.TestExplorerRateSlot(identity, bucket);
    };
    const auto take = [&](const std::string& identity,
                          const std::string& bucket,
                          uint64_t amount, uint64_t limit,
                          uint32_t seconds, uint64_t now_s) {
        return explorer.TestExplorerTakeChargeAt(
            identity, bucket, amount, limit, seconds, now_s);
    };
    const auto client_identity = [&](size_t ordinal) {
        const std::string raw = "10."
            + std::to_string((ordinal >> 16) & 0xff) + "."
            + std::to_string((ordinal >> 8) & 0xff) + "."
            + std::to_string(ordinal & 0xff);
        std::string canonical;
        check(veld::net::trusted_proxy::CanonicalIp(raw, canonical));
        check(canonical == raw);
        return "client:" + canonical;
    };

    constexpr size_t kMaximumKeyBytes = 73;
    check(explorer.TestExplorerRateMapMax() == 10000);
    std::string canonical;
    check(!veld::net::trusted_proxy::CanonicalIp(std::string(65, '1'), canonical));
    check(veld::net::trusted_proxy::CanonicalIp(
        "2001:0db8:0000:0000:0000:0000:0000:0001", canonical));
    check(canonical == "2001:db8::1");
    check(canonical.size() <= 45);

    // The live quota window resets at exactly window_start + seconds.
    const std::string logical = "client:192.0.2.1";
    check(take(logical, "client", 1, 1, 60, 100));
    check(state(logical, "client").present);
    check(state(logical, "client").window_start == 100);
    check(state(logical, "client").count == 1);
    check(!take(logical, "client", 1, 1, 60, 159));
    check(state(logical, "client").window_start == 100);
    check(state(logical, "client").count == 1);
    check(take(logical, "client", 1, 1, 60, 160));
    check(state(logical, "client").window_start == 160);
    check(state(logical, "client").count == 1);

    // Lazy pruning starts at half capacity. At the exact two-window expiry,
    // stale principals disappear while a longer-lived principal survives.
    explorer.TestExplorerClearRateSlots();
    const std::string client_bucket = "client";
    for (size_t i = 0; i < 4999; ++i)
        check(take(client_identity(i), client_bucket, 1, 60, 60, 100));
    const std::string live = "client:2001:db8::1";
    check(take(live, "route:address-page", 1, 60, 3600, 100));
    check(explorer.TestExplorerRateSlotCount() == 5000);
    check(state(client_identity(0), client_bucket).present);
    check(state(live, "route:address-page").present);

    const std::string boundary = "client:203.0.113.9";
    check(take(boundary, client_bucket, 1, 60, 60, 220));
    check(explorer.TestExplorerRateSlotCount() == 2);
    check(!state(client_identity(0), client_bucket).present);
    check(state(live, "route:address-page").present);
    check(state(boundary, client_bucket).present);

    // The aggregate map cannot exceed its fixed cap. Before the exact stale
    // boundary a new key fails closed, but an existing key can reset normally.
    explorer.TestExplorerClearRateSlots();
    const std::string route_bucket = "route:address-page";
    for (size_t i = 0; i < explorer.TestExplorerRateMapMax(); ++i)
        check(take(client_identity(i), route_bucket, 1, 2, 60, 100));
    check(explorer.TestExplorerRateSlotCount()
          == explorer.TestExplorerRateMapMax());
    size_t longest = 0;
    const size_t aggregate = explorer.TestExplorerRateKeyBytes(&longest);
    check(longest <= kMaximumKeyBytes);
    check(aggregate <= explorer.TestExplorerRateMapMax() * kMaximumKeyBytes);

    const std::string overflow = client_identity(
        explorer.TestExplorerRateMapMax());
    check(!take(overflow, route_bucket, 1, 2, 60, 219));
    check(explorer.TestExplorerRateSlotCount()
          == explorer.TestExplorerRateMapMax());
    check(!state(overflow, route_bucket).present);

    const std::string retained = client_identity(0);
    check(take(retained, route_bucket, 1, 2, 60, 219));
    check(state(retained, route_bucket).present);
    check(state(retained, route_bucket).window_start == 219);
    check(state(retained, route_bucket).count == 1);
    check(!take(overflow, route_bucket, 1, 2, 60, 219));
    check(explorer.TestExplorerRateSlotCount()
          == explorer.TestExplorerRateMapMax());

    check(take(overflow, route_bucket, 1, 2, 60, 220));
    check(explorer.TestExplorerRateSlotCount() == 2);
    check(state(retained, route_bucket).present);
    check(state(overflow, route_bucket).present);
    check(!state(client_identity(1), route_bucket).present);
    longest = 0;
    check(explorer.TestExplorerRateKeyBytes(&longest)
          <= 2 * kMaximumKeyBytes);
    check(longest <= kMaximumKeyBytes);

    std::cout << "PASS daybreak_explorer_rate_expiry_tests checks=" << checks
              << " exact_window_reset=1 exact_stale_prune=1"
              << " bounded_key_bytes=1 hard_cap="
              << explorer.TestExplorerRateMapMax() << "\n";
    return 0;
}
