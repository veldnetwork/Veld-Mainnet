#include "../include/node/block_template_authorization.h"

#include <chrono>
#include <atomic>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <memory>
#include <future>
#include <new>
#include <stdexcept>
#include <string>
#include <thread>

using namespace veld;

namespace allocation_probe {
std::atomic<int> fail_next{0};
}

void* operator new(std::size_t size) {
    if (allocation_probe::fail_next.exchange(0, std::memory_order_acq_rel) != 0)
        throw std::bad_alloc();
    if (void* memory = std::malloc(size))
        return memory;
    throw std::bad_alloc();
}

void operator delete(void* memory) noexcept {
    std::free(memory);
}
void operator delete(void* memory, std::size_t) noexcept {
    std::free(memory);
}

void* operator new[](std::size_t size) {
    return ::operator new(size);
}
void operator delete[](void* memory) noexcept {
    ::operator delete(memory);
}
void operator delete[](void* memory, std::size_t size) noexcept {
    ::operator delete(memory, size);
}

namespace {

using Store = work_admission::BlockTemplateAuthorizationStore;
using Claim = work_admission::BlockTemplateAuthorizationClaim;

size_t checks = 0;

void Check(bool condition, const char* label) {
    ++checks;
    if (!condition)
        throw std::runtime_error(std::string("FAIL: ") + label);
}

Hash256 Filled(uint8_t value) {
    Hash256 hash{};
    hash.fill(value);
    return hash;
}

work_admission::Binding TemplateBinding(uint64_t generation = 17, uint8_t identity = 0x51) {
    work_admission::Binding binding;
    binding.subject.purpose = work_admission::Purpose::BlockProduction;
    binding.subject.height = 12;
    binding.subject.target_hash = Filled(identity);
    binding.subject.parent_height = 11;
    binding.subject.parent_hash = Filled(0x22);
    binding.validation_generation = generation;
    binding.network_magic = 0x56454c44;
    binding.genesis_hash = Filled(0x33);
    binding.profile_digest = Filled(0x44);
    return binding;
}

struct Fixture {
    Store::TimePoint now{Store::TimePoint{} + std::chrono::seconds(100)};
    uint64_t token_sequence{1};
    bool clock_throws{false};
    Store store;

    explicit Fixture(Store::Limits limits = Store::Limits{})
        : store(
              limits,
              [this](Store::TokenBytes& token) {
                  token.fill(0);
                  uint64_t value = token_sequence++;
                  for (size_t i = 0; i < sizeof(value); ++i)
                      token[i] = static_cast<uint8_t>(value >> (8U * i));
                  return true;
              },
              [this] {
                  if (clock_throws)
                      throw std::runtime_error("injected clock failure");
                  return now;
              }) {}
};

struct CopyReentryState {
    Store* store{nullptr};
    bool armed{false};
    std::atomic<size_t> reentries{0};
};

struct ReentrantCopyMint {
    std::shared_ptr<CopyReentryState> state;

    explicit ReentrantCopyMint(std::shared_ptr<CopyReentryState> value) : state(std::move(value)) {}
    ReentrantCopyMint(const ReentrantCopyMint& other) : state(other.state) {
        if (state && state->armed && state->store) {
            (void)state->store->GetSnapshot();
            state->reentries.fetch_add(1, std::memory_order_acq_rel);
        }
    }
    bool operator()(Store::TokenBytes& token) const {
        token.fill(0x6b);
        return true;
    }
};

struct ReentrantCopyClock {
    std::shared_ptr<CopyReentryState> state;
    Store::TimePoint now{};

    ReentrantCopyClock(std::shared_ptr<CopyReentryState> value, Store::TimePoint current)
        : state(std::move(value)), now(current) {}
    ReentrantCopyClock(const ReentrantCopyClock& other) : state(other.state), now(other.now) {
        if (state && state->armed && state->store) {
            (void)state->store->GetSnapshot();
            state->reentries.fetch_add(1, std::memory_order_acq_rel);
        }
    }
    Store::TimePoint operator()() const {
        return now;
    }
};

} // namespace

int main() {
    try {
        Fixture fixture;
        const auto binding = TemplateBinding();
        auto issued = fixture.store.Issue(binding, 23, std::chrono::milliseconds(5000));
        Check(issued && issued.authorization && issued.authorization->token.size() == 64 &&
                  issued.authorization->binding == binding &&
                  issued.authorization->coordinator_generation == 23 &&
                  issued.authorization->ttl == std::chrono::milliseconds(5000) &&
                  fixture.store.GetSnapshot().active == 1,
              "exact bounded template authorization is issued");
        const std::string token = issued.authorization->token;

        auto wrong_binding = binding;
        wrong_binding.subject.target_hash = Filled(0x52);
        auto mismatch = fixture.store.Consume(token, wrong_binding, 23);
        Check(!mismatch && mismatch.error == Store::Error::BindingMismatch &&
                  fixture.store.GetSnapshot().active == 1,
              "caller-edited template identity does not burn authorization");

        std::string unknown_token(64, 'a');
        auto unknown = fixture.store.Consume(unknown_token, binding, 23);
        Check(!unknown && unknown.error == Store::Error::TokenUnknown &&
                  fixture.store.GetSnapshot().active == 1,
              "unknown random bearer fails without consuming issued record");

        auto wrong_epoch = fixture.store.Consume(token, binding, 24);
        Check(!wrong_epoch && wrong_epoch.error == Store::Error::BindingMismatch &&
                  fixture.store.GetSnapshot().active == 1,
              "coordinator-generation mismatch fails without mutation");

        auto consumed = fixture.store.Consume(token, binding, 23);
        Check(consumed && consumed.authorization && consumed.authorization->binding() == binding &&
                  consumed.authorization->coordinator_generation() == 23 &&
                  consumed.authorization->IsLive() && fixture.store.GetSnapshot().active == 0,
              "exact bearer atomically reserves immutable claim");
        auto replay = fixture.store.Consume(token, binding, 23);
        Check(!replay && replay.error == Store::Error::TokenConsumed,
              "reserved bearer replay is refused");
        Check(!consumed.authorization->ClaimForTicket(binding, 24) &&
                  consumed.authorization->IsLive(),
              "claim epoch mismatch does not consume private reservation");
        Check(consumed.authorization->ClaimForTicket(binding, 23) &&
                  consumed.authorization->IsClaimedAndLive() &&
                  !consumed.authorization->ClaimForTicket(binding, 23),
              "private reservation claims exactly once");

        Fixture concurrent;
        auto concurrent_issue =
            concurrent.store.Issue(TemplateBinding(27, 0x59), 29, std::chrono::milliseconds(1000));
        Check(concurrent_issue && concurrent_issue.authorization, "concurrent bearer issued");
        std::promise<void> consume_start_promise;
        auto consume_start = consume_start_promise.get_future().share();
        Store::ConsumeResult consume_a;
        Store::ConsumeResult consume_b;
        std::thread consumer_a([&] {
            consume_start.wait();
            consume_a = concurrent.store.Consume(concurrent_issue.authorization->token,
                                                 concurrent_issue.authorization->binding, 29);
        });
        std::thread consumer_b([&] {
            consume_start.wait();
            consume_b = concurrent.store.Consume(concurrent_issue.authorization->token,
                                                 concurrent_issue.authorization->binding, 29);
        });
        consume_start_promise.set_value();
        consumer_a.join();
        consumer_b.join();
        Check(static_cast<unsigned>(static_cast<bool>(consume_a)) +
                          static_cast<unsigned>(static_cast<bool>(consume_b)) ==
                      1 &&
                  concurrent.store.GetSnapshot().active == 0,
              "simultaneous bearer reservation has exactly one winner");
        const std::shared_ptr<Claim> shared_claim =
            consume_a ? consume_a.authorization : consume_b.authorization;
        std::promise<void> claim_start_promise;
        auto claim_start = claim_start_promise.get_future().share();
        std::atomic<unsigned> claim_winners{0};
        std::thread claimant_a([&] {
            claim_start.wait();
            if (shared_claim->ClaimForTicket(concurrent_issue.authorization->binding, 29))
                claim_winners.fetch_add(1, std::memory_order_acq_rel);
        });
        std::thread claimant_b([&] {
            claim_start.wait();
            if (shared_claim->ClaimForTicket(concurrent_issue.authorization->binding, 29))
                claim_winners.fetch_add(1, std::memory_order_acq_rel);
        });
        claim_start_promise.set_value();
        claimant_a.join();
        claimant_b.join();
        Check(claim_winners.load(std::memory_order_acquire) == 1,
              "simultaneous private claim has exactly one winner");

        auto expiring =
            fixture.store.Issue(TemplateBinding(17, 0x53), 23, std::chrono::milliseconds(5));
        Check(expiring && expiring.authorization, "short-lived authorization issued");
        const std::string expiring_token = expiring.authorization->token;
        auto expiring_claim =
            fixture.store.Consume(expiring_token, expiring.authorization->binding, 23);
        Check(expiring_claim && expiring_claim.authorization,
              "short-lived authorization reserved before expiry");
        fixture.now += std::chrono::milliseconds(5);
        Check(!expiring_claim.authorization->ClaimForTicket(expiring.authorization->binding, 23) &&
                  !expiring_claim.authorization->IsClaimedAndLive(),
              "claim fails at the exact absolute expiry boundary");

        auto clock_failure =
            fixture.store.Issue(TemplateBinding(17, 0x54), 23, std::chrono::milliseconds(100));
        Check(clock_failure && clock_failure.authorization,
              "clock-failure claim issued while clock is healthy");
        auto clock_claim = fixture.store.Consume(clock_failure.authorization->token,
                                                 clock_failure.authorization->binding, 23);
        Check(clock_claim && clock_claim.authorization,
              "clock-failure claim reserved while clock is healthy");
        fixture.clock_throws = true;
        Check(!clock_claim.authorization->ClaimForTicket(clock_failure.authorization->binding, 23),
              "injected clock exception fails claim closed");
        fixture.clock_throws = false;

        Fixture bounded(Store::Limits{std::chrono::milliseconds(1000), 2, 4});
        auto first =
            bounded.store.Issue(TemplateBinding(31, 0x61), 41, std::chrono::milliseconds(1000));
        auto second =
            bounded.store.Issue(TemplateBinding(31, 0x62), 41, std::chrono::milliseconds(1000));
        auto over_cap =
            bounded.store.Issue(TemplateBinding(31, 0x63), 41, std::chrono::milliseconds(1000));
        Check(first && second && !over_cap && over_cap.error == Store::Error::Capacity &&
                  bounded.store.GetSnapshot().active == 2,
              "active template authorization cardinality is bounded");
        auto released =
            bounded.store.Consume(first.authorization->token, first.authorization->binding, 41);
        auto after_release =
            bounded.store.Issue(TemplateBinding(31, 0x63), 41, std::chrono::milliseconds(1000));
        Check(released && after_release && bounded.store.GetSnapshot().active == 2,
              "capacity recovers after exact one-use reservation");
        bounded.store.CancelAll();
        Check(bounded.store.GetSnapshot().active == 0 &&
                  !bounded.store.Consume(first.authorization->token, first.authorization->binding,
                                         41),
              "shutdown cancellation retires every pending authorization");

        Fixture generations;
        auto old_generation =
            generations.store.Issue(TemplateBinding(51, 0x71), 61, std::chrono::milliseconds(1000));
        auto new_generation =
            generations.store.Issue(TemplateBinding(52, 0x72), 62, std::chrono::milliseconds(1000));
        Check(old_generation && new_generation && generations.store.GetSnapshot().active == 1 &&
                  !generations.store.Consume(old_generation.authorization->token,
                                             old_generation.authorization->binding, 61),
              "new authority epoch retires stale template records before cap");

        Store unwired;
        auto no_mint = unwired.Issue(TemplateBinding(), 23, std::chrono::milliseconds(10));
        Check(!no_mint && no_mint.error == Store::Error::TokenMintUnavailable,
              "missing production token mint fails closed");
        Store mint_failure(Store::Limits{}, [](Store::TokenBytes&) { return false; });
        auto failed_mint = mint_failure.Issue(TemplateBinding(), 23, std::chrono::milliseconds(10));
        Check(!failed_mint && failed_mint.error == Store::Error::TokenMintFailed,
              "failed production token mint fails closed");
        Store::TokenBytes collision_token{};
        collision_token.fill(0x7c);
        Store collisions(Store::Limits{}, [collision_token](Store::TokenBytes& token) {
            token = collision_token;
            return true;
        });
        auto collision_first =
            collisions.Issue(TemplateBinding(71, 0x73), 81, std::chrono::milliseconds(1000));
        auto collision_second =
            collisions.Issue(TemplateBinding(71, 0x74), 81, std::chrono::milliseconds(1000));
        Check(collision_first && !collision_second &&
                  collision_second.error == Store::Error::TokenCollision &&
                  collisions.GetSnapshot().active == 1,
              "all random-token collisions refuse without eviction");
        Check(
            !collisions.Consume(std::string(63, 'a'), collision_first.authorization->binding, 81) &&
                !collisions.Consume(std::string(64, 'A'), collision_first.authorization->binding,
                                    81) &&
                collisions.GetSnapshot().active == 1,
            "malformed and noncanonical bearer encodings fail closed");

        Store* reentrant_store = nullptr;
        bool reentered_clock = false;
        bool inside_clock = false;
        Store::TimePoint reentrant_now = Store::TimePoint{} + std::chrono::seconds(200);
        Store reentrant(
            Store::Limits{},
            [](Store::TokenBytes& token) {
                token.fill(0x5a);
                return true;
            },
            [&] {
                if (!inside_clock && reentrant_store) {
                    inside_clock = true;
                    (void)reentrant_store->GetSnapshot();
                    reentered_clock = true;
                    inside_clock = false;
                }
                return reentrant_now;
            });
        reentrant_store = &reentrant;
        auto reentrant_issue =
            reentrant.Issue(TemplateBinding(81, 0x79), 91, std::chrono::milliseconds(100));
        Check(reentrant_issue && reentered_clock && reentrant.GetSnapshot().active == 1,
              "injected clock may re-enter store without mutex deadlock");

        auto mint_copy_state = std::make_shared<CopyReentryState>();
        Store mint_copy_reentrant(Store::Limits{}, ReentrantCopyMint{mint_copy_state});
        mint_copy_state->store = &mint_copy_reentrant;
        mint_copy_state->armed = true;
        auto mint_copy_issue = mint_copy_reentrant.Issue(TemplateBinding(83, 0x7b), 93,
                                                         std::chrono::milliseconds(100));
        Check(mint_copy_issue && mint_copy_state->reentries.load(std::memory_order_acquire) > 0,
              "token-mint target copy may re-enter before store mutex");

        auto clock_copy_state = std::make_shared<CopyReentryState>();
        Store clock_copy_reentrant(
            Store::Limits{},
            [](Store::TokenBytes& token) {
                token.fill(0x6c);
                return true;
            },
            ReentrantCopyClock{clock_copy_state, Store::TimePoint{} + std::chrono::seconds(300)});
        clock_copy_state->store = &clock_copy_reentrant;
        clock_copy_state->armed = true;
        auto clock_copy_issue = clock_copy_reentrant.Issue(TemplateBinding(84, 0x7c), 94,
                                                           std::chrono::milliseconds(100));
        Check(clock_copy_issue && clock_copy_issue.authorization,
              "authorization issued for reentrant clock-copy test");
        auto clock_copy_claim = clock_copy_reentrant.Consume(
            clock_copy_issue.authorization->token, clock_copy_issue.authorization->binding, 94);
        Check(clock_copy_claim && clock_copy_state->reentries.load(std::memory_order_acquire) > 0,
              "clock target copy may re-enter before store mutex");

        Fixture allocation_safe;
        const auto allocation_binding = TemplateBinding(82, 0x7a);
        allocation_probe::fail_next.store(1, std::memory_order_release);
        auto issue_oom =
            allocation_safe.store.Issue(allocation_binding, 92, std::chrono::milliseconds(100));
        Check(!issue_oom && issue_oom.error == Store::Error::Capacity &&
                  allocation_safe.store.GetSnapshot().active == 0,
              "issuance allocation failure returns fail-closed without termination");
        auto allocation_issue =
            allocation_safe.store.Issue(allocation_binding, 92, std::chrono::milliseconds(100));
        Check(allocation_issue && allocation_issue.authorization,
              "authorization remains usable after issuance allocation failure");
        allocation_probe::fail_next.store(1, std::memory_order_release);
        auto consume_oom = allocation_safe.store.Consume(
            allocation_issue.authorization->token, allocation_issue.authorization->binding, 92);
        Check(!consume_oom && consume_oom.error == Store::Error::Capacity &&
                  allocation_safe.store.GetSnapshot().active == 1,
              "claim allocation failure returns fail-closed without consuming authority");
        Check(static_cast<bool>(
                  allocation_safe.store.Consume(allocation_issue.authorization->token,
                                                allocation_issue.authorization->binding, 92)),
              "authorization remains exactly consumable after allocation recovery");

        Fixture expiry_capacity(Store::Limits{std::chrono::milliseconds(5), 1, 2});
        auto capacity_expiring = expiry_capacity.store.Issue(TemplateBinding(91, 0x75), 101,
                                                             std::chrono::milliseconds(5));
        Check(capacity_expiring && !expiry_capacity.store.Issue(TemplateBinding(91, 0x76), 101,
                                                                std::chrono::milliseconds(5)),
              "full active set refuses N plus one without eviction");
        expiry_capacity.now += std::chrono::milliseconds(5);
        auto capacity_recovered = expiry_capacity.store.Issue(TemplateBinding(91, 0x76), 101,
                                                              std::chrono::milliseconds(5));
        Check(capacity_recovered && expiry_capacity.store.GetSnapshot().active == 1,
              "capacity recovers exactly at authorization expiry");

        std::cout << "PASS block_template_authorization_tests checks=" << checks
                  << " exact_issue=1 mismatch_no_burn=1 replay=1 expiry=1"
                     " clock_fail_closed=1 clock_reentrant=1 copy_reentrant=1"
                     " allocation_fail_closed=1"
                     " cap=1 shutdown=1 stale_epoch=1 concurrent_exactly_one=1"
                     " mint_failures=1 collision=1\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}
