#include "../include/node/work_admission_coordinator.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <future>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>

using namespace veld;
using namespace veld::work_admission;

namespace {

using Coordinator = AdmissionCoordinator;
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

Coordinator::Configuration Ready(const Coordinator& coordinator) {
    const uint64_t close_epoch_before = coordinator.ObserveCloseEpoch();
    Coordinator::Configuration configuration;
    auto& p = configuration.prerequisites;
    p.role_permitted = true;
    p.node_running = true;
    p.startup_replay_complete = true;
    p.independent_validation_complete = true;
    p.sync_complete = true;
    p.snapshot_state_clean = true;
    p.durable_state_proven = true;
    p.datadir_identity_valid = true;
    p.checkpoint_anchor_valid = true;
    p.canonical_tip_known = true;
    p.runtime_open = true;
    p.peer_view_safe = true;
    p.validation_generation = 71;
    p.network_magic = 0x56454c44u;
    p.genesis_hash = Filled(0x11);
    p.profile_digest = Filled(0x22);
    configuration.permitted_paths.fill(true);
    Coordinator::BindCloseEpochSnapshot(
        configuration, close_epoch_before, coordinator.ObserveCloseEpoch());
    return configuration;
}

Subject SubjectFor(Path path) {
    Subject subject;
    subject.parent_height = 80;
    subject.parent_hash = Filled(0x33);
    switch (path) {
        case Path::InternalMining:
        case Path::GetBlockTemplate:
        case Path::SubmitBlock:
        case Path::SynchronousGeneration:
            subject.purpose = Purpose::BlockProduction;
            subject.height = 81;
            break;
        case Path::ValidatorEndorsement:
            subject.purpose = Purpose::ValidatorEndorsement;
            subject.height = 60;
            subject.target_hash = Filled(0x44);
            break;
        case Path::FinalityVote:
            subject.purpose = Purpose::FinalityVote;
            subject.height = 40;
            subject.target_hash = Filled(0x55);
            break;
    }
    return subject;
}

Coordinator::TokenMintFn Mint() {
    auto next = std::make_shared<std::atomic<uint64_t>>(0);
    return [next](Coordinator::TokenBytes& token) {
        token.fill(0x6a);
        const uint64_t value = next->fetch_add(1) + 1;
        for (size_t i = 0; i < sizeof(value); ++i)
            token[i] = static_cast<uint8_t>(value >> (8U * i));
        return true;
    };
}

Coordinator::Limits Limits() {
    Coordinator::Limits limits;
    limits.max_local_lease = Coordinator::Duration{50};
    limits.max_remote_lease = Coordinator::Duration{80};
    limits.max_active_leases = 16;
    limits.max_spent_tokens = 32;
    return limits;
}

}  // namespace

int main() {
    // Every node-owned irreversible block sink uses this order in production:
    // transition sequencer -> lease claim -> commit/publication -> release.
    for (const Path path : {Path::InternalMining, Path::SubmitBlock,
                            Path::SynchronousGeneration}) {
        Coordinator coordinator(Limits(), Mint());
        Check(coordinator.Open(Ready(coordinator)).opened,
              "local sink fixture opened");
        std::mutex transition;
        std::promise<void> claimed_promise;
        auto claimed = claimed_promise.get_future().share();
        std::promise<void> release_promise;
        auto release = release_promise.get_future().share();
        std::atomic<bool> sink_effect{false};
        std::atomic<bool> state_flipped{false};

        std::thread sink([&] {
            std::lock_guard<std::mutex> guard(transition);
            auto attempt = coordinator.AcquireLocal(
                path, SubjectFor(path), std::nullopt, false,
                Coordinator::Duration{40});
            Check(attempt && attempt.lease->ClaimForSink(),
                  "local sink acquired and claimed");
            claimed_promise.set_value();
            release.wait();
            Check(attempt.lease->IsLive(),
                  "local sink remains live before bounded release");
            sink_effect.store(true, std::memory_order_release);
        });
        claimed.wait();
        const auto close = coordinator.BeginClose(Refusal::SyncIncomplete);
        Check(!close.fully_closed, "local sink predecessor makes close wait");
        std::thread transition_thread([&] {
            std::lock_guard<std::mutex> guard(transition);
            state_flipped.store(true, std::memory_order_release);
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        Check(!state_flipped.load(std::memory_order_acquire),
              "state cannot flip across claimed local sink");
        release_promise.set_value();
        sink.join();
        transition_thread.join();
        Check(sink_effect.load(std::memory_order_acquire) &&
                  state_flipped.load(std::memory_order_acquire),
              "local sink effect precedes state transition");
    }

    // A template is response-visible but not retained by the node. Holding the
    // same sequencer from final predicate check through serialization gives a
    // deterministic pre- or post-close response, never a half-bound template.
    {
        Coordinator coordinator(Limits(), Mint());
        Check(coordinator.Open(Ready(coordinator)).opened,
              "GBT fixture opened");
        std::mutex transition;
        std::promise<void> serializing_promise;
        auto serializing = serializing_promise.get_future().share();
        std::promise<void> publish_promise;
        auto publish = publish_promise.get_future().share();
        std::atomic<bool> response_visible{false};
        std::atomic<bool> state_flipped{false};
        std::thread gbt([&] {
            std::lock_guard<std::mutex> guard(transition);
            Check(Evaluate(SubjectFor(Path::GetBlockTemplate),
                           Ready(coordinator).prerequisites).allowed,
                  "GBT final predicate open");
            serializing_promise.set_value();
            publish.wait();
            response_visible.store(true, std::memory_order_release);
        });
        serializing.wait();
        std::thread closer([&] {
            std::lock_guard<std::mutex> guard(transition);
            coordinator.BeginClose(Refusal::SyncIncomplete);
            state_flipped.store(true, std::memory_order_release);
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        Check(!state_flipped.load(std::memory_order_acquire),
              "GBT serialization excludes state flip");
        publish_promise.set_value();
        gbt.join();
        closer.join();
        Check(response_visible.load(std::memory_order_acquire) &&
                  state_flipped.load(std::memory_order_acquire),
              "GBT response linearizes before close");
    }

    // Remote validators must consume the pending bearer into a node-held
    // active lease before either journal/sign path starts.
    for (const Path path : {Path::ValidatorEndorsement,
                            Path::FinalityVote}) {
        Coordinator coordinator(Limits(), Mint());
        Check(coordinator.Open(Ready(coordinator)).opened,
              "remote sink fixture opened");
        const Subject subject = SubjectFor(path);
        auto pending = coordinator.IssueRemoteSigningLease(
            path, subject, std::nullopt, false, Coordinator::Duration{60});
        Check(static_cast<bool>(pending), "pending remote grant issued");
        const auto close = coordinator.BeginClose(Refusal::PeerViewUnsafe);
        Check(!close.fully_closed, "pending remote grant owns predecessor slot");
        auto active = coordinator.ConsumeRemoteSigningLease(
            pending.grant->token, path, subject, pending.grant->binding);
        Check(active && active.lease->IsLive(),
              "remote begin-signing consumes grant during Closing");
        std::atomic<bool> journal{false}, signature{false}, gossip{false};
        Check(active.lease->IsLive(), "remote lease live before journal");
        journal.store(true, std::memory_order_release);
        Check(active.lease->IsLive(), "remote lease live before signature");
        signature.store(true, std::memory_order_release);
        Check(active.lease->ClaimForSink(), "remote sink claim succeeds once");
        gossip.store(active.lease->IsLive(), std::memory_order_release);
        active.lease->Release();
        Check(journal.load() && signature.load() && gossip.load(),
              "remote journal signature and sink share one lease");
        Check(coordinator.GetSnapshot().phase == Coordinator::Phase::Closed,
              "remote release completes waiting close");
    }

    // The operation deadline is strictly earlier than hard lease expiry. At
    // that cutoff a signer emits nothing, while the hard reservation still
    // prevents the prerequisite transition from flipping underneath it.
    {
        std::atomic<int64_t> now_ms{1000};
        Coordinator coordinator(
            Limits(), Mint(), [&] {
                return Coordinator::TimePoint(
                    Coordinator::Duration(now_ms.load()));
            });
        Check(coordinator.Open(Ready(coordinator)).opened,
              "over-deadline remote fixture opened");
        const Subject subject = SubjectFor(Path::FinalityVote);
        auto pending = coordinator.IssueRemoteSigningLease(
            Path::FinalityVote, subject, std::nullopt, false,
            Coordinator::Duration{60});
        auto active = coordinator.ConsumeRemoteSigningLease(
            pending.grant->token, Path::FinalityVote, subject,
            pending.grant->binding);
        Check(active && active.lease->deadline() ==
                  Coordinator::TimePoint(Coordinator::Duration{1060}),
              "hard remote deadline fixed");
        const auto operation_deadline =
            active.lease->deadline() - Coordinator::Duration{15};
        const auto close = coordinator.BeginClose(Refusal::SyncIncomplete);
        Check(!close.fully_closed, "over-deadline close waits hard lease");
        now_ms.store(1045);
        const bool operation_live =
            Coordinator::TimePoint(Coordinator::Duration{now_ms.load()}) <
                operation_deadline && active.lease->IsLive();
        std::atomic<uint64_t> signatures{0}, journals{0}, sinks{0};
        if (operation_live) {
            ++journals;
            ++signatures;
            if (active.lease->ClaimForSink()) ++sinks;
        }
        Check(!operation_live && journals.load() == 0 &&
                  signatures.load() == 0 && sinks.load() == 0,
              "operation cutoff emits no journal signature or sink effect");
        Check(coordinator.GetSnapshot().phase == Coordinator::Phase::Closing &&
                  active.lease->IsLive(),
              "hard safety margin still blocks transition");
        active.lease->Release();
        Check(coordinator.GetSnapshot().phase == Coordinator::Phase::Closed,
              "explicit over-deadline release closes promptly");
    }

    // Even if the coordinator's hard record expires while a claimed durable
    // callback runs, the production lock order keeps the state transition
    // behind the callback's consensus-transition guard.
    {
        std::atomic<int64_t> now_ms{2000};
        Coordinator coordinator(
            Limits(), Mint(), [&] {
                return Coordinator::TimePoint(
                    Coordinator::Duration(now_ms.load()));
            });
        Check(coordinator.Open(Ready(coordinator)).opened,
              "claimed overrun fixture opened");
        std::mutex transition;
        std::promise<void> claimed_promise;
        auto claimed = claimed_promise.get_future().share();
        std::promise<void> finish_promise;
        auto finish = finish_promise.get_future().share();
        std::atomic<bool> durable_effect{false};
        std::thread sink([&] {
            std::lock_guard<std::mutex> guard(transition);
            auto attempt = coordinator.AcquireLocal(
                Path::SubmitBlock, SubjectFor(Path::SubmitBlock),
                std::nullopt, false, Coordinator::Duration{20});
            Check(attempt && attempt.lease->ClaimForSink(),
                  "claimed overrun sink started");
            claimed_promise.set_value();
            finish.wait();
            durable_effect.store(true, std::memory_order_release);
        });
        claimed.wait();
        coordinator.BeginClose(Refusal::DurableStateUnproven);
        now_ms.store(2020);
        Check(coordinator.GetSnapshot().phase == Coordinator::Phase::Closed,
              "hard record expires at bounded deadline");
        auto transition_future = std::async(std::launch::async, [&] {
            std::lock_guard<std::mutex> guard(transition);
            return durable_effect.load(std::memory_order_acquire);
        });
        Check(transition_future.wait_for(std::chrono::milliseconds(10)) ==
                  std::future_status::timeout,
              "expired record cannot bypass claimed sink transition lock");
        finish_promise.set_value();
        sink.join();
        Check(transition_future.get(),
              "durable effect completes before state transition acquires lock");
    }

    std::cout << "PASS daybreak_work_admission_sink_race_tests checks="
              << checks << "\n";
    return 0;
}
