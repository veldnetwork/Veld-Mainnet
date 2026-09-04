#include "../include/node/work_admission_coordinator.h"

#include <atomic>
#include <cstdlib>
#include <future>
#include <iostream>
#include <thread>

using namespace veld;
using namespace veld::work_admission;

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

AdmissionCoordinator::Configuration ReadyConfiguration(const AdmissionCoordinator& coordinator) {
    const uint64_t close_epoch_before = coordinator.ObserveCloseEpoch();
    AdmissionCoordinator::Configuration configuration;
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
    p.validation_generation = 29;
    p.network_magic = 0x56454c44u;
    p.genesis_hash = Filled(0x11);
    p.profile_digest = Filled(0x22);
    configuration.permitted_paths.fill(true);
    AdmissionCoordinator::BindCloseEpochSnapshot(configuration, close_epoch_before,
                                                 coordinator.ObserveCloseEpoch());
    return configuration;
}

Subject BlockSubject() {
    Subject subject;
    subject.purpose = Purpose::BlockProduction;
    subject.height = 8;
    subject.parent_height = 7;
    subject.parent_hash = Filled(0x33);
    return subject;
}

Subject FinalitySubject() {
    Subject subject;
    subject.purpose = Purpose::FinalityVote;
    subject.height = 6;
    subject.target_hash = Filled(0x44);
    subject.parent_height = 7;
    subject.parent_hash = Filled(0x33);
    return subject;
}

AdmissionCoordinator::TokenMintFn Mint() {
    auto counter = std::make_shared<std::atomic<uint64_t>>(0);
    return [counter](AdmissionCoordinator::TokenBytes& token) {
        const uint64_t value = counter->fetch_add(1) + 1;
        token.fill(0x5a);
        for (size_t i = 0; i < sizeof(value); ++i)
            token[i] = static_cast<uint8_t>(value >> (8U * i));
        return true;
    };
}

AdmissionCoordinator::Limits Limits() {
    AdmissionCoordinator::Limits limits;
    limits.max_local_lease = AdmissionCoordinator::Duration{25};
    limits.max_remote_lease = AdmissionCoordinator::Duration{50};
    limits.max_active_leases = 8;
    limits.max_spent_tokens = 16;
    return limits;
}

bool SameCoordinatorState(const AdmissionCoordinator::Snapshot& lhs,
                          const AdmissionCoordinator::Snapshot& rhs) {
    return lhs.phase == rhs.phase && lhs.configured == rhs.configured &&
           lhs.refusal == rhs.refusal && lhs.active_leases == rhs.active_leases &&
           lhs.pending_remote_tokens == rhs.pending_remote_tokens &&
           lhs.spent_remote_tokens == rhs.spent_remote_tokens &&
           lhs.close_deadline == rhs.close_deadline &&
           lhs.configuration_generation == rhs.configuration_generation &&
           lhs.close_epoch == rhs.close_epoch;
}

} // namespace

int main() {
    using Coordinator = AdmissionCoordinator;

    // close-wins: the close mutex transition is complete before acquisition
    // is permitted to run, so no valid lease or cached record can appear.
    {
        Coordinator coordinator(Limits(), Mint());
        Check(coordinator.Open(ReadyConfiguration(coordinator)).opened,
              "close-wins fixture opened");
        std::promise<void> closed_promise;
        std::shared_future<void> closed = closed_promise.get_future().share();
        Coordinator::CloseResult close_result;
        Coordinator::LocalAttempt acquire_result;
        std::thread closer([&] {
            close_result = coordinator.BeginClose(Refusal::SyncIncomplete);
            closed_promise.set_value();
        });
        std::thread acquirer([&] {
            closed.wait();
            acquire_result = coordinator.AcquireLocal(
                Path::SubmitBlock, BlockSubject(), std::nullopt, false, Coordinator::Duration{10});
        });
        closer.join();
        acquirer.join();
        Check(close_result.fully_closed, "close-wins transition has no predecessor lease");
        Check(!acquire_result && acquire_result.decision.refusal == Refusal::SyncIncomplete,
              "close-wins acquisition fails at closed state");
        Check(coordinator.GetSnapshot().active_leases == 0, "close-wins leaves no work artifact");
    }

    // Exact two-preparer regression for CAND-P8-PEER-REOPEN-01. T1 and T2
    // complete the same safe epoch snapshot; this fixture begins at T1's
    // post-peer-bound/pre-Acquire boundary (the NodeServer composition is in
    // peer_work_view_race_tests). A peer writer then fully closes
    // before waiting for the canonical transition. T2's delayed Open must not
    // reopen, and T1 must not acquire or reach any canonical sink.
    {
        Coordinator coordinator(Limits(), Mint());
        const auto before_unbound = coordinator.GetSnapshot();
        Check(!coordinator.Open(Coordinator::Configuration{}).opened &&
                  SameCoordinatorState(before_unbound, coordinator.GetSnapshot()),
              "zero-epoch default configuration fails before mutation");
        const auto t1_configuration = ReadyConfiguration(coordinator);
        const auto t2_stale_configuration = ReadyConfiguration(coordinator);
        Check(t1_configuration.close_epoch != 0 &&
                  t1_configuration.close_epoch == t2_stale_configuration.close_epoch,
              "two preparers bind the same nonzero close epoch");
        Check(coordinator.Open(t1_configuration).opened,
              "two-preparer fixture opens at observed epoch");
        const auto t1_decision = Evaluate(BlockSubject(), t1_configuration.prerequisites);
        Check(t1_decision.allowed && t1_decision.binding,
              "T1 safe snapshot produces exact prior binding");
        const auto open_snapshot = coordinator.GetSnapshot();

        std::promise<void> close_complete_promise;
        auto close_complete = close_complete_promise.get_future();
        Coordinator::CloseResult peer_close;
        std::thread peer_writer([&] {
            peer_close = coordinator.BeginClose(Refusal::PeerViewUnsafe);
            close_complete_promise.set_value();
        });
        Check(close_complete.wait_for(std::chrono::seconds(2)) == std::future_status::ready,
              "peer close reaches deterministic pre-transition barrier");
        peer_writer.join();
        const auto closed_snapshot = coordinator.GetSnapshot();
        Check(peer_close.fully_closed && closed_snapshot.phase == Coordinator::Phase::Closed &&
                  closed_snapshot.close_epoch == open_snapshot.close_epoch + 1,
              "peer writer fully closes and advances close epoch");

        const auto before_stale_open = coordinator.GetSnapshot();
        const auto stale_open = coordinator.Open(t2_stale_configuration);
        const auto after_stale_open = coordinator.GetSnapshot();
        Check(!stale_open.opened && stale_open.error == Coordinator::Error::Closed &&
                  SameCoordinatorState(before_stale_open, after_stale_open),
              "stale T2 Open refuses before any coordinator mutation");

        uint64_t canonical_mutations = 0;
        for (const Path path : {Path::InternalMining, Path::GetBlockTemplate, Path::SubmitBlock,
                                Path::SynchronousGeneration}) {
            auto successor = coordinator.AcquireLocal(path, BlockSubject(), t1_decision.binding,
                                                      true, Coordinator::Duration{10});
            if (successor && successor.lease && path != Path::GetBlockTemplate &&
                successor.lease->ClaimForCanonicalCommit()) {
                ++canonical_mutations;
            }
            Check(!successor, "stale reopen cannot enable any block-work path");
        }
        Check(canonical_mutations == 0 && coordinator.GetSnapshot().active_leases == 0,
              "T1 bound predecessor emits zero lease claim or mutation");

        // Close before the first sample is legitimate: both observations see
        // the new epoch, and a fresh safe configuration may reopen. Repeating
        // that same configuration while Open is idempotent.
        const auto fresh = ReadyConfiguration(coordinator);
        Check(fresh.close_epoch == closed_snapshot.close_epoch && coordinator.Open(fresh).opened,
              "fresh post-close snapshot reopens legitimately");
        const auto fresh_open = coordinator.GetSnapshot();
        Check(coordinator.Open(fresh).opened &&
                  coordinator.GetSnapshot().configuration_generation ==
                      fresh_open.configuration_generation,
              "same-open-epoch stable Open is idempotent");
        for (const Path path : {Path::InternalMining, Path::GetBlockTemplate, Path::SubmitBlock,
                                Path::SynchronousGeneration}) {
            auto allowed = coordinator.AcquireLocal(path, BlockSubject(), std::nullopt, false,
                                                    Coordinator::Duration{10});
            Check(allowed && allowed.lease, "fresh epoch preserves equivalent block-work paths");
            allowed.lease->Release();
        }

        // A close between the two samples makes the snapshot explicitly
        // unsafe. Open also independently rejects its stale epoch.
        auto between_samples = ReadyConfiguration(coordinator);
        const uint64_t between_before = between_samples.close_epoch;
        const auto between_close = coordinator.BeginClose(Refusal::PeerViewUnsafe);
        const uint64_t between_after = coordinator.ObserveCloseEpoch();
        Check(between_close.fully_closed &&
                  !Coordinator::BindCloseEpochSnapshot(between_samples, between_before,
                                                       between_after) &&
                  !between_samples.prerequisites.runtime_open &&
                  !between_samples.prerequisites.peer_view_safe,
              "close between samples marks configuration unsafe");
        const auto before_between_open = coordinator.GetSnapshot();
        Check(!coordinator.Open(between_samples).opened &&
                  SameCoordinatorState(before_between_open, coordinator.GetSnapshot()),
              "between-sample stale Open has zero mutation");

        // A close after the second sample but before Open is caught by the
        // same current-epoch check even though that snapshot was internally
        // stable when it was created.
        Check(coordinator.Open(ReadyConfiguration(coordinator)).opened,
              "between-sample fixture reopens from fresh epoch");
        const auto after_samples = ReadyConfiguration(coordinator);
        const auto after_close = coordinator.BeginClose(Refusal::PeerViewUnsafe);
        const auto before_after_open = coordinator.GetSnapshot();
        Check(after_close.fully_closed && !coordinator.Open(after_samples).opened &&
                  SameCoordinatorState(before_after_open, coordinator.GetSnapshot()),
              "close after samples invalidates delayed Open without mutation");

        // Shutdown cancellation advances the same epoch, revokes acquired
        // work, and leaves every pre-shutdown configuration unusable.
        Check(coordinator.Open(ReadyConfiguration(coordinator)).opened,
              "shutdown fixture reopens from fresh epoch");
        const auto pre_shutdown_configuration = ReadyConfiguration(coordinator);
        auto pending = coordinator.AcquireLocal(Path::SynchronousGeneration, BlockSubject(),
                                                std::nullopt, false, Coordinator::Duration{10});
        Check(pending && pending.lease, "shutdown fixture acquires bounded local work");
        const uint64_t before_cancel = coordinator.ObserveCloseEpoch();
        coordinator.CancelAndClose(Refusal::NodeNotRunning);
        const auto cancelled = coordinator.GetSnapshot();
        Check(cancelled.close_epoch == before_cancel + 1 && !pending.lease->IsLive() &&
                  cancelled.active_leases == 0,
              "shutdown cancel advances epoch and revokes work");
        const auto before_shutdown_stale = coordinator.GetSnapshot();
        Check(!coordinator.Open(pre_shutdown_configuration).opened &&
                  SameCoordinatorState(before_shutdown_stale, coordinator.GetSnapshot()),
              "pre-shutdown snapshot cannot reopen or mutate state");

        // Every authoritative close call advances the epoch, including calls
        // made while already Closed. An epoch-matched unsafe Open also starts
        // a new close epoch so an older safe snapshot cannot follow it.
        const uint64_t before_repeated_close = coordinator.ObserveCloseEpoch();
        coordinator.BeginClose(Refusal::NodeNotRunning);
        coordinator.CancelAndClose(Refusal::NodeNotRunning);
        Check(coordinator.ObserveCloseEpoch() == before_repeated_close + 2,
              "repeated BeginClose and CancelAndClose each advance epoch");
        auto unsafe = ReadyConfiguration(coordinator);
        const auto safe_before_unsafe = unsafe;
        unsafe.prerequisites.node_running = false;
        const uint64_t before_unsafe_open = coordinator.ObserveCloseEpoch();
        const auto unsafe_open = coordinator.Open(unsafe);
        Check(!unsafe_open.opened && unsafe_open.error == Coordinator::Error::Rejected &&
                  coordinator.ObserveCloseEpoch() == before_unsafe_open + 1,
              "epoch-matched unsafe Open advances close epoch");
        const auto before_old_safe = coordinator.GetSnapshot();
        Check(!coordinator.Open(safe_before_unsafe).opened &&
                  SameCoordinatorState(before_old_safe, coordinator.GetSnapshot()),
              "unsafe Open invalidates older safe snapshot before mutation");
    }

    // lease-wins: acquisition and the one-shot sink claim linearize first.
    // Close immediately blocks every successor, then becomes fully closed as
    // soon as the predecessor lease is released.
    {
        Coordinator coordinator(Limits(), Mint());
        Check(coordinator.Open(ReadyConfiguration(coordinator)).opened,
              "lease-wins fixture opened");
        std::promise<void> acquired_promise;
        std::shared_future<void> acquired = acquired_promise.get_future().share();
        std::promise<void> close_started_promise;
        std::shared_future<void> close_started = close_started_promise.get_future().share();
        std::promise<void> release_promise;
        std::shared_future<void> release = release_promise.get_future().share();
        std::atomic<bool> acquired_ok{false};
        std::atomic<bool> remained_live{false};
        Coordinator::CloseResult close_result;

        std::thread sink([&] {
            auto attempt = coordinator.AcquireLocal(Path::InternalMining, BlockSubject(),
                                                    std::nullopt, false, Coordinator::Duration{20});
            acquired_ok.store(attempt && attempt.lease->ClaimForSink(), std::memory_order_release);
            acquired_promise.set_value();
            close_started.wait();
            remained_live.store(attempt.lease && attempt.lease->IsLive(),
                                std::memory_order_release);
            release.wait();
        });
        std::thread closer([&] {
            acquired.wait();
            close_result = coordinator.BeginClose(Refusal::SyncIncomplete);
            close_started_promise.set_value();
        });
        close_started.wait();
        Check(acquired_ok.load(std::memory_order_acquire), "lease-wins sink claimed before close");
        Check(!close_result.fully_closed && close_result.completion_deadline.has_value(),
              "lease-wins close is bounded while predecessor runs");
        const uint64_t repeated_close_epoch = coordinator.ObserveCloseEpoch();
        const auto repeated_close = coordinator.BeginClose(Refusal::SyncIncomplete);
        Check(!repeated_close.fully_closed &&
                  coordinator.ObserveCloseEpoch() == repeated_close_epoch + 1 &&
                  coordinator.GetSnapshot().active_leases == 1,
              "BeginClose while Closing advances epoch and preserves winner");
        auto successor = coordinator.AcquireLocal(Path::SubmitBlock, BlockSubject(), std::nullopt,
                                                  false, Coordinator::Duration{10});
        Check(!successor && successor.error == Coordinator::Error::Closing,
              "lease-wins close rejects all successor work immediately");
        Check(coordinator.GetSnapshot().phase == Coordinator::Phase::Closing,
              "lease-wins predecessor is the only closing work");
        release_promise.set_value();
        sink.join();
        closer.join();
        Check(remained_live.load(std::memory_order_acquire),
              "lease-wins predecessor stays valid before release");
        Check(coordinator.GetSnapshot().phase == Coordinator::Phase::Closed &&
                  coordinator.GetSnapshot().active_leases == 0,
              "lease release completes close without cached work");
    }

    // A forgotten predecessor cannot keep a safety transition in Closing
    // forever. Advancing the monotonic clock to the capped deadline revokes it.
    {
        std::atomic<int64_t> now_ms{2000};
        Coordinator coordinator(Limits(), Mint(), [&] {
            return Coordinator::TimePoint(
                Coordinator::Duration(now_ms.load(std::memory_order_acquire)));
        });
        Check(coordinator.Open(ReadyConfiguration(coordinator)).opened, "deadline fixture opened");
        auto lease = coordinator.AcquireLocal(Path::SynchronousGeneration, BlockSubject(),
                                              std::nullopt, false, Coordinator::Duration{10000});
        Check(lease && lease.lease->ClaimForSink(), "deadline fixture lease claimed");
        const auto close = coordinator.BeginClose(Refusal::DurableStateUnproven);
        Check(!close.fully_closed &&
                  close.completion_deadline == Coordinator::TimePoint(Coordinator::Duration{2025}),
              "close deadline capped by local lease limit");
        now_ms.store(2024, std::memory_order_release);
        Check(coordinator.GetSnapshot().phase == Coordinator::Phase::Closing &&
                  lease.lease->IsLive(),
              "lease remains live strictly before deadline");
        now_ms.store(2025, std::memory_order_release);
        Check(coordinator.GetSnapshot().phase == Coordinator::Phase::Closed &&
                  !lease.lease->IsLive(),
              "deadline cancels forgotten lease and completes close");
    }

    // An already-issued remote signing capability is a bounded predecessor:
    // it may be consumed once while Closing, but no new capability can issue.
    {
        Coordinator coordinator(Limits(), Mint());
        Check(coordinator.Open(ReadyConfiguration(coordinator)).opened,
              "remote lease-wins fixture opened");
        const Subject finality = FinalitySubject();
        auto remote = coordinator.IssueRemoteSigningLease(
            Path::FinalityVote, finality, std::nullopt, false, Coordinator::Duration{30});
        Check(static_cast<bool>(remote), "remote predecessor issued");
        const auto close = coordinator.BeginClose(Refusal::PeerViewUnsafe);
        Check(!close.fully_closed, "remote predecessor gives close a bounded deadline");
        auto successor = coordinator.IssueRemoteSigningLease(
            Path::FinalityVote, finality, std::nullopt, false, Coordinator::Duration{10});
        Check(!successor && successor.error == Coordinator::Error::Closing,
              "closing state issues no successor remote capability");
        auto consumed = coordinator.ConsumeRemoteSigningLease(
            remote.grant->token, Path::FinalityVote, finality, remote.grant->binding);
        Check(consumed && consumed.lease->ClaimForSink(),
              "remote predecessor consumes once during bounded close");
        auto replay = coordinator.ConsumeRemoteSigningLease(remote.grant->token, Path::FinalityVote,
                                                            finality, remote.grant->binding);
        Check(!replay && replay.error == Coordinator::Error::TokenConsumed,
              "remote predecessor replay rejected during close");
        consumed.lease->Release();
        Check(coordinator.GetSnapshot().phase == Coordinator::Phase::Closed,
              "remote predecessor release completes close");
    }

    // Emergency cancellation wins even against an already-claimed lease.
    {
        Coordinator coordinator(Limits(), Mint());
        Check(coordinator.Open(ReadyConfiguration(coordinator)).opened,
              "emergency race fixture opened");
        auto lease = coordinator.AcquireLocal(Path::InternalMining, BlockSubject(), std::nullopt,
                                              false, Coordinator::Duration{20});
        Check(lease && lease.lease->ClaimForSink(), "emergency race predecessor claimed");
        coordinator.CancelAndClose(Refusal::SnapshotStateUntrusted);
        Check(!lease.lease->IsLive() &&
                  coordinator.GetSnapshot().phase == Coordinator::Phase::Closed,
              "emergency cancellation invalidates claimed predecessor");
    }

    std::cout << "PASS work_admission_coordinator_race_tests checks=" << checks << "\n";
    return 0;
}
