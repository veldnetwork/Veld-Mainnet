#include "node/node.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>

using namespace veld;
using namespace veld::work_admission;

namespace {

using Coordinator = AdmissionCoordinator;
std::atomic<size_t> checks{0};

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
    p.validation_generation = 17;
    p.network_magic = MAINNET_MAGIC;
    p.genesis_hash = Filled(0x11);
    p.profile_digest = Filled(0x22);
    configuration.permitted_paths.fill(true);
    Coordinator::BindCloseEpochSnapshot(
        configuration, close_epoch_before, coordinator.ObserveCloseEpoch());
    return configuration;
}

Coordinator::Configuration ReadyWithPeerView(
        const Coordinator& coordinator,
        const net::NodeServer& server) {
    const uint64_t close_epoch_before = coordinator.ObserveCloseEpoch();
    auto configuration = Ready(coordinator);
    const auto view = server.GetPeerHeightView();
    configuration.prerequisites.peer_view_safe =
        view.work_sequencer_wired && view.work_view_stable;
    Coordinator::BindCloseEpochSnapshot(
        configuration, close_epoch_before, coordinator.ObserveCloseEpoch());
    return configuration;
}

Subject BlockSubject() {
    Subject subject;
    subject.purpose = Purpose::BlockProduction;
    subject.height = 2;
    subject.parent_height = 1;
    subject.parent_hash = Filled(0x33);
    return subject;
}

Subject FinalitySubject() {
    Subject subject;
    subject.purpose = Purpose::FinalityVote;
    subject.height = 1;
    subject.target_hash = Filled(0x44);
    subject.parent_height = 1;
    subject.parent_hash = Filled(0x33);
    return subject;
}

Coordinator::TokenMintFn Mint() {
    auto next = std::make_shared<std::atomic<uint64_t>>(0);
    return [next](Coordinator::TokenBytes& token) {
        token.fill(0x75);
        const uint64_t value = next->fetch_add(1) + 1;
        for (size_t i = 0; i < sizeof(value); ++i)
            token[i] = static_cast<uint8_t>(value >> (8U * i));
        return true;
    };
}

Coordinator::Limits Limits() {
    Coordinator::Limits limits;
    limits.max_local_lease = std::chrono::milliseconds(1000);
    limits.max_remote_lease = std::chrono::milliseconds(1500);
    limits.max_active_leases = 16;
    limits.max_spent_tokens = 32;
    return limits;
}

std::shared_ptr<net::Connection> MakeConnection(
        const std::string& ip, uint16_t port, bool inbound = false) {
    const auto fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!compat::IsValidSocket(fd)) return {};
    return std::make_shared<net::Connection>(fd, ip, port, inbound);
}

struct TransitionPermit {
    explicit TransitionPermit(std::unique_lock<std::mutex> guard)
        : guard(std::move(guard)) {}
    std::unique_lock<std::mutex> guard;
};

bool WaitForCoordinatorClose(Coordinator& coordinator) {
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        if (coordinator.GetSnapshot().phase == Coordinator::Phase::Closed)
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    coordinator.CancelAndClose(Refusal::PeerViewUnsafe);
    return false;
}

bool SameCoordinatorState(const Coordinator::Snapshot& lhs,
                          const Coordinator::Snapshot& rhs) {
    return lhs.phase == rhs.phase &&
        lhs.configured == rhs.configured &&
        lhs.refusal == rhs.refusal &&
        lhs.active_leases == rhs.active_leases &&
        lhs.pending_remote_tokens == rhs.pending_remote_tokens &&
        lhs.spent_remote_tokens == rhs.spent_remote_tokens &&
        lhs.close_deadline == rhs.close_deadline &&
        lhs.configuration_generation == rhs.configuration_generation &&
        lhs.close_epoch == rhs.close_epoch;
}

}  // namespace

int main() {
    compat::InitNetwork();
    Blockchain chain;
    Block genesis = CreateGenesisBlock();
    Check(chain.AddBlockDirect(
              genesis, true, false, false,
              mining::PowAdmissionContext::Internal()).IsAccepted(),
          "genesis fixture accepted");
    Mempool mempool;
    net::NodeServer server(0, MAINNET_MAGIC, chain, mempool);
    server.TestSetPeerHeightClock(100);

    auto peer_a = MakeConnection("10.20.0.1", 30101, false);
    auto peer_b = MakeConnection("10.20.0.2", 30102, false);
    Check(peer_a && peer_b, "outbound peer fixtures allocated");
    server.TestRecordVersionClaim(peer_a, 110);
    server.TestRecordVersionClaim(peer_b, 120);
    server.TestMarkPeerHandshakeReady(peer_a);
    server.TestMarkPeerHandshakeReady(peer_b);
    auto initial = server.GetPeerHeightView();
    Check(!initial.work_sequencer_wired,
          "unwired peer view cannot authorize work");
    Check(initial.distinct_version_ips == 2 &&
              initial.distinct_outbound_sync_ips == 2,
          "two exact outbound source generations visible");
    Check(initial.outbound_sync_height == 110,
          "outbound floor is second-highest exact source");

    // Exercise the production VERSION and VERACK handlers, not only the
    // focused mutation seams. The unsigned raw VERSION claim is invisible
    // until the first sequenced publication; VERACK readiness is a second,
    // independently sequenced boundary.
    {
        Coordinator coordinator(Limits(), Mint());
        std::mutex transition;
        std::atomic<uint64_t> callbacks{0};
        server.SetPeerWorkViewTransitionFn([&]() {
            callbacks.fetch_add(1, std::memory_order_acq_rel);
            coordinator.BeginClose(Refusal::PeerViewUnsafe);
            Check(WaitForCoordinatorClose(coordinator),
                  "production handshake transition closes boundedly");
            auto permit = std::make_shared<TransitionPermit>(
                std::unique_lock<std::mutex>(transition));
            return std::static_pointer_cast<void>(permit);
        });
        auto peer = MakeConnection("10.20.0.3", 30103, false);
        Check(peer != nullptr, "production handshake peer allocated");
        net::PeerState state;
        state.version_sent = true;
        PeerManager manager(MAINNET_MAGIC, 0);
        const size_t sources_before = server.TestPeerWorkSourceCount();
        const auto version = manager.BuildVersionMessage(130, 0x5057);
        server.TestDispatchPeerMessageWithState(state, *peer, version);
        Check(state.their_version && !state.handshake_done,
              "VERSION publishes claim without premature readiness");
        Check(server.TestPeerWorkSourceCount() == sources_before + 1,
              "VERSION publishes one exact source generation");
        Check(callbacks.load(std::memory_order_acquire) == 1,
              "VERSION mutation crossed sequencer exactly once");
        server.TestDispatchPeerMessageWithState(
            state, *peer, manager.BuildVerackMessage());
        Check(state.version_acked && state.handshake_done,
              "VERACK publishes handshake readiness");
        Check(callbacks.load(std::memory_order_acquire) == 2,
              "VERACK mutation crossed sequencer exactly once");
        server.TestFinalizePeerConnection("unused-production", peer);
        Check(server.TestPeerWorkSourceCount() == sources_before,
              "production handshake cleanup retires exact source");
        Check(callbacks.load(std::memory_order_acquire) == 3,
              "production cleanup crossed sequencer exactly once");
    }

    // Writer-first: write_pending is visible before the callback waits for the
    // transition mutex. A GBT-style pure predicate and all coordinator grants
    // fail while no peer byte has yet changed.
    {
        Coordinator coordinator(Limits(), Mint());
        const auto t1_configuration =
            ReadyWithPeerView(coordinator, server);
        const auto t2_stale_configuration =
            ReadyWithPeerView(coordinator, server);
        const auto t1_decision = Evaluate(
            BlockSubject(), t1_configuration.prerequisites);
        Check(t1_configuration.close_epoch ==
                  t2_stale_configuration.close_epoch &&
                  t1_decision.allowed && t1_decision.binding,
              "two real peer snapshots prepare T1 and delayed T2");
        Check(coordinator.Open(t1_configuration).opened,
              "writer-first coordinator opened");
        const auto t1_bound = net::NodeServer::BoundPeerWorkLifetimeMs(
            server.GetPeerHeightView(), 100, 1);
        Check(t1_bound.has_value(),
              "T1 real peer lifetime bound succeeds before writer intent");
        std::mutex transition;
        std::promise<void> close_started_promise;
        auto close_started = close_started_promise.get_future();
        server.SetPeerWorkViewTransitionFn([&]() {
            const auto close = coordinator.BeginClose(
                Refusal::PeerViewUnsafe);
            Check(close.fully_closed,
                  "writer-first close has no predecessor");
            close_started_promise.set_value();
            auto permit = std::make_shared<TransitionPermit>(
                std::unique_lock<std::mutex>(transition));
            return std::static_pointer_cast<void>(permit);
        });
        std::unique_lock<std::mutex> hold_transition(transition);
        std::atomic<bool> writer_done{false};
        std::thread writer([&] {
            server.TestRecordPeerSyncHeight(*peer_a, 200);
            writer_done.store(true, std::memory_order_release);
        });
        Check(close_started.wait_for(std::chrono::seconds(2)) ==
                  std::future_status::ready,
              "writer-first close reached deterministic barrier");
        const auto pending = server.GetPeerHeightView();
        Check(!pending.work_view_stable &&
                  (pending.work_generation & 1U) == 0,
              "write intent refuses new work before odd publication");
        const auto before_stale_open = coordinator.GetSnapshot();
        const auto stale_open = coordinator.Open(t2_stale_configuration);
        Check(!stale_open.opened &&
                  stale_open.error == Coordinator::Error::Closed &&
                  SameCoordinatorState(
                      before_stale_open, coordinator.GetSnapshot()),
              "actual peer close rejects delayed stale Open without mutation");
        auto refused = coordinator.AcquireLocal(
            Path::InternalMining, BlockSubject(), t1_decision.binding, true,
            std::chrono::milliseconds(*t1_bound));
        uint64_t journal = 0;
        uint64_t signature = 0;
        uint64_t sink = 0;
        if (refused && refused.lease) {
            ++journal;
            ++signature;
            if (refused.lease->ClaimForSink()) ++sink;
        }
        Check(!refused && refused.error == Coordinator::Error::Closed,
              "writer-first refuses new local sink");
        Check(journal == 0 && signature == 0 && sink == 0,
              "writer-first emits zero journal signature or sink artifacts");
        Check(!writer_done.load(std::memory_order_acquire),
              "peer mutation waits behind transition holder");
        hold_transition.unlock();
        writer.join();
        const auto after = server.GetPeerHeightView();
        Check(after.work_view_stable && after.work_sequencer_wired,
              "post-write peer generation stable and wired");
        Check(after.outbound_sync_height == 120,
              "writer-first sync-height mutation published once");
        Check(coordinator.Open(
                  ReadyWithPeerView(coordinator, server)).opened,
              "fresh post-publication peer snapshot reopens legitimately");
    }

    // Local sink first: BeginClose waits outside peer/chain mutexes until the
    // already-claimed block sink releases. Mutation necessarily follows the
    // irreversible sink effect.
    {
        Coordinator coordinator(Limits(), Mint());
        Check(coordinator.Open(Ready(coordinator)).opened,
              "local predecessor coordinator opened");
        auto local = coordinator.AcquireLocal(
            Path::SubmitBlock, BlockSubject(), std::nullopt, false,
            std::chrono::milliseconds(800));
        Check(local && local.lease->ClaimForSink(),
              "local block predecessor claimed");
        std::mutex transition;
        std::promise<void> close_started_promise;
        auto close_started = close_started_promise.get_future();
        std::atomic<bool> close_wait_succeeded{false};
        server.SetPeerWorkViewTransitionFn([&]() {
            const auto close = coordinator.BeginClose(
                Refusal::PeerViewUnsafe);
            Check(!close.fully_closed,
                  "local predecessor makes peer writer wait");
            close_started_promise.set_value();
            close_wait_succeeded.store(
                WaitForCoordinatorClose(coordinator),
                std::memory_order_release);
            auto permit = std::make_shared<TransitionPermit>(
                std::unique_lock<std::mutex>(transition));
            return std::static_pointer_cast<void>(permit);
        });
        std::atomic<bool> writer_done{false};
        std::atomic<uint64_t> order{0};
        uint64_t sink_order = 0;
        uint64_t writer_order = 0;
        std::thread writer([&] {
            server.TestRecordPeerSyncHeight(*peer_b, 300);
            writer_order = order.fetch_add(1) + 1;
            writer_done.store(true, std::memory_order_release);
        });
        Check(close_started.wait_for(std::chrono::seconds(2)) ==
                  std::future_status::ready,
              "local predecessor close barrier reached");
        Check(!writer_done.load(std::memory_order_acquire),
              "local predecessor blocks peer publication");
        Check(local.lease->IsLive(),
              "claimed local predecessor remains live while Closing");
        sink_order = order.fetch_add(1) + 1;
        local.lease->Release();
        writer.join();
        Check(close_wait_succeeded.load(std::memory_order_acquire),
              "local predecessor close completed boundedly");
        Check(sink_order < writer_order,
              "local sink effect precedes peer mutation");
    }

    // An abandoned predecessor cannot deadlock a peer transition. The
    // coordinator's hard lease deadline closes it without cancellation, then
    // the waiting writer publishes normally.
    {
        Coordinator::Limits short_limits = Limits();
        short_limits.max_local_lease = std::chrono::milliseconds(80);
        Coordinator coordinator(short_limits, Mint());
        Check(coordinator.Open(Ready(coordinator)).opened,
              "timeout coordinator opened");
        auto abandoned = coordinator.AcquireLocal(
            Path::SubmitBlock, BlockSubject(), std::nullopt, false,
            std::chrono::milliseconds(80));
        Check(abandoned && abandoned.lease,
              "bounded abandoned predecessor acquired");
        std::mutex transition;
        std::atomic<bool> close_wait_succeeded{false};
        server.SetPeerWorkViewTransitionFn([&]() {
            const auto close = coordinator.BeginClose(
                Refusal::PeerViewUnsafe);
            Check(!close.fully_closed,
                  "abandoned predecessor initially delays writer");
            close_wait_succeeded.store(
                WaitForCoordinatorClose(coordinator),
                std::memory_order_release);
            auto permit = std::make_shared<TransitionPermit>(
                std::unique_lock<std::mutex>(transition));
            return std::static_pointer_cast<void>(permit);
        });
        auto write = std::async(std::launch::async, [&] {
            server.TestRecordPeerSyncHeight(*peer_b, 350);
        });
        Check(write.wait_for(std::chrono::seconds(2)) ==
                  std::future_status::ready,
              "expired predecessor cannot deadlock peer writer");
        write.get();
        Check(close_wait_succeeded.load(std::memory_order_acquire),
              "expired predecessor closed before mutation");
        Check(!abandoned.lease->IsLive(),
              "abandoned predecessor is unusable after deadline");
    }

    // Remote signer first: an exact pending bearer consumes during Closing,
    // then journal/sign/one-use sink complete before peer publication.
    {
        Coordinator coordinator(Limits(), Mint());
        Check(coordinator.Open(Ready(coordinator)).opened,
              "remote predecessor coordinator opened");
        const Subject subject = FinalitySubject();
        auto remote = coordinator.IssueRemoteSigningLease(
            Path::FinalityVote, subject, std::nullopt, false,
            std::chrono::milliseconds(1200));
        Check(remote && remote.grant,
              "remote predecessor bearer issued");
        std::mutex transition;
        std::promise<void> close_started_promise;
        auto close_started = close_started_promise.get_future();
        server.SetPeerWorkViewTransitionFn([&]() {
            const auto close = coordinator.BeginClose(
                Refusal::PeerViewUnsafe);
            Check(!close.fully_closed,
                  "pending remote bearer makes peer writer wait");
            close_started_promise.set_value();
            Check(WaitForCoordinatorClose(coordinator),
                  "remote predecessor completes before timeout");
            auto permit = std::make_shared<TransitionPermit>(
                std::unique_lock<std::mutex>(transition));
            return std::static_pointer_cast<void>(permit);
        });
        std::atomic<uint64_t> order{0};
        uint64_t sink_order = 0;
        uint64_t writer_order = 0;
        std::thread writer([&] {
            server.TestRecordPeerSyncHeight(*peer_a, 400);
            writer_order = order.fetch_add(1) + 1;
        });
        Check(close_started.wait_for(std::chrono::seconds(2)) ==
                  std::future_status::ready,
              "remote predecessor close barrier reached");
        auto active = coordinator.ConsumeRemoteSigningLease(
            remote.grant->token, Path::FinalityVote, subject,
            remote.grant->binding);
        Check(active && active.lease->IsLive(),
              "exact predecessor bearer consumes during Closing");
        bool journal = active.lease->IsLive();
        bool signature = active.lease->IsLive();
        bool sink = active.lease->ClaimForSink() && active.lease->IsLive();
        Check(journal && signature && sink,
              "remote journal signature and sink share predecessor lease");
        sink_order = order.fetch_add(1) + 1;
        active.lease->Release();
        writer.join();
        Check(sink_order < writer_order,
              "remote signed sink precedes peer mutation");
        auto replay = coordinator.ConsumeRemoteSigningLease(
            remote.grant->token, Path::FinalityVote, subject,
            remote.grant->binding);
        Check(!replay, "remote predecessor bearer remains one-use");
    }

    // Verified-height writes and exact handshake removal use the same
    // transition contract; cleanup removes both source and IP evidence.
    {
        Coordinator coordinator(Limits(), Mint());
        std::mutex transition;
        std::atomic<uint64_t> callbacks{0};
        server.SetPeerWorkViewTransitionFn([&]() {
            ++callbacks;
            coordinator.BeginClose(Refusal::PeerViewUnsafe);
            Check(WaitForCoordinatorClose(coordinator),
                  "non-predecessor peer transition closes boundedly");
            auto permit = std::make_shared<TransitionPermit>(
                std::unique_lock<std::mutex>(transition));
            return std::static_pointer_cast<void>(permit);
        });
        const uint64_t before_verified = callbacks.load();
        server.TestRecordVerifiedPeerHeight(
            peer_a->RemoteAddr(), genesis.GetHash());
        Check(callbacks.load() == before_verified + 1,
              "verified-height mutation entered sequencer");
        Check(server.TestVerifiedPeerEvidenceCount() == 1,
              "canonical verified-height evidence published");
        const size_t before_sources = server.TestPeerWorkSourceCount();
        server.TestFinalizePeerConnection("unused-a", peer_a);
        Check(server.TestPeerWorkSourceCount() + 1 == before_sources,
              "connection cleanup removed exact work source");
        Check(server.TestVerifiedPeerEvidenceCount() == 0,
              "last-source cleanup removed IP verified evidence");
        Check(server.GetPeerHeightView().distinct_version_ips == 1,
              "handshake removal immediately changes authoritative view");
    }

    // Natural freshness expiry is not a callback-producing writer. The view
    // exposes a conservative boundary and the shared lifetime helper refuses
    // every lease at the safety margin, so no acquired work crosses it.
    {
        server.TestSetPeerHeightClock(100);
        const auto fresh = server.GetPeerHeightView();
        Check(fresh.freshness_valid_for_ms == 120000,
              "freshness deadline is conservative to coarse clock");
        auto long_ttl = net::NodeServer::BoundPeerWorkLifetimeMs(
            fresh, 200000, 1000);
        Check(long_ttl && *long_ttl == 119000,
              "all peer-bound work lifetimes end before expiry");
        server.TestSetPeerHeightClock(219);
        const auto margin = server.GetPeerHeightView();
        Check(margin.freshness_valid_for_ms == 1000,
              "one-second conservative freshness window exposed");
        Check(!net::NodeServer::BoundPeerWorkLifetimeMs(
                  margin, 5000, 1000),
              "lease refused when freshness margin is insufficient");
        server.TestSetPeerHeightClock(221);
        const auto expired = server.GetPeerHeightView();
        Check(expired.outbound_sync_height == 0 &&
                  expired.freshness_valid_for_ms == UINT64_MAX,
              "expired outbound claim no longer influences work view");
    }

    // Public-testnet wall-clock bounds use the same strict-before-deadline
    // contract. At the returned hard deadline the coordinator prunes the work
    // before journal/sign/sink code can emit an artifact.
    {
        auto wall_ttl = VeldNode::BoundWallClockWorkLifetimeMs(
            100, 105, 10000, 1000);
        Check(wall_ttl && *wall_ttl == 3000,
              "wall-clock lifetime subtracts quantization and margin");
        Check(!VeldNode::BoundWallClockWorkLifetimeMs(
                  103, 105, 10000, 1000),
              "wall-clock work refused at insufficient margin");
        std::atomic<int64_t> now_ms{100000};
        Coordinator coordinator(
            Limits(), Mint(), [&] {
                return Coordinator::TimePoint(
                    Coordinator::Duration(now_ms.load()));
            });
        Check(coordinator.Open(Ready(coordinator)).opened,
              "wall deadline coordinator opened");
        auto pending = coordinator.IssueRemoteSigningLease(
            Path::FinalityVote, FinalitySubject(), std::nullopt, false,
            std::chrono::milliseconds(*wall_ttl));
        Check(pending && pending.grant,
              "wall-bounded remote grant issued");
        now_ms.store(103000);
        auto expired = coordinator.ConsumeRemoteSigningLease(
            pending.grant->token, Path::FinalityVote, FinalitySubject(),
            pending.grant->binding);
        uint64_t artifacts = 0;
        if (expired && expired.lease->IsLive()) ++artifacts;
        Check(!expired && artifacts == 0,
              "crossing wall deadline emits zero artifacts");
    }

    // A configured callback failure never publishes unsequenced peer state and
    // permanently marks the work view unsafe.
    {
        const size_t sources_before = server.TestPeerWorkSourceCount();
        const size_t claims_before = server.TestPeerHeightClaimCount();
        const size_t sync_before = server.TestPeerSyncClaimCount();
        server.SetPeerWorkViewTransitionFn([] {
            return net::NodeServer::PeerWorkViewTransitionPermit{};
        });
        auto failed_peer = MakeConnection("10.20.0.9", 30109, false);
        Check(failed_peer != nullptr, "failure-path peer allocated");
        net::PeerState failed_state;
        failed_state.version_sent = true;
        PeerManager manager(MAINNET_MAGIC, 0);
        server.TestDispatchPeerMessageWithState(
            failed_state, *failed_peer,
            manager.BuildVersionMessage(999, 0x5058));
        Check(!failed_state.their_version &&
                  !failed_peer->VersionReceived(),
              "failed production VERSION stays unpublished");
        Check(server.TestPeerWorkSourceCount() == sources_before,
              "failed permit publishes no source");
        Check(server.TestPeerHeightClaimCount() == claims_before &&
                  server.TestPeerSyncClaimCount() == sync_before,
              "failed permit rolls back both raw VERSION claim maps");
        const auto failed = server.GetPeerHeightView();
        Check(!failed.work_view_stable && failed.work_sequencer_wired,
              "permit failure leaves production work fail-closed");
        failed_peer->Close();
    }

    peer_b->Close();
    std::cout << "PASS daybreak_peer_work_view_race_tests checks="
              << checks.load(std::memory_order_acquire)
              << " writer_first=1 local_predecessor=1 remote_predecessor=1"
              << " close_epoch_stale_reopen=1"
              << " version_verack=1 handshake_removal=1 verified_height=1"
              << " expiry=1 wall_deadline=1 failure_closed=1 timeout=1\n";
    return 0;
}
