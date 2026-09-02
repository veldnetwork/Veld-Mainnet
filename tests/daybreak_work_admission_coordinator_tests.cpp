#include "../include/node/work_admission_coordinator.h"

#include <atomic>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <type_traits>
#include <vector>

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

Prerequisites ReadyPrerequisites() {
    Prerequisites p;
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
    p.network_magic = 0x56454c44u;
    p.genesis_hash = Filled(0x11);
    p.profile_digest = Filled(0x22);
    return p;
}

AdmissionCoordinator::Configuration ReadyConfiguration(
        const AdmissionCoordinator& coordinator) {
    const uint64_t close_epoch_before = coordinator.ObserveCloseEpoch();
    AdmissionCoordinator::Configuration configuration;
    configuration.prerequisites = ReadyPrerequisites();
    configuration.permitted_paths.fill(true);
    AdmissionCoordinator::BindCloseEpochSnapshot(
        configuration, close_epoch_before, coordinator.ObserveCloseEpoch());
    return configuration;
}

Subject BlockSubject() {
    Subject subject;
    subject.purpose = Purpose::BlockProduction;
    subject.height = 43;
    subject.parent_height = 42;
    subject.parent_hash = Filled(0x33);
    return subject;
}

Subject FinalitySubject() {
    Subject subject;
    subject.purpose = Purpose::FinalityVote;
    subject.height = 40;
    subject.target_hash = Filled(0x44);
    subject.parent_height = 42;
    subject.parent_hash = Filled(0x33);
    return subject;
}

Subject SubjectFor(Path path) {
    if (path == Path::FinalityVote) return FinalitySubject();
    if (path == Path::ValidatorEndorsement) {
        Subject subject = FinalitySubject();
        subject.purpose = Purpose::ValidatorEndorsement;
        return subject;
    }
    return BlockSubject();
}

AdmissionCoordinator::TokenMintFn CounterMint(
        const std::shared_ptr<std::atomic<uint64_t>>& counter) {
    return [counter](AdmissionCoordinator::TokenBytes& token) {
        const uint64_t value = counter->fetch_add(1) + 1;
        token.fill(0);
        for (size_t i = 0; i < sizeof(value); ++i)
            token[i] = static_cast<uint8_t>(value >> (8U * i));
        token.back() = 0xa5;
        return true;
    };
}

}  // namespace

int main() {
    using Coordinator = AdmissionCoordinator;
    static_assert(!std::is_copy_constructible_v<Coordinator::Lease>);
    static_assert(!std::is_copy_assignable_v<Coordinator::Lease>);
    static_assert(std::is_move_constructible_v<Coordinator::Lease>);
    static_assert(std::is_nothrow_destructible_v<Coordinator::Lease>);

    std::atomic<int64_t> now_ms{1000};
    const Coordinator::NowFn now = [&]() {
        return Coordinator::TimePoint(
            Coordinator::Duration(now_ms.load(std::memory_order_acquire)));
    };
    Coordinator::Limits limits;
    limits.max_local_lease = Coordinator::Duration{20};
    limits.max_remote_lease = Coordinator::Duration{80};
    limits.max_active_leases = 4;
    limits.max_spent_tokens = 8;

    Coordinator unwired(limits, {}, now);
    auto default_attempt = unwired.AcquireLocal(
        Path::SubmitBlock, BlockSubject(), std::nullopt, false,
        Coordinator::Duration{10});
    Check(!default_attempt && default_attempt.error == Coordinator::Error::Closed &&
              default_attempt.decision.refusal == Refusal::Unwired,
          "default coordinator is closed and unwired");

    auto counter = std::make_shared<std::atomic<uint64_t>>(0);
    Coordinator coordinator(limits, CounterMint(counter), now);
    auto bad_configuration = ReadyConfiguration(coordinator);
    bad_configuration.prerequisites.sync_complete = false;
    const auto bad_open = coordinator.Open(bad_configuration);
    Check(!bad_open.opened && bad_open.error == Coordinator::Error::Rejected &&
              bad_open.refusal == Refusal::SyncIncomplete,
          "open rejects an unproven prerequisite");

    using PrerequisiteMutator = std::function<void(Prerequisites&)>;
    const std::vector<std::pair<Refusal, PrerequisiteMutator>>
        false_prerequisites{
            {Refusal::NodeNotRunning,
             [](auto& p) { p.node_running = false; }},
            {Refusal::StartupReplayIncomplete,
             [](auto& p) { p.startup_replay_complete = false; }},
            {Refusal::IndependentValidationIncomplete,
             [](auto& p) { p.independent_validation_complete = false; }},
            {Refusal::SyncIncomplete,
             [](auto& p) { p.sync_complete = false; }},
            {Refusal::SnapshotStateUntrusted,
             [](auto& p) { p.snapshot_state_clean = false; }},
            {Refusal::DurableStateUnproven,
             [](auto& p) { p.durable_state_proven = false; }},
            {Refusal::DatadirIdentityUnproven,
             [](auto& p) { p.datadir_identity_valid = false; }},
            {Refusal::CheckpointAnchorUnproven,
             [](auto& p) { p.checkpoint_anchor_valid = false; }},
            {Refusal::TipUnknown,
             [](auto& p) { p.canonical_tip_known = false; }},
            {Refusal::RuntimeClosed,
             [](auto& p) { p.runtime_open = false; }},
            {Refusal::PeerViewUnsafe,
             [](auto& p) { p.peer_view_safe = false; }},
        };
    const std::vector<Path> every_path{
        Path::InternalMining, Path::GetBlockTemplate, Path::SubmitBlock,
        Path::SynchronousGeneration, Path::ValidatorEndorsement,
        Path::FinalityVote};
    for (const auto& [expected, mutate] : false_prerequisites) {
        Coordinator matrix(limits, CounterMint(
            std::make_shared<std::atomic<uint64_t>>(0)), now);
        auto configuration = ReadyConfiguration(matrix);
        mutate(configuration.prerequisites);
        const auto refused = matrix.Open(configuration);
        Check(!refused.opened && refused.refusal == expected,
              "false prerequisite closes coordinator");
        for (const Path path : every_path) {
            const auto attempt = matrix.AcquireLocal(
                path, SubjectFor(path), std::nullopt, false,
                Coordinator::Duration{10});
            Check(!attempt && attempt.decision.refusal == expected,
                  "false prerequisite closes every production path");
        }
        Check(matrix.GetSnapshot().active_leases == 0,
              "false prerequisite retains no cached work");
    }

    const auto opened = coordinator.Open(ReadyConfiguration(coordinator));
    Check(opened.opened && opened.error == Coordinator::Error::None,
          "ready configuration opens atomically");
    Check(coordinator.GetSnapshot().phase == Coordinator::Phase::Open,
          "open phase visible");

    auto invalid_duration = coordinator.AcquireLocal(
        Path::SubmitBlock, BlockSubject(), std::nullopt, false,
        Coordinator::Duration::zero());
    Check(!invalid_duration &&
              invalid_duration.error == Coordinator::Error::InvalidDuration,
          "zero lease duration rejected");

    auto wrong_path = coordinator.AcquireLocal(
        Path::FinalityVote, BlockSubject(), std::nullopt, false,
        Coordinator::Duration{10});
    Check(!wrong_path &&
              wrong_path.error == Coordinator::Error::PathPurposeMismatch,
          "path and purpose must match");

    auto role_configuration = ReadyConfiguration(coordinator);
    role_configuration.permitted_paths[
        static_cast<size_t>(Path::SubmitBlock)] = false;
    Check(coordinator.Open(role_configuration).opened,
          "configuration may intentionally deny one role path");
    auto denied_role = coordinator.AcquireLocal(
        Path::SubmitBlock, BlockSubject(), std::nullopt, false,
        Coordinator::Duration{10});
    Check(!denied_role && denied_role.decision.refusal == Refusal::RoleDenied,
          "path-specific role denial enforced at acquisition");
    Check(coordinator.Open(ReadyConfiguration(coordinator)).opened,
          "all-path configuration restored");

    auto issued = coordinator.AcquireLocal(
        Path::SubmitBlock, BlockSubject(), std::nullopt, false,
        Coordinator::Duration{10000});
    Check(issued && issued.lease->IsLive(), "valid local lease issued");
    Check(issued.lease->deadline() ==
              Coordinator::TimePoint(Coordinator::Duration{1020}),
          "local lease duration capped by configured maximum");
    Check(issued.lease->binding() == *issued.decision.binding,
          "lease retains exact evaluated binding");
    Check(issued.lease->ClaimForSink(), "local sink claim succeeds once");
    Check(!issued.lease->ClaimForSink(), "local sink claim cannot be replayed");
    Check(coordinator.Open(ReadyConfiguration(coordinator)).opened,
          "identical open state is idempotent under a live lease");
    auto changed_configuration = ReadyConfiguration(coordinator);
    ++changed_configuration.prerequisites.validation_generation;
    Check(coordinator.Open(changed_configuration).error ==
              Coordinator::Error::Busy,
          "changed open state cannot replace a live lease");
    const Binding first_binding = issued.lease->binding();
    issued.lease->Release();
    Check(coordinator.GetSnapshot().active_leases == 0,
          "explicit release removes local lease");

    auto missing_prior = coordinator.AcquireLocal(
        Path::SubmitBlock, BlockSubject(), std::nullopt, true,
        Coordinator::Duration{10});
    Check(!missing_prior &&
              missing_prior.decision.refusal == Refusal::BindingMissing,
          "required prior binding re-evaluated at acquisition");
    Binding stale = first_binding;
    ++stale.validation_generation;
    auto stale_prior = coordinator.AcquireLocal(
        Path::SubmitBlock, BlockSubject(), stale, true,
        Coordinator::Duration{10});
    Check(!stale_prior &&
              stale_prior.decision.refusal == Refusal::BindingMismatch,
          "stale generation binding rejected at acquisition");

    try {
        auto exceptional = coordinator.AcquireLocal(
            Path::InternalMining, BlockSubject(), std::nullopt, false,
            Coordinator::Duration{10});
        Check(exceptional && exceptional.lease->ClaimForSink(),
              "exception fixture acquired lease");
        throw std::runtime_error("fixture");
    } catch (const std::runtime_error&) {
    }
    Check(coordinator.GetSnapshot().active_leases == 0,
          "lease releases during stack unwinding");

    Coordinator no_mint(limits, {}, now);
    Check(no_mint.Open(ReadyConfiguration(no_mint)).opened,
          "local coordinator can open without remote token mint");
    auto no_mint_remote = no_mint.IssueRemoteSigningLease(
        Path::FinalityVote, FinalitySubject(), std::nullopt, false,
        Coordinator::Duration{10});
    Check(!no_mint_remote && no_mint_remote.error ==
              Coordinator::Error::TokenMintUnavailable,
          "remote signing fails closed without entropy provider");

    auto block_remote = coordinator.IssueRemoteSigningLease(
        Path::SubmitBlock, BlockSubject(), std::nullopt, false,
        Coordinator::Duration{10});
    Check(!block_remote && block_remote.error ==
              Coordinator::Error::PathPurposeMismatch,
          "remote signing tokens restricted to validator paths");

    const Subject finality = FinalitySubject();
    auto remote = coordinator.IssueRemoteSigningLease(
        Path::FinalityVote, finality, std::nullopt, false,
        Coordinator::Duration{10000});
    Check(remote && remote.grant->deadline ==
              Coordinator::TimePoint(Coordinator::Duration{1080}),
          "remote lease issued with capped deadline");
    Check(remote.grant->binding == *remote.decision.binding,
          "remote capability bound to evaluated state");

    Coordinator::TokenBytes forged_bytes = remote.grant->token.bytes();
    forged_bytes[17] ^= 0x80;
    auto forged = coordinator.ConsumeRemoteSigningLease(
        Coordinator::RemoteToken::FromBytes(forged_bytes),
        Path::FinalityVote, finality, remote.grant->binding);
    Check(!forged && forged.error == Coordinator::Error::TokenUnknown,
          "forged remote capability rejected");

    Subject changed_target = finality;
    changed_target.target_hash = Filled(0x55);
    auto wrong_subject = coordinator.ConsumeRemoteSigningLease(
        remote.grant->token, Path::FinalityVote, changed_target,
        remote.grant->binding);
    Check(!wrong_subject && wrong_subject.error ==
              Coordinator::Error::PathPurposeMismatch,
          "remote capability cannot authorize a different subject");

    Binding wrong_binding = remote.grant->binding;
    ++wrong_binding.validation_generation;
    auto wrong_remote_binding = coordinator.ConsumeRemoteSigningLease(
        remote.grant->token, Path::FinalityVote, finality, wrong_binding);
    Check(!wrong_remote_binding &&
              wrong_remote_binding.decision.refusal == Refusal::BindingMismatch,
          "remote prior binding re-evaluated before consumption");

    auto consumed = coordinator.ConsumeRemoteSigningLease(
        remote.grant->token, Path::FinalityVote, finality,
        remote.grant->binding);
    Check(consumed && consumed.lease->IsLive(),
          "exact remote capability converts to local lease");
    auto replay = coordinator.ConsumeRemoteSigningLease(
        remote.grant->token, Path::FinalityVote, finality,
        remote.grant->binding);
    Check(!replay && replay.error == Coordinator::Error::TokenConsumed,
          "remote capability is one-use");
    Check(consumed.lease->ClaimForSink(),
          "consumed remote capability claims sink once");
    Check(!consumed.lease->ClaimForSink(),
          "consumed remote sink claim cannot repeat");
    consumed.lease->Release();

    auto cancellable = coordinator.IssueRemoteSigningLease(
        Path::FinalityVote, finality, std::nullopt, false,
        Coordinator::Duration{10});
    Check(cancellable && coordinator.CancelRemoteSigningLease(
              cancellable.grant->token),
          "pending remote capability can be released explicitly");
    auto cancelled_use = coordinator.ConsumeRemoteSigningLease(
        cancellable.grant->token, Path::FinalityVote, finality,
        cancellable.grant->binding);
    Check(!cancelled_use && cancelled_use.error ==
              Coordinator::Error::TokenConsumed,
          "cancelled remote capability remains replay-proof");

    auto expiring = coordinator.IssueRemoteSigningLease(
        Path::FinalityVote, finality, std::nullopt, false,
        Coordinator::Duration{5});
    Check(static_cast<bool>(expiring), "expiry fixture issued");
    now_ms.store(1005, std::memory_order_release);
    auto expired_use = coordinator.ConsumeRemoteSigningLease(
        expiring.grant->token, Path::FinalityVote, finality,
        expiring.grant->binding);
    Check(!expired_use, "expired remote capability rejected");

    auto emergency = coordinator.AcquireLocal(
        Path::SynchronousGeneration, BlockSubject(), std::nullopt, false,
        Coordinator::Duration{10});
    Check(emergency && emergency.lease->IsLive(),
          "emergency cancellation fixture acquired");
    const auto cancelled = coordinator.CancelAndClose(
        Refusal::DurableStateUnproven);
    Check(cancelled.fully_closed &&
              cancelled.refusal == Refusal::DurableStateUnproven,
          "emergency close completes immediately");
    Check(!emergency.lease->IsLive() &&
              !emergency.lease->ClaimForSink(),
          "emergency close revokes outstanding local lease");
    Check(coordinator.GetSnapshot().active_leases == 0,
          "emergency close retains no cached work");

    {
        Coordinator canonical(limits, CounterMint(
            std::make_shared<std::atomic<uint64_t>>(0)), now);
        Check(canonical.Open(ReadyConfiguration(canonical)).opened,
              "canonical-claim coordinator opens");
        const uint64_t initial_generation =
            canonical.GetSnapshot().configuration_generation;
        const uint64_t initial_close_epoch =
            canonical.GetSnapshot().close_epoch;
        auto sole = canonical.AcquireLocal(
            Path::InternalMining, BlockSubject(), std::nullopt, false,
            Coordinator::Duration{10});
        Check(sole && sole.lease->configuration_generation() ==
                  initial_generation,
              "local ticket captures coordinator configuration generation");
        Check(sole.lease->ClaimForCanonicalCommit() &&
                  sole.lease->IsLive() &&
                  canonical.GetSnapshot().close_epoch ==
                      initial_close_epoch + 1,
              "canonical claim advances close epoch without revoking winner");
        Check(!sole.lease->ClaimForCanonicalCommit() &&
                  canonical.GetSnapshot().phase == Coordinator::Phase::Closing,
              "canonical ticket reuse fails while new acquisition is closed");
        auto after_claim = canonical.AcquireLocal(
            Path::SubmitBlock, BlockSubject(), std::nullopt, false,
            Coordinator::Duration{10});
        Check(!after_claim,
              "canonical claim closes every competing acquisition");
        sole.lease->Release();
        Check(canonical.GetSnapshot().phase == Coordinator::Phase::Closed,
              "canonical claim closes fully after propagation lease release");
        Check(canonical.Open(ReadyConfiguration(canonical)).opened &&
                  canonical.GetSnapshot().configuration_generation >
                      initial_generation,
              "closed-to-open transition advances the coordinator epoch");
        const uint64_t reopened_generation =
            canonical.GetSnapshot().configuration_generation;
        Check(canonical.Open(ReadyConfiguration(canonical)).opened &&
                  canonical.GetSnapshot().configuration_generation ==
                      reopened_generation,
              "identical Open call within one epoch is idempotent");
        auto next_configuration = ReadyConfiguration(canonical);
        ++next_configuration.prerequisites.validation_generation;
        Check(canonical.Open(next_configuration).opened &&
                  canonical.GetSnapshot().configuration_generation >
                      reopened_generation,
              "changed configuration advances its generation");

        auto first = canonical.AcquireLocal(
            Path::InternalMining, BlockSubject(), std::nullopt, false,
            Coordinator::Duration{10});
        auto competitor = canonical.AcquireLocal(
            Path::SubmitBlock, BlockSubject(), std::nullopt, false,
            Coordinator::Duration{10});
        Check(first && competitor,
              "two prepared local tickets may coexist before canonical claim");
        Check(!first.lease->ClaimForCanonicalCommit() &&
                  canonical.GetSnapshot().phase == Coordinator::Phase::Closing,
              "canonical claim defers behind a competing acquired-first ticket");
        competitor.lease->Release();
        first.lease->Release();
        Check(canonical.GetSnapshot().phase == Coordinator::Phase::Closed,
              "competing ticket deferral drains boundedly without a sink");

        Check(canonical.Open(ReadyConfiguration(canonical)).opened,
              "shutdown-cancel coordinator reopens");
        auto pending = canonical.AcquireLocal(
            Path::SynchronousGeneration, BlockSubject(), std::nullopt, false,
            Coordinator::Duration{10});
        const uint64_t pending_generation =
            pending.lease->configuration_generation();
        canonical.CancelAndClose(Refusal::NodeNotRunning);
        Check(!pending.lease->IsLive() &&
                  !pending.lease->ClaimForCanonicalCommit() &&
                  canonical.GetSnapshot().configuration_generation >
                      pending_generation,
              "shutdown cancellation invalidates pending ticket generation");
    }

    for (const Path path : {Path::InternalMining, Path::SubmitBlock,
                            Path::SynchronousGeneration}) {
        Coordinator equivalent(limits, CounterMint(
            std::make_shared<std::atomic<uint64_t>>(0)), now);
        Check(equivalent.Open(ReadyConfiguration(equivalent)).opened,
              "equivalent block-production path coordinator opens");
        auto ticket = equivalent.AcquireLocal(
            path, BlockSubject(), std::nullopt, false,
            Coordinator::Duration{10});
        Check(ticket && ticket.decision.binding &&
                  ticket.decision.binding->subject == BlockSubject(),
              "equivalent block-production path uses canonical subject");
        Check(ticket.lease->ClaimForCanonicalCommit(),
              "equivalent block-production path reaches one-use claim");
        ticket.lease->Release();
        Check(equivalent.GetSnapshot().phase == Coordinator::Phase::Closed &&
                  equivalent.GetSnapshot().active_leases == 0,
              "equivalent block-production path drains without retained work");
    }

    std::cout << "PASS daybreak_work_admission_coordinator_tests checks="
              << checks << "\n";
    return 0;
}
