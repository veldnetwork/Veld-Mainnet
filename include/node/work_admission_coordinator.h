#pragma once

#include "work_admission.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace veld::work_admission {

// Serializes the local decision-to-sink boundary for work production and
// signing.  The coordinator deliberately owns no chain, network, or crypto
// objects: VeldNode must publish a coherent prerequisite snapshot while it
// holds its consensus-transition lock, then acquire and retain a Lease across
// the corresponding bounded irreversible sink.
class AdmissionCoordinator {
  private:
    struct SharedState;

  public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    using Duration = std::chrono::milliseconds;
    using TokenBytes = std::array<uint8_t, 32>;
    using TokenMintFn = std::function<bool(TokenBytes&)>;
    using NowFn = std::function<TimePoint()>;

    static constexpr Duration ABSOLUTE_MAX_LEASE{30000};

    enum class Phase : uint8_t {
        Closed,
        Open,
        Closing,
    };

    enum class Error : uint8_t {
        None,
        Closed,
        Closing,
        Busy,
        Rejected,
        InvalidDuration,
        Capacity,
        TokenMintUnavailable,
        TokenMintFailed,
        TokenCollision,
        TokenUnknown,
        TokenConsumed,
        PathPurposeMismatch,
    };

    struct Limits {
        Duration max_local_lease{250};
        Duration max_remote_lease{5000};
        size_t max_active_leases{64};
        size_t max_spent_tokens{128};
    };

    // role_permitted in prerequisites is ignored.  Role permission is
    // path-specific, so callers must populate permitted_paths explicitly.
    struct Configuration {
        Prerequisites prerequisites{};
        std::array<bool, 6> permitted_paths{};
        // Sampled before the caller reads prerequisites/peer state and checked
        // again after that complete snapshot. Open authenticates the sample
        // against the coordinator's current close epoch before any mutation.
        // Zero is an invalid sentinel: a default/caller-forged Configuration
        // cannot open the coordinator without a real epoch observation.
        uint64_t close_epoch{0};
    };

    class RemoteToken {
      public:
        RemoteToken() = default;

        static RemoteToken FromBytes(const TokenBytes& bytes) noexcept {
            return RemoteToken(bytes);
        }

        const TokenBytes& bytes() const noexcept {
            return bytes_;
        }

        bool IsZero() const noexcept {
            uint8_t aggregate = 0;
            for (const uint8_t byte : bytes_)
                aggregate |= byte;
            return aggregate == 0;
        }

      private:
        explicit RemoteToken(const TokenBytes& bytes) noexcept : bytes_(bytes) {}
        TokenBytes bytes_{};
    };

    // A valid Lease can only be constructed by this coordinator. It is
    // move-only, one-shot at the sink boundary, self-releasing, and becomes
    // unusable at its capped deadline or on emergency cancellation.
    class Lease {
      public:
        Lease() = default;
        ~Lease() {
            Release();
        }

        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;

        Lease(Lease&& other) noexcept {
            MoveFrom_(std::move(other));
        }

        Lease& operator=(Lease&& other) noexcept {
            if (this != &other) {
                Release();
                MoveFrom_(std::move(other));
            }
            return *this;
        }

        bool IsLive() const noexcept;

        // This is the final authorization linearization point for the sink.
        // It succeeds exactly once. The caller must retain this Lease through
        // the bounded commit/journal/sign/enqueue operation and must not begin
        // an irreversible action after IsLive() becomes false.
        bool ClaimForSink() noexcept;

        // Canonical block commit uses the same one-use lease, but it must also
        // close every competing acquisition before mutating the protected tip.
        // The coordinator mutex is the complete implementation boundary: this
        // method never calls chain, transport, RPC, wallet, DB, or filesystem
        // code.  An acquired-first close may preserve this exact lease; any
        // competing live record makes the claim fail closed.
        bool ClaimForCanonicalCommit() noexcept;

        void Release() noexcept;

        const Binding& binding() const noexcept {
            return binding_;
        }
        Path path() const noexcept {
            return path_;
        }
        TimePoint deadline() const noexcept {
            return deadline_;
        }
        uint64_t configuration_generation() const noexcept {
            return configuration_generation_;
        }

        explicit operator bool() const noexcept {
            return id_ != 0 && !state_.expired();
        }

      private:
        friend class AdmissionCoordinator;

        Lease(const std::shared_ptr<SharedState>& state, uint64_t id, Path path,
              const Binding& binding, TimePoint deadline,
              uint64_t configuration_generation) noexcept
            : state_(state), id_(id), path_(path), binding_(binding), deadline_(deadline),
              configuration_generation_(configuration_generation) {}

        void MoveFrom_(Lease&& other) noexcept {
            state_ = std::move(other.state_);
            id_ = std::exchange(other.id_, 0);
            path_ = other.path_;
            binding_ = other.binding_;
            deadline_ = other.deadline_;
            configuration_generation_ = other.configuration_generation_;
        }

        std::weak_ptr<SharedState> state_;
        uint64_t id_{0};
        Path path_{Path::InternalMining};
        Binding binding_{};
        TimePoint deadline_{};
        uint64_t configuration_generation_{0};
    };

    struct OpenResult {
        bool opened{false};
        Error error{Error::Closed};
        Refusal refusal{Refusal::Unwired};
    };

    struct CloseResult {
        bool new_acquisitions_closed{true};
        bool fully_closed{true};
        Refusal refusal{Refusal::RuntimeClosed};
        std::optional<TimePoint> completion_deadline;
    };

    struct LocalAttempt {
        Decision decision{};
        Error error{Error::Closed};
        std::optional<Lease> lease;

        explicit operator bool() const noexcept {
            return decision.allowed && lease.has_value();
        }
    };

    struct RemoteGrant {
        RemoteToken token{};
        Binding binding{};
        TimePoint deadline{};
        Duration ttl{};
    };

    struct RemoteAttempt {
        Decision decision{};
        Error error{Error::Closed};
        std::optional<RemoteGrant> grant;

        explicit operator bool() const noexcept {
            return decision.allowed && grant.has_value();
        }
    };

    struct RemoteConsumeAttempt {
        Decision decision{};
        Error error{Error::Closed};
        std::optional<Lease> lease;

        explicit operator bool() const noexcept {
            return decision.allowed && lease.has_value();
        }
    };

    struct Snapshot {
        Phase phase{Phase::Closed};
        bool configured{false};
        Refusal refusal{Refusal::Unwired};
        size_t active_leases{0};
        size_t pending_remote_tokens{0};
        size_t spent_remote_tokens{0};
        std::optional<TimePoint> close_deadline;
        uint64_t configuration_generation{0};
        uint64_t close_epoch{0};
    };

    AdmissionCoordinator() : AdmissionCoordinator(Limits{}, TokenMintFn{}, NowFn{}) {}

    explicit AdmissionCoordinator(Limits limits, TokenMintFn token_mint = TokenMintFn{},
                                  NowFn now = NowFn{});

    AdmissionCoordinator(const AdmissionCoordinator&) = delete;
    AdmissionCoordinator& operator=(const AdmissionCoordinator&) = delete;
    AdmissionCoordinator(AdmissionCoordinator&&) = delete;
    AdmissionCoordinator& operator=(AdmissionCoordinator&&) = delete;

    // Open linearizes while holding the coordinator mutex. It is refused
    // while an earlier bounded close or any live lease is outstanding.
    OpenResult Open(const Configuration& configuration) noexcept;

    // Callers take one sample before reading every prerequisite and a second
    // afterwards. A transition between those samples makes the configuration
    // explicitly closed; a transition after the second sample is caught by
    // Open's current-epoch comparison.
    uint64_t ObserveCloseEpoch() const noexcept;
    static bool BindCloseEpochSnapshot(Configuration& configuration, uint64_t before,
                                       uint64_t after) noexcept;

    // BeginClose immediately linearizes refusal of every new acquisition.
    // Work that acquired first may finish only until its already-capped
    // deadline; therefore the transition has a finite completion deadline and
    // cannot be postponed by a forgotten local lease or remote signer.
    CloseResult BeginClose(Refusal refusal = Refusal::RuntimeClosed) noexcept;

    // Safety-critical transitions may revoke all outstanding work at once.
    // Lease::IsLive and ClaimForSink then fail closed immediately.
    CloseResult CancelAndClose(Refusal refusal = Refusal::RuntimeClosed) noexcept;

    LocalAttempt AcquireLocal(Path path, const Subject& subject,
                              const std::optional<Binding>& prior, bool require_prior,
                              Duration requested_ttl) noexcept;

    // The mint callback must provide unpredictable, process-private 256-bit
    // values (for example SecureRandom in the eventual VeldNode wiring). A
    // missing/failing callback is closed; this header has no crypto fallback.
    RemoteAttempt IssueRemoteSigningLease(Path path, const Subject& subject,
                                          const std::optional<Binding>& prior, bool require_prior,
                                          Duration requested_ttl) noexcept;

    // Atomically authenticates and consumes a remote bearer capability,
    // re-evaluates its exact path/subject/prior binding, and converts it to the
    // same unforgeable local Lease used by in-process sinks. Replays fail.
    RemoteConsumeAttempt ConsumeRemoteSigningLease(const RemoteToken& token, Path path,
                                                   const Subject& subject,
                                                   const std::optional<Binding>& prior) noexcept;

    bool CancelRemoteSigningLease(const RemoteToken& token) noexcept;

    Snapshot GetSnapshot() const noexcept;

    static const char* ErrorName(Error error) noexcept {
        switch (error) {
        case Error::None:
            return "none";
        case Error::Closed:
            return "closed";
        case Error::Closing:
            return "closing";
        case Error::Busy:
            return "busy";
        case Error::Rejected:
            return "rejected";
        case Error::InvalidDuration:
            return "invalid_duration";
        case Error::Capacity:
            return "capacity";
        case Error::TokenMintUnavailable:
            return "token_mint_unavailable";
        case Error::TokenMintFailed:
            return "token_mint_failed";
        case Error::TokenCollision:
            return "token_collision";
        case Error::TokenUnknown:
            return "token_unknown";
        case Error::TokenConsumed:
            return "token_consumed";
        case Error::PathPurposeMismatch:
            return "path_purpose_mismatch";
        }
        return "unknown";
    }

    static std::string EncodeRemoteToken(const RemoteToken& token) {
        return BytesToHex(token.bytes().data(), token.bytes().size());
    }

    static std::optional<RemoteToken> DecodeRemoteToken(const std::string& encoded) noexcept {
        if (encoded.size() != TokenBytes{}.size() * 2U)
            return std::nullopt;
        TokenBytes bytes{};
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            return -1;
        };
        for (size_t i = 0; i < bytes.size(); ++i) {
            const int high = nibble(encoded[2 * i]);
            const int low = nibble(encoded[2 * i + 1]);
            if (high < 0 || low < 0)
                return std::nullopt;
            bytes[i] = static_cast<uint8_t>((high << 4) | low);
        }
        const RemoteToken token = RemoteToken::FromBytes(bytes);
        return token.IsZero() ? std::nullopt : std::optional<RemoteToken>(token);
    }

  private:
    enum class RecordKind : uint8_t {
        Local,
        RemotePending,
        RemoteConsumed,
    };

    struct Record {
        uint64_t id{0};
        RecordKind kind{RecordKind::Local};
        Path path{Path::InternalMining};
        Subject subject{};
        Binding binding{};
        TimePoint deadline{};
        uint64_t configuration_generation{0};
        bool sink_claimed{false};
        std::optional<TokenBytes> token;
    };

    struct SpentToken {
        TokenBytes token{};
        TimePoint forget_after{};
    };

    struct SharedState {
        explicit SharedState(Limits bounded_limits, TokenMintFn mint, NowFn clock)
            : limits(std::move(bounded_limits)), token_mint(std::move(mint)),
              now(std::move(clock)) {}

        mutable std::mutex mutex;
        Limits limits{};
        TokenMintFn token_mint;
        NowFn now;
        Phase phase{Phase::Closed};
        bool configured{false};
        Refusal refusal{Refusal::Unwired};
        Configuration configuration{};
        uint64_t configuration_generation{0};
        uint64_t next_id{1};
        std::optional<TimePoint> close_deadline;
        std::vector<Record> records;
        std::vector<SpentToken> spent_tokens;
        std::atomic<uint64_t> close_epoch{1};
        bool close_epoch_exhausted{false};
    };

    static Limits NormalizeLimits_(Limits limits) noexcept;
    static bool PathMatchesPurpose_(Path path, Purpose purpose) noexcept;
    static size_t PathIndex_(Path path) noexcept;
    static Refusal BasePrerequisiteRefusal_(const Prerequisites& prerequisites) noexcept;
    static Refusal NormalizeCloseRefusal_(Refusal refusal) noexcept;
    static bool ConfigurationEqual_(const Configuration& lhs, const Configuration& rhs) noexcept;
    static bool TokenEqual_(const TokenBytes& lhs, const TokenBytes& rhs) noexcept;
    static void AdvanceCloseEpochLocked_(SharedState& state) noexcept;

    static TimePoint NowLocked_(const SharedState& state) noexcept;
    static void RememberSpentLocked_(SharedState& state, const TokenBytes& token,
                                     TimePoint now) noexcept;
    static void FinalizeCloseLocked_(SharedState& state) noexcept;
    static void PruneLocked_(SharedState& state, TimePoint now) noexcept;
    static bool TokenKnownLocked_(const SharedState& state, const TokenBytes& token) noexcept;
    static Decision EvaluateLocked_(const SharedState& state, Path path, const Subject& subject,
                                    const std::optional<Binding>& prior,
                                    bool require_prior) noexcept;
    static uint64_t AllocateIdLocked_(SharedState& state) noexcept;
    static Record* FindRecordLocked_(SharedState& state, uint64_t id) noexcept;
    static Record* FindRemoteRecordLocked_(SharedState& state, const TokenBytes& token) noexcept;
    static bool SpentTokenKnownLocked_(const SharedState& state, const TokenBytes& token) noexcept;
    static bool LeaseLive_(const std::shared_ptr<SharedState>& state, uint64_t id, bool claim,
                           bool canonical_commit = false) noexcept;
    static void ReleaseLease_(const std::shared_ptr<SharedState>& state, uint64_t id) noexcept;

    std::shared_ptr<SharedState> state_;
};

inline AdmissionCoordinator::Limits AdmissionCoordinator::NormalizeLimits_(Limits limits) noexcept {
    const auto clamp_duration = [](Duration value, Duration fallback) {
        if (value <= Duration::zero())
            return fallback;
        return std::min(value, ABSOLUTE_MAX_LEASE);
    };
    limits.max_local_lease = clamp_duration(limits.max_local_lease, Duration{1});
    limits.max_remote_lease = clamp_duration(limits.max_remote_lease, Duration{1});
    limits.max_active_leases = std::max<size_t>(1, limits.max_active_leases);
    limits.max_spent_tokens = std::max(limits.max_active_leases, limits.max_spent_tokens);
    return limits;
}

inline AdmissionCoordinator::AdmissionCoordinator(Limits limits, TokenMintFn token_mint, NowFn now)
    : state_(std::make_shared<SharedState>(NormalizeLimits_(limits), std::move(token_mint),
                                           std::move(now))) {}

inline uint64_t AdmissionCoordinator::ObserveCloseEpoch() const noexcept {
    return state_->close_epoch.load(std::memory_order_acquire);
}

inline bool AdmissionCoordinator::BindCloseEpochSnapshot(Configuration& configuration,
                                                         uint64_t before, uint64_t after) noexcept {
    configuration.close_epoch = before;
    if (before != 0 && before == after)
        return true;
    configuration.prerequisites.runtime_open = false;
    configuration.prerequisites.peer_view_safe = false;
    return false;
}

inline bool AdmissionCoordinator::PathMatchesPurpose_(Path path, Purpose purpose) noexcept {
    switch (path) {
    case Path::InternalMining:
    case Path::GetBlockTemplate:
    case Path::SubmitBlock:
    case Path::SynchronousGeneration:
        return purpose == Purpose::BlockProduction;
    case Path::ValidatorEndorsement:
        return purpose == Purpose::ValidatorEndorsement;
    case Path::FinalityVote:
        return purpose == Purpose::FinalityVote;
    }
    return false;
}

inline size_t AdmissionCoordinator::PathIndex_(Path path) noexcept {
    return static_cast<size_t>(path);
}

inline Refusal AdmissionCoordinator::BasePrerequisiteRefusal_(const Prerequisites& p) noexcept {
    if (!p.node_running)
        return Refusal::NodeNotRunning;
    if (!p.startup_replay_complete)
        return Refusal::StartupReplayIncomplete;
    if (!p.independent_validation_complete)
        return Refusal::IndependentValidationIncomplete;
    if (!p.sync_complete)
        return Refusal::SyncIncomplete;
    if (!p.snapshot_state_clean)
        return Refusal::SnapshotStateUntrusted;
    if (!p.durable_state_proven)
        return Refusal::DurableStateUnproven;
    if (!p.datadir_identity_valid)
        return Refusal::DatadirIdentityUnproven;
    if (!p.checkpoint_anchor_valid)
        return Refusal::CheckpointAnchorUnproven;
    if (!p.canonical_tip_known)
        return Refusal::TipUnknown;
    if (!p.runtime_open)
        return Refusal::RuntimeClosed;
    if (!p.peer_view_safe)
        return Refusal::PeerViewUnsafe;
    return Refusal::None;
}

inline Refusal AdmissionCoordinator::NormalizeCloseRefusal_(Refusal refusal) noexcept {
    return refusal == Refusal::None ? Refusal::RuntimeClosed : refusal;
}

inline bool AdmissionCoordinator::ConfigurationEqual_(const Configuration& lhs,
                                                      const Configuration& rhs) noexcept {
    const auto& a = lhs.prerequisites;
    const auto& b = rhs.prerequisites;
    return lhs.close_epoch == rhs.close_epoch && lhs.permitted_paths == rhs.permitted_paths &&
           a.node_running == b.node_running &&
           a.startup_replay_complete == b.startup_replay_complete &&
           a.independent_validation_complete == b.independent_validation_complete &&
           a.sync_complete == b.sync_complete && a.snapshot_state_clean == b.snapshot_state_clean &&
           a.durable_state_proven == b.durable_state_proven &&
           a.datadir_identity_valid == b.datadir_identity_valid &&
           a.checkpoint_anchor_valid == b.checkpoint_anchor_valid &&
           a.canonical_tip_known == b.canonical_tip_known && a.runtime_open == b.runtime_open &&
           a.peer_view_safe == b.peer_view_safe &&
           a.validation_generation == b.validation_generation &&
           a.network_magic == b.network_magic && a.genesis_hash == b.genesis_hash &&
           a.profile_digest == b.profile_digest;
}

inline bool AdmissionCoordinator::TokenEqual_(const TokenBytes& lhs,
                                              const TokenBytes& rhs) noexcept {
    uint8_t difference = 0;
    for (size_t i = 0; i < lhs.size(); ++i)
        difference |= static_cast<uint8_t>(lhs[i] ^ rhs[i]);
    return difference == 0;
}

inline void AdmissionCoordinator::AdvanceCloseEpochLocked_(SharedState& state) noexcept {
    const uint64_t current = state.close_epoch.load(std::memory_order_relaxed);
    if (current == std::numeric_limits<uint64_t>::max()) {
        // Epoch exhaustion is a permanent fail-closed state. Reusing a wrapped
        // value could otherwise authenticate an ancient snapshot.
        state.close_epoch_exhausted = true;
        return;
    }
    state.close_epoch.store(current + 1, std::memory_order_release);
}

inline AdmissionCoordinator::TimePoint
AdmissionCoordinator::NowLocked_(const SharedState& state) noexcept {
    try {
        return state.now ? state.now() : Clock::now();
    } catch (...) {
        // A broken injected clock expires all work rather than extending it.
        return TimePoint::max();
    }
}

inline void AdmissionCoordinator::RememberSpentLocked_(SharedState& state, const TokenBytes& token,
                                                       TimePoint now) noexcept {
    for (const auto& spent : state.spent_tokens) {
        if (TokenEqual_(spent.token, token))
            return;
    }
    if (state.spent_tokens.size() >= state.limits.max_spent_tokens)
        return;
    const TimePoint forget_after =
        now == TimePoint::max() ? TimePoint::max() : now + state.limits.max_remote_lease;
    state.spent_tokens.push_back({token, forget_after});
}

inline void AdmissionCoordinator::FinalizeCloseLocked_(SharedState& state) noexcept {
    state.phase = Phase::Closed;
    state.close_deadline.reset();
}

inline void AdmissionCoordinator::PruneLocked_(SharedState& state, TimePoint now) noexcept {
    state.spent_tokens.erase(
        std::remove_if(state.spent_tokens.begin(), state.spent_tokens.end(),
                       [&](const SpentToken& spent) { return spent.forget_after <= now; }),
        state.spent_tokens.end());

    for (auto it = state.records.begin(); it != state.records.end();) {
        if (it->deadline > now) {
            ++it;
            continue;
        }
        if (it->token)
            RememberSpentLocked_(state, *it->token, now);
        it = state.records.erase(it);
    }

    if (state.phase == Phase::Closing &&
        (state.records.empty() || (state.close_deadline && *state.close_deadline <= now))) {
        for (const auto& record : state.records) {
            if (record.token)
                RememberSpentLocked_(state, *record.token, now);
        }
        state.records.clear();
        FinalizeCloseLocked_(state);
    }
}

inline bool AdmissionCoordinator::TokenKnownLocked_(const SharedState& state,
                                                    const TokenBytes& token) noexcept {
    for (const auto& record : state.records) {
        if (record.token && TokenEqual_(*record.token, token))
            return true;
    }
    return SpentTokenKnownLocked_(state, token);
}

inline Decision AdmissionCoordinator::EvaluateLocked_(const SharedState& state, Path path,
                                                      const Subject& subject,
                                                      const std::optional<Binding>& prior,
                                                      bool require_prior) noexcept {
    if (!PathMatchesPurpose_(path, subject.purpose))
        return {false, Refusal::SubjectNotCanonical, std::nullopt};
    Prerequisites prerequisites = state.configuration.prerequisites;
    const size_t index = PathIndex_(path);
    prerequisites.role_permitted = index < state.configuration.permitted_paths.size() &&
                                   state.configuration.permitted_paths[index];
    return Evaluate(subject, prerequisites, prior, require_prior);
}

inline uint64_t AdmissionCoordinator::AllocateIdLocked_(SharedState& state) noexcept {
    for (size_t attempts = 0; attempts <= state.records.size(); ++attempts) {
        uint64_t candidate = state.next_id++;
        if (candidate == 0)
            candidate = state.next_id++;
        bool used = false;
        for (const auto& record : state.records)
            used = used || record.id == candidate;
        if (!used)
            return candidate;
    }
    return 0;
}

inline AdmissionCoordinator::Record* AdmissionCoordinator::FindRecordLocked_(SharedState& state,
                                                                             uint64_t id) noexcept {
    for (auto& record : state.records)
        if (record.id == id)
            return &record;
    return nullptr;
}

inline AdmissionCoordinator::Record*
AdmissionCoordinator::FindRemoteRecordLocked_(SharedState& state,
                                              const TokenBytes& token) noexcept {
    for (auto& record : state.records) {
        if (record.kind == RecordKind::RemotePending && record.token &&
            TokenEqual_(*record.token, token))
            return &record;
    }
    return nullptr;
}

inline bool AdmissionCoordinator::SpentTokenKnownLocked_(const SharedState& state,
                                                         const TokenBytes& token) noexcept {
    for (const auto& spent : state.spent_tokens)
        if (TokenEqual_(spent.token, token))
            return true;
    return false;
}

inline AdmissionCoordinator::OpenResult
AdmissionCoordinator::Open(const Configuration& configuration) noexcept {
    std::lock_guard<std::mutex> lock(state_->mutex);
    const uint64_t close_epoch = state_->close_epoch.load(std::memory_order_acquire);
    if (configuration.close_epoch == 0 || state_->close_epoch_exhausted ||
        configuration.close_epoch != close_epoch) {
        const Refusal refusal =
            state_->refusal == Refusal::None ? Refusal::RuntimeClosed : state_->refusal;
        return {false, Error::Closed, refusal};
    }
    const TimePoint now = NowLocked_(*state_);
    PruneLocked_(*state_, now);
    if (state_->phase == Phase::Closing)
        return {false, Error::Closing, state_->refusal};
    if (!state_->records.empty() && !ConfigurationEqual_(state_->configuration, configuration))
        return {false, Error::Busy, state_->refusal};

    const bool configuration_changed =
        !state_->configured || !ConfigurationEqual_(state_->configuration, configuration);
    const bool reopening = state_->phase == Phase::Closed;
    if (configuration_changed || reopening) {
        ++state_->configuration_generation;
        if (state_->configuration_generation == 0)
            ++state_->configuration_generation;
    }

    state_->configured = true;
    const Refusal refusal = BasePrerequisiteRefusal_(configuration.prerequisites);
    if (refusal != Refusal::None) {
        AdvanceCloseEpochLocked_(*state_);
        state_->configuration = configuration;
        state_->phase = Phase::Closed;
        state_->refusal = refusal;
        state_->close_deadline.reset();
        return {false, Error::Rejected, refusal};
    }

    state_->configuration = configuration;
    state_->phase = Phase::Open;
    state_->refusal = Refusal::None;
    state_->close_deadline.reset();
    return {true, Error::None, Refusal::None};
}

inline AdmissionCoordinator::CloseResult
AdmissionCoordinator::BeginClose(Refusal refusal) noexcept {
    std::lock_guard<std::mutex> lock(state_->mutex);
    AdvanceCloseEpochLocked_(*state_);
    const TimePoint now = NowLocked_(*state_);
    PruneLocked_(*state_, now);
    state_->refusal = NormalizeCloseRefusal_(refusal);
    if (state_->phase == Phase::Closed) {
        return {true, true, state_->refusal, std::nullopt};
    }
    if (state_->records.empty()) {
        FinalizeCloseLocked_(*state_);
        return {true, true, state_->refusal, std::nullopt};
    }

    state_->phase = Phase::Closing;
    TimePoint deadline = now;
    for (const auto& record : state_->records)
        deadline = std::max(deadline, record.deadline);
    const TimePoint absolute_deadline =
        now == TimePoint::max() ? TimePoint::max() : now + ABSOLUTE_MAX_LEASE;
    deadline = std::min(deadline, absolute_deadline);
    state_->close_deadline = deadline;
    return {true, false, state_->refusal, deadline};
}

inline AdmissionCoordinator::CloseResult
AdmissionCoordinator::CancelAndClose(Refusal refusal) noexcept {
    std::lock_guard<std::mutex> lock(state_->mutex);
    AdvanceCloseEpochLocked_(*state_);
    const TimePoint now = NowLocked_(*state_);
    PruneLocked_(*state_, now);
    state_->refusal = NormalizeCloseRefusal_(refusal);
    for (const auto& record : state_->records) {
        if (record.token)
            RememberSpentLocked_(*state_, *record.token, now);
    }
    state_->records.clear();
    ++state_->configuration_generation;
    if (state_->configuration_generation == 0)
        ++state_->configuration_generation;
    FinalizeCloseLocked_(*state_);
    return {true, true, state_->refusal, std::nullopt};
}

inline AdmissionCoordinator::LocalAttempt
AdmissionCoordinator::AcquireLocal(Path path, const Subject& subject,
                                   const std::optional<Binding>& prior, bool require_prior,
                                   Duration requested_ttl) noexcept {
    LocalAttempt attempt;
    if (requested_ttl <= Duration::zero()) {
        attempt.error = Error::InvalidDuration;
        attempt.decision.refusal = Refusal::RuntimeClosed;
        return attempt;
    }

    std::lock_guard<std::mutex> lock(state_->mutex);
    const TimePoint now = NowLocked_(*state_);
    PruneLocked_(*state_, now);
    if (now == TimePoint::max()) {
        attempt.error = Error::Closed;
        attempt.decision.refusal = Refusal::RuntimeClosed;
        return attempt;
    }
    if (state_->phase != Phase::Open) {
        attempt.error = state_->phase == Phase::Closing ? Error::Closing : Error::Closed;
        attempt.decision.refusal = state_->configured ? state_->refusal : Refusal::Unwired;
        return attempt;
    }
    if (state_->records.size() >= state_->limits.max_active_leases) {
        attempt.error = Error::Capacity;
        attempt.decision.refusal = Refusal::RuntimeClosed;
        return attempt;
    }

    attempt.decision = EvaluateLocked_(*state_, path, subject, prior, require_prior);
    if (!attempt.decision.allowed || !attempt.decision.binding) {
        attempt.error = PathMatchesPurpose_(path, subject.purpose) ? Error::Rejected
                                                                   : Error::PathPurposeMismatch;
        return attempt;
    }

    const uint64_t id = AllocateIdLocked_(*state_);
    if (id == 0) {
        attempt.decision = {false, Refusal::RuntimeClosed, std::nullopt};
        attempt.error = Error::Capacity;
        return attempt;
    }
    const Duration ttl =
        std::min({requested_ttl, state_->limits.max_local_lease, ABSOLUTE_MAX_LEASE});
    const TimePoint deadline = now + ttl;
    state_->records.push_back(Record{id, RecordKind::Local, path, subject,
                                     *attempt.decision.binding, deadline,
                                     state_->configuration_generation, false, std::nullopt});
    attempt.error = Error::None;
    attempt.lease = Lease(state_, id, path, *attempt.decision.binding, deadline,
                          state_->configuration_generation);
    return attempt;
}

inline AdmissionCoordinator::RemoteAttempt
AdmissionCoordinator::IssueRemoteSigningLease(Path path, const Subject& subject,
                                              const std::optional<Binding>& prior,
                                              bool require_prior, Duration requested_ttl) noexcept {
    RemoteAttempt attempt;
    if (path != Path::ValidatorEndorsement && path != Path::FinalityVote) {
        attempt.error = Error::PathPurposeMismatch;
        attempt.decision.refusal = Refusal::SubjectNotCanonical;
        return attempt;
    }
    if (requested_ttl <= Duration::zero()) {
        attempt.error = Error::InvalidDuration;
        attempt.decision.refusal = Refusal::RuntimeClosed;
        return attempt;
    }

    TokenMintFn mint;
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        mint = state_->token_mint;
    }
    if (!mint) {
        attempt.error = Error::TokenMintUnavailable;
        attempt.decision.refusal = Refusal::Unwired;
        return attempt;
    }

    std::array<TokenBytes, 8> candidates{};
    size_t candidate_count = 0;
    try {
        for (; candidate_count < candidates.size(); ++candidate_count) {
            if (!mint(candidates[candidate_count]))
                break;
        }
    } catch (...) {
        candidate_count = 0;
    }
    if (candidate_count == 0) {
        attempt.error = Error::TokenMintFailed;
        attempt.decision.refusal = Refusal::RuntimeClosed;
        return attempt;
    }

    std::lock_guard<std::mutex> lock(state_->mutex);
    const TimePoint now = NowLocked_(*state_);
    PruneLocked_(*state_, now);
    if (now == TimePoint::max()) {
        attempt.error = Error::Closed;
        attempt.decision.refusal = Refusal::RuntimeClosed;
        return attempt;
    }
    if (state_->phase != Phase::Open) {
        attempt.error = state_->phase == Phase::Closing ? Error::Closing : Error::Closed;
        attempt.decision.refusal = state_->configured ? state_->refusal : Refusal::Unwired;
        return attempt;
    }
    size_t pending_remote = 0;
    for (const auto& record : state_->records)
        pending_remote += record.kind == RecordKind::RemotePending ? 1U : 0U;
    if (state_->records.size() >= state_->limits.max_active_leases ||
        state_->spent_tokens.size() + pending_remote >= state_->limits.max_spent_tokens) {
        attempt.error = Error::Capacity;
        attempt.decision.refusal = Refusal::RuntimeClosed;
        return attempt;
    }

    attempt.decision = EvaluateLocked_(*state_, path, subject, prior, require_prior);
    if (!attempt.decision.allowed || !attempt.decision.binding) {
        attempt.error = PathMatchesPurpose_(path, subject.purpose) ? Error::Rejected
                                                                   : Error::PathPurposeMismatch;
        return attempt;
    }

    std::optional<TokenBytes> selected;
    for (size_t i = 0; i < candidate_count; ++i) {
        RemoteToken candidate = RemoteToken::FromBytes(candidates[i]);
        if (!candidate.IsZero() && !TokenKnownLocked_(*state_, candidates[i])) {
            selected = candidates[i];
            break;
        }
    }
    if (!selected) {
        attempt.decision = {false, Refusal::RuntimeClosed, std::nullopt};
        attempt.error = Error::TokenCollision;
        return attempt;
    }

    const uint64_t id = AllocateIdLocked_(*state_);
    if (id == 0) {
        attempt.decision = {false, Refusal::RuntimeClosed, std::nullopt};
        attempt.error = Error::Capacity;
        return attempt;
    }
    const Duration ttl =
        std::min({requested_ttl, state_->limits.max_remote_lease, ABSOLUTE_MAX_LEASE});
    const TimePoint deadline = now + ttl;
    state_->records.push_back(Record{id, RecordKind::RemotePending, path, subject,
                                     *attempt.decision.binding, deadline,
                                     state_->configuration_generation, false, *selected});
    attempt.error = Error::None;
    attempt.grant =
        RemoteGrant{RemoteToken::FromBytes(*selected), *attempt.decision.binding, deadline, ttl};
    return attempt;
}

inline AdmissionCoordinator::RemoteConsumeAttempt
AdmissionCoordinator::ConsumeRemoteSigningLease(const RemoteToken& token, Path path,
                                                const Subject& subject,
                                                const std::optional<Binding>& prior) noexcept {
    RemoteConsumeAttempt attempt;
    std::lock_guard<std::mutex> lock(state_->mutex);
    const TimePoint now = NowLocked_(*state_);
    PruneLocked_(*state_, now);

    Record* record = FindRemoteRecordLocked_(*state_, token.bytes());
    if (!record) {
        attempt.error = SpentTokenKnownLocked_(*state_, token.bytes()) ? Error::TokenConsumed
                                                                       : Error::TokenUnknown;
        attempt.decision.refusal = Refusal::BindingMismatch;
        return attempt;
    }
    if (state_->phase == Phase::Closed || record->deadline <= now) {
        attempt.error = Error::Closed;
        attempt.decision.refusal = state_->refusal;
        return attempt;
    }
    if (record->path != path || record->subject != subject) {
        attempt.error = Error::PathPurposeMismatch;
        attempt.decision.refusal = Refusal::BindingMismatch;
        return attempt;
    }

    attempt.decision = EvaluateLocked_(*state_, path, subject, prior, true);
    if (!attempt.decision.allowed || !attempt.decision.binding ||
        *attempt.decision.binding != record->binding) {
        attempt.error = Error::Rejected;
        return attempt;
    }

    const uint64_t id = record->id;
    const Binding binding = record->binding;
    const TimePoint deadline = record->deadline;
    const TokenBytes consumed_token = *record->token;
    record->token.reset();
    record->kind = RecordKind::RemoteConsumed;
    RememberSpentLocked_(*state_, consumed_token, now);
    attempt.error = Error::None;
    attempt.lease = Lease(state_, id, path, binding, deadline, record->configuration_generation);
    return attempt;
}

inline bool AdmissionCoordinator::CancelRemoteSigningLease(const RemoteToken& token) noexcept {
    std::lock_guard<std::mutex> lock(state_->mutex);
    const TimePoint now = NowLocked_(*state_);
    PruneLocked_(*state_, now);
    for (auto it = state_->records.begin(); it != state_->records.end(); ++it) {
        if (it->kind != RecordKind::RemotePending || !it->token ||
            !TokenEqual_(*it->token, token.bytes()))
            continue;
        RememberSpentLocked_(*state_, *it->token, now);
        state_->records.erase(it);
        if (state_->phase == Phase::Closing && state_->records.empty())
            FinalizeCloseLocked_(*state_);
        return true;
    }
    return false;
}

inline AdmissionCoordinator::Snapshot AdmissionCoordinator::GetSnapshot() const noexcept {
    std::lock_guard<std::mutex> lock(state_->mutex);
    const TimePoint now = NowLocked_(*state_);
    PruneLocked_(*state_, now);
    Snapshot snapshot;
    snapshot.phase = state_->phase;
    snapshot.configured = state_->configured;
    snapshot.refusal = state_->refusal;
    snapshot.active_leases = state_->records.size();
    for (const auto& record : state_->records)
        snapshot.pending_remote_tokens += record.kind == RecordKind::RemotePending ? 1U : 0U;
    snapshot.spent_remote_tokens = state_->spent_tokens.size();
    snapshot.close_deadline = state_->close_deadline;
    snapshot.configuration_generation = state_->configuration_generation;
    snapshot.close_epoch = state_->close_epoch.load(std::memory_order_acquire);
    return snapshot;
}

inline bool AdmissionCoordinator::LeaseLive_(const std::shared_ptr<SharedState>& state, uint64_t id,
                                             bool claim, bool canonical_commit) noexcept {
    std::lock_guard<std::mutex> lock(state->mutex);
    const TimePoint now = NowLocked_(*state);
    PruneLocked_(*state, now);
    Record* record = FindRecordLocked_(*state, id);
    if (!record || record->deadline <= now || state->phase == Phase::Closed ||
        record->configuration_generation == 0 ||
        record->configuration_generation != state->configuration_generation)
        return false;
    if (claim) {
        if (record->sink_claimed)
            return false;
        if (canonical_commit) {
            if (record->path != Path::InternalMining && record->path != Path::SubmitBlock &&
                record->path != Path::SynchronousGeneration)
                return false;
            if (state->phase == Phase::Open)
                AdvanceCloseEpochLocked_(*state);
            state->phase = Phase::Closing;
            state->refusal = Refusal::BindingMismatch;
            TimePoint close_deadline = now;
            for (const auto& live_record : state->records)
                close_deadline = std::max(close_deadline, live_record.deadline);
            state->close_deadline = close_deadline;
            // The caller owns the canonical transition sequencer.  A different
            // acquired-first lease must complete outside that sequencer, so the
            // block attempt defers after closing every new acquisition.
            if (state->records.size() != 1)
                return false;
        }
        record->sink_claimed = true;
    }
    return true;
}

inline void AdmissionCoordinator::ReleaseLease_(const std::shared_ptr<SharedState>& state,
                                                uint64_t id) noexcept {
    std::lock_guard<std::mutex> lock(state->mutex);
    const TimePoint now = NowLocked_(*state);
    PruneLocked_(*state, now);
    state->records.erase(std::remove_if(state->records.begin(), state->records.end(),
                                        [&](const Record& record) { return record.id == id; }),
                         state->records.end());
    if (state->phase == Phase::Closing && state->records.empty())
        FinalizeCloseLocked_(*state);
}

inline bool AdmissionCoordinator::Lease::IsLive() const noexcept {
    const auto state = state_.lock();
    return id_ != 0 && state && AdmissionCoordinator::LeaseLive_(state, id_, false);
}

inline bool AdmissionCoordinator::Lease::ClaimForSink() noexcept {
    const auto state = state_.lock();
    return id_ != 0 && state && AdmissionCoordinator::LeaseLive_(state, id_, true);
}

inline bool AdmissionCoordinator::Lease::ClaimForCanonicalCommit() noexcept {
    const auto state = state_.lock();
    return id_ != 0 && state && AdmissionCoordinator::LeaseLive_(state, id_, true, true);
}

inline void AdmissionCoordinator::Lease::Release() noexcept {
    if (id_ == 0)
        return;
    const auto state = state_.lock();
    const uint64_t id = std::exchange(id_, 0);
    state_.reset();
    if (state)
        AdmissionCoordinator::ReleaseLease_(state, id);
}

} // namespace veld::work_admission
