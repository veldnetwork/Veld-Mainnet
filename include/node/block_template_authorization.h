#pragma once

#include "work_admission.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace veld::work_admission {

class BlockTemplateAuthorizationStore;

// Move-free immutable authority handed from the RPC reservation boundary to
// LocalWorkAdmissionTicket preparation. Construction is private to the store;
// the exact binding/epoch can be claimed once and only before its deadline.
class BlockTemplateAuthorizationClaim {
public:
    using Clock = std::chrono::steady_clock;
    using NowFn = std::function<Clock::time_point()>;

    BlockTemplateAuthorizationClaim(
        const BlockTemplateAuthorizationClaim&) = delete;
    BlockTemplateAuthorizationClaim& operator=(
        const BlockTemplateAuthorizationClaim&) = delete;

    bool ClaimForTicket(const Binding& expected_binding,
                        uint64_t expected_coordinator_generation) noexcept {
        if (binding_ != expected_binding ||
            coordinator_generation_ != expected_coordinator_generation ||
            Now_() >= deadline_)
            return false;
        bool expected = false;
        if (!claimed_.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel))
            return false;
        // A clock advance or injected boundary interleave between the first
        // check and one-use CAS must not extend authorization past deadline.
        return Now_() < deadline_;
    }

    bool IsLive() const noexcept {
        return !claimed_.load(std::memory_order_acquire) &&
            Now_() < deadline_;
    }

    bool IsClaimedAndLive() const noexcept {
        return claimed_.load(std::memory_order_acquire) &&
            Now_() < deadline_;
    }

    const Binding& binding() const noexcept { return binding_; }
    uint64_t coordinator_generation() const noexcept {
        return coordinator_generation_;
    }
    std::chrono::steady_clock::time_point deadline() const noexcept {
        return deadline_;
    }

private:
    friend class BlockTemplateAuthorizationStore;

    BlockTemplateAuthorizationClaim(
            const Binding& binding, uint64_t coordinator_generation,
            Clock::time_point deadline, NowFn now)
        : binding_(binding),
          coordinator_generation_(coordinator_generation),
          deadline_(deadline), now_(std::move(now)) {}

    Clock::time_point Now_() const noexcept {
        try { return now_ ? now_() : Clock::now(); }
        catch (...) { return Clock::time_point::max(); }
    }

    const Binding binding_{};
    const uint64_t coordinator_generation_{0};
    const Clock::time_point deadline_{};
    const NowFn now_;
    std::atomic<bool> claimed_{false};
};

// Bounded node-owned bearer capabilities for the GBT -> submitblock boundary.
// A serialized Binding is an identity document and is caller-constructible;
// only a token retained in this store proves that this process issued the exact
// template.  Records do not reserve AdmissionCoordinator leases, so requesting
// templates cannot delay canonical peer admission.  A matching submit consumes
// its record atomically and is then converted by VeldNode into the ordinary
// one-use LocalWorkAdmissionTicket.
class BlockTemplateAuthorizationStore {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    using Duration = std::chrono::milliseconds;
    using TokenBytes = std::array<uint8_t, 32>;
    using TokenMintFn = std::function<bool(TokenBytes&)>;
    using NowFn = std::function<TimePoint()>;

    static constexpr Duration ABSOLUTE_MAX_LIFETIME{10000};

    struct Limits {
        Duration max_lifetime{10000};
        size_t max_active{64};
        size_t max_spent{128};
    };

    enum class Error : uint8_t {
        None,
        Invalid,
        Expired,
        Capacity,
        TokenMintUnavailable,
        TokenMintFailed,
        TokenCollision,
        TokenUnknown,
        TokenConsumed,
        BindingMismatch,
    };

    struct Issued {
        std::string token;
        Binding binding{};
        uint64_t coordinator_generation{0};
        TimePoint deadline{};
        Duration ttl{};
    };

    struct IssueResult {
        Error error{Error::Invalid};
        std::optional<Issued> authorization;

        explicit operator bool() const noexcept {
            return error == Error::None && authorization.has_value();
        }
    };

    struct ConsumeResult {
        Error error{Error::Invalid};
        std::shared_ptr<BlockTemplateAuthorizationClaim> authorization;

        explicit operator bool() const noexcept {
            return error == Error::None &&
                static_cast<bool>(authorization);
        }
    };

    struct Snapshot {
        size_t active{0};
        size_t spent{0};
    };

    BlockTemplateAuthorizationStore()
        : BlockTemplateAuthorizationStore(
              Limits{}, TokenMintFn{}, NowFn{}) {}

    explicit BlockTemplateAuthorizationStore(
            Limits limits, TokenMintFn mint = TokenMintFn{},
            NowFn now = NowFn{})
        : limits_(NormalizeLimits_(limits)), token_mint_(std::move(mint)),
          now_(std::move(now)) {}

    BlockTemplateAuthorizationStore(
        const BlockTemplateAuthorizationStore&) = delete;
    BlockTemplateAuthorizationStore& operator=(
        const BlockTemplateAuthorizationStore&) = delete;

    IssueResult Issue(const Binding& binding,
                      uint64_t coordinator_generation,
                      Duration requested_lifetime) noexcept {
        IssueResult result;
        try {
            if (!ValidIssuedBinding_(binding) ||
                coordinator_generation == 0 ||
                requested_lifetime <= Duration::zero()) {
                result.error = Error::Invalid;
                return result;
            }

            // These construction-time callbacks are immutable. Copy their
            // type-erased targets before taking the store mutex: an arbitrary
            // target copy constructor is external code and may re-enter.
            TokenMintFn mint = token_mint_;
            if (!mint) {
                result.error = Error::TokenMintUnavailable;
                return result;
            }

            std::array<TokenBytes, 8> candidates{};
            size_t candidate_count = 0;
            for (; candidate_count < candidates.size(); ++candidate_count) {
                if (!mint(candidates[candidate_count])) break;
            }
            if (candidate_count == 0) {
                result.error = Error::TokenMintFailed;
                return result;
            }

            // The injected clock is an external callback. Sample it before
            // taking the store mutex so a test clock (or a future clock
            // adapter) cannot re-enter the store and self-deadlock. Sampling
            // before issuance is conservative: lock contention can only
            // shorten, never extend, the resulting authority lifetime.
            const bool injected_clock = static_cast<bool>(now_);
            const TimePoint sampled_now = injected_clock
                ? SampleInjectedNow_() : TimePoint{};
            std::lock_guard<std::mutex> lock(mutex_);
            const TimePoint now = injected_clock
                ? sampled_now : Clock::now();
            PruneLocked_(now);
            if (now == TimePoint::max()) {
                result.error = Error::Expired;
                return result;
            }

            // A coordinator epoch change makes every older template stale.
            // Retire those records before enforcing the cap so stale work
            // cannot consume the issuance budget until wall-clock expiry.
            for (auto it = active_.begin(); it != active_.end();) {
                if (it->coordinator_generation == coordinator_generation &&
                    SameAuthorityDomain_(it->binding, binding)) {
                    ++it;
                    continue;
                }
                (void)RememberSpentLocked_(it->token, it->deadline);
                it = active_.erase(it);
            }
            PruneLocked_(now);
            if (active_.size() >= limits_.max_active ||
                spent_.size() >= limits_.max_spent) {
                result.error = Error::Capacity;
                return result;
            }

            std::optional<TokenBytes> selected;
            for (size_t i = 0; i < candidate_count; ++i) {
                if (!TokenIsZero_(candidates[i]) &&
                    !TokenKnownLocked_(candidates[i])) {
                    selected = candidates[i];
                    break;
                }
            }
            if (!selected) {
                result.error = Error::TokenCollision;
                return result;
            }

            const Duration ttl = std::min(
                {requested_lifetime, limits_.max_lifetime,
                 ABSOLUTE_MAX_LIFETIME});
            const TimePoint deadline = now + ttl;
            // Build the externally returned value before mutating the store.
            // If string allocation fails, no unreachable active capability is
            // retained. Moving the completed value into optional is noexcept
            // for its default-allocator string/shared fixed-width fields.
            Issued published{EncodeToken_(*selected), binding,
                             coordinator_generation, deadline, ttl};
            active_.push_back(
                Record{*selected, binding, coordinator_generation, deadline});
            try {
                result.authorization.emplace(std::move(published));
            } catch (...) {
                active_.pop_back();
                throw;
            }
            result.error = Error::None;
            return result;
        } catch (...) {
            // Public authorization APIs are fail-closed and noexcept. In
            // particular, memory pressure must not terminate the node.
            result.error = Error::Capacity;
            result.authorization.reset();
            return result;
        }
    }

    // Exact mismatch does not consume a capability. Exact successful lookup
    // moves it to the bounded spent set before returning, so two concurrent
    // submitters can never both obtain authority.
    ConsumeResult Consume(const std::string& token_text,
                          const Binding& binding,
                          uint64_t coordinator_generation) noexcept {
        ConsumeResult result;
        try {
            const auto token = DecodeToken_(token_text);
            if (!token || !ValidIssuedBinding_(binding) ||
                coordinator_generation == 0) {
                result.error = Error::Invalid;
                return result;
            }

            // See Issue(): never invoke the injected clock while holding the
            // store mutex. The detached claim performs a second current-time
            // check before it can become a canonical ticket, so a deadline
            // crossed while waiting for this bounded mutex cannot commit.
            const bool injected_clock = static_cast<bool>(now_);
            const TimePoint sampled_now = injected_clock
                ? SampleInjectedNow_() : TimePoint{};
            // Copy the injected clock before taking the mutex. Moving this
            // prepared std::function into the detached claim is noexcept;
            // no arbitrary target copy constructor runs in the critical
            // section.
            NowFn claim_clock = now_;
            std::lock_guard<std::mutex> lock(mutex_);
            const TimePoint now = injected_clock
                ? sampled_now : Clock::now();
            PruneLocked_(now);
            for (auto it = active_.begin(); it != active_.end(); ++it) {
                if (!TokenEqual_(it->token, *token)) continue;
                if (it->binding != binding ||
                    it->coordinator_generation != coordinator_generation) {
                    result.error = Error::BindingMismatch;
                    return result;
                }
                if (now == TimePoint::max() || it->deadline <= now) {
                    (void)RememberSpentLocked_(it->token, it->deadline);
                    active_.erase(it);
                    result.error = Error::Expired;
                    return result;
                }
                std::shared_ptr<BlockTemplateAuthorizationClaim> consumed(
                    new BlockTemplateAuthorizationClaim(
                        it->binding, it->coordinator_generation,
                        it->deadline, std::move(claim_clock)));
                (void)RememberSpentLocked_(it->token, it->deadline);
                active_.erase(it);
                result.error = Error::None;
                result.authorization = std::move(consumed);
                return result;
            }
            result.error = SpentKnownLocked_(*token)
                ? Error::TokenConsumed : Error::TokenUnknown;
            return result;
        } catch (...) {
            result.error = Error::Capacity;
            result.authorization.reset();
            return result;
        }
    }

    void CancelAll() noexcept {
        const bool injected_clock = static_cast<bool>(now_);
        const TimePoint sampled_now = injected_clock
            ? SampleInjectedNow_() : TimePoint{};
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            const TimePoint now = injected_clock
                ? sampled_now : Clock::now();
            PruneLocked_(now);
            for (const auto& record : active_)
                (void)RememberSpentLocked_(record.token, record.deadline);
            // Retiring authority is mandatory even if a replay-label
            // allocation failed; unknown capabilities still fail closed.
            active_.clear();
            PruneLocked_(now);
        } catch (...) {
            // A mutex failure is not recoverable here, but no exception may
            // escape a shutdown/fail-stop path.
        }
    }

    Snapshot GetSnapshot() const noexcept {
        const bool injected_clock = static_cast<bool>(now_);
        const TimePoint sampled_now = injected_clock
            ? SampleInjectedNow_() : TimePoint{};
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            const TimePoint now = injected_clock
                ? sampled_now : Clock::now();
            PruneLocked_(now);
            return Snapshot{active_.size(), spent_.size()};
        } catch (...) {
            return {};
        }
    }

    static const char* ErrorName(Error error) noexcept {
        switch (error) {
            case Error::None: return "none";
            case Error::Invalid: return "invalid";
            case Error::Expired: return "expired";
            case Error::Capacity: return "capacity";
            case Error::TokenMintUnavailable: return "token_mint_unavailable";
            case Error::TokenMintFailed: return "token_mint_failed";
            case Error::TokenCollision: return "token_collision";
            case Error::TokenUnknown: return "token_unknown";
            case Error::TokenConsumed: return "token_consumed";
            case Error::BindingMismatch: return "binding_mismatch";
        }
        return "unknown";
    }

private:
    struct Record {
        TokenBytes token{};
        Binding binding{};
        uint64_t coordinator_generation{0};
        TimePoint deadline{};
    };

    struct Spent {
        TokenBytes token{};
        TimePoint forget_after{};
    };

    static Limits NormalizeLimits_(Limits limits) noexcept {
        if (limits.max_lifetime <= Duration::zero())
            limits.max_lifetime = Duration{1};
        limits.max_lifetime = std::min(
            limits.max_lifetime, ABSOLUTE_MAX_LIFETIME);
        limits.max_active = std::max<size_t>(1, limits.max_active);
        limits.max_spent = std::max(limits.max_active, limits.max_spent);
        return limits;
    }

    static bool ValidIssuedBinding_(const Binding& binding) noexcept {
        const auto& subject = binding.subject;
        return binding.version == 1 &&
            subject.purpose == Purpose::BlockProduction &&
            subject.height > 0 &&
            subject.parent_height != UINT64_MAX &&
            subject.height == subject.parent_height + 1 &&
            !HashIsZero(subject.parent_hash) &&
            !HashIsZero(subject.target_hash) &&
            binding.validation_generation > 0 &&
            binding.network_magic != 0 &&
            !HashIsZero(binding.genesis_hash) &&
            !HashIsZero(binding.profile_digest);
    }

    static bool SameAuthorityDomain_(const Binding& lhs,
                                     const Binding& rhs) noexcept {
        return lhs.validation_generation == rhs.validation_generation &&
            lhs.network_magic == rhs.network_magic &&
            lhs.genesis_hash == rhs.genesis_hash &&
            lhs.profile_digest == rhs.profile_digest;
    }

    static bool TokenIsZero_(const TokenBytes& token) noexcept {
        uint8_t aggregate = 0;
        for (const uint8_t byte : token) aggregate |= byte;
        return aggregate == 0;
    }

    static bool TokenEqual_(const TokenBytes& lhs,
                            const TokenBytes& rhs) noexcept {
        uint8_t difference = 0;
        for (size_t i = 0; i < lhs.size(); ++i)
            difference |= static_cast<uint8_t>(lhs[i] ^ rhs[i]);
        return difference == 0;
    }

    static std::string EncodeToken_(const TokenBytes& token) {
        return BytesToHex(token.data(), token.size());
    }

    static std::optional<TokenBytes> DecodeToken_(
            const std::string& encoded) noexcept {
        if (encoded.size() != TokenBytes{}.size() * 2U)
            return std::nullopt;
        TokenBytes token{};
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
        };
        for (size_t i = 0; i < token.size(); ++i) {
            const int high = nibble(encoded[2 * i]);
            const int low = nibble(encoded[2 * i + 1]);
            if (high < 0 || low < 0) return std::nullopt;
            token[i] = static_cast<uint8_t>((high << 4) | low);
        }
        return TokenIsZero_(token) ? std::nullopt
                                   : std::optional<TokenBytes>(token);
    }

    TimePoint SampleInjectedNow_() const noexcept {
        try { return now_ ? now_() : TimePoint::max(); }
        catch (...) { return TimePoint::max(); }
    }

    bool TokenKnownLocked_(const TokenBytes& token) const noexcept {
        for (const auto& record : active_)
            if (TokenEqual_(record.token, token)) return true;
        return SpentKnownLocked_(token);
    }

    bool SpentKnownLocked_(const TokenBytes& token) const noexcept {
        for (const auto& spent : spent_)
            if (TokenEqual_(spent.token, token)) return true;
        return false;
    }

    bool RememberSpentLocked_(const TokenBytes& token,
                              TimePoint forget_after) const noexcept {
        if (SpentKnownLocked_(token) ||
            spent_.size() >= limits_.max_spent)
            return true;
        try {
            spent_.push_back(Spent{token, forget_after});
            return true;
        } catch (...) {
            // Replay labels improve diagnostics only. The active record is
            // still erased by the caller, so allocation failure cannot revive
            // or duplicate authority.
            return false;
        }
    }

    void PruneLocked_(TimePoint now) const noexcept {
        spent_.erase(
            std::remove_if(spent_.begin(), spent_.end(),
                [&](const Spent& spent) {
                    return spent.forget_after <= now;
                }),
            spent_.end());
        for (auto it = active_.begin(); it != active_.end();) {
            if (it->deadline > now) {
                ++it;
                continue;
            }
            (void)RememberSpentLocked_(it->token, it->deadline);
            it = active_.erase(it);
        }
    }

    Limits limits_{};
    TokenMintFn token_mint_;
    NowFn now_;
    mutable std::mutex mutex_;
    mutable std::vector<Record> active_;
    mutable std::vector<Spent> spent_;
};

}  // namespace veld::work_admission
