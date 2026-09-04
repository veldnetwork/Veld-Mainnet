#pragma once

// Fail-closed runtime lease for the disposable public testnet.
//
// The lease is two compiled constants -- a height cap and a UTC
// instant -- so a downloaded client needs no credential file, no signature
// check, and no per-launch authorization to know when the disposable
// testnet stops.  Limits are never accepted as CLI strings.  The byte-exact
// owner-only session marker prevents changing the lease identity or either
// limit when the same role-bound datadir is restarted, and the durable clock
// high-water still catches wall-clock rollback across restarts.

#include "../core/constants.h"
#include "../core/hash.h"
#include "../core/version.h"
#include "../wallet/secure_channel_file.h"
#include "public_testnet_json.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <ctime>
#include <cstdint>
#include <limits>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace veld::public_testnet {

class ListenerActivationAuthorityRefusal final : public std::runtime_error {
  public:
    explicit ListenerActivationAuthorityRefusal(const std::string& message)
        : std::runtime_error(message) {}
};

inline constexpr const char* SESSION_MARKER_NAME = "public-testnet.session";
inline constexpr const char* SESSION_MARKER_HEADER = "VELD_PUBLIC_TESTNET_RUNTIME_V1";
inline constexpr const char* CLOCK_HIGH_WATER_NAME = "public-testnet.clock-high-water";
inline constexpr const char* CLOCK_HIGH_WATER_HEADER = "VELD_PUBLIC_TESTNET_CLOCK_HIGH_WATER_V1";
// CurrentUnixTime() and the platform monotonic clocks are sampled as integral
// seconds with unrelated sub-second phases.  Permit only that bounded
// quantization difference; a frozen/rolled-back wall clock still latches
// closed once suspend-aware elapsed time exceeds this allowance.
inline constexpr uint64_t CLOCK_CORRELATION_SLACK_SECONDS = 2;

struct RuntimeLimits {
    std::string lease_identity_sha256;
    uint64_t not_after_height{0};
    std::string not_after_utc;
    int64_t not_after_unix{0};

    bool TimePermitted(int64_t now_unix) const noexcept {
        return not_after_unix > 0 && now_unix >= 0 && now_unix < not_after_unix;
    }

    bool CandidateHeightPermitted(uint64_t candidate_height) const noexcept {
        return not_after_height > 0 && candidate_height <= not_after_height;
    }

    bool CandidatePermitted(uint64_t candidate_height, int64_t now_unix) const noexcept {
        return CandidateHeightPermitted(candidate_height) && TimePermitted(now_unix);
    }

    // A node may accept the terminal block itself, but it must stop official
    // service immediately afterward.  Therefore an already-running service is
    // open only while its canonical tip remains strictly below the height cap.
    bool ServicePermitted(uint64_t current_height, int64_t now_unix) const noexcept {
        return not_after_height > 0 && current_height < not_after_height && TimePermitted(now_unix);
    }
};

// Convert a sampled lease decision into a monotonic process latch. Once any
// ingest/mining/supervisor path observes closure, clock rollback or a stale
// caller can never reopen this process.
inline bool PermitOrLatchClosed(std::atomic<bool>& closed, bool sampled_permitted) noexcept {
    if (closed.load(std::memory_order_acquire))
        return false;
    if (!sampled_permitted) {
        closed.store(true, std::memory_order_release);
        return false;
    }
    return !closed.load(std::memory_order_acquire);
}

// The terminal block itself is admissible, but once that canonical frame is
// durable the process must close before any concurrent RPC, mining, mempool,
// or reorg path can observe service as open.  The outer one-second supervisor
// remains a shutdown mechanism, not the authority that first notices height
// expiry.  Invalid/missing limits are closed by construction.
inline void LatchClosedAtDurableCanonicalHeight(std::atomic<bool>& closed,
                                                const RuntimeLimits* limits,
                                                uint64_t durable_canonical_height) noexcept {
    if (!limits || limits->not_after_height == 0 ||
        durable_canonical_height >= limits->not_after_height) {
        closed.store(true, std::memory_order_release);
    }
}

inline int64_t CurrentUnixTime() noexcept {
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
    return seconds < 0 ? -1 : static_cast<int64_t>(seconds);
}

// Unlike std::chrono::steady_clock on Linux, CLOCK_BOOTTIME advances while the
// host is suspended. GetTickCount64 has the same property on Windows. There is
// deliberately no steady-clock fallback: unavailable suspend accounting makes
// testnet authority admission and observation fail closed.
inline constexpr uint64_t INVALID_SUSPEND_AWARE_SECONDS = UINT64_MAX;

inline bool TrySuspendAwareMonotonicSeconds(uint64_t& value) noexcept {
#ifdef _WIN32
    value = static_cast<uint64_t>(::GetTickCount64() / 1000ULL);
    return true;
#elif defined(CLOCK_BOOTTIME)
    struct timespec ts{};
    if (::clock_gettime(CLOCK_BOOTTIME, &ts) == 0 && ts.tv_sec >= 0) {
        value = static_cast<uint64_t>(ts.tv_sec);
        return true;
    }
#endif
    value = INVALID_SUSPEND_AWARE_SECONDS;
    return false;
}

inline uint64_t SuspendAwareMonotonicSeconds() noexcept {
    uint64_t value = INVALID_SUSPEND_AWARE_SECONDS;
    (void)TrySuspendAwareMonotonicSeconds(value);
    return value;
}

// A signed fleet restart bundle authorizes entry into Start(), not an
// unbounded delay after verification. Measure its lifetime from the
// pre-verification monotonic sample so verification work, wall-clock rollback,
// or a SIGSTOP/suspend cannot stretch the five-minute window. Both the signed
// time lower bound plus elapsed time and local UTC must remain strictly before
// the signed valid-until second.
inline bool RestartBundleFreshAt(int64_t signed_observed_unix, int64_t valid_until_unix,
                                 int64_t local_now_unix, uint64_t authority_monotonic_seconds,
                                 uint64_t current_monotonic_seconds) noexcept {
    if (signed_observed_unix <= 0 || valid_until_unix <= signed_observed_unix ||
        local_now_unix < 0 || local_now_unix >= valid_until_unix ||
        authority_monotonic_seconds == INVALID_SUSPEND_AWARE_SECONDS ||
        current_monotonic_seconds == INVALID_SUSPEND_AWARE_SECONDS ||
        current_monotonic_seconds < authority_monotonic_seconds)
        return false;
    const uint64_t elapsed = current_monotonic_seconds - authority_monotonic_seconds;
    if (elapsed > static_cast<uint64_t>(INT64_MAX) ||
        signed_observed_unix > INT64_MAX - static_cast<int64_t>(elapsed))
        return false;
    return signed_observed_unix + static_cast<int64_t>(elapsed) < valid_until_unix;
}

inline bool IsCanonicalSha256(const std::string& value) noexcept {
    if (value.size() != 64)
        return false;
    bool nonzero = false;
    for (char c : value) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
        nonzero = nonzero || c != '0';
    }
    return nonzero;
}

inline bool ParseCanonicalPositiveUint64(const std::string& value, uint64_t& out) noexcept {
    if (value.empty() || value.front() == '0')
        return false;
    uint64_t parsed = 0;
    for (char c : value) {
        if (c < '0' || c > '9')
            return false;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (parsed > (std::numeric_limits<uint64_t>::max() - digit) / 10)
            return false;
        parsed = parsed * 10 + digit;
    }
    if (parsed == 0)
        return false;
    out = parsed;
    return true;
}

inline bool IsLeapYear(int year) noexcept {
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

inline int DaysInMonth(int year, int month) noexcept {
    static constexpr int DAYS[] = {
        0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    };
    if (month < 1 || month > 12)
        return 0;
    return month == 2 && IsLeapYear(year) ? 29 : DAYS[month];
}

inline int64_t DaysFromCivil(int year, unsigned month, unsigned day) noexcept {
    year -= month <= 2;
    const int era = (year >= 0 ? year : year - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(year - era * 400);
    const unsigned month_prime = month > 2 ? month - 3 : month + 9;
    const unsigned doy = (153 * month_prime + 2) / 5 + day - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return static_cast<int64_t>(era) * 146097 + static_cast<int64_t>(doe) - 719468;
}

inline bool ParseCanonicalUtc(const std::string& value, int64_t& unix_seconds) noexcept {
    // Match the lifecycle schema exactly: one UTC second in 2000..2099.
    if (value.size() != 20 || value[4] != '-' || value[7] != '-' || value[10] != 'T' ||
        value[13] != ':' || value[16] != ':' || value[19] != 'Z')
        return false;
    for (size_t i :
         {size_t{0}, size_t{1}, size_t{2}, size_t{3}, size_t{5}, size_t{6}, size_t{8}, size_t{9},
          size_t{11}, size_t{12}, size_t{14}, size_t{15}, size_t{17}, size_t{18}}) {
        if (value[i] < '0' || value[i] > '9')
            return false;
    }
    auto decimal = [&](size_t offset, size_t length) noexcept {
        int result = 0;
        for (size_t i = 0; i < length; ++i)
            result = result * 10 + (value[offset + i] - '0');
        return result;
    };
    const int year = decimal(0, 4);
    const int month = decimal(5, 2);
    const int day = decimal(8, 2);
    const int hour = decimal(11, 2);
    const int minute = decimal(14, 2);
    const int second = decimal(17, 2);
    if (year < 2000 || year > 2099 || month < 1 || month > 12 || day < 1 ||
        day > DaysInMonth(year, month) || hour > 23 || minute > 59 || second > 59)
        return false;
    const int64_t days =
        DaysFromCivil(year, static_cast<unsigned>(month), static_cast<unsigned>(day));
    unix_seconds = days * 86400 + hour * 3600 + minute * 60 + second;
    return unix_seconds > 0;
}

// The disposable testnet has a scheduled end, and that end is the entire
// lease: one height cap and one UTC instant.  Both are compiled constants
// built into the profile, so a downloaded client knows when the
// testnet stops without a signed record, a credential file, or any
// per-launch authorization.  The lease identity is derived from those exact
// bytes, which is what binds a datadir to the lease it was created under.
inline constexpr uint64_t COMPILED_LEASE_NOT_AFTER_HEIGHT = 20000;
inline constexpr const char* COMPILED_LEASE_NOT_AFTER_UTC = "2026-08-30T18:00:00Z";

inline bool CompiledRuntimeLimits(int64_t now_unix, RuntimeLimits& out,
                                  std::string* error = nullptr) {
#if !defined(VELD_PUBLIC_TESTNET)
    (void)now_unix;
    (void)out;
    if (error)
        *error = "the public-testnet lease is unavailable outside that profile";
    return false;
#else
    RuntimeLimits limits;
    limits.not_after_height = COMPILED_LEASE_NOT_AFTER_HEIGHT;
    limits.not_after_utc = COMPILED_LEASE_NOT_AFTER_UTC;
    if (limits.not_after_height == 0 ||
        !ParseCanonicalUtc(limits.not_after_utc, limits.not_after_unix) ||
        limits.not_after_unix <= 0) {
        if (error)
            *error = "compiled public-testnet lease is malformed";
        return false;
    }
    if (now_unix < 0 || now_unix >= limits.not_after_unix) {
        if (error)
            *error = "the public testnet has ended, or the local clock is invalid";
        return false;
    }
    const std::string identity = std::string("veld-public-testnet-compiled-lease-v1\n") +
                                 "profile_id=" + DEPLOYMENT_PROFILE_ID + "\n" +
                                 "genesis_hash=" + GENESIS_HASH + "\n" +
                                 "not_after_height=" + std::to_string(limits.not_after_height) +
                                 "\n" + "not_after_utc=" + limits.not_after_utc + "\n";
    SHA256 hasher;
    hasher.update(reinterpret_cast<const uint8_t*>(identity.data()), identity.size());
    limits.lease_identity_sha256 = BytesToHex(hasher.digest());
    if (!IsCanonicalSha256(limits.lease_identity_sha256)) {
        if (error)
            *error = "compiled public-testnet lease identity is invalid";
        return false;
    }
    out = std::move(limits);
    if (error)
        error->clear();
    return true;
#endif
}

inline bool ParseRuntimeLimits(const std::string& lease_identity_sha256,
                               const std::string& not_after_height,
                               const std::string& not_after_utc, int64_t now_unix,
                               RuntimeLimits& out, std::string* error = nullptr) {
    RuntimeLimits parsed;
    if (!IsCanonicalSha256(lease_identity_sha256)) {
        if (error)
            *error = "--testnet-start-index-sha256 must be 64 lowercase nonzero hex characters";
        return false;
    }
    if (!ParseCanonicalPositiveUint64(not_after_height, parsed.not_after_height)) {
        if (error)
            *error = "START not_after_height must be a canonical positive decimal integer";
        return false;
    }
    if (!ParseCanonicalUtc(not_after_utc, parsed.not_after_unix)) {
        if (error)
            *error = "START not_after_utc must be canonical YYYY-MM-DDTHH:MM:SSZ in 2000..2099";
        return false;
    }
    if (now_unix < 0 || now_unix >= parsed.not_after_unix) {
        if (error)
            *error =
                "public-testnet not-after UTC is already reached or the local clock is invalid";
        return false;
    }
    parsed.lease_identity_sha256 = lease_identity_sha256;
    parsed.not_after_utc = not_after_utc;
    out = std::move(parsed);
    if (error)
        error->clear();
    return true;
}

inline std::string CanonicalClockHighWater(const RuntimeLimits& limits, int64_t observed_unix) {
    return std::string(CLOCK_HIGH_WATER_HEADER) + "\n" +
           "lease_identity_sha256=" + limits.lease_identity_sha256 + "\n" +
           "not_after_unix=" + std::to_string(limits.not_after_unix) + "\n" +
           "observed_unix=" + std::to_string(observed_unix) + "\n";
}

inline bool ReadClockHighWater(const std::string& data_dir, const RuntimeLimits& limits,
                               int64_t& observed_unix, bool& missing,
                               std::string* error = nullptr) {
    observed_unix = 0;
    missing = false;
    std::vector<uint8_t> bytes;
    std::string read_error;
    const std::string path = data_dir + "/" + CLOCK_HIGH_WATER_NAME;
    const auto result = channel::secure_file::Read(path, bytes, &read_error, 1024,
                                                   /*require_private_parent=*/true);
    if (result == channel::secure_file::ReadResult::NotFound) {
        missing = true;
        if (error)
            error->clear();
        return true;
    }
    if (result != channel::secure_file::ReadResult::Ok) {
        if (error) {
            *error = "cannot securely read public-testnet UTC high-water";
            if (!read_error.empty())
                *error += ": " + read_error;
        }
        return false;
    }

    const std::string wire(bytes.begin(), bytes.end());
    channel::secure_file::WipeAndClear(bytes);
    const std::string prefix = std::string(CLOCK_HIGH_WATER_HEADER) + "\n" +
                               "lease_identity_sha256=" + limits.lease_identity_sha256 + "\n" +
                               "not_after_unix=" + std::to_string(limits.not_after_unix) + "\n" +
                               "observed_unix=";
    if (wire.size() <= prefix.size() + 1 || wire.compare(0, prefix.size(), prefix) != 0 ||
        wire.back() != '\n') {
        if (error)
            *error = "public-testnet UTC high-water is malformed or bound to another START index";
        return false;
    }
    const std::string decimal = wire.substr(prefix.size(), wire.size() - prefix.size() - 1);
    uint64_t parsed = 0;
    if (!ParseCanonicalPositiveUint64(decimal, parsed) ||
        parsed > static_cast<uint64_t>(INT64_MAX)) {
        if (error)
            *error = "public-testnet UTC high-water timestamp is not canonical";
        return false;
    }
    observed_unix = static_cast<int64_t>(parsed);
    if (wire != CanonicalClockHighWater(limits, observed_unix)) {
        if (error)
            *error = "public-testnet UTC high-water is not byte-exact canonical data";
        return false;
    }
    if (error)
        error->clear();
    return true;
}

inline bool CheckPersistedClockHighWater(const std::string& data_dir, const RuntimeLimits& limits,
                                         int64_t now_unix, bool require_existing,
                                         std::string* error = nullptr) {
    int64_t persisted = 0;
    bool missing = false;
    if (!ReadClockHighWater(data_dir, limits, persisted, missing, error))
        return false;
    if (missing && require_existing) {
        if (error)
            *error = "existing public-testnet session is missing its UTC high-water";
        return false;
    }
    if (!missing && (now_unix < 0 || now_unix < persisted)) {
        if (error)
            *error = "local UTC is behind the owner-only public-testnet high-water; clock rollback "
                     "is refused";
        return false;
    }
    if (error)
        error->clear();
    return true;
}

// Process-local monotonic/UTC correlation plus a durable owner-only wall-clock
// high-water.  This catches wall-clock rollback/freeze after the process has
// observed honest time and catches rollback behind a prior local observation
// across restart.  It is intentionally not described as trusted time: an
// already-backdated host before its first observation still requires an
// external clock authority, while the independent signed height cap remains
// absolute.
class RuntimeClockGuard {
  public:
    bool Initialize(const std::string& data_dir, const RuntimeLimits& limits, int64_t now_unix,
                    std::string* error = nullptr) {
        return InitializeAt(data_dir, limits, now_unix, SuspendAwareMonotonicSeconds(), error);
    }

    bool InitializeAt(const std::string& data_dir, const RuntimeLimits& limits, int64_t now_unix,
                      uint64_t monotonic_now, std::string* error = nullptr) {
        return InitializeAuthenticatedAt(data_dir, limits, now_unix, now_unix, monotonic_now,
                                         error);
    }

    // Initialize from one freshly signed owner time.  The signed value is an
    // independent lower bound on UTC, while local UTC remains subject to the
    // verifier's bounded-skew rule.  The effective high-water advances from
    // max(signed UTC + suspend-aware elapsed, local UTC), so wall-clock rollback
    // cannot stretch the testnet lease after authority admission.
    bool InitializeAuthenticatedAt(const std::string& data_dir, const RuntimeLimits& limits,
                                   int64_t signed_observed_unix, int64_t local_now_unix,
                                   uint64_t monotonic_now, std::string* error = nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (initialized_) {
            if (error)
                *error = "public-testnet clock guard is startup-only and immutable";
            return false;
        }
        if (signed_observed_unix <= 0 || local_now_unix < 0 ||
            monotonic_now == INVALID_SUSPEND_AWARE_SECONDS) {
            if (error)
                *error = "public-testnet clock guard requires authenticated and local UTC";
            return false;
        }
        const int64_t effective_now = std::max(signed_observed_unix, local_now_unix);
        if (!limits.TimePermitted(effective_now)) {
            if (error)
                *error =
                    "public-testnet clock guard cannot initialize at an invalid or expired UTC";
            return false;
        }
        std::string private_error;
        if (!channel::secure_file::EnsurePrivateDirectory(data_dir, &private_error)) {
            if (error)
                *error = "public-testnet clock datadir is unsafe: " + private_error;
            return false;
        }
        int64_t persisted = 0;
        bool missing = false;
        if (!ReadClockHighWater(data_dir, limits, persisted, missing, error))
            return false;
        // A durable session marker proves a prior startup crossed the clock
        // initialization boundary. Never recreate a missing high-water in
        // that state: deletion/torn state must fail closed. Conversely, an
        // existing high-water with no session marker is the intentionally
        // recoverable crash window before BindOrVerifySession publishes the
        // second file.
        bool session_exists = false;
        {
            std::vector<uint8_t> session_bytes;
            std::string session_error;
            const auto session_result = channel::secure_file::Read(
                data_dir + "/" + SESSION_MARKER_NAME, session_bytes, &session_error, 4096,
                /*require_private_parent=*/true);
            if (session_result == channel::secure_file::ReadResult::Ok) {
                session_exists = true;
                channel::secure_file::WipeAndClear(session_bytes);
            } else if (session_result != channel::secure_file::ReadResult::NotFound) {
                channel::secure_file::WipeAndClear(session_bytes);
                if (error) {
                    *error = "cannot securely inspect public-testnet session before clock "
                             "initialization";
                    if (!session_error.empty())
                        *error += ": " + session_error;
                }
                return false;
            }
        }
        if (missing && session_exists) {
            if (error)
                *error = "existing public-testnet session is missing its UTC high-water";
            return false;
        }
        if (!missing && effective_now < persisted) {
            if (error)
                *error = "authenticated/local UTC is behind the owner-only public-testnet "
                         "high-water; rollback is refused";
            return false;
        }

        data_dir_ = data_dir;
        limits_ = limits;
        anchor_wall_unix_ = local_now_unix;
        anchor_signed_unix_ = signed_observed_unix;
        last_wall_unix_ = local_now_unix;
        persisted_wall_unix_ = missing ? 0 : persisted;
        anchor_monotonic_seconds_ = monotonic_now;
        initialized_ = true;
        if (!PersistLocked(effective_now, error)) {
            closed_ = true;
            return false;
        }
        if (error)
            error->clear();
        return true;
    }

    bool ObserveNow(std::string* error = nullptr) noexcept {
        // Read wall UTC first and BOOTTIME second.  A suspend between samples
        // is therefore included in the decisive elapsed-time lower bound.
        const int64_t wall_now = CurrentUnixTime();
        const uint64_t monotonic_now = SuspendAwareMonotonicSeconds();
        return ObserveAt(wall_now, monotonic_now, error);
    }

    bool ObserveAt(int64_t now_unix, uint64_t monotonic_now,
                   std::string* error = nullptr) noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!initialized_ || closed_) {
                if (error)
                    *error = "public-testnet clock guard is unavailable or latched closed";
                return false;
            }
            if (now_unix < 0 || monotonic_now == INVALID_SUSPEND_AWARE_SECONDS ||
                monotonic_now < anchor_monotonic_seconds_ || now_unix < last_wall_unix_) {
                closed_ = true;
                if (error)
                    *error = "public-testnet wall clock moved backward";
                return false;
            }
            const uint64_t elapsed = monotonic_now - anchor_monotonic_seconds_;
            const uint64_t wall_elapsed = static_cast<uint64_t>(now_unix - anchor_wall_unix_);
            if (elapsed > wall_elapsed &&
                elapsed - wall_elapsed > CLOCK_CORRELATION_SLACK_SECONDS) {
                closed_ = true;
                if (error)
                    *error = "public-testnet wall clock stalled or rolled back relative to "
                             "monotonic time";
                return false;
            }
            last_wall_unix_ = now_unix;
            if (elapsed > static_cast<uint64_t>(INT64_MAX) ||
                anchor_signed_unix_ > INT64_MAX - static_cast<int64_t>(elapsed)) {
                closed_ = true;
                if (error)
                    *error = "public-testnet authenticated time arithmetic overflow";
                return false;
            }
            const int64_t signed_floor = anchor_signed_unix_ + static_cast<int64_t>(elapsed);
            const int64_t effective_now = std::max(now_unix, signed_floor);
            if (!PersistLocked(effective_now, error)) {
                closed_ = true;
                return false;
            }
            if (!limits_.TimePermitted(effective_now)) {
                closed_ = true;
                if (error)
                    *error = "public-testnet not-after UTC has been reached";
                return false;
            }
            if (error)
                error->clear();
            return true;
        } catch (...) {
            // This boundary is called from consensus/RPC/mining threads. No
            // allocation or filesystem exception may reopen service.
            closed_ = true;
            if (error)
                *error = "public-testnet clock observation failed closed";
            return false;
        }
    }

  private:
    bool PersistLocked(int64_t observed_unix, std::string* error) {
        if (observed_unix <= persisted_wall_unix_)
            return true;
        const std::string wire = CanonicalClockHighWater(limits_, observed_unix);
        const std::string path = data_dir_ + "/" + CLOCK_HIGH_WATER_NAME;
        std::string write_error;
        if (!channel::secure_file::AtomicWriteText(path, wire, &write_error,
                                                   /*require_private_parent=*/true)) {
            if (error)
                *error = "cannot atomically advance public-testnet UTC high-water: " + write_error;
            return false;
        }
        int64_t verified = 0;
        bool missing = false;
        if (!ReadClockHighWater(data_dir_, limits_, verified, missing, error) || missing ||
            verified < observed_unix) {
            if (error && error->empty())
                *error = "advanced public-testnet UTC high-water did not verify";
            return false;
        }
        persisted_wall_unix_ = verified;
        return true;
    }

    std::mutex mutex_;
    std::string data_dir_;
    RuntimeLimits limits_;
    uint64_t anchor_monotonic_seconds_{0};
    int64_t anchor_wall_unix_{0};
    int64_t anchor_signed_unix_{0};
    int64_t last_wall_unix_{0};
    int64_t persisted_wall_unix_{0};
    bool initialized_{false};
    std::atomic<bool> closed_{false};
};

inline bool LoadRuntimeLimitsFromStartIndex(const std::string& start_index_path,
                                            const std::string& expected_sha256, int64_t now_unix,
                                            RuntimeLimits& out, std::string* error = nullptr) {
    if (start_index_path.empty()) {
        if (error)
            *error = "--testnet-start-index requires an explicit file";
        return false;
    }
    if (!IsCanonicalSha256(expected_sha256)) {
        if (error)
            *error = "--testnet-start-index-sha256 must be 64 lowercase nonzero hex characters";
        return false;
    }

    std::vector<uint8_t> bytes;
    std::string read_error;
    const auto read = channel::secure_file::ReadExplicitImport(start_index_path, bytes, &read_error,
                                                               256u * 1024u);
    if (read != channel::secure_file::ReadResult::Ok) {
        if (error) {
            *error = "cannot securely read START index";
            if (!read_error.empty())
                *error += ": " + read_error;
        }
        return false;
    }

    SHA256 hasher;
    hasher.update(bytes);
    const std::string actual_sha256 = BytesToHex(hasher.digest());
    if (actual_sha256 != expected_sha256) {
        channel::secure_file::WipeAndClear(bytes);
        if (error)
            *error = "START index SHA-256 does not match the independently accepted digest";
        return false;
    }

    runtime_json::Value root;
    std::string json_error;
    const std::string_view view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    runtime_json::Parser parser(view, 256u * 1024u);
    if (!parser.Parse(root, json_error)) {
        channel::secure_file::WipeAndClear(bytes);
        if (error)
            *error = "invalid START index JSON: " + json_error;
        return false;
    }
    std::string canonical_json;
    if (!runtime_json::Canonicalize(root, canonical_json, json_error) ||
        canonical_json.size() != bytes.size() ||
        !std::equal(canonical_json.begin(), canonical_json.end(),
                    reinterpret_cast<const char*>(bytes.data()))) {
        channel::secure_file::WipeAndClear(bytes);
        if (error)
            *error = "START index is not canonical sorted, 2-space indented ASCII JSON with one LF";
        return false;
    }
    channel::secure_file::WipeAndClear(bytes);
    if (root.kind != runtime_json::Value::Kind::Object) {
        if (error)
            *error = "START index root must be an object";
        return false;
    }

    auto exact_string = [&](const runtime_json::Value& object, const char* key,
                            const std::string& expected) {
        const auto* value = object.Get(key);
        return value && value->kind == runtime_json::Value::Kind::String && value->text == expected;
    };
    auto exact_bool = [&](const runtime_json::Value& object, const char* key, bool expected) {
        const auto* value = object.Get(key);
        return value && value->kind == runtime_json::Value::Kind::Bool &&
               value->boolean == expected;
    };
    auto exact_number = [&](const runtime_json::Value& object, const char* key,
                            const char* expected) {
        const auto* value = object.Get(key);
        return value && value->kind == runtime_json::Value::Kind::Number && value->text == expected;
    };
    auto exact_keys = [](const runtime_json::Value& object, const std::set<std::string>& expected) {
        if (object.kind != runtime_json::Value::Kind::Object ||
            object.object.size() != expected.size())
            return false;
        for (const auto& [key, ignored] : object.object) {
            (void)ignored;
            if (!expected.count(key))
                return false;
        }
        return true;
    };
    auto is_nonzero_hash = [](const std::string& value, bool allow_source_width = false) {
        if ((!allow_source_width && value.size() != 64) ||
            (allow_source_width && value.size() != 40 && value.size() != 64))
            return false;
        bool nonzero = false;
        for (char c : value) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                return false;
            nonzero = nonzero || c != '0';
        }
        return nonzero;
    };
    auto exact_string_array = [](const runtime_json::Value* value,
                                 const std::vector<std::string>& expected) {
        if (!value || value->kind != runtime_json::Value::Kind::Array ||
            value->array.size() != expected.size())
            return false;
        for (size_t i = 0; i < expected.size(); ++i) {
            if (value->array[i].kind != runtime_json::Value::Kind::String ||
                value->array[i].text != expected[i])
                return false;
        }
        return true;
    };

    static const std::set<std::string> START_FIELDS = {
        "allowed_services", "completed_at_utc", "data_directory",  "disposable",
        "display_name",     "evidence",         "external_value",  "forbidden_services",
        "genesis_hash",     "lifecycle",        "network_magic",   "not_after_height",
        "not_after_utc",    "operator_set",     "ports",           "platform_scope",
        "profile_id",       "release_version",  "result",          "role",
        "schema",           "source_commit",    "source_identity", "source_manifest_sha256",
        "source_tree",      "statement",        "warning_banner",
    };
    static const std::vector<std::string> ALLOWED_SERVICES = {
        "checkpoint", "core-node", "explorer",  "miner",  "oracle",
        "seed",       "snapshot",  "validator", "wallet",
    };
    static const std::vector<std::string> FORBIDDEN_SERVICES = {
        "bitcoin-anchor", "btcveld-custody",  "btcveld-issuer-mint", "btcveld-peg",
        "btcveld-redeem", "btcveld-spv-mint", "btcveld-wrap",        "doge-desk",
        "eth-desk",       "ltc-desk",         "swap-desk",
    };
    static const std::vector<std::string> PLATFORM_SCOPE = {
        "linux-x86_64",
        "windows-ucrt64-x86_64",
    };
    const auto* schema = root.Get("schema");
    if (!exact_keys(root, START_FIELDS) ||
        !exact_string(root, "statement", "veld-public-testnet-start-index-v2") ||
        !exact_string(root, "lifecycle", "START") || !exact_string(root, "role", DEPLOYMENT_ROLE) ||
        !exact_string(root, "profile_id", DEPLOYMENT_PROFILE_ID) ||
        !exact_string(root, "genesis_hash", GENESIS_HASH) ||
        !exact_string(root, "release_version", CLIENT_VERSION) ||
        !exact_string(root, "display_name", DEPLOYMENT_DISPLAY_NAME) ||
        !exact_string(root, "warning_banner", DEPLOYMENT_WARNING) ||
        !exact_string(root, "data_directory", "./veld-public-testnet-data") ||
        !exact_string(root, "result", "PASS") || !exact_bool(root, "disposable", true) ||
        !exact_bool(root, "external_value", false) ||
        !exact_number(root, "network_magic", "1381387332") || !schema ||
        schema->kind != runtime_json::Value::Kind::Number || schema->text != "2" ||
        !exact_string_array(root.Get("platform_scope"), PLATFORM_SCOPE) ||
        !exact_string_array(root.Get("allowed_services"), ALLOWED_SERVICES) ||
        !exact_string_array(root.Get("forbidden_services"), FORBIDDEN_SERVICES)) {
        if (error)
            *error = "START index exact schema/identity/service policy does not match this "
                     "disposable testnet binary";
        return false;
    }

    const auto* ports = root.Get("ports");
    static const std::set<std::string> PORT_FIELDS = {"p2p", "rpc"};
    if (!ports || !exact_keys(*ports, PORT_FIELDS) || !exact_number(*ports, "p2p", "19333") ||
        !exact_number(*ports, "rpc", "19334")) {
        if (error)
            *error = "START index ports do not match this testnet binary";
        return false;
    }

    const auto* evidence = root.Get("evidence");
    static const std::set<std::string> EVIDENCE_FIELDS = {
        "deployment_info_report_sha256",        "linux_deployment_set_manifest_sha256",
        "runtime_expiry_gate_report_sha256",    "source_archive_sha256",
        "valueless_service_gate_report_sha256", "windows_client_manifest_sha256",
    };
    std::set<std::string> operator_and_evidence_hashes;
    if (!evidence || !exact_keys(*evidence, EVIDENCE_FIELDS)) {
        if (error)
            *error = "START index evidence set is not exact";
        return false;
    }
    for (const auto& [key, value] : evidence->object) {
        (void)key;
        if (value.kind != runtime_json::Value::Kind::String || !is_nonzero_hash(value.text) ||
            !operator_and_evidence_hashes.insert(value.text).second) {
            if (error)
                *error = "START index evidence hashes are invalid or reused";
            return false;
        }
    }

    const auto* operators = root.Get("operator_set");
    static const std::set<std::string> OPERATOR_FIELDS = {
        "attestation_sha256",
        "attestation_signature_sha256",
        "operator_id",
        "operator_public_key_sha256",
    };
    if (!operators || operators->kind != runtime_json::Value::Kind::Array ||
        operators->array.size() != 1) {
        if (error)
            *error = "START index must contain exactly one testnet owner/operator";
        return false;
    }
    std::set<std::string> operator_ids;
    std::set<std::string> operator_keys;
    for (const auto& op : operators->array) {
        if (!exact_keys(op, OPERATOR_FIELDS)) {
            if (error)
                *error = "START operator fields are not exact";
            return false;
        }
        const auto* id = op.Get("operator_id");
        const auto* public_key = op.Get("operator_public_key_sha256");
        bool safe_operator_id = id && id->kind == runtime_json::Value::Kind::String &&
                                id->text.size() >= 3 && id->text.size() <= 128 &&
                                std::isalnum(static_cast<unsigned char>(id->text.front()));
        if (safe_operator_id) {
            for (char c : id->text) {
                const bool allowed = std::isalnum(static_cast<unsigned char>(c)) || c == '.' ||
                                     c == '_' || c == ':' || c == '@' || c == '+' || c == '-';
                if (!allowed) {
                    safe_operator_id = false;
                    break;
                }
            }
        }
        if (!safe_operator_id || !operator_ids.insert(id->text).second || !public_key ||
            public_key->kind != runtime_json::Value::Kind::String ||
            !is_nonzero_hash(public_key->text) || !operator_keys.insert(public_key->text).second) {
            if (error)
                *error = "START operator identities/keys are invalid or reused";
            return false;
        }
        for (const auto& [key, value] : op.object) {
            if (key == "operator_id")
                continue;
            if (value.kind != runtime_json::Value::Kind::String || !is_nonzero_hash(value.text) ||
                !operator_and_evidence_hashes.insert(value.text).second) {
                if (error)
                    *error = "START operator/evidence hashes are invalid or reused";
                return false;
            }
        }
    }
    if (operator_ids.size() != 1 || operator_keys.size() != 1) {
        if (error)
            *error = "START index testnet owner/operator is missing or ambiguous";
        return false;
    }

    const auto* source_identity = root.Get("source_identity");
    const auto* source_commit = root.Get("source_commit");
    const auto* source_tree = root.Get("source_tree");
    const auto* source_manifest = root.Get("source_manifest_sha256");
    if (!source_identity || source_identity->kind != runtime_json::Value::Kind::String ||
        (source_identity->text != "git-v1" && source_identity->text != "source-manifest-v1") ||
        !source_commit || source_commit->kind != runtime_json::Value::Kind::String ||
        !is_nonzero_hash(source_commit->text, true) || !source_tree ||
        source_tree->kind != runtime_json::Value::Kind::String ||
        !is_nonzero_hash(source_tree->text, true) || !source_manifest ||
        source_manifest->kind != runtime_json::Value::Kind::String ||
        !is_nonzero_hash(source_manifest->text)) {
        if (error)
            *error = "START source identity/digests are incomplete";
        return false;
    }

    const auto* height = root.Get("not_after_height");
    const auto* utc = root.Get("not_after_utc");
    const auto* completed = root.Get("completed_at_utc");
    if (!height || height->kind != runtime_json::Value::Kind::Number || !utc ||
        utc->kind != runtime_json::Value::Kind::String || !completed ||
        completed->kind != runtime_json::Value::Kind::String) {
        if (error)
            *error = "START index completion/not-after fields are invalid";
        return false;
    }
    int64_t completed_unix = 0;
    if (!ParseCanonicalUtc(completed->text, completed_unix)) {
        if (error)
            *error = "START completed_at_utc is not canonical";
        return false;
    }
    RuntimeLimits parsed;
    if (!ParseRuntimeLimits(expected_sha256, height->text, utc->text, now_unix, parsed, error))
        return false;
    if (parsed.not_after_height > static_cast<uint64_t>(INT64_MAX) ||
        completed_unix >= parsed.not_after_unix || completed_unix > now_unix) {
        if (error)
            *error = "START completion/not-after chronology or height range is invalid";
        return false;
    }
    out = std::move(parsed);
    if (error)
        error->clear();
    return true;
}

inline std::string CanonicalSessionMarker(const RuntimeLimits& limits) {
    return std::string(SESSION_MARKER_HEADER) + "\n" + "role=" + DEPLOYMENT_ROLE + "\n" +
           "profile_id=" + DEPLOYMENT_PROFILE_ID + "\n" + "genesis_hash=" + GENESIS_HASH + "\n" +
           "lease_identity_sha256=" + limits.lease_identity_sha256 + "\n" +
           "not_after_height=" + std::to_string(limits.not_after_height) + "\n" +
           "not_after_utc=" + limits.not_after_utc + "\n" +
           "not_after_unix=" + std::to_string(limits.not_after_unix) + "\n";
}

inline bool BindOrVerifySession(const std::string& data_dir, const RuntimeLimits& limits,
                                int64_t now_unix, std::string* error = nullptr) {
#if !defined(VELD_PUBLIC_TESTNET)
    (void)data_dir;
    (void)limits;
    (void)now_unix;
    if (error)
        *error = "public-testnet runtime session is unavailable outside VELD_PUBLIC_TESTNET";
    return false;
#else
    if (!IsCanonicalSha256(limits.lease_identity_sha256) || limits.not_after_height == 0 ||
        limits.not_after_unix <= 0 || limits.not_after_utc.empty() || now_unix < 0 ||
        now_unix >= limits.not_after_unix) {
        if (error)
            *error = "public-testnet runtime limits are malformed or expired";
        return false;
    }
    int64_t reparsed_unix = 0;
    if (!ParseCanonicalUtc(limits.not_after_utc, reparsed_unix) ||
        reparsed_unix != limits.not_after_unix) {
        if (error)
            *error = "public-testnet UTC/Unix cutoff binding is inconsistent";
        return false;
    }
    std::string private_error;
    if (!channel::secure_file::EnsurePrivateDirectory(data_dir, &private_error)) {
        if (error)
            *error = "public-testnet session datadir is unsafe: " + private_error;
        return false;
    }
    const std::string path = data_dir + "/" + SESSION_MARKER_NAME;
    const std::string expected = CanonicalSessionMarker(limits);
    auto read_exact = [&](bool* missing) {
        std::vector<uint8_t> bytes;
        std::string read_error;
        const auto result = channel::secure_file::Read(path, bytes, &read_error, 4096,
                                                       /*require_private_parent=*/true);
        if (result == channel::secure_file::ReadResult::NotFound) {
            if (missing)
                *missing = true;
            return false;
        }
        if (missing)
            *missing = false;
        if (result != channel::secure_file::ReadResult::Ok) {
            if (error)
                *error = "cannot securely read public-testnet session marker: " + read_error;
            return false;
        }
        const bool exact = bytes.size() == expected.size() &&
                           std::equal(bytes.begin(), bytes.end(), expected.begin());
        channel::secure_file::WipeAndClear(bytes);
        if (!exact && error) {
            *error = "public-testnet session marker does not byte-exactly "
                     "match the accepted START digest and not-after limits";
        }
        return exact;
    };

    bool missing = false;
    if (read_exact(&missing)) {
        return CheckPersistedClockHighWater(data_dir, limits, now_unix,
                                            /*require_existing=*/true, error);
    }
    if (!missing)
        return false;

    // The clock high-water must be durable before the immutable session marker
    // is created. This ordering makes both first-start crash windows
    // recoverable: no marker is written if node/clock initialization fails,
    // while a crash after the high-water but before this marker is completed
    // by the next exact-START invocation. A session without a high-water is
    // therefore corruption and remains fail-closed.
    if (!CheckPersistedClockHighWater(data_dir, limits, now_unix,
                                      /*require_existing=*/true, error))
        return false;

    const std::vector<uint8_t> bytes(expected.begin(), expected.end());
    std::string write_error;
    if (!channel::secure_file::AtomicWriteNew(path, bytes, &write_error,
                                              /*require_private_parent=*/true)) {
        // A concurrent first start is acceptable only when it published the
        // exact same immutable marker.
        bool still_missing = false;
        if (read_exact(&still_missing)) {
            return CheckPersistedClockHighWater(data_dir, limits, now_unix,
                                                /*require_existing=*/true, error);
        }
        if (error && error->empty()) {
            *error = "cannot create immutable public-testnet session marker: " + write_error;
        }
        return false;
    }
    bool unexpectedly_missing = false;
    if (!read_exact(&unexpectedly_missing)) {
        if (error && error->empty())
            *error = "new public-testnet session marker did not verify byte-for-byte";
        return false;
    }
    if (error)
        error->clear();
    return true;
#endif
}

} // namespace veld::public_testnet
