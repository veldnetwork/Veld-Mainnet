#pragma once

#include "../core/hash.h"
#include "../core/constants.h"
#include "../core/pow_target.h"
#include <array>
#include <vector>
#include <cstdint>
#include <cstring>
#include <string>
#include <sstream>

#include "../crypto/vendored.h"
#include <iomanip>
#include <stdexcept>
#include <atomic>
#include <chrono>
#include <functional>
#include <cmath>
#include <limits>
#include <mutex>
#include <iostream>
#include <cstdlib>
#include <shared_mutex>
#include <optional>
#include <memory>
#include <utility>

namespace veld {
namespace work_admission {
class BlockTemplateAuthorizationClaim;
}
namespace mining {

enum class ExpensivePowUse : uint8_t {
    PeerBlock,
    PeerNms,
    RpcSubmit,
    PeerReorg,
    RpcReorg,
    InternalReorg,
    ReorgVerify,
    InternalMine,
    NearMiss,
    Prewarm,
};

struct ExpensivePowBudgetStats {
    uint64_t attempts{0};
    uint64_t admitted{0};
    uint64_t refused{0};
    uint32_t in_flight{0};
    uint32_t peak_in_flight{0};
};

class ExpensivePowBudget;

class ExpensivePowLease {
public:
    ExpensivePowLease() = default;
    explicit ExpensivePowLease(ExpensivePowBudget* owner) : owner_(owner) {}
    ExpensivePowLease(const ExpensivePowLease&) = delete;
    ExpensivePowLease& operator=(const ExpensivePowLease&) = delete;
    ExpensivePowLease(ExpensivePowLease&& other) noexcept
        : owner_(other.owner_) { other.owner_ = nullptr; }
    ExpensivePowLease& operator=(ExpensivePowLease&& other) noexcept;
    ~ExpensivePowLease();
    explicit operator bool() const noexcept { return owner_ != nullptr; }
private:
    ExpensivePowBudget* owner_{nullptr};
};

class ExpensivePowBudget {
public:
    explicit ExpensivePowBudget(
            uint32_t max_in_flight,
            uint32_t max_external_starts_per_window = 0,
            std::chrono::milliseconds external_window =
                std::chrono::minutes(1))
        : maximum_(max_in_flight == 0 ? 1 : max_in_flight),
          max_external_starts_(max_external_starts_per_window),
          external_window_(external_window.count() <= 0
              ? std::chrono::minutes(1) : external_window),
          external_window_started_(std::chrono::steady_clock::now()) {}

    std::optional<ExpensivePowLease> TryAcquire(
            ExpensivePowUse use) noexcept {
        attempts_.fetch_add(1, std::memory_order_relaxed);
        uint32_t observed = in_flight_.load(std::memory_order_relaxed);
        while (observed < maximum_) {
            if (in_flight_.compare_exchange_weak(
                    observed, observed + 1,
                    std::memory_order_acq_rel,
                    std::memory_order_relaxed)) {
                if (!ReserveExternalStart_(use)) {
                    in_flight_.fetch_sub(1, std::memory_order_acq_rel);
                    refused_.fetch_add(1, std::memory_order_relaxed);
                    return std::nullopt;
                }
                admitted_.fetch_add(1, std::memory_order_relaxed);
                uint32_t peak = peak_.load(std::memory_order_relaxed);
                while (peak < observed + 1 &&
                       !peak_.compare_exchange_weak(
                           peak, observed + 1,
                           std::memory_order_relaxed,
                           std::memory_order_relaxed)) {}
                return ExpensivePowLease(this);
            }
        }
        refused_.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
    }

    ExpensivePowBudgetStats Stats() const noexcept {
        return {attempts_.load(std::memory_order_relaxed),
                admitted_.load(std::memory_order_relaxed),
                refused_.load(std::memory_order_relaxed),
                in_flight_.load(std::memory_order_relaxed),
                peak_.load(std::memory_order_relaxed)};
    }

private:
    friend class ExpensivePowLease;
    void Release() noexcept {
        in_flight_.fetch_sub(1, std::memory_order_acq_rel);
    }
    bool ReserveExternalStart_(ExpensivePowUse use) noexcept {
        const bool external = use == ExpensivePowUse::PeerBlock ||
            use == ExpensivePowUse::PeerNms ||
            use == ExpensivePowUse::RpcSubmit ||
            use == ExpensivePowUse::PeerReorg ||
            use == ExpensivePowUse::RpcReorg;
        if (!external || max_external_starts_ == 0) return true;
        std::lock_guard<std::mutex> lock(external_work_mutex_);
        const auto now = std::chrono::steady_clock::now();
        if (now - external_window_started_ >= external_window_) {
            external_window_started_ = now;
            external_starts_ = 0;
        }
        if (external_starts_ >= max_external_starts_) return false;
        ++external_starts_;
        return true;
    }
    const uint32_t maximum_;
    const uint32_t max_external_starts_;
    const std::chrono::milliseconds external_window_;
    std::mutex external_work_mutex_;
    std::chrono::steady_clock::time_point external_window_started_;
    uint32_t external_starts_{0};
    std::atomic<uint32_t> in_flight_{0};
    std::atomic<uint32_t> peak_{0};
    std::atomic<uint64_t> attempts_{0};
    std::atomic<uint64_t> admitted_{0};
    std::atomic<uint64_t> refused_{0};
};

inline ExpensivePowLease& ExpensivePowLease::operator=(
        ExpensivePowLease&& other) noexcept {
    if (this != &other) {
        if (owner_) owner_->Release();
        owner_ = other.owner_;
        other.owner_ = nullptr;
    }
    return *this;
}

inline ExpensivePowLease::~ExpensivePowLease() {
    if (owner_) owner_->Release();
}

// An expensive-PoW decision must retain the identity that caused the work,
// not merely a borrowed pointer whose owner can expire after first ingress.
// Side branches copy this object into their bounded in-memory index.  The
// shared source budget therefore survives disconnect/reconnect and is charged
// again if that exact block later participates in a reorganization.
enum class PowAdmissionOrigin : uint8_t {
    Unwired,
    Peer,
    Rpc,
    Internal,
};

enum class LocalWorkKind : uint8_t {
    None,
    InternalMining,
    SubmitBlock,
    SynchronousGeneration,
};

// A local/RPC work lease is prepared before Blockchain enters its connect and
// chain locks, claimed exactly once at serialized canonical precommit, then
// handed back to the synchronous caller so the same bounded lease remains
// alive through post-commit relay/enqueue effects. P2P contexts never allocate
// or populate this object.
class LocalWorkLeaseHandoff {
public:
    void Install(std::shared_ptr<void> owner,
                 std::function<bool()> live) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        owner_ = std::move(owner);
        live_ = std::move(live);
    }

    bool IsLive() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!owner_ || !live_) return false;
        try { return live_(); }
        catch (...) { return false; }
    }

    void Reset() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        live_ = {};
        owner_.reset();
    }

private:
    mutable std::mutex mutex_;
    std::shared_ptr<void> owner_;
    std::function<bool()> live_;
};

struct PowAdmissionContext {
    PowAdmissionOrigin origin{PowAdmissionOrigin::Unwired};
    std::string source_identity;
    std::shared_ptr<ExpensivePowBudget> source_budget;
    LocalWorkKind local_work_kind{LocalWorkKind::None};
    std::string work_binding;
    // Server-minted bearer returned by getblocktemplate. A raw serialized
    // work binding is caller-constructible and therefore cannot authorize
    // submitblock on its own.
    std::string work_authorization;
    std::shared_ptr<work_admission::BlockTemplateAuthorizationClaim>
        block_template_authorization_claim;
    std::shared_ptr<LocalWorkLeaseHandoff> local_work_handoff;

    static PowAdmissionContext Peer(
            std::string source,
            std::shared_ptr<ExpensivePowBudget> budget) {
        PowAdmissionContext out;
        out.origin = PowAdmissionOrigin::Peer;
        out.source_identity = std::move(source);
        out.source_budget = std::move(budget);
        return out;
    }

    static PowAdmissionContext Rpc(std::string source = {}) {
        PowAdmissionContext out;
        out.origin = PowAdmissionOrigin::Rpc;
        out.source_identity = std::move(source);
        return out;
    }

    static PowAdmissionContext Internal() {
        PowAdmissionContext out;
        out.origin = PowAdmissionOrigin::Internal;
        return out;
    }

    static PowAdmissionContext RpcWork(std::string binding,
            std::string authorization,
            std::shared_ptr<
                work_admission::BlockTemplateAuthorizationClaim> claim) {
        PowAdmissionContext out = Rpc("submitblock");
        out.local_work_kind = LocalWorkKind::SubmitBlock;
        out.work_binding = std::move(binding);
        out.work_authorization = std::move(authorization);
        out.block_template_authorization_claim = std::move(claim);
        out.local_work_handoff =
            std::make_shared<LocalWorkLeaseHandoff>();
        return out;
    }

    static PowAdmissionContext InternalMiningWork(std::string binding) {
        PowAdmissionContext out = Internal();
        out.local_work_kind = LocalWorkKind::InternalMining;
        out.work_binding = std::move(binding);
        out.local_work_handoff =
            std::make_shared<LocalWorkLeaseHandoff>();
        return out;
    }

    static PowAdmissionContext SynchronousGenerationWork(
            std::string binding) {
        PowAdmissionContext out = Internal();
        out.local_work_kind = LocalWorkKind::SynchronousGeneration;
        out.work_binding = std::move(binding);
        out.local_work_handoff =
            std::make_shared<LocalWorkLeaseHandoff>();
        return out;
    }

    bool RequiresLocalWorkAdmission() const noexcept {
        return local_work_kind != LocalWorkKind::None;
    }

    bool HasRequiredProvenance() const noexcept {
        if (source_identity.size() > 255) return false;
        if (origin == PowAdmissionOrigin::Unwired) return false;
        if (RequiresLocalWorkAdmission()) {
            if (origin != PowAdmissionOrigin::Rpc &&
                origin != PowAdmissionOrigin::Internal)
                return false;
            if (work_binding.empty() || work_binding.size() > 512 ||
                !local_work_handoff)
                return false;
            if (local_work_kind == LocalWorkKind::SubmitBlock) {
                if (work_authorization.empty() ||
                    work_authorization.size() > 128 ||
                    !block_template_authorization_claim)
                    return false;
            } else if (!work_authorization.empty() ||
                       block_template_authorization_claim) {
                return false;
            }
        } else if (!work_binding.empty() || !work_authorization.empty() ||
                   block_template_authorization_claim || local_work_handoff) {
            return false;
        }
        if (origin == PowAdmissionOrigin::Peer)
            return !source_identity.empty() &&
                   static_cast<bool>(source_budget);
        return !source_budget;
    }

    bool IsExternal() const noexcept {
        return origin == PowAdmissionOrigin::Peer ||
               origin == PowAdmissionOrigin::Rpc;
    }

    ExpensivePowUse InitialUse() const noexcept {
        switch (origin) {
            case PowAdmissionOrigin::Unwired:
                return ExpensivePowUse::RpcSubmit;
            case PowAdmissionOrigin::Peer:
                return ExpensivePowUse::PeerBlock;
            case PowAdmissionOrigin::Rpc:
                return ExpensivePowUse::RpcSubmit;
            case PowAdmissionOrigin::Internal:
                return ExpensivePowUse::InternalMine;
        }
        return ExpensivePowUse::RpcSubmit;
    }

    ExpensivePowUse ReorgUse() const noexcept {
        switch (origin) {
            case PowAdmissionOrigin::Unwired:
                return ExpensivePowUse::RpcReorg;
            case PowAdmissionOrigin::Peer:
                return ExpensivePowUse::PeerReorg;
            case PowAdmissionOrigin::Rpc:
                return ExpensivePowUse::RpcReorg;
            case PowAdmissionOrigin::Internal:
                return ExpensivePowUse::InternalReorg;
        }
        return ExpensivePowUse::RpcReorg;
    }

    ExpensivePowUse NmsUse() const noexcept {
        switch (origin) {
            case PowAdmissionOrigin::Unwired:
                return ExpensivePowUse::RpcSubmit;
            case PowAdmissionOrigin::Peer:
                return ExpensivePowUse::PeerNms;
            case PowAdmissionOrigin::Rpc:
                return ExpensivePowUse::RpcSubmit;
            case PowAdmissionOrigin::Internal:
                return ExpensivePowUse::InternalReorg;
        }
        return ExpensivePowUse::RpcSubmit;
    }
};

inline ExpensivePowBudget& GlobalExpensivePowBudget() {
    // One verifier/reorg slot plus one internal mining slot.  Contextual target
    // rejection happens before acquisition, so aliases consume neither.
    // External callers also share a bounded replenishing work envelope.  The
    // semaphore alone only caps concurrency and would still permit an
    // unbounded sequential NMS/block hashing stream.
    static ExpensivePowBudget budget(2, 32, std::chrono::minutes(1));
    return budget;
}

// Consensus numeric lane.
//
// VeldHash previously fed native IEEE-754 `double` results and std::sqrt bit
// patterns back into its integer state.  That made block validity depend on
// compiler, standard-library, FPU, contraction, and denormal behavior.  The
// fresh public-mainnet genesis instead uses a fully specified signed Q40.24
// lane.  Every operation below is integer-only:
//
//   * addition/subtraction and conversion saturate at INT64_MIN/MAX;
//   * multiplication divides the signed 128-bit product by 2^24, truncating
//     toward zero (the C++17 signed-division rule);
//   * square root is the floor of sqrt(raw_q24 * 2^24), computed by a
//     bit-by-bit unsigned 128-bit algorithm;
//   * register serialization is the exact two's-complement 64-bit object
//     representation, guarded by static assertions.
//
// Veld already requires compilers with 128-bit integer support for IMULH_R and
// ISMUL_R, so this introduces no new toolchain primitive.
static_assert(sizeof(int64_t) == 8, "VeldHash requires 64-bit int64_t");
static_assert(INT64_MIN == (-INT64_MAX - 1),
              "VeldHash requires two's-complement int64_t");

inline constexpr unsigned VELD_FIXED_FRAC_BITS = 24;
inline constexpr int64_t VELD_FIXED_ONE =
    static_cast<int64_t>(uint64_t{1} << VELD_FIXED_FRAC_BITS);

inline uint64_t VeldFixedBits(int64_t value) {
    uint64_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}

inline int64_t VeldFixedFromBits(uint64_t bits) {
    int64_t value = 0;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

inline int64_t VeldFixedClamp(__int128 value) {
    if (value > static_cast<__int128>(INT64_MAX)) return INT64_MAX;
    if (value < static_cast<__int128>(INT64_MIN)) return INT64_MIN;
    return static_cast<int64_t>(value);
}

inline int64_t VeldFixedAdd(int64_t a, int64_t b) {
    return VeldFixedClamp(static_cast<__int128>(a) +
                          static_cast<__int128>(b));
}

inline int64_t VeldFixedSub(int64_t a, int64_t b) {
    return VeldFixedClamp(static_cast<__int128>(a) -
                          static_cast<__int128>(b));
}

inline int64_t VeldFixedFromInteger(int64_t value) {
    return VeldFixedClamp(static_cast<__int128>(value) *
                          static_cast<__int128>(VELD_FIXED_ONE));
}

inline int64_t VeldFixedMul(int64_t a, int64_t b) {
    const __int128 product =
        static_cast<__int128>(a) * static_cast<__int128>(b);
    return VeldFixedClamp(product /
                          static_cast<__int128>(VELD_FIXED_ONE));
}

inline uint64_t VeldIntegerSqrt128(unsigned __int128 value) {
    unsigned __int128 result = 0;
    unsigned __int128 bit = static_cast<unsigned __int128>(1) << 126;
    while (bit > value) bit >>= 2;
    while (bit != 0) {
        if (value >= result + bit) {
            value -= result + bit;
            result = (result >> 1) + bit;
        } else {
            result >>= 1;
        }
        bit >>= 2;
    }
    return static_cast<uint64_t>(result);
}

inline int64_t VeldFixedAbs(int64_t value) {
    if (value == INT64_MIN) return INT64_MAX;
    return value < 0 ? -value : value;
}

inline int64_t VeldFixedSqrt(int64_t nonnegative_q24) {
    if (nonnegative_q24 <= 0) return 0;
    const unsigned __int128 scaled =
        static_cast<unsigned __int128>(
            static_cast<uint64_t>(nonnegative_q24))
        << VELD_FIXED_FRAC_BITS;
    const uint64_t root = VeldIntegerSqrt128(scaled);
    return root > static_cast<uint64_t>(INT64_MAX)
        ? INT64_MAX : static_cast<int64_t>(root);
}

inline int64_t VeldFixedSignedHigh32(uint64_t word) {
    const uint32_t high_bits = static_cast<uint32_t>(word >> 32);
    int32_t signed_high = 0;
    std::memcpy(&signed_high, &high_bits, sizeof(signed_high));
    return static_cast<int64_t>(signed_high);
}

inline uint64_t VeldIntegerDeterminismKat() {
    const int64_t half = VELD_FIXED_ONE / 2;
    const int64_t three_halves = VELD_FIXED_ONE + half;
    const int64_t three = VELD_FIXED_ONE * 3;
    auto normalize = [&](int64_t value) {
        while (value > three) value = VeldFixedSub(value, three_halves);
        while (value < VELD_FIXED_ONE) value = VeldFixedAdd(value, half);
        return value;
    };

    int64_t a = VeldFixedAdd(VeldFixedFromInteger(10), 1);
    int64_t b = VeldFixedClamp(
        static_cast<__int128>(VELD_FIXED_ONE) * 4 / 3);
    int64_t c = VeldFixedAdd(VeldFixedFromInteger(2), 3);
    int64_t s = VELD_FIXED_ONE;
    uint64_t mix = 0x9E3779B97F4A7C15ULL;
    for (int i = 0; i < 96; ++i) {
        const int64_t t1 =
            VeldFixedAdd(VeldFixedMul(a, b), s);
        const int64_t t2 = normalize(VeldFixedSqrt(
            t1 > 0 ? t1 : VELD_FIXED_ONE));
        const int64_t next_a = normalize(VeldFixedAdd(b, t2));
        const int64_t next_b = normalize(
            VeldFixedSub(c, VeldFixedSub(t1, t2)));
        const int64_t next_c = normalize(
            VeldFixedMul(VeldFixedAdd(t1, t2), half));
        const int64_t sum =
            VeldFixedAdd(VeldFixedAdd(a, b), c);
        const int64_t next_s = normalize(
            VeldFixedClamp(static_cast<__int128>(sum) / 3));
        s = next_s;
        a = next_a;
        b = next_b;
        c = next_c;
        mix ^= VeldFixedBits(a) + (VeldFixedBits(b) << 1) +
               (VeldFixedBits(c) >> 1) + VeldFixedBits(s);
        mix = (mix << 13) | (mix >> 51);
    }
    return mix;
}

inline constexpr uint64_t VELD_INTEGER_KAT_EXPECTED =
    0x8a02b1c3b36ab8e8ULL;

inline void VeldIntegerDeterminismCheck() {
    const uint64_t got = VeldIntegerDeterminismKat();
    if (got != VELD_INTEGER_KAT_EXPECTED) {
        std::cerr << "  [FATAL INTEGER-KAT] expected=0x" << std::hex
                  << VELD_INTEGER_KAT_EXPECTED << " got=0x" << got
                  << std::dec << "\n  This binary's consensus integer "
                     "semantics are non-conforming. Refusing to run.\n";
        std::cerr.flush();
        std::abort();
    }
}

// A thread-local status flag distinguishes dataset unavailability from a valid
// proof-of-work result. Callers retry a transient dataset failure rather than
// treating the 0xFF sentinel as a consensus rejection.
inline bool& g_veldhash_last_dataset_ok() {
    thread_local bool ok = true;
    return ok;
}

class ChaCha20 {
public:
    ChaCha20(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter = 0) {
        std::memcpy(key_, key, 32);
        counter_ = counter;
        std::memcpy(nonce_, nonce, 12);
        block_off_ = 64;
    }

    void fill(uint8_t* out, size_t len) {
        while (len > 0) {
            if (block_off_ >= 64) refill_();
            size_t avail = 64 - block_off_;
            size_t take = len < avail ? len : avail;
            std::memcpy(out, block_ + block_off_, take);
            block_off_ += take;
            out += take;
            len -= take;
        }
    }

    uint64_t next64() {
        uint8_t b[8]; fill(b, 8);
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= ((uint64_t)b[i]) << (i * 8);
        return v;
    }

private:
    void refill_() {
        uint8_t iv[16];
        iv[0] = (uint8_t)(counter_);
        iv[1] = (uint8_t)(counter_ >> 8);
        iv[2] = (uint8_t)(counter_ >> 16);
        iv[3] = (uint8_t)(counter_ >> 24);
        std::memcpy(iv + 4, nonce_, 12);
        ::veld::vendored_crypto::chacha20_keystream(key_, iv, block_, 64);
        block_off_ = 0;
        counter_++;
    }

    uint8_t  key_[32]{};
    uint8_t  nonce_[12]{};
    uint32_t counter_{0};
    uint8_t  block_[64]{};
    size_t   block_off_{64};
};

#ifdef VELD_MAINNET_POW
// ── Light-verify dataset recompute ──────────────────────────────────────────
// The 1 GB VeldHash dataset is pure ChaCha20 keystream (key = epoch seed,
// nonce = all-zero), so any word is recomputable on the fly without holding
// the dataset:  dataset_[d_addr] is the native-endian u64 at keystream byte
// offset d_addr*8  ==  ChaCha20 block (d_addr>>3), bytes ((d_addr&7)<<3 .. +8).
// This is BYTE-IDENTICAL to the held-dataset path on the little-endian targets
// Veld ships (x86-64 / aarch64) — verified against a real fill at startup by
// VeldDatasetLightKat(). Only verify-only infra nodes built with
// -DVELD_LIGHT_VERIFY use it; miners always read the held dataset. Identical
// output => no consensus divergence; the recompute is just slower per hash,
// which is irrelevant for a node that verifies rather than mines.
inline uint64_t VeldDatasetWordLight(const uint8_t key[32], size_t d_addr) {
    uint8_t nonce[12] = {};
    ChaCha20 cc(key, nonce, (uint32_t)(d_addr >> 3));
    uint8_t blk[64];
    cc.fill(blk, 64);
    uint64_t w;
    std::memcpy(&w, blk + ((d_addr & 7) << 3), 8);
    return w;
}

// Fail-closed validation of the light recompute against a REAL ChaCha20 dataset
// fill. Runs at startup on every build (full + light). A sequential fill across
// 1024 blocks is compared word-for-word against the block-indexed recompute; any
// divergence aborts because a byte-divergent binary must
// never run/relay/fork. This is the guarantee that light-verify can't desync.
inline void VeldDatasetLightKat() {
    Hash256 seed{};
    for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)(0x5A ^ (i * 31 + 7));
    uint8_t key[32];
    std::memcpy(key, seed.data(), 32);
    uint8_t nonce[12] = {};
    const size_t N = 8192;                       // 64 KB == 1024 ChaCha20 blocks
    std::vector<uint64_t> ref(N);
    ChaCha20 cc(key, nonce);
    cc.fill(reinterpret_cast<uint8_t*>(ref.data()), N * sizeof(uint64_t));
    for (size_t i = 0; i < N; ++i) {
        if (VeldDatasetWordLight(key, i) != ref[i]) {
            std::cerr << "  [FATAL DATASET-LIGHT-KAT] light recompute diverges from"
                      << " the canonical dataset at word " << i
                      << " — refusing to run (would fork).\n";
            std::cerr.flush();
            std::abort();
        }
    }
}
#endif

class Blake2b {
public:
    Blake2b() : b_() {}

    void update(const uint8_t* data, size_t len) {
        if (len > 0) b_.update(data, len);
    }

    void finalize(uint8_t out[32]) {
        uint8_t full[64];
        b_.finalize(full);
        std::memcpy(out, full, 32);
    }

private:
    ::veld::vendored_crypto::Blake2b b_;
};

inline Hash256 Blake2b256(const uint8_t* data, size_t len) {
    Blake2b h; h.update(data, len);
    Hash256 out; h.finalize(out.data());
    return out;
}

#ifdef VELD_MAINNET_POW
constexpr size_t   SCRATCHPAD_SIZE    = 2 * 1024 * 1024;
constexpr size_t   SCRATCHPAD_WORDS   = SCRATCHPAD_SIZE / 8;
#if defined(VELD_TEST_DATASET_BYTES) && defined(VELD_PUBLIC_RELEASE)
#error "VELD_TEST_DATASET_BYTES is forbidden in VELD_PUBLIC_RELEASE"
#endif
#ifdef VELD_TEST_DATASET_BYTES
constexpr size_t   DATASET_SIZE       = VELD_TEST_DATASET_BYTES;
#else
constexpr size_t   DATASET_SIZE       = 1ull * 1024 * 1024 * 1024;
#endif
constexpr size_t   DATASET_WORDS      = DATASET_SIZE / 8;
constexpr uint32_t PROGRAM_SIZE       = 4096;
constexpr uint32_t PROGRAM_ITERATIONS = 16;
constexpr uint32_t REGISTER_COUNT     = 8;
constexpr uint32_t FIXED_REG_COUNT    = 8;
constexpr uint64_t DATASET_EPOCH_BLOCKS = 256;
#else
constexpr size_t   SCRATCHPAD_SIZE    = 256 * 1024;
constexpr size_t   SCRATCHPAD_WORDS   = SCRATCHPAD_SIZE / 8;
constexpr size_t   DATASET_SIZE       = 0;
constexpr size_t   DATASET_WORDS      = 0;
constexpr uint32_t PROGRAM_SIZE       = 256;
constexpr uint32_t PROGRAM_ITERATIONS = 8;
constexpr uint32_t REGISTER_COUNT     = 8;
constexpr uint32_t FIXED_REG_COUNT    = 4;
#endif

#ifdef VELD_MAINNET_POW
class DatasetHandle {
public:
    DatasetHandle() : data_(nullptr) {}
    DatasetHandle(std::shared_lock<std::shared_mutex> lock, const uint64_t* data)
        : read_lock_(std::move(lock)), data_(data) {}
    DatasetHandle(std::unique_lock<std::shared_mutex> lock, const uint64_t* data)
        : write_lock_(std::move(lock)), data_(data) {}
    const uint64_t* get() const { return data_; }
    operator bool() const { return data_ != nullptr; }
private:
    std::shared_lock<std::shared_mutex> read_lock_;
    std::unique_lock<std::shared_mutex> write_lock_;
    const uint64_t* data_;
};

class DatasetCache {
public:
    DatasetCache() {
        try {
#ifndef VELD_LIGHT_VERIFY
            dataset_.resize(DATASET_WORDS);
#endif
        } catch (const std::bad_alloc&) {
            std::cerr << "\n  FATAL: failed to allocate "
                      << (DATASET_SIZE / 1024 / 1024) << " MB for the VeldHash dataset.\n"
                      << "  This node CANNOT validate blocks without it.\n"
                      << "  Provision a host with at least "
                      << ((DATASET_SIZE / 1024 / 1024) + 256) << " MB of free RAM.\n\n";
            std::cerr.flush();
            std::abort();
        }
    }

    DatasetHandle get_for_seed(const Hash256& seed) {
        requests_.fetch_add(1, std::memory_order_relaxed);
        if (dataset_.empty()) return DatasetHandle();
        {
            std::shared_lock<std::shared_mutex> rl(mutex_);
            if (seed_valid_ && seed == current_seed_) {
                hits_.fetch_add(1, std::memory_order_relaxed);
                return DatasetHandle(std::move(rl), dataset_.data());
            }
        }
        std::unique_lock<std::shared_mutex> wl(mutex_);
        if (seed_valid_ && seed == current_seed_) {
            hits_.fetch_add(1, std::memory_order_relaxed);
            return DatasetHandle(std::move(wl), dataset_.data());
        }
        try {
                        uint8_t key[32];
                        std::memcpy(key, seed.data(), 32);
                        // The domain-separator nonce
                        // ("veldds01" || zeros) is a CONSENSUS change — it
                        // alters the dataset keystream and therefore every
                        // VeldHash output. Any node running the old all-zero
                        // nonce rejects blocks from nodes running the new
                        // one as pow_verify_failed. Reverting to the original
                        // all-zero nonce so the fleet stays in sync. The
                        // concern (wallet-chosen ChaCha20 nonce collision)
                        // is not a real attack surface — wallet nonces are
                        // randomly generated per-encryption and the seed
                        // space (32-byte Hash256) has 2^256 entropy; coincidence
                        // is cryptographically infeasible.
                        //
                        //  (Crypto M5 — nonce-space
                        // discipline). The ChaCha20 dataset uses an all-zero
                        // (12-byte) nonce against the seed-derived key. The
                        // wallet AEAD path uses a per-encryption RANDOM
                        // 12-byte nonce against a PBKDF2-derived key. The
                        // two key spaces are SEPARATE (dataset key derives
                        // from a chain-derived seed; wallet key derives
                        // from password + per-file salt) so a same-nonce
                        // collision across the two systems would still
                        // operate against different keys — no two-time-
                        // pad failure is possible. This invariant ("dataset
                        // ChaCha20 key MUST NEVER be derivable from any
                        // user-controlled input") MUST be preserved in any
                        // future feature that derives ChaCha20 keys from
                        // chain state. Adding such a feature requires
                        // either (a) a domain-separator nonce scheme on
                        // the dataset side or (b) a separate cipher for
                        // the new feature.
                        uint8_t nonce[12] = {};
                        ChaCha20 cc(key, nonce);
                        cc.fill(reinterpret_cast<uint8_t*>(dataset_.data()), DATASET_SIZE);
                        current_seed_ = seed;
                        seed_valid_ = true;
                        builds_.fetch_add(1, std::memory_order_relaxed);
        } catch (...) {
            seed_valid_ = false;
            failures_.fetch_add(1, std::memory_order_relaxed);
            return DatasetHandle();
        }
        // Retain the exclusive lock in the first returned handle.  A waiter
        // cannot replace the freshly built single-entry dataset before its
        // first hash consumes it; identical waiters then take the hit path.
        return DatasetHandle(std::move(wl), dataset_.data());
    }

    struct StatsSnapshot {
        uint64_t requests{0};
        uint64_t hits{0};
        uint64_t builds{0};
        uint64_t failures{0};
    };
    StatsSnapshot Stats() const noexcept {
        return {requests_.load(std::memory_order_relaxed),
                hits_.load(std::memory_order_relaxed),
                builds_.load(std::memory_order_relaxed),
                failures_.load(std::memory_order_relaxed)};
    }
    static constexpr size_t CapacityIdentities() noexcept { return 1; }

private:
    std::shared_mutex     mutex_;
    Hash256               current_seed_{};
    bool                  seed_valid_ = false;
    std::vector<uint64_t> dataset_;
    std::atomic<uint64_t> requests_{0};
    std::atomic<uint64_t> hits_{0};
    std::atomic<uint64_t> builds_{0};
    std::atomic<uint64_t> failures_{0};
};

inline DatasetCache& GlobalDataset() {
    static DatasetCache instance;
    return instance;
}
#endif

class VeldPRNG {
public:
    explicit VeldPRNG(uint64_t seed_a, uint64_t seed_b = 0) {
        state_[0] = seed_a;
        state_[1] = seed_b ^ 0x9e3779b97f4a7c15ULL;
        state_[2] = seed_a ^ 0x6c62272e07bb0142ULL;
        state_[3] = seed_b ^ 0x62b821756295c58dULL;
        for (int i = 0; i < 20; ++i) Next64();
    }

    uint64_t Next64() {
        uint64_t result = rotl(state_[1] * 5, 7) * 9;
        uint64_t t = state_[1] << 17;
        state_[2] ^= state_[0];
        state_[3] ^= state_[1];
        state_[1] ^= state_[2];
        state_[0] ^= state_[3];
        state_[2] ^= t;
        state_[3] = rotl(state_[3], 45);
        return result;
    }

    uint32_t Next32() { return (uint32_t)(Next64() >> 32); }

private:
    uint64_t state_[4];
    static uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
};

enum class VeldOp : uint8_t {
    IADD_RS  = 0,
    IADD_M   = 1,
    ISUB_R   = 2,
    IMUL_R   = 3,
    IMUL_M   = 4,
    IMULH_R  = 5,
    ISMUL_R  = 6,
    IDIV_C   = 7,
    IROR_R   = 8,
    IROL_R   = 9,
    IXOR_R   = 10,
    IXOR_M   = 11,
    IMIX_R   = 12,
    IEXT_R   = 13,
    IMIX_M   = 14,
    ISWAP_R  = 15,
    IREV_R   = 16,
    CBRANCH  = 17,
    ISTORE   = 18,
    IADD_D   = 19,
    IXOR_D   = 20,
    IMIX_D   = 21,
    IADD_C   = 22,
    IMUL_C   = 23,
    QADD_R   = 24,
    QMUL_R   = 25,
    QSUB_R   = 26,
    QSQRT_R  = 27,
    COUNT    = 28
};

struct VeldInstruction {
    VeldOp   op;
    uint8_t  dst;
    uint8_t  src;
    uint8_t  mod;
    uint32_t imm;
    uint32_t mem_mask;
};

inline std::vector<VeldInstruction> GenerateProgram(uint64_t seed_a, uint64_t seed_b) {
    VeldPRNG prng(seed_a, seed_b);
    std::vector<VeldInstruction> program(PROGRAM_SIZE);

#ifdef VELD_MAINNET_POW
    static const uint8_t OP_WEIGHTS[] = {
        12, 7, 12, 12, 4,
        4,  4, 4,  8,  8,
        12, 4, 8,  8,  8,
        4,  4, 16, 8,
        10, 10, 8, 6, 6,
        22, 22, 18, 18
    };
#else
    static const uint8_t OP_WEIGHTS[] = {
        16, 7, 16, 16, 4,
        4,  4, 4,  8,  8,
        16, 4, 8,  8,  8,
        4,  4, 16, 8,
        0,  0,  0, 0, 0,
        0,  0,  0, 0
    };
#endif

    uint32_t weight_table[512] = {};
    uint32_t total = 0;
    for (int op = 0; op < (int)VeldOp::COUNT; ++op) {
        for (int w = 0; w < OP_WEIGHTS[op] && total < 512; ++w)
            weight_table[total++] = op;
    }
    if (total == 0) total = 1;
    for (uint32_t i = total; i < 512; ++i)
        weight_table[i] = weight_table[i % total];

    for (uint32_t i = 0; i < PROGRAM_SIZE; ++i) {
        VeldInstruction& instr = program[i];
        uint64_t r = prng.Next64();
        instr.op       = (VeldOp)(weight_table[r & 0x1FF]);
        instr.dst      = (r >>  9) & (REGISTER_COUNT - 1);
        instr.src      = (r >> 17) & (REGISTER_COUNT - 1);
        instr.mod      = (r >> 25) & 0x3F;
        instr.imm      = (uint32_t)(r >> 32);
        instr.mem_mask = (uint32_t)(SCRATCHPAD_WORDS - 1);
    }

#ifdef VELD_MAINNET_POW
    const uint32_t MIN_ISTORES = PROGRAM_SIZE / 64;
    const uint32_t MIN_DATA_OPS = PROGRAM_SIZE / 32;
    const uint32_t MIN_FIXED_OPS = PROGRAM_SIZE / 64;
    uint32_t istores = 0, dops = 0, fixed_ops = 0;
    for (uint32_t i = 0; i < PROGRAM_SIZE; ++i) {
        const auto& op = program[i].op;
        if (op == VeldOp::ISTORE) ++istores;
        if (op == VeldOp::IADD_D || op == VeldOp::IXOR_D || op == VeldOp::IMIX_D) ++dops;
        if (op == VeldOp::QADD_R || op == VeldOp::QMUL_R ||
            op == VeldOp::QSUB_R || op == VeldOp::QSQRT_R) ++fixed_ops;
    }
    uint32_t cursor = 0;
    auto force_op = [&](VeldOp want, uint32_t needed, uint32_t& have) {
        while (have < needed && cursor < PROGRAM_SIZE) {
            if (program[cursor].op != want) {
                program[cursor].op = want;
                ++have;
            }
            ++cursor;
        }
    };
    force_op(VeldOp::ISTORE, MIN_ISTORES, istores);
    force_op(VeldOp::IADD_D, MIN_DATA_OPS, dops);
    force_op(VeldOp::QADD_R, MIN_FIXED_OPS, fixed_ops);
#endif

    return program;
}

class VeldHashVM {
public:
    VeldHashVM() {
        scratchpad_.resize(SCRATCHPAD_WORDS);
        Reset();
    }

    void SetDataset(const uint64_t* dataset) { dataset_ = dataset; }
#if defined(VELD_MAINNET_POW) && defined(VELD_LIGHT_VERIFY)
    void SetLightKey(const Hash256& seed) { std::memcpy(light_key_, seed.data(), 32); }
#endif

    void Initialize(const Hash256& seed) {
#ifdef VELD_MAINNET_POW
        uint8_t key[32];
        std::memcpy(key, seed.data(), 32);
        uint8_t nonce[12] = {};
        ChaCha20 cc_sp(key, nonce);
        cc_sp.fill(reinterpret_cast<uint8_t*>(scratchpad_.data()), SCRATCHPAD_SIZE);

        for (int i = 0; i < REGISTER_COUNT; ++i)
            regs_[i] = cc_sp.next64();

        for (int i = 0; i < (int)FIXED_REG_COUNT; ++i) {
            uint64_t u = cc_sp.next64();
            int64_t signed_mantissa = (int64_t)(u & 0x1FFFFFFFFFFFFFULL);
            if (u & 0x8000000000000000ULL) signed_mantissa = -signed_mantissa;
            // Q40.24 stores the intended rational exactly by multiplying the signed
            // 53-bit magnitude by 2^(24-21).
            fixed_regs_[i] = signed_mantissa * 8;
        }

        uint8_t prog_nonce[12] = {1};
        ChaCha20 cc_prog(key, prog_nonce);
        uint64_t prog_seed_a = cc_prog.next64();
        uint64_t prog_seed_b = cc_prog.next64();
        program_ = GenerateProgram(prog_seed_a, prog_seed_b);
#else
        auto le64 = [](const uint8_t* b) -> uint64_t {
            uint64_t v = 0;
            for (int i = 0; i < 8; ++i) v |= (uint64_t)b[i] << (i * 8);
            return v;
        };
        VeldPRNG sp_prng(
            le64(seed.data()),
            le64(seed.data() + 8)
        );
        for (size_t i = 0; i < SCRATCHPAD_WORDS; ++i)
            scratchpad_[i] = sp_prng.Next64();
        for (int i = 0; i < REGISTER_COUNT; ++i)
            regs_[i] = sp_prng.Next64();
        uint64_t prog_seed_a = le64(seed.data() + 16);
        uint64_t prog_seed_b = le64(seed.data() + 24);
        program_ = GenerateProgram(prog_seed_a, prog_seed_b);
#endif
    }

    void Execute() {
        for (uint32_t round = 0; round < PROGRAM_ITERATIONS; ++round) {
            uint32_t pc    = 0;
            uint32_t steps = 0;
            const uint32_t MAX_STEPS = PROGRAM_SIZE * 4;

            while (pc < PROGRAM_SIZE && steps < MAX_STEPS) {
                ExecuteInstruction(program_[pc], pc);
                ++pc;
                ++steps;
            }

            for (int i = 0; i < REGISTER_COUNT; ++i) {
#ifdef VELD_MAINNET_POW
                size_t base = (regs_[i] >> 3) & (SCRATCHPAD_WORDS - 8);
                scratchpad_[base + (i & 7)] ^= regs_[i];
                size_t far_addr = (regs_[i] * 0x6c62272e07bb0142ULL) >> 3;
                far_addr &= (SCRATCHPAD_WORDS - 1);
                scratchpad_[far_addr] ^= rotl64(regs_[i], round * 7 + i);
#else
                size_t addr = (regs_[i] >> 3) & (SCRATCHPAD_WORDS - 1);
                scratchpad_[addr] ^= regs_[i];
#endif
            }
        }
    }

    std::vector<uint8_t> FinalizeRaw() const {
#ifdef VELD_MAINNET_POW
        std::vector<uint8_t> state;
        state.reserve(256 * 8 + REGISTER_COUNT * 8 + FIXED_REG_COUNT * 8);
        uint64_t stride_seed = regs_[0] ^ regs_[1] ^ 0x9e3779b97f4a7c15ULL;
        uint64_t idx = regs_[2] & (SCRATCHPAD_WORDS - 1);
        for (int k = 0; k < 256; ++k) {
            idx = (idx + (stride_seed | 1)) & (SCRATCHPAD_WORDS - 1);
            uint64_t w = scratchpad_[idx];
            for (int j = 0; j < 8; ++j)
                state.push_back((w >> (j * 8)) & 0xFF);
            stride_seed = stride_seed * 0x9e3779b97f4a7c15ULL + 1;
        }
        for (int i = 0; i < REGISTER_COUNT; ++i)
            for (int j = 0; j < 8; ++j)
                state.push_back((regs_[i] >> (j * 8)) & 0xFF);
        for (int i = 0; i < (int)FIXED_REG_COUNT; ++i) {
            const uint64_t fbits = VeldFixedBits(fixed_regs_[i]);
            for (int j = 0; j < 8; ++j)
                state.push_back((fbits >> (j * 8)) & 0xFF);
        }
        return state;
#else
        std::vector<uint8_t> state;
        state.reserve(REGISTER_COUNT * 8 + 256);
        for (int i = 0; i < REGISTER_COUNT; ++i)
            for (int j = 0; j < 8; ++j)
                state.push_back((regs_[i] >> (j * 8)) & 0xFF);
        for (size_t i = SCRATCHPAD_WORDS - 32; i < SCRATCHPAD_WORDS; ++i) {
            uint64_t word = scratchpad_[i];
            for (int j = 0; j < 8; ++j)
                state.push_back((word >> (j * 8)) & 0xFF);
        }
        return state;
#endif
    }

    Hash256 Finalize() const {
        auto state = FinalizeRaw();
        return Hash256d(state);
    }

    void Reset() {
        std::memset(regs_, 0, sizeof(regs_));
        std::memset(fixed_regs_, 0, sizeof(fixed_regs_));
        program_.clear();
    }

private:
    std::vector<uint64_t>        scratchpad_;
    uint64_t                     regs_[REGISTER_COUNT];
    int64_t                      fixed_regs_[FIXED_REG_COUNT] = {};
    std::vector<VeldInstruction> program_;
    const uint64_t*              dataset_ = nullptr;
#ifdef VELD_MAINNET_POW
#ifdef VELD_LIGHT_VERIFY
    uint8_t                      light_key_[32]{};   // epoch seed; words recomputed on the fly (no 1 GB held)
#endif
    // Dataset word accessor: held 1 GB array (miners / full nodes) or on-the-fly
    // ChaCha20 recompute (-DVELD_LIGHT_VERIFY infra nodes). Identical value
    // either way (see VeldDatasetWordLight / VeldDatasetLightKat); inlines to a
    // plain array read in full builds, so miners are unaffected.
    inline uint64_t DsWord_(size_t d_addr) const {
#ifdef VELD_LIGHT_VERIFY
        return VeldDatasetWordLight(light_key_, d_addr);
#else
        return dataset_[d_addr];
#endif
    }
#endif

    inline uint64_t rotr64(uint64_t x, int n) {
        n &= 63;
        return n ? ((x >> n) | (x << (64 - n))) : x;
    }
    inline uint64_t rotl64(uint64_t x, int n) {
        n &= 63;
        return n ? ((x << n) | (x >> (64 - n))) : x;
    }

    inline size_t MemAddr(uint64_t addr_base, uint32_t mask) const {
        return (size_t)((addr_base >> 3) & mask) & (SCRATCHPAD_WORDS - 1);
    }

    void ExecuteInstruction(const VeldInstruction& instr, uint32_t& pc) {
        uint64_t& dst = regs_[instr.dst & (REGISTER_COUNT - 1)];
        uint64_t  src = regs_[instr.src & (REGISTER_COUNT - 1)];
        size_t    addr = MemAddr(dst ^ src, instr.mem_mask);

        switch (instr.op) {

        case VeldOp::IADD_RS:  dst += src << (instr.mod & 0x3); break;
        case VeldOp::IADD_M:   dst += scratchpad_[addr]; break;
        case VeldOp::ISUB_R:   dst -= src; break;
        case VeldOp::IMUL_R:   dst *= src; break;
        case VeldOp::IMUL_M:   dst *= scratchpad_[addr]; break;

        case VeldOp::IMULH_R: {
            __uint128_t r = (__uint128_t)dst * src;
            dst = (uint64_t)(r >> 64);
            break;
        }
        case VeldOp::ISMUL_R: {
            int64_t a = (int64_t)dst, b = (int64_t)src;
            dst = (uint64_t)((__int128_t)a * b);
            break;
        }
        case VeldOp::IDIV_C: {
            uint64_t d = (uint64_t)instr.imm | 1;
            dst /= d;
            break;
        }
        case VeldOp::IROR_R:  dst = rotr64(dst, src & 63); break;
        case VeldOp::IROL_R:  dst = rotl64(dst, src & 63); break;
        case VeldOp::IXOR_R:  dst ^= src; break;
        case VeldOp::IXOR_M:  dst ^= scratchpad_[addr]; break;

#ifdef VELD_MAINNET_POW
        case VeldOp::IMIX_R: {
            const int64_t fd = VeldFixedAdd(
                VeldFixedMul(
                    VeldFixedFromInteger(VeldFixedSignedHigh32(dst)),
                    VELD_FIXED_ONE + 1),
                VeldFixedFromInteger(VeldFixedSignedHigh32(src)));
            const uint64_t fbits = VeldFixedBits(fd);
            dst = (dst + src) ^ rotr64(fbits, 17);
            break;
        }
        case VeldOp::IEXT_R: {
            const int64_t fd = VeldFixedMul(
                VeldFixedFromInteger(VeldFixedSignedHigh32(dst)),
                VeldFixedAdd(
                    VeldFixedFromInteger(VeldFixedSignedHigh32(src)),
                    VELD_FIXED_ONE));
            const uint64_t fbits = VeldFixedBits(fd);
            dst = fbits ^ (dst * 0x9e3779b97f4a7c15ULL + src);
            break;
        }
        case VeldOp::IMIX_M: {
            uint64_t mem = scratchpad_[addr];
            const int64_t fd = VeldFixedSqrt(VeldFixedAbs(
                VeldFixedFromInteger(
                    VeldFixedSignedHigh32(mem | 1ULL))));
            const uint64_t fbits = VeldFixedBits(fd);
            dst ^= rotr64(mem, dst & 63) ^ fbits;
            break;
        }
#else
        case VeldOp::IMIX_R:  dst = (dst + src) ^ rotr64(dst, 17); break;
        case VeldOp::IEXT_R:  dst = dst * 0x9e3779b97f4a7c15ULL + src; break;
        case VeldOp::IMIX_M:  dst ^= rotr64(scratchpad_[addr], dst & 63); break;
#endif

        case VeldOp::ISWAP_R: {
            uint64_t& s = regs_[instr.src & (REGISTER_COUNT - 1)];
            uint64_t  t = dst; dst = s; s = t;
            break;
        }
        case VeldOp::IREV_R: {
            uint64_t x = dst;
            x = ((x & 0x5555555555555555ULL) <<  1) | ((x >>  1) & 0x5555555555555555ULL);
            x = ((x & 0x3333333333333333ULL) <<  2) | ((x >>  2) & 0x3333333333333333ULL);
            x = ((x & 0x0F0F0F0F0F0F0F0FULL) <<  4) | ((x >>  4) & 0x0F0F0F0F0F0F0F0FULL);
            x = ((x & 0x00FF00FF00FF00FFULL) <<  8) | ((x >>  8) & 0x00FF00FF00FF00FFULL);
            x = ((x & 0x0000FFFF0000FFFFULL) << 16) | ((x >> 16) & 0x0000FFFF0000FFFFULL);
            dst = (x << 32) | (x >> 32);
            break;
        }
        case VeldOp::CBRANCH: {
            if ((dst >> (instr.mod & 0x3F)) & 1) {
#ifdef VELD_MAINNET_POW
                int8_t  signed_off = (int8_t)(instr.imm & 0xFF);
                int32_t target = (int32_t)pc + (int32_t)signed_off;
#else
                int32_t target = (int32_t)pc + ((int32_t)instr.imm & 0xF) + 1;
#endif
                if (target >= 0 && target < (int32_t)PROGRAM_SIZE)
                    pc = (uint32_t)target - 1;
            }
            break;
        }
        case VeldOp::ISTORE:  scratchpad_[addr] = src; break;

#ifdef VELD_MAINNET_POW
        case VeldOp::IADD_D: {
            size_t d_addr = ((dst ^ src) >> 3) & (DATASET_WORDS - 1);
            dst += DsWord_(d_addr);
            break;
        }
        case VeldOp::IXOR_D: {
            size_t d_addr = ((dst + src) >> 3) & (DATASET_WORDS - 1);
            dst ^= DsWord_(d_addr);
            break;
        }
        case VeldOp::IMIX_D: {
            size_t d_addr = ((dst * 0x9e3779b97f4a7c15ULL) >> 3) & (DATASET_WORDS - 1);
            uint64_t v = DsWord_(d_addr);
            dst = rotl64(dst + v, (uint32_t)(src & 63));
            break;
        }
        case VeldOp::IADD_C: dst += (uint64_t)instr.imm; break;
        case VeldOp::IMUL_C: dst *= ((uint64_t)instr.imm | 1ULL); break;

        case VeldOp::QADD_R: {
            int64_t& fdst = fixed_regs_[instr.dst & (FIXED_REG_COUNT - 1)];
            const int64_t fsrc =
                fixed_regs_[instr.src & (FIXED_REG_COUNT - 1)];
            fdst = VeldFixedAdd(
                fdst,
                VeldFixedAdd(
                    fsrc,
                    VeldFixedFromInteger(
                        static_cast<int64_t>(
                            static_cast<uint32_t>(src >> 32)))));
            const uint64_t fbits = VeldFixedBits(fdst);
            dst ^= rotr64(fbits, 23);
            break;
        }
        case VeldOp::QMUL_R: {
            int64_t& fdst = fixed_regs_[instr.dst & (FIXED_REG_COUNT - 1)];
            const int64_t fsrc =
                fixed_regs_[instr.src & (FIXED_REG_COUNT - 1)];
            fdst = VeldFixedMul(
                fdst, VeldFixedAdd(fsrc, VELD_FIXED_ONE + 1));
            const uint64_t fbits = VeldFixedBits(fdst);
            dst = (dst * 0x9e3779b97f4a7c15ULL) ^ fbits;
            break;
        }
        case VeldOp::QSUB_R: {
            int64_t& fdst = fixed_regs_[instr.dst & (FIXED_REG_COUNT - 1)];
            const int64_t fsrc =
                fixed_regs_[instr.src & (FIXED_REG_COUNT - 1)];
            const int64_t integer_term = VeldFixedFromInteger(
                VeldFixedSignedHigh32(src << 1));
            fdst = VeldFixedSub(
                fdst, VeldFixedSub(fsrc, integer_term));
            const uint64_t fbits = VeldFixedBits(fdst);
            dst += fbits;
            break;
        }
        case VeldOp::QSQRT_R: {
            int64_t& fdst = fixed_regs_[instr.dst & (FIXED_REG_COUNT - 1)];
            const int64_t integer_term = VeldFixedFromInteger(
                static_cast<int64_t>(((src >> 10) & 0xFFFFFFULL) + 1));
            fdst = VeldFixedSqrt(
                VeldFixedAdd(VeldFixedAbs(fdst), integer_term));
            const uint64_t fbits = VeldFixedBits(fdst);
            dst ^= fbits ^ rotl64(fbits, 31);
            break;
        }
#else
        case VeldOp::IADD_D:
        case VeldOp::IXOR_D:
        case VeldOp::IMIX_D:
        case VeldOp::IADD_C:
        case VeldOp::IMUL_C:
        case VeldOp::QADD_R:
        case VeldOp::QMUL_R:
        case VeldOp::QSUB_R:
        case VeldOp::QSQRT_R:
            break;
#endif

        default: break;
        }
    }
};

#ifdef VELD_MAINNET_POW
inline Hash256 ComputeEpochSeed(const Hash256& prev_hash, uint64_t height,
                                const CanonicalPowTarget& expected_target) {
    uint64_t epoch = height / DATASET_EPOCH_BLOCKS;
    SHA256 h;
    static const uint8_t TAG[8] = { 'V','E','L','D','_','E','P','C' };
    h.update(TAG, 8);
    h.update(prev_hash.data(), 32);
    uint8_t epoch_le[8];
    for (int i = 0; i < 8; ++i) epoch_le[i] = (uint8_t)((epoch >> (i * 8)) & 0xFF);
    h.update(epoch_le, 8);
    uint8_t bits_le[4];
    for (int i = 0; i < 4; ++i)
        bits_le[i] = static_cast<uint8_t>(
            expected_target.bits >> (i * 8));
    h.update(bits_le, 4);
    return h.digest();
}

inline Hash256 ComputeEpochSeed(const Hash256& prev_hash, uint64_t height,
                                uint32_t bits) {
    CanonicalPowTarget expected;
    if (!DecodeCanonicalVeldTarget(bits, expected)) return ZeroHash();
    return ComputeEpochSeed(prev_hash, height, expected);
}
#endif

inline Hash256 VeldHash(const std::vector<uint8_t>& header_bytes,
                         uint64_t block_height,
                         const CanonicalPowTarget& expected_target) {
#ifdef VELD_MAINNET_POW
    if (header_bytes.size() != 88) {
        throw std::invalid_argument("VeldHash: header_bytes must be exactly 88 bytes");
    }
    uint32_t header_bits = static_cast<uint32_t>(header_bytes[76]) |
        (static_cast<uint32_t>(header_bytes[77]) << 8) |
        (static_cast<uint32_t>(header_bytes[78]) << 16) |
        (static_cast<uint32_t>(header_bytes[79]) << 24);
    if (header_bits != expected_target.bits) {
        g_veldhash_last_dataset_ok() = false;
        Hash256 fail{}; fail.fill(0xff); return fail;
    }
#endif

    SHA256 h;
    h.update(header_bytes.data(), header_bytes.size());
    Hash256 seed = h.digest();

    VeldHashVM vm;
    vm.Initialize(seed);

#ifdef VELD_MAINNET_POW
    Hash256 prev_hash;
    std::memcpy(prev_hash.data(), header_bytes.data() + 4, 32);
    Hash256 ds_seed =
        ComputeEpochSeed(prev_hash, block_height, expected_target);
#ifdef VELD_LIGHT_VERIFY
    // Light-verify infra node: recompute dataset words on the fly; never hold the
    // 1 GB. Byte-identical to the full path (proven by VeldDatasetLightKat).
    g_veldhash_last_dataset_ok() = true;
    vm.SetLightKey(ds_seed);
#else
    DatasetHandle ds = GlobalDataset().get_for_seed(ds_seed);

    if (!ds.get()) {
        std::cerr << "  [VeldHash] CRITICAL: dataset unavailable for seed "
                  << HashToHex(ds_seed).substr(0,16) << "... — returning sentinel hash\n";
        std::cerr.flush();
        // Set a thread-local status flag so callers that validate
        // blocks can distinguish "dataset regen failed" from "hash
        // happens to be huge" — the former is a transient validator
        // fault (re-queue / retry), the latter is a real PoW failure
        // (reject the block).
        //
        // The 0xFF...FF sentinel VALUE is safe for verification
        // (Bitcoin-style bits encoding caps mantissa at 0x7FFFFF so
        // max target = 0x7F7FFF << (8*29) ≪ 0xFF...FF, always rejects).
        // The side-channel lets callers handle regen-fail specially
        // without depending on the hash bytes.
        g_veldhash_last_dataset_ok() = false;
        Hash256 fail{};
        fail.fill(0xFF);
        return fail;
    }
    g_veldhash_last_dataset_ok() = true;
    vm.SetDataset(ds.get());
#endif

    vm.Execute();

    auto state = vm.FinalizeRaw();
    return Blake2b256(state.data(), state.size());
#else
    vm.Execute();
    Hash256 vm_hash = vm.Finalize();
    return Hash256d(vm_hash.data(), vm_hash.size());
#endif
}

inline Hash256 VeldHash(const std::vector<uint8_t>& header_bytes,
                         uint64_t block_height = 0) {
#ifdef VELD_MAINNET_POW
    if (header_bytes.size() != 88)
        throw std::invalid_argument(
            "VeldHash: header_bytes must be exactly 88 bytes");
    const uint32_t bits = static_cast<uint32_t>(header_bytes[76]) |
        (static_cast<uint32_t>(header_bytes[77]) << 8) |
        (static_cast<uint32_t>(header_bytes[78]) << 16) |
        (static_cast<uint32_t>(header_bytes[79]) << 24);
    CanonicalPowTarget expected;
    if (!DecodeCanonicalVeldTarget(bits, expected)) {
        g_veldhash_last_dataset_ok() = false;
        Hash256 fail{}; fail.fill(0xff); return fail;
    }
    return VeldHash(header_bytes, block_height, expected);
#else
    CanonicalPowTarget unused;
    return VeldHash(header_bytes, block_height, unused);
#endif
}

inline Hash256 VeldHash(const uint8_t* header_bytes, size_t len, uint64_t block_height = 0) {
    return VeldHash(std::vector<uint8_t>(header_bytes, header_bytes + len), block_height);
}

struct VeldHashResult {
    bool     found;
    uint64_t nonce;
    Hash256  hash;
    uint64_t hashes_tried;
    double   elapsed_seconds;
    double   hash_rate;
};

inline VeldHashResult VeldHashMine(
    std::vector<uint8_t> header_bytes,
    const Hash256& target,
    std::atomic<bool>& stop,
    std::function<void(uint64_t)> progress_cb = nullptr,
    uint64_t block_height = 0
) {
    VeldHashResult result{};
    result.found = false;

    auto start = std::chrono::steady_clock::now();
    uint64_t hashes = 0;

    for (uint64_t nonce = 0; ; ++nonce) {
        if (stop.load()) break;

        for (int b = 0; b < 8; ++b)
            header_bytes[80 + b] = (uint8_t)((nonce >> (b * 8)) & 0xFF);

        Hash256 hash = VeldHash(header_bytes, block_height);
        ++hashes;

        if (hash < target) {
            result.found       = true;
            result.nonce       = nonce;
            result.hash        = hash;
            result.hashes_tried = hashes;
            auto end = std::chrono::steady_clock::now();
            result.elapsed_seconds = std::chrono::duration<double>(end - start).count();
            result.hash_rate = hashes / std::max(result.elapsed_seconds, 0.001);
            return result;
        }

        if (progress_cb && hashes % 10000 == 0) progress_cb(hashes);
        if (nonce == UINT64_MAX) break;
    }

    auto end = std::chrono::steady_clock::now();
    result.elapsed_seconds = std::chrono::duration<double>(end - start).count();
    result.hashes_tried = hashes;
    result.hash_rate = hashes / std::max(result.elapsed_seconds, 0.001);
    return result;
}

inline double EstimateBlockTime(double hash_rate_per_sec, const Hash256& target) {

    int leading_zeros = 0;
    for (int i = 0; i < 32; ++i) {
        if (target[i] == 0) {
            leading_zeros += 8;
        } else {
            uint8_t b = target[i];
            while (!(b & 0x80)) { ++leading_zeros; b <<= 1; }
            break;
        }
    }

    double difficulty = std::pow(2.0, leading_zeros);
    return difficulty / std::max(hash_rate_per_sec, 1.0);
}

inline std::string GetAlgorithmInfo() {
    std::ostringstream oss;
#ifdef VELD_MAINNET_POW
    oss << "Algorithm:      VeldHash v3 (mainnet, deterministic fixed-point)\n";
    oss << "Type:           Memory-hard SuperScalar PoW (integer + Q40.24)\n";
    oss << "Scratchpad:     " << SCRATCHPAD_SIZE / 1024 / 1024 << " MB\n";
    oss << "Dataset:        " << (DATASET_SIZE / 1024 / 1024) << " MB (epoch seed from prev_hash + height/" << DATASET_EPOCH_BLOCKS << ")\n";
    oss << "Program size:   " << PROGRAM_SIZE << " instructions\n";
    oss << "Iterations:     " << PROGRAM_ITERATIONS << " rounds/hash\n";
    oss << "Int registers:  " << REGISTER_COUNT << " x 64-bit\n";
    oss << "Fixed registers:" << FIXED_REG_COUNT << " x signed Q40.24 (persistent)\n";
    oss << "PRNG:           ChaCha20 (RFC 7539)\n";
    oss << "Finalizer:      Blake2b-256 (RFC 7693, single pass)\n";
    oss << "Operations:     " << (int)VeldOp::COUNT << " distinct opcodes\n";
    oss << "ASIC resistance:\n";
    oss << "  + Dual random-access memory (scratchpad + dataset)\n";
    oss << "  + Data-dependent branching (CBRANCH)\n";
    oss << "  + Per-block unique program + dataset seed\n";
    oss << "  + Superscalar + fixed-point execution dependency chains\n";
    oss << "  + Cryptographic PRNG + finalizer\n";
#else
    oss << "Algorithm:      VeldHash v1 (testnet)\n";
    oss << "Type:           Memory-hard SuperScalar PoW (integer-only)\n";
    oss << "Scratchpad:     " << SCRATCHPAD_SIZE / 1024 << " KB (L2 cache resident)\n";
    oss << "Program size:   " << PROGRAM_SIZE << " instructions\n";
    oss << "Iterations:     " << PROGRAM_ITERATIONS << " rounds/hash\n";
    oss << "Registers:      " << REGISTER_COUNT << " x 64-bit integer\n";
    oss << "Operations:     " << (int)VeldOp::COUNT << " distinct opcodes (all integer)\n";
    oss << "Production:     VeldHash v3 — compile with -DVELD_MAINNET_POW\n";
#endif
    return oss.str();
}

}
}
