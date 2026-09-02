#pragma once
//
// Constant-product VELD/btcVELD consensus pool. AMM operations spend and
// recreate the pool's VELD covenant UTXO, preserve x*y>=k, move btcVELD through
// the token ledger, and require the user's signature for debited balances.
//
#include "hash.h"
#include "block.h"
#include "script.h"
#include "op_authorization.h"
#include "onchain_tokens.h"
#include "../consensus/state_digest.h"
#include "../consensus/btcveld_amm_gate.h"   // Layer-4 swap gate + pool btcVELD cap (51%-defense §6)
#include "../consensus/btcveld_peg_gate.h"   // state-derived launch/liveness gate
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <algorithm>
#include <optional>
#include <sstream>
#include <array>
#include <cstdint>
#include <cmath>
#include <limits>

namespace veld {

// One-time authority for the first market-priced VELD/btcVELD seed.  Reuse
// the isolated btcVELD issuer identity so launch does not introduce another
// production secret.  This authority is consulted only while the singleton
// pool is unseeded; every later ADD/REMOVE/SWAP remains permissionless.
inline constexpr const char* BTCVELD_AMM_LAUNCH_AUTHORITY_ADDRESS =
    BTCVELD_ISSUER_ADDRESS;

// floor(sqrt(n)) for a non-negative 128-bit value.
inline int64_t IsqrtU128(unsigned __int128 n) {
    if (n == 0) return 0;
    unsigned __int128 x = (unsigned __int128)std::sqrt((double)(long double)n) + 2;
    while (x > 0 && x * x > n) --x;
    while ((x + 1) * (x + 1) <= n) ++x;
    return (int64_t)x;
}

struct AmmPool {
    int64_t  reserve_veld    = 0;
    int64_t  reserve_btcveld = 0;
    int64_t  lp_supply       = 0;
    // LP units attributed to no identity are permanently non-withdrawable.
    // This generalises the existing
    // MIN_LIQUIDITY lock: the first provider is denied ownership of a fraction
    // of initial LP according to the per-leg seed floors. This is an LP-
    // ownership lock, not a perpetual
    // per-asset reserve floor or a fixed-market-value bond: swaps may reshape
    // the assets represented by the locked units while the opening anchor stays
    // immutable. Because locked units belong to nobody there is no partial-
    // removal-around-a-floor rule to specify.
    // INVARIANT: lp_supply == sum(lp_[pool:*]) + locked_lp.
    int64_t  locked_lp       = 0;
    uint32_t fee_bps         = BTCVELD_AMM_FEE_BPS;   // consensus ceiling (1%); quote fee is direction/anchor aware
    // Immutable opening-price anchor.  It is set exactly once by the first
    // liquidity seed and never follows later swaps/adds/removes.  Dynamic fees
    // compare each quote's post-trade ratio to this seed ratio.
    int64_t  anchor_veld     = 0;
    int64_t  anchor_btcveld  = 0;
    bool     exists          = false;
    // on-chain binding (increment 2): the pool's VELD lives in this chained UTXO
    Hash256  pool_txid{};
    uint32_t pool_vout   = 0;
    bool     utxo_valid  = false;
    std::vector<uint8_t> veld_script;     // pool covenant scriptPubKey
    std::string          btcveld_addr;    // pool's btcVELD ledger address
};

struct AmmOp { std::string action, user; int64_t amt = 0, extra = 0; };

// VELD-to-btcVELD swaps must commit to a positive minimum receive amount.
// Requiring the commitment in consensus prevents handcrafted transactions from
// opting out of slippage protection. The reverse direction has an exact native
// payout in output[1], so its canonical marker value remains zero.
inline bool AmmSwapMinimumOutputSatisfied(bool veld_in, int64_t minimum_out,
                                          int64_t actual_out) {
    if (actual_out <= 0) return false;
    return veld_in ? minimum_out > 0 && actual_out >= minimum_out
                   : minimum_out == 0;
}

enum class AmmOpParseStatus : uint8_t { NONE = 0, VALID, INVALID };

struct AmmOpParseResult {
    AmmOpParseStatus status = AmmOpParseStatus::NONE;
    AmmOp op;
};

inline std::string EncodeAmmOp(const AmmOp& op) {
    std::ostringstream ss;
    ss << "VELD_AMM|" << op.action << "|" << op.user << "|" << op.amt << "|" << op.extra;
    return ss.str();
}

// Parse exactly the signed decimal representation emitted by EncodeAmmOp.
// std::stoll without a consumed-length check accepts ambiguous prefixes such as
// "1junk", leading whitespace, and a leading '+'.  Consensus data must have one
// byte representation, including no leading zeroes and no negative zero.
inline bool ParseCanonicalAmmI64(const std::string& s, int64_t* out) {
    if (!out || s.empty()) return false;
    bool negative = false;
    size_t pos = 0;
    if (s[0] == '-') {
        negative = true;
        pos = 1;
        if (pos == s.size()) return false;
    } else if (s[0] == '+') {
        return false;
    }
    if (s[pos] == '0' && pos + 1 != s.size()) return false;
    if (negative && s[pos] == '0') return false;

    const uint64_t limit = negative
        ? (uint64_t)INT64_MAX + uint64_t{1}
        : (uint64_t)INT64_MAX;
    uint64_t value = 0;
    for (; pos < s.size(); ++pos) {
        const unsigned char c = (unsigned char)s[pos];
        if (c < '0' || c > '9') return false;
        const uint64_t digit = (uint64_t)(c - '0');
        if (value > (limit - digit) / 10) return false;
        value = value * 10 + digit;
    }
    if (negative) {
        *out = value == (uint64_t)INT64_MAX + uint64_t{1}
            ? INT64_MIN : -(int64_t)value;
    } else {
        *out = (int64_t)value;
    }
    return true;
}

// Scan the whole transaction.  More than one AMM marker is invalid even when
// the first marker is valid and a later one is malformed: choosing "the first"
// would make output ordering change consensus meaning and leave other consumers
// free to choose a different marker.  Other OP_RETURN families are ignored.
inline AmmOpParseResult ParseAmmOpDetailed(const Transaction& tx) {
    AmmOpParseResult result;
    size_t markers = 0;
    size_t op_return_outputs = 0;
    for (const auto& o : tx.outputs) {
        if (!o.script_pubkey.empty() && o.script_pubkey[0] == 0x6a)
            ++op_return_outputs;
        std::string s = ParseOpReturn(o.script_pubkey);
        if (s.rfind("VELD_AMM|", 0) != 0) continue;
        if (++markers != 1) {
            result.status = AmmOpParseStatus::INVALID;
            return result;
        }

        // Consensus markers have exactly one byte encoding.  The generic
        // ParseOpReturn helper intentionally accepts legacy/non-minimal pushes
        // and ignores trailing bytes for non-consensus UI consumers.  An AMM
        // marker cannot inherit that permissiveness: PUSHDATA1/2 aliases or a
        // byte appended after the declared payload would otherwise describe
        // the same pool transition under a different txid.  Re-encode with the
        // canonical builder and require byte equality.
        if (o.script_pubkey != BuildOpReturnScript(s)) {
            result.status = AmmOpParseStatus::INVALID;
            return result;
        }

        // An AMM transaction is one atomic protocol operation.  Allowing a
        // second OP_RETURN lets a token TRANSFER/REDEEM/SPV mint mutate the
        // token ledger before ApplyAmmOpLocked runs.  Such a transaction could
        // pass the parent-state AMM mempool check, then be impossible to mine
        // while occupying the sole AMM slot.  It also creates cross-module
        // ordering aliases.  Bundled AMM builders emit exactly one zero-value
        // marker, so fail closed on every mixed-protocol/junk carrier.
        if (o.value != 0) {
            result.status = AmmOpParseStatus::INVALID;
            return result;
        }

        std::vector<std::string> fields;
        size_t begin = 9;
        for (;;) {
            const size_t end = s.find('|', begin);
            if (end == std::string::npos) {
                fields.push_back(s.substr(begin));
                break;
            }
            fields.push_back(s.substr(begin, end - begin));
            begin = end + 1;
        }
        if (fields.size() != 4 || fields[0].empty() || fields[1].empty() ||
            !ParseCanonicalAmmI64(fields[2], &result.op.amt) ||
            !ParseCanonicalAmmI64(fields[3], &result.op.extra)) {
            result.status = AmmOpParseStatus::INVALID;
            return result;
        }
        result.op.action = fields[0];
        result.op.user = fields[1];
        result.status = AmmOpParseStatus::VALID;
    }
    if (result.status == AmmOpParseStatus::VALID && op_return_outputs != 1)
        result.status = AmmOpParseStatus::INVALID;
    return result;
}

inline std::optional<AmmOp> ParseAmmOp(const Transaction& tx) {
    AmmOpParseResult parsed = ParseAmmOpDetailed(tx);
    if (parsed.status != AmmOpParseStatus::VALID) return std::nullopt;
    return parsed.op;
}

// Deterministic pool VELD covenant scriptPubKey. The real block validator
// special-cases this script (spendable ONLY by a valid AMM-op tx); here it is a
// unique recognizable marker keyed by pool_id.
inline std::vector<uint8_t> PoolVeldScript(const std::string& pool_id) {
    std::string tag = "AMMPOOLv1:" + pool_id;
    std::vector<uint8_t> s(tag.begin(), tag.end());
    return s;
}

// Recognize the pool covenant marker (any pool_id). The block validator uses
// this to spot a UTXO spendable ONLY via a consensus-checked AMM op.
inline bool IsAmmPoolScript(const std::vector<uint8_t>& script) {
    static const char pfx[] = "AMMPOOLv1:";
    size_t n = sizeof(pfx) - 1;
    return script.size() > n && std::equal(pfx, pfx + n, script.begin());
}

// A valid AMM operation receives deterministic first position in a block
// template because every live operation advances one singleton covenant UTXO.
// That liveness exception must not become a low-fee block-padding primitive.
// Twenty-four current ML-DSA funding inputs plus the signatureless pool input
// fit just below 128 KiB; the byte cap also remains authoritative if the wire
// encoding ever changes.  These are consensus limits, mirrored by mempool and
// the bundled RPC builders.
inline constexpr size_t MAX_AMM_FUNDING_INPUTS = 24;
inline constexpr size_t MAX_AMM_TX_BYTES = 128u * 1024u;

inline bool AmmTransactionEnvelopeWithinBounds(const Transaction& tx) {
    if (tx.version != 1 || tx.locktime != 0 || tx.inputs.empty() ||
        tx.inputs.size() > MAX_AMM_FUNDING_INPUTS + 1 ||
        tx.Serialize().size() > MAX_AMM_TX_BYTES)
        return false;
    for (const auto& in : tx.inputs) {
        if (in.sequence != 0xFFFFFFFFu) return false;
    }
    return true;
}

// Authorization: does `tx` carry a VALID signature from `address`?
// Verify authorization cryptographically. Merely finding a public key in an input
// would allow a covenant input to impersonate that key's owner.
// Now delegates to the shared verified-signer check (op_authorization.h): a key in a
// sigless input contributes nothing because it carries no valid signature. Thin
// alias so the SWAP/ADD/REMOVE call sites are unchanged.
inline bool AmmTxSignedBy(const Transaction& tx, const std::string& address) {
    return TxVerifiedSignedBy(tx, address);
}

class AmmLedger {
public:
    static constexpr int64_t  MIN_LIQUIDITY = 1000;
    static constexpr uint32_t FEE_DENOM     = 10000;

    // Per-leg admission floors for the first seed also define the permanent
    // denominators of the permanent lock.  One pair of constants does both
    // jobs, which guarantees the locked fraction f <= 1 by construction.
    //
    // WHY: AmmPool::anchor_veld/anchor_btcveld is set exactly once by the first
    // seed, is immutable, and is digest-committed.  The four-band fee model
    // classifies EVERY future swap by deviation from it, so consensus pins the
    // initial ratio before any public pool exists. Arbitrage moves reserves; it
    // never changes the anchor. The old
    // product threshold (g > MIN_LIQUIDITY, i.e. V*B >= 1,002,001) admitted
    // economically tiny extreme-ratio seeds: 1 VELD x 10,000 sats passes it.
    //
    // A seed with EITHER leg at its floor locks its entire LP position (see
    // LockedSeedUnits), so the floor-one-leg dodge receives no withdrawable LP.
    // That statement is deliberately about ownership, not economic sacrifice.
    // Market-anchor profiles separately require the one-time launch authority
    // plus the resource-bound liveness probe; legacy profiles retain the fixed
    // launch-ratio check.
    static constexpr int64_t AMM_SEED_LOCK_VELD_UNITS   = 5'000'000'000;  // 50 VELD
    static constexpr int64_t AMM_SEED_LOCK_BTCVELD_SATS = 50'000;         // 10% of pool ceiling
    // Minimum withdrawable LP position (D-STATE-02).  A seed whose remainder
    // would be sub-minimum dust is invalid, fail-closed, rather than rounded.
    static constexpr int64_t LP_MIN_POSITION            = 1000;

    // ---- D-STATE-02: active LP identity ceiling ----------------------------
    // lp_ erases a position only at zero, and ADD can mint to a fresh address.
    // The aggregate custody-bound pool ceiling does NOT bound identity count over time:
    // swaps and removals reduce reserves, after which new providers add while
    // older positive positions remain. The singleton pool UTXO limits growth to
    // one accepted AMM op per block, but that is ~175,200 identities per year
    // for the life of the chain.
    //
    // At capacity: existing identities may ADD or REMOVE freely, a full REMOVE
    // prunes and frees a slot, and a NEW identity fails with no state mutation.
    // Live positions are never evicted.
    static constexpr size_t AMM_MAX_LP_IDENTITIES = 65536;
    static constexpr const char* FEE_MODEL_ID = "seed-ratio-output-asset-4band-v1";
    static constexpr size_t MAX_FUNDING_INPUTS = MAX_AMM_FUNDING_INPUTS;
    static constexpr size_t MAX_TX_BYTES = MAX_AMM_TX_BYTES;

    // Stable machine-readable quote failures.  A rejected quote is never
    // executable; callers must not infer a fallback fee from the code.
    enum class SwapRejectCode : uint8_t {
        NONE = 0,
        FEE_MODEL_NOT_ACTIVE,
        INVALID_ANCHOR,
        INVALID_STATE,
        FEE_SCHEDULE_NO_FIXED_POINT,
    };

    static const char* SwapRejectCodeName(SwapRejectCode code) {
        switch (code) {
            case SwapRejectCode::NONE: return "NONE";
            case SwapRejectCode::FEE_MODEL_NOT_ACTIVE: return "FEE_MODEL_NOT_ACTIVE";
            case SwapRejectCode::INVALID_ANCHOR: return "INVALID_ANCHOR";
            case SwapRejectCode::INVALID_STATE: return "INVALID_STATE";
            case SwapRejectCode::FEE_SCHEDULE_NO_FIXED_POINT:
                return "FEE_SCHEDULE_NO_FIXED_POINT";
        }
        return "INVALID_STATE";
    }

    static bool FourBandActive(uint64_t height) {
        // Match the other consensus activation gates: zero means deliberately
        // dormant/unconfigured, never "active since height zero".  A release
        // profile must choose an explicit non-zero activation identity.
        return BTCVELD_AMM_FOURBAND_ACTIVATION_HEIGHT != 0 &&
               height >= BTCVELD_AMM_FOURBAND_ACTIVATION_HEIGHT;
    }

    struct SwapQuote {
        int64_t  gross_out       = -1; // invariant output before the LP fee
        int64_t  amount_out      = -1; // net output delivered to the trader
        int64_t  fee_out         = 0;  // retained in the output reserve
        uint32_t fee_bps         = BTCVELD_AMM_FEE_BPS;
        bool     rebalances_anchor = false;  // healing: post-trade deviation <= pre-trade (four-band spec §1.2)
        uint8_t  band            = 0;        // 1..4 post-trade band (0 = unset / rejected)
        bool     reject          = false;    // fail-closed quote; reject_code is the stable reason
        SwapRejectCode reject_code = SwapRejectCode::NONE;
        bool     fee_model_active = false;
        int64_t  post_reserve_veld = 0;
        int64_t  post_reserve_btcveld = 0;
        unsigned __int128 pre_deviation_num = 0;
        unsigned __int128 pre_deviation_den = 0;
        unsigned __int128 post_deviation_num = 0;
        unsigned __int128 post_deviation_den = 0;
        uint32_t pre_deviation_bps = 0;   // display-only floor, capped at 100%
        uint32_t post_deviation_bps = 0;  // display-only floor, capped at 100%
    };

    static std::string U128Decimal(unsigned __int128 value) {
        if (value == 0) return "0";
        std::string out;
        while (value != 0) {
            out.push_back((char)('0' + (uint8_t)(value % 10)));
            value /= 10;
        }
        std::reverse(out.begin(), out.end());
        return out;
    }

    // Consensus-safe positive floor(a*b/divisor) conversion.  The quotient is
    // formed in u128 and range-checked before converting to the signed ledger
    // unit type; callers must never rely on an implementation-defined narrowing
    // conversion when an extreme reserve ratio exceeds INT64_MAX.
    static bool CheckedMulDivPositiveI64(int64_t a, int64_t b,
                                         int64_t divisor, int64_t* out) {
        if (!out || a <= 0 || b <= 0 || divisor <= 0) return false;
        const unsigned __int128 q =
            (unsigned __int128)(uint64_t)a * (uint64_t)b /
            (uint64_t)divisor;
        if (q == 0 || q > (unsigned __int128)INT64_MAX) return false;
        *out = (int64_t)q;
        return true;
    }

    struct U192 { uint64_t lo = 0, mid = 0, hi = 0; };

    static U192 MulU128U64(unsigned __int128 a, uint64_t b) {
        uint64_t alo = (uint64_t)a;
        uint64_t ahi = (uint64_t)(a >> 64);
        unsigned __int128 p0 = (unsigned __int128)alo * b;
        unsigned __int128 p1 = (unsigned __int128)ahi * b;
        U192 r;
        r.lo = (uint64_t)p0;
        unsigned __int128 middle = (p0 >> 64) + (uint64_t)p1;
        r.mid = (uint64_t)middle;
        r.hi = (uint64_t)(p1 >> 64) + (uint64_t)(middle >> 64);
        return r;
    }

    static int CompareU192(const U192& a, const U192& b) {
        if (a.hi != b.hi) return a.hi < b.hi ? -1 : 1;
        if (a.mid != b.mid) return a.mid < b.mid ? -1 : 1;
        if (a.lo != b.lo) return a.lo < b.lo ? -1 : 1;
        return 0;
    }

    static unsigned __int128 AnchorCrossDistance(
        int64_t veld, int64_t btcveld, int64_t anchor_veld,
        int64_t anchor_btcveld) {
        unsigned __int128 lhs = (unsigned __int128)(uint64_t)veld *
                                (uint64_t)anchor_btcveld;
        unsigned __int128 rhs = (unsigned __int128)(uint64_t)btcveld *
                                (uint64_t)anchor_veld;
        return lhs >= rhs ? lhs - rhs : rhs - lhs;
    }

    // floor(10000*num/den), saturated at 10000, without overflowing u128.
    static uint32_t RatioBpsCapped(unsigned __int128 num,
                                   unsigned __int128 den) {
        if (den == 0 || num >= den) return FEE_DENOM;
        const U192 scaled_num = MulU128U64(num, FEE_DENOM);
        uint32_t lo = 0, hi = FEE_DENOM;
        while (lo + 1 < hi) {
            uint32_t mid = lo + (hi - lo) / 2;
            if (CompareU192(scaled_num, MulU128U64(den, mid)) >= 0)
                lo = mid;
            else
                hi = mid;
        }
        return lo;
    }

    // Four-band deviation classifier (four-band spec §2.3). Given the post-trade
    //   delta = |R_v·A_b − R_b·A_v|   and   den = R_b·A_v ,
    // return the band's LP fee (bps). The exact comparison "D = delta/den <= edge/FEE_DENOM"
    // is done division-free as  FEE_DENOM·delta <= edge·den  in checked 192-bit products.
    // Edges are CLOSED-LOWER: exactly 5/10/20% belongs to the lower band. Writes the 1..4
    // band index through band_index when non-null. den==0 is degenerate (non-positive
    // anchor/reserve, already rejected by callers) -> band 4 fail-safe.
    static uint32_t BandFeeBps(unsigned __int128 delta, unsigned __int128 den,
                               uint8_t* band_index = nullptr) {
        auto pick = [&](uint8_t b, uint32_t fee) { if (band_index) *band_index = b; return fee; };
        if (den == 0) return pick(4, BTCVELD_AMM_BAND_FEE_BPS[3]);
        const U192 lhs = MulU128U64(delta, (uint64_t)FEE_DENOM);   // FEE_DENOM · delta
        auto within = [&](int i) {
            return CompareU192(lhs, MulU128U64(den, (uint64_t)BTCVELD_AMM_BAND_EDGE_BPS[i])) <= 0;
        };
        if (within(0)) return pick(1, BTCVELD_AMM_BAND_FEE_BPS[0]);   // D <= 5%
        if (within(1)) return pick(2, BTCVELD_AMM_BAND_FEE_BPS[1]);   // 5% < D <= 10%
        if (within(2)) return pick(3, BTCVELD_AMM_BAND_FEE_BPS[2]);   // 10% < D <= 20%
        return pick(4, BTCVELD_AMM_BAND_FEE_BPS[3]);                  // D > 20%
    }

    // Constant-product gross output before fees, floored toward the pool.
    static int64_t GrossSwapOut(int64_t rin, int64_t rout, int64_t amt_in) {
        if (rin <= 0 || rout <= 0 || amt_in <= 0) return -1;
        int64_t gross = (int64_t)(
            (unsigned __int128)(uint64_t)rout * (uint64_t)amt_in /
            ((unsigned __int128)(uint64_t)rin + (uint64_t)amt_in));
        if (gross <= 0 || gross >= rout) return -1;
        return gross;
    }

    // Net output after charging the fee IN THE OUTPUT ASSET.  The entire input
    // enters the pool; gross_out-amount_out remains in the output reserve and is
    // therefore owned pro rata by LPs.  There is no protocol/treasury cut.
    static int64_t SwapOut(int64_t rin, int64_t rout, int64_t amt_in, uint32_t fee_bps) {
        if (fee_bps >= FEE_DENOM) return -1;
        int64_t gross = GrossSwapOut(rin, rout, amt_in);
        if (gross < 0) return -1;
        int64_t out = (int64_t)((unsigned __int128)(uint64_t)gross *
                                (FEE_DENOM - fee_bps) / FEE_DENOM);
        if (out <= 0 || out >= rout) return -1;
        return out;
    }

    void Reset() { std::lock_guard<std::mutex> lk(mu_); pools_.clear(); lp_.clear(); }

    // Atomic block-state snapshot and restore. Captures every
    // block-mutable member (the same two that Reset() clears; never the mutex)
    // so the block-connect path can roll the pool ledger back verbatim on an
    // all-or-nothing block reject. Digest() commits the same state, including
    // the immutable seed-ratio anchor used by consensus fee quotes.
    struct StateSnapshot {
        std::unordered_map<std::string, AmmPool> pools;
        std::unordered_map<std::string, int64_t> lp;
    };
    StateSnapshot SnapshotState() const {
        std::lock_guard<std::mutex> lk(mu_);
        return StateSnapshot{ pools_, lp_ };
    }
    void RestoreState(const StateSnapshot& s) {
        std::lock_guard<std::mutex> lk(mu_);
        pools_ = s.pools;
        lp_    = s.lp;
    }

    void CreatePool(const std::string& pool_id, uint32_t fee_bps) {
        std::lock_guard<std::mutex> lk(mu_);
        AmmPool& p = pools_[pool_id];
        if (!p.exists) { p = AmmPool{};
                         p.fee_bps = fee_bps == 0 ? BTCVELD_AMM_FEE_BPS
                             : std::clamp<uint32_t>(fee_bps, BTCVELD_AMM_FEE_MIN_BPS,
                                                    BTCVELD_AMM_FEE_BPS);
                         p.exists = true;
                         p.veld_script = PoolVeldScript(pool_id); p.btcveld_addr = "AMM:" + pool_id; }
    }

#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
    // Qualification-only in-band carrier transition. VeldNode invokes this
    // from ApplyBlockModules_ after decoding the address from canonical block
    // bytes. Public builds cannot contain the seam. The arithmetic and public
    // mutators are the same ones used by the production AMM implementation.
    bool ApplyDStateQualificationLp(const std::string& pool_id,
                                    const std::string& address) {
        AmmPool pool = GetPool(pool_id);
        // ProcessBlock creates the launch-active pool before this in-band
        // qualification carrier runs.  An existing zero-supply pool is still
        // unseeded and must take the same first-provider path as an absent
        // pool; otherwise the real node ingest rejects the first S5 frame.
        if (!pool.exists || pool.lp_supply == 0) {
            if (!pool.exists) CreatePool(pool_id, BTCVELD_AMM_FEE_BPS);
            const auto seed = AddLiquidity(
                pool_id, address,
                40 * AMM_SEED_LOCK_VELD_UNITS,
                40 * AMM_SEED_LOCK_BTCVELD_SATS);
            if (seed.lp_minted <= LP_MIN_POSITION) return false;
            const auto trim = RemoveLiquidity(
                pool_id, address, seed.lp_minted);
            if (trim.veld_out < 0 || trim.btcveld_out < 0 ||
                GetLp(pool_id, address) != 0)
                return false;
            pool = GetPool(pool_id);
        }
        if (GetLp(pool_id, address) != 0 || pool.reserve_veld <= 0 ||
            pool.reserve_btcveld <= 0 || pool.lp_supply <= 0)
            return false;
        const unsigned __int128 numerator =
            static_cast<unsigned __int128>(LP_MIN_POSITION) *
            static_cast<uint64_t>(pool.reserve_veld);
        const uint64_t denominator =
            static_cast<uint64_t>(pool.lp_supply);
        const uint64_t base = static_cast<uint64_t>(
            (numerator + denominator - 1) / denominator);
        const uint64_t btc_min = static_cast<uint64_t>(
            (static_cast<unsigned __int128>(LP_MIN_POSITION) *
                 static_cast<uint64_t>(pool.reserve_btcveld) +
             denominator - 1) /
            denominator);
        const uint64_t veld_for_btc = static_cast<uint64_t>(
            (static_cast<unsigned __int128>(btc_min) *
                 static_cast<uint64_t>(pool.reserve_veld) +
             static_cast<uint64_t>(pool.reserve_btcveld) - 1) /
            static_cast<uint64_t>(pool.reserve_btcveld));
        const uint64_t veld = std::max(base, veld_for_btc);
        if (veld <= static_cast<uint64_t>(INT64_MAX)) {
            const uint64_t btc = static_cast<uint64_t>(
                static_cast<unsigned __int128>(veld) *
                static_cast<uint64_t>(pool.reserve_btcveld) /
                static_cast<uint64_t>(pool.reserve_veld));
            if (btc == 0 || btc > static_cast<uint64_t>(INT64_MAX))
                return false;
            const auto added = AddLiquidity(
                pool_id, address, static_cast<int64_t>(veld),
                static_cast<int64_t>(btc));
            return added.lp_minted >= LP_MIN_POSITION &&
                   added.btcveld_used == static_cast<int64_t>(btc);
        }
        return false;
    }
#endif

    // ---- A4 locked-seed-core math -------------------------------------------
    // ceil(a/b) on unsigned 128-bit.  b > 0 enforced by callers (both floors
    // are nonzero constants).
    static int64_t CeilDivU128(unsigned __int128 a, unsigned __int128 b) {
        return (int64_t)((a + b - 1) / b);
    }

    // Permanent lock for a first seed of (V, B) minting g LP units.
    //
    //   locked = max( MIN_LIQUIDITY,
    //                 ceil(g * LOCK_VELD / V),
    //                 ceil(g * LOCK_SATS / B) )
    //
    // Both legs are >= their floor (admission enforces it), so each ceil term
    // is <= g and locked <= g holds by construction.  If EITHER leg sits at its
    // floor the binding term equals g and the entire seed locks.
    static int64_t LockedSeedUnits(int64_t g, int64_t V, int64_t B) {
        const int64_t by_veld = CeilDivU128((unsigned __int128)(uint64_t)g *
                                            (uint64_t)AMM_SEED_LOCK_VELD_UNITS,
                                            (unsigned __int128)(uint64_t)V);
        const int64_t by_btc  = CeilDivU128((unsigned __int128)(uint64_t)g *
                                            (uint64_t)AMM_SEED_LOCK_BTCVELD_SATS,
                                            (unsigned __int128)(uint64_t)B);
        int64_t locked = MIN_LIQUIDITY;
        if (by_veld > locked) locked = by_veld;
        if (by_btc  > locked) locked = by_btc;
        if (locked  > g)      locked = g;      // defensive; unreachable given admission
        return locked;
    }

    // Canonical first-seed quote shared by consensus, RPC and tests.  Keeping
    // all A4 floor/lock/sliver arithmetic here prevents a wallet from showing
    // the retired `g - MIN_LIQUIDITY` result for a seed that consensus will
    // either reject or lock more heavily.  `gross_lp` is total initial supply;
    // only `lp_minted` is owned and withdrawable by the seeder.
    struct SeedQuote {
        bool valid = false;
        int64_t gross_lp = 0;
        int64_t locked_lp = 0;
        int64_t lp_minted = 0;
    };

    static bool IsCanonicalOpeningSeedRatio(int64_t veld_units,
                                            int64_t btcveld_sats) {
        if (veld_units <= 0 || btcveld_sats <= 0 ||
            btcveld_sats > INT64_MAX /
                BTCVELD_AMM_OPENING_VELD_UNITS_PER_BTCVELD_SAT)
            return false;
        return veld_units == btcveld_sats *
            BTCVELD_AMM_OPENING_VELD_UNITS_PER_BTCVELD_SAT;
    }

    static bool MarketSeedAnchorActive(uint64_t height) noexcept {
#if defined(VELD_BTCVELD_REGTEST)
        // The disposable L3 profile exercises the same one-time market-seed
        // rule without compiling a public-release artifact.  All L3 nodes must
        // share this macro/profile; public releases use the explicit activation
        // constant below.
        return height >= 1;
#else
        return BTCVELD_AMM_MARKET_SEED_ACTIVATION_HEIGHT != 0 &&
               height >= BTCVELD_AMM_MARKET_SEED_ACTIVATION_HEIGHT;
#endif
    }

    static bool InitialSeedAuthorized(const std::string& user,
                                      uint64_t height) noexcept {
        return !MarketSeedAnchorActive(height) ||
               user == BTCVELD_AMM_LAUNCH_AUTHORITY_ADDRESS;
    }

private:
    static SeedQuote QuoteInitialSeedPolicy_(int64_t veld_units,
                                             int64_t btcveld_sats,
                                             bool market_anchor) {
        SeedQuote quote;
        if ((!market_anchor &&
             !IsCanonicalOpeningSeedRatio(veld_units, btcveld_sats)) ||
            veld_units < AMM_SEED_LOCK_VELD_UNITS ||
            btcveld_sats < AMM_SEED_LOCK_BTCVELD_SATS ||
            btcveld_sats > BTCVELD_AMM_MAX_POOL_BTCVELD_SATS ||
            static_cast<uint64_t>(veld_units) > MAX_SUPPLY_UNITS)
            return quote;
        quote.gross_lp = IsqrtU128(
            (unsigned __int128)(uint64_t)veld_units *
            (uint64_t)btcveld_sats);
        if (quote.gross_lp <= MIN_LIQUIDITY) return SeedQuote{};
        quote.locked_lp = LockedSeedUnits(
            quote.gross_lp, veld_units, btcveld_sats);
        quote.lp_minted = quote.gross_lp - quote.locked_lp;
        if (quote.lp_minted != 0 && quote.lp_minted < LP_MIN_POSITION)
            return SeedQuote{};
        quote.valid = true;
        return quote;
    }

public:

    static SeedQuote QuoteInitialSeed(int64_t veld_units,
                                      int64_t btcveld_sats) {
        return QuoteInitialSeedPolicy_(veld_units, btcveld_sats,
                                       /*market_anchor=*/false);
    }

    // First-seed admission rule. Market-anchor profiles accept the authorized
    // seed's submitted ratio; legacy profiles require the fixed launch ratio.
    // Both reject a seed for which neither swap direction can execute inside
    // the native-supply, btcVELD-pool, dust, token-account, four-band, and
    // swap-gate bounds.
    // Later ADD operations deliberately do not run this probe.
    static constexpr const char* SEED_LIVENESS_POLICY_ID =
        "SEED_LIVENESS_PROBE_V1";

    enum class SeedLivenessDirection : uint8_t {
        NONE = 0,
        B2V = 1,
        V2B = 2,
    };

    static const char* SeedLivenessDirectionName(
        SeedLivenessDirection direction) {
        switch (direction) {
            case SeedLivenessDirection::B2V: return "B2V";
            case SeedLivenessDirection::V2B: return "V2B";
            case SeedLivenessDirection::NONE: return "NONE";
        }
        return "NONE";
    }

    struct SeedLivenessProbe {
        bool valid = false;
        SeedLivenessDirection direction = SeedLivenessDirection::NONE;
        int64_t amount_in = 0;
        SwapQuote quote{};
    };

private:
    // Evaluate the opening pool against resources that are provably retained
    // by the seeder after the seed transaction commits.  `continuation_units`
    // is the value of the seed transaction's canonical P2PKH change output;
    // `remaining_btcveld_sats` is the seeder's token balance after the seed
    // debit.  Keeping this helper resource-aware prevents global supply
    // headroom from being mistaken for a UTXO or token account the seeder can
    // actually spend in the witness transaction.
    static SeedLivenessProbe ProbeInitialSeedLivenessWithResources_(
        int64_t veld_units, int64_t btcveld_sats, uint64_t height,
        uint64_t continuation_units, int64_t remaining_btcveld_sats) {
        SeedLivenessProbe result;
        if (!QuoteInitialSeedPolicy_(
                veld_units, btcveld_sats,
                MarketSeedAnchorActive(height)).valid ||
            veld_units <= 0 ||
            (uint64_t)veld_units > MAX_SUPPLY_UNITS ||
            btcveld_sats <= 0 ||
            btcveld_sats > BTCVELD_AMM_MAX_POOL_BTCVELD_SATS ||
            !FourBandActive(height) || !ammgate::SwapAllowed(height))
            return result;

        AmmPool hypothetical;
        hypothetical.exists = true;
        hypothetical.reserve_veld = veld_units;
        hypothetical.reserve_btcveld = btcveld_sats;
        hypothetical.anchor_veld = veld_units;
        hypothetical.anchor_btcveld = btcveld_sats;

        const unsigned __int128 initial_k =
            (unsigned __int128)(uint64_t)veld_units *
            (uint64_t)btcveld_sats;
        auto potentially_executable = [&](const SwapQuote& quote,
                                          SeedLivenessDirection direction) {
            if (quote.reject || quote.amount_out <= 0 ||
                quote.post_reserve_veld <= 0 ||
                (uint64_t)quote.post_reserve_veld < DUST_THRESHOLD_UNITS ||
                (uint64_t)quote.post_reserve_veld > MAX_SUPPLY_UNITS ||
                quote.post_reserve_btcveld <
                    OnChainTokenLedger::MIN_ACCOUNT_SATS ||
                quote.post_reserve_btcveld >
                    BTCVELD_AMM_MAX_POOL_BTCVELD_SATS)
                return false;
            if ((unsigned __int128)(uint64_t)quote.post_reserve_veld *
                    (uint64_t)quote.post_reserve_btcveld < initial_k)
                return false;
            return direction != SeedLivenessDirection::B2V ||
                   (uint64_t)quote.amount_out >= DUST_THRESHOLD_UNITS;
        };

        // One token satoshi is a capability witness for B2V.  The seed must
        // retain both a distinct network-fee UTXO and an account with at least
        // 1,001 sats, so the one-sat debit ends at the 1,000-sat floor.
        if (btcveld_sats < BTCVELD_AMM_MAX_POOL_BTCVELD_SATS &&
            continuation_units >= AMM_SEED_LIVENESS_TX_FEE_UNITS &&
            remaining_btcveld_sats >=
                OnChainTokenLedger::MIN_ACCOUNT_SATS + 1) {
            const SwapQuote quote = QuoteSwapLocked(
                hypothetical, false, 1, height);
            if (potentially_executable(
                    quote, SeedLivenessDirection::B2V)) {
                result.valid = true;
                result.direction = SeedLivenessDirection::B2V;
                result.amount_in = 1;
                result.quote = quote;
                return result;
            }
        }

        // At a full btcVELD cap, locate the smallest native input with a
        // positive 30-bps net output.  This preliminary monotone search only
        // selects a candidate; the four-band quote below is authoritative.
        // V2B must retain an already-admissible token destination and a
        // continuation output large enough for both its input and its own
        // network fee.  The seed fee has already been paid by the parent
        // transaction and is deliberately not counted a second time here.
        if (remaining_btcveld_sats < OnChainTokenLedger::MIN_ACCOUNT_SATS ||
            continuation_units <= AMM_SEED_LIVENESS_TX_FEE_UNITS)
            return result;
        const uint64_t max_input =
            continuation_units - AMM_SEED_LIVENESS_TX_FEE_UNITS;
        if (SwapOut(veld_units, btcveld_sats, (int64_t)max_input,
                    BTCVELD_AMM_FEE_MIN_BPS) <= 0)
            return result;
        uint64_t lo = 1;
        uint64_t hi = max_input;
        while (lo < hi) {
            const uint64_t mid = lo + (hi - lo) / 2;
            if (SwapOut(veld_units, btcveld_sats, (int64_t)mid,
                        BTCVELD_AMM_FEE_MIN_BPS) > 0)
                hi = mid;
            else
                lo = mid + 1;
        }
        const SwapQuote quote = QuoteSwapLocked(
            hypothetical, true, (int64_t)lo, height);
        if (potentially_executable(quote, SeedLivenessDirection::V2B)) {
            result.valid = true;
            result.direction = SeedLivenessDirection::V2B;
            result.amount_in = (int64_t)lo;
            result.quote = quote;
        }
        return result;
    }

public:
    // Structural preflight used by independent arithmetic audits and clients.
    // It assumes every native unit outside the proposed pool can be retained
    // by the seed transaction, after paying that transaction's own fee.  Block
    // consensus does not rely on that assumption: ApplyAdd calls the bounded
    // form below with the actual change output and actual remaining account.
    static SeedLivenessProbe ProbeInitialSeedLiveness(
        int64_t veld_units, int64_t btcveld_sats, uint64_t height) {
        if (veld_units <= 0 || (uint64_t)veld_units > MAX_SUPPLY_UNITS)
            return SeedLivenessProbe{};
        const uint64_t total_headroom =
            MAX_SUPPLY_UNITS - (uint64_t)veld_units;
        if (total_headroom <= AMM_SEED_LIVENESS_TX_FEE_UNITS)
            return SeedLivenessProbe{};
        return ProbeInitialSeedLivenessWithResources_(
            veld_units, btcveld_sats, height,
            total_headroom - AMM_SEED_LIVENESS_TX_FEE_UNITS,
            OnChainTokenLedger::MIN_ACCOUNT_SATS + 1);
    }

    // Authoritative resource-bound form.  Consensus and the RPC preparer use
    // this exact helper, so the reported direction is backed by the seed's
    // real P2PKH continuation output and post-seed token balance.
    static SeedLivenessProbe ProbeInitialSeedLivenessWithResources(
        int64_t veld_units, int64_t btcveld_sats, uint64_t height,
        uint64_t continuation_units, int64_t remaining_btcveld_sats) {
        return ProbeInitialSeedLivenessWithResources_(
            veld_units, btcveld_sats, height, continuation_units,
            remaining_btcveld_sats);
    }

    static SeedQuote QuoteInitialSeedAtHeight(
        int64_t veld_units, int64_t btcveld_sats, uint64_t height,
        SeedLivenessProbe* probe_out = nullptr) {
        const SeedQuote quote = QuoteInitialSeedPolicy_(
            veld_units, btcveld_sats, MarketSeedAnchorActive(height));
        if (!quote.valid) {
            if (probe_out) *probe_out = SeedLivenessProbe{};
            return SeedQuote{};
        }
        const SeedLivenessProbe probe = ProbeInitialSeedLiveness(
            veld_units, btcveld_sats, height);
        if (probe_out) *probe_out = probe;
        return probe.valid ? quote : SeedQuote{};
    }

    // ---- pool arithmetic ----------------------------------------------------
    struct AddResult    { int64_t lp_minted;  int64_t btcveld_used; };
    struct RemoveResult { int64_t veld_out;   int64_t btcveld_out;  };

    AddResult AddLiquidity(const std::string& pool_id, const std::string& addr,
                           int64_t d_veld, int64_t d_btcveld_max) {
        std::lock_guard<std::mutex> lk(mu_);
        AmmPool* p = get(pool_id);
        if (!p || d_veld <= 0 || d_btcveld_max <= 0 ||
            p->reserve_veld < 0 || p->reserve_btcveld < 0 || p->lp_supply < 0)
            return {-1, 0};
        const bool seed = (p->lp_supply == 0);
        int64_t use_btc = 0, minted = 0;
        if (seed) {
            use_btc = d_btcveld_max;
            const uint64_t seed_height =
                BTCVELD_AMM_FOURBAND_ACTIVATION_HEIGHT;
            if (!InitialSeedAuthorized(addr, seed_height)) return {-1, 0};
            const SeedQuote quote = QuoteInitialSeedAtHeight(
                d_veld, use_btc, seed_height);
            if (!quote.valid) return {-1, 0};
            minted = quote.lp_minted;
            p->locked_lp = quote.locked_lp;
        } else {
            if (p->reserve_veld <= 0 || p->reserve_btcveld <= 0 || p->lp_supply <= 0)
                return {-1, 0};
            if (!CheckedMulDivPositiveI64(d_veld, p->reserve_btcveld,
                                          p->reserve_veld, &use_btc) ||
                use_btc > d_btcveld_max)
                return {-1, 0};
            // Mint against BOTH assets actually deposited.  `use_btc` is the
            // floored proportional token leg; minting only from d_veld lets a
            // thin btcVELD reserve turn the sub-satoshi rounding remainder into
            // materially excess LP ownership.  The limiting-leg minimum is the
            // integer constant-product LP rule and prevents that dilution.
            int64_t minted_from_veld = 0;
            int64_t minted_from_btc  = 0;
            if (!CheckedMulDivPositiveI64(p->lp_supply, d_veld,
                                          p->reserve_veld, &minted_from_veld) ||
                !CheckedMulDivPositiveI64(p->lp_supply, use_btc,
                                          p->reserve_btcveld, &minted_from_btc))
                return {-1, 0};
            minted = std::min(minted_from_veld, minted_from_btc);
        }
        // A4: total supply grows by minted + the permanent lock (== g for a
        // seed).  Was MIN_LIQUIDITY; the lock generalises that constant.
        const unsigned __int128 lp_delta_u =
            (unsigned __int128)(uint64_t)minted +
            (seed ? (uint64_t)p->locked_lp : 0u);
        if (lp_delta_u > (unsigned __int128)INT64_MAX) return {-1, 0};
        const int64_t lp_delta = (int64_t)lp_delta_u;
        const auto lp_key = pool_id + ":" + addr;
        const int64_t owner_lp = lp_.count(lp_key) ? lp_.at(lp_key) : 0;
        // Package-A D-STATE rule: a fresh identity must enter at the selected
        // minimum. Existing providers may add any positive amount because their
        // resulting position is already above the retained floor.
        if (owner_lp == 0 && minted > 0 && minted < LP_MIN_POSITION)
            return {-1, 0};
        // D-STATE-02: identity ceiling, fail-closed (see ApplyAdd).
        if (owner_lp == 0 && minted > 0 && lp_.size() >= AMM_MAX_LP_IDENTITIES)
            return {-1, 0};
        if (d_veld > INT64_MAX - p->reserve_veld ||
            use_btc > INT64_MAX - p->reserve_btcveld ||
            lp_delta > INT64_MAX - p->lp_supply ||
            owner_lp < 0 || minted > INT64_MAX - owner_lp)
            return {-1, 0};
        p->reserve_veld += d_veld; p->reserve_btcveld += use_btc; p->lp_supply += lp_delta;
        if (seed) {
            p->anchor_veld = p->reserve_veld;
            p->anchor_btcveld = p->reserve_btcveld;
        }
        // A4: a floor-leg seed mints ZERO withdrawable units.  Do not create a
        // zero-balance identity — the ledger's zero-erasure rule (D-STATE-02)
        // requires that only positive positions exist.
        if (minted > 0) lp_[lp_key] += minted;
        return {minted, use_btc};
    }
    RemoveResult RemoveLiquidity(const std::string& pool_id, const std::string& addr, int64_t d_lp) {
        std::lock_guard<std::mutex> lk(mu_);
        AmmPool* p = get(pool_id);
        if (!p || d_lp <= 0 || p->lp_supply <= 0 || d_lp > p->lp_supply ||
            p->reserve_veld <= 0 || p->reserve_btcveld <= 0) return {-1, 0};
        auto key = pool_id + ":" + addr; auto it = lp_.find(key);
        int64_t bal = (it != lp_.end()) ? it->second : 0;
        if (bal < d_lp) return {-1, 0};
        const int64_t residual = bal - d_lp;
        if (residual != 0 && residual < LP_MIN_POSITION) return {-1, 0};
        int64_t v = (int64_t)((unsigned __int128)(uint64_t)p->reserve_veld    * (uint64_t)d_lp / (uint64_t)p->lp_supply);
        int64_t b = (int64_t)((unsigned __int128)(uint64_t)p->reserve_btcveld * (uint64_t)d_lp / (uint64_t)p->lp_supply);
        p->reserve_veld -= v; p->reserve_btcveld -= b; p->lp_supply -= d_lp;
        lp_[key] -= d_lp;
        // A closed LP position has no future decision-bearing state.  Keeping
        // a permanent zero entry lets an attacker cycle tiny positions through
        // fresh addresses and grow every node's consensus map/digest forever.
        if (lp_[key] == 0) lp_.erase(key);
        return {v, b};
    }
    int64_t SwapAtHeight(const std::string& pool_id, bool veld_in, int64_t amt_in,
                         uint64_t height) {
        std::lock_guard<std::mutex> lk(mu_);
        AmmPool* p = get(pool_id);
        if (!p || amt_in <= 0 || p->lp_supply <= 0) return -1;
        int64_t rin = veld_in ? p->reserve_veld : p->reserve_btcveld;
        int64_t rout = veld_in ? p->reserve_btcveld : p->reserve_veld;
        if (rin <= 0 || rout <= 0 || amt_in > INT64_MAX - rin) return -1;
        unsigned __int128 kb = (unsigned __int128)(uint64_t)rin * (uint64_t)rout;
        SwapQuote quote = QuoteSwapLocked(*p, veld_in, amt_in, height);
        int64_t out = quote.amount_out;
        if (quote.reject || out < 0) return -1;   // FEE_SCHEDULE_NO_FIXED_POINT => refuse
        int64_t nrin = rin + amt_in, nrout = rout - out;
        if ((unsigned __int128)(uint64_t)nrin * (uint64_t)nrout < kb) return -1;
        if (veld_in) { p->reserve_veld = nrin; p->reserve_btcveld = nrout; }
        else         { p->reserve_btcveld = nrin; p->reserve_veld = nrout; }
        return out;
    }
    // Direct math helper used by tests and local tools. Consensus execution
    // always calls SwapAtHeight/QuoteSwapLocked with the candidate block height.
    int64_t Swap(const std::string& pool_id, bool veld_in, int64_t amt_in) {
        return SwapAtHeight(pool_id, veld_in, amt_in,
                            BTCVELD_AMM_FOURBAND_ACTIVATION_HEIGHT);
    }

    // ---- increment-2: seed the pool UTXO, then TX-DRIVEN swaps ---------------
    void SeedPool(const std::string& pool_id, uint32_t fee_bps, int64_t veld,
                  int64_t btcveld, int64_t lp_supply, int64_t locked_lp,
                  const Hash256& utxo_txid, uint32_t utxo_vout) {
        std::lock_guard<std::mutex> lk(mu_);
        if (veld <= 0 || btcveld <= 0 || lp_supply <= 0 ||
            locked_lp < MIN_LIQUIDITY ||
            locked_lp > lp_supply)
            throw std::invalid_argument("invalid reconstructed AMM seed state");
        unsigned __int128 attributed = (uint64_t)locked_lp;
        const std::string prefix = pool_id + ":";
        for (const auto& [key, balance] : lp_) {
            if (key.rfind(prefix, 0) != 0) continue;
            if (balance <= 0)
                throw std::invalid_argument(
                    "invalid reconstructed AMM LP position");
            attributed += (uint64_t)balance;
            if (attributed > (unsigned __int128)(uint64_t)lp_supply)
                throw std::invalid_argument(
                    "reconstructed AMM LP attribution exceeds supply");
        }
        if (attributed != (unsigned __int128)(uint64_t)lp_supply)
            throw std::invalid_argument(
                "reconstructed AMM LP attribution does not equal supply");
        AmmPool& p = pools_[pool_id];
        p = AmmPool{}; p.exists = true;
        p.fee_bps = fee_bps == 0 ? BTCVELD_AMM_FEE_BPS
            : std::clamp<uint32_t>(fee_bps, BTCVELD_AMM_FEE_MIN_BPS,
                                   BTCVELD_AMM_FEE_BPS);
        p.reserve_veld = veld; p.reserve_btcveld = btcveld;
        p.lp_supply = lp_supply; p.locked_lp = locked_lp;
        p.anchor_veld = veld; p.anchor_btcveld = btcveld;
        p.pool_txid = utxo_txid; p.pool_vout = utxo_vout; p.utxo_valid = true;
        p.veld_script = PoolVeldScript(pool_id); p.btcveld_addr = "AMM:" + pool_id;
    }

    // Validate + apply the block's AMM operations against `pool_id`, moving
    // btcVELD through `tokens`. A parsed AMM operation that cannot be applied is
    // a BLOCK failure, not a silently dropped no-op: ValidateBlock may have
    // succeeded against the parent token state while an earlier token operation
    // in this same block changed the balance needed by the live AMM apply.
    //
    // Keep this method atomic on its own as well as under the node-wide module
    // snapshot. That protects direct/replay callers if parsing, the explicit
    // one-operation policy, or the sole operation's apply fails: both ledgers
    // are restored to their exact entry snapshots before false escapes.
    bool ProcessBlock(const std::string& pool_id, const Block& block,
                      OnChainTokenLedger& tokens,
                      const BtcVeldPegGateState& peg_gate) {
        std::lock_guard<std::mutex> lk(mu_);
        // Parse and enforce the one-op policy before copying any lifetime
        // state. Ordinary blocks overwhelmingly contain no AMM marker; taking
        // pools_, the bounded-but-large LP map, and the token ledger/history
        // snapshot for every such block made IBD cost grow with accumulated
        // state even though this module had nothing to apply.
        size_t op_index = block.transactions.size();
        AmmOp sole_op;
        for (size_t i = 0; i < block.transactions.size(); ++i) {
            const AmmOpParseResult parsed =
                ParseAmmOpDetailed(block.transactions[i]);
            if (parsed.status == AmmOpParseStatus::INVALID) return false;
            if (parsed.status == AmmOpParseStatus::VALID) {
                if (op_index != block.transactions.size()) return false;
                op_index = i;
                sole_op = parsed.op;
            }
        }

        const bool has_op = op_index != block.transactions.size();
        if (has_op && !peg_gate.AmmAllowed()) return false;

        auto current = pools_.find(pool_id);
        const bool pool_exists =
            current != pools_.end() && current->second.exists;
        const bool creation_allowed =
            PoolCreationAllowed(block.height, peg_gate);

        if (!has_op) {
            // Activation-only blocks mutate at most the tiny pool registry and
            // never touch LP/token lifetime state. Preserve exception atomicity
            // for that one-time insertion without copying unrelated ledgers.
            if (pool_exists || !creation_allowed) return true;
            const auto pools_before = pools_;
            try {
                MaybeCreatePool(pool_id, block.height, peg_gate);
                return true;
            } catch (...) {
                pools_ = pools_before;
                throw;
            }
        }

        // A pre-activation parsed request retains the historical paid-no-op
        // behavior. It cannot mutate this module, so it needs no snapshot.
        if (!pool_exists && !creation_allowed) return true;

#ifdef VELD_TEST_HOOKS
        ++process_block_deep_snapshot_count_;
#endif
        const auto pools_before  = pools_;
        const auto lp_before     = lp_;
        const auto tokens_before = tokens.SnapshotState();
        auto rollback = [&]() {
            pools_ = pools_before;
            lp_    = lp_before;
            tokens.RestoreState(tokens_before);
        };

        try {
            MaybeCreatePool(pool_id, block.height, peg_gate);
            auto it = pools_.find(pool_id);
            if (it == pools_.end() || !it->second.exists) return true;
            if (!ApplyAmmOpLocked(pool_id, it->second, sole_op,
                                  block.transactions[op_index], tokens, false,
                                  block.height)) {
                rollback();
                return false;
            }
            return true;
        } catch (...) {
            rollback();
            throw;
        }
    }

    // Block-level covenant guard (pre-commit, PURE - no mutation). Returns false
    // => REJECT block. Any tx that spends the committed pool UTXO, or creates the
    // pool's covenant output (a seed), MUST be a valid AMM op; anything else that
    // touches the covenant is theft and fails the whole block. This is the SOLE
    // authority protecting the pool - ValidateTransaction sigless-exempts the pool
    // input, trusting this guard to reject a non-AMM spend. Mirrors the vault's
    // ValidateExpectedVaultDistribution. The real state change is ProcessBlock.
    enum class TokenValidationFrame : uint8_t {
        PARENT_STATE = 0,
        POST_BLOCK_STATE = 1,
    };

    bool ValidateBlock(const std::string& pool_id, const Block& block,
                       OnChainTokenLedger& tokens,
                       const BtcVeldPegGateState& peg_gate,
                       TokenValidationFrame token_frame =
                           TokenValidationFrame::PARENT_STATE) {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<AmmOpParseResult> parsed_ops;
        parsed_ops.reserve(block.transactions.size());
        size_t parsed_amm_ops = 0;
        for (const auto& tx : block.transactions) {
            AmmOpParseResult parsed = ParseAmmOpDetailed(tx);
            if (parsed.status == AmmOpParseStatus::INVALID) return false;
            if (parsed.status == AmmOpParseStatus::VALID && ++parsed_amm_ops != 1)
                return false;
            parsed_ops.push_back(std::move(parsed));
        }
        if (parsed_amm_ops != 0 && !peg_gate.AmmAllowed()) return false;

        // The canonical module order is token ledger first, AMM second.  Dry
        // validation must inspect the same post-token state or a block whose
        // issuer MINT funds its sole ADD seed would be rejected here even though
        // ProcessBlock can execute it.  Build an isolated token preview; the
        // live ledger and its BTC-header back-pointer are never mutated.
        OnChainTokenLedger token_preview;
        OnChainTokenLedger* validation_tokens = &tokens;
        if (parsed_amm_ops != 0 &&
            token_frame == TokenValidationFrame::PARENT_STATE) {
            if (!tokens.BuildPostBlockPreview(block, peg_gate, token_preview))
                return false;
            validation_tokens = &token_preview;
        }
        // Validation must not publish activation state.  This method runs while a
        // candidate can still fail unrelated consensus checks, and is called from
        // paths that do not wrap it in an AmmLedger snapshot.  Build the activation-
        // height pool locally; ProcessBlock is the only path allowed to insert it.
        auto it = pools_.find(pool_id);
        AmmPool prospective;
        if (it != pools_.end() && it->second.exists) {
            prospective = it->second;
        } else {
            if (!PoolCreationAllowed(block.height, peg_gate)) return true;
            prospective = NewPool(pool_id);
        }

        // Only the currently committed pool outpoint may be spent without a
        // signature.  Consequently same-block chaining is deliberately forbidden:
        // one block may carry at most one transaction that touches the AMM covenant
        // and at most one parsed AMM operation.  ProcessBlock applies that sole op
        // sequentially after the block has passed this pure guard.
        size_t covenant_touches = 0;
        for (size_t tx_index = 0; tx_index < block.transactions.size(); ++tx_index) {
            const auto& tx = block.transactions[tx_index];
            int pool_input_pos = -1;
            if (prospective.utxo_valid) {   // the committed pool UTXO may ONLY be spent at input[0]
                int pos = -1;
                for (size_t i = 0; i < tx.inputs.size(); ++i)
                    if (tx.inputs[i].prev_tx_hash == prospective.pool_txid &&
                        tx.inputs[i].prev_out_index == prospective.pool_vout) {
                        pos = (int)i;
                        break;
                    }
                if (pos > 0) return false;   // pool spent in a non-canonical position
                pool_input_pos = pos;
            }
            const bool spends_pool = pool_input_pos == 0;
            const bool creates_pool = !tx.outputs.empty() &&
                                      tx.outputs[0].script_pubkey == prospective.veld_script;
            const auto& parsed = parsed_ops[tx_index];
            const bool has_op = parsed.status == AmmOpParseStatus::VALID;
            if (!spends_pool && !creates_pool && !has_op) continue;
            if (spends_pool || creates_pool) {
                if (++covenant_touches != 1) return false;
            }
            if (!has_op) return false;                      // covenant touched w/o an AMM op
            if (!spends_pool && !creates_pool) return false; // an orphan AMM marker would fail apply
            AmmPool pcopy = prospective;
            if (!ApplyAmmOpLocked(pool_id, pcopy, parsed.op, tx,
                                  *validation_tokens,
                                  /*dry_run=*/true, block.height)) return false;
        }
        return true;
    }

    // For ValidateTransaction's sigless exemption: is (txid,vout) the CURRENT
    // committed pool UTXO? Only that exact outpoint may be spent siglessly - any
    // other pool-marker UTXO (attacker-created or same-block chained) is rejected.
    bool IsCommittedPoolOutpoint(const std::string& pool_id, const Hash256& txid, uint32_t vout) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = pools_.find(pool_id);
        if (it == pools_.end() || !it->second.exists || !it->second.utxo_valid) return false;
        return it->second.pool_txid == txid && it->second.pool_vout == vout;
    }

    AmmPool GetPool(const std::string& pool_id) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = pools_.find(pool_id); return it != pools_.end() ? it->second : AmmPool{};
    }
    uint32_t EffectiveFeeBps(const std::string& pool_id) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = pools_.find(pool_id);
        if (it == pools_.end() || !it->second.exists)
            return BTCVELD_AMM_FEE_MIN_BPS;
        return BTCVELD_AMM_FEE_MIN_BPS;
    }
    SwapQuote QuoteSwapAtHeight(const std::string& pool_id, bool veld_in,
                                int64_t amt_in, uint64_t height) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = pools_.find(pool_id);
        if (it == pools_.end() || !it->second.exists) {
            SwapQuote q;
            q.reject = true;
            q.reject_code = SwapRejectCode::INVALID_STATE;
            q.fee_bps = 0;
            q.fee_model_active = FourBandActive(height);
            return q;
        }
        return QuoteSwapLocked(it->second, veld_in, amt_in, height);
    }
    SwapQuote QuoteSwap(const std::string& pool_id, bool veld_in,
                        int64_t amt_in) const {
        return QuoteSwapAtHeight(pool_id, veld_in, amt_in,
                                 BTCVELD_AMM_FOURBAND_ACTIVATION_HEIGHT);
    }
    int64_t GetLp(const std::string& pool_id, const std::string& addr) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = lp_.find(pool_id + ":" + addr); return it != lp_.end() ? it->second : 0;
    }
#ifdef VELD_TEST_HOOKS
    uint64_t DebugProcessBlockDeepSnapshotCount() const {
        std::lock_guard<std::mutex> lk(mu_);
        return process_block_deep_snapshot_count_;
    }
#endif

    Hash256 Digest() const {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<uint8_t> body; namespace sd = ::veld::state_digest;
        // Encoding v3 commits the complete pool record.  `exists`, the
        // covenant script, and the token-ledger address all change subsequent
        // validation/execution behavior and therefore cannot be inferred or
        // omitted from a consensus-state measurement.
        //
        // v4 () adds A4's locked_lp. It is NOT derivable from
        // lp_supply and the lp_ map on a node that did not observe the seed,
        // and it bounds every future REMOVE, so omitting it would let two nodes
        // agree on a digest while disagreeing on withdrawable liquidity.
        // Fresh genesis makes the bump free; no dual-encoding window exists.
        sd::put_u32_le(body, 4);
        std::vector<std::string> pk; pk.reserve(pools_.size());
        for (auto& [k, _v] : pools_) pk.push_back(k);
        std::sort(pk.begin(), pk.end());
        sd::put_u32_le(body, (uint32_t)pk.size());
        for (auto& k : pk) {
            const AmmPool& p = pools_.at(k);
            sd::put_len_prefixed(body, k);
            sd::put_u8(body, p.exists ? 1 : 0);
            sd::put_u64_le(body, (uint64_t)p.reserve_veld);
            sd::put_u64_le(body, (uint64_t)p.reserve_btcveld);
            sd::put_u64_le(body, (uint64_t)p.lp_supply);
            sd::put_u64_le(body, (uint64_t)p.locked_lp);      // A4
            sd::put_u32_le(body, p.fee_bps);
            sd::put_u64_le(body, (uint64_t)p.anchor_veld);
            sd::put_u64_le(body, (uint64_t)p.anchor_btcveld);
            body.insert(body.end(), p.pool_txid.begin(), p.pool_txid.end());
            sd::put_u32_le(body, p.pool_vout);
            sd::put_u8(body, p.utxo_valid ? 1 : 0);
            sd::put_len_prefixed(body, p.veld_script);
            sd::put_len_prefixed(body, p.btcveld_addr);
        }
        std::vector<std::string> l2; l2.reserve(lp_.size());
        for (auto& [k, _v] : lp_) l2.push_back(k);
        std::sort(l2.begin(), l2.end());
        sd::put_u32_le(body, (uint32_t)l2.size());
        for (auto& k : l2) { sd::put_len_prefixed(body, k); sd::put_u64_le(body, (uint64_t)lp_.at(k)); }
        return sd::sha256_domain(sd::tags::AMM, body);
    }

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, AmmPool> pools_;
    std::unordered_map<std::string, int64_t> lp_;
#ifdef VELD_TEST_HOOKS
    uint64_t process_block_deep_snapshot_count_ = 0;
#endif
    AmmPool* get(const std::string& id) {
        auto it = pools_.find(id);
        return (it != pools_.end() && it->second.exists) ? &it->second : nullptr;
    }

    static bool PoolCreationAllowed(uint64_t height,
                                    const BtcVeldPegGateState& peg_gate) {
        if (!peg_gate.AmmAllowed()) return false;
        if (BTCVELD_ISSUER_ADDRESS[0] == '\0') return false;
        if (height < BTCVELD_ACTIVATION_HEIGHT) return false;
        if (BTCVELD_AMM_ACTIVATION_HEIGHT != 0 &&
            height < BTCVELD_AMM_ACTIVATION_HEIGHT) return false;
        return FourBandActive(height);
    }

    static AmmPool NewPool(const std::string& pool_id) {
        AmmPool p;
        p.fee_bps = BTCVELD_AMM_FEE_BPS;
        p.exists = true;
        p.veld_script = PoolVeldScript(pool_id);
        p.btcveld_addr = "AMM:" + pool_id;
        return p;
    }

    // Gated pool activation: create the btcVELD pool at BTCVELD_ACTIVATION_HEIGHT
    // IFF an issuer is configured. Empty issuer => launch profile inactive => no-op => amm_ stays
    // empty => zero effect on the node. Re-applied on reorg because Reset() clears.
    void MaybeCreatePool(const std::string& pool_id, uint64_t height,
                         const BtcVeldPegGateState& peg_gate) {
        // The AMM's sigless pool-spend is consensus-critical; hold pool creation
        // (and thus seeding + the sigless exemption) until its own activation and
        // the explicit four-band activation identity.
        if (!PoolCreationAllowed(height, peg_gate)) return;
        // A fresh chain must never create/seed a pool under an unimplemented
        // legacy fee rule and later re-price it.  The four-band activation is
        // therefore also a pool-creation floor.  Existing-chain deployments
        // must use an explicit migration rather than applying the genesis
        // profile.
        auto& p = pools_[pool_id];
        if (!p.exists) p = NewPool(pool_id);
    }

    static SwapQuote QuoteSwapLocked(const AmmPool& p, bool veld_in,
                                     int64_t amt_in, uint64_t height) {
        SwapQuote q;
        q.fee_model_active = FourBandActive(height);
        if (!q.fee_model_active) {
            q.reject = true;
            q.reject_code = SwapRejectCode::FEE_MODEL_NOT_ACTIVE;
            q.fee_bps = 0;
            return q;
        }
        if (!p.exists || p.reserve_veld <= 0 || p.reserve_btcveld <= 0 ||
            amt_in <= 0) {
            q.reject = true;
            q.reject_code = SwapRejectCode::INVALID_STATE;
            q.fee_bps = 0;
            return q;
        }

        // The opening ratio is consensus state, not an optional display hint.
        // At/after activation a missing or non-positive anchor has no safe
        // deterministic interpretation and MUST fail closed.  In particular,
        // never adopt the current reserve ratio: doing so would erase accrued
        // deviation and make replay depend on when the legacy state was read.
        if (p.anchor_veld <= 0 || p.anchor_btcveld <= 0) {
            q.reject = true;
            q.reject_code = SwapRejectCode::INVALID_ANCHOR;
            q.fee_bps = 0;
            return q;
        }

        const int64_t rin  = veld_in ? p.reserve_veld : p.reserve_btcveld;
        const int64_t rout = veld_in ? p.reserve_btcveld : p.reserve_veld;
        q.gross_out = GrossSwapOut(rin, rout, amt_in);
        if (q.gross_out < 0) {
            q.reject = true;
            q.reject_code = SwapRejectCode::INVALID_STATE;
            q.fee_bps = 0;
            return q;
        }

        if ((veld_in && amt_in > INT64_MAX - p.reserve_veld) ||
            (!veld_in && amt_in > INT64_MAX - p.reserve_btcveld)) {
            q.gross_out = -1;
            q.reject = true;
            q.reject_code = SwapRejectCode::INVALID_STATE;
            q.fee_bps = 0;
            return q;
        }
        const int64_t anchor_veld = p.anchor_veld;
        const int64_t anchor_btc = p.anchor_btcveld;
        const unsigned __int128 before = AnchorCrossDistance(
            p.reserve_veld, p.reserve_btcveld, anchor_veld, anchor_btc);
        const unsigned __int128 before_den =
            (unsigned __int128)(uint64_t)p.reserve_btcveld * (uint64_t)anchor_veld;
        q.pre_deviation_num = before;
        q.pre_deviation_den = before_den;
        q.pre_deviation_bps = RatioBpsCapped(before, before_den);

        // ---- Four-band deviation fee (spec seed-ratio-output-asset-4band-v1, §4.2) ----
        // The fee is retained in the OUTPUT reserve, so it shifts the post-trade deviation
        // that selects the band. The charged fee must therefore be a self-consistent fixed
        // point over the four permitted rates {30,50,75,100} bps: charging f must leave the
        // fee-retained post-state in a band whose rate is exactly f. Evaluate each candidate
        // against its OWN post-state; a candidate is valid iff
        //   - the trade HEALS at that fee (post-deviation <= pre-deviation)  -> only the 30-bps
        //     base rate is valid (spec §1.2 healing override); or
        //   - the trade WORSENS and its post-deviation lands in the band charging exactly f.
        // Exactly one feasible candidate must be valid. If every candidate's
        // net output rounds to zero the quote is INVALID_STATE; otherwise zero
        // or multiple valid candidates => FEE_SCHEDULE_NO_FIXED_POINT. Both
        // FAIL CLOSED (q.reject) — never a floor fallback, which could undercharge a worsening
        // trade. QuoteSwapLocked is height-gated above: activation 0 is dormant;
        // the fresh-genesis profile uses 1 so this model governs from block 1.
        struct FeeEval {
            int64_t out = -1;
            int64_t post_veld = 0;
            int64_t post_btc = 0;
            unsigned __int128 delta_after = 0;  // |R_v'*A_b - R_b'*A_v| of the fee-retained post-state
            unsigned __int128 den_after = 0;    // R_b'*A_v of the fee-retained post-state (band normalizer)
            bool rebalances = false;            // healing: post-deviation <= pre-deviation
        };
        auto evaluate = [&](uint32_t charged_bps) {
            FeeEval e;
            e.out = SwapOut(rin, rout, amt_in, charged_bps);
            if (e.out < 0) return e;
            e.post_veld = veld_in
                ? p.reserve_veld + amt_in
                : p.reserve_veld - e.out;
            e.post_btc = veld_in
                ? p.reserve_btcveld - e.out
                : p.reserve_btcveld + amt_in;
            if (e.post_veld <= 0 || e.post_btc <= 0) {
                e.out = -1;
                return e;
            }
            e.delta_after = AnchorCrossDistance(
                e.post_veld, e.post_btc, anchor_veld, anchor_btc);
            e.den_after = (unsigned __int128)(uint64_t)e.post_btc *
                          (uint64_t)anchor_veld;
            // Healing (spec §2.4): D_after <= D_before. Both deviations carry the same +A_v
            // factor in their denominators, so it cancels and the test reduces to
            // delta_after * R_b(before) <= delta_before * R_b(after). The 192-bit products use
            // the ACTUAL fee-retained reserves and avoid u128 overflow.
            e.rebalances = CompareU192(
                MulU128U64(e.delta_after, (uint64_t)p.reserve_btcveld),
                MulU128U64(before, (uint64_t)e.post_btc)) <= 0;
            return e;
        };

        int valid = 0;
        bool any_fee_output_feasible = false;
        FeeEval chosen;
        uint32_t chosen_fee = 0;
        uint8_t chosen_band = 0;
        for (uint32_t cand : BTCVELD_AMM_BAND_FEE_BPS) {
            const FeeEval e = evaluate(cand);
            if (e.out < 0) continue;                     // output infeasible at this fee
            any_fee_output_feasible = true;
            bool ok;
            uint8_t band_i;
            if (e.rebalances) {                          // healing / equal -> base rate only
                ok = (cand == BTCVELD_AMM_FEE_MIN_BPS);
                band_i = 1;
            } else {                                     // worsening -> exact band fixed point
                uint8_t b = 0;
                ok = (BandFeeBps(e.delta_after, e.den_after, &b) == cand);
                band_i = b;
            }
            if (ok) { ++valid; chosen = e; chosen_fee = cand; chosen_band = band_i; }
        }

        if (valid != 1) {
            q.reject = true;
            // Preserve the exact same fail-closed acceptance decision while
            // distinguishing output granularity from a real band-boundary
            // discontinuity.  With a one-satoshi gross output, every allowed
            // output fee rounds the net to zero: that is INVALID_STATE (and
            // changing the amount may need substantially more than a boundary
            // nudge), not a missing four-band fixed point.  RPC uses this code
            // only for an accurate user-facing diagnostic.
            q.reject_code = any_fee_output_feasible
                ? SwapRejectCode::FEE_SCHEDULE_NO_FIXED_POINT
                : SwapRejectCode::INVALID_STATE;
            q.fee_bps = 0;
            q.band = 0;
            q.rebalances_anchor = false;
            q.amount_out = -1;
            q.fee_out = 0;
            return q;
        }

        q.fee_bps           = chosen_fee;
        q.band              = chosen_band;
        q.rebalances_anchor = chosen.rebalances;
        q.amount_out        = chosen.out;
        q.fee_out           = q.gross_out - q.amount_out;
        q.post_reserve_veld = chosen.post_veld;
        q.post_reserve_btcveld = chosen.post_btc;
        q.post_deviation_num = chosen.delta_after;
        q.post_deviation_den = chosen.den_after;
        q.post_deviation_bps = RatioBpsCapped(chosen.delta_after,
                                               chosen.den_after);
        q.reject_code = SwapRejectCode::NONE;
        return q;
    }

    // dry_run=true validates every rule against current state WITHOUT mutating
    // (used by ValidateBlock); dry_run=false additionally commits the move + pool
    // update (used by ProcessBlock). Both return true iff the op is valid.
    // `height` = the block being validated/applied — the Layer-4 gate (swap lock +
    // pool btcVELD cap) keys on it; REMOVE never sees the gate (funds never trapped).
    bool ApplyAmmOpLocked(const std::string& pool_id, AmmPool& p, const AmmOp& op,
                          const Transaction& tx, OnChainTokenLedger& tokens, bool dry_run,
                          uint64_t height) {
        if (!ValidateAmmEnvelope(p, op, tx)) return false;
        // Every AMM operation names an external token account. B2V/ADD/REMOVE
        // already require that account's P2PKH signature, but V2B is a receive-
        // only leg and intentionally permits a distinct recipient. Apply the
        // token ledger's canonical credit-domain rule explicitly so a crafted
        // V2B cannot drain pool btcVELD into an unspendable P2SH/text balance.
        if (!IsCanonicalTokenCreditAddress(op.user)) return false;
        if (op.action == "SWAP_V2B" || op.action == "SWAP_B2V") return ApplySwap(pool_id, p, op, tx, tokens, dry_run, height);
        if (op.action == "ADD")    return ApplyAdd(pool_id, p, op, tx, tokens, dry_run, height);
        if (op.action == "REMOVE") return ApplyRemove(pool_id, p, op, tx, tokens, dry_run);
        return false;
    }

    // Exact transaction grammar emitted by the launch RPCs.  The final marker
    // is the sole OP_RETURN (ParseAmmOpDetailed enforces that), output[0] is the
    // sole pool covenant output, and at most one ordinary change output is
    // permitted.  B2V/REMOVE payout identity/value checks remain in their
    // operation handlers.  The optional change is deliberately not tied to
    // op.user so sponsored/multi-funder V2B remains possible.
    bool ValidateAmmEnvelope(const AmmPool& p, const AmmOp& op,
                             const Transaction& tx) const {
        if (!AmmTransactionEnvelopeWithinBounds(tx) || tx.outputs.empty())
            return false;

        const bool seed = op.action == "ADD" &&
                          (!p.utxo_valid || p.lp_supply == 0);
        const size_t pool_inputs = seed ? 0u : 1u;
        if (tx.inputs.size() <= pool_inputs ||
            tx.inputs.size() - pool_inputs > MAX_AMM_FUNDING_INPUTS)
            return false;

        const std::vector<uint8_t> expected_marker =
            BuildOpReturnScript(EncodeAmmOp(op));
        if (tx.outputs.back().value != 0 ||
            tx.outputs.back().script_pubkey != expected_marker)
            return false;
        if (tx.outputs[0].script_pubkey != p.veld_script) return false;
        for (size_t i = 1; i + 1 < tx.outputs.size(); ++i) {
            const auto& script = tx.outputs[i].script_pubkey;
            if (script.empty() || script[0] == 0x6a ||
                IsAmmPoolScript(script))
                return false;
        }

        if (op.action == "SWAP_V2B" || op.action == "ADD")
            return tx.outputs.size() == 2 || tx.outputs.size() == 3;
        if (op.action == "SWAP_B2V" || op.action == "REMOVE")
            return tx.outputs.size() == 3 || tx.outputs.size() == 4;
        return false;
    }

    // Common gate: spends the live pool UTXO as input[0] + recreates it as output[0].
    bool SpendsPool(const AmmPool& p, const Transaction& tx) {
        return !tx.inputs.empty() &&
               tx.inputs[0].prev_tx_hash == p.pool_txid && tx.inputs[0].prev_out_index == p.pool_vout &&
               tx.inputs[0].script_sig.empty() &&
               !tx.outputs.empty() && tx.outputs[0].script_pubkey == p.veld_script;
    }
    void ChainPool(AmmPool& p, const Transaction& tx) {
        p.pool_txid = tx.GetTxID(); p.pool_vout = 0; p.utxo_valid = true;
    }

    bool ApplySwap(const std::string& pool_id, AmmPool& p, const AmmOp& op,
                   const Transaction& tx, OnChainTokenLedger& tokens, bool dry_run, uint64_t height) {
        const bool v2b = (op.action == "SWAP_V2B");
        // Layer-4 swap gate: while armed, VELD<->btcVELD swaps (either direction)
        // are rejected until the swap-unlock height — the cheap-VELD drain needs
        // the swap leg, so this is the choke. Dormant => passes unconditionally.
        if (!ammgate::SwapAllowed(height)) return false;
        // `extra` is the V2B minimum-output field.  It has no meaning on the
        // opposite direction and therefore has one canonical value there.
        // Reject semantic aliases instead of leaving multiple signed wire
        // encodings for the same B2V state transition.
        if (!p.utxo_valid || op.amt <= 0 || op.extra < 0 ||
            (v2b ? op.extra <= 0 : op.extra != 0) ||
            !SpendsPool(p, tx)) return false;
        int64_t rin  = v2b ? p.reserve_veld    : p.reserve_btcveld;
        int64_t rout = v2b ? p.reserve_btcveld : p.reserve_veld;
        if (rin <= 0 || rout <= 0) return false;
        unsigned __int128 kb = (unsigned __int128)(uint64_t)rin * (uint64_t)rout;
        SwapQuote quote = QuoteSwapLocked(p, v2b, op.amt, height);
        int64_t out = quote.amount_out;
        if (quote.reject || out < 0) return false;   // FEE_SCHEDULE_NO_FIXED_POINT => block-invalid swap
        if (!AmmSwapMinimumOutputSatisfied(v2b, op.extra, out)) return false;
        int64_t new_rveld = quote.post_reserve_veld;
        int64_t new_rbtc  = quote.post_reserve_btcveld;
        if (new_rveld <= 0 || new_rbtc <= 0) return false;
        // The pool is recreated as a native VELD UTXO and B2V pays a native
        // output.  Both are subject to the launch-active consensus dust floor.
        // Mirror that rule inside the covenant guard so its pure verdict cannot
        // claim an operation is executable when base block validation rejects it.
        if ((uint64_t)new_rveld < DUST_THRESHOLD_UNITS ||
            (!v2b && (uint64_t)out < DUST_THRESHOLD_UNITS)) return false;
        // Layer-4 pool cap: the btcVELD reserve may never INCREASE past the cap
        // (only bites the B2V leg — V2B decreases the reserve and always passes).
        if (!ammgate::PoolReserveAllowed(height, p.reserve_btcveld, new_rbtc)) return false;
        if ((unsigned __int128)(uint64_t)new_rveld * (uint64_t)new_rbtc < kb) return false;    // k must not drop
        if (tx.outputs[0].value != (uint64_t)new_rveld) return false;
        if (v2b) {
            // Use the exact token-ledger transition predicate here, not just a
            // balance check.  The launch D-state floor also constrains the
            // source remainder and destination balance/overflow.  Keeping this
            // in the pure path makes ValidateBlock and ProcessBlock agree.
            if (!tokens.CanAmmMove("btcVELD", p.btcveld_addr, op.user, out))
                return false;
        } else {
            if (!AmmTxSignedBy(tx, op.user)) return false;                               // user authorizes btcVELD spend
            const auto user_script = AddressToScript(op.user);
            // The token debit, operation signer, and VELD recipient are one
            // protocol identity.  Amount-only validation lets a compromised
            // or non-conforming client obtain the user's valid SIGHASH_ALL
            // signature over a B2V transaction whose output[1] pays somebody
            // else.  Enforce the semantic destination in consensus, not just
            // in the bundled wallet.
            if (user_script.empty() || tx.outputs.size() < 2 ||
                tx.outputs[1].value != (uint64_t)out ||
                tx.outputs[1].script_pubkey != user_script) return false;
            if (!tokens.CanAmmMove("btcVELD", op.user, p.btcveld_addr, op.amt))
                return false;
        }
        if (dry_run) return true;
        if (v2b) { if (!tokens.AmmMove("btcVELD", p.btcveld_addr, op.user, out))   return false; }
        else     { if (!tokens.AmmMove("btcVELD", op.user, p.btcveld_addr, op.amt)) return false; }
        p.reserve_veld = new_rveld; p.reserve_btcveld = new_rbtc; ChainPool(p, tx);
        return true;
    }

    // ADD: op.amt=d_veld, op.extra=d_btcveld_max, op.user=LP recipient. First add
    // (empty pool) SEEDS - it mints the pool UTXO and sets the price by its ratio.
    bool ApplyAdd(const std::string& pool_id, AmmPool& p, const AmmOp& op,
                  const Transaction& tx, OnChainTokenLedger& tokens, bool dry_run,
                  uint64_t height) {
        if (op.amt <= 0 || op.extra <= 0) return false;
        if (!AmmTxSignedBy(tx, op.user)) return false;                                   // user authorizes btcVELD deposit
        if (tx.outputs.empty() || tx.outputs[0].script_pubkey != p.veld_script) return false;
        const bool seed = (!p.utxo_valid || p.lp_supply == 0);
        int64_t use_btc = 0, minted = 0;
        if (seed) {
            if ((uint64_t)op.amt < DUST_THRESHOLD_UNITS) return false;
            if (!InitialSeedAuthorized(op.user, height)) return false;
            use_btc = op.extra;
            const SeedQuote quote =
                QuoteInitialSeedAtHeight(op.amt, use_btc, height);
            if (!quote.valid) return false;
            const auto user_script = AddressToScript(op.user);
            if (user_script.empty() || tx.outputs.size() != 3 ||
                tx.outputs[1].script_pubkey != user_script)
                return false;
            const int64_t token_balance =
                tokens.GetBalance(BTCVELD_TOKEN_ID, op.user);
            if (token_balance < use_btc) return false;
            const SeedLivenessProbe seed_probe =
                ProbeInitialSeedLivenessWithResources(
                    op.amt, use_btc, height, tx.outputs[1].value,
                    token_balance - use_btc);
            if (!seed_probe.valid) return false;
            minted = quote.lp_minted;
            p.locked_lp = quote.locked_lp;
            if (tx.outputs[0].value != (uint64_t)op.amt) return false;                   // seed pool UTXO == d_veld
        } else {
            if (p.reserve_veld <= 0 || p.reserve_btcveld <= 0 || p.lp_supply <= 0)
                return false;
            if (!SpendsPool(p, tx)) return false;
            if (!CheckedMulDivPositiveI64(op.amt, p.reserve_btcveld,
                                          p.reserve_veld, &use_btc) ||
                use_btc > op.extra)
                return false;
            // LP ownership is bounded by the scarcer ACTUAL contribution.
            // Computing shares from the VELD leg alone over-mints whenever the
            // proportional btcVELD leg rounds down (most severely in a thin or
            // extreme-ratio pool), diluting every existing LP.
            int64_t minted_from_veld = 0;
            int64_t minted_from_btc  = 0;
            if (!CheckedMulDivPositiveI64(p.lp_supply, op.amt,
                                          p.reserve_veld, &minted_from_veld) ||
                !CheckedMulDivPositiveI64(p.lp_supply, use_btc,
                                          p.reserve_btcveld, &minted_from_btc))
                return false;
            minted = std::min(minted_from_veld, minted_from_btc);
            if (op.amt > INT64_MAX - p.reserve_veld) return false;
            if (tx.outputs[0].value != (uint64_t)(p.reserve_veld + op.amt)) return false;
        }
        // A4: total supply grows by minted + the permanent lock (== g for a
        // seed).  Was MIN_LIQUIDITY; the lock generalises that constant.
        const unsigned __int128 lp_delta_u =
            (unsigned __int128)(uint64_t)minted +
            (seed ? (uint64_t)p.locked_lp : 0u);
        if (lp_delta_u > (unsigned __int128)INT64_MAX) return false;
        const int64_t lp_delta = (int64_t)lp_delta_u;
        if (op.amt > INT64_MAX - (seed ? 0 : p.reserve_veld) ||
            use_btc > INT64_MAX - (seed ? 0 : p.reserve_btcveld) ||
            lp_delta > INT64_MAX - (seed ? 0 : p.lp_supply))
            return false;
        const auto lp_key = pool_id + ":" + op.user;
        const int64_t owner_lp = lp_.count(lp_key) ? lp_.at(lp_key) : 0;
        if (owner_lp < 0 || minted > INT64_MAX - owner_lp) return false;
        if (owner_lp == 0 && minted > 0 && minted < LP_MIN_POSITION)
            return false;
        // D-STATE-02: fail-closed admission at the identity ceiling. Existing
        // providers are unaffected; only a NEW identity is refused, and it is
        // refused before any state mutation.
        if (owner_lp == 0 && minted > 0 && lp_.size() >= AMM_MAX_LP_IDENTITIES)
            return false;
        // Layer-4 pool cap: seeds/adds may never push the pool's btcVELD reserve
        // past the cap while armed — bounds the LP btcVELD ever at risk from the
        // cheap-VELD drain. Rejecting an add traps nothing (funds stay with the LP).
        if (!ammgate::PoolReserveAllowed(height, seed ? 0 : p.reserve_btcveld,
                                         (seed ? 0 : p.reserve_btcveld) + use_btc)) return false;
        if (!tokens.CanAmmMove("btcVELD", op.user, p.btcveld_addr, use_btc))
            return false;
        if (dry_run) return true;
        if (!tokens.AmmMove("btcVELD", op.user, p.btcveld_addr, use_btc)) return false;
        if (seed) {
            p.reserve_veld = op.amt;
            p.reserve_btcveld = use_btc;
            p.anchor_veld = op.amt;
            p.anchor_btcveld = use_btc;
            p.lp_supply = lp_delta;
        }
        else      { p.reserve_veld += op.amt; p.reserve_btcveld += use_btc; p.lp_supply += lp_delta; }
        // A4: a floor-leg seed mints ZERO withdrawable units — never create a
        // zero-balance identity (D-STATE-02 zero-erasure rule).
        if (minted > 0) lp_[lp_key] += minted;
        ChainPool(p, tx);
        return true;
    }

    // REMOVE: op.amt=d_lp, op.user=LP holder. Pays pro-rata VELD (output[1]) + btcVELD.
    bool ApplyRemove(const std::string& pool_id, AmmPool& p, const AmmOp& op,
                     const Transaction& tx, OnChainTokenLedger& tokens, bool dry_run) {
        // REMOVE has no secondary amount.  Keep the unused field canonical so
        // one LP burn has exactly one protocol encoding.
        if (op.amt <= 0 || op.extra != 0 ||
            p.lp_supply <= 0 || op.amt > p.lp_supply ||
            p.reserve_veld <= 0 || p.reserve_btcveld <= 0 ||
            !p.utxo_valid || !SpendsPool(p, tx)) return false;
        if (!AmmTxSignedBy(tx, op.user)) return false;
        auto key = pool_id + ":" + op.user;
        auto it = lp_.find(key); int64_t bal = (it != lp_.end()) ? it->second : 0;
        if (bal < op.amt) return false;
        const int64_t residual = bal - op.amt;
        if (residual != 0 && residual < LP_MIN_POSITION) return false;
        int64_t v = (int64_t)((unsigned __int128)(uint64_t)p.reserve_veld    * (uint64_t)op.amt / (uint64_t)p.lp_supply);
        int64_t b = (int64_t)((unsigned __int128)(uint64_t)p.reserve_btcveld * (uint64_t)op.amt / (uint64_t)p.lp_supply);
        if (v <= 0 || (uint64_t)v < DUST_THRESHOLD_UNITS ||
            (uint64_t)(p.reserve_veld - v) < DUST_THRESHOLD_UNITS)
            return false;
        if (tx.outputs[0].value != (uint64_t)(p.reserve_veld - v)) return false;
        const auto user_script = AddressToScript(op.user);
        // REMOVE burns this user's LP balance and credits their btcVELD
        // account; the corresponding VELD output must pay that same canonical
        // account.  A signature alone is authorization for the exact tx, not a
        // substitute for this protocol-level destination invariant.
        if (user_script.empty() || tx.outputs.size() < 2 ||
            tx.outputs[1].value != (uint64_t)v ||
            tx.outputs[1].script_pubkey != user_script) return false;
        if (b > 0 &&
            !tokens.CanAmmMove("btcVELD", p.btcveld_addr, op.user, b))
            return false;
        if (dry_run) return true;
        if (b > 0 && !tokens.AmmMove("btcVELD", p.btcveld_addr, op.user, b)) return false;
        p.reserve_veld -= v; p.reserve_btcveld -= b; p.lp_supply -= op.amt;
        lp_[key] -= op.amt;
        // Prune completed positions.  GetLp already defines absence as zero,
        // so this preserves all semantics while bounding state by live LPs
        // instead of lifetime addresses that ever touched the pool.
        if (lp_[key] == 0) lp_.erase(key);
        ChainPool(p, tx);
        return true;
    }
};

}
