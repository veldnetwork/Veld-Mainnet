#pragma once
// btcveld_tier_ladder.h — btcVELD Layer-1 difficulty-tier cap ladder (51%-defense §3.2).
//
// The custody cap bounds the maximum BTC the peg can hold = the maximum prize a 51%
// attacker can win. A human-declared cap can be mis-set or raised too aggressively in a
// release; the tier ladder makes the EFFECTIVE cap the smaller of that declared cap and
// what MEASURED on-chain hashrate justifies:
//
//   effective_mint_ceiling = max( live_supply , min( DECLARED_CAP , TierCap(sustained) ) )
//
// - `min(DECLARED_CAP, TierCap)` — the ladder is a SAFETY CLAMP, never an amplifier: it can
//   only pull the ceiling DOWN toward what hashrate supports, never above the human cap. So
//   even a runaway hashrate explosion cannot push the peg past the declared cap, and a buggy
//   or over-eager DECLARED_CAP is clamped by real security.
// - `max(live_supply, ...)` — STICKY-UP for supply: a difficulty DROP never forces burns
//   (you cannot un-mint). It only blocks NEW mints above the now-lower tier; existing supply
//   is grandfathered (the same "never lower the cap below live supply" rule the static cap
//   already honors).
//
// `sustained` is the TRAILING-MINIMUM per-block work over BTCVELD_TIER_WINDOW_BLOCKS — the
// minimum, not the average or sum, so a brief hashrate SPIKE unlocks nothing: to clear a
// tier, EVERY block in the window must carry >= that work, i.e. the hashrate was committed
// for the whole window (longer than any plausible rent-and-attack). A partial window (young
// chain) yields 0 => the pilot floor only. Work saturates safely at UINT64_MAX; under the
// min(DECLARED_CAP, ...) clamp even a saturated metric cannot over-unlock.
//
// PURE, deterministic core (no I/O, no class state) so it is unit-testable in isolation;
// the token ledger tracks the trailing window in-instance (replay-exact, main/alt-correct)
// and feeds `sustained` in. DORMANT until BTCVELD_TIER_LADDER_ACTIVATION_HEIGHT is armed.
//
// a consensus rule is a pure function of chain state + constants.

#include "core/constants.h"
#include <cstdint>

namespace veld {

// Is the Layer-1 tier ladder active at this Veld height? 0 == dormant/off — while dormant
// the mint gate uses DECLARED_CAP unchanged (behaviour byte-identical to no ladder).
inline bool BtcVeldTierLadderActive(uint64_t height) {
    return BTCVELD_TIER_LADDER_ACTIVATION_HEIGHT != 0 &&
           height >= BTCVELD_TIER_LADDER_ACTIVATION_HEIGHT;
}

namespace tierladder {

// One rung: sustained per-block work at or above `min_sustained_work` unlocks `cap_sats`.
// Ordered ascending by threshold; rung 0 is the pilot floor (threshold 0 => always met).
struct Tier { uint64_t min_sustained_work; int64_t cap_sats; };

// The ladder. CALIBRATED against a real VeldHash bench (§3.4b): the home-miner
// PC (i9-11900K) does 1047 H/s tuned / ~1197 H/s peak, at a $540 CPU MSRP ⇒ $0.52/(H/s) —
// which validates the $0.50/(H/s) hardware-acquisition basis the ladder rests on.
// work ≈ network_hashrate × block_time, so at 3-min blocks a threshold of N work ≈ N/180
// H/s sustained. The per-tier hashrate embeds a 10× conservatism factor over the raw
// hardware model (design §3.4b caveat 1): raw safe-cap needs 2.5k/25k/250k H/s, ×10 ⇒ the
// 25k/250k/2.5M/25M H/s gates below. The final rung reaches the configured
// 10 BTC absolute custody ceiling without leaving a hidden 1 BTC maximum.
// At the current 180-second target, tier 1 represents roughly 24 of the benchmarked
// rigs sustained for the complete 14-day window; tier 3 is roughly 2,400. No live
// fleet-hashrate estimate is embedded here because that operational value changes.
constexpr Tier TIERS[] = {
    {          0,     100'000 },   // pilot   — 0.001 BTC — any hashrate (floor)
    {  4'500'000,   1'000'000 },   // tier 1  — 0.01  BTC — ~25 kH/s @3min sustained (10×-conservative)
    { 45'000'000,  10'000'000 },   // tier 2  — 0.1   BTC — ~250 kH/s
    {450'000'000, 100'000'000 },   // tier 3  — 1     BTC — ~2.5 MH/s
    {4'500'000'000ULL, 1'000'000'000 }, // tier 4 — 10 BTC — ~25 MH/s
};
constexpr int TIER_COUNT = (int)(sizeof(TIERS) / sizeof(TIERS[0]));

// The cap unlocked by `sustained` work — the highest rung whose threshold it clears.
// Monotonic non-decreasing in `sustained`. Saturation-safe (a UINT64_MAX metric simply
// selects the top rung; the caller's min(DECLARED_CAP, ...) still bounds it).
inline int64_t TierCap(uint64_t sustained_work) {
    int64_t cap = TIERS[0].cap_sats;
    for (int i = 1; i < TIER_COUNT; ++i)
        if (sustained_work >= TIERS[i].min_sustained_work) cap = TIERS[i].cap_sats;
        else break;   // ascending thresholds: first miss ends the climb
    return cap;
}

// The effective aggregate mint ceiling. `declared_cap` = the static/human cap
// (BTCVELD_ISSUER_MAX_CUSTODY_SATS); `live_supply` = current outstanding btcVELD;
// `sustained_work` = trailing-minimum per-block work. Never above the declared cap,
// never below live supply (no forced burns). Fail-closed on nonsense (negative) inputs.
inline int64_t EffectiveMintCeiling(int64_t declared_cap, int64_t live_supply,
                                    uint64_t sustained_work) {
    if (declared_cap < 0)  declared_cap = 0;
    if (live_supply < 0)   live_supply  = 0;
    int64_t tier = TierCap(sustained_work);
    int64_t clamped = tier < declared_cap ? tier : declared_cap;   // min(declared, tier)
    return clamped > live_supply ? clamped : live_supply;          // max(live_supply, clamped)
}

}  // namespace tierladder
}  // namespace veld
