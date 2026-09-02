#pragma once
// btcveld_redeem_guard.h — btcVELD §5b redeem drain guard (51%-defense design §5b).
//
// Consensus outflow rate-limit on REDEEM burns, modeled on the proven
// VAULT-NEVER-DRAINS rule (VAULT_INFLOW_PAYOUT_PPM / VAULT_DISTRIBUTION_PPM):
// per window of BTCVELD_REDEEM_WINDOW_BLOCKS, at most
// BTCVELD_REDEEM_WINDOW_PPM_OF_CAP of the custody cap may leave via REDEEM.
// One deliberate difference from the vault: btcVELD must stay FULLY redeemable,
// so an over-budget redeem is REJECTED WHOLE — the burn never happens, the
// funds stay with the redeemer (resubmit next window). Nothing is ever trapped
// or partially applied. The guard caps what a successful reorg-double-spend can
// extract to ONE window's ceiling, composing with the custody cap (bounds the
// total prize) and Bitcoin anchoring (bounds reorg depth): worst-case
// single-attack extraction <= one window's redeem ceiling.
//
// This header is the PURE, deterministic core (no I/O, no class state) so it is
// unit-testable in isolation; onchain_tokens.h enforces it in the REDEEM branch
// with a per-window accumulator. Windows are pure functions of height and the
// accumulator advances only on accepted chain ops, so replay is exact and the
// alt-chain shadow ledgers inherit the behaviour for free. DORMANT until
// BTCVELD_REDEEM_GUARD_ACTIVATION_HEIGHT is armed (0 == off).
//
// a consensus rule is a pure function of chain state + constants.

#include "core/constants.h"
#include "consensus/btcveld_spv_params.h" // launch-wide 10 BTC custody ceiling
#include <cstdint>
#include <limits>

namespace veld {

// Is the §5b redeem drain guard active at this Veld height? 0 == dormant/off.
inline bool BtcVeldRedeemGuardActive(uint64_t height) {
    return BTCVELD_REDEEM_GUARD_ACTIVATION_HEIGHT != 0 &&
           height >= BTCVELD_REDEEM_GUARD_ACTIVATION_HEIGHT;
}

namespace redeemguard {

// The window a height falls in. Pure function of height — no persisted
// schedule, so a replaying node computes the identical window for every op.
inline uint64_t WindowId(uint64_t height) {
    return height / BTCVELD_REDEEM_WINDOW_BLOCKS;
}

// Per-window redeem ceiling in sats = custody_cap × ppm / 1e6. 128-bit
// intermediate: cap(int64) × ppm(<=1e6) overflows int64 for caps above
// ~9.2e12 sats (~92,000 BTC), and the cap constant may grow with the
// difficulty-tier ladder — never trust the product to fit 64 bits.
inline int64_t WindowCeilingSats(int64_t custody_cap_sats) {
    if (custody_cap_sats <= 0) return 0;
    return (int64_t)(((unsigned __int128)(uint64_t)custody_cap_sats
                      * BTCVELD_REDEEM_WINDOW_PPM_OF_CAP) / 1'000'000u);
}

// Launch-live issuer and SPV mints share one redemption/custody domain. The
// issuer path's smaller safety cap limits only issuer-authorized inflow; it must
// not strand SPV-backed supply by shrinking redemption throughput. Both the
// consensus ledger and RPC preflight call this helper so the guard is always
// 20% of the shared/SPV custody ceiling (1 BTC at launch).
inline int64_t LaunchWindowCeilingSats() {
    static_assert(BTCVELD_SPV_MAX_CUSTODY_SATS <=
                      static_cast<uint64_t>(std::numeric_limits<int64_t>::max()),
                  "btcVELD shared custody ceiling must fit consensus int64 amounts");
    return WindowCeilingSats(
        static_cast<int64_t>(BTCVELD_SPV_MAX_CUSTODY_SATS));
}

// Does `amount` fit the window's remaining budget? Overflow-safe (mirrors the
// issuer mint-cap form: never computes redeemed + amount). Fail-closed on any
// nonsense input.
inline bool FitsWindow(int64_t redeemed_in_window, int64_t amount, int64_t ceiling) {
    if (amount <= 0 || redeemed_in_window < 0 || ceiling <= 0) return false;
    if (redeemed_in_window > ceiling) return false;
    return amount <= ceiling - redeemed_in_window;
}

}  // namespace redeemguard
}  // namespace veld
