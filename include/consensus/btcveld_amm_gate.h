#pragma once
// btcveld_amm_gate.h — Layer-4 AMM swap gate (51%-defense design §6).
//
// The cheap-VELD drain: mine near-free VELD on a young network → swap it for the
// pool's btcVELD → redeem for real BTC. The victim is the LP (the peg itself stays
// 1:1). Liquidity DEPTH cannot fix this — a deeper pool is just a bigger prize;
// the attack profits whenever cost-to-mine-VELD < value-of-btcVELD-drained. So the
// defense gates the one surface where cheap VELD can pull hard assets:
//
//   1. SWAP gate  — while the gate regime is armed, VELD<->btcVELD AMM swaps are
//      rejected until BTCVELD_AMM_SWAP_UNLOCK_HEIGHT (UINT64_MAX = explicitly
//      locked/fail-closed; zero = enabled from gate activation).
//   2. POOL CAP   — the pool's btcVELD reserve may never INCREASE past
//      BTCVELD_AMM_MAX_POOL_BTCVELD_SATS, bounding the btcVELD ever at risk.
//      Decreases are ALWAYS allowed (a grandfathered over-cap pool can only
//      shrink; removes and btcVELD-out swaps are never blocked by the cap).
//
// NEVER gated: wrap (mint), redeem (burn), transfers, and liquidity-REMOVE —
// funds are never trapped, and every ungated op only lowers or preserves the
// btcVELD at risk. This is a pure consensus rule: no operator, no oracle — a
// function of (height, state,
// constants) only. DORMANT until BTCVELD_AMM_SWAP_GATE_ACTIVATION_HEIGHT is
// armed (0 == off: the AMM validates exactly as it does today).
//
// a consensus rule is a pure function of chain state + constants.

#include "core/constants.h"
#include <cstdint>

namespace veld {

// Is the Layer-4 AMM gate regime active at this Veld height? 0 == dormant/off.
inline bool BtcVeldAmmGateActive(uint64_t height) {
    return BTCVELD_AMM_SWAP_GATE_ACTIVATION_HEIGHT != 0 &&
           height >= BTCVELD_AMM_SWAP_GATE_ACTIVATION_HEIGHT;
}

namespace ammgate {

// May a VELD<->btcVELD AMM swap (either direction) execute at `height`?
// Dormant => always. Armed => only at/after the swap-unlock height.
inline bool SwapAllowed(uint64_t height) {
    if (!BtcVeldAmmGateActive(height))
        return true;
    return height >= BTCVELD_AMM_SWAP_UNLOCK_HEIGHT;
}

// May the pool's btcVELD reserve move old_reserve -> new_reserve at `height`?
// Dormant => always. Armed => decreases always allowed (never trap; a
// grandfathered over-cap reserve can only shrink), increases only up to the
// pool cap. Fail-closed on a negative (wrapped/corrupt) new_reserve.
inline bool PoolReserveAllowed(uint64_t height, int64_t old_reserve, int64_t new_reserve) {
    if (new_reserve < 0)
        return false;
    if (!BtcVeldAmmGateActive(height))
        return true;
    if (new_reserve <= old_reserve)
        return true;
    return new_reserve <= BTCVELD_AMM_MAX_POOL_BTCVELD_SATS;
}

} // namespace ammgate
} // namespace veld
