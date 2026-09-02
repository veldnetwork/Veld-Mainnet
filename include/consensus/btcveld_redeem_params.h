#pragma once
// btcVELD redemption activation parameters.
//
// The bond/slash covenant (btcveld_signer_bond.h) is wired into the node behind
// BTCVELD_REDEEM_ACTIVATION_HEIGHT. 0 == permanently OFF (production default),
// reserved for coordinated activation. While off, the covenant is never fed and its v7 subdigest remains
// the deterministic empty-state commitment. The covenant depends on the SPV relay (its
// slash triggers verify BTC facts via btc_header_chain), so redeem activation
// MUST be >= the SPV activation height.
//
// All values are compile-time constants; a gate is a pure function of state and
// constants, never a per-node flag.

#include "consensus/btcveld_signer_bond.h"
#include "consensus/btcveld_redeem_spv.h"   // SPV-proven payout resolution (fulfill / wrong-payout)
#include "consensus/btcveld_spv_params.h"   // BTCVELD_SPV_ACTIVATION_HEIGHT (redeem >= spv)
#include <cstdint>

namespace veld {

#if defined(VELD_BTCVELD_REGTEST)
constexpr uint64_t BTCVELD_REDEEM_ACTIVATION_HEIGHT = 1;       // regtest: redeem covenant live from h1
constexpr uint64_t BTCVELD_REDEEM_SLA               = 200;     // signer honor window (Veld blocks)
constexpr uint64_t BTCVELD_SIGNER_MIN_BOND_SATS     = 1;       // low bar for the regtest fixture
#else
constexpr uint64_t BTCVELD_REDEEM_ACTIVATION_HEIGHT = 0;       // dormant; coordinated activation must follow SPV activation
constexpr uint64_t BTCVELD_REDEEM_SLA               = 1000;    // ~honor window before default
constexpr uint64_t BTCVELD_SIGNER_MIN_BOND_SATS     = 100000000ULL;  // 1 VELD-unit floor (placeholder)
static_assert(BTCVELD_REDEEM_ACTIVATION_HEIGHT == 0,
              "production signer-bond covenant must remain OFF until registration "
              "is authenticated, collateral is UTXO-locked, and complete state is "
              "included in the consensus digest and independently audited");
#endif

// non-payment penalty on the group, in basis points of the owed amount
constexpr uint64_t BTCVELD_NONPAY_PENALTY_BPS = 2000;   // 20%

// Is the redeem-leg bond/slash covenant active at this Veld height?
inline bool BtcVeldRedeemActive(uint64_t height) {
    return BTCVELD_REDEEM_ACTIVATION_HEIGHT != 0 && height >= BTCVELD_REDEEM_ACTIVATION_HEIGHT;
}

}  // namespace veld
