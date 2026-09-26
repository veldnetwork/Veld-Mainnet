#pragma once
// btcveld_peg_gate.h -- explicit state-derived peg access passed to every
// consensus transition that can create/destroy btcVELD or move AMM reserves.
//
// The compiled launch profile, validator activation, and later liveness gate
// are deliberately separate:
//
//   * unlocked means the compiled btcVELD launch profile is active at the
//     candidate height AND the chain has completed its existing seven-validator
//     finality activation. Bitcoin anchoring is not an additional prerequisite;
//   * before validator finality has ever activated, every peg transition is
//     closed;
//   * activation is a one-way chain-state latch. A later validator-count drop
//     alone does not close the peg;
//   * after activation, a sustained finality-liveness failure pauses only new
//     mint exposure. Completion, redeem, and the configured AMM path remain
//     available.
//
// After validator activation, redeem and safe completion remain available even
// if finality later stalls. CompletionAllowed remains deliberately
// narrow: callers may use it only for C1C1 gap closure, exact C1F1 funding of an
// already-exposed allocation, and exact MNP2 credit of an already-funded
// allocation. It does not authorize C1R1, C1E1, MNP1, or MSPV. Bitcoin anchors
// validator finality provides the initial activation; Bitcoin anchors remain an
// additive security layer.
//
// No field has a permissive default and no "fully open" helper exists.  A
// consensus caller must spell out all three facts at the candidate block.

namespace veld {

struct BtcVeldPegGateState {
    bool unlocked;
    bool mint_live;
    bool amm_live;

    constexpr bool MintAllowed() const noexcept {
        return unlocked && mint_live;
    }
    constexpr bool CompletionAllowed() const noexcept {
        return unlocked;
    }
    constexpr bool FundingAllowed() const noexcept {
        return unlocked && mint_live;
    }
    constexpr bool RedeemAllowed() const noexcept {
        return unlocked;
    }
    constexpr bool AmmAllowed() const noexcept {
        return unlocked && amm_live;
    }
};

// One pure derivation is shared by candidate-block validation and asynchronous
// mempool/RPC readers. Keeping the validator activation rule here prevents a
// service-only flag from drifting away from the actual permission bits consumed
// by token and AMM consensus.
//
// `launch_active` is derived from the compiled issuer/token activation at the
// exact candidate height. `finality_ever_active` is the chain-derived latch
// reached only after the existing finality profile has observed its qualified
// validator set (minimum seven) for the required warm-up. `finality_live` then
// controls only new mint exposure; it does not undo the activation latch.
constexpr BtcVeldPegGateState DeriveBtcVeldPegGate(bool launch_active, bool finality_ever_active,
                                                   bool finality_live,
                                                   bool amm_continues_during_later_stall) noexcept {
    if (!launch_active || !finality_ever_active)
        return BtcVeldPegGateState{false, false, false};

    const bool later_stall = !finality_live;
    return BtcVeldPegGateState{
        /*unlocked=*/true,
        /*mint_live=*/!later_stall,
        /*amm_live=*/!later_stall || amm_continues_during_later_stall,
    };
}

} // namespace veld
