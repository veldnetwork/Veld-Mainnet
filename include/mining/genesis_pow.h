#pragma once

// One canonical verifier for the mined genesis proof of work.  The genesis
// block is inserted through trusted replay because it has no parent/UTXO
// frame, but that must never mean its memory-hard PoW is trusted blindly.

#include "../core/block.h"
#include "veldhash.h"

namespace veld::mining {

struct GenesisPowVerification {
    bool target_valid{false};
    bool dataset_ok{false};
    bool passed{false};
    Hash256 target{};
    Hash256 pow_hash{};
};

inline GenesisPowVerification VerifyGenesisPoW(const Block& genesis) {
    GenesisPowVerification result;
    if (genesis.height != 0 || genesis.header.version != 1 ||
        !HashIsZero(genesis.header.prev_block_hash)) {
        return result;
    }
    CanonicalPowTarget target;
    result.target_valid = DecodeCanonicalVeldTarget(genesis.header.bits, target);
    if (!result.target_valid)
        return result;
    result.target = target.bytes;
    result.pow_hash = VeldHashForVerification(genesis.header.Serialize(), 0, target);
    result.dataset_ok = g_veldhash_last_dataset_ok();
    result.passed = result.dataset_ok && result.pow_hash < result.target;
    return result;
}

} // namespace veld::mining
