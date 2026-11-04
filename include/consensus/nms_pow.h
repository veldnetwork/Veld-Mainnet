#pragma once

#include "../core/pow_target.h"

namespace veld {

// Shared by consensus validation and mining proof routing. This is the
// existing NMS interval: target < proof <= 4*target, refusing overflow.
// Finding a proof in this interval alone does not establish chain eligibility.
inline bool IsNmsProofInRange(const Hash256& proof, const CanonicalPowTarget& target) {
    Hash256 upper{};
    uint32_t carry = 0;
    for (int i = 31; i >= 0; --i) {
        const uint32_t value = uint32_t(target.bytes[i]) * 4u + carry;
        upper[i] = static_cast<uint8_t>(value & 0xffu);
        carry = value >> 8;
    }
    return carry == 0 && proof > target.bytes && proof <= upper;
}

} // namespace veld
