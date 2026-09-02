#pragma once

// Shared, dependency-light finality wire profile.  Both the P2P structural
// envelope and the consensus codec derive their exact FINVOTE size here so a
// future ML-DSA profile/layout change cannot leave transport accepting a
// different byte range from the decoder.

#include "crypto/dilithium.h"

#include <cstddef>

namespace veld {
namespace finality {
namespace wire {

constexpr size_t SIGNED_VOTE_BYTES =
    4 + 8 + 32 + 1 + 4 + 8 + 32 + 8 + 32 +
    ::veld::dilithium::PUBKEY_BYTES + ::veld::dilithium::SIG_MAX_BYTES;

}  // namespace wire
}  // namespace finality
}  // namespace veld

