#pragma once

#include <functional>

namespace veld {
namespace net {

// A testnet listener must re-enter the signed restart lease at the actual
// socket activation boundary.  Keep exception handling identical for every
// listener: an unavailable or throwing guard is an authority refusal, never
// an ordinary bind failure.
inline bool ListenerActivationPermitted(
        const std::function<bool()>& activation_guard) noexcept {
    if (!activation_guard) return true;
    try {
        return activation_guard();
    } catch (...) {
        return false;
    }
}

} // namespace net
} // namespace veld
