#pragma once
#include "../core/constants.h"

// Coordinated 3.3.4 mainnet candidate: block 34,750 targets November 13, 2026
// near noon America/Denver (19:00 UTC). Height is authoritative; block timing
// cannot guarantee a wall-clock instant. Shipping qualification and operator
// readiness must precede publication. Existing historical gates stay unchanged.
#if defined(VELD_NATIVE_334_ACTIVATION_HEIGHT)
#error "Native 3.3.4 activation must be pinned in reviewed source"
#endif

namespace veld {
#if defined(VELD_PUBLIC_MAINNET)
inline constexpr uint64_t NATIVE_334_ACTIVATION_HEIGHT = 34750;
#else
inline constexpr uint64_t NATIVE_334_ACTIVATION_HEIGHT = 0;
#endif
static_assert(NATIVE_334_ACTIVATION_HEIGHT == 0 ||
              (PROTOCOL_UPGRADE_HEIGHT != 0 &&
               NATIVE_334_ACTIVATION_HEIGHT > PROTOCOL_UPGRADE_HEIGHT));
} // namespace veld
