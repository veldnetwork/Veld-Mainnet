#pragma once
// Append-only history for changes to the vendored crypto source pin.
// Build and runtime checks require vendored.h, vendored_pin_expected.h, and
// this reviewed history tip to agree. No build regenerates these values.

namespace veld { namespace crypto {

// Most recent approved pin.
inline constexpr const char* VENDORED_PIN_HISTORY_TIP =
    "88d5ad6faeb0e54a806563d4078845dd48e50ea4915d5d1410235d737bf52eb9";

// New entries go above existing entries. Format:
//   //   YYYY-MM-DD <reason>: <pin>
//
//   2026-08-31 PROVENANCE_GATE_CORRECTION: 88d5ad6faeb0e54a806563d4078845dd48e50ea4915d5d1410235d737bf52eb9
//
//   2026-08-06 SOURCE_MAINTENANCE: afea9fedbb97b84649d9eec8503bf0cbf1a8c4cc991b5fe81cadf91cf1c67536
//
//   2026-08-06 SOURCE_MAINTENANCE: d76b21a21f1593c92b5fbe6009db14a18859bfa8295b588c0cecf4d50ffb397f
//
//   2026-08-06 SOURCE_COMMENT_CLEANUP: 4b1fd62e91273c3bb8d9dd6099b03e344c0bbd96d567fe70f0f26b12fc3d2977
//
//   2026-08-05 PQCLEAN_MLDSA65_NIST_KAT: 891ea0c125747b4e05e91974a7728d2fa40e6483aafe65044129d09f49fb650e
//   ADD_HISTORY_PIN: 01f2d2e69241cde84adb04025d6e3beacc729e1eb805b235e2ddbb77c7deb90e
//   INITIAL_PIN: 5ca4b3f28668dee91157198c1d9f2986f0dcf3288678f177b985105964f5a9c0

}}  // namespace veld::crypto
