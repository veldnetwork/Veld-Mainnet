#pragma once
// Expected SHA-256 of vendored.h.
// CHECKED in code review. The release provenance gate fails if the exact raw
// hash diverges; there is intentionally no automatic pin-update command.
namespace veld { namespace crypto {
inline constexpr const char* VENDORED_SHA256_EXPECTED =
    "88d5ad6faeb0e54a806563d4078845dd48e50ea4915d5d1410235d737bf52eb9";
}}
