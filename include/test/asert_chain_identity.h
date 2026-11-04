#pragma once
// Mined with the full VeldHash parameters; qualification artifacts pin the proof.
#define VELD_ASERT_GENESIS_NONCE 2ULL
#define VELD_ASERT_GENESIS_HASH "ee875e86d25aabad2442451b82f6550b732a1387cbc172c2a3fc02eb216af3d5"

namespace veld::asert_qualification {
inline std::atomic<uint64_t> candidate_time{0};
}
