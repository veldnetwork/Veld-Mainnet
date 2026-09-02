#pragma once

#include <cstdint>
#include <string_view>

namespace veld {

// Parse the one canonical text encoding of an unsigned 64-bit integer.
// Consensus markers are byte strings, not user-facing numbers: signs,
// whitespace, suffixes, and redundant leading zeroes are distinct encodings
// and must never be accepted as aliases for the same value.
inline bool ParseCanonicalUint64Text(std::string_view text,
                                     uint64_t& out) noexcept {
    if (text.empty() || (text.size() > 1 && text.front() == '0')) return false;

    uint64_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') return false;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (value > (UINT64_MAX - digit) / 10) return false;
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

} // namespace veld
