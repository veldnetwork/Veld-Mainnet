#pragma once
#include "security_state_migration.h"
#include "../core/canonical_numeric.h"
#include "../core/hash.h"
#include <array>
#include <string>
#include <string_view>

namespace veld {

struct EndorsementWire {
    bool attributed = false;
    uint64_t height = 0;
    std::string hash;
    std::string address;
    std::string signature;
};

inline bool EndorsementLowerHex(std::string_view text, size_t size) {
    if (text.size() != size) return false;
    for (char c : text)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}

inline bool HasEndorsementWirePrefix(std::string_view data) {
    return data.starts_with("VELD_VALIDATOR|ENDORSE|") ||
           data.starts_with("VELD_VALIDATOR|ENDORSE2|");
}

// Grammar only: eligibility and the single selected-key signature verification
// remain at the registry boundary. No caller infers acceptance from this parse.
inline bool ParseEndorsementWire(std::string_view data, EndorsementWire& out) {
    out = {};
    constexpr std::string_view legacy = "VELD_VALIDATOR|ENDORSE|";
    constexpr std::string_view current = "VELD_VALIDATOR|ENDORSE2|";
    const bool attributed = data.starts_with(current);
    if (!attributed && !data.starts_with(legacy)) return false;
    data.remove_prefix(attributed ? current.size() : legacy.size());
    std::array<std::string_view, 4> fields{};
    const size_t count = attributed ? 4 : 3;
    for (size_t i = 0; i < count; ++i) {
        const size_t end = data.find('|');
        if ((i + 1 == count) != (end == std::string_view::npos)) return false;
        fields[i] = end == std::string_view::npos ? data : data.substr(0, end);
        if (end != std::string_view::npos) data.remove_prefix(end + 1);
    }
    if (!ParseCanonicalUint64Text(fields[0], out.height) ||
        !EndorsementLowerHex(fields[1], 64) ||
        !EndorsementLowerHex(fields[count - 1], 6618)) return false;
    if (attributed) {
        constexpr std::string_view alphabet =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        if (fields[2].empty() || fields[2].size() > 64 ||
            fields[2].find_first_not_of(alphabet) != std::string_view::npos)
            return false;
        out.address = fields[2];
    }
    out.attributed = attributed;
    out.hash = fields[1];
    out.signature = fields[count - 1];
    return true;
}

} // namespace veld
