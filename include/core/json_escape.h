#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace veld {
namespace json {

// Produce a JSON string payload from an arbitrary byte string.  Consensus and
// RPC records can contain bytes that did not originate in a UTF-8 UI.  Passing
// an invalid octet through verbatim makes the complete JSON document invalid
// for strict consumers.  Preserve canonical UTF-8 sequences byte-for-byte and
// encode each invalid octet as a U+00xx escape; this keeps valid international
// text readable without letting one hostile record poison the surrounding API.
inline std::string EscapeStringBytes(std::string_view input) {
    static constexpr char HEX[] = "0123456789abcdef";
    std::string out;
    out.reserve(input.size() + 8);

    auto append_u00 = [&](uint8_t c) {
        out += "\\u00";
        out.push_back(HEX[c >> 4]);
        out.push_back(HEX[c & 0x0f]);
    };
    auto continuation = [&](size_t index) {
        return index < input.size() &&
               (static_cast<uint8_t>(input[index]) & 0xc0U) == 0x80U;
    };

    for (size_t i = 0; i < input.size();) {
        const uint8_t c = static_cast<uint8_t>(input[i]);
        if (c < 0x80U) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b";  break;
                case '\f': out += "\\f";  break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:
                    if (c < 0x20U) append_u00(c);
                    else out.push_back(static_cast<char>(c));
            }
            ++i;
            continue;
        }

        size_t width = 0;
        bool valid = false;
        if (c >= 0xc2U && c <= 0xdfU) {
            width = 2;
            valid = continuation(i + 1);
        } else if (c >= 0xe0U && c <= 0xefU) {
            width = 3;
            if (continuation(i + 1) && continuation(i + 2)) {
                const uint8_t c1 = static_cast<uint8_t>(input[i + 1]);
                valid = (c != 0xe0U || c1 >= 0xa0U) &&
                        (c != 0xedU || c1 <= 0x9fU); // no overlong/surrogate
            }
        } else if (c >= 0xf0U && c <= 0xf4U) {
            width = 4;
            if (continuation(i + 1) && continuation(i + 2) &&
                continuation(i + 3)) {
                const uint8_t c1 = static_cast<uint8_t>(input[i + 1]);
                valid = (c != 0xf0U || c1 >= 0x90U) &&
                        (c != 0xf4U || c1 <= 0x8fU); // <= U+10ffff
            }
        }

        if (!valid) {
            append_u00(c);
            ++i;
            continue;
        }
        out.append(input.data() + i, width);
        i += width;
    }
    return out;
}

} // namespace json
} // namespace veld
