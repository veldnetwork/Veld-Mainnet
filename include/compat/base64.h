#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <vector>

namespace veld::compat {

// Decode canonical RFC 4648 base64. Browser keystore fields are emitted by
// btoa(), so they have exactly one padded spelling: no whitespace, padding only
// in the final quartet, and zero unused tail bits.
inline bool DecodeBase64Canonical(std::string_view input, std::vector<uint8_t>& output,
                                  size_t max_decoded_bytes) {
    output.clear();
    if (input.empty())
        return true;
    if ((input.size() & 3u) != 0)
        return false;
    if (max_decoded_bytes > std::numeric_limits<size_t>::max() - 2)
        return false;
    const size_t max_quartets = (max_decoded_bytes + 2) / 3;
    if (max_quartets > std::numeric_limits<size_t>::max() / 4)
        return false;
    if (input.size() > max_quartets * 4)
        return false;

    auto value = [](unsigned char c) -> int {
        if (c >= 'A' && c <= 'Z')
            return c - 'A';
        if (c >= 'a' && c <= 'z')
            return c - 'a' + 26;
        if (c >= '0' && c <= '9')
            return c - '0' + 52;
        if (c == '+')
            return 62;
        if (c == '/')
            return 63;
        return -1;
    };

    output.reserve(input.size() / 4 * 3);
    for (size_t i = 0; i < input.size(); i += 4) {
        const bool final = i + 4 == input.size();
        const int a = value(static_cast<unsigned char>(input[i]));
        const int b = value(static_cast<unsigned char>(input[i + 1]));
        if (a < 0 || b < 0) {
            output.clear();
            return false;
        }

        const char cch = input[i + 2];
        const char dch = input[i + 3];
        if (cch == '=') {
            if (!final || dch != '=' || (b & 0x0f) != 0) {
                output.clear();
                return false;
            }
            output.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
            continue;
        }

        const int c = value(static_cast<unsigned char>(cch));
        if (c < 0) {
            output.clear();
            return false;
        }
        output.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
        if (dch == '=') {
            if (!final || (c & 0x03) != 0) {
                output.clear();
                return false;
            }
            output.push_back(static_cast<uint8_t>((b << 4) | (c >> 2)));
            continue;
        }

        const int d = value(static_cast<unsigned char>(dch));
        if (d < 0) {
            output.clear();
            return false;
        }
        output.push_back(static_cast<uint8_t>((b << 4) | (c >> 2)));
        output.push_back(static_cast<uint8_t>((c << 6) | d));
    }
    if (output.size() > max_decoded_bytes) {
        output.clear();
        return false;
    }
    return true;
}

} // namespace veld::compat
