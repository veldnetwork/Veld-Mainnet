#pragma once

#include <algorithm>
#include <array>
#include <cctype>
#include <string>
#include <string_view>

namespace veld {
namespace wallet_crypto {

inline constexpr size_t MIN_NEW_PASSPHRASE_BYTES = 16;
inline constexpr size_t MAX_PASSPHRASE_BYTES = 1024;

inline bool ValidateNewPassphrase(std::string_view passphrase,
                                  std::string* error = nullptr) {
    auto fail = [&](const char* message) {
        if (error) *error = message;
        return false;
    };
    if (passphrase.size() < MIN_NEW_PASSPHRASE_BYTES)
        return fail("Passphrase must be at least 16 characters.");
    if (passphrase.size() > MAX_PASSPHRASE_BYTES)
        return fail("Passphrase is too long.");

    bool any_non_space = false;
    bool all_same = true;
    std::array<bool, 256> seen{};
    size_t distinct = 0;
    for (size_t i = 0; i < passphrase.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(passphrase[i]);
        if (!std::isspace(c)) any_non_space = true;
        if (i != 0 && passphrase[i] != passphrase[0]) all_same = false;
        if (!seen[c]) {
            seen[c] = true;
            ++distinct;
        }
    }
    if (!any_non_space)
        return fail("Passphrase cannot contain only spaces.");
    if (all_same)
        return fail("Passphrase is too easy to guess.");
    if (distinct < 5)
        return fail("Passphrase uses too few distinct characters.");

    std::string lowered;
    lowered.reserve(passphrase.size());
    for (const unsigned char c : passphrase)
        lowered.push_back(static_cast<char>(std::tolower(c)));
    std::string compact;
    compact.reserve(lowered.size());
    bool all_digits = true;
    for (const unsigned char c : lowered) {
        if (std::isalnum(c)) compact.push_back(static_cast<char>(c));
        if (!std::isdigit(c)) all_digits = false;
    }
    if (all_digits)
        return fail("Passphrase cannot contain only numbers.");

    static constexpr std::array<std::string_view, 12> blocked_fragments = {
        "password", "passphrase", "qwerty", "letmein", "administrator",
        "welcome", "veldnetwork", "veldpassword", "veldmainnet",
        "correcthorsebatterystaple", "changeme", "iloveyou"
    };
    for (const auto fragment : blocked_fragments) {
        if (compact.find(fragment) != std::string::npos)
            return fail("Passphrase contains a commonly guessed pattern.");
    }

    static constexpr std::array<std::string_view, 6> sequences = {
        "0123456789", "1234567890", "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba", "qwertyuiop", "asdfghjkl"
    };
    for (const auto sequence : sequences) {
        if (compact.find(sequence) != std::string::npos)
            return fail("Passphrase contains a predictable sequence.");
    }

    for (size_t period = 1;
         period <= std::min<size_t>(8, passphrase.size() / 2); ++period) {
        if ((passphrase.size() % period) != 0) continue;
        bool repeats = true;
        for (size_t i = period; i < passphrase.size(); ++i) {
            if (passphrase[i] != passphrase[i % period]) {
                repeats = false;
                break;
            }
        }
        if (repeats)
            return fail("Passphrase is a repeated pattern.");
    }

    if (error) error->clear();
    return true;
}

} // namespace wallet_crypto
} // namespace veld
