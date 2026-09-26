#pragma once

#include <string>
#include <string_view>

#include "../core/constants.h"
#include "../core/version.h"

namespace veld::operational_key {

inline constexpr const char* TESTNET_RECORD_SCHEMA = "VELD_OPERATIONAL_KEY_V1";

struct RecordFields {
    std::string_view private_key_hex;
    std::string_view public_key_hex;
    std::string_view address;
};

inline std::string_view TrimRecordField(std::string_view value) {
    auto space = [](char c) { return c == ' ' || c == '\t' || c == '\r'; };
    while (!value.empty() && space(value.front()))
        value.remove_prefix(1);
    while (!value.empty() && space(value.back()))
        value.remove_suffix(1);
    return value;
}

// Parse only the record envelope selected at compile time.  Public-testnet
// operational keys carry an exact role/profile/genesis header; every other
// build retains the legacy three-line record.  This makes copied testnet
// keys fail closed in final builds and copied final/generic keys fail closed in
// testnet builds before any private-key material is accepted.
inline bool ParseRecord(std::string_view content, RecordFields& out) {
    size_t cursor = 0;
    auto next_line = [&](std::string_view& line) -> bool {
        if (cursor >= content.size())
            return false;
        const size_t nl = content.find('\n', cursor);
        if (nl == std::string_view::npos) {
            line = content.substr(cursor);
            cursor = content.size() + 1;
        } else {
            line = content.substr(cursor, nl - cursor);
            cursor = nl + 1;
        }
        line = TrimRecordField(line);
        return true;
    };

#ifdef VELD_PUBLIC_TESTNET
    std::string_view schema, role, profile_id, genesis_hash;
    if (!next_line(schema) || !next_line(role) || !next_line(profile_id) ||
        !next_line(genesis_hash)) {
        return false;
    }
    if (schema != TESTNET_RECORD_SCHEMA || role != std::string("role=") + DEPLOYMENT_ROLE ||
        profile_id != std::string("profile_id=") + DEPLOYMENT_PROFILE_ID ||
        genesis_hash != std::string("genesis_hash=") + GENESIS_HASH) {
        return false;
    }
#endif

    RecordFields parsed;
    if (!next_line(parsed.private_key_hex) || !next_line(parsed.public_key_hex) ||
        !next_line(parsed.address)) {
        return false;
    }

    // Preserve compatibility with blank trailing lines while refusing any
    // appended record or alternate identity metadata.
    if (cursor < content.size()) {
        for (size_t i = cursor; i < content.size(); ++i) {
            const char c = content[i];
            if (c != '\r' && c != '\n' && c != ' ' && c != '\t')
                return false;
        }
    }
    out = parsed;
    return true;
}

inline std::string FormatRecord(std::string_view private_key_hex, std::string_view public_key_hex,
                                std::string_view address) {
    std::string record;
#ifdef VELD_PUBLIC_TESTNET
    record.reserve(256 + private_key_hex.size() + public_key_hex.size() + address.size());
    record += TESTNET_RECORD_SCHEMA;
    record += "\nrole=";
    record += DEPLOYMENT_ROLE;
    record += "\nprofile_id=";
    record += DEPLOYMENT_PROFILE_ID;
    record += "\ngenesis_hash=";
    record += GENESIS_HASH;
    record.push_back('\n');
#else
    record.reserve(private_key_hex.size() + public_key_hex.size() + address.size() + 3);
#endif
    record.append(private_key_hex.data(), private_key_hex.size());
    record.push_back('\n');
    record.append(public_key_hex.data(), public_key_hex.size());
    record.push_back('\n');
    record.append(address.data(), address.size());
    record.push_back('\n');
    return record;
}

} // namespace veld::operational_key
