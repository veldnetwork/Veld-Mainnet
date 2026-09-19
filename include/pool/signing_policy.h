#pragma once
#include "crypto/veld_signing.h"
#include "core/script.h"
#include "network/strict_json.h"
#include "wallet/secure_channel_file.h"
#include <charconv>
#include <set>
namespace veld::pool_signing {
using namespace veld;
using Json = btc_buy::JsonValue;
inline void Require(bool condition, const char* reason) {
    if (!condition) throw std::runtime_error(reason);
}
inline void Fields(const Json& value, std::initializer_list<const char*> names) {
    Require(value.kind == Json::Kind::Object && value.object.size() == names.size(), "object schema");
    for (const auto name : names) Require(value.Get(name) != nullptr, "missing field");
}
inline std::string Text(const Json& value) {
    Require(value.kind == Json::Kind::String && !value.string_had_escape, "canonical string");
    return value.text;
}
inline uint64_t Amount(const Json& value, uint64_t maximum = MAX_SUPPLY_UNITS) {
    const auto text = Text(value);
    uint64_t amount = 0;
    const auto parsed = std::from_chars(text.data(), text.data()+text.size(), amount);
    Require(parsed.ec == std::errc{} && parsed.ptr == text.data()+text.size() &&
            text == std::to_string(amount) && amount <= maximum, "integer encoding or range");
    return amount;
}
inline uint64_t Add(uint64_t a, uint64_t b) {
    Require(b <= MAX_SUPPLY_UNITS && a <= MAX_SUPPLY_UNITS-b, "amount overflow");
    return a+b;
}
inline RealKeyPair Key(const char* path) {
    std::vector<uint8_t> raw;
    std::string error;
    Require(channel::secure_file::Read(path, raw, &error, 32, true) ==
            channel::secure_file::ReadResult::Ok && raw.size() == 32, "protected seed unavailable");
    RealKeyPair key;
    std::copy(raw.begin(),raw.end(),key.private_key.begin());
    channel::secure_file::WipeAndClear(raw);
    key.public_key = DerivePublicKey(key.private_key);
    return key;
}
}
