#pragma once

// Strict, dependency-free JSON parsing shared by local RPC clients.

#include <cctype>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace veld::btc_buy {

inline constexpr const char* kCustodyScriptPubKey =
    "a9145d00e96815a807a478a9345d5b4d1a99dfc9524487";
inline constexpr uint64_t kMaxBitcoinSats = 21000000ULL * 100000000ULL;
inline constexpr uint64_t kMaxBitcoinBlockHeight = 100000000ULL;
inline constexpr size_t kMaxExplorerResponseBytes = 4U * 1024U * 1024U;
inline constexpr size_t kMaxTxOutputs = 10000;

struct JsonValue {
    enum class Kind { Null, Bool, Number, String, Array, Object };
    Kind kind{Kind::Null};
    bool boolean{false};
    bool string_had_escape{false};
    std::string text;
    std::vector<JsonValue> array;
    std::map<std::string, JsonValue> object;

    const JsonValue* Get(const std::string& key) const {
        if (kind != Kind::Object)
            return nullptr;
        auto it = object.find(key);
        return it == object.end() ? nullptr : &it->second;
    }
};

class StrictJsonParser {
  public:
    explicit StrictJsonParser(std::string_view input,
                              size_t max_input_bytes = kMaxExplorerResponseBytes,
                              bool reject_escaped_object_keys = false)
        : input_(input), max_input_bytes_(max_input_bytes),
          reject_escaped_object_keys_(reject_escaped_object_keys) {}

    bool Parse(JsonValue& out, std::string& error) {
        if (input_.empty() || input_.size() > max_input_bytes_)
            return Fail(error, "response size outside policy");
        SkipWhitespace();
        if (!ParseValue(out, error, 0))
            return false;
        SkipWhitespace();
        if (pos_ != input_.size())
            return Fail(error, "trailing JSON bytes");
        return true;
    }

  private:
    static constexpr size_t kMaxDepth = 64;
    static constexpr size_t kMaxNodes = 250000;
    std::string_view input_;
    size_t max_input_bytes_;
    bool reject_escaped_object_keys_{false};
    size_t pos_{0};
    size_t nodes_{0};

    bool Fail(std::string& error, const char* message) {
        error = message;
        return false;
    }

    void SkipWhitespace() {
        while (pos_ < input_.size() && (input_[pos_] == ' ' || input_[pos_] == '\t' ||
                                        input_[pos_] == '\r' || input_[pos_] == '\n'))
            ++pos_;
    }

    bool ParseValue(JsonValue& out, std::string& error, size_t depth) {
        if (++nodes_ > kMaxNodes)
            return Fail(error, "too many JSON nodes");
        if (depth > kMaxDepth)
            return Fail(error, "JSON nesting too deep");
        SkipWhitespace();
        if (pos_ >= input_.size())
            return Fail(error, "truncated JSON value");
        const char c = input_[pos_];
        if (c == '{')
            return ParseObject(out, error, depth + 1);
        if (c == '[')
            return ParseArray(out, error, depth + 1);
        if (c == '"') {
            out.kind = JsonValue::Kind::String;
            return ParseString(out.text, error, &out.string_had_escape);
        }
        if (c == 't' && Consume("true")) {
            out.kind = JsonValue::Kind::Bool;
            out.boolean = true;
            return true;
        }
        if (c == 'f' && Consume("false")) {
            out.kind = JsonValue::Kind::Bool;
            out.boolean = false;
            return true;
        }
        if (c == 'n' && Consume("null")) {
            out.kind = JsonValue::Kind::Null;
            return true;
        }
        return ParseNumber(out, error);
    }

    bool Consume(std::string_view token) {
        if (input_.substr(pos_, token.size()) != token)
            return false;
        pos_ += token.size();
        return true;
    }

    static void AppendUtf8(std::string& out, uint32_t cp) {
        if (cp <= 0x7f)
            out.push_back(static_cast<char>(cp));
        else if (cp <= 0x7ff) {
            out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        } else if (cp <= 0xffff) {
            out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        } else {
            out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        }
    }

    static int HexNibble(char c) {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    }

    bool ParseHex4(uint32_t& out, std::string& error) {
        if (pos_ + 4 > input_.size())
            return Fail(error, "truncated unicode escape");
        out = 0;
        for (int i = 0; i < 4; ++i) {
            int n = HexNibble(input_[pos_++]);
            if (n < 0)
                return Fail(error, "invalid unicode escape");
            out = (out << 4) | static_cast<uint32_t>(n);
        }
        return true;
    }

    bool ParseString(std::string& out, std::string& error, bool* had_escape = nullptr) {
        if (pos_ >= input_.size() || input_[pos_] != '"')
            return Fail(error, "expected JSON string");
        ++pos_;
        out.clear();
        if (had_escape)
            *had_escape = false;
        while (pos_ < input_.size()) {
            unsigned char c = static_cast<unsigned char>(input_[pos_++]);
            if (c == '"')
                return true;
            if (c < 0x20)
                return Fail(error, "control byte in JSON string");
            if (c != '\\') {
                out.push_back(static_cast<char>(c));
                continue;
            }
            if (had_escape)
                *had_escape = true;
            if (pos_ >= input_.size())
                return Fail(error, "truncated JSON escape");
            char e = input_[pos_++];
            switch (e) {
            case '"':
                out.push_back('"');
                break;
            case '\\':
                out.push_back('\\');
                break;
            case '/':
                out.push_back('/');
                break;
            case 'b':
                out.push_back('\b');
                break;
            case 'f':
                out.push_back('\f');
                break;
            case 'n':
                out.push_back('\n');
                break;
            case 'r':
                out.push_back('\r');
                break;
            case 't':
                out.push_back('\t');
                break;
            case 'u': {
                uint32_t cp = 0;
                if (!ParseHex4(cp, error))
                    return false;
                if (cp >= 0xd800 && cp <= 0xdbff) {
                    if (pos_ + 2 > input_.size() || input_[pos_] != '\\' || input_[pos_ + 1] != 'u')
                        return Fail(error, "unpaired high surrogate");
                    pos_ += 2;
                    uint32_t low = 0;
                    if (!ParseHex4(low, error))
                        return false;
                    if (low < 0xdc00 || low > 0xdfff)
                        return Fail(error, "invalid low surrogate");
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
                } else if (cp >= 0xdc00 && cp <= 0xdfff) {
                    return Fail(error, "unpaired low surrogate");
                }
                AppendUtf8(out, cp);
                break;
            }
            default:
                return Fail(error, "invalid JSON escape");
            }
        }
        return Fail(error, "unterminated JSON string");
    }

    bool ParseNumber(JsonValue& out, std::string& error) {
        const size_t begin = pos_;
        if (pos_ < input_.size() && input_[pos_] == '-')
            ++pos_;
        if (pos_ >= input_.size())
            return Fail(error, "truncated JSON number");
        if (input_[pos_] == '0') {
            ++pos_;
            if (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_])))
                return Fail(error, "non-canonical leading zero");
        } else if (input_[pos_] >= '1' && input_[pos_] <= '9') {
            while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_])))
                ++pos_;
        } else
            return Fail(error, "invalid JSON number");
        if (pos_ < input_.size() && input_[pos_] == '.') {
            ++pos_;
            size_t digits = pos_;
            while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_])))
                ++pos_;
            if (pos_ == digits)
                return Fail(error, "invalid JSON fraction");
        }
        if (pos_ < input_.size() && (input_[pos_] == 'e' || input_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < input_.size() && (input_[pos_] == '+' || input_[pos_] == '-'))
                ++pos_;
            size_t digits = pos_;
            while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_])))
                ++pos_;
            if (pos_ == digits)
                return Fail(error, "invalid JSON exponent");
        }
        out.kind = JsonValue::Kind::Number;
        out.text.assign(input_.substr(begin, pos_ - begin));
        return true;
    }

    bool ParseArray(JsonValue& out, std::string& error, size_t depth) {
        ++pos_;
        out.kind = JsonValue::Kind::Array;
        out.array.clear();
        SkipWhitespace();
        if (pos_ < input_.size() && input_[pos_] == ']') {
            ++pos_;
            return true;
        }
        for (;;) {
            JsonValue item;
            if (!ParseValue(item, error, depth))
                return false;
            out.array.push_back(std::move(item));
            SkipWhitespace();
            if (pos_ >= input_.size())
                return Fail(error, "unterminated JSON array");
            if (input_[pos_] == ']') {
                ++pos_;
                return true;
            }
            if (input_[pos_] != ',')
                return Fail(error, "expected JSON array comma");
            ++pos_;
            SkipWhitespace();
        }
    }

    bool ParseObject(JsonValue& out, std::string& error, size_t depth) {
        ++pos_;
        out.kind = JsonValue::Kind::Object;
        out.object.clear();
        SkipWhitespace();
        if (pos_ < input_.size() && input_[pos_] == '}') {
            ++pos_;
            return true;
        }
        for (;;) {
            std::string key;
            bool key_had_escape = false;
            if (!ParseString(key, error, &key_had_escape))
                return false;
            if (reject_escaped_object_keys_ && key_had_escape)
                return Fail(error, "escaped JSON object key");
            SkipWhitespace();
            if (pos_ >= input_.size() || input_[pos_] != ':')
                return Fail(error, "expected JSON object colon");
            ++pos_;
            JsonValue value;
            if (!ParseValue(value, error, depth))
                return false;
            if (!out.object.emplace(std::move(key), std::move(value)).second)
                return Fail(error, "duplicate JSON object key");
            SkipWhitespace();
            if (pos_ >= input_.size())
                return Fail(error, "unterminated JSON object");
            if (input_[pos_] == '}') {
                ++pos_;
                return true;
            }
            if (input_[pos_] != ',')
                return Fail(error, "expected JSON object comma");
            ++pos_;
            SkipWhitespace();
        }
    }
};

inline bool IsLowerHex(const std::string& value, size_t exact_chars = 0) {
    if ((exact_chars && value.size() != exact_chars) || value.empty() || (value.size() & 1U))
        return false;
    for (char c : value)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}

inline bool IsNonzeroHash256(const std::string& value) {
    if (!IsLowerHex(value, 64))
        return false;
    for (char c : value)
        if (c != '0')
            return true;
    return false;
}

inline bool ParseUint(const JsonValue& value, uint64_t& out) {
    if (value.kind != JsonValue::Kind::Number || value.text.empty())
        return false;
    uint64_t n = 0;
    for (char c : value.text) {
        if (c < '0' || c > '9')
            return false;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (n > (std::numeric_limits<uint64_t>::max() - digit) / 10)
            return false;
        n = n * 10 + digit;
    }
    out = n;
    return true;
}

} // namespace veld::btc_buy
