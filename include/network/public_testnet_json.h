#pragma once

// Bounded strict JSON reader for the authenticated public-testnet START
// index. Kept independent of desk/external-value code so the core node does
// not acquire those services merely to extract its runtime lease.

#include <cctype>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace veld::public_testnet::runtime_json {

struct Value {
    enum class Kind { Null, Bool, Number, String, Array, Object };
    Kind kind{Kind::Null};
    bool boolean{false};
    std::string text;
    std::vector<Value> array;
    std::map<std::string, Value> object;

    const Value* Get(const std::string& key) const {
        if (kind != Kind::Object) return nullptr;
        const auto it = object.find(key);
        return it == object.end() ? nullptr : &it->second;
    }
};

class Parser {
public:
    explicit Parser(std::string_view input, size_t max_input_bytes)
        : input_(input), max_input_bytes_(max_input_bytes) {}

    bool Parse(Value& out, std::string& error) {
        if (input_.empty() || input_.size() > max_input_bytes_)
            return Fail(error, "JSON size outside runtime policy");
        SkipWhitespace();
        if (!ParseValue(out, error, 0)) return false;
        SkipWhitespace();
        if (pos_ != input_.size()) return Fail(error, "trailing JSON bytes");
        return true;
    }

private:
    static constexpr size_t MAX_DEPTH = 64;
    static constexpr size_t MAX_NODES = 100000;
    std::string_view input_;
    size_t max_input_bytes_;
    size_t pos_{0};
    size_t nodes_{0};

    static bool Fail(std::string& error, const char* message) {
        error = message;
        return false;
    }
    void SkipWhitespace() {
        while (pos_ < input_.size() &&
               (input_[pos_] == ' ' || input_[pos_] == '\t' ||
                input_[pos_] == '\r' || input_[pos_] == '\n'))
            ++pos_;
    }
    bool Consume(std::string_view token) {
        if (input_.substr(pos_, token.size()) != token) return false;
        pos_ += token.size();
        return true;
    }
    static int HexNibble(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }
    static void AppendUtf8(std::string& out, uint32_t cp) {
        if (cp <= 0x7f) out.push_back(static_cast<char>(cp));
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
    bool ParseHex4(uint32_t& out, std::string& error) {
        if (pos_ + 4 > input_.size())
            return Fail(error, "truncated JSON unicode escape");
        out = 0;
        for (int i = 0; i < 4; ++i) {
            const int nibble = HexNibble(input_[pos_++]);
            if (nibble < 0) return Fail(error, "invalid JSON unicode escape");
            out = (out << 4) | static_cast<uint32_t>(nibble);
        }
        return true;
    }
    bool ParseString(std::string& out, std::string& error) {
        if (pos_ >= input_.size() || input_[pos_] != '"')
            return Fail(error, "expected JSON string");
        ++pos_;
        out.clear();
        while (pos_ < input_.size()) {
            const unsigned char c = static_cast<unsigned char>(input_[pos_++]);
            if (c == '"') return true;
            if (c < 0x20) return Fail(error, "control byte in JSON string");
            if (c != '\\') {
                out.push_back(static_cast<char>(c));
                continue;
            }
            if (pos_ >= input_.size()) return Fail(error, "truncated JSON escape");
            switch (input_[pos_++]) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    uint32_t cp = 0;
                    if (!ParseHex4(cp, error)) return false;
                    if (cp >= 0xd800 && cp <= 0xdbff) {
                        if (pos_ + 2 > input_.size() || input_[pos_] != '\\' ||
                            input_[pos_ + 1] != 'u')
                            return Fail(error, "unpaired JSON high surrogate");
                        pos_ += 2;
                        uint32_t low = 0;
                        if (!ParseHex4(low, error) ||
                            low < 0xdc00 || low > 0xdfff)
                            return Fail(error, "invalid JSON low surrogate");
                        cp = 0x10000 + ((cp - 0xd800) << 10) +
                             (low - 0xdc00);
                    } else if (cp >= 0xdc00 && cp <= 0xdfff) {
                        return Fail(error, "unpaired JSON low surrogate");
                    }
                    AppendUtf8(out, cp);
                    break;
                }
                default: return Fail(error, "invalid JSON escape");
            }
        }
        return Fail(error, "unterminated JSON string");
    }
    bool ParseNumber(Value& out, std::string& error) {
        const size_t begin = pos_;
        if (pos_ < input_.size() && input_[pos_] == '-') ++pos_;
        if (pos_ >= input_.size()) return Fail(error, "truncated JSON number");
        if (input_[pos_] == '0') {
            ++pos_;
            if (pos_ < input_.size() &&
                std::isdigit(static_cast<unsigned char>(input_[pos_])))
                return Fail(error, "JSON number has a leading zero");
        } else if (input_[pos_] >= '1' && input_[pos_] <= '9') {
            while (pos_ < input_.size() &&
                   std::isdigit(static_cast<unsigned char>(input_[pos_])))
                ++pos_;
        } else {
            return Fail(error, "invalid JSON number");
        }
        if (pos_ < input_.size() && input_[pos_] == '.') {
            ++pos_;
            const size_t digits = pos_;
            while (pos_ < input_.size() &&
                   std::isdigit(static_cast<unsigned char>(input_[pos_])))
                ++pos_;
            if (pos_ == digits) return Fail(error, "invalid JSON fraction");
        }
        if (pos_ < input_.size() &&
            (input_[pos_] == 'e' || input_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < input_.size() &&
                (input_[pos_] == '+' || input_[pos_] == '-'))
                ++pos_;
            const size_t digits = pos_;
            while (pos_ < input_.size() &&
                   std::isdigit(static_cast<unsigned char>(input_[pos_])))
                ++pos_;
            if (pos_ == digits) return Fail(error, "invalid JSON exponent");
        }
        out.kind = Value::Kind::Number;
        out.text.assign(input_.substr(begin, pos_ - begin));
        return true;
    }
    bool ParseValue(Value& out, std::string& error, size_t depth) {
        if (++nodes_ > MAX_NODES) return Fail(error, "too many JSON nodes");
        if (depth > MAX_DEPTH) return Fail(error, "JSON nesting too deep");
        SkipWhitespace();
        if (pos_ >= input_.size()) return Fail(error, "truncated JSON value");
        if (input_[pos_] == '{') return ParseObject(out, error, depth + 1);
        if (input_[pos_] == '[') return ParseArray(out, error, depth + 1);
        if (input_[pos_] == '"') {
            out.kind = Value::Kind::String;
            return ParseString(out.text, error);
        }
        if (Consume("true")) {
            out.kind = Value::Kind::Bool;
            out.boolean = true;
            return true;
        }
        if (Consume("false")) {
            out.kind = Value::Kind::Bool;
            out.boolean = false;
            return true;
        }
        if (Consume("null")) {
            out.kind = Value::Kind::Null;
            return true;
        }
        return ParseNumber(out, error);
    }
    bool ParseArray(Value& out, std::string& error, size_t depth) {
        ++pos_;
        out.kind = Value::Kind::Array;
        out.array.clear();
        SkipWhitespace();
        if (pos_ < input_.size() && input_[pos_] == ']') {
            ++pos_;
            return true;
        }
        for (;;) {
            Value value;
            if (!ParseValue(value, error, depth)) return false;
            out.array.push_back(std::move(value));
            SkipWhitespace();
            if (pos_ >= input_.size()) return Fail(error, "unterminated JSON array");
            if (input_[pos_] == ']') {
                ++pos_;
                return true;
            }
            if (input_[pos_] != ',') return Fail(error, "missing JSON array comma");
            ++pos_;
            SkipWhitespace();
        }
    }
    bool ParseObject(Value& out, std::string& error, size_t depth) {
        ++pos_;
        out.kind = Value::Kind::Object;
        out.object.clear();
        SkipWhitespace();
        if (pos_ < input_.size() && input_[pos_] == '}') {
            ++pos_;
            return true;
        }
        for (;;) {
            std::string key;
            if (!ParseString(key, error)) return false;
            SkipWhitespace();
            if (pos_ >= input_.size() || input_[pos_] != ':')
                return Fail(error, "missing JSON object colon");
            ++pos_;
            Value value;
            if (!ParseValue(value, error, depth)) return false;
            if (!out.object.emplace(std::move(key), std::move(value)).second)
                return Fail(error, "duplicate JSON object key");
            SkipWhitespace();
            if (pos_ >= input_.size()) return Fail(error, "unterminated JSON object");
            if (input_[pos_] == '}') {
                ++pos_;
                return true;
            }
            if (input_[pos_] != ',') return Fail(error, "missing JSON object comma");
            ++pos_;
            SkipWhitespace();
        }
    }
};

inline bool AppendCanonicalString(const std::string& value,
                                  std::string& out,
                                  std::string& error) {
    static constexpr char HEX[] = "0123456789abcdef";
    auto append_u16 = [&](uint16_t cp) {
        out += "\\u";
        out.push_back(HEX[(cp >> 12) & 0xf]);
        out.push_back(HEX[(cp >> 8) & 0xf]);
        out.push_back(HEX[(cp >> 4) & 0xf]);
        out.push_back(HEX[cp & 0xf]);
    };
    out.push_back('"');
    for (size_t i = 0; i < value.size();) {
        const uint8_t first = static_cast<uint8_t>(value[i]);
        uint32_t cp = 0;
        size_t width = 0;
        if (first < 0x80) {
            cp = first;
            width = 1;
        } else if (first >= 0xc2 && first <= 0xdf) {
            cp = first & 0x1f;
            width = 2;
        } else if (first >= 0xe0 && first <= 0xef) {
            cp = first & 0x0f;
            width = 3;
        } else if (first >= 0xf0 && first <= 0xf4) {
            cp = first & 0x07;
            width = 4;
        } else {
            error = "invalid UTF-8 in START JSON string";
            return false;
        }
        if (i + width > value.size()) {
            error = "truncated UTF-8 in START JSON string";
            return false;
        }
        for (size_t j = 1; j < width; ++j) {
            const uint8_t continuation = static_cast<uint8_t>(value[i + j]);
            if ((continuation & 0xc0) != 0x80) {
                error = "invalid UTF-8 continuation in START JSON string";
                return false;
            }
            cp = (cp << 6) | (continuation & 0x3f);
        }
        if ((width == 3 && ((first == 0xe0 && cp < 0x800) ||
                            (first == 0xed && cp >= 0xd800))) ||
            (width == 4 && ((first == 0xf0 && cp < 0x10000) ||
                            (first == 0xf4 && cp > 0x10ffff))) ||
            (cp >= 0xd800 && cp <= 0xdfff) || cp > 0x10ffff) {
            error = "non-canonical UTF-8 in START JSON string";
            return false;
        }
        i += width;

        switch (cp) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (cp < 0x20) {
                    append_u16(static_cast<uint16_t>(cp));
                } else if (cp < 0x80) {
                    out.push_back(static_cast<char>(cp));
                } else if (cp <= 0xffff) {
                    append_u16(static_cast<uint16_t>(cp));
                } else {
                    cp -= 0x10000;
                    append_u16(static_cast<uint16_t>(0xd800 + (cp >> 10)));
                    append_u16(static_cast<uint16_t>(0xdc00 + (cp & 0x3ff)));
                }
                break;
        }
    }
    out.push_back('"');
    return true;
}

inline bool AppendCanonical(const Value& value, size_t depth,
                            std::string& out, std::string& error) {
    switch (value.kind) {
        case Value::Kind::Null:
            out += "null";
            return true;
        case Value::Kind::Bool:
            out += value.boolean ? "true" : "false";
            return true;
        case Value::Kind::Number:
            out += value.text;
            return true;
        case Value::Kind::String:
            return AppendCanonicalString(value.text, out, error);
        case Value::Kind::Array: {
            if (value.array.empty()) {
                out += "[]";
                return true;
            }
            out += "[\n";
            for (size_t i = 0; i < value.array.size(); ++i) {
                out.append((depth + 1) * 2, ' ');
                if (!AppendCanonical(value.array[i], depth + 1, out, error))
                    return false;
                out += i + 1 == value.array.size() ? "\n" : ",\n";
            }
            out.append(depth * 2, ' ');
            out.push_back(']');
            return true;
        }
        case Value::Kind::Object: {
            if (value.object.empty()) {
                out += "{}";
                return true;
            }
            out += "{\n";
            size_t i = 0;
            for (const auto& [key, child] : value.object) {
                out.append((depth + 1) * 2, ' ');
                if (!AppendCanonicalString(key, out, error)) return false;
                out += ": ";
                if (!AppendCanonical(child, depth + 1, out, error))
                    return false;
                out += ++i == value.object.size() ? "\n" : ",\n";
            }
            out.append(depth * 2, ' ');
            out.push_back('}');
            return true;
        }
    }
    error = "unknown START JSON value kind";
    return false;
}

inline bool Canonicalize(const Value& value, std::string& out,
                         std::string& error) {
    out.clear();
    if (!AppendCanonical(value, 0, out, error)) return false;
    out.push_back('\n');
    return true;
}

}  // namespace veld::public_testnet::runtime_json
