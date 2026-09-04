#pragma once

// Strict top-level JSON-RPC method extraction for veld-desktop's remote
// allow-list.  This parser intentionally validates the complete JSON value and
// only accepts a single, literal `method` member of the root object.  A nested
// object such as
//
//   {"decoy":{"method":"getblockcount"},"method":"generatekey"}
//
// must never let the nested read-only name authorize the outer privileged
// request.  Keeping this dependency-free also lets the libFuzzer harness target
// the exact release parser.

#include <cstddef>
#include <cstdint>
#include <string>

namespace veld {
namespace rpc_proxy {
namespace detail {

class StrictMethodParser {
  public:
    explicit StrictMethodParser(const std::string& input) : input_(input) {}

    bool Parse(std::string& method) {
        method.clear();
        if (input_.empty() || input_.size() > kMaxBytes)
            return false;
        SkipWhitespace();
        if (!ParseObject(/*depth=*/1, /*root=*/true, method))
            return false;
        SkipWhitespace();
        return pos_ == input_.size() && method_seen_;
    }

  private:
    static constexpr size_t kMaxBytes = 4u * 1024u * 1024u;
    static constexpr size_t kMaxDepth = 64;
    static constexpr size_t kMaxNodes = 250000;

    const std::string& input_;
    size_t pos_{0};
    size_t nodes_{0};
    bool method_seen_{false};

    void SkipWhitespace() {
        while (pos_ < input_.size()) {
            const char c = input_[pos_];
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
                break;
            ++pos_;
        }
    }

    bool Consume(char expected) {
        if (pos_ >= input_.size() || input_[pos_] != expected)
            return false;
        ++pos_;
        return true;
    }

    static bool HexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    // Parses one JSON string. `literal` is false if an escape was used, which
    // is important for parser parity: the node's RPC parser recognizes the
    // literal root key "method" and does not reinterpret escaped key bytes.
    // Capture is bounded so an attacker cannot turn a 4 MiB key into a second
    // large allocation.
    bool ParseString(std::string* captured, bool& literal, bool& overflow, size_t capture_limit) {
        if (!Consume('"'))
            return false;
        literal = true;
        overflow = false;
        if (captured)
            captured->clear();
        while (pos_ < input_.size()) {
            const unsigned char c = static_cast<unsigned char>(input_[pos_++]);
            if (c == '"')
                return true;
            if (c < 0x20)
                return false;
            if (c == '\\') {
                literal = false;
                if (pos_ >= input_.size())
                    return false;
                const char e = input_[pos_++];
                if (e == 'u') {
                    if (pos_ + 4 > input_.size())
                        return false;
                    for (int i = 0; i < 4; ++i)
                        if (!HexDigit(input_[pos_++]))
                            return false;
                } else if (e != '"' && e != '\\' && e != '/' && e != 'b' && e != 'f' && e != 'n' &&
                           e != 'r' && e != 't') {
                    return false;
                }
                // Escaped method names are rejected, so their decoded form is
                // deliberately not appended to `captured`.
                continue;
            }
            if (captured) {
                if (captured->size() < capture_limit)
                    captured->push_back(static_cast<char>(c));
                else
                    overflow = true;
            }
        }
        return false;
    }

    bool ParseNumber() {
        if (pos_ < input_.size() && input_[pos_] == '-')
            ++pos_;
        if (pos_ >= input_.size())
            return false;
        if (input_[pos_] == '0') {
            ++pos_;
            if (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9')
                return false;
        } else if (input_[pos_] >= '1' && input_[pos_] <= '9') {
            do {
                ++pos_;
            } while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9');
        } else {
            return false;
        }
        if (pos_ < input_.size() && input_[pos_] == '.') {
            ++pos_;
            const size_t begin = pos_;
            while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9')
                ++pos_;
            if (pos_ == begin)
                return false;
        }
        if (pos_ < input_.size() && (input_[pos_] == 'e' || input_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < input_.size() && (input_[pos_] == '+' || input_[pos_] == '-'))
                ++pos_;
            const size_t begin = pos_;
            while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9')
                ++pos_;
            if (pos_ == begin)
                return false;
        }
        return true;
    }

    bool ConsumeLiteral(const char* word, size_t n) {
        if (pos_ + n > input_.size() || input_.compare(pos_, n, word) != 0)
            return false;
        pos_ += n;
        return true;
    }

    bool ParseValue(size_t depth) {
        if (++nodes_ > kMaxNodes || depth > kMaxDepth)
            return false;
        SkipWhitespace();
        if (pos_ >= input_.size())
            return false;
        const char c = input_[pos_];
        if (c == '{') {
            std::string ignored;
            return ParseObject(depth + 1, /*root=*/false, ignored);
        }
        if (c == '[')
            return ParseArray(depth + 1);
        if (c == '"') {
            bool literal = false, overflow = false;
            return ParseString(nullptr, literal, overflow, 0);
        }
        if (c == 't')
            return ConsumeLiteral("true", 4);
        if (c == 'f')
            return ConsumeLiteral("false", 5);
        if (c == 'n')
            return ConsumeLiteral("null", 4);
        return ParseNumber();
    }

    bool ParseArray(size_t depth) {
        if (depth > kMaxDepth || !Consume('['))
            return false;
        SkipWhitespace();
        if (Consume(']'))
            return true;
        for (;;) {
            if (!ParseValue(depth))
                return false;
            SkipWhitespace();
            if (Consume(']'))
                return true;
            if (!Consume(','))
                return false;
            SkipWhitespace();
        }
    }

    bool ParseObject(size_t depth, bool root, std::string& method) {
        if (depth > kMaxDepth || !Consume('{'))
            return false;
        SkipWhitespace();
        if (Consume('}'))
            return !root;
        for (;;) {
            std::string key;
            bool key_literal = false, key_overflow = false;
            if (!ParseString(&key, key_literal, key_overflow, 16))
                return false;
            SkipWhitespace();
            if (!Consume(':'))
                return false;
            SkipWhitespace();

            const bool is_method = root && key_literal && !key_overflow && key == "method";
            if (is_method) {
                if (method_seen_)
                    return false; // reject duplicate authorization keys
                method_seen_ = true;
                bool value_literal = false, value_overflow = false;
                if (!ParseString(&method, value_literal, value_overflow, 128) || !value_literal ||
                    value_overflow || method.size() < 2)
                    return false;
                if (method[0] < 'a' || method[0] > 'z')
                    return false;
                for (size_t i = 1; i < method.size(); ++i) {
                    const char c = method[i];
                    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
                        return false;
                }
            } else if (!ParseValue(depth)) {
                return false;
            }

            SkipWhitespace();
            if (Consume('}'))
                return true;
            if (!Consume(','))
                return false;
            SkipWhitespace();
        }
    }
};

} // namespace detail

inline std::string ExtractMethodFromJson(const std::string& json) {
    std::string method;
    detail::StrictMethodParser parser(json);
    if (!parser.Parse(method))
        return "";
    return method;
}

} // namespace rpc_proxy
} // namespace veld
