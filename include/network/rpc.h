#pragma once

#include "../core/blockchain.h"
#include "../core/pow_target.h"
#include "../core/version.h"
#include "../core/pqc_script.h"
#include "../core/vault.h"
#include "../consensus/staking.h"
#include "../consensus/validators.h"
#include "../consensus/finality_equivocation.h"
#include "../consensus/btcveld_redeem_guard.h"
#include "../consensus/btcveld_amm_gate.h"
#include "../consensus/btcveld_mint_policy.h"
#include "../core/multisig.h"
#include "strict_json.h"

#include "../core/mempool.h"
#include "../core/transaction.h"
#include "../core/storage.h"
#include "../core/onchain_tokens.h"
#include "../core/amm_pool.h"
#include "../core/btc_relay_order.h"
#include "../mining/preflight_selector.h"
#include "../consensus/tiers.h"
#include "../consensus/governance.h"
#include "../wallet/wallet.h"
#include "../wallet/wallet_crypto.h"
#include "../wallet/passphrase_policy.h"
#include "../wallet/secure_channel_file.h"
#include "../wallet/offline_signing.h"
#include "../node/work_admission.h"
#include "../node/block_template_authorization.h"
#include <fstream>
#include <filesystem>
#include <string>
#include <chrono>
#include <mutex>
#include <unordered_map>
#include <functional>
#include <sstream>
#include <iomanip>
#include <vector>
#include <mutex>
#include <algorithm>
#include <ctime>
#include <cmath>
#include <memory>
#include <set>
#include <cctype>
#include <charconv>
#include <cstring>
#include <limits>
#include <utility>
#include <atomic>
#include "../compat/platform.h"
#include "../crypto/vendored.h"

namespace veld {

struct BtcVeldPegStatus {
    BtcVeldPegGateState gate{false, false, false};
    uint64_t tip{0};
    uint64_t final_height{0};
    bool finality_active{false};
    bool finality_ever_active{false};
    bool anchor_promoted{false};
    std::string reason{"status_unavailable"};
};

inline uint64_t ParseCanonicalRpcU64OrThrow(const std::string& s, const char* field) {
    if (s.empty() || (s.size() > 1 && s.front() == '0'))
        throw std::invalid_argument(std::string(field) +
                                    " must be a canonical non-negative integer");
    uint64_t value = 0;
    const char* begin = s.data();
    const char* end = begin + s.size();
    const auto parsed = std::from_chars(begin, end, value, 10);
    if (parsed.ec != std::errc{} || parsed.ptr != end)
        throw std::invalid_argument(std::string(field) +
                                    " must be a canonical non-negative integer");
    return value;
}

inline uint32_t ParseCanonicalRpcU32OrThrow(const std::string& s, const char* field) {
    const uint64_t value = ParseCanonicalRpcU64OrThrow(s, field);
    if (value > UINT32_MAX)
        throw std::invalid_argument(std::string(field) + " is out of range");
    return static_cast<uint32_t>(value);
}

inline bool IsCanonicalRpcLowerHex(const std::string& s, size_t exact_chars) {
    if (s.size() != exact_chars)
        return false;
    for (const char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

namespace rpc_detail {

// A signer may already hold a durable lease on an otherwise selectable
// issuer-fee input.  Preparers cannot observe that isolated signer journal, so
// an exact exit-75 conflict acknowledgement feeds a bounded, canonical
// exclusion list back into the next preparation attempt.  Keep the transport
// a single string because RpcRequest intentionally exposes scalar params only.
inline const std::string& IssuerPrevoutExclusionPrefix() {
    static const std::string prefix{"issuer-prevout-exclusions-v1:"};
    return prefix;
}

inline constexpr size_t MAX_ISSUER_PREVOUT_EXCLUSIONS = 64;

inline bool IsIssuerPrevoutExclusionParam(const std::string& value) {
    const auto& prefix = IssuerPrevoutExclusionPrefix();
    return value.rfind(prefix, 0) == 0;
}

inline std::vector<std::string> ParseIssuerPrevoutExclusions(const std::string& value) {
    const auto& prefix = IssuerPrevoutExclusionPrefix();
    if (!IsIssuerPrevoutExclusionParam(value))
        throw std::invalid_argument("issuer fee prevout exclusions are malformed");
    std::vector<std::string> result;
    // A migrated never-sign revocation may not know which historical lease
    // intersected.  Its authenticated empty list still authorizes discarding
    // that exact unsigned hash and preparing afresh.
    if (value.size() == prefix.size())
        return result;
    size_t begin = prefix.size();
    while (begin <= value.size()) {
        const size_t comma = value.find(',', begin);
        const size_t end = comma == std::string::npos ? value.size() : comma;
        const std::string outpoint = value.substr(begin, end - begin);
        if (!IsValidBtcOutpointId(outpoint))
            throw std::invalid_argument(
                "issuer fee prevout exclusion is not a canonical txid:vout");
        if (!result.empty() && outpoint <= result.back())
            throw std::invalid_argument(
                "issuer fee prevout exclusions must be strictly sorted and unique");
        result.push_back(outpoint);
        if (result.size() > MAX_ISSUER_PREVOUT_EXCLUSIONS)
            throw std::invalid_argument("issuer fee prevout exclusion limit exceeded");
        if (comma == std::string::npos)
            break;
        begin = comma + 1;
    }
    return result;
}

inline std::string UtxoOutpointId(const UTXO& utxo) {
    return HashToHex(utxo.tx_hash) + ":" + std::to_string(utxo.output_index);
}

inline bool IssuerPrevoutIsExcluded(const UTXO& utxo, const std::vector<std::string>& exclusions) {
    return std::binary_search(exclusions.begin(), exclusions.end(), UtxoOutpointId(utxo));
}

struct ExactPrevoutSpender {
    Transaction tx;
    bool confirmed = false;
    uint64_t block_height = 0;
    Hash256 block_hash{};
};

// Canonical state must dominate the mempool during the independently locked
// block-connect -> mempool-cleanup window.  The second canonical lookup closes
// a commit that lands after the first miss but before/during the mempool read.
// `after_first_canonical_miss` is normally a no-op; the regression supplies a
// deterministic commit at that exact interleaving.
template <typename AfterFirstCanonicalMiss>
inline std::optional<ExactPrevoutSpender>
ResolveExactPrevoutSpender(const Blockchain& chain, const Mempool& mempool,
                           const Hash256& prev_txid, uint32_t vout,
                           AfterFirstCanonicalMiss&& after_first_canonical_miss) {
    auto confirmed_result = [](Blockchain::CanonicalSpender spender) {
        ExactPrevoutSpender out;
        out.tx = std::move(spender.tx);
        out.confirmed = true;
        out.block_height = spender.block_height;
        out.block_hash = spender.block_hash;
        return out;
    };

    if (auto canonical = chain.GetCanonicalSpender(prev_txid, vout))
        return confirmed_result(std::move(*canonical));

    std::forward<AfterFirstCanonicalMiss>(after_first_canonical_miss)();
    auto pending = mempool.GetSpender(prev_txid, vout);

    if (auto canonical = chain.GetCanonicalSpender(prev_txid, vout))
        return confirmed_result(std::move(*canonical));

    if (!pending)
        return std::nullopt;
    ExactPrevoutSpender out;
    out.tx = std::move(*pending);
    return out;
}

inline std::optional<ExactPrevoutSpender> ResolveExactPrevoutSpender(const Blockchain& chain,
                                                                     const Mempool& mempool,
                                                                     const Hash256& prev_txid,
                                                                     uint32_t vout) {
    return ResolveExactPrevoutSpender(chain, mempool, prev_txid, vout, [] {});
}

struct ValidatorEndorsementTarget {
    uint64_t height{0};
    Hash256 hash{};
};

// Extract the exact target from the canonical endorsement marker emitted by
// ValidatorRegistry::BuildEndorseOp. Once the endorsement prefix is visible,
// malformed/noncanonical pushes fail closed instead of falling back to the
// ordinary unbound sendrawtransaction path.
inline bool ExtractValidatorEndorsementTarget(const Transaction& tx,
                                              std::optional<ValidatorEndorsementTarget>& target) {
    static const std::string prefix{"VELD_VALIDATOR|ENDORSE|"};
    target.reset();
    for (const auto& output : tx.outputs) {
        const auto& script = output.script_pubkey;
        if (script.size() < 2 || script.front() != 0x6a)
            continue;
        size_t cursor = 1;
        size_t payload_size = 0;
        if (script[cursor] <= 75) {
            payload_size = script[cursor++];
        } else if (script[cursor] == 0x4c) {
            if (++cursor >= script.size())
                continue;
            payload_size = script[cursor++];
        } else if (script[cursor] == 0x4d) {
            if (cursor + 2 >= script.size())
                continue;
            ++cursor;
            payload_size = static_cast<size_t>(script[cursor]) |
                           (static_cast<size_t>(script[cursor + 1]) << 8);
            cursor += 2;
        } else {
            continue;
        }
        if (payload_size > script.size() - cursor)
            continue;
        const std::string payload(script.begin() + static_cast<ptrdiff_t>(cursor),
                                  script.begin() + static_cast<ptrdiff_t>(cursor + payload_size));
        if (payload.rfind(prefix, 0) != 0)
            continue;

        if (target || output.value != 0 || cursor + payload_size != script.size() ||
            BuildOpReturnScript(payload) != script)
            return false;
        const size_t height_end = payload.find('|', prefix.size());
        if (height_end == std::string::npos || height_end == prefix.size())
            return false;
        const size_t hash_begin = height_end + 1;
        const size_t hash_end = payload.find('|', hash_begin);
        if (hash_end == std::string::npos || hash_end - hash_begin != 64 ||
            hash_end + 1 >= payload.size() || payload.find('|', hash_end + 1) != std::string::npos)
            return false;
        ValidatorEndorsementTarget parsed;
        try {
            parsed.height = ParseCanonicalRpcU64OrThrow(
                payload.substr(prefix.size(), height_end - prefix.size()), "endorsement height");
        } catch (...) {
            return false;
        }
        const std::string hash_text = payload.substr(hash_begin, hash_end - hash_begin);
        if (!IsCanonicalRpcLowerHex(hash_text, 64))
            return false;
        parsed.hash = HexToHash(hash_text);
        target = parsed;
    }
    return true;
}

} // namespace rpc_detail

// Parse a base-10 VELD quantity without ever passing through binary floating
// point.  RPC transaction preparers sign exact base units; accepting `1junk`,
// scientific notation, or silently rounding a ninth decimal place would make
// the displayed intent differ from the transaction being authorized.
inline uint64_t ParseVeldDecimalToUnitsOrThrow(const std::string& s, const char* field,
                                               bool allow_zero) {
    if (s.empty())
        throw std::invalid_argument(std::string(field) + " is empty");

    const size_t dot = s.find('.');
    if (dot != std::string::npos && s.find('.', dot + 1) != std::string::npos)
        throw std::invalid_argument(std::string(field) +
                                    " must be a plain decimal with at most 8 places");
    const std::string whole_text = s.substr(0, dot);
    const std::string frac_text = (dot == std::string::npos) ? std::string{} : s.substr(dot + 1);
    if (whole_text.empty() || (dot != std::string::npos && frac_text.empty()) ||
        frac_text.size() > 8 || (whole_text.size() > 1 && whole_text.front() == '0')) {
        throw std::invalid_argument(std::string(field) +
                                    " must be a canonical plain decimal with at most 8 places");
    }
    const auto all_digits = [](const std::string& text) {
        return std::all_of(text.begin(), text.end(),
                           [](unsigned char c) { return c >= '0' && c <= '9'; });
    };
    if (!all_digits(whole_text) || !all_digits(frac_text))
        throw std::invalid_argument(std::string(field) +
                                    " must be a canonical plain decimal with at most 8 places");

    const uint64_t whole = ParseCanonicalRpcU64OrThrow(whole_text, field);
    if (whole > static_cast<uint64_t>(MAX_SUPPLY))
        throw std::invalid_argument(std::string(field) + " exceeds MAX_SUPPLY (" +
                                    std::to_string(MAX_SUPPLY) + " VELD)");

    uint64_t fraction = 0;
    for (char c : frac_text)
        fraction = fraction * 10 + static_cast<uint64_t>(c - '0');
    for (size_t i = frac_text.size(); i < 8; ++i)
        fraction *= 10;
    if (whole == static_cast<uint64_t>(MAX_SUPPLY) && fraction != 0)
        throw std::invalid_argument(std::string(field) + " exceeds MAX_SUPPLY (" +
                                    std::to_string(MAX_SUPPLY) + " VELD)");

    const uint64_t units = whole * static_cast<uint64_t>(VELD_UNITS) + fraction;
    if (!allow_zero && units == 0)
        throw std::invalid_argument(std::string(field) +
                                    " must be at least one base unit (0.00000001 VELD)");
    return units;
}

inline uint64_t ParseAmountVeldToUnitsOrThrow(const std::string& s, const char* field = "Amount") {
    return ParseVeldDecimalToUnitsOrThrow(s, field, false);
}

class JsonBuilder {
  public:
    static std::string String(const std::string& s) {
        return "\"" + EscapeString(s) + "\"";
    }
    static std::string Number(uint64_t n) {
        return std::to_string(n);
    }
    static std::string Number(int64_t n) {
        return std::to_string(n);
    }
    static std::string Float(double d, int precision = 8) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(precision) << d;
        return oss.str();
    }
    static std::string Bool(bool b) {
        return b ? "true" : "false";
    }
    static std::string Null() {
        return "null";
    }

    static std::string Object(const std::vector<std::pair<std::string, std::string>>& fields) {
        std::string result = "{";
        for (size_t i = 0; i < fields.size(); ++i) {
            if (i > 0)
                result += ",";
            result += "\"" + fields[i].first + "\":" + fields[i].second;
        }
        result += "}";
        return result;
    }

    static std::string Array(const std::vector<std::string>& items) {
        std::string result = "[";
        for (size_t i = 0; i < items.size(); ++i) {
            if (i > 0)
                result += ",";
            result += items[i];
        }
        result += "]";
        return result;
    }

    static std::string NormalizeId(const std::string& id) {
        return id.empty() ? std::string("null") : id;
    }

    static std::string RpcResponse(const std::string& id, const std::string& result) {
        return Object({{"jsonrpc", String("2.0")},
                       {"id", NormalizeId(id)},
                       {"result", result},
                       {"error", Null()}});
    }

    static std::string RpcError(const std::string& id, int code, const std::string& message) {
        return Object(
            {{"jsonrpc", String("2.0")},
             {"id", NormalizeId(id)},
             {"result", Null()},
             {"error", Object({{"code", Number((int64_t)code)}, {"message", String(message)}})}});
    }

  private:
    static std::string EscapeString(const std::string& s) {
        static const char hex[] = "0123456789abcdef";
        std::string result;
        result.reserve(s.size() + 8);
        for (unsigned char c : s) {
            switch (c) {
            case '"':
                result += "\\\"";
                break;
            case '\\':
                result += "\\\\";
                break;
            case '\n':
                result += "\\n";
                break;
            case '\r':
                result += "\\r";
                break;
            case '\t':
                result += "\\t";
                break;
            case '\b':
                result += "\\b";
                break;
            case '\f':
                result += "\\f";
                break;
            case '/':
                result += "\\/";
                break;
            case '<':
                result += "\\u003c";
                break;
            case '>':
                result += "\\u003e";
                break;
            case '&':
                result += "\\u0026";
                break;
            default:
                if (c < 0x20) {
                    result += "\\u00";
                    result += hex[(c >> 4) & 0xF];
                    result += hex[c & 0xF];
                } else {
                    result += (char)c;
                }
            }
        }
        return result;
    }
};

class rpc_error : public std::runtime_error {
  public:
    rpc_error(int code, const std::string& message) : std::runtime_error(message), code_(code) {}
    int code() const noexcept {
        return code_;
    }

  private:
    int code_;
};

struct RpcRequest {
    std::string id;
    std::string method;
    std::vector<std::string> params;

    static RpcRequest Parse(const std::string& json) {
        RpcRequest req;
        auto fail = [&]() {
            req.id.clear();
            req.method = "__parse_error__";
            req.params.clear();
            return req;
        };

        btc_buy::JsonValue root;
        std::string error;
        btc_buy::StrictJsonParser parser(json, 4u * 1024u * 1024u, true);
        if (!parser.Parse(root, error) || root.kind != btc_buy::JsonValue::Kind::Object)
            return fail();

        const auto* version = root.Get("jsonrpc");
        if (version &&
            (version->kind != btc_buy::JsonValue::Kind::String || version->text != "2.0"))
            return fail();

        const auto* id = root.Get("id");
        if (id) {
            switch (id->kind) {
            case btc_buy::JsonValue::Kind::Null:
                req.id = "null";
                break;
            case btc_buy::JsonValue::Kind::Number:
                req.id = id->text;
                break;
            case btc_buy::JsonValue::Kind::String:
                req.id = JsonBuilder::String(id->text);
                break;
            default:
                return fail();
            }
        }

        const auto* method = root.Get("method");
        if (!method || method->kind != btc_buy::JsonValue::Kind::String || method->text.empty() ||
            method->string_had_escape)
            return fail();
        for (unsigned char c : method->text) {
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
                return fail();
        }
        req.method = method->text;

        const auto* params = root.Get("params");
        if (!params)
            return req;
        if (params->kind != btc_buy::JsonValue::Kind::Array)
            return fail();
        req.params.reserve(params->array.size());
        for (const auto& param : params->array) {
            switch (param.kind) {
            case btc_buy::JsonValue::Kind::Null:
                req.params.emplace_back("null");
                break;
            case btc_buy::JsonValue::Kind::Bool:
                req.params.emplace_back(param.boolean ? "true" : "false");
                break;
            case btc_buy::JsonValue::Kind::Number:
                req.params.push_back(param.text);
                break;
            case btc_buy::JsonValue::Kind::String:
                req.params.push_back(param.text);
                break;
            default:
                return fail();
            }
        }
        return req;
    }

  private:
    static RpcRequest ParseLegacy(const std::string& json) {
        RpcRequest req;
        req.id = "";

        if (json.size() > 4u * 1024u * 1024u) {
            req.method = "__parse_error__";
            return req;
        }

        // Step 1 — locate the top-level field key positions in a single
        // pass. We only honour matches that occur at depth == 1 (i.e.
        // the outer object) and that are NOT inside a string value.
        struct FieldPos {
            size_t key_end = std::string::npos;
            size_t value_start = std::string::npos;
        };
        FieldPos id_field, method_field, params_field;
        bool in_string = false;
        int depth = 0;
        auto skip_string = [&](size_t p) -> size_t {
            ++p;
            while (p < json.size()) {
                char c = json[p];
                if (c == '\\') {
                    p += 2;
                    continue;
                }
                if (c == '"')
                    return p + 1;
                ++p;
            }
            return std::string::npos;
        };
        auto try_match = [&](const char* key, size_t klen, size_t key_pos, FieldPos& slot) {
            if (key_pos + 1 + klen + 1 > json.size())
                return false;
            if (json[key_pos] != '"' || json[key_pos + 1 + klen] != '"')
                return false;
            if (std::memcmp(json.data() + key_pos + 1, key, klen) != 0)
                return false;
            size_t after = key_pos + klen + 2;
            while (after < json.size() && std::isspace((unsigned char)json[after]))
                ++after;
            if (after >= json.size() || json[after] != ':')
                return false;
            ++after;
            while (after < json.size() && std::isspace((unsigned char)json[after]))
                ++after;
            slot.key_end = key_pos + klen + 2;
            slot.value_start = after;
            return true;
        };
        for (size_t p = 0; p < json.size();) {
            char c = json[p];
            if (in_string) {
                if (c == '\\' && p + 1 < json.size()) {
                    p += 2;
                    continue;
                }
                if (c == '"')
                    in_string = false;
                ++p;
                continue;
            }
            if (c == '"') {
                size_t string_end = skip_string(p);
                if (string_end == std::string::npos)
                    break;
                if (depth == 1) {
                    if (id_field.key_end == std::string::npos && try_match("id", 2, p, id_field)) {
                    } else if (method_field.key_end == std::string::npos &&
                               try_match("method", 6, p, method_field)) {
                    } else if (params_field.key_end == std::string::npos &&
                               try_match("params", 6, p, params_field)) {
                    }
                }
                p = string_end;
                continue;
            }
            if (c == '{' || c == '[') {
                ++depth;
                ++p;
                continue;
            }
            if (c == '}' || c == ']') {
                --depth;
                ++p;
                continue;
            }
            ++p;
        }

        auto read_scalar_or_string = [&](size_t value_start) -> std::string {
            if (value_start >= json.size())
                return "";
            if (json[value_start] == '"') {
                size_t end = skip_string(value_start);
                if (end == std::string::npos)
                    return "";
                return json.substr(value_start + 1, end - value_start - 2);
            }
            size_t end = value_start;
            int local_depth = 0;
            bool ls = false;
            while (end < json.size()) {
                char c = json[end];
                if (ls) {
                    if (c == '\\' && end + 1 < json.size()) {
                        end += 2;
                        continue;
                    }
                    if (c == '"')
                        ls = false;
                    ++end;
                    continue;
                }
                if (c == '"') {
                    ls = true;
                    ++end;
                    continue;
                }
                if (c == '{' || c == '[')
                    ++local_depth;
                else if (c == '}' || c == ']') {
                    if (local_depth == 0)
                        break;
                    --local_depth;
                } else if ((c == ',') && local_depth == 0)
                    break;
                ++end;
            }
            std::string val = json.substr(value_start, end - value_start);
            while (!val.empty() && std::isspace((unsigned char)val.back()))
                val.pop_back();
            return val;
        };
        if (id_field.value_start != std::string::npos) {
            size_t vs = id_field.value_start;
            if (vs < json.size() && json[vs] == '"') {
                size_t end = skip_string(vs);
                if (end != std::string::npos) {
                    req.id = json.substr(vs, end - vs);
                }
            } else {
                req.id = read_scalar_or_string(vs);
            }
        }
        if (method_field.value_start != std::string::npos)
            req.method = read_scalar_or_string(method_field.value_start);

        if (params_field.value_start != std::string::npos &&
            params_field.value_start < json.size() && json[params_field.value_start] == '[') {
            size_t bracket = params_field.value_start;
            int local_depth = 0;
            bool ls = false;
            size_t close = std::string::npos;
            for (size_t i = bracket; i < json.size(); ++i) {
                char c = json[i];
                if (ls) {
                    if (c == '\\' && i + 1 < json.size()) {
                        ++i;
                        continue;
                    }
                    if (c == '"')
                        ls = false;
                    continue;
                }
                if (c == '"') {
                    ls = true;
                    continue;
                }
                if (c == '[' || c == '{')
                    ++local_depth;
                else if (c == ']' || c == '}') {
                    --local_depth;
                    if (local_depth == 0) {
                        close = i;
                        break;
                    }
                }
            }
            if (close != std::string::npos) {
                std::string params_str = json.substr(bracket + 1, close - bracket - 1);
                size_t p = 0;
                while (p < params_str.size()) {
                    while (p < params_str.size() &&
                           (std::isspace((unsigned char)params_str[p]) || params_str[p] == ','))
                        ++p;
                    if (p >= params_str.size())
                        break;
                    if (params_str[p] == '"') {
                        ++p;
                        size_t end = p;
                        while (end < params_str.size() && params_str[end] != '"') {
                            if (params_str[end] == '\\')
                                ++end;
                            ++end;
                        }
                        req.params.push_back(params_str.substr(p, end - p));
                        p = end + 1;
                    } else if (params_str[p] == '{' || params_str[p] == '[') {
                        int d = 1;
                        char open_c = params_str[p], close_c = (open_c == '{') ? '}' : ']';
                        ++p;
                        while (p < params_str.size() && d > 0) {
                            if (params_str[p] == open_c)
                                ++d;
                            if (params_str[p] == close_c)
                                --d;
                            ++p;
                        }
                    } else {
                        size_t end = p;
                        while (end < params_str.size() && params_str[end] != ',' &&
                               params_str[end] != ']' &&
                               !std::isspace((unsigned char)params_str[end]))
                            ++end;
                        req.params.push_back(params_str.substr(p, end - p));
                        p = end;
                    }
                }
            }
        }

        return req;
    }
};

inline std::string DiagnoseFeeSelectFailed(const Blockchain& chain, const Mempool& mempool,
                                           const std::vector<uint8_t>& script, uint64_t fee) {
    auto utxos = chain.GetUTXOsForScript(script);
    auto spent = mempool.GetSpentOutputs();
    uint64_t tip = chain.Height();
    uint64_t mature_unspent = 0;
    uint64_t immature_coinbase = 0;
    uint64_t mempool_locked = 0;
    uint64_t earliest_mature_h = UINT64_MAX;
    for (const auto& u : utxos) {
        std::string ukey = HashToHex(u.tx_hash) + ":" + std::to_string(u.output_index);
        if (spent.count(ukey)) {
            mempool_locked += u.value;
            continue;
        }
        const bool enforce_mat = (tip + 1) >= COINBASE_MATURITY_CONSENSUS_HEIGHT;
        if (enforce_mat && u.is_coinbase && u.block_height <= tip &&
            (tip - u.block_height) < COINBASE_MATURITY) {
            immature_coinbase += u.value;
            uint64_t mat_h = u.block_height + COINBASE_MATURITY;
            if (mat_h < earliest_mature_h)
                earliest_mature_h = mat_h;
        } else {
            mature_unspent += u.value;
        }
    }
    std::ostringstream os;
    if (immature_coinbase > 0 && mature_unspent == 0 && mempool_locked == 0) {
        uint64_t bu = (earliest_mature_h > tip) ? (earliest_mature_h - tip) : 0;
        os << "Your balance is still maturing - you have no spendable VELD yet to "
              "cover the fee. Mining rewards unlock after "
           << COINBASE_MATURITY << " confirmations; yours start unlocking at block "
           << earliest_mature_h << " (~" << bu << " blocks away). "
           << ((double)immature_coinbase / VELD_UNITS) << " VELD maturing.";
        return os.str();
    }
    if (mempool_locked > 0 && mature_unspent == 0) {
        os << "A previous transaction from this address is still pending in "
              "the mempool (locks "
           << ((double)mempool_locked / VELD_UNITS) << " VELD). Wait for the next block (target ~"
           << TARGET_BLOCK_TIME << " seconds), then try again.";
        return os.str();
    }
    os << "Insufficient mature balance to fund the " << ((double)fee / VELD_UNITS)
       << " VELD fee. Mature: " << ((double)mature_unspent / VELD_UNITS)
       << " VELD; immature coinbase: " << ((double)immature_coinbase / VELD_UNITS)
       << " VELD; mempool-locked: " << ((double)mempool_locked / VELD_UNITS) << " VELD.";
    return os.str();
}

class RpcServer {
  public:
    using TxBroadcastFn = std::function<void(const Transaction&)>;
    using BlockBroadcastFn = std::function<void(const Block&)>;
    using PeerCountFn = std::function<size_t()>;
    using PeerInfoFn = std::function<std::string()>;
    using TokenSaveFn = std::function<void()>;
    using MiningTemplatePreflightFn = std::function<bool(const Block&)>;
    using RuntimeAdmissionFn = std::function<bool()>;
    using WorkAdmissionFn = std::function<work_admission::Decision(
        work_admission::Path, const work_admission::Subject&,
        const std::optional<work_admission::Binding>&, bool)>;
    struct BlockTemplateAuthorizationResult {
        work_admission::Decision decision{};
        std::string token;
        uint64_t ttl_ms{0};
    };
    using IssueBlockTemplateAuthorizationFn = std::function<BlockTemplateAuthorizationResult(
        const work_admission::Subject&, const Hash256&)>;
    using ConsumeBlockTemplateAuthorizationFn =
        std::function<std::shared_ptr<work_admission::BlockTemplateAuthorizationClaim>(
            const std::string&, const work_admission::Binding&)>;
    struct RemoteWorkGrantResult {
        work_admission::Decision decision{};
        std::string token;
        uint64_t ttl_ms{0};
    };
    using RemoteWorkGrantFn =
        std::function<RemoteWorkGrantResult(work_admission::Path, const work_admission::Subject&)>;
    struct RemoteSigningActivationResult {
        bool started{false};
        bool deferred{false};
        uint64_t ttl_ms{0};
        std::string reason;
    };
    using BeginRemoteSigningFn = std::function<RemoteSigningActivationResult(
        work_admission::Path, const std::string&, const std::string&)>;
    using CancelRemoteSigningFn = std::function<bool(const std::string&)>;
    struct AuthorizedWorkTxResult {
        bool accepted{false};
        bool deferred{false};
        std::string reason;
    };
    using ValidatorEndorsementSinkFn = std::function<AuthorizedWorkTxResult(
        const Transaction&, uint64_t, const std::string&, const std::string&, bool)>;
    struct GenerateResult {
        uint64_t generated = 0;
        uint64_t height = 0;
        std::string error;
    };
    using GenerateFn = std::function<GenerateResult(int)>;
    using FinalityEvidenceSummary = ::veld::finality::qc::FinalityEquivocationCollector::Summary;
    using FinalityEvidence = ::veld::finality::qc::ValidatedEquivocationEvidence;

    RpcServer(Blockchain& chain, Mempool& mempool, StorageEngine& storage)
        : chain_(chain), mempool_(mempool), storage_(storage), tiers_(nullptr), vault_(nullptr),
          gov_(nullptr), staking_(nullptr), onchain_tokens_(nullptr), validators_(nullptr),
          token_op_cb_(nullptr) {
        RegisterMethods();
    }

    uint64_t GetReservedStake(const std::string& address) {
        std::lock_guard<std::recursive_mutex> lk(stake_reserve_mutex_);
        auto now = std::chrono::steady_clock::now();
        auto ex_it = stake_reserve_expiry_.find(address);
        if (ex_it != stake_reserve_expiry_.end() &&
            now - ex_it->second > std::chrono::seconds(10)) {
            stake_reserve_units_.erase(address);
            stake_reserve_expiry_.erase(ex_it);
        }
        auto it = stake_reserve_units_.find(address);
        return (it != stake_reserve_units_.end()) ? it->second : 0;
    }

    static constexpr size_t MAX_STAKE_RESERVATIONS = 50000;

    void AddStakeReservation(const std::string& address, uint64_t units) {
        std::lock_guard<std::recursive_mutex> lk(stake_reserve_mutex_);
        auto it = stake_reserve_units_.find(address);
        if (it == stake_reserve_units_.end() &&
            stake_reserve_units_.size() >= MAX_STAKE_RESERVATIONS) {
            return;
        }
        stake_reserve_units_[address] += units;
        stake_reserve_expiry_[address] = std::chrono::steady_clock::now();
    }

    void ClearStakeReservation(const std::string& address) {
        std::lock_guard<std::recursive_mutex> lk(stake_reserve_mutex_);
        stake_reserve_units_.erase(address);
        stake_reserve_expiry_.erase(address);
    }

    bool TryReserveStakeAtomic(const std::string& address, uint64_t units,
                               uint64_t pending_in_mempool, uint64_t* out_pending,
                               uint64_t* out_reserved) {
        std::lock_guard<std::recursive_mutex> lk(stake_reserve_mutex_);
        auto now = std::chrono::steady_clock::now();
        uint64_t pending_live = mempool_.GetPendingStakeUnits(address);
        (void)pending_in_mempool;
        for (auto it = stake_reserve_expiry_.begin(); it != stake_reserve_expiry_.end();) {
            if (now - it->second > std::chrono::seconds(10)) {
                stake_reserve_units_.erase(it->first);
                it = stake_reserve_expiry_.erase(it);
            } else {
                ++it;
            }
        }
        uint64_t reserved = 0;
        auto it = stake_reserve_units_.find(address);
        if (it != stake_reserve_units_.end())
            reserved = it->second;

        if (pending_live == 0 && reserved > 0) {
            auto ex_it = stake_reserve_expiry_.find(address);
            if (ex_it != stake_reserve_expiry_.end() &&
                (now - ex_it->second) > std::chrono::seconds(3)) {
                stake_reserve_units_.erase(address);
                stake_reserve_expiry_.erase(address);
                reserved = 0;
            }
        }
        if (out_pending)
            *out_pending = pending_live;
        if (out_reserved)
            *out_reserved = reserved;
        if (pending_live > 0)
            return false;
        if (reserved > 0)
            return false;
        if (stake_reserve_units_.size() >= MAX_STAKE_RESERVATIONS)
            return false;
        stake_reserve_units_[address] += units;
        stake_reserve_expiry_[address] = now;
        return true;
    }

    void SetTxBroadcast(TxBroadcastFn fn) {
        tx_broadcast_ = fn;
    }
    void SetBlockBroadcast(BlockBroadcastFn fn) {
        block_broadcast_ = std::move(fn);
    }
    void SetPeerCount(PeerCountFn fn) {
        peer_count_ = fn;
    }
    void SetPeerInfo(PeerInfoFn fn) {
        peer_info_ = fn;
    }
    void SetDataDir(const std::string& d) {
        datadir_ = d;
    }
    void SetTokenSave(TokenSaveFn fn) {
        token_save_ = fn;
    }
    // The node supplies the exact same all-module dry run used by MineOnly.
    // getblocktemplate invokes it while already holding Blockchain's consensus
    // transition guard, so the callback must not acquire that guard recursively.
    void SetMiningTemplatePreflightFn(MiningTemplatePreflightFn fn) {
        mining_template_preflight_fn_ = std::move(fn);
    }
    void SetWorkAdmissionFn(WorkAdmissionFn fn) {
        work_admission_fn_ = std::move(fn);
    }
    void SetIssueBlockTemplateAuthorizationFn(IssueBlockTemplateAuthorizationFn fn) {
        issue_block_template_authorization_fn_ = std::move(fn);
    }
    void SetConsumeBlockTemplateAuthorizationFn(ConsumeBlockTemplateAuthorizationFn fn) {
        consume_block_template_authorization_fn_ = std::move(fn);
    }
    void SetRemoteWorkGrantFn(RemoteWorkGrantFn fn) {
        remote_work_grant_fn_ = std::move(fn);
    }
    void SetBeginRemoteSigningFn(BeginRemoteSigningFn fn) {
        begin_remote_signing_fn_ = std::move(fn);
    }
    void SetCancelRemoteSigningFn(CancelRemoteSigningFn fn) {
        cancel_remote_signing_fn_ = std::move(fn);
    }
    void SetValidatorEndorsementSinkFn(ValidatorEndorsementSinkFn fn) {
        validator_endorsement_sink_fn_ = std::move(fn);
    }
    // Optional process-level lease installed before listeners start.  It lives
    // inside RpcServer rather than only in a VeldNode wrapper because the node
    // HTTP listener and the in-process desktop UI both dispatch through
    // RpcServer::Handle directly.  An unwired server (including public mainnet)
    // preserves the existing behavior.  Any callback exception fails closed.
    void SetRuntimeAdmissionFn(RuntimeAdmissionFn fn, std::string refusal_message) {
        runtime_admission_fn_ = std::move(fn);
        runtime_admission_refusal_ = std::move(refusal_message);
    }
    void SetTierEngine(TierEngine* t) {
        tiers_ = t;
    }
    void SetStaking(StakingLedger* s) {
        staking_ = s;
    }
    StakingLedger* GetStaking() const {
        return staking_;
    }

    struct WalletState {
        uint64_t total_units = 0;
        uint64_t immature_coinbase_units = 0;
        uint64_t staked_units = 0;
        uint64_t active_stake_backing_units = 0;
        uint64_t pending_out_units = 0;
        uint64_t pending_in_units = 0;
        uint64_t spendable_units = 0;
        bool stake_backing_consistent = true;
        std::vector<UTXO> selectable;
        std::vector<UTXO> pending_out_utxos;
    };

    WalletState ComputeWalletState(const std::string& addr) const {
        WalletState w;
        auto script = AddressToScript(addr);
        if (script.empty())
            return w;
        const uint64_t tip = chain_.Height();
        auto utxos = chain_.GetUTXOsForScript(script);
        auto mempool_spent = mempool_.GetSpentOutputs();
        w.staked_units = staking_ ? staking_->GetStake(addr) : 0;

        const bool exact_stake_backing = StakeOutpointBackingActive(tip);
        std::unordered_set<std::string> active_backing_outpoints;
        std::unordered_map<std::string, uint64_t> expected_backing_values;
        uint64_t expected_backing_units = 0;
        if (exact_stake_backing) {
            if (!staking_)
                throw std::runtime_error(
                    "Wallet stake backing state is unavailable; refusing wallet accounting");
            active_backing_outpoints = staking_->GetActiveBackingOutpoints();
            for (const auto& record : staking_->GetStakeRecords(addr)) {
                if (!record.active)
                    continue;
                if (record.address != addr || record.amount_units == 0 ||
                    HashIsZero(record.backing_txid) || record.backing_vout == UINT32_MAX) {
                    w.stake_backing_consistent = false;
                    continue;
                }
                const std::string key = UTXOKey(record.backing_txid, record.backing_vout);
                if (!active_backing_outpoints.count(key) ||
                    !expected_backing_values.emplace(key, record.amount_units).second ||
                    expected_backing_units > UINT64_MAX - record.amount_units) {
                    w.stake_backing_consistent = false;
                    continue;
                }
                expected_backing_units += record.amount_units;
            }
            if (expected_backing_units != w.staked_units)
                w.stake_backing_consistent = false;
        }

        std::unordered_set<std::string> observed_expected_backings;

        for (const auto& u : utxos) {
            w.total_units += u.value;
            const std::string key = UTXOKey(u.tx_hash, u.output_index);
            const bool active_backing =
                exact_stake_backing && active_backing_outpoints.count(key) > 0;
            if (active_backing) {
                if (w.active_stake_backing_units > UINT64_MAX - u.value) {
                    w.stake_backing_consistent = false;
                } else {
                    w.active_stake_backing_units += u.value;
                }
                const auto expected = expected_backing_values.find(key);
                if (expected == expected_backing_values.end() || expected->second != u.value ||
                    !observed_expected_backings.insert(key).second) {
                    w.stake_backing_consistent = false;
                }
            }
            const bool immature =
                u.is_coinbase && u.block_height >= COINBASE_MATURITY_ACTIVATES_AT_HEIGHT &&
                tip >= COINBASE_MATURITY_ACTIVATES_AT_HEIGHT && u.block_height <= tip &&
                (tip - u.block_height) < COINBASE_MATURITY;
            const bool locked = mempool_spent.count(key) > 0;
            if (immature)
                w.immature_coinbase_units += u.value;
            if (locked) {
                w.pending_out_units += u.value;
                w.pending_out_utxos.push_back(u);
            }
            if (!immature && !locked && !active_backing)
                w.selectable.push_back(u);
        }
        std::sort(w.selectable.begin(), w.selectable.end(),
                  [](const UTXO& a, const UTXO& b) { return a.value > b.value; });

        uint64_t selectable_sum = 0;
        for (const auto& u : w.selectable)
            selectable_sum += u.value;
        if (exact_stake_backing) {
            if (observed_expected_backings.size() != expected_backing_values.size() ||
                w.active_stake_backing_units != w.staked_units) {
                w.stake_backing_consistent = false;
            }
            w.spendable_units = selectable_sum;
        } else {
            // Legacy logical-only stake has no exact principal outpoint to
            // exclude, so retain its aggregate reservation.  Exact-backed
            // profiles already removed every principal above and must not
            // subtract the same stake a second time.
            w.spendable_units =
                selectable_sum > w.staked_units ? selectable_sum - w.staked_units : 0;
        }

        auto pin = mempool_.GetPendingOutputsForScript(script);
        for (const auto& u : pin)
            w.pending_in_units += u.value;

        if (!w.stake_backing_consistent) {
            w.selectable.clear();
            w.spendable_units = 0;
            std::cerr << "[ComputeWalletState] STAKE BACKING INCONSISTENT addr=" << addr
                      << " staked=" << w.staked_units
                      << " expected_backing=" << expected_backing_units
                      << " observed_backing=" << w.active_stake_backing_units << "\n";
            throw std::runtime_error("Wallet stake backing is inconsistent; refusing wallet "
                                     "accounting and transaction preparation");
        }

        // ── INVARIANT GUARD ────────────────────────────────────────────
        // Bitcoin Core's wallet has exactly one balance path and asserts
        // its accounting closes. So do we. Two structural invariants must
        // hold by construction; if a future edit breaks one we want it
        // LOUD in /var/log/veld-node.log — but a money RPC must never
        // crash a node, so we log + clamp (CHECK_NONFATAL philosophy)
        // rather than throw.
        //
        //  (1) spendable_units == selectable_sum after exact active stake
        //      principals have been excluded.  Legacy logical-only profiles
        //      retain the aggregate stake reservation.
        //  (2) selectable + active backing + immature + pending_out >= total
        //      — partition soundness: every confirmed UTXO lands in a
        //      bucket. It's '>=' not '==' because a UTXO that is BOTH
        //      immature coinbase AND mempool-locked is counted in both
        //      immature_coinbase_units and pending_out_units yet excluded
        //      from selectable exactly once (double-count is expected).
        const uint64_t expect_spendable =
            exact_stake_backing
                ? selectable_sum
                : (selectable_sum > w.staked_units ? selectable_sum - w.staked_units : 0);
        if (w.spendable_units != expect_spendable) {
            std::cerr << "[ComputeWalletState] INVARIANT(1) VIOLATED addr=" << addr
                      << " spendable=" << w.spendable_units << " expected=" << expect_spendable
                      << " selectable_sum=" << selectable_sum << " staked=" << w.staked_units
                      << "\n";
            w.spendable_units = expect_spendable;
        }
        const unsigned __int128 accounted_units =
            (unsigned __int128)selectable_sum + (unsigned __int128)w.active_stake_backing_units +
            (unsigned __int128)w.immature_coinbase_units + (unsigned __int128)w.pending_out_units;
        if (accounted_units < w.total_units) {
            std::cerr << "[ComputeWalletState] INVARIANT(2) VIOLATED addr=" << addr
                      << " selectable=" << selectable_sum
                      << " active_stake_backing=" << w.active_stake_backing_units
                      << " immature=" << w.immature_coinbase_units
                      << " pending_out=" << w.pending_out_units << " total=" << w.total_units
                      << " (a confirmed UTXO escaped all buckets)\n";
        }
        return w;
    }

    std::vector<uint8_t> AuthenticatedParentRaw(const UTXO& utxo) const {
        const Block block = chain_.GetBlock(utxo.block_height);
        for (const auto& transaction : block.transactions) {
            if (transaction.GetTxID() != utxo.tx_hash)
                continue;
            if (utxo.output_index >= transaction.outputs.size())
                break;
            const auto& output = transaction.outputs[utxo.output_index];
            if (output.value != utxo.value || output.script_pubkey != utxo.script_pubkey)
                break;
            const auto raw = transaction.Serialize();
            if (raw.empty() || raw.size() > offline_signing::kMaxParentTransactionBytes)
                break;
            return raw;
        }
        throw std::runtime_error(
            "selected funding output has no authenticated canonical parent transaction");
    }

    static std::string SigningIntentJson(const offline_signing::Intent& intent) {
        return JsonBuilder::Object({
            {"version", JsonBuilder::String(intent.version)},
            {"operation_type", JsonBuilder::String(intent.operation_type)},
            {"intended_recipient", JsonBuilder::String(intent.intended_recipient)},
            {"intended_amount", JsonBuilder::Number(intent.intended_amount)},
            {"expected_change_destination",
             JsonBuilder::String(intent.expected_change_destination)},
            {"expected_change", JsonBuilder::Number(intent.expected_change)},
            {"maximum_absolute_fee", JsonBuilder::Number(intent.maximum_absolute_fee)},
            {"maximum_fee_rate", JsonBuilder::Number(intent.maximum_fee_rate)},
            {"source_transactions_digest", JsonBuilder::String(intent.source_transactions_digest)},
            {"complete_output_digest", JsonBuilder::String(intent.complete_output_digest)},
            {"operation_identity_digest", JsonBuilder::String(intent.operation_identity_digest)},
            {"intent_digest", JsonBuilder::String(intent.intent_digest)},
        });
    }
    void SetVault(VaultLedger* v) {
        vault_ = v;
    }
    void SetPoolInfoFn(std::function<std::string()> fn) {
        pool_info_fn_ = fn;
    }
    void SetMinerStatusFn(std::function<std::string()> fn) {
        miner_status_fn_ = std::move(fn);
    }
    void SetFlushTriggerFn(std::function<std::string(bool)> fn) {
        flush_trigger_fn_ = fn;
    }
    void SetIBDCompleteFn(std::function<bool()> fn) {
        ibd_complete_fn_ = fn;
    }
    void SetTxIndexEnabledFn(std::function<bool()> fn) {
        txindex_enabled_fn_ = std::move(fn);
    }
    void SetTxIndexLookupFn(std::function<std::optional<uint64_t>(const std::string&)> fn) {
        txindex_lookup_fn_ = std::move(fn);
    }
    void SetAddressHistoryFn(
        std::function<std::string(const std::string&, size_t, const std::string&)> fn) {
        address_history_fn_ = std::move(fn);
    }
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    void SetDumpSnapshotFn(std::function<std::string(const std::string&)> fn) {
        dump_snapshot_fn_ = fn;
    }
#endif
    void SetClearMiningHaltFn(std::function<std::string()> fn) {
        clear_mining_halt_fn_ = std::move(fn);
    }
    void SetInvalidateBlockFn(std::function<std::string(const Hash256&)> fn) {
        invalidate_block_fn_ = std::move(fn);
    }
    void SetReconsiderBlockFn(std::function<std::string(const Hash256&)> fn) {
        reconsider_block_fn_ = std::move(fn);
    }
    void SetClearRejectCacheFn(std::function<size_t()> fn) {
        clear_reject_cache_fn_ = std::move(fn);
    }
    void SetClearOrphanPoolFn(std::function<size_t()> fn) {
        clear_orphan_pool_fn_ = std::move(fn);
    }
    void SetClearBadAltTipsFn(std::function<size_t()> fn) {
        clear_bad_alt_tips_fn_ = std::move(fn);
    }
    void SetGovernance(GovernanceEngine* g) {
        gov_ = g;
    }
    void SetOnChainTokens(OnChainTokenLedger* t) {
        onchain_tokens_ = t;
    }
    void SetAmm(AmmLedger* a) {
        amm_ = a;
    }
    void SetValidators(ValidatorRegistry* v) {
        validators_ = v;
    }
    void SetTokenOpCallback(std::function<void(const TokenOpData&)> cb) {
        token_op_cb_ = cb;
    }
    void SetFinalHeightFn(std::function<uint64_t()> fn) {
        final_height_fn_ = std::move(fn);
    }
    void SetBtcVeldPegStatusFn(std::function<BtcVeldPegStatus()> fn) {
        btcveld_peg_status_fn_ = std::move(fn);
    }
    void SetBtcVeldRedeemPageFn(std::function<std::string(const std::vector<std::string>&)> fn) {
        btcveld_redeem_page_fn_ = std::move(fn);
    }
    void SetBtcVeldSupplySnapshotFn(std::function<std::string()> fn) {
        btcveld_supply_snapshot_fn_ = std::move(fn);
    }
    void SetBtcVeldMintProofFn(std::function<BtcVeldMintProofStatus(const std::string&)> fn) {
        btcveld_mint_proof_fn_ = std::move(fn);
    }
    // btcVELD relay: the node's in-consensus BTC-header view (best height/tip), snapshotted
    // race-free by the block thread. Returns a JSON string; unwired => dormant semantics.
    void SetBtcHeaderInfoFn(std::function<std::string()> fn) {
        btc_header_info_fn_ = std::move(fn);
    }
    void SetBtcHeaderDigestFn(std::function<Hash256()> fn) {
        btc_header_digest_fn_ = std::move(fn);
    }
    // Regtest-only block generator (bitcoin-style `generate`); wired by the node ONLY on
    // the "Veld Regtest" network, so it stays unwired (=> error) on testnet/mainnet binaries.
    void SetGenerateFn(GenerateFn fn) {
        generate_fn_ = std::move(fn);
    }
    // btcVELD Layer-2 anchor-set summary (high-water anchored Veld height); JSON string.
    void SetAnchorInfoFn(std::function<std::string()> fn) {
        anchor_info_fn_ = std::move(fn);
    }
    void SetAnchorDigestFn(std::function<Hash256()> fn) {
        anchor_digest_fn_ = std::move(fn);
    }
    void SetFinalityDigestFn(std::function<Hash256()> fn) {
        finality_digest_fn_ = std::move(fn);
    }
    // Serves a retained finality epoch snapshot to validator daemons as JSON.
    // A daemon needs the frozen set (epoch id, set root, the ordered member
    // commitments) to know whether it is a member and to bind its votes. The
    // node owns the snapshot; this is the read surface. Returns "" when no
    // snapshot is retained (finality warm-up not begun).
    void SetFinalitySnapshotFn(std::function<std::string(std::optional<uint64_t>)> fn) {
        finality_snapshot_fn_ = std::move(fn);
    }
    // Accepts a gossiped finality vote from a daemon and relays it to the
    // assembler pool. Returns true if the vote verified and was stored. The
    // node owns the pool; this is the write surface.
    void SetFinalityVoteSink(
        std::function<bool(const std::string&, const std::string&, const std::string&)> fn) {
        finality_vote_sink_ = std::move(fn);
    }
    void SetFinalityQcFn(std::function<std::string(uint8_t)> fn) {
        finality_qc_fn_ = std::move(fn);
    }
    void SetFinalityEvidenceListFn(
        std::function<std::vector<FinalityEvidenceSummary>(size_t, size_t)> fn) {
        finality_evidence_list_fn_ = std::move(fn);
    }
    void
    SetFinalityEvidenceFindFn(std::function<std::optional<FinalityEvidence>(const Hash256&)> fn) {
        finality_evidence_find_fn_ = std::move(fn);
    }
    void SetFinalitySlashPrepareFn(std::function<std::optional<std::string>(const Hash256&)> fn) {
        finality_slash_prepare_fn_ = std::move(fn);
    }
    void SetRedeemBondDigestFn(std::function<Hash256()> fn) {
        redeem_bond_digest_fn_ = std::move(fn);
    }
    // The module replay cursor is node-owned derived state.  It is not another
    // digest domain, but a stale cursor changes whether the next canonical block
    // is accepted.  getstatedigest therefore refuses to publish a seemingly
    // healthy measurement unless the cursor matches the guarded chain snapshot.
    void SetModuleCursorFn(std::function<std::pair<uint64_t, uint64_t>()> fn) {
        module_cursor_fn_ = std::move(fn);
    }
    // Historical validation progress for independent snapshot IBD or an
    // explicit local PoW diagnostic.
    void SetPowVerifyStatusFn(std::function<std::string()> fn) {
        pow_verify_status_fn_ = std::move(fn);
    }

    std::string Handle(const std::string& request_json) {
        RpcRequest req = RpcRequest::Parse(request_json);

        if (req.method == "__parse_error__") {
            return JsonBuilder::RpcError(
                req.id, -32700, "Parse error: request must be one complete JSON-RPC object");
        }

        if (runtime_admission_fn_) {
            bool admitted = false;
            try {
                admitted = runtime_admission_fn_();
            } catch (...) {
                admitted = false;
            }
            if (!admitted) {
                return JsonBuilder::RpcError(req.id, -32603,
                                             runtime_admission_refusal_.empty()
                                                 ? "Runtime admission is closed"
                                                 : runtime_admission_refusal_);
            }
        }

        auto it = methods_.find(req.method);
        if (it == methods_.end()) {
            return JsonBuilder::RpcError(req.id, -32601, "Method not found: " + req.method);
        }

        try {
            std::string result = it->second(req.params);
            return JsonBuilder::RpcResponse(req.id, result);
        } catch (const rpc_error& e) {
            return JsonBuilder::RpcError(req.id, e.code(), SanitizeErrorMessage(e.what()));
        } catch (const std::invalid_argument& e) {
            return JsonBuilder::RpcError(req.id, -32602, SanitizeErrorMessage(e.what()));
        } catch (const std::exception& e) {
            return JsonBuilder::RpcError(req.id, -32603, SanitizeErrorMessage(e.what()));
        } catch (...) {
            return JsonBuilder::RpcError(req.id, -32603, "Unknown internal error");
        }
    }

    static std::string SanitizeErrorMessage(const std::string& msg) {
        std::string out = msg;
        static const char* posix_pfx[] = {"/var/", "/home/", "/tmp/", "/etc/", "/root/", "/opt/"};
        for (const char* pfx : posix_pfx) {
            size_t p = 0;
            while ((p = out.find(pfx, p)) != std::string::npos) {
                size_t end = p;
                while (end < out.size() && !std::isspace((unsigned char)out[end]))
                    ++end;
                out.replace(p, end - p, "<datadir>");
                p += 9;
            }
        }
        for (size_t i = 0; i + 2 < out.size();) {
            char c0 = out[i], c1 = out[i + 1], c2 = out[i + 2];
            bool is_drive = ((c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z')) && c1 == ':' &&
                            (c2 == '\\' || c2 == '/');
            if (!is_drive) {
                ++i;
                continue;
            }
            size_t end = i;
            while (end < out.size() && !std::isspace((unsigned char)out[end]))
                ++end;
            out.replace(i, end - i, "<datadir>");
            i += 9;
        }
        return out;
    }

    std::vector<std::string> GetMethods() const {
        std::vector<std::string> names;
        for (const auto& [name, _] : methods_)
            names.push_back(name);
        std::sort(names.begin(), names.end());
        return names;
    }

  private:
    static CoinSelection SelectWalletStateCoins_(const WalletState& state, uint64_t target_units,
                                                 uint64_t fee_units) {
        CoinSelection result;
        if (!state.stake_backing_consistent || target_units > UINT64_MAX - fee_units)
            return result;
        const uint64_t needed = target_units + fee_units;
        uint64_t accumulated = 0;
        for (const auto& utxo : state.selectable) {
            if (accumulated > UINT64_MAX - utxo.value)
                return CoinSelection{};
            result.selected_utxos.push_back(utxo);
            accumulated += utxo.value;
            if (accumulated >= needed)
                break;
        }
        if (accumulated < needed)
            return CoinSelection{};
        result.total_input = accumulated;
        result.change_amount = accumulated - needed;
        result.sufficient = true;
        return result;
    }

    CoinSelection SelectWalletCoins_(const std::string& address, uint64_t target_units,
                                     uint64_t fee_units) const {
        return SelectWalletStateCoins_(ComputeWalletState(address), target_units, fee_units);
    }

    enum class BtcVeldPegOperation {
        MINT,
        COMPLETION,
        REDEEM,
        AMM,
    };

    // Transaction preparers are an authorization surface, not merely a UX
    // convenience.  Consult the node-owned, next-candidate consensus frame on
    // every call and fail closed when that frame is unavailable.  Consensus
    // and mempool admission still re-check the operation, but this prevents an
    // RPC client from being handed a signable transaction while its specific
    // launch/liveness permission is closed.
    void RequireAuthoritativeBtcVeldPegPermission_(BtcVeldPegOperation operation,
                                                   const char* operation_name) const {
#ifdef VELD_PUBLIC_TESTNET
        (void)operation;
        throw std::runtime_error(std::string("public testnet is disposable and valueless; ") +
                                 operation_name + " is unavailable");
#else
        if (!btcveld_peg_status_fn_)
            throw std::runtime_error(
                std::string("btcVELD consensus status unavailable; refusing to prepare ") +
                operation_name);

        const BtcVeldPegStatus peg = btcveld_peg_status_fn_();
        bool allowed = false;
        switch (operation) {
        case BtcVeldPegOperation::MINT:
            allowed = peg.gate.MintAllowed();
            break;
        case BtcVeldPegOperation::COMPLETION:
            allowed = peg.gate.CompletionAllowed();
            break;
        case BtcVeldPegOperation::REDEEM:
            allowed = peg.gate.RedeemAllowed();
            break;
        case BtcVeldPegOperation::AMM:
            allowed = peg.gate.AmmAllowed();
            break;
        }
        if (!allowed) {
            const std::string reason =
                peg.reason.empty() ? std::string("status_unavailable") : peg.reason;
            throw std::runtime_error(
                std::string("btcVELD ") + operation_name +
                " preparation is closed by the consensus launch/liveness gate (" + reason + ")");
        }
#endif
    }

    Blockchain& chain_;
    Mempool& mempool_;
    StorageEngine& storage_;
    TxBroadcastFn tx_broadcast_;
    BlockBroadcastFn block_broadcast_;
    PeerCountFn peer_count_;
    PeerInfoFn peer_info_;
    TokenSaveFn token_save_;
    MiningTemplatePreflightFn mining_template_preflight_fn_;
    WorkAdmissionFn work_admission_fn_;
    IssueBlockTemplateAuthorizationFn issue_block_template_authorization_fn_;
    ConsumeBlockTemplateAuthorizationFn consume_block_template_authorization_fn_;
    RemoteWorkGrantFn remote_work_grant_fn_;
    BeginRemoteSigningFn begin_remote_signing_fn_;
    CancelRemoteSigningFn cancel_remote_signing_fn_;
    ValidatorEndorsementSinkFn validator_endorsement_sink_fn_;
    TierEngine* tiers_;
    VaultLedger* vault_;
    GovernanceEngine* gov_;
    StakingLedger* staking_{nullptr};
    std::string datadir_;
    std::function<std::string()> pool_info_fn_;
    std::function<std::string()> miner_status_fn_;
    std::function<std::string(bool)> flush_trigger_fn_;
    std::function<bool()> ibd_complete_fn_;
    std::function<bool()> txindex_enabled_fn_;
    std::function<std::optional<uint64_t>(const std::string&)> txindex_lookup_fn_;
    std::function<std::string(const std::string&, size_t, const std::string&)> address_history_fn_;
    std::atomic<uint32_t> address_history_queries_{0};
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    std::function<std::string(const std::string&)> dump_snapshot_fn_;
#endif
    std::function<std::string()> clear_mining_halt_fn_;
    std::function<std::string(const Hash256&)> invalidate_block_fn_;
    std::function<std::string(const Hash256&)> reconsider_block_fn_;
    std::function<size_t()> clear_reject_cache_fn_;
    std::function<size_t()> clear_orphan_pool_fn_;
    std::function<size_t()> clear_bad_alt_tips_fn_;
    OnChainTokenLedger* onchain_tokens_;
    AmmLedger* amm_ = nullptr;
    ValidatorRegistry* validators_{nullptr};
    std::function<void(const TokenOpData&)> token_op_cb_;
    std::function<uint64_t()>
        final_height_fn_; // retained certificate height; zero means nothing finalized
    std::function<BtcVeldPegStatus()> btcveld_peg_status_fn_;
    std::function<std::string(const std::vector<std::string>&)> btcveld_redeem_page_fn_;
    std::function<std::string()> btcveld_supply_snapshot_fn_;
    std::function<BtcVeldMintProofStatus(const std::string&)> btcveld_mint_proof_fn_;
    std::function<std::string()>
        btc_header_info_fn_; // node's in-consensus BTC-header tip (btcVELD relay)
    std::function<Hash256()> btc_header_digest_fn_; // complete in-consensus SPV header state
    GenerateFn generate_fn_;                        // regtest-only on-demand block generator
    std::function<std::string()> anchor_info_fn_;   // btcVELD Layer-2 anchor set summary
    std::function<Hash256()> anchor_digest_fn_;     // complete in-consensus Bitcoin anchor set
    std::function<Hash256()>
        finality_digest_fn_; // raw Layer-3 high-water + fixed advancement inputs
    std::function<std::string(std::optional<uint64_t>)>
        finality_snapshot_fn_; // retained epoch snapshot as JSON (daemon read surface)
    std::function<bool(const std::string&, const std::string&,
                       const std::string&)>
        finality_vote_sink_; // gossiped vote + bound authorization intake
    std::function<std::string(uint8_t)> finality_qc_fn_; // verified assembled prevote/precommit QC
    std::function<std::vector<FinalityEvidenceSummary>(size_t, size_t)>
        finality_evidence_list_fn_; // bounded durable completed-pair summaries
    std::function<std::optional<FinalityEvidence>(const Hash256&)>
        finality_evidence_find_fn_; // exact authenticated pair by durable id
    std::function<std::optional<std::string>(const Hash256&)>
        finality_slash_prepare_fn_;                  // consensus-prechecked exact-17 slash op
    std::function<Hash256()> redeem_bond_digest_fn_; // complete signer-bond/redeem covenant state
    std::function<std::pair<uint64_t, uint64_t>()> module_cursor_fn_;
    std::function<std::string()> pow_verify_status_fn_;
    std::unordered_map<std::string, std::time_t> unstake_cooldowns_;

    std::recursive_mutex stake_reserve_mutex_;
    std::unordered_map<std::string, uint64_t> stake_reserve_units_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> stake_reserve_expiry_;

    using RpcMethod = std::function<std::string(const std::vector<std::string>&)>;
    std::unordered_map<std::string, RpcMethod> methods_;
    RuntimeAdmissionFn runtime_admission_fn_;
    std::string runtime_admission_refusal_;

    void RegisterMethods() {
        using JB = JsonBuilder;
        using P = std::vector<std::string>;

        static const auto rpc_process_start_steady = std::chrono::steady_clock::now();
        methods_["getclockinfo"] = RpcMethod([](const P&) -> std::string {
            uint64_t now_wall = (uint64_t)std::time(nullptr);
            auto uptime_secs = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::steady_clock::now() - rpc_process_start_steady)
                                   .count();
            std::ostringstream j;
            j << "{"
              << "\"wall_clock_unix\":" << now_wall << ","
              << "\"process_uptime_sec\":" << uptime_secs << ","
              << "\"future_time_tolerance_sec\":600,"
              << "\"note\":\"Veld accepts blocks with timestamp <= wall_clock + 600s. "
                 "If wall_clock drifts > 600s from network consensus, this node "
                 "rejects honest peers' blocks. Run 'chronyc tracking' (Linux) "
                 "or 'w32tm /query /status' (Windows) for NTP-sync diagnostics.\""
              << "}";
            return j.str();
        });

        methods_["getblockchaininfo"] = RpcMethod([this](const P&) -> std::string {
            bool is_bootstrap = chain_.TotalSupplyUnits() < chain_.GetStakingActivationUnits();
            std::string best_hash =
                chain_.IsEmpty() ? std::string(64, '0') : HashToHex(chain_.TipCopy().GetHash());
            // tip block's REAL mined timestamp — the wallet's status bar needs this
            // so "X ago" reflects when the block was actually found, not when the
            // wallet first observed it (which reset the counter on every app open).
            uint64_t tip_time = chain_.IsEmpty() ? 0 : (uint64_t)chain_.TipCopy().header.timestamp;
            double difficulty = 1.0;
            double expected_hashes_per_block = 1.0;
            uint32_t tip_bits = 0;
            if (!chain_.IsEmpty()) {
                tip_bits = chain_.TipCopy().header.bits;
                uint32_t exp = tip_bits >> 24;
                uint32_t mant = tip_bits & 0x7FFFFF;
                if (exp > 0 && exp <= 32 && mant > 0) {
                    double log2_expected =
                        256.0 - 8.0 * (double)((int)exp - 3) - std::log2((double)mant);
                    expected_hashes_per_block = std::pow(2.0, log2_expected);
                    double log2_diff1_expected =
                        256.0 - 8.0 * (double)(0x1d - 3) - std::log2((double)0x00ffff);
                    double expected_diff1 = std::pow(2.0, log2_diff1_expected);
                    difficulty = expected_hashes_per_block / expected_diff1;
                }
            }
            std::ostringstream diff_ss;
            diff_ss << std::fixed << std::setprecision(12) << difficulty;
            std::ostringstream hpb_ss;
            hpb_ss << std::fixed << std::setprecision(0) << expected_hashes_per_block;
            return JB::Object({
                {"chain", JB::String(is_bootstrap ? "bootstrap" : "standard")},
                {"blocks", JB::Number((uint64_t)chain_.Height())},
                {"supply", JB::Float(chain_.TotalSupplyVeld())},
                {"supply_units", JB::Number(chain_.TotalSupplyUnits())},
                {"max_supply", JB::Number((uint64_t)MAX_SUPPLY)},
                {"max_reorg_depth", JB::Number((uint64_t)MAX_REORG_DEPTH)},
                {"phase", JB::String(is_bootstrap ? "bootstrap" : "standard")},
                {"staking_active",
                 JB::Bool(chain_.TotalSupplyUnits() >= chain_.GetStakingActivationUnits())},

                {"min_miners", JB::Number((uint64_t)1)},
                {"best_block_hash", JB::String(best_hash)},
                {"tip_time", JB::Number(tip_time)},
                {"bits", JB::Number((uint64_t)tip_bits)},
                {"difficulty", JB::String(diff_ss.str())},
                {"expected_hashes_per_block", JB::String(hpb_ss.str())},
                {"vault_balance",
                 JB::Float((double)chain_.GetBalance(AddressToScript(VAULT_ADDRESS)) / VELD_UNITS)},
                {"ibd_complete", JB::Bool(ibd_complete_fn_ ? ibd_complete_fn_() : true)},
                // Funds-bearing services use this authenticated capability bit
                // before accepting work whose crash recovery may need an exact
                // transaction lookup beyond the bounded recent-block scan.
                // Unwired defaults FALSE (fail closed).
                {"txindex_enabled", JB::Bool(txindex_enabled_fn_ ? txindex_enabled_fn_() : false)},
                //  authoritative governance
                // challenge prefix = GovChainIdPrefix() (network byte + GENESIS_HASH),
                // the EXACT string the on-chain Apply*FromChain path prepends at
                // signed_height >= BATCH2_HARDENING_HEIGHT (=0 on mainnet ⇒ always).
                // The wallet builds its governance signing challenge with this so
                // wallet sig, RPC pre-check, and on-chain verify use one identical
                // string — closing the cross-layer mismatch that silently dropped
                // every governance op.
                {"gov_chain_prefix", JB::String(GovernanceEngine::GovChainIdPrefix())},
            });
        });

        methods_["getblockcount"] = RpcMethod(
            [this](const P&) -> std::string { return JB::Number((uint64_t)chain_.Height()); });

        methods_["getbestblockhash"] = RpcMethod([this](const P&) -> std::string {
            if (chain_.IsEmpty())
                return JB::String(std::string(64, '0'));
            return JB::String(HashToHex(chain_.TipCopy().GetHash()));
        });

        methods_["getblockfull"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Missing block hash");
            Hash256 hash = HexToHash(params[0]);
            auto block = chain_.GetBlockByHash(hash);
            if (!block)
                throw std::runtime_error("Block not found");

            std::vector<std::string> txs;
            for (const auto& tx : block->transactions) {
                std::vector<std::string> inputs;
                for (const auto& inp : tx.inputs) {
                    inputs.push_back(JB::Object({
                        {"txid", JB::String(HashToHex(inp.prev_tx_hash))},
                        {"vout", JB::Number((uint64_t)inp.prev_out_index)},
                    }));
                }
                std::vector<std::string> outputs;
                for (size_t i = 0; i < tx.outputs.size(); ++i) {
                    std::string addr = ScriptToAddress(tx.outputs[i].script_pubkey);
                    outputs.push_back(JB::Object({
                        {"n", JB::Number((uint64_t)i)},
                        {"value", JB::Float((double)tx.outputs[i].value / VELD_UNITS)},
                        {"address", JB::String(addr)},
                    }));
                }
                txs.push_back(JB::Object({
                    {"txid", JB::String(HashToHex(tx.GetTxID()))},
                    {"coinbase", JB::Bool(tx.IsCoinbase())},
                    {"vin", JB::Array(inputs)},
                    {"vout", JB::Array(outputs)},
                }));
            }
            return JB::Object({
                {"hash", JB::String(HashToHex(block->GetHash()))},
                {"height", JB::Number(block->height)},
                {"time", JB::Number((uint64_t)block->header.timestamp)},
                {"tx", JB::Array(txs)},
                {"ntx", JB::Number((uint64_t)block->transactions.size())},
            });
        });

        methods_["getblockhash"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Missing height");
            const uint64_t h = ParseCanonicalRpcU64OrThrow(params[0], "height");
            if (h > chain_.Height())
                throw std::runtime_error("Block height out of range");
            auto block = chain_.GetBlock(h);
            return JB::String(HashToHex(block.GetHash()));
        });

        // Authenticated local identity used by the snapshot publisher. Unlike
        // getblockhash(0), this is constructed directly from the constants
        // compiled into the running binary; publishers require both to match.
        methods_["getcompiledgenesis"] = RpcMethod([](const P&) -> std::string {
            return JB::String(HashToHex(CreateGenesisBlock().GetHash()));
        });

        methods_["getrawblock"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Missing block hash");
            Hash256 hash = HexToHash(params[0]);
            auto block = chain_.GetBlockByHash(hash);
            if (!block)
                throw std::runtime_error("Block not found");
            auto bytes = block->Serialize();
            static const char* hex_digits = "0123456789abcdef";
            std::string hex;
            hex.reserve(bytes.size() * 2);
            for (uint8_t b : bytes) {
                hex.push_back(hex_digits[(b >> 4) & 0xF]);
                hex.push_back(hex_digits[b & 0xF]);
            }
            return JB::String(hex);
        });

        methods_["getblock"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Missing block hash");
            Hash256 hash = HexToHash(params[0]);
            auto block = chain_.GetBlockByHash(hash);
            if (!block)
                throw std::runtime_error("Block not found");

            std::vector<std::string> tx_ids;
            for (const auto& tx : block->transactions)
                tx_ids.push_back(JB::String(HashToHex(tx.GetTxID())));

            return JB::Object({
                {"hash", JB::String(HashToHex(block->GetHash()))},
                {"height", JB::Number(block->height)},
                {"time", JB::Number((uint64_t)block->header.timestamp)},
                {"bits", JB::String(std::to_string(block->header.bits))},
                {"nonce", JB::Number((uint64_t)block->header.nonce)},
                {"merkleroot", JB::String(HashToHex(block->header.merkle_root))},
                {"previousblockhash", JB::String(HashToHex(block->header.prev_block_hash))},
                {"tx", JB::Array(tx_ids)},
                {"ntx", JB::Number((uint64_t)block->transactions.size())},
            });
        });

        methods_["gettransaction"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Missing txid");
            if (params.size() < 2)
                throw rpc_error(-32602,
                                "height_or_block_hash required: pass `gettransaction <txid> "
                                "<height|block_hash>` (chain-wide scan removed for performance)");
            Hash256 txid = HexToHash(params[0]);

            uint64_t height_hint = 0;
            const std::string& hint = params[1];
            bool is_hash = (hint.size() == 64);
            for (char c : hint) {
                if (!std::isxdigit((unsigned char)c)) {
                    is_hash = false;
                    break;
                }
            }
            if (is_hash) {
                Hash256 bh = HexToHash(hint);
                auto blk = chain_.GetBlockByHash(bh);
                if (!blk)
                    throw rpc_error(-32602, "block hash not found");
                height_hint = blk->height;
            } else {
                try {
                    height_hint = ParseCanonicalRpcU64OrThrow(hint, "height/block_hash");
                } catch (const std::invalid_argument&) {
                    throw rpc_error(-32602, "invalid height/block_hash");
                }
            }

            uint64_t height = chain_.Height();
            for (int64_t h = (int64_t)height_hint; h == (int64_t)height_hint; --h) {
                auto block = chain_.GetBlock((uint64_t)h);
                for (const auto& tx : block.transactions) {
                    if (tx.GetTxID() == txid) {
                        std::vector<std::string> inputs;
                        for (const auto& inp : tx.inputs) {
                            inputs.push_back(JB::Object({
                                {"txid", JB::String(HashToHex(inp.prev_tx_hash))},
                                {"vout", JB::Number((uint64_t)inp.prev_out_index)},
                            }));
                        }
                        std::vector<std::string> outputs;
                        for (size_t i = 0; i < tx.outputs.size(); ++i) {
                            auto script = tx.outputs[i].script_pubkey;
                            std::string addr = ScriptToAddress(script);
                            outputs.push_back(JB::Object({
                                {"n", JB::Number((uint64_t)i)},
                                {"value", JB::Float((double)tx.outputs[i].value / VELD_UNITS)},
                                {"address", JB::String(addr)},
                            }));
                        }
                        return JB::Object({
                            {"txid", JB::String(HashToHex(txid))},
                            {"raw_hex", JB::String(BytesToHex(tx.Serialize()))},
                            {"block_height", JB::Number((uint64_t)h)},
                            {"block_hash", JB::String(HashToHex(block.GetHash()))},
                            {"time", JB::Number((uint64_t)block.header.timestamp)},
                            {"coinbase", JB::Bool(tx.IsCoinbase())},
                            {"vin", JB::Array(inputs)},
                            {"vout", JB::Array(outputs)},
                            {"confirmations", JB::Number(height - (uint64_t)h + 1)},
                        });
                    }
                }
            }
            throw std::runtime_error("Transaction not found");
        });

        methods_["gettransactionrecent"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw rpc_error(-32602, "txid required");
            const std::string& txid_hex = params[0];
            if (txid_hex.size() != 64)
                throw rpc_error(-32602, "invalid txid");
            for (char c : txid_hex) {
                bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                if (!ok)
                    throw rpc_error(-32602, "invalid txid (lowercase hex required)");
            }
            Hash256 txid = HexToHash(txid_hex);

            constexpr uint64_t SCAN_WINDOW = 2016;
            uint64_t tip = chain_.Height();
            uint64_t scan_from = (tip > SCAN_WINDOW) ? tip - SCAN_WINDOW : 0;

            for (uint64_t h = tip; h + 1 > scan_from; --h) {
                bool got_block = false;
                Block block;
                try {
                    block = chain_.GetBlock(h);
                    got_block = true;
                } catch (...) {
                }
                if (!got_block) {
                    if (h == 0)
                        break;
                    continue;
                }
                for (const auto& tx : block.transactions) {
                    if (tx.GetTxID() == txid) {
                        std::vector<std::string> inputs;
                        for (const auto& inp : tx.inputs) {
                            inputs.push_back(JB::Object({
                                {"txid", JB::String(HashToHex(inp.prev_tx_hash))},
                                {"vout", JB::Number((uint64_t)inp.prev_out_index)},
                            }));
                        }
                        std::vector<std::string> outputs;
                        for (size_t i = 0; i < tx.outputs.size(); ++i) {
                            std::string addr = ScriptToAddress(tx.outputs[i].script_pubkey);
                            outputs.push_back(JB::Object({
                                {"n", JB::Number((uint64_t)i)},
                                {"value", JB::Float((double)tx.outputs[i].value / VELD_UNITS)},
                                {"address", JB::String(addr)},
                            }));
                        }
                        return JB::Object({
                            {"txid", JB::String(HashToHex(txid))},
                            {"block_height", JB::Number((uint64_t)h)},
                            {"block_hash", JB::String(HashToHex(block.GetHash()))},
                            {"time", JB::Number((uint64_t)block.header.timestamp)},
                            {"coinbase", JB::Bool(tx.IsCoinbase())},
                            {"vin", JB::Array(inputs)},
                            {"vout", JB::Array(outputs)},
                            {"confirmations", JB::Number(tip - h + 1)},
                        });
                    }
                }
                if (h == 0)
                    break;
            }
            throw rpc_error(-32602, "tx not found in last 2016 blocks; use `gettransaction <txid> "
                                    "<height|block_hash>` for older txs");
        });

        methods_["getrawtransaction"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw rpc_error(-32602, "txid required");
            const std::string& txid_hex = params[0];
            if (txid_hex.size() != 64)
                throw rpc_error(-32602, "invalid txid");
            for (char c : txid_hex) {
                bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                if (!ok)
                    throw rpc_error(-32602, "invalid txid (lowercase hex required)");
            }
            Hash256 txid = HexToHash(txid_hex);
            uint64_t tip = chain_.Height();

            auto emit = [&](const Block& block, const Transaction& tx, uint64_t h) -> std::string {
                std::vector<std::string> inputs;
                for (const auto& inp : tx.inputs) {
                    inputs.push_back(JB::Object({
                        {"txid", JB::String(HashToHex(inp.prev_tx_hash))},
                        {"vout", JB::Number((uint64_t)inp.prev_out_index)},
                    }));
                }
                std::vector<std::string> outputs;
                for (size_t i = 0; i < tx.outputs.size(); ++i) {
                    std::string addr = ScriptToAddress(tx.outputs[i].script_pubkey);
                    outputs.push_back(JB::Object({
                        {"n", JB::Number((uint64_t)i)},
                        {"value", JB::Float((double)tx.outputs[i].value / VELD_UNITS)},
                        {"address", JB::String(addr)},
                    }));
                }
                return JB::Object({
                    {"txid", JB::String(HashToHex(txid))},
                    // Exact canonical bytes are required by the isolated swap
                    // policy signer to authenticate every selected prevout. The
                    // signer hashes/parses these bytes locally and never trusts
                    // node-supplied value/script metadata by itself.
                    {"raw_hex", JB::String(BytesToHex(tx.Serialize()))},
                    {"block_height", JB::Number(h)},
                    {"block_hash", JB::String(HashToHex(block.GetHash()))},
                    {"time", JB::Number((uint64_t)block.header.timestamp)},
                    {"coinbase", JB::Bool(tx.IsCoinbase())},
                    {"vin", JB::Array(inputs)},
                    {"vout", JB::Array(outputs)},
                    {"confirmations", JB::Number(tip - h + 1)},
                });
            };

            if (txindex_lookup_fn_) {
                try {
                    auto h_opt = txindex_lookup_fn_(txid_hex);
                    if (h_opt && *h_opt <= tip) {
                        uint64_t h = *h_opt;
                        Block block = chain_.GetBlock(h);
                        for (const auto& tx : block.transactions) {
                            if (tx.GetTxID() == txid)
                                return emit(block, tx, h);
                        }
                    }
                } catch (...) {
                }
            }

            constexpr uint64_t SCAN_WINDOW = 2016;
            uint64_t scan_from = (tip > SCAN_WINDOW) ? tip - SCAN_WINDOW : 0;
            for (uint64_t h = tip; h + 1 > scan_from; --h) {
                Block block;
                try {
                    block = chain_.GetBlock(h);
                } catch (...) {
                    if (h == 0)
                        break;
                    continue;
                }
                for (const auto& tx : block.transactions) {
                    if (tx.GetTxID() == txid)
                        return emit(block, tx, h);
                }
                if (h == 0)
                    break;
            }

            throw rpc_error(-32602, "tx not found; start the node with --txindex for O(1) "
                                    "txid lookups, or use `gettransaction <txid> "
                                    "<height|block_hash>`");
        });

        methods_["getminerstatus"] = RpcMethod([this](const P&) -> std::string {
            if (miner_status_fn_)
                return miner_status_fn_();
            return JB::Object({
                {"mining", JB::Bool(false)},
                {"hashrate", JB::Float(0.0)},
                {"total_hashes", JB::Number((uint64_t)0)},
                {"threads", JB::Number((uint64_t)0)},
                {"miner_address", JB::String("")},
                {"bits", JB::Number((uint64_t)0)},
                {"network_hashrate_est", JB::Float(0.0)},
            });
        });

        methods_["getmininginfo"] = RpcMethod([this](const P&) -> std::string {
            bool is_bootstrap = chain_.TotalSupplyUnits() < chain_.GetStakingActivationUnits();
            bool emission_done = chain_.TotalSupplyUnits() >= MAX_SUPPLY_UNITS;
            return JB::Object({
                {"blocks", JB::Number((uint64_t)chain_.Height())},
                {"phase", JB::String(is_bootstrap ? "bootstrap" : "standard")},
                {"emission_complete", JB::Bool(emission_done)},
                {"staking_active", JB::Bool(!is_bootstrap)},
                // Compiled activation threshold in whole VELD for wallet status.
                {"staking_activation_supply",
                 JB::Float((double)chain_.GetStakingActivationUnits() / VELD_UNITS)},
                {"block_reward_veld", JB::Float((double)BLOCK_REWARD_UNITS / VELD_UNITS)},
                {"winner_pct", JB::Number((uint64_t)50)},
                {"pool_pct", JB::Number((uint64_t)20)},
                {"vault_pct", JB::Number((uint64_t)20)},
                {"endorse_pct", JB::Number((uint64_t)10)},
                {"supply_veld", JB::Float(chain_.TotalSupplyVeld())},
                {"supply_pct_mined", JB::Float(chain_.TotalSupplyVeld() / MAX_SUPPLY * 100.0, 4)},
            });
        });

        methods_["getpoolinfo"] = RpcMethod([this](const P&) -> std::string {
            if (pool_info_fn_)
                return pool_info_fn_();
            uint64_t h = chain_.Height();
            uint64_t blocks_in_window = h % 100;
            uint64_t blocks_until_payout = 100 - blocks_in_window;
            return JB::Object({
                {"pool_balance_veld", JB::Float(0.0)},
                {"window_start_height", JB::Number((uint64_t)(h - blocks_in_window))},
                {"blocks_in_window", JB::Number((uint64_t)blocks_in_window)},
                {"blocks_until_payout", JB::Number((uint64_t)blocks_until_payout)},
                {"window_size", JB::Number((uint64_t)100)},
                {"pool_pct", JB::Number((uint64_t)27)},
                {"participants", JB::Number((uint64_t)0)},
                {"total_near_misses", JB::Number((uint64_t)0)},
                {"entries", JsonBuilder::Array({})},
            });
        });

        methods_["getutxosum"] = RpcMethod([this](const P&) -> std::string {
            auto balances = chain_.GetAllBalances();
            uint64_t total_utxo_units = 0;
            uint64_t utxo_count = 0;
            for (auto& [k, v] : balances) {
                total_utxo_units += v;
                utxo_count++;
            }
            uint64_t supply_units = chain_.TotalSupplyUnits();
            int64_t diff = (int64_t)total_utxo_units - (int64_t)supply_units;
            std::ostringstream j;
            j << std::fixed << std::setprecision(8);
            j << "{"
              << "\"utxo_sum_veld\":" << (double)total_utxo_units / VELD_UNITS << ","
              << "\"supply_veld\":" << (double)supply_units / VELD_UNITS << ","
              << "\"diff_veld\":" << (double)diff / VELD_UNITS << ","
              << "\"utxo_count\":" << utxo_count << ","
              << "\"height\":" << chain_.Height() << ","
              << "\"balanced\":" << (diff == 0 ? "true" : "false") << "}";
            return j.str();
        });

        methods_["getmempoolinfo"] = RpcMethod([this](const P&) -> std::string {
            return JB::Object({
                {"size", JB::Number((uint64_t)mempool_.Size())},
                {"bytes", JB::Number((uint64_t)mempool_.Bytes())},
                {"maxmempool", JB::Number((uint64_t)Mempool::MAX_MEMPOOL_BYTES)},
                {"mempoolminfee", JB::Number(Mempool::MIN_FEE_RATE)},
            });
        });

        methods_["dryrunmempool"] = RpcMethod([this](const P&) -> std::string {
            auto pool_raw = mempool_.GetBlockTransactionsWithFees(999, MAX_BLOCK_SIZE, &chain_);
            std::set<std::string> returned_by_filter;
            for (auto& [tx, fee] : pool_raw)
                returned_by_filter.insert(HashToHex(tx.GetTxID()));

            std::ostringstream j;
            j << "{\"filter_returned\":" << pool_raw.size() << ",\"txs\":[";
            bool first = true;
            mempool_.ForEachDiagnostic([&](const std::string& txid, const Transaction& tx) {
                if (!first)
                    j << ",";
                first = false;
                j << "{\"txid\":" << JB::String(txid);
                j << ",\"in_filter_result\":"
                  << (returned_by_filter.count(txid) ? "true" : "false");
                bool inputs_on_chain = true;
                std::string missing;
                for (const auto& inp : tx.inputs) {
                    if (inp.IsCoinbase())
                        continue;
                    if (!chain_.GetUTXO(inp.prev_tx_hash, inp.prev_out_index)) {
                        inputs_on_chain = false;
                        missing =
                            HashToHex(inp.prev_tx_hash) + ":" + std::to_string(inp.prev_out_index);
                        break;
                    }
                }
                j << ",\"inputs_on_chain\":" << (inputs_on_chain ? "true" : "false");
                if (!inputs_on_chain)
                    j << ",\"missing_utxo\":" << JB::String(missing);
                bool sig_ok = false;
                std::string sig_err;
                if (inputs_on_chain) {
                    try {
                        sig_ok = chain_.ValidateTransactionLocking(tx, false);
                    } catch (const std::exception& e) {
                        sig_err = e.what();
                    } catch (...) {
                        sig_err = "unknown exception";
                    }
                }
                j << ",\"validate_tx\":" << (sig_ok ? "true" : "false");
                if (!sig_err.empty())
                    j << ",\"validate_error\":" << JB::String(sig_err);
                j << ",\"would_include\":"
                  << (returned_by_filter.count(txid) && inputs_on_chain && sig_ok ? "true"
                                                                                  : "false");
                j << "}";
            });
            j << "]}";
            return j.str();
        });

        methods_["getmempoolentry"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Usage: getmempoolentry <txid>");
            const std::string& txid = params[0];
            auto tx_opt = mempool_.GetTransaction(txid);
            if (!tx_opt)
                return "{\"error\":\"not in mempool\",\"txid\":" + JB::String(txid) + "}";
            const auto& tx = *tx_opt;
            auto fee_size = mempool_.GetFeeAndSize(txid);

            std::ostringstream j;
            j << std::fixed << std::setprecision(8);
            j << "{";
            j << "\"txid\":" << JB::String(txid) << ",";
            // Watchtowers must parse the exact spender locally; value/vout
            // summaries are not sufficient to authorize a penalty signature.
            j << "\"raw_hex\":" << JB::String(BytesToHex(tx.Serialize())) << ",";
            if (fee_size) {
                j << "\"fee_units\":" << fee_size->first << ",";
                j << "\"size_bytes\":" << fee_size->second << ",";
            }
            j << "\"num_inputs\":" << tx.inputs.size() << ",";
            j << "\"num_outputs\":" << tx.outputs.size() << ",";
            j << "\"inputs\":[";
            bool first = true;
            uint64_t total_input = 0;
            size_t not_on_chain = 0;
            for (size_t i = 0; i < tx.inputs.size(); ++i) {
                const auto& inp = tx.inputs[i];
                if (!first)
                    j << ",";
                first = false;
                j << "{";
                j << "\"prev_txid\":\"" << HashToHex(inp.prev_tx_hash) << "\",";
                j << "\"prev_vout\":" << inp.prev_out_index << ",";
                j << "\"is_coinbase\":" << (inp.IsCoinbase() ? "true" : "false") << ",";
                if (!inp.IsCoinbase()) {
                    auto utxo = chain_.GetUTXO(inp.prev_tx_hash, inp.prev_out_index);
                    if (utxo) {
                        j << "\"on_chain\":true,";
                        j << "\"value_veld\":" << ((double)utxo->value / VELD_UNITS) << ",";
                        j << "\"utxo_height\":" << utxo->block_height << ",";
                        j << "\"is_coinbase_utxo\":" << (utxo->is_coinbase ? "true" : "false");
                        total_input += utxo->value;
                    } else {
                        j << "\"on_chain\":false";
                        ++not_on_chain;
                        auto parent = mempool_.GetTransaction(HashToHex(inp.prev_tx_hash));
                        j << ",\"parent_in_mempool\":" << (parent ? "true" : "false");
                    }
                }
                j << "}";
            }
            j << "],";
            j << "\"total_input_veld\":" << ((double)total_input / VELD_UNITS) << ",";
            uint64_t total_output = 0;
            for (const auto& out : tx.outputs)
                total_output += out.value;
            j << "\"total_output_veld\":" << ((double)total_output / VELD_UNITS) << ",";
            j << "\"inputs_missing_from_chain\":" << not_on_chain << ",";
            j << "\"miner_will_skip\":" << (not_on_chain > 0 ? "true" : "false");
            j << "}";
            return j.str();
        });

        methods_["getrawmempool"] = RpcMethod([this](const P&) -> std::string {
            auto txids = mempool_.GetTxIds();
            std::vector<std::string> quoted;
            quoted.reserve(txids.size());
            for (auto& id : txids)
                quoted.push_back(JsonBuilder::String(id));
            return JsonBuilder::Array(quoted);
        });

        methods_["estimatefee"] = RpcMethod([this](const P&) -> std::string {
            size_t mempool_size = mempool_.Size();
            uint64_t base_rate = Mempool::MIN_FEE_RATE;
            uint64_t recommended;
            if (mempool_size < 100)
                recommended = base_rate;
            else if (mempool_size < 500)
                recommended = base_rate * 2;
            else if (mempool_size < 2000)
                recommended = base_rate * 5;
            else
                recommended = base_rate * 10;
            double fee_per_kb = (double)(recommended * 1000) / VELD_UNITS;
            return JB::Object({
                {"feerate", JB::Float(fee_per_kb)},
                {"blocks", JB::Number((uint64_t)1)},
                {"mempool_txs", JB::Number((uint64_t)mempool_size)},
            });
        });

        methods_["getnetworkinfo"] = RpcMethod([this](const P&) -> std::string {
#ifdef VELD_REGTEST_FIXED_DIFF
            constexpr const char* consensus_build_profile = "l3-regtest-fixed-difficulty-v1";
            constexpr bool fixed_difficulty_regtest = true;
#else
            constexpr const char* consensus_build_profile = "variable-difficulty-v1";
            constexpr bool fixed_difficulty_regtest = false;
#endif
            return JB::Object({
                {"version", JB::Number((uint64_t)PROTOCOL_VERSION)},
                {"subversion", JB::String(CLIENT_USER_AGENT)},
                {"protocolversion", JB::Number((uint64_t)PROTOCOL_VERSION)},
                {"connections", JB::Number((uint64_t)(peer_count_ ? peer_count_() : 0))},
                {"relayfee", JB::Float((double)Mempool::MIN_FEE_RATE / VELD_UNITS)},
                {"role", JB::String(DEPLOYMENT_ROLE)},
                {"profile_id", JB::String(DEPLOYMENT_PROFILE_ID)},
                {"display_name", JB::String(DEPLOYMENT_DISPLAY_NAME)},
                {"disposable", JB::Bool(DEPLOYMENT_DISPOSABLE)},
                {"external_value", JB::Bool(DEPLOYMENT_EXTERNAL_VALUE)},
                {"consensus_build_profile", JB::String(consensus_build_profile)},
                {"fixed_difficulty_regtest", JB::Bool(fixed_difficulty_regtest)},
                {"genesis_fingerprint", JB::String(GENESIS_HASH)},
                {"deployment_warning", JB::String(DEPLOYMENT_WARNING)},
            });
        });

        methods_["getpeerinfo"] = RpcMethod([this](const P&) -> std::string {
            if (!peer_info_)
                return "[]";
            return peer_info_();
        });

        methods_["getminerinfo"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Usage: getminerinfo <address>");
            const std::string& addr = params[0];
            auto script = AddressToScript(addr);
            std::string script_hex = BytesToHex(script);

            // Count and last-height are one rebuildable archival record.  Do
            // not combine separate reads (or render a plausible zero) while a
            // rebuild/reorg has deliberately closed that record.
            const auto miner_archive = chain_.GetMinerArchiveRecord(script_hex);
            if (!miner_archive)
                throw std::runtime_error("miner archive unavailable; restart/rebuild required");
            uint64_t blocks_mined = miner_archive->blocks_mined;
            uint64_t last_block_height = miner_archive->last_block_mined;
            // Use canonical wallet state so balance and miner status report the
            // same treatment of staked, immature, and mempool-locked outputs.
            WalletState ws = ComputeWalletState(addr);
            double balance_veld = (double)ws.total_units / VELD_UNITS;
            double immature_coinbase_veld = (double)ws.immature_coinbase_units / VELD_UNITS;
            double staked = (double)ws.staked_units / VELD_UNITS;
            double spendable = (double)ws.spendable_units / VELD_UNITS;

            int tier = 0;
            double mult = 1.0;
            std::string tier_name = "Seedling";
            uint64_t cur_active = 0, cur_total = 0, cur_required = 0;
            if (tiers_) {
                auto t = tiers_->GetTier(script_hex);
                tier = t.level;
                mult = t.multiplier;
                if (!t.name.empty())
                    tier_name = t.name;
                if (t.is_window_tier) {
                    cur_active = t.windows_active;
                    cur_total = t.windows_total;
                    cur_required = t.windows_required;
                }
            }
            uint64_t height = chain_.Height();
            const char* next_name = "";
            uint64_t next_active = 0, next_total = 0, next_required = 0;
            switch (tier) {
            case 0:
                next_name = "Bronze";
                next_total = 14;
                next_required = 7;
                next_active = chain_.GetActiveWindowCount(script_hex, 14, height);
                break;
            case 1:
                next_name = "Silver";
                next_total = 30;
                next_required = 25;
                next_active = chain_.GetActiveWindowCount(script_hex, 30, height);
                break;
            case 2:
                next_name = "Gold";
                next_total = 180;
                next_required = 165;
                next_active = chain_.GetActiveWindowCount(script_hex, 180, height);
                break;
            case 3:
                next_name = "Platinum";
                next_total = 365;
                next_required = 335;
                next_active = chain_.GetActiveWindowCount(script_hex, 365, height);
                break;
            case 4:
                next_name = "Diamond";
                next_total = 1095;
                next_required = 1000;
                next_active = chain_.GetActiveWindowCount(script_hex, 1095, height);
                break;
            }

            std::ostringstream j;
            j << std::fixed << std::setprecision(8);
            j << "{"
              << "\"address\":\"" << addr << "\","
              << "\"blocks_mined\":" << blocks_mined << ","
              << "\"last_block_height\":" << last_block_height << ","
              << "\"balance_veld\":" << balance_veld << ","
              << "\"staked_veld\":" << staked << ","
              << "\"immature_coinbase_veld\":" << immature_coinbase_veld << ","
              << "\"spendable_veld\":" << spendable << ","
              << "\"tier\":" << tier << ","
              << "\"tier_name\":\"" << tier_name << "\","
              << "\"multiplier\":" << std::setprecision(2) << mult << ","
              << "\"windows_active\":" << cur_active << ","
              << "\"windows_total\":" << cur_total << ","
              << "\"windows_required\":" << cur_required << ","
              << "\"next_tier_name\":\"" << next_name << "\","
              << "\"next_windows_active\":" << next_active << ","
              << "\"next_windows_total\":" << next_total << ","
              << "\"next_windows_required\":" << next_required << ","
              << "\"staking_active\":"
              << (staking_ && staking_->IsStakingActive(chain_.TotalSupplyUnits()) ? "true"
                                                                                   : "false");
            {
                bool sl = false;
                uint64_t sl_h = 0;
                if (validators_) {
                    auto st = validators_->GetSlashStatusByAddress(addr);
                    sl = st.first;
                    sl_h = st.second;
                }
                j << ",\"slashed\":" << (sl ? "true" : "false")
                  << ",\"slashed_at_height\":" << sl_h;
            }
            j << "}";
            return j.str();
        });

        methods_["getvaultinfo"] = RpcMethod([this](const P&) -> std::string {
            auto vault_script = AddressToScript(VAULT_ADDRESS);
            double vault_bal = (double)chain_.GetBalance(vault_script) / VELD_UNITS;
            uint64_t height = chain_.Height();
            uint64_t next_dist =
                VAULT_DISTRIBUTION_INTERVAL - (height % VAULT_DISTRIBUTION_INTERVAL);
            uint64_t next_vault_block = VAULT_BLOCK_INTERVAL - (height % VAULT_BLOCK_INTERVAL);

            std::ostringstream j;
            j << std::fixed << std::setprecision(8);
            j << "{"
              << "\"vault_address\":\"" << VAULT_ADDRESS << "\","
              << "\"balance_veld\":" << vault_bal << ","
              << "\"balance_units\":" << chain_.GetBalance(vault_script) << ","
              << "\"fees_collected_veld\":" << chain_.TotalFeesCollectedVeld() << ","
              << "\"fees_collected_units\":" << chain_.TotalFeesCollectedUnits() << ","
              << "\"next_distribution_blocks\":" << next_dist << ","
              << "\"next_vault_block_in\":" << next_vault_block << ","
              << "\"distribution_interval\":" << VAULT_DISTRIBUTION_INTERVAL << ","
              << "\"vault_block_interval\":" << VAULT_BLOCK_INTERVAL << "}";
            return j.str();
        });

        methods_["getbondvaultinfo"] = RpcMethod([this](const P&) -> std::string {
            uint64_t height = chain_.Height();
            auto sv_script = AddressToScript(STAKE_VAULT_ADDRESS);
            auto esc_script = AddressToScript(BOND_YIELD_ESCROW);
            uint64_t custodied_units = sv_script.empty() ? 0 : chain_.GetBalance(sv_script);
            uint64_t escrow_units = esc_script.empty() ? 0 : chain_.GetBalance(esc_script);
            bool activated = (height >= BOND_YIELD_ACTIVATION_HEIGHT);
            uint64_t blocks_until = activated ? 0 : (BOND_YIELD_ACTIVATION_HEIGHT - height);
            const uint64_t finality_evidence_window =
                ::veld::finality::qc::FINALITY_EQUIV_EVIDENCE_WINDOW;
            const uint64_t complete_evidence_window =
                std::max<uint64_t>(SLASH_EVIDENCE_WINDOW, finality_evidence_window);

            std::unordered_map<std::string, uint64_t> accrued_by_pk;
            uint64_t escrow_attributed = 0;
            if (validators_) {
                for (const auto& t : validators_->GetBondYieldEscrowSummary()) {
                    accrued_by_pk[std::get<1>(t)] = std::get<2>(t);
                    escrow_attributed += std::get<2>(t);
                }
            }

            std::ostringstream j;
            j << std::fixed << std::setprecision(8);
            j << "{"
              << "\"stake_vault_address\":\"" << STAKE_VAULT_ADDRESS << "\","
              << "\"custodied_principal_veld\":" << (double)custodied_units / VELD_UNITS << ","
              << "\"custody_active_since_height\":" << STAKE_VAULT_ACTIVATION_HEIGHT << ","
              << "\"bond_yield_escrow_address\":\"" << BOND_YIELD_ESCROW << "\","
              << "\"escrow_balance_veld\":" << (double)escrow_units / VELD_UNITS << ","
              << "\"escrow_gross_accrued_veld\":" << (double)escrow_attributed / VELD_UNITS << ","
              << "\"yield_escrow_activation_height\":" << BOND_YIELD_ACTIVATION_HEIGHT << ","
              << "\"yield_escrow_activated\":" << (activated ? "true" : "false") << ","
              << "\"blocks_until_activation\":" << blocks_until << ","
              << "\"current_height\":" << height << ","
              << "\"settlement_interval\":" << BOND_SETTLEMENT_INTERVAL << ","
              << "\"vest_horizon_blocks\":" << BOND_YIELD_VEST_BLOCKS << ","
              << "\"ordinary_slash_evidence_window_blocks\":" << SLASH_EVIDENCE_WINDOW << ","
              << "\"finality_equivocation_evidence_window_blocks\":" << finality_evidence_window
              << ","
              << "\"slash_evidence_window_blocks\":" << complete_evidence_window
              << ","
              // Backward-compatible field name: callers of the old RPC used
              // this value as the post-deregister bond hold.  Returning the
              // unrelated 12-hour generic minimum would continue to advertise
              // an unsafe early-return expectation, so the alias now reports
              // the actual complete slashing-evidence window too.
              << "\"min_evidence_window\":" << complete_evidence_window << ",";
            uint64_t custodial_count = 0;
            uint64_t pending_return_count = 0;
            j << "\"validators\":[";
            if (validators_) {
                bool first = true;
                for (const auto& v : validators_->GetAllValidatorRecords()) {
                    // Non-custodial historical records carry no protocol coin
                    // and are not part of this vault surface.  Inactive
                    // custodial records remain visible through/after exit so a
                    // pending slashable bond never disappears from operator UI.
                    if (!v.bond_custodial || v.bond_units == 0)
                        continue;
                    if (v.active && !v.slashed)
                        custodial_count++;
                    uint64_t return_boundary = 0;
                    uint64_t settlement_boundary = 0;
                    bool pending_return = false;
                    if (!v.slashed && v.deregistered_at_height > 0) {
                        return_boundary = ValidatorRegistry::DeregReturnBoundary(
                            v.deregistered_at_height, v.last_finality_vote_height);
                        settlement_boundary = return_boundary;
                        pending_return = height < return_boundary;
                        if (pending_return)
                            pending_return_count++;
                    } else if (v.slashed && v.slashed_at_height > 0) {
                        settlement_boundary =
                            ValidatorRegistry::SlashSettlementBoundary(v.slashed_at_height);
                    }
                    const bool principal_held =
                        v.active || (settlement_boundary > 0 && height < settlement_boundary);
                    uint64_t acc = 0;
                    auto it = accrued_by_pk.find(v.pubkey_hex);
                    if (it != accrued_by_pk.end())
                        acc = it->second;
                    if (!first)
                        j << ",";
                    j << "{\"address\":\"" << v.address << "\","
                      << "\"pubkey\":\"" << v.pubkey_hex << "\","
                      << "\"active\":" << (v.active ? "true" : "false") << ","
                      << "\"bond_custodial\":" << (v.bond_custodial ? "true" : "false") << ","
                      << "\"bond_veld\":"
                      << (principal_held ? (double)v.bond_units / VELD_UNITS : 0.0) << ","
                      << "\"original_bond_veld\":" << (double)v.bond_units / VELD_UNITS << ","
                      << "\"principal_held\":" << (principal_held ? "true" : "false") << ","
                      << "\"yield_accrued_veld\":" << (double)acc / VELD_UNITS << ","
                      << "\"slashed\":" << (v.slashed ? "true" : "false") << ","
                      << "\"slashed_equivocation\":" << (v.slashed_equivocation ? "true" : "false")
                      << ","
                      << "\"registered_height\":" << v.registered_height << ","
                      << "\"deregistered_at_height\":" << v.deregistered_at_height << ","
                      << "\"last_finality_vote_height\":" << v.last_finality_vote_height << ","
                      << "\"return_boundary\":" << return_boundary << ","
                      << "\"settlement_boundary\":" << settlement_boundary << ","
                      << "\"pending_return\":" << (pending_return ? "true" : "false") << "}";
                    first = false;
                }
            }
            j << "],"
              << "\"custodial_validator_count\":" << custodial_count << ","
              << "\"pending_return_count\":" << pending_return_count << "}";
            return j.str();
        });

        methods_["getstatedigest"] = RpcMethod([this](const P&) -> std::string {
            namespace sd = ::veld::state_digest;
            // One top-level digest must never splice the chain half of block N
            // together with module state from N-1. AddBlockDirect holds this same
            // transition sequencer across validation, module callbacks, canonical
            // publication, persistence, and rollback; individual digest methods
            // may safely take their normal shared/module locks underneath it.
            auto transition_guard = chain_.AcquireConsensusTransitionGuard();
            const uint64_t H = chain_.Height();
            const uint64_t canonical_supply = chain_.TotalSupplyUnits();
            if (!module_cursor_fn_) {
                throw rpc_error(
                    -32603,
                    "state digest unavailable: module replay cursor invariant is not wired");
            }
            const auto module_cursor = module_cursor_fn_();
            if (module_cursor.first != H || module_cursor.second != canonical_supply) {
                throw rpc_error(-32603,
                                "state digest unavailable: module replay cursor invariant mismatch "
                                "(cursor_height=" +
                                    std::to_string(module_cursor.first) +
                                    ", chain_height=" + std::to_string(H) +
                                    ", cursor_supply=" + std::to_string(module_cursor.second) +
                                    ", chain_supply=" + std::to_string(canonical_supply) + ")");
            }
            const Hash256 d_utxo = chain_.UtxoDigest();
            const Hash256 d_nmstally = chain_.NmsTallyDigest();
            const Hash256 d_validators = validators_
                                             ? validators_->ValidatorsDigest()
                                             : sd::empty_container_digest(sd::tags::VALIDATORS);
            const Hash256 d_staking = staking_ ? staking_->StakingDigest()
                                               : sd::empty_container_digest(sd::tags::STAKING);
            const Hash256 d_bondyield = validators_
                                            ? validators_->BondYieldEscrowDigest()
                                            : sd::empty_container_digest(sd::tags::BONDYIELD);
            const Hash256 d_tokens =
                onchain_tokens_
                    ? onchain_tokens_->Digest()
                    : sd::empty_container_digest(btcveld::reserve::TRANSITION_V1_REQUIRED
                                                     ? sd::tags::TOKENS_RESERVE_V1
                                                     : sd::tags::TOKENS);
            Hash256 tip_hash = ZeroHash();
            if (!chain_.IsEmpty()) {
                try {
                    tip_hash = chain_.TipCopy().GetHash();
                } catch (...) {
                    tip_hash = ZeroHash();
                }
            }
            const Hash256 d_supply = chain_.SupplyDigest();
            const Hash256 d_governance =
                gov_ ? gov_->GovernanceDigest() : sd::empty_container_digest(sd::tags::GOVERNANCE);
            const Hash256 d_nms_extended = chain_.NmsExtendedDigest();
            const Hash256 d_spv = btc_header_digest_fn_ ? btc_header_digest_fn_()
                                                        : sd::empty_container_digest(sd::tags::SPV);
            const Hash256 d_anchors = anchor_digest_fn_
                                          ? anchor_digest_fn_()
                                          : sd::empty_container_digest(sd::tags::ANCHORS);
            const Hash256 d_amm =
                amm_ ? amm_->Digest()
                     : sd::empty_container_digest(sd::tags::AMM); // AMM pool ledger
            const Hash256 d_finality = finality_digest_fn_
                                           ? finality_digest_fn_()
                                           : sd::empty_container_digest(sd::tags::FINALITY);
            const Hash256 d_redeem_bond = redeem_bond_digest_fn_
                                              ? redeem_bond_digest_fn_()
                                              : sd::empty_container_digest(sd::tags::REDEEM_BOND);
            const Hash256 top =
                btcveld::reserve::TRANSITION_V1_REQUIRED
                    ? sd::ComposeV8(H, tip_hash, d_utxo, d_validators, d_staking, d_bondyield,
                                    d_nmstally, d_tokens, d_supply, d_governance, d_nms_extended,
                                    d_spv, d_anchors, d_amm, d_finality, d_redeem_bond)
                    : sd::ComposeV7(H, tip_hash, d_utxo, d_validators, d_staking, d_bondyield,
                                    d_nmstally, d_tokens, d_supply, d_governance, d_nms_extended,
                                    d_spv, d_anchors, d_amm, d_finality, d_redeem_bond);
            std::ostringstream j;
            j << "{"
              << "\"spec_version\":\""
              << (btcveld::reserve::TRANSITION_V1_REQUIRED ? "VELD_STATE_DIGEST_v8"
                                                           : "VELD_STATE_DIGEST_v7")
              << "\","
              << "\"height\":" << H << ","
              << "\"tip_hash\":\"" << HashToHex(tip_hash) << "\","
              << "\"digest\":\"" << HashToHex(top) << "\","
              << "\"sub\":{"
              << "\"utxo\":\"" << HashToHex(d_utxo) << "\","
              << "\"validators\":\"" << HashToHex(d_validators) << "\","
              << "\"staking\":\"" << HashToHex(d_staking) << "\","
              << "\"bondyield\":\"" << HashToHex(d_bondyield) << "\","
              << "\"nmstally\":\"" << HashToHex(d_nmstally) << "\","
              << "\"tokens\":\"" << HashToHex(d_tokens) << "\","
              << "\"supply\":\"" << HashToHex(d_supply) << "\","
              << "\"governance\":\"" << HashToHex(d_governance) << "\","
              << "\"nms_extended\":\"" << HashToHex(d_nms_extended) << "\","
              << "\"spv\":\"" << HashToHex(d_spv) << "\","
              << "\"anchors\":\"" << HashToHex(d_anchors) << "\","
              << "\"amm\":\"" << HashToHex(d_amm) << "\","
              << "\"finality\":\"" << HashToHex(d_finality) << "\","
              << "\"redeem_bond\":\"" << HashToHex(d_redeem_bond) << "\""
              << "}"
              << "}";
            return j.str();
        });

        methods_["getbalance"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Missing address");
            const std::string& addr = params[0];
            auto script = AddressToScript(addr);
            if (script.empty())
                return JB::Float(0.0);
            WalletState ws = ComputeWalletState(addr);
            double total_veld = (double)ws.total_units / VELD_UNITS;
            double immature_coinbase_veld = (double)ws.immature_coinbase_units / VELD_UNITS;
            double staked = (double)ws.staked_units / VELD_UNITS;
            double spendable = (double)ws.spendable_units / VELD_UNITS;

            double pending_in_veld = (double)ws.pending_in_units / VELD_UNITS;
            double pending_out_veld = (double)ws.pending_out_units / VELD_UNITS;
            double pending_transfer_out_veld = 0.0;
            {
                std::unordered_set<std::string> my_spent_utxos;
                for (const auto& u : ws.pending_out_utxos) {
                    my_spent_utxos.insert(UTXOKey(u.tx_hash, u.output_index));
                }
                if (!my_spent_utxos.empty()) {
                    auto txids = mempool_.GetTxIds();
                    for (const auto& txid : txids) {
                        auto tx_opt = mempool_.GetTransaction(txid);
                        if (!tx_opt.has_value())
                            continue;
                        const Transaction& tx = tx_opt.value();
                        bool im_sender = false;
                        for (const auto& inp : tx.inputs) {
                            std::string in_key = HashToHex(inp.prev_tx_hash) + ":" +
                                                 std::to_string(inp.prev_out_index);
                            if (my_spent_utxos.count(in_key)) {
                                im_sender = true;
                                break;
                            }
                        }
                        if (!im_sender)
                            continue;
                        for (const auto& out : tx.outputs) {
                            if (out.value == 0)
                                continue;
                            if (out.script_pubkey == script)
                                continue;
                            pending_transfer_out_veld += (double)out.value / VELD_UNITS;
                        }
                    }
                }
            }
            double pending_veld = pending_in_veld - pending_out_veld;
            if (pending_veld < 0.0)
                pending_veld = 0.0;

            std::ostringstream jb;
            jb << std::fixed << std::setprecision(8);
            jb << "{\"balance_veld\":" << total_veld << ",\"staked_veld\":" << staked
               << ",\"immature_coinbase_veld\":" << immature_coinbase_veld
               << ",\"pending_veld\":" << pending_veld << ",\"pending_in_veld\":" << pending_in_veld
               << ",\"pending_out_veld\":" << pending_out_veld
               << ",\"pending_transfer_out_veld\":" << pending_transfer_out_veld
               << ",\"spendable_veld\":" << spendable << "}";
            return jb.str();
        });

        // Bounded, index-only public history. This deliberately does not
        // accept block ranges: one request performs one ordered index seek,
        // returns at most 50 fixed-shape rows, and never loads block bodies.
        methods_["getaddresshistory"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty() || params.size() > 3)
                throw std::invalid_argument("expected address, optional limit, optional cursor");
            size_t limit = 25;
            if (params.size() >= 2) {
                const uint64_t parsed = ParseCanonicalRpcU64OrThrow(params[1], "limit");
                if (parsed == 0 || parsed > 50)
                    throw std::invalid_argument("limit must be an integer from 1 to 50");
                limit = static_cast<size_t>(parsed);
            }
            const std::string cursor = params.size() >= 3 ? params[2] : std::string{};
            if (cursor.size() > 192)
                throw std::invalid_argument("cursor is too long");
            if (!address_history_fn_)
                throw rpc_error(-32004, "address history index unavailable");

            uint32_t active = address_history_queries_.load(std::memory_order_relaxed);
            do {
                if (active >= 4)
                    throw rpc_error(-32005, "address history is busy; retry shortly");
            } while (!address_history_queries_.compare_exchange_weak(
                active, active + 1, std::memory_order_acq_rel, std::memory_order_relaxed));
            struct QueryGuard {
                std::atomic<uint32_t>& count;
                ~QueryGuard() {
                    count.fetch_sub(1, std::memory_order_release);
                }
            } guard{address_history_queries_};

            std::string result = address_history_fn_(params[0], limit, cursor);
            if (result.size() > 32768)
                throw rpc_error(-32004, "address history response exceeded bound");
            return result;
        });

        methods_["listunspent"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Missing address");
            auto script = AddressToScript(params[0]);
            if (script.empty())
                return JB::Array({});
            WalletState ws = ComputeWalletState(params[0]);
            uint64_t tip = chain_.Height();
            std::vector<std::string> items;
            for (const auto& u : ws.selectable) {
                uint64_t confs = (u.block_height <= tip) ? (tip - u.block_height + 1) : 0;
                items.push_back(JB::Object({
                    {"txid", JB::String(HashToHex(u.tx_hash))},
                    {"vout", JB::Number((uint64_t)u.output_index)},
                    {"value", JB::Float((double)u.value / VELD_UNITS)},
                    {"value_units", JB::Number(u.value)},
                    {"confirmations", JB::Number(confs)},
                    {"block_height", JB::Number(u.block_height)},
                }));
            }
            return JB::Array(items);
        });

        methods_["sendrawtransaction"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Missing raw tx hex");
            const std::string& hex = params[0];
            if (hex.size() % 2 != 0)
                throw std::invalid_argument("Invalid hex");
            if (hex.size() > 2u * (size_t)MAX_BLOCK_SIZE)
                throw rpc_error(-32602, "invalid hex in raw: exceeds 2*MAX_BLOCK_SIZE");
            for (char c : hex) {
                if (!std::isxdigit((unsigned char)c))
                    throw rpc_error(-32602, "invalid hex in raw");
            }
            std::vector<uint8_t> raw;
            raw.reserve(hex.size() / 2);
            for (size_t i = 0; i < hex.size(); i += 2) {
                auto hc = [](char c) -> uint8_t {
                    if (c >= '0' && c <= '9')
                        return (uint8_t)(c - '0');
                    if (c >= 'a' && c <= 'f')
                        return (uint8_t)(c - 'a' + 10);
                    return (uint8_t)(c - 'A' + 10);
                };
                raw.push_back((hc(hex[i]) << 4) | hc(hex[i + 1]));
            }
            Transaction tx;
            size_t consumed = Transaction::Deserialize(raw, 0, tx);
            if (consumed == 0) {
#ifdef VELD_DEBUG_LOG
                Hash256 fp = Hash256d(raw);
                std::cerr << "[sendrawtx] deserialize_failed len=" << raw.size()
                          << " fp=" << HashToHex(fp).substr(0, 16) << "\n";
                std::cerr.flush();
#endif
                throw std::invalid_argument("Failed to deserialize transaction");
            }
            if (consumed != raw.size()) {
#ifdef VELD_DEBUG_LOG
                std::cerr << "[sendrawtx] trailing_bytes consumed=" << consumed
                          << " total=" << raw.size() << "\n";
                std::cerr.flush();
#endif
                throw std::invalid_argument("Transaction has trailing bytes");
            }
            if (tx.Serialize() != raw) {
                throw std::invalid_argument("Transaction uses a non-canonical encoding");
            }
            if (!tx.IsValid()) {
#ifdef VELD_DEBUG_LOG
                Hash256 fp = Hash256d(raw);
                std::cerr << "[sendrawtx] isvalid_failed inputs=" << tx.inputs.size()
                          << " outputs=" << tx.outputs.size()
                          << " fp=" << HashToHex(fp).substr(0, 16) << "\n";
                std::cerr.flush();
#endif
                throw std::invalid_argument("Transaction failed basic validation");
            }

            std::optional<rpc_detail::ValidatorEndorsementTarget> endorsement_target;
            if (!rpc_detail::ExtractValidatorEndorsementTarget(tx, endorsement_target)) {
                throw rpc_error(-32602, "malformed or noncanonical validator endorsement");
            }
            std::optional<work_admission::Binding> endorsement_binding;
            std::function<bool()> endorsement_work_open;
            if (endorsement_target) {
                if (params.size() != 3)
                    throw rpc_error(-32602, "validator endorsement requires its work binding and "
                                            "one-use signing token");
                endorsement_binding = work_admission::DecodeBinding(params[1]);
                if (!endorsement_binding ||
                    work_admission::EncodeBinding(*endorsement_binding) != params[1]) {
                    throw rpc_error(-32602, "invalid validator work binding");
                }
                endorsement_work_open = [this, &endorsement_target, &endorsement_binding]() {
                    if (!work_admission_fn_ || !endorsement_target || !endorsement_binding)
                        return false;
                    Block tip;
                    if (!chain_.TryTip(tip))
                        return false;
                    work_admission::Subject subject;
                    subject.purpose = work_admission::Purpose::ValidatorEndorsement;
                    subject.height = endorsement_target->height;
                    subject.target_hash = endorsement_target->hash;
                    subject.parent_height = tip.height;
                    subject.parent_hash = tip.GetHash();
                    try {
                        const auto decision =
                            work_admission_fn_(work_admission::Path::ValidatorEndorsement, subject,
                                               endorsement_binding, true);
                        return decision.allowed;
                    } catch (...) {
                        return false;
                    }
                };
                if (!endorsement_work_open())
                    throw rpc_error(-32010, "validator endorsement work admission refused");
            } else if (params.size() != 1) {
                throw rpc_error(-32602, "Usage: sendrawtransaction <raw_tx_hex>");
            }
            uint64_t real_fee = 0;
            {
                uint64_t input_total = 0;
                bool inputs_known = true;
                bool overflow = false;
                for (const auto& inp : tx.inputs) {
                    auto utxo = chain_.GetUTXO(inp.prev_tx_hash, inp.prev_out_index);
                    if (!utxo) {
                        inputs_known = false;
                        break;
                    }
                    if (utxo->value > MAX_SUPPLY_UNITS || input_total > UINT64_MAX - utxo->value) {
                        overflow = true;
                        inputs_known = false;
                        break;
                    }
                    input_total += utxo->value;
                }
                if (overflow)
                    throw std::invalid_argument("Rejected: input_value_out_of_range");
                if (inputs_known) {
                    uint64_t output_total = tx.TotalOutput();
                    if (output_total > input_total)
                        throw std::invalid_argument("Rejected: outputs_exceed_inputs");
                    real_fee = input_total - output_total;
                    if (real_fee < MIN_TX_FEE)
                        throw std::invalid_argument("Rejected: fee_below_min_tx_fee");
                }
            }

            {
                std::string cons_reason;
                if (!chain_.ValidateTransactionLocking(tx, false)) {
                    for (const auto& out : tx.outputs) {
                        if (!out.script_pubkey.empty() && out.script_pubkey[0] == 0x6A &&
                            out.script_pubkey.size() > MAX_OP_RETURN_SCRIPT_PUBKEY_BYTES) {
                            cons_reason = "op_return_too_large";
                            break;
                        }
                    }
                    if (cons_reason.empty()) {
                        if (tx.inputs.empty())
                            cons_reason = "no_inputs";
                        else {
                            for (size_t ii = 0; ii < tx.inputs.size(); ++ii) {
                                auto utxo = chain_.GetUTXO(tx.inputs[ii].prev_tx_hash,
                                                           tx.inputs[ii].prev_out_index);
                                if (!utxo) {
                                    cons_reason = "utxo_missing_input_" + std::to_string(ii);
                                    break;
                                }
                            }
                            if (cons_reason.empty()) {
                                uint64_t in_sum = 0, out_sum = tx.TotalOutput();
                                bool ovf = false;
                                for (const auto& inp : tx.inputs) {
                                    auto u = chain_.GetUTXO(inp.prev_tx_hash, inp.prev_out_index);
                                    if (!u) {
                                        ovf = true;
                                        break;
                                    }
                                    if (in_sum > UINT64_MAX - u->value) {
                                        ovf = true;
                                        break;
                                    }
                                    in_sum += u->value;
                                }
                                if (ovf)
                                    cons_reason = "input_value_overflow";
                                else if (out_sum > in_sum)
                                    cons_reason = "outputs_exceed_inputs";
                                else
                                    cons_reason = "consensus_rejected_unknown_subcause";
                            }
                        }
                    }
                    std::cerr << "  [rpc] sendrawtransaction REJECTED: " << cons_reason
                              << " (txid=";
                    auto txid = tx.GetTxID();
                    for (int i = 0; i < 8; ++i) {
                        char buf[3];
                        snprintf(buf, sizeof(buf), "%02x", txid[i]);
                        std::cerr << buf;
                    }
                    std::cerr << "...)\n";
                    std::cerr.flush();
                    throw std::invalid_argument("Rejected: " + cons_reason);
                }
            }

            bool authorized_sink_broadcast = false;
            Mempool::AddResult result = Mempool::AddResult::INVALID;
            if (endorsement_target) {
                if (!validator_endorsement_sink_fn_)
                    throw rpc_error(-32010, "validator endorsement sink is not wired");
                AuthorizedWorkTxResult sink_result;
                try {
                    sink_result =
                        validator_endorsement_sink_fn_(tx, real_fee, params[1], params[2], false);
                } catch (...) {
                    sink_result.reason = "sink_exception";
                }
                if (sink_result.deferred)
                    throw rpc_error(-32010,
                                    "validator endorsement deferred: " +
                                        (sink_result.reason.empty()
                                             ? std::string("retryable local-work-unavailable")
                                             : sink_result.reason));
                if (!sink_result.accepted)
                    throw std::invalid_argument(
                        "Rejected: " + (sink_result.reason.empty()
                                            ? std::string("validator work admission refused")
                                            : sink_result.reason));
                result = Mempool::AddResult::ACCEPTED;
                authorized_sink_broadcast = true;
            } else {
                result = mempool_.Add(tx, real_fee, (uint32_t)chain_.Height(), chain_);
            }
            if (result != Mempool::AddResult::ACCEPTED) {
                std::string reason;
                switch (result) {
                case Mempool::AddResult::DUPLICATE:
                    reason = "duplicate";
                    break;
                case Mempool::AddResult::FEE_TOO_LOW:
                    reason = "fee too low";
                    break;
                case Mempool::AddResult::DOUBLE_SPEND:
                    reason = "double spend";
                    break;
                case Mempool::AddResult::FULL:
                    reason = "mempool full";
                    break;
                case Mempool::AddResult::STAKE_ALREADY_PENDING:
                    reason = "a stake transaction for this address is already pending in the "
                             "mempool; wait for it to confirm";
                    break;
                case Mempool::AddResult::STAKE_EXCEEDS_BALANCE:
                    reason = "stake amount exceeds the address's on-chain spendable balance";
                    break;
                case Mempool::AddResult::COINBASE_IMMATURE:
                    reason = "input spends a coinbase output that has not yet matured (needs 100 "
                             "confirmations)";
                    break;
                case Mempool::AddResult::VALIDATOR_STATE_COOLDOWN:
                    reason = "validator REGISTER/DEREGISTER cooldown still active for this address";
                    break;
                case Mempool::AddResult::PUBLIC_TESTNET_EXTERNAL_VALUE_DISABLED:
                    reason = "public testnet is disposable and valueless; external-value protocols "
                             "are disabled";
                    break;
                case Mempool::AddResult::RUNTIME_ADMISSION_CLOSED:
                    reason = "runtime admission is closed";
                    break;
                case Mempool::AddResult::DEFERRED_LOCAL_WORK:
                    throw rpc_error(-32010, "retryable local-work-unavailable");
                default:
                    reason = "invalid";
                    break;
                }
                throw std::invalid_argument("Rejected: " + reason);
            }
            if (!authorized_sink_broadcast && tx_broadcast_)
                tx_broadcast_(tx);

            for (const auto& out : tx.outputs) {
                if (out.value != 0)
                    continue;
                if (out.script_pubkey.size() < 2)
                    continue;
                if (out.script_pubkey[0] != 0x6A)
                    continue;
                size_t off = 1;
                size_t opdata_len = 0;
                if (out.script_pubkey[off] <= 75) {
                    opdata_len = out.script_pubkey[off++];
                } else if (out.script_pubkey[off] == 0x4C && out.script_pubkey.size() > off + 1) {
                    off++;
                    opdata_len = out.script_pubkey[off++];
                } else if (out.script_pubkey[off] == 0x4D && out.script_pubkey.size() > off + 2) {
                    off++;
                    opdata_len = out.script_pubkey[off] | (out.script_pubkey[off + 1] << 8);
                    off += 2;
                }
                if (off + opdata_len > out.script_pubkey.size())
                    continue;
                std::string opdata(out.script_pubkey.begin() + off,
                                   out.script_pubkey.begin() + off + opdata_len);
                static const std::string LOCK_PREFIX = "VELD_STAKE|LOCK|";
                if (opdata.rfind(LOCK_PREFIX, 0) != 0)
                    continue;
                size_t addr_start = LOCK_PREFIX.size();
                size_t addr_end = opdata.find('|', addr_start);
                if (addr_end == std::string::npos)
                    continue;
                std::string staker_addr = opdata.substr(addr_start, addr_end - addr_start);
                ClearStakeReservation(staker_addr);
                break;
            }

            return JB::String(HashToHex(tx.GetTxID()));
        });

        // rebroadcasttx <txid> — re-push an existing mempool TX to all peers.
        // Wallets call this when a send has sat unconfirmed for many minutes
        // (the user clicks the "Rebroadcast" chip on a pending row). Peer
        // churn or a transient relay gap can drop a TX from the rest of
        // the network's mempools even though we still hold it locally; this
        // walks the local mempool entry through tx_broadcast_ again so the
        // INV reaches every currently-connected peer. We deliberately do
        // NOT re-add to our own mempool (no fee bump, no replacement) —
        // this is a pure re-announcement of bytes we already validated.
        methods_["rebroadcasttx"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Usage: rebroadcasttx <txid>");
            const std::string& txid_hex = params[0];
            if (txid_hex.size() != 64)
                throw rpc_error(-32602, "invalid txid");
            for (char c : txid_hex) {
                bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                if (!ok)
                    throw rpc_error(-32602, "invalid txid (lowercase hex required)");
            }
            auto tx_opt = mempool_.GetTransaction(txid_hex);
            if (!tx_opt) {
                return JB::Object({
                    {"txid", JB::String(txid_hex)},
                    {"rebroadcast", JB::Bool(false)},
                    {"status", JB::String("not_in_mempool")},
                });
            }
            std::optional<rpc_detail::ValidatorEndorsementTarget> endorsement_target;
            if (!rpc_detail::ExtractValidatorEndorsementTarget(*tx_opt, endorsement_target)) {
                throw rpc_error(-32602, "mempool contains a malformed validator endorsement");
            }
            if (endorsement_target) {
                if (params.size() != 3)
                    throw rpc_error(-32602, "validator endorsement rebroadcast requires a fresh "
                                            "work binding and one-use signing token");
                if (!validator_endorsement_sink_fn_)
                    throw rpc_error(-32010, "validator endorsement sink is not wired");
                const auto sink_result =
                    validator_endorsement_sink_fn_(*tx_opt, 0, params[1], params[2], true);
                if (sink_result.deferred)
                    throw rpc_error(-32010,
                                    "validator endorsement rebroadcast deferred: " +
                                        (sink_result.reason.empty()
                                             ? std::string("retryable local-work-unavailable")
                                             : sink_result.reason));
                if (!sink_result.accepted)
                    throw rpc_error(-32010, "validator endorsement rebroadcast refused: " +
                                                sink_result.reason);
            } else {
                if (params.size() != 1)
                    throw rpc_error(-32602, "Usage: rebroadcasttx <txid>");
                if (tx_broadcast_)
                    tx_broadcast_(*tx_opt);
            }
            return JB::Object({
                {"txid", JB::String(txid_hex)},
                {"rebroadcast", JB::Bool(true)},
                {"status", JB::String("rebroadcast")},
            });
        });

        methods_["createtransaction"] = RpcMethod([this](const P&) -> std::string {
            throw std::runtime_error("createtransaction is disabled. Sign transactions client-side "
                                     "and submit via sendrawtransaction. See include/network/rpc.h "
                                     "for the preparerawtransaction flow.");
        });
        methods_["gettxspendingprevout"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() != 2)
                throw rpc_error(-32602, "Usage: gettxspendingprevout <txid> <vout>");
            const std::string& txid_hex = params[0];
            if (txid_hex.size() != 64)
                throw rpc_error(-32602, "invalid txid");
            for (char c : txid_hex) {
                const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                if (!ok)
                    throw rpc_error(-32602, "invalid txid (lowercase hex required)");
            }
            const Hash256 prev_txid = HexToHash(txid_hex);
            const uint32_t vout = ParseCanonicalRpcU32OrThrow(params[1], "vout");

            auto spender =
                rpc_detail::ResolveExactPrevoutSpender(chain_, mempool_, prev_txid, vout);
            if (spender && spender->confirmed) {
                const std::string spender_txid = HashToHex(spender->tx.GetTxID());
                return JB::Object({
                    {"status", JB::String("confirmed")},
                    {"txid", JB::String(spender_txid)},
                    {"raw_hex", JB::String(BytesToHex(spender->tx.Serialize()))},
                    {"block_height", JB::Number(spender->block_height)},
                    {"block_hash", JB::String(HashToHex(spender->block_hash))},
                });
            }
            if (spender) {
                const std::string spender_txid = HashToHex(spender->tx.GetTxID());
                return JB::Object({
                    {"status", JB::String("mempool")},
                    {"txid", JB::String(spender_txid)},
                    {"raw_hex", JB::String(BytesToHex(spender->tx.Serialize()))},
                });
            }
            return JB::Null();
        });
        methods_["gettxout"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() < 2)
                throw std::invalid_argument("Missing txid and vout");
            Hash256 txid = HexToHash(params[0]);
            const uint32_t vout = ParseCanonicalRpcU32OrThrow(params[1], "vout");
            auto utxo = chain_.GetUTXO(txid, vout);
            if (!utxo)
                return JB::Null();
            uint64_t tip = chain_.Height();
            uint64_t confs = (utxo->block_height <= tip) ? (tip - utxo->block_height + 1) : 0;
            return JB::Object({
                {"txid", JB::String(HashToHex(utxo->tx_hash))},
                {"vout", JB::Number((uint64_t)utxo->output_index)},
                {"value", JB::Float((double)utxo->value / VELD_UNITS)},
                {"value_units", JB::Number(utxo->value)},
                // N-01: offline/isolated policy signers must resolve the exact
                // prevout script and value from their own trusted node.  Do not
                // make them trust the transaction preparer's `inputs[]` claims.
                {"script_pubkey_hex", JB::String(BytesToHex(utxo->script_pubkey))},
                {"block_height", JB::Number(utxo->block_height)},
                {"confirmations", JB::Number(confs)},
                {"coinbase", JB::Bool(false)},
            });
        });

#ifndef VELD_PUBLIC_TESTNET
        methods_["setupwallet"] = RpcMethod([this](const P&) -> std::string {
            throw std::runtime_error(
                "setupwallet is disabled — install a miner key via veld-keygen "
                "or veld-node --setup. Remote key installation over RPC is not "
                "permitted (it bypassed the encrypted-key security model).");
        });

        methods_["getnewaddress"] = RpcMethod([](const P&) -> std::string {
            throw rpc_error(-32601, "method removed; use 'veld-keygen new' CLI");
        });
#endif

        methods_["getaddressfrompubkey"] = RpcMethod([](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Missing pubkey_hex");
            auto pk_hex = params[0];
            if (pk_hex.size() != 3904)
                throw std::invalid_argument(
                    "Public key must be 1952 bytes (3904 hex chars, ML-DSA-65)");
            std::array<uint8_t, 1952> pubkey;
            for (size_t i = 0; i < 1952; ++i)
                pubkey[i] = (uint8_t)std::stoi(pk_hex.substr(i * 2, 2), nullptr, 16);
#ifdef VELD_MAINNET_POW
            constexpr bool rpc_testnet_address = false;
#else
            constexpr bool rpc_testnet_address = true;
#endif
            std::string addr = PubKeyToAddress(pubkey, rpc_testnet_address);
            return "{\"address\":\"" + addr + "\"}";
        });

#ifndef VELD_PUBLIC_TESTNET
        methods_["generatekey"] = RpcMethod([](const P&) -> std::string {
            throw rpc_error(-32601, "method removed; use 'veld-keygen new' CLI");
        });

        methods_["createwallet"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() < 2)
                throw std::invalid_argument("Usage: createwallet <filename> <password>");
            std::string raw_name = params[0];
            for (char c : raw_name) {
                if (c == '/' || c == '\\' || c == 0) {
                    throw std::invalid_argument("wallet name may not contain path separators");
                }
            }
            if (raw_name.empty() || raw_name == "." || raw_name == ".." || raw_name.size() > 64 ||
                raw_name.find("..") != std::string::npos) {
                throw std::invalid_argument("invalid wallet name");
            }
            for (unsigned char c : raw_name) {
                const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
                if (!ok)
                    throw rpc_error(-32602, "wallet name may only contain [a-zA-Z0-9._-]");
            }

            const std::string wallets_dir = (datadir_.empty() ? "." : datadir_) + "/wallets";
            std::string secure_error;
            if (!channel::secure_file::EnsurePrivateDirectory(wallets_dir, &secure_error)) {
                throw std::runtime_error("Cannot secure wallet directory: " + secure_error);
            }
            const std::string filename = wallets_dir + "/" + raw_name;

            // Reject obvious duplicates before generating a key, while the
            // AtomicWriteNew publication below remains the authoritative
            // race-safe no-replace gate for concurrent callers.
            std::error_code path_ec;
            const auto destination_status = std::filesystem::symlink_status(filename, path_ec);
            if (!path_ec && destination_status.type() != std::filesystem::file_type::not_found) {
                throw rpc_error(-32602, "wallet already exists");
            }
            if (path_ec && path_ec != std::errc::no_such_file_or_directory) {
                throw std::runtime_error("Cannot safely inspect wallet destination: " +
                                         path_ec.message());
            }

            const std::string& password = params[1];
            std::string policy_error;
            if (!wallet_crypto::ValidateNewPassphrase(password, &policy_error))
                throw std::invalid_argument(policy_error);

            RealKeyPair kp = GenerateKeyPair(false);

            std::ostringstream plain;
            plain << "address=" << kp.address << "\n";
            plain << "privkey=";
            for (auto b : kp.private_key)
                plain << std::hex << std::setw(2) << std::setfill('0') << (int)b;
            plain << "\n";
            plain << "pubkey=";
            for (auto b : kp.public_key)
                plain << std::hex << std::setw(2) << std::setfill('0') << (int)b;
            plain << "\n";

            auto encrypted = wallet_crypto::EncryptWallet(plain.str(), password);
            const std::string magic = "VELDWALLET1\n";
            std::vector<uint8_t> wallet_frame;
            wallet_frame.reserve(magic.size() + encrypted.size());
            wallet_frame.insert(wallet_frame.end(), magic.begin(), magic.end());
            wallet_frame.insert(wallet_frame.end(), encrypted.begin(), encrypted.end());

            secure_error.clear();
            if (!channel::secure_file::AtomicWriteNew(filename, wallet_frame, &secure_error,
                                                      /*require_private_parent=*/true)) {
                throw rpc_error(-32602, secure_error.find("already exists") != std::string::npos
                                            ? "wallet already exists"
                                            : "Cannot create wallet file safely: " + secure_error);
            }

            return JB::Object({
                {"address", JB::String(kp.address)},
                {"wallet_file", JB::String(filename)},
                {"encrypted", JB::Bool(true)},
                {"warning", JB::String("Back up your wallet file and remember your password. "
                                       "There is no recovery if either is lost.")},
            });
        });

        methods_["openwallet"] = RpcMethod([this](const P& params) -> std::string {
            // Usage: openwallet <filename> <password>
            // Decrypts wallet file and returns address (NOT privkey — use dumpprivkey for that)
            if (params.size() < 2)
                throw std::invalid_argument("Usage: openwallet <filename> <password>");
            std::string raw_name = params[0];
            for (char c : raw_name) {
                if (c == '/' || c == '\\' || c == 0) {
                    throw std::invalid_argument("wallet name may not contain path separators");
                }
            }
            if (raw_name.empty() || raw_name == "." || raw_name == ".." || raw_name.size() > 64 ||
                raw_name.find("..") != std::string::npos) {
                throw std::invalid_argument("invalid wallet name");
            }
            std::string wallets_dir = (datadir_.empty() ? "." : datadir_) + "/wallets";
            std::string filename = wallets_dir + "/" + raw_name;
            const std::string& password = params[1];

            std::ifstream f(filename, std::ios::binary);
            if (!f)
                throw std::runtime_error("Cannot open wallet file: " + filename);

            const std::string magic = "VELDWALLET1\n";
            std::string hdr(magic.size(), 0);
            f.read(hdr.data(), magic.size());
            if (hdr != magic)
                throw std::runtime_error("Invalid wallet file format");

            std::vector<uint8_t> encrypted((std::istreambuf_iterator<char>(f)),
                                           std::istreambuf_iterator<char>());
            f.close();

            std::string plain;
            try {
                plain = wallet_crypto::DecryptWallet(encrypted, password);
            } catch (...) {
                throw std::runtime_error("Wrong password or corrupted wallet file");
            }

            std::string address, pubkey;
            std::istringstream ss(plain);
            std::string line;
            while (std::getline(ss, line)) {
                if (line.substr(0, 8) == "address=")
                    address = line.substr(8);
                if (line.substr(0, 7) == "pubkey=")
                    pubkey = line.substr(7);
            }
            if (address.empty())
                throw std::runtime_error("Corrupted wallet file — no address found");

            std::ostringstream j;
            j << "{";
            j << "\"address\":\"" << address << "\",";
            j << "\"pubkey\":\"" << pubkey << "\",";
            j << "\"wallet_file\":\"" << filename << "\"";
            j << "}";
            return j.str();
        });
#endif

#ifndef VELD_PUBLIC_TESTNET
        methods_["dumpprivkey"] =
            RpcMethod([](const P&) -> std::string { throw rpc_error(-32601, "method removed"); });
#endif

        methods_["validateaddress"] = RpcMethod([](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Missing address");
            const std::string& addr = params[0];
            uint8_t version = 0;
            std::vector<uint8_t> payload;
            bool valid = Base58CheckDecode(addr, version, payload) && payload.size() == 20 &&
                         (version == 0x46 || version == 0x6F);
            std::string network = (version == 0x6F) ? "testnet" :
#ifdef VELD_PUBLIC_TESTNET
                                                    "public-testnet";
#else
                                                    "mainnet";
#endif
            return JsonBuilder::Object({
                {"isvalid", JsonBuilder::Bool(valid)},
                {"address", JsonBuilder::String(addr)},
                {"ismine", JsonBuilder::Bool(false)},
                {"network", JsonBuilder::String(valid ? network : "unknown")},
#ifdef VELD_PUBLIC_TESTNET
                {"profile_id", JsonBuilder::String(DEPLOYMENT_PROFILE_ID)},
#endif
            });
        });

        methods_["getveldinfo"] = RpcMethod([](const P&) -> std::string {
            return JsonBuilder::Object({
                {"name", JsonBuilder::String("Veld")},
                {"ticker", JsonBuilder::String("VELD")},
                {"version", JsonBuilder::String(CLIENT_VERSION)},
                {"max_supply", JsonBuilder::Number((uint64_t)MAX_SUPPLY)},
                {"annual_emission", JsonBuilder::Number((uint64_t)ANNUAL_EMISSION_CAP)},
                {"block_time_secs", JsonBuilder::Number((uint64_t)TARGET_BLOCK_TIME)},
                {"blocks_per_year", JsonBuilder::Number((uint64_t)BLOCKS_PER_YEAR)},
                {"emission_years", JsonBuilder::Number((uint64_t)21)},
                {"tagline", JsonBuilder::String(
#ifdef VELD_PUBLIC_TESTNET
                                "Disposable public testnet; no external value.")},
#else
                                "Where value is earned.")},
#endif
            });
        });

        methods_["getblockbyheight"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Missing height");
            const uint64_t h = ParseCanonicalRpcU64OrThrow(params[0], "height");
            if (h > chain_.Height())
                throw std::runtime_error("Height out of range");
            Block blk = chain_.GetBlock(h);
            std::vector<std::string> tx_ids;
            for (const auto& tx : blk.transactions)
                tx_ids.push_back(JB::String(HashToHex(tx.GetTxID())));
            uint64_t reward = 0;
            if (!blk.transactions.empty()) {
                for (const auto& out : blk.transactions[0].outputs)
                    reward += out.value;
            }
            std::string miner_addr;
            if (!blk.transactions.empty()) {
                auto vault_script = AddressToScript(VAULT_ADDRESS);
                for (const auto& out : blk.transactions[0].outputs) {
                    if (out.script_pubkey.size() == 25 && out.script_pubkey[0] == 0x76) {
                        std::string addr = ScriptToAddress(out.script_pubkey);
                        if (!addr.empty() && addr != VAULT_ADDRESS) {
                            miner_addr = addr;
                            break;
                        }
                    }
                }
            }
            return JB::Object({
                {"hash", JB::String(HashToHex(blk.GetHash()))},
                {"height", JB::Number((uint64_t)h)},
                {"time", JB::Number((uint64_t)blk.header.timestamp)},
                {"nonce", JB::Number((uint64_t)blk.header.nonce)},
                {"bits", JB::Number((uint64_t)blk.header.bits)},
                {"tx", JB::Array(tx_ids)},
                {"ntx", JB::Number((uint64_t)blk.transactions.size())},
                {"reward", JB::Float((double)reward / VELD_UNITS)},
                {"miner", JB::String(miner_addr)},
                {"winner", JB::String(miner_addr)},
            });
        });

#ifndef VELD_PUBLIC_TESTNET
        methods_["gettokens"] = RpcMethod([this](const P&) -> std::string {
            if (!onchain_tokens_)
                return "[]";
            auto list = onchain_tokens_->ListTokens();
            std::ostringstream j;
            j << "[";
            bool first = true;
            for (auto& t : list) {
                if (!first)
                    j << ",";
                j << std::fixed << std::setprecision(8);
                j << "{\"id\":\"" << t.id << "\",\"name\":\"" << t.name << "\",\"issuer\":\""
                  << t.issuer << "\",\"supply\":" << onchain_tokens_->GetSupply(t.id) << "}";
                first = false;
            }
            j << "]";
            return j.str();
        });

        methods_["gettokenbalance"] = RpcMethod([this](const P& params) -> std::string {
            if (!onchain_tokens_ || params.size() < 2)
                throw std::invalid_argument("Usage: gettokenbalance TOKEN ADDRESS");
            double bal = onchain_tokens_->GetBalance(params[0], params[1]);
            std::ostringstream j;
            j << std::fixed << std::setprecision(8) << bal;
            return j.str();
        });
#endif

#ifndef VELD_PUBLIC_TESTNET
        // btcVELD redeem feed for the payout service:
        // Persistent, bounded redemption feed. params=[cursor,limit], where the
        // cursor is exclusive and opaque.  The node-owned index binds every row
        // to its canonical block hash and caps each response; the payout daemon
        // walks all pages and durably inserts each burn before maturity checks.
        methods_["getbtcveldredeems"] = RpcMethod([this](const P& params) -> std::string {
            if (!btcveld_redeem_page_fn_)
                throw std::runtime_error("persistent btcVELD redeem index is not configured");
            return btcveld_redeem_page_fn_(params);
        });

        // Total btcVELD supply (int64 sats) for the minter's supply<=custody
        // reconciliation invariant (the load-bearing peg guard, since
        // consensus trusts the issuer signature and does not verify BTC). Peg
        // dormant (issuer unset) => 0.
        methods_["getbtcveldsupply"] = RpcMethod([this](const P&) -> std::string {
            if (!btcveld_supply_snapshot_fn_)
                throw std::runtime_error("coherent btcVELD supply snapshot is not configured");
            return btcveld_supply_snapshot_fn_();
        });

        // Exact, authenticated issuer/SPV replay-domain query.  The derived
        // index rebuilds a target witness in bounded RAM and verifies its full
        // transition stream against the constant-size consensus root/count.
        methods_["getbtcveldmintstatus"] = RpcMethod([this](const P& params) -> std::string {
            if (!onchain_tokens_ || !btcveld_mint_proof_fn_)
                throw std::runtime_error("btcVELD nullifier proof index not available");
            if (params.size() != 1 || !IsValidBtcOutpointId(params[0]))
                throw std::invalid_argument(
                    "Usage: getbtcveldmintstatus <canonical-btc-txid:vout>");
            const BtcVeldMintProofStatus status = btcveld_mint_proof_fn_(params[0]);
            const std::vector<uint8_t> proof = btcnull::EncodeProof(status.proof);
            if (proof.empty() ||
                !btcnull::Verify(status.root, params[0], status.consumed, status.proof))
                throw std::runtime_error("btcVELD nullifier proof callback returned invalid state");
            return JB::Object({
                {"outpoint", JB::String(params[0])},
                {"consumed", JB::Bool(status.consumed)},
                {"minted", JB::Bool(status.minted)},
                {"proof_version", JB::String("MNP1")},
                {"proof_hex", JB::String(BytesToHex(proof))},
                {"root", JB::String(HashToHex(status.root))},
                {"count", JB::Number(status.count)},
                {"tip", JB::Number(status.tip)},
                {"tip_hash", JB::String(HashToHex(status.tip_hash))},
                {"accepted_txid", status.consumed ? JB::String(status.accepted_txid) : JB::Null()},
                {"accepted_block_height",
                 status.consumed ? JB::Number(status.accepted_block_height) : JB::Null()},
                {"accepted_block_hash",
                 status.consumed ? JB::String(HashToHex(status.accepted_block_hash)) : JB::Null()},
                {"accepted_tx_index",
                 status.consumed ? JB::Number(static_cast<uint64_t>(status.accepted_tx_index))
                                 : JB::Null()},
                {"accepted_marker_vout",
                 status.consumed ? JB::Number(static_cast<uint64_t>(status.accepted_marker_vout))
                                 : JB::Null()},
                {"accepted_effect_kind",
                 status.consumed ? JB::String(status.accepted_effect_kind) : JB::Null()},
                {"c1_allocation_id", status.consumed && !status.c1_allocation_id.empty()
                                         ? JB::String(status.c1_allocation_id)
                                         : JB::Null()},
                {"consumer_txid", status.consumed ? JB::String(status.consumer_txid) : JB::Null()},
                {"consumer_block_height",
                 status.consumed ? JB::Number(status.consumer_block_height) : JB::Null()},
                {"consumer_block_hash",
                 status.consumed ? JB::String(HashToHex(status.consumer_block_hash)) : JB::Null()},
                {"consumer_tx_index",
                 status.consumed ? JB::Number(static_cast<uint64_t>(status.consumer_tx_index))
                                 : JB::Null()},
                {"consumer_marker_vout",
                 status.consumed ? JB::Number(static_cast<uint64_t>(status.consumer_marker_vout))
                                 : JB::Null()},
                {"credit_txid", status.minted ? JB::String(status.credit_txid) : JB::Null()},
                {"credit_block_height",
                 status.minted ? JB::Number(status.credit_block_height) : JB::Null()},
                {"credit_block_hash",
                 status.minted ? JB::String(HashToHex(status.credit_block_hash)) : JB::Null()},
                {"credit_tx_index", status.minted
                                        ? JB::Number(static_cast<uint64_t>(status.credit_tx_index))
                                        : JB::Null()},
                {"credit_marker_vout",
                 status.minted ? JB::Number(static_cast<uint64_t>(status.credit_marker_vout))
                               : JB::Null()},
            });
        });
#endif

        // Informational/control-plane peg status for the wallet, anchor daemon,
        // and payout finality gate. This RPC is NOT solvency authorization: its
        // supply field must never be paired with its independently sampled tip
        // for minting. The signer/watchtower exclusively use getbtcveldsupply,
        // whose supply/tip/tip_hash tuple is atomically published after commit.
        // `active` is the legacy asset-registration flag: true iff an issuer
        // is compiled. It is intentionally NOT a mint authorization. Operators
        // must use mint_live / redeem_live / amm_live. Those fields describe the
        // next candidate height using the same launch profile and, after finality
        // has ever activated, liveness frame consumed by consensus validation.
#ifndef VELD_PUBLIC_TESTNET
        methods_["getpeginfo"] = RpcMethod([this](const P&) -> std::string {
            std::string issuer = BTCVELD_ISSUER_ADDRESS;
            const BtcVeldPegStatus peg =
                btcveld_peg_status_fn_ ? btcveld_peg_status_fn_() : BtcVeldPegStatus{};
            uint64_t tip = btcveld_peg_status_fn_ ? peg.tip : chain_.Height();
            uint64_t cap_height = tip;
            if (cap_height != UINT64_MAX)
                ++cap_height; // preparetokenmint target
            uint32_t cap_bits = chain_.ComputeNextBitsAt(tip);
            BtcVeldIssuerMintCapacity issuer_cap;
            if (onchain_tokens_) {
                issuer_cap = onchain_tokens_->GetBtcVeldIssuerMintCapacity(cap_height, cap_bits);
            } else {
                issuer_cap.height = cap_height;
                issuer_cap.includes_prospective_block = true;
                issuer_cap.prospective_block_bits = cap_bits;
                issuer_cap.tier_ladder_active = BtcVeldTierLadderActive(cap_height);
                issuer_cap.effective_ceiling_sats =
                    issuer_cap.tier_ladder_active
                        ? tierladder::EffectiveMintCeiling(issuer_cap.static_ceiling_sats, 0, 0)
                        : issuer_cap.static_ceiling_sats;
                issuer_cap.remaining_sats = issuer_cap.effective_ceiling_sats;
            }
            int64_t supply = issuer_cap.current_supply_sats;
            const btcveld::reserve::State reserve = onchain_tokens_
                                                        ? onchain_tokens_->GetBtcVeldReserveState()
                                                        : btcveld::reserve::State{};
            // The redeem service releases BTC only for burns at or below this
            // finality height. An unavailable finality source reports zero.
            uint64_t fin = btcveld_peg_status_fn_ ? peg.final_height
                                                  : (final_height_fn_ ? final_height_fn_() : 0);
            const std::string custody_spk = BytesToHex(BtcVeldCustodySpk());
            std::ostringstream j;
            j << "{\"active\":" << (issuer.empty() ? "false" : "true") << ",\"issuer\":\"" << issuer
              << "\""
              << ",\"token_id\":\"" << BTCVELD_TOKEN_ID << "\""
              << ",\"supply_sats\":" << supply << ",\"reserve_semantics\":"
              << (btcveld::reserve::TRANSITION_V1_REQUIRED ? "\"rolling-outpoint-v1\"" : "null")
              << ",\"reserve_status\":\"" << btcveld::reserve::StatusName(reserve.status) << "\""
              << ",\"reserve_txid\":\"" << HashToHex(reserve.reserve_txid) << "\""
              << ",\"reserve_vout\":" << reserve.reserve_vout
              << ",\"reserve_value_sats\":" << reserve.reserve_value_sats
              << ",\"reserve_bitcoin_block\":\"" << HashToHex(reserve.reserve_bitcoin_block) << "\""
              << ",\"reserve_transition_count\":" << reserve.transition_count
              << ",\"reserve_transition_commitment\":\"" << HashToHex(reserve.transition_commitment)
              << "\""
              << ",\"reserve_surplus_sats\":" << reserve.surplus_sats
              << ",\"open_redemption_principal_sats\":" << reserve.open_redemption_principal
              << ",\"reserve_processed_veld_height\":" << reserve.processed_veld_height
              << ",\"reserve_processed_veld_block_hash\":\""
              << HashToHex(reserve.processed_veld_block_hash) << "\""
              << ",\"reserve_accounting_holds\":"
              << ((supply >= 0 && reserve.AccountingHolds(static_cast<uint64_t>(supply))) ? "true"
                                                                                          : "false")
              << ",\"public_mint_proof_version\":\""
              << (btcveld::reserve::TRANSITION_V1_REQUIRED ? "RTP1" : "MSP3") << "\""
              << ",\"activation_height\":"
              << BTCVELD_ACTIVATION_HEIGHT
              // `spv_active` authorizes the next candidate operation, just like
              // mint_live/redeem_live/amm_live. Preserve explicit current-tip
              // and candidate fields so status never conflates the two views.
              << ",\"spv_active\":" << (BtcVeldSpvActive(cap_height) ? "true" : "false")
              << ",\"spv_active_current_tip\":" << (BtcVeldSpvActive(tip) ? "true" : "false")
              << ",\"spv_active_next_candidate\":"
              << (BtcVeldSpvActive(cap_height) ? "true" : "false")
              << ",\"issuer_static_custody_cap_sats\":" << issuer_cap.static_ceiling_sats
              << ",\"issuer_effective_custody_cap_sats\":" << issuer_cap.effective_ceiling_sats
              << ",\"issuer_effective_cap_height\":" << issuer_cap.height
              << ",\"issuer_reserved_sats\":" << issuer_cap.reserved_sats
              << ",\"issuer_mint_headroom_sats\":" << issuer_cap.remaining_sats
              << ",\"spv_max_custody_sats\":" << BTCVELD_SPV_MAX_CUSTODY_SATS
              << ",\"spv_k_btc\":" << BTCVELD_SPV_K_BTC << ",\"custody_descriptor_sha256\":\""
              << BTCVELD_CUSTODY_DESCRIPTOR_SHA256 << "\""
              << ",\"custody_manifest_sha256\":\"" << BTCVELD_CUSTODY_MANIFEST_SHA256 << "\""
              << ",\"custody_descriptor_range\":[" << BTCVELD_CUSTODY_DESCRIPTOR_RANGE_START << ","
              << BTCVELD_CUSTODY_DESCRIPTOR_RANGE_END << "]"
              << ",\"spv_custody_descriptor_index\":" << BTCVELD_SPV_CUSTODY_DESCRIPTOR_INDEX
              << ",\"spv_custody_spk_hex\":\"" << custody_spk << "\""
              << ",\"peg_unlocked\":" << (peg.gate.unlocked ? "true" : "false")
              << ",\"mint_live\":" << (peg.gate.MintAllowed() ? "true" : "false")
              << ",\"completion_live\":" << (peg.gate.CompletionAllowed() ? "true" : "false")
              << ",\"redeem_live\":" << (peg.gate.RedeemAllowed() ? "true" : "false")
              << ",\"amm_live\":" << (peg.gate.AmmAllowed() ? "true" : "false")
              << ",\"gate_reason\":\"" << peg.reason << "\""
              << ",\"anchor_promoted\":" << (peg.anchor_promoted ? "true" : "false")
              << ",\"finality_ever_active\":" << (peg.finality_ever_active ? "true" : "false")
              << ",\"finality_active\":" << (peg.finality_active ? "true" : "false")
              << ",\"final_height\":" << fin << ",\"tip\":" << tip << "}";
            return j.str();
        });
#endif

#ifndef VELD_PUBLIC_TESTNET
        // btcVELD SPV relay status: the node's in-consensus BTC-header view. The
        // header-relay daemon (swap/veld_btcrelayd.py) reads best_height to know which
        // Bitcoin headers are still missing from consensus, then submits the gap as
        // VELD_BHDR ops. best_height is a race-free snapshot taken by the block thread.
        // Read-only. Dormant (SPV off) => best_height 0, spv_active false.
        methods_["getbtcheaderinfo"] = RpcMethod([this](const P&) -> std::string {
            if (btc_header_info_fn_)
                return btc_header_info_fn_();
            return std::string(
                "{\"spv_active\":false,\"spv_active_current_tip\":false,"
                "\"spv_active_next_candidate\":false,\"best_height\":0,\"k_btc\":0}");
        });

        // btcVELD Layer-2 anchor status: the high-water Veld height committed into Bitcoin and
        // recorded by consensus (AnchorSet). The anchor daemon (swap/veld_anchord.py) reads this
        // to confirm its relayed VELD_ANCHOR op landed. Dormant (anchoring off) => high_water 0.
        methods_["getanchorinfo"] = RpcMethod([this](const P&) -> std::string {
            if (anchor_info_fn_)
                return anchor_info_fn_();
            return std::string(
                "{\"anchor_active\":false,\"anchor_admission_live\":false,"
                "\"anchor_checkpoint_enforced\":false,\"anchor_security_milestone\":false,"
                "\"high_water\":0,\"active_count\":0,\"pending_count\":0,"
                "\"retired_count\":0,\"k_btc\":0}");
        });
#endif

        // Historical validation status. Qualified snapshot recovery reports
        // the independent peer-fed chainstate; --verify-pow reports the
        // optional same-datadir operator diagnostic.
        methods_["getverificationstatus"] = RpcMethod([this](const P&) -> std::string {
            if (pow_verify_status_fn_)
                return pow_verify_status_fn_();
            return std::string("{\"running\":false,\"failed\":false,\"diagnostic_complete\":false,"
                               "\"verified_height\":0,\"target_height\":0}");
        });

#ifndef VELD_FLEET_NO_MINE
        // Regtest-ONLY on-demand block generator (bitcoin-style `generate <count>`). Wired by
        // the node solely on the "Veld Regtest" network → unwired (error) on every testnet/
        // mainnet binary. Lets service integration tests mine deterministically without
        // the pacing/anchor guards of the live mining loop.
        methods_["generate"] = RpcMethod([this](const P& params) -> std::string {
            if (!generate_fn_)
                throw std::runtime_error(
                    "generate is regtest-only (not available on this network)");
            int n = 1;
            if (!params.empty()) {
                const uint64_t count = ParseCanonicalRpcU64OrThrow(params[0], "count");
                if (count > static_cast<uint64_t>(std::numeric_limits<int>::max()))
                    throw std::invalid_argument("count out of range (1..5000)");
                n = static_cast<int>(count);
            }
            if (n < 1 || n > 5000)
                throw std::invalid_argument("count out of range (1..5000)");
            GenerateResult generated = generate_fn_(n);
            if (!generated.error.empty() || generated.generated != static_cast<uint64_t>(n)) {
                std::ostringstream error;
                error << "generate failed after " << generated.generated << " of " << n
                      << " blocks";
                if (!generated.error.empty())
                    error << ": " << generated.error;
                throw std::runtime_error(error.str());
            }
            std::ostringstream j;
            j << "{\"generated\":" << generated.generated << ",\"height\":" << generated.height
              << "}";
            return j.str();
        });
#endif

#ifndef VELD_PUBLIC_TESTNET
        // Build the UNSIGNED tx that carries a PERMISSIONLESS btcVELD relay op as a single
        // value-0 OP_RETURN, funding ONLY the fee from <fund_addr>. Used by the header-relay
        // + SPV-mint operator to post VELD_BHDR / VELD_ANCHOR / VELD_MSPV ops that
        // exceed the 80-B memo cap
        // of preparerawtransaction (the consensus OP_RETURN cap is 32 KB; BuildOpReturnScript
        // emits PUSHDATA2). These ops are self-validated by consensus (a bad header/proof is
        // simply ignored — "a liar wastes only their own fee"), so this RPC guards only the op
        // PREFIX + size: it cannot post arbitrary data, only the known relay families. Symmetric
        // with preparetokenmint — the caller signs the returned sighashes (veld-keygen sign-tx
        // with the fund key) then broadcasts via sendrawtransaction.
        methods_["preparerawop"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() < 2)
                throw std::invalid_argument("Usage: preparerawop <fund_addr> <op_string>");
            const std::string& fund_addr = params[0];
            const std::string& op_string = params[1];
            static const std::string PFX_BHDR = "VELD_BHDR|";
            static const std::string PFX_ANCH = "VELD_ANCHOR|";
            static const std::string PFX_MSPV = "VELD_MSPV|";
            static const std::string PFX_RSV1 = "VELD_RSV1|";
            static const std::string PFX_ENDR = "VELD_VALIDATOR|ENDORSE|";
            const bool known =
                (op_string.rfind(PFX_BHDR, 0) == 0) || (op_string.rfind(PFX_ANCH, 0) == 0) ||
                (op_string.rfind(PFX_RSV1, 0) == 0) ||
                (!btcveld::reserve::TRANSITION_V1_REQUIRED && op_string.rfind(PFX_MSPV, 0) == 0) ||
                (op_string.rfind(PFX_ENDR, 0) == 0);
            if (!known)
                throw std::invalid_argument("op_string must begin with VELD_BHDR|, VELD_ANCHOR|, "
                                            "VELD_RSV1| (or legacy VELD_MSPV| where enabled), or "
                                            "VELD_VALIDATOR|ENDORSE|");
            const size_t op_max =
                (op_string.rfind(PFX_MSPV, 0) == 0 || op_string.rfind(PFX_RSV1, 0) == 0)
                    ? btcnull::MAX_MSPV_OP_PAYLOAD_BYTES
                    : 24000;
            if (op_string.size() < 12 || op_string.size() > op_max)
                throw std::invalid_argument(
                    "op_string length outside its canonical relay-family range");

            auto fund_script = AddressToScript(fund_addr);
            if (fund_script.empty())
                throw std::invalid_argument("Invalid fund address: " + fund_addr);

            const uint64_t fee_units = MIN_TX_FEE;
            WalletState ws = ComputeWalletState(fund_addr);
            if (ws.spendable_units < fee_units)
                throw std::runtime_error(
                    "fund address has no spendable VELD to cover the op tx fee");
            std::vector<UTXO> selected;
            uint64_t gathered = 0;
            for (auto& u : ws.selectable) {
                if (gathered >= fee_units)
                    break;
                selected.push_back(u);
                gathered += u.value;
            }
            if (gathered < fee_units)
                throw std::runtime_error("fund address cannot cover the op tx fee");

            Transaction tx;
            for (auto& u : selected) {
                TxInput in;
                in.prev_tx_hash = u.tx_hash;
                in.prev_out_index = u.output_index;
                tx.inputs.push_back(in);
            }
            uint64_t change = gathered - fee_units;
            if (change > 0)
                tx.outputs.push_back(TxOutput(change, fund_script)); // change -> fund addr
            tx.outputs.push_back(
                TxOutput((uint64_t)0, BuildOpReturnScript(op_string))); // the relay op

            auto raw = tx.Serialize();
            std::vector<std::string> input_items;
            std::vector<std::vector<uint8_t>> parent_raws;
            for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
                Hash256 sighash = ComputeSighash(tx, i, fund_script);
                const auto parent_raw = AuthenticatedParentRaw(selected[i]);
                parent_raws.push_back(parent_raw);
                input_items.push_back(JB::Object({
                    {"index", JB::Number((uint64_t)i)},
                    {"sighash_hex", JB::String(BytesToHex(sighash))},
                    {"prev_script_hex", JB::String(BytesToHex(fund_script))},
                    {"value", JB::Number(selected[i].value)},
                    {"parent_tx_hex", JB::String(BytesToHex(parent_raw))},
                }));
            }
            std::string intent_operation;
            if (op_string.rfind(PFX_BHDR, 0) == 0)
                intent_operation = PFX_BHDR;
            else if (op_string.rfind(PFX_ANCH, 0) == 0)
                intent_operation = PFX_ANCH;
            else if (op_string.rfind(PFX_RSV1, 0) == 0)
                intent_operation = PFX_RSV1;
            else if (op_string.rfind(PFX_MSPV, 0) == 0)
                intent_operation = PFX_MSPV;
            else
                intent_operation = "VALIDATOR_ENDORSEMENT";
            const auto signing_intent = offline_signing::MakeIntent(
                tx, parent_raws, intent_operation, "", 0, fund_addr, change, op_string);
            return JB::Object({
                {"unsigned_tx_hex", JB::String(BytesToHex(raw))},
                {"inputs", JB::Array(input_items)},
                {"total_input", JB::Number(gathered)},
                {"total_output", JB::Number(change)},
                {"fee", JB::Number(fee_units)},
                {"change", JB::Number(change)},
                {"signing_intent", SigningIntentJson(signing_intent)},
            });
        });

        // Canonical C1 capacity lease state.  The public allocator checks this
        // on its own node after the signer/coordinator broadcasts C1R1 and does
        // not reveal the Bitcoin address until `canonical_depth_reached` is
        // true.  The bounded-reorg depth is consensus configuration, not an
        // operator-supplied confirmation count.
        methods_["getbtcveldc1reservation"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() != 1 || !c1reserve::IsAllocationId(params[0]))
                throw std::invalid_argument(
                    "Usage: getbtcveldc1reservation <32-hex-sequence-allocation-id>");
            if (!onchain_tokens_)
                throw std::runtime_error("token ledger not available");
            const uint64_t tip = chain_.Height();
            const auto status = onchain_tokens_->GetBtcVeldC1Reservation(params[0], tip);
            uint64_t sequence = 0;
            if (!c1reserve::AllocationSequence(params[0], sequence))
                throw std::invalid_argument("invalid C1 allocation sequence");
            const BtcVeldC1SequenceState sequence_state =
                onchain_tokens_->GetBtcVeldC1SequenceState();
            const bool retired = !status.found && sequence <= sequence_state.last_sequence;
            uint64_t confirmations = 0;
            bool canonical_depth = false;
            // Address-publication authority is monotonic.  Funding must
            // not make an already 101-deep C1E1 look shallow again; its
            // separate confirmation fields describe C1F1 depth.
            const uint64_t authority_height =
                status.found && status.reservation.exposed
                    ? status.reservation.exposed_height
                    : (status.found ? status.reservation.created_height : 0);
            if (status.found && tip >= authority_height) {
                confirmations = tip - authority_height + 1;
                canonical_depth = confirmations >= c1reserve::FINALITY_DEPTH;
            }
            uint64_t reserve_confirmations = 0;
            uint64_t exposure_confirmations = 0;
            uint64_t funding_confirmations = 0;
            if (status.found && tip >= status.reservation.created_height)
                reserve_confirmations = tip - status.reservation.created_height + 1;
            if (status.found && status.reservation.exposed &&
                tip >= status.reservation.exposed_height)
                exposure_confirmations = tip - status.reservation.exposed_height + 1;
            if (status.found && status.reservation.funded &&
                tip >= status.reservation.funded_height)
                funding_confirmations = tip - status.reservation.funded_height + 1;
            uint64_t latest_funding_height = 0;
            uint64_t recommended_send_cutoff_height = 0;
            if (status.found && status.reservation.exposed) {
                if (!c1reserve::LatestFundingAcceptanceHeight(
                        status.reservation.funding_expires_height, latest_funding_height) ||
                    !c1reserve::RecommendedSendCutoffHeight(
                        status.reservation.funding_expires_height, recommended_send_cutoff_height))
                    throw std::runtime_error("C1 funding window state is malformed");
            }
            return JB::Object({
                {"allocation_id", JB::String(params[0])},
                {"found", JB::Bool(status.found)},
                {"active", JB::Bool(status.active)},
                {"retired", JB::Bool(retired)},
                {"sequence", JB::Number(sequence)},
                {"last_sequence", JB::Number(sequence_state.last_sequence)},
                {"sequence_history_count", JB::Number(sequence_state.count)},
                {"sequence_history_root", JB::String(HashToHex(sequence_state.history_root))},
                {"recipient", status.found ? JB::String(status.reservation.recipient) : JB::Null()},
                {"allocation_commitment",
                 status.found ? JB::String(status.reservation.allocation_commitment) : JB::Null()},
                {"amount_sats",
                 status.found ? JB::Number(static_cast<uint64_t>(status.reservation.amount_sats))
                              : JB::Null()},
                {"created_height",
                 status.found ? JB::Number(status.reservation.created_height) : JB::Null()},
                {"expires_height",
                 status.found ? JB::Number(status.reservation.expires_height) : JB::Null()},
                {"pre_exposure_expires_height",
                 status.found ? JB::Number(status.reservation.expires_height) : JB::Null()},
                {"exposed", JB::Bool(status.found && status.reservation.exposed)},
                {"exposed_height", status.found && status.reservation.exposed
                                       ? JB::Number(status.reservation.exposed_height)
                                       : JB::Null()},
                {"funding_starts_height", status.found && status.reservation.exposed
                                              ? JB::Number(status.reservation.funding_starts_height)
                                              : JB::Null()},
                {"funding_expires_height",
                 status.found && status.reservation.exposed
                     ? JB::Number(status.reservation.funding_expires_height)
                     : JB::Null()},
                {"funding_accepts_through_height", status.found && status.reservation.exposed
                                                       ? JB::Number(latest_funding_height)
                                                       : JB::Null()},
                {"recommended_send_cutoff_height", status.found && status.reservation.exposed
                                                       ? JB::Number(recommended_send_cutoff_height)
                                                       : JB::Null()},
                {"funded", JB::Bool(status.found && status.reservation.funded)},
                {"funded_height", status.found && status.reservation.funded
                                      ? JB::Number(status.reservation.funded_height)
                                      : JB::Null()},
                {"funding_outpoint", status.found && status.reservation.funded
                                         ? JB::String(status.reservation.funding_outpoint)
                                         : JB::Null()},
                {"tip", JB::Number(tip)},
                {"confirmations", JB::Number(confirmations)},
                {"reserve_confirmations",
                 status.found ? JB::Number(reserve_confirmations) : JB::Null()},
                {"reserve_canonical_depth_reached",
                 JB::Bool(status.found && reserve_confirmations >= c1reserve::FINALITY_DEPTH)},
                {"exposure_confirmations", status.found && status.reservation.exposed
                                               ? JB::Number(exposure_confirmations)
                                               : JB::Null()},
                {"exposure_canonical_depth_reached",
                 JB::Bool(status.found && status.reservation.exposed &&
                          exposure_confirmations >= c1reserve::FINALITY_DEPTH)},
                {"funding_confirmations", status.found && status.reservation.funded
                                              ? JB::Number(funding_confirmations)
                                              : JB::Null()},
                {"funding_canonical_depth_reached",
                 JB::Bool(status.found && status.reservation.funded &&
                          funding_confirmations >= c1reserve::FINALITY_DEPTH)},
                {"required_confirmations", JB::Number(c1reserve::FINALITY_DEPTH)},
                {"canonical_depth_reached", JB::Bool(canonical_depth)},
            });
        });

        // Build one issuer-signed C1R1 lease carrier.  The accepted block, not
        // this RPC's wall clock or claimed target, deterministically assigns
        // the seven-day expiry height.
        methods_["preparebtcveldc1reservation"] = RpcMethod([this](const P& params) -> std::string {
            size_t argument_count = params.size();
            std::vector<std::string> excluded_issuer_prevouts;
            if (!params.empty() && rpc_detail::IsIssuerPrevoutExclusionParam(params.back())) {
                excluded_issuer_prevouts = rpc_detail::ParseIssuerPrevoutExclusions(params.back());
                --argument_count;
            }
            if (argument_count < 5 || argument_count > 10)
                throw std::invalid_argument(
                    "Usage: preparebtcveldc1reservation <issuer> <recipient> "
                    "<amount_sats> <allocation_id> <allocation_commitment> "
                    "[RESERVE|EXPOSE|CANCEL|FUND] "
                    "[fund_script fund_blind fund_outpoint CFP1_hex] "
                    "[issuer-prevout-exclusions-v1:<sorted-outpoints>]");
            const std::string& issuer = params[0];
            const std::string& recipient = params[1];
            const std::string& request_id = params[3];
            const std::string& allocation_commitment = params[4];
            const std::string action = argument_count >= 6 ? params[5] : "RESERVE";
            const bool exposure = action == "EXPOSE";
            const bool cancellation = action == "CANCEL";
            const bool funding = action == "FUND";
            if (action != "RESERVE" && !exposure && !cancellation && !funding)
                throw std::invalid_argument(
                    "reservation action must be RESERVE, EXPOSE, CANCEL, or FUND");
            RequireAuthoritativeBtcVeldPegPermission_(
                (cancellation || funding) ? BtcVeldPegOperation::COMPLETION
                                          : BtcVeldPegOperation::MINT,
                (cancellation || funding) ? "C1 completion" : "C1 reservation");
            if (!onchain_tokens_)
                throw std::runtime_error("token ledger not available");
            if ((funding && argument_count != 10) ||
                (!funding && action == "RESERVE" && argument_count != 5 && argument_count != 6) ||
                (!funding && action != "RESERVE" && argument_count != 6))
                throw std::invalid_argument(
                    "FUND requires script/blind/outpoint/proof; other actions do not");
            if (issuer != std::string(BTCVELD_ISSUER_ADDRESS) || issuer.empty())
                throw std::invalid_argument("issuer is not the configured btcVELD issuer");
            if (!IsCanonicalTokenCreditAddress(recipient))
                throw std::invalid_argument("recipient must be a canonical Veld P2PKH account");
            int64_t amount_sats = 0;
            if (!ParseCanonicalAmmI64(params[2], &amount_sats) ||
                amount_sats < c1reserve::MIN_SATS || amount_sats > BTCVELD_ISSUER_MAX_CUSTODY_SATS)
                throw std::invalid_argument("reservation amount is below 10,000 sats or above the "
                                            "absolute custody ceiling");
            if (!c1reserve::IsAllocationId(request_id) ||
                !c1reserve::IsCommitmentHex(allocation_commitment))
                throw std::invalid_argument(
                    "request id or blinded allocation commitment is not canonical");
            uint64_t target_height = chain_.Height();
            const uint64_t target_tip = target_height;
            if (target_height != UINT64_MAX)
                ++target_height;
            const uint32_t target_bits = chain_.ComputeNextBitsAt(target_tip);
            const auto existing =
                onchain_tokens_->GetBtcVeldC1Reservation(request_id, target_height);
            uint64_t request_sequence = 0;
            if (!c1reserve::AllocationSequence(request_id, request_sequence))
                throw std::invalid_argument("C1 allocation id is not a canonical uint64 sequence");
            const BtcVeldC1SequenceState sequence_state =
                onchain_tokens_->GetBtcVeldC1SequenceState();
            std::string memo;
            if (funding) {
                uint64_t latest_funding_height = 0;
                if (!existing.found || !existing.active || !existing.reservation.exposed ||
                    existing.reservation.funded || existing.reservation.recipient != recipient ||
                    existing.reservation.amount_sats != amount_sats ||
                    existing.reservation.allocation_commitment != allocation_commitment ||
                    target_height < existing.reservation.funding_starts_height ||
                    !c1reserve::LatestFundingAcceptanceHeight(
                        existing.reservation.funding_expires_height, latest_funding_height) ||
                    target_height > latest_funding_height ||
                    c1reserve::AllocationCommitment(request_id, recipient, amount_sats, params[6],
                                                    params[7]) !=
                        existing.reservation.allocation_commitment)
                    throw std::runtime_error("matching fundable C1 reservation is unavailable");
                memo = c1reserve::EncodeFundingMemo(request_id, params[6], params[7], params[8],
                                                    params[9]);
            } else if (exposure) {
                if (!existing.found || !existing.active || existing.reservation.exposed ||
                    !c1reserve::HasFinalityDepth(existing.reservation.created_height,
                                                 target_height) ||
                    existing.reservation.recipient != recipient ||
                    existing.reservation.amount_sats != amount_sats ||
                    existing.reservation.allocation_commitment != allocation_commitment)
                    throw std::runtime_error("matching unexposed C1 reservation is unavailable");
                memo = c1reserve::EncodeExposureMemo(request_id, allocation_commitment);
            } else {
                if (existing.found || sequence_state.last_sequence == UINT64_MAX ||
                    request_sequence != sequence_state.last_sequence + 1)
                    throw std::runtime_error("C1 allocation sequence is not exactly next");
                if (cancellation) {
                    memo = c1reserve::EncodeCancellationMemo(request_id, allocation_commitment);
                } else {
                    const auto cap =
                        onchain_tokens_->GetBtcVeldIssuerMintCapacity(target_height, target_bits);
                    if (!BtcVeldIssuerMintFitsCapacity(cap, amount_sats))
                        throw std::runtime_error(
                            "C1 reservation exceeds unreserved issuer headroom");
                    memo = c1reserve::EncodeMemo(request_id, allocation_commitment);
                }
            }
            if (memo.empty())
                throw std::runtime_error("C1 sequence/commitment is malformed");

            const auto issuer_script = AddressToScript(issuer);
            if (issuer_script.empty())
                throw std::invalid_argument("invalid issuer address");
            TokenOpData op;
            op.action = action;
            op.token_id = BTCVELD_TOKEN_ID;
            op.from = issuer;
            op.to = recipient;
            op.amount = amount_sats;
            op.memo = memo;

            const uint64_t fee_units = MIN_TX_FEE;
            WalletState ws = ComputeWalletState(issuer);
            if (ws.spendable_units < fee_units)
                throw std::runtime_error("issuer has no spendable VELD for the reservation fee");
            std::vector<UTXO> selected;
            uint64_t gathered = 0;
            for (auto& u : ws.selectable) {
                if (gathered >= fee_units)
                    break;
                if (rpc_detail::IssuerPrevoutIsExcluded(u, excluded_issuer_prevouts))
                    continue;
                selected.push_back(u);
                gathered += u.value;
            }
            if (gathered < fee_units)
                throw std::runtime_error("issuer cannot cover the reservation fee");
            Transaction tx;
            for (auto& u : selected) {
                TxInput input;
                input.prev_tx_hash = u.tx_hash;
                input.prev_out_index = u.output_index;
                tx.inputs.push_back(input);
            }
            const uint64_t change = gathered - fee_units;
            if (change > 0)
                tx.outputs.push_back(TxOutput(change, issuer_script));
            const std::string encoded_operation = EncodeTokenOp(op);
            tx.outputs.push_back(TxOutput(0, BuildOpReturnScript(encoded_operation)));
            const std::string unsigned_hex = BytesToHex(tx.Serialize());
            std::vector<std::string> input_items;
            std::vector<std::vector<uint8_t>> parent_raws;
            for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
                const Hash256 sighash = ComputeSighash(tx, i, issuer_script);
                const auto parent_raw = AuthenticatedParentRaw(selected[i]);
                parent_raws.push_back(parent_raw);
                input_items.push_back(JB::Object({
                    {"index", JB::Number(static_cast<uint64_t>(i))},
                    {"sighash_hex", JB::String(BytesToHex(sighash))},
                    {"prev_script_hex", JB::String(BytesToHex(issuer_script))},
                    {"value", JB::Number(selected[i].value)},
                    {"parent_tx_hex", JB::String(BytesToHex(parent_raw))},
                }));
            }
            const auto signing_intent = offline_signing::MakeIntent(
                tx, parent_raws, "BTCVELD_C1_" + action, recipient,
                static_cast<uint64_t>(amount_sats), issuer, change, encoded_operation);
            std::vector<std::string> excluded_items;
            for (const auto& outpoint : excluded_issuer_prevouts)
                excluded_items.push_back(JB::String(outpoint));
            return JB::Object({
                {"unsigned_tx_hex", JB::String(unsigned_hex)},
                {"inputs", JB::Array(input_items)},
                {"allocation_id", JB::String(request_id)},
                {"action", JB::String(action)},
                {"recipient", JB::String(recipient)},
                {"amount_sats", JB::Number(static_cast<uint64_t>(amount_sats))},
                {"allocation_commitment", JB::String(allocation_commitment)},
                {"sequence", JB::Number(request_sequence)},
                {"sequence_parent", JB::Number(sequence_state.last_sequence)},
                {"sequence_history_root", JB::String(HashToHex(sequence_state.history_root))},
                {"target_height", JB::Number(target_height)},
                {"lifetime_blocks", JB::Number(c1reserve::LIFETIME_BLOCKS)},
                {"required_confirmations", JB::Number(c1reserve::FINALITY_DEPTH)},
                {"excluded_issuer_prevouts", JB::Array(excluded_items)},
                {"fee", JB::Number(fee_units)},
                {"change", JB::Number(change)},
                {"total_input", JB::Number(gathered)},
                {"total_output", JB::Number(change)},
                {"signing_intent", SigningIntentJson(signing_intent)},
            });
        });

        // Build the UNSIGNED issuer MINT tx: an issuer-signed spend carrying a
        // trailing OP_RETURN MINT op (VELD_TOKEN|MINT|btcVELD|issuer|recipient|sats).
        // Consensus credits the recipient's btcVELD balance because the input is
        // signed by the issuer key (onchain_tokens.h::ApplyTokenOp). The >80-B-op
        // sibling of preparerawtransaction (whose memo caps at 80 B). No native VELD
        // goes to the recipient; the issuer funds only the fee + signs the sighashes.
        methods_["preparetokenmint"] = RpcMethod([this](const P& params) -> std::string {
            size_t argument_count = params.size();
            std::vector<std::string> excluded_issuer_prevouts;
            if (!params.empty() && rpc_detail::IsIssuerPrevoutExclusionParam(params.back())) {
                excluded_issuer_prevouts = rpc_detail::ParseIssuerPrevoutExclusions(params.back());
                --argument_count;
            }
            if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED) {
                if (argument_count != 4)
                    throw std::invalid_argument(
                        "Usage: preparetokenmint <issuer> <recipient> "
                        "<amount_sats> <rtp1_proof_hex> "
                        "[issuer-prevout-exclusions-v1:<sorted-outpoints>]");
                RequireAuthoritativeBtcVeldPegPermission_(BtcVeldPegOperation::MINT,
                                                          "RTP1 reserve mint transition");
                if (!onchain_tokens_)
                    throw std::runtime_error("token ledger not available");
                const std::string issuer = params[0];
                const std::string recipient = params[1];
                if (issuer != std::string(BTCVELD_ISSUER_ADDRESS))
                    throw std::invalid_argument("issuer is not the configured btcVELD issuer");
                if (!IsCanonicalTokenCreditAddress(recipient))
                    throw std::invalid_argument(
                        "Invalid recipient token account (canonical Veld P2PKH required)");
                int64_t amount_sats = 0;
                if (!ParseCanonicalAmmI64(params[2], &amount_sats) || amount_sats <= 0)
                    throw std::invalid_argument("amount_sats must be a positive canonical integer");
                const std::vector<uint8_t> proof = HexToBytes(params[3]);
                btcveld::reserve::Claim claim;
                if (proof.empty() || params[3] != BytesToHex(proof) ||
                    !btcveld::reserve::DecodeProof(proof.data(), proof.size(), claim) ||
                    (claim.operation != btcveld::reserve::Operation::OPEN &&
                     claim.operation != btcveld::reserve::Operation::DEPOSIT) ||
                    claim.mint_amount != static_cast<uint64_t>(amount_sats))
                    throw std::invalid_argument(
                        "RTP1 proof is non-canonical or does not describe the exact mint amount");

                const auto reserve_prior_state = onchain_tokens_->GetBtcVeldReserveState();
                const int64_t signed_supply = onchain_tokens_->GetSupply(BTCVELD_TOKEN_ID);
                if (signed_supply < 0)
                    throw std::runtime_error("btcVELD supply is not canonical");
                const BtcVeldReserveMintPolicyContext reserve_context{
                    reserve_prior_state, static_cast<uint64_t>(signed_supply)};
                const std::string reserve_memo =
                    std::string(btcveld::reserve::ISSUER_MEMO_PREFIX) + params[3];
                if (!BtcVeldReserveMintPolicyMemo(reserve_memo, recipient,
                                                  static_cast<uint64_t>(amount_sats),
                                                  &reserve_context))
                    throw std::invalid_argument("RTP1 proof is stale or differs from the canonical "
                                                "reserve transition decision");

                auto issuer_script = AddressToScript(issuer);
                if (issuer_script.empty())
                    throw std::invalid_argument("Invalid issuer address");
                TokenOpData op;
                op.action = "MINT";
                op.token_id = BTCVELD_TOKEN_ID;
                op.from = issuer;
                op.to = recipient;
                op.amount = amount_sats;
                op.memo = reserve_memo;
                if (op.memo.size() > MAX_TOKEN_MEMO_BYTES)
                    throw std::invalid_argument("RTP1 proof is oversized");

                const uint64_t fee_units = MIN_TX_FEE;
                WalletState ws = ComputeWalletState(issuer);
                std::vector<UTXO> selected;
                uint64_t gathered = 0;
                for (const auto& utxo : ws.selectable) {
                    if (gathered >= fee_units)
                        break;
                    if (rpc_detail::IssuerPrevoutIsExcluded(utxo, excluded_issuer_prevouts))
                        continue;
                    selected.push_back(utxo);
                    gathered += utxo.value;
                }
                if (gathered < fee_units)
                    throw std::runtime_error("issuer cannot cover the mint tx fee");
                Transaction tx;
                for (const auto& utxo : selected) {
                    TxInput input;
                    input.prev_tx_hash = utxo.tx_hash;
                    input.prev_out_index = utxo.output_index;
                    tx.inputs.push_back(input);
                }
                const uint64_t change = gathered - fee_units;
                if (change != 0)
                    tx.outputs.emplace_back(change, issuer_script);
                const std::string encoded_operation = EncodeTokenOp(op);
                tx.outputs.emplace_back(0, BuildOpReturnScript(encoded_operation));

                std::vector<std::string> input_items;
                std::vector<std::vector<uint8_t>> parent_raws;
                for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
                    const Hash256 sighash = ComputeSighash(tx, i, issuer_script);
                    const auto parent_raw = AuthenticatedParentRaw(selected[i]);
                    parent_raws.push_back(parent_raw);
                    input_items.push_back(JB::Object({
                        {"index", JB::Number(static_cast<uint64_t>(i))},
                        {"sighash_hex", JB::String(BytesToHex(sighash))},
                        {"prev_script_hex", JB::String(BytesToHex(issuer_script))},
                        {"value", JB::Number(selected[i].value)},
                        {"parent_tx_hex", JB::String(BytesToHex(parent_raw))},
                    }));
                }
                const auto signing_intent = offline_signing::MakeIntent(
                    tx, parent_raws, "BTCVELD_MINT", recipient, static_cast<uint64_t>(amount_sats),
                    issuer, change, encoded_operation);
                std::vector<std::string> excluded_items;
                for (const auto& outpoint : excluded_issuer_prevouts)
                    excluded_items.push_back(JB::String(outpoint));
                return JB::Object({
                    {"unsigned_tx_hex", JB::String(BytesToHex(tx.Serialize()))},
                    {"inputs", JB::Array(input_items)},
                    {"mint_sats", JB::Number(static_cast<uint64_t>(amount_sats))},
                    {"recipient", JB::String(recipient)},
                    {"fee", JB::Number(fee_units)},
                    {"change", JB::Number(change)},
                    {"total_input", JB::Number(gathered)},
                    {"total_output", JB::Number(change)},
                    {"proof_version", JB::String("RTP1")},
                    {"reserve_operation",
                     JB::String(btcveld::reserve::OperationName(claim.operation))},
                    {"reserve_prior_state_hex",
                     JB::String(BytesToHex(btcveld::reserve::EncodeState(reserve_prior_state)))},
                    {"reserve_prior_supply_sats", JB::Number(static_cast<uint64_t>(signed_supply))},
                    {"excluded_issuer_prevouts", JB::Array(excluded_items)},
                    {"signing_intent", SigningIntentJson(signing_intent)},
                });
            }
            if (argument_count < 3 || argument_count > 7)
                throw std::invalid_argument(
                    "Usage: preparetokenmint <issuer> <recipient> <amount_sats> "
                    "[deposit_outpoint] [c1_allocation_id] [c1_p2tr_script] "
                    "[c1_commitment_blind] "
                    "[issuer-prevout-exclusions-v1:<sorted-outpoints>]");
            const bool completion_requested = argument_count >= 5 && !params[4].empty();
            RequireAuthoritativeBtcVeldPegPermission_(
                completion_requested ? BtcVeldPegOperation::COMPLETION : BtcVeldPegOperation::MINT,
                completion_requested ? "C1 mint completion" : "mint");
            if (!onchain_tokens_)
                throw std::runtime_error("token ledger not available");

            std::string cfg_issuer = BTCVELD_ISSUER_ADDRESS;
            if (cfg_issuer.empty())
                throw std::runtime_error("btcVELD issuer not configured (peg dormant)");
            const std::string& issuer = params[0];
            const std::string& recipient = params[1];
            if (issuer != cfg_issuer)
                throw std::invalid_argument("issuer is not the configured btcVELD issuer");

            int64_t amount_sats = 0;
            if (!ParseCanonicalAmmI64(params[2], &amount_sats))
                throw std::invalid_argument("amount_sats must be a canonical integer (sats)");
            if (amount_sats <= 0)
                throw std::invalid_argument("amount_sats must be positive");
            // Query the same coherent tier-aware capacity snapshot used by
            // ApplyTokenOp. The target is the next block: using only the static
            // 1 BTC static cap here could strand a depositor while consensus remains
            // clamped to the 0.001 BTC pilot tier.
            uint64_t target_tip = chain_.Height();
            uint64_t target_height = target_tip;
            if (target_height != UINT64_MAX)
                ++target_height;
            uint32_t target_bits = chain_.ComputeNextBitsAt(target_tip);
            BtcVeldIssuerMintCapacity cap =
                onchain_tokens_->GetBtcVeldIssuerMintCapacity(target_height, target_bits);
            const std::string c1_request_id = argument_count >= 5 ? params[4] : "";
            const std::string c1_script_pubkey_hex = argument_count >= 6 ? params[5] : "";
            const std::string c1_commitment_blind_hex = argument_count >= 7 ? params[6] : "";
            if ((c1_request_id.empty()) != c1_script_pubkey_hex.empty() ||
                (c1_request_id.empty()) != c1_commitment_blind_hex.empty())
                throw std::invalid_argument(
                    "C1 request id, P2TR script, and blind are required together");
            BtcVeldC1ReservationStatus c1_status;
            if (!c1_request_id.empty()) {
                c1_status = onchain_tokens_->GetBtcVeldC1Reservation(c1_request_id, target_height);
                if (!c1_status.found || !c1_status.active || !c1_status.reservation.exposed ||
                    !c1_status.reservation.funded || c1_status.reservation.recipient != recipient ||
                    c1_status.reservation.amount_sats != amount_sats ||
                    c1reserve::AllocationCommitment(
                        c1_request_id, recipient, amount_sats, c1_script_pubkey_hex,
                        c1_commitment_blind_hex) != c1_status.reservation.allocation_commitment)
                    throw std::runtime_error(
                        "matching active C1 consensus reservation is unavailable");
            } else if (!BtcVeldIssuerMintFitsCapacity(cap, amount_sats))
                throw std::runtime_error(
                    "mint would exceed the effective issuer custody cap (" +
                    std::to_string(cap.effective_ceiling_sats) + " sats at height " +
                    std::to_string(cap.height) + "; current supply " +
                    std::to_string(cap.current_supply_sats) + "; remaining issuer headroom " +
                    std::to_string(cap.remaining_sats) + ")");

            const std::string deposit_outpoint = (argument_count >= 4) ? params[3] : "";
            if (BTCVELD_MINT_DEPOSIT_ID_ACTIVATION_HEIGHT != 0 &&
                !::veld::IsValidBtcOutpointId(deposit_outpoint))
                throw std::invalid_argument(
                    "btcVELD mint requires the funding BTC deposit outpoint "
                    "(txid:vout, lowercase) as the one-time mint id");
            if (!btcveld_mint_proof_fn_)
                throw std::runtime_error("btcVELD nullifier proof index not available");
            const BtcVeldMintProofStatus mint_status = btcveld_mint_proof_fn_(deposit_outpoint);
            if (c1_request_id.empty()) {
                if (mint_status.consumed)
                    throw std::runtime_error("btcVELD deposit outpoint was already consumed");
            } else if (!mint_status.consumed || mint_status.minted ||
                       mint_status.accepted_effect_kind != "C1_FUND" ||
                       mint_status.c1_allocation_id != c1_request_id ||
                       c1_status.reservation.funding_outpoint != deposit_outpoint) {
                throw std::runtime_error(
                    "btcVELD C1 funding effect is unavailable or already minted");
            }
            std::string memo =
                c1_request_id.empty()
                    ? btcnull::EncodeIssuerMemo(deposit_outpoint, mint_status.proof)
                    : btcnull::EncodeReservedIssuerMemo(c1_request_id, c1_script_pubkey_hex,
                                                        c1_commitment_blind_hex, deposit_outpoint);
            if (memo.empty() || memo.size() > MAX_TOKEN_MEMO_BYTES)
                throw std::runtime_error("btcVELD nullifier proof is malformed or oversized");

            auto issuer_script = AddressToScript(issuer);
            if (issuer_script.empty())
                throw std::invalid_argument("Invalid issuer address");
            if (!IsCanonicalTokenCreditAddress(recipient))
                throw std::invalid_argument(
                    "Invalid recipient token account (canonical Veld P2PKH required)");

            // The MINT OP_RETURN op (EncodeTokenOp is ~104 B, past the 80-B memo cap).
            TokenOpData op;
            op.action = "MINT";
            op.token_id = BTCVELD_TOKEN_ID;
            op.from = issuer;
            op.to = recipient;
            op.amount = amount_sats;
            op.memo = memo;
            const std::string encoded_operation = EncodeTokenOp(op);
            std::vector<uint8_t> op_out = BuildOpReturnScript(encoded_operation);

            // Fund only the fee from issuer UTXOs (the mint credits btcVELD to the
            // recipient via the op; it pays no native VELD to the recipient).
            const uint64_t fee_units = MIN_TX_FEE;
            WalletState ws = ComputeWalletState(issuer);
            if (ws.spendable_units < fee_units)
                throw std::runtime_error("issuer has no spendable VELD to fund the mint tx fee");
            std::vector<UTXO> selected;
            uint64_t gathered = 0;
            for (auto& u : ws.selectable) {
                if (gathered >= fee_units)
                    break;
                if (rpc_detail::IssuerPrevoutIsExcluded(u, excluded_issuer_prevouts))
                    continue;
                selected.push_back(u);
                gathered += u.value;
            }
            if (gathered < fee_units)
                throw std::runtime_error("issuer cannot cover the mint tx fee");

            Transaction tx;
            for (auto& u : selected) {
                TxInput in;
                in.prev_tx_hash = u.tx_hash;
                in.prev_out_index = u.output_index;
                tx.inputs.push_back(in);
            }
            uint64_t change = gathered - fee_units;
            if (change > 0)
                tx.outputs.push_back(TxOutput(change, issuer_script)); // change -> issuer
            tx.outputs.push_back(TxOutput((uint64_t)0, op_out));       // the MINT op

            auto raw = tx.Serialize();
            std::string unsigned_tx_hex = BytesToHex(raw);
            std::vector<std::string> input_items;
            std::vector<std::vector<uint8_t>> parent_raws;
            for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
                Hash256 sighash = ComputeSighash(tx, i, issuer_script);
                const auto parent_raw = AuthenticatedParentRaw(selected[i]);
                parent_raws.push_back(parent_raw);
                input_items.push_back(JB::Object({
                    {"index", JB::Number((uint64_t)i)},
                    {"sighash_hex", JB::String(BytesToHex(sighash))},
                    {"prev_script_hex", JB::String(BytesToHex(issuer_script))},
                    {"value", JB::Number(selected[i].value)},
                    {"parent_tx_hex", JB::String(BytesToHex(parent_raw))},
                }));
            }
            const auto signing_intent = offline_signing::MakeIntent(
                tx, parent_raws, "BTCVELD_MINT", recipient, static_cast<uint64_t>(amount_sats),
                issuer, change, encoded_operation);
            std::vector<std::string> excluded_items;
            for (const auto& outpoint : excluded_issuer_prevouts)
                excluded_items.push_back(JB::String(outpoint));
            return JB::Object({
                {"unsigned_tx_hex", JB::String(unsigned_tx_hex)},
                {"inputs", JB::Array(input_items)},
                {"mint_sats", JB::Number((uint64_t)amount_sats)},
                {"recipient", JB::String(recipient)},
                {"fee", JB::Number(fee_units)},
                {"change", JB::Number(change)},
                {"total_input", JB::Number(gathered)},
                {"total_output", JB::Number(change)},
                {"deposit_outpoint", JB::String(deposit_outpoint)},
                {"c1_allocation_id",
                 c1_request_id.empty() ? JB::Null() : JB::String(c1_request_id)},
                {"c1_script_pubkey_hex",
                 c1_request_id.empty() ? JB::Null() : JB::String(c1_script_pubkey_hex)},
                {"c1_commitment_blind_hex",
                 c1_request_id.empty() ? JB::Null() : JB::String(c1_commitment_blind_hex)},
                {"excluded_issuer_prevouts", JB::Array(excluded_items)},
                {"nullifier_root", JB::String(HashToHex(mint_status.root))},
                {"nullifier_count", JB::Number(mint_status.count)},
                {"signing_intent", SigningIntentJson(signing_intent)},
            });
        });

        // Build the UNSIGNED btcVELD REDEEM (burn) tx: a redeemer-signed spend
        // carrying a trailing OP_RETURN REDEEM op
        // (VELD_TOKEN|REDEEM|btcVELD|<redeemer>||<sats>|<dest_spk_hex>). Consensus
        // DESTROYS `sats` btcVELD from the redeemer and drops supply (because the
        // input is signed by the redeemer — onchain_tokens.h::ApplyTokenOp is_redeem),
        // and records the payout obligation (memo = the destination BTC scriptPubKey)
        // into the redeem feed (getbtcveldredeems) that the payout service
        // (swap/veld_redeemd.py) fulfils. The redeemer funds ONLY the native-VELD
        // fee (change returns to self); no native VELD leaves but the fee. The
        // >80-B-op sibling of preparerawtransaction (memo caps at 80 B), symmetric
        // with preparetokenmint on the mint leg.
        methods_["preparetokenredeem"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() < 3)
                throw std::invalid_argument("Usage: preparetokenredeem <redeemer> <amount_sats> "
                                            "<dest_btc_scriptpubkey_hex>");
            RequireAuthoritativeBtcVeldPegPermission_(BtcVeldPegOperation::REDEEM, "redeem");
            if (!onchain_tokens_)
                throw std::runtime_error("token ledger not available");
            if (std::string(BTCVELD_ISSUER_ADDRESS).empty())
                throw std::runtime_error("btcVELD issuer not configured (peg dormant)");

            const std::string& redeemer = params[0];
            int64_t amount_sats = 0;
            if (!ParseCanonicalAmmI64(params[1], &amount_sats))
                throw std::invalid_argument("amount_sats must be a canonical integer (sats)");
            if (amount_sats <= 0)
                throw std::invalid_argument("amount_sats must be positive");

            // dest BTC scriptPubKey: lowercase hex, even length, bounded to a
            // standard payout-script size (P2WPKH 22 B .. P2TR/P2WSH 34 B, with slack
            // for P2PKH 25 B / P2SH 23 B). Must never contain '|' (the op delimiter);
            // a hex string cannot. The daemon (veld_redeemd.py) independently resolves
            // it via bitcoind decodescript and FAILS CLOSED on a non-standard script,
            // so a malformed spk cannot cause a wrong payout — only a stuck redeem.
            std::string spk = params[2];
            for (auto& c : spk)
                if (c >= 'A' && c <= 'F')
                    c = (char)(c - 'A' + 'a');
            if (spk.size() < 4 || spk.size() > 100 || (spk.size() % 2) != 0)
                throw std::invalid_argument("dest scriptPubKey hex has an invalid length");
            for (char c : spk)
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                    throw std::invalid_argument("dest scriptPubKey must be hex");

            auto redeemer_script = AddressToScript(redeemer);
            if (!IsCanonicalTokenCreditAddress(redeemer))
                throw std::invalid_argument(
                    "Invalid redeemer token account (canonical Veld P2PKH required)");

            // UX pre-check (consensus re-checks exactly in ApplyTokenOp): the
            // redeemer must actually hold the btcVELD they are burning.
            // GetBalance is already an exact int64 count of token base units;
            // multiplying it by VELD_UNITS again overstates the balance by 1e8
            // and can build a transaction consensus will ignore after its fee
            // is spent.
            const int64_t have_sats = onchain_tokens_->GetBalance(BTCVELD_TOKEN_ID, redeemer);
            if (have_sats < amount_sats)
                throw std::runtime_error("redeemer btcVELD balance is less than the redeem amount");
            // Mirror the §5b drain-guard per-window ceiling so an over-ceiling
            // redeem fails LOUDLY here instead of building a tx consensus will
            // silently drop. (Consensus additionally enforces the live window
            // accumulator; a redeem that fits the ceiling but not the remaining
            // window budget is rejected on-chain and can be resubmitted next
            // window — nothing is burned either way.) Inert while dormant.
            if (BtcVeldRedeemGuardActive(chain_.Height() + 1)) {
                int64_t ceiling = redeemguard::LaunchWindowCeilingSats();
                if (amount_sats > ceiling)
                    throw std::invalid_argument("amount exceeds the per-window redeem ceiling (" +
                                                std::to_string(ceiling) +
                                                " sats) — split the redeem across windows");
            }

            // The REDEEM OP_RETURN op (to = "" — a burn has no recipient).
            TokenOpData op;
            op.action = "REDEEM";
            op.token_id = BTCVELD_TOKEN_ID;
            op.from = redeemer;
            op.to = "";
            op.amount = amount_sats;
            op.memo = spk;
            std::vector<uint8_t> op_out = BuildOpReturnScript(EncodeTokenOp(op));

            // Fund only the fee from the redeemer's native VELD UTXOs; change to self.
            const uint64_t fee_units = MIN_TX_FEE;
            WalletState ws = ComputeWalletState(redeemer);
            if (ws.spendable_units < fee_units)
                throw std::runtime_error(
                    "redeemer has no spendable VELD to fund the redeem tx fee");
            std::vector<UTXO> selected;
            uint64_t gathered = 0;
            for (auto& u : ws.selectable) {
                if (gathered >= fee_units)
                    break;
                selected.push_back(u);
                gathered += u.value;
            }
            if (gathered < fee_units)
                throw std::runtime_error("redeemer cannot cover the redeem tx fee");

            Transaction tx;
            for (auto& u : selected) {
                TxInput in;
                in.prev_tx_hash = u.tx_hash;
                in.prev_out_index = u.output_index;
                tx.inputs.push_back(in);
            }
            uint64_t change = gathered - fee_units;
            if (change > 0)
                tx.outputs.push_back(TxOutput(change, redeemer_script)); // change -> redeemer
            tx.outputs.push_back(TxOutput((uint64_t)0, op_out));         // the REDEEM op

            auto raw = tx.Serialize();
            std::string unsigned_tx_hex = BytesToHex(raw);
            std::vector<std::string> input_items;
            for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
                Hash256 sighash = ComputeSighash(tx, i, redeemer_script);
                input_items.push_back(JB::Object({
                    {"index", JB::Number((uint64_t)i)},
                    {"sighash_hex", JB::String(BytesToHex(sighash))},
                    {"prev_script_hex", JB::String(BytesToHex(redeemer_script))},
                }));
            }
            return JB::Object({
                {"unsigned_tx_hex", JB::String(unsigned_tx_hex)},
                {"inputs", JB::Array(input_items)},
                {"redeem_sats", JB::Number((uint64_t)amount_sats)},
                {"redeemer", JB::String(redeemer)},
                {"dest_spk_hex", JB::String(spk)},
                {"fee", JB::Number(fee_units)},
                {"change", JB::Number(change)},
            });
        });

        // btcVELD AMM pool state for the wallet swap/LP UI + monitoring: reserves,
        // LP supply, fee, and the mid price (VELD per btcVELD). Empty/absent pool
        // (production dormancy) returns exists:false.
        methods_["getammpool"] = RpcMethod([this](const P& params) -> std::string {
            if (!amm_)
                return "{\"error\":\"amm not available\"}";
            std::string pool_id = params.empty() ? std::string("VELD:btcVELD") : params[0];
            AmmPool p = amm_->GetPool(pool_id);
            std::ostringstream j;
            j << "{\"pool\":" << JB::String(pool_id)
              << ",\"exists\":" << (p.exists ? "true" : "false");
            if (p.exists) {
                uint32_t base_fee_bps = amm_->EffectiveFeeBps(pool_id);
                const uint64_t quote_height = chain_.Height() + 1;
                const bool anchor_valid = p.anchor_veld > 0 && p.anchor_btcveld > 0;
                const int64_t withdrawable_lp_supply =
                    p.lp_supply >= p.locked_lp ? p.lp_supply - p.locked_lp : 0;
                j << ",\"reserve_veld\":" << p.reserve_veld
                  << ",\"reserve_btcveld\":" << p.reserve_btcveld
                  << ",\"lp_supply\":" << p.lp_supply << ",\"locked_lp\":" << p.locked_lp
                  << ",\"withdrawable_lp_supply\":" << withdrawable_lp_supply
                  << ",\"seed_lock_veld_floor_sats\":" << AmmLedger::AMM_SEED_LOCK_VELD_UNITS
                  << ",\"seed_lock_btcveld_floor_sats\":" << AmmLedger::AMM_SEED_LOCK_BTCVELD_SATS
                  << ",\"pool_btcveld_cap_sats\":" << BTCVELD_AMM_MAX_POOL_BTCVELD_SATS
                  << ",\"fee_bps\":null"
                  << ",\"base_fee_bps\":" << base_fee_bps
                  << ",\"healing_fee_bps\":" << BTCVELD_AMM_FEE_MIN_BPS
                  << ",\"effective_fee_bps\":null"
                  << ",\"fee_quote_dependent\":true"
                  << ",\"fee_ceiling_bps\":" << BTCVELD_AMM_BAND_FEE_BPS[3] << ",\"fee_model\":\""
                  << AmmLedger::FEE_MODEL_ID << "\""
                  << ",\"fourband_activation_height\":" << BTCVELD_AMM_FOURBAND_ACTIVATION_HEIGHT
                  << ",\"quote_height\":" << quote_height << ",\"fee_model_active\":"
                  << (AmmLedger::FourBandActive(quote_height) ? "true" : "false")
                  << ",\"swap_allowed\":" << (ammgate::SwapAllowed(quote_height) ? "true" : "false")
                  << ",\"seed_liveness_policy\":" << JB::String(AmmLedger::SEED_LIVENESS_POLICY_ID)
                  << ",\"seed_liveness_tx_fee_units\":" << AMM_SEED_LIVENESS_TX_FEE_UNITS
                  << ",\"seed_liveness_fee_reserve_units\":" << AMM_SEED_LIVENESS_FEE_RESERVE_UNITS
                  << ",\"anchor_veld\":" << p.anchor_veld
                  << ",\"anchor_btcveld\":" << p.anchor_btcveld
                  << ",\"anchor_valid\":" << (anchor_valid ? "true" : "false")
                  << ",\"utxo_valid\":" << (p.utxo_valid ? "true" : "false");
                // Four permitted deviation bands (spec seed-ratio-output-asset-4band-v1). A
                // worsening trade pays the band its post-trade deviation lands in; a healing
                // trade (post-deviation <= pre-deviation) always pays healing_fee_bps.
                j << ",\"fee_bands\":[";
                for (int bi = 0; bi < 4; ++bi) {
                    if (bi)
                        j << ",";
                    j << "{\"band\":" << (bi + 1) << ",\"fee_bps\":" << BTCVELD_AMM_BAND_FEE_BPS[bi]
                      << ",\"max_deviation_bps\":";
                    if (bi < 3)
                        j << BTCVELD_AMM_BAND_EDGE_BPS[bi];
                    else
                        j << "null";
                    j << "}";
                }
                j << "]";
                // Normative field name from the public RPC contract. Keep the
                // older fee_bands alias above for client compatibility.
                j << ",\"bands\":[";
                for (int bi = 0; bi < 4; ++bi) {
                    if (bi)
                        j << ",";
                    j << "{\"band\":" << (bi + 1) << ",\"fee_bps\":" << BTCVELD_AMM_BAND_FEE_BPS[bi]
                      << ",\"max_deviation_bps\":";
                    if (bi < 3)
                        j << BTCVELD_AMM_BAND_EDGE_BPS[bi];
                    else
                        j << "null";
                    j << "}";
                }
                j << "]";
                if (anchor_valid && p.reserve_veld > 0 && p.reserve_btcveld > 0) {
                    const auto current_num = AmmLedger::AnchorCrossDistance(
                        p.reserve_veld, p.reserve_btcveld, p.anchor_veld, p.anchor_btcveld);
                    const auto current_den =
                        (unsigned __int128)(uint64_t)p.reserve_btcveld * (uint64_t)p.anchor_veld;
                    uint8_t current_band = 0;
                    AmmLedger::BandFeeBps(current_num, current_den, &current_band);
                    j << ",\"current_deviation_num\":\"" << AmmLedger::U128Decimal(current_num)
                      << "\""
                      << ",\"current_deviation_den\":\"" << AmmLedger::U128Decimal(current_den)
                      << "\""
                      << ",\"current_deviation_bps\":"
                      << AmmLedger::RatioBpsCapped(current_num, current_den)
                      << ",\"current_reserve_health_band\":" << (uint32_t)current_band;
                } else {
                    j << ",\"current_deviation_num\":null,\"current_deviation_den\":null"
                      << ",\"current_deviation_bps\":null,\"current_reserve_health_band\":null";
                }
                if (p.reserve_btcveld > 0)
                    j << ",\"price_veld_per_btcveld\":" << (p.reserve_veld / p.reserve_btcveld);
            }
            j << "}";
            return j.str();
        });

        // Build the UNSIGNED btcVELD AMM swap for browser signing. input[0] spends
        // the pool covenant UTXO (sigless-exempt at consensus); input[1..] are the
        // user's VELD (the swap-in on V2B, or just the fee on B2V). The browser
        // signs ONLY its own inputs (sighashes returned here) and submits via
        // sendrawtransaction. The block-covenant guard enforces x*y>=k + exact pool
        // recreation + the user signature, so a malformed proposal is rejected.
        methods_["prepareammswap"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() < 3)
                throw std::invalid_argument(
                    "Usage: prepareammswap <from> <v2b|b2v> <amount_in_sats> [pool_id]");
            RequireAuthoritativeBtcVeldPegPermission_(BtcVeldPegOperation::AMM, "AMM swap");
            if (!amm_)
                throw std::runtime_error("amm not available");
            // Layer-4 swap gate mirror: fail LOUDLY here instead of building a tx
            // consensus will drop. Inert while the gate is dormant.
            if (!ammgate::SwapAllowed(chain_.Height() + 1))
                throw std::runtime_error(
                    "AMM swaps have not reached the configured consensus unlock height "
                    "(Layer-4 gate) — wrap, redeem, and liquidity removal remain available");
            const std::string& from = params[0];
            std::string dir = params[1];
            int64_t amount_in = 0;
            if (!ParseCanonicalAmmI64(params[2], &amount_in))
                throw std::invalid_argument("amount_in must be a canonical integer (sats)");
            std::string pool_id = (params.size() >= 4 && !params[3].empty())
                                      ? params[3]
                                      : std::string("VELD:btcVELD");
            bool v2b = (dir == "v2b" || dir == "V2B" || dir == "SWAP_V2B");
            if (!v2b && dir != "b2v" && dir != "B2V" && dir != "SWAP_B2V")
                throw std::invalid_argument("direction must be v2b or b2v");
            if (amount_in <= 0)
                throw std::invalid_argument("amount_in must be positive");

            AmmPool p = amm_->GetPool(pool_id);
            if (!p.exists || !p.utxo_valid)
                throw std::runtime_error("pool not active");
            auto from_script = AddressToScript(from);
            if (!IsCanonicalTokenCreditAddress(from))
                throw std::invalid_argument(
                    "Invalid AMM token account (canonical Veld P2PKH required)");
            auto pool_script = PoolVeldScript(pool_id);

            const uint64_t quote_height = chain_.Height() + 1;
            AmmLedger::SwapQuote quote =
                amm_->QuoteSwapAtHeight(pool_id, v2b, amount_in, quote_height);
            int64_t out = quote.amount_out;
            if (quote.reject) {
                std::string detail = std::string("swap rejected: ") +
                                     AmmLedger::SwapRejectCodeName(quote.reject_code);
                if (quote.reject_code == AmmLedger::SwapRejectCode::FEE_SCHEDULE_NO_FIXED_POINT)
                    detail += " — try a slightly different amount";
                else if (quote.reject_code == AmmLedger::SwapRejectCode::INVALID_ANCHOR)
                    detail += " — immutable opening anchor is missing or invalid";
                throw std::runtime_error(detail);
            }
            if (out <= 0)
                throw std::runtime_error("swap too small for this pool (rounds to zero out)");
            int64_t new_rveld = quote.post_reserve_veld;
            int64_t new_rbtc = quote.post_reserve_btcveld;
            if (new_rveld <= 0 || (uint64_t)new_rveld < DUST_THRESHOLD_UNITS)
                throw std::runtime_error(
                    "swap would leave the native pool output below the consensus dust floor");
            if (!v2b && (uint64_t)out < DUST_THRESHOLD_UNITS)
                throw std::runtime_error(
                    "swap output is below the native VELD consensus dust floor");

            const uint64_t fee_units = MIN_TX_FEE;
            uint64_t need = v2b ? (uint64_t)amount_in + fee_units : fee_units;
            if (!v2b) {
                int64_t ubtc = onchain_tokens_ ? onchain_tokens_->GetBalance("btcVELD", from) : 0;
                if (ubtc < amount_in)
                    throw std::runtime_error("insufficient btcVELD: have " + std::to_string(ubtc) +
                                             " sats, need " + std::to_string(amount_in));
            }

            WalletState ws = ComputeWalletState(from);
            if (ws.spendable_units < need)
                throw std::runtime_error("insufficient spendable VELD: have " +
                                         std::to_string(ws.spendable_units) + " units, need " +
                                         std::to_string(need));
            std::vector<UTXO> selected;
            uint64_t gathered = 0;
            for (auto& u : ws.selectable) {
                if (gathered >= need &&
                    (gathered == need || gathered - need >= DUST_THRESHOLD_UNITS))
                    break;
                selected.push_back(u);
                if (gathered > UINT64_MAX - u.value)
                    throw std::runtime_error("selected VELD input total overflow");
                gathered += u.value;
            }
            if (selected.size() > AmmLedger::MAX_FUNDING_INPUTS)
                throw std::runtime_error(
                    "AMM funding needs more than " + std::to_string(AmmLedger::MAX_FUNDING_INPUTS) +
                    " inputs and would exceed the consensus-priority envelope (" +
                    std::to_string(AmmLedger::MAX_TX_BYTES / 1024) +
                    " KiB). Consolidate this wallet's UTXOs, wait for that "
                    "transaction to confirm, then prepare the swap again.");
            if (gathered < need)
                throw std::runtime_error("insufficient spendable VELD to fund the swap");
            if (gathered != need && gathered - need < DUST_THRESHOLD_UNITS)
                throw std::runtime_error("available VELD inputs would create dust change; "
                                         "consolidate or add another confirmed input");

            Transaction tx;
            {
                TxInput pin;
                pin.prev_tx_hash = p.pool_txid;
                pin.prev_out_index = p.pool_vout;
                tx.inputs.push_back(pin);
            }
            for (auto& u : selected) {
                TxInput in;
                in.prev_tx_hash = u.tx_hash;
                in.prev_out_index = u.output_index;
                tx.inputs.push_back(in);
            }

            tx.outputs.push_back(
                TxOutput((uint64_t)new_rveld, pool_script)); // output[0] = recreated pool UTXO
            if (v2b) {
                int64_t change = (int64_t)gathered - amount_in - (int64_t)fee_units;
                if (change > 0)
                    tx.outputs.push_back(
                        TxOutput((uint64_t)change, from_script)); // output[1] = change
            } else {
                tx.outputs.push_back(
                    TxOutput((uint64_t)out, from_script)); // output[1] = VELD payout
                int64_t change = (int64_t)gathered - (int64_t)fee_units;
                if (change > 0)
                    tx.outputs.push_back(
                        TxOutput((uint64_t)change, from_script)); // output[2] = change
            }
            AmmOp op;
            op.action = v2b ? "SWAP_V2B" : "SWAP_B2V";
            op.user = from;
            op.amt = amount_in;
            if (v2b)
                op.extra = out; // min btcVELD out
            tx.outputs.push_back(
                TxOutput((uint64_t)0, BuildOpReturnScript(EncodeAmmOp(op)))); // OP_RETURN AMM op

            auto raw = tx.Serialize();
            std::vector<std::string> input_items;
            // input[0] = pool covenant UTXO: consensus-sigless. Emit it with NO
            // sighash + a sigless flag so the browser's injectSignatures leaves its
            // scriptSig empty. The remaining entries are 1:1 with the user inputs.
            input_items.push_back(JB::Object({
                {"index", JB::Number((uint64_t)0)},
                {"sigless", JB::String("1")},
            }));
            for (uint32_t i = 1; i < tx.inputs.size(); ++i) { // user inputs get real sighashes
                Hash256 sighash = ComputeSighash(tx, i, from_script);
                input_items.push_back(JB::Object({
                    {"index", JB::Number((uint64_t)i)},
                    {"sighash_hex", JB::String(BytesToHex(sighash))},
                    {"prev_script_hex", JB::String(BytesToHex(from_script))},
                }));
            }
            return JB::Object({
                {"unsigned_tx_hex", JB::String(BytesToHex(raw))},
                {"inputs", JB::Array(input_items)},
                {"pool_input_index", JB::Number((uint64_t)0)},
                {"direction", JB::String(v2b ? "v2b" : "b2v")},
                {"quote_height", JB::Number(quote_height)},
                {"fee_model", JB::String(AmmLedger::FEE_MODEL_ID)},
                {"fourband_activation_height", JB::Number(BTCVELD_AMM_FOURBAND_ACTIVATION_HEIGHT)},
                {"amount_in_sats", JB::Number((uint64_t)amount_in)},
                {"amount_out_sats", JB::Number((uint64_t)out)},
                {"gross_out_sats", JB::Number((uint64_t)quote.gross_out)},
                {"min_out_sats", JB::Number((uint64_t)(v2b ? out : 0))},
                {"new_reserve_veld", JB::Number((uint64_t)new_rveld)},
                {"new_reserve_btcveld", JB::Number((uint64_t)new_rbtc)},
                {"fee_bps", JB::Number((uint64_t)quote.fee_bps)},
                {"fee_band", JB::Number((uint64_t)quote.band)},
                {"lp_fee_sats", JB::Number((uint64_t)quote.fee_out)},
                {"lp_fee_asset", JB::String(v2b ? "btcVELD" : "VELD")},
                {"anchor_veld", JB::Number((uint64_t)p.anchor_veld)},
                {"anchor_btcveld", JB::Number((uint64_t)p.anchor_btcveld)},
                {"pre_deviation_num", JB::String(AmmLedger::U128Decimal(quote.pre_deviation_num))},
                {"pre_deviation_den", JB::String(AmmLedger::U128Decimal(quote.pre_deviation_den))},
                {"post_deviation_num",
                 JB::String(AmmLedger::U128Decimal(quote.post_deviation_num))},
                {"post_deviation_den",
                 JB::String(AmmLedger::U128Decimal(quote.post_deviation_den))},
                {"pre_deviation_bps", JB::Number((uint64_t)quote.pre_deviation_bps)},
                {"post_deviation_bps", JB::Number((uint64_t)quote.post_deviation_bps)},
                {"rebalances_anchor", JB::Bool(quote.rebalances_anchor)},
                {"healing_override", JB::Bool(quote.rebalances_anchor)},
                {"network_fee_sats", JB::Number(fee_units)},
                {"fee", JB::Number(fee_units)},
            });
        });

        // The caller's LP position for the pool (raw shares + fractional share).
        methods_["getammlp"] = RpcMethod([this](const P& params) -> std::string {
            if (!amm_ || params.empty())
                return "{\"lp\":0,\"lp_supply\":0,\"share\":0}";
            std::string pool_id = (params.size() >= 2 && !params[1].empty())
                                      ? params[1]
                                      : std::string("VELD:btcVELD");
            int64_t lp = amm_->GetLp(pool_id, params[0]);
            AmmPool p = amm_->GetPool(pool_id);
            double share = (p.lp_supply > 0) ? (double)lp / (double)p.lp_supply : 0.0;
            std::ostringstream j;
            j << "{\"lp\":" << lp << ",\"lp_supply\":" << p.lp_supply << ",\"share\":" << std::fixed
              << std::setprecision(6) << share << "}";
            return j.str();
        });

        // UNSIGNED add-liquidity: deposit d_veld VELD (recreating the grown pool
        // UTXO) + the matching btcVELD (moved through the ledger). Browser signs
        // its own inputs. Mirrors AmmLedger::ApplyAdd.
        methods_["prepareammadd"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() < 2)
                throw std::invalid_argument("Usage: prepareammadd <from> <d_veld_sats> [pool_id]");
            RequireAuthoritativeBtcVeldPegPermission_(BtcVeldPegOperation::AMM,
                                                      "AMM add-liquidity");
            if (!amm_)
                throw std::runtime_error("amm not available");
            const std::string& from = params[0];
            int64_t d_veld = 0;
            if (!ParseCanonicalAmmI64(params[1], &d_veld))
                throw std::invalid_argument("d_veld must be a canonical integer (sats)");
            std::string pool_id = (params.size() >= 3 && !params[2].empty())
                                      ? params[2]
                                      : std::string("VELD:btcVELD");
            if (d_veld <= 0)
                throw std::invalid_argument("d_veld must be positive");
            AmmPool p = amm_->GetPool(pool_id);
            if (!p.exists || !p.utxo_valid || p.reserve_veld <= 0)
                throw std::runtime_error("pool not active");
            int64_t use_btc = 0;
            if (!AmmLedger::CheckedMulDivPositiveI64(d_veld, p.reserve_btcveld, p.reserve_veld,
                                                     &use_btc))
                throw std::runtime_error(
                    "add amount or current pool ratio exceeds the signed ledger range");
            int64_t lp_from_veld = 0;
            int64_t lp_from_btc = 0;
            if (!AmmLedger::CheckedMulDivPositiveI64(p.lp_supply, d_veld, p.reserve_veld,
                                                     &lp_from_veld) ||
                !AmmLedger::CheckedMulDivPositiveI64(p.lp_supply, use_btc, p.reserve_btcveld,
                                                     &lp_from_btc))
                throw std::runtime_error("add is too small for the pool's limiting reserve");
            const int64_t lp_minted = std::min(lp_from_veld, lp_from_btc);
            if (lp_minted > INT64_MAX - p.lp_supply)
                throw std::runtime_error("add would exceed the signed LP-supply range");
            const int64_t owner_lp = amm_->GetLp(pool_id, from);
            if (owner_lp < 0 || lp_minted > INT64_MAX - owner_lp)
                throw std::runtime_error("add would exceed the signed LP-balance range");
            if (d_veld > INT64_MAX - p.reserve_veld || use_btc > INT64_MAX - p.reserve_btcveld)
                throw std::runtime_error("add would overflow a pool reserve");
            // Layer-4 pool-cap mirror (consensus re-checks in ApplyAdd): the add's
            // proportional btcVELD leg must not push the reserve past the cap.
            if (!ammgate::PoolReserveAllowed(chain_.Height() + 1, p.reserve_btcveld,
                                             p.reserve_btcveld + use_btc))
                throw std::runtime_error(
                    "add would push the pool's btcVELD reserve past the Layer-4 pool cap (" +
                    std::to_string(BTCVELD_AMM_MAX_POOL_BTCVELD_SATS) + " sats)");
            auto from_script = AddressToScript(from);
            if (!IsCanonicalTokenCreditAddress(from))
                throw std::invalid_argument(
                    "Invalid AMM token account (canonical Veld P2PKH required)");
            auto pool_script = PoolVeldScript(pool_id);

            int64_t ubtc = onchain_tokens_ ? onchain_tokens_->GetBalance("btcVELD", from) : 0;
            if (ubtc < use_btc)
                throw std::runtime_error("insufficient btcVELD: need " + std::to_string(use_btc) +
                                         " sats, have " + std::to_string(ubtc));
            const unsigned __int128 extra_u =
                (unsigned __int128)(uint64_t)use_btc + (uint64_t)(use_btc / 100) + 1u;
            int64_t extra =
                extra_u > (unsigned __int128)INT64_MAX
                    ? INT64_MAX
                    : (int64_t)extra_u; // 1% buffer for pool drift between prepare + mine
            if (ubtc < extra)
                extra = ubtc;

            const uint64_t fee_units = MIN_TX_FEE;
            uint64_t need = (uint64_t)d_veld + fee_units;
            WalletState ws = ComputeWalletState(from);
            if (ws.spendable_units < need)
                throw std::runtime_error("insufficient spendable VELD");
            std::vector<UTXO> selected;
            uint64_t gathered = 0;
            for (auto& u : ws.selectable) {
                if (gathered >= need &&
                    (gathered == need || gathered - need >= DUST_THRESHOLD_UNITS))
                    break;
                selected.push_back(u);
                if (gathered > UINT64_MAX - u.value)
                    throw std::runtime_error("selected VELD input total overflow");
                gathered += u.value;
            }
            if (selected.size() > AmmLedger::MAX_FUNDING_INPUTS)
                throw std::runtime_error(
                    "AMM funding needs more than " + std::to_string(AmmLedger::MAX_FUNDING_INPUTS) +
                    " inputs and would exceed the consensus-priority envelope (" +
                    std::to_string(AmmLedger::MAX_TX_BYTES / 1024) +
                    " KiB). Consolidate this wallet's UTXOs, wait for that "
                    "transaction to confirm, then prepare the add again.");
            if (gathered < need)
                throw std::runtime_error("insufficient spendable VELD");
            if (gathered != need && gathered - need < DUST_THRESHOLD_UNITS)
                throw std::runtime_error("available VELD inputs would create dust change; "
                                         "consolidate or add another confirmed input");

            Transaction tx;
            {
                TxInput pin;
                pin.prev_tx_hash = p.pool_txid;
                pin.prev_out_index = p.pool_vout;
                tx.inputs.push_back(pin);
            }
            for (auto& u : selected) {
                TxInput in;
                in.prev_tx_hash = u.tx_hash;
                in.prev_out_index = u.output_index;
                tx.inputs.push_back(in);
            }
            tx.outputs.push_back(TxOutput((uint64_t)(p.reserve_veld + d_veld), pool_script));
            int64_t change = (int64_t)gathered - d_veld - (int64_t)fee_units;
            if (change > 0)
                tx.outputs.push_back(TxOutput((uint64_t)change, from_script));
            AmmOp op;
            op.action = "ADD";
            op.user = from;
            op.amt = d_veld;
            op.extra = extra;
            tx.outputs.push_back(TxOutput((uint64_t)0, BuildOpReturnScript(EncodeAmmOp(op))));

            auto raw = tx.Serialize();
            std::vector<std::string> input_items;
            input_items.push_back(
                JB::Object({{"index", JB::Number((uint64_t)0)}, {"sigless", JB::String("1")}}));
            for (uint32_t i = 1; i < tx.inputs.size(); ++i) {
                Hash256 sighash = ComputeSighash(tx, i, from_script);
                input_items.push_back(
                    JB::Object({{"index", JB::Number((uint64_t)i)},
                                {"sighash_hex", JB::String(BytesToHex(sighash))},
                                {"prev_script_hex", JB::String(BytesToHex(from_script))}}));
            }
            return JB::Object({{"unsigned_tx_hex", JB::String(BytesToHex(raw))},
                               {"inputs", JB::Array(input_items)},
                               {"d_veld_sats", JB::Number((uint64_t)d_veld)},
                               {"btcveld_used_sats", JB::Number((uint64_t)use_btc)},
                               {"fee", JB::Number(fee_units)}});
        });

        // Build the UNSIGNED FIRST-LIQUIDITY SEED for an empty pool.  Public
        // market-anchor profiles let the authorized first valid seed establish
        // the immutable opening ratio; legacy profiles retain the fixed ratio.
        // Unlike prepareammadd there is no pool UTXO to spend yet: this tx CREATES the
        // pool covenant UTXO (output[0] = d_veld VELD) from the seeder's own VELD, and
        // the block covenant guard's "creates_pool" branch validates it as an ADD
        // seed. All inputs are the seeder's (no sigless pool input). The btcVELD leg
        // (d_btcveld) moves in the ledger via AmmMove — the seeder must hold it.
        methods_["prepareammseed"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() < 3)
                throw std::invalid_argument(
                    "Usage: prepareammseed <from> <d_veld_sats> <d_btcveld_sats> [pool_id]");
            RequireAuthoritativeBtcVeldPegPermission_(BtcVeldPegOperation::AMM, "AMM seed");
            if (!amm_)
                throw std::runtime_error("amm not available");
            const std::string& from = params[0];
            int64_t d_veld = 0, d_btc = 0;
            if (!ParseCanonicalAmmI64(params[1], &d_veld))
                throw std::invalid_argument("d_veld must be a canonical integer (sats)");
            if (!ParseCanonicalAmmI64(params[2], &d_btc))
                throw std::invalid_argument("d_btcveld must be a canonical integer (sats)");
            std::string pool_id = (params.size() >= 4 && !params[3].empty())
                                      ? params[3]
                                      : std::string("VELD:btcVELD");
            if (d_veld <= 0 || d_btc <= 0)
                throw std::invalid_argument("d_veld and d_btcveld must both be positive");
            const uint64_t candidate_height = chain_.Height() + 1;
            const bool market_seed_anchor_active =
                AmmLedger::MarketSeedAnchorActive(candidate_height);
            if (!AmmLedger::InitialSeedAuthorized(from, candidate_height))
                throw rpc_error(
                    -32602,
                    "the first market-priced AMM seed requires the one-time launch authority");
            if (!market_seed_anchor_active &&
                !AmmLedger::IsCanonicalOpeningSeedRatio(d_veld, d_btc))
                throw std::invalid_argument(
                    "seed must use the canonical launch ratio: " +
                    std::to_string(BTCVELD_AMM_OPENING_VELD_UNITS_PER_BTCVELD_SAT) +
                    " VELD base units per btcVELD satoshi");
            if ((uint64_t)d_veld < DUST_THRESHOLD_UNITS)
                throw std::invalid_argument("seed VELD reserve is below the consensus dust floor");
            AmmPool p = amm_->GetPool(pool_id);
            if (!p.exists)
                throw std::runtime_error("pool not active (peg/activation gated)");
            if (p.utxo_valid && p.reserve_veld > 0)
                throw std::runtime_error("pool already seeded — use prepareammadd");
            if (d_veld < AmmLedger::AMM_SEED_LOCK_VELD_UNITS)
                throw std::runtime_error("seed VELD leg is below the A4 locked-core minimum (" +
                                         std::to_string(AmmLedger::AMM_SEED_LOCK_VELD_UNITS) +
                                         " sats / 50 VELD)");
            if (d_btc < AmmLedger::AMM_SEED_LOCK_BTCVELD_SATS)
                throw std::runtime_error("seed btcVELD leg is below the A4 locked-core minimum (" +
                                         std::to_string(AmmLedger::AMM_SEED_LOCK_BTCVELD_SATS) +
                                         " sats)");
            // Layer-4 pool-cap mirror (consensus re-checks in ApplyAdd's seed branch).
            if (!ammgate::PoolReserveAllowed(candidate_height, 0, d_btc))
                throw std::runtime_error("seed exceeds the Layer-4 pool btcVELD cap (" +
                                         std::to_string(BTCVELD_AMM_MAX_POOL_BTCVELD_SATS) +
                                         " sats)");
            const AmmLedger::SeedQuote locked_core_quote =
                AmmLedger::QuoteInitialSeedAtHeight(d_veld, d_btc, candidate_height);
            if (!locked_core_quote.valid)
                throw std::runtime_error("seed fails the A4 locked-core/sliver consensus rules");
            int64_t ubtc = onchain_tokens_ ? onchain_tokens_->GetBalance("btcVELD", from) : 0;
            if (ubtc < d_btc)
                throw std::runtime_error("insufficient btcVELD: need " + std::to_string(d_btc) +
                                         " sats, have " + std::to_string(ubtc));
            auto from_script = AddressToScript(from);
            if (!IsCanonicalTokenCreditAddress(from))
                throw std::invalid_argument(
                    "Invalid AMM token account (canonical Veld P2PKH required)");
            if (!onchain_tokens_ ||
                !onchain_tokens_->CanAmmMove(BTCVELD_TOKEN_ID, from, "AMM:" + pool_id, d_btc))
                throw std::runtime_error("seed btcVELD move would violate the consensus account "
                                         "balance floor or overflow rule");
            auto pool_script = PoolVeldScript(pool_id);

            const uint64_t fee_units = MIN_TX_FEE;
            WalletState ws = ComputeWalletState(from);
            const uint64_t seed_base_need = (uint64_t)d_veld + fee_units;
            if (ws.spendable_units < seed_base_need)
                throw std::runtime_error("insufficient spendable VELD");
            const int64_t remaining_btcveld = ubtc - d_btc;
            const uint64_t available_continuation = ws.spendable_units - seed_base_need;
            AmmLedger::SeedLivenessProbe seed_probe =
                AmmLedger::ProbeInitialSeedLivenessWithResources(
                    d_veld, d_btc, candidate_height, available_continuation, remaining_btcveld);
            if (!seed_probe.valid)
                throw std::runtime_error("seed fails SEED_LIVENESS_PROBE_V1: the wallet cannot "
                                         "retain the canonical P2PKH continuation UTXO and "
                                         "btcVELD account floor required by either witness "
                                         "direction");
            uint64_t required_continuation = fee_units;
            if (seed_probe.direction == AmmLedger::SeedLivenessDirection::V2B) {
                if (seed_probe.amount_in <= 0 ||
                    (uint64_t)seed_probe.amount_in > UINT64_MAX - required_continuation)
                    throw std::runtime_error("seed liveness continuation amount overflow");
                required_continuation += (uint64_t)seed_probe.amount_in;
            }
            if (seed_base_need > UINT64_MAX - required_continuation)
                throw std::runtime_error("seed funding amount overflow");
            const uint64_t need = seed_base_need + required_continuation;
            if (ws.spendable_units < need)
                throw std::runtime_error("insufficient spendable VELD for the seed and its "
                                         "resource-bound liveness witness");
            std::vector<UTXO> selected;
            uint64_t gathered = 0;
            for (auto& u : ws.selectable) {
                if (gathered >= need &&
                    (gathered == need || gathered - need >= DUST_THRESHOLD_UNITS))
                    break;
                selected.push_back(u);
                if (gathered > UINT64_MAX - u.value)
                    throw std::runtime_error("selected VELD input total overflow");
                gathered += u.value;
            }
            if (selected.size() > AmmLedger::MAX_FUNDING_INPUTS)
                throw std::runtime_error(
                    "AMM funding needs more than " + std::to_string(AmmLedger::MAX_FUNDING_INPUTS) +
                    " inputs and would exceed the consensus-priority envelope (" +
                    std::to_string(AmmLedger::MAX_TX_BYTES / 1024) +
                    " KiB). Consolidate this wallet's UTXOs, wait for that "
                    "transaction to confirm, then prepare the seed again.");
            if (gathered < need)
                throw std::runtime_error("insufficient spendable VELD");
            if (gathered != need && gathered - need < DUST_THRESHOLD_UNITS)
                throw std::runtime_error("available VELD inputs would create dust change; "
                                         "consolidate or add another confirmed input");

            Transaction tx;
            for (auto& u : selected) {
                TxInput in;
                in.prev_tx_hash = u.tx_hash;
                in.prev_out_index = u.output_index;
                tx.inputs.push_back(in);
            }
            tx.outputs.push_back(
                TxOutput((uint64_t)d_veld, pool_script)); // output[0] = the new pool UTXO
            const uint64_t change = gathered - seed_base_need;
            if (change < required_continuation)
                throw std::runtime_error("seed coin selection lost the liveness continuation");
            seed_probe = AmmLedger::ProbeInitialSeedLivenessWithResources(
                d_veld, d_btc, candidate_height, change, remaining_btcveld);
            if (!seed_probe.valid)
                throw std::runtime_error("selected seed inputs do not preserve the liveness "
                                         "continuation");
            tx.outputs.push_back(TxOutput(change, from_script));
            AmmOp op;
            op.action = "ADD";
            op.user = from;
            op.amt = d_veld;
            op.extra = d_btc; // extra carries the seed btcVELD (sets the ratio)
            tx.outputs.push_back(TxOutput((uint64_t)0, BuildOpReturnScript(EncodeAmmOp(op))));

            auto raw = tx.Serialize();
            std::vector<std::string> input_items;
            for (uint32_t i = 0; i < tx.inputs.size();
                 ++i) { // all inputs are the seeder's — every one is signed
                Hash256 sighash = ComputeSighash(tx, i, from_script);
                input_items.push_back(
                    JB::Object({{"index", JB::Number((uint64_t)i)},
                                {"sighash_hex", JB::String(BytesToHex(sighash))},
                                {"prev_script_hex", JB::String(BytesToHex(from_script))}}));
            }
            return JB::Object(
                {{"unsigned_tx_hex", JB::String(BytesToHex(raw))},
                 {"inputs", JB::Array(input_items)},
                 {"d_veld_sats", JB::Number((uint64_t)d_veld)},
                 {"d_btcveld_sats", JB::Number((uint64_t)d_btc)},
                 {"opening_price_veld_per_btcveld",
                  JB::Number((uint64_t)(d_btc > 0 ? d_veld / d_btc : 0))},
                 {"market_seed_anchor_active", JB::Bool(market_seed_anchor_active)},
                 {"seed_anchor_policy",
                  JB::String(market_seed_anchor_active ? "first-valid-seed-anchor-v1"
                                                       : "fixed-ratio-v1")},
                 // Deprecated compatibility alias.  The explicit policy flag
                 // and exact anchor legs above are authoritative in market mode.
                 {"opening_veld_units_per_btcveld_sat",
                  JB::Number((uint64_t)BTCVELD_AMM_OPENING_VELD_UNITS_PER_BTCVELD_SAT)},
                 {"legacy_fixed_veld_units_per_btcveld_sat",
                  JB::Number((uint64_t)BTCVELD_AMM_OPENING_VELD_UNITS_PER_BTCVELD_SAT)},
                 {"initial_lp", JB::Number((uint64_t)locked_core_quote.lp_minted)},
                 {"lp_minted", JB::Number((uint64_t)locked_core_quote.lp_minted)},
                 {"lp_supply", JB::Number((uint64_t)locked_core_quote.gross_lp)},
                 {"locked_lp", JB::Number((uint64_t)locked_core_quote.locked_lp)},
                 {"seed_fully_locked", JB::Bool(locked_core_quote.lp_minted == 0)},
                 {"seed_lock_veld_floor_sats",
                  JB::Number((uint64_t)AmmLedger::AMM_SEED_LOCK_VELD_UNITS)},
                 {"seed_lock_btcveld_floor_sats",
                  JB::Number((uint64_t)AmmLedger::AMM_SEED_LOCK_BTCVELD_SATS)},
                 {"seed_liveness_policy", JB::String(AmmLedger::SEED_LIVENESS_POLICY_ID)},
                 {"seed_liveness_tx_fee_units", JB::Number(AMM_SEED_LIVENESS_TX_FEE_UNITS)},
                 {"seed_liveness_fee_reserve_units",
                  JB::Number(AMM_SEED_LIVENESS_FEE_RESERVE_UNITS)},
                 {"seed_liveness_direction",
                  JB::String(AmmLedger::SeedLivenessDirectionName(seed_probe.direction))},
                 {"seed_liveness_input_sats", JB::Number((uint64_t)seed_probe.amount_in)},
                 {"seed_liveness_output_sats", JB::Number((uint64_t)seed_probe.quote.amount_out)},
                 {"seed_liveness_fee_bps", JB::Number((uint64_t)seed_probe.quote.fee_bps)},
                 {"seed_liveness_band", JB::Number((uint64_t)seed_probe.quote.band)},
                 {"seed_liveness_continuation_units", JB::Number(change)},
                 {"seed_liveness_token_remaining_sats", JB::Number((uint64_t)remaining_btcveld)},
                 {"anchor_veld", JB::Number((uint64_t)d_veld)},
                 {"anchor_btcveld", JB::Number((uint64_t)d_btc)},
                 {"fee_model", JB::String(AmmLedger::FEE_MODEL_ID)},
                 {"fee", JB::Number(fee_units)}});
        });

        // UNSIGNED remove-liquidity: burn d_lp LP shares, pay pro-rata VELD (output[1])
        // + btcVELD (ledger) back to the holder. Mirrors AmmLedger::ApplyRemove.
        methods_["prepareammremove"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() < 2)
                throw std::invalid_argument("Usage: prepareammremove <from> <d_lp> [pool_id]");
            RequireAuthoritativeBtcVeldPegPermission_(BtcVeldPegOperation::AMM,
                                                      "AMM remove-liquidity");
            if (!amm_)
                throw std::runtime_error("amm not available");
            const std::string& from = params[0];
            int64_t d_lp = 0;
            if (!ParseCanonicalAmmI64(params[1], &d_lp))
                throw std::invalid_argument("d_lp must be a canonical integer");
            std::string pool_id = (params.size() >= 3 && !params[2].empty())
                                      ? params[2]
                                      : std::string("VELD:btcVELD");
            if (d_lp <= 0)
                throw std::invalid_argument("d_lp must be positive");
            AmmPool p = amm_->GetPool(pool_id);
            if (!p.exists || !p.utxo_valid || p.lp_supply <= 0)
                throw std::runtime_error("pool not active");
            int64_t user_lp = amm_->GetLp(pool_id, from);
            if (user_lp < d_lp)
                throw std::runtime_error("insufficient LP: have " + std::to_string(user_lp) +
                                         ", need " + std::to_string(d_lp));
            auto from_script = AddressToScript(from);
            if (!IsCanonicalTokenCreditAddress(from))
                throw std::invalid_argument(
                    "Invalid AMM token account (canonical Veld P2PKH required)");
            auto pool_script = PoolVeldScript(pool_id);

            int64_t v = (int64_t)((unsigned __int128)(uint64_t)p.reserve_veld * (uint64_t)d_lp /
                                  (uint64_t)p.lp_supply);
            if (v <= 0 || (uint64_t)v < DUST_THRESHOLD_UNITS)
                throw std::runtime_error("LP amount is too small to create a non-dust VELD payout");
            int64_t new_rveld = p.reserve_veld - v;
            if (new_rveld <= 0 || (uint64_t)new_rveld < DUST_THRESHOLD_UNITS)
                throw std::runtime_error("removal would leave the pool below the native consensus "
                                         "dust floor; withdraw fewer LP shares");

            const uint64_t fee_units = MIN_TX_FEE;
            WalletState ws = ComputeWalletState(from);
            if (ws.spendable_units < fee_units)
                throw std::runtime_error("insufficient VELD for the fee");
            std::vector<UTXO> selected;
            uint64_t gathered = 0;
            for (auto& u : ws.selectable) {
                if (gathered >= fee_units &&
                    (gathered == fee_units || gathered - fee_units >= DUST_THRESHOLD_UNITS))
                    break;
                selected.push_back(u);
                if (gathered > UINT64_MAX - u.value)
                    throw std::runtime_error("selected VELD input total overflow");
                gathered += u.value;
            }
            if (selected.size() > AmmLedger::MAX_FUNDING_INPUTS)
                throw std::runtime_error(
                    "AMM fee funding needs more than " +
                    std::to_string(AmmLedger::MAX_FUNDING_INPUTS) +
                    " inputs and would exceed the consensus-priority envelope (" +
                    std::to_string(AmmLedger::MAX_TX_BYTES / 1024) +
                    " KiB). Consolidate this wallet's UTXOs, wait for that "
                    "transaction to confirm, then prepare the removal again.");
            if (gathered < fee_units)
                throw std::runtime_error("insufficient VELD for the fee");
            if (gathered != fee_units && gathered - fee_units < DUST_THRESHOLD_UNITS)
                throw std::runtime_error("available VELD inputs would create dust change; "
                                         "consolidate or add another confirmed input");

            Transaction tx;
            {
                TxInput pin;
                pin.prev_tx_hash = p.pool_txid;
                pin.prev_out_index = p.pool_vout;
                tx.inputs.push_back(pin);
            }
            for (auto& u : selected) {
                TxInput in;
                in.prev_tx_hash = u.tx_hash;
                in.prev_out_index = u.output_index;
                tx.inputs.push_back(in);
            }
            tx.outputs.push_back(
                TxOutput((uint64_t)new_rveld, pool_script));          // output[0] = shrunk pool
            tx.outputs.push_back(TxOutput((uint64_t)v, from_script)); // output[1] = VELD payout
            int64_t change = (int64_t)gathered - (int64_t)fee_units;
            if (change > 0)
                tx.outputs.push_back(TxOutput((uint64_t)change, from_script));
            AmmOp op;
            op.action = "REMOVE";
            op.user = from;
            op.amt = d_lp;
            tx.outputs.push_back(TxOutput((uint64_t)0, BuildOpReturnScript(EncodeAmmOp(op))));

            auto raw = tx.Serialize();
            std::vector<std::string> input_items;
            input_items.push_back(
                JB::Object({{"index", JB::Number((uint64_t)0)}, {"sigless", JB::String("1")}}));
            for (uint32_t i = 1; i < tx.inputs.size(); ++i) {
                Hash256 sighash = ComputeSighash(tx, i, from_script);
                input_items.push_back(
                    JB::Object({{"index", JB::Number((uint64_t)i)},
                                {"sighash_hex", JB::String(BytesToHex(sighash))},
                                {"prev_script_hex", JB::String(BytesToHex(from_script))}}));
            }
            return JB::Object({{"unsigned_tx_hex", JB::String(BytesToHex(raw))},
                               {"inputs", JB::Array(input_items)},
                               {"d_lp", JB::Number((uint64_t)d_lp)},
                               {"veld_out_sats", JB::Number((uint64_t)v)},
                               {"fee", JB::Number(fee_units)}});
        });
#endif

        methods_["createmultisig"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() < 3)
                throw std::invalid_argument("Usage: createmultisig <M> <pubkey1> <pubkey2> ...");
            const uint32_t required = ParseCanonicalRpcU32OrThrow(params[0], "required signatures");
            std::vector<std::string> pubkeys(params.begin() + 1, params.end());
            bool testnet = (chain_.Height() == 0);
            std::string addr = CreateMultiSigAddress(required, pubkeys, testnet);
            return "{\"address\":\"" + addr +
                   "\","
                   "\"required\":" +
                   std::to_string(required) +
                   ","
                   "\"total\":" +
                   std::to_string(pubkeys.size()) + "}";
        });

        methods_["stake"] =
            RpcMethod([](const P&) -> std::string { throw rpc_error(-32601, "method removed"); });

        methods_["unstake"] =
            RpcMethod([](const P&) -> std::string { throw rpc_error(-32601, "method removed"); });

        methods_["getstake"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Missing address");
            if (!staking_)
                return "{\"staked_veld\":0.0,\"unlock_height\":0,\"blocks_until_unlock\":0,"
                       "\"unstake_cooldown_blocks\":0,\"unstake_allowed_height\":0}";
            double stake = (double)staking_->GetStake(params[0]) / VELD_UNITS;
            uint64_t unlock_height = staking_->GetEarliestUnlockHeight(params[0]);
            uint64_t current = chain_.Height();
            uint64_t blocks_left = (unlock_height > current) ? unlock_height - current : 0;
            uint64_t ucd_blocks = 0, ucd_height = 0;
            std::ostringstream j;
            j << std::fixed << std::setprecision(8);
            j << "{\"staked_veld\":" << stake << ",\"unlock_height\":" << unlock_height
              << ",\"blocks_until_unlock\":" << blocks_left
              << ",\"unstake_cooldown_blocks\":" << ucd_blocks
              << ",\"unstake_allowed_height\":" << ucd_height << "}";
            return j.str();
        });

        methods_["getstakehistory"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Missing address");
            if (!staking_)
                return "[]";
            try {
                auto records = staking_->GetStakeRecords(params[0]);
                auto unstakes = staking_->GetUnstakeHistory(params[0]);
                uint64_t current = chain_.Height();
                struct HistEntry {
                    std::string type;
                    double amount;
                    uint64_t block;
                    uint64_t unlock;
                    bool active;
                    std::string status;
                    uint8_t tier;
                    double mult;
                };
                std::vector<HistEntry> entries;
                entries.reserve(records.size() + unstakes.size());
                for (auto& r : records) {
                    std::string st =
                        r.active ? (r.unlock_height > current ? "locked" : "unlocked") : "consumed";
                    double m = ComputeStakeMultiplier(r.lockup_tier, r.amount_units);
                    entries.push_back({"stake", (double)r.amount_units / VELD_UNITS,
                                       r.locked_at_height, r.unlock_height, r.active, st,
                                       r.lockup_tier, m});
                }
                for (auto& u : unstakes) {
                    entries.push_back({"unstake", (double)u.amount_units / VELD_UNITS,
                                       u.block_height, 0, false, "unstaked", (uint8_t)0, 0.0});
                }
                std::sort(entries.begin(), entries.end(),
                          [](const HistEntry& a, const HistEntry& b) { return a.block < b.block; });
                std::ostringstream j;
                j << std::fixed << std::setprecision(8) << "[";
                bool first = true;
                for (auto& e : entries) {
                    if (!first)
                        j << ",";
                    j << "{\"type\":\"" << e.type << "\""
                      << ",\"amount_veld\":" << e.amount << ",\"block\":" << e.block
                      << ",\"unlock_at\":" << e.unlock
                      << ",\"active\":" << (e.active ? "true" : "false") << ",\"status\":\""
                      << e.status << "\""
                      << ",\"lockup_tier\":" << (int)e.tier
                      << ",\"multiplier\":" << std::setprecision(3) << e.mult
                      << std::setprecision(8) << "}";
                    first = false;
                }
                j << "]";
                return j.str();
            } catch (const std::bad_alloc&) {
                std::cerr << "  [rpc] getstakehistory: std::bad_alloc — "
                          << "host is under memory pressure; returning empty\n";
                std::cerr.flush();
                return "[]";
            }
        });

#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        methods_["dumpsnapshot"] = RpcMethod([this](const P& params) -> std::string {
            if (!dump_snapshot_fn_)
                return "{\"error\":\"dump-snapshot not wired\"}";
            if (params.empty())
                throw std::invalid_argument("dumpsnapshot requires target_dir param");
            const std::string& target_dir = params[0];

            if (target_dir.find("..") != std::string::npos)
                throw std::invalid_argument("dumpsnapshot target_dir cannot contain '..'");
            for (char c : target_dir) {
                if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                      c == '.' || c == '_' || c == '/' || c == '-')) {
                    throw std::invalid_argument(
                        "dumpsnapshot target_dir contains a disallowed byte");
                }
            }
            if (datadir_.empty())
                throw std::runtime_error("dumpsnapshot: datadir is not configured");
            std::string allowed_prefix = datadir_ + "/snap-dump/";
            if (target_dir.compare(0, allowed_prefix.size(), allowed_prefix) != 0)
                throw std::invalid_argument("dumpsnapshot target_dir must start with " +
                                            allowed_prefix);
            if (target_dir.size() <= allowed_prefix.size())
                throw std::invalid_argument(
                    "dumpsnapshot target_dir must include a subpath under " + allowed_prefix);
            try {
                namespace fs = std::filesystem;
                auto canon_target = fs::weakly_canonical(fs::path(target_dir)).generic_string();
                auto canon_prefix = fs::weakly_canonical(fs::path(allowed_prefix)).generic_string();
                if (!canon_prefix.empty() && canon_prefix.back() != '/')
                    canon_prefix.push_back('/');
                if (canon_target.compare(0, canon_prefix.size(), canon_prefix) != 0) {
                    throw std::invalid_argument(
                        "dumpsnapshot target_dir resolves outside the allowed prefix (symlink?)");
                }
            } catch (const std::filesystem::filesystem_error&) {
                throw std::invalid_argument("dumpsnapshot target_dir failed canonicalization");
            }

            std::string result = dump_snapshot_fn_(target_dir);
            if (result.rfind("ok|", 0) == 0) {
                const size_t sep = result.find('|', 3);
                const std::string dump_height =
                    sep == std::string::npos ? std::string() : result.substr(3, sep - 3);
                const std::string dump_tip =
                    sep == std::string::npos ? std::string() : result.substr(sep + 1);
                bool height_ok = !dump_height.empty();
                for (char c : dump_height)
                    if (c < '0' || c > '9')
                        height_ok = false;
                bool tip_ok = dump_tip.size() == 64;
                for (char c : dump_tip)
                    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                        tip_ok = false;
                if (!height_ok || !tip_ok)
                    throw std::runtime_error("dumpsnapshot returned malformed locked tip identity");
                std::string esc;
                esc.reserve(target_dir.size() + 4);
                for (char c : target_dir) {
                    if (c == '\\' || c == '"')
                        esc += '\\';
                    esc += c;
                }
                return "{\"ok\":true,\"target\":\"" + esc + "\",\"height\":" + dump_height +
                       ",\"tip_hash\":\"" + dump_tip + "\"}";
            }
            std::string esc_err;
            esc_err.reserve(result.size() + 4);
            for (char c : result) {
                if (c == '\\' || c == '"')
                    esc_err += '\\';
                esc_err += c;
            }
            return "{\"ok\":false,\"error\":\"" + esc_err + "\"}";
        });
#endif

        methods_["flushpools"] = RpcMethod([this](const P&) -> std::string {
            if (!flush_trigger_fn_)
                return "{\"error\":\"flush trigger not wired\"}";
            std::string pool_result = flush_trigger_fn_(false);
            if (pool_result.find("\"error\"") != std::string::npos)
                return "{\"pool\":" + pool_result + "}";
            std::string ep_result = flush_trigger_fn_(true);
            return "{\"pool\":" + pool_result + ",\"endorse\":" + ep_result + "}";
        });

        methods_["getlockuptiers"] = RpcMethod([this](const P&) -> std::string {
            std::ostringstream j;
            j << std::fixed << std::setprecision(3);
            j << "{\"max_multiplier\":" << LOCKUP_MAX_MULTIPLIER << ","
              << "\"min_stake_veld\":" << LOCKUP_REFERENCE_MIN_VELD << ","
              << "\"max_stake_veld\":" << LOCKUP_REFERENCE_MAX_VELD << ","
              << "\"effective_min_stake_veld\":" << (double)MIN_STAKE_UNITS / VELD_UNITS << ","
              << "\"effective_max_stake_veld\":" << (double)MAX_STAKE_UNITS / VELD_UNITS << ","
              << "\"tiers\":[";
            for (int i = 0; i < 4; ++i) {
                if (i)
                    j << ",";
                const auto& t = LOCKUP_TIERS[i];
                double days = (double)t.blocks / (double)BLOCKS_PER_DAY;
                j << "{\"tier\":" << (i + 1) << ",\"blocks\":" << t.blocks << ",\"days\":" << days
                  << ",\"multiplier\":" << t.multiplier << ",\"multiplier_lo\":" << t.multiplier
                  << ",\"multiplier_hi\":" << t.multiplier << ",\"label\":\"" << t.label << "\"}";
            }
            j << "]}";
            return j.str();
        });

        methods_["gettestnetparticipants"] = RpcMethod([this](const P&) -> std::string {
            std::unordered_map<std::string, uint64_t> miner_counts;
            std::unordered_map<std::string, uint64_t> first_block;
            std::unordered_map<std::string, uint64_t> last_block;
            uint64_t height = chain_.Height();

            constexpr uint64_t TESTNET_PARTICIPANTS_HARD_CAP = 10000;
            if (height > TESTNET_PARTICIPANTS_HARD_CAP)
                throw rpc_error(-32602, "height_cap_exceeded: gettestnetparticipants is bounded to "
                                        "the first 10,000 blocks");
            for (uint64_t h = 1; h <= height; ++h) {
                try {
                    Block blk = chain_.GetBlock(h);
                    if (blk.transactions.empty())
                        continue;
                    for (const auto& out : blk.transactions[0].outputs) {
                        if (out.script_pubkey.size() != 25)
                            continue;
                        if (out.script_pubkey[0] == 0x76) {
                            std::string addr = ScriptToAddress(out.script_pubkey);
                            if (addr.empty() || addr == VAULT_ADDRESS)
                                continue;
                            miner_counts[addr]++;
                            if (!first_block.count(addr))
                                first_block[addr] = h;
                            last_block[addr] = h;
                        }
                    }
                } catch (...) {
                    break;
                }
            }

            std::ostringstream j;
            j << "[";
            bool first = true;
            for (auto& [addr, count] : miner_counts) {
                if (!first)
                    j << ",";
                j << "{"
                  << "\"address\":\"" << addr << "\","
                  << "\"blocks_mined\":" << count << ","
                  << "\"first_block\":" << first_block[addr] << ","
                  << "\"last_block\":" << last_block[addr] << "}";
                first = false;
            }
            j << "]";
            return j.str();
        });

        methods_["gettierinfo"] = RpcMethod([this](const P& params) -> std::string {
            if (!tiers_)
                return "{}";
            if (params.empty())
                return tiers_->GetAllTiersJSON();
            auto script = AddressToScript(params[0]);
            std::ostringstream hex;
            for (uint8_t b : script)
                hex << std::hex << std::setw(2) << std::setfill('0') << (int)b;
            if (!tiers_)
                return "{}";
            return tiers_->GetTierJSON(hex.str());
        });

        methods_["getalltiers"] = RpcMethod([this](const P&) -> std::string {
            if (!tiers_)
                return "[]";
            return tiers_->GetAllTiersJSON();
        });

        methods_["checkeligibility"] = RpcMethod([this](const P& params) -> std::string {
            if (!gov_)
                throw std::runtime_error("Governance not initialized");
            if (params.size() < 2)
                throw std::invalid_argument("Usage: checkeligibility <address> <script_hex>");
            auto e = gov_->CheckEligibility(params[0], params[1]);
            return gov_->GetEligibilityJSON(e);
        });
        methods_["getstakinginfo"] = RpcMethod([this](const P& params) -> std::string {
            if (!staking_)
                return "{}";
            uint64_t supply = chain_.TotalSupplyUnits();
            bool active = staking_->IsStakingActive(supply);
            uint64_t total_stake = staking_->GetTotalStake();
            uint64_t height = chain_.Height();
            uint64_t next_dist_in = (height == 0) ? VAULT_DISTRIBUTION_INTERVAL
                                                  : VAULT_DISTRIBUTION_INTERVAL -
                                                        (height % VAULT_DISTRIBUTION_INTERVAL);
            auto vault_script = AddressToScript(VAULT_ADDRESS);
            uint64_t vault_units = chain_.GetBalance(vault_script);

            auto all_stakers = staking_->GetAllStakers();
            struct WStaker {
                std::string addr;
                uint64_t units;
                uint64_t unlock;
                double mult;
                double mining_mult;
                double lockup_mult;
                double share;
            };
            std::vector<WStaker> ws;
            double total_consensus = 0.0;
            for (auto& s : all_stakers) {
                auto script = AddressToScript(s.address);
                double mining_mult = tiers_ ? tiers_->GetTier(BytesToHex(script)).multiplier : 1.0;
                double lockup_mult = staking_->GetEffectiveMultiplier(s.address);
                double mult = mining_mult * lockup_mult;
                if (mult > LOCKUP_MAX_MULTIPLIER)
                    mult = LOCKUP_MAX_MULTIPLIER;
                ws.push_back({s.address, s.staked_units, s.earliest_unlock_height, mult,
                              mining_mult, lockup_mult, 0.0});
                total_consensus += (double)s.staked_units * lockup_mult;
            }
            // CONSENSUS-PARITY (): the vault distribution treats the
            // bond-yield escrow as a competing staker — ComputeExpectedVault-
            // Distribution (blockchain.h:1251) adds GetEligibleBondYieldWeight
            // to the weight pool. A bonded validator's escrow often holds the
            // MAJORITY of the weight, so omitting it here overstated every real
            // staker's share + payout (e.g. est 8.31 vs actual 1.94 for a 10-VELD
            // stake behind a 50-VELD bond). Add the SAME escrow weight to the
            // denominator so share_pct / payout_veld mirror what the chain pays.
            if (validators_ && height >= BOND_YIELD_ACTIVATION_HEIGHT) {
                uint64_t next_boundary =
                    ((height / VAULT_DISTRIBUTION_INTERVAL) + 1) * VAULT_DISTRIBUTION_INTERVAL;
                total_consensus += (double)validators_->GetEligibleBondYieldWeight(next_boundary);
            }
            if (total_consensus > 0)
                for (auto& w : ws)
                    w.share = ((double)w.units * w.lockup_mult) / total_consensus;

            {
                constexpr double WHALE_CAP_FRAC = 0.75;
                for (auto& w : ws) {
                    if (w.share > WHALE_CAP_FRAC)
                        w.share = WHALE_CAP_FRAC;
                }
            }

            double vault_veld = (double)vault_units / VELD_UNITS;
            double backstop = vault_veld * ((double)VAULT_DISTRIBUTION_PPM / 1e6);
            double cycle_budget_veld = backstop;
            if (height >= VAULT_INFLOW_CAP_ACTIVATION_HEIGHT) {
                uint64_t last_boundary =
                    (height / VAULT_DISTRIBUTION_INTERVAL) * VAULT_DISTRIBUTION_INTERVAL;
                if (last_boundary >= VAULT_DISTRIBUTION_INTERVAL) {
                    uint64_t inflow_units =
                        chain_.ComputeVaultInflowSinceLastDistribution(last_boundary);
                    double inflow_cap = ((double)inflow_units / VELD_UNITS) *
                                        ((double)VAULT_INFLOW_PAYOUT_PPM / 1e6);
                    if (cycle_budget_veld > inflow_cap)
                        cycle_budget_veld = inflow_cap;
                }
            }
            double effective_rate_pct =
                (vault_veld > 0) ? (cycle_budget_veld / vault_veld) * 100.0 : 0.0;

            std::ostringstream j;
            j << std::fixed << std::setprecision(8);
            j << "{";
            j << "\"staking_active\":" << (active ? "true" : "false") << ",";
            j << "\"activation_supply_veld\":"
              << (double)chain_.GetStakingActivationUnits() / VELD_UNITS << ",";
            j << "\"current_supply_veld\":" << chain_.TotalSupplyVeld() << ",";
            j << "\"total_staked_veld\":" << (double)total_stake / VELD_UNITS << ",";
            j << "\"vault_balance_veld\":" << (double)vault_units / VELD_UNITS << ",";
            j << "\"min_stake_veld\":"
              << (double)(staking_ ? staking_->GetEffectiveMinStake() : MIN_STAKE_UNITS) /
                     VELD_UNITS
              << ",";
            j << "\"max_stake_veld\":" << (double)MAX_STAKE_UNITS / VELD_UNITS << ",";
            j << "\"lockup_blocks\":" << STAKE_LOCKUP_BLOCKS << ",";
            j << "\"distribution_interval\":" << VAULT_DISTRIBUTION_INTERVAL << ",";
            j << "\"next_distribution_in\":" << next_dist_in << ",";
            j << "\"distributable_veld\":" << cycle_budget_veld << ",";
            j << "\"effective_rate_pct\":" << effective_rate_pct << ",";
            j << "\"current_height\":" << height << ",";
            j << "\"stakers\":[";
            bool first = true;
            for (auto& w : ws) {
                if (!first)
                    j << ",";
                uint64_t mature_units = staking_->GetMatureStake(w.addr, height);
                uint64_t next_unlock = staking_->GetNextUnlockHeight(w.addr, height);
                uint64_t next_in = (next_unlock == UINT64_MAX) ? 0 : (next_unlock - height);
                uint64_t ucd_blk = 0;
                double gross_payout = cycle_budget_veld * w.share;
                double net_payout = gross_payout;
                j << "{\"address\":\"" << w.addr << "\","
                  << "\"staked_veld\":" << (double)w.units / VELD_UNITS << ","
                  << "\"mature_stake_veld\":" << (double)mature_units / VELD_UNITS << ","
                  << "\"next_unlock_blocks\":" << next_in << ","
                  << "\"multiplier\":" << std::setprecision(2) << w.mult << ","
                  << "\"mining_multiplier\":" << std::setprecision(2) << w.mining_mult << ","
                  << "\"lockup_multiplier\":" << std::setprecision(2) << w.lockup_mult << ","
                  << "\"share_pct\":" << std::setprecision(4) << (w.share * 100) << ","
                  << "\"payout_veld\":" << std::setprecision(8) << net_payout << ","
                  << "\"payout_gross_veld\":" << std::setprecision(8) << gross_payout << ","
                  << "\"payout_net_veld\":" << std::setprecision(8) << net_payout << ","
                  << "\"unlock_height\":" << w.unlock << ","
                  << "\"blocks_until_unlock\":" << (w.unlock > height ? w.unlock - height : 0)
                  << ",\"unstake_cooldown_blocks\":" << ucd_blk << "}";
                first = false;
            }
            j << "]}";
            return j.str();
        });

        methods_["getvalidators"] = RpcMethod([this](const P& params) -> std::string {
            size_t offset = 0;
            size_t limit = 100;
            if (params.size() >= 1) {
                const uint64_t value = ParseCanonicalRpcU64OrThrow(params[0], "offset");
                if (value > static_cast<uint64_t>(std::numeric_limits<size_t>::max()))
                    throw std::invalid_argument("offset is out of range");
                offset = static_cast<size_t>(value);
            }
            if (params.size() >= 2) {
                const uint64_t value = ParseCanonicalRpcU64OrThrow(params[1], "limit");
                if (value > static_cast<uint64_t>(std::numeric_limits<size_t>::max()))
                    throw std::invalid_argument("limit is out of range");
                limit = static_cast<size_t>(value);
            }
            if (limit == 0 || limit > 500)
                limit = 100;

            std::ostringstream j;
            j << std::fixed << std::setprecision(8);
            bool sys_active = validators_ && validators_->IsValidatorSystemActive();
            uint64_t total_staked = staking_ ? staking_->GetTotalStake() : 0;
            j << "{";
            j << "\"system_active\":" << (sys_active ? "true" : "false") << ",";
            j << "\"unlock_threshold_veld\":" << (double)VALIDATOR_UNLOCK_STAKED / VELD_UNITS
              << ",";
            j << "\"total_staked_veld\":" << (double)total_staked / VELD_UNITS << ",";
            j << "\"min_stake_veld\":"
              << (double)(validators_ ? validators_->GetEffectiveMinStake() : MIN_VALIDATOR_STAKE) /
                     VELD_UNITS
              << ",";
            j << "\"validator_count\":"
              << (validators_ ? validators_->GetActiveValidatorCount() : 0) << ",";
            j << "\"recently_active_count\":"
              << (validators_ ? validators_->GetRecentlyActiveValidatorCount(chain_.Height()) : 0)
              << ",";
            j << "\"offset\":" << offset << ",";
            j << "\"limit\":" << limit << ",";
            j << "\"validators\":[";
            if (validators_) {
                auto vlist = validators_->GetValidators();
                size_t end = std::min(vlist.size(), offset + limit);
                bool first = true;
                for (size_t i = offset; i < end; ++i) {
                    const auto& v = vlist[i];
                    if (!first)
                        j << ",";
                    uint64_t vstake = staking_ ? staking_->GetStake(v.address) : 0;
                    j << "{";
                    j << "\"pubkey\":\"" << v.pubkey_hex << "\",";
                    j << "\"address\":\"" << v.address << "\",";
                    j << "\"registered_height\":" << v.registered_height << ",";
                    j << "\"staked_veld\":" << std::fixed << std::setprecision(2)
                      << (double)vstake / VELD_UNITS;
                    j << "}";
                    first = false;
                }
            }
            j << "]}";
            return j.str();
        });

        methods_["getmisbehavior"] = RpcMethod([this](const P& params) -> std::string {
            (void)params;
            uint64_t tip = chain_.Height();
            std::ostringstream j;
            j << "{\"phase\":3,"
              << "\"slashing_height\":" << VALIDATOR_SLASHING_HEIGHT << ","
              << "\"slashing_active\":" << (tip >= VALIDATOR_SLASHING_HEIGHT ? "true" : "false")
              << ","
              << "\"current_height\":" << tip << ","
              << "\"bond_lockup_blocks\":" << SLASH_BOND_LOCKUP_BLOCKS << ","
              << "\"evidence\":[";
            if (validators_) {
                auto ev = validators_->GetMisbehavior();
                bool first = true;
                for (const auto& e : ev) {
                    if (!first)
                        j << ",";
                    bool penalized = e.evidence_block >= VALIDATOR_SLASHING_HEIGHT;
                    j << "{";
                    j << "\"pubkey\":\"" << e.pubkey_hex.substr(0, 32) << "...\",";
                    j << "\"address\":\"" << e.address << "\",";
                    j << "\"signed_height\":" << e.height << ",";
                    j << "\"hash_a\":\"" << e.hash_a_hex << "\",";
                    j << "\"hash_b\":\"" << e.hash_b_hex << "\",";
                    j << "\"slasher_address\":\"" << e.slasher_address << "\",";
                    j << "\"evidence_block\":" << e.evidence_block << ",";
                    j << "\"penalty_applied\":" << (penalized ? "true" : "false");
                    j << "}";
                    first = false;
                }
            }
            j << "]}";
            return j.str();
        });

        methods_["getblockendorsements"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Usage: getblockendorsements <height>");
            const uint64_t height = ParseCanonicalRpcU64OrThrow(params[0], "height");
            std::ostringstream j;
            j << "{";
            j << "\"height\":" << height << ",";
            j << "\"endorsements\":[";
            if (validators_) {
                auto ends = validators_->GetEndorsements(height);
                bool first = true;
                for (auto& e : ends) {
                    if (!first)
                        j << ",";
                    j << "{";
                    j << "\"pubkey\":\"" << e.pubkey_hex << "\",";
                    j << "\"address\":\"" << e.address << "\",";
                    j << "\"reward_paid\":" << (e.reward_paid ? "true" : "false");
                    j << "}";
                    first = false;
                }
            }
            j << "],";
            j << "\"count\":" << (validators_ ? validators_->GetEndorsementCount(height) : 0);
            j << "}";
            return j.str();
        });

        // Finality snapshot for validator daemons: the frozen epoch set a
        // daemon needs to know its membership and bind its votes. Empty result
        // (an object with a null snapshot) means warm-up has not begun.
        methods_["getfinalitysnapshot"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() > 1)
                throw std::invalid_argument("Usage: getfinalitysnapshot [epoch]");
            std::optional<uint64_t> epoch;
            if (!params.empty())
                epoch = ParseCanonicalRpcU64OrThrow(params[0], "epoch");
            if (!finality_snapshot_fn_)
                return "{\"snapshot\":null}";
            const std::string js = finality_snapshot_fn_(epoch);
            if (js.empty())
                return "{\"snapshot\":null}";
            return js;
        });

        // Issue an opaque, versioned authorization for a canonical validator
        // target.  The current canonical tip and validation generation are
        // part of the binding; the write sink must re-evaluate it.
        methods_["getworkadmission"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() != 3 ||
                (params[0] != "validator_endorsement" && params[0] != "finality_vote")) {
                throw std::invalid_argument("Usage: getworkadmission "
                                            "<validator_endorsement|finality_vote> "
                                            "<target_height> <target_hash>");
            }
            if (!IsCanonicalRpcLowerHex(params[2], 64))
                throw rpc_error(-32602, "target_hash must be 64 lowercase hex characters");
            if (!remote_work_grant_fn_)
                throw rpc_error(-32010, "work admission unavailable: unwired");

            auto transition_guard = chain_.AcquireConsensusTransitionGuard();
            if (chain_.IsEmpty())
                throw rpc_error(-32010, "work admission unavailable: tip_unknown");
            const Block tip = chain_.TipCopy();
            work_admission::Subject subject;
            subject.purpose = params[0] == "finality_vote"
                                  ? work_admission::Purpose::FinalityVote
                                  : work_admission::Purpose::ValidatorEndorsement;
            subject.height = ParseCanonicalRpcU64OrThrow(params[1], "target_height");
            subject.target_hash = HexToHash(params[2]);
            subject.parent_height = tip.height;
            subject.parent_hash = tip.GetHash();
            RemoteWorkGrantResult grant;
            try {
                grant = remote_work_grant_fn_(params[0] == "finality_vote"
                                                  ? work_admission::Path::FinalityVote
                                                  : work_admission::Path::ValidatorEndorsement,
                                              subject);
            } catch (...) {
                grant.decision = {false, work_admission::Refusal::Unwired, std::nullopt};
            }
            if (!grant.decision.allowed || !grant.decision.binding || grant.token.empty() ||
                grant.ttl_ms == 0) {
                throw rpc_error(-32010, std::string("work admission refused: ") +
                                            work_admission::RefusalName(grant.decision.refusal));
            }
            return JsonBuilder::Object({
                {"allowed", JsonBuilder::Bool(true)},
                {"binding",
                 JsonBuilder::String(work_admission::EncodeBinding(*grant.decision.binding))},
                {"signing_token", JsonBuilder::String(grant.token)},
                {"ttl_ms", JsonBuilder::Number(grant.ttl_ms)},
                {"tip_height", JsonBuilder::Number(tip.height)},
                {"tip_hash", JsonBuilder::String(HashToHex(tip.GetHash()))},
            });
        });

        // Convert a pending bearer into a node-held active signing lease
        // before the remote process writes an anti-equivocation journal or
        // invokes its private-key operation.  A raw grant is deliberately not
        // sufficient at either submission sink.
        methods_["beginworksigning"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() != 3 ||
                (params[0] != "validator_endorsement" && params[0] != "finality_vote")) {
                throw std::invalid_argument("Usage: beginworksigning "
                                            "<validator_endorsement|finality_vote> "
                                            "<work_binding> <one_use_signing_token>");
            }
            const auto binding = work_admission::DecodeBinding(params[1]);
            if (!binding || work_admission::EncodeBinding(*binding) != params[1])
                throw rpc_error(-32602, "invalid work binding");
            const bool finality = params[0] == "finality_vote";
            if ((finality && binding->subject.purpose != work_admission::Purpose::FinalityVote) ||
                (!finality &&
                 binding->subject.purpose != work_admission::Purpose::ValidatorEndorsement))
                throw rpc_error(-32602, "work binding purpose mismatch");
            if (!IsCanonicalRpcLowerHex(params[2], 64))
                throw rpc_error(-32602, "invalid signing token");
            if (!begin_remote_signing_fn_)
                throw rpc_error(-32010, "remote signing activation unavailable: unwired");

            auto transition_guard = chain_.AcquireConsensusTransitionGuard();
            RemoteSigningActivationResult activation;
            try {
                activation =
                    begin_remote_signing_fn_(finality ? work_admission::Path::FinalityVote
                                                      : work_admission::Path::ValidatorEndorsement,
                                             params[1], params[2]);
            } catch (...) {
                activation.reason = "activation_exception";
            }
            if (!activation.started) {
                throw rpc_error(-32010, std::string("remote signing activation refused: ") +
                                            (activation.reason.empty()
                                                 ? std::string("retryable local-work-unavailable")
                                                 : activation.reason));
            }
            return JsonBuilder::Object({
                {"started", JsonBuilder::Bool(true)},
                {"ttl_ms", JsonBuilder::Number(activation.ttl_ms)},
            });
        });

        // Explicit exception/cancellation release.  Expiry remains the hard
        // upper bound if a validator process disappears without calling it.
        methods_["cancelworksigning"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() != 1 || !IsCanonicalRpcLowerHex(params[0], 64))
                throw std::invalid_argument("Usage: cancelworksigning <one_use_signing_token>");
            if (!cancel_remote_signing_fn_)
                throw rpc_error(-32010, "remote signing cancellation unavailable: unwired");
            auto transition_guard = chain_.AcquireConsensusTransitionGuard();
            bool released = false;
            try {
                released = cancel_remote_signing_fn_(params[0]);
            } catch (...) {
                released = false;
            }
            return JsonBuilder::Object({
                {"released", JsonBuilder::Bool(released)},
            });
        });

        // Vote intake: the node rechecks the exact authorization immediately
        // before verification, storage, and gossip.  A stale or missing
        // binding cannot be cached for later use.
        methods_["submitfinalityvote"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() != 3)
                throw std::invalid_argument("Usage: submitfinalityvote <canonical_FVT1_hex> "
                                            "<work_binding> <one_use_signing_token>");
            const bool ok =
                finality_vote_sink_ ? finality_vote_sink_(params[0], params[1], params[2]) : false;
            std::ostringstream j;
            j << "{\"accepted\":" << (ok ? "true" : "false") << "}";
            return j.str();
        });

        methods_["getfinalityqc"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() != 1 || (params[0] != "1" && params[0] != "2"))
                throw std::invalid_argument("Usage: getfinalityqc <1|2>");
            const uint8_t phase = (uint8_t)(params[0][0] - '0');
            if (!finality_qc_fn_)
                return "{\"qc_hex\":\"\"}";
            const std::string hex = finality_qc_fn_(phase);
            return std::string("{\"qc_hex\":\"") + hex + "\"}";
        });

        // Authenticated operator read surface for durable completed
        // finality-equivocation pairs.  Pagination is intentionally bounded:
        // one summary carries a 1,952-byte ML-DSA public key and the collector
        // itself has a fixed completed-pair capacity.
        methods_["listfinalityevidence"] = RpcMethod([this](const P& params) -> std::string {
            namespace fq = ::veld::finality::qc;
            if (params.size() > 2)
                throw std::invalid_argument("Usage: listfinalityevidence [offset] [limit]");
            uint64_t offset = 0;
            uint64_t limit = 20;
            if (!params.empty())
                offset = ParseCanonicalRpcU64OrThrow(params[0], "offset");
            if (params.size() == 2)
                limit = ParseCanonicalRpcU64OrThrow(params[1], "limit");
            if (offset > fq::FinalityEquivocationCollector::MAX_COMPLETED_PAIRS)
                throw std::invalid_argument("offset exceeds the completed evidence pool bound");
            if (limit == 0 || limit > 100)
                throw std::invalid_argument("limit must be between 1 and 100");
            if (!finality_evidence_list_fn_)
                throw rpc_error(-32603, "finality evidence journal is unavailable");

            const auto rows =
                finality_evidence_list_fn_(static_cast<size_t>(offset), static_cast<size_t>(limit));
            std::vector<std::string> items;
            items.reserve(rows.size());
            for (const auto& row : rows) {
                items.push_back(JB::Object({
                    {"evidence_id", JB::String(HashToHex(row.id))},
                    {"signer_commit", JB::String(HashToHex(row.signer_commit))},
                    {"pubkey_hex", JB::String(row.pubkey_hex)},
                    {"epoch", JB::Number(row.epoch)},
                    {"phase", JB::Number(static_cast<uint64_t>(static_cast<uint8_t>(row.phase)))},
                    {"round", JB::Number(static_cast<uint64_t>(row.round))},
                    {"target_height", JB::Number(row.target_height)},
                    {"target_a_hash", JB::String(HashToHex(row.target_a_hash))},
                    {"target_b_hash", JB::String(HashToHex(row.target_b_hash))},
                }));
            }
            return JB::Object({
                {"offset", JB::Number(offset)},
                {"limit", JB::Number(limit)},
                {"count", JB::Number(static_cast<uint64_t>(items.size()))},
                {"evidence", JB::Array(items)},
            });
        });

        methods_["getfinalityevidence"] = RpcMethod([this](const P& params) -> std::string {
            namespace fq = ::veld::finality::qc;
            if (params.size() != 1 || !IsCanonicalRpcLowerHex(params[0], 64))
                throw std::invalid_argument(
                    "Usage: getfinalityevidence <canonical_lowercase_evidence_id_hex>");
            if (!finality_evidence_find_fn_)
                throw rpc_error(-32603, "finality evidence journal is unavailable");
            const Hash256 evidence_id = HexToHash(params[0]);
            const auto evidence = finality_evidence_find_fn_(evidence_id);
            if (!evidence || evidence->Id() != evidence_id)
                throw rpc_error(-5, "finality evidence not found");
            const auto first_wire = fq::EncodeSignedVoteWire(evidence->First());
            const auto second_wire = fq::EncodeSignedVoteWire(evidence->Second());
            if (first_wire.size() != fq::SIGNED_VOTE_WIRE_BYTES ||
                second_wire.size() != fq::SIGNED_VOTE_WIRE_BYTES)
                throw rpc_error(-32603, "stored finality evidence failed canonical encoding");
            const auto& first = evidence->First();
            const auto& second = evidence->Second();
            return JB::Object({
                {"evidence_id", JB::String(HashToHex(evidence->Id()))},
                {"signer_commit", JB::String(HashToHex(evidence->SignerCommit()))},
                {"pubkey_hex", JB::String(first.pubkey_hex)},
                {"epoch", JB::Number(first.epoch_id)},
                {"set_root", JB::String(HashToHex(first.set_root))},
                {"phase", JB::Number(static_cast<uint64_t>(static_cast<uint8_t>(first.phase)))},
                {"round", JB::Number(static_cast<uint64_t>(first.round))},
                {"target_height", JB::Number(first.target.height)},
                {"target_a_hash", JB::String(HashToHex(first.target.hash))},
                {"target_b_hash", JB::String(HashToHex(second.target.hash))},
                {"vote_a_hex", JB::String(BytesToHex(first_wire))},
                {"vote_b_hex", JB::String(BytesToHex(second_wire))},
            });
        });

        // Construct an unsigned, reporter-funded SLASH_EQUIV transaction from a
        // durable authenticated evidence id.  The node callback rechecks every
        // non-cryptographic consensus gate against the next block before it
        // returns the exact-17 op.  Reporter authorization remains an ordinary
        // signed input owned by reporter_address.
        methods_["preparefinalityslash"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() != 2 || !IsCanonicalRpcLowerHex(params[1], 64))
                throw std::invalid_argument("Usage: preparefinalityslash <reporter_address> "
                                            "<canonical_lowercase_evidence_id_hex>");
            const std::string& reporter = params[0];
            const auto reporter_script = AddressToScript(reporter);
            if (reporter_script.size() != 25)
                throw std::invalid_argument("Invalid reporter address");
            if (!finality_slash_prepare_fn_)
                throw rpc_error(-32603, "finality slash preparation is unavailable");
            const Hash256 evidence_id = HexToHash(params[1]);
            const auto prepared_op = finality_slash_prepare_fn_(evidence_id);
            if (!prepared_op)
                throw rpc_error(-8, "finality evidence is missing, expired, already slashed, "
                                    "or not admissible in the next block");
            const std::string& slash_op = *prepared_op;
            const std::string prefix = "VELD_VALIDATOR|SLASH_EQUIV|";
            if (slash_op.rfind(prefix, 0) != 0 ||
                std::count(slash_op.begin(), slash_op.end(), '|') != 17 ||
                slash_op.size() > UINT16_MAX)
                throw rpc_error(-32603, "node returned a malformed finality slash operation");
            if (mempool_.HasPendingOpReturn(slash_op))
                throw rpc_error(-8,
                                "this finality evidence already has a pending slash transaction");

            std::vector<uint8_t> op_script{0x6A};
            if (slash_op.size() <= 75) {
                op_script.push_back(static_cast<uint8_t>(slash_op.size()));
            } else if (slash_op.size() <= 255) {
                op_script.push_back(0x4C);
                op_script.push_back(static_cast<uint8_t>(slash_op.size()));
            } else {
                op_script.push_back(0x4D);
                op_script.push_back(static_cast<uint8_t>(slash_op.size() & 0xFF));
                op_script.push_back(static_cast<uint8_t>((slash_op.size() >> 8) & 0xFF));
            }
            op_script.insert(op_script.end(), slash_op.begin(), slash_op.end());

            const uint64_t fee = MIN_TX_FEE;
            const CoinSelection coins = SelectWalletCoins_(reporter, 0, fee);
            if (!coins.sufficient)
                throw std::runtime_error(
                    "Insufficient reporter funds for finality slash submission fee");

            Transaction tx;
            for (const auto& utxo : coins.selected_utxos) {
                TxInput input;
                input.prev_tx_hash = utxo.tx_hash;
                input.prev_out_index = utxo.output_index;
                tx.inputs.push_back(input);
            }
            if (coins.change_amount > 0)
                tx.outputs.push_back(TxOutput(coins.change_amount, reporter_script));
            tx.outputs.push_back(TxOutput(0, std::move(op_script)));

            const auto raw = tx.Serialize();
            std::vector<std::string> input_items;
            input_items.reserve(tx.inputs.size());
            for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
                const Hash256 sighash = ComputeSighash(tx, i, reporter_script);
                input_items.push_back(JB::Object({
                    {"index", JB::Number(static_cast<uint64_t>(i))},
                    {"sighash_hex", JB::String(BytesToHex(sighash))},
                    {"prev_script_hex", JB::String(BytesToHex(reporter_script))},
                }));
            }
            uint64_t total_input = 0;
            for (const auto& utxo : coins.selected_utxos) {
                if (total_input > UINT64_MAX - utxo.value)
                    throw rpc_error(-32603, "reporter input total overflow");
                total_input += utxo.value;
            }
            return JB::Object({
                {"unsigned_tx_hex", JB::String(BytesToHex(raw))},
                {"inputs", JB::Array(input_items)},
                {"evidence_id", JB::String(params[1])},
                {"total_input", JB::Number(total_input)},
                {"total_output", JB::Number(static_cast<uint64_t>(0))},
                {"fee", JB::Number(fee)},
                {"change", JB::Number(coins.change_amount)},
                {"op_return_bytes", JB::Number(static_cast<uint64_t>(slash_op.size()))},
            });
        });

        methods_["getvalidatorinfo"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Usage: getvalidatorinfo <address_or_pubkey_hex>");
            const std::string& arg = params[0];
            bool registered = false;
            bool is_address = (!arg.empty() && arg[0] == 'V');
            if (is_address) {
                auto s = AddressToScript(arg);
                if (s.size() == 25) {
                    registered = validators_ && validators_->IsValidatorByAddress(arg);
                } else {
                    is_address = false;
                }
            }
            if (!is_address) {
                registered = validators_ && validators_->IsRegistered(arg);
            }
            std::ostringstream j;
            j << std::fixed << std::setprecision(8);
            j << "{";
            j << "\"query\":\"" << arg << "\",";
            j << "\"resolved_as\":\"" << (is_address ? "address" : "pubkey") << "\",";
            j << "\"registered\":" << (registered ? "true" : "false") << ",";
            j << "\"system_active\":"
              << (validators_ && validators_->IsValidatorSystemActive() ? "true" : "false");
            j << "}";
            return j.str();
        });

        methods_["markvalidatorrewardspaid"] = RpcMethod([](const P&) -> std::string {
            throw rpc_error(-32601, "markvalidatorrewardspaid removed: paid state is derived only "
                                    "from canonical endorsement-pool flush transactions");
        });

#ifndef VELD_PUBLIC_TESTNET
        methods_["minttoken"] = RpcMethod([](const P&) -> std::string {
            throw std::runtime_error("minttoken disabled — use browser-signed sendrawtransaction. "
                                     "Issuer signs a P2PKH spend with a trailing OP_RETURN MINT "
                                     "op; consensus accepts because the input is signed by the "
                                     "issuer address.");
        });

        methods_["sendtoken"] = RpcMethod([](const P&) -> std::string {
            throw std::runtime_error("sendtoken disabled — use browser-signed sendrawtransaction. "
                                     "The wallet UI builds a signed P2PKH spend with a trailing "
                                     "OP_RETURN TRANSFER op, which consensus accepts because the "
                                     "input is signed by the `from` address.");
        });
#endif

#ifndef VELD_PUBLIC_TESTNET
        methods_["gettokenhistory"] = RpcMethod([this](const P& params) -> std::string {
            if (!onchain_tokens_)
                return "[]";
            auto hist = params.empty() ? onchain_tokens_->GetAllHistory(50)
                                       : onchain_tokens_->GetHistory(params[0], 20);
            std::ostringstream j;
            j << "[";
            bool first = true;
            for (auto& t : hist) {
                if (!first)
                    j << ",";
                j << onchain_tokens_->TransferToJSON(t);
                first = false;
            }
            j << "]";
            return j.str();
        });
#endif

        methods_["gettierstatus"] = RpcMethod([this](const P& params) -> std::string {
            if (!tiers_ || params.empty())
                return "{\"error\":\"address required\"}";
            auto script = AddressToScript(params[0]);
            std::string script_hex;
            if (script.size() == 25) {
                std::ostringstream _h;
                for (auto _b : script)
                    _h << std::hex << std::setw(2) << std::setfill('0') << (int)_b;
                script_hex = _h.str();
            }
            if (!tiers_)
                return "{}";
            return tiers_->GetTierInfoJSON(params[0], script_hex);
        });

        methods_["getvault"] = RpcMethod([this](const P&) -> std::string {
            return vault_ ? vault_->ToJSON() : "{\"balance_veld\":0}";
        });

#ifndef VELD_PUBLIC_TESTNET
        methods_["getonchainstatus"] = RpcMethod([this](const P& params) -> std::string {
            if (!onchain_tokens_)
                return "{\"error\":\"on-chain tokens not available\"}";
            if (params.empty()) {
                auto toks = onchain_tokens_->ListTokens();
                std::ostringstream j;
                j << "[";
                bool first = true;
                for (auto& t : toks) {
                    if (!first)
                        j << ",";
                    j << "{\"id\":\"" << t.id << "\""
                      << ",\"name\":\"" << t.name << "\""
                      << ",\"supply\":" << std::fixed << std::setprecision(8)
                      << onchain_tokens_->GetSupply(t.id) << "}";
                    first = false;
                }
                j << "]";
                return j.str();
            }
            std::string addr = params[0];
            if (params.size() < 2)
                return "{\"error\":\"usage: getonchainstatus <addr> <token_id>\"}";
            std::string token = params[1];
            double bal = onchain_tokens_->GetBalance(token, addr);
            std::ostringstream j;
            j << std::fixed << std::setprecision(8);
            j << "{\"token\":\"" << token << "\",\"address\":\"" << addr << "\",\"balance\":" << bal
              << "}";
            return j.str();
        });
#endif

        methods_["getproposals"] = RpcMethod([this](const P& params) -> std::string {
            if (!gov_)
                return "[]";
            std::string requester = (params.size() >= 1 ? params[0] : "");
            return gov_->GetAllProposalsJSON(requester);
        });

        methods_["getgovernanceinfo"] = RpcMethod([this](const P&) -> std::string {
            uint64_t h = chain_.Height();
            size_t registered = validators_ ? validators_->GetActiveValidatorCount() : 0;
            size_t active = validators_
                                ? validators_->GetRecentlyActiveValidatorCount(h, GOV_ACTIVE_WINDOW)
                                : 0;
            uint32_t gen_votes =
                gov_ ? gov_->GetMinVotesRequired(ProposalType::GENERAL) : GOV_QUORUM_GENERAL;
            uint32_t proto_votes = gov_ ? gov_->GetMinVotesRequired(ProposalType::PROTOCOL_UPGRADE)
                                        : GOV_QUORUM_PROTOCOL;
            uint64_t bonded = validators_ ? validators_->GetGovernanceBondedTotal() : 0;
            std::ostringstream j;
            j << "{\"registered_validators\":" << registered << ",\"active_validators\":" << active
              << ",\"governance_active\":"
              << ((gov_ && gov_->GovernanceBondGateOpen()) ? "true" : "false")
              << ",\"bonded_veld\":" << std::fixed << std::setprecision(8)
              << ((double)bonded / VELD_UNITS) << ",\"general_votes_needed\":" << gen_votes
              << ",\"general_threshold_pct\":" << GOV_PASS_PCT_GENERAL
              << ",\"protocol_votes_needed\":" << proto_votes
              << ",\"protocol_threshold_pct\":" << GOV_PASS_PCT_PROTOCOL
              << ",\"protocol_timelock_blocks\":" << GOV_PROTOCOL_TIMELOCK
              << ",\"vote_window_blocks\":" << (GOV_VOTE_DURATION_DAYS * BLOCKS_PER_DAY)
              << ",\"active_window_blocks\":" << GOV_ACTIVE_WINDOW
              << ",\"quorum_general\":" << GOV_QUORUM_GENERAL
              << ",\"quorum_protocol\":" << GOV_QUORUM_PROTOCOL << ",\"height\":" << h << "}";
            return j.str();
        });

        methods_["getgoveligibility"] = RpcMethod([this](const P& params) -> std::string {
            if (!gov_ || params.empty())
                return "{\"error\":\"address required\"}";
            auto script = AddressToScript(params[0]);
            std::string script_hex;
            if (script.size() == 25) {
                std::ostringstream _h;
                for (auto _b : script)
                    _h << std::hex << std::setw(2) << std::setfill('0') << (int)_b;
                script_hex = _h.str();
            }
            auto e = gov_->CheckEligibility(params[0], script_hex);
            return gov_->GetEligibilityJSON(e);
        });

        auto build_op_return_script = [](const std::string& payload) -> std::vector<uint8_t> {
            std::vector<uint8_t> bytes(payload.begin(), payload.end());
            std::vector<uint8_t> script;
            script.push_back(0x6A);
            if (bytes.size() <= 75) {
                script.push_back((uint8_t)bytes.size());
            } else if (bytes.size() <= 255) {
                script.push_back(0x4C);
                script.push_back((uint8_t)bytes.size());
            } else {
                script.push_back(0x4D);
                script.push_back((uint8_t)(bytes.size() & 0xFF));
                script.push_back((uint8_t)((bytes.size() >> 8) & 0xFF));
            }
            script.insert(script.end(), bytes.begin(), bytes.end());
            return script;
        };

        auto build_gov_tx_template =
            [this, build_op_return_script](const std::string& address,
                                           const std::vector<uint8_t>& op_script) -> std::string {
            auto script = AddressToScript(address);
            uint64_t fee = MIN_TX_FEE;
            CoinSelection coins = SelectWalletCoins_(address, 0, fee);
            if (!coins.sufficient)
                throw std::runtime_error("Insufficient funds for governance TX fee");
            Transaction tx;
            for (auto& utxo : coins.selected_utxos) {
                TxInput inp;
                inp.prev_tx_hash = utxo.tx_hash;
                inp.prev_out_index = utxo.output_index;
                tx.inputs.push_back(inp);
            }
            if (coins.change_amount > 0)
                tx.outputs.push_back(TxOutput(coins.change_amount, script));
            tx.outputs.push_back(TxOutput(0, op_script));
            auto raw = tx.Serialize();
            std::string unsigned_tx_hex = BytesToHex(raw);
            std::vector<std::string> input_items;
            for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
                Hash256 sighash = ComputeSighash(tx, i, script);
                input_items.push_back(JB::Object({
                    {"index", JB::Number((uint64_t)i)},
                    {"sighash_hex", JB::String(BytesToHex(sighash))},
                    {"prev_script_hex", JB::String(BytesToHex(script))},
                }));
            }
            uint64_t total_input = 0;
            for (auto& utxo : coins.selected_utxos)
                total_input += utxo.value;
            return JB::Object({
                {"unsigned_tx_hex", JB::String(unsigned_tx_hex)},
                {"inputs", JB::Array(input_items)},
                {"total_input", JB::Number(total_input)},
                {"total_output", JB::Number((uint64_t)0)},
                {"fee", JB::Number(fee)},
                {"change", JB::Number(coins.change_amount)},
            });
        };

        methods_["preparegovproposal"] = RpcMethod([this, build_gov_tx_template,
                                                    build_op_return_script](
                                                       const P& params) -> std::string {
            if (!gov_ || !gov_->GovernanceBondGateOpen())
                throw std::runtime_error("Governance is locked until the bonded-validator "
                                         "activation threshold is reached");
            if (params.size() != 6 && params.size() != 7)
                throw std::invalid_argument("Usage: preparegovproposal ADDRESS [TYPE] TITLE "
                                            "DESCRIPTION PUBKEY_HEX SIGNATURE_HEX SIGNED_HEIGHT");
            const bool typed_marker = params.size() == 7;
            const std::string& address = params[0];
            ProposalType proposal_type = ProposalType::GENERAL;
            size_t offset = 1;
            if (typed_marker) {
                if (!GovernanceEngine::ParseProposalType(params[1], proposal_type))
                    throw std::invalid_argument("TYPE must be general|protocol_upgrade");
                offset = 2;
            }
            const std::string& title = params[offset];
            const std::string& description = params[offset + 1];
            const std::string& pubkey_hex = params[offset + 2];
            const std::string& sig_hex = params[offset + 3];
            const uint64_t signed_height =
                ParseCanonicalRpcU64OrThrow(params[offset + 4], "signed_height");
            if (title.size() > 200)
                throw std::invalid_argument("Title too long (max 200 chars)");
            if (description.size() > 4096)
                throw std::invalid_argument("Description too long (max 4096 chars)");
            uint64_t tip = (uint64_t)chain_.Height();
            if (signed_height > tip + 1)
                throw std::runtime_error("signed_height is ahead of chain tip");
            if (tip > signed_height + GOV_SIG_REPLAY_WINDOW_BLOCKS)
                throw std::runtime_error("signed_height too stale; re-sign against current tip");
            //  genesis-bind the challenge to match the on-chain
            // ApplyProposalFromChain path (BATCH2_HARDENING_HEIGHT=0 ⇒ always
            // prefixed). Single source: GovChainIdPrefix() is the same fn the
            // consensus path calls, so pre-check and on-chain never diverge.
            std::string challenge =
                GovernanceEngine::GovChainIdPrefix() + "GOV_PROPOSAL:" +
                (typed_marker ? GovernanceEngine::ProposalTypeName(proposal_type) + ":" : "") +
                title + "|" + description + ":@" + std::to_string(signed_height);
            if (!GovernanceEngine::VerifyGovSig(pubkey_hex, sig_hex, challenge))
                throw std::runtime_error("Invalid signature");
            if (GovernanceEngine::PubKeyHexToAddress(pubkey_hex) != address)
                throw std::runtime_error("Public key does not derive to claimed address");
            const bool proposal_pending =
                mempool_.HasPendingOpReturn("VELD_GOV|P|" + address + "|") ||
                mempool_.HasPendingOpReturn("VELD_GOV|P|general|" + address + "|") ||
                mempool_.HasPendingOpReturn("VELD_GOV|P|protocol_upgrade|" + address + "|");
            if (proposal_pending)
                throw std::runtime_error("A governance proposal from this address is already "
                                         "pending in the mempool. Wait for it to be mined "
                                         "(target block interval " +
                                         std::to_string(TARGET_BLOCK_TIME) +
                                         " seconds) before submitting another.");
            uint64_t ts = (uint64_t)std::time(nullptr);
            std::string payload =
                typed_marker
                    ? GovernanceEngine::BuildProposalOp(proposal_type, address, title, description,
                                                        ts, signed_height, pubkey_hex, sig_hex)
                    : GovernanceEngine::BuildProposalOp(address, title, description, ts,
                                                        signed_height, pubkey_hex, sig_hex);
            auto op_script = build_op_return_script(payload);
            return build_gov_tx_template(address, op_script);
        });

        methods_["preparegovvote"] = RpcMethod([this, build_gov_tx_template,
                                                build_op_return_script](
                                                   const P& params) -> std::string {
            if (!gov_ || !gov_->GovernanceBondGateOpen())
                throw std::runtime_error("Governance is locked until the bonded-validator "
                                         "activation threshold is reached");
            if (params.size() < 6)
                throw std::invalid_argument("Usage: preparegovvote ADDRESS PROPOSAL_ID CHOICE "
                                            "PUBKEY_HEX SIGNATURE_HEX SIGNED_HEIGHT");
            const std::string& address = params[0];
            const uint64_t proposal_id = ParseCanonicalRpcU64OrThrow(params[1], "proposal_id");
            const std::string& choice_str = params[2];
            const std::string& pubkey_hex = params[3];
            const std::string& sig_hex = params[4];
            const uint64_t signed_height = ParseCanonicalRpcU64OrThrow(params[5], "signed_height");
            VoteChoice choice = VoteChoice::ABSTAIN;
            if (choice_str == "yes")
                choice = VoteChoice::YES;
            else if (choice_str == "no")
                choice = VoteChoice::NO;
            else if (choice_str != "abstain")
                throw std::invalid_argument("choice must be yes|no|abstain");
            //  genesis-bind to match on-chain ApplyVoteFromChain.
            std::string challenge = GovernanceEngine::GovChainIdPrefix() +
                                    "GOV_VOTE:" + std::to_string(proposal_id) + ":" + choice_str +
                                    ":@" + std::to_string(signed_height);
            if (!GovernanceEngine::VerifyGovSig(pubkey_hex, sig_hex, challenge))
                throw std::runtime_error("Invalid signature");
            if (GovernanceEngine::PubKeyHexToAddress(pubkey_hex) != address)
                throw std::runtime_error("Public key does not derive to claimed address");
            uint64_t tip = (uint64_t)chain_.Height();
            if (tip > signed_height + GOV_SIG_REPLAY_WINDOW_BLOCKS)
                throw std::runtime_error("Signed height too stale; re-sign against current tip");
            if (signed_height > tip + 1)
                throw std::runtime_error("signed_height is ahead of chain tip");
            if (mempool_.HasPendingOpReturn("VELD_GOV|V|" + std::to_string(proposal_id) + "|" +
                                            address + "|"))
                throw std::runtime_error("A vote from this address on this proposal is already "
                                         "pending in the mempool. Wait for it to be mined "
                                         "(target block interval " +
                                         std::to_string(TARGET_BLOCK_TIME) +
                                         " seconds) before re-submitting.");
            std::string payload = GovernanceEngine::BuildVoteOp(proposal_id, address, choice,
                                                                signed_height, pubkey_hex, sig_hex);
            auto op_script = build_op_return_script(payload);
            return build_gov_tx_template(address, op_script);
        });

        methods_["registervalidator"] =
            RpcMethod([](const P&) -> std::string { throw rpc_error(-32601, "method removed"); });

        methods_["deregistervalidator"] =
            RpcMethod([](const P&) -> std::string { throw rpc_error(-32601, "method removed"); });

        methods_["preparerawtransaction"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() < 3)
                throw std::invalid_argument(
                    "Usage: preparerawtransaction <from> <to> <amount> [fee] [memo]");

            const std::string& from_addr = params[0];
            const std::string& to_addr = params[1];
            uint64_t amount_units = ParseAmountVeldToUnitsOrThrow(params[2], "Amount");
            uint64_t fee_units = MIN_TX_FEE;
            if (params.size() >= 4 && !params[3].empty()) {
                const uint64_t requested = ParseVeldDecimalToUnitsOrThrow(params[3], "Fee", true);
                fee_units = std::max<uint64_t>(MIN_TX_FEE, requested);
            }
            // Optional memo (params[4]) → carried as a value-0 OP_RETURN below.
            // Empty fee slot ("") above means "use the default min fee", so the
            // wallet can pass [from,to,amount,"",memo] without computing a fee.
            std::string memo;
            if (params.size() >= 5) {
                memo = params[4];
                if (memo.size() > 80)
                    throw std::invalid_argument("Memo too long: " + std::to_string(memo.size()) +
                                                " bytes (max 80).");
            }
            uint64_t total_needed = amount_units + fee_units;

            auto from_script = AddressToScript(from_addr);
            if (from_script.empty())
                throw std::invalid_argument("Invalid from address: " + from_addr);
            auto to_script = AddressToScript(to_addr);
            if (to_script.empty())
                throw std::invalid_argument("Invalid to address: " + to_addr);

            WalletState ws = ComputeWalletState(from_addr);
            const uint64_t staked_units = ws.staked_units;
            const uint64_t spendable = ws.spendable_units;
            if (spendable < total_needed) {
                std::string err =
                    "Insufficient spendable funds. Balance: " +
                    std::to_string((double)ws.total_units / VELD_UNITS) + " VELD, " +
                    "Staked (locked): " + std::to_string((double)staked_units / VELD_UNITS) +
                    " VELD, " + "Immature coinbase: " +
                    std::to_string((double)ws.immature_coinbase_units / VELD_UNITS) + " VELD, " +
                    "Spendable: " + std::to_string((double)spendable / VELD_UNITS) +
                    " VELD, need " + std::to_string((double)total_needed / VELD_UNITS) + " VELD.";
                if (ws.pending_out_units > 0)
                    err += " (" + std::to_string((double)ws.pending_out_units / VELD_UNITS) +
                           " VELD is pending confirmation — wait for your previous transaction to "
                           "confirm)";
                throw std::runtime_error(err);
            }

            std::vector<UTXO> selected;
            uint64_t gathered = 0;
            uint64_t spendable_remaining = spendable;
            for (auto& u : ws.selectable) {
                if (gathered >= total_needed)
                    break;
                uint64_t take = std::min(u.value, spendable_remaining);
                if (take == 0)
                    break;
                selected.push_back(u);
                gathered += u.value;
                spendable_remaining -= std::min(u.value, spendable_remaining);
            }

            constexpr size_t MAX_INPUTS_PER_TX = 180;
            if (selected.size() > MAX_INPUTS_PER_TX) {
                throw std::runtime_error(
                    "Cannot build transaction: would need " + std::to_string(selected.size()) +
                    " inputs to cover " + std::to_string((double)total_needed / VELD_UNITS) +
                    " VELD, exceeds per-TX cap of " + std::to_string(MAX_INPUTS_PER_TX) +
                    " (mempool MAX_TX_SIZE = 1 MB). Your wallet is fragmented "
                    "across many small UTXOs. Either (a) send a smaller "
                    "amount that fits within " +
                    std::to_string(MAX_INPUTS_PER_TX) +
                    " of your largest UTXOs, or (b) consolidate via "
                    "Wallet > Consolidate dust first.");
            }

            if (gathered < total_needed)
                throw std::runtime_error(
                    "Insufficient funds. Have " + std::to_string((double)gathered / VELD_UNITS) +
                    " VELD spendable, need " + std::to_string((double)total_needed / VELD_UNITS) +
                    " VELD" +
                    (ws.pending_out_units > 0
                         ? " (" + std::to_string((double)ws.pending_out_units / VELD_UNITS) +
                               " VELD is pending confirmation)"
                         : ""));

            Transaction tx;
            for (auto& u : selected) {
                TxInput inp;
                inp.prev_tx_hash = u.tx_hash;
                inp.prev_out_index = u.output_index;
                tx.inputs.push_back(inp);
            }
            tx.outputs.push_back(TxOutput(amount_units, to_script));
            uint64_t change = gathered - total_needed;
            if (change > 0)
                tx.outputs.push_back(TxOutput(change, from_script));
            // Optional user memo → value-0 OP_RETURN data output. Encoding
            // mirrors the JS builder (_veldBuildMemoOpReturnHex) in ui_desktop.h
            // byte-for-byte: the wallet re-derives this exact script and refuses
            // to sign if the node returned a different one, so a compromised node
            // cannot alter the memo the user typed. ≤80 B is far under the 32 KB
            // OP_RETURN consensus cap, so existing nodes accept + relay it.
            if (!memo.empty()) {
                std::vector<uint8_t> op_return = {0x6A};
                if (memo.size() < 0x4C) {
                    op_return.push_back((uint8_t)memo.size());
                } else { // 76..80 bytes → OP_PUSHDATA1
                    op_return.push_back(0x4C);
                    op_return.push_back((uint8_t)memo.size());
                }
                op_return.insert(op_return.end(), memo.begin(), memo.end());
                tx.outputs.push_back(TxOutput((uint64_t)0, op_return));
            }

            auto raw = tx.Serialize();
            std::string unsigned_tx_hex = BytesToHex(raw);

            // Compute sighash for each input
            std::vector<std::string> input_items;
            for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
                Hash256 sighash = ComputeSighash(tx, i, from_script);
                input_items.push_back(JB::Object({
                    {"index", JB::Number((uint64_t)i)},
                    {"sighash_hex", JB::String(BytesToHex(sighash))},
                    {"prev_script_hex", JB::String(BytesToHex(from_script))},
                }));
            }

            return JB::Object({
                {"unsigned_tx_hex", JB::String(unsigned_tx_hex)},
                {"inputs", JB::Array(input_items)},
                {"total_input", JB::Number(gathered)},
                {"total_output", JB::Number(amount_units)},
                {"fee", JB::Number(fee_units)},
                {"change", JB::Number(change)},
            });
        });

        methods_["prepareconsolidatetx"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("Usage: prepareconsolidatetx <address> "
                                            "[max_inputs=150] [dust_threshold_veld=1.0]");
            const std::string& addr = params[0];
            size_t max_inputs = 150;
            uint64_t dust_thr_units = VELD_UNITS;
            if (params.size() >= 2) {
                const uint64_t requested = ParseCanonicalRpcU64OrThrow(params[1], "max_inputs");
                if (requested < 2)
                    throw std::invalid_argument("max_inputs must be at least 2");
                // 180 current ML-DSA inputs stay below the generic 1 MiB
                // mempool transaction cap; larger advertised batches could be
                // signed successfully and then deterministically rejected.
                max_inputs = static_cast<size_t>(std::min<uint64_t>(requested, 180));
            }
            if (params.size() >= 3) {
                dust_thr_units =
                    ParseVeldDecimalToUnitsOrThrow(params[2], "dust_threshold_veld", true);
            }
            const double dust_thr_veld = static_cast<double>(dust_thr_units) / VELD_UNITS;

            auto script = AddressToScript(addr);
            if (script.empty())
                throw std::invalid_argument("Invalid address: " + addr);

            WalletState ws = ComputeWalletState(addr);
            constexpr size_t MIN_UTXOS_TO_CONSOLIDATE = 2;
            if (ws.selectable.size() < MIN_UTXOS_TO_CONSOLIDATE) {
                throw std::runtime_error(
                    "Wallet not fragmented enough to consolidate (has " +
                    std::to_string(ws.selectable.size()) + " consolidatable UTXOs, threshold is " +
                    std::to_string(MIN_UTXOS_TO_CONSOLIDATE) + "). " + "No consolidation needed.");
            }

            std::vector<UTXO> candidates;
            size_t skipped_above_thr = 0;
            uint64_t total_units = 0;
            for (auto& u : ws.selectable) {
                if (dust_thr_units > 0 && u.value >= dust_thr_units) {
                    ++skipped_above_thr;
                    continue;
                }
                candidates.push_back(u);
                total_units += u.value;
            }
            if (candidates.size() < 2) {
                std::string msg = "Nothing to consolidate: need at least 2 mature dust UTXOs. "
                                  "Found " +
                                  std::to_string(candidates.size()) + " spendable";
                if (ws.immature_coinbase_units > 0) {
                    char buf[64];
                    std::snprintf(buf, sizeof(buf), "%.8f",
                                  (double)ws.immature_coinbase_units / VELD_UNITS);
                    msg += " (" + std::string(buf) +
                           " VELD of immature coinbase is waiting on "
                           "maturity — click Consolidate again once it ripens)";
                }
                msg += ".";
                throw std::runtime_error(msg);
            }

            std::sort(candidates.begin(), candidates.end(),
                      [](const UTXO& a, const UTXO& b) { return a.value < b.value; });

            if (candidates.size() > max_inputs)
                candidates.resize(max_inputs);

            uint64_t fee_units = MIN_TX_FEE;
            uint64_t gathered = 0;
            for (auto& u : candidates)
                gathered += u.value;
            if (gathered <= fee_units)
                throw std::runtime_error(
                    "Selected UTXOs sum (" + std::to_string((double)gathered / VELD_UNITS) +
                    " VELD) is at or below the minimum fee. Lower the dust threshold "
                    "or wait for more confirmed UTXOs.");
            if (ws.spendable_units < fee_units)
                throw std::runtime_error("Insufficient balance to pay consolidation fee.");

            uint64_t output_units = gathered - fee_units;

            Transaction tx;
            for (auto& u : candidates) {
                TxInput inp;
                inp.prev_tx_hash = u.tx_hash;
                inp.prev_out_index = u.output_index;
                tx.inputs.push_back(inp);
            }
            tx.outputs.push_back(TxOutput(output_units, script));

            auto raw = tx.Serialize();
            std::string unsigned_tx_hex = BytesToHex(raw);

            std::vector<std::string> input_items;
            for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
                Hash256 sighash = ComputeSighash(tx, i, script);
                input_items.push_back(JB::Object({
                    {"index", JB::Number((uint64_t)i)},
                    {"sighash_hex", JB::String(BytesToHex(sighash))},
                    {"prev_script_hex", JB::String(BytesToHex(script))},
                }));
            }

            return JB::Object({
                {"unsigned_tx_hex", JB::String(unsigned_tx_hex)},
                {"inputs", JB::Array(input_items)},
                {"total_input", JB::Number(gathered)},
                {"total_output", JB::Number(output_units)},
                {"fee", JB::Number(fee_units)},
                {"change", JB::Number((uint64_t)0)},
                {"inputs_consolidated", JB::Number((uint64_t)candidates.size())},
                {"dust_threshold_veld", JB::Float(dust_thr_veld)},
            });
        });

        methods_["getdustutxocount"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument(
                    "Usage: getdustutxocount <address> [dust_threshold_veld=1.0]");
            const std::string& addr = params[0];
            uint64_t dust_thr_units = VELD_UNITS;
            if (params.size() >= 2) {
                dust_thr_units =
                    ParseVeldDecimalToUnitsOrThrow(params[1], "dust_threshold_veld", true);
            }
            const double dust_thr_veld = static_cast<double>(dust_thr_units) / VELD_UNITS;
            auto script = AddressToScript(addr);
            if (script.empty())
                throw std::invalid_argument("Invalid address: " + addr);
            auto utxos = chain_.GetUTXOsForScript(script);
            auto mempool_spent = mempool_.GetSpentOutputs();
            uint64_t dust_count = 0;
            uint64_t dust_value_units = 0;
            uint64_t total_count = utxos.size();
            uint64_t total_value_units = 0;
            for (auto& u : utxos) {
                total_value_units += u.value;
                std::string k = HashToHex(u.tx_hash) + ":" + std::to_string(u.output_index);
                if (mempool_spent.count(k))
                    continue;
                if (u.value < dust_thr_units) {
                    dust_count++;
                    dust_value_units += u.value;
                }
            }
            return JB::Object({
                {"address", JB::String(addr)},
                {"dust_threshold_veld", JB::Float(dust_thr_veld)},
                {"dust_count", JB::Number(dust_count)},
                {"dust_value_veld", JB::Float((double)dust_value_units / VELD_UNITS)},
                {"total_count", JB::Number(total_count)},
                {"total_value_veld", JB::Float((double)total_value_units / VELD_UNITS)},
            });
        });

        methods_["preparestake"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() < 2)
                throw std::invalid_argument("Usage: preparestake <address> <amount_veld> [tier]");

            if (!staking_ || !staking_->IsStakingActive(chain_.TotalSupplyUnits())) {
                uint64_t supply = chain_.TotalSupplyUnits();
                uint64_t activation = chain_.GetStakingActivationUnits();
                uint64_t remaining = (supply < activation) ? (activation - supply) : 0;
                throw std::runtime_error(
                    "Staking not yet active. " + std::to_string((double)remaining / VELD_UNITS) +
                    " VELD remaining until activation (" +
                    std::to_string((double)activation / VELD_UNITS) + " VELD threshold)");
            }

            const std::string& address = params[0];
            uint64_t amount_units = ParseAmountVeldToUnitsOrThrow(params[1], "Amount");
            uint8_t lockup_tier = 1;
            if (params.size() >= 3) {
                const uint64_t tier = ParseCanonicalRpcU64OrThrow(params[2], "tier");
                if (tier < 1 || tier > 4)
                    throw std::invalid_argument("tier must be 1..4");
                lockup_tier = static_cast<uint8_t>(tier);
            }

            uint64_t eff_min_stake = staking_ ? staking_->GetEffectiveMinStake() : MIN_STAKE_UNITS;
            if (amount_units < eff_min_stake)
                throw std::runtime_error("Amount below minimum stake of " +
                                         std::to_string((double)eff_min_stake / VELD_UNITS) +
                                         " VELD");

            uint64_t pending_staked = mempool_.GetPendingStakeUnits(address);
            uint64_t reserved_units = 0;
            uint64_t _p = 0;
            if (!TryReserveStakeAtomic(address, amount_units, pending_staked, &_p,
                                       &reserved_units)) {
                if (_p > 0)
                    throw std::runtime_error(
                        "A stake transaction is already pending in the mempool. "
                        "Wait for it to be mined (~180 seconds) before staking again.");
                throw std::runtime_error("A stake of " +
                                         std::to_string((double)reserved_units / VELD_UNITS) +
                                         " VELD was just prepared and is awaiting broadcast. "
                                         "Wait ~30 seconds for the reservation to clear or for the "
                                         "previous TX to confirm before staking again.");
            }
            bool reservation_committed = false;
            auto reservation_guard =
                std::shared_ptr<void>(nullptr, [this, address, &reservation_committed](void*) {
                    if (!reservation_committed) {
                        try {
                            ClearStakeReservation(address);
                        } catch (...) {
                        }
                    }
                });

            uint64_t on_chain_staked = staking_ ? staking_->GetStake(address) : 0;
            uint64_t already_staked = on_chain_staked + pending_staked + reserved_units;

            if (already_staked + amount_units > MAX_STAKE_UNITS)
                throw std::runtime_error(
                    "Stake would exceed maximum of " +
                    std::to_string((double)MAX_STAKE_UNITS / VELD_UNITS) +
                    " VELD per address. Currently committed: " +
                    std::to_string((double)already_staked / VELD_UNITS) + " VELD (on-chain " +
                    std::to_string((double)on_chain_staked / VELD_UNITS) + " + pending " +
                    std::to_string((double)pending_staked / VELD_UNITS) + " + reserved " +
                    std::to_string((double)reserved_units / VELD_UNITS) + ")");

            auto script = AddressToScript(address);
            if (script.empty())
                throw std::runtime_error("Invalid address");

            // Production stake is economically locked in an exact output.  It
            // is not merely a balance annotation: coin selection excludes all
            // existing stake principals and this transaction creates the new
            // principal at canonical vout zero.
            uint64_t fee = MIN_TX_FEE;
            WalletState wallet_state = ComputeWalletState(address);
            if (amount_units > UINT64_MAX - fee)
                throw std::runtime_error("Stake amount and fee overflow");
            const uint64_t required_units = amount_units + fee;
            if (required_units > wallet_state.spendable_units)
                throw std::runtime_error(
                    "Insufficient spendable balance. Available: " +
                    std::to_string((double)wallet_state.spendable_units / VELD_UNITS) +
                    " VELD (balance " +
                    std::to_string((double)wallet_state.total_units / VELD_UNITS) +
                    ", exact active stake backing " +
                    std::to_string((double)wallet_state.active_stake_backing_units / VELD_UNITS) +
                    ", pending spends " +
                    std::to_string((double)wallet_state.pending_out_units / VELD_UNITS) + ")");

            std::string stake_op =
                StakingLedger::BuildLockOp(address, amount_units, chain_.Height(), lockup_tier);

            CoinSelection coins = SelectWalletStateCoins_(wallet_state, amount_units, fee);
            if (!coins.sufficient)
                throw std::runtime_error(DiagnoseFeeSelectFailed(chain_, mempool_, script, fee));

            Transaction tx;
            for (auto& utxo : coins.selected_utxos) {
                TxInput inp;
                inp.prev_tx_hash = utxo.tx_hash;
                inp.prev_out_index = utxo.output_index;
                tx.inputs.push_back(inp);
            }
            tx.outputs.push_back(TxOutput(amount_units, script));
            if (coins.change_amount > 0)
                tx.outputs.push_back(TxOutput(coins.change_amount, script));

            std::vector<uint8_t> op_return_script;
            op_return_script.push_back(0x6A);
            std::vector<uint8_t> data(stake_op.begin(), stake_op.end());
            if (data.size() <= 75) {
                op_return_script.push_back((uint8_t)data.size());
            } else if (data.size() <= 255) {
                op_return_script.push_back(0x4C);
                op_return_script.push_back((uint8_t)data.size());
            } else {
                op_return_script.push_back(0x4D);
                op_return_script.push_back((uint8_t)(data.size() & 0xFF));
                op_return_script.push_back((uint8_t)((data.size() >> 8) & 0xFF));
            }
            op_return_script.insert(op_return_script.end(), data.begin(), data.end());
            tx.outputs.push_back(TxOutput(0, op_return_script));

            auto raw = tx.Serialize();
            std::string unsigned_tx_hex = BytesToHex(raw);

            // Compute sighash for each input
            std::vector<std::string> input_items;
            for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
                Hash256 sighash = ComputeSighash(tx, i, script);
                input_items.push_back(JB::Object({
                    {"index", JB::Number((uint64_t)i)},
                    {"sighash_hex", JB::String(BytesToHex(sighash))},
                    {"prev_script_hex", JB::String(BytesToHex(script))},
                }));
            }

            uint64_t total_input = 0;
            for (auto& utxo : coins.selected_utxos)
                total_input += utxo.value;

            reservation_committed = true;

            uint64_t tier_blocks = LOCKUP_TIERS[lockup_tier - 1].blocks;
            uint64_t unlock_height = chain_.Height() + tier_blocks;
            double tier_mult = ComputeStakeMultiplier(lockup_tier, amount_units);
            double amount_veld_d = (double)amount_units / (double)VELD_UNITS;
            std::ostringstream veld_str;
            veld_str << std::fixed << std::setprecision(8) << amount_veld_d;
            std::ostringstream mult_str;
            mult_str << std::fixed << std::setprecision(3) << tier_mult;

            return JB::Object({
                {"unsigned_tx_hex", JB::String(unsigned_tx_hex)},
                {"inputs", JB::Array(input_items)},
                {"total_input", JB::Number(total_input)},
                {"total_output", JB::Number(total_input - fee)},
                {"fee", JB::Number(fee)},
                {"change", JB::Number(coins.change_amount)},
                {"staked_veld", JB::String(veld_str.str())},
                {"unlock_height", JB::Number(unlock_height)},
                {"lockup_blocks", JB::Number(tier_blocks)},
                {"lockup_tier", JB::Number((uint64_t)lockup_tier)},
                {"multiplier", JB::String(mult_str.str())},
            });
        });

        methods_["prepareunstake"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() < 2)
                throw std::invalid_argument("Usage: prepareunstake <address> <amount_veld>");

            if (!staking_ || !staking_->IsStakingActive(chain_.TotalSupplyUnits())) {
                uint64_t supply = chain_.TotalSupplyUnits();
                uint64_t activation = chain_.GetStakingActivationUnits();
                uint64_t remaining = (supply < activation) ? (activation - supply) : 0;
                throw std::runtime_error(
                    "Staking not yet active. " + std::to_string((double)remaining / VELD_UNITS) +
                    " VELD remaining until activation (" +
                    std::to_string((double)activation / VELD_UNITS) + " VELD threshold)");
            }

            const std::string& address = params[0];
            uint64_t amount_units = ParseAmountVeldToUnitsOrThrow(params[1], "Amount");

            if (!staking_)
                throw std::runtime_error("Staking not initialized");
            uint64_t staked = staking_->GetStake(address);
            if (staked < amount_units)
                throw std::runtime_error("Insufficient staked balance");

            {
                uint64_t pending_staked = mempool_.GetPendingStakeUnits(address);
                if (pending_staked > 0)
                    throw std::runtime_error(
                        "Cannot unstake while a stake transaction is pending "
                        "confirmation. Wait until your stake is mined (target " +
                        std::to_string(TARGET_BLOCK_TIME) +
                        " seconds per block) before attempting to unstake.");
            }

            uint64_t current_height = chain_.Height();

            uint64_t mature = staking_->GetMatureStake(address, current_height);
            if (amount_units > mature) {
                uint64_t next_unlock = staking_->GetNextUnlockHeight(address, current_height);
                uint64_t blocks_remaining =
                    (next_unlock == UINT64_MAX) ? 0 : (next_unlock - current_height);
                throw std::runtime_error("Amount exceeds mature stake. Mature: " +
                                         std::to_string((double)mature / VELD_UNITS) +
                                         " VELD. Newly staked funds unlock in " +
                                         std::to_string(blocks_remaining) + " blocks.");
            }

            {
                auto& unstake_cooldowns = unstake_cooldowns_;
                auto now = std::time(nullptr);
                auto it = unstake_cooldowns.find(address);
                if (it != unstake_cooldowns.end() && (now - it->second) < 60) {
                    throw std::runtime_error("Unstake cooldown: please wait " +
                                             std::to_string(60 - (now - it->second)) + " seconds");
                }
                unstake_cooldowns[address] = now;
                if (unstake_cooldowns.size() > 1000) {
                    for (auto jt = unstake_cooldowns.begin(); jt != unstake_cooldowns.end();) {
                        if (now - jt->second > 300)
                            jt = unstake_cooldowns.erase(jt);
                        else
                            ++jt;
                    }
                }
            }

            auto script = AddressToScript(address);
            uint64_t fee = MIN_TX_FEE;
            if (amount_units <= fee)
                throw std::runtime_error("Unstake amount must exceed the transaction fee");

            std::string unstake_op = StakingLedger::BuildUnlockOp(address, amount_units);

            Transaction tx;
            uint64_t total_input = 0;
            uint64_t change_amount = 0;
            const bool backed = StakeOutpointBackingActive(current_height + 1);
            if (backed) {
                const auto plan = staking_->PlanUnlock(address, amount_units, current_height + 1);
                if (!plan.valid || plan.consumed.empty())
                    throw std::runtime_error("Mature stake does not have valid outpoint backing");
                for (const auto& record : plan.consumed) {
                    TxInput inp;
                    inp.prev_tx_hash = record.backing_txid;
                    inp.prev_out_index = record.backing_vout;
                    tx.inputs.push_back(inp);
                }
                total_input = plan.backing_input_units;
                if (plan.residual_units > 0) {
                    tx.outputs.push_back(TxOutput(plan.residual_units, script));
                    change_amount = plan.residual_units;
                }
                tx.outputs.push_back(TxOutput(amount_units - fee, script));
            } else {
                CoinSelection coins = SelectWalletCoins_(address, 0, fee);
                if (!coins.sufficient)
                    throw std::runtime_error(
                        DiagnoseFeeSelectFailed(chain_, mempool_, script, fee));
                for (auto& utxo : coins.selected_utxos) {
                    TxInput inp;
                    inp.prev_tx_hash = utxo.tx_hash;
                    inp.prev_out_index = utxo.output_index;
                    tx.inputs.push_back(inp);
                }
                if (coins.change_amount > 0)
                    tx.outputs.push_back(TxOutput(coins.change_amount, script));
                total_input = coins.total_input;
                change_amount = coins.change_amount;
            }

            std::vector<uint8_t> op_return_script;
            op_return_script.push_back(0x6A);
            std::vector<uint8_t> data(unstake_op.begin(), unstake_op.end());
            if (data.size() <= 75) {
                op_return_script.push_back((uint8_t)data.size());
            } else if (data.size() <= 255) {
                op_return_script.push_back(0x4C);
                op_return_script.push_back((uint8_t)data.size());
            } else {
                op_return_script.push_back(0x4D);
                op_return_script.push_back((uint8_t)(data.size() & 0xFF));
                op_return_script.push_back((uint8_t)((data.size() >> 8) & 0xFF));
            }
            op_return_script.insert(op_return_script.end(), data.begin(), data.end());
            tx.outputs.push_back(TxOutput(0, op_return_script));

            auto raw = tx.Serialize();
            std::string unsigned_tx_hex = BytesToHex(raw);

            // Compute sighash for each input
            std::vector<std::string> input_items;
            for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
                Hash256 sighash = ComputeSighash(tx, i, script);
                input_items.push_back(JB::Object({
                    {"index", JB::Number((uint64_t)i)},
                    {"sighash_hex", JB::String(BytesToHex(sighash))},
                    {"prev_script_hex", JB::String(BytesToHex(script))},
                }));
            }

            std::ostringstream unstaked_str;
            double amount_veld_d = (double)amount_units / (double)VELD_UNITS;
            unstaked_str << std::fixed << std::setprecision(8) << amount_veld_d;

            return JB::Object({
                {"unsigned_tx_hex", JB::String(unsigned_tx_hex)},
                {"inputs", JB::Array(input_items)},
                {"total_input", JB::Number(total_input)},
                {"total_output", JB::Number(total_input - fee)},
                {"fee", JB::Number(fee)},
                {"change", JB::Number(change_amount)},
                {"unstaked_veld", JB::String(unstaked_str.str())},
            });
        });

        methods_["prepareregistervalidator"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() < 2)
                throw std::invalid_argument(
                    "Usage: prepareregistervalidator <address> <pubkey_hex>");

            const std::string& address = params[0];
            const std::string& pubkey_hex = params[1];
            if (pubkey_hex.size() != 3904)
                throw std::invalid_argument(
                    "Public key must be 3904 hex characters (1952 bytes, ML-DSA-65)");
            for (char c : pubkey_hex) {
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                    throw std::invalid_argument("Public key contains non-hex characters");
            }
            const auto validator_pk_bytes = HexToBytes(pubkey_hex);
            if (validator_pk_bytes.size() != 1952)
                throw std::invalid_argument("Public key failed hex decode to 1952 bytes");
            const std::string validator_address =
                ValidatorRegistry::PubkeyToAddress(validator_pk_bytes);
            if (validator_address.empty() || validator_address != address)
                throw std::invalid_argument(
                    "Address does not correspond to the supplied validator public key");

            // Reject a second pending registration for this exact public key.
            // Match the complete canonical OP_RETURN marker so malformed or
            // unrelated prefix matches cannot block legitimate registration.
            // only fires when THIS pubkey is genuinely already pending.
            if (mempool_.HasPendingOpReturn("VELD_VALIDATOR|REGISTER|" + pubkey_hex))
                throw std::runtime_error(
                    "Your validator registration is already pending. Wait for it to be mined.");

            if (validators_ && validators_->IsRegistered(pubkey_hex))
                return JB::Object({{"status", JB::String("already_registered")},
                                   {"pubkey", JB::String(pubkey_hex)}});

            if (validators_) {
                auto lifecycle = validators_->GetBondLifecycleStatus(pubkey_hex);
                const uint64_t prospective_height = chain_.Height() + 1;
                if (lifecycle.found && lifecycle.slashed) {
                    throw std::runtime_error(
                        "Cannot re-register a permanently slashed validator key; "
                        "use a fresh ML-DSA validator key and a fresh bond.");
                }
                if (lifecycle.found && lifecycle.bond_custodial && !lifecycle.slashed &&
                    lifecycle.bond_units > 0 && lifecycle.deregistered_at_height > 0 &&
                    lifecycle.return_boundary >= prospective_height) {
                    throw std::runtime_error(
                        "Cannot re-register this validator key while its prior "
                        "custodial bond remains slashable/pending return. The "
                        "mandatory return settles at block " +
                        std::to_string(lifecycle.return_boundary) +
                        "; re-register in a later block with a new bond.");
                }
                if (validators_->HasPendingBondYield(pubkey_hex)) {
                    throw std::runtime_error(
                        "Cannot re-register this validator key while its prior "
                        "term still has unsettled bond-yield tranches. Wait for "
                        "the final tranche to release or be confiscated, or use "
                        "a fresh ML-DSA validator key and fresh bond.");
                }
            }

            uint64_t effective_min =
                validators_ ? validators_->GetEffectiveMinStake() : MIN_VALIDATOR_STAKE;
            bool custodial_bond = (chain_.Height() + 1) >= STAKE_VAULT_ACTIVATION_HEIGHT;
            if (!custodial_bond) {
                if (validators_ && staking_) {
                    uint64_t user_stake = staking_->GetStake(address);
                    if (user_stake < effective_min) {
                        double need = (double)effective_min / VELD_UNITS;
                        double have = (double)user_stake / VELD_UNITS;
                        throw std::runtime_error("Must stake at least " +
                                                 std::to_string((uint64_t)need) +
                                                 " VELD before registering (you have " +
                                                 std::to_string((uint64_t)have) + " staked)");
                    }
                }
            }

            std::string reg_op = ValidatorRegistry::BuildRegisterOp(pubkey_hex);
            std::vector<uint8_t> op_bytes(reg_op.begin(), reg_op.end());
            std::vector<uint8_t> op_script;
            op_script.push_back(0x6A);
            if (op_bytes.size() <= 75) {
                op_script.push_back((uint8_t)op_bytes.size());
            } else if (op_bytes.size() <= 255) {
                op_script.push_back(0x4C);
                op_script.push_back((uint8_t)op_bytes.size());
            } else {
                op_script.push_back(0x4D);
                op_script.push_back((uint8_t)(op_bytes.size() & 0xFF));
                op_script.push_back((uint8_t)((op_bytes.size() >> 8) & 0xFF));
            }
            op_script.insert(op_script.end(), op_bytes.begin(), op_bytes.end());

            auto script = AddressToScript(address);
            uint64_t fee = MIN_TX_FEE;
            uint64_t reg_target = custodial_bond ? effective_min : 0;
            CoinSelection coins = SelectWalletCoins_(address, reg_target, fee);
            if (!coins.sufficient)
                throw std::runtime_error(
                    custodial_bond ? ("Insufficient funds: a custodial validator bond now "
                                      "requires " +
                                      std::to_string(effective_min / VELD_UNITS) +
                                      " VELD sent to the protocol stake vault, plus the fee")
                                   : "Insufficient funds for registration fee");

            Transaction tx;
            for (auto& utxo : coins.selected_utxos) {
                TxInput inp;
                inp.prev_tx_hash = utxo.tx_hash;
                inp.prev_out_index = utxo.output_index;
                tx.inputs.push_back(inp);
            }
            if (custodial_bond) {
                auto sv_script = AddressToScript(STAKE_VAULT_ADDRESS);
                if (sv_script.empty())
                    throw std::runtime_error("STAKE_VAULT_ADDRESS misconfigured");
                tx.outputs.push_back(TxOutput(effective_min, sv_script));
            }
            if (coins.change_amount > 0)
                tx.outputs.push_back(TxOutput(coins.change_amount, script));
            tx.outputs.push_back(TxOutput(0, op_script));

            auto raw = tx.Serialize();
            std::string unsigned_tx_hex = BytesToHex(raw);

            // Compute sighash for each input
            std::vector<std::string> input_items;
            for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
                Hash256 sighash = ComputeSighash(tx, i, script);
                input_items.push_back(JB::Object({
                    {"index", JB::Number((uint64_t)i)},
                    {"sighash_hex", JB::String(BytesToHex(sighash))},
                    {"prev_script_hex", JB::String(BytesToHex(script))},
                }));
            }

            uint64_t total_input = 0;
            for (auto& utxo : coins.selected_utxos)
                total_input += utxo.value;
            if (reg_target > MAX_SUPPLY_UNITS ||
                coins.change_amount > MAX_SUPPLY_UNITS - reg_target)
                throw std::runtime_error("Validator registration output total overflow");
            const uint64_t total_output = reg_target + coins.change_amount;

            return JB::Object({
                {"unsigned_tx_hex", JB::String(unsigned_tx_hex)},
                {"inputs", JB::Array(input_items)},
                {"total_input", JB::Number(total_input)},
                {"total_output", JB::Number(total_output)},
                {"fee", JB::Number(fee)},
                {"change", JB::Number(coins.change_amount)},
            });
        });

        methods_["preparederegistervalidator"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() < 2)
                throw std::invalid_argument(
                    "Usage: preparederegistervalidator <address> <pubkey_hex>");

            const std::string& address = params[0];
            const std::string& pubkey_hex = params[1];
            if (pubkey_hex.size() != 3904)
                throw std::invalid_argument(
                    "Public key must be 3904 hex characters (1952 bytes, ML-DSA-65)");

            if (mempool_.HasPendingOpReturn("VELD_VALIDATOR|DEREGISTER|" + pubkey_hex))
                throw std::runtime_error(
                    "Your validator deregistration is already pending. Wait for it to be mined.");

            if (validators_ && !validators_->IsRegistered(pubkey_hex))
                return JB::Object({{"status", JB::String("not_registered")}});

            // Cooldown pre-check — match the consensus DEREGISTER gate exactly
            // so we never hand back a tx that can never be mined. ProcessBlock
            // rejects a DEREGISTER while block.height < last_op_height[address]
            // + VALIDATOR_OP_COOLDOWN_BLOCKS (100). The earliest block this tx
            // could land in is chain_.Height()+1; if even that is below the
            // unlock height, the tx is unminable and we refuse to build it.
            if (validators_) {
                auto cd = validators_->GetDeregisterCooldown(pubkey_hex);
                if (cd.found && cd.unlock_height > 0 && chain_.Height() + 1 < cd.unlock_height) {
                    throw std::runtime_error(
                        "Cannot deregister yet — validator operations have a " +
                        std::to_string(VALIDATOR_OP_COOLDOWN_BLOCKS) +
                        "-block cooldown. You registered at block " +
                        std::to_string(cd.registered_height) + " and can deregister at block " +
                        std::to_string(cd.unlock_height) + " (current height " +
                        std::to_string(chain_.Height()) + ").");
                }
            }

            std::string dereg_op = ValidatorRegistry::BuildDeregisterOp(pubkey_hex);
            std::vector<uint8_t> op_bytes(dereg_op.begin(), dereg_op.end());
            std::vector<uint8_t> op_script;
            op_script.push_back(0x6A);
            if (op_bytes.size() <= 75) {
                op_script.push_back((uint8_t)op_bytes.size());
            } else if (op_bytes.size() <= 255) {
                op_script.push_back(0x4C);
                op_script.push_back((uint8_t)op_bytes.size());
            } else {
                op_script.push_back(0x4D);
                op_script.push_back((uint8_t)(op_bytes.size() & 0xFF));
                op_script.push_back((uint8_t)((op_bytes.size() >> 8) & 0xFF));
            }
            op_script.insert(op_script.end(), op_bytes.begin(), op_bytes.end());

            auto script = AddressToScript(address);
            uint64_t fee = MIN_TX_FEE;
            CoinSelection coins = SelectWalletCoins_(address, 0, fee);
            if (!coins.sufficient)
                throw std::runtime_error("Insufficient funds for deregistration fee");

            Transaction tx;
            for (auto& utxo : coins.selected_utxos) {
                TxInput inp;
                inp.prev_tx_hash = utxo.tx_hash;
                inp.prev_out_index = utxo.output_index;
                tx.inputs.push_back(inp);
            }
            if (coins.change_amount > 0)
                tx.outputs.push_back(TxOutput(coins.change_amount, script));
            tx.outputs.push_back(TxOutput(0, op_script));

            auto raw = tx.Serialize();
            std::string unsigned_tx_hex = BytesToHex(raw);

            // Compute sighash for each input
            std::vector<std::string> input_items;
            for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
                Hash256 sighash = ComputeSighash(tx, i, script);
                input_items.push_back(JB::Object({
                    {"index", JB::Number((uint64_t)i)},
                    {"sighash_hex", JB::String(BytesToHex(sighash))},
                    {"prev_script_hex", JB::String(BytesToHex(script))},
                }));
            }

            uint64_t total_input = 0;
            for (auto& utxo : coins.selected_utxos)
                total_input += utxo.value;

            return JB::Object({
                {"unsigned_tx_hex", JB::String(unsigned_tx_hex)},
                {"inputs", JB::Array(input_items)},
                {"total_input", JB::Number(total_input)},
                {"total_output", JB::Number(coins.change_amount)},
                {"fee", JB::Number(fee)},
                {"change", JB::Number(coins.change_amount)},
            });
        });

        methods_["prepareslashvalidator"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() < 7)
                throw std::invalid_argument(
                    "Usage: prepareslashvalidator <address> <pubkey_hex> <signed_height>"
                    " <hash_a_hex> <sig_a_hex> <hash_b_hex> <sig_b_hex>");

            const std::string& address = params[0];
            const std::string& pubkey_hex = params[1];
            const uint64_t sig_height = ParseCanonicalRpcU64OrThrow(params[2], "signed_height");
            const std::string& hash_a_hex = params[3];
            const std::string& sig_a_hex = params[4];
            const std::string& hash_b_hex = params[5];
            const std::string& sig_b_hex = params[6];

            auto is_hex = [](char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            };

            if (pubkey_hex.size() != 3904)
                throw std::invalid_argument(
                    "Public key must be 3904 hex characters (1952 bytes, ML-DSA-65)");
            for (char c : pubkey_hex)
                if (!is_hex(c))
                    throw std::invalid_argument("Public key contains non-hex characters");

            if (hash_a_hex.size() != 64 || hash_b_hex.size() != 64)
                throw std::invalid_argument("Block hashes must be 64 hex characters (SHA-256)");
            for (char c : hash_a_hex)
                if (!is_hex(c))
                    throw std::invalid_argument("hash_a contains non-hex characters");
            for (char c : hash_b_hex)
                if (!is_hex(c))
                    throw std::invalid_argument("hash_b contains non-hex characters");
            if (hash_a_hex == hash_b_hex)
                throw std::invalid_argument("hash_a and hash_b must differ (distinct blocks)");

            if (sig_a_hex.size() != 6618 || sig_b_hex.size() != 6618)
                throw std::invalid_argument(
                    "Signatures must be 6618 hex characters (ML-DSA-65, 3309 bytes)");
            for (char c : sig_a_hex)
                if (!is_hex(c))
                    throw std::invalid_argument("sig_a contains non-hex characters");
            for (char c : sig_b_hex)
                if (!is_hex(c))
                    throw std::invalid_argument("sig_b contains non-hex characters");
            if (sig_a_hex == sig_b_hex)
                throw std::invalid_argument("sig_a and sig_b must differ (distinct signatures)");

            uint64_t tip_height = chain_.Height();
            if (sig_height > tip_height)
                throw std::invalid_argument(
                    "signed_height is in the future relative to current tip");
            if (tip_height > sig_height && tip_height - sig_height >= SLASH_EVIDENCE_WINDOW)
                throw std::invalid_argument("Evidence age (" +
                                            std::to_string(tip_height - sig_height) +
                                            " blocks) is at or past SLASH_EVIDENCE_WINDOW (" +
                                            std::to_string(SLASH_EVIDENCE_WINDOW) +
                                            "); consensus would reject after one more block");

            if (!validators_)
                throw std::runtime_error("Validator registry unavailable");
            auto lifecycle = validators_->GetBondLifecycleStatus(pubkey_hex);
            if (!lifecycle.found)
                throw std::runtime_error("Validator pubkey is not known on chain");
            const uint64_t prospective_height = tip_height + 1;
            if (!validators_->CanAcceptSlashEvidence(pubkey_hex, sig_height, prospective_height)) {
                if (!lifecycle.slashed && lifecycle.return_boundary > 0 &&
                    prospective_height >= lifecycle.return_boundary) {
                    throw std::runtime_error(
                        "The deregistered validator's evidence window has closed "
                        "and its custodial bond reached return boundary " +
                        std::to_string(lifecycle.return_boundary));
                }
                if (sig_height < lifecycle.registered_height) {
                    throw std::runtime_error("Evidence predates this validator registration term");
                }
                throw std::runtime_error(
                    "Slash evidence is not admissible at the next block height");
            }

            if (validators_->IsAlreadySlashed(pubkey_hex, sig_height))
                throw std::runtime_error(
                    "Evidence for this (pubkey, signed_height) is already on chain");

            auto a_bytes = HexToBytes(hash_a_hex);
            auto b_bytes = HexToBytes(hash_b_hex);
            if (a_bytes.size() != 32 || b_bytes.size() != 32)
                throw std::invalid_argument("Block hashes failed hex decode to 32 bytes");
            Hash256 hash_a, hash_b;
            std::copy(a_bytes.begin(), a_bytes.end(), hash_a.begin());
            std::copy(b_bytes.begin(), b_bytes.end(), hash_b.begin());
            if (!ValidatorRegistry::VerifyEndorseSignature(pubkey_hex, sig_height, hash_a,
                                                           sig_a_hex))
                throw std::runtime_error("sig_a does not verify against pubkey at signed_height");
            if (!ValidatorRegistry::VerifyEndorseSignature(pubkey_hex, sig_height, hash_b,
                                                           sig_b_hex))
                throw std::runtime_error("sig_b does not verify against pubkey at signed_height");

            std::string canonical_prefix = std::string("VELD_VALIDATOR|SLASH|") + pubkey_hex + "|" +
                                           std::to_string(sig_height) + "|";
            if (mempool_.HasPendingOpReturn(canonical_prefix))
                throw std::runtime_error(
                    "A SLASH TX for this (pubkey, signed_height) is already pending");

            std::string slash_op = ValidatorRegistry::BuildSlashOp(
                pubkey_hex, sig_height, hash_a_hex, sig_a_hex, hash_b_hex, sig_b_hex);
            std::vector<uint8_t> op_bytes(slash_op.begin(), slash_op.end());
            std::vector<uint8_t> op_script;
            op_script.push_back(0x6A);
            if (op_bytes.size() <= 75) {
                op_script.push_back((uint8_t)op_bytes.size());
            } else if (op_bytes.size() <= 255) {
                op_script.push_back(0x4C);
                op_script.push_back((uint8_t)op_bytes.size());
            } else {
                op_script.push_back(0x4D);
                op_script.push_back((uint8_t)(op_bytes.size() & 0xFF));
                op_script.push_back((uint8_t)((op_bytes.size() >> 8) & 0xFF));
            }
            op_script.insert(op_script.end(), op_bytes.begin(), op_bytes.end());

            auto script = AddressToScript(address);
            uint64_t fee = MIN_TX_FEE;
            CoinSelection coins = SelectWalletCoins_(address, 0, fee);
            if (!coins.sufficient)
                throw std::runtime_error("Insufficient funds for slash submission fee");

            Transaction tx;
            for (auto& utxo : coins.selected_utxos) {
                TxInput inp;
                inp.prev_tx_hash = utxo.tx_hash;
                inp.prev_out_index = utxo.output_index;
                tx.inputs.push_back(inp);
            }
            if (coins.change_amount > 0)
                tx.outputs.push_back(TxOutput(coins.change_amount, script));
            tx.outputs.push_back(TxOutput(0, op_script));

            auto raw = tx.Serialize();
            std::string unsigned_tx_hex = BytesToHex(raw);

            std::vector<std::string> input_items;
            for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
                Hash256 sighash = ComputeSighash(tx, i, script);
                input_items.push_back(JB::Object({
                    {"index", JB::Number((uint64_t)i)},
                    {"sighash_hex", JB::String(BytesToHex(sighash))},
                    {"prev_script_hex", JB::String(BytesToHex(script))},
                }));
            }

            uint64_t total_input = 0;
            for (auto& utxo : coins.selected_utxos)
                total_input += utxo.value;

            return JB::Object({
                {"unsigned_tx_hex", JB::String(unsigned_tx_hex)},
                {"inputs", JB::Array(input_items)},
                {"total_input", JB::Number(total_input)},
                {"total_output", JB::Number((uint64_t)0)},
                {"fee", JB::Number(fee)},
                {"change", JB::Number(coins.change_amount)},
                {"op_return_bytes", JB::Number((uint64_t)op_bytes.size())},
            });
        });

        methods_["getvalidatorhistory"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument(
                    "Usage: getvalidatorhistory <address> [page] [per_page] [filter] [scan_from]");
            const std::string& address = params[0];
            auto script = AddressToScript(address);
            if (script.empty())
                throw rpc_error(-32602, "Invalid address");
            int page = 1, per_page = 20;
            std::string filter = "all";
            if (params.size() >= 2) {
                const uint64_t value = ParseCanonicalRpcU64OrThrow(params[1], "page");
                if (value > static_cast<uint64_t>(std::numeric_limits<int>::max()))
                    throw std::invalid_argument("page is out of range");
                page = static_cast<int>(value);
            }
            if (params.size() >= 3) {
                const uint64_t value = ParseCanonicalRpcU64OrThrow(params[2], "per_page");
                if (value > static_cast<uint64_t>(std::numeric_limits<int>::max()))
                    throw std::invalid_argument("per_page is out of range");
                per_page = static_cast<int>(value);
            }
            if (params.size() >= 4)
                filter = params[3];
            if (page < 1)
                page = 1;
            if (per_page < 1)
                per_page = 1;
            if (per_page > 500)
                per_page = 500;
            if (filter != "paid" && filter != "pending")
                filter = "all";

            auto ep_script = AddressToScript(ENDORSEMENT_POOL_ADDRESS);
            uint64_t cur_h = chain_.Height();
            constexpr uint64_t HISTORY_DEFAULT_LOOKBACK = 2000;
            constexpr uint64_t HISTORY_HARD_LOOKBACK = 10000;
            uint64_t lookback = HISTORY_DEFAULT_LOOKBACK;
            if (params.size() >= 5) {
                uint64_t want = ParseCanonicalRpcU64OrThrow(params[4], "scan_from");
                if (want > HISTORY_HARD_LOOKBACK)
                    want = HISTORY_HARD_LOOKBACK;
                if (want > 0)
                    lookback = want;
            }
            uint64_t scan_from = cur_h > lookback ? cur_h - lookback : 0;

            double reward_per_endorsement_est = 0.0;
            if (validators_) {
                reward_per_endorsement_est = validators_->GetLastFlushRewardPerEndorsement();
            }
            if (reward_per_endorsement_est <= 0.0) {
                uint64_t ep_total = chain_.GetBalance(ep_script);
                uint64_t win_start = cur_h > 100 ? cur_h - 100 : 1;
                uint64_t recent_eds = 0;
                if (validators_) {
                    for (uint64_t h = win_start; h <= cur_h; ++h)
                        recent_eds += validators_->GetEndorsements(h).size();
                }
                if (recent_eds == 0)
                    recent_eds = 1;
                reward_per_endorsement_est = (double)ep_total / VELD_UNITS / (double)recent_eds;
            }

            std::map<uint64_t, uint64_t> flush_paid_to_addr;
            uint64_t b_start =
                ((scan_from + VAULT_DISTRIBUTION_INTERVAL - 1) / VAULT_DISTRIBUTION_INTERVAL) *
                VAULT_DISTRIBUTION_INTERVAL;
            if (b_start == 0)
                b_start = VAULT_DISTRIBUTION_INTERVAL;
            for (uint64_t b = b_start; b <= cur_h; b += VAULT_DISTRIBUTION_INTERVAL) {
                Block blk;
                try {
                    blk = chain_.GetBlock(b);
                } catch (...) {
                    continue;
                }
                for (size_t i = 1; i < blk.transactions.size(); ++i) {
                    const auto& tx = blk.transactions[i];
                    if (tx.inputs.empty())
                        continue;

                    bool any_oprt = false;
                    for (const auto& o : tx.outputs) {
                        if (!o.script_pubkey.empty() && o.script_pubkey[0] == 0x6A) {
                            any_oprt = true;
                            break;
                        }
                    }
                    if (any_oprt)
                        continue;

                    bool sigless = tx.inputs[0].script_sig.empty();
                    bool all_p2pkh = !tx.outputs.empty();
                    for (const auto& o : tx.outputs) {
                        if (o.script_pubkey.size() != 25 || o.script_pubkey[0] != 0x76) {
                            all_p2pkh = false;
                            break;
                        }
                    }
                    if (!sigless || !all_p2pkh)
                        continue;

                    uint64_t paid = 0;
                    for (const auto& out : tx.outputs) {
                        if (out.script_pubkey == script)
                            paid += out.value;
                    }
                    if (paid > 0)
                        flush_paid_to_addr[b] = paid;
                    break;
                }
            }
            (void)ep_script;

            std::map<uint64_t, uint64_t> match_count_per_boundary;
            if (validators_) {
                for (const auto& [boundary, paid_total] : flush_paid_to_addr) {
                    (void)paid_total;
                    uint64_t win_start = boundary > VAULT_DISTRIBUTION_INTERVAL
                                             ? boundary - VAULT_DISTRIBUTION_INTERVAL + 1
                                             : 1;
                    uint64_t cnt = 0;
                    for (uint64_t hh = win_start; hh <= boundary; ++hh) {
                        auto eds = validators_->GetEndorsements(hh);
                        for (auto& e : eds) {
                            if (e.address == address)
                                cnt++;
                        }
                    }
                    if (cnt > 0)
                        match_count_per_boundary[boundary] = cnt;
                }
            }

            std::vector<std::string> entries;
            double total_rewards = 0;
            double paid_rewards = 0;
            double pending_rewards = 0;
            uint64_t paid_count = 0;
            uint64_t pending_count = 0;

            if (validators_) {
                for (uint64_t h = cur_h; h >= scan_from; --h) {
                    auto eds = validators_->GetEndorsements(h);
                    for (auto& e : eds) {
                        if (e.address != address)
                            continue;
                        uint64_t boundary = ((h - 1) / VAULT_DISTRIBUTION_INTERVAL + 1) *
                                            VAULT_DISTRIBUTION_INTERVAL;

                        double reward;
                        if (e.reward_paid) {
                            uint64_t paid_total = 0;
                            uint64_t paid_count_in_window = 0;
                            auto fit = flush_paid_to_addr.find(boundary);
                            if (fit != flush_paid_to_addr.end())
                                paid_total = fit->second;
                            auto cit = match_count_per_boundary.find(boundary);
                            if (cit != match_count_per_boundary.end())
                                paid_count_in_window = cit->second;
                            if (paid_count_in_window > 0) {
                                reward = ((double)paid_total / (double)paid_count_in_window) /
                                         (double)VELD_UNITS;
                            } else {
                                reward = 0.0;
                            }
                            paid_rewards += reward;
                            ++paid_count;
                        } else {
                            reward = reward_per_endorsement_est;
                            pending_rewards += reward;
                            ++pending_count;
                        }
                        total_rewards += reward;

                        bool include = (filter == "all") || (filter == "paid" && e.reward_paid) ||
                                       (filter == "pending" && !e.reward_paid);
                        if (include) {
                            std::ostringstream entry;
                            entry << std::fixed << std::setprecision(8);
                            entry << "{";
                            entry << "\"height\":" << e.block_height << ",";
                            entry << "\"reward_veld\":" << reward << ",";
                            entry << "\"reward_paid\":" << (e.reward_paid ? "true" : "false");
                            entry << "}";
                            entries.push_back(entry.str());
                        }
                    }
                    if (h == 0)
                        break;
                }
            }

            double on_chain_paid_total = 0;
            for (const auto& [b, v] : flush_paid_to_addr) {
                (void)b;
                on_chain_paid_total += (double)v / (double)VELD_UNITS;
            }
            if (on_chain_paid_total > paid_rewards) {
                paid_rewards = on_chain_paid_total;
                total_rewards = paid_rewards + pending_rewards;
            }

            int total_filtered = (int)entries.size();
            int start = (page - 1) * per_page;
            int end = std::min(start + per_page, total_filtered);
            if (start > total_filtered)
                start = total_filtered;
            int total_pages = (per_page > 0) ? (total_filtered + per_page - 1) / per_page : 1;
            if (total_pages < 1)
                total_pages = 1;

            std::ostringstream j;
            j << std::fixed << std::setprecision(8);
            j << "{";
            j << "\"total\":" << (paid_count + pending_count) << ",";
            j << "\"total_filtered\":" << total_filtered << ",";
            j << "\"page\":" << page << ",";
            j << "\"per_page\":" << per_page << ",";
            j << "\"total_pages\":" << total_pages << ",";
            j << "\"filter\":\"" << filter << "\",";
            j << "\"total_rewards_veld\":" << total_rewards << ",";
            j << "\"paid_rewards_veld\":" << paid_rewards << ",";
            j << "\"pending_rewards_veld\":" << pending_rewards << ",";
            j << "\"paid_count\":" << paid_count << ",";
            j << "\"pending_count\":" << pending_count << ",";
            j << "\"reward_per_endorsement_est\":" << reward_per_endorsement_est << ",";
            j << "\"endorsements\":[";
            for (int i = start; i < end; ++i) {
                if (i > start)
                    j << ",";
                j << entries[i];
            }
            j << "]}";
            return j.str();
        });

        methods_["endorseblock"] =
            RpcMethod([](const P&) -> std::string { throw rpc_error(-32601, "method removed"); });

#ifndef VELD_FLEET_NO_MINE
        methods_["getblocktemplate"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() != 1)
                throw std::invalid_argument("Usage: getblocktemplate <miner_address>");

            std::string miner_addr = params[0];
            auto miner_script = AddressToScript(miner_addr);
            if (miner_script.empty())
                throw std::invalid_argument("Invalid miner address");

            // Keep the canonical parent, every module snapshot consulted by
            // mempool selection, the finished template, and its exact module
            // preflight in one coherent pre- or post-block frame.  Without
            // this guard AddBlockDirect can publish chain N before on_commit_
            // has advanced modules from N-1, yielding an invalid external
            // template even though the in-process miner is protected.
            auto transition_guard = chain_.AcquireConsensusTransitionGuard();
            if (chain_.IsEmpty())
                throw std::runtime_error("Chain not ready");
            if (!mining_template_preflight_fn_)
                throw rpc_error(-32603,
                                "getblocktemplate unavailable: full module preflight is not wired");
            if (!work_admission_fn_)
                throw rpc_error(-32010,
                                "getblocktemplate unavailable: work admission is not wired");
            if (!issue_block_template_authorization_fn_)
                throw rpc_error(
                    -32010, "getblocktemplate unavailable: template authorization is not wired");

            const Block canonical_tip = chain_.TipCopy();
            work_admission::Subject work_subject;
            work_subject.purpose = work_admission::Purpose::BlockProduction;
            work_subject.height = canonical_tip.height + 1;
            work_subject.parent_height = canonical_tip.height;
            work_subject.parent_hash = canonical_tip.GetHash();
            work_admission::Decision work_decision;
            try {
                work_decision = work_admission_fn_(work_admission::Path::GetBlockTemplate,
                                                   work_subject, std::nullopt, false);
            } catch (...) {
                work_decision = {false, work_admission::Refusal::Unwired, std::nullopt};
            }
            if (!work_decision.allowed || !work_decision.binding) {
                throw rpc_error(-32010, std::string("getblocktemplate refused: ") +
                                            work_admission::RefusalName(work_decision.refusal));
            }

            Block candidate;
            candidate.height = work_subject.height;
            candidate.header.version = PROTOCOL_VERSION;
            candidate.header.prev_block_hash = work_subject.parent_hash;
            candidate.header.timestamp = (uint64_t)std::time(nullptr);
            candidate.header.bits = chain_.ComputeNextBits();
            candidate.header.nonce = 0;

            // RpcServer does not own the node's staking/validator settlement
            // builders.  Never hand an external miner a knowingly incomplete
            // boundary template; the in-process VeldNode builder derives and
            // embeds those canonical transactions.
            if ((candidate.height % COMINE_WINDOW_BLOCKS) == 0 ||
                (candidate.height % VAULT_DISTRIBUTION_INTERVAL) == 0 ||
                (candidate.height % BOND_SETTLEMENT_INTERVAL) == 0) {
                throw rpc_error(-32603, "getblocktemplate unavailable at a mandatory protocol "
                                        "settlement height; use the in-process VeldNode miner");
            }

            auto vault_script = AddressToScript(VaultAddressAtHeight(candidate.height));
            auto pool_script = AddressToScript(POOL_ADDRESS);
            auto endorse_script = AddressToScript(ENDORSEMENT_POOL_ADDRESS);

            // Reserve the complete 92-byte block envelope plus a canonically
            // serialized maximum coinbase built from the actual launch scripts.
            // Amounts are fixed-width, so the eventual fee total cannot change
            // this size; the real coinbase is a subset of this output shape.
            std::vector<std::pair<std::vector<uint8_t>, uint64_t>> max_cb_outputs;
            for (const auto* script :
                 {&miner_script, &pool_script, &vault_script, &endorse_script}) {
                if (!script->empty())
                    max_cb_outputs.push_back({*script, 1});
            }
            if (max_cb_outputs.empty())
                throw std::runtime_error("No canonical coinbase destination");
            const size_t max_coinbase_size =
                Transaction::CreateProportionalCoinbase(
                    max_cb_outputs, "Veld block " + std::to_string(candidate.height))
                    .Serialize()
                    .size();
            if (max_coinbase_size > (size_t)MAX_BLOCK_SIZE - 92)
                throw std::runtime_error("Canonical coinbase exceeds the block-size envelope");
            const size_t mempool_byte_budget = (size_t)MAX_BLOCK_SIZE - 92 - max_coinbase_size;
            // External miners must receive the same current-state AMM covenant
            // revalidation as the in-process miner.  Without the chain view, a
            // quote made stale by a pool rotation (or an unchecked legacy
            // poison entry) could be handed out in an invalid template.
            auto mempool_raw = mempool_.GetBlockTransactionsWithFees(
                std::min<size_t>(999, MAX_TRANSACTIONS_PER_BLOCK - 1), mempool_byte_budget,
                &chain_);
            std::vector<std::pair<Transaction, uint64_t>> mempool_txs;
            for (auto& [tx, fee] : mempool_raw) {
                if (tx.IsCoinbase())
                    continue;
                bool ok = true;
                for (const auto& inp : tx.inputs) {
                    if (inp.IsCoinbase())
                        continue;
                    if (!chain_.GetUTXO(inp.prev_tx_hash, inp.prev_out_index)) {
                        ok = false;
                        break;
                    }
                }
                if (ok) {
                    try {
                        if (!chain_.ValidateTransactionLocking(tx, false)) {
                            ok = false;
                        }
                    } catch (...) {
                        ok = false;
                    }
                }
                if (ok)
                    mempool_txs.push_back({tx, fee});
            }

            // Match the in-process miner: resolve same-candidate Bitcoin
            // header dependencies before the existing all-module preflight.
            btcspv::StableDependencyOrderBtcHeaderTransactions(mempool_txs);

            const bool is_vault_block =
                candidate.height > 0 && candidate.height % VAULT_BLOCK_INTERVAL == 0;
            const uint64_t total_supply_now = chain_.TotalSupplyUnits();
            const uint64_t remaining_to_cap =
                MAX_SUPPLY_UNITS > total_supply_now ? MAX_SUPPLY_UNITS - total_supply_now : 0;
            const uint64_t effective_reward =
                std::min(Blockchain::ExpectedBlockSubsidy(candidate.height), remaining_to_cap);
            const bool is_pre_activation = total_supply_now < STAKING_UNLOCK_SUPPLY;

            // Match MineOnly and ValidateCanonicalCoinbaseSplit exactly so
            // locally submitted templates use the canonical reward split.
            auto build_coinbase = [&](uint64_t fees) {
                std::vector<std::pair<std::vector<uint8_t>, uint64_t>> outputs;
                if (effective_reward == 0) {
                    if (fees > 0) {
                        const uint64_t vault_cut = (fees * 40) / 100;
                        const uint64_t endorse_cut = (fees * 10) / 100;
                        const uint64_t miner_cut = fees - vault_cut - endorse_cut;
                        outputs.push_back({miner_script, miner_cut});
                        if (!vault_script.empty() && vault_script != miner_script)
                            outputs.push_back({vault_script, vault_cut});
                        else
                            outputs[0].second += vault_cut;
                        if (!endorse_script.empty() && endorse_cut > 0)
                            outputs.push_back({endorse_script, endorse_cut});
                        else
                            outputs[0].second += endorse_cut;
                    } else {
                        outputs.push_back({vault_script, 0});
                    }
                } else if (is_vault_block) {
                    outputs.push_back({vault_script, effective_reward + fees});
                } else if (is_pre_activation) {
                    const uint64_t miner_cut = (effective_reward * 50) / 100;
                    const uint64_t vault_cut = effective_reward - miner_cut + fees;
                    outputs.push_back({miner_script, miner_cut});
                    if (!vault_script.empty() && vault_script != miner_script)
                        outputs.push_back({vault_script, vault_cut});
                    else
                        outputs[0].second += vault_cut;
                } else {
                    const uint64_t pool_cut = (effective_reward * 20) / 100;
                    const uint64_t vault_cut = (effective_reward * 20) / 100;
                    const uint64_t endorse_cut = (effective_reward * 10) / 100;
                    const uint64_t winner_cut =
                        effective_reward - pool_cut - vault_cut - endorse_cut;
                    const uint64_t vault_total = vault_cut + fees;
                    outputs.push_back({miner_script, winner_cut});
                    if (!pool_script.empty() && pool_script != miner_script)
                        outputs.push_back({pool_script, pool_cut});
                    else
                        outputs[0].second += pool_cut;
                    if (!vault_script.empty() && vault_script != miner_script)
                        outputs.push_back({vault_script, vault_total});
                    else
                        outputs[0].second += vault_total;
                    if (!endorse_script.empty() && endorse_script != miner_script)
                        outputs.push_back({endorse_script, endorse_cut});
                    else
                        outputs[0].second += endorse_cut;
                }
                return Transaction::CreateProportionalCoinbase(
                    outputs, "Veld block " + std::to_string(candidate.height));
            };

            // Run the same constructive selector as MineOnly.  The existing
            // mempool/AMM and Bitcoin-header dependency ordering is the shared
            // deterministic priority order; excluded trials remain in mempool.
            auto full_preflight = [&](const Block& trial) {
                try {
                    return mining_template_preflight_fn_(trial);
                } catch (...) {
                    return false;
                }
            };
            const std::vector<Transaction> mandatory_txs;
            auto selection = mining::SelectConstructivePreflightCandidate(
                candidate, mempool_txs, mandatory_txs, build_coinbase, full_preflight);
            if (!selection.success) {
                throw rpc_error(-32603, "getblocktemplate " + selection.error);
            }
            candidate = std::move(selection.candidate);

            if (candidate.SerializedSize() > (size_t)MAX_BLOCK_SIZE)
                throw std::runtime_error("getblocktemplate exceeded its canonical size budget");

            work_admission::Decision final_work_decision;
            try {
                final_work_decision = work_admission_fn_(work_admission::Path::GetBlockTemplate,
                                                         work_subject, work_decision.binding, true);
            } catch (...) {
                final_work_decision = {false, work_admission::Refusal::Unwired, std::nullopt};
            }
            if (!final_work_decision.allowed || !final_work_decision.binding) {
                throw rpc_error(-32010,
                                std::string("getblocktemplate closed before publication: ") +
                                    work_admission::RefusalName(final_work_decision.refusal));
            }
            const uint32_t bits = candidate.header.bits;
            CanonicalPowTarget canonical_target;
            if (!DecodeCanonicalVeldTarget(bits, canonical_target))
                throw rpc_error(-32603, "getblocktemplate internal target is not canonical");
            std::ostringstream target_stream;
            for (const uint8_t byte : canonical_target.bytes)
                target_stream << std::hex << std::setw(2) << std::setfill('0')
                              << static_cast<unsigned>(byte);
            const std::string target_hex = target_stream.str();

            auto block_bytes = candidate.Serialize();
            std::string block_hex;
            for (auto b : block_bytes) {
                char buf[3];
                snprintf(buf, sizeof(buf), "%02x", b);
                block_hex += buf;
            }

            BlockTemplateAuthorizationResult template_authorization;
            try {
                template_authorization = issue_block_template_authorization_fn_(
                    work_subject, candidate.header.GetTemplateWorkIdentity());
            } catch (...) {
                template_authorization.decision = {false, work_admission::Refusal::Unwired,
                                                   std::nullopt};
            }
            if (!template_authorization.decision.allowed ||
                !template_authorization.decision.binding || template_authorization.token.empty() ||
                template_authorization.ttl_ms == 0) {
                throw rpc_error(-32010, std::string("getblocktemplate authorization refused: ") +
                                            work_admission::RefusalName(
                                                template_authorization.decision.refusal));
            }
            const auto& published_work_binding = *template_authorization.decision.binding;
            if (published_work_binding.subject.target_hash !=
                    candidate.header.GetTemplateWorkIdentity() ||
                published_work_binding.subject.height != work_subject.height ||
                published_work_binding.subject.parent_height != work_subject.parent_height ||
                published_work_binding.subject.parent_hash != work_subject.parent_hash) {
                throw rpc_error(-32603, "getblocktemplate authorization binding mismatch");
            }

            std::ostringstream j;
            j << "{\"height\":" << candidate.height << ",\"prev_block_hash\":\""
              << HashToHex(candidate.header.prev_block_hash) << "\""
              << ",\"bits\":" << bits << ",\"target\":\"" << target_hex << "\""
              << ",\"timestamp\":" << candidate.header.timestamp << ",\"block_hex\":\"" << block_hex
              << "\""
              << ",\"work_binding\":\"" << work_admission::EncodeBinding(published_work_binding)
              << "\""
              << ",\"work_token\":\"" << template_authorization.token << "\""
              << ",\"work_ttl_ms\":" << template_authorization.ttl_ms
              << ",\"coinbase_value\":" << candidate.transactions[0].TotalOutput()
              << ",\"tx_count\":" << candidate.transactions.size()
              << ",\"is_vault_block\":" << (is_vault_block ? "true" : "false") << "}";
            return j.str();
        });

        methods_["submitblock"] = RpcMethod([this](const P& params) -> std::string {
            if (params.size() != 3)
                throw std::invalid_argument(
                    "Usage: submitblock <block_hex> <work_binding> <work_token>");
            const auto prior = work_admission::DecodeBinding(params[1]);
            if (!prior)
                throw rpc_error(-32602, "invalid work binding");

            std::string hex = params[0];
            if (hex.size() % 2 != 0)
                throw rpc_error(-32602, "invalid hex in raw: odd length");
            if (hex.size() > 2u * (size_t)MAX_BLOCK_SIZE)
                throw rpc_error(-32602, "invalid hex in raw: exceeds 2*MAX_BLOCK_SIZE");
            for (char c : hex) {
                if (!std::isxdigit((unsigned char)c))
                    throw rpc_error(-32602, "invalid hex in raw");
            }
            std::vector<uint8_t> data;
            data.resize(hex.size() / 2);
            for (size_t i = 0; i < data.size(); ++i) {
                uint32_t byte = 0;
                auto fc = std::from_chars(hex.data() + 2 * i, hex.data() + 2 * i + 2, byte, 16);
                if (fc.ec != std::errc{} || fc.ptr != hex.data() + 2 * i + 2)
                    throw rpc_error(-32602, "invalid hex in raw");
                data[i] = (uint8_t)byte;
            }

            Block block;
            const size_t consumed = Block::Deserialize(data, 0, block);
            if (consumed == 0 || consumed != data.size() || block.Serialize() != data)
                throw std::runtime_error("Failed to deserialize block");

            if (!work_admission_fn_)
                throw rpc_error(-32010, "submitblock refused: work admission is not wired");
            if (!consume_block_template_authorization_fn_)
                throw rpc_error(-32010, "submitblock refused: template authorization is not wired");
            if (!block_broadcast_)
                throw rpc_error(-32010, "submitblock refused: block publication sink is unwired");

            std::shared_ptr<work_admission::BlockTemplateAuthorizationClaim> template_claim;
            {
                // Reserve the opaque bearer while the exact canonical parent
                // and coordinator epoch are protected. Release this sequencer
                // before AddBlockDirect, which acquires it independently after
                // preparing the immutable local-work ticket.
                auto transition_guard = chain_.AcquireConsensusTransitionGuard();
                if (chain_.IsEmpty())
                    throw rpc_error(-32010, "submitblock refused: tip_unknown");
                const Block canonical_tip = chain_.TipCopy();
                block.height = canonical_tip.height + 1;

                if (block.header.prev_block_hash != canonical_tip.GetHash())
                    throw std::runtime_error("Block does not extend current tip (stale template)");

                if (work_admission::EncodeBinding(*prior) != params[1] ||
                    HashIsZero(prior->subject.target_hash) ||
                    prior->subject.target_hash != block.header.GetTemplateWorkIdentity())
                    throw rpc_error(-32010, "submitblock refused: template work identity mismatch");

                work_admission::Subject work_subject;
                work_subject.purpose = work_admission::Purpose::BlockProduction;
                work_subject.height = block.height;
                work_subject.parent_height = canonical_tip.height;
                work_subject.parent_hash = canonical_tip.GetHash();
                auto normalized_prior = *prior;
                normalized_prior.subject.target_hash = ZeroHash();
                work_admission::Decision work_decision;
                try {
                    work_decision = work_admission_fn_(work_admission::Path::SubmitBlock,
                                                       work_subject, normalized_prior, true);
                } catch (...) {
                    work_decision = {false, work_admission::Refusal::Unwired, std::nullopt};
                }
                if (!work_decision.allowed) {
                    throw rpc_error(-32010, std::string("submitblock refused: ") +
                                                work_admission::RefusalName(work_decision.refusal));
                }
                try {
                    template_claim = consume_block_template_authorization_fn_(params[2], *prior);
                } catch (...) {
                    template_claim.reset();
                }
                if (!template_claim)
                    throw rpc_error(-32010, "submitblock refused: template authorization invalid");
            }

            auto pow_context = mining::PowAdmissionContext::RpcWork(params[1], params[2],
                                                                    std::move(template_claim));
            const auto admission = chain_.AddBlockDirect(block, false, false, false, pow_context);
            if (admission.IsDeferred())
                throw rpc_error(-32010, "submitblock deferred: retryable local-work-unavailable");
            if (!admission.IsAccepted())
                throw std::runtime_error("Block rejected by chain validation");

            std::string hash_hex = HashToHex(block.GetHash());

            // Re-enter the same transition sequencer for response-visible
            // post-commit effects. A peer/state transition that won after the
            // commit cancels the handoff; it never turns into a cached work
            // artifact for later publication.
            auto post_commit = chain_.AcquireConsensusTransitionGuard();
            if (!pow_context.local_work_handoff->IsLive())
                throw rpc_error(-32010, "submitblock committed but work publication is closed");
            mempool_.RemoveStale(chain_);
            block_broadcast_(block);

            return "{\"accepted\":true,\"hash\":\"" + hash_hex +
                   "\",\"height\":" + std::to_string(block.height) + "}";
        });
#endif

        methods_["getchaintips"] = RpcMethod([this](const P&) -> std::string {
            auto tips = chain_.GetChainTips();
            std::vector<std::string> rows;
            rows.reserve(tips.size());
            for (const auto& t : tips) {
                rows.push_back(JB::Object({
                    {"height", JB::Number(t.height)},
                    {"hash", JB::String(HashToHex(t.hash))},
                    {"branchlen", JB::Number(t.branchlen)},
                    // Chainwork is 320-bit; emit fixed-width big-endian hex as
                    // a string rather than an unsafe/lossy JSON number.
                    {"cumulative_work", JB::String(t.cumulative_work)},
                    {"status", JB::String(t.status)},
                }));
            }
            return JB::Array(rows);
        });

#ifndef VELD_FLEET_NO_MINE
        methods_["clearmininghalt"] = RpcMethod([this](const P&) -> std::string {
            if (!clear_mining_halt_fn_) {
                throw rpc_error(-32601, "clearmininghalt not wired (node startup race?)");
            }
            std::string result = clear_mining_halt_fn_();
            return JB::Object({
                {"ok", JB::Bool(result == "ok")},
                {"result", JB::String(result)},
            });
        });
#endif

        methods_["invalidateblock"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("invalidateblock requires <hash>");
            if (params[0].size() != 64)
                throw std::invalid_argument("hash must be 64-char hex");
            if (!invalidate_block_fn_) {
                throw rpc_error(-32601, "invalidateblock not wired");
            }
            Hash256 h = HexToHash(params[0]);
            std::string result = invalidate_block_fn_(h);
            return JB::Object({
                {"ok", JB::Bool(result == "ok")},
                {"hash", JB::String(params[0])},
                {"result", JB::String(result)},
                {"note",
                 JB::String(
                     "v1: P2P-layer rejection only; see runbook for canonical-chain invalidation")},
            });
        });

        methods_["reconsiderblock"] = RpcMethod([this](const P& params) -> std::string {
            if (params.empty())
                throw std::invalid_argument("reconsiderblock requires <hash>");
            if (params[0].size() != 64)
                throw std::invalid_argument("hash must be 64-char hex");
            if (!reconsider_block_fn_) {
                throw rpc_error(-32601, "reconsiderblock not wired");
            }
            Hash256 h = HexToHash(params[0]);
            std::string result = reconsider_block_fn_(h);
            return JB::Object({
                {"ok", JB::Bool(result == "ok")},
                {"hash", JB::String(params[0])},
                {"result", JB::String(result)},
            });
        });

        methods_["clearrejectcache"] = RpcMethod([this](const P&) -> std::string {
            if (!clear_reject_cache_fn_)
                throw rpc_error(-32601, "clearrejectcache not wired");
            size_t n = clear_reject_cache_fn_();
            return JB::Object({
                {"ok", JB::Bool(true)},
                {"cleared", JB::Number((uint64_t)n)},
            });
        });
        methods_["clearorphanpool"] = RpcMethod([this](const P&) -> std::string {
            if (!clear_orphan_pool_fn_)
                throw rpc_error(-32601, "clearorphanpool not wired");
            size_t n = clear_orphan_pool_fn_();
            return JB::Object({
                {"ok", JB::Bool(true)},
                {"cleared", JB::Number((uint64_t)n)},
            });
        });
        methods_["clearbadalttips"] = RpcMethod([this](const P&) -> std::string {
            if (!clear_bad_alt_tips_fn_)
                throw rpc_error(-32601, "clearbadalttips not wired");
            size_t n = clear_bad_alt_tips_fn_();
            return JB::Object({
                {"ok", JB::Bool(true)},
                {"cleared", JB::Number((uint64_t)n)},
            });
        });

        methods_["getreorghealth"] = RpcMethod([this](const P&) -> std::string {
            uint64_t div = chain_.GetReorgHarnessDivergenceCount();
            uint64_t obs = chain_.GetReorgHarnessObservedCount();
            uint64_t bad_alt_count = chain_.BadAltTipCount();
            constexpr uint64_t kConfidenceThreshold = 20;
            return JB::Object({
                {"reorg_harness_divergence_count", JB::Number(div)},
                {"reorg_harness_observed_count", JB::Number(obs)},
                {"bad_alt_tips_count", JB::Number(bad_alt_count)},
                {"step4_safe_to_ship", JB::Bool(div == 0 && obs >= kConfidenceThreshold)},
            });
        });

        methods_["help"] = RpcMethod([this](const P&) -> std::string {
            auto names = GetMethods();
            std::vector<std::string> quoted;
            for (const auto& n : names)
                quoted.push_back(JsonBuilder::String(n));
            return JsonBuilder::Array(quoted);
        });
    }
};

} // namespace veld
