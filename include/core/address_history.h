#pragma once

#include "block.h"
#include "canonical_numeric.h"
#include "hash.h"
#include "leveldb.h"
#include "../wallet/wallet.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <limits>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace veld::address_history {

// Public history is served only from this derived LevelDB index. A request
// performs one ordered seek and reads at most MAX_PAGE_SIZE + 1 small rows; it
// never opens a block body or walks a height range.
inline constexpr size_t MAX_PAGE_SIZE = 50;
inline constexpr size_t DEFAULT_PAGE_SIZE = 25;
inline constexpr size_t MAX_CURSOR_SIZE = 192;
inline constexpr const char* ROW_PREFIX = "ah1:r:";
inline constexpr const char* OUTPOINT_PREFIX = "ah1:o:";
inline constexpr const char* BLOCK_PREFIX = "ah1:b:";
inline constexpr const char* TIP_HEIGHT_KEY = "ah1:tip_height";
inline constexpr const char* TIP_HASH_KEY = "ah1:tip_hash";

struct Entry {
    std::string txid;
    uint64_t block_height{0};
    int64_t net_units{0};
    uint64_t fee_units{0};
    std::string type;
};

struct Page {
    std::vector<Entry> entries;
    std::string next_cursor;
    bool has_more{false};
};

struct OutputRecord {
    std::vector<uint8_t> script;
    uint64_t value{0};
};

inline bool IsLowerHex(std::string_view text) {
    for (const unsigned char c : text) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

inline bool IsCanonicalAddressScript(const std::vector<uint8_t>& script) {
    if (script.empty()) return false;
    const std::string address = ScriptToAddress(script);
    return !address.empty() && AddressToScript(address) == script;
}

inline std::string FixedDecimal(uint64_t value, size_t width) {
    std::ostringstream out;
    out << std::setw(static_cast<int>(width)) << std::setfill('0') << value;
    return out.str();
}

inline bool ParseFixedDecimal(std::string_view text, size_t width,
                              uint64_t& out) {
    if (text.size() != width || text.empty()) return false;
    uint64_t value = 0;
    for (const unsigned char c : text) {
        if (c < '0' || c > '9') return false;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (value > (UINT64_MAX - digit) / 10) return false;
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

inline std::string OutpointKey(const Hash256& txid, uint32_t index) {
    return std::string(OUTPOINT_PREFIX) + HashToHex(txid) + ':' +
           std::to_string(index);
}

inline std::string RowPrefixForScript(
        const std::vector<uint8_t>& script) {
    return std::string(ROW_PREFIX) + BytesToHex(script) + ':';
}

inline std::string RowKey(const std::vector<uint8_t>& script,
                          uint64_t height, uint32_t tx_ordinal,
                          const std::string& txid) {
    return RowPrefixForScript(script) +
           FixedDecimal(UINT64_MAX - height, 20) + ':' +
           FixedDecimal(tx_ordinal, 10) + ':' + txid;
}

inline std::string BlockReversePrefix(const Hash256& block_hash) {
    return std::string(BLOCK_PREFIX) + HashToHex(block_hash) + ':';
}

inline std::string BlockReverseKey(const Hash256& block_hash,
                                   uint64_t ordinal) {
    return BlockReversePrefix(block_hash) + FixedDecimal(ordinal, 20);
}

inline std::string EncodeOutput(const OutputRecord& output) {
    return BytesToHex(output.script) + '|' + std::to_string(output.value);
}

inline std::optional<OutputRecord> DecodeOutput(std::string_view text) {
    const size_t split = text.find('|');
    if (split == std::string_view::npos || split == 0 ||
        split + 1 >= text.size() || text.find('|', split + 1) !=
                                      std::string_view::npos) {
        return std::nullopt;
    }
    const std::string_view script_hex = text.substr(0, split);
    if ((script_hex.size() & 1U) != 0 || !IsLowerHex(script_hex) ||
        script_hex.size() > 2 * MAX_SPENDABLE_SCRIPT_PUBKEY_BYTES)
        return std::nullopt;
    uint64_t value = 0;
    if (!ParseCanonicalUint64Text(text.substr(split + 1), value) ||
        value > MAX_SUPPLY_UNITS)
        return std::nullopt;
    OutputRecord out;
    out.script.reserve(script_hex.size() / 2);
    auto nibble = [](char c) -> uint8_t {
        return static_cast<uint8_t>(c <= '9' ? c - '0' : c - 'a' + 10);
    };
    for (size_t i = 0; i < script_hex.size(); i += 2) {
        out.script.push_back(static_cast<uint8_t>(
            (nibble(script_hex[i]) << 4) | nibble(script_hex[i + 1])));
    }
    out.value = value;
    return out;
}

inline std::string EncodeEntryValue(int64_t net_units, uint64_t fee_units,
                                    const std::string& type) {
    return std::to_string(net_units) + '|' + std::to_string(fee_units) + '|' +
           type;
}

inline bool ParseCanonicalInt64(std::string_view text, int64_t& out) {
    if (text.empty()) return false;
    bool negative = text.front() == '-';
    if (negative) text.remove_prefix(1);
    if (text.empty() || (text.size() > 1 && text.front() == '0')) return false;
    uint64_t magnitude = 0;
    if (!ParseCanonicalUint64Text(text, magnitude)) return false;
    if (negative && magnitude == 0) return false;
    const uint64_t negative_limit =
        static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1;
    if ((!negative && magnitude >
                          static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) ||
        (negative && magnitude > negative_limit))
        return false;
    if (!negative) out = static_cast<int64_t>(magnitude);
    else if (magnitude == negative_limit)
        out = std::numeric_limits<int64_t>::min();
    else
        out = -static_cast<int64_t>(magnitude);
    return true;
}

inline std::optional<Entry> DecodeEntry(const std::string& key,
                                        std::string_view value,
                                        std::string_view expected_prefix) {
    if (key.rfind(expected_prefix, 0) != 0) return std::nullopt;
    const std::string_view suffix(key.data() + expected_prefix.size(),
                                  key.size() - expected_prefix.size());
    if (suffix.size() != 20 + 1 + 10 + 1 + 64 || suffix[20] != ':' ||
        suffix[31] != ':')
        return std::nullopt;
    uint64_t reverse_height = 0, ordinal = 0;
    if (!ParseFixedDecimal(suffix.substr(0, 20), 20, reverse_height) ||
        !ParseFixedDecimal(suffix.substr(21, 10), 10, ordinal) ||
        ordinal > UINT32_MAX || !db::IsCanonicalHash256Text(suffix.substr(32)))
        return std::nullopt;

    const size_t first = value.find('|');
    const size_t second = first == std::string_view::npos
        ? std::string_view::npos : value.find('|', first + 1);
    if (first == std::string_view::npos || second == std::string_view::npos ||
        first == 0 || second == first + 1 || second + 1 >= value.size() ||
        value.find('|', second + 1) != std::string_view::npos)
        return std::nullopt;
    int64_t net = 0;
    uint64_t fee = 0;
    if (!ParseCanonicalInt64(value.substr(0, first), net) ||
        !ParseCanonicalUint64Text(
            value.substr(first + 1, second - first - 1), fee) ||
        fee > MAX_SUPPLY_UNITS)
        return std::nullopt;
    const std::string type(value.substr(second + 1));
    if (type.empty() || type.size() > 32) return std::nullopt;
    for (const unsigned char c : type)
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '_'))
            return std::nullopt;
    Entry out;
    out.txid = std::string(suffix.substr(32));
    out.block_height = UINT64_MAX - reverse_height;
    out.net_units = net;
    out.fee_units = fee;
    out.type = type;
    return out;
}

inline bool DeletePrefixBatched(db::KVStore& store,
                                const std::string& prefix) {
    std::string cursor;
    for (;;) {
        std::vector<std::string> keys;
        keys.reserve(4096);
        store.IterateFrom(prefix, cursor,
            [&](const std::string& key, const std::string&) {
                keys.push_back(key);
                return keys.size() < 4096;
            });
        if (keys.empty()) return true;
        cursor = keys.back();
        db::WriteBatch batch;
        for (const auto& key : keys) batch.Delete(key);
        if (!store.Write(batch)) return false;
    }
}

using OutputLookup =
    std::function<std::optional<OutputRecord>(const Hash256&, uint32_t)>;

inline std::string OpReturnPayload(const Transaction& tx) {
    for (const auto& output : tx.outputs) {
        const auto& script = output.script_pubkey;
        if (script.size() < 2 || script[0] != 0x6a) continue;
        size_t pos = 1;
        size_t length = 0;
        if (script[pos] <= 75) {
            length = script[pos++];
        } else if (script[pos] == 0x4c && pos + 1 < script.size()) {
            ++pos;
            length = script[pos++];
        } else if (script[pos] == 0x4d && pos + 2 < script.size()) {
            ++pos;
            length = static_cast<size_t>(script[pos]) |
                     (static_cast<size_t>(script[pos + 1]) << 8);
            pos += 2;
        } else {
            continue;
        }
        if (length > 4096 || pos > script.size() ||
            length > script.size() - pos)
            continue;
        return std::string(script.begin() + static_cast<std::ptrdiff_t>(pos),
                           script.begin() +
                               static_cast<std::ptrdiff_t>(pos + length));
    }
    return {};
}

inline std::string EntryType(const Transaction& tx, uint64_t input,
                             int64_t net, std::string_view marker) {
    if (tx.IsCoinbase()) return "coinbase";
    if (marker.find("VELD_DIST|STAKING") != std::string_view::npos)
        return "staking_distribution";
    if (marker.find("VELD_DIST|ENDORSEMENT") != std::string_view::npos)
        return "endorsement_reward";
    if (marker.find("VELD_DIST|COMINE") != std::string_view::npos)
        return "comine_payout";
    if (marker.find("VELD_VALIDATOR|ENDORSE") != std::string_view::npos)
        return "endorsement";
    if (marker.find("VELD_VALIDATOR|REGISTER") != std::string_view::npos)
        return "validator_register";
    if (marker.find("VELD_VALIDATOR|DEREGISTER") != std::string_view::npos)
        return "validator_deregister";
    if (marker.find("VELD_VALIDATOR|SLASH|") != std::string_view::npos)
        return "slash_evidence";
    if (marker.rfind("VELD_STAKE|LOCK", 0) == 0) return "stake_lock";
    if (marker.rfind("VELD_STAKE|UNLOCK", 0) == 0) return "stake_unlock";
    if (marker.rfind("VELD_GOV|", 0) == 0) return "gov_other";
    if (marker.rfind("VELD_TOKEN|M", 0) == 0) return "btcveld_mint";
    if (marker.rfind("VELD_TOKEN|R", 0) == 0) return "btcveld_redeem";
    if (marker.rfind("VELD_TOKEN|T", 0) == 0) return "btcveld_transfer";
    if (marker.rfind("VELD_TOKEN|", 0) == 0) return "btcveld_op";
    if (marker.rfind("VELD_MSPV|", 0) == 0) return "btcveld_spv_mint";
    if (marker.rfind("VELD_AMM|", 0) == 0) return "amm_op";
    if (marker.rfind("VELD_ANCHOR|", 0) == 0) return "anchor_post";
    if (marker.rfind("VELD_BHDR|", 0) == 0) return "btc_header_relay";
    if (marker.rfind("VELD_FRAUD|", 0) == 0) return "fraud_proof";
    if (input > 0 && net < 0) return "sent";
    if (input > 0 && net == 0) return "self";
    return "received";
}

inline bool AppendBlock(const Block& block,
                        const OutputLookup& previous_output_lookup,
                        db::WriteBatch& batch) {
    struct Effect { uint64_t input{0}; uint64_t output{0}; };
    std::map<std::string, OutputRecord> local_outputs;
    uint64_t reverse_ordinal = 0;

    for (size_t tx_pos = 0; tx_pos < block.transactions.size(); ++tx_pos) {
        if (tx_pos > UINT32_MAX) return false;
        const Transaction& tx = block.transactions[tx_pos];
        const Hash256 txid_hash = tx.GetTxID();
        const std::string txid = HashToHex(txid_hash);
        std::map<std::string, Effect> effects;
        uint64_t total_input = 0;
        uint64_t total_output = 0;

        if (!tx.IsCoinbase()) {
            for (const auto& input : tx.inputs) {
                const std::string outpoint = OutpointKey(
                    input.prev_tx_hash, input.prev_out_index);
                std::optional<OutputRecord> parent;
                auto local = local_outputs.find(outpoint);
                if (local != local_outputs.end()) parent = local->second;
                else parent = previous_output_lookup(
                    input.prev_tx_hash, input.prev_out_index);
                if (!parent || parent->value > MAX_SUPPLY_UNITS ||
                    total_input > MAX_SUPPLY_UNITS - parent->value)
                    return false;
                total_input += parent->value;
                if (IsCanonicalAddressScript(parent->script)) {
                    auto& effect = effects[BytesToHex(parent->script)];
                    if (effect.input > MAX_SUPPLY_UNITS - parent->value)
                        return false;
                    effect.input += parent->value;
                }
            }
        }

        for (size_t output_index = 0; output_index < tx.outputs.size();
             ++output_index) {
            if (output_index > UINT32_MAX) return false;
            const TxOutput& output = tx.outputs[output_index];
            if (total_output > MAX_SUPPLY_UNITS - output.value) return false;
            total_output += output.value;
            if (IsProvablyUnspendableOutput(output)) continue;
            OutputRecord record{output.script_pubkey, output.value};
            const std::string outpoint = OutpointKey(
                txid_hash, static_cast<uint32_t>(output_index));
            local_outputs[outpoint] = record;
            batch.Put(outpoint, EncodeOutput(record));
            batch.Put(BlockReverseKey(block.GetHash(), reverse_ordinal++),
                      outpoint);
            if (IsCanonicalAddressScript(output.script_pubkey)) {
                auto& effect = effects[BytesToHex(output.script_pubkey)];
                if (effect.output > MAX_SUPPLY_UNITS - output.value)
                    return false;
                effect.output += output.value;
            }
        }
        if (!tx.IsCoinbase() && total_output > total_input) return false;
        const uint64_t fee = tx.IsCoinbase() ? 0 : total_input - total_output;
        const std::string marker = OpReturnPayload(tx);

        for (const auto& [script_hex, effect] : effects) {
            if (effect.input > static_cast<uint64_t>(INT64_MAX) ||
                effect.output > static_cast<uint64_t>(INT64_MAX))
                return false;
            int64_t net = static_cast<int64_t>(effect.output) -
                          static_cast<int64_t>(effect.input);
            // Preserve the established UI contract: net is the transferred
            // value, while the transaction fee is reported separately.
            if (effect.input > 0) {
                if (fee > static_cast<uint64_t>(INT64_MAX) ||
                    net > INT64_MAX - static_cast<int64_t>(fee))
                    return false;
                net += static_cast<int64_t>(fee);
            }
            std::vector<uint8_t> script;
            script.reserve(script_hex.size() / 2);
            auto nibble = [](char c) -> uint8_t {
                return static_cast<uint8_t>(c <= '9' ? c - '0' :
                                            c - 'a' + 10);
            };
            for (size_t i = 0; i < script_hex.size(); i += 2)
                script.push_back(static_cast<uint8_t>(
                    (nibble(script_hex[i]) << 4) | nibble(script_hex[i + 1])));
            const std::string type = EntryType(
                tx, effect.input, net, marker);
            const std::string row_key = RowKey(
                script, block.height, static_cast<uint32_t>(tx_pos), txid);
            batch.Put(row_key, EncodeEntryValue(
                net, effect.input > 0 ? fee : 0, type));
            batch.Put(BlockReverseKey(block.GetHash(), reverse_ordinal++),
                      row_key);
        }
    }
    batch.Put(TIP_HEIGHT_KEY, std::to_string(block.height));
    batch.Put(TIP_HASH_KEY, HashToHex(block.GetHash()));
    return true;
}

inline bool MarkersMatch(db::KVStore& store, uint64_t height,
                         const Hash256& hash) {
    const auto stored_height = store.Get(TIP_HEIGHT_KEY);
    const auto stored_hash = store.Get(TIP_HASH_KEY);
    return stored_height && stored_hash &&
           *stored_height == std::to_string(height) &&
           *stored_hash == HashToHex(hash);
}

inline bool Rebuild(
        db::KVStore& store,
        const std::optional<std::pair<uint64_t, Hash256>>& tip,
        const std::function<Block(uint64_t)>& block_loader,
        const std::function<bool(uint64_t, const Hash256&)>& tip_matches) {
    db::WriteBatch invalidate;
    invalidate.Delete(TIP_HEIGHT_KEY);
    invalidate.Delete(TIP_HASH_KEY);
    if (!store.Write(invalidate) ||
        !DeletePrefixBatched(store, ROW_PREFIX) ||
        !DeletePrefixBatched(store, OUTPOINT_PREFIX) ||
        !DeletePrefixBatched(store, BLOCK_PREFIX))
        return false;
    if (!tip) return true;

    Hash256 expected_parent{};
    for (uint64_t height = 0;; ++height) {
        Block block = block_loader(height);
        if (block.height != height || block.GetHash() == Hash256{} ||
            (height > 0 && block.header.prev_block_hash != expected_parent))
            return false;
        db::WriteBatch batch;
        const OutputLookup lookup = [&store](const Hash256& txid,
                                              uint32_t index)
                -> std::optional<OutputRecord> {
            const auto raw = store.Get(OutpointKey(txid, index));
            return raw ? DecodeOutput(*raw) : std::nullopt;
        };
        if (!AppendBlock(block, lookup, batch) || !store.Write(batch))
            return false;
        expected_parent = block.GetHash();
        if (height == tip->first) break;
        if (height == UINT64_MAX) return false;
    }
    return expected_parent == tip->second &&
           tip_matches(tip->first, tip->second) &&
           MarkersMatch(store, tip->first, tip->second);
}

inline bool Advance(db::KVStore& store, const Block& block) {
    if (block.height == 0) {
        if (store.Get(TIP_HEIGHT_KEY) || store.Get(TIP_HASH_KEY)) return false;
    } else {
        const auto height = store.Get(TIP_HEIGHT_KEY);
        const auto hash = store.Get(TIP_HASH_KEY);
        if (!height || !hash || *height != std::to_string(block.height - 1) ||
            *hash != HashToHex(block.header.prev_block_hash))
            return false;
    }
    db::WriteBatch batch;
    const OutputLookup lookup = [&store](const Hash256& txid, uint32_t index)
            -> std::optional<OutputRecord> {
        const auto raw = store.Get(OutpointKey(txid, index));
        return raw ? DecodeOutput(*raw) : std::nullopt;
    };
    return AppendBlock(block, lookup, batch) && store.Write(batch);
}

inline bool Rollback(db::KVStore& store, const Block& popped) {
    if (!MarkersMatch(store, popped.height, popped.GetHash())) return false;
    db::WriteBatch batch;
    const std::string reverse_prefix = BlockReversePrefix(popped.GetHash());
    bool malformed = false;
    store.Iterate(reverse_prefix,
        [&](const std::string& reverse_key, const std::string& target_key) {
            if (target_key.rfind(ROW_PREFIX, 0) != 0 &&
                target_key.rfind(OUTPOINT_PREFIX, 0) != 0) {
                malformed = true;
                return false;
            }
            batch.Delete(target_key);
            batch.Delete(reverse_key);
            return true;
        });
    if (malformed) return false;
    if (popped.height == 0) {
        batch.Delete(TIP_HEIGHT_KEY);
        batch.Delete(TIP_HASH_KEY);
    } else {
        batch.Put(TIP_HEIGHT_KEY, std::to_string(popped.height - 1));
        batch.Put(TIP_HASH_KEY, HashToHex(popped.header.prev_block_hash));
    }
    return store.Write(batch);
}

inline std::optional<Page> ReadPage(db::KVStore& store,
                                    const std::vector<uint8_t>& script,
                                    size_t limit,
                                    const std::string& cursor) {
    if (!IsCanonicalAddressScript(script) || limit == 0 ||
        limit > MAX_PAGE_SIZE || cursor.size() > MAX_CURSOR_SIZE)
        return std::nullopt;
    const std::string prefix = RowPrefixForScript(script);
    if (!cursor.empty()) {
        if (cursor.rfind(prefix, 0) != 0) return std::nullopt;
    }
    Page page;
    bool malformed = false;
    std::string last_key;
    store.IterateFrom(prefix, cursor,
        [&](const std::string& key, const std::string& value) {
            const auto entry = DecodeEntry(key, value, prefix);
            if (!entry) {
                malformed = true;
                return false;
            }
            if (page.entries.size() == limit) {
                page.has_more = true;
                return false;
            }
            page.entries.push_back(*entry);
            last_key = key;
            return true;
        });
    if (malformed) return std::nullopt;
    if (page.has_more) page.next_cursor = last_key;
    return page;
}

}  // namespace veld::address_history
