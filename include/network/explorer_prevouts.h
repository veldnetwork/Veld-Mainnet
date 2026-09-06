#pragma once

#include "../core/script.h"
#include <map>
#include <optional>

namespace veld::explorer {

// Keep only the values and addresses needed by this page. No transaction or
// historical block owns storage through this projection.
class PrevoutProjection {
public:
    struct Value { uint64_t units; std::string address; };
    static constexpr size_t MAX_OUTPOINTS = 8192;

    bool AddInputs(const Transaction& tx) {
        if (tx.IsCoinbase()) return true;
        for (const auto& in : tx.inputs) {
            const Key key{in.prev_tx_hash, in.prev_out_index};
            if (values_.find(key) != values_.end()) continue;
            if (values_.size() == MAX_OUTPOINTS) return false;
            values_.emplace(key, std::nullopt);
            ++remaining_;
        }
        return true;
    }

    void Observe(const Transaction& tx) {
        const auto hash = tx.GetTxID();
        auto it = values_.lower_bound(Key{hash, 0});
        for (; it != values_.end() && it->first.first == hash; ++it) {
            const auto index = it->first.second;
            if (it->second || index >= tx.outputs.size()) continue;
            const auto& out = tx.outputs[index];
            it->second = Value{out.value, ScriptToAddress(out.script_pubkey)};
            --remaining_;
        }
    }

    const Value* Find(const TxInput& in) const {
        const auto it = values_.find(Key{in.prev_tx_hash, in.prev_out_index});
        return it == values_.end() || !it->second ? nullptr : &*it->second;
    }
    size_t Remaining() const { return remaining_; }

private:
    using Key = std::pair<Hash256, uint32_t>;
    std::map<Key, std::optional<Value>> values_;
    size_t remaining_ = 0;
};
} // namespace veld::explorer
