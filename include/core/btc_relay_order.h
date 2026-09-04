#pragma once

// Block templates are fee ordered, but Bitcoin header-relay transactions can
// depend on headers supplied by another transaction in the same candidate.
// Preserve fee order where possible while placing an in-candidate parent
// provider before each dependent relay. Consensus still validates the exact
// transaction order in the finished block; this helper only builds an order
// that can pass that existing validation.

#include "btc_relay_op.h"
#include "marker_composition.h"

#include <functional>
#include <map>
#include <queue>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace veld {
namespace btcspv {

struct BtcRelayDependencies {
    std::set<H256> provides;
    std::set<H256> required_parents;
    bool has_relay = false;
};

inline int BtcRelayHexNibble(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

inline bool DecodeBtcRelayMarker(const std::string& marker, std::vector<uint8_t>* raw) {
    static constexpr char PREFIX[] = "VELD_BHDR|";
    static constexpr size_t PREFIX_LEN = sizeof(PREFIX) - 1;
    if (!raw || marker.rfind(PREFIX, 0) != 0)
        return false;
    const size_t hex_len = marker.size() - PREFIX_LEN;
    if ((hex_len & 1u) != 0)
        return false;
    raw->clear();
    raw->reserve(hex_len / 2);
    for (size_t i = PREFIX_LEN; i < marker.size(); i += 2) {
        const int hi = BtcRelayHexNibble(marker[i]);
        const int lo = BtcRelayHexNibble(marker[i + 1]);
        if (hi < 0 || lo < 0) {
            raw->clear();
            return false;
        }
        raw->push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return IsBtcHeaderOp(raw->data(), raw->size());
}

inline BtcRelayDependencies BtcRelayDependenciesForTransaction(const Transaction& tx) {
    BtcRelayDependencies deps;
    std::set<H256> earlier_in_transaction;
    for (const auto& out : tx.outputs) {
        const std::string marker = MarkerOpReturnPayload(out.script_pubkey);
        if (marker.rfind("VELD_BHDR|", 0) != 0)
            continue;
        std::vector<uint8_t> op;
        if (!DecodeBtcRelayMarker(marker, &op))
            continue;
        deps.has_relay = true;
        const size_t count = op[4];
        for (size_t i = 0; i < count; ++i) {
            const uint8_t* header = op.data() + 5 + i * 80;
            const H256 parent = rd_hash(header + 4);
            if (earlier_in_transaction.count(parent) == 0)
                deps.required_parents.insert(parent);
            const H256 hash = BtcHeaderHash(header);
            deps.provides.insert(hash);
            earlier_in_transaction.insert(hash);
        }
    }
    return deps;
}

// Returns false only for an in-candidate dependency cycle. Unknown parents are
// deliberately left alone because they may already exist in consensus state.
// On failure the input order is unchanged.
inline bool
StableDependencyOrderBtcHeaderTransactions(std::vector<std::pair<Transaction, uint64_t>>& txs) {
    const size_t n = txs.size();
    if (n < 2)
        return true;

    std::vector<BtcRelayDependencies> deps;
    deps.reserve(n);
    std::map<H256, std::vector<size_t>> providers;
    for (size_t i = 0; i < n; ++i) {
        deps.push_back(BtcRelayDependenciesForTransaction(txs[i].first));
        for (const H256& hash : deps.back().provides)
            providers[hash].push_back(i);
    }

    std::vector<std::set<size_t>> outgoing(n);
    std::vector<size_t> indegree(n, 0);
    for (size_t consumer = 0; consumer < n; ++consumer) {
        for (const H256& required : deps[consumer].required_parents) {
            const auto found = providers.find(required);
            if (found == providers.end())
                continue;
            size_t provider = n;
            for (const size_t candidate : found->second) {
                if (candidate != consumer) {
                    provider = candidate;
                    break;
                }
            }
            if (provider == n)
                continue;
            if (outgoing[provider].insert(consumer).second)
                ++indegree[consumer];
        }
    }

    std::priority_queue<size_t, std::vector<size_t>, std::greater<size_t>> ready;
    for (size_t i = 0; i < n; ++i)
        if (indegree[i] == 0)
            ready.push(i);

    std::vector<size_t> order;
    order.reserve(n);
    while (!ready.empty()) {
        const size_t current = ready.top();
        ready.pop();
        order.push_back(current);
        for (const size_t child : outgoing[current]) {
            if (--indegree[child] == 0)
                ready.push(child);
        }
    }
    if (order.size() != n)
        return false;

    bool changed = false;
    for (size_t i = 0; i < n; ++i)
        changed = changed || order[i] != i;
    if (!changed)
        return true;

    std::vector<std::pair<Transaction, uint64_t>> reordered;
    reordered.reserve(n);
    for (const size_t index : order)
        reordered.push_back(txs[index]);
    txs.swap(reordered);
    return true;
}

} // namespace btcspv
} // namespace veld
