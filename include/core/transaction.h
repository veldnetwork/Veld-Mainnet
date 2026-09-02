#pragma once

#include "hash.h"
#include "constants.h"
#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <unordered_set>
#include <cassert>
#include <atomic>

namespace veld {

// Fresh-genesis transaction-envelope bounds.  Stateful C1F1 carries a bounded
// Bitcoin inclusion proof and sparse-nullifier witness in one canonical
// OP_RETURN, so its 42,000-byte protocol payload must fit the generic
// transaction script envelope.  Spendable scripts and input scripts retain
// their tighter historical limits.
inline constexpr size_t MAX_TRANSACTION_SCRIPT_SIG_BYTES = 32'768;
inline constexpr size_t MAX_SPENDABLE_SCRIPT_PUBKEY_BYTES = 10'000;
inline constexpr size_t MAX_OP_RETURN_SCRIPT_PUBKEY_BYTES = 65'535;

struct TxInput {
    Hash256  prev_tx_hash;
    uint32_t prev_out_index;
    std::vector<uint8_t> script_sig;
    uint32_t sequence;

    TxInput() : prev_out_index(0), sequence(0xFFFFFFFF) {
        prev_tx_hash = ZeroHash();
    }

    static TxInput Coinbase(const std::string& message = "") {
        TxInput input;
        input.prev_tx_hash = ZeroHash();
        input.prev_out_index = 0xFFFFFFFF;
        input.script_sig = std::vector<uint8_t>(message.begin(), message.end());
        return input;
    }

    bool IsCoinbase() const {
        return prev_out_index == 0xFFFFFFFF && HashIsZero(prev_tx_hash);
    }

    std::vector<uint8_t> Serialize() const {
        std::vector<uint8_t> data;
        data.insert(data.end(), prev_tx_hash.begin(), prev_tx_hash.end());
        data.push_back(prev_out_index & 0xFF);
        data.push_back((prev_out_index >> 8) & 0xFF);
        data.push_back((prev_out_index >> 16) & 0xFF);
        data.push_back((prev_out_index >> 24) & 0xFF);
        uint64_t slen = script_sig.size();
        if (slen < 0xFD) {
            data.push_back((uint8_t)slen);
        } else if (slen <= 0xFFFF) {
            data.push_back(0xFD);
            data.push_back(slen & 0xFF);
            data.push_back((slen >> 8) & 0xFF);
        } else {
            data.push_back(0xFE);
            for (int i = 0; i < 4; ++i) data.push_back((slen >> (i*8)) & 0xFF);
        }
        data.insert(data.end(), script_sig.begin(), script_sig.end());
        data.push_back(sequence & 0xFF);
        data.push_back((sequence >> 8) & 0xFF);
        data.push_back((sequence >> 16) & 0xFF);
        data.push_back((sequence >> 24) & 0xFF);
        return data;
    }
};

struct TxOutput {
    uint64_t value;
    std::vector<uint8_t> script_pubkey;

    TxOutput() : value(0) {}
    TxOutput(uint64_t val, const std::vector<uint8_t>& script)
        : value(val), script_pubkey(script) {}

    std::vector<uint8_t> Serialize() const {
        std::vector<uint8_t> data;
        for (int i = 0; i < 8; ++i)
            data.push_back((value >> (i * 8)) & 0xFF);
        uint64_t slen = script_pubkey.size();
        if (slen < 0xFD) {
            data.push_back((uint8_t)slen);
        } else if (slen <= 0xFFFF) {
            data.push_back(0xFD);
            data.push_back(slen & 0xFF);
            data.push_back((slen >> 8) & 0xFF);
        } else {
            data.push_back(0xFE);
            for (int i = 0; i < 4; ++i) data.push_back((slen >> (i*8)) & 0xFF);
        }
        data.insert(data.end(), script_pubkey.begin(), script_pubkey.end());
        return data;
    }
};

// OP_RETURN outputs are consensus-provably unspendable.  They remain part of
// the transaction, txid, Merkle root, protocol-marker scans, and history, but
// must never occupy the spendable UTXO set.  Keeping this predicate next to
// TxOutput gives live commit, reorg rebuild, persistence callbacks, and tests
// one byte-identical definition.
inline bool IsProvablyUnspendableOutput(const TxOutput& out) {
    return !out.script_pubkey.empty() && out.script_pubkey[0] == 0x6A;
}

struct Transaction {
    uint32_t version;
    std::vector<TxInput>  inputs;
    std::vector<TxOutput> outputs;
    uint32_t locktime;

    Transaction() : version(1), locktime(0) {}

    static inline void put_varint(std::vector<uint8_t>& out, uint64_t v) {
        if (v < 0xFD) {
            out.push_back((uint8_t)v);
        } else if (v <= 0xFFFF) {
            out.push_back(0xFD);
            out.push_back((uint8_t)(v & 0xFF));
            out.push_back((uint8_t)((v >> 8) & 0xFF));
        } else if (v <= 0xFFFFFFFFULL) {
            out.push_back(0xFE);
            for (int i = 0; i < 4; ++i) out.push_back((uint8_t)((v >> (i*8)) & 0xFF));
        } else {
            out.push_back(0xFF);
            for (int i = 0; i < 8; ++i) out.push_back((uint8_t)((v >> (i*8)) & 0xFF));
        }
    }

    std::vector<uint8_t> Serialize() const {
        std::vector<uint8_t> data;

        data.push_back(version & 0xFF);
        data.push_back((version >> 8) & 0xFF);
        data.push_back((version >> 16) & 0xFF);
        data.push_back((version >> 24) & 0xFF);

        put_varint(data, (uint64_t)inputs.size());
        for (const auto& input : inputs) {
            auto s = input.Serialize();
            data.insert(data.end(), s.begin(), s.end());
        }

        put_varint(data, (uint64_t)outputs.size());
        for (const auto& output : outputs) {
            auto s = output.Serialize();
            data.insert(data.end(), s.begin(), s.end());
        }

        data.push_back(locktime & 0xFF);
        data.push_back((locktime >> 8) & 0xFF);
        data.push_back((locktime >> 16) & 0xFF);
        data.push_back((locktime >> 24) & 0xFF);

        return data;
    }

    Hash256 GetTxID() const {
        // FAST PATH: cache already published. Acquire-load pairs with the
        // winner's release-store below, so reading txid_.value here is ordered
        // strictly after that write — never concurrent with it.
        if (txid_.ready.load(std::memory_order_acquire)) {
#ifndef NDEBUG
            auto recheck = Hash256d(Serialize());
            assert(recheck == txid_.value &&
                   "Transaction txid cache stale — caller mutated tx fields "
                   "without InvalidateTxIDCache(). This would produce a txid "
                   "that disagrees with peers and corrupt mempool/UTXO indexing.");
#endif
            return txid_.value;
        }
        // SLOW PATH: every caller computes its OWN local hash (the value is
        // consensus-deterministic, so a benign double-compute is fine). The
        // single CAS winner of writing(false->true) publishes it to the shared
        // slot and flips ready(release). Losers NEVER read the shared slot —
        // they return their own identical local — so the publish write below is
        // never concurrent with any read. Race-free WITHOUT a per-tx mutex (a
        // mutex would make Transaction non-copyable).
        Hash256 local = Hash256d(Serialize());
        bool expected = false;
        if (txid_.writing.compare_exchange_strong(expected, true,
                                                  std::memory_order_acq_rel)) {
            txid_.value = local;
            txid_.ready.store(true, std::memory_order_release);
        }
        return local;
    }

    // Owned-object operation: the caller is mutating this tx and must not be
    // sharing it with another thread (same precondition the old code implied).
    void InvalidateTxIDCache() {
        txid_.writing.store(false, std::memory_order_relaxed);
        txid_.ready.store(false, std::memory_order_release);
    }

    static size_t Deserialize(const std::vector<uint8_t>& data, size_t offset, Transaction& out) {
        // `out` is an owned mutable destination.  It may be reused after its
        // previous txid was cached; every parse attempt mutates fields below,
        // so carrying that cache across deserialization would make GetTxID()
        // return the prior transaction's identity in release builds (and trip
        // the debug stale-cache assertion).  Invalidate before the first write,
        // including failure paths that leave a partially parsed object.
        out.InvalidateTxIDCache();
        size_t pos = offset;
        const size_t n = data.size();

        if (pos + 4 > n) return 0;
        out.version = data[pos] | ((uint32_t)data[pos+1]<<8) | ((uint32_t)data[pos+2]<<16) | ((uint32_t)data[pos+3]<<24);
        pos += 4;

        auto read_varint = [&](uint64_t& v) -> bool {
            if (pos + 1 > n) return false;
            uint8_t first = data[pos++];
            if (first < 0xFD) { v = first; return true; }
            if (first == 0xFD) {
                if (pos + 2 > n) return false;
                v = (uint64_t)data[pos] | ((uint64_t)data[pos+1] << 8);
                pos += 2; return true;
            }
            if (first == 0xFE) {
                if (pos + 4 > n) return false;
                v = (uint64_t)data[pos] | ((uint64_t)data[pos+1] << 8)
                  | ((uint64_t)data[pos+2] << 16) | ((uint64_t)data[pos+3] << 24);
                pos += 4; return true;
            }
            return false;
        };
        uint64_t in_count = 0;
        if (!read_varint(in_count)) return 0;
        // Reject impossible cardinalities before constructing element objects.
        // IsValid() has always capped valid transactions at the named 10k
        // consensus limits, so accepting ten times that many into a partially
        // parsed object only created a pre-validation memory/CPU amplifier.
        if (in_count > MAX_TRANSACTION_INPUTS) return 0;
        out.inputs.clear();
        // Bound the pre-allocation by what the remaining buffer can physically
        // hold (min serialized input = 32 prevhash + 4 index + 1 scriptlen + 4
        // sequence = 41 B). Without this a small crafted tx that declares a
        // large in_count forces a large reserve() before the loop below
        // bounds-checks each element — a memory-amplification DoS. The parsed
        // result is unchanged (reserve only sets capacity), so this is not a
        // consensus change.
        out.inputs.reserve((size_t)std::min<uint64_t>(in_count,
            std::min<uint64_t>(1024, (uint64_t)(n - pos) / 41)));
        for (uint64_t i = 0; i < in_count; ++i) {
            TxInput inp;
            if (pos + 32 > n) return 0;
            std::copy(data.begin() + pos, data.begin() + pos + 32, inp.prev_tx_hash.begin());
            pos += 32;
            if (pos + 4 > n) return 0;
            inp.prev_out_index = data[pos] | ((uint32_t)data[pos+1]<<8) | ((uint32_t)data[pos+2]<<16) | ((uint32_t)data[pos+3]<<24);
            pos += 4;
            if (pos + 1 > n) return 0;
            uint64_t script_len = 0;
            uint8_t ss_first = data[pos++];
            if (ss_first < 0xFD) {
                script_len = ss_first;
            } else if (ss_first == 0xFD) {
                if (pos + 2 > n) return 0;
                script_len = data[pos] | ((uint64_t)data[pos+1] << 8);
                pos += 2;
            } else if (ss_first == 0xFE) {
                if (pos + 4 > n) return 0;
                script_len = data[pos] | ((uint64_t)(uint32_t)data[pos+1]<<8)
                           | ((uint64_t)(uint32_t)data[pos+2]<<16) | ((uint64_t)(uint32_t)data[pos+3]<<24);
                pos += 4;
            } else {
                return 0;
            }
            if (script_len > MAX_TRANSACTION_SCRIPT_SIG_BYTES ||
                pos + script_len > n) return 0;
            inp.script_sig = std::vector<uint8_t>(data.begin() + pos, data.begin() + pos + script_len);
            pos += script_len;
            if (pos + 4 > n) return 0;
            inp.sequence = data[pos] | ((uint32_t)data[pos+1]<<8) | ((uint32_t)data[pos+2]<<16) | ((uint32_t)data[pos+3]<<24);
            pos += 4;
            out.inputs.push_back(inp);
        }

        uint64_t out_count = 0;
        if (!read_varint(out_count)) return 0;
        if (out_count > MAX_TRANSACTION_OUTPUTS) return 0;
        out.outputs.clear();
        // Same buffer-bounded reservation (min serialized output = 8 value +
        // 1 pk_len = 9 B). Capacity-only; not a consensus change.
        out.outputs.reserve((size_t)std::min<uint64_t>(out_count,
            std::min<uint64_t>(1024, (uint64_t)(n - pos) / 9)));
        for (uint64_t i = 0; i < out_count; ++i) {
            TxOutput txout;
            if (pos + 8 > n) return 0;
            txout.value = 0;
            for (int j = 0; j < 8; ++j)
                txout.value |= ((uint64_t)data[pos + j] << (j * 8));
            pos += 8;
            if (pos + 1 > n) return 0;
            uint64_t pk_len = 0;
            uint8_t varint_first = data[pos++];
            if (varint_first < 0xFD) {
                pk_len = varint_first;
            } else if (varint_first == 0xFD) {
                if (pos + 2 > n) return 0;
                pk_len = data[pos] | ((uint64_t)data[pos+1] << 8);
                pos += 2;
            } else if (varint_first == 0xFE) {
                if (pos + 4 > n) return 0;
                pk_len = data[pos] | ((uint64_t)(uint32_t)data[pos+1]<<8) | ((uint64_t)(uint32_t)data[pos+2]<<16) | ((uint64_t)(uint32_t)data[pos+3]<<24);
                pos += 4;
            } else {
                return 0;
            }
            if (pos + pk_len > n) return 0;
            txout.script_pubkey = std::vector<uint8_t>(data.begin() + pos, data.begin() + pos + pk_len);
            pos += pk_len;
            out.outputs.push_back(txout);
        }

        if (pos + 4 > n) return 0;
        out.locktime = data[pos] | ((uint32_t)data[pos+1]<<8) | ((uint32_t)data[pos+2]<<16) | ((uint32_t)data[pos+3]<<24);
        pos += 4;

        return pos - offset;
    }

    uint64_t TotalOutput() const {
        uint64_t total = 0;
        for (const auto& out : outputs) {
            if (out.value > MAX_SUPPLY_UNITS) return MAX_SUPPLY_UNITS + 1;
            if (total > MAX_SUPPLY_UNITS - out.value) return MAX_SUPPLY_UNITS + 1;
            total += out.value;
        }
        return total;
    }

    bool IsValid() const {
        if (inputs.empty() || outputs.empty()) return false;
        if (TotalOutput() > MAX_SUPPLY_UNITS) return false;
        if (inputs.size() > MAX_TRANSACTION_INPUTS ||
            outputs.size() > MAX_TRANSACTION_OUTPUTS) return false;
        // The already-mined public-test genesis is the sole historical shape
        // that needs a zero-valued empty-script output.  Requiring it to be the
        // coinbase's only output prevents miners from padding every later
        // coinbase with hundreds of permanent zero-value UTXOs; height>0's
        // canonical coinbase validator independently requires OP_RETURN for a
        // genuinely zero-reward block.
        const bool legacy_zero_coinbase_shape =
            inputs.size() == 1 && inputs[0].IsCoinbase() &&
            outputs.size() == 1 && outputs[0].value == 0 &&
            outputs[0].script_pubkey.empty();
        for (const auto& inp : inputs) {
            if (inp.script_sig.size() > MAX_TRANSACTION_SCRIPT_SIG_BYTES)
                return false;
        }
        for (const auto& out : outputs) {
            bool is_op_return = !out.script_pubkey.empty()
                             && out.script_pubkey[0] == 0x6A;
            // Zero-valued ordinary outputs have no economic purpose, but each
            // one used to become a permanent UTXO.  In particular, an empty
            // script slipped through the old `!script.empty()` condition and
            // enabled 10,000-output UTXO/memory amplification.  Preserve only
            // the historical zero-reward coinbase shape (including genesis)
            // and provably unspendable OP_RETURN metadata.
            if (out.value == 0 && !is_op_return &&
                !legacy_zero_coinbase_shape)
                return false;
            const size_t max_script = is_op_return
                ? MAX_OP_RETURN_SCRIPT_PUBKEY_BYTES
                : MAX_SPENDABLE_SCRIPT_PUBKEY_BYTES;
            if (out.script_pubkey.size() > max_script) return false;
        }
        std::unordered_set<std::string> seen_inputs;
        for (const auto& inp : inputs) {
            if (inp.IsCoinbase()) continue;
            std::string key;
            for (auto b : inp.prev_tx_hash) key += (char)b;
            key += ':';
            key += std::to_string(inp.prev_out_index);
            if (!seen_inputs.insert(key).second) return false;
        }
        return true;
    }

    bool IsCoinbase() const {
        return inputs.size() == 1 && inputs[0].IsCoinbase();
    }

    bool HasDustOutput(uint64_t threshold) const {
        if (threshold == 0) return false;
        for (const auto& out : outputs) {
            const bool is_op_return =
                !out.script_pubkey.empty() && out.script_pubkey[0] == 0x6A;
            if (is_op_return) continue;
            if (out.value > 0 && out.value < threshold) return true;
        }
        return false;
    }

    static Transaction CreateCoinbase(
        uint64_t reward_units,
        const std::vector<uint8_t>& miner_script,
        const std::string& message = GENESIS_MESSAGE
    ) {
        Transaction tx;
        tx.inputs.push_back(TxInput::Coinbase(message));
        tx.outputs.push_back(TxOutput(reward_units, miner_script));
        return tx;
    }

    static Transaction CreateProportionalCoinbase(
        const std::vector<std::pair<std::vector<uint8_t>, uint64_t>>& miner_rewards,
        const std::string& message = GENESIS_MESSAGE
    ) {
        Transaction tx;
        tx.inputs.push_back(TxInput::Coinbase(message));
        for (const auto& [script, reward] : miner_rewards) {
            if (reward > 0 && !script.empty())
                tx.outputs.push_back(TxOutput(reward, script));
        }
        // Once subsidy is exhausted, an empty block may have no fees.  A
        // coinbase still needs one structurally valid output; a zero-valued
        // non-OP_RETURN output is invalid, and omitting outputs is invalid.
        // Canonical empty OP_RETURN represents the zero-value coinbase without
        // creating a spendable UTXO or altering supply.
        if (tx.outputs.empty())
            tx.outputs.push_back(TxOutput(0, std::vector<uint8_t>{0x6A, 0x00}));
        return tx;
    }

    // Thread-safe, copyable lazy txid cache backing GetTxID()/InvalidateTxIDCache().
    // Self-contained so Transaction stays copyable WITHOUT a hand-written rule-of-5
    // (a std::mutex member would delete the implicit copy ctor and break the many
    // `Transaction a = b;` copies across the codebase). A copy/move is a DISTINCT
    // object: it carries the value over only if the source is already finalized
    // (so copying a warmed tx stays warm) and never carries the transient
    // `writing` marker. Copying a tx that another thread is concurrently
    // Concurrent mutation during hashing is unsupported; callers must not share
    // a mutable transaction across hashing operations.
    struct TxidCache {
        std::atomic<bool> ready{false};
        std::atomic<bool> writing{false};
        Hash256           value{};
        TxidCache() = default;
        TxidCache(const TxidCache& o)                { copy_from(o); }
        TxidCache(TxidCache&& o) noexcept            { copy_from(o); }
        TxidCache& operator=(const TxidCache& o)     { if (this != &o) copy_from(o); return *this; }
        TxidCache& operator=(TxidCache&& o) noexcept { if (this != &o) copy_from(o); return *this; }
    private:
        void copy_from(const TxidCache& o) {
            writing.store(false, std::memory_order_relaxed);
            if (o.ready.load(std::memory_order_acquire)) {
                value = o.value;
                ready.store(true, std::memory_order_relaxed);
            } else {
                ready.store(false, std::memory_order_relaxed);
            }
        }
    };
    mutable TxidCache txid_;
};

}
