#include "../include/core/address_history.h"
#include "../include/consensus/nms.h"

#include <algorithm>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

size_t checks = 0;
size_t failures = 0;

void Check(bool condition, const char* label) {
    ++checks;
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << label << "\n";
    }
}

class MemoryStore final : public veld::db::KVStore {
public:
    bool Put(const std::string& key, const std::string& value) override {
        values_[key] = value;
        return true;
    }
    bool Delete(const std::string& key) override {
        values_.erase(key);
        return true;
    }
    std::optional<std::string> Get(const std::string& key) override {
        const auto it = values_.find(key);
        return it == values_.end() ? std::nullopt
                                  : std::optional<std::string>(it->second);
    }
    bool Has(const std::string& key) override {
        return values_.find(key) != values_.end();
    }
    bool Write(const veld::db::WriteBatch& batch) override {
        auto next = values_;
        for (const auto& op : batch.ops) {
            if (op.kind == veld::db::WriteBatch::Kind::Put)
                next[op.key] = op.value;
            else
                next.erase(op.key);
        }
        values_.swap(next);
        return true;
    }
    void Iterate(const std::string& prefix,
                 std::function<bool(const std::string&,
                                    const std::string&)> fn) override {
        for (auto it = values_.lower_bound(prefix); it != values_.end(); ++it) {
            if (it->first.rfind(prefix, 0) != 0) break;
            ++iterate_callbacks;
            if (!fn(it->first, it->second)) break;
        }
    }
    void IterateFrom(const std::string& prefix,
                     const std::string& start_after,
                     std::function<bool(const std::string&,
                                        const std::string&)> fn) override {
        auto it = start_after.empty() ? values_.lower_bound(prefix)
                                      : values_.upper_bound(start_after);
        for (; it != values_.end(); ++it) {
            if (it->first.rfind(prefix, 0) != 0) break;
            ++iterate_from_callbacks;
            if (!fn(it->first, it->second)) break;
        }
    }
    std::string GetPath() const override { return "memory"; }
    std::string GetStats() const override {
        return std::to_string(values_.size());
    }

    std::string FirstKey(const std::string& prefix) const {
        const auto it = values_.lower_bound(prefix);
        return it != values_.end() && it->first.rfind(prefix, 0) == 0
            ? it->first : std::string{};
    }

    size_t iterate_callbacks{0};
    size_t iterate_from_callbacks{0};

private:
    std::map<std::string, std::string> values_;
};

std::vector<uint8_t> P2PKH(uint8_t fill) {
    std::vector<uint8_t> script{0x76, 0xa9, 0x14};
    script.insert(script.end(), 20, fill);
    script.push_back(0x88);
    script.push_back(0xac);
    return script;
}

veld::Transaction Coinbase(const std::vector<uint8_t>& script,
                           uint64_t value, const std::string& label) {
    veld::Transaction tx;
    tx.inputs.push_back(veld::TxInput::Coinbase(label));
    tx.outputs.emplace_back(value, script);
    return tx;
}

veld::Block MakeBlock(uint64_t height, const veld::Hash256& parent,
                      std::vector<veld::Transaction> txs) {
    veld::Block block;
    block.height = height;
    block.header.version = veld::PROTOCOL_VERSION;
    block.header.prev_block_hash = parent;
    block.header.timestamp = 1'700'000'000 + height;
    block.header.bits = veld::GENESIS_BITS;
    block.header.nonce = height + 1;
    block.transactions = std::move(txs);
    block.UpdateMerkleRoot();
    return block;
}

}  // namespace

int main() {
    using namespace veld;
    using namespace veld::address_history;

    const auto alice_script = P2PKH(0x11);
    const auto bob_script = P2PKH(0x22);
    const auto miner_script = P2PKH(0x33);
    const std::string alice = ScriptToAddress(alice_script);
    const std::string bob = ScriptToAddress(bob_script);
    Check(!alice.empty() && AddressToScript(alice) == alice_script,
          "Alice address round-trips canonically");
    Check(!bob.empty() && AddressToScript(bob) == bob_script,
          "Bob address round-trips canonically");

    Transaction genesis_coinbase = Coinbase(
        alice_script, 100 * VELD_UNITS, "genesis");
    Block b0 = MakeBlock(0, ZeroHash(), {genesis_coinbase});

    Transaction spend;
    TxInput input;
    input.prev_tx_hash = genesis_coinbase.GetTxID();
    input.prev_out_index = 0;
    spend.inputs.push_back(input);
    spend.outputs.emplace_back(10 * VELD_UNITS, bob_script);
    spend.outputs.emplace_back(89 * VELD_UNITS, alice_script);
    Block b1 = MakeBlock(1, b0.GetHash(), {
        Coinbase(miner_script, 2 * VELD_UNITS, "one"), spend});
    Block b2 = MakeBlock(2, b1.GetHash(), {
        Coinbase(alice_script, 2 * VELD_UNITS, "two")});
    std::vector<Block> chain{b0, b1, b2};

    MemoryStore store;
    store.Put("ah1:r:legacy", "stale received label");
    store.Put("ah1:tip_hash", HashToHex(b2.GetHash()));
    size_t block_loads = 0;
    const bool rebuilt = Rebuild(
        store, std::make_pair<uint64_t, Hash256>(2, b2.GetHash()),
        [&](uint64_t height) {
            ++block_loads;
            if (height >= chain.size()) throw std::out_of_range("height");
            return chain[height];
        },
        [&](uint64_t height, const Hash256& hash) {
            return height == 2 && hash == b2.GetHash();
        });
    Check(rebuilt, "canonical history rebuild succeeds");
    Check(!store.Get("ah1:r:legacy") && !store.Get("ah1:tip_hash"),
          "upgrade removes obsolete history labels and markers");
    Check(block_loads == 3, "rebuild loads each canonical block once");
    Check(MarkersMatch(store, 2, b2.GetHash()),
          "rebuild publishes exact canonical marker");

    const size_t loads_before_query = block_loads;
    store.iterate_from_callbacks = 0;
    auto alice_page = ReadPage(store, alice_script, 2, "");
    Check(alice_page && alice_page->entries.size() == 2,
          "bounded first page contains exactly requested rows");
    Check(alice_page && alice_page->has_more &&
              !alice_page->next_cursor.empty(),
          "bounded first page returns an opaque continuation cursor");
    Check(alice_page && alice_page->entries[0].block_height == 2 &&
              alice_page->entries[0].type == "coinbase" &&
              alice_page->entries[0].net_units ==
                  static_cast<int64_t>(2 * VELD_UNITS),
          "newest mining reward is first");
    Check(alice_page && alice_page->entries[1].block_height == 1 &&
              alice_page->entries[1].type == "sent" &&
              alice_page->entries[1].net_units ==
                  -static_cast<int64_t>(10 * VELD_UNITS) &&
              alice_page->entries[1].fee_units == VELD_UNITS,
          "spend binds exact debit and fee");
    Check(store.iterate_from_callbacks == 3,
          "page reads no more than limit plus one index row");
    Check(block_loads == loads_before_query,
          "history query never invokes the block loader");

    store.iterate_from_callbacks = 0;
    auto alice_next = ReadPage(store, alice_script, 2,
                               alice_page ? alice_page->next_cursor : "");
    Check(alice_next && alice_next->entries.size() == 1 &&
              alice_next->entries[0].block_height == 0,
          "cursor continues strictly after the prior row");
    Check(alice_next && !alice_next->has_more &&
              alice_next->next_cursor.empty(),
          "final page has no continuation cursor");
    Check(store.iterate_from_callbacks == 1,
          "final page reads only the remaining index row");

    auto bob_page = ReadPage(store, bob_script, 50, "");
    Check(bob_page && bob_page->entries.size() == 1 &&
              bob_page->entries[0].type == "received" &&
              bob_page->entries[0].net_units ==
                  static_cast<int64_t>(10 * VELD_UNITS),
          "recipient history binds exact credit");
    Check(!ReadPage(store, alice_script, 0, "") &&
              !ReadPage(store, alice_script, MAX_PAGE_SIZE + 1, ""),
          "zero and oversized pages fail closed");
    Check(!ReadPage(store, alice_script, 1,
                    RowPrefixForScript(bob_script) + "cursor"),
          "cross-address cursor fails closed");
    Check(!ReadPage(store, alice_script, 1,
                    std::string(MAX_CURSOR_SIZE + 1, 'x')),
          "oversized cursor fails closed");

    Check(Rollback(store, b2), "tip rollback succeeds");
    Check(MarkersMatch(store, 1, b1.GetHash()),
          "rollback restores exact parent marker");
    alice_page = ReadPage(store, alice_script, 50, "");
    Check(alice_page && alice_page->entries.size() == 2 &&
              alice_page->entries[0].block_height == 1,
          "rollback removes every row created by the popped block");

    Block alternate2 = MakeBlock(2, b1.GetHash(), {
        Coinbase(bob_script, 3 * VELD_UNITS, "alternate")});
    Check(Advance(store, alternate2),
          "linear advance after rollback succeeds");
    bob_page = ReadPage(store, bob_script, 50, "");
    Check(bob_page && bob_page->entries.size() == 2 &&
              bob_page->entries[0].block_height == 2 &&
              bob_page->entries[0].type == "coinbase",
          "replacement branch rows are visible newest first");

    Check(store.Delete(TIP_HASH_KEY), "test removes completion marker");
    Check(!MarkersMatch(store, 2, alternate2.GetHash()),
          "missing completion marker is detected");

    uint64_t fixed = 0;
    Check(ParseFixedDecimal("00000000000000000042", 20, fixed) && fixed == 42,
          "fixed-width index integer accepts required zero padding");
    Check(!ParseFixedDecimal("0000000000000000004x", 20, fixed),
          "fixed-width index integer rejects non-decimal bytes");
    // Production pool settlements contain no text marker. Their source is
    // established by the spent outputs, including after a history rebuild.
    Transaction funding = Coinbase(alice_script, 10 * VELD_UNITS, "rewards");
    const std::vector<std::pair<std::string, std::string>> pools{
        {VAULT_ADDRESS, "staking_distribution"},
        {POOL_ADDRESS, "comine_payout"},
        {ENDORSEMENT_POOL_ADDRESS, "endorsement_reward"}};
    for (const auto& pool : pools)
        funding.outputs.emplace_back(100 * VELD_UNITS, AddressToScript(pool.first));
    Block rewards0 = MakeBlock(0, ZeroHash(), {funding});
    std::vector<Transaction> payouts;
    for (size_t i = 0; i < pools.size(); ++i) {
        Transaction payout;
        TxInput pool_input;
        pool_input.prev_tx_hash = funding.GetTxID();
        pool_input.prev_out_index = static_cast<uint32_t>(i + 1);
        payout.inputs.push_back(pool_input);
        payout.outputs.emplace_back(20 * VELD_UNITS, alice_script);
        payout.outputs.emplace_back(80 * VELD_UNITS, AddressToScript(pools[i].first));
        payouts.push_back(payout);
    }
    Block rewards1 = MakeBlock(1, rewards0.GetHash(), payouts);
    MemoryStore rewards;
    Check(Advance(rewards, rewards0) && Advance(rewards, rewards1),
          "markerless pool payouts indexed");
    auto reward_page = ReadPage(rewards, alice_script, 50, "");
    for (size_t i = 0; i < pools.size(); ++i) {
        const auto found = std::find_if(reward_page->entries.begin(), reward_page->entries.end(),
            [&](const Entry& entry) { return entry.txid == HashToHex(payouts[i].GetTxID()); });
        Check(found != reward_page->entries.end() && found->type == pools[i].second &&
                  found->net_units == 20 * VELD_UNITS && found->fee_units == 0,
              "markerless payout classified from its funding pool with exact value");
    }
    Transaction nms;
    TxInput nms_input;
    nms_input.prev_tx_hash = funding.GetTxID();
    nms_input.prev_out_index = 0;
    nms.inputs.push_back(nms_input);
    nms.outputs.emplace_back(MIN_TX_FEE, alice_script);
    BlockHeader claim;
    claim.prev_block_hash = rewards1.GetHash();
    claim.bits = GENESIS_BITS;
    nms.outputs.emplace_back(0, BuildNmsOpReturnScript(EncodeNmsPayload(claim)));
    nms.outputs.emplace_back(10 * VELD_UNITS - 2 * MIN_TX_FEE, alice_script);
    Block rewards2 = MakeBlock(2, rewards1.GetHash(), {nms});
    Check(Advance(rewards, rewards2), "near-miss history indexed");
    reward_page = ReadPage(rewards, alice_script, 1, "");
    Check(reward_page && reward_page->entries[0].type == "near_miss_submission" &&
              reward_page->entries[0].fee_units == MIN_TX_FEE &&
              reward_page->entries[0].net_units == 0,
          "near-miss is a fee-paying entry rather than a self-transfer");
    Check(EntryType(spend, 0, static_cast<int64_t>(VELD_UNITS),
                    "VELD_DIST|STAKING|fixture") == "received",
          "an ordinary sender cannot label a transfer as a staking reward");

    std::cout << (failures == 0 ? "PASS " : "FAIL ")
              << "address_history_index_tests checks=" << checks
              << " block_loads=" << block_loads << "\n";
    return failures == 0 ? 0 : 1;
}
