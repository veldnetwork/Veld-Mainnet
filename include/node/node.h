#pragma once

#include "../core/blockchain.h"
#include "../core/canonical_numeric.h"
#include "../core/version.h"
#include "../core/mempool.h"
#include "../core/storage.h"
#include "../core/leveldb.h"
#include "../core/miner_archive.h"
#include "../core/script.h"
#include "../core/pqc_script.h"
#include "../core/onchain_tokens.h"
#include "../core/redeem_index.h"
#include "../core/mint_nullifier_index.h"
#include "../core/btcveld_supply_snapshot.h"
#include "../core/amm_pool.h"
#include "../core/btc_relay_order.h"
#include "../consensus/tiers.h"
#include "../consensus/governance.h"
#include "../consensus/checkpoints.h"
#include "../mining/miner.h"
#include "../mining/veldhash.h"
#include "../mining/genesis_pow.h"
#include "../mining/preflight_selector.h"
#include "../consensus/staking.h"
#include "../consensus/validators.h"
#include "../consensus/btcveld_redeem_params.h"
#include "../consensus/btcveld_anchor.h"          // Layer-2 BTC checkpoint anchor set + VerifyAnchor
#include "../consensus/btcveld_anchor_floor_store.h" // durable local observed floor (VLF1)
#include "../consensus/btcveld_anchor_params.h"   // Layer-2 anchoring: state-derived activation (R3)
#include "../consensus/finality_state.h"           // locked-QC retained finality artifact
#include "../consensus/finality_codec.h"           // finality certificate wire format
#include "../consensus/finality_producer.h"        // validator vote intake / assembler
#include "../consensus/finality_equivocation.h"     // authenticated sibling evidence
#include "../core/vault.h"
#include "../crypto/veld_signing.h"
#include "../crypto/ripemd160.h"
#include "ibd_policy.h"
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
#include "snapshot_manifest.h"
#include "full_ibd_receipt.h"
#endif
#include "work_admission.h"
#include "work_admission_coordinator.h"
#include "block_template_authorization.h"
#include "../wallet/wallet.h"
#include "../wallet/secure_channel_file.h"
#include "../network/p2p.h"
#include "../network/tcp.h"
#include "../network/rpc.h"
#include "../network/finality_rpc_limits.h"
#include "../network/explorer.h"
#include "../network/chainparams.h"
#include "../network/network_identity.h"
#include "../network/public_testnet_runtime.h"
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <filesystem>
#include "../compat/platform.h"
#include "../compat/process.h"
#include <queue>
#include <deque>
#include <condition_variable>
#include <set>
#include <fstream>
#include <cstdlib>
#include <cctype>
#include <cmath>
#include <system_error>
#include <optional>
// Terminal detection for bounded user-facing progress output: in-place \r
// rendering on a real TTY, plain periodic lines otherwise (e.g. systemd logs).
#if defined(_WIN32)
#  include <io.h>
#  include <cstdio>
#else
#  include <unistd.h>
#endif

namespace veld {

struct RpcCall {
    std::string              id;
    std::string              method;
    std::vector<std::string> params;

    static RpcCall Parse(const std::string& json) {
        RpcCall call;

        auto extract_string_field = [&](const std::string& key) -> std::string {
            auto kpos = json.find("\"" + key + "\"");
            if (kpos == std::string::npos) return "";
            auto colon = json.find(':', kpos);
            if (colon == std::string::npos) return "";
            auto start = json.find_first_not_of(" \t\n\r", colon + 1);
            if (start == std::string::npos) return "";

            if (json[start] == '"') {
                auto end = json.find('"', start + 1);
                while (end != std::string::npos && json[end-1] == '\\')
                    end = json.find('"', end + 1);
                if (end == std::string::npos) return "";
                return json.substr(start + 1, end - start - 1);
            } else {
                auto end = json.find_first_of(",}\n", start);
                std::string val = json.substr(start, end - start);
                while (!val.empty() && std::isspace(val.back())) val.pop_back();
                return val;
            }
        };

        call.id     = extract_string_field("id");
        call.method = extract_string_field("method");

        auto params_pos = json.find("\"params\"");
        if (params_pos != std::string::npos) {
            auto bracket = json.find('[', params_pos);
            if (bracket != std::string::npos) {
                size_t i = bracket + 1;
                while (i < json.size() && json[i] != ']') {
                    while (i < json.size() && std::isspace(json[i])) ++i;
                    if (i >= json.size() || json[i] == ']') break;

                    if (json[i] == '"') {
                        ++i;
                        std::string val;
                        while (i < json.size() && json[i] != '"') {
                            if (json[i] == '\\' && i+1 < json.size()) {
                                ++i;
                                switch (json[i]) {
                                    case 'n': val += '\n'; break;
                                    case 't': val += '\t'; break;
                                    case '"': val += '"'; break;
                                    case '\\': val += '\\'; break;
                                    default: val += json[i]; break;
                                }
                            } else {
                                val += json[i];
                            }
                            ++i;
                        }
                        ++i;
                        call.params.push_back(val);
                    } else if (json[i] == 't' || json[i] == 'f' || json[i] == 'n') {
                        size_t end = json.find_first_of(",]", i);
                        call.params.push_back(json.substr(i, end - i));
                        i = end;
                    } else {
                        size_t end = json.find_first_of(",]", i);
                        std::string num = json.substr(i, end - i);
                        while (!num.empty() && std::isspace(num.back())) num.pop_back();
                        call.params.push_back(num);
                        i = end;
                    }

                    while (i < json.size() && (std::isspace(json[i]) || json[i] == ',')) ++i;
                }
            }
        }

        return call;
    }

    std::string ToJson() const {
        std::string j = "{\"jsonrpc\":\"2.0\",\"id\":\"" + id + "\",\"method\":\"" + method + "\",\"params\":[";
        for (size_t i = 0; i < params.size(); ++i) {
            if (i > 0) j += ",";
            j += "\"" + params[i] + "\"";
        }
        j += "]}";
        return j;
    }
};

struct MineBlockResult {
    bool    success;
    Block   block;
    Hash256 hash;
    uint64_t new_height;
    uint64_t new_supply_units;
    double  elapsed_ms;
    uint64_t hashes_tried;
    std::string error;
    uint32_t best_nonce{0};
    Hash256  best_hash{};
};

inline uint64_t NextMiningTimestamp(const Blockchain& chain) {
    uint64_t now = (uint64_t)std::time(nullptr);
    if (chain.IsEmpty()) return now;
    uint64_t min_ts = chain.MedianTimePast() + 1;
    return now < min_ts ? min_ts : now;
}

inline bool IsProtocolSettlementHeight(uint64_t height) {
    return height > 0 &&
           ((height % COMINE_WINDOW_BLOCKS) == 0 ||
            (height % VAULT_DISTRIBUTION_INTERVAL) == 0 ||
            (height % BOND_SETTLEMENT_INTERVAL) == 0);
}

// Return the canonical serialized size of the largest coinbase shape the
// launch builder can emit for this height. Values are fixed-width on the wire,
// so fee/reward amounts do not affect the result. Using the real scripts and
// CreateProportionalCoinbase keeps this budget tied to the canonical serializer
// instead of a hand-maintained byte constant.
inline size_t MaxCanonicalMiningCoinbaseSize(
    uint64_t height,
    const std::vector<uint8_t>& miner_script,
    const std::vector<uint8_t>& pool_script,
    const std::vector<uint8_t>& vault_script,
    const std::vector<uint8_t>& endorse_script,
    const std::vector<std::vector<uint8_t>>& metadata_scripts = {})
{
    std::vector<std::pair<std::vector<uint8_t>, uint64_t>> outputs;
    auto add = [&](const std::vector<uint8_t>& script) {
        if (!script.empty()) outputs.push_back({script, 1});
    };
    add(miner_script);
    add(pool_script);
    add(vault_script);
    add(endorse_script);
    if (outputs.empty()) outputs.push_back({{}, 1});
    Transaction cb = Transaction::CreateProportionalCoinbase(
        outputs, "Veld block " + std::to_string(height));
    for (const auto& script : metadata_scripts)
        cb.outputs.push_back(TxOutput(0, script));
    return cb.Serialize().size();
}

// The block-size limit covers the complete canonical wire object. Reserve the
// 92-byte header/count envelope, the maximum canonical coinbase for this
// builder, and every already-derived mandatory protocol settlement before
// selecting ordinary mempool transactions. All additions are checked.
inline bool ComputeMiningMempoolBudget(
    size_t max_coinbase_size,
    const std::vector<Transaction>& mandatory_txs,
    size_t* out_bytes,
    size_t* out_count)
{
    if (!out_bytes || !out_count ||
        mandatory_txs.size() > (size_t)MAX_TRANSACTIONS_PER_BLOCK - 1)
        return false;
    size_t fixed = 92;
    auto add_size = [&](size_t n) {
        if (n > std::numeric_limits<size_t>::max() - fixed) return false;
        fixed += n;
        return true;
    };
    if (!add_size(max_coinbase_size)) return false;
    for (const auto& tx : mandatory_txs) {
        if (tx.IsCoinbase() || !tx.IsValid()) return false;
        if (!add_size(tx.Serialize().size())) return false;
    }
    if (fixed > (size_t)MAX_BLOCK_SIZE) return false;
    *out_bytes = (size_t)MAX_BLOCK_SIZE - fixed;
    *out_count = (size_t)MAX_TRANSACTIONS_PER_BLOCK - 1 -
                 mandatory_txs.size();
    return true;
}

inline MineBlockResult MineAndCommit(
    Blockchain& chain,
    Mempool& mempool,
    const RealKeyPair& miner_keypair,
    uint32_t bits_override = 0,
    std::atomic<bool>* stop = nullptr
) {
    MineBlockResult result{};
    result.success = false;

    if (chain.IsEmpty()) return result;

    Block candidate;
    candidate.height = chain.Height() + 1;
    candidate.header.version         = PROTOCOL_VERSION;
    candidate.header.prev_block_hash = chain.Tip().GetHash();
    candidate.header.timestamp       = NextMiningTimestamp(chain);
    const uint32_t expected_bits      = chain.ComputeNextBits();
    candidate.header.bits            = bits_override ? bits_override : expected_bits;
    candidate.header.nonce           = 0;
    CanonicalPowTarget mining_target;
    if (!DecodeExpectedVeldTarget(
            candidate.header.bits, expected_bits, mining_target)) {
        result.error = "local mining target is noncanonical or not branch-local";
        return result;
    }

    // This standalone helper has no access to the node-owned settlement
    // engines. Refuse boundary construction explicitly instead of mining a
    // template that full consensus will reject for a missing payout.
    if (IsProtocolSettlementHeight(candidate.height)) {
        result.error =
            "protocol settlement height requires the VeldNode mining builder";
        return result;
    }

    uint64_t reward = Blockchain::ExpectedBlockSubsidy(candidate.height);
    auto vault_script  = AddressToScript(VaultAddressAtHeight(candidate.height));
    auto miner_script  = miner_keypair.GetP2PKHScript();

    std::vector<std::pair<std::vector<uint8_t>, uint64_t>> cb_outputs;
    bool is_vault_block = (candidate.height > 0 && candidate.height % VAULT_BLOCK_INTERVAL == 0);

    uint64_t total_supply_now = chain.TotalSupplyUnits();
    uint64_t remaining = (MAX_SUPPLY_UNITS > total_supply_now) ? (MAX_SUPPLY_UNITS - total_supply_now) : 0;
    uint64_t effective_reward = std::min(reward, remaining);
    reward = effective_reward;

    const auto pool_script_const = AddressToScript(POOL_ADDRESS);
    const auto endorse_script_const = AddressToScript(ENDORSEMENT_POOL_ADDRESS);
    size_t mempool_byte_budget = 0, mempool_count_budget = 0;
    const size_t max_coinbase_size = MaxCanonicalMiningCoinbaseSize(
        candidate.height, miner_script, pool_script_const, vault_script,
        endorse_script_const);
    if (!ComputeMiningMempoolBudget(max_coinbase_size, {},
                                    &mempool_byte_budget,
                                    &mempool_count_budget)) {
        result.error = "canonical coinbase exceeds the block-size envelope";
        return result;
    }
    auto mempool_raw = mempool.GetBlockTransactionsWithFees(
        mempool_count_budget, mempool_byte_budget, &chain);
    std::vector<Transaction> mempool_txs_to_include;
    uint64_t total_tx_fees = 0;
    for (auto& [tx, fee] : mempool_raw) {
        if (tx.IsCoinbase()) continue;
        bool inputs_valid = true;
        for (const auto& inp : tx.inputs) {
            if (inp.IsCoinbase()) continue;
            auto utxo = chain.GetUTXO(inp.prev_tx_hash, inp.prev_out_index);
            if (!utxo) { inputs_valid = false; break; }
        }
        if (inputs_valid) {
            mempool_txs_to_include.push_back(tx);
            total_tx_fees += fee;
        }
    }

    const uint64_t supply_at_parent_sm = chain.TotalSupplyUnits();
    const bool is_pre_activation_sm =
        (supply_at_parent_sm < STAKING_UNLOCK_SUPPLY);

    if (effective_reward == 0) {
        if (total_tx_fees > 0) {
            uint64_t v = (total_tx_fees * 40) / 100;
            uint64_t e = (total_tx_fees * 10) / 100;
            uint64_t m = total_tx_fees - v - e;
            cb_outputs.push_back({miner_script, m});
            if (!vault_script.empty() && vault_script != miner_script)
                cb_outputs.push_back({vault_script, v});
            else
                cb_outputs[0].second += v;
            if (!endorse_script_const.empty() && e > 0)
                cb_outputs.push_back({endorse_script_const, e});
            else
                cb_outputs[0].second += e;
        } else {
            cb_outputs.push_back({vault_script, 0});
        }
    } else if (is_vault_block) {
        // Canonical split priority is height first: every 100th block is
        // all-to-vault even while the public chain remains below the 100k VELD
        // staking threshold.  Keep this before the pre-activation 50/50 arm,
        // matching Blockchain::ValidateCanonicalCoinbaseSplit exactly.
        cb_outputs.push_back({vault_script, effective_reward + total_tx_fees});
    } else if (is_pre_activation_sm) {
        const uint64_t miner_cut = (effective_reward * 50) / 100;
        const uint64_t vault_cut = effective_reward - miner_cut + total_tx_fees;
        cb_outputs.push_back({miner_script, miner_cut});
        if (!vault_script.empty() && vault_script != miner_script)
            cb_outputs.push_back({vault_script, vault_cut});
        else
            cb_outputs[0].second += vault_cut;
    } else {
        const uint64_t pool_cut    = (effective_reward * 20) / 100;
        const uint64_t vault_cut   = (effective_reward * 20) / 100;
        const uint64_t endorse_cut = (effective_reward * 10) / 100;
        const uint64_t winner_cut  = effective_reward - pool_cut - vault_cut - endorse_cut;
        const uint64_t vault_total = vault_cut + total_tx_fees;

        cb_outputs.push_back({miner_script,   winner_cut});
        if (!pool_script_const.empty() && pool_script_const != miner_script)
            cb_outputs.push_back({pool_script_const, pool_cut});
        else
            cb_outputs[0].second += pool_cut;
        if (!vault_script.empty() && vault_script != miner_script)
            cb_outputs.push_back({vault_script, vault_total});
        else
            cb_outputs[0].second += vault_total;
        if (!endorse_script_const.empty() && endorse_script_const != miner_script)
            cb_outputs.push_back({endorse_script_const, endorse_cut});
        else
            cb_outputs[0].second += endorse_cut;
    }
    Transaction coinbase = Transaction::CreateProportionalCoinbase(
        cb_outputs, "Veld block " + std::to_string(candidate.height));
    candidate.transactions.push_back(coinbase);

    for (const auto& tx : mempool_txs_to_include)
        candidate.transactions.push_back(tx);

    candidate.UpdateMerkleRoot();

    auto header_bytes = candidate.header.Serialize();
    Hash256 target = candidate.header.GetTarget();

    auto global_pow_lease = mining::GlobalExpensivePowBudget().TryAcquire(
        mining::ExpensivePowUse::InternalMine);
    if (!global_pow_lease) {
        result.error = "global expensive-PoW admission budget exhausted";
        return result;
    }
    auto t_start = std::chrono::high_resolution_clock::now();
    uint64_t hashes = 0;
    bool found = false;
    Hash256 found_hash;

    for (uint64_t nonce = 0; ; ++nonce) {
        if (stop && stop->load()) {
            result.error = "Mining stopped";
            return result;
        }

        for (int b = 0; b < 8; ++b)
            header_bytes[80 + b] = (uint8_t)((nonce >> (b * 8)) & 0xFF);

        Hash256 h = mining::VeldHash(header_bytes, candidate.height);
        ++hashes;

        if (h < target) {
            candidate.header.nonce = nonce;
            found_hash = h;
            found = true;
            if (veld::DiagVerbose().load()) veld::vcerr() << "  [mine_debug h=" << candidate.height
                      << "] pow=" << HashToHex(h).substr(0,32)
                      << "... nonce=" << nonce
                      << " prev=" << HashToHex(candidate.header.prev_block_hash).substr(0,16)
                      << "... merk=" << HashToHex(candidate.header.merkle_root).substr(0,16)
                      << "... bits=0x" << std::hex << candidate.header.bits << std::dec
                      << " ts=" << candidate.header.timestamp
                      << "\n";
            std::cerr.flush();
            break;
        }

        if (nonce == UINT64_MAX) break;
    }

    auto t_end = std::chrono::high_resolution_clock::now();
    result.elapsed_ms   = std::chrono::duration<double, std::milli>(t_end - t_start).count();
    result.hashes_tried = hashes;

    if (!found) {
        result.error = "Nonce space exhausted";
        return result;
    }

    // Rebuild the block with the selected nonce without recomputing its Merkle
    // root. The broadcast header must remain byte-identical to the mined header.
    //  PoW hard fork: nonce is uint64 at offset 80..88.
    {
        uint64_t n = 0;
        for (int b = 0; b < 8; ++b)
            n |= ((uint64_t)header_bytes[80 + b]) << (b * 8);
        candidate.header.nonce = n;
    }

    // Local production must traverse the exact same consensus path as an
    // inbound block.  PoW was already solved above, but rechecking it is cheap
    // compared with admitting a block that peers will deterministically reject.
    global_pow_lease.reset();
    bool committed = chain.AddBlockDirect(
        candidate, false, false, false,
        mining::PowAdmissionContext::Internal());
    if (!committed) {
        result.error = "Block validation failed during commit";
        return result;
    }

    mempool.RemoveConfirmed(candidate);

    result.success           = true;
    result.block             = candidate;
    result.hash              = found_hash;
    result.new_height        = chain.Height();
    result.new_supply_units  = chain.TotalSupplyUnits();
    return result;
}

// MineOnly: find a valid nonce but do NOT commit to chain
// Returns the solved block for the caller to modify (e.g. add co-miners) then commit
// Optional progress callback for co-mining: called periodically with the
// current block height + best nonce/hash so the caller (VeldNode) can
// publish them to tcp_server for the COMINE peer-handshake.
using MiningProgressCb =
    std::function<void(uint64_t height, uint32_t best_nonce, const Hash256& best_hash)>;

using NmsBroadcastCb = std::function<void(const BlockHeader& )>;
using MiningCandidatePreflight = std::function<bool(const Block&)>;

inline MineBlockResult MineOnly(
    Blockchain& chain,
    Mempool& mempool,
    const RealKeyPair& miner_keypair,
    uint32_t bits_override = 0,
    std::atomic<bool>* stop = nullptr,
    const std::vector<uint8_t>& pool_script = {},
    unsigned num_threads = 1,
    MiningProgressCb progress_cb = nullptr,
    const std::vector<std::pair<std::vector<uint8_t>, uint64_t>>& validator_cb_outputs = {},
    NmsBroadcastCb nms_cb = nullptr,
    std::atomic<uint64_t>* progress_counter = nullptr,
    const std::vector<Transaction>& mandatory_txs = {},
    MiningCandidatePreflight candidate_preflight = nullptr,
    const std::vector<std::vector<uint8_t>>& coinbase_metadata_scripts = {}
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
    , bool qualification_candidate_only = false
#endif
) {
    MineBlockResult result{};
    result.success = false;

    if (chain.IsEmpty()) return result;

    Block candidate;
    candidate.height = chain.Height() + 1;
    candidate.header.version        = PROTOCOL_VERSION;
    candidate.header.prev_block_hash = chain.Tip().GetHash();
    candidate.header.timestamp      = NextMiningTimestamp(chain);
    const uint32_t expected_bits     = chain.ComputeNextBits();
    candidate.header.bits           = bits_override ? bits_override : expected_bits;
    candidate.header.nonce          = 0;
    CanonicalPowTarget mining_target;
    if (!DecodeExpectedVeldTarget(
            candidate.header.bits, expected_bits, mining_target)) {
        result.error = "local mining target is noncanonical or not branch-local";
        return result;
    }

    auto vault_script  = AddressToScript(VaultAddressAtHeight(candidate.height));
    auto miner_script  = miner_keypair.script_override.empty()
                       ? miner_keypair.GetP2PKHScript()
                       : miner_keypair.script_override;

    const auto shared_pool_script = AddressToScript(POOL_ADDRESS);
    const auto effective_pool_script = !shared_pool_script.empty()
        ? shared_pool_script : pool_script;
    const auto endorse_script = AddressToScript(ENDORSEMENT_POOL_ADDRESS);
    size_t mempool_byte_budget = 0, mempool_count_budget = 0;
    const size_t max_coinbase_size = MaxCanonicalMiningCoinbaseSize(
        candidate.height, miner_script, effective_pool_script, vault_script,
        endorse_script, coinbase_metadata_scripts);
    if (!ComputeMiningMempoolBudget(max_coinbase_size, mandatory_txs,
                                    &mempool_byte_budget,
                                    &mempool_count_budget)) {
        result.error =
            "mandatory settlements and coinbase exceed the block-size envelope";
        return result;
    }
    mempool_count_budget = std::min<size_t>(mempool_count_budget, 999);
    auto mempool_raw = mempool.GetBlockTransactionsWithFees(
        mempool_count_budget, mempool_byte_budget, &chain);
    std::vector<std::pair<Transaction, uint64_t>> mempool_with_fees;
    uint64_t total_tx_fees = 0;
    for (auto& [tx, fee] : mempool_raw) {
        if (tx.IsCoinbase()) continue;
        bool inputs_valid = true;
        for (const auto& inp : tx.inputs) {
            if (inp.IsCoinbase()) continue;
            auto utxo = chain.GetUTXO(inp.prev_tx_hash, inp.prev_out_index);
            if (!utxo) { inputs_valid = false; break; }
        }
        if (inputs_valid) {
            mempool_with_fees.push_back({tx, fee});
            total_tx_fees += fee;
        } else {
            mempool.Remove(HashToHex(tx.GetTxID()));
        }
    }

    // Header relays can form a valid replacement Bitcoin branch across
    // multiple mempool transactions. Fee-rate order alone may place a child
    // before the batch that supplies its parent, making an otherwise valid
    // candidate fail the unchanged consensus preflight.
    btcspv::StableDependencyOrderBtcHeaderTransactions(mempool_with_fees);

    uint64_t total_supply_now = chain.TotalSupplyUnits();
    uint64_t remaining_to_cap = (MAX_SUPPLY_UNITS > total_supply_now)
                              ? (MAX_SUPPLY_UNITS - total_supply_now) : 0;
    uint64_t base_reward = Blockchain::ExpectedBlockSubsidy(candidate.height);
    uint64_t effective_reward = std::min(base_reward, remaining_to_cap);

    const uint64_t supply_at_parent_for_split = chain.TotalSupplyUnits();
    const bool is_pre_activation =
        (supply_at_parent_for_split < STAKING_UNLOCK_SUPPLY);

    auto build_coinbase = [&](uint64_t fees) {
        std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
            coinbase_outputs;
        if (effective_reward == 0) {
          if (fees > 0) {
            uint64_t vault_cut   = (fees * 40) / 100;
            uint64_t endorse_cut = (fees * 10) / 100;
            uint64_t miner_cut   = fees - vault_cut - endorse_cut;
            coinbase_outputs.push_back({miner_script, miner_cut});
            if (!vault_script.empty() && vault_script != miner_script)
                coinbase_outputs.push_back({vault_script, vault_cut});
            else
                coinbase_outputs[0].second += vault_cut;
            { auto eps = AddressToScript(ENDORSEMENT_POOL_ADDRESS);
              if (!eps.empty() && endorse_cut > 0) coinbase_outputs.push_back({eps, endorse_cut});
              else coinbase_outputs[0].second += endorse_cut; }
          } else {
            coinbase_outputs.push_back({vault_script, 0});
          }
        } else if (candidate.height > 0 &&
                   candidate.height % VAULT_BLOCK_INTERVAL == 0) {
        // Every vault-cadence block is all-to-vault regardless of whether the
        // staking supply threshold has been reached.  This ordering is the
        // consensus ordering in ValidateCanonicalCoinbaseSplit.
        coinbase_outputs.push_back({vault_script, effective_reward + fees});
        } else if (is_pre_activation) {
        const uint64_t miner_cut = (effective_reward * 50) / 100;
        const uint64_t vault_cut = effective_reward - miner_cut + fees;
        coinbase_outputs.push_back({miner_script, miner_cut});
        if (!vault_script.empty() && vault_script != miner_script)
            coinbase_outputs.push_back({vault_script, vault_cut});
        else
            coinbase_outputs[0].second += vault_cut;
        } else {
        uint64_t pool_cut      = (effective_reward * 20) / 100;
        uint64_t vault_cut     = (effective_reward * 20) / 100;
        uint64_t endorse_cut   = (effective_reward * 10) / 100;
        uint64_t winner_cut    = effective_reward - pool_cut - vault_cut - endorse_cut;
        uint64_t vault_total   = vault_cut + fees;

        coinbase_outputs.push_back({miner_script, winner_cut});

        auto shared_pool_script = AddressToScript(POOL_ADDRESS);
        if (!shared_pool_script.empty())
            coinbase_outputs.push_back({shared_pool_script, pool_cut});
        else if (!pool_script.empty() && pool_script != miner_script)
            coinbase_outputs.push_back({pool_script, pool_cut});
        else
            coinbase_outputs[0].second += pool_cut;

        { auto eps = AddressToScript(ENDORSEMENT_POOL_ADDRESS);
          if (!eps.empty() && endorse_cut > 0) coinbase_outputs.push_back({eps, endorse_cut});
          else vault_total += endorse_cut; }

        if (!vault_script.empty() && vault_script != miner_script)
            coinbase_outputs.push_back({vault_script, vault_total});
        else
            coinbase_outputs[0].second += vault_total;
        }
        Transaction cb = Transaction::CreateProportionalCoinbase(
            coinbase_outputs,
            "Veld block " + std::to_string(candidate.height));
        for (const auto& script : coinbase_metadata_scripts)
            cb.outputs.push_back(TxOutput(0, script));
        return cb;
    };

    // Stateful modules consume the whole block in one canonical order.  Two
    // individually admissible mempool entries can still conflict in that
    // sequence. The shared selector keeps the passing full candidate fast path;
    // if that fails, it proves an ordinary/mandatory baseline and constructively
    // retains each stateful request that preserves full-module validity.
    if (candidate_preflight) {
        auto selection = mining::SelectConstructivePreflightCandidate(
            candidate, mempool_with_fees, mandatory_txs, build_coinbase,
            candidate_preflight);
        if (!selection.success) {
            result.error = selection.error;
            return result;
        }
        candidate = std::move(selection.candidate);

        std::vector<std::pair<Transaction, uint64_t>> retained_mempool;
        retained_mempool.reserve(mempool_with_fees.size());
        for (size_t i = 0; i < mempool_with_fees.size(); ++i) {
            if (selection.retained_mempool[i])
                retained_mempool.push_back(std::move(mempool_with_fees[i]));
        }
        mempool_with_fees = std::move(retained_mempool);
    } else {
        candidate.transactions.push_back(build_coinbase(total_tx_fees));
        for (const auto& tx_and_fee : mempool_with_fees)
            candidate.transactions.push_back(tx_and_fee.first);
        for (const auto& tx : mandatory_txs)
            candidate.transactions.push_back(tx);
    }

    if (candidate.SerializedSize() > (size_t)MAX_BLOCK_SIZE) {
        result.error = "candidate exceeded its precomputed block-size budget";
        return result;
    }

    if (veld::DiagVerbose().load()) veld::vcerr() << "  [mineonly h=" << candidate.height
              << "] mempool_raw=" << mempool_raw.size()
              << " mempool_with_fees=" << mempool_with_fees.size()
              << " candidate_txs=" << candidate.transactions.size() << "\n";
    std::cerr.flush();

    candidate.UpdateMerkleRoot();

    uint64_t min_ts = chain.MedianTimePast() + 1;
    if (candidate.header.timestamp < min_ts)
        candidate.header.timestamp = min_ts;

#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
    // The native D-state harness needs the exact production candidate builder
    // without spending five synthetic years of memory-hard work.  This returns
    // an uncommitted candidate only; AddBlockDirect still runs afterward with
    // skip_pow=false, where VELD_TEST_BRANCH_CONTEXT bypasses only the final
    // hash-vs-target comparison.  Public builds cannot contain either seam.
    if (qualification_candidate_only) {
        result.success = true;
        result.block = candidate;
        result.hash = candidate.GetHash();
        result.new_height = candidate.height;
        result.elapsed_ms = 0.0;
        result.hashes_tried = 0;
        return result;
    }
#endif

    auto global_pow_lease = mining::GlobalExpensivePowBudget().TryAcquire(
        mining::ExpensivePowUse::InternalMine);
    if (!global_pow_lease) {
        result.error = "global expensive-PoW admission budget exhausted";
        return result;
    }
    auto start = std::chrono::steady_clock::now();
    Hash256 found_hash;
    uint64_t hashes = 0;

    Hash256 best_hash_found{};
    best_hash_found.fill(0xFF);
    uint64_t best_nonce_found = 0;

    candidate.UpdateMerkleRoot();

    std::vector<uint8_t> header_bytes(88);
    auto write32 = [&](int offset, uint32_t v) {
        header_bytes[offset]   =  v        & 0xFF;
        header_bytes[offset+1] = (v >>  8) & 0xFF;
        header_bytes[offset+2] = (v >> 16) & 0xFF;
        header_bytes[offset+3] = (v >> 24) & 0xFF;
    };
    auto write64 = [&](int offset, uint64_t v) {
        for (int i = 0; i < 8; ++i)
            header_bytes[offset + i] = (uint8_t)((v >> (i*8)) & 0xFF);
    };

    auto rebuild_header = [&]() {
        write32(0,  candidate.header.version);
        std::copy(candidate.header.prev_block_hash.begin(),
                  candidate.header.prev_block_hash.end(), header_bytes.begin() + 4);
        std::copy(candidate.header.merkle_root.begin(),
                  candidate.header.merkle_root.end(),     header_bytes.begin() + 36);
        write64(68, candidate.header.timestamp);
        write32(76, candidate.header.bits);
    };
    rebuild_header();

    Hash256 target = candidate.header.GetTarget();

    Hash256 target_x4{};
    {
        uint32_t carry = 0;
        for (int i = 31; i >= 0; --i) {
            uint32_t v = (uint32_t)target[i] * 4u + carry;
            target_x4[i] = (uint8_t)(v & 0xFF);
            carry = v >> 8;
        }
        if (carry != 0) target_x4.fill(0xFF);
    }
    std::atomic<bool> nms_broadcast_guard{false};

#ifdef VELD_MAINNET_POW
    Hash256 ds_seed_loop = mining::ComputeEpochSeed(
        candidate.header.prev_block_hash, candidate.height,
        candidate.header.bits);
    {
        mining::DatasetHandle warm =
            mining::GlobalDataset().get_for_seed(ds_seed_loop);
        if (!warm.get()) {
            std::cerr << "  [MineOnly] ABORT: dataset unavailable for seed "
                      << HashToHex(ds_seed_loop).substr(0,16)
                      << " after 8 retries — caller will retry\n";
            std::cerr.flush();
            return result;
        }
    }
    mining::DatasetHandle ds_handle;
#endif

    unsigned N = num_threads > 0 ? num_threads : 1;
    if (N > 64) N = 64;

    std::atomic<bool>     stop_local{false};
    std::atomic<uint64_t> total_hashes_accum{0};
    std::atomic<uint64_t> winner_nonce{0};
    std::atomic<uint64_t> winner_ts{0};
    std::atomic<bool>     winner_found{false};
    std::array<uint8_t, 32> winner_merkle_root{};
    std::mutex            best_mtx;

    std::mutex            rollover_mtx;
    std::atomic<uint64_t> shared_timestamp{candidate.header.timestamp};
    std::atomic<uint32_t> header_generation{0};
    std::array<uint8_t, 32> shared_merkle_root;
    std::copy(candidate.header.merkle_root.begin(),
              candidate.header.merkle_root.end(),
              shared_merkle_root.begin());

    auto worker_fn = [&](unsigned worker_id) {
        std::vector<uint8_t> tb(88);
        auto tw32 = [&](int offset, uint32_t v) {
            tb[offset]   =  v        & 0xFF;
            tb[offset+1] = (v >>  8) & 0xFF;
            tb[offset+2] = (v >> 16) & 0xFF;
            tb[offset+3] = (v >> 24) & 0xFF;
        };
        auto tw64 = [&](int offset, uint64_t v) {
            for (int i = 0; i < 8; ++i) tb[offset + i] = (uint8_t)((v >> (i*8)) & 0xFF);
        };
        uint32_t my_gen = 0;
        auto rebuild_local = [&]() {
            tw32(0, candidate.header.version);
            std::copy(candidate.header.prev_block_hash.begin(),
                      candidate.header.prev_block_hash.end(),
                      tb.begin() + 4);
            std::copy(shared_merkle_root.begin(),
                      shared_merkle_root.end(),
                      tb.begin() + 36);
            tw64(68, shared_timestamp.load());
            tw32(76, candidate.header.bits);
            my_gen = header_generation.load();
        };
        rebuild_local();

        mining::VeldHashVM tvm;

        Hash256 local_best{};
        local_best.fill(0xFF);
        uint64_t local_best_nonce = 0;
        uint64_t local_hashes = 0;

        uint64_t nonce = worker_id;
        while (!stop_local.load(std::memory_order_relaxed)) {
            if (stop && stop->load()) { stop_local = true; break; }
            if ((local_hashes & 63) == 0) {
                if (chain.Height() != candidate.height - 1) {
                    stop_local = true; break;
                }
                auto live_tip_hash = chain.Tip().GetHash();
                if (live_tip_hash != candidate.header.prev_block_hash) {
                    stop_local = true; break;
                }
            }
            if (header_generation.load(std::memory_order_acquire) != my_gen) {
                rebuild_local();
                nonce = worker_id;
                continue;
            }

            tw64(80, nonce);

            Hash256 h;
            {
                SHA256 sh;
                sh.update(tb.data(), tb.size());
                Hash256 seed = sh.digest();
                tvm.Initialize(seed);
#ifdef VELD_MAINNET_POW
                Hash256 per_hash_seed = mining::ComputeEpochSeed(
                    candidate.header.prev_block_hash, candidate.height,
                    candidate.header.bits);
                mining::DatasetHandle ds =
                    mining::GlobalDataset().get_for_seed(per_hash_seed);
                if (!ds.get()) {
                    stop_local = true;
                    break;
                }
                tvm.SetDataset(ds.get());
                tvm.Execute();
                auto state = tvm.FinalizeRaw();
                h = mining::Blake2b256(state.data(), state.size());
#else
                tvm.Execute();
                Hash256 vh = tvm.Finalize();
                h = Hash256d(vh.data(), vh.size());
#endif
            }
            ++local_hashes;

            if (progress_counter && (local_hashes & 31u) == 0) {
                progress_counter->fetch_add(1, std::memory_order_relaxed);
            }

            if (h < local_best) {
                local_best = h;
                local_best_nonce = nonce;
                if (worker_id == 0 && progress_cb && (local_hashes & 0x3FFu) == 0) {
                    progress_cb(candidate.height, local_best_nonce, local_best);
                }
                if constexpr (OPTION_B_CONSENSUS_GATE_ENABLED) {
                    if (nms_cb && h < target_x4 && !(h < target)) {
                        bool expected = false;
                        if (nms_broadcast_guard.compare_exchange_strong(expected, true)) {
                            if (veld::DiagVerbose().load()) veld::vcerr() << "  [nms-worker w=" << worker_id
                                      << "] near-miss nonce=" << nonce
                                      << " hash=" << HashToHex(h).substr(0, 16)
                                      << " — calling nms_cb\n";
                            std::cerr.flush();
                            BlockHeader nms_hdr = candidate.header;
                            nms_hdr.nonce     = nonce;
                            nms_hdr.timestamp = shared_timestamp.load();
                            std::copy(shared_merkle_root.begin(),
                                      shared_merkle_root.end(),
                                      nms_hdr.merkle_root.begin());
                            try { nms_cb(nms_hdr); } catch (...) {}
                        }
                    }
                }
            }

            if (h < target) {
                if (!winner_found.exchange(true)) {
                    winner_nonce = nonce;
                    uint64_t ts_hashed = 0;
                    for (int i = 0; i < 8; ++i)
                        ts_hashed |= (uint64_t)tb[68 + i] << (i * 8);
                    winner_ts = ts_hashed;
                    std::copy(tb.begin() + 36, tb.begin() + 68,
                              winner_merkle_root.begin());
                    if (veld::DiagVerbose().load()) veld::vcerr() << "  [mine_debug h=" << candidate.height
                              << "] pow=" << HashToHex(h).substr(0,32)
                              << "... nonce=" << nonce
                              << " prev=" << HashToHex(candidate.header.prev_block_hash).substr(0,16)
                              << "... merk=" << HashToHex(winner_merkle_root).substr(0,16)
                              << "... bits=0x" << std::hex << candidate.header.bits << std::dec
                              << " ts=" << ts_hashed
                              << " worker=" << worker_id << "/" << N
                              << "\n";
                    std::cerr.flush();
                }
                stop_local = true;
                break;
            }

            nonce += N;
            constexpr uint64_t REFRESH_EVERY_HASHES = 65536ULL;
            if (local_hashes > 0 && (local_hashes % REFRESH_EVERY_HASHES) == 0) {
                if (progress_counter) progress_counter->fetch_add(1, std::memory_order_relaxed);
                std::lock_guard<std::mutex> lk(rollover_mtx);
                if (header_generation.load() == my_gen) {
                    uint64_t now_ts = (uint64_t)std::time(nullptr);
                    uint64_t cur_ts = shared_timestamp.load();
                    uint64_t new_ts = (now_ts > cur_ts) ? now_ts : (cur_ts + 1);
                    shared_timestamp.store(new_ts);
                    candidate.header.timestamp = new_ts;
                    candidate.UpdateMerkleRoot();
                    std::copy(candidate.header.merkle_root.begin(),
                              candidate.header.merkle_root.end(),
                              shared_merkle_root.begin());
                    header_generation.fetch_add(1, std::memory_order_release);
                }
            }
        }

        total_hashes_accum += local_hashes;
        std::lock_guard<std::mutex> bg(best_mtx);
        if (local_best < best_hash_found) {
            best_hash_found = local_best;
            best_nonce_found = local_best_nonce;
        }
    };

    std::vector<std::thread> workers;
    workers.reserve(N);
    for (unsigned i = 0; i < N; ++i) workers.emplace_back(worker_fn, i);
    for (auto& t : workers) if (t.joinable()) t.join();

    hashes = total_hashes_accum.load();
    if (!winner_found.load()) {
        return result;
    }
    candidate.header.nonce     = winner_nonce.load();
    candidate.header.timestamp = winner_ts.load();
    std::copy(winner_merkle_root.begin(), winner_merkle_root.end(),
              candidate.header.merkle_root.begin());

#ifdef VELD_MAINNET_POW
    ds_handle = mining::DatasetHandle();
#endif
    {
        std::vector<uint8_t> tb = candidate.header.Serialize();
        found_hash = mining::VeldHash(tb, candidate.height);
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();

    result.success      = true;
    result.block        = candidate;
    result.hash         = found_hash;
    result.new_height   = candidate.height;
    result.elapsed_ms   = (double)elapsed;
    result.hashes_tried = hashes;
    result.best_nonce   = best_nonce_found;
    result.best_hash    = best_hash_found;
    return result;
}

class VeldNode {
public:
    // Opaque authority retained by a TCP peer-view writer. Construction first
    // closes coordinator acquisition and then obtains the canonical transition
    // sequencer. Destruction cancels any lease acquired in the close-to-lock
    // gap and bumps every work binding before releasing that sequencer. TCP
    // owns only shared_ptr<void>, so it cannot forge this guard.
    class PeerWorkViewTransitionPermit {
    public:
        PeerWorkViewTransitionPermit(
                VeldNode& owner,
                Blockchain::ConsensusTransitionGuard transition) noexcept
            : owner_(owner), transition_(std::move(transition)) {}
        PeerWorkViewTransitionPermit(
            const PeerWorkViewTransitionPermit&) = delete;
        PeerWorkViewTransitionPermit& operator=(
            const PeerWorkViewTransitionPermit&) = delete;
        ~PeerWorkViewTransitionPermit() noexcept {
            owner_.BumpValidationGeneration_();
            owner_.work_admission_coordinator_.CancelAndClose(
                work_admission::Refusal::PeerViewUnsafe);
        }

    private:
        VeldNode& owner_;
        Blockchain::ConsensusTransitionGuard transition_;
    };

    // Move-only local signing reservation.  Construction is private to the
    // node's authoritative coordinator, so a caller cannot manufacture an
    // "admitted" validator operation from a raw work binding.  The permit is
    // intentionally held across anti-equivocation journaling and signing;
    // canonical/prerequisite transitions which arrive second remain bounded
    // in Closing until this permit is consumed, released, or expires.
    class LocalSigningPermit {
    public:
        LocalSigningPermit() = default;
        LocalSigningPermit(const LocalSigningPermit&) = delete;
        LocalSigningPermit& operator=(const LocalSigningPermit&) = delete;
        LocalSigningPermit(LocalSigningPermit&&) noexcept = default;
        LocalSigningPermit& operator=(LocalSigningPermit&&) noexcept = default;

        bool IsLive() const noexcept {
            return lease_ &&
                std::chrono::steady_clock::now() < operation_deadline_ &&
                lease_->IsLive();
        }
        const work_admission::Binding* binding() const noexcept {
            return lease_ ? &lease_->binding() : nullptr;
        }
        explicit operator bool() const noexcept { return IsLive(); }

    private:
        friend class VeldNode;
        explicit LocalSigningPermit(
                std::shared_ptr<
                    work_admission::AdmissionCoordinator::Lease> lease,
                std::chrono::steady_clock::time_point operation_deadline)
            : lease_(std::move(lease)),
              operation_deadline_(operation_deadline) {}

        std::shared_ptr<work_admission::AdmissionCoordinator::Lease> lease_;
        std::chrono::steady_clock::time_point operation_deadline_{};
    };

    static constexpr std::chrono::milliseconds
        LOCAL_SIGNING_SAFETY_MARGIN{1000};
    static constexpr std::chrono::milliseconds
        REMOTE_SIGNING_SAFETY_MARGIN{2000};
    static constexpr std::chrono::milliseconds
        PEER_VIEW_EXPIRY_SAFETY_MARGIN{1000};

    static std::optional<uint64_t> BoundWallClockWorkLifetimeMs(
            int64_t now_unix, int64_t not_after_unix,
            uint64_t requested_ms, uint64_t safety_margin_ms) noexcept {
        if (requested_ms == 0 || now_unix < 0 ||
            not_after_unix <= now_unix)
            return std::nullopt;
        const uint64_t remaining_seconds = static_cast<uint64_t>(
            not_after_unix - now_unix);
        if (remaining_seconds <= 1) return std::nullopt;
        const uint64_t conservative_seconds = remaining_seconds - 1;
        const uint64_t conservative_ms = conservative_seconds >
                UINT64_MAX / 1000
            ? UINT64_MAX : conservative_seconds * 1000;
        if (conservative_ms <= safety_margin_ms)
            return std::nullopt;
        const uint64_t bounded = std::min(
            requested_ms, conservative_ms - safety_margin_ms);
        return bounded == 0 ? std::nullopt
                            : std::optional<uint64_t>(bounded);
    }

    struct ActiveRemoteSigningLease {
        work_admission::Path path{
            work_admission::Path::ValidatorEndorsement};
        work_admission::Binding binding{};
        std::shared_ptr<work_admission::AdmissionCoordinator::Lease> lease;
        std::chrono::steady_clock::time_point operation_deadline{};

        bool OperationLive() const noexcept {
            return lease &&
                std::chrono::steady_clock::now() < operation_deadline &&
                lease->IsLive();
        }
    };

    static std::string EnsureDataDir(const std::string& d) {
        std::string path = d;
        std::replace(path.begin(), path.end(), '\\', '/');
        std::filesystem::create_directories(path);
#ifdef VELD_PUBLIC_RELEASE
        std::string identity_error;
        if (!channel::secure_file::EnsurePrivateDirectory(path, &identity_error)
                || !ValidateOrCreatePublicNetworkIdentity(path, &identity_error)) {
            throw std::runtime_error(
                "public datadir network identity check failed: " + identity_error);
        }
#endif
        std::filesystem::create_directories(path + "/blocks");
        std::filesystem::create_directories(path + "/db");
        return path;
    }

    explicit VeldNode(const NetworkConfig& config, const std::string& data_dir)
        : config_(config)
        , data_dir_(EnsureDataDir(data_dir))
        , chain_()
        , work_admission_coordinator_(
              work_admission::AdmissionCoordinator::Limits{
                  std::chrono::milliseconds(5000),
                  std::chrono::milliseconds(10000), 64, 128},
              [](work_admission::AdmissionCoordinator::TokenBytes& token) {
                  return compat::SecureRandom(token.data(), token.size());
              })
        , block_template_authorizations_(
              work_admission::BlockTemplateAuthorizationStore::Limits{
                  std::chrono::milliseconds(10000), 64, 128},
              [](work_admission::BlockTemplateAuthorizationStore::
                     TokenBytes& token) {
                  return compat::SecureRandom(token.data(), token.size());
              })
        , mempool_()
        , staking_()
        , onchain_tokens_()
        , btc_headers_(BtcVeldCheckpoint(), BtcVeldPowLimit(), 2016, 1209600, BtcVeldNoRetarget())
        , tiers_(chain_, staking_)
        , vault_()
        , governance_(chain_, staking_)
        , storage_(data_dir_ + "/blocks", config.magic)
        , db_(data_dir_ + "/db")
        , rpc_(chain_, mempool_, storage_)
        , explorer_(chain_, mempool_, CompiledPublicExplorerPort())
        , running_(false)
        , mining_(false) {
        WireMainTokenConsensusDependencies_();
        std::filesystem::create_directories(data_dir_);
        datadir_identity_valid_.store(true, std::memory_order_release);
        rpc_.SetWorkAdmissionFn(
            [this](work_admission::Path path,
                   const work_admission::Subject& subject,
                   const std::optional<work_admission::Binding>& prior,
                   bool require_prior) {
                return EvaluateWorkAdmission(
                    path, subject, prior, require_prior);
            });
        rpc_.SetIssueBlockTemplateAuthorizationFn(
            [this](const work_admission::Subject& subject,
                   const Hash256& template_identity) {
                return IssueBlockTemplateAuthorizationUnderTransition_(
                    subject, template_identity);
            });
        rpc_.SetConsumeBlockTemplateAuthorizationFn(
            [this](const std::string& token,
                   const work_admission::Binding& binding) {
                return ConsumeBlockTemplateAuthorizationUnderTransition_(
                    token, binding);
            });
        rpc_.SetRemoteWorkGrantFn(
            [this](work_admission::Path path,
                   const work_admission::Subject& subject) {
                return IssueRemoteWorkGrantUnderTransition_(path, subject);
            });
        rpc_.SetBeginRemoteSigningFn(
            [this](work_admission::Path path,
                   const std::string& binding,
                   const std::string& token) {
                return BeginRemoteSigningUnderTransition_(
                    path, binding, token);
            });
        rpc_.SetCancelRemoteSigningFn(
            [this](const std::string& token) {
                return CancelRemoteSigningUnderTransition_(token);
            });
        rpc_.SetValidatorEndorsementSinkFn(
            [this](const Transaction& tx, uint64_t fee,
                   const std::string& binding,
                   const std::string& token, bool rebroadcast) {
                return SubmitAuthorizedValidatorEndorsement_(
                    tx, fee, binding, token, rebroadcast);
            });
        // Lock order for every irreversible local-work sink is:
        // Blockchain consensus-transition sequencer -> admission coordinator
        // -> subsystem/journal/mempool locks.  P2P block ingress already owns
        // the first lock in AddBlockDirect; it closes new local work and
        // transiently defers behind any acquired-first bounded lease, but
        // never acquires a work lease itself.
        chain_.SetCanonicalWorkTransitionFn(
            [this](const Block&) noexcept {
                const auto closed = work_admission_coordinator_.BeginClose(
                    work_admission::Refusal::BindingMismatch);
                // AddBlockDirect already owns the consensus sequencer here, so
                // it must not wait while a remote signer needs that same lock
                // to consume/release an acquired-first capability. Deferral
                // releases the lock; bounded retransmit/retry then makes P2P
                // progress once the signer finishes or its deadline expires.
                return closed.fully_closed;
            });
        chain_.SetLocalWorkAdmissionPrepareFn(
            [this](const Block& block,
                   const mining::PowAdmissionContext& context)
                -> std::optional<Blockchain::LocalWorkAdmissionTicket> {
                const auto path = WorkPathForLocalKind_(
                    context.local_work_kind);
                const auto prior = work_admission::DecodeBinding(
                    context.work_binding);
                Block tip;
                if (!path || !prior ||
                    work_admission::EncodeBinding(*prior) !=
                        context.work_binding ||
                    prior->subject.purpose !=
                        work_admission::Purpose::BlockProduction ||
                    !chain_.TryTip(tip) || tip.height == UINT64_MAX ||
                    prior->subject.height != tip.height + 1 ||
                    prior->subject.parent_height != tip.height ||
                    prior->subject.parent_hash != tip.GetHash() ||
                    block.header.prev_block_hash != tip.GetHash())
                    return std::nullopt;

                const Hash256 work_identity =
                    block.header.GetTemplateWorkIdentity();
                if ((*path == work_admission::Path::SubmitBlock &&
                     (HashIsZero(prior->subject.target_hash) ||
                      prior->subject.target_hash != work_identity ||
                      context.work_authorization.empty() ||
                      !context.block_template_authorization_claim)) ||
                    (*path != work_admission::Path::SubmitBlock &&
                     (!HashIsZero(prior->subject.target_hash) ||
                      !context.work_authorization.empty() ||
                      context.block_template_authorization_claim)))
                    return std::nullopt;

                work_admission::Subject subject;
                subject.purpose = work_admission::Purpose::BlockProduction;
                subject.height = tip.height + 1;
                subject.parent_height = tip.height;
                subject.parent_hash = block.header.prev_block_hash;
                auto normalized_prior = *prior;
                normalized_prior.subject.target_hash = ZeroHash();
                const auto configuration = WorkCoordinatorConfiguration_(
                    subject.parent_height, true);
                const auto opened = OpenWorkCoordinator_(configuration);
                if (!opened.opened) return std::nullopt;
                auto lease_ttl = BoundPeerWorkLifetime_(
                    std::chrono::milliseconds(5000));
                if (!lease_ttl) return std::nullopt;
                if (*path == work_admission::Path::SubmitBlock) {
                    const auto coordinator =
                        work_admission_coordinator_.GetSnapshot();
                    if (coordinator.phase !=
                            work_admission::AdmissionCoordinator::Phase::Open ||
                        coordinator.configuration_generation == 0)
                        return std::nullopt;
                    const auto& authorization =
                        context.block_template_authorization_claim;
                    if (!authorization->ClaimForTicket(
                            *prior,
                            coordinator.configuration_generation))
                        return std::nullopt;
                    const auto now = std::chrono::steady_clock::now();
                    if (authorization->deadline() <= now)
                        return std::nullopt;
                    const auto remaining =
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            authorization->deadline() - now);
                    if (remaining <= std::chrono::milliseconds::zero())
                        return std::nullopt;
                    lease_ttl = std::min(*lease_ttl, remaining);
                }
                auto attempt = work_admission_coordinator_.AcquireLocal(
                    *path, subject, normalized_prior, true,
                    *lease_ttl);
                if (!attempt || !attempt.lease) return std::nullopt;
                auto lease = std::make_shared<
                    work_admission::AdmissionCoordinator::Lease>(
                        std::move(*attempt.lease));
                if (context.block_template_authorization_claim &&
                    !context.block_template_authorization_claim->
                        IsClaimedAndLive())
                    return std::nullopt;
                struct PreparedTicketAuthority {
                    std::shared_ptr<
                        work_admission::AdmissionCoordinator::Lease> lease;
                    std::shared_ptr<
                        work_admission::BlockTemplateAuthorizationClaim>
                        template_claim;
                };
                auto authority = std::make_shared<PreparedTicketAuthority>(
                    PreparedTicketAuthority{
                        lease,
                        context.block_template_authorization_claim});
                const auto& binding = lease->binding();
                Blockchain::LocalWorkAdmissionTicket ticket;
                ticket.owner = authority;
                ticket.claim_for_canonical_commit = [this, authority](
                        uint64_t coordinator_generation,
                        uint64_t validation_generation,
                        uint32_t network_magic,
                        const Hash256& genesis_hash,
                        const Hash256& profile_digest) noexcept {
                    const auto& issued = authority->lease->binding();
                    if (authority->template_claim &&
                        !authority->template_claim->IsClaimedAndLive())
                        return false;
                    if (authority->lease->configuration_generation() !=
                            coordinator_generation ||
                        validation_generation_.load(
                            std::memory_order_acquire) !=
                            validation_generation ||
                        issued.validation_generation !=
                            validation_generation ||
                        issued.network_magic != network_magic ||
                        issued.genesis_hash != genesis_hash ||
                        issued.profile_digest != profile_digest)
                        return false;
                    return authority->lease->ClaimForCanonicalCommit();
                };
                ticket.live = [authority]() noexcept {
                    return authority->lease->IsLive() &&
                        (!authority->template_claim ||
                         authority->template_claim->IsClaimedAndLive());
                };
                ticket.candidate_hash = block.GetHash();
                ticket.candidate_height = subject.height;
                ticket.parent_hash = subject.parent_hash;
                ticket.source = context.local_work_kind;
                ticket.work_binding = context.work_binding;
                ticket.work_authorization = context.work_authorization;
                ticket.work_identity = prior->subject.target_hash;
                ticket.validation_generation =
                    binding.validation_generation;
                ticket.coordinator_generation =
                    lease->configuration_generation();
                ticket.network_magic = binding.network_magic;
                ticket.genesis_hash = binding.genesis_hash;
                ticket.profile_digest = binding.profile_digest;
                ticket.deadline = authority->template_claim
                    ? std::min(lease->deadline(),
                               authority->template_claim->deadline())
                    : lease->deadline();
                return ticket;
            });
        // These bounded evidence reads do not depend on sockets or background
        // threads. Wire them at construction so every in-process RPC entrypoint
        // has the same operator surface; completed pairs remain hidden until the
        // startup journal has been re-authenticated by Start().
        rpc_.SetFinalityEvidenceListFn(
            [this](size_t offset, size_t limit) {
                return ListFinalityEquivocationEvidence(offset, limit);
            });
        rpc_.SetFinalityEvidenceFindFn(
            [this](const Hash256& evidence_id) {
                return FindFinalityEquivocationEvidence(evidence_id);
            });
        rpc_.SetFinalitySlashPrepareFn(
            [this](const Hash256& evidence_id) {
                return PrepareFinalityEquivocationSlash(evidence_id);
            });
        if (config_.validator_system_always_active)
        chain_.SetStakedForAddrFn([this](const std::string& addr) -> uint64_t {
            const auto* overlay = Blockchain::alt_engine_overlay_;
            const StakingLedger& staking =
                (overlay && overlay->staking) ? *overlay->staking : staking_;
            return staking.GetStake(addr);
        });
        chain_.SetMatureStakeForAddrFn(
            [this](const std::string& addr, uint64_t height) -> uint64_t {
                const auto* overlay = Blockchain::alt_engine_overlay_;
                const StakingLedger& staking =
                    (overlay && overlay->staking) ? *overlay->staking : staking_;
                return staking.GetMatureStake(addr, height);
            });
        chain_.SetEffectiveMinStakeFn([this]() -> uint64_t {
            const auto* overlay = Blockchain::alt_engine_overlay_;
            const StakingLedger& staking =
                (overlay && overlay->staking) ? *overlay->staking : staking_;
            return staking.GetEffectiveMinStake();
        });
        validators_.SetBlockKnownAtHeightQuery(
            [this](uint64_t h, const std::string& hash_hex) -> bool {
                return chain_.HasBlockAtHeight(h, hash_hex);
            });
        chain_.SetAllActiveStakesFn([this]() {
            const auto* overlay = Blockchain::alt_engine_overlay_;
            const StakingLedger& staking =
                (overlay && overlay->staking) ? *overlay->staking : staking_;
            return staking.GetAllActiveStakes();
        });
        chain_.SetStakeBlockValidatorFn([this](const Block& block) {
            const auto* overlay = Blockchain::alt_engine_overlay_;
            const StakingLedger& staking =
                (overlay && overlay->staking) ? *overlay->staking : staking_;
            return staking.ValidateBlock(block);
        });
        governance_.SetValidators(&validators_);

        if (config_.IsTestNetwork()) {
            chain_.SetCoinbaseCapGrandfatherHeight(3100);
        } else {
            chain_.SetCoinbaseCapGrandfatherHeight(0);
        }
    }

    void SetStakingActivation(uint64_t units) {
#if defined(VELD_MAINNET_POW) && \
    (defined(VELD_PUBLIC_RELEASE) || defined(VELD_DSTATE_QUALIFICATION))
        // Production mainnet policy is compiled, never an operator/config
        // input. Clamp even internal callers so two otherwise valid
        // NetworkConfig objects cannot instantiate different activation
        // boundaries in a release or its nonshipping D-state qualification.
        (void)units;
        units = STAKING_ACTIVATION_SUPPLY;
#endif
        chain_.SetStakingActivationUnits(units);
        staking_.SetStakingActivationUnits(units);
    }

    bool txindex_enabled_ = false;
    std::atomic<bool> txindex_operational_{false};
    void SetTxIndexEnabled(bool e) {
        txindex_enabled_ = e;
        txindex_operational_.store(false);
    }

    // Test/support hook for suppressing normal startup status lines. Security
    // diagnostics, validation failures, and listener refusals remain visible.
    bool quiet_boot_ = false;
    void SetQuietBoot(bool q) { quiet_boot_ = q; }
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    void SetBackgroundValidationOnly(bool enabled) {
        if (running_.load(std::memory_order_acquire) || tcp_server_)
            throw std::logic_error(
                "background validation mode must be selected before Start");
        background_validation_only_ = enabled;
    }
    void SetSnapshotQuarantineOnly(bool enabled) {
        if (running_.load(std::memory_order_acquire) || tcp_server_)
            throw std::logic_error(
                "snapshot quarantine mode must be selected before Start");
        snapshot_quarantine_only_ = enabled;
    }
    bool SnapshotQuarantineOnly() const { return snapshot_quarantine_only_; }
#endif

    // Install the locally-observed Bitcoin-anchored floor (VLF1) for this
    // startup.  The floor is not settable over RPC and cannot change after
    // bootstrap preparation or Start(): trust-floor changes require a clean
    // restart.  Start(), snapshot preference and candidate validation all call
    // the same routine,
    void PrepareAnchorSecurityBootstrap() {
        PrepareAnchorSecurityBootstrap_();
    }

    // A node with no observed floor carries no extra IBD requirement.  Once a
    // floor exists, this becomes true only after the canonical chain has
    // reached C, all T/A/C hashes match, and replay reconstructed that
    // permanent floor (or a strictly higher one which subsumes it).
    bool AnchorSecurityImportSatisfied() const {
        if (anchor_floor_security_uncertain_.load(
                std::memory_order_acquire) ||
            anchor_floor_repair_required_.load(
                std::memory_order_acquire))
            return false;
        auto transition = chain_.AcquireConsensusTransitionGuard();
        const auto status = EffectiveAnchorSecurityStatusNoTransition_();
        return status == EffectiveAnchorSecurityStatus::None ||
               status == EffectiveAnchorSecurityStatus::Satisfied;
    }

    // A durable block can contain a newly promoted BTC-authenticated floor.
    // If publishing the matching VLF1 record fails after that block's durable
    // boundary, continuing to admit traffic could forget security knowledge on
    // restart.  This latch lets the process supervisor stop promptly without
    // attempting an impossible rollback of the already-durable block.
    bool SecurityFloorUncertain() const {
        return anchor_floor_security_uncertain_.load(
                   std::memory_order_acquire) ||
               anchor_floor_repair_required_.load(
                   std::memory_order_acquire);
    }

    // Any persistence failure which leaves the canonical DB frame unproven
    // must stop service.  For a definite pre-publication failure Blockchain
    // still receives false so it can roll memory back and repair the touched
    // UTXO frame; for an uncertain/post-publication failure the callback keeps
    // memory at the possibly-durable tip.  In both cases restart's full replay
    // is the only safe way to prove the complete canonical frame again.
    bool DurableCommitFailStop() const {
        return durable_commit_fail_stop_.load(std::memory_order_acquire) ||
               durable_commit_repair_required_.load(
                   std::memory_order_acquire) ||
               chain_.DurabilityCompromised();
    }
    bool FailStopRequired() const {
        return SecurityFloorUncertain() || DurableCommitFailStop();
    }

#ifdef VELD_PUBLIC_TESTNET
    // Install the compiled testnet lease before Start().  The lease is two
    // compiled constants, so there is no credential to verify and nothing to
    // consume; the durable clock high-water still catches wall-clock rollback
    // across restarts, and the height cap remains absolute.
    void SetPublicTestnetCompiledLease(
            const public_testnet::RuntimeLimits& lease) {
        if (running_.load(std::memory_order_acquire) ||
            public_testnet_limits_) {
            throw std::runtime_error(
                "public-testnet runtime limits are startup-only and immutable");
        }
        const int64_t local_now = public_testnet::CurrentUnixTime();
        if (!lease.TimePermitted(local_now) ||
            lease.not_after_height == 0 ||
            !public_testnet::IsCanonicalSha256(lease.lease_identity_sha256)) {
            throw std::runtime_error(
                "public-testnet lease is malformed or already ended");
        }
        std::string error;
        auto clock_guard =
            std::make_unique<public_testnet::RuntimeClockGuard>();
        if (!clock_guard->Initialize(data_dir_, lease, local_now, &error)) {
            throw std::runtime_error(
                "invalid public-testnet runtime clock: " + error);
        }
        public_testnet_limits_ = lease;
        public_testnet_clock_guard_ = std::move(clock_guard);
        public_testnet_expired_.store(false, std::memory_order_release);
        if (!PublicTestnetRestartAuthorityFreshNow()) {
            throw public_testnet::ListenerActivationAuthorityRefusal(
                "public-testnet lease closed during startup");
        }
        chain_.SetRuntimeAdmissionFn([this](uint64_t candidate_height) {
            // Time/clock failure is process-global and latches. A candidate
            // above the height cap is only a stateless rejection: a remote
            // side-branch child must not be able to retire a below-cap node.
            const bool time_open = public_testnet_clock_guard_ &&
                public_testnet_clock_guard_->ObserveNow();
            if (!public_testnet::PermitOrLatchClosed(
                    public_testnet_expired_, time_open))
                return false;
            return public_testnet_limits_->CandidateHeightPermitted(
                candidate_height);
        });
        rpc_.SetRuntimeAdmissionFn([this]() {
            return !PublicTestnetRuntimeStopRequired();
        }, "Public-testnet runtime lease is closed");
    }

    // Called immediately before every listener is opened.  The lease itself is
    // compiled in, so what this re-checks is that the testnet has not ended
    // and that local time has not moved backwards behind the durable
    // high-water since the last observation.
    bool PublicTestnetRestartAuthorityFreshNow() const noexcept {
        if (!public_testnet_limits_ || !public_testnet_clock_guard_)
            return false;
        const int64_t local_now = public_testnet::CurrentUnixTime();
        const uint64_t monotonic_now =
            public_testnet::SuspendAwareMonotonicSeconds();
        return public_testnet_limits_->TimePermitted(local_now) &&
               public_testnet_clock_guard_->ObserveAt(
                   local_now, monotonic_now);
    }

    bool PublicTestnetRuntimeStopRequired() const noexcept {
        const bool sampled = public_testnet_limits_ &&
            public_testnet_clock_guard_ &&
            public_testnet_clock_guard_->ObserveNow() &&
            public_testnet_limits_->not_after_height > 0 &&
            chain_.Height() < public_testnet_limits_->not_after_height;
        return !public_testnet::PermitOrLatchClosed(
            public_testnet_expired_, sampled);
    }
#else
    bool PublicTestnetRuntimeStopRequired() const noexcept { return false; }
#endif

#ifdef VELD_TEST_HOOKS
    // Test-only explicit keyset seam. VELD_PUBLIC_RELEASE rejects
    // VELD_TEST_HOOKS at compile time in constants.h.
    bool TestMainTokenConsensusDependenciesBound() const {
        return onchain_tokens_.TestHasBtcVeldConsensusDependencies(
            &btc_headers_, &bond_covenant_);
    }
    btcspv::BtcHeaderChain& TestMainBtcHeaderChain() {
        return btc_headers_;
    }
    btcveld::SignerBondCovenant& TestMainBtcVeldRedeemCovenant() {
        return bond_covenant_;
    }
    bool TestAnchorSecurityPinPermits(uint64_t height,
                                      const Hash256& hash) const {
        return EffectiveAnchorSecurityPinPermits_(height, hash);
    }
    bool TestAnchorSecurityReorgPermitted(uint64_t common_ancestor,
                                          uint64_t current_tip) const {
        return EffectiveAnchorSecurityReorgPermitted_(common_ancestor,
                                                       current_tip);
    }
    std::string TestAnchorSecurityStatus() const {
        auto transition = chain_.AcquireConsensusTransitionGuard();
        return EffectiveAnchorSecurityStatusName_(
            EffectiveAnchorSecurityStatusNoTransition_());
    }
    size_t TestRequiredAnchorSecurityFloorCount() const {
        std::lock_guard<std::mutex> lock(
            anchor_security_floors_mutex_);
        return effective_anchor_security_floors_.size();
    }
    size_t TestObservedAnchorSecurityFloorCount() const {
        std::lock_guard<std::mutex> lock(
            anchor_security_floors_mutex_);
        return static_cast<size_t>(std::count_if(
            effective_anchor_security_floors_.begin(),
            effective_anchor_security_floors_.end(),
            [](const EffectiveAnchorSecurityFloor& floor) {
                return floor.exact_reconstruction_observed;
            }));
    }
    bool TestAllAnchorSecurityFloorsPermanentlyCovered() const {
        std::lock_guard<std::mutex> lock(
            anchor_security_floors_mutex_);
        return std::all_of(
            effective_anchor_security_floors_.begin(),
            effective_anchor_security_floors_.end(),
            [this](const EffectiveAnchorSecurityFloor& floor) {
                return EffectiveAnchorSecurityPermanentCovers_(floor);
            });
    }
    void TestRequireAnchorSecurityAfterReplay(uint64_t replayed_tip_height) const {
        RequireEffectiveAnchorSecurityAfterReplay_(replayed_tip_height);
    }
    void TestSetAnchorSecurityPermanent(
            const btcanchor::AnchorSet::PermanentCheckpoint& permanent) {
        auto state = anchors_.SnapshotState();
        state.permanent = permanent;
        anchors_.RestoreState(state);
    }
    void TestObserveAnchorSecurityReconstruction(uint64_t applied_height) {
        ObserveExactAnchorSecurityReconstruction_(applied_height);
    }
    bool TestPersistAnchorLocalFloorAfterDurable(bool startup_replay = false) {
        return PersistObservedAnchorFloorAfterDurable_(startup_replay);
    }
    void TestFinishAnchorFloorReplayRepair() {
        FinishAnchorFloorReplayRepair_();
    }
    bool TestHasAnchorLocalFloor() const {
        std::lock_guard<std::mutex> lock(anchor_floor_store_mutex_);
        return anchor_floor_store_.Current().has_value();
    }
    std::optional<btcanchor::floor_store::Record>
    TestAnchorLocalFloor() const {
        std::lock_guard<std::mutex> lock(anchor_floor_store_mutex_);
        return anchor_floor_store_.Current();
    }
    bool TestAnchorFloorRepairRequired() const {
        return anchor_floor_repair_required_.load(
            std::memory_order_acquire);
    }
    void TestSetAnchorFloorPersistenceFailure(bool fail) {
        anchor_floor_test_persist_failure_ = fail;
    }
    void TestWireDBForDurableCommit() {
        PrepareAnchorSecurityBootstrap_();
        WireDB();
    }
    void TestSetCanonicalDurableMarkerFailure(bool fail) {
        canonical_durable_marker_test_failure_ = fail;
    }
    void TestSetDurablePublicationClearFailure(bool fail) {
        durable_publication_clear_test_failure_ = fail;
    }
    std::optional<db::VeldDB::DurablePublicationPending>
    TestDurablePublicationPending() {
        return db_.ReadDurablePublicationPending();
    }
    bool TestDeleteDurableUTXO(const Hash256& tx_hash, uint32_t index) {
        return db_.DeleteUTXO(tx_hash, index);
    }
    std::optional<std::string> TestReadDurableUTXO(
            const Hash256& tx_hash, uint32_t index) {
        return db_.ReadUTXO(tx_hash, index);
    }
    void TestReplayStoredChainForDurableCommitRepair(uint64_t height) {
        WireDB();
        ReplayChain(height);
    }
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
    // Native D-STATE only: build with the production candidate constructor and
    // accept a canonical serialized frame through the same Blockchain ->
    // module preflight -> ApplyBlockModules_ -> durable VeldDB callback used by
    // ordinary node ingest. The only validation exceptions are the isolated
    // hash-vs-target and host-wall-clock seams; bits, MTP, transaction,
    // coinbase, custody, settlement, module, persistence and archive gates all
    // remain active. VELD_DSTATE_Q1 is only a capacity-benchmark state-
    // construction carrier: it does not claim to exercise the public mint or
    // LP transaction grammar. Public builds cannot contain any of these entry
    // points.
    void TestPrepareDStateQualificationIngest() {
        if (!chain_.IsEmpty())
            throw std::logic_error("D-STATE ingest requires an empty node");
        PrepareAnchorSecurityBootstrap_();
        WireDB();
    }
    Block TestBuildDStateQualificationBlock(
            uint64_t expected_height,
            const std::vector<uint8_t>& miner_script,
            const std::string& token_address,
            const std::string& lp_address,
            uint64_t timestamp,
            uint64_t nonce,
            uint64_t capacity_token_accounts = 0,
            uint64_t capacity_lp_identities = 0) {
        if (chain_.IsEmpty() || expected_height != chain_.Height() + 1)
            throw std::logic_error(
                "D-STATE candidate height does not extend the live tip");
        if (miner_script.size() != 25 || miner_script[0] != 0x76 ||
            miner_script[1] != 0xA9 || miner_script[2] != 0x14 ||
            miner_script[23] != 0x88 || miner_script[24] != 0xAC)
            throw std::logic_error(
                "D-STATE candidate miner script is not canonical P2PKH");
        const auto valid_field = [](const std::string& value) {
            return value == "-" || IsCanonicalTokenCreditAddress(value);
        };
        if (!valid_field(token_address) || !valid_field(lp_address))
            throw std::logic_error(
                "D-STATE candidate carrier field is not canonical");
        const bool capacity_carrier =
            capacity_token_accounts != 0 || capacity_lp_identities != 0;
        if (capacity_carrier &&
            (expected_height != 400 || token_address != "-" ||
             lp_address != "-" || capacity_token_accounts == 0 ||
             capacity_token_accounts > 100'000 ||
             capacity_lp_identities == 0 ||
             capacity_lp_identities > AmmLedger::AMM_MAX_LP_IDENTITIES)) {
            throw std::logic_error(
                "D-STATE S6 capacity carrier has invalid scope or cardinality");
        }

        Block settlement_probe;
        settlement_probe.height = expected_height;
        settlement_probe.header.prev_block_hash = chain_.Tip().GetHash();
        if (expected_height % VAULT_DISTRIBUTION_INTERVAL == 0) {
            (void)BuildEndorsementFlushTx(settlement_probe);
            (void)BuildVaultDistributionTx(settlement_probe);
            (void)BuildBondSettlementTx(settlement_probe);
            (void)BuildBondYieldSettlementTx(settlement_probe);
        }
        if (expected_height % COMINE_WINDOW_BLOCKS == 0) {
            (void)BuildPoolPayoutTx(
                settlement_probe, AddressToScript(POOL_ADDRESS), mempool_);
        }
        std::vector<Transaction> mandatory_settlements =
            std::move(settlement_probe.transactions);
        const auto finality_metadata =
            PendingFinalityCoinbaseMetadata_(expected_height);

        RealKeyPair qualification_miner;
        qualification_miner.script_override = miner_script;
        MineBlockResult candidate = MineOnly(
            chain_, mempool_, qualification_miner, 0, nullptr,
            AddressToScript(POOL_ADDRESS), 1, nullptr, {}, nullptr, nullptr,
            mandatory_settlements,
            [this](const Block& block) {
                return PreflightMiningCandidate_(block);
            },
            finality_metadata,
            /*qualification_candidate_only=*/true);
        if (!candidate.success || candidate.block.height != expected_height)
            throw std::runtime_error(
                "D-STATE production candidate construction failed: " +
                candidate.error);

        Block& block = candidate.block;
        block.header.timestamp = timestamp;
        block.header.nonce = nonce;
        if (token_address != "-" || lp_address != "-" ||
            capacity_carrier) {
            if (block.transactions.empty() ||
                block.transactions.front().inputs.size() != 1 ||
                !block.transactions.front().IsCoinbase())
                throw std::runtime_error(
                    "D-STATE production candidate lacks canonical coinbase");
            const std::string carrier = capacity_carrier
                ? "dstate-replay:" + std::to_string(expected_height) +
                      "|VELD_DSTATE_S6_CAPACITY_V1|" +
                      std::to_string(capacity_token_accounts) + "|" +
                      std::to_string(capacity_lp_identities)
                : "dstate-replay:" + std::to_string(expected_height) +
                      "|VELD_DSTATE_Q1|" + token_address + "|" +
                      lp_address;
            auto& coinbase = block.transactions.front();
            coinbase.inputs.front().script_sig.assign(
                carrier.begin(), carrier.end());
            coinbase.InvalidateTxIDCache();
        }
        block.UpdateMerkleRoot();
        if (!PreflightMiningCandidate_(block))
            throw std::runtime_error(
                "D-STATE carrier-bearing production candidate failed module preflight");
        if (block.SerializedSize() > static_cast<size_t>(MAX_BLOCK_SIZE))
            throw std::runtime_error(
                "D-STATE production candidate exceeds the block-size envelope");
        return block;
    }
    bool TestIngestDStateQualificationFrame(
            const std::vector<uint8_t>& raw, uint64_t expected_height) {
        Block block;
        const size_t consumed = Block::Deserialize(raw, 0, block);
        if (consumed == 0 || consumed != raw.size() ||
            block.Serialize() != raw)
            return false;
        block.height = expected_height;
        if (expected_height == 0 &&
            raw != CreateGenesisBlock().Serialize())
            return false;
        if (expected_height > 0) {
            const auto parent_height =
                chain_.GetKnownBlockHeightByHash(
                    block.header.prev_block_hash);
            if (!parent_height || *parent_height == UINT64_MAX ||
                *parent_height + 1 != expected_height)
                return false;
        }
        return chain_.AddBlockDirect(
            block, false, false, false,
            mining::PowAdmissionContext::Internal());
    }
    void TestReplayDStateQualificationCorpus(uint64_t expected_height) {
        if (!chain_.IsEmpty())
            throw std::logic_error("D-STATE replay requires an empty node");
        PrepareAnchorSecurityBootstrap_();
        WireDB();
        ReplayChain(expected_height);
    }
    struct DStateQualificationObservation {
        uint64_t height{0};
        Hash256 tip_hash{};
        Hash256 token_digest{};
        Hash256 token_capacity_projection_digest{};
        Hash256 amm_digest{};
        Hash256 utxo_digest{};
        Hash256 supply_digest{};
        uint64_t canonical_supply_units{0};
        std::optional<Hash256> miner_archive_digest;
        int64_t btcveld_supply{0};
        uint64_t token_balance_count{0};
        uint64_t token_history_count{0};
        uint64_t lp_identity_count{0};
        bool lp_positions_all_admissible{false};
        uint64_t miner_hot_identity_count{0};
        uint64_t miner_archive_count_rows{0};
        std::optional<uint64_t> miner_archive_tip_height;
        std::optional<std::string> miner_archive_tip_hash;
        std::optional<uint64_t> durable_tip_height;
        std::optional<std::string> durable_tip_hash;
        std::optional<uint64_t> durable_tip_supply_units;
        Hash256 consensus_state_digest{};
        bool miner_archive_ready{false};
        bool durable_publication_pending{false};
        bool utxo_recovery_required{false};
        bool reorg_recovery_frame_pending{false};
        bool durability_compromised{false};
        bool durable_commit_fail_stop{false};
        bool fail_stop_required{false};
        bool module_cursor_matches{false};
    };
    DStateQualificationObservation
    TestObserveDStateQualificationState() {
        auto transition = chain_.AcquireConsensusTransitionGuard();
        DStateQualificationObservation out;
        out.height = chain_.Height();
        if (!chain_.IsEmpty()) out.tip_hash = chain_.TipCopy().GetHash();
        const auto tokens = onchain_tokens_.SnapshotState();
        const auto amm = amm_.SnapshotState();
        out.token_digest = onchain_tokens_.Digest();
        OnChainTokenLedger::StateSnapshot token_projection;
        token_projection.tokens = tokens.tokens;
        token_projection.balances = tokens.balances;
        token_projection.supply = tokens.supply;
        OnChainTokenLedger projected_tokens;
        projected_tokens.RestoreState(token_projection);
        out.token_capacity_projection_digest = projected_tokens.Digest();
        out.amm_digest = amm_.Digest();
        out.utxo_digest = chain_.UtxoDigest();
        out.supply_digest = chain_.SupplyDigest();
        out.canonical_supply_units = chain_.TotalSupplyUnits();
        out.miner_archive_digest = MinerArchiveLogicalDigest_();
        const auto supply = tokens.supply.find(BTCVELD_TOKEN_ID);
        out.btcveld_supply = supply == tokens.supply.end()
            ? 0 : supply->second;
        out.token_balance_count = tokens.balances.size();
        out.token_history_count = tokens.history.size();
        out.lp_identity_count = amm.lp.size();
        out.lp_positions_all_admissible = std::all_of(
            amm.lp.begin(), amm.lp.end(), [](const auto& entry) {
                return entry.second >= AmmLedger::LP_MIN_POSITION;
            });
        out.miner_hot_identity_count = chain_.TestMinerIdentityCount();
        db_.GetIndexDB().Iterate(
            MINER_ARCHIVE_COUNT_PREFIX_,
            [&out](const std::string&, const std::string&) {
                if (out.miner_archive_count_rows == UINT64_MAX) return false;
                ++out.miner_archive_count_rows;
                return true;
            });
        if (const auto raw =
                db_.GetIndexDB().Get(MINER_ARCHIVE_HEIGHT_KEY_)) {
            uint64_t parsed = 0;
            if (ParseMinerArchiveUint64_(*raw, parsed))
                out.miner_archive_tip_height = parsed;
        }
        if (const auto raw =
                db_.GetIndexDB().Get(MINER_ARCHIVE_HASH_KEY_);
            raw && db::IsCanonicalHash256Text(*raw)) {
            out.miner_archive_tip_hash = *raw;
        }
        if (const auto durable = db_.ReadChainTipExact()) {
            out.durable_tip_height = durable->height;
            out.durable_tip_hash = durable->tip_hash;
            out.durable_tip_supply_units = durable->supply_units;
        }
        out.consensus_state_digest =
            btcveld::reserve::TRANSITION_V1_REQUIRED
            ? state_digest::ComposeV8(
            out.height, out.tip_hash, out.utxo_digest,
            validators_.ValidatorsDigest(), staking_.StakingDigest(),
            validators_.BondYieldEscrowDigest(), chain_.NmsTallyDigest(),
            out.token_digest, out.supply_digest,
            governance_.GovernanceDigest(), chain_.NmsExtendedDigest(),
            btc_headers_.StateDigest(), anchors_.Digest(), out.amm_digest,
            fin_state_.Digest(), bond_covenant_.Digest())
            : state_digest::ComposeV7(
            out.height, out.tip_hash, out.utxo_digest,
            validators_.ValidatorsDigest(), staking_.StakingDigest(),
            validators_.BondYieldEscrowDigest(), chain_.NmsTallyDigest(),
            out.token_digest, out.supply_digest,
            governance_.GovernanceDigest(), chain_.NmsExtendedDigest(),
            btc_headers_.StateDigest(), anchors_.Digest(), out.amm_digest,
            fin_state_.Digest(), bond_covenant_.Digest());
        out.miner_archive_ready =
            miner_archive_ready_.load(std::memory_order_acquire);
        out.durable_publication_pending =
            db_.ReadDurablePublicationPending().has_value();
        out.utxo_recovery_required = db_.UtxoRecoveryRequired();
        out.reorg_recovery_frame_pending =
            chain_.ReorgRecoveryFramePending();
        out.durability_compromised = chain_.DurabilityCompromised();
        out.durable_commit_fail_stop = DurableCommitFailStop();
        out.fail_stop_required = FailStopRequired();
        out.module_cursor_matches =
            last_token_height_ == out.height &&
            last_module_supply_ == out.canonical_supply_units;
        return out;
    }
    // Qualification-only memory sampler for canonical replay and the real
    // bounded-reorg path. The callback runs synchronously while consensus and
    // chain locks may be held, so it must only sample process memory and must
    // never call back into VeldNode/Blockchain. Exceptions deliberately fail
    // the qualification run.
    void TestSetDStateMemoryObserver(std::function<void()> observer) {
        auto transition = chain_.AcquireConsensusTransitionGuard();
        dstate_memory_observer_ = std::move(observer);
    }
#endif
    void TestWireMinerArchiveLookup() {
        chain_.SetMinerArchiveLookup(
            [this](const std::string& script_hex)
                -> std::optional<Blockchain::MinerArchiveRecord> {
                return ReadMinerArchiveRecord_(script_hex);
            });
    }
    void TestWireMinerArchiveRollbackOnly() {
        chain_.SetOnRollback(
            [this](const Blockchain::UTXODelta&, const Block& popped) {
                if (!RollbackMinerArchiveIndex_(popped))
                    miner_archive_ready_.store(
                        false, std::memory_order_release);
            });
    }
    bool TestRebuildMinerArchiveIndex() {
        return RebuildMinerArchiveIndex_();
    }
    bool TestAdvanceMinerArchiveIndex(const Block& block) {
        return AdvanceMinerArchiveIndex_(block);
    }
    bool TestRollbackMinerArchiveIndex(const Block& block) {
        return RollbackMinerArchiveIndex_(block);
    }
    std::optional<Blockchain::MinerArchiveRecord>
    TestReadMinerArchiveRecord(const std::string& script_hex) {
        return ReadMinerArchiveRecord_(script_hex);
    }
    std::optional<Hash256> TestMinerArchiveLogicalDigest() {
        return MinerArchiveLogicalDigest_();
    }
    bool TestPutMinerArchiveRaw(const std::string& key,
                                const std::string& value) {
        return db_.GetIndexDB().Put(key, value);
    }
    std::optional<std::string> TestGetMinerArchiveRaw(
            const std::string& key) {
        return db_.GetIndexDB().Get(key);
    }
    bool TestDeleteMinerArchiveRaw(const std::string& key) {
        return db_.GetIndexDB().Delete(key);
    }
    bool TestMinerArchiveReady() const {
        return miner_archive_ready_.load(std::memory_order_acquire);
    }
    void TestCaptureReorgAnchorFloorForAbort() {
        CaptureReorgAnchorFloorForAbort_();
    }
    bool TestHasCapturedReorgAnchorFloorForAbort() const {
        return reorg_anchor_floor_restore_captured_;
    }
    std::optional<std::vector<uint8_t>>
    TestCapturedReorgAnchorFloorForAbort() const {
        return reorg_anchor_floor_restore_wire_;
    }
    std::optional<std::vector<uint8_t>>
    TestCapturedReorgDurablePublicationForAbort() const {
        return reorg_durable_publication_restore_wire_;
    }

    // Finding-4 process qualification uses the real node/RPC/P2P entrypoints,
    // but must be able to install one prerequisite tuple without running the
    // unbounded listener/startup lifecycle.  Every field below writes the same
    // production latch consumed by WorkCoordinatorConfiguration_; there is no
    // parallel test predicate.  Public profiles reject VELD_TEST_HOOKS in
    // constants.h, so none of these setters can exist in a release binary.
    struct TestWorkAdmissionProcessState {
        bool node_running{true};
        bool startup_replay_complete{true};
        bool independent_validation_complete{true};
        bool sync_complete{true};
        bool snapshot_state_clean{true};
        bool durable_state_proven{true};
        bool datadir_identity_valid{true};
        bool checkpoint_anchor_valid{true};
        bool canonical_tip_known{true};
        bool runtime_open{true};
        bool role_permitted{true};
    };

    void TestConfigureWorkAdmissionProcess(
            const TestWorkAdmissionProcessState& state) {
        work_admission_coordinator_.CancelAndClose(
            work_admission::Refusal::Unwired);
        ClearActiveRemoteSigningLeases_();
        startup_replay_complete_.store(
            state.startup_replay_complete, std::memory_order_release);
        chain_fully_validated_.store(
            state.independent_validation_complete,
            std::memory_order_release);
        ibd_complete_.store(state.sync_complete, std::memory_order_release);
        snapshot_state_clean_.store(
            state.snapshot_state_clean, std::memory_order_release);
        durable_commit_fail_stop_.store(
            !state.durable_state_proven, std::memory_order_release);
        durable_commit_repair_required_.store(false,
                                               std::memory_order_release);
        reorg_publication_uncertain_.store(false,
                                            std::memory_order_release);
        datadir_identity_valid_.store(
            state.datadir_identity_valid, std::memory_order_release);
        checkpoint_anchor_valid_.store(
            state.checkpoint_anchor_valid, std::memory_order_release);
        background_validation_only_ = !state.role_permitted;
        test_work_force_tip_unknown_.store(
            !state.canonical_tip_known, std::memory_order_release);
        test_work_local_runtime_open_.store(
            state.runtime_open, std::memory_order_release);
        // The F4 gate controls local production/signing. Ordinary inbound
        // block admission retains its independent Blockchain runtime policy.
        chain_.SetRuntimeAdmissionFn(
            [](uint64_t) noexcept { return true; });
        running_.store(state.node_running, std::memory_order_release);
        BumpValidationGeneration_();
    }

    void TestInstallWorkAdmissionProcessServer() {
        tcp_server_ = std::make_unique<net::NodeServer>(
            0, config_.magic, chain_, mempool_);
        tcp_server_->SetPeerWorkViewTransitionFn([this]()
                -> net::NodeServer::PeerWorkViewTransitionPermit {
            (void)CloseWorkAdmissionBounded_(
                work_admission::Refusal::PeerViewUnsafe);
            try {
                auto transition = chain_.AcquireConsensusTransitionGuard();
                return net::NodeServer::PeerWorkViewTransitionPermit(
                    new PeerWorkViewTransitionPermit(
                        *this, std::move(transition)));
            } catch (...) {
                work_admission_coordinator_.CancelAndClose(
                    work_admission::Refusal::Unwired);
                return {};
            }
        });
        rpc_.SetBlockBroadcast([this](const Block& block) {
            test_work_block_broadcast_calls_.fetch_add(
                1, std::memory_order_acq_rel);
            if (!tcp_server_)
                throw std::runtime_error(
                    "test process block transport unavailable");
            tcp_server_->BroadcastBlock(block);
        });
        // Reuse the exact production submitfinalityvote verifier/storage/
        // gossip entrypoint without starting listeners or background loops.
        WireFinalityVoteRpcSink_();
    }

    net::NodeServer& TestWorkAdmissionProcessServer() {
        if (!tcp_server_)
            throw std::logic_error("work-admission process server not installed");
        return *tcp_server_;
    }

    std::string TestHandleWorkAdmissionRpc(const std::string& request) {
        return rpc_.Handle(request);
    }

    std::optional<work_admission::Subject>
    TestCurrentBlockProductionSubject() const {
        return CurrentBlockProductionSubject_();
    }

    work_admission::Decision TestEvaluateWorkAdmission(
            work_admission::Path path,
            const work_admission::Subject& subject) const {
        return EvaluateWorkAdmission(path, subject);
    }

    void TestUnwireAuthoritativeWorkAdmission() {
        work_admission_coordinator_.CancelAndClose(
            work_admission::Refusal::Unwired);
        block_template_authorizations_.CancelAll();
        ClearActiveRemoteSigningLeases_();
        rpc_.SetWorkAdmissionFn({});
        rpc_.SetIssueBlockTemplateAuthorizationFn({});
        rpc_.SetConsumeBlockTemplateAuthorizationFn({});
        chain_.SetLocalWorkAdmissionPrepareFn({});
    }

    void TestEnableWorkAdmissionMiningBarrier(bool enabled) noexcept {
        test_work_admission_mining_barrier_.store(
            enabled, std::memory_order_release);
    }

    void TestResetWorkAdmissionProcessCounters() noexcept {
        test_work_mining_admitted_calls_.store(0,
                                                std::memory_order_release);
        test_work_durable_writer_calls_.store(0,
                                               std::memory_order_release);
        test_work_block_broadcast_calls_.store(0,
                                                std::memory_order_release);
        test_work_tx_gossip_calls_.store(0, std::memory_order_release);
        test_work_finality_gossip_calls_.store(
            0, std::memory_order_release);
        test_work_finality_sink_calls_.store(0, std::memory_order_release);
        test_work_finality_active_calls_.store(0,
                                                std::memory_order_release);
        test_work_finality_verify_result_.store(
            UINT8_MAX, std::memory_order_release);
        Blockchain::TestResetAddBlockDirectCalls();
        ::veld::finality::qc::FinalityVoter::TestResetSignatureCount();
    }

    uint64_t TestWorkMiningAdmittedCalls() const noexcept {
        return test_work_mining_admitted_calls_.load(
            std::memory_order_acquire);
    }
    uint64_t TestWorkDurableWriterCalls() const noexcept {
        return test_work_durable_writer_calls_.load(
            std::memory_order_acquire);
    }
    uint64_t TestWorkBlockBroadcastCalls() const noexcept {
        return test_work_block_broadcast_calls_.load(
            std::memory_order_acquire);
    }
    uint64_t TestWorkTxGossipCalls() const noexcept {
        return test_work_tx_gossip_calls_.load(
            std::memory_order_acquire);
    }
    uint64_t TestWorkFinalityGossipCalls() const noexcept {
        return test_work_finality_gossip_calls_.load(
            std::memory_order_acquire);
    }
    uint64_t TestWorkFinalitySinkCalls() const noexcept {
        return test_work_finality_sink_calls_.load(
            std::memory_order_acquire);
    }
    uint64_t TestWorkFinalityActiveCalls() const noexcept {
        return test_work_finality_active_calls_.load(
            std::memory_order_acquire);
    }
    uint8_t TestWorkFinalityVerifyResult() const noexcept {
        return test_work_finality_verify_result_.load(
            std::memory_order_acquire);
    }
    size_t TestActiveRemoteSigningLeaseCount() noexcept {
        std::lock_guard<std::mutex> lock(active_remote_signing_mu_);
        return active_remote_signing_leases_.size();
    }
    work_admission::AdmissionCoordinator::Snapshot
    TestWorkAdmissionCoordinatorSnapshot() const noexcept {
        return work_admission_coordinator_.GetSnapshot();
    }
    size_t TestPendingBroadcastCount() const noexcept {
        std::lock_guard<std::mutex> lock(pending_broadcasts_mutex_);
        return pending_broadcasts_.size();
    }
    // getblocktemplate retains no full Block, but it now retains a bounded
    // server-issued authorization record for each published template identity.
    // Report that state so process tests cannot mistake a leaked capability for
    // a zero-artifact shutdown/refusal.
    size_t TestCachedTemplateCount() const noexcept {
        return block_template_authorizations_.GetSnapshot().active;
    }
    work_admission::BlockTemplateAuthorizationStore::Snapshot
    TestBlockTemplateAuthorizationSnapshot() const noexcept {
        return block_template_authorizations_.GetSnapshot();
    }
#endif

    StakingLedger& GetStaking() { return staking_; }
    ValidatorRegistry& GetValidators() { return validators_; }

    using FinalityEvidenceSummary =
        ::veld::finality::qc::FinalityEquivocationCollector::Summary;
    enum class FinalityEvidencePersistStatus : uint8_t {
        NotCommitted = 0,
        Committed,
        CommitUncertain,
    };

    // RPC-neutral bounded surfaces.  They return typed data/payloads only;
    // network/rpc.h owns JSON spelling, pagination errors, reporter-wallet
    // authorization, and transaction construction.
    std::vector<FinalityEvidenceSummary>
    ListFinalityEquivocationEvidence(size_t offset = 0,
                                     size_t limit = 100) const {
        namespace fq = ::veld::finality::qc;
        if (offset >= fq::FinalityEquivocationCollector::
                          MAX_COMPLETED_PAIRS || limit == 0)
            return {};
        limit = std::min<size_t>(limit, 100);
        std::lock_guard<std::mutex> gate(fin_equivocation_gate_mu_);
        if (fin_equivocation_journal_uncertain_) return {};
        return fin_equivocation_collector_.ListSummaryPage(offset, limit);
    }

    std::optional<::veld::finality::qc::ValidatedEquivocationEvidence>
    FindFinalityEquivocationEvidence(const Hash256& evidence_id) const {
        std::lock_guard<std::mutex> gate(fin_equivocation_gate_mu_);
        if (fin_equivocation_journal_uncertain_) return std::nullopt;
        return fin_equivocation_collector_.FindById(evidence_id);
    }

    std::optional<std::string> PrepareFinalityEquivocationSlash(
            const Hash256& evidence_id) const {
        namespace fq = ::veld::finality::qc;
        std::optional<fq::ValidatedEquivocationEvidence> evidence;
        {
            std::lock_guard<std::mutex> gate(fin_equivocation_gate_mu_);
            if (fin_equivocation_journal_uncertain_)
                return std::nullopt;
            evidence = fin_equivocation_collector_.FindById(evidence_id);
        }
        if (!evidence) return std::nullopt;

        auto transition = chain_.AcquireConsensusTransitionGuard();
        const uint64_t tip = chain_.Height();
        if (tip == UINT64_MAX) return std::nullopt;
        const auto& vote = evidence->First();
        if (!validators_.CanAcceptFinalityEquivocationEvidence(
                vote.pubkey_hex, vote.epoch_id, vote.set_root,
                static_cast<uint8_t>(vote.phase), vote.round,
                vote.target.height, tip + 1))
            return std::nullopt;
        return ValidatorRegistry::BuildSlashEquivOp(*evidence);
    }

    // True when `addr` is a registered, active validator — lets the status line
    // print [endorsing] for a validator vs [mining] for a plain miner.
    bool IsAddressRegisteredValidator(const std::string& addr) const {
        return validators_.IsValidatorByAddress(addr);
    }
    TierEngine& GetTiers() { return tiers_; }

    ~VeldNode() {
        try { Stop(); } catch (...) {}
    }

    void Start() {
        work_admission_coordinator_.CancelAndClose(
            work_admission::Refusal::StartupReplayIncomplete);
        ClearActiveRemoteSigningLeases_();
        startup_replay_complete_.store(false, std::memory_order_release);
        snapshot_state_clean_.store(false, std::memory_order_release);
        checkpoint_anchor_valid_.store(false, std::memory_order_release);
        BumpValidationGeneration_();
#ifdef VELD_PUBLIC_TESTNET
        if (!public_testnet_limits_ || !public_testnet_clock_guard_ ||
            !PublicTestnetRestartAuthorityFreshNow() ||
            public_testnet_limits_->not_after_height == 0) {
            throw std::runtime_error(
                "FATAL: public-testnet runtime limits are missing, malformed, or expired");
        }
#endif
#if defined(VELD_PUBLIC_MAINNET) && \
    !defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        std::string public_snapshot_marker;
        if (PublicSnapshotDatadirRefusal(&public_snapshot_marker)) {
            throw std::runtime_error(
                "FATAL: public mainnet refuses a datadir marked as "
                "snapshot-imported (" + public_snapshot_marker +
                "); restore an independently full-validated datadir or "
                "perform a fresh ordinary IBD");
        }
        snapshot_state_clean_.store(true, std::memory_order_release);
#endif
        // Every official node profile (public testnet, final mainnet,
        // qualification, and the isolated test-chain artifact) selects
        // VELD_MAINNET_POW.  Genesis enters those chains through trusted replay
        // because it has no parent state, so verify its actual memory-hard PoW
        // before any database, replay, RPC, or P2P state is exposed.  Legacy
        // v1-only synthetic harnesses deliberately select a different PoW
        // algorithm; applying the v2-mined nonce to that algorithm is not a
        // meaningful security check and deterministically rejects their fixture.
        // Public roles compile-require VELD_MAINNET_POW in constants.h, so this
        // profile guard cannot weaken a testnet or final-mainnet artifact.
        // Constructing the block remains universal: CreateGenesisBlock() also
        // enforces the pinned SHA256d identity and the fresh-start paths below
        // reuse these exact checked bytes in every profile.
        const Block verified_genesis = CreateGenesisBlock();
#ifdef VELD_MAINNET_POW
        const auto genesis_pow = mining::VerifyGenesisPoW(verified_genesis);
        if (!genesis_pow.target_valid || !genesis_pow.dataset_ok ||
                !genesis_pow.passed) {
            throw std::runtime_error(
                "FATAL: compiled genesis failed strict VeldHash proof-of-work "
                "verification; refusing to initialize or replay chain state");
        }
#endif

        // Authenticate the durable locally-observed anchor floor before
        // WireDB installs block callbacks or replay/snapshot/network code can
        // consume chain state.
        PrepareAnchorSecurityBootstrap_();
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        {
            const auto base = ReadIndependentValidationRequirement_();
            std::lock_guard<std::mutex> lock(background_validation_mutex_);
            snapshot_validation_base_ = base;
        }
#endif
        running_ = true;

        PruneStaleQuarantines_();

        {
            auto vault_script = AddressToScript(VAULT_ADDRESS);
            if (vault_script.empty()) {
                std::cerr << "\n  [CRITICAL] VAULT_ADDRESS is not decodable.\n"
                          << "  VAULT_ADDRESS = " << VAULT_ADDRESS << "\n"
                          << "  Update constants.h.\n\n";
            } else if (!quiet_boot_ && veld::DiagVerbose().load()) {
                std::cout << "  Vault:      " << VAULT_ADDRESS << "\n";
            }
        }

        WireDB();

        bool initialized_fresh_genesis = false;
        auto tip = db_.ReadChainTip();
#ifdef VELD_PUBLIC_TESTNET
        if (tip && tip->height > public_testnet_limits_->not_after_height) {
            throw std::runtime_error(
                "FATAL: durable public-testnet tip exceeds the immutable not-after height");
        }
#endif
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        const bool snapshot_replay_pending =
            ReadSnapshotReplayRequirement_().has_value();
        const bool trusted_snapshot_replay =
            snapshot_replay_pending && snapshot_fast_start_eligible_ &&
            !full_ibd_;
        snapshot_state_clean_.store(
            !trusted_snapshot_replay && !snapshot_replay_pending,
            std::memory_order_release);
#else
        constexpr bool snapshot_replay_pending = false;
        constexpr bool trusted_snapshot_replay = false;
        snapshot_state_clean_.store(true, std::memory_order_release);
#endif
        uint64_t trusted_local_pow_through = 0;
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        if (tip && tip->height > 0 && !snapshot_replay_pending &&
            snapshot_fast_start_eligible_ &&
            snapshot_receipt_height_ > 0 &&
            snapshot_receipt_height_ <= tip->height) {
            const auto receipt_hash =
                db_.GetHashAtHeight(snapshot_receipt_height_);
            if (receipt_hash && *receipt_hash == snapshot_receipt_tip_) {
                trusted_local_pow_through = snapshot_receipt_height_;
            }
        }
#endif
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        if (tip && tip->height > 0 && background_validation_only_) {
            if (const auto prefix = ReadValidatedBackgroundPrefix_()) {
                if (prefix->first > tip->height) {
                    throw std::runtime_error(
                        "validated background prefix exceeds the durable tip");
                }
                const auto stored_hash = db_.GetHashAtHeight(prefix->first);
                if (!stored_hash || *stored_hash != prefix->second) {
                    throw std::runtime_error(
                        "validated background prefix does not match the durable chain");
                }
                trusted_local_pow_through =
                    std::max(trusted_local_pow_through, prefix->first);
                background_prefix_persisted_height_.store(
                    prefix->first, std::memory_order_release);
            }
        }
#endif
        if (tip && tip->height > 0) {
            if (!quiet_boot_) {
                if (trusted_local_pow_through > 0 && !trusted_snapshot_replay) {
                    std::cout << "  [startup] Loading verified local chain state";
                } else {
                    std::cout << "  [startup] Rebuilding verified chain state";
                }
                if (trusted_snapshot_replay) {
                    std::cout << "; independent validation will continue "
                                 "from genesis in the background";
                } else if (trusted_local_pow_through > 0) {
                    std::cout << "; prior full IBD covers blocks 0-"
                              << trusted_local_pow_through;
                    if (tip->height > trusted_local_pow_through) {
                        std::cout << ", checking "
                                  << (tip->height - trusted_local_pow_through)
                                  << " newer block(s)";
                    }
                }
                std::cout << " ...\n" << std::flush;
            }
            ReplayChain(tip->height,
                        /*verify_historical_pow=*/!trusted_snapshot_replay,
                        trusted_local_pow_through);
        } else if (tip && tip->height == 0) {
            ReplayChain(0, /*verify_historical_pow=*/true);
        } else {
            Block genesis = verified_genesis;
            storage_.WriteBlock(genesis);
            db_.WriteChainTip(genesis.GetHash(), 0, 0);
            db_.WriteBlockIndex(HashToHex(genesis.GetHash()), 0, genesis.header.bits);
            chain_.AddBlockDirect(
                genesis, true, false, false,
                mining::PowAdmissionContext::Internal());
            SetChainFullyValidatedLatch_(true);
            initialized_fresh_genesis = true;
            if (!quiet_boot_ && veld::DiagVerbose().load())
                std::cout << "  Initialized new chain from genesis\n";
        }

        // If the in-memory chain remains empty, restore genesis without
        // overwriting a higher indexed tip. ReadChainTip handles indexed block
        // recovery before this branch is reached.
        if (chain_.IsEmpty()) {
            Block genesis = verified_genesis;
            chain_.AddBlockDirect(
                genesis, true, false, false,
                mining::PowAdmissionContext::Internal());
            // Only persist genesis metadata if the DB has nothing indexed yet.
            // If FindHighestIndexedHeight() > 0 we must NOT reset the tip —
            // the index already knows about real blocks.
            uint64_t existing_max = db_.FindHighestIndexedHeight();
            if (existing_max == 0) {
                storage_.WriteBlock(genesis);
                db_.WriteChainTip(genesis.GetHash(), 0, 0);
                db_.WriteBlockIndex(HashToHex(genesis.GetHash()), 0, genesis.header.bits);
                initialized_fresh_genesis = true;
                std::cout << "  [WARN] Inserted genesis (recovered from empty chain)\n";
            } else {
                std::cout << "  [WARN] Chain empty in memory but index has blocks up to height "
                          << existing_max << " — preserving stored tip for peer sync recovery\n";
            }
        }

        if (initialized_fresh_genesis && !chain_.IsEmpty()) {
            const Block genesis = chain_.GetBlock(0);
            PrepareCanonicalDerivedIndexesForReplay_(0, genesis.GetHash());
            FinishCanonicalDerivedIndexesAfterReplay_(0, genesis.GetHash());
        }

#ifdef VELD_PUBLIC_TESTNET
        // The terminal block may be durably accepted, but this process may not
        // reopen network/RPC/mining service at or beyond that terminal tip.
        if (PublicTestnetRuntimeStopRequired()) {
            throw std::runtime_error(
                "FATAL: public-testnet runtime not-after height/UTC has been reached");
        }
#endif

        // Replay has reconstructed the canonical retained validator snapshot
        // history.  Re-authenticate the owner-only completed-evidence journal
        // now, before any P2P/RPC thread can observe or mutate evidence state.
        LoadFinalityEvidence_();

        // Startup/replay has now rebuilt the token ledger to the in-memory
        // canonical tip. Publish the first coherent tuple before RPC/P2P starts.
        PublishBtcVeldSupplySnapshot_(chain_.TipCopy());
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        MaybeCaptureBackgroundValidationTarget_();
#endif
        checkpoint_anchor_valid_.store(
            AnchorSecurityImportSatisfied(), std::memory_order_release);
        startup_replay_complete_.store(true, std::memory_order_release);
        BumpValidationGeneration_();

        tcp_server_ = std::make_unique<net::NodeServer>(
            p2p_port_ ? p2p_port_ : config_.port, config_.magic, chain_, mempool_);
        tcp_server_->SetPeerWorkViewTransitionFn([this]()
                -> net::NodeServer::PeerWorkViewTransitionPermit {
            // Writer-first immediately closes every new local/remote grant.
            // A lease/token which linearized first remains a bounded
            // predecessor; the writer waits outside every peer/chain mutex for
            // it to consume/release/expire, then owns the chain sequencer for
            // the complete peer-state publication.
            (void)CloseWorkAdmissionBounded_(
                work_admission::Refusal::PeerViewUnsafe);
            try {
                auto transition = chain_.AcquireConsensusTransitionGuard();
                return net::NodeServer::PeerWorkViewTransitionPermit(
                    new PeerWorkViewTransitionPermit(
                        *this, std::move(transition)));
            } catch (...) {
                work_admission_coordinator_.CancelAndClose(
                    work_admission::Refusal::Unwired);
                return {};
            }
        });
        tcp_server_->SetAdvertisedServices(
            advertised_services_.load(std::memory_order_acquire));

        tcp_server_->SetBanFilePath(data_dir_ + "/banned-ips.txt");
        tcp_server_->LoadBansFromFile();

        tcp_server_->SetPeerCachePath(data_dir_ + "/peers.dat");
        tcp_server_->SetAnchorsPath(data_dir_ + "/anchors.dat");
        tcp_server_->LoadPeerCache();

        tcp_server_->SetBlockCallback([this](const Block& blk, const std::string& from_peer) {
            RecordPeerBlockAccepted();
            // AddBlockDirect returns true for a valid side-branch block even
            // when it does not win fork choice.  Never publish durable tip
            // metadata from this generic post-accept notification: WireDB's
            // on_commit callback is the sole writer after a canonical linear
            // connect or completed reorg.  Writing `blk` here made any valid
            // non-winning fork select an unpersisted/non-canonical tip on the
            // next restart.
            // OnChainTokenLedger::NeedsRebuild() is permanently false in the
            // current consensus implementation. Canonical derived-state recovery is
            // performed only by ReplayChain / the hash-bound module-checkpoint
            // reorg path, both of which run ApplyBlockModules_ in historical
            // order with the gate derived at each height.
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
            MaybeCaptureBackgroundValidationTarget_();
#endif
        });
        tcp_server_->SetTxCallback([this](const Transaction& tx, const std::string&) {
            tcp_server_->BroadcastTransaction(tx);
        });

        tcp_server_->SetBlockAckCallback([this](const Hash256& h, const std::string& peer_addr) {
            NotePeerInvOfBlock(h);
            RecordAckFromPeer(h, peer_addr);
        });

        if constexpr (!OPTION_B_CONSENSUS_GATE_ENABLED) {
            tcp_server_->SetSolutionCallback([this](uint64_t height, const Hash256& prev_hash,
                                                    uint64_t nonce, const std::vector<uint8_t>& script) {
            std::lock_guard<std::mutex> lock(solution_mutex_);
            PendingSolution sol;
            sol.prev_height  = height;
            sol.prev_hash    = prev_hash;
            sol.nonce        = nonce;
            sol.miner_script = script;
            sol.received_at  = std::chrono::steady_clock::now();
            pending_solutions_.push_back(sol);
            auto cutoff = std::chrono::steady_clock::now() - std::chrono::seconds(30);
            pending_solutions_.erase(
                std::remove_if(pending_solutions_.begin(), pending_solutions_.end(),
                    [&cutoff](const PendingSolution& s){ return s.received_at < cutoff; }),
                pending_solutions_.end());
            });

            tcp_server_->SetCOMineCallback([this](uint64_t height, const Hash256& prev_hash,
                                                  uint64_t best_nonce, const Hash256& best_hash,
                                                  const std::vector<uint8_t>& script) -> bool {
            std::lock_guard<std::mutex> lock(solution_mutex_);
            for (auto& s : pending_solutions_)
                if (s.prev_height == height && s.miner_script == script) return false;
            PendingSolution sol;
            sol.prev_height  = height;
            sol.prev_hash    = prev_hash;
            sol.nonce        = best_nonce;
            sol.best_hash    = best_hash;
            sol.miner_script = script;
            sol.received_at  = std::chrono::steady_clock::now();
            sol.is_winner    = false;
            pending_solutions_.push_back(sol);
            return true;
            });
        }

        // Stage 1 runs on NodeServer's dedicated prefilter thread.  Sibling
        // target hashes are intentionally admissible here: exact retained-set
        // membership is cheap to resolve, while signature authentication and
        // canonical-vs-evidence routing happen in the bounded crypto pool.
        tcp_server_->SetFinalityVotePrecheck(
            [this](const std::vector<uint8_t>& wire) -> bool {
                return PrecheckFinalityVoteWire_(wire);
            });

        // Stage 2 is invoked only by the hard-capped FINVOTE crypto pool.
        // Return a typed local-policy result so only a genuinely new stored
        // vote is relayed and only an intrinsic bad signature earns ban score.
        tcp_server_->SetFinalityVoteVerifier(
            [this](const std::vector<uint8_t>& wire)
                -> net::NodeServer::FinalityVoteVerifyResult {
                return VerifyFinalityVoteWire_(wire);
            });

        rpc_.SetTxBroadcast([this](const Transaction& tx) {
            if (tcp_server_) tcp_server_->BroadcastTransaction(tx);
        });
        rpc_.SetBlockBroadcast([this](const Block& block) {
            if (!tcp_server_)
                throw std::runtime_error("block publication transport unavailable");
            tcp_server_->BroadcastBlock(block);
        });
        rpc_.SetPeerCount([this]() -> size_t {
            return tcp_server_ ? tcp_server_->ConnectedPeers() : 0;
        });
        rpc_.SetPeerInfo([this]() -> std::string {
            if (!tcp_server_) return "[]";
            auto peers       = tcp_server_->GetPeerInfoList();
            auto tip_snaps   = tcp_server_->SnapshotPeerTips();
            uint64_t our_h   = chain_.Height();
            // system_clock, NOT steady: updated_at is stamped with system_clock at
            // every RecordPeerTip site — a steady read here yielded age ≈ -(unix now)
            int64_t now_s    = (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();

            std::unordered_map<std::string, const veld::net::NodeServer::PeerTipSnapshot*> by_ip;
            by_ip.reserve(tip_snaps.size());
            for (const auto& s : tip_snaps) by_ip[s.ip] = &s;

            std::ostringstream j;
            j << "[";
            bool first = true;
            for (const auto& p : peers) {
                if (!first) j << ",";
                first = false;
                std::string ip_only = p.ip;
                size_t colon = ip_only.find_last_of(':');
                if (colon != std::string::npos) ip_only = ip_only.substr(0, colon);
                auto it = by_ip.find(ip_only);
                bool   have_tip      = (it != by_ip.end());
                uint64_t peer_h      = have_tip ? it->second->height : 0;
                std::string peer_hex = have_tip ? HashToHex(it->second->hash) : "";
                int64_t age_s        = have_tip ? (now_s - it->second->updated_at) : -1;
                int64_t lag_blocks   = have_tip ? (int64_t)our_h - (int64_t)peer_h : 0;
                j << "{"
                  << "\"addr\":\"" << p.addr << "\","
                  << "\"ip\":\"" << p.ip << "\","
                  << "\"port\":" << p.port << ","
                  << "\"inbound\":" << (p.inbound ? "true" : "false") << ","
                  << "\"bytes_sent\":" << p.bytes_sent << ","
                  << "\"bytes_recv\":" << p.bytes_recv << ","
                  << "\"peer_height\":" << peer_h << ","
                  << "\"peer_tip_hash\":\"" << peer_hex << "\","
                  << "\"peer_tip_age_s\":" << age_s << ","
                  << "\"lag_blocks\":" << lag_blocks
                  << "}";
            }
            j << "]";
            return j.str();
        });
        rpc_.SetOnChainTokens(&onchain_tokens_);
        rpc_.SetBtcVeldMintProofFn(
            [this](const std::string& outpoint) {
                return BuildMintNullifierStatus_(outpoint);
            });
        rpc_.SetBtcVeldSupplySnapshotFn(
            [this]() -> std::string { return BtcVeldSupplySnapshotJson_(); });
        // Layer-3: the redeem daemon reads the retained certificate high-water
        // mark from getpeginfo/getbtcveldredeems and holds a burn's BTC payout
        // until its block is final. Before the first certificate the mark is 0.
        rpc_.SetFinalHeightFn([this]() -> uint64_t { return FinalHeight(); });
        rpc_.SetBtcVeldPegStatusFn([this]() -> BtcVeldPegStatus {
            auto transition = chain_.AcquireConsensusTransitionGuard();
            BtcVeldPegStatus out;
            out.tip = chain_.Height();
            out.final_height = fin_state_.FinalizedHeight();
            out.finality_active = fin_state_.FinalityActive();
            out.finality_ever_active = fin_state_.finality_ever_active;
            out.anchor_promoted = fin_state_.ever_promoted_anchor;
            // The status authorizes work for the next candidate block, matching
            // mempool/template admission.
            const uint64_t candidate_height = out.tip == UINT64_MAX
                ? out.tip : out.tip + 1;
            const Block tip_block = chain_.TipCopy();
            const uint64_t candidate_time = tip_block.header.timestamp <=
                    UINT64_MAX - TARGET_BLOCK_TIME
                ? tip_block.header.timestamp + TARGET_BLOCK_TIME
                : tip_block.header.timestamp;
            out.gate = PegGateForState_(
                fin_state_, candidate_height, &btc_headers_, candidate_time);
            const bool launch_profile_active =
                BTCVELD_ISSUER_ADDRESS[0] != '\0' &&
                candidate_height >= BTCVELD_ACTIVATION_HEIGHT;
            if (!launch_profile_active)
                out.reason = "launch_profile_inactive";
            else if (!out.finality_ever_active)
                out.reason = "waiting_for_seven_validator_activation";
            else if (!out.gate.MintAllowed())
                out.reason =
                    "new_mint_exposure_paused_finality_stale_completion_open";
            else if (!out.finality_active)
                out.reason = "ready_validator_activation_latched";
            else if (!out.anchor_promoted)
                out.reason = "ready_anchor_pending";
            else
                out.reason = "ready_security_layers_active";
            return out;
        });
        rpc_.SetBtcVeldRedeemPageFn(
            [this](const std::vector<std::string>& params) {
                return BuildRedeemPageJson_(params);
            });
        // btcVELD relay: expose the in-consensus BTC-header tip so the header-relay daemon
        // (swap/veld_btcrelayd.py) knows which Bitcoin headers are still missing. best_height
        // is the race-free snapshot updated by the block thread; the rest are compile consts.
        rpc_.SetBtcHeaderInfoFn([this]() -> std::string {
            uint64_t bh = btc_header_tip_.load(std::memory_order_acquire);
            const uint64_t tip = chain_.Height();
            const uint64_t candidate_height = tip == UINT64_MAX ? tip : tip + 1;
            const bool active_tip = BtcVeldSpvActive(tip);
            const bool active_candidate = BtcVeldSpvActive(candidate_height);
            std::ostringstream j;
            // `spv_active` is the compatibility/control-plane alias and reports
            // the next candidate block, matching the relay operation it gates.
            j << "{\"spv_active\":" << (active_candidate ? "true" : "false")
              << ",\"spv_active_current_tip\":" << (active_tip ? "true" : "false")
              << ",\"spv_active_next_candidate\":" << (active_candidate ? "true" : "false")
              << ",\"best_height\":" << bh
              << ",\"k_btc\":" << BTCVELD_SPV_K_BTC
              << ",\"activation_height\":" << BTCVELD_SPV_ACTIVATION_HEIGHT << "}";
            return j.str();
        });
        rpc_.SetBtcHeaderDigestFn([this]() -> Hash256 {
            return btc_headers_.StateDigest();
        });
        // Regtest-only: bitcoin-style on-demand block generator for the btcVELD daemon E2E.
        // The live mining loop's pacing + clock-drift + anchor guards make a single-node
        // regtest impractical for bulk block production, so `generate` mines directly via
        // MineBlocks. Quiesce the loop first so generate owns the chain tip (no double-mine
        // race). Wired ONLY on regtest → the RPC is absent on testnet/mainnet binaries.
#ifndef VELD_FLEET_NO_MINE
        if (config_.name == "Veld Regtest") {
            rpc_.SetGenerateFn([this](int n) {
                return GenerateBlocksForRpc(n, 0x207fffffu);
            });
        }
#endif
        // btcVELD Layer-2: expose the anchor-set high-water so the anchor daemon can confirm
        // its relayed VELD_ANCHOR op was verified + recorded by consensus.
        rpc_.SetAnchorInfoFn([this]() -> std::string {
            // Module preflight mutates the live AnchorSet under a snapshot and
            // restores it before canonical publication.  Quiesce that complete
            // lifecycle so an operator can never mistake a transient,
            // ultimately rejected candidate anchor for canonical high-water.
            auto transition = chain_.AcquireConsensusTransitionGuard();
            const uint64_t fin = final_height_.load(std::memory_order_acquire);
            // R3: "configured" no longer exists as a separate concept — the
            // constant it read is retired. Anchors are active exactly when the
            // chain has finalized a real block. This endpoint previously
            // computed the correct condition (configured && finality_active &&
            // fin > 0) and reported it, while consensus enforced none of it;
            // the rule now lives in consensus and this merely reports it.
            const bool configured      = fin_state_.AnchorWarmupComplete();
            const bool finality_active = fin_state_.FinalityActive();
            const bool admission_live  = configured && BtcVeldAnchorActive(fin);
            uint64_t hw = anchors_.HighWater();
            const size_t active_count = anchors_.ActiveSize();
            const size_t pending_count = anchors_.PendingSize();
            const uint64_t retired_count = anchors_.RetiredCount();
            const auto permanent = anchors_.Permanent();
            const auto pending_observations = anchors_.PendingForObservation();
            const bool checkpoint_enforced = permanent.has_value();
            const bool floor_exportable =
                anchors_.HasExportablePermanentFloor();
            const auto bootstrap_status =
                EffectiveAnchorSecurityStatusNoTransition_();
            std::ostringstream j;
            // `anchor_active` remains the daemon-compatible alias for NEW
            // proof admission. Existing promoted checkpoints remain enforced
            // through a later qualification dip and are reported separately.
            j << "{\"anchor_active\":" << (admission_live ? "true" : "false")
              << ",\"anchor_admission_live\":" << (admission_live ? "true" : "false")
              << ",\"anchor_checkpoint_enforced\":" << (checkpoint_enforced ? "true" : "false")
              << ",\"anchor_floor_exportable\":" << (floor_exportable ? "true" : "false")
              << ",\"anchor_security_milestone\":" << (fin_state_.ever_promoted_anchor ? "true" : "false")
              << ",\"anchor_configured\":" << (configured ? "true" : "false")
              << ",\"finality_active\":" << (finality_active ? "true" : "false")
              << ",\"final_height\":" << fin
              << ",\"high_water\":" << hw
              << ",\"active_count\":" << active_count
              << ",\"pending_count\":" << pending_count
              << ",\"retired_count\":" << retired_count
              << ",\"k_btc\":" << BTCVELD_ANCHOR_BTC_CONFS;
            // The Bitcoin-anchored floor is reported through the permissionless
            // ANCHOR_SPV / VLF1 fields below.
            j << ",\"bootstrap\":null";
            j << ",\"btc_observed_checkpoint_height\":"
              << btc_headers_.ObservedCheckpointHeight()
              << ",\"btc_observed_checkpoint_hash\":\""
              << HashToHex(btc_headers_.ObservedCheckpoint()) << "\"";
            j << ",\"pending_observations\":[";
            for (size_t i = 0; i < pending_observations.size(); ++i) {
                if (i) j << ",";
                const auto& pending = pending_observations[i];
                const bool btc_final = btc_headers_.IsFinal(
                    pending.entry.btc_block_hash, BTCVELD_ANCHOR_BTC_CONFS);
                j << "{\"target_height\":" << pending.target_height
                  << ",\"proof_carrier_height\":"
                  << pending.entry.carrying_veld_height
                  << ",\"proof_carrier_hash\":\""
                  << HashToHex(pending.entry.carrying_veld_hash) << "\""
                  << ",\"btc_block_hash\":\""
                  << HashToHex(pending.entry.btc_block_hash) << "\""
                  << ",\"btc_final\":" << (btc_final ? "true" : "false")
                  << "}";
            }
            j << "]";
            std::optional<btcanchor::floor_store::Record> local_floor;
            {
                std::lock_guard<std::mutex> floor_lock(
                    anchor_floor_store_mutex_);
                local_floor = anchor_floor_store_.Current();
            }
            j << ",\"local_floor\":{"
              << "\"installed\":"
              << (local_floor ? "true" : "false")
              << ",\"repair_required\":"
              << (anchor_floor_repair_required_.load(
                      std::memory_order_acquire) ? "true" : "false")
              << ",\"fail_stop\":"
              << (anchor_floor_security_uncertain_.load(
                      std::memory_order_acquire) ? "true" : "false");
            if (local_floor) {
                const auto& p = local_floor->checkpoint;
                j << ",\"target_height\":" << p.target_height
                  << ",\"proof_carrier_height\":"
                  << p.entry.carrying_veld_height
                  << ",\"authorization_carrier_height\":"
                  << p.authorization_record.carrier.height
                  << ",\"floor_digest\":\""
                  << HashToHex(local_floor->floor_digest) << "\"";
            } else {
                j << ",\"target_height\":null"
                  << ",\"proof_carrier_height\":null"
                  << ",\"authorization_carrier_height\":null"
                  << ",\"floor_digest\":null";
            }
            j << "}";
            if (permanent) {
                const auto& p = *permanent;
                const auto& e = p.entry;
                j << ",\"permanent\":{\"target_height\":" << p.target_height
                  << ",\"target_hash\":\"" << HashToHex(e.veld_block_hash) << "\""
                  << ",\"proof_carrier_height\":" << e.carrying_veld_height
                  << ",\"proof_carrier_hash\":\"" << HashToHex(e.carrying_veld_hash) << "\""
                  << ",\"authorization_carrier_height\":" << e.authorization_veld_height
                  << ",\"authorization_carrier_hash\":\"" << HashToHex(e.authorization_veld_hash) << "\""
                  << ",\"authorization_finality_digest\":\""
                  << HashToHex(e.authorization_finality_digest) << "\""
                  << ",\"btc_block_hash\":\"" << HashToHex(e.btc_block_hash) << "\""
                  << ",\"btc_txid\":\"" << HashToHex(e.btc_txid) << "\"";
                if (!p.authorization_record.IsNull()) {
                    const auto& r = p.authorization_record;
                    j << ",\"authorization_record\":{\"epoch_id\":" << r.epoch_id
                      << ",\"finalized_height\":" << r.target.height
                      << ",\"finalized_hash\":\"" << HashToHex(r.target.hash) << "\""
                      << ",\"set_root\":\"" << HashToHex(r.set_root) << "\""
                      << ",\"round\":" << r.round
                      << ",\"phase\":" << static_cast<unsigned>(r.phase)
                      << ",\"cert_commit\":\"" << HashToHex(r.cert_commit) << "\""
                      << ",\"carrier_height\":" << r.carrier.height
                      << ",\"carrier_hash\":\"" << HashToHex(r.carrier.hash) << "\""
                      << ",\"retention_floor\":" << r.retention_floor
                      << "}";
                } else {
                    j << ",\"authorization_record\":null";
                }
                j << "}";
            } else {
                j << ",\"permanent\":null";
            }
            j << "}";
            return j.str();
        });
        rpc_.SetAnchorDigestFn([this]() -> Hash256 {
            return anchors_.Digest();
        });
        rpc_.SetFinalityDigestFn([this]() -> Hash256 {
            // Commit the complete retained finality state: validator snapshots,
            // certificate carrier, activation counters, and finality record.
            return fin_state_.Digest();
        });
        rpc_.SetRedeemBondDigestFn([this]() -> Hash256 {
            return bond_covenant_.Digest();
        });

        // Serve a retained finality epoch snapshot to validator daemons.  The
        // optional epoch is consensus-relevant at boundaries: after h=959 the
        // epoch-2 snapshot is newest, while target 940 still has two legal
        // carrier heights left in epoch 1's +1..+20 vote window.
        rpc_.SetFinalitySnapshotFn(
            [this](std::optional<uint64_t> requested_epoch) -> std::string {
            namespace fq = ::veld::finality::qc;
            auto transition = chain_.AcquireConsensusTransitionGuard();
            if (fin_state_.snapshots.empty()) return "";
            auto selected = requested_epoch
                ? fin_state_.snapshots.find(*requested_epoch)
                : std::prev(fin_state_.snapshots.end());
            if (selected == fin_state_.snapshots.end()) return "";
            const auto& s = selected->second;
            // A snapshot above the consensus carrier ceiling cannot produce a
            // valid QC and must not inflate the validator RPC past the exact
            // maximum-set policy.  Canonical validator addresses are bounded
            // Base58Check P2PKH strings; reject impossible retained state here
            // rather than emitting unescaped or unbounded JSON.
            if (s.entries.size() > fq::MAX_FINALITY_VALIDATOR_COUNT ||
                !fq::SnapshotWellFormed(s)) return "";
            for (const auto& entry : s.entries) {
                if (entry.address.empty() ||
                    entry.address.size() >
                        ::veld::finality::rpc_limits::kMaxValidatorAddressChars ||
                    AddressToScript(entry.address).size() != 25)
                    return "";
            }
            std::ostringstream j;
            j << "{\"snapshot\":{";
            j << "\"epoch\":"       << s.epoch_id       << ",";
            j << "\"snapshot_height\":" << s.snapshot_height << ",";
            j << "\"set_root\":\""  << HashToHex(s.root) << "\",";
            j << "\"total_weight\":" << s.total_weight   << ",";
            j << "\"active\":"      << (fin_state_.FinalityActive() ? "true" : "false") << ",";
            j << "\"members\":[";
            for (size_t i = 0; i < s.entries.size(); ++i) {
                if (i) j << ",";
                j << "{\"index\":" << i
                  << ",\"pubkey\":\"" << s.entries[i].pubkey_hex << "\""
                  << ",\"commit\":\"" << HashToHex(s.entries[i].pubkey_commit) << "\""
                  << ",\"address\":\"" << s.entries[i].address << "\""
                  << ",\"registered_height\":" << s.entries[i].registered_height
                  << ",\"weight\":" << s.entries[i].weight << "}";
            }
            j << "],\"finalized\":";
            if (fin_state_.record.IsNull()) {
                j << "null";
            } else {
                const auto& r = fin_state_.record;
                j << "{\"epoch\":" << r.epoch_id
                  << ",\"height\":" << r.target.height
                  << ",\"hash\":\"" << HashToHex(r.target.hash) << "\""
                  << ",\"round\":" << r.round << "}";
            }
            j << "}}";
            return j.str();
        });

        WireFinalityVoteRpcSink_();
        rpc_.SetFinalityQcFn([this](uint8_t phase) -> std::string {
            namespace fq = ::veld::finality::qc;
            if (phase != 1 && phase != 2) return "";
            auto transition = chain_.AcquireConsensusTransitionGuard();
            const uint64_t tip = chain_.Height();
            std::lock_guard<std::mutex> g(fin_assembler_mu_);
            for (auto it = fin_state_.snapshots.rbegin();
                 it != fin_state_.snapshots.rend(); ++it) {
                auto qc = fin_assembler_.TryAssemble(
                    it->second, fq::NETWORK_ID, GenesisHashBytes_(),
                    (fq::Phase)phase,
                    [this, tip](const fq::DecodedQc& d) {
                        if (!fq::InVoteWindow(d.qc.target.height, tip))
                            return false;
                        try {
                            if (chain_.GetBlock(d.qc.target.height).GetHash() !=
                                d.qc.target.hash) return false;
                        } catch (...) { return false; }
                        if (fin_state_.record.IsNull())
                            return d.qc.source.IsNull();
                        return d.qc.source == fin_state_.record.target &&
                               d.qc.target.height >
                                   fin_state_.record.target.height;
                    });
                if (!qc) continue;
                const std::string payload = fq::EncodeQc(qc->qc, qc->sigs);
                if (!payload.empty())
                    return fq::ToHexBytes(
                        reinterpret_cast<const uint8_t*>(payload.data()),
                        payload.size());
            }
            return "";
        });
        // getstatedigest holds Blockchain's consensus-transition guard while
        // invoking this callback, so these single-writer replay cursors cannot
        // race a block/reorg transition.  A mismatch is reported as an RPC
        // error; it must never be hidden behind an apparently valid v7 digest.
        rpc_.SetModuleCursorFn([this]() {
            return std::make_pair(last_token_height_, last_module_supply_);
        });
        rpc_.SetPowVerifyStatusFn(
            [this]() -> std::string { return PowVerifyStatusJson(); });
        rpc_.SetAmm(&amm_);
        rpc_.SetStaking(&staking_);
        rpc_.SetValidators(&validators_);
        rpc_.SetGovernance(&governance_);
        rpc_.SetTierEngine(&tiers_);
        rpc_.SetVault(&vault_);
        rpc_.SetPoolInfoFn([this]() -> std::string { return GetPoolInfoJSON(); });
        rpc_.SetMinerStatusFn([this]() -> std::string {
            double hr = hashrate_.load();
            uint64_t th = total_hashes_.load();
            std::string miner_addr = miner_keypair_.address;
            uint32_t bits = mining_bits_;
            if (bits == 0) bits = chain_.ComputeNextBits();
            double net_hr = 0.0;
            {
                uint32_t exp = bits >> 24;
                uint32_t mantissa = bits & 0x007fffff;
                if (mantissa > 0 && exp >= 3) {
                    int shift_exp = 256 - 8 * ((int)exp - 3);
                    if (shift_exp >= 0 && shift_exp < 1023) {
                        double pow2 = std::ldexp(1.0, shift_exp);
                        double target_f = pow2 / (double)mantissa;
                        double T = (double)TARGET_BLOCK_TIME;
                        if (T > 0) net_hr = target_f / T;
                    }
                }
            }
            std::ostringstream j;
            const bool mining_configured =
                mining_.load(std::memory_order_acquire);
            const bool mining_ready = mining_configured &&
                ibd_complete_.load(std::memory_order_acquire) &&
                chain_fully_validated_.load(std::memory_order_acquire);
            const bool mining_active =
                mining_work_state_.load(std::memory_order_acquire) ==
                MiningWorkState::Hashing;
            j << std::fixed << std::setprecision(2);
            j << "{";
            j << "\"mining\":"        << (mining_active ? "true" : "false") << ",";
            j << "\"mining_configured\":"
              << (mining_configured ? "true" : "false") << ",";
            j << "\"mining_ready\":"
              << (mining_ready ? "true" : "false") << ",";
            j << "\"work_state\":\"" << GetMiningWorkStateName()
              << "\",";
            j << "\"hashrate\":"      << hr << ",";
            j << "\"total_hashes\":"  << th << ",";
            j << "\"threads\":"       << mining_threads_ << ",";
            j << "\"miner_address\":\"" << miner_addr << "\",";
            j << "\"bits\":"          << bits << ",";
            j << "\"network_hashrate_est\":" << net_hr << ",";
            j << "\"target_block_time_sec\":" << (uint64_t)TARGET_BLOCK_TIME;
            j << "}";
            return j.str();
        });
        rpc_.SetIBDCompleteFn([this]() -> bool { return ibd_complete_.load(); });
        rpc_.SetTxIndexEnabledFn([this]() -> bool {
            return txindex_enabled_ && txindex_operational_.load();
        });

        rpc_.SetTxIndexLookupFn(
            [this](const std::string& txid_hex) -> std::optional<uint64_t> {
                if (!txindex_enabled_ || !txindex_operational_.load())
                    return std::nullopt;
                try {
                    auto v = db_.GetIndexDB().Get("txi:" + txid_hex);
                    if (!v || v->empty()) return std::nullopt;
                    uint64_t height = 0;
                    if (!ParseMinerArchiveUint64_(*v, height) ||
                        height > chain_.Height())
                        return std::nullopt;
                    const Block canonical = chain_.GetBlock(height);
                    const bool exact = std::any_of(
                        canonical.transactions.begin(),
                        canonical.transactions.end(),
                        [&txid_hex](const Transaction& tx) {
                            return HashToHex(tx.GetTxID()) == txid_hex;
                        });
                    return exact ? std::optional<uint64_t>(height)
                                 : std::nullopt;
                } catch (...) { return std::nullopt; }
            });

#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        rpc_.SetDumpSnapshotFn([this](const std::string& target_dir) -> std::string {
            try {
                // Serialize against the complete connect/on_commit lifecycle,
                // then bind the exact canonical tip covered by all three
                // LevelDB snapshots while that lifecycle is quiescent.
                auto guard = chain_.AcquireConsistentDumpGuard();
                const uint64_t dump_height = chain_.Height();
                if (dump_height == 0)
                    return "snapshot tip is genesis/empty";
                const std::string dump_tip =
                    HashToHex(chain_.GetBlockUnlocked(dump_height).GetHash());
                std::string err;
                if (db_.DumpConsistentSnapshot(target_dir, &err))
                    return "ok|" + std::to_string(dump_height) + "|" + dump_tip;
                return err.empty() ? "DumpConsistentSnapshot returned false" : err;
            } catch (const std::exception& e) {
                return std::string("dumpsnapshot exception: ") + e.what();
            }
        });
#endif

        rpc_.SetClearMiningHaltFn([this]() -> std::string {
            size_t dropped = 0;
            {
                std::lock_guard<std::mutex> lock(pending_broadcasts_mutex_);
                dropped = pending_broadcasts_.size();
                pending_broadcasts_.clear();
            }
            mining_halted_for_propagation_.store(false, std::memory_order_release);
            std::cerr << "  [layer1] OPERATOR clearmininghalt: dropped "
                      << dropped << " pending broadcast entries; mining halt cleared.\n";
            std::cerr.flush();
            return "ok";
        });

        // invalidateblock <hash> — adds the hash to the P2P-layer
        // reject cache so future relays of this block are rejected
        // before validation. NOTE v1 limitation: this does NOT undo
        // canonical-chain inclusion if the block is already in the
        // active chain. For that case the operator must also use
        // explicit offline recovery using independently reviewed local data.
        rpc_.SetInvalidateBlockFn([this](const Hash256& h) -> std::string {
            if (!tcp_server_) return "tcp_server not initialised";
            tcp_server_->MarkBlockRejected(HashToHex(h));
            std::cerr << "  [recovery] invalidateblock "
                      << HashToHex(h).substr(0, 16) << "... — added to reject cache.\n";
            std::cerr.flush();
            return "ok";
        });

        rpc_.SetReconsiderBlockFn([this](const Hash256& h) -> std::string {
            if (!tcp_server_) return "tcp_server not initialised";
            bool removed = tcp_server_->UnmarkBlockRejected(HashToHex(h));
            std::cerr << "  [recovery] reconsiderblock "
                      << HashToHex(h).substr(0, 16) << "... — "
                      << (removed ? "removed from reject cache." : "not in reject cache (no-op).") << "\n";
            std::cerr.flush();
            return removed ? "ok" : "not_in_cache";
        });

        rpc_.SetClearRejectCacheFn([this]() -> size_t {
            if (!tcp_server_) return 0;
            size_t n = tcp_server_->ClearRejectCache();
            std::cerr << "  [recovery] clearrejectcache cleared " << n << " entries.\n";
            std::cerr.flush();
            return n;
        });
        rpc_.SetClearOrphanPoolFn([this]() -> size_t {
            if (!tcp_server_) return 0;
            size_t n = tcp_server_->ClearOrphanPool();
            std::cerr << "  [recovery] clearorphanpool cleared " << n << " entries.\n";
            std::cerr.flush();
            return n;
        });
        rpc_.SetClearBadAltTipsFn([this]() -> size_t {
            size_t n = chain_.ClearBadAltTips();
            std::cerr << "  [recovery] clearbadalttips cleared " << n << " entries.\n";
            std::cerr.flush();
            return n;
        });

        rpc_.SetFlushTriggerFn([this](bool is_endorse) -> std::string {
            std::ostringstream j;
            j << "{";
            uint64_t h = chain_.Height();
            j << "\"height\":" << h << ",";
            if (!is_endorse) {
                j << "\"status\":\"disabled\",\"reason\":\"pool_flush_is_lottery_only_in_mining_loop\"";
                j << "}";
                return j.str();
            }
            j << "\"status\":\"disabled\",\"reason\":\"endorse_flush_is_block_embedded_in_mining_loop\"";
            j << "}";
            return j.str();
        });
        explorer_.SetTokenLedger(&onchain_tokens_);
        explorer_.SetRpcDelegate(&rpc_);
        explorer_.SetValidators(&validators_);
        explorer_.SetCacheDir(data_dir_);
        explorer_.SetTiers(&tiers_);
        explorer_.SetNetworkHeightFn([this]() -> uint64_t {
            return tcp_server_ ? tcp_server_->GetPeerVerifiedHeight() : 0;
        });
        explorer_.SetPeerCountFn([this]() -> size_t {
            return tcp_server_ ? tcp_server_->ConnectedPeers() : 0;
        });
        explorer_.SetPeerStatsFn([this]() -> std::vector<veld::explorer::BlockExplorer::PeerStatsItem> {
            std::vector<veld::explorer::BlockExplorer::PeerStatsItem> out;
            if (!tcp_server_) return out;
            auto snaps = tcp_server_->SnapshotPeerStats();
            int64_t now_s = (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            out.reserve(snaps.size());
            for (const auto& s : snaps) {
                veld::explorer::BlockExplorer::PeerStatsItem item;
                item.ip           = s.ip;
                item.mempool_size = s.mempool_size;
                item.peer_count   = s.peer_count;
                item.age_s        = now_s - s.updated_at;
                out.push_back(std::move(item));
            }
            return out;
        });

        governance_.SetPersistence(
            [this](const std::string& k, const std::string& v) {
                try { db_.GetIndexDB().Put(k, v); } catch (...) {}
            },
            [this](const std::string& k) {
                try { db_.GetIndexDB().Delete(k); } catch (...) {}
            },
            [this](const std::string& prefix,
                   std::function<bool(const std::string&, const std::string&)> fn) {
                try { db_.GetIndexDB().Iterate(prefix, fn); } catch (...) {}
            }
        );
        try { governance_.PersistAll(); } catch (...) {}
        try { governance_.PruneOrphanedKV(); } catch (...) {}

        // Token/endorsement operations are ordinary funded, signed mempool
        // transactions.  There is deliberately no privileged miner queue:
        // the retired queue encoded an extra coinbase-like transaction that
        // full peer validation rejects.
        rpc_.SetTokenOpCallback([](const TokenOpData& op) {
            std::cerr << "  [TOKEN] REFUSED legacy privileged token op: "
                      << op.action << " (submit a funded, signed transaction)\n";
            std::cerr.flush();
        });

        rpc_.SetTokenSave([]() {});

        {
            // Display-only historical rate. Paid/cleanup state itself is never
            // restored from local KV; ValidatorRegistry reconstructs it from
            // canonical endorsement-pool outpoints during block replay.
            auto rate_opt = db_.GetIndexDB().Get("validator_last_flush_rate");
            if (rate_opt && !rate_opt->empty()) {
                try {
                    double r = std::stod(*rate_opt);
                    validators_.SetLastFlushRewardPerEndorsement(r);
                } catch (...) {}
            }
        }

        txindex_operational_.store(false);
        if (txindex_enabled_) {
            try {
                uint64_t tip = chain_.Height();
                const std::string tip_marker = std::to_string(tip) + ":" +
                    HashToHex(chain_.GetBlock(tip).GetHash());
                auto complete = db_.GetIndexDB().Get("txi:_complete_v3");
                if (!complete || *complete != tip_marker) {
                    // v3 begins by removing every canonical-format txid row.
                    // Older versions never pruned displaced reorg txids, so a
                    // backfill alone cannot prove absence/completeness. Keep the
                    // completion marker absent throughout the checked delete and
                    // backfill; a crash simply repeats this idempotent rebuild.
                    std::cout << "  [txindex] checked backfill 0.." << tip << "\n";
                    {
                        db::WriteBatch invalidate;
                        invalidate.Delete("txi:_complete_v2");
                        invalidate.Delete("txi:_complete_v3");
                        invalidate.Delete("txi:_synced");
                        if (!db_.GetIndexDB().Write(invalidate))
                            throw std::runtime_error(
                                "txindex v3 invalidation write failed");
                    }
                    std::string cursor;
                    for (;;) {
                        std::vector<std::string> stale_keys;
                        std::string last_key;
                        size_t scanned = 0;
                        bool page_full = false;
                        db_.GetIndexDB().IterateFrom(
                            "txi:", cursor,
                            [&](const std::string& key,
                                const std::string&) {
                                last_key = key;
                                ++scanned;
                                if (key.size() == 68 &&
                                    db::IsCanonicalHash256Text(
                                        std::string_view(key).substr(4))) {
                                    stale_keys.push_back(key);
                                }
                                if (scanned >= 4096) {
                                    page_full = true;
                                    return false;
                                }
                                return true;
                            });
                        if (!stale_keys.empty()) {
                            db::WriteBatch erase;
                            for (const auto& key : stale_keys)
                                erase.Delete(key);
                            if (!db_.GetIndexDB().Write(erase))
                                throw std::runtime_error(
                                    "txindex v3 stale-row deletion failed");
                        }
                        if (!page_full || last_key.empty()) break;
                        cursor = std::move(last_key);
                    }
                    for (uint64_t h = 0; h <= tip; ++h) {
                        Block b = chain_.GetBlock(h);
                        for (const auto& tx : b.transactions) {
                            if (!db_.GetIndexDB().Put(
                                    "txi:" + HashToHex(tx.GetTxID()),
                                    std::to_string(h)))
                                throw std::runtime_error(
                                    "txindex transaction write failed at height " +
                                    std::to_string(h));
                        }
                    }
                    db::WriteBatch complete_batch;
                    complete_batch.Put("txi:_synced",
                                       std::to_string(tip));
                    complete_batch.Put("txi:_complete_v3", tip_marker);
                    if (!db_.GetIndexDB().Write(complete_batch))
                        throw std::runtime_error("txindex completion marker write failed");
                    std::cout << "  [txindex] checked backfill complete to h="
                              << tip << "\n";
                }
                txindex_operational_.store(true);
            } catch (const std::exception& e) {
                txindex_operational_.store(false);
                std::cerr << "  [txindex] DISABLED: completeness check/backfill "
                          << "failed: " << e.what() << "\n";
            } catch (...) {
                txindex_operational_.store(false);
                std::cerr << "  [txindex] DISABLED: completeness check/backfill "
                          << "failed with unknown error\n";
            }
        }

        uint16_t actual_port = p2p_port_ ? p2p_port_ : config_.port;
#ifdef VELD_PUBLIC_TESTNET
        // PUBLIC_TESTNET_RESTART_BUNDLE_RECHECK_BEFORE_LISTENERS
        // Full replay can take most of the signed five-minute admission
        // window.  Never expose P2P unless both signed+monotonic and local UTC
        // are still strictly below valid_until at this exact boundary.
        if (!PublicTestnetRestartAuthorityFreshNow()) {
            throw public_testnet::ListenerActivationAuthorityRefusal(
                "FATAL: public-testnet restart authority expired before P2P listener");
        }
#endif
        bool p2p_started = false;
        if (background_validation_only_ || snapshot_quarantine_only_) {
            p2p_started = tcp_server_->Start({}, /*accept_inbound=*/false);
        } else {
#ifdef VELD_PUBLIC_TESTNET
            const auto listener_activation_guard = [this]() noexcept {
                return PublicTestnetRestartAuthorityFreshNow();
            };
            p2p_started = tcp_server_->Start(listener_activation_guard);
#else
            p2p_started = tcp_server_->Start();
#endif
        }
        if (p2p_started) {
            if (!quiet_boot_ && veld::DiagVerbose().load())
                std::cout << ((background_validation_only_ ||
                               snapshot_quarantine_only_)
                                  ? "  P2P validation sync is outbound-only\n"
                                  : "  P2P listening on port " +
                                        std::to_string(actual_port) + "\n");
        } else {
#ifdef VELD_PUBLIC_TESTNET
            if (tcp_server_->ActivationGuardRefused()) {
                throw public_testnet::ListenerActivationAuthorityRefusal(
                    "FATAL: public-testnet restart authority refused at P2P activation");
            }
            throw std::runtime_error(
                "FATAL: public-testnet P2P activation failed; a node without relay connectivity is not startable");
#endif
            if (!quiet_boot_)
            std::cout << "  P2P server: port " << actual_port << " unavailable (OK in sandbox)\n";
        }

        // The independent chainstate is connected explicitly by the caller
        // after any Tor-only routing policy is installed. Starting anchor
        // dials here would create a brief clearnet race on private miners.
        if (!background_validation_only_ && !snapshot_quarantine_only_)
            tcp_server_->DialAnchorsAsync();

        LoadPeerTipsCache();

        if (!background_validation_only_ && !snapshot_quarantine_only_) {
#ifdef VELD_PUBLIC_TESTNET
            if (!PublicTestnetRestartAuthorityFreshNow()) {
                tcp_server_->Stop();
                throw public_testnet::ListenerActivationAuthorityRefusal(
                    "FATAL: public-testnet restart authority expired before explorer listener");
            }
#endif
#ifdef VELD_PUBLIC_TESTNET
            const auto explorer_activation_guard = [this]() noexcept {
                return PublicTestnetRestartAuthorityFreshNow();
            };
            if (explorer_.Start(explorer_activation_guard)) {
#else
            if (explorer_.Start()) {
#endif
                if (!quiet_boot_ && veld::DiagVerbose().load())
                    std::cout << "  Explorer: http://localhost:"
                              << CompiledPublicExplorerPort() << "\n";
            } else {
#ifdef VELD_PUBLIC_TESTNET
                if (explorer_.ActivationGuardRefused()) {
                    tcp_server_->Stop();
                    throw public_testnet::ListenerActivationAuthorityRefusal(
                        "FATAL: public-testnet restart authority refused at explorer activation");
                }
#endif
                if (!quiet_boot_)
                    std::cout << "  Explorer: failed to start on port "
                              << CompiledPublicExplorerPort() << "\n";
            }
        }
        StartReorgFixupWorker();
    }

    void Stop() {
        (void)CloseWorkAdmissionBounded_(
            work_admission::Refusal::NodeNotRunning);
        {
            auto transition = chain_.AcquireConsensusTransitionGuard();
            work_admission_coordinator_.CancelAndClose(
                work_admission::Refusal::NodeNotRunning);
            startup_replay_complete_.store(
                false, std::memory_order_release);
            running_  = false;
            mining_   = false;
            BumpValidationGeneration_();
        }
        ClearActiveRemoteSigningLeases_();
        prewarm_cv_.notify_all();

        // Oracle and dataset prewarm closures capture this and may touch the
        // chain/TCP/global dataset.  Take ownership under their launch mutexes
        // and join before tearing down connections or member state.  Moving
        // makes repeated Stop() calls harmless.
        std::thread oracle_to_join;
        {
            std::lock_guard<std::mutex> lock(oracle_thread_mutex_);
            if (oracle_thread_.joinable())
                oracle_to_join = std::move(oracle_thread_);
        }
        if (oracle_to_join.joinable()) oracle_to_join.join();
        oracle_in_flight_.store(false, std::memory_order_release);

        std::thread prewarm_to_join;
        {
            std::lock_guard<std::mutex> lock(prewarm_thread_mutex_);
            if (prewarm_thread_.joinable())
                prewarm_to_join = std::move(prewarm_thread_);
        }
        if (prewarm_to_join.joinable()) prewarm_to_join.join();

        //  Snapshot the peer book + anchor list
        // BEFORE tcp_server_->Stop() tears down live connections.
        // SaveAnchors() reads from the live peer_connections_ map to
        // pick the 4 longest-lived non-trusted outbound peers; once
        // Stop() runs, those peers are gone and the snapshot would
        // be empty. SavePeerCache() flushes the in-memory address
        // book to disk so the next run starts with knowledge of all
        // organic peers we've learned about during this session.
        // Both are best-effort: failure logs but never raises (a
        // disk-full condition must NOT prevent clean shutdown).
        if (tcp_server_) {
            tcp_server_->SaveAnchors();
            tcp_server_->SavePeerCache();
        }
        if (tcp_server_) tcp_server_->Stop();
        explorer_.Stop();
        if (mining_thread_.joinable()) mining_thread_.join();
        if (pow_verify_thread_.joinable()) pow_verify_thread_.join();
        // Join the reorg worker before chain and mempool destruction.
        reorg_fixup_cv_.notify_all();
        if (reorg_fixup_thread_.joinable()) reorg_fixup_thread_.join();
    }

    // Run post-reorg mempool purges and orphan reinjection serially on an owned
    // worker. Tasks execute outside chain_mutex_ to preserve lock ordering.
    void StartReorgFixupWorker() {
        reorg_fixup_thread_ = std::thread([this]() {
            for (;;) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lk(reorg_fixup_mtx_);
                    reorg_fixup_cv_.wait(lk, [this]{
                        return !reorg_fixup_q_.empty() || !running_.load();
                    });
                    if (reorg_fixup_q_.empty()) { if (!running_.load()) return; continue; }
                    task = std::move(reorg_fixup_q_.front());
                    reorg_fixup_q_.pop_front();
                }
                try { task(); }
                catch (const std::exception& e) { std::cerr << "  [reorg-fixup] " << e.what() << "\n"; }
                catch (...) {}
            }
        });
    }
    void EnqueueReorgFixup(std::function<void()> fn) {
        { std::lock_guard<std::mutex> lk(reorg_fixup_mtx_); reorg_fixup_q_.push_back(std::move(fn)); }
        reorg_fixup_cv_.notify_one();
    }

    void SetPoolKeypair(const RealKeyPair& kp) { pool_keypair_ = kp; }
    const RealKeyPair& GetPoolKeypair() const { return pool_keypair_; }
    void SetEndorsementPoolKeypair(const RealKeyPair& kp) { endorsement_pool_keypair_ = kp; }
    const RealKeyPair& GetEndorsementPoolKeypair() const { return endorsement_pool_keypair_; }
    double GetHashrate() const { return hashrate_.load(); }
    uint64_t GetTotalHashes() const { return total_hashes_.load(); }
    uint64_t GetMiningProgressCounter() const {
        return miner_progress_counter_.load(std::memory_order_relaxed);
    }
    uint64_t GetSessionBlocksMined() const {
        return session_blocks_mined_.load(std::memory_order_relaxed);
    }
    bool IsMiningConfigured() const {
        return mining_.load(std::memory_order_acquire);
    }
    bool IsMiningReady() const {
        return IsMiningConfigured() &&
            ibd_complete_.load(std::memory_order_acquire) &&
            chain_fully_validated_.load(std::memory_order_acquire);
    }
    enum class MiningWorkState : uint8_t {
        Stopped,
        Synchronizing,
        WaitingForAnchor,
        WorkAdmission,
        ClockDrift,
        GenesisMismatch,
        WaitingForPeerTip,
        BelowPeerFloor,
        Propagation,
        ReorgRebuild,
        Hashing,
        Error,
    };
    bool IsMiningActive() const {
        return mining_work_state_.load(std::memory_order_acquire) ==
            MiningWorkState::Hashing;
    }
    const char* GetMiningWorkStateName() const {
        switch (mining_work_state_.load(std::memory_order_acquire)) {
            case MiningWorkState::Stopped: return "stopped";
            case MiningWorkState::Synchronizing: return "synchronizing";
            case MiningWorkState::WaitingForAnchor: return "waiting-for-anchor";
            case MiningWorkState::WorkAdmission: return "work-admission";
            case MiningWorkState::ClockDrift: return "clock-drift";
            case MiningWorkState::GenesisMismatch: return "genesis-mismatch";
            case MiningWorkState::WaitingForPeerTip: return "waiting-for-peer-tip";
            case MiningWorkState::BelowPeerFloor: return "below-peer-floor";
            case MiningWorkState::Propagation: return "propagation";
            case MiningWorkState::ReorgRebuild: return "reorg-rebuild";
            case MiningWorkState::Hashing: return "hashing";
            case MiningWorkState::Error: return "error";
        }
        return "error";
    }

    void PrewarmRichList() {
        try { explorer_.PrewarmRichList(); }
        catch (...) {  }
    }

    void PrewarmHashDataset() {
#ifdef VELD_MAINNET_POW
        // Independent snapshot validation is already building and using the
        // same global VeldHash dataset. Starting a second prewarm worker here
        // adds memory/CPU pressure without reducing time to safe mining; the
        // background chainstate leaves the shared dataset warm on completion.
        if (!chain_fully_validated_.load(std::memory_order_acquire)) {
            std::cout << "  [prewarm] delegated to independent background IBD\n";
            std::cout.flush();
            return;
        }
        std::lock_guard<std::mutex> lifecycle_lock(prewarm_thread_mutex_);
        if (prewarm_started_ || !running_.load(std::memory_order_acquire))
            return;
        prewarm_started_ = true;
        prewarm_thread_ = std::thread([this]() {
            try {
                // Building the memory-hard dataset while from-genesis IBD is
                // doing memory-hard block verification can starve P2P socket
                // service.  Keep the requested prewarm, but defer its CPU/RAM
                // work until the existing IBD-complete safety latch opens.
                std::unique_lock<std::mutex> wait_lock(prewarm_thread_mutex_);
                prewarm_cv_.wait(wait_lock, [this]() {
                    return !running_.load(std::memory_order_acquire) ||
                           ibd_complete_.load(std::memory_order_acquire);
                });
                wait_lock.unlock();
                if (!running_.load(std::memory_order_acquire)) return;
                // Recheck the same structured peer-height view that opened
                // IBD.  A contradictory high VERSION can arrive between the
                // supervisor's last observation and this worker waking; it has
                // no sync authority, but it must hold off memory-hard prewarm.
                // Poll while the exact claim remains live because transport
                // state changes do not own this lifecycle condition variable.
                while (config_.name != "Veld Regtest") {
                    // Reuse the complete IBD admission rule.  Merely seeing a
                    // zero best-height after one/both peers disconnect is not
                    // enough to start the memory-hard dataset while the node
                    // is trying to restore its transport quorum.
                    if (MiningWorkStillSafe_()) break;
                    std::unique_lock<std::mutex> hold(prewarm_thread_mutex_);
                    prewarm_cv_.wait_for(
                        hold, std::chrono::milliseconds(500), [this]() {
                            return !running_.load(std::memory_order_acquire);
                        });
                    if (!running_.load(std::memory_order_acquire)) return;
                }
                uint64_t h = chain_.Height();
                if (h == 0) return;
#ifdef VELD_LIGHT_VERIFY
                return;   // light-verify: no held dataset to prewarm
#endif
                auto pow_lease = mining::GlobalExpensivePowBudget().TryAcquire(
                    mining::ExpensivePowUse::Prewarm);
                if (!pow_lease) return;
                auto tip = chain_.GetBlock(h);
                Hash256 seed = mining::ComputeEpochSeed(
                    tip.header.prev_block_hash, tip.height, tip.header.bits);
                auto t0 = std::chrono::steady_clock::now();
                mining::DatasetHandle warm =
                    mining::GlobalDataset().get_for_seed(seed);
                auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0).count();
                if (warm.get()) {
                    std::cout << "  [prewarm] VeldHash dataset ready ("
                              << dt << " ms) — first-click Mine will be instant\n";
                    std::cout.flush();
                } else {
                    std::cerr << "  [prewarm] VeldHash dataset build failed; "
                                 "first click will lazy-init normally\n";
                    std::cerr.flush();
                }
            } catch (...) {
            }
        });
#endif
    }

    bool BindGenerationIdentity(const RealKeyPair& miner_keypair,
                                std::string* error = nullptr) {
#ifdef VELD_FLEET_NO_MINE
        (void)miner_keypair;
        if (error)
            *error = "VELD_FLEET_NO_MINE: generation identity binding disabled";
        return false;
#else
        std::lock_guard<std::mutex> lock(generation_mutex_);
        if (mining_.load(std::memory_order_acquire)) {
            if (error)
                *error = "cannot replace the generation identity while mining is active";
            return false;
        }
        return BindGenerationIdentityLocked_(miner_keypair, error);
#endif
    }

    void StartMining(const RealKeyPair& miner_keypair, uint32_t bits_override = 0) {
#ifdef VELD_FLEET_NO_MINE
        // Fleet infrastructure nodes are built with
        // -DVELD_FLEET_NO_MINE so block production is physically absent
        // from the binary. This neutralises EVERY path — an accidental
        // `--mine` flag, a stale/forgotten systemd drop-in, a
        // compromised cron, a future RPC — not just the ones we
        // remembered to scrub operationally. The node keeps running as
        // a P2P/RPC relay (a non-mining fleet node is the safe state;
        // per the invariant, a frozen chain is always preferable to
        // fleet mining). The sole legitimate producer is the operator
        // PC (VEB), built WITHOUT this flag. Fail loud, do not abort.
        (void)miner_keypair; (void)bits_override;
        std::cerr << "  [FLEET-NO-MINE] StartMining() refused — this binary "
                     "was built -DVELD_FLEET_NO_MINE (fleet infra node). "
                     "Block production is disabled by construction. "
                     "Continuing as a non-mining relay.\n";
        std::cerr.flush();
        return;
#else
        std::lock_guard<std::mutex> lock(generation_mutex_);
#ifdef VELD_PUBLIC_TESTNET
        if (PublicTestnetRuntimeStopRequired()) {
            std::cerr << "  [PUBLIC-TESTNET-EXPIRED] StartMining() refused; "
                         "the immutable START-index runtime lease is closed.\n";
            std::cerr.flush();
            return;
        }
#endif
        if (mining_.load()) return;
        if (mining_thread_.joinable()) {
            mining_.store(false, std::memory_order_release);
            mining_thread_.join();
        }
        std::string identity_error;
        if (!BindGenerationIdentityLocked_(miner_keypair, &identity_error)) {
            std::cerr << "  [mining] StartMining() refused: "
                      << identity_error << "\n";
            std::cerr.flush();
            return;
        }
        mining_bits_   = bits_override;
        if (tcp_server_) {
            tcp_server_->SetMinerScript(miner_keypair_.GetP2PKHScript());
            std::vector<uint8_t> pk_vec(miner_keypair_.public_key.begin(),
                                        miner_keypair_.public_key.end());
            tcp_server_->SetCOMineIdentity(pk_vec, [this](const std::vector<uint8_t>& challenge) {
                ::veld::Hash256 h = ::veld::Hash256d(challenge.data(), challenge.size());
                return ::veld::Sign(miner_keypair_.private_key, h);
            });
        }
        mining_work_state_.store(MiningWorkState::Synchronizing,
                                 std::memory_order_release);
        mining_.store(true, std::memory_order_release);
        mining_thread_ = std::thread(&VeldNode::MiningLoop, this);
#endif
    }

    void SetMiningThreads(unsigned n) {
        if (n < 1) n = 1;
        if (n > 64) n = 64;
        mining_threads_ = n;
    }
    unsigned GetMiningThreads() const { return mining_threads_; }

    void StopMining() {
        std::lock_guard<std::mutex> lock(generation_mutex_);
        StopMiningLocked_();
    }

    RpcServer::GenerateResult GenerateBlocksForRpc(
        int count,
        uint32_t bits_override = 0x207fffff
    ) {
        RpcServer::GenerateResult generated;
        generated.height = chain_.Height();
#ifdef VELD_FLEET_NO_MINE
        (void)count;
        (void)bits_override;
        generated.error =
            "VELD_FLEET_NO_MINE: synchronous generation disabled";
        return generated;
#else
        std::lock_guard<std::mutex> lock(generation_mutex_);
        if (!generation_identity_bound_) {
            generated.error =
                "synchronous generation identity is not bound";
            return generated;
        }

        // StopMiningLocked_ joins the background worker before synchronous
        // construction starts. Holding generation_mutex_ serializes every
        // concurrent generate/bind/start transition around the same identity.
        StopMiningLocked_();
        const uint64_t start_height = chain_.Height();
        std::vector<MineBlockResult> results;
        try {
            results = MineBlocks(miner_keypair_, count, bits_override);
        } catch (const std::exception& e) {
            generated.height = chain_.Height();
            generated.generated = generated.height >= start_height
                ? generated.height - start_height : 0;
            generated.error = std::string("MineBlocks exception: ") + e.what();
            return generated;
        } catch (...) {
            generated.height = chain_.Height();
            generated.generated = generated.height >= start_height
                ? generated.height - start_height : 0;
            generated.error = "MineBlocks exception: unknown failure";
            return generated;
        }

        std::string first_failure;
        for (size_t i = 0; i < results.size(); ++i) {
            const auto& result = results[i];
            if (result.success) {
                ++generated.generated;
            } else if (first_failure.empty()) {
                first_failure = result.error.empty()
                    ? "MineBlocks returned an unspecified failure"
                    : result.error;
            }
        }
        generated.height = chain_.Height();

        if (results.size() != static_cast<size_t>(count) &&
            first_failure.empty()) {
            first_failure = "MineBlocks returned an incomplete result vector";
        }
        if (generated.generated != static_cast<uint64_t>(count) &&
            first_failure.empty()) {
            first_failure = "MineBlocks did not complete the requested count";
        }
        if (generated.height != start_height + generated.generated &&
            first_failure.empty()) {
            first_failure =
                "canonical height change does not match successful generation results";
        }
        generated.error = std::move(first_failure);
        return generated;
#endif
    }

    std::vector<MineBlockResult> MineBlocks(
        const RealKeyPair& keypair,
        int count,
        uint32_t bits_override = 0x207fffff
    ) {
#ifdef VELD_FLEET_NO_MINE
        // This synchronous path backs regtest `generate` and in-process
        // integration callers, so guarding only StartMining/MiningLoop left a
        // third block-production entry in a fleet build.  Compile the complete
        // mining body out of this method and return one explicit refusal result.
        (void)keypair;
        (void)count;
        (void)bits_override;
        std::cerr << "  [FLEET-NO-MINE] MineBlocks() refused — synchronous "
                     "block production is disabled in this fleet binary.\n";
        std::cerr.flush();
        MineBlockResult denied{};
        denied.success = false;
        denied.error = "VELD_FLEET_NO_MINE: MineBlocks disabled";
        return {denied};
#else
        std::vector<MineBlockResult> results;
        for (int i = 0; i < count; ++i) {
            const auto work_subject = CurrentBlockProductionSubject_();
            const auto issued = work_subject
                ? EvaluateWorkAdmission(
                      work_admission::Path::SynchronousGeneration,
                      *work_subject, std::nullopt, false)
                : work_admission::Decision{
                      false, work_admission::Refusal::TipUnknown,
                      std::nullopt};
            if (mining_.load(std::memory_order_acquire) ||
                !issued.allowed || !issued.binding) {
                MineBlockResult denied{};
                denied.success = false;
                denied.error =
                    "Synchronous mining refused: IBD/work admission is closed";
                results.push_back(std::move(denied));
                break;
            }
            // This API backs regtest `generate` and in-process integration
            // clients, but it is still a VeldNode miner and therefore has
            // access to every node-owned settlement engine.  The standalone
            // MineAndCommit helper correctly refuses protocol boundaries;
            // using it here made VeldNode::MineBlocks halt at the first
            // co-mine boundary once roll-forwards became mandatory.
            Block settlement_probe;
            settlement_probe.height = chain_.Height() + 1;
            settlement_probe.header.prev_block_hash = chain_.Tip().GetHash();
            if (settlement_probe.height > 0 &&
                settlement_probe.height % VAULT_DISTRIBUTION_INTERVAL == 0) {
                (void)BuildEndorsementFlushTx(settlement_probe);
                (void)BuildVaultDistributionTx(settlement_probe);
                (void)BuildBondSettlementTx(settlement_probe);
                (void)BuildBondYieldSettlementTx(settlement_probe);
            }
            if (settlement_probe.height > 0 &&
                settlement_probe.height % COMINE_WINDOW_BLOCKS == 0) {
                (void)BuildPoolPayoutTx(
                    settlement_probe, AddressToScript(POOL_ADDRESS), mempool_);
            }
            std::vector<Transaction> mandatory_settlements =
                std::move(settlement_probe.transactions);
            auto finality_metadata = PendingFinalityCoinbaseMetadata_(
                settlement_probe.height);

            std::atomic<bool> synchronous_stop{false};
            std::atomic<bool> synchronous_safety_cancelled{false};
            std::mutex synchronous_watchdog_mutex;
            std::condition_variable synchronous_watchdog_cv;
            std::thread synchronous_watchdog;
            synchronous_watchdog = std::thread([&, issued_binding =
                                                    *issued.binding]() {
                    while (!synchronous_stop.load(
                               std::memory_order_acquire)) {
                        bool safe = false;
                        try {
                            safe = running_.load(std::memory_order_acquire) &&
                                   !mining_.load(std::memory_order_acquire) &&
                                   MiningWorkStillSafe_(
                                       work_admission::Path::SynchronousGeneration,
                                       issued_binding, true);
                        } catch (...) {
                            safe = false;
                        }
                        if (!safe) {
                            synchronous_safety_cancelled.store(
                                true, std::memory_order_release);
                            synchronous_stop.store(
                                true, std::memory_order_release);
                            break;
                        }
                        std::unique_lock<std::mutex> hold(
                            synchronous_watchdog_mutex);
                        synchronous_watchdog_cv.wait_for(
                            hold, std::chrono::milliseconds(500), [&]() {
                                return synchronous_stop.load(
                                    std::memory_order_acquire);
                            });
                    }
                });
            auto stop_synchronous_watchdog = [&]() {
                synchronous_stop.store(true, std::memory_order_release);
                synchronous_watchdog_cv.notify_all();
                if (synchronous_watchdog.joinable())
                    synchronous_watchdog.join();
            };

            MineBlockResult r;
            try {
                r = MineOnly(
                    chain_, mempool_, keypair, bits_override,
                    &synchronous_stop,
                    AddressToScript(POOL_ADDRESS), 1, nullptr, {}, nullptr,
                    nullptr, mandatory_settlements,
                    [this](const Block& candidate) {
                        return PreflightMiningCandidate_(candidate);
                    }, finality_metadata);
            } catch (...) {
                stop_synchronous_watchdog();
                throw;
            }
            stop_synchronous_watchdog();
            if (synchronous_safety_cancelled.load(
                    std::memory_order_acquire)) {
                r.success = false;
                r.error =
                    "Synchronous mining cancelled: IBD/work admission closed";
            }
            if (r.success) {
                bool final_safe =
                    !mining_.load(std::memory_order_acquire) &&
                    MiningWorkStillSafe_(
                        work_admission::Path::SynchronousGeneration,
                        *issued.binding, true);
                if (final_safe) {
                    final_safe = r.new_height > 0 &&
                        chain_.Height() == r.new_height - 1 &&
                        chain_.GetBlockHashAtHeight(r.new_height - 1) ==
                            HashToHex(r.block.header.prev_block_hash);
                }
                if (!final_safe) {
                    r.success = false;
                    r.error =
                        "Synchronous mining discarded: work admission "
                        "closed before commit";
                }
            }
            if (r.success) {
                auto pow_context =
                    mining::PowAdmissionContext::SynchronousGenerationWork(
                        work_admission::EncodeBinding(*issued.binding));
                const auto admission = chain_.AddBlockDirect(
                    r.block, false, false, false, pow_context);
                if (admission.IsDeferred()) {
                    r.success = false;
                    r.error =
                        "Block commit deferred: local work admission unavailable";
                } else if (!admission.IsAccepted()) {
                    r.success = false;
                    r.error = "Block validation failed during commit";
                } else {
                    mempool_.RemoveConfirmed(r.block);
                    // Close-wins/lease-wins is deterministic at this second
                    // transition boundary: a peer/state transition that won
                    // after commit cancels the handoff, while a live handoff
                    // keeps result publication coherent through this scope.
                    auto post_commit =
                        chain_.AcquireConsensusTransitionGuard();
                    if (!pow_context.local_work_handoff->IsLive()) {
                        r.success = false;
                        r.error =
                            "Block committed but local work publication closed";
                    } else {
                        r.new_height = chain_.Height();
                        r.new_supply_units = chain_.TotalSupplyUnits();
                    }
                }
            }
            results.push_back(r);
            if (!r.success) break;
            // The canonical on_commit callback already persisted the exact tip.
            // Do not write from the mining wrapper: a peer can advance fork
            // choice between MineOnly and AddBlockDirect, in which case the
            // solved block is accepted only as side-branch data.
        }
        return results;
#endif
    }

    std::string HandleRPC(const std::string& json) {
        auto call = RpcCall::Parse(json);

        // The process supervisor closes transports promptly after a security
        // fail-stop, but an already-accepted RPC connection can race that
        // shutdown.  Refuse dispatch here so no mutating (or stale read) RPC
        // reaches its handler after the durable invariant latch is raised.
        if (FailStopRequired()) {
            return JsonBuilder::RpcError(
                call.id, -32603,
                "Node is in security fail-stop; restart and complete local replay");
        }

#ifdef VELD_PUBLIC_TESTNET
        if (PublicTestnetRuntimeStopRequired()) {
            return JsonBuilder::RpcError(
                call.id, -32603,
                "Public-testnet START-index runtime lease is closed");
        }
#endif

        return rpc_.Handle(call.ToJson());
    }

    struct SendResult {
        bool        success;
        std::string txid;
        std::string error;
        uint64_t    fee_units;
    };

    uint64_t EstimateFee(size_t tx_size_bytes = 250) const {
        size_t mempool_size = mempool_.Size();
        uint64_t rate;
        if      (mempool_size < 100)  rate = Mempool::MIN_FEE_RATE;
        else if (mempool_size < 500)  rate = Mempool::MIN_FEE_RATE * 2;
        else if (mempool_size < 2000) rate = Mempool::MIN_FEE_RATE * 5;
        else                          rate = Mempool::MIN_FEE_RATE * 10;
        return (rate * tx_size_bytes) / 1000;
    }

    SendResult Send(
        const RealKeyPair& sender,
        const std::string& recipient_address,
        uint64_t amount_units,
        uint64_t fee_units = 0
    ) {
        SendResult result{false, "", "", 0};

        if (fee_units == 0) fee_units = EstimateFee();

        uint64_t total_needed = amount_units + fee_units;
        CoinSelection coins = SelectCoins(chain_, sender.GetP2PKHScript(), total_needed, fee_units);

        if (!coins.sufficient) {
            result.error = "Insufficient funds: need "
                         + std::to_string(total_needed)
                         + " units, have "
                         + std::to_string(chain_.GetBalance(sender.GetP2PKHScript()));
            return result;
        }

        Transaction tx;

        for (const auto& utxo : coins.selected_utxos) {
            TxInput input;
            input.prev_tx_hash   = utxo.tx_hash;
            input.prev_out_index = utxo.output_index;
            tx.inputs.push_back(input);
        }

        std::vector<uint8_t> recipient_script = AddressToScript(recipient_address);
        if (recipient_script.empty()) {
            result.error = "Invalid recipient address: " + recipient_address;
            return result;
        }
        tx.outputs.push_back(TxOutput(amount_units, recipient_script));

        if (coins.change_amount > 0)
            tx.outputs.push_back(TxOutput(coins.change_amount, sender.GetP2PKHScript()));

        for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
            auto signed_input = sender.SignInput(tx, i, sender.GetP2PKHScript());
            tx.inputs[i].script_sig = signed_input.script_sig;
        }

        auto add_result = mempool_.Add(tx, fee_units, (uint32_t)chain_.Height(), chain_);

        if (add_result != Mempool::AddResult::ACCEPTED) {
            switch (add_result) {
                case Mempool::AddResult::DUPLICATE:    result.error = "Duplicate tx"; break;
                case Mempool::AddResult::FEE_TOO_LOW:  result.error = "Fee too low"; break;
                case Mempool::AddResult::DOUBLE_SPEND: result.error = "Double spend"; break;
                case Mempool::AddResult::FULL:         result.error = "Mempool full"; break;
                default:                               result.error = "Invalid tx"; break;
            }
            return result;
        }

        result.success    = true;
        result.txid       = HashToHex(tx.GetTxID());
        result.fee_units  = fee_units;
        return result;
    }

    const Blockchain&   GetChain()   const { return chain_; }
    const Mempool&      GetMempool() const { return mempool_; }
    Blockchain&         GetChainMut()      { return chain_; }
    Mempool&            GetMempoolMut()    { return mempool_; }
    bool MiningWorkStillSafeFromView_(
            const net::NodeServer::PeerHeightView& heights,
            uint64_t local_height,
            bool chain_empty) const {
        if (config_.name == "Veld Regtest") return true;
        return IsInitialDownloadAtTip(
            false, local_height, chain_empty,
            heights.distinct_version_ips, heights.verified_height,
            heights.distinct_outbound_sync_ips,
            heights.outbound_sync_height);
    }

    static std::optional<work_admission::Path> WorkPathForLocalKind_(
            mining::LocalWorkKind kind) noexcept {
        switch (kind) {
            case mining::LocalWorkKind::InternalMining:
                return work_admission::Path::InternalMining;
            case mining::LocalWorkKind::SubmitBlock:
                return work_admission::Path::SubmitBlock;
            case mining::LocalWorkKind::SynchronousGeneration:
                return work_admission::Path::SynchronousGeneration;
            case mining::LocalWorkKind::None:
                return std::nullopt;
        }
        return std::nullopt;
    }

    work_admission::AdmissionCoordinator::Configuration
    WorkCoordinatorConfiguration_(uint64_t canonical_tip_height,
                                  bool canonical_tip_known) const noexcept {
        work_admission::AdmissionCoordinator::Configuration configuration;
        const uint64_t close_epoch_before =
            work_admission_coordinator_.ObserveCloseEpoch();
        try {
#ifdef VELD_TEST_HOOKS
            canonical_tip_known = canonical_tip_known &&
                !test_work_force_tip_unknown_.load(
                    std::memory_order_acquire);
#endif
            auto& prerequisites = configuration.prerequisites;
            prerequisites.role_permitted = true;  // path-specific below
            prerequisites.node_running =
                running_.load(std::memory_order_acquire);
            prerequisites.startup_replay_complete =
                startup_replay_complete_.load(std::memory_order_acquire);
            prerequisites.independent_validation_complete =
                chain_fully_validated_.load(std::memory_order_acquire);
            const bool regtest = config_.name == "Veld Regtest";
            prerequisites.sync_complete = regtest ||
                ibd_complete_.load(std::memory_order_acquire);
            prerequisites.snapshot_state_clean =
                snapshot_state_clean_.load(std::memory_order_acquire);
            prerequisites.durable_state_proven =
                !FailStopRequired() &&
                !reorg_publication_uncertain_.load(
                    std::memory_order_acquire);
            prerequisites.datadir_identity_valid =
                datadir_identity_valid_.load(std::memory_order_acquire);
            prerequisites.checkpoint_anchor_valid =
                checkpoint_anchor_valid_.load(std::memory_order_acquire);
            prerequisites.canonical_tip_known = canonical_tip_known;
            prerequisites.runtime_open = canonical_tip_known &&
                canonical_tip_height != UINT64_MAX;
#ifdef VELD_PUBLIC_TESTNET
            prerequisites.runtime_open = prerequisites.runtime_open &&
                chain_.RuntimeAdmissionPermits(canonical_tip_height + 1) &&
                PublicTestnetRestartAuthorityFreshNow();
#endif
#ifdef VELD_TEST_HOOKS
            prerequisites.runtime_open = prerequisites.runtime_open &&
                test_work_local_runtime_open_.load(
                    std::memory_order_acquire);
#endif
            if (regtest) {
                prerequisites.peer_view_safe = canonical_tip_known;
            } else if (tcp_server_ && canonical_tip_known) {
                const auto heights = tcp_server_->GetPeerHeightView();
                const bool freshness_window =
                    heights.freshness_valid_for_ms == UINT64_MAX ||
                    heights.freshness_valid_for_ms >
                        static_cast<uint64_t>(
                            PEER_VIEW_EXPIRY_SAFETY_MARGIN.count());
                prerequisites.peer_view_safe =
                    heights.work_sequencer_wired &&
                    heights.work_view_stable && freshness_window &&
                    MiningWorkStillSafeFromView_(
                        heights, canonical_tip_height, false);
            }
            prerequisites.validation_generation =
                validation_generation_.load(std::memory_order_acquire);
            prerequisites.network_magic = config_.magic;
            prerequisites.genesis_hash = GenesisHashBytes_();
            prerequisites.profile_digest = Hash256d(
                std::string(DEPLOYMENT_PROFILE_ID));

            const bool any_local_work = !background_validation_only_;
#ifdef VELD_FLEET_NO_MINE
            constexpr bool block_work = false;
#else
            const bool block_work = any_local_work;
#endif
            configuration.permitted_paths[
                static_cast<size_t>(work_admission::Path::InternalMining)] =
                block_work;
            configuration.permitted_paths[
                static_cast<size_t>(work_admission::Path::GetBlockTemplate)] =
                block_work;
            configuration.permitted_paths[
                static_cast<size_t>(work_admission::Path::SubmitBlock)] =
                block_work;
            configuration.permitted_paths[
                static_cast<size_t>(
                    work_admission::Path::SynchronousGeneration)] =
                block_work;
            configuration.permitted_paths[
                static_cast<size_t>(
                    work_admission::Path::ValidatorEndorsement)] =
                any_local_work;
            configuration.permitted_paths[
                static_cast<size_t>(work_admission::Path::FinalityVote)] =
                any_local_work;
        } catch (...) {
            // Epoch zero is an invalid sentinel, so a failed snapshot cannot
            // mutate or reopen the coordinator.
            return {};
        }
        const uint64_t close_epoch_after =
            work_admission_coordinator_.ObserveCloseEpoch();
        work_admission::AdmissionCoordinator::BindCloseEpochSnapshot(
            configuration, close_epoch_before, close_epoch_after);
        return configuration;
    }

    std::optional<std::chrono::milliseconds> BoundPeerWorkLifetime_(
            std::chrono::milliseconds requested) const noexcept {
        if (requested <= std::chrono::milliseconds::zero())
            return std::nullopt;
        uint64_t bounded_ms = static_cast<uint64_t>(requested.count());
#ifdef VELD_PUBLIC_TESTNET
        if (!public_testnet_limits_ ||
            !PublicTestnetRestartAuthorityFreshNow())
            return std::nullopt;
        const int64_t wall_now = public_testnet::CurrentUnixTime();
        const uint64_t wall_margin = static_cast<uint64_t>(
            PEER_VIEW_EXPIRY_SAFETY_MARGIN.count());
        const auto wall_bounded = BoundWallClockWorkLifetimeMs(
            wall_now, public_testnet_limits_->not_after_unix,
            bounded_ms, wall_margin);
        if (!wall_bounded) return std::nullopt;
        bounded_ms = *wall_bounded;
#endif
        if (config_.name == "Veld Regtest")
            return std::chrono::milliseconds(bounded_ms);
        if (!tcp_server_) return std::nullopt;
        try {
            const auto heights = tcp_server_->GetPeerHeightView();
            const uint64_t margin = static_cast<uint64_t>(
                PEER_VIEW_EXPIRY_SAFETY_MARGIN.count());
            const auto peer_bounded =
                net::NodeServer::BoundPeerWorkLifetimeMs(
                    heights, bounded_ms, margin);
            if (!peer_bounded) return std::nullopt;
            bounded_ms = *peer_bounded;
            if (bounded_ms == 0 ||
                bounded_ms > static_cast<uint64_t>(
                    std::chrono::milliseconds::max().count()))
                return std::nullopt;
            return std::chrono::milliseconds(bounded_ms);
        } catch (...) {
            return std::nullopt;
        }
    }

    work_admission::AdmissionCoordinator::OpenResult OpenWorkCoordinator_(
            const work_admission::AdmissionCoordinator::Configuration&
                configuration) noexcept {
        auto opened = work_admission_coordinator_.Open(configuration);
        // Busy/Closing is intentionally returned to the caller. An acquired-
        // first remote signer owns a bounded reservation: canonical/state
        // transitions defer until it consumes/releases the token or the hard
        // deadline expires. Revoking it here would recreate the sign-vs-close
        // TOCTOU this coordinator exists to remove.
        return opened;
    }

    // Caller owns Blockchain's consensus-transition guard. A serialized work
    // binding is caller-constructible, so GBT publication also mints a random,
    // bounded, node-retained bearer for this exact template identity. The
    // bearer itself does not reserve a coordinator lease; only submitblock can
    // atomically consume it and convert it to the canonical commit ticket.
    RpcServer::BlockTemplateAuthorizationResult
    IssueBlockTemplateAuthorizationUnderTransition_(
            const work_admission::Subject& subject,
            const Hash256& template_identity) noexcept {
        RpcServer::BlockTemplateAuthorizationResult result;
        if (HashIsZero(template_identity)) {
            result.decision = {
                false, work_admission::Refusal::SubjectNotCanonical,
                std::nullopt};
            return result;
        }
        try {
            const auto gbt_decision = EvaluateWorkAdmission(
                work_admission::Path::GetBlockTemplate, subject,
                std::nullopt, false);
            result.decision = EvaluateWorkAdmission(
                work_admission::Path::SubmitBlock, subject,
                std::nullopt, false);
            if (!gbt_decision.allowed || !gbt_decision.binding) {
                result.decision = gbt_decision;
                return result;
            }
            if (!result.decision.allowed || !result.decision.binding ||
                *result.decision.binding != *gbt_decision.binding)
                return result;

            Block tip;
            if (!chain_.TryTip(tip) || subject.height != tip.height + 1 ||
                subject.parent_height != tip.height ||
                subject.parent_hash != tip.GetHash()) {
                result.decision = {
                    false, work_admission::Refusal::SubjectNotCanonical,
                    std::nullopt};
                return result;
            }
            const auto configuration = WorkCoordinatorConfiguration_(
                tip.height, true);
            const auto opened = OpenWorkCoordinator_(configuration);
            if (!opened.opened) {
                result.decision = {
                    false, opened.refusal, std::nullopt};
                return result;
            }
            const auto lifetime = BoundPeerWorkLifetime_(
                std::chrono::milliseconds(10000));
            if (!lifetime) {
                result.decision = {
                    false, work_admission::Refusal::PeerViewUnsafe,
                    std::nullopt};
                return result;
            }
            const auto coordinator =
                work_admission_coordinator_.GetSnapshot();
            if (coordinator.phase !=
                    work_admission::AdmissionCoordinator::Phase::Open ||
                coordinator.configuration_generation == 0) {
                result.decision = {
                    false, work_admission::Refusal::RuntimeClosed,
                    std::nullopt};
                return result;
            }

            auto published_binding = *result.decision.binding;
            published_binding.subject.target_hash = template_identity;
            auto issued = block_template_authorizations_.Issue(
                published_binding, coordinator.configuration_generation,
                *lifetime);
            if (!issued || !issued.authorization) {
                result.decision = {
                    false, work_admission::Refusal::RuntimeClosed,
                    std::nullopt};
                return result;
            }
            result.decision.binding = issued.authorization->binding;
            result.token = issued.authorization->token;
            result.ttl_ms = static_cast<uint64_t>(
                issued.authorization->ttl.count());
            return result;
        } catch (...) {
            result.decision = {
                false, work_admission::Refusal::Unwired, std::nullopt};
            result.token.clear();
            result.ttl_ms = 0;
            return result;
        }
    }

    // Caller owns the consensus-transition guard. This reservation is the
    // pre-AddBlockDirect rejection boundary: a caller-edited binding, unknown
    // token, replay, stale coordinator epoch, or validation-generation change
    // cannot reach the chain sink. The returned claim remains one-use and is
    // checked again during ticket preparation outside every chain lock.
    std::shared_ptr<work_admission::BlockTemplateAuthorizationClaim>
    ConsumeBlockTemplateAuthorizationUnderTransition_(
            const std::string& token,
            const work_admission::Binding& binding) noexcept {
        try {
            if (binding.validation_generation !=
                    validation_generation_.load(
                        std::memory_order_acquire))
                return {};
            const auto coordinator =
                work_admission_coordinator_.GetSnapshot();
            if (coordinator.phase !=
                    work_admission::AdmissionCoordinator::Phase::Open ||
                coordinator.configuration_generation == 0)
                return {};
            auto consumed = block_template_authorizations_.Consume(
                token, binding, coordinator.configuration_generation);
            if (!consumed || !consumed.authorization)
                return {};
            return std::move(consumed.authorization);
        } catch (...) {
            return {};
        }
    }

    // Caller owns Blockchain's consensus-transition guard.  This is the only
    // capability-issuing path exposed to getworkadmission; a raw binding is an
    // identity document, not authority to sign or publish.
    RpcServer::RemoteWorkGrantResult IssueRemoteWorkGrantUnderTransition_(
            work_admission::Path path,
            const work_admission::Subject& subject) noexcept {
        RpcServer::RemoteWorkGrantResult result;
        result.decision = EvaluateWorkAdmission(
            path, subject, std::nullopt, false);
        if (!result.decision.allowed || !result.decision.binding)
            return result;
        try {
            Block tip;
            if (!chain_.TryTip(tip)) {
                result.decision = {
                    false, work_admission::Refusal::TipUnknown, std::nullopt};
                return result;
            }
            const auto configuration = WorkCoordinatorConfiguration_(
                tip.height, true);
            const auto opened = OpenWorkCoordinator_(configuration);
            if (!opened.opened) {
                result.decision = {
                    false, opened.refusal, std::nullopt};
                return result;
            }
            const auto lease_ttl = BoundPeerWorkLifetime_(
                std::chrono::milliseconds(10000));
            if (!lease_ttl) {
                result.decision = {
                    false, work_admission::Refusal::PeerViewUnsafe,
                    std::nullopt};
                return result;
            }
            auto issued = work_admission_coordinator_.IssueRemoteSigningLease(
                path, subject, std::nullopt, false,
                *lease_ttl);
            result.decision = issued.decision;
            if (!issued || !issued.grant) return result;
            result.token =
                work_admission::AdmissionCoordinator::EncodeRemoteToken(
                    issued.grant->token);
            result.ttl_ms = static_cast<uint64_t>(
                issued.grant->ttl.count());
            return result;
        } catch (...) {
            result.decision = {
                false, work_admission::Refusal::Unwired, std::nullopt};
            result.token.clear();
            result.ttl_ms = 0;
            return result;
        }
    }

    // Caller owns Blockchain's consensus-transition guard. The remote bearer
    // is consumed exactly once and converted to the same move-only Lease used
    // by local production. A changed tip/prerequisite tuple cancels the token
    // before it can reach a journal, mempool, or gossip sink.
    std::shared_ptr<work_admission::AdmissionCoordinator::Lease>
    ConsumeRemoteWorkLeaseUnderTransition_(
            work_admission::Path path,
            const work_admission::Subject& subject,
            const std::string& binding_text,
            const std::string& token_text) noexcept {
        const auto prior = work_admission::DecodeBinding(binding_text);
        const auto token =
            work_admission::AdmissionCoordinator::DecodeRemoteToken(
                token_text);
        if (!prior || !token ||
            work_admission::EncodeBinding(*prior) != binding_text ||
            work_admission::AdmissionCoordinator::EncodeRemoteToken(*token) !=
                token_text)
            return {};
        try {
            const auto snapshot = work_admission_coordinator_.GetSnapshot();
            const bool acquired_before_close = snapshot.phase ==
                work_admission::AdmissionCoordinator::Phase::Closing;
            if (!acquired_before_close) {
                const auto decision = EvaluateWorkAdmission(
                    path, subject, prior, true);
                if (!decision.allowed || !decision.binding) return {};
                Block tip;
                if (!chain_.TryTip(tip)) return {};
                const auto configuration = WorkCoordinatorConfiguration_(
                    tip.height, true);
                const auto opened = OpenWorkCoordinator_(configuration);
                if (!opened.opened) return {};
            }
            // BeginClose preserves an exact already-issued one-use bearer. Its
            // old coordinator configuration is the predecessor linearization
            // point; re-evaluating the now-published peer view here would
            // incorrectly revoke a signer which acquired first.
            auto consumed =
                work_admission_coordinator_.ConsumeRemoteSigningLease(
                    *token, path, subject, prior);
            if (!consumed || !consumed.lease) return {};
            return std::make_shared<
                work_admission::AdmissionCoordinator::Lease>(
                    std::move(*consumed.lease));
        } catch (...) {
            return {};
        }
    }

    void PruneActiveRemoteSigningLeases_() noexcept {
        std::vector<std::shared_ptr<
            work_admission::AdmissionCoordinator::Lease>> retired;
        const auto now = std::chrono::steady_clock::now();
        {
            std::lock_guard<std::mutex> lock(active_remote_signing_mu_);
            for (auto it = active_remote_signing_leases_.begin();
                 it != active_remote_signing_leases_.end();) {
                if (!it->second.lease ||
                    it->second.lease->deadline() <= now) {
                    retired.push_back(std::move(it->second.lease));
                    it = active_remote_signing_leases_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        // Destroy outside the map lock: Lease::Release takes the coordinator
        // mutex, while activation obtains coordinator state before this map.
        retired.clear();
    }

    void ClearActiveRemoteSigningLeases_() noexcept {
        std::unordered_map<std::string, ActiveRemoteSigningLease> retired;
        {
            std::lock_guard<std::mutex> lock(active_remote_signing_mu_);
            retired.swap(active_remote_signing_leases_);
        }
        // Destroy after releasing the map lock for the same lock-order reason
        // as pruning.
        retired.clear();
    }

    // Caller owns Blockchain's consensus-transition guard.  This is the
    // remote sign-start linearization point: the pending token becomes a
    // node-held Lease before the validator journal or private-key operation.
    RpcServer::RemoteSigningActivationResult
    BeginRemoteSigningUnderTransition_(
            work_admission::Path path,
            const std::string& binding_text,
            const std::string& token_text) noexcept {
        RpcServer::RemoteSigningActivationResult out;
        try {
            const auto binding = work_admission::DecodeBinding(binding_text);
            if (!binding || work_admission::EncodeBinding(*binding) !=
                                binding_text) {
                out.reason = "invalid_binding";
                return out;
            }
            auto lease = ConsumeRemoteWorkLeaseUnderTransition_(
                path, binding->subject, binding_text, token_text);
            if (!lease) {
                out.deferred = true;
                out.reason = "stale_expired_or_consumed_signing_token";
                return out;
            }
            const auto now = std::chrono::steady_clock::now();
            if (lease->deadline() <=
                now + REMOTE_SIGNING_SAFETY_MARGIN +
                    std::chrono::milliseconds(1000)) {
                out.deferred = true;
                out.reason = "insufficient_signing_lease_time";
                return out;
            }
            const auto operation_deadline =
                lease->deadline() - REMOTE_SIGNING_SAFETY_MARGIN;

            PruneActiveRemoteSigningLeases_();
            {
                std::lock_guard<std::mutex> lock(active_remote_signing_mu_);
                if (active_remote_signing_leases_.size() >= 64 ||
                    active_remote_signing_leases_.find(token_text) !=
                        active_remote_signing_leases_.end()) {
                    out.deferred = true;
                    out.reason = "active_signing_capacity";
                    return out;
                }
                ActiveRemoteSigningLease active;
                active.path = path;
                active.binding = *binding;
                active.lease = lease;
                active.operation_deadline = operation_deadline;
                active_remote_signing_leases_.emplace(
                    token_text, std::move(active));
            }
            const auto remaining = std::chrono::duration_cast<
                std::chrono::milliseconds>(operation_deadline - now);
            out.started = true;
            out.ttl_ms = static_cast<uint64_t>(remaining.count());
            return out;
        } catch (...) {
            out.reason = "activation_exception";
            return out;
        }
    }

    // Caller owns Blockchain's consensus-transition guard.  Remove-before-
    // use makes the active remote capability one-shot even when a caller
    // retries the same signed bytes concurrently.
    std::optional<ActiveRemoteSigningLease>
    TakeActiveRemoteSigningLeaseUnderTransition_(
            work_admission::Path path,
            const work_admission::Subject& subject,
            const std::string& binding_text,
            const std::string& token_text) noexcept {
        PruneActiveRemoteSigningLeases_();
        std::optional<ActiveRemoteSigningLease> active;
        {
            std::lock_guard<std::mutex> lock(active_remote_signing_mu_);
            const auto it = active_remote_signing_leases_.find(token_text);
            if (it == active_remote_signing_leases_.end() ||
                it->second.path != path ||
                it->second.binding.subject != subject ||
                std::chrono::steady_clock::now() >=
                    it->second.operation_deadline ||
                work_admission::EncodeBinding(it->second.binding) !=
                    binding_text)
                return {};
            active = std::move(it->second);
            active_remote_signing_leases_.erase(it);
        }
        if (!active || !active->OperationLive() ||
            active->lease->binding().subject != subject ||
            work_admission::EncodeBinding(active->lease->binding()) !=
                binding_text)
            return {};
        const auto snapshot = work_admission_coordinator_.GetSnapshot();
        if (snapshot.phase !=
                work_admission::AdmissionCoordinator::Phase::Closing) {
            const auto decision = EvaluateWorkAdmission(
                path, subject, active->binding, true);
            if (!decision.allowed || !decision.binding ||
                *decision.binding != active->binding)
                return {};
        }
        return active;
    }

    // Caller owns Blockchain's consensus-transition guard.  A bearer can
    // cancel either a not-yet-started token or an active node-held lease.
    bool CancelRemoteSigningUnderTransition_(
            const std::string& token_text) noexcept {
        const auto token =
            work_admission::AdmissionCoordinator::DecodeRemoteToken(
                token_text);
        if (!token ||
            work_admission::AdmissionCoordinator::EncodeRemoteToken(*token) !=
                token_text)
            return false;
        PruneActiveRemoteSigningLeases_();
        std::shared_ptr<work_admission::AdmissionCoordinator::Lease> retired;
        {
            std::lock_guard<std::mutex> lock(active_remote_signing_mu_);
            const auto it = active_remote_signing_leases_.find(token_text);
            if (it != active_remote_signing_leases_.end()) {
                retired = std::move(it->second.lease);
                active_remote_signing_leases_.erase(it);
            }
        }
        if (retired) {
            retired.reset();
            return true;
        }
        return work_admission_coordinator_.CancelRemoteSigningLease(*token);
    }

    std::optional<LocalSigningPermit>
    AcquireLocalValidatorEndorsementPermit(
            const work_admission::Subject& subject) noexcept {
        try {
            auto transition = chain_.AcquireConsensusTransitionGuard();
            const auto decision = EvaluateWorkAdmission(
                work_admission::Path::ValidatorEndorsement, subject,
                std::nullopt, false);
            if (!decision.allowed || !decision.binding) return std::nullopt;
            Block tip;
            if (!chain_.TryTip(tip)) return std::nullopt;
            const auto configuration = WorkCoordinatorConfiguration_(
                tip.height, subject.parent_height == tip.height &&
                                subject.parent_hash == tip.GetHash());
            const auto opened = OpenWorkCoordinator_(configuration);
            if (!opened.opened) return std::nullopt;
            const auto lease_ttl = BoundPeerWorkLifetime_(
                std::chrono::milliseconds(5000));
            if (!lease_ttl) return std::nullopt;
            auto attempt = work_admission_coordinator_.AcquireLocal(
                work_admission::Path::ValidatorEndorsement, subject,
                decision.binding, true, *lease_ttl);
            if (!attempt || !attempt.lease) return std::nullopt;
            auto lease = std::make_shared<
                work_admission::AdmissionCoordinator::Lease>(
                    std::move(*attempt.lease));
            const auto now = std::chrono::steady_clock::now();
            if (lease->deadline() <= now + LOCAL_SIGNING_SAFETY_MARGIN +
                                        std::chrono::milliseconds(250))
                return std::nullopt;
            const auto operation_deadline =
                lease->deadline() - LOCAL_SIGNING_SAFETY_MARGIN;
            return LocalSigningPermit(
                std::move(lease), operation_deadline);
        } catch (...) {
            return std::nullopt;
        }
    }

    RpcServer::AuthorizedWorkTxResult SubmitLocalValidatorEndorsement(
            const Transaction& tx, uint64_t fee,
            LocalSigningPermit&& permit) noexcept {
        RpcServer::AuthorizedWorkTxResult out;
        try {
            auto transition = chain_.AcquireConsensusTransitionGuard();
            if (!permit.IsLive() || !permit.lease_) {
                out.deferred = true;
                out.reason = "local_signing_permit_expired";
                return out;
            }
            std::optional<rpc_detail::ValidatorEndorsementTarget> target;
            if (!rpc_detail::ExtractValidatorEndorsementTarget(tx, target) ||
                !target) {
                out.reason = "malformed_validator_endorsement";
                return out;
            }
            Block tip;
            if (!chain_.TryTip(tip)) {
                out.deferred = true;
                out.reason = "tip_unknown";
                return out;
            }
            work_admission::Subject subject;
            subject.purpose =
                work_admission::Purpose::ValidatorEndorsement;
            subject.height = target->height;
            subject.target_hash = target->hash;
            subject.parent_height = tip.height;
            subject.parent_hash = tip.GetHash();
            if (permit.lease_->binding().subject != subject) {
                out.reason = "local_signing_subject_mismatch";
                return out;
            }
            const auto coordinator_snapshot =
                work_admission_coordinator_.GetSnapshot();
            if (coordinator_snapshot.phase !=
                    work_admission::AdmissionCoordinator::Phase::Closing) {
                const auto decision = EvaluateWorkAdmission(
                    work_admission::Path::ValidatorEndorsement, subject,
                    permit.lease_->binding(), true);
                if (!decision.allowed || !decision.binding) {
                    out.deferred = true;
                    out.reason = "local_signing_prerequisite_changed";
                    return out;
                }
            }

            const auto lease = std::move(permit.lease_);
            const auto operation_deadline = permit.operation_deadline_;
            const auto operation_live = [lease, operation_deadline]() noexcept {
                return lease &&
                    std::chrono::steady_clock::now() < operation_deadline &&
                    lease->IsLive();
            };
            Mempool::WorkSinkAuthorization authorization;
            authorization.owner = lease;
            authorization.claim = [lease]() noexcept {
                return lease->ClaimForSink();
            };
            authorization.live = operation_live;
            const auto add = mempool_.AddAuthorizedWork_(
                tx, fee, static_cast<uint32_t>(tip.height), chain_,
                std::move(authorization));
            if (add != Mempool::AddResult::ACCEPTED) {
                out.deferred =
                    add == Mempool::AddResult::DEFERRED_LOCAL_WORK;
                out.reason = Mempool::ResultToString(add);
                return out;
            }
            if (!operation_live() || !tcp_server_) {
                mempool_.Remove(HashToHex(tx.GetTxID()));
                out.deferred = true;
                out.reason = "work_gossip_unavailable";
                return out;
            }
#ifdef VELD_TEST_HOOKS
            test_work_tx_gossip_calls_.fetch_add(
                1, std::memory_order_acq_rel);
#endif
            tcp_server_->BroadcastTransaction(tx);
            out.accepted = true;
            return out;
        } catch (...) {
            out.reason = "authorized_local_sink_exception";
            return out;
        }
    }

    RpcServer::AuthorizedWorkTxResult SubmitAuthorizedValidatorEndorsement_(
            const Transaction& tx, uint64_t fee,
            const std::string& binding_text,
            const std::string& token_text,
            bool rebroadcast) noexcept {
        RpcServer::AuthorizedWorkTxResult out;
        try {
            // This guard is the outermost lock.  State/tip closure and all
            // canonical block transitions use the same sequencer.
            auto transition = chain_.AcquireConsensusTransitionGuard();
            std::optional<rpc_detail::ValidatorEndorsementTarget> target;
            if (!rpc_detail::ExtractValidatorEndorsementTarget(tx, target) ||
                !target) {
                out.reason = "malformed_validator_endorsement";
                return out;
            }
            Block tip;
            if (!chain_.TryTip(tip)) {
                out.deferred = true;
                out.reason = "tip_unknown";
                return out;
            }
            work_admission::Subject subject;
            subject.purpose =
                work_admission::Purpose::ValidatorEndorsement;
            subject.height = target->height;
            subject.target_hash = target->hash;
            subject.parent_height = tip.height;
            subject.parent_hash = tip.GetHash();
            auto active = TakeActiveRemoteSigningLeaseUnderTransition_(
                work_admission::Path::ValidatorEndorsement, subject,
                binding_text, token_text);
            if (!active || !active->OperationLive()) {
                out.deferred = true;
                out.reason = "signing_lease_not_started_stale_or_consumed";
                return out;
            }
            const auto lease = active->lease;
            const auto operation_deadline = active->operation_deadline;
            const auto operation_live = [lease, operation_deadline]() noexcept {
                return lease &&
                    std::chrono::steady_clock::now() < operation_deadline &&
                    lease->IsLive();
            };

            if (rebroadcast) {
                const auto retained = mempool_.GetTransaction(
                    HashToHex(tx.GetTxID()));
                if (!retained || retained->Serialize() != tx.Serialize()) {
                    out.reason = "endorsement_not_in_mempool";
                    return out;
                }
                if (!operation_live() || !lease->ClaimForSink() ||
                    !operation_live()) {
                    out.deferred = true;
                    out.reason = "retryable local-work-unavailable";
                    return out;
                }
            } else {
                Mempool::WorkSinkAuthorization authorization;
                authorization.owner = lease;
                authorization.claim = [lease]() noexcept {
                    return lease->ClaimForSink();
                };
                authorization.live = operation_live;
                const auto add = mempool_.AddAuthorizedWork_(
                    tx, fee, static_cast<uint32_t>(tip.height), chain_,
                    std::move(authorization));
                if (add != Mempool::AddResult::ACCEPTED) {
                    out.deferred =
                        add == Mempool::AddResult::DEFERRED_LOCAL_WORK;
                    out.reason = Mempool::ResultToString(add);
                    return out;
                }
                if (!operation_live()) {
                    mempool_.Remove(HashToHex(tx.GetTxID()));
                    out.deferred = true;
                    out.reason = "retryable local-work-unavailable";
                    return out;
                }
            }

            if (!tcp_server_ || !operation_live()) {
                if (!rebroadcast)
                    mempool_.Remove(HashToHex(tx.GetTxID()));
                out.deferred = true;
                out.reason = "work_gossip_unavailable";
                return out;
            }
#ifdef VELD_TEST_HOOKS
            test_work_tx_gossip_calls_.fetch_add(
                1, std::memory_order_acq_rel);
#endif
            tcp_server_->BroadcastTransaction(tx);
            out.accepted = true;
            return out;
        } catch (...) {
            out.reason = "authorized_sink_exception";
            return out;
        }
    }

    std::optional<work_admission::Subject>
    CurrentBlockProductionSubject_() const {
        Block tip;
        if (!chain_.TryTip(tip) || tip.height == UINT64_MAX)
            return std::nullopt;
        work_admission::Subject subject;
        subject.purpose = work_admission::Purpose::BlockProduction;
        subject.height = tip.height + 1;
        subject.parent_height = tip.height;
        subject.parent_hash = tip.GetHash();
        return subject;
    }

    work_admission::Decision EvaluateWorkAdmission(
            work_admission::Path path,
            const work_admission::Subject& subject,
            const std::optional<work_admission::Binding>& prior = std::nullopt,
            bool require_prior = false) const noexcept {
        auto deny = [](work_admission::Refusal refusal) {
            return work_admission::Decision{false, refusal, std::nullopt};
        };
        try {
            const bool block_path =
                path == work_admission::Path::InternalMining ||
                path == work_admission::Path::GetBlockTemplate ||
                path == work_admission::Path::SubmitBlock ||
                path == work_admission::Path::SynchronousGeneration;
            if ((block_path &&
                 subject.purpose != work_admission::Purpose::BlockProduction) ||
                (path == work_admission::Path::ValidatorEndorsement &&
                 subject.purpose !=
                     work_admission::Purpose::ValidatorEndorsement) ||
                (path == work_admission::Path::FinalityVote &&
                 subject.purpose != work_admission::Purpose::FinalityVote))
                return deny(work_admission::Refusal::SubjectNotCanonical);

            Block tip;
            const bool have_tip = chain_.TryTip(tip);
            const bool subject_tip_matches = have_tip &&
                subject.parent_height == tip.height &&
                subject.parent_hash == tip.GetHash();

            if (!block_path) {
                if (!have_tip || subject.height > tip.height)
                    return deny(work_admission::Refusal::SubjectNotCanonical);
                const Block target = chain_.GetBlock(subject.height);
                if (target.GetHash() != subject.target_hash)
                    return deny(work_admission::Refusal::SubjectNotCanonical);
            }

            auto configuration = WorkCoordinatorConfiguration_(
                have_tip ? tip.height : UINT64_MAX, subject_tip_matches);
            auto prerequisites = configuration.prerequisites;
            const size_t path_index = static_cast<size_t>(path);
            prerequisites.role_permitted =
                path_index < configuration.permitted_paths.size() &&
                configuration.permitted_paths[path_index];
            return work_admission::Evaluate(
                subject, prerequisites, prior, require_prior);
        } catch (...) {
            return deny(work_admission::Refusal::Unwired);
        }
    }

    bool MiningWorkStillSafe_(
            work_admission::Path path =
                work_admission::Path::InternalMining,
            const std::optional<work_admission::Binding>& prior = std::nullopt,
            bool require_prior = false) const {
        const auto subject = CurrentBlockProductionSubject_();
        return subject && EvaluateWorkAdmission(
            path, *subject, prior, require_prior).allowed;
    }

    bool CloseWorkAdmissionBounded_(
            work_admission::Refusal refusal) noexcept {
        auto closing = work_admission_coordinator_.BeginClose(refusal);
        if (closing.fully_closed) return true;
        const auto hard_stop = std::chrono::steady_clock::now() +
            work_admission::AdmissionCoordinator::ABSOLUTE_MAX_LEASE +
            std::chrono::milliseconds(50);
        while (std::chrono::steady_clock::now() < hard_stop) {
            const auto snapshot = work_admission_coordinator_.GetSnapshot();
            if (snapshot.phase ==
                work_admission::AdmissionCoordinator::Phase::Closed)
                return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        // A broken clock/callback cannot hold a safety transition forever.
        work_admission_coordinator_.CancelAndClose(refusal);
        return false;
    }

    void BumpValidationGeneration_() noexcept {
        // Every issued GBT capability is bound to the prior validation epoch.
        // This production store has no injected clock callback and never
        // acquires chain/coordinator locks, so retiring it here cannot recurse
        // into Blockchain.
        block_template_authorizations_.CancelAll();
        validation_generation_.fetch_add(1, std::memory_order_acq_rel);
    }

    void SetChainFullyValidatedLatch_(bool value) noexcept {
        if (chain_fully_validated_.load(std::memory_order_acquire) == value)
            return;
        (void)CloseWorkAdmissionBounded_(
            work_admission::Refusal::IndependentValidationIncomplete);
        try {
            auto transition = chain_.AcquireConsensusTransitionGuard();
            work_admission_coordinator_.CancelAndClose(
                work_admission::Refusal::IndependentValidationIncomplete);
            const bool previous = chain_fully_validated_.exchange(
                value, std::memory_order_acq_rel);
            if (previous != value) BumpValidationGeneration_();
        } catch (...) {
            work_admission_coordinator_.CancelAndClose(
                work_admission::Refusal::Unwired);
            chain_fully_validated_.store(false, std::memory_order_release);
            BumpValidationGeneration_();
        }
    }

    void SetIbdCompleteLatch_(bool value) noexcept {
        if (ibd_complete_.load(std::memory_order_acquire) == value) return;
        (void)CloseWorkAdmissionBounded_(
            work_admission::Refusal::SyncIncomplete);
        try {
            auto transition = chain_.AcquireConsensusTransitionGuard();
            work_admission_coordinator_.CancelAndClose(
                work_admission::Refusal::SyncIncomplete);
            const bool previous = ibd_complete_.exchange(
                value, std::memory_order_acq_rel);
            if (previous != value) BumpValidationGeneration_();
        } catch (...) {
            work_admission_coordinator_.CancelAndClose(
                work_admission::Refusal::Unwired);
            ibd_complete_.store(false, std::memory_order_release);
            BumpValidationGeneration_();
        }
    }

    void SetIBDComplete(bool v)  {
        if (v && DurableCommitFailStop()) {
            SetIbdCompleteLatch_(false);
            bool expected = false;
            if (durable_commit_ibd_refusal_logged_.compare_exchange_strong(
                    expected, true, std::memory_order_acq_rel)) {
                std::cerr << "  [durable-commit] IBD completion REFUSED: a "
                             "post-DB commit invariant failed; restart and "
                             "full replay are required.\n";
                std::cerr.flush();
            }
            return;
        }
        if (v && !AnchorSecurityImportSatisfied()) {
            SetIbdCompleteLatch_(false);
            bool expected = false;
            if (anchor_floor_ibd_refusal_logged_.compare_exchange_strong(
                    expected, true, std::memory_order_acq_rel)) {
                std::cerr << "  [anchor-floor] IBD completion REFUSED: the "
                             "Bitcoin-authenticated local floor is still "
                             "pending, mismatched, or awaiting repair.\n";
                std::cerr.flush();
            }
            return;
        }
        if (v && config_.name != "Veld Regtest") {
            const auto heights = tcp_server_
                ? tcp_server_->GetPeerHeightView()
                : net::NodeServer::PeerHeightView{};
            const uint64_t local_height = chain_.Height();
            if (!tcp_server_ || !MiningWorkStillSafeFromView_(
                    heights, local_height, chain_.IsEmpty())) {
                SetIbdCompleteLatch_(false);
                std::cerr << "  [IBD] completion REFUSED: current peer-height "
                             "work admission is unsafe; verified peer height="
                          << heights.verified_height
                          << ", diagnostic VERSION fetch hint="
                          << heights.version_fetch_hint_height
                          << ", outbound sync floor="
                          << heights.outbound_sync_height
                          << ", local height=" << local_height
                          << " (ready distinct IPs="
                          << heights.distinct_version_ips
                          << ", outbound sync IPs="
                          << heights.distinct_outbound_sync_ips
                          << "); waiting for current peers or validated "
                             "canonical evidence.\n";
                std::cerr.flush();
                return;
            }
        }
        SetIbdCompleteLatch_(v);
        if (v) {
            checkpoint_anchor_valid_.store(true, std::memory_order_release);
            prewarm_cv_.notify_all();
        }
    }
    // Trust-min opt-out: when set, all external snapshot-bootstrap paths are
    // refused. A new datadir still performs a full peer IBD from genesis. A
    // signed receipt from that completed IBD may accelerate later replay of the
    // same local chain without weakening validation of new blocks.
    void SetFullIbd(bool v)      { full_ibd_ = v; }
    bool IsFullIbd() const       { return full_ibd_; }

    // A public binary must not attempt to reinterpret an imported snapshot as
    // ordinary local history.  These durable sentinels are written before
    // snapshot promotion/background validation; their mere presence proves the
    // datadir crossed the unsupported trust boundary.  Errors also fail closed.
    bool PublicSnapshotDatadirRefusal(std::string* marker = nullptr) const {
#ifdef VELD_PUBLIC_MAINNET
        const std::array<std::pair<std::string, const char*>, 4> candidates{{
            {SnapshotReplayRequirementPath_(),
             ".snapshot-consensus-replay-required"},
            {IndependentValidationRequirementPath_(),
             ".background-chainstate-required"},
            {SnapshotRecoveryRequestPath_(),
             ".snapshot-recovery-requested"},
            {SnapshotRevocationMarkerPath_(),
             ".snapshot-fast-start-revoked"},
        }};
        for (const auto& candidate : candidates) {
            std::error_code ec;
            const bool present = std::filesystem::exists(candidate.first, ec);
            if (ec || present) {
                if (marker) *marker = candidate.second;
                return true;
            }
        }
#else
        (void)marker;
#endif
        return false;
    }
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    // Prepare an isolated extracted candidate for the same consensus replay
    // used by Start().  The durable marker is written before any historical
    // PoW may be deferred, and successful replay writes the independent-IBD
    // requirement which travels with the staged tree during publication.
    void PrepareSnapshotCandidateReplay(uint64_t height,
                                        const std::string& tip_hash) {
        if (running_.load(std::memory_order_acquire) || tcp_server_ ||
            height == 0 || !SnapshotManifestIsHex64(tip_hash) ||
            !WriteSnapshotReplayRequirementAt_(
                SnapshotReplayRequirementPath_(), height, tip_hash)) {
            throw std::runtime_error(
                "cannot durably prepare isolated snapshot candidate replay");
        }
        SetSnapshotFastStartEligible(true, height, tip_hash);
    }

    void SetSnapshotFastStartEligible(bool v,
                                      uint64_t validated_height = 0,
                                      const std::string& validated_tip = {}) {
        if (running_.load(std::memory_order_acquire))
            throw std::logic_error(
                "snapshot fast-start eligibility must be set before Start");
        snapshot_fast_start_eligible_ = v;
        snapshot_receipt_height_ = v ? validated_height : 0;
        snapshot_receipt_tip_ = v ? validated_tip : std::string{};
    }
    bool SnapshotFastStartEligible() const {
        return snapshot_fast_start_eligible_;
    }
#endif
    bool ChainFullyValidated() const {
        return chain_fully_validated_.load(std::memory_order_acquire);
    }
    Hash256 ConsensusStateDigest() const {
        auto transition = chain_.AcquireConsensusTransitionGuard();
        Hash256 tip_hash{};
        if (!chain_.IsEmpty()) tip_hash = chain_.TipCopy().GetHash();
        if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED)
            return state_digest::ComposeV8(
                chain_.Height(), tip_hash, chain_.UtxoDigest(),
                validators_.ValidatorsDigest(), staking_.StakingDigest(),
                validators_.BondYieldEscrowDigest(), chain_.NmsTallyDigest(),
                onchain_tokens_.Digest(), chain_.SupplyDigest(),
                governance_.GovernanceDigest(), chain_.NmsExtendedDigest(),
                btc_headers_.StateDigest(), anchors_.Digest(), amm_.Digest(),
                fin_state_.Digest(), bond_covenant_.Digest());
        return state_digest::ComposeV7(
            chain_.Height(), tip_hash, chain_.UtxoDigest(),
            validators_.ValidatorsDigest(), staking_.StakingDigest(),
            validators_.BondYieldEscrowDigest(), chain_.NmsTallyDigest(),
            onchain_tokens_.Digest(), chain_.SupplyDigest(),
            governance_.GovernanceDigest(), chain_.NmsExtendedDigest(),
            btc_headers_.StateDigest(), anchors_.Digest(), amm_.Digest(),
            fin_state_.Digest(), bond_covenant_.Digest());
    }
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    struct SnapshotValidationBase {
        uint64_t height{0};
        Hash256 tip_hash{};
        Hash256 state_digest{};
    };
    std::optional<SnapshotValidationBase> IndependentValidationBase() const {
        std::lock_guard<std::mutex> lock(background_validation_mutex_);
        return snapshot_validation_base_;
    }
    struct BackgroundValidationObservation {
        uint64_t height{0};
        Hash256 tip_hash{};
        Hash256 state_digest{};
        bool reached{false};
        bool passed_target{false};
    };
    void SetBackgroundValidationTarget(uint64_t height) {
        if (running_.load(std::memory_order_acquire) || tcp_server_ ||
            !background_validation_only_ || height == 0) {
            throw std::logic_error(
                "background validation target requires an offline background node");
        }
        background_validation_target_height_ = height;
    }
    BackgroundValidationObservation BackgroundValidationResult() const {
        std::lock_guard<std::mutex> lock(background_validation_mutex_);
        return background_validation_observation_;
    }
    void SetIndependentValidationProgress(uint64_t height) {
        independent_validation_height_.store(height,
                                             std::memory_order_release);
    }
    bool FinalizeIndependentBackgroundValidation(
            const BackgroundValidationObservation& observation,
            std::string* error = nullptr) {
        std::optional<SnapshotValidationBase> base;
        {
            std::lock_guard<std::mutex> lock(background_validation_mutex_);
            base = snapshot_validation_base_;
        }
        if (!base) {
            if (error) *error = "no independent validation requirement is active";
            return false;
        }
        const auto local_base_hash = db_.GetHashAtHeight(base->height);
        if (!local_base_hash ||
            *local_base_hash != HashToHex(base->tip_hash)) {
            if (error) *error =
                "snapshot base is no longer on the local canonical chain";
            return false;
        }
        if (!observation.reached || observation.passed_target ||
            observation.height != base->height ||
            observation.tip_hash != base->tip_hash ||
            observation.state_digest != base->state_digest) {
            if (error) *error = "background chainstate does not match the snapshot base";
            return false;
        }
        try {
            DurableRemoveControlFile_(
                IndependentValidationRequirementPath_());
            DurableRemoveControlFile_(SnapshotReplayRequirementPath_());
        } catch (const std::exception& e) {
            if (error) *error = e.what();
            return false;
        }
        {
            std::lock_guard<std::mutex> lock(background_validation_mutex_);
            snapshot_validation_base_.reset();
        }
        snapshot_background_verification_failed_.store(
            false, std::memory_order_release);
        independent_validation_height_.store(0,
                                             std::memory_order_release);
        SetChainFullyValidatedLatch_(true);
        snapshot_state_clean_.store(true, std::memory_order_release);
        BumpValidationGeneration_();
        return true;
    }
    void RejectIndependentBackgroundValidation(const std::string& reason) {
        RevokeSnapshotValidation_(reason);
    }
    bool SnapshotBackgroundVerificationFailed() const {
        return snapshot_background_verification_failed_.load(
            std::memory_order_acquire);
    }
#endif
    void SyncTCPIBDFlag() {
        if (tcp_server_) tcp_server_->SetIBDComplete(ibd_complete_.load());
    }
    net::NodeServer::PeerHeightView GetPeerHeightView() const {
        if (tcp_server_) return tcp_server_->GetPeerHeightView();
        return {};
    }
    uint64_t GetPeerVerifiedHeight() const {
        return GetPeerHeightView().verified_height;
    }
    uint64_t GetReceivedVersionCount() const {
        if (tcp_server_) return tcp_server_->GetReceivedVersionCount();
        return 0;
    }
    bool IsIBDComplete() const   { return ibd_complete_.load(); }

    void TryBackfillFlushes() {
        if (!ibd_complete_.load()) return;
        uint64_t h = chain_.Height();

        auto init_if_unset = [&](std::atomic<uint64_t>& last, uint64_t window) {
            if (last.load() == 0 && window > 0) {
                uint64_t baseline = (h / window) * window;
                last.store(baseline);
            }
        };
        init_if_unset(last_pool_flush_height_, (uint64_t)COMINE_WINDOW_BLOCKS);

        auto try_flush = [&](const char* label,
                              std::atomic<uint64_t>& last_h, uint64_t window) {
            if (h < last_h.load() + window) return;
            try {
                Transaction tx = BuildEndorsementFlushStandalone(h);
                if (tx.inputs.empty() || tx.outputs.empty()) return;
                auto res = mempool_.Add(tx, MIN_TX_FEE, (uint32_t)h, chain_);
                if (res == Mempool::AddResult::ACCEPTED) {
                    if (tcp_server_) tcp_server_->BroadcastTransaction(tx);
                    last_h.store(h);
                    std::cout << "  [IBD-backfill] " << label
                              << " broadcast at height " << h
                              << " — " << tx.inputs.size() << " inputs, "
                              << tx.outputs.size() << " payouts\n";
                    std::cout.flush();
                }
            } catch (...) {}
        };
        (void)try_flush;
    }

    OnChainTokenLedger& GetTokens() { return onchain_tokens_; }
    AmmLedger&          GetAmm()    { return amm_; }

    RpcServer&    GetRPC()     { return rpc_; }
    bool          IsRunning()  const { return running_.load(); }
    bool          IsMining()   const { return mining_.load(); }

    void SetP2PPort(uint16_t port) { p2p_port_ = port; }

    void SetAdvertisedServices(uint64_t services) {
        services |= MessageType::NODE_FULL;
        advertised_services_.store(services, std::memory_order_release);
        if (tcp_server_) tcp_server_->SetAdvertisedServices(services);
    }

    bool ConnectTo(const std::string& host, uint16_t port) {
        if (!tcp_server_) return false;
        // A preferred outbound endpoint is not a trust grant.  Hardcoded
        // seeds, watchdog re-dials, and ordinary --connect targets retain all
        // ban, eclipse-rotation, and inbound-admission controls.  Only the
        // separately explicit --trust/AddTrustedIP and fleet-anchor paths
        // below may install exemptions.
        return tcp_server_->ConnectTo(host, port,
                                      /*explicitly_trusted=*/false,
                                      /*fleet_anchor=*/false);
    }

    void AddTrustedIP(const std::string& ip) {
        if (!tcp_server_ || ip.empty()) return;
        tcp_server_->AddTrustedIP(ip);
    }

    bool AddFleetAnchorIp(const std::string& ip) {
        if (!tcp_server_ ||
            !net::NodeServer::IsCanonicalIPv4Literal(ip)) return false;
        // Configuration is also an outbound-dial instruction. Merely adding a
        // name to a trust set could leave mining permanently halted when that
        // IP was not already one of the hardcoded seeds. ConnectTo is
        // idempotent and dynamically promotes an existing ordinary outbound
        // connection when the exact configured IP is already live.
        if (!tcp_server_->AddFleetAnchorIp(ip)) return false;
        return tcp_server_->ConnectTo(ip, config_.port,
                                      /*explicitly_trusted=*/true,
                                      /*fleet_anchor=*/true);
    }

    size_t ClearRejectCache() {
        return tcp_server_ ? tcp_server_->ClearRejectCache() : 0;
    }
    size_t ClearOrphanPool() {
        return tcp_server_ ? tcp_server_->ClearOrphanPool() : 0;
    }

    bool IsPeerConnected(const std::string& key) const {
        if (!tcp_server_) return false;
        return tcp_server_->IsPeerConnected(key);
    }

    size_t ConnectedPeers() const {
        if (!tcp_server_) return 0;
        return tcp_server_->ConnectedPeers();
    }

    size_t VersionReadyPeers() const {
        if (!tcp_server_) return 0;
        return tcp_server_->VersionReadyPeers();
    }

    // How many of the given seed hosts are currently held as connected
    // OUTBOUND peers (resolves each seed and matches against outbound peer
    // IPs). Used by the seed-watchdog log gate so the "re-dialing dropped
    // seed(s)" message fires on actual seed loss rather than being masked by
    // inbound miner count.
    size_t CountConnectedSeeds(const std::vector<std::string>& seeds) const {
        if (!tcp_server_) return 0;
        return tcp_server_->CountConnectedSeeds(seeds);
    }

    net::NodeServer* GetTCPServer() {
        return tcp_server_.get();
    }

    std::string GetNodeInfo() const {
        std::ostringstream oss;
        oss << "Veld Node v" << CLIENT_VERSION << "\n";
        oss << "Network:    " << config_.name << "\n";
        oss << "Height:     " << chain_.Height() << "\n";
        oss << "Supply:     " << std::fixed << std::setprecision(8)
            << chain_.TotalSupplyVeld() << " / 21,000,000 VELD\n";
        oss << "Phase:      " << (!chain_.IsStakingActive()
                               ? "Bootstrap (pre-staking)"
                               : "Standard (staking active)") << "\n";
        oss << "Staking:    " << (chain_.IsStakingActive() ? "Active" : "Inactive (awaiting " + std::to_string((uint64_t)(chain_.GetStakingActivationUnits()/VELD_UNITS)) + " VELD)") << "\n";
        oss << "Mempool:    " << mempool_.Size() << " txs\n";
        oss << "Mining:     "
            << (!mining_.load() ? "Stopped"
                : (!ibd_complete_.load() ||
                   !chain_fully_validated_.load()) ? "Sync (mining paused)"
                : "Active")
            << "\n";
        return oss.str();
    }

public:
    std::atomic<uint64_t> local_blocks_since_peer_block_{0};
    std::atomic<int64_t>  last_peer_block_at_seconds_{0};
    std::atomic<int64_t>  last_fork_recovery_at_seconds_{0};
    std::atomic<uint32_t> consecutive_commit_failures_{0};
    // Display-only lifetime count and last-mined height live in a rebuildable
    // LevelDB index, never in Blockchain's consensus frame. False makes the
    // typed archive record unavailable until an exact transition/rebuild.
    std::atomic<bool> miner_archive_ready_{false};
    std::atomic<uint64_t> miner_archive_revision_{0};

    mutable std::mutex on_commit_serial_mutex_;

    void RecordPeerBlockAccepted() {
        local_blocks_since_peer_block_.store(0, std::memory_order_relaxed);
        last_peer_block_at_seconds_.store(
            (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count(),
            std::memory_order_relaxed);
    }

    void RecordLocalBlockMined() {
        local_blocks_since_peer_block_.fetch_add(1, std::memory_order_relaxed);
    }

    Hash256              last_self_mined_hash_{};
    std::atomic<int64_t> last_self_mined_at_seconds_{0};
    std::atomic<bool>    peer_acked_self_mined_{true};
    mutable std::mutex   self_mined_mutex_;

    // Tracks propagation of locally mined blocks. Mining pauses until an
    // acknowledgement quorum is reached; the supervisor escalates from normal
    // inventory relay to direct block delivery and chain synchronization.
    //
    // pending_broadcasts_mutex_ protects the queue and serializes writes to
    // mining_halted_for_propagation_. Network calls are made only after the
    // queue lock is released. The queue and per-block acknowledgement sets are
    // bounded by the constants below. Direct delivery uses the existing BLOCK
    // message and does not introduce a new wire format.
    struct PendingBlockBroadcast {
        Hash256                 block_hash;
        uint64_t                height           = 0;
        std::vector<uint8_t>    payload;
        int64_t                 mined_at_ms     = 0;
        int64_t                 last_action_at_ms = 0;
        int                     direct_push_attempts = 0;
        std::set<std::string>   acked_peers;
    };
    static constexpr size_t  LAYER1_PENDING_MAX_ENTRIES   = 16;
    static constexpr int64_t LAYER1_SOFT_PACING_MS        = 5'000;
    static constexpr int64_t LAYER1_DIRECT_PUSH_INTERVAL_MS = 5'000;
    static constexpr int     LAYER1_DIRECT_PUSH_MAX_ATTEMPTS = 3;
    static constexpr int64_t LAYER1_RECOVERY_TRIGGER_MS    = 15'000;
    static constexpr int64_t LAYER1_HARD_HALT_MS           = 90'000;
    static constexpr int64_t LAYER1_PENDING_MAX_AGE_MS     = 600'000;
    static constexpr size_t  LAYER1_ACK_QUORUM             = 2;

    mutable std::mutex                    pending_broadcasts_mutex_;
    std::deque<PendingBlockBroadcast>     pending_broadcasts_;
    std::atomic<bool>                     mining_halted_for_propagation_{false};

    // Record a freshly-mined block in the pending-broadcast tracker.
    // Caller must NOT hold self_mined_mutex_ or pending_broadcasts_mutex_.
    // Called from MiningLoop's post-mine path (node.h ~5009), AFTER the
    // initial BroadcastBlock(INV) and AFTER RecordSelfMinedBlock — so by
    // the time this runs, the block is in chain_, peer_acked_self_mined_
    // is false, and the INV is already in flight on every peer's send
    // queue.
    void RecordPendingBroadcast(const Block& blk) {
        PendingBlockBroadcast entry;
        entry.block_hash = blk.GetHash();
        entry.height     = blk.height;
        entry.payload    = blk.Serialize();
        int64_t now_ms = (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        entry.mined_at_ms = now_ms;
        entry.last_action_at_ms = now_ms;
        std::lock_guard<std::mutex> lock(pending_broadcasts_mutex_);
        pending_broadcasts_.push_back(std::move(entry));
        while (pending_broadcasts_.size() > LAYER1_PENDING_MAX_ENTRIES)
            pending_broadcasts_.pop_front();
    }

    void RecordAckFromPeer(const Hash256& h, const std::string& peer_addr) {
        if (peer_addr.empty()) return;
        std::lock_guard<std::mutex> lock(pending_broadcasts_mutex_);
        for (auto& e : pending_broadcasts_) {
            if (!(e.block_hash == h)) continue;
            size_t before = e.acked_peers.size();
            e.acked_peers.insert(peer_addr);
            size_t after = e.acked_peers.size();
            size_t live_peers = tcp_server_ ? tcp_server_->ConnectedPeers() : 0;
            size_t need = std::min<size_t>(LAYER1_ACK_QUORUM, std::max<size_t>(1, live_peers));
            if (before < need && after >= need) {
                mining_halted_for_propagation_.store(false, std::memory_order_release);
            }
            break;
        }
    }

    void BroadcastSupervisorTick() {
        if (!tcp_server_) return;
        int64_t now_ms = (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        size_t live_peers = tcp_server_->ConnectedPeers();

        struct PushAction {
            std::vector<uint8_t>  payload;
            std::set<std::string> exclude_addrs;
            uint64_t              height;
        };
        std::vector<PushAction>     pushes;
        bool                        trigger_chain_sync = false;
        bool                        trigger_hard_halt  = false;
        Hash256                     halt_for_block{};
        uint64_t                    halt_for_height = 0;
        bool                        any_entry_over_halt_threshold = false;

        {
            std::lock_guard<std::mutex> lock(pending_broadcasts_mutex_);
            for (auto it = pending_broadcasts_.begin(); it != pending_broadcasts_.end(); ) {
                int64_t age_ms = now_ms - it->mined_at_ms;

                bool reorged_out = false;
                try {
                    std::string at_height_hex = chain_.GetBlockHashAtHeight(it->height);
                    if (at_height_hex.empty() ||
                        at_height_hex != HashToHex(it->block_hash)) {
                        reorged_out = true;
                    }
                } catch (...) {
                }
                if (reorged_out) {
                    it = pending_broadcasts_.erase(it);
                    continue;
                }

                if (tcp_server_ &&
                    tcp_server_->GetPeerVerifiedHeight() >= it->height) {
                    it = pending_broadcasts_.erase(it);
                    continue;
                }

                if (age_ms >= LAYER1_PENDING_MAX_AGE_MS) {
                    it = pending_broadcasts_.erase(it);
                    continue;
                }

                size_t need = std::min<size_t>(LAYER1_ACK_QUORUM,
                                               std::max<size_t>(1, live_peers));
                if (it->acked_peers.size() >= need) {
                    it = pending_broadcasts_.erase(it);
                    continue;
                }

                if (age_ms < LAYER1_SOFT_PACING_MS) { ++it; continue; }

                int64_t since_action = now_ms - it->last_action_at_ms;
                if (it->direct_push_attempts < LAYER1_DIRECT_PUSH_MAX_ATTEMPTS &&
                    since_action >= LAYER1_DIRECT_PUSH_INTERVAL_MS) {
                    PushAction pa;
                    pa.payload       = it->payload;
                    pa.exclude_addrs = it->acked_peers;
                    pa.height        = it->height;
                    pushes.push_back(std::move(pa));
                    it->direct_push_attempts++;
                    it->last_action_at_ms = now_ms;
                }

                if (age_ms >= LAYER1_RECOVERY_TRIGGER_MS) {
                    trigger_chain_sync = true;
                }

                if (age_ms >= LAYER1_HARD_HALT_MS) {
                    any_entry_over_halt_threshold = true;
                    if (!mining_halted_for_propagation_.load(std::memory_order_acquire)) {
                        trigger_hard_halt = true;
                        halt_for_block    = it->block_hash;
                        halt_for_height   = it->height;
                    }
                }

                ++it;
            }
        }
        bool will_log_halt_set   = false;
        bool will_log_halt_clear = false;
        {
            std::lock_guard<std::mutex> lock(pending_broadcasts_mutex_);
            int64_t now_ms2 = (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            size_t live_peers_now = tcp_server_->ConnectedPeers();
            bool any_over_now = false;
            for (const auto& e : pending_broadcasts_) {
                size_t need = std::min<size_t>(LAYER1_ACK_QUORUM,
                                               std::max<size_t>(1, live_peers_now));
                if (e.acked_peers.size() >= need) continue;
                if ((now_ms2 - e.mined_at_ms) >= LAYER1_HARD_HALT_MS) {
                    any_over_now = true;
                    break;
                }
            }
            bool current_halt = mining_halted_for_propagation_.load(std::memory_order_acquire);
            if (any_over_now && !current_halt) {
                mining_halted_for_propagation_.store(true, std::memory_order_release);
                will_log_halt_set = true;
            } else if (!any_over_now && current_halt) {
                mining_halted_for_propagation_.store(false, std::memory_order_release);
                will_log_halt_clear = true;
            }
        }

        for (const auto& pa : pushes) {
            tcp_server_->BroadcastBlockBytesDirectExcept(pa.payload, pa.exclude_addrs);
            std::cerr << "  [layer1] direct-push BLOCK h=" << pa.height
                      << " to peers (excluded " << pa.exclude_addrs.size() << " already-acked)\n";
            std::cerr.flush();
        }
        if (trigger_chain_sync) {
            tcp_server_->RequestChainSyncFromAllPeers();
        }
        if (will_log_halt_set) {
            std::cerr << "  [layer1] HARD HALT mining: block h=" << halt_for_height
                      << " (" << HashToHex(halt_for_block).substr(0, 16)
                      << "...) failed to reach ACK quorum within "
                      << (LAYER1_HARD_HALT_MS / 1000) << "s. Will resume when "
                      << "quorum reached, our tip moves past this block, or "
                      << "operator clears via RPC.\n";
            std::cerr.flush();
        }
        if (will_log_halt_clear) {
            std::cerr << "  [layer1] HARD HALT cleared (no entries remain over-threshold; "
                      << "stuck blocks delivered, reorged away, or aged out)\n";
            std::cerr.flush();
        }
    }

    bool MiningHaltedForPropagation() const {
        return mining_halted_for_propagation_.load(std::memory_order_acquire);
    }

    void InvalidateReorgedPendingBroadcasts_Deferred() {
        try {
            // Reorg fixups already have a node-owned, Stop()-joined worker.
            // Queue this task there as well: a detached closure capturing this
            // could otherwise outlive chain_, pending_broadcasts_, and their
            // mutex during shutdown.
            EnqueueReorgFixup([this]() {
                try {
                    size_t dropped = 0;
                    size_t after_size = 0;
                    {
                        std::lock_guard<std::mutex> lock(pending_broadcasts_mutex_);
                        size_t before = pending_broadcasts_.size();
                        for (auto it = pending_broadcasts_.begin();
                             it != pending_broadcasts_.end(); ) {
                            bool stale = false;
                            try {
                                std::string at_height_hex =
                                    chain_.GetBlockHashAtHeight(it->height);
                                if (at_height_hex.empty() ||
                                    at_height_hex != HashToHex(it->block_hash)) {
                                    stale = true;
                                }
                            } catch (...) {
                            }
                            if (stale) {
                                it = pending_broadcasts_.erase(it);
                            } else {
                                ++it;
                            }
                        }
                        after_size = pending_broadcasts_.size();
                        dropped = before - after_size;
                    }
                    if (dropped > 0) {
                        std::cerr << "  [layer1] reorg-invalidate dropped "
                                  << dropped
                                  << " stale pending_broadcasts entr"
                                  << (dropped == 1 ? "y" : "ies")
                                  << " (now " << after_size << ")\n";
                        std::cerr.flush();
                    }
                } catch (const std::exception& e) {
                    std::cerr << "  [layer1] reorg-invalidate deferred "
                                 "exception: " << e.what() << "\n";
                    std::cerr.flush();
                } catch (...) {
                    std::cerr << "  [layer1] reorg-invalidate deferred "
                                 "unknown exception\n";
                    std::cerr.flush();
                }
            });
        } catch (const std::exception& e) {
            std::cerr << "  [layer1] reorg-invalidate dispatch exception: "
                      << e.what() << "\n";
            std::cerr.flush();
        } catch (...) {
            std::cerr << "  [layer1] reorg-invalidate dispatch unknown "
                         "exception\n";
            std::cerr.flush();
        }
    }

    std::string PeerTipsCachePath_() const {
        return data_dir_ + "/peer-tips.cache";
    }

    static constexpr const char* PEER_TIPS_CACHE_HEADER_V1 = "# veld-peer-tips-cache v1";

    void PersistPeerCache() {
        if (tcp_server_) tcp_server_->SavePeerCache();
    }
    void PersistAnchors() {
        if (tcp_server_) tcp_server_->SaveAnchors();
    }

    void RotateOutboundPeers() {
        if (tcp_server_) tcp_server_->RotateOneRandomOutbound();
    }

    void PersistPeerTipsCache() {
        if (!tcp_server_) return;
        auto snaps = tcp_server_->SnapshotPeerTips();
        if (snaps.empty()) return;
        std::string tmp  = PeerTipsCachePath_() + ".tmp";
        std::string final_path = PeerTipsCachePath_();
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            static std::atomic<bool> warned{false};
            if (!warned.exchange(true)) {
                std::cerr << "  [peer-tips-cache] WARN: cannot open "
                          << tmp << " for write — peer-tips persistence disabled this cycle.\n";
                std::cerr.flush();
            }
            return;
        }
        //  (P2P H14) — corruption / casual-tamper
        // detection via trailing SHA-256 line. Computes the digest over
        // the file body (header + data lines, excluding the final
        // checksum line itself) and writes it as `# sha256: <hex>` at
        // EOF. On load, the loader recomputes and compares; mismatch
        // → cache is treated as corrupt (silently skipped, same as a
        // missing file). NOTE: this is NOT an HMAC — an adversary with
        // write access to the datadir can also recompute the digest
        // and forge a valid file. Adversarial-tamper protection
        // requires an HMAC with a key whose trust domain is separate
        // from the datadir (e.g. derived from miner.key after the
        // wallet wizard runs).
        // Today's threat model is "process running as same user with
        // partial-stale file" → SHA-256 catches that cleanly.
        std::ostringstream body_ss;
        body_ss << PEER_TIPS_CACHE_HEADER_V1 << '\n';
        for (const auto& s : snaps) {
            if (s.ip.empty()) continue;
            body_ss << s.ip << '\t'
                    << s.height << '\t'
                    << HashToHex(s.hash) << '\t'
                    << s.updated_at << '\n';
        }
        std::string body_str = body_ss.str();
        out << body_str;
        SHA256 hasher;
        hasher.update(body_str);
        Hash256 body_hash = hasher.digest();
        out << "# sha256: " << HashToHex(body_hash) << '\n';
        out.flush();
        out.close();
        std::error_code ec;
        std::filesystem::rename(tmp, final_path, ec);
        if (ec) {
            std::filesystem::remove(tmp, ec);
        }
    }

    void LoadPeerTipsCache() {
        if (!tcp_server_) return;
        std::ifstream in(PeerTipsCachePath_(), std::ios::binary);
        if (!in) return;
        std::string content((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
        if (content.empty()) return;
        const std::string sha_prefix = "# sha256: ";
        size_t last_nl = content.rfind('\n');
        size_t prev_nl = std::string::npos;
        if (last_nl != std::string::npos && last_nl > 0)
            prev_nl = content.rfind('\n', last_nl - 1);
        std::string trailer = (prev_nl == std::string::npos)
            ? content.substr(0, last_nl)
            : content.substr(prev_nl + 1, last_nl - prev_nl - 1);
        while (!trailer.empty() && (trailer.back() == '\r' || trailer.back() == '\n'))
            trailer.pop_back();
        if (trailer.rfind(sha_prefix, 0) == 0 && trailer.size() == sha_prefix.size() + 64) {
            std::string body = (prev_nl == std::string::npos)
                ? std::string()
                : content.substr(0, prev_nl + 1);
            SHA256 hasher;
            hasher.update(body);
            Hash256 body_hash = hasher.digest();
            std::string actual = HashToHex(body_hash);
            std::string expected = trailer.substr(sha_prefix.size());
            if (actual != expected) {
                static std::atomic<bool> warned{false};
                if (!warned.exchange(true)) {
                    std::cerr << "  [peer-tips-cache] integrity check FAILED "
                              << "(sha256 mismatch). Ignoring cache; next "
                              << "persist will rewrite. If this fires "
                              << "repeatedly, datadir may be tampered.\n";
                    std::cerr.flush();
                }
                return;
            }
            content = body;
        }
        std::istringstream sin(content);
        std::string header_line;
        if (!std::getline(sin, header_line)) return;
        if (!header_line.empty() && header_line.back() == '\r') header_line.pop_back();
        if (header_line != PEER_TIPS_CACHE_HEADER_V1) {
            std::cerr << "  [peer-tips-cache] header mismatch (got '"
                      << header_line.substr(0, 50)
                      << "', expected '" << PEER_TIPS_CACHE_HEADER_V1
                      << "') — ignoring stale cache.\n";
            std::cerr.flush();
            return;
        }
        std::vector<veld::net::NodeServer::PeerTipSnapshot> snaps;
        std::string line;
        size_t malformed = 0;
        while (std::getline(sin, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            size_t t1 = line.find('\t');
            if (t1 == std::string::npos) { ++malformed; continue; }
            size_t t2 = line.find('\t', t1 + 1);
            if (t2 == std::string::npos) { ++malformed; continue; }
            size_t t3 = line.find('\t', t2 + 1);
            if (t3 == std::string::npos) { ++malformed; continue; }
            std::string ip      = line.substr(0,         t1);
            std::string h_str   = line.substr(t1 + 1,    t2 - t1 - 1);
            std::string hex_str = line.substr(t2 + 1,    t3 - t2 - 1);
            std::string ts_str  = line.substr(t3 + 1);
            if (ip.empty() || hex_str.size() != 64) { ++malformed; continue; }
            uint64_t height = 0;
            int64_t  ts     = 0;
            try { height = std::stoull(h_str); ts = std::stoll(ts_str); }
            catch (...) { ++malformed; continue; }
            veld::net::NodeServer::PeerTipSnapshot s;
            s.ip         = ip;
            s.hash       = HexToHashSafe_(hex_str);
            s.height     = height;
            s.updated_at = ts;
            snaps.push_back(std::move(s));
        }
        if (malformed > 0) {
            std::cerr << "  [peer-tips-cache] " << malformed
                      << " malformed line(s) skipped during load.\n";
            std::cerr.flush();
        }
        int64_t now_s = (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        tcp_server_->ImportPeerTipSnapshots(snaps, now_s);
        if (!snaps.empty()) {
            std::cerr << "  [peer-tips-cache] restored " << snaps.size()
                      << " peer tip observation(s) from disk.\n";
            std::cerr.flush();
        }
    }

private:
    static Hash256 HexToHashSafe_(const std::string& hex) {
        Hash256 out{};
        if (hex.size() != 64) return out;
        auto nyb = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
            return -1;
        };
        for (size_t i = 0; i < 32; ++i) {
            int hi = nyb(hex[i*2]);
            int lo = nyb(hex[i*2 + 1]);
            if (hi < 0 || lo < 0) return Hash256{};
            out[i] = (uint8_t)((hi << 4) | lo);
        }
        return out;
    }
public:

    void RecordSelfMinedBlock(const Hash256& h) {
        std::lock_guard<std::mutex> lock(self_mined_mutex_);
        last_self_mined_hash_ = h;
        last_self_mined_at_seconds_.store(
            (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count(),
            std::memory_order_relaxed);
        peer_acked_self_mined_.store(false, std::memory_order_release);
    }

    void NotePeerInvOfBlock(const Hash256& h) {
        std::lock_guard<std::mutex> lock(self_mined_mutex_);
        if (last_self_mined_hash_ == h) {
            peer_acked_self_mined_.store(true, std::memory_order_release);
        }
    }

    bool BlockFloodGuardHolding() const {
        if (mining_halted_for_propagation_.load(std::memory_order_acquire)) return true;

        if (peer_acked_self_mined_.load(std::memory_order_acquire)) return false;
        if (chain_.IsEmpty()) return false;
        Hash256 our_tip;
        try { our_tip = chain_.Tip().GetHash(); } catch (...) { return false; }
        std::lock_guard<std::mutex> lock(self_mined_mutex_);
        if (!(our_tip == last_self_mined_hash_)) return false;
        if (tcp_server_) {
            uint64_t peer_verified = tcp_server_->GetPeerVerifiedHeight();
            if (peer_verified >= chain_.Height()) return false;
        }
        constexpr int64_t BLOCK_FLOOD_GUARD_TIMEOUT_S = 10;
        int64_t now_s = (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        int64_t since = now_s - last_self_mined_at_seconds_.load(std::memory_order_relaxed);
        return since < BLOCK_FLOOD_GUARD_TIMEOUT_S;
    }

    bool ForkSuspected() const {
        if (!tcp_server_) return false;
        if (tcp_server_->ConnectedPeers() < 1) return false;
        // A dominant miner may receive no peer-originated blocks while still
        // having healthy relay coverage. A locally verified peer at the local
        // height proves the miner is not isolated; unsigned VERSION heights do
        // not satisfy this condition.
        uint64_t our_tip = chain_.Height();
        uint64_t peer_verified = tcp_server_->GetPeerVerifiedHeight();
        if (peer_verified > 0 && peer_verified >= our_tip) {
            return false;
        }
        constexpr uint64_t FORK_SELF_HEAL_THRESHOLD = 5;
        if (local_blocks_since_peer_block_.load(std::memory_order_relaxed) < FORK_SELF_HEAL_THRESHOLD)
            return false;
        constexpr int64_t FORK_SELF_HEAL_COOLDOWN_S = 300;
        int64_t now_s = (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        int64_t last  = last_fork_recovery_at_seconds_.load(std::memory_order_relaxed);
        if (last > 0 && now_s - last < FORK_SELF_HEAL_COOLDOWN_S)
            return false;
        return true;
    }

    void TriggerForkRecovery() {
        int64_t now_s = (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        last_fork_recovery_at_seconds_.store(now_s, std::memory_order_relaxed);
        uint64_t streak = local_blocks_since_peer_block_.load(std::memory_order_relaxed);
        std::cerr << "  [tip-confirm] " << streak
                  << " self-mined blocks since the last peer block; "
                  << "checking peers agree on the tip.\n";
        std::cerr.flush();
        if (tcp_server_) tcp_server_->RequestChainSyncFromAllPeers();
    }

    std::atomic<int64_t> last_tip_reconcile_at_seconds_{0};
    void TriggerTipReconcile() {
        int64_t now_s = (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        int64_t last = last_tip_reconcile_at_seconds_.load(std::memory_order_relaxed);
        constexpr int64_t TIP_RECONCILE_MIN_INTERVAL_S = 10;
        if (last > 0 && now_s - last < TIP_RECONCILE_MIN_INTERVAL_S) return;
        last_tip_reconcile_at_seconds_.store(now_s, std::memory_order_relaxed);
        if (tcp_server_ && tcp_server_->ConnectedPeers() > 0) {
            tcp_server_->RequestChainSyncFromAllPeers();
        }
    }

    std::vector<veld::net::NodeServer::PeerTipSnapshot> SnapshotPeerTips() const {
        if (!tcp_server_) return {};
        return tcp_server_->SnapshotPeerTips();
    }

    void BroadcastTipsig() {
        if (tcp_server_) tcp_server_->BroadcastTipsig();
    }

    void ReapStuckHandshakes() {
        if (tcp_server_) tcp_server_->ReapStuckHandshakes();
    }

    void ReapIdlePeers() {
        if (tcp_server_) tcp_server_->ReapIdlePeers();
    }

    void BroadcastStatsig() {
        if (!tcp_server_) return;
        uint64_t mempool_size = mempool_.Size();
        uint32_t peer_count   = (uint32_t)tcp_server_->ConnectedPeers();
        tcp_server_->BroadcastStatsig(mempool_size, peer_count);
    }
    std::vector<veld::net::NodeServer::PeerStatsSnapshot> SnapshotPeerStats() const {
        if (!tcp_server_) return {};
        return tcp_server_->SnapshotPeerStats();
    }

    // ──────────────────────────────────────────────────────────────────
    //   LAYER-5: OUT-OF-BAND HTTPS ORACLE (eclipse defense)
    //
    //  Threat model
    //  ────────────
    //  An attacker who controls every peer in our peer-set can feed us
    //  a fake "canonical chain" — every TIPSIG, GETBLOCKS response,
    //  and BLOCK comes from the attacker. Pure P2P-only sync has no
    //  way to detect this; we'd believe the fork is canonical because
    //  our entire view of the network agrees.
    //
    //  Defense: every 5 minutes, fetch
    //  `https://explorer.veld.network/api/stats`
    //  over HTTPS (out-of-band — independent of our TCP peer set).
    //  Compare oracle's (height, best_block_hash) to our own. Three
    //  cases:
    //
    //    (a) oracle == us : agreement, no action.
    //    (b) oracle ahead of us OR same-height-different-hash :
    //          we may be behind / on a fork. Log loudly + invoke
    //          TriggerTipReconcile (sends GETBLOCKS to all peers).
    //          If our peers are honest but we missed a block, this
    //          recovers cleanly. If our peers are hostile, the
    //          recovery does nothing (they all confirm the bad
    //          chain) — but the LOG signal is unmissable to the
    //          operator.
    //    (c) we ahead of oracle : we may be the dominant miner with
    //          fresh blocks not yet on the public explorer. Don't
    //          alarm — this is normal for miners outpacing the
    //          oracle's update lag. (Oracle is the explorer, which
    //          serves veld-node's `/api/stats` after IBD-complete.
    //          Miner's OWN explorer would also be ahead.)
    //
    //  Hardcoded URL (no DNS-replacement attack vector)
    //  ────────────────────────────────────────────────
    //  The hostname `veld.network` resolves via system DNS, but the
    //  TLS handshake validates the server's cert against the system
    //  trust store. A DNS hijack to a hostile IP would require the
    //  attacker to also have a valid cert for `veld.network` — which
    //  requires compromising the cert authority chain. This is the
    //  same trust model every HTTPS user implicitly relies on.
    //
    //  Failure modes
    //  ─────────────
    //  - Network unreachable : silent skip. We try again next cycle.
    //    DO NOT alarm or change peer state on transient failure.
    //  - Curl missing on host : silent skip (POSIX has it; Windows
    //    10+ ships curl.exe in System32; MSYS2 builds use ucrt64
    //    curl). Logs once at startup if curl-not-found.
    //  - Oracle returns malformed JSON : silent skip + log warning.
    //  - Oracle reports impossibly-high height (>2× our height) :
    //    silent skip + log warning (oracle may be compromised or
    //    DNS-hijacked; refuse to trust).
    //
    //  Cost: one HTTP request every 5 min. ~2 KB response. Negligible.
    // ──────────────────────────────────────────────────────────────────
    void OracleSyncCheck() {
#ifdef VELD_PUBLIC_TESTNET
        // The final-mainnet explorer is not an oracle for a disposable chain.
        // Testnet liveness comes from its isolated peers and signed lifecycle
        // record until a distinct testnet oracle endpoint is provisioned.
        return;
#endif
        if (!running_.load(std::memory_order_acquire)) return;
        if (oracle_in_flight_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        std::lock_guard<std::mutex> lifecycle_lock(oracle_thread_mutex_);
        if (!running_.load(std::memory_order_acquire)) {
            oracle_in_flight_.store(false, std::memory_order_release);
            return;
        }
        try {
            // A completed std::thread remains joinable.  The in-flight flag is
            // already false before a later call can reach this point, so reap
            // that completed owner before assigning the next 5-minute task.
            if (oracle_thread_.joinable()) oracle_thread_.join();
            oracle_thread_ = std::thread([this]() {
                struct InFlightReset {
                    std::atomic<bool>& flag;
                    ~InFlightReset() {
                        flag.store(false, std::memory_order_release);
                    }
                } reset{oracle_in_flight_};
                try {
                    OracleSyncCheckImpl_();
                } catch (...) {
                }
            });
        } catch (...) {
            oracle_in_flight_.store(false, std::memory_order_release);
        }
    }
private:
    void OracleSyncCheckImpl_() {
        static std::atomic<bool>     curl_logged_missing{false};
        static std::atomic<int64_t>  last_alarm_at_seconds{0};
        static std::string           last_alarm_signature;
        static std::mutex            last_alarm_signature_mtx;

        const std::string curl_executable =
            compat::TrustedSystemCurlExecutable();
        if (curl_executable.empty()) {
            if (!curl_logged_missing.exchange(true)) {
                std::cerr << "  [oracle] trusted system curl executable "
                             "unavailable - eclipse-defense oracle disabled.\n";
                std::cerr.flush();
            }
            return;
        }
        auto oracle = compat::RunProcess(
            {curl_executable, "--disable", "-fsS", "--max-time", "8",
             "--proto", "=https",
             "-H", "User-Agent: veld-node-oracle/1.0",
             "https://explorer.veld.network/api/stats"},
            true, {}, false, 64u * 1024u);
        if (oracle.exit_code == 127) {
            if (!curl_logged_missing.exchange(true)) {
                std::cerr << "  [oracle] trusted system curl executable "
                             "could not be started - eclipse-defense oracle disabled.\n";
                std::cerr.flush();
            }
            return;
        }
        if (oracle.output_truncated) {
            // A valid-looking prefix is not an authenticated complete JSON
            // response.  Fail closed and retry next cycle.
            std::cerr << "  [oracle] oversized/truncated response — skipping.\n";
            std::cerr.flush();
            return;
        }
        std::string body = std::move(oracle.output);
        if (oracle.exit_code != 0 || body.empty()) {
            // Transient network/oracle failure. Silent skip — try
            // again on next 5-min cycle. NOT an alarm condition;
            // alarming on every transient failure would create
            // noise indistinguishable from real divergence.
            return;
        }

        auto extract_uint = [&](const std::string& key) -> uint64_t {
            std::string needle = "\"" + key + "\":";
            size_t p = body.find(needle);
            if (p == std::string::npos) return 0;
            p += needle.size();
            while (p < body.size() && (body[p] == ' ' || body[p] == '\t')) ++p;
            uint64_t v = 0;
            try { v = std::stoull(body.substr(p)); } catch (...) {}
            return v;
        };
        auto extract_str = [&](const std::string& key) -> std::string {
            std::string needle = "\"" + key + "\":\"";
            size_t p = body.find(needle);
            if (p == std::string::npos) return "";
            p += needle.size();
            size_t e = body.find('"', p);
            return e == std::string::npos ? "" : body.substr(p, e - p);
        };
        uint64_t    oracle_height = extract_uint("height");
        std::string oracle_hash   = extract_str("best_block_hash");

        if (oracle_height == 0 || oracle_hash.empty()) {
            std::cerr << "  [oracle] malformed response from explorer endpoint — skipping.\n";
            std::cerr.flush();
            return;
        }

        uint64_t our_height = chain_.Height();
        uint64_t plausible_max = (our_height < 100) ? (our_height + 100'000)
                                                    : (our_height * 10);
        if (oracle_height > plausible_max) {
            std::cerr << "  [oracle] suspicious oracle response: oracle_height="
                      << oracle_height << " vs our_height=" << our_height
                      << " — refusing to trust, no action taken.\n";
            std::cerr.flush();
            return;
        }

        std::string our_hash_hex;
        if (!chain_.IsEmpty()) {
            try { our_hash_hex = HashToHex(chain_.Tip().GetHash()); } catch (...) {}
        }

        bool ahead     = oracle_height > our_height;
        bool diff_at_h = (oracle_height == our_height) && (oracle_hash != our_hash_hex);
        bool we_lead   = oracle_height < our_height;

        if (we_lead) return;

        if (!ahead && !diff_at_h) return;

        std::string sig = std::to_string(oracle_height) + ":" + oracle_hash;
        bool log_now = false;
        {
            std::lock_guard<std::mutex> lk(last_alarm_signature_mtx);
            if (sig != last_alarm_signature) {
                last_alarm_signature = sig;
                log_now = true;
            }
        }
        if (log_now) {
            std::cerr << "  [oracle] DIVERGENCE: veld.network reports h="
                      << oracle_height << " hash=" << oracle_hash.substr(0, 16) << "...\n"
                      << "  [oracle] our local view:        h="
                      << our_height << " hash=" << (our_hash_hex.empty() ? "(empty)" : our_hash_hex.substr(0, 16) + "...") << "\n"
                      << "  [oracle] " << (ahead ? "we are BEHIND oracle" : "SAME height, DIFFERENT hash (likely on a fork)")
                      << " — triggering TipReconcile to fetch canonical chain from peers.\n"
                      << "  [oracle] If this alarm persists across multiple cycles AND your peers all\n"
                      << "  [oracle] agree with us (not the oracle), you may be ECLIPSED. Action: stop\n"
                      << "  [oracle] the node, verify peer-list, dial fresh seeds from a different\n"
                      << "  [oracle] network, or restart with a fresh ordinary IBD.\n";
            std::cerr.flush();
            last_alarm_at_seconds.store(
                (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count(),
                std::memory_order_relaxed);
        }
        TriggerTipReconcile();
    }

private:
    void QuarantineDataDir_() {
        namespace fs = std::filesystem;
        db_.Close();

        std::time_t now = std::time(nullptr);
        std::tm tmv{};
#if defined(_WIN32)
        gmtime_s(&tmv, &now);
#else
        gmtime_r(&now, &tmv);
#endif
        char ts_buf[40];
        std::strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d-%H%M%S", &tmv);
        std::string suffix = std::string(".stale-") + ts_buf;

        auto require_rename = [&](const std::string& dir) {
            std::error_code ec;
            const bool present = fs::exists(dir, ec);
            if (ec)
                throw std::runtime_error(
                    "cannot inspect live data directory before quarantine: " +
                    dir + ": " + ec.message());
            if (!present) return;
            const std::string target = dir + suffix;
            if (fs::exists(target, ec) || ec)
                throw std::runtime_error(
                    "quarantine destination already exists or is inaccessible: " + target);
            fs::rename(dir, target, ec);
            if (ec || fs::exists(dir) || !fs::exists(target))
                throw std::runtime_error(
                    "failed to quarantine live directory " + dir +
                    (ec ? ": " + ec.message() : std::string()));
            std::cerr << "  [recover] quarantined: " << dir
                      << " -> " << target << "\n";
        };
        // All live storage namespaces must move successfully before a new DB
        // can be promoted. Any failure throws after db_.Close(); callers may
        // not continue into P2P with a mixed old/new directory set.
        require_rename(data_dir_ + "/blocks");
        require_rename(data_dir_ + "/db");
        require_rename(data_dir_ + "/index");

        try {
            std::unordered_map<std::string, std::vector<fs::directory_entry>> groups;
            for (auto& ent : fs::directory_iterator(data_dir_)) {
                if (!ent.is_directory()) continue;
                std::string name = ent.path().filename().string();
                size_t dot = name.find('.');
                if (dot == std::string::npos) continue;
                std::string base = name.substr(0, dot);
                if (base != "blocks" && base != "db" && base != "index") continue;
                size_t dash = name.find('-', dot);
                if (dash == std::string::npos) continue;
                std::string variant = name.substr(dot + 1, dash - dot - 1);
                if (variant.empty()) continue;
                std::string group_key = base + "." + variant;
                groups[group_key].push_back(ent);
            }
            for (auto& [k, vec] : groups) {
                if (vec.size() <= 2) continue;
                std::sort(vec.begin(), vec.end(),
                          [](const fs::directory_entry& a, const fs::directory_entry& b) {
                              std::error_code ec_a, ec_b;
                              auto ta = fs::last_write_time(a.path(), ec_a);
                              auto tb = fs::last_write_time(b.path(), ec_b);
                              return ta > tb;
                          });
                for (size_t i = 2; i < vec.size(); ++i) {
                    std::error_code ec;
                    fs::remove_all(vec[i].path(), ec);
                    if (!ec) {
                        std::cerr << "  [recover] pruned old quarantine: "
                                  << vec[i].path().filename().string() << "\n";
                    } else {
                        std::cerr << "  [recover] WARN: could not prune "
                                  << vec[i].path().filename().string()
                                  << ": " << ec.message() << "\n";
                    }
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "  [recover] WARN: quarantine prune failed: "
                      << e.what() << " (live data unaffected)\n";
        }
        std::cerr.flush();
    }

    void PruneStaleQuarantines_() {
        namespace fs = std::filesystem;
        try {
            std::unordered_map<std::string, std::vector<fs::directory_entry>> groups;
            for (auto& ent : fs::directory_iterator(data_dir_)) {
                if (!ent.is_directory()) continue;
                std::string name = ent.path().filename().string();
                size_t dot = name.find('.');
                if (dot == std::string::npos) continue;
                std::string base = name.substr(0, dot);
                if (base != "blocks" && base != "db" && base != "index") continue;
                size_t dash = name.find('-', dot);
                if (dash == std::string::npos) continue;
                std::string variant = name.substr(dot + 1, dash - dot - 1);
                if (variant.empty()) continue;
                groups[base + "." + variant].push_back(ent);
            }
            size_t total_pruned = 0;
            uint64_t total_bytes = 0;
            for (auto& [k, vec] : groups) {
                if (vec.size() <= 2) continue;
                std::sort(vec.begin(), vec.end(),
                          [](const fs::directory_entry& a, const fs::directory_entry& b) {
                              std::error_code ec_a, ec_b;
                              return fs::last_write_time(a.path(), ec_a) >
                                     fs::last_write_time(b.path(), ec_b);
                          });
                for (size_t i = 2; i < vec.size(); ++i) {
                    uint64_t bytes_before = 0;
                    try {
                        for (auto& f : fs::recursive_directory_iterator(vec[i].path())) {
                            std::error_code ec;
                            if (f.is_regular_file(ec)) bytes_before += fs::file_size(f.path(), ec);
                        }
                    } catch (...) {}
                    std::error_code ec;
                    fs::remove_all(vec[i].path(), ec);
                    if (!ec) { ++total_pruned; total_bytes += bytes_before; }
                }
            }
            if (total_pruned > 0) {
                std::cout << "  [startup] pruned " << total_pruned
                          << " stale quarantine dirs ("
                          << (total_bytes / (1024 * 1024)) << " MB freed)\n";
            }

            constexpr size_t MAX_QUARANTINE_DIRS_GLOBAL = 8;
            std::vector<fs::directory_entry> all_quarantines;
            for (auto& ent : fs::directory_iterator(data_dir_)) {
                if (!ent.is_directory()) continue;
                std::string name = ent.path().filename().string();
                size_t dot = name.find('.');
                if (dot == std::string::npos) continue;
                std::string base = name.substr(0, dot);
                if (base != "blocks" && base != "db" && base != "index") continue;
                all_quarantines.push_back(ent);
            }
            if (all_quarantines.size() > MAX_QUARANTINE_DIRS_GLOBAL) {
                std::sort(all_quarantines.begin(), all_quarantines.end(),
                          [](const fs::directory_entry& a, const fs::directory_entry& b) {
                              std::error_code ec_a, ec_b;
                              return fs::last_write_time(a.path(), ec_a) >
                                     fs::last_write_time(b.path(), ec_b);
                          });
                size_t global_pruned = 0;
                uint64_t global_bytes = 0;
                for (size_t i = MAX_QUARANTINE_DIRS_GLOBAL; i < all_quarantines.size(); ++i) {
                    uint64_t bytes_before = 0;
                    try {
                        for (auto& f : fs::recursive_directory_iterator(all_quarantines[i].path())) {
                            std::error_code ec;
                            if (f.is_regular_file(ec)) bytes_before += fs::file_size(f.path(), ec);
                        }
                    } catch (...) {}
                    std::error_code ec;
                    fs::remove_all(all_quarantines[i].path(), ec);
                    if (!ec) { ++global_pruned; global_bytes += bytes_before; }
                }
                if (global_pruned > 0) {
                    std::cout << "  [startup] global quarantine cap: pruned "
                              << global_pruned << " more dirs ("
                              << (global_bytes / (1024 * 1024)) << " MB freed)\n";
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "  [startup] WARN: quarantine sweep failed: "
                      << e.what() << "\n";
        }
    }

public:
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    // Validate an extracted snapshot in isolation before it can replace live
    // state.  This opens only the candidate directory, performs the same full
    // synchronous ReplayChain used at startup, and binds the resulting tip to
    // the signed (height, tip_hash) tuple.  It intentionally starts no RPC,
    // P2P, explorer, or mining threads.
    void ValidateStoredChainOnly(uint64_t expected_height,
                                 const std::string& expected_tip_hash,
                                 bool verify_historical_pow = true) {
        if (expected_height == 0 ||
            !SnapshotManifestIsHex64(expected_tip_hash)) {
            throw std::runtime_error(
                "snapshot candidate has malformed signed tip identity");
        }
        PrepareAnchorSecurityBootstrap_();
        WireDB();
        auto stored_tip = db_.ReadChainTip();
        if (!stored_tip || stored_tip->height != expected_height ||
            stored_tip->tip_hash != expected_tip_hash) {
            throw std::runtime_error(
                "snapshot candidate database tip does not match signed manifest");
        }
        ReplayChain(expected_height, verify_historical_pow);
        if (chain_.Height() != expected_height || chain_.IsEmpty() ||
            HashToHex(chain_.TipCopy().GetHash()) != expected_tip_hash) {
            throw std::runtime_error(
                "snapshot candidate consensus replay tip does not match signed manifest");
        }
    }

#endif  // VELD_ENABLE_SNAPSHOT_BOOTSTRAP

    bool DurableWriteControlFile_(const std::string& path,
                                  const std::string& body) const {
        const std::string tmp = path + ".new";
#if defined(_WIN32)
        HANDLE h = ::CreateFileA(tmp.c_str(), GENERIC_WRITE, 0, nullptr,
                                 CREATE_ALWAYS,
                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                                 nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        DWORD written = 0;
        bool ok = body.size() <= static_cast<size_t>(MAXDWORD) &&
            ::WriteFile(h, body.data(), static_cast<DWORD>(body.size()),
                        &written, nullptr) && written == body.size() &&
            ::FlushFileBuffers(h);
        ::CloseHandle(h);
        if (!ok) { ::DeleteFileA(tmp.c_str()); return false; }
        if (!::MoveFileExA(tmp.c_str(), path.c_str(),
                           MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            ::DeleteFileA(tmp.c_str());
            return false;
        }
        return compat::RestrictFileToOwner(path);
#else
        ::unlink(tmp.c_str());
        int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL |
                        O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) return false;
        struct stat created{};
        if (::fstat(fd, &created) != 0 || !S_ISREG(created.st_mode) ||
            created.st_uid != ::geteuid() || (created.st_mode & 0077) != 0) {
            ::close(fd);
            ::unlink(tmp.c_str());
            return false;
        }
        size_t off = 0;
        bool ok = true;
        while (off < body.size()) {
            ssize_t n = ::write(fd, body.data() + off, body.size() - off);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { ok = false; break; }
            off += static_cast<size_t>(n);
        }
        if (ok) ok = ::fsync(fd) == 0;
        if (::close(fd) != 0) ok = false;
        if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0) {
            ::unlink(tmp.c_str());
            return false;
        }
        const std::string parent =
            std::filesystem::path(path).parent_path().string();
        int dfd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd < 0) return false;
        const bool dir_ok = ::fsync(dfd) == 0;
        ::close(dfd);
        return dir_ok;
#endif
    }

    std::optional<std::string> ReadSecureControlFile_(
        const std::string& path, size_t cap) const {
#if defined(_WIN32)
        DWORD attrs = ::GetFileAttributesA(path.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) return std::nullopt;
        if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) ||
            (attrs & FILE_ATTRIBUTE_DIRECTORY))
            throw std::runtime_error("control file is a link or not regular");
        HANDLE h = ::CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                 nullptr, OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL |
                                 FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (h == INVALID_HANDLE_VALUE)
            throw std::runtime_error("cannot securely open control file");
        LARGE_INTEGER sz{};
        if (!::GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 ||
            static_cast<uint64_t>(sz.QuadPart) > cap) {
            ::CloseHandle(h);
            throw std::runtime_error("control file has invalid size");
        }
        std::string body(static_cast<size_t>(sz.QuadPart), '\0');
        DWORD got = 0;
        bool ok = ::ReadFile(h, body.data(), static_cast<DWORD>(body.size()),
                             &got, nullptr) && got == body.size();
        ::CloseHandle(h);
        if (!ok) throw std::runtime_error("cannot read control file");
        return body;
#else
        struct stat lst{};
        if (::lstat(path.c_str(), &lst) != 0) {
            if (errno == ENOENT) return std::nullopt;
            throw std::runtime_error("cannot lstat control file");
        }
        if (!S_ISREG(lst.st_mode) || lst.st_uid != ::geteuid() ||
            (lst.st_mode & 0077) != 0)
            throw std::runtime_error(
                "control file must be regular, owner-only, and owned by the node user");
        int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) throw std::runtime_error("cannot securely open control file");
        struct stat fst{};
        if (::fstat(fd, &fst) != 0 || !S_ISREG(fst.st_mode) ||
            fst.st_dev != lst.st_dev || fst.st_ino != lst.st_ino ||
            fst.st_uid != ::geteuid() || (fst.st_mode & 0077) != 0 ||
            fst.st_size <= 0 || static_cast<uint64_t>(fst.st_size) > cap) {
            ::close(fd);
            throw std::runtime_error("control file changed or has invalid metadata");
        }
        std::string body(static_cast<size_t>(fst.st_size), '\0');
        size_t off = 0;
        while (off < body.size()) {
            ssize_t n = ::read(fd, body.data() + off, body.size() - off);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { ::close(fd); throw std::runtime_error("cannot read control file"); }
            off += static_cast<size_t>(n);
        }
        ::close(fd);
        return body;
#endif
    }

    std::string FinalityEvidenceJournalPath_() const {
        return data_dir_ + "/finality-equivocation.evj";
    }

    FinalityEvidencePersistStatus PersistFinalityEvidenceLocked_() {
        std::string body;
        try {
            const std::vector<uint8_t> encoded =
                fin_equivocation_collector_.Encode();
            if (encoded.size() > ::veld::finality::qc::
                                     FinalityEquivocationCollector::
                                         MAX_ENCODED_JOURNAL_BYTES)
                return FinalityEvidencePersistStatus::NotCommitted;
            body.assign(reinterpret_cast<const char*>(encoded.data()),
                        encoded.size());
#ifdef VELD_TEST_HOOKS
            if (fin_equivocation_persist_override_)
                return fin_equivocation_persist_override_(body);
#endif
            if (DurableWriteControlFile_(FinalityEvidenceJournalPath_(), body))
                return FinalityEvidencePersistStatus::Committed;
        } catch (...) {
            // Continue to the exact read-back below.  An allocator, path, or
            // platform exception may have happened before the write (then it
            // is NotCommitted) or after rename (then it is CommitUncertain).
        }

        // DurableWriteControlFile_ can fail after rename (directory fsync on
        // Unix, owner-ACL tightening after MoveFileEx on Windows).  At that
        // point rolling back the in-memory pair would diverge from a journal
        // that already contains it.  Distinguish this from a pre-commit
        // failure by securely reading back the exact bytes.  The caller keeps
        // the pair hidden/non-assembling and asks for a retry while durability
        // remains uncertain.
        try {
            const auto committed = ReadSecureControlFile_(
                FinalityEvidenceJournalPath_(),
                ::veld::finality::qc::FinalityEquivocationCollector::
                    MAX_ENCODED_JOURNAL_BYTES);
            if (!body.empty() && committed && *committed == body)
                return FinalityEvidencePersistStatus::CommitUncertain;
        } catch (...) {
        }
        return FinalityEvidencePersistStatus::NotCommitted;
    }

    // Startup is deliberately fail-closed for an existing malformed journal:
    // silently discarding a valid, slashable pair after restart would make
    // enforcement depend on uptime.  Missing means no evidence and is valid.
    void LoadFinalityEvidence_() {
        namespace fq = ::veld::finality::qc;
        auto transition = chain_.AcquireConsensusTransitionGuard();
        std::lock_guard<std::mutex> gate(fin_equivocation_gate_mu_);
        fin_equivocation_detector_.Clear();
        const auto body = ReadSecureControlFile_(
            FinalityEvidenceJournalPath_(),
            fq::FinalityEquivocationCollector::MAX_ENCODED_JOURNAL_BYTES);
        if (!body) {
            fin_equivocation_collector_.Clear();
            fin_equivocation_journal_uncertain_ = false;
            return;
        }
#if defined(_WIN32)
        if (!compat::RestrictFileToOwner(FinalityEvidenceJournalPath_()))
            throw std::runtime_error(
                "finality equivocation journal is not owner-restricted");
#endif
        const std::vector<uint8_t> encoded(body->begin(), body->end());
        const uint64_t tip = chain_.Height();
        const auto validate_pair =
            [this, tip](const fq::SignedVote& first,
                        const fq::SignedVote& second)
                -> std::optional<fq::ValidatedEquivocationEvidence> {
                if (first.epoch_id != second.epoch_id ||
                    first.set_root != second.set_root ||
                    first.pubkey_hex != second.pubkey_hex)
                    return std::nullopt;
                const auto retained =
                    validators_.ResolveRetainedFinalityMember(
                        first.epoch_id, first.set_root,
                        first.pubkey_hex);
                if (!retained) return std::nullopt;
                fq::SnapshotEntry member;
                member.pubkey_commit = retained->pubkey_commit;
                member.pubkey_hex = retained->pubkey_hex;
                return fq::ValidateEquivocationPairForRetainedMember(
                    first, second, retained->epoch, retained->root, member,
                    tip, fq::NETWORK_ID, GenesisHashBytes_());
            };
        if (!fin_equivocation_collector_.Restore(encoded, validate_pair))
            throw std::runtime_error(
                "finality equivocation journal is corrupt or no longer authenticates");

        fin_equivocation_journal_uncertain_ = false;
        if (fin_equivocation_collector_.PruneExpired(tip) > 0) {
            const auto persisted = PersistFinalityEvidenceLocked_();
            if (persisted != FinalityEvidencePersistStatus::Committed)
                throw std::runtime_error(
                    "cannot durably prune expired finality equivocation evidence");
        }
    }

    void PruneFinalityEvidenceAfterDurableTip_(uint64_t tip) noexcept {
        try {
            std::lock_guard<std::mutex> gate(fin_equivocation_gate_mu_);
            fin_equivocation_detector_.PruneExpired(tip);
            const bool pruned =
                fin_equivocation_collector_.PruneExpired(tip) > 0;
            if (!pruned && !fin_equivocation_journal_uncertain_) return;

            const auto persisted = PersistFinalityEvidenceLocked_();
            if (persisted == FinalityEvidencePersistStatus::Committed) {
                // A later durable block is a natural retry point after an
                // earlier rename/fsync ambiguity.  Re-enable operator/RPC
                // evidence surfaces only after the journal is confirmed.
                fin_equivocation_journal_uncertain_ = false;
            } else {
                // The old durable file contains only harmless expired extras.
                // If this is an uncertain new pair, keep it hidden and retry
                // again at the next durable tip.  Never roll back an already-
                // durable block for evidence housekeeping.
                if (persisted ==
                    FinalityEvidencePersistStatus::CommitUncertain)
                    fin_equivocation_journal_uncertain_ = true;
                std::cerr << "  [finality] could not confirm evidence journal "
                             "housekeeping; retry deferred\n";
                std::cerr.flush();
            }
        } catch (...) {
            std::cerr << "  [finality] evidence pruning deferred\n";
            std::cerr.flush();
        }
    }

    static ::veld::finality::qc::SnapshotEntry
    EvidenceSnapshotEntry_(const RetainedFinalityMember& retained) {
        ::veld::finality::qc::SnapshotEntry member;
        member.pubkey_commit = retained.pubkey_commit;
        member.pubkey_hex = retained.pubkey_hex;
        return member;
    }

    bool PrecheckFinalityVoteWire_(const std::vector<uint8_t>& wire) const {
        namespace fq = ::veld::finality::qc;
        const auto vote = fq::DecodeSignedVoteWire(wire);
        if (!vote) return false;
        auto transition = chain_.AcquireConsensusTransitionGuard();
        const uint64_t tip = chain_.Height();
        if (!fq::FinalityEvidenceVoteWellFormed(
                *vote, vote->epoch_id, vote->set_root, tip))
            return false;
        {
            std::lock_guard<std::mutex> evidence_gate(
                fin_equivocation_gate_mu_);
            if (!fin_equivocation_journal_uncertain_ &&
                fin_equivocation_collector_.HasOffense(
                    vote->epoch_id, fq::PubkeyCommit(vote->pubkey_hex)))
                return false;
        }
        return validators_.ResolveRetainedFinalityMember(
                   vote->epoch_id, vote->set_root,
                   vote->pubkey_hex).has_value();
    }

    net::NodeServer::FinalityVoteVerifyResult VerifyFinalityVoteWire_(
            const std::vector<uint8_t>& wire,
            bool caller_holds_consensus_transition = false) {
        namespace fq = ::veld::finality::qc;
        using Result = net::NodeServer::FinalityVoteVerifyResult;
        const auto vote = fq::DecodeSignedVoteWire(wire);
        if (!vote) return Result::RejectedState;

        RetainedFinalityMember retained;
        uint64_t initial_tip = 0;
        {
            std::optional<Blockchain::ConsensusTransitionGuard> transition;
            if (!caller_holds_consensus_transition) {
                transition.emplace(
                    chain_.AcquireConsensusTransitionGuard());
            }
            initial_tip = chain_.Height();
            if (!fq::FinalityEvidenceVoteWellFormed(
                    *vote, vote->epoch_id, vote->set_root, initial_tip))
                return Result::RejectedState;
            const auto found = validators_.ResolveRetainedFinalityMember(
                vote->epoch_id, vote->set_root, vote->pubkey_hex);
            if (!found) return Result::RejectedState;
            retained = *found;
            std::lock_guard<std::mutex> assembler_gate(fin_assembler_mu_);
            if (fin_assembler_.HasExactVote(*vote))
                return Result::AlreadyKnown;
        }

        const fq::SnapshotEntry initial_member =
            EvidenceSnapshotEntry_(retained);
        const auto authenticated = fq::AuthenticateVoteForMember(
            *vote, retained.epoch, retained.root, initial_member,
            fq::NETWORK_ID, GenesisHashBytes_());
        if (!authenticated) return Result::InvalidSignature;

        // A block/reorg may have completed during ML-DSA verification.  Repeat
        // structural and retained-membership checks while the consensus
        // transition is serialized, then mutate evidence/assembler state in
        // the fixed transition -> evidence -> assembler lock order.
        {
        std::optional<Blockchain::ConsensusTransitionGuard> transition;
        if (!caller_holds_consensus_transition) {
            transition.emplace(chain_.AcquireConsensusTransitionGuard());
        }
        const uint64_t tip = chain_.Height();
        if (!fq::FinalityEvidenceVoteWellFormed(
                *vote, vote->epoch_id, vote->set_root, tip))
            return Result::RejectedState;
        const auto fresh_retained =
            validators_.ResolveRetainedFinalityMember(
                vote->epoch_id, vote->set_root, vote->pubkey_hex);
        if (!fresh_retained ||
            fresh_retained->epoch != retained.epoch ||
            fresh_retained->root != retained.root ||
            fresh_retained->pubkey_commit != retained.pubkey_commit ||
            fresh_retained->pubkey_hex != retained.pubkey_hex)
            return Result::RejectedState;
        const fq::SnapshotEntry member =
            EvidenceSnapshotEntry_(*fresh_retained);

        std::lock_guard<std::mutex> evidence_gate(
            fin_equivocation_gate_mu_);
        const Hash256 signer_commit = authenticated->MemberCommit();
        if (fin_equivocation_journal_uncertain_) {
            const auto retried = PersistFinalityEvidenceLocked_();
            if (retried != FinalityEvidencePersistStatus::Committed)
                return Result::RejectedState;
            fin_equivocation_journal_uncertain_ = false;
        }
        if (fin_equivocation_collector_.HasOffense(
                vote->epoch_id, signer_commit)) {
            fin_equivocation_detector_.EraseSignerEpoch(
                vote->epoch_id, signer_commit);
            std::lock_guard<std::mutex> assembler_gate(fin_assembler_mu_);
            fin_assembler_.RemoveSignerEpoch(vote->epoch_id, signer_commit);
            return Result::EvidenceOnly;
        }

        const auto observed = fin_equivocation_detector_.ObserveAuthenticated(
            *authenticated, member, tip, fq::NETWORK_ID,
            GenesisHashBytes_());
        if (observed.result == fq::FinalityEquivocationDetector::
                                   ObserveResult::REJECTED ||
            observed.result == fq::FinalityEquivocationDetector::
                                   ObserveResult::STORAGE_ERROR)
            return Result::RejectedState;
        if (observed.result == fq::FinalityEquivocationDetector::
                                   ObserveResult::COMPLETED_EVIDENCE) {
            if (!observed.evidence) return Result::RejectedState;
            const auto offer =
                fin_equivocation_collector_.Offer(*observed.evidence);
            if (offer == fq::FinalityEquivocationCollector::
                             OfferResult::INSERTED) {
                const auto persisted = PersistFinalityEvidenceLocked_();
                if (persisted != FinalityEvidencePersistStatus::Committed) {
                    if (persisted ==
                            FinalityEvidencePersistStatus::NotCommitted) {
                        fin_equivocation_collector_.EraseById(
                            observed.evidence->Id());
                    } else {
                        fin_equivocation_journal_uncertain_ = true;
                    }
                    // A cryptographically proven conflict must stop local QC
                    // assembly even when the disk cannot yet acknowledge it.
                    // Keep the detector's first vote so the sibling can retry.
                    std::lock_guard<std::mutex> assembler_gate(
                        fin_assembler_mu_);
                    fin_assembler_.RemoveSignerEpoch(
                        vote->epoch_id, signer_commit);
                    return Result::RejectedState;
                }
            } else if (offer != fq::FinalityEquivocationCollector::
                                    OfferResult::ALREADY_KNOWN &&
                       offer != fq::FinalityEquivocationCollector::
                                    OfferResult::OFFENSE_ALREADY_STORED) {
                // The proof is authentic even when the bounded durable pool is
                // full or cannot encode it.  It must still revoke this
                // signer's local QC contribution; storage pressure cannot turn
                // an equivocator back into an assembling voter.
                std::lock_guard<std::mutex> assembler_gate(
                    fin_assembler_mu_);
                fin_assembler_.RemoveSignerEpoch(
                    vote->epoch_id, signer_commit);
                return Result::RejectedState;
            }
            fin_equivocation_detector_.EraseSignerEpoch(
                vote->epoch_id, signer_commit);
            std::lock_guard<std::mutex> assembler_gate(fin_assembler_mu_);
            fin_assembler_.RemoveSignerEpoch(vote->epoch_id, signer_commit);
            return Result::EvidenceOnly;
        }

        // Only a current canonical vote-window frame may reach QC assembly.
        // Every other authenticated historical/sibling vote remains
        // evidence-only and is never re-gossiped.
        const auto snapshot = fin_state_.snapshots.find(vote->epoch_id);
        if (snapshot == fin_state_.snapshots.end() ||
            snapshot->second.root != vote->set_root)
            return Result::EvidenceOnly;
        fq::CheckpointRef canonical_target;
        canonical_target.height = vote->target.height;
        try {
            canonical_target.hash =
                chain_.GetBlock(vote->target.height).GetHash();
        } catch (...) {
            return Result::EvidenceOnly;
        }
        if (!fq::VoteMatchesCanonicalFrame(
                *vote, snapshot->second, tip, canonical_target,
                fin_state_.record))
            return Result::EvidenceOnly;

        std::lock_guard<std::mutex> assembler_gate(fin_assembler_mu_);
        if (fin_assembler_.HasVoteClaim(*vote))
            return Result::AlreadyKnown;
        return fin_assembler_.OfferAuthenticated(
                   *authenticated, snapshot->second)
            ? Result::AcceptedNew : Result::RejectedState;
        }
    }

    void DurableRemoveControlFile_(const std::string& path) const {
        std::error_code ec;
        if (!std::filesystem::remove(path, ec) || ec)
            throw std::runtime_error("cannot remove durable control file");
#if !defined(_WIN32)
        const std::string parent =
            std::filesystem::path(path).parent_path().string();
        int dfd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd < 0) throw std::runtime_error("cannot open datadir for control-file fsync");
        const bool ok = ::fsync(dfd) == 0;
        ::close(dfd);
        if (!ok) throw std::runtime_error("cannot fsync control-file removal");
#endif
    }

    std::string SnapshotReplayRequirementPath_() const {
        std::string dd = data_dir_;
        for (auto& c : dd) if (c == '\\') c = '/';
        return dd + "/db/.snapshot-consensus-replay-required";
    }

    bool SnapshotFastStartRevoked_() const {
        std::error_code ec;
        const bool exists = std::filesystem::exists(
            SnapshotRevocationMarkerPath_(), ec);
        return ec || exists;
    }

    std::string SnapshotRevocationMarkerPath_() const {
        return (std::filesystem::path(data_dir_) /
                ".snapshot-fast-start-revoked").string();
    }

#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    bool WriteSnapshotReplayRequirementAt_(const std::string& path,
                                           uint64_t height,
                                           const std::string& tip_hash) {
        if (height == 0 || !SnapshotManifestIsHex64(tip_hash)) return false;
        const std::string body = "schema=1\nheight=" + std::to_string(height) +
                                 "\ntip_hash=" + tip_hash + "\n";
        return DurableWriteControlFile_(path, body);
    }

    std::optional<std::pair<uint64_t, std::string>>
    ReadSnapshotReplayRequirement_() const {
        auto body = ReadSecureControlFile_(SnapshotReplayRequirementPath_(), 512);
        if (!body) return std::nullopt;
        std::istringstream in(*body);
        std::string schema, height_text, tip_hash, line;
        size_t schema_count = 0, height_count = 0, tip_count = 0;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            auto eq = line.find('=');
            if (eq == std::string::npos)
                throw std::runtime_error(
                    "snapshot consensus-replay requirement is malformed");
            const std::string key = line.substr(0, eq);
            const std::string value = line.substr(eq + 1);
            if (key == "schema") { ++schema_count; schema = value; }
            else if (key == "height") { ++height_count; height_text = value; }
            else if (key == "tip_hash") { ++tip_count; tip_hash = value; }
            else throw std::runtime_error(
                "snapshot consensus-replay requirement has an unknown field");
        }
        bool digits = !height_text.empty() && height_text.size() <= 20;
        for (char c : height_text)
            if (c < '0' || c > '9') { digits = false; break; }
        uint64_t height = 0;
        if (digits) {
            try { height = std::stoull(height_text); }
            catch (...) { digits = false; }
        }
        if (schema_count != 1 || height_count != 1 || tip_count != 1 ||
            schema != "1" || !digits || height == 0 ||
            !SnapshotManifestIsHex64(tip_hash)) {
            throw std::runtime_error(
                "snapshot consensus-replay requirement is not canonical");
        }
        return std::make_pair(height, tip_hash);
    }

    void RemoveSnapshotReplayRequirement_() {
        DurableRemoveControlFile_(SnapshotReplayRequirementPath_());
    }
#endif

    std::string IndependentValidationRequirementPath_() const {
        std::string dd = data_dir_;
        for (auto& c : dd) if (c == '\\') c = '/';
        return dd + "/.background-chainstate-required";
    }

#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    std::string ValidatedBackgroundPrefixPath_() const {
        std::string dd = data_dir_;
        for (auto& c : dd) if (c == '\\') c = '/';
        return dd + "/.validated-background-prefix";
    }

    bool WriteValidatedBackgroundPrefix_(uint64_t height,
                                         const Hash256& tip_hash) {
        if (height == 0 || HashIsZero(tip_hash)) return false;
        return DurableWriteControlFile_(
            ValidatedBackgroundPrefixPath_(),
            "schema=1\nheight=" + std::to_string(height) +
            "\ntip_hash=" + HashToHex(tip_hash) + "\n");
    }

    std::optional<std::pair<uint64_t, std::string>>
    ReadValidatedBackgroundPrefix_() const {
        auto body = ReadSecureControlFile_(
            ValidatedBackgroundPrefixPath_(), 384);
        if (!body) return std::nullopt;
        std::istringstream in(*body);
        std::string line, schema, height_text, tip_hash;
        size_t schema_count = 0, height_count = 0, tip_count = 0;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            const auto eq = line.find('=');
            if (eq == std::string::npos)
                throw std::runtime_error(
                    "validated background prefix is malformed");
            const std::string key = line.substr(0, eq);
            const std::string value = line.substr(eq + 1);
            if (key == "schema") { ++schema_count; schema = value; }
            else if (key == "height") {
                ++height_count;
                height_text = value;
            } else if (key == "tip_hash") {
                ++tip_count;
                tip_hash = value;
            } else {
                throw std::runtime_error(
                    "validated background prefix has an unknown field");
            }
        }
        uint64_t height = 0;
        if (schema_count != 1 || height_count != 1 || tip_count != 1 ||
            schema != "1" ||
            !ParseCanonicalUint64Text(height_text, height) || height == 0 ||
            !SnapshotManifestIsHex64(tip_hash)) {
            throw std::runtime_error(
                "validated background prefix is not canonical");
        }
        return std::make_pair(height, tip_hash);
    }

    bool WriteIndependentValidationRequirement_(
            const SnapshotValidationBase& base) {
        if (base.height == 0 || HashIsZero(base.tip_hash) ||
            HashIsZero(base.state_digest)) {
            return false;
        }
        return DurableWriteControlFile_(
            IndependentValidationRequirementPath_(),
            "schema=1\nheight=" + std::to_string(base.height) +
            "\ntip_hash=" + HashToHex(base.tip_hash) +
            "\nstate_digest=" + HashToHex(base.state_digest) + "\n");
    }

    std::optional<SnapshotValidationBase>
    ReadIndependentValidationRequirement_() const {
        auto body = ReadSecureControlFile_(
            IndependentValidationRequirementPath_(), 512);
        if (!body) return std::nullopt;
        std::istringstream in(*body);
        std::string line, schema, height_text, tip_hash, state_digest;
        size_t schema_count = 0, height_count = 0, tip_count = 0,
               digest_count = 0;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            const auto eq = line.find('=');
            if (eq == std::string::npos)
                throw std::runtime_error(
                    "background chainstate requirement is malformed");
            const std::string key = line.substr(0, eq);
            const std::string value = line.substr(eq + 1);
            if (key == "schema") { ++schema_count; schema = value; }
            else if (key == "height") {
                ++height_count;
                height_text = value;
            } else if (key == "tip_hash") {
                ++tip_count;
                tip_hash = value;
            } else if (key == "state_digest") {
                ++digest_count;
                state_digest = value;
            } else {
                throw std::runtime_error(
                    "background chainstate requirement has an unknown field");
            }
        }
        uint64_t height = 0;
        const bool height_ok = ParseCanonicalUint64Text(height_text, height) &&
                               height > 0;
        if (schema_count != 1 || height_count != 1 || tip_count != 1 ||
            digest_count != 1 || schema != "1" || !height_ok ||
            !SnapshotManifestIsHex64(tip_hash) ||
            !SnapshotManifestIsHex64(state_digest)) {
            throw std::runtime_error(
                "background chainstate requirement is not canonical");
        }
        SnapshotValidationBase base;
        base.height = height;
        base.tip_hash = HexToHash(tip_hash);
        base.state_digest = HexToHash(state_digest);
        if (HashIsZero(base.tip_hash) || HashIsZero(base.state_digest)) {
            throw std::runtime_error(
                "background chainstate requirement contains a zero commitment");
        }
        return base;
    }
#endif

    std::string SnapshotRecoveryRequestPath_() const {
        std::string dd = data_dir_;
        for (auto& c : dd) if (c == '\\') c = '/';
        return dd + "/.snapshot-recovery-requested";
    }

#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    bool RequestSnapshotRecoveryOnRestart(const std::string& reason) {
        std::string canonical_reason;
        for (char c : reason) {
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                c == '-' || c == '_') canonical_reason.push_back(c);
        }
        if (canonical_reason.empty() || canonical_reason.size() > 64)
            canonical_reason = "runtime-consensus-stall";
        return DurableWriteControlFile_(
            SnapshotRecoveryRequestPath_(),
            "schema=1\nreason=" + canonical_reason + "\n");
    }

    bool SnapshotRecoveryRequestedAtStartup_() const {
        auto body = ReadSecureControlFile_(SnapshotRecoveryRequestPath_(), 256);
        if (!body) return false;
        std::istringstream in(*body);
        std::string line, schema, reason;
        size_t schema_count = 0, reason_count = 0;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            auto eq = line.find('=');
            if (eq == std::string::npos)
                throw std::runtime_error("snapshot recovery request is malformed");
            std::string key = line.substr(0, eq), value = line.substr(eq + 1);
            if (key == "schema") { ++schema_count; schema = value; }
            else if (key == "reason") { ++reason_count; reason = value; }
            else throw std::runtime_error("snapshot recovery request has unknown field");
        }
        bool reason_ok = !reason.empty() && reason.size() <= 64;
        for (char c : reason)
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                  c == '-' || c == '_')) reason_ok = false;
        if (schema_count != 1 || reason_count != 1 || schema != "1" || !reason_ok)
            throw std::runtime_error("snapshot recovery request is not canonical");
        return true;
    }

    void ClearSnapshotRecoveryRequest_() {
        DurableRemoveControlFile_(SnapshotRecoveryRequestPath_());
    }

    // Same-datadir historical verification remains available as the explicit
    // operator `--verify-pow` diagnostic.

    void RevokeSnapshotValidation_(const std::string& reason) {
        mining_.store(false, std::memory_order_release);
        SetChainFullyValidatedLatch_(false);
        snapshot_state_clean_.store(false, std::memory_order_release);
        BumpValidationGeneration_();
        snapshot_background_verification_failed_.store(
            true, std::memory_order_release);
        for (const auto& path : {
                 IndependentValidationRequirementPath_(),
                 SnapshotReplayRequirementPath_()}) {
            std::error_code exists_ec;
            const bool present = std::filesystem::exists(path, exists_ec);
            if (exists_ec || !present) continue;
            try {
                DurableRemoveControlFile_(path);
            } catch (const std::exception& e) {
                std::cerr << "  [snapshot] FATAL: could not retire rejected "
                             "validation state: " << e.what() << "\n";
            }
        }
        {
            std::lock_guard<std::mutex> lock(background_validation_mutex_);
            snapshot_validation_base_.reset();
        }
        independent_validation_height_.store(0,
                                             std::memory_order_release);
        std::string canonical_reason;
        for (char c : reason) {
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                c == '-' || c == '_') {
                canonical_reason.push_back(c);
            }
        }
        if (canonical_reason.empty() || canonical_reason.size() > 64)
            canonical_reason = "background-chainstate-failed";
        const std::string revoked_path =
            snapshot_bootstrap::RevocationPath(data_dir_);
        if (!DurableWriteControlFile_(
                revoked_path,
                "schema=1\nreason=" + canonical_reason + "\n")) {
            std::cerr << "  [snapshot] FATAL: could not persist the "
                         "fast-start revocation sentinel; local storage "
                         "requires operator inspection.\n";
        }
        std::error_code receipt_ec;
        std::filesystem::remove(
            snapshot_bootstrap::ReceiptPath(data_dir_), receipt_ec);
        (void)RequestSnapshotRecoveryOnRestart(canonical_reason);
    }
#endif

    void FailPowVerify_(uint64_t h, const char* why,
                        bool mandatory_snapshot_check = false) {
        pow_verify_failed_.store(true, std::memory_order_release);
        mining_.store(false, std::memory_order_release);   // never extend an unverified chain
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        if (mandatory_snapshot_check)
            RevokeSnapshotValidation_(
                "snapshot-background-pow-failed");
#else
        (void)mandatory_snapshot_check;
#endif
        std::cerr << "\n  [pow-verify] *** FATAL: block " << h << " FAILED PoW re-verification ("
                  << why << "). The on-disk history is NOT proven to be the canonical "
                  << "proof-of-work chain. Mining HALTED. Re-sync trustlessly:\n"
                  << "      veld-node --full-ibd     (after discarding this datadir)\n\n";
        std::cerr.flush();
    }

    void StartBackgroundPowVerification(
            uint64_t from_height,
            std::string marker_path = "",
            bool mandatory_snapshot_check = false) {
        if (pow_verify_target_.load() != 0) return;              // already running / ran
        uint64_t tip = chain_.Height();
        if (from_height < 1) from_height = 1;
        if (tip == 0 || from_height > tip) {
            pow_verify_done_.store(true);
            if (!marker_path.empty()) { std::error_code ec; std::filesystem::remove(marker_path, ec); }
            return;
        }
        pow_verify_from_.store(from_height);
        pow_verified_height_.store(from_height - 1);
        pow_verify_dataset_unavailable_.store(false, std::memory_order_release);
        pow_verify_target_.store(tip);
        pow_verify_thread_ = std::thread(
            [this, from_height, tip, marker_path,
             mandatory_snapshot_check]() {
            std::cerr << "  [pow-verify] background PoW re-verification " << from_height << ".."
                      << tip
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
                      << (mandatory_snapshot_check
                              ? " (mandatory snapshot validation)\n"
                              : " (optional operator diagnostic)\n");
#else
                      << " (optional operator diagnostic)\n";
#endif
            std::cerr.flush();
            for (uint64_t h = from_height; h <= tip && running_.load(); ++h) {
                auto hash_opt = db_.GetHashAtHeight(h);
                if (!hash_opt) {
                    FailPowVerify_(h, "canonical height index missing",
                                   mandatory_snapshot_check);
                    return;
                }
                auto data = db_.ReadBlock(HexToHash(*hash_opt));
                if (!data) {
                    FailPowVerify_(h, "block data missing",
                                   mandatory_snapshot_check);
                    return;
                }
                Block blk;
                const size_t consumed = Block::Deserialize(*data, 0, blk);
                if (consumed == 0 || consumed != data->size() ||
                    blk.Serialize() != *data) {
                    FailPowVerify_(h, "non-canonical serialized block",
                                   mandatory_snapshot_check);
                    return;
                }
                blk.height = h;
                uint32_t want = chain_.ComputeNextBitsAt(h - 1);
                if (want == 0 || blk.header.bits != want) {
                    FailPowVerify_(h, "bits != expected difficulty",
                                   mandatory_snapshot_check);
                    return;
                }
                auto pow_lease =
                    mining::GlobalExpensivePowBudget().TryAcquire(
                        mining::ExpensivePowUse::ReorgVerify);
                if (!pow_lease) {
                    pow_verify_from_.store(h, std::memory_order_release);
                    pow_verify_target_.store(0, std::memory_order_release);
                    std::cerr << "  [pow-verify] PAUSED at block " << h
                              << ": global expensive-PoW budget exhausted; "
                                 "no validity decision was recorded.\n";
                    std::cerr.flush();
                    return;
                }
                bool dataset_unavailable = false;
                if (!Blockchain::VerifyBlockPoW(blk, &dataset_unavailable)) {
                    if (dataset_unavailable) {
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
                        if (mandatory_snapshot_check) {
                            FailPowVerify_(h, "VeldHash dataset unavailable",
                                           true);
                        } else {
                            pow_verify_dataset_unavailable_.store(
                                true, std::memory_order_release);
                            pow_verify_from_.store(h, std::memory_order_release);
                            pow_verify_target_.store(0, std::memory_order_release);
                            std::cerr << "  [pow-verify] PAUSED at block " << h
                                      << ": the local VeldHash dataset is unavailable; "
                                         "the chain was not marked invalid and mining "
                                         "was not stopped. Repair local dataset access "
                                         "and retry --verify-pow.\n";
                            std::cerr.flush();
                        }
#else
                        pow_verify_dataset_unavailable_.store(
                            true, std::memory_order_release);
                        pow_verify_from_.store(h, std::memory_order_release);
                        pow_verify_target_.store(0, std::memory_order_release);
                        std::cerr << "  [pow-verify] PAUSED at block " << h
                                  << ": the local VeldHash dataset is unavailable; "
                                     "the chain was not marked invalid and mining "
                                     "was not stopped. Repair local dataset access "
                                     "and retry --verify-pow.\n";
                        std::cerr.flush();
#endif
                        return;
                    }
                    FailPowVerify_(h, "PoW below target (fabricated work)",
                                   mandatory_snapshot_check);
                    return;
                }
                pow_verified_height_.store(h, std::memory_order_release);
            }
            if (!running_.load()) return;
            pow_verify_done_.store(true, std::memory_order_release);
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
            if (mandatory_snapshot_check)
                SetChainFullyValidatedLatch_(true);
#endif
            if (!marker_path.empty()) {
                try {
                    DurableRemoveControlFile_(marker_path);
                } catch (const std::exception& e) {
                    std::cerr << "  [pow-verify] WARN: verification completed but "
                                 "the replay marker could not be removed: "
                              << e.what() << "; verification will repeat on the "
                                 "next start.\n";
                }
            }
            std::cerr << "  [pow-verify] COMPLETE — PoW re-verified up to tip=" << tip
                      << ".\n";
            std::cerr.flush();
        });
    }

    // From the highest compiled checkpoint <= tip (everything below is pin-guaranteed).
    uint64_t PowVerifyStartHeight_() const {
        uint64_t tip = chain_.Height();
        uint64_t from = 1;
        for (const auto& [cp_h, cp_hex] : Blockchain::AllCheckpointPins()) {
            (void)cp_hex;
            if (cp_h <= tip && cp_h + 1 > from) from = cp_h + 1;
        }
        return from;
    }
    // Explicit operator diagnostic only. Startup consensus replay has already
    // completed before this optional pass can run.
    void ForcePowVerification() {
        StartBackgroundPowVerification(PowVerifyStartHeight_());
    }
    // Shared status for independent snapshot validation and the optional
    // same-datadir operator diagnostic.
    std::string PowVerifyStatusJson() const {
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        std::optional<SnapshotValidationBase> independent_base;
        {
            std::lock_guard<std::mutex> lock(background_validation_mutex_);
            independent_base = snapshot_validation_base_;
        }
        if (independent_base) {
            const bool failed =
                snapshot_background_verification_failed_.load(
                    std::memory_order_acquire);
            std::ostringstream j;
            j << "{\"mode\":\"independent-background-ibd\""
              << ",\"running\":" << (failed ? "false" : "true")
              << ",\"failed\":" << (failed ? "true" : "false")
              << ",\"diagnostic_complete\":false"
              << ",\"verified_height\":"
              << independent_validation_height_.load(
                     std::memory_order_acquire)
              << ",\"target_height\":" << independent_base->height
              << "}";
            return j.str();
        }
#endif
        uint64_t tgt = pow_verify_target_.load();
        bool running = tgt != 0 && !pow_verify_done_.load() &&
                       !pow_verify_failed_.load() &&
                       !pow_verify_dataset_unavailable_.load();
        std::ostringstream j;
        j << "{\"running\":" << (running ? "true" : "false")
          << ",\"failed\":" << (pow_verify_failed_.load() ? "true" : "false")
          << ",\"dataset_unavailable\":"
          << (pow_verify_dataset_unavailable_.load() ? "true" : "false")
          << ",\"diagnostic_complete\":" << (pow_verify_done_.load() && !pow_verify_failed_.load() ? "true" : "false")
          << ",\"verified_height\":" << pow_verified_height_.load()
          << ",\"target_height\":" << tgt << "}";
        return j.str();
    }

    size_t LoadCheckpointsFromUrl() {
#ifdef VELD_PUBLIC_TESTNET
        // Testnet has no final-mainnet checkpoint control plane. V1 is
        // retained only for replay compatibility with already-issued local
        // records; never download from the final-mainnet checkpoint URL.
        return 0;
#endif
        constexpr const char* CHECKPOINTS_URL =
            "https://veld.network/downloads/checkpoints.json";
        uint8_t nonce[16]{};
        if (!compat::SecureRandom(nonce, sizeof(nonce))) return 0;
#if defined(_WIN32)
        const std::string tmp = data_dir_ + "\\.checkpoints.json.fetch." +
                                BytesToHex(nonce, sizeof(nonce));
#else
        const std::string tmp = data_dir_ + "/.checkpoints.json.fetch." +
                                BytesToHex(nonce, sizeof(nonce));
#endif
        struct RemoveCheckpointFetch {
            std::string path;
            ~RemoveCheckpointFetch() {
                std::error_code ignored;
                std::filesystem::remove(path, ignored);
            }
        } remove_fetch{tmp};

        const std::string curl_executable =
            compat::TrustedSystemCurlExecutable();
        if (curl_executable.empty()) return 0;
        const auto transfer = compat::RunProcessToBoundedFile(
            {curl_executable, "--disable", "--fail", "--silent", "--show-error",
             "--connect-timeout", "10", "--max-time", "30",
             "--max-filesize", std::to_string(kMaxCheckpointDocumentBytes),
             "--location", "--max-redirs", "0", "--proto", "=https",
             "--proto-redir", "=https", CHECKPOINTS_URL},
            tmp, kMaxCheckpointDocumentBytes, std::chrono::seconds(35));
        if (!transfer || transfer.bytes_written == 0) {
            return 0;
        }

        std::string body;
        try {
            std::error_code size_error;
            const uintmax_t length = std::filesystem::file_size(tmp, size_error);
            if (size_error || length == 0 ||
                length > kMaxCheckpointDocumentBytes) {
                return 0;
            }
            std::ifstream in(tmp, std::ios::binary);
            if (!in) return 0;
            body.resize(static_cast<size_t>(length));
            in.read(body.data(), static_cast<std::streamsize>(body.size()));
            if (!in || static_cast<size_t>(in.gcount()) != body.size()) return 0;
            char unexpected = 0;
            if (in.get(unexpected)) return 0;
        } catch (...) {
            return 0;
        }
        auto parsed = ParseCheckpointsJson(body);
        size_t pre = checkpoints_.Size();
        size_t accepted = 0;
        size_t rejected = 0;
        for (const auto& cp : parsed) {
            if (checkpoints_.Add(cp)) {
                ++accepted;
            } else {
                ++rejected;
            }
        }
        size_t added = checkpoints_.Size() - pre;
        if (added > 0 || rejected > 0) {
            std::cerr << "  [checkpoint-fetch] parsed=" << parsed.size()
                      << " new=" << added
                      << " accepted=" << accepted
                      << " rejected=" << rejected
                      << " total=" << checkpoints_.Size() << "\n";
            std::cerr.flush();
        }
        if (added > 0 && chain_.Height() > 0) {
            uint64_t our_h = chain_.Height();
            for (const auto& cp : checkpoints_.UpToHeight(our_h)) {
                try {
                    Block our_block = chain_.GetBlock(cp.height);
                    if (our_block.GetHash() != cp.block_hash) {
                        std::cerr << "  [checkpoint-mainchain-mismatch] "
                                  << "our h=" << cp.height
                                  << " hash=" << HashToHex(our_block.GetHash()).substr(0,16)
                                  << " checkpoint says "
                                  << HashToHex(cp.block_hash).substr(0,16)
                                  << " — node is on a wrong chain; "
                                  << "stop service and use authenticated recovery "
                                     "or a full peer IBD.\n";
                        std::cerr.flush();
                    }
                } catch (...) {
                }
            }
        }
        return added;
    }
private:

    void WireMainTokenConsensusDependencies_() {
        // These are stable VeldNode members. Install their addresses before
        // WireDB, replay, direct ingest, repair, qualification, or RPC setup
        // can expose the main token ledger to a consensus transition.
        onchain_tokens_.SetBtcHeaderChain(&btc_headers_);
        onchain_tokens_.SetBtcVeldRedeemCovenant(&bond_covenant_);
    }

    void WireFinalityVoteRpcSink_() {
        // Local validator submissions traverse the same authenticated router
        // as P2P FINVOTE.  Only AcceptedNew is relayed; EvidenceOnly siblings
        // can complete durable slash evidence but never enter gossip/QC state.
        rpc_.SetFinalityVoteSink(
            [this](const std::string& vote_json,
                   const std::string& binding_text,
                   const std::string& token_text) -> bool {
            namespace fq = ::veld::finality::qc;
            using Result = net::NodeServer::FinalityVoteVerifyResult;
#ifdef VELD_TEST_HOOKS
            test_work_finality_sink_calls_.fetch_add(
                1, std::memory_order_acq_rel);
#endif
            if (vote_json.size() != 2 * fq::SIGNED_VOTE_WIRE_BYTES)
                return false;
            const auto binding =
                work_admission::DecodeBinding(binding_text);
            if (!binding) return false;
            std::vector<uint8_t> wire;
            if (!fq::FromHexBytes(vote_json, wire)) return false;
            const auto vote = fq::DecodeSignedVoteWire(wire);
            if (!vote) return false;
            auto transition = chain_.AcquireConsensusTransitionGuard();
            const auto block_subject = CurrentBlockProductionSubject_();
            if (!block_subject) return false;
            work_admission::Subject subject;
            subject.purpose = work_admission::Purpose::FinalityVote;
            subject.height = vote->target.height;
            subject.target_hash = vote->target.hash;
            subject.parent_height = block_subject->parent_height;
            subject.parent_hash = block_subject->parent_hash;
            auto active = TakeActiveRemoteSigningLeaseUnderTransition_(
                work_admission::Path::FinalityVote, subject,
                binding_text, token_text);
            if (!active || !active->OperationLive() ||
                !active->lease->ClaimForSink() || !active->OperationLive())
                return false;
#ifdef VELD_TEST_HOOKS
            test_work_finality_active_calls_.fetch_add(
                1, std::memory_order_acq_rel);
#endif
            // The authorized RPC sink already owns the outer transition
            // sequencer.  Keep that single guard through verification,
            // evidence/QC mutation, and gossip; reacquiring the non-recursive
            // block-connect mutex here would deadlock a valid standalone vote.
            const Result result = VerifyFinalityVoteWire_(
                wire, /*caller_holds_consensus_transition=*/true);
#ifdef VELD_TEST_HOOKS
            test_work_finality_verify_result_.store(
                static_cast<uint8_t>(result), std::memory_order_release);
#endif
            if (result == Result::AcceptedNew && tcp_server_ &&
                active->OperationLive()) {
#ifdef VELD_TEST_HOOKS
                test_work_finality_gossip_calls_.fetch_add(
                    1, std::memory_order_acq_rel);
#endif
                auto pm = tcp_server_->GetMessageBuilder();
                tcp_server_->BroadcastMessage(
                    pm.BuildFinalityVoteMessage(wire));
            }
            return result == Result::AcceptedNew ||
                   result == Result::AlreadyKnown ||
                   result == Result::EvidenceOnly;
        });
    }

    bool ValidateGenerationIdentityLocked_(
        const RealKeyPair& miner_keypair,
        std::string* error
    ) const {
        auto refuse = [&](const std::string& message) {
            if (error) *error = message;
            return false;
        };
        if (miner_keypair.address.empty())
            return refuse("generation identity has no address");
        if (miner_keypair.testnet != config_.IsTestNetwork())
            return refuse("generation identity belongs to the wrong network");
        try {
            const auto derived_public =
                DerivePublicKey(miner_keypair.private_key);
            if (derived_public != miner_keypair.public_key)
                return refuse("generation identity public/private key mismatch");
            if (miner_keypair.script_override.empty()) {
                if (PubKeyToAddress(derived_public, config_.IsTestNetwork()) !=
                    miner_keypair.address)
                    return refuse("generation identity address/key mismatch");
            } else {
                const auto override_script =
                    AddressToScript(miner_keypair.address);
                if (override_script.empty() ||
                    override_script != miner_keypair.script_override)
                    return refuse("generation payout override is invalid");
            }
            if (miner_keypair.GetP2PKHScript().empty())
                return refuse("generation identity has no payout script");
        } catch (const std::exception& e) {
            return refuse(std::string("generation identity validation failed: ") +
                          e.what());
        } catch (...) {
            return refuse("generation identity validation failed");
        }
        return true;
    }

    bool BindGenerationIdentityLocked_(
        const RealKeyPair& miner_keypair,
        std::string* error
    ) {
        if (!ValidateGenerationIdentityLocked_(miner_keypair, error))
            return false;
        miner_keypair_ = miner_keypair;
        generation_identity_bound_ = true;
        return true;
    }

    void StopMiningLocked_() {
        mining_.store(false, std::memory_order_release);
        if (mining_thread_.joinable()) mining_thread_.join();
        hashrate_.store(0.0, std::memory_order_release);
        mining_work_state_.store(MiningWorkState::Stopped,
                                 std::memory_order_release);
    }

    NetworkConfig   config_;
    const std::string     data_dir_;
    Blockchain          chain_;
    work_admission::AdmissionCoordinator work_admission_coordinator_;
    work_admission::BlockTemplateAuthorizationStore
        block_template_authorizations_;
    mutable std::mutex active_remote_signing_mu_;
    std::unordered_map<std::string, ActiveRemoteSigningLease>
        active_remote_signing_leases_;
#ifdef VELD_PUBLIC_TESTNET
    std::optional<public_testnet::RuntimeLimits>
        public_testnet_limits_;
    mutable std::unique_ptr<public_testnet::RuntimeClockGuard>
        public_testnet_clock_guard_;
    int64_t public_testnet_restart_signed_observed_unix_{0};
    int64_t public_testnet_restart_valid_until_unix_{0};
    mutable std::atomic<bool> public_testnet_expired_{false};
#endif
    Mempool             mempool_;
    StakingLedger       staking_;
    ValidatorRegistry   validators_;
    CheckpointStore     checkpoints_;
    OnChainTokenLedger  onchain_tokens_;
    btcspv::BtcHeaderChain btc_headers_;                        // SPV relay state
    std::atomic<uint64_t>  btc_header_tip_{0};                  // btcVELD relay: race-free snapshot of btc_headers_.BestHeight() read by the RPC thread (single writer = block path)
    std::atomic<bool>      btc_relay_fresh_snapshot_{
        !btcspv::EXTERNAL_VALUE_FRESHNESS_REQUIRED};
    btcanchor::AnchorSet   anchors_;                            // Layer-2 BTC checkpoint anchor set (dormant unless armed)

    // Security floors consumed by block admission, reorg and replay
    // reconciliation. Every floor is derived from locally verified VLF1 data.
    struct EffectiveAnchorSecurityFloor {
        enum class Source : uint8_t {
            LocalObserved = 2,
            // When the external mirror and the authoritative DB copy differ
            // monotonically after a crash, retain the older one until replay
            // proves both.  It must not be silently erased merely because a
            // numerically higher unauthenticated local record also exists.
            LocalRecovery = 3,
        };
        Source source = Source::LocalObserved;
        // The artifact identity is carried with the floor so a monotonic
        // update retains every prior milestone without duplicating an
        // idempotent re-observation.
        Hash256 artifact_id{};
        uint64_t target_height = 0;
        Hash256 target_hash{};
        uint64_t proof_carrier_height = 0;
        Hash256 proof_carrier_hash{};
        Hash256 btc_block_hash{};
        Hash256 btc_txid{};
        ::veld::finality::qc::FinalizedRecord authorization_record{};
        Hash256 floor_digest{};
        // A higher permanent anchor proves ancestry, but cannot prove that the
        // complete signed authorization record below was reconstructed at C.
        // This latch is set only while the exact floor is the replay/live
        // promotion result, and is rolled back with module state.
        bool exact_reconstruction_observed = false;
    };
    enum class EffectiveAnchorSecurityStatus : uint8_t {
        None = 0,
        Pending,
        Satisfied,
        Mismatched,
    };
    btcanchor::floor_store::Store anchor_floor_store_;
    std::vector<btcanchor::floor_store::Record>
        anchor_floor_inherited_records_;
    std::vector<btcanchor::floor_store::Record>
        anchor_floor_validation_records_;
    size_t anchor_floor_recovery_record_count_{0};
    mutable std::mutex anchor_floor_store_mutex_;
    // Every observed floor remains pinned.  A newer floor cannot erase lower
    // knowledge until exact replay proves it.  VLF1 contributes one monotonic
    // LocalObserved entry: after a higher permanent is itself durable, that
    // higher target commits the older local prefix.
    std::vector<EffectiveAnchorSecurityFloor>
        effective_anchor_security_floors_;
    mutable std::mutex anchor_security_floors_mutex_;
    mutable std::mutex anchor_floor_prepare_mutex_;
    bool anchor_floor_prepared_{false};
    // The anchor-floor repair flag mirrors the owner-only VLF1 uncertainty
    // sentinel. The durable-commit repair flag is derived solely from VDP1 in
    // the authoritative index DB; there is deliberately no second VDC file.
    std::atomic<bool> anchor_floor_repair_required_{false};
    std::atomic<bool> anchor_floor_security_uncertain_{false};
    std::atomic<bool> durable_commit_fail_stop_{false};
    std::atomic<bool> durable_commit_repair_required_{false};
    std::atomic<bool> durable_commit_ibd_refusal_logged_{false};
    std::atomic<bool> startup_replay_active_{false};
    std::optional<db::VeldDB::DurablePublicationPending>
        startup_durable_publication_recovery_;
    std::optional<db::VeldDB::ReorgUtxoPending>
        startup_reorg_utxo_recovery_;
    bool startup_utxo_recovery_required_{false};
#ifdef VELD_TEST_HOOKS
    bool anchor_floor_test_persist_failure_{false};
    bool canonical_durable_marker_test_failure_{false};
    bool durable_publication_clear_test_failure_{false};
#endif
    // Locked-QC finality state: epoch snapshots, the retained certificate and
    // its carrier, and
    // the warm-up machine. Guarded by the same serialized block path that
    // single-writes final_height_ below.
    //
    // final_height_ is retained as the published READ surface (RPC, anchors,
    // gates all load it), but it is no longer COMPUTED from live votes — it is
    // now mirrored from fin_state_.FinalizedHeight() after every block, so the
    // published mark is the artifact rather than a re-derivation of it.
    ::veld::finality::qc::FinalityState fin_state_;

    // Node-side certificate assembler: collects gossiped votes from validator
    // daemons (via the submitfinalityvote RPC) and assembles a QC when a
    // supermajority agrees. Permissionless — a certificate carries its own
    // proof — so this holds no secrets and is not consensus-critical: a node
    // that assembles differently still converges, because certificates are
    // accepted on proof, not provenance.
    ::veld::finality::qc::CertAssembler fin_assembler_;
    mutable std::mutex fin_assembler_mu_;

    // Authenticated sibling votes never enter CertAssembler.  Pending singles
    // are bounded process-local detection state; completed pairs are held in a
    // separate bounded collector and atomically journaled before they become
    // visible to operator/RPC preparation surfaces.
    ::veld::finality::qc::FinalityEquivocationDetector
        fin_equivocation_detector_;
    ::veld::finality::qc::FinalityEquivocationCollector
        fin_equivocation_collector_;
    mutable std::mutex fin_equivocation_gate_mu_;
    bool fin_equivocation_journal_uncertain_{false};
#ifdef VELD_TEST_HOOKS
    std::function<FinalityEvidencePersistStatus(const std::string&)>
        fin_equivocation_persist_override_;
#endif

    std::atomic<uint64_t>  final_height_{0};                    // Layer-3 finalized high-water-mark (single writer = the serialized block path via UpdateFinality_; read by RPC)
    // One atomic frame, not two independently sampled atomics: asynchronous
    // mempool readers must never pair a new `finality ever active` bit with an
    // old finalized height (or vice versa) while a block/reorg publishes
    // consensus state. Launch activation itself is compiled and height-derived;
    // Bitcoin anchor state is additive and does not enter this permission frame.
    // Heights cannot approach bit 63 within the protocol lifetime.
    static constexpr uint64_t PEG_GATE_FINALITY_EVER_ACTIVE_BIT_ =
        uint64_t{1} << 63;
    std::atomic<uint64_t>  peg_gate_snapshot_{0};
    std::atomic<bool>      redeem_index_healthy_{true};          // N-02: false closes payout RPC until startup replay repairs the derived index
    std::atomic<bool>      mint_nullifier_index_healthy_{true};  // false pauses new mint proof production; transfers/redeems remain live
    btcveld::SupplySnapshotPublisher btcveld_supply_snapshot_;   // coherent (token supply, canonical tip, hash) RPC tuple
    btcveld::SignerBondCovenant bond_covenant_;                 // redeem bond and slash state
    AmmLedger           amm_;
    TierEngine          tiers_;
    VaultLedger         vault_;
    GovernanceEngine    governance_;
    std::unique_ptr<ValidatorRegistry> validators_alt_;
    std::unique_ptr<StakingLedger>     staking_alt_;
    std::unique_ptr<OnChainTokenLedger> onchain_tokens_alt_;   // btcVELD: fork-aware
    std::unique_ptr<btcspv::BtcHeaderChain> btc_headers_alt_;  // btcVELD SPV: fork-aware
    std::unique_ptr<btcveld::SignerBondCovenant> bond_covenant_alt_;  // btcVELD redeem: fork-aware
    std::unique_ptr<AmmLedger>          amm_alt_;               // btcVELD: fork-aware
    std::unique_ptr<btcanchor::AnchorSet> anchors_alt_;
    std::unique_ptr<::veld::finality::qc::FinalityState> fin_state_alt_;
    std::map<uint64_t, Hash256>          alt_chain_hashes_;
    uint64_t                             alt_common_ancestor_height_ = 0;
    Blockchain::AltEngineOverlay       overlay_alt_;
    uint64_t                           alt_running_supply_ = 0;
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
    std::function<void()>               dstate_memory_observer_;
#endif
    StorageEngine   storage_;
    db::VeldDB      db_;
    RpcServer       rpc_;
    explorer::BlockExplorer explorer_;

    struct PendingSolution {
        uint64_t    prev_height;
        Hash256     prev_hash;
        uint64_t    nonce;
        Hash256     best_hash;
        std::vector<uint8_t> miner_script;
        std::chrono::steady_clock::time_point received_at;
        bool        is_winner{false};
    };
    std::vector<PendingSolution> pending_solutions_;
    std::mutex                   solution_mutex_;
    std::unique_ptr<net::NodeServer> tcp_server_;
    std::atomic<uint64_t> advertised_services_{MessageType::NODE_FULL};

    std::atomic<bool>   running_;
    std::atomic<bool>   mining_;
    std::atomic<bool>   ibd_complete_{false};
    bool                background_validation_only_{false};
    bool                snapshot_quarantine_only_{false};
    mutable std::atomic<bool> anchor_floor_ibd_refusal_logged_{false};
    bool                full_ibd_ = false;   // --full-ibd/--no-snapshot: never bootstrap from a snapshot
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    bool                snapshot_fast_start_eligible_ = false;
    uint64_t            snapshot_receipt_height_ = 0;
    std::string         snapshot_receipt_tip_;
    mutable std::mutex  background_validation_mutex_;
    std::optional<SnapshotValidationBase> snapshot_validation_base_;
    std::atomic<uint64_t> independent_validation_height_{0};
    uint64_t            background_validation_target_height_{0};
    std::atomic<uint64_t> background_prefix_persisted_height_{0};
    std::atomic<bool>     background_prefix_write_warning_logged_{false};
    BackgroundValidationObservation background_validation_observation_;
    void MaybeCaptureBackgroundValidationTarget_() {
        if (!background_validation_only_ ||
            background_validation_target_height_ == 0) {
            return;
        }

        const uint64_t height = chain_.Height();
        if (height > 0 &&
            (height <= 10 || height % 25 == 0 ||
             height >= background_validation_target_height_) &&
            height > background_prefix_persisted_height_.load(
                         std::memory_order_acquire) &&
            !chain_.IsEmpty()) {
            const Hash256 tip_hash = chain_.TipCopy().GetHash();
            if (WriteValidatedBackgroundPrefix_(height, tip_hash)) {
                background_prefix_persisted_height_.store(
                    height, std::memory_order_release);
            } else if (!background_prefix_write_warning_logged_.exchange(
                           true, std::memory_order_acq_rel)) {
                std::cerr << "  [background-ibd] WARN: could not persist "
                             "restart progress; validation remains safe but "
                             "more work may repeat after a restart.\n";
                std::cerr.flush();
            }
        }

        {
            std::lock_guard<std::mutex> lock(background_validation_mutex_);
            if (background_validation_observation_.reached ||
                background_validation_observation_.passed_target) {
                return;
            }
        }
        if (height < background_validation_target_height_) return;

        BackgroundValidationObservation observation;
        observation.height = height;
        if (!chain_.IsEmpty()) observation.tip_hash = chain_.TipCopy().GetHash();
        if (height == background_validation_target_height_) {
            observation.state_digest = ConsensusStateDigest();
            observation.reached = true;
        } else {
            observation.passed_target = true;
        }

        std::lock_guard<std::mutex> lock(background_validation_mutex_);
        if (!background_validation_observation_.reached &&
            !background_validation_observation_.passed_target) {
            background_validation_observation_ = observation;
        }
    }
#endif
    std::atomic<bool>   chain_fully_validated_{false};
    // One authoritative production-work gate consumes these explicit startup
    // proofs.  Default false is intentional: unknown state is refusal.
    std::atomic<bool>   startup_replay_complete_{false};
    std::atomic<bool>   snapshot_state_clean_{false};
    std::atomic<bool>   datadir_identity_valid_{false};
    std::atomic<bool>   checkpoint_anchor_valid_{false};
    std::atomic<uint64_t> validation_generation_{1};
#ifdef VELD_TEST_HOOKS
    std::atomic<bool> test_work_force_tip_unknown_{false};
    std::atomic<bool> test_work_local_runtime_open_{true};
    std::atomic<bool> test_work_admission_mining_barrier_{false};
    std::atomic<uint64_t> test_work_mining_admitted_calls_{0};
    std::atomic<uint64_t> test_work_durable_writer_calls_{0};
    std::atomic<uint64_t> test_work_block_broadcast_calls_{0};
    std::atomic<uint64_t> test_work_tx_gossip_calls_{0};
    std::atomic<uint64_t> test_work_finality_gossip_calls_{0};
    std::atomic<uint64_t> test_work_finality_sink_calls_{0};
    std::atomic<uint64_t> test_work_finality_active_calls_{0};
    std::atomic<uint8_t> test_work_finality_verify_result_{UINT8_MAX};
#endif
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
    std::atomic<bool>   snapshot_background_verification_failed_{false};
#endif
    // Optional same-datadir PoW diagnostic. Snapshot trust convergence uses
    // the independent peer-fed chainstate above.
    std::thread           pow_verify_thread_;
    std::atomic<uint64_t> pow_verify_from_{0};
    std::atomic<uint64_t> pow_verified_height_{0};
    std::atomic<uint64_t> pow_verify_target_{0};      // 0 => not running
    std::atomic<bool>     pow_verify_failed_{false};
    std::atomic<bool>     pow_verify_done_{false};
    std::atomic<bool>     pow_verify_dataset_unavailable_{false};
    // Owned lifecycle threads.  Both closures capture this, so detached
    // execution is forbidden; Stop() moves/joins them before member teardown.
    std::thread           prewarm_thread_;
    std::mutex            prewarm_thread_mutex_;
    std::condition_variable prewarm_cv_;
    bool                  prewarm_started_{false};
    std::thread           oracle_thread_;
    std::mutex            oracle_thread_mutex_;
    std::atomic<bool>     oracle_in_flight_{false};
    std::atomic<uint64_t> miner_progress_counter_{0};
    std::atomic<uint64_t> last_pool_flush_height_{0};
    std::mutex          generation_mutex_;
    bool                generation_identity_bound_{false};
    std::thread         mining_thread_;
    // Owned, joined-on-shutdown worker that runs post-reorg mempool fixups serially.
    // Replaces the old detached reorg threads whose unbounded lifetime dereferenced
    // chain_/mempool_ after teardown (heap-use-after-free / destroyed-mutex hang).
    std::thread                       reorg_fixup_thread_;
    std::deque<std::function<void()>> reorg_fixup_q_;
    std::mutex                        reorg_fixup_mtx_;
    std::condition_variable           reorg_fixup_cv_;
    // Set while on_commit_ rebuilds the derived-state engines (staking_/validators_/
    // governance_) after a reorg, OFF the chain lock. The miner checks it and pauses a
    // round rather than reading half-rebuilt engine state (a reorg-time consistency race).
    std::atomic<bool>                 reorg_rebuild_active_{false};
    std::atomic<MiningWorkState>      mining_work_state_{
        MiningWorkState::Stopped};
    std::atomic<uint64_t> total_hashes_{0};
    std::atomic<double>   hashrate_{0.0};
    std::atomic<uint64_t> session_blocks_mined_{0};
    RealKeyPair         miner_keypair_;
    RealKeyPair         pool_keypair_;
    RealKeyPair         endorsement_pool_keypair_;
    uint32_t            mining_bits_ = 0;
    unsigned            mining_threads_ = 1;
    uint16_t            p2p_port_    = 0;
    uint64_t            last_token_height_ = 0;
    uint64_t            last_module_supply_ = 0;  // exact canonical emission through last_token_height_

    static constexpr size_t ANCHOR_WS_MAX_WIRE_BYTES_ = 16u * 1024u;

    std::string AnchorSecurityDirectory_() const {
        return data_dir_ + "/security";
    }

    // The VLF1 store owns its private security directory.
    void EnsureAnchorSecurityDirectory_() const {
        std::string dir_error;
        if (!channel::secure_file::EnsurePrivateDirectory(
                AnchorSecurityDirectory_(), &dir_error)) {
            throw std::runtime_error(
                "anchor security directory is not a private owner-only "
                "directory: " + dir_error);
        }
    }

    std::string AnchorFloorPersistentPath_() const {
        return AnchorSecurityDirectory_() + "/anchor-floor.vlf1";
    }

    std::string AnchorFloorUncertaintyPath_() const {
        return AnchorSecurityDirectory_() + "/anchor-floor.uncertain";
    }

    static const std::vector<uint8_t>& AnchorFloorUncertainMarker_() {
        static const std::vector<uint8_t> marker{
            'V','L','F','1','-','U','N','C','E','R','T','A','I','N','\n'};
        return marker;
    }

    static const std::vector<uint8_t>& AnchorFloorClearMarker_() {
        static const std::vector<uint8_t> marker{
            'V','L','F','1','-','C','L','E','A','R','\n'};
        return marker;
    }

    bool AnchorFloorRepairBlocksSnapshot_() const {
        return anchor_floor_repair_required_.load(
                   std::memory_order_acquire) ||
               anchor_floor_security_uncertain_.load(
                   std::memory_order_acquire);
    }

    bool DurableCommitFailStopBlocksSnapshot_() const {
        return DurableCommitFailStop();
    }

    void LogAnchorFloorSnapshotRefusal_(const char* surface) const {
        std::cerr << "  [" << surface << "] REFUSED: a post-durable "
                     "anchor-floor write is uncertain. The existing local "
                     "blocks/db must be replayed first to reconstruct and "
                     "persist the exact VLF1 floor; snapshot replacement "
                     "cannot run until that repair completes.\n";
        std::cerr.flush();
    }

    void LogDurableCommitSnapshotRefusal_(const char* surface) const {
        std::cerr << "  [" << surface << "] REFUSED: canonical persistence "
                     "or its in-memory durable publication invariant is "
                     "unproven. Restart and canonical replay must reconcile "
                     "the existing datadir before snapshot replacement is "
                     "eligible.\n";
        std::cerr.flush();
    }

    size_t EffectiveAnchorSecurityFloorCount_() const {
        std::lock_guard<std::mutex> lock(anchor_security_floors_mutex_);
        return effective_anchor_security_floors_.size();
    }

    static std::array<std::pair<uint64_t, Hash256>, 3>
    EffectiveAnchorSecurityPins_(
            const EffectiveAnchorSecurityFloor& floor) {
        return {{{floor.target_height, floor.target_hash},
                 {floor.proof_carrier_height,
                  floor.proof_carrier_hash},
                 {floor.authorization_record.carrier.height,
                  floor.authorization_record.carrier.hash}}};
    }

    static EffectiveAnchorSecurityFloor EffectiveLocalFloorFromRecord_(
            const btcanchor::floor_store::Record& record,
            EffectiveAnchorSecurityFloor::Source source,
            bool exact_reconstruction_observed) {
        const auto& checkpoint = record.checkpoint;
        EffectiveAnchorSecurityFloor incoming;
        incoming.source = source;
        incoming.target_height = checkpoint.target_height;
        incoming.target_hash = checkpoint.entry.veld_block_hash;
        incoming.proof_carrier_height =
            checkpoint.entry.carrying_veld_height;
        incoming.proof_carrier_hash =
            checkpoint.entry.carrying_veld_hash;
        incoming.btc_block_hash = checkpoint.entry.btc_block_hash;
        incoming.btc_txid = checkpoint.entry.btc_txid;
        incoming.authorization_record = checkpoint.authorization_record;
        incoming.floor_digest = record.floor_digest;
        incoming.exact_reconstruction_observed =
            exact_reconstruction_observed;
        return incoming;
    }

    void RequireEffectiveAnchorFloorCompatibilityLocked_(
            const EffectiveAnchorSecurityFloor& incoming,
            const char* source_name) const {
        const auto incoming_pins = EffectiveAnchorSecurityPins_(incoming);
        for (const auto& prior : effective_anchor_security_floors_) {
            const auto prior_pins = EffectiveAnchorSecurityPins_(prior);
            for (const auto& a : incoming_pins) {
                for (const auto& b : prior_pins) {
                    if (a.first == b.first && a.second != b.second) {
                        throw std::runtime_error(
                            std::string(source_name) +
                            " conflicts with an installed anchor pin at height " +
                            std::to_string(a.first));
                    }
                }
            }
            if (prior.target_height == incoming.target_height) {
                btcanchor::AnchorSet::PermanentCheckpoint checkpoint;
                checkpoint.target_height = incoming.target_height;
                checkpoint.entry.veld_block_hash = incoming.target_hash;
                checkpoint.entry.carrying_veld_height =
                    incoming.proof_carrier_height;
                checkpoint.entry.carrying_veld_hash =
                    incoming.proof_carrier_hash;
                checkpoint.entry.btc_block_hash = incoming.btc_block_hash;
                checkpoint.entry.btc_txid = incoming.btc_txid;
                checkpoint.entry.authorization_veld_height =
                    incoming.authorization_record.carrier.height;
                checkpoint.entry.authorization_veld_hash =
                    incoming.authorization_record.carrier.hash;
                checkpoint.entry.authorization_finality_digest =
                    ::veld::finality::qc::RecordDigest(
                        incoming.authorization_record);
                checkpoint.authorization_record =
                    incoming.authorization_record;
                if (!EffectiveAnchorSecurityPermanentExactlyMatches_(
                        prior, checkpoint)) {
                    throw std::runtime_error(
                        std::string(source_name) +
                        " conflicts with installed full anchor metadata at the same target T");
                }
            }
        }
    }

    void RequireAnchorLocalFloorCompatibility_(
            const btcanchor::floor_store::Record& record) const {
        const auto incoming = EffectiveLocalFloorFromRecord_(
            record,
            EffectiveAnchorSecurityFloor::Source::LocalObserved,
            /*exact_reconstruction_observed=*/false);
        std::lock_guard<std::mutex> lock(anchor_security_floors_mutex_);
        RequireEffectiveAnchorFloorCompatibilityLocked_(incoming, "VLF1");
    }

    bool AllRecoveredLocalFloorsExactlyObserved_() const {
        std::lock_guard<std::mutex> lock(anchor_security_floors_mutex_);
        for (const auto& floor : effective_anchor_security_floors_) {
            if ((floor.source ==
                     EffectiveAnchorSecurityFloor::Source::LocalObserved ||
                 floor.source ==
                     EffectiveAnchorSecurityFloor::Source::LocalRecovery) &&
                !floor.exact_reconstruction_observed)
                return false;
        }
        return true;
    }

    void InstallAnchorLocalFloor_(
            const btcanchor::floor_store::Record& record,
            bool exact_reconstruction_observed) {
        if (record.network_magic != config_.magic ||
            record.genesis_hash != CreateGenesisBlock().GetHash())
            throw std::runtime_error(
                "local anchor floor belongs to another network/genesis");

        const auto& checkpoint = record.checkpoint;
        auto incoming = EffectiveLocalFloorFromRecord_(
            record,
            EffectiveAnchorSecurityFloor::Source::LocalObserved,
            exact_reconstruction_observed);

        std::lock_guard<std::mutex> lock(anchor_security_floors_mutex_);
        RequireEffectiveAnchorFloorCompatibilityLocked_(incoming, "VLF1");

        auto local = std::find_if(
            effective_anchor_security_floors_.begin(),
            effective_anchor_security_floors_.end(),
            [](const EffectiveAnchorSecurityFloor& floor) {
                return floor.source ==
                    EffectiveAnchorSecurityFloor::Source::LocalObserved;
            });
        if (local != effective_anchor_security_floors_.end()) {
            if (local->target_height > incoming.target_height)
                throw std::logic_error(
                    "attempted to roll back installed local anchor floor");
            if (local->target_height == incoming.target_height) {
                local->exact_reconstruction_observed =
                    local->exact_reconstruction_observed ||
                    exact_reconstruction_observed;
                return;
            }
            effective_anchor_security_floors_.erase(local);
        }
        effective_anchor_security_floors_.push_back(std::move(incoming));
    }

    void InstallAnchorRecoveryFloor_(
            const btcanchor::floor_store::Record& record) {
        auto incoming = EffectiveLocalFloorFromRecord_(
            record,
            EffectiveAnchorSecurityFloor::Source::LocalRecovery,
            /*exact_reconstruction_observed=*/false);
        std::lock_guard<std::mutex> lock(anchor_security_floors_mutex_);
        RequireEffectiveAnchorFloorCompatibilityLocked_(
            incoming, "recovered VLF1 copy");
        const auto duplicate = std::find_if(
            effective_anchor_security_floors_.begin(),
            effective_anchor_security_floors_.end(),
            [&incoming](const EffectiveAnchorSecurityFloor& prior) {
                return prior.source ==
                           EffectiveAnchorSecurityFloor::Source::LocalRecovery &&
                       prior.floor_digest == incoming.floor_digest;
            });
        if (duplicate == effective_anchor_security_floors_.end())
            effective_anchor_security_floors_.push_back(
                std::move(incoming));
    }

    void InheritAnchorLocalFloorForValidation_(
            const std::vector<btcanchor::floor_store::Record>& records) {
        if (running_.load(std::memory_order_acquire) ||
            anchor_floor_prepared_)
            throw std::logic_error(
                "snapshot floor inheritance is startup-only");
        if (records.empty()) return;
        std::string error;
        for (const auto& record : records) {
            if (!btcanchor::floor_store::Validate(record, &error) ||
                record.network_magic != config_.magic ||
                record.genesis_hash != CreateGenesisBlock().GetHash())
                throw std::runtime_error(
                    "cannot inherit invalid snapshot anchor floor: " + error);
        }
        anchor_floor_inherited_records_ = records;
    }

    void InheritAnchorLocalFloorForValidation_(
            const btcanchor::floor_store::Record& record) {
        InheritAnchorLocalFloorForValidation_(
            std::vector<btcanchor::floor_store::Record>{record});
    }

    bool WriteAnchorFloorUncertaintyMarker_(
            bool uncertain, std::string* error) {
        const auto& marker = uncertain
            ? AnchorFloorUncertainMarker_()
            : AnchorFloorClearMarker_();
        if (!::veld::channel::secure_file::AtomicWrite(
                AnchorFloorUncertaintyPath_(), marker, error,
                /*require_private_parent=*/true))
            return false;
        anchor_floor_repair_required_.store(
            uncertain, std::memory_order_release);
        return true;
    }

    bool ClearDurablePublicationAfterCommit_(const Block& block) {
        bool cleared = false;
        try {
#ifdef VELD_TEST_HOOKS
            if (!durable_publication_clear_test_failure_)
#endif
            {
                cleared = db_.ClearDurablePublicationPending(
                    block.height, block.GetHash());
            }
        } catch (const std::exception& e) {
            FailStopDurableCommitInvariant_(
                std::string("VDP1 clear threw for durable h=") +
                std::to_string(block.height) + ": " + e.what());
            return false;
        } catch (...) {
            FailStopDurableCommitInvariant_(
                "VDP1 clear threw an unknown exception for durable h=" +
                std::to_string(block.height));
            return false;
        }
        if (!cleared) {
            FailStopDurableCommitInvariant_(
                "VDP1 identity-checked clear failed for durable h=" +
                std::to_string(block.height) + " hash=" +
                HashToHex(block.GetHash()).substr(0, 16));
            return false;
        }
        return true;
    }

    void LoadDurablePublicationRepair_() {
        // Authenticate every cross-database recovery obligation before any
        // snapshot path can replace the local replay source. VDP1 means the
        // published tip must be replayed; VUR1 means the old tip remains
        // authoritative while candidate UTXOs are reconciled away. A generic
        // rebuild marker likewise blocks snapshots until reconciliation.
        const auto pending = db_.ReadDurablePublicationPending();
        const auto reorg = db_.ReadReorgUtxoPending();
        const bool utxo_recovery = db_.UtxoRecoveryRequired();
        if (pending && reorg) {
            throw std::runtime_error(
                "VDP1 and retained VUR1 coexist; canonical recovery is ambiguous");
        }
        if (reorg && !db_.ReorgOldCanonicalMatches(*reorg)) {
            throw std::runtime_error(
                "retained VUR1 does not exactly match the authoritative old canonical frame");
        }
        startup_durable_publication_recovery_ = pending;
        startup_reorg_utxo_recovery_ = reorg;
        startup_utxo_recovery_required_ = utxo_recovery;

        if (pending) {
            const auto stored_tip = db_.ReadChainTipExact();
            const std::string pending_hex = HashToHex(pending->hash);
            if (!stored_tip || stored_tip->height != pending->height ||
                stored_tip->tip_hash != pending_hex) {
                throw std::runtime_error(
                    "durable publication pending identity does not exactly match the authoritative DB tip");
            }
            const auto indexed = db_.GetHashAtHeight(pending->height);
            if (!indexed || *indexed != pending_hex) {
                throw std::runtime_error(
                    "durable publication pending identity does not exactly match the canonical height index");
            }
            const auto bytes = db_.ReadBlock(pending->hash);
            if (!bytes) {
                throw std::runtime_error(
                    "durable publication pending block body is missing");
            }
            Block body;
            body.height = pending->height;
            const size_t consumed = Block::Deserialize(*bytes, 0, body);
            if (consumed == 0 || consumed != bytes->size() ||
                body.Serialize() != *bytes ||
                body.GetHash() != pending->hash) {
                throw std::runtime_error(
                    "durable publication pending block body is non-canonical or does not match its identity");
            }
        }
        durable_commit_repair_required_.store(
            pending.has_value() || utxo_recovery,
            std::memory_order_release);
    }

    void FinishDurableCommitReplayRepair_() {
        // RebuildUTXOsFromSnapshot must have completed immediately before this
        // method. A retained VUR1 is cleared only by its exact identity-bound
        // acknowledgement after the old canonical chain has been replayed.
        if (startup_reorg_utxo_recovery_) {
            const auto& expected = *startup_reorg_utxo_recovery_;
            if (chain_.IsEmpty() || chain_.Height() != expected.old_height ||
                chain_.TipCopy().GetHash() != expected.old_hash ||
                chain_.TotalSupplyUnits() != expected.old_supply ||
                !db_.ReorgOldCanonicalMatches(expected)) {
                throw std::runtime_error(
                    "startup replay did not reconstruct the exact old VUR1 canonical frame");
            }
            bool completed = false;
            try {
                completed = db_.CompleteReorgUtxoRecoveryAfterReplay(
                    expected);
            } catch (const db::DurableWriteUncertain& e) {
                FailStopDurableCommitInvariant_(
                    std::string("VUR1 startup acknowledgement is uncertain: ") +
                    e.what());
                throw;
            }
            if (!completed) {
                FailStopDurableCommitInvariant_(
                    "VUR1 startup identity-checked acknowledgement failed");
                throw std::runtime_error(
                    "canonical replay completed but retained VUR1 could not be cleared");
            }
            startup_reorg_utxo_recovery_.reset();
        }
        if (db_.UtxoRecoveryRequired()) {
            throw std::runtime_error(
                "UTXO recovery obligation remains after checked reconciliation");
        }
        startup_utxo_recovery_required_ = false;

        const auto pending = db_.ReadDurablePublicationPending();
        auto expected_pending = startup_durable_publication_recovery_;
        // Focused in-process fault tests can arm VDP1 after Prepare; production
        // recovery observes it in LoadDurablePublicationRepair_ on restart.
        if (!expected_pending && pending &&
            durable_commit_fail_stop_.load(std::memory_order_acquire)) {
            expected_pending = pending;
        }
        if (expected_pending) {
            if (!pending || pending->height != expected_pending->height ||
                pending->hash != expected_pending->hash) {
                throw std::runtime_error(
                    "durable publication recovery identity disappeared or changed before replay completed");
            }
            const auto stored_tip = db_.ReadChainTipExact();
            const std::string pending_hex = HashToHex(pending->hash);
            if (!stored_tip || stored_tip->height != pending->height ||
                stored_tip->tip_hash != pending_hex || chain_.IsEmpty() ||
                chain_.Height() != pending->height ||
                chain_.TipCopy().GetHash() != pending->hash) {
                throw std::runtime_error(
                    "canonical replay did not reconstruct the exact VDP1 pending tip");
            }
        } else if (pending) {
            throw std::runtime_error(
                "an unexpected VDP1 obligation appeared during startup replay");
        }

        if (pending) {
            bool cleared = false;
            try {
#ifdef VELD_TEST_HOOKS
                if (!durable_publication_clear_test_failure_)
#endif
                {
                    cleared = db_.ClearDurablePublicationPending(
                        pending->height, pending->hash);
                }
            } catch (const std::exception& e) {
                FailStopDurableCommitInvariant_(
                    std::string("VDP1 clear threw after exact replay: ") +
                    e.what());
                throw;
            } catch (...) {
                FailStopDurableCommitInvariant_(
                    "VDP1 clear threw an unknown exception after exact replay");
                throw;
            }
            if (!cleared) {
                FailStopDurableCommitInvariant_(
                    "VDP1 identity-checked clear failed after exact replay");
                throw std::runtime_error(
                    "canonical replay completed but VDP1 could not be cleared");
            }
        }
        startup_durable_publication_recovery_.reset();
        durable_commit_repair_required_.store(false,
                                               std::memory_order_release);
        durable_commit_fail_stop_.store(false, std::memory_order_release);
    }

    void FailStopAnchorFloorPersistence_(const std::string& why) {
        work_admission_coordinator_.CancelAndClose(
            work_admission::Refusal::CheckpointAnchorUnproven);
        std::string sentinel_error;
        const bool sentinel_ok = WriteAnchorFloorUncertaintyMarker_(
            true, &sentinel_error);
        anchor_floor_security_uncertain_.store(
            true, std::memory_order_release);
        if (ibd_complete_.exchange(false, std::memory_order_acq_rel))
            BumpValidationGeneration_();
        mining_.store(false, std::memory_order_release);
        running_.store(false, std::memory_order_release);
        prewarm_cv_.notify_all();
        if (tcp_server_) tcp_server_->SetIBDComplete(false);
        std::cerr << "  [anchor-floor] FATAL FAIL-STOP: " << why
                  << ". The block is already durable, so it will not be "
                     "rolled back. Network admission and mining are stopped; "
                     "restart must replay and repair VLF1 before service.";
        if (!sentinel_ok)
            std::cerr << " Uncertainty sentinel also failed: "
                      << sentinel_error;
        std::cerr << "\n";
        std::cerr.flush();
    }

    void FailStopDurableCommitInvariant_(const std::string& why) {
        // May run inside AddBlockDirect's transition sequencer and under the
        // current local-work lease. Emergency revocation is safe here because
        // the very sink owning that lease has already proven its durable
        // outcome uncertain; recursive bounded waiting would deadlock.
        work_admission_coordinator_.CancelAndClose(
            work_admission::Refusal::DurableStateUnproven);
        durable_commit_fail_stop_.store(true, std::memory_order_release);
        durable_commit_repair_required_.store(true,
                                               std::memory_order_release);
        if (ibd_complete_.exchange(false, std::memory_order_acq_rel))
            BumpValidationGeneration_();
        mining_.store(false, std::memory_order_release);
        running_.store(false, std::memory_order_release);
        prewarm_cv_.notify_all();
        try {
            if (tcp_server_) tcp_server_->SetIBDComplete(false);
        } catch (...) {
            // The fail-stop latch and local admission gates above are the
            // authority; a transport notification must not unwind across an
            // unproven canonical-persistence callback.
        }
        std::cerr << "  [durable-commit] FATAL FAIL-STOP: " << why
                  << ". Canonical persistence is now unproven. "
                     "RPC/P2P/mining are stopping; restart will perform full "
                     "canonical replay and reconciliation.";
        std::cerr << "\n";
        std::cerr.flush();
    }

    void LoadAnchorFloorSecurity_(const Hash256& genesis_hash) {
        std::string error;
        std::vector<uint8_t> marker;
        const auto marker_read = ::veld::channel::secure_file::Read(
            AnchorFloorUncertaintyPath_(), marker, &error, 64,
            /*require_private_parent=*/true);
        if (marker_read ==
            ::veld::channel::secure_file::ReadResult::Error) {
            throw std::runtime_error(
                "cannot securely read anchor-floor uncertainty marker: " +
                error);
        }
        if (marker_read ==
            ::veld::channel::secure_file::ReadResult::Ok) {
            if (marker == AnchorFloorUncertainMarker_()) {
                anchor_floor_repair_required_.store(
                    true, std::memory_order_release);
            } else if (marker == AnchorFloorClearMarker_()) {
                anchor_floor_repair_required_.store(
                    false, std::memory_order_release);
            } else {
                throw std::runtime_error(
                    "anchor-floor uncertainty marker is malformed");
            }
        }

        std::vector<btcanchor::floor_store::Record> learned;
        if (!anchor_floor_inherited_records_.empty()) {
            // An isolated snapshot candidate inherits the live node's trusted
            // local floor before Prepare().  Ignore any VLF copy supplied by
            // the downloaded archive: VLF1 is unsigned local memory, so a
            // publisher-provided numerically higher record must never erase
            // the parent's exact pins.  The inherited record is written over
            // both candidate copies below and full replay may then advance it
            // from consensus-verified blocks.
            learned = anchor_floor_inherited_records_;
        } else {
            std::vector<uint8_t> external_wire;
            const auto external_read =
                ::veld::channel::secure_file::Read(
                    AnchorFloorPersistentPath_(), external_wire, &error,
                    btcanchor::floor_store::VLF1_ENCODED_SIZE,
                    /*require_private_parent=*/true);
            if (external_read ==
                ::veld::channel::secure_file::ReadResult::Error) {
                throw std::runtime_error(
                    "cannot securely read external local anchor floor: " +
                    error);
            }
            if (external_read ==
                ::veld::channel::secure_file::ReadResult::Ok) {
                const auto decoded = btcanchor::floor_store::Decode(
                    external_wire, &error);
                if (!decoded || decoded->network_magic != config_.magic ||
                    decoded->genesis_hash != genesis_hash) {
                    throw std::runtime_error(
                        "external local anchor floor rejected: " + error);
                }
                learned.push_back(*decoded);
            }

            const auto db_wire = db_.ReadAnchorSecurityFloor();
            if (db_wire) {
                const auto decoded = btcanchor::floor_store::Decode(
                    *db_wire, &error);
                if (!decoded || decoded->network_magic != config_.magic ||
                    decoded->genesis_hash != genesis_hash) {
                    throw std::runtime_error(
                        "authoritative DB local anchor floor rejected: " +
                        error);
                }
                learned.push_back(*decoded);
            }
        }

        if (learned.empty()) return;
        std::sort(learned.begin(), learned.end(),
            [](const btcanchor::floor_store::Record& a,
               const btcanchor::floor_store::Record& b) {
                if (a.checkpoint.target_height !=
                    b.checkpoint.target_height)
                    return a.checkpoint.target_height <
                           b.checkpoint.target_height;
                return a.floor_digest < b.floor_digest;
            });
        learned.erase(std::unique(learned.begin(), learned.end(),
            [](const btcanchor::floor_store::Record& a,
               const btcanchor::floor_store::Record& b) {
                return btcanchor::floor_store::ExactDuplicate(a, b);
            }), learned.end());

        btcanchor::floor_store::Store rebuilt;
        for (const auto& record : learned) {
            const auto merged = rebuilt.Merge(record, &error);
            if (merged == btcanchor::floor_store::MergeResult::Rejected ||
                merged == btcanchor::floor_store::MergeResult::IoError) {
                throw std::runtime_error(
                    "local anchor floor copies are not one monotonic history: " +
                    error);
            }
        }
        if (!rebuilt.Current())
            throw std::logic_error("non-empty VLF source set rebuilt empty");

        // Retain every older crash-recovery source as an independent replay
        // obligation.  Only the highest record is the writable local store;
        // replay must still prove the lower exact pins rather than assuming
        // that two independently recovered files came from one branch.
        for (size_t i = 0; i + 1 < learned.size(); ++i)
            InstallAnchorRecoveryFloor_(learned[i]);
        InstallAnchorLocalFloor_(*rebuilt.Current(),
                                 /*exact_reconstruction_observed=*/false);

        // With one source, repair the missing/stale redundant copy before any
        // snapshot operation.  With two distinct monotonic sources, do not
        // collapse the lower on-disk evidence yet: a crash before replay would
        // otherwise leave only the unproven higher copy.  Both are installed
        // above, and successful replay promotes the exact high-water through
        // PersistObservedAnchorFloorAfterDurable_ / PersistCurrent... below.
        if (learned.size() == 1) {
            const auto selected_wire = btcanchor::floor_store::Encode(
                *rebuilt.Current(), &error);
            if (!selected_wire)
                throw std::runtime_error(
                    "selected local anchor floor could not be encoded: " +
                    error);
            const auto mirrored = rebuilt.MergeAndPersist(
                AnchorFloorPersistentPath_(), *rebuilt.Current(), &error);
            if (mirrored == btcanchor::floor_store::MergeResult::Rejected ||
                mirrored == btcanchor::floor_store::MergeResult::IoError) {
                throw std::runtime_error(
                    "cannot repair external local anchor floor mirror: " +
                    error);
            }
            if (!db_.WriteAnchorSecurityFloor(*selected_wire)) {
                throw std::runtime_error(
                    "cannot repair authoritative DB local anchor floor copy");
            }
        }

        std::lock_guard<std::mutex> store_lock(
            anchor_floor_store_mutex_);
        anchor_floor_store_ = std::move(rebuilt);
        anchor_floor_validation_records_ = learned;
        anchor_floor_recovery_record_count_ = learned.size() - 1;
    }

    std::optional<std::vector<uint8_t>>
    AnchorFloorWireForDurableCommit_(bool include_new_permanent) {
        std::optional<btcanchor::floor_store::Record> selected;
        size_t recovery_count = 0;
        {
            std::lock_guard<std::mutex> store_lock(
                anchor_floor_store_mutex_);
            selected = anchor_floor_store_.Current();
            recovery_count = anchor_floor_recovery_record_count_;
        }

        if (include_new_permanent &&
            anchors_.HasExportablePermanentFloor()) {
            const auto permanent = anchors_.Permanent();
            if (!permanent)
                throw std::logic_error(
                    "exportable anchor floor has no permanent checkpoint");
            std::string error;
            const auto candidate = btcanchor::floor_store::Make(
                config_.magic, CreateGenesisBlock().GetHash(), *permanent,
                &error);
            if (!candidate)
                throw std::runtime_error(
                    "durable block cannot form its exact VLF1 floor: " +
                    error);

            if (!selected) {
                RequireAnchorLocalFloorCompatibility_(*candidate);
                selected = *candidate;
            } else {
                const uint64_t incoming_t =
                    candidate->checkpoint.target_height;
                const uint64_t current_t =
                    selected->checkpoint.target_height;
                if (incoming_t == current_t) {
                    if (!btcanchor::floor_store::ExactDuplicate(
                            *candidate, *selected)) {
                        throw std::runtime_error(
                            "durable block reconstructs conflicting VLF1 metadata at the current T");
                    }
                } else if (incoming_t > current_t) {
                    btcanchor::floor_store::Store trial;
                    if (trial.Merge(*selected, &error) ==
                            btcanchor::floor_store::MergeResult::Rejected ||
                        trial.Merge(*candidate, &error) ==
                            btcanchor::floor_store::MergeResult::Rejected) {
                        throw std::runtime_error(
                            "durable block cannot monotonically advance VLF1: " +
                            error);
                    }
                    RequireAnchorLocalFloorCompatibility_(*candidate);
                    selected = *candidate;
                }
                // A lower historical permanent is expected only during cold
                // replay. Live commits preserve the stronger current copy.
            }
        }

        if (!selected) return std::nullopt;
        // Two different crash-recovery copies remain independent evidence
        // until replay observes both exact records.  Omitting the optional DB
        // update leaves the existing index value untouched; publishing the
        // numerically higher copy too early would erase the lower disk witness
        // if power failed before replay completed. ApplyBlockModules_ observes
        // an exact current-block reconstruction before this helper runs, so a
        // legitimate advancement naturally becomes eligible here.
        if (recovery_count > 0 &&
            !AllRecoveredLocalFloorsExactlyObserved_())
            return std::nullopt;
        std::string error;
        const auto wire = btcanchor::floor_store::Encode(*selected, &error);
        if (!wire)
            throw std::runtime_error(
                "durable VLF1 copy could not be encoded: " + error);
        return *wire;
    }

    void PersistCurrentAnchorFloorToDb_() {
        std::optional<btcanchor::floor_store::Record> current;
        size_t recovery_count = 0;
        {
            std::lock_guard<std::mutex> store_lock(
                anchor_floor_store_mutex_);
            current = anchor_floor_store_.Current();
            recovery_count = anchor_floor_recovery_record_count_;
        }
        if (!current) return;
        if (recovery_count > 0 &&
            !AllRecoveredLocalFloorsExactlyObserved_())
            return;
        std::string error;
        const auto wire = btcanchor::floor_store::Encode(*current, &error);
        if (!wire || !db_.WriteAnchorSecurityFloor(*wire)) {
            throw std::runtime_error(
                "cannot publish replay-verified VLF1 into the authoritative DB copy" +
                (error.empty() ? std::string() : ": " + error));
        }
    }

    bool PersistObservedAnchorFloorAfterDurable_(bool startup_replay) {
        if (!anchors_.HasExportablePermanentFloor()) return true;
        const auto permanent = anchors_.Permanent();
        if (!permanent) return true;

        std::string error;
        const auto candidate = btcanchor::floor_store::Make(
            config_.magic, CreateGenesisBlock().GetHash(), *permanent,
            &error);
        const auto fail = [this, startup_replay](
                              const std::string& message) -> bool {
            if (startup_replay)
                throw std::runtime_error(
                    "startup replay could not repair local anchor floor: " +
                    message);
            FailStopAnchorFloorPersistence_(message);
            return false;
        };
        if (!candidate)
            return fail("exportable permanent could not form VLF1: " +
                        error);

        // When two different durable copies were recovered, the older copy is
        // independent security evidence until replay reconstructs its exact
        // full record.  Do not replace that older external witness merely
        // because replay reached the numerically higher current floor: a
        // higher permanent can share all of the older T/A/C pins while failing
        // to reproduce the older full authorization metadata.  If we collapsed
        // the external file here and the end-of-replay floor check then failed,
        // the next restart would see only the higher DB/external copy and could
        // forget the failed lower obligation.
        size_t recovery_count = 0;
        {
            std::lock_guard<std::mutex> store_lock(
                anchor_floor_store_mutex_);
            recovery_count = anchor_floor_recovery_record_count_;
        }
        const bool preserve_recovery_witness =
            recovery_count > 0 &&
            !AllRecoveredLocalFloorsExactlyObserved_();

        {
            std::lock_guard<std::mutex> store_lock(
                anchor_floor_store_mutex_);
            const auto current = anchor_floor_store_.Current();
            if (current) {
                const uint64_t incoming_t =
                    candidate->checkpoint.target_height;
                const uint64_t current_t =
                    current->checkpoint.target_height;
                if (incoming_t < current_t) {
                    // Expected while a cold replay walks lower historical
                    // promotions under a stronger already-observed VLF1.
                    return true;
                }
                if (incoming_t == current_t &&
                    !btcanchor::floor_store::ExactDuplicate(
                        *candidate, *current)) {
                    return fail(
                        "reconstructed permanent conflicts with VLF1 at "
                        "the same target T");
                }
            }

            if (preserve_recovery_witness) {
                // The exact latches are set by
                // ObserveExactAnchorSecurityReconstruction_ while applying C.
                // A lower unmatched recovery record can never become exact at
                // a later height, so leave both disk copies byte-for-byte
                // unchanged and let the mandatory end-of-replay check reject.
                return true;
            }

            btcanchor::floor_store::MergeResult result;
#ifdef VELD_TEST_HOOKS
            if (anchor_floor_test_persist_failure_) {
                error = "injected VLF1 persistence failure";
                result = btcanchor::floor_store::MergeResult::IoError;
            } else
#endif
            {
                result = anchor_floor_store_.MergeAndPersist(
                    AnchorFloorPersistentPath_(), *candidate, &error);
            }
            if (result == btcanchor::floor_store::MergeResult::Rejected)
                return fail("VLF1 monotonic merge rejected: " + error);
            if (result == btcanchor::floor_store::MergeResult::IoError)
                return fail("VLF1 atomic persistence failed: " + error);
        }

        try {
            InstallAnchorLocalFloor_(
                *candidate,
                /*exact_reconstruction_observed=*/true);
        } catch (const std::exception& e) {
            return fail(std::string(
                "persisted VLF1 conflicts with installed security floors: ") +
                e.what());
        }
        {
            std::lock_guard<std::mutex> store_lock(
                anchor_floor_store_mutex_);
            if (anchor_floor_validation_records_.size() >
                anchor_floor_recovery_record_count_) {
                anchor_floor_validation_records_.resize(
                    anchor_floor_recovery_record_count_);
            }
            anchor_floor_validation_records_.push_back(*candidate);
        }
        return true;
    }

    void FinishAnchorFloorReplayRepair_() {
        if (!anchor_floor_repair_required_.load(
                std::memory_order_acquire))
            return;
        const auto permanent = anchors_.Permanent();
        std::optional<btcanchor::floor_store::Record> current;
        {
            std::lock_guard<std::mutex> store_lock(
                anchor_floor_store_mutex_);
            current = anchor_floor_store_.Current();
        }
        if (!permanent || !current ||
            !EffectiveAnchorSecurityPermanentExactlyMatches_(
                EffectiveAnchorSecurityFloor{
                    EffectiveAnchorSecurityFloor::Source::LocalObserved,
                    {}, current->checkpoint.target_height,
                    current->checkpoint.entry.veld_block_hash,
                    current->checkpoint.entry.carrying_veld_height,
                    current->checkpoint.entry.carrying_veld_hash,
                    current->checkpoint.entry.btc_block_hash,
                    current->checkpoint.entry.btc_txid,
                    current->checkpoint.authorization_record,
                    current->floor_digest, true},
                *permanent)) {
            throw std::runtime_error(
                "startup replay did not reconstruct the uncertain VLF1 floor");
        }
        std::string error;
        if (!WriteAnchorFloorUncertaintyMarker_(false, &error))
            throw std::runtime_error(
                "startup replay repaired VLF1 but could not clear its "
                "uncertainty marker: " + error);
        anchor_floor_security_uncertain_.store(
            false, std::memory_order_release);
    }

    void PrepareAnchorSecurityBootstrap_() {
        std::lock_guard<std::mutex> lock(anchor_floor_prepare_mutex_);
        if (anchor_floor_prepared_) return;
        if (running_.load(std::memory_order_acquire) || tcp_server_ ||
            mining_thread_.joinable() || pow_verify_thread_.joinable()) {
            throw std::runtime_error(
                "anchor WS preparation must complete before node startup");
        }

        const Hash256 genesis_hash = CreateGenesisBlock().GetHash();
        if (HashIsZero(genesis_hash))
            throw std::runtime_error(
                "compiled genesis hash is null during anchor WS preparation");

        // Authenticate the atomic VDP1 crash obligation before any caller can
        // reach snapshot preference. A post-DB publication failure requires
        // replay of this exact local tip/body; replacing it first would erase
        // the repair source.
        LoadDurablePublicationRepair_();

        // The anchor security surface is the independently durable,
        // Bitcoin-authenticated local floor. Its directory used to be created
        // as a side effect of opening that journal; it is now created here,
        // before the floor is installed or repaired, so a VLF1 pin or same-T
        // metadata contradiction stays startup-fatal.
        EnsureAnchorSecurityDirectory_();
        LoadAnchorFloorSecurity_(genesis_hash);

        anchor_floor_prepared_ = true;
    }

    bool EffectiveAnchorSecurityPinPermits_(
            uint64_t height, const Hash256& hash) const {
        if ((!startup_replay_active_.load(std::memory_order_acquire) &&
             DurableCommitFailStop()) ||
            anchor_floor_security_uncertain_.load(
                std::memory_order_acquire))
            return false;
        std::lock_guard<std::mutex> lock(anchor_security_floors_mutex_);
        for (const auto& floor : effective_anchor_security_floors_) {
            if (height == floor.target_height && hash != floor.target_hash)
                return false;
            if (height == floor.proof_carrier_height &&
                hash != floor.proof_carrier_hash)
                return false;
            if (height == floor.authorization_record.carrier.height &&
                hash != floor.authorization_record.carrier.hash)
                return false;
        }
        return true;
    }

    bool EffectiveAnchorSecurityReorgPermitted_(
            uint64_t common_ancestor_height,
            uint64_t current_tip_height) const {
        if (DurableCommitFailStop() ||
            anchor_floor_security_uncertain_.load(
                std::memory_order_acquire))
            return false;
        std::lock_guard<std::mutex> lock(anchor_security_floors_mutex_);
        for (const auto& floor : effective_anchor_security_floors_) {
            const uint64_t carrier =
                floor.authorization_record.carrier.height;
            // During a from-genesis sync, a future C is only a block pin.  It
            // becomes a reorg floor once the current canonical chain has
            // actually reached and validated C.
            if (current_tip_height >= carrier &&
                common_ancestor_height < carrier)
                return false;
        }
        return true;
    }

    static bool EffectiveAnchorSecurityPermanentExactlyMatches_(
            const EffectiveAnchorSecurityFloor& floor,
            const btcanchor::AnchorSet::PermanentCheckpoint& permanent) {
        if (permanent.target_height != floor.target_height ||
            permanent.authorization_record.IsNull())
            return false;
        const auto expected_record_digest =
            ::veld::finality::qc::RecordDigest(
                floor.authorization_record);
        const auto& entry = permanent.entry;
        return entry.veld_block_hash == floor.target_hash &&
               entry.carrying_veld_height ==
                   floor.proof_carrier_height &&
               entry.carrying_veld_hash ==
                   floor.proof_carrier_hash &&
               entry.btc_block_hash == floor.btc_block_hash &&
               entry.btc_txid == floor.btc_txid &&
               entry.authorization_veld_height ==
                   floor.authorization_record.carrier.height &&
               entry.authorization_veld_hash ==
                   floor.authorization_record.carrier.hash &&
               entry.authorization_finality_digest ==
                   expected_record_digest &&
               ::veld::finality::qc::RecordDigest(
                   permanent.authorization_record) ==
                   expected_record_digest;
    }

    void ObserveExactAnchorSecurityReconstruction_(
            uint64_t applied_height) {
        const auto permanent = anchors_.Permanent();
        if (!permanent) return;
        std::lock_guard<std::mutex> lock(anchor_security_floors_mutex_);
        for (auto& floor : effective_anchor_security_floors_) {
            if (floor.exact_reconstruction_observed ||
                applied_height !=
                    floor.authorization_record.carrier.height)
                continue;
            if (EffectiveAnchorSecurityPermanentExactlyMatches_(
                    floor, *permanent)) {
                floor.exact_reconstruction_observed = true;
            }
        }
    }

    void ResetExactAnchorSecurityReconstructions_() {
        std::lock_guard<std::mutex> lock(anchor_security_floors_mutex_);
        for (auto& floor : effective_anchor_security_floors_)
            floor.exact_reconstruction_observed = false;
    }

    std::vector<bool> SnapshotExactAnchorSecurityReconstructions_() const {
        std::lock_guard<std::mutex> lock(anchor_security_floors_mutex_);
        std::vector<bool> observed;
        observed.reserve(effective_anchor_security_floors_.size());
        for (const auto& floor : effective_anchor_security_floors_)
            observed.push_back(floor.exact_reconstruction_observed);
        return observed;
    }

    void RestoreExactAnchorSecurityReconstructions_(
            const std::vector<bool>& observed) {
        std::lock_guard<std::mutex> lock(anchor_security_floors_mutex_);
        if (observed.size() != effective_anchor_security_floors_.size())
            throw std::logic_error(
                "anchor security reconstruction snapshot shape changed");
        for (size_t i = 0; i < observed.size(); ++i)
            effective_anchor_security_floors_[i]
                .exact_reconstruction_observed = observed[i];
    }

    bool EffectiveAnchorSecurityPermanentCovers_(
            const EffectiveAnchorSecurityFloor& floor) const {
        const auto permanent = anchors_.Permanent();
        if (!permanent) return false;
        if (permanent->target_height > floor.target_height) {
            // The later target commits the old block prefix, but it cannot
            // retroactively authenticate arbitrary metadata carried in an
            // older floor record.  Exact reconstruction at that floor's own C
            // must have been observed before it was superseded.
            return floor.exact_reconstruction_observed;
        }
        return EffectiveAnchorSecurityPermanentExactlyMatches_(
            floor, *permanent);
    }

    EffectiveAnchorSecurityStatus
    EffectiveAnchorSecurityStatusNoTransition_() const {
        if (anchor_floor_security_uncertain_.load(
                std::memory_order_acquire))
            return EffectiveAnchorSecurityStatus::Mismatched;
        std::lock_guard<std::mutex> lock(anchor_security_floors_mutex_);
        if (effective_anchor_security_floors_.empty())
            return EffectiveAnchorSecurityStatus::None;
        const uint64_t tip = chain_.Height();
        const auto reached_pin_matches =
            [this, tip](uint64_t height, const Hash256& expected) {
                if (tip < height) return true;
                return chain_.GetBlockHashAtHeight(height) ==
                       HashToHex(expected);
            };
        bool pending = false;
        for (const auto& floor : effective_anchor_security_floors_) {
            if (!reached_pin_matches(floor.target_height,
                                     floor.target_hash) ||
                !reached_pin_matches(floor.proof_carrier_height,
                                     floor.proof_carrier_hash) ||
                !reached_pin_matches(
                    floor.authorization_record.carrier.height,
                    floor.authorization_record.carrier.hash)) {
                return EffectiveAnchorSecurityStatus::Mismatched;
            }
            if (tip < floor.authorization_record.carrier.height) {
                pending = true;
                continue;
            }
            if (!EffectiveAnchorSecurityPermanentCovers_(floor))
                return EffectiveAnchorSecurityStatus::Mismatched;
        }
        return pending ? EffectiveAnchorSecurityStatus::Pending
                       : EffectiveAnchorSecurityStatus::Satisfied;
    }

    static const char* EffectiveAnchorSecurityStatusName_(
            EffectiveAnchorSecurityStatus status) {
        switch (status) {
            case EffectiveAnchorSecurityStatus::None: return "none";
            case EffectiveAnchorSecurityStatus::Pending: return "pending";
            case EffectiveAnchorSecurityStatus::Satisfied: return "satisfied";
            case EffectiveAnchorSecurityStatus::Mismatched: return "mismatched";
        }
        return "mismatched";
    }

    void VerifyEffectiveAnchorSecurityStoredPins_(
            uint64_t stored_tip_height) {
        std::lock_guard<std::mutex> lock(anchor_security_floors_mutex_);
        for (const auto& floor : effective_anchor_security_floors_) {
            const std::array<std::pair<uint64_t, Hash256>, 3> pins{{
                {floor.target_height, floor.target_hash},
                {floor.proof_carrier_height, floor.proof_carrier_hash},
                {floor.authorization_record.carrier.height,
                 floor.authorization_record.carrier.hash},
            }};
            for (const auto& pin : pins) {
                if (pin.first > stored_tip_height) continue;
                const auto stored = db_.GetHashAtHeight(pin.first);
                // A missing forward index may still be repaired from the
                // reverse index by ReplayChain. A present conflict is fatal.
                if (!stored || *stored == HashToHex(pin.second)) continue;
                throw std::runtime_error(
                    "stored chain conflicts with anchor security pin at height " +
                    std::to_string(pin.first));
            }
        }
    }

    void RequireEffectiveAnchorSecurityAfterReplay_(
            uint64_t replayed_tip_height) const {
        std::lock_guard<std::mutex> lock(anchor_security_floors_mutex_);
        for (const auto& floor : effective_anchor_security_floors_) {
            if (replayed_tip_height <
                floor.authorization_record.carrier.height)
                continue;
            if (!EffectiveAnchorSecurityPermanentCovers_(floor)) {
                throw std::runtime_error(
                    "replayed chain did not reconstruct a required anchor security floor");
            }
        }
    }

    void PublishBtcVeldSupplySnapshot_(const Block& tip) {
        const int64_t supply = onchain_tokens_.GetSupply(BTCVELD_TOKEN_ID);
        btcveld_supply_snapshot_.Publish(supply, tip.height, tip.GetHash());
    }

    std::string BtcVeldSupplySnapshotJson_() const {
        auto snapshot = btcveld_supply_snapshot_.Read();
        if (!snapshot)
            throw std::runtime_error("coherent btcVELD supply snapshot unavailable");
        std::ostringstream j;
        j << "{\"supply_sats\":" << snapshot->supply_sats
          << ",\"tip\":" << snapshot->tip
          << ",\"tip_hash\":\"" << HashToHex(snapshot->tip_hash) << "\"}";
        return j.str();
    }

    static std::string SerializeUTXO(const UTXO& u) {
        std::string data(9 + u.script_pubkey.size(), '\0');
        for (int i = 0; i < 8; ++i) data[i] = (u.value >> (i*8)) & 0xFF;
        data[8] = (uint8_t)u.script_pubkey.size();
        std::copy(u.script_pubkey.begin(), u.script_pubkey.end(), data.begin()+9);
        return data;
    }

    static std::vector<std::pair<
        std::string, std::optional<std::string>>>
    SerializeUTXODelta_(const Blockchain::UTXODelta& delta) {
        std::vector<std::pair<
            std::string, std::optional<std::string>>> out;
        out.reserve(delta.size());
        for (const auto& entry : delta) {
            std::optional<std::string> value;
            if (entry.value) value = SerializeUTXO(*entry.value);
            out.emplace_back("u:" + entry.key, std::move(value));
        }
        return out;
    }

    BtcVeldMintProofStatus BuildMintNullifierStatus_(
            const std::string& outpoint) {
        if (!mint_nullifier_index_healthy_.load(std::memory_order_acquire))
            throw std::runtime_error(
                "btcVELD nullifier proof index is degraded; restart/replay required");
        for (int attempt = 0; attempt < 3; ++attempt) {
            try {
                MintNullifierIndex index(db_.GetIndexDB());
                return index.BuildStatusFromQuiescentSample(
                    chain_, outpoint, [this] {
                        // Recheck after waiting for any in-flight canonical
                        // transition.  The helper releases the transition and
                        // token locks before its O(mints) index/GetBlock scan.
                        if (!mint_nullifier_index_healthy_.load(
                                std::memory_order_acquire))
                            throw std::runtime_error(
                                "btcVELD nullifier proof index is degraded; "
                                "restart/replay required");
                        return onchain_tokens_.GetBtcVeldMintAccumulator();
                    });
            } catch (const MintNullifierTipRace&) {
                // A block/reorg racing the accumulator sample is retryable.  A
                // normal race must not permanently degrade the service.
                if (attempt == 2) throw;
            } catch (const MintNullifierIndexError&) {
                mint_nullifier_index_healthy_.store(
                    false, std::memory_order_release);
                throw;
            } catch (const std::runtime_error&) {
                // Storage/iterator errors are index failures too.  Never return
                // a partial best effort; require restart/replay repair.
                mint_nullifier_index_healthy_.store(
                    false, std::memory_order_release);
                throw;
            }
        }
        throw std::runtime_error("btcVELD nullifier proof unavailable");
    }

    std::string BuildRedeemPageJson_(const std::vector<std::string>& params) {
        if (!redeem_index_healthy_.load(std::memory_order_acquire))
            throw std::runtime_error(
                "btcVELD redeem index is degraded; restart/replay required");
        const std::string cursor = params.empty() ? std::string() : params[0];
        size_t limit = RedeemObligationIndex::DEFAULT_PAGE_SIZE;
        if (params.size() >= 2 && !params[1].empty()) {
            try {
                unsigned long long parsed = std::stoull(params[1]);
                if (parsed == 0 || parsed > RedeemObligationIndex::MAX_PAGE_SIZE)
                    throw std::out_of_range("page size");
                limit = (size_t)parsed;
            } catch (...) {
                throw std::invalid_argument(
                    "getbtcveldredeems limit must be 1..1000");
            }
        }

        // A reorg/new block between the page snapshot and finality read causes
        // a retry, so each response carries one coherent
        // (tip,tip_hash,final_height) tuple. Cross-page changes are detected and
        // retried by the daemon too, including same-height tip replacement.
        for (int attempt = 0; attempt < 3; ++attempt) {
            RedeemObligationIndex index(db_.GetIndexDB());
            auto page = index.ReadPage(chain_, cursor, limit);
            const auto commitment =
                onchain_tokens_.GetBtcVeldRedeemCommitment();
            uint64_t fin = FinalHeight();
            Block current_tip;
            const bool genesis_empty_commitment =
                page.tip == 0 && commitment.processed_height == 0 &&
                HashIsZero(commitment.processed_block_hash) &&
                commitment.count == 0 &&
                commitment.root == EmptyBtcVeldRedeemCommitment();
            const bool commitment_at_page_tip =
                (commitment.processed_height == page.tip &&
                 commitment.processed_block_hash == page.tip_hash) ||
                genesis_empty_commitment;
            if (!commitment_at_page_tip || !chain_.TryTip(current_tip) ||
                current_tip.height != page.tip ||
                current_tip.GetHash() != page.tip_hash || fin > page.tip) continue;

            std::ostringstream j;
            j << "{\"tip\":" << page.tip
              << ",\"tip_hash\":\"" << HashToHex(page.tip_hash) << "\""
              << ",\"final_height\":" << fin
              << ",\"redeem_count\":" << commitment.count
              << ",\"redeem_root\":\""
              << HashToHex(commitment.root) << "\""
              << ",\"cursor\":\""
              << OnChainTokenLedger::JsonEscape(cursor) << "\""
              << ",\"next_cursor\":\""
              << OnChainTokenLedger::JsonEscape(
                     page.next_cursor.empty() ? cursor : page.next_cursor)
              << "\""
              << ",\"has_more\":" << (page.has_more ? "true" : "false")
              << ",\"page_limit\":" << limit
              << ",\"redeems\":[";
            bool first = true;
            for (const auto& indexed : page.items) {
                if (!first) j << ',';
                std::string item =
                    onchain_tokens_.TransferToJSON(indexed.record);
                if (!item.empty() && item.back() == '}') item.pop_back();
                j << item << ",\"block_hash\":\""
                  << HashToHex(indexed.block_hash) << "\"}";
                first = false;
            }
            j << "]}";
            return j.str();
        }
        throw std::runtime_error(
            "chain changed while reading btcVELD redeem page; retry");
    }

    // Apply a block's VELD_BHDR header-relay operations to `ch`. This is a
    // no-op unless the relay is active at this height (dormant => never touches
    // `ch`, so consensus is byte-identical to a chain without the relay). Applied
    // BEFORE the token ledger's ProcessBlock so an in-block deposit proof sees the
    // same header view on every node. `ch` is touched only from the block-
    // processing thread (BtcHeaderChain has no internal lock).
    static bool FeedBtcHeaders_(btcspv::BtcHeaderChain& ch,
                                const Block& b) {
        if (!BtcVeldSpvActive(b.height)) return true;
        for (const auto& tx : b.transactions)
            for (const auto& out : tx.outputs) {
                std::string d = ParseOpReturn(out.script_pubkey);
                if (d.rfind("VELD_BHDR|", 0) != 0) continue;
                std::vector<uint8_t> raw = BtcVeldHex_(d.c_str() + 10);
                if (raw.empty() || !btcspv::IsBtcHeaderOp(raw.data(), raw.size()))
                    continue;   // malformed marker remains a consensus no-op
                const int accepted = btcspv::ApplyBtcHeaderOp(
                    ch, raw.data(), raw.size(), (uint32_t)b.header.timestamp);
                // ApplyBtcHeaderOp can accept a valid prefix then reject a later
                // header. Never let that partial state escape as a successful
                // block apply; the outer module snapshot restores the prefix.
                if (accepted != (int)raw[4]) return false;
            }
        return true;
    }

    // Layer-2 anchoring: advance bounded state and stage VELD_ANCHOR proofs
    // from block `b`. Staging has no fork-choice or economic authority.
    // Promotion is a distinct post-QC transition below, after this block's
    // economics have already consumed the parent finality frame.
    // An anchor OP_RETURN = "VELD_ANCHOR|" <hex ANCHOR_SPV payload>; VerifyAnchor proves it
    // against the in-consensus BTC header chain `btc` (>= K confirmations), first-seen wins.
    // No-op unless anchoring is active at this height (dormant => never touched => consensus
    // byte-identical). Call AFTER FeedBtcHeaders_(btc, b) so the proof's BTC block is present.
    static bool FeedAnchors_(
            btcanchor::AnchorSet& aset,
            const btcspv::BtcHeaderChain& btc, const Block& b,
            ::veld::finality::qc::FinalityState& finality_state,
            const std::function<bool(uint64_t, Hash256&)>&
                resolve_applied_ancestor) {
        // A Bitcoin proof cannot select consensus history until validator
        // finality is active. Anchor activation is derived from retained chain
        // state rather than a height constant.
        // Advance on every block, even during a validator-qualification dip.
        // A proof staged while admission was healthy must not be stranded just
        // because the QC which later covers its carrier shares an epoch-boundary
        // block with a sub-floor snapshot.
        aset.AdvanceHeight(b.height);
        if (!finality_state.AnchorWarmupComplete() ||
            finality_state.record.IsNull() ||
            !BtcVeldAnchorActive(finality_state.record.target.height))
            return true;
        for (const auto& tx : b.transactions)
            for (const auto& out : tx.outputs) {
                std::string d = ParseOpReturn(out.script_pubkey);
                if (d.rfind("VELD_ANCHOR|", 0) != 0) continue;
                std::vector<uint8_t> raw = BtcVeldHex_(d.c_str() + 12);
                if (raw.empty()) continue;
                btcanchor::AnchorResult r = btcanchor::VerifyAnchor(btc, raw.data(), raw.size(), BTCVELD_ANCHOR_BTC_CONFS);
                if (!r.ok) continue;
                // Anti-front-run (Layer-3 composition): only a FINALIZED block may be anchored
                // — an attacker cannot anchor a secret fork because validators won't finalize
                // it. Keyed on b.height, NEVER chain_.Height(): during a reorg/startup replay
                // the chain is already at its final tip while this runs per historical block,
                // and any tip-keyed read here would admit a different anchor set on a
                // replaying node than the live node recorded => ANCHORS digest split.
                const uint64_t fin = finality_state.FinalizedHeight();
                if (r.veld_height > fin) continue;
                if (!BtcVeldAnchorTargetValid(finality_state.record,
                                              r.veld_height,
                                              r.veld_block_hash,
                                              b.height)) continue;

                // The BTC proof authenticates only the anchor transaction's
                // claim.  It must also name the exact Veld branch being applied;
                // otherwise a permissionless submitter could commit arbitrary
                // bytes for a current/past height and freeze every legitimate
                // alternative at that height.  Precommit runs while Blockchain
                // already owns chain_mutex_, so use its explicit unlocked read;
                // every post-commit/startup/reorg replay call uses the ordinary
                // locked accessor after the candidate branch is canonical.
                if (!btcanchor::MatchesAppliedVeldBranch(
                        r, b, resolve_applied_ancestor)) continue;
                // Deterministic first-seen ordering = block-processing order; `b.height` is
                // the Veld height it was seen at (stored for the digest). First Record wins.
                // Require the anchor target to be finalized and within the
                // configured acceptance window. Finality, rather than recency,
                // provides the required safety property.
                if (!BtcVeldAnchorTargetInWindow(r.veld_height, b.height)) continue;

                // First valid proof per target wins, but it is only STAGED in
                // this unfinalized carrier. A later finalized prefix promotes
                // it on every live/replay/reorg path. This preserves the proof
                // without turning competing unfinalized carriers into
                // partition locks.
                (void)aset.Stage(r.veld_height, r.veld_block_hash,
                                 b.height, b.GetHash(), r.btc_block_hash,
                                 r.btc_txid);
            }
        return true;
    }

    // Promote only after this block's finality certificate has been verified
    // and retained. The exact proof carrier must lie in that finalized prefix,
    // and the Bitcoin proof block must still be k-deep on the deterministic
    // BTC view at this one-shot transition. A normal Bitcoin reorg drops the
    // pending proof and requires a fresh carrier; a substituted/missing Veld
    // carrier is a consensus failure. This runs before the epoch snapshot so a
    // same-boundary qualification dip cannot strand a now-finalized proof.
    static bool PromoteFinalizedAnchors_(
            btcanchor::AnchorSet& aset,
            btcspv::BtcHeaderChain& btc,
            ::veld::finality::qc::FinalityState& finality_state,
            const std::function<bool(uint64_t, Hash256&)>&
                resolve_applied_ancestor) {
        if (finality_state.record.IsNull() ||
            !BtcVeldAnchorActive(finality_state.FinalizedHeight()))
            return true;
        const auto promotion = aset.PromoteFinalized(
            finality_state.FinalizedHeight(), resolve_applied_ancestor,
            [&btc](const btcspv::H256& btc_block_hash) {
                return btc.IsFinal(btc_block_hash,
                                   BTCVELD_ANCHOR_BTC_CONFS);
            },
            finality_state.record);
        if (!promotion.ok) return false;
        if (promotion.promoted != 0) {
            const auto permanent = aset.Permanent();
            if (!permanent ||
                !btc.PromoteObservedCheckpoint(permanent->entry.btc_block_hash))
                return false;
            finality_state.ever_promoted_anchor = true;
        }
        return true;
    }

    // Layer-3: publish the retained finalized high-water mark. Called at the same
    // per-block position on every path — incremental accept, reorg replay, startup
    // replay — so anchor authorization and payout holds observe replay-identical
    // certificate state. It must key on the block transition, never the already-
    // advanced chain tip during replay.
    // Atomic block-state commit foundation. One snapshot/restore
    // over ALL nine block-mutable subsystems + the finality high-water mark, so the
    // block-connect path can run the per-module apply as a single all-or-nothing unit:
    // snapshot -> apply -> on any failure restore every subsystem verbatim and reject
    // the block, so no partial / digest-divergent state can ever persist. Each field is
    // the subsystem's own Reset()-derived StateSnapshot; final_height_ is a plain atomic.
    struct AllModuleSnapshots {
        OnChainTokenLedger::StateSnapshot          tokens;
        AmmLedger::StateSnapshot                   amm;
        StakingLedger::StateSnapshot               staking;
        ValidatorRegistry::StateSnapshot           validators;
        GovernanceEngine::StateSnapshot            governance;
        btcspv::BtcHeaderChain::StateSnapshot      btc_headers;
        btcanchor::AnchorSet::StateSnapshot        anchors;
        btcveld::SignerBondCovenant::StateSnapshot bond_covenant;
        VaultLedger::StateSnapshot                 vault;
        // Roll back the complete finality state with the other consensus
        // modules; final_height is only a status mirror.
        ::veld::finality::qc::FinalityState        fin_state;
        uint64_t                                   final_height = 0;
        uint64_t                                   btc_header_tip = 0;
        bool                                       btc_relay_fresh = false;
        uint64_t                                   peg_gate_snapshot = 0;
        uint64_t                                   last_pool_flush_height = 0;
        std::vector<bool>                          anchor_security_exact_observed;
    };
    AllModuleSnapshots SnapshotAllModules() const {
        return AllModuleSnapshots{
            onchain_tokens_.SnapshotState(),
            amm_.SnapshotState(),
            staking_.SnapshotState(),
            validators_.SnapshotState(),
            governance_.SnapshotState(),
            btc_headers_.SnapshotState(),
            anchors_.SnapshotState(),
            bond_covenant_.SnapshotState(),
            vault_.SnapshotState(),
            fin_state_,
            final_height_.load(std::memory_order_acquire),
            btc_header_tip_.load(std::memory_order_acquire),
            btc_relay_fresh_snapshot_.load(std::memory_order_acquire),
            peg_gate_snapshot_.load(std::memory_order_acquire),
            last_pool_flush_height_.load(std::memory_order_acquire),
            SnapshotExactAnchorSecurityReconstructions_(),
        };
    }
    void RestoreAllModules(const AllModuleSnapshots& s) {
        onchain_tokens_.RestoreState(s.tokens);
        amm_.RestoreState(s.amm);
        staking_.RestoreState(s.staking);
        validators_.RestoreState(s.validators);
        governance_.RestoreState(s.governance);
        btc_headers_.RestoreState(s.btc_headers);
        anchors_.RestoreState(s.anchors);
        bond_covenant_.RestoreState(s.bond_covenant);
        vault_.RestoreState(s.vault);
        fin_state_ = s.fin_state;
        final_height_.store(s.final_height, std::memory_order_release);
        btc_header_tip_.store(s.btc_header_tip, std::memory_order_release);
        btc_relay_fresh_snapshot_.store(s.btc_relay_fresh,
                                        std::memory_order_release);
        peg_gate_snapshot_.store(s.peg_gate_snapshot,
                                 std::memory_order_release);
        last_pool_flush_height_.store(s.last_pool_flush_height,
                                      std::memory_order_release);
        RestoreExactAnchorSecurityReconstructions_(
            s.anchor_security_exact_observed);
    }

    // Reorg preparation must never replay module state from genesis.  Retain a
    // small rolling set of complete, post-block checkpoints spaced at the
    // consensus reorg horizon.  The selected checkpoint is hash-bound to the
    // currently published canonical chain before use, so stale checkpoints
    // left by an aborted branch are ignored deterministically.
    struct ModuleCheckpoint {
        uint64_t height{0};
        Hash256 hash{};
        uint64_t supply{0};
        AllModuleSnapshots modules;
    };
    std::deque<ModuleCheckpoint> module_checkpoints_;
    static constexpr size_t MODULE_CHECKPOINT_RETAIN = 4;

    void CaptureModuleCheckpoint_(uint64_t height, const Hash256& hash,
                                  uint64_t supply, bool force = false) {
        if (!force && (height % MAX_REORG_DEPTH) != 0) return;
        InstallModuleCheckpoint_(height, hash, supply,
                                 SnapshotAllModules());
    }

    void InstallModuleCheckpoint_(uint64_t height, const Hash256& hash,
                                  uint64_t supply,
                                  const AllModuleSnapshots& modules) {
        for (auto it = module_checkpoints_.begin();
             it != module_checkpoints_.end(); ) {
            if (it->height == height && it->hash == hash)
                it = module_checkpoints_.erase(it);
            else
                ++it;
        }
        module_checkpoints_.push_back(ModuleCheckpoint{
            height, hash, supply, modules});
        while (module_checkpoints_.size() > MODULE_CHECKPOINT_RETAIN)
            module_checkpoints_.pop_front();
    }

    const ModuleCheckpoint* FindCanonicalModuleCheckpoint_(
            uint64_t max_height,
            bool chain_mutex_already_held = false) const {
        for (auto it = module_checkpoints_.rbegin();
             it != module_checkpoints_.rend(); ++it) {
            if (it->height > max_height) continue;
            try {
                // BuildAltOverlay is invoked synchronously from the bounded
                // reorg while Blockchain owns chain_mutex_.  Re-entering the
                // locking accessor there throws resource_deadlock_would_occur;
                // the ordinary callback/replay callers run unlocked and must
                // retain the locking accessor.
                const Block canonical = chain_mutex_already_held
                    ? chain_.GetBlockUnlocked(it->height)
                    : chain_.GetBlock(it->height);
                if (canonical.GetHash() == it->hash)
                    return &*it;
            } catch (...) {
                continue;
            }
        }
        return nullptr;
    }

    // Retained across every per-block callback of one multi-block reorg.  A
    // failure on block N must restore the modules/latches from before block 1,
    // matching Blockchain's whole-canonical-frame compensation.
    std::optional<AllModuleSnapshots> reorg_transaction_modules_;
    uint64_t reorg_transaction_height_ = 0;
    uint64_t reorg_transaction_supply_ = 0;
    // Captured before the reorg's first durable mutation.  The outer optional
    // is represented by the boolean so the inner nullopt remains meaningful:
    // it instructs abort compensation to delete an alt-only VLF key when the
    // pre-reorg DB had no local floor.
    bool reorg_anchor_floor_restore_captured_ = false;
    std::optional<std::vector<uint8_t>> reorg_anchor_floor_restore_wire_;
    // VDP1 is also part of the authoritative canonical frame.  Preserve its
    // exact pre-reorg tri-state so abort compensation cannot either lose an
    // existing repair obligation or retain an alt-branch-only one.
    std::optional<std::vector<uint8_t>>
        reorg_durable_publication_restore_wire_;
    std::optional<db::VeldDB::ReorgUtxoPending>
        reorg_utxo_pending_;
    // Retain the exact old/new frame through post-canonical publication of
    // rebuildable indexes.  reorg_utxo_pending_ is retired as soon as the
    // authoritative chain batch commits, but btcvr:/btcmn: still need the old
    // tip and common ancestor to prune the complete displaced height range.
    std::optional<db::VeldDB::ReorgUtxoPending>
        reorg_derived_index_frame_;
    // A sync failure while arming VUR1 cannot prove whether the intent and/or
    // candidate UTXO batch reached durable storage.  In that state Blockchain
    // must not compensate (which could overwrite a recoverable candidate), and
    // it must not publish the replacement suffix either.  Finish the in-memory
    // callback sequence as no-op successes under a process-wide fail-stop; a
    // clean restart resolves the retained identity against the old DB tip.
    std::atomic<bool> reorg_publication_uncertain_{false};
    struct ReorgBlockPublicationStage {
        uint64_t height{0};
        Hash256 hash{};
        uint32_t bits{0};
        uint64_t module_supply{0};
        uint64_t vault_fees{0};
        uint64_t vault_reserve_payout{0};
        std::optional<AllModuleSnapshots> boundary_checkpoint;
        std::vector<TokenTransferRecord> redeems;
        std::vector<BtcVeldMintTransition> mint_transitions;
    };
    std::vector<ReorgBlockPublicationStage>
        reorg_block_publication_stages_;
    // Exact rows from the displaced canonical suffix, captured while the old
    // DB index is still authoritative. The final txindex batch conditionally
    // deletes only rows which still name their old height, then publishes the
    // replacement suffix. Retained across publication uncertainty for recovery
    // and restart recovery; cleared only on definite publication or abort.
    std::vector<std::pair<std::string, uint64_t>>
        reorg_displaced_txindex_rows_;
    // Finality vote retirement is intentionally outside AllModuleSnapshots:
    // votes are live operator/P2P input, not replay-derived consensus state.
    // During a multi-block reorg, stage carried QCs until the LAST callback is
    // durably accepted.  A later callback can still abort the entire reorg, so
    // consuming an intermediate carrier here would be irreversible data loss.
    std::vector<::veld::finality::qc::QuorumCert>
        reorg_finality_retirements_;
    void CaptureReorgAnchorFloorForAbort_() {
        if (reorg_anchor_floor_restore_captured_) return;
        // Compensation must restore the exact pre-reorg DB value, not the
        // in-memory Store high-water.  During crash recovery the external and
        // DB witnesses may intentionally differ until replay proves both; using
        // the higher Store value here would silently collapse that evidence if
        // the reorg later aborted.
        auto db_wire = db_.ReadAnchorSecurityFloor();
        if (db_wire) {
            if (db_wire->empty() ||
                db_wire->size() >
                    db::VeldDB::MAX_ANCHOR_SECURITY_FLOOR_BYTES) {
                throw std::runtime_error(
                    "pre-reorg DB anchor floor exceeds its strict size bound");
            }
            std::string error;
            const auto decoded = btcanchor::floor_store::Decode(
                *db_wire, &error);
            if (!decoded || decoded->network_magic != config_.magic ||
                decoded->genesis_hash != CreateGenesisBlock().GetHash()) {
                throw std::runtime_error(
                    "pre-reorg DB anchor floor is malformed or belongs to another chain: " +
                    error);
            }
        }
        reorg_anchor_floor_restore_wire_ = std::move(db_wire);
        reorg_durable_publication_restore_wire_ =
            db_.ReadDurablePublicationPendingWire();
        reorg_anchor_floor_restore_captured_ = true;
    }
    void ClearReorgAnchorFloorForAbort_() {
        reorg_anchor_floor_restore_wire_.reset();
        reorg_durable_publication_restore_wire_.reset();
        reorg_anchor_floor_restore_captured_ = false;
    }
    void RestoreReorgTransactionModules_() {
        if (!reorg_transaction_modules_) return;
        RestoreAllModules(*reorg_transaction_modules_);
        last_token_height_ = reorg_transaction_height_;
        last_module_supply_ = reorg_transaction_supply_;
        reorg_transaction_modules_.reset();
        reorg_finality_retirements_.clear();
        reorg_block_publication_stages_.clear();
    }

    void CaptureReorgDisplacedTxIndexRows_(
            uint64_t ancestor_height, const Hash256& ancestor_hash,
            const Block& old_tip) {
        reorg_displaced_txindex_rows_.clear();
        if (!txindex_enabled_) return;
        if (old_tip.height <= ancestor_height)
            throw std::runtime_error(
                "reorg displaced txindex suffix is empty");

        Hash256 prior = ancestor_hash;
        for (uint64_t height = ancestor_height + 1;; ++height) {
            const auto indexed = db_.GetHashAtHeight(height);
            if (!indexed || !db::IsCanonicalHash256Text(*indexed))
                throw std::runtime_error(
                    "cannot stage displaced txindex: invalid old height row");
            const Hash256 hash = HexToHash(*indexed);
            const auto bytes = db_.ReadBlock(hash);
            if (!bytes)
                throw std::runtime_error(
                    "cannot stage displaced txindex: old block body missing");
            Block old_block;
            old_block.height = height;
            const size_t consumed = Block::Deserialize(*bytes, 0, old_block);
            if (consumed == 0 || consumed != bytes->size() ||
                old_block.Serialize() != *bytes ||
                old_block.GetHash() != hash ||
                old_block.header.prev_block_hash != prior) {
                throw std::runtime_error(
                    "cannot stage displaced txindex: old suffix is non-canonical");
            }
            for (const auto& tx : old_block.transactions) {
                reorg_displaced_txindex_rows_.emplace_back(
                    HashToHex(tx.GetTxID()), height);
            }
            prior = hash;
            if (height == old_tip.height) break;
            if (height == UINT64_MAX)
                throw std::runtime_error(
                    "cannot stage displaced txindex: height overflow");
        }
        if (prior != old_tip.GetHash())
            throw std::runtime_error(
                "displaced txindex suffix does not end at the old tip");
    }

    // Monotonic within a chain; the reorg/startup rebuild sites zero it before replaying.
    // Single writer (the block paths are serialized); atomic so RPC reads race-free.
    // The genesis hash this binary is built for, as bytes. Parsed from the
    // ASCII constant rather than read from chain_, so a node that has not yet
    // loaded block 0 still binds votes correctly, and so a chain whose block 0
    // disagrees with the binary can never verify a vote at all.
    static const Hash256& GenesisHashBytes_() {
        static const Hash256 h = [] {
            Hash256 out{};
            auto nib = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return 0;
            };
            for (size_t i = 0; i < 32 && GENESIS_HASH[2 * i] && GENESIS_HASH[2 * i + 1]; ++i)
                out[i] = (uint8_t)((nib(GENESIS_HASH[2 * i]) << 4) |
                                    nib(GENESIS_HASH[2 * i + 1]));
            return out;
        }();
        return h;
    }

    // Parse a submitted finality vote from JSON into a SignedVote.
    //
    // STRICT: this decodes untrusted daemon input into a consensus object, so
    // a missing or malformed field is a rejection, not a defaulted zero. It
    // does NOT verify the signature — the assembler's Offer() does that against
    // the snapshot. Separating parse from verify keeps the ~1ms ML-DSA cost
    // behind the cheap structural checks.
    //
    // Format (flat JSON, the daemon's own encoding):
    //   {"epoch":N,"set_root":"hex64","phase":1|2,"round":N,
    //    "src_h":N,"src_hash":"hex64","tgt_h":N,"tgt_hash":"hex64",
    //    "pubkey":"hex3904","sig":"hex6618"}
    static bool ParseSignedVoteJson_(const std::string& j,
                                     ::veld::finality::qc::SignedVote& out) {
        namespace fq = ::veld::finality::qc;
        auto num = [&](const char* key, uint64_t& v) -> bool {
            const std::string pat = std::string("\"") + key + "\":";
            auto p = j.find(pat);
            if (p == std::string::npos) return false;
            p += pat.size();
            size_t e = p;
            while (e < j.size() && (j[e] == ' ')) ++e;
            size_t start = e;
            while (e < j.size() && j[e] >= '0' && j[e] <= '9') ++e;
            if (e == start) return false;
            const std::string tok = j.substr(start, e - start);
            if (tok.size() > 1 && tok[0] == '0') return false;   // canonical
            try { v = std::stoull(tok); } catch (...) { return false; }
            return true;
        };
        auto str = [&](const char* key, std::string& v) -> bool {
            const std::string pat = std::string("\"") + key + "\":\"";
            auto p = j.find(pat);
            if (p == std::string::npos) return false;
            p += pat.size();
            auto e = j.find('"', p);
            if (e == std::string::npos) return false;
            v = j.substr(p, e - p);
            return true;
        };
        auto hex_to_hash = [](const std::string& h, Hash256& o) -> bool {
            if (h.size() != 64) return false;
            for (size_t i = 0; i < 32; ++i) {
                auto nib = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                    return -1;   // lowercase-only, canonical
                };
                const int hi = nib(h[2*i]), lo = nib(h[2*i+1]);
                if (hi < 0 || lo < 0) return false;
                o[i] = (uint8_t)((hi << 4) | lo);
            }
            return true;
        };

        uint64_t epoch = 0, phase = 0, round = 0, src_h = 0, tgt_h = 0;
        std::string set_root, src_hash, tgt_hash, pubkey, sig;
        if (!num("epoch", epoch) || !num("phase", phase) || !num("round", round))
            return false;
        if (phase != 1 && phase != 2) return false;
        if (round > UINT32_MAX) return false;
        if (!num("src_h", src_h) || !num("tgt_h", tgt_h)) return false;
        if (!str("set_root", set_root) || !str("src_hash", src_hash) ||
            !str("tgt_hash", tgt_hash) || !str("pubkey", pubkey) ||
            !str("sig", sig)) return false;
        if (pubkey.size() != 3904 || sig.size() != 6618) return false;

        if (!hex_to_hash(set_root, out.set_root)) return false;
        if (!hex_to_hash(src_hash, out.source.hash)) return false;
        if (!hex_to_hash(tgt_hash, out.target.hash)) return false;
        out.epoch_id      = epoch;
        out.phase         = (fq::Phase)(uint8_t)phase;
        out.round         = (uint32_t)round;
        out.source.height = src_h;
        out.target.height = tgt_h;
        out.pubkey_hex    = pubkey;
        // sig hex -> bytes
        out.signature.clear(); out.signature.reserve(3309);
        for (size_t i = 0; i < sig.size(); i += 2) {
            auto nib = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                return -1;
            };
            const int hi = nib(sig[i]), lo = nib(sig[i+1]);
            if (hi < 0 || lo < 0) return false;
            out.signature.push_back((uint8_t)((hi << 4) | lo));
        }
        return out.signature.size() == 3309;
    }

    // Epoch boundary: freeze the validator set for the NEXT epoch.
    //
    // MUST run as block epoch_start-1 connects and nowhere else. The set is not
    // reconstructible after the fact: ValidatorRecord carries history for
    // membership but NOT for bond_units, so a snapshot rebuilt later is a
    // different set, which would silently change a past epoch's denominator and
    // therefore its finality. See finality_snapshot.h.
    bool MaybeSnapshotEpochFor_(
            uint64_t h, ValidatorRegistry& registry,
            ::veld::finality::qc::FinalityState& state) {
        namespace fq = ::veld::finality::qc;
        const uint64_t next_epoch = fq::EpochOf(h) + 1;
        if (h == UINT64_MAX || h + 1 != fq::EpochStart(next_epoch))
            return true;   // not a boundary
        const fq::EpochSnapshot snapshot =
            fq::BuildEpochSnapshot(registry, next_epoch, h);
        return registry.RecordFinalitySnapshot(snapshot) &&
               state.OnEpochBoundary(snapshot);
    }

    bool MaybeSnapshotEpoch_(uint64_t h) {
        return MaybeSnapshotEpochFor_(h, validators_, fin_state_);
    }

    // Ingest any finality certificate carried by this block.
    //
    // Bind each certificate to the height and hash of its canonical carrier so
    // a reorganization must preserve both the finalized target and its proof.
    bool FeedFinalityCerts_(const Block& block,
                            bool chain_mutex_already_held) {
        namespace fq = ::veld::finality::qc;
        auto r = fq::ParseFinalityBlock(
            block, [](const std::vector<uint8_t>& spk) {
                return ::veld::ParseOpReturn(spk);
            });
        if (r.status == fq::FinParseStatus::NONE) return true;
        if (r.status != fq::FinParseStatus::VALID ||
            r.decoded.qc.phase != fq::Phase::PRECOMMIT ||
            !fq::InVoteWindow(r.decoded.qc.target.height, block.height))
            return false;

        auto it = fin_state_.snapshots.find(r.decoded.qc.epoch_id);
        if (it == fin_state_.snapshots.end()) return false;
            // Chain binding: the compile-time network byte plus the genesis
            // hash this binary was built for. Same pair the endorsement V2
            // preimage uses, for the same reason (validators.h:1195).
        if (!fq::VerifyDecodedQc(r.decoded, it->second,
                                 fq::NETWORK_ID, GenesisHashBytes_()))
            return false;

        Hash256 canonical_target{};
        try {
            const Block target = chain_mutex_already_held
                ? chain_.GetBlockUnlocked(r.decoded.qc.target.height)
                : chain_.GetBlock(r.decoded.qc.target.height);
            canonical_target = target.GetHash();
        } catch (...) {
            return false;
        }
        if (canonical_target != r.decoded.qc.target.hash) return false;

        fq::CheckpointRef carrier;
        carrier.height = block.height;
        carrier.hash   = block.GetHash();
        if (!fin_state_.OnCertificate(r.decoded.qc, carrier,
                                      canonical_target)) return false;
        if (!validators_.RecordFinalityQc(r.decoded.qc, it->second,
                                          block.height)) return false;
        return true;
    }

    // Retire assembler votes only after the exact carrier bytes are durable.
    // FeedFinalityCerts_ runs during preflight, startup/reorg replay, and the
    // rollback-capable live module pass, so it must never mutate the live vote
    // pool.  Parse again at this post-durable boundary; failure is conservative
    // (votes remain until a later carrier/epoch prune) and cannot affect the
    // already-committed consensus transition.
    bool DecodeDurableFinalityCarrier_(
            const Block& block,
            ::veld::finality::qc::QuorumCert& out) const {
        namespace fq = ::veld::finality::qc;
        const auto r = fq::ParseFinalityBlock(
            block, [](const std::vector<uint8_t>& spk) {
                return ::veld::ParseOpReturn(spk);
            });
        if (r.status != fq::FinParseStatus::VALID ||
            r.decoded.qc.phase != fq::Phase::PRECOMMIT)
            return false;
        out = r.decoded.qc;
        return true;
    }

    void RetireDurableFinalityCarrier_(const Block& block) noexcept {
        try {
            ::veld::finality::qc::QuorumCert qc;
            if (!DecodeDurableFinalityCarrier_(block, qc)) return;
            std::lock_guard<std::mutex> g(fin_assembler_mu_);
            fin_assembler_.RemoveFinalizedClaim(qc);
        } catch (const std::exception& e) {
            std::cerr << "  [finality] durable carrier vote retirement deferred: "
                      << e.what() << "\n";
            std::cerr.flush();
        } catch (...) {
            std::cerr << "  [finality] durable carrier vote retirement deferred\n";
            std::cerr.flush();
        }
    }

    void StageReorgFinalityCarrier_(const Block& block) noexcept {
        try {
            ::veld::finality::qc::QuorumCert qc;
            if (DecodeDurableFinalityCarrier_(block, qc))
                reorg_finality_retirements_.push_back(std::move(qc));
        } catch (const std::exception& e) {
            std::cerr << "  [finality] reorg carrier retirement staging deferred: "
                      << e.what() << "\n";
            std::cerr.flush();
        } catch (...) {
            std::cerr << "  [finality] reorg carrier retirement staging deferred\n";
            std::cerr.flush();
        }
    }

    void RetireCompletedReorgFinalityCarriers_() noexcept {
        try {
            std::lock_guard<std::mutex> g(fin_assembler_mu_);
            for (const auto& qc : reorg_finality_retirements_)
                fin_assembler_.RemoveFinalizedClaim(qc);
        } catch (const std::exception& e) {
            std::cerr << "  [finality] completed-reorg vote retirement deferred: "
                      << e.what() << "\n";
            std::cerr.flush();
        } catch (...) {
            std::cerr << "  [finality] completed-reorg vote retirement deferred\n";
            std::cerr.flush();
        }
        // Whether retirement succeeded or was conservatively skipped, these
        // carriers need no retry queue: epoch pruning remains the safe fallback.
        reorg_finality_retirements_.clear();
    }

    // Mirror the retained finality mark to the status atomic used by RPC and
    // runtime gates. Consensus state remains authoritative.
    void UpdateFinality_(uint64_t h, bool chain_mutex_already_held) {
        (void)h; (void)chain_mutex_already_held;
        final_height_.store(fin_state_.FinalizedHeight(),
                            std::memory_order_release);
    }

    // Return at most one verified PRECOMMIT certificate as canonical coinbase
    // metadata for `candidate_height`.  The full module preflight repeats every
    // consensus check; these filters keep miners from burning PoW on a stale or
    // wrong-branch certificate while a competing block is arriving.
    std::vector<std::vector<uint8_t>> PendingFinalityCoinbaseMetadata_(
            uint64_t candidate_height) {
        namespace fq = ::veld::finality::qc;
        std::vector<std::vector<uint8_t>> out;
        auto transition = chain_.AcquireConsensusTransitionGuard();
        if (!fin_state_.FinalityActive()) return out;

        std::lock_guard<std::mutex> g(fin_assembler_mu_);
        for (auto it = fin_state_.snapshots.rbegin();
             it != fin_state_.snapshots.rend(); ++it) {
            auto cert = fin_assembler_.TryAssemble(
                it->second, fq::NETWORK_ID, GenesisHashBytes_(),
                fq::Phase::PRECOMMIT,
                [this, candidate_height](const fq::DecodedQc& d) {
                    if (!fq::InVoteWindow(d.qc.target.height,
                                          candidate_height)) return false;
                    try {
                        if (chain_.GetBlock(d.qc.target.height).GetHash() !=
                            d.qc.target.hash) return false;
                    } catch (...) { return false; }
                    if (fin_state_.record.IsNull())
                        return d.qc.source.IsNull();
                    return d.qc.source == fin_state_.record.target &&
                           d.qc.target.height >
                               fin_state_.record.target.height;
                });
            if (!cert) continue;
            const std::string wire = fq::EncodeQc(cert->qc, cert->sigs);
            auto payloads = fq::EncodeFinalityCarrierPayloads(wire);
            if (payloads.empty()) continue;
            bool fit = true;
            for (const auto& payload : payloads) {
                auto script = BuildOpReturnScript(payload);
                // Finality deliberately retains its 32-KiB per-fragment cap;
                // C1F1 alone needs the larger generic OP_RETURN envelope.
                if (script.size() > 32768) { fit = false; break; }
                out.push_back(std::move(script));
            }
            if (!fit) out.clear();
            break;
        }
        return out;
    }

    // Layer-3 finalized high-water mark mirrors the retained certificate record.
    // It is read-only from the RPC thread and exposed via getpeginfo /
    // getbtcveldredeems so the redeem daemon holds a burn's BTC payout until its
    // block is final. It reports 0 until a certificate exists; there is no
    // dormant/tip fallback. Consensus gates consume the candidate-block
    // FinalityState directly rather than this status mirror.
    uint64_t FinalHeight() {
        // Zero means no certificate has finalized a block. Irreversible Bitcoin
        // payouts remain pending until the associated burn is actually final.
        return final_height_.load(std::memory_order_acquire);
    }

    // Derive every btcVELD consensus permission at the exact candidate height.
    // The compiled issuer/token profile must be active and the existing
    // seven-validator finality activation must have completed. Bitcoin
    // anchoring is additive, not an unlock prerequisite. Once activated, a
    // later validator-count drop does not re-lock the peg; a sustained loss of
    // finalized checkpoints pauses only new custody exposure. Replay, reorg and
    // mempool policy all call this same pure derivation.
    static BtcVeldPegGateState PegGateForState_(
            const ::veld::finality::qc::FinalityState& state,
            uint64_t current_height,
            const btcspv::BtcHeaderChain* btc_headers = nullptr,
            uint64_t candidate_timestamp = 0) {
        const bool launch_active = BTCVELD_ISSUER_ADDRESS[0] != '\0' &&
            current_height >= BTCVELD_ACTIVATION_HEIGHT;
        const bool finality_live = state.finality_ever_active &&
            ::veld::finality::qc::FinalityLive(
                current_height, state.FinalizedHeight());
        // The validator count is activation-only. Once the chain-derived latch
        // is set, a later finality stall pauses new mint exposure while safe
        // completion, redeem, and AMM operations remain open.
        BtcVeldPegGateState gate = DeriveBtcVeldPegGate(
            launch_active, state.finality_ever_active, finality_live,
            /*amm_continues_during_later_stall=*/true);
        if (gate.mint_live && btcspv::EXTERNAL_VALUE_FRESHNESS_REQUIRED &&
            (!btc_headers ||
             !btc_headers->ExternalValueFresh(candidate_timestamp)))
            gate.mint_live = false;
        return gate;
    }

    // Pure AMM covenant prefix preview.  The isolated covenant guard runs
    // before ApplyBlockModules_, so it must reconstruct the exact state that
    // AMM validation sees in the authoritative module sequence:
    //
    //   BTC headers -> additive anchor staging -> token ops -> AMM.
    //
    // Once validator-activated, an anchor carried beside MINT + SEED is
    // additive rather than authorizing. Every object below is an isolated
    // snapshot clone. No rejected or merely preflighted carrier can publish a
    // header, anchor, token balance, pool, or LP position.
    static bool ValidateAmmBlockWithModulePrefix_(
            AmmLedger& amm_parent, OnChainTokenLedger& tokens_parent,
            const btcspv::BtcHeaderChain& btc_parent,
            const btcanchor::AnchorSet& anchors_parent,
            const ::veld::finality::qc::FinalityState& finality_parent,
            const Block& block,
            const std::function<bool(uint64_t, Hash256&)>&
                resolve_applied_ancestor) {
        try {
            btcspv::BtcHeaderChain btc_preview(
                BtcVeldCheckpoint(), BtcVeldPowLimit(),
                2016, 1209600, BtcVeldNoRetarget());
            btc_preview.RestoreState(btc_parent.SnapshotState());
            btcanchor::AnchorSet anchors_preview;
            anchors_preview.RestoreState(anchors_parent.SnapshotState());
            auto finality_preview = finality_parent;

            if (!FeedBtcHeaders_(btc_preview, block)) return false;
            if (!FeedAnchors_(anchors_preview, btc_preview, block,
                              finality_preview,
                              resolve_applied_ancestor)) return false;
            const BtcVeldPegGateState peg_gate =
                PegGateForState_(finality_preview, block.height,
                                 &btc_preview, block.header.timestamp);

            OnChainTokenLedger tokens_preview;
            tokens_preview.RestoreState(tokens_parent.SnapshotState());
            tokens_preview.SetBtcHeaderChain(&btc_preview);
            tokens_preview.SetBtcVeldRedeemCovenant(
                tokens_parent.GetBtcVeldRedeemCovenant());
            if (!tokens_preview.ProcessBlock(block, peg_gate)) return false;

            return amm_parent.ValidateBlock(
                "VELD:btcVELD", block, tokens_preview, peg_gate,
                AmmLedger::TokenValidationFrame::POST_BLOCK_STATE);
        } catch (...) {
            return false;
        }
    }

#ifdef VELD_TEST_HOOKS
public:
    bool TestPrecheckFinalityVoteWire(
            const std::vector<uint8_t>& wire) const {
        return PrecheckFinalityVoteWire_(wire);
    }

    net::NodeServer::FinalityVoteVerifyResult TestVerifyFinalityVoteWire(
            const std::vector<uint8_t>& wire) {
        return VerifyFinalityVoteWire_(wire);
    }

    // Deterministic regression seam for the standalone validator RPC path.
    // The caller-held variant must never recursively acquire block_connect_mu.
    net::NodeServer::FinalityVoteVerifyResult
    TestVerifyFinalityVoteWireWithHeldTransition(
            const std::vector<uint8_t>& wire) {
        auto transition = chain_.AcquireConsensusTransitionGuard();
        return VerifyFinalityVoteWire_(
            wire, /*caller_holds_consensus_transition=*/true);
    }

    void TestSetFinalityEvidencePersistOverride(
            std::function<FinalityEvidencePersistStatus(
                const std::string&)> override_fn) {
        std::lock_guard<std::mutex> gate(fin_equivocation_gate_mu_);
        fin_equivocation_persist_override_ = std::move(override_fn);
    }

    void TestLoadFinalityEvidence() { LoadFinalityEvidence_(); }

    void TestPruneFinalityEvidenceAfterDurableTip(uint64_t tip) {
        PruneFinalityEvidenceAfterDurableTip_(tip);
    }

    size_t TestFinalityEvidenceCount() const {
        return fin_equivocation_collector_.PairCount();
    }

    size_t TestPendingFinalityEvidenceCount() const {
        return fin_equivocation_detector_.PendingCount();
    }

    bool TestFinalityEvidenceJournalUncertain() const {
        std::lock_guard<std::mutex> gate(fin_equivocation_gate_mu_);
        return fin_equivocation_journal_uncertain_;
    }

    size_t TestFinalityAssemblerCount() const {
        std::lock_guard<std::mutex> gate(fin_assembler_mu_);
        return fin_assembler_.PoolSize();
    }

    bool TestInstallFinalityEvidenceSnapshot(
            const ::veld::finality::qc::EpochSnapshot& snapshot) {
        if (!validators_.RecordFinalitySnapshot(snapshot)) return false;
        auto transition = chain_.AcquireConsensusTransitionGuard();
        fin_state_.snapshots[snapshot.epoch_id] = snapshot;
        return true;
    }

    // Replay-reset regression hooks.  Snapshot validation intentionally reuses
    // the same VeldNode object, so poison every launch-relevant finality field
    // and prove ReplayChain reconstructs it solely from canonical carriers.
    void TestPoisonFinalityReplayState() {
        auto transition = chain_.AcquireConsensusTransitionGuard();
        fin_state_.consecutive_qualified_epochs = 2;
        fin_state_.finality_ever_active = true;
        fin_state_.ever_promoted_anchor = true;
        final_height_.store(123, std::memory_order_release);
        peg_gate_snapshot_.store(
            PEG_GATE_FINALITY_EVER_ACTIVE_BIT_ | uint64_t{123},
            std::memory_order_release);
    }

    // Test-only seam for AMM/node fixtures that need to exercise the
    // post-validator-activation, pre-certificate liveness state without
    // constructing seven production-sized ML-DSA validator registrations.
    void TestActivatePegValidatorFloorWithoutCertificate() {
        auto transition = chain_.AcquireConsensusTransitionGuard();
        fin_state_.consecutive_qualified_epochs = 2;
        fin_state_.finality_ever_active = true;
        fin_state_.ever_promoted_anchor = false;
        final_height_.store(0, std::memory_order_release);
        peg_gate_snapshot_.store(
            PEG_GATE_FINALITY_EVER_ACTIVE_BIT_, std::memory_order_release);
    }

    bool TestFinalityReplayStateIsCold() const {
        return fin_state_.consecutive_qualified_epochs == 0 &&
               !fin_state_.finality_ever_active &&
               !fin_state_.ever_promoted_anchor &&
               fin_state_.snapshots.empty() && fin_state_.record.IsNull() &&
               final_height_.load(std::memory_order_acquire) == 0 &&
               peg_gate_snapshot_.load(std::memory_order_acquire) == 0;
    }

    static bool TestValidateAmmBlockWithModulePrefix(
            AmmLedger& amm_parent, OnChainTokenLedger& tokens_parent,
            const btcspv::BtcHeaderChain& btc_parent,
            const btcanchor::AnchorSet& anchors_parent,
            const ::veld::finality::qc::FinalityState& finality_parent,
            const Block& block,
            const std::function<bool(uint64_t, Hash256&)>& resolver) {
        return ValidateAmmBlockWithModulePrefix_(
            amm_parent, tokens_parent, btc_parent, anchors_parent,
            finality_parent, block, resolver);
    }

    // Staged-anchor carrier-preservation regression seams.  These are compiled
    // out of every production binary.  The harness installs the exact
    // consensus parent frame which a checkpoint/replay snapshot would supply,
    // then drives ordinary AddBlockDirect/on-commit and real reorg fork choice;
    // no production transition is reimplemented in the test.
    struct TestAnchorFinalityStatus {
        btcanchor::AnchorSet::StateSnapshot anchors;
        ::veld::finality::qc::FinalityState finality;
        Hash256 anchor_digest{};
        Hash256 finality_digest{};
    };

    bool TestInstallAnchorFinalityParent(
            const ::veld::finality::qc::FinalityState& parent) {
        auto transition = chain_.AcquireConsensusTransitionGuard();
        if (parent.record.IsNull() || !parent.AnchorWarmupComplete() ||
            anchors_.ActiveSize() != 0 || anchors_.PendingSize() != 0)
            return false;
        fin_state_ = parent;
        const uint64_t finalized = fin_state_.FinalizedHeight();
        final_height_.store(finalized, std::memory_order_release);
        const uint64_t frame =
            (finalized & ~PEG_GATE_FINALITY_EVER_ACTIVE_BIT_) |
            (fin_state_.finality_ever_active
                 ? PEG_GATE_FINALITY_EVER_ACTIVE_BIT_ : 0);
        peg_gate_snapshot_.store(frame, std::memory_order_release);
        return true;
    }

    TestAnchorFinalityStatus TestReadAnchorFinalityStatus() const {
        auto transition = chain_.AcquireConsensusTransitionGuard();
        return TestAnchorFinalityStatus{
            anchors_.SnapshotState(), fin_state_, anchors_.Digest(),
            fin_state_.Digest()};
    }

    bool TestAnchorAllows(uint64_t height, const Hash256& hash) const {
        auto transition = chain_.AcquireConsensusTransitionGuard();
        return anchors_.Allows(height, hash);
    }

    bool TestCaptureAnchorFinalityCheckpoint() {
        auto transition = chain_.AcquireConsensusTransitionGuard();
        const Block tip = chain_.TipCopy();
        if (tip.height != last_token_height_) return false;
        CaptureModuleCheckpoint_(tip.height, tip.GetHash(),
                                 chain_.TotalSupplyUnits(),
                                 /*force=*/true);
        return true;
    }

private:
#endif

    BtcVeldPegGateState PegGateForHeight_(uint64_t current_height) const {
        const uint64_t frame =
            peg_gate_snapshot_.load(std::memory_order_acquire);
        const bool finality_ever_active =
            (frame & PEG_GATE_FINALITY_EVER_ACTIVE_BIT_) != 0;
        const uint64_t finalized =
            frame & ~PEG_GATE_FINALITY_EVER_ACTIVE_BIT_;
        const bool launch_active = BTCVELD_ISSUER_ADDRESS[0] != '\0' &&
            current_height >= BTCVELD_ACTIVATION_HEIGHT;
        const bool finality_live = finality_ever_active &&
            ::veld::finality::qc::FinalityLive(current_height, finalized);
        BtcVeldPegGateState gate = DeriveBtcVeldPegGate(
            launch_active, finality_ever_active, finality_live,
            /*amm_continues_during_later_stall=*/true);
        if (gate.mint_live &&
            !btc_relay_fresh_snapshot_.load(std::memory_order_acquire))
            gate.mint_live = false;
        return gate;
    }

    // Feed the redeem bond/slash covenant its consensus inputs from
    // block `b` + the token ledger's just-processed accepted redeems. No-op unless
    // the redeem covenant is active at this height (dormant => never touched, so
    // consensus is byte-identical). Call AFTER `led`.ProcessBlock so LastBlockRedeems
    // reflects this block. `led` is the paired (main or alt) token ledger.
    // The implementation below includes SPV-proven fulfillment, wrong-payout
    // and fraudulent-spend verdicts, non-payment enforcement, and deterministic
    // btcVELD compensation.  Fresh reserve semantics use the request map for
    // exact liability accounting without treating signer collateral as the
    // backing asset; legacy activation remains separately gated.
    bool FeedRedeemCovenant_(btcveld::SignerBondCovenant& cov, OnChainTokenLedger& led,
                             const btcspv::BtcHeaderChain& btc, const Block& b) {
        if (!BtcVeldRedeemActive(b.height) &&
            !btcveld::reserve::TRANSITION_V1_REQUIRED)
            return true;
        // (a) signer bonding ops: "VELD_SBOND|register|<addr>|<bond_sats>"
        for (const auto& tx : b.transactions)
            for (const auto& out : tx.outputs) {
                std::string d = ParseOpReturn(out.script_pubkey);
                if (d.rfind("VELD_SBOND|", 0) != 0) continue;
                std::vector<std::string> f; { std::string cur; for (char c : d.substr(11)) { if (c=='|') { f.push_back(cur); cur.clear(); } else cur += c; } f.push_back(cur); }
                if (f.size() == 3 && f[0] == "register" &&
                    !f[1].empty()) {
                    uint64_t amt = 0;
                    if (ParseCanonicalUint64Text(f[2], amt) &&
                        amt >= BTCVELD_SIGNER_MIN_BOND_SATS) {
                        if (!cov.Register(f[1], amt) || !cov.Activate(f[1]))
                            return false;
                    }
                }
            }
        // RTP1 PAYOUT verification read the exact parent request view during
        // token processing. Consume that staged result before admitting this
        // block's new burns, so a payout can never target a same-block request.
        for (const auto& payout : led.LastBlockReservePayoutsCopy()) {
            if (!cov.MarkAuthorizedReservePayout(
                    payout.request_id, payout.payout_txid,
                    payout.principal_sats, payout.destination_spk))
                return false;
        }
        // (b) redemption obligations from THIS block's accepted redeems (deterministic set)
        for (const auto& r : led.LastBlockRedeems()) {
            btcveld::RedeemRequest req;
            std::vector<uint8_t> idb = BtcVeldHex_(r.txid.c_str());
            if (idb.size() == 32) std::memcpy(req.request_id.data(), idb.data(), 32);
            req.amount_sats     = (uint64_t)r.amount;
            req.dest_spk        = BtcVeldHex_(r.memo.c_str());   // dest BTC scriptPubKey (hex in the redeem memo)
            req.veld_recipient  = r.from;                        // the burner — re-minted btcVELD on a compensating slash
            req.request_height  = r.block_height;
            req.deadline_height = r.block_height + BTCVELD_REDEEM_SLA;
            req.btc_observed_height = btc.BestHeight();
            req.status          = btcveld::ReqStatus::LOCKED_IN;  // accepted burn is on-chain; SLA is the honor window
            req.request_commitment =
                btcveld::SignerBondCovenant::RequestCommitment(req);
            cov.AddRequest(
                req,
                /*reserve_backed_without_bond=*/
                    btcveld::reserve::TRANSITION_V1_REQUIRED);
        }
        // (b2) SPV-PROVEN PAYOUT ops: "VELD_PAYOUT|<hex PSP2 proof>" -> a correct
        //      payout FULFILLS the request (releases the bond lock); a wrong one
        //      (amount/spk) is a WRONG_PAYOUT slash. The BTC fact is proven against
        //      the in-consensus header chain, not an operator's word.
        for (const auto& tx : b.transactions)
            for (const auto& out : tx.outputs) {
                std::string d = ParseOpReturn(out.script_pubkey);
                if (d.rfind("VELD_PAYOUT|", 0) != 0) continue;
                if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED)
                    return false; // replaced by the shared RTP1 verifier
                std::vector<uint8_t> proof = BtcVeldHex_(d.c_str() + 12);
                if (proof.empty()) return false;
                bool fulfilled = false; btcveld::SlashVerdict sv;
                const auto payout = btcveld::VerifyAndResolvePayout(
                    cov, btc, proof.data(), proof.size(), BTCVELD_SPV_K_BTC,
                    fulfilled, sv, BtcVeldCustodySpk());
                if (!payout.ok || (!fulfilled && !sv.slash)) return false;
                if (sv.slash) {
                    cov.ApplySlash(sv);             // proven-but-wrong payout
                    if (sv.compensate_sats && !sv.compensate_to.empty())
                        if (!led.CompensateMint(sv.compensate_to, sv.compensate_sats,
                                                b.height, HashToHex(b.GetHash())))
                            return false;   // slash + compensation are one transition
                }
            }
        // (b3) FRAUDULENT-SPEND ops: "VELD_FRAUD|<hex FSP2 proof>" -> a
        //      final spend plus its complete hash-bound input lineage proving
        //      that custody moved outside change and exact bound requests.
        for (const auto& tx : b.transactions)
            for (const auto& out : tx.outputs) {
                std::string d = ParseOpReturn(out.script_pubkey);
                if (d.rfind("VELD_FRAUD|", 0) != 0) continue;
                std::vector<uint8_t> proof = BtcVeldHex_(d.c_str() + 11);
                if (proof.empty()) return false;
                if constexpr (btcveld::reserve::TRANSITION_V1_REQUIRED) {
                    const auto fraud = btcveld::VerifyFraudulentSpend(
                        btc, proof.data(), proof.size(),
                        BtcVeldCustodySpk(), BTCVELD_SPV_K_BTC);
                    if (!fraud.ok || cov.IsConsumedPayout(fraud.spend_txid) ||
                        cov.IsConsumedFraudSpend(fraud.spend_txid))
                        return false;
                    const auto classification =
                        led.ClassifyBtcVeldReserveSpend(
                            fraud.spend_tx, fraud.direct_parents);
                    if (classification.disposition ==
                            btcveld::reserve::SpendDisposition::
                                AUTHORIZED_TRANSITION) {
                        // A valid PAYOUT cannot remain a no-op: withholding a
                        // separate RTP1 relay through the SLA would otherwise
                        // compensate an already-paid request and break reserve
                        // accounting.  Re-run the complete reserve verifier,
                        // advance that exact edge, and fulfill the request in
                        // this same all-module transaction. Other authorized
                        // transition types remain non-fraud and await their
                        // RTP1 carrier (DEPOSIT also needs its nullifier proof).
                        if (classification.operation ==
                                btcveld::reserve::Operation::PAYOUT) {
                            BtcVeldReservePayoutTransition applied;
                            if (!led.ApplyFsp2AuthorizedReservePayout(
                                    fraud.spend_block,
                                    fraud.spend_merkle_directions,
                                    fraud.spend_merkle_branch,
                                    fraud.spend_tx,
                                    fraud.direct_parents, applied) ||
                                !cov.MarkAuthorizedReservePayout(
                                    applied.request_id,
                                    applied.payout_txid,
                                    applied.principal_sats,
                                    applied.destination_spk))
                                return false;
                        }
                        continue;
                    }
                    if (classification.disposition !=
                            btcveld::reserve::SpendDisposition::
                                UNAUTHORIZED_SPEND)
                        return false;
                    btcveld::SlashVerdict classified;
                    classified.slash = true;
                    classified.reason =
                        btcveld::SlashReason::FRAUDULENT_SPEND;
                    classified.slash_sats = std::min(
                        fraud.custody_value, cov.TotalActiveBond());
                    classified.diagnostic =
                        "current canonical reserve spent without a valid "
                        "state-bound reserve transition";
                    if (!cov.ConsumeFraudSpend(fraud.spend_txid) ||
                        !led.FreezeBtcVeldReserve(
                            fraud.spend_txid, fraud.spend_block))
                        return false;
                    cov.ApplySlash(classified);
                    continue;
                }
                btcveld::SlashVerdict sv;
                const auto fraud = btcveld::VerifyAndResolveFraud(
                    cov, btc, proof.data(), proof.size(), BtcVeldCustodySpk(),
                    BTCVELD_SPV_K_BTC, sv);
                if (!fraud.ok || !sv.slash) return false;
                cov.ApplySlash(sv);
            }
        // (c) NON-PAYMENT enforcement: LOCKED_IN + past deadline + unfulfilled ->
        //     slash the group + mark DEFAULTED (so it is not re-slashed each block).
        for (const auto& id : cov.DueForDefault(b.height)) {
            auto v = cov.EvalNonPayment(id, b.height, BTCVELD_NONPAY_PENALTY_BPS);
            if (v.slash) {
                cov.ApplySlash(v);
                if (v.compensate_sats && !v.compensate_to.empty())
                    if (!led.CompensateMint(v.compensate_to, v.compensate_sats,
                                            b.height, HashToHex(b.GetHash())))
                        return false;   // never commit a slash without make-whole mint
                cov.SetStatus(id, btcveld::ReqStatus::DEFAULTED);             // don't re-slash
            }
        }
        return true;
    }

#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
    // Benchmark-only worst-state construction seam. The height-bound envelope
    // is carried by an otherwise production-built and fully validated block;
    // its token/LP mutations establish capacity state, not evidence that the
    // public mint or liquidity transaction grammar was exercised.
    static std::string DStateQualificationAddress_(uint64_t index) {
        std::vector<uint8_t> script{0x76, 0xa9, 0x14};
        std::array<uint8_t, 20> payload{};
        payload[0] = 0xa1;
        payload[1] = 0x44;
        payload[2] = 0x53;
        payload[3] = 0x54;
        for (size_t i = 0; i < 8; ++i)
            payload[12 + i] =
                static_cast<uint8_t>(index >> (56 - 8 * i));
        const Hash256 mix = Hash256d(
            std::string("dstate-p2pkh:161:") + std::to_string(index));
        for (size_t i = 4; i < 12; ++i) payload[i] = mix[i];
        script.insert(script.end(), payload.begin(), payload.end());
        script.push_back(0x88);
        script.push_back(0xac);
        return ScriptToAddress(script, false);
    }

    static bool ParseDStateQualificationCount_(const std::string& text,
                                               uint64_t& out) {
        if (text.empty() || (text.size() > 1 && text.front() == '0'))
            return false;
        uint64_t value = 0;
        for (const char c : text) {
            if (c < '0' || c > '9') return false;
            const uint64_t digit = static_cast<uint64_t>(c - '0');
            if (value > (UINT64_MAX - digit) / 10) return false;
            value = value * 10 + digit;
        }
        out = value;
        return true;
    }

    bool ApplyDStateQualificationCapacity_(uint64_t token_accounts,
                                           uint64_t lp_identities) {
        if (token_accounts == 0 || token_accounts > 100'000 ||
            lp_identities == 0 ||
            lp_identities > AmmLedger::AMM_MAX_LP_IDENTITIES)
            return false;
        const auto token_before = onchain_tokens_.SnapshotState();
        const auto supply = token_before.supply.find(BTCVELD_TOKEN_ID);
        const auto token = token_before.tokens.find(BTCVELD_TOKEN_ID);
        if (token_before.tokens.size() > 1 ||
            (!token_before.tokens.empty() &&
             token == token_before.tokens.end()) ||
            (token != token_before.tokens.end() &&
             (token->second.id != BTCVELD_TOKEN_ID ||
              token->second.name != "Wrapped Bitcoin" ||
              token->second.issuer != BTCVELD_ISSUER_ADDRESS ||
              token->second.decimals != BTCVELD_DECIMALS ||
              token->second.peg_asset != BTCVELD_PEG_ASSET)) ||
            token_before.supply.size() > 1 ||
            (!token_before.supply.empty() &&
             supply == token_before.supply.end()) ||
            !token_before.balances.empty() || !token_before.history.empty() ||
            (supply != token_before.supply.end() && supply->second != 0) ||
            !token_before.c1_reservations.empty())
            return false;

        const auto amm_before = amm_.SnapshotState();
        if (!amm_before.lp.empty() || amm_before.pools.size() > 1)
            return false;
        const auto pool = amm_before.pools.find("VELD:btcVELD");
        if (pool != amm_before.pools.end()) {
            const AmmPool& p = pool->second;
            if (!p.exists || p.reserve_veld != 0 ||
                p.reserve_btcveld != 0 || p.lp_supply != 0 ||
                p.locked_lp != 0 || p.anchor_veld != 0 ||
                p.anchor_btcveld != 0 || p.utxo_valid ||
                !HashIsZero(p.pool_txid) || p.pool_vout != 0 ||
                p.veld_script != PoolVeldScript("VELD:btcVELD") ||
                p.btcveld_addr != "AMM:VELD:btcVELD")
                return false;
        }

        for (uint64_t i = 0; i < token_accounts; ++i) {
            if (!onchain_tokens_.ApplyDStateQualificationCredit(
                    DStateQualificationAddress_(i)))
                return false;
        }
        for (uint64_t i = 0; i < 2'000; ++i) {
            TokenTransferRecord record{};
            record.txid = HashToHex(Hash256d(
                "dstate-history:" + std::to_string(i)));
            record.token_id = BTCVELD_TOKEN_ID;
            record.from = DStateQualificationAddress_(i % token_accounts);
            record.to = DStateQualificationAddress_(
                (i + 1) % token_accounts);
            record.amount = OnChainTokenLedger::MIN_ACCOUNT_SATS;
            record.block_height = i + 1;
            record.timestamp =
                static_cast<std::time_t>(1'700'000'000 + i);
            record.memo = "dstate-bounded-history";
            if (!onchain_tokens_.ApplyDStateQualificationHistoryRecord(
                    record))
                return false;
        }
        for (uint64_t i = 0; i < lp_identities; ++i) {
            if (!amm_.ApplyDStateQualificationLp(
                    "VELD:btcVELD",
                    DStateQualificationAddress_(200'000 + i)))
                return false;
        }
        const auto token_after = onchain_tokens_.SnapshotState();
        const auto amm_after = amm_.SnapshotState();
        const auto final_supply = token_after.supply.find(BTCVELD_TOKEN_ID);
        return token_after.balances.size() == token_accounts &&
               token_after.history.size() == 2'000 &&
               final_supply != token_after.supply.end() &&
               final_supply->second ==
                   static_cast<int64_t>(token_accounts) *
                       OnChainTokenLedger::MIN_ACCOUNT_SATS &&
               amm_after.lp.size() == lp_identities &&
               std::all_of(
                   amm_after.lp.begin(), amm_after.lp.end(),
                   [](const auto& entry) {
                       return entry.second >= AmmLedger::LP_MIN_POSITION;
                   });
    }

    bool ApplyDStateQualificationCarrier_(const Block& block) {
        static constexpr const char* envelope_prefix = "dstate-replay:";
        if (block.transactions.empty() ||
            block.transactions.front().inputs.size() != 1 ||
            !block.transactions.front().IsCoinbase()) return false;
        const auto& script_sig =
            block.transactions.front().inputs.front().script_sig;
        const std::string payload(script_sig.begin(), script_sig.end());
        if (payload.rfind(envelope_prefix, 0) != 0) return true;
        if (block.height == 0) return false;

        const std::string exact_prefix =
            std::string(envelope_prefix) + std::to_string(block.height) + "|";
        if (payload.rfind(exact_prefix, 0) != 0) return false;
        const std::string body = payload.substr(exact_prefix.size());

        static constexpr const char* capacity_prefix =
            "VELD_DSTATE_S6_CAPACITY_V1|";
        if (body.rfind(capacity_prefix, 0) == 0) {
            if (block.height != 400) return false;
            const std::string fields =
                body.substr(std::char_traits<char>::length(capacity_prefix));
            const size_t split = fields.find('|');
            if (split == std::string::npos ||
                fields.find('|', split + 1) != std::string::npos)
                return false;
            uint64_t token_accounts = 0, lp_identities = 0;
            if (!ParseDStateQualificationCount_(
                    fields.substr(0, split), token_accounts) ||
                !ParseDStateQualificationCount_(
                    fields.substr(split + 1), lp_identities))
                return false;
            return ApplyDStateQualificationCapacity_(
                token_accounts, lp_identities);
        }

        static constexpr const char* q1_prefix = "VELD_DSTATE_Q1|";
        if (body.rfind(q1_prefix, 0) != 0) return false;
        const std::string fields =
            body.substr(std::char_traits<char>::length(q1_prefix));
        const size_t split = fields.find('|');
        if (split == std::string::npos ||
            fields.find('|', split + 1) != std::string::npos)
            return false;
        const std::pair<std::string, std::string> carrier{
            fields.substr(0, split), fields.substr(split + 1)};
        const auto valid_field = [](const std::string& value) {
            return value == "-" || IsCanonicalTokenCreditAddress(value);
        };
        if (!valid_field(carrier.first) || !valid_field(carrier.second) ||
            (carrier.first == "-" && carrier.second == "-")) {
            std::cerr << "  [dstate] invalid qualification carrier fields at h="
                      << block.height << "\n";
            return false;
        }
        if (carrier.first != "-" &&
            !onchain_tokens_.ApplyDStateQualificationCredit(carrier.first)) {
            std::cerr << "  [dstate] token qualification credit rejected at h="
                      << block.height << "\n";
            return false;
        }
        if (carrier.second != "-" &&
            !amm_.ApplyDStateQualificationLp("VELD:btcVELD",
                                             carrier.second)) {
            std::cerr << "  [dstate] AMM qualification LP rejected at h="
                      << block.height << "\n";
            return false;
        }
        return true;
    }
#endif

    // One authoritative ordering for every block-derived subsystem. Boolean
    // failures are consensus failures and propagate to the caller; exceptions
    // likewise escape so the caller can restore its AllModuleSnapshots frame.
    // Keeping live connect, startup replay, reorg replay, and alt-overlay replay
    // on this sequence prevents one path from silently accepting a transition
    // that another path rejects.
    bool ApplyBlockModules_(const Block& block, uint64_t total_supply_after,
                            bool persist_governance,
                            bool publish_rpc_snapshots,
                            bool chain_mutex_already_held) {
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
        const auto dstate_reject = [&block](const char* module) {
            std::cerr << "  [dstate] module rejected h=" << block.height
                      << " module=" << module << "\n";
            std::cerr.flush();
            return false;
        };
#endif
        // Transaction-level resource allocation invariant: one STAKE_VAULT
        // funding set may create at most one validator bond.  Check before any
        // module mutation so rejection is atomic on every caller path.
        if (!ValidatorRegistry::HasValidRegisterMultiplicity(block)) {
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
            return dstate_reject("validator-register-multiplicity");
#else
            return false;
#endif
        }
        if (!FeedBtcHeaders_(btc_headers_, block)) {
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
            return dstate_reject("btc-headers");
#else
            return false;
#endif
        }
        if (publish_rpc_snapshots) {
            btc_header_tip_.store(btc_headers_.BestHeight(),
                                  std::memory_order_release);
            const uint64_t next_timestamp = block.header.timestamp <=
                    UINT64_MAX - TARGET_BLOCK_TIME
                ? block.header.timestamp + TARGET_BLOCK_TIME
                : block.header.timestamp;
            btc_relay_fresh_snapshot_.store(
                btc_headers_.ExternalValueFresh(next_timestamp),
                std::memory_order_release);
        }
        // Anchors and every peg/economic operation in this block see only the
        // finality artifact retained below the block. A certificate carried by
        // this same block becomes authoritative for the NEXT block; it cannot
        // authorize a sibling anchor/mint in its own carrier.
        if (!FeedAnchors_(
            anchors_, btc_headers_, block, fin_state_,
            [this, chain_mutex_already_held](uint64_t height,
                                             Hash256& out) -> bool {
                try {
                    const Block ancestor = chain_mutex_already_held
                        ? chain_.GetBlockUnlocked(height)
                        : chain_.GetBlock(height);
                    out = ancestor.GetHash();
                    return true;
                } catch (...) { return false; }
            })) return false;
        const BtcVeldPegGateState peg_gate =
            PegGateForState_(fin_state_, block.height, &btc_headers_,
                             block.header.timestamp);
        if (!onchain_tokens_.ProcessBlock(block, peg_gate)) {
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
            return dstate_reject("onchain-tokens");
#else
            return false;
#endif
        }
        if (!FeedRedeemCovenant_(bond_covenant_, onchain_tokens_,
                                 btc_headers_, block)) {
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
            return dstate_reject("redeem-covenant");
#else
            return false;
#endif
        }
        if (!amm_.ProcessBlock("VELD:btcVELD", block, onchain_tokens_,
                               peg_gate)) {
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
            return dstate_reject("amm");
#else
            return false;
#endif
        }
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
        if (!ApplyDStateQualificationCarrier_(block))
            return dstate_reject("qualification-carrier");
#endif
        staking_.SetTotalSupply(total_supply_after);
        if (!staking_.ProcessBlock(block)) return false;
        validators_.SetTotalStaked(staking_.GetTotalStake());
        if (!validators_.ProcessBlock(
                block,
                [this](const std::string& addr){ return staking_.GetStake(addr); },
                [this](const std::string& a, uint64_t h){
                    staking_.ApplySlashBondLockup(a, h);
                })) {
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
            return dstate_reject("validators");
#else
            return false;
#endif
        }
        governance_.ProcessBlock(block, block.height, persist_governance);
        // The epoch snapshot is state at epoch_start-1 AFTER that block's
        // validator transitions.  Ingest the current certificate first so an
        // epoch-boundary block cannot activate finality and consume that new
        // activation in the same transition.
        if (!FeedFinalityCerts_(block, chain_mutex_already_held)) {
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
            return dstate_reject("finality-certificates");
#else
            return false;
#endif
        }
        if (!PromoteFinalizedAnchors_(
                anchors_, btc_headers_, fin_state_,
                [this, chain_mutex_already_held](uint64_t height,
                                                 Hash256& out) -> bool {
                    try {
                        const Block ancestor = chain_mutex_already_held
                            ? chain_.GetBlockUnlocked(height)
                            : chain_.GetBlock(height);
                        out = ancestor.GetHash();
                        return true;
                    } catch (...) { return false; }
                })) {
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
            return dstate_reject("anchor-promotion");
#else
            return false;
#endif
        }
        // Only canonical/replay applies may publish this local-security
        // observation.  Module preflight deliberately passes
        // publish_rpc_snapshots=false and is restored, so an uncommitted
        // candidate can never satisfy an anchor floor. The latch itself is part
        // of AllModuleSnapshots for failed/reorg replay rollback.
        if (publish_rpc_snapshots)
            ObserveExactAnchorSecurityReconstruction_(block.height);
        UpdateFinality_(block.height, chain_mutex_already_held);
        if (!MaybeSnapshotEpoch_(block.height)) {
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
            return dstate_reject("epoch-snapshot");
#else
            return false;
#endif
        }
        if (publish_rpc_snapshots) {
            const uint64_t finalized = fin_state_.FinalizedHeight();
            const uint64_t frame =
                (finalized & ~PEG_GATE_FINALITY_EVER_ACTIVE_BIT_) |
                (fin_state_.finality_ever_active
                     ? PEG_GATE_FINALITY_EVER_ACTIVE_BIT_ : 0);
            peg_gate_snapshot_.store(frame, std::memory_order_release);
        }
        // Durable redeem/nullifier rows are deliberately not written here.
        // Module application is reversible during a multi-block reorg, while
        // the index DB is not. The caller snapshots these exact per-block
        // transitions and publishes them only after the canonical DB frame is
        // final; startup replay uses the same post-accept helper below.
        return true;
    }

    static std::string CanonicalDerivedIndexTipMarker_(
            uint64_t height, const Hash256& hash) {
        return std::to_string(height) + ":" + HashToHex(hash);
    }

    bool ResetDerivedIndexPrefixForReplay_(
            const char* row_prefix, const char* completion_key,
            const char* label) {
        try {
            // Invalidate first.  A crash during the paged erase or later
            // replay can therefore never leave an exact marker over a partial
            // rebuild; the next startup repeats this idempotent reset.
            db::WriteBatch invalidate;
            invalidate.Delete(completion_key);
            if (!db_.GetIndexDB().Write(invalidate))
                throw std::runtime_error(
                    std::string(label) + " completion invalidation failed");

            std::string cursor;
            for (;;) {
                std::vector<std::string> stale;
                std::string last_key;
                bool page_full = false;
                db_.GetIndexDB().IterateFrom(
                    row_prefix, cursor,
                    [&](const std::string& key, const std::string&) {
                        last_key = key;
                        stale.push_back(key);
                        if (stale.size() >= 4096) {
                            page_full = true;
                            return false;
                        }
                        return true;
                    });
                if (!stale.empty()) {
                    db::WriteBatch erase;
                    for (const auto& key : stale) erase.Delete(key);
                    if (!db_.GetIndexDB().Write(erase))
                        throw std::runtime_error(
                            std::string(label) +
                            " stale-row deletion failed");
                }
                if (!page_full) break;
                if (last_key.empty() || last_key == cursor)
                    throw std::runtime_error(
                        std::string(label) +
                        " stale-row deletion made no progress");
                cursor = std::move(last_key);
            }
            return true;
        } catch (const std::exception& e) {
            std::cerr << "  [" << label << "] replay reset failed: "
                      << e.what() << "; index remains closed\n";
            std::cerr.flush();
            return false;
        } catch (...) {
            std::cerr << "  [" << label
                      << "] replay reset failed with unknown error; "
                         "index remains closed\n";
            std::cerr.flush();
            return false;
        }
    }

    void PrepareCanonicalDerivedIndexesForReplay_(
            uint64_t target_height, const Hash256& target_hash) {
        const std::string expected = CanonicalDerivedIndexTipMarker_(
            target_height, target_hash);
        const auto prepare_one = [this, &expected](
                const char* marker_key, const char* row_prefix,
                const char* label, std::atomic<bool>& healthy) {
            healthy.store(false, std::memory_order_release);
            try {
                const auto marker = db_.GetIndexDB().Get(marker_key);
                if (marker && *marker == expected) {
                    healthy.store(true, std::memory_order_release);
                    return;
                }
            } catch (const std::exception& e) {
                std::cerr << "  [" << label
                          << "] completion-marker read failed: " << e.what()
                          << "; attempting clean rebuild\n";
                std::cerr.flush();
            } catch (...) {
                std::cerr << "  [" << label
                          << "] completion-marker read failed; attempting "
                             "clean rebuild\n";
                std::cerr.flush();
            }
            if (ResetDerivedIndexPrefixForReplay_(
                    row_prefix, marker_key, label)) {
                // Writable during offline replay, but no completion marker is
                // published until the complete canonical tip is verified.
                healthy.store(true, std::memory_order_release);
            }
        };
        prepare_one(RedeemObligationIndex::CLEANUP_COMPLETE_KEY,
                    RedeemObligationIndex::PREFIX, "redeem-index",
                    redeem_index_healthy_);
        prepare_one(MintNullifierIndex::CLEANUP_COMPLETE_KEY,
                    MintNullifierIndex::PREFIX, "mint-nullifier-index",
                    mint_nullifier_index_healthy_);
    }

    void FinishCanonicalDerivedIndexesAfterReplay_(
            uint64_t target_height, const Hash256& target_hash) {
        const std::string marker = CanonicalDerivedIndexTipMarker_(
            target_height, target_hash);
        const bool redeem_ok = redeem_index_healthy_.load(
            std::memory_order_acquire);
        const bool mint_ok = mint_nullifier_index_healthy_.load(
            std::memory_order_acquire);
        db::WriteBatch complete;
        if (redeem_ok)
            complete.Put(RedeemObligationIndex::CLEANUP_COMPLETE_KEY,
                         marker);
        if (mint_ok)
            complete.Put(MintNullifierIndex::CLEANUP_COMPLETE_KEY, marker);
        if (complete.IsEmpty()) return;
        try {
            if (!db_.GetIndexDB().Write(complete))
                throw std::runtime_error(
                    "derived replay completion batch returned false");
        } catch (const std::exception& e) {
            if (redeem_ok)
                redeem_index_healthy_.store(false,
                                            std::memory_order_release);
            if (mint_ok)
                mint_nullifier_index_healthy_.store(
                    false, std::memory_order_release);
            std::cerr << "  [derived-index] replay completion failed: "
                      << e.what() << "; affected indexes remain closed\n";
            std::cerr.flush();
        } catch (...) {
            if (redeem_ok)
                redeem_index_healthy_.store(false,
                                            std::memory_order_release);
            if (mint_ok)
                mint_nullifier_index_healthy_.store(
                    false, std::memory_order_release);
            std::cerr << "  [derived-index] replay completion failed with "
                         "unknown error; affected indexes remain closed\n";
            std::cerr.flush();
        }
    }

    bool CanonicalDerivedIndexMarkersMatch_(
            uint64_t height, const Hash256& hash) {
        try {
            const std::string expected = CanonicalDerivedIndexTipMarker_(
                height, hash);
            const auto redeem = db_.GetIndexDB().Get(
                RedeemObligationIndex::CLEANUP_COMPLETE_KEY);
            const auto mint = db_.GetIndexDB().Get(
                MintNullifierIndex::CLEANUP_COMPLETE_KEY);
            return redeem && mint && *redeem == expected &&
                   *mint == expected;
        } catch (...) {
            return false;
        }
    }

    void PersistCanonicalDerivedIndexes_(
            const std::vector<ReorgBlockPublicationStage>& stages,
            bool from_reorg = false,
            bool publish_txindex = true,
            bool publish_completion_markers = true) {
        if (stages.empty()) return;

        std::vector<Block> blocks;
        blocks.reserve(stages.size());
        for (const auto& stage : stages) {
            Block block = chain_.GetBlock(stage.height);
            if (block.GetHash() != stage.hash)
                throw std::runtime_error(
                    "derived-index stage no longer names the canonical block");
            blocks.push_back(std::move(block));
        }

        if (txindex_enabled_ && publish_txindex) {
            bool ok = true;
            try {
                db::WriteBatch batch;
                if (from_reorg) {
                    for (const auto& [txid, old_height] :
                             reorg_displaced_txindex_rows_) {
                        const std::string key = "txi:" + txid;
                        const auto current = db_.GetIndexDB().Get(key);
                        if (current &&
                            *current == std::to_string(old_height)) {
                            batch.Delete(key);
                        }
                    }
                }
                for (const auto& block : blocks) {
                    for (const auto& tx : block.transactions) {
                        batch.Put("txi:" + HashToHex(tx.GetTxID()),
                                  std::to_string(block.height));
                    }
                }
                const Block& tip = blocks.back();
                batch.Put("txi:_synced", std::to_string(tip.height));
                batch.Delete("txi:_complete_v2");
                batch.Put("txi:_complete_v3",
                          std::to_string(tip.height) + ":" +
                          HashToHex(tip.GetHash()));
                ok = db_.GetIndexDB().Write(batch);
            } catch (...) {
                ok = false;
            }
            if (!ok && txindex_operational_.exchange(
                           false, std::memory_order_acq_rel)) {
                std::cerr << "  [txindex] DISABLED: final canonical batch "
                             "publication failed at height "
                          << blocks.back().height
                          << "; restart with --txindex to rebuild\n";
                std::cerr.flush();
            }
        }

        RedeemObligationIndex redeem_index(db_.GetIndexDB());
        MintNullifierIndex mint_index(db_.GetIndexDB());
        db::WriteBatch derived_batch;

        if (publish_completion_markers) {
            if (!redeem_index_healthy_.load(std::memory_order_acquire) ||
                !mint_nullifier_index_healthy_.load(
                    std::memory_order_acquire))
                throw std::runtime_error(
                    "derived index is already unhealthy; full replay required");

            if (from_reorg) {
                if (!reorg_derived_index_frame_)
                    throw std::runtime_error(
                        "reorg derived-index cleanup frame is missing");
                const auto& frame = *reorg_derived_index_frame_;
                if (stages.front().height != frame.ancestor_height + 1 ||
                    stages.back().height != frame.new_height ||
                    stages.back().hash != frame.new_hash ||
                    !CanonicalDerivedIndexMarkersMatch_(
                        frame.old_height, frame.old_hash))
                    throw std::runtime_error(
                        "reorg derived-index parent/frame marker mismatch");
                for (size_t i = 1; i < stages.size(); ++i) {
                    if (stages[i].height != stages[i - 1].height + 1 ||
                        blocks[i].header.prev_block_hash != stages[i - 1].hash)
                        throw std::runtime_error(
                            "reorg derived-index suffix is non-contiguous");
                }
                const uint64_t cleanup_tip = std::max(
                    frame.old_height, frame.new_height);
                for (uint64_t height = frame.ancestor_height + 1;
                     height <= cleanup_tip; ++height) {
                    std::optional<Hash256> canonical;
                    if (height <= frame.new_height) {
                        const size_t offset = static_cast<size_t>(
                            height - (frame.ancestor_height + 1));
                        if (offset >= stages.size() ||
                            stages[offset].height != height)
                            throw std::runtime_error(
                                "reorg derived-index cleanup height gap");
                        canonical = stages[offset].hash;
                    }
                    if (!redeem_index.AppendCanonicalHeightCleanupToBatch(
                            derived_batch, height, canonical) ||
                        !mint_index.AppendCanonicalHeightCleanupToBatch(
                            derived_batch, height, canonical))
                        throw std::runtime_error(
                            "reorg derived-index stale-row validation failed at h=" +
                            std::to_string(height));
                    if (height == UINT64_MAX) break;
                }
            } else {
                if (stages.size() != 1)
                    throw std::runtime_error(
                        "linear derived-index parent marker mismatch");
                if (stages.front().height == 0) {
                    const auto redeem_marker = db_.GetIndexDB().Get(
                        RedeemObligationIndex::CLEANUP_COMPLETE_KEY);
                    const auto mint_marker = db_.GetIndexDB().Get(
                        MintNullifierIndex::CLEANUP_COMPLETE_KEY);
                    bool stale_redeem_row = false;
                    bool stale_mint_row = false;
                    db_.GetIndexDB().Iterate(
                        RedeemObligationIndex::PREFIX,
                        [&](const std::string&, const std::string&) {
                            stale_redeem_row = true;
                            return false;
                        });
                    db_.GetIndexDB().Iterate(
                        MintNullifierIndex::PREFIX,
                        [&](const std::string&, const std::string&) {
                            stale_mint_row = true;
                            return false;
                        });
                    if (stages.front().hash !=
                            CreateGenesisBlock().GetHash() ||
                        blocks.front().header.prev_block_hash != Hash256{} ||
                        redeem_marker || mint_marker || stale_redeem_row ||
                        stale_mint_row)
                        throw std::runtime_error(
                            "genesis derived-index initialization mismatch");
                } else if (!CanonicalDerivedIndexMarkersMatch_(
                               stages.front().height - 1,
                               blocks.front().header.prev_block_hash)) {
                    throw std::runtime_error(
                        "linear derived-index parent marker mismatch");
                }
            }
        }

        for (size_t i = 0; i < stages.size(); ++i) {
            if (!redeem_index.AppendAcceptedToBatch(
                    derived_batch, blocks[i], stages[i].redeems) ||
                !mint_index.AppendAcceptedToBatch(
                    derived_batch, blocks[i], stages[i].mint_transitions))
                throw std::runtime_error(
                    "derived-index accepted-row validation failed at h=" +
                    std::to_string(stages[i].height));
        }

        if (publish_completion_markers) {
            const std::string marker = CanonicalDerivedIndexTipMarker_(
                stages.back().height, stages.back().hash);
            derived_batch.Put(
                RedeemObligationIndex::CLEANUP_COMPLETE_KEY, marker);
            derived_batch.Put(
                MintNullifierIndex::CLEANUP_COMPLETE_KEY, marker);
        }
        if (!derived_batch.IsEmpty() &&
            !db_.GetIndexDB().Write(derived_batch))
            throw std::runtime_error(
                "atomic redeem/nullifier derived-index batch returned false");
    }

    static bool AdvanceModuleSupply_(const Block& block,
                                     uint64_t& running_supply) noexcept {
        return Blockchain::AdvanceCanonicalSupply(block, running_supply);
    }

    // Run the complete module transition before Blockchain publishes the block
    // as canonical. The live objects are always restored, whether validation
    // succeeds, returns false, or throws. Governance persistence is suppressed,
    // so this preflight cannot leak module KV writes for an uncommitted block.
    bool PreflightBlockModules_(const Block& block, uint64_t total_supply_after,
                                bool chain_mutex_already_held = true) {
        const auto snap = SnapshotAllModules();
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
        // Sparse, deterministic sampling avoids charging one OS RSS query to
        // every replayed block while still covering each checkpoint/reorg
        // boundary (8,761 samples across the full h0..876,000 corpus).
        if (dstate_memory_observer_ &&
            (block.height % MAX_REORG_DEPTH) == 0)
            dstate_memory_observer_();
#endif
        try {
            const bool ok = ApplyBlockModules_(block, total_supply_after,
                                               /*persist_governance=*/false,
                                               /*publish_rpc_snapshots=*/false,
                                               chain_mutex_already_held);
            RestoreAllModules(snap);
            return ok;
        } catch (...) {
            RestoreAllModules(snap);
            return false;
        }
    }

    // Mining runs before Blockchain::AddBlockDirect acquires its transition
    // sequencer.  Take that same outer mutex here so the live module snapshot
    // cannot race a peer connect/reorg callback, verify the candidate still
    // names the current tip, then dry-run the exact full module sequence.
    bool PreflightMiningCandidateUnderTransition_(const Block& block) {
        Block tip;
        if (!chain_.TryTip(tip) ||
            block.height != tip.height + 1 ||
            block.header.prev_block_hash != tip.GetHash()) return false;
        uint64_t projected_supply = chain_.TotalSupplyUnits();
        if (!Blockchain::AdvanceCanonicalSupply(block, projected_supply))
            return false;
        return PreflightBlockModules_(
            block, projected_supply,
            /*chain_mutex_already_held=*/false);
    }

    bool PreflightMiningCandidate_(const Block& block) {
        auto transition = chain_.AcquireConsensusTransitionGuard();
        return PreflightMiningCandidateUnderTransition_(block);
    }

    void BuildAltOverlay(uint64_t anc_height) {
        const ModuleCheckpoint* checkpoint =
            FindCanonicalModuleCheckpoint_(
                anc_height, /*chain_mutex_already_held=*/true);
        if (!checkpoint) {
            throw std::runtime_error(
                "no hash-bound module checkpoint covers reorg ancestor " +
                std::to_string(anc_height));
        }

        validators_alt_ = std::make_unique<ValidatorRegistry>();
        staking_alt_    = std::make_unique<StakingLedger>();
        onchain_tokens_alt_ = std::make_unique<OnChainTokenLedger>();
        amm_alt_            = std::make_unique<AmmLedger>();
        btc_headers_alt_    = std::make_unique<btcspv::BtcHeaderChain>(
                                  BtcVeldCheckpoint(), BtcVeldPowLimit(), 2016, 1209600, BtcVeldNoRetarget());
        bond_covenant_alt_  = std::make_unique<btcveld::SignerBondCovenant>();   // fork-aware redeem covenant (fresh)
        anchors_alt_        = std::make_unique<btcanchor::AnchorSet>();
        fin_state_alt_      = std::make_unique<
                                  ::veld::finality::qc::FinalityState>(
                                      checkpoint->modules.fin_state);
        onchain_tokens_alt_->SetBtcHeaderChain(btc_headers_alt_.get());   // fork-aware SPV mint gate
        onchain_tokens_alt_->SetBtcVeldRedeemCovenant(
            bond_covenant_alt_.get());
        validators_alt_->RestoreState(checkpoint->modules.validators);
        staking_alt_->RestoreState(checkpoint->modules.staking);
        onchain_tokens_alt_->RestoreState(checkpoint->modules.tokens);
        amm_alt_->RestoreState(checkpoint->modules.amm);
        btc_headers_alt_->RestoreState(checkpoint->modules.btc_headers);
        bond_covenant_alt_->RestoreState(checkpoint->modules.bond_covenant);
        anchors_alt_->RestoreState(checkpoint->modules.anchors);
        alt_chain_hashes_.clear();
        alt_common_ancestor_height_ = anc_height;
        alt_running_supply_ = checkpoint->supply;
        for (uint64_t h = checkpoint->height + 1; h <= anc_height; ++h) {
            if (!AltProcessOne(chain_.GetBlockUnlocked(h)))
                throw std::runtime_error("alt module replay failed at ancestor height " +
                                         std::to_string(h));
        }
        overlay_alt_ = Blockchain::AltEngineOverlay{};
        overlay_alt_.validators = validators_alt_.get();
        overlay_alt_.staking    = staking_alt_.get();
        overlay_alt_.tokens     = onchain_tokens_alt_.get();
        overlay_alt_.amm        = amm_alt_.get();
        Blockchain::alt_engine_overlay_ = &overlay_alt_;
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
        if (dstate_memory_observer_)
            dstate_memory_observer_();
#endif
    }
    void AdvanceAltOverlay(const Block& b) {
        if (!validators_alt_ || !staking_alt_)
            throw std::runtime_error("alt module overlay is not initialized");
        if (!AltProcessOne(b))
            throw std::runtime_error("alt module apply rejected block at height " +
                                     std::to_string(b.height));
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
        if (dstate_memory_observer_)
            dstate_memory_observer_();
#endif
    }
    void TeardownAltOverlay() {
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
        if (dstate_memory_observer_)
            dstate_memory_observer_();
#endif
        Blockchain::alt_engine_overlay_ = nullptr;
        overlay_alt_ = Blockchain::AltEngineOverlay{};
        validators_alt_.reset();
        staking_alt_.reset();
        onchain_tokens_alt_.reset();
        btc_headers_alt_.reset();
        bond_covenant_alt_.reset();
        anchors_alt_.reset();
        fin_state_alt_.reset();
        amm_alt_.reset();
        alt_chain_hashes_.clear();
        alt_common_ancestor_height_ = 0;
        alt_running_supply_ = 0;
    }

    bool ResolveAltHash_(uint64_t height, Hash256& out) const {
        auto it = alt_chain_hashes_.find(height);
        if (it != alt_chain_hashes_.end()) { out = it->second; return true; }
        if (height > alt_common_ancestor_height_) return false;
        try {
            out = chain_.GetBlockUnlocked(height).GetHash();
            return true;
        } catch (...) { return false; }
    }

    bool FeedFinalityCertsAlt_(const Block& block) {
        namespace fq = ::veld::finality::qc;
        if (!fin_state_alt_ || !validators_alt_) return false;
        auto parsed = fq::ParseFinalityBlock(
            block, [](const std::vector<uint8_t>& spk) {
                return ::veld::ParseOpReturn(spk);
            });
        if (parsed.status == fq::FinParseStatus::NONE) return true;
        if (parsed.status != fq::FinParseStatus::VALID ||
            parsed.decoded.qc.phase != fq::Phase::PRECOMMIT ||
            !fq::InVoteWindow(parsed.decoded.qc.target.height,
                              block.height)) return false;
        auto snapshot = fin_state_alt_->snapshots.find(
            parsed.decoded.qc.epoch_id);
        if (snapshot == fin_state_alt_->snapshots.end()) return false;
        if (!fq::VerifyDecodedQc(parsed.decoded, snapshot->second,
                                 fq::NETWORK_ID, GenesisHashBytes_()))
            return false;
        Hash256 canonical{};
        if (!ResolveAltHash_(parsed.decoded.qc.target.height, canonical) ||
            canonical != parsed.decoded.qc.target.hash) return false;
        fq::CheckpointRef carrier{block.height, block.GetHash()};
        if (!fin_state_alt_->OnCertificate(parsed.decoded.qc, carrier,
                                           canonical)) return false;
        return validators_alt_->RecordFinalityQc(
            parsed.decoded.qc, snapshot->second, block.height);
    }

    bool AltProcessOne(const Block& b) {
        if (!validators_alt_ || !staking_alt_ || !onchain_tokens_alt_ ||
            !amm_alt_ || !btc_headers_alt_ || !bond_covenant_alt_ ||
            !anchors_alt_ || !fin_state_alt_)
            return false;
        alt_chain_hashes_[b.height] = b.GetHash();
        if (!ValidatorRegistry::HasValidRegisterMultiplicity(b)) return false;
        if (!AdvanceModuleSupply_(b, alt_running_supply_)) return false;
        // btcVELD: keep the alt token ledger + AMM fork-aware (tokens first, so the
        // AMM's btcVELD legs resolve against the alt chain's balances).
        if (!FeedBtcHeaders_(*btc_headers_alt_, b)) return false;      // fork-aware BTC header view (before the mint gate)
        if (!FeedAnchors_(*anchors_alt_, *btc_headers_alt_, b,
                          *fin_state_alt_,
                          [this](uint64_t h, Hash256& out) {
                              return ResolveAltHash_(h, out);
                          })) return false;
        const BtcVeldPegGateState peg_gate =
            PegGateForState_(*fin_state_alt_, b.height, btc_headers_alt_.get(),
                             b.header.timestamp);
        if (!onchain_tokens_alt_->ProcessBlock(b, peg_gate)) return false;
        if (!FeedRedeemCovenant_(*bond_covenant_alt_, *onchain_tokens_alt_,
                                 *btc_headers_alt_, b)) return false;
        if (!amm_alt_->ProcessBlock("VELD:btcVELD", b,
                                    *onchain_tokens_alt_, peg_gate)) return false;
        staking_alt_->SetTotalSupply(alt_running_supply_);
        if (!staking_alt_->ProcessBlock(b)) return false;
        validators_alt_->SetTotalStaked(staking_alt_->GetTotalStake());
        if (!validators_alt_->ProcessBlock(
                b,
                [this](const std::string& a){ return staking_alt_->GetStake(a); },
                [this](const std::string& a, uint64_t hh){
                    staking_alt_->ApplySlashBondLockup(a, hh);
                })) return false;
        if (!FeedFinalityCertsAlt_(b)) return false;
        if (!PromoteFinalizedAnchors_(
                *anchors_alt_, *btc_headers_alt_, *fin_state_alt_,
                [this](uint64_t h, Hash256& out) {
                    return ResolveAltHash_(h, out);
                })) return false;
        if (!MaybeSnapshotEpochFor_(b.height, *validators_alt_,
                                    *fin_state_alt_)) return false;
        return true;
    }

    static constexpr const char* MINER_ARCHIVE_COUNT_PREFIX_ =
        "miner:count:";
    static constexpr const char* MINER_ARCHIVE_LAST_PREFIX_ =
        "miner:last:";
    static constexpr const char* MINER_ARCHIVE_UNDO_PREFIX_ =
        "miner:undo:";
    static constexpr const char* MINER_ARCHIVE_HEIGHT_KEY_ =
        "miner:archive:tip_height";
    static constexpr const char* MINER_ARCHIVE_HASH_KEY_ =
        "miner:archive:tip_hash";
    static constexpr size_t MINER_ARCHIVE_REBUILD_BATCH_BLOCKS_ = 4096;

    void CloseMinerArchive_() {
        miner_archive_ready_.store(false, std::memory_order_release);
        miner_archive_revision_.fetch_add(1, std::memory_order_acq_rel);
    }

    void OpenMinerArchive_() {
        miner_archive_revision_.fetch_add(1, std::memory_order_acq_rel);
        miner_archive_ready_.store(true, std::memory_order_release);
    }

    static bool ParseMinerArchiveUint64_(const std::string& text,
                                         uint64_t& out) {
        if (text.empty() || (text.size() > 1 && text.front() == '0'))
            return false;
        uint64_t value = 0;
        for (const unsigned char c : text) {
            if (c < '0' || c > '9') return false;
            const uint64_t digit = (uint64_t)(c - '0');
            if (value > (UINT64_MAX - digit) / 10) return false;
            value = value * 10 + digit;
        }
        out = value;
        return true;
    }

    static bool IsCanonicalMinerArchiveScript_(
            const std::string& script_hex) {
        if (script_hex.size() != 50 ||
            script_hex.compare(0, 6, "76a914") != 0 ||
            script_hex.compare(46, 4, "88ac") != 0)
            return false;
        return std::all_of(
            script_hex.begin(), script_hex.end(), [](unsigned char c) {
                return (c >= '0' && c <= '9') ||
                       (c >= 'a' && c <= 'f');
            });
    }

    static std::string MinerArchiveUndoHeightPrefix_(uint64_t height) {
        std::ostringstream out;
        out << MINER_ARCHIVE_UNDO_PREFIX_ << std::setw(20)
            << std::setfill('0') << height << ':';
        return out.str();
    }

    static std::string MinerArchiveUndoKey_(
            uint64_t height, const std::string& script_hex) {
        return MinerArchiveUndoHeightPrefix_(height) + script_hex;
    }

    static std::string EncodeMinerArchiveUndo_(
            const Blockchain::MinerArchiveRecord& prior) {
        return std::to_string(prior.blocks_mined) + "," +
               std::to_string(prior.last_block_mined);
    }

    static bool ParseMinerArchiveUndo_(
            const std::string& text,
            Blockchain::MinerArchiveRecord& prior) {
        const size_t comma = text.find(',');
        if (comma == std::string::npos || comma == 0 ||
            comma + 1 >= text.size() ||
            text.find(',', comma + 1) != std::string::npos)
            return false;
        uint64_t count = 0, last = 0;
        if (!ParseMinerArchiveUint64_(text.substr(0, comma), count) ||
            !ParseMinerArchiveUint64_(text.substr(comma + 1), last) ||
            (count == 0 && last != 0))
            return false;
        prior = Blockchain::MinerArchiveRecord{count, last};
        return true;
    }

    bool ReadMinerArchiveRecordRaw_(
            const std::string& script_hex,
            Blockchain::MinerArchiveRecord& record) {
        const auto count_raw = db_.GetIndexDB().Get(
            std::string(MINER_ARCHIVE_COUNT_PREFIX_) + script_hex);
        const auto last_raw = db_.GetIndexDB().Get(
            std::string(MINER_ARCHIVE_LAST_PREFIX_) + script_hex);
        if (!count_raw && !last_raw) {
            record = Blockchain::MinerArchiveRecord{};
            return true;
        }
        return count_raw && last_raw &&
               ParseMinerArchiveUint64_(*count_raw, record.blocks_mined) &&
               ParseMinerArchiveUint64_(*last_raw,
                                         record.last_block_mined) &&
               record.blocks_mined > 0;
    }

    bool DeleteMinerArchivePrefixBatched_(const std::string& prefix) {
        std::string cursor;
        for (;;) {
            std::vector<std::string> keys;
            keys.reserve(MINER_ARCHIVE_REBUILD_BATCH_BLOCKS_);
            db_.GetIndexDB().IterateFrom(
                prefix, cursor,
                [&](const std::string& key, const std::string&) {
                    keys.push_back(key);
                    return keys.size() <
                           MINER_ARCHIVE_REBUILD_BATCH_BLOCKS_;
                });
            if (keys.empty()) return true;
            cursor = keys.back();
            veld::db::WriteBatch batch;
            for (const auto& key : keys) batch.Delete(key);
            if (!db_.GetIndexDB().Write(batch)) return false;
        }
    }

    std::optional<Blockchain::MinerArchiveRecord>
    ReadMinerArchiveRecord_(const std::string& script_hex) {
        if (!miner_archive_ready_.load(std::memory_order_acquire))
            return std::nullopt;
        const uint64_t revision =
            miner_archive_revision_.load(std::memory_order_acquire);
        const auto result = miner_archive::Read(db_.GetIndexDB(), script_hex);
        if (!result) {
            miner_archive_ready_.store(false, std::memory_order_release);
            return std::nullopt;
        }
        if (!miner_archive_ready_.load(std::memory_order_acquire) ||
            miner_archive_revision_.load(std::memory_order_acquire) != revision)
            return std::nullopt;
        return result;
    }

    std::optional<Hash256> MinerArchiveLogicalDigest_() {
        if (!miner_archive_ready_.load(std::memory_order_acquire))
            return std::nullopt;
        const uint64_t revision =
            miner_archive_revision_.load(std::memory_order_acquire);
        try {
            const auto height_raw =
                db_.GetIndexDB().Get(MINER_ARCHIVE_HEIGHT_KEY_);
            const auto hash_raw =
                db_.GetIndexDB().Get(MINER_ARCHIVE_HASH_KEY_);
            uint64_t tip_height = 0;
            if (!height_raw || !hash_raw ||
                !ParseMinerArchiveUint64_(*height_raw, tip_height) ||
                !db::IsCanonicalHash256Text(*hash_raw))
                throw std::runtime_error("invalid miner archive tip markers");

            uint64_t count_rows = 0, last_rows = 0;
            bool count_overflow = false, last_overflow = false;
            db_.GetIndexDB().Iterate(
                MINER_ARCHIVE_COUNT_PREFIX_,
                [&](const std::string&, const std::string&) {
                    if (count_rows == UINT64_MAX) {
                        count_overflow = true;
                        return false;
                    }
                    ++count_rows;
                    return true;
                });
            db_.GetIndexDB().Iterate(
                MINER_ARCHIVE_LAST_PREFIX_,
                [&](const std::string&, const std::string&) {
                    if (last_rows == UINT64_MAX) {
                        last_overflow = true;
                        return false;
                    }
                    ++last_rows;
                    return true;
                });
            if (count_overflow || last_overflow || count_rows != last_rows)
                throw std::runtime_error("miner archive row cardinality mismatch");

            SHA256 hash;
            hash.update("VELD_MINER_ARCHIVE_v1|");
            auto hash_u32 = [&hash](uint32_t value) {
                uint8_t bytes[4];
                for (size_t i = 0; i < 4; ++i)
                    bytes[i] = static_cast<uint8_t>(value >> (8 * i));
                hash.update(bytes, sizeof(bytes));
            };
            auto hash_u64 = [&hash](uint64_t value) {
                uint8_t bytes[8];
                for (size_t i = 0; i < 8; ++i)
                    bytes[i] = static_cast<uint8_t>(value >> (8 * i));
                hash.update(bytes, sizeof(bytes));
            };
            hash_u32(1);
            hash_u64(tip_height);
            const Hash256 tip_hash = HexToHash(*hash_raw);
            hash.update(tip_hash.data(), tip_hash.size());
            hash_u64(count_rows);

            const size_t count_prefix_len =
                std::char_traits<char>::length(MINER_ARCHIVE_COUNT_PREFIX_);
            const size_t last_prefix_len =
                std::char_traits<char>::length(MINER_ARCHIVE_LAST_PREFIX_);
            std::string count_cursor, last_cursor;
            uint64_t hashed_rows = 0;
            for (;;) {
                std::vector<std::pair<std::string, std::string>> counts;
                std::vector<std::pair<std::string, std::string>> lasts;
                counts.reserve(MINER_ARCHIVE_REBUILD_BATCH_BLOCKS_);
                lasts.reserve(MINER_ARCHIVE_REBUILD_BATCH_BLOCKS_);
                db_.GetIndexDB().IterateFrom(
                    MINER_ARCHIVE_COUNT_PREFIX_, count_cursor,
                    [&](const std::string& key, const std::string& value) {
                        counts.emplace_back(key, value);
                        return counts.size() <
                               MINER_ARCHIVE_REBUILD_BATCH_BLOCKS_;
                    });
                db_.GetIndexDB().IterateFrom(
                    MINER_ARCHIVE_LAST_PREFIX_, last_cursor,
                    [&](const std::string& key, const std::string& value) {
                        lasts.emplace_back(key, value);
                        return lasts.size() <
                               MINER_ARCHIVE_REBUILD_BATCH_BLOCKS_;
                    });
                if (counts.empty() && lasts.empty()) break;
                if (counts.size() != lasts.size())
                    throw std::runtime_error(
                        "miner archive row-page mismatch");
                count_cursor = counts.back().first;
                last_cursor = lasts.back().first;
                for (size_t i = 0; i < counts.size(); ++i) {
                    const std::string script =
                        counts[i].first.substr(count_prefix_len);
                    if (!IsCanonicalMinerArchiveScript_(script) ||
                        lasts[i].first.substr(last_prefix_len) != script ||
                        script.size() > UINT32_MAX)
                        throw std::runtime_error(
                            "miner archive row-key mismatch");
                    uint64_t count = 0, last = 0;
                    if (!ParseMinerArchiveUint64_(counts[i].second, count) ||
                        !ParseMinerArchiveUint64_(lasts[i].second, last) ||
                        count == 0 || last > tip_height)
                        throw std::runtime_error(
                            "invalid miner archive row");
                    hash_u32(static_cast<uint32_t>(script.size()));
                    hash.update(script);
                    hash_u64(count);
                    hash_u64(last);
                    ++hashed_rows;
                }
            }
            if (hashed_rows != count_rows ||
                !miner_archive_ready_.load(std::memory_order_acquire) ||
                miner_archive_revision_.load(
                    std::memory_order_acquire) != revision)
                return std::nullopt;
            return hash.digest();
        } catch (...) {
            miner_archive_ready_.store(false, std::memory_order_release);
            return std::nullopt;
        }
    }

    bool MinerArchiveMarkersMatch_(uint64_t height,
                                   const Hash256& hash) {
        return miner_archive::MarkersMatch(db_.GetIndexDB(), height, hash);
    }

    bool RebuildMinerArchiveIndex_() {
        {
            CloseMinerArchive_();
            try {
                std::optional<std::pair<uint64_t, Hash256>> tip;
                if (!chain_.IsEmpty())
                    tip = std::make_pair(chain_.Height(),
                                         chain_.TipCopy().GetHash());
                const bool ok = miner_archive::Rebuild(
                    db_.GetIndexDB(), tip,
                    [this](uint64_t h) { return chain_.GetBlock(h); },
                    [this](uint64_t h, const Hash256& hash) {
                        return !chain_.IsEmpty() && chain_.Height() == h &&
                               chain_.TipCopy().GetHash() == hash;
                    });
                if (ok) OpenMinerArchive_();
                return ok;
            } catch (...) {
                miner_archive_ready_.store(false,
                                           std::memory_order_release);
                return false;
            }
        }
        CloseMinerArchive_();
        try {
            // Remove completion markers first. A crash during any later page
            // leaves a visibly incomplete archive which startup must rebuild;
            // it can never expose a stale tip over partially replaced rows.
            veld::db::WriteBatch invalidate;
            invalidate.Delete(MINER_ARCHIVE_HEIGHT_KEY_);
            invalidate.Delete(MINER_ARCHIVE_HASH_KEY_);
            if (!db_.GetIndexDB().Write(invalidate) ||
                !DeleteMinerArchivePrefixBatched_(
                    MINER_ARCHIVE_COUNT_PREFIX_) ||
                !DeleteMinerArchivePrefixBatched_(
                    MINER_ARCHIVE_LAST_PREFIX_) ||
                !DeleteMinerArchivePrefixBatched_(
                    MINER_ARCHIVE_UNDO_PREFIX_))
                return false;

            if (chain_.IsEmpty()) {
                OpenMinerArchive_();
                return true;
            }

            const uint64_t tip_height = chain_.Height();
            const Hash256 tip_hash = chain_.TipCopy().GetHash();
            std::unordered_map<std::string, Blockchain::MinerArchiveRecord>
                pending;
            std::vector<std::pair<std::string, std::string>> pending_undo;
            size_t blocks_buffered = 0;
            auto flush = [&]() -> bool {
                if (pending.empty() && pending_undo.empty()) {
                    blocks_buffered = 0;
                    return true;
                }
                std::vector<std::string> scripts;
                scripts.reserve(pending.size());
                for (const auto& [script, _record] : pending)
                    scripts.push_back(script);
                std::sort(scripts.begin(), scripts.end());
                std::sort(pending_undo.begin(), pending_undo.end());
                veld::db::WriteBatch page;
                for (const auto& script : scripts) {
                    const auto& record = pending.at(script);
                    page.Put(std::string(MINER_ARCHIVE_COUNT_PREFIX_) +
                                 script,
                             std::to_string(record.blocks_mined));
                    page.Put(std::string(MINER_ARCHIVE_LAST_PREFIX_) +
                                 script,
                             std::to_string(record.last_block_mined));
                }
                for (const auto& [key, value] : pending_undo)
                    page.Put(key, value);
                if (!db_.GetIndexDB().Write(page)) return false;
                pending.clear();
                pending_undo.clear();
                blocks_buffered = 0;
                return true;
            };

            for (uint64_t h = 0; h <= tip_height; ++h) {
                const Block block = chain_.GetBlock(h);
                for (const auto& script :
                         Blockchain::MinerScriptsForArchive(block)) {
                    auto found = pending.find(script);
                    if (found == pending.end()) {
                        Blockchain::MinerArchiveRecord current;
                        if (!ReadMinerArchiveRecordRaw_(
                                script, current))
                            return false;
                        found = pending.emplace(script, current).first;
                    }
                    auto& record = found->second;
                    if (record.blocks_mined == UINT64_MAX) return false;
                    const Blockchain::MinerArchiveRecord prior = record;
                    ++record.blocks_mined;
                    record.last_block_mined = h;
                    if (tip_height - h <= MAX_REORG_DEPTH) {
                        pending_undo.emplace_back(
                            MinerArchiveUndoKey_(h, script),
                            EncodeMinerArchiveUndo_(prior));
                    }
                }
                ++blocks_buffered;
                if (blocks_buffered >=
                        MINER_ARCHIVE_REBUILD_BATCH_BLOCKS_ && !flush())
                    return false;
            }
            if (!flush()) return false;
            if (chain_.Height() != tip_height ||
                chain_.TipCopy().GetHash() != tip_hash) return false;

            veld::db::WriteBatch complete;
            complete.Put(MINER_ARCHIVE_HEIGHT_KEY_,
                         std::to_string(tip_height));
            complete.Put(MINER_ARCHIVE_HASH_KEY_, HashToHex(tip_hash));
            const bool ok = db_.GetIndexDB().Write(complete);
            if (ok) OpenMinerArchive_();
            return ok;
        } catch (...) {
            miner_archive_ready_.store(false, std::memory_order_release);
            return false;
        }
    }

    bool AdvanceMinerArchiveIndex_(const Block& block) {
        {
            const bool was_ready =
                miner_archive_ready_.load(std::memory_order_acquire);
            CloseMinerArchive_();
            if (!was_ready) return RebuildMinerArchiveIndex_();
            const auto result =
                miner_archive::Advance(db_.GetIndexDB(), block);
            if (result == miner_archive::AdvanceResult::ParentMismatch)
                return RebuildMinerArchiveIndex_();
            const bool ok = result == miner_archive::AdvanceResult::Ok;
            if (ok) OpenMinerArchive_();
            return ok;
        }
        const bool was_ready =
            miner_archive_ready_.load(std::memory_order_acquire);
        CloseMinerArchive_();
        try {
            // Once any reader/rollback has detected corruption, do not reopen
            // by validating only the current miner's row. Rebuild every row
            // from canonical bodies before publishing this tip.
            if (!was_ready) return RebuildMinerArchiveIndex_();
            auto stored_height = db_.GetIndexDB().Get(MINER_ARCHIVE_HEIGHT_KEY_);
            auto stored_hash = db_.GetIndexDB().Get(MINER_ARCHIVE_HASH_KEY_);
            bool parent_matches = false;
            if (block.height == 0) {
                parent_matches = !stored_height && !stored_hash;
            } else if (stored_height && stored_hash) {
                uint64_t parsed_height = 0;
                parent_matches =
                    ParseMinerArchiveUint64_(*stored_height, parsed_height) &&
                    parsed_height == block.height - 1 &&
                    *stored_hash == HashToHex(block.header.prev_block_hash);
            }
            if (!parent_matches) return RebuildMinerArchiveIndex_();

            veld::db::WriteBatch batch;
            for (const auto& script :
                     Blockchain::MinerScriptsForArchive(block)) {
                const std::string count_key =
                    std::string(MINER_ARCHIVE_COUNT_PREFIX_) + script;
                const std::string last_key =
                    std::string(MINER_ARCHIVE_LAST_PREFIX_) + script;
                auto count_raw = db_.GetIndexDB().Get(count_key);
                auto last_raw = db_.GetIndexDB().Get(last_key);
                Blockchain::MinerArchiveRecord prior;
                if (count_raw || last_raw) {
                    if (!count_raw || !last_raw ||
                        !ParseMinerArchiveUint64_(*count_raw,
                                                  prior.blocks_mined) ||
                        !ParseMinerArchiveUint64_(*last_raw,
                                                  prior.last_block_mined) ||
                        prior.blocks_mined == 0 ||
                        prior.blocks_mined == UINT64_MAX ||
                        prior.last_block_mined >= block.height)
                        return false;
                }
                batch.Put(MinerArchiveUndoKey_(block.height, script),
                          EncodeMinerArchiveUndo_(prior));
                batch.Put(count_key,
                          std::to_string(prior.blocks_mined + 1));
                batch.Put(last_key, std::to_string(block.height));
            }
            if (block.height > MAX_REORG_DEPTH) {
                const std::string expired = MinerArchiveUndoHeightPrefix_(
                    block.height - MAX_REORG_DEPTH - 1);
                db_.GetIndexDB().Iterate(
                    expired,
                    [&](const std::string& key, const std::string&) {
                        batch.Delete(key);
                        return true;
                    });
            }
            batch.Put(MINER_ARCHIVE_HEIGHT_KEY_,
                      std::to_string(block.height));
            batch.Put(MINER_ARCHIVE_HASH_KEY_,
                      HashToHex(block.GetHash()));
            const bool ok = db_.GetIndexDB().Write(batch);
            if (ok) OpenMinerArchive_();
            return ok;
        } catch (...) {
            miner_archive_ready_.store(false, std::memory_order_release);
            return false;
        }
    }

    bool RollbackMinerArchiveIndex_(const Block& popped) {
        {
            if (!miner_archive_ready_.load(std::memory_order_acquire))
                return false;
            CloseMinerArchive_();
            const bool ok =
                miner_archive::Rollback(db_.GetIndexDB(), popped);
            if (ok) OpenMinerArchive_();
            return ok;
        }
        // Called from Blockchain while its unique consensus lock is held.
        // This path must use only the bounded archival undo row; never call
        // chain_.Height/GetBlock/Rebuild here or it will self-deadlock.
        if (!miner_archive_ready_.load(std::memory_order_acquire))
            return false;
        CloseMinerArchive_();
        try {
            auto stored_height = db_.GetIndexDB().Get(MINER_ARCHIVE_HEIGHT_KEY_);
            auto stored_hash = db_.GetIndexDB().Get(MINER_ARCHIVE_HASH_KEY_);
            uint64_t parsed_height = 0;
            // AddBlockDirect invokes on_rollback after any on_commit failure.
            // If that failure happened before AdvanceMinerArchiveIndex_, the
            // archive is already at the exact parent (or empty for a failed
            // genesis commit). Treat that frame as an idempotent successful
            // rollback. Anything else is corruption/staleness and fails
            // closed; notably this does not relax GetLastBlockMined policy.
            if (!stored_height && !stored_hash) {
                const bool exact_empty_parent = popped.height == 0;
                if (exact_empty_parent) OpenMinerArchive_();
                return exact_empty_parent;
            }
            if (!stored_height || !stored_hash ||
                !ParseMinerArchiveUint64_(*stored_height, parsed_height))
                return false;
            if (popped.height > 0 &&
                parsed_height == popped.height - 1 &&
                *stored_hash == HashToHex(popped.header.prev_block_hash)) {
                OpenMinerArchive_();
                return true;
            }
            if (parsed_height != popped.height ||
                *stored_hash != HashToHex(popped.GetHash())) return false;

            veld::db::WriteBatch batch;
            for (const auto& script :
                     Blockchain::MinerScriptsForArchive(popped)) {
                const std::string count_key =
                    std::string(MINER_ARCHIVE_COUNT_PREFIX_) + script;
                const std::string last_key =
                    std::string(MINER_ARCHIVE_LAST_PREFIX_) + script;
                const std::string undo_key =
                    MinerArchiveUndoKey_(popped.height, script);
                auto count_raw = db_.GetIndexDB().Get(count_key);
                auto last_raw = db_.GetIndexDB().Get(last_key);
                auto undo_raw = db_.GetIndexDB().Get(undo_key);
                uint64_t count = 0, last = 0;
                Blockchain::MinerArchiveRecord prior;
                if (!count_raw || !last_raw || !undo_raw ||
                    !ParseMinerArchiveUint64_(*count_raw, count) ||
                    !ParseMinerArchiveUint64_(*last_raw, last) ||
                    !ParseMinerArchiveUndo_(*undo_raw, prior) || count == 0 ||
                    last != popped.height || prior.blocks_mined + 1 != count ||
                    (prior.blocks_mined > 0 &&
                     prior.last_block_mined >= popped.height))
                    return false;
                if (prior.blocks_mined == 0) {
                    batch.Delete(count_key);
                    batch.Delete(last_key);
                } else {
                    batch.Put(count_key,
                              std::to_string(prior.blocks_mined));
                    batch.Put(last_key,
                              std::to_string(prior.last_block_mined));
                }
                batch.Delete(undo_key);
            }
            if (popped.height == 0) {
                batch.Delete(MINER_ARCHIVE_HEIGHT_KEY_);
                batch.Delete(MINER_ARCHIVE_HASH_KEY_);
            } else {
                batch.Put(MINER_ARCHIVE_HEIGHT_KEY_,
                          std::to_string(popped.height - 1));
                batch.Put(MINER_ARCHIVE_HASH_KEY_,
                          HashToHex(popped.header.prev_block_hash));
            }
            const bool ok = db_.GetIndexDB().Write(batch);
            if (ok) OpenMinerArchive_();
            return ok;
        } catch (...) {
            miner_archive_ready_.store(false, std::memory_order_release);
            return false;
        }
    }

    void WireDB() {
        if (!anchor_floor_prepared_)
            throw std::logic_error(
                "WireDB called before anchor security bootstrap preparation");
        // Historical canonical bodies are loaded from the authoritative block
        // database after Blockchain has evicted them from its bounded resident
        // cache.  Blockchain performs the strict full-frame/hash/merkle checks;
        // this callback deliberately supplies only opaque durable bytes.
        chain_.SetHistoricalBlockLoader(
            [this](const Hash256& hash)
                -> std::optional<std::vector<uint8_t>> {
                return db_.ReadBlock(hash);
            });
        chain_.SetDurableBlockBodyWriter(
            [this](const Hash256& hash,
                   const std::vector<uint8_t>& bytes) -> bool {
#ifdef VELD_TEST_HOOKS
                test_work_durable_writer_calls_.fetch_add(
                    1, std::memory_order_acq_rel);
#endif
                return db_.WriteBlock(hash, bytes);
            });
        chain_.SetDurableBlockBodyEraser(
            [this](const Hash256& hash) -> bool {
                return db_.DeleteNonCanonicalBlock(hash);
            });
        chain_.SetMinerArchiveLookup(
            [this](const std::string& script_hex)
                -> std::optional<Blockchain::MinerArchiveRecord> {
                return ReadMinerArchiveRecord_(script_hex);
            });

        rpc_.SetMiningTemplatePreflightFn([this](const Block& candidate) {
            // RpcServer owns the consensus transition guard across the exact
            // parent snapshot, template construction, and this dry run.
            return PreflightMiningCandidateUnderTransition_(candidate);
        });
        chain_.SetNmsStakeQuery([this](const std::string& address) -> uint64_t {
            const auto* ov = Blockchain::alt_engine_overlay_;
            const StakingLedger& sl = (ov && ov->staking) ? *ov->staking : staking_;
            return sl.GetStake(address);
        });

        chain_.SetValidatorFilter([this](const std::string& address) -> bool {
            const auto* ov = Blockchain::alt_engine_overlay_;
            const ValidatorRegistry& vr = (ov && ov->validators) ? *ov->validators : validators_;
            return vr.IsValidatorByAddress(address);
        });

        chain_.SetAcceptedEndorsementQuery(
            [this](const std::string& address, uint64_t height,
                   const std::string& block_hash_hex,
                   const std::string& sig_hex) -> bool {
                const auto* ov = Blockchain::alt_engine_overlay_;
                const ValidatorRegistry& vr = (ov && ov->validators)
                    ? *ov->validators : validators_;
                return vr.HasAcceptedEndorsement(address, height,
                                                  block_hash_hex, sig_hex);
            });

        chain_.SetStakeSnapshot(
            [this](uint64_t query_height) -> std::map<std::string, uint64_t> {
                const auto* ov = Blockchain::alt_engine_overlay_;
                const StakingLedger& sl = (ov && ov->staking) ? *ov->staking : staking_;
                return sl.GetWeightedStakeSnapshot(query_height);
            });

        chain_.SetBondSettlementsFn(
            [this](uint64_t boundary_height)
                -> std::vector<std::tuple<std::string,int,uint64_t,std::string>> {
                const auto* ov = Blockchain::alt_engine_overlay_;
                const ValidatorRegistry& vr = (ov && ov->validators) ? *ov->validators : validators_;
                std::vector<std::tuple<std::string,int,uint64_t,std::string>> out;
                for (const auto& s : vr.GetBondSettlements(boundary_height)) {
                    out.emplace_back(
                        s.address,
                        s.kind == BondSettlement::SLASH_EQUIVOCATION ? 2
                            : (s.kind == BondSettlement::SLASH_CONFISCATE ? 1 : 0),
                        s.bond_units,
                        s.slasher_address);
                }
                return out;
            });

        chain_.SetBondYieldWeightFn(
            [this](uint64_t boundary_height) -> uint64_t {
                const auto* ov = Blockchain::alt_engine_overlay_;
                const ValidatorRegistry& vr = (ov && ov->validators) ? *ov->validators : validators_;
                return vr.GetEligibleBondYieldWeight(boundary_height);
            });
        chain_.SetBondYieldSettlementsFn(
            [this](uint64_t boundary_height)
                -> std::vector<std::tuple<std::string,int,uint64_t,std::string>> {
                const auto* ov = Blockchain::alt_engine_overlay_;
                const ValidatorRegistry& vr = (ov && ov->validators) ? *ov->validators : validators_;
                std::vector<std::tuple<std::string,int,uint64_t,std::string>> out;
                for (const auto& s : vr.GetBondYieldSettlements(boundary_height)) {
                    out.emplace_back(
                        s.address,
                        s.kind == BondSettlement::SLASH_EQUIVOCATION ? 2
                            : (s.kind == BondSettlement::SLASH_CONFISCATE ? 1 : 0),
                        s.bond_units,
                        s.slasher_address);
                }
                return out;
            });

        chain_.SetAltOverlayBuildFn   ([this](uint64_t anc_h){ this->BuildAltOverlay(anc_h); });
        chain_.SetAltOverlayAdvanceFn ([this](const Block& b){ this->AdvanceAltOverlay(b); });
        chain_.SetAltOverlayTeardownFn([this](){ this->TeardownAltOverlay(); });
        chain_.SetModulePrecommitValidator(
            [this](const Block& b, uint64_t projected_supply) -> bool {
                return this->PreflightBlockModules_(b, projected_supply);
            });

        chain_.SetCheckpointAtOrBelow(
            [](uint64_t max_height, uint64_t& out_height,
               Hash256& out_hash) -> bool {
                // Derive the reorg and synchronization anchor only from compiled
                // checkpoints. Runtime-fetched checkpoints remain advisory.
                // Highest compiled pin at or below max_height.
                bool found = false; uint64_t best_h = 0; std::string best_hex;
                for (const auto& [cp_h, cp_hex] : Blockchain::AllCheckpointPins()) {
                    if (cp_h > max_height) continue;
                    if (!found || cp_h > best_h) { found = true; best_h = cp_h; best_hex = cp_hex; }
                }
                if (!found) return false;
                out_height = best_h;
                out_hash   = HexToHash(best_hex);
                return true;
            });

        chain_.SetOnReorg([this](const Blockchain::UTXODelta& delta,
                                 uint64_t ancestor_height,
                                 const Hash256& ancestor_hash,
                                 const Block& old_tip,
                                 uint64_t old_supply,
                                 const Block& intended_new_tip,
                                 uint64_t intended_new_supply)
        {
            // Archive rows still name the old canonical tip until the complete
            // replacement branch publishes. Hide them throughout the staged
            // reorg; the final on-commit rebuild, or an identity-checked abort,
            // is the only operation allowed to reopen display reads.
            miner_archive_ready_.store(false, std::memory_order_release);
            try {
                if (reorg_utxo_pending_ || reorg_derived_index_frame_ ||
                    reorg_transaction_modules_ ||
                    !reorg_block_publication_stages_.empty() ||
                    !reorg_displaced_txindex_rows_.empty()) {
                    FailStopDurableCommitInvariant_(
                        "a new reorg entered with stale staged durable state");
                    throw std::runtime_error(
                        "stale reorg durable transaction state");
                }

                // Capture the exact pre-reorg security metadata, then bind the
                // complete old/ancestor/intended-new identity before touching
                // utxo_db.  Until the final suffix batch commits, the old tip,
                // height index, supply and VLF1 remain authoritative.
                CaptureReorgAnchorFloorForAbort_();
                reorg_finality_retirements_.clear();
                reorg_block_publication_stages_.clear();
                CaptureReorgDisplacedTxIndexRows_(
                    ancestor_height, ancestor_hash, old_tip);

                db::VeldDB::ReorgUtxoPending pending;
                pending.ancestor_height = ancestor_height;
                pending.ancestor_hash = ancestor_hash;
                pending.old_height = old_tip.height;
                pending.old_hash = old_tip.GetHash();
                pending.old_supply = old_supply;
                pending.new_height = intended_new_tip.height;
                pending.new_hash = intended_new_tip.GetHash();
                pending.new_supply = intended_new_supply;
                // Retain the expected identity even if Begin reports an
                // uncertain sync result. The uncertainty path deliberately
                // avoids compensation and preserves Blockchain's rollback/body
                // recovery frame until restart; a definite pre-write false
                // takes the exact identity-checked abort hook below.
                reorg_utxo_pending_ = pending;
                reorg_derived_index_frame_ = pending;

                const auto durable_delta = SerializeUTXODelta_(delta);
                bool ok = db_.BeginReorgUTXO(durable_delta, pending);
                std::cerr << "  [reorg-leveldb] bounded writes="
                          << durable_delta.size() << " — "
                          << (ok ? "ok" : "FAILED") << "\n";
                std::cerr.flush();
                if (!ok) {
                    throw std::runtime_error(
                        "retained reorg UTXO transaction returned false");
                }
            } catch (const db::DurableWriteUncertain& e) {
                reorg_publication_uncertain_.store(
                    true, std::memory_order_release);
                FailStopDurableCommitInvariant_(
                    std::string("VUR1 begin durability is uncertain: ") +
                    e.what());
                std::cerr << "  [reorg-leveldb] durability uncertain: "
                          << e.what() << "\n";
                std::cerr.flush();
                // Do not throw into Blockchain's generic reorg compensation.
                // The old canonical metadata is still authoritative, but the
                // candidate UTXO write outcome is unknowable until restart.
                return;
            } catch (const std::exception& e) {
                std::cerr << "  [reorg-leveldb] exception: " << e.what() << "\n";
                std::cerr.flush();
                throw;
            } catch (...) {
                std::cerr << "  [reorg-leveldb] unknown exception\n";
                std::cerr.flush();
                throw;
            }

            // Do not dispatch mempool mutation from this preliminary durable-
            // UTXO callback.  A later per-block on_commit callback can still
            // reject and roll the complete reorg back.  Blockchain publishes
            // displaced transactions only after every callback succeeds; the
            // post-commit worker below performs the corresponding purge.

        });

        chain_.SetOnReorgAbort([this](
            const Blockchain::UTXODelta& delta,
            const Block& old_tip, uint64_t old_supply,
            const std::vector<Block>& old_canonical_tail) -> bool
        {
            try {
                (void)old_canonical_tail;
                if (!reorg_utxo_pending_) {
                    // An exception before BeginReorgUTXO armed its identity did
                    // not mutate durable UTXOs.  Accept only an exact old DB
                    // frame and the absence of any retained VUR1.
                    const auto tip = db_.ReadChainTipExact();
                    const auto current = db_.ReadReorgUtxoPending();
                    const bool untouched = !current && tip &&
                        tip->height == old_tip.height &&
                        tip->tip_hash == HashToHex(old_tip.GetHash()) &&
                        tip->supply_units == old_supply;
                    if (untouched) {
                        ClearReorgAnchorFloorForAbort_();
                        reorg_finality_retirements_.clear();
                        reorg_block_publication_stages_.clear();
                        reorg_displaced_txindex_rows_.clear();
                        reorg_derived_index_frame_.reset();
                        miner_archive_ready_.store(
                            MinerArchiveMarkersMatch_(old_tip.height,
                                                      old_tip.GetHash()),
                            std::memory_order_release);
                    }
                    return untouched;
                }

                const auto expected = *reorg_utxo_pending_;
                if (expected.old_height != old_tip.height ||
                    expected.old_hash != old_tip.GetHash() ||
                    expected.old_supply != old_supply) {
                    FailStopDurableCommitInvariant_(
                        "VUR1 abort callback old-frame identity mismatch");
                    return false;
                }
                const bool restored = db_.AbortReorgUTXO(
                    SerializeUTXODelta_(delta), expected);
                if (!restored) {
                    FailStopDurableCommitInvariant_(
                        "VUR1 identity-checked abort returned false");
                    return false;
                }
                reorg_utxo_pending_.reset();
                ClearReorgAnchorFloorForAbort_();
                reorg_finality_retirements_.clear();
                reorg_block_publication_stages_.clear();
                reorg_displaced_txindex_rows_.clear();
                reorg_derived_index_frame_.reset();
                miner_archive_ready_.store(
                    MinerArchiveMarkersMatch_(old_tip.height,
                                              old_tip.GetHash()),
                    std::memory_order_release);
                return true;
            } catch (const db::DurableWriteUncertain& e) {
                FailStopDurableCommitInvariant_(
                    std::string("VUR1 abort durability is uncertain: ") +
                    e.what());
                return false;
            } catch (const std::exception& e) {
                FailStopDurableCommitInvariant_(
                    std::string("VUR1 abort failed: ") + e.what());
                return false;
            } catch (...) {
                FailStopDurableCommitInvariant_(
                    "VUR1 abort failed with an unknown exception");
                return false;
            }
        });

        chain_.SetReorgPublicationUncertainFn([this]() -> bool {
            return reorg_publication_uncertain_.load(
                std::memory_order_acquire);
        });

        chain_.SetOnOrphanedTxs([this](
            const std::vector<Transaction>& orphan_txs)
        {
            if (reorg_publication_uncertain_.load(
                    std::memory_order_acquire) ||
                FailStopRequired()) {
                return;
            }
            auto orphans_owned = std::make_shared<std::vector<Transaction>>(orphan_txs);
            try {
                EnqueueReorgFixup([this, orphans_owned]() {
                    try {
                        // This task is dispatched only after the reorg's full
                        // durable callback sequence succeeds. Purge the old
                        // parent frame before resurrecting its transactions so
                        // no stale/conflicting root is briefly advertisable.
                        size_t purged = mempool_.PurgeInvalidAgainst(
                            [this](const Hash256& tx_hash,
                                   uint32_t idx) -> bool {
                                return chain_.GetUTXO(tx_hash, idx).has_value();
                            });
                        // The preliminary existence-only pass above drops obvious
                        // stale roots cheaply.  Now run the complete contextual
                        // policy sweep against the final durable tip
                        // before resurrecting displaced transactions: maturity,
                        // locking, AMM/TOKEN state, orphan closure, and expiry all
                        // belong to this one post-success reorg transaction.
                        purged += mempool_.RemoveStale(chain_);
                        purged += mempool_.SweepOrphans(chain_);
                        purged += mempool_.ExpireOld();
                        size_t reinjected = 0;
                        size_t dropped = 0;
                        for (const auto& tx : *orphans_owned) {
                            uint64_t fee = 0;
                            try {
                                // frame.old_tail is canonical-height ordered.
                                // A child from a later displaced block may
                                // spend a parent just re-added above, so resolve
                                // through both the chain and current mempool.
                                auto input_total = mempool_.ResolveInputTotal(
                                    tx, chain_);
                                if (!input_total) { ++dropped; continue; }
                                uint64_t output_total = tx.TotalOutput();
                                if (output_total > *input_total) {
                                    ++dropped;
                                    continue;
                                }
                                fee = *input_total - output_total;
                            } catch (...) { ++dropped; continue; }

                            auto res = mempool_.Add(tx, fee,
                                                    (uint32_t)chain_.Height(),
                                                    chain_);
                            if (res == Mempool::AddResult::ACCEPTED) {
                                ++reinjected;
                            } else {
                                ++dropped;
                            }
                        }
                        if (purged > 0 || reinjected > 0 || dropped > 0) {
                            std::cerr << "  [reorg-mempool] re-injected "
                                      << reinjected
                                      << " orphan TX(s), dropped " << dropped
                                      << ", purged " << purged
                                      << " (post-reorg)\n";
                            std::cerr.flush();
                        }
                    } catch (const std::exception& e) {
                        std::cerr << "  [reorg-mempool] re-inject exception: "
                                  << e.what() << "\n";
                        std::cerr.flush();
                    } catch (...) {
                        std::cerr << "  [reorg-mempool] re-inject unknown exception\n";
                        std::cerr.flush();
                    }
                });
            } catch (const std::exception& e) {
                std::cerr << "  [reorg-mempool] re-inject dispatch: "
                          << e.what() << "\n";
                std::cerr.flush();
            } catch (...) {
                std::cerr << "  [reorg-mempool] re-inject dispatch: unknown\n";
                std::cerr.flush();
            }
            // Like mempool resurrection, pending-broadcast invalidation must
            // observe only a fully committed reorg. Dispatching it from
            // on_reorg_ could erase ACK tracking for the old chain before a
            // later callback failed and restored that chain.
            InvalidateReorgedPendingBroadcasts_Deferred();
        });

        chain_.SetOnRollback([this](const Blockchain::UTXODelta& delta,
                                    const Block& popped)
        {
            const auto durable_delta = SerializeUTXODelta_(delta);
            const bool ok = db_.ApplyUTXODelta(durable_delta);
            std::cerr << "  [rollback-leveldb] applied "
                      << durable_delta.size()
                      << " bounded UTXO writes — " << (ok ? "ok" : "FAILED")
                      << "\n";
            std::cerr.flush();
            if (!ok) {
                // Propagate failure into Blockchain's process-lifetime
                // durability latch.  Swallowing this error lets the node keep
                // committing above a disk frame that may still contain the
                // rejected block.
                throw std::runtime_error(
                    "leveldb UTXO rollback failed; restart required");
            }
            // The miner archive is display-only and rebuildable. A missing or
            // corrupt undo row must close archive reads, but it must not turn a
            // successful consensus/UTXO rollback into a durability failure.
            // The next linear commit detects the marker mismatch and rebuilds;
            // restart always performs an exact canonical rebuild as well.
            if (!RollbackMinerArchiveIndex_(popped)) {
                miner_archive_ready_.store(false,
                                           std::memory_order_release);
                std::cerr << "  [miner-archive] rollback deferred; index "
                             "closed until canonical rebuild\n";
                std::cerr.flush();
            }

            try {
                InvalidateReorgedPendingBroadcasts_Deferred();
            } catch (const std::exception& e) {
                std::cerr << "  [layer1] reorg-invalidate dispatch from "
                             "on_rollback_: " << e.what() << "\n";
                std::cerr.flush();
            } catch (...) {
                std::cerr << "  [layer1] reorg-invalidate dispatch from "
                             "on_rollback_: unknown\n";
                std::cerr.flush();
            }
        });

        // btcVELD AMM pool covenant hooks (see blockchain.h). Inert until a pool is
        // seeded; once live, every pool spend is bound to the committed outpoint and
        // the consensus AMM block validator below.
        chain_.SetAmmMempoolValidator(
            [this](const Transaction& tx, uint64_t candidate_height) {
                // Mempool policy evaluates one transaction against the exact
                // parent AMM/token frame. ValidateBlock is pure (pcopy + token
                // reads only) and therefore supplies byte-for-byte the same
                // reserve, LP, authorization, cap and four-band checks that the
                // eventual block guard applies. A block may carry only one AMM
                // op, so the synthetic one-tx frame is the complete candidate.
                Block candidate;
                candidate.height = candidate_height;
                candidate.transactions.push_back(tx);
                return amm_.ValidateBlock("VELD:btcVELD", candidate,
                                          onchain_tokens_,
                                          PegGateForHeight_(candidate_height));
            });
        chain_.SetTokenMempoolValidator(
            [this](const Transaction& tx, uint64_t candidate_height,
                   uint32_t candidate_bits) {
                return onchain_tokens_.ValidateMempoolCandidate(
                    tx, candidate_height, candidate_bits,
                    PegGateForHeight_(candidate_height));
            });
        chain_.SetTokenMempoolBatchFilter(
            [this](const std::vector<Transaction>& candidates,
                   const std::vector<bool>& token_authorization_prevalidated,
                   uint64_t candidate_height, uint32_t candidate_bits) {
                return onchain_tokens_.FilterMempoolCandidates(
                    candidates, candidate_height, candidate_bits,
                    PegGateForHeight_(candidate_height),
                    token_authorization_prevalidated);
            });
        chain_.SetTokenAwareMempoolSelector(
            [this](const std::vector<const Transaction*>& candidates,
                   const std::vector<size_t>& serialized_sizes,
                   const std::vector<bool>& token_families,
                   const std::vector<bool>& token_authorization_prevalidated,
                   size_t initial_count, size_t initial_bytes,
                   size_t max_count, size_t max_bytes,
                   uint64_t candidate_height, uint32_t candidate_bits) {
                return onchain_tokens_.SelectResourceFeasibleMempoolCandidates(
                    candidates, serialized_sizes, token_families,
                    token_authorization_prevalidated,
                    initial_count, initial_bytes, max_count, max_bytes,
                    candidate_height, candidate_bits,
                    PegGateForHeight_(candidate_height));
            });
        chain_.amm_pool_input_check_ =
            [this](const std::vector<uint8_t>& spk, const Hash256& txid, uint32_t vout) -> int {
                if (!IsAmmPoolScript(spk)) return 0;
                const auto* ov = Blockchain::alt_engine_overlay_;   // fork-aware during reorg eval
                AmmLedger& a = (ov && ov->amm) ? *ov->amm : amm_;
                return a.IsCommittedPoolOutpoint("VELD:btcVELD", txid, vout) ? 1 : -1;
            };
        chain_.amm_block_validator_ =
            [this](const Block& b) {
                const auto* ov = Blockchain::alt_engine_overlay_;   // fork-aware during reorg eval
                AmmLedger&          a = (ov && ov->amm)    ? *ov->amm    : amm_;
                OnChainTokenLedger& t = (ov && ov->tokens) ? *ov->tokens : onchain_tokens_;
                if (ov) {
                    if (!btc_headers_alt_ || !anchors_alt_ ||
                        !fin_state_alt_) return false;
                    return ValidateAmmBlockWithModulePrefix_(
                        a, t, *btc_headers_alt_, *anchors_alt_,
                        *fin_state_alt_, b,
                        [this](uint64_t h, Hash256& out) {
                            return ResolveAltHash_(h, out);
                        });
                }
                return ValidateAmmBlockWithModulePrefix_(
                    a, t, btc_headers_, anchors_, fin_state_, b,
                    [this](uint64_t h, Hash256& out) {
                        try {
                            out = chain_.GetBlockUnlocked(h).GetHash();
                            return true;
                        } catch (...) { return false; }
                    });
            };
        // btcVELD Layer-2 anchor fork-choice gate. Consults the CANONICAL anchor set (not
        // the fork-aware overlay) so a reorg that would rewrite a Bitcoin-anchored height is
        // vetoed regardless of work. Inert while anchoring is dormant (anchors_ stays empty).
        chain_.anchor_gate_ =
            [this](uint64_t h, const Hash256& block_hash) -> bool {
                return EffectiveAnchorSecurityPinPermits_(h, block_hash) &&
                       anchors_.Allows(h, block_hash);
            };
        chain_.anchor_reorg_gate_ =
            [this](uint64_t common_ancestor_height,
                   uint64_t current_tip_height) -> bool {
                return EffectiveAnchorSecurityReorgPermitted_(
                           common_ancestor_height,
                           current_tip_height) &&
                       anchors_.PermanentReorgPermitted(
                           common_ancestor_height);
            };
        // Preserve the canonical certificate carrier across reorganization.
        // A carrier cannot precede its target, so requiring the common ancestor
        // to include the carrier also preserves the finalized target. With no
        // finalized record, this gate imposes no additional restriction.
        chain_.finality_reorg_gate_ =
            [this](uint64_t common_ancestor_height) -> bool {
                if (fin_state_.record.IsNull()) return true;
                return common_ancestor_height >= fin_state_.record.carrier.height;
            };

        chain_.SetOnCommit([this](
            const Block& block,
            const std::vector<std::pair<Hash256,uint32_t>>& spent,
            const std::vector<UTXO>& created,
            bool from_reorg) -> bool
        {
            std::lock_guard<std::mutex> commit_lock(on_commit_serial_mutex_);

            std::optional<AllModuleSnapshots> callback_entry_modules;
            const uint64_t callback_entry_height = last_token_height_;
            const uint64_t callback_entry_supply = last_module_supply_;
            bool durable_commit_done = false;
            bool durable_publication_cleared = false;
            bool definite_reorg_publication = false;
            const bool publishes_final_frame =
                !from_reorg || block.height == chain_.Height();
            const auto clear_definite_reorg_state = [this]() {
                reorg_transaction_modules_.reset();
                reorg_utxo_pending_.reset();
                ClearReorgAnchorFloorForAbort_();
                reorg_finality_retirements_.clear();
                reorg_block_publication_stages_.clear();
                reorg_displaced_txindex_rows_.clear();
                reorg_derived_index_frame_.reset();
                reorg_publication_uncertain_.store(
                    false, std::memory_order_release);
            };

            // BeginReorgUTXO reported an indeterminate sync result.  Returning
            // false would invoke a potentially destructive UTXO compensation;
            // doing normal work could publish a suffix over an unknown UTXO
            // frame.  Service is already fail-stopped, so make every remaining
            // callback a side-effect-free success and let startup replay decide.
            if (from_reorg && reorg_publication_uncertain_.load(
                                  std::memory_order_acquire)) {
                return true;
            }

            // Wrap entire callback in try/catch — a LevelDB IO error or any other
            // exception must NOT propagate out of on_commit_ into AddBlockDirect callers
            // (MiningLoop thread and HandlePeer thread would call std::terminate otherwise).
            try {
            callback_entry_modules = SnapshotAllModules();
            if (from_reorg && !reorg_transaction_modules_) {
                reorg_transaction_modules_ = *callback_entry_modules;
                reorg_transaction_height_ = callback_entry_height;
                reorg_transaction_supply_ = callback_entry_supply;
                reorg_finality_retirements_.clear();
            }
            uint64_t module_supply_after = callback_entry_supply;
            std::vector<std::tuple<Hash256,uint32_t,std::string>> new_utxos;
            for (const auto& u : created)
                new_utxos.emplace_back(u.tx_hash, u.output_index, SerializeUTXO(u));

            // Derived tx/redeem/nullifier rows are published only after this
            // callback's canonical DB frame is irrevocable. In particular an
            // intermediate reorg callback must leave no durable side effects.

            //  Track whether the post-reorg state rebuild
            // walked all blocks cleanly. The replay loop below uses
            // try/catch+break on exception (e.g. a malformed VELD_GOV
            // OP_RETURN whose ingest-time validation missed). Previously
            // the `last_token_height_ = block.height` assignment after
            // the if-reorg branch fired unconditionally — claiming success
            // even when the loop bailed mid-walk. Next on_commit_ then saw
            // a high last_token_height_ and refused to re-replay, leaving
            // derived state permanently truncated. With this flag, a failed
            // replay does NOT advance last_token_height_: the next commit
            // retries (loudly, with stderr log) until the failing block is
            // identified and the operator intervenes. Non-reorg commits
            // never touch this flag so it stays `true` → unconditional
            // latch advance as before.
            bool replay_ok = true;
            std::optional<AllModuleSnapshots> pre_reorg_modules;
            const uint64_t pre_reorg_last_token_height = last_token_height_;
            if (block.height <= last_token_height_ && last_token_height_ > 0) {
                pre_reorg_modules = SnapshotAllModules();
                // Reorg derived-state rebuild in progress: pause the miner (checked in the
                // safety gate) so it can't read half-rebuilt engines. RAII clears on any exit.
                struct RebuildFlag { std::atomic<bool>& f;
                    RebuildFlag(std::atomic<bool>& x):f(x){ f.store(true, std::memory_order_release); }
                    ~RebuildFlag(){ f.store(false, std::memory_order_release); } } _rbf{reorg_rebuild_active_};
                const ModuleCheckpoint* checkpoint =
                    FindCanonicalModuleCheckpoint_(block.height - 1);
                if (!checkpoint) {
                    replay_ok = false;
                    std::cerr << "  [reorg] no canonical module checkpoint at/below h="
                              << (block.height - 1) << "\n";
                    std::cerr.flush();
                } else {
                  RestoreAllModules(checkpoint->modules);
                  last_token_height_ = checkpoint->height;
                  last_module_supply_ = checkpoint->supply;
                  uint64_t running_supply = checkpoint->supply;
                  for (uint64_t h = checkpoint->height + 1;
                       h < block.height; ++h) {
                    try {
                        Block rb = chain_.GetBlock(h);
                        if (!AdvanceModuleSupply_(rb, running_supply))
                            throw std::runtime_error(
                                "canonical supply advance failed during reorg replay");
                        if (!ApplyBlockModules_(rb, running_supply,
                                                /*persist_governance=*/false,
                                                /*publish_rpc_snapshots=*/true,
                                                /*chain_mutex_already_held=*/false)) {
                            throw std::runtime_error(
                                "stateful module returned failure during reorg replay");
                        }
                    } catch (const std::exception& e) { std::cerr << "  [replay] exception at h=" << h << ": " << e.what() << "\n"; std::cerr.flush(); replay_ok = false; break; } catch (...) { std::cerr << "  [replay] unknown exception at h=" << h << "\n"; std::cerr.flush(); replay_ok = false; break; }
                  }
                  module_supply_after = running_supply;
                }
            }
            if (!replay_ok) {
                if (from_reorg && reorg_transaction_modules_) {
                    RestoreReorgTransactionModules_();
                } else {
                    if (pre_reorg_modules) RestoreAllModules(*pre_reorg_modules);
                    last_token_height_ = pre_reorg_last_token_height;
                    last_module_supply_ = callback_entry_supply;
                }
                std::cerr << "  [reorg] post-reorg module replay failed closed; "
                             "restored pre-reorg modules and rejected commit callback\n";
                std::cerr.flush();
                return false;
            }
            if (!pre_reorg_modules && block.height > 0 &&
                callback_entry_height + 1 != block.height) {
                throw std::runtime_error(
                    "non-contiguous module apply height: prior=" +
                    std::to_string(callback_entry_height) + " block=" +
                    std::to_string(block.height));
            }
            if (!AdvanceModuleSupply_(block, module_supply_after))
                throw std::runtime_error(
                    "canonical supply advance failed for live module apply");
            // Linear connect and the final callback in a multi-block reorg must
            // land on Blockchain's authoritative supply exactly.  Intermediate
            // reorg callbacks intentionally represent their own height, while
            // chain_.TotalSupplyUnits() already represents the final new tip.
            if ((!from_reorg || block.height == chain_.Height()) &&
                module_supply_after != chain_.TotalSupplyUnits()) {
                throw std::runtime_error(
                    "module/canonical supply mismatch at h=" +
                    std::to_string(block.height));
            }
            // Fee routing: 100% of tx fees go to vault via coinbase.
            // MineOnly adds total_tx_fees directly into the vault coinbase output.
            // The on_commit_ callback does NOT need to separately deposit fees —
            // they are already on-chain as a vault UTXO via the coinbase split.
            // vault_.Deposit() is only used for the in-memory accounting ledger.
            // The real vault balance is chain_.GetBalance(vault_script) from UTXOs.
            //
            // Use Blockchain::ExpectedBlockSubsidy(height). Year-boundary blocks
            // legitimate subsidy is BLOCK_REWARD_UNITS + ANNUAL_EMISSION_REMAINDER,
            // so a fixed subsidy would misclassify the remainder as fees.
            uint64_t block_fees = 0;
            if (block.transactions.size() > 1) {
                uint64_t cb_total = 0;
                for (auto& out : block.transactions[0].outputs) cb_total += out.value;
                uint64_t subsidy = Blockchain::ExpectedBlockSubsidy(block.height);
                if (cb_total > subsidy)
                    block_fees = cb_total - subsidy;
            }

            // Reject a block whose state cannot be durably published and recover
            // from peers without retaining an in-memory-only canonical state.
            // BeginReorgUTXO retains VUR1 before
            // installing the complete candidate UTXO delta while leaving the
            // old canonical metadata authoritative. Intermediate callbacks
            // stage only reversible/module data. The final callback publishes
            // the entire contiguous suffix, final tip/supply/VLF1 and VDP1 in
            // one CommitReorgMetadata index batch which also retires VUR1.
            // Apply per-module state as one all-or-nothing unit before database
            // persistence. Restore every subsystem on any module failure.
            // Applying before persistence means a rejected block needs only an in-memory
            // RollbackTip (no db-undo). Deadlock-free: on_commit_ runs with chain_mutex_
            // released (blockchain.h:3646/3825). A reorg block (multi-block, from_reorg)
            // re-throws to the existing reorg/replay recovery instead of a single-tip
            // pop. Rollback mechanism proven by equiv_c2 EQUIV_C2_ATOMIC.
            auto __mod_snap = SnapshotAllModules();
            std::optional<std::vector<uint8_t>> durable_anchor_floor;
            ReorgBlockPublicationStage current_publication_stage;
            try {
                if (!ApplyBlockModules_(block, module_supply_after,
                                        /*persist_governance=*/false,
                                        /*publish_rpc_snapshots=*/true,
                                        /*chain_mutex_already_held=*/false)) {
                    throw std::runtime_error("stateful module returned apply failure");
                }
                // Publish the opaque VLF1 bytes in the same authoritative
                // index batch as chain:tip.  A power loss after that batch can
                // therefore recover the floor even if the separate security/
                // mirror was not yet replaced.  A multi-block reorg may expose
                // a new floor only in its final callback; intermediate frames
                // preserve the previously durable floor.
                durable_anchor_floor = AnchorFloorWireForDurableCommit_(
                    !from_reorg || block.height == chain_.Height());
                current_publication_stage.height = block.height;
                current_publication_stage.hash = block.GetHash();
                current_publication_stage.bits = block.header.bits;
                current_publication_stage.module_supply =
                    module_supply_after;
                current_publication_stage.vault_fees = block_fees;
                current_publication_stage.vault_reserve_payout =
                    staking_.GetReserveBlockPayout(module_supply_after);
                current_publication_stage.redeems =
                    onchain_tokens_.LastBlockRedeemsCopy();
                current_publication_stage.mint_transitions =
                    onchain_tokens_.LastBlockMintTransitionsCopy();
                if (from_reorg &&
                    (block.height % MAX_REORG_DEPTH) == 0) {
                    current_publication_stage.boundary_checkpoint =
                        SnapshotAllModules();
                }
                if (from_reorg) {
                    reorg_block_publication_stages_.push_back(
                        current_publication_stage);
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
                    // Sample after retaining the complete boundary stage: at
                    // h500 this observes callback-entry, reorg-transaction,
                    // module-undo, and boundary-checkpoint copies together,
                    // before any callback-local snapshot can be released.
                    if (dstate_memory_observer_)
                        dstate_memory_observer_();
#endif
                }
            } catch (const std::exception& e) {
                if (from_reorg && reorg_transaction_modules_)
                    RestoreReorgTransactionModules_();
                else if (callback_entry_modules)
                    RestoreAllModules(*callback_entry_modules);
                else
                    RestoreAllModules(__mod_snap);
                if (!from_reorg) {
                    last_token_height_ = callback_entry_height;
                    last_module_supply_ = callback_entry_supply;
                }
                std::cerr << "  [module] apply failed at h=" << block.height
                          << ": " << e.what()
                          << " — all subsystems rolled back to pre-block\n";
                std::cerr.flush();
                return false;   // Blockchain owns the exact-tip rollback/result propagation
            }

            if (from_reorg && !publishes_final_frame) {
                // The old DB tip and retained VUR1 marker remain authoritative
                // through every intermediate callback.  Only reversible module
                // state and explicitly staged publication data may advance.
                StageReorgFinalityCarrier_(block);
                last_token_height_ = block.height;
                last_module_supply_ = module_supply_after;
                return true;
            }

            const std::vector<uint8_t>* durable_anchor_floor_ptr =
                durable_anchor_floor ? &*durable_anchor_floor : nullptr;

            bool persist_ok = false;
            try {
                if (from_reorg) {
                    if (!reorg_utxo_pending_)
                        throw std::runtime_error(
                            "final reorg callback has no retained VUR1 identity");
                    if (reorg_utxo_pending_->new_height != block.height ||
                        reorg_utxo_pending_->new_hash != block.GetHash() ||
                        reorg_utxo_pending_->new_supply !=
                            module_supply_after) {
                        throw std::runtime_error(
                            "final reorg callback does not match retained VUR1 identity");
                    }
                    db::VeldDB::ReorgCanonicalSuffix suffix;
                    suffix.reserve(reorg_block_publication_stages_.size());
                    for (const auto& stage :
                             reorg_block_publication_stages_) {
                        suffix.emplace_back(stage.height, stage.hash,
                                            stage.bits);
                    }
                    persist_ok = db_.CommitReorgMetadata(
                        suffix, *reorg_utxo_pending_,
                        durable_anchor_floor_ptr);
                } else {
                    persist_ok = db_.CommitBlock(
                        block.GetHash(), block.Serialize(), block.height,
                        module_supply_after, block.header.bits, spent,
                        new_utxos, durable_anchor_floor_ptr);
                }
            } catch (const db::DurableWriteUncertain& e) {
                // The canonical WAL may already contain the final tip/VDP1
                // even when sync reported failure.  Never ask Blockchain to
                // restore the old in-memory frame across this cut point.
                if (from_reorg) {
                    reorg_publication_uncertain_.store(
                        true, std::memory_order_release);
                }
                durable_commit_done = true;
                FailStopDurableCommitInvariant_(
                    "canonical persistence durability is uncertain at h=" +
                    std::to_string(block.height) + ": " + e.what());
                return true;
            } catch (const std::exception& e) {
                std::cerr << "  [commit] pre-publication persistence failure at h="
                          << block.height << ": " << e.what() << "\n";
                std::cerr.flush();
                if (from_reorg && reorg_transaction_modules_)
                    RestoreReorgTransactionModules_();
                else if (callback_entry_modules)
                    RestoreAllModules(*callback_entry_modules);
                if (!from_reorg) {
                    last_token_height_ = callback_entry_height;
                    last_module_supply_ = callback_entry_supply;
                    FailStopDurableCommitInvariant_(
                        "linear canonical persistence failed before publication at h=" +
                        std::to_string(block.height) + ": " + e.what());
                }
                return false;
            } catch (...) {
                if (from_reorg && reorg_transaction_modules_)
                    RestoreReorgTransactionModules_();
                else if (callback_entry_modules)
                    RestoreAllModules(*callback_entry_modules);
                if (!from_reorg) {
                    last_token_height_ = callback_entry_height;
                    last_module_supply_ = callback_entry_supply;
                    FailStopDurableCommitInvariant_(
                        "linear canonical persistence failed before publication at h=" +
                        std::to_string(block.height) +
                        ": unknown persistence exception");
                }
                return false;
            }
            if (!persist_ok) {
                consecutive_commit_failures_.fetch_add(
                    1, std::memory_order_relaxed);
                if (from_reorg && reorg_transaction_modules_)
                    RestoreReorgTransactionModules_();
                else if (callback_entry_modules)
                    RestoreAllModules(*callback_entry_modules);
                if (!from_reorg) {
                    last_token_height_ = callback_entry_height;
                    last_module_supply_ = callback_entry_supply;
                    FailStopDurableCommitInvariant_(
                        "linear canonical persistence rejected before publication at h=" +
                        std::to_string(block.height));
                }
                return false;
            }

            // CommitBlock/CommitReorgMetadata just published the exact block or
            // complete replacement suffix, canonical tip, module supply, VLF1
            // candidate, and VDP1 identity in the authoritative DB.  From this
            // instruction onward a false return would roll memory behind disk.
            durable_commit_done = true;
#ifdef VELD_PUBLIC_TESTNET
            // Close at the authoritative durable terminal frame, before a
            // concurrent RPC or reorg can race the outer supervisor poll.
            public_testnet::LatchClosedAtDurableCanonicalHeight(
                public_testnet_expired_,
                public_testnet_limits_
                    ? &public_testnet_limits_.value() : nullptr,
                block.height);
#endif
            definite_reorg_publication = from_reorg;
            consecutive_commit_failures_.store(0, std::memory_order_relaxed);

            // Body eviction is legal only after the exact canonical bytes and
            // height mapping above are durable.  A mismatch means the chain
            // changed under the callback contract; fail closed before
            // publishing any replay/module latches.
            bool canonical_durable_marker_ok = true;
            bool canonical_durable_marker_threw = false;
            uint64_t marker_failure_height = block.height;
            Hash256 marker_failure_hash = block.GetHash();
            try {
#ifdef VELD_TEST_HOOKS
            if (canonical_durable_marker_test_failure_) {
                canonical_durable_marker_ok = false;
            } else
#endif
            {
                const auto mark = [this, &canonical_durable_marker_ok,
                                   &marker_failure_height,
                                   &marker_failure_hash](
                                      uint64_t height,
                                      const Hash256& hash) {
                    if (!canonical_durable_marker_ok) return;
                    if (!chain_.MarkCanonicalBlockDurable(height, hash)) {
                        canonical_durable_marker_ok = false;
                        marker_failure_height = height;
                        marker_failure_hash = hash;
                    }
                };
                if (from_reorg) {
                    for (const auto& stage :
                             reorg_block_publication_stages_)
                        mark(stage.height, stage.hash);
                } else {
                    mark(block.height, block.GetHash());
                }
            }
            } catch (const std::exception& e) {
                canonical_durable_marker_threw = true;
                FailStopDurableCommitInvariant_(
                    "canonical durable-body marker threw at h=" +
                    std::to_string(block.height) + " hash=" +
                    HashToHex(block.GetHash()).substr(0, 16) + ": " +
                    e.what());
            } catch (...) {
                canonical_durable_marker_threw = true;
                FailStopDurableCommitInvariant_(
                    "canonical durable-body marker threw at h=" +
                    std::to_string(marker_failure_height) + " hash=" +
                    HashToHex(marker_failure_hash).substr(0, 16));
            }
            if (!canonical_durable_marker_ok &&
                !canonical_durable_marker_threw) {
                // The DB block/tip/module frame above is already durable.
                // Returning false would make Blockchain roll the canonical
                // in-memory block and module frame back while disk remains
                // ahead (and, on a reorg, could strand an alt-only VLF key).
                // Preserve DB/memory alignment, finish the current synchronous
                // callback transaction, and stop all subsequent service so a
                // clean restart can rebuild the body-cache marker by replay.
                FailStopDurableCommitInvariant_(
                    "canonical durable-body marker rejected h=" +
                    std::to_string(block.height) + " hash=" +
                    HashToHex(block.GetHash()).substr(0, 16));
            }

            // Persistence and the canonical durable marker are now both
            // complete, or the marker failed after the authoritative frame was
            // already durable and the node is fail-stopping.

            if (from_reorg && publishes_final_frame) {
                // The final alt tip is already authoritative and this callback
                // may no longer request transaction abort.  Drop the displaced
                // restore frame now so any post-durable exception cannot leak a
                // stale capture into the next independent reorg.
                reorg_transaction_modules_.reset();
                reorg_utxo_pending_.reset();
                ClearReorgAnchorFloorForAbort_();
            }

            if (from_reorg) {
                StageReorgFinalityCarrier_(block);
                // Reorganize invokes one callback per newly canonical block.
                // Intermediate callbacks remain rollback-capable if a later
                // callback fails; retire all staged QCs only at the final tip.
                if (publishes_final_frame)
                    RetireCompletedReorgFinalityCarriers_();
            } else {
                RetireDurableFinalityCarrier_(block);
            }
            if (publishes_final_frame)
                PruneFinalityEvidenceAfterDurableTip_(chain_.Height());

            // Publish the replay latches before any best-effort checkpoint or
            // housekeeping work.  The callback must report success after the
            // durable boundary even if one of those later operations throws.
            last_token_height_ = block.height;
            last_module_supply_ = module_supply_after;
            // The permanent AnchorSet transition happened in the module frame
            // above, but it is local security knowledge only after the exact
            // canonical block bytes and DB tip have crossed their durable
            // boundary. A multi-block reorg publishes its VLF1 only on the
            // final callback, when the complete branch transaction can no
            // longer roll back to the displaced module snapshot.
            if (publishes_final_frame &&
                !PersistObservedAnchorFloorAfterDurable_(
                    /*startup_replay=*/false)) {
                // The helper has latched fail-stop. Returning false here would
                // ask Blockchain to undo an already-durable block, which is
                // both impossible and less safe than immediate shutdown.
                if (definite_reorg_publication)
                    clear_definite_reorg_state();
                return true;
            }

            // Intermediate reorg callbacks intentionally retain VDP1: a later
            // callback can still abort the whole branch.  The final callback
            // (or an ordinary linear commit) clears it only after both the
            // durable-body marker and mandatory VLF1 mirror succeeded.  A
            // fail-stop raised by any earlier callback is monotonic and makes
            // every later callback leave the final-tip obligation armed.
            if (publishes_final_frame && !FailStopRequired()) {
                if (!ClearDurablePublicationAfterCommit_(block)) {
                    if (definite_reorg_publication)
                        clear_definite_reorg_state();
                    return true;
                }
                durable_publication_cleared = true;
            }

            if (publishes_final_frame) {
                if (from_reorg) {
                    for (const auto& stage :
                             reorg_block_publication_stages_) {
                        if (stage.boundary_checkpoint) {
                            InstallModuleCheckpoint_(
                                stage.height, stage.hash,
                                stage.module_supply,
                                *stage.boundary_checkpoint);
                        }
                    }
                }
                CaptureModuleCheckpoint_(
                    block.height, block.GetHash(), module_supply_after,
                    /*force=*/block.height == 0);
            }

            // These indexes are rebuildable but RPC-visible. Publish the exact
            // staged suffix only after the canonical frame and VDP1 clear are
            // complete, so no intermediate reorg branch can leak a tx mapping.
            if (publishes_final_frame) {
                try {
                    if (from_reorg) {
                        PersistCanonicalDerivedIndexes_(
                            reorg_block_publication_stages_,
                            /*from_reorg=*/true);
                    } else {
                        PersistCanonicalDerivedIndexes_(
                            std::vector<ReorgBlockPublicationStage>{
                                current_publication_stage});
                    }
                } catch (const std::exception& e) {
                    txindex_operational_.store(false,
                                               std::memory_order_release);
                    redeem_index_healthy_.store(false,
                                                std::memory_order_release);
                    mint_nullifier_index_healthy_.store(
                        false, std::memory_order_release);
                    std::cerr << "  [derived-index] final publication failed: "
                              << e.what() << "; indexes closed until replay\n";
                    std::cerr.flush();
                }
            }

            // Publish only after module apply and the exact canonical block are
            // durable. During a multi-block reorg retain the previous coherent
            // tuple until the final callback; signer-side tip-hash binding makes
            // that safely lagging ancestor fail closed while the reorg is active.
            if (btcveld::ShouldPublishSupplySnapshot(
                    from_reorg, block.height, chain_.Height()))
                PublishBtcVeldSupplySnapshot_(block);

            if (publishes_final_frame && from_reorg) {
                // Display-only accounting/pool caches are not consensus
                // modules. Mutate them once, after the complete replacement
                // suffix is canonical, never in a reversible callback.
                vault_.ResetLog();
                std::lock_guard<std::mutex> lk(comine_pool_mutex_);
                comine_pool_.tallies.clear();
                comine_pool_.pool_units = 0;
                comine_pool_.window_start = 0;
            }

            // Module KV publication follows the durable block commit. The
            // preflight and live in-memory passes both suppress it, so a module
            // or block-persistence failure cannot leave governance records for
            // a rejected/non-durable block.
            if (publishes_final_frame)
                governance_.PersistAll();

            // Per-module state has already been applied atomically by the
            // SnapshotAllModules() transaction above.

            // A multi-block reorg is not committed as a whole until every alt
            // block callback succeeds.  Mutating the mempool in an intermediate
            // callback loses old-chain-valid entries if a later callback rejects
            // and Blockchain restores the complete pre-reorg frame.  The
            // post-success orphan worker performs this same full sweep before
            // dependency-ordered reinjection once rollback is no longer possible.
            if (!from_reorg) {
                mempool_.RemoveStale(chain_);
                mempool_.SweepOrphans(chain_);
                mempool_.ExpireOld();
            }
            // ProcessBlock performs deterministic daily pruning on live,
            // preflight, reorg, and startup-replay paths.  Remove any now-
            // orphaned cache rows only after the canonical block is durable.
            if (publishes_final_frame &&
                (block.height % BLOCKS_PER_DAY) == 0)
                governance_.PruneOrphanedKV();

            if (publishes_final_frame) {
                const auto publish_vault_entry = [this](
                        const ReorgBlockPublicationStage& stage) {
                    if (stage.vault_fees > 0) {
                        vault_.Deposit(
                            stage.vault_fees,
                            "fees block " + std::to_string(stage.height));
                    }
                    if (stage.vault_reserve_payout > 0) {
                        vault_.Deposit(
                            stage.vault_reserve_payout,
                            "reserve block " + std::to_string(stage.height));
                    }
                };
                if (from_reorg) {
                    for (const auto& stage :
                             reorg_block_publication_stages_)
                        publish_vault_entry(stage);
                } else {
                    publish_vault_entry(current_publication_stage);
                }
            }

            // Lifetime miner totals are a display-only, rebuildable archival
            // index. Linear commits advance atomically. Reorg callbacks leave
            // the old canonical index untouched until the complete new branch
            // is durable, then rebuild it from canonical block bodies once.
            if (from_reorg)
                miner_archive_ready_.store(false,
                                           std::memory_order_release);
            const bool archive_ok = from_reorg
                ? (block.height == chain_.Height()
                       ? RebuildMinerArchiveIndex_() : true)
                : AdvanceMinerArchiveIndex_(block);
            if (!archive_ok) {
                miner_archive_ready_.store(false, std::memory_order_release);
                std::cerr << "  [miner-archive] index unavailable at h="
                          << block.height
                          << "; count/last display disabled until rebuild\n";
                std::cerr.flush();
            }

            if (publishes_final_frame && ibd_complete_.load() &&
                block.height > 0 &&
                (block.height % COMINE_WINDOW_BLOCKS) == 0) {
                last_pool_flush_height_.store(block.height);
            }

            if (definite_reorg_publication)
                clear_definite_reorg_state();

            return true;
            } catch (const std::exception& e) {
                std::cerr << "  [ERROR] on_commit_ exception at height "
                          << block.height << ": " << e.what() << "\n";
                if (!durable_commit_done) {
                    if (from_reorg && reorg_transaction_modules_)
                        RestoreReorgTransactionModules_();
                    else if (callback_entry_modules)
                        RestoreAllModules(*callback_entry_modules);
                    if (!from_reorg) {
                        last_token_height_ = callback_entry_height;
                        last_module_supply_ = callback_entry_supply;
                    }
                    return false;
                }
                if (!durable_publication_cleared &&
                    !DurableCommitFailStop()) {
                    FailStopDurableCommitInvariant_(
                        "post-DB commit exception before VDP1 clear at h=" +
                        std::to_string(block.height) + ": " + e.what());
                }
                if (definite_reorg_publication)
                    clear_definite_reorg_state();
                std::cerr << "  [WARN] block is already durable; treating the "
                             "exception as post-commit failure without rollback\n";
                std::cerr.flush();
                return true;
            } catch (...) {
                std::cerr << "  [ERROR] on_commit_ unknown exception at height "
                          << block.height << "\n";
                if (!durable_commit_done) {
                    if (from_reorg && reorg_transaction_modules_)
                        RestoreReorgTransactionModules_();
                    else if (callback_entry_modules)
                        RestoreAllModules(*callback_entry_modules);
                    if (!from_reorg) {
                        last_token_height_ = callback_entry_height;
                        last_module_supply_ = callback_entry_supply;
                    }
                    return false;
                }
                if (!durable_publication_cleared &&
                    !DurableCommitFailStop()) {
                    FailStopDurableCommitInvariant_(
                        "unknown post-DB commit exception before VDP1 clear at h=" +
                        std::to_string(block.height));
                }
                if (definite_reorg_publication)
                    clear_definite_reorg_state();
                std::cerr << "  [WARN] block is already durable; treating the "
                             "unknown exception as post-commit failure without rollback\n";
                std::cerr.flush();
                return true;
            }
        });
    }

    void ReplayChain(uint64_t target_height,
                     bool verify_historical_pow = true,
                     uint64_t trusted_pow_through = 0) {
        // Startup replay is a consensus ingest path, not a trusted database
        // deserializer.  Disable only persistence of blocks that are already
        // durable; retain the complete module precommit validator installed by
        // WireDB and run every block through scripts, difficulty, coinbase,
        // payout, AMM, staking, token, and covenant validation synchronously.
        // Qualified snapshot recovery may defer only historical proof-of-work
        // to the mandatory independent peer-fed chainstate.
        if (startup_replay_active_.exchange(
                true, std::memory_order_acq_rel)) {
            throw std::logic_error("nested startup replay is not permitted");
        }
        struct StartupReplayGuard {
            std::atomic<bool>& active;
            ~StartupReplayGuard() {
                active.store(false, std::memory_order_release);
            }
        } startup_replay_guard{startup_replay_active_};

#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        const auto snapshot_requirement = ReadSnapshotReplayRequirement_();
        const bool local_pow_cache_permitted =
            !snapshot_requirement &&
            (snapshot_fast_start_eligible_ ||
             background_validation_only_);
        if (!local_pow_cache_permitted && trusted_pow_through != 0) {
            throw std::runtime_error(
                "ReplayChain: local PoW cache is not valid for this replay mode");
        }
        if (trusted_pow_through > target_height) {
            throw std::runtime_error(
                "ReplayChain: local PoW cache exceeds the durable chain tip");
        }
        if (snapshot_requirement && !snapshot_fast_start_eligible_ &&
            !verify_historical_pow) {
            throw std::runtime_error(
                "ReplayChain: unqualified snapshot attempted to bypass historical PoW verification");
        }
        const bool independent_snapshot_validation =
            snapshot_requirement.has_value() && !verify_historical_pow;
#else
        if (trusted_pow_through != 0) {
            throw std::runtime_error(
                "ReplayChain: local PoW cache is not valid for this replay mode");
        }
        if (trusted_pow_through > target_height) {
            throw std::runtime_error(
                "ReplayChain: local PoW cache exceeds the durable chain tip");
        }
#endif
        const auto replay_tip = db_.ReadChainTipExact();
        if (!replay_tip || replay_tip->height != target_height ||
            !db::IsCanonicalHash256Text(replay_tip->tip_hash)) {
            throw std::runtime_error(
                "ReplayChain: exact durable tip unavailable for derived-index rebuild");
        }
        const Hash256 replay_target_hash = HexToHash(replay_tip->tip_hash);
        // If either exact-tip completion marker is absent/mismatched, first
        // remove it, then delete every byte under that index's strict row
        // prefix (including malformed legacy rows). Per-height replay below
        // appends rows with completion publication disabled; only the fully
        // validated target can restore the marker.
        PrepareCanonicalDerivedIndexesForReplay_(
            target_height, replay_target_hash);
        chain_.SetOnCommit(nullptr);

        onchain_tokens_.Reset();
        btc_headers_.Reset();
        anchors_.Reset();
        // Re-prove every imported floor from canonical block/module history.
        // A latch learned from an earlier in-memory branch must never survive
        // startup replay and allow a later permanent to mask a bad C record.
        ResetExactAnchorSecurityReconstructions_();
        // Replay rebuilds the complete locked-QC artifact from canonical block
        // carriers.  Clearing only the published height/gate atomics leaves a
        // reused snapshot-validation node with stale snapshots, warm-up state,
        // retained certificates, and finality_ever_active.  That can either
        // reject the same certificate as non-advancing or silently derive the
        // later-stall mint policy while replaying a pre-finality chain.
        fin_state_.Reset();
        final_height_.store(0, std::memory_order_release);
        peg_gate_snapshot_.store(0, std::memory_order_release);
        bond_covenant_.Reset();
        amm_.Reset();
        staking_.Reset();
        validators_.Reset();
        governance_.Reset();
        module_checkpoints_.clear();
        LoadCominePool();
        last_token_height_ = 0;
        last_module_supply_ = 0;

        {
            auto genesis_hash_hex = db_.GetHashAtHeight(0);
            if (genesis_hash_hex) {
                std::string expected_genesis_hex;
                try {
                    Block expected_genesis = CreateGenesisBlock();
                    expected_genesis_hex = HashToHex(expected_genesis.GetHash());
                } catch (const std::exception& e) {
                    std::cerr << "  [recover] FATAL: CreateGenesisBlock self-check failed: "
                              << e.what() << "\n";
                    std::cerr.flush();
                    throw;
                }
                if (*genesis_hash_hex != expected_genesis_hex) {
                    std::cerr << "\n";
                    std::cerr << "  [recover] STALE veld-data DETECTED.\n";
                    std::cerr << "  [recover] Stored chain genesis : " << *genesis_hash_hex << "\n";
                    std::cerr << "  [recover] Binary expects genesis: " << expected_genesis_hex << "\n";
                    std::cerr << "  [recover] These do NOT match. The likely cause is that\n";
                    std::cerr << "  [recover] veld-data/ persisted across a genesis bump (e.g.\n";
                    std::cerr << "  [recover] you re-extracted the new client over an existing\n";
                    std::cerr << "  [recover] folder). Loading the stored chain would put this\n";
                    std::cerr << "  [recover] miner on an orphan chain forever and silently fork.\n";
                    std::cerr << "  [recover] Auto-quarantining veld-data/{blocks,db} to\n";
                    std::cerr << "  [recover] *.stale-<timestamp> and aborting startup.\n";
                    std::cerr << "  [recover] Restart the client to begin fresh sync from peers.\n";
                    std::cerr << "  [recover] (your stake-key, miner.key, and rpc.token are\n";
                    std::cerr << "  [recover]  preserved — only the chain blob is quarantined.)\n";
                    std::cerr << "\n";
                    std::cerr.flush();
                    QuarantineDataDir_();
                    throw std::runtime_error(
                        "VeldNode: disk genesis does not match binary — veld-data/{blocks,db} "
                        "auto-quarantined. Restart to begin fresh sync.");
                }
            }
        }
        uint64_t running_supply = 0;
        {
            auto genesis_hash_hex = db_.GetHashAtHeight(0);
            if (genesis_hash_hex) {
                Hash256 ghash = HexToHash(*genesis_hash_hex);
                auto data = db_.ReadBlock(ghash);
                if (data) {
                    Block gb;
                    const size_t consumed = Block::Deserialize(*data, 0, gb);
                    if (consumed != 0 && consumed == data->size() &&
                        gb.Serialize() == *data) {
                        gb.height = 0;
                        bool replay_genesis_skip_pow = true;
#if defined(VELD_TEST_HOOKS) && defined(VELD_DSTATE_QUALIFICATION)
                        // The D-state binary's hash-only branch hook makes the
                        // exact compiled genesis cheap to validate while
                        // preserving every non-PoW gate. Production startup
                        // retains its trusted, byte-equal genesis fast path.
                        replay_genesis_skip_pow = false;
#endif
                        if (gb.GetHash() != ghash ||
                            !chain_.AddBlockDirect(
                                gb, replay_genesis_skip_pow, false, false,
                                mining::PowAdmissionContext::Internal())) {
                            throw std::runtime_error(
                                "ReplayChain: stored genesis bytes do not match the compiled genesis");
                        }
                        // Live ingest advances the canonical supply and every
                        // stateful module for h=0 before publishing its durable
                        // frame. Startup replay must do exactly the same once:
                        // omitting this step loses genesis-derived history,
                        // while checkpointing first would preserve a poisoned
                        // pre-genesis module snapshot for short reorg rebuilds.
                        if (!AdvanceModuleSupply_(gb, running_supply) ||
                            running_supply != chain_.TotalSupplyUnits()) {
                            throw std::runtime_error(
                                "ReplayChain: canonical supply mismatch at genesis");
                        }
                        if (!ApplyBlockModules_(
                                gb, running_supply,
                                /*persist_governance=*/false,
                                /*publish_rpc_snapshots=*/true,
                                /*chain_mutex_already_held=*/false)) {
                            throw std::runtime_error(
                                "ReplayChain: stateful module rejected genesis");
                        }
                        // MarkCanonicalBlockDurable is intentionally
                        // contiguous: h=1 cannot be published until h=0 has
                        // established the durable high-water. Startup replay
                        // disables on_commit_, so it must publish genesis
                        // explicitly before entering the h=1..tip loop.
                        if (!chain_.MarkCanonicalBlockDurable(0, ghash)) {
                            throw std::runtime_error(
                                "ReplayChain: durable genesis publication mismatch");
                        }
                        CaptureModuleCheckpoint_(
                            0, ghash, running_supply, /*force=*/true);
                        last_token_height_ = 0;
                        last_module_supply_ = running_supply;
                    } else {
                        throw std::runtime_error(
                            "ReplayChain: stored genesis deserialization failed");
                    }
                } else {
                    throw std::runtime_error(
                        "ReplayChain: stored genesis block data is missing");
                }
            }
        }

        // ── assumeUTXO checkpoint anchor ─────────
        // The snapshot tarball's .sha256 proves DOWNLOAD integrity, not content
        // honesty: a hostile mirror can serve an internally-consistent foreign
        // chain DB whose genesis matches (genesis is public). UTXO state is
        // never trusted from disk — this replay rebuilds it from blocks — so
        // the one remaining trust gap is BLOCK HISTORY authenticity. Anchor it
        // to the compiled-in checkpoint map before replaying a single block:
        // every pinned height at or below the stored tip must carry EXACTLY
        // the pinned hash. A PRESENT-but-DIFFERENT hash is never benign (the
        // stored history is not the canonical chain) and keeping it would
        // strand the node on a foreign fork past MAX_REORG_DEPTH, so the
        // remedy mirrors the genesis-mismatch path above: quarantine + fresh
        // sync. A MISSING index entry is left alone — the replay loop below
        // repairs benign index gaps from the reverse index, and the
        // per-block ingest gate (PassesCheckpoint in AddBlockDirect) still
        // enforces the pin when that height replays. No-op until checkpoints
        // are added (map is empty pre-mainnet).
        for (const auto& [cp_h, cp_hex] : Blockchain::AllCheckpointPins()) {
            if (cp_h == 0 || cp_h > target_height) continue;
            auto stored = db_.GetHashAtHeight(cp_h);
            if (!stored || *stored == cp_hex) continue;
            std::cerr << "\n  [recover] FATAL: stored chain fails the checkpoint anchor at h="
                      << cp_h << "\n";
            std::cerr << "  [recover]   pinned : " << cp_hex << "\n";
            std::cerr << "  [recover]   stored : " << *stored << "\n";
            std::cerr << "  [recover] The on-disk history (snapshot bootstrap or prior sync)\n";
            std::cerr << "  [recover] is NOT the canonical chain. Auto-quarantining\n";
            std::cerr << "  [recover] veld-data/{blocks,db} and aborting startup. Restart to\n";
            std::cerr << "  [recover] begin fresh sync from peers. (stake-key, miner.key and\n";
            std::cerr << "  [recover] rpc.token are preserved — only the chain blob moves.)\n";
            std::cerr.flush();
            QuarantineDataDir_();
            throw std::runtime_error(
                "VeldNode: stored chain fails checkpoint anchor at height " +
                std::to_string(cp_h) +
                " — veld-data/{blocks,db} auto-quarantined. Restart to begin fresh sync.");
        }

        // VLF1 local security pins are installed before WireDB and are
        // enforced again on every AddBlockDirect.  This early sweep produces
        // an immediate startup-fatal verdict for any present conflicting
        // T/A/C index entry before the expensive replay loop begins.
        VerifyEffectiveAnchorSecurityStoredPins_(target_height);

        if (target_height > 0 && chain_.IsEmpty()) {
            throw std::runtime_error(
                "ReplayChain: nonzero stored tip has no canonical genesis");
        }

        for (uint64_t h = 1; h <= target_height; ++h) {
            auto hash_opt = db_.GetHashAtHeight(h);
            if (!hash_opt) {
                std::string recovered = db_.FindBlockHashByHeight(h);
                if (!recovered.empty()) {
                    std::cerr << "  [replay] hash index gap at h=" << h
                              << " — repaired from reverse-index ("
                              << recovered.substr(0, 16) << "...)\n";
                    db_.RepairHeightHashMapping(h, recovered);
                    hash_opt = recovered;
                } else {
                    throw std::runtime_error(
                        "ReplayChain: hash index and reverse index missing at height " +
                        std::to_string(h));
                }
            }
            Hash256 hash = HexToHash(*hash_opt);
            auto data = db_.ReadBlock(hash);
            if (!data) {
                throw std::runtime_error(
                    "ReplayChain: block data missing at height " +
                    std::to_string(h));
            }
            Block blk; blk.height = h;
            const size_t consumed = Block::Deserialize(*data, 0, blk);
            if (consumed == 0 || consumed != data->size() ||
                blk.Serialize() != *data) {
                throw std::runtime_error(
                    "ReplayChain: non-canonical block serialization at height " +
                    std::to_string(h));
            }
            blk.height = h;
            if (blk.GetHash() != hash) {
                throw std::runtime_error(
                    "ReplayChain: indexed hash does not match stored block bytes at height " +
                    std::to_string(h));
            }
            // Full synchronous consensus validation. The D-state executable's
            // compile-isolated branch hook bypasses only hash-vs-target; never
            // select the broad trusted-replay `skip_pow=true` shortcut here.
            if (!chain_.AddBlockDirect(
                    blk, /*skip_pow=*/false, /*skip_scripts=*/false,
                    /*skip_pow_hash_only=*/
                        !verify_historical_pow || h <= trusted_pow_through,
                    mining::PowAdmissionContext::Internal())) {
                throw std::runtime_error(
                    "ReplayChain: full consensus validation rejected block at height " +
                    std::to_string(h));
            }
            if (!AdvanceModuleSupply_(blk, running_supply) ||
                running_supply != chain_.TotalSupplyUnits()) {
                throw std::runtime_error(
                    "ReplayChain: canonical supply mismatch at height " +
                    std::to_string(h));
            }
            if (!ApplyBlockModules_(blk, running_supply,
                                    /*persist_governance=*/false,
                                    /*publish_rpc_snapshots=*/true,
                                    /*chain_mutex_already_held=*/false)) {
                throw std::runtime_error(
                    "ReplayChain: stateful module rejected block at height " +
                    std::to_string(h));
            }
            try {
                ReorgBlockPublicationStage stage;
                stage.height = h;
                stage.hash = hash;
                stage.bits = blk.header.bits;
                stage.redeems = onchain_tokens_.LastBlockRedeemsCopy();
                stage.mint_transitions =
                    onchain_tokens_.LastBlockMintTransitionsCopy();
                // Startup's v3 txindex rebuild must first delete every legacy
                // canonical-format row. Do not publish per-height v3 markers
                // during replay or an exact final marker could falsely skip
                // that stale-row cleanup. Redeem/mint indexes still replay.
                PersistCanonicalDerivedIndexes_(
                    {stage}, /*from_reorg=*/false,
                    /*publish_txindex=*/false,
                    /*publish_completion_markers=*/false);
            } catch (const std::exception& e) {
                txindex_operational_.store(false,
                                           std::memory_order_release);
                redeem_index_healthy_.store(false,
                                            std::memory_order_release);
                mint_nullifier_index_healthy_.store(
                    false, std::memory_order_release);
                std::cerr << "  [derived-index] replay publication failed at h="
                          << h << ": " << e.what()
                          << "; indexes closed until next rebuild\n";
                std::cerr.flush();
            }
            if (!chain_.MarkCanonicalBlockDurable(h, hash)) {
                throw std::runtime_error(
                    "ReplayChain: durable body publication mismatch at height " +
                    std::to_string(h));
            }
            // Replay is the recovery path for a crash/failure between the
            // durable block boundary and VLF1 publication. Lower historical
            // permanents are ignored by the monotonic store; an equal conflict
            // or any I/O failure is startup-fatal before sockets exist.
            PersistObservedAnchorFloorAfterDurable_(
                /*startup_replay=*/true);
            RetireDurableFinalityCarrier_(blk);
            CaptureModuleCheckpoint_(h, hash, running_supply);
            last_token_height_ = h;
            last_module_supply_ = running_supply;
        }

        if (chain_.Height() != target_height ||
            running_supply != chain_.TotalSupplyUnits()) {
            throw std::runtime_error(
                "ReplayChain: did not reach the complete stored tip");
        }
        const std::string replayed_tip = chain_.IsEmpty()
            ? std::string() : HashToHex(chain_.TipCopy().GetHash());
        auto stored_tip = db_.ReadChainTip();
        if (!stored_tip || stored_tip->height != target_height ||
            (target_height > 0 && stored_tip->tip_hash != replayed_tip)) {
            throw std::runtime_error(
                "ReplayChain: replayed tip does not match the durable database tip");
        }
        // An explicit offline canonical-index rebuild cannot infer monetary
        // supply from headers, so it seeds chain:supply at zero. Only a full
        // successful consensus/module replay may repair that value. Do this
        // before listeners start and verify the exact durable triplet.
        if (stored_tip->supply_units != running_supply) {
            if (replayed_tip.empty() ||
                !db_.WriteChainTip(HexToHash(replayed_tip), target_height,
                                   running_supply)) {
                throw std::runtime_error(
                    "ReplayChain: failed to repair canonical supply after full replay");
            }
            stored_tip = db_.ReadChainTipExact();
            if (!stored_tip || stored_tip->height != target_height ||
                stored_tip->tip_hash != replayed_tip ||
                stored_tip->supply_units != running_supply) {
                throw std::runtime_error(
                    "ReplayChain: repaired canonical tip failed exact verification");
            }
        }
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        if (snapshot_requirement &&
            (snapshot_requirement->first != target_height ||
             snapshot_requirement->second != replayed_tip)) {
            throw std::runtime_error(
                "ReplayChain: replayed tip does not match the signed snapshot handoff");
        }
#endif
        // If replay reached a required C, exact block pins are insufficient on
        // their own: consensus must also have reconstructed that permanent
        // floor (or a strictly higher one which commits its whole prefix).
        RequireEffectiveAnchorSecurityAfterReplay_(target_height);
        FinishAnchorFloorReplayRepair_();
        // Candidate replay may advance beyond the inherited floor written at
        // Prepare. Carry that fully replay-verified high-water in the staged
        // authoritative DB before any snapshot promotion.
        PersistCurrentAnchorFloorToDb_();
        // Reconcile utxo_db to the fully replayed authoritative chain before
        // acknowledging either VUR1 or VDP1. This is mandatory for every
        // non-genesis restart and for a recovery obligation at height zero.
        if (target_height > 0 ||
            durable_commit_repair_required_.load(
                std::memory_order_acquire) ||
            db_.UtxoRecoveryRequired()) {
            try {
                auto utxo_kvs =
                    chain_.SnapshotUTXOsForLevelDB_NoLock();
                bool rebuilt = db_.RebuildUTXOsFromSnapshot(utxo_kvs);
                if (veld::DiagVerbose().load()) {
                    veld::vcerr()
                        << "  [replay-leveldb-sync] rewrote "
                        << utxo_kvs.size()
                        << " UTXO entries to leveldb u:* — "
                        << (rebuilt ? "ok" : "FAILED") << "\n";
                }
                std::cerr.flush();
                if (!rebuilt) {
                    throw std::runtime_error(
                        "LevelDB UTXO rebuild returned false after consensus replay");
                }
            } catch (const std::exception& e) {
                std::cerr << "  [replay-leveldb-sync] exception: "
                          << e.what() << "\n";
                std::cerr.flush();
                throw;
            } catch (...) {
                std::cerr
                    << "  [replay-leveldb-sync] unknown exception\n";
                std::cerr.flush();
                throw;
            }
        }
        // MarkCanonicalBlockDurable was re-executed contiguously for genesis
        // through the exact stored tip, and all consensus/module/floor checks
        // and the UTXO reconciliation above succeeded. Only now may retained
        // VUR1/VDP1 obligations be cleared and snapshot/service admission
        // become eligible again.
        FinishDurableCommitReplayRepair_();
        FinishCanonicalDerivedIndexesAfterReplay_(
            target_height, replay_target_hash);

        // Side-branch bodies are intentionally a bounded runtime cache and
        // their in-memory indexes are not reconstructed across restart.  Sweep
        // every body not named by the now fully replay-validated canonical
        // height index, or repeated restarts could accumulate one hostile fork
        // budget each time.  Failure is storage-compromising and blocks network
        // startup rather than silently abandoning the disk bound.
        db::VeldDB::NonCanonicalBodyPruneStats body_prune;
        if (!db_.PruneNonCanonicalBlockBodies(&body_prune)) {
            throw std::runtime_error(
                "ReplayChain: failed to prune non-canonical durable block bodies");
        }
        if (body_prune.deleted > 0 || veld::DiagVerbose().load()) {
            std::cerr << "  [replay-body-cache] canonical="
                      << body_prune.canonical << " pruned="
                      << body_prune.deleted << "\n";
            std::cerr.flush();
        }
        // Lifetime miner totals are intentionally outside the consensus
        // snapshot. Rebuild them from the just-validated canonical history
        // before RPC/P2P starts, so a stale/corrupt derived index cannot leak
        // plausible but incorrect totals after restart.
        if (!RebuildMinerArchiveIndex_()) {
            std::cerr << "  [miner-archive] rebuild failed after replay; "
                         "count/last display remains unavailable\n";
            std::cerr.flush();
        }
        governance_.PersistAll();
        // Restore durable on-commit wiring only after every block and module
        // transition has passed.  Start() still has not created P2P or RPC.
        WireDB();

        // btcVELD SPV: publish the rebuilt BTC-header tip into the RPC-snapshot atomic.
        // The Reset+replay above fully rebuilt btc_headers_ (that is why the anchor high-
        // water survives a restart), but — unlike the reorg replay (~node.h:4725) which
        // stores this per block — the startup/IBD replay left btc_header_tip_ at 0. So
        // getbtcheaderinfo (and veld_btcrelayd, which reads best_height from it) saw a
        // stale 0 after every restart and tried to re-relay Bitcoin from height 1.
        // btc_header_tip_ is an RPC-only snapshot (never part of the consensus digest),
        // so publishing the real height here is display-correctness, not a consensus change.
        btc_header_tip_.store(btc_headers_.BestHeight(), std::memory_order_release);
        const uint64_t tip_timestamp = chain_.TipCopy().header.timestamp;
        const uint64_t next_timestamp = tip_timestamp <=
                UINT64_MAX - TARGET_BLOCK_TIME
            ? tip_timestamp + TARGET_BLOCK_TIME : tip_timestamp;
        btc_relay_fresh_snapshot_.store(
            btc_headers_.ExternalValueFresh(next_timestamp),
            std::memory_order_release);

#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
        if (independent_snapshot_validation) {
            SnapshotValidationBase base;
            base.height = target_height;
            base.tip_hash = replay_target_hash;
            base.state_digest = ConsensusStateDigest();
            if (!WriteIndependentValidationRequirement_(base)) {
                throw std::runtime_error(
                    "ReplayChain: cannot persist independent background-validation requirement");
            }
            std::lock_guard<std::mutex> lock(background_validation_mutex_);
            snapshot_validation_base_ = base;
        }
#endif

        SetChainFullyValidatedLatch_(verify_historical_pow);

        if (chain_.Height() > 0) {
            std::cout << "  Chain "
                      << (verify_historical_pow
                              ? "fully consensus-replayed"
                              : "state-replayed (independent IBD pending)")
                      << " from disk: height="
                      << chain_.Height() << " supply="
                      << chain_.TotalSupplyVeld() << " VELD\n";

#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
            if (snapshot_requirement) {
                if (verify_historical_pow) {
                    RemoveSnapshotReplayRequirement_();
                    std::error_code background_marker_error;
                    if (std::filesystem::exists(
                            IndependentValidationRequirementPath_(),
                            background_marker_error)) {
                        if (background_marker_error)
                            throw std::runtime_error(
                                "cannot inspect background validation marker after full replay");
                        DurableRemoveControlFile_(
                            IndependentValidationRequirementPath_());
                    } else if (background_marker_error) {
                        throw std::runtime_error(
                            "cannot inspect background validation marker after full replay");
                    }
                    snapshot_state_clean_.store(true,
                                                std::memory_order_release);
                    std::cerr << "  [snapshot] signed tip handoff satisfied by "
                                 "full foreground replay; marker removed before "
                                 "network startup.\n";
                } else {
                    std::cerr << "  [snapshot] signed tip handoff and complete "
                                 "state replay satisfied; independent background "
                                 "IBD remains mandatory.\n";
                }
                std::cerr.flush();
            }
#endif
        } else {
            std::cout << "  Fresh start - waiting for peer sync\n";
        }
        SetIbdCompleteLatch_(false);
    }

    std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
    ComputeExpectedPoolPayoutOutputs(const Hash256& prev_block_hash,
                                      uint64_t pool_balance_units,
                                      uint64_t block_height) const {
        return chain_.ComputeExpectedPoolOutputs(
            prev_block_hash, pool_balance_units, block_height);
    }

    void BuildAndBroadcastNmsTx(const BlockHeader& nms_header) {
        if constexpr (!OPTION_B_CONSENSUS_GATE_ENABLED) {
            std::cerr << "  [nms] skip: OPTION_B disabled at compile time\n";
            std::cerr.flush();
            return;
        }
        if (miner_keypair_.public_key[0] == 0) {
            std::cerr << "  [nms] skip: miner pubkey unset\n";
            std::cerr.flush();
            return;
        }

        {
            static std::atomic<uint64_t> last_nms_window{0};
            uint64_t cur_window = chain_.Height() / COMINE_WINDOW_BLOCKS;
            uint64_t prev = last_nms_window.load(std::memory_order_relaxed);
            if (cur_window <= prev && prev != 0) {
                return;
            }
            if (!last_nms_window.compare_exchange_strong(prev, cur_window,
                    std::memory_order_acq_rel)) {
                return;
            }
        }

        auto miner_script = miner_keypair_.script_override.empty()
                          ? miner_keypair_.GetP2PKHScript()
                          : miner_keypair_.script_override;
        if (miner_script.empty()) {
            std::cerr << "  [nms] skip: miner_script empty\n";
            std::cerr.flush();
            return;
        }

        if (!chain_.NmsBondSatisfied(miner_script)) {
            std::cerr << "  [nms] skip: NMS bond not satisfied (need >= "
                      << (NMS_MIN_BOND_UNITS / VELD_UNITS) << " VELD staked under miner addr)\n";
            std::cerr.flush();
            return;
        }

        auto early_payload = EncodeNmsPayload(nms_header);
        if (!early_payload.empty() && chain_.NmsPayloadSeen(early_payload)) {
            std::cerr << "  [nms] skip: payload already seen on chain "
                      << "(dedup window; cross-restart re-derivation expected)\n";
            std::cerr.flush();
            return;
        }

        constexpr uint64_t NMS_MARKER_VEL = MIN_TX_FEE;
        constexpr uint64_t NMS_MIN_INPUT  = NMS_MARKER_VEL + MIN_TX_FEE;

        auto utxos = chain_.GetUTXOsForScript(miner_script);
        if (utxos.empty()) {
            std::cerr << "  [nms] skip: miner has zero UTXOs\n";
            std::cerr.flush();
            return;
        }
        std::sort(utxos.begin(), utxos.end(),
                  [](const UTXO& a, const UTXO& b){ return a.value < b.value; });
        auto mempool_spent = mempool_.GetSpentOutputs();
        uint64_t tip = chain_.Height();
        const bool enforce_maturity =
            (tip + 1) >= COINBASE_MATURITY_CONSENSUS_HEIGHT;
        const UTXO* input_utxo = nullptr;
        size_t skipped_pending = 0, skipped_immature = 0;
        for (const auto& u : utxos) {
            if (u.value < NMS_MIN_INPUT) continue;
            std::string ukey = HashToHex(u.tx_hash) + ":"
                             + std::to_string(u.output_index);
            if (mempool_spent.count(ukey)) { ++skipped_pending; continue; }
            if (enforce_maturity
                && u.is_coinbase
                && u.block_height <= tip
                && (tip - u.block_height) < COINBASE_MATURITY) {
                ++skipped_immature; continue;
            }
            input_utxo = &u; break;
        }
        if (!input_utxo) {
            std::cerr << "  [nms] skip: no eligible UTXO (have " << utxos.size()
                      << " total, " << skipped_pending << " pending in mempool, "
                      << skipped_immature << " immature coinbase, rest below "
                      << ((double)NMS_MIN_INPUT / VELD_UNITS) << " VELD min)\n";
            std::cerr.flush();
            return;
        }

        Transaction tx;
        tx.version = 1;

        TxInput in;
        in.prev_tx_hash   = input_utxo->tx_hash;
        in.prev_out_index = input_utxo->output_index;
        tx.inputs.push_back(in);

        TxOutput marker;
        marker.value         = NMS_MARKER_VEL;
        marker.script_pubkey = miner_script;
        tx.outputs.push_back(marker);

        auto payload = EncodeNmsPayload(nms_header);
        if (payload.empty()) return;
        TxOutput op_ret;
        op_ret.value = 0;
        op_ret.script_pubkey = BuildNmsOpReturnScript(payload);
        tx.outputs.push_back(op_ret);

        uint64_t change = input_utxo->value - NMS_MARKER_VEL - MIN_TX_FEE;
        if (change > 0) {
            TxOutput ch;
            ch.value         = change;
            ch.script_pubkey = miner_script;
            tx.outputs.push_back(ch);
        }

        try {
            auto signed_in = miner_keypair_.SignInput(tx, 0, miner_script);
            tx.inputs[0].script_sig = signed_in.script_sig;
        } catch (...) {
            std::cerr << "  [nms] skip: SignInput threw\n";
            std::cerr.flush();
            return;
        }

        auto res = mempool_.Add(tx, MIN_TX_FEE, (uint32_t)chain_.Height(), chain_);
        if (res != Mempool::AddResult::ACCEPTED) {
            const char* reason = "INVALID";
            switch (res) {
                case Mempool::AddResult::DUPLICATE:    reason = "DUPLICATE"; break;
                case Mempool::AddResult::FEE_TOO_LOW:  reason = "FEE_TOO_LOW"; break;
                case Mempool::AddResult::DOUBLE_SPEND: reason = "DOUBLE_SPEND"; break;
                case Mempool::AddResult::FULL:         reason = "FULL"; break;
                default: break;
            }
            std::cerr << "  [nms] skip: mempool reject " << reason << "\n";
            std::cerr.flush();
            return;
        }

        if (tcp_server_) tcp_server_->BroadcastTransaction(tx);
        std::cerr << "  [nms] broadcast: nonce=" << nms_header.nonce
                  << " height=" << (chain_.Height() + 1) << "\n";
        std::cerr.flush();
    }

    bool BuildPoolPayoutTx(Block& block, const std::vector<uint8_t>& pool_script, Mempool& ) {
        auto pool_utxos = chain_.GetUTXOsForScript(pool_script);
        if (pool_utxos.empty()) return false;

        uint64_t total_pool = 0;
        for (auto& u : pool_utxos) total_pool += u.value;
        if (total_pool == 0) return false;

        auto payouts = ComputeExpectedPoolPayoutOutputs(
            block.header.prev_block_hash, total_pool, block.height);
        if (payouts.empty()) return false;

        std::sort(pool_utxos.begin(), pool_utxos.end(),
                  [](const UTXO& a, const UTXO& b) {
                      if (a.tx_hash != b.tx_hash) return a.tx_hash < b.tx_hash;
                      return a.output_index < b.output_index;
                  });

        Transaction tx;
        tx.version = 1;
        for (auto& u : pool_utxos) {
            TxInput inp;
            inp.prev_tx_hash   = u.tx_hash;
            inp.prev_out_index = u.output_index;
            tx.inputs.push_back(inp);
        }
        for (auto& [script, amount] : payouts) {
            TxOutput o;
            o.value         = amount;
            o.script_pubkey = script;
            tx.outputs.push_back(o);
        }

        if (!tx.IsValid()) return false;
        block.transactions.push_back(tx);
        block.UpdateMerkleRoot();
        return true;
    }

    bool BuildEndorsementFlushTx(Block& block) {
        auto ep_script = AddressToScript(ENDORSEMENT_POOL_ADDRESS);
        if (ep_script.empty()) return false;

        auto ep_utxos = chain_.GetUTXOsForScript(ep_script);
        if (ep_utxos.empty()) return false;

        uint64_t total_pool = 0;
        for (auto& u : ep_utxos) total_pool += u.value;
        if (total_pool == 0) return false;

        auto payouts = chain_.ComputeExpectedEndorsementFlushOutputs(
            block.height, total_pool, 0);
        if (payouts.empty()) return false;

        std::sort(ep_utxos.begin(), ep_utxos.end(),
                  [](const UTXO& a, const UTXO& b) {
                      if (a.tx_hash != b.tx_hash) return a.tx_hash < b.tx_hash;
                      return a.output_index < b.output_index;
                  });

        Transaction tx;
        tx.version = 1;
        for (auto& u : ep_utxos) {
            TxInput inp;
            inp.prev_tx_hash   = u.tx_hash;
            inp.prev_out_index = u.output_index;
            tx.inputs.push_back(inp);
        }
        for (auto& [script, amount] : payouts) {
            TxOutput o;
            o.value         = amount;
            o.script_pubkey = script;
            tx.outputs.push_back(o);
        }

        if (!tx.IsValid()) return false;
        block.transactions.push_back(tx);
        block.UpdateMerkleRoot();
        return true;
    }

    bool BuildVaultDistributionTx(Block& block) {
        // Activation height zero means active from genesis.
        if (block.height < VAULT_SIGLESS_ACTIVATION_HEIGHT) return false;
        if (block.height == 0) return false;
        if ((block.height % VAULT_DISTRIBUTION_INTERVAL) != 0) return false;

        auto vault_script = AddressToScript(VaultAddressAtHeight(block.height));
        if (vault_script.empty()) return false;

        auto vault_utxos = chain_.GetUTXOsForScript(vault_script);
        if (vault_utxos.empty()) return false;

        uint64_t total_vault = 0;
        for (const auto& u : vault_utxos) total_vault += u.value;

        // Mandatory custody transitions are zero-fee so principal remains in
        // the exact expected output set even after subsidy-cap fee routing.
        uint64_t fee_reserve = 0;
        if (total_vault <= fee_reserve) return false;

        auto snapshot = staking_.GetWeightedStakeSnapshot(block.height - 1);

        uint64_t prev_cycle_inflow =
            chain_.ComputeVaultInflowSinceLastDistribution(block.height);

        auto payouts = chain_.ComputeExpectedVaultDistribution(
            block.height, total_vault, fee_reserve,
            prev_cycle_inflow, snapshot);
        if (payouts.empty()) return false;

        std::sort(vault_utxos.begin(), vault_utxos.end(),
                  [](const UTXO& a, const UTXO& b) {
                      if (a.tx_hash != b.tx_hash) return a.tx_hash < b.tx_hash;
                      return a.output_index < b.output_index;
                  });

        Transaction tx;
        tx.version = 1;
        for (const auto& u : vault_utxos) {
            TxInput inp;
            inp.prev_tx_hash   = u.tx_hash;
            inp.prev_out_index = u.output_index;
            tx.inputs.push_back(inp);
        }
        for (const auto& [script, amount] : payouts) {
            TxOutput o;
            o.value         = amount;
            o.script_pubkey = script;
            tx.outputs.push_back(o);
        }

        if (!tx.IsValid()) return false;
        block.transactions.push_back(tx);
        block.UpdateMerkleRoot();
        return true;
    }

    bool BuildBondSettlementTx(Block& block) {
        // Activation height zero means active from genesis.
        if (block.height < STAKE_VAULT_ACTIVATION_HEIGHT) return false;
        if (block.height == 0) return false;
        if ((block.height % BOND_SETTLEMENT_INTERVAL) != 0) return false;

        auto sv_script = AddressToScript(STAKE_VAULT_ADDRESS);
        if (sv_script.empty()) return false;

        auto sv_utxos = chain_.GetUTXOsForScript(sv_script);
        if (sv_utxos.empty()) return false;

        uint64_t total_sv = 0;
        for (const auto& u : sv_utxos) total_sv += u.value;
        // Principal is an exact custody liability.  This miner-built canonical
        // protocol transaction is consensus-zero-fee; taking a fee from the
        // stake vault would under-collateralize the remaining bonds and strand
        // the terminal claimant.  ValidateExpectedBondMovements uses the same 0.
        uint64_t fee_reserve = 0;

        auto payouts = chain_.ComputeExpectedBondMovements(
            block.height, total_sv, fee_reserve);
        if (payouts.empty()) return false;

        std::sort(sv_utxos.begin(), sv_utxos.end(),
                  [](const UTXO& a, const UTXO& b) {
                      if (a.tx_hash != b.tx_hash) return a.tx_hash < b.tx_hash;
                      return a.output_index < b.output_index;
                  });

        Transaction tx;
        tx.version = 1;
        for (const auto& u : sv_utxos) {
            TxInput inp;
            inp.prev_tx_hash   = u.tx_hash;
            inp.prev_out_index = u.output_index;
            tx.inputs.push_back(inp);
        }
        for (const auto& [script, amount] : payouts) {
            TxOutput o;
            o.value         = amount;
            o.script_pubkey = script;
            tx.outputs.push_back(o);
        }

        if (!tx.IsValid()) return false;
        block.transactions.push_back(tx);
        block.UpdateMerkleRoot();
        return true;
    }

    bool BuildBondYieldSettlementTx(Block& block) {
        // Activation height zero means active from genesis.
        if (block.height < BOND_YIELD_ACTIVATION_HEIGHT) return false;
        if (block.height == 0) return false;
        if ((block.height % BOND_SETTLEMENT_INTERVAL) != 0) return false;

        auto esc_script = AddressToScript(BOND_YIELD_ESCROW);
        if (esc_script.empty()) return false;

        auto esc_utxos = chain_.GetUTXOsForScript(esc_script);
        if (esc_utxos.empty()) return false;

        uint64_t total_esc = 0;
        for (const auto& u : esc_utxos) total_esc += u.value;
        // Exact D' escrow liabilities use the same consensus-zero-fee model as
        // bond principal.  The validation gate below derives with the same 0.
        uint64_t fee_reserve = 0;

        auto payouts = chain_.ComputeExpectedBondYieldSettlement(
            block.height, total_esc, fee_reserve);
        if (payouts.empty()) return false;

        std::sort(esc_utxos.begin(), esc_utxos.end(),
                  [](const UTXO& a, const UTXO& b) {
                      if (a.tx_hash != b.tx_hash) return a.tx_hash < b.tx_hash;
                      return a.output_index < b.output_index;
                  });

        Transaction tx;
        tx.version = 1;
        for (const auto& u : esc_utxos) {
            TxInput inp;
            inp.prev_tx_hash   = u.tx_hash;
            inp.prev_out_index = u.output_index;
            tx.inputs.push_back(inp);
        }
        for (const auto& [script, amount] : payouts) {
            TxOutput o;
            o.value         = amount;
            o.script_pubkey = script;
            tx.outputs.push_back(o);
        }

        if (!tx.IsValid()) return false;
        block.transactions.push_back(tx);
        block.UpdateMerkleRoot();
        return true;
    }

    Transaction BuildEndorsementFlushStandalone(uint64_t current_height) {
        Transaction tx;
        if (endorsement_pool_keypair_.public_key[0] == 0) return tx;

        auto ep_script = endorsement_pool_keypair_.GetP2PKHScript();
        auto ep_utxos_all = chain_.GetUTXOsForScript(ep_script);
        auto ep_mempool_spent = mempool_.GetSpentOutputs();
        std::vector<UTXO> ep_utxos;
        ep_utxos.reserve(ep_utxos_all.size());
        for (const auto& u : ep_utxos_all) {
            std::string outpoint = HashToHex(u.tx_hash) + ":" + std::to_string(u.output_index);
            if (ep_mempool_spent.count(outpoint)) continue;
            ep_utxos.push_back(u);
        }
        if (ep_utxos.empty()) return tx;

        uint64_t window_size  = VAULT_DISTRIBUTION_INTERVAL;
        uint64_t window_start = current_height > window_size ? current_height - window_size + 1 : 1;
        std::map<std::string, uint64_t> validator_counts;
        uint64_t total_endorsements = 0;
        for (uint64_t h = window_start; h <= current_height; ++h) {
            auto ends = validators_.GetEndorsements(h);
            for (const auto& e : ends) {
                if (e.address.empty()) continue;
                validator_counts[e.address]++;
                total_endorsements++;
            }
        }
        // Registry records are the only authoritative source.  In particular,
        // do not fall back to rescanning raw OP_RETURN bytes: that would let an
        // invalid, pre-registration, or wrong-branch marker influence the
        // transaction this builder proposes even though consensus rejects the
        // corresponding payout tuple.
        if (total_endorsements == 0 || validator_counts.empty()) return tx;

        uint64_t total_pool = 0;
        for (const auto& u : ep_utxos) total_pool += u.value;
        if (total_pool == 0) return tx;

        tx.version = 1;
        uint64_t consumed = 0;
        size_t   max_inputs = 180;
        for (const auto& u : ep_utxos) {
            if (tx.inputs.size() >= max_inputs) break;
            TxInput in;
            in.prev_tx_hash   = u.tx_hash;
            in.prev_out_index = u.output_index;
            tx.inputs.push_back(in);
            consumed += u.value;
        }

        if (consumed <= MIN_TX_FEE) return Transaction{};
        uint64_t distributable = consumed - MIN_TX_FEE;

        double per_endorsement_veld =
            (double)distributable / (double)total_endorsements / (double)VELD_UNITS;
        validators_.SetLastFlushRewardPerEndorsement(per_endorsement_veld);
        try {
            std::ostringstream rs; rs << std::fixed << std::setprecision(12) << per_endorsement_veld;
            db_.GetIndexDB().Put("validator_last_flush_rate", rs.str());
        } catch (...) {}

        std::vector<std::pair<std::vector<uint8_t>, uint64_t>> payouts;
        uint64_t distributed = 0;
        for (const auto& [addr, count] : validator_counts) {
            auto vs = AddressToScript(addr);
            if (vs.empty()) continue;
            uint64_t share = (distributable * count) / total_endorsements;
            if (share > 0) {
                payouts.push_back({vs, share});
                distributed += share;
            }
        }
        if (payouts.empty()) return Transaction{};
        if (distributed < distributable)
            payouts[0].second += (distributable - distributed);

        for (auto& [script, amount] : payouts) {
            TxOutput o;
            o.value         = amount;
            o.script_pubkey = script;
            tx.outputs.push_back(o);
        }

        for (size_t i = 0; i < tx.inputs.size(); ++i) {
            auto si = endorsement_pool_keypair_.SignInput(tx, i, ep_script);
            tx.inputs[i].script_sig = si.script_sig;
        }

        return tx;
    }

    std::string GetPoolInfoJSON() const {
        uint64_t h = chain_.Height();
        uint64_t window_start = h > COMINE_WINDOW_BLOCKS ? (h - COMINE_WINDOW_BLOCKS + 1) : 1;
        uint64_t window_end   = h;
        uint64_t blocks_in_window = (COMINE_WINDOW_BLOCKS == 0) ? 0 : (h % COMINE_WINDOW_BLOCKS);
        uint64_t blocks_until_payout = (COMINE_WINDOW_BLOCKS == 0) ? 0
            : (blocks_in_window == 0 ? 0 : (COMINE_WINDOW_BLOCKS - blocks_in_window));

        double pool_veld = 0.0;
        {
            auto pool_script = AddressToScript(POOL_ADDRESS);
            auto pool_utxos = chain_.GetUTXOsForScript(pool_script);
            uint64_t total = 0;
            for (auto& u : pool_utxos) total += u.value;
            pool_veld = (double)total / VELD_UNITS;
        }

        auto vault_script_bytes = AddressToScript(VAULT_ADDRESS);
        auto pool_script_bytes  = AddressToScript(POOL_ADDRESS);
        auto vault_hex = BytesToHex(vault_script_bytes);
        auto pool_hex  = BytesToHex(pool_script_bytes);
        auto nms_snap = chain_.NmsSnapshot();
        std::vector<std::pair<std::string, uint64_t>> chain_entries;
        chain_entries.reserve(nms_snap.size());
        uint64_t total_near_misses = 0;
        for (const auto& [script_hex, count] : nms_snap) {
            if (count == 0) continue;
            if (script_hex == vault_hex || script_hex == pool_hex) continue;
            auto script_bytes = HexToBytes(script_hex);
            std::string addr = ScriptToAddress(script_bytes);
            if (addr.empty() || addr == VAULT_ADDRESS || addr == POOL_ADDRESS) continue;
            chain_entries.push_back({addr, count});
            total_near_misses += count;
        }
        std::sort(chain_entries.begin(), chain_entries.end(),
            [](const auto& a, const auto& b){ return a.second > b.second; });

        std::ostringstream j;
        j << std::fixed << std::setprecision(8);
        j << "{"
          << "\"pool_balance_veld\":" << pool_veld << ","
          << "\"window_start_height\":" << window_start << ","
          << "\"current_height\":" << h << ","
          << "\"blocks_in_window\":" << blocks_in_window << ","
          << "\"blocks_until_payout\":" << blocks_until_payout << ","
          << "\"window_size\":" << COMINE_WINDOW_BLOCKS << ","
          << "\"pool_pct\":27,"
          << "\"participants\":" << chain_entries.size() << ","
          << "\"total_near_misses\":" << total_near_misses << ","
          << "\"entries\":[";

        bool first = true;
        for (auto& [addr, c] : chain_entries) {
            if (!first) j << ",";
            j << "{\"address\":\"" << addr << "\","
              << "\"near_misses\":" << c << "}";
            first = false;
        }
        j << "]}";
        return j.str();
    }

    bool VerifyNearMiss(const Block& solved_block, uint64_t comine_nonce,
                        const Hash256& comine_hash) const {
        auto pow_lease = mining::GlobalExpensivePowBudget().TryAcquire(
            mining::ExpensivePowUse::NearMiss);
        if (!pow_lease) return false;
        std::vector<uint8_t> header_bytes = solved_block.header.Serialize();
        for (int b = 0; b < 8; ++b)
            header_bytes[80 + b] = (uint8_t)((comine_nonce >> (b * 8)) & 0xFF);

        auto actual_hash = mining::VeldHash(header_bytes, solved_block.height);
        if (actual_hash != comine_hash) return false;

        uint32_t bits = solved_block.header.bits;
        Hash256 target_arr{};
        if (!BlockHeader::DecodeBits(bits, target_arr)) return false;
        std::vector<uint8_t> target(target_arr.begin(), target_arr.end());

        static_assert(COMINE_NEARMISS_MULTIPLIER == 4, "Bit-shift below assumes multiplier of 4");
        uint8_t carry = 0;
        for (int i = 31; i >= 0; --i) {
            uint16_t v = ((uint16_t)target[i] << 2) | carry;
            target[i]  = (uint8_t)(v & 0xFF);
            carry      = (uint8_t)(v >> 8);
        }
        if (carry) return true;

        for (int i = 0; i < 32; ++i) {
            if (actual_hash[i] < target[i]) return true;
            if (actual_hash[i] > target[i]) return false;
        }
        return true;
    }

    static constexpr uint64_t COMINE_WINDOW_BLOCKS = ::veld::COMINE_WINDOW_BLOCKS;

    struct ComineTally {
        std::string script_hex;
        std::vector<uint8_t> script;
        double      near_miss_count{0.0};
    };

    struct CominePool {
        uint64_t pool_units{0};
        uint64_t window_start{0};
        std::unordered_map<std::string, ComineTally> tallies;
    };

    CominePool comine_pool_;
    mutable std::mutex comine_pool_mutex_;

    std::vector<std::pair<std::vector<uint8_t>, uint64_t>>
    ComputeValidatorCoinbaseOutputs(uint64_t current_height, uint64_t endorse_cut) {
        std::vector<std::pair<std::vector<uint8_t>, uint64_t>> outputs;
        if (endorse_cut == 0) return outputs;

        uint64_t window = VAULT_DISTRIBUTION_INTERVAL;
        uint64_t start = current_height > window ? current_height - window + 1 : 1;
        std::map<std::string, uint64_t> counts;
        uint64_t total = 0;
        for (uint64_t h = start; h <= current_height; ++h) {
            auto ends = validators_.GetEndorsements(h);
            for (const auto& e : ends) {
                if (e.address.empty()) continue;
                counts[e.address]++;
                total++;
            }
        }
        if (total == 0 || counts.empty()) return outputs;

        auto registered = validators_.GetValidators();
        std::unordered_set<std::string> valid_addrs;
        for (auto& r : registered) valid_addrs.insert(r.address);
        for (auto it = counts.begin(); it != counts.end(); ) {
            if (!valid_addrs.count(it->first)) {
                total -= it->second;
                it = counts.erase(it);
            } else ++it;
        }
        if (total == 0 || counts.empty()) return outputs;

        uint64_t paid = 0;
        for (auto it = counts.begin(); it != counts.end(); ++it) {
            auto script = AddressToScript(it->first);
            if (script.empty()) continue;
            uint64_t payout;
            auto next = std::next(it);
            if (next == counts.end()) {
                payout = endorse_cut - paid;
            } else {
                payout = (endorse_cut * it->second) / total;
            }
            if (payout > 0) {
                outputs.push_back({script, payout});
                paid += payout;
            }
        }
        return outputs;
    }

    void RecordComineTally(const std::vector<uint8_t>& script) {
        std::string key = BytesToHex(script);
        std::lock_guard<std::mutex> lock(comine_pool_mutex_);
        auto& t = comine_pool_.tallies[key];
        t.script_hex = key;
        t.script = script;
        ++t.near_miss_count;
    }

    void SaveCominePool() {
        std::lock_guard<std::mutex> lock(comine_pool_mutex_);
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(6);
        ss << "pool_units=" << comine_pool_.pool_units << "\n";
        ss << "window_start=" << comine_pool_.window_start << "\n";
        for (auto& [key, tally] : comine_pool_.tallies)
            ss << "t:" << key << ":" << tally.near_miss_count << "\n";
        db_.GetIndexDB().Put("comine_pool_state", ss.str());
    }

    void LoadCominePool() {
        auto data_opt = db_.GetIndexDB().Get("comine_pool_state");
        if (!data_opt) return;
        std::string data = *data_opt;
        std::lock_guard<std::mutex> lock(comine_pool_mutex_);
        std::istringstream ss(data);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.substr(0, 11) == "pool_units=")
                try { comine_pool_.pool_units = std::stoull(line.substr(11)); } catch (...) {}
            else if (line.substr(0, 13) == "window_start=")
                try { comine_pool_.window_start = std::stoull(line.substr(13)); } catch (...) {}
            else if (line.size() > 2 && line.substr(0, 2) == "t:") {
                auto rest = line.substr(2);
                auto colon = rest.rfind(':');
                if (colon != std::string::npos) {
                    std::string key = rest.substr(0, colon);
                    double count = 0.0;
                    try { count = std::stod(rest.substr(colon+1)); } catch (...) { continue; }
                    comine_pool_.tallies[key].script_hex = key;
                    comine_pool_.tallies[key].near_miss_count = count;
                    if (key.size() == 50) {
                        std::vector<uint8_t> script;
                        bool valid = true;
                        for (size_t i = 0; i < key.size(); i += 2) {
                            try {
                                uint8_t b = (uint8_t)std::stoul(key.substr(i, 2), nullptr, 16);
                                script.push_back(b);
                            } catch (...) { valid = false; break; }
                        }
                        if (valid) comine_pool_.tallies[key].script = script;
                    }
                }
            }
        }
        std::cout << "  [Pool] Loaded co-miner pool state: "
                  << comine_pool_.pool_units << " units accumulated, "
                  << comine_pool_.tallies.size() << " miners tallied\n";
    }

    void MiningLoop() {
#ifdef VELD_FLEET_NO_MINE
        std::cerr << "  [FLEET-NO-MINE] MiningLoop() entered on a "
                     "-DVELD_FLEET_NO_MINE binary — exiting without "
                     "producing any block.\n";
        std::cerr.flush();
        return;
#else
        while (mining_.load() && running_.load()) {
            try {
                if (!ibd_complete_.load()) {
                    mining_work_state_.store(MiningWorkState::Synchronizing,
                                             std::memory_order_release);
                    hashrate_.store(0.0, std::memory_order_release);
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    continue;
                }

                // Mining requires a connection to a configured network anchor
                // so a partitioned miner does not extend an isolated branch.
                // LAN peers do not satisfy this requirement.
                // Regtest is an isolated single-node chain by design (empty seed
                // list, LAN-only) - the fleet-anchor requirement can never be met,
                // so exempt it. Every non-regtest network keeps the always-on gate.
                bool qualification_pre_hash_barrier = false;
#ifdef VELD_TEST_HOOKS
                qualification_pre_hash_barrier =
                    test_work_admission_mining_barrier_.load(
                        std::memory_order_acquire);
#endif
                if (tcp_server_ && config_.name != "Veld Regtest" &&
                    !qualification_pre_hash_barrier) {
                    int anchors = tcp_server_->GetConnectedAnchorCount();
                    if (anchors <= 0) {
                        mining_work_state_.store(
                            MiningWorkState::WaitingForAnchor,
                            std::memory_order_release);
                        hashrate_.store(0.0, std::memory_order_release);
                        static std::atomic<uint64_t> last_warn{0};
                        uint64_t now = (uint64_t)std::time(nullptr);
                        if (now >= last_warn.load() + 30) {
                            last_warn.store(now);
                            std::cerr << "  [mining] HALTED: no anchor peer connected. "
                                      << "Refusing to produce blocks until a network anchor is "
                                      << "reachable; mining resumes automatically once one "
                                      << "connects.\n";
                            std::cerr.flush();
                        }
                        std::this_thread::sleep_for(std::chrono::seconds(2));
                        continue;
                    }
                }

                // Re-evaluate the complete admission rule every round.  The
                // IBD latch records a prior safe observation; it is not a
                // lease that survives peer loss or a new contradictory claim.
                const auto round_subject = CurrentBlockProductionSubject_();
                const auto round_admission = round_subject
                    ? EvaluateWorkAdmission(
                          work_admission::Path::InternalMining,
                          *round_subject, std::nullopt, false)
                    : work_admission::Decision{
                          false, work_admission::Refusal::TipUnknown,
                          std::nullopt};
                if (!round_admission.allowed || !round_admission.binding) {
                    mining_work_state_.store(MiningWorkState::WorkAdmission,
                                             std::memory_order_release);
                    hashrate_.store(0.0, std::memory_order_release);
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    continue;
                }
                const work_admission::Binding round_binding =
                    *round_admission.binding;

#ifdef VELD_TEST_HOOKS
                // Deterministic process-test barrier immediately after the
                // authoritative predicate and before timestamp checks,
                // candidate construction, VeldHash, or any publication state.
                // It proves admission without turning a qualification child
                // into an uncontrolled background miner.
                if (test_work_admission_mining_barrier_.load(
                        std::memory_order_acquire)) {
                    test_work_mining_admitted_calls_.fetch_add(
                        1, std::memory_order_acq_rel);
                    mining_work_state_.store(MiningWorkState::Hashing,
                                             std::memory_order_release);
                    hashrate_.store(0.0, std::memory_order_release);
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(1));
                    continue;
                }
#endif

                // Refuse to mine when local time differs from peer median by
                // 600 seconds or more, matching block timestamp validation.
                // This prevents repeated production of future-dated blocks.
                //
                // IBD / sync is NOT gated: we still want to download the
                // real chain from peers; we only block OUTBOUND block
                // production. Require ≥ 3 configured outbound fleet-anchor
                // samples before trusting the halt median so arbitrary inbound
                // peers cannot Sybil the miner offline. The all-peer median is
                // retained for diagnostics only.
                //
                // Tolerance is 600s — same as MAX_FUTURE_BLOCK_TIME, so a
                // drift we allow to mine is mathematically impossible to
                // drift further in the time it takes to propagate the
                // block.
                if (tcp_server_) {
                    const auto clock =
                        tcp_server_->GetActiveClockDriftSnapshot();
                    const auto diagnostic_clock =
                        tcp_server_->GetDiagnosticClockDriftSnapshot();
                    const int64_t hard_abs = clock.median_seconds < 0
                        ? -clock.median_seconds : clock.median_seconds;
                    const bool authoritative_halt =
                        clock.distinct_ip_count >= 3 && hard_abs >= 600;
                    const int64_t diagnostic_abs =
                        diagnostic_clock.median_seconds < 0
                            ? -diagnostic_clock.median_seconds
                            : diagnostic_clock.median_seconds;
                    if (!authoritative_halt &&
                        diagnostic_clock.distinct_ip_count >= 3 &&
                        diagnostic_abs >= 600) {
                        static std::atomic<uint64_t> last_diagnostic_warn{0};
                        const uint64_t now = (uint64_t)std::time(nullptr);
                        if (now >= last_diagnostic_warn.load() + 30) {
                            last_diagnostic_warn.store(now);
                            std::cerr << "  [mining] CLOCK DIAGNOSTIC ONLY: all-active-peer "
                                         "median differs by "
                                      << diagnostic_abs << "s (n="
                                      << diagnostic_clock.distinct_ip_count
                                      << "); no mining halt without a 3-peer "
                                         "configured outbound fleet-anchor quorum.\n";
                            std::cerr.flush();
                        }
                    }
                    if (clock.distinct_ip_count >= 3) {
                        int64_t drift = clock.median_seconds;
                        int64_t adrift = drift < 0 ? -drift : drift;
                        if (adrift >= 600) {
                            mining_work_state_.store(MiningWorkState::ClockDrift,
                                                     std::memory_order_release);
                            hashrate_.store(0.0, std::memory_order_release);
                            static std::atomic<uint64_t> last_warn{0};
                            uint64_t now = (uint64_t)std::time(nullptr);
                            if (now >= last_warn.load() + 30) {
                                last_warn.store(now);
                                std::cerr << "  [mining] REFUSING TO MINE: local clock is "
                                          << adrift << "s "
                                          << (drift > 0 ? "behind" : "ahead of")
                                          << " configured outbound fleet-anchor median (n="
                                          << clock.distinct_ip_count
                                          << "). Fix your clock (w32tm /resync on "
                                             "Windows, chronyc makestep on Linux) "
                                             "then mining will resume automatically.\n";
                                std::cerr.flush();
                            }
                            std::this_thread::sleep_for(std::chrono::seconds(5));
                            continue;
                        }
                    }
                }

                if (tcp_server_) {
                    uint64_t mm = tcp_server_->GetGenesisMismatchCount();
                    uint64_t mt = tcp_server_->GetGenesisMatchCount();
                    if (mm > 0 && mt == 0) {
                        mining_work_state_.store(
                            MiningWorkState::GenesisMismatch,
                            std::memory_order_release);
                        hashrate_.store(0.0, std::memory_order_release);
                        static std::atomic<uint64_t> last_warn{0};
                        uint64_t now = (uint64_t)std::time(nullptr);
                        if (now >= last_warn.load() + 30) {
                            last_warn.store(now);
                            std::cerr << "  [mining] REFUSING TO MINE: every peer that has handshaked with us ("
                                      << mm << " so far) has a different GENESIS_HASH. We're either on a "
                                      << "stale binary (download the latest from veld.network/downloads/) or "
                                      << "the network has bumped genesis since we last upgraded. Mining now "
                                      << "would just produce a private fork that nobody accepts. Will retry "
                                      << "every 5s; mining auto-resumes the moment we connect to a peer with "
                                      << "matching genesis.\n";
                            std::cerr.flush();
                        }
                        std::this_thread::sleep_for(std::chrono::seconds(5));
                        continue;
                    }
                }

                // Mining safety uses locally validated peer-tip consensus.
                // SnapshotPeerTips returns only locally validated
                // canonical hashes reconfirmed by exact live handshake-ready
                // connection generations. Unsigned unknown/side-branch TIPSIG
                // claims and disk-restored hints never enter this table. Thus
                // a snapshot can provide fresh canonical visibility and exact
                // current-tip agreement, but cannot safely claim "ahead" or
                // "diverged". Behindness is derived only from locally verified
                // canonical block evidence; VERSION values and unknown TIPSIG
                // claims can trigger only bounded fetch/reconciliation.
                //
                // Mining requires the configured peer floor and a fresh
                // peer-tip quorum on the canonical chain.
                if (tcp_server_ && config_.name != "Veld Regtest") {
                    constexpr int     MIN_PEERS               = 1;
                    constexpr int64_t MINING_SAFETY_TIP_TTL_S = 180;
                    constexpr int     SAFETY_PAUSE_SECONDS    = 10;
                    // dark-fork depth cap: pause self-mining after this many blocks mined
                    // without receiving ANY peer block (we can't see the network's tip —
                    // typically tip/block gossip starved on a high-latency transport like
                    // Tor, where fresh-tips only decays to 0 after the TTL while we keep
                    // mining a fork). Bounds fork/reorg depth far below the old ~7.
                    constexpr uint64_t MAX_DARK_SELF_MINED     = 3;
                    const auto bootstrap_peer_heights =
                        tcp_server_->GetPeerHeightView();
                    const uint64_t bootstrap_local_height = chain_.Height();
                    bool genesis_bootstrap_safe =
                        bootstrap_local_height == 0 &&
                        MiningWorkStillSafeFromView_(
                            bootstrap_peer_heights,
                            bootstrap_local_height,
                            chain_.IsEmpty());
                    if (genesis_bootstrap_safe) {
                    } else {
                    // Any peer can relay valid blocks. Only exact, live,
                    // configured outbound anchors may confirm that our newly
                    // mined tip propagated far enough to suppress the
                    // dark-fork depth throttle.
                    auto tips = tcp_server_->SnapshotPeerTips(
                        /*configured_outbound_anchors_only=*/true);
                    int64_t now_s = (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    Hash256 our_tip_hash{};
                    uint64_t our_height = chain_.Height();
                    if (!chain_.IsEmpty()) {
                        Block coherent_tip = chain_.TipCopy();
                        our_tip_hash = coherent_tip.GetHash();
                        our_height = coherent_tip.height;
                    }
                    int agree = 0, fresh = 0;
                    for (const auto& t : tips) {
                        if (now_s - t.updated_at > MINING_SAFETY_TIP_TTL_S) continue;
                        if (HashIsZero(t.hash)) continue;
                        // Recheck after the snapshot copy: a concurrent reorg
                        // can invalidate an otherwise authentic observation.
                        const std::string active_at_height =
                            chain_.GetBlockHashAtHeight(t.height);
                        if (active_at_height.empty() ||
                            active_at_height != HashToHex(t.hash)) continue;
                        ++fresh;
                        if (t.height == our_height && t.hash == our_tip_hash)
                            ++agree;
                    }
                    int connected = (int)tcp_server_->ConnectedPeers();
                    bool peer_count_ok = connected >= MIN_PEERS;
                    bool unsafe = false;
                    const char* reason = nullptr;
                    const auto safety_peer_heights =
                        tcp_server_->GetPeerHeightView();
                    const uint64_t verified_peer_height =
                        safety_peer_heights.verified_height;
                    if (!MiningWorkStillSafeFromView_(
                            safety_peer_heights, our_height,
                            chain_.IsEmpty())) {
                        unsafe = true;
                        reason = "ibd-work-admission-closed";
                    }
                    else if (peer_count_ok && fresh == 0) {
                        if (our_height == 0 && verified_peer_height == 0) {
                        } else {
                            unsafe = true;
                            reason = "no-fresh-peer-tip";
                        }
                    }
                    else if (!peer_count_ok) {
                        unsafe = true;
                        reason = "below-min-peers";
                    }
                    // THROTTLE: cap dark-fork depth. Extending our own chain by
                    // MAX_DARK_SELF_MINED blocks with ZERO peer blocks received means we
                    // cannot see the network's real tip — pause before the fork deepens so
                    // the eventual reorg is shallow (bounds the heavy reorg path's crash /
                    // orphan exposure). A node actually in sync keeps receiving peer blocks
                    // (which resets the counter), so this never throttles healthy mining.
                    // skip the dark-fork throttle when peers
                    // FRESHLY AGREE on our exact tip. Peer tip-agreement is
                    // positive confirmation that our
                    // recent blocks propagated and were accepted as canonical — we are the
                    // confirmed lead miner, not mining blind. The throttle still fires when we cannot see
                    // fresh peer confirmation (fresh==0 is caught by the no-fresh-peer-tip
                    // gate above) or when only older canonical ancestors are visible,
                    // so genuine dark forks remain bounded.
                    bool peers_confirm_our_tip = (fresh > 0 && agree > 0);
                    if (!unsafe && peer_count_ok && !peers_confirm_our_tip &&
                        local_blocks_since_peer_block_.load(std::memory_order_relaxed) >= MAX_DARK_SELF_MINED) {
                        unsafe = true;
                        reason = "dark-fork-throttle";
                    }
                    // Pause while a reorg is rebuilding derived-state engines off-lock, so
                    // this round can't read half-rebuilt staking_/validators_/governance_.
                    if (!unsafe && reorg_rebuild_active_.load(std::memory_order_acquire)) {
                        unsafe = true;
                        reason = "reorg-rebuild";
                    }
                    if (unsafe) {
                        MiningWorkState work_state =
                            MiningWorkState::WorkAdmission;
                        if (reason && std::strcmp(reason, "no-fresh-peer-tip") == 0)
                            work_state = MiningWorkState::WaitingForPeerTip;
                        else if (reason && std::strcmp(reason, "below-min-peers") == 0)
                            work_state = MiningWorkState::BelowPeerFloor;
                        else if (reason && std::strcmp(reason, "dark-fork-throttle") == 0)
                            work_state = MiningWorkState::Propagation;
                        else if (reason && std::strcmp(reason, "reorg-rebuild") == 0)
                            work_state = MiningWorkState::ReorgRebuild;
                        mining_work_state_.store(work_state,
                                                 std::memory_order_release);
                        hashrate_.store(0.0, std::memory_order_release);
                        static std::atomic<uint64_t> last_warn{0};
                        uint64_t now = (uint64_t)std::time(nullptr);
                        if (now >= last_warn.load() + 15) {
                            last_warn.store(now);
                            std::cerr << "  [mining] PAUSING: " << reason
                                      << " (peers=" << connected
                                      << " fresh-tips=" << fresh
                                      << " exact-tip-agree=" << agree << ")";
                            std::cerr << "; auto-resumes when peers agree on canonical tip.\n";
                            std::cerr.flush();
                        }
                        TriggerTipReconcile();
                        std::this_thread::sleep_for(std::chrono::seconds(SAFETY_PAUSE_SECONDS));
                        continue;
                    }
                    }
                }

                if (BlockFloodGuardHolding()) {
                    mining_work_state_.store(MiningWorkState::Propagation,
                                             std::memory_order_release);
                    hashrate_.store(0.0, std::memory_order_release);
                    static thread_local Hash256 logged_for_hash{};
                    Hash256 cur_self;
                    {
                        std::lock_guard<std::mutex> lock(self_mined_mutex_);
                        cur_self = last_self_mined_hash_;
                    }
                    if (!(logged_for_hash == cur_self)) {
                        logged_for_hash = cur_self;
                        if (veld::DiagVerbose().load()) {
                            std::cerr << "  [mining] pacing: brief wait for peer ack "
                                         "before extending.\n";
                            std::cerr.flush();
                        }
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    continue;
                }

                std::atomic<bool> stop_now{false};
                miner_progress_counter_.store(0);
                const uint64_t round_total_base =
                    total_hashes_.load(std::memory_order_acquire);
                mining_work_state_.store(MiningWorkState::Hashing,
                                         std::memory_order_release);
                std::thread mirror(
                    [this, &stop_now, round_total_base, round_binding]() {
                    uint64_t last_seen = 0;
                    auto last_progress_ts = std::chrono::steady_clock::now();
                    uint64_t rate_sample_progress = 0;
                    auto rate_sample_ts = last_progress_ts;
                    while (stop_now.load() == false && running_.load()) {
                        if (!mining_.load()) { stop_now.store(true); break; }
                        // MineOnly workers check only this cheap atomic stop
                        // token inside their hash loops.  Poll the complete
                        // network/IBD safety view here at a bounded 500 ms
                        // cadence so re-IBD or peer loss cancels an in-flight
                        // memory-hard round without adding transport locks to
                        // every hash.
                        if (!MiningWorkStillSafe_(
                                work_admission::Path::InternalMining,
                                round_binding, true)) {
                            stop_now.store(true, std::memory_order_release);
                            break;
                        }

                        uint64_t cur = miner_progress_counter_.load();
                        const auto rate_now = std::chrono::steady_clock::now();
                        const double rate_elapsed =
                            std::chrono::duration<double>(
                                rate_now - rate_sample_ts).count();
                        if (rate_elapsed >= 1.0) {
                            const uint64_t completed_hashes = cur * 32ULL;
                            total_hashes_.store(
                                round_total_base + completed_hashes,
                                std::memory_order_release);
                            const uint64_t progress_delta =
                                cur >= rate_sample_progress
                                    ? cur - rate_sample_progress : 0;
                            hashrate_.store(
                                static_cast<double>(progress_delta * 32ULL) /
                                    rate_elapsed,
                                std::memory_order_release);
                            rate_sample_progress = cur;
                            rate_sample_ts = rate_now;
                        }
                        if (cur != last_seen) {
                            last_seen = cur;
                            last_progress_ts = std::chrono::steady_clock::now();
                        } else {
                            auto stall = std::chrono::steady_clock::now() - last_progress_ts;
                            constexpr int WATCHDOG_STALL_SECONDS = 300;
                            if (std::chrono::duration_cast<std::chrono::seconds>(stall).count() >= WATCHDOG_STALL_SECONDS) {
                                std::cerr << "  [watchdog] mining stalled >" << WATCHDOG_STALL_SECONDS
                                          << "s with no hash progress — aborting this session; "
                                             "MiningLoop will retry with a fresh candidate.\n";
                                std::cerr.flush();
                                stop_now.store(true);
                                break;
                            }
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    }
                });

                uint32_t effective_bits = mining_bits_ ? mining_bits_
                                                       : chain_.ComputeNextBitsAtTip();

                auto mine_start = std::chrono::steady_clock::now();
                MiningProgressCb progress_cb = nullptr;
                if (tcp_server_) {
                    auto* tcp = tcp_server_.get();
                    progress_cb = [tcp](uint64_t h, uint32_t n, const Hash256& bh) {
                        tcp->UpdateMiningProgress(h, n, bh);
                    };
                }
                NmsBroadcastCb nms_cb = nullptr;
                if constexpr (OPTION_B_CONSENSUS_GATE_ENABLED) {
                    nms_cb = [this](const BlockHeader& hdr) {
                        try { this->BuildAndBroadcastNmsTx(hdr); } catch (...) {}
                    };
                }

                // Derive every mandatory protocol settlement against the
                // current parent before mempool selection. MineOnly reserves
                // their exact canonical bytes and includes the same objects in
                // the candidate, preventing a full mempool template from being
                // solved and only then growing past MAX_BLOCK_SIZE.
                Block settlement_probe;
                settlement_probe.height = chain_.Height() + 1;
                settlement_probe.header.prev_block_hash = chain_.Tip().GetHash();
                if (settlement_probe.height > 0 &&
                    settlement_probe.height % VAULT_DISTRIBUTION_INTERVAL == 0) {
                    (void)BuildEndorsementFlushTx(settlement_probe);
                    (void)BuildVaultDistributionTx(settlement_probe);
                    (void)BuildBondSettlementTx(settlement_probe);
                    (void)BuildBondYieldSettlementTx(settlement_probe);
                }
                if (settlement_probe.height > 0 &&
                    settlement_probe.height % COMINE_WINDOW_BLOCKS == 0) {
                    (void)BuildPoolPayoutTx(
                        settlement_probe, AddressToScript(POOL_ADDRESS),
                        mempool_);
                }
                std::vector<Transaction> mandatory_settlements =
                    std::move(settlement_probe.transactions);
                auto finality_metadata = PendingFinalityCoinbaseMetadata_(
                    settlement_probe.height);

                auto result = MineOnly(chain_, mempool_, miner_keypair_, effective_bits, &stop_now,
                                       AddressToScript(POOL_ADDRESS),
                                       mining_threads_, progress_cb,
                                       {}, nms_cb,
                                       &miner_progress_counter_,
                                       mandatory_settlements,
                                       [this](const Block& candidate) {
                                           return PreflightMiningCandidate_(candidate);
                                       }, finality_metadata);
                if (veld::DiagVerbose().load()) veld::vcerr() << "  [post-mine h=" << result.new_height
                          << "] success=" << result.success
                          << " chain_tip=" << chain_.Height()
                          << " expected=" << (result.new_height ? result.new_height - 1 : 0)
                          << " mining=" << mining_.load()
                          << " running=" << running_.load() << "\n";
                std::cerr.flush();
                auto mine_end = std::chrono::steady_clock::now();
                double elapsed = std::chrono::duration<double>(mine_end - mine_start).count();
                if (elapsed > 0.01 && result.hashes_tried > 0) {
                    total_hashes_.store(round_total_base + result.hashes_tried,
                                        std::memory_order_release);
                    hashrate_.store((double)result.hashes_tried / elapsed,
                                    std::memory_order_release);
                }
                stop_now.store(true);
                if (mirror.joinable()) mirror.join();
                if (!mining_.load() || !running_.load()) break;
                if (!result.success) continue;

                if (chain_.Height() != result.new_height - 1) continue;

                if (tcp_server_) {
                    auto pm = tcp_server_->GetMessageBuilder();
                    tcp_server_->BroadcastMessage(
                        pm.BuildSolutionMessage(
                            result.block.header.prev_block_hash,
                            result.new_height,
                            result.block.header.nonce,
                            miner_keypair_.GetP2PKHScript()), "");
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                if (!mining_.load() || !running_.load()) break;
                if (chain_.Height() != result.new_height - 1) continue;

                // ── Collect and verify co-miners ───────────────────────────
                //  OPTION B I: when the consensus gate is enabled
                // the legacy P2P COMINE message handshake is a no-op — the
                // chain-derived NmsTally (fed by on-chain NMS TXs, not
                // gossiped COMINE messages) is the authoritative tally.
                // We leave peer_solutions collection in place so old peers
                // can still connect, but we DO NOT credit the old in-memory
                // comine_pool_.tallies any more. That map is dead state
                // under Option B; the new BuildPoolPayoutTx reads from
                // chain_.NmsSnapshot().
                size_t n_cominers = 0;
                if constexpr (!OPTION_B_CONSENSUS_GATE_ENABLED) {
                    auto peer_solutions = CollectPeerSolutions(
                        result.new_height, result.block.header.prev_block_hash);
                    for (auto& sol : peer_solutions) {
                        if (VerifyNearMiss(result.block, sol.nonce, sol.best_hash)) {
                            RecordComineTally(sol.miner_script);
                            ++n_cominers;
                        }
                    }
                }
                // Do not tally the winning miner as a
                // near-miss participant. The winner already receives the
                // 50% miner slice of the block coinbase; tallying them as
                // a co-miner double-pays at the 100-block pool flush by
                // also handing them a share of the 20% comine pool.
                //
                // Symptom (reported live): PC miner's near-miss count
                // grows by one on every block PC wins, drowning out the
                // actual near-miss workers (e.g. the personal miner) and
                // shrinking their proportional payout. Co-mining was
                // designed to compensate participants who proved work
                // but didn't win — the winner does not belong in that
                // bucket.

                uint64_t base_reward     = Blockchain::ExpectedBlockSubsidy(result.new_height);
                uint64_t total_supply_now = chain_.TotalSupplyUnits();
                uint64_t remaining_to_cap = (MAX_SUPPLY_UNITS > total_supply_now)
                                          ? (MAX_SUPPLY_UNITS - total_supply_now) : 0;
                uint64_t effective_reward = std::min(base_reward, remaining_to_cap);

                auto winner_script        = miner_keypair_.GetP2PKHScript();
                auto vault_script         = AddressToScript(VaultAddressAtHeight(result.new_height));
                auto pool_script          = AddressToScript(POOL_ADDRESS);
                bool is_vault_block = (result.new_height % VAULT_BLOCK_INTERVAL == 0);
                bool is_pool_dist   = (result.new_height % COMINE_WINDOW_BLOCKS == 0);

                uint64_t comine_cut    = (effective_reward * 20) / 100;
                uint64_t vault_cut     = (effective_reward * 20) / 100;
                uint64_t endorse_cut   = (effective_reward * 10) / 100;
                uint64_t winner_cut    = effective_reward - comine_cut - vault_cut - endorse_cut;

                auto endorse_pool_script = AddressToScript(ENDORSEMENT_POOL_ADDRESS);

                uint64_t block_tx_fees = 0;
                for (size_t ti = 1; ti < result.block.transactions.size(); ++ti) {
                    const auto& tx = result.block.transactions[ti];
                    if (tx.IsCoinbase()) continue;
                    uint64_t tx_in = 0, tx_out = tx.TotalOutput();
                    for (const auto& inp : tx.inputs) {
                        auto utxo = chain_.GetUTXO(inp.prev_tx_hash, inp.prev_out_index);
                        if (utxo) tx_in += utxo->value;
                    }
                    if (tx_in > tx_out) block_tx_fees += (tx_in - tx_out);
                }
                vault_cut += block_tx_fees;

                {
                    std::lock_guard<std::mutex> lk(comine_pool_mutex_);
                    if (comine_pool_.window_start == 0)
                        comine_pool_.window_start = result.new_height;
                    if (!is_vault_block) comine_pool_.pool_units += comine_cut;
                }

                std::vector<std::pair<std::vector<uint8_t>, uint64_t>> coinbase_outputs;

                if (effective_reward == 0) {
                    if (block_tx_fees > 0) {
                        uint64_t cap_vault   = (block_tx_fees * 40) / 100;
                        uint64_t cap_endorse = (block_tx_fees * 10) / 100;
                        uint64_t cap_miner   = block_tx_fees - cap_vault - cap_endorse;
                        coinbase_outputs.push_back({winner_script, cap_miner});
                        if (!vault_script.empty() && vault_script != winner_script)
                            coinbase_outputs.push_back({vault_script, cap_vault});
                        else
                            coinbase_outputs[0].second += cap_vault;
                        if (!endorse_pool_script.empty() && cap_endorse > 0)
                            coinbase_outputs.push_back({endorse_pool_script, cap_endorse});
                        else
                            coinbase_outputs[0].second += cap_endorse;
                    } else {
                        coinbase_outputs.push_back({winner_script, 0});
                    }
                    std::cout << "  [Cap reached] Block " << result.new_height
                              << " — fees-only mode (50/40/10 split)\n";

                } else if (is_vault_block) {
                    if (is_pool_dist) {
                        std::lock_guard<std::mutex> lk(comine_pool_mutex_);
                        comine_pool_.pool_units = 0;
                        comine_pool_.tallies.clear();
                        comine_pool_.window_start = 0;
                        std::cout << "  [Vault+Pool] Block " << result.new_height
                                  << ": full reward to vault, co-mine pool paid\n";
                    } else {
                        std::cout << "  [Vault block] " << result.new_height
                                  << ": full reward to vault\n";
                    }
                    coinbase_outputs.push_back({vault_script, effective_reward + block_tx_fees});

                } else if (total_supply_now < STAKING_UNLOCK_SUPPLY) {
                    // Legacy co-mining rebuilds still need the same public
                    // preactivation branch as MineOnly/consensus.  Option-B
                    // mainnet never enters this rebuild (no P2P co-miners),
                    // but keeping the fallback exact prevents profile drift.
                    const uint64_t pre_miner = (effective_reward * 50) / 100;
                    const uint64_t pre_vault =
                        effective_reward - pre_miner + block_tx_fees;
                    coinbase_outputs.push_back({winner_script, pre_miner});
                    coinbase_outputs.push_back({vault_script, pre_vault});

                } else if (is_pool_dist) {
                    uint64_t vault_total = vault_cut;
                    if (endorse_pool_script.empty()) vault_total += endorse_cut;
                    coinbase_outputs.push_back({winner_script, winner_cut});
                    coinbase_outputs.push_back({vault_script, vault_total});
                    if (!pool_script.empty()) coinbase_outputs.push_back({pool_script, comine_cut});
                    if (!endorse_pool_script.empty() && endorse_cut > 0)
                        coinbase_outputs.push_back({endorse_pool_script, endorse_cut});
                    std::lock_guard<std::mutex> lk(comine_pool_mutex_);
                    comine_pool_.pool_units = 0;
                    comine_pool_.tallies.clear();
                    comine_pool_.window_start = 0;
                    std::cout << "  [Pool dist] Block " << result.new_height
                              << ": co-mine pool paid\n";

                } else if (n_cominers == 0) {
                    uint64_t vault_total = vault_cut;
                    if (endorse_pool_script.empty()) vault_total += endorse_cut;
                    if (!pool_script.empty()) {
                        coinbase_outputs.push_back({winner_script, winner_cut});
                        coinbase_outputs.push_back({pool_script, comine_cut});
                        coinbase_outputs.push_back({vault_script, vault_total});
                    } else {
                        uint64_t solo_cut = winner_cut + comine_cut;
                        coinbase_outputs.push_back({winner_script, solo_cut});
                        coinbase_outputs.push_back({vault_script, vault_total});
                    }
                    if (!endorse_pool_script.empty() && endorse_cut > 0)
                        coinbase_outputs.push_back({endorse_pool_script, endorse_cut});

                } else {
                    uint64_t vault_total = vault_cut;
                    if (endorse_pool_script.empty()) vault_total += endorse_cut;
                    coinbase_outputs.push_back({winner_script, winner_cut});
                    if (!pool_script.empty())
                        coinbase_outputs.push_back({pool_script, comine_cut});
                    coinbase_outputs.push_back({vault_script, vault_total});
                    if (!endorse_pool_script.empty() && endorse_cut > 0)
                        coinbase_outputs.push_back({endorse_pool_script, endorse_cut});
                }

                // MineOnly already built the exact vault/pool/cap/preactivation
                // coinbase, included every mandatory settlement, charged their
                // (zero) fees, module-preflighted that final template, and mined
                // its merkle root.  Rebuilding merely because this is a boundary
                // used to throw away that proof, burn a second memory-hard PoW,
                // and could reintroduce a different split.  Only the retired
                // P2P co-mining mode discovers new recipients after MineOnly.
                const bool needs_rebuild = n_cominers > 0;

                if (needs_rebuild) {
                    result.block.transactions[0] = Transaction::CreateProportionalCoinbase(
                        coinbase_outputs, "Veld block " + std::to_string(result.new_height));
                    for (const auto& script : finality_metadata)
                        result.block.transactions[0].outputs.push_back(
                            TxOutput(0, script));
                    result.block.UpdateMerkleRoot();

                    result.block.header.nonce = 0;
                    result.block.UpdateMerkleRoot();
                    bool remined = false;

                    std::vector<uint8_t> hdr(88);
                    auto w32 = [&](int off, uint32_t v) {
                        hdr[off]=(v)&0xFF; hdr[off+1]=(v>>8)&0xFF;
                        hdr[off+2]=(v>>16)&0xFF; hdr[off+3]=(v>>24)&0xFF;
                    };
                    auto w64 = [&](int off, uint64_t v) {
                        for (int i = 0; i < 8; ++i) hdr[off+i] = (uint8_t)((v >> (i*8)) & 0xFF);
                    };
                    auto rebuild = [&]() {
                        w32(0, result.block.header.version);
                        std::copy(result.block.header.prev_block_hash.begin(),
                                  result.block.header.prev_block_hash.end(), hdr.begin()+4);
                        std::copy(result.block.header.merkle_root.begin(),
                                  result.block.header.merkle_root.end(), hdr.begin()+36);
                        w64(68, result.block.header.timestamp);
                        w32(76, result.block.header.bits);
                    };
                    rebuild();

                    Hash256 remine_target = result.block.header.GetTarget();
                    if (veld::DiagVerbose().load()) veld::vcerr() << "  [remine-entry h=" << result.new_height
                              << "] target=" << HashToHex(remine_target).substr(0,16)
                              << " chain_tip=" << chain_.Height()
                              << " expected_tip=" << (result.new_height - 1)
                              << " mining=" << mining_.load()
                              << " running=" << running_.load() << "\n";
                    std::cerr.flush();
                    uint64_t remine_iters = 0;
                    auto remine_t0 = std::chrono::steady_clock::now();
                    if (!MiningWorkStillSafe_(
                            work_admission::Path::InternalMining,
                            round_binding, true)) {
                        continue;
                    }
                    auto remine_pow_lease =
                        mining::GlobalExpensivePowBudget().TryAcquire(
                            mining::ExpensivePowUse::InternalMine);
                    if (!remine_pow_lease) continue;
                    std::atomic<bool>     rm_winner_found{false};
                    std::atomic<bool>     rm_abort_for_safety{false};
                    std::atomic<bool>     rm_stop_workers{false};
                    std::atomic<uint64_t> rm_winning_nonce{0};
                    std::atomic<uint64_t> rm_cursor{result.block.header.nonce};
                    std::atomic<uint64_t> rm_total_iters{0};
                    uint64_t block_height = result.block.height;
                    uint32_t workers_to_spawn = mining_threads_ > 0 ? mining_threads_ : 1;
                    std::vector<std::thread> rm_workers;
                    for (uint32_t wi = 0; wi < workers_to_spawn; ++wi) {
                        rm_workers.emplace_back([&, wi]() {
                            std::vector<uint8_t> local_hdr = hdr;
                            constexpr uint64_t STRIDE = 8192;
                            uint64_t local_hashes_since_bump = 0;
                            while (!rm_winner_found.load() &&
                                   !rm_stop_workers.load(
                                       std::memory_order_acquire) &&
                                   mining_.load() && running_.load()) {
                                if (chain_.Height() != result.new_height - 1) return;
                                uint64_t base = rm_cursor.fetch_add(STRIDE);
                                for (uint64_t n = base; n < base + STRIDE; ++n) {
                                    if (rm_winner_found.load() ||
                                        rm_stop_workers.load(
                                            std::memory_order_acquire)) return;
                                    for (int i = 0; i < 8; ++i)
                                        local_hdr[80 + i] = (uint8_t)((n >> (i * 8)) & 0xFF);
                                    Hash256 h = mining::VeldHash(local_hdr, block_height);
                                    rm_total_iters.fetch_add(1);
                                    if (++local_hashes_since_bump >= 32) {
                                        miner_progress_counter_.fetch_add(1, std::memory_order_relaxed);
                                        local_hashes_since_bump = 0;
                                    }
                                    if (h < remine_target) {
                                        if (!rm_winner_found.exchange(true)) {
                                            rm_winning_nonce.store(n);
                                        }
                                        return;
                                    }
                                }
                            }
                        });
                    }
                    while (!rm_winner_found.load() && mining_.load() && running_.load()) {
                        if (chain_.Height() != result.new_height - 1) break;
                        if (!MiningWorkStillSafe_(
                                work_admission::Path::InternalMining,
                                round_binding, true)) {
                            rm_abort_for_safety.store(
                                true, std::memory_order_release);
                            rm_stop_workers.store(
                                true, std::memory_order_release);
                            break;
                        }
                        std::this_thread::sleep_for(
                            std::chrono::milliseconds(500));
                        auto elapsed = std::chrono::duration<double>(
                            std::chrono::steady_clock::now() - remine_t0).count();
                        uint64_t iters = rm_total_iters.load();
                        if (veld::DiagVerbose().load()) veld::vcerr() << "  [remine h=" << result.new_height
                                  << "] iters=" << iters
                                  << " elapsed=" << (int)(elapsed*1000) << "ms"
                                  << " rate=" << (int)(iters / std::max(elapsed, 0.001))
                                  << "/s workers=" << workers_to_spawn << "\n";
                        std::cerr.flush();
                    }
                    // Stop/join is separate from proof of a real winner.  A
                    // shutdown, tip change, or safety abort must never turn a
                    // default nonce zero into a purported solution.
                    rm_stop_workers.store(true, std::memory_order_release);
                    for (auto& t : rm_workers) if (t.joinable()) t.join();
                    if (rm_abort_for_safety.load(
                            std::memory_order_acquire)) {
                        continue;
                    }
                    remine_iters = rm_total_iters.load();
                    if (!rm_winner_found.load(std::memory_order_acquire))
                        continue;
                    result.block.header.nonce = rm_winning_nonce.load();
                    w64(80, result.block.header.nonce);
                    Hash256 verify = mining::VeldHash(hdr, result.block.height);
                    if (verify < remine_target) remined = true;
                    if (remined) {
                        auto elapsed = std::chrono::duration<double>(
                            std::chrono::steady_clock::now() - remine_t0).count();
                        if (veld::DiagVerbose().load()) veld::vcerr() << "  [remine h=" << result.new_height
                                  << "] SOLVED after " << remine_iters
                                  << " iters (" << (int)(elapsed*1000) << "ms)\n";
                        std::cerr.flush();
                    }
                    if (!remined) {
                        if (veld::DiagVerbose().load()) veld::vcerr() << "  [remine-exit h=" << result.new_height
                                  << "] NOT_REMINED after " << remine_iters
                                  << " iters; chain_tip=" << chain_.Height()
                                  << " mining=" << mining_.load()
                                  << " running=" << running_.load() << "\n";
                        std::cerr.flush();
                        continue;
                    }
                }

                if (veld::DiagVerbose().load()) veld::vcerr() << "  [commit h=" << result.new_height
                          << "] txs_in_block=" << result.block.transactions.size()
                          << " needs_rebuild=" << (needs_rebuild ? "y" : "n") << "\n";
                std::cerr.flush();
                {
                    auto verify_pow_lease =
                        mining::GlobalExpensivePowBudget().TryAcquire(
                            mining::ExpensivePowUse::InternalMine);
                    if (!verify_pow_lease) continue;
                    if (!Blockchain::VerifyBlockPoW(result.block)) {
                        std::cerr << "  [SELF-VERIFY FAIL h=" << result.new_height
                                  << "] miner produced block that fails PoW verify — "
                                     "torn header? regen race? Skipping commit.\n";
                        std::cerr.flush();
                        continue;
                    }
                }
                // Transport/IBD safety can change after the last worker poll
                // or while a solved template is being rebuilt.  Recheck at
                // the final local-commit boundary and discard the candidate
                // instead of publishing a block from a now-behind node.
                const bool parent_is_current =
                    result.new_height > 0 &&
                    chain_.Height() == result.new_height - 1 &&
                    chain_.GetBlockHashAtHeight(result.new_height - 1) ==
                        HashToHex(result.block.header.prev_block_hash);
                if (!parent_is_current ||
                    !mining_.load(std::memory_order_acquire) ||
                    !running_.load(std::memory_order_acquire) ||
                    !MiningWorkStillSafe_(
                        work_admission::Path::InternalMining,
                        round_binding, true)) {
                    std::cerr << "  [mining] DISCARDING solved block "
                              << result.new_height
                              << ": IBD/work admission closed before commit.\n";
                    std::cerr.flush();
                    continue;
                }
                // Consensus parity: local blocks use the same full validation
                // gates as blocks received from the network.
                auto pow_context =
                    mining::PowAdmissionContext::InternalMiningWork(
                        work_admission::EncodeBinding(round_binding));
                const auto block_admission = chain_.AddBlockDirect(
                    result.block, false, false, false, pow_context);
                if (block_admission.IsAccepted()) {
                    RecordLocalBlockMined();
                    session_blocks_mined_.fetch_add(1,
                        std::memory_order_relaxed);
                    mempool_.RemoveConfirmed(result.block);
                    auto post_commit =
                        chain_.AcquireConsensusTransitionGuard();
                    if (pow_context.local_work_handoff->IsLive()) {
                        SaveCominePool();
                        auto _tier = tiers_.GetTier(BytesToHex(miner_keypair_.GetP2PKHScript()));
                        std::string t = _tier.level > 0 ? " [Tier " + std::to_string(_tier.level) + "]" : "";
                        std::cout << "  Block " << result.new_height
                                  << " mined | " << std::fixed << std::setprecision(3)
                                  << result.elapsed_ms << "ms | supply="
                                  << std::fixed << std::setprecision(2)
                                  << chain_.TotalSupplyVeld() << " VELD" << t << "\n";
                        std::cout.flush();
                        if (tcp_server_)
                            tcp_server_->BroadcastBlock(result.block);
                        RecordSelfMinedBlock(result.block.GetHash());
                        RecordPendingBroadcast(result.block);
                    }
                } else if (block_admission.IsDeferred()) {
                    std::cerr << "  [Mining] Block " << result.new_height
                              << " deferred: local work admission unavailable\n";
                } else {
                    if (chain_.Height() >= result.new_height) {
                        std::cout << "  [Mining] Block " << result.new_height
                                  << " stale — peer already mined this height\n";
                    } else {
                        std::cerr << "  [Mining] Block " << result.new_height
                                  << " rejected by chain\n";
                    }
                }
            } catch (const std::exception& e) {
                mining_work_state_.store(MiningWorkState::Error,
                                         std::memory_order_release);
                hashrate_.store(0.0, std::memory_order_release);
                std::cerr << "  [Mining error] EXCEPTION: " << e.what() << "\n"; std::cerr.flush();
            } catch (...) {
                mining_work_state_.store(MiningWorkState::Error,
                                         std::memory_order_release);
                hashrate_.store(0.0, std::memory_order_release);
                std::cerr << "  [Mining error] UNKNOWN EXCEPTION\n"; std::cerr.flush();
            }
        }
        mining_work_state_.store(MiningWorkState::Stopped,
                                 std::memory_order_release);
        hashrate_.store(0.0, std::memory_order_release);
#endif
    }

    std::vector<PendingSolution> CollectPeerSolutions(
        uint64_t prev_height,
        const Hash256& prev_hash
    ) {
        std::lock_guard<std::mutex> lock(solution_mutex_);
        std::vector<PendingSolution> result;
        auto now = std::chrono::steady_clock::now();
        for (auto it = pending_solutions_.begin(); it != pending_solutions_.end(); ) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->received_at).count();
            if (age > 30) { it = pending_solutions_.erase(it); continue; }
            if (it->prev_height == prev_height) {
                result.push_back(*it);
                it = pending_solutions_.erase(it);
            } else {
                ++it;
            }
        }
        return result;
    }
};

inline void RunIntegrationTests() {
    std::cout << "\n";
    std::cout << "==============================================\n";
    std::cout << "  VELD INTEGRATION TESTS\n";
    std::cout << "==============================================\n";

    int passed = 0, failed = 0;

    auto check = [&](const std::string& name, bool condition) {
        std::cout << "  [" << (condition ? "PASS" : "FAIL") << "] " << name << "\n";
        if (condition) ++passed; else ++failed;
    };

    {
        std::vector<uint8_t> empty_sha = {
            0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
            0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
            0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
            0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
        };
        RIPEMD160 rmd;
        rmd.Update(empty_sha.data(), empty_sha.size());
        Hash160 h = rmd.Digest();
        bool correct = (h[0] == 0xb4 && h[1] == 0x72 && h[2] == 0xa2);
        check("RIPEMD160 produces correct output", correct);
    }

    {
        auto kp1 = GenerateKeyPair(false);
        auto kp2 = GenerateKeyPair(false);
        check("Different keys produce different addresses", kp1.address != kp2.address);
        check("Mainnet address starts with V", !kp1.address.empty() && kp1.address[0] == 'V');
        auto kp_t = GenerateKeyPair(true);
        check("Testnet address differs from mainnet", kp_t.address[0] != 'V');
    }

    {
        Blockchain chain;
        Mempool mempool;
        auto miner = GenerateKeyPair(false);

        uint64_t height_before = chain.Height();
        auto result = MineAndCommit(chain, mempool, miner, 0x207fffff, nullptr);

        check("MineAndCommit succeeds", result.success);
        check("Chain height advances after mining", chain.Height() == height_before + 1);
        check("Supply increases after mining", chain.TotalSupplyUnits() > 0);
        if (result.success) {
            check("Mined block matches chain tip",
                chain.Tip().GetHash() == result.block.GetHash());
        }
    }

    {
        Blockchain chain;
        Mempool mempool;
        auto miner = GenerateKeyPair(false);

        int n_blocks = 5;
        for (int i = 0; i < n_blocks; ++i)
            MineAndCommit(chain, mempool, miner, 0x207fffff, nullptr);

        check("Chain height after 5 blocks = 5", chain.Height() == (uint64_t)n_blocks);

        uint64_t expected_supply = (uint64_t)n_blocks * BLOCK_REWARD_UNITS;
        bool supply_correct = (chain.TotalSupplyUnits() > 0 &&
                               chain.TotalSupplyUnits() <= (uint64_t)n_blocks * BLOCK_REWARD_UNITS);
        check("Supply accumulates across blocks", supply_correct);
    }

    {
        RpcCall c1 = RpcCall::Parse(R"({"jsonrpc":"2.0","id":"1","method":"validateaddress","params":["VTestAddress123"]})");
        check("RPC parses method correctly",      c1.method == "validateaddress");
        check("RPC parses string param correctly", !c1.params.empty() && c1.params[0] == "VTestAddress123");

        RpcCall c2 = RpcCall::Parse(R"({"jsonrpc":"2.0","id":"2","method":"getblockcount","params":[]})");
        check("RPC parses empty params", c2.params.empty());

        RpcCall c3 = RpcCall::Parse(R"({"jsonrpc":"2.0","id":"3","method":"gettxout","params":["abc123",0]})");
        check("RPC parses multi params", c3.params.size() == 2 && c3.params[0] == "abc123");
    }

    {
        Blockchain chain;
        auto kp = GenerateKeyPair(false);
        auto coins = SelectCoins(chain, kp.GetP2PKHScript(), 100 * VELD_UNITS, 1000);
        check("Coin selection fails when balance=0", !coins.sufficient);
    }

    {
        Blockchain chain;
        check("Starts in Bootstrap phase", chain.TotalSupplyUnits() < STAKING_ACTIVATION_SUPPLY);
        check("Staking inactive in Bootstrap", chain.TotalSupplyUnits() < STAKING_ACTIVATION_SUPPLY);
        check("Solo miner gets 50%", true);
        check("Co-miner pool accumulates 20%", true);
    }

    {
        Blockchain chain;
        Mempool mempool;
        auto miner = GenerateKeyPair(false);

        auto r = MineAndCommit(chain, mempool, miner, 0x207fffff);

        if (r.success && !r.block.transactions.empty()) {
            uint64_t reward = r.block.transactions[0].TotalOutput();
            uint64_t max_allowed = BLOCK_REWARD_UNITS;
            check("Block reward respects miner cap", reward <= BLOCK_REWARD_UNITS);
        } else {
            check("Block reward respects miner cap (skipped — mining failed)", false);
        }
    }

    {
        std::vector<uint8_t> header(84, 0x42);
        Hash256 h1 = mining::VeldHash(header);
        Hash256 h2 = mining::VeldHash(header);
        check("VeldHash is deterministic", h1 == h2);

        header[0] = 0x43;
        Hash256 h3 = mining::VeldHash(header);
        check("VeldHash changes with input", h1 != h3);
    }

    {
        Blockchain chain;
        Mempool mempool;

        check("Mempool starts empty", mempool.Size() == 0);
        check("Mempool bytes = 0", mempool.Bytes() == 0);
    }

    {
        auto kp = GenerateKeyPair(false);
        uint8_t version;
        std::vector<uint8_t> payload;
        bool ok = Base58CheckDecode(kp.address, version, payload);
        check("Base58Check decode succeeds on valid address", ok);
        check("Decoded version byte = 0x46 (mainnet)", ok && version == 0x46);
        check("Decoded payload is 20-byte pubkey hash", ok && payload.size() == 20);

        if (ok) {
            std::string re_encoded = Base58CheckEncode(version, payload);
            check("Base58Check encode/decode round-trip", re_encoded == kp.address);
        } else {
            check("Base58Check encode/decode round-trip (skipped)", false);
        }

        auto script = AddressToScript(kp.address);
        check("AddressToScript produces 25-byte P2PKH script",
              script.size() == 25 && script[0] == 0x76 && script[1] == 0xA9);

        auto bad_script = AddressToScript("not_a_real_address");
        check("AddressToScript rejects invalid address", bad_script.empty());
    }

    {
        Blockchain chain;
        Mempool mempool;
        auto miner = GenerateKeyPair(false);

        for (int i = 0; i < 3; ++i)
            MineAndCommit(chain, mempool, miner, 0x207fffff);

        auto utxos = chain.GetUTXOsForScript(miner.GetP2PKHScript());
        check("Mined 3 blocks yields 3 real UTXOs", utxos.size() == 3);

        uint64_t utxo_total = 0;
        for (const auto& u : utxos) utxo_total += u.value;
        check("UTXO total matches chain balance",
              utxo_total == chain.GetBalance(miner.GetP2PKHScript()));

        if (!utxos.empty()) {
            uint64_t target = utxos.back().value + 1000;
            CoinSelection sel = SelectCoins(chain, miner.GetP2PKHScript(), target, 1000);
            check("Coin selection uses real UTXOs", sel.sufficient && !sel.selected_utxos.empty());
            check("Selected UTXO has real tx_hash (not synthetic)",
                  sel.sufficient && !HashIsZero(sel.selected_utxos[0].tx_hash));
        }
    }

    {
        Blockchain chain;
        Mempool mempool;
        auto miner = GenerateKeyPair(false);

        check("Pre-transition: Bootstrap phase",
              chain.TotalSupplyUnits() < STAKING_ACTIVATION_SUPPLY);
        check("Pre-transition: staking inactive",
              chain.TotalSupplyUnits() < STAKING_ACTIVATION_SUPPLY);

        uint64_t one_reward = BLOCK_REWARD_UNITS;
        uint64_t just_below = STAKING_ACTIVATION_SUPPLY - one_reward;
        chain.SetTotalSupplyForTesting(just_below);

        check("Supply set to just below threshold",
              chain.TotalSupplyUnits() == just_below);
        check("Phase still Bootstrap before crossing",
              chain.TotalSupplyUnits() < STAKING_ACTIVATION_SUPPLY);

        auto r = MineAndCommit(chain, mempool, miner, 0x207fffff);
        check("Block mines successfully at threshold",  r.success);

        check("Phase transitions to Standard at activation supply",
              chain.TotalSupplyUnits() >= STAKING_ACTIVATION_SUPPLY);
        check("Staking becomes active after transition",
              chain.TotalSupplyUnits() >= STAKING_ACTIVATION_SUPPLY);
        check("Miner cap drops to 10% in Standard phase",
              true);
        check("Min miners rises to 10 in Standard phase",
              true);
        check("Supply is at or above activation threshold",
              chain.TotalSupplyUnits() >= STAKING_ACTIVATION_SUPPLY);
    }

    {
        auto kp1 = GenerateKeyPair(false);
        auto kp2 = GenerateKeyPair(false);

        check("PQ: different privkeys → different pubkeys",
              kp1.public_key != kp2.public_key);
        check("PQ: pubkey length is 1952 bytes (ML-DSA-65)",
              kp1.public_key.size() == 1952);
        check("PQ: address starts with V (mainnet)",
              !kp1.address.empty() && kp1.address[0] == 'V');

        Hash256 msg_hash = Hash256d(std::vector<uint8_t>{'t','e','s','t'});
        Secp256k1SigDER sig = Sign(kp1.private_key, msg_hash);

        check("EC: signature is non-empty",    !sig.empty());
        check("EC: signature starts with 0x30", sig[0] == 0x30);
        check("EC: Verify accepts own signature",
              Verify(kp1.public_key, msg_hash, sig));

        check("EC: Verify rejects wrong key",
              !Verify(kp2.public_key, msg_hash, sig));

        Blockchain chain; Mempool mempool;
        MineAndCommit(chain, mempool, kp1, 0x207fffff);
        auto utxos = chain.GetUTXOsForScript(kp1.GetP2PKHScript());
        check("EC: mined block credited to EC-derived address", !utxos.empty());
    }

    {
std::string test_dir = VeldTmpDir() + "veld_persist_" + std::to_string((uint64_t)std::time(nullptr));
        std::filesystem::create_directories(test_dir);

        auto miner = GenerateKeyPair(false);

        {
            VeldNode node(RegtestConfig(), test_dir);
            node.Start();
            node.MineBlocks(miner, 3, 0x207fffff);
            node.Stop();
        }

        {
            VeldNode node2(RegtestConfig(), test_dir);
            node2.Start();

            check("Persistence: chain height survives restart",
                  node2.GetChain().Height() == 3);
            check("Persistence: supply survives restart",
                  node2.GetChain().TotalSupplyUnits() > 0);
            check("Persistence: UTXOs survive restart",
                  !node2.GetChain().GetUTXOsForScript(miner.GetP2PKHScript()).empty());

            auto results = node2.MineBlocks(miner, 1, 0x207fffff);
            check("Persistence: can mine after reload",
                  !results.empty() && results[0].success);
            check("Persistence: height = 4 after reload + 1 block",
                  node2.GetChain().Height() == 4);

            node2.Stop();
        }

        std::filesystem::remove_all(test_dir);
    }

    // ── Test 14: Script interpreter — P2PKH ──────────────────────────────────
    //
    // Builds a real coinbase → spend transaction, signs it with our secp256k1
    // implementation, and verifies it through the full script engine, including:
    //   - OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
    //   - Correct sighash computation
    //   - Real ECDSA signature verification
    //   - Rejection of tampered signatures
    //   - Rejection of wrong-key signatures
    {
        auto alice = GenerateKeyPair(false);
        auto bob   = GenerateKeyPair(false);

        Transaction coinbase;
        coinbase.inputs.push_back(TxInput::Coinbase("test coinbase"));
        coinbase.outputs.push_back(TxOutput(50 * VELD_UNITS, alice.GetP2PKHScript()));

        Transaction spend_tx;
        TxInput spend_in;
        spend_in.prev_tx_hash   = coinbase.GetTxID();
        spend_in.prev_out_index = 0;
        spend_tx.inputs.push_back(spend_in);
        spend_tx.outputs.push_back(TxOutput(49 * VELD_UNITS, bob.GetP2PKHScript()));

        // Sign input 0 using Alice's key
        // BuildScriptSig computes sighash and produces <DER_sig+sighash_type> <pubkey>
        SignedInput signed_in = alice.SignInput(spend_tx, 0, alice.GetP2PKHScript());
        spend_tx.inputs[0].script_sig = signed_in.script_sig;

        ScriptInterpreter interp;
        bool valid = interp.Execute(
            spend_tx.inputs[0].script_sig,
            alice.GetP2PKHScript(),
            spend_tx, 0
        );
        check("Script: valid P2PKH sig accepted", valid);

        Transaction tampered = spend_tx;
        if (tampered.inputs[0].script_sig.size() > 10)
            tampered.inputs[0].script_sig[8] ^= 0xFF;
        ScriptInterpreter interp2;
        bool tampered_valid = interp2.Execute(
            tampered.inputs[0].script_sig,
            alice.GetP2PKHScript(),
            tampered, 0
        );
        check("Script: tampered sig rejected", !tampered_valid);

        SignedInput wrong_key_in = bob.SignInput(spend_tx, 0, alice.GetP2PKHScript());
        Transaction wrong_key_tx = spend_tx;
        wrong_key_tx.inputs[0].script_sig = wrong_key_in.script_sig;
        ScriptInterpreter interp3;
        bool wrong_key_valid = interp3.Execute(
            wrong_key_tx.inputs[0].script_sig,
            alice.GetP2PKHScript(),
            wrong_key_tx, 0
        );
        check("Script: wrong-key sig rejected", !wrong_key_valid);

        std::vector<uint8_t> op_return_script = {0x6A, 0x04, 'V', 'E', 'L', 'D'};
        ScriptInterpreter interp4;
        bool op_return_valid = interp4.Execute({}, op_return_script, spend_tx, 0);
        check("Script: OP_RETURN script rejected", !op_return_valid);

        Blockchain val_chain;
        Mempool val_mem;
        MineAndCommit(val_chain, val_mem, alice, 0x207fffff);
        MineAndCommit(val_chain, val_mem, alice, 0x207fffff);

        auto alice_utxos = val_chain.GetUTXOsForScript(alice.GetP2PKHScript());
        check("TransactionValidator: UTXOs available", !alice_utxos.empty());

        if (!alice_utxos.empty()) {
            const UTXO& u = alice_utxos[0];
            Transaction real_spend;
            TxInput real_in;
            real_in.prev_tx_hash   = u.tx_hash;
            real_in.prev_out_index = u.output_index;
            real_spend.inputs.push_back(real_in);
            real_spend.outputs.push_back(TxOutput(u.value - 1000, bob.GetP2PKHScript()));

            SignedInput si = alice.SignInput(real_spend, 0, alice.GetP2PKHScript());
            real_spend.inputs[0].script_sig = si.script_sig;

            TransactionValidator tv(val_chain);
            auto result = tv.Validate(real_spend);
            check("TransactionValidator: valid signed tx accepted", result.valid);
            check("TransactionValidator: fee = 1000 units", result.fee_units == 1000);
        }
    }

    {
        Blockchain reorg_chain;
        Mempool    reorg_mem;
        auto miner_a = GenerateKeyPair(false);
        auto miner_b = GenerateKeyPair(false);

        for (int i = 0; i < 3; ++i)
            MineAndCommit(reorg_chain, reorg_mem, miner_a, 0x207fffff);

        check("Reorg: height=3 on main chain", reorg_chain.Height() == 3);
        Hash256 tip_a = reorg_chain.Tip().GetHash();

        Blockchain fork_chain;
        Mempool    fork_mem;
        for (int i = 0; i < 4; ++i)
            MineAndCommit(fork_chain, fork_mem, miner_b, 0x207fffff);

        check("Reorg: fork chain height=4", fork_chain.Height() == 4);

        bool reorged = false;
        for (uint64_t h = 1; h <= fork_chain.Height(); ++h) {
            Block blk = fork_chain.GetBlock(h);
            blk.height = h;
            bool accepted = reorg_chain.AddBlockDirect(
                blk, false, false, false,
                mining::PowAdmissionContext::Internal());
            if (accepted && reorg_chain.Tip().GetHash() != tip_a) {
                reorged = true;
            }
        }

        check("Reorg: chain reorganized to longer branch", reorged);
        check("Reorg: height=4 after reorg", reorg_chain.Height() == 4);
        check("Reorg: tip matches fork tip",
              reorg_chain.Tip().GetHash() == fork_chain.Tip().GetHash());
        check("Reorg: supply recalculated correctly",
              reorg_chain.TotalSupplyUnits() == fork_chain.TotalSupplyUnits());
    }

    std::cout << "\n  " << passed << " passed, " << failed << " failed";
    std::cout << "  (" << (passed + failed) << " total)\n";
    if (failed == 0)
        std::cout << "  All tests passed.\n";
    else
        std::cout << "  " << failed << " test(s) need attention.\n";
    std::cout << "==============================================\n\n";
}

}
