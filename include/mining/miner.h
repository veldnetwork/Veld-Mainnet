#pragma once

#include "../core/block.h"
#include "../core/blockchain.h"
#include "../core/constants.h"
#include <functional>
#include <atomic>
#include <thread>
#include <chrono>
#include <iostream>

namespace veld {

struct MiningResult {
    bool     found;
    Block    block;
    uint64_t nonce;
    double   elapsed_seconds;
    uint64_t hashes_tried;

    MiningResult() : found(false), nonce(0), elapsed_seconds(0), hashes_tried(0) {}
};

struct MinerSubmission {
    Hash256  miner_address_hash;
    uint64_t nonce;
    Hash256  block_hash;
    uint64_t timestamp;
    uint64_t reward_units;
};

class MiningEngine {
public:
    explicit MiningEngine(Blockchain& chain)
        : chain_(chain), running_(false) {}

    Block BuildCandidateBlock(
        const std::vector<Transaction>& mempool_txs,
        const std::vector<uint8_t>& miner_script,
        const std::string& miner_message = ""
    ) const {
        Block candidate;
        candidate.height = chain_.Height() + 1;

        candidate.header.version         = PROTOCOL_VERSION;
        candidate.header.prev_block_hash  = chain_.Tip().GetHash();
        candidate.header.timestamp        = (uint64_t)std::time(nullptr);
        candidate.header.bits             = chain_.ComputeNextBits();
        candidate.header.nonce            = 0;

        uint64_t reward = BLOCK_REWARD_UNITS;
        Transaction coinbase = Transaction::CreateCoinbase(reward, miner_script, miner_message);
        candidate.transactions.push_back(coinbase);

        size_t tx_count = 1;
        for (const auto& tx : mempool_txs) {
            if (tx_count >= MAX_TRANSACTIONS_PER_BLOCK) break;
            candidate.transactions.push_back(tx);
            ++tx_count;
        }

        candidate.UpdateMerkleRoot();
        return candidate;
    }

    bool MineAndCommit(
        const std::vector<uint8_t>& ,
        const std::vector<Transaction>&  = {},
        const std::string&  = "",
        uint32_t  = 0
    ) {
        return false;
    }

    MiningResult Mine(
        Block& ,
        std::atomic<bool>& ,
        std::function<void(uint64_t)>  = nullptr
    ) {
        MiningResult result;
        result.found        = false;
        result.hashes_tried = 0;
        result.elapsed_seconds = 0.0;
        return result;
    }

    static double EstimateHashRate(uint64_t hashes, double elapsed_seconds) {
        if (elapsed_seconds <= 0) return 0;
        return (double)hashes / elapsed_seconds;
    }

    static std::string FormatHashRate(double hashes_per_sec) {
        if (hashes_per_sec >= 1e12) return std::to_string(hashes_per_sec / 1e12) + " TH/s";
        if (hashes_per_sec >= 1e9)  return std::to_string(hashes_per_sec / 1e9)  + " GH/s";
        if (hashes_per_sec >= 1e6)  return std::to_string(hashes_per_sec / 1e6)  + " MH/s";
        if (hashes_per_sec >= 1e3)  return std::to_string(hashes_per_sec / 1e3)  + " KH/s";
        return std::to_string(hashes_per_sec) + " H/s";
    }

    bool IsRunning() const { return running_.load(); }

private:
    Blockchain&         chain_;
    std::atomic<bool>   running_;
};

}
