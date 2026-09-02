#pragma once

#include "../core/constants.h"
#include <string>
#include <vector>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <ctime>

namespace veld {

struct VaultEntry {
    uint64_t    timestamp;
    uint64_t    amount_units;
    std::string type;
    std::string label;
};

class VaultLedger {
public:
    struct StateSnapshot {
        uint64_t total_deposited{0};
        uint64_t total_distributed{0};
        std::vector<VaultEntry> log;
    };

    VaultLedger() = default;

    StateSnapshot SnapshotState() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return StateSnapshot{total_deposited_, total_distributed_, log_};
    }

    void RestoreState(const StateSnapshot& state) {
        std::lock_guard<std::mutex> lock(mutex_);
        total_deposited_ = state.total_deposited;
        total_distributed_ = state.total_distributed;
        log_ = state.log;
    }

    void Deposit(uint64_t amount_units, const std::string& label = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        total_deposited_ += amount_units;
        log_.push_back({(uint64_t)std::time(nullptr), amount_units, "deposit", label});
        if (log_.size() > 10000) log_.erase(log_.begin());
    }

    void Distribute(uint64_t amount_units, const std::string& label = "",
                    const std::string& recipient = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        // the bare subtraction wraps to ~2^64 whenever
        // total_distributed_ exceeds total_deposited_, which makes the guard
        // pass unconditionally. Every other reader in this class uses the
        // guarded ternary form; match them. Exposure is RestoreState and reorg
        // rollback, where a partially-restored frame can invert the pair.
        const uint64_t available = total_deposited_ > total_distributed_
                                       ? (total_deposited_ - total_distributed_)
                                       : 0;
        if (amount_units > available) return;
        total_distributed_ += amount_units;
        log_.push_back({(uint64_t)std::time(nullptr), amount_units, "distribute",
                        label + (recipient.empty() ? "" : " → " + recipient)});
    }

    double BalanceVeld() const {
        std::lock_guard<std::mutex> lock(mutex_);
        uint64_t bal = total_deposited_ > total_distributed_
                     ? total_deposited_ - total_distributed_ : 0;
        return (double)bal / VELD_UNITS;
    }

    uint64_t TotalDeposited()   const { return total_deposited_; }
    uint64_t TotalDistributed() const { return total_distributed_; }

    void ResetLog() {
        std::lock_guard<std::mutex> lock(mutex_);
        log_.clear();
        total_deposited_   = 0;
        total_distributed_ = 0;
    }

    std::string ToJSON() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ostringstream j;
        j << std::fixed << std::setprecision(8);
        uint64_t bal = total_deposited_ > total_distributed_
                     ? total_deposited_ - total_distributed_ : 0;
        j << "{"
          << "\"balance_veld\":" << (double)bal / VELD_UNITS << ","
          << "\"total_deposited_veld\":" << (double)total_deposited_ / VELD_UNITS << ","
          << "\"total_distributed_veld\":" << (double)total_distributed_ / VELD_UNITS << ","
          << "\"vault_address\":\"" << VAULT_ADDRESS << "\","
          << "\"log_entries\":" << log_.size()
          << "}";
        return j.str();
    }

private:
    mutable std::mutex mutex_;
    uint64_t total_deposited_{0};
    uint64_t total_distributed_{0};
    std::vector<VaultEntry> log_;
};

}
