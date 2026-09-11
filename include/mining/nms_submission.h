#pragma once

#include <cstdint>
#include <mutex>
#include <optional>

namespace veld::mining {

// Serialize local submissions and count only transactions accepted by the mempool.
class NmsSubmissionGate {
    std::mutex mutex_;
    std::optional<uint64_t> accepted_window_;

  public:
    class Attempt {
        friend class NmsSubmissionGate;
        NmsSubmissionGate& gate_;
        std::unique_lock<std::mutex> lock_;
        uint64_t window_;
        bool eligible_;

        Attempt(NmsSubmissionGate& gate, uint64_t window)
            : gate_(gate), lock_(gate.mutex_, std::try_to_lock), window_(window),
              eligible_(lock_.owns_lock() &&
                        (!gate.accepted_window_ || window > *gate.accepted_window_)) {}

      public:
        Attempt(const Attempt&) = delete;
        Attempt& operator=(const Attempt&) = delete;
        explicit operator bool() const { return eligible_; }

        void CommitAccepted() {
            if (!eligible_) return;
            gate_.accepted_window_ = window_;
            eligible_ = false;
            lock_.unlock();
        }
    };

    Attempt TryBegin(uint64_t window) { return Attempt(*this, window); }
};

} // namespace veld::mining
