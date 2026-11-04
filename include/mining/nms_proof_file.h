#pragma once

#include "../wallet/secure_channel_file.h"
#include <cstdint>
#include <string>

namespace veld::mining {
// Public proof transfer between an address-only miner and a separate wallet.
// Cache successful writes; retry failures at most once every 30 status ticks.
class NmsProofFile {
  public:
    enum class Result { Unchanged, Written, Deferred, Failed };
    Result Update(const std::string& path, const std::string& packet, uint64_t tick,
                  std::string& error) {
        error.clear();
        if (written_ && packet == last_)
            return Result::Unchanged;
        if (tick < retry_tick_)
            return Result::Deferred;
        retry_tick_ = tick + 30;
        if (packet.empty() || packet.size() > 1200) {
            error = "invalid public proof size";
            return Result::Failed;
        }
        if (!channel::secure_file::AtomicWriteText(path, packet, &error, true))
            return Result::Failed;
        last_ = packet;
        written_ = true;
        retry_tick_ = 0;
        return Result::Written;
    }

  private:
    std::string last_;
    bool written_ = false;
    uint64_t retry_tick_ = 0;
};
} // namespace veld::mining
