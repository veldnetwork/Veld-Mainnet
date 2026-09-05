#pragma once
#include <cstddef>
#include <string>
#include <unordered_map>

namespace veld::explorer {
// Caller holds the accepted-socket mutex. Entries exist only while sockets
// are admitted; the global socket cap also bounds this map's cardinality.
class ReceiptSourceSlots {
public:
    static constexpr size_t PER_SOURCE = 8;
    bool Take(const std::string& source) {
        auto it = active_.find(source);
        if (it != active_.end() && it->second >= PER_SOURCE) return false;
        ++active_[source];
        return true;
    }
    void Release(const std::string& source) {
        auto it = active_.find(source);
        if (it != active_.end() && --it->second == 0) active_.erase(it);
    }
private:
    std::unordered_map<std::string, size_t> active_;
};
}
