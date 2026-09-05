#pragma once
#include <bitset>
#include <cstdint>
#include <optional>
#include <string>

namespace veld::rpc_detail {
// Metadata only: bit i records a checked block at tip_height - i. Ordinary
// extensions retain checked ancestry; a replaced anchor discards all results.
struct RecentLookupProgress {
    static constexpr size_t WINDOW = 2017;
    std::string tip_hash;
    uint64_t tip_height = 0;
    std::bitset<WINDOW> examined;

    void ObserveTip(uint64_t height, const std::string& hash, bool anchor_canonical) {
        if (tip_hash.empty() || !anchor_canonical || height < tip_height) {
            examined.reset();
        } else if (height > tip_height) {
            const auto delta = height - tip_height;
            if (delta >= WINDOW) examined.reset();
            else examined <<= static_cast<size_t>(delta);
        }
        tip_height = height;
        tip_hash = hash;
    }
    std::optional<uint64_t> Next() const {
        const uint64_t count = tip_height < WINDOW - 1 ? tip_height + 1 : WINDOW;
        for (size_t i = 0; i < count; ++i)
            if (!examined[i]) return tip_height - i;
        return std::nullopt;
    }
    void MarkExamined(uint64_t height) {
        if (height <= tip_height && tip_height - height < WINDOW)
            examined.set(static_cast<size_t>(tip_height - height));
    }
};
}
