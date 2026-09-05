#pragma once

#include <algorithm>
#include <cstddef>

namespace veld {
namespace rpc_detail {

struct PageRange {
    size_t begin;
    size_t end;
    size_t total_pages;
};

// Check against the result count before multiplying a user-selected page.
// Every returned endpoint is within [0, total], including an empty page.
inline constexpr PageRange BoundedPageRange(size_t total, size_t page,
                                            size_t per_page) noexcept {
    const size_t width = std::max<size_t>(1, per_page);
    const size_t index = page == 0 ? 0 : page - 1;
    const size_t begin = index > total / width ? total : index * width;
    const size_t end = begin + std::min(width, total - begin);
    const size_t pages = total / width + (total % width != 0);
    return {begin, end, std::max<size_t>(1, pages)};
}

} // namespace rpc_detail
} // namespace veld
