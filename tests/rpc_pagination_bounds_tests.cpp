#include "network/pagination.h"

#include <cstddef>
#include <iostream>
#include <limits>

using veld::rpc_detail::BoundedPageRange;

constexpr bool HasRange(size_t total, size_t page, size_t width,
                        size_t begin, size_t end, size_t pages) {
    const auto r = BoundedPageRange(total, page, width);
    return r.begin == begin && r.end == end && r.total_pages == pages
        && r.begin <= r.end && r.end <= total;
}

static_assert(HasRange(0, 1, 20, 0, 0, 1));
static_assert(HasRange(45, 1, 20, 0, 20, 3));
static_assert(HasRange(45, 2, 20, 20, 40, 3));
static_assert(HasRange(45, 3, 20, 40, 45, 3));
static_assert(HasRange(45, 4, 20, 45, 45, 3));
static_assert(HasRange(40, 3, 20, 40, 40, 2));
static_assert(HasRange(3, 0, 0, 0, 1, 3));

// Pure arithmetic over an abstract count; no allocation or RPC invocation.
constexpr size_t kLargest = std::numeric_limits<size_t>::max();
static_assert(HasRange(45, kLargest, 20, 45, 45, 3));
static_assert(HasRange(kLargest, 1, kLargest, 0, kLargest, 1));
static_assert(HasRange(kLargest, kLargest, kLargest,
                       kLargest, kLargest, 1));

int main() {
    std::cout << "PASS rpc_pagination_bounds_tests (10 compile-time cases)\n";
}
