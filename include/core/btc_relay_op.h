#pragma once
// btcVELD SPV relay BTC_HEADER operation.
//
// A permissionless OP_RETURN op that carries Bitcoin block headers into Veld
// consensus. ANYONE may submit — consensus validates each header via
// BtcHeaderChain (a liar wastes only their own fee), so an honest relayer just
// keeps the in-consensus BTC view current. node.h::ProcessBlock feeds these ops
// to the node's BtcHeaderChain exactly where it feeds token ops to the ledger,
// and the header chain is reset and replayed on a Veld reorganization. The BTC
// view is therefore a deterministic function of the ordered BTC_HEADER
// operations in the current Veld chain.
//
// Payload wire format:  "BHDR" | uint8 count | count × 80-byte headers.
//
#include "core/btc_header_chain.h"
#include <algorithm>

namespace veld {
namespace btcspv {

inline constexpr uint8_t BTC_HEADER_OP_MAGIC[4] = {'B', 'H', 'D', 'R'};
inline constexpr size_t BTC_HEADER_MAX_PER_OP = 255;

// Build a BTC_HEADER op payload from a batch of raw 80-byte headers.
inline std::vector<uint8_t> EncodeBtcHeaderOp(const std::vector<std::array<uint8_t, 80>>& hdrs) {
    std::vector<uint8_t> p{'B', 'H', 'D', 'R'};
    size_t n = std::min(hdrs.size(), BTC_HEADER_MAX_PER_OP);
    p.push_back((uint8_t)n);
    for (size_t i = 0; i < n; ++i)
        p.insert(p.end(), hdrs[i].begin(), hdrs[i].end());
    return p;
}

// Is `payload` a well-formed BTC_HEADER op? (cheap magic/length check)
inline bool IsBtcHeaderOp(const uint8_t* p, size_t len) {
    if (len < 5)
        return false;
    if (p[0] != 'B' || p[1] != 'H' || p[2] != 'D' || p[3] != 'R')
        return false;
    return len == (size_t)5 + (size_t)p[4] * 80;
}

// Apply a BTC_HEADER op payload to `ch` (headers submitted in order). Returns the
// number of headers accepted; 0 (pure no-op, state unchanged) if the payload is
// not a well-formed BTC_HEADER op — fail closed. `veld_time` bounds each header's
// future time to +2h against the enclosing (consensus-agreed) Veld block.
inline int ApplyBtcHeaderOp(BtcHeaderChain& ch, const uint8_t* p, size_t len,
                            uint32_t veld_time = 0) {
    if (!IsBtcHeaderOp(p, len))
        return 0;
    size_t count = p[4];
    int accepted = 0;
    for (size_t i = 0; i < count; ++i)
        if (ch.SubmitHeader(p + 5 + i * 80, veld_time))
            ++accepted;
    return accepted;
}

} // namespace btcspv
} // namespace veld
