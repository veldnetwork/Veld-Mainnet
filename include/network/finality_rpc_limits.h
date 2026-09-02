#pragma once

// Size policy for the two validator-finality RPCs whose legitimate maximum
// response is larger than the ordinary 4 MiB operator/explorer ceiling.
//
// This header deliberately contains only arithmetic and bounded accumulation.
// The validator client and its focused regression therefore use the same
// method allow-list and the same byte ceilings.  No other RPC inherits these
// larger limits.

#include "../consensus/finality_codec.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace veld::finality::rpc_limits {

inline constexpr size_t kDefaultRpcResponseBytes = 4U * 1024U * 1024U;
inline constexpr size_t kMaxValidatorAddressChars = 35;
inline constexpr size_t kValidatorPubkeyHexChars =
    2U * ::veld::dilithium::PUBKEY_BYTES;
inline constexpr size_t kHashHexChars = 64;

constexpr size_t DecimalChars(uint64_t value) {
    size_t digits = 1;
    while (value >= 10) {
        value /= 10;
        ++digits;
    }
    return digits;
}

constexpr size_t SumIndexDecimalChars(size_t count) {
    size_t total = 0;
    for (size_t i = 0; i < count; ++i)
        total += DecimalChars(static_cast<uint64_t>(i));
    return total;
}

inline constexpr size_t kMaxSnapshotMembers =
    static_cast<size_t>(qc::MAX_FINALITY_VALIDATOR_COUNT);
inline constexpr uint64_t kMaxSnapshotTotalWeight =
    qc::MAX_FINALITY_VALIDATOR_COUNT * qc::BOND_PER_KEY_UNITS;

// Exact maximum emitted size of one member except for its canonical index.
// Validator addresses are canonical Base58Check P2PKH strings; the shared
// decoder's accepted wire bound is 25..35 characters.
inline constexpr size_t kSnapshotMemberBytesWithoutIndex =
    (sizeof("{\"index\":") - 1) +
    (sizeof(",\"pubkey\":\"") - 1) + kValidatorPubkeyHexChars +
    (sizeof("\",\"commit\":\"") - 1) + kHashHexChars +
    (sizeof("\",\"address\":\"") - 1) + kMaxValidatorAddressChars +
    (sizeof("\",\"registered_height\":") - 1) + DecimalChars(UINT64_MAX) +
    (sizeof(",\"weight\":") - 1) + DecimalChars(qc::BOND_PER_KEY_UNITS) +
    (sizeof("}") - 1);

inline constexpr size_t kSnapshotMembersJsonMaxBytes =
    kMaxSnapshotMembers * kSnapshotMemberBytesWithoutIndex +
    SumIndexDecimalChars(kMaxSnapshotMembers) +
    (kMaxSnapshotMembers == 0 ? 0 : kMaxSnapshotMembers - 1); // commas

inline constexpr size_t kFinalizedRecordJsonMaxBytes =
    (sizeof("{\"epoch\":") - 1) + DecimalChars(UINT64_MAX) +
    (sizeof(",\"height\":") - 1) + DecimalChars(UINT64_MAX) +
    (sizeof(",\"hash\":\"") - 1) + kHashHexChars +
    (sizeof("\",\"round\":") - 1) + DecimalChars(UINT32_MAX) +
    (sizeof("}") - 1);

// Exact worst-case JSON produced by Node's getfinalitysnapshot callback for
// the bounded field widths above and the maximum validator count.
inline constexpr size_t kSnapshotResultJsonMaxBytes =
    (sizeof("{\"snapshot\":{\"epoch\":") - 1) + DecimalChars(UINT64_MAX) +
    (sizeof(",\"snapshot_height\":") - 1) + DecimalChars(UINT64_MAX) +
    (sizeof(",\"set_root\":\"") - 1) + kHashHexChars +
    (sizeof("\",\"total_weight\":") - 1) +
        DecimalChars(kMaxSnapshotTotalWeight) +
    (sizeof(",\"active\":") - 1) + (sizeof("false") - 1) +
    (sizeof(",\"members\":[") - 1) + kSnapshotMembersJsonMaxBytes +
    (sizeof("],\"finalized\":") - 1) + kFinalizedRecordJsonMaxBytes +
    (sizeof("}}") - 1);

// veld-validator always sends JSON-RPC id "val1". RpcServer preserves that
// canonical id and emits fields in this exact JsonBuilder order.
inline constexpr size_t kValidatorRpcEnvelopePrefixBytes =
    sizeof("{\"jsonrpc\":\"2.0\",\"id\":\"val1\",\"result\":") - 1;
inline constexpr size_t kValidatorRpcEnvelopeSuffixBytes =
    sizeof(",\"error\":null}") - 1;

inline constexpr size_t kSnapshotJsonResponseMaxBytes =
    kValidatorRpcEnvelopePrefixBytes + kSnapshotResultJsonMaxBytes +
    kValidatorRpcEnvelopeSuffixBytes;

// getfinalityqc returns the canonical QB2 payload as lowercase hex.  Use the
// consensus carrier ceiling rather than today's slightly smaller maximum-set
// encoding so any future valid encoding up to MAX_FINALITY_QC_BYTES remains
// representable without another client release.
inline constexpr size_t kQcResultJsonMaxBytes =
    (sizeof("{\"qc_hex\":\"") - 1) + 2U * qc::MAX_FINALITY_QC_BYTES +
    (sizeof("\"}") - 1);
inline constexpr size_t kQcJsonResponseMaxBytes =
    kValidatorRpcEnvelopePrefixBytes + kQcResultJsonMaxBytes +
    kValidatorRpcEnvelopeSuffixBytes;

// Exact fixed headers emitted by RpcHttpServer for an authenticated POST.
// Content-Length is the only response-size-dependent header field.
inline constexpr size_t kRpcHttpFixedHeaderBytes =
    (sizeof("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n") - 1) +
#ifdef VELD_PUBLIC_TESTNET
    (sizeof("Access-Control-Allow-Origin: null\r\n"
            "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type, Authorization\r\n") - 1) +
#else
    (sizeof("Access-Control-Allow-Origin: https://wallet.veld.network\r\n"
            "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type, Authorization\r\n") - 1) +
#endif
    (sizeof("Content-Length: ") - 1) +
    (sizeof("\r\nConnection: close\r\n\r\n") - 1);

constexpr size_t HttpResponseBytesFor(size_t json_body_bytes) {
    return json_body_bytes + kRpcHttpFixedHeaderBytes +
           DecimalChars(static_cast<uint64_t>(json_body_bytes));
}

struct ResponsePolicy {
    size_t max_http_response_bytes;
    size_t max_json_response_bytes;
};

inline constexpr ResponsePolicy kDefaultResponsePolicy{
    kDefaultRpcResponseBytes, kDefaultRpcResponseBytes};
inline constexpr ResponsePolicy kSnapshotResponsePolicy{
    HttpResponseBytesFor(kSnapshotJsonResponseMaxBytes),
    kSnapshotJsonResponseMaxBytes};
inline constexpr ResponsePolicy kQcResponsePolicy{
    HttpResponseBytesFor(kQcJsonResponseMaxBytes),
    kQcJsonResponseMaxBytes};

constexpr ResponsePolicy PolicyForMethod(std::string_view method) {
    return method == "getfinalitysnapshot" ? kSnapshotResponsePolicy :
           method == "getfinalityqc"       ? kQcResponsePolicy :
                                              kDefaultResponsePolicy;
}

inline bool AppendBoundedResponse(std::string& response, const char* bytes,
                                  size_t count, size_t limit) {
    if (response.size() > limit || count > limit - response.size())
        return false;
    response.append(bytes, count);
    return true;
}

static_assert(kValidatorPubkeyHexChars == 3904,
              "snapshot RPC width must track ML-DSA-65 public keys");
static_assert(kSnapshotJsonResponseMaxBytes > kDefaultRpcResponseBytes,
              "maximum finality snapshot must exercise the scoped large path");
static_assert(kQcJsonResponseMaxBytes > kDefaultRpcResponseBytes,
              "maximum finality QC must exercise the scoped large path");

} // namespace veld::finality::rpc_limits
