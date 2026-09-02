#pragma once
// finality_codec.h — the consensus wire format for finality certificates.
//
// DESIGN: the CERTIFICATE goes on chain, not the individual votes.
//
// Votes are gossiped off-chain and assembled by whoever builds the block; only
// the resulting QC is carried. This is not a size micro-optimisation, it is the
// difference between one transaction per checkpoint and five, and it means a
// replaying node validates one object instead of reassembling a quorum from
// scattered transactions whose ordering would then matter.
//
// COST, STATED PLAINLY: ML-DSA-65 signatures are 3,309 bytes and do not
// aggregate. A 5-of-7 certificate therefore carries ~16.5 KB of signature.
// At one checkpoint per hour that is ~16.5 KB/hour, ~145 MB/year of BLOCK data.
// That is the honest price of post-quantum finality and there is no clever
// encoding that avoids it — the alternative is not smaller signatures, it is
// weaker finality. Note what it is NOT: consensus STATE grows only by the
// retained FinalizedRecord (a few hundred bytes). Votes and certificates are
// history, not working set.
//
// A vote names its signer by the 32-byte commitment, never by the 1,952-byte
// key. Repeating keys is precisely what "made the rolling finality/reward
// window grow by gigabytes under otherwise-valid traffic" (validators.h:43);
// the key is resolved from the retained snapshot instead.
//
// The set root is NOT transmitted. It is reconstructed from the retained
// snapshot for the named epoch and fed into the signed preimage. If a signer
// and a verifier disagree about the set, the signature simply fails — the vote
// is bound to an exact validator set without spending a byte on it.
//
// one canonical byte representation per object. Parsing is
// strict — no leading zeroes, no '+', no ambiguous prefixes, no trailing junk —
// matching ParseCanonicalAmmI64's discipline. Two encodings of one meaning is
// a consensus split waiting for someone to notice.

#include "finality_qc.h"
#include "finality_votes.h"
#include "finality_wire_profile.h"
#include "core/marker_composition.h"

#include <optional>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>

namespace veld {
namespace finality {
namespace qc {

constexpr const char* FIN_PREFIX = "VELD_FINALITY|";
constexpr const char* FIN_QC_BINARY_PREFIX = "VELD_FINALITY|QB2|";
constexpr const char* FIN_QC_FRAGMENT_PREFIX = "VELD_FINALITY|QF1|";
constexpr const char* FIN_VOTE_BINARY_PREFIX = "FVT1";
constexpr size_t SIGNED_VOTE_WIRE_BYTES =
    ::veld::finality::wire::SIGNED_VOTE_BYTES;
constexpr size_t FINALITY_FRAGMENT_DATA_BYTES = 32'000;
constexpr size_t MAX_FINALITY_QC_BYTES = 7'500'000;
constexpr size_t MAX_FINALITY_CARRIER_FRAGMENTS =
    (MAX_FINALITY_QC_BYTES + FINALITY_FRAGMENT_DATA_BYTES - 1) /
    FINALITY_FRAGMENT_DATA_BYTES;
static_assert(MAX_FINALITY_CARRIER_FRAGMENTS ==
                  ::veld::MAX_FINALITY_MARKER_OUTPUTS,
              "core/finality fragment limits must remain identical");
constexpr size_t FinalityQuorumCountFor(size_t n) {
    return (2 * n) / 3 + 1;
}
constexpr size_t FinalityQcWireSizeFor(size_t n) {
    return std::char_traits<char>::length(FIN_QC_BINARY_PREFIX) +
           8 + 1 + 4 + 8 + 32 + 8 + 32 + 2 + ((n + 7) / 8) + 2 +
           FinalityQuorumCountFor(n) * ::veld::dilithium::SIG_MAX_BYTES;
}
static_assert(FinalityQcWireSizeFor(MAX_FINALITY_VALIDATOR_COUNT) <=
                  MAX_FINALITY_QC_BYTES &&
              FinalityQcWireSizeFor(MAX_FINALITY_VALIDATOR_COUNT + 1) >
                  MAX_FINALITY_QC_BYTES,
              "snapshot carrier ceiling must match QB2 capacity");

// ---------------------------------------------------------------- hex

inline std::string ToHexBytes(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s.push_back(d[p[i] >> 4]); s.push_back(d[p[i] & 15]); }
    return s;
}

inline bool FromHexBytes(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;   // uppercase deliberately rejected: one canonical form
    };
    out.clear(); out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return true;
}

inline bool HexToHash(const std::string& hex, Hash256& out) {
    if (hex.size() != 64) return false;
    std::vector<uint8_t> b;
    if (!FromHexBytes(hex, b) || b.size() != 32) return false;
    std::copy(b.begin(), b.end(), out.begin());
    return true;
}

// Canonical unsigned decimal. Same strictness as ParseCanonicalAmmI64: a
// consensus integer has exactly one spelling.
inline bool ParseCanonicalU64(const std::string& s, uint64_t* out) {
    if (!out || s.empty() || s.size() > 20) return false;
    if (s[0] == '0' && s.size() != 1) return false;      // no leading zeroes
    uint64_t v = 0;
    for (unsigned char c : s) {
        if (c < '0' || c > '9') return false;
        const uint64_t d = (uint64_t)(c - '0');
        if (v > (UINT64_MAX - d) / 10) return false;
        v = v * 10 + d;
    }
    *out = v;
    return true;
}

// ---------------------------------------------------------------- encode

// VELD_FINALITY|QC|epoch|phase|round|src_h|src_hash|tgt_h|tgt_hash|bitmap|sig,sig,...
//
// Field order matches the signed preimage's field order. That is deliberate:
// a reviewer comparing the wire format against VotePreimage() should be able
// to read them side by side, because a mismatch between what is signed and
// what is transmitted must remain byte-identical.
inline std::string EncodeQc(const QuorumCert& qc,
                            const std::vector<std::vector<uint8_t>>& sigs) {
    if (qc.bitmap.empty() || qc.bitmap.size() > UINT16_MAX ||
        sigs.empty() || sigs.size() > UINT16_MAX) return {};
    for (const auto& sig : sigs)
        if (sig.size() != ::veld::dilithium::SIG_MAX_BYTES) return {};

    std::string out(FIN_QC_BINARY_PREFIX);
    auto u8 = [&](uint8_t v) { out.push_back((char)v); };
    auto u16 = [&](uint16_t v) {
        u8((uint8_t)v); u8((uint8_t)(v >> 8));
    };
    auto u32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i) u8((uint8_t)(v >> (8 * i)));
    };
    auto u64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) u8((uint8_t)(v >> (8 * i)));
    };
    auto bytes = [&](const uint8_t* p, size_t n) {
        out.append(reinterpret_cast<const char*>(p), n);
    };
    u64(qc.epoch_id);
    u8((uint8_t)qc.phase);
    u32(qc.round);
    u64(qc.source.height); bytes(qc.source.hash.data(), qc.source.hash.size());
    u64(qc.target.height); bytes(qc.target.hash.data(), qc.target.hash.size());
    u16((uint16_t)qc.bitmap.size()); bytes(qc.bitmap.data(), qc.bitmap.size());
    u16((uint16_t)sigs.size());
    for (const auto& sig : sigs) bytes(sig.data(), sig.size());
    if (out.size() > MAX_FINALITY_QC_BYTES) return {};
    return out;
}

struct DecodedQc {
    QuorumCert                        qc;
    std::vector<std::vector<uint8_t>> sigs;   // in ascending signer-index order
};

// Split on a delimiter WITHOUT collapsing empties. An empty field must be a
// parse error, not a silently-defaulted zero.
inline std::vector<std::string> SplitExact(const std::string& s, char d) {
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == d) { out.push_back(s.substr(start, i - start)); start = i + 1; }
    }
    return out;
}

// Parse. Returns nullopt on ANY deviation. Never throws.
//
// This does NOT verify signatures or weight — that is VerifyDecodedQc below,
// which needs the snapshot. Separating them keeps the expensive work behind the
// cheap work: a malformed certificate costs a string split, not seven ML-DSA
// verifications.
inline std::optional<DecodedQc> DecodeQc(const std::string& data) {
    DecodedQc d;
    if (data.size() > MAX_FINALITY_QC_BYTES ||
        data.rfind(FIN_QC_BINARY_PREFIX, 0) != 0) return std::nullopt;
    size_t p = std::strlen(FIN_QC_BINARY_PREFIX);
    auto need = [&](size_t n) { return n <= data.size() - std::min(p, data.size()); };
    auto u8 = [&](uint8_t& v) {
        if (!need(1)) return false; v = (uint8_t)data[p++]; return true;
    };
    auto u16 = [&](uint16_t& v) {
        if (!need(2)) return false;
        v = (uint16_t)(uint8_t)data[p] | ((uint16_t)(uint8_t)data[p + 1] << 8);
        p += 2; return true;
    };
    auto u32 = [&](uint32_t& v) {
        if (!need(4)) return false; v = 0;
        for (int i = 0; i < 4; ++i) v |= (uint32_t)(uint8_t)data[p++] << (8 * i);
        return true;
    };
    auto u64 = [&](uint64_t& v) {
        if (!need(8)) return false; v = 0;
        for (int i = 0; i < 8; ++i) v |= (uint64_t)(uint8_t)data[p++] << (8 * i);
        return true;
    };
    auto bytes = [&](uint8_t* out, size_t n) {
        if (!need(n)) return false;
        std::memcpy(out, data.data() + p, n); p += n; return true;
    };
    uint8_t phase = 0;
    uint16_t bitmap_len = 0, sig_count = 0;
    if (!u64(d.qc.epoch_id) || !u8(phase) || (phase != 1 && phase != 2) ||
        !u32(d.qc.round) || !u64(d.qc.source.height) ||
        !bytes(d.qc.source.hash.data(), d.qc.source.hash.size()) ||
        !u64(d.qc.target.height) ||
        !bytes(d.qc.target.hash.data(), d.qc.target.hash.size()) ||
        !u16(bitmap_len) || bitmap_len == 0 || !need(bitmap_len)) return std::nullopt;
    d.qc.phase = (Phase)phase;
    d.qc.bitmap.assign((const uint8_t*)data.data() + p,
                       (const uint8_t*)data.data() + p + bitmap_len);
    p += bitmap_len;
    if (!u16(sig_count) || sig_count == 0) return std::nullopt;
    const size_t sig_bytes = (size_t)sig_count * ::veld::dilithium::SIG_MAX_BYTES;
    if (!need(sig_bytes) || p + sig_bytes != data.size()) return std::nullopt;
    d.sigs.reserve(sig_count);
    for (uint16_t i = 0; i < sig_count; ++i) {
        d.sigs.emplace_back((const uint8_t*)data.data() + p,
                            (const uint8_t*)data.data() + p +
                                ::veld::dilithium::SIG_MAX_BYTES);
        p += ::veld::dilithium::SIG_MAX_BYTES;
    }
    if (!SourceRefWellFormed(d.qc.source, d.qc.target) ||
        !IsScheduledCheckpoint(d.qc.target.height) ||
        EpochOf(d.qc.target.height) != d.qc.epoch_id ||
        d.qc.round != CheckpointRound(d.qc.target.height)) return std::nullopt;
    return d;
}

// Verify a decoded certificate against the epoch snapshot.
//
// The bitmap is a CLAIM about who signed; this is what turns it into evidence.
// Every set bit must have exactly one signature, in ascending index order, and
// each must verify against the preimage that signer would have produced. A
// bitmap with more bits than signatures — or fewer — is rejected outright
// rather than being generously reconciled.
inline bool VerifyDecodedQc(DecodedQc& d,
                            const EpochSnapshot& s,
                            uint32_t network_id,
                            const Hash256& genesis_hash) {
    if (!SnapshotWellFormed(s))              return false;
    if (d.qc.epoch_id != s.epoch_id)         return false;
    if (EpochOf(d.qc.target.height) != d.qc.epoch_id) return false;
    if (d.qc.round != CheckpointRound(d.qc.target.height)) return false;
    if (d.qc.bitmap.size() != (s.entries.size() + 7) / 8) return false;
    if (!IsScheduledCheckpoint(d.qc.target.height))       return false;
    if (!SourceRefWellFormed(d.qc.source, d.qc.target))   return false;

    // Any bit set beyond the set size would be counted by nobody but must not
    // be silently tolerated: it is a malformed certificate.
    for (size_t i = s.entries.size(); i < d.qc.bitmap.size() * 8; ++i)
        if (d.qc.bitmap[i >> 3] & (uint8_t)(1u << (i & 7))) return false;

    size_t sig_i = 0;
    const std::vector<uint8_t> msg = VotePreimage(
        network_id, genesis_hash, d.qc.epoch_id, s.root,
        d.qc.phase, d.qc.round, d.qc.source, d.qc.target);

    for (size_t i = 0; i < s.entries.size(); ++i) {
        if (!(d.qc.bitmap[i >> 3] & (uint8_t)(1u << (i & 7)))) continue;
        if (sig_i >= d.sigs.size())          return false;   // bitmap outruns sigs
        if (d.sigs[sig_i].size() != ::veld::dilithium::SIG_MAX_BYTES) return false;
        ::veld::dilithium::PublicKey pk{};
        if (!HexToPublicKey(s.entries[i].pubkey_hex, pk))    return false;
        if (!::veld::dilithium::Verify(pk, msg, d.sigs[sig_i])) return false;
        ++sig_i;
    }
    if (sig_i != d.sigs.size())              return false;   // sigs outrun bitmap

    // Recompute; never trust a transmitted weight.
    const uint64_t w = BitmapWeight(s, d.qc.bitmap);
    if (!IsSupermajority(w, s.total_weight)) return false;
    d.qc.set_root = s.root;
    d.qc.weight   = w;
    return true;
}

// Compact, canonical peer wire form for one signed vote.  Votes are not chain
// data, but relaying the 1,952-byte key and 3,309-byte signature as raw bytes
// avoids doubling both into hex and gives the P2P handler one exact length.
inline std::vector<uint8_t> EncodeSignedVoteWire(const SignedVote& v) {
    ::veld::dilithium::PublicKey pk{};
    if (!HexToPublicKey(v.pubkey_hex, pk) ||
        v.signature.size() != ::veld::dilithium::SIG_MAX_BYTES) return {};
    std::vector<uint8_t> out;
    out.insert(out.end(), FIN_VOTE_BINARY_PREFIX,
               FIN_VOTE_BINARY_PREFIX + std::strlen(FIN_VOTE_BINARY_PREFIX));
    state_digest::put_u64_le(out, v.epoch_id);
    state_digest::put_bytes(out, v.set_root.data(), v.set_root.size());
    state_digest::put_u8(out, (uint8_t)v.phase);
    state_digest::put_u32_le(out, v.round);
    state_digest::put_u64_le(out, v.source.height);
    state_digest::put_bytes(out, v.source.hash.data(), v.source.hash.size());
    state_digest::put_u64_le(out, v.target.height);
    state_digest::put_bytes(out, v.target.hash.data(), v.target.hash.size());
    state_digest::put_bytes(out, pk.data(), pk.size());
    state_digest::put_bytes(out, v.signature.data(), v.signature.size());
    return out;
}

inline std::optional<SignedVote> DecodeSignedVoteWire(
        const std::vector<uint8_t>& in) {
    constexpr size_t PREFIX = 4;
    constexpr size_t FIXED = SIGNED_VOTE_WIRE_BYTES;
    if (in.size() != FIXED ||
        !std::equal(in.begin(), in.begin() + PREFIX, FIN_VOTE_BINARY_PREFIX))
        return std::nullopt;
    size_t p = PREFIX;
    auto u8 = [&]() { return in[p++]; };
    auto u32 = [&]() { uint32_t v=0; for(int i=0;i<4;++i)v|=(uint32_t)in[p++]<<(8*i); return v; };
    auto u64 = [&]() { uint64_t v=0; for(int i=0;i<8;++i)v|=(uint64_t)in[p++]<<(8*i); return v; };
    SignedVote v;
    v.epoch_id = u64();
    std::copy_n(in.begin() + (ptrdiff_t)p, 32, v.set_root.begin()); p += 32;
    const uint8_t phase = u8();
    if (phase != 1 && phase != 2) return std::nullopt;
    v.phase = (Phase)phase;
    v.round = u32();
    v.source.height = u64();
    std::copy_n(in.begin() + (ptrdiff_t)p, 32, v.source.hash.begin()); p += 32;
    v.target.height = u64();
    std::copy_n(in.begin() + (ptrdiff_t)p, 32, v.target.hash.begin()); p += 32;
    v.pubkey_hex = ToHexBytes(in.data() + p, ::veld::dilithium::PUBKEY_BYTES);
    p += ::veld::dilithium::PUBKEY_BYTES;
    v.signature.assign(in.begin() + (ptrdiff_t)p, in.end());
    if (!SourceRefWellFormed(v.source, v.target) ||
        !IsScheduledCheckpoint(v.target.height) ||
        EpochOf(v.target.height) != v.epoch_id) return std::nullopt;
    return v;
}

// Scan a transaction for exactly one finality marker.
//
// More than one is INVALID even if the first parses: choosing "the first" would
// make output ordering change consensus meaning. Same rule, same reason, as
// ParseAmmOpDetailed.
enum class FinParseStatus : uint8_t { NONE = 0, VALID, INVALID };

struct FinParseResult {
    FinParseStatus status = FinParseStatus::NONE;
    DecodedQc      decoded;
};

inline Hash256 FinalityWireId(const std::string& wire) {
    const std::vector<uint8_t> bytes(wire.begin(), wire.end());
    return state_digest::sha256_domain("VELD_FINALITY_FRAGMENT_v1|", bytes);
}

// Convert one canonical QB2 certificate into one direct marker or an ordered
// QF1 fragment sequence. Each fragment independently fits the 32,768-byte
// consensus script ceiling; the block parser below requires the complete
// sequence in exact index order and reconstructs exactly one logical QC.
inline std::vector<std::string> EncodeFinalityCarrierPayloads(
        const std::string& wire) {
    constexpr size_t MAX_DIRECT_PAYLOAD = 32764; // OP_RETURN+PUSHDATA2 = 4
    if (wire.empty() || wire.size() > MAX_FINALITY_QC_BYTES ||
        !DecodeQc(wire)) return {};
    if (wire.size() <= MAX_DIRECT_PAYLOAD) return {wire};
    const size_t count = (wire.size() + FINALITY_FRAGMENT_DATA_BYTES - 1) /
                         FINALITY_FRAGMENT_DATA_BYTES;
    if (count == 0 || count > MAX_FINALITY_CARRIER_FRAGMENTS ||
        count > UINT16_MAX) return {};
    const Hash256 id = FinalityWireId(wire);
    std::vector<std::string> out;
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        std::string f(FIN_QC_FRAGMENT_PREFIX);
        f.append(reinterpret_cast<const char*>(id.data()), id.size());
        auto u16 = [&](uint16_t v) {
            f.push_back((char)v); f.push_back((char)(v >> 8));
        };
        auto u32 = [&](uint32_t v) {
            for (int n = 0; n < 4; ++n) f.push_back((char)(v >> (8 * n)));
        };
        u32((uint32_t)wire.size());
        u16((uint16_t)i);
        u16((uint16_t)count);
        const size_t off = i * FINALITY_FRAGMENT_DATA_BYTES;
        const size_t n = std::min(FINALITY_FRAGMENT_DATA_BYTES,
                                  wire.size() - off);
        f.append(wire.data() + off, n);
        if (f.size() > MAX_DIRECT_PAYLOAD) return {};
        out.push_back(std::move(f));
    }
    return out;
}

struct QcFragment {
    Hash256 id{};
    uint32_t total_bytes = 0;
    uint16_t index = 0;
    uint16_t count = 0;
    std::string bytes;
};

inline std::optional<QcFragment> DecodeQcFragment(const std::string& payload) {
    if (payload.rfind(FIN_QC_FRAGMENT_PREFIX, 0) != 0) return std::nullopt;
    size_t p = std::strlen(FIN_QC_FRAGMENT_PREFIX);
    constexpr size_t FIXED = 32 + 4 + 2 + 2;
    if (payload.size() < p + FIXED) return std::nullopt;
    QcFragment f;
    std::memcpy(f.id.data(), payload.data() + p, f.id.size());
    p += f.id.size();
    auto u16 = [&]() -> uint16_t {
        uint16_t v = (uint16_t)(uint8_t)payload[p] |
                     ((uint16_t)(uint8_t)payload[p + 1] << 8);
        p += 2; return v;
    };
    auto u32 = [&]() -> uint32_t {
        uint32_t v = 0;
        for (int n = 0; n < 4; ++n)
            v |= (uint32_t)(uint8_t)payload[p++] << (8 * n);
        return v;
    };
    f.total_bytes = u32();
    f.index = u16();
    f.count = u16();
    if (f.total_bytes == 0 || f.total_bytes > MAX_FINALITY_QC_BYTES ||
        f.count < 2 || f.count > MAX_FINALITY_CARRIER_FRAGMENTS ||
        f.index >= f.count) return std::nullopt;
    const size_t expected_count =
        (f.total_bytes + FINALITY_FRAGMENT_DATA_BYTES - 1) /
        FINALITY_FRAGMENT_DATA_BYTES;
    if (f.count != expected_count) return std::nullopt;
    const size_t expected_bytes = f.index + 1 == f.count
        ? f.total_bytes - (size_t)f.index * FINALITY_FRAGMENT_DATA_BYTES
        : FINALITY_FRAGMENT_DATA_BYTES;
    if (payload.size() - p != expected_bytes) return std::nullopt;
    f.bytes.assign(payload.data() + p, expected_bytes);
    return f;
}

// Parse all finality outputs in a block before mutating retained state. This
// enforces logical cardinality (exactly zero or one QC), zero value, shortest
// push opcode, no trailing bytes, and one canonical fragment order.
template <typename BlockT, typename ParseOpReturnFn>
inline FinParseResult ParseFinalityBlock(const BlockT& block,
                                         ParseOpReturnFn parse_op_return) {
    FinParseResult r;
    std::optional<std::string> direct;
    std::vector<QcFragment> fragments;
    for (const auto& tx : block.transactions) {
        for (const auto& o : tx.outputs) {
            const std::string payload = parse_op_return(o.script_pubkey);
            if (payload.rfind(FIN_PREFIX, 0) != 0) continue;
            if (o.value != 0 || o.script_pubkey.size() > 32768 ||
                !::veld::IsCanonicalMarkerOpReturn(o.script_pubkey, payload)) {
                r.status = FinParseStatus::INVALID; return r;
            }
            if (payload.rfind(FIN_QC_BINARY_PREFIX, 0) == 0) {
                if (direct || !fragments.empty()) {
                    r.status = FinParseStatus::INVALID; return r;
                }
                direct = payload;
            } else {
                auto f = DecodeQcFragment(payload);
                if (!f || direct || fragments.size() >=
                        MAX_FINALITY_CARRIER_FRAGMENTS) {
                    r.status = FinParseStatus::INVALID; return r;
                }
                fragments.push_back(std::move(*f));
            }
        }
    }
    std::string wire;
    if (direct) {
        wire = std::move(*direct);
    } else if (!fragments.empty()) {
        const auto& first = fragments.front();
        if (fragments.size() != first.count) {
            r.status = FinParseStatus::INVALID; return r;
        }
        wire.reserve(first.total_bytes);
        for (size_t i = 0; i < fragments.size(); ++i) {
            const auto& f = fragments[i];
            if (f.id != first.id || f.total_bytes != first.total_bytes ||
                f.count != first.count || f.index != i) {
                r.status = FinParseStatus::INVALID; return r;
            }
            wire.append(f.bytes);
        }
        if (wire.size() != first.total_bytes ||
            FinalityWireId(wire) != first.id) {
            r.status = FinParseStatus::INVALID; return r;
        }
    } else {
        return r;
    }
    auto decoded = DecodeQc(wire);
    if (!decoded) { r.status = FinParseStatus::INVALID; return r; }
    r.decoded = std::move(*decoded);
    r.status = FinParseStatus::VALID;
    return r;
}

template <typename TxT, typename ParseOpReturnFn>
inline FinParseResult ParseFinalityOp(const TxT& tx, ParseOpReturnFn parse_op_return) {
    FinParseResult r;
    size_t markers = 0;
    for (const auto& o : tx.outputs) {
        const std::string data = parse_op_return(o.script_pubkey);
        if (data.rfind(FIN_PREFIX, 0) != 0) continue;
        if (++markers > 1 || o.value != 0 || o.script_pubkey.size() > 32768 ||
            !::veld::IsCanonicalMarkerOpReturn(o.script_pubkey, data)) {
            r.status = FinParseStatus::INVALID; return r;
        }
        auto d = DecodeQc(data);
        if (!d) { r.status = FinParseStatus::INVALID; return r; }
        r.decoded = *d;
        r.status  = FinParseStatus::VALID;
    }
    return r;
}

}  // namespace qc
}  // namespace finality
}  // namespace veld
