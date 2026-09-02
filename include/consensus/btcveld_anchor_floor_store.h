#pragma once
// btcveld_anchor_floor_store.h -- durable, local btcVELD recovery floor.
//
// This is deliberately NOT a consensus/bootstrap artifact and carries no
// operator signature.  It is the node's monotonic memory of the highest
// Bitcoin-authenticated Veld prefix that this node has already accepted.  A
// future startup/recovery caller may compare it with independently verified
// chain state; this file only supplies the canonical codec, strict structural
// checks, rollback-resistant in-process merge rule, and durable replacement.
//
// VLF1 is a fixed-width binary format.  There are no optional fields, lengths,
// textual integers, or ignored suffixes:
//
//   "VLF1"                                      4
//   network_magic (u32 little endian)           4
//   genesis_hash                               32
//   T: target_height (u64le), target_hash      40
//   A: proof-carrier height (u64le), hash      40
//   Bitcoin block hash, transaction id         64
//   authorization FinalizedRecord             165
//   floor_digest                               32
//                                               ---
//                                               381 bytes exactly
//
// floor_digest = SHA256("VELD_ANCHOR_LOCAL_FLOOR_V1|" || all preceding
// 349 bytes).  The network identity, T, A, Bitcoin proof identity, and complete
// finality authorization are consequently inseparable.  The redundant
// authorization fields in AnchorSet::Entry are reconstructed from the full
// FinalizedRecord and must match when an in-memory checkpoint is encoded.

#include "btcveld_anchor.h"
#include "../wallet/secure_channel_file.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace veld {
namespace btcanchor {
namespace floor_store {

constexpr size_t VLF1_PREFIX_SIZE = 349;
constexpr size_t VLF1_ENCODED_SIZE = 381;
constexpr char VLF1_DOMAIN[] = "VELD_ANCHOR_LOCAL_FLOOR_V1|";

struct Record {
    uint32_t network_magic = 0;
    ::veld::Hash256 genesis_hash{};
    AnchorSet::PermanentCheckpoint checkpoint{};
    ::veld::Hash256 floor_digest{};
};

inline void SetError(std::string* error, const std::string& message) {
    if (error) *error = message;
}

inline void ClearError(std::string* error) {
    if (error) error->clear();
}

inline void PutHash(std::vector<uint8_t>& out, const ::veld::Hash256& hash) {
    ::veld::state_digest::put_bytes(out, hash.data(), hash.size());
}

// Serialize every digest-covered field.  Validation is intentionally separate
// so Decode can parse first and then run one invariant set shared with Encode.
inline std::vector<uint8_t> CanonicalPrefix(const Record& record) {
    namespace sd = ::veld::state_digest;
    const auto& p = record.checkpoint;
    const auto& e = p.entry;
    const auto& f = p.authorization_record;

    std::vector<uint8_t> out;
    out.reserve(VLF1_PREFIX_SIZE);
    out.push_back('V');
    out.push_back('L');
    out.push_back('F');
    out.push_back('1');
    sd::put_u32_le(out, record.network_magic);
    PutHash(out, record.genesis_hash);

    sd::put_u64_le(out, p.target_height);
    PutHash(out, e.veld_block_hash);
    sd::put_u64_le(out, e.carrying_veld_height);
    PutHash(out, e.carrying_veld_hash);
    PutHash(out, e.btc_block_hash);
    PutHash(out, e.btc_txid);

    sd::put_u64_le(out, f.epoch_id);
    sd::put_u64_le(out, f.target.height);
    PutHash(out, f.target.hash);
    PutHash(out, f.set_root);
    sd::put_u32_le(out, f.round);
    sd::put_u8(out, static_cast<uint8_t>(f.phase));
    PutHash(out, f.cert_commit);
    sd::put_u64_le(out, f.carrier.height);
    PutHash(out, f.carrier.hash);
    sd::put_u64_le(out, f.retention_floor);
    return out;
}

inline ::veld::Hash256 ComputeFloorDigest(const Record& record) {
    const std::vector<uint8_t> prefix = CanonicalPrefix(record);
    return ::veld::state_digest::sha256_domain(VLF1_DOMAIN, prefix);
}

inline bool ValidateCheckpoint(
    const AnchorSet::PermanentCheckpoint& checkpoint,
    std::string* error = nullptr)
{
    namespace fq = ::veld::finality::qc;
    const auto& e = checkpoint.entry;
    const auto& f = checkpoint.authorization_record;

    // T is an actual historical block and A is the later, exact Veld block
    // which carried its Bitcoin proof.  Record() fixtures have a null A hash,
    // null Bitcoin block, and no authorization record, so they fail here.
    if (checkpoint.target_height == 0 ||
        ::veld::HashIsZero(e.veld_block_hash)) {
        SetError(error, "VLF1 target T is null");
        return false;
    }
    if (e.carrying_veld_height <= checkpoint.target_height ||
        ::veld::HashIsZero(e.carrying_veld_hash)) {
        SetError(error, "VLF1 proof carrier A must be exact and later than T");
        return false;
    }
    if (!::veld::BtcVeldAnchorTargetInWindow(
            checkpoint.target_height, e.carrying_veld_height)) {
        SetError(error,
                 "VLF1 proof carrier A is outside the anchor admission window");
        return false;
    }
    if (::veld::HashIsZero(e.btc_block_hash) ||
        ::veld::HashIsZero(e.btc_txid)) {
        SetError(error, "VLF1 Bitcoin proof identity is null");
        return false;
    }

    // These are all properties of Finalize() output which can be checked
    // without a validator snapshot or QC signatures.  Cryptographic/ancestry
    // verification belongs to the future node wiring, not this local codec.
    if (f.IsNull()) {
        SetError(error, "VLF1 authorization record is null");
        return false;
    }
    if (f.phase != fq::Phase::PRECOMMIT) {
        SetError(error, "VLF1 authorization is not a PRECOMMIT record");
        return false;
    }
    if (f.epoch_id == 0 ||
        !fq::IsScheduledCheckpoint(f.target.height) ||
        f.epoch_id != fq::EpochOf(f.target.height) ||
        f.round != fq::CheckpointRound(f.target.height)) {
        SetError(error, "VLF1 authorization target/epoch/round is inconsistent");
        return false;
    }
    if (::veld::HashIsZero(f.target.hash) ||
        ::veld::HashIsZero(f.set_root) ||
        ::veld::HashIsZero(f.cert_commit) ||
        ::veld::HashIsZero(f.carrier.hash)) {
        SetError(error, "VLF1 authorization contains a null commitment");
        return false;
    }
    if (!fq::InVoteWindow(f.target.height, f.carrier.height) ||
        f.retention_floor != f.target.height) {
        SetError(error, "VLF1 authorization carrier/retention fields are inconsistent");
        return false;
    }
    if (e.carrying_veld_height > f.target.height) {
        SetError(error, "VLF1 finality target does not cover proof carrier A");
        return false;
    }
    if (e.carrying_veld_height == f.target.height &&
        e.carrying_veld_hash != f.target.hash) {
        SetError(error,
                 "VLF1 proof carrier A conflicts with finality target at the same height");
        return false;
    }

    const ::veld::Hash256 authorization_digest = fq::RecordDigest(f);
    if (e.authorization_veld_height != f.carrier.height ||
        e.authorization_veld_hash != f.carrier.hash ||
        e.authorization_finality_digest != authorization_digest) {
        SetError(error, "VLF1 redundant authorization fields conflict with full record");
        return false;
    }
    return true;
}

inline bool Validate(const Record& record, std::string* error = nullptr) {
    if (::veld::HashIsZero(record.genesis_hash)) {
        SetError(error, "VLF1 genesis identity is null");
        return false;
    }
    if (!ValidateCheckpoint(record.checkpoint, error)) return false;

    const std::vector<uint8_t> prefix = CanonicalPrefix(record);
    if (prefix.size() != VLF1_PREFIX_SIZE) {
        SetError(error, "internal VLF1 prefix size mismatch");
        return false;
    }
    if (record.floor_digest !=
        ::veld::state_digest::sha256_domain(VLF1_DOMAIN, prefix)) {
        SetError(error, "VLF1 floor digest mismatch");
        return false;
    }
    return true;
}

// The only constructor for a new local floor.  It refuses the null
// authorization produced by AnchorSet::Record() test fixtures.
inline std::optional<Record> Make(
    uint32_t network_magic,
    const ::veld::Hash256& genesis_hash,
    const AnchorSet::PermanentCheckpoint& checkpoint,
    std::string* error = nullptr)
{
    ClearError(error);
    Record out;
    out.network_magic = network_magic;
    out.genesis_hash = genesis_hash;
    out.checkpoint = checkpoint;
    if (::veld::HashIsZero(out.genesis_hash)) {
        SetError(error, "VLF1 genesis identity is null");
        return std::nullopt;
    }
    if (!ValidateCheckpoint(out.checkpoint, error)) return std::nullopt;
    const std::vector<uint8_t> prefix = CanonicalPrefix(out);
    if (prefix.size() != VLF1_PREFIX_SIZE) {
        SetError(error, "internal VLF1 prefix size mismatch");
        return std::nullopt;
    }
    out.floor_digest =
        ::veld::state_digest::sha256_domain(VLF1_DOMAIN, prefix);
    return out;
}

inline std::optional<std::vector<uint8_t>> Encode(
    const Record& record, std::string* error = nullptr)
{
    ClearError(error);
    if (!Validate(record, error)) return std::nullopt;
    std::vector<uint8_t> out = CanonicalPrefix(record);
    PutHash(out, record.floor_digest);
    if (out.size() != VLF1_ENCODED_SIZE) {
        SetError(error, "internal VLF1 encoded size mismatch");
        return std::nullopt;
    }
    return out;
}

class Reader {
public:
    explicit Reader(const std::vector<uint8_t>& bytes) : bytes_(bytes) {}

    bool Magic() {
        static constexpr uint8_t magic[4] = {'V', 'L', 'F', '1'};
        if (bytes_.size() - offset_ < sizeof(magic) ||
            std::memcmp(bytes_.data() + offset_, magic, sizeof(magic)) != 0)
            return false;
        offset_ += sizeof(magic);
        return true;
    }

    bool U8(uint8_t& value) {
        if (offset_ >= bytes_.size()) return false;
        value = bytes_[offset_++];
        return true;
    }

    bool U32(uint32_t& value) {
        if (bytes_.size() - offset_ < 4) return false;
        value = static_cast<uint32_t>(bytes_[offset_]) |
                (static_cast<uint32_t>(bytes_[offset_ + 1]) << 8) |
                (static_cast<uint32_t>(bytes_[offset_ + 2]) << 16) |
                (static_cast<uint32_t>(bytes_[offset_ + 3]) << 24);
        offset_ += 4;
        return true;
    }

    bool U64(uint64_t& value) {
        if (bytes_.size() - offset_ < 8) return false;
        value = 0;
        for (unsigned i = 0; i < 8; ++i)
            value |= static_cast<uint64_t>(bytes_[offset_ + i]) << (8 * i);
        offset_ += 8;
        return true;
    }

    bool Hash(::veld::Hash256& value) {
        if (bytes_.size() - offset_ < value.size()) return false;
        std::memcpy(value.data(), bytes_.data() + offset_, value.size());
        offset_ += value.size();
        return true;
    }

    size_t Offset() const { return offset_; }
    bool AtEnd() const { return offset_ == bytes_.size(); }

private:
    const std::vector<uint8_t>& bytes_;
    size_t offset_ = 0;
};

inline std::optional<Record> Decode(
    const std::vector<uint8_t>& bytes, std::string* error = nullptr)
{
    ClearError(error);
    if (bytes.size() != VLF1_ENCODED_SIZE) {
        SetError(error, "VLF1 must be exactly 381 bytes");
        return std::nullopt;
    }

    Record out;
    auto& p = out.checkpoint;
    auto& e = p.entry;
    auto& f = p.authorization_record;
    Reader reader(bytes);
    uint8_t phase = 0;
    if (!reader.Magic() ||
        !reader.U32(out.network_magic) ||
        !reader.Hash(out.genesis_hash) ||
        !reader.U64(p.target_height) ||
        !reader.Hash(e.veld_block_hash) ||
        !reader.U64(e.carrying_veld_height) ||
        !reader.Hash(e.carrying_veld_hash) ||
        !reader.Hash(e.btc_block_hash) ||
        !reader.Hash(e.btc_txid) ||
        !reader.U64(f.epoch_id) ||
        !reader.U64(f.target.height) ||
        !reader.Hash(f.target.hash) ||
        !reader.Hash(f.set_root) ||
        !reader.U32(f.round) ||
        !reader.U8(phase) ||
        !reader.Hash(f.cert_commit) ||
        !reader.U64(f.carrier.height) ||
        !reader.Hash(f.carrier.hash) ||
        !reader.U64(f.retention_floor) ||
        !reader.Hash(out.floor_digest) ||
        !reader.AtEnd()) {
        SetError(error, "VLF1 truncated, malformed, or has trailing bytes");
        return std::nullopt;
    }
    f.phase = static_cast<::veld::finality::qc::Phase>(phase);

    // The compact VLF1 body stores the authoritative full record once.  These
    // fields are exact derivations, never a second spelling on disk.
    e.authorization_veld_height = f.carrier.height;
    e.authorization_veld_hash = f.carrier.hash;
    e.authorization_finality_digest =
        ::veld::finality::qc::RecordDigest(f);

    if (!Validate(out, error)) return std::nullopt;
    return out;
}

inline bool ExactDuplicate(const Record& a, const Record& b) {
    if (a.floor_digest != b.floor_digest) return false;
    return CanonicalPrefix(a) == CanonicalPrefix(b);
}

enum class MergeResult {
    Installed,
    Advanced,
    Idempotent,
    Rejected,
    IoError,
};

enum class LoadResult {
    NotFound,
    Loaded,
    Rejected,
    IoError,
};

// Single-writer local store.  Merge() is useful for deterministic validation
// and tests; MergeAndPersist() is the operational path.  It publishes bytes
// with exclusive temp creation, file fsync, atomic replacement, and directory
// fsync (or Windows write-through), then advances memory only after success.
class Store {
public:
    const std::optional<Record>& Current() const { return current_; }

    MergeResult Merge(const Record& incoming, std::string* error = nullptr) {
        ClearError(error);
        const MergeResult decision = Classify_(incoming, error);
        if (decision == MergeResult::Installed ||
            decision == MergeResult::Advanced) {
            current_ = incoming;
            durable_path_.clear();
        }
        return decision;
    }

    MergeResult MergeAndPersist(const std::string& path,
                                const Record& incoming,
                                std::string* error = nullptr) {
        ClearError(error);
        const MergeResult decision = Classify_(incoming, error);
        if (decision == MergeResult::Rejected) return decision;

        // An exact duplicate is a no-op only if this exact Store learned it
        // from, or committed it to, this path.  A prior in-memory Merge must
        // still publish the bytes when durability is requested.
        if (decision == MergeResult::Idempotent && durable_path_ == path)
            return decision;

        const auto encoded = Encode(incoming, error);
        if (!encoded) return MergeResult::Rejected;
        if (!::veld::channel::secure_file::AtomicWrite(
                path, *encoded, error,
                /*require_private_parent=*/true)) {
            return MergeResult::IoError;
        }
        current_ = incoming;
        durable_path_ = path;
        return decision;
    }

    LoadResult Load(const std::string& path,
                    uint32_t expected_network_magic,
                    const ::veld::Hash256& expected_genesis_hash,
                    std::string* error = nullptr) {
        ClearError(error);
        std::vector<uint8_t> bytes;
        const auto read = ::veld::channel::secure_file::Read(
            path, bytes, error, VLF1_ENCODED_SIZE,
            /*require_private_parent=*/true);
        if (read == ::veld::channel::secure_file::ReadResult::NotFound)
            return LoadResult::NotFound;
        if (read != ::veld::channel::secure_file::ReadResult::Ok)
            return LoadResult::IoError;

        const auto decoded = Decode(bytes, error);
        if (!decoded) return LoadResult::Rejected;
        if (decoded->network_magic != expected_network_magic ||
            decoded->genesis_hash != expected_genesis_hash) {
            SetError(error, "VLF1 belongs to a different network or genesis");
            return LoadResult::Rejected;
        }

        const MergeResult decision = Classify_(*decoded, error);
        if (decision == MergeResult::Rejected)
            return LoadResult::Rejected;
        current_ = *decoded;
        durable_path_ = path;
        return LoadResult::Loaded;
    }

private:
    MergeResult Classify_(const Record& incoming,
                          std::string* error) const {
        if (!Validate(incoming, error)) return MergeResult::Rejected;
        if (!current_) return MergeResult::Installed;

        if (incoming.network_magic != current_->network_magic ||
            incoming.genesis_hash != current_->genesis_hash) {
            SetError(error, "VLF1 merge changes network or genesis identity");
            return MergeResult::Rejected;
        }
        if (ExactDuplicate(incoming, *current_))
            return MergeResult::Idempotent;

        const uint64_t incoming_t = incoming.checkpoint.target_height;
        const uint64_t current_t = current_->checkpoint.target_height;
        if (incoming_t <= current_t) {
            SetError(error,
                     "VLF1 merge is lower or conflicts at the current T");
            return MergeResult::Rejected;
        }

        const uint64_t incoming_c =
            incoming.checkpoint.authorization_record.carrier.height;
        const uint64_t current_c =
            current_->checkpoint.authorization_record.carrier.height;
        if (incoming_c <= current_c) {
            SetError(error,
                     "VLF1 merge must advance finality carrier C with T");
            return MergeResult::Rejected;
        }
        return MergeResult::Advanced;
    }

    std::optional<Record> current_;
    std::string durable_path_;
};

}  // namespace floor_store
}  // namespace btcanchor
}  // namespace veld
