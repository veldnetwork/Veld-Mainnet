#pragma once

#include "../core/hash.h"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace veld::work_admission {

enum class Path : uint8_t {
    InternalMining,
    GetBlockTemplate,
    SubmitBlock,
    SynchronousGeneration,
    ValidatorEndorsement,
    FinalityVote,
};

enum class Purpose : uint8_t {
    BlockProduction = 1,
    ValidatorEndorsement = 2,
    FinalityVote = 3,
};

enum class Refusal : uint8_t {
    None,
    Unwired,
    RoleDenied,
    NodeNotRunning,
    StartupReplayIncomplete,
    IndependentValidationIncomplete,
    SyncIncomplete,
    SnapshotStateUntrusted,
    DurableStateUnproven,
    DatadirIdentityUnproven,
    CheckpointAnchorUnproven,
    TipUnknown,
    RuntimeClosed,
    PeerViewUnsafe,
    SubjectNotCanonical,
    BindingMissing,
    BindingMismatch,
};

struct Subject {
    Purpose purpose{Purpose::BlockProduction};
    uint64_t height{0};
    Hash256 target_hash{};
    uint64_t parent_height{0};
    Hash256 parent_hash{};

    bool operator==(const Subject& other) const noexcept {
        return purpose == other.purpose && height == other.height &&
               target_hash == other.target_hash && parent_height == other.parent_height &&
               parent_hash == other.parent_hash;
    }
};

struct Prerequisites {
    bool role_permitted{false};
    bool node_running{false};
    bool startup_replay_complete{false};
    bool independent_validation_complete{false};
    bool sync_complete{false};
    bool snapshot_state_clean{false};
    bool durable_state_proven{false};
    bool datadir_identity_valid{false};
    bool checkpoint_anchor_valid{false};
    bool canonical_tip_known{false};
    bool runtime_open{false};
    bool peer_view_safe{false};
    uint64_t validation_generation{0};
    uint32_t network_magic{0};
    Hash256 genesis_hash{};
    Hash256 profile_digest{};
};

struct Binding {
    uint8_t version{1};
    Subject subject{};
    uint64_t validation_generation{0};
    uint32_t network_magic{0};
    Hash256 genesis_hash{};
    Hash256 profile_digest{};

    bool operator==(const Binding& other) const noexcept {
        return version == other.version && subject == other.subject &&
               validation_generation == other.validation_generation &&
               network_magic == other.network_magic && genesis_hash == other.genesis_hash &&
               profile_digest == other.profile_digest;
    }
};

struct Decision {
    bool allowed{false};
    Refusal refusal{Refusal::Unwired};
    std::optional<Binding> binding;
};

inline const char* RefusalName(Refusal refusal) noexcept {
    switch (refusal) {
    case Refusal::None:
        return "none";
    case Refusal::Unwired:
        return "unwired";
    case Refusal::RoleDenied:
        return "role_denied";
    case Refusal::NodeNotRunning:
        return "node_not_running";
    case Refusal::StartupReplayIncomplete:
        return "startup_replay_incomplete";
    case Refusal::IndependentValidationIncomplete:
        return "independent_validation_incomplete";
    case Refusal::SyncIncomplete:
        return "sync_incomplete";
    case Refusal::SnapshotStateUntrusted:
        return "snapshot_state_untrusted";
    case Refusal::DurableStateUnproven:
        return "durable_state_unproven";
    case Refusal::DatadirIdentityUnproven:
        return "datadir_identity_unproven";
    case Refusal::CheckpointAnchorUnproven:
        return "checkpoint_anchor_unproven";
    case Refusal::TipUnknown:
        return "tip_unknown";
    case Refusal::RuntimeClosed:
        return "runtime_closed";
    case Refusal::PeerViewUnsafe:
        return "peer_view_unsafe";
    case Refusal::SubjectNotCanonical:
        return "subject_not_canonical";
    case Refusal::BindingMissing:
        return "binding_missing";
    case Refusal::BindingMismatch:
        return "binding_mismatch";
    }
    return "unknown";
}

inline Decision Evaluate(const Subject& subject, const Prerequisites& prerequisites,
                         const std::optional<Binding>& prior = std::nullopt,
                         bool require_prior = false) noexcept {
    auto deny = [](Refusal refusal) { return Decision{false, refusal, std::nullopt}; };
    if (!prerequisites.role_permitted)
        return deny(Refusal::RoleDenied);
    if (!prerequisites.node_running)
        return deny(Refusal::NodeNotRunning);
    if (!prerequisites.startup_replay_complete)
        return deny(Refusal::StartupReplayIncomplete);
    if (!prerequisites.independent_validation_complete)
        return deny(Refusal::IndependentValidationIncomplete);
    if (!prerequisites.sync_complete)
        return deny(Refusal::SyncIncomplete);
    if (!prerequisites.snapshot_state_clean)
        return deny(Refusal::SnapshotStateUntrusted);
    if (!prerequisites.durable_state_proven)
        return deny(Refusal::DurableStateUnproven);
    if (!prerequisites.datadir_identity_valid)
        return deny(Refusal::DatadirIdentityUnproven);
    if (!prerequisites.checkpoint_anchor_valid)
        return deny(Refusal::CheckpointAnchorUnproven);
    if (!prerequisites.canonical_tip_known)
        return deny(Refusal::TipUnknown);
    if (!prerequisites.runtime_open)
        return deny(Refusal::RuntimeClosed);
    if (!prerequisites.peer_view_safe)
        return deny(Refusal::PeerViewUnsafe);
    if (subject.height == 0 || HashIsZero(subject.parent_hash))
        return deny(Refusal::SubjectNotCanonical);
    if (subject.purpose == Purpose::BlockProduction) {
        if (subject.height != subject.parent_height + 1 || !HashIsZero(subject.target_hash))
            return deny(Refusal::SubjectNotCanonical);
    } else if (HashIsZero(subject.target_hash)) {
        // Validator endorsements and finality votes may target an historical
        // canonical block.  parent_* is deliberately the current canonical
        // tip to which the authorization is bound, not the target's parent.
        return deny(Refusal::SubjectNotCanonical);
    }

    Binding current;
    current.subject = subject;
    current.validation_generation = prerequisites.validation_generation;
    current.network_magic = prerequisites.network_magic;
    current.genesis_hash = prerequisites.genesis_hash;
    current.profile_digest = prerequisites.profile_digest;
    if (require_prior && !prior)
        return deny(Refusal::BindingMissing);
    if (prior && *prior != current)
        return deny(Refusal::BindingMismatch);
    return Decision{true, Refusal::None, current};
}

inline void AppendU64(std::vector<uint8_t>& out, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i)
        out.push_back(static_cast<uint8_t>(value >> (8U * i)));
}
inline void AppendU32(std::vector<uint8_t>& out, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
        out.push_back(static_cast<uint8_t>(value >> (8U * i)));
}

inline std::string EncodeBinding(const Binding& binding) {
    std::vector<uint8_t> bytes;
    bytes.reserve(158);
    bytes.push_back(binding.version);
    bytes.push_back(static_cast<uint8_t>(binding.subject.purpose));
    AppendU64(bytes, binding.subject.height);
    bytes.insert(bytes.end(), binding.subject.target_hash.begin(),
                 binding.subject.target_hash.end());
    AppendU64(bytes, binding.subject.parent_height);
    bytes.insert(bytes.end(), binding.subject.parent_hash.begin(),
                 binding.subject.parent_hash.end());
    AppendU64(bytes, binding.validation_generation);
    AppendU32(bytes, binding.network_magic);
    bytes.insert(bytes.end(), binding.genesis_hash.begin(), binding.genesis_hash.end());
    bytes.insert(bytes.end(), binding.profile_digest.begin(), binding.profile_digest.end());
    return "v1:" + BytesToHex(bytes);
}

inline std::optional<Binding> DecodeBinding(std::string_view encoded) noexcept {
    constexpr size_t kBytes = 158;
    if (encoded.size() != 3U + kBytes * 2U || encoded.substr(0, 3) != "v1:")
        return std::nullopt;
    std::vector<uint8_t> bytes;
    bytes.reserve(kBytes);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        return -1;
    };
    for (size_t i = 3; i < encoded.size(); i += 2) {
        const int high = nibble(encoded[i]);
        const int low = nibble(encoded[i + 1]);
        if (high < 0 || low < 0)
            return std::nullopt;
        bytes.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    size_t offset = 0;
    auto read_u64 = [&]() {
        uint64_t value = 0;
        for (unsigned i = 0; i < 8; ++i)
            value |= static_cast<uint64_t>(bytes[offset++]) << (8U * i);
        return value;
    };
    auto read_u32 = [&]() {
        uint32_t value = 0;
        for (unsigned i = 0; i < 4; ++i)
            value |= static_cast<uint32_t>(bytes[offset++]) << (8U * i);
        return value;
    };
    Binding binding;
    binding.version = bytes[offset++];
    if (binding.version != 1)
        return std::nullopt;
    const uint8_t purpose = bytes[offset++];
    if (purpose < static_cast<uint8_t>(Purpose::BlockProduction) ||
        purpose > static_cast<uint8_t>(Purpose::FinalityVote))
        return std::nullopt;
    binding.subject.purpose = static_cast<Purpose>(purpose);
    binding.subject.height = read_u64();
    std::copy_n(bytes.begin() + offset, 32, binding.subject.target_hash.begin());
    offset += 32;
    binding.subject.parent_height = read_u64();
    std::copy_n(bytes.begin() + offset, 32, binding.subject.parent_hash.begin());
    offset += 32;
    binding.validation_generation = read_u64();
    binding.network_magic = read_u32();
    std::copy_n(bytes.begin() + offset, 32, binding.genesis_hash.begin());
    offset += 32;
    std::copy_n(bytes.begin() + offset, 32, binding.profile_digest.begin());
    offset += 32;
    if (offset != bytes.size())
        return std::nullopt;
    return binding;
}

} // namespace veld::work_admission
