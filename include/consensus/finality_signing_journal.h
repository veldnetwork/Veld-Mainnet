#pragma once
#include "finality_daemon.h"
#include "finality_codec.h"
#include "../wallet/secure_channel_file.h"

namespace veld::finality::qc {
namespace fq = veld::finality::qc;
inline std::vector<uint8_t> encode_finality_journal(const fq::DaemonJournal& journal) {
    std::vector<uint8_t> out{'V', 'F', 'J', '1'};
    state_digest::put_u32_le(out, journal.version);
    state_digest::put_u8(out, journal.lock.held ? 1 : 0);
    state_digest::put_u64_le(out, journal.lock.epoch_id);
    state_digest::put_u32_le(out, journal.lock.round);
    state_digest::put_u64_le(out, journal.lock.target.height);
    state_digest::put_bytes(out, journal.lock.target.hash.data(), 32);
    state_digest::put_u8(out, journal.last_vote ? 1 : 0);
    if (journal.last_vote) {
        const auto vote = fq::EncodeSignedVoteWire(*journal.last_vote);
        if (vote.size() != fq::SIGNED_VOTE_WIRE_BYTES)
            return {};
        state_digest::put_bytes(out, vote.data(), vote.size());
    }
    const Hash256 checksum = state_digest::sha256_domain("VELD_FINALITY_DAEMON_JOURNAL_v1|", out);
    state_digest::put_bytes(out, checksum.data(), checksum.size());
    return out;
}

inline std::optional<fq::DaemonJournal> decode_finality_journal(const std::vector<uint8_t>& in) {
    constexpr size_t BASE = 4 + 4 + 1 + 8 + 4 + 8 + 32 + 1;
    if (in.size() != BASE + 32 && in.size() != BASE + fq::SIGNED_VOTE_WIRE_BYTES + 32)
        return std::nullopt;
    if (!std::equal(in.begin(), in.begin() + 4, std::array<uint8_t, 4>{'V', 'F', 'J', '1'}.begin()))
        return std::nullopt;
    const size_t checksum_at = in.size() - 32;
    std::vector<uint8_t> body(in.begin(), in.begin() + (ptrdiff_t)checksum_at);
    const Hash256 checksum = state_digest::sha256_domain("VELD_FINALITY_DAEMON_JOURNAL_v1|", body);
    if (!std::equal(checksum.begin(), checksum.end(), in.begin() + (ptrdiff_t)checksum_at))
        return std::nullopt;
    size_t p = 4;
    auto u8 = [&]() -> uint8_t { return in[p++]; };
    auto u32 = [&]() {
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i)
            v |= (uint32_t)in[p++] << (8 * i);
        return v;
    };
    auto u64 = [&]() {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
            v |= (uint64_t)in[p++] << (8 * i);
        return v;
    };
    fq::DaemonJournal journal;
    journal.version = u32();
    const uint8_t held = u8();
    if (held > 1)
        return std::nullopt;
    journal.lock.held = held != 0;
    journal.lock.epoch_id = u64();
    journal.lock.round = u32();
    journal.lock.target.height = u64();
    std::copy_n(in.begin() + (ptrdiff_t)p, 32, journal.lock.target.hash.begin());
    p += 32;
    const uint8_t has_vote = u8();
    if (has_vote > 1)
        return std::nullopt;
    if (has_vote) {
        if (p + fq::SIGNED_VOTE_WIRE_BYTES != checksum_at)
            return std::nullopt;
        std::vector<uint8_t> vote(in.begin() + (ptrdiff_t)p,
                                  in.begin() + (ptrdiff_t)(p + fq::SIGNED_VOTE_WIRE_BYTES));
        auto decoded = fq::DecodeSignedVoteWire(vote);
        if (!decoded)
            return std::nullopt;
        journal.last_vote = std::move(*decoded);
        p += fq::SIGNED_VOTE_WIRE_BYTES;
    }
    if (p != checksum_at)
        return std::nullopt;
    return journal;
}

// Caller holds the shared validator-identity lifetime lease. A separate marker
// distinguishes an unused signer from a lost journal; a missing file after
// initialization must never silently become an unlocked signer.
class DurableFinalityJournal {
  public:
    explicit DurableFinalityJournal(std::string directory)
        : directory_(std::move(directory)), path_(directory_ + "/journal.bin"),
          marker_(directory_ + "/finality-initialized") {}

    std::optional<DaemonJournal> Load(const std::string& legacy_directory) {
        namespace sf = veld::channel::secure_file;
        if (attempted_)
            return Invalid_("finality journal already loaded");
        attempted_ = true;
        std::vector<uint8_t> marker, bytes;
        const auto mr = sf::Read(marker_, marker, &error_, 32, true);
        if (mr == sf::ReadResult::Error || (mr == sf::ReadResult::Ok && marker != Marker_()))
            return Invalid_("finality initialization marker is invalid");
        const auto result = sf::Read(path_, bytes, &error_, 64u * 1024u, true);
        if (result == sf::ReadResult::Error)
            return Invalid_("cannot read finality journal");
        if (result == sf::ReadResult::NotFound) {
            if (mr == sf::ReadResult::Ok)
                return Invalid_("finality safety history is missing; restore current safety state");
            if (!sf::EnsurePrivateDirectory(legacy_directory, &error_))
                return Invalid_("cannot inspect legacy finality directory");
            const auto lr =
                sf::Read(legacy_directory + "/journal.bin", bytes, &error_, 64u * 1024u, true);
            if (lr == sf::ReadResult::Error)
                return Invalid_("cannot read legacy finality history");
            if (lr == sf::ReadResult::NotFound)
                bytes = encode_finality_journal(DaemonJournal{});
            if (!decode_finality_journal(bytes) || !sf::AtomicWriteNew(path_, bytes, &error_, true))
                return Invalid_("cannot durably initialize finality history");
        }
        auto decoded = decode_finality_journal(bytes);
        if (!decoded)
            return Invalid_("finality history is malformed");
        if (mr == sf::ReadResult::NotFound &&
            !sf::AtomicWriteNew(marker_, Marker_(), &error_, true))
            return Invalid_("cannot durably mark finality initialization");
        expected_ = std::move(bytes);
        ready_ = true;
        return decoded;
    }

    bool Persist(const DaemonJournal& journal) {
        namespace sf = veld::channel::secure_file;
        if (!ready_)
            return false;
        std::vector<uint8_t> current;
        if (sf::Read(path_, current, &error_, 64u * 1024u, true) != sf::ReadResult::Ok ||
            current != expected_) {
            Invalid_("finality journal changed during signing; voting stopped");
            return false;
        }
        auto bytes = encode_finality_journal(journal);
        if (bytes.empty() || !sf::AtomicWrite(path_, bytes, &error_, true)) {
            Invalid_("finality write failed; voting stopped");
            return false;
        }
        expected_ = std::move(bytes);
        return true;
    }
    const std::string& error() const {
        return error_;
    }

  private:
    static std::vector<uint8_t> Marker_() {
        return {'V', 'F', 'J', '-', 'S', 'A', 'F', 'E', 'T', 'Y', '-', '1', '\n'};
    }
    DaemonJournal Invalid_(const std::string& why) {
        ready_ = false;
        error_ = why;
        DaemonJournal invalid;
        invalid.version = 0;
        return invalid;
    }
    std::string directory_, path_, marker_, error_;
    std::vector<uint8_t> expected_;
    bool attempted_{false}, ready_{false};
};

} // namespace veld::finality::qc
