#pragma once

#include "../consensus/btcveld_anchor_floor_store.h"
#include "../core/leveldb.h"
#include "../wallet/secure_channel_file.h"

#include <algorithm>
#include <array>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace veld::snapshot_recovery {

namespace fs = std::filesystem;
using Floors = std::vector<btcanchor::floor_store::Record>;
inline constexpr const char* REQUEST = ".snapshot-recovery-requested";
inline constexpr const char* REVOKED = ".snapshot-fast-start-revoked";
inline constexpr const char* JOURNAL = ".snapshot-recovery.v1";
inline constexpr const char* IMPORT = ".snapshot-import.v1";
inline constexpr const char* FLOORS = "snapshot-recovery-floors.v1";
inline constexpr std::array<const char*, 10> NAMES{{
    "db", "blocks", "index", ".snapshot-handoff",
    ".background-chainstate-required", "background-ibd", "background-chainstate",
    "full-ibd.receipt", "fleet-full-ibd.receipt", "finality-equivocation.evj"}};

inline void Require(bool value, const std::string& message) {
    if (!value) throw std::runtime_error("snapshot recovery: " + message);
}

// Missing and unreadable are different states. Never follow a link while
// deciding whether recovery may retire or replace a namespace.
inline bool Exists(const fs::path& path) {
    std::error_code ec;
    const auto status = fs::symlink_status(path, ec);
    if (ec == std::errc::no_such_file_or_directory ||
        status.type() == fs::file_type::not_found) return false;
    Require(!ec && !fs::is_symlink(status), "unsafe or unreadable path: " + path.string());
#ifdef _WIN32
    const DWORD attrs = ::GetFileAttributesW(path.c_str());
    Require(attrs != INVALID_FILE_ATTRIBUTES &&
            !(attrs & FILE_ATTRIBUTE_REPARSE_POINT), "reparse or unreadable path");
#endif
    Require(fs::is_directory(status) || fs::is_regular_file(status), "special filesystem object");
    return true;
}

inline std::optional<std::vector<uint8_t>> Read(const fs::path& path, size_t bound) {
    if (!Exists(path)) return std::nullopt;
    std::vector<uint8_t> wire;
    std::string error;
    const auto result = channel::secure_file::Read(path.string(), wire, &error, bound, true);
    Require(result == channel::secure_file::ReadResult::Ok, "control read failed: " + error);
    return wire;
}

inline void Sync(const fs::path& directory) {
#ifndef _WIN32
    const int fd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    Require(fd >= 0, "cannot open directory for durable publication");
    const bool ok = ::fsync(fd) == 0;
    const int closed = ::close(fd);
    Require(ok && closed == 0, "directory synchronization failed");
#else
    // Namespace moves use MoveFileExW(MOVEFILE_WRITE_THROUGH). Protected
    // control publication uses the handle-validated secure-file primitive.
    Require(Exists(directory) && fs::is_directory(directory), "invalid directory");
#endif
}

inline void Write(const fs::path& path, const std::vector<uint8_t>& wire) {
    std::string error;
    Require(channel::secure_file::AtomicWrite(path.string(), wire, &error, true), error);
}
inline void Write(const fs::path& path, const std::string& body) {
    Write(path, std::vector<uint8_t>(body.begin(), body.end()));
}
inline void Remove(const fs::path& path) {
    if (!Exists(path)) return;
    Require(fs::is_regular_file(path), "refusing to remove non-file control state");
    Require(fs::remove(path), "control removal failed");
    Sync(path.parent_path());
}
inline void Move(const fs::path& from, const fs::path& to) {
    Require(Exists(from) && !Exists(to), "ambiguous namespace move");
#ifdef _WIN32
    Require(::MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_WRITE_THROUGH) != 0,
            "write-through namespace move failed");
#else
    fs::rename(from, to);
#endif
    Sync(from.parent_path());
    if (from.parent_path() != to.parent_path()) Sync(to.parent_path());
}

inline void CheckTree(const fs::path& path) {
    if (!Exists(path) || !fs::is_directory(path)) return;
    for (const auto& item : fs::recursive_directory_iterator(path)) (void)Exists(item.path());
}

inline bool LowerHex(const std::string& text, size_t size) {
    return text.size() == size && std::all_of(text.begin(), text.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
inline bool ReasonValid(const std::string& reason) {
    return !reason.empty() && reason.size() <= 64 &&
        std::all_of(reason.begin(), reason.end(), [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
        });
}
inline bool HasReason(const fs::path& path) {
    const auto wire = Read(path, 128);
    if (!wire) return false;
    const std::string body(wire->begin(), wire->end());
    const std::string prefix = "schema=1\nreason=";
    Require(body.starts_with(prefix) && body.ends_with('\n'), "malformed rejection marker");
    const auto reason = body.substr(prefix.size(), body.size() - prefix.size() - 1);
    Require(ReasonValid(reason), "noncanonical rejection reason");
    return true;
}

inline bool Pending(const fs::path& root) {
    // Read both even when the first exists; corruption must not be hidden.
    const bool request = HasReason(root / REQUEST);
    const bool revoked = HasReason(root / REVOKED);
    const bool journal = Exists(root / JOURNAL);
    return request || revoked || journal;
}

inline void Request(const fs::path& root, const std::string& reason) {
    const auto canonical = ReasonValid(reason) ? reason : "background-chainstate-failed";
    // The original independent-validation obligations remain intact until a
    // durable recovery transaction has moved them with the rejected database.
    Write(root / REQUEST, "schema=1\nreason=" + canonical + "\n");
    Write(root / REVOKED, "schema=1\nreason=" + canonical + "\n");
}

// Restart is appropriate only when rejection intent is durably readable.
// Corrupt or missing intent requires inspection instead of a restart loop.
inline int RejectionExitCode(const fs::path& root) noexcept {
    try { return HasReason(root / REQUEST) ? 75 : 76; }
    catch (...) { return 76; }
}

inline Floors Normalize(Floors records, uint32_t magic, const Hash256& genesis) {
    std::string error;
    Require(records.size() <= 64, "too many retained floor obligations");
    for (const auto& record : records)
        Require(btcanchor::floor_store::Validate(record, &error) &&
                record.network_magic == magic && record.genesis_hash == genesis,
                "invalid floor identity: " + error);
    std::sort(records.begin(), records.end(), [](const auto& a, const auto& b) {
        if (a.checkpoint.target_height != b.checkpoint.target_height)
            return a.checkpoint.target_height < b.checkpoint.target_height;
        return a.floor_digest < b.floor_digest;
    });
    records.erase(std::unique(records.begin(), records.end(),
        btcanchor::floor_store::ExactDuplicate), records.end());
    btcanchor::floor_store::Store store;
    for (const auto& record : records) {
        const auto result = store.Merge(record, &error);
        Require(result != btcanchor::floor_store::MergeResult::Rejected &&
                result != btcanchor::floor_store::MergeResult::IoError,
                "conflicting local floors: " + error);
    }
    return records;
}

inline Floors ReadFloors(const fs::path& root, uint32_t magic, const Hash256& genesis) {
    const auto path = root / "security" / FLOORS;
    if (!Exists(root / "security")) return {};
    auto wire = Read(path, 4 + 64 * btcanchor::floor_store::VLF1_ENCODED_SIZE);
    if (!wire) return {};
    Require(wire->size() >= 4 && std::string(wire->begin(), wire->begin() + 4) == "VSF1" &&
            (wire->size() - 4) % btcanchor::floor_store::VLF1_ENCODED_SIZE == 0,
            "malformed retained floor set");
    Floors records;
    for (size_t at = 4; at < wire->size(); at += btcanchor::floor_store::VLF1_ENCODED_SIZE) {
        std::string error;
        const auto record = btcanchor::floor_store::Decode(std::vector<uint8_t>(
            wire->begin() + at, wire->begin() + at + btcanchor::floor_store::VLF1_ENCODED_SIZE), &error);
        Require(record.has_value(), "malformed retained floor: " + error);
        records.push_back(*record);
    }
    const auto canonical = Normalize(records, magic, genesis);
    Require(canonical.size() == records.size(), "duplicate retained floor");
    return canonical;
}

inline void PreserveFloors(const fs::path& root, const Floors& records) {
    std::string error;
    Require(channel::secure_file::EnsurePrivateDirectory((root / "security").string(), &error), error);
    std::vector<uint8_t> wire{'V','S','F','1'};
    for (const auto& record : records) {
        const auto encoded = btcanchor::floor_store::Encode(record, &error);
        Require(encoded.has_value(), error);
        wire.insert(wire.end(), encoded->begin(), encoded->end());
    }
    Write(root / "security" / FLOORS, wire);
    Sync(root);
}

// Run before VeldDB construction: that constructor can consume pending:commit.
// A rejected snapshot cannot erase an unresolved local repair obligation.
inline Floors CaptureLocalState(const fs::path& root, uint32_t magic, const Hash256& genesis) {
    auto records = ReadFloors(root, magic, genesis);
    std::string error;
    if (Exists(root / "security")) {
        if (const auto uncertainty = Read(root / "security/anchor-floor.uncertain", 64)) {
            Require(std::string(uncertainty->begin(), uncertainty->end()) == "VLF1-CLEAR\n",
                    "local floor persistence must be repaired before replacing chain data");
        }
        if (const auto wire = Read(root / "security/anchor-floor.vlf1", btcanchor::floor_store::VLF1_ENCODED_SIZE)) {
            const auto record = btcanchor::floor_store::Decode(*wire, &error);
            Require(record.has_value(), "external floor decode failed: " + error);
            records.push_back(*record);
        }
    }
    const auto index = root / "db/index";
    if (Exists(root / "db")) {
        if (Exists(index)) {
            CheckTree(index);
#ifdef VELD_USE_LEVELDB
            Require(db::ValidateLevelDBCurrentManifest(index, &error) &&
                    db::ValidateLevelDBLogsInDirectory(index, &error),
                    "canonical index requires offline inspection: " + error);
            db::LevelDBStore store(index.string(), false);
#else
            db::FlatFileStore store(index.string());
#endif
            for (const char* key : {db::VeldDB::DURABLE_PUBLICATION_PENDING_KEY,
                    db::VeldDB::REORG_UTXO_PENDING_KEY, "reorg:utxo:rebuilding", "pending:commit"})
                Require(!store.Get(key), "unresolved durable chain repair prevents replacement");
            if (const auto wire = store.Get(db::VeldDB::ANCHOR_SECURITY_FLOOR_KEY)) {
                const auto record = btcanchor::floor_store::Decode(
                    std::vector<uint8_t>(wire->begin(), wire->end()), &error);
                Require(record.has_value(), "database floor decode failed: " + error);
                records.push_back(*record);
            }
        } else {
            Require(!Exists(root / "db/blocks") && !Exists(root / "db/utxo"),
                    "missing authoritative index prevents safe replacement");
        }
    }
    return Normalize(std::move(records), magic, genesis);
}

struct Transaction {
    std::string id;
    std::string phase;
    unsigned present = 0;
    std::string receipt;
    std::string receipt_hash;
};
inline std::string Body(const Transaction& t) {
    return "schema=1\nid=" + t.id + "\nphase=" + t.phase +
        "\npresent=" + std::to_string(t.present) + "\nreceipt=" + t.receipt +
        "\nreceipt_hash=" + t.receipt_hash + "\n";
}
inline std::optional<Transaction> Load(const fs::path& root) {
    const auto wire = Read(root / JOURNAL, 512);
    if (!wire) return std::nullopt;
    const std::string body(wire->begin(), wire->end());
    std::istringstream input(body);
    std::array<std::string,6> values;
    const std::array<const char*,6> names{{"schema=", "id=", "phase=", "present=", "receipt=", "receipt_hash="}};
    std::string line;
    for (size_t i=0; i<names.size(); ++i) {
        Require(bool(std::getline(input,line)) && line.starts_with(names[i]), "invalid recovery journal field");
        values[i]=line.substr(std::strlen(names[i]));
    }
    Require(!std::getline(input,line), "trailing recovery journal data");
    uint64_t mask=0;
    Require(values[0]=="1" && LowerHex(values[1],24) &&
            ParseCanonicalUint64Text(values[3],mask) && mask < (1U<<NAMES.size()), "invalid recovery journal identity");
    Transaction t{values[1],values[2],static_cast<unsigned>(mask),values[4],values[5]};
    Require(t.phase=="quarantine" || t.phase=="ibd" || t.phase=="complete", "unknown recovery phase");
    Require(t.phase=="complete" ?
        ((t.receipt=="full-ibd.receipt" || t.receipt=="fleet-full-ibd.receipt") && LowerHex(t.receipt_hash,64)) :
        (t.receipt.empty() && t.receipt_hash.empty()), "invalid completion evidence");
    Require(Body(t)==body, "noncanonical recovery journal");
    return t;
}

inline void Finish(const fs::path& root, const Transaction& t) {
    const auto receipt=Read(root/t.receipt,24*1024);
    Require(receipt && HashToHex(Hash256d(*receipt))==t.receipt_hash,
            "durable completion receipt is missing or changed");
    Remove(root/REQUEST);
    Remove(root/REVOKED);
    Remove(root/JOURNAL);
    // Retain the exact floor set and rejected namespace as evidence. Neither
    // participates in the ordinary age-based quarantine pruning scheme.
}

struct ImportTransaction {
    std::string stage;
    std::string quarantine;
    unsigned next = 0;
    unsigned present = 0;
};
inline std::string ImportBody(const ImportTransaction& t) {
    return "schema=1\nstage=" + t.stage + "\nquarantine=" + t.quarantine +
        "\nnext=" + std::to_string(t.next) + "\npresent=" + std::to_string(t.present) + "\n";
}
inline ImportTransaction LoadImport(const fs::path& root) {
    const auto wire=Read(root/IMPORT,512);
    Require(wire.has_value(), "missing import journal");
    const std::string body(wire->begin(),wire->end());
    std::istringstream in(body);
    const std::array<const char*,5> names{{"schema=","stage=","quarantine=","next=","present="}};
    std::array<std::string,5> values;
    std::string line;
    for (size_t i=0;i<names.size();++i) {
        Require(bool(std::getline(in,line)) && line.starts_with(names[i]), "malformed import journal");
        values[i]=line.substr(std::strlen(names[i]));
    }
    uint64_t next=0,present=0;
    Require(!std::getline(in,line) && values[0]=="1" &&
        values[1].starts_with(".snapshot-stage-") && LowerHex(values[1].substr(16),32) &&
        values[2].starts_with(".snapshot-preimport-") && LowerHex(values[2].substr(20),24) &&
        ParseCanonicalUint64Text(values[3],next) && next<=5 &&
        ParseCanonicalUint64Text(values[4],present) && present<4, "invalid import journal identity");
    ImportTransaction t{values[1],values[2],static_cast<unsigned>(next),static_cast<unsigned>(present)};
    Require(ImportBody(t)==body,"noncanonical import journal");
    return t;
}

inline void ResumeImport(const fs::path& root) {
    if (!Exists(root/IMPORT)) return;
    Require(!Pending(root), "recovery and import obligations coexist");
    auto t=LoadImport(root);
    const auto stage=root/t.stage/"extract", quarantine=root/t.quarantine;
    Require(Exists(stage) && Exists(quarantine), "import staging or quarantine disappeared");
    const std::array<std::pair<fs::path,fs::path>,5> moves{{
        {root/"db",quarantine/"db"},
        {root/".snapshot-handoff",quarantine/"handoff"},
        {stage/"db",root/"db"},
        {stage/".background-chainstate-required",root/".background-chainstate-required"},
        {stage/".snapshot-handoff",root/".snapshot-handoff"}}};
    while (t.next<moves.size()) {
        const auto& [from,to]=moves[t.next];
        const bool source=Exists(from),destination=Exists(to);
        if (t.next<2 && !(t.present & (1U<<t.next))) {
            Require(!source && !destination, "unexpected prior import namespace");
        } else {
            Require(source!=destination, "ambiguous interrupted import");
            if (source) Move(from,to);
            else { Sync(from.parent_path());Sync(to.parent_path()); }
        }
        ++t.next;
        Write(root/IMPORT,ImportBody(t));
    }
    Require(Exists(root/"db") && Exists(root/".background-chainstate-required") &&
            Exists(root/".snapshot-handoff"), "import publication is incomplete");
    Remove(root/IMPORT);
}

inline void PublishImport(const fs::path& root, const fs::path& scratch) {
    Require(!Pending(root) && !Exists(root/IMPORT), "another recovery or import is pending");
    const auto relative=fs::absolute(scratch).lexically_normal().lexically_relative(fs::absolute(root).lexically_normal());
    const std::string stage=relative.generic_string();
    Require(relative.parent_path().empty() && stage.starts_with(".snapshot-stage-") &&
            LowerHex(stage.substr(16),32), "import staging is not an owned direct child");
    const auto extracted=scratch/"extract";
    for (const auto* name : {"db",".background-chainstate-required",".snapshot-handoff"}) {
        Require(Exists(extracted/name),"missing staged publication member");
        CheckTree(extracted/name);
    }
    Require(!Exists(root/".background-chainstate-required"), "independent validation is already pending");
    std::array<uint8_t,12> random{};
    Require(compat::SecureRandom(random.data(),random.size()),"import identity generation failed");
    ImportTransaction t{stage,".snapshot-preimport-"+BytesToHex(random.data(),random.size()),0,0};
    if (Exists(root/"db")) { CheckTree(root/"db");t.present|=1; }
    if (Exists(root/".snapshot-handoff")) { CheckTree(root/".snapshot-handoff");t.present|=2; }
    const auto quarantine=root/t.quarantine;
    Require(fs::create_directory(quarantine),"import quarantine collision");
    std::string error;
    Require(channel::secure_file::EnsurePrivateDirectory(quarantine.string(),&error),error);
    Sync(root);
    Write(root/IMPORT,ImportBody(t));
    ResumeImport(root);
}

inline bool Prepare(const fs::path& root, uint32_t magic, const Hash256& genesis) {
    ResumeImport(root);
    if (!Pending(root)) return false;
    auto transaction=Load(root);
    if (transaction && transaction->phase=="complete") { Finish(root,*transaction); return false; }
    if (!transaction) {
        const auto records=CaptureLocalState(root,magic,genesis);
        PreserveFloors(root,records);
        std::array<uint8_t,12> random{};
        Require(compat::SecureRandom(random.data(),random.size()), "recovery identity generation failed");
        Transaction next{BytesToHex(random.data(),random.size()),"quarantine",0,{},{}};
        for (size_t i=0;i<NAMES.size();++i) {
            if (Exists(root/NAMES[i])) { CheckTree(root/NAMES[i]);next.present|=1U<<i; }
        }
        const auto quarantine=root/(".snapshot-rejected-"+next.id);
        Require(fs::create_directory(quarantine), "recovery directory collision");
        std::string error;
        Require(channel::secure_file::EnsurePrivateDirectory(quarantine.string(),&error),error);
        Sync(root);
        Write(root/JOURNAL,Body(next));
        transaction=next;
    }
    Require(Exists(root/"security"/FLOORS), "retained security obligations disappeared");
    (void)ReadFloors(root,magic,genesis);
    if (transaction->phase=="ibd") return true;
    const auto quarantine=root/(".snapshot-rejected-"+transaction->id);
    Require(Exists(quarantine) && fs::is_directory(quarantine), "quarantine directory disappeared");
    for (size_t i=0;i<NAMES.size();++i) {
        const auto from=root/NAMES[i],to=quarantine/NAMES[i];
        const bool source=Exists(from),destination=Exists(to);
        if (!(transaction->present & (1U<<i))) {
            Require(!source && !destination, "unexpected namespace during recovery");
        } else {
            Require(source!=destination, "missing or duplicated recovery namespace");
            if (source) Move(from,to);
            else { Sync(root);Sync(quarantine); }
        }
    }
    transaction->phase="ibd";
    Write(root/JOURNAL,Body(*transaction));
    return true;
}

// The node calls this only after fresh ordinary IBD and exact floor
// reconstruction, and only after its role-bound receipt is durably published.
inline void Complete(const fs::path& root, const std::string& receipt_name) {
    auto t=Load(root);
    Require(t && (t->phase=="ibd" || t->phase=="complete"), "completion requires fresh IBD phase");
    Require(receipt_name=="full-ibd.receipt" || receipt_name=="fleet-full-ibd.receipt", "unknown receipt role");
    if (t->phase=="complete") {
        Require(t->receipt==receipt_name, "completion receipt role changed");
        Finish(root,*t);
        return;
    }
    const auto receipt=Read(root/receipt_name,24*1024);
    Require(receipt.has_value(), "completion receipt is unavailable");
    t->phase="complete";t->receipt=receipt_name;t->receipt_hash=HashToHex(Hash256d(*receipt));
    Write(root/JOURNAL,Body(*t));
    Finish(root,*t);
}

} // namespace veld::snapshot_recovery
