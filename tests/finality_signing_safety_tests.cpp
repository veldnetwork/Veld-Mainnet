// Focused production-path signing tests. Synthetic chain/snapshot callbacks;
// genuine ML-DSA keys, votes, quorum verification and durable journal files.
#include "consensus/finality_signing_journal.h"
#include "compat/endorse_guard.h"
#include <atomic>
#include <iostream>
#include <thread>

using namespace veld;
namespace fq = veld::finality::qc;
namespace sf = veld::channel::secure_file;
unsigned checks = 0;
void Check(bool condition, const char* why) {
    ++checks;
    if (!condition)
        throw std::runtime_error(why);
}

struct Fixture {
    std::vector<dilithium::KeyPair> keys;
    std::filesystem::path root;
    Hash256 genesis = Hash256d("disposable signing fixture genesis");
    Hash256 hash = Hash256d("checkpoint A");
    uint64_t tip = 21;
    std::optional<fq::DecodedQc> qc;
    std::vector<fq::SignedVote> delivered;
    bool delivery_ok = true;
    int persistence_failure = 0;
    unsigned persists = 0;
    std::unique_ptr<fq::DurableFinalityJournal> journal;
    Fixture(const std::filesystem::path& path) : root(path) {
        std::string error;
        Check(sf::EnsurePrivateDirectory(path.string(), &error), "private fixture directory");
        for (int i = 0; i < 7; ++i)
            keys.push_back(dilithium::Generate());
    }
    std::string Public(size_t i = 0) const {
        return BytesToHex(keys[i].public_key.data(), keys[i].public_key.size());
    }
    fq::EpochSnapshot Snapshot(uint64_t epoch) const {
        fq::EpochSnapshot s;
        s.epoch_id = epoch;
        s.snapshot_height = epoch ? epoch * fq::EPOCH_BLOCKS - 1 : 0;
        for (size_t i = 0; i < keys.size(); ++i) {
            fq::SnapshotEntry m;
            m.pubkey_hex = Public(i);
            m.pubkey_commit = fq::PubkeyCommit(m.pubkey_hex);
            m.address = "disposable-validator-" + std::to_string(i);
            m.registered_height = 1;
            m.weight = fq::BOND_PER_KEY_UNITS;
            s.entries.push_back(m);
        }
        std::sort(s.entries.begin(), s.entries.end(),
                  [](const auto& a, const auto& b) { return a.pubkey_commit < b.pubkey_commit; });
        s.total_weight = 7 * fq::BOND_PER_KEY_UNITS;
        s.root = fq::SnapshotRoot(s.entries, s.epoch_id, s.snapshot_height, s.total_weight);
        return s;
    }
    fq::DaemonHooks Hooks() {
        journal = std::make_unique<fq::DurableFinalityJournal>(root.string());
        fq::DaemonHooks h;
        h.fetch_tip_height = [&] { return tip; };
        h.fetch_snapshot = [&](uint64_t e) {
            return std::optional<fq::EpochSnapshot>(Snapshot(e));
        };
        h.fetch_block_hash = [&](uint64_t) { return std::optional<Hash256>(hash); };
        h.fetch_finalized = []() -> std::optional<fq::FinalizedRecord> { return std::nullopt; };
        h.fetch_prevote_qc = [&](const auto&) { return qc; };
        h.authorize_target = [](const auto&) { return true; };
        h.authorize_work = [](const auto&) -> std::optional<fq::DaemonWorkGrant> {
            return fq::DaemonWorkGrant{"test-binding", "test-token",
                                       std::chrono::steady_clock::now() + std::chrono::seconds(10)};
        };
        h.cancel_work = [](const auto&) {};
        h.load_journal = [&] { return journal->Load((root / "legacy").string()); };
        h.persist_journal = [&](const auto& j) {
            ++persists;
            if (persistence_failure == 1)
                return false;
            if (persistence_failure == 2)
                throw std::runtime_error("injected storage exception");
            return journal->Persist(j);
        };
        h.gossip_vote = [&](const auto& vote, const auto&) {
            Check(fq::VerifyVote(vote, Snapshot(vote.epoch_id), fq::NETWORK_ID, genesis),
                  "genuine vote verifies");
            std::vector<uint8_t> bytes;
            Check(sf::Read((root / "journal.bin").string(), bytes) == sf::ReadResult::Ok,
                  "journal precedes external signature");
            auto saved = fq::decode_finality_journal(bytes);
            Check(saved && saved->last_vote &&
                      fq::EncodeSignedVoteWire(*saved->last_vote) == fq::EncodeSignedVoteWire(vote),
                  "exact signed vote durable before gossip");
            delivered.push_back(vote);
            return delivery_ok;
        };
        return h;
    }
    std::unique_ptr<fq::FinalityDaemon> Start() {
        return std::make_unique<fq::FinalityDaemon>(Public(), keys[0].secret_key, fq::NETWORK_ID,
                                                    genesis, Hooks());
    }
    void Quorum() {
        const uint64_t target = ((tip - 1) / fq::CHECKPOINT_INTERVAL) * fq::CHECKPOINT_INTERVAL;
        const auto s = Snapshot(fq::EpochOf(target));
        fq::CertAssembler assembler;
        for (size_t i = 0; i < 5; ++i) {
            fq::FinalityVoter v(Public(i), keys[i].secret_key);
            auto vote = v.Prevote(s, fq::CheckpointRound(target), {}, {target, hash}, std::nullopt,
                                  false, fq::NETWORK_ID, genesis);
            Check(vote && assembler.Offer(*vote, s, fq::NETWORK_ID, genesis),
                  "valid quorum contribution");
        }
        qc = assembler.TryAssemble(s, fq::NETWORK_ID, genesis, fq::Phase::PREVOTE);
        Check(qc && fq::VerifyDecodedQc(*qc, s, fq::NETWORK_ID, genesis),
              "real five-of-seven quorum");
    }
};

int main(int argc, char** argv) {
    if (argc != 2)
        return 2;
    try {
        const std::filesystem::path root = argv[1];
        {
            Fixture f(root / "endorsement");
            const auto path = (f.root / "endorsements").string();
            const std::string key = "20:" + f.Public();
            {
                EndorseAntiEquivGuard g;
                Check(g.load(path) && g.record(key, HashToHex(f.hash)),
                      "endorsement durable before signature");
                const auto msg = ValidatorRegistry::BuildEndorseMessage(20, f.hash);
                const auto signature = dilithium::Sign(
                    f.keys[0].secret_key, std::vector<uint8_t>(msg.begin(), msg.end()));
                Check(ValidatorRegistry::VerifyEndorseSignature(f.Public(), 20, f.hash,
                                                                BytesToHex(signature)),
                      "real endorsement accepted by unchanged validator verifier");
                Check(!ValidatorRegistry::VerifyEndorseSignature(f.Public(), 21, f.hash,
                                                                 BytesToHex(signature)),
                      "signature bound to endorsement height");
            }
            EndorseAntiEquivGuard restarted;
            Check(restarted.load(path), "endorsement history reloads");
            Check(!restarted.record(key, HashToHex(Hash256d("sibling"))),
                  "no second endorsement signature authorized");
            Check(restarted.record(key, HashToHex(f.hash)), "same endorsement retry allowed");
        }
        {
            Fixture f(root / "retry");
            f.delivery_ok = false;
            auto d = f.Start();
            Check(!d->Tick(), "lost delivery response");
            const auto original = fq::EncodeSignedVoteWire(f.delivered.back());
            f.delivery_ok = true;
            Check(d->Tick(), "same-process retry");
            Check(fq::EncodeSignedVoteWire(f.delivered.back()) == original,
                  "same signed bytes on retry");
            d.reset();
            d = f.Start();
            Check(d->Tick(), "restart retries exact vote");
            Check(fq::EncodeSignedVoteWire(f.delivered.back()) == original,
                  "same bytes after restart");
            d.reset();
            f.hash = Hash256d("reorg B");
            d = f.Start();
            Check(!d->Tick(), "restart refuses conflicting prevote");
        }
        {
            Fixture f(root / "precommit");
            auto d = f.Start();
            Check(d->Tick(), "initial prevote");
            Check(!d->Tick(), "no precommit without QC");
            f.Quorum();
            Check(d->Tick(), "qualified precommit");
            Check(f.delivered.back().phase == fq::Phase::PRECOMMIT, "correct phase");
            const auto original = fq::EncodeSignedVoteWire(f.delivered.back());
            d.reset();
            d = f.Start();
            Check(d->Tick(), "restart precommit retry");
            Check(fq::EncodeSignedVoteWire(f.delivered.back()) == original,
                  "exact precommit bytes");
            f.hash = Hash256d("reorg sibling");
            Check(!d->Tick(), "no conflicting precommit");
        }
        {
            Fixture f(root / "epochs");
            auto d = f.Start();
            Check(d->Tick(), "older epoch vote");
            f.tip = fq::EPOCH_BLOCKS + 1;
            Check(d->Tick(), "next epoch vote");
            d.reset();
            d = f.Start();
            f.tip = fq::EPOCH_BLOCKS - 1;
            Check(!d->Tick(), "epoch rollback does not erase high water mark");
        }
        for (int fault : {1, 2}) {
            Fixture f(root / ("failure" + std::to_string(fault)));
            f.persistence_failure = fault;
            auto d = f.Start();
            Check(!d->Tick(), "persistence error stops vote release");
            Check(f.delivered.empty(), "no signature released after failure");
            f.persistence_failure = 0;
            f.hash = Hash256d("later sibling");
            Check(!d->Tick() && f.persists == 1, "failure remains latched until restart");
        }
        {
            Fixture f(root / "threads");
            auto d = f.Start();
            std::vector<std::thread> threads;
            for (int i = 0; i < 12; ++i)
                threads.emplace_back([&] { d->Tick(); });
            for (auto& t : threads)
                t.join();
            Check(f.persists == 1 && f.delivered.size() == 1,
                  "one signing transition under concurrent ticks");
        }
        {
            Fixture f(root / "missing");
            auto d = f.Start();
            Check(d->Tick(), "vote before journal loss");
            d.reset();
            std::filesystem::remove(f.root / "journal.bin");
            d = f.Start();
            Check(!d->Tick(), "missing initialized journal refuses signing");
        }
        {
            Fixture f(root / "corrupt");
            auto d = f.Start();
            Check(d->Tick(), "vote before corruption");
            d.reset();
            std::vector<uint8_t> bytes;
            Check(sf::Read((f.root / "journal.bin").string(), bytes) == sf::ReadResult::Ok,
                  "read corruption fixture");
            bytes[10] ^= 1;
            Check(sf::AtomicWrite((f.root / "journal.bin").string(), bytes),
                  "inject corrupt checksum");
            d = f.Start();
            Check(!d->Tick(), "corrupt finality journal refuses signing");
        }
        {
            Fixture f(root / "rewind");
            auto d = f.Start();
            Check(d->Tick(), "vote before journal replacement");
            const auto empty = fq::encode_finality_journal(fq::DaemonJournal{});
            Check(sf::AtomicWrite((f.root / "journal.bin").string(), empty),
                  "replace fixture journal");
            f.tip = 41;
            Check(!d->Tick(), "live journal rewind refuses vote");
        }
        {
            Fixture f(root / "migration");
            auto d = f.Start();
            Check(d->Tick(), "migration source vote");
            d.reset();
            std::vector<uint8_t> bytes;
            Check(sf::Read((f.root / "journal.bin").string(), bytes) == sf::ReadResult::Ok,
                  "read legacy source");
            const auto destination = root / "migrated";
            Check(sf::EnsurePrivateDirectory(destination.string()), "migration destination");
            fq::DurableFinalityJournal migrated(destination.string());
            auto saved = migrated.Load(f.root.string());
            Check(saved && saved->last_vote, "legacy history retained");
            Check(fq::encode_finality_journal(*saved) == bytes, "byte-exact journal migration");
            std::filesystem::remove(destination / "journal.bin");
            fq::DurableFinalityJournal missing(destination.string());
            auto invalid = missing.Load(f.root.string());
            Check(invalid && invalid->version == 0,
                  "never reimport stale legacy after journal loss");
        }
        std::cout << "PASS finality signing safety checks=" << checks << '\n';
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        return 1;
    }
}
