#pragma once
#include "appchain/auth/action.h"
#include <set>

namespace app {
using ParentHash = std::array<uint8_t, 32>;
using PublicKey = std::array<uint8_t, 1952>;
using Signature = std::array<uint8_t, 3309>;
struct Committee {
    ParentHash parentGenesis{};
    Id childGenesis{}, bridge{};
    uint32_t version = 1;
    uint64_t developmentReserveCap = 1000000000000ULL;
    std::array<PublicKey, 10> keys{};
    Bytes encode() const {
        need(version == 1 && childGenesis != Id{} && bridge != Id{} &&
                 parentGenesis != ParentHash{} && developmentReserveCap == 1000000000000ULL,
             "committee profile");
        std::set<PublicKey> unique;
        Writer w;
        w.raw(Bytes{'V', 'A', 'C', 'D', 1});
        w.raw(parentGenesis);
        w.raw(childGenesis);
        w.raw(bridge);
        w.n(version, 4);
        w.n(10, 1);
        w.n(7, 1);
        w.n(developmentReserveCap, 8);
        for (auto& key : keys) {
            need(key != PublicKey{} && unique.insert(key).second, "duplicate/empty committee key");
            w.raw(key);
        }
        return w.b;
    }
    Id id() const {
        return hash("VAPP/committee/1", encode());
    }
};
struct Checkpoint {
    ParentHash parentGenesis{}, parentAnchorHash{};
    Id childGenesis{}, bridge{}, descriptor{}, previous{}, sourceHash{};
    uint32_t version = 1;
    uint64_t sequence = 0, sourceHeight = 0, parentAnchorHeight = 0;
    // Unsigned little-endian 512-bit accumulated work, exactly 64 bytes.
    std::array<uint8_t, 64> sourceWork{};
    Id accountsRoot{}, assetsRoot{}, fuelRoot{}, minerRoot{}, withdrawalsRoot{};
    uint64_t depositedTotal = 0, withdrawnTotal = 0;
    Bytes encode() const {
        need(version == 1 && sequence > 0 && sequence <= MAX && sourceHeight > 0 &&
                 sourceHeight <= MAX && sourceHeight % 120 == 0 && parentAnchorHeight > 0 &&
                 parentAnchorHeight <= MAX && depositedTotal <= MAX &&
                 withdrawnTotal <= depositedTotal,
             "checkpoint bounds");
        need(parentGenesis != ParentHash{} && parentAnchorHash != ParentHash{} &&
                 childGenesis != Id{} && bridge != Id{} && descriptor != Id{} &&
                 sourceHash != Id{} && accountsRoot != Id{} && assetsRoot != Id{} &&
                 fuelRoot != Id{} && minerRoot != Id{} && withdrawalsRoot != Id{} &&
                 sourceWork != std::array<uint8_t, 64>{},
             "checkpoint commitment");
        Writer w;
        w.raw(Bytes{'V', 'A', 'C', 'P', 1});
        w.raw(parentGenesis);
        w.raw(childGenesis);
        w.raw(bridge);
        w.n(version, 4);
        w.raw(descriptor);
        w.raw(previous);
        w.n(sequence, 8);
        w.n(sourceHeight, 8);
        w.raw(sourceHash);
        w.raw(sourceWork);
        w.raw(accountsRoot);
        w.raw(assetsRoot);
        w.raw(fuelRoot);
        w.raw(minerRoot);
        w.raw(withdrawalsRoot);
        w.n(parentAnchorHeight, 8);
        w.raw(parentAnchorHash);
        w.n(depositedTotal, 8);
        w.n(withdrawnTotal, 8);
        return w.b;
    }
    Id id() const {
        return hash("VAPP/checkpoint/1", encode());
    }
    static Checkpoint decode(std::span<const uint8_t> bytes) {
        Reader r{bytes};
        need(r.raw(5) == Bytes({'V', 'A', 'C', 'P', 1}), "checkpoint version");
        Checkpoint c;
        auto parent = r.raw(32);
        std::copy(parent.begin(), parent.end(), c.parentGenesis.begin());
        c.childGenesis = r.id();
        c.bridge = r.id();
        c.version = r.n(4);
        c.descriptor = r.id();
        c.previous = r.id();
        c.sequence = r.n(8);
        c.sourceHeight = r.n(8);
        c.sourceHash = r.id();
        auto work = r.raw(64);
        std::copy(work.begin(), work.end(), c.sourceWork.begin());
        c.accountsRoot = r.id();
        c.assetsRoot = r.id();
        c.fuelRoot = r.id();
        c.minerRoot = r.id();
        c.withdrawalsRoot = r.id();
        c.parentAnchorHeight = r.n(8);
        parent = r.raw(32);
        std::copy(parent.begin(), parent.end(), c.parentAnchorHash.begin());
        c.depositedTotal = r.n(8);
        c.withdrawnTotal = r.n(8);
        r.end();
        need(c.encode() == Bytes(bytes.begin(), bytes.end()), "canonical checkpoint");
        return c;
    }
};
struct IndexedSignature {
    uint8_t index = 0;
    Signature bytes{};
};
struct Certificate {
    Checkpoint checkpoint;
    std::vector<IndexedSignature> signatures;
    Bytes encode() const {
        need(signatures.size() >= 7 && signatures.size() <= 10, "checkpoint quorum count");
        Writer w;
        w.raw(Bytes{'V', 'A', 'C', 'S', 1});
        w.str(checkpoint.encode(), 1024);
        w.n(signatures.size(), 1);
        int last = -1;
        for (auto& sig : signatures) {
            need(sig.index < 10 && sig.index > last, "checkpoint signer ordering");
            last = sig.index;
            w.n(sig.index, 1);
            w.raw(sig.bytes);
        }
        need(w.b.size() <= 35000, "certificate bound");
        return w.b;
    }
    static Certificate decode(std::span<const uint8_t> bytes) {
        need(bytes.size() <= 35000, "certificate bound");
        Reader r{bytes};
        need(r.raw(5) == Bytes({'V', 'A', 'C', 'S', 1}), "certificate version");
        Certificate c;
        c.checkpoint = Checkpoint::decode(r.str(1024));
        auto count = r.n(1);
        need(count >= 7 && count <= 10, "checkpoint quorum count");
        for (unsigned i = 0; i < count; i++) {
            IndexedSignature sig;
            sig.index = r.n(1);
            auto value = r.raw(3309);
            std::copy(value.begin(), value.end(), sig.bytes.begin());
            c.signatures.push_back(sig);
        }
        r.end();
        need(c.encode() == Bytes(bytes.begin(), bytes.end()), "canonical certificate");
        return c;
    }
    void verify(const Committee& committee, const Id& predecessor, uint64_t sequence) const {
        encode();
        auto& c = checkpoint;
        need(c.parentGenesis == committee.parentGenesis &&
                 c.childGenesis == committee.childGenesis && c.bridge == committee.bridge &&
                 c.version == committee.version && c.descriptor == committee.id() &&
                 c.previous == predecessor && c.sequence == sequence,
             "checkpoint authority or predecessor");
        need(c.depositedTotal - c.withdrawnTotal <= committee.developmentReserveCap,
             "checkpoint reserve cap");
        auto digest = c.id();
        for (auto& sig : signatures)
            need(PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig.bytes.data(), sig.bytes.size(),
                                                          digest.data(), digest.size(),
                                                          committee.keys[sig.index].data()) == 0,
                 "checkpoint signature");
    }
};
// Certificate verification is not parent UTXO validation, checkpoint delay,
// an attestor's independent replay, or authority to release any backing.
} // namespace app
