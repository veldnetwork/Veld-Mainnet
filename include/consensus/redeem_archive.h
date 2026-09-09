#pragma once
// Persistent authenticated radix map. Only root/count are rollback state.
// Content-addressed immutable records may be shared by candidate branches;
// unreachable records never confer authority. Lookups use <= 256 branch nodes
// and one leaf, independent of lifetime request volume. Storage errors are
// fatal to the transition, never interpreted as authenticated nonmembership.
#include "btcveld_mint_nullifier.h"
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace veld::btcveld {

class RedeemArchive {
public:
    using Read = std::function<std::optional<std::string>(const std::string&)>;
    using Records = std::vector<std::pair<std::string, std::string>>;
    using Write = std::function<bool(const Records&)>;
    static Hash256 HashRecord(const std::string& record) {
        return state_digest::sha256_domain("VELD_REDEEM_ARCHIVE_NODE_v1|",
            std::vector<uint8_t>(record.begin(), record.end()));
    }
    static Hash256 EmptyRoot() { return HashRecord(std::string(1, char(2))); }
    struct Root {
        Hash256 hash = EmptyRoot();
        uint64_t count = 0;
        bool operator==(const Root&) const = default;
    };
    static Hash256 Key(uint8_t kind, const std::string& identity) {
        std::vector<uint8_t> body{kind};
        state_digest::put_len_prefixed(body, identity);
        return state_digest::sha256_domain("VELD_REDEEM_ARCHIVE_KEY_v1|", body);
    }
    static Hash256 Key(uint8_t kind, const Hash256& identity) {
        return Key(kind, std::string(identity.begin(), identity.end()));
    }
    void SetBackend(Read read, Write write) {
        read_ = std::move(read);
        write_ = std::move(write);
    }
    bool Available() const { return bool(read_) && bool(write_); }

    std::optional<std::string> Get(const Root& root, const Hash256& key) const {
        CheckRoot(root);
        if (root.count == 0) return std::nullopt;
        Hash256 hash = root.hash;
        int previous = -1;
        for (size_t steps = 0; steps <= 256; ++steps) {
            const Node node = Load(hash);
            if (node.leaf)
                return node.key == key ? std::optional<std::string>(node.value)
                                       : std::nullopt;
            if (int(node.depth) <= previous)
                throw std::runtime_error("redeem archive branch order");
            previous = node.depth;
            hash = btcnull::Bit(key, node.depth) ? node.right : node.left;
        }
        throw std::runtime_error("redeem archive depth");
    }

    // An immutable identifier can only be inserted once. Exact existing value
    // is idempotent; conflicting data is rejected without publishing a root.
    bool Insert(Root& root, const Hash256& key, const std::string& value) {
        CheckRoot(root);
        if (!Available())
            throw std::runtime_error("redeem archive backend unavailable");
        std::vector<Node> path;
        std::vector<Hash256> hashes;
        Hash256 cursor = root.hash;
        Node terminal;
        if (root.count != 0) {
            int previous = -1;
            for (size_t steps = 0; ; ++steps) {
                if (steps > 256) throw std::runtime_error("redeem archive depth");
                terminal = Load(cursor);
                if (terminal.leaf) break;
                if (int(terminal.depth) <= previous)
                    throw std::runtime_error("redeem archive branch order");
                previous = terminal.depth;
                path.push_back(terminal);
                hashes.push_back(cursor);
                cursor = btcnull::Bit(key, terminal.depth)
                    ? terminal.right : terminal.left;
            }
            if (terminal.key == key) {
                if (terminal.value != value)
                    throw std::runtime_error("conflicting archived identifier");
                return false;
            }
        }
        if (root.count == UINT64_MAX)
            throw std::runtime_error("redeem archive count overflow");
        Records records;
        Hash256 child = Stage(records, Leaf(key, value));
        size_t ancestors = 0;
        if (root.count != 0) {
            size_t split = 0;
            while (split < 256 && btcnull::Bit(key, split) ==
                                   btcnull::Bit(terminal.key, split)) ++split;
            if (split == 256) throw std::runtime_error("redeem archive key collision");
            while (ancestors < path.size() && path[ancestors].depth < split)
                ++ancestors;
            const Hash256 old_subtree =
                ancestors < hashes.size() ? hashes[ancestors] : cursor;
            child = btcnull::Bit(key, split)
                ? Stage(records, Branch(uint16_t(split), old_subtree, child))
                : Stage(records, Branch(uint16_t(split), child, old_subtree));
        }
        while (ancestors != 0) {
            const Node& parent = path[--ancestors];
            child = btcnull::Bit(key, parent.depth)
                ? Stage(records, Branch(parent.depth, parent.left, child))
                : Stage(records, Branch(parent.depth, child, parent.right));
        }
        // Backend writes one atomic, durable batch. A failure leaves root and
        // count unchanged. Old roots remain readable through rollback/restart.
        if (!write_(records))
            throw std::runtime_error("redeem archive durable write failed");
        root.hash = child;
        ++root.count;
        return true;
    }

private:
    struct Node {
        bool leaf = false;
        uint16_t depth = 0;
        Hash256 key{}, left{}, right{};
        std::string value;
    };
    Read read_;
    Write write_;
    static void AppendHash(std::string& s, const Hash256& h) {
        s.append(reinterpret_cast<const char*>(h.data()), h.size());
    }
    static Hash256 ReadHash(const std::string& s, size_t at) {
        Hash256 h{};
        std::copy_n(s.begin() + at, 32, h.begin());
        return h;
    }
    static std::string Leaf(const Hash256& key, const std::string& value) {
        std::string record(1, char(0));
        AppendHash(record, key);
        record += value;
        return record;
    }
    static std::string Branch(uint16_t depth, const Hash256& left,
                              const Hash256& right) {
        std::string record{char(1), char(depth & 255), char(depth >> 8)};
        AppendHash(record, left);
        AppendHash(record, right);
        return record;
    }
    static Hash256 Stage(Records& records, const std::string& value) {
        const Hash256 hash = HashRecord(value);
        records.emplace_back(HashToHex(hash), value);
        return hash;
    }
    static void CheckRoot(const Root& root) {
        if ((root.count == 0) != (root.hash == EmptyRoot()))
            throw std::runtime_error("redeem archive root/count mismatch");
    }
    Node Load(const Hash256& hash) const {
        if (!read_) throw std::runtime_error("redeem archive backend unavailable");
        const auto raw = read_(HashToHex(hash));
        if (!raw || raw->empty() || HashRecord(*raw) != hash)
            throw std::runtime_error("redeem archive record missing or corrupt");
        Node node;
        if ((*raw)[0] == char(0) && raw->size() >= 33) {
            node.leaf = true;
            node.key = ReadHash(*raw, 1);
            node.value = raw->substr(33);
        } else if ((*raw)[0] == char(1) && raw->size() == 67) {
            node.depth = uint16_t(uint8_t((*raw)[1])) |
                         (uint16_t(uint8_t((*raw)[2])) << 8);
            node.left = ReadHash(*raw, 3);
            node.right = ReadHash(*raw, 35);
            if (node.depth >= 256 || node.left == EmptyRoot() ||
                node.right == EmptyRoot())
                throw std::runtime_error("redeem archive invalid branch");
        } else {
            throw std::runtime_error("redeem archive invalid record");
        }
        return node;
    }
};

} // namespace veld::btcveld
