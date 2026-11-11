// Inspect an isolated copy of authenticated snapshot bodies for fork fixtures.
#include "core/block.h"
#include <leveldb/db.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>

namespace fs = std::filesystem;
int main(int argc, char** argv) {
    try {
        if (argc != 3)
            throw std::runtime_error("snapshot database copy and fresh output directory required");
        const fs::path root = fs::canonical(argv[1]), out = fs::absolute(argv[2]);
        if (!fs::create_directory(out))
            throw std::runtime_error("fresh fixture export required");
        auto open = [&](const char* name) {
            leveldb::DB* raw = nullptr;
            leveldb::Options options;
            options.create_if_missing = false;
            auto status = leveldb::DB::Open(options, (root / name).string(), &raw);
            if (!status.ok())
                throw std::runtime_error(status.ToString());
            return std::unique_ptr<leveldb::DB>(raw);
        };
        auto blocks = open("blocks"), index = open("index");
        std::map<std::string, uint64_t> canonical;
        std::unique_ptr<leveldb::Iterator> i(index->NewIterator({}));
        for (i->Seek("idx:height:"); i->Valid() && i->key().starts_with("idx:height:"); i->Next()) {
            auto key = i->key().ToString(), value = i->value().ToString();
            size_t used = 0;
            auto h = std::stoull(key.substr(11), &used);
            if (used != key.size() - 11 || value.size() != 64 ||
                !canonical.emplace(value, h).second)
                throw std::runtime_error("noncanonical height index");
        }
        if (!i->status().ok())
            throw std::runtime_error(i->status().ToString());
        size_t count = 0;
        bool comma = false;
        std::cout << "{\"status\":\"PASS_AUTHENTICATED_BODY_INVENTORY\",\"canonical_bodies\":"
                  << canonical.size() << ",\"side_bodies\":[";
        i.reset(blocks->NewIterator({}));
        for (i->Seek("b:"); i->Valid() && i->key().starts_with("b:"); i->Next()) {
            auto key = i->key().ToString();
            if (key.size() != 66)
                throw std::runtime_error("invalid block key");
            const auto hash = key.substr(2);
            if (canonical.contains(hash))
                continue;
            if (++count > 100)
                throw std::runtime_error("side body inventory bound");
            const auto value = i->value().ToString();
            std::vector<uint8_t> raw(value.begin(), value.end());
            veld::Block b;
            if (veld::Block::Deserialize(raw, 0, b) != raw.size() || b.Serialize() != raw ||
                veld::HashToHex(b.GetHash()) != hash)
                throw std::runtime_error("side body identity mismatch");
            const auto parent = veld::HashToHex(b.header.prev_block_hash);
            const auto found = canonical.find(parent);
            if (comma)
                std::cout << ',';
            comma = true;
            std::cout << "{\"hash\":\"" << hash << "\",\"parent\":\"" << parent << "\",\"height\":";
            if (found == canonical.end())
                std::cout << "null";
            else
                std::cout << (found->second + 1);
            std::cout << ",\"transactions\":" << b.transactions.size()
                      << ",\"bytes\":" << raw.size() << ",\"bits\":" << b.header.bits << "}";
            std::ofstream file(out / (hash + ".block"), std::ios::binary);
            file.write(value.data(), value.size());
            file.close();
            if (!file)
                throw std::runtime_error("fixture export failed");
        }
        if (!i->status().ok())
            throw std::runtime_error(i->status().ToString());
        std::cout << "],\"consensus_validated\":false,\"network_services\":0}\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
