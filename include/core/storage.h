#pragma once

#include "../core/block.h"
#include "../core/blockchain.h"
#include "../core/hash.h"
#include "../core/canonical_numeric.h"
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <stdexcept>
#include <sstream>
#include <iostream>

namespace veld {

namespace fs = std::filesystem;

struct BlockFileHeader {
    uint32_t magic;
    uint32_t block_size;
};

struct BlockIndexEntry {
    std::string hash_hex;
    uint64_t    height;
    uint32_t    file_number;
    uint64_t    file_offset;
    uint32_t    block_size;
    uint64_t    timestamp;
    uint32_t    bits;
};

class StorageEngine {
public:
    explicit StorageEngine(const std::string& data_dir, uint32_t network_magic)
        : data_dir_(data_dir)
        , magic_(network_magic)
        , current_file_number_(0)
        , current_file_size_(0) {
        Initialize();
    }

    bool WriteBlock(const Block& block) {
        std::string hash_hex = HashToHex(block.GetHash());

        if (block_index_.count(hash_hex)) return true;

        std::vector<uint8_t> block_data = block.Serialize();
        uint32_t block_size = (uint32_t)block_data.size();

        if (current_file_size_ + block_size + sizeof(BlockFileHeader) > 128 * 1024 * 1024) {
            ++current_file_number_;
            current_file_size_ = 0;
        }

        std::string block_file = BlockFilePath(current_file_number_);
        std::ofstream ofs(block_file, std::ios::binary | std::ios::app);
        if (!ofs) throw std::runtime_error("Cannot open block file: " + block_file);

        BlockFileHeader hdr;
        hdr.magic      = magic_;
        hdr.block_size = block_size;
        ofs.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));

        ofs.write(reinterpret_cast<const char*>(block_data.data()), block_size);
        ofs.close();

        BlockIndexEntry entry;
        entry.hash_hex     = hash_hex;
        entry.height       = block.height;
        entry.file_number  = current_file_number_;
        entry.file_offset  = current_file_size_ + sizeof(BlockFileHeader);
        entry.block_size   = block_size;
        entry.timestamp    = block.header.timestamp;
        entry.bits         = block.header.bits;

        block_index_[hash_hex] = entry;
        height_index_[block.height] = hash_hex;

        current_file_size_ += sizeof(BlockFileHeader) + block_size;

        FlushIndex();

        return true;
    }

    std::optional<std::vector<uint8_t>> ReadBlockRaw(const std::string& hash_hex) const {
        auto it = block_index_.find(hash_hex);
        if (it == block_index_.end()) return std::nullopt;

        const BlockIndexEntry& entry = it->second;
        std::string block_file = BlockFilePath(entry.file_number);

        std::ifstream ifs(block_file, std::ios::binary);
        if (!ifs) return std::nullopt;

        ifs.seekg(entry.file_offset);
        std::vector<uint8_t> data(entry.block_size);
        ifs.read(reinterpret_cast<char*>(data.data()), entry.block_size);

        if (!ifs) return std::nullopt;
        return data;
    }

    bool WriteChainState(uint64_t height, const Hash256& tip_hash, uint64_t supply_units) {
        std::string path = ChainStatePath();
        std::string tmp  = path + ".tmp";
        {
            std::ofstream ofs(tmp);
            if (!ofs) return false;
            ofs << "height=" << height << "\n";
            ofs << "tip="    << HashToHex(tip_hash) << "\n";
            ofs << "supply=" << supply_units << "\n";
        }
        std::error_code ec;
        std::filesystem::rename(tmp, path, ec);
        return !ec;
    }

    struct ChainState {
        uint64_t height;
        std::string tip_hash_hex;
        uint64_t supply_units;
    };

    std::optional<ChainState> ReadChainState() const {
        std::string path = ChainStatePath();
        std::ifstream ifs(path);
        if (!ifs) return std::nullopt;

        ChainState state{};
        bool have_height = false;
        bool have_tip = false;
        bool have_supply = false;
        std::string line;
        while (std::getline(ifs, line)) {
            if (line.rfind("height=", 0) == 0) {
                if (have_height || !ParseCanonicalUint64Text(
                        std::string_view(line).substr(7), state.height))
                    return std::nullopt;
                have_height = true;
            } else if (line.rfind("tip=", 0) == 0) {
                if (have_tip) return std::nullopt;
                state.tip_hash_hex = line.substr(4);
                if (state.tip_hash_hex.size() != 64) return std::nullopt;
                for (char c : state.tip_hash_hex) {
                    if (!((c >= '0' && c <= '9') ||
                          (c >= 'a' && c <= 'f'))) return std::nullopt;
                }
                have_tip = true;
            } else if (line.rfind("supply=", 0) == 0) {
                if (have_supply || !ParseCanonicalUint64Text(
                        std::string_view(line).substr(7), state.supply_units) ||
                    state.supply_units > MAX_SUPPLY_UNITS)
                    return std::nullopt;
                have_supply = true;
            } else if (!line.empty()) {
                return std::nullopt;
            }
        }
        if (!ifs.eof() || !have_height || !have_tip || !have_supply)
            return std::nullopt;
        return state;
    }

    bool WriteUTXOSet(const std::unordered_map<std::string, UTXO>& utxos) {
        std::string path = UTXOPath();
        std::ofstream ofs(path, std::ios::binary);
        if (!ofs) return false;

        uint64_t count = utxos.size();
        ofs.write(reinterpret_cast<const char*>(&count), sizeof(count));

        for (const auto& [key, utxo] : utxos) {
            uint32_t klen = (uint32_t)key.size();
            ofs.write(reinterpret_cast<const char*>(&klen), sizeof(klen));
            ofs.write(key.data(), klen);

            ofs.write(reinterpret_cast<const char*>(utxo.tx_hash.data()), 32);
            ofs.write(reinterpret_cast<const char*>(&utxo.output_index), sizeof(utxo.output_index));
            ofs.write(reinterpret_cast<const char*>(&utxo.value), sizeof(utxo.value));
            ofs.write(reinterpret_cast<const char*>(&utxo.block_height), sizeof(utxo.block_height));

            uint32_t script_len = (uint32_t)utxo.script_pubkey.size();
            ofs.write(reinterpret_cast<const char*>(&script_len), sizeof(script_len));
            ofs.write(reinterpret_cast<const char*>(utxo.script_pubkey.data()), script_len);
        }

        return true;
    }

    bool HasBlock(const Hash256& hash) const {
        return block_index_.count(HashToHex(hash)) > 0;
    }

    bool HasBlock(const std::string& hash_hex) const {
        return block_index_.count(hash_hex) > 0;
    }

    std::optional<BlockIndexEntry> GetBlockIndex(const std::string& hash_hex) const {
        auto it = block_index_.find(hash_hex);
        if (it == block_index_.end()) return std::nullopt;
        return it->second;
    }

    uint64_t BlockCount()     const { return block_index_.size(); }
    std::string DataDir()     const { return data_dir_; }

    std::string GetStorageInfo() const {
        std::string info;
        info += "Data dir:      " + data_dir_ + "\n";
        info += "Blocks stored: " + std::to_string(block_index_.size()) + "\n";
        info += "Block files:   " + std::to_string(current_file_number_ + 1) + "\n";
        info += "Current size:  " + std::to_string(current_file_size_ / 1024) + " KB\n";
        return info;
    }

private:
    std::string  data_dir_;
    uint32_t     magic_;
    uint32_t     current_file_number_;
    uint64_t     current_file_size_;

    std::unordered_map<std::string, BlockIndexEntry> block_index_;
    std::unordered_map<uint64_t, std::string>        height_index_;

    void Initialize() {
        fs::create_directories(data_dir_ + "/blocks");
        fs::create_directories(data_dir_ + "/chainstate");
        fs::create_directories(data_dir_ + "/index");

        LoadIndex();
    }

    std::string BlockFilePath(uint32_t file_number) const {
        char buf[32];
        snprintf(buf, sizeof(buf), "blk%05u.dat", file_number);
        return data_dir_ + "/blocks/" + buf;
    }

    std::string IndexPath()      const { return data_dir_ + "/index/block_index.dat"; }
    std::string ChainStatePath() const { return data_dir_ + "/chainstate/chain.dat"; }
    std::string UTXOPath()       const { return data_dir_ + "/chainstate/utxo.dat"; }

    void FlushIndex() {
        std::ofstream ofs(IndexPath());
        if (!ofs) return;
        for (const auto& [hash, entry] : block_index_) {
            ofs << entry.hash_hex     << " "
                << entry.height       << " "
                << entry.file_number  << " "
                << entry.file_offset  << " "
                << entry.block_size   << " "
                << entry.timestamp    << " "
                << entry.bits         << "\n";
        }
    }

    void LoadIndex() {
        std::ifstream ifs(IndexPath());
        if (!ifs) return;

        std::string line;
        while (std::getline(ifs, line)) {
            std::istringstream ss(line);
            BlockIndexEntry entry;
            ss >> entry.hash_hex
               >> entry.height
               >> entry.file_number
               >> entry.file_offset
               >> entry.block_size
               >> entry.timestamp
               >> entry.bits;
            if (!entry.hash_hex.empty()) {
                block_index_[entry.hash_hex] = entry;
                height_index_[entry.height] = entry.hash_hex;
                if (entry.file_number >= current_file_number_)
                    current_file_number_ = entry.file_number;
            }
        }
        std::string last_file = BlockFilePath(current_file_number_);
        if (std::filesystem::exists(last_file))
            current_file_size_ = std::filesystem::file_size(last_file);
    }
};

}
