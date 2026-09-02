#pragma once

#include "hash.h"
#include "constants.h"
#include "transaction.h"
#include "pow_target.h"
#include <vector>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <limits>
#include <stdexcept>

namespace veld {

struct BlockHeader {
    uint32_t version;
    Hash256  prev_block_hash;
    Hash256  merkle_root;
    uint64_t timestamp;
    uint32_t bits;
    uint64_t nonce;

    BlockHeader()
        : version(2), timestamp((uint64_t)std::time(nullptr)), bits(GENESIS_BITS), nonce(0) {
        prev_block_hash = ZeroHash();
        merkle_root = ZeroHash();
    }

    std::vector<uint8_t> Serialize() const {
        std::vector<uint8_t> data;
        data.reserve(88);
        data.push_back(version & 0xFF);
        data.push_back((version >> 8) & 0xFF);
        data.push_back((version >> 16) & 0xFF);
        data.push_back((version >> 24) & 0xFF);
        data.insert(data.end(), prev_block_hash.begin(), prev_block_hash.end());
        data.insert(data.end(), merkle_root.begin(), merkle_root.end());
        for (int i = 0; i < 8; ++i) data.push_back((uint8_t)((timestamp >> (i*8)) & 0xFF));
        data.push_back(bits & 0xFF);
        data.push_back((bits >> 8) & 0xFF);
        data.push_back((bits >> 16) & 0xFF);
        data.push_back((bits >> 24) & 0xFF);
        for (int i = 0; i < 8; ++i) data.push_back((uint8_t)((nonce >> (i*8)) & 0xFF));
        return data;
    }

    bool Deserialize(const std::vector<uint8_t>& data, size_t offset = 0) {
        if (data.size() < offset + 88) return false;
        auto rd32 = [](const std::vector<uint8_t>& d, size_t o) -> uint32_t {
            return (uint32_t)d[o] | ((uint32_t)d[o+1]<<8)
                 | ((uint32_t)d[o+2]<<16) | ((uint32_t)d[o+3]<<24);
        };
        auto rd64 = [](const std::vector<uint8_t>& d, size_t o) -> uint64_t {
            uint64_t v = 0;
            for (int i = 0; i < 8; ++i) v |= ((uint64_t)d[o+i]) << (i*8);
            return v;
        };
        version   = rd32(data, offset);
        for (int _i=0;_i<32;_i++) prev_block_hash[_i]=data[offset+4+_i];
        for (int _i=0;_i<32;_i++) merkle_root[_i]=data[offset+36+_i];
        timestamp = rd64(data, offset+68);
        bits      = rd32(data, offset+76);
        nonce     = rd64(data, offset+80);
        return true;
    }

    Hash256 GetHash() const {
        auto data = Serialize();
        return Hash256d(data);
    }

    // Public work templates authorize one exact header/body identity while
    // leaving only the proof nonce mutable.  This is not a consensus hash and
    // never replaces GetHash(); it is the nonce-independent identity carried
    // from getblocktemplate to submitblock.
    Hash256 GetTemplateWorkIdentity() const {
        BlockHeader template_header = *this;
        template_header.nonce = 0;
        return Hash256d(template_header.Serialize());
    }

    static bool DecodeBits(uint32_t bits, Hash256& out) {
        CanonicalPowTarget target;
        if (!DecodeCanonicalVeldTarget(bits, target)) {
            out.fill(0);
            return false;
        }
        out = target.bytes;
        return true;
    }

    Hash256 GetTarget() const {
        Hash256 target{};
        if (!DecodeBits(bits, target)) {
            target.fill(0);
        }
        return target;
    }

    bool MeetsTarget() const {
        Hash256 hash   = GetHash();
        Hash256 target = GetTarget();
        return hash < target;
    }
};

namespace internal_merkle {
inline Hash256 TaggedHash(const std::string& tag, const uint8_t* data, size_t len) {
    Hash256 tag_hash = Hash256d((const uint8_t*)tag.data(), tag.size());
    std::vector<uint8_t> buf;
    buf.reserve(64 + len);
    buf.insert(buf.end(), tag_hash.begin(), tag_hash.end());
    buf.insert(buf.end(), tag_hash.begin(), tag_hash.end());
    buf.insert(buf.end(), data, data + len);
    return Hash256d(buf);
}
}

inline Hash256 ComputeMerkleRoot(const std::vector<Transaction>& txs) {
    if (txs.empty()) return ZeroHash();

    static const std::string LEAF_TAG   = "VeldMerkleLeaf";
    static const std::string BRANCH_TAG = "VeldMerkleBranch";

    std::vector<Hash256> hashes;
    hashes.reserve(txs.size());
    for (const auto& tx : txs) {
        Hash256 txid = tx.GetTxID();
        hashes.push_back(internal_merkle::TaggedHash(LEAF_TAG, txid.data(), txid.size()));
    }

    while (hashes.size() > 1) {
        std::vector<Hash256> next;
        next.reserve((hashes.size() + 1) / 2);
        size_t i = 0;
        for (; i + 1 < hashes.size(); i += 2) {
            uint8_t pair[64];
            ::memcpy(pair,      hashes[i].data(),     32);
            ::memcpy(pair + 32, hashes[i + 1].data(), 32);
            next.push_back(internal_merkle::TaggedHash(BRANCH_TAG, pair, 64));
        }
        if (i < hashes.size()) {
            next.push_back(hashes[i]);
        }
        hashes = std::move(next);
    }
    return hashes[0];
}

struct Block {
    BlockHeader             header;
    std::vector<Transaction> transactions;
    uint64_t                height;

    Block() : height(0) {}

    void UpdateMerkleRoot() {
        header.merkle_root = ComputeMerkleRoot(transactions);
    }

    bool DeserializeHeader(const std::vector<uint8_t>& data, size_t offset = 0) {
        return header.Deserialize(data, offset);
    }

    Hash256 GetHash() const {
        return header.GetHash();
    }

    //  -5: this is a STRUCTURAL validity check only —
    // it does NOT verify that `bits` is consistent with the chain's
    // LWMA-computed expected difficulty (that lives in AddBlockDirect
    // via ComputeNextBitsAt). Callers should NOT use this as the sole
    // gate before adding a block to the chain. `IsStructurallyValid` is
    // the new preferred name for clarity; `IsValid` retained as alias
    // for backward compat with explorer display path.
    bool IsStructurallyValid() const {
        if (transactions.empty()) return false;
        if (!transactions[0].IsCoinbase()) return false;

        Hash256 computed = ComputeMerkleRoot(transactions);
        if (computed != header.merkle_root) return false;

        if (!header.MeetsTarget()) return false;

        if (transactions.size() > MAX_TRANSACTIONS_PER_BLOCK) return false;

        return true;
    }

    bool IsValid() const { return IsStructurallyValid(); }

    std::vector<uint8_t> Serialize() const {
        std::vector<uint8_t> data;
        auto header_bytes = header.Serialize();
        data.insert(data.end(), header_bytes.begin(), header_bytes.end());

        uint32_t tx_count = (uint32_t)transactions.size();
        data.push_back(tx_count & 0xFF);
        data.push_back((tx_count >> 8) & 0xFF);
        data.push_back((tx_count >> 16) & 0xFF);
        data.push_back((tx_count >> 24) & 0xFF);
        for (const auto& tx : transactions) {
            auto tx_bytes = tx.Serialize();
            data.insert(data.end(), tx_bytes.begin(), tx_bytes.end());
        }
        return data;
    }

    size_t SerializedSize() const {
        // Fixed wire envelope: 88-byte header + 4-byte transaction count.
        // Keep this helper aligned with Serialize(); consensus size checks must
        // count the complete block, not only its transaction payloads.
        size_t total = 92;
        for (const auto& tx : transactions) {
            const size_t tx_size = tx.Serialize().size();
            if (tx_size > std::numeric_limits<size_t>::max() - total)
                return std::numeric_limits<size_t>::max();
            total += tx_size;
        }
        return total;
    }

    static size_t Deserialize(const std::vector<uint8_t>& data, size_t offset, Block& out) {
        size_t pos = offset;
        const size_t n = data.size();

        if (pos + 88 > n) return 0;
        BlockHeader hdr;
        hdr.version = data[pos] | ((uint32_t)data[pos+1]<<8) | ((uint32_t)data[pos+2]<<16) | ((uint32_t)data[pos+3]<<24);
        pos += 4;
        std::copy(data.begin() + pos, data.begin() + pos + 32, hdr.prev_block_hash.begin());
        pos += 32;
        std::copy(data.begin() + pos, data.begin() + pos + 32, hdr.merkle_root.begin());
        pos += 32;
        {
            uint64_t ts = 0;
            for (int i = 0; i < 8; ++i) ts |= ((uint64_t)data[pos+i]) << (i*8);
            hdr.timestamp = ts;
            pos += 8;
        }
        hdr.bits  = data[pos] | ((uint32_t)data[pos+1]<<8) | ((uint32_t)data[pos+2]<<16) | ((uint32_t)data[pos+3]<<24);
        pos += 4;
        {
            uint64_t n8 = 0;
            for (int i = 0; i < 8; ++i) n8 |= ((uint64_t)data[pos+i]) << (i*8);
            hdr.nonce = n8;
            pos += 8;
        }
        out.header = hdr;

        if (pos + 4 > n) return 0;
        uint32_t tx_count = data[pos] | ((uint32_t)data[pos+1]<<8) | ((uint32_t)data[pos+2]<<16) | ((uint32_t)data[pos+3]<<24);
        pos += 4;
        if (tx_count > MAX_TRANSACTIONS_PER_BLOCK) return 0;
        out.transactions.clear();
        for (uint32_t i = 0; i < tx_count; ++i) {
            Transaction tx;
            size_t consumed = Transaction::Deserialize(data, pos, tx);
            if (consumed == 0) return 0;
            pos += consumed;
            out.transactions.push_back(tx);
        }

        return pos - offset;
    }
};

inline Block CreateGenesisBlock() {
    Block genesis;
    genesis.height = 0;

    Transaction coinbase;
    coinbase.inputs.push_back(TxInput::Coinbase(GENESIS_MESSAGE));
    coinbase.outputs.push_back(TxOutput(0, {}));
    genesis.transactions.push_back(coinbase);

    genesis.UpdateMerkleRoot();

    genesis.header.version         = 1;
    genesis.header.prev_block_hash = ZeroHash();
    genesis.header.timestamp       = GENESIS_TIME;
    genesis.header.bits            = GENESIS_BITS;
    genesis.header.nonce           = GENESIS_NONCE;

    if (GENESIS_HASH[0] != '\0') {
        std::string computed = HashToHex(genesis.header.GetHash());
        Hash256 raw = genesis.header.GetHash();
        std::string be_hex;
        for (int i = 31; i >= 0; --i) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", raw[i]);
            be_hex += buf;
        }
        if (be_hex != std::string(GENESIS_HASH)) {
            throw std::runtime_error(
                "FATAL: genesis hash mismatch. Computed " + be_hex +
                " but constants.h pins " + std::string(GENESIS_HASH) +
                ". Either re-mine genesis (genesis_miner) and update "
                "GENESIS_HASH, or revert your local source. Refusing to "
                "start with a divergent genesis.");
        }
    }

    return genesis;
}

}
