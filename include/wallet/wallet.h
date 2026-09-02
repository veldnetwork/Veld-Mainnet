#pragma once

#include "../core/hash.h"
#include "../crypto/veld_signing.h"
#include "../core/transaction.h"
#include "../core/constants.h"
#include "../core/script.h"
#include "../crypto/ripemd160.h"
#include <vector>
#include <string>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <sstream>
#include <iomanip>

namespace veld {

using PrivateKey = std::array<uint8_t, 32>;
using PublicKey  = std::array<uint8_t, 1952>;

static const std::string BASE58_ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

inline std::string Base58Encode(const std::vector<uint8_t>& data) {
    int leading_zeros = 0;
    for (auto byte : data) {
        if (byte == 0) ++leading_zeros;
        else break;
    }

    std::vector<uint8_t> digits = {0};
    for (auto byte : data) {
        int carry = byte;
        for (auto& digit : digits) {
            carry += 256 * digit;
            digit = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            digits.push_back(carry % 58);
            carry /= 58;
        }
    }

    std::string result(leading_zeros, '1');
    auto it = digits.rbegin();
    while (it != digits.rend() && *it == 0) ++it;
    for (; it != digits.rend(); ++it)
        result += BASE58_ALPHABET[*it];

    return result;
}

inline std::vector<uint8_t> Base58Decode(const std::string& input) {
    static const int8_t TABLE[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
        -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
        22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
        -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
        47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1
    };

    int leading_ones = 0;
    for (char c : input) {
        if (c == '1') ++leading_ones;
        else break;
    }

    std::vector<uint8_t> digits = {0};
    for (char c : input) {
        int carry = TABLE[(uint8_t)c];
        if (carry < 0) return {};
        for (auto& d : digits) {
            int val = (int)d * 58 + carry;
            d = (uint8_t)(val & 0xFF);
            carry = val >> 8;
        }
        while (carry > 0) {
            digits.push_back((uint8_t)(carry & 0xFF));
            carry >>= 8;
        }
    }

    std::vector<uint8_t> result(leading_ones, 0);
    auto it = digits.rbegin();
    while (it != digits.rend() && *it == 0) ++it;
    result.insert(result.end(), it, digits.rend());

    return result;
}

inline bool Base58CheckDecode(
    const std::string& address,
    uint8_t& version_out,
    std::vector<uint8_t>& payload_out
) {
    auto decoded = Base58Decode(address);
    if (decoded.size() < 5) return false;

    std::vector<uint8_t> body(decoded.begin(), decoded.end() - 4);
    std::vector<uint8_t> expected_chk(decoded.end() - 4, decoded.end());

    Hash256 actual_chk = Hash256d(body);
    if (actual_chk[0] != expected_chk[0] ||
        actual_chk[1] != expected_chk[1] ||
        actual_chk[2] != expected_chk[2] ||
        actual_chk[3] != expected_chk[3])
        return false;

    version_out = body[0];
    payload_out = std::vector<uint8_t>(body.begin() + 1, body.end());
    return true;
}

inline std::string Base58CheckEncode(uint8_t version, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> data = {version};
    data.insert(data.end(), payload.begin(), payload.end());

    Hash256 checksum = Hash256d(data);
    data.push_back(checksum[0]);
    data.push_back(checksum[1]);
    data.push_back(checksum[2]);
    data.push_back(checksum[3]);

    return Base58Encode(data);
}

inline std::string PubKeyToAddress(const PublicKey& pubkey, bool testnet = false) {
    Hash160 pubkey_hash = Hash160Compute(pubkey.data(), pubkey.size());
    uint8_t version = testnet ? 0x6F : 0x46;
    std::vector<uint8_t> payload(pubkey_hash.begin(), pubkey_hash.end());
    return Base58CheckEncode(version, payload);
}

inline std::vector<uint8_t> BuildP2PKHScript(const std::array<uint8_t, 20>& pubkey_hash) {
    std::vector<uint8_t> script;
    script.push_back(0x76);
    script.push_back(0xA9);
    script.push_back(0x14);
    script.insert(script.end(), pubkey_hash.begin(), pubkey_hash.end());
    script.push_back(0x88);
    script.push_back(0xAC);
    return script;
}

inline std::vector<uint8_t> BuildOpReturnScript(const std::string& data) {
    std::vector<uint8_t> script;
    script.push_back(0x6A);
    if (data.size() <= 75) {
        script.push_back((uint8_t)data.size());
    } else if (data.size() <= 255) {
        script.push_back(0x4C);
        script.push_back((uint8_t)data.size());
    } else {
        script.push_back(0x4D);
        script.push_back(data.size() & 0xFF);
        script.push_back((data.size() >> 8) & 0xFF);
    }
    script.insert(script.end(), data.begin(), data.end());
    return script;
}

inline std::string ParseOpReturn(const std::vector<uint8_t>& script) {
    if (script.size() < 2 || script[0] != 0x6A) return "";
    size_t offset = 1;
    size_t len = 0;
    if (script[offset] <= 75) {
        len = script[offset++];
    } else if (script[offset] == 0x4C && script.size() > offset+1) {
        offset++; len = script[offset++];
    } else if (script[offset] == 0x4D && script.size() > offset+2) {
        offset++; len = script[offset] | (script[offset+1]<<8); offset+=2;
    }
    if (offset + len > script.size()) return "";
    return std::string(script.begin()+offset, script.begin()+offset+len);
}

struct KeyPair {
    PrivateKey private_key;
    PublicKey  public_key;
    std::string address;

    std::vector<uint8_t> GetP2PKHScript() const {
        Hash160 pubkey_hash = Hash160Compute(public_key.data(), public_key.size());
        return BuildP2PKHScript(pubkey_hash);
    }
};

class Wallet {
public:
    Wallet() : testnet_(false) {}
    explicit Wallet(bool testnet) : testnet_(testnet) {}

    KeyPair GenerateKeyPair() const {
        throw std::runtime_error(
            "wallet::WalletFile::GenerateKeyPair is disabled — use "
            "veld::GenerateKeyPair(opt_testnet) from crypto/veld_signing.h "
            "(CSPRNG + ML-DSA-65 keypair).");
    }

    Transaction BuildTransaction(
        const KeyPair& sender,
        const std::string& recipient_address,
        uint64_t amount_units,
        uint64_t fee_units,
        const std::vector<std::pair<Hash256, uint32_t>>& utxos
    ) const {
        if (amount_units == 0)
            throw std::invalid_argument("Transaction amount must be greater than zero");
        if (utxos.empty())
            throw std::invalid_argument("No UTXOs provided to spend");

        Transaction tx;

        for (const auto& [tx_hash, index] : utxos) {
            TxInput input;
            input.prev_tx_hash   = tx_hash;
            input.prev_out_index = index;
            tx.inputs.push_back(input);
        }

        std::vector<uint8_t> recipient_script = {0x76, 0xA9, 0x14};
        for (int i = 0; i < 20; ++i) recipient_script.push_back(0x00);
        recipient_script.push_back(0x88);
        recipient_script.push_back(0xAC);
        tx.outputs.push_back(TxOutput(amount_units, recipient_script));

        uint64_t change = 0;
        if (change > 0) {
            tx.outputs.push_back(TxOutput(change, sender.GetP2PKHScript()));
        }

        return tx;
    }

    static std::string FormatBalance(uint64_t units) {
        static_assert(MAX_SUPPLY_UNITS < (1ULL << 53),
                      "FormatBalance precision loss: MAX_SUPPLY_UNITS exceeds "
                      "double-precision exact-integer range. Switch FormatBalance "
                      "to fixed-point arithmetic before bumping the supply cap.");
        double veld = (double)units / VELD_UNITS;
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(8) << veld << " VELD";
        return oss.str();
    }

    bool IsTestnet() const { return testnet_; }

private:
    bool testnet_;
};

}
