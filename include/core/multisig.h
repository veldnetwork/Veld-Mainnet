#pragma once

#include "transaction.h"
#include "hash.h"
#include "constants.h"
#include "../crypto/veld_signing.h"
#include <vector>
#include <string>
#include <stdexcept>
#include <unordered_map>

namespace veld {

class MultiSig {
public:
    MultiSig(uint32_t required, const std::vector<Secp256k1PubKey>& pubkeys)
        : required_(required), pubkeys_(pubkeys) {
        if (required == 0 || required > pubkeys.size())
            throw std::invalid_argument("Invalid M-of-N parameters");
        if (pubkeys.size() > 15)
            throw std::invalid_argument("Maximum 15 keys in multisig");
        redeem_script_ = BuildRedeemScript();
    }

    std::string GetAddress(bool testnet = false) const {
        Hash160 script_hash = Hash160Compute(redeem_script_);
        uint8_t version     = testnet ? 0xC4 : 0x05;

        std::vector<uint8_t> data = {version};
        data.insert(data.end(), script_hash.begin(), script_hash.end());
        Hash256 chk = Hash256d(data);
        data.push_back(chk[0]); data.push_back(chk[1]);
        data.push_back(chk[2]); data.push_back(chk[3]);

        static const char* B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        int lead = 0;
        for (auto b : data) { if (b==0) ++lead; else break; }
        std::vector<uint8_t> digits = {0};
        for (auto byte : data) {
            int carry = byte;
            for (auto& d : digits) { carry += 256*d; d = carry%58; carry /= 58; }
            while (carry > 0) { digits.push_back(carry%58); carry /= 58; }
        }
        std::string addr(lead, '1');
        for (auto it = digits.rbegin(); it != digits.rend(); ++it)
            addr += B58[*it];
        return addr;
    }

    std::vector<uint8_t> GetScriptPubKey() const {
        Hash160 script_hash = Hash160Compute(redeem_script_);
        std::vector<uint8_t> script;
        script.push_back(0xA9);
        script.push_back(0x14);
        script.insert(script.end(), script_hash.begin(), script_hash.end());
        script.push_back(0x87);
        return script;
    }

    void Sign(Transaction& tx, uint32_t input_idx,
              const Secp256k1PrivKey& privkey) {
        Secp256k1PubKey pubkey = DerivePublicKey(privkey);

        bool found = false;
        for (auto& pk : pubkeys_) if (pk == pubkey) { found = true; break; }
        if (!found) throw std::runtime_error("Key not in multisig set");

        Hash256 sighash = ComputeSighash(tx, input_idx, redeem_script_);
        Secp256k1SigDER sig = veld::Sign(privkey, sighash);
        sig.push_back(0x01);

        partial_sigs_[input_idx].push_back({pubkey, sig});
    }

    bool Finalize(Transaction& tx, uint32_t input_idx) {
        auto it = partial_sigs_.find(input_idx);
        if (it == partial_sigs_.end()) return false;
        if (it->second.size() < required_) return false;

        std::vector<uint8_t> script_sig;
        script_sig.push_back(0x00);

        for (uint32_t i = 0; i < required_; ++i) {
            const auto& sig = it->second[i].sig;
            const size_t n = sig.size();
            if (n <= 75) {
                script_sig.push_back((uint8_t)n);
            } else if (n <= 255) {
                script_sig.push_back(0x4C);
                script_sig.push_back((uint8_t)n);
            } else if (n <= 0xFFFF) {
                script_sig.push_back(0x4D);
                script_sig.push_back((uint8_t)(n & 0xFF));
                script_sig.push_back((uint8_t)((n >> 8) & 0xFF));
            } else {
                return false;
            }
            script_sig.insert(script_sig.end(), sig.begin(), sig.end());
        }

        if (redeem_script_.size() <= 75) {
            script_sig.push_back((uint8_t)redeem_script_.size());
        } else if (redeem_script_.size() <= 255) {
            script_sig.push_back(0x4C);
            script_sig.push_back((uint8_t)redeem_script_.size());
        } else {
            script_sig.push_back(0x4D);
            script_sig.push_back(redeem_script_.size() & 0xFF);
            script_sig.push_back((redeem_script_.size() >> 8) & 0xFF);
        }
        script_sig.insert(script_sig.end(), redeem_script_.begin(), redeem_script_.end());

        tx.inputs[input_idx].script_sig = script_sig;
        return true;
    }

    bool IsComplete(uint32_t input_idx) const {
        auto it = partial_sigs_.find(input_idx);
        if (it == partial_sigs_.end()) return false;
        return it->second.size() >= required_;
    }

    uint32_t Required()  const { return required_; }
    uint32_t Total()     const { return (uint32_t)pubkeys_.size(); }
    const std::vector<uint8_t>& RedeemScript() const { return redeem_script_; }

private:
    uint32_t required_;
    std::vector<Secp256k1PubKey> pubkeys_;
    std::vector<uint8_t> redeem_script_;

    struct PartialSig {
        Secp256k1PubKey pubkey;
        Secp256k1SigDER sig;
    };
    std::unordered_map<uint32_t, std::vector<PartialSig>> partial_sigs_;

    std::vector<uint8_t> BuildRedeemScript() const {
        std::vector<uint8_t> script;
        script.push_back(0x50 + (uint8_t)required_);
        for (const auto& pk : pubkeys_) {
            script.push_back(0x4D);
            script.push_back((uint8_t)(pk.size() & 0xFF));
            script.push_back((uint8_t)((pk.size() >> 8) & 0xFF));
            script.insert(script.end(), pk.begin(), pk.end());
        }
        script.push_back(0x50 + (uint8_t)pubkeys_.size());
        script.push_back(0xAE);
        return script;
    }
};

inline std::string CreateMultiSigAddress(
    uint32_t required,
    const std::vector<std::string>& pubkey_hexes,
    bool testnet = false)
{
    std::vector<Secp256k1PubKey> pubkeys;
    for (const auto& hex : pubkey_hexes) {
        if (hex.size() != 3904)
            throw std::invalid_argument("Pubkey must be 1952 bytes (3904 hex chars, ML-DSA-65)");
        Secp256k1PubKey pk;
        for (int i = 0; i < 1952; ++i) {
            auto hc = [](char c) -> uint8_t {
                if (c>='0'&&c<='9') return c-'0';
                if (c>='a'&&c<='f') return c-'a'+10;
                return c-'A'+10;
            };
            pk[i] = (hc(hex[i*2])<<4)|hc(hex[i*2+1]);
        }
        pubkeys.push_back(pk);
    }
    MultiSig ms(required, pubkeys);
    return ms.GetAddress(testnet);
}

}
