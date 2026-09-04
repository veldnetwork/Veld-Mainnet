#pragma once

#include "../compat/platform.h"
#include "../core/hash.h"
#include "../core/transaction.h"
#include "../crypto/ripemd160.h"
#include "../crypto/dilithium.h"
#include <array>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <cstring>
#include <mutex>

extern "C" {
int veld_mldsa65_keypair_from_seed(const uint8_t seed[32], uint8_t* pk, uint8_t* sk);
}

namespace veld {

using Secp256k1PrivKey = std::array<uint8_t, 32>;
using Secp256k1PubKey = std::array<uint8_t, 1952>;
using Secp256k1SigDER = std::vector<uint8_t>;

namespace key_entropy {

inline bool CandidateLooksSane(const Secp256k1PrivKey& candidate) noexcept {
    std::array<bool, 256> seen{};
    size_t distinct = 0;
    for (const uint8_t byte : candidate) {
        if (!seen[byte]) {
            seen[byte] = true;
            ++distinct;
        }
    }
    return distinct >= 16;
}

inline bool SamplesLookIndependent(const Secp256k1PrivKey& probe,
                                   const Secp256k1PrivKey& candidate) noexcept {
    return CandidateLooksSane(probe) && CandidateLooksSane(candidate) &&
           !veld::compat::ConstantTimeEqual(probe.data(), candidate.data(), candidate.size());
}

inline bool AcceptFreshCandidate(const Secp256k1PrivKey& candidate) {
    SHA256 hash;
    static constexpr char domain[] = "VELD key entropy fingerprint v1";
    hash.update(reinterpret_cast<const uint8_t*>(domain), sizeof(domain) - 1);
    hash.update(candidate.data(), candidate.size());
    const Hash256 fingerprint = hash.digest();

    static std::mutex mutex;
    static Hash256 previous{};
    static bool have_previous = false;
    std::lock_guard<std::mutex> lock(mutex);
    if (have_previous &&
        veld::compat::ConstantTimeEqual(previous.data(), fingerprint.data(), fingerprint.size()))
        return false;
    previous = fingerprint;
    have_previous = true;
    return true;
}

} // namespace key_entropy

inline Secp256k1PrivKey GeneratePrivateKey() {
    Secp256k1PrivKey probe{};
    Secp256k1PrivKey key{};
    const bool probe_ok = veld::compat::SecureRandom(probe.data(), probe.size());
    const bool key_ok = veld::compat::SecureRandom(key.data(), key.size());
    if (!probe_ok || !key_ok || !key_entropy::SamplesLookIndependent(probe, key) ||
        !key_entropy::AcceptFreshCandidate(key)) {
        veld::compat::SecureZero(probe.data(), probe.size());
        veld::compat::SecureZero(key.data(), key.size());
        throw std::runtime_error(
            "operating-system CSPRNG health check failed; key generation stopped");
    }
    veld::compat::SecureZero(probe.data(), probe.size());
    return key;
}

inline Secp256k1PubKey DerivePublicKey(const Secp256k1PrivKey& privkey) {
    Secp256k1PubKey pk{};
    std::array<uint8_t, veld::dilithium::SECKEY_BYTES> sk_tmp{};
    // Touch the temporary secret buffer before locking it so the backing pages
    // are committed before mlock/VirtualLock pins them.
    // SecureZero performs a non-elidable write before the memory lock, ensuring
    // the lock covers the pages that will hold the derived secret key.
    veld::compat::SecureZero(sk_tmp.data(), sk_tmp.size());
    veld::compat::SecureLockMemory(sk_tmp.data(), sk_tmp.size());
    int rc = veld_mldsa65_keypair_from_seed(privkey.data(), pk.data(), sk_tmp.data());
    veld::compat::SecureZero(sk_tmp.data(), sk_tmp.size());
    veld::compat::SecureUnlockMemory(sk_tmp.data(), sk_tmp.size());
    if (rc != 0)
        throw std::runtime_error("ML-DSA-65 seed-keygen failed");
    return pk;
}

inline Secp256k1SigDER Sign(const Secp256k1PrivKey& privkey, const Hash256& hash) {
    Secp256k1PubKey pk_unused{};
    std::array<uint8_t, veld::dilithium::SECKEY_BYTES> sk_tmp{};
    veld::compat::SecureZero(sk_tmp.data(), sk_tmp.size());
    veld::compat::SecureLockMemory(sk_tmp.data(), sk_tmp.size());
    if (veld_mldsa65_keypair_from_seed(privkey.data(), pk_unused.data(), sk_tmp.data()) != 0) {
        veld::compat::SecureZero(sk_tmp.data(), sk_tmp.size());
        veld::compat::SecureUnlockMemory(sk_tmp.data(), sk_tmp.size());
        throw std::runtime_error("ML-DSA-65 seed-keygen failed");
    }
    Secp256k1SigDER sig(veld::dilithium::SIG_MAX_BYTES, 0);
    size_t siglen = 0;
    int rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig.data(), &siglen, hash.data(),
                                                         hash.size(), sk_tmp.data());
    veld::compat::SecureZero(sk_tmp.data(), sk_tmp.size());
    veld::compat::SecureUnlockMemory(sk_tmp.data(), sk_tmp.size());
    if (rc != 0)
        throw std::runtime_error("ML-DSA-65 sign failed");
    sig.resize(siglen);
    return sig;
}

inline bool Verify(const Secp256k1PubKey& pub, const Hash256& hash,
                   const Secp256k1SigDER& der_sig) {
    (void)PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify;
    if (der_sig.empty() || der_sig.size() > veld::dilithium::SIG_MAX_BYTES)
        return false;
    int rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(der_sig.data(), der_sig.size(), hash.data(),
                                                      hash.size(), pub.data());
    return rc == 0;
}

// ─────────────────────────────────────────────
//  SIGHASH (SIGHASH_ALL)
// ─────────────────────────────────────────────
// (transaction.h is included at the TOP of this file, outside the namespace.)

constexpr uint8_t SCHEME_ID_MLDSA65 = 0x01;

inline Hash256 ComputeSighash(const Transaction& tx, uint32_t input_index,
                              const std::vector<uint8_t>& subscript,
                              uint8_t scheme_id = SCHEME_ID_MLDSA65) {
    std::vector<uint8_t> pre;
    auto push_le32 = [&](uint32_t v) {
        pre.push_back(v & 0xFF);
        pre.push_back((v >> 8) & 0xFF);
        pre.push_back((v >> 16) & 0xFF);
        pre.push_back((v >> 24) & 0xFF);
    };
    auto push_varint = [&](uint64_t v) {
        if (v < 0xFD) {
            pre.push_back((uint8_t)v);
        } else if (v <= 0xFFFF) {
            pre.push_back(0xFD);
            pre.push_back((uint8_t)(v & 0xFF));
            pre.push_back((uint8_t)((v >> 8) & 0xFF));
        } else if (v <= 0xFFFFFFFFULL) {
            pre.push_back(0xFE);
            for (int i = 0; i < 4; ++i)
                pre.push_back((uint8_t)((v >> (i * 8)) & 0xFF));
        } else {
            pre.push_back(0xFF);
            for (int i = 0; i < 8; ++i)
                pre.push_back((uint8_t)((v >> (i * 8)) & 0xFF));
        }
    };
    //  (cross-chain replay defence):
    // Prepend a chain-id domain-separation tag + the current
    // GENESIS_HASH (from constants.h) to the sighash preimage. A
    // signed transaction is now only valid on the chain whose
    // genesis hash matches — after any future chain reset, old TXs
    // cannot be replayed on the new chain even if an attacker
    // reconstructs matching UTXO references. The tag "VELD_SIG\x01"
    // (8 bytes) ensures any future sighash format change (e.g. a new
    // tag byte) produces an entirely distinct preimage space; any
    // two schemes cannot collide.
    static const uint8_t kSighashTag[8] = {'V', 'E', 'L', 'D', '_', 'S', 'I', 'G'};
    pre.insert(pre.end(), kSighashTag, kSighashTag + 8);
    pre.push_back(0x03); // sighash format version.
                         //   v1 ( 12th bump): chain-id-binding only
                         //   v2: + signature scheme_id
                         //   v3: + network-id byte
                         //                              (mainnet vs testnet)
                         // The VIII-byte tag + version byte guarantee that
                         // every version's preimage space is disjoint, so no
                         // cross-version replay is possible. Bump this byte
                         // on every future sighash layout change.
    // Bind signatures to the network explicitly. Genesis header bytes can be
    // identical across proof-of-work profiles, so the genesis hash alone is
    // not a sufficient network discriminator. 0x4D identifies mainnet and
    // 0x54 identifies testnet.
#ifdef VELD_MAINNET_POW
    pre.push_back(0x4D);
#else
    pre.push_back(0x54);
#endif
    for (const char* p = GENESIS_HASH; *p; ++p)
        pre.push_back((uint8_t)*p);
    pre.push_back(scheme_id);

    push_le32(tx.version);
    push_varint((uint64_t)tx.inputs.size());
    for (uint32_t i = 0; i < tx.inputs.size(); ++i) {
        const auto& inp = tx.inputs[i];
        pre.insert(pre.end(), inp.prev_tx_hash.begin(), inp.prev_tx_hash.end());
        push_le32(inp.prev_out_index);
        if (i == input_index) {
            push_varint((uint64_t)subscript.size());
            pre.insert(pre.end(), subscript.begin(), subscript.end());
        } else {
            push_varint(0);
        }
        push_le32(inp.sequence);
    }
    push_varint((uint64_t)tx.outputs.size());
    for (const auto& out : tx.outputs) {
        for (int i = 0; i < 8; ++i)
            pre.push_back((out.value >> (i * 8)) & 0xFF);
        push_varint((uint64_t)out.script_pubkey.size());
        pre.insert(pre.end(), out.script_pubkey.begin(), out.script_pubkey.end());
    }
    push_le32(tx.locktime);
    push_le32(0x00000001);
    return Hash256d(pre);
}

struct SignedInput {
    std::vector<uint8_t> script_sig;
};

inline SignedInput BuildScriptSig(const Secp256k1PrivKey& priv, const Secp256k1PubKey& pub,
                                  const Transaction& tx, uint32_t input_index,
                                  const std::vector<uint8_t>& prev_script) {
    constexpr uint8_t scheme_id = SCHEME_ID_MLDSA65;

    Hash256 sighash = ComputeSighash(tx, input_index, prev_script, scheme_id);
    Secp256k1SigDER raw_sig = Sign(priv, sighash);

    std::vector<uint8_t> sig;
    sig.reserve(raw_sig.size() + 2);
    sig.push_back(scheme_id);
    sig.insert(sig.end(), raw_sig.begin(), raw_sig.end());
    sig.push_back(0x01);

    auto push_pushdata2 = [](std::vector<uint8_t>& out, const uint8_t* data, size_t n) {
        out.push_back(0x4D);
        out.push_back((uint8_t)(n & 0xFF));
        out.push_back((uint8_t)((n >> 8) & 0xFF));
        out.insert(out.end(), data, data + n);
    };

    SignedInput si;
    push_pushdata2(si.script_sig, sig.data(), sig.size());
    push_pushdata2(si.script_sig, pub.data(), pub.size());
    return si;
}

struct RealKeyPair {
    Secp256k1PrivKey private_key;
    Secp256k1PubKey public_key;
    std::string address;
    bool testnet = false;
    std::vector<uint8_t> script_override;

    RealKeyPair() {
        veld::compat::SecureLockMemory(private_key.data(), private_key.size());
    }
    RealKeyPair(const RealKeyPair& o)
        : private_key(o.private_key), public_key(o.public_key), address(o.address),
          testnet(o.testnet), script_override(o.script_override) {
        veld::compat::SecureLockMemory(private_key.data(), private_key.size());
    }
    RealKeyPair(RealKeyPair&& o) noexcept
        : private_key(o.private_key), public_key(std::move(o.public_key)),
          address(std::move(o.address)), testnet(o.testnet),
          script_override(std::move(o.script_override)) {
        veld::compat::SecureLockMemory(private_key.data(), private_key.size());
        veld::compat::SecureZero(o.private_key.data(), o.private_key.size());
        veld::compat::SecureUnlockMemory(o.private_key.data(), o.private_key.size());
    }
    RealKeyPair& operator=(const RealKeyPair& o) {
        if (this != &o) {
            veld::compat::SecureZero(private_key.data(), private_key.size());
            private_key = o.private_key;
            public_key = o.public_key;
            address = o.address;
            testnet = o.testnet;
            script_override = o.script_override;
        }
        return *this;
    }
    RealKeyPair& operator=(RealKeyPair&& o) noexcept {
        if (this != &o) {
            veld::compat::SecureZero(private_key.data(), private_key.size());
            private_key = o.private_key;
            public_key = std::move(o.public_key);
            address = std::move(o.address);
            testnet = o.testnet;
            script_override = std::move(o.script_override);
            veld::compat::SecureZero(o.private_key.data(), o.private_key.size());
        }
        return *this;
    }

    ~RealKeyPair() {
        veld::compat::SecureZero(private_key.data(), private_key.size());
        veld::compat::SecureUnlockMemory(private_key.data(), private_key.size());
    }

    std::vector<uint8_t> GetP2PKHScript() const {
        if (!script_override.empty())
            return script_override;
        Hash160 h = Hash160Compute(public_key);
        std::vector<uint8_t> s;
        s.push_back(0x76);
        s.push_back(0xA9);
        s.push_back(0x14);
        s.insert(s.end(), h.begin(), h.end());
        s.push_back(0x88);
        s.push_back(0xAC);
        return s;
    }

    SignedInput SignInput(const Transaction& tx, uint32_t idx,
                          const std::vector<uint8_t>& prev_script) const {
        return BuildScriptSig(private_key, public_key, tx, idx, prev_script);
    }
};

inline RealKeyPair GenerateKeyPair(bool testnet = false) {
    RealKeyPair kp;
    kp.testnet = testnet;
    kp.private_key = GeneratePrivateKey();
    kp.public_key = DerivePublicKey(kp.private_key);

    Hash160 h = Hash160Compute(kp.public_key);
    uint8_t ver = testnet ? 0x6F : 0x46;
    std::vector<uint8_t> data = {ver};
    data.insert(data.end(), h.begin(), h.end());
    Hash256 chk = Hash256d(data);
    data.push_back(chk[0]);
    data.push_back(chk[1]);
    data.push_back(chk[2]);
    data.push_back(chk[3]);

    static const char* B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    int lead = 0;
    for (auto b : data) {
        if (b == 0)
            ++lead;
        else
            break;
    }
    std::vector<uint8_t> digits = {0};
    for (auto byte : data) {
        int carry = byte;
        for (auto& d : digits) {
            carry += 256 * d;
            d = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            digits.push_back(carry % 58);
            carry /= 58;
        }
    }
    kp.address = std::string(lead, '1');
    for (auto it = digits.rbegin(); it != digits.rend(); ++it)
        kp.address += B58[*it];
    return kp;
}

} // namespace veld
