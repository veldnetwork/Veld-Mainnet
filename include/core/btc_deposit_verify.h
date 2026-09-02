#pragma once
// btcVELD SPV deposit verification and mint gate.
//
// Given a MINT_SPV op (an SPV proof of a Bitcoin deposit) and the in-consensus
// BtcHeaderChain, decide — with NO issuer signature and NO in-consensus EC math —
// whether to credit btcVELD, and to WHOM and HOW MUCH. The recipient and amount
// are read from the PROVEN deposit tx (an OP_RETURN "btcVELD:<addr>" output + the
// value paid to the canonical custody scriptPubKey), never from the op submitter,
// so a real deposit can only be minted to the address its depositor committed on
// Bitcoin — front-running is worthless.
//
// an invalid acceptance could credit an unbacked mint. Fail closed everywhere.
// The commitment binds the Bitcoin output to the intended Veld recipient so a
// relayer cannot redirect a valid deposit proof.

#include "core/btc_header_chain.h"
#include "consensus/btcveld_mint_nullifier.h"
#include <string>
#include <functional>
#include <algorithm>

namespace veld {
namespace btcspv {

// ── minimal Bitcoin CompactSize (varint) reader — bounds-checked ──
inline bool ReadVarint(const uint8_t* p, size_t len, size_t& off, uint64_t& out) {
    if (off >= len) return false;
    uint8_t c = p[off++];
    if (c < 0xfd) { out = c; return true; }
    int n = (c == 0xfd) ? 2 : (c == 0xfe) ? 4 : 8;
    if (off + (size_t)n > len) return false;
    uint64_t v = 0;
    for (int i = 0; i < n; ++i) v |= (uint64_t)p[off++] << (8 * i);
    out = v;
    return true;
}

struct BtcTxOut { uint64_t value = 0; std::vector<uint8_t> spk; };

// Parse a Bitcoin tx in its LEGACY (non-witness) serialization and return its
// outputs. Rejects (returns false, no partial state) on ANY malformation — incl.
// a segwit marker (vin_count byte == 0x00 → 0 inputs → reject) and any trailing
// bytes after locktime (strict). Never parses witnesses.
inline bool ParseBtcTxOutputs(const uint8_t* p, size_t len, std::vector<BtcTxOut>& outs) {
    outs.clear();
    size_t off = 0;
    if (len < 4 + 1 + 1 + 4) return false;        // version + min vin/vout + locktime
    off += 4;                                     // version
    uint64_t vin = 0;
    if (!ReadVarint(p, len, off, vin)) return false;
    if (vin == 0 || vin > 100000) return false;   // 0 == segwit-marker / non-standard
    for (uint64_t i = 0; i < vin; ++i) {
        if (off + 36 > len) return false;
        off += 36;                                      // prevout
        uint64_t sl = 0;
        if (!ReadVarint(p, len, off, sl)) return false;
        if (sl > len || off + sl + 4 > len) return false;
        off += sl + 4;                                  // scriptSig + sequence
    }
    uint64_t vout = 0;
    if (!ReadVarint(p, len, off, vout)) return false;
    if (vout == 0 || vout > 100000) return false;
    for (uint64_t i = 0; i < vout; ++i) {
        if (off + 8 > len) return false;
        uint64_t val = 0;
        for (int b = 0; b < 8; ++b)
            val |= (uint64_t)p[off + b] << (8 * b);
        off += 8;
        uint64_t sl = 0;
        if (!ReadVarint(p, len, off, sl)) return false;
        if (sl > len || off + sl > len) return false;
        BtcTxOut o;
        o.value = val;
        o.spk.assign(p + off, p + off + sl);
        off += sl;
        outs.push_back(std::move(o));
    }
    if (off + 4 != len) return false;             // locktime — and NOTHING after (rejects witness tails)
    return true;
}

// Parse the prevout (txid, vout) of input `vin_index` of a LEGACY tx. Returns
// false on malformation or out-of-range index. `out_txid` is in internal (LE)
// serialization order — the same order as Hash256d(funding_tx), so the two compare
// directly. Used by the fraudulent-spend proof to show an input spent custody.
inline bool ParseBtcTxInputPrevout(const uint8_t* p, size_t len, uint32_t vin_index,
                                   std::array<uint8_t,32>& out_txid, uint32_t& out_vout) {
    size_t off = 0;
    if (len < 4 + 1) return false;
    off += 4;                                         // version
    uint64_t vin = 0;
    if (!ReadVarint(p, len, off, vin)) return false;
    if (vin == 0 || vin > 100000 || vin_index >= vin) return false;
    for (uint64_t i = 0; i < vin; ++i) {
        if (off + 36 > len) return false;
        if (i == vin_index) {
            std::memcpy(out_txid.data(), p + off, 32);
            out_vout = rd_le32(p + off + 32);
            return true;
        }
        off += 36;                                    // prevout
        uint64_t sl = 0; if (!ReadVarint(p, len, off, sl)) return false;
        if (sl > len || off + sl + 4 > len) return false;
        off += sl + 4;                                // scriptSig + sequence
    }
    return false;
}

struct BtcPrevout { H256 txid{}; uint32_t vout = 0; };

// Strict Bitcoin transaction view for the fresh rolling-reserve protocol.
// The historical MSPV/PSPV parsers above intentionally remain legacy-only;
// reserve-v1 must additionally understand the canonical marker/flag/witness
// serialization because the custody output itself is P2WPKH.  `txid` is always
// the Bitcoin transaction ID: for a witness transaction it hashes the stripped
// version|vin|vout|locktime serialization, never the witness-inclusive wtxid.
struct WitnessAwareBtcTx {
    H256 txid{};
    bool has_witness = false;
    std::vector<BtcPrevout> prevouts;
    std::vector<BtcTxOut> outputs;
};

inline bool ReadCanonicalVarint(const uint8_t* p, size_t len, size_t& off,
                                uint64_t& out) {
    if (p == nullptr || off >= len) return false;
    const uint8_t prefix = p[off];
    if (!ReadVarint(p, len, off, out)) return false;
    if ((prefix == 0xfd && out < 0xfd) ||
        (prefix == 0xfe && out <= 0xffffULL) ||
        (prefix == 0xff && out <= 0xffffffffULL))
        return false;
    return true;
}

inline bool ParseWitnessAwareBtcTx(
        const uint8_t* p, size_t len, WitnessAwareBtcTx& parsed,
        size_t max_inputs = 100000,
        size_t max_outputs = 100000) {
    parsed = WitnessAwareBtcTx{};
    if (p == nullptr || len < 4 + 1 + 1 + 4 ||
        max_inputs == 0 || max_outputs == 0)
        return false;

    size_t off = 4;
    bool witness = false;
    if (p[off] == 0x00) {
        // Bitcoin Core's transaction decoder rejects unknown optional-data
        // flags and a marker/flag record with no actual witness stacks.
        if (off + 2 > len || p[off + 1] != 0x01) return false;
        witness = true;
        off += 2;
    }
    const size_t vin_start = off;
    uint64_t vin = 0;
    if (!ReadCanonicalVarint(p, len, off, vin) || vin == 0 ||
        vin > max_inputs)
        return false;
    parsed.prevouts.reserve(static_cast<size_t>(vin));
    for (uint64_t i = 0; i < vin; ++i) {
        if (off + 36 > len) return false;
        BtcPrevout prev;
        std::memcpy(prev.txid.data(), p + off, 32);
        prev.vout = rd_le32(p + off + 32);
        off += 36;
        uint64_t script_len = 0;
        if (!ReadCanonicalVarint(p, len, off, script_len) ||
            script_len > len - off || len - off - script_len < 4)
            return false;
        off += static_cast<size_t>(script_len) + 4; // scriptSig + sequence
        parsed.prevouts.push_back(prev);
    }

    uint64_t vout = 0;
    if (!ReadCanonicalVarint(p, len, off, vout) || vout == 0 ||
        vout > max_outputs)
        return false;
    parsed.outputs.reserve(static_cast<size_t>(vout));
    for (uint64_t i = 0; i < vout; ++i) {
        if (off + 8 > len) return false;
        uint64_t value = 0;
        for (unsigned b = 0; b < 8; ++b)
            value |= static_cast<uint64_t>(p[off + b]) << (8 * b);
        off += 8;
        uint64_t script_len = 0;
        if (!ReadCanonicalVarint(p, len, off, script_len) ||
            script_len > len - off)
            return false;
        BtcTxOut output;
        output.value = value;
        output.spk.assign(p + off, p + off + static_cast<size_t>(script_len));
        off += static_cast<size_t>(script_len);
        parsed.outputs.push_back(std::move(output));
    }
    const size_t vin_vout_end = off;

    if (witness) {
        bool has_witness_stack = false;
        for (uint64_t i = 0; i < vin; ++i) {
            uint64_t item_count = 0;
            if (!ReadCanonicalVarint(p, len, off, item_count) ||
                item_count > 100000)
                return false;
            if (item_count != 0) has_witness_stack = true;
            for (uint64_t item = 0; item < item_count; ++item) {
                uint64_t item_len = 0;
                if (!ReadCanonicalVarint(p, len, off, item_len) ||
                    item_len > len - off)
                    return false;
                off += static_cast<size_t>(item_len);
            }
        }
        if (!has_witness_stack) return false;
    }
    if (off > len || len - off != 4) return false;

    parsed.has_witness = witness;
    if (!witness) {
        parsed.txid = ::veld::Hash256d(p, len);
        return true;
    }
    std::vector<uint8_t> stripped;
    stripped.reserve(4 + (vin_vout_end - vin_start) + 4);
    stripped.insert(stripped.end(), p, p + 4);
    stripped.insert(stripped.end(), p + vin_start, p + vin_vout_end);
    stripped.insert(stripped.end(), p + off, p + off + 4);
    parsed.txid = ::veld::Hash256d(stripped);
    return true;
}

inline bool ParseWitnessAwareBtcTx(
        const std::vector<uint8_t>& tx, WitnessAwareBtcTx& parsed,
        size_t max_inputs = 100000,
        size_t max_outputs = 100000) {
    return ParseWitnessAwareBtcTx(
        tx.data(), tx.size(), parsed, max_inputs, max_outputs);
}

inline bool ParseBtcTxPrevouts(const uint8_t* p, size_t len,
                               std::vector<BtcPrevout>& prevouts) {
    prevouts.clear();
    size_t off = 0;
    if (p == nullptr || len < 5) return false;
    off += 4;
    uint64_t vin = 0;
    if (!ReadVarint(p, len, off, vin) || vin == 0 ||
        vin > btcnull::MAX_MSPV_PARENT_COUNT) return false;
    prevouts.reserve(static_cast<size_t>(vin));
    for (uint64_t i = 0; i < vin; ++i) {
        if (off + 36 > len) return false;
        BtcPrevout prev;
        std::memcpy(prev.txid.data(), p + off, 32);
        prev.vout = rd_le32(p + off + 32);
        off += 36;
        if (HashIsZero(prev.txid) && prev.vout == UINT32_MAX) return false;
        uint64_t script_len = 0;
        if (!ReadVarint(p, len, off, script_len) ||
            script_len > len || off + script_len + 4 > len) return false;
        off += static_cast<size_t>(script_len) + 4;
        prevouts.push_back(prev);
    }
    return true;
}

// extract the pushed data of an OP_RETURN scriptPubKey (0x6a <push> data); {} otherwise
inline std::vector<uint8_t> ExtractOpReturn(const std::vector<uint8_t>& spk) {
    if (spk.size() < 2 || spk[0] != 0x6a) return {};
    size_t i, dlen;
    if (spk[1] < 0x4c)      { dlen = spk[1]; i = 2; }
    else if (spk[1] == 0x4c){ if (spk.size() < 3) return {}; dlen = spk[2]; i = 3; }
    else if (spk[1] == 0x4d){ if (spk.size() < 4) return {}; dlen = (size_t)spk[2] | ((size_t)spk[3] << 8); i = 4; }
    else return {};
    if (i + dlen > spk.size()) return {};
    return std::vector<uint8_t>(spk.begin() + i, spk.begin() + i + dlen);
}

struct DepositResult {
    bool        ok = false;
    std::string reason;       // diagnostic on reject
    std::string recipient;    // VELD address (from the deposit's OP_RETURN)
    uint64_t    amount = 0;   // sats paid to custody
    H256        deposit_key{};// proven txid (internal/wire byte order)
    uint32_t    deposit_vout = 0; // exact, uniquely-matched custody output
    std::string outpoint_id;  // canonical bitcoind-display "txid:vout"
    btcnull::Proof nullifier_proof; // MNP1 proof shared with issuer mints
    uint64_t custody_input_amount = 0;
    uint64_t custody_output_amount = 0;
};

struct C1FundingResult {
    bool ok = false;
    std::string reason;
    std::string outpoint_id;
    btcnull::Proof nullifier_proof;
};

// Hash256d() is kept in Bitcoin's internal/wire byte order throughout the SPV
// relay. Issuer mints receive bitcoind's display-order txid in their memo, so
// cross-path replay protection must reverse the digest before constructing the
// one canonical outpoint identity shared by both mint paths.
inline std::string BtcDisplayTxid(const H256& internal_txid) {
    static constexpr char HEX[] = "0123456789abcdef";
    std::string out(64, '0');
    for (size_t i = 0; i < internal_txid.size(); ++i) {
        const uint8_t b = internal_txid[internal_txid.size() - 1 - i];
        out[i * 2]     = HEX[(b >> 4) & 0x0f];
        out[i * 2 + 1] = HEX[b & 0x0f];
    }
    return out;
}

inline std::string BtcDepositOutpointId(const H256& internal_txid,
                                        uint32_t vout) {
    return BtcDisplayTxid(internal_txid) + ":" + std::to_string(vout);
}

// Canonical C1 funding proof. Public CFP2 appends one hash-bound direct parent
// per input before the nullifier witness; non-public historical fixtures retain
// CFP1 behind the custody-lineage profile gate.
inline bool ParseC1FundingProof(const uint8_t* p, size_t len,
                                H256& block_hash, uint64_t& dirs,
                                std::vector<H256>& branch,
                                std::vector<uint8_t>& legacy_tx,
                                std::vector<std::vector<uint8_t>>& parent_txs,
                                btcnull::Proof& nullifier_proof) {
    block_hash = H256{};
    dirs = 0;
    branch.clear();
    legacy_tx.clear();
    parent_txs.clear();
    nullifier_proof = btcnull::Proof{};
    if (p == nullptr || len < 4 + 32 + 4 + 1 + 4 + 10 ||
        p[0] != 'C' || p[1] != 'F' || p[2] != 'P' ||
        p[3] != (btcnull::CUSTODY_LINEAGE_REQUIRED ? '2' : '1'))
        return false;
    size_t off = 4;
    std::memcpy(block_hash.data(), p + off, 32); off += 32;
    dirs = rd_le32(p + off); off += 4;
    const uint8_t mlen = p[off++];
    if (mlen > 32 || (mlen < 32 && (dirs >> mlen) != 0) ||
        off + static_cast<size_t>(mlen) * 32 + 4 > len)
        return false;
    for (uint8_t i = 0; i < mlen; ++i) {
        H256 h{};
        std::memcpy(h.data(), p + off, 32);
        off += 32;
        branch.push_back(h);
    }
    const uint32_t tx_len = rd_le32(p + off); off += 4;
    if (tx_len < 10 || tx_len > 8000 || off + tx_len > len)
        return false;
    legacy_tx.assign(p + off, p + off + tx_len);
    off += tx_len;
    if (btcnull::CUSTODY_LINEAGE_REQUIRED) {
        if (off + 2 > len) return false;
        const uint16_t parent_count = static_cast<uint16_t>(p[off]) |
            (static_cast<uint16_t>(p[off + 1]) << 8);
        off += 2;
        if (parent_count == 0 ||
            parent_count > btcnull::MAX_MSPV_PARENT_COUNT) return false;
        size_t parent_total = 0;
        parent_txs.reserve(parent_count);
        for (uint16_t i = 0; i < parent_count; ++i) {
            if (off + 4 > len) return false;
            const uint32_t parent_len = rd_le32(p + off);
            off += 4;
            if (parent_len < 10 ||
                parent_len > btcnull::MAX_MSPV_PARENT_TX_BYTES ||
                parent_total > btcnull::MAX_MSPV_PARENT_TOTAL_BYTES - parent_len ||
                off + parent_len > len) return false;
            parent_txs.emplace_back(p + off, p + off + parent_len);
            off += parent_len;
            parent_total += parent_len;
        }
    }
    const size_t proof_len = len - off;
    return proof_len >= btcnull::MIN_PROOF_BYTES &&
           proof_len <= btcnull::MAX_PROOF_BYTES &&
           btcnull::DecodeProof(p + off, proof_len, nullifier_proof);
}

inline bool ParseC1FundingProof(const uint8_t* p, size_t len,
                                H256& block_hash, uint64_t& dirs,
                                std::vector<H256>& branch,
                                std::vector<uint8_t>& legacy_tx,
                                btcnull::Proof& nullifier_proof) {
    std::vector<std::vector<uint8_t>> parents;
    return ParseC1FundingProof(p, len, block_hash, dirs, branch, legacy_tx,
                               parents, nullifier_proof);
}

inline C1FundingResult VerifyC1Funding(
        const BtcHeaderChain& chain, const uint8_t* payload, size_t len,
        const std::vector<uint8_t>& exact_script, uint64_t exact_amount,
        const std::string& exact_outpoint, uint32_t k_btc) {
    C1FundingResult result;
    if (exact_script.empty() || exact_amount == 0) {
        result.reason = "empty script or zero amount";
        return result;
    }
    H256 block_hash{};
    uint64_t dirs = 0;
    std::vector<H256> branch;
    std::vector<uint8_t> tx;
    std::vector<std::vector<uint8_t>> parent_txs;
    btcnull::Proof nullifier_proof;
    if (!ParseC1FundingProof(payload, len, block_hash, dirs, branch, tx,
                             parent_txs, nullifier_proof)) {
        result.reason = btcnull::CUSTODY_LINEAGE_REQUIRED
            ? "malformed CFP2" : "malformed CFP1";
        return result;
    }
    if (tx.size() <= 64) {
        result.reason = "funding tx is merkle-ambiguous";
        return result;
    }
    const H256 txid = ::veld::Hash256d(tx);
    if (!chain.VerifyMerkle(block_hash, txid, branch, dirs) ||
        !chain.IsFinalForExternalValue(block_hash, k_btc)) {
        result.reason = "funding proof is not validator-observed final on best chain";
        return result;
    }
    std::vector<BtcTxOut> outputs;
    if (!ParseBtcTxOutputs(tx.data(), tx.size(), outputs)) {
        result.reason = "funding tx is not canonical legacy serialization";
        return result;
    }
    uint64_t custody_inputs = 0;
    if (btcnull::CUSTODY_LINEAGE_REQUIRED) {
        std::vector<BtcPrevout> prevouts;
        if (!ParseBtcTxPrevouts(tx.data(), tx.size(), prevouts) ||
            prevouts.size() != parent_txs.size()) {
            result.reason = "funding input lineage is incomplete";
            return result;
        }
        for (size_t i = 0; i < prevouts.size(); ++i) {
            if (::veld::Hash256d(parent_txs[i]) != prevouts[i].txid) {
                result.reason = "funding lineage parent hash mismatch";
                return result;
            }
            std::vector<BtcTxOut> parent_outputs;
            if (!ParseBtcTxOutputs(parent_txs[i].data(), parent_txs[i].size(),
                                   parent_outputs) ||
                prevouts[i].vout >= parent_outputs.size()) {
                result.reason = "funding lineage parent output invalid";
                return result;
            }
            const BtcTxOut& input = parent_outputs[prevouts[i].vout];
            if (input.spk == exact_script) {
                if (custody_inputs > UINT64_MAX - input.value) {
                    result.reason = "funding custody input overflow";
                    return result;
                }
                custody_inputs += input.value;
            }
        }
    }
    size_t matches = 0;
    uint32_t matched_vout = 0;
    uint64_t matched_value = 0;
    for (size_t i = 0; i < outputs.size(); ++i) {
        if (outputs[i].spk == exact_script &&
            (btcnull::CUSTODY_LINEAGE_REQUIRED ||
             outputs[i].value == exact_amount)) {
            ++matches;
            matched_vout = static_cast<uint32_t>(i);
            matched_value = outputs[i].value;
        }
    }
    if (matches != 1) {
        result.reason = "funding tx lacks one exact script/amount output";
        return result;
    }
    if (btcnull::CUSTODY_LINEAGE_REQUIRED &&
        (matched_value <= custody_inputs ||
         matched_value - custody_inputs != exact_amount)) {
        result.reason = "funding does not add the exact net-new allocation";
        return result;
    }
    result.outpoint_id = BtcDepositOutpointId(txid, matched_vout);
    if (result.outpoint_id != exact_outpoint) {
        result.reason = "funding outpoint differs from proven transaction";
        result.outpoint_id.clear();
        return result;
    }
    result.ok = true;
    result.nullifier_proof = std::move(nullifier_proof);
    return result;
}

// Fresh-genesis MINT_SPV payload v3:
//   "MSP3" | block_hash(32) | merkle_dirs(u32 le) | merkle_len(u8)
//          | len×branch(32) | legacy_tx_len(u32 le) | legacy_deposit_tx
//          | parent_count(u16 le)
//          | parent_count × (parent_len(u32 le) | legacy_parent_tx)
//          | canonical MNP1 compressed nonmembership proof
//
// Every direct input parent is supplied in input order.  Its raw hash must equal
// the child prevout, so consensus can distinguish external BTC from custody
// change/consolidation without trusting an operator-supplied label.
inline bool ParseMintSpvOp(const uint8_t* p, size_t len, H256& block_hash,
                           uint64_t& dirs, std::vector<H256>& branch,
                           std::vector<uint8_t>& legacy_tx,
                           std::vector<std::vector<uint8_t>>& parent_txs,
                           btcnull::Proof& nullifier_proof) {
    block_hash = H256{};
    dirs = 0;
    branch.clear();
    legacy_tx.clear();
    parent_txs.clear();
    nullifier_proof = btcnull::Proof{};
    if (p == nullptr || len < 4 + 32 + 4 + 1 + 4 +
                            btcnull::MIN_PROOF_BYTES)
        return false;
    const uint8_t expected_version = btcnull::CUSTODY_LINEAGE_REQUIRED
        ? static_cast<uint8_t>('3') : static_cast<uint8_t>('2');
    if (p[0]!='M'||p[1]!='S'||p[2]!='P'||p[3]!=expected_version) return false;
    size_t off = 4;
    std::memcpy(block_hash.data(), p + off, 32); off += 32;
    dirs = rd_le32(p + off); off += 4;
    uint8_t mlen = p[off++];
    if (mlen > 32) return false;
    // Direction bits above the branch length are semantically unused.  They
    // must be zero so one inclusion proof has one consensus encoding.
    if (mlen < 32 && (dirs >> mlen) != 0) return false;
    if (off + (size_t)mlen * 32 + 4 > len) return false;
    for (int i = 0; i < mlen; ++i) { H256 h; std::memcpy(h.data(), p + off, 32); off += 32; branch.push_back(h); }
    const uint32_t tx_len = rd_le32(p + off); off += 4;
    if (tx_len == 0 || tx_len > btcnull::MAX_MSPV_STRIPPED_TX_BYTES ||
        off + (size_t)tx_len > len)
        return false;
    legacy_tx.assign(p + off, p + off + tx_len);
    off += tx_len;
    if (!btcnull::CUSTODY_LINEAGE_REQUIRED) {
        const size_t proof_len = len - off;
        return proof_len >= btcnull::MIN_PROOF_BYTES &&
               proof_len <= btcnull::MAX_PROOF_BYTES &&
               btcnull::DecodeProof(p + off, proof_len,
                                    nullifier_proof);
    }
    if (off + 2 > len) return false;
    const uint16_t parent_count = static_cast<uint16_t>(p[off]) |
        (static_cast<uint16_t>(p[off + 1]) << 8);
    off += 2;
    if (parent_count == 0 ||
        parent_count > btcnull::MAX_MSPV_PARENT_COUNT) return false;
    size_t parent_total = 0;
    parent_txs.reserve(parent_count);
    for (uint16_t i = 0; i < parent_count; ++i) {
        if (off + 4 > len) return false;
        const uint32_t parent_len = rd_le32(p + off);
        off += 4;
        if (parent_len < 10 ||
            parent_len > btcnull::MAX_MSPV_PARENT_TX_BYTES ||
            parent_total > btcnull::MAX_MSPV_PARENT_TOTAL_BYTES - parent_len ||
            off + parent_len > len) return false;
        parent_txs.emplace_back(p + off, p + off + parent_len);
        off += parent_len;
        parent_total += parent_len;
    }
    const size_t proof_len = len - off;
    if (proof_len < btcnull::MIN_PROOF_BYTES ||
        proof_len > btcnull::MAX_PROOF_BYTES) return false;
    return btcnull::DecodeProof(p + off, proof_len, nullifier_proof);
}

inline bool ParseMintSpvOp(const uint8_t* p, size_t len, H256& block_hash,
                           uint64_t& dirs, std::vector<H256>& branch,
                           std::vector<uint8_t>& legacy_tx,
                           btcnull::Proof& nullifier_proof) {
    std::vector<std::vector<uint8_t>> parents;
    return ParseMintSpvOp(p, len, block_hash, dirs, branch, legacy_tx,
                          parents, nullifier_proof);
}

// Read-only callers interested only in the deposit identity may omit the
// decoded witness, but they still parse the strict MSP3 format.
inline bool ParseMintSpvOp(const uint8_t* p, size_t len, H256& block_hash,
                           uint64_t& dirs, std::vector<H256>& branch,
                           std::vector<uint8_t>& legacy_tx) {
    btcnull::Proof ignored;
    return ParseMintSpvOp(p, len, block_hash, dirs, branch, legacy_tx, ignored);
}

struct CustodyLineageResult {
    bool ok = false;
    std::string reason;
    uint64_t custody_input_amount = 0;
};

inline CustodyLineageResult EvaluateCustodyInputLineage(
        const std::vector<uint8_t>& child_tx,
        const std::vector<std::vector<uint8_t>>& parent_txs,
        const std::vector<uint8_t>& custody_spk) {
    CustodyLineageResult result;
    if (custody_spk.empty()) {
        result.reason = "custody script unavailable";
        return result;
    }
    std::vector<BtcPrevout> prevouts;
    if (!ParseBtcTxPrevouts(child_tx.data(), child_tx.size(), prevouts) ||
        prevouts.size() != parent_txs.size()) {
        result.reason = "input lineage is incomplete";
        return result;
    }
    for (size_t i = 0; i < prevouts.size(); ++i) {
        if (::veld::Hash256d(parent_txs[i]) != prevouts[i].txid) {
            result.reason = "lineage parent hash mismatch";
            return result;
        }
        std::vector<BtcTxOut> parent_outputs;
        if (!ParseBtcTxOutputs(parent_txs[i].data(), parent_txs[i].size(),
                               parent_outputs) ||
            prevouts[i].vout >= parent_outputs.size()) {
            result.reason = "lineage parent output invalid";
            return result;
        }
        const auto& parent_output = parent_outputs[prevouts[i].vout];
        if (parent_output.spk == custody_spk) {
            if (result.custody_input_amount >
                UINT64_MAX - parent_output.value) {
                result.reason = "custody input amount overflow";
                return result;
            }
            result.custody_input_amount += parent_output.value;
        }
    }
    result.ok = true;
    return result;
}

// The proof gate. `valid_recipient` = predicate for a well-formed VELD address
// (AddressToScript in consensus; a check in tests). This function is read-only:
// the token ledger owns the one canonical exact-outpoint accumulator used by
// both issuer and SPV mints, and atomically consumes result.outpoint_id when
// crediting.
inline DepositResult VerifyDepositMint(
        const BtcHeaderChain& ch, const uint8_t* payload, size_t len,
        const std::vector<uint8_t>& custody_spk, uint32_t k_btc,
        uint64_t current_supply, uint64_t max_custody,
        const std::function<bool(const std::string&)>& valid_recipient) {
    DepositResult r;
    // Fail closed if the compiled custody script did not decode. An
    // empty Bitcoin scriptPubKey is a real, matchable output; treating an empty
    // configured vector as merely "no configured script" would therefore mint
    // against an anyone-can-spend empty-script output instead of disabling SPV.
    if (custody_spk.empty()) {
        r.reason = "custody script is empty / not configured";
        return r;
    }
    H256 block_hash; uint64_t dirs = 0; std::vector<H256> branch;
    std::vector<uint8_t> tx;
    std::vector<std::vector<uint8_t>> parent_txs;
    btcnull::Proof nullifier_proof;
    if (!ParseMintSpvOp(payload, len, block_hash, dirs, branch, tx,
                        parent_txs, nullifier_proof)) {
        r.reason = "malformed MSP3/lineage/nullifier op";
        return r;
    }

    // Merkle-ambiguity guard (CVE-2012-2459 class): a 64-byte "tx" is
    // indistinguishable from two concatenated 32-byte interior Merkle nodes, so a
    // proof could try to pass an interior node off as a leaf. A real deposit (one
    // custody output + one btcVELD OP_RETURN) is always far larger; reject anything
    // small enough to be confused with an interior node. Belt-and-suspenders — the
    // exactly-one-custody + exactly-one-OP_RETURN requirements already exclude it.
    if (tx.size() <= 64) { r.reason = "deposit tx implausibly short (merkle-ambiguity guard)"; return r; }

    H256 txid = ::veld::Hash256d(tx);
    if (!ch.VerifyMerkle(block_hash, txid, branch, dirs)) { r.reason = "merkle proof invalid"; return r; }
    if (!ch.IsFinalForExternalValue(block_hash, k_btc))   { r.reason = "block not deep and validator-observed on the Bitcoin best chain"; return r; }

    std::vector<BtcTxOut> outs;
    if (!ParseBtcTxOutputs(tx.data(), tx.size(), outs))   { r.reason = "deposit tx unparseable"; return r; }

    uint64_t custody_inputs = 0;
    if (btcnull::CUSTODY_LINEAGE_REQUIRED) {
        const CustodyLineageResult lineage = EvaluateCustodyInputLineage(
            tx, parent_txs, custody_spk);
        if (!lineage.ok) { r.reason = lineage.reason; return r; }
        custody_inputs = lineage.custody_input_amount;
    }

    // Exactly one output to the canonical custody spk -> amount + exact vout.
    // The vout is derived from the proven transaction itself, never supplied by
    // the SPV submitter, and forms the shared issuer/SPV replay identity.
    int custody_n = 0; uint64_t amount = 0; uint32_t custody_vout = 0;
    for (size_t i = 0; i < outs.size(); ++i) {
        if (outs[i].spk == custody_spk) {
            ++custody_n;
            amount = outs[i].value;
            custody_vout = static_cast<uint32_t>(i); // parser caps outputs at 100000
        }
    }
    if (custody_n != 1) { r.reason = "deposit must have exactly one custody output"; return r; }

    // exactly one "btcVELD:<addr>" OP_RETURN → the recipient
    static const std::string TAG = "btcVELD:";
    int rec_n = 0; std::string recipient;
    for (const auto& o : outs) {
        std::vector<uint8_t> d = ExtractOpReturn(o.spk);
        if (d.size() > TAG.size() && std::equal(TAG.begin(), TAG.end(), d.begin()))
            { ++rec_n; recipient.assign(d.begin() + TAG.size(), d.end()); }
    }
    if (rec_n != 1)                 { r.reason = "deposit must have exactly one btcVELD OP_RETURN"; return r; }
    if (!valid_recipient(recipient)){ r.reason = "invalid recipient address"; return r; }

    if (amount == 0 ||
        (btcnull::CUSTODY_LINEAGE_REQUIRED && amount <= custody_inputs)) {
        r.reason = "transaction adds no net-new external custody";
        return r;
    }
    const uint64_t net_new_amount = amount - custody_inputs;
    // overflow-safe form of (current_supply + net_new_amount > max_custody)
    if (current_supply > max_custody ||
        net_new_amount > max_custody - current_supply)
                                                      { r.reason = "over custody cap"; return r; }

    r.ok = true;
    r.recipient = recipient;
    r.amount = net_new_amount;
    r.custody_input_amount = custody_inputs;
    r.custody_output_amount = amount;
    r.deposit_key = txid;
    r.deposit_vout = custody_vout;
    r.outpoint_id = BtcDepositOutpointId(txid, custody_vout);
    r.nullifier_proof = std::move(nullifier_proof);
    return r;
}

// Compatibility overload used by the standalone SPV harness and relay tools
// that additionally impose a per-deposit operational ceiling.  The consensus
// net-new lineage result is authoritative; the extra cap can only tighten it.
inline DepositResult VerifyDepositMint(
        const BtcHeaderChain& ch, const uint8_t* payload, size_t len,
        const std::vector<uint8_t>& custody_spk, uint32_t k_btc,
        uint64_t max_per_mint, uint64_t current_supply,
        uint64_t max_custody,
        const std::function<bool(const std::string&)>& valid_recipient) {
    DepositResult result = VerifyDepositMint(
        ch, payload, len, custody_spk, k_btc, current_supply, max_custody,
        valid_recipient);
    if (result.ok && result.amount > max_per_mint) {
        result.ok = false;
        result.reason = "over per-mint cap";
    }
    return result;
}

}  // namespace btcspv
}  // namespace veld
