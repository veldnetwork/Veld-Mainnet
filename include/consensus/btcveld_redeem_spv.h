#pragma once
// SPV-proven btcVELD payout resolution.
//
// Turns an SPV proof of a Bitcoin PAYOUT tx into a covenant decision, with the BTC
// fact proven by the in-consensus SPV relay (btc_header_chain) — never an
// operator's word. A correct payout (pays the request's exact dest scriptPubKey
// the exact amount, buried K_btc deep) FULFILLS the request and releases the
// signer bond lock; an incorrect one is a WRONG_PAYOUT slash. This is the positive
// half of the redeem leg — the path that a signer group MUST hit before the
// deadline or eat the non-payment slash.
//
// Public wire formats are PSP2 (request commitment + final payout + exact
// custody parent) and FSP2 (final spend + every hash-bound direct parent).
// Non-public historical fixtures retain PSPV/FSPV parsers behind the strict
// public profile gate.
//
// Validation is fail-closed and remains dormant until the SPV relay and redeem
// covenant activate.

#include "core/btc_deposit_verify.h"        // btcspv:: BtcHeaderChain / BtcTxOut / ParseBtcTxOutputs / rd_le32 / Hash256d
#include "consensus/btcveld_signer_bond.h"  // btcveld:: SignerBondCovenant / SlashVerdict / H256

namespace veld {
namespace btcveld {

struct PayoutProof {
    bool                          ok = false;
    std::string                   reason;
    H256                          request_id{};
    H256                          payout_txid{};
    std::vector<btcspv::BtcTxOut> outputs;
    H256                          request_commitment{};
    uint64_t                      payout_btc_height = 0;
    bool                          spends_recognized_custody = false;
    uint64_t                      proven_input_sats = 0;
};

// Parse + SPV-verify a payout proof. Proves the payout tx is buried `k_btc` deep on
// the most-work BTC header chain and returns its parsed outputs (for the covenant
// to compare against the request). Read-only on the chain.
inline PayoutProof VerifyRedeemPayout(const btcspv::BtcHeaderChain& ch,
                                      const uint8_t* p, size_t len, uint32_t k_btc,
                                      const std::vector<uint8_t>& custody_spk = {}) {
    PayoutProof r;
    if (p == nullptr) { r.reason = "null payout proof"; return r; }
    if (REDEEM_PAYOUT_BINDING_REQUIRED) {
        // PSP2 is deliberately one request per transaction.  It proves one
        // final payout transaction and the sole input's exact custody parent.
        // Requiring exactly one input makes the entire input value known to
        // consensus; output conservation is then enforced by the covenant.
        if (custody_spk.empty() || len < 4 + 32 + 32 + 32 + 4 + 1 + 4 + 10 +
                                      4 + 10 + 4 + 4 ||
            std::memcmp(p, "PSP2", 4) != 0) {
            r.reason = "malformed PSP2 payout proof";
            return r;
        }
        size_t off = 4;
        std::memcpy(r.request_id.data(), p + off, 32); off += 32;
        std::memcpy(r.request_commitment.data(), p + off, 32); off += 32;
        H256 block_hash{};
        std::memcpy(block_hash.data(), p + off, 32); off += 32;
        const uint64_t dirs = btcspv::rd_le32(p + off); off += 4;
        const uint8_t mlen = p[off++];
        if (mlen > 32 || (mlen < 32 && (dirs >> mlen) != 0) ||
            off + static_cast<size_t>(mlen) * 32 + 4 > len) {
            r.reason = "invalid PSP2 merkle branch";
            return r;
        }
        std::vector<H256> branch;
        for (uint8_t i = 0; i < mlen; ++i) {
            H256 h{};
            std::memcpy(h.data(), p + off, 32);
            off += 32;
            branch.push_back(h);
        }
        const uint32_t tx_len = btcspv::rd_le32(p + off); off += 4;
        if (tx_len <= 64 || tx_len > btcnull::MAX_MSPV_STRIPPED_TX_BYTES ||
            off + tx_len + 4 > len) {
            r.reason = "invalid PSP2 payout transaction length";
            return r;
        }
        std::vector<uint8_t> payout_tx(p + off, p + off + tx_len);
        off += tx_len;
        const uint32_t parent_len = btcspv::rd_le32(p + off); off += 4;
        if (parent_len < 10 || parent_len > btcnull::MAX_MSPV_PARENT_TX_BYTES ||
            off + parent_len + 8 != len) {
            r.reason = "invalid PSP2 custody parent length";
            return r;
        }
        std::vector<uint8_t> parent_tx(p + off, p + off + parent_len);
        off += parent_len;
        const uint32_t custody_vout = btcspv::rd_le32(p + off); off += 4;
        const uint32_t payout_vin = btcspv::rd_le32(p + off); off += 4;

        r.payout_txid = ::veld::Hash256d(payout_tx);
        if (!ch.VerifyMerkle(block_hash, r.payout_txid, branch, dirs) ||
            !ch.IsFinalForExternalValue(block_hash, k_btc)) {
            r.reason = "PSP2 payout is not final on the best chain";
            return r;
        }
        const auto record = ch.Get(block_hash);
        if (!record) { r.reason = "PSP2 payout header unavailable"; return r; }
        r.payout_btc_height = record->height;
        if (!btcspv::ParseBtcTxOutputs(payout_tx.data(), payout_tx.size(),
                                       r.outputs)) {
            r.reason = "PSP2 payout transaction is unparseable";
            return r;
        }
        std::vector<btcspv::BtcPrevout> payout_prevouts;
        if (!btcspv::ParseBtcTxPrevouts(payout_tx.data(), payout_tx.size(),
                                        payout_prevouts) ||
            payout_prevouts.size() != 1 || payout_vin != 0) {
            r.reason = "PSP2 payout must spend exactly one proven custody input";
            return r;
        }
        const std::vector<uint8_t> expected_commitment =
            RedeemRequestCommitmentScript(r.request_commitment);
        size_t commitment_outputs = 0;
        for (const auto& output : r.outputs) {
            if (output.value == 0 && output.spk == expected_commitment)
                ++commitment_outputs;
        }
        if (commitment_outputs != 1) {
            r.reason = "PSP2 payout lacks one exact request commitment";
            return r;
        }
        std::vector<btcspv::BtcTxOut> parent_outputs;
        if (!btcspv::ParseBtcTxOutputs(parent_tx.data(), parent_tx.size(),
                                       parent_outputs) ||
            custody_vout >= parent_outputs.size() ||
            parent_outputs[custody_vout].spk != custody_spk) {
            r.reason = "PSP2 parent is not recognized custody";
            return r;
        }
        const H256 parent_txid = ::veld::Hash256d(parent_tx);
        if (payout_prevouts[0].txid != parent_txid ||
            payout_prevouts[0].vout != custody_vout) {
            r.reason = "PSP2 payout does not spend the proven custody parent";
            return r;
        }
        r.proven_input_sats = parent_outputs[custody_vout].value;
        if (r.proven_input_sats == 0) {
            r.reason = "PSP2 custody input has zero value";
            return r;
        }
        r.spends_recognized_custody = true;
        r.ok = true;
        return r;
    }
    if (len < 4 + 32 + 32 + 4 + 1 || std::memcmp(p, "PSPV", 4) != 0) { r.reason = "malformed payout op"; return r; }
    size_t off = 4;
    std::memcpy(r.request_id.data(), p + off, 32); off += 32;
    H256 block_hash; std::memcpy(block_hash.data(), p + off, 32); off += 32;
    uint64_t dirs = btcspv::rd_le32(p + off); off += 4;
    uint8_t mlen = p[off++];
    // H-1: reject non-canonical direction bits, matching
    // ParseC1FundingProof/ParseMintSpvOp. Without this, every direction bit
    // above the branch length is a free bit, so one logical proof has many
    // valid byte encodings. Not a forgery path on its own (the root must still
    // match), but it becomes replay or digest divergence the moment either
    // payload is hashed.
    if (mlen > 32)                    { r.reason = "bad merkle length"; return r; }
    if (mlen < 32 && (dirs >> mlen) != 0) {
        r.reason = "non-canonical merkle direction bits"; return r;
    }
    if (off + (size_t)mlen * 32 > len){ r.reason = "truncated merkle branch"; return r; }
    std::vector<H256> branch;
    for (int i = 0; i < mlen; ++i) { H256 h; std::memcpy(h.data(), p + off, 32); off += 32; branch.push_back(h); }
    std::vector<uint8_t> tx(p + off, p + len);
    if (tx.size() <= 64)                                    { r.reason = "payout tx implausibly short (merkle-ambiguity guard)"; return r; }
    H256 txid = ::veld::Hash256d(tx);
    if (!ch.VerifyMerkle(block_hash, txid, branch, dirs))    { r.reason = "merkle proof invalid"; return r; }
    if (!ch.IsFinal(block_hash, k_btc))                      { r.reason = "payout not final / not on best chain"; return r; }
    if (!btcspv::ParseBtcTxOutputs(tx.data(), tx.size(), r.outputs)) { r.reason = "payout tx unparseable"; return r; }
    r.ok = true; r.payout_txid = txid;
    r.spends_recognized_custody = true;
    r.payout_btc_height = UINT64_MAX;
    return r;
}

// Convenience: SPV-verify a payout proof AND resolve it against the covenant
// (fulfill-or-slash). Returns the PayoutProof (for diagnostics); on a proven-but-
// wrong payout, `out_slash` is set and the caller applies it.
inline PayoutProof VerifyAndResolvePayout(SignerBondCovenant& cov,
                                          const btcspv::BtcHeaderChain& ch,
                                          const uint8_t* p, size_t len, uint32_t k_btc,
                                          bool& fulfilled, SlashVerdict& out_slash,
                                          const std::vector<uint8_t>& custody_spk = {}) {
    fulfilled = false;
    PayoutProof r = VerifyRedeemPayout(ch, p, len, k_btc, custody_spk);
    if (!r.ok) return r;
    fulfilled = cov.ResolveProvenPayout(
        r.request_id, r.payout_txid, r.outputs, out_slash,
        r.request_commitment, r.payout_btc_height,
        r.spends_recognized_custody, custody_spk, r.proven_input_sats);
    return r;
}

// ── FRAUDULENT SPEND (§7 trigger 2): complete custody-spend proof ──
//
// A tx input references its prevout by (txid, vout) only — not the prevout's
// scriptPubKey. FSP2 therefore supplies every direct parent in input order and
// hash-binds each one through the final spend. The historical non-public FSPV
// fixture uses the older two-transaction wire format:
//   "FSPV"
//     | F_block(32) F_dirs(u32) F_mlen(u8) F_branch(F_mlen×32) F_vout(u32) F_txlen(u32) F_tx
//     | S_block(32) S_dirs(u32) S_mlen(u8) S_branch(S_mlen×32) S_vin(u32)  S_txlen(u32) S_tx
struct FraudProof {
    bool                          ok = false;
    std::string                   reason;
    H256                          spend_txid{};
    uint64_t                      custody_value = 0;   // value that left custody (from the funding output)
    uint64_t                      total_input_value = 0;
    std::vector<btcspv::BtcTxOut> spend_outputs;       // the spending tx's outputs (for the request check)
    H256                          spend_block{};
    uint64_t                      spend_merkle_directions = 0;
    std::vector<H256>             spend_merkle_branch;
    std::vector<uint8_t>          spend_tx;
    std::vector<std::vector<uint8_t>> direct_parents;
};

inline FraudProof VerifyFraudulentSpend(const btcspv::BtcHeaderChain& ch, const uint8_t* p, size_t len,
                                        const std::vector<uint8_t>& custody_spk, uint32_t k_btc) {
    FraudProof r;
    if (p == nullptr || custody_spk.empty()) {
        r.reason = "custody script/proof unavailable";
        return r;
    }
    if (REDEEM_PAYOUT_BINDING_REQUIRED) {
        // FSP2 proves the final spend once, then supplies every direct parent
        // transaction in input order.  Each parent is hash-bound by the spend,
        // allowing complete input/output conservation and complete custody
        // classification without trusting a partial-output assertion.
        if (len < 4 + 32 + 4 + 1 + 4 + 10 + 2 ||
            std::memcmp(p, "FSP2", 4) != 0) {
            r.reason = "malformed FSP2 proof";
            return r;
        }
        size_t off = 4;
        std::memcpy(r.spend_block.data(), p + off, 32); off += 32;
        const uint64_t dirs = btcspv::rd_le32(p + off); off += 4;
        const uint8_t mlen = p[off++];
        if (mlen > 32 || (mlen < 32 && (dirs >> mlen) != 0) ||
            off + static_cast<size_t>(mlen) * 32 + 4 > len) {
            r.reason = "invalid FSP2 merkle branch";
            return r;
        }
        std::vector<H256> branch;
        for (uint8_t i = 0; i < mlen; ++i) {
            H256 h{};
            std::memcpy(h.data(), p + off, 32);
            off += 32;
            branch.push_back(h);
        }
        r.spend_merkle_directions = dirs;
        r.spend_merkle_branch = branch;
        const uint32_t spend_len = btcspv::rd_le32(p + off); off += 4;
        if (spend_len <= 64 ||
            spend_len > btcnull::MAX_MSPV_STRIPPED_TX_BYTES ||
            off + spend_len + 2 > len) {
            r.reason = "invalid FSP2 spend length";
            return r;
        }
        r.spend_tx.assign(p + off, p + off + spend_len);
        off += spend_len;
        btcspv::WitnessAwareBtcTx spend;
        if (!btcspv::ParseWitnessAwareBtcTx(
                r.spend_tx, spend, btcnull::MAX_MSPV_PARENT_COUNT)) {
            r.reason = "FSP2 spend serialization is non-canonical";
            return r;
        }
        r.spend_txid = spend.txid;
        if (!ch.VerifyMerkle(r.spend_block, r.spend_txid, branch, dirs) ||
            !ch.IsFinalForExternalValue(r.spend_block, k_btc)) {
            r.reason = "FSP2 spend is not final on the best chain";
            return r;
        }
        const std::vector<btcspv::BtcPrevout>& prevouts = spend.prevouts;
        const uint16_t parent_count = static_cast<uint16_t>(p[off]) |
            (static_cast<uint16_t>(p[off + 1]) << 8);
        off += 2;
        if (parent_count != prevouts.size() || parent_count == 0 ||
            parent_count > btcnull::MAX_MSPV_PARENT_COUNT) {
            r.reason = "FSP2 parent set is incomplete";
            return r;
        }
        size_t parent_total = 0;
        for (uint16_t i = 0; i < parent_count; ++i) {
            if (off + 4 > len) { r.reason = "truncated FSP2 parent"; return r; }
            const uint32_t parent_len = btcspv::rd_le32(p + off); off += 4;
            if (parent_len < 10 ||
                parent_len > btcnull::MAX_MSPV_PARENT_TX_BYTES ||
                parent_total > btcnull::MAX_MSPV_PARENT_TOTAL_BYTES - parent_len ||
                off + parent_len > len) {
                r.reason = "invalid FSP2 parent length";
                return r;
            }
            std::vector<uint8_t> parent_tx(p + off, p + off + parent_len);
            off += parent_len;
            parent_total += parent_len;
            r.direct_parents.push_back(parent_tx);
            btcspv::WitnessAwareBtcTx parent;
            if (!btcspv::ParseWitnessAwareBtcTx(parent_tx, parent) ||
                parent.txid != prevouts[i].txid) {
                r.reason = "FSP2 parent hash mismatch";
                return r;
            }
            if (prevouts[i].vout >= parent.outputs.size()) {
                r.reason = "FSP2 parent output invalid";
                return r;
            }
            const auto& input = parent.outputs[prevouts[i].vout];
            if (r.total_input_value > UINT64_MAX - input.value) {
                r.reason = "FSP2 input value overflow";
                return r;
            }
            r.total_input_value += input.value;
            if (input.spk == custody_spk) {
                if (r.custody_value > UINT64_MAX - input.value) {
                    r.reason = "FSP2 custody value overflow";
                    return r;
                }
                r.custody_value += input.value;
            }
        }
        r.spend_outputs = spend.outputs;
        if (off != len || r.custody_value == 0) {
            r.reason = "FSP2 is trailing, non-custody, or unparseable";
            return r;
        }
        r.ok = true;
        return r;
    }
    size_t off = 0;
    auto need = [&](size_t n){ return off + n <= len; };
    auto rd32 = [&](){ uint32_t v = btcspv::rd_le32(p + off); off += 4; return v; };
    // H-1: `dirs` is now supplied so the canonical
    // direction-bits rule that ParseC1FundingProof/ParseMintSpvOp enforce also
    // binds here — any bit above the branch length must be zero, otherwise one
    // logical proof has many valid byte encodings.
    auto rd_merkle = [&](std::vector<H256>& br, uint64_t dirs)->bool {
        if (!need(1)) return false; uint8_t mlen = p[off++];
        if (mlen > 32 || !need((size_t)mlen*32)) return false;
        if (mlen < 32 && (dirs >> mlen) != 0) return false;
        for (int i=0;i<mlen;i++){ H256 h; std::memcpy(h.data(), p+off, 32); off+=32; br.push_back(h); }
        return true;
    };
    if (len < 4 || std::memcmp(p, "FSPV", 4) != 0) { r.reason = "malformed fraud op"; return r; }
    off = 4;

    // ── funding tx: proves the custody output existed ──
    if (!need(32+4)) { r.reason="trunc F"; return r; }
    H256 fblk; std::memcpy(fblk.data(), p+off, 32); off+=32; uint64_t fdirs = rd32();
    std::vector<H256> fbranch; if (!rd_merkle(fbranch, fdirs)) { r.reason="bad F merkle"; return r; }
    if (!need(4+4)) { r.reason="trunc F vout/len"; return r; }
    uint32_t custody_vout = rd32(); uint32_t ftxlen = rd32();
    if (!need(ftxlen) || ftxlen <= 64) { r.reason="bad F txlen"; return r; }
    std::vector<uint8_t> ftx(p+off, p+off+ftxlen); off += ftxlen;
    H256 ftxid = ::veld::Hash256d(ftx);
    if (!ch.VerifyMerkle(fblk, ftxid, fbranch, fdirs)) { r.reason="F merkle invalid"; return r; }
    if (!ch.IsFinal(fblk, k_btc))                      { r.reason="F not final"; return r; }
    std::vector<btcspv::BtcTxOut> fouts;
    if (!btcspv::ParseBtcTxOutputs(ftx.data(), ftx.size(), fouts)) { r.reason="F unparseable"; return r; }
    if (custody_vout >= fouts.size())                  { r.reason="custody_vout out of range"; return r; }
    if (fouts[custody_vout].spk != custody_spk)        { r.reason="funding output is not the custody spk"; return r; }
    r.custody_value = fouts[custody_vout].value;
    r.total_input_value = r.custody_value;

    // ── spending tx: proves that custody output was consumed ──
    if (!need(32+4)) { r.reason="trunc S"; return r; }
    H256 sblk; std::memcpy(sblk.data(), p+off, 32); off+=32; uint64_t sdirs = rd32();
    std::vector<H256> sbranch; if (!rd_merkle(sbranch, sdirs)) { r.reason="bad S merkle"; return r; }
    if (!need(4+4)) { r.reason="trunc S vin/len"; return r; }
    uint32_t spend_vin = rd32(); uint32_t stxlen = rd32();
    if (off + stxlen != len || stxlen <= 64)           { r.reason="bad S txlen"; return r; }
    std::vector<uint8_t> stx(p+off, p+off+stxlen);
    r.spend_txid = ::veld::Hash256d(stx);
    if (!ch.VerifyMerkle(sblk, r.spend_txid, sbranch, sdirs)) { r.reason="S merkle invalid"; return r; }
    if (!ch.IsFinal(sblk, k_btc))                      { r.reason="S not final"; return r; }
    H256 prev_txid; uint32_t prev_vout;
    if (!btcspv::ParseBtcTxInputPrevout(stx.data(), stx.size(), spend_vin, prev_txid, prev_vout)) { r.reason="S input parse"; return r; }
    if (prev_txid != ftxid || prev_vout != custody_vout) { r.reason="spend does not reference the custody output"; return r; }
    if (!btcspv::ParseBtcTxOutputs(stx.data(), stx.size(), r.spend_outputs)) { r.reason="S unparseable"; return r; }
    r.ok = true;
    return r;
}

// SPV-verify a fraud proof AND evaluate it against the covenant.  Classification
// is txid-global across PSP2/FSP2: an already classified payout cannot later be
// reinterpreted as fraud, and an already classified fraud spend cannot be
// replayed or reinterpreted as a payout.
inline FraudProof VerifyAndResolveFraud(SignerBondCovenant& cov,
                                        const btcspv::BtcHeaderChain& ch, const uint8_t* p, size_t len,
                                        const std::vector<uint8_t>& custody_spk, uint32_t k_btc,
                                        SlashVerdict& out_slash) {
    FraudProof r = VerifyFraudulentSpend(ch, p, len, custody_spk, k_btc);
    if (!r.ok) return r;
    if (cov.IsConsumedPayout(r.spend_txid)) {
        r.ok = false;
        r.reason = "custody spend already classified by payout proof";
        return r;
    }
    if (cov.IsConsumedFraudSpend(r.spend_txid)) {
        r.ok = false;
        r.reason = "fraudulent custody spend already consumed";
        return r;
    }
    out_slash = cov.EvalFraudulentSpend(
        r.custody_value, r.spend_outputs, custody_spk,
        r.total_input_value);
    if (out_slash.slash && !cov.ConsumeFraudSpend(r.spend_txid)) {
        out_slash = SlashVerdict{};
        r.ok = false;
        r.reason = "custody spend classification conflict";
    }
    return r;
}

}  // namespace btcveld
}  // namespace veld
