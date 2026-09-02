#pragma once
// Canonical btcVELD MINT transaction
// output-template policy, shared by the issuer signer (veld-keygen sign-tx / decode-mint)
// and its tests (and available to the node for on-chain mint validation). Enforced on the
// DESERIALIZED transaction, never a byte substring, so a marker smuggled behind
// OP_PUSHDATA1 in a non-OP_RETURN script — or an attacker-controlled output — can never
// masquerade as a mint and coax the isolated signer into an arbitrary issuer-wallet spend.
#include "../core/transaction.h"
#include "../core/script.h"
#include "../core/btc_deposit_verify.h"
#include "btcveld_mint_nullifier.h"
#include "btcveld_c1_reservation.h"
#include "btcveld_reserve_transition.h"
#include <string>
#include <vector>
#include <cstdint>

namespace veld {

struct BtcVeldReserveMintPolicyContext {
    btcveld::reserve::State prior_state;
    uint64_t circulating_supply = 0;
};

inline bool BtcVeldMintPolicyRawOutpointId(const std::string& text) {
    if (text.size() < 66 || text[64] != ':') return false;
    for (size_t i = 0; i < 64; ++i) {
        const char c = text[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    const size_t digits = text.size() - 65;
    if (digits == 0 || digits > 10) return false;
    if (digits > 1 && text[65] == '0') return false;
    uint64_t vout = 0;
    for (size_t i = 65; i < text.size(); ++i) {
        if (text[i] < '0' || text[i] > '9') return false;
        vout = vout * 10 + static_cast<uint64_t>(text[i] - '0');
    }
    return vout <= UINT32_MAX;
}

inline bool BtcVeldMintPolicyOutpointId(const std::string& text) {
    std::string outpoint;
    std::string reservation_request_id;
    btcnull::Proof proof;
    return btcnull::ParseIssuerMemo(
               text, outpoint, proof, reservation_request_id) &&
           BtcVeldMintPolicyRawOutpointId(outpoint);
}

// Isolated issuer signing policy for the fresh rolling-reserve profile.  The
// signer has no independent Bitcoin-header or Veld-state authority, so it does
// not duplicate consensus finality or assert freshness by itself.  It requires
// the online preparer's complete fixed-binary prior-state snapshot and supply,
// then invokes the same canonical classifier against that context.  Consensus
// later re-authenticates the same claim against live state.  A coordinator
// therefore cannot redirect the token credit, omit the state context, or pair
// a proof with a different prior while asking the issuer key to sign it.
inline bool BtcVeldReserveMintPolicyMemo(
        const std::string& memo, const std::string& expected_recipient,
        uint64_t expected_sats,
        const BtcVeldReserveMintPolicyContext* context) {
#if !defined(VELD_PUBLIC_MAINNET) && !defined(VELD_BTCVELD_REGTEST)
    (void)memo;
    (void)expected_recipient;
    (void)expected_sats;
    (void)context;
    return false;
#else
    const std::string prefix = btcveld::reserve::ISSUER_MEMO_PREFIX;
    if (memo.rfind(prefix, 0) != 0) return false;
    const std::string encoded = memo.substr(prefix.size());
    const std::vector<uint8_t> proof = HexToBytes(encoded);
    btcveld::reserve::Claim claim;
    if (proof.empty() || encoded != BytesToHex(proof) ||
        !btcveld::reserve::DecodeProof(
            proof.data(), proof.size(), claim) ||
        btcveld::reserve::EncodeProof(claim) != proof ||
        (claim.operation != btcveld::reserve::Operation::OPEN &&
         claim.operation != btcveld::reserve::Operation::DEPOSIT) ||
        claim.network_binding != btcveld::reserve::NetworkBinding() ||
        claim.mint_amount != expected_sats || expected_sats == 0 ||
        !claim.has_nullifier_proof)
        return false;
    btcspv::WitnessAwareBtcTx bitcoin;
    if (!btcspv::ParseWitnessAwareBtcTx(
            claim.bitcoin_tx, bitcoin,
            btcveld::reserve::MAX_DIRECT_INPUTS) ||
        claim.bitcoin_txid != bitcoin.txid ||
        claim.new_reserve_txid != claim.bitcoin_txid ||
        claim.new_reserve_vout == btcveld::reserve::NO_VOUT ||
        claim.new_reserve_value == 0 ||
        claim.new_reserve_value > BTCVELD_SPV_MAX_CUSTODY_SATS ||
        context == nullptr || !context->prior_state.Canonical() ||
        !context->prior_state.AccountingHolds(context->circulating_supply) ||
        !btcveld::reserve::detail::MatchesPrior(
            context->prior_state, claim))
        return false;
    const auto classified = btcveld::reserve::ClassifyBitcoinReserveSpend(
        context->prior_state, context->circulating_supply,
        claim.bitcoin_tx, claim.direct_parents, BtcVeldCustodySpk(),
        [&expected_recipient](const std::string& candidate) {
            return candidate == expected_recipient &&
                   IsCanonicalTokenCreditAddress(candidate);
        });
    return classified.disposition ==
               btcveld::reserve::SpendDisposition::AUTHORIZED_TRANSITION &&
           classified.operation == claim.operation &&
           classified.bitcoin_txid == claim.bitcoin_txid &&
           classified.new_reserve_txid == claim.new_reserve_txid &&
           classified.new_reserve_vout == claim.new_reserve_vout &&
           classified.new_reserve_value == claim.new_reserve_value &&
           classified.exact_commitment == claim.exact_commitment &&
           classified.mint_amount == claim.mint_amount &&
           classified.recipient == expected_recipient;
#endif
}

// Returns "" iff `tx` is a clean single canonical mint: every spendable output pays
// `issuer_p2pkh` (change only — a mint pays no native VELD to anyone), and there is
// exactly one value-0 OP_RETURN carrying VELD_TOKEN|MINT|btcVELD|<from>|<to>|<sats>|<memo>
// at the start of its pushed payload, with NO other stateful VELD_ marker and no stray
// data carrier. Otherwise a human-readable refusal reason. On success fills
// from/to/sats/memo; the caller checks from==issuer separately (it holds the identity).
inline std::string BtcVeldMintTemplatePolicy(const Transaction& tx,
                                             const std::vector<uint8_t>& issuer_p2pkh,
                                             std::string& from_out, std::string& to_out,
                                             uint64_t& sats_out, std::string& memo_out,
                                             const BtcVeldReserveMintPolicyContext*
                                                 reserve_context = nullptr) {
    static const std::string kMint = "VELD_TOKEN|MINT|btcVELD|";
    int mint_markers = 0, other_markers = 0, change_outputs = 0;
    for (size_t oi = 0; oi < tx.outputs.size(); ++oi) {
        const std::vector<uint8_t>& s = tx.outputs[oi].script_pubkey;
        if (!s.empty() && s[0] == 0x6A) {                        // OP_RETURN data carrier
            if (tx.outputs[oi].value != 0)
                return "OP_RETURN output [" + std::to_string(oi) + "] carries value";
            size_t k = 1, pushed = 0;
            if (k >= s.size()) return "OP_RETURN has no data push";
            const uint8_t push = s[k++];
            if (push <= 75) {
                pushed = push;
            } else if (push == 0x4C) {
                if (k >= s.size()) return "truncated OP_PUSHDATA1";
                pushed = s[k++];
                if (pushed <= 75) return "non-canonical OP_PUSHDATA1";
            } else if (push == 0x4D) {
                if (k + 2 > s.size()) return "truncated OP_PUSHDATA2";
                pushed = static_cast<size_t>(s[k]) |
                         (static_cast<size_t>(s[k + 1]) << 8);
                k += 2;
                if (pushed <= 255) return "non-canonical OP_PUSHDATA2";
            } else {
                return "unsupported OP_RETURN push opcode";
            }
            if (k + pushed != s.size())
                return "OP_RETURN push length/trailing bytes mismatch";
            std::string payload(s.begin() + k, s.end());
            if (payload.rfind(kMint, 0) == 0) {                  // canonical mint marker AT START
                ++mint_markers;
                std::vector<std::string> f; size_t p = 0, q;
                while ((q = payload.find('|', p)) != std::string::npos) { f.push_back(payload.substr(p, q - p)); p = q + 1; }
                f.push_back(payload.substr(p));
                // EncodeTokenOp emits exactly seven fields for a mint, with the
                // deposit outpoint in the final memo field.  Accepting extra
                // separators here would make the isolated signer interpret a
                // different operation than DecodeTokenOp/consensus.
                if (f.size() != 7) return "MINT marker field count is not canonical";
                from_out = f[3]; to_out = f[4];
                if (from_out.empty() || to_out.empty())
                    return "MINT issuer or recipient is empty";
                if (f[5].empty() || (f[5].size() > 1 && f[5][0] == '0'))
                    return "MINT amount unparseable";
                uint64_t amount = 0;
                for (char c : f[5]) {
                    if (c < '0' || c > '9')
                        return "MINT amount unparseable";
                    const uint64_t digit = static_cast<uint64_t>(c - '0');
                    if (amount > (UINT64_MAX - digit) / 10)
                        return "MINT amount unparseable";
                    amount = amount * 10 + digit;
                }
                if (amount == 0 || amount > static_cast<uint64_t>(INT64_MAX))
                    return "MINT amount out of consensus range";
                sats_out = amount;
                memo_out = f[6];
#if defined(VELD_PUBLIC_MAINNET) || defined(VELD_BTCVELD_REGTEST)
                if (!BtcVeldReserveMintPolicyMemo(
                        memo_out, to_out, sats_out, reserve_context))
                    return "MINT memo or live reserve context is not canonical recipient-bound RTP1";
#else
                if (!BtcVeldMintPolicyOutpointId(memo_out))
                    return "MINT memo is not canonical MNP1 or root-neutral MNP2";
#endif
            } else if (payload.rfind("VELD_", 0) == 0) {
                ++other_markers;                                 // any OTHER stateful family marker
            } else {
                return "non-VELD OP_RETURN present (unexpected data carrier)";
            }
        } else {                                                 // any spendable output MUST be one exact issuer change
            if (s != issuer_p2pkh)
                return "output [" + std::to_string(oi) + "] pays a non-issuer script "
                       "(a mint may only return change to the issuer)";
            if (++change_outputs != 1)
                return "MINT transaction has more than one change output";
        }
    }
    if (mint_markers != 1) return "expected exactly one canonical MINT OP_RETURN, found " + std::to_string(mint_markers);
    if (other_markers != 0) return "tx carries " + std::to_string(other_markers) + " other VELD_ protocol marker(s)";
    return "";
}

struct BtcVeldC1CarrierPolicyResult {
    std::string action;
    std::string from;
    std::string to;
    uint64_t sats = 0;
    std::string allocation_id;
    std::string allocation_commitment;
    // Populated only by C1F1.  The funding carrier opens the blinded
    // allocation commitment and proves the exact Bitcoin deposit plus its
    // current MNP1 nonmembership witness.  R/E/C leave every field empty.
    std::string fund_script_pubkey_hex;
    std::string fund_commitment_blind_hex;
    std::string fund_outpoint;
    std::string funding_proof_hex;
};

// Exact sibling policy for every issuer-signed C1 capacity carrier.  All four
// phases use the same fees-only transaction envelope as MINT but never pay a
// native-Veld recipient. C1R1/C1E1/C1C1 carry only the blinded allocation
// commitment. C1F1 opens that commitment and carries the canonical CFP1+MNP1
// funding proof; it still performs no token credit (the later root-neutral
// MNP2 does that). The returned structure is cleared on entry and is valid only
// when the function returns an empty refusal string.
inline std::string BtcVeldC1ReservationTemplatePolicy(
        const Transaction& tx,
        const std::vector<uint8_t>& issuer_p2pkh,
        BtcVeldC1CarrierPolicyResult& result_out) {
    result_out = BtcVeldC1CarrierPolicyResult{};
    int c1_markers = 0;
    int other_markers = 0;
    int change_outputs = 0;
    for (size_t oi = 0; oi < tx.outputs.size(); ++oi) {
        const auto& script = tx.outputs[oi].script_pubkey;
        if (!script.empty() && script[0] == 0x6a) {
            if (tx.outputs[oi].value != 0)
                return "OP_RETURN output carries value";
            size_t pos = 1;
            size_t pushed = 0;
            if (pos >= script.size()) return "OP_RETURN has no data push";
            const uint8_t push = script[pos++];
            if (push <= 75) {
                pushed = push;
            } else if (push == 0x4c) {
                if (pos >= script.size()) return "truncated OP_PUSHDATA1";
                pushed = script[pos++];
                if (pushed <= 75) return "non-canonical OP_PUSHDATA1";
            } else if (push == 0x4d) {
                if (pos + 2 > script.size()) return "truncated OP_PUSHDATA2";
                pushed = static_cast<size_t>(script[pos]) |
                         (static_cast<size_t>(script[pos + 1]) << 8);
                pos += 2;
                if (pushed <= 255) return "non-canonical OP_PUSHDATA2";
            } else {
                return "unsupported OP_RETURN push opcode";
            }
            if (pos + pushed != script.size())
                return "OP_RETURN push length/trailing bytes mismatch";
            const std::string payload(script.begin() + pos, script.end());
            const bool token_c1 =
                payload.rfind("VELD_TOKEN|RESERVE|btcVELD|", 0) == 0 ||
                payload.rfind("VELD_TOKEN|EXPOSE|btcVELD|", 0) == 0 ||
                payload.rfind("VELD_TOKEN|CANCEL|btcVELD|", 0) == 0 ||
                payload.rfind("VELD_TOKEN|FUND|btcVELD|", 0) == 0;
            if (token_c1) {
                ++c1_markers;
                std::vector<std::string> fields;
                size_t begin = 0;
                size_t split = 0;
                while ((split = payload.find('|', begin)) !=
                       std::string::npos) {
                    fields.push_back(payload.substr(begin, split - begin));
                    begin = split + 1;
                }
                fields.push_back(payload.substr(begin));
                if (fields.size() != 7 || fields[0] != "VELD_TOKEN" ||
                    fields[2] != "btcVELD" ||
                    (fields[1] != "RESERVE" && fields[1] != "EXPOSE" &&
                     fields[1] != "CANCEL" && fields[1] != "FUND"))
                    return "C1 marker fields are not canonical";
                result_out.action = fields[1];
                result_out.from = fields[3];
                result_out.to = fields[4];
                if (result_out.from.empty() || result_out.to.empty())
                    return "C1 issuer or recipient is empty";
                if (fields[5].empty() ||
                    (fields[5].size() > 1 && fields[5][0] == '0'))
                    return "C1 amount unparseable";
                uint64_t amount = 0;
                for (char c : fields[5]) {
                    if (c < '0' || c > '9')
                        return "C1 amount unparseable";
                    const uint64_t digit = static_cast<uint64_t>(c - '0');
                    if (amount > (UINT64_MAX - digit) / 10)
                        return "C1 amount unparseable";
                    amount = amount * 10 + digit;
                }
                if (amount < static_cast<uint64_t>(c1reserve::MIN_SATS) ||
                    amount > static_cast<uint64_t>(
                        BTCVELD_ISSUER_MAX_CUSTODY_SATS))
                    return "C1 amount outside consensus range";
                result_out.sats = amount;

                bool memo_ok = false;
                if (result_out.action == "RESERVE") {
                    memo_ok = c1reserve::ParseMemo(
                        fields[6], result_out.allocation_id,
                        result_out.allocation_commitment);
                } else if (result_out.action == "EXPOSE") {
                    memo_ok = c1reserve::ParseExposureMemo(
                        fields[6], result_out.allocation_id,
                        result_out.allocation_commitment);
                } else if (result_out.action == "CANCEL") {
                    memo_ok = c1reserve::ParseCancellationMemo(
                        fields[6], result_out.allocation_id,
                        result_out.allocation_commitment);
                } else {
                    memo_ok = c1reserve::ParseFundingMemo(
                        fields[6], result_out.allocation_id,
                        result_out.fund_script_pubkey_hex,
                        result_out.fund_commitment_blind_hex,
                        result_out.fund_outpoint,
                        result_out.funding_proof_hex);
                    if (memo_ok) {
                        const std::vector<uint8_t> funding_proof =
                            HexToBytes(result_out.funding_proof_hex);
                        btcspv::H256 block_hash{};
                        uint64_t merkle_dirs = 0;
                        std::vector<btcspv::H256> merkle_branch;
                        std::vector<uint8_t> legacy_tx;
                        btcnull::Proof nullifier_proof;
                        memo_ok = !funding_proof.empty() &&
                            btcspv::ParseC1FundingProof(
                                funding_proof.data(), funding_proof.size(),
                                block_hash, merkle_dirs, merkle_branch,
                                legacy_tx, nullifier_proof) &&
                            legacy_tx.size() > 64;
                        std::vector<btcspv::BtcTxOut> outputs;
                        if (memo_ok)
                            memo_ok = btcspv::ParseBtcTxOutputs(
                                legacy_tx.data(), legacy_tx.size(), outputs);
                        const std::vector<uint8_t> exact_script =
                            HexToBytes(result_out.fund_script_pubkey_hex);
                        size_t exact_matches = 0;
                        uint32_t exact_vout = 0;
                        if (memo_ok && !exact_script.empty()) {
                            for (size_t i = 0; i < outputs.size(); ++i) {
                                if (outputs[i].spk == exact_script &&
                                    outputs[i].value == result_out.sats) {
                                    ++exact_matches;
                                    exact_vout = static_cast<uint32_t>(i);
                                }
                            }
                            memo_ok = exact_matches == 1 &&
                                btcspv::BtcDepositOutpointId(
                                    Hash256d(legacy_tx), exact_vout) ==
                                    result_out.fund_outpoint;
                        } else {
                            memo_ok = false;
                        }
                    }
                    if (memo_ok) {
                        result_out.allocation_commitment =
                            c1reserve::AllocationCommitment(
                                result_out.allocation_id, result_out.to,
                                static_cast<int64_t>(result_out.sats),
                                result_out.fund_script_pubkey_hex,
                                result_out.fund_commitment_blind_hex);
                        memo_ok = !result_out.allocation_commitment.empty();
                    }
                }
                if (!memo_ok)
                    return result_out.action +
                           " memo is not canonical C1 wire data";
            } else if (payload.rfind("VELD_", 0) == 0) {
                ++other_markers;
            } else {
                return "non-VELD OP_RETURN present";
            }
        } else {
            if (script != issuer_p2pkh)
                return "spendable output does not return issuer change";
            if (++change_outputs != 1)
                return "C1 transaction has more than one change output";
        }
    }
    if (c1_markers != 1)
        return "expected exactly one canonical C1 OP_RETURN";
    if (other_markers != 0)
        return "C1 tx carries another VELD protocol marker";
    return {};
}

} // namespace veld
