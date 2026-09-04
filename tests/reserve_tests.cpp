#include "consensus/btcveld_reserve_transition.h"
#include "consensus/btcveld_redeem_params.h"
#include "consensus/btcveld_redeem_spv.h"
#include "core/blockchain.h"
#include "core/onchain_tokens.h"
#include "core/transaction.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace veld;
namespace reserve = veld::btcveld::reserve;

namespace {

constexpr const char* RECIPIENT = "VUjD1JoewGkiGxRqJ52FkK1UiMotjsp9Tg";
constexpr const char* RECIPIENT_2 = "VV6pcrLQvxq7uBZEFtc4qxCizQ26azxTtK";

int g_checks = 0;

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        ++g_checks;                                                                                \
        if (!(condition)) {                                                                        \
            throw std::runtime_error(std::string("check failed at line ") +                        \
                                     std::to_string(__LINE__) + ": " #condition);                  \
        }                                                                                          \
    } while (false)

Hash256 TaggedHash(const std::string& tag) {
    std::vector<uint8_t> bytes(tag.begin(), tag.end());
    return Hash256d(bytes);
}

void PutU32(std::array<uint8_t, 80>& out, size_t off, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
        out[off + i] = static_cast<uint8_t>(value >> (8 * i));
}

std::vector<uint8_t> BitcoinOpReturn(const std::string& value) {
    CHECK(value.size() <= 75);
    std::vector<uint8_t> out{0x6a, static_cast<uint8_t>(value.size())};
    out.insert(out.end(), value.begin(), value.end());
    return out;
}

TxInput BitcoinInput(const Hash256& txid, uint32_t vout) {
    TxInput in;
    in.prev_tx_hash = txid;
    in.prev_out_index = vout;
    in.sequence = 0xffffffffu;
    return in;
}

std::vector<uint8_t> MakeBitcoinTx(const std::vector<std::pair<Hash256, uint32_t>>& inputs,
                                   const std::vector<btcspv::BtcTxOut>& outputs) {
    Transaction tx;
    for (const auto& input : inputs)
        tx.inputs.push_back(BitcoinInput(input.first, input.second));
    for (const auto& output : outputs)
        tx.outputs.emplace_back(output.value, output.spk);
    return tx.Serialize();
}

Hash256 BitcoinTxid(const std::vector<uint8_t>& tx) {
    btcspv::WitnessAwareBtcTx parsed;
    if (!btcspv::ParseWitnessAwareBtcTx(tx, parsed))
        throw std::runtime_error("test Bitcoin transaction is non-canonical");
    return parsed.txid;
}

std::vector<uint8_t> MakeWitnessBitcoinTx(const std::vector<std::pair<Hash256, uint32_t>>& inputs,
                                          const std::vector<btcspv::BtcTxOut>& outputs) {
    const std::vector<uint8_t> stripped = MakeBitcoinTx(inputs, outputs);
    if (stripped.size() < 10 || inputs.empty())
        throw std::runtime_error("invalid stripped witness fixture");
    std::vector<uint8_t> tx;
    tx.reserve(stripped.size() + 2 + inputs.size() * 3);
    tx.insert(tx.end(), stripped.begin(), stripped.begin() + 4);
    tx.push_back(0x00);
    tx.push_back(0x01);
    tx.insert(tx.end(), stripped.begin() + 4, stripped.end() - 4);
    for (size_t i = 0; i < inputs.size(); ++i) {
        tx.push_back(0x01); // one witness stack item
        tx.push_back(0x01); // one-byte item
        tx.push_back(static_cast<uint8_t>(i + 1));
    }
    tx.insert(tx.end(), stripped.end() - 4, stripped.end());
    btcspv::WitnessAwareBtcTx parsed;
    if (!btcspv::ParseWitnessAwareBtcTx(tx, parsed) || !parsed.has_witness ||
        parsed.txid != Hash256d(stripped) || parsed.txid == Hash256d(tx))
        throw std::runtime_error("witness fixture txid mismatch");
    return tx;
}

std::vector<uint8_t> MakeFundingParent(uint64_t value, const std::vector<uint8_t>& script,
                                       const std::string& recipient = {}) {
    static uint64_t sequence = 1;
    const Hash256 fake = TaggedHash("external-funding-" + std::to_string(sequence++));
    std::vector<btcspv::BtcTxOut> outputs{{value, script}};
    if (!recipient.empty())
        outputs.push_back({0, BitcoinOpReturn(std::string("btcVELD:") + recipient)});
    return MakeBitcoinTx({{fake, 0}}, outputs);
}

struct BitcoinHistory {
    struct Node {
        Hash256 parent{};
        uint32_t height = 0;
        uint32_t time = 0;
    };

    btcspv::BtcHeaderChain chain;
    std::map<Hash256, Node> nodes;
    Hash256 tip{};
    uint64_t dummy_counter = 0;

    BitcoinHistory()
        : chain(BtcVeldCheckpoint(), BtcVeldPowLimit(), 2016, 1209600, BtcVeldNoRetarget()) {
        const auto cp = BtcVeldCheckpoint();
        tip = cp.hash;
        nodes.emplace(cp.hash, Node{Hash256{}, cp.height, cp.time});
    }

    Hash256 MineOn(const Hash256& parent, const Hash256& merkle) {
        auto parent_it = nodes.find(parent);
        CHECK(parent_it != nodes.end());
        std::array<uint8_t, 80> header{};
        PutU32(header, 0, 1);
        std::copy(parent.begin(), parent.end(), header.begin() + 4);
        std::copy(merkle.begin(), merkle.end(), header.begin() + 36);
        const uint32_t time = parent_it->second.time + 1;
        PutU32(header, 68, time);
        PutU32(header, 72, 0x207fffffu);
        bool mined = false;
        for (uint32_t nonce = 0;; ++nonce) {
            PutU32(header, 76, nonce);
            if (btcspv::CheckProofOfWork(header.data(), 0x207fffffu, BtcVeldPowLimit())) {
                mined = true;
                break;
            }
            if (nonce == UINT32_MAX)
                throw std::runtime_error("test Bitcoin header nonce exhausted");
        }
        CHECK(mined);
        const Hash256 block = btcspv::BtcHeaderHash(header.data());
        CHECK(chain.SubmitHeader(header.data(), time + 60));
        nodes.emplace(block, Node{parent, parent_it->second.height + 1, time});
        tip = chain.BestTip();
        return block;
    }

    Hash256 MineTx(const std::vector<uint8_t>& tx) {
        return MineOn(chain.BestTip(), BitcoinTxid(tx));
    }

    Hash256 MineDummyOn(const Hash256& parent) {
        return MineOn(parent, TaggedHash("dummy-bitcoin-block-" + std::to_string(++dummy_counter)));
    }

    void Bury(const Hash256& block, uint32_t depth = BTCVELD_SPV_K_BTC) {
        CHECK(chain.Has(block));
        Hash256 parent = chain.BestTip();
        for (uint32_t i = 0; i < depth; ++i)
            parent = MineDummyOn(parent);
        CHECK(chain.IsFinalForExternalValue(block, depth));
    }

    void ReorgFrom(const Hash256& fork_parent) {
        auto fork = nodes.find(fork_parent);
        CHECK(fork != nodes.end());
        const uint32_t old_best = chain.BestHeight();
        Hash256 cursor = fork_parent;
        const uint32_t required = old_best - fork->second.height + 1;
        for (uint32_t i = 0; i < required; ++i)
            cursor = MineDummyOn(cursor);
        CHECK(chain.BestTip() == cursor);
    }
};

struct TransitionFixture {
    reserve::Claim claim;
    std::vector<uint8_t> proof;
    std::vector<uint8_t> bitcoin_tx;
    std::vector<std::vector<uint8_t>> parents;
    reserve::PayoutContext payout;
};

reserve::Claim PriorClaim(const reserve::State& state, reserve::Operation operation) {
    reserve::Claim claim;
    claim.operation = operation;
    claim.network_binding = reserve::NetworkBinding();
    claim.prior_commitment = state.transition_commitment;
    claim.prior_reserve_txid = state.reserve_txid;
    claim.prior_reserve_vout = state.reserve_vout;
    claim.prior_reserve_value = state.reserve_value_sats;
    claim.prior_transition_count = state.transition_count;
    return claim;
}

void FinalizeFixture(BitcoinHistory& bitcoin, TransitionFixture& fixture,
                     uint32_t burial = BTCVELD_SPV_K_BTC) {
    fixture.claim.bitcoin_tx = fixture.bitcoin_tx;
    fixture.claim.direct_parents = fixture.parents;
    fixture.claim.bitcoin_txid = BitcoinTxid(fixture.bitcoin_tx);
    fixture.claim.bitcoin_block = bitcoin.MineTx(fixture.bitcoin_tx);
    fixture.claim.merkle_branch.clear();
    fixture.claim.merkle_directions = 0;
    if (burial != 0)
        bitcoin.Bury(fixture.claim.bitcoin_block, burial);
    fixture.proof = reserve::EncodeProof(fixture.claim);
    CHECK(!fixture.proof.empty());
}

TransitionFixture MakeOpen(BitcoinHistory& bitcoin, const reserve::State& state,
                           uint64_t reserve_value, uint64_t mint_amount,
                           const std::string& recipient, const btcnull::Proof& witness,
                           uint32_t burial = BTCVELD_SPV_K_BTC,
                           bool witness_serialization = false) {
    TransitionFixture fixture;
    fixture.claim = PriorClaim(state, reserve::Operation::OPEN);
    fixture.claim.new_reserve_vout = 0;
    fixture.claim.new_reserve_value = reserve_value;
    fixture.claim.mint_amount = mint_amount;
    fixture.claim.exact_commitment =
        reserve::detail::OpenDepositCommitment(0, reserve_value, recipient);
    fixture.claim.nullifier_proof = witness;
    fixture.claim.has_nullifier_proof = true;
    const auto source = MakeFundingParent(reserve_value + 1000, {0x51});
    fixture.parents = {source};
    const std::vector<std::pair<Hash256, uint32_t>> inputs{{BitcoinTxid(source), 0}};
    const std::vector<btcspv::BtcTxOut> outputs{
        {reserve_value, BtcVeldCustodySpk()},
        {0, reserve::detail::OpenAuthScript(state.transition_commitment, recipient, mint_amount)}};
    fixture.bitcoin_tx = witness_serialization ? MakeWitnessBitcoinTx(inputs, outputs)
                                               : MakeBitcoinTx(inputs, outputs);
    fixture.claim.new_reserve_txid = BitcoinTxid(fixture.bitcoin_tx);
    FinalizeFixture(bitcoin, fixture, burial);
    return fixture;
}

std::vector<uint8_t> MakePendingDeposit(uint64_t value, const std::string& recipient,
                                        bool witness_serialization = false) {
    const auto source = MakeFundingParent(value + 1000, {0x51});
    const std::vector<std::pair<Hash256, uint32_t>> inputs{{BitcoinTxid(source), 0}};
    const std::vector<btcspv::BtcTxOut> outputs{
        {value, BtcVeldCustodySpk()}, {0, BitcoinOpReturn(std::string("btcVELD:") + recipient)}};
    return witness_serialization ? MakeWitnessBitcoinTx(inputs, outputs)
                                 : MakeBitcoinTx(inputs, outputs);
}

TransitionFixture MakeDeposit(BitcoinHistory& bitcoin, const reserve::State& state,
                              const std::vector<uint8_t>& current_reserve_tx,
                              const std::vector<uint8_t>& pending_tx, uint64_t successor_value,
                              uint64_t mint_amount, const btcnull::Proof& witness,
                              bool witness_serialization = false) {
    TransitionFixture fixture;
    fixture.claim = PriorClaim(state, reserve::Operation::DEPOSIT);
    fixture.claim.new_reserve_vout = 0;
    fixture.claim.new_reserve_value = successor_value;
    fixture.claim.mint_amount = mint_amount;
    btcspv::WitnessAwareBtcTx pending;
    CHECK(btcspv::ParseWitnessAwareBtcTx(pending_tx, pending));
    CHECK(!pending.outputs.empty());
    std::string recipient;
    CHECK(reserve::detail::ExtractRecipient(pending.outputs, recipient));
    fixture.claim.exact_commitment = reserve::detail::PendingDepositCommitment(
        pending.txid, 0, pending.outputs[0].value, recipient);
    fixture.claim.nullifier_proof = witness;
    fixture.claim.has_nullifier_proof = true;
    fixture.parents = {current_reserve_tx, pending_tx};
    const std::vector<std::pair<Hash256, uint32_t>> inputs{{state.reserve_txid, state.reserve_vout},
                                                           {pending.txid, 0}};
    const std::vector<btcspv::BtcTxOut> outputs{
        {successor_value, BtcVeldCustodySpk()},
        {0, reserve::detail::AuthScript(reserve::Operation::DEPOSIT, state.transition_commitment,
                                        fixture.claim.exact_commitment, mint_amount)}};
    fixture.bitcoin_tx = witness_serialization ? MakeWitnessBitcoinTx(inputs, outputs)
                                               : MakeBitcoinTx(inputs, outputs);
    fixture.claim.new_reserve_txid = BitcoinTxid(fixture.bitcoin_tx);
    FinalizeFixture(bitcoin, fixture);
    return fixture;
}

TransitionFixture MakeRollover(BitcoinHistory& bitcoin, const reserve::State& state,
                               const std::vector<uint8_t>& current_reserve_tx,
                               bool witness_serialization = false) {
    TransitionFixture fixture;
    fixture.claim = PriorClaim(state, reserve::Operation::ROLLOVER);
    fixture.claim.new_reserve_vout = 0;
    fixture.claim.new_reserve_value = state.reserve_value_sats;
    fixture.parents = {current_reserve_tx};
    const std::vector<std::pair<Hash256, uint32_t>> inputs{
        {state.reserve_txid, state.reserve_vout}};
    const std::vector<btcspv::BtcTxOut> outputs{
        {state.reserve_value_sats, BtcVeldCustodySpk()},
        {0, reserve::detail::AuthScript(reserve::Operation::ROLLOVER, state.transition_commitment,
                                        Hash256{}, 0)}};
    fixture.bitcoin_tx = witness_serialization ? MakeWitnessBitcoinTx(inputs, outputs)
                                               : MakeBitcoinTx(inputs, outputs);
    fixture.claim.new_reserve_txid = BitcoinTxid(fixture.bitcoin_tx);
    FinalizeFixture(bitcoin, fixture);
    return fixture;
}

TransitionFixture MakePayout(BitcoinHistory& bitcoin, const reserve::State& state,
                             const std::vector<uint8_t>& current_reserve_tx, uint64_t principal,
                             const Hash256& request_commitment,
                             const std::vector<uint8_t>& destination,
                             bool include_external_fee_input = true,
                             bool witness_serialization = false) {
    TransitionFixture fixture;
    fixture.claim = PriorClaim(state, reserve::Operation::PAYOUT);
    fixture.claim.exact_commitment = request_commitment;
    const uint64_t successor = state.reserve_value_sats - principal;
    fixture.claim.new_reserve_value = successor;
    fixture.claim.new_reserve_vout = successor == 0 ? reserve::NO_VOUT : 0;
    fixture.payout.present = true;
    fixture.payout.request_id = TaggedHash("payout-request-id");
    fixture.payout.request_commitment = request_commitment;
    fixture.payout.principal_sats = principal;
    fixture.payout.destination_spk = destination;

    std::vector<std::pair<Hash256, uint32_t>> inputs{{state.reserve_txid, state.reserve_vout}};
    fixture.parents = {current_reserve_tx};
    if (include_external_fee_input) {
        const auto fee_parent = MakeFundingParent(1000, {0x51});
        inputs.push_back({BitcoinTxid(fee_parent), 0});
        fixture.parents.push_back(fee_parent);
    }
    std::vector<btcspv::BtcTxOut> outputs;
    const uint64_t successor_output =
        !include_external_fee_input && successor >= 100 ? successor - 100 : successor;
    if (successor != 0)
        outputs.push_back({successor_output, BtcVeldCustodySpk()});
    outputs.push_back({principal, destination});
    outputs.push_back(
        {0, reserve::detail::AuthScript(reserve::Operation::PAYOUT, state.transition_commitment,
                                        request_commitment, 0)});
    fixture.bitcoin_tx = witness_serialization ? MakeWitnessBitcoinTx(inputs, outputs)
                                               : MakeBitcoinTx(inputs, outputs);
    fixture.claim.new_reserve_txid = successor == 0 ? Hash256{} : BitcoinTxid(fixture.bitcoin_tx);
    FinalizeFixture(bitcoin, fixture);
    return fixture;
}

std::vector<uint8_t> Fsp2Proof(const TransitionFixture& fixture) {
    std::vector<uint8_t> proof{'F', 'S', 'P', '2'};
    auto put_u16 = [&proof](uint16_t value) {
        proof.push_back(static_cast<uint8_t>(value));
        proof.push_back(static_cast<uint8_t>(value >> 8));
    };
    auto put_u32 = [&proof](uint32_t value) {
        for (unsigned i = 0; i < 4; ++i)
            proof.push_back(static_cast<uint8_t>(value >> (8 * i)));
    };
    proof.insert(proof.end(), fixture.claim.bitcoin_block.begin(),
                 fixture.claim.bitcoin_block.end());
    put_u32(static_cast<uint32_t>(fixture.claim.merkle_directions));
    proof.push_back(static_cast<uint8_t>(fixture.claim.merkle_branch.size()));
    for (const auto& sibling : fixture.claim.merkle_branch)
        proof.insert(proof.end(), sibling.begin(), sibling.end());
    put_u32(static_cast<uint32_t>(fixture.bitcoin_tx.size()));
    proof.insert(proof.end(), fixture.bitcoin_tx.begin(), fixture.bitcoin_tx.end());
    put_u16(static_cast<uint16_t>(fixture.parents.size()));
    for (const auto& parent : fixture.parents) {
        put_u32(static_cast<uint32_t>(parent.size()));
        proof.insert(proof.end(), parent.begin(), parent.end());
    }
    return proof;
}

TransitionFixture MakeClose(BitcoinHistory& bitcoin, const reserve::State& state,
                            const std::vector<uint8_t>& current_reserve_tx) {
    TransitionFixture fixture;
    fixture.claim = PriorClaim(state, reserve::Operation::CLOSE);
    fixture.claim.new_reserve_vout = reserve::NO_VOUT;
    fixture.parents = {current_reserve_tx};
    fixture.bitcoin_tx = MakeBitcoinTx(
        {{state.reserve_txid, state.reserve_vout}},
        {{state.reserve_value_sats, {0x51}},
         {0, reserve::detail::AuthScript(reserve::Operation::CLOSE, state.transition_commitment,
                                         Hash256{}, 0)}});
    FinalizeFixture(bitcoin, fixture);
    return fixture;
}

struct TestLedger {
    struct NullifierEvent {
        Hash256 old_root{};
        Hash256 new_root{};
        std::string outpoint;
        btcnull::Proof proof;
    };

    reserve::State state;
    uint64_t supply = 0;
    Hash256 nullifier_root = btcnull::EmptyRoot();
    std::vector<NullifierEvent> nullifier_events;
    std::map<std::string, uint64_t> balances;
    std::vector<uint8_t> current_reserve_tx;
    uint64_t veld_height = 0;

    btcnull::Proof WitnessFor(const std::string& outpoint) const {
        btcnull::Proof proof = btcnull::EmptyProof();
        bool occupied = false;
        for (const auto& event : nullifier_events) {
            CHECK(btcnull::UpdateWitnessAfterInsert(event.old_root, event.new_root, outpoint,
                                                    occupied, proof, event.outpoint, event.proof));
        }
        CHECK(!occupied);
        CHECK(btcnull::Verify(nullifier_root, outpoint, false, proof));
        return proof;
    }

    Hash256 CompleteDigest() const {
        std::vector<uint8_t> body = reserve::EncodeState(state);
        body.insert(body.end(), nullifier_root.begin(), nullifier_root.end());
        state_digest::put_u64_le(body, supply);
        state_digest::put_u64_le(body, veld_height);
        for (const auto& item : balances) {
            state_digest::put_len_prefixed(body, item.first);
            state_digest::put_u64_le(body, item.second);
        }
        return state_digest::sha256_domain("VELD/SECURITY_TEST/PURPOSE_BUILT_COMPLETE_STATE/v1",
                                           body);
    }

    bool Apply(BitcoinHistory& bitcoin, const TransitionFixture& fixture) {
        const Hash256 before = CompleteDigest();
        const auto verified = reserve::Verify(
            bitcoin.chain, state, supply, fixture.proof.data(), fixture.proof.size(),
            BtcVeldCustodySpk(), BTCVELD_SPV_K_BTC,
            [](const std::string& address) {
                return address == RECIPIENT || address == RECIPIENT_2;
            },
            fixture.payout);
        if (!verified.ok) {
            CHECK(CompleteDigest() == before);
            return false;
        }
        if (supply > UINT64_MAX - verified.claim.mint_amount)
            return false;
        const uint64_t next_supply = supply + verified.claim.mint_amount;
        reserve::State next_state = state;
        if (!reserve::ApplyAuthorized(next_state, verified, supply, next_supply))
            return false;

        btcnull::InsertResult insertion;
        const bool consumes_deposit = verified.claim.operation == reserve::Operation::OPEN ||
                                      verified.claim.operation == reserve::Operation::DEPOSIT;
        if (consumes_deposit) {
            insertion = btcnull::Insert(nullifier_root, verified.pending_outpoint,
                                        verified.claim.nullifier_proof);
            if (!insertion.ok)
                return false;
        }
        if (verified.claim.mint_amount != 0)
            balances[verified.recipient] += verified.claim.mint_amount;
        supply = next_supply;
        state = next_state;
        if (consumes_deposit) {
            nullifier_events.push_back(NullifierEvent{insertion.old_root, insertion.new_root,
                                                      verified.pending_outpoint,
                                                      verified.claim.nullifier_proof});
            nullifier_root = insertion.new_root;
        }
        if (state.status == reserve::Status::ACTIVE)
            current_reserve_tx = fixture.bitcoin_tx;
        else
            current_reserve_tx.clear();
        ++veld_height;
        CHECK(reserve::SetProcessed(state, veld_height,
                                    TaggedHash("veld-block-" + std::to_string(veld_height))));
        CHECK(state.AccountingHolds(supply));
        return true;
    }

    bool OpenRedemption(uint64_t amount) {
        if (amount > supply)
            return false;
        reserve::State next = state;
        if (!reserve::OpenRedemption(next, amount, supply - amount))
            return false;
        state = next;
        supply -= amount;
        return state.AccountingHolds(supply);
    }

    bool Compensate(uint64_t amount) {
        reserve::State next = state;
        if (!reserve::ResolveDefaultOrCompensation(next, amount, supply + amount))
            return false;
        state = next;
        supply += amount;
        return state.AccountingHolds(supply);
    }
};

reserve::SpendClassification Classify(const TestLedger& ledger, const std::vector<uint8_t>& tx,
                                      const std::vector<std::vector<uint8_t>>& parents,
                                      const reserve::PayoutContext& payout = {}) {
    reserve::PayoutLookup lookup;
    if (payout.present) {
        lookup = [&payout](const Hash256& commitment, reserve::PayoutContext& found) {
            if (commitment != payout.request_commitment)
                return false;
            found = payout;
            return true;
        };
    }
    return reserve::ClassifyBitcoinReserveSpend(
        ledger.state, ledger.supply, tx, parents, BtcVeldCustodySpk(),
        [](const std::string& address) { return address == RECIPIENT || address == RECIPIENT_2; },
        lookup);
}

Transaction ReserveCarrier(const TransitionFixture& fixture) {
    Transaction tx;
    tx.inputs.push_back(TxInput::Coinbase("security-test-reserve-carrier"));
    const std::string payload =
        std::string(reserve::PUBLIC_CARRIER_PREFIX) + BytesToHex(fixture.proof);
    tx.outputs.emplace_back(0, BuildOpReturnScript(payload));
    return tx;
}

Transaction IssuerReserveCarrier(const TransitionFixture& fixture,
                                 const std::string& recipient = RECIPIENT) {
    Transaction tx;
    tx.inputs.push_back(TxInput::Coinbase("security-test-reserve-issuer"));
    TokenOpData op;
    op.action = "MINT";
    op.token_id = BTCVELD_TOKEN_ID;
    op.from = BTCVELD_ISSUER_ADDRESS;
    op.to = recipient;
    op.amount = static_cast<int64_t>(fixture.claim.mint_amount);
    op.memo = std::string(reserve::ISSUER_MEMO_PREFIX) + BytesToHex(fixture.proof);
    tx.outputs.emplace_back(0, BuildOpReturnScript(EncodeTokenOp(op)));
    return tx;
}

Transaction RawCarrier(const std::string& payload) {
    Transaction tx;
    tx.inputs.push_back(TxInput::Coinbase("security-test-raw-carrier"));
    tx.outputs.emplace_back(0, BuildOpReturnScript(payload));
    return tx;
}

Transaction SignedTokenCarrier(const TokenOpData& op, const RealKeyPair& signer,
                               const std::string& nonce) {
    Transaction tx;
    TxInput input;
    input.prev_tx_hash = TaggedHash("security-test-token-input-" + nonce);
    input.prev_out_index = 0;
    tx.inputs.push_back(input);
    tx.outputs.emplace_back(0, BuildOpReturnScript(EncodeTokenOp(op)));
    tx.inputs[0].script_sig = signer.SignInput(tx, 0, signer.GetP2PKHScript()).script_sig;
    tx.InvalidateTxIDCache();
    CHECK(TxVerifiedSignedBy(tx, signer.address));
    return tx;
}

btcveld::RedeemRequest RequestFromRedeem(const TokenTransferRecord& record,
                                         const Transaction& transaction,
                                         uint64_t bitcoin_observed_height) {
    CHECK(record.is_redeem);
    CHECK(record.txid == HashToHex(transaction.GetTxID()));
    btcveld::RedeemRequest request;
    request.request_id = transaction.GetTxID();
    request.amount_sats = static_cast<uint64_t>(record.amount);
    request.dest_spk = HexToBytes(record.memo);
    request.request_height = record.block_height;
    request.deadline_height = record.block_height + BTCVELD_REDEEM_SLA;
    request.status = btcveld::ReqStatus::LOCKED_IN;
    request.veld_recipient = record.from;
    request.btc_observed_height = bitcoin_observed_height;
    request.request_commitment = btcveld::SignerBondCovenant::RequestCommitment(request);
    return request;
}

Block TransactionsBlock(uint64_t height, const std::vector<Transaction>& transactions,
                        const std::string& branch = "canonical") {
    Block block;
    block.height = height;
    block.header.version = 1;
    block.header.prev_block_hash =
        TaggedHash("production-ledger-parent-" + branch + "-" + std::to_string(height));
    block.header.timestamp = 1700000000 + height;
    block.header.bits = 0x207fffffu;
    block.header.nonce = height;
    block.transactions = transactions;
    block.UpdateMerkleRoot();
    return block;
}

Block ReserveBlock(uint64_t height, const std::vector<TransitionFixture>& fixtures) {
    std::vector<Transaction> transactions;
    for (const auto& fixture : fixtures)
        transactions.push_back(ReserveCarrier(fixture));
    return TransactionsBlock(height, transactions);
}

Hash256 CompleteNodeEnvelope(const OnChainTokenLedger& tokens,
                             const btcspv::BtcHeaderChain& bitcoin,
                             const btcveld::SignerBondCovenant& covenant, uint64_t height,
                             const Hash256& tip) {
    const Hash256 zero = TaggedHash("security-test-empty-component");
    return state_digest::ComposeV8(height, tip, zero, zero, zero, zero, zero, tokens.Digest(), zero,
                                   zero, zero, bitcoin.StateDigest(), zero, zero,
                                   state_digest::FinalityDigest(0, 0, 0), covenant.Digest());
}

} // namespace

int main() {
    try {
        CHECK(reserve::TRANSITION_V1_REQUIRED);
        CHECK(!BtcVeldCustodySpk().empty());
        CHECK(IsCanonicalTokenCreditAddress(RECIPIENT));
        CHECK(IsCanonicalTokenCreditAddress(RECIPIENT_2));

        // Case 32: fresh-genesis deterministic empty state and digest equality.
        TestLedger fresh_a;
        TestLedger fresh_b;
        CHECK(fresh_a.state.status == reserve::Status::EMPTY);
        CHECK(fresh_a.state.Canonical());
        CHECK(fresh_a.state.AccountingHolds(0));
        CHECK(fresh_a.CompleteDigest() == fresh_b.CompleteDigest());
        CHECK(reserve::Digest(fresh_a.state) == reserve::Digest(fresh_b.state));

        BitcoinHistory fresh_bitcoin_a;
        BitcoinHistory fresh_bitcoin_b;
        OnChainTokenLedger fresh_tokens_a;
        OnChainTokenLedger fresh_tokens_b;
        btcveld::SignerBondCovenant fresh_covenant_a;
        btcveld::SignerBondCovenant fresh_covenant_b;
        CHECK(CompleteNodeEnvelope(fresh_tokens_a, fresh_bitcoin_a.chain, fresh_covenant_a, 0,
                                   Hash256{}) ==
              CompleteNodeEnvelope(fresh_tokens_b, fresh_bitcoin_b.chain, fresh_covenant_b, 0,
                                   Hash256{}));

        BitcoinHistory bitcoin;
        TestLedger ledger;
        std::vector<TransitionFixture> canonical_history;

        // Case 1: a genuine external Bitcoin input opens the sole reserve and
        // mints no more than the proven reserve value.
        auto open =
            MakeOpen(bitcoin, ledger.state, 100000, 100000, RECIPIENT, btcnull::EmptyProof());
        reserve::Claim decoded_open;
        CHECK(reserve::DecodeProof(open.proof.data(), open.proof.size(), decoded_open));
        CHECK(reserve::EncodeProof(decoded_open) == open.proof);
        std::vector<btcspv::BtcTxOut> open_outputs;
        CHECK(btcspv::ParseBtcTxOutputs(open.bitcoin_tx.data(), open.bitcoin_tx.size(),
                                        open_outputs));
        CHECK(open_outputs.size() == 2);
        CHECK(open_outputs[1].spk.size() == 82);
        CHECK(open_outputs[1].spk.size() <= reserve::MAX_STANDARD_NULL_DATA_SCRIPT_BYTES);
        reserve::detail::AuthMarker open_marker;
        CHECK(reserve::detail::ParseAuthMarker(open_outputs[1], open_marker));
        CHECK(open_marker.operation == reserve::Operation::OPEN);
        CHECK(open_marker.open_recipient == RECIPIENT);
        CHECK(reserve::detail::AuthScript(reserve::Operation::OPEN,
                                          ledger.state.transition_commitment,
                                          open.claim.exact_commitment, 100000)
                  .empty());
        auto legacy_open_auth = reserve::detail::AuthScript(reserve::Operation::ROLLOVER,
                                                            ledger.state.transition_commitment,
                                                            open.claim.exact_commitment, 100000);
        CHECK(legacy_open_auth.size() == 80);
        legacy_open_auth[7] = static_cast<uint8_t>(reserve::Operation::OPEN);
        CHECK(
            !reserve::detail::ParseAuthMarker(btcspv::BtcTxOut{0, legacy_open_auth}, open_marker));
        auto trailing_open_auth = open_outputs[1];
        trailing_open_auth.spk.push_back(0);
        CHECK(!reserve::detail::ParseAuthMarker(trailing_open_auth, open_marker));
        const auto nonstandard_open =
            MakeBitcoinTx({{Hash256d(open.parents[0]), 0}},
                          {{100000, BtcVeldCustodySpk()},
                           {0, BitcoinOpReturn(std::string("btcVELD:") + RECIPIENT)},
                           {0, reserve::detail::OpenAuthScript(ledger.state.transition_commitment,
                                                               RECIPIENT, 100000)}});
        CHECK(Classify(ledger, nonstandard_open, open.parents).disposition !=
              reserve::SpendDisposition::AUTHORIZED_TRANSITION);

        // Cases 14, 27 and 30: both relay interfaces consume identical RTP1
        // bytes; the verified recipient comes only from the Bitcoin deposit.
        const auto public_result =
            reserve::Verify(bitcoin.chain, ledger.state, ledger.supply, open.proof.data(),
                            open.proof.size(), BtcVeldCustodySpk(), BTCVELD_SPV_K_BTC,
                            [](const std::string& a) { return a == RECIPIENT; });
        const auto issuer_result =
            reserve::Verify(bitcoin.chain, ledger.state, ledger.supply, open.proof.data(),
                            open.proof.size(), BtcVeldCustodySpk(), BTCVELD_SPV_K_BTC,
                            [](const std::string& a) { return a == RECIPIENT; });
        CHECK(public_result.ok && issuer_result.ok);
        CHECK(public_result.recipient == RECIPIENT);
        CHECK(public_result.recipient == issuer_result.recipient);
        CHECK(public_result.claim.bitcoin_txid == issuer_result.claim.bitcoin_txid);
        CHECK(public_result.claim.mint_amount == 100000);
        canonical_history.push_back(open);
        CHECK(ledger.Apply(bitcoin, open));
        CHECK(ledger.supply == 100000);
        CHECK(ledger.state.reserve_value_sats == 100000);
        CHECK(ledger.state.surplus_sats == 0);

        // Case 2: direct reserve rollover consumes the exact canonical
        // outpoint, creates one successor, and cannot change supply.
        const uint64_t supply_before_rollover = ledger.supply;
        auto rollover = MakeRollover(bitcoin, ledger.state, ledger.current_reserve_tx);
        CHECK(Classify(ledger, rollover.bitcoin_tx, rollover.parents).disposition ==
              reserve::SpendDisposition::AUTHORIZED_TRANSITION);
        canonical_history.push_back(rollover);
        CHECK(ledger.Apply(bitcoin, rollover));
        CHECK(ledger.supply == supply_before_rollover);

        // Cases 5-8: split, merge, mixed-value, and laundering attempts all
        // encounter the current reserve classifier before any later custody
        // output can be treated as a deposit.
        const TestLedger represented_base = ledger;
        const auto current_parent = represented_base.current_reserve_tx;
        const auto current_txid = represented_base.state.reserve_txid;
        const uint32_t current_vout = represented_base.state.reserve_vout;

        const auto split =
            MakeBitcoinTx({{current_txid, current_vout}},
                          {{50000, BtcVeldCustodySpk()},
                           {50000, BtcVeldCustodySpk()},
                           {0, reserve::detail::AuthScript(
                                   reserve::Operation::ROLLOVER,
                                   represented_base.state.transition_commitment, Hash256{}, 0)}});
        CHECK(Classify(represented_base, split, {current_parent}).disposition ==
              reserve::SpendDisposition::UNAUTHORIZED_SPEND);

        const auto external = MakeFundingParent(1000, {0x51});
        const auto merge =
            MakeBitcoinTx({{current_txid, current_vout}, {Hash256d(external), 0}},
                          {{100500, BtcVeldCustodySpk()},
                           {0, reserve::detail::AuthScript(
                                   reserve::Operation::ROLLOVER,
                                   represented_base.state.transition_commitment, Hash256{}, 0)}});
        CHECK(Classify(represented_base, merge, {current_parent, external}).disposition ==
              reserve::SpendDisposition::UNAUTHORIZED_SPEND);

        std::vector<uint8_t> laundering_parent =
            MakeBitcoinTx({{current_txid, current_vout}}, {{99500, {0x51}}});
        auto laundering_class = Classify(represented_base, laundering_parent, {current_parent});
        CHECK(laundering_class.disposition == reserve::SpendDisposition::UNAUTHORIZED_SPEND);
        TestLedger frozen = represented_base;
        CHECK(reserve::ApplyFreeze(frozen.state, Hash256d(laundering_parent),
                                   TaggedHash("laundering-spend-block")));
        const uint64_t frozen_supply = frozen.supply;
        for (int hop = 0; hop < 6; ++hop) {
            const auto next = MakeBitcoinTx({{Hash256d(laundering_parent), 0}},
                                            {{static_cast<uint64_t>(99000 - hop * 100), {0x51}}});
            laundering_parent = next;
        }
        const auto return_to_custody =
            MakeBitcoinTx({{Hash256d(laundering_parent), 0}},
                          {{98000, BtcVeldCustodySpk()},
                           {0, BitcoinOpReturn(std::string("btcVELD:") + RECIPIENT_2)}});
        CHECK(Classify(frozen, return_to_custody, {laundering_parent}).disposition ==
              reserve::SpendDisposition::NOT_CURRENT_RESERVE);
        std::vector<uint8_t> cycle_parent = return_to_custody;
        for (int cycle = 0; cycle < 3; ++cycle) {
            const auto ordinary_again =
                MakeBitcoinTx({{Hash256d(cycle_parent), 0}},
                              {{static_cast<uint64_t>(97500 - cycle * 500), {0x51}}});
            const auto custody_again =
                MakeBitcoinTx({{Hash256d(ordinary_again), 0}},
                              {{static_cast<uint64_t>(97000 - cycle * 500), BtcVeldCustodySpk()},
                               {0, BitcoinOpReturn(std::string("btcVELD:") + RECIPIENT_2)}});
            CHECK(Classify(frozen, custody_again, {ordinary_again}).disposition ==
                  reserve::SpendDisposition::NOT_CURRENT_RESERVE);
            cycle_parent = custody_again;
        }
        CHECK(frozen.supply == frozen_supply);
        CHECK(frozen.state.status == reserve::Status::FROZEN);
        CHECK(frozen.state.AccountingHolds(frozen.supply));

        // Cases 3, 4 and 7 specifically cover custody -> ordinary -> custody,
        // five ordinary hops, and mixing represented value with new value.
        const auto mixed_new = MakeFundingParent(5000, {0x51});
        const auto mixed_return =
            MakeBitcoinTx({{Hash256d(laundering_parent), 0}, {Hash256d(mixed_new), 0}},
                          {{102000, BtcVeldCustodySpk()},
                           {0, BitcoinOpReturn(std::string("btcVELD:") + RECIPIENT)}});
        CHECK(Classify(frozen, mixed_return, {laundering_parent, mixed_new}).disposition ==
              reserve::SpendDisposition::NOT_CURRENT_RESERVE);
        CHECK(frozen.supply == frozen_supply);

        // Case 6 also covers a represented-value merge directly against the
        // live reserve. It is fraud, not a mintable DEPOSIT.
        CHECK(Classify(represented_base, merge, {current_parent, external}).mint_amount == 0);

        // A new pending deposit is inert until the reserve transaction consumes
        // that exact outpoint. The mint is bounded by reserve growth; one
        // unminted satoshi range becomes explicit surplus.
        const auto pending = MakePendingDeposit(25000, RECIPIENT_2);
        const std::string pending_outpoint = btcspv::BtcDepositOutpointId(Hash256d(pending), 0);
        auto pending_witness = ledger.WitnessFor(pending_outpoint);
        auto deposit = MakeDeposit(bitcoin, ledger.state, ledger.current_reserve_tx, pending,
                                   124000, 24000, pending_witness);
        canonical_history.push_back(deposit);
        const uint64_t before_deposit = ledger.supply;
        CHECK(ledger.Apply(bitcoin, deposit));
        CHECK(ledger.supply - before_deposit == 24000);
        CHECK(ledger.state.reserve_value_sats == 124000);
        CHECK(ledger.state.surplus_sats == 0);

        const auto pending_surplus = MakePendingDeposit(10000, RECIPIENT);
        const std::string surplus_outpoint =
            btcspv::BtcDepositOutpointId(Hash256d(pending_surplus), 0);
        auto surplus_witness = ledger.WitnessFor(surplus_outpoint);
        auto deposit_surplus = MakeDeposit(bitcoin, ledger.state, ledger.current_reserve_tx,
                                           pending_surplus, 133000, 8000, surplus_witness);
        canonical_history.push_back(deposit_surplus);
        CHECK(ledger.Apply(bitcoin, deposit_surplus));
        CHECK(ledger.state.surplus_sats == 1000);
        CHECK(ledger.state.AccountingHolds(ledger.supply));

        // Cases 12, 13 and 15: orderly state copy, independent short replay,
        // and cross-node complete digest equality.
        const TestLedger orderly_restart = ledger;
        CHECK(orderly_restart.CompleteDigest() == ledger.CompleteDigest());
        TestLedger replay;
        for (const auto& fixture : canonical_history)
            CHECK(replay.Apply(bitcoin, fixture));
        CHECK(replay.CompleteDigest() == ledger.CompleteDigest());
        CHECK(replay.state.transition_commitment == ledger.state.transition_commitment);
        CHECK(replay.nullifier_root == ledger.nullifier_root);

        // Production OnChainTokenLedger integration: public RTP1 carrier,
        // ProcessBlock state publication, snapshots, preview/mempool parity,
        // rejection rollback, reset, and independent replay.
        const BtcVeldPegGateState peg_gate{true, true, true};
        OnChainTokenLedger production;
        production.SetBtcHeaderChain(&bitcoin.chain);
        uint64_t production_height = 1;
        size_t production_index = 0;
        for (const auto& fixture : canonical_history) {
            const Block block = ReserveBlock(production_height++, {fixture});
            if (!production.ProcessBlock(block, peg_gate)) {
                const auto diagnostic = reserve::Verify(
                    bitcoin.chain, production.GetBtcVeldReserveState(),
                    static_cast<uint64_t>(production.GetSupply(BTCVELD_TOKEN_ID)),
                    fixture.proof.data(), fixture.proof.size(), BtcVeldCustodySpk(),
                    BTCVELD_SPV_K_BTC,
                    [](const std::string& address) {
                        return address == RECIPIENT || address == RECIPIENT_2;
                    },
                    fixture.payout);
                const auto accumulator = production.GetBtcVeldMintAccumulator();
                const auto insertion =
                    diagnostic.ok ? btcnull::Insert(accumulator.root, diagnostic.pending_outpoint,
                                                    diagnostic.claim.nullifier_proof)
                                  : btcnull::InsertResult{};
                throw std::runtime_error("production ledger rejected canonical fixture " +
                                         std::to_string(production_index) + ": " +
                                         diagnostic.reason +
                                         " verify=" + (diagnostic.ok ? "ok" : "fail") +
                                         " nullifier=" + (insertion.ok ? "ok" : "fail"));
            }
            ++production_index;
        }
        CHECK(production.GetSupply(BTCVELD_TOKEN_ID) == static_cast<int64_t>(ledger.supply));
        CHECK(production.GetBtcVeldReserveState().reserve_value_sats ==
              ledger.state.reserve_value_sats);
        CHECK(production.GetBtcVeldReserveState().surplus_sats == ledger.state.surplus_sats);
        CHECK(production.GetBtcVeldReserveState().transition_commitment ==
              ledger.state.transition_commitment);

        const auto production_snapshot = production.SnapshotState();
        const Hash256 production_digest = production.Digest();
        OnChainTokenLedger production_copy;
        production_copy.SetBtcHeaderChain(&bitcoin.chain);
        production_copy.RestoreState(production_snapshot);
        CHECK(production_copy.Digest() == production_digest);

        OnChainTokenLedger production_replay;
        production_replay.SetBtcHeaderChain(&bitcoin.chain);
        production_height = 1;
        for (const auto& fixture : canonical_history)
            CHECK(production_replay.ProcessBlock(ReserveBlock(production_height++, {fixture}),
                                                 peg_gate));
        CHECK(production_replay.Digest() == production.Digest());
        btcveld::SignerBondCovenant production_covenant_a;
        btcveld::SignerBondCovenant production_covenant_b;
        const auto production_state = production.GetBtcVeldReserveState();
        const auto production_replay_state = production_replay.GetBtcVeldReserveState();
        CHECK(CompleteNodeEnvelope(production, bitcoin.chain, production_covenant_a,
                                   production_state.processed_veld_height,
                                   production_state.processed_veld_block_hash) ==
              CompleteNodeEnvelope(production_replay, bitcoin.chain, production_covenant_b,
                                   production_replay_state.processed_veld_height,
                                   production_replay_state.processed_veld_block_hash));

        // Cases 14 and 30 at the production interface: permissionless RTP1
        // and pre-authorized issuer RTP1 both invoke the same verifier.  The
        // wrapper cannot supply a different amount or recipient.
        OnChainTokenLedger public_interface;
        OnChainTokenLedger issuer_interface;
        public_interface.SetBtcHeaderChain(&bitcoin.chain);
        issuer_interface.SetBtcHeaderChain(&bitcoin.chain);
        const Transaction public_open = ReserveCarrier(open);
        const Transaction issuer_open = IssuerReserveCarrier(open);
        CHECK(public_interface.ValidateMempoolCandidate(public_open, 1, 0x207fffffu, peg_gate));
        const auto issuer_accepted = issuer_interface.FilterMempoolCandidates(
            {issuer_open}, 1, 0x207fffffu, peg_gate, {true});
        CHECK(issuer_accepted.size() == 1 && issuer_accepted[0]);
        const auto redirected = issuer_interface.FilterMempoolCandidates(
            {IssuerReserveCarrier(open, RECIPIENT_2)}, 1, 0x207fffffu, peg_gate, {true});
        CHECK(redirected.size() == 1 && !redirected[0]);
        TransitionFixture wrong_amount = open;
        ++wrong_amount.claim.mint_amount;
        const auto amount_mismatch = issuer_interface.FilterMempoolCandidates(
            {IssuerReserveCarrier(wrong_amount)}, 1, 0x207fffffu, peg_gate, {true});
        CHECK(amount_mismatch.size() == 1 && !amount_mismatch[0]);

        auto preview_next = MakeRollover(bitcoin, ledger.state, ledger.current_reserve_tx);
        const Transaction preview_tx = ReserveCarrier(preview_next);
        CHECK(production.ValidateMempoolCandidate(preview_tx, production_height, 0x207fffffu,
                                                  peg_gate));
        OnChainTokenLedger post_block_preview;
        CHECK(production.BuildPostBlockPreview(ReserveBlock(production_height, {preview_next}),
                                               peg_gate, post_block_preview));
        CHECK(post_block_preview.GetBtcVeldReserveState().transition_commitment ==
              reserve::detail::TransitionCommitment(preview_next.claim));
        CHECK(production.Digest() == production_digest);

        const Block two_carrier_block =
            ReserveBlock(production_height, {preview_next, preview_next});
        CHECK(!production.ProcessBlock(two_carrier_block, peg_gate));
        CHECK(production.Digest() == production_digest);

        production.Reset();
        CHECK(production.GetSupply(BTCVELD_TOKEN_ID) == 0);
        CHECK(production.GetBtcVeldReserveState().status == reserve::Status::EMPTY);
        production.SetBtcHeaderChain(&bitcoin.chain);
        production_height = 1;
        for (const auto& fixture : canonical_history)
            CHECK(production.ProcessBlock(ReserveBlock(production_height++, {fixture}), peg_gate));
        CHECK(production.Digest() == production_digest);

        // Cases 16-18: competing/stale transitions and two reserve edges in one
        // Veld block are rejected without changing the parent frame.
        TestLedger competing_parent = ledger;
        auto competing_a =
            MakeRollover(bitcoin, competing_parent.state, competing_parent.current_reserve_tx);
        auto competing_b =
            MakeRollover(bitcoin, competing_parent.state, competing_parent.current_reserve_tx);
        TestLedger competing_winner = competing_parent;
        CHECK(competing_winner.Apply(bitcoin, competing_a));
        const Hash256 winner_digest = competing_winner.CompleteDigest();
        CHECK(!competing_winner.Apply(bitcoin, competing_b));
        CHECK(competing_winner.CompleteDigest() == winner_digest);
        TestLedger two_in_one = competing_parent;
        const Hash256 batch_parent_digest = two_in_one.CompleteDigest();
        const bool batch_ok =
            two_in_one.Apply(bitcoin, competing_a) && two_in_one.Apply(bitcoin, competing_b);
        CHECK(!batch_ok);
        two_in_one = competing_parent; // atomic Veld-block rollback
        CHECK(two_in_one.CompleteDigest() == batch_parent_digest);

        // Cases 19 and 20: FSP2-first classification of a valid transaction is
        // never fraud.  The ingress path below applies the same transition;
        // ordering cannot make one Bitcoin transaction both valid and a
        // freeze.
        TestLedger fsp_first = competing_parent;
        const auto valid_classification =
            Classify(fsp_first, competing_a.bitcoin_tx, competing_a.parents);
        CHECK(valid_classification.disposition == reserve::SpendDisposition::AUTHORIZED_TRANSITION);
        const Hash256 fsp_before = fsp_first.CompleteDigest();
        CHECK(fsp_first.CompleteDigest() == fsp_before);
        CHECK(fsp_first.Apply(bitcoin, competing_a));
        CHECK(Classify(fsp_first, competing_a.bitcoin_tx, competing_a.parents).disposition ==
              reserve::SpendDisposition::NOT_CURRENT_RESERVE);

        // FSP2's outer parser permits a broader generic parent count, but the
        // shared reserve classifier must enforce RTP1's exact eight-parent
        // grammar.  An over-wide signer spend is unauthorized/freezeable; it
        // can never enter the FSP2 authorized-payout fallback and then fail
        // only while reconstructing RTP1.
        TestLedger overwide = competing_parent;
        CHECK(overwide.OpenRedemption(1000));
        const Hash256 overwide_commitment = TaggedHash("overwide-fsp2-payout");
        const std::vector<uint8_t> overwide_destination{0x51, 0x33};
        reserve::PayoutContext overwide_context;
        overwide_context.present = true;
        overwide_context.request_id = TaggedHash("overwide-request");
        overwide_context.request_commitment = overwide_commitment;
        overwide_context.principal_sats = 1000;
        overwide_context.destination_spk = overwide_destination;
        std::vector<std::pair<Hash256, uint32_t>> overwide_inputs{
            {overwide.state.reserve_txid, overwide.state.reserve_vout}};
        std::vector<std::vector<uint8_t>> overwide_parents{overwide.current_reserve_tx};
        for (size_t i = 0; i < reserve::MAX_DIRECT_INPUTS; ++i) {
            const auto parent = MakeFundingParent(100, {0x51});
            overwide_inputs.push_back({Hash256d(parent), 0});
            overwide_parents.push_back(parent);
        }
        const std::vector<uint8_t> overwide_tx = MakeBitcoinTx(
            overwide_inputs, {{overwide.state.reserve_value_sats - 1000, BtcVeldCustodySpk()},
                              {1000, overwide_destination},
                              {0, reserve::detail::AuthScript(reserve::Operation::PAYOUT,
                                                              overwide.state.transition_commitment,
                                                              overwide_commitment, 0)}});
        CHECK(overwide_parents.size() == reserve::MAX_DIRECT_INPUTS + 1);
        CHECK(Classify(overwide, overwide_tx, overwide_parents, overwide_context).disposition ==
              reserve::SpendDisposition::UNAUTHORIZED_SPEND);

        TestLedger fraud_first = competing_parent;
        const auto theft =
            MakeBitcoinTx({{fraud_first.state.reserve_txid, fraud_first.state.reserve_vout}},
                          {{fraud_first.state.reserve_value_sats - 100, {0x51}}});
        CHECK(Classify(fraud_first, theft, {fraud_first.current_reserve_tx}).disposition ==
              reserve::SpendDisposition::UNAUTHORIZED_SPEND);
        CHECK(reserve::ApplyFreeze(fraud_first.state, Hash256d(theft),
                                   TaggedHash("fraud-first-block")));
        CHECK(!fraud_first.Apply(bitcoin, competing_a));
        CHECK(fraud_first.state.status == reserve::Status::FROZEN);

        // Case 26: a Bitcoin successor seen before its predecessor is accepted
        // on Veld is stale against the canonical prior; after predecessor
        // acceptance it becomes the one permitted next edge.
        TestLedger predecessor_parent = competing_parent;
        const auto predecessor_result =
            reserve::Verify(bitcoin.chain, predecessor_parent.state, predecessor_parent.supply,
                            competing_a.proof.data(), competing_a.proof.size(), BtcVeldCustodySpk(),
                            BTCVELD_SPV_K_BTC, [](const std::string&) { return true; });
        CHECK(predecessor_result.ok);
        reserve::State post_predecessor = predecessor_parent.state;
        CHECK(reserve::ApplyAuthorized(post_predecessor, predecessor_result,
                                       predecessor_parent.supply, predecessor_parent.supply));
        auto successor = MakeRollover(bitcoin, post_predecessor, competing_a.bitcoin_tx);
        CHECK(!predecessor_parent.Apply(bitcoin, successor));
        CHECK(predecessor_parent.Apply(bitcoin, competing_a));
        CHECK(predecessor_parent.Apply(bitcoin, successor));

        // Case 9: a rejected reserve-sensitive Veld block leaves every
        // represented state component invariant.
        TestLedger rejected = competing_winner;
        const Hash256 rejected_before = rejected.CompleteDigest();
        CHECK(!rejected.Apply(bitcoin, competing_b));
        CHECK(rejected.CompleteDigest() == rejected_before);

        // Case 10: Veld reorganization restores the exact parent snapshot and
        // deterministically selects the alternative reserve edge.
        TestLedger veld_reorg_parent = competing_parent;
        const TestLedger veld_snapshot = veld_reorg_parent;
        CHECK(veld_reorg_parent.Apply(bitcoin, competing_a));
        veld_reorg_parent = veld_snapshot;
        CHECK(veld_reorg_parent.Apply(bitcoin, competing_b));
        TestLedger independent_alt = veld_snapshot;
        CHECK(independent_alt.Apply(bitcoin, competing_b));
        CHECK(veld_reorg_parent.CompleteDigest() == independent_alt.CompleteDigest());

        // Case 11: a post-acceptance Bitcoin reorganization removes finality
        // for the carrying block and deterministically freezes the bridge.
        BitcoinHistory reorg_bitcoin;
        TestLedger reorg_ledger;
        const Hash256 fork_parent = reorg_bitcoin.chain.BestTip();
        auto reorg_open = MakeOpen(reorg_bitcoin, reorg_ledger.state, 50000, 50000, RECIPIENT,
                                   btcnull::EmptyProof());
        CHECK(reorg_ledger.Apply(reorg_bitcoin, reorg_open));
        CHECK(reorg_bitcoin.chain.IsFinalForExternalValue(reorg_ledger.state.reserve_bitcoin_block,
                                                          BTCVELD_SPV_K_BTC));
        reorg_bitcoin.ReorgFrom(fork_parent);
        CHECK(!reorg_bitcoin.chain.IsFinalForExternalValue(reorg_ledger.state.reserve_bitcoin_block,
                                                           BTCVELD_SPV_K_BTC));
        CHECK(reserve::ApplyFreeze(reorg_ledger.state, reorg_ledger.state.reserve_txid,
                                   reorg_ledger.state.reserve_bitcoin_block));
        CHECK(reorg_ledger.state.status == reserve::Status::FROZEN);
        CHECK(reorg_ledger.state.AccountingHolds(reorg_ledger.supply));

        // The production ledger performs that freeze automatically at the
        // next Veld block boundary; no watchtower submission order is needed.
        BitcoinHistory production_reorg_bitcoin;
        const Hash256 production_reorg_fork = production_reorg_bitcoin.chain.BestTip();
        TestLedger production_reorg_model;
        auto production_reorg_open =
            MakeOpen(production_reorg_bitcoin, production_reorg_model.state, 45000, 45000,
                     RECIPIENT, btcnull::EmptyProof());
        OnChainTokenLedger production_reorg;
        production_reorg.SetBtcHeaderChain(&production_reorg_bitcoin.chain);
        CHECK(production_reorg.ProcessBlock(ReserveBlock(1, {production_reorg_open}), peg_gate));
        production_reorg_bitcoin.ReorgFrom(production_reorg_fork);
        CHECK(production_reorg.ProcessBlock(TransactionsBlock(2, {}, "bitcoin-reorg"), peg_gate));
        CHECK(production_reorg.GetBtcVeldReserveState().status == reserve::Status::FROZEN);
        CHECK(production_reorg.GetBtcVeldReserveState().AccountingHolds(
            static_cast<uint64_t>(production_reorg.GetSupply(BTCVELD_TOKEN_ID))));

        // Case 21: a complete, separately-fee-funded payout reduces reserve by
        // exactly the fulfilled principal and reaches ACTIVE -> EMPTY.
        BitcoinHistory terminal_bitcoin;
        TestLedger terminal;
        auto terminal_open = MakeOpen(terminal_bitcoin, terminal.state, 40000, 40000, RECIPIENT,
                                      btcnull::EmptyProof());
        CHECK(terminal.Apply(terminal_bitcoin, terminal_open));
        CHECK(terminal.OpenRedemption(40000));
        const Hash256 terminal_commitment = TaggedHash("terminal-redemption");
        const std::vector<uint8_t> destination{0x51, 0x21};
        auto terminal_payout =
            MakePayout(terminal_bitcoin, terminal.state, terminal.current_reserve_tx, 40000,
                       terminal_commitment, destination, true);
        std::vector<btcspv::BtcTxOut> payout_outputs;
        CHECK(btcspv::ParseBtcTxOutputs(terminal_payout.bitcoin_tx.data(),
                                        terminal_payout.bitcoin_tx.size(), payout_outputs));
        CHECK(std::count_if(payout_outputs.begin(), payout_outputs.end(),
                            [](const btcspv::BtcTxOut& output) {
                                return !output.spk.empty() && output.spk.front() == 0x6a;
                            }) == 1);
        CHECK(payout_outputs.back().spk.size() <= reserve::MAX_STANDARD_NULL_DATA_SCRIPT_BYTES);
        std::vector<btcspv::BtcPrevout> payout_prevouts;
        CHECK(btcspv::ParseBtcTxPrevouts(terminal_payout.bitcoin_tx.data(),
                                         terminal_payout.bitcoin_tx.size(), payout_prevouts));
        std::vector<std::pair<Hash256, uint32_t>> payout_inputs;
        for (const auto& prevout : payout_prevouts)
            payout_inputs.push_back({prevout.txid, prevout.vout});
        payout_outputs.insert(
            payout_outputs.end() - 1,
            btcspv::BtcTxOut{0, btcveld::RedeemRequestCommitmentScript(terminal_commitment)});
        const auto nonstandard_payout = MakeBitcoinTx(payout_inputs, payout_outputs);
        CHECK(
            Classify(terminal, nonstandard_payout, terminal_payout.parents, terminal_payout.payout)
                .disposition == reserve::SpendDisposition::UNAUTHORIZED_SPEND);
        CHECK(terminal.Apply(terminal_bitcoin, terminal_payout));
        CHECK(terminal.state.status == reserve::Status::EMPTY);
        CHECK(terminal.supply == 0);
        CHECK(terminal.state.open_redemption_principal == 0);

        // A surplus-only reserve closes only after all supply and payout
        // obligations are zero.
        BitcoinHistory close_bitcoin;
        TestLedger close_ledger;
        auto surplus_open =
            MakeOpen(close_bitcoin, close_ledger.state, 5000, 0, RECIPIENT, btcnull::EmptyProof());
        CHECK(close_ledger.Apply(close_bitcoin, surplus_open));
        CHECK(close_ledger.state.surplus_sats == 5000);
        auto close = MakeClose(close_bitcoin, close_ledger.state, close_ledger.current_reserve_tx);
        CHECK(close_ledger.Apply(close_bitcoin, close));
        CHECK(close_ledger.state.status == reserve::Status::EMPTY);

        // Case 23: reducing the successor by a fee while using only the reserve
        // input fails. Fees never silently reduce backing.
        BitcoinHistory fee_bitcoin;
        TestLedger fee_ledger;
        auto fee_open =
            MakeOpen(fee_bitcoin, fee_ledger.state, 30000, 30000, RECIPIENT, btcnull::EmptyProof());
        CHECK(fee_ledger.Apply(fee_bitcoin, fee_open));
        CHECK(fee_ledger.OpenRedemption(10000));
        auto reserve_fee = MakePayout(fee_bitcoin, fee_ledger.state, fee_ledger.current_reserve_tx,
                                      10000, TaggedHash("reserve-fee-attempt"), destination, false);
        const Hash256 fee_before = fee_ledger.CompleteDigest();
        CHECK(!fee_ledger.Apply(fee_bitcoin, reserve_fee));
        CHECK(fee_ledger.CompleteDigest() == fee_before);

        // Case 24: cancellation is impossible after the Veld burn. Default and
        // expiry resolve through exact compensation, swapping obligation back
        // into supply without changing total liabilities.
        TestLedger defaulted = ledger;
        CHECK(defaulted.OpenRedemption(5000));
        CHECK(!reserve::CancelRedemption(defaulted.state, 5000));
        CHECK(defaulted.Compensate(5000));
        CHECK(defaulted.state.open_redemption_principal == 0);
        TestLedger expired = ledger;
        CHECK(expired.OpenRedemption(7000));
        CHECK(expired.Compensate(7000));
        CHECK(expired.CompleteDigest() == ledger.CompleteDigest());

        // Case 22: only one competing first OPEN can consume EMPTY. The loser
        // is stale even when its Bitcoin proof is independently final.
        BitcoinHistory first_open_bitcoin;
        TestLedger first_open_ledger;
        auto first_a = MakeOpen(first_open_bitcoin, first_open_ledger.state, 20000, 20000,
                                RECIPIENT, btcnull::EmptyProof());
        auto first_b = MakeOpen(first_open_bitcoin, first_open_ledger.state, 21000, 21000,
                                RECIPIENT_2, btcnull::EmptyProof());
        CHECK(first_open_ledger.Apply(first_open_bitcoin, first_a));
        const Hash256 first_winner = first_open_ledger.CompleteDigest();
        CHECK(!first_open_ledger.Apply(first_open_bitcoin, first_b));
        CHECK(first_open_ledger.CompleteDigest() == first_winner);

        // Case 25: a pre-finality transaction fails; replacing the relayed
        // Bitcoin branch and then burying the replacement admits only the
        // replacement.
        BitcoinHistory rbf_bitcoin;
        const auto rbf_checkpoint = rbf_bitcoin.chain.SnapshotState();
        TestLedger rbf_ledger;
        auto rbf_original = MakeOpen(rbf_bitcoin, rbf_ledger.state, 12000, 12000, RECIPIENT,
                                     btcnull::EmptyProof(), 0);
        CHECK(!rbf_ledger.Apply(rbf_bitcoin, rbf_original));
        rbf_bitcoin.chain.RestoreState(rbf_checkpoint);
        rbf_bitcoin.tip = rbf_bitcoin.chain.BestTip();
        auto rbf_replacement = MakeOpen(rbf_bitcoin, rbf_ledger.state, 11000, 11000, RECIPIENT_2,
                                        btcnull::EmptyProof());
        CHECK(rbf_ledger.Apply(rbf_bitcoin, rbf_replacement));
        CHECK(!rbf_bitcoin.chain.Has(rbf_original.claim.bitcoin_block));

        // Cases 28 and 29: both old issuer and public direct-mint proof families
        // fail the new RTP1 decoder and cannot reach the state machine.
        const std::vector<uint8_t> old_issuer{'M', 'N', 'P', '1', ';', 'd', 'e', 'a', 'd'};
        const std::vector<uint8_t> old_public{'M', 'S', 'P', '3', 0, 0, 0, 0};
        reserve::Claim rejected_old;
        CHECK(!reserve::DecodeProof(old_issuer.data(), old_issuer.size(), rejected_old));
        CHECK(!reserve::DecodeProof(old_public.data(), old_public.size(), rejected_old));

        // Reject the two legacy carriers through the actual production block
        // path, not only at the new binary decoder boundary.
        OnChainTokenLedger legacy_public;
        legacy_public.SetBtcHeaderChain(&bitcoin.chain);
        const Hash256 legacy_public_before = legacy_public.Digest();
        CHECK(!legacy_public.ProcessBlock(
            TransactionsBlock(1, {RawCarrier("VELD_MSPV|00")}, "legacy-public"), peg_gate));
        CHECK(legacy_public.Digest() == legacy_public_before);

        TokenOpData legacy_issuer_op;
        legacy_issuer_op.action = "MINT";
        legacy_issuer_op.token_id = BTCVELD_TOKEN_ID;
        legacy_issuer_op.from = BTCVELD_ISSUER_ADDRESS;
        legacy_issuer_op.to = RECIPIENT;
        legacy_issuer_op.amount = 1;
        legacy_issuer_op.memo =
            "0000000000000000000000000000000000000000000000000000000000000000:0";
        OnChainTokenLedger legacy_issuer;
        legacy_issuer.SetBtcHeaderChain(&bitcoin.chain);
        const Hash256 legacy_issuer_before = legacy_issuer.Digest();
        CHECK(!legacy_issuer.ProcessBlock(
            TransactionsBlock(1, {RawCarrier(EncodeTokenOp(legacy_issuer_op))}, "legacy-issuer"),
            peg_gate));
        CHECK(legacy_issuer.Digest() == legacy_issuer_before);

        // Production lifecycle integration: an authenticated Veld burn opens
        // the exact reserve liability, the covenant supplies the read-only
        // payout view to the common RTP1 verifier, and only the staged result
        // closes the request.  Bitcoin fees come from the second, non-reserve
        // input constructed by MakePayout.
        BitcoinHistory lifecycle_bitcoin;
        const RealKeyPair lifecycle_user = GenerateKeyPair(false);
        CHECK(IsCanonicalTokenCreditAddress(lifecycle_user.address));
        reserve::State lifecycle_empty;
        auto lifecycle_open = MakeOpen(lifecycle_bitcoin, lifecycle_empty, 40000, 40000,
                                       lifecycle_user.address, btcnull::EmptyProof());
        OnChainTokenLedger lifecycle_tokens;
        btcveld::SignerBondCovenant lifecycle_covenant;
        lifecycle_tokens.SetBtcHeaderChain(&lifecycle_bitcoin.chain);
        CHECK(lifecycle_tokens.ProcessBlock(ReserveBlock(1, {lifecycle_open}), peg_gate));

        const std::vector<uint8_t> lifecycle_destination = lifecycle_user.GetP2PKHScript();
        CHECK(IsStandardBtcRedeemSpk(lifecycle_destination));
        TokenOpData lifecycle_redeem_op;
        lifecycle_redeem_op.action = "REDEEM";
        lifecycle_redeem_op.token_id = BTCVELD_TOKEN_ID;
        lifecycle_redeem_op.from = lifecycle_user.address;
        lifecycle_redeem_op.amount = 40000;
        lifecycle_redeem_op.memo = BytesToHex(lifecycle_destination);
        const Transaction lifecycle_redeem =
            SignedTokenCarrier(lifecycle_redeem_op, lifecycle_user, "fulfilled");
        CHECK(lifecycle_tokens.ProcessBlock(TransactionsBlock(2, {lifecycle_redeem}, "redeem"),
                                            peg_gate));
        const auto lifecycle_redeems = lifecycle_tokens.LastBlockRedeemsCopy();
        CHECK(lifecycle_redeems.size() == 1);
        const auto lifecycle_request = RequestFromRedeem(lifecycle_redeems[0], lifecycle_redeem,
                                                         lifecycle_bitcoin.chain.BestHeight());
        lifecycle_covenant.AddRequest(lifecycle_request, /*reserve_backed_without_bond=*/true);
        lifecycle_tokens.SetBtcVeldRedeemCovenant(&lifecycle_covenant);
        CHECK(lifecycle_tokens.GetSupply(BTCVELD_TOKEN_ID) == 0);
        CHECK(lifecycle_tokens.GetBtcVeldReserveState().open_redemption_principal == 40000);
        CHECK(lifecycle_tokens.GetBtcVeldReserveState().AccountingHolds(0));

        const auto before_payout_tokens = lifecycle_tokens.SnapshotState();
        const auto before_payout_covenant = lifecycle_covenant.SnapshotState();

        auto lifecycle_payout = MakePayout(
            lifecycle_bitcoin, lifecycle_tokens.GetBtcVeldReserveState(), lifecycle_open.bitcoin_tx,
            40000, lifecycle_request.request_commitment, lifecycle_destination, true);
        CHECK(lifecycle_tokens.ProcessBlock(ReserveBlock(3, {lifecycle_payout}), peg_gate));
        const auto staged_payouts = lifecycle_tokens.LastBlockReservePayoutsCopy();
        CHECK(staged_payouts.size() == 1);
        CHECK(staged_payouts[0].request_id == lifecycle_request.request_id);
        CHECK(staged_payouts[0].principal_sats == 40000);
        CHECK(!lifecycle_covenant.IsConsumedPayout(lifecycle_payout.claim.bitcoin_txid));
        CHECK(lifecycle_covenant.MarkAuthorizedReservePayout(
            staged_payouts[0].request_id, staged_payouts[0].payout_txid,
            staged_payouts[0].principal_sats, staged_payouts[0].destination_spk));
        CHECK(lifecycle_covenant.IsConsumedPayout(lifecycle_payout.claim.bitcoin_txid));
        const auto fulfilled_snapshot = lifecycle_covenant.SnapshotState();
        CHECK(fulfilled_snapshot.requests.at(lifecycle_request.request_id).status ==
              btcveld::ReqStatus::FULFILLED);
        CHECK(lifecycle_tokens.GetBtcVeldReserveState().status == reserve::Status::EMPTY);
        CHECK(lifecycle_tokens.GetBtcVeldReserveState().AccountingHolds(0));

        // Cases 19/20 plus withheld-relay adversarial closure: present the
        // exact valid Bitcoin PAYOUT only through FSP2, never through RTP1.
        // The shared verifier must still advance the reserve and fulfill the
        // request before its SLA, so later default/compensation is impossible.
        lifecycle_tokens.RestoreState(before_payout_tokens);
        lifecycle_covenant.RestoreState(before_payout_covenant);
        CHECK(lifecycle_tokens.ProcessBlock(TransactionsBlock(3, {}, "fsp2-first"), peg_gate));
        const std::vector<uint8_t> fsp2_bytes = Fsp2Proof(lifecycle_payout);
        const auto fsp2 = btcveld::VerifyFraudulentSpend(lifecycle_bitcoin.chain, fsp2_bytes.data(),
                                                         fsp2_bytes.size(), BtcVeldCustodySpk(),
                                                         BTCVELD_SPV_K_BTC);
        CHECK(fsp2.ok);
        CHECK(fsp2.spend_txid == lifecycle_payout.claim.bitcoin_txid);
        const auto fsp2_classification =
            lifecycle_tokens.ClassifyBtcVeldReserveSpend(fsp2.spend_tx, fsp2.direct_parents);
        CHECK(fsp2_classification.disposition == reserve::SpendDisposition::AUTHORIZED_TRANSITION);
        CHECK(fsp2_classification.operation == reserve::Operation::PAYOUT);
        BtcVeldReservePayoutTransition fsp2_applied;
        CHECK(lifecycle_tokens.ApplyFsp2AuthorizedReservePayout(
            fsp2.spend_block, fsp2.spend_merkle_directions, fsp2.spend_merkle_branch, fsp2.spend_tx,
            fsp2.direct_parents, fsp2_applied));
        CHECK(lifecycle_covenant.MarkAuthorizedReservePayout(
            fsp2_applied.request_id, fsp2_applied.payout_txid, fsp2_applied.principal_sats,
            fsp2_applied.destination_spk));
        CHECK(lifecycle_tokens.GetBtcVeldReserveState().status == reserve::Status::EMPTY);
        CHECK(lifecycle_tokens.GetBtcVeldReserveState().AccountingHolds(0));
        CHECK(lifecycle_covenant.DueForDefault(lifecycle_request.deadline_height + 1).empty());
        CHECK(!lifecycle_covenant
                   .EvalNonPayment(lifecycle_request.request_id,
                                   lifecycle_request.deadline_height + 1)
                   .slash);
        CHECK(lifecycle_covenant.IsConsumedPayout(fsp2.spend_txid));

        // The one-edge budget is shared by RTP1, FSP2 payout, and FSP2 freeze.
        // Scenario A proves RTP1 ROLLOVER followed by an otherwise-valid FSP2
        // payout (or any FSP2 freeze) is rejected in the same Veld block.
        BitcoinHistory edge_bitcoin_a;
        const RealKeyPair edge_user_a = GenerateKeyPair(false);
        reserve::State edge_empty_a;
        auto edge_open_a = MakeOpen(edge_bitcoin_a, edge_empty_a, 50000, 50000, edge_user_a.address,
                                    btcnull::EmptyProof());
        OnChainTokenLedger edge_tokens_a;
        btcveld::SignerBondCovenant edge_covenant_a;
        edge_tokens_a.SetBtcHeaderChain(&edge_bitcoin_a.chain);
        edge_tokens_a.SetBtcVeldRedeemCovenant(&edge_covenant_a);
        CHECK(edge_tokens_a.ProcessBlock(ReserveBlock(1, {edge_open_a}), peg_gate));
        TokenOpData edge_redeem_op_a;
        edge_redeem_op_a.action = "REDEEM";
        edge_redeem_op_a.token_id = BTCVELD_TOKEN_ID;
        edge_redeem_op_a.from = edge_user_a.address;
        edge_redeem_op_a.amount = 10000;
        edge_redeem_op_a.memo = BytesToHex(edge_user_a.GetP2PKHScript());
        const Transaction edge_redeem_a =
            SignedTokenCarrier(edge_redeem_op_a, edge_user_a, "edge-a");
        CHECK(
            edge_tokens_a.ProcessBlock(TransactionsBlock(2, {edge_redeem_a}, "edge-a"), peg_gate));
        const auto edge_redeems_a = edge_tokens_a.LastBlockRedeemsCopy();
        CHECK(edge_redeems_a.size() == 1);
        const auto edge_request_a =
            RequestFromRedeem(edge_redeems_a[0], edge_redeem_a, edge_bitcoin_a.chain.BestHeight());
        edge_covenant_a.AddRequest(edge_request_a, /*reserve_backed_without_bond=*/true);
        const reserve::State edge_prior_a = edge_tokens_a.GetBtcVeldReserveState();
        auto edge_rollover_a = MakeRollover(edge_bitcoin_a, edge_prior_a, edge_open_a.bitcoin_tx);
        const auto edge_rollover_verified =
            reserve::Verify(edge_bitcoin_a.chain, edge_prior_a, 40000, edge_rollover_a.proof.data(),
                            edge_rollover_a.proof.size(), BtcVeldCustodySpk(), BTCVELD_SPV_K_BTC,
                            [](const std::string&) { return true; });
        CHECK(edge_rollover_verified.ok);
        reserve::State edge_after_rollover_a = edge_prior_a;
        CHECK(
            reserve::ApplyAuthorized(edge_after_rollover_a, edge_rollover_verified, 40000, 40000));
        auto edge_successor_payout_a =
            MakePayout(edge_bitcoin_a, edge_after_rollover_a, edge_rollover_a.bitcoin_tx, 10000,
                       edge_request_a.request_commitment, edge_user_a.GetP2PKHScript(), true);
        const std::vector<uint8_t> edge_fsp_bytes_a = Fsp2Proof(edge_successor_payout_a);
        const auto edge_fsp_a = btcveld::VerifyFraudulentSpend(
            edge_bitcoin_a.chain, edge_fsp_bytes_a.data(), edge_fsp_bytes_a.size(),
            BtcVeldCustodySpk(), BTCVELD_SPV_K_BTC);
        CHECK(edge_fsp_a.ok);
        CHECK(edge_tokens_a.ProcessBlock(ReserveBlock(3, {edge_rollover_a}), peg_gate));
        BtcVeldReservePayoutTransition rejected_second_edge;
        CHECK(!edge_tokens_a.ApplyFsp2AuthorizedReservePayout(
            edge_fsp_a.spend_block, edge_fsp_a.spend_merkle_directions,
            edge_fsp_a.spend_merkle_branch, edge_fsp_a.spend_tx, edge_fsp_a.direct_parents,
            rejected_second_edge));
        CHECK(!edge_tokens_a.FreezeBtcVeldReserve(TaggedHash("rtp1-then-fsp-freeze"),
                                                  edge_fsp_a.spend_block));
        CHECK(edge_tokens_a.GetBtcVeldReserveState().transition_count ==
              edge_after_rollover_a.transition_count);

        // Scenario B proves an FSP2-only partial payout consumes that block's
        // edge budget, so a following successor fraud proof cannot freeze as
        // a second edge.  A later block may classify it normally.
        BitcoinHistory edge_bitcoin_b;
        const RealKeyPair edge_user_b = GenerateKeyPair(false);
        reserve::State edge_empty_b;
        auto edge_open_b = MakeOpen(edge_bitcoin_b, edge_empty_b, 50000, 50000, edge_user_b.address,
                                    btcnull::EmptyProof());
        OnChainTokenLedger edge_tokens_b;
        btcveld::SignerBondCovenant edge_covenant_b;
        edge_tokens_b.SetBtcHeaderChain(&edge_bitcoin_b.chain);
        edge_tokens_b.SetBtcVeldRedeemCovenant(&edge_covenant_b);
        CHECK(edge_tokens_b.ProcessBlock(ReserveBlock(1, {edge_open_b}), peg_gate));
        TokenOpData edge_redeem_op_b;
        edge_redeem_op_b.action = "REDEEM";
        edge_redeem_op_b.token_id = BTCVELD_TOKEN_ID;
        edge_redeem_op_b.from = edge_user_b.address;
        edge_redeem_op_b.amount = 10000;
        edge_redeem_op_b.memo = BytesToHex(edge_user_b.GetP2PKHScript());
        const Transaction edge_redeem_b =
            SignedTokenCarrier(edge_redeem_op_b, edge_user_b, "edge-b");
        CHECK(
            edge_tokens_b.ProcessBlock(TransactionsBlock(2, {edge_redeem_b}, "edge-b"), peg_gate));
        const auto edge_redeems_b = edge_tokens_b.LastBlockRedeemsCopy();
        CHECK(edge_redeems_b.size() == 1);
        const auto edge_request_b =
            RequestFromRedeem(edge_redeems_b[0], edge_redeem_b, edge_bitcoin_b.chain.BestHeight());
        edge_covenant_b.AddRequest(edge_request_b, /*reserve_backed_without_bond=*/true);
        auto edge_payout_b = MakePayout(
            edge_bitcoin_b, edge_tokens_b.GetBtcVeldReserveState(), edge_open_b.bitcoin_tx, 10000,
            edge_request_b.request_commitment, edge_user_b.GetP2PKHScript(), true);
        CHECK(edge_tokens_b.ProcessBlock(TransactionsBlock(3, {}, "edge-b-fsp"), peg_gate));
        const std::vector<uint8_t> edge_fsp_bytes_b = Fsp2Proof(edge_payout_b);
        const auto edge_fsp_b = btcveld::VerifyFraudulentSpend(
            edge_bitcoin_b.chain, edge_fsp_bytes_b.data(), edge_fsp_bytes_b.size(),
            BtcVeldCustodySpk(), BTCVELD_SPV_K_BTC);
        CHECK(edge_fsp_b.ok);
        BtcVeldReservePayoutTransition edge_applied_b;
        CHECK(edge_tokens_b.ApplyFsp2AuthorizedReservePayout(
            edge_fsp_b.spend_block, edge_fsp_b.spend_merkle_directions,
            edge_fsp_b.spend_merkle_branch, edge_fsp_b.spend_tx, edge_fsp_b.direct_parents,
            edge_applied_b));
        CHECK(edge_covenant_b.MarkAuthorizedReservePayout(
            edge_applied_b.request_id, edge_applied_b.payout_txid, edge_applied_b.principal_sats,
            edge_applied_b.destination_spk));
        CHECK(!edge_tokens_b.FreezeBtcVeldReserve(TaggedHash("fsp-payout-then-fsp-freeze"),
                                                  edge_fsp_b.spend_block));
        CHECK(edge_tokens_b.GetBtcVeldReserveState().transition_count == 2);
        CHECK(edge_tokens_b.GetBtcVeldReserveState().AccountingHolds(40000));

        // Production expiry/default integration.  Compensation swaps the
        // exact open payout principal back into circulating supply, preserving
        // reserve equality.  Snapshot restoration and a second application
        // prove rejected-block/reorg determinism for both modules together.
        BitcoinHistory default_bitcoin;
        const RealKeyPair default_user = GenerateKeyPair(false);
        reserve::State default_empty;
        auto default_open = MakeOpen(default_bitcoin, default_empty, 50000, 50000,
                                     default_user.address, btcnull::EmptyProof());
        OnChainTokenLedger default_tokens;
        btcveld::SignerBondCovenant default_covenant;
        default_tokens.SetBtcHeaderChain(&default_bitcoin.chain);
        CHECK(default_tokens.ProcessBlock(ReserveBlock(1, {default_open}), peg_gate));
        TokenOpData default_redeem_op;
        default_redeem_op.action = "REDEEM";
        default_redeem_op.token_id = BTCVELD_TOKEN_ID;
        default_redeem_op.from = default_user.address;
        default_redeem_op.amount = 10000;
        default_redeem_op.memo = BytesToHex(default_user.GetP2PKHScript());
        const Transaction default_redeem =
            SignedTokenCarrier(default_redeem_op, default_user, "defaulted");
        CHECK(default_tokens.ProcessBlock(TransactionsBlock(2, {default_redeem}, "default"),
                                          peg_gate));
        const auto default_redeems = default_tokens.LastBlockRedeemsCopy();
        CHECK(default_redeems.size() == 1);
        const auto default_request = RequestFromRedeem(default_redeems[0], default_redeem,
                                                       default_bitcoin.chain.BestHeight());
        default_covenant.AddRequest(default_request, /*reserve_backed_without_bond=*/true);
        CHECK(default_tokens.GetSupply(BTCVELD_TOKEN_ID) == 40000);
        CHECK(default_tokens.GetBtcVeldReserveState().open_redemption_principal == 10000);
        CHECK(default_tokens.GetBtcVeldReserveState().AccountingHolds(40000));
        const uint64_t default_height = default_request.deadline_height + 1;
        const auto due = default_covenant.DueForDefault(default_height);
        CHECK(due.size() == 1 && due[0] == default_request.request_id);
        const auto default_verdict = default_covenant.EvalNonPayment(
            default_request.request_id, default_height, BTCVELD_NONPAY_PENALTY_BPS);
        CHECK(default_verdict.slash);
        CHECK(default_verdict.compensate_sats == 10000);
        CHECK(default_verdict.compensate_to == default_user.address);

        const auto default_token_snapshot = default_tokens.SnapshotState();
        const auto default_covenant_snapshot = default_covenant.SnapshotState();
        const Hash256 before_default_token_digest = default_tokens.Digest();
        const Hash256 before_default_covenant_digest = default_covenant.Digest();
        auto apply_default = [&]() {
            default_covenant.ApplySlash(default_verdict);
            CHECK(default_tokens.CompensateMint(default_verdict.compensate_to,
                                                default_verdict.compensate_sats, default_height,
                                                "security-test-default"));
            default_covenant.SetStatus(default_request.request_id, btcveld::ReqStatus::DEFAULTED);
        };
        apply_default();
        const Hash256 after_default_token_digest = default_tokens.Digest();
        const Hash256 after_default_covenant_digest = default_covenant.Digest();
        CHECK(default_tokens.GetSupply(BTCVELD_TOKEN_ID) == 50000);
        CHECK(default_tokens.GetBalance(BTCVELD_TOKEN_ID, default_user.address) == 50000);
        CHECK(default_tokens.GetBtcVeldReserveState().open_redemption_principal == 0);
        CHECK(default_tokens.GetBtcVeldReserveState().AccountingHolds(50000));
        CHECK(default_covenant.SnapshotState().requests.at(default_request.request_id).status ==
              btcveld::ReqStatus::DEFAULTED);
        CHECK(
            !default_covenant.EvalNonPayment(default_request.request_id, default_height + 1).slash);

        default_tokens.RestoreState(default_token_snapshot);
        default_covenant.RestoreState(default_covenant_snapshot);
        CHECK(default_tokens.Digest() == before_default_token_digest);
        CHECK(default_covenant.Digest() == before_default_covenant_digest);
        apply_default();
        CHECK(default_tokens.Digest() == after_default_token_digest);
        CHECK(default_covenant.Digest() == after_default_covenant_digest);

        // Real Bitcoin Core wallets spend the P2WPKH custody output with a
        // witness serialization. Prove that txid (not wtxid), direct-parent
        // binding, issuer/public verification, and FSP2 all share that exact
        // interpretation, while malformed witness encodings remain closed.
        BitcoinHistory witness_bitcoin;
        TestLedger witness_ledger;
        auto witness_open = MakeOpen(witness_bitcoin, witness_ledger.state, 100000, 100000,
                                     RECIPIENT, btcnull::EmptyProof(), BTCVELD_SPV_K_BTC, true);
        btcspv::WitnessAwareBtcTx parsed_witness_open;
        CHECK(btcspv::ParseWitnessAwareBtcTx(witness_open.bitcoin_tx, parsed_witness_open,
                                             reserve::MAX_DIRECT_INPUTS));
        CHECK(parsed_witness_open.has_witness);
        CHECK(parsed_witness_open.txid == witness_open.claim.bitcoin_txid);
        CHECK(parsed_witness_open.txid != Hash256d(witness_open.bitcoin_tx));
        std::vector<btcspv::BtcTxOut> legacy_only_outputs;
        CHECK(!btcspv::ParseBtcTxOutputs(witness_open.bitcoin_tx.data(),
                                         witness_open.bitcoin_tx.size(), legacy_only_outputs));
        const auto witness_public = reserve::Verify(
            witness_bitcoin.chain, witness_ledger.state, witness_ledger.supply,
            witness_open.proof.data(), witness_open.proof.size(), BtcVeldCustodySpk(),
            BTCVELD_SPV_K_BTC, [](const std::string& address) { return address == RECIPIENT; });
        const auto witness_issuer = reserve::Verify(
            witness_bitcoin.chain, witness_ledger.state, witness_ledger.supply,
            witness_open.proof.data(), witness_open.proof.size(), BtcVeldCustodySpk(),
            BTCVELD_SPV_K_BTC, [](const std::string& address) { return address == RECIPIENT; });
        CHECK(witness_public.ok && witness_issuer.ok);
        CHECK(witness_public.claim.bitcoin_txid == witness_issuer.claim.bitcoin_txid);
        CHECK(witness_ledger.Apply(witness_bitcoin, witness_open));

        const auto witness_pending = MakePendingDeposit(50000, RECIPIENT, true);
        btcspv::WitnessAwareBtcTx parsed_witness_pending;
        CHECK(btcspv::ParseWitnessAwareBtcTx(witness_pending, parsed_witness_pending));
        const std::string witness_pending_outpoint =
            btcspv::BtcDepositOutpointId(parsed_witness_pending.txid, 0);
        auto witness_deposit =
            MakeDeposit(witness_bitcoin, witness_ledger.state, witness_ledger.current_reserve_tx,
                        witness_pending, 150000, 40000,
                        witness_ledger.WitnessFor(witness_pending_outpoint), true);
        const auto witness_deposit_classification =
            Classify(witness_ledger, witness_deposit.bitcoin_tx, witness_deposit.parents);
        if (witness_deposit_classification.disposition !=
            reserve::SpendDisposition::AUTHORIZED_TRANSITION)
            throw std::runtime_error("witness DEPOSIT classification failed: " +
                                     witness_deposit_classification.reason);
        CHECK(witness_deposit_classification.disposition ==
              reserve::SpendDisposition::AUTHORIZED_TRANSITION);
        CHECK(witness_ledger.Apply(witness_bitcoin, witness_deposit));
        auto witness_rollover = MakeRollover(witness_bitcoin, witness_ledger.state,
                                             witness_ledger.current_reserve_tx, true);
        CHECK(witness_ledger.Apply(witness_bitcoin, witness_rollover));
        CHECK(witness_ledger.OpenRedemption(10000));
        auto witness_payout =
            MakePayout(witness_bitcoin, witness_ledger.state, witness_ledger.current_reserve_tx,
                       10000, TaggedHash("witness-payout-request"), {0x51}, true, true);
        CHECK(Classify(witness_ledger, witness_payout.bitcoin_tx, witness_payout.parents,
                       witness_payout.payout)
                  .disposition == reserve::SpendDisposition::AUTHORIZED_TRANSITION);
        const std::vector<uint8_t> witness_fsp2 = Fsp2Proof(witness_payout);
        const auto witness_fraud = btcveld::VerifyFraudulentSpend(
            witness_bitcoin.chain, witness_fsp2.data(), witness_fsp2.size(), BtcVeldCustodySpk(),
            BTCVELD_SPV_K_BTC);
        CHECK(witness_fraud.ok);
        CHECK(witness_fraud.spend_txid == witness_payout.claim.bitcoin_txid);
        CHECK(witness_fraud.direct_parents == witness_payout.parents);
        CHECK(witness_ledger.Apply(witness_bitcoin, witness_payout));
        CHECK(witness_ledger.state.AccountingHolds(witness_ledger.supply));

        const auto stripped_witness_open = MakeBitcoinTx(
            {{parsed_witness_open.prevouts[0].txid, parsed_witness_open.prevouts[0].vout}},
            parsed_witness_open.outputs);
        auto unknown_witness_flag = witness_open.bitcoin_tx;
        unknown_witness_flag[5] = 0x02;
        btcspv::WitnessAwareBtcTx malformed_witness;
        CHECK(!btcspv::ParseWitnessAwareBtcTx(unknown_witness_flag, malformed_witness));
        std::vector<uint8_t> superfluous_witness;
        superfluous_witness.insert(superfluous_witness.end(), stripped_witness_open.begin(),
                                   stripped_witness_open.begin() + 4);
        superfluous_witness.push_back(0x00);
        superfluous_witness.push_back(0x01);
        superfluous_witness.insert(superfluous_witness.end(), stripped_witness_open.begin() + 4,
                                   stripped_witness_open.end() - 4);
        superfluous_witness.push_back(0x00);
        superfluous_witness.insert(superfluous_witness.end(), stripped_witness_open.end() - 4,
                                   stripped_witness_open.end());
        CHECK(!btcspv::ParseWitnessAwareBtcTx(superfluous_witness, malformed_witness));
        auto truncated_witness = witness_open.bitcoin_tx;
        truncated_witness.pop_back();
        CHECK(!btcspv::ParseWitnessAwareBtcTx(truncated_witness, malformed_witness));
        auto trailing_witness = witness_open.bitcoin_tx;
        trailing_witness.push_back(0x00);
        CHECK(!btcspv::ParseWitnessAwareBtcTx(trailing_witness, malformed_witness));
        std::vector<uint8_t> noncanonical_vin;
        noncanonical_vin.insert(noncanonical_vin.end(), stripped_witness_open.begin(),
                                stripped_witness_open.begin() + 4);
        noncanonical_vin.insert(noncanonical_vin.end(), {0xfd, 0x01, 0x00});
        noncanonical_vin.insert(noncanonical_vin.end(), stripped_witness_open.begin() + 5,
                                stripped_witness_open.end());
        CHECK(!btcspv::ParseWitnessAwareBtcTx(noncanonical_vin, malformed_witness));

        // Case 31: the accounting equality has been asserted after every
        // accepted operation above; explicitly reject a one-satoshi mismatch.
        reserve::State corrupted = ledger.state;
        ++corrupted.reserve_value_sats;
        CHECK(!corrupted.AccountingHolds(ledger.supply));

        std::cout << "PASS reserve_tests checks=" << g_checks
                  << " transitions=" << canonical_history.size()
                  << " final_supply=" << ledger.supply
                  << " final_reserve=" << ledger.state.reserve_value_sats
                  << " surplus=" << ledger.state.surplus_sats
                  << " canonical_digest=" << HashToHex(ledger.CompleteDigest())
                  << " production_token_digest=" << HashToHex(production.Digest()) << "\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL reserve_tests: " << error.what() << "\n";
        return 1;
    }
}
