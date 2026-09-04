// Purpose-built disposable profile: the seed below is test material only.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_REGTEST_FIXED_DIFF 1
#define VELD_BTCVELD_REGTEST 1
#define VELD_L3_DISPOSABLE_BTCVELD_AUTHORITY_ADDRESS "VZqR3pfH6br3Aqatjkwn8XCvtFaaNqa3mj"
#define VELD_L3_DISPOSABLE_BTCVELD_CUSTODY_SPK_HEX "00141111111111111111111111111111111111111111"

#define main original_reserve_main
#include "reserve_tests.cpp"
#undef main

#include <iostream>

namespace {

RealKeyPair DisposableIssuer() {
    RealKeyPair key;
    for (size_t i = 0; i < key.private_key.size(); ++i)
        key.private_key[i] = static_cast<uint8_t>(i + 1);
    key.public_key = DerivePublicKey(key.private_key);

    const Hash160 hash = Hash160Compute(key.public_key);
    std::vector<uint8_t> data{0x46};
    data.insert(data.end(), hash.begin(), hash.end());
    const Hash256 check = Hash256d(data);
    data.insert(data.end(), check.begin(), check.begin() + 4);
    static constexpr char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::vector<uint8_t> digits{0};
    for (const uint8_t byte : data) {
        int carry = byte;
        for (uint8_t& digit : digits) {
            carry += 256 * digit;
            digit = static_cast<uint8_t>(carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            digits.push_back(static_cast<uint8_t>(carry % 58));
            carry /= 58;
        }
    }
    for (auto it = digits.rbegin(); it != digits.rend(); ++it)
        key.address += alphabet[*it];
    return key;
}

Transaction SignedIssuerReserveCarrier(const TransitionFixture& fixture,
                                       const RealKeyPair& issuer) {
    Transaction tx = IssuerReserveCarrier(fixture);
    tx.inputs.clear();
    TxInput input;
    input.prev_tx_hash = TaggedHash("reopen-ledger-issuer-input");
    input.prev_out_index = 0;
    tx.inputs.push_back(input);
    tx.inputs[0].script_sig = issuer.SignInput(tx, 0, issuer.GetP2PKHScript()).script_sig;
    tx.InvalidateTxIDCache();
    CHECK(TxVerifiedSignedBy(tx, issuer.address));
    return tx;
}

} // namespace

int main() {
    try {
        CHECK(std::string(BTCVELD_ISSUER_ADDRESS) == "VZqR3pfH6br3Aqatjkwn8XCvtFaaNqa3mj");
        const RealKeyPair issuer = DisposableIssuer();
        CHECK(issuer.address == BTCVELD_ISSUER_ADDRESS);
        CHECK(IsCanonicalTokenCreditAddress(issuer.address));

        BitcoinHistory bitcoin;
        TestLedger model;
        const auto first_open =
            MakeOpen(bitcoin, model.state, 10'000, 0, RECIPIENT, btcnull::EmptyProof());
        CHECK(model.Apply(bitcoin, first_open));
        const auto close = MakeClose(bitcoin, model.state, model.current_reserve_tx);
        CHECK(model.Apply(bitcoin, close));
        CHECK(model.state.status == reserve::Status::EMPTY);
        CHECK(model.state.transition_count == 2);
        CHECK(model.state.transition_commitment != reserve::EmptyTransitionCommitment());

        auto reopen =
            MakeOpen(bitcoin, model.state, 20'000, 20'000, RECIPIENT, btcnull::EmptyProof());
        // OPEN consumes its own newly created reserve output in the nullifier
        // domain. Bind the witness to that exact transition txid/vout.
        const std::string reopen_outpoint = btcspv::BtcDepositOutpointId(
            Hash256d(reopen.bitcoin_tx), reopen.claim.new_reserve_vout);
        reopen.claim.nullifier_proof = model.WitnessFor(reopen_outpoint);
        reopen.proof = reserve::EncodeProof(reopen.claim);
        CHECK(!reopen.proof.empty());
        const std::vector<uint8_t> canonical_reopen = reopen.proof;

        const BtcVeldPegGateState peg_gate{true, true, true};
        OnChainTokenLedger public_ledger;
        OnChainTokenLedger issuer_ledger;
        public_ledger.SetBtcHeaderChain(&bitcoin.chain);
        issuer_ledger.SetBtcHeaderChain(&bitcoin.chain);
        for (OnChainTokenLedger* ledger : {&public_ledger, &issuer_ledger}) {
            CHECK(ledger->ProcessBlock(ReserveBlock(1, {first_open}), peg_gate));
            CHECK(ledger->ProcessBlock(ReserveBlock(2, {close}), peg_gate));
            CHECK(ledger->GetBtcVeldReserveState().status == reserve::Status::EMPTY);
            CHECK(ledger->GetBtcVeldReserveState().transition_count == 2);
        }
        CHECK(public_ledger.Digest() == issuer_ledger.Digest());
        CHECK(public_ledger.GetBtcVeldMintAccumulator().root ==
              issuer_ledger.GetBtcVeldMintAccumulator().root);

        const Transaction public_carrier = ReserveCarrier(reopen);
        const Transaction issuer_carrier = SignedIssuerReserveCarrier(reopen, issuer);
        const auto public_payload_bytes =
            btcspv::ExtractOpReturn(public_carrier.outputs[0].script_pubkey);
        const std::string public_payload(public_payload_bytes.begin(), public_payload_bytes.end());
        const auto issuer_payload_bytes =
            btcspv::ExtractOpReturn(issuer_carrier.outputs[0].script_pubkey);
        const auto issuer_operation =
            DecodeTokenOp(std::string(issuer_payload_bytes.begin(), issuer_payload_bytes.end()));
        CHECK(public_payload ==
              std::string(reserve::PUBLIC_CARRIER_PREFIX) + BytesToHex(canonical_reopen));
        CHECK(issuer_operation.has_value());
        CHECK(issuer_operation->memo ==
              std::string(reserve::ISSUER_MEMO_PREFIX) + BytesToHex(canonical_reopen));
        const auto direct_reopen =
            reserve::Verify(bitcoin.chain, public_ledger.GetBtcVeldReserveState(),
                            static_cast<uint64_t>(public_ledger.GetSupply(BTCVELD_TOKEN_ID)),
                            canonical_reopen.data(), canonical_reopen.size(), BtcVeldCustodySpk(),
                            BTCVELD_SPV_K_BTC, [](const std::string& address) {
                                return IsCanonicalTokenCreditAddress(address);
                            });
        if (!direct_reopen.ok)
            throw std::runtime_error("direct post-CLOSE re-OPEN verification failed: " +
                                     direct_reopen.reason);
        CHECK(direct_reopen.recipient == RECIPIENT);
        const auto public_before_reopen_accumulator = public_ledger.GetBtcVeldMintAccumulator();
        CHECK(public_before_reopen_accumulator.root == model.nullifier_root);
        CHECK(public_before_reopen_accumulator.count == model.nullifier_events.size());
        CHECK(btcnull::Insert(public_before_reopen_accumulator.root, direct_reopen.pending_outpoint,
                              direct_reopen.claim.nullifier_proof)
                  .ok);
        CHECK(public_ledger.ValidateMempoolCandidate(public_carrier, 3, 0x207fffffu, peg_gate));
        CHECK(issuer_ledger.ValidateMempoolCandidate(issuer_carrier, 3, 0x207fffffu, peg_gate));
        CHECK(public_ledger.ProcessBlock(TransactionsBlock(3, {public_carrier}, "public-reopen"),
                                         peg_gate));
        CHECK(issuer_ledger.ProcessBlock(TransactionsBlock(3, {issuer_carrier}, "issuer-reopen"),
                                         peg_gate));

        const auto public_state = public_ledger.GetBtcVeldReserveState();
        const auto issuer_state = issuer_ledger.GetBtcVeldReserveState();
        CHECK(public_state.status == reserve::Status::ACTIVE);
        CHECK(issuer_state.status == public_state.status);
        CHECK(public_state.transition_count == 3);
        CHECK(issuer_state.transition_count == public_state.transition_count);
        CHECK(public_state.reserve_value_sats == 20'000);
        CHECK(issuer_state.reserve_txid == public_state.reserve_txid);
        CHECK(issuer_state.reserve_vout == public_state.reserve_vout);
        CHECK(issuer_state.reserve_value_sats == public_state.reserve_value_sats);
        CHECK(issuer_state.surplus_sats == public_state.surplus_sats);
        CHECK(public_state.surplus_sats == 0);
        CHECK(public_state.open_redemption_principal == 0);
        CHECK(issuer_state.open_redemption_principal == public_state.open_redemption_principal);
        CHECK(issuer_state.transition_commitment == public_state.transition_commitment);
        CHECK(issuer_state.reserve_bitcoin_block == public_state.reserve_bitcoin_block);
        CHECK(issuer_state.processed_veld_height == public_state.processed_veld_height);
        CHECK(public_ledger.GetSupply(BTCVELD_TOKEN_ID) == 20'000);
        CHECK(issuer_ledger.GetSupply(BTCVELD_TOKEN_ID) == 20'000);
        CHECK(public_ledger.GetBalance(BTCVELD_TOKEN_ID, RECIPIENT) == 20'000);
        CHECK(issuer_ledger.GetBalance(BTCVELD_TOKEN_ID, RECIPIENT) == 20'000);
        CHECK(public_state.reserve_value_sats ==
              static_cast<uint64_t>(public_ledger.GetSupply(BTCVELD_TOKEN_ID)) +
                  public_state.open_redemption_principal + public_state.surplus_sats);
        const auto public_accumulator = public_ledger.GetBtcVeldMintAccumulator();
        const auto issuer_accumulator = issuer_ledger.GetBtcVeldMintAccumulator();
        CHECK(public_accumulator.root == issuer_accumulator.root);
        CHECK(public_accumulator.count == issuer_accumulator.count);
        // The carrier transaction and resulting Veld block hashes differ by
        // interface, but both wrappers carry the exact same canonical claim.
        // Consensus reserve fields and the nullifier set are identical.
        CHECK(reopen.proof == canonical_reopen);

        // A second proof against the now-stale terminal EMPTY state is rejected
        // by both wrappers without changing supply, reserve, or accumulators.
        auto competing =
            MakeOpen(bitcoin, model.state, 21'000, 21'000, RECIPIENT_2, btcnull::EmptyProof());
        const std::string competing_outpoint = btcspv::BtcDepositOutpointId(
            Hash256d(competing.bitcoin_tx), competing.claim.new_reserve_vout);
        competing.claim.nullifier_proof = model.WitnessFor(competing_outpoint);
        competing.proof = reserve::EncodeProof(competing.claim);
        CHECK(!competing.proof.empty());
        const Hash256 public_before = public_ledger.Digest();
        const Hash256 issuer_before = issuer_ledger.Digest();
        const auto public_state_before = public_ledger.GetBtcVeldReserveState();
        const auto issuer_state_before = issuer_ledger.GetBtcVeldReserveState();
        const int64_t public_supply_before = public_ledger.GetSupply(BTCVELD_TOKEN_ID);
        const int64_t issuer_supply_before = issuer_ledger.GetSupply(BTCVELD_TOKEN_ID);
        CHECK(!public_ledger.ProcessBlock(ReserveBlock(4, {competing}), peg_gate));
        CHECK(!issuer_ledger.ProcessBlock(
            TransactionsBlock(4, {SignedIssuerReserveCarrier(competing, issuer)},
                              "issuer-stale-reopen"),
            peg_gate));
        CHECK(public_ledger.Digest() == public_before);
        CHECK(issuer_ledger.Digest() == issuer_before);
        CHECK(reserve::EncodeState(public_ledger.GetBtcVeldReserveState()) ==
              reserve::EncodeState(public_state_before));
        CHECK(reserve::EncodeState(issuer_ledger.GetBtcVeldReserveState()) ==
              reserve::EncodeState(issuer_state_before));
        CHECK(public_ledger.GetSupply(BTCVELD_TOKEN_ID) == public_supply_before);
        CHECK(issuer_ledger.GetSupply(BTCVELD_TOKEN_ID) == issuer_supply_before);
        CHECK(public_ledger.GetBtcVeldMintAccumulator().root == public_accumulator.root);
        CHECK(issuer_ledger.GetBtcVeldMintAccumulator().root == issuer_accumulator.root);

        std::cout << "PASS reopen_ledger_tests checks=" << g_checks
                  << " transition_count=" << public_state.transition_count << " supply=20000"
                  << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL reopen_ledger_tests: " << error.what() << '\n';
        return 1;
    }
}
