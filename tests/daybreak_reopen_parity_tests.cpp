#define main daybreak_original_signing_policy_main
#include "daybreak_signing_policy_tests.cpp"
#undef main

#include <iostream>
#include <string>
#include <vector>

namespace {

reserve::Claim MakeOpenClaim(const reserve::State& prior,
                             uint64_t mint_amount,
                             const std::string& tag,
                             const std::string& recipient = RECIPIENT) {
    const uint64_t reserve_value = MINT_SATS;
    const std::vector<uint8_t> parent = BitcoinTx(
        {{TaggedHash(tag + "-funding"), 0}},
        {{reserve_value + 1'000, {0x51}}});
    reserve::Claim claim;
    claim.operation = reserve::Operation::OPEN;
    claim.network_binding = reserve::NetworkBinding();
    claim.prior_commitment = prior.transition_commitment;
    claim.prior_reserve_txid = prior.reserve_txid;
    claim.prior_reserve_vout = prior.reserve_vout;
    claim.prior_reserve_value = prior.reserve_value_sats;
    claim.prior_transition_count = prior.transition_count;
    claim.new_reserve_vout = 0;
    claim.new_reserve_value = reserve_value;
    claim.mint_amount = mint_amount;
    claim.exact_commitment = reserve::detail::OpenDepositCommitment(
        claim.new_reserve_vout, claim.new_reserve_value, recipient);
    claim.direct_parents = {parent};
    claim.has_nullifier_proof = true;
    claim.nullifier_proof = btcnull::EmptyProof();
    claim.bitcoin_block = TaggedHash(tag + "-bitcoin-block");
    claim.bitcoin_tx = BitcoinTx(
        {{Hash256d(parent), 0}},
        {{reserve_value, BtcVeldCustodySpk()},
         {0, reserve::detail::OpenAuthScript(
             claim.prior_commitment, recipient, claim.mint_amount)}});
    claim.bitcoin_txid = Hash256d(claim.bitcoin_tx);
    claim.new_reserve_txid = claim.bitcoin_txid;
    return claim;
}

reserve::Claim MakeCloseClaim(const reserve::State& prior,
                              const std::vector<uint8_t>& reserve_parent,
                              const std::string& tag) {
    reserve::Claim claim;
    claim.operation = reserve::Operation::CLOSE;
    claim.network_binding = reserve::NetworkBinding();
    claim.prior_commitment = prior.transition_commitment;
    claim.prior_reserve_txid = prior.reserve_txid;
    claim.prior_reserve_vout = prior.reserve_vout;
    claim.prior_reserve_value = prior.reserve_value_sats;
    claim.prior_transition_count = prior.transition_count;
    claim.bitcoin_block = TaggedHash(tag + "-bitcoin-block");
    claim.direct_parents = {reserve_parent};
    claim.bitcoin_tx = BitcoinTx(
        {{prior.reserve_txid, prior.reserve_vout}},
        {{0, reserve::detail::AuthScript(
             reserve::Operation::CLOSE, claim.prior_commitment,
             ZeroHash(), 0)}});
    claim.bitcoin_txid = Hash256d(claim.bitcoin_tx);
    return claim;
}

reserve::SpendClassification Classify(const reserve::State& state,
                                      const reserve::Claim& claim) {
    return reserve::ClassifyBitcoinReserveSpend(
        state, 0, claim.bitcoin_tx, claim.direct_parents,
        BtcVeldCustodySpk(),
        [](const std::string& recipient) { return recipient == RECIPIENT; });
}

reserve::Result Authorized(const reserve::Claim& claim,
                           const reserve::SpendClassification& classified) {
    reserve::Result result;
    result.ok = classified.disposition ==
        reserve::SpendDisposition::AUTHORIZED_TRANSITION;
    result.claim = claim;
    result.recipient = classified.recipient;
    result.terminal = claim.operation == reserve::Operation::CLOSE;
    return result;
}

bool IssuerAccepts(const reserve::Claim& claim,
                   const std::vector<uint8_t>& issuer_script,
                   const reserve::State& expected_prior,
                   uint64_t expected_supply = 0,
                   const std::string& recipient = RECIPIENT) {
    const std::vector<uint8_t> proof = reserve::EncodeProof(claim);
    const std::string memo = std::string(reserve::ISSUER_MEMO_PREFIX) +
        BytesToHex(proof);
    const Transaction carrier = Carrier(
        MintPayload(recipient, claim.mint_amount, memo), issuer_script);
    std::string from, to, decoded;
    uint64_t amount = 0;
    const BtcVeldReserveMintPolicyContext context{
        expected_prior, expected_supply};
    return BtcVeldMintTemplatePolicy(
        carrier, issuer_script, from, to, amount, decoded,
        &context).empty();
}

bool RelayAccepts(const reserve::Claim& claim,
                  const std::vector<uint8_t>& fee_script) {
    const std::vector<uint8_t> proof = reserve::EncodeProof(claim);
    const Transaction carrier = Carrier(
        std::string(reserve::PUBLIC_CARRIER_PREFIX) + BytesToHex(proof),
        fee_script);
    std::string family;
    return BtcVeldRelayTemplatePolicy(carrier, fee_script, family).empty() &&
           family == reserve::PUBLIC_CARRIER_PREFIX;
}

} // namespace

int main() {
    try {
        const std::vector<uint8_t> fee_script{
            0x76, 0xa9, 0x14, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0x88, 0xac};
        const std::vector<uint8_t> issuer_script{
            0x76, 0xa9, 0x14, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0x88, 0xac};

        reserve::State genesis;
        const reserve::Claim first =
            MakeOpenClaim(genesis, MINT_SATS, "first-open");
        CHECK(Classify(genesis, first).disposition ==
              reserve::SpendDisposition::AUTHORIZED_TRANSITION);
        CHECK(RelayAccepts(first, fee_script));
        CHECK(IssuerAccepts(first, issuer_script, genesis));
        {
            const std::vector<uint8_t> proof = reserve::EncodeProof(first);
            const Transaction carrier = Carrier(
                MintPayload(
                    RECIPIENT, first.mint_amount,
                    std::string(reserve::ISSUER_MEMO_PREFIX) +
                        BytesToHex(proof)),
                issuer_script);
            std::string from, to, memo;
            uint64_t amount = 0;
            CHECK(!BtcVeldMintTemplatePolicy(
                carrier, issuer_script, from, to, amount, memo).empty());
        }

        // Three complete OPEN/CLOSE cycles preserve and advance the rolling
        // count/root.  Zero-mint public OPEN creates explicit surplus, which
        // permits canonical CLOSE without manufacturing a burn path.
        reserve::State closed;
        for (unsigned cycle = 0; cycle < 3; ++cycle) {
            const std::string tag = "cycle-" + std::to_string(cycle);
            const reserve::Claim opened =
                MakeOpenClaim(closed, 0, tag + "-open");
            const auto open_classified = Classify(closed, opened);
            CHECK(open_classified.disposition ==
                  reserve::SpendDisposition::AUTHORIZED_TRANSITION);
            CHECK(RelayAccepts(opened, fee_script));
            const uint64_t before_open_count = closed.transition_count;
            const Hash256 before_open_root = closed.transition_commitment;
            CHECK(reserve::ApplyAuthorized(
                closed, Authorized(opened, open_classified), 0, 0));
            CHECK(closed.status == reserve::Status::ACTIVE);
            CHECK(closed.transition_count == before_open_count + 1);
            CHECK(closed.transition_commitment != before_open_root);
            CHECK(closed.reserve_value_sats == closed.surplus_sats);
            CHECK(closed.AccountingHolds(0));

            const reserve::Claim close =
                MakeCloseClaim(closed, opened.bitcoin_tx, tag + "-close");
            const auto close_classified = Classify(closed, close);
            CHECK(close_classified.disposition ==
                  reserve::SpendDisposition::AUTHORIZED_TRANSITION);
            const uint64_t before_close_count = closed.transition_count;
            const Hash256 before_close_root = closed.transition_commitment;
            CHECK(reserve::ApplyAuthorized(
                closed, Authorized(close, close_classified), 0, 0));
            CHECK(closed.status == reserve::Status::EMPTY);
            CHECK(closed.transition_count == before_close_count + 1);
            CHECK(closed.transition_commitment != before_close_root);
            CHECK(closed.AccountingHolds(0));
        }

        const reserve::State reopen_prior = closed;
        const std::vector<uint8_t> prior_bytes =
            reserve::EncodeState(reopen_prior);
        reserve::State decoded_prior;
        CHECK(reserve::DecodeState(
            prior_bytes.data(), prior_bytes.size(), decoded_prior));
        CHECK(reserve::EncodeState(decoded_prior) == prior_bytes);
        std::vector<uint8_t> noncanonical_prior = prior_bytes;
        noncanonical_prior.push_back(0);
        CHECK(!reserve::DecodeState(
            noncanonical_prior.data(), noncanonical_prior.size(),
            decoded_prior));
        const reserve::Claim reopen =
            MakeOpenClaim(reopen_prior, MINT_SATS, "canonical-reopen");
        const std::vector<uint8_t> canonical_bytes = reserve::EncodeProof(reopen);
        CHECK(!canonical_bytes.empty());
        CHECK(Classify(reopen_prior, reopen).disposition ==
              reserve::SpendDisposition::AUTHORIZED_TRANSITION);
        CHECK(RelayAccepts(reopen, fee_script));
        CHECK(IssuerAccepts(reopen, issuer_script, reopen_prior));

        // Public and issuer wrappers carry exactly the same canonical RTP1
        // claim bytes; neither path has a distinct OPEN interpretation.
        reserve::Claim decoded;
        CHECK(reserve::DecodeProof(
            canonical_bytes.data(), canonical_bytes.size(), decoded));
        CHECK(reserve::EncodeProof(decoded) == canonical_bytes);

        reserve::Claim earlier_count = reopen;
        --earlier_count.prior_transition_count;
        CHECK(!reserve::detail::MatchesPrior(reopen_prior, earlier_count));
        CHECK(!IssuerAccepts(
            earlier_count, issuer_script, reopen_prior));
        reserve::Claim earlier_root = reopen;
        earlier_root.prior_commitment = genesis.transition_commitment;
        earlier_root.bitcoin_tx = MakeOpenClaim(
            reserve::State{}, MINT_SATS, "earlier-root").bitcoin_tx;
        earlier_root.bitcoin_txid = Hash256d(earlier_root.bitcoin_tx);
        earlier_root.new_reserve_txid = earlier_root.bitcoin_txid;
        CHECK(!reserve::detail::MatchesPrior(reopen_prior, earlier_root));
        CHECK(!IssuerAccepts(
            earlier_root, issuer_script, reopen_prior));

        reserve::Claim malformed_prior = reopen;
        malformed_prior.prior_reserve_txid = TaggedHash("not-empty-prior");
        CHECK(!IssuerAccepts(
            malformed_prior, issuer_script, reopen_prior));
        reserve::Claim overflow_prior = reopen;
        overflow_prior.prior_transition_count = UINT64_MAX;
        CHECK(!IssuerAccepts(
            overflow_prior, issuer_script, reopen_prior));
        reserve::State false_genesis;
        false_genesis.transition_commitment = TaggedHash("false-genesis-root");
        const reserve::Claim false_first =
            MakeOpenClaim(false_genesis, MINT_SATS, "false-first");
        CHECK(!IssuerAccepts(false_first, issuer_script, genesis));
        const reserve::Claim invalid_recipient = MakeOpenClaim(
            reopen_prior, MINT_SATS, "invalid-recipient",
            "not-a-canonical-veld-address");
        CHECK(!IssuerAccepts(
            invalid_recipient, issuer_script, reopen_prior, 0,
            "not-a-canonical-veld-address"));

        // Competing proofs are each structurally valid against the same EMPTY
        // prior, but the winner advances state and makes the loser stale.
        const reserve::Claim competing =
            MakeOpenClaim(reopen_prior, MINT_SATS, "competing-reopen");
        CHECK(Classify(reopen_prior, competing).disposition ==
              reserve::SpendDisposition::AUTHORIZED_TRANSITION);
        CHECK(RelayAccepts(competing, fee_script));
        CHECK(IssuerAccepts(
            competing, issuer_script, reopen_prior));
        reserve::State advanced = reopen_prior;
        const auto reopen_classified = Classify(advanced, reopen);
        CHECK(reserve::ApplyAuthorized(
            advanced, Authorized(reopen, reopen_classified), 0, MINT_SATS));
        CHECK(!reserve::detail::MatchesPrior(advanced, competing));
        CHECK(Classify(advanced, competing).disposition !=
              reserve::SpendDisposition::AUTHORIZED_TRANSITION);
        CHECK(!IssuerAccepts(
            competing, issuer_script, advanced, MINT_SATS));

        // A rejected stale/redirected re-OPEN cannot mutate any state field.
        const std::vector<uint8_t> state_before = reserve::EncodeState(advanced);
        reserve::Result rejected = Authorized(
            earlier_count, Classify(reopen_prior, earlier_count));
        rejected.ok = true; // exercise ApplyAuthorized's own live-state guard
        CHECK(!reserve::ApplyAuthorized(
            advanced, rejected, MINT_SATS, 2 * MINT_SATS));
        CHECK(reserve::EncodeState(advanced) == state_before);
        CHECK(!IssuerAccepts(
            reopen, issuer_script, reopen_prior, 0,
            "VV6pcrLQvxq7uBZEFtc4qxCizQ26azxTtK"));

        const Transaction old_mnp = Carrier(
            MintPayload(RECIPIENT, MINT_SATS,
                        std::string(64, '0') + ":0"), issuer_script);
        std::string from, to, memo;
        uint64_t amount = 0;
        CHECK(!BtcVeldMintTemplatePolicy(
            old_mnp, issuer_script, from, to, amount, memo).empty());
        std::string family;
        CHECK(!BtcVeldRelayTemplatePolicy(
            Carrier("VELD_MSPV|4d53503200", fee_script), fee_script,
            family).empty());

        std::cout << "PASS daybreak_reopen_parity_tests checks=" << g_checks
                  << " cycles=3 final_prior_count="
                  << reopen_prior.transition_count << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL daybreak_reopen_parity_tests: "
                  << error.what() << '\n';
        return 1;
    }
}
