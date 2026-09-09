#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_TESTING 1
#define VELD_TEST_STAKE_OUTPOINT_BACKING 1
#include "node/node.h"
#include <cassert>
#include <future>
#include <iostream>

// Small benign fixtures only. No node Start, listener, peer, key generation,
// signature generation, serialized attack input or production data directory.
int main(int argc, char** argv) {
    using namespace veld;
    namespace fq = finality::qc;
    assert(argc == 2);
    assert(!std::filesystem::exists(argv[1]));
    {
        fq::EpochSnapshot snapshot;
        snapshot.epoch_id = 0;
        snapshot.root.fill(0x19);
        fq::SnapshotEntry member;
        member.pubkey_hex = std::string(dilithium::PUBKEY_BYTES * 2, '0');
        member.pubkey_commit = fq::PubkeyCommit(member.pubkey_hex);
        member.weight = 1;
        snapshot.entries.push_back(member);
        fq::SignedVote vote;
        vote.set_root = snapshot.root;
        vote.target.height = fq::CHECKPOINT_INTERVAL;
        vote.target.hash.fill(0x21);
        vote.round = fq::CheckpointRound(vote.target.height);
        vote.pubkey_hex = member.pubkey_hex;
        vote.signature.resize(dilithium::SIG_MAX_BYTES);
        fq::CertAssembler assembler;
        // Test-only in-memory storage seam: these bytes are not signed votes.
        assert(assembler.OfferAuthenticatedCapacityFixture(vote, snapshot));
        vote.phase = fq::Phase::PRECOMMIT;
        assert(assembler.OfferAuthenticatedCapacityFixture(vote, snapshot));
        assert(assembler.PoolSize() == 2);
        fq::QuorumCert decoded;
        decoded.phase = fq::Phase::PRECOMMIT;
        decoded.target = vote.target;
        decoded.round = vote.round;
        std::map<uint64_t, fq::EpochSnapshot> snapshots{{0, snapshot}};
        fq::EpochSnapshot other = snapshot;
        other.epoch_id = 1; other.root.fill(0x22);
        snapshots.emplace(1, other);
        fq::QuorumCert resolved;
        assert(fq::ResolveDurableCarrierClaim(decoded, snapshots, resolved));
        assert(resolved.set_root == snapshot.root);
        assert(resolved.target == decoded.target);
        // Staging owns the resolved identity even after epoch retention changes.
        snapshots.erase(0);
        assembler.RemoveFinalizedClaim(resolved);
        assert(assembler.PoolSize() == 0);
        assert(!fq::ResolveDurableCarrierClaim(decoded, snapshots, resolved));
        decoded.epoch_id = 1; decoded.phase = fq::Phase::PREVOTE;
        assert(!fq::ResolveDurableCarrierClaim(decoded, snapshots, resolved));
    }
    {
        struct OrdinaryBodyStore {
            size_t calls = 0; bool unavailable = false;
            Block GetBlock(uint64_t height, size_t limit) {
                ++calls;
                assert(limit == explorer::ExplorerHistoryBudget::BODY_LIMIT);
                if (unavailable) throw std::runtime_error("ordinary missing body");
                Block result; result.height = height; return result;
            }
        } store;
        explorer::ExplorerHistoryBudget shared;
        // A shared request budget includes outer and nested lookups.
        assert(shared.Read(store, 1).height == 1);
        store.unavailable = true;
        for (size_t i = 1; i < explorer::ExplorerHistoryBudget::MAX_READS; ++i) {
            try { (void)shared.Read(store, i); assert(false); } catch (const std::runtime_error&) {}
        }
        try { (void)shared.Read(store, 9); assert(false); } catch (const std::runtime_error&) {}
        assert(store.calls == explorer::ExplorerHistoryBudget::MAX_READS);
        assert(shared.remaining_load_bytes == 0);
    }
    {
        explorer::ExplorerLookupProgress progress;
        progress.ObserveTip(2, "ordinary-tip", false);
        // An unavailable newest body does not hide the readable older height.
        progress.MarkUnavailable(2);
        assert(progress.Next() == 1);
        progress.MarkAvailable(1);
        assert(progress.Next() == 0);
        progress.MarkAvailable(0);
        assert(!progress.Complete());
        progress.RetryUnavailable();
        assert(progress.Next() == 2);
        progress.MarkAvailable(2);
        assert(progress.Complete());
        progress.ObserveTip(3, "ordinary-extension", true);
        assert(!progress.Complete() && progress.Next() == 3);
        progress.MarkUnavailable(3);
        progress.ObserveTip(3, "replacement-tip", false);
        assert(progress.unavailable.none() && progress.Next() == 3);
        progress.MarkUnavailable(3);
        progress.ObserveTip(600, "ordinary-later-tip", true);
        assert(progress.unavailable.none());
    }
    Blockchain chain;
    const auto genesis = CreateGenesisBlock();
    assert(chain.AddBlockDirect(genesis, true, true, false,
        mining::PowAdmissionContext::Internal()).IsAccepted());
    size_t stake_checks = 0;
    chain.SetStakeBlockValidatorFn([&](const Block&) { ++stake_checks; return true; });
    Mempool pool;
    Transaction ordinary;
    ordinary.inputs.resize(1);
    ordinary.inputs[0].prev_tx_hash.fill(0x11);
    ordinary.outputs.emplace_back(1000000, std::vector<uint8_t>{0x51});
    pool.InsertUncheckedForTest(ordinary);
    assert(pool.Add(ordinary, MIN_TX_FEE, 0, chain) == Mempool::AddResult::DUPLICATE);
    assert(stake_checks == 0);
    auto other_tx = ordinary;
    other_tx.inputs[0].prev_tx_hash[1] = 2;
    other_tx.InvalidateTxIDCache();
    (void)pool.Add(other_tx, MIN_TX_FEE, 0, chain);
    assert(stake_checks == 1);

    // Summary boundary is tested just beyond its 200-row cap, using tiny
    // ordinary unsigned records. It never materializes signature-sized bodies.
    uint64_t expected_fees = MIN_TX_FEE;
    for (size_t i = 1; i <= Mempool::MAX_SUMMARY_ROWS; ++i) {
        Transaction tx = ordinary;
        tx.inputs[0].prev_out_index = static_cast<uint32_t>(i);
        tx.InvalidateTxIDCache();
        pool.InsertUncheckedForTest(tx, MIN_TX_FEE + i);
        expected_fees += MIN_TX_FEE + i;
    }
    const auto summaries = pool.GetSummaryPage();
    assert(summaries.total_count == Mempool::MAX_SUMMARY_ROWS + 1);
    assert(summaries.rows.size() == Mempool::MAX_SUMMARY_ROWS);
    assert(summaries.total_bytes == pool.Bytes());
    assert(summaries.total_fee_units == expected_fees);
    assert(summaries.rows.front().fee == MIN_TX_FEE + Mempool::MAX_SUMMARY_ROWS);
    assert(summaries.rows.back().fee == MIN_TX_FEE + 1);
    assert(summaries.rows.front().input_count == 1 && summaries.rows.front().output_count == 1);

    // A simple true covenant provides a legitimate no-key control. Relative
    // maturity is contextual; the same bytes must be reconsidered when the
    // confirmation context changes. Test hooks install only in-memory UTXOs.
    const std::vector<uint8_t> redeem{0x51};
    const auto hash = Hash160Compute(redeem.data(), redeem.size());
    std::vector<uint8_t> covenant{0xa9,0x14};
    covenant.insert(covenant.end(), hash.begin(), hash.end()); covenant.push_back(0x87);
    UTXO u;
    u.tx_hash.fill(0x35); u.value = 2 * VELD_UNITS;
    u.script_pubkey = covenant; u.block_height = 2; u.is_coinbase = false;
    chain.TestInjectUTXO(u);
    Transaction contextual;
    contextual.version = 2;
    contextual.inputs.resize(1);
    contextual.inputs[0].prev_tx_hash = u.tx_hash;
    contextual.inputs[0].script_sig = {1, 0x51};
    contextual.inputs[0].sequence = 1;
    contextual.outputs.emplace_back(u.value - MIN_TX_FEE, std::vector<uint8_t>{0x51});
    bool permanent = true;
    assert(!chain.ValidateTransactionLocking(contextual, false, &permanent) && !permanent);
    Mempool contextual_pool;
    assert(contextual_pool.Add(contextual, MIN_TX_FEE, 0, chain) == Mempool::AddResult::INVALID);
    u.block_height = 0; chain.TestEraseUTXO(u.tx_hash, 0); chain.TestInjectUTXO(u);
    assert(chain.ValidateTransactionLocking(contextual, false, &permanent) && !permanent);
    assert(contextual_pool.Add(contextual, MIN_TX_FEE, 0, chain) == Mempool::AddResult::ACCEPTED);
    UTXO auth = u; auth.tx_hash.fill(0x36);
    auth.script_pubkey = {0x76, 0xa9, 0x14}; auth.script_pubkey.insert(auth.script_pubkey.end(), 20, 0x19);
    auth.script_pubkey.insert(auth.script_pubkey.end(), {0x88, 0xac}); chain.TestInjectUTXO(auth);
    auto unsigned_fixture = contextual; unsigned_fixture.inputs[0].prev_tx_hash = auth.tx_hash;
    unsigned_fixture.inputs[0].script_sig.clear();
    unsigned_fixture.InvalidateTxIDCache();
    assert(!chain.ValidateTransactionLocking(unsigned_fixture, false, &permanent) && permanent);

    explorer::BlockExplorer explorer(chain, pool);
    auto route = [&](const std::string& path) {
        return explorer.Route(explorer::HttpRequest::Parse("GET " + path + " HTTP/1.1\r\nHost: localhost\r\n\r\n"));
    };
    const auto txid = HashToHex(genesis.transactions[0].GetTxID());
    const auto located = route("/tx/" + txid);
    assert(located.status_code == 302 && located.headers.at("Location") == "/block/height/0");
    const auto absent = route("/tx/" + HashToHex(ZeroHash()));
    assert(absent.body.find("not found in the recent 501-block window") != std::string::npos);
    const auto page = route("/api/v1/blocks/latest/1");
    assert(page.status_code == 200 && page.body.find("\"tx_count\":1") != std::string::npos);
    assert(page.body.find("\"tip_hash\":\"" + HashToHex(genesis.GetHash()) + "\"") != std::string::npos);
    const auto pending = route("/mempool");
    assert(pending.status_code == 200 && pending.body.find("200 of 201 pending") != std::string::npos);

    {
        VeldNode node(MainnetConfig(), argv[1]);
        node.SetQuietBoot(true);
        assert(node.GetChainMut().AddBlockDirect(genesis, true, true, false,
            mining::PowAdmissionContext::Internal()).IsAccepted());
        const auto page = node.TestReadRedeemPage();
        assert(page.find("\"final_height\":0") != std::string::npos);
        std::future<std::string> read;
        std::promise<void> started;
        auto ready = started.get_future();
        {
            auto transition = node.GetChain().AcquireConsensusTransitionGuard();
            read = std::async(std::launch::async, [&] {
                started.set_value(); return node.TestReadRedeemPage();
            });
            ready.wait();
            assert(read.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout);
        }
        assert(read.wait_for(std::chrono::seconds(2)) == std::future_status::ready);
        assert(read.get() == page);
    }
    std::cout << "PASS: epoch retirement identity; aggregate history budget; duplicate fast path; bounded summaries; contextual retry; Explorer controls; coherent payout-page read\n";
}
