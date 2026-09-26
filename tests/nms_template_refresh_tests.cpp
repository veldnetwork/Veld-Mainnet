#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_TESTING 1
#define VELD_TEST_BRANCH_CONTEXT 1
#define VELD_TEST_NMS_BRANCH_CONTEXT 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_TEST_DATASET_BYTES (1024u * 1024u)
#include "node/node.h"
#include <future>
#include <iostream>
#include <stdexcept>

using namespace veld;
void Check(bool value, const char* message) {
    if (!value)
        throw std::runtime_error(message);
}

int main() try {
    Blockchain chain;
    Check(chain
              .AddBlockDirect(CreateGenesisBlock(), true, false, false,
                              mining::PowAdmissionContext::Internal())
              .IsAccepted(),
          "fixture genesis");
    const auto owner = GenerateKeyPair(false);
    const auto script = owner.GetP2PKHScript();
    UTXO funding;
    funding.tx_hash.fill(0x73);
    funding.value = 10 * MIN_TX_FEE;
    funding.script_pubkey = script;
    chain.TestInjectUTXO(funding);
    BlockHeader claim;
    claim.version = PROTOCOL_VERSION;
    claim.prev_block_hash = chain.TipCopy().GetHash();
    claim.timestamp = NextMiningTimestamp(chain);
    claim.bits = chain.ComputeNextBits();
    claim.nonce = 1;
    Transaction tx;
    TxInput input;
    input.prev_tx_hash = funding.tx_hash;
    tx.inputs.push_back(input);
    tx.outputs.emplace_back(MIN_TX_FEE, script);
    tx.outputs.emplace_back(0, BuildNmsOpReturnScript(EncodeNmsPayload(claim)));
    tx.outputs.emplace_back(funding.value - 2 * MIN_TX_FEE, script);
    tx.inputs[0].script_sig = owner.SignInput(tx, 0, script).script_sig;
    bool refreshed = false;
    for (unsigned attempt = 0; attempt < 8 && !refreshed; ++attempt) {
        Mempool pool;
        std::atomic<bool> stop{false}, built{false};
        auto search = std::async(std::launch::async, [&] {
            return MineOnly(chain, pool, owner, 0, &stop, {}, 1, nullptr, {}, nullptr, nullptr, {},
                            [&](const Block& candidate) {
                                Check(candidate.transactions.size() == 1,
                                      "original candidate must predate claim");
                                built.store(true);
                                return true;
                            });
        });
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
        while (!built.load() && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        if (!built.load()) {
            stop.store(true);
            search.get();
            throw std::runtime_error("candidate timeout");
        }
        Check(pool.Add(tx, MIN_TX_FEE, chain.Height(), chain) == Mempool::AddResult::ACCEPTED,
              "real signed near-miss admission");
        if (search.wait_for(std::chrono::seconds(15)) != std::future_status::ready) {
            stop.store(true);
            search.get();
            throw std::runtime_error("new claim never refreshed active mining");
        }
        const auto old_work = search.get();
        if (old_work.success)
            continue;
        Check(!stop.load() && old_work.hashes_tried > 0 && old_work.elapsed_ms >= 5000,
              "refresh must retain work accounting and respect rate limit");
        const auto rebuilt = MineOnly(chain, pool, owner, 0, nullptr, {}, 1, nullptr, {}, nullptr,
                                      nullptr, {}, nullptr, {}, true);
        Check(rebuilt.success && rebuilt.block.transactions.size() == 2 &&
                  rebuilt.block.transactions[1].GetTxID() == tx.GetTxID(),
              "replacement candidate includes the new claim");
        Check(chain
                  .AddBlockDirect(rebuilt.block, false, false, false,
                                  mining::PowAdmissionContext::Internal())
                  .IsAccepted(),
              "unchanged consensus accepts replacement candidate");
        Check(chain.NmsGetCredit(BytesToHex(script)) == 1, "confirmed lottery eligibility");
        chain.SetTotalSupplyForTesting(STAKING_UNLOCK_SUPPLY);
        const auto payouts =
            chain.ComputeExpectedPoolOutputs(chain.TipCopy().GetHash(), 100 * VELD_UNITS, 5000);
        uint64_t paid = 0, carried = 0;
        for (const auto& [recipient, value] : payouts) {
            if (recipient == script)
                paid += value;
            else if (recipient == AddressToScript(POOL_ADDRESS))
                carried += value;
            else
                Check(false, "unexpected payout recipient");
        }
        Check(paid == 20 * VELD_UNITS && carried == 80 * VELD_UNITS,
              "sole participant receives one slot and unused slots carry forward");
        refreshed = true;
    }
    Check(refreshed, "did not observe an unsolved search refresh");
    std::cout
        << "PASS active mining refresh, signed claim inclusion, confirmed eligibility and sole-participant payout\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << "FAIL " << error.what() << '\n';
    return 1;
}
