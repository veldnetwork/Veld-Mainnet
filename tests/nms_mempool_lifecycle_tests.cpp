#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_TESTING 1
#define VELD_TEST_BRANCH_CONTEXT 1
#define VELD_TEST_NMS_BRANCH_CONTEXT 1

#include "core/mempool.h"
#include "crypto/veld_signing.h"
#include <iostream>
#include <stdexcept>

using namespace veld;
namespace {
unsigned checks = 0;
void Check(bool ok, const char* label) {
    ++checks;
    if (!ok) throw std::runtime_error(label);
}
UTXO Funding(Blockchain& chain, const RealKeyPair& signer, uint8_t tag) {
    UTXO u;
    u.tx_hash.fill(tag);
    u.output_index = 0;
    u.value = 20 * MIN_TX_FEE;
    u.script_pubkey = signer.GetP2PKHScript();
    u.block_height = chain.Height();
    u.is_coinbase = false;
    chain.TestInjectUTXO(u);
    return u;
}
Transaction Spend(const UTXO& u, const RealKeyPair& signer,
                  const std::optional<BlockHeader>& claim = std::nullopt) {
    Transaction tx;
    TxInput input;
    input.prev_tx_hash = u.tx_hash;
    input.prev_out_index = u.output_index;
    tx.inputs.push_back(input);
    if (claim) {
        tx.outputs.emplace_back(MIN_TX_FEE, u.script_pubkey);
        tx.outputs.emplace_back(0, BuildNmsOpReturnScript(EncodeNmsPayload(*claim)));
        tx.outputs.emplace_back(u.value - 2 * MIN_TX_FEE, u.script_pubkey);
    } else {
        tx.outputs.emplace_back(u.value - MIN_TX_FEE, u.script_pubkey);
    }
    tx.inputs[0].script_sig = signer.SignInput(tx, 0, u.script_pubkey).script_sig;
    return tx;
}
BlockHeader Claim(Blockchain& chain, uint64_t nonce) {
    BlockHeader h;
    h.version = PROTOCOL_VERSION;
    h.prev_block_hash = chain.TipCopy().GetHash();
    h.timestamp = chain.TipCopy().header.timestamp + 1;
    h.bits = chain.ComputeNextBits();
    h.merkle_root.fill(static_cast<uint8_t>(nonce));
    h.nonce = nonce;
    return h;
}
Block Candidate(Blockchain& chain, const RealKeyPair& signer,
                const std::vector<std::pair<Transaction, uint64_t>>& entries = {}) {
    Block b;
    b.height = chain.Height() + 1;
    b.header = Claim(chain, b.height * 101);
    uint64_t fees = 0;
    for (const auto& entry : entries) fees += entry.second;
    const uint64_t subsidy = Blockchain::ExpectedBlockSubsidy(b.height);
    b.transactions.push_back(Transaction::CreateProportionalCoinbase({
        {signer.GetP2PKHScript(), subsidy / 2},
        {AddressToScript(VaultAddressAtHeight(b.height)), subsidy - subsidy / 2 + fees}
    }, "Veld block " + std::to_string(b.height)));
    for (const auto& entry : entries) b.transactions.push_back(entry.first);
    b.UpdateMerkleRoot();
    return b;
}
bool Contains(const std::vector<std::pair<Transaction, uint64_t>>& rows,
              const Transaction& tx) {
    for (const auto& row : rows) if (row.first.GetTxID() == tx.GetTxID()) return true;
    return false;
}
}
int main() {
    try {
        Blockchain chain;
        Check(chain.AddBlockDirect(CreateGenesisBlock(), true, false, false,
            mining::PowAdmissionContext::Internal()).IsAccepted(), "genesis");
        const auto signer = GenerateKeyPair(false);
        Check(chain.AddBlockDirect(Candidate(chain, signer), false, false, false,
            mining::PowAdmissionContext::Internal()).IsAccepted(), "first block");
        Mempool pool;
        const auto old_input = Funding(chain, signer, 0x81);
        const auto old = Spend(old_input, signer, Claim(chain, 111));
        Check(pool.Add(old, MIN_TX_FEE, chain.Height(), chain) ==
            Mempool::AddResult::ACCEPTED, "current signed claim admission");
        Check(Contains(pool.GetBlockTransactionsWithFees(20, MAX_BLOCK_SIZE, &chain), old),
            "current claim selectable");
        Check(chain.ValidateNmsLocking(*ExtractNmsFromTx(old), chain.Height() + 1) ==
            NmsValidationDisposition::Valid, "current claim consensus context");

        Check(chain.AddBlockDirect(Candidate(chain, signer), false, false, false,
            mining::PowAdmissionContext::Internal()).IsAccepted(), "competing block");
        Check(chain.ValidateNmsLocking(*ExtractNmsFromTx(old), chain.Height() + 1) ==
            NmsValidationDisposition::ConsensusInvalid, "old claim expires at next tip");
        const auto fresh = Spend(Funding(chain, signer, 0x82), signer, Claim(chain, 222));
        const auto payment = Spend(Funding(chain, signer, 0x83), signer);
        Check(pool.Add(fresh, MIN_TX_FEE, chain.Height(), chain) ==
            Mempool::AddResult::ACCEPTED, "fresh claim admission");
        Check(pool.Add(payment, MIN_TX_FEE, chain.Height(), chain) ==
            Mempool::AddResult::ACCEPTED, "payment admission");
        UTXO child_input;
        child_input.tx_hash = old.GetTxID();
        child_input.output_index = 2;
        child_input.value = old.outputs[2].value;
        child_input.script_pubkey = old.outputs[2].script_pubkey;
        const auto child = Spend(child_input, signer);
        pool.InsertUncheckedForTest(child, MIN_TX_FEE, true);
        const auto selected = pool.GetBlockTransactionsWithFees(20, MAX_BLOCK_SIZE, &chain);
        Check(Contains(selected, fresh) && Contains(selected, payment),
            "current claim and payment retained");
        Check(!Contains(selected, child), "unconfirmed child withheld");
#ifdef EXPECT_STALE_NMS_DEFECT
        Check(Contains(selected, old), "baseline reproduces expired selection");
        Check(pool.RemoveStale(chain) == 0, "baseline maintenance misses expired claim");
        const auto rejected = chain.AddBlockDirect(Candidate(chain, signer, selected),
            false, false, false, mining::PowAdmissionContext::Internal());
        Check(rejected.Disposition() == Blockchain::BlockAdmissionDisposition::ConsensusInvalid &&
            Blockchain::GetLastRejectTag() == "nms_validation_failed",
            "baseline completed candidate rejected for expired claim");
#else
        Check(!Contains(selected, old), "expired claim excluded before maintenance");
        const auto direct = pool.GetBlockTransactions(20, MAX_BLOCK_SIZE, &chain);
        for (const auto& tx : direct)
            Check(tx.GetTxID() != old.GetTxID(), "transaction-only selector excludes expired claim");
        Check(pool.RemoveStale(chain) == 2, "maintenance removes expired claim and descendant");
        Check(!pool.Contains(old.GetTxID()) && !pool.Contains(child.GetTxID()),
            "expired graph removed");
        Check(pool.Contains(fresh.GetTxID()) && pool.Contains(payment.GetTxID()),
            "current entries survive maintenance");
        Check(!pool.GetSpender(old_input.tx_hash, old_input.output_index),
            "expired claim releases input reservation");
        Check(pool.RemoveStale(chain) == 0, "maintenance idempotent");
        const auto candidate = Candidate(chain, signer, selected);
        const auto accepted = chain.AddBlockDirect(candidate,
            false, false, false, mining::PowAdmissionContext::Internal());
        Check(accepted.IsAccepted(), "same consensus accepts corrected candidate");
        pool.RemoveConfirmed(candidate);
        Check(!pool.Contains(fresh.GetTxID()) && !pool.Contains(payment.GetTxID()),
            "confirmed entries removed");
        Check(chain.Height() == 3, "chain advances through expired claim");
#endif
        std::cout << "PASS " << checks << " checks; synthetic PoW, real signed transactions\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL after " << checks << " checks: " << error.what() << "\n";
        return 1;
    }
}
