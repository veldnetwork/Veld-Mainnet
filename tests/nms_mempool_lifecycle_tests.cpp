#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_TESTING 1
#define VELD_TEST_BRANCH_CONTEXT 1
#define VELD_TEST_NMS_BRANCH_CONTEXT 1

#include "core/mempool.h"
#include "crypto/veld_signing.h"
#include "network/tcp.h"
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
        Mempool relay;
#ifdef EXPECT_STALE_RELAY_DEFECT
        const auto expired_result = Mempool::AddResult::INVALID;
#else
        const auto expired_result = Mempool::AddResult::EXPIRED_NMS;
#endif
        for (unsigned retry = 0; retry < 12; ++retry)
            Check(relay.Add(old, MIN_TX_FEE, chain.Height(), chain) ==
                expired_result,
                "expired relay is not an invalid-transaction offence");
        Check(!relay.Contains(old.GetTxID()), "expired relay never admitted");
        Check(!relay.GetSpender(old_input.tx_hash, old_input.output_index),
            "expired relay never reserves funds");
        auto forged = old;
        forged.inputs[0].script_sig.back() ^= 1;
        forged.InvalidateTxIDCache();
        Check(relay.Add(forged, MIN_TX_FEE, chain.Height(), chain) ==
            Mempool::AddResult::INVALID, "forged expired claim still invalid");
        auto unknown_header = Claim(chain, 333);
        unknown_header.prev_block_hash.fill(0xa4);
        const auto unknown = Spend(old_input, signer, unknown_header);
        Check(relay.Add(unknown, MIN_TX_FEE, chain.Height(), chain) ==
            Mempool::AddResult::INVALID, "unknown parent is not expiry");
        auto wrong_target = ExtractNmsFromTx(old)->header;
        wrong_target.bits ^= 1;
        const auto malformed = Spend(old_input, signer, wrong_target);
        Check(relay.Add(malformed, MIN_TX_FEE, chain.Height(), chain) ==
            Mempool::AddResult::INVALID, "incorrect old target still invalid");
        compat::InitNetwork();
        {
            Mempool peer_pool;
            net::NodeServer server(0, MAINNET_MAGIC, chain, peer_pool);
            const std::string peer_ip = "198.51.100.68";
            const auto fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            Check(compat::IsValidSocket(fd), "peer fixture socket");
            net::Connection peer(fd, peer_ip, 32068, true);
            const P2PMessage message(MAINNET_MAGIC, MessageType::TX, old.Serialize());
            for (unsigned retry = 0; retry < 12; ++retry)
                server.TestDispatchPeerMessage(peer, message);
#ifdef EXPECT_STALE_RELAY_DEFECT
            Check(server.IsBanned(peer_ip), "baseline reproduces stale relay ban");
#else
            Check(!server.IsBanned(peer_ip) &&
                server.TestViolationScore(peer_ip) == 0,
                "repeated expired relay has zero peer penalty");
            Check(net::NodeServer::MempoolRejectBanScore(expired_result) == 0,
                "expiration carries no ban score");
#endif
            Check(!peer_pool.Contains(old.GetTxID()), "peer expiry never admitted");
            const auto invalid_fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            Check(compat::IsValidSocket(invalid_fd), "invalid peer fixture socket");
            const std::string invalid_ip = "198.51.100.69";
            net::Connection invalid_peer(invalid_fd, invalid_ip, 32069, true);
            server.TestDispatchPeerMessage(invalid_peer,
                P2PMessage(MAINNET_MAGIC, MessageType::TX, malformed.Serialize()));
            Check(server.TestViolationScore(invalid_ip) == 10,
                "invalid target still penalized through peer handler");
        }
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
