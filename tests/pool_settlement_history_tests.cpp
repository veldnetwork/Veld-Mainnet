#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#include "core/blockchain.h"
#include <iostream>
#include <stdexcept>

using namespace veld;
void Check(bool value, const char* label) {
    if (!value)
        throw std::runtime_error(label);
}
Block Child(const Block& parent, const char* label) {
    Block b;
    b.height = parent.height + 1;
    b.header.prev_block_hash = parent.GetHash();
    b.header.timestamp = parent.header.timestamp + 180;
    b.header.bits = parent.header.bits;
    Transaction cb;
    cb.inputs.push_back(TxInput::Coinbase(std::string(label) + std::to_string(b.height)));
    cb.outputs.emplace_back(1, AddressToScript(VaultAddressAtHeight(b.height)));
    for (int i = 0; i < 3; ++i)
        cb.outputs.emplace_back(1, std::vector<uint8_t>{0x51});
    b.transactions.push_back(cb);
    b.UpdateMerkleRoot();
    return b;
}
void Admit(Blockchain& chain, const Block& b) {
    Check(chain.AddBlockDirect(b, true, true, false, mining::PowAdmissionContext::Internal())
              .IsAccepted(),
          "synthetic summary fixture admission");
}
int main() {
    try {
        Blockchain chain;
        auto b = CreateGenesisBlock();
        Admit(chain, b);
        b = Child(b, "a");
        Admit(chain, b);
        const auto parent = b;
        b = Child(b, "a");
        for (uint32_t index = 1; index <= 3; ++index) {
            Transaction tx;
            TxInput input;
            input.prev_tx_hash = parent.transactions[0].GetTxID();
            input.prev_out_index = index;
            tx.inputs.push_back(input);
            tx.outputs.emplace_back(
                index == 2 ? 1 : 0,
                index == 2 ? std::vector<uint8_t>{0x51}
                           : std::vector<uint8_t>{0x6A, 1, static_cast<uint8_t>(index)});
            b.transactions.push_back(tx);
        }
        b.UpdateMerkleRoot();
        Admit(chain, b);
        const auto summary = chain.TestSettlementHistory(2);
        Check(summary == std::vector<std::vector<uint8_t>>{b.transactions[0].Serialize(),
                                                           b.transactions[1].Serialize(),
                                                           b.transactions[3].Serialize()},
              "coinbase and all marker transaction bytes retained exactly");
        chain.TestResetBlockBodyLookupCount();
        Check(chain.TestSettlementHistory(2) == summary && chain.TestBlockBodyLookupCount() == 0,
              "cached facts avoid a second historical body load");
        for (uint64_t height = 3; height <= 600; ++height) {
            b = Child(b, "a");
            Admit(chain, b);
            chain.TestSettlementHistory(height);
        }
        const auto bounds = chain.TestSettlementHistoryCacheSize();
        Check(bounds.first <= 512 && bounds.second <= 16 * 1024 * 1024,
              "entry and encoded byte limits enforced");
        Check(chain.ComputeVaultInflowSinceLastDistribution(600) == 480,
              "historical vault inflow unchanged");
        Check(chain.ComputeVaultInflowSinceLastDistribution(601) == 479,
              "candidate boundary excludes its not-yet-included coinbase");
        const auto old = chain.TestSettlementHistory(600);
        Check(chain.RollbackTip(), "synthetic rollback");
        b = Child(chain.TipCopy(), "replacement");
        Admit(chain, b);
        chain.TestResetBlockBodyLookupCount();
        Check(chain.TestSettlementHistory(600) != old && chain.TestBlockBodyLookupCount() == 1,
              "same height on replacement fork cannot reuse old hash-bound facts");
        std::cout
            << "PASS immutable settlement facts, exact bytes, bounds, inflow and fork identity; synthetic fixture\n";
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
