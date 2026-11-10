// Disk-backed node/module regression with a separate genesis and no listeners.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_ASERT_TESTCHAIN 1
#define VELD_TEST_BRANCH_CONTEXT 1
#define VELD_TEST_STAKE_OUTPOINT_BACKING 1
#ifndef VELD_PROTOCOL_UPGRADE_TEST_HEIGHT
#define VELD_PROTOCOL_UPGRADE_TEST_HEIGHT 3360
#endif
#define VELD_MINER_FEE_TEST_HEIGHT 4000
#include "node/node.h"
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace veld;
namespace fs = std::filesystem;
namespace {
size_t checks = 0;
constexpr uint64_t activation = MINER_FEE_ACTIVATION_HEIGHT;
static_assert(PROTOCOL_UPGRADE_HEIGHT == 3360 && activation == 4000);
constexpr uint64_t settlement = (activation / VAULT_BLOCK_INTERVAL + 1) * VAULT_BLOCK_INTERVAL;
#ifdef VELD_SUBSIDY_TEST_FIRST_HALVING
static_assert(SUBSIDY_ACTIVATION_HEIGHT == 4000 && FIRST_HALVING_HEIGHT == 4001 && SECOND_HALVING_HEIGHT == 4101);
#endif
static_assert(activation > CONSENSUS_SECURITY_UPGRADE_HEIGHT);
void Require(bool value, const std::string& message) {
    ++checks;
    if (!value)
        throw std::runtime_error(message);
}
std::unique_ptr<VeldNode> Open(const fs::path& data, bool fresh) {
    if (fresh)
        Require(!fs::exists(data), "fresh disposable directory required");
    auto config = RegtestConfig();
    config.port = 31349;
    auto node = std::make_unique<VeldNode>(config, data.string());
    node->SetQuietBoot(true);
    if (fresh) {
        node->TestPrepareDStateQualificationIngest();
        Require(node->TestIngestDStateQualificationFrame(CreateGenesisBlock().Serialize(), 0),
                "genesis refused");
    }
    Require(node->GetTCPServer() == nullptr, "offline fixture opened P2P");
    return node;
}
Block Candidate(VeldNode& node, const RealKeyPair& owner, uint64_t nonce) {
    auto& chain = node.GetChainMut();
    const auto h = chain.Height() + 1;
    return node.TestBuildDStateQualificationBlock(h, owner.GetP2PKHScript(), "-", "-",
                                                  chain.TipCopy().header.timestamp + 180, nonce);
}
void Accept(VeldNode& node, const Block& block, const char* label = "node") {
    const bool accepted = node.TestIngestDStateQualificationFrame(block.Serialize(), block.height);
    Require(accepted, std::string(label) + " canonical admission failed at " +
                std::to_string(block.height) + " current=" + std::to_string(node.GetChain().Height()) +
                ": " + Blockchain::GetLastRejectTag());
    if (block.height == activation - 1) {
        const auto vault = node.TestVaultAccountingSnapshot();
        const auto found = std::find_if(vault.log.begin(), vault.log.end(), [&](const VaultEntry& entry) {
            return entry.label == "fees block " + std::to_string(block.height) &&
                   entry.amount_units == MIN_TX_FEE + 17;
        });
        Require(found != vault.log.end(), "historical vault fee income was lost");
    }
    if (block.height >= activation) {
        const auto vault = node.TestVaultAccountingSnapshot();
        for (const auto& entry : vault.log) {
            if (entry.label.rfind("fees block ", 0) == 0)
                Require(std::stoull(entry.label.substr(11)) < activation,
                        "miner-owned fees were recorded as vault income");
        }
    }
}
void Fee(VeldNode& node, const RealKeyPair& owner, uint64_t amount) {
    auto& chain = node.GetChainMut();
    auto coins = chain.GetUTXOsForScript(owner.GetP2PKHScript());
    std::sort(coins.begin(), coins.end(), [](const UTXO& a, const UTXO& b) {
        return a.block_height < b.block_height ||
               (a.block_height == b.block_height &&
                UTXOKey(a.tx_hash, a.output_index) < UTXOKey(b.tx_hash, b.output_index));
    });
    uint64_t sum = 0;
    Transaction tx;
    for (const auto& coin : coins) {
        if (coin.is_coinbase && chain.Height() + 1 < coin.block_height + COINBASE_MATURITY)
            continue;
        TxInput input;
        input.prev_tx_hash = coin.tx_hash;
        input.prev_out_index = coin.output_index;
        tx.inputs.push_back(input);
        sum += coin.value;
        if (sum > amount + MIN_TX_FEE)
            break;
    }
    Require(sum > amount + MIN_TX_FEE, "insufficient mature fixture rewards");
    tx.outputs.emplace_back(sum - amount, owner.GetP2PKHScript());
    for (size_t i = 0; i < tx.inputs.size(); ++i)
        tx.inputs[i].script_sig =
            owner.SignInput(tx, static_cast<uint32_t>(i), owner.GetP2PKHScript()).script_sig;
    const auto result =
        node.GetMempoolMut().Add(tx, amount, static_cast<uint32_t>(chain.Height()), chain);
    Require(result == Mempool::AddResult::ACCEPTED,
            std::string("signed fee transaction refused by mempool: ") +
                Mempool::ResultToString(result));
}
void CheckFeeAllocation(VeldNode& node, const Block& block,
                        const RealKeyPair& owner, uint64_t fee) {
    const uint64_t subsidy = std::min(Blockchain::ExpectedBlockSubsidy(block.height),
                                     MAX_SUPPLY_UNITS - node.GetChain().TotalSupplyUnits());
    const bool periodic = block.height % VAULT_BLOCK_INTERVAL == 0;
    const bool locked = node.GetChain().TotalSupplyUnits() < STAKING_UNLOCK_SUPPLY;
    uint64_t miner = 0, vault = 0, pool = 0, endorsement = 0;
    Require(subsidy > 0, "this durable fixture must still issue subsidy");
    if (periodic) vault = subsidy;
    else if (locked) { miner = subsidy / 2; vault = subsidy - miner; }
    else {
        pool = subsidy / 5; vault = subsidy / 5; endorsement = subsidy / 10;
        miner = subsidy - pool - vault - endorsement;
    }
    if (block.height >= activation) miner += fee;
    else vault += fee;
    const auto paid = [&](const std::vector<uint8_t>& script) {
        uint64_t result = 0;
        for (const auto& output : block.transactions.front().outputs)
            if (output.script_pubkey == script) result += output.value;
        return result;
    };
    Require(paid(owner.GetP2PKHScript()) == miner, "miner fee allocation differs");
    Require(paid(AddressToScript(VaultAddressAtHeight(block.height))) == vault,
            "vault subsidy or historical fee changed");
    Require(paid(AddressToScript(PoolAddressAtHeight(block.height))) == pool,
            "pool subsidy changed");
    Require(paid(AddressToScript(EndorsementPoolAddressAtHeight(block.height))) == endorsement,
            "endorsement subsidy changed");
    Require(block.transactions.front().TotalOutput() == subsidy + fee,
            "coinbase value is not subsidy plus recycled fees");
}
#ifdef VELD_SUBSIDY_TEST_FIRST_HALVING
void CheckSubsidyBoundary(VeldNode& node, const Block& block) {
    const auto h = block.height;
    // Literal independent monetary oracle at both shortened durable boundaries.
    const uint64_t expected = h < 4001 ? 313926940 : h < 4101 ? 156963470 : 78481735;
    Require(Blockchain::ExpectedBlockSubsidy(h) == expected, "durable subsidy boundary differs");
    if (h != 4001 && h != 4101) return;
    Block old = block;
    const uint64_t difference = h == 4001 ? 156963470 : 78481735;
    old.transactions.front().outputs.front().value += difference;
    old.transactions.front().InvalidateTxIDCache();old.UpdateMerkleRoot();
    const auto state = node.ConsensusStateDigest();
    Require(!node.GetChain().ValidateMiningCoinbase(old), "old subsidy passed mining policy after halving");
    Require(!node.TestIngestDStateQualificationFrame(old.Serialize(), h), "old subsidy entered durable chain after halving");
    Require(node.ConsensusStateDigest() == state, "refused old subsidy changed state");
}
#endif
void RejectFormerFeeRouting(VeldNode& node, const Block& candidate,
                           const RealKeyPair& owner, uint64_t fee) {
    Require(candidate.height >= activation && fee > 0, "active fee fixture required");
    Block former = candidate;
    bool movedMiner = false, movedVault = false;
    const auto vault = AddressToScript(VaultAddressAtHeight(candidate.height));
    for (auto& output : former.transactions.front().outputs) {
        if (output.script_pubkey == owner.GetP2PKHScript()) {
            Require(output.value >= fee, "miner is missing the fee");
            output.value -= fee; movedMiner = true;
        } else if (output.script_pubkey == vault) {
            output.value += fee; movedVault = true;
        }
    }
    Require(movedMiner && movedVault, "expected coinbase recipients absent");
    // On a periodic vault block the historical policy has no miner output.
    // Remove that zero output so this is a well-formed former policy, rather
    // than a malformed transaction rejected before allocation validation.
    auto& outputs = former.transactions.front().outputs;
    outputs.erase(std::remove_if(outputs.begin(), outputs.end(), [&](const auto& output) {
                      return output.value == 0 && output.script_pubkey == owner.GetP2PKHScript();
                  }), outputs.end());
    former.transactions.front().InvalidateTxIDCache();
    former.UpdateMerkleRoot();
    Require(former.transactions.front().IsValid(), "former policy must be structurally valid");
    const auto state = node.ConsensusStateDigest();
    Require(!node.GetChain().ValidateMiningCoinbase(former), "former fee routing accepted by mining");
    Require(!node.TestIngestDStateQualificationFrame(former.Serialize(), former.height),
            "former fee routing accepted by block admission");
    Require(node.ConsensusStateDigest() == state, "refused former routing changed state");
}
void Equal(VeldNode& a, VeldNode& b, const char* label) {
    const auto x = a.TestObserveDStateQualificationState(),
               y = b.TestObserveDStateQualificationState();
    Require(x.tip_hash == y.tip_hash && x.canonical_supply_units == y.canonical_supply_units &&
                x.utxo_digest == y.utxo_digest && x.supply_digest == y.supply_digest &&
                x.consensus_state_digest == y.consensus_state_digest &&
                x.token_digest == y.token_digest && x.amm_digest == y.amm_digest &&
                x.miner_archive_digest == y.miner_archive_digest,
            label);
    Require(!x.durable_publication_pending && !x.utxo_recovery_required &&
                !x.reorg_recovery_frame_pending && !x.durability_compromised &&
                !x.durable_commit_fail_stop && !x.fail_stop_required && x.module_cursor_matches,
            "node has unresolved durability or module state");
}
}
int main(int argc, char** argv) {
    try {
        Require(argc == 2, "supply a fresh disposable directory");
        const auto root = fs::absolute(argv[1]).lexically_normal();
        Require(!fs::exists(root), "existing fixture must be preserved");
        fs::create_directories(root);
        auto owner = GenerateKeyPair(true);
        auto direct = Open(root / "direct", true);
        std::vector<Block> history;
        history.push_back(CreateGenesisBlock());
        for (uint64_t h = 1; h < activation; ++h) {
            if (h == activation - 1) Fee(*direct, owner, MIN_TX_FEE + 17);
            const auto block = Candidate(*direct, owner, h);
            if (h == activation - 1)
                CheckFeeAllocation(*direct, block, owner, MIN_TX_FEE + 17);
            Accept(*direct, block);
            history.push_back(block);
            if (h % 480 == 0)
                std::cout << "PROGRESS durable height=" << h << std::endl;
        }
        auto branch = Open(root / "branch", true);
        for (size_t h = 1; h < history.size(); ++h)
            Accept(*branch, history[h]);
        Equal(*direct, *branch, "same parent state differs");
        for (uint64_t h = activation; h <= activation + 1; ++h)
            Accept(*direct, Candidate(*direct, owner, 100000 + h));
        Fee(*branch, owner, 6 * BLOCK_REWARD_UNITS + 1);
        for (uint64_t h = activation; h <= activation + 2; ++h) {
            if (h == activation + 1) Fee(*branch, owner, 2 * MIN_TX_FEE + 1);
            auto block = Candidate(*branch, owner, 200000 + h);
#ifdef VELD_SUBSIDY_TEST_FIRST_HALVING
            CheckSubsidyBoundary(*branch, block);
#endif
            Require(branch->GetChain().ValidateMiningCoinbase(block),
                    "mining policy rejected canonical candidate");
            if (h == activation) {
                Require(!branch->GetChain().ValidateLegacyMinerCaps(block),
                        "fee fixture did not exceed old backstop");
                Require(block.transactions.size() > 1, "fee or mandatory settlement omitted");
                CheckFeeAllocation(*branch, block, owner, 6 * BLOCK_REWARD_UNITS + 1);
                RejectFormerFeeRouting(*branch, block, owner, 6 * BLOCK_REWARD_UNITS + 1);
            } else if (h == activation + 1) {
                CheckFeeAllocation(*branch, block, owner, 2 * MIN_TX_FEE + 1);
                RejectFormerFeeRouting(*branch, block, owner, 2 * MIN_TX_FEE + 1);
            }
            Require(branch->GetChain().ValidateMiningCoinbase(block),
                    "refusal mutated the canonical candidate or parent state");
            Accept(*branch, block, "branch");
            history.push_back(block);
            Accept(*direct, block, "reorganizing node");
        }
        Equal(*direct, *branch, "direct versus reorg state differs across activation");
        std::cout
            << "PASS activation reorganization and exact UTXO/supply/module/archive equality\n";

        auto independent = Open(root / "independent", true);
        for (size_t h = 1; h < history.size(); ++h)
            Accept(*independent, history[h]);
        Equal(*branch, *independent, "independent full admission replay differs");
        for (uint64_t h = activation + 3; h <= settlement + 2; ++h) {
            if (h == settlement)
                Fee(*branch, owner, 30 * BLOCK_REWARD_UNITS + 1);
            auto block = Candidate(*branch, owner, h);
#ifdef VELD_SUBSIDY_TEST_FIRST_HALVING
            CheckSubsidyBoundary(*branch, block);
#endif
            if (h == settlement) {
                Require(!branch->GetChain().ValidateLegacyMinerCaps(block),
                        "vault fee fixture missed old total boundary");
                CheckFeeAllocation(*branch, block, owner, 30 * BLOCK_REWARD_UNITS + 1);
                RejectFormerFeeRouting(*branch, block, owner, 30 * BLOCK_REWARD_UNITS + 1);
            }
            Accept(*branch, block);
            Accept(*independent, block);
            Accept(*direct, block);
            history.push_back(block);
        }
        Equal(*direct, *branch, "ordinary and vault fee histories differ");
        Equal(*independent, *branch, "independent accepted state differs");
        auto bad = Candidate(*branch, owner, 999999);
        ++bad.transactions.front().outputs.front().value;
        bad.transactions.front().InvalidateTxIDCache();
        bad.UpdateMerkleRoot();
        const auto digest = branch->ConsensusStateDigest();
        Require(!branch->GetChain().ValidateMiningCoinbase(bad), "overpayment preflight accepted");
        Require(!branch->TestIngestDStateQualificationFrame(bad.Serialize(), bad.height),
                "overpayment admission accepted");
        Require(branch->ConsensusStateDigest() == digest, "rejected coinbase changed module state");
        const auto height = branch->GetChain().Height();
        branch.reset();
        branch = Open(root / "branch", false);
        branch->TestReplayDStateQualificationCorpus(height);
        Equal(*direct, *branch, "disk restart replay differs from accepted state");
        Require(branch->GetTCPServer() == nullptr, "restart fixture opened a listener");
        std::ofstream receipt(root / "result.json");
        receipt << "{\"status\":\"passed\",\"height\":" << height << ",\"checks\":" << checks
#ifdef VELD_SUBSIDY_TEST_FIRST_HALVING
                << ",\"isolated_first_halving_height\":" << FIRST_HALVING_HEIGHT
                << ",\"isolated_second_halving_height\":" << SECOND_HALVING_HEIGHT
#endif
                << ",\"tip\":\"" << HashToHex(branch->GetChain().TipCopy().GetHash())
                << "\",\"digest\":\"" << HashToHex(digest)
                << "\",\"network_started\":false,\"hash_work_bypassed\":true}\n";
        std::cout << "PASS miner-fee disk-backed direct/reorg/independent replay/restart checks=" << checks
                  << " height=" << height << '\n';
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        return 1;
    }
}
