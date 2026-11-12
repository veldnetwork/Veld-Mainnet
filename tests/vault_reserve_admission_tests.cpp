// Earned-funds native journey. No balances, stake records or UTXOs are injected.
// Test substitutions: isolated genesis, PoW bypass and early upgrade heights.
#define main registration_fixture_main
#include "validator_registration_admission_tests.cpp"
#undef main

namespace {
constexpr uint64_t reserve_height = 22560;
uint64_t Ratio(uint64_t value, uint64_t numerator, uint64_t denominator) {
    return value / denominator * numerator + value % denominator * numerator / denominator;
}
uint64_t Budget(uint64_t height, uint64_t balance, uint64_t inflow) {
    const auto limit = Ratio(balance, 8, 100);
    const auto old = std::min(limit, Ratio(inflow, 9, 10));
    if (height < reserve_height)
        return old;
    const uint64_t extra = balance > 20'000 * VELD_UNITS ? balance - 20'000 * VELD_UNITS : 0;
    return std::max(old, std::min(limit, extra));
}
uint64_t Inflow(VeldNode& node, uint64_t boundary) {
    uint64_t amount = 0;
    if (!boundary)
        return 0;
    const auto script = AddressToScript(VaultAddressAtHeight(boundary));
    for (uint64_t h = boundary > 480 ? boundary - 479 : 1;
         h <= std::min(boundary, node.GetChain().Height()); ++h) {
        const auto block = node.GetChain().GetBlock(h, 16 * 1024 * 1024);
        for (const auto& out : block.transactions.front().outputs)
            if (out.script_pubkey == script)
                amount += out.value;
    }
    return amount;
}
void Spend(VeldNode& node, const RealKeyPair& key, std::vector<TxOutput> outputs) {
    Transaction tx;
    uint64_t needed = MIN_TX_FEE, total = 0;
    for (const auto& output : outputs)
        needed += output.value;
    auto coins = Mature(node, key);
    std::sort(coins.begin(), coins.end(),
              [](const auto& a, const auto& b) { return a.value > b.value; });
    for (const auto& coin : coins) {
        TxInput in;
        in.prev_tx_hash = coin.tx_hash;
        in.prev_out_index = coin.output_index;
        tx.inputs.push_back(in);
        total += coin.value;
        if (total > needed)
            break;
    }
    Check(total > needed, "earned funding insufficient");
    tx.outputs = std::move(outputs);
    tx.outputs.emplace_back(total - needed, key.GetP2PKHScript());
    SignAndQueue(node, tx, key);
}
void Stake(VeldNode& node, const RealKeyPair& key) {
    const uint64_t amount = 1000 * VELD_UNITS;
    // The staking covenant binds principal to output zero; the marker follows it.
    Spend(node, key,
          {{amount, key.GetP2PKHScript()},
           {0, BuildOpReturnScript(StakingLedger::BuildLockOp(key.address, amount,
                                                              node.GetChain().Height() + 1, 1))}});
}
void View(VeldNode& node, const fs::path& path) {
    node.GetRPC().SetStaking(&node.GetStaking());
    node.GetRPC().SetValidators(&node.GetValidators());
    const auto preview = node.GetChain().GetVaultPayoutPreview();
    const auto expected = Budget(preview.next_boundary, preview.balance,
                                 Inflow(node, preview.inflow_reference_height));
    Check(preview.budget == expected, "display preview differs from independent budget");
    for (const auto& method : {"getvaultinfo", "getstakinginfo"}) {
        const auto raw = node.GetRPC().Handle(std::string("{\"id\":1,\"method\":\"") + method +
                                              "\",\"params\":[]}");
        btc_buy::JsonValue json;
        std::string error;
        Check(btc_buy::StrictJsonParser(raw).Parse(json, error), "RPC JSON invalid");
        const auto* result = json.Get("result");
        Check(result != nullptr, "RPC result missing");
        const bool vault = std::string(method) == "getvaultinfo";
        const auto* units = result->Get(vault ? "estimated_budget_units" : "distributable_units");
        uint64_t actual = 0;
        Check(units && btc_buy::ParseUint(*units, actual) && actual == expected,
              "RPC budget mismatch");
        Check(result->Get("budget_is_estimate")->boolean, "RPC promised an estimated payout");
        Check(result->Get("reserve_policy_active")->boolean == (preview.height >= reserve_height),
              "RPC activation mismatch");
        Check(result->Get("next_distribution_reserve_policy")->boolean ==
                  (preview.next_boundary >= reserve_height),
              "RPC next-boundary activation mismatch");
        if (!vault) {
            const auto* stakers = result->Get("stakers");
            Check(stakers && stakers->array.size() == 2, "RPC staker list mismatch");
            for (const auto& row : stakers->array)
                Check(row.Get("payout_units") &&
                          row.Get("payout_units")->text == std::to_string(expected / 2),
                      "RPC recipient rounding differs from consensus");
        }
        std::ofstream(path.string() + "-" + method + ".json") << raw;
    }
    explorer::BlockExplorer page(node.GetChainMut(), node.GetMempoolMut());
    const auto rendered =
        page.Route(explorer::HttpRequest::Parse("GET /vault HTTP/1.1\r\nHost: localhost\r\n\r\n"));
    Check(rendered.status_code == 200 &&
              rendered.body.find("Estimated payout budget") != std::string::npos,
          "vault page missing budget");
    Check((rendered.body.find("uses the 20,000 VELD reserve target") != std::string::npos) ==
              (preview.next_boundary >= reserve_height),
          "vault page policy differs from next settlement");
    Check((rendered.body.find("Paid entirely to miners") != std::string::npos) ==
              (preview.height + 1 >= reserve_height),
          "vault page fee policy mismatch");
    Check(rendered.body.find("vault growth (10%)") == std::string::npos,
          "vault page fabricated guaranteed growth");
    std::ofstream(path.string() + "-vault.html") << rendered.body;
}
size_t Flush(VeldNode& node, const Block& block) {
    const auto script = AddressToScript(VaultAddressAtHeight(block.height));
    for (size_t i = 1; i < block.transactions.size(); ++i) {
        for (const auto& input : block.transactions[i].inputs) {
            const auto coin = node.GetChain().GetUTXO(input.prev_tx_hash, input.prev_out_index);
            if (coin && coin->script_pubkey == script)
                return i;
        }
    }
    throw std::runtime_error("canonical vault settlement missing");
}
void Boundary(VeldNode& node, const Block& block, const RealKeyPair& first,
              const RealKeyPair& second) {
    const auto& tx = block.transactions.at(Flush(node, block));
    const auto vault = AddressToScript(VaultAddressAtHeight(block.height));
    const auto balance = node.GetChain().GetBalance(vault);
    const auto budget = Budget(block.height, balance, Inflow(node, block.height));
    uint64_t inputs = 0, outputs = 0, a = 0, b = 0, change = 0;
    for (const auto& input : tx.inputs) {
        auto coin = node.GetChain().GetUTXO(input.prev_tx_hash, input.prev_out_index);
        Check(coin && coin->script_pubkey == vault, "settlement spends non-vault funds");
        inputs += coin->value;
    }
    for (const auto& out : tx.outputs) {
        outputs += out.value;
        if (out.script_pubkey == first.GetP2PKHScript())
            a += out.value;
        else if (out.script_pubkey == second.GetP2PKHScript())
            b += out.value;
        else {
            Check(out.script_pubkey == vault, "unexpected payout recipient");
            change += out.value;
        }
    }
    Check(inputs == balance && outputs == inputs, "settlement does not conserve vault funds");
    Check(a == budget / 2 && b == budget / 2 && change == balance - a - b,
          "actual payouts differ from independent allocation");
    Check(node.GetChain().GetBalance(AddressToScript(STAKE_VAULT_ADDRESS)) == 0,
          "ordinary staking entered bond custody");
    if (block.height == reserve_height)
        Check(budget > Ratio(Inflow(node, block.height), 9, 10),
              "reserve test did not increase payout");
}
void RejectPayout(VeldNode& node, const Block& canonical, bool extra) {
    auto bad = canonical;
    auto& tx = bad.transactions.at(Flush(node, bad));
    auto change = std::find_if(tx.outputs.begin(), tx.outputs.end(), [&](const auto& out) {
        return out.script_pubkey == AddressToScript(VaultAddressAtHeight(bad.height));
    });
    Check(change != tx.outputs.end(), "negative payout fixture missing change");
    auto recipient = std::find_if(tx.outputs.begin(), tx.outputs.end(), [&](const auto& out) {
        return out.script_pubkey != change->script_pubkey;
    });
    Check(change != tx.outputs.end() && recipient != tx.outputs.end() && recipient->value > 1,
          "negative payout fixture missing outputs");
    if (extra) {
        ++recipient->value;
        --change->value;
    } else {
        --recipient->value;
        ++change->value;
    }
    tx.InvalidateTxIDCache();
    bad.UpdateMerkleRoot();
    const auto before = node.TestObserveDStateQualificationState();
    Check(!node.TestIngestDStateQualificationFrame(bad.Serialize(), bad.height),
          "incorrect payout admitted");
    const auto after = node.TestObserveDStateQualificationState();
    Check(before.utxo_digest == after.utxo_digest &&
              before.consensus_state_digest == after.consensus_state_digest &&
              before.durable_tip_hash == after.durable_tip_hash,
          "rejected payout changed state");
}
}
int main(int argc, char** argv) {
    try {
        static_assert(VAULT_RESERVE_ACTIVATION_HEIGHT == reserve_height &&
                      MINER_FEE_ACTIVATION_HEIGHT == reserve_height);
        Check(argc == 2, "fresh fixture directory required");
        const auto root = fs::absolute(argv[1]);
        Check(!fs::exists(root), "preserve prior fixture");
        fs::create_directories(root);
        const auto owner = GenerateKeyPair(false), second = GenerateKeyPair(false),
                   miner = GenerateKeyPair(false);
        auto direct = Fresh(root / "direct");
        std::vector<Block> history;
        for (uint64_t h = 1; h < reserve_height; ++h) {
            if (h < 22000 && h % 128 == 0)
                Consolidate(*direct, owner);
            if (h == 22000)
                Spend(*direct, owner, {{2000 * VELD_UNITS, second.GetP2PKHScript()}});
            if (h == 22001)
                Stake(*direct, owner);
            if (h == 22002)
                Stake(*direct, second);
            const auto block = Build(*direct, h < 22000 ? owner : miner, h);
            if (h == 22080) {
                View(*direct, root / "before-legacy");
                Boundary(*direct, block, owner, second);
            }
            Admit(*direct, block);
            history.push_back(block);
            if (h % 480 == 0)
                std::cout << "PROGRESS earned-funds height=" << h << std::endl;
        }
        Check(direct->GetStaking().GetTotalStake() == 2000 * VELD_UNITS,
              "signed stake markers not applied");
        View(*direct, root / "before-activation");
        auto branch = Fresh(root / "branch");
        for (const auto& block : history) {
            Admit(*branch, block);
            if (block.height % 4800 == 0)
                std::cout << "PROGRESS branch-replay height=" << block.height << std::endl;
        }
        Equal(*direct, *branch);
        const auto original = Build(*direct, miner, 100000 + reserve_height);
        Boundary(*direct, original, owner, second);
        RejectPayout(*direct, original, true);
        RejectPayout(*direct, original, false);
        Admit(*direct, original);
        uint64_t disconnected = 0;
        for (uint64_t h = reserve_height; h <= 24482; ++h) {
            if (h == reserve_height)
                Fee(*branch, miner, MIN_TX_FEE + 19);
            auto block = Build(*branch, miner, 200000 + h);
            if (h % 480 == 0) {
                Boundary(*branch, block, owner, second);
                View(*branch, root / ("boundary-" + std::to_string(h)));
                std::cout << "PROGRESS checked-payout height=" << h << std::endl;
            }
            Admit(*branch, block);
            history.push_back(block);
            Admit(*direct, block);
            disconnected += direct->GetChain().LastReorgDisconnectCount();
        }
        Check(disconnected > 0, "reserve settlement reorganization was not exercised");
        Equal(*direct, *branch);
        View(*branch, root / "final");
        auto replay = Fresh(root / "replay");
        for (const auto& block : history) {
            Admit(*replay, block);
            if (block.height % 4800 == 0)
                std::cout << "PROGRESS independent-replay height=" << block.height << std::endl;
        }
        Equal(*replay, *branch);
        branch.reset();
        branch = Reopen(root / "branch", history.back().height);
        Equal(*direct, *branch);
        Equal(*replay, *branch);
        View(*branch, root / "after-restart");
        std::ofstream(root / "result.json")
            << "{\"status\":\"passed\",\"checks\":" << checks
            << ",\"height\":" << history.back().height << ",\"activation\":" << reserve_height
            << ",\"tip\":\"" << HashToHex(branch->GetChain().TipCopy().GetHash())
            << "\",\"digest\":\"" << HashToHex(branch->ConsensusStateDigest())
            << "\",\"injected_funds\":false,\"network_started\":false,\"hash_work_bypassed\":true}\n";
        std::cout << "PASS vault funded admission/reorganization/replay/restart/RPC checks="
                  << checks << '\n';
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        return 1;
    }
}
