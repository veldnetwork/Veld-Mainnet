#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_TEST_BRANCH_CONTEXT 1
#define VELD_TEST_NMS_BRANCH_CONTEXT 1

#include "../include/node/node.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

int checks = 0;
int failures = 0;

void Check(bool condition, const char* label) {
    ++checks;
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << label << "\n";
    }
}

std::vector<uint8_t> MinerScript(uint8_t tag) {
    std::vector<uint8_t> out{0x76, 0xa9, 0x14};
    for (uint8_t i = 0; i < 20; ++i)
        out.push_back(static_cast<uint8_t>(tag + i));
    out.push_back(0x88);
    out.push_back(0xac);
    return out;
}

std::shared_ptr<veld::net::Connection> MakeConnection(
        const std::string& address, uint16_t port) {
    const auto fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!veld::compat::IsValidSocket(fd)) return {};
    return std::make_shared<veld::net::Connection>(
        fd, address, port, true);
}

veld::UTXO InstallNmsInput(veld::Blockchain& chain,
                           const veld::RealKeyPair& signer,
                           uint8_t tag) {
    veld::UTXO input;
    input.tx_hash.fill(tag);
    input.output_index = 0;
    input.value = 20 * veld::MIN_TX_FEE;
    input.script_pubkey = signer.GetP2PKHScript();
    input.block_height = chain.Height();
    input.is_coinbase = false;
    chain.TestInjectUTXO(input);
    return input;
}

veld::Transaction BuildNmsTransaction(
        veld::Blockchain& chain,
        const veld::RealKeyPair& signer,
        const veld::UTXO& parent,
        uint64_t nonce,
        std::optional<uint32_t> bits_override = std::nullopt) {
    using namespace veld;
    BlockHeader claimed;
    claimed.version = PROTOCOL_VERSION;
    claimed.prev_block_hash = chain.TipCopy().GetHash();
    claimed.merkle_root.fill(static_cast<uint8_t>(nonce));
    claimed.timestamp = chain.TipCopy().header.timestamp + 1;
    claimed.bits = bits_override.value_or(chain.ComputeNextBits());
    claimed.nonce = nonce;

    Transaction tx;
    TxInput in;
    in.prev_tx_hash = parent.tx_hash;
    in.prev_out_index = parent.output_index;
    tx.inputs.push_back(in);

    const auto miner_script = signer.GetP2PKHScript();
    tx.outputs.emplace_back(MIN_TX_FEE, miner_script);
    tx.outputs.emplace_back(
        0, BuildNmsOpReturnScript(EncodeNmsPayload(claimed)));
    tx.outputs.emplace_back(
        parent.value - (2 * MIN_TX_FEE), miner_script);
    tx.inputs[0].script_sig =
        signer.SignInput(tx, 0, parent.script_pubkey).script_sig;
    return tx;
}

void AttachNmsTransaction(veld::Block& block,
                          const veld::Transaction& tx) {
    const auto vault_script = veld::AddressToScript(
        veld::VaultAddressAtHeight(block.height));
    bool fee_attached = false;
    for (auto& output : block.transactions.front().outputs) {
        if (output.script_pubkey != vault_script) continue;
        output.value += veld::MIN_TX_FEE;
        fee_attached = true;
        break;
    }
    if (!fee_attached)
        throw std::runtime_error("NMS fixture lacks vault coinbase leg");
    block.transactions.front().InvalidateTxIDCache();
    block.transactions.push_back(tx);
    block.UpdateMerkleRoot();
}

void Init(veld::Blockchain& chain) {
    auto genesis = veld::CreateGenesisBlock();
    const auto result = chain.AddBlockDirect(
        genesis, true, false, false,
        veld::mining::PowAdmissionContext::Internal());
    if (!result.IsAccepted())
        throw std::runtime_error("test genesis rejected");
}

veld::Block BuildCandidate(veld::Blockchain& chain,
                           const std::vector<uint8_t>& miner_script,
                           uint64_t timestamp) {
    using namespace veld;
    Block block;
    block.height = chain.Height() + 1;
    block.header.version = PROTOCOL_VERSION;
    block.header.prev_block_hash = chain.TipCopy().GetHash();
    block.header.timestamp = timestamp;
    block.header.bits = chain.ComputeNextBits();
    block.header.nonce = block.height * 17 + timestamp;

    const uint64_t subsidy = Blockchain::ExpectedBlockSubsidy(block.height);
    const uint64_t supply = chain.TotalSupplyUnits();
    const uint64_t remaining = MAX_SUPPLY_UNITS > supply
        ? MAX_SUPPLY_UNITS - supply : 0;
    const uint64_t effective = std::min(subsidy, remaining);
    const auto vault_script = AddressToScript(
        VaultAddressAtHeight(block.height));
    std::vector<std::pair<std::vector<uint8_t>, uint64_t>> outputs;
    if (block.height > 0 && block.height % VAULT_BLOCK_INTERVAL == 0) {
        outputs.push_back({vault_script, effective});
    } else if (supply < STAKING_UNLOCK_SUPPLY) {
        const uint64_t miner_cut = (effective * 50) / 100;
        const uint64_t vault_cut = effective - miner_cut;
        outputs.push_back({miner_script, miner_cut});
        if (vault_script == miner_script)
            outputs.front().second += vault_cut;
        else
            outputs.push_back({vault_script, vault_cut});
    } else {
        const uint64_t pool_cut = (effective * 20) / 100;
        const uint64_t vault_cut = (effective * 20) / 100;
        const uint64_t endorse_cut = (effective * 10) / 100;
        const uint64_t miner_cut =
            effective - pool_cut - vault_cut - endorse_cut;
        outputs.push_back({miner_script, miner_cut});
        outputs.push_back({
            AddressToScript(PoolAddressAtHeight(block.height)), pool_cut});
        outputs.push_back({vault_script, vault_cut});
        outputs.push_back({AddressToScript(
            EndorsementPoolAddressAtHeight(block.height)), endorse_cut});
    }
    block.transactions.push_back(Transaction::CreateProportionalCoinbase(
        outputs, "Veld block " + std::to_string(block.height)));
    block.UpdateMerkleRoot();
    return block;
}

veld::Block Append(veld::Blockchain& chain,
                   const std::vector<uint8_t>& miner_script,
                   uint64_t timestamp) {
    auto block = BuildCandidate(chain, miner_script, timestamp);
    const auto result = chain.AddBlockDirect(
        block, false, false, false,
        veld::mining::PowAdmissionContext::Internal());
    if (!result.IsAccepted()) {
        throw std::runtime_error(
            "candidate rejected: " + veld::Blockchain::GetLastRejectTag());
    }
    return block;
}

void Replay(veld::Blockchain& chain, const veld::Block& source) {
    auto block = source;
    const auto result = chain.AddBlockDirect(
        block, false, false, false,
        veld::mining::PowAdmissionContext::Internal());
    if (!result.IsAccepted()) {
        throw std::runtime_error(
            "replay rejected: " + veld::Blockchain::GetLastRejectTag());
    }
}

}  // namespace

int main() {
    using namespace veld;
    using namespace veld::mining;

    Blockchain prefix_builder;
    Blockchain main_builder;
    Blockchain side_builder;
    Blockchain recipient;
    Init(prefix_builder);
    Init(main_builder);
    Init(side_builder);
    Init(recipient);

    const auto prefix_script = MinerScript(0x10);
    const auto main_script = MinerScript(0x40);
    const auto side_script = MinerScript(0x80);
    uint64_t timestamp = prefix_builder.TipCopy().header.timestamp;
    std::vector<Block> prefix;
    for (uint64_t height = 1; height <= BOOTSTRAP_BLOCKS; ++height) {
        timestamp += 60;
        prefix.push_back(Append(prefix_builder, prefix_script, timestamp));
    }
    for (const auto& block : prefix) {
        Replay(main_builder, block);
        Replay(side_builder, block);
        Replay(recipient, block);
    }

    std::vector<Block> main_suffix;
    std::vector<Block> side_suffix;
    uint64_t main_time = timestamp;
    uint64_t side_time = timestamp;
    for (uint64_t height = BOOTSTRAP_BLOCKS + 1; height <= 37; ++height) {
        main_time += 15;
        side_time += 600;
        main_suffix.push_back(Append(main_builder, main_script, main_time));
        side_suffix.push_back(Append(side_builder, side_script, side_time));
    }
    for (const auto& block : main_suffix) Replay(recipient, block);

    Check(main_suffix[5].height == EARLY_RETARGET_INTERVAL &&
              side_suffix[5].height == EARLY_RETARGET_INTERVAL,
          "fixtures reach the first real early-LWMA boundary");
    Check(main_suffix[5].header.bits != side_suffix[5].header.bits,
          "fast and slow branches derive different canonical LWMA bits");

    size_t durable_writes = 0;
    size_t peer_credits = 0;
    size_t relays = 0;
    size_t on_block = 0;
    std::unordered_map<std::string, std::vector<uint8_t>> durable;
    recipient.SetDurableBlockBodyWriter(
        [&](const Hash256& hash, const std::vector<uint8_t>& raw) {
            ++durable_writes;
            durable[HashToHex(hash)] = raw;
            return true;
        });
    recipient.SetHistoricalBlockLoader([&](const Hash256& hash)
            -> std::optional<std::vector<uint8_t>> {
        auto it = durable.find(HashToHex(hash));
        if (it == durable.end()) return std::nullopt;
        return it->second;
    });
    auto observe = [&](const Blockchain::BlockAdmissionResult& result) {
        if (!result.IsAccepted()) return;
        ++peer_credits;
        ++relays;
        ++on_block;
    };

    for (size_t i = 0; i < 5; ++i) {
        auto block = side_suffix[i];
        const auto result = recipient.AddBlockDirect(
            block, false, true, false,
            PowAdmissionContext::Internal());
        observe(result);
        Check(result.IsAccepted(),
              "correct lower-work side prefix is contextually accepted");
    }
    Check(durable_writes == 5 && peer_credits == 5 && relays == 5 &&
              on_block == 5 && recipient.VolatileSideQuarantineCount() == 0,
          "validated side prefix is promoted exactly once before peer effects");

    Block invalid_state = side_suffix[5];
    auto& invalid_outputs = invalid_state.transactions.front().outputs;
    if (invalid_outputs.size() < 2 || invalid_outputs[1].value == 0)
        throw std::runtime_error("unexpected coinbase fixture shape");
    ++invalid_outputs[0].value;
    --invalid_outputs[1].value;
    invalid_state.transactions.front().InvalidateTxIDCache();
    invalid_state.UpdateMerkleRoot();
    Blockchain::TestResetVerifyBlockPowCalls();
    const size_t effects_before_invalid =
        durable_writes + peer_credits + relays + on_block;
    const auto invalid_result = recipient.AddBlockDirect(
        invalid_state, false, true, false,
        PowAdmissionContext::Internal());
    observe(invalid_result);
    Check(!invalid_result.IsAccepted() && !invalid_result.IsDeferred(),
          "branch-state-invalid lower-work side block is consensus rejected");
    Check(Blockchain::TestVerifyBlockPowCalls() >= 2,
          "invalid side fixture reaches full ingress plus VBFR validation");
    Check(durable_writes + peer_credits + relays + on_block ==
              effects_before_invalid &&
              recipient.VolatileSideQuarantineCount() == 0,
          "VBFR-invalid side block reaches no writer credit relay or on-block effect");

    Block wrong_bits = side_suffix[5];
    wrong_bits.header.bits = main_suffix[5].header.bits;
    ++wrong_bits.header.nonce;
    Blockchain::TestResetVerifyBlockPowCalls();
    const size_t effects_before_wrong =
        durable_writes + peer_credits + relays + on_block;
    const auto wrong_result = recipient.AddBlockDirect(
        wrong_bits, false, true, false,
        PowAdmissionContext::Internal());
    observe(wrong_result);
    Check(!wrong_result.IsAccepted() && !wrong_result.IsDeferred() &&
              Blockchain::GetLastRejectTag() == "bits_mismatch_lwma",
          "main-branch bits are rejected on a varying-LWMA side parent");
    Check(Blockchain::TestVerifyBlockPowCalls() == 0,
          "wrong branch-local bits are rejected before VeldHash");
    Check(durable_writes + peer_credits + relays + on_block ==
              effects_before_wrong,
          "wrong-bit side block reaches no durable or peer effect");

    auto correct_boundary = side_suffix[5];
    const auto correct_result = recipient.AddBlockDirect(
        correct_boundary, false, true, false,
        PowAdmissionContext::Internal());
    observe(correct_result);
    Check(correct_result.IsAccepted(),
          "correct varying-LWMA side bits pass full contextual validation");
    Check(durable_writes == 6 && peer_credits == 6 && relays == 6 &&
              on_block == 6 && recipient.VolatileSideQuarantineCount() == 0,
          "correct boundary side block is promoted before one peer effect");

    const size_t effects_before_known =
        durable_writes + peer_credits + relays + on_block;
    const auto known_result = recipient.AddBlockDirect(
        correct_boundary, false, true, false,
        PowAdmissionContext::Internal());
    observe(known_result);
    Check(!known_result.IsAccepted() && !known_result.IsDeferred() &&
              Blockchain::GetLastRejectTag() == "duplicate_block",
          "known promoted side retransmit is not accepted again");
    Check(durable_writes + peer_credits + relays + on_block ==
              effects_before_known,
          "known promoted retransmit repeats no writer or peer effect");

    Block next_main = BuildCandidate(
        recipient, main_script,
        recipient.TipCopy().header.timestamp + 15);
    Hash256 wrong_checkpoint = next_main.GetHash();
    wrong_checkpoint[0] ^= 0x80;
    recipient.SetCheckpointAtOrBelow(
        [&](uint64_t max_height, uint64_t& out_height,
            Hash256& out_hash) {
            out_height = max_height;
            out_hash = wrong_checkpoint;
            return true;
        });
    Blockchain::TestResetVerifyBlockPowCalls();
    const auto checkpoint_result = recipient.AddBlockDirect(
        next_main, false, true, false,
        PowAdmissionContext::Internal());
    Check(!checkpoint_result.IsAccepted() &&
              Blockchain::GetLastRejectTag() == "checkpoint_violation" &&
              Blockchain::TestVerifyBlockPowCalls() == 0,
          "checkpoint ancestry conflict rejects before VeldHash");
    recipient.SetCheckpointAtOrBelow({});

    recipient.anchor_gate_ = [](uint64_t, const Hash256&) { return false; };
    Blockchain::TestResetVerifyBlockPowCalls();
    const auto anchor_result = recipient.AddBlockDirect(
        next_main, false, true, false,
        PowAdmissionContext::Internal());
    Check(!anchor_result.IsAccepted() &&
              Blockchain::GetLastRejectTag() == "anchor_conflict" &&
              Blockchain::TestVerifyBlockPowCalls() == 0,
          "anchor conflict rejects before VeldHash");
    recipient.anchor_gate_ = {};

    Blockchain::TestResetVerifyBlockPowCalls();
    const auto unwired_result = recipient.AddBlockDirect(
        next_main, false, true, false);
    Check(!unwired_result.IsAccepted() && !unwired_result.IsDeferred() &&
              Blockchain::GetLastRejectTag() ==
                  "pow_admission_context_unavailable" &&
              Blockchain::TestVerifyBlockPowCalls() == 0,
          "unwired default admission context fails closed before work");

    // A peer block with a valid canonical header/body envelope but an invalid
    // input signature reaches the active V2 parent-state gate.  It must never
    // cross the durable writer or any public block/index view first.
    UTXO forged_parent;
    forged_parent.tx_hash.fill(0xA5);
    forged_parent.output_index = 0;
    forged_parent.value = 2 * DUST_THRESHOLD_UNITS;
    forged_parent.script_pubkey = MinerScript(0xA0);
    forged_parent.block_height = recipient.Height();
    forged_parent.is_coinbase = false;
    recipient.TestInjectUTXO(forged_parent);

    Transaction forged_spend;
    TxInput forged_input;
    forged_input.prev_tx_hash = forged_parent.tx_hash;
    forged_input.prev_out_index = forged_parent.output_index;
    forged_input.script_sig = {0x00};
    forged_spend.inputs.push_back(forged_input);
    forged_spend.outputs.emplace_back(
        forged_parent.value, MinerScript(0xB0));

    Block bad_signature = BuildCandidate(
        recipient, main_script,
        recipient.TipCopy().header.timestamp + 15);
    bad_signature.transactions.push_back(forged_spend);
    bad_signature.UpdateMerkleRoot();
    const Hash256 bad_signature_hash = bad_signature.GetHash();
    const std::string bad_signature_hex =
        HashToHex(bad_signature_hash);
    const size_t writes_before_bad_signature = durable_writes;
    auto bad_signature_budget = std::make_shared<ExpensivePowBudget>(
        1, 8, std::chrono::minutes(1));
    const auto bad_signature_context = PowAdmissionContext::Peer(
        "198.51.100.44", bad_signature_budget);
    const auto bad_signature_result = recipient.AddBlockDirect(
        bad_signature, false, true, false, bad_signature_context);
    Check(!bad_signature_result.IsAccepted() &&
              !bad_signature_result.IsDeferred() &&
              Blockchain::GetLastRejectTag() ==
                  "consensus_tx_sig_or_value_invalid_v2",
          "bad peer signature is rejected at the active V2 contextual gate");

    bool bad_signature_tip_exposed = false;
    for (const auto& tip : recipient.GetChainTips()) {
        if (tip.hash == bad_signature_hash) bad_signature_tip_exposed = true;
    }
    Check(durable_writes == writes_before_bad_signature &&
              !recipient.GetBlockByHash(bad_signature_hash).has_value() &&
              !recipient.GetKnownBlockHeightByHash(
                  bad_signature_hash).has_value() &&
              !recipient.HasBlockAtHeight(
                  bad_signature.height, bad_signature_hex) &&
              !bad_signature_tip_exposed,
          "late-invalid canonical candidate has no durable or public residue");

    const auto bad_signature_retry = recipient.AddBlockDirect(
        bad_signature, false, true, false, bad_signature_context);
    Check(!bad_signature_retry.IsAccepted() &&
              !bad_signature_retry.IsDeferred() &&
              Blockchain::GetLastRejectTag() ==
                  "consensus_tx_sig_or_value_invalid_v2" &&
              durable_writes == writes_before_bad_signature,
          "late-invalid retransmit is revalidated and never cached as a duplicate");

    Block valid_after_reject = BuildCandidate(
        recipient, main_script,
        recipient.TipCopy().header.timestamp + 15);
    const auto valid_after_reject_result = recipient.AddBlockDirect(
        valid_after_reject, false, true, false, bad_signature_context);
    Check(valid_after_reject_result.IsAccepted() &&
              durable_writes == writes_before_bad_signature + 1 &&
              recipient.GetBlockByHash(
                  valid_after_reject.GetHash()).has_value() &&
              recipient.GetKnownBlockHeightByHash(
                  valid_after_reject.GetHash()).has_value(),
          "valid canonical extension persists once and becomes publicly visible");

    // The ordinary main-extension path must preserve NMS local-work deferral.
    // Pre-consuming one of two starts lets header PoW pass and makes only the
    // subsequent NMS verification hit the source rate cap.
    Blockchain nms_block_chain;
    Init(nms_block_chain);
    const auto nms_signer = GenerateKeyPair(false);
    const auto nms_parent = InstallNmsInput(
        nms_block_chain, nms_signer, 0xC1);
    const auto nms_tx = BuildNmsTransaction(
        nms_block_chain, nms_signer, nms_parent, 0xC101);
    Block nms_candidate = BuildCandidate(
        nms_block_chain, nms_signer.GetP2PKHScript(),
        nms_block_chain.TipCopy().header.timestamp + 1);
    AttachNmsTransaction(nms_candidate, nms_tx);
    size_t nms_block_writes = 0;
    nms_block_chain.SetDurableBlockBodyWriter(
        [&](const Hash256&, const std::vector<uint8_t>&) {
            ++nms_block_writes;
            return true;
        });
    auto nms_block_budget = std::make_shared<ExpensivePowBudget>(
        1, 2, std::chrono::milliseconds(100));
    auto preconsume_nms_start = nms_block_budget->TryAcquire(
        ExpensivePowUse::PeerNms);
    preconsume_nms_start.reset();
    const auto nms_block_context = PowAdmissionContext::Peer(
        "198.51.100.61", nms_block_budget);
    const auto nms_block_deferred = nms_block_chain.AddBlockDirect(
        nms_candidate, false, true, false, nms_block_context);
    Check(nms_block_deferred.IsDeferred() &&
              Blockchain::GetLastRejectTag() ==
                  "nms_local_work_deferred" &&
              nms_block_writes == 0 && nms_block_chain.Height() == 0,
          "canonical NMS extension defers without persistence or tip change");
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    const auto nms_block_retry = nms_block_chain.AddBlockDirect(
        nms_candidate, false, true, false, nms_block_context);
    Check(nms_block_retry.IsAccepted() && nms_block_writes == 1 &&
              nms_block_chain.Height() == 1,
          "same-origin canonical NMS extension succeeds after bounded refill");

    // Exercise the production Mempool::Add taxonomy directly. A transient
    // refusal is retryable and uncached; a compact alias remains invalid.
    Blockchain nms_pool_chain;
    Init(nms_pool_chain);
    Mempool nms_pool;
    const auto pool_signer = GenerateKeyPair(false);
    const auto pool_parent = InstallNmsInput(
        nms_pool_chain, pool_signer, 0xC2);
    const auto pool_tx = BuildNmsTransaction(
        nms_pool_chain, pool_signer, pool_parent, 0xC201);
    ExpensivePowBudget blocked_pool_budget(1);
    auto held_pool_lease = blocked_pool_budget.TryAcquire(
        ExpensivePowUse::PeerNms);
    Check(nms_pool.Add(
              pool_tx, MIN_TX_FEE,
              static_cast<uint32_t>(nms_pool_chain.Height()),
              nms_pool_chain, &blocked_pool_budget) ==
              Mempool::AddResult::DEFERRED_LOCAL_WORK &&
              !nms_pool.Contains(pool_tx.GetTxID()),
          "mempool exposes NMS local-work deferral without insertion");
    held_pool_lease.reset();
    Check(nms_pool.Add(
              pool_tx, MIN_TX_FEE,
              static_cast<uint32_t>(nms_pool_chain.Height()),
              nms_pool_chain, &blocked_pool_budget) ==
              Mempool::AddResult::ACCEPTED &&
              nms_pool.Contains(pool_tx.GetTxID()),
          "mempool exact retry succeeds after local capacity returns");
    const auto invalid_parent = InstallNmsInput(
        nms_pool_chain, pool_signer, 0xC3);
    const auto invalid_nms_tx = BuildNmsTransaction(
        nms_pool_chain, pool_signer, invalid_parent, 0xC301,
        0x20ffffffu);
    Check(nms_pool.Add(
              invalid_nms_tx, MIN_TX_FEE,
              static_cast<uint32_t>(nms_pool_chain.Height()),
              nms_pool_chain, &blocked_pool_budget) ==
              Mempool::AddResult::INVALID &&
              net::NodeServer::MempoolRejectBanScore(
                  Mempool::AddResult::INVALID) == 10,
          "consensus-invalid NMS remains punishable");

    // Drive the same deferred result through the real P2P TX handler. The
    // source-keyed budget object survives the first attempt; no peer score is
    // charged, and the exact retransmit is admitted after the lease releases.
    compat::InitNetwork();
    Blockchain p2p_chain;
    Init(p2p_chain);
    Mempool p2p_pool;
    net::NodeServer p2p_server(0, MAINNET_MAGIC, p2p_chain, p2p_pool);
    const auto p2p_signer = GenerateKeyPair(false);
    const auto p2p_parent = InstallNmsInput(
        p2p_chain, p2p_signer, 0xC4);
    const auto p2p_tx = BuildNmsTransaction(
        p2p_chain, p2p_signer, p2p_parent, 0xC401);
    const std::string p2p_source = "198.51.100.62";
    auto p2p_conn = MakeConnection(p2p_source, 32062);
    Check(p2p_conn != nullptr, "P2P NMS fixture connection created");
    if (p2p_conn) {
        auto source_budget = p2p_server.TestPowBudgetForSource(p2p_source);
        auto held_p2p_lease = source_budget->TryAcquire(
            ExpensivePowUse::PeerNms);
        const P2PMessage p2p_message(
            MAINNET_MAGIC, MessageType::TX, p2p_tx.Serialize());
        p2p_server.TestDispatchPeerMessage(*p2p_conn, p2p_message);
        Check(!p2p_pool.Contains(p2p_tx.GetTxID()) &&
                  p2p_server.TestViolationScore(p2p_source) == 0 &&
                  !p2p_server.IsBanned(p2p_source) &&
                  net::NodeServer::MempoolRejectBanScore(
                      Mempool::AddResult::DEFERRED_LOCAL_WORK) == 0,
              "P2P NMS deferral has no insertion ban score or ban");
        held_p2p_lease.reset();
        p2p_server.TestDispatchPeerMessage(*p2p_conn, p2p_message);
        Check(p2p_pool.Contains(p2p_tx.GetTxID()) &&
                  source_budget ==
                      p2p_server.TestPowBudgetForSource(p2p_source),
              "P2P exact retry preserves source budget and is admitted");

        const auto p2p_invalid_parent = InstallNmsInput(
            p2p_chain, p2p_signer, 0xC5);
        const auto p2p_invalid_tx = BuildNmsTransaction(
            p2p_chain, p2p_signer, p2p_invalid_parent, 0xC501,
            0x20ffffffu);
        const P2PMessage p2p_invalid_message(
            MAINNET_MAGIC, MessageType::TX,
            p2p_invalid_tx.Serialize());
        p2p_server.TestDispatchPeerMessage(
            *p2p_conn, p2p_invalid_message);
        Check(!p2p_pool.Contains(p2p_invalid_tx.GetTxID()) &&
                  p2p_server.TestViolationScore(p2p_source) == 10 &&
                  !p2p_server.IsBanned(p2p_source),
              "P2P consensus-invalid NMS remains scored and unrelayed");
    }

    if (failures == 0) {
        std::cout << "PASS checks=" << checks << "\n";
        return 0;
    }
    std::cerr << "FAIL checks=" << checks
              << " failures=" << failures << "\n";
    return 1;
}
