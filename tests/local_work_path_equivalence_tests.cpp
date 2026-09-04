#ifndef VELD_TEST_HOOKS
#error "local-work path equivalence tests require VELD_TEST_HOOKS"
#endif
#if defined(VELD_PUBLIC_RELEASE) || defined(VELD_PUBLIC_MAINNET)
#error "local-work path equivalence tests must never compile in a public profile"
#endif

#define VELD_TEST_DATASET_BYTES (1024u * 1024u)
#include "regtest_profile.h"
#include "../include/node/node.h"

#include <cstdlib>
#include <atomic>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <future>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace veld;

namespace {

size_t checks = 0;

void Check(bool condition, const char* label) {
    ++checks;
    if (!condition)
        throw std::runtime_error(std::string("FAIL: ") + label);
}

std::string JsonEscape(const std::string& value) {
    std::string out;
    for (char c : value) {
        if (c == '\\' || c == '"')
            out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

std::string MakeRpcRequest(const std::string& method, const std::vector<std::string>& params = {}) {
    std::ostringstream out;
    out << "{\"jsonrpc\":\"2.0\",\"method\":\"" << method << "\",\"params\":[";
    for (size_t i = 0; i < params.size(); ++i) {
        if (i)
            out << ',';
        out << '"' << JsonEscape(params[i]) << '"';
    }
    out << "],\"id\":1}";
    return out.str();
}

btc_buy::JsonValue ParseResponse(const std::string& response) {
    btc_buy::JsonValue root;
    std::string error;
    btc_buy::StrictJsonParser parser(response, 4u * 1024u * 1024u, true);
    Check(parser.Parse(root, error) && root.kind == btc_buy::JsonValue::Kind::Object,
          "RPC response parses as one strict JSON object");
    return root;
}

bool RpcSucceeded(const std::string& response) {
    const auto root = ParseResponse(response);
    const auto* error = root.Get("error");
    return error && error->kind == btc_buy::JsonValue::Kind::Null;
}

struct TemplateResponse {
    Block block;
    work_admission::Binding binding;
    std::string token;
    uint64_t ttl_ms{0};
};

TemplateResponse ParseTemplate(const std::string& response) {
    const auto root = ParseResponse(response);
    const auto* error = root.Get("error");
    const auto* result = root.Get("result");
    Check(error && error->kind == btc_buy::JsonValue::Kind::Null && result &&
              result->kind == btc_buy::JsonValue::Kind::Object,
          "getblocktemplate returns an object result without error");
    const auto* block_hex = result->Get("block_hex");
    const auto* work_binding = result->Get("work_binding");
    const auto* work_token = result->Get("work_token");
    const auto* work_ttl_ms = result->Get("work_ttl_ms");
    Check(block_hex && work_binding && work_token && work_ttl_ms &&
              block_hex->kind == btc_buy::JsonValue::Kind::String &&
              work_binding->kind == btc_buy::JsonValue::Kind::String &&
              work_token->kind == btc_buy::JsonValue::Kind::String &&
              work_ttl_ms->kind == btc_buy::JsonValue::Kind::Number &&
              work_token->text.size() == 64 && !work_ttl_ms->text.empty() &&
              std::stoull(work_ttl_ms->text) > 0,
          "template publishes bytes, binding, and bounded opaque token");
    const std::vector<uint8_t> bytes = HexToBytes(block_hex->text);
    Block block;
    const size_t consumed = Block::Deserialize(bytes, 0, block);
    Check(consumed == bytes.size() && consumed > 0 && block.Serialize() == bytes,
          "template block has one canonical wire encoding");
    const auto binding = work_admission::DecodeBinding(work_binding->text);
    Check(binding.has_value() && work_admission::EncodeBinding(*binding) == work_binding->text,
          "template work binding has one canonical encoding");
    block.height = binding->subject.height;
    return TemplateResponse{std::move(block), *binding, work_token->text,
                            std::stoull(work_ttl_ms->text)};
}

std::shared_ptr<net::Connection> MakeConnection(const std::string& ip, uint16_t port) {
    const auto fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!compat::IsValidSocket(fd))
        return {};
    return std::make_shared<net::Connection>(fd, ip, port, false);
}

struct PeerPair {
    std::shared_ptr<net::Connection> first;
    std::shared_ptr<net::Connection> second;
};

void PublishPeer(VeldNode& node, const std::shared_ptr<net::Connection>& peer, uint64_t height,
                 const Hash256& tip) {
    auto& server = node.TestWorkAdmissionProcessServer();
    server.TestRecordVersionClaim(peer, height);
    server.TestMarkPeerHandshakeReady(peer);
    std::string ip = peer->RemoteAddr();
    const size_t colon = ip.find_last_of(':');
    if (colon != std::string::npos)
        ip.resize(colon);
    server.TestRecordVerifiedPeerHeight(ip, tip);
}

PeerPair InstallPeers(VeldNode& node, uint64_t height, const Hash256& tip) {
    auto& server = node.TestWorkAdmissionProcessServer();
    server.TestSetPeerHeightClock(100);
    PeerPair peers{MakeConnection("10.82.0.1", 38201), MakeConnection("10.82.0.2", 38202)};
    Check(peers.first && peers.second, "two peer sockets allocated");
    PublishPeer(node, peers.first, height, tip);
    PublishPeer(node, peers.second, height, tip);
    const auto view = server.GetPeerHeightView();
    Check(view.work_sequencer_wired && view.work_view_stable && view.distinct_version_ips == 2 &&
              view.distinct_outbound_sync_ips == 2 && view.verified_height == height &&
              view.outbound_sync_height == height && server.TestVerifiedPeerEvidenceCount() == 2,
          "two peers publish an exact canonical-tip view");
    return peers;
}

void RefreshPeers(VeldNode& node, const PeerPair& peers) {
    const Block tip = node.GetChain().TipCopy();
    PublishPeer(node, peers.first, tip.height, tip.GetHash());
    PublishPeer(node, peers.second, tip.height, tip.GetHash());
    const auto view = node.TestWorkAdmissionProcessServer().GetPeerHeightView();
    Check(view.verified_height == tip.height && view.outbound_sync_height == tip.height &&
              view.distinct_version_ips == 2,
          "peer view refreshes to the newly committed exact tip");
}

void SolveTemplate(Block& block) {
    const Hash256 target = block.header.GetTarget();
    Check(!HashIsZero(target), "template target decodes canonically");
    for (uint64_t nonce = 0; nonce < 5'000'000; ++nonce) {
        block.header.nonce = nonce;
        const Hash256 hash = mining::VeldHash(block.header.Serialize(), block.height);
        if (hash < target) {
            Check(Blockchain::VerifyBlockPoW(block),
                  "solved template passes authoritative PoW verification");
            return;
        }
    }
    throw std::runtime_error("test template did not solve within bound");
}

void WaitUntilWallClockExceedsMtp(const Blockchain& chain) {
    // The fixed-difficulty fixture can commit a block faster than the wall
    // clock advances by one second. Production mining variance naturally
    // supplies that spacing; wait boundedly here so the next GBT timestamp is
    // deterministically later than its parent's median-time-past.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    const uint64_t mtp = chain.MedianTimePast();
    while (std::chrono::steady_clock::now() < deadline) {
        const std::time_t now = std::time(nullptr);
        if (now >= 0 && static_cast<uint64_t>(now) > mtp)
            return;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    throw std::runtime_error("wall clock did not advance beyond parent MTP within 3 seconds");
}

struct ChainView {
    uint64_t height{0};
    Hash256 tip{};
    uint64_t supply{0};
    Hash256 state{};
};

ChainView Observe(const VeldNode& node) {
    return ChainView{node.GetChain().Height(), node.GetChain().TipCopy().GetHash(),
                     node.GetChain().TotalSupplyUnits(), node.ConsensusStateDigest()};
}

bool Same(const ChainView& a, const ChainView& b) {
    return a.height == b.height && a.tip == b.tip && a.supply == b.supply && a.state == b.state;
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 2)
            throw std::invalid_argument("usage: fixture <artifact-root>");
        compat::InitNetwork();
        const std::filesystem::path root(argv[1]);
        std::filesystem::create_directories(root);
        VeldNode node(MainnetConfig(), (root / "node").string());
        node.TestWireDBForDurableCommit();
        Check(node.GetChainMut()
                  .AddBlockDirect(CreateGenesisBlock(), true, true, false,
                                  mining::PowAdmissionContext::Internal())
                  .IsAccepted(),
              "trusted genesis installed");
        node.TestInstallWorkAdmissionProcessServer();
        auto peers = InstallPeers(node, 0, node.GetChain().TipCopy().GetHash());
        VeldNode::TestWorkAdmissionProcessState ready;
        node.TestConfigureWorkAdmissionProcess(ready);

        const auto subject = node.TestCurrentBlockProductionSubject();
        Check(subject.has_value(), "canonical block-production subject is available");
        std::optional<work_admission::Binding> common;
        for (const auto path :
             {work_admission::Path::InternalMining, work_admission::Path::GetBlockTemplate,
              work_admission::Path::SubmitBlock, work_admission::Path::SynchronousGeneration}) {
            const auto decision = node.TestEvaluateWorkAdmission(path, *subject);
            Check(decision.allowed && decision.binding,
                  "every block-production path passes the same open predicate");
            if (!common)
                common = decision.binding;
            else
                Check(*decision.binding == *common,
                      "all block-production paths bind the same state tuple");
        }

        const RealKeyPair miner = GenerateKeyPair(false);
        auto stale_candidate = MineOnly(node.GetChainMut(), node.GetMempoolMut(), miner);
        Check(stale_candidate.success, "stale-publication candidate is solved before view change");
        const auto stale_binding =
            node.TestEvaluateWorkAdmission(work_admission::Path::InternalMining, *subject);
        Check(stale_binding.allowed && stale_binding.binding,
              "pre-publication local binding is issued");
        const uint64_t generation_before =
            node.TestWorkAdmissionCoordinatorSnapshot().configuration_generation;
        (void)node.TestWorkAdmissionProcessServer().TestFinalizePeerConnection("stale-exact-peer",
                                                                               peers.first);
        const auto changed_view = node.TestWorkAdmissionProcessServer().GetPeerHeightView();
        Check(changed_view.distinct_version_ips == 1 &&
                  node.TestWorkAdmissionProcessServer().TestVerifiedPeerEvidenceCount() == 1 &&
                  node.TestWorkAdmissionCoordinatorSnapshot().configuration_generation >
                      generation_before,
              "exact peer disconnect publishes a new view and coordinator epoch");
        const ChainView before_stale = Observe(node);
        auto stale_context = mining::PowAdmissionContext::InternalMiningWork(
            work_admission::EncodeBinding(*stale_binding.binding));
        const auto stale_result = node.GetChainMut().AddBlockDirect(stale_candidate.block, false,
                                                                    false, false, stale_context);
        Check(stale_result.IsDeferred() && Same(before_stale, Observe(node)) &&
                  !stale_context.local_work_handoff->IsLive(),
              "binding issued before published peer change cannot prepare a ticket");

        peers.first = MakeConnection("10.82.0.3", 38203);
        Check(peers.first != nullptr, "replacement exact-tip peer allocated");
        PublishPeer(node, peers.first, 0, node.GetChain().TipCopy().GetHash());
        Check(node.TestWorkAdmissionProcessServer().GetPeerHeightView().distinct_version_ips == 2,
              "replacement peer restores the safe exact-tip view");

        Blockchain::TestResetAddBlockDirectCalls();
        const auto synchronous = node.MineBlocks(miner, 1);
        Check(synchronous.size() == 1 && synchronous[0].success && node.GetChain().Height() == 1 &&
                  Blockchain::TestAddBlockDirectCalls() == 1,
              "synchronous production uses the shared ticket and commits once");
        RefreshPeers(node, peers);
        WaitUntilWallClockExceedsMtp(node.GetChain());

        const std::string template_response =
            node.TestHandleWorkAdmissionRpc(MakeRpcRequest("getblocktemplate", {miner.address}));
        auto templ = ParseTemplate(template_response);
        Check(templ.binding.subject.target_hash == templ.block.header.GetTemplateWorkIdentity() &&
                  !HashIsZero(templ.binding.subject.target_hash) &&
                  node.TestCachedTemplateCount() == 1,
              "GBT retains one bounded authorization for the exact template identity");
        const std::string block_hex = BytesToHex(templ.block.Serialize());
        const ChainView before_refusals = Observe(node);

        Blockchain::TestResetAddBlockDirectCalls();
        Check(!RpcSucceeded(
                  node.TestHandleWorkAdmissionRpc(MakeRpcRequest("submitblock", {block_hex}))) &&
                  Blockchain::TestAddBlockDirectCalls() == 0,
              "submitblock without a work identity reaches no chain sink");
        auto missing = templ.binding;
        missing.subject.target_hash = ZeroHash();
        Check(!RpcSucceeded(node.TestHandleWorkAdmissionRpc(
                  MakeRpcRequest("submitblock", {block_hex, work_admission::EncodeBinding(missing),
                                                 templ.token}))) &&
                  Blockchain::TestAddBlockDirectCalls() == 0,
              "zero template identity reaches no chain sink");
        auto mismatched = templ.binding;
        mismatched.subject.target_hash.fill(0x5a);
        Check(!RpcSucceeded(node.TestHandleWorkAdmissionRpc(MakeRpcRequest(
                  "submitblock",
                  {block_hex, work_admission::EncodeBinding(mismatched), templ.token}))) &&
                  Blockchain::TestAddBlockDirectCalls() == 0 &&
                  Same(before_refusals, Observe(node)),
              "mismatched template identity refuses with zero state mutation");

        // Exact 18fddd5 vulnerability reproduction: modify only timestamp,
        // recompute the caller-visible target identity, solve, and pair that
        // forged binding with the genuine token for the original template.
        // The old implementation trusted these serialized caller fields and
        // committed the alternate block; the node-owned record must reject it
        // before AddBlockDirect or any durable/broadcast sink is entered.
        Block alternate = templ.block;
        ++alternate.header.timestamp;
        alternate.header.nonce = 0;
        auto forged_binding = templ.binding;
        forged_binding.subject.target_hash = alternate.header.GetTemplateWorkIdentity();
        SolveTemplate(alternate);
        std::string attacker_token(64, 'a');
        if (attacker_token == templ.token)
            attacker_token.assign(64, 'b');
        node.TestResetWorkAdmissionProcessCounters();
        Blockchain::TestResetAddBlockDirectCalls();
        const std::string random_token_refusal = node.TestHandleWorkAdmissionRpc(MakeRpcRequest(
            "submitblock", {BytesToHex(alternate.Serialize()),
                            work_admission::EncodeBinding(forged_binding), attacker_token}));
        Check(!RpcSucceeded(random_token_refusal) &&
                  random_token_refusal.find(attacker_token) == std::string::npos &&
                  Blockchain::TestAddBlockDirectCalls() == 0 &&
                  node.TestWorkDurableWriterCalls() == 0 &&
                  node.TestWorkBlockBroadcastCalls() == 0 && node.TestCachedTemplateCount() == 1 &&
                  Same(before_refusals, Observe(node)),
              "caller-forged identity and random token are rejected before every sink without "
              "token reflection");
        node.TestResetWorkAdmissionProcessCounters();
        Blockchain::TestResetAddBlockDirectCalls();
        const std::string genuine_token_mismatch = node.TestHandleWorkAdmissionRpc(MakeRpcRequest(
            "submitblock", {BytesToHex(alternate.Serialize()),
                            work_admission::EncodeBinding(forged_binding), templ.token}));
        Check(!RpcSucceeded(genuine_token_mismatch) &&
                  genuine_token_mismatch.find(templ.token) == std::string::npos &&
                  Blockchain::TestAddBlockDirectCalls() == 0 &&
                  node.TestWorkDurableWriterCalls() == 0 &&
                  node.TestWorkBlockBroadcastCalls() == 0 && node.TestCachedTemplateCount() == 1 &&
                  Same(before_refusals, Observe(node)),
              "caller-forged exact template identity is rejected before every chain sink without "
              "burning the genuine token");

        SolveTemplate(templ.block);
        Check(templ.block.header.GetTemplateWorkIdentity() == templ.binding.subject.target_hash,
              "solving changes only nonce and preserves template identity");
        Blockchain::TestResetAddBlockDirectCalls();
        const std::string accepted = node.TestHandleWorkAdmissionRpc(MakeRpcRequest(
            "submitblock", {BytesToHex(templ.block.Serialize()),
                            work_admission::EncodeBinding(templ.binding), templ.token}));
        Check(RpcSucceeded(accepted) && Blockchain::TestAddBlockDirectCalls() == 1 &&
                  node.GetChain().Height() == 2 && node.TestCachedTemplateCount() == 0,
              "exact GBT token is consumed by one successful submitblock");
        const ChainView after_submit = Observe(node);
        Blockchain::TestResetAddBlockDirectCalls();
        Check(!RpcSucceeded(node.TestHandleWorkAdmissionRpc(MakeRpcRequest(
                  "submitblock", {BytesToHex(templ.block.Serialize()),
                                  work_admission::EncodeBinding(templ.binding), templ.token}))) &&
                  Blockchain::TestAddBlockDirectCalls() == 0 && Same(after_submit, Observe(node)),
              "replayed consumed template cannot reach AddBlockDirect");

        RefreshPeers(node, peers);
        WaitUntilWallClockExceedsMtp(node.GetChain());
        auto next_template = ParseTemplate(
            node.TestHandleWorkAdmissionRpc(MakeRpcRequest("getblocktemplate", {miner.address})));
        Blockchain::TestResetAddBlockDirectCalls();
        Check(!RpcSucceeded(node.TestHandleWorkAdmissionRpc(
                  MakeRpcRequest("submitblock", {BytesToHex(next_template.block.Serialize()),
                                                 work_admission::EncodeBinding(templ.binding),
                                                 next_template.token}))) &&
                  Blockchain::TestAddBlockDirectCalls() == 0 && Same(after_submit, Observe(node)),
              "old binding cannot authorize a newly issued template");

        SolveTemplate(next_template.block);
        const std::string simultaneous_request =
            MakeRpcRequest("submitblock", {BytesToHex(next_template.block.Serialize()),
                                           work_admission::EncodeBinding(next_template.binding),
                                           next_template.token});
        node.TestResetWorkAdmissionProcessCounters();
        Blockchain::TestResetAddBlockDirectCalls();
        std::promise<void> simultaneous_start_promise;
        auto simultaneous_start = simultaneous_start_promise.get_future().share();
        std::string simultaneous_a;
        std::string simultaneous_b;
        std::exception_ptr simultaneous_failure_a;
        std::exception_ptr simultaneous_failure_b;
        std::thread submit_a([&] {
            try {
                simultaneous_start.wait();
                simultaneous_a = node.TestHandleWorkAdmissionRpc(simultaneous_request);
            } catch (...) {
                simultaneous_failure_a = std::current_exception();
            }
        });
        std::thread submit_b([&] {
            try {
                simultaneous_start.wait();
                simultaneous_b = node.TestHandleWorkAdmissionRpc(simultaneous_request);
            } catch (...) {
                simultaneous_failure_b = std::current_exception();
            }
        });
        simultaneous_start_promise.set_value();
        submit_a.join();
        submit_b.join();
        Check(!simultaneous_failure_a && !simultaneous_failure_b &&
                  (RpcSucceeded(simultaneous_a) != RpcSucceeded(simultaneous_b)) &&
                  Blockchain::TestAddBlockDirectCalls() == 1 &&
                  node.TestWorkDurableWriterCalls() == 1 &&
                  node.TestWorkBlockBroadcastCalls() == 1 && node.GetChain().Height() == 3 &&
                  node.TestCachedTemplateCount() == 0 &&
                  node.TestWorkAdmissionCoordinatorSnapshot().active_leases == 0,
              "simultaneous submitblock attempts consume one token and reach one "
              "canonical/durable/broadcast sink");
        const ChainView after_simultaneous = Observe(node);
        Blockchain::TestResetAddBlockDirectCalls();
        Check(!RpcSucceeded(node.TestHandleWorkAdmissionRpc(simultaneous_request)) &&
                  Blockchain::TestAddBlockDirectCalls() == 0 &&
                  Same(after_simultaneous, Observe(node)),
              "simultaneous winner leaves no replayable authorization");

        RefreshPeers(node, peers);

        const auto internal_subject = node.TestCurrentBlockProductionSubject();
        const auto internal_binding =
            internal_subject ? node.TestEvaluateWorkAdmission(work_admission::Path::InternalMining,
                                                              *internal_subject)
                             : work_admission::Decision{};
        auto internal = MineOnly(node.GetChainMut(), node.GetMempoolMut(), miner);
        Check(internal.success && internal_binding.allowed && internal_binding.binding,
              "internal production prepares a solved bound candidate");
        auto internal_context = mining::PowAdmissionContext::InternalMiningWork(
            work_admission::EncodeBinding(*internal_binding.binding));
        Blockchain::TestResetAddBlockDirectCalls();
        Check(node.GetChainMut()
                      .AddBlockDirect(internal.block, false, false, false, internal_context)
                      .IsAccepted() &&
                  Blockchain::TestAddBlockDirectCalls() == 1 && node.GetChain().Height() == 4,
              "internal mining uses the shared ticket and commits once");
        internal_context.local_work_handoff->Reset();

        peers.first->Close();
        peers.second->Close();
        node.Stop();
        std::cout << "PASS local_work_path_equivalence_tests checks=" << checks
                  << " paths=internal,gbt,submitblock,synchronous"
                     " stale_peer_publication=1 template_replay=1"
                     " simultaneous_submit=1 shutdown=1\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}
