#ifndef VELD_TEST_HOOKS
#error "BLOCK-COMMIT-DEADLOCK-01 process fixture requires VELD_TEST_HOOKS"
#endif
#if defined(VELD_PUBLIC_RELEASE) || defined(VELD_PUBLIC_MAINNET)
#error "BLOCK-COMMIT-DEADLOCK-01 fixture must never compile in a public profile"
#endif

#define VELD_TEST_DATASET_BYTES (1024u * 1024u)
#include "regtest_profile.h"
#include "node/node.h"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

using namespace veld;

namespace {

size_t checks = 0;

void Check(bool condition, const char* label) {
    ++checks;
    if (!condition)
        throw std::runtime_error(std::string("FAIL: ") + label);
}

std::shared_ptr<net::Connection> MakeConnection(const std::string& ip, uint16_t port) {
    const auto fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!compat::IsValidSocket(fd))
        return {};
    return std::make_shared<net::Connection>(fd, ip, port, false);
}

struct ExactTipPeers {
    std::shared_ptr<net::Connection> first;
    std::shared_ptr<net::Connection> second;
};

void InstallGenesis(VeldNode& node) {
    node.TestWireDBForDurableCommit();
    const Block genesis = CreateGenesisBlock();
    const auto result = node.GetChainMut().AddBlockDirect(genesis, true, true, false,
                                                          mining::PowAdmissionContext::Internal());
    Check(result.IsAccepted(), "trusted fixture genesis installed");
    Check(node.GetChain().Height() == 0, "fresh production-profile node begins at height zero");
    Check(node.GetChain().TipCopy().GetHash() == genesis.GetHash(),
          "fresh node has exact compiled genesis");
}

ExactTipPeers InstallExactTipEvidence(VeldNode& node, uint16_t base_port) {
    auto& server = node.TestWorkAdmissionProcessServer();
    server.TestSetPeerHeightClock(100);
    ExactTipPeers peers{MakeConnection("10.81.0.1", base_port),
                        MakeConnection("10.81.0.2", static_cast<uint16_t>(base_port + 1))};
    Check(peers.first && peers.second, "two outbound peer observations allocated");
    server.TestRecordVersionClaim(peers.first, 0);
    server.TestRecordVersionClaim(peers.second, 0);
    server.TestMarkPeerHandshakeReady(peers.first);
    server.TestMarkPeerHandshakeReady(peers.second);

    const Hash256 tip = node.GetChain().TipCopy().GetHash();
    server.TestRecordVerifiedPeerHeight("10.81.0.1", tip);
    server.TestRecordVerifiedPeerHeight("10.81.0.2", tip);
    Check(server.TestVerifiedPeerEvidenceCount() == 2,
          "two distinct peers publish canonical exact-tip evidence");

    const auto view = server.GetPeerHeightView();
    Check(view.work_sequencer_wired && view.work_view_stable,
          "exact peer view is sequenced and stable");
    Check(view.distinct_version_ips == 2 && view.distinct_outbound_sync_ips == 2,
          "two distinct exact-tip outbound observations are live");
    Check(view.verified_height == 0 && view.outbound_sync_height == 0,
          "both peer observations identify the height-zero canonical tip");
    return peers;
}

struct EqualityView {
    uint64_t height{0};
    Hash256 tip{};
    std::string work;
    uint64_t supply{0};
    Hash256 state{};
};

EqualityView Observe(const VeldNode& node) {
    EqualityView out;
    out.height = node.GetChain().Height();
    out.tip = node.GetChain().TipCopy().GetHash();
    out.supply = node.GetChain().TotalSupplyUnits();
    out.state = node.ConsensusStateDigest();
    const auto tips = node.GetChain().GetChainTips();
    Check(tips.size() == 1 && tips.front().status == "active" &&
              tips.front().height == out.height && tips.front().hash == out.tip,
          "node exposes exactly one active canonical tip");
    out.work = tips.front().cumulative_work;
    return out;
}

void PropagateToObserver(VeldNode& observer, const Block& block, const char* source) {
    auto& server = observer.TestWorkAdmissionProcessServer();
    server.SetIBDComplete(true);
    server.TestUseQueuedBlockIngest(true);
    server.TestResetBlockIngestOutcomeCounters();
    const auto queued = server.TestEnqueueBlockIngest(block, block.SerializedSize(), source);
    Check(queued == net::NodeServer::IngestEnqueueResult::Queued,
          "solved block enters observer production ingest queue");
    Check(server.TestProcessOnePendingBlockIngest(),
          "observer executes production block-ingest worker path");
    Check(server.TestBlockIngestConsensusCallCount() == 1,
          "observer calls consensus admission exactly once");
    Check(server.TestBlockIngestRelayCount() == 1 && server.TestBlockIngestPenaltyCount() == 0,
          "observer accepts and relays block without peer penalty");
    Check(observer.GetChain().Height() == 1 &&
              observer.GetChain().TipCopy().GetHash() == block.GetHash(),
          "observer advances from height zero to solved height one");
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 2)
            throw std::invalid_argument(
                "usage: block_commit_deadlock_process_fixture <artifact-root>");
        const std::filesystem::path root(argv[1]);
        std::filesystem::create_directories(root);
        compat::InitNetwork();

        const auto config = MainnetConfig();
        Check(config.kind == NetworkKind::Mainnet && config.name == "Veld Mainnet" &&
                  config.magic == MAINNET_MAGIC,
              "all objects use the production network configuration");

        auto miner_node = std::make_unique<VeldNode>(config, (root / "miner").string());
        auto observer_a = std::make_unique<VeldNode>(config, (root / "observer-a").string());
        auto observer_b = std::make_unique<VeldNode>(config, (root / "observer-b").string());
        InstallGenesis(*miner_node);
        InstallGenesis(*observer_a);
        InstallGenesis(*observer_b);
        miner_node->TestInstallWorkAdmissionProcessServer();
        observer_a->TestInstallWorkAdmissionProcessServer();
        observer_b->TestInstallWorkAdmissionProcessServer();
        auto exact_tip_peers = InstallExactTipEvidence(*miner_node, 38101);

        VeldNode::TestWorkAdmissionProcessState ready;
        miner_node->TestConfigureWorkAdmissionProcess(ready);
        observer_a->TestConfigureWorkAdmissionProcess(ready);
        observer_b->TestConfigureWorkAdmissionProcess(ready);

        const auto subject = miner_node->TestCurrentBlockProductionSubject();
        Check(subject && subject->height == 1 && subject->parent_height == 0 &&
                  subject->parent_hash == miner_node->GetChain().TipCopy().GetHash(),
              "production local-work subject is bound to height one");
        const auto decision =
            miner_node->TestEvaluateWorkAdmission(work_admission::Path::InternalMining, *subject);
        Check(decision.allowed && decision.binding,
              "production local-work predicate issues an exact binding");

        const RealKeyPair miner_key = GenerateKeyPair(false);
        auto solved = MineOnly(miner_node->GetChainMut(), miner_node->GetMempoolMut(), miner_key);
        Check(solved.success && solved.block.height == 1 &&
                  Blockchain::VerifyBlockPoW(solved.block),
              "test-only fixture genuinely solves a valid height-one block");
        auto context = mining::PowAdmissionContext::InternalMiningWork(
            work_admission::EncodeBinding(*decision.binding));

        std::cout << "BLOCK_COMMIT_DEADLOCK_ARMED verified_peers=2 height=0" << std::endl;
        const auto admission =
            miner_node->GetChainMut().AddBlockDirect(solved.block, false, false, false, context);
        Check(admission.IsAccepted(), "exact production AddBlockDirect local-work path returns");
        Check(miner_node->GetChain().Height() == 1 &&
                  miner_node->GetChain().TipCopy().GetHash() == solved.block.GetHash(),
              "local solved block commits height zero to one");
        Check(context.local_work_handoff && context.local_work_handoff->IsLive(),
              "claimed one-use admission remains live for propagation");

        PropagateToObserver(*observer_a, solved.block, "198.51.100.81");
        PropagateToObserver(*observer_b, solved.block, "198.51.100.82");

        context.local_work_handoff->Reset();
        const auto coordinator = miner_node->TestWorkAdmissionCoordinatorSnapshot();
        Check(coordinator.active_leases == 0, "local-work ticket releases after propagation");

        const EqualityView miner_view = Observe(*miner_node);
        const EqualityView observer_a_view = Observe(*observer_a);
        const EqualityView observer_b_view = Observe(*observer_b);
        const auto equal = [&](const EqualityView& other) {
            return other.height == miner_view.height && other.tip == miner_view.tip &&
                   other.work == miner_view.work && other.supply == miner_view.supply &&
                   other.state == miner_view.state;
        };
        Check(equal(observer_a_view) && equal(observer_b_view),
              "all three nodes agree on tip work supply and state digest");
        Check(miner_node->GetMempool().IsEmpty() && observer_a->GetMempool().IsEmpty() &&
                  observer_b->GetMempool().IsEmpty(),
              "height-one propagation leaves every mempool empty");

        exact_tip_peers.first->Close();
        exact_tip_peers.second->Close();
        miner_node->Stop();
        observer_a->Stop();
        observer_b->Stop();
        Check(true, "all three node shutdown calls complete");

        std::cout << "BLOCK_COMMIT_DEADLOCK_JSON {\"status\":\"pass\","
                  << "\"nodes\":3,\"verified_peers\":2,"
                  << "\"height_before\":0,\"height_after\":1,"
                  << "\"tip\":\"" << HashToHex(miner_view.tip) << "\","
                  << "\"work\":\"" << miner_view.work << "\","
                  << "\"supply\":" << miner_view.supply << ","
                  << "\"state_digest\":\"" << HashToHex(miner_view.state) << "\","
                  << "\"observer_accepts\":2,\"observer_relays\":2,"
                  << "\"shutdown\":true,\"checks\":" << checks << "}" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}
