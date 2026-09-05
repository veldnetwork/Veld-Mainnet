#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#include "network/tcp.h"
#include <cassert>
#include <iostream>

// Test state publication and accounting directly. Sockets remain unconnected;
// the server is never started and no frames or traffic are sent.
int main() {
    using namespace veld;
    compat::InitNetwork();
    Blockchain chain;
    const Block genesis = CreateGenesisBlock();
    assert(chain.AddBlockDirect(genesis, true, true, false,
        mining::PowAdmissionContext::Internal()).IsAccepted());
    Block previous = genesis;
    for (uint64_t height = 1; height <= 2; ++height) {
        Block block;
        block.height = height;
        block.header.prev_block_hash = previous.GetHash();
        block.header.timestamp = previous.header.timestamp + 180;
        block.header.bits = previous.header.bits;
        Transaction coinbase;
        coinbase.inputs.push_back(TxInput::Coinbase("ordinary fixture " + std::to_string(height)));
        coinbase.outputs.emplace_back(1, std::vector<uint8_t>{0x51});
        block.transactions.push_back(coinbase);
        block.UpdateMerkleRoot();
        assert(chain.AddBlockDirect(block, true, true, false,
            mining::PowAdmissionContext::Internal()).IsAccepted());
        previous = block;
    }
    Mempool mempool;
    net::NodeServer server(0, MAINNET_MAGIC, chain, mempool);
    size_t transitions = 0;
    server.SetPeerWorkViewTransitionFn([&]() {
        ++transitions;
        return std::static_pointer_cast<void>(std::make_shared<int>(1));
    });
    server.TestSetPeerHeightClock(100);
    auto connection = [](const char* ip, bool inbound) {
        auto fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        assert(compat::IsValidSocket(fd));
        return std::make_shared<net::Connection>(fd, ip, 8333, inbound);
    };
    auto a = connection("192.0.2.1", false);
    auto b = connection("192.0.2.2", false);
    auto inbound = connection("192.0.2.3", true);
    for (const auto& c : {a,b,inbound}) {
        server.TestRecordVersionClaim(c, 100);
        server.TestMarkPeerHandshakeReady(c);
    }
    const auto before = server.GetPeerHeightView();
    const auto count = transitions;
    server.TestSetPeerHeightClock(101);
    server.TestRecordPeerSyncHeight(*a, 100);
    assert(transitions == count);
    assert(server.GetPeerHeightView().work_generation == before.work_generation);
    server.TestRecordPeerSyncHeight(*inbound, 100);
    assert(transitions == count);
    server.TestRecordPeerSyncHeight(*a, 101);
    assert(transitions == count); // unchanged second-highest outbound floor
    server.TestRecordPeerSyncHeight(*b, 101);
    assert(transitions == count + 1);
    const auto after = server.GetPeerHeightView();
    assert(after.outbound_sync_height == 101 && after.work_view_stable);
    assert(after.work_generation > before.work_generation);

    server.TestRecordVerifiedPeerHeight("192.0.2.2", chain.GetBlock(2).GetHash());
    const auto evidence_count = transitions;
    const auto evidence_view = server.GetPeerHeightView();
    server.TestRecordVerifiedPeerHeight("192.0.2.1", chain.GetBlock(1).GetHash());
    assert(server.GetPeerHeightView().verified_height == evidence_view.verified_height);
    assert(transitions == evidence_count);

    const auto cap = net::NodeServer::TestGetBlocksResponseByteCap();
    assert(server.TestTakeGetBlocksResponseBytes("192.0.2.4:1000", cap - 1));
    assert(server.TestTakeGetBlocksResponseBytes("192.0.2.4:1001", 1));
    assert(!server.TestTakeGetBlocksResponseBytes("192.0.2.4:1002", 1));
    assert(!server.TestTakeGetBlocksBodyWork("192.0.2.4:1003"));
    assert(server.TestTakeGetBlocksBodyWork("192.0.2.5:1003"));
    std::cout << "PASS: ordinary peer progress, unchanged views, shared endpoint accounting\n";
}
