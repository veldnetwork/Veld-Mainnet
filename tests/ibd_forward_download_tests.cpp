#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#include "network/tcp.h"
#include <iostream>
#include <stdexcept>

using namespace veld;

static void Check(bool condition, const char* label) {
    if (!condition)
        throw std::runtime_error(label);
}

// Exercise the actual message handler and output queue. Sockets remain
// unconnected; the synthetic genesis is only a locator fixture, not PoW evidence.
static size_t Requests(bool synchronized, bool orphan_body) {
    Blockchain chain;
    auto genesis = CreateGenesisBlock();
    Check(chain.AddBlockDirect(genesis, true, true, false, mining::PowAdmissionContext::Internal())
              .IsAccepted(),
          "genesis locator fixture");
    Mempool pool;
    net::NodeServer server(0, MAINNET_MAGIC, chain, pool);
    server.SetIBDComplete(synchronized);
    const auto socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Check(compat::IsValidSocket(socket), "unconnected local queue socket");
    net::Connection peer(socket, "127.0.0.9", 32001);
    peer.EnableEventLoopIO();
    peer.MarkHandshakeReady();
    PeerManager messages(MAINNET_MAGIC, 0);
    if (orphan_body) {
        Block block;
        block.header.prev_block_hash.fill(0x42);
        block.header.bits = genesis.header.bits;
        block.header.timestamp = genesis.header.timestamp + 180;
        Transaction coinbase;
        coinbase.inputs.push_back(TxInput::Coinbase("orphan fixture"));
        coinbase.outputs.emplace_back(1, std::vector<uint8_t>{0x51});
        block.transactions.push_back(coinbase);
        block.UpdateMerkleRoot();
        server.TestDispatchPeerMessage(
            peer, P2PMessage(MAINNET_MAGIC, MessageType::BLOCK, block.Serialize()));
    } else {
        Hash256 distant{};
        distant.fill(0x43);
        server.TestDispatchPeerMessage(peer, messages.BuildTipsigMessage(721, distant));
    }
    Check(chain.Height() == 0, "unverified announcement cannot advance canonical state");
    return peer.QueuedSendFrames();
}

int main() {
    compat::InitNetwork();
    Check(Requests(false, false) == 0, "IBD tip announcement cannot start reverse download");
    Check(Requests(true, false) == 2, "synchronized tip recovery retains locator and exact fetch");
    Check(Requests(false, true) == 1, "IBD orphan requests forward locator only");
    Check(Requests(true, true) == 2, "synchronized orphan recovery still requests its parent");
    std::cout
        << "IBD_FORWARD_DOWNLOAD: PASS (actual handlers; queued frames; no network/PoW claim)\n";
}
