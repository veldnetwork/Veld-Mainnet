#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#include "network/tcp.h"
#include <iostream>
#include <stdexcept>

using namespace veld;
void Check(bool value, const char* label) {
    if (!value) throw std::runtime_error(label);
}
Block Child(const Block& parent, const char* branch) {
    Block block;
    block.height = parent.height + 1;
    block.header.prev_block_hash = parent.GetHash();
    block.header.timestamp = parent.header.timestamp + 180;
    block.header.bits = parent.header.bits;
    Transaction coinbase;
    coinbase.inputs.push_back(TxInput::Coinbase(std::string(branch) + std::to_string(block.height)));
    coinbase.outputs.emplace_back(1, std::vector<uint8_t>{0x51});
    block.transactions.push_back(coinbase);
    block.UpdateMerkleRoot();
    return block;
}
Hash256 First(const P2PMessage& message) {
    Check(message.payload.size() >= 69 && message.payload[4] <= 32, "bounded locator wire");
    Hash256 hash;
    std::copy_n(message.payload.begin() + 5, 32, hash.begin());
    return hash;
}
int main() {
    try {
        compat::InitNetwork();
        Blockchain chain;
        auto block = CreateGenesisBlock();
        Check(chain.AddBlockDirect(block, true, true, false,
            mining::PowAdmissionContext::Internal()).IsAccepted(), "synthetic genesis");
        for (int i = 0; i < 320; ++i) {
            block = Child(block, "main");
            Check(chain.AddBlockDirect(block, true, true, false,
                mining::PowAdmissionContext::Internal()).IsAccepted(), "synthetic canonical history");
        }
        Mempool pool;
        net::NodeServer server(0, MAINNET_MAGIC, chain, pool);
        auto response_frames = [&](const P2PMessage& request, const char* address) {
            const auto socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            Check(compat::IsValidSocket(socket), "unconnected response queue socket");
            net::Connection queued(socket, address, 1);
            queued.EnableEventLoopIO();
            server.TestDispatchPeerMessage(queued, request);
            // Exercise the actual handler and bounded serialization queue.
            // Nothing is transmitted on this unconnected local socket.
            return queued.QueuedSendFrames();
        };
        PeerManager messages(MAINNET_MAGIC, chain.Height());
        const auto start = chain.GetBlock(224).GetHash();
        const auto fallback = chain.GetBlock(227).GetHash();
        Check(response_frames(messages.BuildGetBlocksMessage(start, std::vector<Hash256>{fallback}), "127.0.0.2") == 33,
              "remaining locator must not be interpreted as stop hash");
        Check(response_frames(messages.BuildGetBlocksMessage(start, {fallback},
              chain.GetBlock(226).GetHash()), "127.0.0.3") == 3,
              "explicit stop hash is read after every locator");
        auto truncated = messages.BuildGetBlocksMessage(start, std::vector<Hash256>{fallback});
        truncated.payload.resize(truncated.payload.size()-1);
        Check(response_frames(truncated, "127.0.0.4") == 0,
              "truncated locator envelope cannot trigger block work");
        const auto fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        Check(compat::IsValidSocket(fd), "unconnected local socket");
        net::Connection connection(fd, "127.0.0.1", 1);
        const auto original = server.TestDownloadLocator(connection);
        Check(First(original) == chain.TipCopy().GetHash(), "fresh connection starts with canonical tip");
        Hash256 unknown{}; unknown[0] = 12;
        server.TestRememberValidatedDownload(connection, unknown);
        Check(server.TestDownloadLocator(connection).payload == original.payload, "unknown cursor rejected");
        // A 92-block fork's exponential locator first matches at h192. Its
        // first 32-body response ends at h224, entirely shared history.
        const auto common = chain.GetBlock(224).GetHash();
        server.TestRememberValidatedDownload(connection, common);
        Check(First(server.TestDownloadLocator(connection)) == common,
              "validated shared-history batch must advance download locator");
        const auto late = chain.GetBlock(223).GetHash();
        server.TestRememberValidatedDownload(connection, late);
        const auto continued = server.TestDownloadLocator(connection);
        Check(First(continued) == common,
              "late near-tip duplicate cannot rewind validated download progress");
        Hash256 second{};
        std::copy_n(continued.payload.begin() + 37, 32, second.begin());
        Check(second == late,
              "peer branch change retains one bounded lower continuation fallback");
        // This focused fixture covers cursor ordering on locally indexed
        // bodies. Genuine fork validation is covered by native co-mining and
        // payment reorganization exercises, not synthetic PoW-free branches.
        const auto higher = chain.GetBlock(227).GetHash();
        server.TestRememberValidatedDownload(connection,higher);
        Check(First(server.TestDownloadLocator(connection))==higher,
              "higher validated progress replaces lower shared-history cursor");
        server.TestRememberValidatedDownload(connection,common);
        const auto changed_branch=server.TestDownloadLocator(connection);
        Check(First(changed_branch)==higher,"lower canonical duplicate preserves progress");
        std::copy_n(changed_branch.payload.begin()+37,32,second.begin());
        Check(second==common,"highest cursor retains recent common-history fallback");
        server.TestRememberValidatedDownload(connection, chain.GetBlock(0).GetHash());
        Check(First(server.TestDownloadLocator(connection)) == higher,
              "ancient duplicate cannot rewind the bounded fork download");
        Check(server.GetPeerHeightView().verified_height == 0,
              "download cursor never grants trusted peer-height evidence");
        const auto next_fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        net::Connection replacement(next_fd, "127.0.0.1", 1);
        Check(First(server.TestDownloadLocator(replacement)) == chain.TipCopy().GetHash(),
              "reconnection owns a fresh cursor");
        std::cout << "PASS bounded validated download continuation; synthetic headers, no network/PoW claim\n";
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
