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
        server.TestRememberValidatedDownload(connection, chain.GetBlock(0).GetHash());
        Check(First(server.TestDownloadLocator(connection)) == common,
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
