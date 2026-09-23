#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#include "network/tcp.h"
#include <iostream>
#include <stdexcept>

using namespace veld;
static unsigned checks=0;
static void Check(bool ok,const char* label) {
    ++checks;if(!ok)throw std::runtime_error(label);
}
static std::shared_ptr<net::Connection> MakeInertPeer(const char* ip, bool inbound=false) {
    auto fd=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    Check(compat::IsValidSocket(fd),"inert local socket");
    return std::make_shared<net::Connection>(fd,ip,32001,inbound);
}
int main() {
    compat::InitNetwork();Blockchain chain;Mempool pool;
    net::NodeServer server(0,MAINNET_MAGIC,chain,pool);
    using Result=net::NodeServer::IngestEnqueueResult;
    uint64_t nonce=1;
    auto enqueue=[&](const std::shared_ptr<net::Connection>& peer,size_t bytes=256) {
        Block block;block.header.nonce=nonce++;
        return server.TestEnqueueBlockIngestFromConnection(
            std::move(block),bytes,peer->RemoteAddr()+":32001",peer);
    };
    auto two_only=[&](const std::shared_ptr<net::Connection>& peer) {
        server.TestClearPendingBlockIngest();
        Check(enqueue(peer)==Result::Queued,"first ordinary slot");
        Check(enqueue(peer)==Result::Queued,"second ordinary slot");
        Check(enqueue(peer)==Result::Full,"ordinary source remains bounded to two");
    };
    auto outbound=MakeInertPeer("192.0.2.50");outbound->MarkHandshakeReady();
    two_only(outbound);
    auto inbound=MakeInertPeer("192.0.2.51",true);
    inbound->MarkHandshakeReady();inbound->NoteIbdGetBlocksRequest();two_only(inbound);
    auto incomplete=MakeInertPeer("192.0.2.52");incomplete->NoteIbdGetBlocksRequest();two_only(incomplete);
    outbound->NoteIbdGetBlocksRequest();outbound->TestExpireIbdDownloadWindow();two_only(outbound);

    server.TestClearPendingBlockIngest();outbound->NoteIbdGetBlocksRequest();
    for(unsigned i=0;i<32;++i)Check(enqueue(outbound)==Result::Queued,"one requested IBD batch is retained");
    Check(enqueue(outbound)==Result::Full,"second unsolicited batch cannot expand the source queue");
    auto alias=MakeInertPeer("192.0.2.50");alias->MarkHandshakeReady();alias->NoteIbdGetBlocksRequest();
    Check(enqueue(alias)==Result::Full,"reconnection cannot multiply per-IP queue capacity");
    server.TestClearPendingBlockIngest();
    Check(enqueue(outbound,MAX_BLOCK_SIZE)==Result::Queued,"first maximum-size body");
    Check(enqueue(outbound,MAX_BLOCK_SIZE)==Result::Queued,"second maximum-size body");
    Check(enqueue(outbound,MAX_BLOCK_SIZE)==Result::Full,"IBD does not expand the existing source byte ceiling");
    Check(server.TestPendingBlockIngestBytes()==2*MAX_BLOCK_SIZE,"byte accounting remains exact");

    server.SetIBDComplete(true);two_only(outbound);
    server.SetIBDComplete(false);server.TestClearPendingBlockIngest();
    std::vector<std::shared_ptr<net::Connection>> peers;
    size_t queued=0;
    for(unsigned ip=60;ip<68;++ip) {
        auto peer=MakeInertPeer(("192.0.2."+std::to_string(ip)).c_str());
        peer->MarkHandshakeReady();peer->NoteIbdGetBlocksRequest();peers.push_back(peer);
        for(unsigned i=0;i<32;++i)if(enqueue(peer)==Result::Queued)++queued;
    }
    Check(queued==240 && server.TestPendingBlockIngestCount()==240,
          "normal global count cap preserves protected-lane reservation");
    server.TestClearPendingBlockIngest();
    Check(server.TestPendingBlockIngestBytes()==0,"queue reset releases all accounting");
    std::cout<<"IBD_INGEST_WINDOW: PASS ("<<checks<<" checks); inert queues, no network or PoW claim\n";
}
