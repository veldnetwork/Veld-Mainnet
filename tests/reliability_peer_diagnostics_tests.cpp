#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#include "network/tcp.h"
#include <cassert>
#include <iostream>

using namespace veld;
int main() {
    compat::InitNetwork();
    Blockchain chain;
    const auto genesis = CreateGenesisBlock();
    assert(chain.AddBlockDirect(genesis, true, false, false,
        mining::PowAdmissionContext::Internal()).IsAccepted());
    const auto hash = genesis.GetHash();
    Mempool mempool;
    net::NodeServer server(0, MAINNET_MAGIC, chain, mempool);
    auto add = [&](const char* ip, const char* key, bool inbound = false) {
        const auto fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        assert(compat::IsValidSocket(fd));
        auto peer = std::make_shared<net::Connection>(fd, ip, 8333, inbound);
        server.TestRegisterAdmittedConnection(key, peer);
        server.TestMarkPeerHandshakeReady(peer);
        return peer;
    };
    // These registry fixtures own unconnected sockets. No listener or dial runs.
    auto first = add("192.0.2.1", "first");
    auto second = add("192.0.2.1", "second", true);
    server.TestRecordPeerTip(first, hash, 100);
    auto diagnostic = server.SnapshotConnectionTips();
    assert(diagnostic.size() == 1 && diagnostic[0].connection_id == first->DiagnosticId());
    assert(diagnostic[0].connection_id != second->DiagnosticId());
    server.TestRecordPeerTip(second, hash, 101);
    diagnostic = server.SnapshotConnectionTips();
    assert(diagnostic.size() == 2 && server.SnapshotPeerTips().size() == 1);
    assert(diagnostic[0].connection_id != diagnostic[1].connection_id);
    auto replacement = add("192.0.2.1", "second", true);
    diagnostic = server.SnapshotConnectionTips();
    assert(diagnostic.size() == 1 && diagnostic[0].connection_id == first->DiagnosticId());
    Hash256 unknown{}; unknown.fill(0x23);
    server.TestRecordPeerTip(replacement, unknown, 102);
    diagnostic = server.SnapshotConnectionTips();
    assert(diagnostic.size() == 1 && diagnostic[0].connection_id == first->DiagnosticId());
    server.TestRecordPeerTip(replacement, hash, 103);
    auto distinct = add("198.51.100.2", "distinct");
    server.TestRecordPeerTip(distinct, hash, 104);
    assert(server.SnapshotConnectionTips().size() == 3);
    assert(server.SnapshotPeerTips().size() == 2);
    server.TestFinalizePeerConnection("first", first);
    diagnostic = server.SnapshotConnectionTips();
    assert(diagnostic.size() == 2);
    for (const auto& tip : diagnostic) assert(tip.connection_id != first->DiagnosticId());
    std::cout << "PASS: same-IP diagnostics keep separate identities; missing, unknown and retired tips stay absent; reconnects inherit no evidence; quorum remains IP-distinct\n";
}
