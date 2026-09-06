#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#include "network/tcp.h"
#include "node/ibd_policy.h"
#include <cassert>
#include <array>
#include <iostream>

// Ordinary registry lifecycle controls. All sockets remain unconnected;
// no server, listener, dial, message stream, blockchain injection, or mining.
using namespace veld;
static std::shared_ptr<net::Connection> connection(const char* ip, bool inbound) {
    auto fd=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    assert(compat::IsValidSocket(fd));
    return std::make_shared<net::Connection>(fd,ip,8333,inbound);
}
int main() {
    compat::InitNetwork();
    for(const uint64_t nonce:std::array<uint64_t,2>{1,UINT64_MAX-1}) {
      for(const bool inbound_first:{false,true}) {
        Blockchain chain; Mempool mempool;
        net::NodeServer server(0,MAINNET_MAGIC,chain,mempool);
        server.SetPeerWorkViewTransitionFn([]{
            return std::static_pointer_cast<void>(std::make_shared<int>(1));
        });
        server.TestSetPeerHeightClock(100);
        auto in=connection("192.0.2.1",true);
        auto out=connection("192.0.2.1",false);
        auto out2=connection("198.51.100.2",false);
        std::string inbound_key="in";
        auto first=inbound_first?in:out;
        auto second=inbound_first?out:in;
        const std::string first_key=inbound_first?"in":"192.0.2.1:8333";
        const std::string second_key=inbound_first?"192.0.2.1:8333":"in";
        server.TestRegisterAdmittedConnection(first_key,first);
        assert(!server.TestResolveDuplicateDirection(first_key,*first,nonce));
        server.TestRegisterAdmittedConnection(second_key,second);
        assert(!server.TestResolveDuplicateDirection(second_key,*second,nonce));
        assert(server.TestDirectionCounts()==std::make_pair(1u,1u));
        assert(server.TestOutboundCopyIndexSize()==1);
        assert(server.IsPeerConnected("192.0.2.1:8333"));
        assert(server.IsPeerConnected("192.0.2.1:8333",true));
        assert(!server.TestPreferActualOutboundTipCopy(*in));
        for(const auto& c:{in,out}) {
            server.TestRecordVersionClaim(c,10);
            server.TestMarkPeerHandshakeReady(c);
        }
        assert(server.TestPreferActualOutboundTipCopy(*in));
        assert(!server.TestPreferActualOutboundTipCopy(*out));
        if (inbound_first) assert(!server.TestAdmitTipCopyWork(*in));
        assert(server.TestAdmitTipCopyWork(*out));
        assert(!server.TestAdmitTipCopyWork(*in));
        assert(!server.TestAdmitTipCopyWork(*out));
        auto unmatched=connection("192.0.2.3",true);
        unmatched->MarkPeerNonce(nonce);
        assert(!server.TestPreferActualOutboundTipCopy(*unmatched));
        assert(server.TestAdmitTipCopyWork(*unmatched));
        assert(!server.TestAdmitTipCopyWork(*unmatched));
        assert(server.GetPeerHeightView().distinct_outbound_sync_ips==1);
        server.TestRegisterAdmittedConnection("198.51.100.2:8333",out2);
        server.TestRecordVersionClaim(out2,10);
        server.TestMarkPeerHandshakeReady(out2);
        assert(server.GetPeerHeightView().distinct_outbound_sync_ips==2);
        // Same-direction reconnects still collapse, without closing outbound.
        auto new_in=connection("192.0.2.1",true);
        server.TestRegisterAdmittedConnection("a-in",new_in);
        assert(!server.TestResolveDuplicateDirection("a-in",*new_in,nonce));
        server.TestFinalizePeerConnection(inbound_key,in);
        assert(!server.TestMappedConnectionIs(inbound_key,in));
        assert(server.TestMappedConnectionIs("192.0.2.1:8333",out));
        assert(server.TestDirectionCounts()==std::make_pair(1u,2u));
        assert(server.TestOutboundCopyIndexSize()==2);
        in=new_in; inbound_key="a-in";
        server.TestRecordVersionClaim(in,10);
        server.TestMarkPeerHandshakeReady(in);
        assert(IsInitialDownloadAtTip(false,10,false,2,10,2,10));
        assert(!IsInitialDownloadAtTip(false,10,false,2,10,1,10));
        // Inbound-copy preference does not refresh any outbound claim.
        const auto generation=server.GetPeerHeightView().work_generation;
        server.TestSetPeerHeightClock(100+server.TestVersionHeightHintTtlSeconds()+1);
        assert(server.TestPreferActualOutboundTipCopy(*in));
        assert(server.GetPeerHeightView().distinct_outbound_sync_ips==0);
        assert(server.GetPeerHeightView().work_generation==generation);
        server.TestRecordPeerSyncHeight(*out,10);
        server.TestRecordPeerSyncHeight(*out2,10);
        assert(server.GetPeerHeightView().distinct_outbound_sync_ips==2);
        // Replacement keeps the opposite leg and exact-object cleanup cannot
        // erase the replacement's map entry or accounting.
        auto replacement=connection("192.0.2.1",false);
        server.TestRegisterAdmittedConnection("192.0.2.1:8333",replacement);
        assert(!server.TestResolveDuplicateDirection("192.0.2.1:8333",*replacement,nonce));
        server.TestFinalizePeerConnection("192.0.2.1:8333",out);
        assert(server.TestMappedConnectionIs("192.0.2.1:8333",replacement));
        assert(server.TestMappedConnectionIs(inbound_key,in));
        assert(server.TestDirectionCounts()==std::make_pair(1u,2u));
        assert(!server.TestPreferActualOutboundTipCopy(*in));
        server.TestRecordVersionClaim(replacement,10);
        server.TestMarkPeerHandshakeReady(replacement);
        assert(server.TestPreferActualOutboundTipCopy(*in));
        server.TestFinalizePeerConnection("192.0.2.1:8333",replacement);
        assert(server.IsPeerConnected("192.0.2.1:8333"));
        assert(!server.IsPeerConnected("192.0.2.1:8333",true));
        assert(!server.TestPreferActualOutboundTipCopy(*in));
        assert(server.GetPeerHeightView().distinct_outbound_sync_ips==1);
        assert(server.TestDirectionCounts()==std::make_pair(1u,1u));
        assert(server.TestOutboundCopyIndexSize()==1);
      }
    }
    std::cout<<"PASS: bounded directional registry, exact outbound evidence, expiry and retirement\n";
}
