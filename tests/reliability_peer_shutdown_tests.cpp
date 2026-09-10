#include "regtest_profile.h"
#define VELD_TEST_HOOKS 1
#include "network/tcp.h"
#include <future>
#include <iostream>

int main() {
    using namespace veld;
    using namespace std::chrono_literals;
    compat::InitNetwork();
    for (const bool queued : {false, true}) {
        for (const bool already_waiting : {false, true}) {
            Blockchain chain;
            Mempool pool;
            net::NodeServer server(0, MAINNET_MAGIC, chain, pool);
            server.TestUseQueuedBlockIngest(queued);
            const auto fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (!compat::IsValidSocket(fd)) return 2;
            net::Connection peer(fd, "198.51.100.81", 32081, true);
            Block block;
            block.header.prev_block_hash.fill(0x51);
            const P2PMessage message(MAINNET_MAGIC, MessageType::BLOCK,
                                     block.Serialize());
            std::future<void> dispatch;
            bool expected_boundary;
            {
                auto commit = chain.AcquireConsensusTransitionGuard();
                if (!already_waiting) server.RequestWorkStop();
                dispatch = std::async(std::launch::async, [&] {
                    server.TestDispatchPeerMessage(peer, message);
                });
                const bool returned = dispatch.wait_for(300ms) ==
                                      std::future_status::ready;
                expected_boundary = returned != already_waiting;
                if (already_waiting) server.RequestWorkStop();
            }
            dispatch.get();
            // The deliberately invalid body must not be classified, cached,
            // or scored once local shutdown has cancelled its validation.
            if (!expected_boundary ||
                server.TestViolationScore("198.51.100.81") != 0 ||
                server.TestIsBlockRejected(block.GetHash()) ||
                server.TestPendingBlockIngestCount() != 0 ||
                server.ClearOrphanPool() != 0) {
                std::cerr << "FAIL: peer shutdown boundary queued=" << queued
                          << " already_waiting=" << already_waiting << '\n';
                return 1;
            }
        }
    }
    std::cout << "PASS: late and waiting peer work cancels in direct and queued modes without a validity decision\n";
}
