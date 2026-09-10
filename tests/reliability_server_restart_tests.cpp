#include "regtest_profile.h"
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_LOCAL_TEST_NETWORK 1
#include "network/chainparams.h"
#include "network/tcp.h"
#include <iostream>

int main() {
    using namespace veld;
    compat::InitNetwork();
    Blockchain chain;
    Mempool pool;
    net::NodeServer server(0, RegtestConfig().magic, chain, pool);
    for (int stage = 1; stage <= 3; ++stage) {
        server.TestSetStartFailureStage(stage);
        if (server.Start()) return 1;
        server.Stop();
        server.TestSetStartFailureStage(0);
        if (!server.Start()) return 2;
        server.RequestWorkStop();
        server.RequestWorkStop();
        Block after_stop;
        after_stop.height = 1;
        after_stop.header.nonce = stage;
        if (server.TestEnqueueBlockIngest(after_stop, 128, "127.0.0.1:12001") !=
            net::NodeServer::IngestEnqueueResult::Full) return 3;
        server.Stop();
        if (server.TestPendingBlockIngestCount() != 0 ||
            server.TestPendingBlockIngestBytes() != 0) return 4;
        // The next successful generation must reopen admission.
        if (!server.Start()) return 5;
        if (server.TestEnqueueBlockIngest(after_stop, 128, "127.0.0.1:12001") !=
            net::NodeServer::IngestEnqueueResult::Queued) return 6;
        server.Stop();
    }
    std::cout << "PASS: partial startup rollback, repeated cancellation, and "
                 "fresh admission after server restart\n";
}
