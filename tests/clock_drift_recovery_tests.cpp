#define VELD_LOCAL_TEST_NETWORK 1
#define VELD_TEST_HOOKS 1
#include "isolated_regtest_profile.h"
#include "network/tcp.h"

#include <iostream>
#include <stdexcept>

using namespace veld;
using Server = net::NodeServer;
using Connection = net::Connection;

namespace {
size_t checks = 0;
void Check(bool ok, const char* message) {
    ++checks;
    if (!ok)
        throw std::runtime_error(message);
}

struct Fixture {
    Blockchain chain;
    Mempool mempool;
    Server server{0, 0xF17EC10C, chain, mempool};
    std::vector<std::shared_ptr<Connection>> peers;
    static constexpr uint64_t mono = 100000;
    static constexpr int64_t wall = 2000000;

    Fixture() {
        server.TestSetClockSampleTime(mono, wall);
    }

    std::shared_ptr<Connection> Add(const std::string& ip, int64_t offset, bool inbound = false,
                                    bool anchor = true, uint64_t sampled = mono) {
        const auto fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        Check(compat::IsValidSocket(fd), "fixture socket");
        auto peer = std::make_shared<Connection>(fd, ip, 8333, inbound);
        if (anchor)
            Check(server.AddFleetAnchorIp(ip), "configured anchor");
        peer->MarkVersionReceived();
        peer->MarkHandshakeReady();
        server.TestRegisterAdmittedConnection(ip + ':' + std::to_string(peers.size()), peer);
        server.TestRecordClockDrift(peer, offset, sampled);
        peers.push_back(peer);
        return peer;
    }

    void Quorum(int64_t offset) {
        Add("198.51.100.1", offset);
        Add("198.51.100.2", offset);
        Add("198.51.100.3", offset);
    }

    void Expect(size_t count, int64_t offset, const char* message) {
        const auto result = server.GetActiveClockDriftSnapshot();
        Check(result.distinct_ip_count == count && result.median_seconds == offset, message);
    }
};
}

int main() {
    try {
        compat::InitNetwork();
        {
            Fixture f;
            f.Quorum(900);
            f.Expect(3, 900, "behind clock initially pauses mining");
            f.server.TestSetClockSampleTime(Fixture::mono + 20, Fixture::wall + 20);
            f.Expect(3, 900, "elapsed time preserves an uncorrected offset");
            f.server.TestSetClockSampleTime(Fixture::mono + 20, Fixture::wall + 920);
            f.Expect(3, 0, "correcting a behind clock clears the halt without reconnecting");
            f.server.TestSetClockSampleTime(Fixture::mono + 40, Fixture::wall + 1840);
            f.Expect(3, -900, "later forward wall-clock jump is detected on existing connections");
            f.server.TestSetClockSampleTime(Fixture::mono + 40, Fixture::wall + 940);
            f.Expect(3, 0, "a second correction clears the halt");
            f.server.TestSetClockSampleTime(Fixture::mono + 3600, Fixture::wall + 4500);
            f.Expect(3, 0, "monotonic expiry boundary retains corrected samples");
            f.server.TestSetClockSampleTime(Fixture::mono + 3601, Fixture::wall + 4501);
            f.Expect(0, 0, "expired samples cannot form a halt quorum");
        }
        {
            Fixture f;
            f.Quorum(-900);
            f.server.TestSetClockSampleTime(Fixture::mono + 5, Fixture::wall - 895);
            f.Expect(3, 0, "correcting an ahead clock clears the halt without reconnecting");
            f.server.TestSetClockSampleTime(Fixture::mono + 6, Fixture::wall - 1794);
            f.Expect(3, 900, "a later backwards wall-clock jump is detected");
        }
        {
            Fixture f;
            f.Quorum(0);
            f.server.TestSetClockSampleTime(Fixture::mono + 10, Fixture::wall + 609);
            f.Expect(3, -599, "offset just below the mining threshold");
            f.server.TestSetClockSampleTime(Fixture::mono + 10, Fixture::wall + 610);
            f.Expect(3, -600, "offset at the mining threshold");
            f.server.TestSetClockSampleTime(Fixture::mono + 10, -1);
            f.Expect(0, 0, "negative wall time cannot become unsigned peer time");
            f.server.TestSetClockSampleTime(Fixture::mono - 1, Fixture::wall);
            f.Expect(0, 0, "future monotonic samples are excluded");
        }
        {
            Fixture f;
            f.Quorum(900);
            f.Add("203.0.113.1", -900, true);
            f.Add("203.0.113.2", -900, false, false);
            f.Add("198.51.100.1", 1200);
            f.Expect(3, 900, "inbound, unconfigured and duplicate IPs cannot inflate the quorum");
            f.server.TestSetClockSampleTime(Fixture::mono + 5, Fixture::wall + 905);
            f.Expect(3, 0, "correction preserves the configured outbound median");
            f.peers[1]->Close();
            f.Expect(2, 300, "a closed connection is excluded immediately");
        }
        std::cout << "PASS: " << checks << " clock recovery and source-authority checks\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
