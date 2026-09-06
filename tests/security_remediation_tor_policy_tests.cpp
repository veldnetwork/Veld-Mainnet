#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#include "compat/platform.h"
#include "compat/process.h"
#include <cassert>
namespace veld::compat {
inline size_t remediation_transport_lookups = 0;
inline std::string RemediationDisabledCurlLookup() {
    ++remediation_transport_lookups;
    return {}; // cannot invoke curl, even if a policy check regresses
}
}
#define TrustedSystemCurlExecutable RemediationDisabledCurlLookup
#include "node/node.h"
#undef TrustedSystemCurlExecutable

int main(int argc, char** argv) {
    assert(argc == 2);
    veld::VeldNode node(veld::MainnetConfig(), argv[1]);
    bool empty_rejected = false;
    try { node.ConfigureTorOnly(""); }
    catch (const std::invalid_argument&) { empty_rejected = true; }
    assert(empty_rejected);
    node.ConfigureTorOnly("ordinary-fixture.onion");
    veld::VeldNode::TestWorkAdmissionProcessState state;
    node.TestConfigureWorkAdmissionProcess(state);
    assert(node.LoadCheckpointsFromUrl() == 0);
    node.OracleSyncCheck();
    assert(veld::compat::remediation_transport_lookups == 0);
    bool late_rejected = false;
    try { node.ConfigureTorOnly("replacement-fixture.onion"); }
    catch (const std::logic_error&) { late_rejected = true; }
    assert(late_rejected);
    state.node_running = false;
    node.TestConfigureWorkAdmissionProcess(state);
    std::cout << "PASS: Tor-only ancillary HTTPS exclusion and immutable startup policy\n";
}
