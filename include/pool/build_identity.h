#pragma once
#include "../core/constants.h"
#include "../core/version.h"
#include <iostream>
#include <string>

namespace veld::pool {
// Pure artifact probes. These execute before reading any configuration or key.
inline bool PrintBuildIdentity(int argc, char** argv, const char* role, bool signing) {
    if (argc != 2)
        return false;
    if (std::string(argv[1]) == "--version") {
        std::cout << "Veld " << role << ' ' << CLIENT_VERSION << '\n';
        return true;
    }
    if (std::string(argv[1]) == "--deployment-info") {
        std::cout << "VELD_DEPLOYMENT_INFO_V1_JSON {\"binary_role\":\"" << role
                  << "\",\"client_version\":\"" << CLIENT_VERSION << "\",\"profile_id\":\""
                  << DEPLOYMENT_PROFILE_ID << "\",\"genesis_fingerprint\":\"" << GENESIS_HASH
                  << "\",\"worker_protocol\":\"veld-pool/1\",\"signing_authority\":"
                  << (signing ? "true" : "false")
                  << ",\"custody_authority\":false,\"network_listener\":false}\n";
        return true;
    }
    return false;
}
}
