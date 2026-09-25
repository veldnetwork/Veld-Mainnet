#include "pool/client_diagnostics.h"
#include <iostream>
#include <stdexcept>
#include <vector>
int main() try {
    using namespace veld::pool;
    const std::vector<std::pair<std::string, std::string>> cases = {
        {"pool certificate verification failed", "certificate"},
        {"pool CA unavailable", "trust_store"},
        {"pool refused request", "remote_refusal"},
        {"duplicate pool HTTP header", "http_response"},
        {"pool JSON response", "response_schema"},
        {"pool job network or version mismatch", "work_identity"},
        {"pool balance identity", "account_identity"},
        {"private pool state write failed", "private_state"},
        {"pool refused request with SECRET", "local_failure"},
        {std::string(100000, 'Z'), "local_failure"}};
    for (const auto& [message, code] : cases) {
        const auto failure = ClassifyFailure(std::runtime_error(message));
        if (failure.code != code)
            throw std::runtime_error("wrong bounded category");
    }
    if (FailureSummary("remote_refusal", "work") != "Pool service refused the request (work).")
        throw std::runtime_error("known stage missing");
    const auto untrusted = FailureSummary("SECRET<script>", "TOKEN\nPASSWORD");
    if (untrusted.find("SECRET") != std::string::npos ||
        untrusted.find("TOKEN") != std::string::npos || untrusted.size() > 100)
        throw std::runtime_error("untrusted diagnostic echo");
    std::cout << "PASS exact failure categories, bounded unknowns, fixed stage projection\n";
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
