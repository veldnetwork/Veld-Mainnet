#include "node/node.h"
#include <iostream>
#include <type_traits>

static_assert(std::is_same_v<decltype(veld::MineBlockResult{}.best_nonce), uint64_t>,
              "mining results must preserve all nonce bits");
static_assert(std::is_same_v<veld::MiningProgressCb,
                             std::function<void(uint64_t, uint64_t, const veld::Hash256&)>>,
              "mining progress must preserve all nonce bits");

int main() {
    const uint64_t expected = 0xfedcba9876543210ULL;
    uint64_t observed = 0;
    veld::MiningProgressCb progress = [&](uint64_t, uint64_t nonce, const veld::Hash256&) {
        observed = nonce;
    };
    progress(1, expected, {});
    veld::MineBlockResult result{};
    result.best_nonce = expected;
    if (observed != expected || result.best_nonce != expected)
        return 1;

    veld::BlockHeader header;
    const auto template_identity = header.GetTemplateWorkIdentity();
    const auto original = header.Serialize();
    header.nonce = expected;
    const auto encoded = header.Serialize();
    veld::BlockHeader decoded;
    if (encoded.size() != 88 || !decoded.Deserialize(encoded) || decoded.nonce != expected ||
        !std::equal(original.begin(), original.begin() + 80, encoded.begin()) ||
        header.GetTemplateWorkIdentity() != template_identity)
        return 1;

    std::cout << "PASS full-width nonce reporting, header roundtrip, and template identity\n";
}
