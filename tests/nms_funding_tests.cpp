#include "mining/nms_submission.h"
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>

struct Output {
    uint64_t value;
    uint64_t block_height;
};

int main() {
    unsigned checks = 0;
    const auto check = [&](bool value, const char* message) {
        ++checks;
        if (!value) throw std::runtime_error(message);
    };
    try {
        using veld::mining::SelectNmsFundingOutput;
        constexpr uint64_t required = 200000, dust = 1000, tip = 5000;
        constexpr uint64_t marker = required / 2, fee = required - marker;
        std::vector<Output> outputs;
        const auto select = [&](uint64_t spendable = std::numeric_limits<uint64_t>::max()) {
            return SelectNmsFundingOutput(outputs, tip, spendable, marker, fee, dust);
        };
        check(!select(), "empty wallet selected funding");
        outputs = {{required + 1, tip}, {required + dust, tip}, {required + 10000, tip}};
        const auto* selected = select();
        check(selected == &outputs[1], "did not continue to usable change");
        check(selected->value - required == dust, "fixed fee/change accounting changed");
        outputs.push_back({required, tip - 1});
        check(select() == &outputs[3],
              "exact funding was not selected");
        outputs = {{required - 1, tip}, {required + dust - 1, tip}};
        check(!select(), "unusable funding selected");
        outputs = {{required, tip + 1}, {required + dust, tip}};
        check(select() == &outputs[1],
              "future output selected");
        outputs = {{std::numeric_limits<uint64_t>::max(), tip}};
        check(select() == &outputs[0],
              "large value overflowed selection");
        check(outputs[0].value == std::numeric_limits<uint64_t>::max(), "selection mutated value");
        outputs = {{100000000000ULL + 150000, tip}};
        check(select(150000) == &outputs[0], "legacy logical stake headroom rejected");
        check(select(fee) == &outputs[0], "exact net fee headroom rejected");
        check(!select(fee - 1), "funding used reserved stake for the fee");
        check(!SelectNmsFundingOutput(outputs, tip, fee,
              std::numeric_limits<uint64_t>::max(), fee, dust), "required amount overflowed");
        std::cout << "PASS nms_funding_tests checks=" << checks
                  << " transactions=0 signatures=0 network=0\n";
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
