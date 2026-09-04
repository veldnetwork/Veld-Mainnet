#include "../include/core/pow_target.h"

#include <cmath>
#include <cstdint>
#include <iostream>

namespace {

int checks = 0;
int failures = 0;

void Check(bool condition, const char* name) {
    ++checks;
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << name << '\n';
    }
}

bool Near(double actual, double expected, double tolerance) {
    return std::fabs(actual - expected) <= tolerance;
}

}  // namespace

int main() {
    veld::PowDisplayMetrics live;
    Check(veld::CalculatePowDisplayMetrics(0x1e11df25u, live),
          "valid mainnet target produces display metrics");
    Check(std::llround(live.expected_hashes_per_block) == 938761,
          "live target expected work matches node RPC");
    Check(Near(live.difficulty, 0.000218568995, 0.000000000001),
          "live target difficulty matches node RPC");
    Check(Near(live.expected_hashes_per_block / 180.0,
               5215.339, 0.01),
          "target-time hashrate uses expected work per block");

    veld::PowDisplayMetrics limit;
    Check(veld::CalculatePowDisplayMetrics(
              veld::VELD_POW_LIMIT_BITS, limit),
          "canonical proof-of-work limit produces metrics");
    Check(std::llround(limit.expected_hashes_per_block) == 2,
          "proof-of-work limit has approximately two expected hashes");

    veld::PowDisplayMetrics invalid{7.0, 9.0};
    Check(!veld::CalculatePowDisplayMetrics(0x20ffffffu, invalid),
          "negative compact target is rejected");
    Check(invalid.expected_hashes_per_block == 0.0 &&
              invalid.difficulty == 0.0,
          "failed display conversion clears outputs");
    Check(!veld::CalculatePowDisplayMetrics(0u, invalid),
          "zero compact target is rejected");

    if (failures != 0) {
        std::cerr << "pow display metrics: FAIL (" << failures << "/"
                  << checks << ")\n";
        return 1;
    }
    std::cout << "pow display metrics: PASS (" << checks << " checks)\n";
    return 0;
}
