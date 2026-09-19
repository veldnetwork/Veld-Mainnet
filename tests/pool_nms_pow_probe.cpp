// Focused arithmetic probe, not an end-to-end lottery qualification.
#include "consensus/nms_pow.h"
#include <iostream>

int main() {
    std::string target, proof;
    while (std::cin >> target >> proof) {
        if (target.size()!=64 || proof.size()!=64 ||
            target.find_first_not_of("0123456789abcdef")!=std::string::npos ||
            proof.find_first_not_of("0123456789abcdef")!=std::string::npos) return 2;
        veld::CanonicalPowTarget decoded;
        decoded.bytes=veld::HexToHash(target);
        std::cout << veld::IsNmsProofInRange(veld::HexToHash(proof),decoded) << '\n';
    }
}
