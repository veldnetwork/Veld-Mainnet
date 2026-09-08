#include "mining/veldhash.h"
#include <fstream>
#include <iostream>

// The expected hashes are frozen from the released 3.0.9 implementation.
// Full-size datasets are intentional: reduced datasets cannot prove mainnet equivalence.
int main(int argc, char** argv) {
    using namespace veld;
#if !defined(VELD_MAINNET_POW) || defined(VELD_LIGHT_VERIFY) || defined(VELD_TEST_DATASET_BYTES)
    std::cerr << "Hash vectors require full production VeldHash parameters\n";
    return 2;
#else
    if (argc != 2) {
        std::cerr << "usage: mining_hash_vectors FIXTURE\n";
        return 2;
    }
    std::ifstream input(argv[1]);
    if (!input)
        return 2;
    uint64_t height;
    std::string encoded, expected;
    unsigned count = 0;
    while (input >> height >> encoded >> expected) {
        const auto header = HexToBytes(encoded);
        if (header.size() != 88 || expected.size() != 64)
            return 1;
        const auto actual = mining::VeldHash(header, height);
        if (!mining::g_veldhash_last_dataset_ok() || HashToHex(actual) != expected) {
            std::cerr << "FAIL released VeldHash vector " << count << " at height " << height
                      << '\n';
            return 1;
        }
        ++count;
    }
    if (!input.eof() || count != 28)
        return 1;
    std::cout << "PASS " << count << " released mainnet hash vectors\n";
#endif
}
