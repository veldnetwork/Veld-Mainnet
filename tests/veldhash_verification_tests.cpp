#include "mining/veldhash.h"
#include <chrono>
#include <fstream>
#include <iostream>

int main(int argc, char** argv) {
    using namespace veld;
    try {
        if (argc != 2) throw std::runtime_error("provide the existing hash vectors");
        mining::VeldDatasetLightKat();
        std::ifstream input(argv[1]);
        if (!input) throw std::runtime_error("hash vectors unavailable");
        uint64_t height;
        std::string raw, expected;
        unsigned vectors = 0;
        while (input >> height >> raw >> expected) {
            if (raw.size() != 176 || expected.size() != 64 || ++vectors > 128)
                throw std::runtime_error("unexpected vector bounds");
            std::vector<uint8_t> bytes;
            for (size_t i = 0; i < raw.size(); i += 2) {
                size_t used = 0;
                const auto value = std::stoul(raw.substr(i, 2), &used, 16);
                if (used != 2 || value > 255) throw std::runtime_error("vector hex");
                bytes.push_back(static_cast<uint8_t>(value));
            }
            const uint32_t bits = uint32_t(bytes[76]) | (uint32_t(bytes[77]) << 8) |
                (uint32_t(bytes[78]) << 16) | (uint32_t(bytes[79]) << 24);
            CanonicalPowTarget target;
            if (!DecodeCanonicalVeldTarget(bits, target))
                throw std::runtime_error("vector target is not canonical");
            const auto before = mining::GlobalDataset().Stats();
            const auto started = std::chrono::steady_clock::now();
            const auto verified = mining::VeldHashForVerification(bytes, height, target);
            const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - started).count();
            const auto after = mining::GlobalDataset().Stats();
            if (!mining::g_veldhash_last_dataset_ok() || HashToHex(verified) != expected)
                throw std::runtime_error("verification differs from the existing vector");
            if (before.requests != after.requests || before.hits != after.hits ||
                before.builds != after.builds || before.failures != after.failures)
                throw std::runtime_error("verification disturbed the mining dataset");
            const auto mined = mining::VeldHash(bytes, height, target);
            if (!mining::g_veldhash_last_dataset_ok() || mined != verified)
                throw std::runtime_error("mining and verification hashes differ");
            const auto repeat = mining::VeldHashForVerification(bytes, height, target);
            if (repeat != verified || !mining::g_veldhash_last_dataset_ok())
                throw std::runtime_error("verification changed after mining");
            std::cout << "{\"vector\":" << vectors << ",\"height\":" << height
                      << ",\"verification_microseconds\":" << elapsed
                      << ",\"hash\":\"" << HashToHex(verified) << "\"}" << std::endl;
        }
        if (!input.eof() || vectors != 28)
            throw std::runtime_error("incomplete known-vector coverage");
        std::cout << "PASS 28 existing vectors; mining/verification parity; mining cache preserved"
                  << std::endl;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << std::endl;
        return 1;
    }
}
