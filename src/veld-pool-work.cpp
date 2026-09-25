// Bounded native PoW subprocess shared by pool verification and worker clients.
// No wallet, RPC credentials, network access or alternative hashing algorithm.
#include "mining/veldhash.h"
#include "core/block.h"
#include "consensus/nms_pow.h"
#include "pool/build_identity.h"
#include <charconv>
#include <iostream>
#include <sstream>

#ifndef VELD_MAINNET_POW
#error "pool work requires canonical VeldHash"
#endif
#ifdef VELD_FLEET_NO_MINE
#error "fleet artifacts cannot contain a pool worker"
#endif

namespace {
uint64_t Number(const std::string& text, int base) {
    uint64_t value = 0;
    auto result = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (text.empty() || result.ec != std::errc{} || result.ptr != text.data() + text.size())
        throw std::runtime_error("integer");
    if (base == 10 && text != std::to_string(value))
        throw std::runtime_error("integer encoding");
    return value;
}

std::vector<uint8_t> Bytes(const std::string& text, size_t size) {
    if (text.size() != size * 2 || text.find_first_not_of("0123456789abcdef") != std::string::npos)
        throw std::runtime_error("hex encoding");
    return veld::HexToBytes(text);
}
}

int main(int argc, char** argv) {
    using namespace veld;
    if (pool::PrintBuildIdentity(argc, argv, "pool-verifier", false))
        return 0;
    if (argc != 1)
        return 2;

    // Requests are sequential in this bounded subprocess. Retain only private
    // scratch allocations; Initialize replaces the complete state for each
    // proof. Verification still uses the light path and cannot evict a miner's
    // dataset. Allocate lazily after schema and target validation.
    std::optional<mining::VeldHashVMImpl<true>> verification_workspace;
    std::optional<mining::VeldHashVM> scan_workspace;
    char frame[514];
    while (std::cin.getline(frame, sizeof(frame))) {
        const std::string line(frame);
        try {
            if (line.size() > 512)
                throw std::runtime_error("request limit");
            std::istringstream input(line);
            std::string command, height_text, encoded, target_text, start_text, count_text, extra;
            input >> command >> height_text >> encoded;
            const uint64_t height = Number(height_text, 10);
            const auto bytes = Bytes(encoded, 88);
            BlockHeader header;
            if (!header.Deserialize(bytes))
                throw std::runtime_error("header");
            CanonicalPowTarget network;
            if (!DecodeCanonicalVeldTarget(header.bits, network))
                throw std::runtime_error("network target");

            if (command == "hash" || command == "inspect") {
                if (input >> extra)
                    throw std::runtime_error("schema");
                if (!verification_workspace)
                    verification_workspace.emplace();
                const auto proof = mining::VeldHashWithDataset<true>(bytes, height, network,
                                                                     &*verification_workspace);
                if (!mining::g_veldhash_last_dataset_ok())
                    throw std::runtime_error("resource unavailable");
                std::cout << "OK " << HashToHex(proof) << ' '
                          << HashToHex(header.GetTemplateWorkIdentity());
                if (command == "inspect")
                    std::cout << ' '
                              << (proof < network.bytes               ? "block"
                                  : IsNmsProofInRange(proof, network) ? "near_miss"
                                                                      : "none");
                std::cout << std::endl;
            } else if (command == "scan") {
                if (!(input >> target_text >> start_text >> count_text) || (input >> extra))
                    throw std::runtime_error("schema");
                const auto target_bytes = Bytes(target_text, 32);
                Hash256 accounting;
                std::copy(target_bytes.begin(), target_bytes.end(), accounting.begin());
                Bytes(start_text, 8);
                const uint64_t start = Number(start_text, 16), count = Number(count_text, 10);
                if (count == 0 || count > 4096 || count - 1 > UINT64_MAX - start)
                    throw std::runtime_error("nonce range");
                if (!scan_workspace)
                    scan_workspace.emplace();

                // Accounting target never replaces the network target in VeldHash.
                for (uint64_t offset = 0; offset < count; ++offset) {
                    header.nonce = start + offset;
                    const auto proof =
                        mining::VeldHashWithDataset<mining::VELD_DEFAULT_LIGHT_DATASET>(
                            header.Serialize(), height, network, &*scan_workspace);
                    if (!mining::g_veldhash_last_dataset_ok())
                        throw std::runtime_error("resource unavailable");
                    // Preserve full solutions and genuine NMS proofs even
                    // when they do not meet the frozen accounting target.
                    if (proof < accounting || proof < network.bytes ||
                        IsNmsProofInRange(proof, network)) {
                        std::cout << "SHARE " << std::hex << std::setw(16) << std::setfill('0')
                                  << header.nonce << ' ' << HashToHex(proof) << std::dec
                                  << std::endl;
                    }
                }
                std::cout << "DONE " << count << std::endl;
            } else
                throw std::runtime_error("command");
        } catch (const std::exception& error) {
            std::cout << "ERROR " << error.what() << std::endl;
        }
    }
    // An oversized or unterminated frame terminates this private subprocess.
    // Never allocate an unbounded line before applying the framing limit.
    if (!std::cin.eof())
        return 2;
}
