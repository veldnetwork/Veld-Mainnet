#include "wallet/wallet.h"
#include <iostream>
#include <stdexcept>

int main() {
    size_t checked = 0;
    auto require = [&](bool condition) {
        ++checked;
        if (!condition) throw std::runtime_error("address codec contract failed");
    };
    for (uint8_t version : {0x46, 0x6f}) {
        for (uint8_t fill : {0, 1, 127, 255}) {
            const std::vector<uint8_t> payload(20, fill);
            const auto address = veld::Base58CheckEncode(version, payload);
            uint8_t decoded_version = 0;
            std::vector<uint8_t> decoded;
            require(veld::Base58CheckDecode(address, decoded_version, decoded));
            require(decoded_version == version && decoded == payload);
            require(veld::Base58Encode(veld::Base58Decode(address)) == address);
        }
    }
    for (unsigned byte = 128; byte < 256; ++byte)
        require(veld::Base58Decode(std::string(1, static_cast<char>(byte))).empty());
    for (const std::string text : {"0", "O", "I", "l", " ", "\n"})
        require(veld::Base58Decode(text).empty());
    std::cout << "PASS " << checked << " wallet address codec assertions\n";
}
