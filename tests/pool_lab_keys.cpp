// Disposable keys only; this executable is never a distributed service.
#if !defined(VELD_TEST_CHAIN_BUILD) || defined(VELD_PUBLIC_RELEASE)
#error "isolated lab only"
#endif
#include "wallet/wallet.h"
#include "wallet/secure_channel_file.h"
#include <filesystem>
#include <iostream>

int main(int argc, char** argv) {
    using namespace veld;
    if (argc != 2 || std::filesystem::exists(argv[1])) return 2;
    std::string error;
    if (!channel::secure_file::EnsurePrivateDirectory(argv[1], &error)) return 2;
    for (const std::string role : {"pool", "fees", "worker-a", "worker-b"}) {
        const auto key = GenerateKeyPair(false);
        const std::string bytes(reinterpret_cast<const char*>(key.private_key.data()), key.private_key.size());
        const auto path = std::filesystem::path(argv[1])/(role + ".seed");
        if (!channel::secure_file::AtomicWriteText(path.string(), bytes, &error, true)) return 2;
        std::cout << role << ' ' << key.address << ' ' << BytesToHex(key.GetP2PKHScript()) << '\n';
    }
}
