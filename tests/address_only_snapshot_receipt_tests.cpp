#include "../include/node/address_only_ibd_receipt.h"
#include "../include/node/snapshot_recovery.h"
#include <iostream>

using namespace veld;
namespace fs = std::filesystem;
namespace sb = snapshot_bootstrap;
namespace sr = snapshot_recovery;

static unsigned checks = 0;
static void Check(bool passed, const char* label) {
    if (!passed) throw std::runtime_error(label);
    ++checks;
}
static void Write(const fs::path& path, const std::string& body) {
    std::string error;
    Check(channel::secure_file::AtomicWriteText(path.string(), body, &error, true),
          "private fixture write");
}
int main(int argc, char** argv) try {
    Check(argc == 2, "fresh private fixture required");
    const fs::path root(argv[1]);
    Check(!fs::exists(root), "fixture must be new");
    std::string error;
    Check(channel::secure_file::EnsurePrivateDirectory(root.string(), &error),
          "private fixture directory");
    compat::InitNetwork();
    const auto signer = GenerateKeyPair(false);
    const auto payout = GenerateKeyPair(false).address;
    const auto other = GenerateKeyPair(false).address;
    Write(root / "network.identity", "private-mainnet-profile\n");
    Write(root / sb::ADDRESS_KEY_FILENAME, "encrypted-test-validation-identity\n");
    const std::string tip(64, 'a');
    Check(sb::WriteAddressIbdReceipt(root.string(), signer, payout, 101,
                                     tip, &error), "address receipt writes");
    sb::FullIbdReceipt receipt;
    Check(sb::VerifyAddressIbdReceipt(root.string(), signer.public_key, payout,
                                      receipt, &error), "address receipt verifies");
    Check(receipt.height == 101 && receipt.tip_hash == tip &&
          receipt.miner_address == payout, "receipt identity and tip exact");
    Check(!sb::VerifyAddressIbdReceipt(root.string(), signer.public_key, other,
                                       receipt, &error), "payout switch refuses reuse");
    Check(!sb::VerifyAddressIbdReceipt(root.string(),
                                       GenerateKeyPair(false).public_key, payout,
                                       receipt, &error), "other validation key refused");
    const auto original = sr::Read(root / sb::ADDRESS_RECEIPT_FILENAME, 24 * 1024);
    Check(bool(original), "original signed receipt retained");
    Write(root / "network.identity", "different-network-identity\n");
    Check(!sb::VerifyAddressIbdReceipt(root.string(), signer.public_key, payout,
                                       receipt, &error), "other network identity refused");
    Write(root / "network.identity", "private-mainnet-profile\n");
    std::string tampered(original->begin(), original->end());
    const auto value = tampered.find("validated_height=101\n");
    Check(value != std::string::npos, "canonical height field found");
    tampered.replace(value, std::string("validated_height=101\n").size(),
                     "validated_height=102\n");
    Write(root / sb::ADDRESS_RECEIPT_FILENAME, tampered);
    Check(!sb::VerifyAddressIbdReceipt(root.string(), signer.public_key, payout,
                                       receipt, &error), "tampered signed height refused");
    Write(root / sb::ADDRESS_RECEIPT_FILENAME,
          std::string(original->begin(), original->end()));
    Check(sb::VerifyAddressIbdReceipt(root.string(), signer.public_key, payout,
                                      receipt, &error), "restored exact receipt verifies");
    const auto testnet_signer = GenerateKeyPair(true);
    const auto testnet_payout = GenerateKeyPair(true).address;
    Check(sb::WriteAddressIbdReceipt(root.string(), testnet_signer,
                                     testnet_payout, 102, tip, &error, true),
          "testnet address receipt writes");
    Check(sb::VerifyAddressIbdReceipt(root.string(), testnet_signer.public_key,
                                      testnet_payout, receipt, &error, false, true),
          "testnet address receipt verifies");
    Check(!sb::VerifyAddressIbdReceipt(root.string(), testnet_signer.public_key,
                                       testnet_payout, receipt, &error),
          "testnet receipt refused in mainnet role");
    Write(root / sb::ADDRESS_RECEIPT_FILENAME,
          std::string(original->begin(), original->end()));
    const std::string journal =
        "schema=1\nid=00112233445566778899aabb\nphase=ibd\npresent=0\n"
        "receipt=\nreceipt_hash=\n";
    sr::Write(root / sr::JOURNAL, journal);
    sr::Complete(root, sb::ADDRESS_RECEIPT_FILENAME);
    Check(!fs::exists(root / sr::JOURNAL), "address receipt retires recovery journal");
    Check(fs::exists(root / sb::ADDRESS_RECEIPT_FILENAME),
          "recovery keeps signed receipt");
    std::cout << "PASS_ADDRESS_ONLY_SNAPSHOT_RECEIPT " << checks << "\n";
} catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
}
