// Private disk-backed admission/reorg fixture. The branch-context profile
// bypasses only proof-of-work hashing; scripts, modules and persistence run.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_ASERT_TESTCHAIN 1
#define VELD_TEST_BRANCH_CONTEXT 1
#define VELD_TEST_STAKE_OUTPOINT_BACKING 1
#define VELD_PROTOCOL_UPGRADE_TEST_HEIGHT 3360
#define VELD_ENABLE_SNAPSHOT_BOOTSTRAP 1
#include "node/node.h"
#include "network/operational_key_identity.h"
#include "wallet/wallet_crypto.h"
#include <future>
#include <iostream>

using namespace veld;
namespace fs = std::filesystem;
namespace sb = snapshot_bootstrap;
unsigned checks = 0;
void Need(bool ok, const char* message) {
    ++checks;
    if (!ok) throw std::runtime_error(message);
}
std::unique_ptr<VeldNode> Fresh(const fs::path& dir) {
    auto config = RegtestConfig(); config.port = 31087;
    auto node = std::make_unique<VeldNode>(config, dir.string());
    node->SetQuietBoot(true);
    node->TestPrepareDStateQualificationIngest();
    Need(node->TestIngestDStateQualificationFrame(CreateGenesisBlock().Serialize(), 0), "genesis refused");
    return node;
}
Block Build(VeldNode& node, const RealKeyPair& key, uint64_t nonce) {
    return node.TestBuildDStateQualificationBlock(node.GetChain().Height()+1,
        key.GetP2PKHScript(), "-", "-", node.GetChain().TipCopy().header.timestamp+180, nonce);
}
void Admit(VeldNode& node, const Block& block) {
    Need(node.TestIngestDStateQualificationFrame(block.Serialize(), block.height), "private block refused");
}
void KeyFile(const fs::path& path, const RealKeyPair& key) {
    auto plain = operational_key::FormatRecord(
        BytesToHex(key.private_key.data(), key.private_key.size()),
        BytesToHex(key.public_key.data(), key.public_key.size()), key.address);
    const auto encrypted = wallet_crypto::EncryptWallet(plain, "Disposable restart qualification 2026!");
    compat::SecureZero(plain.data(), plain.size());
    std::string error;
    Need(!encrypted.empty() && channel::secure_file::AtomicWrite(path.string(), encrypted, &error, true),
         "disposable encrypted identity could not be saved");
}
int main(int argc, char** argv) {
    try {
        Need(argc == 2, "new disposable directory required");
        const auto root = fs::absolute(argv[1]);
        Need(!fs::exists(root), "existing evidence must be preserved");
        auto key = GenerateKeyPair(true); key.address = PubKeyToAddress(key.public_key, false);
        auto a=Fresh(root/"a"), b=Fresh(root/"b"), c=Fresh(root/"c");
        for (uint64_t h=1; h<=24; ++h) {
            const auto block=Build(*a,key,h); Admit(*a,block); Admit(*b,block); Admit(*c,block);
        }
        const auto a25=Build(*a,key,100); Admit(*a,a25);
        a->SetBackgroundValidationOnly(true); a->SetBackgroundValidationTarget(50);
        a->TestCaptureBackgroundValidationTarget();
        auto marker=a->ReadValidatedBackgroundPrefix_();
        Need(marker && marker->first==25 && marker->second==HashToHex(a25.GetHash()), "initial prefix missing");
        Block b25; bool selected=false;
        for (uint64_t nonce=200; nonce<2200; ++nonce) {
            b25=Build(*b,key,nonce);
            if (HashToHex(b25.GetHash()) < HashToHex(a25.GetHash())) { selected=true; break; }
        }
        Need(selected,"same-height better-score branch not constructed");
        Admit(*b,b25); Admit(*a,b25);
        Need(a->GetChain().Height()==25 && a->GetChain().TipCopy().GetHash()==b25.GetHash(), "same-height reorg not executed");
        a->TestCaptureBackgroundValidationTarget(); marker=a->ReadValidatedBackgroundPrefix_();
        Need(marker && marker->first==25 && marker->second==HashToHex(b25.GetHash()), "same-height reorg left an old prefix");
        const auto c25=Build(*c,key,3000); Admit(*c,c25); Admit(*a,c25);
        const auto c26=Build(*c,key,3001); Admit(*c,c26); Admit(*a,c26);
        Need(a->GetChain().Height()==26 && a->GetChain().TipCopy().GetHash()==c26.GetHash(), "longer branch reorg not executed");
        a->TestCaptureBackgroundValidationTarget(); marker=a->ReadValidatedBackgroundPrefix_();
        Need(marker && marker->first==26 && marker->second==HashToHex(c26.GetHash()), "reorg below save cadence retained an old prefix");
        // Reproduce a process stopping after chain commit but before the
        // progress callback can replace the old, otherwise canonical marker.
        Need(a->WriteValidatedBackgroundPrefix_(25,a25.GetHash()), "stale cache interruption fixture failed");
        a.reset(); b.reset(); c.reset();
        auto config=RegtestConfig(); config.port=31087;
        {
            VeldNode resumed(config,(root/"a").string()); resumed.SetQuietBoot(true);
            resumed.SetFullIbd(true); resumed.SetBackgroundValidationOnly(true);
            resumed.SetBackgroundValidationTarget(50); resumed.Start();
            Need(resumed.GetChain().Height()==26 && resumed.GetChain().TipCopy().GetHash()==c26.GetHash(), "background restart rejected canonical prefix");
            resumed.Stop();
        }
        VeldNode node(config,(root/"a").string()); node.SetQuietBoot(true); node.SetFullIbd(true); node.Start();
        Need(node.ChainFullyValidated(), "receipt fixture lacks fully replayed state");
        KeyFile(root/"a/miner.key",key);
        const auto stale_height=node.GetChain().Height();
        const auto newer=Build(node,key,4000); Admit(node,newer);
        std::string error; sb::FullIbdReceipt receipt,verified;
        Need(sb::WriteFullIbdReceipt((root/"a").string(),key,stale_height,HashToHex(newer.GetHash()),&error),
             "old separate-read counterexample was not represented");
        Need(sb::VerifyFullIbdReceipt((root/"a").string(),key.public_key,verified,&error) &&
             HashToHex(node.GetChain().GetBlock(verified.height).GetHash())!=verified.tip_hash,
             "old receipt tuple counterexample missing");
        auto payout=GenerateKeyPair(true); key.address=payout.address;
        Need(node.PersistFullIbdReceiptAtTip(key,false,receipt,&error), "current canonical receipt failed");
        Need(receipt.height==newer.height && receipt.tip_hash==HashToHex(newer.GetHash()) &&
             receipt.miner_address==PubKeyToAddress(key.public_key,false), "receipt used stale height or payout identity");
        for (uint64_t i=0;i<12;++i) {
            const auto block=Build(node,key,5000+i);
            auto writer=std::async(std::launch::async,[&]{return node.PersistFullIbdReceiptAtTip(key,false,receipt,&error);});
            Admit(node,block); Need(writer.get(), "concurrent receipt publication failed");
            Need(sb::VerifyFullIbdReceipt((root/"a").string(),key.public_key,verified,&error) &&
                 HashToHex(node.GetChain().GetBlock(verified.height).GetHash())==verified.tip_hash,
                 "concurrent admission split the signed tuple");
        }
        KeyFile(root/"a"/sb::FLEET_KEY_FILENAME,key);
        Need(channel::secure_file::AtomicWriteText((root/"a/network.identity").string(),
             CompiledPublicNetworkIdentityText(),&error,true), "private profile identity fixture failed");
        Need(node.PersistFullIbdReceiptAtTip(key,true,receipt,&error), "fleet canonical receipt failed");
        Need(sb::VerifyFleetIbdReceipt((root/"a").string(),key.public_key,verified,&error) &&
             HashToHex(node.GetChain().GetBlock(verified.height).GetHash())==verified.tip_hash,
             "fleet receipt tuple does not authenticate");
        node.Stop();
        std::cout<<"PASS restart consistency checks="<<checks<<" private_branch_context=1\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr<<"FAIL "<<error.what()<<'\n'; return 1;
    }
}
