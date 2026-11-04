#include "node/appchain_parent_restart.h"
#include "node/public_snapshot_bootstrap.h"
#include <fstream>
#include <iostream>
#include <sstream>

namespace fs = std::filesystem;
using namespace veld;
static unsigned checks = 0;
static void require(bool okay, const char* label) {
    if (!okay) throw std::runtime_error(label);
    ++checks; std::cout << "PASS " << label << std::endl;
}
static std::string read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("fixture input missing");
    return {std::istreambuf_iterator<char>(input), {}};
}
static void write(const fs::path& path, const std::string& value) {
    require(!fs::exists(path), "fresh fixture output");
    std::ofstream output(path, std::ios::binary); output << value;
    require(bool(output), "fixture output persisted");
}
static std::vector<Block> inputs(const fs::path& corpus, const fs::path& list) {
    std::istringstream lines(read(list)); std::vector<Block> result;
    for (uint64_t height = 0; height <= 10; ++height) {
        uint64_t supplied = UINT64_MAX; std::string hash;
        require(bool(lines >> supplied >> hash) && supplied == height &&
                    db::IsCanonicalHash256Text(hash), "ordered public corpus identity");
        const auto bytes = read(corpus / (hash + ".block"));
        const std::vector<uint8_t> raw(bytes.begin(), bytes.end()); Block block;
        require(Block::Deserialize(raw, 0, block) == raw.size(), "actual public block parsed");
        block.height = height;
        require(block.Serialize() == raw && HashToHex(block.GetHash()) == hash,
                "actual public block canonical identity");
        result.push_back(block);
    }
    std::string extra; require(!(lines >> extra), "exact eleven source blocks");
    require(result[0].GetHash() == CreateGenesisBlock().GetHash() &&
                HashToHex(result[1].GetHash()) == SNAPSHOT_LAUNCH_ANCHOR_HASH,
            "real compiled public genesis and launch anchor");
    return result;
}
static fs::path seed(const fs::path& root, const std::string& name,
                     const std::vector<Block>& blocks, unsigned last = 10) {
    const auto target = root / name; require(fs::create_directory(target), "fresh disposable parent state");
    std::string error;
    if (!ValidateOrCreatePublicNetworkIdentity(target.string(), &error))
        throw std::runtime_error("fresh fixture network identity: " + error);
    require(read(target / "network.identity") == CompiledPublicNetworkIdentityText(),
            "compiled public network identity written");
    write(target / "appchain-parent-reader", "public-parent-anchor-restart\n");
    db::VeldDB disk((target / "db").string()); uint64_t supply = 0;
    for (unsigned h = 0; h <= last; ++h) {
        const auto& block = blocks.at(h); const auto hash = block.GetHash();
        require(disk.WriteBlock(hash, block.Serialize()) &&
                    disk.WriteBlockIndex(HashToHex(hash), h, block.header.bits), "actual source block retained");
        for (const auto& out : block.transactions.front().outputs) supply += out.value;
        if (h == last) require(disk.WriteChainTip(hash, h, supply), "actual source tip retained");
    }
    return target;
}
template<class F> static void refused(F action, const char* label) {
    bool failed = false;
    try { action(); } catch (const std::exception&) { failed = true; }
    require(failed, label);
}
int main(int argc, char** argv) {
    try {
        require(argc == 4, "explicit disposable root corpus and block list");
        const auto root = fs::canonical(argv[1]), corpus = fs::canonical(argv[2]);
        require(read(root / ".qualification-only") == "public-parent-anchor-restart\n",
                "dedicated disposable marker");
        require(!APPCHAIN_BRIDGE_ENABLED, "public activation remains disabled");
        vendored_crypto::vendored_crypto_selftest();
        const auto blocks = inputs(corpus, fs::canonical(argv[3]));
        const auto anchor = HashToHex(blocks[8].GetHash()), tip = HashToHex(blocks[10].GetHash());
        const auto good = seed(root, "good", blocks); Hash256 digest{};
        {
            VeldNode strict(MainnetConfig(), good.string()); strict.SetStakingActivation(STAKING_ACTIVATION_SUPPLY);
            refused([&] { strict.ValidateStoredChainOnly(8, anchor, true); },
                    "unchanged strict snapshot method rejects an extension");
            require(strict.GetTCPServer() == nullptr && !strict.IsMiningReady(), "strict refusal starts no service or mining");
        }
        {
            const auto captured = ReadAppchainParentReplayTip(good, 8, anchor);
            require(captured.height == 10 && captured.tip_hash == tip, "exact actual durable descendant captured");
            VeldNode node(MainnetConfig(), good.string()); node.SetStakingActivation(STAKING_ACTIVATION_SUPPLY);
            ValidateAppchainParentFromAnchor(node, captured, 8, anchor);
            digest = node.ConsensusStateDigest();
            require(node.GetChain().Height() == 10 && node.GetChain().HasBlockAtHeight(8, anchor),
                    "full historical PoW replay retains original anchor and advanced tip");
            require(node.GetTCPServer() == nullptr && !node.IsMiningReady(), "anchor replay opens no service or mining");
        }
        {
            const auto captured = ReadAppchainParentReplayTip(good, 10, tip);
            VeldNode node(MainnetConfig(), good.string()); node.SetStakingActivation(STAKING_ACTIVATION_SUPPLY);
            ValidateAppchainParentFromAnchor(node, captured, 10, tip);
            require(node.ConsensusStateDigest() == digest, "exact-tip cold reopen preserves actual full state");
        }
        {
            const auto wrong = HashToHex(blocks[9].GetHash());
            const auto captured = ReadAppchainParentReplayTip(good, 8, wrong);
            VeldNode node(MainnetConfig(), good.string()); node.SetStakingActivation(STAKING_ACTIVATION_SUPPLY);
            refused([&] { ValidateAppchainParentFromAnchor(node, captured, 8, wrong); },
                    "fully replayed branch rejects wrong expected anchor at exact height");
            require(node.GetTCPServer() == nullptr && !node.IsMiningReady(), "wrong-anchor refusal exposes no service");
        }
        refused([&] { ReadAppchainParentReplayTip(good, 11, tip); }, "shorter durable chain cannot cover expected anchor");
        refused([&] { ReadAppchainParentReplayTip(good, 0, anchor); }, "genesis-only anchor refused");
        refused([&] { ReadAppchainParentReplayTip(good, 8, std::string(64, 'A')); }, "noncanonical expected anchor refused");
        const auto missing = seed(root, "missing-tip", blocks);
        { db::VeldDB disk((missing / "db").string()); require(disk.GetIndexDB().Delete("chain:tip"), "delete disposable authoritative tip"); }
        refused([&] { ReadAppchainParentReplayTip(missing, 8, anchor); }, "missing exact tip never falls back to indexes");
        const auto malformed = seed(root, "noncanonical-tip", blocks);
        { db::VeldDB disk((malformed / "db").string()); require(disk.GetIndexDB().Put("chain:height", "010"), "noncanonical disposable height"); }
        refused([&] { ReadAppchainParentReplayTip(malformed, 8, anchor); }, "noncanonical authoritative triplet refused");
        const auto changed = seed(root, "changed-tip", blocks);
        const auto captured = ReadAppchainParentReplayTip(changed, 8, anchor);
        { db::VeldDB disk((changed / "db").string()); require(disk.WriteChainTip(blocks[9].GetHash(), 9, 0), "fixture race changes captured identity"); }
        {
            VeldNode node(MainnetConfig(), changed.string()); node.SetStakingActivation(STAKING_ACTIVATION_SUPPLY);
            refused([&] { ValidateAppchainParentFromAnchor(node, captured, 8, anchor); },
                    "captured tip changed before replay is refused");
        }
        const auto corrupt = seed(root, "corrupt-body", blocks);
        { db::VeldDB disk((corrupt / "db").string()); require(disk.DeleteBlock(blocks[8].GetHash()), "delete actual expected-anchor body"); }
        {
            const auto corrupt_tip = ReadAppchainParentReplayTip(corrupt, 8, anchor);
            VeldNode node(MainnetConfig(), corrupt.string()); node.SetStakingActivation(STAKING_ACTIVATION_SUPPLY);
            refused([&] { ValidateAppchainParentFromAnchor(node, corrupt_tip, 8, anchor); },
                    "missing historical anchor body fails complete replay");
        }
        const auto wrong_tip = seed(root, "wrong-tip", blocks);
        { db::VeldDB disk((wrong_tip / "db").string()); require(disk.WriteChainTip(blocks[9].GetHash(), 10, 0), "wrong disposable tip hash"); }
        {
            const auto incorrect = ReadAppchainParentReplayTip(wrong_tip, 8, anchor);
            VeldNode node(MainnetConfig(), wrong_tip.string()); node.SetStakingActivation(STAKING_ACTIVATION_SUPPLY);
            refused([&] { ValidateAppchainParentFromAnchor(node, incorrect, 8, anchor); }, "corrupt durable tip cannot pass full replay");
        }
        write(root / "expected-anchor", "8 " + anchor + "\n");
        write(root / "expected-tip", "10 " + tip + "\n");
        write(root / "expected-digest", HashToHex(digest) + "\n");
        seed(root, "advance", blocks, 8);
        std::cout << "PASS_PUBLIC_PARENT_ANCHOR_RESTART checks=" << checks << std::endl;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL_PUBLIC_PARENT_ANCHOR_RESTART " << error.what() << std::endl;
        return 1;
    }
}
