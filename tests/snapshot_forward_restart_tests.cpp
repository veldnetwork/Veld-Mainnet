// Offline lifecycle regression using two authenticated public snapshots.
// Appends two ordinary historical blocks, closes the database, then resumes
// unfinished independent validation without starting any network service.
#include "node/node.h"
#include "node/public_snapshot_bootstrap.h"
#include <fstream>
#include <iostream>
#include <sstream>

namespace fs = std::filesystem;
namespace sb = veld::snapshot_bootstrap;
using namespace veld;

void Require(bool ok, const char* label) {
    if (!ok) throw std::runtime_error(label);
}
std::string Read(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    Require(bool(f), "fixture file missing");
    return std::string(std::istreambuf_iterator<char>(f), {});
}
void Write(const fs::path& p, const std::string& text) {
    Require(!fs::exists(p), "fixture result already exists");
    std::ofstream f(p, std::ios::binary); f << text;
    Require(bool(f), "fixture result write failed");
}
SnapshotManifest Authenticate(const fs::path& root, const std::string& kind) {
    auto bytes = sb::ReadBoundedPlainFile(root / (kind + ".manifest"), 65536);
    auto sig = sb::ReadBoundedPlainFile(root / (kind + ".manifest.sig"), 65536);
    SnapshotManifest manifest; std::string error;
    Require(bytes && sig && VerifySignedSnapshotManifestPinned(*bytes, *sig, manifest),
            "snapshot manifest signature refused");
    Require(sb::ManifestMatchesCompiledPublicChain(manifest, &error),
            "snapshot profile mismatch");
    auto digest = sb::Sha256File(root / manifest.archive_file, sb::PUBLIC_SNAPSHOT_MAX_ARCHIVE_BYTES);
    Require(digest && *digest == manifest.sha256, "snapshot archive digest mismatch");
    return manifest;
}

int main(int argc, char** argv) {
    try {
        Require(argc == 4, "expected mode, scratch directory, authenticated inputs");
        const std::string mode = argv[1];
        Require(mode == "prepare" || mode == "resume" || mode == "finish", "unknown fixture mode");
        const auto root = fs::canonical(argv[2]);
        Require(fs::is_regular_file(root / ".qualification-only"), "scratch marker required");
        const auto inputs = fs::canonical(argv[3]);
        vendored_crypto::vendored_crypto_selftest();
        const auto base = Authenticate(inputs, "base");
        const auto donor = Authenticate(inputs, "donor");
        Require(donor.height > base.height + 2, "donor lacks ordinary successor blocks");
        const uint64_t target = base.height + 2;
        std::vector<Block> successors;
        std::string target_hash;
        {
            db::VeldDB disk((root / "donor/db").string());
            for (uint64_t h = base.height + 1; h <= target; ++h) {
                auto hash = disk.GetHashAtHeight(h);
                Require(hash.has_value(), "successor index missing");
                auto data = disk.ReadBlock(HexToHash(*hash));
                Require(data.has_value(), "successor body missing");
                Block b; b.height = h;
                Require(Block::Deserialize(*data, 0, b) == data->size(), "successor body not canonical");
                b.height = h;
                Require(b.Serialize() == *data && HashToHex(b.GetHash()) == *hash, "successor identity mismatch");
                successors.push_back(std::move(b)); target_hash = *hash;
            }
        }
        const auto data = root / "pending";
        const auto obligation = data / ".background-chainstate-required";
        const auto handoff = data / "db/.snapshot-consensus-replay-required";
        if (mode == "prepare") {
            std::string error;
            Require(sb::InitializeAuthenticatedSnapshotIdentity(data, &error), "snapshot identity failed");
            VeldNode node(MainnetConfig(), data.string());
            node.SetStakingActivation(STAKING_ACTIVATION_SUPPLY);
            node.PrepareSnapshotCandidateReplay(base.height, base.tip_hash);
            node.ValidateStoredChainOnly(base.height, base.tip_hash, false);
            Require(!node.ChainFullyValidated() && !node.IsMiningReady(), "snapshot work was admitted early");
            Write(root / "expected-obligation", Read(obligation));
            Write(root / "expected-handoff", Read(handoff));
            for (const auto& block : successors) {
                Require(node.GetChainMut().AddBlockDirect(block, false, false, false,
                    mining::PowAdmissionContext::Internal()), "ordinary successor rejected");
            }
            Require(node.GetChain().Height() == target && !node.FailStopRequired(), "foreground advance failed");
            Write(root / "expected-tip-digest", HashToHex(node.ConsensusStateDigest()));
        } else {
            VeldNode node(MainnetConfig(), data.string());
            node.SetStakingActivation(STAKING_ACTIVATION_SUPPLY);
            node.SetSnapshotFastStartEligible(true, base.height, base.tip_hash);
            node.ValidateStoredChainOnly(target, target_hash, false);
            Require(!node.ChainFullyValidated() && !node.IsMiningReady(), "restart admitted unfinished work");
            Require(node.GetTCPServer() == nullptr, "offline fixture opened network services");
            auto requirement = node.IndependentValidationBase();
            Require(requirement && requirement->height == base.height &&
                HashToHex(requirement->tip_hash) == base.tip_hash, "restart moved the background target");
            Require(Read(obligation) == Read(root / "expected-obligation"), "restart rewrote the background commitment");
            Require(Read(handoff) == Read(root / "expected-handoff"), "restart changed the signed handoff");
            Require(HashToHex(node.ConsensusStateDigest()) == Read(root / "expected-tip-digest"), "restart changed the foreground state");
            if (mode == "finish") {
                const auto independent_data = root / "independent";
                std::string error;
                Require(sb::InitializeAuthenticatedSnapshotIdentity(independent_data, &error), "independent identity failed");
                VeldNode independent(MainnetConfig(), independent_data.string());
                independent.SetStakingActivation(STAKING_ACTIVATION_SUPPLY);
                independent.ValidateStoredChainOnly(base.height, base.tip_hash, true);
                Require(independent.ChainFullyValidated(), "independent full verification incomplete");
                VeldNode::BackgroundValidationObservation observation;
                observation.height = base.height; observation.tip_hash = HexToHash(base.tip_hash);
                observation.state_digest = independent.ConsensusStateDigest(); observation.reached = true;
                Require(node.FinalizeIndependentBackgroundValidation(observation, &error), "independent comparison failed");
                Require(node.ChainFullyValidated() && !node.IndependentValidationBase(), "independent completion not promoted");
                Require(!fs::exists(obligation) && !fs::exists(handoff), "completed snapshot obligations remain");
                Require(node.GetChain().Height() == target, "completion changed foreground height");
            }
        }
        std::cout << "PASS SNAPSHOT_FORWARD_RESTART mode=" << mode << " base=" << base.height
                  << " foreground=" << target << " network_services=0" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL SNAPSHOT_FORWARD_RESTART " << e.what() << std::endl;
        return 1;
    }
}
