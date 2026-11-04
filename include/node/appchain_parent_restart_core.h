#pragma once
#include "node/appchain_parent_feed_core.h"

namespace veld {

// This private parent process keeps its reviewed bootstrap anchor fixed while
// its own fully validated durable tip advances. The returned tip is an input
// to mandatory replay, never a cached validation verdict.
inline db::VeldDB::ChainTip ReadAppchainParentReplayTip(
    const std::filesystem::path& directory, uint64_t anchor_height,
    const std::string& anchor_hash) {
    app::need(anchor_height > 0 && anchor_height < UINT64_MAX &&
                  db::IsCanonicalHash256Text(anchor_hash),
              "invalid reviewed public parent anchor");
    app::need(!snapshot_recovery::Pending(directory),
              "public parent replay is disabled during snapshot recovery");
    const auto base = directory / "db";
    for (const auto& path : {directory, base, base / "blocks", base / "utxo", base / "index"}) {
        app::need(std::filesystem::is_directory(path) &&
                      !std::filesystem::is_symlink(path) &&
                      std::filesystem::canonical(path) == path,
                  "existing physical public parent database required");
    }
    // Use the authoritative triplet parser and normal durable recovery. All
    // existing stores are required, so this cannot create an empty chain.
    // The temporary DB and every LevelDB lock close before VeldNode opens it.
    db::VeldDB stored(base.string());
    const auto tip = stored.ReadChainTipExact();
    app::need(tip && tip->height >= anchor_height && tip->height < UINT64_MAX,
              "exact durable public parent tip must cover reviewed anchor");
    return *tip;
}

inline void ValidateAppchainParentFromAnchor(
    VeldNode& node, const db::VeldDB::ChainTip& captured_tip,
    uint64_t anchor_height, const std::string& anchor_hash) {
    app::need(anchor_height > 0 && anchor_height <= captured_tip.height &&
                  captured_tip.height < UINT64_MAX &&
                  db::IsCanonicalHash256Text(anchor_hash) &&
                  db::IsCanonicalHash256Text(captured_tip.tip_hash),
              "exact public parent replay inputs required");
    // The unchanged snapshot validator checks the exact captured disk tip,
    // recovery state, security floor and every historical consensus rule.
    // It calls PrepareAnchorSecurityBootstrap_ and WireDB exactly once here.
    node.ValidateStoredChainOnly(captured_tip.height, captured_tip.tip_hash, true);
    app::need(node.ChainFullyValidated() && !node.FailStopRequired() &&
                  node.GetChain().Height() == captured_tip.height &&
                  HashToHex(node.GetChain().TipCopy().GetHash()) == captured_tip.tip_hash &&
                  node.GetChain().HasBlockAtHeight(anchor_height, anchor_hash),
              "fully validated public parent must retain reviewed canonical anchor");
}

} // namespace veld
