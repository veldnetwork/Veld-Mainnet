#!/usr/bin/env python3
"""Focused regression checks for Windows snapshot status and update continuity."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NODE = (ROOT / "src/veld-node.cpp").read_text(encoding="utf-8")
GUI = (ROOT / "src/veld-node-gui.cpp").read_text(encoding="utf-8")
MODEL = (ROOT / "include/gui/node_gui_model.h").read_text(encoding="utf-8")
RECEIPT = (ROOT / "include/node/full_ibd_receipt.h").read_text(encoding="utf-8")
UPDATER = (ROOT / "pkg/veld-update.ps1").read_text(encoding="utf-8")

checks = 0


def check(condition: bool, message: str) -> None:
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)


check('\\"snapshot_bootstrap_compiled\\":' in NODE,
      "node status must report whether snapshot support is compiled")
check('\\"snapshot_fast_start_eligible\\":' in NODE,
      "node status must report authenticated restart eligibility")
check('\\"full_ibd\\":' in NODE,
      "node status must report the active synchronization mode")
check("node.SnapshotFastStartEligible()" in NODE,
      "eligibility must come from the running node, not a GUI guess")
check("node.IsFullIbd()" in NODE,
      "active full-IBD state must come from the running node")

for field in (
    "snapshot_bootstrap_compiled",
    "snapshot_fast_start_eligible",
    "full_ibd",
):
    check(f'root.Get("{field}")' in MODEL,
          f"GUI status parser does not require {field}")
check('<< ",\\"snapshot_eligible\\":false"' not in GUI,
      "GUI must not hardcode snapshot eligibility to false")
check('<< ",\\"full_ibd\\":true"' not in GUI,
      "GUI must not hardcode full IBD to true")
check("next.mining.snapshot_fast_start_eligible" in GUI,
      "live eligibility must be copied from authenticated node status")
check("next.mining.snapshot_bootstrap_compiled" in GUI,
      "GUI must distinguish compiled support from runtime eligibility")
check("live.mining.full_ibd" in GUI,
      "remote status must use the running node's actual mode")
check('L"Snapshot",\n                      L"Disabled"' not in GUI,
      "overview must not hardcode snapshot status to disabled")
overview_start = GUI.index("const bool snapshot_selected")
overview_end = GUI.index("void DrawCheck", overview_start)
overview = GUI[overview_start:overview_end]
check('live.snapshot_eligible' in overview and 'L"Eligible"' in overview,
      "overview must display authenticated snapshot eligibility")
check('snapshot_selected ? L"Selected" : L"Full IBD"' in GUI,
      "stopped overview must display the persisted synchronization choice")

check('line == "sync=snapshot"' in GUI,
      "snapshot selection must reload from persistent GUI settings")
check('"sync=" << (full_ibd_choice_ ? "full" : "snapshot")' in GUI,
      "snapshot selection must be saved persistently")
check('L" --snapshot-bootstrap"' in GUI,
      "snapshot selection must reach the node command line")
check('return std::filesystem::path(raw) / L"Veld" / L"Node";' in GUI,
      "GUI settings must live outside the replaceable client directory")

check("$rel.StartsWith('veld-data/'" in UPDATER,
      "signed updater must exclude the datadir from installed-code inventory")
check("$OldEntries.Keys" in UPDATER and "Apply-VerifiedPackage" in UPDATER,
      "updater must only remove files from the prior signed-code manifest")
check("CLIENT_VERSION" not in RECEIPT,
      "snapshot eligibility must survive maintenance client-version updates")
check('"\\ndeployment_profile=" + DEPLOYMENT_PROFILE_ID' in RECEIPT,
      "snapshot receipt must remain bound to the deployment profile")
check('"\\ngenesis=" + GENESIS_HASH' in RECEIPT,
      "snapshot receipt must remain bound to genesis")

print(f"PASS windows_snapshot_update_eligibility_tests checks={checks}")
