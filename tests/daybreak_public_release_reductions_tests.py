#!/usr/bin/env python3
"""Source/profile assertions for public-release convenience-feature reductions."""

import os
from pathlib import Path
import socket
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
checks = 0


def check(condition: bool, message: str) -> None:
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1


constants = (ROOT / "include/core/constants.h").read_text(encoding="utf-8")
rpc = (ROOT / "include/network/rpc.h").read_text(encoding="utf-8")
desktop = (ROOT / "src/veld-desktop.cpp").read_text(encoding="utf-8")
ui = (ROOT / "include/network/ui_desktop.h").read_text(encoding="utf-8")
wallet_cli = (ROOT / "include/wallet/cli.h").read_text(encoding="utf-8")
node_main = (ROOT / "src/veld-node.cpp").read_text(encoding="utf-8")
node = (ROOT / "include/node/node.h").read_text(encoding="utf-8")
nat = (ROOT / "include/network/nat_traversal.h").read_text(encoding="utf-8")
linux = (ROOT / "build/mainnet-v2-linux.sh").read_text(encoding="utf-8")
windows = (ROOT / "build/mainnet-v2-windows.sh").read_text(encoding="utf-8")
launcher = (ROOT / "pkg/Start Mining.bat").read_text(encoding="utf-8")
clearnet_launcher = (ROOT / "pkg/Start Mining (Clearnet).bat").read_text(
    encoding="utf-8")
portal = (ROOT / "src/veld-miner-portal.py").read_text(encoding="utf-8")
gui = (ROOT / "src/veld-node-gui.cpp").read_text(encoding="utf-8")
explorer = (ROOT / "include/network/explorer.h").read_text(encoding="utf-8")
address_history = (ROOT / "include/core/address_history.h").read_text(
    encoding="utf-8")

check("VELD_ENABLE_DIAGNOSTIC_TX_HISTORY" in constants,
      "missing public/history profile interlock")
check("VELD_ENABLE_SNAPSHOT_BOOTSTRAP" in constants,
      "missing snapshot storage-profile interlock")
check("VELD_ENABLE_UPNP" in constants or "VELD_ENABLE_UPNP" in nat,
      "missing public/UPnP profile interlock")
check('methods_["gettxhistory"]' not in rpc and "gettxhistory" not in rpc,
      "legacy gettxhistory scanner/source remains in the RPC registry")
check('methods_["getearnings"]' not in rpc and "getearnings" not in rpc,
      "unbounded local earnings/history scanner remains in the RPC registry")

allowlist = desktop[desktop.index("REMOTE_ALLOWED_METHODS"):]
allowlist = allowlist[:allowlist.index("};")]
check('"gettxhistory"' not in allowlist,
      "hosted/public desktop allow-list still exposes gettxhistory")
check('methods_["getaddresshistory"]' in rpc,
      "bounded indexed address-history RPC is missing")
check('"getaddresshistory"' in allowlist,
      "hosted desktop does not expose bounded indexed history")
check("rpc('gettxhistory'" not in ui and 'rpc("gettxhistory"' not in ui,
      "desktop still contains a gettxhistory RPC call")
check("getearnings" not in desktop and "getearnings" not in ui and
      "getearnings" not in wallet_cli,
      "desktop or wallet still retains the unbounded earnings/history method")
history_helper = ui[ui.index("function publicAddressHistory(address, limit)"):
                    ui.index("function rpc(method, params)")]
check("rpc('getaddresshistory'" in history_helper and
      "Math.min(50" in history_helper and "gettxhistory" not in history_helper and
      "setTimeout" not in history_helper and "setInterval" not in history_helper,
      "desktop history helper is not bound to the capped indexed RPC")
earnings_helper = ui[ui.index("function loadEarningsPage(addr) {"):
                     ui.index("function loadPayoutEndorsements() {")]
check("publicAddressHistory(addr, 50)" in earnings_helper and
      "gettxhistory" not in earnings_helper and
      "setTimeout" not in earnings_helper and "setInterval" not in earnings_helper,
      "desktop earnings view is not using bounded indexed history")
check('method == "gettxhistory"' not in wallet_cli and
      'method\":\"gettxhistory' not in wallet_cli,
      "wallet CLI still tells users to call unavailable history")
check("txhistory" not in explorer.lower(),
      "legacy explorer txhistory route/scanner remains in source")
check('resource == "addresshistory"' in explorer and
      'limit > 50' in explorer,
      "explorer indexed-history route is missing its hard page cap")
check("MAX_PAGE_SIZE = 50" in address_history and
      "IterateFrom(prefix, cursor" in address_history and
      "block_loader" not in address_history[
          address_history.index("inline std::optional<Page> ReadPage"):],
      "address-history query can exceed its row cap or load block bodies")

check("PublicSnapshotDatadirRefusal" in node,
      "legacy public snapshot-marker boundary disappeared")
check(".snapshot-fast-start-revoked" in node,
      "public startup omits the snapshot revocation marker")
check("--snapshot-bootstrap" in node_main and
      "--no-snapshot" in node_main and "--full-ibd" in node_main,
      "public CLI does not expose the bounded snapshot/full-IBD choice")
check("#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)" in rpc and
      'methods_["dumpsnapshot"]' in rpc,
      "snapshot RPC is not compile-profile gated")
check("MaybePreferSnapshotAtStartup" not in node_main and
      "TryAutoSnapshotBootstrap" not in node,
      "retired mirror-driven snapshot entrypoint returned")
check('#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)\n#include "snapshot_manifest.h"' in node and
      "SetBackgroundValidationOnly" in node and
      "SnapshotValidationBase" in node,
      "generic snapshot implementation is not behind its explicit profile")
check("#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)\n    background_validation_base =" in node_main and
      "#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)\n        if (node.SnapshotBackgroundVerificationFailed())" in node_main,
      "snapshot background-validation launcher/runtime is not profile-gated")
snapshot_impl = node[node.index("void ValidateStoredChainOnly"):]
snapshot_impl_prefix = node[:node.index("void ValidateStoredChainOnly")]
check("#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)" in
      snapshot_impl_prefix[-700:],
      "snapshot validate/download/promote entrypoints remain in public preprocessing")
check("--bootstrap-only" not in launcher and
      "--snapshot-bootstrap" in launcher,
      "shipped Windows launcher does not select signed snapshot bootstrap")
check('data-mode="snapshot"' in portal and
      'payload["mode"] not in {' in portal,
      "portal does not offer the bounded snapshot/full synchronization modes")
check('L"Snapshot bootstrap: available' in gui and
      'L" --snapshot-bootstrap"' in gui,
      "GUI does not expose signed snapshot bootstrap")
check("A snapshot is an availability optimization" in explorer and
      "independent genesis IBD" in explorer,
      "Explorer rules omit the public snapshot trust boundary")
check("defined(VELD_PUBLIC_TESTNET) || defined(VELD_PUBLIC_RELEASE)" in node_main,
      "public deep-gap watcher can still persist a snapshot recovery request")
start_body = node[node.index("    void Start() {"):node.index("    void Stop() {")]
check(start_body.index("ReadIndependentValidationRequirement_") <
      start_body.index("tcp_server_ = std::make_unique"),
      "snapshot validation requirement is not loaded before service construction")

check("#if defined(VELD_ENABLE_UPNP)" in nat,
      "UPnP implementation is not compile-profile gated")
check("TryUpnp(localip" in nat and
      nat.index("#if defined(VELD_ENABLE_UPNP)", nat.index("void RunLoop")) <
      nat.index("TryUpnp(localip", nat.index("void RunLoop")),
      "worker can still call UPnP without the opt-in profile")
check('arg == "--upnp"' in node_main and
      '<< " is not supported in the "' in node_main and
      "Veld public release" in node_main,
      "public CLI does not explicitly reject --upnp")
check("NAT-PMP/PCP" in node_main and "NAT-PMP/PCP/UPnP" not in node_main,
      "public help still advertises UPnP")
check("UPnP" not in clearnet_launcher and "NAT-PMP/PCP" in clearnet_launcher,
      "clearnet launcher still advertises public UPnP")
check('arg.find("snapshot")' in node_main and
      'arg.rfind("--upnp=", 0)' in node_main,
      "public pre-scan does not reject snapshot/UPnP assignment aliases")
check("veld-node: unknown option '" in node_main,
      "node parser still silently ignores unknown options")

for controller, text in (("linux", linux), ("windows", windows)):
    for forbidden in (
        "-DVELD_ENABLE_DIAGNOSTIC_TX_HISTORY",
        "-DVELD_ENABLE_UPNP",
    ):
        check(forbidden not in text,
              f"{controller} public controller enables forbidden feature {forbidden}")
    check("node)" in text and "-DVELD_ENABLE_SNAPSHOT_BOOTSTRAP" in text,
          f"{controller} node build omits snapshot bootstrap")


binary_value = os.environ.get("VELD_PUBLIC_NODE_UNDER_TEST", "")
if binary_value:
    binary = Path(binary_value)
    check(binary.is_file(), "VELD_PUBLIC_NODE_UNDER_TEST is not a file")

    def run_node(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(binary), *arguments], cwd=ROOT, text=True,
            capture_output=True, timeout=20,
        )

    rejected = (
        ("--snapshot", "--help"),
        ("--snapshot=fixture", "--help"),
        ("--snapshot-anything", "--help"),
        ("--foo-snapshot-alias=fixture", "--help"),
        ("--snapshot-url=https://127.0.0.1/archive", "--help"),
        ("--snapshot-path", "fixture", "--help"),
        ("--snapshot-path=fixture", "--help"),
        ("--prefer-snapshot=1", "--help"),
        ("--bootstrap-only", "--help"),
        ("--bootstrap-only=1", "--help"),
        ("--verify-snapshot=fixture", "--help"),
        ("--upnp", "--help"),
        ("--upnp=1", "--help"),
        ("--upnp-enabled", "--help"),
        ("--upnp-mode=igd", "--help"),
        ("--definitely-unknown", "--help"),
        ("--help", "--definitely-unknown"),
    )
    for arguments in rejected:
        result = run_node(*arguments)
        check(result.returncode == 2,
              f"public node accepted {arguments}: rc={result.returncode} "
              f"stdout={result.stdout!r} stderr={result.stderr!r}")
    help_result = run_node("--help")
    check(help_result.returncode == 0 and "Usage: veld-node" in help_result.stdout,
          "ordinary public help probe failed")
    deployment = run_node("--deployment-info")
    check(deployment.returncode == 0 and
          '"profile_id":"veld-public-mainnet-v2"' in deployment.stdout and
          '"snapshot_bootstrap_compiled":true' in deployment.stdout,
          "ordinary public deployment-info probe failed")

    for control in ("--snapshot-bootstrap", "--no-snapshot", "--full-ibd"):
        controlled = run_node(control, "--deployment-info")
        check(controlled.returncode == 0 and
              '"snapshot_bootstrap_compiled":true' in controlled.stdout,
              f"public node rejected exact synchronization control {control}")

    # Exercise the launcher's retained ordinary-validation selector through
    # the real parser without opening listeners: offline reindex is expected
    # to stop at the deliberately empty fixture database, after accepting
    # --full-ibd and binding the public network identity.
    with tempfile.TemporaryDirectory(prefix="veld-public-full-ibd-") as datadir:
        full_ibd = run_node("--full-ibd", "--reindex-canonical",
                            "--datadir", datadir)
        check(full_ibd.returncode == 1 and
              "offline reindex requires an existing" in full_ibd.stderr and
              "unknown option" not in full_ibd.stderr and
              "snapshot bootstrap" not in full_ibd.stderr,
              "ordinary --full-ibd launcher path was rejected by the parser")
        check((Path(datadir) / "network.identity").is_file(),
              "ordinary --full-ibd path did not bind the public datadir identity")

    def unused_loopback_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            return int(listener.getsockname()[1])

    def port_is_closed(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(0.25)
            return client.connect_ex(("127.0.0.1", port)) != 0

print(f"PASS daybreak_public_release_reductions_tests checks={checks}")
