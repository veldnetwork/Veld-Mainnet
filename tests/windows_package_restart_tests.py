"""Real signed Commit, GUI relaunch and node restart in a disposable Windows runner.

The fixture stages authenticated packages and creates an explicit protected
resume ticket. It does not exercise the hourly scheduler or HTTP download.
"""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

import psutil


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args, **kwargs):
    result = subprocess.run(
        list(map(str, args)), capture_output=True, timeout=120, **kwargs
    )
    if result.returncode:
        raise RuntimeError(
            str(args[0]) + " failed: " + result.stderr.decode(errors="replace")[-6000:]
        )
    return result


def wait_for(label, action, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = action()
        if result:
            return result
        time.sleep(0.25)
    raise AssertionError("Timed out: " + label)


user32 = ctypes.WinDLL("user32", use_last_error=True)
callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
user32.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]


def window(pid):
    found = []

    @callback_type
    def visit(hwnd, unused):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        title = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, title, len(title))
        kind = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(hwnd, kind, len(kind))
        if owner.value == pid and kind.value == "VeldNodeGuiWindow":
            found.append(hwnd)
        return True

    user32.EnumWindows(visit, 0)
    return found[0] if found else None


def diagnostics(pid):
    rows = []

    @callback_type
    def visit(hwnd, unused):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value != pid:
            return True
        title = ctypes.create_unicode_buffer(512)
        kind = ctypes.create_unicode_buffer(256)
        user32.GetWindowTextW(hwnd, title, len(title))
        user32.GetClassNameW(hwnd, kind, len(kind))
        rows.append({"handle": hwnd, "class": kind.value, "title": title.value})
        return True

    user32.EnumWindows(visit, 0)
    process = psutil.Process(pid)
    return {"windows": rows, "status": process.status(), "threads": process.num_threads()}


def processes(path):
    result = []
    for process in psutil.process_iter(["pid", "exe", "cmdline", "create_time"]):
        try:
            if process.info["exe"] and Path(process.info["exe"]).resolve() == path.resolve():
                result.append(process)
        except (psutil.Error, OSError):
            pass
    return result


def verified(package, verifier):
    result = run(
        [verifier, "--verify-release", package / "SHA256SUMS.txt", package / "SHA256SUMS.txt.sig"]
    )
    assert result.stdout.strip() == b"RELEASE-SIGNATURE-VALID"
    entries = {}
    for line in (package / "SHA256SUMS.txt").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        sha, name = line.split(" *", 1)
        assert name not in entries and (package / name).resolve().is_relative_to(package.resolve())
        assert digest(package / name) == sha, name
        entries[name] = sha
    return entries


def case(root, previous, target, verifier, writer, running):
    root.mkdir()
    install = root / "installation"
    shutil.copytree(previous, install)
    profile = root / "profile"
    state = profile / "Veld/Node"
    state.mkdir(parents=True)
    data = root / "data"
    data.mkdir()
    sentinel = data / "preserved.txt"
    sentinel.write_text("disposable persistent state")
    address = "VYTVc2e49QRPbb2LWSeRBH95GsmYdszfRC"
    settings = (
        "startup=0\nstartup_unlock=0\nminimize_to_tray=0\nauto_update=0\n"
        "reachable=0\ntor=0\naddress_only=1\nsolo_payout="
        + address
        + "\nmining=1\nmining_preset=custom\nmining_threads=1\nsync=full\n"
        "reference_display=0\nremote_monitoring=0\n"
    )
    (state / "node-gui.conf").write_text(settings)
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.upper().startswith("VELD_") and k.upper() != "PSMODULEPATH"
    }
    env.update(LOCALAPPDATA=str(profile), VELD_UPDATE_NODE_DATA_DIR=str(data))
    gui = install / "Veld Node.exe"
    node = install / "bin/veld-node.exe"
    firewall = "Veld disposable package " + root.name
    ps = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    # Elevated hosted runners default new objects to Administrators ownership.
    # A normal user profile belongs to its individual SID. Reproduce that
    # ownership only within this newly created disposable fixture tree.
    ownership_script = root / "ownership.ps1"
    ownership_script.write_text(
        "param([string]$Path)\n$ErrorActionPreference='Stop'\n"
        "$target = (Resolve-Path -LiteralPath $Path).Path\n"
        "$boundary = [IO.Path]::GetFullPath((Join-Path $env:RUNNER_TEMP 'package-results')) "
        "+ [IO.Path]::DirectorySeparatorChar\n"
        "if (!$target.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase)) "
        "{ throw 'Outside fixture boundary' }\n"
        "$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User\n"
        "$before = (Get-Acl -LiteralPath $target).Owner\n"
        "$items = @(Get-Item -LiteralPath $target) + "
        "@(Get-ChildItem -LiteralPath $target -Recurse -Force)\n"
        "foreach ($item in $items) {\n"
        "  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) "
        "{ throw 'Unexpected fixture reparse point' }\n"
        "  $acl = Get-Acl -LiteralPath $item.FullName\n"
        "  $acl.SetOwner($sid)\n"
        "  Set-Acl -LiteralPath $item.FullName -AclObject $acl\n"
        "  $actual = (Get-Acl -LiteralPath $item.FullName).GetOwner("
        "[Security.Principal.SecurityIdentifier]).Value\n"
        "  if ($actual -ne $sid.Value) { throw 'Fixture ownership mismatch' }\n"
        "}\n"
        "@{ before=$before; current_user_sid=$sid.Value; checked=$items.Count } "
        "| ConvertTo-Json -Compress\n"
    )
    ownership = run([ps, "-NoProfile", "-File", ownership_script, str(root)], env=env)
    (root / "ownership.json").write_bytes(ownership.stdout)
    # The runner is disposable. Block this fixture node only; retain loopback.
    firewall_script = root / "firewall.ps1"
    firewall_script.write_text(
        "param([string]$Name,[string]$Program,[switch]$Remove)\n$ErrorActionPreference='Stop'\n"
        "if ($Remove) { Remove-NetFirewallRule -DisplayName $Name; exit }\n"
        "New-NetFirewallRule -DisplayName $Name -Direction Outbound -Action Block "
        "-Program $Program -RemoteAddress Internet | Out-Null\n"
    )
    run([ps, "-NoProfile", "-File", firewall_script, firewall, node], env=env)
    parent = updater = None
    try:
        assert not processes(gui) and not processes(node)
        parent = subprocess.Popen([str(gui), "--datadir", str(data)], cwd=install, env=env)
        hwnd = wait_for("previous signed GUI", lambda: window(parent.pid))
        old_node = None
        if running:
            assert user32.PostMessageW(hwnd, 0x111, 4102, 0)
            old_node = wait_for("previous real node", lambda: next(iter(processes(node)), None))
            time.sleep(8)
            assert old_node.is_running()
            assert "--address-only" in old_node.cmdline() and "--mine" in old_node.cmdline()
            assert user32.PostMessageW(hwnd, 0x111, 4102, 0)
            wait_for("previous node graceful stop", lambda: not processes(node))
        stage = install / ".veld-update-transaction/stage"
        shutil.copytree(target, stage)
        (stage.parent / "state").write_bytes(b"HANDOFF\n")
        ticket = None
        if running:
            context = "Veld update resume v1|" + str(install.resolve()).lower()
            ticket = state / (
                "update-resume-" + hashlib.sha256(context.encode()).hexdigest() + ".dat"
            )
            identity = hashlib.sha256(("address-only|" + address).encode()).hexdigest()
            run(
                [
                    writer,
                    ticket,
                    context,
                    data.resolve(),
                    identity,
                    digest(previous / "SHA256SUMS.txt"),
                    digest(target / "SHA256SUMS.txt"),
                    "address-only",
                ]
            )
        with (root / "commit.log").open("wb") as log:
            updater = subprocess.Popen(
                [
                    str(ps),
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(target / "veld-update.ps1"),
                    "-Mode",
                    "Commit",
                    "-InstallDir",
                    str(install),
                    "-ParentPid",
                    str(parent.pid),
                ],
                env=env,
                stdout=log,
                stderr=log,
            )
            time.sleep(2)
            assert updater.poll() is None and parent.poll() is None
            assert user32.PostMessageW(hwnd, 0x0010, 0, 0)
            assert parent.wait(timeout=40) == 0
            assert updater.wait(timeout=120) == 0
        outcome = json.loads((install / "update-last-result.json").read_text(encoding="utf-8-sig"))
        assert outcome["status"] == "installed"
        installed = verified(install, verifier)
        assert installed == verified(target, verifier)
        children = processes(gui)
        assert len(children) == 1 and children[0].pid != parent.pid
        reopened = children[0]
        hwnd = wait_for("new signed GUI window", lambda: window(reopened.pid))
        if running:
            resumed = wait_for("real node resumed", lambda: next(iter(processes(node)), None))
            assert resumed.pid != old_node.pid
            args = resumed.cmdline()
            assert "--address-only" in args and "--mine" in args
            assert args[args.index("--miner") + 1] == address
            assert Path(args[args.index("--datadir") + 1]).resolve() == data.resolve()
            assert args[args.index("--threads") + 1] == "1"
            assert not ticket.exists()
            time.sleep(10)
            assert resumed.is_running()
            assert not any(
                p.status == psutil.CONN_ESTABLISHED
                and p.raddr
                and p.raddr.ip not in ("127.0.0.1", "::1")
                for p in resumed.net_connections(kind="tcp")
            )
            assert not (data / "miner.key").exists() and not (data / "pool.key").exists()
            assert user32.PostMessageW(hwnd, 0x111, 4102, 0)
            wait_for("resumed node graceful stop", lambda: not processes(node))
        else:
            time.sleep(10)
            assert not processes(node), "stopped node unexpectedly started"
        assert sentinel.read_text() == "disposable persistent state"
        assert not stage.parent.exists()
        assert user32.PostMessageW(hwnd, 0x0010, 0, 0)
        wait_for("new GUI exit", lambda: not processes(gui))
        result = {
            "status": "PASS",
            "previous_gui_pid": parent.pid,
            "reopened_gui_pid": reopened.pid,
            "running_intent": running,
            "node_restarted": running,
            "preserved_data": True,
            "outcome": outcome,
        }
        (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    except BaseException:
        observed = {}
        for path in (gui, node):
            for process in processes(path):
                try:
                    observed[str(process.pid)] = diagnostics(process.pid)
                except psutil.NoSuchProcess:
                    pass
        (root / "diagnostics.json").write_text(json.dumps(observed, indent=2) + "\n")
        raise
    finally:
        # Only processes from this absent-at-start disposable installation.
        for path in (gui, node):
            for process in processes(path):
                process.terminate()
                process.wait(timeout=15)
        if updater is not None and updater.poll() is None:
            updater.terminate()
            updater.wait(timeout=15)
        run([ps, "-NoProfile", "-File", firewall_script, "-Name", firewall, "-Remove"], env=env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("previous", "target", "verifier", "ticket-writer", "output"):
        parser.add_argument("--" + field, required=True, type=Path)
    args = parser.parse_args()
    assert os.environ.get("GITHUB_ACTIONS") == "true", "Use only a disposable GitHub Windows runner"
    assert (
        digest(args.verifier) == "1efb09f9069f4cc12c7ff1112d3554a4c53946d30ba74b2eefeb70b6710c1230"
    )
    verified(args.previous, args.verifier)
    verified(args.target, args.verifier)
    assert not args.output.exists()
    args.output.mkdir()
    result = {"status": "RUNNING", "cases": []}
    try:
        for name, running in (("stopped", False), ("address-only-running", True)):
            result["cases"].append(
                case(
                    args.output / name,
                    args.previous,
                    args.target,
                    args.verifier,
                    args.ticket_writer,
                    running,
                )
            )
        result["status"] = "PASS_SIGNED_PACKAGE_GUI_AND_NODE_RESTART"
    except BaseException as error:
        result.update(status="FAILED", error=repr(error))
        raise
    finally:
        result["scope"] = (
            "Authenticated staged packages, real Commit, GUI and node; fixture-created protected ticket. No hourly scheduler or download."
        )
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(result["status"])


if __name__ == "__main__":
    main()
