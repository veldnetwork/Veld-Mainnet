"""Signed staged-Commit or complete automatic/manual updates on a disposable runner."""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

import psutil

from windows_package_test_paths import TEMP_PATH_CASES, configure_temp_path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def package_version(package):
    match = re.search(
        r"(?m)^# release-version=([0-9]+\.[0-9]+\.[0-9]+)$",
        (package / "SHA256SUMS.txt").read_text(),
    )
    assert match, "Signed package version missing"
    return match.group(1)


def run(args, **kwargs):
    result = subprocess.run(list(map(str, args)), capture_output=True, timeout=120, **kwargs)
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
user32.SendMessageTimeoutW.argtypes = [
    wintypes.HWND,
    wintypes.UINT,
    wintypes.WPARAM,
    wintypes.LPARAM,
    wintypes.UINT,
    wintypes.UINT,
    ctypes.POINTER(ctypes.c_size_t),
]
user32.SendMessageTimeoutW.restype = ctypes.c_ssize_t
user32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
user32.GetDpiForWindow.argtypes = [wintypes.HWND]
user32.GetDpiForWindow.restype = wintypes.UINT
user32.UpdateWindow.argtypes = [wintypes.HWND]


def click_update(hwnd):
    """Use the released Settings keyboard navigation and update button."""
    result = ctypes.c_size_t()
    for key in (ord("8"), 0x23):
        assert user32.SendMessageTimeoutW(hwnd, 0x100, key, 0, 3, 20000, ctypes.byref(result))
        user32.UpdateWindow(hwnd)
    rect = wintypes.RECT()
    assert user32.GetClientRect(hwnd, ctypes.byref(rect))
    dpi = user32.GetDpiForWindow(hwnd)
    scale = lambda value: (value * dpi + 48) // 96
    # 3.2.9's release panel begins at content y=1232; the button center is 1272.
    x = rect.right - scale(284)
    y = scale(1272) - max(0, scale(1502) - rect.bottom)
    assert 0 < x < rect.right and 0 < y < rect.bottom
    assert user32.SendMessageTimeoutW(hwnd, 0x202, 0, x | (y << 16), 3, 20000, ctypes.byref(result))


def menu_command(hwnd, command):
    result = ctypes.c_size_t()
    assert user32.SendMessageTimeoutW(hwnd, 0x111, command, 0, 3, 20000, ctypes.byref(result)), (
        "Native menu command was not handled"
    )


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


def case(root, previous, target, verifier, writer, running, flow="commit", temp_path="inherited"):
    root.mkdir()
    install = root / "installation"
    shutil.copytree(previous, install)
    profile = root / "profile"
    state = profile / "Veld/Node"
    state.mkdir(parents=True)
    data = root / "data"
    data.mkdir()
    sentinel = data / "preserved.txt"
    if not running:
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
    if flow == "automatic":
        (state / "node-gui.conf").write_text(settings.replace("auto_update=0", "auto_update=1"))
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.upper().startswith("VELD_") and k.upper() != "PSMODULEPATH"
    }
    env.update(
        LOCALAPPDATA=str(profile),
        VELD_UPDATE_NODE_DATA_DIR=str(data),
    )
    path_receipt = configure_temp_path(env, root, temp_path)
    (root / "environment.json").write_text(json.dumps(path_receipt, indent=2) + "\n")
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
        if running and flow != "coldstart":
            # An existing 3.2.9 installation already has its native network marker.
            # Initialize it through the authenticated native utility, without P2P.
            initialized = subprocess.run(
                [
                    str(node),
                    "--address-only",
                    "--miner",
                    address,
                    "--datadir",
                    str(data),
                    "--print-rpc-token",
                ],
                env=env,
                capture_output=True,
                timeout=30,
            )
            assert initialized.returncode == 2
            assert b"address-only RPC credential is missing" in initialized.stderr
            assert (data / "network.identity").is_file()
        parent = subprocess.Popen([str(gui), "--datadir", str(data)], cwd=install, env=env)
        hwnd = wait_for("previous signed GUI", lambda: window(parent.pid))
        old_node = None
        if running:
            menu_command(hwnd, 4102)
            old_node = wait_for("previous real node", lambda: next(iter(processes(node)), None))
            time.sleep(8)
            assert old_node.is_running()
            assert (data / "network.identity").is_file()
            sentinel.write_text("disposable persistent state")
            assert "--address-only" in old_node.cmdline() and "--mine" in old_node.cmdline()
            if flow == "coldstart":
                menu_command(hwnd, 4102)
                wait_for("fresh address-only node graceful stop", lambda: not processes(node))
                assert user32.PostMessageW(hwnd, 0x0010, 0, 0)
                assert parent.wait(timeout=40) == 0
                result = {
                    "status": "PASS",
                    "temp_path": path_receipt,
                    "flow": "coldstart",
                    "native_network_identity_created": True,
                    "address_only_gui_start": True,
                }
                (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
                return result
            if flow == "commit":
                menu_command(hwnd, 4102)
                wait_for("previous node graceful stop", lambda: not processes(node))
        stage = install / ".veld-update-transaction/stage"
        ticket = None
        if running:
            context = "Veld update resume v1|" + str(install.resolve()).lower()
            ticket = state / (
                "update-resume-" + hashlib.sha256(context.encode()).hexdigest() + ".dat"
            )
            identity = hashlib.sha256(("address-only|" + address).encode()).hexdigest()
        if flow == "commit":
            shutil.copytree(target, stage)
            (stage.parent / "state").write_bytes(b"HANDOFF\n")
        if running and flow == "commit":
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
        if flow != "commit":
            if flow == "manual":
                click_update(hwnd)
                wait_for(
                    "manual signed update check",
                    lambda: (state / "update-check.log").is_file()
                    and re.search(
                        r"Remote version:\s+" + re.escape(package_version(target)) + r"(?:\s|$)",
                        (state / "update-check.log").read_text(errors="replace"),
                    ),
                )
                time.sleep(3)
                click_update(hwnd)

            def installed_gui_closed():
                outcome_path = install / "update-last-result.json"
                if outcome_path.is_file():
                    try:
                        update_result = json.loads(outcome_path.read_text(encoding="utf-8-sig"))
                    except (OSError, ValueError):
                        return False
                    if update_result.get("status") == "failed":
                        raise AssertionError(
                            "Released updater refused the update: " + str(update_result)
                        )
                return parent.poll() is not None

            wait_for("previous GUI shutdown after verified handoff", installed_gui_closed, 300)
            assert parent.returncode == 0
            wait_for(
                "completed real update",
                lambda: not stage.parent.exists()
                and (install / "update-last-result.json").is_file()
                and json.loads(
                    (install / "update-last-result.json").read_text(encoding="utf-8-sig")
                ).get("status")
                == "installed",
                180,
            )
            wait_for("updated GUI process", lambda: processes(gui), 60)
        else:
            with (root / "commit.log").open("wb") as log:
                updater = subprocess.Popen(
                    [
                        str(ps),
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(install / "veld-update.ps1"),
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
            menu_command(hwnd, 4102)
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
            "temp_path": path_receipt,
            "flow": flow,
            "resume_ticket_created_by": "fixture" if flow == "commit" else "actual_previous_gui",
            "commit_helper_sha256": digest(previous / "veld-update.ps1"),
            "commit_helper_version": package_version(previous),
            "previous_gui_pid": parent.pid,
            "reopened_gui_pid": reopened.pid,
            "running_intent": running,
            "node_restarted": running,
            "preserved_data": True,
            "outcome": outcome,
        }
        (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    except BaseException as error:
        (root / "result.json").write_text(
            json.dumps(
                {"status": "FAILED", "flow": flow, "temp_path": path_receipt, "error": repr(error)},
                indent=2,
            )
            + "\n"
        )
        (root / "datadir-entries.json").write_text(
            json.dumps(
                [{"name": item.name, "directory": item.is_dir()} for item in data.iterdir()],
                indent=2,
            )
            + "\n"
        )
        observed = {}
        for path in (gui, node):
            for process in processes(path):
                try:
                    observed[str(process.pid)] = diagnostics(process.pid)
                except psutil.NoSuchProcess:
                    pass
        (root / "diagnostics.json").write_text(json.dumps(observed, indent=2) + "\n")
        log = state / "node-gui-node.log"
        if log.is_file():
            lines = log.read_bytes()[-65536:].decode(errors="replace").splitlines()
            safe = [
                line
                for line in lines
                if not re.search(
                    r"token|passphrase|password|secret|cookie|authorization", line, re.I
                )
            ]
            (root / "node-diagnostic.log").write_text("\n".join(safe) + "\n")
        raise
    finally:
        for folder, name in (
            (install, "update-commit.log"),
            (install, "update-commit-error.log"),
            (state, "update-check.log"),
            (state, "update-install.log"),
        ):
            log_path = folder / name
            if log_path.is_file():
                (root / name).write_bytes(log_path.read_bytes()[-65536:])
        # Only helpers bound to this absent-at-start disposable installation.
        for process in processes(ps):
            try:
                command = process.cmdline()
                if (
                    "-InstallDir" in command
                    and Path(command[command.index("-InstallDir") + 1]).resolve()
                    == install.resolve()
                ):
                    process.terminate()
                    process.wait(timeout=15)
            except psutil.NoSuchProcess:
                pass
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
    parser.add_argument("--flow", choices=("commit", "complete"), default="commit")
    parser.add_argument("--temp-path", choices=("all", *TEMP_PATH_CASES), default="all")
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
        path_cases = TEMP_PATH_CASES if args.temp_path == "all" else (args.temp_path,)
        result["requested_temp_paths"] = list(path_cases)
        result["temp_path_coverage_complete"] = False
        for temp_path in path_cases:
            path_root = args.output / temp_path
            path_root.mkdir()
            if args.flow == "commit":
                for name, running in (("stopped", False), ("address-only-running", True)):
                    result["cases"].append(
                        case(
                            path_root / name,
                            args.previous,
                            args.target,
                            args.verifier,
                            args.ticket_writer,
                            running,
                            temp_path=temp_path,
                        )
                    )
            else:
                from windows_package_https_fixture import PrivateFeed

                result["cases"].append(
                    case(
                        path_root / "coldstart",
                        args.target,
                        args.target,
                        args.verifier,
                        args.ticket_writer,
                        True,
                        "coldstart",
                        temp_path=temp_path,
                    )
                )
                with PrivateFeed(args.target, path_root / "https-feed") as feed:
                    for flow in ("automatic", "manual"):
                        start = len(feed.rows)
                        result["cases"].append(
                            case(
                                path_root / flow,
                                args.previous,
                                args.target,
                                args.verifier,
                                args.ticket_writer,
                                True,
                                flow,
                                temp_path=temp_path,
                            )
                        )
                        routes = {row["path"] for row in feed.rows[start:] if row["status"] == 200}
                        assert (set(feed.payloads) - {"/downloads/CHANGES.txt"}).issubset(routes), (
                            routes
                        )
        result["temp_path_coverage_complete"] = set(path_cases) == set(TEMP_PATH_CASES)
        result["status"] = (
            "PASS_SIGNED_PACKAGE_GUI_AND_NODE_RESTART"
            if args.flow == "commit"
            else "PASS_SIGNED_AUTOMATIC_AND_MANUAL_UPDATE_NODE_RESTART"
        )
    except BaseException as error:
        result.update(status="FAILED", error=repr(error))
        raise
    finally:
        result["scope"] = (
            (
                "Authenticated staged packages, previous installed updater Commit, real GUI and node; fixture-created protected ticket. No hourly scheduler or download."
            )
            if args.flow == "commit"
            else (
                "Unmodified signed previous and target clients; recorded inherited, long or real short TEMP paths; private loopback HTTPS feed; actual automatic timer and Settings check/install, download, native signatures, GUI-created protected ticket, shutdown, Commit, GUI and address-only node resume. No mining or live peer connectivity."
            )
        )
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(result["status"])


if __name__ == "__main__":
    main()
