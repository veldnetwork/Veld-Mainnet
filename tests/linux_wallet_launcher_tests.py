#!/usr/bin/env python3
"""Bounded Linux launcher tests; optional real packaged wallet, isolated HOME."""

import hashlib
import http.cookiejar
import json
import re
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
NATIVE = None
CAPTURE = None
if "--capture-dir" in sys.argv:
    index = sys.argv.index("--capture-dir")
    CAPTURE = Path(sys.argv[index + 1]).resolve()
    del sys.argv[index : index + 2]
if "--native-binary" in sys.argv:
    index = sys.argv.index("--native-binary")
    NATIVE = Path(sys.argv[index + 1]).resolve()
    del sys.argv[index : index + 2]

FAKE = """#!/usr/bin/env python3
import os, signal, socket, time
from pathlib import Path
Path(os.environ['HOME'], 'child.pid').write_text(str(os.getpid()))
Path(os.environ['HOME'], 'capability').write_text(os.environ.get('VELD_LOCAL_SIGNER_TOKEN', 'absent'))
s = socket.socket()
s.bind(('127.0.0.1', 0))
s.listen()
print('  [OK] Wallet UI on port ' + str(s.getsockname()[1]), flush=True)
signal.signal(signal.SIGTERM, lambda *_: exit(0))
while True: time.sleep(.1)
"""


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="veld-wallet-test-")
        self.root = Path(self.temp.name)
        self.package = self.root / 'Veld space % $ ` quote" slash\\'
        (self.package / "bin").mkdir(parents=True)
        (self.package / "share/icons").mkdir(parents=True)
        self.launcher = self.package / "bin/veld-wallet"
        shutil.copyfile(ROOT / "pkg/linux/veld-wallet", self.launcher)
        self.backend = self.package / "bin/veld-desktop"
        self.backend.write_text(FAKE)
        self.backend.chmod(0o755)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.runtime = self.root / "run"
        self.runtime.mkdir(mode=0o700)
        self.opened = self.root / "opened"
        self.tools = self.root / "tools"
        self.tools.mkdir()
        opener = self.tools / "xdg-open"
        opener.write_text(
            "#!/usr/bin/python3\nimport os,sys\nwith open(os.environ['OPENED'], 'a') as f: f.write(sys.argv[1]+'\\n')\n"
        )
        opener.chmod(0o755)
        self.env = dict(
            os.environ,
            HOME=str(self.home),
            XDG_RUNTIME_DIR=str(self.runtime),
            XDG_DATA_HOME=str(self.home / ".local/share"),
            DISPLAY=":test",
            PATH=str(self.tools) + ":/usr/bin:/bin",
            OPENED=str(self.opened),
            VELD_LOCAL_SIGNER_TOKEN="a" * 64,
            PYTHONDONTWRITEBYTECODE="1",
        )
        self.env.pop("USERPROFILE", None)

    def run_launcher(self, action="open", success=True, env=None):
        result = subprocess.run(
            [sys.executable, str(self.launcher), action],
            env=env or self.env,
            capture_output=True,
            text=True,
            timeout=40,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def tearDown(self):
        try:
            self.run_launcher("stop")
        finally:
            self.temp.cleanup()

    def test_open_reopen_one_child_and_stop(self):
        self.run_launcher()
        pid = int((self.home / "child.pid").read_text())
        self.run_launcher()
        self.assertEqual(int((self.home / "child.pid").read_text()), pid)
        self.assertEqual(len(self.opened.read_text().splitlines()), 2)
        self.assertRegex((self.home / "capability").read_text(), r"^[A-Za-z0-9_-]{43}$")
        self.run_launcher("stop")
        self.assertFalse(Path(f"/proc/{pid}").exists())

    def test_concurrent_opens_share_one_listener(self):
        children = [
            subprocess.Popen(
                [sys.executable, str(self.launcher)],
                env=self.env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for _ in range(4)
        ]
        for child in children:
            _, error = child.communicate(timeout=40)
            self.assertEqual(child.returncode, 0, error)
        self.assertEqual(len({u.split("/?")[0] for u in self.opened.read_text().splitlines()}), 1)

    def test_failed_backend_never_opens_browser(self):
        self.backend.write_text("#!/bin/sh\nexit 2\n")
        self.run_launcher(success=False)
        self.assertFalse(self.opened.exists())

    def test_headless_refuses_before_backend(self):
        env = self.env.copy()
        env.pop("DISPLAY", None)
        env.pop("WAYLAND_DISPLAY", None)
        self.run_launcher(success=False, env=env)
        self.assertFalse((self.home / "child.pid").exists())

    def test_missing_payload(self):
        self.backend.unlink()
        self.run_launcher(success=False)
        self.assertFalse(self.opened.exists())

    def test_unmanaged_shortcut_preserved(self):
        path = Path(self.env["XDG_DATA_HOME"]) / "applications/network.veld.Wallet.desktop"
        path.parent.mkdir(parents=True)
        path.write_text("Owner content\n")
        self.run_launcher("install", success=False)
        self.run_launcher("uninstall", success=False)
        self.assertEqual(path.read_text(), "Owner content\n")

    def test_desktop_menu_real_gio_dispatch_special_path(self):
        self.run_launcher("install")
        path = Path(self.env["XDG_DATA_HOME"]) / "applications/network.veld.Wallet.desktop"
        command = "from gi.repository import Gio; import sys; a=Gio.DesktopAppInfo.new_from_filename(sys.argv[1]); assert a; assert a.launch([], None)"
        result = subprocess.run(
            ["/usr/bin/python3", "-c", command, str(path)],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        deadline = time.monotonic() + 10
        while not self.opened.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertTrue(self.opened.exists())
        self.run_launcher("uninstall")
        self.assertFalse(path.exists())

    def test_unsafe_state_refused(self):
        path = self.runtime / "veld-wallet"
        path.mkdir(mode=0o755)
        self.run_launcher(success=False)
        self.assertFalse((self.home / "child.pid").exists())
        path.chmod(0o700)

    def test_shared_runtime_refused(self):
        self.runtime.chmod(0o777)
        try:
            self.run_launcher(success=False)
            self.assertFalse((self.home / "child.pid").exists())
        finally:
            self.runtime.chmod(0o700)

    def test_lock_symlink_refused(self):
        path = self.runtime / "veld-wallet"
        path.mkdir(mode=0o700)
        sentinel = self.home / "sentinel"
        sentinel.write_text("untouched")
        (path / "lock").symlink_to(sentinel)
        self.run_launcher(success=False)
        self.assertEqual(sentinel.read_text(), "untouched")
        (path / "lock").unlink()

    def test_stale_socket_recovered(self):
        directory = self.runtime / "veld-wallet"
        directory.mkdir(mode=0o700)
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(directory / "control"))
        sock.close()
        self.run_launcher()
        self.assertTrue(self.opened.exists())

    def test_supervisor_death_stops_own_child(self):
        supervisor = subprocess.Popen([sys.executable, str(self.launcher), "_serve"], env=self.env)
        try:
            deadline = time.monotonic() + 5
            while not (self.home / "child.pid").exists() and time.monotonic() < deadline:
                time.sleep(0.1)
            pid = int((self.home / "child.pid").read_text())
            supervisor.kill()
            supervisor.wait(timeout=5)
            deadline = time.monotonic() + 5
            while Path(f"/proc/{pid}/stat").exists() and time.monotonic() < deadline:
                if Path(f"/proc/{pid}/stat").read_text().split()[2] == "Z":
                    break
                time.sleep(0.1)
            self.assertTrue(
                not Path(f"/proc/{pid}/stat").exists()
                or Path(f"/proc/{pid}/stat").read_text().split()[2] == "Z"
            )
        finally:
            if supervisor.poll() is None:
                supervisor.kill()
                supervisor.wait(timeout=5)

    @unittest.skipUnless(NATIVE, "pass --native-binary for the real packaged wallet")
    def test_attached_browser_consumes_native_token_once(self):
        shutil.copyfile(NATIVE, self.backend)
        self.backend.chmod(0o755)
        opener = self.tools / "xdg-open"
        original = opener.read_text()
        opener.write_text(
            "#!/usr/bin/python3\n"
            "import http.cookiejar, os, sys, time, urllib.request\n"
            "from pathlib import Path\n"
            "jar = http.cookiejar.CookieJar()\n"
            "browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))\n"
            "with browser.open(sys.argv[1], timeout=5) as response:\n"
            "    assert response.status == 200\n"
            "    assert b'<script src=\"/dilithium.js\">' in response.read()\n"
            "Path(os.environ['OPENED']).write_text(sys.argv[1] + '\\n')\n"
            "Path(os.environ['HOME'], 'opener.pid').write_text(str(os.getpid()))\n"
            "time.sleep(30)\n"
        )
        try:
            self.run_launcher()
            pid = int((self.home / "opener.pid").read_text())
            self.assertNotEqual(Path(f"/proc/{pid}/stat").read_text().split()[2], "Z")
            first = self.opened.read_text().splitlines()[0]
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(first, timeout=5)
            self.assertEqual(caught.exception.code, 403)
            caught.exception.close()
            opener.write_text(original)
            self.run_launcher()
            self.assertEqual(self.opened.read_text().splitlines()[-1], first.split("/?")[0])
        finally:
            record = self.home / "opener.pid"
            if record.exists():
                try:
                    os.kill(int(record.read_text()), signal.SIGTERM)
                except ProcessLookupError:
                    pass

    @unittest.skipUnless(NATIVE, "pass --native-binary for the real packaged wallet")
    def test_native_wallet_and_occupied_port(self):
        shutil.copyfile(NATIVE, self.backend)
        self.backend.chmod(0o755)
        self.run_launcher()
        bootstrap_url = self.opened.read_text().splitlines()[-1]
        self.assertIn("/?signer=", bootstrap_url)
        url = bootstrap_url.split("/?")[0]
        cookies = http.cookiejar.CookieJar()
        browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
        with urllib.request.urlopen(url, timeout=5) as response:
            self.assertNotIn(b'<script src="/dilithium.js">', response.read())
        with browser.open(bootstrap_url, timeout=5) as response:
            html = response.read()
            self.assertEqual(response.status, 200)
            self.assertIn(b"<html", html)
            self.assertIn(b"wallet", html.lower())
            self.assertIn(b'<script src="/dilithium.js">', html)
            html_headers = dict(response.headers)
        for rejected in (bootstrap_url, url + "/dilithium.js"):
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(rejected, timeout=5)
            self.assertIn(caught.exception.code, (403, 404))
            caught.exception.close()
        with self.assertRaises(urllib.error.HTTPError) as caught:
            browser.open(
                urllib.request.Request(
                    url + "/dilithium.js",
                    headers={"Origin": "https://untrusted.invalid"},
                ),
                timeout=5,
            )
        self.assertIn(caught.exception.code, (403, 404))
        caught.exception.close()
        if CAPTURE:
            CAPTURE.mkdir(parents=True, exist_ok=True)
            (CAPTURE / "wallet.html").write_bytes(html)
            routes = {
                "/": {
                    "file": "wallet.html",
                    "type": "text/html",
                    "headers": html_headers,
                }
            }
            paths = set(re.findall(rb'(?:src|href)="(/[^"?#]+)', html))
            for path in sorted(paths):
                try:
                    with browser.open(url + path.decode(), timeout=3) as response:
                        name = hashlib.sha256(path).hexdigest() + ".asset"
                        body = response.read()
                        (CAPTURE / name).write_bytes(body)
                        routes[path.decode()] = {
                            "file": name,
                            "type": response.headers.get("Content-Type"),
                        }
                except (OSError, ValueError):
                    pass
            (CAPTURE / "routes.json").write_text(json.dumps(routes, indent=2))
        self.run_launcher()
        self.assertEqual(self.opened.read_text().splitlines()[-1], url)
        self.run_launcher("stop")
        self.opened.unlink()
        with socket.socket() as conflict:
            conflict.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            conflict.bind(("127.0.0.1", int(url.rsplit(":", 1)[1])))
            conflict.listen()
            self.run_launcher(success=False)
            self.assertFalse(self.opened.exists())
        print(
            json.dumps(
                {
                    "native_sha256": hashlib.sha256(NATIVE.read_bytes()).hexdigest(),
                    "wallet_html_sha256": hashlib.sha256(html).hexdigest(),
                    "wallet_html_bytes": len(html),
                }
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
