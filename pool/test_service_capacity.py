"""Real bounded IPC burst admission; no external node or credentials."""

import concurrent.futures
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace

if os.name != 'posix':
    raise unittest.SkipTest('Unix IPC service')
from pool.service import Server


class Capacity(unittest.TestCase):
    def test_short_saturation_drains_without_dropping_next_request(self):
        with tempfile.TemporaryDirectory() as d:
            release = threading.Event()
            full = threading.Event()
            lock = threading.Lock()
            active = [0]
            peak = [0]

            def health():
                with lock:
                    active[0] += 1
                    peak[0] = max(peak[0], active[0])
                    if active[0] == 16:
                        full.set()
                try:
                    if not release.wait(3):
                        raise RuntimeError('fixture deadline')
                    return {'fixture': True}
                finally:
                    with lock:
                        active[0] -= 1

            path = str(Path(d) / 'ipc')
            server = Server(path, SimpleNamespace(health=health))
            t = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02})
            t.start()

            def request():
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    s.connect(path)
                    s.sendall(b'{"action":"health","payload":{}}\n')
                    with s.makefile('rb') as f:
                        return json.loads(f.readline(16385))

            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=17) as ex:
                    futures = [ex.submit(request) for _ in range(16)]
                    self.assertTrue(full.wait(2))
                    extra = ex.submit(request)
                    time.sleep(0.05)
                    release.set()
                    self.assertTrue(all(f.result()['ok'] for f in futures + [extra]))
                self.assertEqual(peak[0], 16)
            finally:
                release.set()
                server.shutdown()
                server.server_close()
                t.join()

    def test_sustained_saturation_is_bounded_and_does_not_spawn_waiters(self):
        with tempfile.TemporaryDirectory() as d:
            server = Server(str(Path(d) / 'ipc'), None)
            for _ in range(16):
                self.assertTrue(server.slots.acquire(False))
            a, b = socket.socketpair()
            try:
                start = time.monotonic()
                server.process_request(a, None)
                elapsed = time.monotonic() - start
                self.assertGreaterEqual(elapsed, 0.2)
                self.assertLess(elapsed, 1)
                b.settimeout(1)
                self.assertEqual(b.recv(1), b'')
            finally:
                a.close()
                b.close()
                for _ in range(16):
                    server.slots.release()
                server.server_close()


if __name__ == '__main__':
    unittest.main()
