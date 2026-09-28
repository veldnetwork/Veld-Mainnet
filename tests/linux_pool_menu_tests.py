#!/usr/bin/env python3
"""Exercise the Linux setup menu with the included worker and a private TLS pool."""

import http.server
import json
import os
from pathlib import Path
import pty
import select
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from linux_pool_client_cli_tests import ADDRESS, Gateway


def main(binary):
    worker = binary.with_name('veld-pool-client')
    assert worker.is_file()
    with tempfile.TemporaryDirectory(prefix='veld-pool-menu-') as tmp:
        root = Path(tmp)
        key, cert = root / 'key.pem', root / 'cert.pem'
        subprocess.run(
            [
                'openssl',
                'req',
                '-x509',
                '-newkey',
                'rsa:2048',
                '-nodes',
                '-days',
                '1',
                '-keyout',
                str(key),
                '-out',
                str(cert),
                '-subj',
                '/CN=localhost',
                '-addext',
                'subjectAltName=DNS:localhost',
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        Gateway.requests = []
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Gateway)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        datadir = root / 'state'
        account = datadir / 'pool/pool-account.json'
        env = dict(
            os.environ,
            SSL_CERT_FILE=str(cert),
            VELD_VAULT_PASSPHRASE='Disposable-Environment-Canary-Only!',
        )
        try:
            for attempt in range(2):
                previous_work = sum(p == '/v1/work' for p, _ in Gateway.requests)
                master, slave = pty.openpty()
                proc = subprocess.Popen(
                    [str(binary), '--setup', '--datadir', str(datadir)],
                    stdin=slave,
                    stdout=slave,
                    stderr=slave,
                    env=env,
                )
                os.close(slave)
                transcript = bytearray()

                def wait_for(predicate, description):
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        if select.select([master], [], [], 0.05)[0]:
                            try:
                                transcript.extend(os.read(master, 65536))
                            except OSError:
                                pass
                        if predicate():
                            return
                        if proc.poll() is not None:
                            break
                    raise AssertionError(f'{description}: {transcript.decode(errors="replace")}')

                try:
                    wait_for(lambda: b'Choice [1-5]:' in transcript, 'pool menu missing')
                    os.write(master, b'5\n')
                    wait_for(lambda: b'Pool URL [' in transcript, 'pool URL prompt missing')
                    os.write(master, f'https://localhost:{server.server_port}\n'.encode())
                    wait_for(lambda: b'Payout address:' in transcript, 'address prompt missing')
                    os.write(master, (ADDRESS + '\n').encode())
                    wait_for(lambda: b'CPU workers [4]:' in transcript, 'worker prompt missing')
                    os.write(master, b'1\n')
                    wait_for(
                        lambda: Path(f'/proc/{proc.pid}/exe').resolve() == worker.resolve()
                        and account.exists()
                        and sum(p == '/v1/work' for p, _ in Gateway.requests) > previous_work,
                        'included worker did not register and request work',
                    )
                    assert (
                        b'VELD_VAULT_PASSPHRASE='
                        not in Path(f'/proc/{proc.pid}/environ').read_bytes()
                    )
                    assert not (datadir / 'miner.key').exists()
                    assert not list(datadir.glob('*.veld-keys'))
                    assert not (datadir / 'chain').exists()
                    assert b'Mining wallet unlocked' not in transcript
                    assert b'Loading verified local chain' not in transcript
                    saved = json.loads(account.read_text())
                    assert saved['address'] == ADDRESS
                    assert len([p for p, _ in Gateway.requests if p == '/v1/register']) == 1
                    if attempt == 0:
                        original = account.read_bytes()
                    else:
                        assert account.read_bytes() == original
                    proc.send_signal(signal.SIGINT)
                    proc.wait(timeout=15)
                    assert proc.returncode == 0, (attempt, proc.returncode, bytes(transcript))
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=5)
                    os.close(master)
        finally:
            server.shutdown()
            server.server_close()
    print(
        'PASS Linux pool menu: real included worker, verified TLS registration/work request, '
        'same account on resume, no wallet or chain startup, passphrase scrub and clean Ctrl+C'
    )


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve())
