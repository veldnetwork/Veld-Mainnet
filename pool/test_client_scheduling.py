"""Native worker through real loopback TLS; synthetic zero-TTL work, NOT mining E2E.

No live accounts, RPC credentials, node, signing keys, or public endpoint.
Exercise concurrency and lease bounds independently of available CPU resources.
"""

import argparse
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time

from pool.test_client_diagnostics import dummy_address


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--openssl', default='openssl')
    args = parser.parse_args()
    identity = json.loads(
        subprocess.check_output([args.binary, '--deployment-info'], text=True, timeout=10).split(
            'VELD_DEPLOYMENT_INFO_V1_JSON ', 1
        )[1]
    )
    genesis = bytes.fromhex(identity['genesis_fingerprint'])[::-1].hex()
    header = (
        (Path(__file__).resolve().parents[1] / 'tests/fixtures/veldhash-3.0.9-vectors.txt')
        .read_text()
        .splitlines()[0]
        .split()[1]
    )
    address = dummy_address()
    sid = None
    if os.name == 'nt':
        sid = json.loads(
            subprocess.check_output(
                [
                    'powershell.exe',
                    '-NoProfile',
                    '-Command',
                    '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value | ConvertTo-Json',
                ],
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        )

    def protect(path, directory=False):
        if sid:
            subprocess.run(
                [
                    'icacls',
                    str(path),
                    '/inheritance:r',
                    '/grant:r',
                    '*' + sid + ':' + ('(OI)(CI)F' if directory else 'F'),
                ],
                capture_output=True,
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            path.chmod(0o700 if directory else 0o600)

    with tempfile.TemporaryDirectory(prefix='veld-native-scheduling-') as temporary:
        root = Path(temporary)
        protect(root, True)
        subprocess.run(
            [
                args.openssl,
                'req',
                '-x509',
                '-newkey',
                'rsa:2048',
                '-nodes',
                '-days',
                '1',
                '-keyout',
                str(root / 'tls.key'),
                '-out',
                str(root / 'tls.crt'),
                '-subj',
                '/CN=localhost',
                '-addext',
                'subjectAltName=DNS:localhost,IP:127.0.0.1',
            ],
            capture_output=True,
            check=True,
        )
        for workers, count, malformed in (
            (14, 256, False),
            (14, 1024, False),
            (64, 4096, False),
            (14, 1024, True),
        ):
            state = dict(active=0, work=0, peak=0, peak_work=0, jobs=0, accounts=0)
            errors = []
            lock = threading.Lock()

            class Handler(http.server.BaseHTTPRequestHandler):
                protocol_version = 'HTTP/1.1'

                def log_message(self, *_):
                    pass

                def do_POST(self):
                    action = self.path.rsplit('/', 1)[-1]
                    with lock:
                        state['active'] += 1
                        state['work'] += action == 'work'
                        state['peak'] = max(state['peak'], state['active'])
                        state['peak_work'] = max(state['peak_work'], state['work'])
                    try:
                        length = int(self.headers['Content-Length'])
                        assert 0 < length <= 16384
                        body = json.loads(self.rfile.read(length))
                        if action == 'register':
                            assert body == dict(address=address)
                            result = dict(
                                version='veld-pool/1',
                                account='a' * 32,
                                worker_token='b' * 64,
                                view_token='c' * 64,
                            )
                        elif action == 'account':
                            assert body == dict(account='a' * 32, token='c' * 64)
                            with lock:
                                state['accounts'] += 1
                            result = dict(
                                account='a' * 32,
                                address=address,
                                pending_units='0',
                                available_units='0',
                                reserved_units='0',
                                paid_units='0',
                                verified_shares='0',
                            )
                        elif action == 'work':
                            assert body == dict(account='a' * 32, token='b' * 64, count=str(count))
                            with lock:
                                state['jobs'] += 1
                                index = state['jobs']
                            time.sleep(0.1)
                            result = dict(
                                version='veld-pool/1',
                                chain=genesis,
                                lease=f'{index:032x}',
                                header=header,
                                target='f' * 64,
                                height='0',
                                start=f'{(index - 1) * count:016x}',
                                count=str(count + 1 if malformed else count),
                                ttl_ms='0',
                            )
                        else:
                            raise AssertionError('zero-TTL job must not be submitted')
                        encoded = json.dumps(dict(ok=True, result=result)).encode()
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self.send_header('Content-Length', str(len(encoded)))
                        self.end_headers()
                        self.wfile.write(encoded)
                        self.close_connection = True
                    except Exception as exc:
                        with lock:
                            errors.append(type(exc).__name__)
                    finally:
                        with lock:
                            state['active'] -= 1
                            state['work'] -= action == 'work'

            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root / 'tls.crt', root / 'tls.key')
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            private = root / f'case-{workers}-{count}-{malformed}'
            private.mkdir()
            protect(private, True)
            config = dict(
                endpoint=f'https://127.0.0.1:{server.server_port}',
                ca_file=str(root / 'tls.crt'),
                genesis=genesis,
                payout_address=address,
                threads=str(workers),
                nonce_count=str(count),
                pause_ms='0',
                state_directory=str(private / 'state'),
            )
            path = private / 'config.json'
            path.write_text(json.dumps(config))
            protect(path)
            start = time.monotonic()
            try:
                proc = subprocess.run(
                    [args.binary, '--config', str(path), '--rounds', '2'],
                    capture_output=True,
                    text=True,
                    timeout=45,
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
            assert not errors, errors
            assert proc.returncode == (1 if malformed else 0), (
                proc.returncode,
                proc.stdout,
                proc.stderr,
            )
            receipt = json.loads((private / 'state/pool-status.json').read_text())
            assert receipt['hashes'] == '0' and receipt['active_workers'] == '0', receipt
            assert (
                state['active'] == 0
                and state['work'] == 0
                and state['peak'] <= 4
                and state['peak_work'] <= 3
            ), state
            if malformed:
                assert (
                    receipt.get('failure_code') == 'response_schema'
                    and receipt.get('failure_stage') == 'work'
                ), receipt
            else:
                assert (
                    state['jobs'] == workers * 2
                    and state['accounts'] >= 1
                    and receipt['status'] == 'Stopped'
                ), state
            print(
                json.dumps(
                    dict(
                        case='overlarge-job-refused' if malformed else 'bounded-transport',
                        workers=workers,
                        nonce_count=count,
                        seconds=round(time.monotonic() - start, 3),
                        observed=state,
                        status='PASS',
                    )
                )
            )


if __name__ == '__main__':
    main()
