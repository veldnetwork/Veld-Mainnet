"""Real native worker/loopback TLS fault cases, NOT mining or payout E2E.

Only temporary synthetic account credentials and a checksummed dummy address.
No public connections, node RPC, real keys, signatures, or broadcast.
"""

import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time


def dummy_address():
    payload = b'\x46' + hashlib.sha256(b'pool-diagnostics-no-private-key').digest()[:20]
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    value = int.from_bytes(raw, 'big')
    out = ''
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    while value:
        value, remainder = divmod(value, 58)
        out = alphabet[remainder] + out
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--openssl', default='openssl')
    parser.add_argument('--expect-legacy', action='store_true')
    args = parser.parse_args()
    info = subprocess.check_output([args.binary, '--deployment-info'], text=True, timeout=10)
    identity = json.loads(info.split('VELD_DEPLOYMENT_INFO_V1_JSON ', 1)[1])
    genesis = bytes.fromhex(identity['genesis_fingerprint'])[::-1].hex()
    address = dummy_address()
    account = 'a' * 32
    worker_token = 'b' * 64
    view_token = 'c' * 64
    private_sentinel = 'DO_NOT_ECHO_SERVER_TEXT_OR_CREDENTIALS'
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

    cases = [
        ('work-refused', 'remote_refusal', 'work'),
        ('registration-refused', 'remote_refusal', 'registration'),
        ('work-shape', 'response_schema', 'work'),
        ('work-chain', 'work_identity', 'work'),
        ('balance-identity', 'account_identity', 'balance'),
        ('certificate', 'certificate', 'registration'),
        ('state-write', 'private_state', 'state'),
        ('submit-refused', 'remote_refusal', 'submission'),
        ('normal', None, None),
        ('retry-then-normal', None, None),
        ('proxy-retry-then-normal', None, None),
    ]
    if args.expect_legacy:
        cases = cases[:1]
    with tempfile.TemporaryDirectory(prefix='veld-native-diagnostics-') as temporary:
        root = Path(temporary)
        protect(root, True)
        for name in ('trusted', 'other'):
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
                    str(root / (name + '.key')),
                    '-out',
                    str(root / (name + '.crt')),
                    '-subj',
                    '/CN=localhost',
                    '-addext',
                    'subjectAltName=DNS:localhost,IP:127.0.0.1',
                ],
                capture_output=True,
                check=True,
            )
        header = (
            (Path(__file__).resolve().parents[1] / 'tests/fixtures/veldhash-3.0.9-vectors.txt')
            .read_text()
            .splitlines()[0]
            .split()[1]
        )
        for name, code, stage in cases:
            private = root / name
            private.mkdir()
            protect(private, True)
            if name == 'state-write':
                state_dir = private / 'state'
                state_dir.mkdir()
                protect(state_dir, True)
                # A directory cannot be replaced by a status file. No real state touched.
                (state_dir / 'pool-status.json').mkdir()
            seen = []
            lock = threading.Lock()

            class Handler(http.server.BaseHTTPRequestHandler):
                protocol_version = 'HTTP/1.1'

                def log_message(self, *_):
                    pass

                def do_POST(self):
                    length = int(self.headers['Content-Length'])
                    assert 0 < length <= 16384
                    body = json.loads(self.rfile.read(length))
                    action = self.path.rsplit('/', 1)[-1]
                    with lock:
                        seen.append(action)
                        work_calls = seen.count('work')
                    if action == 'register':
                        result = dict(
                            version='veld-pool/1',
                            account=account,
                            worker_token=worker_token,
                            view_token=view_token,
                        )
                    elif action == 'account':
                        assert body == dict(account=account, token=view_token)
                        result = dict(
                            account='0' * 32 if name == 'balance-identity' else account,
                            address=address,
                            pending_units='0',
                            available_units='0',
                            reserved_units='0',
                            paid_units='0',
                            verified_shares='0',
                        )
                    elif action == 'work':
                        assert body == dict(account=account, token=worker_token, count='1')
                        # Zero TTL performs no hashing. This is a diagnostic fixture.
                        result = dict(
                            version='veld-pool/1',
                            chain=genesis,
                            lease='d' * 32,
                            header=header,
                            target='f' * 64,
                            height='0',
                            start='0' * 16,
                            count='1',
                            ttl_ms='0',
                        )
                        if name == 'work-shape':
                            result = []
                        if name == 'work-chain':
                            result['chain'] = '0' * 64
                        if name == 'submit-refused':
                            result['ttl_ms'] = '10000'
                        if name == 'balance-identity':
                            time.sleep(0.15)
                    elif action == 'submit':
                        assert name == 'submit-refused' and body == dict(
                            account=account, token=worker_token, lease='d' * 32, nonce='0' * 16
                        )
                        result = {}
                    else:
                        raise AssertionError('unexpected endpoint')
                    refused = (
                        (name == 'work-refused' and action == 'work')
                        or (name == 'registration-refused' and action == 'register')
                        or (name == 'submit-refused' and action == 'submit')
                    )
                    retry = name == 'retry-then-normal' and action == 'work' and work_calls == 1
                    if name == 'proxy-retry-then-normal' and action == 'work' and work_calls == 1:
                        encoded = private_sentinel.encode()
                        self.send_response(502)
                        self.send_header('Content-Type', 'text/html')
                        self.send_header('Content-Length', str(len(encoded)))
                        self.end_headers()
                        self.wfile.write(encoded)
                        self.close_connection = True
                        return
                    response = (
                        dict(ok=False, error=private_sentinel, retryable=retry)
                        if refused or retry
                        else dict(ok=True, result=result)
                    )
                    encoded = json.dumps(response).encode()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(encoded)))
                    self.end_headers()
                    self.wfile.write(encoded)
                    self.close_connection = True

            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root / 'trusted.crt', root / 'trusted.key')
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            config = dict(
                endpoint='https://127.0.0.1:' + str(server.server_port),
                ca_file=str(root / ('other.crt' if name == 'certificate' else 'trusted.crt')),
                genesis=genesis,
                payout_address=address,
                threads='2' if name == 'work-refused' else '1',
                nonce_count='1',
                pause_ms='0',
                state_directory=str(private / 'state'),
            )
            path = private / 'config.json'
            path.write_text(json.dumps(config))
            protect(path)
            try:
                proc = subprocess.run(
                    [args.binary, '--config', str(path), '--rounds', '1'],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
            logs = proc.stdout + proc.stderr
            assert all(
                secret not in logs for secret in (worker_token, view_token, private_sentinel)
            ), (name, 'private output')
            assert proc.returncode == (1 if code else 0), (name, proc.returncode, logs)
            receipts = [json.loads(line) for line in logs.splitlines() if line.startswith('{')]
            assert receipts, (name, logs)
            if args.expect_legacy:
                assert receipts[-1]['status'] == 'refused' and 'failure_code' not in receipts[-1]
                print('REPRODUCED legacy worker hides work refusal cause and stage')
                continue
            receipt = receipts[-1]
            assert receipt['failure_code'] == (code or '') and receipt['failure_stage'] == (
                stage or ''
            ), (name, receipt)
            status_path = private / 'state/pool-status.json'
            if stage not in ('registration', 'state'):
                state = json.loads(status_path.read_text())
                assert all(
                    secret not in status_path.read_text()
                    for secret in (worker_token, view_token, private_sentinel)
                )
                assert state['active_workers'] == '0' and state['hashes'] == (
                    '1' if name == 'submit-refused' else '0'
                ), (name, state)
                if code:
                    assert (state['failure_code'], state['failure_stage']) == (code, stage), (
                        name,
                        state,
                    )
                else:
                    assert state['status'] == 'Stopped' and 'failure_code' not in state
                saved = json.loads((private / 'state/pool-account.json').read_text())
                assert (saved['account'], saved['worker_token'], saved['view_token']) == (
                    account,
                    worker_token,
                    view_token,
                )
            if name == 'certificate':
                assert seen == [], 'credentials sent before verified TLS'
            if name in ('retry-then-normal', 'proxy-retry-then-normal'):
                assert seen.count('work') == 2 and seen.count('register') == 1, seen
            print('PASS', name, 'bounded diagnosis, no raw private output')
    print('PASS native diagnostic fixtures; no mining, payment or production-build claim')


if __name__ == '__main__':
    main()
