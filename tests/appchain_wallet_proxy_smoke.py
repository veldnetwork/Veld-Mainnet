"""Exercise bridge or excess-bond RPC admission through a packaged desktop binary.

The upstream is a loopback transport fixture, not a simulated financial chain.
No wallet key, transaction, mining or public endpoint is used.
"""

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import tempfile
import threading
import time


def main(a):
    assert hashlib.sha256(a.binary.read_bytes()).hexdigest() == a.sha256
    if os.name != 'nt':
        interfaces = json.loads(subprocess.check_output(['ip', '-json', 'link', 'show']))
        assert [entry['ifname'] for entry in interfaces] == ['lo'], (
            'Empty network namespace required'
        )
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
        assert json.loads(subprocess.check_output(['ip', '-json', 'route', 'show'])) == []
    a.evidence.mkdir(exist_ok=False)
    (a.evidence / 'test-source.py').write_bytes(Path(__file__).read_bytes())
    report = dict(
        status='RUNNING',
        checks=[],
        binary_sha256=a.sha256,
        real_funds=False,
        upstream='controlled loopback RPC fixture',
        suite=a.suite,
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    )
    if os.name != 'nt':
        report['network_namespace'] = os.readlink('/proc/self/ns/net')
        report['external_routes'] = []
    calls = []

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            size = int(self.headers.get('Content-Length', 0))
            assert 0 < size < 100000
            data = json.loads(self.rfile.read(size))
            calls.append(data)
            body = json.dumps(
                dict(jsonrpc='2.0', id=data['id'], result=dict(forwarded=data))
            ).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    upstream = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    proc = None

    def save():
        (a.evidence / 'result.json').write_text(
            json.dumps(report, indent=2) + '\n', encoding='utf-8'
        )

    def check(value, label):
        assert value, label
        report['checks'].append(label)
        save()

    try:
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        data = Path(tempfile.mkdtemp(prefix='veld-wallet-bridge-proxy-'))
        report['disposable_data'] = str(data)
        token = secrets.token_urlsafe(32)
        env = os.environ.copy()
        env.update(VELD_LOCAL_SIGNER_TOKEN=token)
        env.pop('VELD_FLEET_ANCHOR_IPS', None)
        command = [
            str(a.binary),
            '--wallet',
            '--rpcurl',
            f'http://127.0.0.1:{upstream.server_port}',
            '--uiport',
            str(port),
            '--datadir',
            str(data),
        ]
        report['command'] = command
        with (a.evidence / 'wallet.log').open('wb') as log:
            proc = subprocess.Popen(
                command,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
            )
        origin = f'http://127.0.0.1:{port}'

        def request(method, path, value=None, headers=None):
            c = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
            h = {
                'Content-Type': 'application/json',
                'Origin': origin,
                'Sec-Fetch-Site': 'same-origin',
            }
            h.update(headers or {})
            c.request(method, path, None if value is None else json.dumps(value), h)
            response = c.getresponse()
            raw = response.read(5 * 1024 * 1024)
            result = response.status, dict(response.getheaders()), raw
            c.close()
            return result

        deadline = time.monotonic() + 60
        while True:
            assert proc.poll() is None, 'Desktop process exited before startup'
            try:
                status, headers, html = request('GET', '/')
                break
            except OSError:
                assert time.monotonic() < deadline, 'Desktop startup timed out'
                time.sleep(0.1)
        check(status == 200, 'actual desktop binary serves the wallet')
        check(
            b'var VELD_TRUSTED_LOCAL_SIGNER = false' in html
            or b'VELD_TRUSTED_LOCAL_SIGNER=false' in html,
            'unauthenticated local page does not receive signer authority',
        )
        status, headers, _ = request('GET', '/?signer=' + token)
        check(
            status in (302, 303) and 'Set-Cookie' in headers,
            'one-use local launch capability establishes wallet session',
        )
        cookie = headers['Set-Cookie'].split(';')[0]
        check(
            'HttpOnly' in headers['Set-Cookie'] and 'SameSite=Strict' in headers['Set-Cookie'],
            'wallet session remains HttpOnly and same-site',
        )
        status, _, _ = request('GET', '/?signer=' + token)
        check(status == 403, 'launch capability cannot be reused')
        status, headers, html = request('GET', '/', headers={'Cookie': cookie})
        check(
            status == 200
            and (
                b'var VELD_TRUSTED_LOCAL_SIGNER = true' in html
                or b'VELD_TRUSTED_LOCAL_SIGNER=true' in html
            ),
            'authenticated local wallet receives signer authority',
        )
        check(
            "frame-ancestors 'none'" in headers.get('Content-Security-Policy', '')
            and headers.get('X-Frame-Options') == 'DENY',
            'wallet embedding protections remain present',
        )
        requests = (
            (('preparereducevalidatorbond', ['test-address', 'ab' * 1952]),)
            if a.suite == 'bond'
            else (
                ('getappchainbridgeinfo', ['ab' * 48]),
                (
                    'prepareappchaindeposit',
                    ['test-address', 'ab' * 48, 'cd' * 48, 'ef' * 48, '12' * 48, '1.25', '0.02'],
                ),
            )
        )
        for index, (method, params) in enumerate(requests):
            body = dict(jsonrpc='2.0', id=index + 1, method=method, params=params)
            before = len(calls)
            status, _, raw = request('POST', '/rpc', body, {'Cookie': cookie})
            reply = json.loads(raw)
            if a.expect_missing:
                check(
                    status == 200
                    and reply.get('error', {}).get('code') == -32601
                    and len(calls) == before,
                    'reproduced packaged wallet rejection: ' + method,
                )
            else:
                check(
                    status == 200
                    and reply.get('result', {}).get('forwarded') == body
                    and calls[before:] == [body],
                    'packaged wallet forwards exact unsigned request: ' + method,
                )
                before = len(calls)
                status, _, raw = request(
                    'POST',
                    '/rpc',
                    body,
                    {'Cookie': cookie, 'Origin': 'https://wallet.veld.network'},
                )
                check(
                    status == 200
                    and json.loads(raw).get('result', {}).get('forwarded') == body
                    and calls[before:] == [body],
                    'official wallet origin forwards the same request: ' + method,
                )
        for method in (
            'stop',
            'dumpprivkey',
            'walletpassphrase',
            'submitblock',
            'getappchainbridgeinfo_admin',
        ):
            before = len(calls)
            status, _, raw = request(
                'POST',
                '/rpc',
                dict(jsonrpc='2.0', id=9, method=method, params=[]),
                {'Cookie': cookie},
            )
            check(
                status == 200
                and json.loads(raw).get('error', {}).get('code') == -32601
                and len(calls) == before,
                'unlisted method remains blocked: ' + method,
            )
        for label, extra, expected in (
            ('cross-site origin', {'Origin': 'https://untrusted.invalid'}, 403),
            ('cross-site fetch', {'Sec-Fetch-Site': 'cross-site'}, 403),
            ('simple-request content type', {'Content-Type': 'text/plain'}, 415),
            ('unrecognized host', {'Host': 'untrusted.invalid'}, 421),
        ):
            before = len(calls)
            status, _, _ = request(
                'POST',
                '/rpc',
                dict(jsonrpc='2.0', id=10, method=requests[0][0], params=[]),
                dict(extra, Cookie=cookie),
            )
            check(
                status == expected and len(calls) == before, label + ' rejected before forwarding'
            )
        report.update(
            status='REPRODUCED_PACKAGED_WALLET_MISSING_' + a.suite.upper() + '_RPC'
            if a.expect_missing
            else 'PASS_PACKAGED_WALLET_' + a.suite.upper() + '_RPC'
        )
    except BaseException as error:
        report.update(status='FAILED', error=repr(error))
        raise
    finally:
        if proc and proc.poll() is None:
            if os.name == 'nt':
                # The wallet-only fixture has no keys or mutable chain. Hidden
                # Windows subprocesses have no CTRL_BREAK console handshake.
                proc.terminate()
            else:
                proc.send_signal(signal.SIGINT)
            proc.wait(timeout=20)
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)
        report['all_owned_processes_stopped'] = (
            proc is None or proc.poll() is not None
        ) and not thread.is_alive()
        report['upstream_calls'] = calls
        save()
    print(json.dumps(dict(status=report['status'], checks=len(report['checks']))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--expect-missing', action='store_true')
    parser.add_argument('--suite', choices=('bridge', 'bond'), default='bridge')
    main(parser.parse_args())
