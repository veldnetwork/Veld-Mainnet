"""Real TLS gateway/Unix IPC qualification with synthetic coordinator responses.

No chain, miner, signing, account creation, or external endpoint. A baseline
source directory is optional for paired response-latency measurement.
"""

import argparse
import concurrent.futures
import hashlib
import http.client
import importlib
import json
import socket
import socketserver
import ssl
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from .gateway import Gateway
from .service import Server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='veld-gateway-latency-') as temporary:
        root = Path(temporary)
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
                str(root / 'key.pem'),
                '-out',
                str(root / 'cert.pem'),
                '-subj',
                '/CN=localhost',
                '-addext',
                'subjectAltName=DNS:localhost,IP:127.0.0.1',
            ],
            check=True,
            capture_output=True,
        )
        received = []
        lock = threading.Lock()

        class IPC(socketserver.StreamRequestHandler):
            def handle(self):
                raw = self.rfile.readline(16385)
                body = json.loads(raw)
                assert set(body) == {'action', 'payload'}
                with lock:
                    received.append(body)
                self.wfile.write(
                    json.dumps(dict(ok=True, result={'echo': body['payload']})).encode() + b'\n'
                )

        class IPCServer(socketserver.ThreadingUnixStreamServer):
            request_queue_size = Server.request_queue_size

        ipc = IPCServer(str(root / 'co.sock'), IPC)
        threading.Thread(target=ipc.serve_forever, daemon=True).start()
        trust = ssl.create_default_context(cafile=str(root / 'cert.pem'))
        classes = {'candidate': Gateway}
        if args.baseline:
            # Load the original module under the same package for its relative
            # imports; never edit it or substitute its logic into the candidate.
            path = Path(args.baseline) / 'pool/gateway.py'
            spec = importlib.util.spec_from_file_location('pool.gateway_baseline', path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            classes['baseline'] = module.Gateway
        services = {}
        for name, cls in classes.items():
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(root / 'cert.pem', root / 'key.pem')
            server = cls(('127.0.0.1', 0), ctx, str(root / 'co.sock'))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            services[name] = (server, thread)

        def request(name, body=b'{}', extra=None):
            server = services[name][0]
            conn = http.client.HTTPSConnection(
                '127.0.0.1', server.server_port, context=trust, timeout=5
            )
            try:
                start = time.monotonic()
                conn.request(
                    'POST', '/v1/work', body, {'Content-Type': 'application/json', **(extra or {})}
                )
                response = conn.getresponse()
                data = response.read(16385)
                assert len(data) <= 16384 and response.getheader('Connection') == 'close'
                assert response.getheader('Cache-Control') == 'no-store'
                assert response.getheader('Content-Type') == 'application/json'
                return response.status, json.loads(data), time.monotonic() - start
            finally:
                conn.close()

        report = dict(scope='actual TLS and Unix IPC, synthetic payloads; not mining E2E', cases=[])
        try:
            # Reuse only successful authenticated-operation envelopes. Each
            # request still traverses Unix IPC and carries its own credentials.
            kept = http.client.HTTPSConnection(
                '127.0.0.1', services['candidate'][0].server_port, context=trust, timeout=5
            )
            warm = []
            ports = []
            try:
                for index in range(16):
                    start = time.monotonic()
                    payload = {'account': str(index % 2), 'token': 'fixture-' + str(index)}
                    kept.request(
                        'POST',
                        '/v1/work',
                        json.dumps(payload),
                        {'Content-Type': 'application/json', 'Connection': 'keep-alive'},
                    )
                    ports.append(kept.sock.getsockname()[1])
                    response = kept.getresponse()
                    value = json.loads(response.read())
                    assert response.status == 200 and value['result']['echo'] == payload
                    assert response.getheader('Connection') == (
                        'keep-alive' if index < 15 else 'close'
                    )
                    warm.append(time.monotonic() - start)
                assert len(set(ports)) == 1 and kept.sock is None
            finally:
                kept.close()
            report['reuse'] = dict(
                requests=16, connections=1, warm_median_ms=statistics.median(warm[1:]) * 1000
            )
            for fault in ('malformed', 'idle'):
                kept = http.client.HTTPSConnection(
                    '127.0.0.1', services['candidate'][0].server_port, context=trust, timeout=5
                )
                try:
                    kept.request(
                        'POST',
                        '/v1/work',
                        b'{}',
                        {'Content-Type': 'application/json', 'Connection': 'keep-alive'},
                    )
                    response = kept.getresponse()
                    response.read()
                    assert response.getheader('Connection') == 'keep-alive'
                    if fault == 'malformed':
                        kept.request(
                            'POST',
                            '/v1/work',
                            b'{"x":1,"x":2}',
                            {'Content-Type': 'application/json', 'Connection': 'keep-alive'},
                        )
                        response = kept.getresponse()
                        response.read()
                        assert (
                            response.status == 400
                            and response.getheader('Connection') == 'close'
                            and kept.sock is None
                        )
                    else:
                        time.sleep(2.2)
                        assert kept.sock.recv(1) == b''
                finally:
                    kept.close()
            # Round-robin paired runs reduce drift from unrelated machine load.
            elapsed = {name: [] for name in classes}
            for index in range(40):
                for name in list(classes) if index % 2 else list(reversed(classes)):
                    status, value, seconds = request(name)
                    assert status == 200 and value == dict(ok=True, result={'echo': {}})
                    elapsed[name].append(seconds)
            for name, values in elapsed.items():
                report['cases'].append(
                    dict(
                        name=name,
                        samples=len(values),
                        median_ms=statistics.median(values) * 1000,
                        p95_ms=sorted(values)[int(len(values) * 0.95) - 1] * 1000,
                    )
                )
            # Responses at the request bound still arrive intact. This payload
            # remains below the response bound after the fixture's envelope.
            payload = {'padding': 'x' * 15000}
            status, value, _ = request('candidate', json.dumps(payload).encode())
            assert status == 200 and value['result']['echo'] == payload
            before = len(received)
            status, value, _ = request('candidate', b'{"x":1,"x":2}')
            assert status == 400 and value['retryable'] is False and len(received) == before
            status, value, _ = request('candidate', b'{}', {'Content-Type': 'text/plain'})
            assert status == 400 and len(received) == before
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
                responses = list(executor.map(lambda _: request('candidate'), range(64)))
            assert all(status == 200 for status, _, _ in responses), {
                'latency': report['cases'],
                'responses': [(status, value) for status, value, _ in responses if status != 200],
            }
            server = services['candidate'][0]
            # Existing admission limits remain exact and reusable.
            acquired = []
            try:
                while server.slots.acquire(False):
                    acquired.append(True)
                assert len(acquired) == 32
            finally:
                for _ in acquired:
                    server.slots.release()
            assert all(server.allow('qualification', 'register') for _ in range(4))
            assert not server.allow('qualification', 'register')
            assert all(server.allow('qualification', 'work') for _ in range(400))
            assert not server.allow('qualification', 'work')
            report.update(
                status='PASS',
                concurrent_requests=64,
                connection_slots=32,
                maximum_response_integrity=True,
                malformed_input_refused=True,
                rate_limits_preserved=True,
            )
        finally:
            for server, thread in services.values():
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
            ipc.shutdown()
            ipc.server_close()
        print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
