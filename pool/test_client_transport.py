"""Native transport fault tests against disposable loopback TLS fixtures.
These do not demonstrate mining, signatures, payouts, or GUI operation.
"""

import argparse
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--openssl', default='openssl')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for name in ('trusted', 'other', 'wrong-host'):
            subject = 'localhost' if name != 'wrong-host' else 'not-the-requested-host.invalid'
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
                    '/CN=' + subject,
                    '-addext',
                    'subjectAltName=DNS:' + subject + ',IP:127.0.0.1',
                ],
                capture_output=True,
                check=True,
            )
        body = b'{"ok":true,"result":{}}'
        normal = (
            b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '
            + str(len(body)).encode()
            + b'\r\n\r\n'
            + body
        )
        cases = [
            ('trusted TLS IP identity', 'trusted', 'trusted', normal, True, True),
            ('localhost IPv6 to IPv4 fallback', 'trusted', 'trusted', normal, True, True),
            ('wrong trust root', 'trusted', 'other', normal, False, False),
            ('wrong certificate hostname', 'wrong-host', 'wrong-host', normal, False, False),
            (
                'duplicate content length',
                'trusted',
                'trusted',
                normal.replace(b'Content-Length:', b'Content-Length: 22\r\nContent-Length:'),
                False,
                True,
            ),
            (
                'transfer encoding',
                'trusted',
                'trusted',
                normal.replace(b'Content-Type:', b'Transfer-Encoding: chunked\r\nContent-Type:'),
                False,
                True,
            ),
            (
                'oversized advertised body',
                'trusted',
                'trusted',
                normal.replace(str(len(body)).encode() + b'\r\n\r\n', b'99999999\r\n\r\n'),
                False,
                True,
            ),
            (
                'redirect refused',
                'trusted',
                'trusted',
                normal.replace(b'200 OK', b'302 Found'),
                False,
                True,
            ),
            (
                'wrong JSON shape',
                'trusted',
                'trusted',
                normal[: -len(body)] + b'[' + b' ' * (len(body) - 2) + b']',
                False,
                True,
            ),
        ]
        expected_retries = {}
        # TLS authenticates the endpoint, but a reverse proxy may return HTML
        # instead of the gateway's JSON during a temporary outage. It must not
        # be accepted as work, and it must not permanently stop the worker.
        for status in (
            408,
            425,
            429,
            500,
            502,
            503,
            504,
            520,
            521,
            522,
            523,
            524,
            525,
            526,
            527,
            530,
        ):
            name = f'proxy transient {status}'
            response = (
                f'HTTP/1.1 {status} Temporary failure\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n'
                '8\r\n<remote>\r\n0\r\n\r\n'
            ).encode()
            cases.append((name, 'trusted', 'trusted', response, False, True))
            expected_retries[name] = (
                'pool rate limit; retrying'
                if status == 429
                else 'pool service temporarily unavailable'
            )
        for status in (200, 301, 302, 400, 401, 403, 404, 409, 422):
            response = (
                f'HTTP/1.1 {status} Refused\r\nContent-Type: text/html\r\nContent-Length: 8\r\n\r\n<remote>'
            ).encode()
            cases.append(
                (f'non-transient HTML {status}', 'trusted', 'trusted', response, False, True)
            )
        proxy = b'HTTP/1.1 503 Unavailable\r\nContent-Type: text/html\r\nContent-Length: 8\r\n\r\n<remote>'
        cases.append(('untrusted proxy error', 'trusted', 'other', proxy, False, False))
        cases.append(
            (
                'duplicate proxy headers',
                'trusted',
                'trusted',
                proxy.replace(b'Content-Length:', b'Content-Length: 8\r\nContent-Length:'),
                False,
                True,
            )
        )
        cases.append(
            (
                'invalid proxy header framing',
                'trusted',
                'trusted',
                proxy.replace(b'Content-Type:', b'Content Type:'),
                False,
                True,
            )
        )
        for name, status, error, expected in (
            ('bounded work retry', 200, 'busy', 'pool work temporarily unavailable'),
            ('bounded rate retry', 429, 'busy', 'pool rate limit; retrying'),
            (
                'untrusted retry text',
                503,
                '<untrusted remote message>',
                'pool service temporarily unavailable',
            ),
        ):
            import json

            retry_body = json.dumps(dict(ok=False, error=error, retryable=True)).encode()
            response = (
                f'HTTP/1.1 {status} Retry\r\nContent-Type: application/json\r\nContent-Length: {len(retry_body)}\r\n\r\n'
            ).encode() + retry_body
            cases.append((name, 'trusted', 'trusted', response, False, True))
            expected_retries[name] = expected
        for name, certificate, ca, response, success, sent in cases:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root / (certificate + '.crt'), root / (certificate + '.key'))
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(10)
            requests = []
            failures = []

            def serve():
                try:
                    connection, _ = listener.accept()
                    connection.settimeout(5)
                    with context.wrap_socket(connection, server_side=True) as tls:
                        request = b''
                        while b'\r\n\r\n' not in request:
                            request += tls.recv(2048)
                            if len(request) > 16384:
                                raise AssertionError('request framing')
                        requests.append(request)
                        tls.sendall(response)
                except ssl.SSLError:
                    pass  # Expected on certificate rejection.
                except Exception as error:
                    failures.append(repr(error))
                finally:
                    listener.close()

            thread = threading.Thread(target=serve)
            thread.start()
            host = (
                'localhost'
                if certificate == 'wrong-host' or name.startswith('localhost')
                else '127.0.0.1'
            )
            try:
                result = subprocess.run(
                    [
                        args.binary,
                        'https://' + host + ':' + str(listener.getsockname()[1]),
                        str(root / (ca + '.crt')),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=25,
                )
            except subprocess.TimeoutExpired as error:
                print(
                    'TIMEOUT',
                    name,
                    'requests',
                    len(requests),
                    'server failures',
                    failures,
                    'output',
                    error.stdout,
                    'errors',
                    error.stderr,
                    flush=True,
                )
                raise
            thread.join(timeout=12)
            assert not thread.is_alive() and not failures, (name, failures)
            assert (result.returncode == 0) == success, (
                name,
                result.returncode,
                result.stdout,
                result.stderr,
            )
            assert bool(requests) == sent, (name, 'credentials sent before TLS authentication')
            if name in expected_retries:
                assert (
                    result.returncode == 2
                    and result.stdout.strip() == 'RETRY ' + expected_retries[name]
                ), (name, result.stdout)
            elif not success:
                assert result.returncode == 1, (
                    name,
                    'unsafe response must be refused, not retried',
                    result.stdout,
                )
            print('PASS', name)
        print('PASS native TLS transport fault suite; no mining claim')


if __name__ == '__main__':
    main()
