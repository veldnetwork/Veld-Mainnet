"""Real HTTPS -> authenticated private IPC -> coordinator journal integration.
Disposable chain fixtures only. Never starts mining or contacts a real node.
"""

import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pool.admin import AdminServer, password_record, COOKIE
from pool.protocol import encode, decode, Refused
from pool.service import Server, dispatch
from pool.test_operator import fixture


class AdminTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.pool, self.operator, self.pj = fixture(self.root, 10000)
        self.ipc = Server(str(self.root / 'operator.sock'), self.pool, os.geteuid())
        self.ipct = threading.Thread(target=self.ipc.serve_forever)
        self.ipct.start()
        self.password = 'isolated-panel-only-disposable-password'
        self.creds = self.root / 'credential.json'
        self.creds.write_bytes(encode(password_record(self.password)))
        self.creds.chmod(0o600)
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
                str(self.root / 'key.pem'),
                '-out',
                str(self.root / 'cert.pem'),
                '-subj',
                '/CN=localhost',
                '-addext',
                'subjectAltName=IP:127.0.0.1',
            ],
            check=True,
            capture_output=True,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(self.root / 'cert.pem', self.root / 'key.pem')
        self.server = AdminServer(
            ('127.0.0.1', 0), context, self.root / 'operator.sock', self.creds
        )
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.context = ssl.create_default_context(cafile=str(self.root / 'cert.pem'))
        self.cookie = None
        self.csrf = None

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.ipc.shutdown()
        self.ipc.server_close()
        self.ipct.join()
        self.pool.journal.close()
        self.pj.close()
        self.tmp.cleanup()

    def request(self, path, body=None, headers=None, raw=None):
        h = {'Origin': self.server.origin, 'Content-Type': 'application/json'}
        if self.cookie:
            h['Cookie'] = self.cookie
        if self.csrf:
            h['X-CSRF-Token'] = self.csrf
        h.update(headers or {})
        connection = http.client.HTTPSConnection(
            '127.0.0.1', self.server.server_port, context=self.context, timeout=5
        )
        connection.request(
            'POST' if body is not None or raw is not None else 'GET',
            path,
            raw if raw is not None else encode(body) if body is not None else None,
            h,
        )
        response = connection.getresponse()
        data = response.read()
        result = (response.status, dict(response.getheaders()), data)
        connection.close()
        return result

    def login(self):
        code, headers, raw = self.request('/api/login', {'password': self.password})
        self.assertEqual(code, 200)
        self.cookie = headers['Set-Cookie'].split(';')[0]
        self.csrf = decode(raw)['result']['csrf']
        for flag in ('Secure', 'HttpOnly', 'SameSite=Strict', 'Path=/'):
            self.assertIn(flag, headers['Set-Cookie'])

    def settings(self, request_id='1' * 32, revision='0', **changes):
        return dict(
            request_id=request_id,
            revision=revision,
            reason='Isolated browser integration',
            settings=dict(self.operator.settings, **changes),
        )

    def test_real_transport_policy_commit_restart_safe_retries_and_reconcile(self):
        self.assertEqual(self.request('/api/snapshot?before=0')[0], 401)
        self.login()
        body = self.settings(minimum_units='200000000', batch_seconds='7200', fee_ppm='10000')
        for _ in range(2):
            self.assertEqual(self.request('/api/settings', body)[0], 200)
        self.assertEqual(self.operator.revision, 1)
        self.assertEqual(len(self.operator.audit), 1)
        snapshot = decode(self.request('/api/snapshot?before=0')[2])['result']
        self.assertEqual(snapshot['settings']['minimum_units'], '200000000')
        for secret in ('worker_hash', 'pool_seed', 'signed_hex', 'view_hash'):
            self.assertNotIn(secret, json.dumps(snapshot))
        self.assertEqual(self.request('/api/settings', self.settings('2' * 32))[0], 409)
        self.assertEqual(
            self.request(
                '/api/reconcile',
                dict(request_id='3' * 32, revision='1', reason='Canonical fixture check'),
            )[0],
            200,
        )
        self.operator.reconcile()
        self.assertEqual(self.operator.snapshot()['audit'][0]['status'], 'completed')
        self.assertEqual(self.pool.node.broadcasts, [])
        self.assertEqual(self.request('/api/logout', {})[0], 200)
        self.assertEqual(self.request('/api/snapshot?before=0')[0], 401)

    def test_host_origin_csrf_json_and_cross_role_boundaries(self):
        self.login()
        body = self.settings()
        for headers in (
            {'Origin': 'https://attacker.invalid'},
            {'Origin': 'null'},
            {'Host': 'attacker.invalid'},
            {'X-CSRF-Token': 'wrong'},
            {'Sec-Fetch-Site': 'cross-site'},
        ):
            self.assertEqual(self.request('/api/settings', body, headers)[0], 400)
        self.assertEqual(
            self.request('/api/settings', raw=b'{"request_id":"a","request_id":"b"}')[0], 400
        )
        self.assertEqual(self.request('/api/settings', raw=b'x' * 4097)[0], 400)
        self.assertEqual(self.operator.revision, 0)
        for path in ('/../credential.json', '/v1/work', '/jsonrpc', '/api/snapshot?before=-1'):
            self.assertEqual(self.request(path)[0], 404)
        for request in (
            dict(action='settings', payload=body),
            dict(action='snapshot', payload={'before': '0'}),
        ):
            with self.assertRaises(Refused):
                dispatch(self.pool, request)
        headers = self.request('/')[1]
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertNotIn('Access-Control-Allow-Origin', headers)

    def test_password_rotation_missing_malformed_and_expired_sessions_fail_closed(self):
        self.login()
        original = self.creds.read_bytes()
        self.creds.write_bytes(encode(password_record('different-isolated-admin-password')))
        self.assertEqual(self.request('/api/settings', self.settings())[0], 401)
        self.creds.write_bytes(original)
        self.login()
        self.creds.unlink()
        self.assertEqual(self.request('/api/settings', self.settings())[0], 503)
        self.creds.write_bytes(original)
        self.creds.chmod(0o600)
        self.assertEqual(
            self.request('/api/settings', self.settings())[0], 401
        )  # no cached session survives absence
        self.login()
        self.creds.write_bytes(b'{}')
        self.assertEqual(self.request('/api/settings', self.settings())[0], 401)
        self.creds.write_bytes(original)
        self.login()
        for session in self.server.sessions.values():
            session['seen'] -= 901
        self.assertEqual(self.request('/api/settings', self.settings())[0], 401)
        self.assertEqual(self.operator.revision, 0)

    def test_bounded_login_attempts_and_distinct_ipc_uid(self):
        for _ in range(5):
            self.assertEqual(
                self.request('/api/login', {'password': 'invalid-but-long-test-password'})[0], 401
            )
        self.assertEqual(self.request('/api/login', {'password': self.password})[0], 429)
        self.ipc.operator_uid = os.geteuid() + 1
        with socket.socket(socket.AF_UNIX) as connection:
            connection.connect(str(self.root / 'operator.sock'))
            connection.sendall(
                encode(
                    dict(action='snapshot', payload={'before': '0'}, actor='operator:' + 'a' * 16)
                )
                + b'\n'
            )
            self.assertFalse(decode(connection.recv(4096))['ok'])
        self.assertEqual(self.operator.revision, 0)

    def test_public_listener_refused(self):
        with self.assertRaisesRegex(Refused, 'loopback'):
            AdminServer(('0.0.0.0', 0), None, self.root / 'operator.sock', self.creds)


if __name__ == '__main__':
    unittest.main(verbosity=2)
