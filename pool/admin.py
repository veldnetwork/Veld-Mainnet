"""Loopback-only HTTPS operator UI; isolated UID, fixed private IPC capabilities.

Access remotely with an authenticated SSH local forward. This listener must
never be reverse-proxied through the public pool gateway. It has no node RPC
credential, wallet key, signing subprocess, file-edit or shell capability.
"""

import argparse
import hashlib
import hmac
import http.server
import ipaddress
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import stat
import threading
import time

from .gateway import Gateway
from .private_file import read_private
from .protocol import decode, encode, require, schema, Refused, units

COOKIE = '__Host-veld-pool-operator'


def password_record(password):
    require(
        type(password) is str and 16 <= len(password) <= 256,
        'use a 16 to 256 character admin passphrase',
    )
    salt = secrets.token_bytes(16)
    value = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=16384, r=8, p=1, dklen=64)
    return dict(version=1, salt=salt.hex(), hash=value.hex())


def credential(path):
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    )
    try:
        meta = os.fstat(descriptor)
        require(
            stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_size <= 1024,
            'admin credential file',
        )
        if os.name != 'nt':
            require(
                meta.st_uid in (0, os.geteuid()) and meta.st_mode & 0o077 == 0,
                'admin credential owner/mode',
            )
        record = decode(os.read(descriptor, 1025), 1024)
        schema(record, ('version', 'salt', 'hash'))
        require(
            type(record['version']) is int and record['version'] == 1, 'admin credential version'
        )
        for key, length in (('salt', 32), ('hash', 128)):
            require(
                type(record[key]) is str
                and re.fullmatch('[a-f0-9]{' + str(length) + '}', record[key]),
                'admin credential encoding',
            )
        return record, hashlib.sha256(encode(record)).hexdigest()
    finally:
        os.close(descriptor)


class AdminServer(Gateway):
    def __init__(self, bind, context, ipc, credential_file):
        require(ipaddress.ip_address(bind[0]).is_loopback, 'operator HTTPS must bind loopback')
        self.context, self.ipc, self.credential_file = context, str(ipc), str(credential_file)
        credential(self.credential_file)  # Refuse a broken initial credential.
        self.slots = threading.BoundedSemaphore(8)
        self.login_slot = threading.BoundedSemaphore(1)
        self.rate_lock = threading.Lock()
        self.rate = {}
        self.session_lock = threading.Lock()
        self.sessions = {}
        http.server.ThreadingHTTPServer.__init__(self, bind, AdminHandler)
        host = '[' + bind[0] + ']' if ':' in bind[0] else bind[0]
        self.authority = host + ':' + str(self.server_port)
        self.origin = 'https://' + self.authority

    def allow(self, address, action):
        with self.rate_lock:
            now = time.monotonic()
            key = (address, action)
            self.rate = {k: v for k, v in self.rate.items() if now - v[0] < 60}
            if key not in self.rate:
                if len(self.rate) >= 32:
                    return False
                self.rate[key] = (now, 0)
            start, count = self.rate[key]
            if count >= ({'login': 5, 'write': 20}.get(action, 120)):
                return False
            self.rate[key] = (start, count + 1)
            return True

    def login(self, password):
        require(type(password) is str and 16 <= len(password) <= 256, 'sign-in refused')
        if not self.login_slot.acquire(False):
            raise Refused('sign-in busy')
        try:
            record, digest = credential(self.credential_file)
            value = hashlib.scrypt(
                password.encode('utf-8'),
                salt=bytes.fromhex(record['salt']),
                n=16384,
                r=8,
                p=1,
                dklen=64,
            )
            require(hmac.compare_digest(value.hex(), record['hash']), 'sign-in refused')
            now = time.monotonic()
            with self.session_lock:
                self.sessions = {
                    k: v
                    for k, v in self.sessions.items()
                    if now - v['seen'] < 900
                    and now - v['created'] < 28800
                    and v['credential'] == digest
                }
                require(len(self.sessions) < 32, 'session capacity')
                token = secrets.token_hex(32)
                session = dict(csrf=secrets.token_hex(32), credential=digest, created=now, seen=now)
                self.sessions[hashlib.sha256(token.encode()).hexdigest()] = session
            return token, dict(session)
        finally:
            self.login_slot.release()

    def session(self, token):
        # Rotation, deletion and malformed replacement invalidate existing
        # sessions before any IPC command. Never fall back to a cached verifier.
        try:
            _, digest = credential(self.credential_file)
        except (OSError, Refused):
            with self.session_lock:
                self.sessions.clear()
            raise
        require(type(token) is str and re.fullmatch('[a-f0-9]{64}', token), 'sign-in required')
        key = hashlib.sha256(token.encode()).hexdigest()
        now = time.monotonic()
        with self.session_lock:
            value = self.sessions.get(key)
            if (
                not value
                or value['credential'] != digest
                or now - value['seen'] >= 900
                or now - value['created'] >= 28800
            ):
                self.sessions.pop(key, None)
                raise PermissionError('sign-in required')
            value['seen'] = now
            return dict(value)

    def logout(self, token):
        with self.session_lock:
            self.sessions.pop(hashlib.sha256(token.encode()).hexdigest(), None)


class AdminHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'VeldPoolOperator/1'
    sys_version = ''

    def log_message(self, *args):
        pass

    def reply(self, status, value, content_type='application/json', cookie=None):
        raw = encode(value) if content_type == 'application/json' else value
        self.send_response(status)
        headers = {
            'Content-Type': content_type,
            'Content-Length': str(len(raw)),
            'Connection': 'close',
            'Cache-Control': 'no-store',
            'Referrer-Policy': 'no-referrer',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
        }
        if cookie:
            headers['Set-Cookie'] = cookie
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.close_connection = True
        try:
            self.wfile.write(raw)
        except (OSError, TimeoutError):
            pass

    def host(self):
        require(self.headers.get_all('Host') == [self.server.authority], 'operator host mismatch')
        require(not self.headers.get_all('Transfer-Encoding'), 'HTTP framing')
        site = self.headers.get_all('Sec-Fetch-Site', [])
        require(not site or site in (['same-origin'], ['none']), 'cross-site request refused')

    def token(self):
        values = self.headers.get_all('Cookie', [])
        require(len(values) == 1, 'sign-in required')
        matches = re.findall(
            r'(?:^|;\s*)' + re.escape(COOKIE) + r'=([a-f0-9]{64})(?=;|$)', values[0]
        )
        require(len(matches) == 1, 'sign-in required')
        return matches[0]

    def ipc(self, action, payload, session):
        actor = 'operator:' + session['credential'][:16]
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(15)
            conn.connect(self.server.ipc)
            conn.sendall(encode(dict(action=action, payload=payload, actor=actor)) + b'\n')
            with conn.makefile('rb') as file:
                response = decode(file.readline(65537), 65536)
        require(type(response.get('ok')) is bool, 'operator service response')
        return response

    def do_GET(self):
        try:
            self.host()
            require(not self.headers.get_all('Content-Length'), 'unexpected GET body')
            if not self.server.allow(self.client_address[0], 'read'):
                self.reply(429, dict(ok=False, error='Too many requests. Wait one minute.'))
                return
            assets = {
                '/': ('index.html', 'text/html; charset=utf-8'),
                '/admin.css': ('admin.css', 'text/css; charset=utf-8'),
                '/admin.js': ('admin.js', 'application/javascript; charset=utf-8'),
            }
            if self.path in assets:
                name, kind = assets[self.path]
                self.reply(200, (Path(__file__).parent / 'admin_web' / name).read_bytes(), kind)
                return
            if self.path != '/api/session' and not re.fullmatch(
                r'/api/snapshot\?before=(0|[1-9][0-9]{0,18})', self.path
            ):
                self.reply(404, dict(ok=False, error='Not found.'))
                return
            try:
                session = self.server.session(self.token())
            except (Refused, PermissionError):
                self.reply(401, dict(ok=False, error='Sign in to continue.'))
                return
            if self.path == '/api/session':
                self.reply(200, dict(ok=True, result={'csrf': session['csrf']}))
                return
            self.reply(200, self.ipc('snapshot', {'before': self.path.split('=')[1]}, session))
        except Refused:
            self.reply(400, dict(ok=False, error='Request refused.'))
        except (OSError, TimeoutError):
            self.reply(503, dict(ok=False, error='Operator service unavailable.'))

    def do_POST(self):
        try:
            self.host()
            require(
                self.path in ('/api/login', '/api/logout', '/api/settings', '/api/reconcile'),
                'operator endpoint',
            )
            require(
                self.headers.get_all('Origin') == [self.server.origin],
                'same-origin request required',
            )
            require(
                self.headers.get_all('Content-Type') == ['application/json'],
                'JSON content type required',
            )
            lengths = self.headers.get_all('Content-Length', [])
            require(
                len(lengths) == 1
                and re.fullmatch('[1-9][0-9]{0,3}', lengths[0])
                and int(lengths[0]) <= 4096,
                'request body limit',
            )
            if not self.server.allow(
                self.client_address[0], 'login' if self.path == '/api/login' else 'write'
            ):
                self.reply(429, dict(ok=False, error='Too many attempts. Wait one minute.'))
                return
            value = decode(self.rfile.read(int(lengths[0])), 4096)
            if self.path == '/api/login':
                schema(value, ('password',))
                try:
                    token, session = self.server.login(value['password'])
                except Refused:
                    self.reply(401, dict(ok=False, error='Sign-in refused.'))
                    return
                self.reply(
                    200,
                    dict(ok=True, result={'csrf': session['csrf']}),
                    cookie=COOKIE
                    + '='
                    + token
                    + '; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800',
                )
                return
            try:
                token = self.token()
                session = self.server.session(token)
            except (Refused, PermissionError):
                self.reply(401, dict(ok=False, error='Sign in to continue.'))
                return
            csrf = self.headers.get_all('X-CSRF-Token', [])
            require(
                len(csrf) == 1
                and re.fullmatch('[a-f0-9]{64}', csrf[0])
                and hmac.compare_digest(csrf[0], session['csrf']),
                'CSRF check failed',
            )
            if self.path == '/api/logout':
                schema(value, ())
                self.server.logout(token)
                self.reply(
                    200,
                    dict(ok=True, result={}),
                    cookie=COOKIE + '=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0',
                )
                return
            response = self.ipc(self.path.rsplit('/', 1)[1], value, session)
            self.reply(200 if response['ok'] else 409, response)
        except Refused:
            self.reply(
                400, dict(ok=False, error='Request refused. Check the form and reload if needed.')
            )
        except (OSError, TimeoutError):
            self.reply(
                503,
                dict(
                    ok=False,
                    error='Response unavailable. Retry the same request; do not create a replacement.',
                ),
            )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    cfg = decode(read_private(args.config, 16384))
    schema(
        cfg, ('host', 'port', 'certificate', 'private_key', 'operator_socket', 'credential_file')
    )
    require(type(cfg['port']) is int and 1024 < cfg['port'] <= 65535, 'operator HTTPS port')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cfg['certificate'], cfg['private_key'])
    with AdminServer(
        (cfg['host'], cfg['port']), context, cfg['operator_socket'], cfg['credential_file']
    ) as server:

        def shutdown(*_):
            threading.Thread(target=server.shutdown, daemon=True).start()

        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGTERM, shutdown)
        server.serve_forever(poll_interval=0.25)


if __name__ == '__main__':
    main()
