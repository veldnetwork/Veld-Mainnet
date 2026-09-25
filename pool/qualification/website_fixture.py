"""Loopback TLS UI qualification. Synthetic accounting fixtures, no chain or signing.
Uses actual candidate Coordinator, Payments, Gateway and read-only public projection.
This is a website/API exercise, not native economic qualification.
"""

import argparse, json, pathlib, socket, ssl, subprocess, tempfile, threading, time, sys, signal
from types import SimpleNamespace
from pool.gateway import Gateway
from pool.coordinator import Coordinator
from pool.payments import Payments
from pool.journal import Journal
from pool.accounting import text
from fractions import Fraction

p = argparse.ArgumentParser()
p.add_argument('--output', type=pathlib.Path, required=True)
p.add_argument('--port', type=int, default=34647)
args = p.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
temp = tempfile.TemporaryDirectory(prefix='veld-pool-web-')
root = pathlib.Path(temp.name)
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
        str(root / 'key'),
        '-out',
        str(root / 'cert'),
        '-subj',
        '/CN=localhost',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
    ],
    check=True,
    capture_output=True,
)
j = Journal(root / 'data', root / 'anchor/current.json')
pj = Journal(root / 'payments', root / 'payment-anchor/current.json')
node = SimpleNamespace(
    check_chain=lambda: None, genesis='a' * 64, call=lambda *_: {'isvalid': True}
)
pool = Coordinator(node, j, None, 'pool', '0' * 60 + 'ffff')
account = pool.register('V' + 'a' * 33)
other = pool.register('V' + 'b' * 33)
pool.payments = Payments(
    pool,
    pj,
    'unused-native-helper',
    'unused-pool-key',
    'unused-fee-key',
    '51',
    '52',
    'V' + 'c' * 33,
    100000,
    1000,
)
for n, amount in [(8997, 156969696), (8999, 156969696), (9011, 156969696), (9154, 156969696)]:
    pool.record(
        'income',
        dict(
            id=f'{n:064x}',
            height=n,
            amount=str(amount),
            category='mining',
            state='pending' if n == 9154 else 'available',
            credits={
                account['account']: text(Fraction(amount * 3, 4)),
                other['account']: text(Fraction(amount, 4)),
            },
        ),
    )
for n, category, amount in [
    (9080, 'comine_payout', 5252000000),
    (9120, 'staking_distribution', 8118000000),
]:
    pool.record(
        'income',
        dict(
            id=f'{n:064x}',
            height=n,
            amount=str(amount),
            category=category,
            state='available',
            credits={account['account']: str(amount * 3 // 4), other['account']: str(amount // 4)},
        ),
    )
for n in range(23):
    identity = f'p{n}'
    pool.payments.record(
        'payment_intent',
        dict(
            id=identity,
            created=1789962000 + n,
            wire='not-signed-ui-fixture',
            deductions={account['account']: '100000000'},
            state='reserved',
        ),
    )
    pool.payments.record(
        'payment_signed',
        dict(
            id=identity,
            txid=f'{n + 10000:064x}',
            state='signed',
            signed_hex='not-signed-ui-fixture',
        ),
    )
    pool.payments.record('payment_state', dict(id=identity, state='confirmed'))
pool.income_tip = (9159, 'b' * 64)
clock = [1000.0]
from pool.overview import WorkOverview

pool.public_work = WorkOverview(lambda: clock[0])
clock[0] = 1540.0
for _ in range(840):
    pool.public_work.add(f'{(1 << 256) // 1250:064x}')
clock[0] = 1600.0
pool.verified_counts = {account['account']: 76348, other['account']: 24395}
ipc = socket.socket(socket.AF_UNIX)
ipc.bind(str(root / 'ipc'))
ipc.listen(8)
stop = threading.Event()


def handle():
    while not stop.is_set():
        try:
            connection, _ = ipc.accept()
        except OSError:
            break
        try:
            with connection, connection.makefile('rb') as f:
                req = json.loads(f.readline(16385))
                action = req['action']
                payload = req['payload']
                try:
                    if action == 'health':
                        pool.last_healthy = time.monotonic()
                        pool.active_accounts = {
                            account['account']: time.monotonic(),
                            other['account']: time.monotonic(),
                        }
                        result = pool.health()
                    elif action == 'account':
                        result = pool.account(payload['account'], payload['token'])
                    elif action == 'history':
                        result = pool.history(
                            payload['account'], payload['token'], int(payload['before'])
                        )
                    else:
                        raise ValueError('UI fixture exposes reads only')
                    response = dict(ok=True, result=result)
                except Exception:
                    response = dict(ok=False, error='refused', retryable=False)
                connection.sendall(json.dumps(response).encode() + b'\n')
        except (OSError, ValueError):
            pass


threading.Thread(target=handle, daemon=True).start()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain(root / 'cert', root / 'key')
server = Gateway(('127.0.0.1', args.port), ctx, str(root / 'ipc'))
# Only disposable viewing access is exported; never any production credentials.
(args.output / 'fixture-access.json').write_text(
    json.dumps(
        {
            'endpoint': 'https://localhost:' + str(args.port),
            'account': account['account'],
            'token': account['view_token'],
        }
    )
)
(args.output / 'fixture-ca.crt').write_bytes((root / 'cert').read_bytes())
(args.output / 'fixture-scope.json').write_text(
    json.dumps(
        {
            'synthetic': True,
            'chain_connected': False,
            'signing_performed': False,
            'production_changed': False,
            'port': args.port,
            'source': str(pathlib.Path(__file__).resolve()),
        }
    )
)
print('WEBSITE_FIXTURE_READY https://localhost:' + str(args.port), flush=True)


def shutdown(*_):
    threading.Thread(target=server.shutdown, daemon=True).start()


signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)


def stop_file():
    while not stop.wait(0.2):
        if (args.output / 'stop-fixture').exists():
            shutdown()
            return


threading.Thread(target=stop_file, daemon=True).start()
try:
    server.serve_forever(0.2)
finally:
    stop.set()
    server.server_close()
    ipc.close()
    j.close()
    pj.close()
    temp.cleanup()
