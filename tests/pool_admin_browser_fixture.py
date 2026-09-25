"""Disposable loopback admin service for real browser/API/IPC qualification.
Uses explicit isolated chain fixtures, not a production wallet or daemon.
"""

import argparse, json, pathlib, sys, time

source = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(source))
from pool.test_admin import AdminTests

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=pathlib.Path, required=True)
args = parser.parse_args()
out = args.output.resolve()
if out.is_relative_to(source):
    raise ValueError('output must be outside source')
out.mkdir(parents=True, exist_ok=False)
stop = out / 'stop.request'
if stop.exists():
    raise RuntimeError('use a new fixture output, not stale stop state')
test = AdminTests('test_real_transport_policy_commit_restart_safe_retries_and_reconcile')
test.setUp()
try:
    (out / 'ready.json').write_text(
        json.dumps(
            dict(
                origin=test.server.origin,
                scope='disposable real admin HTTPS and IPC; fixture chain only',
            )
        )
    )
    deadline = time.monotonic() + 300
    while not stop.exists() and time.monotonic() < deadline:
        test.operator.reconcile()
        test.pool.last_healthy = time.monotonic()
        time.sleep(0.2)
    (out / 'server-result.json').write_text(
        json.dumps(
            dict(
                revision=test.operator.revision,
                audit=list(test.operator.audit.values()),
                settings=test.operator.settings,
                broadcasts=len(test.pool.node.broadcasts),
                payment_intents=len(test.pool.payments.intents),
            ),
            indent=2,
        )
    )
finally:
    test.tearDown()
