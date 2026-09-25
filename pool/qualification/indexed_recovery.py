"""Actual retained-intent recovery on a cloned disposable failed native chain."""

import argparse, datetime, hashlib, json, pathlib, shutil, subprocess, sys, tempfile, time, traceback

S = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S))
from pool.backend import Node
from pool.protocol import Busy, Refused, encode
from pool.qualification.control import mine_block
from pool.qualification.build import hashes
from pool.qualification.progress import ValidationProgress
from pool.qualification.isolation import require_isolated_network

require_isolated_network()
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
parser = argparse.ArgumentParser()
parser.add_argument('--build', type=pathlib.Path, required=True)
parser.add_argument('--output', type=pathlib.Path, required=True)
parser.add_argument('--fixture', type=pathlib.Path, required=True)
parser.add_argument('--fixture-build', type=pathlib.Path, required=True)
parser.add_argument('--aged', action='store_true')
args = parser.parse_args()
original = args.fixture.resolve()
assert original.is_relative_to('/var/tmp'), (
    'only an explicitly supplied disposable fixture is permitted'
)
for proc in pathlib.Path('/proc').iterdir():
    if not proc.name.isdigit():
        continue
    try:
        process_args = (proc / 'cmdline').read_bytes().split(b'\0')
    except (OSError, PermissionError):
        continue
    assert str(original / 'node').encode() not in process_args, 'original fixture running'
out = args.output
out.mkdir(parents=True, exist_ok=False)
state = pathlib.Path(tempfile.mkdtemp(prefix='veld-pool-indexed-recovery-', dir='/var/tmp'))
shutil.copytree(original, state, dirs_exist_ok=True, ignore=shutil.ignore_patterns('*.sock'))
shutil.copytree(original / 'node', state / 'independent')
build = args.build
built = json.loads((build / 'result.json').read_text())
before = hashes()
assert built['status'] == 'PASS' and built['source_unchanged'] and built['source_hashes'] == before
assert not built['production_build']
for name, digest in built['binaries'].items():
    assert hashlib.sha256((build / name).read_bytes()).hexdigest() == digest
settings = json.loads((state / 'coordinator.json').read_text())
old_build = str(args.fixture_build.resolve())


def remap(value):
    if isinstance(value, str):
        return value.replace(str(original), str(state)).replace(old_build, str(build / 'existing'))
    if isinstance(value, dict):
        return {k: remap(v) for k, v in value.items()}
    if isinstance(value, list):
        return [remap(v) for v in value]
    return value


settings = remap(settings)
settings.update(rpc_url='http://127.0.0.1:32922')
(state / 'coordinator.json').write_bytes(encode(settings))
(state / 'coordinator.json').chmod(0o600)
report = dict(
    status='RUNNING',
    scope='native retained signed-payment recovery with operational index',
    mainnet_writes=False,
    production_build=False,
    complete_pool_gate=False,
    processes=[],
)
logs = []
processes = []


def events(folder):
    return [json.loads(line) for line in (folder / 'events.jsonl').read_text().splitlines()]


def saved_payments(folder):
    return {
        e['payload']['id']: e['payload'] for e in events(folder) if e['kind'] == 'payment_signed'
    }


old_signed = saved_payments(original / 'payments')
assert len(old_signed) == 1


def start(name, command, stdin=False):
    log = (out / (name + '.log')).open('w')
    logs.append(log)
    p = subprocess.Popen(
        command,
        cwd=S,
        stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    processes.append(p)
    report['processes'].append(dict(name=name, pid=p.pid))
    return p


def node(name, folder, peer, port):
    p = start(name, [str(build / 'existing/pool-backend'), str(folder), str(peer), str(port)], True)
    rpc = Node('http://127.0.0.1:' + str(port), folder / 'lab-rpc-token', settings['genesis'])
    until = time.monotonic() + 900
    while True:
        assert p.poll() is None
        try:
            rpc.check_chain()
            rpc.require_transaction_index()
            return p, rpc
        except (OSError, Busy):
            if time.monotonic() > until:
                raise
            time.sleep(0.25)


def save():
    temporary = out / 'result.json.new'
    temporary.write_text(json.dumps(report, indent=2) + '\n')
    temporary.replace(out / 'result.json')


try:
    save()
    primary, rpc = node('node', state / 'node', 32921, 32922)
    if args.aged:
        signed = next(iter(old_signed.values()))
        payment_tx = rpc.call('getrawtransaction', signed['txid'])
        target = payment_tx['block_height'] + 2017
        until = time.monotonic() + 2400
        while rpc.call('getblockcount') < target:
            if time.monotonic() > until:
                raise RuntimeError('genuine aged-payment history deadline')
            mine_block(primary, rpc, settings['payments']['fee_address'], out / 'node.log')
        try:
            rpc.call('gettransactionrecent', signed['txid'])
        except Refused as error:
            assert 'canonical range' in str(error), 'recent lookup failed for an unrelated reason'
        else:
            raise AssertionError('aged transaction unexpectedly inside recent range')
        assert rpc.call('getrawtransaction', signed['txid'])['raw_hex'] == signed['signed_hex']
        report.update(
            accelerated_historical_clock=True,
            real_pow_history=True,
            payment_age_blocks=target - payment_tx['block_height'],
            recent_lookup_refused=True,
            full_index_exact_signed_bytes_found=True,
        )
        save()
    observer, independent = node('independent', state / 'independent', 32931, 32932)
    observer.stdin.write('peer 32921\n')
    observer.stdin.flush()
    target_hash = rpc.call('getbestblockhash')
    wait = ValidationProgress(
        independent.call('getblockcount'), rpc.call('getblockcount'), time.monotonic()
    )
    report['validation_budget_seconds'] = wait.budget_seconds
    report['validation_progress'] = []
    while independent.call('getbestblockhash') != target_hash:
        height = independent.call('getblockcount')
        now = time.monotonic()
        report['validation_progress'].append(
            dict(height=height, elapsed_seconds=now - wait.started)
        )
        save()
        wait.observe(height, now)
        assert primary.poll() is None and observer.poll() is None, 'validation node exited'
        assert rpc.call('getbestblockhash') == target_hash, (
            'frozen recovery fixture unexpectedly advanced'
        )
        time.sleep(10)
    assert rpc.call('getbestblockhash') == independent.call('getbestblockhash')
    assert rpc.call('getstatedigest') == independent.call('getstatedigest')
    report['height'] = rpc.call('getblockcount')
    report['independent_chain_agreement'] = True
    save()
    service = start(
        'coordinator',
        [sys.executable, '-m', 'pool.service', '--config', str(state / 'coordinator.json')],
    )
    started = time.monotonic()
    until = started + 60
    while True:
        assert service.poll() is None, 'recovery coordinator exited'
        states = {}
        for event in events(state / 'payments'):
            if event['kind'] == 'payment_state':
                states[event['payload']['id']] = event['payload']
        if all(states.get(identity, {}).get('state') == 'confirmed' for identity in old_signed):
            break
        if time.monotonic() > until:
            raise RuntimeError('indexed retained-payment recovery deadline')
        time.sleep(0.25)
    report['recovery_seconds'] = time.monotonic() - started
    service.terminate()
    service.wait(timeout=60)
    assert saved_payments(state / 'payments') == old_signed, (
        'recovery changed or added a signed payment'
    )
    signed = next(iter(old_signed.values()))
    tx = independent.call('gettransaction', signed['txid'], states[signed['id']]['block_hash'])
    assert tx['raw_hex'] == signed['signed_hex']
    intent = next(e['payload'] for e in events(state / 'payments') if e['kind'] == 'payment_intent')
    recipients = {r['address']: int(r['units']) for r in intent['wire']['recipients']}
    actual = {
        address: sum(c['value_units'] for c in independent.call('listunspent', address))
        for address in recipients
    }
    assert actual == recipients, 'independent recipient balances differ'
    assert rpc.call('getblockcount') == report['height'], 'recovery unexpectedly mined blocks'
    assert hashes() == before
    report.update(
        status='PASS',
        same_exact_signed_transaction=True,
        new_economic_payments=0,
        recipient_wallet_units=actual,
        expected_wallet_units=recipients,
        source_unchanged=True,
        original_state_unchanged=True,
    )
except BaseException as error:
    report.update(status='FAILED', error=repr(error))
    (out / 'failure.txt').write_text(traceback.format_exc())
    raise
finally:
    for process in reversed(processes):
        if process.poll() is not None:
            continue
        if process.stdin:
            process.stdin.write('stop\n')
            process.stdin.flush()
        else:
            process.terminate()
        try:
            process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    for log in logs:
        log.close()
    report['processes_stopped'] = all(p.poll() is not None for p in processes)
    report['source_manifest_sha256'] = hashlib.sha256(
        json.dumps(before, sort_keys=True).encode()
    ).hexdigest()
    report['backend_sha256'] = built['binaries']['existing/pool-backend']
    report['utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save()
print(json.dumps(report))
