"""Real-node, real-signature payment crashes from a naturally mined fixture.

The crash/lost-response hooks are explicit. Wallet reconciliation and recovery
use ordinary native node/RPC and the unmodified payment service after restart.
"""

import argparse
from contextlib import closing
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from ..backend import Node
from ..native import Native
from ..protocol import decode, encode, Busy, Refused
from .isolation import require_isolated_network


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--build-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    build = args.build_directory
    source = Path(__file__).resolve().parents[2]
    require_isolated_network()
    fixture = json.loads(args.fixture.read_text())
    original = Path(fixture['state_directory']).resolve()
    assert original.parent == Path('/var/tmp') and original.name.startswith('veld-pool-payment-'), (
        'disposable fixture required'
    )
    args.output.mkdir(parents=True, exist_ok=False)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    report = {
        'status': 'RUNNING',
        'scope': 'native payments with explicit process-fault injection',
        'cases': [],
    }
    cases = [
        'before_sign',
        'after_native_signature',
        'after_signed_journal',
        'after_broadcast',
        'after_confirmation_before_journal',
        'after_confirmation_journal',
        'lost_response',
        'cached_signed_payload_corruption',
    ]
    for fault in cases:
        out = args.output / fault
        out.mkdir()
        state = Path(tempfile.mkdtemp(prefix='veld-pool-payment-case-', dir='/var/tmp'))
        (out / 'state-directory.txt').write_text(str(state) + '\n')
        processes = []
        logs = []
        verifier = None
        result = {'case': fault, 'status': 'RUNNING'}

        def remap(value):
            if isinstance(value, dict):
                return {k: remap(v) for k, v in value.items()}
            if isinstance(value, list):
                return [remap(v) for v in value]
            if isinstance(value, str) and value.startswith(str(original) + '/'):
                return str(state) + value[len(str(original)) :]
            return value

        # Only stopped disposable state is copied. There are no signed payment
        # obligations in the base fixture, so branches cannot double-pay one.
        assert not (original / 'payments').exists(), (
            'fixture already contains payment authority history'
        )
        for name in ('node', 'observer', 'coordinator', 'work-anchor', 'disposable-keys'):
            shutil.copytree(original / name, state / name)
        settings = remap(fixture['settings'])
        settings['native_binary'] = str(build / 'pool-work')
        settings['payments'] = {
            'state_directory': str(state / 'payments'),
            'rollback_anchor': str(state / 'payment-anchor/current.json'),
            'native_binary': str(build / 'pool-payout'),
            'pool_seed': str(state / 'disposable-keys/pool.seed'),
            'fee_seed': str(state / 'disposable-keys/fees.seed'),
            'pool_script': fixture['scripts']['pool'],
            'fee_script': fixture['scripts']['fees'],
            'fee_address': fixture['addresses']['fees'],
            'fee_units': '100000',
        }
        config = state / 'coordinator.json'
        config.write_bytes(encode(settings))
        config.chmod(0o600)
        accounts = {
            name: json.loads((original / (name + '-account.json')).read_text())
            for name in ('worker-a', 'worker-b')
        }

        def start(name, command, stdin=False):
            log = (out / (name + '.log')).open('w')
            logs.append(log)
            p = subprocess.Popen(
                command,
                cwd=source,
                stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            processes.append(p)
            return p

        def stop(p):
            if p.poll() is None:
                if p.stdin:
                    p.stdin.write('stop\n')
                    p.stdin.flush()
                else:
                    p.terminate()
                try:
                    p.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()

        def ready(rpc, p):
            for _ in range(600):
                if p.poll() is not None:
                    raise RuntimeError('native backend exited')
                try:
                    rpc.check_chain()
                    return
                except (OSError, ValueError):
                    time.sleep(0.1)
            raise RuntimeError('native backend startup')

        def ipc(action, payload):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
                c.settimeout(15)
                c.connect(settings['socket'])
                c.sendall(encode({'action': action, 'payload': payload}) + b'\n')
                with c.makefile('rb') as f:
                    response = decode(f.readline(16385))
            assert response['ok'], response
            return response['result']

        def balances():
            return {
                name: ipc('account', {'account': a['account'], 'token': a['view_token']})
                for name, a in accounts.items()
            }

        def wallet_totals(chain):
            return {
                address: sum(u['value_units'] for u in chain.call('listunspent', address))
                for address in {fixture['addresses'][n] for n in accounts}
            }

        def expected_wallets(amounts):
            result = {}
            for name, amount in amounts.items():
                address = fixture['addresses'][name]
                result[address] = result.get(address, 0) + amount
            return result

        def service_ready(process):
            for _ in range(600):
                if process.poll() is not None:
                    raise RuntimeError('coordinator exited before readiness')
                try:
                    ipc('health', {})
                    return
                except (OSError, ValueError):
                    time.sleep(0.1)
            raise RuntimeError('coordinator readiness deadline')

        def mine():
            height = rpc.call('getblockcount')
            node.stdin.write('clock ' + str(1767225600 + (height + 1) * 180) + '\n')
            node.stdin.flush()
            time.sleep(0.1)
            template = rpc.template(fixture['addresses']['fees'])
            raw = bytearray.fromhex(template['block_hex'][:176])
            solution = None
            for nonce in range(2048):
                raw[80:88] = nonce.to_bytes(8, 'little')
                proof, _ = verifier.hash(bytes(raw), template['height'])
                if int(proof, 16) < int(template['target'], 16):
                    solution = nonce
                    break
            assert solution is not None, 'native fixture PoW bound'
            until = time.monotonic() + 90
            while time.monotonic() < until:
                try:
                    result = rpc.submit(template, solution)
                    if result['accepted']:
                        return
                except (Busy, Refused):
                    if rpc.call('getblockcount') > height:
                        return
                    time.sleep(0.5)
                    template = rpc.renew(template, fixture['addresses']['fees'])
            raise RuntimeError('native confirmation admission deadline')

        try:
            node = start(
                'node', [str(build / 'pool-backend'), str(state / 'node'), '32361', '32362'], True
            )
            rpc = Node('http://127.0.0.1:32362', state / 'node/lab-rpc-token', fixture['genesis'])
            ready(rpc, node)
            observer = start(
                'observer',
                [str(build / 'pool-backend'), str(state / 'observer'), '32371', '32372'],
                True,
            )
            independent = Node(
                'http://127.0.0.1:32372', state / 'observer/lab-rpc-token', fixture['genesis']
            )
            ready(independent, observer)
            observer.stdin.write('peer 32361\n')
            observer.stdin.flush()
            verifier_log = (out / 'work.log').open('w')
            logs.append(verifier_log)
            verifier = Native(build / 'pool-work', verifier_log)
            fee_before = sum(
                u['value_units'] for u in rpc.call('listunspent', fixture['addresses']['fees'])
            )
            marker = state / 'fault-fired'
            boundary = (
                'after_signed_journal' if fault == 'cached_signed_payload_corruption' else fault
            )
            service = start(
                'fault-service',
                [
                    sys.executable,
                    '-m',
                    'pool.qualification.payment_fault_service',
                    boundary,
                    str(marker),
                    '--config',
                    str(config),
                ],
            )
            for _ in range(120):
                if marker.exists():
                    break
                if service.poll() is not None:
                    raise RuntimeError('fault service exited before trigger')
                if fault in ('after_confirmation_before_journal', 'after_confirmation_journal'):
                    mine()
                time.sleep(0.25)
            else:
                raise RuntimeError('fault did not reach selected boundary')
            stop(service)
            retained_signature = None
            if fault == 'cached_signed_payload_corruption':
                # Damage only a stopped disposable index, after the actual
                # native signer has durably committed its real transaction.
                # Keep authoritative signed bytes and rollback anchor intact.
                authority = state / 'payments/events.jsonl'
                anchor = Path(settings['payments']['rollback_anchor'])
                original_log = authority.read_bytes()
                original_anchor = anchor.read_bytes()
                entries = [json.loads(line) for line in original_log.splitlines()]
                retained = [e['payload'] for e in entries if e['kind'] == 'payment_signed']
                assert len(retained) == 1
                retained_signature = retained[0]
                with closing(sqlite3.connect(state / 'payments/index.sqlite')) as db, db:
                    sequence, body = db.execute(
                        "SELECT seq,body FROM events WHERE json_extract(body,'$.kind')='payment_signed'"
                    ).fetchone()
                    altered = json.loads(body)
                    altered['payload'].update(signed_hex='00', state='reserved')
                    db.execute('UPDATE events SET body=? WHERE seq=?', (encode(altered), sequence))
                assert (
                    authority.read_bytes() == original_log
                    and anchor.read_bytes() == original_anchor
                )
                result['cache_corruption'] = {
                    'authoritative_log_unchanged': True,
                    'anchor_unchanged': True,
                    'actual_native_signature_retained': True,
                }
            # The killed coordinator leaves its real Unix socket behind. The
            # normal service must recover it while holding the journal lock;
            # qualification must not repair the filesystem for the service.
            service = start(
                'recovered-service', [sys.executable, '-m', 'pool.service', '--config', str(config)]
            )
            service_ready(service)
            for _ in range(40):
                current = balances()
                if all(int(a['paid_units']) > 0 for a in current.values()):
                    break
                mine()
                time.sleep(0.5)
            else:
                raise RuntimeError('payment recovery did not confirm')
            expected = {n: int(a['paid_units']) for n, a in current.items()}
            actual = wallet_totals(rpc)
            expected_by_wallet = expected_wallets(expected)
            assert actual == expected_by_wallet, 'native recipient accounting mismatch'
            fee_after = sum(
                u['value_units'] for u in rpc.call('listunspent', fixture['addresses']['fees'])
            )
            assert fee_before - fee_after == 100000, 'operator fee paid more than once'
            tip = rpc.call('getblockcount')
            for _ in range(240):
                if independent.call('getblockcount') == tip and independent.call(
                    'getbestblockhash'
                ) == rpc.call('getbestblockhash'):
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError('independent peer did not validate payout')
            independent_actual = wallet_totals(independent)
            assert independent_actual == expected_by_wallet, 'independent wallet mismatch'
            payment_events = [
                json.loads(line)
                for line in (state / 'payments/events.jsonl').read_text().splitlines()
            ]
            signed = [e['payload'] for e in payment_events if e['kind'] == 'payment_signed']
            assert len(signed) == 1, 'more than one signed economic intent'
            if retained_signature is not None:
                assert signed[0] == retained_signature, (
                    'recovery changed the retained native signature'
                )
                result['cache_corruption']['same_exact_signed_transaction_confirmed'] = True
            intents = [e['payload'] for e in payment_events if e['kind'] == 'payment_intent']
            assert (
                len(intents) == 1
                and {r['address']: int(r['units']) for r in intents[0]['wire']['recipients']}
                == expected_by_wallet
            )
            assert len(intents[0]['wire']['recipients']) == len(expected_by_wallet)
            assert {accounts[n]['account']: str(v) for n, v in expected.items()} == intents[0][
                'deductions'
            ]
            assert len({a['account'] for a in accounts.values()}) == 2, (
                'worker accounts were merged'
            )
            result.update(
                height=tip,
                recipient_wallet_units=actual,
                independent_wallet_units=independent_actual,
                operator_fee_units='100000',
                signed_transaction_count=1,
                txid=signed[0]['txid'],
                account_paid_units=expected,
                shared_destination=fixture.get('shared_destination', False),
            )
            # An extra restart plus ordinary maintenance cannot create a retry
            # payment for an obligation already confirmed on the chain.
            stop(service)
            service = start(
                'second-recovery', [sys.executable, '-m', 'pool.service', '--config', str(config)]
            )
            service_ready(service)
            again = balances()
            assert {n: int(a['paid_units']) for n, a in again.items()} == expected
            if fault == 'before_sign':
                stop(service)
                # Restore old rebuildable accounting indexes while preserving
                # the current authoritative logs and separate rollback anchors.
                for folder in ('coordinator', 'payments'):
                    for suffix in ('', '-wal', '-shm'):
                        (state / folder / ('index.sqlite' + suffix)).unlink(missing_ok=True)
                shutil.copy2(
                    original / 'coordinator/index.sqlite', state / 'coordinator/index.sqlite'
                )
                service = start(
                    'restored-old-index',
                    [sys.executable, '-m', 'pool.service', '--config', str(config)],
                )
                service_ready(service)
                again = balances()
                assert {n: int(a['paid_units']) for n, a in again.items()} == expected
                stop(service)
                authoritative = state / 'payments/events.jsonl'
                surviving = authoritative.read_bytes()
                authoritative.write_bytes(b'')
                refused = start(
                    'refuse-stale-authority',
                    [sys.executable, '-m', 'pool.service', '--config', str(config)],
                )
                assert refused.wait(timeout=60) != 0, 'old authoritative journal was accepted'
                assert not Path(settings['socket']).exists(), 'stale authority exposed an API'
                authoritative.write_bytes(surviving)
                service = start(
                    'restored-current-authority',
                    [sys.executable, '-m', 'pool.service', '--config', str(config)],
                )
                service_ready(service)
                again = balances()
                assert {n: int(a['paid_units']) for n, a in again.items()} == expected
                assert wallet_totals(rpc) == expected_by_wallet
                result['backup_recovery'] = {
                    'old_index_replayed': True,
                    'stale_authoritative_log_refused': True,
                    'current_signing_log_restored': True,
                    'recipient_balances_unchanged': True,
                }
            result.update(status='PASS')
        except BaseException as error:
            result.update(status='FAILED', error=repr(error))
            raise
        finally:
            if verifier:
                verifier.close()
            for p in reversed(processes):
                stop(p)
            for log in logs:
                log.close()
            result['processes_stopped'] = all(p.poll() is not None for p in processes)
            (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            report['cases'].append(result)
            (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(fault, 'PASS', flush=True)
    report['status'] = 'PASS'
    report['binary_sha256'] = {
        n: hashlib.sha256((build / n).read_bytes()).hexdigest()
        for n in ('pool-backend', 'pool-payout', 'pool-work')
    }
    (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
