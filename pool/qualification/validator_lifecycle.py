"""Actual funded bond exit, slash and full vesting on the isolated chain.

This qualification changes no consensus setting. It
uses the existing diagnostic native build, genuine mined funding, native
ML-DSA signatures and the complete canonical settlement builder. The clock
is accelerated; all monetary amounts and block waiting periods are unchanged.
It is not production/mainnet or external-pool-worker qualification.
"""

from pathlib import Path
from fractions import Fraction
import argparse, datetime, hashlib, json, os, shutil, subprocess, sys, tempfile, time, traceback

S = Path(__file__).resolve().parents[2]
from pool.backend import Node
from pool.protocol import Busy, Refused, encode
from pool.qualification.isolation import require_isolated_network
from pool.qualification.control import mine_block
from pool.qualification.build import hashes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-directory', type=Path, required=True)
    parser.add_argument('--matrix-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require_isolated_network()
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    out = args.output.resolve()
    if out.is_relative_to(S):
        raise ValueError('evidence must be outside the source')
    out.mkdir(parents=True, exist_ok=False)
    build = args.build_directory.resolve()
    assert build.name == 'candidate', 'candidate diagnostic profile required'
    build_root = build.parent
    built = json.loads((build_root / 'result.json').read_text())
    before = hashes()
    assert built['status'] == 'PASS' and before == built['source_hashes']
    binary_hashes = {
        n: hashlib.sha256((build / n).read_bytes()).hexdigest()
        for n in ('pool-backend', 'pool-lab-sign', 'pool-lab-keys')
    }
    assert all(built['binaries']['candidate/' + n] == v for n, v in binary_hashes.items())
    # This funding branch was naturally mined and consolidated by the separate
    # matrix controller, which closed it before beginning independent cases.
    matrix = args.matrix_output.resolve()
    funding_result = json.loads((matrix / 'result.json').read_text())
    assert funding_result['status'] == 'PASS' and funding_result['processes_stopped']
    assert funding_result['funding_height'] >= 9500
    matrix_state = Path((matrix / 'state-directory.txt').read_text().strip())
    assert matrix_state.parent == Path('/var/tmp') and matrix_state.name.startswith(
        'veld-pool-validator-matrix-'
    )
    funding = matrix_state / 'funding'
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            command = (entry / 'cmdline').read_bytes().split(b'\0')
        except OSError:
            continue
        assert str(funding).encode() not in command, 'funding source must be closed'
    state = Path(tempfile.mkdtemp(prefix='veld-pool-validator-lifecycle-', dir='/var/tmp'))
    shutil.copytree(funding, state / 'node')
    shutil.copytree(matrix_state / 'keys', state / 'keys')
    (out / 'state-directory.txt').write_text(str(state) + '\n')
    # Public identities are derived from this fixture's disposable keys;
    # no machine-specific history folder or real wallet is consulted.
    addresses = {}
    for key in ('pool', 'worker-a', 'worker-b', 'fees'):
        public = subprocess.run(
            [str(build / 'pool-lab-sign'), str(state / 'keys' / (key + '.seed')), 'identity'],
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        ).stdout.split()
        assert len(public) == 3
        addresses[key] = public[0]
    genesis = 'd5f36a21eb02fca3c272c1cb87132a730b55f6821b454224adab5ad2865e87ee'
    report = dict(
        status='RUNNING',
        scope='funded native bond lifecycle and unchanged full vesting',
        production_build=False,
        mainnet_writes=False,
        accelerated_clock=True,
        economics_modified=False,
        source_commit=built['commit'],
        binary_sha256=binary_hashes,
        source_manifest_sha256=hashlib.sha256(
            json.dumps(before, sort_keys=True).encode()
        ).hexdigest(),
        funding_height=funding_result['funding_height'],
        funding_tip=funding_result['funding_tip'],
        checks=[],
        transactions=[],
        events=[],
        complete_pool_gate=False,
    )
    processes = []
    logs = []
    paths = {}
    started = time.monotonic()

    def save():
        report['updated_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        temp = out / 'result.json.new'
        temp.write_text(json.dumps(report, indent=2) + '\n')
        temp.replace(out / 'result.json')

    def checked(name, condition):
        assert condition, name
        report['checks'].append(name)
        save()
        print(name, flush=True)

    def start(name, folder, p2p, port):
        log = (out / (name + '.log')).open('w')
        logs.append(log)
        proc = subprocess.Popen(
            [str(build / 'pool-backend'), str(folder), str(p2p), str(port)],
            cwd=S,
            stdin=subprocess.PIPE,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        processes.append(proc)
        paths[proc.pid] = out / (name + '.log')
        rpc = Node('http://127.0.0.1:' + str(port), folder / 'lab-rpc-token', genesis)
        deadline = time.monotonic() + 7200
        while True:
            assert proc.poll() is None, 'native replay process exited'
            try:
                rpc.check_chain()
                return proc, rpc
            except (OSError, ValueError, Busy):
                if time.monotonic() > deadline:
                    raise TimeoutError('bounded full native replay')
                time.sleep(0.5)

    def stop(proc):
        if proc.poll() is not None:
            return
        proc.stdin.write('stop\n')
        proc.stdin.flush()
        try:
            proc.wait(timeout=180)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    def mine():
        if time.monotonic() - started > 24 * 3600:
            raise TimeoutError('full native lifecycle deadline')
        return mine_block(node, rpc, addresses['fees'], paths[node.pid])

    def to(height):
        while rpc.call('getblockcount') < height:
            h = mine()
            if h % 120 == 0:
                report['height'] = h
                report['target_height'] = height
                save()

    def sign(prepared, key):
        assert 0 < len(prepared['inputs']) <= 128, (
            'disposable signer input bound; consolidate before preparation'
        )
        result = subprocess.run(
            [str(build / 'pool-lab-sign'), str(state / 'keys' / (key + '.seed')), 'transaction'],
            input=encode(
                dict(
                    unsigned_tx_hex=prepared['unsigned_tx_hex'],
                    bond_units='',
                    reduce_change_units='0',
                )
            )
            + b'\n',
            capture_output=True,
            check=False,
            timeout=120,
        )
        if result.returncode:
            (out / 'signer-refusal.txt').write_bytes(result.stderr)
            raise RuntimeError(
                'disposable signer refused: ' + result.stderr.decode(errors='replace')[:500]
            )
        answer = result.stdout.decode().split()
        assert len(answer) == 2
        return answer

    def pay(prepared, key, label):
        txid, raw = sign(prepared, key)
        assert rpc.call('sendrawtransaction', raw) == txid
        h = mine()
        tx = rpc.call('gettransaction', txid, str(h))
        assert tx['raw_hex'] == raw
        report['transactions'].append(dict(label=label, txid=txid, height=h, raw_hex=raw))
        save()
        return h, txid

    def units(value):
        number = Fraction(str(value)) * 100000000
        assert number.denominator == 1
        return int(number)

    def balance(key, chain=None):
        return units(
            (rpc if chain is None else chain).call('getbalance', addresses[key])['balance_veld']
        )

    def vault(key):
        return next(
            v for v in rpc.call('getbondvaultinfo')['validators'] if v['address'] == addresses[key]
        )

    def event(label):
        h = rpc.call('getblockcount')
        block = rpc.call('getblock', rpc.call('getbestblockhash'))
        txs = [rpc.call('gettransaction', txid, str(h)) for txid in block['tx']]
        report['events'].append(
            dict(
                label=label,
                height=h,
                block=block,
                transactions=txs,
                vault=rpc.call('getbondvaultinfo'),
                balances={k: balance(k) for k in ('pool', 'worker-a', 'worker-b', 'fees')},
            )
        )
        save()

    def refusal(name, method, *values):
        digest = rpc.call('getstatedigest')
        try:
            rpc.call(method, *values)
        except Refused:
            pass
        else:
            raise AssertionError(name + ' was accepted')
        checked(name, rpc.call('getstatedigest') == digest)

    try:
        save()
        node, rpc = start('node', state / 'node', 33801, 33802)
        checked(
            'closed natural funding history replayed exactly',
            rpc.call('getbestblockhash') == funding_result['funding_tip'],
        )
        checked(
            'no ordinary stakes or prior validator positions',
            rpc.call('getvalidators')['total_staked_veld'] == 0
            and rpc.call('getvalidators')['validator_count'] == 0,
        )
        identities = {}
        for key in ('pool', 'worker-a', 'worker-b', 'fees'):
            identity = subprocess.run(
                [str(build / 'pool-lab-sign'), str(state / 'keys' / (key + '.seed')), 'identity'],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.split()
            assert identity[0] == addresses[key]
            identities[key] = identity
        for key in ('worker-a', 'worker-b'):
            pay(
                rpc.call('preparerawtransaction', addresses['pool'], addresses[key], '10000.01'),
                'pool',
                'fund ' + key,
            )
        registrations = {}
        for key in ('pool', 'worker-a', 'worker-b'):
            for attempt in range(1000):
                try:
                    prepared = rpc.call(
                        'prepareregistervalidator', addresses[key], identities[key][1]
                    )
                    if len(prepared['inputs']) <= 128:
                        break
                except Refused as error:
                    if 'cap' not in str(error) and 'fragment' not in str(error):
                        raise
                pay(
                    rpc.call('prepareconsolidatetx', addresses[key], '128', '0'),
                    key,
                    'consolidate bond funding ' + key,
                )
            else:
                raise TimeoutError('bounded genuine registration funding consolidation')
            prior = balance(key)
            h, txid = pay(prepared, key, 'register ' + key)
            registrations[key] = h
            checked(
                key + ' individual principal plus fee debited once',
                prior - balance(key) == 10000 * 100000000 + 100000,
            )
            checked(
                key + ' principal attributable and held',
                vault(key)['principal_held']
                and units(vault(key)['bond_veld']) == 10000 * 100000000,
            )
        refusal(
            'early clean deregistration refused without mutation',
            'preparederegistervalidator',
            addresses['worker-a'],
            identities['worker-a'][1],
        )
        checked(
            'three validators do not activate governance or finality',
            not rpc.call('getgovernanceinfo')['governance_active']
            and not ((rpc.call('getfinalitysnapshot').get('snapshot') or {}).get('active')),
        )
        info = rpc.call('getbondvaultinfo')
        interval = info['settlement_interval']
        vesting = info['vest_horizon_blocks']
        checked(
            'production monetary waiting periods remain unchanged',
            interval == 480 and vesting == 43200,
        )
        first_boundary = ((max(registrations.values()) + 100 + interval - 1) // interval) * interval
        to(first_boundary)
        event('first genuine bond-yield accrual')
        accrued = {key: units(vault(key)['yield_accrued_veld']) for key in registrations}
        checked(
            'each funded active bond accrued genuine escrow yield',
            all(value > 0 for value in accrued.values()),
        )
        clean_before = balance('worker-a')
        slash_before = balance('worker-b')
        active_before = balance('pool')
        # Create two actual contradictory signed claims using only the lab key.
        # The lab signer and slash verifier both consume core/hash.h's direct
        # HexToHash byte order. Preserve the same hash when carrying evidence.
        signed_height = rpc.call('getblockcount')
        display_a = rpc.call('getbestblockhash')
        display_b = ('0' if display_a[0] != '0' else '1') + display_a[1:]
        signatures = []
        for block in (display_a, display_b):
            op = (
                subprocess.run(
                    [str(build / 'pool-lab-sign'), str(state / 'keys/worker-b.seed'), 'endorse'],
                    input=encode(dict(height=str(signed_height), block=block)) + b'\n',
                    capture_output=True,
                    check=True,
                    timeout=120,
                )
                .stdout.decode()
                .strip()
            )
            signatures.append(op.split('|')[-1])
        evidence = [
            addresses['fees'],
            identities['worker-b'][1],
            str(signed_height),
            display_a,
            signatures[0],
            display_b,
            signatures[1],
        ]
        malformed = list(evidence)
        malformed[4] = '00' * 3309
        refusal(
            'forged slash signature refused without state mutation',
            'prepareslashvalidator',
            *malformed,
        )
        slash_height, _ = pay(
            rpc.call('prepareslashvalidator', *evidence), 'fees', 'ordinary slash'
        )
        checked(
            'genuine equivocal endorsement removes only offending validator',
            vault('worker-b')['slashed']
            and not vault('worker-a')['slashed']
            and not vault('pool')['slashed'],
        )
        refusal('same slash evidence cannot be charged twice', 'prepareslashvalidator', *evidence)
        dereg_height, _ = pay(
            rpc.call(
                'preparederegistervalidator', addresses['worker-a'], identities['worker-a'][1]
            ),
            'worker-a',
            'clean exit',
        )
        clean_before -= 100000
        exit_boundary = vault('worker-a')['return_boundary']
        slash_boundary = vault('worker-b')['settlement_boundary']
        checked(
            'clean exit holds full principal through complete evidence window',
            exit_boundary > dereg_height + 43200 and vault('worker-a')['principal_held'],
        )
        refusal(
            'pending clean exit principal cannot fund re-registration',
            'prepareregistervalidator',
            addresses['worker-a'],
            identities['worker-a'][1],
        )
        to(slash_boundary - 1)
        checked(
            'slash does not release principal before settlement',
            vault('worker-b')['principal_held'] and balance('worker-b') == slash_before,
        )
        to(slash_boundary)
        event('ordinary slash principal and unvested yield settlement')
        checked(
            'ordinary slash returns exactly the existing fifty percent principal',
            balance('worker-b') - slash_before == 5000 * 100000000
            and not vault('worker-b')['principal_held'],
        )
        checked(
            'all offender unvested yield is confiscated',
            units(vault('worker-b')['yield_accrued_veld']) == 0,
        )
        refusal(
            'slashed key cannot re-register',
            'prepareregistervalidator',
            addresses['worker-b'],
            identities['worker-b'][1],
        )
        vest_boundary = first_boundary + vesting
        to(vest_boundary - 1)
        checked(
            'clean exited and active bonds receive no early escrow yield',
            balance('worker-a') == clean_before and balance('pool') == active_before,
        )
        to(vest_boundary)
        event('full unchanged ninety-day vesting boundary')
        checked(
            'clean exited validator receives exactly its vested yield',
            balance('worker-a') - clean_before == accrued['worker-a'],
        )
        checked(
            'active validator receives exactly first matured escrow tranche',
            balance('pool') - active_before == accrued['pool'],
        )
        checked(
            'slashed validator receives no matured forfeited yield',
            balance('worker-b') - slash_before == 5000 * 100000000,
        )
        to(exit_boundary - 1)
        checked(
            'clean principal remains held until exact return boundary',
            vault('worker-a')['principal_held']
            and balance('worker-a') == clean_before + accrued['worker-a'],
        )
        to(exit_boundary)
        event('clean principal return')
        checked(
            'clean exit returns original principal exactly once',
            not vault('worker-a')['principal_held']
            and balance('worker-a') == clean_before + accrued['worker-a'] + 10000 * 100000000,
        )
        to(exit_boundary + interval)
        event('following boundary')
        checked(
            'returned principal and finished clean yield are not paid again',
            balance('worker-a') == clean_before + accrued['worker-a'] + 10000 * 100000000
            and units(vault('worker-a')['yield_accrued_veld']) == 0,
        )
        end_tip = rpc.call('getbestblockhash')
        end_digest = rpc.call('getstatedigest')
        end_vault = rpc.call('getbondvaultinfo')
        end_balances = {k: balance(k) for k in identities}
        stop(node)
        # An independently opened full native replay, rather than injecting a
        # synthetic registry or accepting our driver-calculated expected state.
        shutil.copytree(state / 'node', state / 'independent-replay')
        observer, independent = start(
            'independent-replay', state / 'independent-replay', 33811, 33812
        )
        checked(
            'independent native restart replay has identical canonical state',
            independent.call('getbestblockhash') == end_tip
            and independent.call('getstatedigest') == end_digest,
        )
        checked(
            'independent wallet and custody reconciliation agrees exactly',
            independent.call('getbondvaultinfo') == end_vault
            and all(balance(k, independent) == v for k, v in end_balances.items()),
        )
        checked('frozen candidate source unchanged', hashes() == before)
        report.update(
            status='PASS_SCOPED_NATIVE_BOND_LIFECYCLE',
            height=independent.call('getblockcount'),
            tip=end_tip,
            independent_digest=end_digest,
            independent_balances=end_balances,
            waiting_period_blocks=vesting,
            exit_boundary=exit_boundary,
            slash_boundary=slash_boundary,
            remaining_scope=[
                'finality-equivocation funded settlement is a separate seven-validator exercise'
            ],
        )
    except BaseException as error:
        report.update(status='FAILED', error=repr(error))
        (out / 'failure.txt').write_text(traceback.format_exc())
        raise
    finally:
        for proc in reversed(processes):
            stop(proc)
        for log in logs:
            log.close()
        report['processes_stopped'] = all(p.poll() is not None for p in processes)
        report['elapsed_seconds'] = time.monotonic() - started
        report['driver_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        save()


if __name__ == '__main__':
    main()
