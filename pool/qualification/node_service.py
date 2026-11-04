"""Canonical CLI supervision, real work and independent native validation.

Uses a new datadir and disposable passphrase in a private network namespace.
The lab observer uses ordinary P2P validation; it cannot bypass admission.
"""

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import traceback
from ..backend import Node
from ..native import Native
from ..node_service import deployment
from ..protocol import encode, Busy, Refused
from .isolation import require_isolated_network


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require_isolated_network()
    source = Path(__file__).resolve().parents[2]
    build = args.build_directory.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    state = Path(tempfile.mkdtemp(prefix='veld-pool-canonical-service-', dir='/var/tmp'))
    (out / 'state-directory.txt').write_text(str(state) + '\n')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    identity = deployment(str(build / 'veld-node'))
    assert identity['disposable'] and not identity['external_value'], 'test artifact required'
    genesis = bytes.fromhex(identity['genesis_fingerprint'])[::-1].hex()
    keys = subprocess.run(
        [str(build / 'pool-lab-keys'), str(state / 'keys')],
        capture_output=True,
        text=True,
        check=True,
    )
    address = keys.stdout.splitlines()[0].split()[1]
    password = state / 'backend.passphrase'
    password.write_text(secrets.token_hex(32) + '\n')
    password.chmod(0o600)
    config = dict(
        enabled=True,
        binary=str(build / 'veld-node'),
        datadir=str(state / 'backend'),
        passphrase_file=str(password),
        rpc_token_file=str(state / 'rpc/token'),
        genesis=genesis,
        profile=identity['profile_id'],
        runtime_network='regtest',
        p2p_port=32901,
        rpc_port=32902,
        peers=['127.0.0.1:32911'],
    )
    path = state / 'backend.json'
    path.write_bytes(encode(config))
    path.chmod(0o600)
    report = dict(
        status='RUNNING',
        scope='actual CLI node service with native work and independent P2P validation',
        complete_pool_gate=False,
        checks=[],
        identity=identity,
    )
    processes = []
    logs = []
    verifier = None

    def save():
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

    def check(name, value):
        assert value, name
        report['checks'].append(name)
        save()
        print(name, flush=True)

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
        if p.poll() is not None:
            return
        if p.stdin:
            p.stdin.write('stop\n')
            p.stdin.flush()
        else:
            p.terminate()
        try:
            p.wait(timeout=120)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()

    def ready(node, process, timeout=300):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            if process.poll() is not None:
                raise RuntimeError('service exited before readiness')
            try:
                node.check_chain()
                return
            except (OSError, ValueError, Busy):
                time.sleep(0.2)
        raise RuntimeError('service readiness deadline')

    try:
        observer = start(
            'observer',
            [str(build / 'pool-backend'), str(state / 'observer'), '32911', '32912'],
            True,
        )
        independent = Node('http://127.0.0.1:32912', state / 'observer/lab-rpc-token', genesis)
        ready(independent, observer)
        service = start(
            'service', [sys.executable, '-m', 'pool.node_service', '--config', str(path)]
        )
        rpc = Node('http://127.0.0.1:32902', state / 'rpc/token', genesis)
        ready(rpc, service)
        check('canonical CLI and protected token export ready', rpc.call('getblockcount') == 0)
        check(
            'encrypted at-rest credential differs from exported capability',
            (state / 'backend/rpc.token').read_bytes() != (state / 'rpc/token').read_bytes(),
        )
        check('RPC capability is owner-only', (state / 'rpc/token').stat().st_mode & 0o777 == 0o600)
        log = (out / 'work.log').open('w')
        logs.append(log)
        verifier = Native(build / 'pool-work', log)
        deadline = time.monotonic() + 180
        while True:
            try:
                template = rpc.template(address)
                break
            except (Busy, Refused):
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.5)
        raw = bytearray.fromhex(template['block_hex'][:176])
        nonce = None
        for trial in range(4096):
            raw[80:88] = trial.to_bytes(8, 'little')
            proof, _ = verifier.hash(bytes(raw), template['height'])
            if int(proof, 16) < int(template['target'], 16):
                nonce = trial
                break
        assert nonce is not None, 'native PoW search bound'
        result = rpc.submit(template, nonce)
        check('actual CLI accepted canonical pool candidate', result['accepted'])
        tip = rpc.call('getbestblockhash')
        digest = rpc.call('getstatedigest')
        until = time.monotonic() + 180
        while independent.call('getbestblockhash') != tip:
            if time.monotonic() > until:
                raise RuntimeError('independent native validation deadline')
            time.sleep(0.2)
        check(
            'independent node agrees with CLI block and state',
            independent.call('getstatedigest') == digest,
        )
        stop(service)
        check('shutdown removes exported RPC capability', not (state / 'rpc/token').exists())
        service = start(
            'service-restarted', [sys.executable, '-m', 'pool.node_service', '--config', str(path)]
        )
        ready(rpc, service)
        check(
            'restart preserves canonical tip and state',
            rpc.call('getbestblockhash') == tip and rpc.call('getstatedigest') == digest,
        )
        report.update(status='PASS', height=rpc.call('getblockcount'), tip=tip)
    except BaseException as error:
        report.update(status='FAILED', error=repr(error))
        (out / 'failure.txt').write_text(traceback.format_exc())
        raise
    finally:
        if verifier:
            verifier.close()
        for p in reversed(processes):
            stop(p)
        for log in logs:
            log.close()
        report['processes_stopped'] = all(p.poll() is not None for p in processes)
        report['binary_sha256'] = {
            n: hashlib.sha256((build / n).read_bytes()).hexdigest()
            for n in ('veld-node', 'pool-backend', 'pool-work')
        }
        save()


if __name__ == '__main__':
    main()
