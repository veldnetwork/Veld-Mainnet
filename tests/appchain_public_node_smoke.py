"""Run a public node only inside a separate, empty network namespace."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import time
import urllib.request
import urllib.error


def main(a):
    assert os.readlink('/proc/self/ns/net') != a.host_network, 'Separate network namespace required'
    interfaces = json.loads(subprocess.check_output(['ip', '-json', 'link', 'show']))
    assert [x['ifname'] for x in interfaces] == ['lo'], 'Namespace must have loopback only'
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    assert json.loads(subprocess.check_output(['ip', '-json', 'route', 'show'])) == []
    assert (
        a.root.parent == Path('/var/tmp')
        and a.root.name.startswith('veld-native-public-smoke-')
        and not a.root.exists()
    )
    assert hashlib.sha256(a.binary.read_bytes()).hexdigest() == a.sha256
    os.umask(0o077)
    a.root.mkdir()
    a.evidence.mkdir(exist_ok=False)
    env = dict(os.environ, VELD_VAULT_PASSPHRASE=secrets.token_urlsafe(32))
    report = dict(
        status='RUNNING',
        checks=[],
        commands=[],
        binary_sha256=a.sha256,
        namespace=os.readlink('/proc/self/ns/net'),
        mainnet_connectivity=False,
        real_funds=False,
        scope='Public binary startup, genesis persistence, authenticated bridge RPC and cold restart; not historical mainnet replay.',
    )
    proc = None

    def save():
        (a.evidence / 'result.json').write_text(
            json.dumps(report, indent=2) + '\n', encoding='utf-8'
        )

    def check(ok, name):
        assert ok, name
        report['checks'].append(name)
        save()
        print('PASS ' + name, flush=True)

    def rpc(method, params, token=None):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        req = urllib.request.Request(
            'http://127.0.0.1:58344/',
            json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=params)).encode(),
            headers,
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            body = response.read(1048577)
        assert len(body) <= 1048576
        return json.loads(body)

    def stop():
        nonlocal proc
        if proc is None:
            return
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
        try:
            code = proc.wait(timeout=75)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise AssertionError('Node did not stop gracefully')
        report['commands'][-1]['exit'] = code
        proc = None
        check(code == 0, 'node stops cleanly without forced termination')

    try:
        check(True, 'only loopback exists; no route to mainnet or the live fleet')
        previous = None
        for run in ('fresh', 'restart'):
            cmd = [
                str(a.binary),
                '--datadir',
                str(a.root / 'data'),
                '--full-ibd',
                '--no-prompt',
                '--rpcport',
                '58344',
                '--p2pport',
                '58333',
            ]
            report['commands'].append(dict(argv=cmd, run=run))
            with (a.evidence / (run + '.log')).open('wb') as log:
                proc = subprocess.Popen(
                    cmd, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT
                )
            deadline = time.monotonic() + 150
            token = None
            info = None
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise AssertionError('Node exited before authenticated RPC startup')
                if token is None and (a.root / 'data/rpc.token').is_file():
                    result = subprocess.run(
                        [str(a.binary), '--datadir', str(a.root / 'data'), '--print-rpc-token'],
                        env=env,
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        timeout=15,
                    )
                    if result.returncode == 0:
                        candidate = result.stdout.decode().strip()
                        if re.fullmatch('[0-9a-f]{64}', candidate):
                            token = candidate
                if token:
                    try:
                        reply = rpc('getappchainbridgeinfo', [], token)
                        if reply.get('result') is not None:
                            info = reply['result']
                            break
                    except (OSError, urllib.error.URLError):
                        pass
                time.sleep(0.25)
            check(info is not None, run + ' public node reaches authenticated RPC')
            check(
                info['active'] is False
                and info['activation_height'] is None
                and info['total_reserve_atoms'] == 0
                and info['bridges'] == [],
                run + ' public bridge remains inactive with no backing',
            )
            chain = rpc('getblockchaininfo', [], token)['result']
            check(
                chain['blocks'] == 0 and chain['best_block_hash'] == info['parent_genesis'],
                run + ' canonical public genesis retained without mining',
            )
            peers = rpc('getpeerinfo', [], token)['result']
            check(peers == [], run + ' node has no external peers')
            try:
                rpc('getappchainbridgeinfo', [])
            except urllib.error.HTTPError as error:
                check(error.code == 401, run + ' unauthenticated bridge RPC refused')
            else:
                raise AssertionError('Unauthenticated bridge state exposed')
            rejected = rpc(
                'prepareappchaindeposit',
                ['unused', 'ab' * 48, 'cd' * 48, 'ef' * 48, '01' * 48, '1', '0.02'],
                token,
            )
            check(
                'not activated' in str(rejected.get('error')),
                run + ' native deposit preparation refuses inactive bridge',
            )
            digest = rpc('getstatedigest', [], token)
            check(
                isinstance(digest.get('result'), dict)
                and re.fullmatch('[0-9a-f]{64}', digest['result'].get('digest', '')),
                run + ' consensus digest is available',
            )
            state = dict(bridge=info, chain=chain, digest=digest)
            (a.evidence / (run + '-state.json')).write_text(
                json.dumps(state, indent=2) + '\n', encoding='utf-8'
            )
            if previous:
                check(
                    info == previous['bridge'] and digest == previous['digest'],
                    'cold restart preserves exact public bridge and consensus digest',
                )
            previous = state
            stop()
        report.update(
            status='PASS_PUBLIC_NODE_ISOLATED_STARTUP_AND_RESTART', all_owned_processes_stopped=True
        )
    except BaseException as e:
        report.update(status='FAILED', error=repr(e))
        raise
    finally:
        if proc:
            try:
                stop()
            except BaseException as error:
                report['cleanup_error'] = repr(error)
        env.pop('VELD_VAULT_PASSPHRASE', None)
        report['source_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        save()
    print(json.dumps(dict(status=report['status'], checks=len(report['checks']))), flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    for key in ('binary', 'root', 'evidence'):
        p.add_argument('--' + key, type=Path, required=True)
    p.add_argument('--sha256', required=True)
    p.add_argument('--host-network', required=True)
    main(p.parse_args())
