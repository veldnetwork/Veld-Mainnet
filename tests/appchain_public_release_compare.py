"""Compare actual released and bridge-candidate public historical state."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path('/var/tmp/veld-native-release-compare-20261013-r1')
PRIOR = Path('/var/tmp/veld-native-public-history-20261013-r2')
PREPARED = Path('/var/tmp/veld-native-public-history-release-compare-20261013-r1')
VERIFIER = Path('/var/tmp/veld-native-public-20261012-r1/linux-node/bin/veld-node')
PACKAGE = Path(
    '/mnt/c/Users/brock/Desktop/veld-win/.codex-ops/updater-package-fileset-20261009/release-3.3.3-r1/packages/linux'
)
PIN = 'a97c28e76d6cf6da54f9920d737e0d91c58fd915ddd7b78a5b4be19bad345d87'


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for data in iter(lambda: f.read(1024 * 1024), b''):
            h.update(data)
    return h.hexdigest()


def save(value):
    (ROOT / 'result.json').write_text(json.dumps(value, indent=2) + '\n')


def prepare():
    os.umask(0o077)
    ROOT.mkdir(exist_ok=False)
    previous = json.loads((PRIOR / 'replay.json').read_bytes())
    assert previous['status'] == 'PASS_PUBLIC_HISTORICAL_REPLAY_AND_RESTART'
    assert sha(VERIFIER) == previous['binary_sha256']
    command = [
        'unshare',
        '-Urn',
        str(VERIFIER),
        '--verify-release',
        str(PACKAGE / 'SHA256SUMS.txt'),
        str(PACKAGE / 'SHA256SUMS.txt.sig'),
    ]
    verified = subprocess.run(command, capture_output=True, timeout=120)
    (ROOT / 'verify-release.log').write_bytes(verified.stdout + verified.stderr)
    assert verified.returncode == 0 and b'RELEASE-SIGNATURE-VALID' in verified.stdout
    lines = (PACKAGE / 'SHA256SUMS.txt').read_text().splitlines()
    assert lines[:2] == ['# veld-release-manifest-v1', '# release-version=3.3.3']
    files = {}
    for line in lines[2:]:
        match = re.fullmatch(r'([0-9a-f]{64}) \*(.+)', line)
        assert match
        expected, relative = match.groups()
        target = (PACKAGE / relative).resolve()
        assert (
            target.is_relative_to(PACKAGE.resolve())
            and target.is_file()
            and not target.is_symlink()
        )
        assert relative not in files and sha(target) == expected
        files[relative] = expected
    assert files['bin/veld-node'] == PIN
    binary = ROOT / 'released-node'
    shutil.copyfile(PACKAGE / 'bin/veld-node', binary)
    binary.chmod(0o700)
    assert sha(binary) == PIN
    prep = [
        'python3',
        '-B',
        str(PRIOR / 'qualification.py'),
        'prepare',
        '--root',
        str(PREPARED),
        '--binary',
        str(VERIFIER),
        '--reuse',
        str(PRIOR),
    ]
    with (ROOT / 'prepare.log').open('xb') as log:
        subprocess.run(prep, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
    report = dict(
        status='AUTHENTICATED_RELEASE_READY',
        started_at=datetime.now(timezone.utc).isoformat(),
        commands=[dict(argv=command, exit=verified.returncode), dict(argv=prep, exit=0)],
        release='3.3.3',
        released_binary_sha256=PIN,
        package_files=files,
        release_manifest_sha256=sha(PACKAGE / 'SHA256SUMS.txt'),
        release_signature_sha256=sha(PACKAGE / 'SHA256SUMS.txt.sig'),
        independent_verifier_sha256=sha(VERIFIER),
        candidate_state_sha256=sha(PRIOR / 'full-replay-state.json'),
        test_sha256=sha(Path(__file__)),
        checks=[],
        real_funds=False,
        production_deployed=False,
        scope='Full historical replay with the signed released Linux client, compared to the bridge candidate at the identical public tip',
    )
    save(report)
    print(report['status'], flush=True)


def run():
    report = json.loads((ROOT / 'result.json').read_bytes())
    assert report['status'] == 'AUTHENTICATED_RELEASE_READY'
    assert [
        row['ifname'] for row in json.loads(subprocess.check_output(['ip', '-json', 'link']))
    ] == ['lo']
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    assert json.loads(subprocess.check_output(['ip', '-json', 'route'])) == []
    report['namespace'] = os.readlink('/proc/self/ns/net')
    report['status'] = 'RUNNING_RELEASED_PUBLIC_HISTORY_COMPARISON'
    data = PREPARED / 'data'
    prepared = json.loads((PREPARED / 'prepare.json').read_bytes())
    assert all(sha(data / name) == spec['sha256'] for name, spec in prepared['files'].items())
    expected = json.loads((PRIOR / 'full-replay-state.json').read_bytes())
    assert sha(PRIOR / 'full-replay-state.json') == report['candidate_state_sha256']
    binary = ROOT / 'released-node'
    assert sha(binary) == PIN
    env = dict(
        os.environ,
        VELD_VAULT_PASSPHRASE=secrets.token_urlsafe(32),
        VELD_LEVELDB_WRITE_BUFFER_MB='8',
        VELD_LEVELDB_BLOCK_CACHE_MB='16',
    )
    command = [
        str(binary),
        '--datadir',
        str(data),
        '--full-ibd',
        '--no-prompt',
        '--verbose',
        '--rpcport',
        '58544',
        '--p2pport',
        '58533',
    ]
    report['commands'].append(dict(argv=command, started_at=datetime.now(timezone.utc).isoformat()))
    save(report)

    def check(value, label):
        assert value, label
        report['checks'].append(label)
        save(report)
        print('PASS ' + label, flush=True)

    token = None

    def rpc(method):
        request = urllib.request.Request(
            'http://127.0.0.1:58544/',
            json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=[])).encode(),
            {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
        )
        with urllib.request.urlopen(request, timeout=10) as reply:
            result = json.loads(reply.read(1024 * 1024))
        assert not result.get('error'), result.get('error')
        return result['result']

    proc = None
    try:
        with (ROOT / 'node.log').open('xb') as log:
            proc = subprocess.Popen(
                command, env=env, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL
            )
            os.setpriority(os.PRIO_PROCESS, proc.pid, 10)
            os.sched_setaffinity(proc.pid, sorted(os.sched_getaffinity(0))[:2])
            report['commands'][-1]['pid'] = proc.pid
            save(report)
            deadline = time.monotonic() + 7200
            chain = None
            while time.monotonic() < deadline:
                assert proc.poll() is None, 'Released node exited before RPC admission'
                if token is None and (data / 'rpc.token').exists():
                    result = subprocess.run(
                        [str(binary), '--datadir', str(data), '--print-rpc-token'],
                        env=env,
                        capture_output=True,
                        timeout=20,
                    )
                    if result.returncode == 0 and re.fullmatch(
                        b'[0-9a-f]{64}', result.stdout.strip()
                    ):
                        token = result.stdout.decode().strip()
                if token:
                    try:
                        chain = rpc('getblockchaininfo')
                        break
                    except OSError:
                        pass
                time.sleep(1)
            check(chain is not None, 'signed released client completes full historical replay')
            state = rpc('getstatedigest')
            (ROOT / 'released-state.json').write_text(
                json.dumps(dict(chain=chain, digest=state), indent=2) + '\n'
            )
            check(
                chain['blocks'] == expected['chain']['blocks']
                and chain['best_block_hash'] == expected['chain']['best_block_hash'],
                'released and candidate clients agree on signed public tip',
            )
            check(
                chain['supply_units'] == expected['chain']['supply_units'],
                'exact public monetary supply preserved',
            )
            for field in ('spec_version', 'height', 'tip_hash', 'digest'):
                check(
                    state[field] == expected['digest'][field],
                    'historical state comparison: ' + field,
                )
            check(
                set(expected['digest']['sub']) - set(state['sub']) == {'appchain_bridge'},
                'only added diagnostic component is inactive bridge state',
            )
            check(
                all(
                    value == expected['digest']['sub'][name] for name, value in state['sub'].items()
                ),
                'all existing consensus component digests match released client',
            )
            check(rpc('getpeerinfo') == [], 'released comparison node has zero external peers')
            proc.send_signal(signal.SIGINT)
            code = proc.wait(timeout=75)
            check(code == 0, 'released comparison node stops cleanly')
            report['commands'][-1]['exit'] = code
            text = (ROOT / 'node.log').read_text(errors='replace')
            check(
                'Chain fully consensus-replayed from disk: height=19559' in text
                and 'prior full IBD covers' not in text,
                'released runtime confirms full verification without prior IBD receipt',
            )
            report.update(
                status='PASS_RELEASED_AND_CANDIDATE_PUBLIC_STATE_MATCH',
                all_owned_processes_stopped=True,
            )
    except BaseException as error:
        report.update(status='FAILED', error=repr(error))
        raise
    finally:
        if proc and proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=75)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                report['forced_stop'] = True
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        save(report)
    print(report['status'], flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('prepare', 'run'))
    args = parser.parse_args()
    (prepare if args.mode == 'prepare' else run)()
