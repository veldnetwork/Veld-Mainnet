"""Replay authenticated public history in a network-isolated public client.

Only the disposable test directory is writable by this workflow. The published
archive is retained unchanged; no running node data or private key is imported.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import signal
import subprocess
import tarfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

BASE = 'https://veld.network/downloads/'
MANIFEST = 'veld-chain-snapshot.manifest'
SIGNATURE = MANIFEST + '.sig'
BINARY_HASH = 'fd29b4b40d45ea18787f0cce64fc2c4f8ff11d7f11685d38f8c75a4887f051c6'
GENESIS = '7be77ab9e820bd9ffb60b269b45ced48288056e5839a1135fafc2f8557000a88'
ANCHOR = 'c595cc31fe47999186a402ee7c6fb8bdf97415e4e9d9e643733a828e2ce573d1'


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def download(name, destination, limit):
    request = urllib.request.Request(
        BASE + name, headers={'User-Agent': 'Veld-History-Qualification/1'}
    )
    with urllib.request.urlopen(request, timeout=60) as response, destination.open('xb') as out:
        assert response.geturl() == BASE + name, 'Unexpected download redirect'
        size = 0
        for data in iter(lambda: response.read(1024 * 1024), b''):
            size += len(data)
            assert size <= limit, 'Download size ceiling'
            out.write(data)
    return dict(url=BASE + name, bytes=size, sha256=digest(destination))


def prepare(a):
    assert a.root.parent == Path('/var/tmp') and a.root.name.startswith(
        'veld-native-public-history-'
    )
    assert not a.root.exists() and digest(a.binary) == BINARY_HASH
    os.umask(0o077)
    a.root.mkdir()
    report = dict(
        status='PREPARING',
        source=str(Path(__file__).resolve()),
        source_sha256=digest(Path(__file__)),
        binary=str(a.binary),
        binary_sha256=BINARY_HASH,
        started_at=datetime.now(timezone.utc).isoformat(),
        downloads=[],
        commands=[],
    )
    save(a.root / 'prepare.json', report)
    try:

        def acquire(name, ceiling):
            if a.reuse is None:
                return download(name, a.root / name, ceiling)
            previous = json.loads((a.reuse / 'prepare.json').read_bytes())
            assert previous['status'] == 'PASS_AUTHENTICATED_PUBLIC_HISTORY_PREPARED'
            expected = next(v for v in previous['downloads'] if v['url'] == BASE + name)
            assert (a.reuse / name).stat().st_size <= ceiling and digest(
                a.reuse / name
            ) == expected['sha256']
            shutil.copyfile(a.reuse / name, a.root / name)
            return dict(expected, reused_from=str(a.reuse / name))

        for name, ceiling in ((MANIFEST, 1024 * 1024), (SIGNATURE, 64 * 1024)):
            report['downloads'].append(acquire(name, ceiling))
        command = [
            'unshare',
            '-Urn',
            str(a.binary),
            '--verify-snapshot',
            str(a.root / MANIFEST),
            str(a.root / SIGNATURE),
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        (a.root / 'verify-signature.log').write_text(
            result.stdout + result.stderr, encoding='utf-8'
        )
        report['commands'].append(dict(argv=command, exit=result.returncode))
        assert result.returncode == 0 and 'RELEASE-SIGNATURE-VALID' in result.stdout
        fields = dict(line.split('=', 1) for line in (a.root / MANIFEST).read_text().splitlines())
        assert fields['genesis'] == GENESIS and fields['anchor_hash'] == ANCHOR
        assert fields['anchor_height'] == '1' and fields['state_digest'] == 'v8'
        name = fields['archive_file']
        assert (
            name == f"veld-chain-snapshot-h{int(fields['height'])}-{fields['sha256'][:16]}.tar.gz"
        )
        assert re.fullmatch('[0-9a-f]{64}', fields['sha256'])
        report['manifest'] = fields
        archive = a.root / name
        report['downloads'].append(acquire(name, 16 * 1024**3))
        assert digest(archive) == fields['sha256'], 'Authenticated archive checksum'
        data = a.root / 'data'
        data.mkdir()
        # The local token utility establishes the compiled public identity before
        # opening any database. No token exists in this new disposable directory.
        initialize = ['unshare', '-Urn', str(a.binary), '--datadir', str(data), '--print-rpc-token']
        initialized = subprocess.run(
            initialize,
            env=dict(os.environ, VELD_VAULT_PASSPHRASE=secrets.token_urlsafe(32)),
            capture_output=True,
            text=True,
            timeout=30,
        )
        report['commands'].append(
            dict(
                argv=initialize,
                exit=initialized.returncode,
                expected='Missing token in a newly initialized public directory',
            )
        )
        assert initialized.returncode == 1 and 'cannot read/decrypt' in initialized.stderr
        assert (data / 'network.identity').is_file() and not (data / 'db').exists()
        report['network_identity_sha256'] = digest(data / 'network.identity')
        names, total, files = set(), 0, {}
        with tarfile.open(archive, 'r:gz') as tar:
            for member in tar:
                name = member.name.rstrip('/')
                p = PurePosixPath(name)
                assert name == p.as_posix() and not p.is_absolute() and '..' not in p.parts
                assert name not in names and len(names) < 16384
                names.add(name)
                assert p.parts[0] == 'db' and len(p.parts) <= 3
                if len(p.parts) >= 2:
                    assert p.parts[1] in ('blocks', 'index', 'utxo')
                if member.isdir():
                    assert len(p.parts) <= 2
                    (data / name).mkdir(exist_ok=True, parents=True)
                    continue
                assert member.isfile() and len(p.parts) == 3
                assert re.fullmatch(
                    r'(?:CURRENT|LOCK|LOG|LOG\.old|MANIFEST-[0-9]+|OPTIONS-[0-9]+|[0-9]+\.(?:ldb|log))',
                    p.name,
                )
                total += member.size
                assert (
                    total <= 64 * 1024**3
                    and shutil.disk_usage(data).free > member.size + 8 * 1024**3
                )
                target = data / name
                target.parent.mkdir(exist_ok=True, parents=True)
                with tar.extractfile(member) as source, target.open('xb') as destination:
                    shutil.copyfileobj(source, destination, 1024 * 1024)
                assert target.stat().st_size == member.size
                files[name] = dict(size=member.size, sha256=digest(target))
        for db in ('blocks', 'index', 'utxo'):
            assert (data / 'db' / db / 'CURRENT').is_file()
            assert list((data / 'db' / db).glob('MANIFEST-*'))
        report.update(
            status='PASS_AUTHENTICATED_PUBLIC_HISTORY_PREPARED',
            files=files,
            expanded_bytes=total,
            members=len(names),
            archive_retained=True,
            private_keys_imported=False,
            live_node_data_used=False,
        )
    except BaseException as error:
        report.update(status='FAILED', error=repr(error))
        raise
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        save(a.root / 'prepare.json', report)
    print(
        json.dumps(dict(status=report['status'], height=fields['height'], expanded_bytes=total)),
        flush=True,
    )


def replay(a):
    assert os.readlink('/proc/self/ns/net') != a.host_network
    assert [v['ifname'] for v in json.loads(subprocess.check_output(['ip', '-json', 'link']))] == [
        'lo'
    ]
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    assert json.loads(subprocess.check_output(['ip', '-json', 'route'])) == []
    prepared = json.loads((a.root / 'prepare.json').read_bytes())
    assert prepared['status'] == 'PASS_AUTHENTICATED_PUBLIC_HISTORY_PREPARED'
    assert digest(a.binary) == prepared['binary_sha256'] == BINARY_HASH
    assert not (a.root / 'replay.json').exists()
    data = a.root / 'data'
    for name, identity in prepared['files'].items():
        assert digest(data / name) == identity['sha256'], name
    assert not any(data.glob('*.key')) and not any(data.glob('*receipt*'))
    report = dict(
        status='RUNNING_PUBLIC_HISTORY_REPLAY',
        checks=[],
        commands=[],
        binary_sha256=BINARY_HASH,
        source_sha256=digest(Path(__file__)),
        manifest=prepared['manifest'],
        started_at=datetime.now(timezone.utc).isoformat(),
        namespace=os.readlink('/proc/self/ns/net'),
        mainnet_connectivity=False,
        new_real_fund_transactions=0,
        production_deployed=False,
    )

    def check(value, label):
        assert value, label
        report['checks'].append(label)
        save(a.root / 'replay.json', report)
        print('PASS ' + label, flush=True)

    def rpc(method, params=(), token=None):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        req = urllib.request.Request(
            'http://127.0.0.1:58444/',
            json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=list(params))).encode(),
            headers,
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            body = response.read(1024 * 1024 + 1)
        assert len(body) <= 1024 * 1024
        value = json.loads(body)
        assert not value.get('error'), value.get('error')
        return value['result']

    proc = None
    env = dict(
        os.environ,
        VELD_VAULT_PASSPHRASE=secrets.token_urlsafe(32),
        VELD_LEVELDB_WRITE_BUFFER_MB='8',
        VELD_LEVELDB_BLOCK_CACHE_MB='16',
    )
    env.pop('VELD_VERBOSE', None)

    def stop():
        nonlocal proc
        if proc is None:
            return
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
        try:
            exit_code = proc.wait(timeout=75)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise AssertionError('Owned node required forced termination')
        report['commands'][-1]['exit'] = exit_code
        proc = None
        check(exit_code == 0, 'public node stopped cleanly')

    try:
        check(True, 'loopback-only network namespace excludes live peers and services')
        first = None
        for phase in ('full-replay', 'cold-restart'):
            command = [
                str(a.binary),
                '--datadir',
                str(data),
                '--full-ibd',
                '--no-prompt',
                '--verbose',
                '--rpcport',
                '58444',
                '--p2pport',
                '58433',
            ]
            report['commands'].append(
                dict(phase=phase, argv=command, started_at=datetime.now(timezone.utc).isoformat())
            )
            save(a.root / 'replay.json', report)
            with (a.root / (phase + '.log')).open('xb') as log:
                proc = subprocess.Popen(
                    command,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                os.setpriority(os.PRIO_PROCESS, proc.pid, 10)
                os.sched_setaffinity(proc.pid, sorted(os.sched_getaffinity(0))[:2])
                report['commands'][-1]['pid'] = proc.pid
                save(a.root / 'replay.json', report)
                deadline = time.monotonic() + a.timeout
                token, chain = None, None
                while time.monotonic() < deadline:
                    assert proc.poll() is None, 'Public client exited during historical replay'
                    rss = (
                        int(
                            next(
                                line.split()[1]
                                for line in Path(f'/proc/{proc.pid}/status')
                                .read_text()
                                .splitlines()
                                if line.startswith('VmRSS:')
                            )
                        )
                        * 1024
                    )
                    assert rss < 6 * 1024**3, (
                        'Qualification RSS ceiling protects other local services'
                    )
                    assert (a.root / (phase + '.log')).stat().st_size < 256 * 1024**2
                    if token is None and (data / 'rpc.token').exists():
                        output = subprocess.run(
                            [str(a.binary), '--datadir', str(data), '--print-rpc-token'],
                            env=env,
                            capture_output=True,
                            timeout=20,
                        )
                        value = output.stdout.decode().strip()
                        if output.returncode == 0 and re.fullmatch('[0-9a-f]{64}', value):
                            token = value
                    if token:
                        try:
                            chain = rpc('getblockchaininfo', token=token)
                            break
                        except (OSError, urllib.error.URLError):
                            pass
                    time.sleep(1)
                check(
                    chain is not None,
                    phase + ' completed full historical replay before RPC admission',
                )
                manifest = prepared['manifest']
                check(
                    chain['blocks'] == int(manifest['height'])
                    and chain['best_block_hash'] == manifest['tip_hash'],
                    phase + ' exact signed historical tip',
                )
                check(rpc('getpeerinfo', token=token) == [], phase + ' zero external peers')
                bridge = rpc('getappchainbridgeinfo', token=token)
                check(
                    bridge['active'] is False
                    and bridge['activation_height'] is None
                    and bridge['bridges'] == []
                    and bridge['total_reserve_atoms'] == 0,
                    phase + ' public bridge remains inactive and empty',
                )
                check(bridge['parent_genesis'] == GENESIS, phase + ' compiled public genesis')
                state = rpc('getstatedigest', token=token)
                check(
                    bool(re.fullmatch('[0-9a-f]{64}', state.get('digest', ''))),
                    phase + ' complete consensus state digest',
                )
                try:
                    rpc('getappchainbridgeinfo')
                except urllib.error.HTTPError as error:
                    check(error.code == 401, phase + ' unauthenticated state request refused')
                else:
                    raise AssertionError('Unauthenticated RPC admitted')
                current = dict(chain=chain, bridge=bridge, digest=state)
                save(a.root / (phase + '-state.json'), current)
                if first is not None:
                    check(
                        current['bridge'] == first['bridge']
                        and current['digest'] == first['digest'],
                        'cold restart preserves exact historical consensus and bridge state',
                    )
                first = current
                stop()
                text = (a.root / (phase + '.log')).read_text(errors='replace')
                check(
                    f"Chain fully consensus-replayed from disk: height={manifest['height']}"
                    in text,
                    phase + ' runtime confirms full validation',
                )
                check(
                    'prior full IBD covers' not in text and 'independent IBD pending' not in text,
                    phase + ' no receipt or deferred validation shortcut',
                )
        check(
            digest(a.root / prepared['manifest']['archive_file']) == prepared['manifest']['sha256'],
            'published archive remains unchanged',
        )
        report.update(
            status='PASS_PUBLIC_HISTORICAL_REPLAY_AND_RESTART',
            all_owned_processes_stopped=True,
            limitations=[
                'Authenticated historical prefix only; not a public P2P reorg or live snapshot-upgrade test',
                'Linux public node only; Windows GUI installation and login are separate',
                'Public native bridge activation remains disabled',
            ],
        )
    except BaseException as error:
        report.update(status='FAILED', error=repr(error))
        raise
    finally:
        if proc:
            try:
                stop()
            except BaseException as error:
                report['cleanup_error'] = repr(error)
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        save(a.root / 'replay.json', report)
    print(json.dumps(dict(status=report['status'], checks=len(report['checks']))), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('prepare', 'replay'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--host-network')
    parser.add_argument('--reuse', type=Path)
    parser.add_argument('--timeout', type=int, default=7200)
    args = parser.parse_args()
    (prepare if args.mode == 'prepare' else replay)(args)
