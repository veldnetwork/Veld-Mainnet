"""Qualify signed public snapshot restart against the actual native node core.

Uses disposable databases and an empty network namespace. It never loads owner
keys, activates the bridge, connects peers or substitutes a PoW test profile.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for part in iter(lambda: source.read(1024 * 1024), b''):
            h.update(part)
    return h.hexdigest()


def main(args):
    os.umask(0o077)
    root = args.root.resolve()
    assert root.parent == Path('/var/tmp') and root.name.startswith('veld-native-snapshot-forward-')
    root.mkdir(exist_ok=False)
    source = Path('/var/tmp/veld-native-public-20261012-r1/source')
    build = source.parent / 'linux-node'
    native = build / 'bin/veld-node'
    test = source / 'tests/snapshot_forward_restart_tests.cpp'
    prior = Path('/var/tmp/veld-native-public-history-20261013-r2')
    original = json.loads((prior / 'prepare.json').read_bytes())
    assert sha(native) == original['binary_sha256']
    assert sha(args.prepare) == original['source_sha256']
    assert sha(test) == sha(args.current / 'tests/snapshot_forward_restart_tests.cpp')
    manifest = json.loads(
        (args.current / 'artifacts/native-public-build-20261012-r1/result.json').read_bytes()
    )
    inputs = {
        name: digest
        for name, digest in manifest['source_files'].items()
        if name.startswith(('include/', 'vendor/'))
        or name == 'tests/snapshot_forward_restart_tests.cpp'
    }
    assert all(
        sha(source / name) == digest == sha(args.current / name) for name, digest in inputs.items()
    )
    report = dict(
        status='PREPARING',
        started_at=datetime.now(timezone.utc).isoformat(),
        test_sha256=sha(test),
        driver_sha256=sha(Path(__file__)),
        source_inputs=inputs,
        source=str(source),
        commands=[],
        real_funds=False,
        public_network_connected=False,
        published=False,
        scope='Actual native public-profile snapshot forward/restart/completion; no network services',
        limitations=[
            'Offline production-core fixture, not the public download/installer wrapper or a P2P reorg.',
            'The public bridge stays inactive; this is snapshot compatibility qualification.',
        ],
    )

    def save():
        (root / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

    def run(label, command, timeout=7200, memory_limit=6 * 1024**3):
        item = dict(label=label, argv=command, started_at=datetime.now(timezone.utc).isoformat())
        report['commands'].append(item)
        save()
        print('START ' + label, flush=True)
        proc = None
        with (root / (label + '.log')).open('xb') as log:
            try:
                proc = subprocess.Popen(
                    command,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )
                item['pid'] = proc.pid
                os.setpriority(os.PRIO_PROCESS, proc.pid, 10)
                os.sched_setaffinity(proc.pid, sorted(os.sched_getaffinity(0))[:2])
                deadline = time.monotonic() + timeout
                while proc.poll() is None:
                    assert time.monotonic() < deadline, label + ' exceeded deadline'
                    try:
                        lines = Path(f'/proc/{proc.pid}/status').read_text().splitlines()
                        rss = next(
                            (
                                int(line.split()[1]) * 1024
                                for line in lines
                                if line.startswith('VmRSS:')
                            ),
                            0,
                        )
                        assert rss < memory_limit, label + ' exceeded memory ceiling'
                    except FileNotFoundError:
                        pass
                    time.sleep(0.5)
                item.update(
                    exit=proc.returncode,
                    finished_at=datetime.now(timezone.utc).isoformat(),
                    log_sha256=sha(root / (label + '.log')),
                )
                save()
                assert proc.returncode == 0, label + ' failed; retained log'
                print('PASS ' + label, flush=True)
            finally:
                if proc and proc.poll() is None:
                    os.killpg(proc.pid, 15)
                    try:
                        proc.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, 9)
                        proc.wait()
                    item['forced_stop'] = True
                    save()

    try:
        objects = sorted((build / 'obj').glob('*.o'))
        assert objects
        report['reused_pqc_objects'] = {str(p): sha(p) for p in objects}
        binary = root / 'snapshot-forward'
        command = [
            'g++',
            '-std=c++20',
            '-O2',
            '-DNDEBUG',
            '-pthread',
            '-DVELD_MAINNET_POW',
            '-DVELD_PUBLIC_RELEASE',
            '-DVELD_PUBLIC_MAINNET',
            '-DVELD_USE_LEVELDB',
            '-DVELD_ENABLE_SNAPSHOT_BOOTSTRAP',
            '-I' + str(source / 'include'),
            '-I' + str(source / 'vendor/pqc'),
            '-I' + str(source / 'vendor/pqc/mldsa65'),
            str(test),
            *map(str, objects),
            '-lssl',
            '-lcrypto',
            '-lleveldb',
            '-o',
            str(binary),
        ]
        if args.reuse_run:
            reused = json.loads((args.reuse_run / 'result.json').read_bytes())
            assert reused['source_inputs'] == inputs and reused['test_sha256'] == sha(test)
            assert reused['reused_pqc_objects'] == report['reused_pqc_objects']
            compiled = next(item for item in reused['commands'] if item['label'] == 'compile')
            assert (
                compiled['exit'] == 0
                and sha(args.reuse_run / 'compile.log') == compiled['log_sha256']
            )
            assert sha(args.reuse_run / 'snapshot-forward') == reused['binary_sha256']
            shutil.copyfile(args.reuse_run / 'snapshot-forward', binary)
            binary.chmod(0o700)
            report['reused_compile'] = dict(
                path=str(args.reuse_run),
                result_sha256=sha(args.reuse_run / 'result.json'),
                command=compiled,
            )
        else:
            run('compile', command, timeout=1800, memory_limit=8 * 1024**3)
        report['binary_sha256'] = sha(binary)
        base = Path(
            '/var/tmp/veld-native-public-history-forward-base-'
            + root.name.removeprefix('veld-native-snapshot-forward-')
        )
        donor = Path(
            '/var/tmp/veld-native-public-history-forward-donor-'
            + root.name.removeprefix('veld-native-snapshot-forward-')
        )
        for name, destination, extra in (
            ('base', base, ['--reuse', str(prior)]),
            ('donor', donor, []),
        ):
            if args.reuse_run:
                original_dir = Path(reused['signed_inputs'][name]['path'])
                assert (
                    sha(original_dir / 'prepare.json')
                    == reused['signed_inputs'][name]['prepare_sha256']
                )
                extra = ['--reuse', str(original_dir)]
            run(
                'prepare-' + name,
                [
                    'python3',
                    '-B',
                    str(args.prepare),
                    'prepare',
                    '--root',
                    str(destination),
                    '--binary',
                    str(native),
                    *extra,
                ],
                timeout=300,
            )
        bp = json.loads((base / 'prepare.json').read_bytes())
        dp = json.loads((donor / 'prepare.json').read_bytes())
        assert int(dp['manifest']['height']) > int(bp['manifest']['height']) + 2
        report['signed_inputs'] = {
            label: dict(
                path=str(directory),
                manifest=p['manifest'],
                prepare_sha256=sha(directory / 'prepare.json'),
            )
            for label, directory, p in (('base', base, bp), ('donor', donor, dp))
        }
        auth = root / 'authenticated-inputs'
        scratch = root / 'scratch'
        auth.mkdir()
        scratch.mkdir()
        (scratch / '.qualification-only').write_text(
            'Disposable snapshot lifecycle qualification\n'
        )
        for label, directory, p in (('base', base, bp), ('donor', donor, dp)):
            for suffix in ('.manifest', '.manifest.sig'):
                shutil.copyfile(
                    directory / ('veld-chain-snapshot' + suffix), auth / (label + suffix)
                )
            archive = p['manifest']['archive_file']
            shutil.copyfile(directory / archive, auth / archive)
            assert sha(auth / archive) == p['manifest']['sha256']
            assert all(
                sha(directory / 'data' / name) == spec['sha256']
                for name, spec in p['files'].items()
            )
        # The production import initializes identity after authenticating a raw
        # database-only snapshot. Do not copy the replay helper's local identity.
        for directory, label in ((base, 'pending'), (base, 'independent'), (donor, 'donor')):
            destination = scratch / label
            destination.mkdir()
            shutil.copytree(directory / 'data/db', destination / 'db')
            assert set(p.name for p in destination.iterdir()) == {'db'}
        report['fixture_layout'] = (
            'Authenticated database-only extraction; identity initialized by the production import helper'
        )
        report['status'] = 'RUNNING_SNAPSHOT_FORWARD_RESTART'
        save()
        for phase in ('prepare', 'resume', 'finish'):
            assert sha(binary) == report['binary_sha256']
            run(phase, ['unshare', '-Urn', str(binary), phase, str(scratch), str(auth)])
            text = (root / (phase + '.log')).read_text(errors='replace')
            assert (
                f'PASS SNAPSHOT_FORWARD_RESTART mode={phase}' in text
                and 'network_services=0' in text
            )
        assert all(
            sha(source / name) == digest == sha(args.current / name)
            for name, digest in inputs.items()
        )
        assert all(
            sha(auth / p['manifest']['archive_file']) == p['manifest']['sha256'] for p in (bp, dp)
        )
        report.update(
            status='PASS_PUBLIC_SNAPSHOT_FORWARD_RESTART_AND_FULL_VALIDATION',
            base_height=int(bp['manifest']['height']),
            foreground_height=int(bp['manifest']['height']) + 2,
            signed_archives_unchanged=True,
            all_owned_processes_stopped=True,
        )
    except BaseException as error:
        report.update(status='FAILED', error=repr(error))
        raise
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        save()
    print(
        json.dumps(dict(status=report['status'], foreground_height=report['foreground_height'])),
        flush=True,
    )


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--prepare', type=Path, required=True)
    parser.add_argument('--current', type=Path, required=True)
    parser.add_argument('--reuse-run', type=Path)
    main(parser.parse_args())
