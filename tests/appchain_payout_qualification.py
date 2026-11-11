"""Isolated native payout planner qualification; never signs with owner keys."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--corpus', type=Path, required=True)
    p.add_argument('--objects', type=Path, required=True)
    a = p.parse_args()
    a.root.mkdir(exist_ok=False)
    source = a.root / 'source'
    source.mkdir()
    for folder in ('include', 'vendor/pqc'):
        shutil.copytree(a.source / folder, source / folder)
    (source / 'tests').mkdir()
    for name in (
        'appchain_bridge_fixture.h',
        'appchain_payout_tests.cpp',
        'appchain_bridge_profile_tests.cpp',
    ):
        shutil.copyfile(a.source / 'tests' / name, source / 'tests' / name)
    shutil.copyfile(Path(__file__), source / 'qualification.py')
    report = dict(
        status='RUNNING',
        started_at=datetime.now(timezone.utc).isoformat(),
        commands=[],
        source_inputs={},
        corpus_inputs={},
        objects={},
        scope='Isolated native payout planner; real ML-DSA, VeldHash and immutable block replay.',
        limitations=[
            'No production scheduler, signing service, mempool reservation or broadcast endpoint is enabled.',
            'The corpus uses its distinct disposable development genesis.',
        ],
        real_funds=False,
        production_deployed=False,
    )
    save = lambda: (a.root / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')

    def run(label, argv, timeout):
        entry = dict(
            label=label,
            argv=list(map(str, argv)),
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        report['commands'].append(entry)
        save()
        print('START ' + label, flush=True)
        with (a.root / (label + '.log')).open('xb') as log:
            child = subprocess.Popen(
                entry['argv'], stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL
            )
            entry['pid'] = child.pid
            save()
            try:
                entry['exit'] = child.wait(timeout)
            except BaseException:
                child.kill()
                child.wait()
                raise
        entry.update(
            finished_at=datetime.now(timezone.utc).isoformat(),
            log_sha256=sha(a.root / (label + '.log')),
        )
        save()
        if entry['exit']:
            raise RuntimeError(label + ' failed')
        print('PASS ' + label, flush=True)

    try:
        for path in source.rglob('*'):
            if path.is_file():
                report['source_inputs'][str(path)] = sha(path)
        for h in range(704):
            path = a.corpus / (str(h) + '.block')
            report['corpus_inputs'][str(path)] = sha(path)
        objects = sorted(a.objects.glob('*.o'))
        if len(objects) != 11:
            raise ValueError('Expected eleven previously built PQC objects')
        for obj in objects:
            report['objects'][str(obj)] = sha(obj)
        binary = a.root / 'payout-tests'
        run(
            'compile',
            [
                'g++',
                '-std=c++20',
                '-O1',
                '-DNDEBUG',
                '-pthread',
                '-DVELD_MAINNET_POW',
                '-DVELD_DSTATE_QUALIFICATION',
                '-I' + str(source / 'include'),
                '-I' + str(source / 'vendor/pqc'),
                '-I' + str(source / 'vendor/pqc/mldsa65'),
                source / 'tests/appchain_payout_tests.cpp',
                *objects,
                '-lcrypto',
                '-lssl',
                '-o',
                binary,
            ],
            600,
        )
        report['binary_sha256'] = sha(binary)
        run('payout', ['unshare', '-Urn', binary, a.corpus, a.root / 'history'], 600)
        result = json.loads((a.root / 'history/result.json').read_text())
        if result['status'] != 'PASS_UNSIGNED_NATIVE_PAYOUT_PLANNER':
            raise ValueError('Payout qualification failed')
        profile = a.root / 'public-profile'
        run(
            'compile-public-profile',
            [
                'g++',
                '-std=c++20',
                '-O1',
                '-DNDEBUG',
                '-pthread',
                '-DVELD_MAINNET_POW',
                '-DVELD_PUBLIC_RELEASE',
                '-DVELD_PUBLIC_MAINNET',
                '-I' + str(source / 'include'),
                '-I' + str(source / 'vendor/pqc'),
                '-I' + str(source / 'vendor/pqc/mldsa65'),
                source / 'tests/appchain_bridge_profile_tests.cpp',
                *objects,
                '-lcrypto',
                '-lssl',
                '-o',
                profile,
            ],
            600,
        )
        run('public-profile', ['unshare', '-Urn', profile], 120)
        if 'PASS_PUBLIC_BRIDGE_INACTIVE' not in (a.root / 'public-profile.log').read_text():
            raise ValueError('Public bridge inactivity not verified')
        report['public_profile_binary_sha256'] = sha(profile)
        for collection in ('source_inputs', 'corpus_inputs', 'objects'):
            for path, digest in report[collection].items():
                if sha(Path(path)) != digest:
                    raise ValueError('Changed immutable input: ' + path)
        report.update(
            status=result['status'],
            result=result,
            unsigned_transaction_sha256=sha(a.root / 'history/unsigned-payout.bin'),
            all_owned_processes_stopped=True,
        )
    except BaseException as error:
        report.update(status='FAILED', error=str(error))
        raise
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        save()
    print(report['status'], flush=True)


if __name__ == '__main__':
    main()
