"""Offline exact-byte admission qualification using a retained native corpus."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess

sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--objects', type=Path, required=True)
    args = parser.parse_args()
    args.root.mkdir(exist_ok=False)
    source = args.root / 'source'
    source.mkdir()
    for folder in ('include', 'vendor/pqc'):
        shutil.copytree(args.source / folder, source / folder)
    (source / 'tests').mkdir()
    for name in ('appchain_bridge_fixture.h', 'appchain_parent_transaction_tests.cpp'):
        shutil.copyfile(args.source / 'tests' / name, source / 'tests' / name)
    shutil.copyfile(Path(__file__), source / 'qualification.py')
    report = dict(
        status='RUNNING',
        started_at=datetime.now(timezone.utc).isoformat(),
        commands=[],
        source_inputs={},
        corpus_inputs={},
        objects={},
        scope='Actual signed checkpoints and finalized-proof payout admission through the native mempool in the LIGHT_VERIFY bridge fixture.',
        full_native=False,
        validation_profile='LIGHT_VERIFY',
        limitations=[
            'Disposable development genesis and retained closed block corpus.',
            'This fixture does not establish complete VeldNode module readiness.',
            'Retained payout uses finalized covenant proofs; separate ordinary sponsor signing is qualified elsewhere.',
            'No public network relay, production activation or real-value transaction.',
        ],
        real_funds=False,
        network_broadcast=False,
        production_deployed=False,
    )
    save = lambda: (args.root / 'qualification.json').write_text(
        json.dumps(report, indent=2) + '\n'
    )

    def run(label, argv, timeout):
        entry = dict(
            label=label,
            argv=list(map(str, argv)),
            cwd=str(args.root),
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        report['commands'].append(entry)
        save()
        print('START ' + label, flush=True)
        try:
            with (args.root / (label + '.log')).open('xb') as log:
                child = subprocess.Popen(
                    entry['argv'],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                    cwd=args.root,
                )
                entry['pid'] = child.pid
                save()
                try:
                    entry['exit'] = child.wait(timeout)
                except BaseException as error:
                    if child.poll() is None:
                        os.killpg(child.pid, signal.SIGTERM)
                        try:
                            child.wait(10)
                        except subprocess.TimeoutExpired:
                            os.killpg(child.pid, signal.SIGKILL)
                            child.wait()
                    entry.update(exit=child.returncode, error=str(error))
                    raise
        finally:
            entry.update(
                finished_at=datetime.now(timezone.utc).isoformat(),
                log_sha256=sha(args.root / (label + '.log')),
            )
            save()
        if entry['exit']:
            raise RuntimeError(label + ' failed')
        print('PASS ' + label, flush=True)

    try:
        for path in source.rglob('*'):
            if path.is_file():
                report['source_inputs'][str(path)] = sha(path)
        for height in range(704):
            path = args.corpus / (str(height) + '.block')
            report['corpus_inputs'][str(path)] = sha(path)
        objects = sorted(args.objects.glob('*.o'))
        if len(objects) != 11:
            raise ValueError('Expected eleven retained PQC objects')
        for obj in objects:
            report['objects'][str(obj)] = sha(obj)
        binary = args.root / 'parent-transaction-tests'
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
                source / 'tests/appchain_parent_transaction_tests.cpp',
                *objects,
                '-lcrypto',
                '-lssl',
                '-o',
                binary,
            ],
            600,
        )
        report['binary_sha256'] = sha(binary)
        run('admission', ['unshare', '-Urn', binary, args.corpus, args.root / 'result'], 600)
        result = json.loads((args.root / 'result/result.json').read_text())
        if result['status'] != 'PASS_NATIVE_PARENT_TRANSACTION_ADMISSION':
            raise ValueError('Native settlement admission failed')
        for collection in ('source_inputs', 'corpus_inputs', 'objects'):
            for path, digest in report[collection].items():
                if sha(Path(path)) != digest:
                    raise ValueError('Changed immutable input: ' + path)
        report.update(status=result['status'], result=result, all_owned_processes_stopped=True)
    except BaseException as error:
        report.update(status='FAILED', error=str(error))
        raise
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        save()
    print(report['status'], flush=True)


if __name__ == '__main__':
    main()
