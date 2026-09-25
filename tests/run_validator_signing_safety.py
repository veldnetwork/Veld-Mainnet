"""Rebuild and run focused native signing tests without contacting any network."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cc', default='clang' if os.name == 'nt' else 'gcc')
    parser.add_argument('--cxx', default='clang++' if os.name == 'nt' else 'g++')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    if out == root or root in out.parents:
        raise SystemExit('build outside source')
    out.mkdir(parents=True, exist_ok=False)
    report = dict(
        status='RUNNING',
        platform=sys.platform,
        commands=[],
        source_hashes={},
        artifacts={},
        scope='native focused tests, production profile, synthetic chain callbacks; no live chain',
    )
    for rel in [
        'include/compat/endorse_guard.h',
        'include/compat/validator_signing_state.h',
        'include/consensus/finality_daemon.h',
        'include/consensus/finality_signing_journal.h',
        'src/veld-node.cpp',
        'src/veld-validator.cpp',
        'tests/endorsement_journal_tests.cpp',
        'tests/finality_signing_safety_tests.cpp',
        'tests/validator_signing_safety_tests.py',
        'tests/run_validator_signing_safety.py',
    ]:
        report['source_hashes'][rel] = hashlib.sha256((root / rel).read_bytes()).hexdigest()

    def save():
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')

    def run(name, command):
        started = time.monotonic()
        print(name, flush=True)
        with (out / (name + '.log')).open('w') as log:
            r = subprocess.run(
                [str(x) for x in command],
                cwd=root,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=600,
            )
        report['commands'].append(
            dict(
                name=name,
                command=[str(x) for x in command],
                exit_code=r.returncode,
                seconds=round(time.monotonic() - started, 3),
            )
        )
        save()
        if r.returncode:
            raise RuntimeError(name + ' failed; see ' + str(out / (name + '.log')))

    try:
        run('compiler-c', [args.cc, '--version'])
        run('compiler-cxx', [args.cxx, '--version'])
        objects = []
        for index, line in enumerate(
            (root / 'vendor/pqc/provenance/release-c-sources.txt').read_text().splitlines()
        ):
            if not line or line.startswith('#'):
                continue
            obj = out / (str(index) + '.o')
            run(
                'pqc-' + str(index),
                [
                    args.cc,
                    '-std=c11',
                    '-O2',
                    '-Ivendor/pqc',
                    '-Ivendor/pqc/mldsa65',
                    '-c',
                    line,
                    '-o',
                    obj,
                ],
            )
            objects.append(obj)
        extension = '.exe' if os.name == 'nt' else ''
        libraries = (
            ['-ladvapi32', '-lbcrypt', '-lws2_32'] if os.name == 'nt' else ['-lssl', '-lcrypto']
        )
        for label, source in [
            ('guard', 'endorsement_journal_tests.cpp'),
            ('finality', 'finality_signing_safety_tests.cpp'),
        ]:
            binary = out / (label + extension)
            command = [
                args.cxx,
                '-std=c++20',
                '-O1',
                '-pthread',
                '-Iinclude',
                '-Ivendor/pqc',
                '-Ivendor/pqc/mldsa65',
                '-DVELD_MAINNET_POW',
                '-DVELD_PUBLIC_RELEASE',
                '-DVELD_PUBLIC_MAINNET',
                'tests/' + source,
                *objects,
                *libraries,
                '-o',
                binary,
            ]
            run('build-' + label, command)
            report['artifacts'][binary.name] = hashlib.sha256(binary.read_bytes()).hexdigest()
        run(
            'guard-tests',
            [
                sys.executable,
                root / 'tests/validator_signing_safety_tests.py',
                '--guard',
                out / ('guard' + extension),
                '--output',
                out / 'guard-results',
            ],
        )
        with tempfile.TemporaryDirectory(prefix='veld-finality-safety-') as temp:
            run('finality-tests', [out / ('finality' + extension), temp])
        report['status'] = 'PASS'
    except Exception as error:
        report['status'] = 'FAIL'
        report['error'] = str(error)
        raise
    finally:
        save()


if __name__ == '__main__':
    main()
