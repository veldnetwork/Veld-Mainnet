"""Native guard processes; disposable files only, no network or real keys.

Usage: python tests/validator_signing_safety_tests.py --guard EXE --output DIR
The native test executable uses the exact shared production guard headers.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--guard', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    binary = args.guard.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix='veld-signing-safety-') as temp:
        root = Path(temp)
        user = root / 'user'
        user.mkdir(mode=0o700)
        env = dict(os.environ, HOME=str(user), LOCALAPPDATA=str(user))

        def run(name, mode, path, expected=0):
            r = subprocess.run(
                [str(binary), mode, str(path)], env=env, text=True, capture_output=True, timeout=15
            )
            results.append(
                dict(
                    name=name,
                    status='PASS' if r.returncode == expected else 'FAIL',
                    expected_exit=expected,
                    exit_code=r.returncode,
                    stdout=r.stdout,
                    stderr=r.stderr,
                )
            )
            print(results[-1], flush=True)

        run('independent-instances', 'two-instances', root / 'instances')
        run('concurrent-threads', 'threads', root / 'threads')
        path = root / 'restart'
        run('durable-decision', 'write-a', path)
        run('restart-exact-retry', 'write-a', path)
        run('restart-reorg-conflict', 'write-b', path, 3)
        run('canonical-input-validation', 'malformed-input', root / 'invalid')
        run('live-truncation', 'truncate-live', root / 'truncate')
        run('live-replacement', 'replace-live', root / 'replace')
        key = '42:' + 'a' * 3904
        valid = key + '=' + 'a' * 64 + '\n'
        for name, body in {
            'partial-record': valid[:-1],
            'ignored-garbage': 'broken record\n',
            'conflicting-history': valid + key + '=' + 'b' * 64 + '\n',
            'oversized-record': 'x' * 9000 + '\n',
            'invalid-hash': key + '=bad\n',
            'height-overflow': '18446744073709551616:aa=' + 'a' * 64 + '\n',
        }.items():
            file = root / name
            file.write_text(body, encoding='ascii')
            run(name, 'write-b', file, 3)
        legacy = root / 'legacy-crlf'
        legacy.write_bytes((valid.replace('\n', '\r\n') * 2).encode('ascii'))
        run('legacy-crlf-identical-duplicates', 'write-a', legacy)
        run('legacy-still-refuses-conflict', 'write-b', legacy, 3)
        run('missing-parent', 'write-a', root / 'missing' / 'journal', 3)
        run('directory-as-journal', 'write-a', root, 3)
        linked = root / 'hardlink'
        os.link(path, linked)
        run('hard-link-alias', 'write-a', linked, 3)
        os.unlink(linked)

        for label, mode in [('journal', 'hold'), ('identity', 'identity-hold')]:
            live = root / (label + '-live')
            child = subprocess.Popen(
                [str(binary), mode, str(live)],
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                assert child.stdout.readline().strip() == 'AUTHORIZED'
                alias = live.parent / '.' / live.name
                run(
                    label + '-second-process',
                    'write-b' if label == 'journal' else 'identity-b',
                    alias if label == 'journal' else root / 'other-datadir',
                    3,
                )
                child.kill()
                child.wait(timeout=10)
                run(
                    label + '-crash-exact-retry',
                    'write-a' if label == 'journal' else 'identity-a',
                    live,
                )
                run(
                    label + '-crash-reorg-refused',
                    'write-b' if label == 'journal' else 'identity-b',
                    live,
                    3,
                )
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=10)
        run('restored-empty-datadir-refuses-conflict', 'identity-b', root / 'restored', 3)
        run('restored-empty-datadir-exact-retry', 'identity-a', root / 'restored')
        conflicting = root / 'conflicting-legacy'
        conflicting.write_text(key + '=' + 'b' * 64 + '\n', encoding='ascii')
        run('conflicting-legacy-import-refused', 'identity-a', conflicting, 3)
        if os.name != 'nt':
            symlink = root / 'symlink'
            symlink.symlink_to(path)
            run('symlink-refused', 'write-a', symlink, 3)
            os.chmod(path, 0o666)
            run('writable-by-others-refused', 'write-a', path, 3)
            import resource
            import signal

            def limit():
                signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
                resource.setrlimit(resource.RLIMIT_FSIZE, (100, 100))

            r = subprocess.run(
                [str(binary), 'write-a', str(root / 'io-failure')],
                env=env,
                capture_output=True,
                text=True,
                preexec_fn=limit,
                timeout=15,
            )
            results.append(
                dict(
                    name='partial-write-refused',
                    status='PASS' if r.returncode == 3 else 'FAIL',
                    exit_code=r.returncode,
                    stdout=r.stdout,
                    stderr=r.stderr,
                )
            )
            run('partial-write-restart-refused', 'write-b', root / 'io-failure', 3)
    report = dict(
        status='PASS' if all(r['status'] == 'PASS' for r in results) else 'FAIL',
        platform=os.name,
        binary=str(binary),
        cases=results,
        scope='native signing guard; no network or bond operations',
    )
    (args.output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
