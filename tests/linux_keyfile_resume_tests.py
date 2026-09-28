#!/usr/bin/env python3
"""Actual public-node create/import/startup in a loopback-only network namespace."""

import argparse
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--expect-old-failure', action='store_true')
    args = parser.parse_args()
    assert {name for _, name in socket.if_nameindex()} == {'lo'}, 'isolated namespace required'
    with tempfile.TemporaryDirectory(prefix='veld-keyfile-resume-') as tmp:
        root = Path(tmp)
        state = root / 'state'
        env = dict(os.environ, VELD_VAULT_PASSPHRASE='Disposable-Resume-Regression-2026!')

        def utility(options):
            result = subprocess.run(
                [str(args.binary), *options, '--datadir', str(state), '--no-prompt'],
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert result.returncode == 0, result.stderr

        utility(['--create-miner-key'])
        portable = next(state.glob('*.veld-keys'))
        original = portable.read_bytes()
        utility(['--import-miner-key', str(portable)])
        operational = (state / 'miner.key').read_bytes()
        assert original != operational and portable.read_bytes() == original
        log = root / 'startup.log'
        with log.open('wb') as output:
            proc = subprocess.Popen(
                [
                    'stdbuf',
                    '-oL',
                    '-eL',
                    str(args.binary),
                    '--mine',
                    '--full-ibd',
                    '--no-prompt',
                    '--threads',
                    '1',
                    '--datadir',
                    str(state),
                ],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 90
                text = ''
                while time.monotonic() < deadline:
                    text = log.read_text(errors='replace')
                    if (
                        'Mining ready; hashing starts after sync.' in text
                        or proc.poll() is not None
                    ):
                        break
                    time.sleep(0.1)
                assert 'Mining wallet unlocked.' in text, text
                if args.expect_old_failure:
                    assert proc.poll() not in (None, 0), text
                    assert 'existing portable keyfile differs from miner.key' in text, text
                else:
                    assert proc.poll() is None, text
                    assert 'Mining ready; hashing starts after sync.' in text, text
                    assert 'portable mining keyfile verification failed' not in text, text
                assert portable.read_bytes() == original
                assert (state / 'miner.key').read_bytes() == operational
            finally:
                if proc.poll() is None:
                    proc.send_signal(signal.SIGTERM)
                    try:
                        proc.wait(timeout=35)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                        raise
            if not args.expect_old_failure:
                assert proc.returncode == 0, log.read_text(errors='replace')
    print(
        'PASS actual Linux same-key reimport and startup: '
        + (
            'old failure reproduced'
            if args.expect_old_failure
            else 'resumed without altering either keyfile'
        )
    )


if __name__ == '__main__':
    main()
