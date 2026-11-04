"""Ordinary detached-intent signing with disposable credentials and no network."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--keygen', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = {
        'status': 'running',
        'started_utc': datetime.now(timezone.utc).isoformat(),
        'keygen_sha256': hashlib.sha256(args.keygen.read_bytes()).hexdigest(),
        'fixture_sha256': hashlib.sha256(args.fixture.read_bytes()).hexdigest(),
        'platform': os.name,
        'disposable_credentials_only': True,
        'network_access': False,
        'checks': [],
        'limits': [
            'Offline signing only; no funded mint, witness reservation, managed worker, or live-chain clearance.'
        ],
    }
    try:
        with tempfile.TemporaryDirectory(prefix='veld-ordinary-signing-') as temporary:
            root = Path(temporary)
            env = dict(os.environ)
            env['VELD_VAULT_PASSPHRASE'] = 'Isolated-ordinary-signing-check-only-2026!'

            def run(arguments, expected=0):
                value = subprocess.run(
                    [str(a) for a in arguments],
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=180,
                    check=False,
                )
                assert value.returncode == expected, (
                    Path(arguments[0]).name,
                    arguments[1],
                    value.returncode,
                    value.stderr[-400:],
                )
                assert env['VELD_VAULT_PASSPHRASE'] not in value.stdout + value.stderr
                return value

            run([args.fixture, '--prepare-dir', root])
            keyfile = root / 'fixture.key'
            run([args.keygen, 'new', '--out', keyfile])
            shown = run([args.keygen, 'show', keyfile])
            address = re.search(r'^address:\s+(\S+)\s*$', shown.stdout, re.MULTILINE).group(1)
            fixtures = root / 'fixtures'
            run([args.fixture, address, fixtures, '--ordinary-only'])
            rows = [
                line.split('\t')
                for line in (fixtures / 'valid-operations.tsv').read_text().splitlines()
            ]
            assert len(rows) == 5
            for name, command, operation, recipient, amount, digest, prepared_name in rows:
                prepared = fixtures / prepared_name
                intent = root / (name + '.intent.json')
                signed = root / (name + '.signed.hex')
                authorized = run(
                    [
                        args.keygen,
                        'authorize-intent',
                        keyfile,
                        prepared,
                        '--operation-type',
                        operation,
                        '--recipient',
                        recipient,
                        '--amount',
                        amount,
                        '--change-destination',
                        address,
                        '--operation-identity-digest',
                        digest,
                        '--maximum-absolute-fee',
                        '100000',
                        '--maximum-fee-rate',
                        '19',
                        '--out',
                        intent,
                    ]
                )
                assert 'No transaction input was signed' in authorized.stderr
                run([args.keygen, command, keyfile, prepared, '--intent', intent, '--out', signed])
                verified = run([args.fixture, '--verify-signed', address, prepared, signed])
                assert 'PASS signed-inputs=' in verified.stdout
                report['checks'].append(
                    {
                        'operation': name,
                        'detached_intent_authorized': True,
                        'actual_input_signatures_verified': True,
                        'input_evidence_retained': True,
                    }
                )
            env.pop('VELD_VAULT_PASSPHRASE', None)
        report['status'] = 'passed'
    except BaseException as error:
        report['status'] = 'failed'
        report['failure'] = {'type': type(error).__name__, 'message': str(error)}
        raise
    finally:
        report['ended_utc'] = datetime.now(timezone.utc).isoformat()
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS ordinary offline signing: 5 operation families with actual signatures')


if __name__ == '__main__':
    main()
