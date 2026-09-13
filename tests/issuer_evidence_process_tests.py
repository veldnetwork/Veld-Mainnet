"""Actual keygen evidence, detached intent and signature checks; no network."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'swap'))
from issuer_signing_evidence import prepare_evidence


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--keygen', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = {'status': 'running', 'platform': os.name, 'network': False,
        'started_utc': datetime.now(timezone.utc).isoformat(),
        'keygen_sha256': hashlib.sha256(args.keygen.read_bytes()).hexdigest(),
        'fixture_sha256': hashlib.sha256(args.fixture.read_bytes()).hexdigest(), 'checks': []}
    try:
        with tempfile.TemporaryDirectory(prefix='issuer-evidence-') as temporary:
            root = Path(temporary)
            env = dict(os.environ, VELD_VAULT_PASSPHRASE='Isolated-issuer-evidence-check-2026!')

            def run(arguments, *, data=None, expected=0):
                value = subprocess.run([str(a) for a in arguments], env=env, text=True,
                    input=data, capture_output=True, timeout=180)
                assert value.returncode == expected, (arguments[1], value.returncode, value.stderr[-350:])
                assert env['VELD_VAULT_PASSPHRASE'] not in value.stdout + value.stderr
                return value

            run([args.fixture, '--prepare-dir', root])
            key = root / 'fixture.key'
            run([args.keygen, 'new', '--out', key])
            address = re.search(r'^address:\s+(\S+)\s*$',
                run([args.keygen, 'show', key]).stdout, re.MULTILINE).group(1)
            fixtures = root / 'fixtures'
            run([args.fixture, address, fixtures, '--ordinary-only'])
            rows = [line.split('\t') for line in (fixtures / 'valid-operations.tsv').read_text().splitlines()]
            for name, command, operation, recipient, amount, digest, prepared_name in rows:
                if not operation.startswith('BTCVELD_'):
                    continue
                prepared = json.loads((fixtures / prepared_name).read_text())
                script = prepared['inputs'][0]['prev_script_hex']
                parents = [i['parent_tx_hex'] for i in prepared['inputs']]
                payload = {'issuer_script_hex': script, 'unsigned_tx_hex': prepared['unsigned_tx_hex'],
                           'parent_transactions': parents}
                built = json.loads(run([args.keygen, 'prepare-signing-stdin'], data=json.dumps(payload)).stdout)
                assert built['operation_identity_digest'] == digest
                assert built['prepared'] == {k: v for k, v in prepared.items() if not k.startswith('reserve_prior_')}
                chain = {'profile_id': 'offline-fixture', 'consensus_build_profile': 'offline-fixture',
                    'disposable': True, 'external_value': False, 'fixed_difficulty_regtest': False,
                    'genesis_hash': built['genesis_hash'], 'launch_block_hash': '12' * 32}
                raw_by_id = {hashlib.sha256(hashlib.sha256(bytes.fromhex(p)).digest()).hexdigest(): p for p in parents}
                resolved = [{'txid': hashlib.sha256(hashlib.sha256(bytes.fromhex(meta['parent_tx_hex'])).digest()).hexdigest(),
                    'value_units': meta['value'], 'script_pubkey_hex': meta['prev_script_hex']}
                    for meta in prepared['inputs']]

                def rpc(method, params):
                    if method == 'getnetworkinfo': return dict(chain)
                    if method == 'getcompiledgenesis': return chain['genesis_hash']
                    if method == 'getblockhash': return chain['genesis_hash'] if params[0] == 0 else chain['launch_block_hash']
                    if method == 'getrawtransaction': return {'txid': params[0], 'raw_hex': raw_by_id[params[0]]}
                    raise AssertionError(method)

                context = {k: v for k, v in prepared.items() if k.startswith('reserve_prior_')} or None
                if os.name == 'posix':
                    evidence = prepare_evidence(str(args.keygen), rpc, chain, prepared['unsigned_tx_hex'], script,
                        resolved, issuer=address, operation_type=operation, recipient=recipient,
                        amount=int(amount), reserve_context=context)
                else:
                    try:
                        prepare_evidence(str(args.keygen), rpc, chain, prepared['unsigned_tx_hex'], script,
                            resolved, issuer=address, operation_type=operation, recipient=recipient,
                            amount=int(amount), reserve_context=context)
                    except RuntimeError as error:
                        assert 'POSIX bounded operator runtime' in str(error)
                    else:
                        raise AssertionError('unsupported service runtime did not refuse')
                    evidence = {'prepared': dict(built['prepared'])}
                    if context:
                        evidence['prepared'].update(context)
                assert evidence['prepared'] == prepared
                evidence_path = root / (name + '.prepared.json')
                evidence_path.write_text(json.dumps(evidence['prepared'], separators=(',', ':')))
                intent = root / (name + '.intent.json')
                signed = root / (name + '.signed')
                run([args.keygen, 'authorize-intent', key, evidence_path,
                    '--operation-type', operation, '--recipient', recipient, '--amount', amount,
                    '--change-destination', address, '--operation-identity-digest', digest,
                    '--maximum-absolute-fee', '100000', '--maximum-fee-rate', '19', '--out', intent])
                run([args.keygen, command, key, evidence_path, '--intent', intent, '--out', signed])
                assert 'PASS signed-inputs=' in run([args.fixture, '--verify-signed', address, evidence_path, signed]).stdout
                bad = dict(payload, parent_transactions=list(reversed(parents)) if len(parents) > 1 else ['00'])
                run([args.keygen, 'prepare-signing-stdin'], data=json.dumps(bad), expected=2)
                run([args.keygen, 'prepare-signing-stdin'], data=json.dumps(payload)[:-1] + ',"extra":0}', expected=2)
                if os.name == 'posix':
                    from swap import veld_signerd as service
                    from unittest import mock
                    state = service._empty_prevout_journal()
                    owner = service.direct_mint_prevout_owner_id('13' * 32 + ':0')
                    stage = root / (name + '-stage')
                    journal = root / (name + '-lease.json')
                    password = root / (name + '-pass')
                    password.write_text(env['VELD_VAULT_PASSPHRASE']); password.chmod(0o600)
                    with mock.patch.multiple(service, PREVOUT_STATEF=str(journal), SIGNING_STAGE_DIR=str(stage),
                            KEYGEN=str(args.keygen), KEYFILE=str(key), PASSFILE=str(password)):
                        service.reserve_issuer_prevouts(state, owner, 'mint-direct', None, '13' * 32 + ':0', prepared['unsigned_tx_hex'])
                        gates = []
                        actual = service.sign_or_recover_staged_carrier(state, owner, prepared['unsigned_tx_hex'], script,
                            'isolated issuer signature', build_evidence=lambda: evidence, revalidate=lambda: gates.append(True))
                        assert len(gates) >= 3
                        assert actual == service.sign_or_recover_staged_carrier(state, owner, prepared['unsigned_tx_hex'], script, 'recovery')
                        stage_signed = root / (name + '-stage-verified.hex')
                        stage_signed.write_text(actual)
                        assert 'PASS signed-inputs=' in run([args.fixture, '--verify-signed', address, evidence_path, stage_signed]).stdout
                        service.mark_issuer_prevout_signature(state, owner, prepared['unsigned_tx_hex'],
                            hashlib.sha256(hashlib.sha256(bytes.fromhex(actual)).digest()).hexdigest())
                        assert not list(stage.iterdir())
                report['checks'].append({'operation': name, 'native_evidence_parity': True,
                    'actual_signature_verified': True, 'wrong_parent_refused': True,
                    'issuer_crash_recovery': os.name == 'posix',
                    'python_service_runtime_supported': os.name == 'posix'})
            assert len(report['checks']) == 2
        report['status'] = 'passed'
    except BaseException as error:
        report['status'] = 'failed'
        report['failure'] = {'type': type(error).__name__, 'message': str(error)}
        raise
    finally:
        report['ended_utc'] = datetime.now(timezone.utc).isoformat()
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS native issuer evidence and actual signing for RTP1 mint and C1 reservation')


if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    main()
