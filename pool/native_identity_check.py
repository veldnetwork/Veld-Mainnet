"""Actual native hashing/signatures with synthetic outpoints, explicitly NOT E2E."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
from .native import Native
from .protocol import encode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    build = args.build_directory
    with tempfile.TemporaryDirectory(prefix='veld-identity-correctness-') as directory:
        root = Path(directory)
        result = subprocess.run(
            [str(build / 'pool-lab-keys'), str(root / 'keys')],
            capture_output=True,
            text=True,
            check=True,
        )
        public = {r.split()[0]: r.split()[1:] for r in result.stdout.splitlines()}
        chain = bytes.fromhex('ee875e86d25aabad2442451b82f6550b732a1387cbc172c2a3fc02eb216af3d5')[
            ::-1
        ].hex()
        inputs = [
            {'txid': 'a' * 64, 'vout': '0', 'units': '100000500000'},
            {'txid': 'b' * 64, 'vout': '1', 'units': '1000000'},
        ]
        policy = {'chain': chain, 'script': public['pool'][1], 'allowed_inputs': inputs}
        path = root / 'policy.json'
        path.write_bytes(encode(policy))
        path.chmod(0o600)
        base = {
            'chain': chain,
            'action': 'stake',
            'height': '3201',
            'header': '',
            'stake_units': '100000000000',
            'tier': '1',
            'inputs': inputs,
        }
        cases = []

        def check(name, request, success, selected_policy=None):
            path.write_bytes(encode(selected_policy or policy))
            path.chmod(0o600)
            completed = subprocess.run(
                [str(build / 'pool-identity'), str(root / 'keys/pool.seed'), str(path)],
                input=encode(request) + b'\n',
                capture_output=True,
                timeout=30,
            )
            assert (completed.returncode == 0) == success, (
                name,
                completed.returncode,
                completed.stderr.decode(),
            )
            assert completed.returncode in (0, 1), ('native abnormal termination', name)
            if success:
                txid, raw = completed.stdout.decode().split()
                assert (
                    hashlib.sha256(hashlib.sha256(bytes.fromhex(raw)).digest()).hexdigest() == txid
                )
            else:
                assert not completed.stdout
            cases.append({'case': name, 'status': 'PASS', 'signature_produced': success})

        check('exact funded stake with native signature self-verification', base, True)
        check(
            'operator self consolidation',
            dict(base, action='consolidate', stake_units='0', tier='0'),
            True,
        )
        check('no stake withdrawals', dict(base, action='unstake'), False)
        check('no arbitrary recipient', dict(base, address=public['worker-a'][0]), False)
        check('no wrong chain', dict(base, chain='0' * 64), False)
        check('no altered principal', dict(base, stake_units='100000000001'), False)
        check('no duplicate funding', dict(base, inputs=[inputs[0], inputs[0]]), False)
        bad = copy.deepcopy(base)
        bad['inputs'][0]['units'] = '100000500001'
        check('no forged funding value', bad, False)
        bad = copy.deepcopy(base)
        bad['inputs'][0]['txid'] = 'd' * 64
        check('no unapproved input', bad, False)
        malformed = dict(policy, allowed_inputs=[{'txid': 'a' * 64, 'vout': '0'}])
        check('malformed protected manifest refuses without crash', base, False, malformed)
        with (args.output / 'native-work.log').open('w') as log:
            native = Native(build / 'pool-work', log)
            try:
                header = bytearray(88)
                header[76:80] = struct.pack('<I', 0x200FFFFF)
                proofs = {}
                for nonce in range(512):
                    header[80:88] = nonce.to_bytes(8, 'little')
                    proof, identity, kind = native.inspect(bytes(header), 3201)
                    proofs.setdefault(kind, header.hex())
                    if 'near_miss' in proofs and 'block' in proofs:
                        break
                assert 'near_miss' in proofs and 'block' in proofs
            finally:
                native.close()
        near = dict(
            base,
            action='nms',
            stake_units='0',
            tier='0',
            inputs=[inputs[1]],
            header=proofs['near_miss'],
        )
        check('genuine VeldHash near miss signs canonical NMS', near, True)
        check(
            'block solution cannot be sold as near miss', dict(near, header=proofs['block']), False
        )
        check('draw-block near miss cannot spend a fee', dict(near, height='3300'), False)
        check('wrong identity key', near, False, dict(policy, script=public['worker-a'][1]))
        report = {
            'status': 'PASS',
            'scope': 'native cryptographic component with synthetic funding outpoints',
            'native_E2E': False,
            'cases': cases,
            'binary_sha256': {
                n: hashlib.sha256((build / n).read_bytes()).hexdigest()
                for n in ('pool-identity', 'pool-work', 'pool-lab-keys')
            },
        }
        (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report))


if __name__ == '__main__':
    main()
