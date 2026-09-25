"""Real native helper, frozen PoW vectors and refusal/recovery; no network."""

import argparse
import hashlib
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    rows = [
        line.split()
        for line in (Path(__file__).resolve().parent / 'fixtures/veldhash-3.0.9-vectors.txt')
        .read_text()
        .splitlines()
        if line.strip()
    ]
    assert len(rows) == 28
    commands, expected = [], []
    for _ in range(2):
        for height, header, proof in rows:
            raw = bytes.fromhex(header)
            identity = hashlib.sha256(hashlib.sha256(raw[:80] + bytes(8)).digest()).hexdigest()
            bits = int.from_bytes(raw[76:80], 'little')
            target = (bits & 0x7FFFFF) << (8 * ((bits >> 24) - 3))
            value = int(proof, 16)
            kind = (
                'block'
                if value < target
                else 'near_miss'
                if target < value <= 4 * target < 1 << 256
                else 'none'
            )
            commands += [f'hash {height} {header}', f'inspect {height} {header}']
            expected += [f'OK {proof} {identity}', f'OK {proof} {identity} {kind}']
            # Refusal cannot poison the next request's retained workspace.
            invalid = bytearray(raw)
            invalid[76:80] = bytes(4)
            commands += [f'hash {height} {invalid.hex()}', f'hash {height} {header} extra']
            expected += ['ERROR network target', 'ERROR schema']
    result = subprocess.run(
        [args.binary],
        input='\n'.join(commands) + '\n',
        text=True,
        capture_output=True,
        check=True,
        timeout=300,
    )
    assert result.stdout.splitlines() == expected, 'native retained workspace changed exact output'
    print(
        f'PASS {len(commands)} native requests: 28 frozen vectors, repeat, inspect, rejection and recovery'
    )


if __name__ == '__main__':
    main()
