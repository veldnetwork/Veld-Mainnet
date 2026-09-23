"""Check the real full-dataset scan and light verification in one process."""
import argparse
import hashlib
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    rows = [line.split() for line in (Path(__file__).resolve().parent /
            'fixtures/veldhash-3.0.9-vectors.txt').read_text().splitlines() if line.strip()]
    commands, expected = [], []
    for height, header, proof in rows:
        raw = bytes.fromhex(header)
        nonce = int.from_bytes(raw[80:88], 'little')
        identity = hashlib.sha256(hashlib.sha256(raw[:80] + bytes(8)).digest()).hexdigest()
        commands += [f'scan {height} {header} '+ 'f' * 64 + f' {nonce:016x} 1',
                     f'hash {height} {header}']
        expected += [f'SHARE {nonce:016x} {proof}', 'DONE 1', f'OK {proof} {identity}']
    result = subprocess.run([args.binary], input='\n'.join(commands) + '\n',
                            text=True, capture_output=True, check=True, timeout=300)
    assert result.stdout.splitlines() == expected, 'scan/light workspace state or known hash changed'
    print('PASS 28 exact full-size scan vectors interleaved with light verification, including maximum nonce')


if __name__ == '__main__':
    main()
