#!/usr/bin/env python3
"""Validate independent nonce origins using a separately compiled native probe."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('probe', type=Path)
args = parser.parse_args()
probe = args.probe.resolve()
counts = (1, 4, 7, 8, 12, 16, 32, 64)

def run(workers):
    result = subprocess.run([str(probe), str(workers)], check=True, capture_output=True, text=True, timeout=20)
    record = json.loads(result.stdout)
    assert record['workers'] == workers
    mask = 2**64 - 1
    assert record['starts'] == [(record['origin'] + i) & mask for i in range(workers)]
    return record

with ThreadPoolExecutor(max_workers=8) as pool:
    records = list(pool.map(run, counts * 3))
assert len({record['origin'] for record in records}) == len(records), 'repeated independent process origin'
nonces = set()
for record in records:
    for start in record['starts']:
        for step in range(1024):
            nonce = (start + step * record['workers']) & (2**64 - 1)
            assert nonce not in nonces, 'overlapping sampled nonce searches'
            nonces.add(nonce)
for invalid in ('0', '65', '256', '-1', '4294967297'):
    result = subprocess.run([str(probe), invalid], capture_output=True, timeout=20)
    assert result.returncode == 2
print(json.dumps({'status': 'PASS', 'processes': len(records), 'sampled_unique_nonces': len(nonces),
                  'workers': counts, 'provider': 'production system randomness',
                  'scope': 'finite independent-process sample, not a proof of impossible collisions'}))
