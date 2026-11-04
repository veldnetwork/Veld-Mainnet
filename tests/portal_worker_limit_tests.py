#!/usr/bin/env python3
"""Check worker command boundaries without opening the portal or a node."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('worker_limit_portal', ROOT / 'src/veld-miner-portal.py')
portal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(portal)
assert portal.MAX_MINING_WORKERS == 64
for workers in (1, 7, 8, 16, 64):
    assert portal.canonical_command_payload('mining.workers', {'workers': workers}) == '{"workers":' + str(workers) + '}'
for workers in (0, -1, 65, 256, 2**64 - 1, 1.5, True, '7', None):
    try:
        portal.canonical_command_payload('mining.workers', {'workers': workers})
    except (ValueError, TypeError):
        pass
    else:
        raise AssertionError('invalid worker count accepted: ' + repr(workers))
print('PASS portal worker limit: valid boundaries and invalid counts/types')
