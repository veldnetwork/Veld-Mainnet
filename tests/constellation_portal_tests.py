import importlib.util, json, copy
from pathlib import Path

s = importlib.util.spec_from_file_location(
    'portal', Path(__file__).resolve().parents[1] / 'src/veld-miner-portal.py'
)
p = importlib.util.module_from_spec(s)
s.loader.exec_module(p)
first, second = 18446744073709551001, 18446744073709551002
t = {
    'local_id': first,
    'nodes': [{'id': first}, {'id': second}],
    'edges': [{'first': first, 'second': second, 'confirmed': True}],
}
stored = json.dumps(t)
d = {'version': '3.3.0', 'snapshot': {'topology': json.loads(stored)}}
p.present_device(d)
got = d['snapshot']['topology']
assert got['nodes'][0]['id'] == str(first) and got['nodes'][1]['id'] == str(second)
assert got['edges'][0]['first'] == str(first) and got['edges'][0]['second'] == str(second)
assert got['local_id'] == str(first) and got['edges'][0]['confirmed'] is True
assert json.dumps(t) == stored
p.present_device(d)
assert d['snapshot']['topology'] == got
print('PASS exact browser peer IDs, unchanged stored report, repeat-safe presentation')
