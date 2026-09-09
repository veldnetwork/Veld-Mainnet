"""Exercise status validity, daemon identity and persistent history migration."""
import copy
from contextlib import closing
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('portal',ROOT/'src/veld-miner-portal.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
checks=0
def check(value):
    global checks
    checks+=1
    assert value, f'check {checks}'
def rejects(value):
    try:p.validate_diagnostics(value)
    except ValueError:check(True)
    else:check(False)

unknown=dict(schema=1,local_status_valid=False,mining_status_valid=False,peer_status_valid=False,
    status_updated_at=None,process_running=True,last_exit_at=0,last_exit_code=None,
    work_state=None,total_hashes=None,mining_ready=None,daemon=None)
check(p.validate_diagnostics(unknown)==unknown)
known=dict(unknown,local_status_valid=True,mining_status_valid=True,peer_status_valid=True,
    status_updated_at=100,work_state='syncing',total_hashes=0,mining_ready=False,
    daemon=dict(version='3.1.1',profile='mainnet-v2',executable_sha256='a'*64,
        network_magic=0x56454c44,protocol_height=0,asert_height=0,migration_height=0,
        security_height=2880,verification_height=12,verification_target=64,
        ibd_complete=False,historical_validated=False))
check(p.validate_diagnostics(known)==known)
for key,value in [('schema',True),('mining_status_valid',0),('total_hashes',0),('last_exit_code',-1)]:
    rejects(dict(unknown,**{key:value}))
for change in ({'version':'3.1.1\nspoof'},{'network_magic':2**32},{'executable_sha256':'keyfile'},
               {'ibd_complete':1},{'profile':'<script>'}):
    v=copy.deepcopy(known);v['daemon'].update(change);rejects(v)
def device(diag):
    return dict(version='3.0.5',height=0,sync_lag=0,hashrate=0,workers=0,blocks=0,peers=0,inbound=0,
        snapshot=dict(mining_active=False,mining_ready=False,total_hashes=0,mempool=0,supply=0,
                      outbound=0,exact_tip=0,diagnostics=copy.deepcopy(diag)))
for diag in (unknown,{}):
    d=device(diag);p.present_device(d)
    check(all(d[k] is None for k in ('height','hashrate','workers','peers','inbound')))
    check(d['snapshot']['mining_active'] is None)
    check(d['daemon_version'] is None and d['gui_version']=='3.0.5')
d=device(known);p.present_device(d)
check(all(d[k]==0 for k in ('height','hashrate','workers','peers','inbound')))
check(d['snapshot']['mining_active'] is False)
check(d['daemon_version']=='3.1.1' and d['gui_version']=='3.0.5')

with tempfile.TemporaryDirectory(prefix='veld-portal-diagnostics-') as temp:
    path=Path(temp)/'portal.sqlite'
    # Existing deployed schema, with an ambiguous zero sample, survives migration.
    with closing(sqlite3.connect(path)) as db:
        db.execute('CREATE TABLE samples(id INTEGER PRIMARY KEY,device_id INTEGER NOT NULL,captured_at INTEGER NOT NULL,height INTEGER NOT NULL,hashrate REAL NOT NULL,peers INTEGER NOT NULL,inbound INTEGER NOT NULL,mining_active INTEGER NOT NULL)')
        db.execute('INSERT INTO samples VALUES(1,99,10,0,0,0,0,0)')
        db.commit()
    store=p.PortalStore(path)
    with store.database() as db:
        row=dict(db.execute('SELECT * FROM samples WHERE id=1').fetchone())
        check(p.present_sample(row)['hashrate'] is None)
    report=dict(name='Disposable fixture',version='3.0.5',height=0,sync_lag=0,hashrate=0,
        workers=0,peers=0,inbound=0,blocks=0,mining_state='Syncing',warning='',
        snapshot=dict(mining_active=False,diagnostics=known))
    token='fixture-token-'+'0'*32
    with patch.object(p.time,'time',return_value=100):store.report(token,report)
    report['snapshot']['diagnostics']=unknown
    with patch.object(p.time,'time',return_value=101):store.report(token,report)
    report['warning']='Local node status is unavailable.'
    with patch.object(p.time,'time',return_value=102):store.report(token,report)
    report['snapshot']['diagnostics']=dict(unknown,process_running=False,last_exit_at=103,last_exit_code=75)
    with patch.object(p.time,'time',return_value=103):store.report(token,report)
    # Reopen the database to establish persisted, not just in-memory, evidence.
    store=p.PortalStore(path)
    with store.database() as db:
        rows=[p.present_sample(dict(r)) for r in db.execute('SELECT * FROM samples WHERE device_id<>99 ORDER BY id')]
    check(len(rows)==4)
    check(rows[0]['hashrate']==0 and rows[0]['diagnostics']['daemon']['verification_height']==12)
    check(rows[1]['hashrate'] is None and rows[1]['height'] is None)
    check(rows[2]['warning']=='Local node status is unavailable.')
    check(rows[3]['diagnostics']['last_exit_code']==75 and rows[3]['diagnostics']['process_running'] is False)
print(f'PASS portal diagnostics: {checks} checks; SQLite migration, unknown readings, mixed versions, warning and exit transitions')
