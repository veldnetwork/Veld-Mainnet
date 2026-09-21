"""Pool telemetry cannot claim solo-node validation or disclose account authority."""
import copy,importlib.util,json,sys,tempfile
from pathlib import Path
source=Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).resolve().parents[1]/'src/veld-miner-portal.py'
spec=importlib.util.spec_from_file_location('portal_pool_test',source);p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
valid=dict(schema=1,running=True,current=True,state='hashing',configured_workers=14,active_workers=8,
           hashrate=1000,total_hashes=10000,accepted=10,verified_shares=20,retry_count=1,updated_at=100)
assert p.validate_pool_snapshot(valid)==valid
assert p.validate_snapshot({})['pool'] is None
assert p.validate_snapshot({'pool':valid})['pool']==valid
for patch in ({'schema':True},{'active_workers':15},{'configured_workers':0},{'hashrate':float('nan')},
              {'current':False},{'running':False},{'state':'<script>'},{'worker_token':'private'},
              {'total_hashes':2**64},{'accepted':True},{'running':1},{'state':[]}):
    try:p.validate_pool_snapshot(dict(valid,**patch))
    except ValueError:pass
    else:raise AssertionError(patch)
assert p.validate_pool_snapshot(dict(valid,running=False,state='stopped',active_workers=0,hashrate=0))['state']=='stopped'
with tempfile.TemporaryDirectory() as td:
    store=p.PortalStore(Path(td)/'portal.sqlite')
    report=dict(name='Disposable pool fixture',version='3.2.2',height=0,sync_lag=0,hashrate=0,
                workers=0,peers=0,inbound=0,blocks=0,mining_state='Stopped',warning='',snapshot=p.validate_snapshot({'pool':valid}))
    store.report('test-only-'+'a'*64,report)
    with store.database() as db:row=dict(db.execute('SELECT * FROM devices').fetchone())
    row['snapshot']=json.loads(row['snapshot_json']);p.present_device(row)
    assert row['snapshot']['pool']==valid
    assert row['height'] is None and row['hashrate'] is None and row['daemon_version'] is None
print('PASS pool report schema, secret refusal, backward compatibility, stored pool state without invented node validation')
