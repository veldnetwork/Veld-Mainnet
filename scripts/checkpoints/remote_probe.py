"""Authenticated, read-only fleet evidence; the RPC credential stays on the host."""
from pathlib import Path
import http.client
import json
import os
import subprocess
import sys
import time

token = open(3, encoding='ascii').read().strip()
host = sys.argv[1]
requested = [] if sys.argv[2] == '-' else [int(value) for value in sys.argv[2].split(',')]
assert len(requested) <= 1001 and all(0 <= h < 2**64 for h in requested)


def rpc(method, params=()):
    conn = http.client.HTTPConnection('127.0.0.1', 8334, timeout=15)
    conn.request('POST', '/', json.dumps({'jsonrpc':'2.0','id':'checkpoint-publication','method':method,'params':list(params)}),
                 {'Authorization':'Bearer '+token,'Content-Type':'application/json'})
    response = conn.getresponse(); raw = response.read(2000001); conn.close()
    assert response.status == 200 and len(raw) <= 2000000, 'RPC transport failed'
    payload = json.loads(raw)
    assert not payload.get('error'), 'RPC method failed'
    return payload.get('result', payload)


def unit():
    raw = subprocess.check_output(['systemctl','show','veld-node.service','--property=MainPID,ActiveState'],text=True)
    return dict(line.split('=',1) for line in raw.splitlines() if '=' in line)


before = unit(); pid = before['MainPID']
args = Path('/proc/'+pid+'/cmdline').read_bytes().decode().split(chr(0))
data = [args[i+1] if a == '--datadir' else a.split('=',1)[1] for i,a in enumerate(args) if a == '--datadir' or a.startswith('--datadir=')]
assert len(data) == 1
daemon_path = Path(data[0])/'gui-status.json'
daemon = json.loads(daemon_path.read_bytes())['daemon']
assert time.time() - daemon_path.stat().st_mtime <= 120 and str(daemon['pid']) == pid
chain = rpc('getblockchaininfo'); state = rpc('getstatedigest'); peers = rpc('getpeerinfo')
fresh = [p for p in peers if not p.get('inbound') and 0 <= p.get('peer_tip_age_s',99999) <= 120]
matching = [p for p in fresh if p.get('peer_height') == chain['blocks'] and p.get('peer_tip_hash') == chain['best_block_hash']]
stats = Path('/proc/'+pid+'/stat').read_text().rsplit(')',1)[1].split()
uptime = float(Path('/proc/uptime').read_text().split()[0]) - int(stats[19])/os.sysconf('SC_CLK_TCK')
out = dict(host=host, unix_time=time.time(), genesis=rpc('getblockhash',[0]), height=chain['blocks'], tip=chain['best_block_hash'],
    ibd_complete=chain['ibd_complete'], historical_validated=daemon['historical_validated'], active=before['ActiveState']=='active',
    pid=pid, uptime_seconds=uptime, fresh_outbound=len({p['ip'] for p in fresh}), matching_outbound=len({p['ip'] for p in matching}),
    state_height=state['height'], state_tip=state['tip_hash'], state_digest=state['digest'],
    clock_synchronized=subprocess.check_output(['timedatectl','show','-p','NTPSynchronized','--value'],text=True).strip()=='yes',
    hashes={str(h):rpc('getblockhash',[h]) for h in requested})
out['pid_unchanged'] = unit()['MainPID'] == pid
print(json.dumps(out))
