"""Native competing branches and exact-byte pool payment recovery.

The initial fixture is produced by real workers and canonical validation. Both
branches mine actual VeldHash and are joined through the normal P2P path.
No invalidation, UTXO edits, or fake confirmations are used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback
from ..backend import Node
from ..protocol import encode,decode,Busy,Refused
from .isolation import require_isolated_network

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--fixture',type=Path,required=True)
    parser.add_argument('--build-directory',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--deep',action='store_true',help='verify that consensus refuses a fork beyond its reorganization limit')
    args=parser.parse_args();require_isolated_network()
    source=Path(__file__).resolve().parents[2];build=args.build_directory.resolve()
    fixture=json.loads(args.fixture.read_text());original=Path(fixture['state_directory']).resolve()
    assert original.parent==Path('/var/tmp') and original.name.startswith('veld-pool-payment-')
    assert not (original/'payments').exists(),'unpaid closed fixture required'
    for p in Path('/proc').iterdir():
        if p.name.isdigit():
            try:argv=(p/'cmdline').read_bytes().split(b'\0')
            except OSError:continue
            assert str(original/'node').encode() not in argv,'fixture backend must be closed'
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    state=Path(tempfile.mkdtemp(prefix='veld-pool-reorg-',dir='/var/tmp'))
    (out/'state-directory.txt').write_text(str(state)+'\n')
    subprocess.run(['ip','link','set','lo','up'],check=True)
    for name in ('node','coordinator','work-anchor','disposable-keys'):
        shutil.copytree(original/name,state/name)
    if not args.deep:shutil.copytree(original/'node',state/'fork')
    def remap(value):
        if isinstance(value,dict):return {k:remap(v) for k,v in value.items()}
        if isinstance(value,list):return [remap(v) for v in value]
        if isinstance(value,str) and value.startswith(str(original)+'/'):return str(state)+value[len(str(original)):]
        return value
    settings=remap(fixture['settings']);settings['native_binary']=str(build/'pool-work')
    settings['rpc_url']='http://127.0.0.1:32602'
    settings['payments']=dict(state_directory=str(state/'payments'),rollback_anchor=str(state/'payment-anchor/current.json'),
        native_binary=str(build/'pool-payout'),pool_seed=str(state/'disposable-keys/pool.seed'),
        fee_seed=str(state/'disposable-keys/fees.seed'),pool_script=fixture['scripts']['pool'],
        fee_script=fixture['scripts']['fees'],fee_address=fixture['addresses']['fees'],fee_units='100000')
    config=state/'coordinator.json';config.write_bytes(encode(settings));config.chmod(0o600)
    accounts={name:json.loads((original/(name+'-account.json')).read_text()) for name in ('worker-a','worker-b')}
    processes=[];logs=[]
    report=dict(status='RUNNING',deep=args.deep,scope='native payment/funding reorganization',
        complete_pool_gate=False,checks=[])
    def save():(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    def check(name,condition):
        assert condition,name
        report['checks'].append(name);save();print(name,flush=True)
    def start(name,command,stdin=False):
        log=(out/(name+'.log')).open('w');logs.append(log)
        p=subprocess.Popen(command,cwd=source,stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
                           stdout=log,stderr=subprocess.STDOUT,text=True)
        processes.append(p);return p
    def stop(p):
        if p.poll() is not None:return
        if p.stdin:p.stdin.write('stop\n');p.stdin.flush()
        else:p.terminate()
        try:p.wait(timeout=90)
        except subprocess.TimeoutExpired:p.kill();p.wait()
    def ready(rpc,p):
        until=time.monotonic()+300
        while time.monotonic()<until:
            if p.poll() is not None:raise RuntimeError('native service exited')
            try:rpc.check_chain();return
            except (OSError,ValueError,Busy):time.sleep(.1)
        raise RuntimeError('native startup deadline')
    def ipc(action,payload):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
            c.settimeout(30);c.connect(settings['socket']);c.sendall(encode(dict(action=action,payload=payload))+b'\n')
            with c.makefile('rb') as stream:response=decode(stream.readline(16385))
        assert response['ok'],response
        return response['result']
    def service_ready(p):
        until=time.monotonic()+120
        while time.monotonic()<until:
            if p.poll() is not None:raise RuntimeError('coordinator exited')
            try:ipc('health',{});return
            except (OSError,ValueError):time.sleep(.1)
        raise RuntimeError('coordinator startup deadline')
    def balances():return {n:ipc('account',dict(account=a['account'],token=a['view_token'])) for n,a in accounts.items()}
    def wallets(rpc):return {n:sum(u['value_units'] for u in rpc.call('listunspent',fixture['addresses'][n])) for n in accounts}
    def signed():
        path=state/'payments/events.jsonl'
        if not path.exists():return []
        return [e['payload'] for line in path.read_text().splitlines() if (e:=json.loads(line))['kind']=='payment_signed']
    def mine(p,rpc):
        height=rpc.call('getblockcount');p.stdin.write('clock '+str(1767225600+(height+1)*180)+'\n');p.stdin.flush()
        deadline=time.monotonic()+180;again=0
        while time.monotonic()<deadline:
            if rpc.call('getblockcount')>height:return
            if time.monotonic()>=again:
                p.stdin.write('mine '+fixture['addresses']['fees']+'\n');p.stdin.flush();again=time.monotonic()+15
            time.sleep(.075)
        raise RuntimeError('native mining admission deadline')
    try:
        node=start('node',[str(build/'pool-backend'),str(state/'node'),'32601','32602'],True)
        rpc=Node('http://127.0.0.1:32602',state/'node/lab-rpc-token',fixture['genesis']);ready(rpc,node)
        fork=start('fork',[str(build/'pool-backend'),str(state/'fork'),'32611','32612'],True)
        alternate=Node('http://127.0.0.1:32612',state/'fork/lab-rpc-token',fixture['genesis']);ready(alternate,fork)
        common=0 if args.deep else rpc.call('getblockcount')
        check('branches start at the intended shared ancestor',rpc.call('getblockhash',str(common))==alternate.call('getblockhash',str(common)))
        service=start('payment-service',[sys.executable,'-m','pool.service','--config',str(config)]);service_ready(service)
        for _ in range(30):
            current=balances()
            if all(int(a['paid_units'])>0 for a in current.values()):break
            time.sleep(.5);mine(node,rpc)
        else:raise RuntimeError('initial payment confirmation deadline')
        expected={n:int(a['paid_units']) for n,a in current.items()}
        check('original branch paid exactly the recorded liabilities',wallets(rpc)==expected)
        original_signed=signed();check('one signed economic payment before fork',len(original_signed)==1)
        stop(service);old_tip=rpc.call('getbestblockhash');old_height=rpc.call('getblockcount')
        while alternate.call('getblockcount')<old_height+6:mine(fork,alternate)
        competing_tip=alternate.call('getbestblockhash')
        check('competing branch excludes the original payment',all(v==0 for v in wallets(alternate).values()))
        fork.stdin.write('peer 32601\n');fork.stdin.flush();deadline=time.monotonic()+300
        if args.deep:
            # The unmodified chain rejects reorganizations of 100 blocks or
            # more. A >=120-confirmation payment input cannot be orphaned by
            # that normal admission path. Test the refusal instead of disabling
            # it to manufacture a deep-reorganization success receipt.
            while 'reorg_beyond_max_depth' not in (out/'node.log').read_text():
                if time.monotonic()>deadline:raise RuntimeError('native deep-fork rejection evidence deadline')
                time.sleep(.2)
            check('consensus refused the over-depth funding fork',rpc.call('getbestblockhash')==old_tip)
            check('independent competing branch retains its separate state',alternate.call('getbestblockhash')==competing_tip)
            service=start('deep-fork-recovery',[sys.executable,'-m','pool.service','--config',str(config)])
            service_ready(service);time.sleep(2)
            check('refused deep fork leaves original recipient balances unchanged',wallets(rpc)==expected)
            check('refused deep fork creates no extra signed payment',signed()==original_signed)
            report.update(status='PASS',consensus_deep_reorg_refused=True,original_height=old_height,
                competing_height=alternate.call('getblockcount'),recipient_wallet_units=wallets(rpc),
                separate_fork_wallet_units=wallets(alternate),txid=original_signed[0]['txid'],
                limitation='This proves native deep-fork refusal, not recovery after an out-of-protocol history replacement.')
            return
        while rpc.call('getbestblockhash')!=competing_tip:
            if time.monotonic()>deadline:raise RuntimeError('normal P2P branch reorganization deadline')
            time.sleep(.2)
        check('normal P2P reorganization replaced the paid branch',rpc.call('getblockhash',str(old_height))!=old_tip)
        check('independent nodes agree immediately after reorganization',rpc.call('getstatedigest')==alternate.call('getstatedigest'))
        service=start('reorg-recovery',[sys.executable,'-m','pool.service','--config',str(config)]);service_ready(service)
        for _ in range(30):
            current=balances()
            # Readiness opens the worker API before its first periodic
            # reconciliation. A cached paid label is not chain evidence.
            if (all(int(current[n]['paid_units'])==expected[n] for n in accounts)
                    and wallets(rpc)==expected):break
            time.sleep(.5);mine(node,rpc)
        else:raise RuntimeError('same-transaction recovery deadline')
        check('replacement branch paid the same liabilities once',wallets(rpc)==expected)
        until=time.monotonic()+120
        while alternate.call('getbestblockhash')!=rpc.call('getbestblockhash'):
            if time.monotonic()>until:raise RuntimeError('independent recovered payment deadline')
            time.sleep(.2)
        check('independent wallets match after recovered payment',wallets(alternate)==expected)
        check('recovery preserves exactly the same signed transaction',signed()==original_signed)
        stop(service);service=start('restarted-recovery',[sys.executable,'-m','pool.service','--config',str(config)])
        service_ready(service);time.sleep(2)
        check('another restart creates no additional signed economic payment',signed()==original_signed)
        report.update(status='PASS',fork_height=common,old_height=old_height,final_height=rpc.call('getblockcount'),
            txid=original_signed[0]['txid'],signed_bytes_sha256=hashlib.sha256(bytes.fromhex(original_signed[0]['signed_hex'])).hexdigest(),
            entitlement_units=expected,recipient_wallet_units=wallets(rpc),independent_wallet_units=wallets(alternate))
    except BaseException as error:
        report.update(status='FAILED',error=repr(error));(out/'failure.txt').write_text(traceback.format_exc());raise
    finally:
        for p in reversed(processes):stop(p)
        for log in logs:log.close()
        report['processes_stopped']=all(p.poll() is not None for p in processes)
        report['binary_sha256']={n:hashlib.sha256((build/n).read_bytes()).hexdigest() for n in ('pool-backend','pool-payout')}
        save()

if __name__=='__main__':main()
