"""Orphan real worker receipts through normal P2P competing-chain admission.

Existing mature income stays backed. Newly orphaned, immature income must never
become payable. Native workers use TLS, VeldHash and the ordinary block builder.
"""
import argparse
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from ..backend import Node
from ..protocol import encode,Busy
from ..worker import Client
from .isolation import require_isolated_network

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--build-directory',type=Path,required=True)
    parser.add_argument('--fixture',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();require_isolated_network()
    source=Path(__file__).resolve().parents[2];build=args.build_directory.resolve()
    fixture=json.loads(args.fixture.read_text());original=Path(fixture['state_directory']).resolve()
    assert original.parent==Path('/var/tmp') and original.name.startswith('veld-pool-payment-')
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:argv=(proc/'cmdline').read_bytes().split(b'\0')
        except OSError:continue
        assert str(original/'node').encode() not in argv,'source fixture must be closed'
    assert 'payments' not in fixture['settings'],'unpaid fixture required'
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    state=Path(tempfile.mkdtemp(prefix='veld-pool-income-reorg-',dir='/var/tmp'))
    (out/'state-directory.txt').write_text(str(state)+'\n')
    for name in ('node','coordinator','work-anchor'):shutil.copytree(original/name,state/name)
    shutil.copytree(original/'node',state/'fork')
    subprocess.run(['ip','link','set','lo','up'],check=True)
    settings={k:(str(state)+v[len(str(original)):] if isinstance(v,str) and v.startswith(str(original)+'/') else v)
              for k,v in fixture['settings'].items()}
    settings.update(native_binary=str(build/'pool-work'),rpc_url='http://127.0.0.1:32902')
    processes=[];logs=[];workers=[]
    report=dict(status='RUNNING',scope='native immature mining income reorganization and restart',
                complete_pool_gate=False,checks=[])
    def save():(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    def check(name,value):
        assert value,name
        report['checks'].append(name);save();print(name,flush=True)
    def config(name,value):
        path=state/(name+'.json');path.write_bytes(encode(value));path.chmod(0o600);return str(path)
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
        until=time.monotonic()+600
        while time.monotonic()<until:
            assert p.poll() is None,'node exited'
            try:rpc.check_chain();return
            except (OSError,Busy,ValueError):time.sleep(.2)
        raise RuntimeError('canonical startup deadline')
    def clock(p,rpc):
        height=rpc.call('getblockcount');p.stdin.write('clock '+str(1767225600+(height+1)*180)+'\n');p.stdin.flush()
        return height
    def mine(p,rpc):
        before=clock(p,rpc);until=time.monotonic()+180;again=0
        while rpc.call('getblockcount')==before:
            if time.monotonic()>until:raise RuntimeError('canonical competing work deadline')
            if time.monotonic()>=again:
                p.stdin.write('mine '+fixture['addresses']['fees']+'\n');p.stdin.flush();again=time.monotonic()+15
            time.sleep(.1)
    def events():
        result=[]
        for line in (state/'coordinator/events.jsonl').read_bytes().splitlines():
            try:result.append(json.loads(line))
            except json.JSONDecodeError:break
        return result
    def incomes():
        rows={}
        for e in events():
            v=e['payload']
            if e['kind']=='income':rows[v['id']]=dict(v)
            elif e['kind']=='income_state':rows[v['id']]['state']=v['state']
        return rows
    def balances():
        result={}
        for name in ('worker-a','worker-b'):
            access=json.loads((state/name/'pool-account.json').read_text())
            result[name]=client.call('account',dict(account=access['account'],token=access['view_token']))
        return result
    def service_ready(p):
        until=time.monotonic()+90
        while time.monotonic()<until:
            assert p.poll() is None,'coordinator exited'
            try:client.call('health',{});return
            except (OSError,Busy,ValueError):time.sleep(.2)
        raise RuntimeError('gateway/coordinator readiness deadline')
    try:
        node=start('node',[str(build/'pool-backend'),str(state/'node'),'32901','32902'],True)
        rpc=Node('http://127.0.0.1:32902',state/'node/lab-rpc-token',fixture['genesis']);ready(rpc,node)
        fork=start('fork',[str(build/'pool-backend'),str(state/'fork'),'32911','32912'],True)
        alternate=Node('http://127.0.0.1:32912',state/'fork/lab-rpc-token',fixture['genesis']);ready(alternate,fork)
        common=rpc.call('getblockcount');prior=incomes()
        check('identical closed canonical funding history',rpc.call('getstatedigest')==alternate.call('getstatedigest'))
        with (out/'certificate.log').open('w') as log:
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(state/'tls.key'),
                '-out',str(state/'tls.crt'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],
                stdout=log,stderr=subprocess.STDOUT,check=True)
        (state/'tls.key').chmod(0o600)
        coordinator=start('coordinator',[sys.executable,'-m','pool.service','--config',config('coordinator',settings)])
        until=time.monotonic()+60
        while not (state/'coordinator.sock').exists():
            assert coordinator.poll() is None
            if time.monotonic()>until:raise RuntimeError('coordinator startup deadline')
            time.sleep(.1)
        gateway=start('gateway',[sys.executable,'-m','pool.gateway','--config',config('gateway',dict(host='127.0.0.1',port=32943,
            certificate=str(state/'tls.crt'),private_key=str(state/'tls.key'),coordinator_socket=settings['socket']))])
        client=Client('https://localhost:32943',str(state/'tls.crt'),fixture['genesis']);service_ready(coordinator)
        clock(node,rpc)
        for name,threads,pause in [('worker-a','2','0'),('worker-b','1','100')]:
            worker=start(name,[str(build/'pool-client'),'--config',config(name,dict(endpoint='https://localhost:32943',
                ca_file=str(state/'tls.crt'),genesis=fixture['genesis'],payout_address=fixture['addresses'][name],
                state_directory=str(state/name),threads=threads,nonce_count='8',pause_ms=pause))]);workers.append((name,worker))
        until=time.monotonic()+300
        while True:
            height=clock(node,rpc)
            if height>=common+4 and all((state/n/'pool-account.json').exists() for n,p in workers):
                if all(int(a['verified_shares'])>0 for a in balances().values()):break
            assert all(p.poll() is None for p in processes)
            if time.monotonic()>until:raise RuntimeError('native worker receipt deadline')
            time.sleep(.2)
        for name,p in workers:(state/name/'stop.request').write_text('stop\n');p.wait(timeout=60)
        until=time.monotonic()+60
        while True:
            new={k:v for k,v in incomes().items() if k not in prior}
            if len(new)>=4:break
            if time.monotonic()>until:raise RuntimeError('new mining income reconciliation deadline')
            time.sleep(.2)
        before=balances();check('new native receipts are pending and never available',all(i['state']=='pending' for i in new.values()) and
            all(int(a['pending_units'])>0 and a['available_units']=='0' and a['paid_units']=='0' for a in before.values()))
        stop(coordinator);old_height=rpc.call('getblockcount');old_tip=rpc.call('getbestblockhash')
        while alternate.call('getblockcount')<old_height+6:mine(fork,alternate)
        replacement=alternate.call('getbestblockhash');fork.stdin.write('peer 32901\n');fork.stdin.flush();until=time.monotonic()+300
        while rpc.call('getbestblockhash')!=replacement:
            if time.monotonic()>until:raise RuntimeError('normal P2P immature-income reorganization deadline')
            time.sleep(.2)
        check('normal P2P replaced the worker blocks',rpc.call('getblockhash',str(old_height))!=old_tip)
        coordinator=start('coordinator-recovered',[sys.executable,'-m','pool.service','--config',str(state/'coordinator.json')]);service_ready(coordinator)
        until=time.monotonic()+90
        while not all(incomes()[k]['state']=='orphaned' for k in new):
            if time.monotonic()>until:raise RuntimeError('orphaned income reconciliation deadline')
            time.sleep(.2)
        after=balances()
        check('orphaned work removes only its unearned pending liability',all(a['pending_units']=='0' and a['available_units']=='0' and a['paid_units']=='0'
            for a in after.values()))
        check('earlier mature income remains available',all(incomes()[k]['state']=='available' for k,v in prior.items() if v['state']=='available'))
        check('independent chain and recipient wallets agree',rpc.call('getstatedigest')==alternate.call('getstatedigest') and
            all(not rpc.call('listunspent',fixture['addresses'][n]) and not alternate.call('listunspent',fixture['addresses'][n]) for n in after))
        stop(coordinator);coordinator=start('coordinator-second-restart',[sys.executable,'-m','pool.service','--config',str(state/'coordinator.json')])
        service_ready(coordinator);time.sleep(2)
        check('restart cannot revive orphaned pending or available earnings',balances()==after and all(incomes()[k]['state']=='orphaned' for k in new))
        report.update(status='PASS',common_height=common,orphaned_receipts=len(new),ending_height=rpc.call('getblockcount'),
            before_reorganization=before,after_reorganization=after,orphaned_amount_units=str(sum(int(i['amount']) for i in new.values())))
    except BaseException as error:
        report.update(status='FAILED',error=repr(error));(out/'failure.txt').write_text(traceback.format_exc());raise
    finally:
        for p in reversed(processes):stop(p)
        for log in logs:log.close()
        report['processes_stopped']=all(p.poll() is not None for p in processes)
        report['binary_sha256']={n:hashlib.sha256((build/n).read_bytes()).hexdigest() for n in ('pool-backend','pool-client','pool-work')};save()

if __name__=='__main__':main()
