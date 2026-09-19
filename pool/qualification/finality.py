"""Seven naturally funded native bonds, unchanged warm-up and pool QC carrier.

Disposable funding history is mined separately with ordinary economics. The
test signer is intentionally never part of the installed service package.
"""
import argparse
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
from ..protocol import encode,Busy,Refused
from .isolation import require_isolated_network
from .control import mine_block

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--build-directory',type=Path,required=True)
    parser.add_argument('--lab-signer',type=Path,required=True)
    parser.add_argument('--history-state',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();require_isolated_network()
    source=Path(__file__).resolve().parents[2];build=args.build_directory.resolve()
    original=args.history_state.resolve()
    assert original.parent==Path('/var/tmp') and original.name.startswith('veld-pool-history-')
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:argv=(proc/'cmdline').read_bytes().split(b'\0')
        except OSError:continue
        assert str(original/'node').encode() not in argv,'funding history must be closed'
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    state=Path(tempfile.mkdtemp(prefix='veld-pool-finality-',dir='/var/tmp'))
    (out/'state-directory.txt').write_text(str(state)+'\n')
    for name in ('node','keys'):shutil.copytree(original/name,state/name)
    shutil.copytree(original/'node',state/'observer')
    public=json.loads((original/'public-identities.json').read_text());addresses=public['addresses']
    subprocess.run(['ip','link','set','lo','up'],check=True)
    genesis='d5f36a21eb02fca3c272c1cb87132a730b55f6821b454224adab5ad2865e87ee'
    report=dict(status='RUNNING',scope='unchanged seven-bond finality with actual pool worker carrier',
                accelerated_historical_clock=True,economics_modified=False,complete_pool_gate=False,checks=[],registrations=[])
    processes=[];logs=[]
    def save():(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    def check(name,value):
        assert value,name
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
        try:p.wait(timeout=120)
        except subprocess.TimeoutExpired:p.kill();p.wait()
    def ready(rpc,p):
        deadline=time.monotonic()+3600
        while time.monotonic()<deadline:
            if p.poll() is not None:raise RuntimeError('backend exited during genuine replay')
            try:rpc.check_chain();return
            except (OSError,ValueError,Busy):time.sleep(.2)
        raise RuntimeError('canonical replay deadline')
    def mine():
        return mine_block(node,rpc,addresses['fees'],out/'node.log')
    def sign(prepared,key):
        result=subprocess.run([str(args.lab_signer),str(key),'transaction'],input=encode(dict(
            unsigned_tx_hex=prepared['unsigned_tx_hex'],bond_units='',reduce_change_units='0'))+b'\n',
            capture_output=True,check=True,timeout=120)
        txid,raw=result.stdout.decode().split()
        assert rpc.call('sendrawtransaction',raw)==txid
        mine();return txid
    def config(name,value):
        path=state/(name+'.json');path.write_bytes(encode(value));path.chmod(0o600);return str(path)
    try:
        node=start('node',[str(build/'pool-backend'),str(state/'node'),'32501','32502'],True)
        rpc=Node('http://127.0.0.1:32502',state/'node/lab-rpc-token',genesis);ready(rpc,node)
        observer=start('observer',[str(build/'pool-backend'),str(state/'observer'),'32511','32512'],True)
        independent=Node('http://127.0.0.1:32512',state/'observer/lab-rpc-token',genesis);ready(independent,observer)
        observer.stdin.write('peer 32501\n');observer.stdin.flush()
        check('naturally funded history has zero aggregate ordinary stake',rpc.call('getvalidators')['total_staked_veld']==0)
        members=[];consolidations=0
        for index in range(7):
            folder=state/('validator-'+str(index))
            subprocess.run([str(build/'pool-lab-keys'),str(folder)],capture_output=True,check=True)
            key=folder/'pool.seed'
            address,pubkey,script=subprocess.run([str(args.lab_signer),str(key),'identity'],capture_output=True,text=True,check=True).stdout.split()
            for attempt in range(1000):
                try:
                    prepared=rpc.call('preparerawtransaction',addresses['pool'],address,'10000.1')
                    if len(prepared['inputs'])<=128:break
                except Refused as error:
                    if 'cap' not in str(error) and 'fragment' not in str(error):raise
                compact=rpc.call('prepareconsolidatetx',addresses['pool'],'128','0')
                sign(compact,state/'keys/pool.seed');consolidations+=1
                if consolidations%20==0:print('native funding consolidations',consolidations,flush=True)
            else:raise RuntimeError('bounded native funding consolidation deadline')
            funding=sign(prepared,state/'keys/pool.seed')
            registration=sign(rpc.call('prepareregistervalidator',address,pubkey),key)
            record=rpc.call('getvalidatorinfo',pubkey)
            check('genuinely funded validator '+str(index+1)+' registered',record['registered'])
            members.append(dict(key=key,address=address,pubkey=pubkey))
            report['registrations'].append(dict(address=address,funding_txid=funding,registration_txid=registration,
                                                height=rpc.call('getblockcount'),bond_units='1000000000000'))
        registered=max(v['height'] for v in report['registrations'])
        snapshot=rpc.call('getfinalitysnapshot')['snapshot']
        check('seven new bonds do not bypass registration maturity or warm-up',not snapshot['active'])
        while True:
            snapshot=rpc.call('getfinalitysnapshot')['snapshot']
            if snapshot and snapshot['active']:break
            mine()
            if rpc.call('getblockcount')%100==0:print('native finality warm-up',rpc.call('getblockcount'),flush=True)
            if rpc.call('getblockcount')>registered+1600:raise RuntimeError('unchanged finality warm-up deadline')
        check('active snapshot preserves seven full bonds',len(snapshot['members'])==7 and snapshot['total_weight']==70000*100000000)
        check('all seven registrations satisfied canonical maturity',all(snapshot['snapshot_height']-v['registered_height']>=480 for v in snapshot['members']))
        check('aggregate ordinary stake remains zero',rpc.call('getvalidators')['total_staked_veld']==0)
        target=((rpc.call('getblockcount')//20)+1)*20
        while rpc.call('getblockcount')<=target:mine()
        block=rpc.call('getblockhash',str(target));snapshot=rpc.call('getfinalitysnapshot',str(target//480))['snapshot']
        for phase in (1,2):
            for index,member in enumerate(members[:5]):
                grant=rpc.call('getworkadmission','finality_vote',str(target),block)
                rpc.call('beginworksigning','finality_vote',grant['binding'],grant['signing_token'])
                intent=dict(epoch=str(snapshot['epoch']),set_root=snapshot['set_root'],phase=str(phase),
                    target_height=str(target),target_hash=block,source_height='0',source_hash='0'*64)
                # Persist the disposable signing intent before invoking crypto.
                intent_path=state/f'vote-{phase}-{index}.json';intent_path.write_bytes(encode(intent));intent_path.chmod(0o600)
                with intent_path.open('rb') as stream:os.fsync(stream.fileno())
                wire=subprocess.run([str(args.lab_signer),str(member['key']),'finality'],input=encode(intent)+b'\n',
                    capture_output=True,check=True,timeout=15).stdout.decode().strip()
                check('native finality vote accepted phase '+str(phase)+' signer '+str(index+1),
                      rpc.call('submitfinalityvote',wire,grant['binding'],grant['signing_token'])['accepted'])
                qc=rpc.call('getfinalityqc',str(phase))['qc_hex']
                if index==3:check('four signatures do not form phase '+str(phase)+' quorum',not qc)
                if index==4:check('five signatures form phase '+str(phase)+' quorum',bool(qc))
        with (out/'certificate.log').open('w') as log:
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(state/'tls.key'),
                '-out',str(state/'tls.crt'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],
                stdout=log,stderr=subprocess.STDOUT,check=True)
        (state/'tls.key').chmod(0o600)
        settings=dict(rpc_url='http://127.0.0.1:32502',rpc_token_file=str(state/'node/lab-rpc-token'),genesis=genesis,
            state_directory=str(state/'coordinator'),rollback_anchor=str(state/'work-anchor/current.json'),
            native_binary=str(build/'pool-work'),pool_address=addresses['pool'],accounting_target='7'+'f'*63,
            socket=str(state/'coordinator.sock'))
        coordinator=start('coordinator',[sys.executable,'-m','pool.service','--config',config('coordinator',settings)])
        until=time.monotonic()+60
        while not (state/'coordinator.sock').exists():
            assert coordinator.poll() is None
            if time.monotonic()>until:raise RuntimeError('pool coordinator readiness')
            time.sleep(.1)
        gateway=start('gateway',[sys.executable,'-m','pool.gateway','--config',config('gateway',dict(host='127.0.0.1',
            port=32543,certificate=str(state/'tls.crt'),private_key=str(state/'tls.key'),coordinator_socket=settings['socket']))])
        time.sleep(.3)
        node.stdin.write('clock '+str(1767225600+(rpc.call('getblockcount')+1)*180)+'\n');node.stdin.flush()
        worker=start('native-worker',[str(build/'pool-client'),'--config',config('worker',dict(endpoint='https://localhost:32543',
            ca_file=str(state/'tls.crt'),genesis=genesis,payout_address=addresses['worker-a'],state_directory=str(state/'worker'),
            threads='2',nonce_count='8',pause_ms='0'))])
        until=time.monotonic()+180
        while True:
            finalized=rpc.call('getfinalitysnapshot')['snapshot']['finalized']
            if finalized:break
            if time.monotonic()>until:raise RuntimeError('native pool QC-carrier deadline')
            assert worker.poll() is None and coordinator.poll() is None and gateway.poll() is None
            time.sleep(.1)
        (state/'worker/stop.request').write_text('stop\n');worker.wait(timeout=60)
        check('native pool worker carried the actual finality certificate',finalized['height']==target and finalized['hash']==block)
        tip=rpc.call('getbestblockhash');digest=rpc.call('getstatedigest');until=time.monotonic()+1800
        while independent.call('getbestblockhash')!=tip:
            if time.monotonic()>until:raise RuntimeError('independent QC validation deadline')
            time.sleep(.3)
        check('independent node validated the same finality and state',independent.call('getstatedigest')==digest and
              independent.call('getfinalitysnapshot')['snapshot']['finalized']==finalized)
        report.update(status='PASS',finalized=finalized,carrier_height=rpc.call('getblockcount'),consolidations=consolidations,
            worker=json.loads((state/'worker/pool-status.json').read_text()),independent_state_match=True)
    except BaseException as error:
        report.update(status='FAILED',error=repr(error));(out/'failure.txt').write_text(traceback.format_exc());raise
    finally:
        for p in reversed(processes):stop(p)
        for log in logs:log.close()
        report['processes_stopped']=all(p.poll() is not None for p in processes)
        report['binary_sha256']={n:hashlib.sha256((build/n).read_bytes()).hexdigest() for n in ('pool-backend','pool-client','pool-work')}
        report['lab_signer_sha256']=hashlib.sha256(args.lab_signer.read_bytes()).hexdigest();save()

if __name__=='__main__':main()
