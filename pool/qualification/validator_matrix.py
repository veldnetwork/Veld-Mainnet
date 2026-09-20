"""Funded registrations at zero/below/at/above the former aggregate floor.

Only closed, naturally mined disposable history is accepted. No state injection,
fake wallet, fee waiver, altered bond, or consensus bypass is used. Historical
activation/reorganization coverage is the companion validator exercise.
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
from ..protocol import Busy, Refused, encode
from .control import mine_block
from .isolation import require_isolated_network
from .progress import ValidationProgress


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--build-directory',type=Path,required=True)
    parser.add_argument('--history-state',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();require_isolated_network()
    source=Path(__file__).resolve().parents[2]
    build=args.build_directory.resolve();history=args.history_state.resolve()
    assert history.parent==Path('/var/tmp') and history.name.startswith('veld-pool-history-')
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():continue
        try:command=(entry/'cmdline').read_bytes().split(b'\0')
        except OSError:continue
        assert str(history/'node').encode() not in command,'source history must be closed'
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    state=Path(tempfile.mkdtemp(prefix='veld-pool-validator-matrix-',dir='/var/tmp'))
    (out/'state-directory.txt').write_text(str(state)+'\n')
    shutil.copytree(history/'node',state/'funding')
    shutil.copytree(history/'keys',state/'keys')
    public=json.loads((history/'public-identities.json').read_text())
    addresses=public['addresses'];genesis='d5f36a21eb02fca3c272c1cb87132a730b55f6821b454224adab5ad2865e87ee'
    subprocess.run(['ip','link','set','lo','up'],check=True)
    report=dict(status='RUNNING',scope='native funded former-floor matrix',
        production_build=False,mainnet_writes=False,accelerated_clock=True,
        economics_modified=False,complete_pool_gate=False,cases=[])
    processes=[];logs=[];logpaths={}
    def save():
        temp=out/'result.json.new';temp.write_text(json.dumps(report,indent=2)+'\n');temp.replace(out/'result.json')
    def start(name,folder,p2p,port):
        log=(out/(name+'.log')).open('w');logs.append(log)
        proc=subprocess.Popen([str(build/'pool-backend'),str(folder),str(p2p),str(port)],
            cwd=source,stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,text=True)
        processes.append(proc);logpaths[proc.pid]=out/(name+'.log')
        rpc=Node('http://127.0.0.1:'+str(port),folder/'lab-rpc-token',genesis)
        until=time.monotonic()+3600
        while True:
            assert proc.poll() is None,'native replay process exited'
            try:rpc.check_chain();return proc,rpc
            except (OSError,ValueError,Busy):
                if time.monotonic()>until:raise TimeoutError('native replay readiness')
                time.sleep(.25)
    def stop(proc):
        if proc.poll() is not None:return
        proc.stdin.write('stop\n');proc.stdin.flush()
        try:proc.wait(timeout=120)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
    def mine(proc,rpc):return mine_block(proc,rpc,addresses['fees'],logpaths[proc.pid])
    def sign(prepared,key):
        answer=subprocess.run([str(build/'pool-lab-sign'),str(key),'transaction'],
            input=encode(dict(unsigned_tx_hex=prepared['unsigned_tx_hex'],bond_units='',reduce_change_units='0'))+b'\n',
            capture_output=True,check=True,timeout=120).stdout.decode().split()
        assert len(answer)==2;return answer
    def pay(proc,rpc,prepared,key):
        txid,raw=sign(prepared,key);assert rpc.call('sendrawtransaction',raw)==txid
        mine(proc,rpc);return txid
    def funds(rpc,address):
        amount=Fraction(str(rpc.call('getbalance',address)['balance_veld']))*100000000
        assert amount.denominator==1;return int(amount)
    def record(case,name,value):
        assert value,name
        case['checks'].append(name);save();print(case['name']+': '+name,flush=True)
    try:
        producer,rpc=start('funding',state/'funding',32901,32902)
        assert rpc.call('getblockcount')>=9500,'history must be after the isolated candidate boundary'
        assert rpc.call('getvalidators')['total_staked_veld']==0
        assert rpc.call('getvalidators')['validator_count']==0
        # Consolidate actual operator earnings once, then clone this CLOSED
        # canonical state for each independent scenario. No database edits.
        for attempt in range(1000):
            try:
                probe=rpc.call('preparerawtransaction',addresses['pool'],addresses['worker-a'],'25000')
                if len(probe['inputs'])<=128:break
            except Refused as error:
                if 'cap' not in str(error) and 'fragment' not in str(error):raise
            pay(producer,rpc,rpc.call('prepareconsolidatetx',addresses['pool'],'128','0'),state/'keys/pool.seed')
        else:raise TimeoutError('bounded genuine bond funding consolidation')
        report['funding_tip']=rpc.call('getbestblockhash')
        report['funding_height']=rpc.call('getblockcount');save();stop(producer)
        for name,stakes in [('zero',()),('below',(9999,)),('at',(10000,)),('above',(9501,500))]:
            case=dict(name=name,ordinary_stake_veld=sum(stakes),checks=[],status='RUNNING')
            report['cases'].append(case);save()
            folder=state/name;shutil.copytree(state/'funding',folder/'node')
            shutil.copytree(state/'funding',folder/'observer')
            producer,rpc=start(name,folder/'node',32901,32902)
            assert rpc.call('getbestblockhash')==report['funding_tip']
            for index,amount in enumerate(stakes):
                keydir=folder/('staker-'+str(index))
                subprocess.run([str(build/'pool-lab-keys'),str(keydir)],capture_output=True,check=True)
                key=keydir/'pool.seed'
                address,pubkey,script=subprocess.run([str(build/'pool-lab-sign'),str(key),'identity'],
                    capture_output=True,text=True,check=True).stdout.split()
                pay(producer,rpc,rpc.call('preparerawtransaction',addresses['pool'],address,str(amount)+'.1'),state/'keys/pool.seed')
                pay(producer,rpc,rpc.call('preparestake',address,str(amount),'1'),key)
            record(case,'actual ordinary stake equals requested aggregate',
                Fraction(str(rpc.call('getvalidators')['total_staked_veld']))==sum(stakes))
            address=addresses['pool'];key=state/'keys/pool.seed'
            _,pubkey,_=subprocess.run([str(build/'pool-lab-sign'),str(key),'identity'],
                capture_output=True,text=True,check=True).stdout.split()
            before=funds(rpc,address);prepared=rpc.call('prepareregistervalidator',address,pubkey)
            registration=pay(producer,rpc,prepared,key);height=rpc.call('getblockcount')
            record(case,'funded individual bond registers regardless of former aggregate floor',
                rpc.call('getvalidatorinfo',pubkey)['registered'] and rpc.call('getvalidators')['validator_count']==1)
            record(case,'individual bond and transaction fee charged exactly once',
                before-funds(rpc,address)==10000*100000000+100000)
            record(case,'registration alone produces no endorsement or automatic payment',
                rpc.call('getblockendorsements',str(height))['count']==0)
            record(case,'bond does not alter ordinary stake',
                Fraction(str(rpc.call('getvalidators')['total_staked_veld']))==sum(stakes))
            vault=rpc.call('getbondvaultinfo')
            bond=[v for v in vault['validators'] if v['address']==address]
            record(case,'custody principal is attributable to this validator',len(bond)==1 and
                bond[0]['bond_veld']==10000 and bond[0]['principal_held'])
            block=rpc.call('getblockhash',str(height))
            grant=rpc.call('getworkadmission','validator_endorsement',str(height),block)
            rpc.call('beginworksigning','validator_endorsement',grant['binding'],grant['signing_token'])
            op=subprocess.run([str(build/'pool-lab-sign'),str(key),'endorse'],
                input=encode(dict(height=str(height),block=block))+b'\n',capture_output=True,check=True,timeout=120).stdout.decode().strip()
            txid,raw=sign(rpc.call('preparerawop',address,op),key)
            assert rpc.call('sendrawtransaction',raw,grant['binding'],grant['signing_token'])==txid
            mine(producer,rpc)
            record(case,'one validator performs eligible endorsement without a finality set',
                rpc.call('getblockendorsements',str(height))['count']==1)
            snapshot=rpc.call('getfinalitysnapshot').get('snapshot')
            record(case,'finality quorum and governance gates remain closed',
                not(snapshot and snapshot['active']) and not rpc.call('getgovernanceinfo')['governance_active'])
            tip=rpc.call('getbestblockhash');digest=rpc.call('getstatedigest');stop(producer)
            producer,rpc=start(name+'-restarted',folder/'node',32901,32902)
            record(case,'restart preserves canonical bond stake and endorsement accounting',
                rpc.call('getbestblockhash')==tip and rpc.call('getstatedigest')==digest)
            observer,independent=start(name+'-observer',folder/'observer',32911,32912)
            observer.stdin.write('peer 32901\n');observer.stdin.flush()
            progress=ValidationProgress(independent.call('getblockcount'),rpc.call('getblockcount'),time.monotonic())
            while independent.call('getbestblockhash')!=tip:
                assert observer.poll() is None and producer.poll() is None
                progress.observe(independent.call('getblockcount'),time.monotonic());time.sleep(1)
            record(case,'independent node validates identical state and owned principal',
                independent.call('getstatedigest')==digest and independent.call('getbondvaultinfo')==rpc.call('getbondvaultinfo'))
            case.update(status='PASS',registration_txid=registration,endorsement_txid=txid,
                height=rpc.call('getblockcount'),tip=tip,independent_state=digest)
            save();stop(observer);stop(producer)
        report['status']='PASS'
    except BaseException as error:
        report.update(status='FAILED',error=repr(error));(out/'failure.txt').write_text(traceback.format_exc());raise
    finally:
        for proc in reversed(processes):stop(proc)
        for log in logs:log.close()
        report['processes_stopped']=all(p.poll() is not None for p in processes)
        report['binaries']={n:hashlib.sha256((build/n).read_bytes()).hexdigest() for n in ('pool-backend','pool-lab-sign','pool-lab-keys')}
        save()


if __name__=='__main__':main()
