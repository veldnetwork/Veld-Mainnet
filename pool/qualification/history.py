"""Mine reusable, closed disposable history with real PoW and unchanged money.

Only construction time is accelerated. This is funding/prehistory preparation,
not proof that the external pool workers or a production network are qualified.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from ..backend import Node
from ..protocol import Busy
from .isolation import require_isolated_network

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--build-directory',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--final-height',type=int,choices=(6500,50000),default=6500)
    args=parser.parse_args();require_isolated_network()
    out=args.output;out.mkdir(parents=True,exist_ok=False);source=Path(__file__).resolve().parents[2]
    state=Path(tempfile.mkdtemp(prefix='veld-pool-history-',dir='/var/tmp'))
    subprocess.run(['ip','link','set','lo','up'],check=True)
    keys=subprocess.check_output([str(args.build_directory/'pool-lab-keys'),str(state/'keys')],text=True)
    identities={'addresses':{},'scripts':{}}
    for line in keys.splitlines():
        name,address,script=line.split();identities['addresses'][name]=address;identities['scripts'][name]=script
    (state/'public-identities.json').write_text(json.dumps(identities,indent=2)+'\n')
    (out/'public-identities.json').write_text(json.dumps(identities,indent=2)+'\n')
    report={'status':'RUNNING','accelerated_historical_clock':True,'money_or_pow_bypassed':False,
            'pool_worker_evidence':False,'state_directory':str(state),'closed_snapshots':{}}
    def save():(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    node=None;logs=[]
    genesis=bytes.fromhex('ee875e86d25aabad2442451b82f6550b732a1387cbc172c2a3fc02eb216af3d5')[::-1].hex()
    rpc=Node('http://127.0.0.1:32662',state/'node/lab-rpc-token',genesis)
    def start(label):
        log=(out/(label+'.log')).open('w');logs.append(log)
        p=subprocess.Popen([str(args.build_directory/'pool-backend'),str(state/'node'),'32661','32662'],
            cwd=source,stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,text=True)
        until=time.monotonic()+1200
        while time.monotonic()<until:
            if p.poll() is not None:raise RuntimeError('history backend exited')
            try:rpc.check_chain();return p
            except (OSError,ValueError,Busy):time.sleep(.2)
        raise RuntimeError('history replay deadline')
    def stop():
        if node is None or node.poll() is not None:return
        node.stdin.write('stop\n');node.stdin.flush()
        try:node.wait(timeout=120)
        except subprocess.TimeoutExpired:node.kill();node.wait();raise RuntimeError('history graceful shutdown deadline')
        if node.returncode:raise RuntimeError('history backend shutdown failed')
    try:
        node=start('node-first')
        with (out/'blocks.jsonl').open('w') as receipts:
            for height in range(1,args.final_height+1):
                address=identities['addresses']['fees' if height<=10 else 'pool']
                node.stdin.write('clock '+str(1767225600+height*180)+'\n');node.stdin.flush()
                until=time.monotonic()+180;next_attempt=0
                while time.monotonic()<until:
                    if node.poll() is not None:raise RuntimeError('history backend exited')
                    if rpc.call('getblockcount')>=height:break
                    if time.monotonic()>=next_attempt:
                        node.stdin.write('mine '+address+'\n');node.stdin.flush();next_attempt=time.monotonic()+15
                    time.sleep(.05)
                else:raise RuntimeError('canonical mining remained unavailable at '+str(height))
                receipts.write(json.dumps({'height':height,'block':rpc.call('getblockhash',str(height)),'miner':address})+'\n')
                receipts.flush()
                if height%100==0:report['height']=height;save();print('native history',height,flush=True)
                if height==3266:
                    stop()
                    snapshot=Path(tempfile.mkdtemp(prefix='veld-pool-history-comining-',dir='/var/tmp'))
                    for directory in ('node','keys'):shutil.copytree(state/directory,snapshot/directory)
                    shutil.copy2(state/'public-identities.json',snapshot/'public-identities.json')
                    report['closed_snapshots']['comining']=str(snapshot);save();node=start('node-resumed')
                if height==6500 and args.final_height>6500:
                    stop()
                    snapshot=Path(tempfile.mkdtemp(prefix='veld-pool-history-validator-',dir='/var/tmp'))
                    for directory in ('node','keys'):shutil.copytree(state/directory,snapshot/directory)
                    shutil.copy2(state/'public-identities.json',snapshot/'public-identities.json')
                    report['closed_snapshots']['validator']=str(snapshot);save();node=start('node-finality-funding')
        stop()
        report['closed_snapshots']['finality' if args.final_height>6500 else 'validator']=str(state)
        report.update(status='PASS',height=args.final_height,processes_stopped=True)
    except BaseException as error:report.update(status='FAILED',error=repr(error));raise
    finally:
        try:stop()
        finally:
            for log in logs:log.close()
            report['binary_sha256']=hashlib.sha256((args.build_directory/'pool-backend').read_bytes()).hexdigest();save()

if __name__=='__main__':main()
