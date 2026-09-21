"""Concurrent native template requests across real canonical PoW commits.

No mocked response or relaxed authorization. The pre-fix adapter stops on the
coordinator's BindingMismatch closure; the repaired adapter must remain closed
but retryable and subsequently obtain fresh native authority.
"""
import argparse
import collections
import hashlib
import json
import pathlib
import subprocess
import tempfile
import threading
import time
from ..backend import Node
from ..protocol import Busy
from .control import mine_block
from .isolation import require_isolated_network


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--build',type=pathlib.Path,required=True)
    parser.add_argument('--output',type=pathlib.Path,required=True)
    args=parser.parse_args();require_isolated_network()
    source=pathlib.Path(__file__).resolve().parents[2]
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    state=pathlib.Path(tempfile.mkdtemp(prefix='veld-template-transition-',dir='/var/tmp'))
    state.chmod(0o700);(out/'state-directory.txt').write_text(str(state)+'\n')
    subprocess.run(['ip','link','set','lo','up'],check=True)
    keys=subprocess.check_output([str(args.build/'pool-lab-keys'),str(state/'keys')],text=True)
    address=next(line.split()[1] for line in keys.splitlines() if line.startswith('pool '))
    genesis='d5f36a21eb02fca3c272c1cb87132a730b55f6821b454224adab5ad2865e87ee'
    def client():return Node('http://127.0.0.1:34762',state/'node/lab-rpc-token',genesis)
    rpc=client();counts=collections.Counter();failures=[];lock=threading.Lock()
    stop=threading.Event();transition_seen=threading.Event();threads=[]
    report=dict(status='RUNNING',scope='native work authorization across actual canonical commits',
                production_build=False,mainnet=False,real_pow=True)
    def save():
        with lock:report.update(outcomes=dict(counts),failures=list(failures))
        (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    def reader():
        node=client()
        while not stop.is_set():
            try:
                result=node.template(address)
                assert result['work_token'] and result['work_binding']
                with lock:
                    counts['usable_template']+=1
                    if transition_seen.is_set():counts['usable_after_transition']+=1
            except Busy as error:
                with lock:
                    counts['bounded_busy']+=1
                    if str(error)=='node canonical work transition; request fresh work':
                        counts['canonical_transition']+=1;transition_seen.set()
            except Exception as error:
                with lock:
                    counts['fatal']+=1
                    if len(failures)<20:failures.append(str(error)[:350])
            stop.wait(.2)
    with (out/'node.log').open('w') as log:
        process=subprocess.Popen([str(args.build/'pool-backend'),str(state/'node'),'34761','34762'],
            cwd=source,stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,text=True)
        try:
            deadline=time.monotonic()+120
            while True:
                assert process.poll() is None
                try:rpc.check_chain();break
                except (OSError,Busy):
                    if time.monotonic()>deadline:raise
                    time.sleep(.1)
            for _ in range(3):
                thread=threading.Thread(target=reader);thread.start();threads.append(thread)
            for index in range(192):
                mine_block(process,rpc,address,out/'node.log');report['height']=rpc.call('getblockcount')
                if index%8==0:save()
                with lock:
                    if counts['fatal']:raise AssertionError('native work transition became a fatal refusal')
                    complete=counts['canonical_transition']>0 and counts['usable_after_transition']>=8
                if index>=63 and complete:break
            assert complete,'required native transition was not observed; this run does not qualify the fix'
            report['status']='PASS'
        except BaseException as error:report.update(status='FAILED',error=repr(error));raise
        finally:
            stop.set()
            for thread in threads:thread.join(timeout=30)
            if process.poll() is None:
                process.stdin.write('stop\n');process.stdin.flush()
                try:process.wait(timeout=60)
                except subprocess.TimeoutExpired:process.kill();process.wait()
            report.update(processes_stopped=process.poll() is not None and not any(t.is_alive() for t in threads),
                backend_sha256=hashlib.sha256((args.build/'pool-backend').read_bytes()).hexdigest())
            save()
    print(json.dumps(report))


if __name__=='__main__':main()
