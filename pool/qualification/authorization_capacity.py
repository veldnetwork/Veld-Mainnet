"""Real disposable backend capacity boundary. No mocked issuance or public RPC."""
import argparse,hashlib,json,pathlib,subprocess,sys,tempfile,time
S=pathlib.Path(__file__).resolve().parents[2];sys.path.insert(0,str(S))
from pool.backend import Node
from pool.protocol import Busy,Refused
from pool.qualification.isolation import require_isolated_network
require_isolated_network()
parser=argparse.ArgumentParser()
parser.add_argument('--build',type=pathlib.Path,required=True)
parser.add_argument('--output',type=pathlib.Path,required=True)
parser.add_argument('--expect',choices=('refused','busy'),default='busy')
args=parser.parse_args()
args.output.mkdir(exist_ok=False)
state=pathlib.Path(tempfile.mkdtemp(prefix='veld-pool-auth-capacity-',dir='/var/tmp'))
(args.output/'state-directory.txt').write_text(str(state)+'\n')
subprocess.run(['ip','link','set','lo','up'],check=True)
keys=subprocess.check_output([str(args.build/'pool-lab-keys'),str(state/'keys')],text=True)
address=next(line.split()[1] for line in keys.splitlines() if line.startswith('pool '))
genesis='d5f36a21eb02fca3c272c1cb87132a730b55f6821b454224adab5ad2865e87ee'
node=Node('http://127.0.0.1:32862',state/'node/lab-rpc-token',genesis)
report=dict(status='RUNNING',scope='native authorization capacity and expiry recovery',
            production_build=False,mainnet_writes=False,issued=0)
with (args.output/'node.log').open('w') as log:
    proc=subprocess.Popen([str(args.build/'pool-backend'),str(state/'node'),'32861','32862'],
                          stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,text=True)
    try:
        until=time.monotonic()+120
        while True:
            assert proc.poll() is None
            try:node.check_chain();break
            except (OSError,Busy):
                if time.monotonic()>until:raise
                time.sleep(.1)
        begin=time.monotonic()
        for trial in range(65):
            try:
                result=node.template(address)
                assert result['height']==1 and 0<result['work_ttl_ms']<=10000
                report['issued']+=1
            except (Busy,Refused) as error:
                report.update(refusal_type=type(error).__name__,reason=str(error),refusal_trial=trial+1)
                assert trial==64,'unexpected capacity boundary'
                assert isinstance(error,Busy) if args.expect=='busy' else isinstance(error,Refused)
                break
        else:raise AssertionError('authorization capacity was not enforced')
        assert time.monotonic()-begin<10,'clock expiry invalidates this capacity exercise'
        # Existing authority may expire naturally; no cap/TTL override or reset.
        time.sleep(10.2)
        recovered=node.template(address)
        assert recovered['height']==1 and node.call('getblockcount')==0
        report.update(status='PASS',recovered_after_normal_expiry=True,chain_unchanged=True,
            interpretation='old defect reproduced' if args.expect=='refused' else 'capacity correctly retryable; no work accepted while full')
    except BaseException as error:
        report.update(status='FAILED',error=repr(error));raise
    finally:
        if proc.poll() is None:
            proc.stdin.write('stop\n');proc.stdin.flush()
            try:proc.wait(timeout=60)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
        report['process_stopped']=proc.poll() is not None
        report['backend_sha256']=hashlib.sha256((args.build/'pool-backend').read_bytes()).hexdigest()
        (args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
