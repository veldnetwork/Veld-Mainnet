"""Genuine TLS workers, normal node admission, maturity and native signatures.
This intermediate probe is not the full pool qualification or a launch gate.
"""
import argparse,hashlib,json,os,pathlib,subprocess,sys,tempfile,time
src=pathlib.Path(__file__).resolve().parents[2]
from pool.backend import Node
from pool.worker import Client
from pool.native import Native
from pool.protocol import encode

from pool.qualification.isolation import require_isolated_network
require_isolated_network()
parser=argparse.ArgumentParser()
parser.add_argument('--build-directory',type=pathlib.Path,required=True)
parser.add_argument('--output',type=pathlib.Path,required=True)
args=parser.parse_args();build=args.build_directory;out=args.output
out.mkdir(parents=True,exist_ok=False)
state=pathlib.Path(tempfile.mkdtemp(prefix='veld-pool-payment-',dir='/var/tmp'))
(out/'state-directory.txt').write_text(str(state)+'\n')
subprocess.run(['ip','link','set','lo','up'],check=True)
keys=subprocess.run([str(build/'pool-lab-keys'),str(state/'disposable-keys')],capture_output=True,text=True,check=True)
addresses={line.split()[0]:line.split()[1] for line in keys.stdout.splitlines()}
scripts={line.split()[0]:line.split()[2] for line in keys.stdout.splitlines()}
(out/'addresses.json').write_text(json.dumps(addresses,indent=2)+'\n')
with (out/'certificate.log').open('w') as log:
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(state/'tls.key'),'-out',str(state/'tls.crt'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],stdout=log,stderr=subprocess.STDOUT,check=True)
os.chmod(state/'tls.key',0o600)
processes=[];handles=[];node=None
def start(name,command,stdin=False):
 log=(out/(name+'.log')).open('w');handles.append(log)
 process=subprocess.Popen(command,cwd=src,stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,text=True)
 processes.append(process);return process
def stop(process):
 if process.poll() is None:
  if process.stdin is not None:process.stdin.write('stop\n');process.stdin.flush()
  else:process.terminate()
  try:process.wait(timeout=30)
  except subprocess.TimeoutExpired:process.kill();process.wait()
def config(name,data):
 path=state/(name+'.json');path.write_bytes(encode(data));os.chmod(path,0o600);return str(path)
def services(generation):
 coordinator=start('coordinator-'+str(generation),[sys.executable,'-m','pool.service','--config',config('coordinator',settings)])
 for _ in range(150):
  if (state/'coordinator.sock').exists():break
  if coordinator.poll() is not None:raise RuntimeError('coordinator exited')
  time.sleep(.1)
 else:raise RuntimeError('IPC startup timeout')
 gateway=start('gateway-'+str(generation),[sys.executable,'-m','pool.gateway','--config',gateway_config]);time.sleep(.4)
 workers=[]
 for name,count,pause in [('worker-a',4,30),('worker-b',2,120)]:
  path=config(name,{'endpoint':'https://localhost:32443','ca_file':str(state/'tls.crt'),'genesis':genesis,'payout_address':addresses[name],'native_binary':str(build/'pool-work'),'account_file':str(state/(name+'-account.json')),'nonce_count':count,'pause_ms':pause})
  workers.append(start(name+'-'+str(generation),[sys.executable,'-m','pool.worker','--config',path]))
 return coordinator,gateway,workers
def accounts():
 result={}
 for name in ('worker-a','worker-b'):
  data=json.loads((state/(name+'-account.json')).read_text())
  result[name]=client.call('account',{'account':data['account'],'token':data['view_token']})
 return result
report={'status':'RUNNING','scope':'native worker-to-wallet including restart; intermediate gate','required_gate_complete':False}
try:
 node=start('node',[str(build/'pool-backend'),str(state/'node'),'32361','32362'],True)
 genesis=bytes.fromhex('ee875e86d25aabad2442451b82f6550b732a1387cbc172c2a3fc02eb216af3d5')[::-1].hex()
 backend=Node('http://127.0.0.1:32362',state/'node/lab-rpc-token',genesis)
 for _ in range(100):
  if node.poll() is not None:raise RuntimeError('node exited')
  try:backend.check_chain();break
  except (OSError,ValueError):time.sleep(.1)
 else:raise RuntimeError('node startup timeout')
 node.stdin.write('clock 1767225780\n');node.stdin.flush();time.sleep(.1)
 # One ordinary, genuinely mined block supplies only operator fee funds.
 with (out/'fee-mining.log').open('w') as log:
  verifier=Native(build/'pool-work',log)
  try:
   template=backend.template(addresses['fees']);raw=bytearray.fromhex(template['block_hex'])
   for nonce in range(1000):
    raw[80:88]=nonce.to_bytes(8,'little')
    proof,_=verifier.hash(bytes(raw[:88]),template['height'])
    if int(proof,16)<int(template['target'],16):
     assert backend.submit(template,nonce)['accepted'];break
   else:raise RuntimeError('fee funding work bound')
  finally:verifier.close()
 assert backend.call('getblockcount')==1
 observer=start('observer',[str(build/'pool-backend'),str(state/'observer'),'32371','32372'],True)
 independent=Node('http://127.0.0.1:32372',state/'observer/lab-rpc-token',genesis)
 for _ in range(100):
  if observer.poll() is not None:raise RuntimeError('observer exited')
  try:independent.check_chain();break
  except (OSError,ValueError):time.sleep(.1)
 else:raise RuntimeError('observer startup timeout')
 observer.stdin.write('peer 32361\n');observer.stdin.flush()
 settings={'rpc_url':'http://127.0.0.1:32362','rpc_token_file':str(state/'node/lab-rpc-token'),'genesis':genesis,'state_directory':str(state/'coordinator'),'rollback_anchor':str(state/'work-anchor/current.json'),'native_binary':str(build/'pool-work'),'pool_address':addresses['pool'],'accounting_target':'7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff','socket':str(state/'coordinator.sock')}
 gateway_config=config('gateway',{'host':'127.0.0.1','port':32443,'certificate':str(state/'tls.crt'),'private_key':str(state/'tls.key'),'coordinator_socket':str(state/'coordinator.sock')})
 client=Client('https://localhost:32443',str(state/'tls.crt'),genesis)
 coordinator,gateway,workers=services(1)
 last=-1;deadline=time.monotonic()+2400
 while time.monotonic()<deadline:
  assert all(p.poll() is None for p in [coordinator,gateway,*workers]),'service exited during mining'
  height=backend.call('getblockcount')
  if height!=last:
   node.stdin.write('clock '+str(1767225600+(height+1)*180)+'\n');node.stdin.flush()
   last=height
   if height%10==0:print('maturity mining height',height,flush=True)
  if height>=140:break
  time.sleep(.15)
 else:raise RuntimeError('maturity timeout')
 for worker in workers:stop(worker)
 before=accounts();(out/'before-payments.json').write_text(json.dumps(before,indent=2)+'\n')
 assert all(int(a['available_units'])>=100000000 for a in before.values()),'both miners need mature balances'
 for _ in range(240):
  if independent.call('getblockcount')==backend.call('getblockcount') and independent.call('getbestblockhash')==backend.call('getbestblockhash'):break
  time.sleep(.5)
 else:raise RuntimeError('independent fixture validation timeout')
 stop(gateway);stop(coordinator)
 fixture={'settings':settings,'addresses':addresses,'scripts':scripts,'genesis':genesis,
          'state_directory':str(state),'build_directory':str(build),'before_payments':before}
 config('fixture',fixture)
 report.update(status='PREPARED',height=height,scope='native mature pool-income fixture before any payout',
               fixture_path=str(state/'fixture.json'))
 print(json.dumps(report),flush=True)
except BaseException as error:
 report.update(status='FAILED',error=repr(error));raise
finally:
 for process in reversed(processes):stop(process)
 report['processes_stopped']=all(p.poll() is not None for p in processes)
 (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
 for handle in handles:handle.close()
