"""Five-minute native worker load while an independent node validates each block.
Measured only for this disposable profile and host; not a public capacity claim.
"""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,sys,tempfile,time,statistics,traceback
src=pathlib.Path(__file__).resolve().parents[2]
from pool.backend import Node
from pool.protocol import encode,Busy,Refused
from pool.worker import Client
from pool.qualification.isolation import require_isolated_network
require_isolated_network()
parser=argparse.ArgumentParser()
parser.add_argument('--build-directory',type=pathlib.Path,required=True)
parser.add_argument('--fixture',type=pathlib.Path,required=True)
parser.add_argument('--output',type=pathlib.Path,required=True)
args=parser.parse_args();build=args.build_directory.resolve()
fixture=json.loads(args.fixture.read_text())
old=pathlib.Path(fixture['state_directory']);state=pathlib.Path(tempfile.mkdtemp(prefix='veld-pool-capacity-',dir='/var/tmp'))
out=args.output.resolve();out.mkdir(parents=True,exist_ok=False);(out/'state-directory.txt').write_text(str(state)+'\n')
subprocess.run(['ip','link','set','lo','up'],check=True)
for name in ('node','observer','coordinator','work-anchor'):shutil.copytree(old/name,state/name)
settings={k:(str(state)+v[len(str(old)):] if isinstance(v,str) and v.startswith(str(old)+'/') else v) for k,v in fixture['settings'].items()}
settings['native_binary']=str(build/'pool-work')
processes=[];logs=[];workers=[];rpc=None;node=None
report={'status':'RUNNING','scope':'300 seconds of two native TLS workers under concurrent native validation',
        'production_capacity_claim':False,'profile':'isolated ASERT full VeldHash, historical clock, unchanged monetary rules',
        'complete_pool_gate':False,'samples':[]}
def save():(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
def config(name,data):
 p=state/(name+'.json');p.write_bytes(encode(data));p.chmod(0o600);return str(p)
def start(name,args,stdin=False):
 log=(out/(name+'.log')).open('w');logs.append(log)
 p=subprocess.Popen(args,cwd=src,stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,text=True)
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
  if p.poll() is not None:raise RuntimeError('node exited')
  try:rpc.check_chain();return
  except (OSError,Busy,ValueError):time.sleep(.2)
 raise RuntimeError('node readiness deadline')
def rss(p):
 try:return int(next(l for l in pathlib.Path(f'/proc/{p.pid}/status').read_text().splitlines() if l.startswith('VmRSS:')).split()[1])*1024
 except (OSError,StopIteration):return 0
try:
 node=start('node',[str(build/'pool-backend'),str(state/'node'),'32361','32362'],True)
 rpc=Node('http://127.0.0.1:32362',state/'node/lab-rpc-token',fixture['genesis']);ready(rpc,node)
 observer=start('observer',[str(build/'pool-backend'),str(state/'observer'),'32371','32372'],True)
 independent=Node('http://127.0.0.1:32372',state/'observer/lab-rpc-token',fixture['genesis']);ready(independent,observer)
 observer.stdin.write('peer 32361\n');observer.stdin.flush()
 with (out/'certificate.log').open('w') as log:subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(state/'tls.key'),'-out',str(state/'tls.crt'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],stdout=log,stderr=subprocess.STDOUT,check=True)
 (state/'tls.key').chmod(0o600)
 coordinator=start('coordinator',[sys.executable,'-m','pool.service','--config',config('coordinator',settings)])
 until=time.monotonic()+60
 while time.monotonic()<until:
  if (state/'coordinator.sock').exists():break
  assert coordinator.poll() is None;time.sleep(.1)
 gateway=start('gateway',[sys.executable,'-m','pool.gateway','--config',config('gateway',{'host':'127.0.0.1','port':32443,'certificate':str(state/'tls.crt'),'private_key':str(state/'tls.key'),'coordinator_socket':str(state/'coordinator.sock')})])
 client=Client('https://localhost:32443',str(state/'tls.crt'),fixture['genesis']);time.sleep(.5)
 first=rpc.call('getblockcount');node.stdin.write('clock '+str(1767225600+(first+1)*180)+'\n');node.stdin.flush()
 for name,threads,pause in [('worker-a','2','0'),('worker-b','1','100')]:
  worker=start(name,[str(build/'pool-client'),'--config',config(name,{'endpoint':'https://localhost:32443','ca_file':str(state/'tls.crt'),'genesis':fixture['genesis'],'payout_address':fixture['addresses'][name],'state_directory':str(state/name),'threads':threads,'nonce_count':'8','pause_ms':pause})]);workers.append((name,worker))
 start_time=time.monotonic();next_sample=start_time;latencies=[];peak=0;max_queue=0;faults=0;previous=first
 while time.monotonic()-start_time<300:
  assert all(p.poll() is None for p in processes),'process exited during load'
  begin=time.monotonic()
  try:height=rpc.call('getblockcount');latencies.append(time.monotonic()-begin)
  except (OSError,Busy):faults+=1;continue
  if height!=previous:node.stdin.write('clock '+str(1767225600+(height+1)*180)+'\n');node.stdin.flush();previous=height
  if time.monotonic()>=next_sample:
   health=client.call('health',{});queue=health['verification_queue'];assert queue['waiting']<=queue['capacity']
   max_queue=max(max_queue,queue['waiting']);usage=sum(rss(p) for p in processes);peak=max(peak,usage)
   report['samples'].append({'seconds':round(time.monotonic()-start_time,2),'height':height,'observer_height':independent.call('getblockcount'),'process_rss_bytes':usage,'waiting':queue['waiting'],'status':health['status']});save()
   print('native load height',height,'queue',queue['waiting'],flush=True);next_sample=time.monotonic()+10
  time.sleep(.2)
 for name,p in workers:(state/name/'stop.request').write_text('stop\n');p.wait(timeout=60)
 end=rpc.call('getblockcount');tip=rpc.call('getbestblockhash');until=time.monotonic()+180
 while time.monotonic()<until:
  if independent.call('getbestblockhash')==tip:break
  time.sleep(.5)
 else:raise RuntimeError('independent observer did not catch up after sustained load')
 assert independent.call('getstatedigest')==rpc.call('getstatedigest'),'independent state mismatch'
 metrics={n:json.loads((state/n/'pool-status.json').read_text()) for n,p in workers}
 assert all(int(m['accepted'])>0 for m in metrics.values()) and end>first
 elapsed=time.monotonic()-start_time;accepted=sum(int(m['accepted']) for m in metrics.values())
 ordered=sorted(latencies)
 report.update(status='PASS',starting_height=first,ending_height=end,elapsed_seconds=elapsed,verified_shares=accepted,
      observed_verified_shares_per_second=accepted/elapsed,rpc_samples=len(latencies),rpc_timeouts=faults,
      rpc_median_seconds=statistics.median(latencies),rpc_p95_seconds=ordered[int(.95*(len(ordered)-1))],
      peak_service_and_worker_rss_bytes=peak,max_unverified_queue=max_queue,independent_tip_and_state_match=True,workers=metrics,
      limitations=['one development host with concurrent compilation','300-second observation, not maximum sustainable public capacity','RSS sample excludes transient signer/verifier child processes'])
except BaseException as error:report.update(status='FAILED',error=repr(error));(out/'failure.txt').write_text(traceback.format_exc());raise
finally:
 for p in reversed(processes):stop(p)
 for log in logs:log.close()
 report['processes_stopped']=all(p.poll() is not None for p in processes)
 report['binary_sha256']={n:hashlib.sha256((build/n).read_bytes()).hexdigest() for n in ('pool-backend','pool-client','pool-work')}
 save()
