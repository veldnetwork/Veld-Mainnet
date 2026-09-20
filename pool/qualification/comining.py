"""Funded native co-mining and shared-yield qualification in a disposable namespace.

Prehistory is naturally mined with unchanged economics. Fast historical clock
construction and intervening fixture blocks are explicitly not worker evidence.
Workers, proofs, signatures, settlements and payouts use native implementations.
"""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,sys,tempfile,time
from fractions import Fraction
src=pathlib.Path(__file__).resolve().parents[2]
from pool.backend import Node
from pool.protocol import encode,Busy,Refused
from pool.worker import Client
from pool.qualification.isolation import require_isolated_network
from pool.qualification.control import mine_block
require_isolated_network()
parser=argparse.ArgumentParser()
parser.add_argument('--build-directory',type=pathlib.Path,required=True)
parser.add_argument('--history-state',type=pathlib.Path,required=True)
parser.add_argument('--output',type=pathlib.Path,required=True)
parser.add_argument('--public-identities',type=pathlib.Path,help='public identity receipt for an older closed fixture')
parser.add_argument('--reorganization',action='store_true',help='replace immature lottery/yield income through a genuine competing branch')
args=parser.parse_args();build=args.build_directory;out=args.output
original=pathlib.Path(args.history_state).resolve()
assert original.parent==pathlib.Path('/var/tmp') and original.name.startswith('veld-pool-history-')
for proc in pathlib.Path('/proc').iterdir():
 if not proc.name.isdigit():continue
 try:running=(proc/'cmdline').read_bytes().split(b'\0')
 except (FileNotFoundError,PermissionError,ProcessLookupError):continue
 assert str(original/'node').encode() not in running,'stop the exact source fixture before cloning'
out.mkdir(parents=True,exist_ok=False)
state=pathlib.Path(tempfile.mkdtemp(prefix='veld-pool-comining-',dir='/var/tmp'))
(out/'state-directory.txt').write_text(str(state)+'\n')
shutil.copytree(original/'node',state/'node');shutil.copytree(original/'node',state/'observer')
if args.reorganization:shutil.copytree(original/'node',state/'fork')
shutil.copytree(original/'keys',state/'disposable-keys')
public=json.loads((args.public_identities or original/'public-identities.json').read_text());addresses,scripts=public['addresses'],public['scripts']
subprocess.run(['ip','link','set','lo','up'],check=True)
with (out/'certificate.log').open('w') as log:
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(state/'tls.key'),'-out',str(state/'tls.crt'),
                 '-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],stdout=log,stderr=subprocess.STDOUT,check=True)
(state/'tls.key').chmod(0o600)
processes=[];logs=[];workers=[];generation=0;coordinator=None;gateway=None
report={'status':'RUNNING','scope':'funded native co-mining, shared ordinary yield and recipient-wallet payments',
        'accelerated_historical_clock':True,'consensus_or_economics_bypassed':False,'complete_pool_gate':False}
def save(name,value):
 (out/name).write_text(json.dumps(value,indent=2)+'\n')
def config(name,value):
 path=state/(name+'.json');path.write_bytes(encode(value));path.chmod(0o600);return str(path)
def start(name,command,stdin=False):
 log=(out/(name+'.log')).open('w');logs.append(log)
 p=subprocess.Popen(command,cwd=src,stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,text=True)
 processes.append(p);return p
def stop(p):
 if p is None or p.poll() is not None:return
 if p.stdin:p.stdin.write('stop\n');p.stdin.flush()
 else:p.terminate()
 try:p.wait(timeout=45)
 except subprocess.TimeoutExpired:p.kill();p.wait()
def ready(rpc,p):
 until=time.monotonic()+900
 while time.monotonic()<until:
  if p.poll() is not None:raise RuntimeError('native backend exited')
  try:rpc.check_chain();return
  except (OSError,ValueError,Busy):time.sleep(.25)
 raise RuntimeError('native replay readiness deadline')
def clock():
 height=rpc.call('getblockcount');node.stdin.write('clock '+str(1767225600+(height+1)*180)+'\n');node.stdin.flush();return height
def services():
 global coordinator,gateway,generation
 generation+=1
 coordinator=start('coordinator-'+str(generation),[sys.executable,'-m','pool.service','--config',config('coordinator',settings)])
 until=time.monotonic()+90
 while time.monotonic()<until:
  if coordinator.poll() is not None:raise RuntimeError('coordinator exited')
  if (state/'coordinator.sock').exists():break
  time.sleep(.1)
 else:raise RuntimeError('coordinator readiness deadline')
 gateway=start('gateway-'+str(generation),[sys.executable,'-m','pool.gateway','--config',gateway_config]);time.sleep(.5)
def start_workers():
 global workers
 workers=[]
 # This economic/fork exercise needs the native signer to observe a stable
 # parent between jobs on the fast historical test clock. Throttle via the
 # normal worker CPU/pause controls; capacity is measured in its own gate.
 for name,threads,pause in [('worker-a','2','4000'),('worker-b','1','6000')]:
  folder=state/name;folder.mkdir(exist_ok=True,mode=0o700)
  (folder/'stop.request').unlink(missing_ok=True)
  path=config(name,{'endpoint':'https://localhost:32443','ca_file':str(state/'tls.crt'),'genesis':genesis,
     'payout_address':addresses[name],'state_directory':str(folder),'threads':threads,'nonce_count':'8','pause_ms':pause})
  workers.append(start(name+'-'+str(generation)+'-'+str(len(processes)),[str(build/'pool-client'),'--config',path]))
def stop_workers():
 for name in ('worker-a','worker-b'):
  path=state/name/'stop.request'
  if path.parent.exists():path.write_text('stop\n');path.chmod(0o600)
 for p in workers:
  try:p.wait(timeout=45)
  except subprocess.TimeoutExpired:stop(p)
def accounts():
 result={}
 for name in ('worker-a','worker-b'):
  access=json.loads((state/name/'pool-account.json').read_text())
  result[name]=client.call('account',{'account':access['account'],'token':access['view_token']})
 return result
def events(directory):
 path=state/directory/'events.jsonl'
 if not path.exists():return []
 rows=path.read_bytes().splitlines();result=[]
 for line in rows:
  try:result.append(json.loads(line))
  except json.JSONDecodeError:break # Live writer may not have finished its last append.
 return result
def advance(target):
 # Intervening history/confirmations only; no worker or pool-income claim.
 while rpc.call('getblockcount')<target:
  mine_block(node,rpc,addresses['fees'],out/'node.log')
def worker_boundary(draw):
 advance(draw-2);clock();start_workers();until=time.monotonic()+300
 while time.monotonic()<until:
  height=clock()
  if height>=draw:break
  assert all(p.poll() is None for p in workers),'native worker exited at boundary'
  time.sleep(.25)
 else:raise RuntimeError('worker settlement boundary deadline')
 stop_workers();report.setdefault('worker_settlement_heights',[]).append(draw)
 print('native worker settlement',draw,flush=True)
try:
 genesis=bytes.fromhex('ee875e86d25aabad2442451b82f6550b732a1387cbc172c2a3fc02eb216af3d5')[::-1].hex()
 node=start('node',[str(build/'pool-backend'),str(state/'node'),'32661','32662'],True)
 rpc=Node('http://127.0.0.1:32662',state/'node/lab-rpc-token',genesis);ready(rpc,node)
 observer=start('observer',[str(build/'pool-backend'),str(state/'observer'),'32671','32672'],True)
 independent=Node('http://127.0.0.1:32672',state/'observer/lab-rpc-token',genesis);ready(independent,observer)
 rpc.require_transaction_index();independent.require_transaction_index()
 report['operational_transaction_indexes_verified']=True
 observer.stdin.write('peer 32661\n');observer.stdin.flush()
 initial=rpc.call('getpoolidentitystate',addresses['pool']);assert initial['staking_active'] and int(initial['stake_units'])==0
 report['starting_height']=clock();report['initial_identity']=initial
 funding=[{'txid':c['txid'],'vout':str(c['vout']),'units':str(c['value_units'])} for c in
          sorted(rpc.call('listunspent',addresses['pool']),key=lambda c:(-c['value_units'],c['txid']))[:750]]
 assert sum(int(c['units']) for c in funding)>1001*100000000
 funding_file=config('operator-funding',{'chain':genesis,'script':scripts['pool'],'funding':funding})
 settings={'rpc_url':'http://127.0.0.1:32662','rpc_token_file':str(state/'node/lab-rpc-token'),'genesis':genesis,
    'state_directory':str(state/'coordinator'),'rollback_anchor':str(state/'work-anchor/current.json'),
    'native_binary':str(build/'pool-work'),'pool_address':addresses['pool'],
    'accounting_target':'7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff','socket':str(state/'coordinator.sock'),
    'identity':{'state_directory':str(state/'identity'),'rollback_anchor':str(state/'identity-anchor/current.json'),
                'native_binary':str(build/'pool-identity'),'seed':str(state/'disposable-keys/pool.seed'),'script':scripts['pool'],
                'operator_funding_file':funding_file,'tier':1}}
 gateway_config=config('gateway',{'host':'127.0.0.1','port':32443,'certificate':str(state/'tls.crt'),'private_key':str(state/'tls.key'),
                                  'coordinator_socket':str(state/'coordinator.sock')})
 client=Client('https://localhost:32443',str(state/'tls.crt'),genesis)
 services()
 # Prepare the separately funded operator stake before worker traffic. Racing
 # a fast worker against the one-second identity maintenance loop wastes many
 # fixture blocks between consolidations and can cross the draw/fork boundary.
 # Every consolidation and stake still uses the restricted signer, mempool,
 # real PoW and normal canonical inclusion.
 until=time.monotonic()+900
 while int(rpc.call('getpoolidentitystate',addresses['pool'])['stake_units'])==0:
  if time.monotonic()>until:raise RuntimeError('operator stake preparation deadline')
  if rpc.call('getrawmempool'):
   advance(rpc.call('getblockcount')+1)
  else:time.sleep(.25)
 report['stake_prepared_height']=rpc.call('getblockcount')
 start_workers();until=time.monotonic()+1800
 while time.monotonic()<until:
  try:clock();status=rpc.call('getpoolidentitystate',addresses['pool'])
  except (OSError,Busy) as error:
   report['temporary_node_retries']=report.get('temporary_node_retries',0)+1
   print('bounded native node retry',type(error).__name__,flush=True);time.sleep(.5);continue
  assert coordinator.poll() is None and all(p.poll() is None for p in workers),'pool service/worker exited'
  if status['included_submission']:
   balances=accounts()
   if all(int(a['verified_shares'])>0 for a in balances.values()):break
  time.sleep(.5)
 else:raise RuntimeError('funded stake and genuine included NMS deadline')
 stop_workers();report['included_entry']=status;save('included-entry.json',status)
 assert int(status['stake_units'])==1000*100000000,'pool eligibility stake changed'
 draw=status['window_draw'];worker_boundary(draw)
 # The owner requires the operator stake's ordinary yield to be shared too.
 yield_draw=((rpc.call('getblockcount')//status['yield_blocks'])+1)*status['yield_blocks']
 worker_boundary(yield_draw)
 until=time.monotonic()+120;categories={}
 while time.monotonic()<until:
  categories={e['payload']['category']:e['payload'] for e in events('coordinator') if e['kind']=='income' and
              e['payload']['category'] in ('comine_payout','staking_distribution')}
  if set(categories)=={'comine_payout','staking_distribution'}:break
  time.sleep(.5)
 else:raise RuntimeError('native reward receipt reconciliation deadline')
 assert all(sum(Fraction(c) for c in income['credits'].values())==int(income['amount']) for income in categories.values())
 save('earned-rewards.json',categories)
 if args.reorganization:
  # Both actual reward categories are still immature. Replace the branch
  # which created the stake, NMS, lottery receipt and yield receipt using only
  # normal P2P admission. The common ancestor is a closed mined fixture.
  original_rewards=dict(categories);old_tip=rpc.call('getbestblockhash');old_height=rpc.call('getblockcount')
  # Both peers must still be able to exchange the first divergent block.
  # An eight-block lead put the replacement tip102 blocks beyond this fixture's
  # ancestor, so its peer correctly refused the original branch before sync.
  # Keep both branch depths inside the actual unchanged native history bound.
  depth_limit=rpc.call('getblockchaininfo')['max_reorg_depth']
  replacement_height=old_height+3
  assert 0<old_height-report['starting_height']<depth_limit
  assert replacement_height-report['starting_height']<depth_limit,'replacement exceeds native peer history bound'
  stop(gateway);stop(coordinator)
  fork=start('fork',[str(build/'pool-backend'),str(state/'fork'),'32681','32682'],True)
  alternate=Node('http://127.0.0.1:32682',state/'fork/lab-rpc-token',genesis);ready(alternate,fork)
  assert alternate.call('getblockcount')==report['starting_height']
  while alternate.call('getblockcount')<replacement_height:
   mine_block(fork,alternate,addresses['fees'],out/'fork.log')
  replacement=alternate.call('getbestblockhash');fork.stdin.write('peer 32661\n');fork.stdin.flush();until=time.monotonic()+1200
  while rpc.call('getbestblockhash')!=replacement:
   if time.monotonic()>until:raise RuntimeError('native lottery reorganization deadline')
   time.sleep(.25)
  assert rpc.call('getblockhash',str(old_height))!=old_tip
  assert rpc.call('getstatedigest')==alternate.call('getstatedigest')
  cleared=rpc.call('getpoolidentitystate',addresses['pool'])
  assert int(cleared['stake_units'])==0 and not cleared['included_submission']
  services();until=time.monotonic()+120
  while True:
   states={e['payload']['id']:e['payload']['state'] for e in events('coordinator') if e['kind']=='income_state'}
   if all(states.get(i['id'])=='orphaned' for i in original_rewards.values()):break
   if time.monotonic()>until:raise RuntimeError('orphaned lottery/yield liability deadline')
   time.sleep(.25)
  assert all(a['available_units']=='0' and a['paid_units']=='0' and a['pending_units']=='0' for a in accounts().values())
  report['reorganization']={'original_height':old_height,'replacement_height':rpc.call('getblockcount'),
      'common_ancestor_height':report['starting_height'],'native_depth_limit':depth_limit,
      'removed_reward_ids':[i['id'] for i in original_rewards.values()],
      'stake_and_entry_rolled_back':True,'orphaned_rewards_not_payable':True}
  save('reorganization.json',report['reorganization']);print('native lottery/yield branch rolled back without payable liabilities',flush=True)
  # Restore operator principal using the existing exact signed intent. A proof
  # from the orphan branch must not become a fee-paying entry on the new tip.
  stale_proofs=[e['payload'] for e in events('identity') if e['kind']=='identity_signed' and
      any(i['kind']=='identity_intent' and i['payload']['id']==e['payload']['id'] and i['payload']['wire']['action']=='nms' for i in events('identity'))]
  for proof in stale_proofs:
   try:rpc.call('sendrawtransaction',proof['signed_hex'])
   except Refused:pass
   else:raise AssertionError('orphan-context near miss accepted on replacement branch')
  stake_signatures={e['payload']['txid'] for e in events('identity') if e['kind']=='identity_signed' and
      any(i['kind']=='identity_intent' and i['payload']['id']==e['payload']['id'] and i['payload']['wire']['action']=='stake' for i in events('identity'))}
  until=time.monotonic()+300
  while int(rpc.call('getpoolidentitystate',addresses['pool'])['stake_units'])==0:
   if time.monotonic()>until:raise RuntimeError('exact operator stake recovery deadline')
   time.sleep(.5);advance(rpc.call('getblockcount')+1)
  recovered_signatures={e['payload']['txid'] for e in events('identity') if e['kind']=='identity_signed' and
      any(i['kind']=='identity_intent' and i['payload']['id']==e['payload']['id'] and i['payload']['wire']['action']=='stake' for i in events('identity'))}
  assert recovered_signatures==stake_signatures and len(stake_signatures)==1
  clock();start_workers();until=time.monotonic()+600
  while True:
   clock();entry=rpc.call('getpoolidentitystate',addresses['pool'])
   if entry['included_submission']:break
   if time.monotonic()>until:raise RuntimeError('genuine replacement-branch near miss deadline')
   assert all(p.poll() is None for p in workers);time.sleep(.25)
  stop_workers();worker_boundary(entry['window_draw']);until=time.monotonic()+120
  while True:
   fresh=[e['payload'] for e in events('coordinator') if e['kind']=='income' and e['payload']['category']=='comine_payout' and
          e['payload']['height']==entry['window_draw'] and e['payload']['id']!=original_rewards['comine_payout']['id']]
   if fresh:break
   if time.monotonic()>until:raise RuntimeError('replacement-branch actual lottery receipt deadline')
   time.sleep(.25)
  assert len(fresh)==1 and sum(Fraction(v) for v in fresh[0]['credits'].values())==int(fresh[0]['amount'])
  categories={'comine_payout':fresh[0]}
  report['reorganization'].update(exact_stake_signature_reused=True,stale_nms_refused=True,
      replacement_entry=entry,replacement_reward=fresh[0]['id'])
  save('reorganization.json',report['reorganization'])
 advance(max(i['height'] for i in categories.values())+119)
 until=time.monotonic()+60
 while time.monotonic()<until:
  mature={e['payload']['id'] for e in events('coordinator') if e['kind']=='income_state' and e['payload']['state']=='available'}
  if all(i['id'] in mature for i in categories.values()):break
  time.sleep(.5)
 else:raise RuntimeError('actual reward spendability/maturity deadline')
 before=accounts();save('before-payments.json',before)
 assert all(int(a['available_units'])>=100000000 for a in before.values())
 stop(gateway);stop(coordinator)
 settings['payments']={'state_directory':str(state/'payments'),'rollback_anchor':str(state/'payment-anchor/current.json'),
    'native_binary':str(build/'pool-payout'),'pool_seed':str(state/'disposable-keys/pool.seed'),'fee_seed':str(state/'disposable-keys/fees.seed'),
    'pool_script':scripts['pool'],'fee_script':scripts['fees'],'fee_address':addresses['fees'],'fee_units':'100000'}
 services();until=time.monotonic()+180
 while time.monotonic()<until:
  paid=accounts()
  if all(int(a['paid_units'])>0 for a in paid.values()):break
  advance(rpc.call('getblockcount')+1);time.sleep(1)
 else:raise RuntimeError('native shared reward payment deadline')
 expected={n:int(a['paid_units']) for n,a in paid.items()}
 actual={n:sum(c['value_units'] for c in rpc.call('listunspent',addresses[n])) for n in expected}
 assert actual==expected,'recipient balance mismatch'
 target=rpc.call('getblockcount');until=time.monotonic()+600
 while time.monotonic()<until:
  if independent.call('getblockcount')==target and independent.call('getbestblockhash')==rpc.call('getbestblockhash'):break
  time.sleep(.5)
 else:raise RuntimeError('independent canonical validation deadline')
 independently={n:sum(c['value_units'] for c in independent.call('listunspent',addresses[n])) for n in expected}
 assert independently==expected,'independent recipient mismatch'
 intents=[e['payload'] for e in events('payments') if e['kind']=='payment_intent']
 roots={(c['txid'],c['vout']) for c in funding}
 operator_descendants={e['payload']['txid'] for e in events('identity') if e['kind']=='identity_signed'}
 assert all((c['txid'],c['vout']) not in roots and c['txid'] not in operator_descendants for i in intents for c in i['wire']['inputs'] if c['role']=='pool')
 report.update(status='PASS',height=target,rewards=categories,recipient_wallet_units=actual,independent_wallet_units=independently,
               shared_yield_verified=not args.reorganization,orphaned_yield_rollback_verified=args.reorganization,
               operator_principal_spent_on_payments=False,after_payments=paid)
except BaseException as error:
 import traceback
 report.update(status='FAILED',error=repr(error));(out/'failure.txt').write_text(traceback.format_exc());raise
finally:
 for p in reversed(processes):stop(p)
 for log in logs:log.close()
 report['processes_stopped']=all(p.poll() is not None for p in processes)
 report['binary_sha256']={n:hashlib.sha256((build/n).read_bytes()).hexdigest() for n in ('pool-backend','pool-client','pool-work','pool-identity','pool-payout')}
 save('result.json',report)
