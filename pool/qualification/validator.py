"""Naturally funded first-validator admission on a private canonical chain.

The isolated boundary is 9000, matching the candidate's selected height while
using a separate disposable chain. The individual 10k bond is unchanged.
No synthetic UTXOs, altered subsidies, signature bypass or fake node is used.
"""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,sys,tempfile,time,traceback
from fractions import Fraction
src=pathlib.Path(__file__).resolve().parents[2]
from pool.backend import Node
from pool.protocol import encode,Busy,Refused
from pool.qualification.isolation import require_isolated_network
from pool.qualification.control import mine_block
require_isolated_network()
parser=argparse.ArgumentParser()
parser.add_argument('--build-directory',type=pathlib.Path,required=True)
parser.add_argument('--history-state',type=pathlib.Path,required=True)
parser.add_argument('--output',type=pathlib.Path,required=True)
parser.add_argument('--public-identities',type=pathlib.Path,help='public identity receipt for an older closed fixture')
args=parser.parse_args();build=args.build_directory;out=args.output
H=9000  # disposable network; no live activation is performed by this exercise
history=pathlib.Path(args.history_state).resolve()
assert history.parent==pathlib.Path('/var/tmp') and history.name.startswith('veld-pool-history-')
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit():continue
 try:command=(p/'cmdline').read_bytes().split(b'\0')
 except (OSError,ProcessLookupError):continue
 assert str(history/'node').encode() not in command,'fixture must be closed before cloning'
out.mkdir(parents=True,exist_ok=False)
state=pathlib.Path(tempfile.mkdtemp(prefix='veld-pool-validator-',dir='/var/tmp'))
(out/'state-directory.txt').write_text(str(state)+'\n')
shutil.copytree(history/'node',state/'node');shutil.copytree(history/'node',state/'observer')
shutil.copytree(history/'keys',state/'keys')
subprocess.run(['ip','link','set','lo','up'],check=True)
public=json.loads((args.public_identities or history/'public-identities.json').read_text());addresses=public['addresses'];scripts=public['scripts']
lab_sign=build/'pool-lab-sign'
genesis=bytes.fromhex('ee875e86d25aabad2442451b82f6550b732a1387cbc172c2a3fc02eb216af3d5')[::-1].hex()
processes=[];logs=[];mining_logs={}
report={'status':'RUNNING','scope':'funded first-validator RPC/signature/admission/endorsement/restart gate',
        'activation_height':H,'private_test_boundary_only':True,'accelerated_clock':True,'consensus_or_economics_bypassed':False,
        'complete_validator_matrix':False,'complete_pool_gate':False,'checks':[]}
def save(name,value):(out/name).write_text(json.dumps(value,indent=2)+'\n')
def start(name,folder,p2p,rpcport):
 log=(out/(name+'.log')).open('w');logs.append(log)
 p=subprocess.Popen([str(build/'pool-backend'),str(folder),str(p2p),str(rpcport)],cwd=src,
                    stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,text=True)
 processes.append(p);rpc=Node('http://127.0.0.1:'+str(rpcport),folder/'lab-rpc-token',genesis)
 mining_logs[p.pid]=out/(name+'.log')
 until=time.monotonic()+1200
 while time.monotonic()<until:
  assert p.poll() is None,'backend exited during canonical replay'
  try:rpc.check_chain();return p,rpc
  except (OSError,ValueError,Busy):time.sleep(.2)
 raise RuntimeError('canonical replay deadline')
def stop(p):
 if p.poll() is not None:return
 p.stdin.write('stop\n');p.stdin.flush()
 try:p.wait(timeout=120)
 except subprocess.TimeoutExpired:p.kill();p.wait()
def checked(name,condition):
 assert condition,name
 report['checks'].append(name);save('progress.json',report);print(name,flush=True)
def mine(address,producer=None,chain=None):
 producer=node if producer is None else producer;chain=rpc if chain is None else chain
 return mine_block(producer,chain,address,mining_logs[producer.pid])
def sign(prepared,key='pool',bond='',reduce='0'):
 command=[str(lab_sign),str(state/'keys'/(key+'.seed')),'transaction']
 result=subprocess.run(command,input=encode({'unsigned_tx_hex':prepared['unsigned_tx_hex'],'bond_units':bond,
                        'reduce_change_units':reduce})+b'\n',capture_output=True,check=True,timeout=120)
 txid,raw=result.stdout.decode().split();return txid,raw
def refused(name,raw):
 before=rpc.call('getstatedigest')
 try:rpc.call('sendrawtransaction',raw)
 except Refused:pass
 else:raise AssertionError(name+' unexpectedly accepted')
 checked(name,rpc.call('getstatedigest')==before)
def balance():return sum(c['value_units'] for c in rpc.call('listunspent',addresses['pool']))
def canonical_balance():
 # The RPC emits eight decimal places; parse that decimal exactly. Unlike
 # listunspent this includes outputs reserved by reinjected orphan operations.
 amount=Fraction(str(rpc.call('getbalance',addresses['pool'])['balance_veld']))*100000000
 assert amount.denominator==1,'noncanonical native wallet amount'
 return int(amount)
try:
 node,rpc=start('node',state/'node',32761,32762)
 identity=subprocess.run([str(lab_sign),str(state/'keys/pool.seed'),'identity'],capture_output=True,check=True).stdout.decode().split()
 address,pubkey,script=identity;assert address==addresses['pool'] and script==scripts['pool']
 checked('zero aggregate ordinary stake before registration',rpc.call('getvalidators')['total_staked_veld']==0)
 checked('fixture predates isolated activation',rpc.call('getblockcount')<H-2)
 # Consolidation is a real ordinary transaction paid entirely by the operator.
 while True:
  coins=sorted(rpc.call('listunspent',address),key=lambda c:(-c['value_units'],c['txid']))
  if coins and coins[0]['value_units']>=10000*100000000+200000:break
  if len(coins)<2:mine(address);continue
  selected=[{'txid':c['txid'],'vout':str(c['vout']),'units':str(c['value_units'])} for c in coins[:64]]
  manifest=state/'authorized-inputs.json';manifest.write_bytes(encode({'chain':genesis,'script':script,'allowed_inputs':selected}));manifest.chmod(0o600)
  wire={'chain':genesis,'action':'consolidate','height':str(rpc.call('getblockcount')+1),'header':'','stake_units':'0','tier':'0','inputs':selected}
  signed=subprocess.run([str(build/'pool-identity'),str(state/'keys/pool.seed'),str(manifest)],input=encode(wire)+b'\n',
                         capture_output=True,check=True,timeout=120).stdout.decode().split()
  assert rpc.call('sendrawtransaction',signed[1])==signed[0]
  mine(address)
  checked('consolidation remains before activation',rpc.call('getblockcount')<H-2)
 checked('individual bond genuinely funded',balance()>10000*100000000+100000)
 while rpc.call('getblockcount')<H-2:mine(addresses['fees'])
 try:rpc.call('prepareregistervalidator',address,pubkey)
 except Refused as error:checked('pre-activation aggregate gate retained','stak' in str(error).lower())
 else:raise AssertionError('pre-activation registration unexpectedly prepared')
 before_boundary=rpc.call('getstatedigest');save('pre-activation-state.json',before_boundary)
 mine(addresses['fees']);assert rpc.call('getblockcount')==H-1
 # Clone only a closed canonical state before the first candidate registration.
 # The competing branch is mined normally and joined by P2P; no database edits
 # or forced block invalidation stand in for actual rollback processing.
 ancestor=rpc.call('getbestblockhash');stop(node)
 shutil.copytree(state/'node',state/'fork')
 node,rpc=start('node-at-boundary',state/'node',32761,32762)
 fork,alternate=start('fork',state/'fork',32781,32782)
 checked('closed pre-activation history replays identically on both branches',
         rpc.call('getbestblockhash')==ancestor==alternate.call('getbestblockhash') and
         rpc.call('getstatedigest')==alternate.call('getstatedigest'))
 prepared=rpc.call('prepareregistervalidator',address,pubkey)
 save('prepared-register.json',prepared)
 refused('missing individual bond rejected without state change',sign(prepared,bond='0')[1])
 refused('insufficient individual bond rejected without state change',sign(prepared,bond=str(10000*100000000-1))[1])
 refused('unauthorized funding signature rejected without state change',sign(prepared,key='fees')[1])
 before_coins=rpc.call('listunspent',address)
 before=sum(c['value_units'] for c in before_coins);txid,raw=sign(prepared)
 save('before-registration-coins.json',before_coins)
 assert rpc.call('sendrawtransaction',raw)==txid
 mine(addresses['fees'])
 registered_hash=rpc.call('getbestblockhash')
 registered=rpc.call('getvalidatorinfo',pubkey);validators=rpc.call('getvalidators')
 checked('registration accepted at activation with zero ordinary stake',registered['registered'] and registered['system_active'] and
         validators['total_staked_veld']==0 and validators['validator_count']==1 and validators['validators'][0]['registered_height']==H)
 checked('bond and fee deducted exactly once',balance()==before-10000*100000000-100000)
 checked('registration alone pays no endorsement reward',rpc.call('getblockendorsements',str(H))['count']==0)
 refused('spent bond inputs cannot be reused',sign(prepared,reduce='1')[1])
 checked('duplicate registration preparation is idempotent',rpc.call('prepareregistervalidator',address,pubkey).get('status')=='already_registered')
 checked('governance gate remains closed',rpc.call('getgovernanceinfo')['governance_active'] is False)
 # Use the exact remote work grant / begin-signing / sink sequence.
 target=rpc.call('getblockcount');block=rpc.call('getblockhash',str(target))
 grant=rpc.call('getworkadmission','validator_endorsement',str(target),block)
 rpc.call('beginworksigning','validator_endorsement',grant['binding'],grant['signing_token'])
 (state/'endorsement-intent.json').write_bytes(encode({'height':str(target),'block':block}))
 with (state/'endorsement-intent.json').open('rb') as stream:os.fsync(stream.fileno())
 op=subprocess.run([str(lab_sign),str(state/'keys/pool.seed'),'endorse'],input=encode({'height':str(target),'block':block})+b'\n',
                   capture_output=True,check=True,timeout=10).stdout.decode().strip()
 endorse=rpc.call('preparerawop',address,op);end_id,end_raw=sign(endorse)
 assert rpc.call('sendrawtransaction',end_raw,grant['binding'],grant['signing_token'])==end_id
 mine(addresses['fees'])
 endorsements=rpc.call('getblockendorsements',str(target))
 checked('first validator performs qualifying endorsement before finality quorum',endorsements['count']==1 and
         endorsements['endorsements'][0]['address']==address and rpc.call('getvalidators')['validator_count']==1)
 save('endorsements.json',endorsements);save('validator-state.json',rpc.call('getvalidators'))
 tip=rpc.call('getbestblockhash');digest=rpc.call('getstatedigest');stop(node)
 node,rpc=start('node-restarted',state/'node',32761,32762)
 checked('restart preserves canonical registration and endorsement state',rpc.call('getbestblockhash')==tip and rpc.call('getstatedigest')==digest and
         rpc.call('getblockendorsements',str(target))==endorsements)
 while alternate.call('getblockcount')<H+7:mine(addresses['fees'],fork,alternate)
 competing_tip=alternate.call('getbestblockhash')
 fork.stdin.write('peer 32761\n');fork.stdin.flush();until=time.monotonic()+600
 while rpc.call('getbestblockhash')!=competing_tip:
  if time.monotonic()>until:raise RuntimeError('activation reorganization deadline')
  time.sleep(.2)
 checked('P2P reorganization removed the first registration branch',rpc.call('getblockhash',str(H))!=registered_hash and
         rpc.call('getblockhash',str(H+1))!=tip)
 # Normal reorganization re-admits orphan transactions to the mempool. Their
 # inputs remain canonical UTXOs but must not become wallet-selectable again.
 # Inspect the actual restored prevouts rather than mistaking a pending-spend
 # reservation for lost chain funds.
 restored=[rpc.call('gettxout',c['txid'],str(c['vout'])) for c in before_coins]
 save('registration-rollback.json',{'original_coins':before_coins,'restored_coins':restored,
      'wallet':rpc.call('getbalance',address),'mempool':rpc.call('getrawmempool'),
      'validators':rpc.call('getvalidators')})
 checked('registration rollback restores bond funding and registry together',
         all(c is not None and c['value_units']==old['value_units'] and c['script_pubkey_hex']==script
             for old,c in zip(before_coins,restored)) and
         sum(c['value_units'] for c in restored)==before and
         rpc.call('getvalidators')['validator_count']==0 and not rpc.call('getvalidatorinfo',pubkey)['registered'])
 checked('orphan registration input remains reserved while pending',txid in rpc.call('getrawmempool') and balance()<before)
 checked('registration rollback removes its qualifying endorsement',rpc.call('getblockendorsements',str(target))['count']==0)
 checked('reorganized state matches independently validated replacement branch',rpc.call('getstatedigest')==alternate.call('getstatedigest'))
 # The original signed transaction spends the original restored inputs.
 # Reconciliation may have already put those exact bytes back in the mempool.
 try:rpc.call('sendrawtransaction',raw)
 except Refused:
  if txid not in rpc.call('getrawmempool'):raise
 inclusion=rpc.call('getblockcount')+1;mine(addresses['fees'])
 save('replacement-registration.json',{'validator':rpc.call('getvalidatorinfo',pubkey),
      'validators':rpc.call('getvalidators'),'wallet':rpc.call('getbalance',address),
      'mempool':rpc.call('getrawmempool'),'expected_canonical_units':before-10000*100000000-100000})
 checked('same signed bond registers once on replacement history',rpc.call('getvalidatorinfo',pubkey)['registered'] and
         rpc.call('getvalidators')['validators'][0]['registered_height']==inclusion and canonical_balance()==before-10000*100000000-100000)
 checked('reorganized registration still grants no automatic endorsement reward',rpc.call('getblockendorsements',str(inclusion))['count']==0)
 tip=rpc.call('getbestblockhash');digest=rpc.call('getstatedigest');stop(node)
 node,rpc=start('node-after-reorganization',state/'node',32761,32762)
 checked('restart preserves reorganized bond accounting',rpc.call('getbestblockhash')==tip and rpc.call('getstatedigest')==digest and
         canonical_balance()==before-10000*100000000-100000)
 observer,independent=start('observer',state/'observer',32771,32772)
 observer.stdin.write('peer 32761\n');observer.stdin.flush();until=time.monotonic()+1200
 while time.monotonic()<until:
  if independent.call('getbestblockhash')==tip:break
  time.sleep(.5)
 else:raise RuntimeError('independent replay deadline')
 checked('independent node agrees on replacement bond and removed endorsement state',independent.call('getstatedigest')==digest and
         independent.call('getblockendorsements',str(target))['count']==0)
 report.update(status='PASS',height=rpc.call('getblockcount'),tip=tip,registered_txid=txid,endorsement_txid=end_id,
               reorganization_across_activation=True,replacement_registration_height=inclusion,
               remaining=['funded below/at/above old floor matrix','bond exit/slashing/yield settlement integration'])
except BaseException as error:
 report.update(status='FAILED',error=repr(error));(out/'failure.txt').write_text(traceback.format_exc());raise
finally:
 for p in reversed(processes):stop(p)
 for log in logs:log.close()
 report['processes_stopped']=all(p.poll() is not None for p in processes)
 report['binary_sha256']={n:hashlib.sha256((build/n).read_bytes()).hexdigest() for n in ('pool-backend','pool-identity')}
 report['lab_sign_sha256']=hashlib.sha256(lab_sign.read_bytes()).hexdigest();save('result.json',report)
