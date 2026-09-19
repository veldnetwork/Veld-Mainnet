"""Private, operator-authorized stake/NMS lifecycle; never a gateway action.

The immutable funding list authorizes only contributed operator coins. Confirmed
self change descends from that list; stake backing and shared receipts are never
eligible. Exact signed transactions and reservations survive restart/rollback.
"""
import hashlib
import subprocess
import threading
from .journal import atomic
from .protocol import encode, require, units, hex64, Refused, Busy


class Identity:
    def __init__(self,pool,journal,binary,seed,script,funding,tier=1):
        self.pool,self.node,self.journal=pool,pool.node,journal
        self.binary,self.seed,self.script=str(binary),str(seed),script
        require(type(tier) is int and 1<=tier<=4,'operator stake tier')
        self.tier=tier;self.intents={};self.last_state=None;self.state='Checking operator funding'
        self.lock=threading.RLock()
        require(isinstance(funding,list) and 0<len(funding)<=10000,'operator funding manifest')
        self.funding={}
        for c in funding:
            require(set(c)=={'txid','vout','units'},'operator funding schema')
            key=(hex64(c['txid']),units(c['vout'],(1<<32)-2))
            require(key not in self.funding and units(c['units'])>0,'operator funding duplicate')
            self.funding[key]=units(c['units'])
        policy={'chain':self.node.genesis,'script':script,'funding':funding,'tier':tier}
        self.policy=hashlib.sha256(encode(policy)).hexdigest()
        prior=None
        for event in journal.events():
            if event['kind']=='identity_policy':prior=event['payload']['digest']
            self.apply(event['kind'],event['payload'])
        require(prior is None or prior==self.policy,'operator funding policy changed; explicit migration required')
        if prior is None:self.record('identity_policy',{'digest':self.policy})

    def apply(self,kind,value):
        if kind=='identity_intent':self.intents[value['id']]=value
        elif kind in ('identity_signed','identity_state'):self.intents[value['id']].update(value)

    def record(self,kind,value):
        self.journal.append(kind,value);self.apply(kind,value)

    def status(self):return self.state

    def allowed(self):
        allowed=dict(self.funding)
        for intent in self.intents.values():
            if intent['state']!='confirmed':continue
            tx=self.node.call('gettransaction',intent['txid'],intent['block'])
            require(tx['block_hash']==intent['block'],'operator change inclusion')
            for o in tx['vout']:
                if intent['wire']['action']=='stake' and o['n']==0:continue
                if o['script_pubkey']==self.script and units(o['value_units'])>0:
                    allowed[(intent['txid'],o['n'])]=units(o['value_units'])
        with self.pool.lock:
            liabilities={(i['txid'],o['vout']) for i in self.pool.incomes.values() for o in i['outputs']}
        require(not liabilities.intersection(allowed),'miner liabilities cannot fund identity operations')
        # Spent or signed inputs remain unavailable. Expired NMS signatures bind
        # a former parent, and may only be replaced using the SAME reserved coin;
        # normal chain validation prevents both transactions spending that coin.
        reserved={(c['txid'],units(c['vout'])) for i in self.intents.values()
                  if i['state']!='expired' for c in i['wire']['inputs']}
        coins=[]
        for c in self.node.call('listunspent',self.pool.pool_address):
            key=(c['txid'],c['vout'])
            if key in allowed and key not in reserved:
                require(type(c['value_units']) is int and c['value_units']==allowed[key],'operator funding value')
                coins.append({'txid':c['txid'],'vout':str(c['vout']),'units':str(c['value_units'])})
        return sorted(coins,key=lambda c:(-units(c['units']),c['txid'],c['vout']))

    def reconcile(self,state):
        for intent in list(self.intents.values()):
            if 'signed_hex' not in intent:continue
            try:
                tx=(self.node.call('gettransaction',intent['txid'],intent['block']) if intent.get('block')
                    else self.node.call('gettransactionrecent',intent['txid']))
                confirmed=(tx.get('confirmations',0)>0 and tx.get('block_hash') and
                           self.node.call('getblockhash',str(tx['block_height']))==tx['block_hash'])
            except (Refused,Busy):confirmed=False
            if confirmed:
                if intent['state']!='confirmed':self.record('identity_state',{'id':intent['id'],'state':'confirmed',
                    'block':tx['block_hash'],'height':tx['block_height']})
                continue
            if intent['wire']['action']=='nms' and (units(intent['wire']['height'])!=state['height']+1 or
                                                   intent['parent']!=state['parent']):
                if intent['state']!='expired':self.record('identity_state',{'id':intent['id'],'state':'expired','block':None})
                continue
            if intent['state']=='confirmed':self.record('identity_state',{'id':intent['id'],'state':'signed','block':None})
            try:require(self.node.call('sendrawtransaction',intent['signed_hex'])==intent['txid'],'identity broadcast id')
            except (Refused,OSError):pass # Preserve exact bytes and reservation.

    def sign(self,intent):
        if 'signed_hex' in intent:return
        # The child sees only the reserved, designated operator inputs. It has
        # no generic transaction/message/destination signing operation.
        manifest=self.journal.directory/'authorized-inputs.json'
        atomic(manifest,encode({'chain':self.node.genesis,'script':self.script,'allowed_inputs':intent['wire']['inputs']}))
        result=subprocess.run([self.binary,self.seed,str(manifest)],input=encode(intent['wire'])+b'\n',
                              capture_output=True,timeout=60,check=False)
        require(result.returncode==0,'restricted identity signer refused')
        require(len(result.stdout)<=2*1024*1024+66,'identity signed response bound')
        parts=result.stdout.decode('ascii').split();require(len(parts)==2,'identity signed response schema')
        txid=hex64(parts[0]);raw=bytes.fromhex(parts[1])
        require(raw.hex()==parts[1] and 0<len(raw)<=1024*1024 and
                hashlib.sha256(hashlib.sha256(raw).digest()).hexdigest()==txid,'identity signed bytes')
        self.record('identity_signed',{'id':intent['id'],'txid':txid,'signed_hex':parts[1],'state':'signed'})

    def maintain(self):
        # ML-DSA signing and bounded node lookups may be slow. They must not
        # monopolize the worker/account lock. Identity transitions have their
        # own serialization; canonical inclusion remains the authority.
        with self.lock:
            state=self.node.call('getpoolidentitystate',self.pool.pool_address)
            require(isinstance(state,dict) and type(state.get('height')) is int,'identity node state')
            self.last_state=state;self.reconcile(state)
            for intent in self.intents.values():
                if intent['state']=='reserved':
                    self.sign(intent);return
            if any(i['state']=='signed' for i in self.intents.values()):
                self.state='Awaiting canonical inclusion';return
            coins=self.allowed();fee=units(state['fee_units']);dust=units(state['dust_units'])
            action=None;header='';selected=[];required=units(state['required_stake_units'])
            if units(state['stake_units'])<required:
                require(units(state['stake_units'])==0,'partial stake requires operator reconciliation')
                if not state['staking_active']:self.state='Waiting for canonical staking activation';return
                gathered=0
                for c in coins[:64]:
                    selected.append(c);gathered+=units(c['units'])
                    if gathered>=required+fee and (gathered==required+fee or gathered-required-fee>=dust):break
                if gathered>=required+fee:action='stake'
                elif len(selected)>=2:action='consolidate'
                else:self.state='Insufficient designated operator stake funds';return
            elif state['eligible'] and state['needs_submission'] and not state['pending_submission']:
                candidates=(self.pool.receipts.select(first=state['height']+1,last=state['height']+1,sequence=True)
                            if hasattr(self.pool.receipts,'select') else
                            sorted(self.pool.receipts.values(),key=lambda r:r['seq']))
                proof=next((r for r in candidates
                    if r.get('proof_kind')=='near_miss' and r['status'] in ('verified','near_miss') and
                    r['height']==state['height']+1 and r['admitted_parent']==state['parent']),None)
                if proof is None:self.state='Eligible; waiting for a genuine near miss';return
                job=self.pool.jobs[self.pool.leases[proof['lease']]['job']]
                raw=bytearray.fromhex(job['node']['block_hex'][:176]);raw[80:88]=int(proof['nonce'],16).to_bytes(8,'little')
                header=raw.hex();action='nms'
                selected=next(([c] for c in reversed(coins) if units(c['units'])>=2*fee and
                    (units(c['units'])==2*fee or units(c['units'])-2*fee>=dust)),[])
                if not selected:self.state='Operator near-miss fee funds required';return
            else:
                self.state=('Entry included for this window' if state.get('included_submission') else
                            'Entry awaiting inclusion' if state['pending_submission'] else
                            'Waiting for the next qualification window')
                return
            wire={'chain':self.node.genesis,'action':action,'height':str(state['height']+1),'header':header,
                  'stake_units':str(required) if action=='stake' else '0','tier':str(self.tier) if action=='stake' else '0',
                  'inputs':selected}
            value={'wire':wire,'parent':state['parent'],'state':'reserved','policy':self.policy}
            value['id']=hashlib.sha256(encode(value)).hexdigest()
            if value['id'] not in self.intents:self.record('identity_intent',value)
            self.sign(self.intents[value['id']]);self.reconcile(state)
            self.state='Awaiting canonical inclusion'
