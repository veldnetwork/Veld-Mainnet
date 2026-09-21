"""Private payment engine. Signed obligations remain reserved across all retries.

The surviving payment journal/rollback anchor is required on restoration. An
operator losing both must stop and reconcile; this is not an erase-and-repay API.
This engine is not reachable through the worker gateway.
"""
import hashlib
import subprocess
import threading
import time
from fractions import Fraction

from .protocol import encode, require, units, hex64, Refused, Busy
from .accounting import floor_total
from .overview import PaymentOverview

class Payments:
    def __init__(self,pool,journal,binary,pool_seed,fee_seed,pool_script,fee_script,fee_address,fee_units,dust_units):
        self.pool,self.node,self.journal=pool,pool.node,journal
        self.binary,self.pool_seed,self.fee_seed=str(binary),str(pool_seed),str(fee_seed)
        self.pool_script,self.fee_script,self.fee_address=pool_script,fee_script,fee_address
        require(fee_address!=pool.pool_address and fee_script!=pool_script,'separate fee identity')
        self.fee=units(str(fee_units));self.dust=units(str(dust_units))
        require(0<self.dust<100000000,'native dust policy')
        self.lock=threading.RLock();self.intents={};self.batches={}
        self.public_overview=PaymentOverview()
        for event in journal.events():self.apply(event['kind'],event['payload'],event['seq'])

    def apply(self,kind,value,sequence=0):
        prior=self.intents.get(value.get('id'))
        old=dict(prior) if prior else None
        if kind=='payment_batch':self.batches[value['id']]=value
        elif kind=='payment_intent':self.intents[value['id']]=dict(value,history_sequence=sequence)
        elif kind=='payment_signed':self.intents[value['id']].update(value)
        elif kind in ('payment_state','payment_notice'):self.intents[value['id']].update(value)
        if kind in ('payment_intent','payment_signed','payment_state','payment_notice'):
            self.public_overview.update(old,self.intents[value['id']])

    def record(self,kind,value):
        sequence=self.journal.append(kind,value);self.apply(kind,value,sequence)

    def deductions(self):
        result={}
        for intent in self.intents.values():
            for account,amount in intent['deductions'].items():result[account]=result.get(account,0)+units(amount)
        return result

    def summary(self,account):
        with self.lock:
            paid=reserved=0
            for intent in self.intents.values():
                amount=units(intent['deductions'].get(account,'0'))
                if intent['state']=='confirmed':paid+=amount
                else:reserved+=amount
            return {'reserved_units':str(reserved),'paid_units':str(paid)}

    def public_summary(self):
        with self.lock:return self.public_overview.snapshot()

    def history(self,account,before=0):
        # Several native-size transactions can belong to one daily batch. The
        # journal sequence, not a timestamp, is the unique pagination cursor.
        # Never expose inputs, other recipients, or exact signed bytes here.
        with self.lock:
            rows=sorted((p for p in self.intents.values() if account in p['deductions'] and
                         (not before or p['history_sequence']<before)),key=lambda p:p['history_sequence'],reverse=True)
            selected=rows[:20]
            return {'payments':[{'created':str(p['created']),'amount_units':p['deductions'][account],
                                 'state':p['state'],'txid':p.get('txid')} for p in selected],
                    'next_before':selected[-1]['history_sequence'] if len(rows)>20 else 0}

    def available(self):
        result={}
        for income in self.pool.incomes.values():
            if income['state']=='available':
                for account,amount in income['credits'].items():result.setdefault(account,[]).append(Fraction(amount))
        result={account:floor_total(values) for account,values in result.items()}
        for account,amount in self.deductions().items():result[account]=result.get(account,0)-amount
        require(all(amount>=0 for amount in result.values()),'income reorganization deficit: payments stopped for reconciliation')
        return result

    def eligible_groups(self,quotas,minimum,address_scope):
        # Payout grouping grants no account access and does not merge balances.
        # Retain individual deductions while evaluating the automatic minimum
        # against all payable work directed to the same immutable destination.
        groups={}
        for account,amount in sorted(quotas.items()):
            if amount<=0:continue
            key=self.pool.accounts[account]['address'] if address_scope else account
            groups.setdefault(key,{})[account]=amount
        return {key:amounts for key,amounts in groups.items() if sum(amounts.values())>=minimum}

    def plan(self,now=None):
        now=int(time.time()) if now is None else now
        with self.pool.lock,self.lock:
            operator=getattr(self.pool,'operator',None)
            require(not operator or not operator.faulted,'operator journal failed; payments stopped')
            if operator and operator.settings['payments_paused']:return None
            policy=operator.policy() if operator else {'minimum_units':'100000000','batch_seconds':'86400','fee_ppm':'0','revision':'0'}
            minimum=units(policy['minimum_units'])
            # Freeze a daily batch, then split it into native-size transactions.
            # Large fragmented receipts must not stop all automatic payments.
            # Existing intents deduct their exact quota before any new chunk.
            available=self.available();batch=None;quotas={};groups={};address_scope=True
            if self.batches:
                batch=max(self.batches.values(),key=lambda b:b['created'])
                minimum=units(batch.get('minimum_units','100000000'))
                scope=batch.get('threshold_scope','account')
                require(scope in ('account','payout_address'),'unknown frozen payout threshold scope')
                address_scope=scope=='payout_address'
                if address_scope:
                    require(set(batch.get('destinations',{}))==set(batch['quotas']) and
                            all(self.pool.accounts[a]['address']==destination for a,destination in batch['destinations'].items()),
                            'frozen payout destination changed')
                spent={}
                for intent in self.intents.values():
                    if intent.get('batch')==batch['id']:
                        for account,amount in intent['deductions'].items():spent[account]=spent.get(account,0)+units(amount)
                quotas={a:units(v)-spent.get(a,0) for a,v in batch['quotas'].items()}
                require(all(v>=0 for v in quotas.values()),'batch quota overdrawn')
                groups=self.eligible_groups(quotas,minimum,address_scope)
                quotas={a:v for values in groups.values() for a,v in values.items()}
            if not quotas:
                prior=[i['created'] for i in self.intents.values()]+[b['created'] for b in self.batches.values()]
                if prior and now-max(prior)<units(policy['batch_seconds']):return None
                minimum=units(policy['minimum_units'])
                address_scope=True
                groups=self.eligible_groups(available,minimum,address_scope)
                quotas={a:v for values in groups.values() for a,v in values.items()}
                if not quotas:return None
                batch={'created':now,'quotas':{a:str(v) for a,v in sorted(quotas.items())},
                       'policy':'operator-payment-policy-v3','threshold_scope':'payout_address',
                       'destinations':{a:self.pool.accounts[a]['address'] for a in sorted(quotas)},
                       'minimum_units':str(minimum),
                       'batch_seconds':policy['batch_seconds'],'operator_revision':policy['revision']}
                batch['id']=hashlib.sha256(encode(batch)).hexdigest();self.record('payment_batch',batch)
            require(all(available.get(a,0)>=v for a,v in quotas.items()),'batch income no longer available')
            allowed={(i['txid'],o['vout']) for i in self.pool.incomes.values() if i['state']=='available' for o in i['outputs']}
            # Signed change is permitted only after it has actually confirmed.
            for intent in self.intents.values():
                if intent.get('state')=='confirmed':
                    tx=self.node.call('gettransaction',intent['txid'],intent['block_hash'])
                    for out in tx['vout']:
                        if out['script_pubkey']==self.pool_script:allowed.add((intent['txid'],out['n']))
            reserved={(i['txid'],units(i['vout'])) for p in self.intents.values() for i in p['wire']['inputs']}
            pool_coins=self.node.call('listunspent',self.pool.pool_address)
            backed=sum(c['value_units'] for c in pool_coins if (c['txid'],c['vout']) in allowed and
                       (c['txid'],c['vout']) not in reserved)
            # Missing signed history or an unexplained spend must not be masked
            # by selecting other miners' still-unspent receipts. Pending change
            # can cause a conservative pause until it confirms; it cannot erase
            # a liability or authorize another economic payment.
            require(backed>=sum(available.values()),'miner liability backing deficit; restore signing records and reconcile')
            selected=[];pool_funding=0
            for role,address,needed in [('pool',self.pool.pool_address,sum(quotas.values())),('fees',self.fee_address,self.fee)]:
                gathered=0
                for coin in sorted(pool_coins if role=='pool' else self.node.call('listunspent',address),key=lambda c:(-c['value_units'],c['txid'],c['vout'])):
                    identity=(coin['txid'],coin['vout'])
                    if identity in reserved or (role=='pool' and identity not in allowed):continue
                    require(type(coin['value_units']) is int and coin['value_units']>0,'funding amount')
                    if role=='pool' and coin['confirmations']<120 and identity[0] not in {p.get('txid') for p in self.intents.values()}:continue
                    if len(selected)>=(63 if role=='pool' else 64):break
                    selected.append({'txid':hex64(coin['txid']),'vout':str(coin['vout']),'units':str(coin['value_units']),'role':role})
                    gathered+=coin['value_units']
                    if gathered>=needed and (role=='pool' or gathered==needed or gathered-needed>=self.dust):break
                if role=='fees':
                    require(gathered>=needed,'insufficient segregated operator fee funding')
                    require(gathered==needed or gathered-needed>=self.dust,'operator change below native dust policy')
                else:
                    if gathered<minimum:return None # Wait for confirmed change; keep the frozen batch.
                    pool_funding=gathered
            selected_groups={};remaining=pool_funding
            for group,values in sorted(groups.items()):
                if len(selected_groups)>=128 or remaining<minimum:break
                amount=min(sum(values.values()),remaining)
                selected_groups[group]=amount;remaining-=amount
            if 0<remaining<self.dust:
                # Preserve a relayable change output without donating liabilities
                # as fees. Sub-threshold leftovers remain owed for a later batch.
                group=max(selected_groups,key=lambda g:(selected_groups[g],g))
                selected_groups[group]-=self.dust-remaining
                if selected_groups[group]<minimum:del selected_groups[group]
            amounts={}
            for group,amount in selected_groups.items():
                # A partial input-bounded payment debits only the exact account
                # units it sends. Remaining quotas survive for subsequent chunks.
                for account,owed in sorted(groups[group].items()):
                    take=min(owed,amount)
                    if take:amounts[account]=take;amount-=take
                    if amount==0:break
                require(amount==0,'payout destination deduction mismatch')
            if not amounts:return None
            require(len(selected)<=64,'batch input bound')
            recipients={}
            for account,amount in amounts.items():
                address=self.pool.accounts[account]['address']
                require(address not in (self.pool.pool_address,self.fee_address),'self payout is not permitted')
                recipients[address]=recipients.get(address,0)+amount
            wire={'chain':self.node.genesis,'pool_script':self.pool_script,'fee_script':self.fee_script,'inputs':selected,
                  'recipients':[{'address':a,'units':str(v)} for a,v in sorted(recipients.items())],'fee_units':str(self.fee)}
            value={'created':now,'batch':batch['id'],'deductions':{a:str(v) for a,v in sorted(amounts.items())},'wire':wire,'state':'reserved'}
            value['id']=hashlib.sha256(encode(value)).hexdigest()
            self.record('payment_intent',value)
            return value['id']

    def sign(self,identity):
        with self.pool.lock,self.lock:
            intent=self.intents[identity]
            if 'signed_hex' in intent:return intent['txid']
            operator=getattr(self.pool,'operator',None)
            require(not operator or not operator.faulted,'operator journal failed; signing stopped')
            require(not operator or not operator.settings['payments_paused'],'new payment signatures are paused')
            # A preparation is not proof of spendability; recheck immediately
            # before any signature. Only this private engine invokes the helper.
            self.available()
            for recipient in intent['wire']['recipients']:
                if len(recipient['address'])>50:
                    active=self.node.call('validateaddress',recipient['address'])
                    require(isinstance(active,dict) and active.get('isvalid') is True and active.get('destination_type')=='sha384-v1' and
                            active.get('active_for_next_block') is True,'SHA-384 payout destination is not active')
            coins={}
            for role,address in [('pool',self.pool.pool_address),('fees',self.fee_address)]:
                for coin in self.node.call('listunspent',address):coins[(role,coin['txid'],str(coin['vout']))]=coin
            for coin in intent['wire']['inputs']:
                current=coins.get((coin['role'],coin['txid'],coin['vout']))
                require(current and current['value_units']==units(coin['units']),'reserved input no longer spendable')
            response=subprocess.run([self.binary,self.pool_seed,self.fee_seed],input=encode(intent['wire'])+b'\n',
                                    capture_output=True,timeout=60,check=False)
            require(response.returncode==0,'private payout construction refused')
            require(len(response.stdout)<=2*1024*1024+66,'signed response bound')
            fields=response.stdout.decode('ascii').strip().split()
            require(len(fields)==2,'signed response schema')
            txid=hex64(fields[0]);raw=bytes.fromhex(fields[1])
            require(raw.hex()==fields[1] and 0<len(raw)<=1024*1024,'signed encoding')
            require(hashlib.sha256(hashlib.sha256(raw).digest()).hexdigest()==txid,'signed transaction identity')
            self.record('payment_signed',{'id':identity,'txid':txid,'signed_hex':fields[1],'state':'signed'})
            return txid

    def reconcile(self,identity,broadcast=True):
        with self.lock:
            intent=self.intents[identity]
            if 'signed_hex' not in intent:return 'reserved'
            if intent['state']=='confirmed' and intent.get('block_hash'):
                height=self.node.call('getblockcount')
                if height>=intent['block_height'] and self.node.call('getblockhash',str(intent['block_height']))==intent['block_hash']:
                    return 'confirmed'
                self.record('payment_state',{'id':identity,'state':'signed','block_hash':None})
            try:
                tx=(self.node.call('gettransaction',intent['txid'],intent['block_hash'])
                    if intent.get('block_hash') else self.node.call('getrawtransaction',intent['txid']))
                confirmed=(tx.get('confirmations',0)>0 and tx.get('block_hash') and
                           self.node.call('getblockhash',str(tx['block_height']))==tx['block_hash'])
            except (Refused,Busy):confirmed=False
            if confirmed:
                if intent['state']!='confirmed':self.record('payment_state',{'id':identity,'state':'confirmed','block_hash':tx['block_hash'],'block_height':tx['block_height']})
                return 'confirmed'
            # The full canonical index also finds signatures retained across
            # downtime beyond the recent-block window. An incomplete lookup
            # (including index recovery) is not evidence that no payment
            # happened. Rebroadcast ONLY the already persisted identical bytes.
            # Loss, disconnection, and rejection retain the same reservation and
            # exact bytes. They never authorize construction of another payment.
            if intent['state']=='confirmed':self.record('payment_state',{'id':identity,'state':'signed','block_hash':None})
            operator=getattr(self.pool,'operator',None)
            if not broadcast or (operator and (operator.faulted or operator.settings['payments_paused'])):return 'signed'
            try:
                result=self.node.call('sendrawtransaction',intent['signed_hex'])
                require(result==intent['txid'],'broadcast identity mismatch')
            except (OSError,Refused) as error:
                notice=str(error)[:256]
                if intent.get('last_broadcast_error')!=notice:
                    self.record('payment_notice',{'id':identity,'last_broadcast_error':notice})
                return 'unconfirmed'
            return 'broadcast'
