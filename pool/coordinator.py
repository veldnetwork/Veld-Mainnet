import hashlib
import hmac
import secrets
import threading
import time
from fractions import Fraction
from collections import OrderedDict

from .protocol import VERSION, Busy, Refused, require, hex64, nonce, units
from .accounting import pplns, allocate_policy, text, floor_total
from .records import Records
from .overview import IncomeOverview, WorkOverview

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def template_identity(header):
    return hashlib.sha256(hashlib.sha256(header[:80]+bytes(8)).digest()).hexdigest()

class Coordinator:
    def __init__(self, node, journal, verifier, pool_address, accounting_target, capacity=16):
        self.node, self.journal, self.verifier = node, journal, verifier
        self.pool_address, self.target = pool_address, hex64(accounting_target)
        require(int(self.target,16)>0, 'zero accounting target')
        self.lock = threading.RLock()
        require(type(capacity) is int and 1<=capacity<=256, 'verification capacity')
        self.queue_capacity=capacity
        self.unverified_count=0
        self.admission = threading.BoundedSemaphore(capacity)
        # Accounts have no expiry: existing credentials and earned liabilities
        # must survive inactivity. Keep their lookup on disk rather than making
        # the lifetime number of registrations a permanent admission limit.
        self.accounts=Records(journal,'accounts')
        self.registration_tokens=16.0
        self.registration_updated=time.monotonic()
        self.jobs=Records(journal,'jobs');self.leases=Records(journal,'leases')
        self.highwater=Records(journal,'nonce_highwater');self.receipts=Records(journal,'receipts')
        self.earnings=Records(journal,'earnings')
        self.active = None
        # Only already durable, account-bound leases are cached. Unused ranges
        # are deliberately abandoned at template changes/restart, never reused.
        self.lease_reserve = OrderedDict()
        self.incomes = Records(journal,'incomes')
        self.payments = None
        self.rewards = None
        self.identity = None
        self.operator = None
        self.solutions = Records(journal,'solutions')
        self.inflight = set()
        self.verified_counts = {}
        self.last_healthy = 0
        self.active_accounts = {} # authenticated activity; never a hashrate estimate
        self.public_income=IncomeOverview();self.public_work=WorkOverview();self.replaying=True
        for event in journal.events(): self.apply(event['kind'], event['payload'], event['seq'])
        self.replaying=False
        self.public_work=WorkOverview()
        for receipt in self.receipts.select(status='pending'):
            self.record('verification', {'identity':receipt['identity'],'status':'deferred'})
        self.node.check_chain()

    def apply(self, kind, value, seq):
        if kind == 'account': self.accounts[value['id']] = value
        elif kind == 'job': self.jobs[value['id']] = value
        elif kind == 'job_authorization':
            job=self.jobs[value['id']];job['node']=value['node'];self.jobs[value['id']]=job
        elif kind == 'lease':
            self.leases[value['id']] = value
            end=max(int(self.highwater.get(value['template'],{'end':'0'})['end']),int(value['end']))
            self.highwater[value['template']]={'end':str(end)}
        elif kind == 'receipt':
            self.receipts[value['identity']] = dict(value, seq=seq, status='pending')
            self.unverified_count+=1
        elif kind == 'verification':
            receipt=self.receipts[value['identity']]
            account=receipt['account']
            change=int(value['status']=='verified')-int(receipt['status']=='verified')
            waiting=('pending','deferred')
            self.unverified_count+=int(value['status'] in waiting)-int(receipt['status'] in waiting)
            self.verified_counts[account]=self.verified_counts.get(account,0)+change
            if change==1 and not self.replaying:self.public_work.add(receipt['target'])
            receipt.update(value)
            self.receipts[value['identity']]=receipt
        elif kind == 'earned':
            self.earnings[value['block']] = value
            solution=self.solutions.get(value['block'])
            if solution is not None:
                solution['status']='accounted';self.solutions[value['block']]=solution
        elif kind == 'solution': self.solutions[value['block']] = value
        elif kind == 'income':
            self.public_income.update(self.incomes.get(value['id']),value)
            self.incomes[value['id']] = value
            if value.get('category')=='mining' and value['id'] in self.earnings:
                earned=self.earnings[value['id']];earned['status']='accounted';self.earnings[value['id']]=earned
        elif kind == 'income_state':
            income=self.incomes[value['id']];old=dict(income);income['state']=value['state']
            if value['state']=='available':income['available_once']=True
            self.public_income.update(old,income)
            self.incomes[value['id']]=income

    def record(self, kind, value):
        seq=self.journal.append(kind,value)
        try:self.apply(kind,value,seq)
        except BaseException:
            # The log is already durable. Never serve from a partially updated
            # nonce/accounting projection; reconstruct it from the log first.
            self.journal.close();raise
        return seq

    def unresolved(self,cutoff):
        return any(next(self.receipts.select(status=status,cutoff=cutoff),None) is not None
                   for status in ('pending','deferred'))

    def register(self, address):
        require(isinstance(address,str) and 25 <= len(address) <= 75, 'payout address')
        require(address!=self.pool_address, 'pool identity cannot be a worker payout address')
        require(not self.payments or address!=self.payments.fee_address,'operator fee identity cannot be a worker payout address')
        # The gateway's per-source limit alone cannot bound distributed callers.
        # Apply one process-wide budget BEFORE private node validation or any
        # durable write. Depletion is temporary and never revokes an account.
        with self.lock:
            now=time.monotonic()
            elapsed=max(0.0,now-self.registration_updated)
            self.registration_tokens=min(16.0,self.registration_tokens+elapsed/5.0)
            self.registration_updated=max(now,self.registration_updated)
            if self.registration_tokens<1.0:
                raise Busy('registration capacity; retry')
            self.registration_tokens-=1.0
        validation=self.node.call('validateaddress',address)
        require(isinstance(validation,dict) and validation.get('isvalid') is True, 'invalid payout address')
        if len(address)>50:
            require(validation.get('destination_type')=='sha384-v1' and validation.get('active_for_next_block') is True,
                    'SHA-384 payout destination is not active on this node')
        with self.lock:
            worker, view = secrets.token_hex(32), secrets.token_hex(32)
            value={'id':secrets.token_hex(16),'address':address,'worker_hash':sha(worker.encode()),'view_hash':sha(view.encode())}
            self.record('account',value)
            return {'version':VERSION,'account':value['id'],'worker_token':worker,'view_token':view}

    def authenticate(self, account, credential, role='worker'):
        require(isinstance(account,str) and isinstance(credential,str) and len(credential)==64, 'account authorization')
        value=self.accounts.get(account)
        require(value is not None and hmac.compare_digest(value[role+'_hash'],sha(credential.encode())), 'account authorization')
        return value

    def work(self, account, credential, count=32):
        self.authenticate(account,credential)
        require(type(count) is int and 1<=count<=4096, 'lease size')
        with self.lock:
            self.journal.ensure_open()
            # Cache only an issuing-node token which still has ample lifetime.
            if self.active is None or self.active[1] < time.monotonic()+2:
                self.lease_reserve.clear()
                started=time.monotonic()
                if self.rewards:
                    seal_height=self.node.call('getblockcount')+1
                    seal_parent=self.node.call('getblockhash',str(seal_height-1))
                    self.rewards.seal(seal_height,seal_parent)
                template=self.node.template(self.pool_address)
                if self.rewards:
                    if template['height']!=seal_height or template['prev_block_hash']!=seal_parent:
                        raise Busy('chain advanced while sealing reward window; retry')
                header=bytes.fromhex(template['block_hex'])[:88]
                identity=self.node.genesis+':'+template_identity(header)
                policy=self.operator.policy() if self.operator else {'fee_ppm':'0','revision':'0'}
                job={'id':secrets.token_hex(16),'template':identity,'height':template['height'],
                     # Every full solution is also an accounting share. Freeze
                     # this adjustment in the job before assigning any work.
                     'target':max(self.target,hex64(template['target'])),
                     'node':template,'policy':'pplns-2-blocks-fee-0-v1' if policy['fee_ppm']=='0' else 'pplns-share-policy-v2',
                     'fee_ppm':policy['fee_ppm'],'operator_revision':policy['revision']}
                self.record('job',job)
                self.active=(job['id'],started+template['work_ttl_ms']/1000)
            job=self.jobs[self.active[0]]
            key=(job['id'],account,count)
            reserve=self.lease_reserve.pop(key,[])
            if not reserve:
                start=int(self.highwater.get(job['template'],{'end':'0'})['end'])
                require(start+count <= 1<<64, 'template nonce space exhausted')
                batch=min(8,((1<<64)-start)//count)
                reserve=[{'id':secrets.token_hex(16),'account':account,'job':job['id'],
                          'template':job['template'],'start':str(start+i*count),
                          'end':str(start+(i+1)*count)} for i in range(batch)]
                # Exact individual ranges, credentials and response schema stay
                # unchanged. One sync group replaces up to eight sync groups.
                sequences=self.journal.append_many([('lease',lease) for lease in reserve])
                try:
                    for lease,sequence in zip(reserve,sequences):self.apply('lease',lease,sequence)
                except BaseException:self.journal.close();raise
            lease=reserve.pop(0)
            start=int(lease['start'])
            if reserve:
                self.lease_reserve[key]=reserve
                if len(self.lease_reserve)>64:self.lease_reserve.popitem(last=False)
            # An expensive durable write must not publish already expired work.
            if self.active[1] <= time.monotonic():raise Busy('work expired during durable reservation; retry')
            self.active_accounts[account] = time.monotonic()
            return {'version':VERSION,'lease':lease['id'],'chain':self.node.genesis,'height':str(job['height']),
                    'header':job['node']['block_hex'][:176], 'target':job['target'],
                    'fee_ppm':job.get('fee_ppm','0'),'policy_revision':job.get('operator_revision','0'),
                    'start':f'{start:016x}','count':str(count),'ttl_ms':str(max(0,int((self.active[1]-time.monotonic())*1000)))}

    def account(self, account, credential):
        self.authenticate(account,credential,'view')
        with self.lock:
            pending=[];available=[];categories={}
            for income in self.incomes.values():
                credit=Fraction(income['credits'].get(account,'0'))
                if income['state']=='pending':pending.append(credit)
                elif income['state']=='available':available.append(credit)
                if income['state'] in ('pending','available'):
                    categories.setdefault(income.get('category','unclassified'),[]).append(credit)
            payment = self.payments.summary(account) if self.payments else {'reserved_units':'0','paid_units':'0'}
            pending_units=floor_total(pending)
            available_units=floor_total(available)-int(payment['reserved_units'])-int(payment['paid_units'])
            return {'account':account,'address':self.accounts[account]['address'],
                    'verified_shares':str(self.verified_counts.get(account,0)),
                    'pending_units':str(pending_units),
                    'available_units':str(max(0,available_units)),
                    'fractional_units':'retained in exact earning records',
                    'lottery_status':self.identity.status() if self.identity else 'Co-mining disabled; operator funding required.',
                    'reward_windows':self.rewards.status() if self.rewards else {},
                    'reward_totals':{key:str(floor_total(value)) for key,value in categories.items()},
                    **payment,'payment_status':('reconciliation required' if available_units<0 else
                        'paused' if self.operator and self.operator.settings['payments_paused'] else
                        'enabled' if self.payments else 'not enabled')}

    def health(self):
        with self.lock:
            now=time.monotonic()
            self.active_accounts={key:seen for key,seen in self.active_accounts.items() if now-seen<120}
            tip=getattr(self,'income_tip',None)
            return {'version':VERSION,'status':'Service responding' if time.monotonic()-self.last_healthy<15
                    else 'Reconciliation paused or starting','test_candidate':True,
                    'chain':self.node.genesis,
                    'reconciled_height':str(tip[0]) if tip else None,
                    'active_accounts':str(len(self.active_accounts)),
                    'verified_shares':str(sum(self.verified_counts.values())),
                    'payments_enabled':self.payments is not None and not (self.operator and self.operator.settings['payments_paused']),
                    'co_mining_enabled':self.identity is not None and not (self.operator and self.operator.settings['comining_paused']),
                    'payment_policy':self.operator.policy() if self.operator else {'minimum_units':'100000000','batch_seconds':'86400','fee_ppm':'0','revision':'0'},
                    'verification_queue':{'waiting':self.unverified_count,'capacity':self.queue_capacity},
                    'overview':{'version':1,**self.public_income.snapshot(tip[0] if tip else 0),
                        'work':self.public_work.snapshot(),
                        'payments':self.payments.public_summary() if self.payments else
                            {'paid_units':'0','confirmed_transactions':'0'}},
                    'retrying':getattr(self,'deferred_phases',[])}

    def history(self,account,credential,before=0):
        self.authenticate(account,credential,'view')
        require(type(before) is int and 0<=before<(1<<63),'history cursor')
        with self.lock:
            return self.payments.history(account,before) if self.payments else {'payments':[],'next_before':0}

    def reconcile_income(self):
        with self.lock:
            height=self.node.call('getblockcount')
            require(type(height) is int and height>=0,'canonical height')
            tip=self.node.call('getblockhash',str(height))
            last=getattr(self,'income_tip',None)
            extends=(last is not None and height>=last[0] and
                     self.node.call('getblockhash',str(last[0]))==last[1])
            for earned in self.earnings.select(status=''):
                block=earned['block']
                if extends and block in self.incomes and earned['height']<=last[0]:continue
                canonical=(height>=earned['height'] and self.node.call('getblockhash',str(earned['height']))==block)
                if block in self.incomes:
                    income=self.incomes[block]
                    if not canonical and income['state']!='orphaned':
                        self.record('income_state',{'id':block,'state':'orphaned'})
                    elif canonical and income['state']=='orphaned':
                        self.record('income_state',{'id':block,'state':'pending'})
                    continue
                if not canonical:continue
                # Preserve arrival cutoff even when verification finishes out of order.
                if self.unresolved(earned['cutoff']):continue
                info=self.node.call('getblock',block)
                tx=self.node.call('gettransaction',info['tx'][0],block)
                require(tx['coinbase'] is True and tx['block_hash']==block,'canonical miner receipt')
                expected=self.jobs[earned['job']]['node']['miner_receipts']
                outputs=[]
                for receipt in expected:
                    matching=[o for o in tx['vout'] if o['n']==receipt['n']]
                    require(len(matching)==1 and matching[0]['address']==self.pool_address and
                            matching[0]['value_units']==receipt['value_units'] and
                            matching[0]['script_pubkey']==receipt['script_pubkey'],'miner category receipt mismatch')
                    outputs.extend(matching)
                amount=sum(units(o['value_units']) for o in outputs)
                weights=pplns(self.receipts.select(status='verified',cutoff=earned['cutoff'],reverse=True,sequence=True),
                              earned['cutoff'],self.jobs[earned['job']]['node']['target'],ordered=True,fee_policy=True)
                credits,fee=allocate_policy(amount,weights)
                self.record('income',{'id':block,'height':earned['height'],'txid':tx['txid'],
                            'outputs':[{'vout':o['n'],'units':o['value_units']} for o in outputs],
                            'amount':str(amount),'category':'mining','policy':'pplns-share-policy-v2',
                            'cutoff':earned['cutoff'],'credits':{a:text(v) for a,v in credits.items()},
                            'operator_fee':text(fee),'state':'pending'})
            spendable={(u['txid'],u['vout']):u for u in self.node.call('listunspent',self.pool_address)}
            # A normal extension cannot orphan an already validated prefix.
            # Query only mature pending receipts and previously orphaned ones;
            # a restart or actual reorg deliberately rechecks the whole ledger.
            def candidates():
                if not extends:
                    yield from self.incomes.values();return
                yield from self.incomes.select(status='pending',last=height-119)
                yield from self.incomes.select(status='orphaned')
            for income in candidates():
                canonical=(extends and income['height']<=last[0] and income['state']!='orphaned') or (height>=income['height'] and
                    self.node.call('getblockhash',str(income['height']))==income.get('block',income['id']))
                if not canonical:
                    if income['state']!='orphaned':self.record('income_state',{'id':income['id'],'state':'orphaned'})
                    continue
                if income['state']=='orphaned':
                    self.record('income_state',{'id':income['id'],'state':'pending'});income['state']='pending'
                if income['state']!='pending' or height-income['height']+1<120:continue
                if income.get('available_once') or all((income['txid'],o['vout']) in spendable and
                       spendable[income['txid'],o['vout']]['value_units']==units(o['units']) for o in income['outputs']):
                    self.record('income_state',{'id':income['id'],'state':'available'})
            # Never cache a prefix if the chain changed during reconciliation.
            require(self.node.call('getblockhash',str(height))==tip,'chain changed during income reconciliation')
            self.income_tip=(height,tip)

    def reconcile_solutions(self,submit=True):
        with self.lock:
            height=self.node.call('getblockcount')
            if self.active and self.jobs[self.active[0]]['height']!=height+1:
                self.active=None
            for solution in self.solutions.select(status=''):
                if solution['block'] in self.earnings:continue
                if submit and height==solution['height']-1:
                    try:
                        job=self.jobs[solution['job']]
                        # A deferred external-work budget may outlive its one-use
                        # token. Renew only the issuing node's retained exact body.
                        renewed=self.node.renew(job['node'],self.pool_address)
                        self.record('job_authorization',{'id':job['id'],'node':renewed})
                        self.node.submit(renewed,int(solution['nonce']))
                        height=self.node.call('getblockcount')
                    except (OSError,Refused,Busy):continue
                if height<solution['height']:continue
                if self.node.call('getblockhash',str(solution['height']))==solution['block']:
                    self.record('earned',{k:v for k,v in solution.items() if k!='nonce'})
                    self.active=None

    def retry_deferred(self):
        # A disconnected worker does not leave a durable receipt unresolved
        # forever. Retry one at a time within the same admission/resource limits.
        with self.lock:
            pending=next((r for r in self.receipts.select(status='deferred',sequence=True)
                          if r['status']=='deferred' and r['identity'] not in self.inflight),None)
            if pending is None or not self.admission.acquire(blocking=False):return
            identity=pending['identity'];self.inflight.add(identity)
            job=self.jobs[self.leases[pending['lease']]['job']]
        return self._verify(identity,job,nonce(pending['nonce']))

    def submit(self, account, credential, lease_id, encoded_nonce):
        self.authenticate(account,credential)
        number=nonce(encoded_nonce)
        with self.lock:
            lease=self.leases.get(lease_id)
            require(lease and lease['account']==account, 'nonce lease authorization')
            require(int(lease['start'])<=number<int(lease['end']), 'nonce outside lease')
            job=self.jobs[lease['job']]
            identity=job['template']+':'+encoded_nonce
            prior=self.receipts.get(identity)
            if identity in self.inflight:
                return {'status':'pending'}
            if prior and prior['status'] not in ('deferred',):
                return {'status':'duplicate','original_status':prior['status']}
            # Deferred receipts still consume queue capacity after their request
            # thread releases its semaphore. Otherwise repeated new nonces can
            # grow durable unverified work without bound while the verifier is
            # unavailable. Existing receipts remain retryable across restart.
            if not prior and self.unverified_count>=self.queue_capacity:
                raise Busy('verification backlog full; retry same proof')
            admitted_parent=self.node.call('getbestblockhash') if not prior else prior.get('admitted_parent')
            if not prior and admitted_parent!=job['node']['prev_block_hash']:
                return {'status':'stale'}
            # Cheap checks precede bounded admission and durable receipt creation.
            if not self.admission.acquire(blocking=False): raise Busy('verification queue full; retry same proof')
            self.inflight.add(identity)
            try:
                if not prior:
                    self.record('receipt',{'identity':identity,'account':account,'lease':lease_id,
                                'height':job['height'],'target':job['target'],'nonce':encoded_nonce,
                                'admitted_parent':admitted_parent,'fee_ppm':job.get('fee_ppm','0'),
                                'operator_revision':job.get('operator_revision','0')})
            except BaseException:
                self.inflight.discard(identity)
                self.admission.release()
                raise
        return self._verify(identity,job,number)

    def _verify(self,identity,job,number):
        try:
            raw=bytearray.fromhex(job['node']['block_hex']); raw[80:88]=number.to_bytes(8,'little')
            try: proof,native_identity,proof_kind=self.verifier.inspect(bytes(raw[:88]),job['height'])
            except Busy:
                with self.lock:self.record('verification',{'identity':identity,'status':'deferred'})
                raise
            require(native_identity==job['template'].split(':')[1], 'native template mismatch')
            if int(proof,16)>=int(job['target'],16) and proof_kind!='near_miss': status='invalid'
            elif (self.receipts[identity].get('admitted_parent')!=job['node']['prev_block_hash'] or
                  self.node.call('getblockhash',str(job['height']-1))!=job['node']['prev_block_hash']):
                status='stale'
            else: status='verified' if int(proof,16)<int(job['target'],16) else 'near_miss'
            with self.lock:
                self.record('verification',{'identity':identity,'status':status,'proof':proof,'proof_kind':proof_kind})
                cutoff=self.receipts[identity]['seq']
            result={'status':status}
            if status=='verified' and int(proof,16)<int(job['node']['target'],16):
                # Do not wait for PPLNS aggregation before normal block admission.
                block_hash=hashlib.sha256(hashlib.sha256(raw[:88]).digest()).hexdigest()
                with self.lock:
                    if block_hash not in self.solutions:
                        self.record('solution',{'block':block_hash,'height':job['height'],'cutoff':cutoff,
                                               'job':job['id'],'receipt':identity,'nonce':str(number)})
                try:
                    response=self.node.submit(job['node'],number)
                    accepted=isinstance(response,dict) and response.get('accepted') is True
                except (Refused,OSError,Busy):
                    # A lost response can follow commitment. Reconcile exact hash.
                    accepted=(self.node.call('getblockcount')>=job['height'] and
                              self.node.call('getblockhash',str(job['height']))==block_hash)
                if accepted:
                    with self.lock:
                        if block_hash not in self.earnings:
                            self.record('earned',{'block':block_hash,'height':job['height'],
                                        'cutoff':cutoff,'job':job['id'],'receipt':identity})
                        self.active=None
                    result['block']=block_hash
            return result
        except BaseException:
            with self.lock:
                if self.receipts[identity]['status'] == 'pending':
                    self.record('verification', {'identity':identity,'status':'deferred'})
            raise
        finally:
            with self.lock: self.inflight.discard(identity)
            self.admission.release()
