"""Private operator controls. No generic RPC, destination edit or signing API.

Settings and commands share the append-first work journal and its independent
rollback anchor. Existing receipt policies and payment batches are immutable.
"""
import contextlib
import hashlib
import itertools
import re
import threading
import time
from fractions import Fraction

from .accounting import floor_total
from .records import Records
from .protocol import Busy, Refused, encode, require, schema, units

DEFAULT_POLICY = {'minimum_units':'100000000','batch_seconds':'86400','fee_ppm':'0'}


class Operator:
    def __init__(self, pool, max_fee_ppm=0):
        require(type(max_fee_ppm) is int and 0<=max_fee_ppm<=100000,'service fee ceiling')
        self.pool=pool; self.max_fee_ppm=max_fee_ppm; self.lock=threading.RLock()
        self.revision=0;self.initialized=False;self.faulted=False
        self.settings=dict(DEFAULT_POLICY,payments_paused=True,comining_paused=True)
        self.audit=Records(pool.journal,'operator_audit')
        for event in pool.journal.events():
            self.apply(event['kind'],event['payload'],event['seq'])
        if not self.initialized:self.record('operator_initialized',dict(settings=dict(self.settings),revision=0,chain=pool.node.genesis))
        self.validate(self.settings)
        require(units(self.settings['fee_ppm'])<=max_fee_ppm,'configured fee ceiling is below recorded policy')
        pool.operator=self

    @contextlib.contextmanager
    def transaction(self):
        if not self.lock.acquire(timeout=2):raise Busy('operator action in progress; retry the same request')
        try:
            with self.pool.lock:yield
        finally:self.lock.release()

    def apply(self,kind,value,seq):
        if kind=='operator_initialized':
            require(value.get('chain')==self.pool.node.genesis,'operator journal chain mismatch')
            self.initialized=True;self.settings=dict(value['settings']);self.revision=value['revision']
        elif kind=='operator_command':self.audit[value['id']]=dict(value,seq=seq,status='pending')
        elif kind=='operator_result':
            item=self.audit[value['id']]; item.update(value); self.audit[value['id']]=item
        elif kind=='operator_settings':
            self.settings=dict(value['settings']);self.revision=value['revision']
            self.audit[value['id']]=dict(value,seq=seq,status='applied')

    def record(self,kind,value):
        try:
            seq=self.pool.journal.append(kind,value);self.apply(kind,value,seq)
        except BaseException:
            self.faulted=True
            raise

    def policy(self):return dict(DEFAULT_POLICY,**{k:self.settings[k] for k in DEFAULT_POLICY},revision=str(self.revision))

    def validate(self,settings):
        schema(settings,(*DEFAULT_POLICY,'payments_paused','comining_paused'))
        for flag in ('payments_paused','comining_paused'):require(type(settings[flag]) is bool,'pause flag')
        require(100000000<=units(settings['minimum_units'])<=1000000000000,'minimum payout: 1 to 10000 VELD')
        require(3600<=units(settings['batch_seconds'])<=604800 and units(settings['batch_seconds'])%3600==0,
                'batch interval: whole hours from 1 hour to 7 days')
        require(units(settings['fee_ppm'])<=self.max_fee_ppm,'fee exceeds separately approved service ceiling')

    def preflight(self,settings):
        pool=self.pool;pool.node.check_chain()
        if not settings['payments_paused']:
            require(pool.payments is not None,'payout signer is not configured')
            pool.reconcile_income()
            with pool.payments.lock:
                pool.payments.available()  # A deficit cannot be cleared by a toggle.
                fee_coins=pool.node.call('listunspent',pool.payments.fee_address)
                require(any(type(c.get('value_units')) is int and c['value_units']>=pool.payments.fee and
                        (c['value_units']==pool.payments.fee or c['value_units']-pool.payments.fee>=pool.payments.dust)
                        for c in fee_coins),'separate spendable operator fee funding required')
        if not settings['comining_paused']:
            require(pool.identity is not None,'restricted co-mining signer and funding manifest are not configured')
            identity=pool.identity
            with identity.lock:
                state=pool.node.call('getpoolidentitystate',pool.pool_address)
                require(type(state) is dict and type(state.get('height')) is int,'canonical identity state unavailable')
                stake=units(state['stake_units']);required=units(state['required_stake_units'])
                require(required>=100000000000,'canonical co-mining eligibility floor')
                require(stake==0 or stake>=required,'partial stake requires reconciliation')
                coins=identity.allowed();fee=units(state['fee_units']);dust=units(state['dust_units'])
                if stake==0:
                    require(state['staking_active'] is True,'staking is not active')
                    funding=sum(units(c['units']) for c in coins[:64])
                    require(funding>=required+fee and (funding==required+fee or funding-required-fee>=dust),
                            'designated operator funds do not cover stake and fee')
                else:
                    require(state['eligible'] is True,'pool identity is not eligible for co-mining')
                    require(any(units(c['units'])>=2*fee and (units(c['units'])==2*fee or units(c['units'])-2*fee>=dust)
                                for c in coins),'designated near-miss fee funds required')
                require(pool.node.call('getblockhash',str(state['height']))==state['parent'],
                        'chain changed during co-mining preflight')

    def execute(self,action,value,actor):
        require(action in ('settings','reconcile'),'operator action')
        fields=('request_id','revision','reason','settings') if action=='settings' else ('request_id','revision','reason')
        schema(value,fields)
        require(type(value['request_id']) is str and re.fullmatch('[a-f0-9]{32}',value['request_id']),'request identity')
        revision=units(value['revision']);reason=value['reason']
        require(type(reason) is str and 3<=len(reason)<=160 and all(ord(c)>=32 for c in reason),'reason required')
        require(type(actor) is str and re.fullmatch('operator:[a-f0-9]{16}',actor),'operator identity')
        digest=hashlib.sha256(encode({'action':action,'value':value,'actor':actor})).hexdigest()
        with self.transaction():
            require(not self.faulted,'operator journal failed; restart with intact journal and anchor')
            prior=self.audit.get(value['request_id'])
            if prior:
                require(prior['digest']==digest,'request identity reused with different content')
                return self.result(prior)
            require(revision==self.revision,'settings changed; refresh before applying')
            event=dict(id=value['request_id'],action=action,digest=digest,actor=actor,reason=reason,created=str(int(time.time())))
            if action=='settings':
                settings=value['settings'];self.validate(settings)
                # Pausing always works, even when chain/RPC is unavailable.
                # Re-enabling checks readiness; every signer still revalidates.
                if any(self.settings[k] and not settings[k] for k in ('payments_paused','comining_paused')):
                    self.preflight(settings)
                event.update(settings=dict(settings),revision=self.revision+1,previous=dict(self.settings))
                self.record('operator_settings',event)
                self.pool.active=None # New jobs capture the new fee; old leases keep theirs.
            else:
                require(sum(1 for _ in self.audit.select(status='pending'))<8,'reconciliation queue full')
                event['revision']=self.revision
                self.record('operator_command',event)
            return self.result(self.audit[event['id']])

    @staticmethod
    def result(event):return {k:event[k] for k in ('id','status','revision','action')}

    def reconcile(self):
        """Complete durable requests without new signing or transaction broadcast."""
        with self.transaction():
            pending=next(self.audit.select(status='pending',sequence=True),None)
            if pending is None:return
            try:
                self.pool.node.check_chain();self.pool.reconcile_solutions(submit=False)
                if self.pool.rewards:self.pool.rewards.reconcile()
                self.pool.reconcile_income()
                if self.pool.payments:
                    for identity in list(self.pool.payments.intents):
                        self.pool.payments.reconcile(identity,broadcast=False)
                    self.pool.payments.available()
                status='completed';detail='Canonical income and existing payment records reconciled; no new signing or broadcast.'
            except (OSError,RuntimeError,ValueError):
                status='failed';detail='Reconciliation did not pass. Reservations remain intact; inspect private service diagnostics.'
            self.record('operator_result',dict(id=pending['id'],status=status,detail=detail,completed=str(int(time.time()))))

    def run(self,kind,callback):
        # A successful pause response waits for any in-flight signature to finish.
        # Already signed transactions cannot be revoked; never erase reservations.
        with self.lock:
            require(not self.faulted,'operator journal failed; signing stopped')
            if self.settings[kind+'_paused']:return
            callback()

    def snapshot(self,before=0):
        require(type(before) is int and 0<=before<(1<<63),'audit cursor')
        with self.transaction():
            p=self.pool
            groups={k:[] for k in ('pending','available')}
            for income in p.incomes.values():
                if income['state'] in groups:groups[income['state']].extend(Fraction(v) for v in income['credits'].values())
            totals={k:str(floor_total(v)) for k,v in groups.items()}
            reserved=paid=0
            if p.payments:
                with p.payments.lock:
                    for item in p.payments.intents.values():
                        amount=sum(units(v) for v in item['deductions'].values())
                        if item['state']=='confirmed':paid+=amount
                        else:reserved+=amount
            available=int(totals['available'])-reserved-paid
            totals.update(available=str(max(available,0)),reserved=str(reserved),paid=str(paid),deficit=str(max(-available,0)))
            rows=list(itertools.islice(self.audit.select(cutoff=before-1 if before else None,reverse=True,sequence=True),21))
            audit=[{k:v for k,v in item.items() if k not in ('digest',)} for item in rows[:20]]
            return dict(settings=dict(self.settings),revision=str(self.revision),health=p.health(),balances=totals,
                        capabilities=dict(payments=p.payments is not None,comining=p.identity is not None,
                                          max_fee_ppm=str(self.max_fee_ppm),minimum_confirmations='120'),
                        identity_status=p.identity.status() if p.identity else 'Restricted signer not configured',
                        audit=audit,next_before=str(rows[19]['seq']) if len(rows)>20 else '0')
