"""Real coordinator/payment/journal paths with isolated chain/signing fixtures.
Not a native PoW, signature, spendability or mainnet qualification receipt.
"""
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pool.accounting import allocate_policy,pplns
from pool.coordinator import Coordinator,template_identity
from pool.journal import Journal
from pool.operator import Operator
from pool.payments import Payments
from pool.protocol import Refused


class Node:
    genesis='a'*64
    def __init__(self):
        self.coins={'pool':[dict(txid='b'*64,vout=0,value_units=300000000,confirmations=200)],
                    'fees':[dict(txid='c'*64,vout=0,value_units=1000000,confirmations=200)]}
        self.broadcasts=[];self.confirmed=False
    def check_chain(self):pass
    def template(self,_):return dict(block_hex='00'*92,height=201,target='0'*63+'1',prev_block_hash='d'*64,work_ttl_ms=10000)
    def call(self,method,*args):
        if method=='validateaddress':return {'isvalid':True}
        if method=='getblockcount':return 200
        if method in ('getblockhash','getbestblockhash'):return 'd'*64
        if method=='listunspent':return self.coins[args[0]]
        if method in ('gettransaction','getrawtransaction'):
            if not self.confirmed:raise Refused('fixture transaction not found')
            return dict(confirmations=1,block_height=200,block_hash='d'*64,vout=[])
        if method=='sendrawtransaction':
            self.broadcasts.append(args[0]);raw=bytes.fromhex(args[0]);return hashlib.sha256(hashlib.sha256(raw).digest()).hexdigest()
        raise AssertionError(method)


def fixture(root,max_fee=0):
    node=Node();journal=Journal(root/'work',root/'anchor/work.json')
    verifier=SimpleNamespace(inspect=lambda *_:('0'*63+'2',template_identity(bytes(88)),'none'))
    pool=Coordinator(node,journal,verifier,'pool','f'*64)
    payment_journal=Journal(root/'payments',root/'payment-anchor/current.json')
    pool.payments=Payments(pool,payment_journal,'no-signer-in-fixture','','','11','22','fees',100000,1000)
    operator=Operator(pool,max_fee);pool.last_healthy=time.monotonic()
    return pool,operator,payment_journal


class OperatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.pool,self.operator,self.pj=fixture(self.root,10000)
        self.counter=0
    def tearDown(self):
        # Close optional identity journals before removing their files on Windows.
        self.doCleanups()
        self.pool.journal.close();self.pj.close();self.tmp.cleanup()
    def payload(self,**settings):
        self.counter+=1
        return dict(request_id=f'{self.counter:032x}',revision=str(self.operator.revision),reason='Fixture operator change',
                    settings=dict(self.operator.settings,**settings))
    def apply(self,**settings):return self.operator.execute('settings',self.payload(**settings),'operator:'+'a'*16)
    def restart(self):
        node,verifier=self.pool.node,self.pool.verifier
        self.pool.journal.close();journal=Journal(self.root/'work',self.root/'anchor/work.json')
        self.pool=Coordinator(node,journal,verifier,'pool','f'*64)
        self.pool.payments=Payments(self.pool,self.pj,'no-signer-in-fixture','','','11','22','fees',100000,1000)
        self.operator=Operator(self.pool,10000)

    def test_default_closed_and_restart_replay_idempotent_audit(self):
        self.assertIsNone(self.pool.payments.plan(now=100000))
        value=self.payload(minimum_units='200000000');result=self.operator.execute('settings',value,'operator:'+'a'*16)
        self.assertEqual(result['status'],'applied');self.assertEqual(self.operator.revision,1)
        self.assertEqual(self.operator.execute('settings',value,'operator:'+'a'*16),result)
        with self.assertRaisesRegex(Refused,'different content'):
            self.operator.execute('settings',dict(value,reason='different operator intent'),'operator:'+'a'*16)
        self.restart()
        self.assertEqual(self.operator.settings['minimum_units'],'200000000');self.assertEqual(self.operator.revision,1)
        self.assertEqual(len(self.operator.snapshot()['audit']),1)
        with self.assertRaisesRegex(Refused,'settings changed'):
            self.operator.execute('settings',dict(self.payload(),revision='0'),'operator:'+'a'*16)

    def test_rollback_refused_with_surviving_anchor(self):
        backup=self.root/'old.jsonl';shutil.copy2(self.pool.journal.directory/'events.jsonl',backup)
        self.apply(minimum_units='200000000');self.pool.journal.close()
        shutil.copy2(backup,self.root/'work/events.jsonl')
        with self.assertRaises(Refused):Journal(self.root/'work',self.root/'anchor/work.json')

    def test_readiness_cannot_be_bypassed_or_turn_off_maturity(self):
        for settings in ({'minimum_units':'0'},{'batch_seconds':'1'},{'fee_ppm':'10001'},{'payments_paused':'false'},
                         {'minimum_confirmations':'0'}):
            with self.assertRaises(Refused):self.apply(**settings)
        self.pool.node.coins['fees']=[]
        with self.assertRaisesRegex(Refused,'fee funding'):self.apply(payments_paused=False)
        with self.assertRaisesRegex(Refused,'signer'):self.apply(comining_paused=False)
        self.assertEqual(self.operator.revision,0)
        self.assertFalse(self.pool.health()['payments_enabled'])

    def test_approved_zero_fee_ceiling_and_prospective_assigned_work(self):
        account=self.pool.register('x'*30)
        first=self.pool.work(account['account'],account['worker_token'],1)
        self.apply(fee_ppm='10000')
        second=self.pool.work(account['account'],account['worker_token'],1)
        for work in (first,second):
            self.assertEqual(self.pool.submit(account['account'],account['worker_token'],work['lease'],work['start'])['status'],'verified')
        receipts=list(self.pool.receipts.values());self.assertEqual(sorted(r['fee_ppm'] for r in receipts),['0','10000'])
        weights=pplns(receipts,self.pool.journal.sequence,'f'*64,fee_policy=True)
        credit,fee=allocate_policy(10000,weights)
        self.assertEqual(credit[account['account']],9950);self.assertEqual(fee,50)
        self.assertEqual(sum(credit.values())+fee,10000)
        self.assertNotEqual(first['start'],second['start'])
        with self.assertRaisesRegex(Refused,'ceiling'):Operator(self.pool,0)

    def test_pause_is_serialized_and_does_not_hold_worker_lock(self):
        self.apply(payments_paused=False)
        entered=threading.Event();release=threading.Event();paused=threading.Event()
        def callback():entered.set();release.wait(3)
        worker=threading.Thread(target=lambda:self.operator.run('payments',callback));worker.start();self.assertTrue(entered.wait(1))
        self.assertTrue(self.pool.lock.acquire(timeout=.2));self.pool.lock.release()
        value=self.payload(payments_paused=True)
        def pause():self.operator.execute('settings',value,'operator:'+'a'*16);paused.set()
        thread=threading.Thread(target=pause);thread.start();self.assertFalse(paused.wait(.05));release.set();thread.join();worker.join()
        self.assertTrue(paused.is_set())
        self.operator.run('payments',lambda:self.fail('callback while paused'))

    def test_pause_keeps_signed_bytes_and_observes_confirmation_without_broadcast(self):
        self.pool.accounts={'a':{'address':'recipient-fixture'}}
        self.pool.incomes['fixture']={'id':'d'*64,'state':'available','txid':'b'*64,'height':1,'outputs':[{'vout':0,'units':'300000000'}],
                                      'credits':{'a':'300000000/1'}}
        self.apply(payments_paused=False)
        identity=self.pool.payments.plan(now=100000);raw=b'fixture bytes, not a signed transaction'
        txid=hashlib.sha256(hashlib.sha256(raw).digest()).hexdigest()
        self.pool.payments.record('payment_signed',dict(id=identity,txid=txid,signed_hex=raw.hex(),state='signed'))
        self.apply(payments_paused=True)
        self.assertEqual(self.pool.payments.reconcile(identity),'signed');self.assertEqual(self.pool.node.broadcasts,[])
        self.assertEqual(self.pool.payments.summary('a')['reserved_units'],'300000000')
        self.pool.node.confirmed=True;self.assertEqual(self.pool.payments.reconcile(identity),'confirmed')
        self.assertEqual(self.pool.payments.summary('a')['paid_units'],'300000000')
        self.assertEqual(self.pool.payments.intents[identity]['signed_hex'],raw.hex())

    def test_failed_audit_write_stops_new_payment_authority(self):
        self.apply(payments_paused=False)
        with patch.object(self.pool.journal,'append',side_effect=OSError('injected disk failure')):
            with self.assertRaises(OSError):self.apply(minimum_units='200000000')
        self.assertTrue(self.operator.faulted)
        with self.assertRaisesRegex(Refused,'journal failed'):self.pool.payments.plan(now=100000)
        with self.assertRaisesRegex(Refused,'journal failed'):self.operator.run('payments',lambda:self.fail('unsafe callback'))

    def test_queued_reconciliation_replays_after_restart_and_never_signs(self):
        request=dict(request_id='f'*32,revision='0',reason='Fixture canonical recheck')
        self.operator.execute('reconcile',request,'operator:'+'a'*16)
        self.restart()
        self.operator.reconcile()
        self.assertEqual(self.operator.snapshot()['audit'][0]['status'],'completed')
        self.assertEqual(self.pool.node.broadcasts,[]);self.assertEqual(self.pool.payments.intents,{})

    def test_operator_reconcile_does_not_submit_retained_block_solution(self):
        account=self.pool.register('x'*30)
        work=self.pool.work(account['account'],account['worker_token'],1)
        job=self.pool.leases[work['lease']]['job']
        self.pool.record('solution',dict(block='e'*64,height=201,job=job,nonce='0',cutoff=self.pool.journal.sequence))
        request=dict(request_id='e'*32,revision='0',reason='Read-only solution reconciliation')
        self.operator.execute('reconcile',request,'operator:'+'a'*16)
        with patch.object(self.pool.node,'renew',create=True) as renew,patch.object(self.pool.node,'submit',create=True) as submit:
            self.operator.reconcile()
            renew.assert_not_called();submit.assert_not_called()
            self.assertEqual(self.operator.snapshot()['audit'][0]['status'],'completed')
            # Normal mining maintenance retains its existing submission path.
            renew.return_value=self.pool.jobs[job]['node']
            self.pool.reconcile_solutions()
            renew.assert_called_once();submit.assert_called_once()

    def test_new_payout_threshold_and_frozen_batch_policy(self):
        self.pool.accounts={'a':{'address':'recipient-fixture'}}
        self.pool.incomes['fixture']={'id':'d'*64,'state':'available','txid':'b'*64,'height':1,'outputs':[{'vout':0,'units':'300000000'}],
                                      'credits':{'a':'300000000/1'}}
        self.apply(payments_paused=False,minimum_units='400000000')
        self.assertIsNone(self.pool.payments.plan(now=100000))
        self.pool.payments.record('payment_batch',dict(id='prior',created=100000,quotas={'a':'300000000'},minimum_units='100000000'))
        self.assertIsNotNone(self.pool.payments.plan(now=100000))
        self.assertEqual(self.pool.payments.deductions(),{'a':300000000})

    def test_comining_readiness_requires_real_manifest_funds_and_excludes_liabilities(self):
        from pool.identity import Identity
        journal=Journal(self.root/'identity',self.root/'identity-anchor/current.json')
        self.addCleanup(journal.close)
        fund=dict(txid='e'*64,vout='0',units='100001000000')
        self.pool.node.coins['pool']=[dict(txid=fund['txid'],vout=0,value_units=int(fund['units']),confirmations=200)]
        original=self.pool.node.call
        state=dict(height=200,parent='d'*64,stake_units='0',required_stake_units='100000000000',
                   fee_units='100000',dust_units='1000',staking_active=True,eligible=False)
        self.pool.node.call=lambda method,*args:state if method=='getpoolidentitystate' else original(method,*args)
        self.pool.identity=Identity(self.pool,journal,'not-invoked','no-live-key','fixture-script',[fund])
        self.apply(comining_paused=False)
        self.assertFalse(self.operator.settings['comining_paused']);self.assertEqual(self.pool.identity.intents,{})
        self.apply(comining_paused=True)
        self.pool.incomes['overlap']={'txid':fund['txid'],'outputs':[{'vout':0}]}
        with self.assertRaisesRegex(Refused,'liabilities'):self.apply(comining_paused=False)
        self.assertTrue(self.operator.settings['comining_paused'])

    def test_mixed_fee_allocations_match_independent_exact_reference(self):
        import random
        from fractions import Fraction
        rng=random.Random(45321)
        for _ in range(300):
            amount=rng.randrange(1,1<<60)
            weights={(str(i%3),i*100):Fraction(rng.randrange(1,1<<80),7) for i in range(1,rng.randrange(2,40))}
            credits,fee=allocate_policy(amount,weights);total=sum(weights.values());expected={}
            for (account,ppm),weight in weights.items():
                expected[account]=expected.get(account,Fraction())+Fraction(amount)*weight*(1000000-ppm)/(total*1000000)
            self.assertEqual(credits,expected);self.assertEqual(sum(credits.values())+fee,amount)

    def test_operator_records_bind_chain_and_persist_initial_pause(self):
        events=list(self.pool.journal.events())
        self.assertEqual(events[0]['kind'],'operator_initialized')
        self.assertEqual(events[0]['payload']['chain'],self.pool.node.genesis)
        self.pool.node.genesis='0'*64
        with self.assertRaisesRegex(Refused,'chain mismatch'):Operator(self.pool,10000)


if __name__=='__main__':unittest.main(verbosity=2)
