"""Focused operator-liability/lifecycle fixtures; native path is separate."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from pool.identity import Identity
from pool.journal import Journal
from pool.protocol import Refused

class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();root=Path(self.tmp.name)
        self.journal=Journal(root/'identity',root/'anchor/current.json')
        self.coin={'txid':'a'*64,'vout':0,'value_units':100000000100,'confirmations':120}
        self.coins=[self.coin];self.txs={};self.raw=[];self.outputs=[]
        self.state={'height':3200,'parent':'b'*64,'stake_units':'0','required_stake_units':'100000000000',
                    'staking_active':True,'eligible':False,'needs_submission':True,'pending_submission':False,
                    'fee_units':'100000','dust_units':'1000'}
        self.node=SimpleNamespace(genesis='c'*64,call=self.call)
        import threading
        self.pool=SimpleNamespace(node=self.node,pool_address='pool',incomes={},receipts={},jobs={},leases={},lock=threading.RLock())
        self.funding=[{'txid':'a'*64,'vout':'0','units':str(self.coin['value_units'])}]
        self.identity=Identity(self.pool,self.journal,'native-identity','seed','script',self.funding)
    def tearDown(self):self.journal.close();self.tmp.cleanup()
    def call(self,method,*args):
        if method=='listunspent':return self.coins
        if method=='getpoolidentitystate':return self.state
        if method in ('gettransaction','gettransactionrecent'):
            if args[0] not in self.txs:raise Refused('not included')
            return self.txs[args[0]]
        if method=='getblockhash':return self.state['parent']
        if method=='sendrawtransaction':
            self.raw.append(args[0]);return hashlib.sha256(hashlib.sha256(bytes.fromhex(args[0])).digest()).hexdigest()
        raise AssertionError(method)

    def test_shared_income_is_not_operator_fee_or_stake_funding(self):
        self.pool.incomes['block']={'txid':'a'*64,'outputs':[{'vout':0}]}
        with self.assertRaisesRegex(Refused,'liabilities'):self.identity.allowed()

    def test_unlisted_coins_and_active_principal_are_never_selected(self):
        self.coins.append({'txid':'d'*64,'vout':0,'value_units':999999999999})
        self.assertEqual(self.identity.allowed(),self.funding)
        self.identity.intents['stake']={'state':'confirmed','txid':'e'*64,'block':'b'*64,
            'wire':{'action':'stake','inputs':self.funding}}
        self.txs['e'*64]={'block_hash':'b'*64,'vout':[
            {'n':0,'script_pubkey':'script','value_units':'100000000000'},
            {'n':1,'script_pubkey':'script','value_units':'1234567'}]}
        self.coins=[{'txid':'e'*64,'vout':0,'value_units':100000000000},
                    {'txid':'e'*64,'vout':1,'value_units':1234567}]
        self.assertEqual(self.identity.allowed(),[{'txid':'e'*64,'vout':'1','units':'1234567'}])

    def test_funding_policy_cannot_silently_change_after_restart(self):
        changed=[dict(self.funding[0],units='1')]
        with self.assertRaisesRegex(Refused,'policy changed'):
            Identity(self.pool,self.journal,'native','seed','script',changed)

    def test_signed_bytes_reserved_before_broadcast_and_identical_retry(self):
        raw=b'focused-fixture';txid=hashlib.sha256(hashlib.sha256(raw).digest()).hexdigest()
        intent={'id':'i','state':'reserved','parent':'b'*64,'wire':{'action':'consolidate','inputs':self.funding}}
        self.identity.record('identity_intent',intent)
        result=SimpleNamespace(returncode=0,stdout=(txid+' '+raw.hex()).encode())
        with patch('pool.identity.subprocess.run',return_value=result) as signer:
            self.identity.sign(intent);self.identity.sign(intent)
            self.assertEqual(signer.call_count,1)
        self.assertEqual(self.identity.allowed(),[])
        restored=Identity(self.pool,self.journal,'native-identity','seed','script',self.funding)
        restored.reconcile(self.state);restored.reconcile(self.state)
        self.assertEqual(self.raw,[raw.hex(),raw.hex()])

    def test_included_entry_and_pending_entry_do_not_sign_another(self):
        self.state.update(stake_units='100000000000',eligible=True,needs_submission=False)
        with patch.object(self.identity,'sign',side_effect=AssertionError('unexpected signature')):
            self.identity.maintain()
            self.state.update(needs_submission=True,pending_submission=True)
            self.identity.maintain()
        self.assertEqual(self.identity.intents,{})

    def test_expired_near_miss_not_broadcast_on_wrong_parent(self):
        intent={'id':'i','state':'signed','txid':'e'*64,'signed_hex':'ff','parent':'0'*64,
                'wire':{'action':'nms','height':'3201','inputs':self.funding}}
        self.identity.record('identity_intent',intent)
        self.identity.reconcile(self.state)
        self.assertEqual(intent['state'],'expired');self.assertEqual(self.raw,[])

    def test_slow_identity_lookup_does_not_hold_worker_lock(self):
        import threading
        waiting=threading.Event();release=threading.Event()
        self.state.update(stake_units='100000000000',eligible=True,needs_submission=False)
        original=self.node.call
        def delayed(method,*args):
            if method=='getpoolidentitystate':waiting.set();release.wait(5)
            return original(method,*args)
        self.node.call=delayed
        worker=threading.Thread(target=self.identity.maintain);worker.start()
        try:
            self.assertTrue(waiting.wait(2))
            acquired=self.pool.lock.acquire(timeout=.1)
            self.assertTrue(acquired,'identity lookup blocked worker accounting')
            if acquired:self.pool.lock.release()
        finally:release.set();worker.join(5)
        self.assertFalse(worker.is_alive())

if __name__=='__main__':unittest.main()
