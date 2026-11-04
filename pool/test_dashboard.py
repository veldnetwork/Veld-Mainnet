"""Dashboard/API regression fixtures. Not native mining or payment E2E."""
import hashlib
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest

from pool.coordinator import Coordinator
from pool.journal import Journal
from pool.protocol import Refused

class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();root=Path(self.tmp.name)
        self.journal=Journal(root/'data',root/'anchor/current.json')
        self.node=SimpleNamespace(check_chain=lambda:None,genesis='a'*64,call=lambda *_:{'isvalid':True})
        self.pool=Coordinator(self.node,self.journal,None,'pool','f'*64)
        self.a=self.pool.register('V'+'a'*33);self.b=self.pool.register('V'+'b'*33)
    def tearDown(self):self.journal.close();self.tmp.cleanup()
    def test_public_health_has_no_account_or_payment_credentials(self):
        self.pool.income_tip=(9001,'b'*64)
        self.pool.active_accounts={self.a['account']:time.monotonic(),self.b['account']:time.monotonic()-121}
        self.pool.verified_counts={self.a['account']:3,self.b['account']:7}
        value=self.pool.health()
        self.assertEqual((value['active_accounts'],value['verified_shares'],value['reconciled_height']),('1','10','9001'))
        text=json.dumps(value)
        for account in (self.a,self.b):
            for key in ('account','worker_token','view_token'):self.assertNotIn(account[key],text)
        self.assertFalse(value['payments_enabled']);self.assertFalse(value['co_mining_enabled'])
    def test_rewards_are_private_and_use_only_canonical_earned_income(self):
        for i,(category,state) in enumerate([('mining','available'),('comine_payout','pending'),('staking_distribution','pending'),('mining','orphaned')]):
            self.pool.record('income',{'id':str(i),'height':i,'category':category,'state':state,
                'credits':{self.a['account']:'100000001/1',self.b['account']:'199999999/1'}})
        with self.assertRaises(Refused):self.pool.account(self.a['account'],self.a['worker_token'])
        with self.assertRaises(Refused):self.pool.account(self.a['account'],self.b['view_token'])
        result=self.pool.account(self.a['account'],self.a['view_token'])
        self.assertEqual(result['reward_totals'],dict(mining='100000001',comine_payout='100000001',staking_distribution='100000001'))
        self.assertEqual(result['pending_units'],'200000002');self.assertEqual(result['available_units'],'100000001')
        self.assertNotIn(self.b['account'],json.dumps(result))
    def test_restart_does_not_invent_active_workers(self):
        self.pool.active_accounts[self.a['account']]=time.monotonic()
        restarted=Coordinator(self.node,self.journal,None,'pool','f'*64)
        self.assertEqual(restarted.health()['active_accounts'],'0')
        self.assertEqual(restarted.account(self.a['account'],self.a['view_token'])['pending_units'],'0')

if __name__=='__main__':unittest.main()
