"""Display-only projections: exact arithmetic, replay, reorg and privacy tests.

Fixture events, never evidence of mining or funded payments on any network.
"""
import copy
import hashlib
import json
from fractions import Fraction
from types import SimpleNamespace
from pathlib import Path
import tempfile
import unittest
from pool.overview import IncomeOverview, PaymentOverview, WorkOverview
from pool.public_status import overview
from pool.protocol import Refused
from pool.coordinator import Coordinator
from pool.journal import Journal

def income(n=1,state='pending',amount='100000001',category='mining'):
    return dict(id=f'{n:064x}',height=n,amount=amount,category=category,state=state,credits={})

class OverviewTests(unittest.TestCase):
    def test_production_packaging_includes_attested_metrics_module(self):
        root=Path(__file__).resolve().parents[1]
        controller=root/'build/mainnet-v2-pool.sh'
        self.assertIn(' operator overview payments ',controller.read_text())
        rows=(root/'vendor/pqc/provenance/PQC_PROVENANCE.tsv').read_text().splitlines()
        row=next(line.split('\t') for line in rows if line.endswith('\tbuild/mainnet-v2-pool.sh'))
        self.assertEqual(row[0],hashlib.sha256(controller.read_bytes()).hexdigest())

    def test_income_maturity_reorg_reconfirmation_idempotency(self):
        p=IncomeOverview();a=income();p.update(None,a)
        b=dict(a,state='available');p.update(a,b);p.update(b,b)
        self.assertEqual(p.snapshot(125)['reward_totals']['mining'],'100000001')
        self.assertEqual(p.snapshot(125)['blocks_won'],'1')
        self.assertEqual(p.snapshot(125)['recent_blocks'][0]['confirmations'],'125')
        c=dict(b,state='orphaned');p.update(b,c)
        self.assertEqual(p.snapshot(126)['reward_totals']['mining'],'0')
        self.assertEqual(p.snapshot(126)['blocks_won'],'0')
        self.assertEqual(p.snapshot(126)['recent_blocks'][0]['confirmations'],'0')
        p.update(c,b);self.assertEqual(p.totals['mining'],100000001)

    def test_recent_bound_and_separate_income_categories(self):
        p=IncomeOverview()
        for n in range(1,101):p.update(None,income(n))
        for n,category in enumerate(['comine_payout','staking_distribution','operator_principal'],101):p.update(None,income(n,category=category))
        s=p.snapshot(105);self.assertEqual(len(s['recent_blocks']),12)
        self.assertEqual([int(r['height']) for r in s['recent_blocks']],list(range(100,88,-1)))
        self.assertEqual(s['blocks_won'],'100');self.assertEqual(len(s['reward_totals']),3)
        self.assertEqual(s['reward_totals']['staking_distribution'],'100000001')
        self.assertNotIn('credits',json.dumps(s));self.assertNotIn('operator_principal',json.dumps(s))

    def test_payment_counts_confirmed_deductions_only(self):
        p=PaymentOverview();a={'state':'reserved','deductions':{'private-a':'123','private-b':'456'}}
        p.update(None,a);self.assertEqual(p.snapshot(),dict(paid_units='0',confirmed_transactions='0'))
        b=dict(a,state='signed');p.update(a,b);self.assertEqual(p.paid,0)
        c=dict(b,state='confirmed');p.update(b,c);p.update(c,c)
        self.assertEqual(p.snapshot(),dict(paid_units='579',confirmed_transactions='1'))
        p.update(c,b);self.assertEqual(p.paid,0);p.update(b,c);self.assertEqual(p.paid,579)
        self.assertNotIn('private',json.dumps(p.snapshot()))

    def test_rate_independent_exact_reference_different_targets(self):
        clock=[0.0];p=WorkOverview(lambda:clock[0]);targets=[1<<240,(1<<245)+17,1<<250]
        for target in targets:p.add(f'{target:064x}')
        self.assertIsNone(p.snapshot()['hashrate_hs'])
        clock[0]=60.0;s=p.snapshot()
        reference=sum((Fraction(1<<256,t) for t in targets),Fraction())/60
        self.assertEqual(int(s['hashrate_hs']),reference.numerator//reference.denominator)
        self.assertEqual(s['sample_shares'],'3');self.assertFalse(s['warming_up'])
        clock[0]=601.0;self.assertEqual(p.snapshot()['hashrate_hs'],'0');self.assertEqual(p.snapshot()['sample_shares'],'0')
        self.assertIsNone(WorkOverview(lambda:clock[0]).snapshot()['hashrate_hs'])

    def test_rate_bounded_buckets_and_partial_expiration(self):
        clock=[0.0];p=WorkOverview(lambda:clock[0])
        for i in range(10000):
            clock[0]=float(i);p.add('f'*64)
            self.assertLessEqual(len(p.bins),61)
        self.assertLessEqual(int(p.snapshot()['sample_shares']),601)
        self.assertEqual(p.snapshot()['window_seconds'],'600')

    def test_coordinator_replay_totals_and_no_replay_hashrate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);j=Journal(root/'data',root/'anchor/current.json')
            try:
                node=SimpleNamespace(check_chain=lambda:None,genesis='a'*64)
                p=Coordinator(node,j,None,'pool','f'*64)
                p.record('income',income());p.record('income_state',dict(id=f'{1:064x}',state='available'))
                p.record('income',income(2,category='comine_payout'));p.record('income_state',dict(id=f'{2:064x}',state='orphaned'))
                # Duplicate verification events do not multiply current rate samples.
                p.record('receipt',dict(identity='r',account='account',target='f'*64,height=1))
                for _ in range(2):p.record('verification',dict(identity='r',status='verified'))
                self.assertEqual(p.public_work.snapshot()['sample_shares'],'1')
                p.income_tip=(130,'b'*64);expected=p.health()['overview']
                q=Coordinator(node,j,None,'pool','f'*64);q.income_tip=p.income_tip;actual=q.health()['overview']
                for k in ['blocks_won','reward_totals','recent_blocks']:self.assertEqual(actual[k],expected[k])
                self.assertEqual(actual['work']['sample_shares'],'0');self.assertIsNone(actual['work']['hashrate_hs'])
            finally:j.close()

    def test_public_allowlist_and_malformed_nested_shapes(self):
        p=IncomeOverview();p.update(None,income())
        value={'version':1,**p.snapshot(4),'work':WorkOverview().snapshot(),'payments':PaymentOverview().snapshot()}
        value['secret']='do-not-forward';value['work']['endpoint']='do-not-forward';value['recent_blocks'][0]['credits']={'private':'secret'}
        wire=json.dumps(overview(value));self.assertNotIn('secret',wire);self.assertNotIn('private',wire);self.assertNotIn('do-not-forward',wire)
        for path,bad in [(('version',),True),(('work','window_seconds'),'601'),(('payments','paid_units'),'-1'),(('work','sample_shares'),True),(('reward_totals','mining'),'9'*81),(('recent_blocks',),[value['recent_blocks'][0]]*13)]:
            copy_value=copy.deepcopy(value);dest=copy_value
            for k in path[:-1]:dest=dest[k]
            dest[path[-1]]=bad
            with self.assertRaises(Refused):overview(copy_value)

if __name__=='__main__':unittest.main()
