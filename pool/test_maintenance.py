"""Secondary indexing must not starve existing payments; canonical checks must."""
import threading
from types import SimpleNamespace
import unittest
import os
if os.name!='posix':
    raise unittest.SkipTest('Linux coordinator service; required and executed in Linux qualification')
from pool.service import maintain_once
from pool.protocol import Busy

class MaintenanceTests(unittest.TestCase):
    def exercise(self,failed):
        calls=[]
        def action(name,result=None):
            def run(*_):
                calls.append(name)
                if name in failed:raise Busy('injected temporary failure')
                return result
            return run
        pool=SimpleNamespace(lock=threading.RLock(),retry_deferred=action('work'),reconcile_solutions=action('solutions'),
            rewards=SimpleNamespace(reconcile=action('rewards')),reconcile_income=action('income'),identity=None,
            payments=SimpleNamespace(intents={'old':{}},sign=action('sign'),reconcile=action('reconcile'),plan=action('plan','new')))
        maintain_once(pool,SimpleNamespace(check_chain=action('chain')),threading.Event())
        return calls,pool
    def test_rebuilding_reward_index_does_not_stop_safe_existing_payouts(self):
        calls,pool=self.exercise({'rewards'})
        self.assertEqual(calls.count('sign'),2);self.assertIn('plan',calls)
        self.assertEqual(pool.deferred_phases,['reward reconciliation'])
    def test_canonical_income_failure_stops_all_payment_signing(self):
        calls,_=self.exercise({'income'});self.assertNotIn('sign',calls);self.assertNotIn('plan',calls)
    def test_wrong_or_unavailable_chain_prevents_all_subsequent_work(self):
        calls,_=self.exercise({'chain'});self.assertEqual(calls,['chain'])

if __name__=='__main__':unittest.main()
