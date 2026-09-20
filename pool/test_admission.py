"""Focused failure injection only; native integration is qualified separately."""
import hashlib
import threading
import unittest
from types import SimpleNamespace
from pathlib import Path
import tempfile
from pool.journal import Journal
from pool.protocol import Busy, Refused
from pool.coordinator import template_identity

from pool.coordinator import Coordinator
from pool.accounting import pplns

class AdmissionTests(unittest.TestCase):
    def test_wide_address_requires_explicit_active_version_and_object_response(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);journal=Journal(root/'events',root/'anchor/current.json')
            response=[None]
            node=SimpleNamespace(check_chain=lambda:None,call=lambda *_:response[0],genesis='a'*64)
            pool=Coordinator(node,journal,None,'pool','f'*64)
            for value in [None,[],True,{'isvalid':True},{'isvalid':True,'destination_type':'sha384-v2','active_for_next_block':True},
                          {'isvalid':True,'destination_type':'sha384-v1','active_for_next_block':False}]:
                response[0]=value
                with self.assertRaises(Refused):pool.register('x'*73)
                self.assertEqual(pool.accounts,{})
            response[0]={'isvalid':True,'destination_type':'sha384-v1','active_for_next_block':True}
            self.assertIn(pool.register('x'*73)['account'],pool.accounts)
            journal.close()

    def test_worker_token_cannot_read_private_balance_or_payment_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);journal=Journal(root/'events',root/'anchor/current.json')
            node=SimpleNamespace(check_chain=lambda:None,call=lambda *_:{'isvalid':True},genesis='a'*64)
            pool=Coordinator(node,journal,None,'pool','f'*64)
            account=pool.register('x'*30)
            with self.assertRaises(Refused):pool.account(account['account'],account['worker_token'])
            with self.assertRaises(Refused):pool.history(account['account'],account['worker_token'])
            self.assertEqual(pool.history(account['account'],account['view_token']),{'payments':[],'next_before':0})
            health=pool.health()
            self.assertNotIn(account['account'],str(health))
            self.assertNotIn('x'*30,str(health))
            journal.close()

    def test_near_miss_outside_accounting_target_is_kept_without_share_credit(self):
        class Node:
            genesis='a'*64
            def check_chain(self):pass
            def template(self,_):return {'block_hex':'00'*92,'height':1,'target':'0'*63+'2',
                                         'prev_block_hash':'a'*64,'work_ttl_ms':10000}
            def call(self,method,*args):
                if method=='validateaddress':return {'isvalid':True}
                if method in ('getbestblockhash','getblockhash'):return 'a'*64
                raise AssertionError(method)
        verifier=SimpleNamespace(inspect=lambda *_:('0'*63+'8',template_identity(bytes(88)),'near_miss'))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);journal=Journal(root/'events',root/'anchor/current.json')
            pool=Coordinator(Node(),journal,verifier,'pool','0'*63+'1')
            account=pool.register('x'*30)
            work=pool.work(account['account'],account['worker_token'],1)
            # Harder configured targets cannot drop a full block solution.
            self.assertEqual(work['target'],'0'*63+'2')
            result=pool.submit(account['account'],account['worker_token'],work['lease'],'0000000000000000')
            self.assertEqual(result,{'status':'near_miss'})
            proof=next(iter(pool.receipts.values()))
            self.assertEqual(proof['proof_kind'],'near_miss')
            self.assertEqual(pplns(pool.receipts.values(),proof['seq'],work['target']),{})
            self.assertEqual(pool.submit(account['account'],account['worker_token'],work['lease'],'0000000000000000')['status'],'duplicate')
            journal.close()

    def test_failed_receipt_commit_releases_verification_slot(self):
        pool=object.__new__(Coordinator)
        pool.lock=threading.RLock();pool.admission=threading.BoundedSemaphore(1)
        pool.inflight=set();pool.receipts={}
        pool.queue_capacity=1;pool.unverified_count=0
        token='a'*64
        pool.accounts={'a':{'worker_hash':hashlib.sha256(token.encode()).hexdigest()}}
        pool.leases={'l':{'account':'a','job':'j','template':'t','start':'0','end':'1'}}
        pool.jobs={'j':{'template':'t','height':1,'target':'f'*64,'node':{'prev_block_hash':'d'}}}
        pool.node=SimpleNamespace(call=lambda *_:'d')
        def fail(*_):raise OSError('injected disk write failure')
        pool.record=fail
        with self.assertRaises(OSError):pool.submit('a',token,'l','0000000000000000')
        self.assertEqual(pool.inflight,set())
        self.assertTrue(pool.admission.acquire(blocking=False))

    def test_disconnected_worker_receipt_is_retried_without_becoming_false_invalid(self):
        class Node:
            genesis='a'*64
            height=0
            def check_chain(self):pass
            def template(self,_):return {'block_hex':'00'*92,'height':1,'target':'0'*63+'1',
                                         'prev_block_hash':'a'*64,'work_ttl_ms':10000}
            def call(self,method,*args):
                if method=='validateaddress':return {'isvalid':True}
                if method=='getbestblockhash':return ('a' if self.height==0 else 'b')*64
                if method=='getblockhash':return 'a'*64
                raise AssertionError(method)
        class Verifier:
            calls=0
            def inspect(self,*_):
                self.calls+=1
                if self.calls==1:raise Busy('injected temporary resource failure')
                return '0'*63+'2',template_identity(bytes(88)),'none'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);journal=Journal(root/'events',root/'anchor/current.json')
            node=Node();verifier=Verifier();pool=Coordinator(node,journal,verifier,'pool','f'*64)
            account=pool.register('x'*30)
            work=pool.work(account['account'],account['worker_token'],1)
            with self.assertRaises(Busy):pool.submit(account['account'],account['worker_token'],work['lease'],'0000000000000000')
            self.assertEqual(next(iter(pool.receipts.values()))['status'],'deferred')
            node.height=1 # Another block arrives while this timely receipt waits.
            self.assertEqual(pool.retry_deferred(),{'status':'verified'})
            self.assertEqual(pool.submit(account['account'],account['worker_token'],work['lease'],'0000000000000000')['status'],'duplicate')
            self.assertEqual(verifier.calls,2)
            journal.close()

    def test_durable_deferred_backlog_is_bounded_and_recovers_after_restart(self):
        class Node:
            genesis='a'*64
            def check_chain(self):pass
            def template(self,_):return {'block_hex':'00'*92,'height':1,'target':'0'*63+'1',
                                         'prev_block_hash':'a'*64,'work_ttl_ms':10000}
            def call(self,method,*args):
                if method=='validateaddress':return {'isvalid':True}
                if method in ('getbestblockhash','getblockhash'):return 'a'*64
                raise AssertionError(method)
        class Verifier:
            busy=True
            def inspect(self,*_):
                if self.busy:raise Busy('injected unavailable native verifier')
                return '0'*63+'2',template_identity(bytes(88)),'none'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);journal=Journal(root/'events',root/'anchor/current.json')
            verifier=Verifier();pool=Coordinator(Node(),journal,verifier,'pool','f'*64,capacity=2)
            account=pool.register('x'*30);work=pool.work(account['account'],account['worker_token'],3)
            for n in range(2):
                with self.assertRaises(Busy):pool.submit(account['account'],account['worker_token'],work['lease'],f'{n:016x}')
            sequence=journal.sequence
            for _ in range(20):
                with self.assertRaisesRegex(Busy,'backlog full'):
                    pool.submit(account['account'],account['worker_token'],work['lease'],'0000000000000002')
            self.assertEqual(journal.sequence,sequence);self.assertEqual(len(pool.receipts),2)
            journal.close();journal=Journal(root/'events',root/'anchor/current.json')
            pool=Coordinator(Node(),journal,verifier,'pool','f'*64,capacity=2)
            self.assertEqual(pool.health()['verification_queue'],{'waiting':2,'capacity':2})
            verifier.busy=False
            self.assertEqual(pool.retry_deferred(),{'status':'verified'})
            self.assertEqual(pool.submit(account['account'],account['worker_token'],work['lease'],'0000000000000002'),{'status':'verified'})
            self.assertEqual(pool.unverified_count,1)
            pool.retry_deferred();self.assertEqual(pool.unverified_count,0)
            self.assertEqual(pool.verified_counts[account['account']],3);journal.close()

    def test_accepted_block_is_recovered_after_crash_before_earned_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);journal=Journal(root/'events',root/'anchor/current.json')
            journal.append('solution',{'block':'b'*64,'height':10,'job':'j','cutoff':3,'receipt':'r','nonce':'4'})
            journal.close()
            journal=Journal(root/'events',root/'anchor/current.json')
            node=SimpleNamespace(check_chain=lambda:None,call=lambda method,*_:10 if method=='getblockcount' else 'b'*64)
            pool=Coordinator(node,journal,None,'pool','f'*64)
            pool.reconcile_solutions();pool.reconcile_solutions()
            earned=[e for e in journal.events() if e['kind']=='earned']
            self.assertEqual(len(earned),1)
            self.assertEqual(earned[0]['payload']['cutoff'],3)
            journal.close()

    def test_deferred_solution_renews_exact_candidate_and_keeps_nonce(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);journal=Journal(root/'events',root/'anchor/current.json')
            calls=[];height=[9]
            def rpc(method,*args):return height[0] if method=='getblockcount' else 'b'*64
            def renew(template,address):
                calls.append(('renew',dict(template),address));return dict(template,work_token='fresh')
            def submit(template,nonce):
                calls.append(('submit',dict(template),nonce));height[0]=10;return {'accepted':True}
            node=SimpleNamespace(check_chain=lambda:None,call=rpc,renew=renew,submit=submit)
            pool=Coordinator(node,journal,None,'pool','f'*64)
            pool.record('job',{'id':'j','height':10,'node':{'work_token':'expired','block_hex':'00'}})
            pool.record('solution',{'block':'b'*64,'height':10,'job':'j','cutoff':3,'receipt':'r','nonce':'4'})
            pool.reconcile_solutions();pool.reconcile_solutions()
            self.assertEqual(calls[1],('submit',{'work_token':'fresh','block_hex':'00'},4))
            self.assertEqual(pool.jobs['j']['node']['block_hex'],'00')
            self.assertEqual(len(pool.earnings),1);journal.close()

if __name__=='__main__':unittest.main()
