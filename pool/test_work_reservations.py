"""Durability, ownership and bounded-cost tests; no production node or miner."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from pool.coordinator import Coordinator
from pool.journal import Journal
from pool.protocol import Busy, Refused

class Node:
    genesis='a'*64
    def check_chain(self):pass
    def call(self,method,*args):
        if method=='validateaddress':return {'isvalid':True}
        raise AssertionError(method)
    def template(self,_):
        return {'block_hex':'00'*92,'height':1,'target':'f'*64,'work_ttl_ms':10000}

class Reservations(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.j=Journal(self.root/'data',self.root/'anchor/current.json')
        self.pool=Coordinator(Node(),self.j,None,'pool','f'*64)
        self.a=self.pool.register('x'*30);self.b=self.pool.register('y'*30)
    def tearDown(self):self.j.close();self.tmp.cleanup()
    def work(self,account=None,count=1024):
        a=account or self.a
        return self.pool.work(a['account'],a['worker_token'],count)
    def test_every_returned_range_is_exactly_durable_and_disjoint(self):
        with ThreadPoolExecutor(max_workers=12) as ex:work=list(ex.map(lambda i:self.work(self.a if i%2 else self.b,512 if i%3 else 1024),range(96)))
        records={e['payload']['id']:e['payload'] for e in self.j.events() if e['kind']=='lease'}
        intervals=[]
        for w in work:
            p=records[w['lease']];start=int(w['start'],16);end=start+int(w['count'])
            self.assertEqual((int(p['start']),int(p['end'])),(start,end));intervals.append((start,end))
        intervals.sort();self.assertTrue(all(a[1]<=b[0] for a,b in zip(intervals,intervals[1:])))
        marker=json.loads(self.j.anchor.read_text());self.assertEqual(marker['seq'],self.j.sequence)
    def test_cached_delivery_does_not_write_and_authentication_is_repeated(self):
        self.work();seq=self.j.sequence
        with patch.object(self.j,'append_many',side_effect=AssertionError('unexpected durable write')):
            self.work();self.assertEqual(self.j.sequence,seq)
            with self.assertRaises(Refused):self.pool.work(self.a['account'],self.b['worker_token'],1024)
    def test_cross_account_submission_is_refused_before_verifier(self):
        w=self.work()
        with self.assertRaisesRegex(Refused,'lease authorization'):
            self.pool.submit(self.b['account'],self.b['worker_token'],w['lease'],w['start'])
    def test_count_change_keeps_exact_nonoverlapping_reservations(self):
        a=self.work(count=1);b=self.work(count=4096);c=self.work(count=1)
        for w in (a,b,c):self.assertEqual(int(self.pool.leases[w['lease']]['end'])-int(w['start'],16),int(w['count']))
        self.assertLess(int(c['start'],16),int(b['start'],16))
        self.assertNotEqual(a['lease'],c['lease'])
    def test_template_alias_and_restart_abandon_unused_ranges(self):
        one=self.work();first_end=int(self.pool.highwater[self.pool.jobs[self.pool.active[0]]['template']]['end'])
        self.pool.active=None;two=self.work()
        self.assertGreaterEqual(int(two['start'],16),first_end)
        high=int(self.pool.highwater[self.pool.jobs[self.pool.active[0]]['template']]['end'])
        self.j.close();self.j=Journal(self.root/'data',self.root/'anchor/current.json')
        self.pool=Coordinator(Node(),self.j,None,'pool','f'*64)
        three=self.work();self.assertGreaterEqual(int(three['start'],16),high)
        self.assertEqual(len({one['lease'],two['lease'],three['lease']}),3)
    def test_nonce_end_boundary_reserves_only_remaining_valid_ranges(self):
        self.work();job=self.pool.jobs[self.pool.active[0]];self.pool.lease_reserve.clear()
        self.pool.record('lease',{'id':'end-fixture','account':self.a['account'],'job':job['id'],'template':job['template'],'start':'8192','end':str((1<<64)-3)})
        w=self.work(count=2);self.assertEqual(int(w['start'],16),(1<<64)-3)
        with self.assertRaisesRegex(Refused,'nonce space'):self.work(count=2)
        w=self.work(count=1);self.assertEqual(int(w['start'],16),(1<<64)-1)
    def test_reserve_memory_is_bounded_and_eviction_never_reissues(self):
        for count in range(1,81):self.work(count=count)
        self.assertLessEqual(len(self.pool.lease_reserve),64)
        high=int(self.pool.highwater[self.pool.jobs[self.pool.active[0]]['template']]['end'])
        w=self.work(count=1);self.assertGreaterEqual(int(w['start'],16),high)
    def test_closed_journal_refuses_cached_leases(self):
        self.work();self.j.close()
        # Authentication consults the same closed index before delivery.
        with self.assertRaises(RuntimeError):self.work()
    def test_slow_commit_does_not_publish_expired_work(self):
        self.work();self.pool.lease_reserve.clear()
        original=self.j.append_many
        def commit(entries):
            result=original(entries);self.pool.active=(self.pool.active[0],time.monotonic()-1);return result
        with patch.object(self.j,'append_many',side_effect=commit):
            with self.assertRaisesRegex(Busy,'expired'):self.work()
    def test_partial_projection_failure_closes_and_restart_never_reissues(self):
        self.work();self.pool.lease_reserve.clear();original=self.pool.apply;calls=[0]
        def fail(kind,value,seq):
            calls[0]+=1
            if calls[0]==3:raise OSError('injected projection failure')
            return original(kind,value,seq)
        with patch.object(self.pool,'apply',side_effect=fail):
            with self.assertRaises(OSError):self.work()
        self.assertIsNone(self.j.db)
        with self.assertRaises(RuntimeError):self.work()
        self.j=Journal(self.root/'data',self.root/'anchor/current.json')
        reserved=max(int(e['payload']['end']) for e in self.j.events() if e['kind']=='lease')
        self.pool=Coordinator(Node(),self.j,None,'pool','f'*64)
        self.assertGreaterEqual(int(self.work()['start'],16),reserved)

class JournalGroups(unittest.TestCase):
    def test_group_is_old_format_and_uses_one_durability_barrier_set(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);j=Journal(root/'data',root/'anchor/current.json');sync=os.fsync
            try:
                with patch('pool.journal.os.fsync',wraps=sync) as spy:
                    seq=j.append_many([('lease',{'end':str(i)}) for i in range(1,9)])
                self.assertEqual(seq,list(range(1,9)));self.assertEqual(spy.call_count,3 if os.name=='posix' else 2)
                self.assertEqual([e['seq'] for e in j.events()],seq)
                self.assertEqual(json.loads(j.anchor.read_text())['seq'],8)
            finally:j.close()
            j=Journal(root/'data',root/'anchor/current.json');self.assertEqual(j.sequence,8);j.close()
    def test_each_explicit_flush_failure_poison_closes_without_success(self):
        for fail_at in range(1,4 if os.name=='posix' else 3):
            with self.subTest(fail_at=fail_at),tempfile.TemporaryDirectory() as d:
                root=Path(d);j=Journal(root/'data',root/'anchor/current.json');real=os.fsync;calls=[0]
                def fail(fd):
                    calls[0]+=1
                    if calls[0]==fail_at:raise OSError('injected flush failure')
                    return real(fd)
                with patch('pool.journal.os.fsync',side_effect=fail):
                    with self.assertRaises(OSError):j.append_many([('lease',{'end':str(i)}) for i in range(8)])
                self.assertIsNone(j.db);self.assertIsNone(j.log)
                with self.assertRaises(RuntimeError):j.append('lease',{'end':'0'})
                # Complete journal bytes are authoritative even when no response
                # was delivered and the marker still points to an older prefix.
                j=Journal(root/'data',root/'anchor/current.json');self.assertEqual(j.sequence,8);j.close()
    def test_bad_later_member_never_writes_first_member(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);j=Journal(root/'data',root/'anchor/current.json')
            try:
                with self.assertRaises(ValueError):j.append_many([('lease',{}),('lease',{'bad':float('nan')})])
                self.assertEqual(j.sequence,0);self.assertEqual((root/'data/events.jsonl').read_bytes(),b'')
                with self.assertRaises(Refused):j.append_many([('lease',{})]*9)
            finally:j.close()

if __name__=='__main__':unittest.main()
