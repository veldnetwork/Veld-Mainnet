"""Failure-injection tests for the checkpoint signing/publication boundary."""
from pathlib import Path
import base64
import copy
import json
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/checkpoints'))
from policy import GENESIS, append_only, bind_candidate, candidate_height, encode, parse, qualify, sha
from publisher import Publisher
from remote_store import Store, atomic_json, atomic_write

FIXTURE = parse((ROOT/'tests/fixtures/mainnet-checkpoint.json').read_bytes())[0]
SIGNED_TIME = int(time.time())


def record(height=4000):
    return dict(FIXTURE,height=height,hash='a'*64,signed_at=SIGNED_TIME)


def observations(tip=4163):
    return [dict(host=host,unix_time=time.time(),genesis=GENESIS,height=tip,tip='b'*64,
        ibd_complete=True,historical_validated=True,active=True,uptime_seconds=1000,pid_unchanged=True,
        clock_synchronized=True,fresh_outbound=2,matching_outbound=2,state_height=tip,state_tip='b'*64,state_digest='c'*64,
        hashes={'2800':FIXTURE['hash'],'4000':'a'*64}) for host in ('n2','n3','n4')]


class PolicyTests(unittest.TestCase):
    def test_interval_stays_beyond_reorganization_limit(self):
        self.assertEqual(candidate_height(4119),3900)
        self.assertEqual(candidate_height(4120),4000)
        self.assertEqual(candidate_height(4163),4000)
        with self.assertRaises(ValueError): bind_candidate(4100,'a'*64,observations())

    def test_rejects_noncanonical_feed_shapes(self):
        for value in ([],None,{},[dict(FIXTURE,height=True)],[dict(FIXTURE,signed_at=True)],
                      [dict(FIXTURE,signed_at=int(time.time())+1000)], [dict(FIXTURE,hash='A'*64)],
                      [dict(FIXTURE,sig='00')],[dict(FIXTURE,extra=1)],[FIXTURE,FIXTURE]):
            with self.subTest(value_type=type(value).__name__),self.assertRaises(ValueError): parse(json.dumps(value).encode())
        with self.assertRaises(ValueError): parse(b'{"checkpoints":[],"checkpoints":[]}')

    def test_accepts_legacy_envelope_without_dropping_records(self):
        self.assertEqual(parse(json.dumps({'checkpoints':[FIXTURE]}).encode()),[FIXTURE])

    def test_rejects_history_replacement_or_removal(self):
        for after in ([record()],[dict(FIXTURE,hash='d'*64),record()],[FIXTURE]):
            with self.assertRaises(ValueError): append_only([FIXTURE],after)

    def test_fleet_failure_modes(self):
        changes = [('unix_time',time.time()-120),('genesis','0'*64),('ibd_complete',False),
            ('historical_validated',False),('uptime_seconds',90),('active',False),('pid_unchanged',False),
            ('clock_synchronized',False),('fresh_outbound',1),('matching_outbound',1),
            ('state_height',4162),('state_tip','d'*64),('state_digest','e'*64)]
        for key,value in changes:
            rows=observations(); rows[0][key]=value
            with self.subTest(field=key),self.assertRaises(ValueError): qualify(rows,[2800])
        with self.assertRaises(ValueError): qualify(observations()[:2])

    def test_historical_hash_disagreement(self):
        rows=observations(); rows[1]['hashes']['4000']='f'*64
        with self.assertRaises(ValueError): bind_candidate(4000,'a'*64,rows)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.feed=self.root/'checkpoints.json'; self.before=encode([FIXTURE]); self.feed.write_bytes(self.before)
        def verifier(raw):
            if any(cp['sig']=='0'*6618 for cp in parse(raw)): raise ValueError('Signature rejected by verifier')
        self.store=Store(dict(feed=str(self.feed),state=str(self.root/'state')),verifier)

    def tearDown(self): self.temp.cleanup()

    def install(self, transaction='a'*32, new=None, base=None):
        return self.store.install(dict(transaction=transaction,base_sha256=base or sha(self.before),document_b64=base64.b64encode(new or encode([FIXTURE,record()])).decode()))

    def test_publication_commit_and_health(self):
        self.install(); self.store.finish('a'*32,True); self.store.checked(4163)
        self.assertTrue(self.store.health()['healthy'])
        self.assertEqual(parse(self.feed.read_bytes()),[FIXTURE,record()])

    def test_changed_origin_refuses_install(self):
        with self.assertRaises(ValueError): self.install(base='f'*64)
        self.assertEqual(self.feed.read_bytes(),self.before)

    def test_invalid_signature_preserves_last_good_feed(self):
        with self.assertRaises(ValueError): self.install(new=encode([FIXTURE,dict(record(),sig='0'*6618)]))
        self.assertEqual(self.feed.read_bytes(),self.before)
        self.assertFalse(self.store.read()['pending'])

    def test_pending_transaction_blocks_another_install(self):
        self.install()
        with self.assertRaises(ValueError): self.install(transaction='b'*32)

    def test_rollback_restores_exact_original_bytes(self):
        self.install(); self.store.finish('a'*32,False)
        self.assertEqual(self.feed.read_bytes(),self.before)
        self.assertFalse(self.store.read()['pending'])

    def test_rollback_refuses_unrelated_change(self):
        self.install(); self.feed.write_bytes(encode([FIXTURE,record(4100)]))
        with self.assertRaises(ValueError): self.store.finish('a'*32,False)
        self.assertEqual(parse(self.feed.read_bytes())[-1]['height'],4100)

    def test_corrupt_backup_cannot_be_restored(self):
        self.install(); (self.store.state/('feed-'+sha(self.before)+'.json')).write_bytes(b'corrupt')
        with self.assertRaises(ValueError): self.store.finish('a'*32,False)

    def test_commit_refuses_changed_public_file(self):
        self.install(); self.feed.write_bytes(self.before)
        with self.assertRaises(ValueError): self.store.finish('a'*32,True)

    def test_recover_crash_after_replace_before_journal_update(self):
        event=self.install(); event['phase']='prepared'
        atomic_json(self.store.transaction_path('a'*32),event)
        self.store.finish('a'*32,True)
        self.assertFalse(self.store.read()['pending'])

    def test_recover_crash_before_replace(self):
        event=self.install(); self.feed.write_bytes(self.before); event['phase']='prepared'
        atomic_json(self.store.transaction_path('a'*32),event)
        self.store.finish('a'*32,False)
        self.assertEqual(self.feed.read_bytes(),self.before)

    def test_stale_publisher_becomes_unhealthy(self):
        status=self.store.checked(4163); status['last_checked_at']=int(time.time())-4*3600
        atomic_json(self.store.state/'publisher-status.json',status)
        with self.assertRaises(ValueError): self.store.health()

    def controller(self):
        parent=self
        class FakePublisher(Publisher):
            def __init__(self):
                self.config=dict(publisher_host='n3'); self.state=parent.root/'signer'; self.state.mkdir(exist_ok=True)
                self.run_dir=self.state/'run'; self.run_dir.mkdir(exist_ok=True); self.sign_calls=0; self.fail_readback=False
            def gateway(self,host,action,**values):
                if action=='read': return parent.store.read()
                if action=='install': return parent.store.install(values)
                if action in ('commit','rollback'): return parent.store.finish(values['transaction'],action=='commit')
                if action=='checked': return parent.store.checked(values['tip'])
                raise AssertionError(action)
            def public_feed(self):
                if self.fail_readback and parent.store.read()['pending']: return b'[]'
                return parent.feed.read_bytes()
            def observe(self,heights): return observations()
            def verify(self,raw,name): return parse(raw)
            def sign(self,height,block_hash):
                self.sign_calls+=1
                return record(height)
        return FakePublisher()

    def test_end_to_end_second_run_is_idempotent(self):
        controller=self.controller()
        self.assertEqual(controller.run()['status'],'published')
        self.assertEqual(controller.run()['status'],'current_no_new_eligible_height')
        self.assertEqual(controller.sign_calls,1)
        self.assertEqual(len(parse(self.feed.read_bytes())),2)

    def test_failed_readback_rolls_back(self):
        controller=self.controller(); controller.fail_readback=True
        with self.assertRaises(ValueError): controller.run()
        self.assertEqual(self.feed.read_bytes(),self.before)
        self.assertFalse(self.store.read()['pending'])

    def test_recovery_commits_interrupted_valid_publication(self):
        self.install()
        controller=self.controller()
        self.assertEqual(controller.run()['status'],'recovered_publication')
        self.assertEqual(controller.sign_calls,0)
        self.assertFalse(self.store.read()['pending'])


if __name__=='__main__': unittest.main()
