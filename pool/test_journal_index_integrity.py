"""Disposable cache-corruption/recovery tests, not native economic E2E evidence."""
import hashlib
from contextlib import closing
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pool.journal import Journal
from pool.protocol import Refused, encode
from pool.payments import Payments
import pool.test_payments as payment_fixtures


class JournalIndexIntegrity(unittest.TestCase):
    def test_cached_payload_rebuilt_from_unchanged_journal_and_anchor(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);data=root/'data';anchor=root/'anchor/current'
            journal=Journal(data,anchor);journal.append('lease',{'end':'100'})
            expected=list(journal.events());journal.close()
            log_before=(data/'events.jsonl').read_bytes();anchor_before=anchor.read_bytes()
            with closing(sqlite3.connect(data/'index.sqlite')) as db, db:
                forged=dict(expected[0],payload={'end':'0'})
                db.execute('UPDATE events SET body=? WHERE seq=1',(encode(forged),))
            journal=Journal(data,anchor)
            self.assertEqual(journal.index_repairs,1)
            self.assertEqual(list(journal.events()),expected)
            self.assertEqual(journal.db.execute('SELECT body FROM events WHERE seq=1').fetchone()[0],encode(expected[0]))
            self.assertEqual((data/'events.jsonl').read_bytes(),log_before)
            self.assertEqual(anchor.read_bytes(),anchor_before);journal.close()

    def test_invalid_and_oversize_cached_bodies_are_not_recovery_input(self):
        for body in (b'{broken', 'text instead of blob', b'x'*8193):
            with self.subTest(body_type=type(body).__name__,length=len(body)),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);journal=Journal(root/'data',root/'anchor/current')
                journal.append('intent',{'id':'unchanged'});expected=list(journal.events());journal.close()
                with closing(sqlite3.connect(root/'data/index.sqlite')) as db, db:
                    db.execute('UPDATE events SET body=?',(body,))
                # A reduced test bound exercises the bounded SQL BLOB read; the
                # production event limit remains unchanged.
                with patch('pool.journal.MAX_EVENT',8192):
                    journal=Journal(root/'data',root/'anchor/current')
                    self.assertEqual(list(journal.events()),expected)
                    self.assertEqual(journal.index_repairs,1);journal.close()

    def test_even_coherent_cache_forgery_after_open_cannot_change_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);journal=Journal(root/'data',root/'anchor/current')
            journal.append('lease',{'end':'100'});expected=list(journal.events())
            forged=dict(expected[0],payload={'end':'0'});body=encode(forged)
            journal.db.execute('UPDATE events SET digest=?,body=? WHERE seq=1',
                               (hashlib.sha256(body).hexdigest(),body));journal.db.commit()
            self.assertEqual(list(journal.events()),expected);journal.close()
            # Existing fail-closed behavior for a changed index identity remains.
            with self.assertRaisesRegex(Refused,'index identity mismatch'):
                Journal(root/'data',root/'anchor/current')

    def test_extra_negative_index_entry_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);journal=Journal(root/'data',root/'anchor/current')
            journal.append('lease',{'end':'100'});journal.close()
            with closing(sqlite3.connect(root/'data/index.sqlite')) as db, db:
                db.execute('INSERT INTO events VALUES(-1,?,?)',('f'*64,b'{}'))
            with self.assertRaisesRegex(Refused,'index ahead'):
                Journal(root/'data',root/'anchor/current')

    def test_nested_replay_and_append_preserve_snapshot_and_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);journal=Journal(root/'data',root/'anchor/current')
            journal.append('lease',{'end':'100'});journal.append('lease',{'end':'200'})
            replay=journal.events();first=next(replay)
            self.assertEqual(len(list(journal.events())),2)
            journal.append('lease',{'end':'300'})
            self.assertEqual([first['payload']['end']]+[e['payload']['end'] for e in replay],['100','200'])
            self.assertEqual([e['payload']['end'] for e in journal.events()],['100','200','300']);journal.close()

    def test_journal_body_change_after_open_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);journal=Journal(root/'data',root/'anchor/current')
            journal.append('lease',{'end':'100'})
            path=root/'data/events.jsonl';changed=json.loads(path.read_bytes())
            changed['payload']['end']='000'
            path.write_bytes(encode(changed)+b'\n')
            with self.assertRaisesRegex(Refused,'journal integrity'):
                list(journal.events())
            journal.close()

    @unittest.skipUnless(os.name=='posix','Linux permits replacement of an open journal pathname')
    def test_replaced_journal_path_is_not_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);journal=Journal(root/'data',root/'anchor/current')
            journal.append('lease',{'end':'100'})
            path=root/'data/events.jsonl';replacement=root/'replacement'
            replacement.write_bytes(path.read_bytes());os.replace(replacement,path)
            with self.assertRaisesRegex(Refused,'journal identity changed'):
                list(journal.events())
            journal.close()

    def test_signed_payment_commitment_survives_cache_corruption_without_resigning(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);node,pool,journal,payment=payment_fixtures.PaymentTests().fixture(root)
            identity=payment.plan(now=100000)
            raw=b'disposable signed-byte recovery fixture'
            payment.record('payment_signed',{'id':identity,'signed_hex':raw.hex(),
                'txid':hashlib.sha256(hashlib.sha256(raw).digest()).hexdigest(),'state':'signed'})
            expected=dict(payment.intents[identity]);journal.close()
            with closing(sqlite3.connect(root/'payments/index.sqlite')) as db, db:
                seq,body=db.execute("SELECT seq,body FROM events WHERE json_extract(body,'$.kind')='payment_signed'").fetchone()
                changed=json.loads(body);changed['payload']['signed_hex']='00';changed['payload']['state']='reserved'
                db.execute('UPDATE events SET body=? WHERE seq=?',(encode(changed),seq))
            journal=Journal(root/'payments',root/'anchor/current.json')
            with patch('pool.payments.subprocess.run',side_effect=AssertionError('signer must not run')):
                restored=Payments(pool,journal,'must-not-run','','','11','22','fees',100000,1000)
                self.assertEqual(restored.intents[identity],expected)
                self.assertEqual(restored.summary('a'),{'paid_units':'0','reserved_units':'150000000'})
            self.assertEqual(node.broadcasts,[]);journal.close()


if __name__=='__main__':unittest.main()
