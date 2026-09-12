from pathlib import Path
import base64
import copy
import hashlib
import importlib.util
import json
import tempfile
import time
import unittest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('portal', ROOT / 'src/veld-miner-portal.py')
portal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(portal)
b64 = lambda value: base64.urlsafe_b64encode(value).decode().rstrip('=')


class RemoteUnlock(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='veld-portal-unlock-')
        self.store = portal.PortalStore(Path(self.temp.name) / 'portal.sqlite')
        self.account = self.store.create_account('fixture-owner', 'Synthetic account passphrase 318')
        self.signer = ec.generate_private_key(ec.SECP256R1())
        numbers = self.signer.public_key().public_numbers()
        x, y = b64(numbers.x.to_bytes(32, 'big')), b64(numbers.y.to_bytes(32, 'big'))
        self.command_key = dict(x=x, y=y, id=portal.command_key_id(x, y))
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_numbers()
        n = b64(rsa_key.n.to_bytes(256, 'big'))
        self.unlock_key = dict(alg='RSA-OAEP-256', n=n, e='AQAB', identity='a' * 64,
            id=hashlib.sha256(('VELD_PORTAL_UNLOCK_KEY_V1\n' + n + '\nAQAB').encode()).hexdigest())
        self.report = portal.validate_report(dict(portal_protocol=4, name='Synthetic node', version='3.1.8', height=0,
            sync_lag=0, hashrate=0, workers=15, peers=0, inbound=0, blocks=0, mining_state='Stopped', warning='',
            snapshot=dict(unlock_key=self.unlock_key, remote_control=False, identity_unlocked=False)))
        self.token = 'synthetic-node-token-' + '0' * 32
        reply = self.store.report(self.token, self.report)
        self.device = reply['device_id']
        self.assertTrue(self.store.claim(self.account, reply['pair_code'], self.command_key))

    def tearDown(self):
        self.temp.cleanup()

    def command(self, sequence=1, action='node.signin'):
        issued = int(time.time())
        payload = dict(ciphertext=b64(b'x' * 40), identity=self.unlock_key['identity'], iv=b64(b'i' * 12),
            key_id=self.unlock_key['id'], wrapped_key=b64(b'k' * 256)) if action == 'node.signin' else {}
        command = dict(id=self.device, sequence=sequence, issued_at=issued, expires_at=issued + 180,
            nonce=b64(sequence.to_bytes(16, 'big')), action=action, payload=payload, key_id=self.command_key['id'])
        signature = self.signer.sign(portal.command_envelope(command).encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(signature)
        order = int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 16)
        command['signature'] = b64(r.to_bytes(32, 'big') + min(s, order-s).to_bytes(32, 'big'))
        return portal.validate_command(command)

    def test_signed_relay_acknowledgement_and_ciphertext_cleanup(self):
        command = self.command()
        command_id = self.store.queue_command(self.account, command)
        reply = self.store.report(self.token, self.report)
        self.assertEqual(reply['portal_protocol'], 4)
        self.assertEqual(reply['command']['payload'], command['payload'])
        self.assertEqual(reply['command']['signature'], command['signature'])
        self.report.update(ack_id=command_id, ack_status='completed', ack_message='Node start requested')
        self.store.report(self.token, self.report)
        with self.store.database() as db:
            row = db.execute('SELECT state,payload_json FROM commands WHERE id=?', (command_id,)).fetchone()
            self.assertEqual(row['state'], 'completed')
            self.assertEqual(row['payload_json'], '{}')

    def test_replay_signature_and_ownership_enforced(self):
        command = self.command()
        self.assertIsNone(self.store.queue_command(self.account + 1, command))
        changed = copy.deepcopy(command)
        changed['payload']['ciphertext'] = b64(b'y' * 40)
        with self.assertRaisesRegex(ValueError, 'signature'):
            self.store.queue_command(self.account, changed)
        self.store.queue_command(self.account, command)
        with self.assertRaisesRegex(ValueError, 'Refresh'):
            self.store.queue_command(self.account, command)

    def test_old_client_monitoring_stays_compatible(self):
        self.report['portal_protocol'] = 3
        self.report['snapshot'].pop('unlock_key')
        reply = self.store.report(self.token, self.report)
        self.assertEqual(reply['portal_protocol'], 3)
        with self.assertRaisesRegex(ValueError, 'Update this node'):
            self.store.queue_command(self.account, self.command())
        self.assertIsNotNone(self.store.queue_command(self.account, self.command(action='node.stop')))

    def test_payload_and_public_key_are_bounded(self):
        payload = self.command()['payload']
        for changed in [dict(payload, password='never accepted'), dict(payload, iv='bad'),
                        dict(payload, ciphertext=b64(b'x' * 1041)), dict(payload, identity='bad')]:
            with self.assertRaises(ValueError):
                portal.validate_unlock_payload(changed)
        self.assertEqual(portal.validate_unlock_key(self.unlock_key), self.unlock_key)
        for changed in [dict(self.unlock_key, id='b' * 64), dict(self.unlock_key, e='Aw'),
                        dict(self.unlock_key, n='A' * 342)]:
            with self.assertRaises(ValueError):
                portal.validate_unlock_key(changed)

    def test_rollback_does_not_deliver_unsupported_signin(self):
        self.store.queue_command(self.account, self.command())
        self.report['portal_protocol'] = 3
        self.report['snapshot'].pop('unlock_key')
        self.assertIsNone(self.store.report(self.token, self.report)['command'])
        self.store.queue_command(self.account, self.command(sequence=2, action='node.stop'))
        self.assertEqual(self.store.report(self.token, self.report)['command']['action'], 'node.stop')

    def test_expired_and_superseded_ciphertext_is_removed(self):
        first = self.store.queue_command(self.account, self.command())
        second = self.store.queue_command(self.account, self.command(sequence=2))
        with self.store.database() as db:
            self.assertEqual(db.execute('SELECT payload_json FROM commands WHERE id=?', (first,)).fetchone()[0], '{}')
            db.execute('UPDATE commands SET expires_at=? WHERE id=?', (int(time.time()) - 1, second))
        self.assertIsNone(self.store.report(self.token, self.report)['command'])
        with self.store.database() as db:
            row = db.execute('SELECT state,payload_json FROM commands WHERE id=?', (second,)).fetchone()
            self.assertEqual(tuple(row), ('expired', '{}'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
