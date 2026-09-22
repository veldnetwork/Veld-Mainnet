"""Real signed portal relay and disposable SQLite; no network or production state."""
import copy
import unittest
import portal_unlock_server_tests as unlock
portal = unlock.portal


class PoolControl(unlock.RemoteUnlock):
    def ready(self):
        self.report['snapshot'].update(pool_remote_control=True, remote_control=True)
        self.store.report(self.token, self.report)

    def test_pool_signed_roundtrip_stop_and_replay(self):
        self.ready()
        for seq, action in enumerate(('pool.start', 'pool.stop'), 1):
            command = self.command(seq, action)
            identity = self.store.queue_command(self.account, command)
            reply = self.store.report(self.token, self.report)
            self.assertEqual(reply['command']['action'], action)
            self.assertEqual(reply['command']['payload'], {})
            self.assertEqual(reply['command']['signature'], command['signature'])
            self.report.update(ack_id=identity, ack_status='completed', ack_message='Fixture worker request accepted')
            self.store.report(self.token, self.report)
            self.assertEqual(self.store.command_status(self.account, self.device, identity)['state'], 'completed')
            with self.assertRaises(ValueError):
                self.store.queue_command(self.account, command)

    def test_pool_schema_authority_and_device_binding(self):
        self.ready()
        command = self.command(action='pool.start')
        for payload in ({'endpoint': 'https://attacker.invalid'}, {'payout_address': 'replacement'}, {'enabled': True}, []):
            with self.assertRaises(ValueError):
                portal.validate_command(dict(command, payload=payload))
        with self.assertRaises(ValueError):
            self.store.queue_command(self.account, dict(command, action='pool.stop'))
        self.assertIsNone(self.store.queue_command(self.account + 1, command))
        self.assertIsNone(self.store.queue_command(self.account, dict(command, id=self.device+1)))
        self.assertEqual(self.store.devices(self.account)[0]['command_sequence'], 0)

    def test_pool_capability_offline_and_pairing_fail_closed(self):
        command = self.command(action='pool.start')
        with self.assertRaisesRegex(ValueError, 'remote pool controls'):
            self.store.queue_command(self.account, command)
        self.ready()
        self.report['snapshot']['remote_control'] = False
        self.store.report(self.token, self.report)
        with self.assertRaisesRegex(ValueError, 'pairing'):
            self.store.queue_command(self.account, command)
        self.ready()
        with self.store.database() as db:
            db.execute('UPDATE devices SET last_seen=0 WHERE id=?', (self.device,))
        with self.assertRaisesRegex(ValueError, 'offline'):
            self.store.queue_command(self.account, command)
        self.ready()
        identity = self.store.queue_command(self.account, command)
        self.report['snapshot']['pool_remote_control'] = False
        self.assertIsNone(self.store.report(self.token, self.report)['command'])
        self.assertEqual(self.store.command_status(self.account,self.device,identity)['state'], 'failed')

    def test_pool_snapshot_capability_is_strict_boolean(self):
        self.assertIs(portal.validate_snapshot({})['pool_remote_control'], False)
        for bad in ('true', 1, None, []):
            with self.assertRaises(ValueError):
                portal.validate_snapshot({'pool_remote_control': bad})


if __name__ == '__main__':
    unittest.main()
