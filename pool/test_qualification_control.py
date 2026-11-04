"""Focused test-driver fault fixtures; not native mining qualification."""

from pathlib import Path
import os
import tempfile
import unittest
from unittest import mock

from pool.qualification.control import acknowledgement, mine_block

BLOCK = 'd4deb97a7a2bfe2ba28bc07cb6bef6904a486ca7e6211bda9168aea8d8dba316'
INTERLEAVED = (
    '  [rpc] sendrawtransaction REJECTED: utxo_missing_input_0 (txid=9eccMINED 3660 '
    + BLOCK
    + '\na133fe1c79ab...)\n'
)


class Fixture:
    def __init__(self, root, mode='mined'):
        self.args = ['pool-backend', str(root), '30001', '30002']
        self.root = root
        self.mode = mode
        self.commands = []
        self.buffer = ''
        self.stdin = self
        self.height = 3659
        self.log = root / 'node.log'
        self.log.write_text('')

    def poll(self):
        return None

    def write(self, value):
        self.buffer += value

    def flush(self):
        for command in self.buffer.splitlines():
            if not command.startswith('mine '):
                continue
            self.commands.append(command)
            fields = command.split()
            request = fields[-1]
            with self.log.open('a') as log:
                log.write(INTERLEAVED)
            if self.mode == 'missing':
                continue
            if self.mode == 'defer' and len(self.commands) == 1:
                text = 'V1 ' + request + ' DEFERRED\n'
            else:
                identity = '0' * 32 if self.mode == 'stale' else request
                block = '0' * 64 if self.mode == 'wrong-block' else BLOCK
                text = 'V1 ' + identity + ' MINED 3660 ' + block + '\n'
                self.height = 3660
            (self.root / 'lab-mining-ack.txt').write_text(text)
        self.buffer = ''

    def call(self, method, *args):
        if method == 'getblockcount':
            return self.height
        if method == 'getblockhash':
            assert args == ('3660',)
            return BLOCK
        raise AssertionError(method)


class ControlTests(unittest.TestCase):
    def test_captured_interleaved_log_does_not_hide_completed_command(self):
        self.assertFalse(any(line.startswith('MINED ') for line in INTERLEAVED.splitlines()))
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            self.assertEqual(mine_block(fixture, fixture, 'fixture-address', fixture.log), 3660)
            self.assertEqual(len(fixture.commands), 1)

    def test_log_alone_is_not_acknowledgement_and_never_queues_a_second_command(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp), 'missing')
            with self.assertRaisesRegex(RuntimeError, 'acknowledgement deadline'):
                mine_block(fixture, fixture, 'fixture-address', fixture.log, timeout=0.02)
            self.assertEqual(len(fixture.commands), 1)

    def test_old_receipt_cannot_acknowledge_current_command(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp), 'stale')
            with self.assertRaisesRegex(RuntimeError, 'acknowledgement deadline'):
                mine_block(fixture, fixture, 'fixture-address', fixture.log, timeout=0.02)
            self.assertEqual(len(fixture.commands), 1)

    def test_only_explicit_deferral_permits_another_command(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp), 'defer')
            self.assertEqual(mine_block(fixture, fixture, 'fixture-address', fixture.log), 3660)
            self.assertEqual(len(fixture.commands), 2)
            self.assertNotEqual(fixture.commands[0].split()[-1], fixture.commands[1].split()[-1])

    def test_receipt_must_match_canonical_chain(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp), 'wrong-block')
            with self.assertRaisesRegex(RuntimeError, 'expected canonical block'):
                mine_block(fixture, fixture, 'fixture-address', fixture.log)

    @unittest.skipUnless(os.name == 'posix', 'Unix atomic replacement inode semantics')
    def test_replaced_open_receipt_retries_without_enqueuing_more_work(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture(Path(temp))
            path = fixture.root / 'lab-mining-ack.txt'
            real_open = os.open
            replaced = []

            def open_then_replace(name, flags, *args, **kwargs):
                descriptor = real_open(name, flags, *args, **kwargs)
                if Path(name) == path and not replaced:
                    replacement = path.with_suffix('.new')
                    replacement.write_bytes(path.read_bytes())
                    os.replace(replacement, path)
                    replaced.append(os.fstat(descriptor).st_nlink)
                return descriptor

            with mock.patch('pool.qualification.control.os.open', side_effect=open_then_replace):
                self.assertEqual(mine_block(fixture, fixture, 'fixture-address', fixture.log), 3660)
            self.assertEqual(replaced, [0])
            self.assertEqual(len(fixture.commands), 1)

    @unittest.skipUnless(os.name == 'posix', 'Unix hard-link rejection')
    def test_hardlinked_receipt_is_still_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'lab-mining-ack.txt'
            identity = '1' * 32
            path.write_text('V1 ' + identity + ' MINED 3660 ' + BLOCK + '\n')
            os.link(path, Path(temp) / 'another-name')
            with self.assertRaisesRegex(RuntimeError, 'invalid native mining acknowledgement file'):
                acknowledgement(path, identity)

    @unittest.skipUnless(os.name == 'posix', 'Unix no-follow receipt opening')
    def test_symlink_receipt_is_still_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'target'
            identity = '1' * 32
            target.write_text('V1 ' + identity + ' MINED 3660 ' + BLOCK + '\n')
            path = Path(temp) / 'lab-mining-ack.txt'
            path.symlink_to(target)
            with self.assertRaises(OSError):
                acknowledgement(path, identity)

    def test_bounded_strict_receipt_schema(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'lab-mining-ack.txt'
            identity = '1' * 32
            for text in [
                'x' * 257 + '\n',
                'V1 ' + identity + ' MINED 3660 ' + BLOCK,
                'V2 ' + identity + ' DEFERRED\n',
                'V1 ' + identity + ' MINED 03660 ' + BLOCK + '\n',
                'V1 ' + identity + ' MINED 3660 ' + BLOCK.upper() + '\n',
                'V1 ' + identity + ' DEFERRED extra\n',
            ]:
                with self.subTest(text=text[:40]):
                    path.write_text(text)
                    with self.assertRaises(RuntimeError):
                        acknowledgement(path, identity)


if __name__ == '__main__':
    unittest.main()
