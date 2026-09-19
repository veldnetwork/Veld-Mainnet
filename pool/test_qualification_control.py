"""Focused orchestration fixtures; not native mining evidence."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from pool.qualification.control import mine_block


class MiningCommandTests(TestCase):
    def exercise(self, first_reply):
        with TemporaryDirectory() as directory:
            log = Path(directory) / 'node.log'
            log.write_text('POOL_LAB_READY\n')
            requests = []
            tick = [0]
            state = {'height': 9, 'replied': False}

            def write(command):
                if command.startswith('mine '):
                    requests.append(command)

            def sleep(_):
                tick[0] += 1
                if tick[0] == 30:
                    # Thirty polls elapse while a single slow command runs.
                    self.assertEqual(len(requests), 1)
                    with log.open('a') as out:
                        out.write(first_reply + '\n')
                    state['replied'] = True
                    if first_reply.startswith('MINED '): state['height'] = 10
                elif state['replied'] and first_reply.startswith('MINE_DEFERRED') and len(requests) == 2:
                    with log.open('a') as out: out.write('MINED 10 abc\n')
                    state['height'] = 10

            process = SimpleNamespace(poll=lambda: None,
                                      stdin=SimpleNamespace(write=write, flush=lambda: None))
            rpc = SimpleNamespace(call=lambda method: state['height'])
            with patch('pool.qualification.control.time.sleep', sleep):
                self.assertEqual(mine_block(process, rpc, 'test-address', log), 10)
            return len(requests)

    def test_slow_success_does_not_queue_additional_blocks(self):
        self.assertEqual(self.exercise('MINED 10 abc'), 1)

    def test_retry_only_after_explicit_native_deferral(self):
        self.assertEqual(self.exercise('MINE_DEFERRED admission temporarily unavailable'), 2)
