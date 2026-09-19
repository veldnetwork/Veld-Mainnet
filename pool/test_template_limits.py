"""Real HTTP/journal boundary tests using synthetic RPC block bodies.

These test transport and persistence, NOT native block validity or mining E2E.
Native construction/admission remain the node's responsibility.
"""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import tempfile
import threading
import unittest
from unittest.mock import patch

from pool.backend import Node
from pool.coordinator import Coordinator
from pool.journal import Journal, MAX_EVENT
from pool.protocol import (decode, encode, Refused, MAX_BLOCK_BYTES,
                           MAX_RPC_BYTES, MAX_JOURNAL_BYTES)


@contextmanager
def rpc_fixture(block_hex):
    state = {'block_hex': block_hex, 'submitted': None}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass

        def do_POST(self):
            if self.headers.get('Authorization') != 'Bearer ' + 'a'*64:
                self.send_error(401)
                return
            length = int(self.headers['Content-Length'])
            if length > MAX_RPC_BYTES:
                self.send_error(413)
                return
            request = decode(self.rfile.read(length), MAX_RPC_BYTES)
            method = request['method']
            if method in ('getblockhash', 'getcompiledgenesis'):
                result = 'b'*64
            elif method == 'validateaddress':
                result = {'isvalid': True}
            elif method == 'getblocktemplate':
                result = dict(block_hex=state['block_hex'], height=1,
                              target='f'*64, prev_block_hash='c'*64,
                              work_binding='fixture-binding', work_token='private-fixture-token',
                              work_ttl_ms=10000, reserved_miner_destination=False,
                              miner_receipts=[])
            elif method == 'submitblock':
                state['submitted'] = request['params']
                result = True
            else:
                self.send_error(400)
                return
            body = encode({'id': request['id'], 'result': result, 'error': None})
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield 'http://127.0.0.1:' + str(server.server_port), state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class TemplateLimitTests(unittest.TestCase):
    def test_bounds_track_consensus_and_leave_public_message_limit_unchanged(self):
        source = (Path(__file__).resolve().parents[1]/'include/core/constants.h').read_text()
        value = re.search(r'\bMAX_BLOCK_SIZE\s*=\s*([0-9\']+)', source).group(1)
        self.assertEqual(MAX_BLOCK_BYTES, int(value.replace("'", '')))
        self.assertEqual(MAX_EVENT, MAX_JOURNAL_BYTES)
        with self.assertRaisesRegex(Refused, 'message limit'):
            decode(encode({'body': 'x'*16384}))

    def test_large_exact_candidate_survives_rpc_restart_lease_and_submission(self):
        for size in (1024*1024+1, MAX_BLOCK_BYTES):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                token = root/'rpc-token'
                token.write_text('a'*64)
                token.chmod(0o600)
                original = '00'*size
                with rpc_fixture(original) as (url, state):
                    node = Node(url, token, 'b'*64)
                    journal = Journal(root/'data', root/'anchor/current.json')
                    try:
                        pool = Coordinator(node, journal, None, 'pool', 'f'*64)
                        account = pool.register('x'*30)
                        first = pool.work(account['account'], account['worker_token'], 32)
                        self.assertLess(len(encode(first)), 16384)
                        self.assertNotIn('work_binding', first)
                        self.assertNotIn('work_token', first)
                    finally:
                        journal.close()
                    journal = Journal(root/'data', root/'anchor/current.json')
                    try:
                        recovered = Coordinator(node, journal, None, 'pool', 'f'*64)
                        old_job = recovered.jobs[recovered.leases[first['lease']]['job']]
                        self.assertEqual(old_job['node']['block_hex'], original)
                        second = recovered.work(account['account'], account['worker_token'], 32)
                        self.assertEqual(second['start'], '0000000000000020')
                        # Actual transport, exact private binding, only nonce changes.
                        self.assertIs(node.submit(old_job['node'], 17), True)
                        sent = state['submitted']
                        self.assertEqual(sent[0][:160], original[:160])
                        self.assertEqual(sent[0][160:176], '1100000000000000')
                        self.assertEqual(sent[0][176:], original[176:])
                        self.assertEqual(sent[1:], ['fixture-binding', 'private-fixture-token'])
                    finally:
                        journal.close()

    def test_oversized_and_noncanonical_templates_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory)/'token'
            token.write_text('a'*64)
            token.chmod(0o600)
            with rpc_fixture('00'*92) as (url, state):
                node = Node(url, token, 'b'*64)
                for value in ('00'*(MAX_BLOCK_BYTES+1), None, [], 4,
                              'AA'+'00'*91, ' '*184, 'zz'*92, '0'*185):
                    with self.subTest(kind=type(value).__name__):
                        state['block_hex'] = value
                        with self.assertRaisesRegex(Refused, 'template encoding'):
                            node.template('pool')

    def test_private_reply_read_remains_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory)/'token'
            token.write_text('a'*64)
            token.chmod(0o600)
            node = Node('http://127.0.0.1:32772', token, 'b'*64)
            with patch('pool.backend.http.client.HTTPConnection') as connection:
                response = connection.return_value.getresponse.return_value
                response.status = 200
                response.read.return_value = b'x'*(MAX_RPC_BYTES+1)
                with self.assertRaisesRegex(Refused, 'message limit'):
                    node.call('getblocktemplate', 'pool')
                response.read.assert_called_once_with(MAX_RPC_BYTES+1)

    def test_oversized_journal_entry_is_not_committed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = Journal(root/'data', root/'anchor/current.json')
            try:
                with self.assertRaisesRegex(Refused, 'event limit'):
                    journal.append('job', {'body': 'x'*MAX_EVENT})
                self.assertEqual(journal.sequence, 0)
                self.assertEqual((root/'data/events.jsonl').stat().st_size, 0)
            finally:
                journal.close()


if __name__ == '__main__': unittest.main()
