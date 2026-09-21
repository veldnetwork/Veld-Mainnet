import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from .backend import Node
from .protocol import Busy, Refused

class BackendHttpTests(unittest.TestCase):
    def test_funds_index_requires_explicit_operational_native_capability(self):
        """Capability schema fixture; the native indexed fork run is separate."""
        node=Node('http://127.0.0.1:32772',Path('not-read'),'b'*64)
        for value in (None,[],{}, {'txindex_enabled':False},{'txindex_enabled':1},
                      {'txindex_enabled':'true'}):
            with self.subTest(value=value),patch.object(node,'call',return_value=value) as call:
                with self.assertRaisesRegex(Refused,'operational transaction index'):
                    node.require_transaction_index()
                call.assert_called_once_with('getblockchaininfo')
        with patch.object(node,'call',return_value={'txindex_enabled':True}):
            node.require_transaction_index()
        with patch.object(node,'call',side_effect=Busy('index rebuilding')):
            with self.assertRaises(Busy):node.require_transaction_index()

    def test_real_http_readiness_is_retryable_without_hiding_policy_refusals(self):
        """Synthetic RPC errors over real HTTP, not a native mining fixture."""
        state={'error':None,'calls':0}
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                state['calls']+=1
                body=json.dumps({'id':request['id'],'error':state['error'],'result':{'ready':True}}).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers()
                self.wfile.write(body)
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever);thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                token=Path(directory)/'token';token.write_text('a'*64);token.chmod(0o600)
                node=Node('http://127.0.0.1:'+str(server.server_port),token,'b'*64)
                stages=('getblocktemplate refused: ','getblocktemplate closed before publication: ',
                        'getblocktemplate authorization refused: ')
                cases=[stage+reason for stage in stages for reason in
                       ('sync_incomplete','startup_replay_incomplete','independent_validation_incomplete')]
                cases.append('getblocktemplate authorization refused: binding_mismatch')
                for message in cases:
                    state['error']={'code':-32010,'message':message}
                    before=state['calls']
                    with self.subTest(message=message),self.assertRaises(Busy):node.call('getblocktemplate','public-address-fixture')
                    self.assertEqual(state['calls'],before+1,'adapter must leave retries to the worker')
                    state['error']=None
                    self.assertEqual(node.call('getblocktemplate','public-address-fixture'),{'ready':True})
                for stage in stages:
                    for reason in ('role_denied','unwired','binding_mismatch','durable_state_unproven',
                                   'snapshot_state_untrusted','runtime_closed','sync_incomplete extra'):
                        if stage=='getblocktemplate authorization refused: ' and reason=='binding_mismatch':continue
                        state['error']={'code':-32010,'message':stage+reason}
                        with self.subTest(stage=stage,reason=reason),self.assertRaises(Refused):node.call('getblocktemplate','public-address-fixture')
                    state['error']={'code':-32010,'message':stage+'sync_incomplete'}
                    before=state['calls']
                    with self.assertRaises(Refused):node.call('sendrawtransaction','exact-fixture-bytes')
                    self.assertEqual(state['calls'],before+1,'writes must not acquire a new retry classification')
                    state['error']['code']=-32603
                    with self.assertRaises(Refused):node.call('getblocktemplate','public-address-fixture')
                for method in ('submitblock','sendrawtransaction','getblockcount'):
                    state['error']={'code':-32010,'message':'getblocktemplate authorization refused: binding_mismatch'}
                    before=state['calls']
                    with self.subTest(method=method),self.assertRaises(Refused):node.call(method,'exact-fixture-bytes')
                    self.assertEqual(state['calls'],before+1)
                for code,message in ((-32603,'getblocktemplate authorization refused: binding_mismatch'),
                        (-32010,'getblocktemplate authorization binding mismatch'),
                        (-32010,'getblocktemplate authorization refused: binding_mismatch extra')):
                    state['error']={'code':code,'message':message}
                    with self.subTest(code=code,message=message),self.assertRaises(Refused):node.call('getblocktemplate','public-address-fixture')
                # Capacity is explicit. Do not make generic runtime closure,
                # token entropy failure or policy refusal silently retryable.
                state['error']={'code':-32005,'message':'getblocktemplate authorization capacity; retry shortly'}
                before=state['calls']
                with self.assertRaises(Busy):node.call('getblocktemplate','public-address-fixture')
                self.assertEqual(state['calls'],before+1)
        finally:
            server.shutdown();server.server_close();thread.join(timeout=5)

    def test_invalid_http_never_becomes_a_result_or_an_automatic_write_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            token=Path(directory)/'token';token.write_text('a'*64);token.chmod(0o600)
            node=Node('http://127.0.0.1:32772',token,'b'*64)
            for error in (http.client.BadStatusLine('POST / HTTP/1.1\r\n'),
                          http.client.IncompleteRead(b'partial'),http.client.RemoteDisconnected()):
                with patch('pool.backend.http.client.HTTPConnection') as connection:
                    connection.return_value.getresponse.side_effect=error
                    with self.assertRaises(Busy):node.call('sendrawtransaction','exact-disposable-test-bytes')
                    self.assertEqual(connection.return_value.request.call_count,1)
                    connection.return_value.close.assert_called_once()

if __name__=='__main__':unittest.main()
