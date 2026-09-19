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
                for reason in ('sync_incomplete','startup_replay_incomplete','independent_validation_incomplete'):
                    state['error']={'code':-32010,'message':'getblocktemplate refused: '+reason}
                    before=state['calls']
                    with self.subTest(reason=reason),self.assertRaises(Busy):node.call('getblocktemplate','public-address-fixture')
                    self.assertEqual(state['calls'],before+1,'adapter must leave retries to the worker')
                    state['error']=None
                    self.assertEqual(node.call('getblocktemplate','public-address-fixture'),{'ready':True})
                for reason in ('role_denied','unwired','binding_mismatch','durable_state_unproven',
                               'snapshot_state_untrusted','sync_incomplete extra'):
                    state['error']={'code':-32010,'message':'getblocktemplate refused: '+reason}
                    with self.subTest(reason=reason),self.assertRaises(Refused):node.call('getblocktemplate','public-address-fixture')
                state['error']={'code':-32010,'message':'getblocktemplate refused: sync_incomplete'}
                before=state['calls']
                with self.assertRaises(Refused):node.call('sendrawtransaction','exact-fixture-bytes')
                self.assertEqual(state['calls'],before+1,'writes must not acquire a new retry classification')
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
