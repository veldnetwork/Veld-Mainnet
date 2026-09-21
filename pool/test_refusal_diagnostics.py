"""Focused error injection over actual private IPC; no native E2E claim."""
import contextlib
import io
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch
from .backend import NodeRefused
from .protocol import encode,decode
if os.name!='posix':raise unittest.SkipTest('Linux coordinator IPC')
from .service import Server

class RefusalDiagnostics(unittest.TestCase):
    def test_fixed_diagnostics_never_echo_arbitrary_rpc_values(self):
        for prefix,stage in (('getblocktemplate refused: ','initial'),
                ('getblocktemplate closed before publication: ','publication'),
                ('getblocktemplate authorization refused: ','authorization')):
            for reason in ('tip_unknown','binding_mismatch','peer_view_unsafe'):
                error=NodeRefused('getblocktemplate',dict(code=-32010,message=prefix+reason))
                self.assertEqual(error.diagnostic,'template_'+stage+'_'+reason)
            for message in (prefix+'secret-token',prefix+'tip_unknown\nsecret-token'):
                self.assertEqual(NodeRefused('getblocktemplate',dict(code=-32010,message=message)).diagnostic,'node_rpc_refused')
        self.assertEqual(NodeRefused('getblocktemplate',dict(code=-32603,message='getblocktemplate canonical builder binding or preflight failed')).diagnostic,'template_builder_preflight_failed')
        self.assertEqual(NodeRefused('sendrawtransaction',dict(code=-32010,message='getblocktemplate refused: tip_unknown')).diagnostic,'node_rpc_refused')

    def test_real_ipc_keeps_refusal_generic_and_operator_notice_bounded(self):
        class Pool:
            def work(self,*args):
                raise NodeRefused('getblocktemplate',dict(code=-32010,message='getblocktemplate refused: tip_unknown'))
        with tempfile.TemporaryDirectory() as directory:
            server=Server(str(Path(directory)/'pool.sock'),Pool())
            thread=threading.Thread(target=server.serve_forever);thread.start()
            output=io.StringIO()
            def request(payload):
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
                    connection.connect(server.server_address);connection.sendall(encode(payload)+b'\n')
                    return decode(connection.makefile('rb').readline())
            try:
                with contextlib.redirect_stderr(output),patch('pool.service.time.monotonic',return_value=100):
                    for _ in range(5):
                        self.assertEqual(request(dict(action='work',payload=dict(account='private-account',token='private-token',count='32'))),
                            dict(ok=False,error='request refused',retryable=False))
                    request(dict(action='secret-action',payload={}))
                self.assertEqual(output.getvalue(),'pool request refused action=work reason=template_initial_tip_unknown\n')
                with contextlib.redirect_stderr(output),patch('pool.service.time.monotonic',return_value=131):
                    request(dict(action=['malformed','secret-action'],payload={}))
                self.assertEqual(len(output.getvalue().splitlines()),2)
                self.assertIn('action=other reason=request_validation_failed',output.getvalue())
                for secret in ('private-account','private-token','secret-action'):self.assertNotIn(secret,output.getvalue())
            finally:
                server.shutdown();server.server_close();thread.join(timeout=5)

if __name__=='__main__':unittest.main()
