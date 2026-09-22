"""Actual gateway/coordinator IPC and authorization; mock node, no mining E2E."""
import http.client
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest

from .coordinator import Coordinator
from .gateway import Gateway
from .journal import Journal
from .service import Server


class GatewayKeepalive(unittest.TestCase):
    def test_each_reused_connection_request_reauthenticates_and_failures_close(self):
        with tempfile.TemporaryDirectory(prefix='veld-keepalive-auth-') as temp:
            root=Path(temp)
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                '-keyout',str(root/'key.pem'),'-out',str(root/'cert.pem'),'-subj','/CN=localhost',
                '-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],check=True,capture_output=True)
            journal=Journal(root/'journal',root/'anchor/current.json')
            node=SimpleNamespace(check_chain=lambda:None,call=lambda *_:{'isvalid':True},genesis='a'*64)
            pool=Coordinator(node,journal,None,'pool','f'*64)
            first=pool.register('x'*30);second=pool.register('y'*30)
            ipc=Server(str(root/'co.sock'),pool)
            self.assertEqual(ipc.request_queue_size,32)
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(root/'cert.pem',root/'key.pem')
            gateway=Gateway(('127.0.0.1',0),ctx,str(root/'co.sock'))
            threads=[]
            for server in (ipc,gateway):
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();threads.append(thread)
            conn=http.client.HTTPSConnection('127.0.0.1',gateway.server_port,
                context=ssl.create_default_context(cafile=str(root/'cert.pem')),timeout=5)
            def request(payload):
                conn.request('POST','/v1/account',json.dumps(payload),{'Content-Type':'application/json','Connection':'keep-alive'})
                response=conn.getresponse();body=json.loads(response.read())
                return response,body
            try:
                response,body=request(dict(account=first['account'],token=first['view_token']))
                port=conn.sock.getsockname()[1]
                self.assertTrue(body['ok']);self.assertEqual(body['result']['address'],'x'*30)
                self.assertEqual(response.getheader('Connection'),'keep-alive')
                response,body=request(dict(account=second['account'],token=second['view_token']))
                self.assertEqual(conn.sock.getsockname()[1],port)
                self.assertEqual(body['result']['address'],'y'*30)
                # The previous account's valid credential cannot authorize the
                # next account, even on the exact same authenticated TLS socket.
                response,body=request(dict(account=first['account'],token=second['view_token']))
                self.assertFalse(body['ok']);self.assertEqual(response.getheader('Connection'),'close')
                self.assertIsNone(conn.sock)
                # Public mining credentials do not become private viewing access.
                response,body=request(dict(account=first['account'],token=first['worker_token']))
                self.assertFalse(body['ok']);self.assertEqual(response.getheader('Connection'),'close')
                self.assertIsNone(conn.sock)
                # Failure on a reused connection cannot poison later valid use.
                response,body=request(dict(account=first['account'],token=first['view_token']))
                self.assertTrue(body['ok']);self.assertEqual(body['result']['address'],'x'*30)
            finally:
                conn.close()
                for server in (gateway,ipc):server.shutdown();server.server_close()
                for thread in threads:thread.join(timeout=5)
                journal.close()


if __name__=='__main__':unittest.main()
