"""Real loopback TLS gateway, fixture IPC health only; no mining/payout claim."""
import http.client,json,pathlib,socket,ssl,subprocess,tempfile,threading,unittest
from pool.gateway import Gateway
from pool.public_status import public_status
from pool.protocol import Refused

def health():
    return dict(ok=True,result=dict(active_accounts='2',verified_shares='123',reconciled_height='8570',
        chain='a'*64,status='Service responding',payments_enabled=False,co_mining_enabled=False,
        worker_token='secret',accounts=['private'],private_endpoint='do-not-forward'))

class PublicStatusTests(unittest.TestCase):
    def test_strict_projection(self):
        body=json.dumps(public_status(health()))
        for private in ('secret','private','worker_token'):self.assertNotIn(private,body)
        for field,bad in [('active_accounts',True),('verified_shares','1e9'),('payments_enabled','yes'),('chain','a'*65)]:
            value=health();value['result'][field]=bad
            with self.assertRaises(Refused):public_status(value)
        for value in ([],None,dict(ok=True,result=[]),dict(ok=False)):
            with self.assertRaises(Refused):public_status(value)

    def test_tls_endpoint_and_private_cors_boundary(self):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp)
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                '-keyout',str(root/'key'),'-out',str(root/'cert'),'-subj','/CN=localhost',
                '-addext','subjectAltName=IP:127.0.0.1'],check=True,capture_output=True)
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(root/'cert',root/'key')
            ipc=socket.socket(socket.AF_UNIX);ipc.bind(str(root/'ipc'));ipc.listen(4);ipc.settimeout(.2)
            stopped=threading.Event();requests=[];errors=[]
            def backend():
                while not stopped.is_set():
                    try:connection,_=ipc.accept()
                    except socket.timeout:continue
                    try:
                        with connection,connection.makefile('rb') as f:
                            request=json.loads(f.readline());requests.append(request)
                            connection.sendall(json.dumps(health()).encode()+b'\n')
                    except Exception as error:errors.append(repr(error))
            bt=threading.Thread(target=backend);bt.start()
            server=Gateway(('127.0.0.1',0),ctx,str(root/'ipc'))
            thread=threading.Thread(target=server.serve_forever);thread.start()
            client_ctx=ssl.create_default_context(cafile=str(root/'cert'))
            def fetch(method,path,body=None):
                c=http.client.HTTPSConnection('127.0.0.1',server.server_port,context=client_ctx,timeout=5)
                c.request(method,path,body,{'Origin':'https://explorer.veld.network','Content-Type':'application/json'})
                r=c.getresponse();result=(r.status,dict(r.getheaders()),json.loads(r.read()));c.close();return result
            try:
                code,headers,value=fetch('GET','/v1/public')
                self.assertEqual(code,200);self.assertEqual(headers['Access-Control-Allow-Origin'],'https://explorer.veld.network')
                self.assertNotIn('Access-Control-Allow-Credentials',headers)
                self.assertEqual(value,public_status(health()));self.assertEqual(requests,[dict(action='health',payload={})])
                for path in ('/v1/account','/v1/history','/v1/public?account=private','/admin','/jsonrpc'):
                    code,headers,_=fetch('GET',path);self.assertEqual(code,404);self.assertNotIn('Access-Control-Allow-Origin',headers)
                code,headers,_=fetch('POST','/v1/health','{}');self.assertEqual(code,200);self.assertNotIn('Access-Control-Allow-Origin',headers)
                self.assertFalse(errors)
            finally:
                server.shutdown();server.server_close();thread.join();stopped.set();bt.join();ipc.close()

if __name__=='__main__':unittest.main(verbosity=2)
