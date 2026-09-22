"""Native nginx -> TLS gateway -> Unix IPC. Synthetic payloads; no mining E2E.

Run with root inside a disposable network namespace on a host with nginx.
No external interfaces, production configurations, credentials or services.
"""
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import socketserver
import ssl
import statistics
import subprocess
import tempfile
import threading
import time

from .gateway import Gateway
from .service import Server


def main():
    assert os.geteuid()==0 and os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net')
    subprocess.run(['ip','link','set','lo','up'],check=True)
    assert {x['ifname'] for x in json.loads(subprocess.check_output(['ip','-j','link','show']))}=={'lo'}
    with tempfile.TemporaryDirectory(prefix='veld-proxy-reuse-') as temp:
        root=Path(temp)
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-keyout',str(root/'key.pem'),'-out',str(root/'cert.pem'),'-subj','/CN=localhost',
            '-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],check=True,capture_output=True)
        class IPC(socketserver.StreamRequestHandler):
            def handle(self):
                payload=json.loads(self.rfile.readline(16385))
                self.wfile.write(json.dumps(dict(ok=True,result={'echo':payload['payload']})).encode()+b'\n')
        class IPCServer(socketserver.ThreadingUnixStreamServer):request_queue_size=Server.request_queue_size
        ipc=IPCServer(str(root/'co.sock'),IPC)
        class ObservedGateway(Gateway):
            connections=0
            def process_request(self,request,address):
                self.connections+=1
                super().process_request(request,address)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(root/'cert.pem',root/'key.pem')
        gateway=ObservedGateway(('127.0.0.1',0),ctx,str(root/'co.sock'))
        threads=[]
        for server in (ipc,gateway):
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();threads.append(thread)
        config=root/'nginx.conf'
        def configuration(identity='localhost'):
            locations=[]
            for label,connection in [('baseline','close'),('optimized','keep-alive')]:
                locations.append(f'''location = /{label} {{
                    proxy_pass https://worker/v1/work;
                    proxy_http_version 1.1;
                    proxy_set_header Connection {connection};
                    proxy_ssl_verify on;
                    proxy_ssl_verify_depth 2;
                    proxy_ssl_server_name on;
                    proxy_ssl_name {identity};
                    proxy_ssl_trusted_certificate {root}/cert.pem;
                    proxy_cache off;
                    proxy_connect_timeout 2s;
                    proxy_read_timeout 5s;
                }}''')
            return f'''worker_processes 1;
                pid {root}/nginx.pid;
                error_log {root}/nginx-error.log warn;
                events {{worker_connections 128;}}
                http {{access_log off;
                    upstream worker {{server 127.0.0.1:{gateway.server_port};
                        keepalive 2;keepalive_requests 16;keepalive_timeout 1s;}}
                    server {{listen 127.0.0.1:18081;client_max_body_size 16k;
                        {' '.join(locations)}
                    }}
                }}'''
        def request(route,value):
            client=http.client.HTTPConnection('127.0.0.1',18081,timeout=10)
            try:
                start=time.monotonic()
                client.request('POST','/'+route,json.dumps(value),{'Content-Type':'application/json','Connection':'close'})
                reply=client.getresponse();data=reply.read(16385)
                return reply.status,data,time.monotonic()-start
            finally:client.close()
        report=dict(scope='native nginx/TLS/IPC; synthetic coordinator; loopback namespace only',cases=[])
        try:
            for wrong_identity in (False,True):
                config.write_text(configuration('wrong.invalid' if wrong_identity else 'localhost'))
                subprocess.run(['nginx','-t','-p',str(root)+'/', '-c',str(config)],check=True,capture_output=True)
                with (root/'nginx-output.log').open('ab') as log:
                    process=subprocess.Popen(['nginx','-p',str(root)+'/', '-c',str(config),'-g','daemon off;'],stdout=log,stderr=log)
                    try:
                        for _ in range(50):
                            try:status,_,_=request('baseline',{});break
                            except OSError:time.sleep(.05)
                        else:raise AssertionError('private nginx start')
                        if wrong_identity:
                            assert status==502
                            report['upstream_certificate_identity_refused']=True
                            continue
                        assert status==200
                        for label in ('baseline','optimized'):
                            before=gateway.connections;times=[]
                            for n in range(32):
                                value={'account':str(n%2),'nonce':str(n)}
                                status,data,seconds=request(label,value)
                                assert status==200 and json.loads(data)['result']['echo']==value
                                times.append(seconds)
                            connections=gateway.connections-before
                            assert connections==(32 if label=='baseline' else 2),connections
                            report['cases'].append(dict(mode=label,requests=32,upstream_tls_connections=connections,
                                median_ms=statistics.median(times)*1000))
                        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                            responses=list(executor.map(lambda i:request('optimized',{'n':i}),range(32)))
                        assert all(status==200 for status,_,_ in responses)
                        report['concurrent_current_client_requests']=32
                    finally:
                        process.terminate();process.wait(timeout=10)
        finally:
            for server in (gateway,ipc):server.shutdown();server.server_close()
            for thread in threads:thread.join(timeout=5)
        report.update(status='PASS',nginx=subprocess.run(['nginx','-v'],capture_output=True,text=True).stderr.strip())
        print(json.dumps(report),flush=True)


if __name__=='__main__':main()
