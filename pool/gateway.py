"""Unprivileged TLS gateway: no node tokens, wallets or signer credentials."""
import argparse
import http.server
from pathlib import Path
import socket
import ssl
import threading
import time
import signal

from .protocol import decode, encode, require, Refused
from .private_file import read_private
from .public_status import public_status

class Gateway(http.server.ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,bind,context,ipc):
        self.context,self.ipc=context,ipc
        self.slots=threading.BoundedSemaphore(32)
        self.rate_lock=threading.Lock();self.rate={}
        super().__init__(bind,Handler)
    def process_request(self,request,address):
        if not self.slots.acquire(False):request.close();return
        try:super().process_request(request,address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,request,address):
        try:
            request.settimeout(10)
            request=self.context.wrap_socket(request,server_side=True)
            super().process_request_thread(request,address)
        except (OSError,ssl.SSLError):request.close()
        finally:self.slots.release()
    def allow(self,address,action):
        with self.rate_lock:
            now=time.monotonic();key=(address,action)
            self.rate={k:v for k,v in self.rate.items() if now-v[0]<10}
            if key not in self.rate:
                if len(self.rate)>=4096:return False
                self.rate[key]=(now,0)
            start,count=self.rate[key]
            limit=4 if action=='register' else 400
            if count>=limit:return False
            self.rate[key]=(start,count+1);return True

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    server_version='VeldPool/1';sys_version=''
    def log_message(self,*args):pass # never log tokens, request bodies or private addresses
    def security_headers(self):
        self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Cache-Control','no-store')
    def do_GET(self):
        if self.path=='/v1/public':
            if not self.server.allow(self.client_address[0],'public'):
                self.reply(429,{'ok':False,'error':'rate limit','retryable':True});return
            try:
                self.reply(200,public_status(self.coordinator_request('health',{})))
            except (Refused,ValueError,OSError,TimeoutError):
                self.reply(503,{'ok':False,'error':'temporarily unavailable','retryable':True})
            return
        assets={'/':('index.html','text/html; charset=utf-8'),'/pool.css':('pool.css','text/css; charset=utf-8'),
                '/site.css':('site.css','text/css; charset=utf-8'),
                '/pool.js':('pool.js','application/javascript; charset=utf-8')}
        if self.path not in assets:
            self.reply(404,{'ok':False,'error':'not found','retryable':False});return
        if not self.server.allow(self.client_address[0],'page'):
            self.reply(429,{'ok':False,'error':'rate limit','retryable':True});return
        name,content_type=assets[self.path]
        body=(Path(__file__).parent/'web'/name).read_bytes()
        self.send_response(200);self.security_headers()
        self.send_header('Content-Type',content_type);self.send_header('Content-Length',str(len(body)))
        self.send_header('Connection','close');self.end_headers();self.wfile.write(body);self.close_connection=True
    def reply(self,code,value):
        body=encode(value)
        self.send_response(code)
        self.security_headers()
        origin=self.headers.get('Origin')
        if self.command=='GET' and self.path=='/v1/public' and origin in (
                'https://explorer.veld.network','https://portal.veld.network'):
            # Anonymous aggregates only. No credentials, private read or write
            # endpoints receive CORS permission. No arbitrary upstream URL.
            self.send_header('Access-Control-Allow-Origin',origin)
            self.send_header('Vary','Origin')
        for key,value in {'Content-Type':'application/json','Content-Length':str(len(body)),
                          'Connection':'close'}.items():self.send_header(key,value)
        self.end_headers();self.wfile.write(body);self.close_connection=True
    def coordinator_request(self,action,payload):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(15);connection.connect(self.server.ipc)
            connection.sendall(encode({'action':action,'payload':payload})+b'\n')
            with connection.makefile('rb') as file:return decode(file.readline(16385))
    def do_POST(self):
        try:
            require(self.path in ('/v1/register','/v1/work','/v1/submit','/v1/account','/v1/history','/v1/health'),'endpoint')
            require(len(self.headers.get_all('Content-Length',[]))==1 and not self.headers.get_all('Transfer-Encoding'),'HTTP framing')
            length=self.headers['Content-Length']
            require(length.isdecimal() and str(int(length))==length and 0<int(length)<=16384,'body limit')
            require(self.headers.get('Content-Type')=='application/json','content type')
            action=self.path.rsplit('/',1)[1]
            if not self.server.allow(self.client_address[0],action):
                self.reply(429,{'ok':False,'error':'rate limit','retryable':True});return
            payload=decode(self.rfile.read(int(length)))
            response=self.coordinator_request(action,payload)
            self.reply(200,response)
        except (Refused,ValueError):self.reply(400,{'ok':False,'error':'invalid request','retryable':False})
        except (OSError,TimeoutError):self.reply(503,{'ok':False,'error':'temporarily unavailable','retryable':True})

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);args=parser.parse_args()
    config=decode(read_private(args.config, 16384))
    require(set(config)=={'host','port','certificate','private_key','coordinator_socket'},'gateway configuration')
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(config['certificate'],config['private_key'])
    with Gateway((config['host'],config['port']),context,config['coordinator_socket']) as server:
        def shutdown(*_):threading.Thread(target=server.shutdown,daemon=True).start()
        signal.signal(signal.SIGTERM,shutdown);signal.signal(signal.SIGINT,shutdown)
        server.serve_forever(poll_interval=.25)

if __name__=='__main__':main()
