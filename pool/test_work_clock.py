"""Real native transport, local TLS and synthetic one-second TTL; no mining."""
import argparse,http.server,json,ssl,subprocess,tempfile,threading,time
from pathlib import Path
def main():
 p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--openssl',required=True);p.add_argument('--legacy',action='store_true');a=p.parse_args()
 with tempfile.TemporaryDirectory(prefix='veld-work-clock-') as t:
  root=Path(t);key=root/'tls.key';cert=root/'tls.crt'
  subprocess.run([a.openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',key,'-out',cert,'-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1'],check=True,capture_output=True)
  state={'active':0,'peak':0,'calls':0};lock=threading.Lock()
  class Handler(http.server.BaseHTTPRequestHandler):
   protocol_version='HTTP/1.1'
   def log_message(self,*_):pass
   def do_POST(self):
    assert self.path=='/v1/work';assert self.rfile.read(int(self.headers['Content-Length']))==b'{}'
    with lock:state['active']+=1;state['peak']=max(state['peak'],state['active']);state['calls']+=1
    try:
     time.sleep(.4);body=json.dumps({'ok':True,'result':{'ttl_ms':'1000'}}).encode()
     self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body);self.close_connection=True
    finally:
     with lock:state['active']-=1
  server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
  context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key);server.socket=context.wrap_socket(server.socket,server_side=True)
  thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
  try:r=subprocess.run([a.binary,f'https://127.0.0.1:{server.server_port}',cert],text=True,capture_output=True,timeout=25)
  finally:server.shutdown();server.server_close();thread.join(5)
  assert r.returncode==0,(r.stdout,r.stderr);rows=[json.loads(x) for x in r.stdout.splitlines()];assert len(rows)==12 and state['calls']==12 and state['peak']<=3
  if a.legacy:assert min(x['remaining_ms'] for x in rows)<0,'fixture must reproduce exhausted lifetime in the old queue timing'
  else:
   assert max(x['before_send_ms'] for x in rows)>1000,'actual local queue delay required'
   assert all(0<x['remaining_ms']<=1000-x['request_response_ms'] for x in rows),'request and response time must still consume TTL'
  print(json.dumps(dict(status='REPRODUCED_LEGACY_EXPIRY_LOSS' if a.legacy else 'PASS_NATIVE_TLS_WORK_CLOCK',synthetic_ttl=True,mining_e2e=False,state=state,rows=rows)))
if __name__=='__main__':main()
