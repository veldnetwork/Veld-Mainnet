"""Explicit-start worker controller; the native executable performs all hashing."""
import argparse
import http.client
from pathlib import Path
import ssl
import subprocess
import time
import urllib.parse

from .journal import atomic
from .protocol import decode,encode,require,VERSION,units

class Retry(RuntimeError):
    pass

class Client:
    def __init__(self,url,ca,genesis):
        self.endpoint=urllib.parse.urlsplit(url)
        require(self.endpoint.scheme=='https' and self.endpoint.hostname and
                self.endpoint.path in ('','/') and not self.endpoint.username and
                not self.endpoint.password and not self.endpoint.query and not self.endpoint.fragment,'TLS pool endpoint')
        self.context=ssl.create_default_context(cafile=ca)
        self.context.minimum_version=ssl.TLSVersion.TLSv1_2
        self.genesis=genesis
    def call(self,action,payload):
        for attempt in range(8):
            try:return self._call(action,payload)
            except ssl.SSLCertVerificationError:
                raise
            except (Retry,OSError,http.client.HTTPException) as error:
                if attempt==7:raise RuntimeError('pool busy after bounded retries') from error
                time.sleep(min(.05*(2**attempt),1))
    def _call(self,action,payload):
        connection=http.client.HTTPSConnection(self.endpoint.hostname,self.endpoint.port or 443,context=self.context,timeout=20)
        try:
            connection.request('POST','/v1/'+action,encode(payload),{'Content-Type':'application/json'})
            response=connection.getresponse();result=decode(response.read(16385))
            if response.status!=200 or not result.get('ok'):
                if result.get('retryable') is True:raise Retry()
                raise RuntimeError(result.get('error','pool unavailable'))
            return result['result']
        finally:connection.close()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);parser.add_argument('--rounds',type=int,default=0)
    args=parser.parse_args();config=decode(Path(args.config).read_bytes())
    require(set(config)=={'endpoint','ca_file','genesis','payout_address','native_binary','account_file','nonce_count','pause_ms'},'worker configuration')
    client=Client(config['endpoint'],config['ca_file'],config['genesis'])
    account_path=Path(config['account_file']);account_path.parent.mkdir(parents=True,exist_ok=True)
    if account_path.exists():
        account=decode(account_path.read_bytes())
        require(account['endpoint']==config['endpoint'] and account['address']==config['payout_address'] and account['genesis']==config['genesis'],'account configuration changed')
    else:
        account=client.call('register',{'address':config['payout_address']})
        account.update(endpoint=config['endpoint'],address=config['payout_address'],genesis=config['genesis'])
        atomic(account_path,encode(account))
    with account_path.with_suffix('.hash.log').open('a') as log:
        process=subprocess.Popen([config['native_binary']],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,text=True,bufsize=1)
        try:
            rounds=0
            while not args.rounds or rounds<args.rounds:
                base={'account':account['account'],'token':account['worker_token']}
                lease=client.call('work',dict(base,count=str(config['nonce_count'])))
                require(lease['version']==VERSION and lease['chain']==config['genesis'],'pool network/profile mismatch')
                process.stdin.write(f"scan {lease['height']} {lease['header']} {lease['target']} {lease['start']} {lease['count']}\n");process.stdin.flush()
                for line in process.stdout:
                    if line.startswith('SHARE '):
                        fields=line.split();require(len(fields)==3,'native share result')
                        response=client.call('submit',dict(base,lease=lease['lease'],nonce=fields[1]))
                        print(encode({'event':'share','status':response['status'],'block':response.get('block')}).decode(),flush=True)
                    elif line.startswith('DONE '):break
                    else:raise RuntimeError('native worker failure')
                else:raise RuntimeError('native worker exited')
                rounds+=1
                time.sleep(units(str(config['pause_ms']),60000)/1000)
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()

if __name__=='__main__':main()
