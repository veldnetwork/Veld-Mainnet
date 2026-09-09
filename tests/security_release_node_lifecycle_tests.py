"""Actual standalone node startup, authenticated RPC, peers and orderly restart."""
from pathlib import Path
import argparse, ctypes, hashlib, http.client, json, os, secrets, subprocess, time
from security_state_migration_network_tests import free_port
from security_release_backup import private_copy

class StandaloneNode:
    def __init__(self,binary,directory,p2p,rpc,peer,env,phase):
        self.directory=directory;self.rpc_port=rpc;self.env=env;self.binary=binary
        self.log=(directory.parent/(directory.name+'-'+phase+'.log')).open('w',encoding='utf-8')
        self.command=[str(binary),'--regtest','--nomine','--no-prompt','--txindex',
            '--datadir',str(directory),'--p2pport',str(p2p),'--rpcport',str(rpc),'--connect','127.0.0.1:'+str(peer)]
        self.process=subprocess.Popen(self.command,env=env,stdin=subprocess.DEVNULL,
            stdout=self.log,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW)
        self.token=''
        try:
            deadline=time.monotonic()+240
            while time.monotonic()<deadline:
                assert self.process.poll() is None,'standalone node exited during startup; inspect its local log'
                if (directory/'rpc.token').exists():
                    utility=subprocess.run([str(binary),'--regtest','--nomine','--print-rpc-token','--datadir',str(directory)],
                        env=env,capture_output=True,text=True,timeout=30)
                    if utility.returncode==0 and len(utility.stdout.strip())==64:
                        self.token=utility.stdout.strip()
                        try:self.rpc('getblockchaininfo');return
                        except (ConnectionError,OSError):pass
                time.sleep(1)
            raise TimeoutError('standalone authenticated RPC did not become ready')
        except BaseException:
            self.stop();raise
    def rpc(self,method,params=()):
        conn=http.client.HTTPConnection('127.0.0.1',self.rpc_port,timeout=30)
        conn.request('POST','/',json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':list(params)}),
            {'Content-Type':'application/json','Authorization':'Bearer '+self.token})
        response=conn.getresponse();body=response.read(1024*1024);status=response.status;conn.close()
        assert status==200
        result=json.loads(body);assert not result.get('error'),result.get('error')
        return result['result']
    def stop(self):
        if self.log.closed:return
        if self.process.poll() is None:
            kernel=ctypes.WinDLL('kernel32',use_last_error=True)
            kernel.OpenEventW.argtypes=[ctypes.c_ulong,ctypes.c_int,ctypes.c_wchar_p];kernel.OpenEventW.restype=ctypes.c_void_p
            kernel.SetEvent.argtypes=[ctypes.c_void_p];kernel.CloseHandle.argtypes=[ctypes.c_void_p]
            handle=kernel.OpenEventW(2,False,'Local\\VeldNodeShutdown-'+str(self.process.pid))
            try:
                assert handle and kernel.SetEvent(handle),'owned node shutdown event unavailable'
                self.process.wait(timeout=60)
                assert self.process.returncode==0,self.process.returncode
            except BaseException:
                if self.process.poll() is None:self.process.kill();self.process.wait(timeout=30)
                raise
            finally:
                if handle:kernel.CloseHandle(handle)
                self.log.close();self.token=''
        else:self.log.close();self.token=''

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--completed-run',type=Path,required=True)
    parser.add_argument('--scenario',choices=('upgrade','full-sync'),default='upgrade')
    args=parser.parse_args();run=args.completed_run.resolve();out=run/'release-qualification'
    full_sync=args.scenario=='full-sync'
    result=out/('standalone-full-sync-lifecycle-results.json' if full_sync else 'standalone-node-lifecycle-results.json');assert not result.exists()
    source_backup=run/('sync-recovery-cold-backup-3' if full_sync else 'upgrade-recovery-cold-backup-3')
    if full_sync:
        prior=json.loads((run/'sync-recovery-results-3.json').read_text())
        assert prior['status']=='integration_pass' and prior['stopped']
    binary=out/'regtest-node-helper.exe'
    env=dict(os.environ);env['PATH']=r'C:\msys64\clang64\bin'+os.pathsep+env.get('PATH','')
    env['VELD_VAULT_PASSPHRASE']=secrets.token_urlsafe(48)
    env['VELD_LEVELDB_WRITE_BUFFER_MB']='8';env['VELD_LEVELDB_BLOCK_CACHE_MB']='16'
    report={'status':'running','checks':{},'scope':'actual src/veld-node.cpp main loop with isolated regtest profile',
            'scenario':args.scenario,'source_backup':str(source_backup),
            'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'samples':[]}
    nodes=[];directories=[];ports=[free_port() for _ in range(4)];assert len(set(ports))==4
    def converged(a,b,timeout=180):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            aa=a.rpc('getblockchaininfo');bb=b.rpc('getblockchaininfo')
            if (aa['ibd_complete'] and bb['ibd_complete'] and aa['blocks']==bb['blocks'] and
                aa['best_block_hash']==bb['best_block_hash'] and
                a.rpc('getnetworkinfo')['connections']>0 and b.rpc('getnetworkinfo')['connections']>0):return aa
            time.sleep(1)
        raise TimeoutError('standalone main loops did not reach synchronized connected state')
    try:
        for role in ('a','b'):
            directory=run/(('node-standalone-full-sync-' if full_sync else 'node-standalone-lifecycle-')+role);assert not directory.exists()
            private_copy(source_backup,directory,run);directories.append(directory)
        a=StandaloneNode(binary,directories[0],ports[0],ports[1],ports[2],env,'initial');nodes.append(a)
        b=StandaloneNode(binary,directories[1],ports[2],ports[3],ports[0],env,'initial');nodes.append(b)
        state=converged(a,b);assert state['blocks']==3360 and state['txindex_enabled']
        report['checks']['actual_node_main_loops_unlock_encrypted_rpc_and_complete_ibd']=True
        for node in (a,b):
            peg=node.rpc('getpeginfo');assert peg['reserve_accounting_holds'] and peg['supply_sats']==2400000
            assert node.rpc('getanchorinfo')['local_floor']['installed']
        report['checks']['actual_startup_reconstructs_reserve_and_installed_anchor_floor']=True
        start=time.monotonic()
        while time.monotonic()-start<190:
            state=converged(a,b,45)
            report['samples'].append({'elapsed_seconds':round(time.monotonic()-start,1),'height':state['blocks'],
                'tip':state['best_block_hash'],'ibd_complete':state['ibd_complete'],
                'a_connections':a.rpc('getnetworkinfo')['connections'],'b_connections':b.rpc('getnetworkinfo')['connections']})
            time.sleep(10)
        report['checks']['connected_synced_operation_survives_peer_freshness_interval']=True
        b.stop()
        b=StandaloneNode(binary,directories[1],ports[2],ports[3],ports[0],env,'restarted');nodes.append(b)
        restarted=converged(a,b)
        assert restarted['best_block_hash']==state['best_block_hash']
        report['checks']['orderly_standalone_shutdown_restart_and_automatic_rejoin']=True
        report['final_state']={key:restarted[key] for key in ('blocks','best_block_hash','ibd_complete','txindex_enabled')}
        report['status']='integration_pass';print('PASS standalone node lifecycle checks='+str(len(report['checks'])),flush=True)
    except BaseException as error:
        report['status']='integration_failed';report['failure']={'type':type(error).__name__,'message':str(error)};raise
    finally:
        for node in reversed(nodes):node.stop()
        for directory in directories:
            if (directory/'rpc.token').exists():(directory/'rpc.token').unlink()
        env.pop('VELD_VAULT_PASSPHRASE',None)
        report['stopped']=all(node.process.poll() is not None for node in nodes)
        result.write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
