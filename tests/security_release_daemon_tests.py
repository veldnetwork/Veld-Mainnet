"""Standalone validator processes, real authenticated RPC and Core observations."""
from pathlib import Path
import argparse, datetime, hashlib, json, os, secrets, shutil, subprocess, time
from security_state_migration_network_tests import Node, wait_admission, advance
from security_first_activation_network_tests import Bitcoin, relay, sha256d, internal

def main():
    p=argparse.ArgumentParser();p.add_argument('--completed-run',type=Path,required=True)
    p.add_argument('--attempt',type=int,default=1)
    a=p.parse_args();run=a.completed_run.resolve();build=run/'release-qualification'
    suffix='' if a.attempt==1 else '-'+str(a.attempt)
    result_path=build/('daemon-results'+suffix+'.json');assert not result_path.exists()
    env=dict(os.environ);env['PATH']=r'C:\msys64\clang64\bin'+os.pathsep+env.get('PATH','')
    env['VELD_VAULT_PASSPHRASE']=secrets.token_urlsafe(48)
    env['VELD_TEST_RUN_ROOT']=str(run)
    report={'status':'running','started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checks':{},
            'binaries':{name:hashlib.sha256((build/name).read_bytes()).hexdigest() for name in
             ('release-integration-node.exe','veld-validator.exe','veld-node.exe','regtest-node-helper.exe','bitcoin-cli-local.exe')},
            'adapters':'node adapter supplies explicit --regtest to the real credential utility; Bitcoin adapter supplies isolated Core RPC settings'}
    node=None;core=None;processes=[];private=run/('daemon-private'+suffix)
    def start_validators(phase):
        for index in range(1,8):
            log=open(build/f'validator-{index}-{phase}{suffix}.log','w',encoding='utf-8')
            cmd=[str(build/'veld-validator.exe'),'--keyfile',str(private/f'validator-{index}.key'),
                 '--rpchost','127.0.0.1','--rpcport',str(node.rpc_port),'--datadir',str(node.directory),
                 '--bitcoin-cli',str(build/'bitcoin-cli-local.exe')]
            proc=subprocess.Popen(cmd,env=env,cwd=build,stdout=log,stderr=subprocess.STDOUT,
                    creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            processes.append((proc,log,index))
    def stop_validators():
        for proc,log,index in processes:
            if proc.poll() is None:proc.terminate();proc.wait(timeout=30)
            log.close()
        processes.clear()
    def finalize(target=None):
        height=node.control('status')['height'];target=target if target is not None else ((height+19)//20)*20
        advance(node,None,target+1)
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            assert all(proc.poll() is None for proc,_,_ in processes),'validator exited; inspect private test logs'
            qc=node.rpc('getfinalityqc',['2'])
            raw=bytes.fromhex(qc.get('qc_hex',''))
            prefix=b'VELD_FINALITY|QB2|'
            offset=len(prefix)+8+1+4+8+32
            if raw.startswith(prefix) and len(raw)>=offset+8 and int.from_bytes(raw[offset:offset+8],'little')==target:break
            node.control('maintain');time.sleep(1)
        else:raise TimeoutError('standalone validators did not assemble a precommit certificate')
        node.generate(1)
        peg=node.rpc('getpeginfo');assert peg['final_height']==target,peg
        print('PASS standalone daemon finality checkpoint='+str(target),flush=True)
        return peg
    try:
        node=Node(build/'release-integration-node.exe',run/('node-daemon-integration'+suffix))
        node.control('import_history',name='final-history.bin');node.control('synchronize');wait_admission(node,require_peer=False)
        keys=subprocess.run([str(build/'release-identities.exe'),str(run),str(node.directory),str(private)],
                             env=env,capture_output=True,text=True,check=True)
        assert len(keys.stdout.splitlines())==11
        status=subprocess.run([str(build/'veld-validator.exe'),'--keyfile',str(private/'validator-1.key'),
            '--rpcport',str(node.rpc_port),'--datadir',str(node.directory),'--status'],env=env,cwd=build,
            capture_output=True,text=True,timeout=60)
        (build/('validator-status'+suffix+'.log')).write_text(status.stdout+status.stderr)
        assert status.returncode==0,status.returncode
        report['checks']['real_node_helper_decrypts_rpc_vault_and_validator_unlocks_key']=True
        # Keep Core's SQLite journal filename below the Windows path limit.
        bitcoin_dir=run/('bd'+str(a.attempt));assert not bitcoin_dir.exists()
        shutil.copytree(run/'bitcoin',bitcoin_dir)
        core=Bitcoin.__new__(Bitcoin)
        Bitcoin.__init__(core,run.parent/'first-activation-tools/bitcoind.exe',bitcoin_dir)
        env.update(VELD_TEST_BITCOIN_CLI=str(run.parent/'first-activation-tools/bitcoin-cli.exe'),
                   VELD_TEST_BITCOIN_DATADIR=str(bitcoin_dir),VELD_TEST_BITCOIN_RPC_PORT=str(core.port),
                   VELD_TEST_BITCOIN_OBSERVATIONS=str(build/('bitcoin-observations'+suffix+'.log')))
        start_validators('initial');finalize(3360)
        report['checks']['seven_independent_daemons_submit_real_prevote_precommit_qc']=True
        finalized=node.rpc('getfinalitysnapshot')['snapshot']['finalized']
        payload=b'VELD_ANCHOR:'+finalized['height'].to_bytes(8,'little')+bytes.fromhex(finalized['hash'])
        anchor=core.send([core.fund(1000,legacy=True)],[{'data':payload.hex()}]);core.mine(144)
        relay(node,core);proof=core.proof(anchor)
        wire=(b'ANCH'+bytes.fromhex(proof['block'])+proof['directions'].to_bytes(4,'little')+
              bytes([len(proof['branch'])])+b''.join(bytes.fromhex(x) for x in proof['branch'])+bytes.fromhex(anchor['raw']))
        node.control('fa_anchor',proof=wire.hex());node.generate(1)
        assert node.rpc('getanchorinfo')['pending_count']>0
        finalize();finalize()
        anchor_state=node.rpc('getanchorinfo')
        assert anchor_state['anchor_security_milestone']
        assert anchor_state['btc_observed_checkpoint_height']>=core.rpc('getblockheader',[anchor['block']])['height']
        observations=(build/('bitcoin-observations'+suffix+'.log')).read_text().splitlines()
        assert len([x for x in observations if x==anchor['block']+' 0'])>=5,observations
        report['checks']['daemon_processes_independently_query_real_bitcoin_core_before_finalizing_observation']=True
        report['observation_count']=len(observations);report['anchor']=anchor_state
        journals=[private/f'validator-{i}.key.finality-state/journal.bin' for i in range(1,8)]
        assert all(path.is_file() and path.stat().st_size>100 for path in journals)
        journal_hashes={path.parent.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in journals}
        stop_validators();start_validators('restarted');time.sleep(8)
        assert all(proc.poll() is None for proc,_,_ in processes)
        report['checks']['all_seven_daemons_restart_from_durable_journals']=True
        finalize()
        assert any(hashlib.sha256(path.read_bytes()).hexdigest()!=journal_hashes[path.parent.name] for path in journals)
        report['checks']['restarted_daemons_finalize_a_later_checkpoint']=True
        assert node.rpc('getpeginfo')['reserve_accounting_holds']
        assert node.rpc('getpeginfo')['supply_sats']==2400000
        report['checks']['independent_service_operation_preserves_financial_accounting']=True
        report['final_state']=node.control('status');report['status']='integration_pass'
        report['mining_admission_retries']=node.admission_retries
        print('PASS standalone daemon checks='+str(len(report['checks'])),flush=True)
    except BaseException as error:
        report['status']='integration_failed';report['failure']={'type':type(error).__name__,'message':str(error)};raise
    finally:
        stop_validators()
        if core and hasattr(core,'process'):
            try:core.stop()
            except Exception:
                if core.process.poll() is None:core.process.terminate();core.process.wait(timeout=30)
                if hasattr(core,'log') and not core.log.closed:core.log.close()
        if node:node.stop()
        if node and (node.directory/'rpc.token').exists():(node.directory/'rpc.token').unlink()
        env.pop('VELD_VAULT_PASSPHRASE',None)
        report['stopped']=not processes and (node is None or node.process.poll() is not None) and (core is None or core.process.poll() is not None)
        report['ended_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        result_path.write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
