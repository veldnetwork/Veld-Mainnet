"""Complete ordinary P2P download and durable recovery on disposable nodes."""
from pathlib import Path
import argparse, datetime, hashlib, json, os, shutil, time
from security_state_migration_network_tests import Node, wait_equal
from security_release_backup import private_copy

def hashes(directory):
    return {str(p.relative_to(directory)):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(directory.rglob('*')) if p.is_file()}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--completed-run',type=Path,required=True)
    parser.add_argument('--timeout-seconds',type=int,default=32400)
    parser.add_argument('--attempt',type=int,default=1)
    a=parser.parse_args(); run=a.completed_run.resolve()
    prior=json.loads((run/'first-activation-results.json').read_text())
    assert prior['status']=='integration_pass' and prior['stopped']
    binary=run/'first-activation-archive-readback-node.exe'
    suffix='' if a.attempt==1 else '-'+str(a.attempt)
    result_path=run/('sync-recovery-results'+suffix+'.json')
    assert not result_path.exists()
    report={'status':'running','started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
            'scope':'isolated loopback, complete genesis-to-3360 P2P history, normal source quotas',
            'checks':{},'progress':[]}
    nodes=[]
    def save():
        temp=result_path.with_suffix('.tmp')
        temp.write_text(json.dumps(report,indent=2)+'\n')
        os.replace(temp,result_path)
    try:
        source=Node(binary,run/('node-sync-source'+suffix));nodes.append(source)
        loaded=source.control('import_history',name='final-history.bin')
        assert loaded['digest']==prior['final_state']['digest']
        source_status=source.control('status')
        fresh=Node(binary,run/('node-sync-fresh'+suffix));nodes.append(fresh)
        assert fresh.ready['height']==0
        assert not (fresh.directory/'blocks.bin').exists()
        report['checks']['fresh_destination_begins_at_genesis']=True
        fresh.control('connect',port=source.p2p)
        start=time.monotonic(); last_progress=-60; last_height=0; last_advance=start; last_redial=start
        while time.monotonic()-start<a.timeout_seconds:
            source.control('maintain');fresh.control('maintain')
            state=fresh.control('status')
            if state['ready_peer_ips']==0 and time.monotonic()-last_redial>=30:
                fresh.control('connect',port=source.p2p)
                last_redial=time.monotonic()
            if state['height']>last_height:
                last_height=state['height'];last_advance=time.monotonic()
            if state['height']==source_status['height']:
                assert state['tip']==source_status['tip'] and state['digest']==source_status['digest']
                break
            if time.monotonic()-last_progress>=60:
                row={'elapsed_seconds':round(time.monotonic()-start,1),'height':state['height'],
                     'target_height':source_status['height'],'peer_ips':state['ready_peer_ips'],
                     'admission':state['admission']}
                report['progress'].append(row);save();print('SYNC '+json.dumps(row),flush=True)
                last_progress=time.monotonic()
            if time.monotonic()-last_advance>600:
                raise TimeoutError('P2P synchronization made no progress for 10 minutes at '+str(last_height))
            time.sleep(5)
        else:raise TimeoutError('complete P2P download deadline exceeded')
        report['download_seconds']=round(time.monotonic()-start,1)
        report['checks']['complete_genesis_to_3360_p2p_validation']=True
        request_id=prior['request']['request_id']
        expected={k:v for k,v in prior['request'].items() if k!='request_id'}
        assert fresh.control('fa_request',request_id=request_id)==expected
        archive=fresh.control('fa_archive_status')
        assert archive['migration_active'] and archive['hot_requests']==0 and archive['hot_payout_identities']==0
        assert fresh.rpc('getpeginfo')['reserve_accounting_holds']
        report['checks']['p2p_reconstructs_financial_state_and_authenticated_archive']=True
        fresh.stop(); report['checks']['clean_shutdown_after_full_download']=True
        restarted=Node(binary,fresh.directory,'-clean-restart');nodes.append(restarted)
        assert restarted.ready['digest']==source_status['digest']
        report['checks']['clean_restart_preserves_complete_state']=True
        restarted.process.kill();restarted.process.wait(timeout=30);restarted.stop()
        recovered=Node(binary,fresh.directory,'-crash-restart');nodes.append(recovered)
        assert recovered.ready['digest']==source_status['digest']
        assert recovered.control('fa_request',request_id=request_id)==expected
        report['checks']['unclean_process_exit_recovers_complete_state']=True
        recovered.stop()
        backup=run/('sync-recovery-cold-backup'+suffix)
        assert not backup.exists()
        before=hashes(fresh.directory);private_copy(fresh.directory,backup,run)
        assert hashes(backup)==before
        report['checks']['stopped_datadir_backup_matches_every_file']=True
        restored_dir=run/('node-sync-restored'+suffix)
        assert not restored_dir.exists();private_copy(backup,restored_dir,run)
        restored=Node(binary,restored_dir);nodes.append(restored)
        assert restored.ready['digest']==source_status['digest']
        assert restored.control('fa_request',request_id=request_id)==expected
        restored.control('connect',port=source.p2p)
        wait_equal(source,restored,120)
        report['checks']['backup_restores_independently_and_rejoins_peer']=True
        report['final_state']=source_status;report['archive']=archive
        report['status']='integration_pass'
        print('PASS synchronization and recovery checks='+str(len(report['checks'])),flush=True)
    except BaseException as error:
        report['status']='integration_failed';report['failure']={'type':type(error).__name__,'message':str(error)}
        raise
    finally:
        for node in reversed(nodes):node.stop()
        report['stopped']=all(node.process.poll() is not None for node in nodes)
        report['ended_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()

if __name__=='__main__':main()
