"""Upgrade a pre-migration datadir, interrupt valid writes, restore a cold backup."""
from pathlib import Path
import argparse, ctypes, hashlib, json, os, shutil, threading, time
from security_state_migration_network_tests import Node, wait_admission, wait_equal
from security_release_backup import private_copy

def inventory(directory):
    return {str(p.relative_to(directory)):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(directory.rglob('*')) if p.is_file()}

def write_bytes(process):
    class Counters(ctypes.Structure):
        _fields_=[(name,ctypes.c_ulonglong) for name in ('read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes')]
    result=Counters()
    fn=ctypes.windll.kernel32.GetProcessIoCounters
    fn.argtypes=[ctypes.c_void_p,ctypes.POINTER(Counters)];fn.restype=ctypes.c_int
    if not fn(int(process._handle),ctypes.byref(result)):raise OSError('cannot read owned test process I/O counters')
    return result.write_bytes

def main():
    p=argparse.ArgumentParser();p.add_argument('--completed-run',type=Path,required=True)
    a=p.parse_args();run=a.completed_run.resolve();build=run/'release-qualification'
    result_path=build/'upgrade-recovery-results.json';assert not result_path.exists()
    old=build/'pre-migration-node.exe';new=build/'release-integration-node.exe'
    prior=json.loads((run/'first-activation-results.json').read_text())
    request_id=prior['request']['request_id'];expected={k:v for k,v in prior['request'].items() if k!='request_id'}
    report={'status':'running','checks':{},'scope':'same candidate before/after scheduled migration, not a previous shipping binary',
            'binaries':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (old,new)}}
    nodes=[]
    try:
        legacy=Node(old,run/'node-upgrade-recovery');nodes.append(legacy)
        legacy.control('import_history',name='prefix-history.bin');legacy.control('synchronize');wait_admission(legacy,require_peer=False)
        legacy.generate(2);before=legacy.control('status');assert before['height']==3359
        assert not legacy.control('fa_archive_status')['migration_active']
        legacy.stop()
        upgraded=Node(new,legacy.directory,'-upgraded');nodes.append(upgraded)
        assert upgraded.ready['height']==3359 and upgraded.ready['digest']==before['digest']
        report['checks']['upgrade_preserves_pre_3360_state_exactly']=True
        upgraded.control('synchronize');wait_admission(upgraded,require_peer=False);upgraded.generate(1)
        activated=upgraded.control('status');archive=upgraded.control('fa_archive_status')
        assert activated['height']==3360 and archive['migration_active']
        assert archive['hot_requests']==0 and archive['hot_payout_identities']==0 and archive['archive_count']>=2
        assert upgraded.control('fa_request',request_id=request_id)==expected
        report['checks']['upgrade_activates_once_at_3360_and_preserves_fulfilled_request']=True
        upgraded.stop()
        restarted=Node(new,legacy.directory,'-post-migration-restart');nodes.append(restarted)
        assert restarted.ready['digest']==activated['digest'] and restarted.control('fa_archive_status')==archive
        report['checks']['post_activation_restart_does_not_repeat_migration']=True
        restarted.control('synchronize');wait_admission(restarted,require_peer=False)
        before_io=write_bytes(restarted.process);thread_result={}
        def generate():
            try:thread_result['result']=restarted.rpc('generate',['512'])
            except Exception as error:thread_result['interrupted_rpc']=type(error).__name__
        worker=threading.Thread(target=generate);worker.start();deadline=time.monotonic()+15
        while time.monotonic()<deadline and write_bytes(restarted.process)<=before_io:
            assert worker.is_alive(),'generation completed before the intended interruption';time.sleep(.01)
        io_at_crash=write_bytes(restarted.process);assert io_at_crash>before_io and worker.is_alive()
        restarted.process.kill();restarted.process.wait(timeout=30);worker.join(timeout=30)
        assert not worker.is_alive();restarted.stop()
        recovered=Node(new,legacy.directory,'-after-write-interruption');nodes.append(recovered)
        state=recovered.control('status');assert 3360<=state['height']<3360+512,state
        if state['height']==3360:assert state['digest']==activated['digest']
        assert recovered.control('fa_request',request_id=request_id)==expected
        peg=recovered.rpc('getpeginfo');assert peg['reserve_accounting_holds'] and peg['supply_sats']==2400000
        report['checks']['process_killed_during_active_block_generation_recovers_a_valid_prefix']=True
        report['checks']['crash_recovery_preserves_reserve_supply_and_archive']=True
        report['interruption']={'write_bytes_before':before_io,'write_bytes_at_crash':io_at_crash,
                                'requested_blocks':512,'committed_height_after_recovery':state['height'],**thread_result}
        recovered.stop()
        backup=run/'upgrade-recovery-cold-backup';assert not backup.exists()
        expected_files=inventory(legacy.directory);private_copy(legacy.directory,backup,run)
        assert inventory(backup)==expected_files
        report['checks']['cold_backup_matches_every_source_file']=True
        restored_dir=run/'node-upgrade-restored';assert not restored_dir.exists();private_copy(backup,restored_dir,run)
        restored=Node(new,restored_dir);nodes.append(restored)
        assert restored.ready['height']==state['height'] and restored.ready['digest']==state['digest']
        assert restored.control('fa_request',request_id=request_id)==expected
        report['checks']['independent_restore_reconstructs_identical_state']=True
        peer_dir=run/'node-upgrade-peer';assert not peer_dir.exists();private_copy(backup,peer_dir,run)
        peer=Node(new,peer_dir);nodes.append(peer)
        restored.control('connect',port=peer.p2p);wait_equal(restored,peer,120)
        restored.control('synchronize');peer.control('synchronize');wait_admission(restored)
        restored.generate(3);continued=wait_equal(restored,peer,240)
        assert continued['height']==state['height']+3
        report['checks']['restored_nodes_rejoin_and_validate_new_peer_blocks']=True
        report['state_before_upgrade']=before;report['state_after_migration']=activated
        report['recovered_state']=state;report['continued_state']=continued;report['archive']=archive
        report['status']='integration_pass';print('PASS upgrade and recovery checks='+str(len(report['checks'])),flush=True)
    except BaseException as error:
        report['status']='integration_failed';report['failure']={'type':type(error).__name__,'message':str(error)};raise
    finally:
        for node in reversed(nodes):node.stop()
        report['stopped']=all(n.process.poll() is not None for n in nodes)
        result_path.write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
