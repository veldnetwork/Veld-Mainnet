"""Complete the ACL-preserving cold-backup and restored-peer recovery checks."""
from pathlib import Path
import argparse, hashlib, json
from security_state_migration_network_tests import Node, wait_equal, wait_admission
from security_release_backup import private_copy
from security_release_upgrade_recovery_tests import inventory

p=argparse.ArgumentParser();p.add_argument('--completed-run',type=Path,required=True)
p.add_argument('--attempt',type=int,default=2)
a=p.parse_args();run=a.completed_run.resolve();build=run/'release-qualification'
suffix='-'+str(a.attempt)
binary=build/'release-integration-node.exe';result_path=build/('backup-restore-results'+suffix+'.json')
assert not result_path.exists()
earlier=json.loads((build/'upgrade-recovery-results.json').read_text())
assert all(earlier['checks'].values()) and len(earlier['checks'])==6
prior=json.loads((run/'first-activation-results.json').read_text())
request_id=prior['request']['request_id'];request={k:v for k,v in prior['request'].items() if k!='request_id'}
report={'status':'running','checks':{},'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
        'continues':'upgrade-recovery-results.json; only the earlier copy procedure failed to preserve Windows ACLs'}
nodes=[]
try:
    source=Node(binary,run/'node-upgrade-recovery','-backup-source');nodes.append(source)
    state=source.control('status');assert source.control('fa_request',request_id=request_id)==request
    source.stop();backup=run/('upgrade-recovery-cold-backup'+suffix)
    before=inventory(source.directory);receipt=private_copy(source.directory,backup,run)
    assert inventory(backup)==before
    report['checks']['cold_backup_preserves_every_byte_and_windows_acl']=True;report['copy_evidence']=[receipt]
    restored_dir=run/('node-upgrade-restored'+suffix);report['copy_evidence'].append(private_copy(backup,restored_dir,run))
    restored=Node(binary,restored_dir);nodes.append(restored)
    assert restored.ready['height']==state['height'] and restored.ready['digest']==state['digest']
    assert restored.control('fa_request',request_id=request_id)==request
    report['checks']['independent_restore_reconstructs_identical_state_and_archive']=True
    peer_dir=run/('node-upgrade-peer'+suffix);report['copy_evidence'].append(private_copy(backup,peer_dir,run))
    peer=Node(binary,peer_dir);nodes.append(peer)
    restored.control('connect',port=peer.p2p);wait_equal(restored,peer,120)
    restored.control('synchronize');peer.control('synchronize');wait_admission(restored)
    restored.generate(3);continued=wait_equal(restored,peer,240)
    assert continued['height']==state['height']+3
    report['checks']['restored_nodes_rejoin_and_validate_new_peer_blocks']=True
    report['restored_state']=state;report['continued_state']=continued;report['status']='integration_pass'
    print('PASS ACL-preserving backup and restore checks=3',flush=True)
except BaseException as error:
    report['status']='integration_failed';report['failure']={'type':type(error).__name__,'message':str(error)};raise
finally:
    for node in reversed(nodes):node.stop()
    report['stopped']=all(n.process.poll() is not None for n in nodes)
    result_path.write_text(json.dumps(report,indent=2)+'\n')
