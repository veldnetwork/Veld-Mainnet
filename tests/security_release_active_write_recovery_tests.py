"""Terminate an owned node after new blocks commit while generation continues."""
from pathlib import Path
import argparse, concurrent.futures, hashlib, json, time
import psutil
from security_state_migration_network_tests import Node, wait_admission
from security_release_backup import private_copy

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--completed-run',type=Path,required=True)
    args=parser.parse_args();run=args.completed_run.resolve();out=run/'release-qualification'
    result=out/'active-write-recovery-results.json';assert not result.exists()
    report={'status':'running','checks':{},'scope':'abrupt process termination after observed block commits during an unfinished generation RPC'}
    binary=out/'release-integration-node.exe';report['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
    directory=run/'node-active-write-recovery';assert not directory.exists()
    private_copy(run/'upgrade-recovery-cold-backup-3',directory,run)
    node=None;recovered=None;pool=concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        node=Node(binary,directory);wait_admission(node,require_peer=False)
        initial=node.rpc('getblockchaininfo');start=initial['blocks']
        request_id=json.loads((run/'first-activation-results.json').read_text())['request']['request_id']
        request=node.control('fa_request',request_id=request_id)
        archive=node.control('fa_archive_status');peg=node.rpc('getpeginfo')
        proc=psutil.Process(node.process.pid);before=proc.io_counters().write_bytes
        future=pool.submit(node.rpc,'generate',['256'])
        deadline=time.monotonic()+180;observed=None
        while time.monotonic()<deadline:
            assert not future.done(),'generation finished before the active-write interruption'
            info=node.rpc('getblockchaininfo',timeout=30)
            writes=proc.io_counters().write_bytes
            if info['blocks']>=start+2 and writes>before:
                observed=info;break
            time.sleep(.1)
        assert observed is not None,'no committed progress observed while generation remained active'
        assert not future.done()
        node.process.kill();node.process.wait(timeout=30)
        try:
            future.result(timeout=30);raise AssertionError('interrupted generation unexpectedly returned normally')
        except (ConnectionError,OSError) as error:report['interrupted_rpc_type']=type(error).__name__
        report['interruption']={'starting_height':start,'observed_committed_height':observed['blocks'],
            'observed_committed_hash':observed['best_block_hash'],'write_bytes_before':before,
            'write_bytes_at_interruption':writes,'requested_blocks':256}
        node.stop()
        recovered=Node(binary,directory,'-after-crash')
        status=recovered.rpc('getblockchaininfo')
        assert observed['blocks']<=status['blocks']<start+256,status
        assert recovered.rpc('getblockhash',[str(observed['blocks'])])==observed['best_block_hash']
        report['checks']['new_committed_prefix_survives_interruption_of_active_generation']=True
        assert recovered.control('fa_request',request_id=request_id)==request
        assert recovered.control('fa_archive_status')==archive
        actual=recovered.rpc('getpeginfo')
        assert actual['reserve_accounting_holds'] and actual['supply_sats']==peg['supply_sats']==2400000
        report['checks']['recovered_prefix_preserves_financial_state_and_authenticated_archive']=True
        wait_admission(recovered,require_peer=False);recovered.generate(1)
        assert recovered.rpc('getblockchaininfo')['blocks']==status['blocks']+1
        report['checks']['recovered_node_accepts_and_commits_new_valid_work']=True
        report['recovered_state']=recovered.control('status');report['status']='integration_pass'
        print('PASS active-write recovery checks='+str(len(report['checks'])),flush=True)
    except BaseException as error:
        report['status']='integration_failed';report['failure']={'type':type(error).__name__,'message':str(error)};raise
    finally:
        if recovered:recovered.stop()
        if node:node.stop()
        pool.shutdown(wait=True,cancel_futures=True)
        report['stopped']=all(n is None or n.process.poll() is not None for n in (node,recovered))
        result.write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
