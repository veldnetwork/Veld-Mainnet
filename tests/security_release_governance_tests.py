"""Funded ten-validator protocol governance and its unchanged full timelock."""
from pathlib import Path
import argparse, datetime, hashlib, json, os, secrets, subprocess, time
from security_state_migration_network_tests import Node, wait_admission, wait_equal, advance, proposal

def main():
    p=argparse.ArgumentParser();p.add_argument('--completed-run',type=Path,required=True)
    a=p.parse_args();run=a.completed_run.resolve();build=run/'release-qualification'
    binary=build/'release-integration-node.exe';result_path=build/'governance-results.json'
    assert not result_path.exists()
    env=dict(os.environ);env['PATH']=r'C:\msys64\clang64\bin'+os.pathsep+env.get('PATH','')
    env['VELD_VAULT_PASSPHRASE']=secrets.token_urlsafe(48)
    identities=subprocess.run([str(build/'release-identities.exe'),str(run),str(run),str(run/'governance-private')],env=env,
                              capture_output=True,text=True,check=True)
    assert len(identities.stdout.splitlines())==11
    del env['VELD_VAULT_PASSPHRASE']
    report={'status':'running','started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'checks':{}}
    nodes=[]
    def save():result_path.write_text(json.dumps(report,indent=2)+'\n')
    try:
        node=Node(binary,run/'node-governance-ten');nodes.append(node)
        assert len(node.ready['addresses'])==11
        node.control('import_history',name='final-history.bin');node.control('synchronize')
        wait_admission(node,require_peer=False)
        for i in range(8,11):
            node.control('fund',to=i,amount='60');node.generate(1)
            node.control('register',wallet=i);node.generate(1)
        assert node.control('status')['active_validators']==10
        report['checks']['ten_validators_have_real_mined_utxo_bonds']=True
        for i in range(1,11):node.control('endorse',wallet=i,sponsor=0,height=node.control('status')['height'])
        node.generate(1)
        title='Protocol governance integration qualification'
        node.control('propose',wallet=8,type='protocol_upgrade',title=title,
                     description='Disposable protocol-upgrade signalling proposal for the full quorum and seven-day timelock.')
        node.generate(1);pr=proposal(node,title)
        assert pr['type']=='protocol_upgrade',pr
        for i in range(1,10):node.control('vote',wallet=i,proposal=pr['id'],identity=pr['vote_identity'])
        node.generate(1);nine=proposal(node,title)
        assert nine['votes_yes']==9 and nine['status']=='open',nine
        report['checks']['nine_legitimate_votes_cannot_satisfy_protocol_quorum']=True
        node.control('vote',wallet=10,proposal=pr['id'],identity=pr['vote_identity'])
        node.generate(1);ten=proposal(node,title);locked_height=node.control('status')['height']
        assert ten['votes_yes']==10 and ten['status']=='timelocked',ten
        assert ten['timelock_until']==locked_height+7*480,ten
        report['checks']['tenth_vote_starts_full_3360_block_timelock']=True
        report['nine_votes']=nine;report['timelocked']=ten;save()
        locked=node.control('status');node.stop()
        node=Node(binary,run/'node-governance-ten','-timelock-restart');nodes.append(node)
        assert node.ready['digest']==locked['digest'] and proposal(node,title)==ten
        node.control('synchronize');wait_admission(node,require_peer=False)
        report['checks']['restart_preserves_votes_identity_and_timelock']=True
        advance(node,None,ten['timelock_until']-1)
        assert proposal(node,title)['status']=='timelocked'
        report['checks']['proposal_remains_locked_until_exact_final_block']=True
        node.generate(1);passed=proposal(node,title)
        assert passed['status']=='passed' and passed['votes_yes']==10
        report['checks']['protocol_proposal_passes_at_exact_timelock_height']=True
        final=node.control('status');node.stop()
        restarted=Node(binary,run/'node-governance-ten','-passed-restart');nodes.append(restarted)
        assert restarted.ready['digest']==final['digest'] and proposal(restarted,title)==passed
        report['checks']['final_state_and_governance_survive_second_restart']=True
        report['passed']=passed;report['final_state']=final;report['status']='integration_pass'
        print('PASS protocol governance checks='+str(len(report['checks'])),flush=True)
    except BaseException as error:
        report['status']='integration_failed';report['failure']={'type':type(error).__name__,'message':str(error)};raise
    finally:
        for node in reversed(nodes):node.stop()
        report['stopped']=all(n.process.poll() is not None for n in nodes)
        report['ended_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()

if __name__=='__main__':main()
