"""One reproducible entrypoint for the connected Linux qualification exercises.

It never converts a missing acceptance boundary into PASS. Native Windows GUI,
full validator/finality/reorg matrices and production artifact qualification
remain explicit completion gates until implemented and executed here.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from .build import hashes
from .isolation import MARKER,require_isolated_network
import os

SOURCE=Path(__file__).resolve().parents[2]
REMAINING=[
    'native Windows clean-install GUI, solo-mode interaction, upgrade and rollback on the final build',
    'funded validator below/at/above former floor, bond lifecycle and reorganization across activation',
    'native finality-certificate-bearing block with the unchanged quorum and warm-up',
    'native income/payment/NMS reorganization and co-mining carryover/failure matrices',
    'canonical CLI service startup and clean service-user installation/upgrade/shutdown',
    'measured sustained capacity while ordinary node validation remains healthy',
    'clean authorized source identity and production-controller artifact qualification']

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--service-roles',action='store_true',
                        help='requires Linux root; exercise real distinct service UIDs in the private network namespace')
    parser.add_argument('--through',choices=('focused','build','payments','complete'),default='complete',
                        help='development stop point; never grants completed qualification')
    args=parser.parse_args()
    if args.service_roles and os.geteuid()!=0:
        raise PermissionError('--service-roles requires root to exercise distinct Linux process credentials')
    if not os.environ.get(MARKER):
        if args.service_roles:
            # Do not remap root into a one-UID user namespace: that would make
            # a claimed separate-UID installation test impossible. Networking
            # remains loopback-only, and all filesystem writes use fresh lab
            # roots. No host service, user, credential, or datadir is selected.
            env=dict(os.environ);env[MARKER]=os.readlink('/proc/self/ns/net')
            raise SystemExit(subprocess.call(['unshare','-n',sys.executable,'-m',
                'pool.qualification.run',*sys.argv[1:]],cwd=SOURCE,env=env))
        raise SystemExit(subprocess.call([sys.executable,'-m','pool.qualification.isolation','--',
            sys.executable,'-m','pool.qualification.run',*sys.argv[1:]],cwd=SOURCE))
    require_isolated_network()
    # A fresh network namespace starts with loopback DOWN. The focused HTTP
    # fixtures run before the node/service fixtures and need it immediately.
    # This happens only after proving that the namespace has no external link.
    subprocess.run(['ip','link','set','lo','up'],check=True)
    out=args.output.resolve()
    if out.is_relative_to(SOURCE):raise ValueError('evidence must be outside source')
    out.mkdir(parents=True,exist_ok=False);(out/'logs').mkdir()
    before=hashes();report={'status':'RUNNING','complete_pool_gate':False,'source_path':str(SOURCE),
        'source_manifest_sha256':hashlib.sha256(json.dumps(before,sort_keys=True).encode()).hexdigest(),
        'steps':[],'blocked':list(REMAINING),'not_authorized':['public deployment','mainnet activation',
            'real funding','release signing','push/merge/tag'],'requested_stop':args.through}
    (out/'source-hashes.json').write_text(json.dumps(before,indent=2)+'\n')
    def save():(out/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(name,module,arguments,timeout=21600):
        command=[sys.executable,'-m',module,*map(str,arguments)]
        entry={'name':name,'command':command,'status':'RUNNING'};report['steps'].append(entry);save()
        start=time.monotonic()
        with (out/'logs'/(name+'.log')).open('w') as log:
            result=subprocess.run(command,cwd=SOURCE,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
        entry.update(exit_code=result.returncode,seconds=time.monotonic()-start,status='PASS' if result.returncode==0 else 'FAILED');save()
        if result.returncode:raise RuntimeError(name+' failed; see raw log')
        print(name+' PASS',flush=True)
    def receipt(path):return json.loads(path.read_text())
    try:
        run('focused-tests','unittest',['discover','-s','pool','-t','.','-p','test_*.py'],600)
        if args.through=='focused':
            report['source_unchanged']=before==hashes()
            if not report['source_unchanged']:raise RuntimeError('source changed during focused qualification')
            report['status']='BLOCKED'
            report['blocked'].insert(0,'development stop after focused tests; native stages not executed')
            print('Focused tests passed; native qualification remains BLOCKED.',flush=True)
            return
        run('clean-native-build','pool.qualification.build',['--output',out/'build'],7200)
        run('native-focused-regressions','pool.qualification.native_regressions',
            ['--build-directory',out/'build/candidate','--output',out/'native-focused-regressions'])
        run('native-history-publication','pool.qualification.history_publication',
            ['--build-directory',out/'build/candidate','--output',out/'history-publication'])
        run('canonical-node-service','pool.qualification.node_service',
            ['--build-directory',out/'build/candidate','--output',out/'canonical-node-service'])
        if args.service_roles:
            run('native-role-installation','pool.qualification.role_install',
                ['--build-directory',out/'build/candidate','--output',out/'native-role-installation','--systemd'],25200)
        else:
            report['blocked'].append('distinct Linux service-user installation not selected; rerun as root with --service-roles')
        if args.through!='build':
            for variant in ('existing','candidate'):
                folder=out/variant;folder.mkdir();build=out/'build'/variant
                run(variant+'-worker-fixture','pool.qualification.payment_fixture',
                    ['--build-directory',build,'--output',folder/'worker-fixture'])
                fixture=receipt(folder/'worker-fixture/result.json')['fixture_path']
                run(variant+'-immature-income-reorganization','pool.qualification.income_reorg',
                    ['--fixture',fixture,'--build-directory',build,'--output',folder/'immature-income-reorganization'])
                run(variant+'-payment-recovery','pool.qualification.payment_matrix',
                    ['--fixture',fixture,'--build-directory',build,'--output',folder/'payment-recovery'])
                run(variant+'-payment-reorganization','pool.qualification.payment_reorg',
                    ['--fixture',fixture,'--build-directory',build,'--output',folder/'payment-reorganization'])
                run(variant+'-deep-reorganization-refusal','pool.qualification.payment_reorg',
                    ['--fixture',fixture,'--build-directory',build,'--output',folder/'deep-reorganization-refusal','--deep'])
                if args.through=='complete':
                    run(variant+'-native-load','pool.qualification.capacity',
                        ['--fixture',fixture,'--build-directory',build,'--output',folder/'native-load'])
        if args.through=='complete':
            run('funded-history','pool.qualification.history',['--build-directory',out/'build/existing',
                '--output',out/'history','--final-height',50000],86400)
            history=receipt(out/'history/result.json')['closed_snapshots']
            for variant in ('existing','candidate'):
                run(variant+'-comining','pool.qualification.comining',['--build-directory',out/'build'/variant,
                    '--history-state',history['comining'],'--output',out/variant/'comining'])
                run(variant+'-comining-reorganization','pool.qualification.comining',['--build-directory',out/'build'/variant,
                    '--history-state',history['comining'],'--output',out/variant/'comining-reorganization','--reorganization'])
            run('funded-first-validator','pool.qualification.validator',['--build-directory',out/'build/candidate',
                '--history-state',history['validator'],'--output',out/'candidate/validator'])
            run('native-finality-pool-carrier','pool.qualification.finality',['--build-directory',out/'build/candidate',
                '--lab-signer',out/'build/candidate/pool-lab-sign','--history-state',history['finality'],
                '--output',out/'candidate/finality'],86400)
        report['source_unchanged']=before==hashes()
        if not report['source_unchanged']:raise RuntimeError('source changed during qualification; exact final candidate not qualified')
        report['status']='BLOCKED'
        if args.through!='complete':report['blocked'].insert(0,'development stop point selected; later connected stages not executed')
    except BaseException as error:
        report.update(status='FAILED',error=repr(error));raise
    finally:
        # Evidence includes only public receipts/logs. Signing seeds, worker
        # capabilities and runtime directories stay in disposable private state.
        report['evidence_hashes']={p.relative_to(out).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for p in out.rglob('*') if p.is_file() and p.name!='qualification.json' and 'build' not in p.relative_to(out).parts}
        save()
    print('Connected exercises finished; completion gates remain explicitly BLOCKED.',flush=True)

if __name__=='__main__':main()
