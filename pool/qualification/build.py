"""Clean native builds for the explicitly isolated qualification profile.

These are NOT public-release artifacts or substitutes for the production build
controller. Source hashes record the actual dirty tree without inventing a Git
identity. Both unchanged rules and a future validator activation are compiled.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from .isolation import require_isolated_network

SOURCE=Path(__file__).resolve().parents[2]
BASE=['-DVELD_MAINNET_POW','-DVELD_TEST_CHAIN_BUILD','-DVELD_TEST_HOOKS',
      '-DVELD_DSTATE_QUALIFICATION','-DVELD_ASERT_TESTCHAIN','-DVELD_PROTOCOL_UPGRADE_TEST_HEIGHT=3840']

def hashes():
    return {p.relative_to(SOURCE).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for folder in ('include','src','tests','vendor/pqc','pool','pkg/pool')
            for p in (SOURCE/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts
            and p.suffix not in ('.pyc','.exe','.o')}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();require_isolated_network();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    if out.is_relative_to(SOURCE):raise ValueError('build output must be outside source')
    (out/'logs').mkdir();(out/'obj').mkdir();before=hashes()
    git_env=dict(os.environ)
    link=SOURCE/'.git'
    if link.is_file():
        location=link.read_text().strip().removeprefix('gitdir: ')
        # A Windows-created worktree retains a Windows absolute gitdir. Map
        # that existing metadata for WSL; never rewrite it or fabricate a tree.
        if len(location)>3 and location[0].isalpha() and location[1:3]==':/':
            metadata=Path('/mnt')/location[0].lower()/location[3:]
            if not metadata.is_dir():raise ValueError('existing Git metadata is unavailable')
            git_env.update(GIT_DIR=str(metadata),GIT_WORK_TREE=str(SOURCE))
    def git(*args):return subprocess.check_output(['git',*args],cwd=SOURCE,env=git_env,text=True,timeout=60).strip()
    try:dirty_status=git('-c','core.fsmonitor=false','status','--short')
    except subprocess.TimeoutExpired:
        # Test-only compilation can still attest the actual source file set.
        # An unavailable status is never represented as clean provenance, and
        # the production controller retains its mandatory clean-checkout gate.
        dirty_status='UNAVAILABLE: Git status exceeded 60 seconds; clean provenance is NOT established'
    report={'scope':'isolated native qualification only','status':'RUNNING','source_path':str(SOURCE),
            'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),
            'branch':git('rev-parse','--abbrev-ref','HEAD'),'dirty_status':dirty_status,
            'source_hashes':before,'commands':[],'binaries':{},'production_build':False}
    def save():(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(name,command,timeout=1800):
        start=time.monotonic()
        with (out/'logs'/(name+'.log')).open('w') as log:
            result=subprocess.run(command,cwd=SOURCE,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
        report['commands'].append({'name':name,'argv':command,'exit_code':result.returncode,
                                   'seconds':time.monotonic()-start});save()
        if result.returncode:raise RuntimeError(name+' failed; see recorded log')
        print(name+' PASS',flush=True)
    try:
        for name,command in [('compiler',['c++','--version']),('c-compiler',['cc','--version']),
                             ('python',[sys.executable,'--version']),('openssl',['openssl','version','-a']),
                             ('openssl-pkgconfig',['pkg-config','--modversion','openssl']),
                             ('library-packages',['dpkg-query','--show','libssl-dev','libleveldb-dev'])]:run(name,command)
        run('pqc-provenance',[sys.executable,'scripts/verify-pqc-provenance.py'])
        objects=[]
        for index,line in enumerate((SOURCE/'vendor/pqc/provenance/release-c-sources.txt').read_text().splitlines()):
            if not line or line.startswith('#'):continue
            obj=str(out/'obj'/f'pqc-{index}.o');objects.append(obj)
            run('pqc-'+str(index),['cc','-std=c11','-O2','-Ivendor/pqc','-Ivendor/pqc/mldsa65','-c',line,'-o',obj])
        for variant,height in [('existing',0),('candidate',9500)]:
            target=out/variant;target.mkdir()
            for name,source,stateful in [
                ('pool-work','src/veld-pool-work.cpp',False),('pool-client','src/veld-pool-client.cpp',False),
                ('pool-identity','src/veld-pool-identity.cpp',False),('pool-payout','src/veld-pool-payout.cpp',False),
                ('pool-lab-keys','tests/pool_lab_keys.cpp',False),('pool-lab-sign','tests/pool_lab_sign.cpp',False),
                ('pool-backend','tests/pool_native_backend.cpp',True)]:
                flags=BASE+['-DVELD_VALIDATOR_REGISTRATION_FORK_TEST_HEIGHT='+str(height)]
                if stateful:flags+=['-DVELD_USE_LEVELDB','-DVELD_LIGHT_VERIFY']
                binary=target/name
                run(variant+'-'+name,['c++','-std=c++20','-O2','-g0','-pthread',*flags,'-Iinclude','-Ivendor/pqc',
                     source,*objects,'-lleveldb','-lssl','-lcrypto','-o',str(binary)])
                report['binaries'][str(binary.relative_to(out))]=hashlib.sha256(binary.read_bytes()).hexdigest();save()
        # The shipped service wrapper is exercised against the actual CLI
        # entrypoint too. Its test-only chain identity cannot reach mainnet.
        run('canonical-cli',['c++','-std=c++20','-O2','-g0','-pthread',*BASE,
            '-DVELD_VALIDATOR_REGISTRATION_FORK_TEST_HEIGHT=9500','-DVELD_USE_LEVELDB','-DVELD_LIGHT_VERIFY',
            '-Iinclude','-Ivendor/pqc','src/veld-node.cpp',*objects,'-lleveldb','-lssl','-lcrypto',
            '-o',str(out/'candidate/veld-node')])
        report['binaries']['candidate/veld-node']=hashlib.sha256((out/'candidate/veld-node').read_bytes()).hexdigest()
        run('native-history-race',['c++','-std=c++20','-O2','-g0','-pthread',*BASE,
            '-DVELD_VALIDATOR_REGISTRATION_FORK_TEST_HEIGHT=9500','-DVELD_USE_LEVELDB','-DVELD_LIGHT_VERIFY',
            '-Iinclude','-Ivendor/pqc','tests/pool_history_publication_race.cpp',*objects,'-lleveldb','-lssl','-lcrypto',
            '-o',str(out/'candidate/history-race')])
        report['binaries']['candidate/history-race']=hashlib.sha256((out/'candidate/history-race').read_bytes()).hexdigest()
        for name, source in [('download-continuation','tests/pool_download_continuation_tests.cpp'),
                             ('settlement-history','tests/pool_settlement_history_tests.cpp')]:
            binary=out/'candidate'/name
            # These files explicitly declare their synthetic regression profile.
            # They do not replace the real native worker/settlement/fork gates.
            run('regression-'+name,['c++','-std=c++20','-O2','-g0','-pthread','-Iinclude','-Ivendor/pqc',
                source,*objects,'-lssl','-lcrypto','-o',str(binary)])
            report['binaries']['candidate/'+name]=hashlib.sha256(binary.read_bytes()).hexdigest()
        report['source_unchanged']=before==hashes()
        if not report['source_unchanged']:raise RuntimeError('source changed while building; fresh build required')
        report['status']='PASS'
    except BaseException as error:
        report.update(status='FAILED',error=repr(error));raise
    finally:save()

if __name__=='__main__':main()
