"""Native Windows isolated-profile artifacts and bounded component checks.

No installed client replacement, wallet discovery, mainnet connection or miner
launch on a public network. Native process ownership tests use closed loopback
with the real worker and disposable controls.
This is not the production controller or complete interactive GUI acceptance.
"""
import argparse,datetime,hashlib,json,os,pathlib,subprocess,sys,traceback
S=pathlib.Path(__file__).resolve().parents[2]
if os.name!='nt':raise SystemExit('native Windows execution is required')
parser=argparse.ArgumentParser()
parser.add_argument('--output',type=pathlib.Path,required=True)
parser.add_argument('--toolchain',type=pathlib.Path,default=pathlib.Path('C:/msys64/clang64'))
args=parser.parse_args();O=args.output.resolve()
if O.is_relative_to(S):raise ValueError('evidence must be outside the source worktree')
O.mkdir(parents=True,exist_ok=False)
for name in ('objects','bin','logs'):(O/name).mkdir()
C=args.toolchain.resolve();env=dict(os.environ,PATH=str(C/'bin')+os.pathsep+os.environ['PATH'],PYTHONDONTWRITEBYTECODE='1')
sys.path.insert(0,str(S));from pool.qualification.build import hashes
before=hashes();report=dict(status='RUNNING',pid=os.getpid(),native_windows=True,
    production_build=False,complete_gui_acceptance=False,mainnet_writes=False,
    source_manifest_sha256=hashlib.sha256(json.dumps(before,sort_keys=True).encode()).hexdigest(),commands=[],binaries={})
(O/'source-hashes.json').write_text(json.dumps(before,indent=2)+'\n')
def save():
    report['updated_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    t=O/'result.json.new';t.write_text(json.dumps(report,indent=2)+'\n');t.replace(O/'result.json')
def run(name,command,limit=1800):
    assert hashes()==before,'source changed; rebuild required'
    step=dict(name=name,command=list(map(str,command)),status='RUNNING');report['commands'].append(step);save()
    with (O/'logs'/(name+'.log')).open('w') as log:
        result=subprocess.run(step['command'],cwd=S,env=env,stdout=log,stderr=subprocess.STDOUT,
            timeout=limit,creationflags=subprocess.CREATE_NO_WINDOW)
    step.update(status='PASS' if result.returncode==0 else 'FAILED',exit_code=result.returncode);save()
    if result.returncode:raise RuntimeError(name+' failed; see exact log')
    print(name+' PASS',flush=True)
try:
    run('compiler',[C/'bin/clang++.exe','--version'])
    run('pqc-provenance',[sys.executable,S/'scripts/verify-pqc-provenance.py'])
    objects=[]
    for n,line in enumerate((S/'vendor/pqc/provenance/release-c-sources.txt').read_text().splitlines()):
        if not line or line.startswith('#'):continue
        obj=O/'objects'/('pqc-'+str(n)+'.o')
        run('pqc-'+str(n),[C/'bin/clang.exe','-std=c11','-O2','-Ivendor/pqc','-Ivendor/pqc/mldsa65','-c',line,'-o',obj]);objects.append(str(obj))
    resource=O/'objects/gui-resource.o'
    run('resources',[C/'bin/llvm-windres.exe','-I.','resources/veld-node.rc','-O','coff','-o',resource])
    defines=['-DVELD_MAINNET_POW','-DVELD_TEST_CHAIN_BUILD','-DVELD_TEST_HOOKS','-DVELD_DSTATE_QUALIFICATION',
        '-DVELD_ASERT_TESTCHAIN','-DVELD_PROTOCOL_UPGRADE_TEST_HEIGHT=3840','-DVELD_VALIDATOR_REGISTRATION_FORK_TEST_HEIGHT=9500']
    archives=[str(C/'lib'/n) for n in ('libc++.a','libc++abi.a','libunwind.a','libssl.a','libcrypto.a')]
    libraries=['-lws2_32','-ladvapi32','-lbcrypt','-lcrypt32','-liphlpapi','-lshell32','-lole32','-luuid','-lgdi32',
        '-lwinhttp','-lcomctl32','-lcomdlg32','-ldwmapi','-luser32']
    for name,path,extra,more in [
        ('veld-pool-client.exe','src/veld-pool-client.cpp',[],[]),
        ('Veld Pool Qualification.exe','src/veld-node-gui.cpp',
            ['-DVELD_GUI_TEST_INSTANCE','-DVELD_POOL_GUI_QUALIFICATION','-D_WIN32_WINNT=0x0A00','-DWINVER=0x0A00','-mwindows','-municode'],objects+[str(resource)]),
        ('panel-regression.exe','tests/pool_panel_redraw_tests.cpp',[],objects),
        ('diagnostics.exe','tests/pool_client_diagnostics_tests.cpp',[],[]),
        ('worker-ownership.exe','tests/pool_gui_worker_ownership_tests.cpp',['-municode'],objects),
        ('transport.exe','tests/pool_transport_probe.cpp',[],[])]:
        binary=O/name if name.startswith('Veld ') else O/'bin'/name
        run('build-'+name,[C/'bin/clang++.exe','-std=c++20','-O2','-pthread','-nostdlib++','-Iinclude','-Ivendor/pqc',
            *defines,*extra,path,*more,*archives,*libraries,'-o',binary])
        run('imports-'+name,[C/'bin/llvm-objdump.exe','-p',binary])
        report['binaries'][binary.relative_to(O).as_posix()]=hashlib.sha256(binary.read_bytes()).hexdigest();save()
    run('native-panel-regression',[O/'bin/panel-regression.exe'],120)
    run('native-diagnostics',[O/'bin/diagnostics.exe'],120)
    run('native-worker-ownership',[O/'bin/worker-ownership.exe',O/'bin/veld-pool-client.exe'],180)
    run('native-transport-faults',[sys.executable,'-m','pool.test_client_transport','--binary',O/'bin/transport.exe',
        '--openssl',C/'bin/openssl.exe'],360)
    report.update(status='PASS_SCOPED_WINDOWS_COMPONENTS',source_unchanged=hashes()==before)
    assert report['source_unchanged']
except BaseException as error:
    report.update(status='FAILED',error=str(error));(O/'failure.txt').write_text(traceback.format_exc());raise
finally:save()
