"""Windows qualification of the reviewed native payout signer; disposable coins."""
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f,'sha256').hexdigest()


def main():
    assert os.name=='nt'
    source=Path(__file__).resolve().parents[1]
    root=Path(os.environ['LOCALAPPDATA'])/'Temp/veld-native-payout-signing-windows-20261013-r1'
    root.mkdir(exist_ok=False)
    report=dict(status='PREPARING',started_at=datetime.now(timezone.utc).isoformat(),commands=[],inputs={},
                real_funds=False,production_deployed=False)
    def save():(root/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(label,argv,timeout=600):
        command=list(map(str,argv));row=dict(label=label,argv=command)
        report['commands'].append(row);save();print('START '+label,flush=True)
        with (root/(label+'.log')).open('xb') as log:
            p=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                               creationflags=subprocess.CREATE_NO_WINDOW|subprocess.BELOW_NORMAL_PRIORITY_CLASS)
            row['pid']=p.pid;save()
            try:row['exit']=p.wait(timeout)
            except BaseException:p.kill();p.wait();raise
        row['log_sha256']=sha(root/(label+'.log'));save()
        assert row['exit']==0,label+' failed'
        print('PASS '+label,flush=True)
    try:
        k=ctypes.WinDLL('kernel32',use_last_error=True)
        k.GetCurrentProcess.restype=ctypes.c_void_p
        k.SetProcessAffinityMask.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
        assert k.SetProcessAffinityMask(k.GetCurrentProcess(),(1<<6)|(1<<7))
        report['processor_affinity']=[6,7]
        frozen=root/'source';frozen.mkdir()
        for folder in ('include','vendor/pqc'):shutil.copytree(source/folder,frozen/folder)
        (frozen/'tests').mkdir()
        for name in ('appchain_bridge_fixture.h','appchain_payout_tests.cpp'):
            shutil.copyfile(source/'tests'/name,frozen/'tests'/name)
        corpus=root/'corpus';corpus.mkdir()
        destination='/mnt/c/'+corpus.as_posix()[3:]
        run('copy-corpus',['wsl','-d','Ubuntu','-u','root','--','python3','-c',
            'from pathlib import Path; import shutil,sys; a=Path("/var/tmp/veld-native-bridge-20261012-r1-history"); b=Path(sys.argv[1]); '
            '[(shutil.copyfile(a/(str(h)+".block"),b/(str(h)+".block"))) for h in range(704)]',destination],120)
        prior=Path(os.environ['LOCALAPPDATA'])/'Temp/veld-native-public-windows-20261012-r2'
        for p in (frozen/'vendor/pqc').rglob('*'):
            if p.is_file():assert sha(p)==sha(prior/'source/vendor/pqc'/p.relative_to(frozen/'vendor/pqc'))
        objects=sorted((prior/'node/obj').glob('*.o'));assert len(objects)==11
        toolchain=Path('C:/msys64/clang64')
        compiler=toolchain/'bin/clang++.exe'
        libraries=[toolchain/'lib'/name for name in ('libc++.a','libc++abi.a','libunwind.a','libssl.a','libcrypto.a')]
        for p in [*frozen.rglob('*'),*corpus.iterdir(),*objects,compiler,*libraries,Path(__file__)]:
            if p.is_file():report['inputs'][str(p)]=sha(p)
        binary=root/'payout-tests.exe'
        run('compile',[compiler,'-std=c++20','-O1','-DNDEBUG','-pthread','-nostdlib++',
            '-DVELD_MAINNET_POW','-DVELD_DSTATE_QUALIFICATION',
            '-I'+str(frozen/'include'),'-I'+str(frozen/'vendor/pqc'),'-I'+str(frozen/'vendor/pqc/mldsa65'),
            frozen/'tests/appchain_payout_tests.cpp',*objects,*libraries,
            '-lws2_32','-ladvapi32','-lbcrypt','-lcrypt32','-liphlpapi','-lshell32','-lole32','-luuid','-lgdi32',
            '-o',binary],900)
        report['binary_sha256']=sha(binary);save()
        run('payout',[binary,corpus,root/'history'],900)
        result=json.loads((root/'history/result.json').read_text())
        assert result['status']=='PASS_UNSIGNED_NATIVE_PAYOUT_PLANNER'
        for file,digest in report['inputs'].items():assert sha(Path(file))==digest,file
        admissions=sum(s.startswith('PASS full parent validation h=') for s in (root/'payout.log').read_text().splitlines())
        report.update(status='PASS_WINDOWS_REVIEWED_NATIVE_PAYOUT_SIGNING',result=result,
                      parent_block_admissions=admissions,focused_checks=result['checks']-admissions,
                      all_owned_processes_stopped=True)
    except BaseException as error:report.update(status='FAILED',error=repr(error));raise
    finally:report['finished_at']=datetime.now(timezone.utc).isoformat();save()
    print(report['status'],flush=True)


if __name__=='__main__':main()
