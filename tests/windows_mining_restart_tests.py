"""Exercise the launcher's real retry dispatch in a disposable cmd session.

Only the node invocation and terminal labels are adapted: the fixture child
returns controlled exit codes, and the terminal labels never run an updater.
The signed-package verification and actual node launch are qualified separately.
"""
from pathlib import Path
import argparse, os, subprocess, tempfile

parser=argparse.ArgumentParser()
parser.add_argument('--launcher',type=Path,default=Path(__file__).resolve().parents[1]/'pkg/Start Mining.bat')
args=parser.parse_args()
if os.name!='nt':
    raise SystemExit('BLOCKED: native Windows cmd is required')
text=args.launcher.read_text(encoding='utf-8')
start=text.index('set _restart_count=0')
end=text.index('REM -- Mandatory-update relaunch',start)
loop=text[start:end]
invocation='"%~dp0bin\\veld-node.exe" --mine !NETFLAG! !SYNCFLAG! --datadir "%~dp0veld-data"'
assert loop.count(invocation)==1,'launcher invocation changed; inspect the qualification adapter'
loop=loop.replace(invocation,'call "%~dp0fixture-child.cmd"')
with tempfile.TemporaryDirectory(prefix='veld-restart-qualification-') as temp:
    root=Path(temp)
    launcher=root/'launcher.cmd'
    launcher.write_text('@echo off\nsetlocal EnableExtensions EnableDelayedExpansion\n'+loop+'''
:final_exit
echo FIXTURE_INSPECT
exit /b 76
:user_stop
echo FIXTURE_STOP
exit /b 0
:relaunch_for_update
echo FIXTURE_UPDATE
exit /b 77
''',encoding='utf-8')
    cmd=Path(os.environ['SystemRoot'])/'System32/cmd.exe'
    for child_code,expected_exit,expected_count in [(75,76,4),(0,0,1),(76,76,1),(77,77,1),(-1073741510,0,1)]:
        (root/'calls.txt').write_text('0',encoding='ascii')
        (root/'fixture-child.cmd').write_text('''@echo off
set /p fixture_calls=<"%~dp0calls.txt"
set /a fixture_calls+=1
>"%~dp0calls.txt" echo !fixture_calls!
if !fixture_calls! GTR 6 exit /b 0
exit /b '''+str(child_code)+'\n',encoding='ascii')
        result=subprocess.run([str(cmd),'/d','/c',str(launcher)],cwd=root,
                              capture_output=True,text=True,timeout=20,
                              creationflags=subprocess.CREATE_NO_WINDOW)
        calls=int((root/'calls.txt').read_text())
        assert (result.returncode,calls)==(expected_exit,expected_count),result.stdout+result.stderr
        print(f'PASS launcher child_exit={child_code} launches={calls} final_exit={result.returncode}')
