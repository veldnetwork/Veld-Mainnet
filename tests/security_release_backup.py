"""Native Windows ACL-preserving copies of disposable stopped datadirs."""
from pathlib import Path
import shutil, subprocess

def private_copy(source,destination,root):
    executable=shutil.which('pwsh') or shutil.which('powershell')
    if not executable:raise RuntimeError('PowerShell is required to preserve Windows datadir ACLs')
    result=subprocess.run([executable,'-NoProfile','-File',str(Path(__file__).with_name('security_release_private_backup.ps1')),
        '-Source',str(source),'-Destination',str(destination),'-FixtureRoot',str(root)],capture_output=True,text=True)
    if result.returncode:raise RuntimeError('private backup failed: '+result.stdout+result.stderr)
    return result.stdout.strip()
