"""Windows ACL setup for disposable correctness-test files only."""
import os
from pathlib import Path
import subprocess


def protect_fixture(path, extra=""):
    if os.name != "nt":
        return
    path = Path(path).resolve(strict=True)
    if not path.is_file() or extra not in ("", "Read", "Modify"):
        raise ValueError("expected a disposable regular test file")
    script = r"""$ErrorActionPreference = 'Stop'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetOwner($identity)
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')
$acl.AddAccessRule($rule)
if ($env:VELD_FIXTURE_EXTRA) {
    $world = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($world, $env:VELD_FIXTURE_EXTRA, 'Allow')
    $acl.AddAccessRule($rule)
}
[System.IO.File]::SetAccessControl($env:VELD_FIXTURE_FILE, $acl)
"""
    env = dict(os.environ, VELD_FIXTURE_FILE=str(path), VELD_FIXTURE_EXTRA=extra)
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, env=env, timeout=30)
    if result.returncode:
        raise RuntimeError("disposable Windows ACL setup failed: " + result.stderr)
