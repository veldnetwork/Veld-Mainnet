#!/usr/bin/env python3
"""Reject non-system DLL dependencies and exercise CLI roles without build PATH."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import subprocess

SYSTEM_DLLS = {
    'kernel32.dll', 'ntdll.dll', 'msvcrt.dll', 'ucrtbase.dll', 'advapi32.dll',
    'bcrypt.dll', 'crypt32.dll', 'ws2_32.dll', 'iphlpapi.dll', 'shell32.dll',
    'ole32.dll', 'oleaut32.dll', 'uuid.dll', 'gdi32.dll', 'user32.dll',
    'winhttp.dll', 'comctl32.dll', 'comdlg32.dll', 'dwmapi.dll', 'secur32.dll',
    'userenv.dll', 'version.dll', 'normaliz.dll', 'shlwapi.dll', 'rpcrt4.dll',
}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--imports', required=True, type=Path)
    parser.add_argument('--role', required=True)
    args = parser.parse_args()
    imports = re.findall(r'DLL Name:\s*(\S+)', args.imports.read_text())
    if not imports:
        raise RuntimeError('No PE imports were inspected')
    unexpected = [name for name in imports if name.lower() not in SYSTEM_DLLS
                  and not name.lower().startswith(('api-ms-win-', 'ext-ms-win-'))]
    if unexpected:
        raise RuntimeError('Unbundled non-system DLL imports: ' + ', '.join(unexpected))
    checks = []
    if args.role != 'gui':
        ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002 | 0x8000)
        env = {key: value for key, value in os.environ.items()
               if key.lower() not in ('path', 'psmodulepath', 'openssl_conf', 'openssl_modules')}
        root = Path(os.environ.get('SystemRoot', r'C:\Windows'))
        env['PATH'] = str(root / 'System32') + ';' + str(root)
        for flag in ('--version', '--deployment-info'):
            result = subprocess.run([str(args.binary.resolve()), flag],
                                    cwd=args.binary.resolve().parent, env=env,
                                    capture_output=True, text=True, timeout=30,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode != 0 or not result.stdout.strip():
                raise RuntimeError(f'{flag} failed with Windows-only PATH: exit {result.returncode}')
            checks.append(flag)
    print(json.dumps(dict(result='PASS_WINDOWS_SYSTEM_RUNTIME', role=args.role,
                          imports=imports, clean_path_checks=checks)))

if __name__ == '__main__':
    main()
