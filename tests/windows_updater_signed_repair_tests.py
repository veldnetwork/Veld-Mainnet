"""Exercise repair of a historical DLL-dependent package with signed fixtures."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import urllib.request
import zipfile


PACKAGES = {
    '3.1.3': 'b7290cd9a3c589c78437d289c3d058f9027db34e0df67e818bb2ae451bad4ca3',
    '3.1.6': '01fe6745793a07190b899750638f3b148a946accdf4614728502ea6c85fe4b51',
}


def main():
    if os.name != 'nt':
        raise SystemExit('This qualification requires Windows PowerShell.')
    root = Path(tempfile.mkdtemp(prefix='veld-signed-repair-')).resolve()
    maximum = 256 * 1024 * 1024
    for version, expected in PACKAGES.items():
        archive = root / (version + '.zip')
        request = urllib.request.Request(
            'https://veld.network/downloads/VeldClient-Windows-x64-' + version + '.zip',
            headers={'Accept-Encoding': 'identity', 'User-Agent': 'VELD-Updater-Qualification/3.1.7'})
        digest = hashlib.sha256()
        count = 0
        with urllib.request.urlopen(request, timeout=60) as response, archive.open('xb') as out:
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > maximum:
                    raise RuntimeError('Signed fixture exceeds archive limit')
                digest.update(chunk)
                out.write(chunk)
        if digest.hexdigest() != expected:
            raise RuntimeError('Historical fixture hash mismatch: ' + version)
        destination = root / version
        destination.mkdir()
        with zipfile.ZipFile(archive) as package:
            entries = package.infolist()
            if len(entries) > 4096 or sum(entry.file_size for entry in entries) > maximum * 2:
                raise RuntimeError('Fixture expansion limit exceeded')
            for entry in entries:
                if not (destination / entry.filename).resolve().is_relative_to(destination):
                    raise RuntimeError('Fixture path escaped its directory')
            package.extractall(destination)
    env = {key: value for key, value in os.environ.items()
           if key.upper() not in {'PATH', 'PSMODULEPATH', 'OPENSSL_CONF', 'OPENSSL_MODULES'}}
    system_root = Path(os.environ['SystemRoot'])
    powershell = system_root / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    env['PATH'] = os.pathsep.join(map(str, (system_root / 'System32', system_root, powershell.parent)))
    subprocess.run([
        str(powershell), '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        str(Path(__file__).with_name('windows_updater_repair_verifier_tests.ps1')),
        '-PreviousPackage', str(root / '3.1.3'), '-RepairPackage', str(root / '3.1.6'),
        '-Output', str(root / 'repaired client'),
    ], env=env, check=True, timeout=90, creationflags=subprocess.CREATE_NO_WINDOW)
    result = json.loads((root / 'repaired client/veld-data/repair-test-result.json').read_text(encoding='utf-8-sig'))
    if result['result'] != 'PASS' or result['before'] != '3.1.3' or result['after'] != '3.1.6':
        raise RuntimeError('Signed repair did not produce the expected runtime receipt')
    print('PASS: pinned signed fixtures, native verification, repair, and persistent state')


if __name__ == '__main__':
    main()
