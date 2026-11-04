#!/usr/bin/env python3
"""Offline, side-by-side installation. Never creates users or starts services.

Run with an explicit empty version directory and already provisioned service
users. Service activation is deliberately a separate operator decision.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil


def checked_name(value):
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', value):
        raise ValueError('invalid service user')
    return value


def verify(package):
    package = package.resolve()
    for directory in ('bin', 'lib', 'setup', 'third-party'):
        folder = package / directory
        if folder.is_symlink() or not folder.is_dir():
            raise ValueError('artifact directory missing or linked')
        if any(path.is_symlink() for path in folder.rglob('*')):
            raise ValueError('artifact symlink refused')
    manifest = package / 'pool-sha256.txt'
    lines = manifest.read_text().splitlines()
    seen = set()
    for line in lines:
        digest, name = line.split('  ', 1)
        path = package / name
        if (
            not re.fullmatch('[a-f0-9]{64}', digest)
            or name in seen
            or Path(name).is_absolute()
            or '..' in Path(name).parts
        ):
            raise ValueError('invalid artifact manifest')
        seen.add(name)
        if path.is_symlink() or not path.resolve().is_relative_to(package):
            raise ValueError('artifact path escapes package')
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('artifact hash mismatch: ' + name)
    expected = {
        path.relative_to(package).as_posix()
        for directory in ('bin', 'lib', 'setup', 'third-party')
        for path in (package / directory).rglob('*')
        if path.is_file() and '__pycache__' not in path.parts
    }
    if seen != expected:
        raise ValueError('artifact manifest is incomplete')
    # The backend has its own controller provenance. Include the exact native
    # node in the outer pool manifest too; no unverified binary substitution.
    if 'bin/veld-node' not in seen:
        raise ValueError('canonical backend absent from pool manifest')
    return hashlib.sha256(manifest.read_bytes()).hexdigest()


def unit(role, prefix, config, state, core, gateway, admin=None):
    prefix, config, state = map(str, (prefix, config, state))
    user = admin if role == 'admin' else gateway if role == 'gateway' else core
    executable = {
        'backend': 'node_service',
        'coordinator': 'service',
        'gateway': 'gateway',
        'admin': 'admin',
    }[role]
    dependencies = {
        'backend': '',
        'coordinator': 'After=veld-pool-backend.service\nRequires=veld-pool-backend.service\n',
        'gateway': 'After=veld-pool-coordinator.service\nRequires=veld-pool-coordinator.service\n',
        'admin': 'After=veld-pool-coordinator.service\nRequires=veld-pool-coordinator.service\n',
    }[role]
    writable = (
        f'{state}/ipc {state}/core {state}/anchors {state}/backend {state}/rpc'
        + (f' {state}/operator-ipc' if admin else '')
        if role not in ('gateway', 'admin')
        else ''
    )
    return f'''[Unit]
Description=Veld pool {role}
{dependencies}StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User={user}
Group={user}
SupplementaryGroups={gateway if role not in ('gateway', 'admin') else ''}
WorkingDirectory={prefix}/lib
Environment=PYTHONPATH={prefix}/lib
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 -m pool.{executable} --config {config}/{role}.json
Restart=on-failure
RestartSec=5
TimeoutStopSec=150
KillMode=mixed
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths={writable}
InaccessiblePaths={state + '/core ' + state + '/anchors ' + state + '/backend ' + state + '/rpc ' + config + '/private' if role in ('gateway', 'admin') else ''}{' ' + state + '/operator-ipc ' + config + '/admin' if role == 'gateway' and admin else ''}
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LimitNOFILE=4096
TasksMax=128
# The shipped setup permits loopback only. A reviewed private test subnet must
# be explicitly allowed before connecting another test machine.
IPAddressDeny=any
IPAddressAllow=localhost

[Install]
WantedBy=multi-user.target
'''


def stage(package, prefix, config, state, core, gateway, admin=None):
    for path in (prefix, config, state):
        if (
            not path.is_absolute()
            or '..' in path.parts
            or not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path))
        ):
            raise ValueError('absolute paths without whitespace or systemd expansion required')
    if core == gateway:
        raise ValueError('gateway and private core must use different users')
    for name in (core, gateway):
        checked_name(name)
    if admin:
        checked_name(admin)
        if admin in (core, gateway):
            raise ValueError('admin needs its own service identity')
    if prefix.resolve().is_relative_to(package):
        raise ValueError('installation must be outside the package')
    digest = verify(package)
    if prefix.exists():
        raise ValueError('side-by-side installation requires a new version directory')
    prefix.mkdir(parents=True, mode=0o755)
    for name in ('bin', 'lib', 'setup', 'third-party'):
        shutil.copytree(package / name, prefix / name, ignore=shutil.ignore_patterns('__pycache__'))
    for path in prefix.rglob('*'):
        if path.is_symlink():
            raise ValueError('symlink not permitted in installed artifact')
        if path.is_file():
            path.chmod(0o755 if path.parent.name == 'bin' else 0o644)
        elif path.is_dir():
            path.chmod(0o755)
    (prefix / 'systemd').mkdir(mode=0o755)
    for role in ('backend', 'coordinator', 'gateway') + (('admin',) if admin else ()):
        (prefix / 'systemd' / f'veld-pool-{role}.service').write_text(
            unit(role, prefix, config, state, core, gateway, admin)
        )
    (prefix / 'installation.json').write_text(
        json.dumps(
            {
                'artifact_manifest_sha256': digest,
                'prefix': str(prefix),
                'config_directory': str(config),
                'state_directory': str(state),
                'core_user': core,
                'gateway_user': gateway,
                'admin_user': admin,
                'services_enabled': False,
                'services_started': False,
            },
            indent=2,
        )
        + '\n'
    )


def main():
    parser = argparse.ArgumentParser()
    for name in ('package', 'prefix', 'config', 'state', 'core-user', 'gateway-user'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--admin-user')
    args = parser.parse_args()
    stage(
        Path(args.package).resolve(),
        Path(args.prefix),
        Path(args.config),
        Path(args.state),
        checked_name(args.core_user),
        checked_name(args.gateway_user),
        checked_name(args.admin_user) if args.admin_user else None,
    )
    print('INSTALLED_OFFLINE: units prepared; no services started or enabled')


if __name__ == '__main__':
    main()
