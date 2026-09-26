"""Supervise the canonical node; export only its local RPC capability.

The node, coordinator and constrained signers are the private core trust domain.
The public gateway runs as another user and cannot read this configuration,
the exported capability, the backend passphrase or any signing material.
"""

import argparse
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

from .backend import Node
from .journal import atomic, private_directory
from .private_file import read_private
from .protocol import decode, schema, require, hex64

PREFIX = 'VELD_DEPLOYMENT_INFO_V1_JSON '


def deployment(binary):
    probe = subprocess.run(
        [binary, '--deployment-info'], capture_output=True, check=True, timeout=15
    )
    require(len(probe.stdout) <= 16384, 'node identity response bound')
    lines = probe.stdout.decode('ascii').splitlines()
    lines = [line[len(PREFIX) :] for line in lines if line.startswith(PREFIX)]
    require(len(lines) == 1, 'node identity record')
    return decode(lines[0].encode())


def validate_deployment(identity, config):
    require(
        identity.get('binary_role') == 'node'
        and identity.get('fleet_no_mine') is False
        and identity.get('mining_rpc_methods_compiled') is True,
        'dedicated mining-capable backend required',
    )
    # Deployment metadata reports the compiled GENESIS_HASH byte sequence.
    # RPC getcompiledgenesis/getblockhash use HashToHex, which reverses it.
    # Keep the service configuration in the same canonical order as the RPC,
    # coordinator and workers rather than comparing unlike representations.
    compiled = hex64(identity.get('genesis_fingerprint'))
    rpc_genesis = bytes.fromhex(compiled)[::-1].hex()
    require(
        identity.get('profile_id') == config['profile'] and rpc_genesis == config['genesis'],
        'backend profile/genesis mismatch',
    )
    if config.get('runtime_network', 'mainnet') != 'mainnet':
        require(
            identity.get('disposable') is True and identity.get('external_value') is False,
            'alternate transport requires an explicitly disposable artifact',
        )


def configuration(value):
    value = dict(value)
    value.setdefault('runtime_network', 'mainnet')
    schema(
        value,
        (
            'enabled',
            'binary',
            'datadir',
            'passphrase_file',
            'rpc_token_file',
            'genesis',
            'profile',
            'p2p_port',
            'rpc_port',
            'peers',
            'runtime_network',
        ),
    )
    require(
        value['enabled'] is True, 'backend disabled; review the private network configuration first'
    )
    hex64(value['genesis'])
    for field in ('binary', 'datadir', 'passphrase_file', 'rpc_token_file'):
        require(
            isinstance(value[field], str) and Path(value[field]).is_absolute(), 'absolute ' + field
        )
    for field in ('p2p_port', 'rpc_port'):
        require(type(value[field]) is int and 1024 < value[field] <= 65535, 'port range')
    require(value['p2p_port'] != value['rpc_port'], 'distinct node ports')
    require(
        isinstance(value['profile'], str) and 1 <= len(value['profile']) <= 80, 'profile identity'
    )
    require(
        value['runtime_network'] in ('mainnet', 'testnet', 'regtest'), 'explicit runtime network'
    )
    require(
        isinstance(value['peers'], list) and 1 <= len(value['peers']) <= 32,
        'explicit peer endpoints required',
    )
    import ipaddress

    for peer in value['peers']:
        require(isinstance(peer, str) and peer.count(':') == 1, 'explicit IPv4 peer and port')
        host, port = peer.split(':')
        ipaddress.IPv4Address(host)
        require(
            port.isdecimal() and str(int(port)) == port and 1024 < int(port) <= 65535, 'peer port'
        )
    return value


def command(config):
    # Never start a competing solo miner or use default peer discovery. All
    # block construction/submission remains in the canonical node RPC path.
    return [
        config['binary'],
        '--no-prompt',
        '--nomine',
        '--full-ibd',
        '--txindex',
        *network_arguments(config),
        '--datadir',
        config['datadir'],
        '--p2pport',
        str(config['p2p_port']),
        '--rpcport',
        str(config['rpc_port']),
        *[part for peer in config['peers'] for part in ('--connect', peer)],
    ]


def network_arguments(config):
    network = config.get('runtime_network', 'mainnet')
    require(network in ('mainnet', 'regtest', 'testnet'), 'runtime network')
    return [] if network == 'mainnet' else ['--' + network]


def export_token(config):
    password = read_private(config['passphrase_file'], 1024).decode('utf-8').rstrip('\r\n')
    require(
        len(password) >= 16 and '\x00' not in password and '\n' not in password,
        'backend passphrase unavailable',
    )
    env = dict(os.environ)
    env['VELD_VAULT_PASSPHRASE'] = password
    try:
        probe = subprocess.run(
            [
                config['binary'],
                *network_arguments(config),
                '--datadir',
                config['datadir'],
                '--print-rpc-token',
            ],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=True,
        )
    finally:
        env.pop('VELD_VAULT_PASSPHRASE', None)
    token = probe.stdout.strip()
    require(
        len(token) == 64 and all(c in b'0123456789abcdef' for c in token), 'node RPC export refused'
    )
    atomic(Path(config['rpc_token_file']), token + b'\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    config = configuration(decode(read_private(args.config, 16384)))
    identity = deployment(config['binary'])
    validate_deployment(identity, config)
    private_directory(config['datadir'])
    private_directory(Path(config['rpc_token_file']).parent)
    # A previous process's capability must not masquerade as current readiness.
    Path(config['rpc_token_file']).unlink(missing_ok=True)
    password = read_private(config['passphrase_file'], 1024).decode('utf-8').rstrip('\r\n')
    require(
        len(password) >= 16 and '\x00' not in password and '\n' not in password,
        'backend passphrase unavailable',
    )
    env = dict(os.environ)
    env['VELD_VAULT_PASSPHRASE'] = password
    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stop.set())
    process = subprocess.Popen(command(config), env=env, stdin=subprocess.DEVNULL)
    env.pop('VELD_VAULT_PASSPHRASE', None)
    password = ''
    token_state = None
    rpc = Node(
        'http://127.0.0.1:' + str(config['rpc_port']), config['rpc_token_file'], config['genesis']
    )
    try:
        while not stop.wait(1):
            require(process.poll() is None, 'canonical node exited; supervisor will restart it')
            source = Path(config['datadir']) / 'rpc.token'
            if not source.exists():
                continue
            info = source.stat()
            current = (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size)
            if token_state != current:
                # No stale fallback if the encrypted token rotates unsuccessfully.
                Path(config['rpc_token_file']).unlink(missing_ok=True)
                export_token(config)
                token_state = current
            try:
                rpc.check_chain()
            except (OSError, RuntimeError, ValueError):
                continue
    finally:
        Path(config['rpc_token_file']).unlink(missing_ok=True)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    main()
