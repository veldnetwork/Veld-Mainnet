#!/usr/bin/env python3
"""Render a complete offline configuration set; never create keys or start services.

Values describe the private candidate network. All chain and account identities
are supplied explicitly. No mainnet endpoints, credentials or wallet defaults
are embedded. Files remain disabled until their operator reviews the setup.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import re


def absolute(value):
    path = Path(value)
    if not path.is_absolute() or not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path)):
        raise ValueError('explicit absolute Linux path required')
    if '..' in path.parts:
        raise ValueError('parent traversal is not a configuration path')
    return str(path)


def render(values):
    prefix, state, config = (absolute(values[k]) for k in ('prefix', 'state', 'config'))
    genesis = values['genesis']
    if not re.fullmatch('[0-9a-f]{64}', genesis):
        raise ValueError('RPC-order genesis must be 64 lowercase hex characters')
    if not re.fullmatch('[a-zA-Z0-9._-]{1,80}', values['profile']):
        raise ValueError('explicit compiled profile required')
    ports = [values[k] for k in ('p2p_port', 'rpc_port', 'tls_port')]
    if any(type(p) is not int or not 1024 < p <= 65535 for p in ports) or len(set(ports)) != 3:
        raise ValueError('three distinct unprivileged ports required')
    listen = ipaddress.ip_address(values['listen'])
    if listen.version != 4 or not (listen.is_loopback or listen.is_private) or listen.is_unspecified:
        raise ValueError('explicit loopback or private IPv4 listener required')
    peer = values['peer'].split(':')
    if len(peer) != 2:
        raise ValueError('explicit private peer IPv4:port required')
    host = ipaddress.ip_address(peer[0])
    if host.version != 4 or not (host.is_loopback or host.is_private) or host.is_unspecified:
        raise ValueError('private peer required')
    if not peer[1].isdecimal() or not 1024 < int(peer[1]) <= 65535:
        raise ValueError('peer port required')
    for field in ('pool_address', 'fee_address'):
        if not re.fullmatch('[1-9A-HJ-NP-Za-km-z]{25,60}', values[field]):
            raise ValueError('explicit payout address required')
    for field in ('pool_script', 'fee_script'):
        if not re.fullmatch('76a914[0-9a-f]{40}88ac', values[field]):
            raise ValueError('canonical P2PKH script required')
    if values['pool_script'] == values['fee_script']:
        raise ValueError('operator fee key must be separate from the pool identity')
    backend = dict(enabled=False, binary=prefix+'/bin/veld-node', datadir=state+'/backend',
        passphrase_file=config+'/private/backend.passphrase', rpc_token_file=state+'/rpc/token',
        genesis=genesis, profile=values['profile'], p2p_port=values['p2p_port'],
        rpc_port=values['rpc_port'], peers=[values['peer']])
    network=values.get('runtime_network','mainnet')
    if network not in ('mainnet','testnet','regtest'):
        raise ValueError('explicit runtime network required')
    backend['runtime_network']=network
    coordinator = dict(rpc_url='http://127.0.0.1:'+str(values['rpc_port']),
        rpc_token_file=state+'/rpc/token', genesis=genesis, state_directory=state+'/core/work',
        rollback_anchor=state+'/anchors/work/current.json', native_binary=prefix+'/bin/veld-pool-work',
        pool_address=values['pool_address'], accounting_target='7'+'f'*63,
        socket=state+'/ipc/coordinator.sock')
    coordinator['payments'] = dict(state_directory=state+'/core/payments',
        rollback_anchor=state+'/anchors/payments/current.json', native_binary=prefix+'/bin/veld-pool-payout',
        pool_seed=config+'/private/pool.seed', fee_seed=config+'/private/fees.seed',
        pool_script=values['pool_script'], fee_script=values['fee_script'],
        fee_address=values['fee_address'], fee_units='100000')
    if values.get('comining', False):
        coordinator['identity'] = dict(state_directory=state+'/core/identity',
            rollback_anchor=state+'/anchors/identity/current.json', native_binary=prefix+'/bin/veld-pool-identity',
            seed=config+'/private/pool.seed', script=values['pool_script'],
            operator_funding_file=config+'/private/operator-funding.json', tier=1)
    gateway = dict(host=str(listen), port=values['tls_port'], certificate=config+'/tls/certificate.pem',
        private_key=config+'/tls/private-key.pem', coordinator_socket=state+'/ipc/coordinator.sock')
    result=dict(backend=backend, coordinator=coordinator, gateway=gateway)
    if values.get('admin_uid') is not None:
        uid=values['admin_uid'];port=values.get('admin_port',24444);ceiling=values.get('approved_max_fee_ppm',0)
        if type(uid) is not int or uid<=0:raise ValueError('non-root admin UID required')
        if type(port) is not int or not 1024<port<=65535 or port in ports:raise ValueError('distinct admin port required')
        if type(ceiling) is not int or not 0<=ceiling<=100000:raise ValueError('approved fee ceiling required')
        coordinator['operator']=dict(socket=state+'/operator-ipc/operator.sock',uid=uid,max_fee_ppm=str(ceiling))
        result['admin']=dict(host='127.0.0.1',port=port,certificate=config+'/admin/certificate.pem',
            private_key=config+'/admin/private-key.pem',credential_file=config+'/admin/access.json',
            operator_socket=coordinator['operator']['socket'])
    return result


def main():
    parser = argparse.ArgumentParser()
    for name in ('prefix', 'state', 'config', 'genesis', 'profile', 'peer', 'listen',
                 'pool-address', 'pool-script', 'fee-address', 'fee-script'):
        parser.add_argument('--'+name, required=True)
    for name in ('p2p-port', 'rpc-port', 'tls-port'):
        parser.add_argument('--'+name, type=int, required=True)
    parser.add_argument('--comining', action='store_true')
    parser.add_argument('--runtime-network',choices=('mainnet','testnet','regtest'),required=True)
    parser.add_argument('--admin-user')
    parser.add_argument('--admin-port',type=int,default=24444)
    parser.add_argument('--approved-max-fee-ppm',type=int,default=0)
    args = parser.parse_args()
    if args.admin_user:
        import pwd
        args.admin_uid=pwd.getpwnam(args.admin_user).pw_uid
    configs = render(vars(args))
    output = Path(args.config)
    if output.exists():
        raise ValueError('configuration directory must be new; never overwrite an existing service')
    output.mkdir(parents=True, mode=0o700)
    for name, value in configs.items():
        path = output/(name+'.json')
        with path.open('x') as file:
            file.write(json.dumps(value, indent=2)+'\n')
        path.chmod(0o600)
    print('CONFIGURED_OFFLINE: backend disabled; no keys, funding or connections created')


if __name__ == '__main__':
    main()
