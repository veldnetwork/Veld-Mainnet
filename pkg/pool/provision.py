#!/usr/bin/env python3
"""Apply the reviewed Linux filesystem layout without creating users or keys.

Requires existing distinct service accounts and explicit configuration/state
roots. Never starts services, changes network settings or moves wallet funds.
"""
import argparse
import os
from pathlib import Path
import pwd
import stat

def safe_path(path):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts or len(path.parts)<3:
        raise ValueError('explicit non-root absolute service directory required')
    for parent in (*reversed(path.parents),path):
        if parent.is_symlink():raise ValueError('linked service path refused')
    return path

def layout(config,state,core_uid,core_gid,gateway_uid,gateway_gid):
    if os.geteuid()!=0:raise PermissionError('filesystem provisioning requires root')
    if (core_uid<=0 or gateway_uid<=0 or core_uid==gateway_uid or core_gid==gateway_gid or
            min(core_gid,gateway_gid)<=0):
        raise ValueError('distinct non-root service identities required')
    config,state=safe_path(config),safe_path(state)
    if config==state or config.is_relative_to(state) or state.is_relative_to(config):
        raise ValueError('configuration and state roots must be separate')
    directories=[(config,0,0,0o751),(state,0,0,0o751),
        (config/'private',core_uid,core_gid,0o700),(config/'tls',gateway_uid,gateway_gid,0o700),
        (state/'ipc',core_uid,gateway_gid,0o2750)]
    directories += [(state/name,core_uid,core_gid,0o700) for name in ('core','backend','rpc','anchors')]
    files=[(config/'backend.json',core_uid,core_gid,True),
           (config/'coordinator.json',core_uid,core_gid,True),
           (config/'gateway.json',gateway_uid,gateway_gid,True)]
    files += [(config/'private'/name,core_uid,core_gid,False) for name in
              ('backend.passphrase','pool.seed','fees.seed','operator-funding.json')]
    files += [(config/'tls'/name,gateway_uid,gateway_gid,False) for name in ('certificate.pem','private-key.pem')]
    # Validate the entire existing layout before changing any owner or mode.
    for path,uid,gid,mode in directories:
        safe_path(path)
        if path.exists():
            info=path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,uid):
                raise ValueError('unexpected directory ownership or type')
    for path,uid,gid,required in files:
        safe_path(path)
        if not path.exists():
            if required:raise ValueError('run configure.py before provisioning')
            continue
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid not in (0,uid):
            raise ValueError('unexpected private file owner, type or hard link')
    for path,uid,gid,mode in directories:
        path.mkdir(parents=True,exist_ok=True,mode=mode)
        os.chown(path,uid,gid,follow_symlinks=False);path.chmod(mode)
    for path,uid,gid,required in files:
        if path.exists():
            os.chown(path,uid,gid,follow_symlinks=False);path.chmod(0o600)
    return dict(core_uid=core_uid,gateway_uid=gateway_uid,services_started=False,keys_created=False)

def main():
    parser=argparse.ArgumentParser()
    for name in ('config','state','core-user','gateway-user'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args();core=pwd.getpwnam(args.core_user);gateway=pwd.getpwnam(args.gateway_user)
    layout(args.config,args.state,core.pw_uid,core.pw_gid,gateway.pw_uid,gateway.pw_gid)
    print('PROVISIONED_OFFLINE: separate core/gateway ownership; no keys or services created')

if __name__=='__main__':main()
