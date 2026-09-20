"""Qualification launcher: record host namespace before entering an isolated one."""
import os
import json
import subprocess
import sys

MARKER='VELD_QUALIFICATION_PARENT_NETNS'

def service_identities_available():
    """A one-UID user namespace cannot test independent service identities."""
    if os.name!='posix' or os.geteuid()!=0:return False
    for name in ('uid_map','gid_map'):
        try:
            with open('/proc/self/'+name) as stream:rows=stream.read(4096).splitlines()
        except OSError:return False
        try:
            mappings=[tuple(map(int,row.split())) for row in rows]
            if not all(any(len(row)==3 and row[0]<=identity<row[0]+row[2] for row in mappings)
                       for identity in (0,61241,61242,61243)):return False
        except ValueError:return False
    return True

def require_isolated_network():
    parent=os.environ.get(MARKER)
    current=os.readlink('/proc/self/ns/net')
    if not parent or not parent.startswith('net:[') or parent==current:
        raise RuntimeError('use python -m pool.qualification.isolation -- COMMAND')
    # No veth, physical NIC, public route, or third-party service is available.
    links=json.loads(subprocess.run(['ip','-j','link','show'],capture_output=True,text=True,check=True).stdout)
    if {link['ifname'] for link in links}!={'lo'}:
        raise RuntimeError('qualification namespace contains a non-loopback interface')
    routes=subprocess.run(['ip','route','show','table','all'],capture_output=True,text=True,check=True).stdout
    if any(line.strip() and ' dev lo ' not in ' '+line+' ' for line in routes.splitlines()):
        raise RuntimeError('qualification namespace has a non-loopback route')

def main():
    args=sys.argv[1:]
    if not args or args[0]!='--' or len(args)<2:raise SystemExit('-- COMMAND required')
    env=dict(os.environ);env[MARKER]=os.readlink('/proc/self/ns/net')
    flags='-n' if service_identities_available() else '-Urn'
    raise SystemExit(subprocess.call(['unshare',flags,*args[1:]],env=env))

if __name__=='__main__':main()
