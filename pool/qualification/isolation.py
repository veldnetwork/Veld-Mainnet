"""Qualification launcher: record host namespace before entering an isolated one."""
import os
import json
import subprocess
import sys

MARKER='VELD_QUALIFICATION_PARENT_NETNS'

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
    raise SystemExit(subprocess.call(['unshare','-Urn',*args[1:]],env=env))

if __name__=='__main__':main()
