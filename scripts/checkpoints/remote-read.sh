#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
label=$1
heights=$2
[[ "$label" =~ ^[A-Za-z0-9_-]+$ ]]
[[ "$heights" =~ ^(-|[0-9]+(,[0-9]+)*)$ ]]
datadir=$(python3 - <<'PYDIR'
import pathlib,subprocess
pid=subprocess.check_output(['systemctl','show','veld-node.service','-p','MainPID','--value'],text=True).strip()
assert pid.isdigit() and int(pid)>0
args=pathlib.Path('/proc/'+pid+'/cmdline').read_bytes().decode().split(chr(0))
dirs=[args[i+1] if a=='--datadir' else a.split('=',1)[1] for i,a in enumerate(args) if a=='--datadir' or a.startswith('--datadir=')]
assert len(dirs)==1 and dirs[0].startswith('/var/lib/veld-public-mainnet-v2-')
assert pathlib.Path(dirs[0]).is_dir() and not pathlib.Path(dirs[0]).is_symlink()
print(dirs[0])
PYDIR
)
[[ -f /etc/veld/env && ! -L /etc/veld/env ]]
set -a
source /etc/veld/env
set +a
token=$(runuser -u veld --preserve-environment -- /usr/local/bin/veld-node --print-rpc-token --datadir "$datadir")
[[ "$token" =~ ^[0-9a-fA-F]{64}$ ]]
exec 3<<<"$token"
unset token VELD_VAULT_PASSPHRASE
exec /usr/bin/python3 /opt/veld-checkpoints/remote_probe.py "$label" "$heights" 3<&3
