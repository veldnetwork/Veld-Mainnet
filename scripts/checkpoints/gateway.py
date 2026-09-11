"""Forced-command gateway for one fleet checkpoint identity."""
from pathlib import Path
import base64
import fcntl
import json
import subprocess
import sys

from policy import MAX_BYTES, parse, require, sha, unique_object
from remote_store import Store


def main():
    config = json.loads(Path('/etc/veld/checkpoint-gateway.json').read_bytes())
    raw = sys.stdin.buffer.read(2*MAX_BYTES+1)
    require(0 < len(raw) <= 2*MAX_BYTES, 'Gateway request size rejected')
    request = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(request, dict) and 'action' in request, 'Gateway request rejected')
    action = request.pop('action')
    if action == 'public-feed':
        require(not request, 'Unexpected public feed fields')
        result = subprocess.run(['/usr/bin/curl','--disable','--fail','--silent','--show-error','--connect-timeout','10',
            '--max-time','30','--max-filesize',str(MAX_BYTES),'--location','--max-redirs','0','--proto','=https','--proto-redir','=https',
            'https://veld.network/downloads/checkpoints.json'],capture_output=True,timeout=35)
        require(result.returncode == 0, 'Public checkpoint feed unavailable')
        parse(result.stdout)
        print(json.dumps(dict(sha256=sha(result.stdout),document_b64=base64.b64encode(result.stdout).decode())))
        return
    if action == 'observe':
        require(set(request) == {'heights'}, 'Unexpected observation fields')
        heights = request['heights']
        require(isinstance(heights, list) and len(heights) <= 16 and all(type(h) is int and 0 <= h < 2**64 for h in heights), 'Historical query range rejected')
        result = subprocess.run(['/usr/bin/bash','/opt/veld-checkpoints/remote-read.sh',config['host'],','.join(map(str,heights)) or '-'],capture_output=True,timeout=80)
        require(result.returncode == 0, 'Authenticated fleet observation failed')
        print(json.dumps(json.loads(result.stdout)))
        return
    require(config['role'] == 'publisher', 'This host only permits checkpoint observations')
    store = Store(json.loads(Path('/etc/veld/checkpoint-publisher.json').read_bytes()))
    with (store.state/'publisher.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if action == 'read':
            require(not request, 'Unexpected read fields'); result = store.read()
        elif action == 'install':
            require(set(request) == {'transaction','base_sha256','document_b64'}, 'Unexpected installation fields')
            result = store.install(request)
        elif action in ('commit','rollback'):
            require(set(request) == {'transaction'}, 'Unexpected transaction fields')
            result = store.finish(request['transaction'], action == 'commit')
        elif action == 'checked':
            require(set(request) == {'tip'}, 'Unexpected observation status fields'); result = store.checked(request['tip'])
        else: raise ValueError('Unknown gateway operation')
        print(json.dumps(result))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('Checkpoint gateway rejected operation: '+str(error), file=sys.stderr)
        raise SystemExit(1)
