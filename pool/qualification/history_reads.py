"""Native address-index reads during normal canonical block publication."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from ..backend import Node
from ..protocol import Busy, Refused
from .control import mine_block
from .isolation import require_isolated_network


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--backend', type=Path, required=True)
    parser.add_argument('--keys-binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require_isolated_network()
    out = args.output
    out.mkdir(exist_ok=False)
    state = Path(tempfile.mkdtemp(prefix='veld-pool-history-read-', dir='/var/tmp'))
    (out / 'state-directory.txt').write_text(str(state) + '\n')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    public = subprocess.check_output([str(args.keys_binary), str(state / 'keys')], text=True)
    address = next(line.split()[1] for line in public.splitlines() if line.startswith('pool '))
    genesis = 'd5f36a21eb02fca3c272c1cb87132a730b55f6821b454224adab5ad2865e87ee'
    rpc = Node('http://127.0.0.1:32822', state / 'node/lab-rpc-token', genesis)
    stop = threading.Event()
    lock = threading.Lock()
    readers = []
    report = dict(
        status='RUNNING',
        scope='native address-history concurrency and quiescent recovery',
        reads=0,
        transient_refusals=0,
        sticky=[],
        complete_pool_gate=False,
    )
    log_path = out / 'node.log'
    with log_path.open('w') as log:
        node = subprocess.Popen(
            [str(args.backend), str(state / 'node'), '32821', '32822'],
            stdin=subprocess.PIPE,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            until = time.monotonic() + 120
            while True:
                assert node.poll() is None
                try:
                    rpc.check_chain()
                    break
                except (OSError, ValueError, Busy):
                    pass
                if time.monotonic() > until:
                    raise RuntimeError('history-read backend deadline')
                time.sleep(0.1)
            mine_block(node, rpc, address, log_path)

            def reader():
                while not stop.is_set():
                    try:
                        page = rpc.call('getaddresshistory', address, '50')
                        assert isinstance(page['entries'], list)
                        with lock:
                            report['reads'] += 1
                    except (OSError, Busy, Refused):
                        with lock:
                            report['transient_refusals'] += 1
                    stop.wait(0.005)

            for _ in range(3):
                thread = threading.Thread(target=reader)
                readers.append(thread)
                thread.start()
            for _ in range(200):
                height = mine_block(node, rpc, address, log_path)
                # A transient read during publication is allowed. After the
                # native command acknowledges completion, the index must not
                # remain disabled until another block happens to arrive.
                until = time.monotonic() + 1
                while True:
                    try:
                        rpc.call('getaddresshistory', address, '50')
                        break
                    except (Busy, Refused) as error:
                        if time.monotonic() > until:
                            report['sticky'].append(dict(height=height, error=str(error)))
                            break
                        time.sleep(0.05)
                if report['sticky']:
                    break
            stop.set()
            for thread in readers:
                thread.join(timeout=15)
            assert not any(thread.is_alive() for thread in readers)
            report['height'] = rpc.call('getblockcount')
            report['status'] = 'FAILED' if report['sticky'] else 'PASS'
        except BaseException as error:
            report.update(status='FAILED', error=repr(error))
            raise
        finally:
            stop.set()
            for thread in readers:
                thread.join(timeout=15)
            if node.poll() is None:
                node.stdin.write('stop\n')
                node.stdin.flush()
                try:
                    node.wait(timeout=180)
                except subprocess.TimeoutExpired:
                    node.kill()
                    node.wait()
            report['process_stopped'] = node.poll() is not None
            report['backend_sha256'] = hashlib.sha256(args.backend.read_bytes()).hexdigest()
            (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    if report['status'] != 'PASS':
        raise RuntimeError('address history did not recover after completed publication')


if __name__ == '__main__':
    main()
