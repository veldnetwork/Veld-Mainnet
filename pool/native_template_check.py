"""Real issuing-node authorization renewal and native-PoW admission in a private namespace."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
from .backend import Node
from .native import Native
from .protocol import Refused
from .qualification.isolation import require_isolated_network


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    # This harness must be invoked inside a fresh unshare -Urn namespace.
    require_isolated_network()
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    args.output.mkdir(parents=True, exist_ok=False)
    build = args.build_directory
    state = Path(tempfile.mkdtemp(prefix='veld-template-qualification-', dir='/var/tmp'))
    (args.output / 'state-directory.txt').write_text(str(state))
    keys = subprocess.run(
        [str(build / 'pool-lab-keys'), str(state / 'keys')],
        capture_output=True,
        text=True,
        check=True,
    )
    addresses = {r.split()[0]: r.split()[1] for r in keys.stdout.splitlines()}
    report = {
        'status': 'RUNNING',
        'scope': 'canonical issuing-node template renewal; native PoW and normal admission',
    }
    with (
        (args.output / 'node.log').open('w') as log,
        (args.output / 'work.log').open('w') as worklog,
    ):
        process = subprocess.Popen(
            [str(build / 'pool-backend'), str(state / 'node'), '32861', '32862'],
            stdin=subprocess.PIPE,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        verifier = Native(build / 'pool-work', worklog)
        genesis = bytes.fromhex('ee875e86d25aabad2442451b82f6550b732a1387cbc172c2a3fc02eb216af3d5')[
            ::-1
        ].hex()
        node = Node('http://127.0.0.1:32862', state / 'node/lab-rpc-token', genesis)
        try:
            for _ in range(100):
                try:
                    node.check_chain()
                    break
                except (OSError, ValueError):
                    time.sleep(0.1)
            else:
                raise RuntimeError('native node startup')
            process.stdin.write('clock 1767225780\n')
            process.stdin.flush()
            time.sleep(0.1)
            original = node.template(addresses['pool'])
            renewed = node.renew(original, addresses['pool'])
            assert (
                original['block_hex'] == renewed['block_hex']
                and original['work_token'] != renewed['work_token']
            )
            template_id = hashlib.sha256(
                hashlib.sha256(bytes.fromhex(original['block_hex'][:176])).digest()
            ).hexdigest()
            refused = []
            for name, address, identity in [
                ('wrong recipient', addresses['worker-a'], template_id),
                ('unknown identity', addresses['pool'], 'f' * 64),
            ]:
                try:
                    node.template(address, identity)
                except Refused:
                    refused.append(name)
                else:
                    raise AssertionError(name + ' accepted')
            solution = None
            raw = bytearray.fromhex(original['block_hex'][:176])
            for nonce in range(512):
                raw[80:88] = nonce.to_bytes(8, 'little')
                proof, _ = verifier.hash(bytes(raw), original['height'])
                if int(proof, 16) < int(original['target'], 16):
                    solution = nonce
                    break
            assert solution is not None
            time.sleep(11)
            try:
                node.submit(original, solution)
            except Refused:
                refused.append('expired token')
            else:
                raise AssertionError('expired token accepted')
            final = node.renew(original, addresses['pool'])
            accepted = node.submit(final, solution)
            assert accepted['accepted']
            expected = bytearray.fromhex(original['block_hex'])
            expected[80:88] = solution.to_bytes(8, 'little')
            assert (
                accepted['hash']
                == hashlib.sha256(hashlib.sha256(expected[:88]).digest()).hexdigest()
            )
            try:
                node.renew(original, addresses['pool'])
            except Refused:
                refused.append('old parent')
            else:
                raise AssertionError('old parent renewal accepted')
            report.update(
                status='PASS',
                refused=refused,
                exact_body_preserved=True,
                accepted_block=accepted['hash'],
                height=1,
            )
        except BaseException as error:
            report.update(status='FAILED', error=repr(error))
            raise
        finally:
            verifier.close()
            if process.poll() is None:
                process.stdin.write('stop\n')
                process.stdin.flush()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            report['processes_stopped'] = process.poll() is not None
            report['binary_sha256'] = {
                n: hashlib.sha256((build / n).read_bytes()).hexdigest()
                for n in ('pool-backend', 'pool-work')
            }
            (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
