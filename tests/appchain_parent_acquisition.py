"""Actual outbound P2P acquisition on an isolated loopback network."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def sha(p):
    with p.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main(a):
    os.umask(0o077)
    assert a.root.parent == Path('/var/tmp') and a.root.name.startswith('veld-parent-acquisition-')
    a.root.mkdir(exist_ok=False)
    result = dict(
        status='PREPARING',
        inputs={},
        commands=[],
        real_funds=False,
        public_network_connected=False,
        started_at=datetime.now(timezone.utc).isoformat(),
    )

    def save():
        (a.root / 'result.json').write_text(json.dumps(result, indent=2) + '\n')

    def pin(p):
        result['inputs'][str(p)] = sha(p)

    def run(label, argv, timeout=900):
        row = dict(label=label, argv=list(map(str, argv)))
        result['commands'].append(row)
        save()
        with (a.root / (label + '.log')).open('xb') as out:
            process = subprocess.Popen(
                row['argv'], stdout=out, stderr=subprocess.STDOUT, start_new_session=True
            )
            row['pid'] = process.pid
            save()
            try:
                row['exit'] = process.wait(timeout)
            except BaseException:
                os.killpg(process.pid, 15)
                try:
                    process.wait(15)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, 9)
                    process.wait()
                raise
        row['log_sha256'] = sha(a.root / (label + '.log'))
        save()
        assert row['exit'] == 0, label

    try:
        pin(Path(__file__))
        pin(a.feed / 'result.json')
        prior = json.loads((a.feed / 'result.json').read_bytes())
        assert prior['status'] == 'PASS_PUBLIC_PARENT_FEED_SMALL_HISTORY'
        command = next(row for row in prior['commands'] if row['label'] == 'compile')
        assert command['exit'] == 0
        for path, digest in prior['inputs'].items():
            path = Path(path)
            if str(path).startswith(str(a.feed / 'source')) or path.suffix == '.o':
                assert sha(path) == digest
                pin(path)
        source = Path(__file__).with_suffix('.cpp')
        pin(source)
        shutil.copyfile(source, a.root / 'acquisition.cpp')
        pin(a.root / 'acquisition.cpp')
        for h in range(11):
            source = a.feed / (str(h) + '.block')
            pin(source)
            shutil.copyfile(source, a.root / source.name)
        source = a.feed / 'data/network.identity'
        pin(source)
        shutil.copyfile(source, a.root / 'network.identity')
        (a.root / '.qualification-only').write_text('parent-acquisition\n')
        argv = command['argv'][:]
        argv[argv.index(str(a.feed / 'source/parent.cpp'))] = str(a.root / 'acquisition.cpp')
        argv[-1] = str(a.root / 'acquisition')
        run('compile', argv)
        result['binary_sha256'] = sha(a.root / 'acquisition')
        save()
        result['status'] = 'RUNNING'
        save()
        run(
            'network',
            [
                'unshare',
                '-Urn',
                'sh',
                '-c',
                'ip link set lo up && exec "$1" "$2"',
                'isolated',
                a.root / 'acquisition',
                a.root,
            ],
            900,
        )
        log = (a.root / 'network.log').read_text()
        assert 'PASS_PUBLIC_PARENT_ACQUISITION' in log
        for path, digest in result['inputs'].items():
            assert sha(Path(path)) == digest, path
        result.update(
            status='PASS_PUBLIC_PARENT_ACQUISITION',
            checks=[line[5:] for line in log.splitlines() if line.startswith('PASS ')],
            limitations=[
                'Authentic public blocks 0-10; two local processes do not represent independent operators.',
                'No public connections, mainnet activation or funds.',
            ],
        )
    except BaseException as error:
        result.update(status='FAILED', error=repr(error))
        raise
    finally:
        result['finished_at'] = datetime.now(timezone.utc).isoformat()
        save()


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--feed', type=Path, required=True)
    main(p.parse_args())
