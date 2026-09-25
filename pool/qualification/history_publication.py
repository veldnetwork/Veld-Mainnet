"""Run the native history publication regression inside the private lab."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from .isolation import require_isolated_network


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require_isolated_network()
    out = args.output
    out.mkdir(exist_ok=False)
    state = Path(tempfile.mkdtemp(prefix='veld-pool-history-race-', dir='/var/tmp'))
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    public = subprocess.check_output(
        [str(args.build_directory / 'pool-lab-keys'), str(state / 'keys')], text=True
    )
    address = next(line.split()[1] for line in public.splitlines() if line.startswith('pool '))
    binary = args.build_directory / 'history-race'
    command = [str(binary), str(state / 'node'), address]
    report = dict(
        status='RUNNING',
        scope='native canonical history read/commit interleaving',
        complete_pool_gate=False,
        argv=command,
        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
    )
    try:
        with (out / 'test.log').open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=180)
        report.update(
            status='PASS' if result.returncode == 0 else 'FAILED', exit_code=result.returncode
        )
        if result.returncode:
            raise RuntimeError('native history publication regression failed')
    except BaseException as error:
        report.update(status='FAILED', error=repr(error))
        raise
    finally:
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
