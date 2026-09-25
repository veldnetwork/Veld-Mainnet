"""Focused native regressions, explicitly distinct from genuine network E2E."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from .isolation import require_isolated_network


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require_isolated_network()
    args.output.mkdir(exist_ok=False)
    report = {'status': 'RUNNING', 'native_e2e': False, 'synthetic_fixtures': True, 'checks': []}
    try:
        for name in ('download-continuation', 'settlement-history'):
            binary = args.build_directory / name
            with (args.output / (name + '.log')).open('w') as log:
                result = subprocess.run(
                    [str(binary)], stdout=log, stderr=subprocess.STDOUT, timeout=180
                )
            report['checks'].append(
                {
                    'name': name,
                    'exit_code': result.returncode,
                    'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                }
            )
            if result.returncode:
                raise RuntimeError(name + ' failed')
        report['status'] = 'PASS'
    except BaseException as error:
        report.update(status='FAILED', error=repr(error))
        raise
    finally:
        (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
