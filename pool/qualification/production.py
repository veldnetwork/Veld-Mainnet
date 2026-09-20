"""Run the normal clean-source production controllers without publishing.

This only builds and inspects artifacts. It never opens a wallet/data directory,
starts mining, connects to a network, signs a release or installs a client.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

SOURCE = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--component', choices=('pool', 'keygen', 'fleet'), default='pool')
    parser.add_argument('--toolchain', type=Path, default=Path('C:/msys64'))
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(SOURCE):
        raise ValueError('build output must be outside the source')
    if os.name == 'nt' and args.component != 'pool':
        raise ValueError('this Windows entrypoint builds the complete node package')
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    if os.name == 'nt':
        env.update(MSYSTEM='CLANG64', CHERE_INVOKING='1')
        env['PATH'] = str(args.toolchain/'clang64/bin') + os.pathsep + str(args.toolchain/'usr/bin') + os.pathsep + env['PATH']
    elif (SOURCE/'.git').is_file():
        metadata = (SOURCE/'.git').read_text().strip().removeprefix('gitdir: ')
        if len(metadata) > 3 and metadata[1:3] == ':/':
            location = Path('/mnt')/metadata[0].lower()/metadata[3:]
            if not location.is_dir():
                raise ValueError('actual worktree metadata is unavailable')
            env.update(GIT_DIR=str(location), GIT_WORK_TREE=str(SOURCE))

    def git(*arguments):
        return subprocess.check_output(['git', '-c', 'core.fsmonitor=false', '-C', str(SOURCE), *arguments],
                                       env=env, text=True, timeout=120).strip()

    commit, tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
    if git('status', '--porcelain'):
        raise ValueError('production controllers require the actual clean committed source')
    output.mkdir(parents=True, exist_ok=False)
    report = dict(status='RUNNING', source=str(SOURCE), commit=commit, tree=tree,
                  platform='windows' if os.name == 'nt' else 'linux', component=args.component,
                  production_profile=True, signed_release=False, mainnet_E2E=False,
                  started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), commands=[])

    def save():
        temporary = output/'result.json.new'
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        for attempt in range(100):
            try:
                temporary.replace(output/'result.json')
                break
            except PermissionError:
                if attempt == 99:
                    raise
                time.sleep(.1)

    def run(name, command, extra=None):
        entry = dict(name=name, command=list(map(str, command)), status='RUNNING')
        report['commands'].append(entry)
        save()
        start = time.monotonic()
        with (output/(name+'.log')).open('w') as log:
            result = subprocess.run(entry['command'], cwd=SOURCE, env=dict(env, **(extra or {})),
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=10800,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        entry.update(status='PASS' if result.returncode == 0 else 'FAILED', exit_code=result.returncode,
                     seconds=time.monotonic()-start)
        save()
        if result.returncode:
            raise RuntimeError(name+' production controller failed; see its raw log')
        print(name+' PASS', flush=True)

    save()
    try:
        if os.name == 'nt':
            def msys(path):
                value = path.resolve().as_posix()
                if value[1:3] != ':/':
                    raise ValueError('native absolute Windows path required')
                return '/'+value[0].lower()+value[2:]
            bash = args.toolchain/'usr/bin/bash.exe'
            for role in ('node', 'desktop', 'gui'):
                extra = {} if role != 'gui' else dict(VELD_TRUSTED_NODE_BUILD=msys(output/'node'),
                                                     VELD_TRUSTED_WALLET_BUILD=msys(output/'desktop'))
                run(role, [bash, '-l', '-c', 'exec bash "$1" "$2" "$3"', 'production-build',
                    msys(SOURCE/'build/mainnet-v2-windows.sh'), role, msys(output/role)], extra)
            binaries = [output/'gui/bin/veld-node.exe', output/'gui/bin/veld-wallet.exe']
        else:
            if args.component == 'pool':
                run('pool', ['bash', SOURCE/'build/mainnet-v2-pool.sh', output/'pool'])
            else:
                run(args.component, ['bash', SOURCE/'build/mainnet-v2-linux.sh', args.component, output/args.component])
            binaries = [] if args.component == 'keygen' else [output/(
                'pool/bin/veld-node' if args.component == 'pool' else 'fleet/bin/veld-node-fleet-no-mine')]
        deployments = {}
        for binary in binaries:
            raw = subprocess.check_output([str(binary), '--deployment-info'], env=env, text=True,
                stdin=subprocess.DEVNULL, timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            values = [json.loads(line.removeprefix('VELD_DEPLOYMENT_INFO_V1_JSON ')) for line in raw.splitlines()
                      if line.startswith('VELD_DEPLOYMENT_INFO_V1_JSON ')]
            assert len(values) == 1
            value = values[0]
            assert value['client_version'] == '3.2.1' and value['profile_id'] == 'veld-public-mainnet-v2'
            assert value['amm_flat_fee_activation_height'] == 9500 and value['amm_flat_fee_bps'] == 30
            if args.component == 'fleet':
                assert value['fleet_no_mine'] and not value['mining_compiled']
            deployments[binary.relative_to(output).as_posix()] = value
        assert git('rev-parse', 'HEAD') == commit and git('rev-parse', 'HEAD^{tree}') == tree
        assert not git('status', '--porcelain')
        report.update(status='PASS', clean_source_after_build=True, deployments=deployments,
            completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            artifact_hashes={p.relative_to(output).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in output.rglob('*') if p.is_file() and ('bin' in p.parts or p.name == 'Veld Node.exe')})
    except BaseException as error:
        report.update(status='FAILED', error=repr(error))
        raise
    finally:
        save()


if __name__ == '__main__':
    main()
