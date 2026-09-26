"""Build and run offline native fee qualification on Linux or native Windows.

Example:
  python3 tests/run_amm_fee_policy.py --baseline-root /path/to/unmodified/source \
      --out /path/to/new/evidence --compiler g++ --node node

An external baseline and new evidence directory are mandatory. No network,
funding, production state, release signing or activation is performed.
"""

import argparse, hashlib, json, os, pathlib, subprocess, sys


def main():
    p = argparse.ArgumentParser()
    for arg in ('baseline-root', 'out', 'compiler', 'node'):
        p.add_argument('--' + arg, required=True)
    p.add_argument('--dll-dir', help='Windows compiler runtime DLL directory')
    a = p.parse_args()
    s = pathlib.Path(__file__).resolve().parents[1]
    baseline = pathlib.Path(a.baseline_root).resolve()
    out = pathlib.Path(a.out).resolve()
    out.mkdir(exist_ok=False)
    env = dict(os.environ)
    if a.dll_dir:
        env['PATH'] = a.dll_dir + os.pathsep + env.get('PATH', '')
    commands = []
    files = [
        'include/core/amm_pool.h',
        'include/core/constants.h',
        'include/network/rpc.h',
        'include/network/ui_desktop.h',
        'src/veld-desktop.cpp',
        'src/veld-node.cpp',
        'tests/amm_fee_policy_probe.cpp',
        'tests/amm_fee_wallet_tests.js',
        'tests/qualify_amm_fee_policy.py',
        'tests/run_amm_fee_policy.py',
    ]

    def hashes():
        return {f: hashlib.sha256((s / f).read_bytes()).hexdigest() for f in files}

    before = hashes()

    def run(label, cmd, expected=0):
        cmd = list(map(str, cmd))
        commands.append(cmd)
        (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        with (out / (label + '.log')).open('w', encoding='utf-8') as log:
            r = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=600)
        if (expected == 0 and r.returncode) or (expected != 0 and not r.returncode):
            raise RuntimeError(f'{label}: unexpected return code {r.returncode}; see its log')

    run('compiler', [a.compiler, '--version'])
    pub = ['-DVELD_MAINNET_POW', '-DVELD_PUBLIC_RELEASE', '-DVELD_PUBLIC_MAINNET']
    test = [
        '-DVELD_MAINNET_POW',
        '-DVELD_TEST_CHAIN_BUILD',
        '-DVELD_TEST_HOOKS',
        '-DVELD_TEST_AMM_FLAT_FEE_HEIGHT=100',
    ]
    suffix = '.exe' if os.name == 'nt' else ''
    sanitize = (
        [] if os.name == 'nt' else ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    )
    for target in ('historical', 'public', 'candidate'):
        root = baseline if target == 'historical' else s
        run(
            target,
            [
                a.compiler,
                '-std=c++20',
                '-O1',
                '-g',
                *sanitize,
                *(test if target == 'candidate' else pub),
                '-I' + str(root / 'include'),
                '-I' + str(root / 'vendor/pqc'),
                s / 'tests/amm_fee_policy_probe.cpp',
                '-lssl',
                '-lcrypto',
                '-o',
                out / (target + suffix),
            ],
        )
    run(
        'quote-tests',
        [
            sys.executable,
            s / 'tests/qualify_amm_fee_policy.py',
            '--candidate',
            out / ('candidate' + suffix),
            '--public',
            out / ('public' + suffix),
            '--baseline',
            out / ('historical' + suffix),
            '--out',
            out / 'quotes',
            '--node',
            a.node,
        ],
    )
    run(
        'seed-build',
        [
            a.compiler,
            '-std=c++20',
            '-O1',
            *pub,
            '-I' + str(s / 'include'),
            '-I' + str(s / 'vendor/pqc'),
            s / 'tests/amm_market_seed_tests.cpp',
            '-lssl',
            '-lcrypto',
            '-o',
            out / ('seed' + suffix),
        ],
    )
    run('seed-test', [out / ('seed' + suffix)])
    (out / 'rpc-syntax.cpp').write_text('#include "core/blockchain.h"\n#include "network/rpc.h"\n')
    run(
        'rpc-syntax',
        [
            a.compiler,
            '-std=c++20',
            *pub,
            '-I' + str(s / 'include'),
            '-I' + str(s / 'vendor/pqc'),
            '-fsyntax-only',
            out / 'rpc-syntax.cpp',
        ],
    )
    run(
        'forbidden-public-override',
        [
            a.compiler,
            '-std=c++20',
            *pub,
            '-DVELD_TEST_AMM_FLAT_FEE_HEIGHT=100',
            '-I' + str(s / 'include'),
            '-I' + str(s / 'vendor/pqc'),
            '-fsyntax-only',
            s / 'tests/amm_fee_policy_probe.cpp',
        ],
        expected=1,
    )
    assert (
        'AMM flat-fee activation override requires an isolated test chain'
        in (out / 'forbidden-public-override.log').read_text()
    )
    assert before == hashes(), 'source changed during qualification'

    def identity(root):
        git_exe = 'git'
        git_root = str(root)
        # A worktree created by Windows Git has an absolute Windows gitdir in
        # its .git file. Do not rewrite that file or fabricate source identity
        # when compiling it under WSL; query the owning Windows Git instead.
        dotgit = root / '.git'
        if os.name != 'nt' and dotgit.is_file():
            pointer = dotgit.read_text().strip()
            if pointer.startswith('gitdir: ') and len(pointer) > 10 and pointer[9] == ':':
                git_exe = '/mnt/c/Program Files/Git/cmd/git.exe'
                git_root = subprocess.check_output(['wslpath', '-w', str(root)], text=True).strip()

        def git(*args):
            return subprocess.check_output([git_exe, '-C', git_root, *args], text=True).strip()

        return dict(
            path=str(root),
            commit=git('rev-parse', 'HEAD'),
            tree=git('rev-parse', 'HEAD^{tree}'),
            branch=git('branch', '--show-current'),
            status=git('status', '--short'),
        )

    report = dict(
        status='PASS',
        platform=sys.platform,
        sanitizers=sanitize,
        scope='offline native component, embedded wallet and syntax qualification; not funded node E2E',
        source=identity(s),
        baseline=identity(baseline),
        files=before,
        quotes=json.loads((out / 'quotes/result.json').read_text()),
    )
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': 'PASS', 'platform': sys.platform, 'evidence': str(out)}))


if __name__ == '__main__':
    main()
