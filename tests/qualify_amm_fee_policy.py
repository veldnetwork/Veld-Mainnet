"""Offline differential qualification. Supply actual compiled native probes.

No keys or sockets; logs and results only in a new specified output directory.
The reference for the new fee uses independent exact Python integer arithmetic.
Historical comparison runs the same probe against the unmodified source.
"""

import argparse, hashlib, json, pathlib, random, subprocess


def main():
    p = argparse.ArgumentParser()
    for arg in ('candidate', 'public', 'baseline', 'out', 'node'):
        p.add_argument('--' + arg, required=True)
    args = p.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(exist_ok=False)
    root = pathlib.Path(__file__).resolve().parents[1]
    rng = random.Random(3200919)
    cases = []
    # Real units and extreme price departures, including starting far from
    # the seed anchor. No resetting the anchor to current reserves per quote.
    for rv, rb in [(10**12, 10**8), (10**10, 10**9), (10**14, 10**5), (10**9, 10**9)]:
        for av, ab in [(10**12, 10**8), (10**15, 1000), (1000, 10**15)]:
            for d in (0, 1):
                rin = rv if d else rb
                for a in (1, 2, 100, rin // 10000, rin // 100, rin // 10, rin, 10 * rin):
                    for h in (0, 1, 99, 100, 101, 8999, 9000, 9001, 9499, 9500, 9501, 2**32):
                        cases.append((rv, rb, av, ab, a, d, h))
    for _ in range(1500):
        rv = rng.randrange(10**9, 2 * 10**15)
        rb = rng.randrange(1000, 10**9)
        cases.append(
            (
                rv,
                rb,
                rng.randrange(1, 10**15),
                rng.randrange(1, 10**9),
                rng.randrange(1, 10**12),
                rng.randrange(2),
                rng.choice((99, 100, 101, 8999, 9000, 9001, 9499, 9500, 9501)),
            )
        )
    for bad in [
        (0, 1000, 100, 100, 1, 1, 100),
        (1000, 0, 100, 100, 1, 1, 100),
        (1000, 1000, 0, 100, 10, 1, 100),
        (1000, 1000, 100, 0, 10, 0, 100),
        (1000, 1000, 100, 100, 0, 0, 100),
        (1000, 1000, 100, 100, -1, 1, 100),
        (2**63 - 2, 1000, 100, 100, 2, 1, 100),
        (1000, 2**63 - 2, 100, 100, 2, 0, 100),
    ]:
        cases.append(bad)
    lines = ['Q ' + ' '.join(map(str, t)) for t in cases]
    # Exercise state snapshots, rollback and same-height replay separately.
    states = [
        (10**12, 10**8, 10**12, 10**8, 10**10, 1, h)
        for h in (99, 100, 101, 8999, 9000, 9001, 9499, 9500, 9501)
    ]
    lines += ['S ' + ' '.join(map(str, t)) for t in states]
    data = '\n'.join(lines) + '\n'
    (out / 'inputs.txt').write_text(data)

    def run(label, exe):
        r = subprocess.run([exe], input=data, text=True, capture_output=True, timeout=90)
        (out / (label + '.stdout')).write_text(r.stdout)
        (out / (label + '.stderr')).write_text(r.stderr)
        if r.returncode:
            raise RuntimeError((label, r.returncode, r.stderr[-1000:]))
        rows = [s.split() for s in r.stdout.splitlines()]
        assert len(rows) == len(lines)
        return [[int(x) if i < 9 else x for i, x in enumerate(row)] for row in rows]

    baseline = run('baseline', args.baseline)
    public = run('public', args.public)
    candidate = run('candidate', args.candidate)
    checked = history = public_history = public_flat = 0
    js = []
    for i, t in enumerate(cases + states):
        v, b, av, ab, a, d, h = t
        n = candidate[i]
        if h < 9500:
            assert public[i] == baseline[i], ('public historical drift', t, public[i], baseline[i])
            public_history += 1
        else:
            assert public[i] == candidate[i], (
                'public activation mismatch',
                t,
                public[i],
                candidate[i],
            )
            public_flat += 1
        if h < 100:
            assert n == baseline[i], ('historical drift', t, n, baseline[i])
            history += 1
        else:
            rin, rout = (v, b) if d else (b, v)
            valid = v > 0 and b > 0 and av > 0 and ab > 0 and a > 0 and rin + a <= 2**63 - 1
            gross = rout * a // (rin + a) if valid else 0
            net = gross * 9970 // 10000 if valid else 0
            if net <= 0:
                assert n[0] == 1, (t, n)
            else:
                pv, pb = (v + a, b - net) if d else (v - net, b + a)
                assert n == [0, 0, 30, net, gross, gross - net, pv, pb, 0, 'NONE'], (t, n)
                assert pv * pb >= v * b and gross == net + n[5]
                checked += 1
        # JS historically uses a non-reject empty preview on zero/dust; test
        # executable numeric-domain quotes and genuine fee-model rejections.
        if h > 0 and v > 0 and b > 0 and av > 0 and ab > 0 and a > 0 and max(v, b) + a < 2**63:
            rin, rout = (v, b) if d else (b, v)
            if (rout * a // (rin + a)) * 9970 // 10000 > 0:
                js.append(
                    dict(
                        input=[str(x) if j < 5 else x for j, x in enumerate(t)],
                        native=[str(x) if j in (3, 4, 5, 6, 7) else x for j, x in enumerate(n)],
                        public=[
                            str(x) if j in (3, 4, 5, 6, 7) else x for j, x in enumerate(public[i])
                        ],
                    )
                )
    (out / 'wallet-vectors.json').write_text(json.dumps(js))
    cmd = [
        args.node,
        str(root / 'tests/amm_fee_wallet_tests.js'),
        str(root / 'include/network/ui_desktop.h'),
        str(out / 'wallet-vectors.json'),
    ]
    r = subprocess.run(cmd, text=True, capture_output=True, timeout=90)
    (out / 'wallet.stdout').write_text(r.stdout)
    (out / 'wallet.stderr').write_text(r.stderr)
    if r.returncode:
        raise RuntimeError(r.stderr[-3000:])
    report = dict(
        status='PASS',
        scope='offline component and wallet quote qualification; not full-chain or mainnet activation',
        cases=len(lines),
        historical_comparisons=history,
        flat_exact_arithmetic=checked,
        public_activation_height=9500,
        public_historical_matches=public_history,
        public_flat_matches=public_flat,
        wallet=json.loads(r.stdout),
        binaries={
            name: hashlib.sha256(pathlib.Path(getattr(args, name)).read_bytes()).hexdigest()
            for name in ('candidate', 'public', 'baseline')
        },
        source={
            str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [
                root / 'include/core/amm_pool.h',
                root / 'include/core/constants.h',
                root / 'include/network/rpc.h',
                root / 'include/network/ui_desktop.h',
                root / 'src/veld-desktop.cpp',
            ]
        },
    )
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
