# Testing

Tests are named for the behavior they cover. Native unit tests, process
fixtures, browser-script checks, and platform-specific checks share this
directory; fixture data is under [fixtures/](fixtures/).

## Portable source and web checks

Install Python 3.10 or later and Node.js 22 or later. In a Python virtual
environment, install the portal test dependency and run the checks:

```sh
python3 -m pip install -r tests/requirements.txt
python3 tests/run_checks.py
```

Use `--suite source`, `--suite web`, or `--suite provenance` to run one group,
and `--list` to inspect the selected checks. Windows can use `python` in place
of `python3`. The runner reports every failure and returns a nonzero status if
any check fails. It does not install dependencies or start production services.

The source group includes source-level checks for Windows client behavior;
running them on Linux does not establish Windows runtime compatibility. The
web group uses JavaScript fixtures and DOM substitutes, not a complete browser
or installed PWA. Mobile layout changes also need rendered narrow-viewport and
safe-area checks.

The [Source checks workflow](../.github/workflows/source-checks.yml) runs these
checks on Linux and Windows for pushes and pull requests. It also compiles
and runs the work-admission unit test on Linux. This is separate from the
production release-build process.

## Native tests

Use a C++20 compiler, the dependencies in [BUILDING.md](../BUILDING.md), and
an output directory outside the checkout. For example:

```sh
mkdir -p ../veld-test-out
c++ -std=c++20 -O1 -pthread -Iinclude tests/work_admission_tests.cpp \
  -o ../veld-test-out/work_admission_tests
../veld-test-out/work_admission_tests
```

Do not define `NDEBUG`: native tests use assertions. Each test's includes and
preprocessor definitions establish its profile; some require the production
profile, while others explicitly require isolated test hooks. Do not apply a
single profile to every test or add test hooks to a production build.

| Area | Test families |
| --- | --- |
| Work and mining | `work_admission_*`, `local_work_*`, `mining_preflight_*`, `mining_nonce_*`, `pow_*` |
| State and consensus | `security_consensus_*`, `snapshot_*`, `public_snapshot_*`, `staking_*`, `finality_*` |
| btcVELD | `reserve_*`, `reopen_*`, `signing_policy_*`, `amm_market_seed_*` |
| Network and RPC | `peer_*`, `rpc_*`, `connect_trust_*`, `trusted_proxy_*`, `punch_*` |
| Wallet and keys | `wallet_*`, `offline_signer_*`, `seed_*`, `desktop_rpc_*` |
| Distribution | `pqc_*`, `version_identity_*`, `network_identity_*`, `updater_*`, `release_controller_*` |

## Mining correctness and performance

`mining_primitive_tests.cpp` compares stream buffering and integer square roots
with the prior implementations, published known answers, and arithmetic bounds.
`mining_work_header_tests.cpp` exercises concurrent timestamp refreshes and the
identity of headers reported by workers. `mining_search_tests.cpp` runs the
actual search loop in a disposable in-memory chain, including concurrent seven-
and eight-worker groups and accounting for canceled searches. It does not open
network connections or submit blocks.
`mining_solution_tests.cpp` uses the existing fixed-difficulty test profile to
check found blocks, including the exact hashed header and canonical coinbase
split, with one, seven, eight and sixteen workers. Both search tests link the C
objects listed in `vendor/pqc/provenance/release-c-sources.txt`, as shown in the
source-checks workflow.

`mining_worker_policy_tests.cpp` checks worker bounds, physical-core presets,
SMT/non-SMT/mixed-core masks, partial affinity and the native Windows detector.
Its Windows affinity check changes only the disposable test process. The
existing conservative estimate is retained when native topology is unavailable;
no affinity or priority is changed in the running miner.

`mining_process_nonce_probe.cpp` is a small standalone fixture. Compile it and
pass its path to `mining_process_nonce_tests.py` to check the production random
origin and worker partitioning in 24 independent processes. This validates a
finite sample of searches rather than claiming that random collisions are
mathematically impossible. The portal worker-limit tests check browser and
server boundaries and saved next-start preferences.

`mining_hash_vectors.cpp` checks full-size VeldHash outputs against the frozen
3.0.9 fixture in `fixtures/veldhash-3.0.9-vectors.txt`. Compile it with
`VELD_MAINNET_POW`, `VELD_PUBLIC_RELEASE`, and `VELD_PUBLIC_MAINNET`; pass the
fixture path as its only argument. It requires a 1 GiB dataset. Do not substitute
a reduced test dataset when checking compatibility with released hashes.

The default leaves one physical core available for other node work. Eco and
Balanced use 25% and 75% of detected physical cores, rounded up; Maximum uses one
worker per physical core. Custom counts from 1 to 64 can use additional logical
processors. These presets are capacity choices, not a measured hardware
autotuner: compare sustained rates before assuming more workers are faster.

The offline benchmark uses production parameters and reuses one virtual machine
per worker as the active miner does:

```sh
c++ -std=c++20 -O2 -DNDEBUG -pthread -Iinclude \
  -DVELD_MAINNET_POW -DVELD_PUBLIC_RELEASE -DVELD_PUBLIC_MAINNET \
  tests/mining_benchmark.cpp -o ../mining_benchmark
../mining_benchmark --workers 7 --hashes 256 --trials 3
```

It prints completed hashes, elapsed time, dataset initialization time and a
deterministic output checksum. `--profile` also measures initialization,
execution and finalization separately. Compare repeated runs with identical
worker counts, compiler options and machine load; timing one run does not
establish a hardware-wide speedup. Benchmarking consumes CPU and memory but does
not load wallets, change settings, connect to peers or publish work.

## Process and platform checks

Python wrappers ending in `_process_tests.py` run separately built fixtures
and may require paths such as `--fixture` or `--keygen`; inspect `--help` and
the wrapper before running them. TLS and download wrappers use local fixture
servers. Windows `.ps1` checks require PowerShell, and Windows native process
fixtures must run on Windows.

Keep fixture keys, journals, certificates, and data directories disposable and
separate from real wallets and node data. Never point a process test at an
operator's data directory or public infrastructure.

## Reporting results

Include the source commit, platform, commands, and results in a pull request.
Distinguish source checks, native execution, browser rendering, and release
build validation. A skipped platform or unavailable dependency is an unrun
check, not a passing result. See [CONTRIBUTING.md](../CONTRIBUTING.md) for
consensus-boundary and compatibility expectations.
