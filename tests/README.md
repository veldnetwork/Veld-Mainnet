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
