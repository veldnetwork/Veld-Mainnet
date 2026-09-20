# Isolated native qualification

From the source root on native Linux with GCC/G++, Python 3.11+, OpenSSL 3,
LevelDB development headers, pkg-config, iproute2, util-linux and unprivileged
user/network namespaces enabled:

```sh
python3 -m pool.qualification.run --output /absolute/new/evidence-directory
```

For the complete Linux exercise, including actual distinct service UIDs, run:

```sh
sudo python3 -m pool.qualification.run --service-roles --output /absolute/new/evidence-directory
```

This variant requires a running systemd system manager and uses a fresh network
namespace without remapping process UIDs. It creates uniquely named transient
test units, with temporary systemd identities and the packaged sandbox settings.
It does not add persistent passwd/group entries or install/enable persistent
services. Temporary units are stopped and collected after the test. Installed
files, configurations, disposable credentials and state stay under a new
`/var/lib/veld-pool-install-*` root; other fixture states use `/var/tmp`.
No existing service or datadir is selected. Without this option, service-user
and systemd installation remain explicit unexecuted requirements.

The entrypoint creates a loopback-only network namespace before starting tests.
It builds both the unchanged validator-gate profile and a candidate with an
isolated activation at height 9500. It matches the selected candidate boundary
on a separate disposable chain; this exercise does not activate mainnet. All output directories must be
new. Runtime chain data, keys and signing history are private `/var/tmp/veld-pool-*`
directories outside the checkout. No existing production datadir is selected.

It runs the connected worker-to-wallet and seven payment crash/lost-response
exercises, competing-chain payment recovery, deep-fork refusal and bounded
native load measurements under both profiles. It starts the canonical CLI
backend and, when requested, installs/upgrades the services under distinct UIDs.
It then mines unchanged monetary prehistory,
stakes real disposable funds, includes a genuine near miss, observes a draw and
ordinary staking yield, pays contributors, and tests funded first-validator
registration, endorsement and activation-boundary reorganization. A separate
50,000-block funding history supplies seven unchanged 10,000-VELD bonds for
the native finality quorum and pool-carried certificate exercise. The funded
validator matrix exercises zero, 9,999, 10,000 and 10,001 aggregate ordinary
stake. The lifecycle run covers actual slashing, exit, full 43,200-block yield
vesting, principal return, replay and exact balance reconciliation. Deliberate
finality equivocation uses disposable keys through real P2P intake and checks
canonical principal/yield settlement and independent validation. Native
VeldHash, ML-DSA signatures, block admission,
settlements, spendability and independent recipient reconciliation are required.
Only historical construction time is accelerated. The two native worker and
settlement exercises distinguish worker-mined blocks from funding/confirmation
blocks produced by the canonical local mining function.

`--through focused`, `--through build` and `--through payments` are development stop points, never
qualification passes. Commands, raw logs, exact source hashes, build identities,
failures and independent wallet amounts are emitted under the selected output.
No copied receipt or manually marked check is accepted as a fresh result.

The runner returns `PASS_SCOPED_LINUX` only after every selected complete Linux
stage passes and all service-role checks run. It retains an explicit separate
list of native Windows GUI/usability and production-artifact requirements;
`complete_pool_gate` stays false until those exact-source requirements are
independently satisfied. `pool.qualification.windows` builds and exercises native
Windows components; `pool.qualification.production` invokes the clean-source
production controllers on the host platform. Neither command substitutes for
the genuine GUI economic exercise or production network operation. The bounded
load result reports observations for that host; it is not a maximum-throughput
or public service-capacity guarantee.
Its completed native cases must not be advertised as complete pool qualification.
The entrypoint creates no release, deployment or public-launch authorization.
