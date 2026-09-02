# Veld 3.0.0 attested mainnet-v2 builds

These instructions build unsigned candidates from source. They do not sign,
package, publish, deploy, or authorize a mainnet launch. The build must begin
from a clean checkout whose commit and tree match the intended release record.

The checked-in controllers build one explicit role at a time and refuse an
unknown or omitted role. They record the source commit and tree automatically
when Git metadata is present and re-check the exact identity after linking. A
source archive must instead provide both
`VELD_SOURCE_COMMIT` and `VELD_SOURCE_TREE` as lowercase 40-character object
IDs. Those archive values are recorded as caller declarations and must be
verified against the sealed source manifest before publication.

Every native production role is compiled with exactly these base profile
definitions:

```text
VELD_MAINNET_POW
VELD_PUBLIC_RELEASE
VELD_PUBLIC_MAINNET
```

Every stateful node/desktop role also defines `VELD_USE_LEVELDB`; this selects
the canonical production datadir backend and is not a chain-profile macro. The
fleet role differs from the ordinary node only by `VELD_FLEET_NO_MINE`. The
Linux desktop additionally defines `VELD_DESKTOP_OPENSSL_TLS` solely to select
its authenticated OpenSSL transport. Test, regtest, and qualification
definitions are refused.

The Linux `operator` role is the checked-in Python operations portal. Its
controller byte-copies the reviewed source, verifies its Python bytecode and
runtime dependencies, and requires its immutable 3.0.0/public-mainnet-v2
deployment identity. It is not a native consensus binary and therefore does
not claim C++ preprocessor definitions.

Every public-mainnet role is also built with the release security reductions:
snapshot bootstrap and UPnP are compile-incompatible with the public profile;
public transaction-history scanners are absent; and keygen accepts seed input
only from a hidden terminal or explicitly inherited protected pipe/handle,
never from argv. The controllers fail if test hooks or those optional public
surfaces are enabled.

## Linux

The Linux controller targets Debian/Ubuntu-family hosts. Install GCC/G++,
binutils, pkg-config, LevelDB development headers, OpenSSL 3.x development
headers, and the ordinary C/C++ runtime. From a clean checkout, run each
required role into a separate empty directory outside the source tree:

```bash
./build/mainnet-v2-linux.sh node ../veld-build-out/linux-node
./build/mainnet-v2-linux.sh desktop ../veld-build-out/linux-desktop
./build/mainnet-v2-linux.sh keygen ../veld-build-out/linux-keygen
./build/mainnet-v2-linux.sh validator ../veld-build-out/linux-validator
./build/mainnet-v2-linux.sh operator ../veld-build-out/linux-operator
./build/mainnet-v2-linux.sh fleet ../veld-build-out/linux-fleet
```

## Windows

Use the MSYS2 CLANG64 shell with Clang, OpenSSL, and the CLANG64 runtime packages
installed. From a clean checkout:

```bash
./build/mainnet-v2-windows.sh node ../veld-build-out/windows-node
./build/mainnet-v2-windows.sh desktop ../veld-build-out/windows-desktop
./build/mainnet-v2-windows.sh keygen ../veld-build-out/windows-keygen
./build/mainnet-v2-windows.sh validator ../veld-build-out/windows-validator
./build/mainnet-v2-windows.sh fleet ../veld-build-out/windows-fleet
VELD_TRUSTED_NODE_BUILD=../veld-build-out/windows-node \
VELD_TRUSTED_WALLET_BUILD=../veld-build-out/windows-desktop \
  ./build/mainnet-v2-windows.sh gui ../veld-build-out/windows-gui
```

Each controller records compiler, linker, dependency, definition, source, and
runtime identity evidence; CLI roles emit `--deployment-info`, while the
windowed GUI is checked by its package identity strings and byte-identical
launcher alias. Every role inventories protocol features and hashes the
finished binary. Fleet builds also prove that mining
flags are absent from help and deterministically refused at argument parsing.
The Windows desktop artifact is emitted with its package name,
`veld-wallet.exe`. The GUI controller requires the complete attested node and
desktop build directories, verifies their commit, tree, role, version, runtime
profile, storage backend, and recorded binary hashes, then embeds those exact
node and wallet hashes. The GUI role emits both `bin/veld-node-gui.exe` and its
byte-identical root package alias `Veld Node.exe`; it also copies the exact
node and wallet binaries into the package set and compiles their SHA-256 values
into the GUI trust boundary. The controllers attest source and build identity;
they do not claim byte-for-byte reproducibility across differing toolchains or
paths.
The scripts never sign, package, publish, deploy, or contact a network.

## Validator and validation builds

The Linux and Windows controllers have a standalone `validator` role with pure
version and deployment-identity probes. It does not link LevelDB and identifies
its local, bearer-authenticated node RPC boundary. The validator oracle checks
only finality-daemon features; it does not require reserve-transition strings
from a binary that does not implement RTP1/RVS1. The public Windows validator
launcher continues to use the attested `veld-node.exe` endorsement mode, so a
separate validator executable is qualified but is not part of the Windows
updater's required package set.

Developer, public-testnet, btcVELD-regtest, sanitizer, and profile-interlock
builds are validation targets, not production artifacts. They must use separate
output directories and must never be substituted for a production-role build.

These controllers build source only. A locally built result is not an official
signed Veld release. Verify official BUILD-02 packages against the signed
manifest and hashes published at `https://veld.network/`.
