# Source identity

This public source release corresponds to the binaries launched as:

- Release ID: `VELD-3.0.0-BUILD-02-03388b12-c540616f`
- Combined BUILD-02 digest:
  `7dcf10fa5d879e383c32693665265f9e8fcbcd90ca6540c7a31cae29b7536612`
- Launch source commit: `03388b12f8125ac0f321984730a9906064f48f62`
- Launch source tree: `c540616f288fe38fffa1ce061598425b6e53fcbc`
- Network: `veld-public-mainnet-v2`
- State digest: `VELD_STATE_DIGEST_v8`

The public repository intentionally started with a clean publication commit so
private audit branches, operator evidence, and development-session history were
not distributed. At that initial publication, every compiled program source,
header, build controller, launcher, vendored dependency, resource, and package
script was byte-identical to the launch source above.

The current maintenance lineage contains explicitly recorded non-consensus
fixes after launch. Those commits do not rewrite the launch commit, launch
tree, release tag, assets, genesis, protocol version, deployment identity, or
state-digest format. They must be identified by their own maintenance commit
and tree rather than being described as BUILD-02 byte equivalence.

`PUBLICATION_SOURCE_MANIFEST.tsv` and `LAUNCH_EQUIVALENCE.tsv` are immutable
launch records. They record the initial public release files and the exact
launch blob identity for files that participated in BUILD-02; maintenance
commits do not regenerate them or imply that later files existed at launch.
