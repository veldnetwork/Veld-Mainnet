# Source identity

This public source release corresponds to the binaries launched as:

- Release ID: `VELD-3.0.0-BUILD-02-03388b12-c540616f`
- Combined BUILD-02 digest:
  `7dcf10fa5d879e383c32693665265f9e8fcbcd90ca6540c7a31cae29b7536612`
- Launch source commit: `03388b12f8125ac0f321984730a9906064f48f62`
- Launch source tree: `c540616f288fe38fffa1ce061598425b6e53fcbc`
- Network: `veld-public-mainnet-v2`
- State digest: `VELD_STATE_DIGEST_v8`

The public repository intentionally starts with a clean publication commit so
private audit branches, operator evidence, and development-session history are
not distributed. Every compiled program source, header, build controller,
launcher, vendored dependency, resource, and package script is byte-identical
to the launch source above. Only `README.md`, `CHANGELOG.md`, `BUILDING.md`, and
`RELEASE_NOTES.md` were updated to describe the completed release; this file
and `LIVE_MAINNET_CHECKS.md` were added. The internal remediation-session note
was omitted. These changes do not affect compiled output or consensus behavior.

`PUBLICATION_SOURCE_MANIFEST.tsv` records every released file and its SHA-256.
`LAUNCH_EQUIVALENCE.tsv` records the exact launch blob identity for every file
that participates in builds or runtime packaging.
