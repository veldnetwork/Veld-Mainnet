# Release checklist

- [ ] Start from a clean, reviewed release-candidate branch.
- [ ] Record the exact commit, tree, version, deployment identity, protocol
      version, genesis fingerprint, and state-digest version.
- [ ] Run required quality gates and all affected production-role builds.
- [ ] Record compiler, dependency, profile definitions, binary hashes, and test
      logs outside the source tree.
- [ ] Verify PQC provenance and historical Veld 3.0.0 source-identity records.
- [ ] Confirm no test, regtest, qualification, or bypass macro enters a production
      role.
- [ ] Confirm Windows packages contain only documented files and no non-system
      runtime DLLs.
- [ ] Prepare SHA-256 and SHA-512 sums, a signed source manifest, detached asset
      signatures, and verification instructions.
- [ ] Create an annotated signed tag only with the owner-controlled release key.
- [ ] Publish immutable assets only after explicit owner approval.
- [ ] Never replace, move, or retag an existing release or asset.
