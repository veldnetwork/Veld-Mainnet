## Summary

Describe the user-visible or engineering outcome and the boundary it changes.

## Compatibility

- [ ] No consensus, genesis, network-magic, address, signature, wire-format, or
      persisted-state behavior changes.
- [ ] If compatibility changes, the activation and legacy replay/spend behavior
      are documented and tested.
- [ ] Existing Veld 3.0.0 release tags, assets, and launch-identity records are
      unchanged.

## Validation

- [ ] Focused positive and negative regression tests pass.
- [ ] `python scripts/check-public-source-hygiene.py` passes.
- [ ] `python scripts/format-maintained-source.py --check` passes.
- [ ] `python scripts/verify-pqc-provenance.py --root .` passes.
- [ ] Every affected production role builds, or an unavailable platform is
      identified explicitly.

## Security-sensitive changes

Complete [SECURITY_CHANGE_CHECKLIST.md](SECURITY_CHANGE_CHECKLIST.md) when this
change affects consensus, cryptography, keys, wallets, networking, persistence,
updates, release identity, btcVELD, or portal authentication.
