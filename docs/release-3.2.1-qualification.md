# Veld 3.2.1 qualification scope

Binary-build commit: `1c693db24de71e71bc45b26958da03340d847f5c`.
This source follow-up contains web/documentation changes that are not in those
signed binaries. Public package authenticity is not a security certification.

Verified on 21 September 2026:

- Clean production Windows node, desktop, GUI, keygen and validator builds;
  Linux pool backend and fleet-no-mine builds, with exact controller identities.
- Sequential fleet rollout; public download signatures, ZIP member hashes,
  checksum parity and matching corresponding source archive.
- Original signed 3.2.0 automatic discovery, verification and installation of
  the public 3.2.1 package, followed by fully synced mainnet solo mining with
  the same payout identity and 15 workers, without another passphrase. Two
  samples confirmed increasing work after restart. The initial opt-in check
  was exercised; an hour-long timer interval was not measured in that run.
  An initial public changelog mismatch was correctly refused, corrected to
  the package's signed bytes, and the actual automatic opt-in flow rerun.
- Isolated existing and candidate co-mining profiles: operator-funded 1,000
  VELD stake, genuine NMS inclusion, draw, staking yield, maturity and real
  signed recipient payments reconciled through an independent node.
  Historical test-chain time is accelerated; consensus/economics are not bypassed.
- Public Explorer and wallet navigation, and mobile/light/dark Pool layout.
  These read-only UI checks do not qualify wallet transaction signing.

Retained qualification limits:

- The combined native Windows GUI economic test was interrupted and did not
  pass; a clean integrated retry is required.
- Custody authorization, complete issuer/witness service qualification and
  managed community signer rollout are not cleared by this release.

No release statement grants custody signing authority, clears the seven-validator gate, guarantees
absence of vulnerabilities, or treats a skipped check as passed.
