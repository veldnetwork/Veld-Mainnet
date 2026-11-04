# Veld 3.2.2 qualification scope

Signed binary source: `1f77a67365ff9c3c36dae2a624feb35615446202`, tree
`97898f972e3a6eb0cce2caf86475afa5e4988bc6`. Evidence below was executed on
21 September 2026. This documentation and hosted presentation follow-up does not change those binaries.

## Verified

- Clean production Windows node, desktop, GUI, pool worker, keygen and validator
  builds; Linux fleet-no-mine, pool and desktop builds, with controller receipts.
- Forty-two portable checks; 159 Linux pool unit tests; native Windows UI,
  account ownership, portal telemetry and crypto interoperation regressions;
  Linux mining and mandatory-settlement template regressions.
- The public-source follow-up passed 43 portable checks, including byte-level
  preservation of the native wallet scripts through the hosted presentation layer.
- Fresh GitHub CI exposed an old 3.2.1 version assertion and a browser fixture
  requesting the now-disabled snapshot command. The test-only corrections passed
  both compiled public activation profiles and native Windows encryption/control
  interoperability. The browser's rejection and the legacy native confirmation
  boundary are tested separately; no production control was relaxed.
- Existing four-block SSE2 ChaCha20 implementation: 10,240 reference comparisons.
  Its isolated stream benchmark was about 2.2 times scalar throughput on the
  tested desktop. No equivalent whole-miner performance claim is made.
- Scoped real TLS/VeldHash 256-nonce loopback exercise with unequal workers,
  43 accepted blocks and 355 shares. The chain's historical clock is accelerated;
  this is not a measured public capacity guarantee or a whole-product gate.
- Sequential deployment to the three fleet nodes, independent chain/state
  agreement and per-node stability checks before proceeding to the next node.
- Public signed downloads, exact archive contents, hashes and corresponding
  source readback. Published 3.2.1 bytes were not replaced.
- Actual desktop public automatic 3.2.1-to-3.2.2 installation and pool resume,
  with 29 installed files verified against the signed manifest, saved account
  retained, accepted work observed and no passphrase prompt. The previously
  enabled automatic-update preference was re-enabled to trigger the normal
  startup check; a full elapsed hour was not measured.
- Actual 3.2.2 pool telemetry received by the hosted portal, plus mobile and
  desktop browser checks of stable refresh, Pool icon and navigation.

- Hosted wallet upgraded from its old 3.0.4 binary to exact production 3.2.2.
  The canary caught obsolete nginx JavaScript substitutions; static asset
  insertion replaced them. All 11 actual HTTPS wallet tabs passed at mobile
  and desktop widths with no JavaScript errors or overflow; fee-model selection
  was checked on both sides of 9,500. These are read-only UI checks, not a
  wallet-signing or economic end-to-end qualification.

## Limits and remaining qualification

- The 3.2.0-to-3.2.1 live solo-resume result is separate; a fresh 3.2.2 solo
  update/resume has not been exercised. The combined native Windows GUI
  economic qualification still requires a clean complete run.
- The earlier full pool testnet gate uses its own frozen source and is not
  relabeled as a complete 3.2.2 gate. Earlier failures remain in the local
  evidence, including the repaired native repaint recursion and stale CI tests.
- Mainnet block 9,041 was earned before the 3.2.2 backend upgrade. Its retained
  liabilities and normal 120-confirmation/daily-payment policy remain under
  observation; it is not a fresh 3.2.2 economic end-to-end pass.
- The pool's mainnet co-mining identity is not yet operator-funded. Earlier
  isolated genuine stake/NMS/draw/yield/payment results remain scoped to their
  exact artifacts and accelerated disposable chain.
- Complete custody payout authority, issuer/witness services, managed community
  signers and broader security clearance are not established by this release.

## Unchanged boundaries

Block 9,500 activation, ML-DSA-65 signatures, individual validator bond,
governance, finality, seven-validator btcVELD gate and custody protections remain
unchanged. No funding, custody enrollment or economic-policy change is implied.
No test count guarantees the absence of exploitable defects.
