# Veld 3.2.2 candidate verification

This maintenance candidate retains the scheduled block 9,500 rules and all
existing consensus and custody thresholds. It does not activate pool co-mining
without operator funding or qualify btcVELD custody for production.

Changes include buffered native Pool-page scrolling, a charcoal scrollbar,
the requested green Paid accent, bounded 256-nonce work batches, current pool
worker telemetry in the portal, stable portal Pool rendering, the missing Pool
icon, and removal of the portal How To navigation item. Solo mining remains
available. A fresh complete template is requested when its internal validation
binding changes before publication; block and transaction writes still fail
closed and require their original authorizations.

Portal source also includes the deployed update progress controls and their
account/device ownership checks. Missing automatic-update capability stays
unknown; an old client cannot be queued an unsupported automatic-update action.

Evidence must distinguish native component tests, browser fixtures, isolated
chain integration, production build identity, fleet deployment and actual
automatic installation with mining resume. Passing an earlier build does not
qualify the final artifact. The original 3.2.0-to-3.2.1 solo updater result is
not a 3.2.2 or pool-resume result.

The existing four-block SSE2 ChaCha20 implementation is retained, not replaced
with a different hash. Native Windows comparisons covered 10,240 reference
cases. Its isolated stream benchmark was about 2.2 times the scalar throughput
on the tested desktop; this does not measure an equivalent whole-miner gain.

The portal UI/schema and current native UI component checks passed locally.
Final production artifacts, new fleet deployment, signed automatic update,
pool mining resume and final combined qualification remain pending until their
exact-artifact receipts exist. No comprehensive security clearance is claimed.
