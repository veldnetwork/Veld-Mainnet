# Public content and release maintenance

The public homepage, how-to library and whitepaper describe the signed 3.3.4
release and its activation at mainnet block 34,750. Historical release records
retain the rules and artifact identities that applied at their publication.

## Current surfaces

| Surface | Source and scope |
| --- | --- |
| Homepage and guides | `website/index.html`, `website/how-to/`; preserve the deployed page structure and assets when editing copy |
| Whitepaper | `docs/WHITEPAPER.md`; render with `scripts/render-public-whitepaper.py` into `website/whitepaper.pdf` |
| Explorer policy explanations | `include/network/subsidy_view.h`; policies use their applicable inclusion or settlement height |
| Wallet copy | `include/network/ui_desktop.h`; registration and bond amounts continue to use native policy and RPC data |
| Hosted copy corrections | `pkg/reverse-proxy/veld-explorer-policy-copy-3.3.4.conf` and `veld-wallet-policy-copy-3.3.4.conf` |
| Release identity | `docs/source-identity.md`, the immutable release tag and signed package records |

The hosted snippets update explanatory text in the existing HTML response.
Include each snippet only in its corresponding mainnet HTML proxy location,
after the existing presentation includes. Preserve the host's live configuration;
do not replace it wholesale with repository examples. Back up the previous
configuration, run `nginx -t`, reload gracefully and verify public readback.
These snippets contain no styles, controls, RPC routes or account operations.
They do not change signed client packages.

The whitepaper renderer retains the public PDF's Arial typography, green headings,
tables, headers and footers. It requires ReportLab 4.4.10 and licensed Arial fonts
from the host's Windows installation. Do not add font binaries to the repository.
Render all pages and inspect them before publication.

## Release distinctions

- Block 34,750 activates the new validator policy, miner fees and vault policy.
  Finality still follows its frozen snapshots, maturity, quorum and warm-up.
- Halvings occur at blocks 700,801 and 1,401,601. Co-mining retirement and the
  60/20/20 ordinary subsidy allocation begin at the first halving.
- The btcVELD seven-validator gate and protocol-upgrade ten-vote minimum are
  separate from the five-key finality minimum.
- Production appchain hosting remains paused. The developer workspace uses a
  separate valueless testnet; it is not production contract deployment.
- The official pool is currently stopped. Its published 1% service fee does
  not mean it is accepting work. Native miner fees, pool service fees, exchange
  operator fees and AMM swap fees describe different flows.

## UI approval

Content updates may correct factual descriptions, release status and links.
Changes to layout, styling, navigation, buttons, controls or interactions require
explicit approval before implementation or deployment. Preserve existing live
UI changes when reconciling source; an older repository page is not a safe
replacement for a newer deployed page.
