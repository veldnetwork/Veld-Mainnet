# Explorer transaction details

The hosted Explorer uses `website/explorer-transactions-v1.js` and its scoped
stylesheet to identify consolidations, show indexed fees, and resolve output
sources omitted by the native page's historical-read budget. Serve both assets
from `/assets/` with their SHA-256 prefixes in the page URLs. Load the stylesheet
in the document head and the deferred script after the existing Explorer scripts.

Include `veld-explorer-transaction-data.conf` once in the Explorer server block.
Its exact locations take precedence over the existing `/api/` prefix. They expose
only `gettransaction` at a specified height and bounded `getaddresshistory` pages
through the existing hosted wallet service. Client bodies and extra arguments
cannot select an RPC method. Retain the wallet RPC rate-limit zone, security-header
snippets, and fixed upstream Host header.

The browser allows two concurrent lookups and 80 requests per page, reuses
responses, and limits history traversal to ten 50-entry pages. A consolidation
requires an indexed same-wallet transaction plus matching transaction data with
multiple inputs and one output to that wallet. Unknown fees remain unavailable;
they are never displayed as zero. Output labels require a matching block event,
transaction ID, and credited address. Existing navigation assets are unchanged.

Qualification includes the reported 36-input consolidation in block 4405, invalid
and missing fees, transfers that must not be classified as consolidations, phone
layouts, history pagination, and rejection of malformed or write requests by an
isolated nginx instance. Deploy with file-hash guards and a rollback copy, validate
with `nginx -t`, then reload nginx and check the public pages. No node binary
replacement is needed for the hosted display changes.
