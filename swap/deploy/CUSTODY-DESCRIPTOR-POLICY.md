# Custody descriptor policy

Custody remains exactly 3-of-5, with five independent community operators and
no fleet custody authority. Runtime manifest validation now enforces the entire
public descriptor produced by `custody-build-descriptor.sh`: the fixed NUMS
internal key, one `multi_a(3,...)` leaf, five distinct account public keys, and
the reviewed BIP86 mainnet account and external wildcard derivation paths.
Other script trees, thresholds, key counts, or derivation paths are refused.
The NUMS point follows [BIP 341's construction guidance](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs).
Bitcoin Core's [descriptor reference](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md#reference)
defines the internal-key and script-tree spending paths checked here.

Validation has separate required layers:

1. The local policy parser checks the complete descriptor structure, bounded
   fields, account xpub encoding and checksums, and distinct underlying public
   keys. Changing an origin label does not create an additional custody member.
2. Independently recorded descriptor and manifest hashes bind exact bytes.
   Veld's compiled descriptor identity, launch manifest, and index-zero custody
   script must match those pins.
3. Bitcoin Core validates the descriptor checksum and public key derivation.
   Every derived address must match the corresponding manifest script. The
   parser alone does not replace Core's cryptographic descriptor validation.

This is runtime enforcement of the existing ceremony format, not a custody
rotation or consensus change. Existing deployments with a different descriptor
must stop for review; operators must not rewrite pins or migrate funds merely
to satisfy the check. The public test descriptor in `swap/fixtures` came from
five disposable Bitcoin Core wallets and must never be used for custody.

Distinct public keys do not establish independent operator control. Enrollment,
key access, backups, managed-worker isolation, update governance, and old/new
custody epochs still require separate qualification. A descriptor policy cannot
establish unique payout intent across conflicting 3-of-5 groups. A02 remains
open, and the existing production payout-authority guard remains closed until
the authoritative intent and signature-retirement design is implemented and
qualified.
