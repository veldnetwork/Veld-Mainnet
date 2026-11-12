# Validator excess bond return

Veld 3.3.4 lets the owner of an active custodial validator bond request the
amount above the new 5,000 VELD minimum back without deregistering. It is gated by
the validator-policy activation height, pinned to block 34,750 for public mainnet.
See the [activation schedule](release-3.3.4-activation.md). The signed release
was published on November 12, 2026. Production funds cannot return before activation
and the full evidence window described below.

The signed operation is
`VELD_VALIDATOR|REDUCE_BOND|<public-key>|<registration-height>|<retained-units>`.
The registration height and exact retained amount bind the request to one term
and the inclusion-height policy. Owner authentication, the existing validator
operation cooldown, a held custodial bond, and canonical fields are required.
There can be one request per registration. Ordinary stake and co-mining principal
are separate and are not affected.

The full bond remains held and slashable while the request is pending. The return
is scheduled at the first 480-block settlement boundary strictly after both:

* The end of the request's current finality epoch plus the full 43,200-block
  finality evidence window.
* The request height plus the greater of the deregistration evidence cooldown
  and the ordinary slash evidence window.

Covering the whole frozen epoch also covers earlier signatures that were never
included in a canonical certificate. Later epochs use the new capped-weight
policy and do not extend the excess hold indefinitely. Arithmetic is checked in
128 bits; an unrepresentable boundary cannot be requested.

A slash or deregistration before the boundary cancels the partial-return path.
The full held bond then follows the existing slash or exit settlement. At the
boundary, the parent-scheduled settlement runs before new block operations. The
old evidence window has expired; a valid new-period slash or exit in that same
block acts on the retained bond.

The native block builder and validator use the existing mandatory stake-vault
settlement mechanism with the exact excess amount. The return is a normal owner
UTXO, funded from existing vault UTXOs with zero settlement fee. It creates no
subsidy. The request itself pays the ordinary transaction fee. After settlement,
the registration, active status and maturity remain, 5,000 VELD stays bonded, and
the full-principal terminal marker stays unset.

The three request/amount/settlement fields are part of validator consensus digest
version 10 only after policy activation. Copy, staged commit, reset, rollback
and replay preserve them. Earlier digest encodings remain unchanged. This is a
coordinated consensus change; mixed policy versions must not be activated.

`getbondvaultinfo` exposes exact atomic-unit amount strings and eligibility,
pending, cancelled and settled state. `preparereducevalidatorbond` prepares an
unsigned fee-only owner transaction; it does not sign or spend the bond. The
desktop wallet independently checks the minimum, registration, owner, amounts,
signer session, self-change destination and exact operation before signing.
The review displays every nonzero fractional atom and explains the delay.

Qualification separates injected-registry component checks from full native
admission with naturally earned funds, real owner signatures and the unshortened
evidence window. Private fixtures bypass hash work and use earlier activation
heights; they do not start network listeners or spend production funds.
