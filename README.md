# Veld

Veld is a CPU-mined blockchain with a fixed 21,000,000 VELD maximum supply,
ML-DSA-65 native transaction and finality signatures, staking, and a
seven-validator finality layer. Native addresses currently use 160-bit
HASH160 commitments, and btcVELD custody inherits Bitcoin Taproot's current
secp256k1/Schnorr assumptions. This maintenance source retains the immutable
Veld 3.0.0 BUILD-02 launch identity on the live `veld-public-mainnet-v2`
network and includes the Veld 3.0.4 non-consensus maintenance changes.

The signed Windows client and its verification hashes are published at
[veld.network](https://veld.network/). Live chain state is available through
the [Explorer](https://explorer.veld.network/). See
[SOURCE_IDENTITY.md](SOURCE_IDENTITY.md) for the exact launch-source identity
and the documentation-only publication boundary.

## Mainnet profile

- Client version: `3.0.4`
- Deployment identity: `veld-public-mainnet-v2`
- State digest: `VELD_STATE_DIGEST_v8`
- Reserve wire formats: `RTP1` and `RVS1`
- Protocol version: `2`
- Genesis fingerprint:
  `880a0057852ffcfa35119a83e556802848ed5cb469b260fb9fbd20e8b97ae77b`
- Release ID: `VELD-3.0.0-BUILD-02-03388b12-c540616f`

The 21,000,000 VELD cap has no premine or treasury allocation. VELD enters
circulation through coinbase issuance under the deterministic reward-routing
rules. Mining uses the CPU-oriented VeldHash proof of work.

Staking becomes active when canonical issued supply reaches 10,000 VELD. The
finality layer requires at least seven qualified validators, each with an exact
10,000 VELD qualifying bond, and a consecutive-epoch warm-up. The staking
activation threshold and the per-validator finality bond are separate rules.

## btcVELD reserve

btcVELD uses a rolling canonical Bitcoin reserve represented by one exact
reserve outpoint and state-bound `RTP1`/`RVS1` transitions. Minting and
redemption are closed until the chain-derived seven-validator finality latch
has activated. Later liveness rules can pause new exposure, and separately
gated redemption-covenant features remain off until a coordinated activation.

No statement in this repository guarantees peg solvency, finality, resistance
to defects, or operational security. Review the code, the
[threat model](THREAT_MODEL.md), and the [security policy](SECURITY.md) before
operating it.

## Supported roles

- Windows mining packages run the mining-capable node and desktop wallet. The
  signed `Start Veld Node.bat` launcher explicitly selects clearnet operation.
- Linux operator builds provide the node, desktop client, key generator,
  standalone validator/finality daemon, authenticated operations portal, and
  fleet roles.
- Fleet builds define `VELD_FLEET_NO_MINE`; mining options and mining RPC
  surfaces are excluded and refused.
- Validator operation uses the node endorsement mode in the public Windows
  launcher. The standalone validator/finality daemon is also qualified as an
  unsigned Linux and Windows role, although it is not required by the Windows
  updater package.

The launchers do not make Tor, the network, or a wallet risk-free. Operators
remain responsible for host security, backups, firewall policy, authenticated
RPC/TLS configuration, and independent verification of release hashes and
signatures.

## Public-release security reductions

Veld public mainnet applies these release security boundaries:

- Veld 3.0.4 supports an official signed snapshot as a startup optimization.
  Snapshot state remains quarantined from RPC, inbound P2P, explorer, mining,
  and validator signing until an independent genesis IBD reaches the exact
  same tip and complete consensus-state digest. Full IBD remains available.
- Legacy request-time whole-chain scanners remain unavailable. The desktop
  wallet and explorer use the bounded
  `getaddresshistory` index instead: at most 50 rows per cursor page, with no
  block-body scan during a request.
- Seed material is never accepted in command-line arguments. Key import uses
  hidden terminal input or an explicitly inherited protected pipe/handle.
- UPnP is not compiled into public-mainnet artifacts, and `--upnp` is refused.

These boundaries do not change genesis, network magic, address encoding,
supply, finality, reserve accounting, state-digest version, or block validity.

## Build and contribute

Use the attested production controllers described in [BUILDING.md](BUILDING.md).
Security reports belong in the private process in [SECURITY.md](SECURITY.md),
not in a public issue. General contributions are described in
[CONTRIBUTING.md](CONTRIBUTING.md).

Operators should also review [LIVE_MAINNET_CHECKS.md](LIVE_MAINNET_CHECKS.md)
before running an Internet-facing node.

## Public web sources

- Homepage: `website/index.html`
- Explorer pages and API: `include/network/explorer.h`
- Hosted wallet and node wallet UI: `include/network/ui_desktop.h`
- Operations portal: `src/veld-miner-portal.py`
- Explorer deployment assets: `resources/explorer-*.js`

Production web surfaces are mainnet-only. Non-production validation profiles
are excluded by the production build controllers and are not deployed as
public services.

## License

Veld-authored source is licensed under the GNU Affero General Public License,
version 3 only (`SPDX-License-Identifier: AGPL-3.0-only`). Third-party material
remains under its own license; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
The source license does not grant rights in Veld branding; see
[TRADEMARKS.md](TRADEMARKS.md).
