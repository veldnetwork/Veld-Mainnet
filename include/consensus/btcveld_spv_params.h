#pragma once
// btcVELD SPV relay activation parameters.
//
// The SPV mint gate activates at BTCVELD_SPV_ACTIVATION_HEIGHT. On the fresh genesis
// this is ARMED = 1 (trust-min SPV mint live from block 1). A value of 0 would mean
// OFF: VELD_MSPV ops ignored and the node's consensus behaviour (incl. the state
// digest) byte-identical to a chain without the relay — the same gate pattern the
// token ledger uses.
//
// Every value here is a compile-time constant (a consensus rule is
// a pure function of chain state + constants, never a per-node flag).

#include "core/btc_deposit_verify.h"   // btcspv:: BtcHeaderChain / BtcCheckpoint / U256 / VerifyDepositMint
#include "core/btc_relay_op.h"         // btcspv:: IsBtcHeaderOp / ApplyBtcHeaderOp (the BTC_HEADER relay op)
#include "core/constants.h"            // compiled custody descriptor and script identity
#include <vector>
#include <cstdint>

namespace veld {

#if defined(VELD_BTCVELD_REGTEST)
constexpr uint64_t BTCVELD_SPV_ACTIVATION_HEIGHT     = 1;     // regtest: SPV live from height 1
constexpr uint64_t BTCVELD_ISSUER_MINT_SUNSET_HEIGHT = 0;     // 0 == issuer mint never sunset
constexpr uint32_t BTCVELD_SPV_K_BTC                 = 3;     // shallow burial (isolated regtest only)
#else
constexpr uint64_t BTCVELD_SPV_ACTIVATION_HEIGHT     = 1;     // fresh-genesis : ARMED (trust-min SPV mint from block 1)
constexpr uint64_t BTCVELD_ISSUER_MINT_SUNSET_HEIGHT = 0;     // 0 == issuer mint never sunset (custodial fallback stays)
// External-value admission is intentionally much deeper than ordinary wallet
// confirmation policy.  The Veld relay validates Bitcoin headers + Merkle
// inclusion rather than full Bitcoin blocks, so an eclipsed relay must not be
// able to manufacture a cheap six-header private branch and mint against it.
// 144 blocks (~24h at target cadence) forces the attacker to sustain roughly a
// day of current-difficulty Bitcoin PoW while the deterministic freshness gate
// remains satisfied.  This makes the residual assumption a deep-Bitcoin-PoW
// security assumption rather than the former short-branch SPV weakness.
constexpr uint32_t BTCVELD_SPV_K_BTC                 = 144;
#endif

// Shared absolute custody cap (sats). A proof may use all remaining aggregate
// headroom; there is no smaller per-mint or per-address ceiling.
constexpr uint64_t BTCVELD_SPV_MAX_CUSTODY_SATS  = 1000000000ULL;  // 10 BTC total custody

// Is the SPV mint gate active at this Veld height?
inline bool BtcVeldSpvActive(uint64_t height) {
    return BTCVELD_SPV_ACTIVATION_HEIGHT != 0 && height >= BTCVELD_SPV_ACTIVATION_HEIGHT;
}
// Is the legacy issuer-signed mint still permitted here? (custodial transition window)
inline bool BtcVeldIssuerMintAllowed(uint64_t height) {
    return BTCVELD_ISSUER_MINT_SUNSET_HEIGHT == 0 || height < BTCVELD_ISSUER_MINT_SUNSET_HEIGHT;
}

// Strict, atomic hex decoder shared by the compiled constants and consensus
// payloads below.  A trailing half-byte must fail closed: silently truncating
// it would let consensus accept a redeem destination that the payout tooling
// (which requires whole bytes) correctly rejects.
inline std::vector<uint8_t> BtcVeldHex_(const char* h) {
    if (h == nullptr) return {};
    size_t n = 0;
    while (h[n] != '\0') ++n;
    if ((n & 1u) != 0) return {};

    auto nyb = [](char c)->int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    std::vector<uint8_t> v;
    v.reserve(n / 2);
    for (size_t i = 0; i < n; i += 2) {
        const int hi = nyb(h[i]);
        const int lo = nyb(h[i + 1]);
        if (hi < 0 || lo < 0) return {};
        v.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return v;
}

// Canonical custody scriptPubKey required by every SPV-proven BTC deposit.
inline const std::vector<uint8_t>& BtcVeldCustodySpk() {
    static const std::vector<uint8_t> spk = [] {
#if defined(VELD_BTCVELD_REGTEST)
        std::vector<uint8_t> configured =
            BtcVeldHex_(VELD_L3_DISPOSABLE_BTCVELD_CUSTODY_SPK_HEX);
        // The disposable build controller supplies a wallet-owned native
        // SegWit v0 keyhash script.  Fail closed if the quoted definition is
        // malformed even though its exact encoded length is compile-gated.
        if (configured.size() != 22 || configured[0] != 0x00 || configured[1] != 0x14)
            configured.clear();
        return configured;
#else
        std::vector<uint8_t> configured = BtcVeldHex_(BTCVELD_SPV_CUSTODY_SPK_HEX);
        // Fail closed if the compiled value is malformed. A production custody
        // output is exactly P2TR:
        // OP_1 (0x51), PUSH32 (0x20), 32-byte output key.
        if (configured.size() != 34 || configured[0] != 0x51 || configured[1] != 0x20)
            configured.clear();
        return configured;
#endif
    }();
    return spk;
}

// Relay PoW parameters (regtest vs mainnet). Consulted only when active.
inline btcspv::U256 BtcVeldPowLimit() {
#if defined(VELD_BTCVELD_REGTEST)
    return btcspv::CompactToTarget(0x207fffffu);
#else
    return btcspv::MainnetPowLimit();
#endif
}
inline bool BtcVeldNoRetarget() {
#if defined(VELD_BTCVELD_REGTEST)
    return true;
#else
    return false;
#endif
}

// Compiled BTC header checkpoint — a deeply-buried retarget boundary the relay
// bootstraps from (never BTC genesis). Consulted when the gate is active; on the fresh
// genesis a real mainnet checkpoint (height 957600, below) is compiled in.
//
// RELEASE STEP (keeps header-relay catch-up bounded to <= one 2016-block retarget
// period instead of growing unbounded as it rots): each build, run
//   scripts/refresh-btc-checkpoint.py   against a synced mainnet bitcoind and paste
// its output over the cp.* assignments in the #else branch below. The checkpoint
// MUST stay on a 2016 boundary (height % 2016 == 0) — a mid-period checkpoint lacks
// the prior period's opening timestamp and cannot validate the next retarget from
// relayed headers alone. See the script header for the full rationale.
inline btcspv::BtcCheckpoint BtcVeldCheckpoint() {
    btcspv::BtcCheckpoint cp;
    cp.chain_work = btcspv::U256::Zero();   // relative fork-choice from the checkpoint; baseline irrelevant
#if defined(VELD_BTCVELD_REGTEST)
    // Real Bitcoin Core regtest genesis (deterministic across every regtest datadir):
    // display hash 0f9188f1…2206, time 1296688602, bits 0x207fffff. cp.hash is the
    // INTERNAL (LE) block hash so a submitted block-1 header connects (its prev ==
    // cp_hash_). Without this the relay's headers are all rejected as orphans.
    cp.height = 0; cp.bits = 0x207fffffu; cp.time = 1296688602;
    { auto hb = BtcVeldHex_("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f");
      for (size_t i = 0; i < 32 && i < hb.size(); ++i) cp.hash[i] = hb[i]; }
    for (int i = 0; i < 10; ++i) cp.prev10_times[i] = cp.time;
#else
    // Release refresh : real mainnet-BTC checkpoint at retarget boundary 957600
    // (display hash 00000000000000000000c1294b131fbf6d489c74e52c13e905f003ad9ccb9ba2).
    // The hash, raw header, metadata and prior-ten timestamps were byte-equal
    // across two independent Bitcoin explorer APIs, and the internal hash below
    // was recomputed locally as dSHA256(the 80-byte header). cp.hash is the
    // INTERNAL (LE) block hash, so a submitted 957601 header connects
    // (its prev == cp_hash_). Without it SubmitHeader rejects EVERY relayed header as an
    // orphan and SPV mint + anchor-verify get no BTC view. MTP seeded from the real
    // prior-10 block times (heights 957590..957599, oldest first).
    cp.height = 957600; cp.bits = 0x1702369du; cp.time = 1783800551;
    { auto hb = BtcVeldHex_("a29bcb9cad03f005e9132ce5749c486dbf1f134b29c100000000000000000000");
      for (size_t i = 0; i < 32 && i < hb.size(); ++i) cp.hash[i] = hb[i]; }
    static const uint32_t p10[10] = { 1783790315u, 1783790490u, 1783792378u, 1783793146u,
                                      1783793553u, 1783794377u, 1783795436u, 1783796528u,
                                      1783798119u, 1783798937u };
    for (int i = 0; i < 10; ++i) cp.prev10_times[i] = p10[i];
#endif
    return cp;
}

}  // namespace veld
