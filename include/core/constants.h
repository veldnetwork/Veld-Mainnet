#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <ctime>
#include <atomic>
#include <iostream>

// Deployment-role selection belongs in this universal public-build header,
// not only version.h: standalone helpers such as the validator and one-time
// genesis miner also include constants.h and must not compile as an ambiguous
// roleless public artifact.
#if defined(VELD_PUBLIC_TESTNET) && defined(VELD_PUBLIC_MAINNET)
#error "a public artifact cannot be both testnet and final mainnet"
#endif
#if defined(VELD_PUBLIC_RELEASE) && !defined(VELD_PUBLIC_TESTNET) && \
    !defined(VELD_PUBLIC_MAINNET)
#error "VELD_PUBLIC_RELEASE requires exactly one explicit deployment role"
#endif
#if (defined(VELD_PUBLIC_TESTNET) || defined(VELD_PUBLIC_MAINNET)) && \
    !defined(VELD_PUBLIC_RELEASE)
#error "a public deployment role requires VELD_PUBLIC_RELEASE"
#endif
#if (defined(VELD_PUBLIC_TESTNET) || defined(VELD_PUBLIC_MAINNET)) && \
    !defined(VELD_MAINNET_POW)
#error "a public deployment role requires VELD_MAINNET_POW"
#endif

// Optional high-risk convenience surfaces are deliberately absent from every
// public-release artifact.  A developer/test build must opt in explicitly;
// accidentally carrying any of these profiles into a release is a hard build
// failure rather than a runtime configuration choice.
#if defined(VELD_PUBLIC_RELEASE) && \
    (defined(VELD_ENABLE_DIAGNOSTIC_TX_HISTORY) || \
     defined(VELD_ENABLE_UPNP))
#error "public releases cannot contain diagnostic history or UPnP"
#endif
#if defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP) && \
    !defined(VELD_USE_LEVELDB)
#error "snapshot bootstrap requires the canonical LevelDB storage backend"
#endif

// `VELD_REGTEST_FIXED_DIFF` is also the externally reported executable
// fingerprint for the disposable L3 consensus profile.  Do not let a
// partial macro set compile into an artifact that getnetworkinfo and the
// startup guard would misidentify as the complete four-part profile.
#if defined(VELD_REGTEST_FIXED_DIFF) && \
    (!defined(VELD_MAINNET_POW) || \
     !defined(VELD_TEST_CHAIN_BUILD) || \
     !defined(VELD_BTCVELD_REGTEST))
#error "VELD_REGTEST_FIXED_DIFF requires VELD_MAINNET_POW, VELD_TEST_CHAIN_BUILD, and VELD_BTCVELD_REGTEST"
#endif

// A public-release artifact may never contain a consensus test seam or bypass.
// Keep this interlock at the top of the shared constants header so every
// consensus-bearing binary (not just veld-node) fails during compilation if a
// build profile accidentally mixes production identity with a harness flag.
#if defined(VELD_PUBLIC_RELEASE) && \
    (defined(VELD_FUZZ_BUILD) || \
     defined(VELD_LOCAL_SIM) || \
     defined(VELD_REGTEST_FIXED_DIFF) || \
     defined(VELD_TEST_CHAIN_BUILD) || \
     defined(VELD_TEST_GOV_GATE) || \
     defined(VELD_TEST_PHASE_INTERLEAVE) || \
     defined(VELD_TEST_MINER_HISTORY_BLOCKS) || \
     defined(VELD_TEST_HOOKS) || \
     defined(VELD_GUI_TEST_INSTANCE) || \
     defined(VELD_DSTATE_QUALIFICATION) || \
     defined(VELD_TEST_NMS_BRANCH_CONTEXT) || \
     defined(VELD_TEST_STAKE_OUTPOINT_BACKING) || \
     defined(VELD_TEST_BTC_CUSTODY_LINEAGE) || \
     defined(VELD_TEST_BTC_REDEEM_BINDING) || \
     defined(VELD_TEST_BTC_RELAY_FRESHNESS) || \
     defined(VELD_TEST_BTC_OBSERVATION_FINALITY) || \
     defined(VELD_TEST_AMM_MARKET_SEED) || \
     defined(VELD_TEST_BRANCH_CONTEXT) || \
     defined(VELD_BTCVELD_REGTEST) || \
     defined(VELD_L3_DISPOSABLE_BTCVELD_AUTHORITY_ADDRESS) || \
     defined(VELD_L3_DISPOSABLE_BTCVELD_CUSTODY_SPK_HEX) || \
     defined(BTCVELD_REGTEST) || \
     defined(VELD_ROUTERD_TEST_KEYS) || \
     defined(VELD_RPC_TEST_NO_AUTH) || \
     defined(VELD_VDR_TEST) || \
     defined(VELD_TESTING))
#error "VELD_PUBLIC_RELEASE cannot be combined with consensus test or bypass macros"
#endif

// The disposable fixed-difficulty L3 profile must never inherit reusable
// btcVELD authority or custody identities.  Its build controller generates
// isolated keys, supplies the matching Veld address and Bitcoin scriptPubKey as
// quoted compile definitions, and seals the definitions and artifact digests
// in external evidence.  Reject either seam in every public or non-regtest
// profile, and reject an L3 btcVELD build that omits either value, so no
// artifact can silently fall back to a hardcoded test identity.
#if defined(VELD_L3_DISPOSABLE_BTCVELD_AUTHORITY_ADDRESS) && \
    (!defined(VELD_BTCVELD_REGTEST) || \
     !defined(VELD_TEST_CHAIN_BUILD) || \
     !defined(VELD_REGTEST_FIXED_DIFF) || \
     defined(VELD_PUBLIC_RELEASE))
#error "the disposable btcVELD authority override is restricted to the non-public fixed-difficulty L3 regtest profile"
#endif
#if defined(VELD_L3_DISPOSABLE_BTCVELD_CUSTODY_SPK_HEX) && \
    (!defined(VELD_BTCVELD_REGTEST) || \
     !defined(VELD_TEST_CHAIN_BUILD) || \
     !defined(VELD_REGTEST_FIXED_DIFF) || \
     defined(VELD_PUBLIC_RELEASE))
#error "the disposable btcVELD custody override is restricted to the non-public fixed-difficulty L3 regtest profile"
#endif
#if defined(VELD_BTCVELD_REGTEST) && \
    !defined(VELD_L3_DISPOSABLE_BTCVELD_AUTHORITY_ADDRESS)
#error "VELD_BTCVELD_REGTEST requires a compile-time disposable btcVELD authority address"
#endif
#if defined(VELD_BTCVELD_REGTEST) && \
    !defined(VELD_L3_DISPOSABLE_BTCVELD_CUSTODY_SPK_HEX)
#error "VELD_BTCVELD_REGTEST requires a compile-time disposable btcVELD custody script"
#endif
#if defined(VELD_L3_DISPOSABLE_BTCVELD_CUSTODY_SPK_HEX)
static_assert(sizeof(VELD_L3_DISPOSABLE_BTCVELD_CUSTODY_SPK_HEX) == 45,
              "the disposable btcVELD custody script must be a quoted 22-byte P2WPKH scriptPubKey");
static_assert(VELD_L3_DISPOSABLE_BTCVELD_CUSTODY_SPK_HEX[0] == '0' &&
                  VELD_L3_DISPOSABLE_BTCVELD_CUSTODY_SPK_HEX[1] == '0' &&
                  VELD_L3_DISPOSABLE_BTCVELD_CUSTODY_SPK_HEX[2] == '1' &&
                  VELD_L3_DISPOSABLE_BTCVELD_CUSTODY_SPK_HEX[3] == '4',
              "the disposable btcVELD custody script must use the P2WPKH 0014 prefix");
#endif

namespace veld {

// ── Runtime diagnostic verbosity (NON-consensus) ──────────────────────────
// Default OFF so the public client console shows only user-facing lines
// (Block mined, periodic status, vault/endorse events, errors). Enabled by
// the --verbose CLI flag or VELD_VERBOSE=1. Gates the per-block engine traces
// (mine_debug / post-mine / mineonly / commit / remine / endorse-diag / hb /
// nms-worker / replay-leveldb-sync). The gate is applied AT THE CALL SITE:
//     if (veld::DiagVerbose().load()) veld::vcerr() << ...;
// vcerr() is simply std::cerr. We deliberately do NOT use a thread-local null
// sink: MinGW mishandles thread_local objects with non-trivial destructors at
// mining-thread exit, corrupting the heap (the 2.7.28 Windows crash, exit
// 0xC0000374). A plain call-site conditional has no per-thread state at all.
inline std::atomic<bool>& DiagVerbose() { static std::atomic<bool> v{false}; return v; }
inline std::ostream& vcerr() { return std::cerr; }

constexpr uint64_t MAX_SUPPLY              = 21'000'000;
constexpr uint64_t VELD_UNITS              = 100'000'000;
constexpr uint64_t VEL_PER_VELD            = VELD_UNITS;
constexpr uint64_t MAX_SUPPLY_UNITS        = MAX_SUPPLY * VELD_UNITS;
constexpr uint64_t ANNUAL_EMISSION_CAP     = 550'000;   // flat 3.13926940 VELD/block @180s, split 50/20/20/10, mined all the way to the 21M cap in ~38 years (21M / 550K), then fee-funded. No separate premine or reserve schedule — the whole 21M is coinbase-issued. Chosen for a long fee-market runway before the subsidy ends + low steady-state dilution while keeping a real early-security subsidy (see 500-600K analysis).
constexpr uint64_t ANNUAL_EMISSION_UNITS   = ANNUAL_EMISSION_CAP * VELD_UNITS;

constexpr uint32_t TARGET_BLOCK_TIME       = 180;   // three-minute target for the fresh genesis chain
constexpr uint32_t BLOCKS_PER_HOUR        = 3600 / TARGET_BLOCK_TIME;
constexpr uint32_t BLOCKS_PER_DAY         = BLOCKS_PER_HOUR * 24;
constexpr uint32_t BLOCKS_PER_YEAR        = BLOCKS_PER_DAY * 365;

// Wall-clock sweep (fresh-genesis 3-min interlock, ): every consensus
// duration whose SEMANTIC is wall-clock (hours/days/years) is expressed via
// BLOCKS_PER_DAY / BLOCKS_PER_YEAR, so a TARGET_BLOCK_TIME change rescales them
// all to the same wall-clock automatically. Each carries a static_assert pinning
// the legacy 60-second profile value — compile-time proof the re-expression
// changed NOTHING for that legacy profile (pins go vacuous on a non-60s build).
// Constants whose semantic is a
// BLOCK COUNT (retarget/LWMA windows, MAX_REORG_DEPTH, co-mine/NMS windows,
// checkpoint + coinbase-routing cadences, short anti-abuse cooldowns) stay
// literal by design. The 144-block settlement/staker-flush cadence CANNOT move on
// the legacy profile; its fresh-genesis re-decision is force-interlocked at its definition.
constexpr uint64_t BLOCK_REWARD_UNITS      = (ANNUAL_EMISSION_UNITS / BLOCKS_PER_YEAR);

constexpr uint64_t ANNUAL_EMISSION_REMAINDER = ANNUAL_EMISSION_UNITS
                                               - (BLOCK_REWARD_UNITS * BLOCKS_PER_YEAR);

// Standard post-ramp LWMA retarget window. This is deliberately a block-count
// parameter (144 blocks, nominally 7.2 hours at the 180-second target), not a
// wall-clock "daily" duration.
constexpr uint32_t DIFFICULTY_ADJUSTMENT_INTERVAL = 144;
constexpr uint32_t CONFIRMATION_DEPTH             = 6;
constexpr uint32_t MAX_BLOCK_SIZE                 = 8'000'000;
constexpr uint32_t MAX_TRANSACTIONS_PER_BLOCK     = 4'096;
constexpr uint32_t MAX_TRANSACTION_INPUTS         = 10'000;
constexpr uint32_t MAX_TRANSACTION_OUTPUTS        = 10'000;
constexpr uint32_t MAX_STANDARD_TRANSACTION_OUTPUTS = 256;
static_assert(MAX_STANDARD_TRANSACTION_OUTPUTS < MAX_TRANSACTION_OUTPUTS,
              "standard fanout bound must remain below the system-distribution ceiling");
constexpr uint32_t VAULT_DISTRIBUTION_RESERVED_OUTPUTS = 2;
constexpr uint32_t MAX_VAULT_PAYOUT_STAKERS =
    MAX_TRANSACTION_OUTPUTS - VAULT_DISTRIBUTION_RESERVED_OUTPUTS;
static_assert(MAX_VAULT_PAYOUT_STAKERS +
                  VAULT_DISTRIBUTION_RESERVED_OUTPUTS ==
              MAX_TRANSACTION_OUTPUTS,
              "vault recipient capacity must exactly fit a valid transaction");
constexpr uint64_t MAX_REORG_DEPTH                = 100;

constexpr uint64_t CHECKPOINT_INTERVAL_BLOCKS               = 100;
constexpr uint64_t CHECKPOINT_ENFORCEMENT_ACTIVATES_AT_HEIGHT = 0;

constexpr const char* FLEET_CHECKPOINT_PUBKEY_HEX =
    "90db73430cfa781e78b9a3b6e585143a790c1fabf184e684821c37bc3d089d5a"
    "efde00992b4219752a370f01643defeee52f7336a7f3566823a68573552f29f7"
    "568c7af522896cf32c5afa1a64bf35c0fba1f6a02b1106cd480608e0d9004438"
    "37287833e875ab9441fa37202b6e8d6ec7d89408cc972f06b078d55e5c729823"
    "52d1a12563507c628e25beb0dba4cdcf093f4c6db8142c95998658efd4f3bb64"
    "5cca11e35416c8c8af71f30e9fa749118cb355dc4e7904da0f4fd5db11fbc44a"
    "9252c5c6ba9c86ec9b6baaccc7cf05e67687acd94bb989560cd9a999f756138f"
    "4b71b5b5108749520f20d31f830468d4f6354f83f1d1358428300de791600e36"
    "36d9214a8e1ff7051c77ec89fe61eceea01e7ef884732e563dbc1977b38651c4"
    "2556fb8b08abaa59979171a969bdecbf86f8ad27fb58cd56f570a1f39940a1ca"
    "167cd9e5de34a0467f4d4b5e9e4f345cb55003e49e2a12d0843e6d932c0dd990"
    "c17b51b658f5812afa81676186e88d4ea0b92c223f2091c0ef5948ca7283ca07"
    "3fbcf6539819efc303bc4e46df7514715c454795ef10a9b09cf01a3a2320bf39"
    "61fb85150c6cffc5c47525f10b1ceb0e0d5ce7746c6b777ea1b9ca938c702756"
    "0438b1722d4465bb1c9b7dfba11b933d7f125105f1bc664a3574835ca797a62b"
    "bb1ea763acadaad83480a6a5c3a4abe0eefd58a2547f4faaaf1f0f46f2a4a64e"
    "46171277a23c1051654473b108de49157c7828bd586db1057b9e3a8a27f242f5"
    "7f5a3ecd72266790525f5956fc6119102e2324aae3767afce1d6d42ab5666c55"
    "70bab62ffb26eff657d9e5be6c41069a86f2a5902a0ece5b2023f30a0f2be62b"
    "6d936f711511dcbdb7adb2f85cf53453771c1c880a2e5f961d5baf52a225da4d"
    "51c710683919dd389e3ccc7b58ece2874229d862f56b42c5efcbd34761a6bf17"
    "73fe87e16df53379bb6f7277952190bdf46aa0a418ce703f33b02f5bf37c4794"
    "c4458475b302414e01462aa5b0f9188a7bd718d0f01c22418d5fa60fd4552462"
    "18732068ff9df786b451f315af71ba50f4b4663f84d08431d48c75c4425b4cb9"
    "8bd794615c23ce92112f4a83ce504e4f9b6a183978892d7da2800bfb0fca9290"
    "3f7ebc79e094b419331e8e5d04836a6918ca4db1a8201079275362075eeba887"
    "4c5baf687c7cd51240296f7b304a458adc2dc79774df53746ab07ce9484ef6fd"
    "51db8e8149761d5012c58f7f1e51781a99a913663508676712f6db066e8c741f"
    "ca18be114cd0d0f9a5643630c7eb6a31161cd5c6500407eca8240f73563ca6a0"
    "7baffbf1e66522eed1e62a1708b241adc898a6565ffc5c496a219e4873e79537"
    "0c6b0d85033bb1858013f591ca6a9d3831863f78e7d5b9c866261eccdba8576d"
    "6731a9df1d7e0a646aa20785fd36f973ea7b627974217d8f1c7f49dcf6ac13e0"
    "0445250425ba08413b7f0c3a172b418c96a0499afbf614b6e23f8a7e43f0c85c"
    "70a5b04d7277da1ce88096d5cecbb94168e116b9020bad815f7304bd58e06ab8"
    "e796b9c008289ced5172e8db4f54198f1449619219148128e723662d7fa132d0"
    "93a1ffd92f604192ce62babf2be70eb0c3a8b6bc61c80564fbe0b7a624023ced"
    "a392c1036e75d5d0049f2b371c80f5c6d90f8e726381037d23f97e6775b5feb8"
    "4bd1c206664059601c7dcee875bf81c833fd34b43074d8a33ed5c4a1fd89786b"
    "2a759523e85cdfed5621be811a8c8d7cb2333d94bb69f6aba0c160409a212f36"
    "38a9bf59b406db59f62c29822a1a79f5d6f102ec119dd3e981a51a3e0270db7b"
    "2dd7bd9248f944a81cdcc4080804a92c5918901d4e855ae8c2475c2108c0b626"
    "8253e8b27ae13db3b7b0f2796838b335965c48ba5fdbc2b26078e65f4359e759"
    "e230ccb749bd58f79e99efbecd345ec48224089f9e5beeeccd47d9292322221f"
    "4da09b11c49c9a904370580a4d5c01fe81c53d7bed4a0133b6a4f87ed3e3fd9e"
    "d2ef4166020b3aa022adedd96a43292ecd5c24f89fd7855924a149f0404ce952"
    "d2f88ff4ac99bca758f062784ea3b26ecf8f90e625abdcb70f3e5e3c50117337"
    "5fe29346074c08ab678c3f0246cbc41f7c981a05a5548cb7eda55633c52322bb"
    "2c580adef40b47654f775c350e68c90aad5e5b9537c2c0cb58848dd49a3851d4"
    "c937d7e41e2a21f8945ab70a106adc0158cc2bc6835ec8664293b298c347d81e"
    "765667c982aa3ed1265c656c262dc271a14bdc5b924848c049b922e29ec90435"
    "5411884ff34936f360bc69bb2aee9beb4a4fb69ddceaac99e80bb5253adb2062"
    "eadfbb17f8aac218cba38c2b987bfbd11e7ac5774896422bf16738c1ee9a655c"
    "2d1ba2ea8d949463c87df775c34b884b917c4eb055b1ea6661613ffa0531a773"
    "17aea38cf12e8d20d9a468050ae850e734bbc5a1f4faf72fffa161b108336402"
    "7d0c1f48b75a4862e5d17dd8d9ed4525e0c85bfe74abb69b509994681925878f"
    "03db61fe2479dbf9ba7f36608bd6b9be51dc99bd82fcb2e7b8636ee4ffd19667"
    "de31599222b451f98aa716ebe7eb3e74f10edd4158601d16d9a02e07d2ba7a2c"
    "e429921157c3439efbf1453ff32dd595858236ff070e20c5190d4cc4561be38b"
    "5d96fbbd262105fb7896f4b68ec79a6894a9ba859c251ce34a6f86f2a81bf770"
    "a83cd90e8bad9459a65f577df589ff272d9896f84cf7cdc734ad4e72653d1752"
    "f699c5da219ba6762c1ddc99c5419ff5355eed264f62c8fd426db9f55fa1bd93";

inline const char* CheckpointPubkeyAtHeight(uint64_t ) {
    return FLEET_CHECKPOINT_PUBKEY_HEX;
}

#ifdef VELD_REGTEST_FIXED_DIFF
constexpr uint64_t COINBASE_MATURITY              = 3;
#else
constexpr uint64_t COINBASE_MATURITY              = 100;
#endif

constexpr uint64_t COINBASE_MATURITY_ACTIVATES_AT_HEIGHT = 0;
constexpr uint64_t COINBASE_MATURITY_CONSENSUS_HEIGHT    = 0;
constexpr uint64_t GAMING_GUARD_CONSENSUS_HEIGHT         = 0;
constexpr uint64_t FEES_TO_VAULT_ACTIVATES_AT            = 1;
constexpr uint64_t PROTOCOL_VAULT_SHARE_PCT              = 20;

#if (defined(VELD_MAINNET_POW) && defined(VELD_PUBLIC_RELEASE)) || \
    defined(VELD_TEST_STAKE_OUTPOINT_BACKING)
constexpr uint64_t STAKE_OUTPOINT_BACKING_ACTIVATION_HEIGHT = 1;
#else
constexpr uint64_t STAKE_OUTPOINT_BACKING_ACTIVATION_HEIGHT = 0;
#endif

inline constexpr bool StakeOutpointBackingActive(uint64_t height) noexcept {
    return STAKE_OUTPOINT_BACKING_ACTIVATION_HEIGHT != 0 &&
           height >= STAKE_OUTPOINT_BACKING_ACTIVATION_HEIGHT;
}

#ifdef VELD_MAINNET_POW
#if defined(VELD_PUBLIC_RELEASE) || defined(VELD_DSTATE_QUALIFICATION)
constexpr uint64_t MIN_STAKE_UNITS         = 1'000ULL * VELD_UNITS;
constexpr uint64_t MAX_STAKE_UNITS         = 10'000ULL * VELD_UNITS;
constexpr uint64_t STAKING_UNLOCK_SUPPLY   = 10'000ULL * VELD_UNITS;
constexpr uint64_t MIN_VALIDATOR_STAKE     = 10'000ULL * VELD_UNITS;
constexpr uint64_t VALIDATOR_UNLOCK_STAKED = 10'000ULL * VELD_UNITS;
static_assert(MIN_STAKE_UNITS == 1'000ULL * VELD_UNITS,
              "production consensus profile: Sybil threshold mis-set");
static_assert(STAKING_UNLOCK_SUPPLY == 10'000ULL * VELD_UNITS,
              "production consensus profile: staking must activate at 10,000 VELD issued supply");
static_assert(MIN_VALIDATOR_STAKE == 10'000ULL * VELD_UNITS,
              "production consensus profile: validator threshold mis-set");
static_assert(VALIDATOR_UNLOCK_STAKED == MIN_VALIDATOR_STAKE,
              "production consensus profile: validator system must unlock with staking at the configured aggregate threshold");
#else
constexpr uint64_t MIN_STAKE_UNITS         = 10ULL * VELD_UNITS;
constexpr uint64_t MAX_STAKE_UNITS         = 10'000ULL * VELD_UNITS;
constexpr uint64_t STAKING_UNLOCK_SUPPLY   = 50ULL * VELD_UNITS;
constexpr uint64_t MIN_VALIDATOR_STAKE     = 50ULL * VELD_UNITS;
constexpr uint64_t VALIDATOR_UNLOCK_STAKED = 50ULL * VELD_UNITS;
#endif
#else
constexpr uint64_t MIN_STAKE_UNITS         = 10 * VELD_UNITS;
constexpr uint64_t MAX_STAKE_UNITS         = 10'000 * VELD_UNITS;
constexpr uint64_t STAKING_UNLOCK_SUPPLY   = 50ULL * VELD_UNITS;
constexpr uint64_t MIN_VALIDATOR_STAKE     = 20 * VELD_UNITS;
constexpr uint64_t VALIDATOR_UNLOCK_STAKED = 10ULL * VELD_UNITS;
#endif

constexpr uint64_t GOVERNANCE_ACTIVATION_BONDED_UNITS = 5ULL * MIN_VALIDATOR_STAKE;
#if (defined(VELD_MAINNET_POW) && \
     (!defined(VELD_TEST_CHAIN_BUILD) || defined(VELD_DSTATE_QUALIFICATION)) && \
     !defined(VELD_FUZZ_BUILD)) \
    || defined(VELD_TEST_GOV_GATE)
constexpr bool GOVERNANCE_BOND_GATE_ACTIVE = true;
#else
constexpr bool GOVERNANCE_BOND_GATE_ACTIVE = false;
#endif
#if defined(VELD_MAINNET_POW) && \
    (!defined(VELD_TEST_CHAIN_BUILD) || defined(VELD_DSTATE_QUALIFICATION)) \
    && !defined(VELD_FUZZ_BUILD) && !defined(VELD_TEST_GOV_GATE)
static_assert(GOVERNANCE_ACTIVATION_BONDED_UNITS == 50'000ULL * VELD_UNITS,
              "mainnet governance activation must be 50,000 VELD (5 validators × 10k bonded)");
#endif

#if defined(VELD_PUBLIC_RELEASE) || defined(VELD_DSTATE_QUALIFICATION)
constexpr bool VALIDATOR_SYSTEM_ALWAYS_ACTIVE = false;
#else
constexpr bool VALIDATOR_SYSTEM_ALWAYS_ACTIVE = true;
#endif

constexpr uint64_t SLASH_EVIDENCE_WINDOW = 7ULL * BLOCKS_PER_DAY;
static_assert(TARGET_BLOCK_TIME != 60 || SLASH_EVIDENCE_WINDOW == 10080,
              "wall-clock re-expression must not change the legacy 60-second profile");
constexpr size_t   MAX_SLASHED_EVIDENCE  = 50000;
constexpr uint32_t MAX_EVIDENCE_PER_PUBKEY = 10;
constexpr uint64_t VALIDATOR_SLASHING_HEIGHT   = 0;
constexpr uint64_t SLASH_BOND_LOCKUP_BLOCKS    = 30ULL * BLOCKS_PER_DAY;
static_assert(TARGET_BLOCK_TIME != 60 || SLASH_BOND_LOCKUP_BLOCKS == 43200,
              "wall-clock re-expression must not change the legacy 60-second profile");
constexpr uint64_t BOND_YIELD_VEST_BLOCKS      = 90ULL * BLOCKS_PER_DAY;
static_assert(TARGET_BLOCK_TIME != 60 || BOND_YIELD_VEST_BLOCKS == 129600,
              "wall-clock re-expression must not change the legacy 60-second profile");
constexpr uint64_t SLASH_EQUIV_SLASHER_PPM = 250'000;
constexpr uint64_t SLASH_EQUIV_BURN_PPM    = 750'000;
static_assert(SLASH_EQUIV_SLASHER_PPM + SLASH_EQUIV_BURN_PPM == 1'000'000,
              "equivocation slash must return 0% of principal");
static const std::string STAKE_VAULT_ADDRESS   = "VV6pcrLQvxq7uBZEFtc4qxCizQ26azxTtK";
constexpr uint64_t STAKE_VAULT_ACTIVATION_HEIGHT = VALIDATOR_SLASHING_HEIGHT;
constexpr uint64_t BOND_SETTLEMENT_INTERVAL    = BLOCKS_PER_DAY;
static_assert(TARGET_BLOCK_TIME == 60 || BOND_SETTLEMENT_INTERVAL == BLOCKS_PER_DAY,
              "the settlement/staker-flush cadence is BLOCKS_PER_DAY on any non-60s chain");
constexpr uint64_t SLASH_SLASHER_PPM           = 250000;
constexpr uint64_t SLASH_VAULT_PPM             = 250000;
constexpr uint64_t SLASH_BOUNTY_HEIGHT         = 0;
constexpr uint64_t ENDORSEMENT_DEDUP_HEIGHT    = 0;
static_assert(SLASH_SLASHER_PPM + SLASH_VAULT_PPM <= 1'000'000,
              "slash split ppm must not exceed 100%");
static const std::string BOND_YIELD_ESCROW = "VSBBBLkFn775t1BoSn7a7nPUNJxxByyALd";
constexpr uint64_t BOND_YIELD_ACTIVATION_HEIGHT = 0;
constexpr uint64_t MIN_EVIDENCE_WINDOW = BLOCKS_PER_DAY / 2;
static_assert(TARGET_BLOCK_TIME != 60 || MIN_EVIDENCE_WINDOW == 720,
              "wall-clock re-expression must not change the legacy 60-second profile");
static_assert(BOND_YIELD_ACTIVATION_HEIGHT % BOND_SETTLEMENT_INTERVAL == 0,
              "bond-yield activation must be a clean settlement-boundary multiple");
constexpr uint64_t COVENANTS_ACTIVATION_HEIGHT = 0;

inline constexpr const char* BTCVELD_TOKEN_ID  = "btcVELD";
inline constexpr const char* BTCVELD_PEG_ASSET = "BTC";
constexpr uint8_t            BTCVELD_DECIMALS   = 8;
constexpr const char* BTCVELD_CUSTODY_DESCRIPTOR_SHA256 =
    "8cb9c00d473f7ecf9cb8e022f8345f023e6a12a3c2bbd87f87c13f9052773c84";
constexpr const char* BTCVELD_CUSTODY_MANIFEST_SHA256 =
    "9074dced0118c7c256a3c4c53c5e48956699a88ef703ecff036f24e9794311bb";
constexpr const char* BTCVELD_SPV_CUSTODY_SPK_HEX =
    "5120e1375941632c9404dd62c8c5d75449feccf1271b4b8f083dcd054784203a782e";
constexpr uint32_t BTCVELD_SPV_CUSTODY_DESCRIPTOR_INDEX = 0;
constexpr uint32_t BTCVELD_CUSTODY_DESCRIPTOR_RANGE_START = 0;
constexpr uint32_t BTCVELD_CUSTODY_DESCRIPTOR_RANGE_END = 999;
constexpr int64_t BTCVELD_ISSUER_MAX_CUSTODY_SATS  = 1000000000LL;
constexpr uint32_t BTCVELD_ANCHOR_BTC_CONFS         = 144;
constexpr uint64_t BTCVELD_FINALITY_ACTIVATION_HEIGHT = 0;
constexpr uint64_t BTCVELD_FINALITY_WINDOW            = 7ULL * BLOCKS_PER_DAY;
static_assert(TARGET_BLOCK_TIME != 60 || BTCVELD_FINALITY_WINDOW == 10080,
              "wall-clock re-expression must not change the legacy 60-second profile");
constexpr uint64_t BTCVELD_TIER_LADDER_ACTIVATION_HEIGHT = 1;
constexpr uint64_t BTCVELD_TIER_WINDOW_BLOCKS            = 14ULL * BLOCKS_PER_DAY;
static_assert(TARGET_BLOCK_TIME != 60 || BTCVELD_TIER_WINDOW_BLOCKS == 20160,
              "wall-clock re-expression must not change the legacy 60-second profile");
constexpr uint64_t BTCVELD_REDEEM_GUARD_ACTIVATION_HEIGHT = 1;
constexpr uint64_t BTCVELD_REDEEM_WINDOW_BLOCKS           = BLOCKS_PER_DAY;
constexpr uint64_t BTCVELD_REDEEM_WINDOW_PPM_OF_CAP       = 200'000;
static_assert(BTCVELD_REDEEM_WINDOW_BLOCKS > 0,
              "redeem drain-guard window must be nonzero");
static_assert(BTCVELD_REDEEM_WINDOW_PPM_OF_CAP > 0 &&
              BTCVELD_REDEEM_WINDOW_PPM_OF_CAP <= 1'000'000,
              "redeem window fraction is parts-per-million of the custody cap");
constexpr uint64_t BTCVELD_REDEEM_SPK_CHECK_ACTIVATION_HEIGHT = 1;
constexpr uint64_t BTCVELD_MINT_DEPOSIT_ID_ACTIVATION_HEIGHT = 1;
constexpr uint64_t BTCVELD_AMM_ACTIVATION_HEIGHT = 1;
constexpr uint64_t BTCVELD_AMM_SWAP_GATE_ACTIVATION_HEIGHT = 1;
constexpr uint64_t BTCVELD_AMM_SWAP_UNLOCK_HEIGHT          = 0;
constexpr int64_t  BTCVELD_AMM_MAX_POOL_BTCVELD_SATS       = 1'000'000'000;
// Legacy fixed-ratio constant retained for historical/test profiles and tooling.
constexpr int64_t  BTCVELD_AMM_OPENING_VELD_UNITS_PER_BTCVELD_SAT = 100'000;
// Owner-approved launch policy: public releases let the first valid LP seed set
// the immutable opening market anchor.  The existing per-leg floors, permanent
// locked LP, supply/custody caps, seed-liveness checks and four-band fee model
// remain consensus-enforced; only the fixed 100,000:1 price pin is removed.
#if (defined(VELD_MAINNET_POW) && defined(VELD_PUBLIC_RELEASE)) || \
    defined(VELD_TEST_AMM_MARKET_SEED)
constexpr uint64_t BTCVELD_AMM_MARKET_SEED_ACTIVATION_HEIGHT = 1;
#else
constexpr uint64_t BTCVELD_AMM_MARKET_SEED_ACTIVATION_HEIGHT = 0;
#endif

constexpr uint32_t BTCVELD_AMM_FEE_BPS                     = 100;
constexpr uint32_t BTCVELD_AMM_FEE_MIN_BPS                 = 30;
static_assert(BTCVELD_AMM_MAX_POOL_BTCVELD_SATS > 0,
              "the Layer-4 pool cap must be positive");
static_assert(BTCVELD_AMM_MAX_POOL_BTCVELD_SATS == BTCVELD_ISSUER_MAX_CUSTODY_SATS,
              "the AMM must not impose a smaller ceiling than aggregate BTC custody");
static_assert((unsigned __int128)BTCVELD_AMM_MAX_POOL_BTCVELD_SATS *
                  BTCVELD_AMM_OPENING_VELD_UNITS_PER_BTCVELD_SAT <=
              (unsigned __int128)MAX_SUPPLY_UNITS,
              "legacy canonical seed ratio must fit the native supply domain");
static_assert(BTCVELD_AMM_FEE_MIN_BPS <= BTCVELD_AMM_FEE_BPS,
              "AMM base fee must not exceed its ceiling");
constexpr uint32_t BTCVELD_AMM_BAND_EDGE_BPS[3] = { 500, 1000, 2000 };
constexpr uint32_t BTCVELD_AMM_BAND_FEE_BPS[4]  = { 30, 50, 75, 100 };
constexpr uint64_t BTCVELD_AMM_FOURBAND_ACTIVATION_HEIGHT = 1;
static_assert(BTCVELD_AMM_BAND_FEE_BPS[0] == BTCVELD_AMM_FEE_MIN_BPS &&
              BTCVELD_AMM_BAND_FEE_BPS[3] == BTCVELD_AMM_FEE_BPS,
              "four-band endpoints must equal the 30-bps base and 100-bps ceiling");
static_assert(BTCVELD_AMM_BAND_FEE_BPS[0] < BTCVELD_AMM_BAND_FEE_BPS[1] &&
              BTCVELD_AMM_BAND_FEE_BPS[1] < BTCVELD_AMM_BAND_FEE_BPS[2] &&
              BTCVELD_AMM_BAND_FEE_BPS[2] < BTCVELD_AMM_BAND_FEE_BPS[3] &&
              BTCVELD_AMM_BAND_EDGE_BPS[0] < BTCVELD_AMM_BAND_EDGE_BPS[1] &&
              BTCVELD_AMM_BAND_EDGE_BPS[1] < BTCVELD_AMM_BAND_EDGE_BPS[2],
              "four-band fees and edges must be strictly ascending");

#if defined(VELD_BTCVELD_REGTEST)
constexpr uint64_t           BTCVELD_ACTIVATION_HEIGHT = 0;
inline constexpr const char* BTCVELD_ISSUER_ADDRESS =
    VELD_L3_DISPOSABLE_BTCVELD_AUTHORITY_ADDRESS;
static_assert(sizeof(VELD_L3_DISPOSABLE_BTCVELD_AUTHORITY_ADDRESS) == 35,
              "the disposable btcVELD authority must be a quoted 34-character Veld address");
#else
constexpr uint64_t           BTCVELD_ACTIVATION_HEIGHT = 0;
inline constexpr const char* BTCVELD_ISSUER_ADDRESS    = "VUjD1JoewGkiGxRqJ52FkK1UiMotjsp9Tg";
#endif

constexpr uint64_t BOND_YIELD_STAKED_POSITION_HEIGHT = 0;
static_assert(BOND_YIELD_STAKED_POSITION_HEIGHT % BOND_SETTLEMENT_INTERVAL == 0,
              "staked-position gate must be a clean settlement/vault-boundary multiple");
static_assert(BOND_YIELD_STAKED_POSITION_HEIGHT > BOND_YIELD_ACTIVATION_HEIGHT
              || (BOND_YIELD_STAKED_POSITION_HEIGHT == 0
                  && BOND_YIELD_ACTIVATION_HEIGHT == 0),
              "staked-position gate must be strictly after D' activation unless both are zero");
constexpr uint64_t TX_FULL_VALIDATION_ACTIVATION_HEIGHT = 0;
static_assert(TX_FULL_VALIDATION_ACTIVATION_HEIGHT % BOND_SETTLEMENT_INTERVAL == 0,
              "C1/C2 gate must be a clean settlement/vault boundary");
static_assert(TX_FULL_VALIDATION_ACTIVATION_HEIGHT > BOND_YIELD_STAKED_POSITION_HEIGHT
              || (TX_FULL_VALIDATION_ACTIVATION_HEIGHT == 0
                  && BOND_YIELD_STAKED_POSITION_HEIGHT == 0),
              "C1/C2 gate ordering invalid");
constexpr uint64_t TX_FULL_VALIDATION_V2_ACTIVATION_HEIGHT = 0;
static_assert(TX_FULL_VALIDATION_V2_ACTIVATION_HEIGHT % BOND_SETTLEMENT_INTERVAL == 0,
              "C1-v2 gate must be a clean settlement/vault boundary");
static_assert(TX_FULL_VALIDATION_V2_ACTIVATION_HEIGHT > TX_FULL_VALIDATION_ACTIVATION_HEIGHT
              || (TX_FULL_VALIDATION_V2_ACTIVATION_HEIGHT == 0
                  && TX_FULL_VALIDATION_ACTIVATION_HEIGHT == 0),
              "C1-v2 gate ordering invalid");

constexpr uint16_t MAINNET_PORT            = 8333;
constexpr uint16_t TESTNET_PORT            = 18333;
constexpr uint32_t PROTOCOL_VERSION        = 2;
constexpr uint32_t MIN_PEER_CONNECTIONS    = 4;
constexpr uint32_t MAX_PEER_CONNECTIONS    = 125;
constexpr uint32_t MAINNET_MAGIC           = 0x56454C44;
constexpr uint32_t TESTNET_MAGIC           = 0x74564C44;
constexpr const char* GENESIS_TIMESTAMP_STR = "2026-08-01T15:46:00Z";
constexpr const char* GENESIS_MESSAGE        = "Veld - Where value is earned.";

namespace genesis_iso {
    constexpr int  digit(char c)  { return (c >= '0' && c <= '9') ? c - '0' : -1; }
    constexpr bool isleap(int y)  { return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0); }
    constexpr int  mdays(int y, int m) {
        constexpr int t[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
        return (m == 2 && isleap(y)) ? 29 : t[m - 1];
    }
    constexpr uint64_t parse(const char* s) {
        if (!s) return 0;
        for (int i = 0; i < 20; ++i) if (s[i] == '\0') return 0;
        if (s[20] != '\0') return 0;
        if (s[4]!='-'||s[7]!='-'||s[10]!='T'||s[13]!=':'||s[16]!=':'||s[19]!='Z') return 0;
        int y = digit(s[0])*1000 + digit(s[1])*100 + digit(s[2])*10 + digit(s[3]);
        int mo = digit(s[5])*10 + digit(s[6]);
        int d  = digit(s[8])*10 + digit(s[9]);
        int hh = digit(s[11])*10 + digit(s[12]);
        int mm = digit(s[14])*10 + digit(s[15]);
        int ss = digit(s[17])*10 + digit(s[18]);
        if (y < 1970 || mo < 1 || mo > 12 || d < 1 || d > mdays(y, mo)
            || hh < 0 || hh > 23 || mm < 0 || mm > 59 || ss < 0 || ss > 60) return 0;
        uint64_t days = 0;
        for (int yy = 1970; yy < y; ++yy) days += isleap(yy) ? 366 : 365;
        for (int mm2 = 1; mm2 < mo; ++mm2) days += mdays(y, mm2);
        days += (uint64_t)(d - 1);
        return days * 86400ULL + (uint64_t)hh * 3600ULL + (uint64_t)mm * 60ULL + (uint64_t)ss;
    }
}
static_assert(genesis_iso::parse(GENESIS_TIMESTAMP_STR) != 0,
              "GENESIS_TIMESTAMP_STR must parse as YYYY-MM-DDTHH:MM:SSZ");
constexpr uint64_t    GENESIS_NONCE          = 187948ULL;
constexpr const char* GENESIS_HASH =
    "880a0057852ffcfa35119a83e556802848ed5cb469b260fb9fbd20e8b97ae77b";
// The first launch-chain block is a second, signed-snapshot identity boundary.
// It prevents a snapshot from another history which reused the compiled
// genesis from being accepted. This is the node's canonical internal hash
// rendering, not a DNS, website, or operator-supplied value.
constexpr uint64_t SNAPSHOT_LAUNCH_ANCHOR_HEIGHT = 1;
constexpr const char* SNAPSHOT_LAUNCH_ANCHOR_HASH =
    "c595cc31fe47999186a402ee7c6fb8bdf97415e4e9d9e643733a828e2ce573d1";
constexpr uint64_t    GENESIS_TIME           = 1785599160;
static_assert(sizeof(std::time_t) >= 8,
              "Veld requires 64-bit time_t");
static_assert(genesis_iso::parse(GENESIS_TIMESTAMP_STR) == GENESIS_TIME,
              "GENESIS_TIMESTAMP_STR must equal GENESIS_TIME — bump both together");
constexpr uint32_t    GENESIS_BITS           = 0x1e390000;
static_assert((GENESIS_BITS & 0x00FFFFFFu) != 0,
              "GENESIS_BITS mantissa is zero");
static_assert((GENESIS_BITS & 0x00800000u) == 0,
              "GENESIS_BITS mantissa sign bit is set");
static_assert(((GENESIS_BITS >> 24) & 0xFFu) >= 0x1cu &&
              ((GENESIS_BITS >> 24) & 0xFFu) <= 0x1fu,
              "GENESIS_BITS exponent out of the sane PoW band");
#if defined(VELD_MAINNET_POW) && !defined(VELD_FUZZ_BUILD) && \
    (!defined(VELD_TEST_CHAIN_BUILD) || defined(VELD_DSTATE_QUALIFICATION))
static_assert(GENESIS_BITS != 0x1e400000u,
              "GENESIS_BITS regressed to the retired pre-relaunch seed");
#endif
#if defined(VELD_MAINNET_POW) && defined(VELD_TEST_CHAIN_BUILD) && \
    !defined(VELD_FUZZ_BUILD) && !defined(VELD_DSTATE_QUALIFICATION)
static_assert(GENESIS_BITS == 0x1e390000u,
              "GENESIS_BITS no longer matches this source tree's test-chain seed");
#endif

static const std::string VAULT_ADDRESS            = "VVzm6RG8W1t3U9KQYoD34z49jHcYb1sXdv";
inline const std::string& VaultAddressAtHeight(uint64_t ) { return VAULT_ADDRESS; }
static const std::string POOL_ADDRESS             = "VHkWh9Xfbnp3gCotHSeM9LLN5MwcoXYijZ";
static const std::string ENDORSEMENT_POOL_ADDRESS = "VQ3MkHSNrXYXiWQErPfUUu4hWWEVvpfAFT";
inline const std::string& PoolAddressAtHeight(uint64_t ) { return POOL_ADDRESS; }
inline const std::string& EndorsementPoolAddressAtHeight(uint64_t ) { return ENDORSEMENT_POOL_ADDRESS; }
inline const std::string& StakeVaultAddressAtHeight(uint64_t ) { return STAKE_VAULT_ADDRESS; }
inline const std::string& BondYieldEscrowAtHeight(uint64_t ) { return BOND_YIELD_ESCROW; }

#ifdef VELD_MAINNET_POW
constexpr uint64_t STAKING_ACTIVATION_SUPPLY  = STAKING_UNLOCK_SUPPLY;
constexpr uint64_t STAKING_ACTIVATION_VELD    = STAKING_ACTIVATION_SUPPLY / VELD_UNITS;
constexpr uint64_t STAKE_LOCKUP_BLOCKS        = 7ULL * BLOCKS_PER_DAY;
static_assert(TARGET_BLOCK_TIME != 60 || STAKE_LOCKUP_BLOCKS == 10'080,
              "wall-clock re-expression must not change the legacy 60-second profile");
#else
constexpr uint64_t STAKING_ACTIVATION_SUPPLY  = STAKING_UNLOCK_SUPPLY;
constexpr uint64_t STAKING_ACTIVATION_VELD    = STAKING_ACTIVATION_SUPPLY / VELD_UNITS;
constexpr uint64_t STAKE_LOCKUP_BLOCKS         = 20;
#endif
static_assert(STAKING_ACTIVATION_VELD * VELD_UNITS == STAKING_ACTIVATION_SUPPLY,
              "staking activation display value must match the consensus supply gate");
constexpr uint64_t VAULT_DISTRIBUTION_INTERVAL = BLOCKS_PER_DAY;
static_assert(VAULT_DISTRIBUTION_INTERVAL == BOND_SETTLEMENT_INTERVAL,
              "the staker-flush and bond-settlement cadences must move together");
#ifdef VELD_VDR_TEST
constexpr uint64_t VAULT_SIGLESS_ACTIVATION_HEIGHT = 1;
#else
constexpr uint64_t VAULT_SIGLESS_ACTIVATION_HEIGHT = 0;
#endif
constexpr uint64_t VAULT_DISTRIBUTION_PPM       = 80000;
constexpr uint64_t VAULT_INFLOW_PAYOUT_PPM      = 900'000;
constexpr uint64_t VAULT_INFLOW_CAP_ACTIVATION_HEIGHT = 0;
constexpr uint64_t VAULT_FEE_PER_INPUT_UNITS    = 1000;
constexpr uint64_t VAULT_CONCENTRATION_CAP_PPM  = 750000;
constexpr uint64_t VAULT_MIN_DISTRIBUTABLE_UNITS = 1000;
constexpr uint32_t COMINE_NEARMISS_MULTIPLIER  = 4;
constexpr const char*    NMS_MAGIC                  = "VELD_NMS";
constexpr size_t         NMS_MAGIC_LEN              = 8;
constexpr uint8_t        NMS_VERSION                = 0x01;
constexpr size_t         NMS_HEADER_LEN             = 88;
constexpr size_t         NMS_PAYLOAD_LEN            = NMS_MAGIC_LEN + 1 + NMS_HEADER_LEN;
constexpr uint64_t       NMS_MAX_PREV_HEIGHT_GAP    = 100;
// NMS verification performs the same memory-hard primitive as block PoW.
// Public-mainnet-v2 begins at fresh genesis, so consensus admits a deliberately
// small fixed work envelope rather than allowing 4,095 hashes in one block.
constexpr size_t         MAX_NMS_RECORDS_PER_BLOCK  = 4;
constexpr uint64_t       NMS_WINDOW_DEDUP_BLOCKS    = 200;
constexpr uint64_t       COMINE_WINDOW_BLOCKS       = 100;
constexpr uint64_t       BOOTSTRAP_BLOCKS           = 30;
#ifdef VELD_MAINNET_POW
constexpr uint64_t       EARLY_RAMP_END_HEIGHT      = 390;
constexpr uint64_t       EARLY_RETARGET_INTERVAL    = 36;
constexpr uint64_t       EARLY_LWMA_WINDOW          = 36;
constexpr uint64_t       EARLY_CLAMP_DIVISOR        = 4;
static_assert(EARLY_RAMP_END_HEIGHT == BOOTSTRAP_BLOCKS + 10 * EARLY_RETARGET_INTERVAL,
              "EARLY_RAMP_END_HEIGHT must equal BOOTSTRAP_BLOCKS + 10 windows");
static_assert(EARLY_RETARGET_INTERVAL >= 1 && EARLY_RETARGET_INTERVAL <= 144,
              "EARLY_RETARGET_INTERVAL out of sane range");
static_assert(EARLY_CLAMP_DIVISOR >= 2,
              "EARLY_CLAMP_DIVISOR must be >= 2");
#endif
constexpr size_t         LOTTERY_K_SMALL_FLEET           = 5;
constexpr size_t         LOTTERY_K_LARGE_FLEET           = 20;
constexpr size_t         LOTTERY_FLEET_SIZE_THRESHOLD    = 1000;
constexpr uint64_t       LOTTERY_KSLOT_DIVISOR_HEIGHT    = 0;
constexpr uint32_t LOTTERY_AGG_SEED_K                       = 8;
constexpr uint64_t LOTTERY_AGG_SEED_ACTIVATION_HEIGHT       = 1;
constexpr uint64_t       NMS_MIN_BOND_UNITS         = MIN_STAKE_UNITS;
constexpr bool           OPTION_B_CONSENSUS_GATE_ENABLED = true;
constexpr uint64_t VAULT_BLOCK_INTERVAL      = 100;
constexpr uint64_t MIN_TX_FEE                = 100'000;
constexpr uint64_t AMM_SEED_LIVENESS_TX_FEE_UNITS = 100'000;
constexpr uint64_t AMM_SEED_LIVENESS_FEE_RESERVE_UNITS =
    2 * AMM_SEED_LIVENESS_TX_FEE_UNITS;
static_assert(AMM_SEED_LIVENESS_TX_FEE_UNITS == MIN_TX_FEE,
              "seed-liveness transaction fee must match the launch wallet/relay fee");
constexpr uint64_t VALIDATOR_OP_COOLDOWN_BLOCKS    = 100;
constexpr uint64_t GOV_SUBMIT_COOLDOWN_BLOCKS      = BLOCKS_PER_DAY / 2;
constexpr uint64_t GOV_VOTE_CHANGE_COOLDOWN_BLOCKS = 6;
constexpr uint64_t GOV_SIG_REPLAY_WINDOW_BLOCKS    = 60;
constexpr uint64_t GOV_PRUNE_DELAY_BLOCKS          = 30ULL * BLOCKS_PER_DAY;
static_assert(TARGET_BLOCK_TIME != 60 ||
              (GOV_SUBMIT_COOLDOWN_BLOCKS == 720 && GOV_PRUNE_DELAY_BLOCKS == 43200),
              "wall-clock re-expression must not change the legacy 60-second profile");
#ifdef VELD_MAINNET_POW
constexpr uint64_t BATCH1_HARDENING_HEIGHT = 0;
constexpr uint64_t BATCH2_HARDENING_HEIGHT = 0;
constexpr uint64_t BATCH3_HARDENING_HEIGHT = 0;
#else
constexpr uint64_t BATCH1_HARDENING_HEIGHT = 0;
constexpr uint64_t BATCH2_HARDENING_HEIGHT = 0;
constexpr uint64_t BATCH3_HARDENING_HEIGHT = 0;
#endif
static_assert(BATCH3_HARDENING_HEIGHT % BOND_SETTLEMENT_INTERVAL == 0,
              "BATCH3_HARDENING_HEIGHT must be a bond-settlement boundary");
#ifdef VELD_MAINNET_POW
constexpr uint64_t ENDORSE_CANONICAL_HEIGHT = 0;
#else
constexpr uint64_t ENDORSE_CANONICAL_HEIGHT = 0;
#endif
static_assert(ENDORSE_CANONICAL_HEIGHT % BOND_SETTLEMENT_INTERVAL == 0,
              "ENDORSE_CANONICAL_HEIGHT must be a flush/settlement boundary");
constexpr uint64_t DUST_THRESHOLD_UNITS = 1000;

#if defined(VELD_MAINNET_POW) && !defined(VELD_FUZZ_BUILD) && \
    (!defined(VELD_TEST_CHAIN_BUILD) || defined(VELD_DSTATE_QUALIFICATION))
static_assert(TX_FULL_VALIDATION_ACTIVATION_HEIGHT == 0,
    "Mainnet build must zero TX_FULL_VALIDATION_ACTIVATION_HEIGHT");
static_assert(TX_FULL_VALIDATION_V2_ACTIVATION_HEIGHT == 0,
    "Mainnet build must zero TX_FULL_VALIDATION_V2_ACTIVATION_HEIGHT");
#endif
static_assert(MAX_REORG_DEPTH <= COMINE_WINDOW_BLOCKS,
    "MAX_REORG_DEPTH must not exceed COMINE_WINDOW_BLOCKS");
static_assert(SLASH_EVIDENCE_WINDOW >= MIN_EVIDENCE_WINDOW,
    "slash-evidence window too short");

}
