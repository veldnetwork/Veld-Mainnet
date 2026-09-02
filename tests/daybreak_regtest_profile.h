#pragma once

// Isolated compile profile for the purpose-built custody provenance harness.
// The disposable values exist only in test binaries and satisfy the same
// fail-closed profile interlocks as the externally generated L3 identities.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_REGTEST_FIXED_DIFF 1
#define VELD_BTCVELD_REGTEST 1
#define VELD_L3_DISPOSABLE_BTCVELD_AUTHORITY_ADDRESS \
    "VUjD1JoewGkiGxRqJ52FkK1UiMotjsp9Tg"
#define VELD_L3_DISPOSABLE_BTCVELD_CUSTODY_SPK_HEX \
    "00141111111111111111111111111111111111111111"
