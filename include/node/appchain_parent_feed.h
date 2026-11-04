#pragma once
#if !defined(VELD_PUBLIC_RELEASE) || !defined(VELD_PUBLIC_MAINNET) || \
    !defined(VELD_MAINNET_POW) || !defined(VELD_USE_LEVELDB) || \
    !defined(VELD_ENABLE_SNAPSHOT_BOOTSTRAP)
#error "Public appchain parent feed requires the persistent public-mainnet validator"
#endif
#if defined(VELD_APPCHAIN_BRIDGE_DEVNET) || defined(VELD_TEST_CHAIN_BUILD) || \
    defined(VELD_ASERT_TESTCHAIN) || defined(VELD_LIGHT_VERIFY) || \
    defined(VELD_TEST_HOOKS) || defined(VELD_TEST_DATASET_BYTES)
#error "Public appchain parent feed cannot use development validation"
#endif
#include "node/appchain_parent_feed_core.h"

namespace veld {
using AppchainPublicParentFeed = AppchainParentFeedCore;
} // namespace veld
