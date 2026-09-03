#!/usr/bin/env python3
"""Regression checks for node-created portable wallet keyfiles."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NODE = (ROOT / "src/veld-node.cpp").read_text(encoding="utf-8")
GUI = (ROOT / "src/veld-node-gui.cpp").read_text(encoding="utf-8")
WALLET = (ROOT / "include/network/ui_desktop.h").read_text(encoding="utf-8")

checks = 0


def check(condition: bool, message: str) -> None:
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)


bundle_start = NODE.index("static bool _wiz_create_portable_key_bundle(")
bundle_end = NODE.index("static bool _wiz_ensure_portable_keyfile(", bundle_start)
bundle = NODE[bundle_start:bundle_end]

check("_wiz_encrypt_key_record(" in bundle, "bundle must encrypt one canonical record")
check(
    'portable_path = datadir + "/veld-wallet-" + address.substr(0, 8)' in bundle,
    "portable keyfile must use the documented .veld-keys name",
)
check('const std::string operational_path = datadir + "/miner.key";' in bundle,
      "bundle must retain the operational miner.key name")
check(bundle.count("AtomicWriteNew(") == 2,
      "both identity names must use no-overwrite publication")
check(bundle.index("portable_path, encrypted") < bundle.index("operational_path, encrypted"),
      "portable recovery copy must be published before operational activation")
check("operational_bytes.size() != encrypted.size()" in bundle,
      "operational keyfile needs exact-size readback")
check("portable_bytes.size() != encrypted.size()" in bundle,
      "portable keyfile needs exact-size readback")
check("std::equal(encrypted.begin(), encrypted.end()," in bundle,
      "bundle must prove byte identity after publication")
check("SecureZero(value.data(), value.size())" in bundle,
      "encrypted staging bytes must be wiped")
check("SecureZero(first.data(), first.size())" in bundle,
      "operational readback must be wiped")
check("SecureZero(second.data(), second.size())" in bundle,
      "portable readback must be wiped")

create_start = NODE.index("    if (opt_create_miner_key) {")
create_end = NODE.index("\n    if (!opt_import_miner_key.empty())", create_start)
create_flow = NODE[create_start:create_end]
check("_wiz_create_portable_key_bundle(" in create_flow,
      "the production create command must use the bundle writer")
check("CreatedPrivateKeyWiper" in create_flow,
      "generated private-key bytes must be wiped on every exit")
check("keyfile=" in create_flow,
      "successful creation must report the non-secret portable path")

import_start = NODE.index("static bool _wiz_import_encrypted_keyfile(")
import_end = NODE.index("\n#endif", import_start)
node_import = NODE[import_start:import_end]
check("wallet_crypto::DecryptWallet(" in node_import,
      "node import must accept the canonical encrypted envelope")
check("_wiz_parse_key_record(decrypted, imported, testnet)" in node_import,
      "node import must authenticate the complete key/address record")
check("authenticated_browser_address != imported_address" in node_import,
      "node import must reject wallet key/address mismatches")

check("binary miner.key is expected to fail textual JSON parsing" in WALLET,
      "wallet import must retain binary miner.key/.veld-keys handling")
check("decryptMinerKeyfile(pendingEncBytes, pass)" in WALLET,
      "wallet import must decrypt the canonical node envelope")
check("_veldParseAndBindKeyPayload(plaintext)" in WALLET,
      "wallet import must rederive and bind the imported address")
check("localStorage.setItem('veld_ks', browserKeystore)" in WALLET,
      "wallet import must persist only a re-encrypted browser keystore")

check("imported into both Veld Wallet and Veld Node" in GUI,
      "GUI must explain the portable keyfile's two supported import targets")
check("using the same passphrase" in GUI,
      "GUI must explain passphrase continuity")

ensure_start = NODE.index("static bool _wiz_ensure_portable_keyfile(")
ensure_end = NODE.index("\n#endif", ensure_start)
ensure_flow = NODE[ensure_start:ensure_end]
check("GenerateKeyPair(" not in ensure_flow,
      "portable-key migration must never generate a second wallet")
check(ensure_flow.count("AtomicWriteNew(") == 1,
      "portable-key migration must publish at most one new file")
check("existing portable keyfile differs from miner.key" in ensure_flow,
      "a conflicting portable keyfile must fail closed")
check("portable keyfile readback differs from miner.key" in ensure_flow,
      "a newly published portable keyfile needs exact-byte readback")
check("portable_exists" in ensure_flow,
      "portable-key migration must be idempotent")
check("_wiz_is_encrypted(operational_path)" in ensure_flow,
      "portable-key migration must refuse plaintext operational keys")

startup_call = NODE.index("// A successful sign-in must leave one wallet/node-compatible")
check(startup_call > NODE.index("Mining wallet unlocked."),
      "portable-key migration must run only after successful sign-in")
check("_wiz_ensure_portable_keyfile(" in NODE[startup_call:startup_call + 1400],
      "successful sign-in must enforce the portable keyfile invariant")

print(f"PASS windows_node_keyfile_interop_tests checks={checks}")
