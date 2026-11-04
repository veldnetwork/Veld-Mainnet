"""Real Core derivation against the disposable public 3-of-5 fixture.

Native peg identity is simulated explicitly. Five fresh Core wallets supply
public account keys. No key export, wallet import or transaction is performed.
"""

import hashlib
import json
from types import SimpleNamespace
import re

import veld_custody_binding as binding
from rtp1_service_runtime import check_descriptor


def exercise(root, core):
    expressions = []
    for index in range(5):
        wallet = "disposable-descriptor-member-" + str(index)
        core.rpc("createwallet", [wallet])
        entries = core.rpc("listdescriptors", [False], wallet=wallet)["descriptors"]
        candidates = [
            row["desc"]
            for row in entries
            if row.get("active") is True
            and row.get("internal") is False
            and row["desc"].startswith("tr(")
        ]
        assert len(candidates) == 1
        expression = candidates[0].split("#")[0][3:-1]
        expression = expression.replace("'", "h")
        assert re.fullmatch(r"\[[0-9a-f]{8}/86h/1h/0h\]tpub[1-9A-HJ-NP-Za-km-z]+/0/\*", expression)
        expressions.append(expression)
    candidate = "tr(" + binding.CUSTODY_NUMS_KEY + ",multi_a(3," + ",".join(expressions) + "))"
    descriptor = core.rpc("getdescriptorinfo", [candidate])["descriptor"]
    assert len(binding.validate_descriptor_policy(descriptor, network="regtest")) == 5
    inspected = core.rpc("getdescriptorinfo", [descriptor])
    assert inspected["descriptor"] == descriptor and inspected["hasprivatekeys"] is False
    addresses = core.rpc("deriveaddresses", [descriptor, [0, 999]])
    assert len(addresses) == len(set(addresses)) == 1000
    scripts = [binding._bech32m_spk(address, "bcrt") for address in addresses]
    for index in (0, 1, 499, 999):
        assert core.rpc("validateaddress", [addresses[index]])["scriptPubKey"] == scripts[index]
    document = {
        "version": 1,
        "descriptor": descriptor,
        "descriptor_sha256": hashlib.sha256(descriptor.encode()).hexdigest(),
        "range": [0, 999],
        "script_pubkeys": scripts,
    }
    manifest = root / "disposable-public-custody.json"
    raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    manifest.write_bytes(raw)
    config = {
        "custody_descriptor_sha256": document["descriptor_sha256"],
        "custody_manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "custody_script_hex": scripts[0],
        "bitcoin_network": "regtest",
    }
    cfg = {"custody_spk_manifest_file": str(manifest)}
    peg = {
        "active": True,
        "spv_active": True,
        "custody_descriptor_sha256": config["custody_descriptor_sha256"],
        "custody_manifest_sha256": config["custody_manifest_sha256"],
        "custody_descriptor_range": [0, 999],
        "spv_custody_descriptor_index": 0,
        "spv_custody_spk_hex": scripts[0],
    }

    def native(method, params):
        assert method == "getpeginfo" and params == []
        return peg

    def bitcoin(method, *params):
        return core.rpc(
            method, [json.loads(p) if type(p) is str and p.startswith("[") else p for p in params]
        )

    check_descriptor(config, cfg, SimpleNamespace(call=native), SimpleNamespace(call=bitcoin))
    try:
        binding.verify_core_derivation(
            bitcoin,
            binding.load_manifest(
                str(manifest),
                config["custody_descriptor_sha256"],
                config["custody_manifest_sha256"],
            ),
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("regtest addresses passed the default mainnet policy")
    document["script_pubkeys"][999] = "5120" + "12" * 32
    raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    manifest.write_bytes(raw)
    config["custody_manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    peg["custody_manifest_sha256"] = config["custody_manifest_sha256"]
    try:
        check_descriptor(config, cfg, SimpleNamespace(call=native), SimpleNamespace(call=bitcoin))
    except RuntimeError as error:
        assert "derivation differs" in str(error)
    else:
        raise AssertionError(
            "hash-pinned but incorrect final script passed independent Core derivation"
        )
    return {
        "all_1000_scripts_derived_by_bitcoin_core": True,
        "native_peg_identity_simulated": True,
        "five_disposable_wallets_created": True,
        "private_keys_exported": False,
        "default_mainnet_policy_rejects_regtest_addresses": True,
        "altered_final_script_refused_after_full_derivation": True,
    }
