"""Forced-command RTP1 qualification with actual private native and Bitcoin RPCs.

The controller must create an isolated network namespace and disposable keys.
This module never supplies a replacement RPC result or a signature stub.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "swap"))
import rtp1_service as lifecycle
import rtp1_service_runtime as runtime
import veld_custody_binding as custody
import veld_wt_reserve as witness_module
from types import SimpleNamespace


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def public_custody(core, root):
    public, private = [], []
    for i in range(5):
        name = "independent-fixture-" + str(i)
        core.rpc("createwallet", [name])
        for secret, target in ((False, public), (True, private)):
            rows = core.rpc("listdescriptors", [secret], wallet=name)["descriptors"]
            row, = [row for row in rows if row["active"] and not row["internal"] and row["desc"].startswith("tr(")]
            target.append(row["desc"].split("#")[0][3:-1].replace("'", "h"))
    body = "tr(" + custody.CUSTODY_NUMS_KEY + ",multi_a(3," + ",".join(public) + "))"
    descriptor = core.rpc("getdescriptorinfo", [body])["descriptor"]
    assert len(custody.validate_descriptor_policy(descriptor, network="regtest")) == 5
    addresses = core.rpc("deriveaddresses", [descriptor, [0, 999]])
    scripts = [custody._bech32m_spk(address, "bcrt") for address in addresses]
    core.rpc("createwallet", ["custody-watch", True, True])
    assert core.rpc("importdescriptors", [[{"desc": descriptor, "timestamp": "now", "range": [0, 999]}]], wallet="custody-watch")[0]["success"]
    for i in range(5):
        member = body.replace(public[i], private[i])
        checksum = core.rpc("getdescriptorinfo", [member])["checksum"]
        assert core.rpc("importdescriptors", [[{"desc": member + "#" + checksum,
            "timestamp": "now", "range": [0, 999]}]], wallet="independent-fixture-" + str(i))[0]["success"]
    private.clear()
    document = {"version": 1, "descriptor": descriptor,
        "descriptor_sha256": hashlib.sha256(descriptor.encode()).hexdigest(),
        "range": [0, 999], "script_pubkeys": scripts}
    manifest = root / "public-custody.json"
    manifest.write_text(canonical(document))
    return {"address": addresses[0], "script": scripts[0], "descriptor": descriptor,
        "descriptor_sha256": document["descriptor_sha256"],
        "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(), "manifest": manifest}


class Services:
    @classmethod
    def reconnect(cls, source, root, keygen, core, node):
        """Resume the same disposable authorities; never recreate their state."""
        from veld_chain_identity import verify_expected_chain
        self = cls.__new__(cls)
        self.root, self.keygen, self.core, self.node = root, keygen, core, node
        self.issuer, self.witness = root / "issuer", root / "witness"
        icfg = json.loads((self.issuer / "signer-config.json").read_text())
        self.wcfg = json.loads((self.witness / "watchtowerd.conf.json").read_text())
        self.config = lifecycle.configuration(icfg["rtp1_service"])
        assert self.wcfg["rtp1_service"] == self.config
        verify_expected_chain(node.rpc, self.config["expected_chain"])
        assert core.rpc("getblockhash", [0]) == self.config["bitcoin_genesis"]
        self.address = self.config["issuer"]
        self.public = (self.witness / "watchtower-beat-pubkey.hex").read_text().strip()
        self.env = dict(os.environ,
            VELD_VAULT_PASSPHRASE=(self.issuer / "passphrase.txt").read_text().strip(),
            VELD_WITNESS_CONFIG=str(self.witness / "watchtowerd.conf.json"),
            VELD_SIGNER_CONFIG=str(self.issuer / "signer-config.json"))
        code_changes = {}
        for directory, cfg, filename in ((self.issuer, icfg, "signer-config.json"),
                (self.witness, self.wcfg, "watchtowerd.conf.json")):
            assert (directory / "rtp1-migration.json").exists()
            assert hashlib.sha256((directory / "veld-keygen").read_bytes()).digest() == hashlib.sha256(keygen.read_bytes()).digest()
            if "keygen" in cfg:
                cfg["keygen"] = str(directory / "veld-keygen")
            cfg["veld_rpc"]["url"] = "http://127.0.0.1:" + str(node.rpc_port)
            cfg["veld_rpc"]["token_file"] = str(node.directory / "test-rpc-token")
            cfg["btc"]["cli_base"] = [str(core.binary.parent / "bitcoin-cli"), "-regtest",
                "-datadir=" + str(core.directory), "-rpcport=" + str(core.port)]
            (directory / filename).write_text(canonical(cfg))
            for path in (source / "swap").glob("*.py"):
                destination = directory / path.name
                old = destination.read_bytes() if destination.exists() else None
                new = path.read_bytes()
                if old == new: continue
                digest = hashlib.sha256(old).hexdigest() if old is not None else None
                if old is not None:
                    archive = root / "prior-service-code" / digest
                    archive.mkdir(parents=True, exist_ok=True)
                    (archive / path.name).write_bytes(old)
                destination.write_bytes(new)
                code_changes[path.name] = {"before": digest, "after": hashlib.sha256(new).hexdigest()}
        (root / "service-code-continuation.json").write_text(canonical(code_changes))
        self.command = [str(root / "operator-python"), str(self.issuer / "veld_signerd.py"), "--capability", "mint"]
        self.sequence = int(json.loads((self.issuer / "signer-heartbeat.json").read_text())["seq"]) if (self.issuer / "signer-heartbeat.json").exists() else 0
        return self

    def __init__(self, source, root, keygen, core, node, binding):
        self.root, self.keygen, self.core, self.node = root, keygen, core, node
        self.issuer, self.witness = root / "issuer", root / "witness"
        self.issuer.mkdir(mode=0o700)
        self.witness.mkdir(mode=0o700)
        self.env = dict(os.environ, VELD_VAULT_PASSPHRASE="Disposable-native-service-check-2026!")
        for directory in (self.issuer, self.witness):
            for path in (source / "swap").glob("*.py"):
                shutil.copyfile(path, directory / path.name)
            shutil.copyfile(keygen, directory / "veld-keygen")
            (directory / "veld-keygen").chmod(0o700)
            (directory / "passphrase.txt").write_text(self.env["VELD_VAULT_PASSPHRASE"])
        self.env["VELD_WITNESS_CONFIG"] = str(self.witness / "watchtowerd.conf.json")
        self.env["VELD_SIGNER_CONFIG"] = str(self.issuer / "signer-config.json")
        seed = (root / "disposable-identities/wallet-0.seed").read_bytes()
        assert len(seed) == 32
        readfd, writefd = os.pipe()
        try:
            os.write(writefd, seed.hex().encode())
            os.close(writefd); writefd = None
            subprocess.run([str(keygen), "from-seed", "--seed-input-handle", str(readfd),
                "--out", str(self.issuer / "issuer.key")], pass_fds=(readfd,), env=self.env,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True, timeout=120)
        finally:
            os.close(readfd)
            if writefd is not None: os.close(writefd)
            seed = None
        shown = self.run([keygen, "show", self.issuer / "issuer.key"])
        self.address = re.search(r"^address:\s+(\S+)\s*$", shown, re.MULTILINE).group(1)
        assert self.address == node.ready["addresses"][0]
        self.run([keygen, "new", "--out", self.witness / "witness.key"])
        shown = self.run([keygen, "show", self.witness / "witness.key", "--full-pubkey-hex"])
        self.public = re.search(r"[0-9a-f]{3904}", shown).group(0)
        for directory in (self.issuer, self.witness):
            (directory / "watchtower-beat-pubkey.hex").write_text(self.public + "\n")
        network = node.rpc("getnetworkinfo")
        chain = {key: network[key] for key in ("profile_id", "consensus_build_profile", "disposable", "external_value", "fixed_difficulty_regtest")}
        chain.update(genesis_hash=node.rpc("getcompiledgenesis"), launch_block_hash=node.rpc("getblockhash", [1]))
        assert chain["disposable"] is True and chain["external_value"] is False
        self.config = {"version": 1, "expected_chain": chain, "issuer": self.address,
            "witness_id": "disposable-independent-witness", "custody_descriptor_sha256": binding["descriptor_sha256"],
            "custody_manifest_sha256": binding["manifest_sha256"], "bitcoin_genesis": core.rpc("getblockhash", [0]),
            "bitcoin_network": "regtest", "custody_script_hex": binding["script"], "minimum_confirmations": 144}
        cli = core.binary.parent / "bitcoin-cli"
        btc = {"cli_base": [str(cli), "-regtest", "-datadir=" + str(core.directory), "-rpcport=" + str(core.port)],
            "wallet": "custody-watch", "confirmations": 144, "tip_age_alert_secs": 3600, "max_tip_age_secs": 7200}
        rpc = {"url": "http://127.0.0.1:" + str(node.rpc_port),
            "token_file": str(node.directory / "test-rpc-token"), "expected_chain": chain}
        common = {"veld_rpc": rpc, "btc": btc, "rtp1_service": self.config,
            "custody_spk_manifest_file": str(binding["manifest"])}
        # The existing witness CLI calls its strict entrypoint guard production;
        # the RTP1 runtime separately requires disposable Veld + Bitcoin regtest.
        self.wcfg = dict(common, production=True, state_dir=str(self.witness), keygen=str(keygen),
            rtp1_witness_public_key_file=str(self.witness / "watchtower-beat-pubkey.hex"),
            signer={"beat_keyfile": str(self.witness / "witness.key"), "beat_passfile": str(self.witness / "passphrase.txt")})
        interpreter = root / "operator-python"
        shutil.copyfile(Path(sys.executable).resolve(), interpreter)
        interpreter.chmod(0o700)
        python = str(interpreter)
        icfg = dict(common, authority_state_activation_marker=str(self.issuer / "signer-authority-state.json"),
            mint_authority={"topology": "single-active-shared-witness", "signer_id": "disposable-issuer",
                "active_signer_id": "disposable-issuer", "issuer_id": self.address, "wrap_allocation_witness_required": True,
                "witness": {"witness_id": self.config["witness_id"],
                    "command": [python, str(self.witness / "veld_wt_reserve.py")]}})
        (self.issuer / "issuer-address.txt").write_text(self.address + "\n")
        (self.issuer / "active-mint-signer").write_text("disposable-issuer\n")
        (self.issuer / "watchtower-required").write_text("required\n")
        (self.issuer / "signer-config.json").write_text(canonical(icfg))
        (self.witness / "watchtowerd.conf.json").write_text(canonical(self.wcfg))
        self.run([python, self.issuer / "veld_signerd.py", "--initialize-authority-state"])
        (self.witness / "mint-reservations.json").write_text(canonical(witness_module._empty_ledger()))
        (self.witness / "mint-reservation-tombstones.jsonl").write_text(witness_module._empty_terminal_log_text())
        allocation = {"version": 5, "initial_descriptor_index": 1000, "capacity_policy_sha256": "ab" * 32,
            "capacity_policy_sequence": 0, "public_descriptor_range_end": 999, "last_consensus_sequence": 0,
            "allocations": [], "events": []}
        (self.witness / "wrap-allocation-authority.json").write_text(canonical(allocation))
        self.run([python, self.issuer / "veld_signerd.py", "--initialize-rtp1-state"])
        self.run([python, self.witness / "veld_wt_reserve.py", "--initialize-rtp1-state"])
        self.command = [python, self.issuer / "veld_signerd.py", "--capability", "mint"]
        self.sequence = 0

    def run(self, argv, data=None, expected=0):
        result = subprocess.run([str(x) for x in argv], input=data, text=True, capture_output=True,
            env=self.env, timeout=180)
        assert self.env["VELD_VAULT_PASSPHRASE"] not in result.stdout + result.stderr
        self.last_command_stderr = result.stderr
        if result.returncode != expected:
            raise RuntimeError("service command " + str(argv[1]) + " exited " + str(result.returncode) + ": " + result.stderr[-1200:])
        return result.stdout.strip()

    def heartbeat(self, reserve_sats):
        cfg = dict(self.wcfg, margin_sats=0, ttl_secs=600)
        cfg["signer"] = dict(cfg["signer"], ssh_target="disposable-local-receiver",
            receiver_command=[str(self.root / "operator-python"), str(self.issuer / "veld_wt_recv.py")])
        path = self.witness / "native-watchtower.json"
        path.write_text(canonical(cfg))
        output = self.run([self.root / "operator-python", self.witness / "veld_watchtowerd.py", path, "--once"])
        assert "SOLVENT beat" in output, "actual watchtower did not deliver a verified solvency heartbeat: " + output[-600:] + self.last_command_stderr[-1600:]
        beat = json.loads((self.issuer / "signer-heartbeat.json").read_text())
        assert beat["custody_sats"] == reserve_sats
        assert beat["supply_sats"] == self.node.rpc("getbtcveldsupply")["supply_sats"]
        assert json.loads((self.witness / "watchtower-current-beat.json").read_text())["seq"] == beat["seq"]
        self.sequence = beat["seq"]

    def mint(self, prepared, amount, reserve_sats):
        self.heartbeat(reserve_sats)
        request = {"action": "rtp1_mint", "unsigned_tx_hex": prepared["unsigned_tx_hex"],
            "recipient": self.address, "sats": amount}
        signed = self.run(self.command, canonical(request))
        assert re.fullmatch(r"[0-9a-f]+", signed)
        assert self.run(self.command, canonical(request)) == signed
        for role, directory in (("issuer", self.issuer), ("witness", self.witness)):
            journal = json.loads((directory / ("rtp1-" + role + ".json")).read_text())
            row = journal["records"][-1]
            assert row["signed_tx_hex"] == signed and row["committed"] is True
        return request, signed

    def confirmed(self, request):
        journal = json.loads((self.issuer / "rtp1-issuer.json").read_text())
        row, = [row for row in journal["records"] if row["request"] == request]
        result = runtime.confirmation(self.config, SimpleNamespace(call=self.node.rpc),
            SimpleNamespace(call=lambda method, *args: self.core.rpc(method, args)), row)
        assert result is not None, "full native/Bitcoin mint confirmation was not recognized"
        return result
