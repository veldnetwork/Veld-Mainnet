#!/usr/bin/env python3
"""Offline deployment-contract tests for the 3-of-5 custody signer mesh."""

import ast
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
DEPLOY = HERE / "deploy"
CANONICAL_IDS = ["custody-signer-%d" % i for i in range(1, 6)]


class DeploymentConfigTests(unittest.TestCase):
    def test_public_signer_examples_do_not_publish_external_coordinates(self):
        external_ipv4 = re.compile(
            r"\b(?!127\.0\.0\.1\b)(?!0\.0\.0\.0\b)"
            r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        )
        public_examples = (
            DEPLOY / "custody-descriptor.txt",
            DEPLOY / "custody-pubkeys-collected.txt",
            DEPLOY / "watchtowerd.conf.example",
            DEPLOY / "veld-signer-node.service",
            HERE / "veld_signerd.py",
            HERE / "veld_mintd.py",
        )
        for path in public_examples:
            self.assertNotRegex(path.read_text(), external_ipv4, str(path))
        watchtower = json.loads((DEPLOY / "watchtowerd.conf.example").read_text())
        self.assertEqual(watchtower["signer"]["ssh_target"], "veldwt@REPLACE_WITH_SIGNER_HOST")

    def test_source_tree_does_not_ship_the_synthetic_custody_allowlist(self):
        """A fixture-shaped manifest must never look deployable by filename."""
        for manifest in (HERE / "custody-spks.json", HERE.parent / "custody-spks.json"):
            if not manifest.exists():
                continue
            doc = json.loads(manifest.read_text())
            descriptor = str(doc.get("descriptor", ""))
            scripts = doc.get("script_pubkeys", [])
            self.assertNotIn("#testsum1", descriptor, manifest)
            self.assertNotIn("[00000001/86h/0h/0h]", descriptor, manifest)
            self.assertFalse(
                scripts[:2] == ["5120" + "00" * 31 + "01", "5120" + "00" * 31 + "02"],
                f"{manifest} contains the sequential synthetic SPK fixture",
            )

    def test_mainnet_mint_witness_and_restore_contract_is_documented(self):
        signer = json.loads((DEPLOY / "signer-config.example.json").read_text())
        authority = signer["mint_authority"]
        self.assertEqual(authority["topology"], "single-active-shared-witness")
        self.assertEqual(authority["signer_id"], authority["active_signer_id"])
        self.assertTrue(authority["witness"]["witness_id"])
        self.assertIn("BatchMode=yes", authority["witness"]["command"])
        self.assertEqual(authority["witness"]["command"][0], "/usr/bin/ssh")
        self.assertEqual(authority["witness"]["command"][-1], "veld_wt_reserve")
        c1_authority = signer["c1_reservation_authority"]
        self.assertEqual(
            c1_authority["durable_archive_command"],
            ["/REPLACE_WITH_C1_SIGNER_COMPLIANCE_ARCHIVE_CLIENT"],
        )
        coordinator = json.loads((DEPLOY / "c1-reservationd-config.example.json").read_text())
        self.assertEqual(coordinator["version"], 2)
        self.assertEqual(
            coordinator["terminal_archive_command"],
            ["/REPLACE_WITH_C1_COORDINATOR_COMPLIANCE_ARCHIVE_CLIENT"],
        )

        c1_runbook = (DEPLOY / "C1-WRAP-ADMISSION-RUNBOOK.md").read_text()
        for required in (
            "read it back",
            "COMPLIANCE",
            "ten years",
            "durable_archive_command",
            "terminal_archive_command",
        ):
            self.assertIn(required, c1_runbook)

        authorized = (DEPLOY / "watchtower-authorized_keys.example").read_text()
        self.assertIn("veld_wt_reserve.py", authorized)
        self.assertIn("no-port-forwarding", authorized)
        self.assertIn("restrict", authorized)

        runbook = (DEPLOY / "MINT-SIGNER-WITNESS-RUNBOOK.md").read_text()
        for required in (
            "Exactly one issuer signer",
            "strictly more than 100",
            "WITNESS_RECONCILIATION_REQUIRED",
            "reconcile_witness_restore.py",
            "Two distinct operators",
            "Never restore `active-mint-signer`",
        ):
            self.assertIn(required, runbook)
        service = (DEPLOY / "veld-watchtowerd.service").read_text()
        self.assertIn("StateDirectoryMode=0700", service)
        self.assertIn("UMask=0077", service)

    def test_bitcoin_core_downloads_authenticate_pinned_release_signer(self):
        for name in ("custody-operator-setup.sh", "signer-box-setup.sh"):
            script = (DEPLOY / name).read_text()
            self.assertIn("SHA256SUMS.asc", script, name)
            self.assertIn("--assert-signer", script, name)
            self.assertIn("--no-options", script, name)
            self.assertIn("--no-auto-key-retrieve", script, name)
            self.assertIn('--homedir "$GNUPGHOME"', script, name)
            self.assertNotIn('grep -F "[GNUPG:] VALIDSIG', script, name)
            self.assertIn("BTC_RELEASE_SIGNING_FINGERPRINT", script, name)
            self.assertIn("must be root-owned", script, name)
            self.assertIn("must not be group/world writable", script, name)
            self.assertIn("sha256sum -c", script, name)

    def test_signer_ids_are_canonical_end_to_end(self):
        for name in ("redeemd-threshold.json", "redeemd-threshold.example.json"):
            cfg = json.loads((DEPLOY / name).read_text())
            signers = cfg["payout_signing"]["signers"]
            self.assertEqual([x["id"] for x in signers], CANONICAL_IDS)
            for expected, signer in zip(CANONICAL_IDS, signers):
                self.assertIn(expected, signer["command"])
        payout = json.loads((DEPLOY / "payout-signer-config.example.json").read_text())
        self.assertEqual(payout["signer_id"], CANONICAL_IDS[0])
        self.assertEqual(payout["custody_script_range"], [0, 10999])
        self.assertIn("custody_manifest_sha256", payout)
        self.assertIn("custody_consensus_manifest_sha256", payout)
        self.assertEqual(payout["wallet"], "btcveld-custody-signer-1")
        self.assertEqual(payout["authority_db"], "/var/lib/veld-signer/obligations.sqlite3")
        self.assertEqual(payout["cli_base"][0], "/usr/local/bin/bitcoin-cli")
        for name in ("redeemd-threshold.json", "redeemd-threshold.example.json"):
            cfg = json.loads((DEPLOY / name).read_text())
            self.assertEqual(cfg["cli_base"][0], "/usr/local/bin/bitcoin-cli")
            self.assertEqual(cfg["custody_script_range"], [0, 10999])
            self.assertEqual(
                cfg["custody_spk_manifest_file"], "/etc/veld/custody-spks-operational.json"
            )

        for name in (
            "signer-box-setup.sh",
            "signer-daemon-setup.sh",
            "custody-operator-setup.sh",
            "custody-signer-keygen.sh",
        ):
            text = (DEPLOY / name).read_text()
            self.assertIn("custody-signer-[1-5]", text, name)
        record = (DEPLOY / "custody-descriptor.txt").read_text()
        for signer_id in CANONICAL_IDS:
            self.assertIn(signer_id, record)
        self.assertNotRegex(record, r'"signer_id":"signer-[1-5]"')

    def test_forced_command_uses_fail_closed_unlocking_wrapper(self):
        authorized = (DEPLOY / "signer-authorized_keys.example").read_text()
        mint_command = (
            'command="/usr/bin/python3 /opt/veld-signer/veld_signerd.py --capability mint"'
        )
        c1_command = (
            'command="/usr/bin/python3 /opt/veld-signer/veld_signerd.py '
            '--capability c1-reservation"'
        )
        self.assertEqual(authorized.count(mint_command), 1)
        self.assertEqual(authorized.count(c1_command), 1)
        self.assertIn("DISTINCT SSH key", authorized)
        self.assertIn("AAAA...MINTER_PUBKEY...", authorized)
        self.assertIn("AAAA...C1_RESERVATION_COORDINATOR_PUBKEY...", authorized)
        self.assertNotIn('command="/usr/bin/python3 /opt/veld-signer/veld_signerd.py"', authorized)
        self.assertIn('command="/opt/veld-signer/sign-wrapper.sh"', authorized)
        self.assertNotIn(
            'command="/usr/bin/python3 /opt/veld-signer/veld_payout_signerd.py"', authorized
        )

        setup = (DEPLOY / "signer-daemon-setup.sh").read_text()
        self.assertIn("/tmp/rpc_url_policy.py", setup)
        self.assertIn("require_root_file \"$ENV_FILE\"", setup)
        self.assertIn("require_private_root_file \"$PASS_FILE\"", setup)
        self.assertIn("require_private_root_file \"$CONFIG\"", setup)
        self.assertIn('. "$ENV_FILE"', setup)
        self.assertIn("set -euo pipefail", setup)
        self.assertIn("trap cleanup EXIT HUP INT TERM", setup)
        unlock_lines = [line for line in setup.splitlines() if "walletpassphrase" in line]
        self.assertEqual(len(unlock_lines), 2)
        self.assertTrue(all("|| true" not in line for line in unlock_lines))
        self.assertIn("bitcoin-cli -stdin", setup)
        self.assertIn('"bitcoin_datadir":bitcoin_datadir', setup)
        self.assertIn(
            '"cli_base":["/usr/local/bin/bitcoin-cli","-datadir="+bitcoin_datadir]', setup
        )
        self.assertIn("BTC_DATADIR=$(python3 -c", setup)
        self.assertNotIn("bitcoin-cli -datadir=/var/lib/bitcoin", setup)
        self.assertNotIn("bitcoin-cli -stdin -datadir=/var/lib/bitcoin", setup)
        self.assertNotRegex(setup, r'encryptwallet\s+"\$PASS"')
        self.assertNotRegex(setup, r'walletpassphrase\s+"\$PASS"')
        self.assertIn("walletlock", setup)
        self.assertIn("flock -x 9", setup)

        for name in ("custody-operator-setup.sh", "custody-signer-keygen.sh"):
            phase_one = (DEPLOY / name).read_text()
            self.assertIn("/root/.veld-signer/wallet.pass", phase_one)
            self.assertIn("bitcoin-cli -stdin", phase_one)

    def test_installed_payout_payload_imports_without_source_tree(self):
        setup = (DEPLOY / "signer-daemon-setup.sh").read_text()
        install_commands = [
            shlex.split(line)
            for line in setup.replace("\\\n", " ").splitlines()
            if line.startswith("install -m640 ")
        ]
        self.assertEqual(len(install_commands), 1)
        command = install_commands[0]
        self.assertEqual(command[-1], "/opt/veld-signer/")
        sources = [Path(value) for value in command[2:-1]]
        self.assertTrue(sources)
        for source in sources:
            self.assertEqual(source.parent, Path("/tmp"))
            self.assertEqual(source.suffix, ".py")

        # Copy exactly the declared deployment payload, without invoking install
        # or adding the checkout to the child's import path.
        with tempfile.TemporaryDirectory(prefix="signer-import-test-") as td:
            installed = Path(td) / "installed"
            empty_cwd = Path(td) / "empty"
            installed.mkdir()
            empty_cwd.mkdir()
            for source in sources:
                shutil.copyfile(HERE / source.name, installed / source.name)
            probe = textwrap.dedent("""
                import json
                import sys
                from pathlib import Path

                installed = Path(sys.argv[1]).resolve()
                sys.path.insert(0, str(installed))
                import veld_payout_signerd

                names = (
                    "veld_payout_signerd", "veld_redeemd", "rpc_url_policy",
                    "veld_redeem_commitment", "veld_custody_binding",
                )
                loaded = {}
                for name in names:
                    module = sys.modules[name]
                    origin = Path(module.__file__).resolve()
                    assert origin.parent == installed, (name, str(origin))
                    loaded[name] = origin.name
                print(json.dumps(loaded, sort_keys=True))
            """)
            out = subprocess.run(
                [sys.executable, "-I", "-B", "-c", probe, str(installed)],
                cwd=empty_cwd,
                env={"PATH": "/usr/bin:/bin", "HOME": str(empty_cwd)},
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(
                json.loads(out.stdout),
                {
                    name: name + ".py"
                    for name in (
                        "veld_payout_signerd",
                        "veld_redeemd",
                        "rpc_url_policy",
                        "veld_redeem_commitment",
                        "veld_custody_binding",
                    )
                },
            )
            self.assertEqual(list(empty_cwd.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "Bash wrapper generation requires POSIX")
    def test_wrapper_generator_preserves_configured_environment_path(self):
        setup = (DEPLOY / "signer-daemon-setup.sh").read_text()
        initialization = [line for line in setup.splitlines() if line.startswith("ENV_FILE=")]
        self.assertEqual(
            initialization,
            [
                'ENV_FILE=$(realpath -e -- "${VELD_ROOT_ENV:-/etc/veld/env}")',
            ],
        )
        self.assertLess(setup.index(initialization[0]), setup.index('[ -f "$ENV_FILE" ]'))
        generator = re.search(
            r"^\{\n(?P<header>.*?)^cat <<'WRAP'\n"
            r"(?P<body>.*?)^WRAP\n^\} >/opt/veld-signer/sign-wrapper\.sh$",
            setup,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(generator)
        header = generator.group("header")
        # Only path resolution and these two printing builtins may execute. The
        # provisioning script and generated wallet wrapper are never run.
        self.assertEqual(
            header.splitlines(),
            [
                "printf '%s\\n' '#!/bin/bash'",
                "printf 'ENV_FILE=%q\\n' \"$ENV_FILE\"",
            ],
        )
        fragment = "set -euo pipefail\n" + initialization[0] + "\n" + header
        with tempfile.TemporaryDirectory(prefix="signer-wrapper-test-") as td:
            root = Path(td)
            env_dir = root / "signer test"
            env_dir.mkdir()
            env_file = env_dir / "owner's $literal;[env]\\name.env"
            env_file.write_text("# harmless temporary environment fixture\n")
            forced_cwd = root / "forced-command"
            forced_cwd.mkdir()
            for configured in (
                str(env_file),
                str(env_file.relative_to(root)),
                str(Path("signer test") / ".." / env_file.relative_to(root)),
            ):
                with self.subTest(configured=configured):
                    out = subprocess.run(
                        ["/bin/bash", "--noprofile", "--norc", "-c", fragment],
                        cwd=root,
                        env={"VELD_ROOT_ENV": configured, "PATH": "/usr/bin:/bin"},
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(out.returncode, 0, out.stderr)
                    lines = out.stdout.splitlines()
                    self.assertEqual(len(lines), 2)
                    self.assertEqual(lines[0], "#!/bin/bash")
                    self.assertEqual(shlex.split(lines[1]), ["ENV_FILE=" + str(env_file.resolve())])
                    wrapper = out.stdout + generator.group("body")
                    self.assertIn('require_root_file "$ENV_FILE"', wrapper)
                    self.assertIn('. "$ENV_FILE"', wrapper)
                    checked = subprocess.run(
                        ["/bin/bash", "--noprofile", "--norc", "-n"],
                        cwd=forced_cwd,
                        input=wrapper,
                        env={"PATH": "/usr/bin:/bin"},
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(checked.returncode, 0, checked.stderr)
            missing = subprocess.run(
                ["/bin/bash", "--noprofile", "--norc", "-c", fragment],
                cwd=root,
                env={"VELD_ROOT_ENV": "missing.env", "PATH": "/usr/bin:/bin"},
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(missing.returncode, 0)
            self.assertEqual(missing.stdout, "")

    def test_public_payout_token_command_uses_signer_node_datadir(self):
        expected = [
            "/usr/local/bin/veld-node",
            "--print-rpc-token",
            "--datadir",
            "/var/lib/veld-node",
        ]
        payout = json.loads((DEPLOY / "payout-signer-config.example.json").read_text())
        self.assertEqual(payout["veld_rpc"]["token_cmd"], expected)

        setup = (DEPLOY / "signer-daemon-setup.sh").read_text()
        config_source = re.search(r"<<'PY'\n(.*?)\nPY\n", setup, re.DOTALL)
        self.assertIsNotNone(config_source)
        assignments = [
            node.value
            for node in ast.parse(config_source.group(1)).body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "cfg" for target in node.targets)
        ]
        self.assertEqual(len(assignments), 1)
        config = assignments[0]
        self.assertIsInstance(config, ast.Dict)
        rpc_values = [
            value
            for key, value in zip(config.keys, config.values)
            if isinstance(key, ast.Constant) and key.value == "veld_rpc"
        ]
        self.assertEqual(len(rpc_values), 1)
        self.assertEqual(ast.literal_eval(rpc_values[0])["token_cmd"], expected)

    def test_canonical_descriptor_and_collected_keys_match(self):
        descriptor = (DEPLOY / "custody-descriptor.txt").read_text()
        collected = (DEPLOY / "custody-pubkeys-collected.txt").read_text()
        pattern = r"xpub[1-9A-HJ-NP-Za-km-z]{20,}"
        descriptor_keys = re.findall(pattern, descriptor)
        collected_keys = re.findall(pattern, collected)
        self.assertEqual(len(descriptor_keys), 5)
        self.assertEqual(len(set(descriptor_keys)), 5)
        self.assertEqual(descriptor_keys, collected_keys)

    @staticmethod
    def _fake_bitcoin_cli(path):
        path.write_text("""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ['FAKE_BTC_LOG'], 'a') as f:
    f.write(json.dumps(args, separators=(',', ':')) + '\\n')
if 'getblockchaininfo' in args:
    print('{}')
elif 'getdescriptorinfo' in args:
    print(json.dumps({'checksum':'testsum1','isrange':True,
                      'hasprivatekeys':os.environ.get('FAKE_HASPRIVATE') == '1'}))
elif 'deriveaddresses' in args:
    request = args[-1]
    parsed = json.loads(request)
    end = parsed[1] if isinstance(parsed, list) and len(parsed) == 2 else 0
    charset='qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    def polymod(v):
      chk=1; gen=(0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3)
      for x in v:
       top=chk>>25; chk=((chk&0x1ffffff)<<5)^x
       for i,g in enumerate(gen):
        if (top>>i)&1: chk^=g
      return chk
    def addr(i):
      raw=i.to_bytes(32,'big'); acc=0; bits=0; data=[1]
      for b in raw:
       acc=(acc<<8)|b; bits+=8
       while bits>=5:
        bits-=5; data.append((acc>>bits)&31)
      if bits: data.append((acc<<(5-bits))&31)
      hrp='bc'; exp=[ord(c)>>5 for c in hrp]+[0]+[ord(c)&31 for c in hrp]
      pm=polymod(exp+data+[0]*6)^0x2bc830a3
      check=[(pm>>5*(5-j))&31 for j in range(6)]
      return hrp+'1'+''.join(charset[x] for x in data+check)
    print(json.dumps([addr(i+1) for i in range(end+1)]))
elif 'getwalletinfo' in args:
    raise SystemExit(1)
elif 'createwallet' in args:
    print('{}')
elif 'importdescriptors' in args:
    print(json.dumps([{'success':True}]))
else:
    raise SystemExit('unexpected fake bitcoin-cli argv: %r' % args)
""")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    def test_ranged_descriptor_build_and_key_rejections(self):
        script = DEPLOY / "custody-build-descriptor.sh"
        with tempfile.TemporaryDirectory(prefix="custody-deploy-test-") as td:
            td = Path(td)
            fake = td / "bitcoin-cli"
            log = td / "bitcoin-cli.log"
            self._fake_bitcoin_cli(fake)
            env = dict(os.environ)
            env.update(
                {
                    "PATH": str(td) + os.pathsep + env.get("PATH", ""),
                    "FAKE_BTC_LOG": str(log),
                    "BTC_DATADIR": str(td / "btc"),
                    "CUSTODY_RANGE_END": "10999",
                    "CUSTODY_SPKS_OUT": str(td / "custody-spks-operational.json"),
                    "CUSTODY_CONSENSUS_SPKS_OUT": str(td / "custody-spks-consensus.json"),
                    "CUSTODY_BINDING_OUT": str(td / "custody-release-binding.json"),
                }
            )
            pubs = [
                "[0000000%d/86h/0h/0h]xpub%s/0/*" % (i, chr(ord("A") + i) * 107)
                for i in range(1, 6)
            ]

            out = subprocess.run(
                [str(script)] + pubs, env=env, capture_output=True, text=True, timeout=10
            )
            self.assertEqual(out.returncode, 0, out.stderr)
            calls = [json.loads(x) for x in log.read_text().splitlines()]
            derive = next(x for x in calls if "deriveaddresses" in x)
            self.assertIn("[0,0]", derive)
            imported = next(x for x in calls if "importdescriptors" in x)
            request = json.loads(imported[-1])
            self.assertEqual(request[0]["range"], [0, 10999])
            # Production pre-issues a cursorless public pool. A private CSPRNG
            # permutation selects unused indices >=1000, so neither Core's
            # sequential next cursor nor an active descriptor may leak the
            # public C1 allocation sequence.
            self.assertNotIn("next_index", request[0])
            self.assertIs(request[0]["active"], False)

            full_derive = next(x for x in calls if "deriveaddresses" in x and x[-1] == "[0,10999]")
            self.assertEqual(full_derive[-1], "[0,10999]")
            operational = json.loads((td / "custody-spks-operational.json").read_text())
            consensus = json.loads((td / "custody-spks-consensus.json").read_text())
            binding = json.loads((td / "custody-release-binding.json").read_text())
            self.assertEqual(operational["range"], [0, 10999])
            self.assertEqual(len(operational["script_pubkeys"]), 11000)
            self.assertEqual(consensus["range"], [0, 999])
            self.assertEqual(consensus["script_pubkeys"], operational["script_pubkeys"][:1000])
            self.assertEqual(binding["schema"], 2)
            self.assertEqual(binding["statement"], "veld-btcveld-custody-binding-v2-dual-manifest")
            self.assertEqual(binding["script_range"], [0, 10999])
            self.assertEqual(binding["consensus_script_range"], [0, 999])
            self.assertEqual(
                binding["manifest_sha256"],
                hashlib.sha256((td / "custody-spks-operational.json").read_bytes()).hexdigest(),
            )
            self.assertEqual(
                binding["consensus_manifest_sha256"],
                hashlib.sha256((td / "custody-spks-consensus.json").read_bytes()).hexdigest(),
            )

            for wrong_end in ("999", "11000"):
                with self.subTest(wrong_launch_range=wrong_end):
                    wrong_env = dict(env)
                    wrong_env["CUSTODY_RANGE_END"] = wrong_end
                    wrong = subprocess.run(
                        [str(script)] + pubs,
                        env=wrong_env,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertNotEqual(wrong.returncode, 0)
                    self.assertIn("must be exactly 10999", wrong.stderr)

            duplicate = subprocess.run(
                [str(script)] + [pubs[0]] * 5, env=env, capture_output=True, text=True, timeout=10
            )
            self.assertNotEqual(duplicate.returncode, 0)
            self.assertIn("duplicate", duplicate.stderr.lower())

            private = list(pubs)
            private[2] = "[00000003/86h/0h/0h]xprv" + "A" * 40 + "/0/*"
            rejected = subprocess.run(
                [str(script)] + private, env=env, capture_output=True, text=True, timeout=10
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("private key material", rejected.stderr.lower())

            injected = list(pubs)
            injected[4] = injected[4] + "),pk(02" + "a" * 64 + ")"
            injection_reject = subprocess.run(
                [str(script)] + injected, env=env, capture_output=True, text=True, timeout=10
            )
            self.assertNotEqual(injection_reject.returncode, 0)
            self.assertIn("exactly match", injection_reject.stderr.lower())

            private_info_env = dict(env)
            private_info_env["FAKE_HASPRIVATE"] = "1"
            core_reject = subprocess.run(
                [str(script)] + pubs,
                env=private_info_env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(core_reject.returncode, 0)
            self.assertIn("contains private keys", core_reject.stderr.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
