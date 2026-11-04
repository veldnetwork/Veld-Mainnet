"""Disposable-network adapter for finalized CIA1 custody signing.

Authority comes from a locally validated native chain. Durable local commitments
supplement that authority; they do not replace it with quorum-overlap assumptions.
"""

import copy
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import itertools
import time

try:
    from . import veld_custody_binding as custody, veld_redeemd as rd
    from .veld_chain_identity import parse_expected_chain, verify_expected_chain
except ImportError:
    import veld_custody_binding as custody
    import veld_redeemd as rd
    from veld_chain_identity import parse_expected_chain, verify_expected_chain

HASH = re.compile(r"[0-9a-f]{64}")
MAX_ROWS = 4096
MAX_RAW_BYTES = 16384
MAX_AUTH_BYTES = 50000
HASH_FIELDS = (
    "domain_hash",
    "deployment_policy_hash",
    "descriptor_hash",
    "manifest_hash",
    "signing_policy_hash",
    "bitcoin_genesis_hash",
    "domain_genesis_hash",
)
INSPECTION_HASHES = (
    "genesis_hash",
    "bitcoin_genesis_hash",
    "domain_hash",
    "deployment_policy_hash",
    "descriptor_hash",
    "manifest_hash",
    "signing_policy_hash",
    "burn_id",
    "intent_commitment",
    "bitcoin_txid",
    "unsigned_tx_sha256",
    "reserve_txid",
    "authorization_block",
    "final_block",
    "finality_certificate",
    "tip_hash",
)
INSPECTION_NUMBERS = (
    "epoch",
    "fee_sats",
    "reserve_vout",
    "principal_sats",
    "authorization_height",
    "final_height",
    "tip",
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def configuration(cfg):
    value = cfg.get("native_custody")
    fields = {
        "version",
        "expected_chain",
        "epoch",
        "member_index",
        "member_key",
        "minimum_bitcoin_confirmations",
        "max_fee_sats",
        "state_path",
        "manifest_path",
        "custody_manifest_sha256",
        *HASH_FIELDS,
    }
    if (
        type(value) is not dict
        or set(value) != fields
        or type(value["version"]) is not int
        or value["version"] != 1
    ):
        raise ValueError("native custody requires its exact versioned policy")
    pins = parse_expected_chain(value["expected_chain"])
    if pins["disposable"] is not True or pins["external_value"] is not False:
        raise ValueError("native custody service activation is closed outside disposable networks")
    if cfg.get("veld_rpc", {}).get("expected_chain") != pins:
        raise ValueError("native custody RPC chain pins differ from its authority policy")
    for field in (*HASH_FIELDS, "member_key", "custody_manifest_sha256"):
        if (
            type(value[field]) is not str
            or not HASH.fullmatch(value[field])
            or value[field] == "0" * 64
        ):
            raise ValueError("native custody has an invalid identity pin")
    for field, low, high in (
        ("epoch", 1, (1 << 63) - 1),
        ("member_index", 0, 4),
        ("minimum_bitcoin_confirmations", 144, 1000000),
        ("max_fee_sats", 1, 100000000),
    ):
        if type(value[field]) is not int or not low <= value[field] <= high:
            raise ValueError("native custody has an invalid numeric policy")
    for field in ("state_path", "manifest_path"):
        if type(value[field]) is not str or not os.path.isabs(value[field]) or "\0" in value[field]:
            raise ValueError("native custody requires explicit absolute local paths")
    if type(cfg.get("signer_id")) is not str or not re.fullmatch(
        r"[A-Za-z0-9._-]{1,128}", cfg["signer_id"]
    ):
        raise ValueError("native custody signer identity is invalid")
    return copy.deepcopy(value)


class CommitmentStore:
    """Explicitly initialized, bounded, FULL-synchronous authority history."""

    def __init__(self, cfg, *, initialize=False):
        self.policy = configuration(cfg)
        path = self.policy["state_path"]
        self.policy_id = hashlib.sha256(
            canonical({"policy": self.policy, "signer_id": cfg["signer_id"]}).encode()
        ).hexdigest()
        parent = rd._ensure_secure_directory(
            os.path.dirname(path), "native custody state directory", create=False, private=True
        )
        if initialize:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.fsync(fd)
            os.close(fd)
        else:
            rd._validate_private_regular(path, "native custody state")
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            if self.db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise ValueError("native custody history failed integrity check")
            if initialize:
                self.db.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE identity (policy TEXT NOT NULL, final_height INTEGER NOT NULL, final_block TEXT NOT NULL);
                    CREATE TABLE commitments (burn TEXT NOT NULL, kind TEXT NOT NULL, intent TEXT NOT NULL,
                        raw TEXT NOT NULL, reserve_txid TEXT NOT NULL, reserve_vout INTEGER NOT NULL,
                        evidence TEXT NOT NULL, psbt TEXT, PRIMARY KEY(burn,kind));
                    CREATE INDEX reserve_edges ON commitments(reserve_txid,reserve_vout);
                    COMMIT;
                """)
                self.db.execute("INSERT INTO identity VALUES (?,0,?)", (self.policy_id, "0" * 64))
                directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            rows = self.db.execute(
                "SELECT policy,final_height,final_block FROM identity"
            ).fetchall()
            if len(rows) != 1 or rows[0][0] != self.policy_id:
                raise ValueError(
                    "native custody authority is absent, changed or partially initialized"
                )
            if self.db.execute("SELECT count(*) FROM commitments").fetchone()[0] > MAX_ROWS:
                raise ValueError("native custody history exceeds its bound")
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def commit(self, observation, raw, native):
        o = observation
        self.db.execute("BEGIN IMMEDIATE")
        try:
            old_height, old_hash = self.db.execute(
                "SELECT final_height,final_block FROM identity"
            ).fetchone()
            if old_height and (
                o["final_height"] < old_height or native("getblockhash", [old_height]) != old_hash
            ):
                raise ValueError("native custody finalized history was rewound or changed")
            peers = self.db.execute(
                "SELECT burn FROM commitments WHERE reserve_txid=? AND reserve_vout=?",
                (o["reserve_txid"], o["reserve_vout"]),
            ).fetchall()
            if any(row[0] != o["burn_id"] for row in peers):
                raise ValueError("reserve edge already belongs to another retained obligation")
            if (
                o["kind"] == "PAYOUT"
                and self.db.execute(
                    "SELECT 1 FROM commitments WHERE burn=? AND kind='RETIREMENT'", (o["burn_id"],)
                ).fetchone()
            ):
                raise ValueError("retirement permanently disables fresh payout signatures")
            existing = self.db.execute(
                "SELECT intent,raw,psbt FROM commitments WHERE burn=? AND kind=?",
                (o["burn_id"], o["kind"]),
            ).fetchone()
            if existing:
                if existing[:2] != (o["intent_commitment"], raw):
                    raise ValueError(
                        "native custody proposal differs from retained signed authority"
                    )
            else:
                if self.db.execute("SELECT count(*) FROM commitments").fetchone()[0] >= MAX_ROWS:
                    raise ValueError("native custody history is full; reconciliation is required")
                self.db.execute(
                    "INSERT INTO commitments VALUES (?,?,?,?,?,?,?,NULL)",
                    (
                        o["burn_id"],
                        o["kind"],
                        o["intent_commitment"],
                        raw,
                        o["reserve_txid"],
                        o["reserve_vout"],
                        canonical(o),
                    ),
                )
            self.db.execute(
                "UPDATE identity SET final_height=?,final_block=?",
                (o["final_height"], o["final_block"]),
            )
            self.db.execute("COMMIT")
            return existing[2] if existing else None
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def retain(self, observation, psbt):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            key = (observation["burn_id"], observation["kind"], observation["intent_commitment"])
            row = self.db.execute(
                "SELECT psbt FROM commitments WHERE burn=? AND kind=? AND intent=?", key
            ).fetchone()
            if row is None or (row[0] is not None and row[0] != psbt):
                raise ValueError("native custody result is absent or conflicts with retained bytes")
            self.db.execute(
                "UPDATE commitments SET psbt=? WHERE burn=? AND kind=? AND intent=?", (psbt, *key)
            )
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise


def inspect(native, policy, wire, raw):
    verify_expected_chain(native, policy["expected_chain"])
    o = native("inspectcustodyintent", [wire])
    fields = {
        "version",
        "native_authorized",
        "kind",
        "destination_script_hex",
        "refund_address",
        *INSPECTION_HASHES,
        *INSPECTION_NUMBERS,
    }
    if (
        type(o) is not dict
        or set(o) != fields
        or type(o["version"]) is not int
        or o["version"] != 1
        or o["native_authorized"] is not True
    ):
        raise ValueError("native custody inspection is malformed or unauthorized")
    if o["kind"] not in ("PAYOUT", "RETIREMENT"):
        raise ValueError("native custody operation is not supported")
    for field in INSPECTION_HASHES:
        if type(o[field]) is not str or not HASH.fullmatch(o[field]) or o[field] == "0" * 64:
            raise ValueError("native custody inspection has an invalid hash")
    for field in INSPECTION_NUMBERS:
        if type(o[field]) is not int or not 0 <= o[field] < (1 << 63):
            raise ValueError("native custody inspection has an invalid number")
    for field in HASH_FIELDS:
        if o["genesis_hash" if field == "domain_genesis_hash" else field] != policy[field]:
            raise ValueError("native custody inspection differs from independent authority pins")
    if (
        o["epoch"] != policy["epoch"]
        or not 0 < o["fee_sats"] <= policy["max_fee_sats"]
        or not o["principal_sats"]
        or not 0 < o["authorization_height"] <= o["final_height"] <= o["tip"]
        or o["reserve_vout"] > 0xFFFFFFFF
        or o["unsigned_tx_sha256"] != hashlib.sha256(bytes.fromhex(raw)).hexdigest()
        or type(o["destination_script_hex"]) is not str
        or not re.fullmatch(r"(?:[0-9a-f]{2}){1,80}", o["destination_script_hex"])
        or type(o["refund_address"]) is not str
        or not re.fullmatch(r"V[1-9A-HJ-NP-Za-km-z]{25,49}", o["refund_address"])
    ):
        raise ValueError("native custody inspection fails exact transaction or finality binding")
    for height, block in (
        ("authorization_height", "authorization_block"),
        ("final_height", "final_block"),
        ("tip", "tip_hash"),
    ):
        if native("getblockhash", [o[height]]) != o[block]:
            raise ValueError("native custody inspection is no longer canonical")
    if native("getblockcount", []) != o["tip"]:
        raise ValueError("native chain advanced during custody inspection")
    return o


def bitcoin_context(core, policy, binding, observed, raw):
    chain = core("getblockchaininfo")
    if (
        type(chain) is not dict
        or chain.get("chain") != "regtest"
        or chain.get("initialblockdownload") is not False
        or core("getblockhash", 0) != bytes.fromhex(policy["bitcoin_genesis_hash"])[::-1].hex()
    ):
        raise ValueError("independent Bitcoin chain is unavailable or mismatched")
    decoded = core("decoderawtransaction", raw)
    if (
        type(decoded) is not dict
        or decoded.get("txid") != bytes.fromhex(observed["bitcoin_txid"])[::-1].hex()
    ):
        raise ValueError("Bitcoin transaction differs from finalized native authority")
    inputs = decoded.get("vin")
    if type(inputs) is not list or not 2 <= len(inputs) <= 8:
        raise ValueError("native custody requires reserve and bounded external fee inputs")
    seen, reserve, total = set(), [], 0
    for index, item in enumerate(inputs):
        if (
            type(item) is not dict
            or type(item.get("txid")) is not str
            or not HASH.fullmatch(item["txid"])
            or type(item.get("vout")) is not int
            or not 0 <= item["vout"] <= 0xFFFFFFFF
        ):
            raise ValueError("Bitcoin prevout identity is malformed")
        key = (item["txid"], item["vout"])
        if key in seen:
            raise ValueError("Bitcoin transaction repeats an input")
        seen.add(key)
        coin = core("gettxout", *key, True)
        if (
            type(coin) is not dict
            or coin.get("bestblock") != chain.get("bestblockhash")
            or type(coin.get("confirmations")) is not int
            or coin["confirmations"] < policy["minimum_bitcoin_confirmations"]
            or type(coin.get("scriptPubKey")) is not dict
        ):
            raise ValueError("Bitcoin prevout is spent, underconfirmed or incoherent")
        script = coin["scriptPubKey"].get("hex")
        if key == (bytes.fromhex(observed["reserve_txid"])[::-1].hex(), observed["reserve_vout"]):
            if script != binding["spv_custody_spk_hex"]:
                raise ValueError("reserve does not use the full pinned custody descriptor")
            reserve.append(index)
        elif script in binding["script_pubkey_set"]:
            raise ValueError("custody backing cannot be used to sponsor payout fees")
        total += rd.btc_to_sats(coin["value"])
    outputs = decoded.get("vout")
    if (
        type(outputs) is not list
        or not 1 <= len(outputs) <= 8
        or any(type(row) is not dict for row in outputs)
    ):
        raise ValueError("Bitcoin outputs are malformed")
    if (
        len(reserve) != 1
        or total - sum(rd.btc_to_sats(row["value"]) for row in outputs) != observed["fee_sats"]
    ):
        raise ValueError("Bitcoin inputs or fee differ from native intent")
    after = core("getblockchaininfo")
    if (
        type(after) is not dict
        or any(after.get(key) != chain.get(key) for key in ("chain", "blocks", "bestblockhash"))
        or after.get("initialblockdownload") is not False
    ):
        raise ValueError("Bitcoin chain changed during custody checks")
    return decoded, reserve[0]


def refresh_authority(native, policy, wire, raw, previous):
    current = inspect(native, policy, wire, raw)
    moving = {"final_height", "final_block", "finality_certificate", "tip", "tip_hash"}
    if (
        any(current[field] != previous[field] for field in previous if field not in moving)
        or current["final_height"] < previous["final_height"]
        or native("getblockhash", [previous["final_height"]]) != previous["final_block"]
    ):
        raise ValueError("native custody authority or finalized ancestry changed")
    return current


def sign(request, cfg, store, native, core):
    policy = configuration(cfg)
    if store.policy != policy:
        raise ValueError("native custody history belongs to another policy")
    if (
        type(request) is not dict
        or set(request) != {"action", "authorization_hex", "raw_tx_hex"}
        or request["action"] != "native_sign"
    ):
        raise ValueError("native custody request schema is invalid")
    wire, raw = request["authorization_hex"], request["raw_tx_hex"]
    for value, bound in ((wire, MAX_AUTH_BYTES), (raw, MAX_RAW_BYTES)):
        if (
            type(value) is not str
            or not 0 < len(value) <= 2 * bound
            or not re.fullmatch(r"(?:[0-9a-f]{2})+", value)
        ):
            raise ValueError("native custody request exceeds its canonical wire bound")
    binding = custody.load_manifest(
        policy["manifest_path"],
        policy["descriptor_hash"],
        policy["custody_manifest_sha256"],
        network="regtest",
    )
    custody.verify_core_derivation(core, binding, expected_hrp="bcrt")
    custody.verify_peg_identity(native("getpeginfo", []), binding, network="regtest")
    observed = inspect(native, policy, wire, raw)
    decoded, reserve_index = bitcoin_context(core, policy, binding, observed, raw)
    psbt = rd._checked_partial_psbt(core("converttopsbt", raw, True))
    psbt = rd._checked_partial_psbt(core("utxoupdatepsbt", psbt))
    answer = core("walletprocesspsbt", psbt, False, "ALL", True, False)
    if type(answer) is not dict:
        raise ValueError("custody wallet could not prepare the exact PSBT")
    psbt = rd._checked_partial_psbt(answer.get("psbt"))
    prepared = core("decodepsbt", psbt)
    validate_partial(prepared, decoded, reserve_index, policy, signed=False)
    observed = refresh_authority(native, policy, wire, raw, observed)
    bitcoin_context(core, policy, binding, observed, raw)
    cached = store.commit(observed, raw, native)
    if cached is not None:
        rd._checked_partial_psbt(cached)
        validate_partial(core("decodepsbt", cached), decoded, reserve_index, policy, signed=True)
        return {"signer_id": cfg["signer_id"], "psbt": cached}
    refresh_authority(native, policy, wire, raw, observed)
    bitcoin_context(core, policy, binding, observed, raw)
    answer = core("walletprocesspsbt", psbt, True, "ALL", True, False)
    if type(answer) is not dict:
        raise ValueError("custody wallet did not return a signing result")
    signed = rd._checked_partial_psbt(answer.get("psbt"))
    validate_partial(core("decodepsbt", signed), decoded, reserve_index, policy, signed=True)
    store.retain(observed, signed)
    return {"signer_id": cfg["signer_id"], "psbt": signed}


def validate_partial(psbt, decoded, reserve_index, policy, *, signed):
    if (
        type(psbt) is not dict
        or type(psbt.get("tx")) is not dict
        or psbt["tx"].get("txid") != decoded["txid"]
    ):
        raise ValueError("custody PSBT changes the authorized transaction")
    inputs = psbt.get("inputs")
    if type(inputs) is not list or len(inputs) != len(decoded["vin"]):
        raise ValueError("custody PSBT input maps are incomplete")
    for index, item in enumerate(inputs):
        if (
            type(item) is not dict
            or item.get("sighash", "ALL") != "ALL"
            or any(
                item.get(key)
                for key in (
                    "partial_signatures",
                    "taproot_key_path_sig",
                    "final_scriptSig",
                    "final_scriptwitness",
                )
            )
        ):
            raise ValueError("custody PSBT has weak sighash or unexpected signing authority")
        signatures = item.get("taproot_script_path_sigs", [])
        if index != reserve_index or not signed:
            if signatures:
                raise ValueError("custody PSBT includes unexpected signatures")
        elif (
            type(signatures) is not list
            or len(signatures) != 1
            or type(signatures[0]) is not dict
            or set(signatures[0]) != {"pubkey", "leaf_hash", "sig"}
            or signatures[0]["pubkey"] != policy["member_key"]
            or type(signatures[0]["sig"]) is not str
            or not re.fullmatch(r"[0-9a-f]{128}01", signatures[0]["sig"])
        ):
            raise ValueError(
                "custody wallet must contribute exactly its one ALL-bound member signature"
            )
        if index != reserve_index:
            continue
        leaves = item.get("taproot_scripts")
        if (
            type(leaves) is not list
            or len(leaves) != 1
            or type(leaves[0]) is not dict
            or leaves[0].get("leaf_ver") != 192
        ):
            raise ValueError("custody PSBT must expose its one reviewed threshold leaf")
        script = leaves[0].get("script")
        if type(script) is not str or not re.fullmatch(r"[0-9a-f]{344}", script):
            raise ValueError("custody threshold script is malformed")
        leaf = bytes.fromhex(script)
        if leaf[-2:] != b"\x53\x9c" or any(
            leaf[i * 34] != 32 or leaf[i * 34 + 33] != (0xAC if i == 0 else 0xBA) for i in range(5)
        ):
            raise ValueError("custody script is not exactly three of five")
        keys = [leaf[i * 34 + 1 : i * 34 + 33].hex() for i in range(5)]
        if len(set(keys)) != 5 or keys[policy["member_index"]] != policy["member_key"]:
            raise ValueError("custody member is not the pinned descriptor position")
        tag = hashlib.sha256(b"TapLeaf").digest()
        leaf_hash = hashlib.sha256(tag + tag + b"\xc0\xac" + leaf).hexdigest()
        if signed and signatures[0]["leaf_hash"] != leaf_hash:
            raise ValueError("custody signature authorizes another leaf")


def dispatch(request, cfg, native, bitcoin, *, initialize=False):
    try:
        from .instance_lock import acquire_instance_lock
    except ImportError:
        from instance_lock import acquire_instance_lock
    policy = configuration(cfg)
    lock = acquire_instance_lock(policy["state_path"])
    store = None
    deadline = time.monotonic() + 180
    try:
        store = CommitmentStore(cfg, initialize=initialize)
        if initialize:
            return {"initialized": True, "production_active": False, "signer_id": cfg["signer_id"]}

        def core(method, *params):
            return bitcoin.call(
                method,
                *(value if type(value) is str else canonical(value) for value in params),
                deadline=deadline,
            )

        def native_call(method, params):
            return native.call(method, params, deadline=deadline)

        return sign(request, cfg, store, native_call, core)
    finally:
        if store is not None:
            store.close()
        os.close(lock)


def collect(request, cfg, native, bitcoin):
    """Collect usable custody shares plus an external fee sponsor; never broadcast."""
    policy = configuration(cfg)
    if (
        type(request) is not dict
        or set(request) != {"action", "authorization_hex", "raw_tx_hex"}
        or request["action"] != "native_sign"
    ):
        raise ValueError("native custody collection request is malformed")
    raw, wire = request["raw_tx_hex"], request["authorization_hex"]
    for value, bound in ((raw, MAX_RAW_BYTES), (wire, MAX_AUTH_BYTES)):
        if (
            type(value) is not str
            or not 0 < len(value) <= 2 * bound
            or not re.fullmatch(r"(?:[0-9a-f]{2})+", value)
        ):
            raise ValueError("native custody collection wire is malformed")
    signing = cfg.get("payout_signing")
    if (
        type(signing) is not dict
        or signing.get("threshold") != 3
        or type(signing.get("threshold")) is not int
    ):
        raise ValueError("native custody collection requires exactly three of five")
    members = signing.get("signers")
    if (
        type(members) is not list
        or len(members) != 5
        or any(
            type(row) is not dict or set(row) != {"id", "command", "member_index", "member_key"}
            for row in members
        )
    ):
        raise ValueError("native custody collection requires five independently pinned members")
    if (
        any(type(row["member_index"]) is not int for row in members)
        or sorted(row["member_index"] for row in members) != list(range(5))
        or any(
            type(row["id"]) is not str
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", row["id"])
            or type(row["member_key"]) is not str
            or not HASH.fullmatch(row["member_key"])
            or type(row["command"]) is not list
            or not 1 <= len(row["command"]) <= 16
            or any(type(arg) is not str or not arg or "\0" in arg for arg in row["command"])
            for row in members
        )
        or len({row["id"] for row in members}) != 5
        or len({row["member_key"] for row in members}) != 5
        or len({canonical(row["command"]) for row in members}) != 5
    ):
        raise ValueError("native custody identities, keys or command paths are invalid or repeated")
    timeout = rd._bounded_config_int(
        signing.get("collection_timeout_secs", 600), "native collection deadline", 1, 1800
    )
    deadline = time.monotonic() + timeout
    native_rpc = native

    def native(method, params):
        return native_rpc.call(method, params, deadline=deadline)

    def core(method, *params):
        return bitcoin.call(
            method,
            *(value if type(value) is str else canonical(value) for value in params),
            deadline=deadline,
        )

    binding = custody.load_manifest(
        policy["manifest_path"],
        policy["descriptor_hash"],
        policy["custody_manifest_sha256"],
        network="regtest",
    )
    custody.verify_core_derivation(core, binding, expected_hrp="bcrt")
    custody.verify_peg_identity(native("getpeginfo", []), binding, network="regtest")
    observation = inspect(native, policy, wire, raw)
    decoded, reserve_index = bitcoin_context(core, policy, binding, observation, raw)
    psbt = rd._checked_partial_psbt(core("converttopsbt", raw, True))
    psbt = rd._checked_partial_psbt(core("utxoupdatepsbt", psbt))
    prepared = core("walletprocesspsbt", psbt, False, "ALL", True, False)
    if type(prepared) is not dict:
        raise ValueError("external fee wallet could not prepare PSBT")
    psbt = rd._checked_partial_psbt(prepared.get("psbt"))
    info = core("decodepsbt", psbt)
    if (
        type(info) is not dict
        or type(info.get("inputs")) is not list
        or len(info["inputs"]) != len(decoded["vin"])
    ):
        raise ValueError("external fee wallet returned malformed input maps")
    forbidden = (
        "partial_signatures",
        "taproot_key_path_sig",
        "taproot_script_path_sigs",
        "final_scriptSig",
        "final_scriptwitness",
    )
    if any(
        type(row) is not dict or any(row.get(key) for key in forbidden) for row in info["inputs"]
    ):
        raise ValueError("external fee wallet prepared pre-signed input maps")
    sponsored = core("walletprocesspsbt", psbt, True, "ALL", True, False)
    if type(sponsored) is not dict:
        raise ValueError("external fee sponsor produced no PSBT")
    sponsored = rd._checked_partial_psbt(sponsored.get("psbt"))
    info = core("decodepsbt", sponsored)
    if (
        type(info) is not dict
        or type(info.get("tx")) is not dict
        or info["tx"].get("txid") != decoded["txid"]
        or type(info.get("inputs")) is not list
        or len(info["inputs"]) != len(decoded["vin"])
        or type(info["inputs"][reserve_index]) is not dict
        or any(info["inputs"][reserve_index].get(key) for key in forbidden)
    ):
        raise ValueError("coordinator fee wallet must have zero custody signing authority")
    partials, attempted = [], set()
    for member in members:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            result = rd.run_bounded_subprocess(
                member["command"],
                input_text=canonical(request),
                timeout=min(remaining, 180),
                stdout_max=rd.MAX_SIGNER_OUTPUT_BYTES,
                stderr_max=1024 * 1024,
                description="native custody member",
            )
            if result.returncode:
                continue
            response = rd.strict_json_loads(result.stdout, "native custody contribution")
            if (
                type(response) is not dict
                or set(response) != {"signer_id", "psbt"}
                or response["signer_id"] != member["id"]
            ):
                continue
            partial = rd._checked_partial_psbt(response["psbt"])
            member_policy = dict(
                policy, member_index=member["member_index"], member_key=member["member_key"]
            )
            validate_partial(
                core("decodepsbt", partial), decoded, reserve_index, member_policy, signed=True
            )
            partials.append((member["id"], partial))
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError):
            continue
        for indices in itertools.combinations(range(len(partials)), 3):
            if indices in attempted or time.monotonic() >= deadline:
                continue
            attempted.add(indices)
            try:
                combined = rd._checked_partial_psbt(
                    core("combinepsbt", [sponsored, *[partials[i][1] for i in indices]])
                )
                final = core("finalizepsbt", combined)
                if type(final) is not dict or final.get("complete") is not True:
                    continue
                signed = final.get("hex")
                if (
                    type(signed) is not str
                    or len(signed) > 2 * rd.MAX_SIGNER_OUTPUT_BYTES
                    or not re.fullmatch(r"(?:[0-9a-f]{2})+", signed)
                ):
                    continue
                transaction = core("decoderawtransaction", signed)
                if (
                    type(transaction) is not dict
                    or transaction.get("txid") != decoded["txid"]
                    or type(transaction.get("vin")) is not list
                    or len(transaction["vin"]) != len(decoded["vin"])
                    or not rd._has_exact_custody_witness(
                        {"vin": [transaction["vin"][reserve_index]]}
                    )
                ):
                    continue
                acceptance = core("testmempoolaccept", [signed])
                if (
                    type(acceptance) is not list
                    or len(acceptance) != 1
                    or type(acceptance[0]) is not dict
                    or acceptance[0].get("txid") != decoded["txid"]
                    or acceptance[0].get("allowed") is not True
                ):
                    continue
                refreshed = refresh_authority(native, policy, wire, raw, observation)
                bitcoin_context(core, policy, binding, refreshed, raw)
                return signed, [partials[i][0] for i in indices]
            except (ValueError, RuntimeError, OSError, subprocess.SubprocessError):
                continue
    raise RuntimeError(
        "no usable three-of-five native custody quorum before the bounded collection ended"
    )
