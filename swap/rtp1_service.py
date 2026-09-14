"""Versioned RTP1 issuance lifecycle; callers hold the operator's authority lock.

The journal never expires a reservation or forgets a possibly signed carrier.
Production activation and migration of funded C1 liabilities are separate gates.
"""
import copy
import hashlib
import json
import re

from rtp1_mint_policy import _template_bytes, validate_inspection
from rtp1_backing_evidence import validate_backing_facts
from veld_chain_identity import parse_expected_chain
from veld_peg_solvency import unsigned_template_from_signed_hex


MAX_ROWS = 4096
MAX_BYTES = 64 * 1024 * 1024
MAX_SIGNED_BYTES = 128 * 1024
ZERO = "0" * 64
HASH = re.compile(r"[0-9a-f]{64}")
CONTEXT_FIELDS = ("genesis_hash", "unsigned_tx_sha256", "proof_sha256", "issuer",
    "recipient", "sats", "fee_units", "deposit_outpoint", "bitcoin_txid",
    "bitcoin_block", "reserve_prior_state_hex", "reserve_prior_supply_sats",
    "nullifier_root", "custody_descriptor_sha256", "custody_manifest_sha256")
RECEIPT_FIELDS = {"version", "kind", "policy_id", "witness_id", "request_id",
    "sequence", "previous", "intent", "sig_alg", "sig"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def hash_value(value, label):
    if type(value) is not str or not HASH.fullmatch(value):
        raise ValueError(label + " is not a canonical hash")
    return value


def configuration(value):
    fields = {"version", "expected_chain", "issuer", "witness_id",
        "custody_descriptor_sha256", "custody_manifest_sha256", "bitcoin_genesis",
        "bitcoin_network", "custody_script_hex", "minimum_confirmations"}
    if type(value) is not dict or set(value) != fields or type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("RTP1 service configuration is not version 1")
    pins = parse_expected_chain(value["expected_chain"])
    if pins["disposable"] is not True or value["bitcoin_network"] != "regtest":
        raise ValueError("RTP1 service activation is closed outside a disposable test network")
    for field in ("custody_descriptor_sha256", "custody_manifest_sha256", "bitcoin_genesis"):
        if hash_value(value[field], field) == ZERO:
            raise ValueError("RTP1 policy requires nonzero identity pins")
    if (type(value["issuer"]) is not str or not re.fullmatch(r"V[1-9A-HJ-NP-Za-km-z]{25,49}", value["issuer"]) or
            type(value["witness_id"]) is not str or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value["witness_id"]) or
            type(value["custody_script_hex"]) is not str or not re.fullmatch(r"5120[0-9a-f]{64}", value["custody_script_hex"]) or
            type(value["minimum_confirmations"]) is not int or not 144 <= value["minimum_confirmations"] <= 1000000):
        raise ValueError("RTP1 service authority or Bitcoin policy is invalid")
    return copy.deepcopy(value)


def mint_policy(config, request):
    return {"expected_chain": config["expected_chain"], "issuer": config["issuer"],
        "recipient": request["recipient"], "sats": request["sats"],
        "custody_descriptor_sha256": config["custody_descriptor_sha256"],
        "custody_manifest_sha256": config["custody_manifest_sha256"]}


def request_identity(request):
    if type(request) is not dict or set(request) != {"action", "unsigned_tx_hex", "recipient", "sats"} or request["action"] != "rtp1_mint":
        raise ValueError("RTP1 mint request schema is invalid")
    raw = _template_bytes(request["unsigned_tx_hex"])
    if (type(request["recipient"]) is not str or not re.fullmatch(r"V[1-9A-HJ-NP-Za-km-z]{25,49}", request["recipient"]) or
            type(request["sats"]) is not int or not 0 < request["sats"] <= 1000000000):
        raise ValueError("RTP1 mint claim is invalid")
    return hashlib.sha256(raw).hexdigest()


def intent_from_evidence(config, request, evidence):
    request_identity(request)
    if type(evidence) is not dict or set(evidence) != {"version", "kind", "native", "bitcoin", "transition", "evidence_sha256"}:
        raise ValueError("independent backing evidence is incomplete")
    body = {key: value for key, value in evidence.items() if key != "evidence_sha256"}
    if (type(evidence["version"]) is not int or evidence["version"] != 1 or
            evidence["kind"] != "rtp1-independent-backing" or
            evidence["evidence_sha256"] != hashlib.sha256(b"VELD/RTP1/BACKING/v1\x00" + canonical(body)).hexdigest()):
        raise ValueError("independent backing evidence binding is invalid")
    native = validate_inspection(evidence["native"], request["unsigned_tx_hex"], **mint_policy(config, request))
    facts = validate_backing_facts(evidence["transition"])
    bitcoin = evidence["bitcoin"]
    if (type(bitcoin) is not dict or bitcoin.get("genesis_hash") != config["bitcoin_genesis"] or
            bitcoin.get("network") != config["bitcoin_network"] or
            type(bitcoin.get("confirmations")) is not int or bitcoin["confirmations"] < config["minimum_confirmations"] or
            facts["custody_script_hex"] != config["custody_script_hex"] or
            facts["sats"] != native["sats"] or facts["recipient"] != native["recipient"] or facts["issuer"] != native["issuer"] or
            facts["deposit_outpoint"] != native["deposit_outpoint"] or
            facts["bitcoin_txid"] != bytes.fromhex(native["bitcoin_txid"])[::-1].hex() or
            facts["bitcoin_block"] != bytes.fromhex(native["bitcoin_block"])[::-1].hex() or
            bitcoin.get("reserve_outpoint") != facts["bitcoin_txid"] + ":" + str(facts["reserve_vout"]) or
            bitcoin.get("reserve_value_sats") != facts["reserve_value_sats"] or
            bitcoin.get("custody_script_hex") != facts["custody_script_hex"]):
        raise ValueError("independent backing evidence differs from the exact RTP1 policy")
    return {"native": {key: native[key] for key in CONTEXT_FIELDS}, "transition": facts}


def receipt_core(receipt):
    return {key: value for key, value in receipt.items() if key not in {"sig", "sig_alg"}}


def validate_receipt(receipt, config, request, evidence, verify):
    rid = request_identity(request)
    if type(receipt) is not dict or set(receipt) != RECEIPT_FIELDS:
        raise ValueError("RTP1 witness receipt schema is invalid")
    if (type(receipt["version"]) is not int or receipt["version"] != 1 or
            receipt["kind"] != "VELD_RTP1_RESERVATION" or receipt["policy_id"] != digest(config) or
            receipt["witness_id"] != config["witness_id"] or receipt["request_id"] != rid or
            type(receipt["sequence"]) is not int or not 1 <= receipt["sequence"] <= MAX_ROWS or
            receipt["intent"] != intent_from_evidence(config, request, evidence) or
            receipt["sig_alg"] != "mldsa65" or type(receipt["sig"]) is not str or
            not re.fullmatch(r"[0-9a-f]{6618}", receipt["sig"])):
        raise ValueError("RTP1 witness receipt differs from the authorized intent")
    hash_value(receipt["previous"], "receipt predecessor")
    if verify(canonical(receipt_core(receipt)), receipt["sig"]) is not True:
        raise ValueError("RTP1 witness receipt signature is invalid")
    return copy.deepcopy(receipt)


def empty_journal(role, config, migration):
    configuration(config)
    if role not in {"issuer", "witness"}:
        raise ValueError("RTP1 journal role is invalid")
    hash_value(migration, "reviewed migration inventory")
    if migration == ZERO:
        raise ValueError("RTP1 migration requires a bound inventory")
    return {"version": 1, "kind": "VELD_RTP1_JOURNAL", "role": role,
        "policy_id": digest(config), "migration": migration, "records": [], "head": ZERO}


def signed_identity(signed, unsigned):
    if (type(signed) is not str or not 2 <= len(signed) <= 2 * MAX_SIGNED_BYTES or len(signed) % 2 or
            not re.fullmatch(r"[0-9a-f]+", signed) or unsigned_template_from_signed_hex(signed) != unsigned):
        raise ValueError("signed carrier does not reconstruct the exact reserved template")
    raw = bytes.fromhex(signed)
    return hashlib.sha256(hashlib.sha256(raw).digest()).hexdigest()


class Journal:
    def __init__(self, state, config, role, persist, verify_receipt):
        self.config = configuration(config)
        self.persist = persist
        verified = set()
        def cached_verify(message, signature):
            key = hashlib.sha256(message + bytes.fromhex(signature)).digest()
            if key in verified:
                return True
            if verify_receipt(message, signature) is not True:
                return False
            if len(verified) < MAX_ROWS + 1:
                verified.add(key)
            return True
        self.verify_receipt = cached_verify
        self.role = role
        self.state = copy.deepcopy(state)
        self.validate()

    def validate(self):
        s = self.state
        if (type(s) is not dict or set(s) != {"version", "kind", "role", "policy_id", "migration", "records", "head"} or
                type(s["version"]) is not int or s["version"] != 1 or s["kind"] != "VELD_RTP1_JOURNAL" or
                s["role"] != self.role or s["policy_id"] != digest(self.config) or
                type(s["records"]) is not list or len(s["records"]) > MAX_ROWS or len(canonical(s)) > MAX_BYTES):
            raise ValueError("RTP1 authority journal is invalid or exceeds capacity")
        if hash_value(s["migration"], "migration inventory") == ZERO:
            raise ValueError("RTP1 authority journal has no migration inventory")
        head, requests, deposits, edges = ZERO, set(), set(), set()
        for seq, row in enumerate(s["records"], 1):
            fields = {"request", "evidence", "receipt", "signed_tx_hex", "committed", "confirmation"}
            if type(row) is not dict or set(row) != fields:
                raise ValueError("RTP1 journal entry schema is invalid")
            rid = request_identity(row["request"])
            receipt = validate_receipt(row["receipt"], self.config, row["request"], row["evidence"], self.verify_receipt)
            native = receipt["intent"]["native"]
            edge = native["reserve_prior_state_hex"]
            deposit = native["deposit_outpoint"]
            if rid in requests or deposit in deposits or edge in edges or receipt["sequence"] != seq or receipt["previous"] != head:
                raise ValueError("RTP1 journal reuses an identity or breaks the witness sequence")
            requests.add(rid); deposits.add(deposit); edges.add(edge)
            head = digest(receipt)
            if row["signed_tx_hex"] is not None:
                signed_identity(row["signed_tx_hex"], row["request"]["unsigned_tx_hex"])
            if type(row["committed"]) is not bool or (row["committed"] and row["signed_tx_hex"] is None):
                raise ValueError("RTP1 committed liability has no exact signed bytes")
            conf = row["confirmation"]
            if conf is not None:
                if (type(conf) is not dict or set(conf) != {"height", "hash"} or
                        type(conf["height"]) is not int or conf["height"] <= 0 or not row["committed"]):
                    raise ValueError("RTP1 confirmation is invalid")
                hash_value(conf["hash"], "confirmation block")
        if s["head"] != head:
            raise ValueError("RTP1 journal head is inconsistent")

    def save(self, mutation):
        before = copy.deepcopy(self.state)
        try:
            mutation()
            self.validate()
            self.persist(copy.deepcopy(self.state))
        except BaseException:
            self.state = before
            raise

    def find(self, request):
        rid = request_identity(request)
        row = next((r for r in self.state["records"] if r["receipt"]["request_id"] == rid), None)
        if row is not None and row["request"] != request:
            raise ValueError("RTP1 request identity has conflicting claims")
        return row

    def append(self, request, evidence, receipt):
        receipt = validate_receipt(receipt, self.config, request, evidence, self.verify_receipt)
        old = self.find(request)
        if old is not None:
            if old["receipt"] != receipt:
                raise ValueError("existing RTP1 reservation has a different receipt")
            return old
        if any(row["confirmation"] is None for row in self.state["records"]):
            raise ValueError("an unresolved RTP1 reserve edge requires reconciliation")
        if len(self.state["records"]) >= MAX_ROWS:
            raise ValueError("RTP1 journal capacity requires reviewed archival")
        row = {"request": copy.deepcopy(request), "evidence": copy.deepcopy(evidence),
            "receipt": receipt, "signed_tx_hex": None, "committed": False, "confirmation": None}
        def mutate():
            self.state["records"].append(row)
            self.state["head"] = digest(receipt)
        self.save(mutate)
        return self.find(request)

    def commit(self, request, signed, committed):
        row = self.find(request)
        if row is None:
            raise ValueError("RTP1 signature has no durable reservation")
        txid = signed_identity(signed, request["unsigned_tx_hex"])
        if row["signed_tx_hex"] not in (None, signed):
            raise ValueError("RTP1 reservation is already bound to different signed bytes")
        if type(committed) is not bool or (row["committed"] and not committed):
            raise ValueError("RTP1 witness commitment cannot be reversed")
        def mutate():
            row["signed_tx_hex"] = signed
            row["committed"] = committed
        self.save(mutate)
        return {"version": 1, "kind": "VELD_RTP1_COMMIT", "policy_id": digest(self.config),
            "request_id": request_identity(request), "receipt_sha256": digest(row["receipt"]),
            "signed_tx_sha256": hashlib.sha256(bytes.fromhex(signed)).hexdigest(), "txid": txid}

    def reconcile(self, observe):
        observations = []
        for row in self.state["records"]:
            if not row["committed"]:
                observations.append(None)
            else:
                observations.append(observe(copy.deepcopy(row)))
        def mutate():
            for row, confirmed in zip(self.state["records"], observations):
                row["confirmation"] = confirmed
        self.save(mutate)
        return sum(r["request"]["sats"] for r in self.state["records"] if r["confirmation"] is None)


def witness_reserve(journal, request, inspect, sign_receipt):
    old = journal.find(request)
    if old is not None:
        return copy.deepcopy(old["receipt"])
    evidence = inspect(request)
    intent = intent_from_evidence(journal.config, request, evidence)
    core = {"version": 1, "kind": "VELD_RTP1_RESERVATION", "policy_id": digest(journal.config),
        "witness_id": journal.config["witness_id"], "request_id": request_identity(request),
        "sequence": len(journal.state["records"]) + 1, "previous": journal.state["head"], "intent": intent}
    receipt = sign_receipt(core)
    journal.append(request, evidence, receipt)
    return copy.deepcopy(receipt)


def witness_commit(journal, request, signed, decode_retained):
    row = journal.find(request)
    if row is None:
        raise ValueError("unknown RTP1 reservation")
    signed_identity(signed, request["unsigned_tx_hex"])
    if decode_retained(request, row["evidence"], signed) is not True:
        raise ValueError("RTP1 committed carrier was not independently verified")
    return journal.commit(request, signed, True)


def witness_status(journal, request):
    row = journal.find(request)
    if row is None:
        raise ValueError("RTP1 witness history has no such reservation")
    return {"receipt": copy.deepcopy(row["receipt"]), "committed": row["committed"],
        "signed_tx_hex": row["signed_tx_hex"]}


def check_witness_status(snapshot, row):
    if (type(snapshot) is not dict or set(snapshot) != {"receipt", "committed", "signed_tx_hex"} or
            snapshot["receipt"] != row["receipt"] or type(snapshot["committed"]) is not bool or
            (snapshot["signed_tx_hex"] is not None) != snapshot["committed"]):
        raise ValueError("witness history differs from the issuer's durable reservation")
    signed = snapshot["signed_tx_hex"]
    if signed is not None:
        signed_identity(signed, row["request"]["unsigned_tx_hex"])
        if row["signed_tx_hex"] not in (None, signed):
            raise ValueError("issuer and witness committed different signature bytes")
    return signed


def issuer_mint(journal, request, *, inspect, reserve, verify_fresh, sign_or_recover,
                commit, halt, receipt_verify, witness_snapshot):
    """Bytes are returned only after both operators persist the exact commitment.

    The signing callback owns the existing durable LEASED/SIGNING/exact-output
    recovery protocol. It must never attempt a second randomized signature.
    """
    halt()
    row = journal.find(request)
    if row is None:
        evidence = inspect(request)
        receipt = reserve(request)
        validate_receipt(receipt, journal.config, request, evidence, receipt_verify)
        row = journal.append(request, evidence, receipt)
    recovered = check_witness_status(witness_snapshot(request), row)
    signed = row["signed_tx_hex"]
    if signed is None and recovered is not None:
        journal.commit(request, recovered, True)
        signed = recovered
    if signed is None:
        def gate():
            halt()
            verify_fresh(request, row["evidence"])
            if check_witness_status(witness_snapshot(request), row) is not None:
                raise ValueError("witness already holds signed bytes; recover without signing")
        signed = sign_or_recover(request, row["evidence"], gate)
        journal.commit(request, signed, False)
    halt()
    expected = journal.commit(request, signed, row["committed"])
    observed = commit(request, signed)
    if type(observed) is not dict or observed != expected:
        raise ValueError("independent witness did not commit these exact signed bytes")
    journal.commit(request, signed, True)
    halt()
    return signed
