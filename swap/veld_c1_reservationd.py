#!/usr/bin/env python3
"""Crash-safe forced-command coordinator for the complete C1 lifecycle.

The custody service sends one exact allocation on stdin.  This process prepares
each carrier on an authenticated Veld node, obtains a signature only from the
isolated issuer signer, fsyncs the unsigned and signed bytes before broadcast,
and replays those same bytes after timeouts, lost RPC replies, or restarts.

With ``funding=null``, exit 0 means the exact C1E1 is canonical at the
compiled 101-block depth.  With a funding object, exit 0 means the exact C1F1
effect is canonical.  Exit 75 means the request is safely pending.  Every
other exit is a refusal.
"""

import fcntl
import copy
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from rpc_url_policy import (
    load_bounded_json_response,
    open_rpc_request,
    read_bounded_regular_file,
    read_bounded_secret_file,
    run_bounded_subprocess,
    strict_json_loads,
    validate_backend_rpc_url,
)
import veld_peg_solvency as solvency
from btcveld_c1 import allocation_commitment

REQUEST_MAX = 64 * 1024
STATE_MAX = 64 * 1024 * 1024
STATE_ADMISSION_MAX = STATE_MAX * 9 // 10
MAX_CARRIER_BYTES = 128 * 1024
MAX_RECORDS = 10_000
MAX_FUND_VARIANTS = 8
MAX_ISSUER_PREVOUT_EXCLUSIONS = 64
FINALITY_DEPTH = 101
LIFETIME_BLOCKS = 7 * 480
MIN_SATS = 10_000
# No independent per-allocation ceiling; consensus custody headroom is
# authoritative. This wire-sanity bound mirrors the 10 BTC absolute custody cap.
MAX_SATS = 1_000_000_000
ARCHIVE_RETENTION_SECONDS = 10 * 365 * 24 * 60 * 60
REQ_RE = re.compile(r"[0-9a-f]{32}")
ALLOCATION_ID_RE = re.compile(r"0{16}[0-9a-f]{16}")
HASH_RE = re.compile(r"[0-9a-f]{64}")
VELD_RE = re.compile(r"V[1-9A-HJ-NP-Za-km-z]{25,49}")
P2TR_RE = re.compile(r"5120[0-9a-f]{64}")
HEX_RE = re.compile(r"[0-9a-f]+")
OUTPOINT_RE = re.compile(r"[0-9a-f]{64}:(?:0|[1-9][0-9]{0,9})")
CONFIG = os.environ.get(
    "VELD_C1_RESERVATIOND_CONFIG", os.path.join(HERE, "c1-reservationd-config.json")
)


def fail(message):
    sys.stderr.write("veld_c1_reservationd REFUSE: %s\n" % str(message)[:400])
    raise SystemExit(2)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def txid(raw_hex):
    raw = bytes.fromhex(raw_hex)
    return hashlib.sha256(hashlib.sha256(raw).digest()).hexdigest()


def _read_tx_varint(raw, pos):
    if pos >= len(raw):
        raise ValueError("truncated transaction varint")
    first = raw[pos]
    pos += 1
    if first < 0xFD:
        return first, pos
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    if pos + width > len(raw):
        raise ValueError("truncated transaction varint body")
    value = int.from_bytes(raw[pos : pos + width], "little")
    if (
        (first == 0xFD and value < 0xFD)
        or (first == 0xFE and value <= 0xFFFF)
        or (first == 0xFF and value <= 0xFFFFFFFF)
    ):
        raise ValueError("non-minimal transaction varint")
    return value, pos + width


def unsigned_input_outpoints(unsigned_tx_hex):
    """Parse the exact ordered inputs from a complete unsigned Veld carrier."""
    solvency.validate_unsigned_template_hex(unsigned_tx_hex)
    raw = bytes.fromhex(unsigned_tx_hex)
    count, pos = _read_tx_varint(raw, 4)
    result = []
    for _ in range(count):
        txid_hex = raw[pos : pos + 32].hex()
        vout = int.from_bytes(raw[pos + 32 : pos + 36], "little")
        pos += 36
        script_len, pos = _read_tx_varint(raw, pos)
        pos += script_len + 4
        result.append("%s:%d" % (txid_hex, vout))
    return result


def validate_issuer_prevout_exclusions(value, *, candidate_inputs=None, allow_empty=True):
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or len(value) > MAX_ISSUER_PREVOUT_EXCLUSIONS
        or value != sorted(set(value))
        or any(
            not isinstance(outpoint, str)
            or not OUTPOINT_RE.fullmatch(outpoint)
            or int(outpoint.rsplit(":", 1)[1]) > 0xFFFFFFFF
            for outpoint in value
        )
        or (candidate_inputs is not None and not set(value).issubset(set(candidate_inputs)))
    ):
        raise ValueError("issuer prevout exclusion set is not exact")
    return list(value)


def issuer_prevout_exclusion_suffix(exclusions, *, force=False):
    validate_issuer_prevout_exclusions(exclusions)
    if not exclusions and not force:
        return None
    return "issuer-prevout-exclusions-v1:" + ",".join(exclusions)


def exact_argv(value, name):
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(part, str) or not part or "\x00" in part for part in value)
        or not os.path.isabs(value[0])
    ):
        raise ValueError("%s must be an absolute non-empty argv" % name)
    return tuple(value)


class Rpc:
    def __init__(self, cfg):
        if not isinstance(cfg, dict) or set(cfg) not in (
            {"url", "token_file"},
            {"url", "token_cmd"},
        ):
            raise ValueError("veld_rpc must contain url and exactly one token source")
        self.url = validate_backend_rpc_url(cfg["url"], "veld_rpc.url")
        if "token_file" in cfg:
            token = read_bounded_secret_file(cfg["token_file"], 4096, "coordinator RPC token")
            try:
                self.token = token.decode("ascii", "strict").strip()
            except UnicodeError as exc:
                raise ValueError("coordinator RPC token is not ASCII") from exc
        else:
            command = exact_argv(cfg["token_cmd"], "veld_rpc.token_cmd")
            out = run_bounded_subprocess(
                list(command),
                timeout=30,
                stdout_max=4096,
                stderr_max=64 * 1024,
                description="coordinator RPC token_cmd",
            )
            if out.returncode != 0:
                raise ValueError("coordinator RPC token command failed")
            self.token = out.stdout.strip()
        if not self.token or len(self.token) > 4096:
            raise ValueError("coordinator RPC token is missing or oversized")

    def call(self, method, params=None):
        body = canonical(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
        ).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self.token,
            },
        )
        with open_rpc_request(request, timeout=20) as response:
            envelope = load_bounded_json_response(
                response, 32 * 1024 * 1024, "coordinator Veld RPC response"
            )
        if not isinstance(envelope, dict) or envelope.get("error"):
            raise RuntimeError(
                "Veld RPC %s failed: %s"
                % (method, envelope.get("error") if isinstance(envelope, dict) else "bad envelope")
            )
        result = envelope.get("result")
        if isinstance(result, str):
            try:
                result = strict_json_loads(result, "nested Veld RPC result")
            except ValueError:
                pass
        return result


def validate_allocation(value):
    keys = {
        "request_id",
        "principal_hash",
        "veld_address",
        "amount_sats",
        "descriptor_index",
        "btc_address",
        "script_pubkey",
        "admitted_at",
        "expires_at",
        "commitment_blind",
        "consensus_allocation_id",
        "capacity_policy_sha256",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("allocation fields are not canonical")
    if (
        not isinstance(value["request_id"], str)
        or not REQ_RE.fullmatch(value["request_id"])
        or not isinstance(value["principal_hash"], str)
        or not HASH_RE.fullmatch(value["principal_hash"])
        or not isinstance(value["veld_address"], str)
        or not VELD_RE.fullmatch(value["veld_address"])
        or type(value["amount_sats"]) is not int
        or not MIN_SATS <= value["amount_sats"] <= MAX_SATS
        or type(value["descriptor_index"]) is not int
        or not 1000 <= value["descriptor_index"] <= 10_999
        or not isinstance(value["btc_address"], str)
        or not 14 <= len(value["btc_address"]) <= 100
        or not isinstance(value["script_pubkey"], str)
        or not P2TR_RE.fullmatch(value["script_pubkey"])
        or not isinstance(value["commitment_blind"], str)
        or not HASH_RE.fullmatch(value["commitment_blind"])
        or not isinstance(value["consensus_allocation_id"], str)
        or not ALLOCATION_ID_RE.fullmatch(value["consensus_allocation_id"])
        or int(value["consensus_allocation_id"], 16) == 0
        or type(value["admitted_at"]) is not int
        or value["admitted_at"] < 0
        or type(value["expires_at"]) is not int
        or value["expires_at"] - value["admitted_at"] != 7 * 24 * 60 * 60
        or not isinstance(value["capacity_policy_sha256"], str)
        or not HASH_RE.fullmatch(value["capacity_policy_sha256"])
    ):
        raise ValueError("allocation identity is malformed")
    return dict(value)


def validate_funding(value):
    if value is None:
        return None
    required = {"outpoint", "proof_hex", "proof_parent_root", "proof_parent_count"}
    if (
        not isinstance(value, dict)
        or set(value) != required
        or not isinstance(value.get("outpoint"), str)
        or not OUTPOINT_RE.fullmatch(value["outpoint"])
        or int(value["outpoint"].rsplit(":", 1)[1]) > 0xFFFFFFFF
        or not isinstance(value.get("proof_hex"), str)
        or not HEX_RE.fullmatch(value["proof_hex"])
        or len(value["proof_hex"]) % 2 != 0
        or not 174 <= len(value["proof_hex"]) <= 38_000
        or not isinstance(value.get("proof_parent_root"), str)
        or not HASH_RE.fullmatch(value["proof_parent_root"])
        or type(value.get("proof_parent_count")) is not int
        or not 0 <= value["proof_parent_count"] <= (1 << 64) - 1
    ):
        raise ValueError("funding proof identity is malformed")
    return dict(value)


def validate_status(status, allocation):
    if not isinstance(status, dict):
        raise ValueError("reservation RPC status is not an object")
    for key in (
        "found",
        "active",
        "retired",
        "exposed",
        "funded",
        "canonical_depth_reached",
        "reserve_canonical_depth_reached",
        "exposure_canonical_depth_reached",
        "funding_canonical_depth_reached",
    ):
        if type(status.get(key)) is not bool:
            raise ValueError("reservation RPC status %s is not boolean" % key)
    for key in (
        "tip",
        "confirmations",
        "required_confirmations",
        "sequence",
        "last_sequence",
        "sequence_history_count",
    ):
        if type(status.get(key)) is not int or status[key] < 0:
            raise ValueError("reservation RPC status %s is not an integer" % key)
    if (
        status.get("allocation_id") != allocation["consensus_allocation_id"]
        or status["sequence"] != int(allocation["consensus_allocation_id"], 16)
        or status["sequence_history_count"] != status["last_sequence"]
        or status["required_confirmations"] != FINALITY_DEPTH
    ):
        raise ValueError("reservation RPC policy identity differs")
    if status["found"] and status["retired"]:
        raise ValueError("reservation cannot be active and retired")
    expected_commitment = allocation_commitment(
        allocation["consensus_allocation_id"],
        allocation["veld_address"],
        allocation["amount_sats"],
        allocation["script_pubkey"],
        allocation["commitment_blind"],
    )
    if status["found"]:
        if (
            status.get("recipient") != allocation["veld_address"]
            or status.get("amount_sats") != allocation["amount_sats"]
            or status.get("allocation_commitment") != expected_commitment
            or type(status.get("created_height")) is not int
            or type(status.get("expires_height")) is not int
            or status["expires_height"] - status["created_height"] + 1 != LIFETIME_BLOCKS
        ):
            raise ValueError("canonical reservation differs from allocation")
        if status["exposed"]:
            for key in (
                "exposed_height",
                "funding_starts_height",
                "funding_expires_height",
                "funding_accepts_through_height",
                "recommended_send_cutoff_height",
                "exposure_confirmations",
            ):
                if type(status.get(key)) is not int or status[key] < 0:
                    raise ValueError("canonical exposure timing is malformed")
            if not (
                status["funding_starts_height"]
                <= status["recommended_send_cutoff_height"]
                < status["funding_accepts_through_height"]
                < status["funding_expires_height"]
            ):
                raise ValueError("canonical funding window is incoherent")
        if status["funded"]:
            if (
                not status["exposed"]
                or not isinstance(status.get("funding_outpoint"), str)
                or not OUTPOINT_RE.fullmatch(status["funding_outpoint"])
                or type(status.get("funded_height")) is not int
                or type(status.get("funding_confirmations")) is not int
            ):
                raise ValueError("canonical funding identity is malformed")
        elif status.get("funding_outpoint") is not None:
            raise ValueError("unfunded reservation carries an outpoint")
    return status


def validate_funding_parent(rpc, funding):
    status = rpc.call("getbtcveldmintstatus", [funding["outpoint"]])
    if (
        not isinstance(status, dict)
        or status.get("outpoint") != funding["outpoint"]
        or status.get("consumed") is not False
        or status.get("minted") is not False
        or status.get("proof_version") != "MNP1"
        or not isinstance(status.get("proof_hex"), str)
        or not HEX_RE.fullmatch(status["proof_hex"])
        or not isinstance(status.get("root"), str)
        or not HASH_RE.fullmatch(status["root"])
        or type(status.get("count")) is not int
        or status["count"] < 0
        or status["root"] != funding["proof_parent_root"]
        or status["count"] != funding["proof_parent_count"]
        or not funding["proof_hex"].endswith(status["proof_hex"])
    ):
        raise ValueError("CFP1 parent differs from the fresh mint-nullifier root")
    for name in (
        "accepted_txid",
        "accepted_block_height",
        "accepted_block_hash",
        "accepted_tx_index",
        "accepted_marker_vout",
        "accepted_effect_kind",
        "c1_allocation_id",
    ):
        if status.get(name) is not None:
            raise ValueError("unconsumed funding outpoint carries stale effect metadata")
    return status


def read_config():
    cfg = strict_json_loads(
        read_bounded_regular_file(
            os.path.abspath(CONFIG), 1024 * 1024, "C1 reservation coordinator config", private=True
        ),
        "C1 reservation coordinator config",
    )
    required = {
        "version",
        "state_file",
        "issuer",
        "veld_rpc",
        "reservation_signer_command",
        "checkpoint_command",
        "terminal_archive_command",
        "allow_initial_state_creation",
    }
    if not isinstance(cfg, dict) or set(cfg) != required or cfg.get("version") != 2:
        raise ValueError("coordinator config schema is not version 2")
    if (
        not isinstance(cfg["state_file"], str)
        or not os.path.isabs(cfg["state_file"])
        or type(cfg["allow_initial_state_creation"]) is not bool
        or not isinstance(cfg["issuer"], str)
        or not VELD_RE.fullmatch(cfg["issuer"])
    ):
        raise ValueError("coordinator state_file/issuer is malformed")
    cfg["reservation_signer_command"] = exact_argv(
        cfg["reservation_signer_command"], "reservation_signer_command"
    )
    cfg["checkpoint_command"] = exact_argv(cfg["checkpoint_command"], "checkpoint_command")
    cfg["terminal_archive_command"] = exact_argv(
        cfg["terminal_archive_command"], "terminal_archive_command"
    )
    return cfg


def load_state(path):
    if not os.path.lexists(path):
        raise FileNotFoundError(path)
    state = strict_json_loads(
        read_bounded_regular_file(path, STATE_MAX, "C1 coordinator state", private=True),
        "C1 coordinator state",
    )
    v3 = (
        isinstance(state, dict)
        and state.get("version") == 3
        and set(state) == {"version", "sequence", "records"}
    )
    v4 = (
        isinstance(state, dict)
        and state.get("version") == 4
        and set(state) == {"version", "sequence", "records", "compaction_cursor"}
    )
    if (
        not (v3 or v4)
        or not isinstance(state.get("records"), dict)
        or type(state.get("sequence")) is not int
        or not 0 <= state["sequence"] <= (1 << 63) - 1
        or len(state["records"]) > MAX_RECORDS
        or (
            v4
            and state["compaction_cursor"] is not None
            and (
                not isinstance(state["compaction_cursor"], str)
                or not ALLOCATION_ID_RE.fullmatch(state["compaction_cursor"])
            )
        )
    ):
        raise ValueError("C1 coordinator state schema is invalid")
    for allocation_id, record in state["records"].items():
        if (
            not isinstance(allocation_id, str)
            or not ALLOCATION_ID_RE.fullmatch(allocation_id)
            or int(allocation_id, 16) == 0
            or not isinstance(record, dict)
        ):
            raise ValueError("C1 coordinator record identity is invalid")
        if record.get("kind") == "terminal":
            if (
                set(record)
                != {
                    "kind",
                    "allocation_sha256",
                    "request_id",
                    "terminal_tip",
                    "record_sha256",
                    "archive_id",
                    "archived_at",
                }
                or not HASH_RE.fullmatch(str(record.get("allocation_sha256")))
                or not REQ_RE.fullmatch(str(record.get("request_id")))
                or type(record.get("terminal_tip")) is not int
                or record["terminal_tip"] < 0
                or not HASH_RE.fullmatch(str(record.get("record_sha256")))
                or not isinstance(record.get("archive_id"), str)
                or not 1 <= len(record["archive_id"]) <= 256
                or type(record.get("archived_at")) is not int
                or record["archived_at"] < 0
            ):
                raise ValueError("C1 coordinator tombstone is invalid")
            continue
        if (
            record.get("kind") != "active"
            or set(record)
            != {
                "kind",
                "allocation_sha256",
                "request_id",
                "terminal_observed_tip",
                "RESERVE",
                "EXPOSE",
                "CANCEL",
                "FUND",
            }
            or not HASH_RE.fullmatch(str(record["allocation_sha256"]))
            or not isinstance(record["request_id"], str)
            or not REQ_RE.fullmatch(record["request_id"])
            or (
                record["terminal_observed_tip"] is not None
                and (
                    type(record["terminal_observed_tip"]) is not int
                    or record["terminal_observed_tip"] < 0
                )
            )
            or not isinstance(record["FUND"], list)
            or len(record["FUND"]) > MAX_FUND_VARIANTS
        ):
            raise ValueError("C1 coordinator record is invalid")
        stages = [record[phase] for phase in ("RESERVE", "EXPOSE", "CANCEL")]
        stages.extend(record["FUND"])
        seen_funding = set()
        for stage in stages:
            if stage is None:
                continue
            base_stage_keys = {
                "unsigned_tx_hex",
                "unsigned_sha256",
                "signed_tx_hex",
                "txid",
                "broadcast_attempts",
                "last_broadcast_at",
                "funding_sha256",
                "semantic_sha256",
                "funding_outpoint",
                "created_at",
                "signer_archive_record_sha256",
                "signer_archive_id",
                "signer_receipt_sequence",
                "signer_receipt_state_sha256",
            }
            exclusion_keys = {"excluded_issuer_prevouts", "replacement_required"}
            if not isinstance(stage, dict) or set(stage) not in (
                base_stage_keys,
                base_stage_keys | exclusion_keys,
            ):
                raise ValueError("C1 coordinator stage is invalid")
            try:
                exclusions = validate_issuer_prevout_exclusions(
                    stage.get("excluded_issuer_prevouts", [])
                )
            except ValueError as exc:
                raise ValueError("C1 coordinator stage is invalid") from exc
            replacement_required = stage.get("replacement_required", False)
            if type(replacement_required) is not bool or (
                replacement_required
                and (
                    stage["signed_tx_hex"] is not None
                    or stage["txid"] is not None
                    or stage["signer_archive_record_sha256"] is not None
                )
            ):
                raise ValueError("C1 coordinator replacement state is invalid")
            if (
                not HEX_RE.fullmatch(str(stage["unsigned_tx_hex"]))
                or not HASH_RE.fullmatch(str(stage["unsigned_sha256"]))
                or hashlib.sha256(bytes.fromhex(stage["unsigned_tx_hex"])).hexdigest()
                != stage["unsigned_sha256"]
                or (
                    stage["signed_tx_hex"] is not None
                    and (
                        not HEX_RE.fullmatch(str(stage["signed_tx_hex"]))
                        or txid(stage["signed_tx_hex"]) != stage["txid"]
                    )
                )
                or (stage["signed_tx_hex"] is None and stage["txid"] is not None)
                or type(stage["broadcast_attempts"]) is not int
                or stage["broadcast_attempts"] < 0
                or (
                    stage["last_broadcast_at"] is not None
                    and type(stage["last_broadcast_at"]) is not int
                )
                or type(stage["created_at"]) is not int
                or stage["created_at"] < 0
                or (
                    (stage["signer_archive_record_sha256"] is None)
                    != (stage["signer_archive_id"] is None)
                )
                or (
                    (stage["signer_archive_record_sha256"] is None)
                    != (stage["signer_receipt_sequence"] is None)
                )
                or (
                    (stage["signer_archive_record_sha256"] is None)
                    != (stage["signer_receipt_state_sha256"] is None)
                )
                or (
                    stage["signer_archive_record_sha256"] is not None
                    and (
                        not HASH_RE.fullmatch(str(stage["signer_archive_record_sha256"]))
                        or not isinstance(stage["signer_archive_id"], str)
                        or not 1 <= len(stage["signer_archive_id"]) <= 256
                        or type(stage["signer_receipt_sequence"]) is not int
                        or stage["signer_receipt_sequence"] <= 0
                        or not HASH_RE.fullmatch(str(stage["signer_receipt_state_sha256"]))
                    )
                )
                or (
                    stage["funding_sha256"] is not None
                    and not HASH_RE.fullmatch(str(stage["funding_sha256"]))
                )
                or (
                    stage["semantic_sha256"] is not None
                    and not HASH_RE.fullmatch(str(stage["semantic_sha256"]))
                )
                or (
                    stage["funding_outpoint"] is not None
                    and not OUTPOINT_RE.fullmatch(str(stage["funding_outpoint"]))
                )
            ):
                raise ValueError("C1 coordinator stage is invalid")
            is_fund = stage in record["FUND"]
            if is_fund != (
                stage["funding_sha256"] is not None
                and stage["semantic_sha256"] is not None
                and stage["funding_outpoint"] is not None
            ):
                raise ValueError("C1 funding variant metadata is inconsistent")
            if is_fund:
                if stage["funding_sha256"] in seen_funding:
                    raise ValueError("duplicate C1 funding variant identity")
                seen_funding.add(stage["funding_sha256"])
    return state


def save_state(path, state):
    raw = (canonical(state) + "\n").encode("utf-8")
    if len(raw) > STATE_MAX:
        raise ValueError("C1 coordinator state exceeds the byte ceiling")
    directory = os.path.dirname(path)
    info = os.lstat(directory)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid not in (0, os.geteuid())
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise ValueError("C1 coordinator state directory is unsafe")
    fd, temporary = tempfile.mkstemp(
        prefix=os.path.basename(path) + ".", suffix=".tmp", dir=directory
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            fd = -1
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        temporary = None
        dfd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    return hashlib.sha256(raw).hexdigest()


def checkpoint_state(cfg, state, digest):
    request = canonical(
        {
            "version": 1,
            "action": "store_c1_coordinator_checkpoint",
            "sequence": state["sequence"],
            "state_sha256": digest,
            "record_count": len(state["records"]),
        }
    )
    completed = run_bounded_subprocess(
        list(cfg["checkpoint_command"]),
        input_text=request,
        timeout=45,
        stdout_max=64 * 1024,
        stderr_max=64 * 1024,
        description="C1 coordinator monotonic checkpoint",
    )
    if completed.returncode != 0:
        raise RuntimeError("C1 checkpoint refused/unavailable: " + completed.stderr.strip()[:240])
    answer = strict_json_loads(completed.stdout, "C1 checkpoint response")
    if (
        not isinstance(answer, dict)
        or set(answer) != {"version", "stored", "sequence", "state_sha256"}
        or answer.get("version") != 1
        or answer.get("stored") is not True
        or answer.get("sequence") != state["sequence"]
        or answer.get("state_sha256") != digest
    ):
        raise RuntimeError("C1 checkpoint acknowledgement is not exact")


def persist(cfg, state):
    if state["sequence"] >= (1 << 63) - 1:
        raise ValueError("C1 coordinator sequence exhausted")
    candidate = copy.deepcopy(state)
    candidate["sequence"] += 1
    digest = save_state(cfg["state_file"], candidate)
    checkpoint_state(cfg, candidate, digest)
    state["sequence"] = candidate["sequence"]
    return digest


def projected_state_size(state, *, increment_sequence=True):
    candidate = copy.deepcopy(state)
    if increment_sequence:
        if candidate["sequence"] >= (1 << 63) - 1:
            raise ValueError("C1 coordinator sequence exhausted")
        candidate["sequence"] += 1
    return len((canonical(candidate) + "\n").encode("utf-8"))


def require_lifecycle_admission_capacity(state, reserve_bytes=0):
    if (
        type(reserve_bytes) is not int
        or reserve_bytes < 0
        or projected_state_size(state) + reserve_bytes > STATE_ADMISSION_MAX
    ):
        raise ValueError("C1 coordinator lifecycle admission reserve is exhausted")


def bind_or_admit_record(cfg, state, allocation, status):
    allocation_id = allocation["consensus_allocation_id"]
    allocation_hash = hashlib.sha256(canonical(allocation).encode("utf-8")).hexdigest()
    record = state["records"].get(allocation_id)
    if record is None:
        if status["retired"]:
            return None
        if status["found"]:
            raise ValueError("active C1 reservation is missing durable coordinator state")
        if len(state["records"]) >= MAX_RECORDS:
            raise ValueError("coordinator record ceiling reached")
        record = {
            "kind": "active",
            "allocation_sha256": allocation_hash,
            "request_id": allocation["request_id"],
            "terminal_observed_tip": None,
            "RESERVE": None,
            "EXPOSE": None,
            "CANCEL": None,
            "FUND": [],
        }
        candidate = copy.deepcopy(state)
        candidate["records"][allocation_id] = copy.deepcopy(record)
        require_lifecycle_admission_capacity(candidate, 2 * MAX_CARRIER_BYTES + 2048)
        state["records"][allocation_id] = record
        try:
            persist(cfg, state)
        except Exception:
            state["records"].pop(allocation_id, None)
            raise
    elif (
        record["allocation_sha256"] != allocation_hash
        or record["request_id"] != allocation["request_id"]
    ):
        raise ValueError("consensus allocation id is already bound differently")
    if any(
        other_id != allocation_id and other["request_id"] == allocation["request_id"]
        for other_id, other in state["records"].items()
    ):
        raise ValueError("private request id is already bound to another sequence")
    return record


def load_or_initialize_state(cfg):
    """Load normal runtime state; a live allocation can never initialize it."""
    state_exists = os.path.lexists(cfg["state_file"])
    if not state_exists:
        raise ValueError(
            "C1 coordinator state is missing; run the explicit local --initialize ceremony"
        )
    if cfg["allow_initial_state_creation"]:
        raise ValueError("allow_initial_state_creation must be false after initialization")
    state = load_state(cfg["state_file"])
    checkpoint_state(
        cfg, state, hashlib.sha256((canonical(state) + "\n").encode("utf-8")).hexdigest()
    )
    if state["version"] == 3:
        # First checkpoint the exact legacy bytes/sequence, then advance the
        # external monotonic authority while adding the fair reaper cursor.
        # This avoids presenting a same-sequence migration fork.
        state["version"] = 4
        state["compaction_cursor"] = None
        persist(cfg, state)
    legacy_terminals = [
        allocation_id
        for allocation_id, record in state["records"].items()
        if record.get("kind") == "terminal"
    ]
    if legacy_terminals:
        for allocation_id in legacy_terminals:
            del state["records"][allocation_id]
        persist(cfg, state)
    return state


def initialize_state(cfg):
    if cfg.get("allow_initial_state_creation") is not True:
        raise ValueError("--initialize requires allow_initial_state_creation=true")
    if os.path.lexists(cfg["state_file"]):
        raise ValueError("C1 coordinator state already exists; refusing replacement")
    state = {"version": 4, "sequence": 0, "records": {}, "compaction_cursor": None}
    persist(cfg, state)
    return state


def acquire_state_lock(cfg):
    lock_path = cfg["state_file"] + ".lock"
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    lock_info = os.fstat(lock_fd)
    if (
        not stat.S_ISREG(lock_info.st_mode)
        or lock_info.st_nlink != 1
        or lock_info.st_uid not in (0, os.geteuid())
        or stat.S_IMODE(lock_info.st_mode) & 0o022
    ):
        os.close(lock_fd)
        raise ValueError("C1 coordinator lock file is unsafe")
    os.fchmod(lock_fd, 0o600)
    lock = os.fdopen(lock_fd, "a+")
    fcntl.flock(lock, fcntl.LOCK_EX)
    return lock


def initialize_main():
    try:
        cfg = read_config()
        lock = acquire_state_lock(cfg)
        initialize_state(cfg)
        sys.stdout.write(
            canonical(
                {
                    "version": 1,
                    "initialized": True,
                    "instruction": "set allow_initial_state_creation=false before runtime",
                }
            )
            + "\n"
        )
        lock.close()
    except Exception as exc:
        fail(exc)


def _funding_sha256(funding):
    return hashlib.sha256(canonical(funding).encode("utf-8")).hexdigest()


def _funding_semantic_sha256(allocation, funding):
    semantic = {
        "allocation_id": allocation["consensus_allocation_id"],
        "recipient": allocation["veld_address"],
        "amount_sats": allocation["amount_sats"],
        "script_pubkey": allocation["script_pubkey"],
        "commitment_blind": allocation["commitment_blind"],
        "outpoint": funding["outpoint"],
    }
    return hashlib.sha256(canonical(semantic).encode("utf-8")).hexdigest()


def _fund_variant(record, funding):
    digest = _funding_sha256(funding)
    return next((stage for stage in record["FUND"] if stage["funding_sha256"] == digest), None)


def acknowledge_signer_durable(cfg, allocation, phase, stage, state, state_digest):
    request = {
        "version": 1,
        "action": "ack_c1_signature_durable",
        "allocation_id": allocation["consensus_allocation_id"],
        "phase": phase,
        "funding_sha256": stage["funding_sha256"],
        "allocation_sha256": hashlib.sha256(canonical(allocation).encode("utf-8")).hexdigest(),
        "unsigned_sha256": stage["unsigned_sha256"],
        "signed_tx_sha256": hashlib.sha256(bytes.fromhex(stage["signed_tx_hex"])).hexdigest(),
        "txid": stage["txid"],
        "coordinator_sequence": state["sequence"],
        "coordinator_state_sha256": state_digest,
    }
    completed = run_bounded_subprocess(
        list(cfg["reservation_signer_command"]),
        input_text=canonical(request),
        timeout=120,
        stdout_max=64 * 1024,
        stderr_max=64 * 1024,
        description="isolated C1 signer durable receipt",
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "isolated C1 signer durable receipt refused: " + completed.stderr.strip()[:240]
        )
    answer = strict_json_loads(completed.stdout, "isolated C1 signer durable response")
    expected = {
        "version",
        "action",
        "allocation_id",
        "phase",
        "funding_sha256",
        "record_sha256",
        "archive_id",
        "idempotent",
    }
    if (
        not isinstance(answer, dict)
        or set(answer) != expected
        or answer.get("version") != 1
        or answer.get("action") != "c1_signature_durable"
        or answer.get("allocation_id") != allocation["consensus_allocation_id"]
        or answer.get("phase") != phase
        or answer.get("funding_sha256") != stage["funding_sha256"]
        or not HASH_RE.fullmatch(str(answer.get("record_sha256")))
        or not isinstance(answer.get("archive_id"), str)
        or not 1 <= len(answer["archive_id"]) <= 256
        or type(answer.get("idempotent")) is not bool
    ):
        raise RuntimeError("isolated C1 signer durable response is not exact")
    return answer


def prepare_stage(rpc, cfg, allocation, phase, record, state, funding=None):
    if phase == "FUND":
        if funding is None:
            raise ValueError("FUND requires an exact CFP1 funding object")
        stage = _fund_variant(record, funding)
    else:
        if funding is not None:
            raise ValueError("non-FUND stage cannot carry a funding object")
        stage = record[phase]
    replacing = stage is not None and stage.get("replacement_required", False) is True
    if stage is None or replacing:
        exclusions = validate_issuer_prevout_exclusions(
            stage.get("excluded_issuer_prevouts", []) if replacing else []
        )
        params = [
            cfg["issuer"],
            allocation["veld_address"],
            str(allocation["amount_sats"]),
            allocation["consensus_allocation_id"],
            allocation_commitment(
                allocation["consensus_allocation_id"],
                allocation["veld_address"],
                allocation["amount_sats"],
                allocation["script_pubkey"],
                allocation["commitment_blind"],
            ),
            phase,
        ]
        if phase == "FUND":
            params.extend(
                [
                    allocation["script_pubkey"],
                    allocation["commitment_blind"],
                    funding["outpoint"],
                    funding["proof_hex"],
                ]
            )
        suffix = issuer_prevout_exclusion_suffix(exclusions, force=replacing)
        if suffix is not None:
            params.append(suffix)
        prepared = rpc.call("preparebtcveldc1reservation", params)
        if (
            not isinstance(prepared, dict)
            or prepared.get("allocation_id") != allocation["consensus_allocation_id"]
            or prepared.get("action") != phase
            or prepared.get("recipient") != allocation["veld_address"]
            or prepared.get("amount_sats") != allocation["amount_sats"]
            or prepared.get("allocation_commitment")
            != allocation_commitment(
                allocation["consensus_allocation_id"],
                allocation["veld_address"],
                allocation["amount_sats"],
                allocation["script_pubkey"],
                allocation["commitment_blind"],
            )
            or prepared.get("required_confirmations") != FINALITY_DEPTH
            or prepared.get("lifetime_blocks") != LIFETIME_BLOCKS
            or prepared.get("fee") != 100_000
            or prepared.get("excluded_issuer_prevouts") != exclusions
            or not isinstance(prepared.get("unsigned_tx_hex"), str)
            or not HEX_RE.fullmatch(prepared["unsigned_tx_hex"])
            or len(prepared["unsigned_tx_hex"]) > 2 * MAX_CARRIER_BYTES
        ):
            raise ValueError("prepared C1 %s carrier is not exact" % phase)
        unsigned = prepared["unsigned_tx_hex"]
        if set(exclusions).intersection(unsigned_input_outpoints(unsigned)):
            raise ValueError("prepared C1 carrier reused an excluded issuer prevout")
        replacement = {
            "unsigned_tx_hex": unsigned,
            "unsigned_sha256": hashlib.sha256(bytes.fromhex(unsigned)).hexdigest(),
            "signed_tx_hex": None,
            "txid": None,
            "broadcast_attempts": 0,
            "last_broadcast_at": None,
            "funding_sha256": (_funding_sha256(funding) if funding is not None else None),
            "semantic_sha256": (
                _funding_semantic_sha256(allocation, funding) if funding is not None else None
            ),
            "funding_outpoint": (funding["outpoint"] if funding is not None else None),
            "created_at": (stage["created_at"] if replacing else int(time.time())),
            "signer_archive_record_sha256": None,
            "signer_archive_id": None,
            "signer_receipt_sequence": None,
            "signer_receipt_state_sha256": None,
            "excluded_issuer_prevouts": exclusions,
            "replacement_required": False,
        }
        if replacing:
            previous = dict(stage)
            stage.clear()
            stage.update(replacement)
            try:
                persist(cfg, state)
            except Exception:
                stage.clear()
                stage.update(previous)
                raise
        elif phase == "FUND":
            if len(record["FUND"]) >= MAX_FUND_VARIANTS:
                raise ValueError(
                    "bounded C1F1 variant ceiling reached; manual reconciliation required"
                )
            if record["FUND"] and any(
                prior["semantic_sha256"] != replacement["semantic_sha256"]
                for prior in record["FUND"]
            ):
                raise ValueError("C1F1 semantic identity changed across retries")
            stage = replacement
            record["FUND"].append(stage)
        elif not replacing:
            stage = replacement
            record[phase] = stage
        if not replacing:
            try:
                if phase == "RESERVE":
                    require_lifecycle_admission_capacity(state)
                persist(cfg, state)
            except Exception:
                if phase == "FUND":
                    record["FUND"].remove(stage)
                else:
                    record[phase] = None
                raise
    if stage["signed_tx_hex"] is None:
        request = {
            "version": 2,
            "action": "sign_c1_reservation",
            "phase": phase,
            "allocation": allocation,
            "funding": funding,
            "unsigned_tx_hex": stage["unsigned_tx_hex"],
        }
        signed = run_bounded_subprocess(
            list(cfg["reservation_signer_command"]),
            input_text=canonical(request),
            timeout=90,
            stdout_max=8 * 1024 * 1024,
            stderr_max=1024 * 1024,
            description="isolated C1 reservation signer",
        )
        if signed.returncode == 75:
            answer = strict_json_loads(signed.stdout, "isolated C1 unsigned abandonment")
            owner_id = (
                "c1:"
                + allocation["consensus_allocation_id"]
                + ":"
                + phase
                + ((":" + stage["funding_sha256"]) if phase == "FUND" else "")
            )
            expected = {
                "version",
                "action",
                "capability",
                "owner_id",
                "allocation_id",
                "deposit_outpoint",
                "unsigned_sha256",
                "conflicting_input_outpoints",
                "reason",
            }
            if not isinstance(answer, dict):
                raise RuntimeError("isolated C1 signer abandonment is not exact")
            try:
                conflicts = validate_issuer_prevout_exclusions(
                    answer.get("conflicting_input_outpoints"),
                    candidate_inputs=unsigned_input_outpoints(stage["unsigned_tx_hex"]),
                )
            except (TypeError, ValueError) as exc:
                raise RuntimeError("isolated C1 signer abandonment is not exact") from exc
            if (
                set(answer) != expected
                or answer.get("version") != 1
                or answer.get("action") != "unsigned_carrier_abandoned"
                or answer.get("capability") != "c1-reservation"
                or answer.get("owner_id") != owner_id
                or answer.get("allocation_id") != allocation["consensus_allocation_id"]
                or answer.get("deposit_outpoint") is not None
                or answer.get("unsigned_sha256") != stage["unsigned_sha256"]
                or answer.get("reason") != "issuer_prevout_conflict"
            ):
                raise RuntimeError("isolated C1 signer abandonment is not exact")
            # The signer fsynced both the never-sign hash and its exact leased
            # input intersection. Preserve that authority before asking Core
            # for a replacement which excludes those inputs. A migrated legacy
            # revocation may carry an empty intersection; the forced suffix is
            # still sent so the replacement transition remains explicit.
            prior = dict(stage)
            exclusions = sorted(set(stage.get("excluded_issuer_prevouts", []) + conflicts))
            if len(exclusions) > MAX_ISSUER_PREVOUT_EXCLUSIONS:
                raise RuntimeError("issuer prevout exclusion ceiling requires operator review")
            stage["excluded_issuer_prevouts"] = exclusions
            stage["replacement_required"] = True
            try:
                persist(cfg, state)
            except Exception:
                stage.clear()
                stage.update(prior)
                raise
            raise RuntimeError(
                "isolated signer durably revoked a conflicting unsigned carrier; "
                "fresh preparation required"
            )
        if signed.returncode != 0:
            raise RuntimeError("isolated C1 signer refused: " + signed.stderr.strip()[:240])
        answer = strict_json_loads(signed.stdout, "isolated C1 signer response")
        expected = {
            "version",
            "action",
            "phase",
            "request_id",
            "allocation_id",
            "signed_tx_hex",
            "txid",
        }
        if (
            not isinstance(answer, dict)
            or set(answer) != expected
            or answer.get("version") != 2
            or answer.get("action") != "signed_c1_reservation"
            or answer.get("phase") != phase
            or answer.get("request_id") != allocation["request_id"]
            or answer.get("allocation_id") != allocation["consensus_allocation_id"]
            or not isinstance(answer.get("signed_tx_hex"), str)
            or not HEX_RE.fullmatch(answer["signed_tx_hex"])
            or len(answer["signed_tx_hex"]) > 2 * MAX_CARRIER_BYTES
            or txid(answer["signed_tx_hex"]) != answer.get("txid")
        ):
            raise ValueError("isolated C1 signer acknowledgement is not exact")
        try:
            reconstructed = solvency.unsigned_template_from_signed_hex(answer["signed_tx_hex"])
        except Exception as exc:
            raise ValueError("isolated C1 signature is not decodable") from exc
        if reconstructed != stage["unsigned_tx_hex"]:
            raise ValueError("isolated C1 signature does not bind the stored unsigned carrier")
        stage["signed_tx_hex"] = answer["signed_tx_hex"]
        stage["txid"] = answer["txid"]
        try:
            state_digest = persist(cfg, state)
        except Exception:
            stage["signed_tx_hex"] = None
            stage["txid"] = None
            raise
    else:
        state_digest = hashlib.sha256((canonical(state) + "\n").encode("utf-8")).hexdigest()
    if stage["signer_archive_record_sha256"] is None:
        receipt_sequence = state["sequence"]
        receipt_state_sha256 = state_digest
        durable = acknowledge_signer_durable(cfg, allocation, phase, stage, state, state_digest)
        stage["signer_archive_record_sha256"] = durable["record_sha256"]
        stage["signer_archive_id"] = durable["archive_id"]
        stage["signer_receipt_sequence"] = receipt_sequence
        stage["signer_receipt_state_sha256"] = receipt_state_sha256
        try:
            persist(cfg, state)
        except Exception:
            stage["signer_archive_record_sha256"] = None
            stage["signer_archive_id"] = None
            stage["signer_receipt_sequence"] = None
            stage["signer_receipt_state_sha256"] = None
            raise
    return stage


def in_mempool(rpc, stage):
    if not stage.get("txid"):
        return False
    try:
        entry = rpc.call("getmempoolentry", [stage["txid"]])
        return isinstance(entry, dict)
    except Exception:
        return False


def mint_lifecycle_live(rpc):
    peg = rpc.call("getpeginfo", [])
    return (
        isinstance(peg, dict)
        and peg.get("active") is True
        and peg.get("peg_unlocked") is True
        and peg.get("mint_live") is True
    )


def completion_lifecycle_live(rpc):
    peg = rpc.call("getpeginfo", [])
    return (
        isinstance(peg, dict)
        and peg.get("active") is True
        and peg.get("peg_unlocked") is True
        and peg.get("completion_live") is True
    )


def rebroadcast_cached_exposure_if_live(rpc, cfg, state, stage):
    if stage is None or not stage.get("signed_tx_hex") or not mint_lifecycle_live(rpc):
        return False
    return broadcast_exact(rpc, cfg, state, stage)


def broadcast_exact(rpc, cfg, state, stage):
    old_attempts = stage["broadcast_attempts"]
    old_last = stage["last_broadcast_at"]
    stage["broadcast_attempts"] += 1
    stage["last_broadcast_at"] = int(time.time())
    try:
        persist(cfg, state)
    except Exception:
        stage["broadcast_attempts"] = old_attempts
        stage["last_broadcast_at"] = old_last
        raise
    try:
        returned = rpc.call("sendrawtransaction", [stage["signed_tx_hex"]])
    except Exception:
        # A timeout, already-known response, or lost reply is not authority to
        # create different signed bytes.  The next invocation first samples the
        # canonical effect and otherwise rebroadcasts this exact carrier.
        return False
    if returned != stage["txid"]:
        raise ValueError("broadcast returned a different transaction id")
    return True


def compact_terminal(rpc, cfg, state, allocation_id, record, status, allow_archive=True):
    """WORM-archive a >100-block-stable terminal before dropping carrier bytes."""
    tip = status.get("tip")
    if type(tip) is not int or tip < 0:
        raise ValueError("terminal C1 status tip is malformed")
    observed = record.get("terminal_observed_tip")
    if observed is None or tip < observed:
        prior_observed = observed
        record["terminal_observed_tip"] = tip
        try:
            persist(cfg, state)
        except Exception:
            record["terminal_observed_tip"] = prior_observed
            raise
        return False

    deep_terminal = tip - observed + 1 > 100
    funded_outpoints = {stage["funding_outpoint"] for stage in record["FUND"]}
    for outpoint in funded_outpoints:
        mint_status = rpc.call("getbtcveldmintstatus", [outpoint])
        if not isinstance(mint_status, dict):
            raise ValueError("terminal C1 mint status is malformed")
        if mint_status.get("consumed") is True:
            if (
                mint_status.get("minted") is not True
                or mint_status.get("accepted_effect_kind") != "C1_MINT"
                or mint_status.get("c1_allocation_id") != allocation_id
                or type(mint_status.get("credit_block_height")) is not int
                or mint_status["credit_block_height"] > tip
                or tip - mint_status["credit_block_height"] + 1 <= 100
            ):
                return False
            deep_terminal = True
        elif mint_status.get("minted") is True:
            raise ValueError("unconsumed terminal outpoint reports a mint credit")
    if not deep_terminal:
        return False
    if not allow_archive:
        return False

    record_sha256 = hashlib.sha256(canonical(record).encode("utf-8")).hexdigest()
    archived_at = int(time.time())
    archive_request = canonical(
        {
            "version": 1,
            "action": "archive_c1_terminal",
            "allocation_id": allocation_id,
            "terminal_tip": tip,
            "archived_at": archived_at,
            "record_sha256": record_sha256,
            "record": record,
        }
    )
    completed = run_bounded_subprocess(
        list(cfg["terminal_archive_command"]),
        input_text=archive_request,
        timeout=120,
        stdout_max=64 * 1024,
        stderr_max=64 * 1024,
        description="C1 terminal WORM archive",
    )
    if completed.returncode != 0:
        raise RuntimeError("C1 terminal archive refused: " + completed.stderr.strip()[:240])
    acknowledgement = strict_json_loads(completed.stdout, "C1 terminal archive acknowledgement")
    if (
        not isinstance(acknowledgement, dict)
        or set(acknowledgement)
        != {
            "version",
            "archived",
            "allocation_id",
            "record_sha256",
            "readback_sha256",
            "archive_id",
            "object_lock_mode",
            "retention_until",
        }
        or acknowledgement.get("version") != 1
        or acknowledgement.get("archived") is not True
        or acknowledgement.get("allocation_id") != allocation_id
        or acknowledgement.get("record_sha256") != record_sha256
        or acknowledgement.get("readback_sha256") != record_sha256
        or acknowledgement.get("object_lock_mode") != "COMPLIANCE"
        or type(acknowledgement.get("retention_until")) is not int
        or acknowledgement["retention_until"] < archived_at + ARCHIVE_RETENTION_SECONDS
        or not isinstance(acknowledgement.get("archive_id"), str)
        or not 1 <= len(acknowledgement["archive_id"]) <= 256
    ):
        raise RuntimeError("C1 terminal archive acknowledgement is not exact")

    # Only an exact external acknowledgement authorizes removal of the large
    # randomized signatures and CFP1 variants. Consensus rejects every retired
    # sequence for life, and main() samples that authority before admission, so
    # retaining one local tombstone per historical allocation would only turn a
    # signed descriptor-range expansion into a deterministic disk ceiling.
    del state["records"][allocation_id]
    try:
        persist(cfg, state)
    except Exception:
        state["records"][allocation_id] = record
        raise
    return True


def maintenance_status(rpc, allocation_id):
    status = rpc.call("getbtcveldc1reservation", [allocation_id])
    if (
        not isinstance(status, dict)
        or status.get("allocation_id") != allocation_id
        or type(status.get("retired")) is not bool
        or type(status.get("tip")) is not int
        or status["tip"] < 0
    ):
        raise ValueError("C1 maintenance status is malformed")
    return status


def maintain_terminal_records(rpc, cfg, state, scan_limit=8, archive_limit=1):
    """Bounded fair reaper independent of per-allocation client retries."""
    if (
        type(scan_limit) is not int
        or not 1 <= scan_limit <= 256
        or type(archive_limit) is not int
        or not 0 <= archive_limit <= scan_limit
    ):
        raise ValueError("C1 maintenance limits are invalid")
    allocation_ids = sorted(state["records"])
    if not allocation_ids:
        if state["compaction_cursor"] is not None:
            prior = state["compaction_cursor"]
            state["compaction_cursor"] = None
            try:
                persist(cfg, state)
            except Exception:
                state["compaction_cursor"] = prior
                raise
        return {"scanned": 0, "compacted": 0}
    cursor = state["compaction_cursor"]
    start = 0
    if cursor is not None:
        while start < len(allocation_ids) and allocation_ids[start] <= cursor:
            start += 1
        if start == len(allocation_ids):
            start = 0
    selected = [
        allocation_ids[(start + offset) % len(allocation_ids)]
        for offset in range(min(scan_limit, len(allocation_ids)))
    ]
    # Advance before remote lookups. A timeout can delay one row for a cycle but
    # cannot pin the cursor forever or starve every later terminal allocation.
    prior_cursor = state["compaction_cursor"]
    state["compaction_cursor"] = selected[-1]
    try:
        persist(cfg, state)
    except Exception:
        state["compaction_cursor"] = prior_cursor
        raise
    compacted = 0
    for allocation_id in selected:
        record = state["records"].get(allocation_id)
        if record is None:
            continue
        status = maintenance_status(rpc, allocation_id)
        if status["retired"]:
            if compact_terminal(
                rpc,
                cfg,
                state,
                allocation_id,
                record,
                status,
                allow_archive=(compacted < archive_limit),
            ):
                compacted += 1
        else:
            clear_terminal_observation(cfg, state, record)
    return {"scanned": len(selected), "compacted": compacted}


def clear_terminal_observation(cfg, state, record):
    observed = record.get("terminal_observed_tip")
    if observed is None:
        return False
    record["terminal_observed_tip"] = None
    try:
        persist(cfg, state)
    except Exception:
        record["terminal_observed_tip"] = observed
        raise
    return True


def emit(status, code):
    public = {
        "version": 3,
        "allocation_id": status["allocation_id"],
        "found": status["found"],
        "active": status["active"],
        "retired": status["retired"],
        "last_sequence": status["last_sequence"],
        "exposed": status["exposed"],
        "funded": status["funded"],
        "funding_outpoint": status.get("funding_outpoint"),
        "confirmations": status["confirmations"],
        "required_confirmations": FINALITY_DEPTH,
        "canonical_depth_reached": status["canonical_depth_reached"],
    }
    sys.stdout.write(canonical(public) + "\n")
    raise SystemExit(code)


def main():
    try:
        raw = getattr(sys.stdin, "buffer", sys.stdin).read(REQUEST_MAX + 1)
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        if len(raw) > REQUEST_MAX:
            raise ValueError("request exceeds byte limit")
        request = strict_json_loads(raw, "C1 coordinator request")
        if (
            not isinstance(request, dict)
            or set(request) != {"version", "action", "allocation", "funding"}
            or request.get("version") != 2
            or request.get("action") != "ensure_c1_lifecycle"
        ):
            raise ValueError("coordinator request schema is not canonical")
        allocation = validate_allocation(request["allocation"])
        funding = validate_funding(request["funding"])
        cfg = read_config()
        rpc = Rpc(cfg["veld_rpc"])
        lock = acquire_state_lock(cfg)
        # Idempotent checkpoint storage lets the external monotonic authority
        # heal a crash after local fsync but before its prior acknowledgement,
        # while refusing a lower sequence or same-sequence fork.
        state = load_or_initialize_state(cfg)
        maintain_terminal_records(rpc, cfg, state)
        allocation_id = allocation["consensus_allocation_id"]
        status = validate_status(rpc.call("getbtcveldc1reservation", [allocation_id]), allocation)
        record = bind_or_admit_record(cfg, state, allocation, status)
        if record is None:
            # Terminal carrier bytes have already been placed in the exact
            # external archive. Canonical consensus is the lifetime replay
            # authority; do not recreate one local row per historic id.
            emit(status, 75)

        if record["kind"] == "terminal":
            if not status["retired"]:
                raise ValueError("archived terminal sequence reappeared; deep-reorg incident")
            # One-way migration of pre-compaction candidate state. Its exact
            # archive id/digest is already stored externally.
            del state["records"][allocation_id]
            persist(cfg, state)
            emit(status, 75)
        # A retired sequence was either cancelled or consumed by MNP2. The
        # independent allocation witness distinguishes terminal mint from an
        # unfunded cancellation; never replay any cached carrier for it.
        if status["retired"]:
            compact_terminal(rpc, cfg, state, allocation_id, record, status)
            emit(status, 75)
        clear_terminal_observation(cfg, state, record)
        if status["funded"]:
            if funding is not None and status["funding_outpoint"] != funding["outpoint"]:
                raise ValueError("C1 reservation was funded by another outpoint")
            if funding is None or status["funding_outpoint"] == funding["outpoint"]:
                emit(status, 0)

        if status["exposed"]:
            exposed_ready = (
                status["active"]
                and status["exposure_canonical_depth_reached"]
                and status["exposure_confirmations"] >= FINALITY_DEPTH
            )
            if not exposed_ready:
                rebroadcast_cached_exposure_if_live(rpc, cfg, state, record["EXPOSE"])
                emit(status, 75)

            if funding is None:
                # An exposed consensus record does not itself authorize the
                # private address reveal during a later finality stall.
                if not mint_lifecycle_live(rpc):
                    emit(status, 75)
                emit(status, 0)

            # Owner-approved completion exception: only exact C1F1 for the
            # already-exposed lifecycle may progress while mint_live is false.
            if not completion_lifecycle_live(rpc):
                emit(status, 75)

            target_height = status["tip"] + 1
            if (
                target_height < status["funding_starts_height"]
                or target_height > status["funding_accepts_through_height"]
            ):
                emit(status, 75)
            validate_funding_parent(rpc, funding)
            funding_digest = _funding_sha256(funding)
            for prior in record["FUND"]:
                if (
                    prior["funding_sha256"] != funding_digest
                    and prior["signed_tx_hex"]
                    and in_mempool(rpc, prior)
                ):
                    # Do not manufacture a competing randomized signature while
                    # an older root child is still accepted by this node.
                    broadcast_exact(rpc, cfg, state, prior)
                    emit(status, 75)
            stage = prepare_stage(rpc, cfg, allocation, "FUND", record, state, funding=funding)
            # Re-sample the root after preparation/signing; a concurrent child
            # makes this exact F stale and requires a new caller-supplied proof.
            validate_funding_parent(rpc, funding)
            broadcast_exact(rpc, cfg, state, stage)
            emit(status, 75)

        # The local timeout is valid only before C1E1.  Once it has elapsed the
        # coordinator will neither create nor sign an exposure, so wrapd may
        # retire the undisclosed intent.  An existing C1R1 then expires by its
        # deterministic block-height lease.
        if int(time.time()) >= allocation["expires_at"]:
            if not status["found"]:
                if not completion_lifecycle_live(rpc):
                    emit(status, 75)
                stage = prepare_stage(rpc, cfg, allocation, "CANCEL", record, state)
                broadcast_exact(rpc, cfg, state, stage)
            emit(status, 75)

        if not status["found"]:
            if not mint_lifecycle_live(rpc):
                emit(status, 75)
            stage = prepare_stage(rpc, cfg, allocation, "RESERVE", record, state)
            broadcast_exact(rpc, cfg, state, stage)
            emit(status, 75)

        if (
            not status["active"]
            or status["confirmations"] < FINALITY_DEPTH
            or not status["canonical_depth_reached"]
        ):
            if (
                record["RESERVE"] is not None
                and record["RESERVE"]["signed_tx_hex"]
                and mint_lifecycle_live(rpc)
            ):
                broadcast_exact(rpc, cfg, state, record["RESERVE"])
            emit(status, 75)

        if not mint_lifecycle_live(rpc):
            emit(status, 75)
        stage = prepare_stage(rpc, cfg, allocation, "EXPOSE", record, state)
        broadcast_exact(rpc, cfg, state, stage)
        emit(status, 75)
    except SystemExit:
        raise
    except Exception as exc:
        fail(exc)


def maintenance_main():
    try:
        cfg = read_config()
        rpc = Rpc(cfg["veld_rpc"])
        lock = acquire_state_lock(cfg)
        state = load_or_initialize_state(cfg)
        result = maintain_terminal_records(rpc, cfg, state, scan_limit=32, archive_limit=1)
        sys.stdout.write(
            canonical(
                {
                    "version": 1,
                    "maintained": True,
                    "scanned": result["scanned"],
                    "compacted": result["compacted"],
                    "remaining_records": len(state["records"]),
                }
            )
            + "\n"
        )
        lock.close()
    except Exception as exc:
        fail(exc)


if __name__ == "__main__":
    if sys.argv[1:] == ["--initialize"]:
        initialize_main()
    elif sys.argv[1:] == ["--maintain"]:
        maintenance_main()
    elif sys.argv[1:]:
        fail("usage: veld_c1_reservationd.py [--initialize|--maintain]")
    else:
        main()
