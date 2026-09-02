#!/usr/bin/env python3
"""Parent process for the Finding-4 real-entrypoint matrix.

Each row gets a new operating-system process and a new artifact/datadir root.
The child itself owns the real VeldNode/RpcServer/NodeServer/FinalityDaemon
objects; this parent only checks exit status, the sealed JSON counters, and
the absence/presence of durable artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


MATRIX_ROWS = [
    "default_unknown",
    "node_running",
    "startup_replay",
    "independent_validation",
    "sync_ibd",
    "snapshot_clean",
    "durable_state",
    "datadir_identity",
    "checkpoint_anchor",
    "tip_known",
    "runtime",
    "peer_view",
    "peer_version_loss",
    "peer_version_expiry",
    "role_profile",
    "open",
]

RACE_ROWS = [
    "race_submit_close_first",
    "race_submit_acquired_first",
    "race_finality_close_first",
    "race_finality_acquired_first",
]

ROWS = MATRIX_ROWS + RACE_ROWS

STARTUP_LISTENER_ROWS = {
    "default_unknown", "node_running", "startup_replay", "datadir_identity"
}

ZERO_EFFECT_KEYS = [
    "internal_mining_admitted",
    "internal_hashes",
    "internal_progress",
    "gbt_templates",
    "submit_add_calls",
    "submit_durable_calls",
    "block_broadcasts",
    "inproc_journals",
    "inproc_signatures",
    "inproc_mempool",
    "inproc_gossip",
    "standalone_journals",
    "standalone_signatures",
    "standalone_mempool",
    "standalone_gossip",
    "finality_journals",
    "finality_signatures",
    "finality_gossip",
    "finality_sink_calls",
    "finality_active_calls",
    "finality_assembler",
    "finality_node_gossip",
    "cached_templates",
    "pending_tokens",
    "active_leases",
    "pending_broadcasts",
]

OPEN_EXACT_ONE = [
    "gbt_templates",
    "submit_add_calls",
    "submit_durable_calls",
    "block_broadcasts",
    "inproc_journals",
    "inproc_signatures",
    "inproc_mempool",
    "inproc_gossip",
    "standalone_journals",
    "standalone_signatures",
    "standalone_mempool",
    "standalone_gossip",
    "finality_journals",
    "finality_signatures",
    "finality_gossip",
    "finality_sink_calls",
    "finality_active_calls",
    "finality_assembler",
    "finality_node_gossip",
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fail(message: str) -> None:
    raise RuntimeError(message)


def source_assertions(root: Path) -> dict[str, bool]:
    constants = (root / "include/core/constants.h").read_text(
        encoding="utf-8"
    )
    node = (root / "include/node/node.h").read_text(encoding="utf-8")
    blockchain = (root / "include/core/blockchain.h").read_text(
        encoding="utf-8"
    )
    tcp = (root / "include/network/tcp.h").read_text(encoding="utf-8")
    fixture = (
        root / "tests/daybreak_work_admission_process_fixture.cpp"
    ).read_text(encoding="utf-8")
    runtime = (
        root / "include/network/public_testnet_runtime.h"
    ).read_text(encoding="utf-8")
    node_main = (root / "src/veld-node.cpp").read_text(encoding="utf-8")
    start_pos = node.find("void Start()")
    replay_complete_pos = node.find(
        "startup_replay_complete_.store(true", start_pos
    )
    production_listener_pos = node.find(
        "tcp_server_ = std::make_unique<net::NodeServer>", replay_complete_pos
    )
    publictest_terminal_pos = node.find(
        "FATAL: public-testnet runtime not-after height/UTC has been reached",
        start_pos,
    )
    normal_authority_marker = node_main.find(
        "PUBLIC_TESTNET_MINER_PREFLIGHT_BEFORE_AUTHORITY_CONSUME"
    )
    lease_admission_pos = node_main.find(
        "if (!admit_testnet_lease()) return 78;", normal_authority_marker
    )
    node_construction_pos = node_main.find("std::make_unique<VeldNode>(config")

    assertions = {
        "public_release_rejects_test_hooks": (
            "defined(VELD_TEST_HOOKS)" in constants
            and "VELD_PUBLIC_RELEASE cannot be combined" in constants
        ),
        "fixture_requires_test_hooks": (
            '#ifndef VELD_TEST_HOOKS' in fixture
            and 'requires VELD_TEST_HOOKS' in fixture
        ),
        "fixture_rejects_public_profiles": (
            "defined(VELD_PUBLIC_RELEASE)" in fixture
            and "must never compile in a public profile" in fixture
        ),
        "all_test_state_is_guarded": (
            "#ifdef VELD_TEST_HOOKS\n    std::atomic<bool> "
            "test_work_force_tip_unknown_" in node
            and "test_work_local_runtime_open_" in node
        ),
        "submit_precommit_barrier_test_only": (
            "#ifdef VELD_TEST_HOOKS\n    // Deterministic process-test barrier"
            in blockchain
            and "TestSetLocalWorkPreCommitBarrier" in blockchain
            and "test_local_work_pre_commit_barrier_();" in blockchain
        ),
        "p2p_outcome_counters_test_only": (
            "#ifdef VELD_TEST_HOOKS\n    std::atomic<int>    "
            "test_start_failure_stage_" in tcp
            and "test_block_ingest_relay_calls_" in tcp
            and "test_block_ingest_penalty_calls_" in tcp
        ),
        "standalone_uses_production_broadcast_path": (
            "broadcast_op_return(host, shim.port(), validator.address" in fixture
            and "standalone bound endorsement reaches one real mempool/gossip sink"
            in fixture
        ),
        "finality_uses_production_rpc_sink": (
            "submit_finality_vote(" in fixture
            and "TestWorkFinalityGossipCalls" in fixture
            and "TestFinalityAssemblerCount" in fixture
            and node.count("WireFinalityVoteRpcSink_();") >= 2
            and "void WireFinalityVoteRpcSink_()" in node
        ),
        "standalone_rejects_altered_complete_output": (
            "standalone signer rejects altered complete-output claim" in fixture
            and "altered total reaches no mempool or gossip sink" in fixture
        ),
        "standalone_rejects_validator_value_wraps": (
            "registration output-wrap reproducer uses exact demonstrated values"
            in fixture
            and "oversized input is refused after both parents authenticate"
            in fixture
            and "malicious value proposal reaches no BuildScriptSig invocation"
            in fixture
            and "malicious value proposal reaches no sendrawtransaction request"
            in fixture
            and "malicious value proposal reaches no mempool or gossip artifact"
            in fixture
        ),
        "production_listener_follows_replay_completion": (
            0 <= replay_complete_pos < production_listener_pos
        ),
        "publictest_expiry_is_immutable": (
            'COMPILED_LEASE_NOT_AFTER_UTC =\n    "2026-08-30T18:00:00Z"'
            in runtime
        ),
        "publictest_expiry_latches": (
            "PermitOrLatchClosed" in runtime
            and "public_testnet_expired_" in node
        ),
        "publictest_expiry_precedes_listeners": (
            0 <= publictest_terminal_pos < production_listener_pos
        ),
        "publictest_authority_precedes_node_construction": (
            0 <= normal_authority_marker <= lease_admission_pos
            < node_construction_pos
        ),
    }
    for name, value in assertions.items():
        if not value:
            fail(f"static source assertion failed: {name}")
    return assertions


def validate_row(row: str, data: dict, artifact_dir: Path) -> int:
    if data.get("row") != row:
        fail(f"{row}: child returned wrong row identity")
    expected_closed = row != "open"
    if bool(data.get("closed")) != expected_closed:
        fail(f"{row}: wrong closed/open disposition")
    checks = int(data.get("checks", 0))
    if checks < 70:
        fail(f"{row}: suspiciously low assertion count {checks}")

    journals = sorted(
        path.relative_to(artifact_dir).as_posix()
        for path in artifact_dir.rglob("*.journal")
    )
    if expected_closed:
        for key in ZERO_EFFECT_KEYS:
            if int(data.get(key, -1)) != 0:
                fail(f"{row}: expected {key}=0, got {data.get(key)!r}")
        if int(data.get("finality_verify_result", -1)) != 255:
            fail(f"{row}: closed finality verifier was unexpectedly invoked")
        if journals:
            fail(f"{row}: closed child emitted journal artifacts: {journals}")
    else:
        if int(data.get("internal_mining_admitted", 0)) < 1:
            fail("open: internal mining never crossed authoritative predicate")
        if int(data.get("internal_hashes", -1)) != 0 or int(
            data.get("internal_progress", -1)
        ) != 0:
            fail("open: deterministic pre-hash barrier allowed mining work")
        for key in OPEN_EXACT_ONE:
            if int(data.get(key, -1)) != 1:
                fail(f"open: expected {key}=1, got {data.get(key)!r}")
        if int(data.get("finality_verify_result", -1)) != 0:
            fail("open: real finality verifier did not return AcceptedNew")
        for key in [
            "cached_templates",
            "pending_tokens",
            "active_leases",
            "pending_broadcasts",
        ]:
            if int(data.get(key, -1)) != 0:
                fail(f"open: retained work artifact {key}")
        expected = {"inproc-endorse.journal", "standalone-endorse.journal",
                    "finality-vote.journal"}
        if {Path(item).name for item in journals} != expected:
            fail(f"open: exact durable journal set mismatch: {journals}")

    if expected_closed:
        if row == "durable_state":
            expected = {
                "p2p_add_calls": 1,
                "p2p_durable_calls": 0,
                "p2p_tip_advanced": 0,
                "p2p_relay_calls": 0,
                "p2p_penalty_calls": 0,
            }
            for key, value in expected.items():
                if int(data.get(key, -1)) != value:
                    fail(f"{row}: expected {key}={value}, got {data.get(key)!r}")
            if data.get("p2p_reject_tag") != "anchor_conflict" or data.get(
                "p2p_disposition"
            ) != "terminal_global_safety_refusal":
                fail(f"{row}: terminal durable refusal was not classified exactly")
        else:
            for key in [
                "p2p_add_calls", "p2p_durable_calls", "p2p_tip_advanced",
                "p2p_relay_calls",
            ]:
                if int(data.get(key, -1)) != 1:
                    fail(f"{row}: inbound P2P proof missing {key}=1")
            if int(data.get("p2p_penalty_calls", -1)) != 0 or data.get(
                "p2p_disposition"
            ) != "advanced_local_gate_independent":
                fail(f"{row}: operational P2P disposition mismatch")
        expected_lifecycle = (
            "production_listener_not_open_until_startup_complete"
            if row in STARTUP_LISTENER_ROWS else "listener_operational"
        )
        if data.get("listener_lifecycle") != expected_lifecycle:
            fail(f"{row}: listener lifecycle classification mismatch")
    else:
        for key in [
            "p2p_add_calls", "p2p_durable_calls", "p2p_tip_advanced",
            "p2p_relay_calls", "p2p_penalty_calls",
        ]:
            if int(data.get(key, -1)) != 0:
                fail(f"{row}: unexpected extra P2P probe in {key}")
    return checks


def validate_race_row(row: str, data: dict, artifact_dir: Path) -> int:
    if data.get("row") != row:
        fail(f"{row}: child returned wrong row identity")
    acquired = row.endswith("acquired_first")
    expected_race = "submitblock" if "submit" in row else "finality"
    if data.get("race") != expected_race or data.get("linearization") != (
        "acquired_first" if acquired else "close_first"
    ):
        fail(f"{row}: race identity mismatch")
    checks = int(data.get("checks", 0))
    minimum = 18 if expected_race == "submitblock" else 55
    if checks < minimum:
        fail(f"{row}: suspiciously low assertion count {checks}")
    retained = [
        "cached_templates", "pending_tokens", "active_leases",
        "active_remote_leases", "pending_broadcasts",
    ]
    for key in retained:
        if int(data.get(key, -1)) != 0:
            fail(f"{row}: retained race artifact {key}={data.get(key)!r}")
    if int(data.get("barrier_calls", -1)) != (1 if acquired else 0):
        fail(f"{row}: real sink barrier count mismatch")
    if int(data.get("close_blocked_before_release", -1)) != (
        1 if acquired else 0
    ):
        fail(f"{row}: close linearization proof mismatch")

    submit_keys = ["submit_add_calls", "submit_durable_calls", "block_broadcasts"]
    finality_keys = ["journal_calls", "signature_calls", "gossip_calls"]
    if expected_race == "finality":
        finality_keys += [
            "sink_calls", "active_calls", "node_gossip_calls",
            "assembler_calls",
        ]
    for key in submit_keys:
        expected = 1 if acquired and expected_race == "submitblock" else 0
        if int(data.get(key, -1)) != expected:
            fail(f"{row}: expected {key}={expected}, got {data.get(key)!r}")
    for key in finality_keys:
        expected = 1 if acquired and expected_race == "finality" else 0
        if int(data.get(key, -1)) != expected:
            fail(f"{row}: expected {key}={expected}, got {data.get(key)!r}")
    if expected_race == "finality":
        expected_verify = 0 if acquired else 255
        if int(data.get("verify_result", -1)) != expected_verify:
            fail(
                f"{row}: expected verify_result={expected_verify}, "
                f"got {data.get('verify_result')!r}"
            )

    journals = sorted(path.name for path in artifact_dir.rglob("*.journal"))
    expected_journals = ["finality-race.journal"] if (
        acquired and expected_race == "finality"
    ) else []
    if journals != expected_journals:
        fail(f"{row}: race journal artifact mismatch: {journals}")
    return checks


def run_matrix(fixture: Path, output: Path, timeout: int) -> list[dict]:
    rows_dir = output / "rows"
    rows_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    seen_pids: set[int] = set()
    pid_reuse_events = 0
    for row in ROWS:
        artifact_dir = rows_dir / row
        if artifact_dir.exists():
            shutil.rmtree(artifact_dir)
        artifact_dir.mkdir(parents=True)
        started = time.time()
        process = subprocess.Popen(
            [str(fixture), row, str(artifact_dir)],
            cwd=str(fixture.parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=os.environ.copy(),
        )
        if process.pid in seen_pids:
            # Every prior Popen has already completed communicate() before the
            # next row starts. Windows may legitimately recycle that exited
            # process identifier immediately; the new Popen handle still
            # proves a fresh child. Treat reuse as telemetry, not as a live-
            # process leak. Timeout/returncode checks below remain authoritative.
            pid_reuse_events += 1
        seen_pids.add(process.pid)
        try:
            stdout, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, _ = process.communicate()
            (output / f"{row}.log").write_text(stdout, encoding="utf-8")
            fail(f"{row}: child exceeded {timeout}s")
        (output / f"{row}.log").write_text(stdout, encoding="utf-8")
        if process.returncode != 0:
            fail(f"{row}: child exit={process.returncode}; see {row}.log")
        records = [
            line[len("F4_ROW_JSON ") :]
            for line in stdout.splitlines()
            if line.startswith("F4_ROW_JSON ")
        ]
        if len(records) != 1:
            fail(f"{row}: expected exactly one sealed JSON row, got {len(records)}")
        data = json.loads(records[0])
        check_count = (
            validate_race_row(row, data, artifact_dir)
            if row in RACE_ROWS else validate_row(row, data, artifact_dir)
        )
        results.append(
            {
                "row": row,
                "pid": process.pid,
                "exit": process.returncode,
                "elapsed_seconds": round(time.time() - started, 3),
                "checks": check_count,
                "counters": data,
                "artifact_files": sorted(
                    path.relative_to(artifact_dir).as_posix()
                    for path in artifact_dir.rglob("*")
                    if path.is_file()
                ),
            }
        )
    for result in results:
        result["pid_reuse_events_in_matrix"] = pid_reuse_events
    return results


def run_publictest_expiry(
    executable: Path, output: Path, timeout: int
) -> dict:
    artifact_dir = output / "rows" / "public_testnet_expiry"
    if artifact_dir.exists():
        shutil.rmtree(artifact_dir)
    artifact_dir.mkdir(parents=True)
    datadir = artifact_dir / "datadir-identity-only"
    started = time.time()
    process = subprocess.Popen(
        [
            str(executable), "--datadir", str(datadir),
            "--connect", "203.0.113.1:19333",
        ],
        cwd=str(executable.parent),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=os.environ.copy(),
    )
    try:
        stdout, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, _ = process.communicate()
        (output / "public_testnet_expiry.log").write_text(
            stdout, encoding="utf-8"
        )
        fail("public_testnet_expiry: process did not refuse startup boundedly")
    (output / "public_testnet_expiry.log").write_text(stdout, encoding="utf-8")
    expected = (
        "veld-node: FATAL: public-testnet lease refusal: "
        "the public testnet has ended, or the local clock is invalid"
    )
    if process.returncode != 78:
        fail(
            "public_testnet_expiry: expected startup-refusal exit 78, "
            f"got {process.returncode}"
        )
    if expected not in stdout:
        fail("public_testnet_expiry: exact compiled-lease refusal missing")
    datadir_files = sorted(
        path.relative_to(datadir).as_posix()
        for path in datadir.rglob("*") if path.is_file()
    ) if datadir.exists() else []
    if datadir_files != ["network.identity"]:
        fail(
            "public_testnet_expiry: node-owned state appeared before lease "
            f"refusal: {datadir_files}"
        )
    return {
        "row": "public_testnet_expiry",
        "pid": process.pid,
        "exit": process.returncode,
        "elapsed_seconds": round(time.time() - started, 3),
        "checks": 5,
        "counters": {
            "row": "public_testnet_expiry",
            "closed": True,
            "node_constructed": 0,
            "listener_opened": 0,
            "identity_file_only": 1,
            "exit": process.returncode,
            "disposition": "terminal_publictest_lifecycle_refusal",
        },
        "artifact_files": [
            path.relative_to(artifact_dir).as_posix()
            for path in artifact_dir.rglob("*") if path.is_file()
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--publictest-node", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--platform", required=True)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()

    root = args.root.resolve()
    fixture = args.fixture.resolve()
    publictest_node = args.publictest_node.resolve()
    output = args.output.resolve()
    if not fixture.is_file():
        fail(f"fixture not found: {fixture}")
    if not publictest_node.is_file():
        fail(f"public-testnet node not found: {publictest_node}")
    output.mkdir(parents=True, exist_ok=True)
    static = source_assertions(root)
    results = run_matrix(fixture, output, args.timeout)
    results.append(run_publictest_expiry(publictest_node, output, args.timeout))
    summary = {
        "schema": "VELD_F4_PROCESS_MATRIX_V1",
        "platform": args.platform,
        "fixture": str(fixture),
        "fixture_sha256": sha256(fixture),
        "publictest_node": str(publictest_node),
        "publictest_node_sha256": sha256(publictest_node),
        "row_count": len(results),
        "process_count": len(results),
        "distinct_observed_pids": len({row["pid"] for row in results}),
        "pid_reuse_events": int(results[0].get(
            "pid_reuse_events_in_matrix", 0)) if results else 0,
        "assertion_count": sum(int(row["checks"]) for row in results),
        "static_assertions": static,
        "p2p_operational_advance_rows": [
            row for row in MATRIX_ROWS
            if row not in {"open", "durable_state"}
        ],
        "p2p_terminal_global_safety_rows": ["durable_state"],
        "startup_listener_unavailable_rows": sorted(STARTUP_LISTENER_ROWS),
        "real_entrypoint_race_rows": RACE_ROWS,
        "public_testnet_terminal_exception": {
            "not_f4_gate_induced": True,
            "reason": (
                "immutable expired public-testnet lifecycle refuses startup before "
                "VeldNode construction/listeners; exercised by a real public-profile "
                "node without TEST_HOOKS"
            ),
        },
        "rows": results,
    }
    (output / "matrix-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (output / "matrix-summary.tsv").open("w", encoding="utf-8", newline="") as out:
        out.write("row\tpid\texit\tchecks\telapsed_seconds\n")
        for row in results:
            out.write(
                f"{row['row']}\t{row['pid']}\t{row['exit']}\t"
                f"{row['checks']}\t{row['elapsed_seconds']}\n"
            )
    print(
        "PASS daybreak_work_admission_process_tests "
        f"platform={args.platform} rows={len(results)} "
        f"processes={len(results)} "
        f"checks={summary['assertion_count']} "
        f"fixture_sha256={summary['fixture_sha256']}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # single-line CI failure plus full logs per child
        print(f"FAIL daybreak_work_admission_process_tests: {exc}", file=sys.stderr)
        raise SystemExit(1)
