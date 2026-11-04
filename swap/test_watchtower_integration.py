#!/usr/bin/env python3
"""
test_watchtower_integration.py - end-to-end wiring test for the F1 peg watchtower.

Unlike test_peg_solvency.py (which tests the pure invariant), this exercises the
REAL programs and proves the pieces agree on the wire:

  Part A - the REAL veld_wt_recv.py receiver, run as a subprocess:
     * an unsigned payload is rejected unless the explicit dev marker exists
     * with that marker, SOLVENT writes a heartbeat the signer's gate ACCEPTS
     * a HALT payload creates the sticky HALT file
     * garbage / inconsistent / oversized-ttl payloads change NOTHING (exit 2)
     * the receiver stamps expiry from its own clock -> the gate honors it

  Part B - the REAL veld_signerd.watchtower_gate(), imported with a stub fcntl:
     * marker absent            -> REFUSE (neither watchtower nor explicit dev opt-out)
     * marker present, no beat  -> REFUSE (SystemExit 2)  [fail-closed]
     * marker present, fresh    -> allow within headroom
     * marker present, stale    -> REFUSE                 [watchtower down]
     * marker present, over     -> REFUSE                 [custody-box over-mint]
"""

import json
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import veld_peg_solvency as sol  # noqa: E402

BTC = sol.SATS
TIP_HASH = "11" * 32
MINT_BLOCK_HASH = "22" * 32
RECIPIENT = "V" + "2" * 25
FAILS = []


class FakeRpc:
    def __init__(self, tip_hash=TIP_HASH):
        self.tip_hash = tip_hash
        self.transactions = {}
        self.calls = []

    def call(self, method, params=None):
        params = params or []
        self.calls.append((method, list(params)))
        if method == "getblockhash":
            if params and params[0] != 100:
                return MINT_BLOCK_HASH
            return self.tip_hash
        if method == "getrawtransaction":
            txid = params[0]
            if txid not in self.transactions:
                raise RuntimeError("transaction not canonical")
            return dict(self.transactions[txid])
        raise RuntimeError("unexpected RPC " + method)


def txid_for(signed_hex):
    raw = bytes.fromhex(signed_hex)
    return hashlib.sha256(hashlib.sha256(raw).digest()).hexdigest()


def heartbeat(supply=6 * BTC, custody=None, tip=100, tip_hash=TIP_HASH):
    if custody is None:
        custody = supply + 10 * BTC
    return sol.stamp_heartbeat(
        sol.build_beat_payload(custody, supply, 0, tip, tip_hash, 1, 120), time.time()
    )


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        FAILS.append(name)


def write_private_json(path, value):
    with open(path, "w") as handle:
        json.dump(value, handle)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


# --------------------------------------------------------------- Part A
def run_receiver(recv_dir, payload):
    """Run the real receiver as a subprocess in recv_dir; return (rc, files)."""
    p = subprocess.run(
        [sys.executable, os.path.join(recv_dir, "veld_wt_recv.py")],
        input=json.dumps(payload) if not isinstance(payload, str) else payload,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return p.returncode


def part_a():
    print("part_a: real veld_wt_recv.py receiver")
    d = tempfile.mkdtemp(prefix="wt_recv_")
    try:
        for f in ("veld_wt_recv.py", "veld_peg_solvency.py", "rpc_url_policy.py"):
            shutil.copy(os.path.join(HERE, f), os.path.join(d, f))
        hbf = os.path.join(d, "signer-heartbeat.json")
        haltf = os.path.join(d, "HALT")

        payload = sol.build_beat_payload(
            10 * BTC, 6 * BTC, 0, tip=100, tip_hash=TIP_HASH, seq=1, ttl_secs=120
        )
        rc = run_receiver(d, payload)
        check("unsigned SOLVENT rejected by default", rc == 2)
        check("rejected unsigned beat wrote no heartbeat", not os.path.exists(hbf))
        open(os.path.join(d, "beat-unsigned-ok"), "w").close()  # explicit dev-only opt-out

        # SOLVENT -> heartbeat written, and the signer gate accepts an in-headroom mint
        rc = run_receiver(d, payload)
        check("dev-marker unsigned SOLVENT accepted (rc 0)", rc == 0)
        check("heartbeat file written", os.path.exists(hbf))
        hb = json.load(open(hbf))
        check(
            "receiver stamped expiry from its clock",
            "expires_at" in hb and hb["expires_at"] > time.time(),
        )
        check(
            "gate accepts mint within headroom", sol.heartbeat_gate(hb, time.time(), 0, 3 * BTC)[0]
        )
        check(
            "gate denies mint over headroom", not sol.heartbeat_gate(hb, time.time(), 0, 5 * BTC)[0]
        )

        first_heartbeat = open(hbf).read()
        rc = run_receiver(d, payload)  # a new process simulates receiver restart
        check("restart replay of same signed seq is rejected", rc == 2)
        check("replay cannot refresh receiver-stamped expiry", open(hbf).read() == first_heartbeat)

        # Two forced-command processes racing the same next sequence serialize on
        # the durable lock; exactly one may publish it.
        payload2 = dict(payload)
        payload2["seq"] = 2
        cmd = [sys.executable, os.path.join(d, "veld_wt_recv.py")]
        p1 = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        p2 = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        p1.communicate(json.dumps(payload2), timeout=30)
        p2.communicate(json.dumps(payload2), timeout=30)
        check(
            "concurrent duplicate beat has exactly one winner",
            sorted([p1.returncode, p2.returncode]) == [0, 2],
        )
        check(
            "durable sequence advanced exactly once",
            json.load(open(hbf))["seq"] == 2
            and open(os.path.join(d, "watchtower-last-seq")).read().strip() == "2",
        )

        # A bounded read must detect truncation. The old read(MAX_STDIN) path
        # accepted this valid JSON prefix plus whitespace and never saw the final
        # trailing byte, refreshing the heartbeat despite an oversized request.
        payload3 = dict(payload)
        payload3["seq"] = 3
        prefix = json.dumps(payload3)
        oversized = prefix + (" " * (65536 - len(prefix))) + "X"
        before_oversize = open(hbf).read()
        rc = run_receiver(d, oversized)
        check("valid JSON prefix with trailing byte beyond limit is rejected", rc == 2)
        check(
            "oversized payload cannot advance heartbeat or durable sequence",
            open(hbf).read() == before_oversize
            and open(os.path.join(d, "watchtower-last-seq")).read().strip() == "2",
        )

        # garbage -> exit 2, no HALT, heartbeat unchanged
        before = open(hbf).read()
        rc = run_receiver(d, "{not json")
        check("garbage rejected (rc 2)", rc == 2)
        check("garbage created no HALT", not os.path.exists(haltf))
        check("garbage left heartbeat unchanged", open(hbf).read() == before)

        # inconsistent headroom -> rejected, nothing written
        lied = dict(payload)
        lied["headroom_sats"] = 9 * BTC
        rc = run_receiver(d, lied)
        check("inconsistent-headroom payload rejected", rc == 2)
        check("liar left heartbeat unchanged", open(hbf).read() == before)

        # HALT -> sticky HALT file created
        rc = run_receiver(d, sol.build_halt_payload("test insolvency"))
        check("HALT accepted (rc 0)", rc == 0)
        check("HALT file created", os.path.exists(haltf))
        check("HALT records watchtower reason", "WATCHTOWER" in open(haltf).read())
    finally:
        shutil.rmtree(d, ignore_errors=True)


# --------------------------------------------------------------- Part B
def part_b():
    print("part_b: real veld_signerd.watchtower_gate (stub fcntl)")
    # Stub the Linux-only fcntl so veld_signerd imports on any platform. The signer
    # only calls fcntl inside main(); import + watchtower_gate never touch it.
    if "fcntl" not in sys.modules:
        stub = types.ModuleType("fcntl")
        stub.LOCK_EX = 2
        stub.LOCK_NB = 4
        stub.flock = lambda *a, **k: None
        sys.modules["fcntl"] = stub
    import veld_signerd as sd

    d = tempfile.mkdtemp(prefix="wt_signer_")
    try:
        # redirect the signer's writable paths into the temp dir
        sd.HEARTBEATF = os.path.join(d, "signer-heartbeat.json")
        sd.WT_REQUIRED = os.path.join(d, "watchtower-required")
        sd.LOGF = os.path.join(d, "signer.log")
        state = {"signed": []}
        rpc = FakeRpc()

        # No watchtower marker and no explicit caps-only dev opt-out is an
        # ambiguous production configuration, so the signer fails safe.
        try:
            sd.watchtower_gate(1 * BTC, state, rpc=rpc)
            check("marker absent -> fail-safe refuse", False)
        except SystemExit as e:
            check("marker absent -> fail-safe refuse", e.code == 2)

        # arm enforcement
        open(sd.WT_REQUIRED, "w").close()

        # armed but no heartbeat -> REFUSE (SystemExit 2)
        try:
            sd.watchtower_gate(1 * BTC, state, rpc=rpc)
            check("armed + no heartbeat -> refuse", False)
        except SystemExit as e:
            check("armed + no heartbeat -> refuse", e.code == 2)

        # fresh in-headroom beat -> allowed (no exception)
        beat = sol.stamp_heartbeat(
            sol.build_beat_payload(10 * BTC, 6 * BTC, 0, 100, TIP_HASH, 1, 120), time.time()
        )
        write_private_json(sd.HEARTBEATF, beat)
        try:
            sd.watchtower_gate(3 * BTC, state, rpc=rpc)
            check("armed + fresh + in-headroom -> allow", True)
        except SystemExit:
            check("armed + fresh + in-headroom -> allow", False)

        # over headroom -> REFUSE
        try:
            sd.watchtower_gate(5 * BTC, state, rpc=rpc)
            check("armed + over-headroom -> refuse", False)
        except SystemExit as e:
            check("armed + over-headroom -> refuse", e.code == 2)

        # in-flight window already consumed headroom -> REFUSE the next mint
        state2 = {
            "signed": [],
            "mint_accounting": {
                "version": sd.MINT_ACCOUNTING_VERSION,
                "pending": [
                    {"request_id": "f" * 64, "sats": 4 * BTC, "signed_at": int(time.time())}
                ],
                "confirmed": [],
            },
        }
        try:
            sd.watchtower_gate(1 * BTC, state2, rpc=rpc)
            check("armed + window in-flight consumes headroom -> refuse", False)
        except SystemExit as e:
            check("armed + window in-flight consumes headroom -> refuse", e.code == 2)

        # stale beat -> REFUSE
        stale = sol.stamp_heartbeat(
            sol.build_beat_payload(10 * BTC, 6 * BTC, 0, 100, TIP_HASH, 2, 120), time.time() - 1000
        )
        write_private_json(sd.HEARTBEATF, stale)
        try:
            sd.watchtower_gate(1 * BTC, state, rpc=rpc)
            check("armed + stale beat -> refuse", False)
        except SystemExit as e:
            check("armed + stale beat -> refuse", e.code == 2)

        # Same height is not sufficient: a different canonical hash is a fork and
        # the signer must not combine that view with the watchtower's supply.
        write_private_json(sd.HEARTBEATF, beat)
        fork_rpc = FakeRpc(tip_hash="33" * 32)
        try:
            sd.watchtower_gate(1, state, rpc=fork_rpc)
            check("same-height competing tip hash -> refuse", False)
        except SystemExit as e:
            check("same-height competing tip hash -> refuse", e.code == 2)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def part_c():
    print("part_c: durable outstanding-mint accounting")
    import veld_signerd as sd

    rpc = FakeRpc()

    # Upgrade is deliberately conservative: every retained legacy signature is
    # unresolved/pending. The old cumulative counter also becomes a one-time
    # unresolved floor because its 500-entry journal may have lost tiny mints.
    legacy = {
        "signed": [
            {"sats": 3 * BTC, "to": "V1", "at": 10},
            {"sats": 2 * BTC, "to": "V2", "at": 11},
        ],
        "total_signed": 100 * BTC,
    }
    try:
        sd.reconcile_mint_accounting(legacy, heartbeat(supply=50 * BTC), rpc)
        check("legacy state pauses pending offline reconciliation", False)
    except ValueError:
        check("legacy state pauses pending offline reconciliation", True)
    check(
        "legacy refusal does not silently mutate/delete audit rows",
        len(legacy["signed"]) == 2 and legacy["total_signed"] == 100 * BTC,
    )

    # Only the exact signed txid in the trusted canonical chain frees headroom.
    state = {"signed": []}
    hb = heartbeat(supply=10 * BTC)
    used, _ = sd.reconcile_mint_accounting(state, hb, rpc)
    check("fresh signer starts with no outstanding mint", used == 0)
    signed1 = "01" * 80
    txid1 = txid_for(signed1)
    sd.record_signed_mint(state, "a" * 64, txid1, signed1, 2 * BTC, RECIPIENT, signed_at=20)
    used, _ = sd.reconcile_mint_accounting(state, hb, rpc)
    check("new signature remains outstanding before confirmation", used == 2 * BTC)
    rpc.transactions[txid1] = {
        "txid": txid1,
        "confirmations": 2,
        "block_height": 99,
        "block_hash": MINT_BLOCK_HASH,
    }
    used, _ = sd.reconcile_mint_accounting(state, heartbeat(supply=12 * BTC), rpc)
    check("exact canonical tx confirmation permits a back-to-back mint", used == 0)

    signed2 = "02" * 80
    txid2 = txid_for(signed2)
    sd.record_signed_mint(state, "b" * 64, txid2, signed2, 3 * BTC, RECIPIENT, signed_at=21)
    used, _ = sd.reconcile_mint_accounting(state, heartbeat(supply=12 * BTC), rpc)
    check("back-to-back mint is charged exactly once", used == 3 * BTC)
    cached, incremental = sd.classify_mint_request(state, "b" * 64, 3 * BTC, RECIPIENT)
    check("retry adds zero rolling-window/headroom capacity", incremental == 0)
    check(
        "retry replays byte-identical signed tx and txid",
        cached["signed_tx_hex"] == signed2
        and txid_for(cached["signed_tx_hex"]) == cached["txid"] == txid2,
    )
    inserted = sd.record_signed_mint(
        state, "b" * 64, txid2, signed2, 3 * BTC, RECIPIENT, signed_at=22
    )
    used, _ = sd.reconcile_mint_accounting(state, heartbeat(supply=12 * BTC), rpc)
    check("same-transaction retry is idempotent", not inserted and used == 3 * BTC)

    # A burn followed by a same-sized reorg increase must not masquerade as this
    # still-unconfirmed tx. Aggregate supply is never confirmation authority.
    used, _ = sd.reconcile_mint_accounting(state, heartbeat(supply=7 * BTC), rpc)
    used, _ = sd.reconcile_mint_accounting(state, heartbeat(supply=12 * BTC), rpc)
    check("burn then supply reorg does not retire unconfirmed mint", used == 3 * BTC)

    # A once-confirmed mint stays in a separate reorg-watch set. If it disappears
    # before the consensus depth bound, its exact amount becomes pending again.
    del rpc.transactions[txid1]
    used, _ = sd.reconcile_mint_accounting(state, heartbeat(supply=10 * BTC), rpc)
    check("pre-finality mint reorg returns exact tx to pending", used == 5 * BTC)
    rpc.transactions[txid1] = {
        "txid": txid1,
        "confirmations": sd.MAX_REORG_DEPTH,
        "block_height": 1,
        "block_hash": MINT_BLOCK_HASH,
    }
    used, _ = sd.reconcile_mint_accounting(state, heartbeat(supply=12 * BTC), rpc)
    check(
        "mint at MAX_REORG_DEPTH remains under reorg watch",
        used == 3 * BTC and len(state["mint_accounting"]["confirmed"]) == 1,
    )
    rpc.transactions[txid1]["confirmations"] = sd.MAX_REORG_DEPTH + 1
    used, _ = sd.reconcile_mint_accounting(
        state, heartbeat(supply=12 * BTC, tip=101, tip_hash=MINT_BLOCK_HASH), rpc
    )
    check(
        "mint deeper than MAX_REORG_DEPTH is pruned from reorg watch",
        used == 3 * BTC and not state["mint_accounting"]["confirmed"],
    )

    constants = open(os.path.join(HERE, "..", "include", "core", "constants.h")).read()
    check(
        "signer MAX_REORG_DEPTH matches consensus constant",
        ("MAX_REORG_DEPTH                = %d" % sd.MAX_REORG_DEPTH) in constants,
    )
    import veld_wt_reserve as reserve

    check(
        "witness MAX_REORG_DEPTH matches signer and consensus",
        reserve.MAX_REORG_DEPTH == sd.MAX_REORG_DEPTH
        and ("MAX_REORG_DEPTH                = %d" % reserve.MAX_REORG_DEPTH) in constants,
    )

    # Count-based truncation is unsafe: 501 one-sat requests can all fit inside
    # the rolling hour. Keep every cap/idempotency record, including the first.
    volume = {"signed": []}
    sd.reconcile_mint_accounting(volume, heartbeat(supply=0), rpc)
    first_request = None
    for i in range(501):
        signed_hex = "%0160x" % (i + 1)
        request_id = hashlib.sha256(("request-%d" % i).encode()).hexdigest()
        if i == 0:
            first_request = (request_id, signed_hex, txid_for(signed_hex))
        sd.record_signed_mint(
            volume,
            request_id,
            txid_for(signed_hex),
            signed_hex,
            1,
            RECIPIENT,
            signed_at=int(time.time()),
        )
    cached, increment = sd.classify_mint_request(volume, first_request[0], 1, RECIPIENT)
    check(
        ">500 tiny mints remain fully counted in rolling window",
        len(volume["signed"]) == 501 and sd.window_signed_sats(volume) == 501,
    )
    check(
        "oldest of >500 requests retains exact replay bytes forever",
        increment == 0
        and cached["signed_tx_hex"] == first_request[1]
        and cached["txid"] == first_request[2],
    )

    # Persistence survives restart and exercises both required fsync barriers.
    d = tempfile.mkdtemp(prefix="signer_state_")
    try:
        path = os.path.join(d, "signer-state.json")
        persisted = {"signed": []}
        sd.reconcile_mint_accounting(persisted, heartbeat(supply=100), rpc)
        signed3 = "03" * 80
        txid3 = txid_for(signed3)
        sd.record_signed_mint(persisted, "c" * 64, txid3, signed3, 25, RECIPIENT, signed_at=30)
        real_fsync = sd.os.fsync
        fsync_calls = []

        def counted_fsync(fd):
            fsync_calls.append(fd)
            return real_fsync(fd)

        sd.os.fsync = counted_fsync
        try:
            sd.save_signer_state_durable(persisted, path)
        finally:
            sd.os.fsync = real_fsync
        restarted = sd.load_signer_state(path)
        outstanding, _ = sd.reconcile_mint_accounting(restarted, heartbeat(supply=100), rpc)
        check("restart preserves outstanding mint headroom charge", outstanding == 25)
        check("state persistence fsyncs file and directory", len(fsync_calls) >= 2)
        check("durable signer state is owner-only", stat.S_IMODE(os.stat(path).st_mode) == 0o600)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def part_d():
    print("part_d: watchtower coherent supply wire contract")
    import veld_watchtowerd as wd

    class SupplyRpc:
        def __init__(self, value):
            self.value = value

        def rpc(self, method):
            if method != "getbtcveldsupply":
                raise RuntimeError("unexpected method")
            return self.value

    wt = wd.Watchtower.__new__(wd.Watchtower)
    wt.veld = SupplyRpc({"supply_sats": 123, "tip": 456, "tip_hash": TIP_HASH})
    check("tip-bound supply object is accepted exactly", wt.read_supply() == (123, 456, TIP_HASH))

    malformed = (
        123,
        {"supply_sats": True, "tip": 456, "tip_hash": TIP_HASH},
        {"supply_sats": "123", "tip": 456, "tip_hash": TIP_HASH},
        {"supply_sats": -1, "tip": 456, "tip_hash": TIP_HASH},
        {"supply_sats": 123, "tip": 1 << 63, "tip_hash": TIP_HASH},
        {"supply_sats": 123, "tip": 456, "tip_hash": "AA" * 32},
    )
    for i, value in enumerate(malformed):
        wt.veld = SupplyRpc(value)
        try:
            wt.read_supply()
            check("malformed supply snapshot %d fails closed" % i, False)
        except RuntimeError:
            check("malformed supply snapshot %d fails closed" % i, True)


if __name__ == "__main__":
    part_a()
    part_b()
    part_c()
    part_d()
    print()
    if FAILS:
        print("FAILED %d: %s" % (len(FAILS), ", ".join(FAILS)))
        raise SystemExit(1)
    print("ALL PASS")
