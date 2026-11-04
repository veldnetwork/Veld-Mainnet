#!/usr/bin/env python3
"""
test_peg_solvency.py - negative + positive tests for the shared peg-solvency
invariant (veld_peg_solvency.py). Pure, no network - runs anywhere.

Proves the properties F1 depends on:
  * insolvent state cannot produce a SOLVENT beat
  * a compromised custody box cannot get the signer to mint past headroom
  * a stale / missing / malformed / forged heartbeat fails CLOSED
  * exact signed-but-unconfirmed transactions are charged against headroom
"""

import time
import veld_peg_solvency as sol

FAILS = []


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        FAILS.append(name)


BTC = sol.SATS
TIP_HASH = "11" * 32


def t_headroom_math():
    check(
        "headroom = custody-liability-margin",
        sol.solvency_headroom(10 * BTC, 6 * BTC, BTC) == 3 * BTC,
    )
    check("solvent when supply+margin<=custody", sol.is_solvent(10 * BTC, 9 * BTC, BTC))
    check("insolvent when supply>custody", not sol.is_solvent(5 * BTC, 6 * BTC, 0))
    check("insolvent when margin eats it", not sol.is_solvent(10 * BTC, 10 * BTC, BTC))


def t_build_beat():
    p = sol.build_beat_payload(
        10 * BTC, 6 * BTC, BTC, tip=100, tip_hash=TIP_HASH, seq=1, ttl_secs=120
    )
    check("beat headroom correct", p["headroom_sats"] == 3 * BTC)
    check("beat validates", sol.validate_beat_payload(p)[0])
    burn_pending = sol.build_beat_payload(
        10 * BTC,
        6 * BTC,
        BTC,
        tip=100,
        tip_hash=TIP_HASH,
        seq=2,
        ttl_secs=120,
        backing_liability_sats=7 * BTC,
    )
    check(
        "pending burn remains in signed backing liability",
        burn_pending["backing_liability_sats"] == 7 * BTC
        and burn_pending["headroom_sats"] == 2 * BTC
        and sol.validate_beat_payload(burn_pending)[0],
    )
    # cannot build a beat while insolvent
    raised = False
    try:
        sol.build_beat_payload(5 * BTC, 6 * BTC, 0, tip=1, tip_hash=TIP_HASH, seq=1, ttl_secs=120)
    except ValueError:
        raised = True
    check("build refuses insolvent beat", raised)
    try:
        sol.build_beat_payload(
            10 * BTC,
            6 * BTC,
            0,
            tip=1,
            tip_hash=TIP_HASH,
            seq=1,
            ttl_secs=120,
            backing_liability_sats=5 * BTC,
        )
        below_supply_raised = False
    except ValueError:
        below_supply_raised = True
    check("build refuses backing liability below live supply", below_supply_raised)


def t_payload_validation():
    good = sol.build_beat_payload(10 * BTC, 6 * BTC, BTC, 1, TIP_HASH, 1, 120)
    check("good payload ok", sol.validate_beat_payload(good)[0])

    bad_ver = dict(good)
    bad_ver["v"] = 999
    check("wrong version rejected", not sol.validate_beat_payload(bad_ver)[0])

    lied = dict(good)
    lied["headroom_sats"] = 9 * BTC  # claim more than custody-supply
    check("inconsistent headroom rejected", not sol.validate_beat_payload(lied)[0])

    missing_liability = dict(good)
    missing_liability.pop("backing_liability_sats")
    check(
        "heartbeat missing complete liability rejected",
        not sol.validate_beat_payload(missing_liability)[0],
    )

    below_supply = dict(good)
    below_supply["backing_liability_sats"] = 5 * BTC
    below_supply["headroom_sats"] = 4 * BTC
    check(
        "heartbeat liability below supply rejected", not sol.validate_beat_payload(below_supply)[0]
    )

    badttl = dict(good)
    badttl["ttl_secs"] = 10**9
    check("oversized ttl rejected", not sol.validate_beat_payload(badttl)[0])

    bad_hash = dict(good)
    bad_hash["tip_hash"] = "AA" * 32
    check("non-canonical tip hash rejected", not sol.validate_beat_payload(bad_hash)[0])

    for label, value in (
        ("bool", True),
        ("string", "10"),
        ("float", 10.0),
        ("int64 overflow", 1 << 63),
    ):
        malformed = dict(good)
        malformed["custody_sats"] = value
        check("%s integer field rejected" % label, not sol.validate_beat_payload(malformed)[0])

    negative_supply = dict(good)
    negative_supply["supply_sats"] = -5 * BTC
    negative_supply["headroom_sats"] = (
        negative_supply["custody_sats"]
        - negative_supply["supply_sats"]
        - negative_supply["margin_sats"]
    )
    check(
        "negative supply cannot fabricate positive headroom",
        not sol.validate_beat_payload(negative_supply)[0],
    )

    check("garbage rejected", not sol.validate_beat_payload("not a dict")[0])


def t_gate_fail_closed():
    now = 1_000_000.0
    beat = sol.stamp_heartbeat(
        sol.build_beat_payload(10 * BTC, 6 * BTC, 0, 1, TIP_HASH, 1, 120), now
    )

    # positive: within headroom, fresh
    check("mint within headroom allowed", sol.heartbeat_gate(beat, now + 1, 0, 3 * BTC)[0])

    # no heartbeat at all -> deny
    check("missing heartbeat denies", not sol.heartbeat_gate(None, now, 0, 1)[0])

    # expired heartbeat -> deny (watchtower stale/down)
    check("expired heartbeat denies", not sol.heartbeat_gate(beat, now + 121, 0, 1)[0])

    # mint exceeds headroom -> deny (custody-box compromise trying to over-mint)
    check("over-headroom mint denies", not sol.heartbeat_gate(beat, now + 1, 0, 5 * BTC)[0])

    # in-flight window already consumed the headroom -> deny the next one
    check(
        "window in-flight charged against headroom",
        not sol.heartbeat_gate(beat, now + 1, 4 * BTC, 1 * BTC)[0],
    )

    # exactly at the boundary (window_signed + mint == headroom) is allowed;
    # one sat over is not.
    check("exact boundary allowed", sol.heartbeat_gate(beat, now + 1, 2 * BTC, 2 * BTC)[0])
    check(
        "one sat over boundary denied",
        not sol.heartbeat_gate(beat, now + 1, 2 * BTC, 2 * BTC + 1)[0],
    )

    # forged on-disk heartbeat (negative headroom) -> deny
    forged = dict(beat)
    forged["headroom_sats"] = -1
    check(
        "forged negative-headroom heartbeat denies",
        not sol.heartbeat_gate(forged, now + 1, 0, 1)[0],
    )

    # non-positive mint -> deny
    check("non-positive mint denies", not sol.heartbeat_gate(beat, now + 1, 0, 0)[0])


def t_receiver_clock_stamp():
    p = sol.build_beat_payload(10 * BTC, 6 * BTC, 0, 1, TIP_HASH, 7, 120)
    hb = sol.stamp_heartbeat(p, 500.0)
    check("stamp uses receiver clock", hb["issued_at"] == 500.0 and hb["expires_at"] == 620.0)
    # receiver clamps an over-long ttl even if it slipped past validation
    p2 = dict(p)
    p2["ttl_secs"] = 10_000
    hb2 = sol.stamp_heartbeat(p2, 500.0)
    check("stamp clamps ttl to MAX_TTL_SECS", hb2["expires_at"] == 500.0 + sol.MAX_TTL_SECS)


if __name__ == "__main__":
    for fn in (
        t_headroom_math,
        t_build_beat,
        t_payload_validation,
        t_gate_fail_closed,
        t_receiver_clock_stamp,
    ):
        print(fn.__name__)
        fn()
    print()
    if FAILS:
        print("FAILED %d: %s" % (len(FAILS), ", ".join(FAILS)))
        raise SystemExit(1)
    print("ALL PASS")
