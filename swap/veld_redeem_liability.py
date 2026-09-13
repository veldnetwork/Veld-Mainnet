#!/usr/bin/env python3
"""Independent btcVELD redemption-liability derivation for the watchtower.

This module deliberately has no mutable authority.  Every pass walks the
canonical, paginated Veld REDEEM index at the *same* tip as the supply snapshot
and reconciles it against the complete history of the watchtower's own Bitcoin
mainnet custody wallet.  An accepted burn remains a backing liability until one
outgoing Bitcoin transaction is independently observed with:

* the canonical ``VLDR\x01`` marker for the exact Veld burn outpoint;
* exactly the burned amount to exactly the committed destination script; and
* at least the confirmation depth compiled into Veld (``spv_k_btc``).

No cache, coordinator database, or payout-daemon status is trusted.  A restart,
stale restore, or either-chain reorg therefore recomputes the liability from the
two primary chains and fails closed on any ambiguity.
"""

from decimal import Decimal, InvalidOperation
import re

try:
    from .veld_redeem_commitment import (RedeemCommitment,
                                         authority_for_rows,
                                         parse_page_authority)
except ImportError:  # direct-script execution
    from veld_redeem_commitment import (RedeemCommitment,
                                        authority_for_rows,
                                        parse_page_authority)


SATS = 100_000_000
MAX_WIRE_INT = (1 << 63) - 1
PAGE_LIMIT = 512
MAX_PAGES = 1_000_000
PAYOUT_MARKER_MAGIC = b"VLDR\x01"
HASH256_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_RE = re.compile(r"^(?:[0-9a-f]{2})+$")


def _uint(value, field, positive=False, maximum=MAX_WIRE_INT):
    if (isinstance(value, bool) or not isinstance(value, int) or value < 0 or
            value > maximum or (positive and value == 0)):
        raise RuntimeError("%s is not a bounded %sinteger" %
                           (field, "positive " if positive else "non-negative "))
    return value


def _hash256(value, field):
    if not isinstance(value, str) or not HASH256_RE.fullmatch(value):
        raise RuntimeError("%s is not canonical lowercase hash256" % field)
    return value


def btc_to_sats(value):
    """Convert a Bitcoin Core JSON amount to exact integer sats."""
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise RuntimeError("Bitcoin amount is not an exact decimal")
    scaled = amount * SATS
    if scaled != scaled.to_integral_value():
        raise RuntimeError("Bitcoin amount has sub-satoshi precision")
    sats = int(scaled)
    if sats < 0 or sats > MAX_WIRE_INT:
        raise RuntimeError("Bitcoin amount is outside the bounded sats range")
    return sats


def _normalize_redeem(row, expected_token_id, snapshot_tip):
    if not isinstance(row, dict):
        raise RuntimeError("getbtcveldredeems row is not an object")
    # The token ledger marks the REDEEM action with is_redeem=true.  Its legacy
    # is_burn field denotes the separate token-history action and is false for a
    # REDEEM even though REDEEM semantically destroys supply.
    if row.get("is_redeem") is not True or row.get("is_burn") is not False:
        raise RuntimeError("redeem index returned a non-canonical REDEEM row")
    if row.get("is_mint") is not False:
        raise RuntimeError("redeem index row is ambiguously also a mint")
    if row.get("token") != expected_token_id:
        raise RuntimeError("redeem index returned the wrong token")

    txid = _hash256(row.get("txid"), "redeem txid")
    block_hash = _hash256(row.get("block_hash"), "redeem block_hash")
    vout = _uint(row.get("vout"), "redeem vout", maximum=0xffffffff)
    amount = _uint(row.get("amount_sats"), "redeem amount_sats", positive=True)
    height = _uint(row.get("block"), "redeem block")
    if height > snapshot_tip:
        raise RuntimeError("redeem row is above its advertised snapshot tip")
    redeemer = row.get("from")
    if not isinstance(redeemer, str) or not (1 <= len(redeemer) <= 128):
        raise RuntimeError("redeem source identity is malformed")
    destination = row.get("memo")
    if (not isinstance(destination, str) or
            not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", destination) or
            len(destination) > 100):
        raise RuntimeError("redeem destination script is not canonical bounded hex")
    return {
        "burn_txid": txid,
        "opreturn_vout": vout,
        "redeemer": redeemer,
        "amount_sats": amount,
        "burn_height": height,
        "burn_block_hash": block_hash,
        "dest_spk_hex": destination.lower(),
    }


def read_canonical_redeems(veld_call, expected_tip, expected_tip_hash,
                           expected_token_id="btcVELD"):
    """Walk one exact Veld obligation snapshot, rejecting pagination ambiguity."""
    expected_tip = _uint(expected_tip, "expected Veld tip")
    expected_tip_hash = _hash256(expected_tip_hash, "expected Veld tip_hash")
    if not isinstance(expected_token_id, str) or not expected_token_id:
        raise RuntimeError("expected token id is missing")

    cursor = ""
    seen_cursors = {cursor}
    seen_outpoints = set()
    records = []
    previous_order_key = None
    authority = None
    commitment = RedeemCommitment()
    for _page_number in range(MAX_PAGES):
        page = veld_call("getbtcveldredeems", [cursor, str(PAGE_LIMIT)])
        if not isinstance(page, dict):
            raise RuntimeError("getbtcveldredeems returned no object")
        if (_uint(page.get("tip"), "redeem page tip") != expected_tip or
                _hash256(page.get("tip_hash"), "redeem page tip_hash") !=
                expected_tip_hash):
            raise RuntimeError("redeem page is not bound to the supply snapshot tip")
        page_authority = parse_page_authority(page)
        if authority is None:
            authority = page_authority
        elif page_authority != authority:
            raise RuntimeError(
                "redeem count/root authority changed between pages")
        final_height = _uint(page.get("final_height"), "redeem final_height")
        if final_height > expected_tip:
            raise RuntimeError("redeem final_height exceeds its snapshot tip")
        if page.get("cursor") != cursor:
            raise RuntimeError("redeem page did not echo the requested cursor")
        if page.get("page_limit") != PAGE_LIMIT:
            raise RuntimeError("redeem page did not honor the bounded page limit")
        has_more = page.get("has_more")
        if not isinstance(has_more, bool):
            raise RuntimeError("redeem page has_more is not boolean")
        rows = page.get("redeems")
        if not isinstance(rows, list) or len(rows) > PAGE_LIMIT:
            raise RuntimeError("redeem page rows are malformed or oversized")
        if has_more and len(rows) != PAGE_LIMIT:
            raise RuntimeError("redeem pagination advertises a gap/short interior page")

        for row in rows:
            commitment.add_rpc_row(row)
            record = _normalize_redeem(row, expected_token_id, expected_tip)
            outpoint = (record["burn_txid"], record["opreturn_vout"])
            if outpoint in seen_outpoints:
                raise RuntimeError("redeem pagination repeated a burn outpoint")
            order_key = (record["burn_height"], record["burn_txid"],
                         record["opreturn_vout"],
                         record["burn_block_hash"])
            if (previous_order_key is not None and
                    order_key <= previous_order_key):
                raise RuntimeError(
                    "redeem pagination is not in canonical index order")
            previous_order_key = order_key
            seen_outpoints.add(outpoint)
            records.append(record)

        next_cursor = page.get("next_cursor")
        if not isinstance(next_cursor, str) or len(next_cursor) > 256:
            raise RuntimeError("redeem page next_cursor is malformed")
        if not has_more:
            commitment.verify(*authority)
            return tuple(records)
        if not next_cursor or next_cursor in seen_cursors:
            raise RuntimeError("redeem pagination cursor did not advance uniquely")
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    raise RuntimeError("redeem pagination exceeded its safety bound")


def bitcoin_chain_identity(btc_call):
    """Return one canonical Bitcoin-mainnet tip identity."""
    info = btc_call("getblockchaininfo")
    if not isinstance(info, dict) or info.get("chain") != "main":
        raise RuntimeError("redemption-liability Bitcoin RPC is not mainnet")
    height = _uint(info.get("blocks"), "Bitcoin blocks")
    best = _hash256(info.get("bestblockhash"), "Bitcoin bestblockhash")
    if info.get("initialblockdownload") is True:
        raise RuntimeError("redemption-liability Bitcoin node is still in IBD")
    return height, best


def _marker_identity(script_hex):
    """Parse the one canonical payout marker, rejecting lookalike encodings."""
    if not isinstance(script_hex, str) or not HEX_RE.fullmatch(script_hex):
        raise RuntimeError("Bitcoin output script is not canonical lowercase hex")
    raw = bytes.fromhex(script_hex)
    if not raw or raw[0] != 0x6a:
        return None
    canonical_len = 2 + len(PAYOUT_MARKER_MAGIC) + 32 + 4
    if (len(raw) == canonical_len and raw[1] == 41 and
            raw[2:2 + len(PAYOUT_MARKER_MAGIC)] == PAYOUT_MARKER_MAGIC):
        data = raw[2:]
        return data[5:37].hex(), int.from_bytes(data[37:41], "big")
    # A payout-domain prefix in an alternate push form, wrong version, partial
    # payload, or script with trailing bytes is ambiguous and cannot release
    # backing.  Only inspect outgoing custody transactions so arbitrary third
    # parties cannot halt the watchtower by sending a lookalike marker to it.
    if b"VLDR" in raw:
        raise RuntimeError("outgoing transaction contains a malformed payout marker")
    return None


def _wallet_txids(btc_call):
    history = btc_call("listsinceblock")
    if not isinstance(history, dict):
        raise RuntimeError("listsinceblock returned no wallet history object")
    transactions = history.get("transactions")
    removed = history.get("removed")
    if not isinstance(transactions, list) or not isinstance(removed, list):
        raise RuntimeError("listsinceblock wallet history is incomplete")
    txids = set()
    for item in transactions + removed:
        if not isinstance(item, dict):
            raise RuntimeError("wallet history entry is malformed")
        txids.add(_hash256(item.get("txid"), "wallet history txid"))
    return tuple(sorted(txids))


def scan_outgoing_payouts(btc_call):
    """Scan complete wallet history and index exact outgoing marker candidates."""
    by_outpoint = {}
    for txid in _wallet_txids(btc_call):
        info = btc_call("gettransaction", txid)
        if not isinstance(info, dict):
            raise RuntimeError("gettransaction returned no wallet transaction")
        if "txid" in info and info.get("txid") != txid:
            raise RuntimeError("gettransaction returned the wrong transaction")
        details = info.get("details")
        if not isinstance(details, list) or any(not isinstance(x, dict) for x in details):
            raise RuntimeError("wallet transaction details are malformed")
        outgoing = any(x.get("category") == "send" for x in details)
        if not outgoing and "fee" in info:
            try:
                outgoing = Decimal(str(info["fee"])) < 0
            except (InvalidOperation, ValueError):
                raise RuntimeError("wallet transaction fee is malformed")
        if not outgoing:
            continue

        raw_hex = info.get("hex")
        if (not isinstance(raw_hex, str) or not raw_hex or
                not re.fullmatch(r"[0-9a-f]+", raw_hex) or len(raw_hex) % 2):
            raise RuntimeError("outgoing wallet transaction has malformed raw hex")
        decoded = btc_call("decoderawtransaction", raw_hex)
        if not isinstance(decoded, dict):
            raise RuntimeError("decoderawtransaction returned no object")
        if "txid" in decoded and decoded.get("txid") != txid:
            raise RuntimeError("decoded outgoing transaction has the wrong txid")
        vouts = decoded.get("vout")
        if not isinstance(vouts, list) or any(not isinstance(x, dict) for x in vouts):
            raise RuntimeError("decoded outgoing transaction outputs are malformed")

        outputs = []
        markers = []
        for vout in vouts:
            script = vout.get("scriptPubKey")
            if not isinstance(script, dict):
                raise RuntimeError("decoded output omitted scriptPubKey")
            script_hex = script.get("hex")
            marker = _marker_identity(script_hex)
            value_sats = btc_to_sats(vout.get("value"))
            outputs.append((script_hex, value_sats))
            if marker is not None:
                if value_sats != 0:
                    raise RuntimeError("payout marker output carries nonzero value")
                markers.append(marker)
        if not markers:
            continue
        if len(markers) != 1:
            raise RuntimeError("outgoing payout transaction has multiple markers")

        confirmations = info.get("confirmations")
        if (isinstance(confirmations, bool) or not isinstance(confirmations, int) or
                confirmations < 0 or confirmations > MAX_WIRE_INT):
            raise RuntimeError("marker-bearing payout has invalid/conflicted confirmations")
        conflicts = info.get("walletconflicts", [])
        if (not isinstance(conflicts, list) or
                any(not isinstance(x, str) or not HASH256_RE.fullmatch(x)
                    for x in conflicts)):
            raise RuntimeError("marker-bearing payout has malformed wallet conflicts")
        if info.get("abandoned") is True or conflicts:
            raise RuntimeError("marker-bearing payout is abandoned or conflicted")

        outpoint = markers[0]
        if outpoint in by_outpoint:
            raise RuntimeError("multiple outgoing payouts carry one burn marker")
        by_outpoint[outpoint] = {
            "txid": txid,
            "confirmations": confirmations,
            "outputs": tuple(outputs),
        }
    return by_outpoint


def backing_liability(supply_sats, redeems, payouts, required_confirmations):
    """Return (total liability, outstanding sats/count, released count)."""
    supply = _uint(supply_sats, "live btcVELD supply")
    required = _uint(required_confirmations, "required payout confirmations",
                     positive=True, maximum=1_000_000)
    if not isinstance(redeems, (list, tuple)) or not isinstance(payouts, dict):
        raise RuntimeError("redemption liability inputs have invalid types")

    outstanding_sats = 0
    outstanding_count = 0
    released_count = 0
    seen = set()
    for record in redeems:
        if not isinstance(record, dict):
            raise RuntimeError("normalized redemption record is malformed")
        outpoint = (record.get("burn_txid"), record.get("opreturn_vout"))
        if outpoint in seen:
            raise RuntimeError("normalized redemption set repeats an outpoint")
        seen.add(outpoint)
        payout = payouts.get(outpoint)
        released = False
        if payout is not None:
            if not isinstance(payout, dict):
                raise RuntimeError("payout candidate is malformed")
            paid = 0
            for script_hex, value_sats in payout.get("outputs", ()):
                if script_hex == record.get("dest_spk_hex"):
                    if paid > MAX_WIRE_INT - value_sats:
                        raise RuntimeError("payout destination sum overflows")
                    paid += value_sats
            if paid != record.get("amount_sats"):
                raise RuntimeError("payout marker has wrong destination or amount")
            confirmations = _uint(
                payout.get("confirmations"), "payout confirmations")
            released = confirmations >= required
        if released:
            released_count += 1
            continue
        amount = _uint(record.get("amount_sats"), "redeem amount_sats", positive=True)
        if outstanding_sats > MAX_WIRE_INT - amount:
            raise RuntimeError("outstanding redemption liability overflows")
        outstanding_sats += amount
        outstanding_count += 1

    if supply > MAX_WIRE_INT - outstanding_sats:
        raise RuntimeError("total btcVELD backing liability overflows")
    return (supply + outstanding_sats, outstanding_sats,
            outstanding_count, released_count)
