"""Guarded rolling-reserve adapter for the existing watchtower entry point."""
import json
import os
import time

import rtp1_service as lifecycle
import veld_custody_binding as custody
from rtp1_backing_evidence import _bitcoin_frame, _hash, _sats, _uint, MAX_BTC_SATS
from rpc_url_policy import run_bounded_subprocess
from veld_chain_identity import verify_expected_chain
from veld_watchtowerd import Watchtower


MAX_CUSTODY_UTXOS = 4096


def verify_wallet_descriptor(result, binding):
    entries = result.get("descriptors") if type(result) is dict else None
    if type(entries) is not list or len(entries) != 1 or type(entries[0]) is not dict:
        raise ValueError("watch-only wallet must contain one pinned descriptor")
    entry = entries[0]
    covered = entry.get("range")
    if (entry.get("desc") != binding["descriptor"] or entry.get("active") is not False or
            entry.get("internal", False) is not False or type(covered) is not list or len(covered) != 2 or
            any(type(value) is not int for value in covered) or covered[0] != 0 or
            not binding["range"][1] <= covered[1] <= 1_000_000):
        raise ValueError("watch-only descriptor does not cover the exact pinned authority")


def read_snapshot(config, veld, bitcoin, scripts):
    """Derive confirmed custody and all native reserve liabilities independently.

    Pending Bitcoin deposits count only as observed collateral. The issuer and
    witness must still prove the exact recipient-bound reserve transition. An
    unobserved or unfinalized payout cannot release native redemption principal.
    """
    config = lifecycle.configuration(config)
    if type(scripts) not in (tuple, list) or len(scripts) != 1000 or len(set(scripts)) != 1000:
        raise ValueError("complete verified custody script range is required")
    if config["custody_script_hex"] != scripts[0]:
        raise ValueError("rolling reserve differs from the verified custody range")
    verify_expected_chain(veld, config["expected_chain"])
    supply = veld("getbtcveldsupply", [])
    if type(supply) is not dict or set(supply) != {"supply_sats", "tip", "tip_hash"}:
        raise ValueError("coherent native supply is unavailable")
    amount = _uint(supply["supply_sats"], MAX_BTC_SATS, "native supply")
    height = _uint(supply["tip"], (1 << 63) - 1, "native height")
    tip = _hash(supply["tip_hash"], "native tip")
    peg = veld("getpeginfo", [])
    if (type(peg) is not dict or peg.get("reserve_semantics") != "rolling-outpoint-v1" or
            peg.get("reserve_status") not in {"EMPTY", "ACTIVE"} or peg.get("reserve_accounting_holds") is not True or
            peg.get("tip") != height or peg.get("supply_sats") != amount or
            type(peg.get("tip")) is not int or type(peg.get("supply_sats")) is not int or
            peg.get("custody_descriptor_sha256") != config["custody_descriptor_sha256"] or
            peg.get("custody_manifest_sha256") != config["custody_manifest_sha256"] or
            peg.get("issuer") != config["issuer"] or peg.get("token_id") != "btcVELD"):
        raise ValueError("native reserve and supply are inconsistent or frozen")
    principal = _uint(peg.get("open_redemption_principal_sats"), MAX_BTC_SATS, "unsettled redemption principal")
    represented = _uint(peg.get("reserve_value_sats"), MAX_BTC_SATS, "represented reserve")
    surplus = _uint(peg.get("reserve_surplus_sats"), MAX_BTC_SATS, "reserve surplus")
    liability = amount + principal
    if liability > MAX_BTC_SATS or represented != liability + surplus:
        raise ValueError("native reserve conservation failed")
    before = _bitcoin_frame(bitcoin, config["bitcoin_network"], config["bitcoin_genesis"])
    rows = bitcoin("listunspent", [config["minimum_confirmations"], 9999999, [], True])
    if type(rows) is not list or len(rows) > MAX_CUSTODY_UTXOS:
        raise ValueError("custody inventory exceeds its bounded snapshot")
    known, seen, total = set(scripts), set(), 0
    for row in rows:
        if type(row) is not dict:
            raise ValueError("custody inventory row is not an object")
        txid = _hash(row.get("txid"), "custody transaction")
        vout = _uint(row.get("vout"), 0xffffffff, "custody output")
        confirmations = _uint(row.get("confirmations"), (1 << 31) - 1, "custody confirmations", config["minimum_confirmations"])
        if (txid, vout) in seen or row.get("scriptPubKey") not in known:
            raise ValueError("custody inventory repeats an output or contains an unrelated script")
        seen.add((txid, vout))
        value = _sats(row.get("amount"))
        coin = bitcoin("gettxout", [txid, vout, True])
        if (type(coin) is not dict or coin.get("bestblock") != before[1] or
                type(coin.get("confirmations")) is not int or coin["confirmations"] != confirmations or
                type(coin.get("scriptPubKey")) is not dict or coin["scriptPubKey"].get("hex") != row["scriptPubKey"] or
                _sats(coin.get("value")) != value):
            raise ValueError("custody output was spent or changed during observation")
        total += value
        if total > MAX_BTC_SATS:
            raise ValueError("custody total exceeds Bitcoin's monetary bound")
    if (_bitcoin_frame(bitcoin, config["bitcoin_network"], config["bitcoin_genesis"]) != before or
            veld("getbtcveldsupply", []) != supply or veld("getblockhash", [height]) != tip):
        raise ValueError("chain changed during the independent custody snapshot")
    return {"custody_sats": total, "supply_sats": amount, "backing_liability_sats": liability,
        "open_redemption_principal_sats": principal, "tip": height, "tip_hash": tip,
        "bitcoin_height": before[0], "bitcoin_hash": before[1], "utxo_count": len(seen)}


class Rtp1Watchtower(Watchtower):
    def _core(self, method, *params):
        return self.btc.call(method, *(value if type(value) is str else json.dumps(value, allow_nan=False)
                                       for value in params))

    def __init__(self, cfg):
        self.rtp1 = lifecycle.configuration(cfg.get("rtp1_service"))
        if cfg.get("production") is not True or cfg.get("veld_rpc", {}).get("expected_chain") != self.rtp1["expected_chain"]:
            raise ValueError("RTP1 watchtower requires its strict entry point and exact disposable chain pins")
        self.receiver_command = cfg.get("signer", {}).get("receiver_command")
        if self.receiver_command is not None:
            argv = self.receiver_command
            if (type(argv) is not list or not 1 <= len(argv) <= 16 or
                    any(type(arg) is not str or not arg or len(arg) > 4096 or "\x00" in arg for arg in argv) or
                    not os.path.isabs(argv[0])):
                raise ValueError("local disposable heartbeat receiver requires bounded absolute argv")
            from veld_signerd import _secure_regular
            _secure_regular(argv[0], executable=True)
        super().__init__(cfg)

    def _configure_production_custody(self, btc_cfg, cfg):
        if self.btc_api or self.btc is None or not btc_cfg.get("wallet") or self.custody_addresses or self.custody_desc_file:
            raise ValueError("RTP1 requires exactly one independently configured watch-only Core wallet")
        binding = custody.load_manifest(cfg.get("custody_spk_manifest_file"), self.rtp1["custody_descriptor_sha256"],
            self.rtp1["custody_manifest_sha256"], expected_spv_spk_hex=self.rtp1["custody_script_hex"], network="regtest")
        wallet = self._core("getwalletinfo")
        if type(wallet) is not dict or wallet.get("private_keys_enabled") is not False:
            raise ValueError("RTP1 custody observer must not hold Bitcoin private keys")
        verify_wallet_descriptor(self._core("listdescriptors"), binding)
        custody.verify_core_derivation(self._core, binding, expected_hrp="bcrt")
        self.production_binding, self.production_descriptor = binding, binding["descriptor"]
        self.production_spks = set(binding["script_pubkeys"])
        self._production_bitcoin_chain_identity()
        if self.k_confs != self.rtp1["minimum_confirmations"]:
            raise ValueError("RTP1 watchtower confirmation policy differs")

    def _production_bitcoin_chain_identity(self):
        frame = _bitcoin_frame(lambda method, params: self._core(method, *params), "regtest", self.rtp1["bitcoin_genesis"])
        header = self._core("getblockheader", frame[1], True)
        stamp = header.get("time") if type(header) is dict else None
        if type(stamp) is not int or not int(time.time()) - 7200 < stamp <= int(time.time()) + 7200:
            raise ValueError("RTP1 Bitcoin observation is stale or future-dated")
        return frame

    def _verify_production_veld_identity(self):
        verify_expected_chain(self.veld.rpc, self.rtp1["expected_chain"])
        peg = self.veld.rpc("getpeginfo")
        custody.verify_peg_identity(peg, self.production_binding, network="regtest")
        compiled = _uint(peg.get("spv_k_btc"), 1_000_000, "compiled Bitcoin confirmation policy", 1)
        if peg.get("issuer") != self.rtp1["issuer"] or compiled > self.k_confs:
            raise ValueError("RTP1 compiled issuer or confirmation policy differs")
        return peg

    def read_production_backing_snapshot(self, supply, tip, tip_hash):
        self._production_bitcoin_chain_identity()
        snapshot = read_snapshot(self.rtp1, self.veld.rpc,
            lambda method, params: self._core(method, *params), self.production_binding["script_pubkeys"])
        if (snapshot["supply_sats"], snapshot["tip"], snapshot["tip_hash"]) != (supply, tip, tip_hash):
            raise ValueError("native supply moved during the watchtower cycle")
        self.last_liability_stats = snapshot
        return snapshot["custody_sats"], snapshot["backing_liability_sats"]

    def _push(self, payload):
        if self.receiver_command is None:
            return super()._push(payload)
        result = run_bounded_subprocess(self.receiver_command, input_text=json.dumps(payload), timeout=45,
            stdout_max=65536, stderr_max=65536, description="disposable heartbeat receiver")
        if result.returncode:
            raise ValueError("RTP1 heartbeat receiver refused delivery")
        return result.stdout.strip()
