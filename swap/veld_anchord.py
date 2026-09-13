#!/usr/bin/env python3
"""
veld_anchord.py - btcVELD Layer-2 Bitcoin checkpoint-anchoring daemon (51%-attack defense).

Periodically commits a Veld block hash into a REAL Bitcoin transaction, then relays that
anchor (with an SPV Merkle proof) back onto the Veld chain. Once the anchor's Bitcoin tx is
>= K_BTC deep, Veld consensus REJECTS any chain that rewrites the anchored height regardless
of PoW work - the peg borrows Bitcoin's immutability instead of relying on Veld's hashrate.

Two-step, low-frequency (bound real-BTC fee usage):

  1. COMMIT : build a Bitcoin OP_RETURN tx  "VELD_ANCHOR:" | veld_height(u64 LE) | veld_hash(32)
              funded from a LEGACY (P2PKH) UTXO so the tx is witnessless => its txid is over the
              exact bytes we relay (Bitcoin txids hash the non-witness serialization).
  2. RELAY  : once the commit tx has K_BTC blocks buried behind it (K_BTC+1 Bitcoin Core
              confirmations), build the Merkle proof of its
              inclusion and post a VELD_ANCHOR op ("VELD_ANCHOR|"<hex ANCH payload>) to Veld via
              preparerawop -> veld-keygen sign-op -> sendrawtransaction. FeedAnchors_/VerifyAnchor
              proves it against the in-consensus BTC header chain (fed by veld_btcrelayd) and
              records it. First-seen wins.

  ANCH payload = "ANCH" | btc_block_hash(32 LE) | dirs(u32 LE) | mlen(u8) | mlen*branch(32 LE) | legacy_tx
  state        : <state>/anchor_state.json  (prepared/committed/submitted/confirmed; idempotent)
  lock         : <state>/anchord.lock       (single-writer)

Fail-closed: the complete signed Bitcoin transaction is fsynced as PREPARED before broadcast;
later states advance only after the corresponding external step provably lands. A crash retries
the exact bytes/txid. A dropped/re-orged commit tx can be superseded by a later cadence target
(Veld dedupes by btc_txid; first-seen wins).
"""
import json, os, sys, subprocess, time, re, stat, urllib.request, tempfile, hashlib, struct
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from rpc_url_policy import open_rpc_request, validate_backend_rpc_url  # noqa: E402

try:
    import fcntl
except ImportError:
    fcntl = None

ANCH_MAGIC   = b"ANCH"
BTC_TAG      = b"VELD_ANCHOR:"          # the Bitcoin-side OP_RETURN tag
VELD_PREFIX  = "VELD_ANCHOR|"           # the Veld-side op prefix (then hex(ANCH payload))
MAX_CONFIG_BYTES = 64 * 1024
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_TRACKED_ANCHORS = 100000
MIN_LOOP_SECS = 5
MAX_LOOP_SECS = 3600
MIN_RESUBMIT_SECS = 30
MAX_RESUBMIT_SECS = 86400
MAX_HEIGHT = 100000000
MAX_BTC_SATS = 21_000_000 * 100_000_000
PRODUCTION_ANCHOR_K_BTC = 6
PRODUCTION_RELAY_RESUBMIT_SECS = 3_600
PRODUCTION_ANCHOR_MAX_VSIZE = 400
PRODUCTION_FEE_CONF_TARGET = 6
PRODUCTION_FEE_FALLBACK_SVB = Decimal("20")
PRODUCTION_MAX_FEE_SATS = 20_000
PRODUCTION_ANCHOR_DEADLINE_BLOCKS = 960
PRODUCTION_ANCHOR_MIN_SPACING_BLOCKS = 480
PRODUCTION_FEE_TARGET_SVB = Decimal("5")
PRODUCTION_FEE_CEILING_SVB = Decimal("50")
PRODUCTION_TIP_ALERT_SECS = 3_600
PRODUCTION_MAX_TIP_AGE_SECS = 7_200
MAX_FEE_CONVERGENCE_PASSES = 8


class ConfigError(RuntimeError):
    pass


def log(m):  sys.stdout.write("  " + m + "\n"); sys.stdout.flush()
def warn(m): sys.stderr.write("  [WARN] " + m + "\n"); sys.stderr.flush()


def _strict_int(value, name, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise RuntimeError(f"{name} must be an integer in [{low},{high}]")
    return value


def _strict_decimal(value, name, low, high):
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        raise RuntimeError(f"{name} must be a finite decimal in [{low},{high}]")
    try:
        out = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise RuntimeError(f"{name} must be a finite decimal in [{low},{high}]") from exc
    if not out.is_finite() or out < Decimal(str(low)) or out > Decimal(str(high)):
        raise RuntimeError(f"{name} must be a finite decimal in [{low},{high}]")
    return out


def _private_regular_file(path, name, max_bytes=None):
    if not isinstance(path, str) or not os.path.isabs(path):
        raise RuntimeError(f"{name} must be an absolute path")
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid()) or
            info.st_nlink != 1 or (info.st_mode & 0o077) != 0):
        raise RuntimeError(
            f"{name} must be a root/service-owned, single-link, mode-0600 regular file")
    if max_bytes is not None and info.st_size > max_bytes:
        raise RuntimeError(f"{name} exceeds its size limit")
    return info


def _trusted_executable(path, name):
    if not isinstance(path, str) or not os.path.isabs(path):
        raise RuntimeError(f"{name} must be an absolute executable path")
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid()) or
            info.st_nlink != 1 or (info.st_mode & 0o022) != 0 or
            not os.access(path, os.X_OK)):
        raise RuntimeError(f"{name} is not a trusted root/service-owned executable")


def _secure_state_dir(path, create=False):
    if not isinstance(path, str) or not os.path.isabs(path):
        raise RuntimeError("state_dir must be an explicit absolute path")
    if create:
        os.makedirs(path, mode=0o700, exist_ok=True)
    info = os.lstat(path)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
            (info.st_mode & 0o777) != 0o700):
        raise RuntimeError(
            "state_dir must be a service-owned non-symlink mode-0700 directory")


def _read_private_json(path, name, max_bytes):
    _private_regular_file(path, name, max_bytes)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid()) or
                info.st_nlink != 1 or (info.st_mode & 0o077) != 0 or
                info.st_size > max_bytes):
            raise RuntimeError(f"unsafe {name}")
        data = b""
        while len(data) <= max_bytes:
            chunk = os.read(fd, min(65536, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        if len(data) > max_bytes:
            raise RuntimeError(f"{name} exceeds its size limit")
    finally:
        os.close(fd)
    try:
        return json.loads(data.decode("utf-8"), parse_float=Decimal)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{name} is not strict UTF-8 JSON") from exc


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def be_to_le(hex_be):
    """bitcoind display hash (BE hex) -> internal little-endian 32 bytes."""
    return bytes.fromhex(hex_be)[::-1]


def build_branch(txids_le, idx):
    """Bitcoin Merkle branch for leaf `idx`. txids_le: list of 32-byte INTERNAL (LE) hashes.
    Returns (branch: list[bytes32], dirs: int, root: bytes32). Mirrors buildBranch in
    mainnet-launch/dryrun/repro_btcveld_e2e.cpp exactly (dir bit 1 == sibling is LEFT)."""
    level = list(txids_le)
    branch = []
    dirs = 0
    i = 0
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])          # Bitcoin duplicates the last node on an odd level
        sib = idx ^ 1
        branch.append(level[sib])
        if sib < idx:
            dirs |= (1 << i)                 # sibling is to the LEFT
        nxt = [dsha(level[j] + level[j + 1]) for j in range(0, len(level), 2)]
        level = nxt
        idx >>= 1
        i += 1
    root = level[0] if level else b"\x00" * 32
    return branch, dirs, root


def _validate_production_rpc(rpc):
    if not isinstance(rpc, dict):
        raise RuntimeError("veld_rpc must be an object")
    if set(rpc) - {"url", "token_cmd", "token_file"}:
        raise RuntimeError("veld_rpc contains unknown fields")
    url = validate_backend_rpc_url(rpc.get("url"), "veld_rpc.url")
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or
            parsed.path not in ("", "/") or parsed.port is None):
        raise RuntimeError("production veld_rpc.url must be exact http://127.0.0.1:PORT")
    cmd = rpc.get("token_cmd")
    token_file = rpc.get("token_file")
    if bool(cmd) == bool(token_file):
        raise RuntimeError(
            "production anchord requires exactly one RPC token source")
    if token_file:
        if token_file != "/run/veld-anchord/rpc.token":
            raise RuntimeError(
                "production anchord token_file must be its exact private runtime file")
        _private_regular_file(token_file, "veld_rpc.token_file", 4096)
        return
    if (not isinstance(cmd, list) or not 2 <= len(cmd) <= 8 or
            not all(isinstance(v, str) and v and "\x00" not in v for v in cmd)):
        raise RuntimeError("production veld_rpc.token_cmd must be a bounded argv array")
    _trusted_executable(cmd[0], "veld_rpc.token_cmd executable")
    if (os.path.basename(cmd[0]) not in (
            "veld-node", "veld-node.exe", "veld-node-tokentool") or
            cmd.count("--print-rpc-token") != 1):
        raise RuntimeError(
            "token_cmd must invoke veld-node or veld-node-tokentool "
            "with --print-rpc-token")
    datadirs = []
    for index, arg in enumerate(cmd[1:], 1):
        if arg == "--datadir" and index + 1 < len(cmd):
            datadirs.append(cmd[index + 1])
        elif arg.startswith("--datadir="):
            datadirs.append(arg.split("=", 1)[1])
    if len(datadirs) != 1 or not os.path.isabs(datadirs[0]):
        raise RuntimeError("token_cmd must bind one absolute veld-node datadir")


def validate_config(cfg):
    if not isinstance(cfg, dict):
        raise RuntimeError("config must be a JSON object")
    if "anchor_lag" in cfg:
        raise RuntimeError(
            "anchor_lag is retired; R1 anchors the latest finalized checkpoint")
    allowed = {
        "production", "state_dir", "cli_base", "btc_wallet", "btc_rpc_timeout",
        "veld_rpc", "fund_addr", "btc_fund_addr", "signer", "k_btc",
        "relay_resubmit_timeout_secs", "anchor_tx_vsize", "fee_conf_target",
        "fee_fallback_sat_vb", "max_fee_sats", "btc_fee_sats",
        "anchor_deadline_blocks", "anchor_min_spacing_blocks",
        "fee_cheap_sat_vb", "fee_ceiling_sat_vb",
        "tip_age_alert_secs", "max_tip_age_secs",
        "regtest_generate",
    }
    if set(cfg) - allowed:
        raise RuntimeError("config contains unknown fields")
    production = cfg.get("production") is True
    _secure_state_dir(cfg.get("state_dir"), create=True)

    cli = cfg.get("cli_base")
    if (not isinstance(cli, list) or not 1 <= len(cli) <= 16 or
            not all(isinstance(v, str) and v and "\x00" not in v for v in cli)):
        raise RuntimeError("cli_base must be a bounded argv array")
    _trusted_executable(cli[0], "bitcoin-cli")
    if os.path.basename(cli[0]) not in ("bitcoin-cli", "bitcoin-cli.exe"):
        raise RuntimeError("cli_base must invoke bitcoin-cli")
    if production:
        datadirs = [v.split("=", 1)[1] for v in cli[1:] if v.startswith("-datadir=")]
        if len(datadirs) != 1 or not os.path.isabs(datadirs[0]):
            raise RuntimeError("production cli_base needs one absolute -datadir= path")
        _validate_production_rpc(cfg.get("veld_rpc"))
    else:
        rpc = cfg.get("veld_rpc")
        if not isinstance(rpc, dict):
            raise RuntimeError("veld_rpc must be an object")
        validate_backend_rpc_url(rpc.get("url"), "veld_rpc.url")

    wallet = cfg.get("btc_wallet")
    if (not isinstance(wallet, str) or not wallet or len(wallet) > 128 or
            "\x00" in wallet or wallet != wallet.strip()):
        raise RuntimeError("btc_wallet must name one explicit bounded wallet")
    _strict_int(cfg.get("btc_rpc_timeout", 30), "btc_rpc_timeout", 5, 300)
    fund = cfg.get("fund_addr")
    if not isinstance(fund, str) or not re.fullmatch(r"V[1-9A-HJ-NP-Za-km-z]{25,60}", fund):
        raise RuntimeError("fund_addr is not a canonical-looking Veld address")
    btc_fund = cfg.get("btc_fund_addr")
    if (not isinstance(btc_fund, str) or not 14 <= len(btc_fund) <= 90 or
            not re.fullmatch(r"[A-Za-z0-9]+", btc_fund)):
        raise RuntimeError("btc_fund_addr is malformed")
    signer = cfg.get("signer")
    if not isinstance(signer, dict) or set(signer) - {"keygen", "keyfile", "passphrase"}:
        raise RuntimeError("signer config is malformed")
    _trusted_executable(signer.get("keygen"), "signer.keygen")
    if os.path.basename(signer["keygen"]) not in ("veld-keygen", "veld-keygen.exe"):
        raise RuntimeError("signer.keygen must invoke veld-keygen")
    _private_regular_file(signer.get("keyfile"), "signer.keyfile", 1024 * 1024)
    if production and signer.get("passphrase"):
        raise RuntimeError("production signer passphrase must come from the service environment")

    # Production economics/security cadence is owner policy. Refuse hidden
    # defaults and drift: every value must be explicit, relationally sound,
    # and equal to the approved launch profile checked below.
    explicit_policy = {
        "relay_resubmit_timeout_secs", "anchor_tx_vsize", "fee_conf_target",
        "fee_fallback_sat_vb", "max_fee_sats", "anchor_deadline_blocks",
        "anchor_min_spacing_blocks", "fee_cheap_sat_vb",
        "fee_ceiling_sat_vb", "tip_age_alert_secs", "max_tip_age_secs",
    }
    if production and not explicit_policy.issubset(cfg):
        raise RuntimeError("production anchord requires every fee/cadence field explicitly")
    if "max_fee_sats" in cfg and "btc_fee_sats" in cfg:
        raise RuntimeError("use max_fee_sats only; btc_fee_sats is legacy")
    k_btc = _strict_int(cfg.get("k_btc", 3), "k_btc", 1, 1000)
    if production and k_btc != PRODUCTION_ANCHOR_K_BTC:
        raise RuntimeError(
            f"production k_btc must equal the configured value "
            f"{PRODUCTION_ANCHOR_K_BTC}")
    resubmit = _strict_int(cfg.get("relay_resubmit_timeout_secs", 600),
                           "relay_resubmit_timeout_secs", MIN_RESUBMIT_SECS,
                           MAX_RESUBMIT_SECS)
    max_vsize = _strict_int(cfg.get("anchor_tx_vsize", 260),
                            "anchor_tx_vsize", 1, 100000)
    fee_conf_target = _strict_int(
        cfg.get("fee_conf_target", PRODUCTION_FEE_CONF_TARGET),
        "fee_conf_target", 1, 1008)
    fallback = _strict_decimal(cfg.get("fee_fallback_sat_vb", 5),
                               "fee_fallback_sat_vb", "0.00000001", "1000000")
    max_fee = _strict_int(cfg.get("max_fee_sats", cfg.get("btc_fee_sats", 10000)),
                          "max_fee_sats", 1, MAX_BTC_SATS)
    if max_fee < max_vsize:
        raise RuntimeError("max_fee_sats must cover at least 1 sat/vB at anchor_tx_vsize")
    deadline = _strict_int(cfg.get("anchor_deadline_blocks", 40),
                           "anchor_deadline_blocks", 1, 1000000)
    spacing = _strict_int(cfg.get("anchor_min_spacing_blocks", 18),
                          "anchor_min_spacing_blocks", 1, 1000000)
    if spacing > deadline:
        raise RuntimeError("anchor_min_spacing_blocks must not exceed anchor_deadline_blocks")
    cheap = _strict_decimal(cfg.get("fee_cheap_sat_vb", 3),
                            "fee_cheap_sat_vb", "0.00000001", "1000000")
    ceiling = _strict_decimal(cfg.get("fee_ceiling_sat_vb", 25),
                              "fee_ceiling_sat_vb", "0.00000001", "1000000")
    if cheap > ceiling:
        raise RuntimeError("fee_cheap_sat_vb must not exceed fee_ceiling_sat_vb")
    tip_alert = _strict_int(
        cfg.get("tip_age_alert_secs", PRODUCTION_TIP_ALERT_SECS),
        "tip_age_alert_secs", 600, 86_400)
    max_tip_age = _strict_int(
        cfg.get("max_tip_age_secs", PRODUCTION_MAX_TIP_AGE_SECS),
        "max_tip_age_secs", 600, 86_400)
    if tip_alert >= max_tip_age:
        raise RuntimeError("tip_age_alert_secs must be below max_tip_age_secs")
    if production and (tip_alert != PRODUCTION_TIP_ALERT_SECS or
                       max_tip_age != PRODUCTION_MAX_TIP_AGE_SECS):
        raise RuntimeError(
            "production Bitcoin freshness must use the configured "
            "3600-second alert and 7200-second hard limit")
    if production:
        approved = {
            "relay_resubmit_timeout_secs": (
                resubmit, PRODUCTION_RELAY_RESUBMIT_SECS),
            "anchor_tx_vsize": (max_vsize, PRODUCTION_ANCHOR_MAX_VSIZE),
            "fee_conf_target": (
                fee_conf_target, PRODUCTION_FEE_CONF_TARGET),
            "fee_fallback_sat_vb": (fallback, PRODUCTION_FEE_FALLBACK_SVB),
            "max_fee_sats": (max_fee, PRODUCTION_MAX_FEE_SATS),
            "anchor_deadline_blocks": (
                deadline, PRODUCTION_ANCHOR_DEADLINE_BLOCKS),
            "anchor_min_spacing_blocks": (
                spacing, PRODUCTION_ANCHOR_MIN_SPACING_BLOCKS),
            "fee_cheap_sat_vb": (cheap, PRODUCTION_FEE_TARGET_SVB),
            "fee_ceiling_sat_vb": (ceiling, PRODUCTION_FEE_CEILING_SVB),
        }
        wrong = [name for name, (actual, expected) in approved.items()
                 if actual != expected]
        if wrong:
            raise RuntimeError(
                "production anchord policy differs from the compiled "
                "launch values: " + ", ".join(wrong))
    if not isinstance(cfg.get("regtest_generate", False), bool):
        raise RuntimeError("regtest_generate must be a JSON boolean")
    if production and cfg.get("regtest_generate", False):
        raise RuntimeError("production anchord forbids regtest_generate")
    return cfg


# ------------------------------------------------------------------ RPC clients
class Btc:
    def __init__(self, cli_base, wallet=None, timeout=30):
        self.base = list(cli_base) + ([f"-rpcwallet={wallet}"] if wallet else [])
        self.timeout = timeout

    def call(self, method, *args):
        out = subprocess.run(self.base + [method] + [str(a) for a in args],
                             capture_output=True, text=True, timeout=self.timeout)
        if out.returncode != 0:
            raise RuntimeError(f"bitcoin-cli {method}: {out.stderr.strip()}")
        s = out.stdout.strip()
        try:
            return json.loads(s, parse_float=Decimal)
        except (json.JSONDecodeError, ValueError):
            return s

    def call_raw(self, method, *args):
        out = subprocess.run(self.base + [method] + [str(a) for a in args],
                             capture_output=True, text=True, timeout=self.timeout)
        if out.returncode != 0:
            raise RuntimeError(f"bitcoin-cli {method}: {out.stderr.strip()}")
        return out.stdout.strip()


class Veld:
    def __init__(self, url, token_file=None, token_cmd=None):
        self.url = validate_backend_rpc_url(url, "veld_rpc.url")
        self.token = ""
        if token_cmd:
            if (not isinstance(token_cmd, list) or not token_cmd or
                    not all(isinstance(x, str) and x and "\x00" not in x for x in token_cmd)):
                raise RuntimeError("rpc token_cmd must be a non-empty argv array")
            out = subprocess.run(list(token_cmd), capture_output=True, text=True, timeout=30)
            if out.returncode != 0:
                raise RuntimeError("rpc token_cmd failed: " + out.stderr.strip()[:200])
            self.token = out.stdout.strip()
        elif token_file and os.path.exists(token_file):
            _private_regular_file(token_file, "veld_rpc.token_file", 4096)
            with open(token_file, "r", encoding="ascii") as source:
                self.token = source.read(4097).strip()
        if not re.fullmatch(r"[0-9a-f]{64}", self.token):
            raise RuntimeError("veld RPC token helper did not return one lowercase 64-hex token")

    def rpc(self, method, params=None):
        body = json.dumps({"jsonrpc": "2.0", "id": 1,
                           "method": method, "params": params or []}).encode()
        req = urllib.request.Request(self.url, data=body, headers={
            "Authorization": "Bearer " + self.token,
            "Content-Type": "application/json"})
        with open_rpc_request(req, timeout=30) as response:
            r = json.load(response)
        if not isinstance(r, dict):
            raise RuntimeError(f"{method}: malformed RPC envelope")
        if r.get("error"):
            raise RuntimeError(f"{method}: {r['error']}")
        return r.get("result")


class LocalSigner:
    """Signs with strict `veld-keygen sign-op` (fees only, no peg power)."""
    def __init__(self, keygen, keyfile, passphrase, workdir):
        self.keygen = keygen; self.keyfile = keyfile
        self.passphrase = passphrase; self.workdir = workdir

    def sign(self, unsigned_tx_hex, prev_script_hex):
        with tempfile.NamedTemporaryFile("w", suffix=".json", dir=self.workdir, delete=False) as tf:
            json.dump({"unsigned_tx_hex": unsigned_tx_hex, "prev_script_hex": prev_script_hex},
                      tf, separators=(",", ":"))
            prep = tf.name
        outp = prep + ".signed"
        try:
            # fees-only hot key: use the config passphrase if given, else inherit
            # VELD_VAULT_PASSPHRASE from the environment (EnvironmentFile=/etc/veld/env)
            # so no plaintext passphrase need live in the config file.
            senv = {**os.environ}
            if self.passphrase:
                senv["VELD_VAULT_PASSPHRASE"] = self.passphrase
            r = subprocess.run([self.keygen, "sign-op", self.keyfile, prep, "--out", outp],
                               input="", env=senv,
                               capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                raise RuntimeError("veld-keygen sign-op failed: " + r.stderr.strip()[:200])
            with open(outp, "r", encoding="ascii") as source:
                signed = source.read(2 * 1024 * 1024 + 1).strip()
            if len(signed) > 2 * 1024 * 1024:
                raise RuntimeError("signer output exceeds its size limit")
            if not re.match(r'^[0-9a-fA-F]+$', signed) or len(signed) < 100:
                raise RuntimeError("signer produced no valid signed tx")
            return signed
        finally:
            for p in (prep, outp):
                try: os.remove(p)
                except OSError: pass


def save_json(path, obj):
    parent = os.path.dirname(os.path.abspath(path))
    _secure_state_dir(parent)
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".",
                               suffix=".tmp", dir=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as out:
            fd = -1
            json.dump(obj, out, indent=2)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        dfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def btc_amount_to_sats(value, name="Bitcoin amount"):
    try:
        amount = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise RuntimeError(f"{name} is not an exact decimal amount") from exc
    scaled = amount * Decimal(100_000_000)
    if (not amount.is_finite() or scaled != scaled.to_integral_value() or
            scaled < 0 or scaled > MAX_BTC_SATS):
        raise RuntimeError(f"{name} is not an exact non-negative satoshi amount")
    return int(scaled)


def sats_json_number(sats):
    _strict_int(sats, "satoshi amount", 0, MAX_BTC_SATS)
    return f"{sats // 100_000_000}.{sats % 100_000_000:08d}"


def load_anchor_state(path):
    if not os.path.exists(path):
        return {"anchors": {}}
    obj = _read_private_json(path, "anchor_state.json", MAX_STATE_BYTES)
    if not isinstance(obj, dict) or set(obj) != {"anchors"} or not isinstance(obj["anchors"], dict):
        raise RuntimeError("anchor_state.json has an invalid schema")
    if len(obj["anchors"]) > MAX_TRACKED_ANCHORS:
        raise RuntimeError("anchor_state.json exceeds the tracked-anchor bound")
    allowed_status = {"prepared", "committed", "submitted", "confirmed", "relayed"}
    allowed_fields = {
        "veld_hash", "btc_txid", "btc_tx_hex", "status", "at", "fee_sats",
        "feerate_sat_vb", "veld_op_txid", "submitted_at", "confirmed_at",
    }
    for key, rec in obj["anchors"].items():
        if (not isinstance(key, str) or not re.fullmatch(r"[1-9][0-9]*", key) or
                int(key) > MAX_HEIGHT or not isinstance(rec, dict) or
                set(rec) - allowed_fields):
            raise RuntimeError("anchor_state.json contains a malformed record")
        if rec.get("status") not in allowed_status:
            raise RuntimeError("anchor_state.json contains an invalid status")
        if not isinstance(rec.get("veld_hash"), str) or not re.fullmatch(
                r"[0-9a-f]{64}", rec["veld_hash"]):
            raise RuntimeError("anchor_state.json contains an invalid Veld hash")
        if not isinstance(rec.get("btc_txid"), str) or not re.fullmatch(
                r"[0-9a-f]{64}", rec["btc_txid"]):
            raise RuntimeError("anchor_state.json contains an invalid Bitcoin txid")
        raw = rec.get("btc_tx_hex")
        if raw is not None:
            if (not isinstance(raw, str) or len(raw) > 2 * 1024 * 1024 or
                    len(raw) % 2 or not re.fullmatch(r"[0-9a-f]+", raw)):
                raise RuntimeError("anchor_state.json contains invalid Bitcoin transaction bytes")
            if dsha(bytes.fromhex(raw))[::-1].hex() != rec["btc_txid"]:
                raise RuntimeError("anchor_state.json Bitcoin txid does not match exact bytes")
        if rec["status"] == "prepared" and raw is None:
            raise RuntimeError("prepared anchor lacks exact rebroadcast bytes")
        for field in ("at", "fee_sats", "submitted_at", "confirmed_at"):
            if field in rec:
                _strict_int(rec[field], f"anchor_state.{field}", 0, MAX_BTC_SATS)
        if "feerate_sat_vb" in rec:
            rec["feerate_sat_vb"] = str(_strict_decimal(
                rec["feerate_sat_vb"], "anchor_state.feerate_sat_vb",
                "0.00000001", "1000000"))
        for field in ("veld_op_txid",):
            if field in rec and (not isinstance(rec[field], str) or
                                 not re.fullmatch(r"[0-9a-f]{64}", rec[field])):
                raise RuntimeError(f"anchor_state.json contains an invalid {field}")
    return obj


# ------------------------------------------------------------------ the anchor daemon
class Anchor:
    def __init__(self, cfg):
        self.cfg = cfg
        self.production = cfg.get("production") is True
        self.state_dir = cfg["state_dir"]
        self.btc = Btc(cfg["cli_base"], cfg.get("btc_wallet"),
                       cfg.get("btc_rpc_timeout", 30))
        self.veld = Veld(cfg["veld_rpc"]["url"], cfg["veld_rpc"].get("token_file"),
                         cfg["veld_rpc"].get("token_cmd"))
        self.fund_addr = cfg["fund_addr"]                 # Veld fee funder (posts the VELD_ANCHOR op)
        self.btc_fund_addr = cfg["btc_fund_addr"]         # a LEGACY (P2PKH) BTC addr with UTXOs
        sc = cfg["signer"]
        self.signer = LocalSigner(sc["keygen"], sc["keyfile"], sc.get("passphrase", ""),
                                  self.state_dir)
        self.k_btc = int(cfg.get("k_btc", PRODUCTION_ANCHOR_K_BTC))
        self.relay_resubmit_secs = int(cfg.get("relay_resubmit_timeout_secs", 600))
        # --- dynamic fee: pay tx_vsize * market_feerate, NOT a flat sat amount. The old
        #     flat `btc_fee_sats` (20k) overpaid ~25-75x on a ~255 vB tx; it now serves
        #     ONLY as an absolute per-tx safety ceiling (max_fee_sats). -----------------
        # This is a hard bug-catch ceiling, not the fee estimate. The exact
        # signed transaction vsize is measured below and the transaction is
        # rebuilt to pay exactly ceil(actual_vsize * selected_rate).
        self.max_vsize        = int(cfg.get("anchor_tx_vsize", PRODUCTION_ANCHOR_MAX_VSIZE))
        self.fee_conf_target  = int(cfg.get("fee_conf_target", PRODUCTION_FEE_CONF_TARGET))
        self.fee_fallback_svb = _strict_decimal(cfg.get("fee_fallback_sat_vb", PRODUCTION_FEE_FALLBACK_SVB), "fee_fallback_sat_vb", "0.00000001", "1000000")
        self.max_fee_sats     = int(cfg.get("max_fee_sats", cfg.get("btc_fee_sats", PRODUCTION_MAX_FEE_SATS)))
        # --- fee-aware cadence: anchor at cheap dips, bounded by a hard deadline. D sets
        #     the security floor (at-risk window <= D + BTC-confirmation lag). ----------
        self.deadline_blocks  = int(cfg.get("anchor_deadline_blocks", PRODUCTION_ANCHOR_DEADLINE_BLOCKS))
        self.min_spacing      = int(cfg.get("anchor_min_spacing_blocks", PRODUCTION_ANCHOR_MIN_SPACING_BLOCKS))
        self.fee_cheap_svb    = _strict_decimal(cfg.get("fee_cheap_sat_vb", PRODUCTION_FEE_TARGET_SVB), "fee_cheap_sat_vb", "0.00000001", "1000000")
        self.fee_ceiling_svb  = _strict_decimal(cfg.get("fee_ceiling_sat_vb", PRODUCTION_FEE_CEILING_SVB), "fee_ceiling_sat_vb", "0.00000001", "1000000")
        self.tip_age_alert_secs = int(cfg.get(
            "tip_age_alert_secs", PRODUCTION_TIP_ALERT_SECS))
        self.max_tip_age_secs = int(cfg.get(
            "max_tip_age_secs", PRODUCTION_MAX_TIP_AGE_SECS))
        self.regtest_generate = bool(cfg.get("regtest_generate", False))  # mine BTC confs (regtest only)
        self.state_path = os.path.join(self.state_dir, "anchor_state.json")
        self.state = load_anchor_state(self.state_path)

    # ---- Veld side: what to anchor -------------------------------------------------
    def veld_tip(self):
        info = self.veld.rpc("getbtcheaderinfo")   # spv must be active for anchoring to be useful
        peg = self.veld.rpc("getpeginfo")
        if (not isinstance(info, dict) or type(info.get("spv_active")) is not bool or
                not isinstance(peg, dict)):
            raise RuntimeError("Veld readiness RPC returned a malformed result")
        return _strict_int(peg.get("tip"), "Veld tip", 0, MAX_HEIGHT), info["spv_active"]

    def veld_block_hash(self, height):
        # getblockhash(height) -> the block hash string (rpc.h:817)
        r = self.veld.rpc("getblockhash", [str(height)])
        h = r["hash"] if isinstance(r, dict) else r
        if not isinstance(h, str) or not re.fullmatch(r'[0-9a-f]{64}', h):
            raise RuntimeError(f"getblockhash({height}) -> {h!r}")
        return h

    def consensus_anchor_info(self):
        info = self.veld.rpc("getanchorinfo")
        if not isinstance(info, dict):
            raise RuntimeError("getanchorinfo returned no object")
        if type(info.get("anchor_active")) is not bool:
            raise RuntimeError("getanchorinfo omitted anchor_active")
        if type(info.get("anchor_admission_live")) is not bool:
            raise RuntimeError("getanchorinfo omitted anchor_admission_live")
        if info["anchor_active"] != info["anchor_admission_live"]:
            raise RuntimeError(
                "getanchorinfo anchor_active/admission alias mismatch")
        if type(info.get("anchor_checkpoint_enforced")) is not bool:
            raise RuntimeError("getanchorinfo omitted anchor_checkpoint_enforced")
        if type(info.get("anchor_security_milestone")) is not bool:
            raise RuntimeError("getanchorinfo omitted anchor_security_milestone")
        if type(info.get("anchor_configured")) is not bool:
            raise RuntimeError("getanchorinfo omitted anchor_configured")
        if type(info.get("finality_active")) is not bool:
            raise RuntimeError("getanchorinfo omitted finality_active")
        final_height = _strict_int(
            info.get("final_height"), "anchor final_height", 0, MAX_HEIGHT)
        high_water = _strict_int(info.get("high_water"), "anchor high_water", 0, MAX_HEIGHT)
        consensus_k = _strict_int(info.get("k_btc"), "anchor k_btc", 1, 1000)
        if consensus_k != self.k_btc:
            raise RuntimeError(
                "anchord k_btc differs from compiled anchor confirmation depth")
        if info["anchor_admission_live"] and (
                not info["anchor_configured"] or
                not info["finality_active"] or final_height == 0):
            raise RuntimeError(
                "getanchorinfo reports anchoring active without real validator finality")
        if high_water > final_height:
            raise RuntimeError(
                "anchor high_water exceeds validator final_height")
        if info["anchor_checkpoint_enforced"] and high_water == 0:
            raise RuntimeError(
                "getanchorinfo enforces a checkpoint without anchor high_water")
        if info["anchor_checkpoint_enforced"] and not info["anchor_security_milestone"]:
            raise RuntimeError(
                "getanchorinfo enforces a checkpoint before the security milestone")
        return info["anchor_admission_live"], high_water, final_height

    def required_core_confirmations(self):
        # BtcHeaderChain::IsFinal(block,k) requires block_height+k <= best_height.
        # Bitcoin Core counts the containing block as confirmation one, hence k+1.
        return self.k_btc + 1

    def btc_tip_age(self):
        """Return the local canonical Bitcoin tip age after strict sync checks."""
        info = self.btc.call("getblockchaininfo")
        if (not isinstance(info, dict) or
                (self.production and info.get("chain") != "main") or
                info.get("chain") not in ("main", "regtest", "signet", "test") or
                info.get("initialblockdownload") is not False):
            raise RuntimeError("Bitcoin Core is not a synced mainnet node")
        blocks = _strict_int(info.get("blocks"), "Bitcoin blocks", 0, MAX_HEIGHT)
        headers = _strict_int(info.get("headers"), "Bitcoin headers", 0, MAX_HEIGHT)
        best = info.get("bestblockhash")
        if blocks != headers or not isinstance(best, str) or not re.fullmatch(
                r"[0-9a-f]{64}", best):
            raise RuntimeError("Bitcoin Core tip is not fully synced/canonical")
        header = self.btc.call("getblockheader", best, True)
        if (not isinstance(header, dict) or header.get("hash") != best or
                _strict_int(header.get("height"), "Bitcoin tip height", 0,
                            MAX_HEIGHT) != blocks or
                _strict_int(header.get("confirmations"),
                            "Bitcoin tip confirmations", 1, MAX_HEIGHT) != 1):
            raise RuntimeError("Bitcoin Core returned an incoherent best header")
        header_time = _strict_int(
            header.get("time"), "Bitcoin tip time", 1, int(time.time()) + 7_200)
        return max(0, int(time.time()) - header_time)

    # ---- fee policy: dynamic (tx size x market rate), clamped ----------------------
    def btc_feerate_sat_vb(self):
        """Market feerate (sat/vB) from the local bitcoind. estimatesmartfee returns
        BTC/kvB; on regtest / a cold mempool it returns no 'feerate' key -> fallback."""
        try:
            r = self.btc.call("estimatesmartfee", self.fee_conf_target)
            fr = r.get("feerate") if isinstance(r, dict) else None
            if fr is not None:
                btc_kvb = _strict_decimal(fr, "estimatesmartfee.feerate",
                                          "0.00000000001", "1000")
                return max(Decimal(1), btc_kvb * Decimal(100_000))
        except Exception as e:
            warn(f"[fee] estimatesmartfee failed ({e}); fallback {self.fee_fallback_svb} sat/vB")
        return self.fee_fallback_svb

    def commit_fee_sats(self, feerate_sat_vb):
        """Upper-bound first pass; final fee uses the measured signed vsize."""
        rate = _strict_decimal(feerate_sat_vb, "feerate", "0.00000001", "1000000")
        raw = int((Decimal(self.max_vsize) * rate).to_integral_value(
            rounding=ROUND_CEILING))
        return max(self.max_vsize, min(raw, self.max_fee_sats))

    def acceptance_ceiling(self, elapsed_blocks):
        """Rising fee ceiling (sat/vB) across the [min_spacing, deadline] window: patient
        early (fee_cheap), accept anything by the deadline (fee_ceiling). Captures cheap
        dips when they occur; the hard deadline guarantees the security bound regardless."""
        span = max(1, self.deadline_blocks - self.min_spacing)
        frac = min(Decimal(1), max(Decimal(0),
                   Decimal(elapsed_blocks - self.min_spacing) / Decimal(span)))
        return self.fee_cheap_svb + (self.fee_ceiling_svb - self.fee_cheap_svb) * frac

    # ---- step 1: PREPARE + durably journal + COMMIT the Bitcoin transaction --------
    def prepare_btc_commit(self, veld_height, veld_hash_hex, fee_sats, feerate_sat_vb):
        _strict_int(veld_height, "anchor Veld height", 1, MAX_HEIGHT)
        if not isinstance(veld_hash_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", veld_hash_hex):
            raise RuntimeError("anchor Veld hash must be canonical lowercase hex")
        _strict_int(fee_sats, "anchor fee_sats", 1, self.max_fee_sats)
        requested_rate = _strict_decimal(
            feerate_sat_vb, "anchor feerate_sat_vb", "1", "1000000")
        if requested_rate > self.fee_ceiling_svb:
            raise RuntimeError("anchor feerate exceeds the production ceiling")
        # OP_RETURN data = tag | height(8 LE) | veld_hash(32, as displayed / big-endian bytes).
        # NOTE: veld_hash is carried verbatim; VerifyAnchor reads it back into ::veld::Hash256
        # and compares to the block's GetHash() (same byte order the node emits).
        data = BTC_TAG + struct.pack("<Q", veld_height) + bytes.fromhex(veld_hash_hex)
        data_hex = data.hex()

        # Prove the configured wallet address is exactly legacy P2PKH before
        # selecting funds.  Merely checking for a witness marker after signing
        # is too late to distinguish an operator typo from a usable launch setup.
        address_info = self.btc.call("getaddressinfo", self.btc_fund_addr)
        if not isinstance(address_info, dict):
            raise RuntimeError("getaddressinfo returned a malformed result")
        fund_spk = address_info.get("scriptPubKey")
        if (not isinstance(fund_spk, str) or not re.fullmatch(
                r"76a914[0-9a-f]{40}88ac", fund_spk) or
                address_info.get("ismine") is not True or
                address_info.get("solvable") is not True or
                address_info.get("iswatchonly") is True):
            raise RuntimeError("btc_fund_addr must be a spendable wallet-owned legacy P2PKH address")

        # Pick one safe confirmed P2PKH UTXO.  Bitcoin amounts are converted
        # through Decimal and must be an integral satoshi value; no float ever
        # decides the input, change, or fee.
        utxos = self.btc.call("listunspent", 1, 9999999, json.dumps([self.btc_fund_addr]))
        if not isinstance(utxos, list):
            raise RuntimeError("listunspent returned a malformed result")
        candidates = []
        for u in utxos:
            if not isinstance(u, dict):
                raise RuntimeError("listunspent returned a malformed entry")
            txid = u.get("txid"); vout = u.get("vout")
            if (not isinstance(txid, str) or not re.fullmatch(r"[0-9a-f]{64}", txid) or
                    isinstance(vout, bool) or not isinstance(vout, int) or
                    not 0 <= vout <= 0xffffffff):
                raise RuntimeError("listunspent returned a malformed outpoint")
            sats = btc_amount_to_sats(u.get("amount"), "listunspent amount")
            if (u.get("spendable") is True and u.get("solvable") is True and
                    u.get("safe") is True and u.get("scriptPubKey") == fund_spk and
                    sats > fee_sats + 1000):
                candidates.append((txid, vout, sats))
        if not candidates:
            raise RuntimeError(f"no spendable legacy UTXO on {self.btc_fund_addr} "
                               f"(fund it: sendtoaddress {self.btc_fund_addr} <btc>, legacy)")
        candidates.sort()
        prev_txid, prev_vout, in_sats = candidates[0]
        change_addr = self.btc_fund_addr   # keep the legacy fund address replenished for the next anchor
        inputs_json = json.dumps([{"txid": prev_txid, "vout": prev_vout}],
                                 separators=(",", ":"))
        expected_op_spk = (b"\x6a" + bytes([len(data)]) + data).hex()

        # P2PKH signature bytes are not known until signing. Build/sign/decode,
        # measure the actual vsize, then rebuild with the exact fee implied by
        # that measured size. Low-R/low-S Bitcoin Core signatures normally
        # converge in two passes; a bounded non-convergence fails closed.
        for _pass in range(MAX_FEE_CONVERGENCE_PASSES):
            change_sats = in_sats - fee_sats
            if change_sats <= 1000:
                raise RuntimeError("anchor input cannot preserve bounded change")
            outputs_json = (
                "[" + json.dumps({"data": data_hex}, separators=(",", ":")) +
                ",{" + json.dumps(change_addr) + ":" +
                sats_json_number(change_sats) + "}]")
            raw = self.btc.call("createrawtransaction", inputs_json, outputs_json)
            signed = self.btc.call("signrawtransactionwithwallet", raw)
            if not isinstance(signed, dict) or signed.get("complete") is not True:
                raise RuntimeError("btc commit tx did not sign complete")
            tx_hex = signed.get("hex")
            if (not isinstance(tx_hex, str) or len(tx_hex) % 2 or
                    not re.fullmatch(r"[0-9a-f]+", tx_hex)):
                raise RuntimeError("Bitcoin wallet returned malformed signed transaction bytes")
            if tx_hex[8:12] == "0001":
                raise RuntimeError("commit tx is segwit-serialized (need a legacy input)")
            txid = dsha(bytes.fromhex(tx_hex))[::-1].hex()

            decoded = self.btc.call("decoderawtransaction", tx_hex)
            if (not isinstance(decoded, dict) or decoded.get("txid") != txid or
                    not isinstance(decoded.get("vin"), list) or len(decoded["vin"]) != 1 or
                    not isinstance(decoded.get("vout"), list) or len(decoded["vout"]) != 2):
                raise RuntimeError("decoded anchor transaction does not match its exact template")
            vin = decoded["vin"][0]
            if (not isinstance(vin, dict) or vin.get("txid") != prev_txid or
                    vin.get("vout") != prev_vout):
                raise RuntimeError("decoded anchor transaction changed the selected input")
            output_total = 0; op_count = 0; change_count = 0
            for out in decoded["vout"]:
                if not isinstance(out, dict) or not isinstance(out.get("scriptPubKey"), dict):
                    raise RuntimeError("decoded anchor transaction contains a malformed output")
                output_total += btc_amount_to_sats(
                    out.get("value"), "decoded output amount")
                spk = out["scriptPubKey"].get("hex")
                if spk == expected_op_spk:
                    op_count += 1
                elif spk == fund_spk and btc_amount_to_sats(
                        out.get("value"), "decoded change amount") == change_sats:
                    change_count += 1
                else:
                    raise RuntimeError("decoded anchor transaction contains an unauthorized output")
            if op_count != 1 or change_count != 1 or in_sats - output_total != fee_sats:
                raise RuntimeError("decoded anchor transaction does not preserve the exact fee/change")
            vsize = decoded.get("vsize")
            if (isinstance(vsize, bool) or not isinstance(vsize, int) or
                    vsize <= 0 or vsize > self.max_vsize):
                raise RuntimeError(
                    f"actual signed anchor vsize exceeds the {self.max_vsize}-vB "
                    "policy ceiling")

            exact_fee = max(vsize, int(
                (Decimal(vsize) * requested_rate).to_integral_value(
                    rounding=ROUND_CEILING)))
            if exact_fee > self.max_fee_sats:
                raise RuntimeError("measured anchor fee exceeds the absolute satoshi cap")
            if exact_fee != fee_sats:
                fee_sats = exact_fee
                continue
            effective_rate = Decimal(fee_sats) / Decimal(vsize)
            if effective_rate > self.fee_ceiling_svb:
                raise RuntimeError("effective signed anchor fee rate exceeds policy")
            return {
                "veld_hash": veld_hash_hex, "btc_txid": txid, "btc_tx_hex": tx_hex,
                "status": "prepared", "at": int(time.time()), "fee_sats": fee_sats,
                "feerate_sat_vb": str(requested_rate),
            }
        raise RuntimeError("signed anchor vsize/fee did not converge")

    def broadcast_prepared(self, rec):
        txid = rec.get("btc_txid"); tx_hex = rec.get("btc_tx_hex")
        if (not isinstance(txid, str) or not re.fullmatch(r"[0-9a-f]{64}", txid) or
                not isinstance(tx_hex, str) or dsha(bytes.fromhex(tx_hex))[::-1].hex() != txid):
            raise RuntimeError("prepared Bitcoin transaction journal is inconsistent")
        try:
            sent = self.btc.call("sendrawtransaction", tx_hex)
            if sent != txid:
                raise RuntimeError("sendrawtransaction returned a different txid")
        except Exception as send_error:
            # Covers the exact crash/transport-ambiguity window: if Core already
            # knows our wallet transaction, the byte-identical rebroadcast is a
            # success.  Otherwise retain PREPARED for a later retry.
            try:
                known = self.btc.call("gettransaction", txid)
                if not isinstance(known, dict):
                    raise RuntimeError("gettransaction returned no object")
                confirmations = _strict_int(
                    known.get("confirmations", 0), "known anchor confirmations",
                    -MAX_HEIGHT, MAX_HEIGHT)
                if confirmations < 0:
                    raise RuntimeError("prepared anchor transaction is conflicted")
                if confirmations == 0:
                    mempool = self.btc.call("getmempoolentry", txid)
                    if not isinstance(mempool, dict):
                        raise RuntimeError("prepared anchor is neither confirmed nor in mempool")
            except Exception:
                raise send_error
        return txid

    # Compatibility helper for one-shot callers.  The service path below uses
    # prepare -> fsync journal -> broadcast, which is the crash-safe sequence.
    def commit_btc(self, veld_height, veld_hash_hex, fee_sats):
        rec = self.prepare_btc_commit(veld_height, veld_hash_hex, fee_sats,
                                      Decimal(fee_sats) / Decimal(self.max_vsize))
        return self.broadcast_prepared(rec)

    # ---- step 2: once buried K deep, build the proof + relay the VELD_ANCHOR op ----
    def try_relay(self, veld_height, rec):
        txid = rec["btc_txid"]
        if not isinstance(txid, str) or not re.fullmatch(r"[0-9a-f]{64}", txid):
            raise RuntimeError("anchor journal contains a malformed Bitcoin txid")
        info = self.btc.call("gettransaction", txid)
        if not isinstance(info, dict):
            raise RuntimeError("gettransaction returned a malformed result")
        confs = _strict_int(info.get("confirmations", 0),
                            "Bitcoin anchor confirmations", -MAX_HEIGHT, MAX_HEIGHT)
        if confs < 0:
            raise RuntimeError("Bitcoin anchor commit is conflicted")
        required = self.required_core_confirmations()
        if confs < required:
            if self.regtest_generate:
                addr = self.btc.call("getnewaddress", "anchor-bury", "legacy")
                self.btc.call("generatetoaddress", required - confs, addr)
                info = self.btc.call("gettransaction", txid)
                if not isinstance(info, dict):
                    raise RuntimeError("gettransaction returned a malformed result")
                confs = _strict_int(info.get("confirmations", 0),
                                    "Bitcoin anchor confirmations", -MAX_HEIGHT, MAX_HEIGHT)
            if confs < required:
                log(f"[anchor] h={veld_height} btc_txid={txid[:16]} "
                    f"confs {confs}<{required} - hold")
                return None
        blk_be = info["blockhash"]
        if not isinstance(blk_be, str) or not re.fullmatch(r"[0-9a-f]{64}", blk_be):
            raise RuntimeError("confirmed anchor lacks a canonical Bitcoin block hash")
        blk = self.btc.call("getblock", blk_be, 1)
        if not isinstance(blk, dict) or not isinstance(blk.get("tx"), list):
            raise RuntimeError("getblock returned a malformed result")
        txids_be = blk["tx"]
        if (not txids_be or len(txids_be) > 1000000 or
                any(not isinstance(t, str) or not re.fullmatch(r"[0-9a-f]{64}", t)
                    for t in txids_be)):
            raise RuntimeError("Bitcoin block contains a malformed txid list")
        if txid not in txids_be:
            raise RuntimeError("commit tx not found in its own block?")
        idx = txids_be.index(txid)
        txids_le = [be_to_le(t) for t in txids_be]
        branch, dirs, root = build_branch(txids_le, idx)
        if len(branch) > 32:
            raise RuntimeError("Bitcoin Merkle branch exceeds the consensus bound")
        merkle = blk.get("merkleroot")
        if (not isinstance(merkle, str) or not re.fullmatch(r"[0-9a-f]{64}", merkle) or
                root != be_to_le(merkle)):
            raise RuntimeError("computed Merkle root != block merkleroot (proof build bug)")
        # A pruned bitcoind has no txindex, so getrawtransaction can't fetch a CONFIRMED
        # tx by txid alone (error -5). Pass the containing block hash (blk_be) so it reads
        # the tx straight from that block, which works on pruned nodes.
        raw_tx_hex = self.btc.call_raw("getrawtransaction", txid, "false", blk_be)
        if (not isinstance(raw_tx_hex, str) or len(raw_tx_hex) % 2 or
                len(raw_tx_hex) > 2 * 1024 * 1024 or
                not re.fullmatch(r"[0-9a-f]+", raw_tx_hex)):
            raise RuntimeError("getrawtransaction returned malformed bytes")
        legacy_tx = bytes.fromhex(raw_tx_hex)
        if dsha(legacy_tx) != be_to_le(txid):
            raise RuntimeError("Hash256d(legacy_tx) != txid (tx is not witnessless)")

        payload = (ANCH_MAGIC + be_to_le(blk_be) + struct.pack("<I", dirs)
                   + bytes([len(branch)]) + b"".join(branch) + legacy_tx)
        op_string = VELD_PREFIX + payload.hex()
        prep = self.veld.rpc("preparerawop", [self.fund_addr, op_string])
        if not isinstance(prep, dict):
            raise RuntimeError("preparerawop returned a malformed result")
        inputs = prep.get("inputs") or []
        if not inputs:
            raise RuntimeError("preparerawop returned no inputs - is the Veld fund address funded?")
        if (not isinstance(inputs[0], dict) or
                not isinstance(inputs[0].get("prev_script_hex"), str)):
            raise RuntimeError("preparerawop input omitted prev_script_hex")
        unsigned = prep.get("unsigned_tx_hex")
        if not isinstance(unsigned, str) or not re.fullmatch(r"[0-9a-f]+", unsigned):
            raise RuntimeError("preparerawop omitted canonical unsigned transaction bytes")
        signed = self.signer.sign(unsigned, inputs[0]["prev_script_hex"])
        veld_txid = self.veld.rpc("sendrawtransaction", [signed])
        if not isinstance(veld_txid, str) or not re.fullmatch(r"[0-9a-f]{64}", veld_txid):
            raise RuntimeError("sendrawtransaction returned no canonical Veld txid")
        log(f"[anchor] SUBMITTED h={veld_height} btc_txid={txid[:16]} (confs={confs}) "
            f"veld_op_txid={veld_txid}; awaiting getanchorinfo")
        return veld_txid

    def run_once(self):
        tip, spv_active = self.veld_tip()
        if not spv_active:
            log("[anchor] SPV dormant - anchoring inert (verify needs the BTC header chain)"); return
        anchor_active, high_water, final_height = self.consensus_anchor_info()
        if not anchor_active:
            log("[anchor] consensus anchoring waiting for validator finality - "
                "nothing to commit or relay"); return
        if final_height > tip:
            raise RuntimeError("anchor final_height exceeds the sampled Veld tip")
        anchors = self.state["anchors"]

        # Recover the only ambiguous external side effect first.  PREPARED is
        # fsynced with the complete signed witnessless transaction before the
        # first broadcast.  A crash or lost CLI response therefore replays the
        # exact same txid, never creates a second fee spend, and never loses the
        # anchor transaction needed to build the later SPV proof.
        for key in sorted(anchors, key=lambda k: int(k)):
            rec = anchors[key]
            if rec.get("status") != "prepared":
                continue
            try:
                self.broadcast_prepared(rec)
                rec["status"] = "committed"
                save_json(self.state_path, self.state)
                log(f"[anchor] COMMITTED journaled h={key} btc_txid={rec['btc_txid'][:16]}")
            except Exception as e:
                warn(f"[anchor] prepared broadcast h={key} deferred: {type(e).__name__}: {e}")

        # Consensus, not sendrawtransaction or local JSON, is the completion
        # authority.  This also repairs legacy `relayed` records and Veld reorgs:
        # if their high-water mark is absent, they return to retryable state.
        dirty = False
        for key, rec in anchors.items():
            height = int(key)
            if high_water >= height:
                if rec.get("status") != "confirmed":
                    rec["status"] = "confirmed"
                    rec["confirmed_at"] = int(time.time())
                    dirty = True
            elif rec.get("status") in ("relayed", "confirmed"):
                rec["status"] = "committed"
                rec.pop("confirmed_at", None)
                dirty = True
        if dirty:
            save_json(self.state_path, self.state)

        # 1. RELAY first: any committed anchor whose BTC commit tx is now buried >= K deep.
        # (Do this before committing new ones - the target height moves with the Veld tip, so a
        # pending commit must be relayed on its own merit, not re-selected as the current target.)
        for key in sorted(anchors, key=lambda k: int(k)):
            rec = anchors[key]
            status = rec.get("status")
            if status == "submitted" and (
                    time.time() - float(rec.get("submitted_at", 0))
                    < self.relay_resubmit_secs):
                continue
            if status not in ("committed", "submitted"):
                continue
            try:
                veld_txid = self.try_relay(int(key), rec)
                if veld_txid:
                    rec["status"] = "submitted"
                    rec["veld_op_txid"] = str(veld_txid)
                    rec["submitted_at"] = int(time.time())
                    save_json(self.state_path, self.state)
            except Exception as e:
                warn(f"[anchor] relay h={key} deferred: {type(e).__name__}: {e}")

        # 2. COMMIT a new anchor, gated by Bitcoin freshness and fee-aware cadence:
        #      * never sooner than min_spacing blocks after the last anchor (bounds cost),
        #      * fire at the first sub-ceiling fee dip (rising acceptance ceiling), OR
        #      * fire at the hard deadline only while the selected rate remains at
        #        or below the production ceiling. Above it, alert and retry.
        # Existing prepared/committed/submitted records above continued their
        # lifecycle even if the backend has become stale; C5 only closes NEW BTC
        # anchor admission.
        tip_age = self.btc_tip_age()
        if tip_age >= self.max_tip_age_secs:
            warn(f"[anchor] C5 recovery-only: Bitcoin tip age {tip_age}s >= "
                 f"{self.max_tip_age_secs}s; no new Bitcoin anchor broadcast")
            log(f"[anchor] pass complete (tip={tip}; {len(anchors)} tracked)")
            return
        if tip_age >= self.tip_age_alert_secs:
            warn(f"[anchor] C5 ALERT: Bitcoin tip age {tip_age}s >= "
                 f"{self.tip_age_alert_secs}s; new admission remains enabled")

        last_h  = max((int(k) for k in anchors), default=0)
        elapsed = max(0, final_height - last_h)
        feerate = self.btc_feerate_sat_vb()
        if last_h and elapsed < self.min_spacing:
            log(f"[anchor] hold: {elapsed}<{self.min_spacing} blk since anchor h={last_h} "
                f"(market {feerate:.1f} sat/vB)")
        else:
            ceil_svb    = self.acceptance_ceiling(elapsed)
            at_deadline = elapsed >= self.deadline_blocks
            if feerate > self.fee_ceiling_svb:
                warn(f"[anchor] fee ceiling: market {feerate:.1f} > hard ceiling "
                     f"{self.fee_ceiling_svb:.1f} sat/vB; skip, alert, retry")
            elif last_h and not at_deadline and feerate > ceil_svb:
                log(f"[anchor] wait for cheaper: market {feerate:.1f} > ceiling {ceil_svb:.1f} "
                    f"sat/vB ({elapsed}/{self.deadline_blocks} blk into window)")
            else:
                if tip < 1:
                    log("[anchor] hold: Veld has no anchorable block yet")
                    return
                # R1: target the exact latest validator-finalized checkpoint.
                # No operator lag knob can substitute for, weaken, or bypass
                # the consensus finality predicate.
                target = final_height
                key = str(target)
                if high_water >= target:
                    log(f"[anchor] target h={target} already secured by consensus "
                        f"high_water={high_water}")
                elif key not in anchors:
                    fee_sats = self.commit_fee_sats(feerate)
                    vhash    = self.veld_block_hash(target)
                    rec = self.prepare_btc_commit(target, vhash, fee_sats, feerate)
                    anchors[key] = rec
                    # Kill-point contract: exact tx bytes reach durable storage
                    # before sendrawtransaction is invoked.
                    save_json(self.state_path, self.state)
                    txid = self.broadcast_prepared(rec)
                    rec["status"] = "committed"
                    save_json(self.state_path, self.state)
                    why = "deadline" if at_deadline else f"cheap<={ceil_svb:.1f}"
                    log(f"[anchor] COMMITTED h={target} veld_hash={vhash[:16]} -> btc_txid={txid[:16]} "
                        f"| {rec['fee_sats']} sats @ {feerate:.1f} sat/vB ({why})")
                else:
                    log(f"[anchor] target h={target} already tracked (status={anchors[key].get('status')})")
        log(f"[anchor] pass complete (tip={tip}; {len(anchors)} tracked; hi_committed={last_h})")


def die(msg, code=64):
    sys.stderr.write("veld_anchord: " + msg + "\n")
    raise SystemExit(code)


def main():
    if len(sys.argv) not in (2, 4) or (len(sys.argv) == 4 and sys.argv[2] != "--loop"):
        die("usage: veld_anchord.py <config.json>  [--loop <secs>]")
    try:
        cfg = validate_config(_read_private_json(
            os.path.abspath(sys.argv[1]), "anchord config", MAX_CONFIG_BYTES))
    except Exception as exc:
        die(f"unsafe configuration: {exc}")

    lock_path = os.path.join(cfg["state_dir"], "anchord.lock")
    if fcntl is None:
        die("POSIX fcntl locking is required")
    lock_flags = (os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) |
                  getattr(os, "O_NOFOLLOW", 0))
    try:
        lock_fd = os.open(lock_path, lock_flags, 0o600)
        lock_info = os.fstat(lock_fd)
        if (not stat.S_ISREG(lock_info.st_mode) or
                lock_info.st_uid != os.geteuid() or lock_info.st_nlink != 1):
            raise RuntimeError("lock is not a service-owned single-link regular file")
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except Exception as exc:
        try:
            os.close(lock_fd)
        except (OSError, UnboundLocalError):
            pass
        die(f"cannot acquire exclusive anchord lock: {exc}")

    try:
        a = Anchor(cfg)
    except Exception as exc:
        die(f"anchord initialization failed: {exc}")
    loop_secs = 0
    if len(sys.argv) == 4:
        try:
            loop_secs = int(sys.argv[3], 10)
        except ValueError:
            die("--loop must be a base-10 integer")
        try:
            _strict_int(loop_secs, "--loop", MIN_LOOP_SECS, MAX_LOOP_SECS)
        except RuntimeError as exc:
            die(str(exc))
    while True:
        try:
            a.run_once()
        except ConfigError as exc:
            die(str(exc))
        except Exception as e:
            warn(f"pass error (fail-closed, exact state retained): {type(e).__name__}: {e}")
        if loop_secs <= 0:
            break
        time.sleep(loop_secs)
        a.state = load_anchor_state(a.state_path)


if __name__ == "__main__":
    main()
