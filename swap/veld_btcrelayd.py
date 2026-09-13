#!/usr/bin/env python3
"""
btcVELD SPV header-relay daemon.

Keeps the Veld chain's IN-CONSENSUS Bitcoin header view current by fetching raw
80-byte BTC headers from a bitcoind (trusted only for AVAILABILITY) and posting
them to Veld as permissionless VELD_BHDR ops. Consensus INDEPENDENTLY validates
every header (PoW, prev-link, MTP) via BtcHeaderChain, so a lying or faulty relay
wastes only its own fee and can never corrupt the header view. The trust-minimized
MINT gate and the Layer-2 anchor verifier both read this view - so an honest relay
is what makes trust-minimized minting + anchoring actually live.

  header source : bitcoin-cli getblockhash/getblockheader  (raw 80-byte hex)
  consensus tip : veld getbtcheaderinfo -> {spv_active, best_height, k_btc}
  post          : preparerawop(fund_addr,"VELD_BHDR|"<hex>) -> sign -> sendrawtransaction
  fund/sign     : a dedicated hot Veld address (FEES ONLY) + veld-keygen sign-op
  state         : <state>/relay_state.json  (in-flight tracking; idempotent)
  lock          : <state>/relayd.lock       (single-writer)

Fail-closed: on any error the pass logs + aborts; headers are re-derived from
bitcoind every pass, and submission is anchored on the CONSENSUS best_height, so a
missed/dropped pass self-heals on the next tick with no gaps (consensus dedupes a
re-submitted header - "a liar wastes only their own fee").
"""
import hashlib, json, math, os, sys, subprocess, time, re, stat, urllib.request, tempfile
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from rpc_url_policy import (open_rpc_request, validate_backend_rpc_url,
                            validate_loopback_http_rpc_url)  # noqa: E402

try:
    import fcntl  # POSIX single-writer lock; the relay is a Linux daemon
except ImportError:
    fcntl = None

BHDR_MAGIC = b"BHDR"
# op_string bytes = len("VELD_BHDR|") + 2*(4+1 + 80*N) = 20 + 160*N. The preparerawop
# guard caps op_string at 24000, so N <= ~149; 100 is a safe, generous batch (~16 KB).
MAX_HEADERS_PER_OP = 100
MAX_CONFIG_BYTES = 64 * 1024
MAX_STATE_BYTES = 64 * 1024
MIN_LOOP_SECS = 5
MAX_LOOP_SECS = 3600
MIN_RESUBMIT_SECS = 30
MAX_RESUBMIT_SECS = 86400
# Bitcoin can reorganize blocks the relay has already fed to Veld consensus. When
# a posted frontier is never adopted (its first header builds on a source block
# consensus does not hold), reposting the same height is a permanent orphan - "a
# liar wastes only their own fee" applies to us too. Re-anchor instead: rewind the
# submission start below best so the replacement branch is re-fed from the last
# common ancestor. Consensus dedupes the unchanged prefix (a known header is an
# idempotent no-op) and reorgs to the heavier branch via most-work. Depth starts
# shallow and doubles per unadopted resubmit window, bounded - real Bitcoin tip
# reorgs are a few blocks at most.
REORG_REWIND_INIT = 1
REORG_REWIND_CAP = 50


class ConfigError(RuntimeError):
    pass


def log(m):  sys.stdout.write("  " + m + "\n"); sys.stdout.flush()
def warn(m): sys.stderr.write("  [WARN] " + m + "\n"); sys.stderr.flush()


def _strict_int(value, name, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise RuntimeError(f"{name} must be an integer in [{low},{high}]")
    return value


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
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{name} is not strict UTF-8 JSON") from exc


def _validate_production_rpc(rpc):
    if not isinstance(rpc, dict):
        raise RuntimeError("veld_rpc must be an object")
    allowed = {"url", "token_cmd", "token_file"}
    if set(rpc) - allowed:
        raise RuntimeError("veld_rpc contains unknown fields")
    url = validate_loopback_http_rpc_url(rpc.get("url"), "veld_rpc.url")
    parsed = urlsplit(url)
    if parsed.hostname != "127.0.0.1" or parsed.path not in ("", "/") or parsed.port is None:
        raise RuntimeError("production veld_rpc.url must be exact http://127.0.0.1:PORT")
    cmd = rpc.get("token_cmd")
    token_file = rpc.get("token_file")
    if bool(cmd) == bool(token_file):
        raise RuntimeError(
            "production relay requires exactly one RPC token source")
    if token_file:
        if token_file != "/run/veld-btcrelayd/rpc.token":
            raise RuntimeError(
                "production relay token_file must be its exact private runtime file")
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
    allowed = {"production", "state_dir", "cli_base", "btc_wallet",
               "btc_rpc_timeout", "veld_rpc", "fund_addr", "signer",
               "checkpoint_height", "max_headers_per_op",
               "resubmit_timeout_secs"}
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
        datadir_args = [v.split("=", 1)[1] for v in cli[1:]
                        if v.startswith("-datadir=")]
        if len(datadir_args) != 1 or not os.path.isabs(datadir_args[0]):
            raise RuntimeError("production cli_base needs one absolute -datadir= path")
        _validate_production_rpc(cfg.get("veld_rpc"))
    else:
        rpc = cfg.get("veld_rpc")
        if not isinstance(rpc, dict):
            raise RuntimeError("veld_rpc must be an object")
        validate_backend_rpc_url(rpc.get("url"), "veld_rpc.url")
    timeout = cfg.get("btc_rpc_timeout", 30)
    _strict_int(timeout, "btc_rpc_timeout", 5, 300)
    checkpoint = cfg.get("checkpoint_height", 0)
    _strict_int(checkpoint, "checkpoint_height", 0, 100000000)
    _strict_int(cfg.get("max_headers_per_op", MAX_HEADERS_PER_OP),
                "max_headers_per_op", 1, MAX_HEADERS_PER_OP)
    _strict_int(cfg.get("resubmit_timeout_secs", 600),
                "resubmit_timeout_secs", MIN_RESUBMIT_SECS, MAX_RESUBMIT_SECS)
    fund = cfg.get("fund_addr")
    if (not isinstance(fund, str) or not re.fullmatch(
            r"V[1-9A-HJ-NP-Za-km-z]{25,60}", fund)):
        raise RuntimeError("fund_addr is not a canonical-looking Veld address")
    signer = cfg.get("signer")
    if not isinstance(signer, dict) or set(signer) - {"keygen", "keyfile", "passphrase"}:
        raise RuntimeError("signer config is malformed")
    _trusted_executable(signer.get("keygen"), "signer.keygen")
    if os.path.basename(signer["keygen"]) not in ("veld-keygen", "veld-keygen.exe"):
        raise RuntimeError("signer.keygen must invoke veld-keygen")
    _private_regular_file(signer.get("keyfile"), "signer.keyfile", 1024 * 1024)
    if production and signer.get("passphrase"):
        raise RuntimeError("production signer passphrase must come from the service environment")
    return cfg


# ------------------------------------------------------------------ RPC clients
class Btc:
    """bitcoin-cli wrapper - READ-ONLY (header + tip queries only)."""
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
            return json.loads(s)
        except (json.JSONDecodeError, ValueError):
            return s

    def call_raw(self, method, *args):
        """Return stdout verbatim - for RPCs whose result is a bare hex string
        (getblockhash, getblockheader false) that json.loads would mangle."""
        out = subprocess.run(self.base + [method] + [str(a) for a in args],
                             capture_output=True, text=True, timeout=self.timeout)
        if out.returncode != 0:
            raise RuntimeError(f"bitcoin-cli {method}: {out.stderr.strip()}")
        return out.stdout.strip()


class Veld:
    """veld-node JSON-RPC over localhost with a bearer token. The node stores rpc.token
    encrypted. Production normally obtains it via the node helper;
    an unprivileged systemd service may instead consume its exact owner-only,
    ephemeral /run token prepared by a privileged ExecStartPre helper."""
    def __init__(self, url, token_file=None, token_cmd=None):
        self.url = validate_backend_rpc_url(url, "veld_rpc.url")
        self.token = ""
        if token_cmd:
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
    """Signs with the strict `veld-keygen sign-op` fees-only policy.

    The key owns only relay-fee UTXOs. sign-op additionally refuses payments,
    issuer mints, unknown markers, and change redirected away from this key.
    """
    def __init__(self, keygen, keyfile, passphrase, workdir):
        self.keygen = keygen
        self.keyfile = keyfile
        self.passphrase = passphrase
        self.workdir = workdir

    def sign(self, unsigned_tx_hex, prev_script_hex):
        # veld-keygen sign-op reads a COMPACT json {"unsigned_tx_hex","prev_script_hex"}
        # by literal substring (no space after the colon), so keep separators tight.
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
            signed = open(outp).read().strip()
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


def load_relay_state(path):
    if not os.path.exists(path):
        return {"submitted_tip": 0, "submitted_at": 0}
    obj = _read_private_json(path, "relay_state.json", MAX_STATE_BYTES)
    # Optional fields preserve state written by earlier builds. New state binds
    # an outstanding transaction to the exact Bitcoin source branch it carries.
    allowed = {"submitted_tip", "submitted_at", "reorg_rewind",
               "submitted_start", "submitted_txid", "submitted_tip_hash"}
    if (not isinstance(obj, dict) or
            not {"submitted_tip", "submitted_at"} <= set(obj) <=
            allowed):
        raise RuntimeError("relay_state.json has an invalid schema")
    tip = obj["submitted_tip"]
    submitted_at = obj["submitted_at"]
    _strict_int(tip, "relay_state.submitted_tip", 0, 100000000)
    if (isinstance(submitted_at, bool) or
            not isinstance(submitted_at, (int, float)) or
            not math.isfinite(submitted_at) or submitted_at < 0):
        raise RuntimeError("relay_state.submitted_at is invalid")
    rewind = obj.get("reorg_rewind", 0)
    _strict_int(rewind, "relay_state.reorg_rewind", 0, REORG_REWIND_CAP)
    state = {"submitted_tip": tip, "submitted_at": float(submitted_at),
             "reorg_rewind": rewind}
    metadata = ("submitted_start", "submitted_txid", "submitted_tip_hash")
    present = [name in obj for name in metadata]
    if any(present) and not all(present):
        raise RuntimeError("relay_state.json has incomplete submission metadata")
    if all(present):
        start = _strict_int(obj["submitted_start"],
                            "relay_state.submitted_start", 1, 100000000)
        if start > tip:
            raise RuntimeError("relay_state.submitted_start exceeds submitted_tip")
        txid = obj["submitted_txid"]
        tip_hash = obj["submitted_tip_hash"]
        if not isinstance(txid, str) or not re.fullmatch(r"[0-9a-f]{64}", txid):
            raise RuntimeError("relay_state.submitted_txid is invalid")
        if (not isinstance(tip_hash, str) or
                not re.fullmatch(r"[0-9a-f]{64}", tip_hash)):
            raise RuntimeError("relay_state.submitted_tip_hash is invalid")
        state.update({"submitted_start": start, "submitted_txid": txid,
                      "submitted_tip_hash": tip_hash})
    return state


def bitcoin_header_hash(raw):
    if not isinstance(raw, bytes) or len(raw) != 80:
        raise RuntimeError("cannot hash a malformed Bitcoin header")
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()


# ------------------------------------------------------------------ the relay
class Relay:
    def __init__(self, cfg):
        self.cfg = cfg
        self.state_dir = cfg["state_dir"]
        self.btc = Btc(cfg["cli_base"], cfg.get("btc_wallet"),
                       cfg.get("btc_rpc_timeout", 30))
        self.veld = Veld(cfg["veld_rpc"]["url"], cfg["veld_rpc"].get("token_file"),
                         cfg["veld_rpc"].get("token_cmd"))
        self.fund_addr = cfg["fund_addr"]
        sc = cfg["signer"]  # {"keygen","keyfile","passphrase"?}
        self.signer = LocalSigner(sc["keygen"], sc["keyfile"], sc.get("passphrase", ""),
                                  self.state_dir)
        # tunables
        self.checkpoint_height = int(cfg.get("checkpoint_height", 0))   # compiled BtcVeldCheckpoint height
        self.max_per_op        = int(cfg.get("max_headers_per_op", MAX_HEADERS_PER_OP))
        # A later batch's first header depends on the prior batch reaching Veld
        # consensus.  Independent fee-paying transactions have no same-block
        # ordering guarantee, so more than one outstanding frontier can make an
        # honest batch arrive as an unknown-parent operation.  Keep exactly one
        # frontier in flight; the next pass waits for getbtcheaderinfo to advance.
        self.max_ops_per_pass  = 1
        self.resubmit_secs     = int(cfg.get("resubmit_timeout_secs", 600))  # in-flight -> assume dropped
        self.state_path = os.path.join(self.state_dir, "relay_state.json")
        self.state = load_relay_state(self.state_path)

    def raw_header(self, height):
        h = self.btc.call_raw("getblockhash", height)
        if not re.match(r'^[0-9a-f]{64}$', h):
            raise RuntimeError(f"getblockhash({height}) returned {h!r}")
        hdr = self.btc.call_raw("getblockheader", h, "false")
        raw = bytes.fromhex(hdr)
        if len(raw) != 80:
            raise RuntimeError(f"header at {height} is not 80 bytes ({len(raw)})")
        return raw

    def post_batch(self, first_h, headers):
        """headers: list[bytes(80)] -> one VELD_BHDR op posted to Veld. Returns veld_txid."""
        if (not isinstance(first_h, int) or first_h <= 0 or not headers or
                len(headers) > self.max_per_op or len(headers) > 255 or
                any(not isinstance(header, bytes) or len(header) != 80
                    for header in headers)):
            raise RuntimeError("refusing malformed or oversized header batch")
        payload = BHDR_MAGIC + bytes([len(headers)]) + b"".join(headers)
        op_string = "VELD_BHDR|" + payload.hex()
        prep = self.veld.rpc("preparerawop", [self.fund_addr, op_string])
        if not isinstance(prep, dict):
            raise RuntimeError("preparerawop returned a malformed result")
        inputs = prep.get("inputs") or []
        if not inputs:
            raise RuntimeError("preparerawop returned no inputs - is the fund address funded?")
        prev = inputs[0].get("prev_script_hex", "")
        if not prev:
            raise RuntimeError("preparerawop input missing prev_script_hex")
        signed = self.signer.sign(prep["unsigned_tx_hex"], prev)
        txid = self.veld.rpc("sendrawtransaction", [signed])
        if not isinstance(txid, str) or not re.fullmatch(r"[0-9a-f]{64}", txid):
            raise RuntimeError("sendrawtransaction returned no canonical txid")
        return txid

    def submitted_batch_is_still_pending(self, submitted, btc_tip):
        """True only when the exact transaction and Bitcoin branch still match."""
        txid = self.state.get("submitted_txid")
        tip_hash = self.state.get("submitted_tip_hash")
        start = self.state.get("submitted_start")
        if txid is None and tip_hash is None and start is None:
            return False
        if (not isinstance(txid, str) or not re.fullmatch(r"[0-9a-f]{64}", txid) or
                not isinstance(tip_hash, str) or
                not re.fullmatch(r"[0-9a-f]{64}", tip_hash) or
                not isinstance(start, int) or isinstance(start, bool) or
                start <= 0 or start > submitted):
            raise RuntimeError("in-memory relay submission metadata is malformed")
        if submitted > btc_tip:
            return False
        current_hash = self.btc.call_raw("getblockhash", submitted)
        if not isinstance(current_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", current_hash):
            raise RuntimeError("Bitcoin source returned a malformed submitted-tip hash")
        if current_hash != tip_hash:
            return False
        entry = self.veld.rpc("getmempoolentry", [txid])
        if not isinstance(entry, dict):
            raise RuntimeError("getmempoolentry returned a malformed result")
        if entry.get("error") == "not in mempool":
            return False
        if entry.get("txid") != txid:
            raise RuntimeError("getmempoolentry returned mismatched transaction data")
        return True

    def run_once(self):
        info = self.veld.rpc("getbtcheaderinfo")
        if not isinstance(info, dict) or not isinstance(info.get("spv_active"), bool):
            raise RuntimeError("getbtcheaderinfo returned a malformed result")
        if not info.get("spv_active"):
            log("[relay] SPV dormant (spv_active=false) - nothing to relay"); return
        best = _strict_int(info.get("best_height"), "consensus best_height", 0, 100000000)
        btc_tip = _strict_int(self.btc.call("getblockcount"),
                              "Bitcoin best height", 0, 100000000)
        if self.checkpoint_height > best:
            raise ConfigError(
                f"configured checkpoint_height={self.checkpoint_height} exceeds "
                f"authoritative consensus best_height={best}")
        if btc_tip < best:
            raise RuntimeError(
                f"Bitcoin source tip {btc_tip} is behind Veld consensus BTC tip {best}")

        # Submission floor = the CONSENSUS best height (source of truth, self-healing, no
        # gaps).  Never build the next batch on our local submitted_tip: that tip is
        # not consensus and a separately mined transaction cannot depend on it.
        # While one frontier is in flight, wait.  After timeout, re-post; once
        # consensus catches up, advance exactly one batch.
        submitted = int(self.state.get("submitted_tip", 0))
        submitted_at = float(self.state.get("submitted_at", 0))
        rewind = int(self.state.get("reorg_rewind", 0))
        in_flight = submitted > best
        if in_flight and (time.time() - submitted_at) < self.resubmit_secs:
            log(f"[relay] waiting for in-flight frontier {best + 1}..{submitted} "
                f"(consensus_best={best}, rewind={rewind})")
            return

        if in_flight and self.submitted_batch_is_still_pending(submitted, btc_tip):
            self.state["submitted_at"] = time.time()
            save_json(self.state_path, self.state)
            log(f"[relay] submitted frontier {self.state['submitted_start']}..{submitted} "
                "is still pending on the same Bitcoin branch; duplicate suppressed")
            return

        # An in-flight frontier consensus has not adopted after the resubmit window
        # is most likely a source reorg under our last submission: its parent is a
        # Bitcoin block consensus never held, so it is a permanent orphan and
        # reposting best+1 cannot heal it. Escalate the re-anchor depth and rewind
        # the start below best so the replacement branch is re-fed from the last
        # common ancestor. A frontier consensus DID adopt (submitted <= best) resets
        # the depth and resumes normal best+1 extension.
        if in_flight:
            rewind = min(max(rewind * 2, REORG_REWIND_INIT), REORG_REWIND_CAP)
        else:
            rewind = 0
        start = max(self.checkpoint_height + 1, best + 1 - rewind)
        if start > btc_tip:
            if rewind != int(self.state.get("reorg_rewind", 0)):
                self.state["reorg_rewind"] = rewind
                save_json(self.state_path, self.state)
            log(f"[relay] up to date: consensus_best={best} btc_tip={btc_tip} "
                f"(in-flight tip={submitted})")
            return

        mode = "re-anchor (suspected source reorg)" if rewind else "extend"
        log(f"[relay] consensus_best={best} btc_tip={btc_tip} rewind={rewind} "
            f"-> {mode}: submitting {start}..{btc_tip}")
        h = start
        batch_end = min(h + self.max_per_op - 1, btc_tip)
        headers = [self.raw_header(x) for x in range(h, batch_end + 1)]
        txid = self.post_batch(h, headers)
        log(f"[relay] posted headers {h}..{batch_end} ({len(headers)}) veld_txid={txid}")
        self.state["submitted_tip"] = batch_end
        self.state["submitted_at"]  = time.time()
        self.state["reorg_rewind"]  = rewind
        self.state["submitted_start"] = h
        self.state["submitted_txid"] = txid
        self.state["submitted_tip_hash"] = bitcoin_header_hash(headers[-1])
        save_json(self.state_path, self.state)
        log(f"[relay] pass complete (1 op; next consensus frontier is {batch_end + 1})")


def die(msg, code=64):
    sys.stderr.write("veld_btcrelayd: " + msg + "\n")
    raise SystemExit(code)


def main():
    if len(sys.argv) not in (2, 4) or (len(sys.argv) == 4 and sys.argv[2] != "--loop"):
        die("usage: veld_btcrelayd.py <config.json>  [--loop <secs>]")
    try:
        cfg = validate_config(_read_private_json(
            os.path.abspath(sys.argv[1]), "relay config", MAX_CONFIG_BYTES))
    except Exception as exc:
        die(f"unsafe configuration: {exc}")

    lock_path = os.path.join(cfg["state_dir"], "relayd.lock")
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
        die(f"cannot acquire exclusive relay lock: {exc}")

    try:
        r = Relay(cfg)
    except Exception as exc:
        die(f"relay initialization failed: {exc}")
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
            r.run_once()
        except ConfigError as exc:
            die(str(exc))
        except Exception as e:
            warn(f"pass error (fail-closed, no partial state advance): {type(e).__name__}: {e}")
        if loop_secs <= 0:
            break
        time.sleep(loop_secs)
        r.state = load_relay_state(r.state_path)


if __name__ == "__main__":
    main()
