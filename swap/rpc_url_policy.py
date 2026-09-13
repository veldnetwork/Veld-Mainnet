"""Transport policy shared by funds-bearing operator RPC clients."""
import json
import math
import os
import selectors
import signal
import stat
import subprocess
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
_MAX_JSON_RESPONSE_BYTES = 64 * 1024 * 1024
_MAX_LOCAL_FILE_BYTES = 64 * 1024 * 1024
_MAX_SUBPROCESS_OUTPUT_BYTES = 64 * 1024 * 1024
_ORIGINAL_SUBPROCESS_RUN = subprocess.run


class _RejectRpcRedirects(urllib.request.HTTPRedirectHandler):
    """Never forward an RPC credential to a redirect-selected authority."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "operator RPC redirects are forbidden", headers, fp)


# RPC credentials must not transit ambient HTTP(S)_PROXY settings.  A deployment
# that deliberately needs a proxy can terminate an authenticated tunnel locally;
# silently inheriting a service-manager environment is not an authorization step.
_RPC_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), _RejectRpcRedirects())


def validate_backend_rpc_url(url, field_name="rpc_url"):
    """Allow plaintext only on exact loopback; remote backends require HTTPS."""
    if not isinstance(url, str) or not url:
        raise ValueError("%s must be a non-empty URL" % field_name)
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        parsed.port  # force malformed-port validation
    except ValueError as exc:
        raise ValueError("%s is malformed" % field_name) from exc
    if parsed.scheme not in ("http", "https") or not host:
        raise ValueError("%s must use http or https with an explicit host" % field_name)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("%s must not embed credentials" % field_name)
    if parsed.query or parsed.fragment:
        raise ValueError("%s must not contain a query or fragment" % field_name)
    if parsed.scheme == "http" and host.lower() not in _LOOPBACK_HOSTS:
        raise ValueError(
            "%s remote endpoints require HTTPS; plaintext HTTP is loopback-only"
            % field_name)
    return url


def validate_loopback_http_rpc_url(url, field_name="rpc_url"):
    """Require an exact loopback HTTP authority with no URL credentials."""
    url = validate_backend_rpc_url(url, field_name)
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname.lower() not in _LOOPBACK_HOSTS:
        raise ValueError("%s must use HTTP on an exact loopback host" % field_name)
    return url


def open_rpc_request(request, timeout=30):
    """Open a validated RPC request without proxies or redirect following."""
    if not isinstance(request, urllib.request.Request):
        raise TypeError("operator RPC request must be urllib.request.Request")
    validate_backend_rpc_url(request.full_url, "operator RPC URL")
    return _RPC_OPENER.open(request, timeout=timeout)


def open_direct_https_request(request, timeout=30):
    """Open one public-source request without proxy/redirect quorum collapse."""
    if not isinstance(request, urllib.request.Request):
        raise TypeError("direct HTTPS request must be urllib.request.Request")
    try:
        parsed = urlsplit(request.full_url)
        parsed.port
    except ValueError as exc:
        raise ValueError("direct HTTPS URL is malformed") from exc
    if (parsed.scheme != "https" or not parsed.hostname or
            parsed.username is not None or parsed.password is not None or
            parsed.fragment):
        raise ValueError(
            "direct source must use HTTPS without credentials or a fragment")
    return _RPC_OPENER.open(request, timeout=timeout)


def strict_json_loads(raw, description="JSON document"):
    """Decode one UTF-8 JSON value with duplicate/non-finite rejection.

    CPython's default decoder silently keeps the last duplicate object member and
    accepts NaN/Infinity.  Neither behaviour is suitable at an operator trust
    boundary, where a human, a policy signer, and the program must all interpret
    the exact same document.
    """
    if not isinstance(raw, (bytes, bytearray, str)):
        raise ValueError("%s must be UTF-8 bytes or text" % description)

    def reject_constant(value):
        raise ValueError("%s contains non-finite number %s" %
                         (description, value))

    def finite_float(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("%s contains an out-of-range number" % description)
        return parsed

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("%s repeats field %s" % (description, key))
            result[key] = value
        return result

    try:
        text = bytes(raw).decode("utf-8") if not isinstance(raw, str) else raw
        return json.loads(text,
                          object_pairs_hook=unique_object,
                          parse_constant=reject_constant,
                          parse_float=finite_float)
    except UnicodeDecodeError as exc:
        raise ValueError("%s is not UTF-8" % description) from exc


def load_bounded_json_response(response, maximum, description="JSON response"):
    """Read one strict UTF-8 JSON value through an explicit memory ceiling."""
    if (type(maximum) is not int or maximum <= 0
            or maximum > _MAX_JSON_RESPONSE_BYTES):
        raise ValueError("JSON response byte limit is invalid")
    raw = response.read(maximum + 1)
    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError("%s did not return bytes" % description)
    if len(raw) > maximum:
        raise ValueError("%s exceeds %d bytes" % (description, maximum))
    return strict_json_loads(raw, description)


def read_bounded_regular_file(path, maximum, description="operator file",
                              *, private=False):
    """Read one bounded, non-linked operator file through its checked descriptor.

    Root-owned deployment files and files owned by the current service account are
    accepted.  Public manifests may be readable by other users but can never be
    group/world writable; ``private=True`` additionally requires mode 0600-style
    confidentiality.  Checking the opened descriptor (rather than an earlier
    ``lstat`` result) closes the pathname substitution race.
    """
    if not isinstance(path, str) or not os.path.isabs(path):
        raise RuntimeError("%s path must be absolute" % description)
    if (type(maximum) is not int or maximum <= 0 or
            maximum > _MAX_LOCAL_FILE_BYTES):
        raise RuntimeError("%s byte limit is invalid" % description)
    if os.name == "nt":
        if __package__:
            from .windows_protected_file import read_protected_file
        else:
            from windows_protected_file import read_protected_file
        try:
            return read_protected_file(path, maximum, description, private=private)
        except (OSError, ValueError) as exc:
            raise RuntimeError("%s could not be read securely: %s" %
                               (description, exc)) from exc
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RuntimeError("platform lacks O_NOFOLLOW required for %s" % description)
    fd = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_uid not in (0, os.geteuid()) or mode & 0o022 or
                (private and mode & 0o077)):
            qualifier = "private " if private else "non-writable "
            raise RuntimeError(
                "%s must be a root/service-owned, non-linked %sregular file" %
                (description, qualifier))
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum:
            raise RuntimeError("%s exceeds %d bytes" % (description, maximum))
        return raw
    finally:
        os.close(fd)


def load_bounded_json_file(path, maximum, description="JSON operator file",
                           *, private=False):
    """Read and strictly decode one security-sensitive local JSON document."""
    raw = read_bounded_regular_file(
        path, maximum, description, private=private)
    try:
        return strict_json_loads(raw, description)
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc


def read_bounded_secret_file(path, maximum=4096, description="secret file"):
    """Read a root/service-owned, owner-only regular file without link races."""
    if type(maximum) is not int or maximum <= 0 or maximum > 1024 * 1024:
        raise RuntimeError("%s byte limit is invalid" % description)
    return read_bounded_regular_file(
        path, maximum, description, private=True)


def run_bounded_subprocess(argv, *, input_text=None, timeout,
                           stdout_max, stderr_max,
                           description="operator subprocess", env=None):
    """Run one POSIX operator command with timeout and hard output ceilings.

    ``subprocess.run(capture_output=True)`` accumulates an arbitrary child response
    in RAM before a caller can inspect its length.  This implementation drains both
    nonblocking pipes incrementally and kills the child's process group as soon as
    either byte budget or the wall-clock deadline is crossed.
    """
    if (not isinstance(argv, (list, tuple)) or not argv or
            any(not isinstance(item, str) or not item or "\x00" in item
                for item in argv)):
        raise RuntimeError("%s argv is malformed" % description)
    if type(timeout) not in (int, float) or isinstance(timeout, bool) or timeout <= 0:
        raise RuntimeError("%s timeout is invalid" % description)
    for value in (stdout_max, stderr_max):
        if (type(value) is not int or value <= 0 or
                value > _MAX_SUBPROCESS_OUTPUT_BYTES):
            raise RuntimeError("%s output limit is invalid" % description)
    if input_text is not None and not isinstance(input_text, str):
        raise RuntimeError("%s input must be text" % description)
    input_raw = b"" if input_text is None else input_text.encode("utf-8")
    if len(input_raw) > _MAX_SUBPROCESS_OUTPUT_BYTES:
        raise RuntimeError("%s input exceeds safety limit" % description)

    # Preserve the project's existing mock seam. In production subprocess.run is
    # untouched and this branch is unreachable; tests that replace it still get a
    # normal CompletedProcess without launching operator binaries.
    if subprocess.run is not _ORIGINAL_SUBPROCESS_RUN:
        completed = subprocess.run(
            list(argv), input=input_text, capture_output=True, text=True,
            timeout=timeout, env=env, check=False)
        stdout_value = getattr(completed, "stdout", "")
        stderr_value = getattr(completed, "stderr", "")
        stdout_raw = (stdout_value.encode("utf-8") if isinstance(stdout_value, str)
                      else bytes(stdout_value or b""))
        stderr_raw = (stderr_value.encode("utf-8") if isinstance(stderr_value, str)
                      else bytes(stderr_value or b""))
    else:
        proc = subprocess.Popen(
            list(argv), stdin=(subprocess.PIPE if input_text is not None
                               else subprocess.DEVNULL),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
            start_new_session=True)
        selector = selectors.DefaultSelector()
        stdout_raw = bytearray()
        stderr_raw = bytearray()
        stdin_offset = 0

        def stop_child():
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    try:
                        proc.kill()
                    except OSError:
                        pass

        try:
            for stream, label in ((proc.stdout, "stdout"),
                                  (proc.stderr, "stderr")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            if proc.stdin is not None:
                os.set_blocking(proc.stdin.fileno(), False)
                selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")

            deadline = time.monotonic() + float(timeout)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    stop_child()
                    raise subprocess.TimeoutExpired(list(argv), timeout)
                events = selector.select(remaining)
                if not events:
                    stop_child()
                    raise subprocess.TimeoutExpired(list(argv), timeout)
                for key, _mask in events:
                    stream = key.fileobj
                    if key.data == "stdin":
                        try:
                            if stdin_offset < len(input_raw):
                                wrote = os.write(
                                    stream.fileno(), input_raw[stdin_offset:
                                                               stdin_offset + 65536])
                                stdin_offset += wrote
                            if stdin_offset >= len(input_raw):
                                selector.unregister(stream)
                                stream.close()
                        except (BlockingIOError, InterruptedError):
                            pass
                        except BrokenPipeError:
                            selector.unregister(stream)
                            stream.close()
                        continue

                    target = stdout_raw if key.data == "stdout" else stderr_raw
                    maximum = stdout_max if key.data == "stdout" else stderr_max
                    try:
                        chunk = os.read(stream.fileno(), min(65536, maximum + 1 - len(target)))
                    except (BlockingIOError, InterruptedError):
                        continue
                    if chunk:
                        target.extend(chunk)
                        if len(target) > maximum:
                            stop_child()
                            raise RuntimeError("%s output exceeds safety limit" % description)
                    else:
                        selector.unregister(stream)
                        stream.close()

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stop_child()
                raise subprocess.TimeoutExpired(list(argv), timeout)
            returncode = proc.wait(timeout=remaining)
        except BaseException:
            stop_child()
            try:
                proc.wait(timeout=5)
            except (subprocess.SubprocessError, OSError):
                pass
            raise
        finally:
            selector.close()
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
        completed = subprocess.CompletedProcess(list(argv), returncode)
        stdout_raw = bytes(stdout_raw)
        stderr_raw = bytes(stderr_raw)

    if len(stdout_raw) > stdout_max or len(stderr_raw) > stderr_max:
        raise RuntimeError("%s output exceeds safety limit" % description)
    try:
        stdout = stdout_raw.decode("utf-8")
        stderr = stderr_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("%s output is not UTF-8" % description) from exc
    return subprocess.CompletedProcess(
        list(argv), completed.returncode, stdout=stdout, stderr=stderr)


def build_direct_requests_session(rpc_url, field_name="rpc_url"):
    """Build the same no-proxy/no-redirect boundary for requests users.

    Web3's HTTP provider uses ``requests`` internally rather than urllib, so it
    cannot call :func:`open_rpc_request` directly.  Revalidate the authority at
    every request, ignore ambient proxy variables, and force redirects off.
    """
    validate_backend_rpc_url(rpc_url, field_name)
    try:
        import requests
    except ImportError as exc:  # pragma: no cover - Web3 itself requires requests
        raise RuntimeError("requests is required for the HTTP RPC provider") from exc

    class _DirectNoRedirectSession(requests.Session):
        def request(self, method, url, **kwargs):
            validate_backend_rpc_url(str(url), field_name)
            kwargs["allow_redirects"] = False
            return super().request(method, url, **kwargs)

    session = _DirectNoRedirectSession()
    session.trust_env = False
    return session
