#!/usr/bin/env python3
"""Small, dependency-free HTTP security primitives for ``swapd_server``.

Keep these helpers separate from the service bootstrap so their trust-boundary
and resource-limit behaviour can be regression-tested without loading signer
keys or connecting to either chain.
"""

from collections import OrderedDict, deque
import http.client
import ipaddress
import json
import math
import os
import socket
import socketserver
import stat
import threading
import time


class RequestSourceError(ValueError):
    """The request contains ambiguous or untrusted source attribution."""


def exact_json_bool(value, description):
    """Return an exact JSON boolean, rejecting truthy strings and integers."""
    if type(value) is not bool:
        raise RuntimeError("%s must be the JSON boolean true or false" % description)
    return value


def bounded_json_int(value, description, minimum, maximum):
    """Return an exact, bounded JSON integer (``bool`` is not an integer here)."""
    if (type(value) is not int or type(minimum) is not int
            or type(maximum) is not int or minimum > maximum
            or value < minimum or value > maximum):
        raise RuntimeError(
            "%s must be a JSON integer in [%d,%d]" %
            (description, minimum, maximum))
    return value


def read_owner_file(path, maximum, description):
    """Read one bounded, non-linked, owner-only service file."""
    if not isinstance(path, str) or not path:
        raise RuntimeError("%s path is missing" % description)
    if type(maximum) is not int or maximum <= 0:
        raise RuntimeError("%s byte limit is invalid" % description)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RuntimeError(
            "platform lacks O_NOFOLLOW required for %s" % description)
    fd = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0))
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise RuntimeError(
                "%s must be an owner-only regular file owned by the service user" %
                description)
        raw = os.read(fd, maximum + 1)
        if len(raw) > maximum:
            raise RuntimeError(
                "%s exceeds %d bytes" % (description, maximum))
        return raw
    finally:
        os.close(fd)


def read_trust_root_file(path, maximum, description, *, trusted_uid=0,
                         trusted_gid=None):
    """Read one immutable authority file owned outside the service account.

    Production installs these files as ``root:veldswap`` mode ``0440`` under
    ``/etc/veld-swap``. The UID/GID seams are keyword-only so unit tests can
    exercise the ownership contract without root; production uses UID 0 and
    the service's primary GID.
    """
    if not isinstance(path, str) or not path:
        raise RuntimeError("%s path is missing" % description)
    if type(maximum) is not int or maximum <= 0:
        raise RuntimeError("%s byte limit is invalid" % description)
    if type(trusted_uid) is not int or trusted_uid < 0:
        raise RuntimeError("%s trusted UID is invalid" % description)
    if trusted_gid is None:
        trusted_gid = os.getegid()
    if type(trusted_gid) is not int or trusted_gid < 0:
        raise RuntimeError("%s trusted GID is invalid" % description)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RuntimeError(
            "platform lacks O_NOFOLLOW required for %s" % description)
    fd = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0))
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_uid != trusted_uid
                or metadata.st_gid != trusted_gid
                or stat.S_IMODE(metadata.st_mode) != 0o440):
            raise RuntimeError(
                "%s must be one root-authorized 0440 regular file for the "
                "service group" % description)
        raw = os.read(fd, maximum + 1)
        if len(raw) > maximum:
            raise RuntimeError(
                "%s exceeds %d bytes" % (description, maximum))
        return raw
    finally:
        os.close(fd)


def _header_values(headers, name):
    """Return every wire occurrence of *name* (never comma-merge values)."""
    get_all = getattr(headers, "get_all", None)
    if get_all is not None:
        return list(get_all(name, []) or [])
    value = headers.get(name) if hasattr(headers, "get") else None
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _one_ip_header(headers, name, *, required=False):
    values = _header_values(headers, name)
    if not values:
        if required:
            raise RequestSourceError("missing %s" % name)
        return None
    if len(values) != 1:
        raise RequestSourceError("multiple %s headers" % name)
    value = values[0]
    if not isinstance(value, str):
        raise RequestSourceError("invalid %s" % name)
    value = value.strip()
    # X-Forwarded-For lists and IPv6 zone identifiers are deliberately not
    # accepted. nginx-swapd.conf overwrites both source headers with one
    # $remote_addr literal, so either construct is evidence of a bad proxy path.
    if not value or "," in value or "%" in value:
        raise RequestSourceError("ambiguous %s" % name)
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise RequestSourceError("invalid %s" % name) from exc


def request_source(client_address, headers):
    """Return the canonical rate-limit key for one HTTP request.

    ``X-Real-IP`` is authority only when the immediate socket peer is local
    (loopback TCP or a Unix-domain client address). A direct non-local peer may
    identify only itself; any proxy-attribution header on that path is rejected,
    not ignored. When nginx supplies both documented headers they must name the
    same single IP. The RFC ``Forwarded`` header is unsupported and rejected so
    there is never a second, conflicting attribution chain.
    """
    forwarded = _header_values(headers, "Forwarded")
    real_values = _header_values(headers, "X-Real-IP")
    xff_values = _header_values(headers, "X-Forwarded-For")

    is_unix = not isinstance(client_address, tuple)
    direct_ip = None
    if not is_unix:
        if not client_address or not isinstance(client_address[0], str):
            raise RequestSourceError("invalid direct peer address")
        try:
            direct_ip = ipaddress.ip_address(client_address[0])
        except ValueError as exc:
            raise RequestSourceError("invalid direct peer address") from exc
    trusted_local = is_unix or direct_ip.is_loopback

    if forwarded:
        raise RequestSourceError("Forwarded header is not accepted")
    if not trusted_local:
        if real_values or xff_values:
            raise RequestSourceError(
                "proxy source headers arrived from a non-local peer")
        return direct_ip.compressed

    if not real_values:
        if xff_values:
            raise RequestSourceError("X-Forwarded-For lacks X-Real-IP")
        return "local-unix" if is_unix else direct_ip.compressed

    real_ip = _one_ip_header(headers, "X-Real-IP", required=True)
    if xff_values:
        xff_ip = _one_ip_header(headers, "X-Forwarded-For", required=True)
        if xff_ip != real_ip:
            raise RequestSourceError("proxy source headers disagree")
    return real_ip.compressed


class SlidingWindowLimiter:
    """Exact per-key sliding window with a hard, CPU-bounded key table.

    Entries remain ordered by their most recent *allowed* hit. Rejected traffic
    cannot keep a slot alive. Expiry work is capped per call; if the table is
    still full after that bounded maintenance, a new key fails closed without
    being inserted. Thus spoofed source churn cannot grow memory or force an
    O(table-size) sweep on every request.
    """

    def __init__(self, limit, window_s, *, table_capacity=20_000,
                 maintenance_budget=256, clock=time.monotonic):
        if type(limit) is not int or limit <= 0:
            raise ValueError("rate limit must be a positive JSON integer")
        if type(window_s) is not int or window_s <= 0:
            raise ValueError("rate window must be a positive JSON integer")
        if type(table_capacity) is not int or table_capacity <= 0:
            raise ValueError("rate table capacity must be positive")
        if type(maintenance_budget) is not int or maintenance_budget <= 0:
            raise ValueError("rate maintenance budget must be positive")
        self.limit = limit
        self.window_s = window_s
        self.table_capacity = table_capacity
        self.maintenance_budget = maintenance_budget
        self._clock = clock
        self._entries = OrderedDict()
        self._lock = threading.Lock()

    def _discard_expired_front(self, cutoff):
        work = 0
        while self._entries and work < self.maintenance_budget:
            key, hits = next(iter(self._entries.items()))
            # Oldest entry is ordered by last allowed hit. If it is live, every
            # later entry is live too and no scan is necessary.
            if hits and hits[-1] > cutoff:
                break
            self._entries.popitem(last=False)
            work += 1

    def allow(self, key):
        if not isinstance(key, str) or not key or len(key) > 64:
            raise ValueError("invalid rate-limit key")
        now = self._clock()
        cutoff = now - self.window_s
        with self._lock:
            hits = self._entries.get(key)
            if hits is not None:
                while hits and hits[0] <= cutoff:
                    hits.popleft()
                if not hits:
                    del self._entries[key]
                    hits = None

            self._discard_expired_front(cutoff)

            if hits is not None and len(hits) >= self.limit:
                return False
            if hits is None:
                if len(self._entries) >= self.table_capacity:
                    return False
                hits = deque()
                self._entries[key] = hits
            hits.append(now)
            self._entries.move_to_end(key)
            return True

    def table_size(self):
        with self._lock:
            return len(self._entries)

    def stored_hits(self):
        with self._lock:
            return sum(len(hits) for hits in self._entries.values())


class HeaderBudgetReader:
    """``readline`` facade enforcing one aggregate HTTP-header byte budget."""

    def __init__(self, raw, byte_limit):
        self._raw = raw
        self._limit = byte_limit
        self._used = 0

    def readline(self, size=-1):
        remaining = self._limit - self._used
        if remaining <= 0:
            raise http.client.LineTooLong("aggregate request headers")
        # Read one byte beyond the budget so crossing it is detected even when
        # the caller supplied http.client's much larger per-line allowance.
        allowed = remaining + 1
        if size is None or size < 0 or size > allowed:
            size = allowed
        line = self._raw.readline(size)
        self._used += len(line)
        if self._used > self._limit:
            raise http.client.LineTooLong("aggregate request headers")
        return line


def strict_json_object(raw):
    """Decode UTF-8 JSON, rejecting duplicate keys and non-finite numbers."""
    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError("request body must be bytes")

    def reject_constant(value):
        raise ValueError("non-finite JSON number: %s" % value)

    def finite_float(value):
        parsed = float(value)
        # Valid JSON such as 1e999 overflows CPython's binary float even though
        # it does not use the NaN/Infinity parse_constant path.
        if not math.isfinite(parsed):
            raise ValueError("JSON number is outside the finite range")
        return parsed

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field: %s" % key)
            result[key] = value
        return result

    try:
        value = json.loads(bytes(raw).decode("utf-8"),
                           object_pairs_hook=unique_object,
                           parse_constant=reject_constant,
                           parse_float=finite_float)
    except UnicodeDecodeError as exc:
        raise ValueError("request body is not UTF-8") from exc
    if not isinstance(value, dict):
        raise ValueError("request JSON must be an object")
    return value


class BoundedThreadingTCPServer(socketserver.ThreadingMixIn,
                                socketserver.TCPServer):
    """Threaded loopback server with a hard worker and request-read deadline."""

    allow_reuse_address = True
    daemon_threads = True
    block_on_close = True
    request_queue_size = 64

    def __init__(self, server_address, handler, *, max_workers,
                 request_read_timeout_s, bind_and_activate=True):
        if type(max_workers) is not int or max_workers <= 0:
            raise ValueError("max_workers must be positive")
        if (type(request_read_timeout_s) is not int
                or request_read_timeout_s <= 0):
            raise ValueError("request_read_timeout_s must be positive")
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        self._request_read_timeout_s = request_read_timeout_s
        self._deadline_lock = threading.Lock()
        self._read_deadlines = {}
        super().__init__(server_address, handler, bind_and_activate)

    @staticmethod
    def _expire_request(request):
        try:
            request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            request.close()
        except OSError:
            pass

    def process_request(self, request, client_address):
        if not self._worker_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        timer = threading.Timer(
            self._request_read_timeout_s, self._expire_request, (request,))
        timer.daemon = True
        with self._deadline_lock:
            self._read_deadlines[id(request)] = timer
        try:
            try:
                timer.start()
            except RuntimeError:
                # A process unable to create the deadline guard must not serve
                # an unbounded request. Close it and still release the slot.
                self._expire_request(request)
                return
            super().process_request_thread(request, client_address)
        finally:
            self.mark_request_read(request)
            self._worker_slots.release()

    def mark_request_read(self, request):
        """Cancel the slow-request deadline after headers/body are complete."""
        with self._deadline_lock:
            timer = self._read_deadlines.pop(id(request), None)
        if timer is not None:
            timer.cancel()

