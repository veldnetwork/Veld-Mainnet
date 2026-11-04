#!/usr/bin/env python3
"""Serve current public stats with a coherent compact-target hashrate."""

from collections import OrderedDict
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import math
import os
import re
import time

MAX_RESPONSE = 1024 * 1024
CACHE_SECONDS = 2
FAILURE_BACKOFF_SECONDS = 1
BACKEND_PORT = int(os.environ.get("VELD_STATS_BACKEND_PORT", "8080"))
if BACKEND_PORT not in (8080, 18080):
    raise ValueError("unsupported local public backend")


class PublicBackendError(ValueError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def read_public(path):
    connection = http.client.HTTPConnection("127.0.0.1", BACKEND_PORT, timeout=2)
    try:
        connection.request(
            "GET", path, headers={"Host": "explorer.veld.network", "Accept-Encoding": "identity"}
        )
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ValueError("public backend unavailable")
        try:
            value = json.loads(raw)
        except ValueError:
            if response.status != 200:
                raise PublicBackendError(
                    response.status,
                    "public backend status " + str(response.status) + " for " + path,
                )
            raise
        if not isinstance(value, dict):
            raise ValueError("invalid public response")
        if response.status != 200:
            raise PublicBackendError(
                response.status, str(value.get("error", "public backend unavailable"))
            )
        return value
    finally:
        connection.close()


BLOCK_PAGE_BUDGET_ERROR = "canonical block page unavailable or above display budget; use block RPC"
BLOCK_FIELDS = (
    "height",
    "hash",
    "prev_hash",
    "time",
    "bits",
    "nonce",
    "merkle_root",
    "size",
    "tx_count",
    "reward_veld",
    "miner",
    "winner",
)


class SharedPublicReader:
    def __init__(self, read=read_public, clock=time.monotonic):
        self.read = read
        self.clock = clock
        self.stats = None
        self.expires = 0
        self.responses = OrderedDict()
        self.blocks = OrderedDict()

    def cached_block(self, height):
        if self.stats is None:
            return None
        return self.blocks.get(
            (self.stats.get("height"), self.stats.get("best_block_hash"), height)
        )

    def remember_blocks(self, values):
        if self.stats is None:
            return
        for value in values:
            key = (self.stats.get("height"), self.stats.get("best_block_hash"), value["height"])
            self.blocks[key] = value
            self.blocks.move_to_end(key)
        while len(self.blocks) > 512:
            self.blocks.popitem(last=False)

    def fresh_stats(self):
        self.stats = self.read("/api/stats")
        self.expires = self.clock() + CACHE_SECONDS
        return self.stats

    def __call__(self, path):
        if path == "/api/stats":
            if self.stats is not None and self.clock() < self.expires:
                return self.stats
            return self.fresh_stats()
        if self.stats is None or not path.startswith("/api/v1/block"):
            return self.read(path)
        key = (self.stats.get("height"), self.stats.get("best_block_hash"), path)
        if key in self.responses:
            self.responses.move_to_end(key)
            value = self.responses[key]
            if isinstance(value, PublicBackendError):
                raise value
            return value
        try:
            value = self.read(path)
        except PublicBackendError as error:
            if error.status != 503 or str(error) != BLOCK_PAGE_BUDGET_ERROR:
                raise
            value = error
        self.responses[key] = value
        if len(self.responses) > 128:
            self.responses.popitem(last=False)
        if isinstance(value, PublicBackendError):
            raise value
        return value


def validate_blocks(blocks, start, count):
    if not isinstance(blocks, list) or len(blocks) != count:
        raise ValueError("incomplete block page")
    for index, block in enumerate(blocks):
        if (
            not isinstance(block, dict)
            or type(block.get("height")) is not int
            or block["height"] != start - index
        ):
            raise ValueError("invalid block height")
        for key in ("hash", "prev_hash"):
            if not isinstance(block.get(key), str) or not re.fullmatch("[a-f0-9]{64}", block[key]):
                raise ValueError("invalid block hash")
        if type(block.get("time")) is not int or not 0 <= block["time"] <= 0xFFFFFFFF:
            raise ValueError("invalid block timestamp")
        if type(block.get("size")) is not int or not 0 < block["size"] <= 8000000:
            raise ValueError("invalid block size")
        if type(block.get("tx_count")) is not int or not 0 <= block["tx_count"] <= 100000:
            raise ValueError("invalid transaction count")
        if index and blocks[index - 1]["prev_hash"] != block["hash"]:
            raise ValueError("noncontiguous block page")
    return blocks


def bounded_block_page(read, start, count, clock=time.monotonic):
    deadline = clock() + 6
    calls = 0

    def fetch(path):
        nonlocal calls
        calls += 1
        if calls > 100 or clock() > deadline:
            raise ValueError("block page read budget exceeded")
        return read(path)

    def collect(height, length):
        if hasattr(read, "cached_block"):
            known = [read.cached_block(h) for h in range(height, height - length, -1)]
            if any(block is not None for block in known):
                result = []
                index = 0
                while index < length:
                    if known[index] is not None:
                        result.append(known[index])
                        index += 1
                    else:
                        end = index + 1
                        while end < length and known[end] is None:
                            end += 1
                        result.extend(collect(height - index, end - index))
                        index = end
                return validate_blocks(result, height, length)
        try:
            page = fetch("/api/v1/blocks/" + str(height) + "/" + str(length))
            blocks = validate_blocks(page.get("blocks"), height, length)
            if hasattr(read, "remember_blocks"):
                read.remember_blocks(blocks)
            return blocks
        except PublicBackendError as error:
            if error.status != 503 or str(error) != BLOCK_PAGE_BUDGET_ERROR:
                raise
            if length == 1:
                block = fetch("/api/v1/block/" + str(height))
                summary = {key: block[key] for key in BLOCK_FIELDS if key in block}
                blocks = validate_blocks([summary], height, 1)
                if hasattr(read, "remember_blocks"):
                    read.remember_blocks(blocks)
                return blocks
            half = length // 2
            return collect(height, half) + collect(height - half, length - half)

    if (
        type(start) is not int
        or not 0 <= start <= 1000000000
        or type(count) is not int
        or not 1 <= count <= min(50, start + 1)
    ):
        raise ValueError("invalid page bounds")
    return validate_blocks(collect(start, count), start, count)


class BlockPageCache:
    def __init__(self, read=read_public):
        self.read = read
        self.pages = OrderedDict()

    def tip(self, fresh=False):
        stats = (
            self.read.fresh_stats()
            if fresh and hasattr(self.read, "fresh_stats")
            else self.read("/api/stats")
        )
        height, block_hash = stats.get("height"), stats.get("best_block_hash")
        if type(height) is not int or not 0 <= height <= 1000000000:
            raise ValueError("invalid tip height")
        if not isinstance(block_hash, str) or not re.fullmatch("[a-f0-9]{64}", block_hash):
            raise ValueError("invalid tip hash")
        return height, block_hash

    def get(self, requested, count):
        tip_height, tip_hash = self.tip()
        start = tip_height if requested == "latest" else int(requested)
        if start > tip_height:
            raise PublicBackendError(409, "requested page is newer than the current tip")
        count = min(count, start + 1)
        key = (tip_height, tip_hash, start, count)
        if key in self.pages:
            self.pages.move_to_end(key)
            return self.pages[key]
        blocks = bounded_block_page(self.read, start, count)
        if self.tip(fresh=True) != (tip_height, tip_hash) or (
            start == tip_height and blocks[0]["hash"] != tip_hash
        ):
            raise PublicBackendError(409, "canonical chain changed during page assembly")
        body = json.dumps(
            {
                "tip_height": tip_height,
                "tip_hash": tip_hash,
                "start": start,
                "end": start + 1 - count,
                "blocks": blocks,
            },
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        if len(body) > 65536:
            raise ValueError("block page response budget exceeded")
        self.pages[key] = body
        if len(self.pages) > 64:
            self.pages.popitem(last=False)
        return body


def network_hashrate(bits, seconds):
    if type(bits) is not int or not 0 < bits <= 0xFFFFFFFF or bits & 0x00800000:
        raise ValueError("invalid compact target")
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if not 3 <= exponent <= 32 or not mantissa:
        raise ValueError("invalid compact target")
    target = mantissa << (8 * (exponent - 3))
    if not 0 < target < 2**256:
        raise ValueError("invalid target range")
    if type(seconds) is not int or seconds != 180:
        raise ValueError("unexpected target interval")
    return round((2**256) / (target + 1) / seconds, 2)


def observed_hashrate(blocks):
    """Legacy-backend display fallback; blocks are canonical, newest first."""
    if len(blocks) < 2:
        return None, 0, 0
    # The oldest block is the starting boundary, not an earned interval.
    work = 0
    for block in blocks[:-1]:
        bits = block.get('bits')
        if type(bits) is not int or not 0 < bits <= 0xFFFFFFFF or bits & 0x00800000:
            raise ValueError('invalid compact target')
        exponent, mantissa = bits >> 24, bits & 0x007FFFFF
        target = (
            mantissa >> (8 * (3 - exponent)) if exponent <= 3 else mantissa << (8 * (exponent - 3))
        )
        if not 0 < target <= (0x7FFFFF << (8 * 29)):
            raise ValueError('invalid target range')
        size = (target.bit_length() + 7) // 8
        compact = target << (8 * (3 - size)) if size <= 3 else target >> (8 * (size - 3))
        if compact & 0x800000:
            compact >>= 8
            size += 1
        if compact | (size << 24) != bits:
            raise ValueError('noncanonical compact target')
        work += (1 << 256) // (target + 1)
    seconds = max(b['time'] for b in blocks) - min(b['time'] for b in blocks)
    return (work / seconds if seconds else None), len(blocks) - 1, seconds


class StatsCollector:
    def __init__(self, read=read_public):
        self.read = read
        self.tip_key = None
        self.bits = None
        self.estimate = None

    def collect(self):
        for _ in range(2):
            stats = self.read("/api/stats")
            height, tip = stats.get("height"), stats.get("best_block_hash")
            if type(height) is not int or not 1 <= height <= 1000000000:
                raise ValueError("invalid height")
            if not isinstance(tip, str) or re.fullmatch("[a-f0-9]{64}", tip) is None:
                raise ValueError("invalid tip")
            key = (height, tip)
            if stats.get('hashrate_method') == 'canonical_work_over_observed_time':
                rate, count, seconds = (
                    stats.get(k)
                    for k in ('hashrate', 'hashrate_window_blocks', 'hashrate_window_seconds')
                )
                if (
                    stats.get('hashrate_sample_height') != height
                    or type(count) is not int
                    or not 0 <= count <= 144
                    or type(seconds) is not int
                    or not 0 <= seconds < 2**64
                    or (
                        rate is not None
                        and (type(rate) not in (int, float) or not math.isfinite(rate) or rate <= 0)
                    )
                    or (rate is not None and (not count or not seconds))
                ):
                    raise ValueError('invalid native hashrate estimate')
                return dict(stats)
            if key == self.tip_key:
                estimate = self.estimate
            else:
                blocks = bounded_block_page(self.read, height, min(25, height + 1))
                block = blocks[0]
                if not isinstance(block, dict):
                    raise ValueError("invalid block")
                if block.get("height") != height or block.get("hash") != tip:
                    continue
                estimate = observed_hashrate(blocks)
                final = (
                    self.read.fresh_stats()
                    if hasattr(self.read, 'fresh_stats')
                    else self.read('/api/stats')
                )
                if (final.get('height'), final.get('best_block_hash')) != key:
                    continue
            # Cache observed work only for this exact canonical tip, not height alone.
            self.tip_key, self.estimate = key, estimate
            result = dict(stats)
            result.update(
                hashrate=estimate[0],
                hashrate_method='canonical_work_over_observed_time',
                hashrate_sample_height=height,
                hashrate_window_blocks=estimate[1],
                hashrate_window_seconds=estimate[2],
            )
            return result
        raise ValueError("chain changed during stats read")


class CurrentStatsCache:
    def __init__(self, collector=None, clock=time.monotonic):
        self.collector = collector or StatsCollector()
        self.clock = clock
        self.body = None
        self.expires_at = 0
        self.retry_at = 0

    def get(self):
        now = self.clock()
        if self.body is not None and now < self.expires_at:
            return self.body
        self.body = None
        if now < self.retry_at:
            raise ValueError("public backend retry pending")
        try:
            value = self.collector.collect()
            body = json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
        except (ValueError, OSError, http.client.HTTPException):
            self.retry_at = self.clock() + FAILURE_BACKOFF_SECONDS
            raise
        self.body = body
        self.expires_at = self.clock() + CACHE_SECONDS
        self.retry_at = 0
        return body


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def setup(self):
        self.request.settimeout(3)
        super().setup()

    def log_message(self, *args):
        pass

    def reply(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/v1/blocks/"):
            match = re.fullmatch(r"/api/v1/blocks/(latest|0|[1-9][0-9]{0,9})/([1-9][0-9]?)", path)
            if not match or int(match[2]) > 50:
                return self.reply(400, b'{"error":"invalid block page"}')
            try:
                return self.reply(200, self.server.block_pages.get(match[1], int(match[2])))
            except PublicBackendError as error:
                code = 409 if error.status == 409 else 503
                return self.reply(code, b'{"error":"canonical block page temporarily unavailable"}')
            except (ValueError, OSError, http.client.HTTPException):
                return self.reply(503, b'{"error":"canonical block page temporarily unavailable"}')
        if path != "/api/stats":
            return self.reply(404, b'{"error":"not found"}')
        try:
            self.reply(200, self.server.current_stats.get())
        except (ValueError, OSError, http.client.HTTPException):
            self.reply(503, b'{"error":"current network stats unavailable"}')

    do_HEAD = do_GET

    def do_POST(self):
        self.reply(405, b'{"error":"method not allowed"}')


def main():
    # One collector serializes refreshes, coalescing simultaneous readers.
    server = HTTPServer(("127.0.0.1", 8096), Handler)
    reader = SharedPublicReader()
    server.current_stats = CurrentStatsCache(StatsCollector(reader))
    server.block_pages = BlockPageCache(reader)
    server.serve_forever()


if __name__ == "__main__":
    main()
