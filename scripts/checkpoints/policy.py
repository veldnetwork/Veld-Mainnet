"""Validation shared by checkpoint signing and atomic publication."""
import hashlib
import json
import re
import time

MAX_BYTES = 8 * 1024 * 1024
GENESIS = '7be77ab9e820bd9ffb60b269b45ced48288056e5839a1135fafc2f8557000a88'
MIN_DEPTH = 120
INTERVAL = 100


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON field')
        result[key] = value
    return result


def parse(raw):
    require(0 < len(raw) <= MAX_BYTES, 'Checkpoint document size rejected')
    value = json.loads(raw, object_pairs_hook=unique_object)
    if isinstance(value, dict):
        require(set(value) == {'checkpoints'}, 'Unexpected checkpoint envelope')
        value = value['checkpoints']
    require(isinstance(value, list) and 0 < len(value) <= 1000, 'Checkpoint list rejected')
    previous = 0
    for record in value:
        require(isinstance(record, dict) and set(record) == {'height', 'hash', 'signed_at', 'sig'}, 'Checkpoint fields rejected')
        require(type(record['height']) is int and previous < record['height'] < 2**64, 'Checkpoint height order rejected')
        require(type(record['signed_at']) is int and 0 < record['signed_at'] <= int(time.time()) + 300, 'Checkpoint signing time rejected')
        require(isinstance(record['hash'], str) and re.fullmatch('[0-9a-f]{64}', record['hash']) and int(record['hash'], 16) != 0, 'Checkpoint hash rejected')
        require(isinstance(record['sig'], str) and re.fullmatch('[0-9a-f]{6618}', record['sig']), 'Checkpoint signature encoding rejected')
        previous = record['height']
    return value


def encode(records):
    raw = (json.dumps(records, separators=(',', ':')) + '\n').encode()
    parse(raw)
    return raw


def preserves(before, after):
    require(len(after) >= len(before) and after[:len(before)] == before, 'Published checkpoint history changed')


def append_only(before, after):
    preserves(before, after)
    require(len(after) == len(before) + 1, 'Publication must append exactly one checkpoint')


def qualify(rows, requested=()):
    require(len(rows) == 3 and len({r['host'] for r in rows}) == 3, 'Three distinct fleet observations required')
    now = time.time()
    for row in rows:
        require(0 <= now - row['unix_time'] <= 90, 'Fleet observation is stale')
        require(row['genesis'] == GENESIS, 'Fleet network mismatch')
        require(row['ibd_complete'] and row['historical_validated'], 'Fleet validation incomplete')
        require(row['active'] and row['uptime_seconds'] >= MIN_DEPTH and row['pid_unchanged'], 'Fleet service unstable')
        require(row['clock_synchronized'], 'Fleet clock unsynchronized')
        require(row['fresh_outbound'] >= 2 and row['matching_outbound'] >= 2, 'Fleet peer quorum unavailable')
        require(row['state_height'] == row['height'] and row['state_tip'] == row['tip'], 'Fleet state is incoherent')
    require(len({(r['height'], r['tip'], r['state_digest']) for r in rows}) == 1, 'Fleet tip or state disagreement')
    for height in requested:
        hashes = {r['hashes'].get(str(height)) for r in rows}
        require(len(hashes) == 1 and None not in hashes, 'Historical block disagreement')
    return rows[0]['height']


def candidate_height(tip):
    require(type(tip) is int and tip >= MIN_DEPTH + INTERVAL, 'Chain below checkpoint range')
    return ((tip - MIN_DEPTH) // INTERVAL) * INTERVAL


def bind_records(records, rows):
    for record in records:
        require(all(r['hashes'].get(str(record['height'])) == record['hash'] for r in rows), 'Signed checkpoint disagrees with fleet history')


def bind_candidate(height, block_hash, rows):
    tip = qualify(rows, [height])
    require(height % INTERVAL == 0 and tip - height >= MIN_DEPTH, 'Checkpoint lacks confirmation depth')
    require(all(r['hashes'][str(height)] == block_hash for r in rows), 'Checkpoint candidate disagrees with fleet')
