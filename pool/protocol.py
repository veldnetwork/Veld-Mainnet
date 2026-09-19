import json
import re

VERSION = 'veld-pool/1'
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
NONCE = re.compile(r'[0-9a-f]{16}\Z')

class Refused(ValueError):
    pass

class Busy(RuntimeError):
    pass

def require(value, message):
    if not value:
        raise Refused(message)

def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON member')
        result[key] = value
    return result

def decode(raw, maximum=16384):
    require(isinstance(raw, bytes) and len(raw) <= maximum, 'message limit')
    try:
        result = json.loads(raw.decode('utf8'), object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(Refused('JSON constant')))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise Refused('invalid JSON') from error
    require(isinstance(result, dict), 'JSON object required')
    return result

def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf8')

def schema(value, fields):
    require(isinstance(value, dict) and set(value) == set(fields), 'message schema')

def hex64(value):
    require(isinstance(value, str) and HEX64.fullmatch(value), 'hex256 encoding')
    return value

def nonce(value):
    require(isinstance(value, str) and NONCE.fullmatch(value), 'nonce encoding')
    return int(value, 16)

def units(value, maximum=(1 << 64) - 1):
    require(isinstance(value, str) and re.fullmatch(r'0|[1-9][0-9]{0,19}', value), 'integer encoding')
    result = int(value)
    require(result <= maximum, 'integer range')
    return result
