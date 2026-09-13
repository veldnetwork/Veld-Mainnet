"""Explicit chain pins for services that authorize external value."""
import re


_TEXT_FIELDS = ("profile_id", "consensus_build_profile")
_BOOL_FIELDS = ("disposable", "external_value", "fixed_difficulty_regtest")
_HASH_FIELDS = ("genesis_hash", "launch_block_hash")
_FIELDS = frozenset(_TEXT_FIELDS + _BOOL_FIELDS + _HASH_FIELDS)


def parse_expected_chain(value):
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise ValueError("expected_chain must contain the exact reviewed chain pins")
    for field in _TEXT_FIELDS:
        if (not isinstance(value[field], str) or
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value[field]) or
                value[field].startswith("REPLACE_")):
            raise ValueError("expected_chain.%s is not a reviewed profile" % field)
    for field in _BOOL_FIELDS:
        if type(value[field]) is not bool:
            raise ValueError("expected_chain.%s must be an exact boolean" % field)
    for field in _HASH_FIELDS:
        if (not isinstance(value[field], str) or
                not re.fullmatch(r"[0-9a-f]{64}", value[field]) or
                value[field] == "0" * 64):
            raise ValueError("expected_chain.%s must be a nonzero canonical hash" % field)
    return dict(value)


def verify_expected_chain(call, expected):
    expected = parse_expected_chain(expected)
    network = call("getnetworkinfo", [])
    if not isinstance(network, dict):
        raise ValueError("intended chain identity is unavailable")
    for field in _TEXT_FIELDS + _BOOL_FIELDS:
        observed = network.get(field)
        if type(observed) is not type(expected[field]) or observed != expected[field]:
            raise ValueError("intended chain %s does not match its pin" % field)
    compiled = call("getcompiledgenesis", [])
    genesis = call("getblockhash", [0])
    launch = call("getblockhash", [1])
    if (type(compiled) is not str or type(genesis) is not str or
            compiled != expected["genesis_hash"] or genesis != compiled):
        raise ValueError("compiled and stored genesis do not match the intended chain")
    if type(launch) is not str or launch != expected["launch_block_hash"]:
        raise ValueError("launch block does not match the intended chain")
    return expected
