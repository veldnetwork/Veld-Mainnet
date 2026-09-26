"""Bounded extraction from a natively verified CIA1 authorization.

Decoding is not signature or chain authorization. The caller must independently
verify the complete envelope with the pinned native node before using its data.
"""


def authorized_parents(wire, unsigned):
    if (
        type(wire) is not bytes
        or not 5 <= len(wire) <= 50000
        or wire[:4] != b"CIA1"
        or wire[4] not in (1, 2)
        or type(unsigned) is not bytes
    ):
        raise ValueError("custody authorization wire is invalid")
    position = 5

    def take(length):
        nonlocal position
        if length > len(wire) - position:
            raise ValueError("custody authorization is truncated")
        value = wire[position : position + length]
        position += length
        return value

    def number(width):
        return int.from_bytes(take(width), "little")

    def vector(maximum):
        length = number(4)
        if not 0 < length <= maximum:
            raise ValueError("custody authorization field exceeds its bound")
        return take(length)

    take(6 * 32 + 2 * 8)
    vector(80)
    vector(128)
    take(8)
    if vector(12000) != unsigned:
        raise ValueError("custody authorization binds another unsigned transaction")
    count = number(1)
    if not 2 <= count <= 8:
        raise ValueError("custody authorization parent count is invalid")
    parents, total = [], 0
    for _ in range(count):
        parent = vector(10000 - total)
        total += len(parent)
        parents.append(parent)
    count = number(1)
    if not 3 <= count <= 5:
        raise ValueError("custody authorization requires three to five approvals")
    previous = -1
    for _ in range(count):
        member = number(1)
        if not previous < member < 5:
            raise ValueError("custody authorization approvals are not distinct and ordered")
        previous = member
        take(3309)
    if position != len(wire):
        raise ValueError("custody authorization has trailing bytes")
    return parents
