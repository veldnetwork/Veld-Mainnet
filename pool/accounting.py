"""Exact pool allocation; caller supplies canonically verified earning events.

No floating point, per-account integer rounding, or payment-time beneficiaries.
Fractional base units remain liabilities; payment can withdraw only floor(balance).
"""

from fractions import Fraction
from .protocol import require, hex64

SPACE = 1 << 256


def expected_work(target):
    target = int(hex64(target), 16)
    require(0 < target < SPACE, 'target range')
    return Fraction(SPACE, target)  # canonical proof rule is hash < target


def fee_key(receipt):
    fee = receipt.get('fee_ppm', '0')
    from .protocol import units

    return receipt['account'], units(fee, 1000000)


def pplns(receipts, cutoff, network_target, lookback=2, ordered=False, fee_policy=False):
    remaining = lookback * expected_work(network_target)
    weights = {}
    # Durable arrival order, regardless of verification completion order.
    for receipt in (
        receipts if ordered else sorted(receipts, key=lambda value: value['seq'], reverse=True)
    ):
        if receipt['seq'] > cutoff or receipt['status'] != 'verified':
            continue
        work = min(expected_work(receipt['target']), remaining)
        key = fee_key(receipt) if fee_policy else receipt['account']
        weights[key] = weights.get(key, Fraction()) + work
        remaining -= work
        if remaining == 0:
            break
    return weights


def window_weights(receipts, first, last, cutoff, fee_policy=False):
    weights = {}
    for receipt in receipts:
        if (
            receipt['seq'] <= cutoff
            and first <= receipt['height'] <= last
            and receipt['status'] == 'verified'
        ):
            key = fee_key(receipt) if fee_policy else receipt['account']
            weights[key] = weights.get(key, Fraction()) + expected_work(receipt['target'])
    return weights


def allocate(amount, weights, fee_ppm=0):
    require(type(amount) is int and amount >= 0, 'amount')
    require(type(fee_ppm) is int and 0 <= fee_ppm <= 1000000, 'fee')
    require(all(isinstance(w, Fraction) and w > 0 for w in weights.values()), 'weights')
    total = sum(weights.values(), Fraction())
    require(total > 0 or amount == 0, 'income with no beneficiaries must be quarantined')
    fee = Fraction(amount * fee_ppm, 1000000)
    return ({account: (amount - fee) * weight / total for account, weight in weights.items()}, fee)


def text(value):
    return f'{value.numerator}/{value.denominator}'


def allocate_policy(amount, weights):
    """Fees follow each assigned share's policy, including mixed PPLNS windows."""
    gross, _ = allocate(amount, weights)
    credits = {}
    fee = Fraction()
    for (account, ppm), value in gross.items():
        require(type(ppm) is int and 0 <= ppm <= 1000000, 'receipt fee')
        charge = value * Fraction(ppm, 1000000)
        fee += charge
        credits[account] = credits.get(account, Fraction()) + value - charge
    return credits, fee


def floor_total(values):
    """Exact spendable units without a giant common-denominator balance.

    Each earning event retains its exact rational entitlement. A 256-bit
    interval usually proves the integer sum; ambiguous boundaries use exact
    arithmetic. No approximation can increase a payment or erase a remainder.
    """
    groups = {}
    for value in values:
        require(isinstance(value, Fraction) and value >= 0, 'nonnegative entitlement')
        groups[value.denominator] = groups.get(value.denominator, 0) + value.numerator
    if not groups:
        return 0
    lower = upper = 0
    inexact = False
    scale = 1 << 256
    for denominator, numerator in groups.items():
        quotient, remainder = divmod(numerator * scale, denominator)
        lower += quotient
        upper += quotient + bool(remainder)
        inexact |= bool(remainder)
    minimum = lower // scale
    maximum = (upper - 1) // scale if inexact else upper // scale
    if minimum == maximum:
        return minimum
    # Balanced addition avoids repeatedly multiplying a growing accumulator.
    terms = [Fraction(n, d) for d, n in groups.items()]
    while len(terms) > 1:
        terms = [
            terms[i] + terms[i + 1] if i + 1 < len(terms) else terms[i]
            for i in range(0, len(terms), 2)
        ]
    return terms[0].numerator // terms[0].denominator
