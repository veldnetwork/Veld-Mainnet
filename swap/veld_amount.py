# veld_amount.py — exact VELD quote math for swaps (no float drift).
#
# A swap quote is a FRACTIONAL VELD amount so cheap coins (DOGE etc.) swap
# smoothly at low amounts instead of rounding the output down to a whole VELD.
# Amounts are quantized to 2 decimal places (0.01 VELD) — both the quoted number
# AND the amount the desk actually locks on-chain — so the user never sees (or
# gets) a VELD figure with more than two digits after the decimal point.
#
# Computed in integer VELD base units (1 VELD = 1e8 units): the per-coin rate
# (which may be fractional, e.g. DOGE 0.124) is scaled to an integer "VELD base
# units per whole coin" exactly once, then everything is pure integer math — so
# there is no float rounding in the amount the desk locks.
from decimal import Decimal, InvalidOperation

VELD_UNITS = 100_000_000  # base units per 1 VELD (chain precision, 8 dp)
QUOTE_DECIMALS = 2  # swaps quote + lock VELD to this many dp
_QUOTE_STEP = VELD_UNITS // (
    10**QUOTE_DECIMALS
)  # base units per one quote step (0.01 VELD = 1_000_000)


def quote_base_units(amount_base, veld_per_coin, decimals):
    """amount_base (coin base units) -> VELD base units (int), floored to 0.01 VELD."""
    if type(amount_base) is not int or amount_base < 0:
        raise ValueError('amount_base must be a non-negative integer')
    if type(decimals) is not int or decimals < 0 or decimals > 18:
        raise ValueError('coin decimals must be an integer in [0,18]')
    if isinstance(veld_per_coin, bool):
        raise ValueError('VELD-per-coin rate must be numeric, not boolean')
    try:
        # str(float) preserves the human decimal chosen by the price feed while
        # avoiding the binary-float multiply that previously lost base units.
        rate = Decimal(str(veld_per_coin))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError('VELD-per-coin rate is malformed') from exc
    if not rate.is_finite() or rate <= 0 or rate > Decimal('1000000000000'):
        raise ValueError('VELD-per-coin rate is outside the supported range')
    scaled = rate * VELD_UNITS
    integral = scaled.to_integral_value()
    if scaled != integral:
        raise ValueError('VELD-per-coin rate has more than 8 decimal places')
    veld_base_per_coin = int(integral)
    raw = (amount_base * veld_base_per_coin) // (10**decimals)
    return (raw // _QUOTE_STEP) * _QUOTE_STEP  # floor to the 0.01-VELD step


def format_veld(base_units):
    """VELD base units -> decimal VELD string with exactly QUOTE_DECIMALS places,
    e.g. 620000000 -> '6.20', 12000000 -> '0.12'. Pure integer formatting (exact)."""
    base_units = int(base_units)
    whole, frac = divmod(base_units, VELD_UNITS)
    frac_str = ('%08d' % frac)[:QUOTE_DECIMALS]
    return '%d.%s' % (whole, frac_str)


def quote_veld_str(amount_base, veld_per_coin, decimals):
    """Convenience: coin base units -> exact 2-dp VELD decimal string."""
    return format_veld(quote_base_units(amount_base, veld_per_coin, decimals))
