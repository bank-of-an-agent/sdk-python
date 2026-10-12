"""Money helpers. Amounts are decimal strings on the wire and integers in minor units.

There are no floats anywhere in this module, and the SDK rejects floats wherever
an amount is accepted (mirrors ``money.ts`` in ``@agentbank/core``)::

    >>> parse_amount("12.50")
    12500000
    >>> format_amount(12_500_000)
    '12.50'
    >>> money("0.10")
    Money(amount='0.10', asset='USDC')
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from decimal import Decimal
from typing import Any

from agentbank.errors import AgentBankError
from agentbank.models import Money

__all__ = [
    "MAX_MINOR_UNITS",
    "USDC_DECIMALS",
    "MoneyInput",
    "coerce_money",
    "format_amount",
    "money",
    "parse_amount",
    "to_minor",
]

USDC_DECIMALS = 6
ASSET_DECIMALS = {"USDC": USDC_DECIMALS}

#: Largest amount the ledger accepts in one line: 2**63 - 1.
MAX_MINOR_UNITS = 2**63 - 1

_DECIMAL_RE = re.compile(r"^(0|[1-9][0-9]*)(?:\.([0-9]+))?$")

#: Anything the SDK accepts where the API expects ``Money``: a ``Money`` model,
#: a ``{"amount": ..., "asset": ...}`` mapping, or a decimal string / ``Decimal``
#: (interpreted as USDC, the only asset in v1). Floats and ints are rejected so
#: that major and minor units can never be confused.
MoneyInput = Money | Mapping[str, Any] | str | Decimal


def _check_decimals(decimals: int) -> None:
    if decimals < 0 or decimals > 36:
        raise AgentBankError("invalid_amount", f"Unsupported decimals: {decimals}")


def parse_amount(value: str, decimals: int = USDC_DECIMALS) -> int:
    """Parse a non-negative decimal string into integer minor units.

    Rejects exponents, signs, whitespace, leading zeros and excess precision.

    Raises:
        AgentBankError: ``invalid_amount``.
    """
    _check_decimals(decimals)
    if not isinstance(value, str):
        raise AgentBankError("invalid_amount", "Amounts must be decimal strings")
    match = _DECIMAL_RE.match(value)
    if match is None or not value.isascii():
        raise AgentBankError("invalid_amount", f'"{value}" is not a valid decimal amount')
    whole, fraction = match.group(1), match.group(2) or ""
    if len(fraction) > decimals:
        raise AgentBankError("invalid_amount", f'"{value}" has more than {decimals} decimal places')
    scale: int = 10**decimals
    minor = int(whole) * scale + int(fraction.ljust(decimals, "0") or "0")
    if minor > MAX_MINOR_UNITS:
        raise AgentBankError("invalid_amount", f'"{value}" exceeds the maximum supported amount')
    return minor


def format_amount(
    minor: int, decimals: int = USDC_DECIMALS, *, min_fraction_digits: int = 2
) -> str:
    """Format integer minor units as a canonical decimal string.

    Trailing zeros are trimmed down to ``min_fraction_digits`` (default 2):
    ``25_000_000`` (USDC) becomes ``"25.00"`` and ``1`` becomes ``"0.000001"``.
    """
    _check_decimals(decimals)
    if isinstance(minor, bool) or not isinstance(minor, int):
        raise AgentBankError("invalid_amount", "Minor units must be an integer")
    negative = minor < 0
    scale: int = 10**decimals
    whole, remainder = divmod(abs(minor), scale)
    fraction = str(remainder).rjust(decimals, "0") if decimals else ""
    keep = min(min_fraction_digits, decimals)
    while len(fraction) > keep and fraction.endswith("0"):
        fraction = fraction[:-1]
    body = f"{whole}.{fraction}" if fraction else str(whole)
    return f"-{body}" if negative else body


def _decimal_string(value: str | Decimal) -> str:
    if isinstance(value, Decimal):
        if not value.is_finite() or value.is_signed():
            raise AgentBankError("invalid_amount", f"{value} is not a valid amount")
        value = format(value, "f")
    parse_amount(value, USDC_DECIMALS)  # validates format and precision
    return value


def money(amount: str | Decimal, asset: str = "USDC") -> Money:
    """Build a :class:`~agentbank.models.Money` from a decimal string or ``Decimal``."""
    if asset not in ASSET_DECIMALS:
        raise AgentBankError("unsupported_asset", f'Asset "{asset}" is not supported')
    return Money.model_validate({"amount": _decimal_string(amount), "asset": asset})


def coerce_money(value: MoneyInput) -> Money:
    """Normalize any :data:`MoneyInput` into a validated :class:`Money` model.

    Raises:
        AgentBankError: ``invalid_amount`` for floats, ints and malformed strings.
    """
    if isinstance(value, Money):
        return value
    if isinstance(value, (str, Decimal)):
        return money(value)
    if isinstance(value, Mapping):
        amount = value.get("amount")
        if not isinstance(amount, (str, Decimal)):
            raise AgentBankError("invalid_amount", "Money.amount must be a decimal string")
        return money(amount, str(value.get("asset", "USDC")))
    raise AgentBankError(
        "invalid_amount",
        f"Amounts must be decimal strings like '12.50', not {type(value).__name__}",
    )


def to_minor(value: MoneyInput) -> int:
    """Convert money to integer minor units of its asset (USDC: 6 decimals)."""
    m = coerce_money(value)
    return parse_amount(m.amount, ASSET_DECIMALS[m.asset])
