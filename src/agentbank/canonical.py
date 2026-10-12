r"""Canonical JSON, byte-for-byte compatible with ``@agentbank/core`` ``canonicalJson``.

Agent Bank hashes policies, mandates, owner-authorization payloads and audit
records over a deterministic JSON encoding so that every service and SDK agrees
on the bytes:

* object keys sorted by UTF-16 code units (exactly what JavaScript's ``<``
  comparison does), no insignificant whitespace;
* strings escaped exactly like ``JSON.stringify`` (non-ASCII is *not* escaped,
  lone surrogates are escaped as ``\udxxx``);
* numbers formatted like JavaScript's ``Number.prototype.toString``;
* integers outside the IEEE-754 safe range (|n| > 2**53 - 1) rendered as decimal
  strings, which is how the TypeScript implementation renders ``bigint`` values;
* timezone-aware ``datetime`` values rendered like ``Date.prototype.toISOString``
  (UTC, millisecond precision, ``Z`` suffix).

Pydantic models, ``Decimal`` values, tuples and other mappings are first
converted with :func:`to_jsonable`, the same conversion the client applies to
request bodies, so a payload hashes identically to the JSON that is sent.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from eth_utils.crypto import keccak
from pydantic import BaseModel

__all__ = [
    "MAX_SAFE_INTEGER",
    "canonical_json",
    "canonical_keccak",
    "canonical_sha256",
    "js_number_to_string",
    "js_string_literal",
    "to_jsonable",
]

#: ``Number.MAX_SAFE_INTEGER`` in JavaScript.
MAX_SAFE_INTEGER = 2**53 - 1

_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def to_jsonable(value: Any) -> Any:
    """Convert SDK values into plain JSON types (dict, list, str, int, float, bool, None).

    * Pydantic models are dumped in JSON mode by alias, omitting ``None`` fields
      (the API distinguishes an absent optional field from ``null``).
    * ``Decimal`` becomes a plain decimal string (money is never a JSON number).
    * ``datetime`` must be timezone-aware and becomes an ISO 8601 UTC string.
    * Tuples become lists; mappings must have string keys.

    Raises:
        TypeError: For unsupported types (bytes, sets, arbitrary objects) or
            non-string mapping keys.
        ValueError: For naive datetimes and non-finite ``Decimal`` values.
    """
    if value is None or isinstance(value, (bool, str, int, float)):
        return value
    if isinstance(value, BaseModel):
        return to_jsonable(value.model_dump(mode="json", by_alias=True, exclude_none=True))
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"JSON object keys must be strings, got {type(key).__name__}")
            out[key] = to_jsonable(item)
        return out
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("Decimal amounts must be finite")
        return format(value, "f")
    if isinstance(value, datetime):
        return _iso_timestamp(value)
    raise TypeError(f"Cannot encode {type(value).__name__} as JSON")


def _iso_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Naive datetime: attach a timezone, e.g. datetime.now(timezone.utc)")
    utc = value.astimezone(timezone.utc)
    millis = utc.microsecond // 1000
    return utc.strftime("%Y-%m-%dT%H:%M:%S") + f".{millis:03d}Z"


def js_string_literal(value: str) -> str:
    """Quote a string exactly like JavaScript's ``JSON.stringify``.

    Python strings may contain surrogate code points; a high surrogate followed
    by a low surrogate is treated as the pair it encodes (as in UTF-16), and lone
    surrogates are escaped, matching well-formed ``JSON.stringify`` (ES2019).
    """
    out: list[str] = ['"']
    i = 0
    n = len(value)
    while i < n:
        cp = ord(value[i])
        if 0xD800 <= cp <= 0xDBFF and i + 1 < n and 0xDC00 <= ord(value[i + 1]) <= 0xDFFF:
            low = ord(value[i + 1])
            out.append(chr(0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00)))
            i += 2
            continue
        if cp in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[cp])
        elif cp < 0x20 or 0xD800 <= cp <= 0xDFFF:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(value[i])
        i += 1
    out.append('"')
    return "".join(out)


def js_number_to_string(value: float) -> str:
    """Format a finite float exactly like JavaScript's ``Number.prototype.toString``.

    Uses Python's shortest round-trip digits (the same digits JavaScript picks)
    and applies the ECMAScript ``Number::toString`` layout rules.

    Raises:
        ValueError: If the value is NaN or infinite.
    """
    if not math.isfinite(value):
        raise ValueError("canonical_json: non-finite number")
    if value == 0:
        return "0"  # also covers -0.0, which JavaScript prints as "0"
    sign = "-" if value < 0 else ""
    _, digit_tuple, exponent = Decimal(repr(abs(value))).as_tuple()
    digits = "".join(str(d) for d in digit_tuple)
    assert isinstance(exponent, int)
    stripped = digits.rstrip("0")
    exponent += len(digits) - len(stripped)
    digits = stripped
    k = len(digits)
    n = exponent + k  # value = 0.<digits> * 10**n
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body


def _utf16_sort_key(key: str) -> bytes:
    return key.encode("utf-16-be", "surrogatepass")


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return js_string_literal(value)
    if isinstance(value, int):
        if -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            return str(value)
        return js_string_literal(str(value))
    if isinstance(value, float):
        return js_number_to_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_serialize(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=_utf16_sort_key)
        members = (js_string_literal(k) + ":" + _serialize(value[k]) for k in keys)
        return "{" + ",".join(members) + "}"
    raise TypeError(f"canonical_json: unsupported type {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Serialize ``value`` as Agent Bank canonical JSON (see module docstring).

    Example:
        >>> canonical_json({"b": 1, "a": [2, {"d": None, "c": "x"}], "e": "ü"})
        '{"a":[2,{"c":"x","d":null}],"b":1,"e":"ü"}'
    """
    return _serialize(to_jsonable(value))


def canonical_sha256(value: Any) -> str:
    """SHA-256 of the canonical JSON encoding (UTF-8), as ``0x``-prefixed hex."""
    return "0x" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def canonical_keccak(value: Any) -> str:
    """Keccak-256 of the canonical JSON encoding (UTF-8), as ``0x``-prefixed hex.

    This is the ``payloadHash`` of an EIP-712 ``OwnerAuthorization``.
    """
    return "0x" + keccak(canonical_json(value).encode("utf-8")).hex()
