"""Build minimal valid JSON examples for any schema in ``openapi.json``.

Tests use these as mock API responses so that every operation can be exercised
against data that satisfies the real contract (and the generated models).
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

SPEC: dict[str, Any] = json.loads(
    (Path(__file__).resolve().parent.parent / "openapi.json").read_text(encoding="utf-8")
)
SCHEMAS: dict[str, Any] = SPEC["components"]["schemas"]

ULID = "01JABCDEFGHJKMNPQRSTVWXYZ0"
ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
BYTES32 = "0x" + "ab" * 32
TIMESTAMP = "2026-10-11T12:00:00Z"

_ID_PATTERN = re.compile(r"^\^(?P<prefix>[a-z0-9]+)_\[0-9A-HJKMNP-TV-Z\]\{26\}\$$")
_PATTERN_EXAMPLES: dict[str, str] = {
    "^0x[a-fA-F0-9]{40}$": ADDRESS,
    "^0x[a-fA-F0-9]{64}$": BYTES32,
    "^0x([a-fA-F0-9]{2})*$": "0x" + "cd" * 65,
    "^(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$": "1.00",
    "^-?(0|[1-9][0-9]{0,17})(\\.[0-9]{1,6})?$": "-1.00",
    "^[0-9]+$": "1000",
    "^(0|[1-9][0-9]{0,18})$": "100",
    "^(0|[1-9][0-9]{0,19})$": "7",
    "^[1-9][0-9]{0,19}$": "7",
    "^(0|[1-9][0-9]{0,76})$": "1",
    "^(0|[1-9][0-9]{0,19})(\\.[0-9]{1,6})?$": "1.00",
    "^[0-9a-f]{64}$": "ab" * 32,
    "^[0-9a-f]{32}$": "ab" * 16,
    "^0x[0-9a-f]{62}$": "0x" + "ab" * 31,
    "^[0-9]{4}-[0-9]{2}$": "2026-10",
    "^[0-9]{4}-(0[1-9]|1[0-2])$": "2026-10",
    "^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\\.(?!-)[a-z0-9-]{1,63}(?<!-))*$": (
        "api.example-data.com"
    ),
    "^(treasury|vault:vlt_[0-9A-HJKMNP-TV-Z]{26})$": "treasury",
    "^([01][0-9]|2[0-3]):[0-5][0-9]$": "09:00",
    "^([01][0-9]|2[0-4]):[0-5][0-9]$": "17:00",
    "^(([01][0-9]|2[0-3]):[0-5][0-9]|24:00)$": "17:00",
    "^[\\x21-\\x7E]{1,200}$": "erc8004:84532:42",
}


def id_for(prefix: str) -> str:
    """A valid id with ``prefix``, e.g. ``id_for("pay")``."""
    return f"{prefix}_{ULID}"


def _string(schema: dict[str, Any]) -> str:
    if "const" in schema:
        return str(schema["const"])
    if "enum" in schema:
        return str(schema["enum"][0])
    if schema.get("format") == "date-time":
        return TIMESTAMP
    if schema.get("format") == "email":
        return "ops@example.com"
    if schema.get("format") == "uri":
        return "https://example.com/resource"
    pattern = schema.get("pattern")
    if pattern is not None:
        match = _ID_PATTERN.match(pattern)
        if match:
            return id_for(match["prefix"])
        if pattern not in _PATTERN_EXAMPLES:
            raise KeyError(f"No example for pattern {pattern!r}")
        return _PATTERN_EXAMPLES[pattern]
    length = max(int(schema.get("minLength", 1)), 1)
    return "x" * length if length > 1 else "example"


def _resolve(ref: str) -> dict[str, Any]:
    result: dict[str, Any] = SCHEMAS[ref.rsplit("/", 1)[-1]]
    return result


def build(schema: dict[str, Any], *, full: bool = False) -> Any:
    """A minimal example of ``schema`` (all properties when ``full``)."""
    if "$ref" in schema:
        return build(_resolve(schema["$ref"]), full=full)
    for key in ("anyOf", "oneOf"):
        if key in schema:
            branches = [b for b in schema[key] if b != {"type": "null"}]
            return build(branches[0], full=full)
    if "const" in schema:
        return schema["const"]
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next(k for k in kind if k != "null")
    if kind == "object" or "properties" in schema:
        props: dict[str, Any] = schema.get("properties", {})
        required = set(schema.get("required", []))
        return {
            name: build(sub, full=full) for name, sub in props.items() if full or name in required
        }
    if kind == "array":
        count = max(int(schema.get("minItems", 0)), 1 if full else 0)
        return [build(schema["items"], full=full) for _ in range(count)]
    if kind == "string":
        return _string(schema)
    if kind == "integer":
        if "exclusiveMinimum" in schema:
            return max(int(schema["exclusiveMinimum"]) + 1, 1)
        return max(int(schema.get("minimum", 1)), 1) if schema.get("minimum", 0) >= 0 else 1
    if kind == "boolean":
        return True
    if kind == "null":
        return None
    return {}


def example(name: str, *, full: bool = False, **overrides: Any) -> dict[str, Any]:
    """A valid example of component schema ``name`` with top-level ``overrides``."""
    value = build(SCHEMAS[name], full=full)
    assert isinstance(value, dict)
    result = copy.deepcopy(value)
    result.update(overrides)
    return result


def response_schema(operation_id: str) -> str | None:
    """Name of the success response schema of an operation."""
    for item in SPEC["paths"].values():
        for op in item.values():
            if op.get("operationId") != operation_id:
                continue
            for code, response in op["responses"].items():
                if code.isdigit():
                    ref: str = response["content"]["application/json"]["schema"]["$ref"]
                    return ref.rsplit("/", 1)[-1]
    return None
