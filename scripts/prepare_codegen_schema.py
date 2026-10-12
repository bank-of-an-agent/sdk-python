"""Normalize ``openapi.json`` for datamodel-code-generator.

The OpenAPI document is generated from the TypeScript route registry (Zod).
A few of its idioms produce awkward Python models when fed to the generator
as-is, so this script rewrites a *copy* of the document before generation:

* Inline object schemas get explicit titles (``--use-title-as-name``) so the
  generated classes have meaningful names (``PaymentDestination`` rather than
  ``To``; ``AmountRangeConstraint`` rather than ``Constraints``).
* ``anyOf: [<primitive>, {"type": "null"}]`` becomes ``type: [<primitive>, "null"]``
  so nullable ids and hashes are plain ``str | None`` instead of root models.
* ``format: date-time`` strings drop their (redundant) regex so Pydantic can
  parse them as timezone-aware datetimes.
* ``format: email`` / ``format: uri`` are dropped: the SDK passes strings
  through untouched (``AnyUrl`` would rewrite URLs, ``EmailStr`` needs an
  extra dependency), and the API validates them.
* ``propertyNames`` constraints are dropped (they generate untypable
  ``constr(...)`` dictionary keys).

Usage: ``python scripts/prepare_codegen_schema.py openapi.json OUT.json``
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

#: JSON-pointer-like paths (relative to ``components/schemas``) to class names.
INLINE_TITLES: dict[str, str] = {
    "OpenPaymentMandate/properties/constraints/items/oneOf/0": "AmountRangeConstraint",
    "OpenPaymentMandate/properties/constraints/items/oneOf/1": "AllowedPayeesConstraint",
    "OpenPaymentMandate/properties/constraints/items/oneOf/1/properties/allowed/items": (
        "MandatePayee"
    ),
    "OpenPaymentMandate/properties/constraints/items/oneOf/2": "BudgetConstraint",
    "OpenPaymentMandate/properties/constraints/items/oneOf/3": "RecurrenceConstraint",
    "OpenPaymentMandate/properties/constraints/items/oneOf/4": "ExecutionDateConstraint",
    "OpenPaymentMandate/properties/constraints/items/oneOf/5": "X402DomainsConstraint",
    "OpenPaymentMandate/properties/cnf/anyOf/0": "JwkKeyBinding",
    "OpenPaymentMandate/properties/cnf/anyOf/0/properties/jwk": "Secp256k1Jwk",
    "OpenPaymentMandate/properties/cnf/anyOf/1": "EthAddressKeyBinding",
    "PolicyDocument/properties/limits": "PolicyLimits",
    "PolicyDocument/properties/counterparties": "PolicyCounterparties",
    "PolicyDocument/properties/counterparties/properties/deny": "CounterpartyDenyList",
    "PolicyDocument/properties/counterparties/properties/caps/items": "CounterpartyCap",
    "PolicyDocument/properties/counterparties/properties/caps/items/properties/match": (
        "CounterpartyMatch"
    ),
    "PolicyDocument/properties/velocity": "PolicyVelocity",
    "PolicyDocument/properties/time_windows/items": "TimeWindow",
    "PolicyDocument/properties/approvals/items": "ApprovalThreshold",
    "PolicyDocument/properties/auto_save": "AutoSave",
    "PolicyDocument/properties/auto_save/properties/income_split": "IncomeSplit",
    "PolicyDocument/properties/auto_save/properties/excess_sweep": "ExcessSweep",
    "PolicyDocument/properties/auto_save/properties/round_up": "RoundUp",
    "PolicyDocument/properties/auto_save/properties/scheduled/items": "ScheduledSave",
    "Balances/properties/vaults/items": "VaultBalance",
    "CreatePaymentRequest/properties/to": "PaymentDestination",
    "X402PayResponse/properties/eip712_domain/anyOf/0": "Eip712Domain",
    "X402SupportedResponse/properties/kinds/items": "X402SupportedKind",
    "Escrow/properties/validator/anyOf/0": "EscrowValidator",
    "CreateEscrowRequest/properties/payee": "EscrowPayee",
    "CreateEscrowRequest/properties/validator": "EscrowValidatorParam",
    "CreateStreamRequest/properties/payee": "StreamPayee",
    "Approval/properties/decisions/items": "ApprovalDecision",
    "Statement/properties/lines/items": "StatementLine",
    "Fund/properties/eligibility": "FundEligibility",
}

PRIMITIVES = {"string", "integer", "boolean"}
HOSTNAME_PATTERN = "^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\\.(?!-)[a-z0-9-]{1,63}(?<!-))*$"
MINOR_UNITS_PATTERN = "^(0|[1-9][0-9]{0,18})$"
DROPPED_FORMATS = {"email", "uri"}


def _is_null(node: Any) -> bool:
    return bool(node == {"type": "null"})


def _flatten_nullable_primitive(node: dict[str, Any]) -> None:
    """Rewrite ``anyOf: [primitive, null]`` into ``type: [primitive, "null"]``."""
    any_of = node.get("anyOf")
    if not isinstance(any_of, list) or len(any_of) != 2:
        return
    others = [branch for branch in any_of if not _is_null(branch)]
    if len(others) != 1 or len(any_of) - len(others) != 1:
        return
    inner = others[0]
    if not isinstance(inner, dict) or "$ref" in inner or inner.get("type") not in PRIMITIVES:
        return
    del node["anyOf"]
    for key, value in inner.items():
        if key == "type":
            node["type"] = [value, "null"]
        elif key not in node:
            node[key] = value


def _name_minor_units_union(node: dict[str, Any]) -> None:
    """Name the AP2 ``MinorUnits`` union (integer or digit string) consistently."""
    any_of = node.get("anyOf")
    if not isinstance(any_of, list) or len(any_of) != 2:
        return
    integer, string = any_of
    if (
        isinstance(integer, dict)
        and isinstance(string, dict)
        and integer.get("type") == "integer"
        and string.get("pattern") == MINOR_UNITS_PATTERN
    ):
        integer["title"] = "MinorUnitsInt"
        string["title"] = "MinorUnitsString"


def _normalize(node: Any, path: list[str]) -> None:
    if isinstance(node, list):
        for index, item in enumerate(node):
            _normalize(item, [*path, str(index)])
        return
    if not isinstance(node, dict):
        return
    _flatten_nullable_primitive(node)
    if node.get("format") == "date-time":
        node.pop("pattern", None)
    if node.get("format") in DROPPED_FORMATS:
        node.pop("format")
        node.pop("pattern", None)
    node.pop("propertyNames", None)
    _name_minor_units_union(node)
    if path and path[-1] == "items" and node.get("pattern") == HOSTNAME_PATTERN:
        node["title"] = "Hostname"
    title = INLINE_TITLES.get("/".join(path))
    if title is not None:
        node["title"] = title
    for key, value in list(node.items()):
        _normalize(value, [*path, key])


def prepare(spec: dict[str, Any]) -> dict[str, Any]:
    """Return a normalized copy of the OpenAPI document for code generation."""
    prepared: dict[str, Any] = json.loads(json.dumps(spec))
    schemas = prepared["components"]["schemas"]
    # Component schemas are named by their key; give them matching titles so
    # ``--use-title-as-name`` keeps their names stable.
    for name, schema in schemas.items():
        _normalize(schema, [name])
        schema["title"] = name
    return prepared


def main(argv: list[str]) -> int:
    """CLI entry point."""
    if len(argv) != 3:
        print(__doc__)
        return 2
    spec = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    Path(argv[2]).write_text(json.dumps(prepare(spec), indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
