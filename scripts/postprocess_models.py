"""Post-process the raw datamodel-code-generator output into ``models.py``.

* Replaces the generator's comment header with a module docstring that names
  the API version the models were generated from.
* Rewrites dictionary defaults of nested-model fields (``limits = {}``) into
  ``default_factory`` calls, which type checkers accept.
* Removes the ``__annotations__ = {"__pydantic_extra__": ...}`` blocks the
  generator emits for open (``additionalProperties``) models; Pydantic does
  not need them and they confuse type checkers.
* Adds ``__all__`` so ``from agentbank.models import *`` exports exactly the
  generated models.

Usage: ``python scripts/postprocess_models.py RAW.py OUT.py [openapi.json]``
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

ANNOTATIONS_BLOCK = re.compile(
    r"\n    __annotations__ = \{\n        \"__pydantic_extra__\": Dict\[str, Any\],\n    \}\n"
)
DICT_DEFAULT = re.compile(
    r"^(?P<field>    \w+): Annotated\[(?P<model>\w+), Field\((?P<args>[^\n]*?),? ?"
    r"validate_default=True\)\] = (?P<default>\{.*?\n    \})$",
    re.MULTILINE | re.DOTALL,
)
EXPORTED = re.compile(r"^(?:class (\w+)\(|(\w+) = TypeAliasType\()", re.MULTILINE)


def _default_factory(match: re.Match[str]) -> str:
    default = ast.literal_eval(match["default"])
    args = match["args"].rstrip(", ")
    prefix = f"{args}, " if args else ""
    return (
        f"{match['field']}: Annotated[{match['model']}, Field({prefix}"
        f"default_factory=lambda: {match['model']}.model_validate({default!r}))]"
    )


def postprocess(source: str, api_version: str) -> str:
    """Return the cleaned-up module source."""
    body = source.split("from __future__ import annotations", 1)[1]
    body = ANNOTATIONS_BLOCK.sub("\n", body)
    body = DICT_DEFAULT.sub(_default_factory, body)
    body = body.replace(
        "from typing import Annotated, Any, Dict, Literal",
        "from typing import Annotated, Any, Literal",
    )
    names = sorted({a or b for a, b in EXPORTED.findall(body)})
    header = (
        '"""Pydantic v2 models for the Agent Bank REST API.\n'
        "\n"
        "Generated from ``openapi.json`` by ``scripts/generate_models.sh``; do not edit\n"
        f"by hand. API version: {api_version}.\n"
        "\n"
        "Money amounts are decimal strings (``str``), never floats; timestamps are\n"
        "timezone-aware datetimes.\n"
        '"""\n'
        "\n"
        "from __future__ import annotations"
    )
    exports = "\n\n__all__ = [\n" + "".join(f'    "{name}",\n' for name in names) + "]\n"
    return header + body.rstrip() + "\n" + exports


def main(argv: list[str]) -> int:
    """CLI entry point."""
    if len(argv) not in (3, 4):
        print(__doc__)
        return 2
    spec_path = Path(argv[3] if len(argv) == 4 else "openapi.json")
    version = json.loads(spec_path.read_text(encoding="utf-8")).get("info", {}).get("version", "?")
    raw = Path(argv[1]).read_text(encoding="utf-8")
    Path(argv[2]).write_text(postprocess(raw, version), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
