"""Generate ``src/agentbank/_operations.py`` (the operation table) from ``openapi.json``.

The table records, for every operation, its method, path, accepted callers
(``x-agentbank-auth``), whether it takes an ``Idempotency-Key``, which service
serves it (``x-agentbank-service``) and its parameters. The client uses it to
pick credentials and to add idempotency keys automatically.

Usage: ``python scripts/generate_operations.py openapi.json OUT.py``
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

HTTP_METHODS = ("get", "post", "put", "delete", "patch")


def constant_name(operation_id: str) -> str:
    """``createPaymentRequest`` -> ``CREATE_PAYMENT_REQUEST``; ``x402Pay`` -> ``X402_PAY``."""
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", operation_id)
    return snake.upper()


def _tuple(values: list[str]) -> str:
    if not values:
        return "()"
    return "(" + ", ".join(json.dumps(v) for v in values) + ",)"


def render(spec: dict[str, Any]) -> str:
    """Render the operation table module source."""
    version = spec.get("info", {}).get("version", "unknown")
    lines = [
        '"""Operation table generated from ``openapi.json``. Do not edit by hand.',
        "",
        "Regenerate with ``scripts/generate_models.sh``.",
        f"API version: {version}.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from typing import Final",
        "",
        "from agentbank._spec import Operation",
        "",
        f'API_VERSION: Final = "{version}"',
        "",
    ]
    names: list[tuple[str, str]] = []
    for path, item in spec["paths"].items():
        for method in HTTP_METHODS:
            op = item.get(method)
            if op is None:
                continue
            operation_id = op["operationId"]
            params = op.get("parameters", [])
            path_params = [p["name"] for p in params if p.get("in") == "path"]
            query_params = [p["name"] for p in params if p.get("in") == "query"]
            idempotent = any(
                p.get("in") == "header" and p.get("name", "").lower() == "idempotency-key"
                for p in params
            )
            success = sorted(code for code in op.get("responses", {}) if code.isdigit())
            status = int(success[0]) if success else 200
            media = list(op["responses"].get(str(status), {}).get("content", {}).keys())
            auth = op.get("x-agentbank-auth", ["public"])
            service = op.get("x-agentbank-service", "api")
            const = constant_name(operation_id)
            names.append((operation_id, const))
            lines += [
                f"{const}: Final = Operation(",
                f'    operation_id="{operation_id}",',
                f'    method="{method.upper()}",',
                f'    path="{path}",',
                f"    auth={_tuple(auth)},",
                f"    idempotent={idempotent},",
                f'    service="{service}",',
                f"    success_status={status},",
                f"    path_params={_tuple(path_params)},",
                f"    query_params={_tuple(query_params)},",
                f"    has_body={'requestBody' in op},",
                f"    response_media_types={_tuple(media)},",
                ")",
                "",
            ]
    lines.append("OPERATIONS: Final[dict[str, Operation]] = {")
    lines += [f'    "{operation_id}": {const},' for operation_id, const in names]
    lines.append("}")
    lines.append('"""Every operation in the API, keyed by ``operationId``."""')
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    """CLI entry point."""
    if len(argv) != 3:
        print(__doc__)
        return 2
    spec = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    Path(argv[2]).write_text(render(spec), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
