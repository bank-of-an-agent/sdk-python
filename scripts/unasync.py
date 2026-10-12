"""Generate the synchronous client (``src/agentbank/_sync``) from the async source.

The async package ``src/agentbank/_async`` is the single source of truth. This
script rewrites it token by token (``async def`` -> ``def``, ``await x`` -> ``x``,
``AsyncAgentBank`` -> ``AgentBank``, ``httpx.AsyncClient`` -> ``httpx.Client``,
``anyio.sleep`` -> ``time.sleep``, ...) and formats the result with ruff.

Usage::

    python scripts/unasync.py          # regenerate src/agentbank/_sync
    python scripts/unasync.py --check  # fail if src/agentbank/_sync is stale (CI)
"""

from __future__ import annotations

import difflib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src" / "agentbank" / "_async"
TARGET = ROOT / "src" / "agentbank" / "_sync"

# Ordered: specific names before the generic ``Async<Name>`` rule.
SUBSTITUTIONS: list[tuple[str, str]] = [
    (r"\basync def\b", "def"),
    (r"\basync with\b", "with"),
    (r"\basync for\b", "for"),
    (r"\bawait\s+", ""),
    (r"\bhandle_async_request\b", "handle_request"),
    (r"\b__aenter__\b", "__enter__"),
    (r"\b__aexit__\b", "__exit__"),
    (r"\baclose\b", "close"),
    (r"\baread\b", "read"),
    (r"\bAsyncIterator\b", "Iterator"),
    (r"\bhttpx\.AsyncByteStream\b", "httpx.SyncByteStream"),
    (r"\bhttpx\.AsyncClient\b", "httpx.Client"),
    (r"\bhttpx\.AsyncHTTPTransport\b", "httpx.HTTPTransport"),
    (r"\bhttpx\.AsyncBaseTransport\b", "httpx.BaseTransport"),
    (r"\bAsync([A-Z][A-Za-z0-9]*)\b", r"\1"),
    (r"\bagentbank\._async\b", "agentbank._sync"),
    (r"^import anyio$", "import time"),
    (r"\banyio\.sleep\b", "time.sleep"),
    (r"\basynchronous\b", "synchronous"),
    (r"\bAsynchronous\b", "Synchronous"),
]

HEADER = (
    "# Generated from src/agentbank/_async/{name} by scripts/unasync.py.\n"
    "# Do not edit: change the async source and regenerate.\n"
)

# Async generators cannot ``yield from``; their sync versions should.
YIELD_LOOP = re.compile(
    r"^(?P<indent>[ ]*)for (?P<var>\w+) in (?P<iterable>.+):\n[ ]*yield (?P=var)$", re.M
)


def transform(source: str) -> str:
    """Rewrite async source code into its synchronous equivalent."""
    for pattern, replacement in SUBSTITUTIONS:
        source = re.sub(pattern, replacement, source, flags=re.MULTILINE)
    return YIELD_LOOP.sub(r"\g<indent>yield from \g<iterable>", source)


def _ruff(directory: Path) -> None:
    config = str(ROOT / "pyproject.toml")
    files = [str(p) for p in sorted(directory.rglob("*.py"))]
    subprocess.run(
        ["ruff", "check", "--quiet", "--fix", "--config", config, "--select", "I,F401", *files],
        check=True,
    )
    subprocess.run(["ruff", "format", "--quiet", "--config", config, *files], check=True)


def generate(output: Path) -> None:
    """Write the synchronous package into ``output``."""
    for path in sorted(SOURCE.rglob("*.py")):
        relative = path.relative_to(SOURCE)
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        text = HEADER.format(name=relative.as_posix()) + transform(path.read_text("utf-8"))
        destination.write_text(text, encoding="utf-8")
    _ruff(output)


def _tree(directory: Path) -> dict[str, str]:
    return {
        p.relative_to(directory).as_posix(): p.read_text("utf-8")
        for p in sorted(directory.rglob("*.py"))
    }


def main(argv: list[str]) -> int:
    """CLI entry point."""
    check = "--check" in argv[1:]
    with tempfile.TemporaryDirectory() as tmp:
        generated_dir = Path(tmp) / "_sync"
        generate(generated_dir)
        generated = _tree(generated_dir)
        if check:
            current = _tree(TARGET) if TARGET.exists() else {}
            if generated == current:
                return 0
            for name in sorted(set(generated) | set(current)):
                diff = difflib.unified_diff(
                    current.get(name, "").splitlines(keepends=True),
                    generated.get(name, "").splitlines(keepends=True),
                    fromfile=f"src/agentbank/_sync/{name}",
                    tofile=f"generated/{name}",
                )
                sys.stdout.writelines(diff)
            print("src/agentbank/_sync is stale: run scripts/unasync.py", file=sys.stderr)
            return 1
        for stale in TARGET.rglob("*.py") if TARGET.exists() else []:
            if stale.relative_to(TARGET).as_posix() not in generated:
                stale.unlink()
        for name, text in generated.items():
            destination = TARGET / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8")
    print(f"Generated {len(generated)} files in src/agentbank/_sync")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
