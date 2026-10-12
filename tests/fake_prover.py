"""A stand-in for ``agentbank-prove`` (``AGENTBANK_PROVER``) with canned answers.

It speaks the real CLI's protocol (modes ``prove`` and ``identity``, JSON on stdin and
stdout, exit codes 0/1/2/3 with a JSON error line on stderr) and answers from the proof
vectors. ``FAKE_PROVER`` picks the behavior; ``FAKE_PROVER_LOG`` (a directory) records
each call. It avoids importing ``agentbank`` so that it starts quickly.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from eth_hash.auto import keccak

VECTOR: dict[str, Any] = json.loads(
    (Path(__file__).parent / "proof_vectors.json").read_text("utf-8")
)["proof"]
COMMITMENT = "0x159D4616C2ACB615D03349C1D71939F02B7936E3C6346EDD05B76A23CF8CE8BF"
GENERATED_SECRET = "0x00" + "11" * 31


def _request_hash(request: dict[str, Any]) -> str:
    # Canonical JSON of an all-ASCII request: sorted keys, no whitespace.
    text = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "0x" + keccak(text.encode("utf-8")).hex()


def _fail(code: int, body: dict[str, Any]) -> int:
    sys.stderr.write(json.dumps(body) + "\n")
    return code


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else "prove"
    behavior = os.environ.get("FAKE_PROVER", "ok")
    text = sys.stdin.read()
    log = os.environ.get("FAKE_PROVER_LOG")
    if log:
        calls = sorted(Path(log).glob("call-*.json"))
        entry = {"mode": mode, "stdin": text, "argv": argv[1:]}
        (Path(log) / f"call-{len(calls):03d}.json").write_text(json.dumps(entry), "utf-8")
    payload: dict[str, Any] = json.loads(text) if text.strip() else {}
    if behavior == "sleep":
        time.sleep(30)
    if behavior == "refuse":
        return _fail(
            3,
            {
                "error": "refused",
                "reason": "witness_mismatch",
                "message": "the secret and the witness do not hash to the witness root",
                "attributes": [],
                "undisclosed_classes": [],
            },
        )
    if behavior == "refuse-odd":
        return _fail(3, {"error": "refused", "reason": "mystery"})
    if behavior == "invalid":
        return _fail(2, {"error": "invalid_input", "message": 'missing "witness"'})
    if behavior == "crash":
        secret = payload.get("secret", "")
        return _fail(1, {"error": "internal", "message": f"boom while proving with {secret}"})
    if behavior == "crash-plain":
        sys.stderr.write("Segmentation fault\n")
        return 139
    if behavior == "silent":
        return 0
    if behavior == "garbage":
        sys.stdout.write(json.dumps({"type": "agentbank.proof.v1"}) + "\n")
        return 0
    if mode == "identity":
        if behavior == "bad-identity":
            sys.stdout.write(json.dumps({"secret": 1}) + "\n")
            return 0
        secret = payload.get("secret", GENERATED_SECRET)
        sys.stdout.write(json.dumps({"secret": secret, "identity_commitment": COMMITMENT}) + "\n")
        return 0
    presentation = dict(VECTOR["presentation"])
    request = payload["request"]
    presentation["request_hash"] = (
        "0x" + "00" * 32 if behavior == "wrong-hash" else _request_hash(request)
    )
    sys.stdout.write("prover log line\n" + json.dumps(presentation) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
