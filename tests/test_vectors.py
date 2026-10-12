"""Cross-language vectors shared with ``@agentbank/core``.

``tests/vectors.json`` is a verbatim copy of
``agent-bank/packages/core/test/vectors/vectors.json`` (refresh it with
``scripts/refresh_vectors.sh``). The TypeScript suite runs the same file; every
digest, signature base, header, hash and signature must match byte for byte.
The keys are public Anvil development keys.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from eth_account import Account

from agentbank.canonical import canonical_json, canonical_keccak
from agentbank.eip712 import (
    owner_authorization_typed_data,
    owner_authorize,
    verify_owner_authorization,
)
from agentbank.http_signatures import (
    SignatureParams,
    content_digest,
    sign_request,
    signature_base,
    verify_request,
)
from agentbank.keys import SessionKey, sign_typed_data
from agentbank.webhooks import sign_webhook, verify_webhook

VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "vectors.json").read_text(encoding="utf-8")
)
KEYS = VECTORS["keys"]
SESSION = Account.from_key(KEYS["session_private_key"])
OWNER = Account.from_key(KEYS["owner_private_key"])


def test_vector_keys_derive_expected_addresses() -> None:
    assert SESSION.address == KEYS["session_address"]
    assert OWNER.address == KEYS["owner_address"]
    assert (
        SessionKey.from_private_key(KEYS["session_private_key"]).address == KEYS["session_address"]
    )


@pytest.mark.parametrize("name", ["http_signature_post", "http_signature_get"])
def test_http_signature_headers(name: str) -> None:
    v = VECTORS[name]
    request = v["request"]
    headers = sign_request(
        request["method"],
        request["url"],
        request["headers"],
        request.get("body"),
        key_id=v["params"]["key_id"],
        signer=SESSION,
        created=v["params"]["created"],
        lifetime_seconds=v["params"]["lifetime_seconds"],
        nonce=v["params"]["nonce"],
    )
    assert headers == v["headers"]


def test_http_signature_post_digest_and_base() -> None:
    v = VECTORS["http_signature_post"]
    request = v["request"]
    assert content_digest(request["body"]) == v["content_digest"]
    assert content_digest(request["body"].encode("utf-8")) == v["content_digest"]
    params = SignatureParams(
        components=("@method", "@target-uri", "content-digest", "idempotency-key"),
        created=v["params"]["created"],
        expires=v["params"]["created"] + v["params"]["lifetime_seconds"],
        nonce=v["params"]["nonce"],
        keyid=v["params"]["key_id"],
    )
    headers = {**request["headers"], "content-digest": v["content_digest"]}
    assert signature_base(request["method"], request["url"], headers, params) == v["signature_base"]


@pytest.mark.parametrize("name", ["http_signature_post", "http_signature_get"])
def test_http_signature_verifies(name: str) -> None:
    v = VECTORS[name]
    request = v["request"]
    verified = verify_request(
        request["method"],
        request["url"],
        {**request["headers"], **v["headers"]},
        request.get("body"),
        resolve_key=lambda key_id: SESSION.address if key_id == v["params"]["key_id"] else None,
        now=v["params"]["created"] + 1,
    )
    assert verified.key_id == v["params"]["key_id"]
    assert verified.address == SESSION.address
    assert verified.nonce == v["params"]["nonce"]


def test_canonical_json() -> None:
    cj = VECTORS["canonical_json"]
    assert canonical_json(cj["input"]) == cj["output"]


def test_owner_authorization_payload_hash_and_signature() -> None:
    oa = VECTORS["owner_authorization"]
    assert canonical_json(oa["payload"]) == oa["payload_canonical_json"]
    assert canonical_keccak(oa["payload"]) == oa["payload_hash"]
    typed = owner_authorization_typed_data(
        chain_id=oa["chain_id"],
        action=oa["action"],
        subject=oa["subject"],
        payload=oa["payload"],
        issued_at=oa["issued_at"],
        expires_at=oa["expires_at"],
    )
    assert typed["message"]["payloadHash"] == oa["payload_hash"]
    assert sign_typed_data(OWNER, typed) == oa["signature"]


def test_owner_authorize_helper_reproduces_vector() -> None:
    oa = VECTORS["owner_authorization"]
    authorization = owner_authorize(
        OWNER,
        oa["chain_id"],
        oa["action"],
        oa["subject"],
        oa["payload"],
        oa["expires_at"] - oa["issued_at"],
        issued_at=oa["issued_at"],
    )
    assert authorization == {
        "signer": KEYS["owner_address"],
        "signature": oa["signature"],
        "issued_at": oa["issued_at"],
        "expires_at": oa["expires_at"],
    }
    verify_owner_authorization(
        owner=KEYS["owner_address"],
        authorization=authorization,
        chain_id=oa["chain_id"],
        action=oa["action"],
        subject=oa["subject"],
        payload=oa["payload"],
        now=oa["issued_at"],
    )


def test_webhook_signature() -> None:
    w = VECTORS["webhook"]
    assert sign_webhook(w["secret"], w["body"], w["timestamp"]) == w["header"]
    assert verify_webhook(w["secret"], w["body"], w["header"], now=w["timestamp"]) == w["timestamp"]
    assert (
        verify_webhook(w["secret"], w["body"].encode("utf-8"), w["header"], now=w["timestamp"])
        == w["timestamp"]
    )
