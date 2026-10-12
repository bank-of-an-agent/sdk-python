"""RFC 9421 request signing and verification (mirrors the TypeScript tests)."""

from __future__ import annotations

import base64

import pytest
from eth_account import Account

from agentbank.errors import SignatureVerificationError
from agentbank.http_signatures import (
    MAX_SIGNATURE_LIFETIME_SECONDS,
    content_digest,
    parse_signature_input,
    sign_request,
    verify_request,
)

SESSION = Account.from_key("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
OTHER = Account.from_key("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a")
NOW = 1_790_000_000
URL = "http://localhost:8080/v1/payments"
BODY = '{"amount":{"amount":"1.00","asset":"USDC"}}'
HEADERS = {"content-type": "application/json", "idempotency-key": "idem-12345678"}


def resolve(key_id: str) -> str | None:
    return SESSION.address if key_id == "ses_1" else None


def signed(**overrides: object) -> dict[str, str]:
    options: dict[str, object] = {"key_id": "ses_1", "signer": SESSION, "created": NOW}
    options.update(overrides)
    return sign_request("POST", URL, HEADERS, BODY, **options)  # type: ignore[arg-type]


def test_sign_and_verify_round_trip() -> None:
    headers = signed(nonce="n1")
    assert (
        '"@method" "@target-uri" "content-digest" "idempotency-key"' in headers["signature-input"]
    )
    verified = verify_request(
        "POST", URL, {**HEADERS, **headers}, BODY, resolve_key=resolve, now=NOW + 5
    )
    assert verified.address == SESSION.address
    assert verified.key_id == "ses_1"
    assert verified.covered_components == (
        "@method",
        "@target-uri",
        "content-digest",
        "idempotency-key",
    )


def test_bytes_body_and_header_case_do_not_matter() -> None:
    headers = signed(nonce="n1")
    upper = {k.upper(): v for k, v in {**HEADERS, **headers}.items()}
    verify_request("post", URL, upper, BODY.encode(), resolve_key=resolve, now=NOW)


def test_rejects_tampering_wrong_keys_expiry_and_replay() -> None:
    headers = {**HEADERS, **signed(nonce="n2")}
    with pytest.raises(SignatureVerificationError, match="Content-Digest"):
        verify_request("POST", URL, headers, '{"amount":"999"}', resolve_key=resolve, now=NOW)
    forged = {**headers, "content-digest": content_digest('{"x":1}')}
    with pytest.raises(SignatureVerificationError, match="session key"):
        verify_request("POST", URL, forged, '{"x":1}', resolve_key=resolve, now=NOW)
    with pytest.raises(SignatureVerificationError, match="expired"):
        verify_request("POST", URL, headers, BODY, resolve_key=resolve, now=NOW + 1000)
    with pytest.raises(SignatureVerificationError, match="session key"):
        verify_request("POST", URL, headers, BODY, resolve_key=lambda _: OTHER.address, now=NOW)
    with pytest.raises(SignatureVerificationError, match="Unknown key") as unknown:
        verify_request("POST", URL, headers, BODY, resolve_key=lambda _: None, now=NOW)
    assert unknown.value.code == "unauthorized"
    with pytest.raises(SignatureVerificationError, match="session key"):
        verify_request("POST", URL + "?x=1", headers, BODY, resolve_key=resolve, now=NOW)

    seen: set[tuple[str, str]] = set()

    def check_and_store(key_id: str, nonce: str, expires: int) -> bool:
        was = (key_id, nonce) in seen
        seen.add((key_id, nonce))
        return was

    verify_request(
        "POST",
        URL,
        headers,
        BODY,
        resolve_key=resolve,
        check_and_store_nonce=check_and_store,
        now=NOW,
    )
    with pytest.raises(SignatureVerificationError, match="nonce"):
        verify_request(
            "POST",
            URL,
            headers,
            BODY,
            resolve_key=resolve,
            check_and_store_nonce=check_and_store,
            now=NOW,
        )


def test_requires_covered_headers_and_well_formed_inputs() -> None:
    headers = signed()
    without_idempotency = {"content-type": "application/json", **headers}
    with pytest.raises(SignatureVerificationError, match='"idempotency-key" is missing'):
        verify_request("POST", URL, without_idempotency, BODY, resolve_key=resolve, now=NOW)
    unsigned_key = sign_request("POST", URL, {}, BODY, key_id="ses_1", signer=SESSION, created=NOW)
    with pytest.raises(SignatureVerificationError, match="must cover idempotency-key"):
        verify_request(
            "POST",
            URL,
            {**unsigned_key, "idempotency-key": "added-later-1"},
            BODY,
            resolve_key=resolve,
            now=NOW,
        )
    with pytest.raises(SignatureVerificationError, match="Missing") as missing:
        verify_request("POST", URL, HEADERS, BODY, resolve_key=resolve, now=NOW)
    assert missing.value.code == "unauthorized"
    with pytest.raises(SignatureVerificationError, match="Malformed"):
        parse_signature_input("garbage")
    label, params = parse_signature_input(headers["signature-input"])
    assert label == "agentbank"
    assert params.alg == "eip191-secp256k1"
    assert params.tag == "agentbank"


def test_signature_must_cover_body_digest_when_body_is_sent() -> None:
    get_headers = sign_request(
        "POST", URL, HEADERS, None, key_id="ses_1", signer=SESSION, created=NOW
    )
    with pytest.raises(SignatureVerificationError, match="content-digest"):
        verify_request("POST", URL, {**HEADERS, **get_headers}, BODY, resolve_key=resolve, now=NOW)


def test_verification_rejects_bad_parameters() -> None:
    headers = {**HEADERS, **signed(nonce="n3")}
    future = {**HEADERS, **signed(created=NOW + 100)}
    with pytest.raises(SignatureVerificationError, match="future"):
        verify_request("POST", URL, future, BODY, resolve_key=resolve, now=NOW)
    long_lived = dict(headers)
    long_lived["signature-input"] = headers["signature-input"].replace(
        f"expires={NOW + 120}", f"expires={NOW + 301}"
    )
    with pytest.raises(SignatureVerificationError, match="300 seconds"):
        verify_request("POST", URL, long_lived, BODY, resolve_key=resolve, now=NOW)
    wrong_alg = dict(headers)
    wrong_alg["signature-input"] = headers["signature-input"].replace(
        'alg="eip191-secp256k1"', 'alg="ed25519"'
    )
    with pytest.raises(SignatureVerificationError, match="algorithm"):
        verify_request("POST", URL, wrong_alg, BODY, resolve_key=resolve, now=NOW)
    no_method = dict(headers)
    no_method["signature-input"] = headers["signature-input"].replace('"@method" ', "")
    with pytest.raises(SignatureVerificationError, match="@method"):
        verify_request("POST", URL, no_method, BODY, resolve_key=resolve, now=NOW)
    other_label = {**headers, "signature": headers["signature"].replace("agentbank=", "other=")}
    with pytest.raises(SignatureVerificationError, match="Malformed Signature header"):
        verify_request("POST", URL, other_label, BODY, resolve_key=resolve, now=NOW)
    garbage = {**headers, "signature": "agentbank=:" + base64.b64encode(b"x" * 10).decode() + ":"}
    with pytest.raises(SignatureVerificationError, match="recovered"):
        verify_request("POST", URL, garbage, BODY, resolve_key=resolve, now=NOW)
    bad_component = dict(headers)
    bad_component["signature-input"] = headers["signature-input"].replace('"@method"', "@method")
    with pytest.raises(SignatureVerificationError, match="component list"):
        verify_request("POST", URL, bad_component, BODY, resolve_key=resolve, now=NOW)
    missing_param = dict(headers)
    missing_param["signature-input"] = headers["signature-input"].replace(';nonce="n3"', "")
    with pytest.raises(SignatureVerificationError, match="nonce"):
        verify_request("POST", URL, missing_param, BODY, resolve_key=resolve, now=NOW)
    extra_component = dict(headers)
    extra_component["signature-input"] = headers["signature-input"].replace(
        '"idempotency-key")', '"idempotency-key" "x-missing")'
    )
    with pytest.raises(SignatureVerificationError, match="x-missing"):
        verify_request("POST", URL, extra_component, BODY, resolve_key=resolve, now=NOW)


def test_get_requests_have_no_digest() -> None:
    url = "http://localhost:8080/v1/accounts/acct_1/balances?x=1"
    headers = sign_request("GET", url, {}, None, key_id="ses_1", signer=SESSION, created=NOW)
    assert "content-digest" not in headers
    assert verify_request("GET", url, headers, None, resolve_key=resolve, now=NOW).key_id == "ses_1"


def test_lifetime_defaults_and_cap() -> None:
    _, params = parse_signature_input(signed()["signature-input"])
    assert params.expires - params.created == 120
    _, capped = parse_signature_input(signed(lifetime_seconds=10_000)["signature-input"])
    assert capped.expires - capped.created == MAX_SIGNATURE_LIFETIME_SECONDS
    with pytest.raises(ValueError, match="positive"):
        signed(lifetime_seconds=0)


def test_default_nonce_is_random_base64url() -> None:
    first = parse_signature_input(signed()["signature-input"])[1].nonce
    second = parse_signature_input(signed()["signature-input"])[1].nonce
    assert first != second
    assert len(first) == 22
    assert "=" not in first


def test_content_digest_of_empty_body() -> None:
    assert content_digest(b"") == "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
