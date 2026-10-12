"""HTTP Message Signatures (RFC 9421) for agent requests.

Byte-for-byte compatible with ``http-signatures.ts`` in ``@agentbank/core``:

* label ``agentbank``, algorithm ``eip191-secp256k1`` (the signature base is
  signed as an EIP-191 personal message by the session key), ``keyid`` = the
  session id, ``tag`` = ``agentbank``;
* covered components ``@method``, ``@target-uri``, plus ``content-digest``
  (RFC 9530 SHA-256) when there is a body and ``idempotency-key`` when sent;
* parameters serialized in the order ``created;expires;nonce;keyid;alg;tag``;
* signatures live at most 300 seconds and carry a single-use random nonce.

The SDK client signs every agent request automatically; these functions are
exposed for custom transports, tests and services that verify agent requests.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from eth_account import Account
from eth_account.messages import encode_defunct

from agentbank._url import whatwg_url
from agentbank.errors import SignatureVerificationError
from agentbank.keys import EthSigner, personal_sign_text

__all__ = [
    "DEFAULT_SIGNATURE_LIFETIME_SECONDS",
    "MAX_CLOCK_SKEW_SECONDS",
    "MAX_SIGNATURE_LIFETIME_SECONDS",
    "SIGNATURE_ALGORITHM",
    "SIGNATURE_LABEL",
    "SIGNATURE_TAG",
    "SignatureParams",
    "VerifiedSignature",
    "content_digest",
    "parse_signature_input",
    "serialize_params",
    "sign_request",
    "signature_base",
    "target_uri",
    "verify_request",
]

SIGNATURE_ALGORITHM = "eip191-secp256k1"
SIGNATURE_LABEL = "agentbank"
SIGNATURE_TAG = "agentbank"
MAX_SIGNATURE_LIFETIME_SECONDS = 300
MAX_CLOCK_SKEW_SECONDS = 30
DEFAULT_SIGNATURE_LIFETIME_SECONDS = 120

_INPUT_RE = re.compile(r'^([a-z][a-z0-9_-]*)=\(([^)]*)\)((?:;[a-z]+=(?:"[^"]*"|[0-9]+))*)$')
_PARAM_RE = re.compile(r';([a-z]+)=("[^"]*"|[0-9]+)')
_SIG_RE = re.compile(r"^([a-z][a-z0-9_-]*)=:([A-Za-z0-9+/=]+):$")
_COMPONENT_RE = re.compile(r'^"[^"]+"$')


@dataclass(frozen=True)
class SignatureParams:
    """Signature parameters (RFC 9421 section 2.3), in Agent Bank's fixed order."""

    components: tuple[str, ...]
    created: int
    expires: int
    nonce: str
    keyid: str
    alg: str = SIGNATURE_ALGORITHM
    tag: str = SIGNATURE_TAG


@dataclass(frozen=True)
class VerifiedSignature:
    """Result of a successful :func:`verify_request`."""

    key_id: str
    address: str
    created: int
    expires: int
    nonce: str
    covered_components: tuple[str, ...]


def content_digest(body: str | bytes) -> str:
    """RFC 9530 ``Content-Digest`` value for ``body``: ``sha-256=:<base64>:``."""
    data = body.encode("utf-8") if isinstance(body, str) else body
    return "sha-256=:" + base64.b64encode(hashlib.sha256(data).digest()).decode("ascii") + ":"


def target_uri(url: str) -> str:
    """The ``@target-uri`` component value: the WHATWG serialization of ``url``."""
    return whatwg_url(url)


def serialize_params(params: SignatureParams) -> str:
    """Serialize signature parameters exactly as the TypeScript reference does."""
    components = " ".join(f'"{c}"' for c in params.components)
    return (
        f"({components});created={params.created};expires={params.expires}"
        f';nonce="{params.nonce}";keyid="{params.keyid}";alg="{params.alg}";tag="{params.tag}"'
    )


def _lower_headers(headers: Mapping[str, str | None]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items() if v is not None}


def _has_body(body: str | bytes | None) -> bool:
    return body is not None and len(body) > 0


def _component_value(component: str, method: str, url: str, headers: Mapping[str, str]) -> str:
    if component == "@method":
        return method.upper()
    if component == "@target-uri":
        return target_uri(url)
    value = headers.get(component)
    if value is None:
        raise SignatureVerificationError(f'Covered header "{component}" is missing')
    return value.strip()


def signature_base(
    method: str,
    url: str,
    headers: Mapping[str, str | None],
    params: SignatureParams,
) -> str:
    """Build the RFC 9421 signature base for a request and its parameters."""
    lowered = _lower_headers(headers)
    lines = [f'"{c}": {_component_value(c, method, url, lowered)}' for c in params.components]
    lines.append(f'"@signature-params": {serialize_params(params)}')
    return "\n".join(lines)


def _b64url_nonce() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")


def sign_request(
    method: str,
    url: str,
    headers: Mapping[str, str | None],
    body: str | bytes | None,
    *,
    key_id: str,
    signer: EthSigner,
    created: int | None = None,
    lifetime_seconds: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Sign a request with a session key.

    Args:
        method: HTTP method.
        url: Absolute URL exactly as sent (scheme, host, path and query).
        headers: Request headers; ``idempotency-key`` is covered when present.
        body: The exact body bytes sent (or ``None``/empty for no body).
        key_id: The session id (``ses_...``).
        signer: The session key.
        created: Unix seconds; defaults to now.
        lifetime_seconds: Signature lifetime (default 120, capped at 300).
        nonce: Single-use nonce; defaults to 16 random bytes, base64url.

    Returns:
        Headers to merge into the request: ``signature-input``, ``signature``
        and, when there is a body, ``content-digest``.
    """
    lowered = _lower_headers(headers)
    out: dict[str, str] = {}
    components = ["@method", "@target-uri"]
    if body is not None and _has_body(body):
        digest = content_digest(body)
        lowered["content-digest"] = digest
        out["content-digest"] = digest
        components.append("content-digest")
    if "idempotency-key" in lowered:
        components.append("idempotency-key")

    lifetime = DEFAULT_SIGNATURE_LIFETIME_SECONDS if lifetime_seconds is None else lifetime_seconds
    if lifetime <= 0:
        raise ValueError("lifetime_seconds must be positive")
    lifetime = min(lifetime, MAX_SIGNATURE_LIFETIME_SECONDS)
    start = int(time.time()) if created is None else created
    params = SignatureParams(
        components=tuple(components),
        created=start,
        expires=start + lifetime,
        nonce=_b64url_nonce() if nonce is None else nonce,
        keyid=key_id,
    )
    base = signature_base(method, url, lowered, params)
    signature = personal_sign_text(signer, base)
    out["signature-input"] = f"{SIGNATURE_LABEL}={serialize_params(params)}"
    out["signature"] = f"{SIGNATURE_LABEL}=:{base64.b64encode(signature).decode('ascii')}:"
    return out


def parse_signature_input(value: str) -> tuple[str, SignatureParams]:
    """Parse an Agent Bank ``Signature-Input`` header into ``(label, params)``.

    Raises:
        SignatureVerificationError: The header is malformed or misses a parameter.
    """
    match = _INPUT_RE.match(value.strip())
    if match is None:
        raise SignatureVerificationError("Malformed Signature-Input header")
    label, component_list, raw_params = match.groups()
    components: list[str] = []
    for item in component_list.split(" "):
        if not item:
            continue
        if not _COMPONENT_RE.match(item):
            raise SignatureVerificationError("Malformed component list")
        components.append(item[1:-1])
    raw: dict[str, str] = {}
    for name, param in _PARAM_RE.findall(raw_params):
        raw[name] = param[1:-1] if param.startswith('"') else param
    for name in ("created", "expires", "nonce", "keyid", "alg"):
        if name not in raw:
            raise SignatureVerificationError(f'Signature-Input missing "{name}"')
    return label, SignatureParams(
        components=tuple(components),
        created=int(raw["created"]),
        expires=int(raw["expires"]),
        nonce=raw["nonce"],
        keyid=raw["keyid"],
        alg=raw["alg"],
        tag=raw.get("tag", ""),
    )


def verify_request(
    method: str,
    url: str,
    headers: Mapping[str, str | None],
    body: str | bytes | None,
    *,
    resolve_key: Callable[[str], str | None],
    check_and_store_nonce: Callable[[str, str, int], bool] | None = None,
    now: int | None = None,
) -> VerifiedSignature:
    """Verify an agent-signed request (mirrors ``verifyRequest`` in ``@agentbank/core``).

    Args:
        method: HTTP method.
        url: Absolute URL of the request.
        headers: Request headers including ``Signature-Input`` and ``Signature``.
        body: Raw request body.
        resolve_key: Returns the session key address for a ``keyid`` (or ``None``).
        check_and_store_nonce: Returns ``True`` if ``(keyid, nonce)`` was seen
            before; implementations must record it until ``expires``.
        now: Unix seconds; defaults to now.

    Raises:
        SignatureVerificationError: With a precise reason (code ``signature_invalid``,
            or ``unauthorized`` for missing headers and unknown keys).
    """
    lowered = _lower_headers(headers)
    input_header = lowered.get("signature-input")
    signature_header = lowered.get("signature")
    if not input_header or not signature_header:
        raise SignatureVerificationError(
            "Missing Signature-Input or Signature header", code="unauthorized"
        )
    label, params = parse_signature_input(input_header)
    sig_match = _SIG_RE.match(signature_header.strip())
    if sig_match is None or sig_match.group(1) != label:
        raise SignatureVerificationError("Malformed Signature header")
    if params.alg != SIGNATURE_ALGORITHM:
        raise SignatureVerificationError(f'Unsupported algorithm "{params.alg}"')
    for required in ("@method", "@target-uri"):
        if required not in params.components:
            raise SignatureVerificationError(f"Signature must cover {required}")
    if body is not None and _has_body(body):
        if "content-digest" not in params.components:
            raise SignatureVerificationError(
                "Signature must cover content-digest when a body is sent"
            )
        if lowered.get("content-digest") != content_digest(body):
            raise SignatureVerificationError("Content-Digest does not match the body")
    if "idempotency-key" in lowered and "idempotency-key" not in params.components:
        raise SignatureVerificationError("Signature must cover idempotency-key when sent")

    current = int(time.time()) if now is None else now
    if params.created > current + MAX_CLOCK_SKEW_SECONDS:
        raise SignatureVerificationError("Signature created in the future")
    if current > params.expires:
        raise SignatureVerificationError("Signature expired")
    if params.expires - params.created > MAX_SIGNATURE_LIFETIME_SECONDS:
        raise SignatureVerificationError("Signature lifetime exceeds 300 seconds")

    expected = resolve_key(params.keyid)
    if not expected:
        raise SignatureVerificationError(f'Unknown key "{params.keyid}"', code="unauthorized")

    base = signature_base(method, url, lowered, params)
    try:
        signature = base64.b64decode(sig_match.group(2), validate=True)
        recovered: str = Account.recover_message(encode_defunct(text=base), signature=signature)
    except Exception:  # any decoding or recovery failure means an invalid signature
        raise SignatureVerificationError("Signature could not be recovered") from None
    if recovered.lower() != expected.lower():
        raise SignatureVerificationError("Signature was not produced by the session key")
    if check_and_store_nonce is not None and check_and_store_nonce(
        params.keyid, params.nonce, params.expires
    ):
        raise SignatureVerificationError("Signature nonce was already used")
    return VerifiedSignature(
        key_id=params.keyid,
        address=recovered,
        created=params.created,
        expires=params.expires,
        nonce=params.nonce,
        covered_components=params.components,
    )
