"""x402 (HTTP 402 Payment Required) for buyer agents: protocol logic without I/O.

The flow, implemented by :class:`agentbank.X402Transport` and
:class:`agentbank.AsyncX402Transport` on top of these functions:

1. A resource answers ``402`` with a challenge: x402 v2 sends a base64 JSON
   ``PaymentRequired`` in the ``PAYMENT-REQUIRED`` header; x402 v1 sends it as
   the JSON body (and expects the payment in ``X-PAYMENT``).
2. :func:`select_requirement` picks the first ``exact`` USDC requirement on a
   supported testnet whose price is within the client's ``max_amount`` (and
   whose host is in ``allowed_domains``, when given). Mainnets are refused.
3. The agent asks Agent Bank (``POST /v1/x402/pay``) to authorize the payment;
   policy (domain allowlists, caps, velocity, mandates) runs server-side and the
   API returns an EIP-3009 ``TransferWithAuthorization`` for the spend key.
4. :func:`build_payment_header` checks that authorization against the challenge
   (payee, exact amount, asset, chain, validity window) and only then signs it
   with the spend key, producing the ``PAYMENT-SIGNATURE`` (v2) or ``X-PAYMENT``
   (v1) header for the retried request.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlsplit

from agentbank.chains import AssetInfo, ChainInfo, chain_for_network, find_asset
from agentbank.eip712 import transfer_with_authorization_typed_data
from agentbank.errors import AgentBankError, X402Error
from agentbank.keys import EthSigner, sign_typed_data
from agentbank.models import Payment, X402PayResponse
from agentbank.money import format_amount

__all__ = [
    "PAYMENT_REQUIRED_HEADER",
    "PAYMENT_RESPONSE_HEADER",
    "PAYMENT_SIGNATURE_HEADER",
    "RECEIPT_EXTENSION",
    "V1_PAYMENT_HEADER",
    "V1_PAYMENT_RESPONSE_HEADER",
    "PaymentHeader",
    "PaymentRequired",
    "SelectedRequirement",
    "X402Receipt",
    "build_payment_header",
    "decode_header",
    "decode_payment_response",
    "encode_header",
    "parse_payment_required",
    "select_requirement",
    "x402_receipt",
]

PAYMENT_REQUIRED_HEADER: Final = "PAYMENT-REQUIRED"
PAYMENT_SIGNATURE_HEADER: Final = "PAYMENT-SIGNATURE"
PAYMENT_RESPONSE_HEADER: Final = "PAYMENT-RESPONSE"
V1_PAYMENT_HEADER: Final = "X-PAYMENT"
V1_PAYMENT_RESPONSE_HEADER: Final = "X-PAYMENT-RESPONSE"

#: Key under which transports attach an :class:`X402Receipt` to ``response.extensions``.
RECEIPT_EXTENSION: Final = "agentbank.x402"

#: Seconds of clock skew tolerated when checking an authorization's validity window.
CLOCK_SKEW_SECONDS: Final = 300

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BYTES32_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_DIGITS_RE = re.compile(r"^[0-9]+$")


# --------------------------------------------------------------------- encoding


def encode_header(value: Mapping[str, Any]) -> str:
    """Encode an x402 header value: base64 of compact UTF-8 JSON."""
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def decode_header(value: str) -> dict[str, Any]:
    """Decode an x402 header value (standard or URL-safe base64, padding optional).

    Raises:
        X402Error: ``x402_invalid_challenge`` if it is not base64 JSON object.
    """
    text = value.strip()
    padded = text + "=" * (-len(text) % 4)
    try:
        raw = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
        data = json.loads(raw)
    except (binascii.Error, ValueError) as exc:
        raise X402Error("x402_invalid_challenge", "x402 header is not base64 JSON") from exc
    if not isinstance(data, dict):
        raise X402Error("x402_invalid_challenge", "x402 header must encode a JSON object")
    return data


def _header(headers: Mapping[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


# --------------------------------------------------------------------- challenge


@dataclass(frozen=True)
class PaymentRequired:
    """A parsed x402 ``PaymentRequired`` challenge.

    Attributes:
        x402_version: ``2`` (header) or ``1`` (JSON body).
        accepts: The offered payment requirements, as sent.
        resource: The v2 ``ResourceInfo`` (``url``, ``description``, ``mimeType``).
        error: The server's error message, if any.
    """

    x402_version: int
    accepts: tuple[dict[str, Any], ...]
    resource: dict[str, Any] | None = None
    error: str | None = None


def parse_payment_required(headers: Mapping[str, str], body: bytes | str) -> PaymentRequired:
    """Parse a 402 response into a :class:`PaymentRequired`.

    Reads the v2 ``PAYMENT-REQUIRED`` header first, then a JSON body (v1, or v2
    servers that also send the challenge in the body).

    Raises:
        X402Error: ``x402_invalid_challenge`` if no valid challenge is present.
    """
    header = _header(headers, PAYMENT_REQUIRED_HEADER)
    if header:
        data = decode_header(header)
    else:
        try:
            parsed: Any = json.loads(body or b"null")
        except ValueError:
            parsed = None
        if not isinstance(parsed, dict):
            raise X402Error(
                "x402_invalid_challenge",
                "402 response has no PAYMENT-REQUIRED header and no x402 JSON body",
            )
        data = parsed
    version = data.get("x402Version")
    accepts = data.get("accepts")
    if not isinstance(version, int) or isinstance(version, bool) or version not in (1, 2):
        raise X402Error("x402_invalid_challenge", f"Unsupported x402Version {version!r}")
    if not isinstance(accepts, list) or not all(isinstance(a, dict) for a in accepts):
        raise X402Error("x402_invalid_challenge", "x402 challenge has no 'accepts' list")
    resource = data.get("resource")
    error = data.get("error")
    return PaymentRequired(
        x402_version=version,
        accepts=tuple(accepts),
        resource=resource if isinstance(resource, dict) else None,
        error=error if isinstance(error, str) else None,
    )


# --------------------------------------------------------------------- selection


@dataclass(frozen=True)
class SelectedRequirement:
    """The requirement the client chose to pay, normalized for the Agent Bank API.

    Attributes:
        x402_version: Protocol version of the challenge.
        accepted: The requirement exactly as offered (echoed back in v2 payloads).
        requirements: The v2 ``X402PaymentRequirements`` sent to ``POST /v1/x402/pay``.
        resource: The ``X402ResourceInfo`` sent to the API (its ``url`` is the URL
            actually requested, so domain policies see the real host).
        payload_resource: The challenge's ``ResourceInfo`` (echoed back in v2 payloads).
        network: Network as offered (CAIP-2 or a v1 name).
        chain: The (testnet) chain.
        asset: The token being paid.
        amount: Price in atomic token units.
        pay_to: Payee address.
        max_timeout_seconds: Maximum validity of the authorization.
    """

    x402_version: int
    accepted: dict[str, Any]
    requirements: dict[str, Any]
    resource: dict[str, Any]
    payload_resource: dict[str, Any] | None
    network: str
    chain: ChainInfo
    asset: AssetInfo
    amount: int
    pay_to: str
    max_timeout_seconds: int


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def _evaluate(
    requirement: Mapping[str, Any], version: int
) -> tuple[ChainInfo, AssetInfo, int, str, int] | str:
    """Return ``(chain, asset, amount, pay_to, timeout)`` or the reason it is unusable."""
    if requirement.get("scheme") != "exact":
        return f"scheme {requirement.get('scheme')!r} is not supported (only 'exact')"
    network = requirement.get("network")
    if not isinstance(network, str):
        return "missing network"
    try:
        chain = chain_for_network(network)
    except AgentBankError as exc:
        return f"network {network!r}: {exc.detail}"
    asset_address = requirement.get("asset")
    asset = find_asset(chain.id, asset_address) if isinstance(asset_address, str) else None
    if asset is None:
        return f"asset {asset_address!r} is not USDC on {chain.display_name}"
    raw_amount = requirement.get("amount" if version >= 2 else "maxAmountRequired")
    if not isinstance(raw_amount, str) or not _DIGITS_RE.match(raw_amount) or int(raw_amount) <= 0:
        return f"invalid amount {raw_amount!r}"
    pay_to = requirement.get("payTo")
    if not isinstance(pay_to, str) or not _ADDRESS_RE.match(pay_to):
        return f"invalid payTo {pay_to!r}"
    timeout = requirement.get("maxTimeoutSeconds")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout <= 0:
        return f"invalid maxTimeoutSeconds {timeout!r}"
    return chain, asset, int(raw_amount), pay_to, timeout


def select_requirement(
    challenge: PaymentRequired,
    *,
    request_url: str,
    max_amount: int,
    allowed_domains: Collection[str] | None = None,
) -> SelectedRequirement:
    """Choose which offered requirement to pay.

    Picks the first ``exact`` requirement for USDC on a supported testnet whose
    amount is at most ``max_amount`` (atomic units, i.e. USDC micro-units).

    Args:
        challenge: The parsed challenge.
        request_url: The URL that answered 402 (its host is the x402 domain).
        max_amount: Client-side price ceiling in atomic units.
        allowed_domains: Optional allowlist of hosts the client may pay.

    Raises:
        X402Error: ``x402_domain_not_allowed``, ``x402_unsupported`` or
            ``x402_amount_exceeds_limit``.
    """
    host = _host(request_url)
    if allowed_domains is not None and host not in {d.lower() for d in allowed_domains}:
        raise X402Error("x402_domain_not_allowed", f"Paying {host!r} is not allowed by this client")
    reasons: list[str] = []
    cheapest_over: int | None = None
    for offered in challenge.accepts:
        evaluated = _evaluate(offered, challenge.x402_version)
        if isinstance(evaluated, str):
            reasons.append(evaluated)
            continue
        chain, asset, amount, pay_to, timeout = evaluated
        if amount > max_amount:
            cheapest_over = amount if cheapest_over is None else min(cheapest_over, amount)
            continue
        extra = offered.get("extra")
        requirements = {
            "scheme": "exact",
            "network": chain.caip2,
            "asset": offered["asset"],
            "amount": str(amount),
            "payTo": pay_to,
            "maxTimeoutSeconds": timeout,
            "extra": dict(extra) if isinstance(extra, dict) else {},
        }
        info = challenge.resource or {}
        if challenge.x402_version == 1:
            info = {
                key: offered[key]
                for key in ("description", "mimeType")
                if isinstance(offered.get(key), str) and offered[key]
            }
        resource = {**info, "url": request_url}
        return SelectedRequirement(
            x402_version=challenge.x402_version,
            accepted=dict(offered),
            requirements=requirements,
            resource=resource,
            payload_resource=challenge.resource,
            network=str(offered["network"]),
            chain=chain,
            asset=asset,
            amount=amount,
            pay_to=pay_to,
            max_timeout_seconds=timeout,
        )
    if cheapest_over is not None:
        limit = format_amount(max_amount)
        price = format_amount(cheapest_over)
        raise X402Error(
            "x402_amount_exceeds_limit",
            f"{host} asks for {price} USDC, above this client's max_amount of {limit} USDC",
        )
    detail = "; ".join(reasons) or "the challenge offers no payment options"
    raise X402Error("x402_unsupported", f"No acceptable x402 payment option: {detail}")


# --------------------------------------------------------------------- payment


@dataclass(frozen=True)
class PaymentHeader:
    """The header to add to the retried request.

    Attributes:
        name: ``PAYMENT-SIGNATURE`` (v2) or ``X-PAYMENT`` (v1).
        value: Base64 JSON ``PaymentPayload``.
        payload: The decoded ``PaymentPayload``.
    """

    name: str
    value: str
    payload: dict[str, Any]


def _mismatch(detail: str, payment: Payment) -> X402Error:
    return X402Error("x402_authorization_mismatch", detail, payment=payment)


def build_payment_header(
    selected: SelectedRequirement,
    response: X402PayResponse,
    signer: EthSigner,
    *,
    now: int | None = None,
) -> PaymentHeader:
    """Check the API's EIP-3009 authorization against the challenge, sign it, encode it.

    The spend key signs only if the authorization pays exactly the offered
    amount, to the offered payee, in the offered asset and chain, from the
    spend key itself, within a sane validity window. Anything else means the
    API and the challenge disagree, and nothing is signed.

    Raises:
        X402Error: ``x402_not_authorized`` (approval required or denied) or
            ``x402_authorization_mismatch``.
    """
    payment = response.payment
    authorization = response.authorization
    domain = response.eip712_domain
    if authorization is None or domain is None:
        raise X402Error(
            "x402_not_authorized",
            f"x402 payment {payment.id} is {payment.status}; nothing to sign",
            payment=payment,
        )
    auth = authorization.model_dump(mode="json", by_alias=True)
    current = int(time.time()) if now is None else now
    if auth["from"].lower() != signer.address.lower():
        raise _mismatch("Authorization is not from this client's spend key", payment)
    if auth["to"].lower() != selected.pay_to.lower():
        raise _mismatch("Authorization pays a different address than the challenge", payment)
    if int(auth["value"]) != selected.amount:
        raise _mismatch("Authorization amount differs from the challenge amount", payment)
    if domain.verifyingContract.lower() != selected.asset.address.lower():
        raise _mismatch("Authorization is for a different token than the challenge", payment)
    if domain.chainId != selected.chain.id:
        raise _mismatch("Authorization is for a different chain than the challenge", payment)
    extra = selected.requirements["extra"]
    for key, expected in (("name", domain.name), ("version", domain.version)):
        if isinstance(extra.get(key), str) and extra[key] != expected:
            raise _mismatch(f"Token EIP-712 {key} differs from the challenge", payment)
    if not _BYTES32_RE.match(auth["nonce"]):
        raise _mismatch("Authorization nonce is not 32 bytes", payment)
    valid_after, valid_before = int(auth["validAfter"]), int(auth["validBefore"])
    if valid_before <= current:
        raise _mismatch("Authorization has already expired", payment)
    if valid_before > current + selected.max_timeout_seconds + CLOCK_SKEW_SECONDS:
        raise _mismatch("Authorization is valid for longer than the challenge allows", payment)
    if valid_after > current + CLOCK_SKEW_SECONDS:
        raise _mismatch("Authorization is not valid yet", payment)

    eip712_domain = {
        "name": domain.name,
        "version": domain.version,
        "chainId": domain.chainId,
        "verifyingContract": domain.verifyingContract,
    }
    signature = sign_typed_data(signer, transfer_with_authorization_typed_data(eip712_domain, auth))
    inner = {"signature": signature, "authorization": auth}
    payload: dict[str, Any]
    if selected.x402_version >= 2:
        payload = {"x402Version": 2}
        if selected.payload_resource is not None:
            payload["resource"] = selected.payload_resource
        payload["accepted"] = selected.accepted
        payload["payload"] = inner
        name = PAYMENT_SIGNATURE_HEADER
    else:
        payload = {
            "x402Version": 1,
            "scheme": selected.accepted["scheme"],
            "network": selected.network,
            "payload": inner,
        }
        name = V1_PAYMENT_HEADER
    return PaymentHeader(name=name, value=encode_header(payload), payload=payload)


def decode_payment_response(headers: Mapping[str, str]) -> dict[str, Any] | None:
    """Decode the seller's settlement response header (``PAYMENT-RESPONSE`` or v1), if any."""
    for name in (PAYMENT_RESPONSE_HEADER, V1_PAYMENT_RESPONSE_HEADER):
        value = _header(headers, name)
        if value:
            try:
                return decode_header(value)
            except X402Error:
                return None
    return None


@dataclass(frozen=True)
class X402Receipt:
    """What an x402 transport paid for a response (``response.extensions``).

    Attributes:
        payment: The Agent Bank payment (kind ``x402``).
        requirement: The requirement that was paid.
        header: The payment header that was sent.
        settlement: The seller's decoded settlement response, if it sent one.
    """

    payment: Payment
    requirement: SelectedRequirement
    header: PaymentHeader
    settlement: dict[str, Any] | None


def x402_receipt(response: Any) -> X402Receipt | None:
    """Return the :class:`X402Receipt` attached to an ``httpx.Response``, if it was paid."""
    extensions = getattr(response, "extensions", None)
    if not isinstance(extensions, Mapping):
        return None
    receipt = extensions.get(RECEIPT_EXTENSION)
    return receipt if isinstance(receipt, X402Receipt) else None
