"""Webhook signatures: ``AgentBank-Signature: t=<unix seconds>,v1=<hex>``.

``v1 = HMAC-SHA256(secret, f"{t}.{raw_body}")``, compatible with ``webhooks.ts``
in ``@agentbank/core``. Always verify against the *raw* request body (not
re-serialized JSON) and reject timestamps outside the tolerance window::

    from agentbank import verify_webhook


    @app.post("/webhooks/agentbank")
    async def receive(request: Request) -> Response:
        body = await request.body()
        verify_webhook(SECRET, body, request.headers.get("agentbank-signature"))
        event = json.loads(body)
        ...
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime
from typing import Any, Final, Literal, get_args

from pydantic import BaseModel, ConfigDict

from agentbank.errors import SignatureVerificationError

__all__ = [
    "DEFAULT_WEBHOOK_TOLERANCE_SECONDS",
    "WEBHOOK_EVENT_HEADER",
    "WEBHOOK_EVENT_TYPES",
    "WEBHOOK_ID_HEADER",
    "WEBHOOK_RETRY_SCHEDULE_SECONDS",
    "WEBHOOK_SIGNATURE_HEADER",
    "WebhookEvent",
    "WebhookEventType",
    "construct_event",
    "sign_webhook",
    "verify_webhook",
]

WEBHOOK_SIGNATURE_HEADER: Final = "agentbank-signature"
WEBHOOK_EVENT_HEADER: Final = "agentbank-event"
WEBHOOK_ID_HEADER: Final = "agentbank-delivery"
DEFAULT_WEBHOOK_TOLERANCE_SECONDS: Final = 300

WebhookEventType = Literal[
    "payment.created",
    "payment.requires_approval",
    "payment.submitted",
    "payment.settled",
    "payment.failed",
    "payment.denied",
    "approval.requested",
    "approval.decided",
    "escrow.locked",
    "escrow.released",
    "escrow.refunded",
    "escrow.disputed",
    "stream.created",
    "stream.settled",
    "stream.canceled",
    "deposit.received",
    "reconciliation.mismatch",
    "agent.frozen",
    "agent.unfrozen",
    "org.frozen",
    "policy.updated",
    "session.revoked",
    "balance.low",
    "statement.ready",
]

#: Every webhook event type.
WEBHOOK_EVENT_TYPES: Final[tuple[str, ...]] = get_args(WebhookEventType)

#: Delivery retry schedule (seconds after the first attempt), covering 72 hours.
WEBHOOK_RETRY_SCHEDULE_SECONDS: Final[tuple[int, ...]] = (
    0,
    30,
    120,
    600,
    1_800,
    3_600,
    7_200,
    14_400,
    28_800,
    43_200,
    86_400,
    129_600,
    172_800,
    216_000,
    259_200,
)


class WebhookEvent(BaseModel):
    """A webhook delivery body.

    Deliveries carry the event envelope (``id``, ``type``, ``data`` and usually
    ``object``, ``org_id`` and ``created_at``, as in ``GET /v1/events``). Unknown
    fields are kept (see ``model_extra``) so new envelope fields never break
    receivers.
    """

    model_config = ConfigDict(extra="allow")

    id: str
    type: str
    data: dict[str, Any]
    object: str | None = None
    org_id: str | None = None
    created_at: datetime | None = None


def _raw(body: str | bytes) -> bytes:
    return body.encode("utf-8") if isinstance(body, str) else bytes(body)


def _mac(secret: str, timestamp: int, body: str | bytes) -> bytes:
    message = f"{timestamp}.".encode() + _raw(body)
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).digest()


def sign_webhook(secret: str, body: str | bytes, timestamp: int | None = None) -> str:
    """Compute the ``AgentBank-Signature`` header value for ``body``.

    Useful for testing your webhook endpoint locally.
    """
    t = int(time.time()) if timestamp is None else timestamp
    return f"t={t},v1={_mac(secret, t, body).hex()}"


def _parse_header(header: str) -> dict[str, list[str]]:
    parts: dict[str, list[str]] = {}
    for part in header.split(","):
        index = part.find("=")
        if index <= 0:
            continue
        parts.setdefault(part[:index].strip(), []).append(part[index + 1 :].strip())
    return parts


def _hex_bytes(value: str) -> bytes | None:
    clean = value.removeprefix("0x")
    if len(clean) % 2 != 0:
        return None
    try:
        return bytes.fromhex(clean)
    except ValueError:
        return None


def verify_webhook(
    secret: str,
    body: str | bytes,
    header: str | None,
    tolerance: int = DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
    *,
    now: int | None = None,
) -> int:
    """Verify an ``AgentBank-Signature`` header against the raw body.

    Several ``v1=`` values may be present (secret rotation); any match passes.

    Args:
        secret: The endpoint's signing secret (shown once at creation).
        body: The raw request body, exactly as received.
        header: The ``AgentBank-Signature`` header value.
        tolerance: Maximum clock difference in seconds (default 300).
        now: Unix seconds; defaults to now.

    Returns:
        The signed timestamp.

    Raises:
        SignatureVerificationError: Missing header or timestamp, timestamp outside
            the tolerance, or no matching signature (code ``signature_invalid``).
    """
    if not header:
        raise SignatureVerificationError("Missing AgentBank-Signature header")
    parts = _parse_header(header)
    raw_t = parts.get("t", [""])[0]
    if not raw_t.isascii() or not raw_t.isdigit():
        raise SignatureVerificationError("Webhook signature missing timestamp")
    t = int(raw_t)
    current = int(time.time()) if now is None else now
    if abs(current - t) > tolerance:
        raise SignatureVerificationError("Webhook timestamp outside tolerance")
    expected = _mac(secret, t, body)
    for candidate in parts.get("v1", []):
        decoded = _hex_bytes(candidate)
        if decoded is not None and hmac.compare_digest(decoded, expected):
            return t
    raise SignatureVerificationError("Webhook signature mismatch")


def construct_event(
    secret: str,
    body: str | bytes,
    header: str | None,
    tolerance: int = DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
    *,
    now: int | None = None,
) -> WebhookEvent:
    """Verify a webhook delivery and parse its body into a :class:`WebhookEvent`.

    Raises:
        SignatureVerificationError: The signature does not verify.
        pydantic.ValidationError: The body is not an event envelope.
    """
    verify_webhook(secret, body, header, tolerance, now=now)
    return WebhookEvent.model_validate(json.loads(_raw(body)))
