"""Small, I/O-free helpers shared by the sync and async resource classes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agentbank.canonical import to_jsonable
from agentbank.errors import ConfigurationError
from agentbank.models import PaymentDestination, SigningRequest

__all__ = [
    "TERMINAL_PAYMENT_STATUSES",
    "compact",
    "destination",
    "payee",
    "signature_idempotency_key",
    "without_owner_authorization",
]

#: Payment statuses after which nothing else will happen.
TERMINAL_PAYMENT_STATUSES = frozenset({"settled", "denied", "failed", "canceled", "expired"})

#: Payment statuses that are terminal failures.
FAILED_PAYMENT_STATUSES = frozenset({"denied", "failed", "canceled", "expired"})


def compact(**fields: Any) -> dict[str, Any]:
    """Build a JSON body from keyword arguments, dropping ``None`` (absent) values."""
    return {key: to_jsonable(value) for key, value in fields.items() if value is not None}


def without_owner_authorization(body: Mapping[str, Any]) -> dict[str, Any]:
    """The request body minus ``owner_authorization`` (the payload owners sign by default)."""
    return {key: value for key, value in body.items() if key != "owner_authorization"}


def _reference(value: str, kinds: Mapping[str, str], what: str) -> dict[str, str]:
    if value.startswith("0x"):
        return {"address": value}
    for prefix, key in kinds.items():
        if value.startswith(prefix):
            return {key: value}
    expected = ", ".join(["an address (0x...)", *(f"an id ({p}...)" for p in kinds)])
    raise ValueError(f"{what} must be {expected}; got {value!r}")


def destination(to: PaymentDestination | Mapping[str, Any] | str) -> dict[str, Any]:
    """Normalize a payment destination.

    Accepts a ``PaymentDestination``/mapping (``address``, ``agent_id`` or
    ``account_id``), or a string: ``0x...`` (address), ``agt_...`` (agent) or
    ``acct_...`` (Agent Bank account).
    """
    if isinstance(to, str):
        return _reference(to, {"agt_": "agent_id", "acct_": "account_id"}, "Payment destination")
    result: dict[str, Any] = to_jsonable(to)
    return result


def payee(value: Mapping[str, Any] | str) -> dict[str, Any]:
    """Normalize an escrow or stream payee: ``0x...`` address, ``agt_...`` id, or a mapping."""
    if isinstance(value, str):
        return _reference(value, {"agt_": "agent_id"}, "Payee")
    result: dict[str, Any] = to_jsonable(value)
    return result


def signature_idempotency_key(resource_id: str, signing_request: SigningRequest) -> str:
    """Deterministic idempotency key for submitting a signature over ``signing_request``.

    Re-running a helper such as ``payments.pay`` after a crash resubmits the
    same signature under the same key, so the API returns the original result.
    """
    return f"sig:{resource_id}:{signing_request.user_op_hash}"


def require_session_for(signing_request: SigningRequest, session_id: str | None) -> str:
    """Check that this client's session is the one asked to sign; return its id."""
    if session_id is None:
        raise ConfigurationError("Signing requires agent credentials (session_id + session_key)")
    if signing_request.session_id is not None and signing_request.session_id != session_id:
        raise ConfigurationError(
            f"The operation must be signed by session {signing_request.session_id}, "
            f"but this client uses {session_id}"
        )
    return session_id
