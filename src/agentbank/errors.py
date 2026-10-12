"""Errors raised by the SDK.

API errors are RFC 9457 problem documents with a stable machine-readable
``code`` (``urn:agentbank:problem:<code>``). They are raised as subclasses of
:class:`AgentBankError` chosen by code first and HTTP status second, so callers
can catch either a broad family (``except PermissionDeniedError``) or one
precise condition (``except PolicyDeniedError``)::

    try:
        bank.payments.pay(to="0x...", amount="25.00")
    except PolicyDeniedError as err:
        print(err.code, err.detail, err.extensions.get("rule_hits"))
    except AgentBankError as err:
        print(err.status, err.code, err.detail)
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx

__all__ = [
    "ERROR_CATALOG",
    "PROBLEM_TYPE_PREFIX",
    "APIConnectionError",
    "APIResponseValidationError",
    "APITimeoutError",
    "AgentBankError",
    "AuthenticationError",
    "BadRequestError",
    "ConfigurationError",
    "ConflictError",
    "FrozenError",
    "IdempotencyConflictError",
    "InsufficientFundsError",
    "InternalServerError",
    "MainnetLockedError",
    "NotFoundError",
    "OwnerSignatureRequiredError",
    "PaymentDeniedError",
    "PaymentError",
    "PaymentFailedError",
    "PermissionDeniedError",
    "PolicyDeniedError",
    "RateLimitError",
    "ServiceUnavailableError",
    "SignatureVerificationError",
    "UnprocessableEntityError",
    "X402Error",
    "error_from_response",
]

PROBLEM_TYPE_PREFIX = "urn:agentbank:problem:"

#: Every error code the API can return, with its HTTP status and title
#: (mirrors ``ERROR_CATALOG`` in ``@agentbank/core``).
ERROR_CATALOG: Mapping[str, tuple[int, str]] = {
    "invalid_request": (400, "Invalid request"),
    "invalid_amount": (400, "Invalid amount"),
    "unsupported_asset": (400, "Unsupported asset"),
    "unsupported_chain": (400, "Unsupported chain"),
    "unauthorized": (401, "Authentication required"),
    "signature_invalid": (401, "Signature invalid"),
    "forbidden": (403, "Forbidden"),
    "owner_signature_required": (403, "Owner signature required"),
    "feature_gated": (403, "Feature not enabled"),
    "mainnet_locked": (403, "Mainnet is locked"),
    "not_found": (404, "Not found"),
    "conflict": (409, "Conflict"),
    "idempotency_conflict": (409, "Idempotency key reused with a different request"),
    "invalid_state": (409, "Invalid state transition"),
    "insufficient_funds": (422, "Insufficient funds"),
    "policy_denied": (422, "Payment denied by policy"),
    "agent_frozen": (423, "Agent is frozen"),
    "org_frozen": (423, "Organization is frozen"),
    "session_expired": (401, "Session key expired"),
    "session_revoked": (401, "Session key revoked"),
    "mandate_invalid": (422, "Mandate invalid"),
    "mandate_expired": (422, "Mandate expired"),
    "approval_expired": (409, "Approval expired"),
    "rate_limited": (429, "Too many requests"),
    "cosigner_unavailable": (503, "Co-signer unavailable; failing closed"),
    "screening_unavailable": (503, "Screening unavailable; failing closed"),
    "chain_error": (502, "Chain or bundler error"),
    "internal": (500, "Internal error"),
}

_STATUS_DEFAULT_CODES = {
    400: "invalid_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    422: "invalid_request",
    429: "rate_limited",
}


class AgentBankError(Exception):
    """Base class for every error raised by the SDK.

    Attributes:
        code: Stable machine-readable code, e.g. ``"policy_denied"``. API errors
            use the server's catalog; client-side errors use SDK codes such as
            ``"connection_error"``, ``"invalid_response"`` or ``"configuration_error"``.
        status: HTTP status of the response, or the catalog status for
            locally raised errors with a catalog code, else ``None``.
        title: Short human-readable summary of the problem type.
        detail: Human-readable explanation of this occurrence.
        type: RFC 9457 problem type URI, e.g. ``urn:agentbank:problem:policy_denied``.
        instance: RFC 9457 instance URI, when the server sent one.
        extensions: Any other members of the problem document (e.g. ``rule_hits``).
        response: The HTTP response, for API errors.
        request_id: Value of the ``x-request-id`` response header, if any.
    """

    def __init__(
        self,
        code: str,
        detail: str | None = None,
        *,
        status: int | None = None,
        title: str | None = None,
        type: str | None = None,
        instance: str | None = None,
        extensions: Mapping[str, Any] | None = None,
        response: httpx.Response | None = None,
    ) -> None:
        catalog = ERROR_CATALOG.get(code)
        self.code = code
        self.status = status if status is not None else (catalog[0] if catalog else None)
        self.title = title or (catalog[1] if catalog else code.replace("_", " ").capitalize())
        self.detail = detail or self.title
        self.type = type if type is not None else (PROBLEM_TYPE_PREFIX + code if catalog else None)
        self.instance = instance
        self.extensions: dict[str, Any] = dict(extensions or {})
        self.response = response
        self.request_id = response.headers.get("x-request-id") if response is not None else None
        super().__init__(self.detail)

    def __str__(self) -> str:
        prefix = f"{self.status} " if self.status is not None else ""
        return f"{prefix}{self.code}: {self.detail}"

    def __repr__(self) -> str:
        name = type(self).__name__
        return f"{name}(code={self.code!r}, status={self.status!r}, detail={self.detail!r})"

    def to_problem(self) -> dict[str, Any]:
        """Return the error as an RFC 9457 problem document."""
        problem: dict[str, Any] = {
            **self.extensions,
            "type": self.type or PROBLEM_TYPE_PREFIX + self.code,
            "title": self.title,
            "detail": self.detail,
            "code": self.code,
        }
        if self.status is not None:
            problem["status"] = self.status
        if self.instance is not None:
            problem["instance"] = self.instance
        return problem


# ----------------------------------------------------------------- transport


class APIConnectionError(AgentBankError):
    """The request could not reach the API or the connection failed mid-flight."""

    def __init__(self, detail: str = "Connection error", *, code: str = "connection_error") -> None:
        super().__init__(code, detail)


class APITimeoutError(APIConnectionError):
    """The request timed out."""

    def __init__(self, detail: str = "Request timed out") -> None:
        super().__init__(detail, code="timeout")


class APIResponseValidationError(AgentBankError):
    """A successful response did not match the API contract (code ``invalid_response``).

    Usually means the SDK is older or newer than the API; upgrade the SDK.
    """

    def __init__(self, response: httpx.Response, detail: str) -> None:
        super().__init__("invalid_response", detail, status=response.status_code, response=response)


# ----------------------------------------------------------------- by status


class BadRequestError(AgentBankError):
    """HTTP 400: the request was malformed (``invalid_request``, ``invalid_amount``, ...)."""


class AuthenticationError(AgentBankError):
    """HTTP 401: missing or invalid credentials, signature, or session key."""


class PermissionDeniedError(AgentBankError):
    """HTTP 403: authenticated but not allowed (``forbidden``, ``feature_gated``, ...)."""


class OwnerSignatureRequiredError(PermissionDeniedError):
    """HTTP 403 ``owner_signature_required``: the change needs the principal's owner key."""


class MainnetLockedError(PermissionDeniedError):
    """``mainnet_locked``: Agent Bank (and this SDK) is testnet-only."""


class NotFoundError(AgentBankError):
    """HTTP 404: the resource does not exist or is not visible to the caller."""


class ConflictError(AgentBankError):
    """HTTP 409: conflicting state (``conflict``, ``invalid_state``, ``approval_expired``)."""


class IdempotencyConflictError(ConflictError):
    """HTTP 409 ``idempotency_conflict``: the key was reused with a different request."""


class UnprocessableEntityError(AgentBankError):
    """HTTP 422: the request is valid but cannot be carried out."""


class InsufficientFundsError(UnprocessableEntityError):
    """HTTP 422 ``insufficient_funds``."""


class PolicyDeniedError(UnprocessableEntityError):
    """HTTP 422 ``policy_denied``: the policy engine refused the payment."""


class FrozenError(AgentBankError):
    """HTTP 423: the agent (``agent_frozen``) or the whole org (``org_frozen``) is frozen."""


class RateLimitError(AgentBankError):
    """HTTP 429: too many requests (retried automatically before being raised)."""


class InternalServerError(AgentBankError):
    """HTTP 5xx: server-side failure (``internal``, ``chain_error``)."""


class ServiceUnavailableError(InternalServerError):
    """HTTP 503: a dependency is down and the bank is failing closed.

    Raised for ``cosigner_unavailable`` and ``screening_unavailable``. No money
    moved; retrying later is safe (requests are idempotent).
    """


# ----------------------------------------------------------------- client side


class ConfigurationError(AgentBankError):
    """The client is missing the credentials or settings an operation needs."""

    def __init__(self, detail: str) -> None:
        super().__init__("configuration_error", detail)


class SignatureVerificationError(AuthenticationError):
    """A webhook or request signature failed local verification (``signature_invalid``)."""

    def __init__(self, detail: str, *, code: str = "signature_invalid") -> None:
        super().__init__(code, detail)


class PaymentError(AgentBankError):
    """A payment, escrow or stream did not complete.

    Raised by the helpers that drive a resource to completion (``payments.pay``,
    ``payments.complete``, ``payments.wait_for_settlement``, ``escrows.lock``,
    ``streams.start``). The resource is available as :attr:`resource`.

    Codes:
        ``payment_canceled``, ``payment_expired``: the payment reached that status.
        ``requires_owner``: policy requires the owner key to sign this payment
            itself; see ``resource.owner_operation_id``.
        ``settlement_timeout``: still pending after the timeout (it may settle later).

    Denials raise :class:`PaymentDeniedError` and on-chain failures
    :class:`PaymentFailedError`, both subclasses.
    """

    def __init__(self, code: str, detail: str, *, resource: Any = None) -> None:
        super().__init__(code, detail)
        self.resource = resource

    @property
    def payment(self) -> Any:
        """Alias of :attr:`resource`."""
        return self.resource


class PaymentDeniedError(PaymentError, PolicyDeniedError):
    """The payment was denied by policy or by the co-signer (code ``policy_denied``).

    Catchable as :class:`PolicyDeniedError` too; ``resource.decision`` lists the
    rules that fired.
    """

    def __init__(self, detail: str, *, resource: Any = None) -> None:
        super().__init__("policy_denied", detail, resource=resource)


class PaymentFailedError(PaymentError):
    """The payment, escrow or stream failed on-chain (code ``chain_error``).

    For example a reverted operation or a bundler timeout; the hold is released.
    """

    def __init__(self, detail: str, *, resource: Any = None) -> None:
        super().__init__("chain_error", detail, resource=resource)


#: Catalog code of each x402 failure reason (same mapping as the TypeScript SDK).
X402_REASON_CODES: Mapping[str, str] = {
    "invalid_challenge": "invalid_request",
    "no_acceptable_requirement": "invalid_request",
    "amount_exceeds_limit": "policy_denied",
    "domain_not_allowed": "policy_denied",
    "approval_required": "policy_denied",
    "authorization_mismatch": "internal",
    "payment_rejected": "conflict",
    "spend_key_missing": "invalid_request",
    "unexpected_status": "internal",
}


class X402Error(AgentBankError):
    """An x402 (HTTP 402) payment failed client-side or was rejected by the seller.

    Attributes:
        reason: Machine-readable reason (``.code`` is the matching catalog code):
            ``invalid_challenge`` (not a valid x402 challenge),
            ``no_acceptable_requirement`` (no ``exact`` USDC option on the network),
            ``amount_exceeds_limit`` (price above ``max_amount``),
            ``domain_not_allowed`` (host not in ``allowed_domains``),
            ``approval_required`` (x402 cannot wait for human approval),
            ``authorization_mismatch`` (the API's authorization differs from the
            challenge, so nothing was signed),
            ``payment_rejected`` (the seller answered 402 again after payment),
            ``spend_key_missing``, ``unexpected_status``.
        payment: The Agent Bank payment, if one was created (its hold expires if
            the seller never settles).
        settlement: The seller's decoded settlement response, if any.
        response: The seller's last HTTP response, if any.
    """

    def __init__(
        self,
        reason: str,
        detail: str,
        *,
        payment: Any = None,
        settlement: Mapping[str, Any] | None = None,
        response: httpx.Response | None = None,
    ) -> None:
        super().__init__(
            X402_REASON_CODES.get(reason, "internal"),
            detail,
            extensions={"reason": reason},
            response=response,
        )
        self.reason = reason
        self.payment = payment
        self.settlement = dict(settlement) if settlement is not None else None


_CODE_CLASSES: dict[str, type[AgentBankError]] = {
    "owner_signature_required": OwnerSignatureRequiredError,
    "mainnet_locked": MainnetLockedError,
    "idempotency_conflict": IdempotencyConflictError,
    "insufficient_funds": InsufficientFundsError,
    "policy_denied": PolicyDeniedError,
    "agent_frozen": FrozenError,
    "org_frozen": FrozenError,
    "cosigner_unavailable": ServiceUnavailableError,
    "screening_unavailable": ServiceUnavailableError,
}

_STATUS_CLASSES: dict[int, type[AgentBankError]] = {
    400: BadRequestError,
    401: AuthenticationError,
    403: PermissionDeniedError,
    404: NotFoundError,
    409: ConflictError,
    422: UnprocessableEntityError,
    423: FrozenError,
    429: RateLimitError,
    503: ServiceUnavailableError,
}


def _class_for(code: str, status: int) -> type[AgentBankError]:
    if code in _CODE_CLASSES:
        return _CODE_CLASSES[code]
    if status in _STATUS_CLASSES:
        return _STATUS_CLASSES[status]
    if status >= 500:
        return InternalServerError
    return AgentBankError


def error_from_response(response: httpx.Response) -> AgentBankError:
    """Build the most specific :class:`AgentBankError` for an error response.

    Reads an RFC 9457 problem document when the body is JSON; otherwise falls
    back to a code derived from the HTTP status.
    """
    status = response.status_code
    problem: dict[str, Any] = {}
    try:
        parsed = response.json()
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        problem = parsed
    code = problem.get("code")
    if not isinstance(code, str) or not code:
        code = _STATUS_DEFAULT_CODES.get(status, "internal" if status >= 500 else "http_error")
    title = problem.get("title")
    detail = problem.get("detail")
    if not isinstance(detail, str) or not detail:
        fallback = title if isinstance(title, str) and title else response.text.strip()[:500]
        detail = fallback or response.reason_phrase or f"HTTP {status}"
    type_ = problem.get("type")
    instance = problem.get("instance")
    known = {"type", "title", "status", "detail", "instance", "code"}
    extensions = {k: v for k, v in problem.items() if k not in known}
    cls = _class_for(code, status)
    return cls(
        code,
        detail,
        status=status,
        title=title if isinstance(title, str) else None,
        type=type_ if isinstance(type_, str) else None,
        instance=instance if isinstance(instance, str) else None,
        extensions=extensions,
        response=response,
    )
