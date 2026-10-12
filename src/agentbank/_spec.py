"""Static description of an API operation (see the generated ``_operations`` table)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

HttpMethod = Literal["GET", "POST", "PUT", "DELETE"]

#: Who may call an operation (``x-agentbank-auth`` in the OpenAPI document).
#:
#: * ``public``: no authentication.
#: * ``principal``: org API key (``Authorization: Bearer abk_...``).
#: * ``agent``: RFC 9421 HTTP Message Signature by a live session key.
#: * ``approver``: org API key of a member with the approver or admin role.
#: * ``seller``: an x402 seller calling the facilitator (no credentials).
#: * ``staff``: Agent Bank operators (internal dashboards).
AuthKind = Literal["public", "principal", "agent", "approver", "seller", "staff"]

#: Which service serves an operation; the load balancer routes facilitator paths.
Service = Literal["api", "facilitator"]

#: Operations without an ``Idempotency-Key`` that are nevertheless safe to retry
#: after an ambiguous failure (pure reads or dry runs).
SAFE_TO_RETRY_POSTS: frozenset[str] = frozenset({"checkPolicy", "x402Verify"})


@dataclass(frozen=True)
class Operation:
    """One REST operation, as described by the OpenAPI document.

    Attributes:
        operation_id: The OpenAPI ``operationId``.
        method: HTTP method.
        path: Path template, e.g. ``/v1/payments/{id}``.
        auth: Accepted caller kinds, in the API's order of preference.
        idempotent: Whether the operation takes a required ``Idempotency-Key``.
        service: ``api`` or ``facilitator``.
        success_status: The documented success status code.
        path_params: Names of the path template parameters.
        query_params: Names of the accepted query parameters.
        has_body: Whether the operation takes a JSON request body.
        response_media_types: Media types of the success response.
    """

    operation_id: str
    method: HttpMethod
    path: str
    auth: tuple[AuthKind, ...]
    idempotent: bool
    service: Service
    success_status: int
    path_params: tuple[str, ...] = ()
    query_params: tuple[str, ...] = ()
    has_body: bool = False
    response_media_types: tuple[str, ...] = ("application/json",)

    @property
    def retry_safe(self) -> bool:
        """Whether a failed attempt may be retried without risking a duplicate effect.

        True for reads, for ``DELETE`` (revocations are idempotent by nature), for
        operations protected by an ``Idempotency-Key``, and for dry-run ``POST``s.
        """
        return (
            self.method in ("GET", "DELETE")
            or self.idempotent
            or self.operation_id in SAFE_TO_RETRY_POSTS
        )
