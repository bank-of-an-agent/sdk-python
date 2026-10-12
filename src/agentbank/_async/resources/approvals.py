"""Human approvals: ``/v1/approvals``."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Any, Literal

from agentbank import _operations as ops
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank.models import Approval, ListApprovalsResponse

__all__ = ["AsyncApprovals"]

ApprovalStatus = Literal["pending", "approved", "denied", "expired"]


class AsyncApprovals(AsyncAPIResource):
    """Payments queued for a human approver (they expire after 15 minutes)."""

    async def list(
        self,
        *,
        status: ApprovalStatus | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListApprovalsResponse:
        """List approvals (one page), e.g. ``status="pending"``."""
        return await self._request(
            ops.LIST_APPROVALS,
            ListApprovalsResponse,
            query={"status": status, "cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    async def list_all(
        self,
        *,
        status: ApprovalStatus | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> AsyncIterator[Approval]:
        """Iterate over every approval, following ``next_cursor``."""
        async for page in self._paginate(
            ops.LIST_APPROVALS,
            ListApprovalsResponse,
            query={"status": status, "limit": limit},
            request_options=request_options,
        ):
            for item in page.data:
                yield item

    async def retrieve(
        self, approval_id: str, *, request_options: RequestOptions | None = None
    ) -> Approval:
        """Get an approval."""
        return await self._request(
            ops.GET_APPROVAL,
            Approval,
            path_params={"id": approval_id},
            request_options=request_options,
        )

    async def decide(
        self,
        approval_id: str,
        *,
        decision: Literal["approve", "deny"],
        webauthn_assertion: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Approval:
        """Approve or deny a queued payment (approver or admin API key).

        Args:
            approval_id: The approval.
            decision: ``"approve"`` or ``"deny"``.
            webauthn_assertion: Passkey assertion for the approval challenge
                (required for console members).
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        return await self._request(
            ops.DECIDE_APPROVAL,
            Approval,
            path_params={"id": approval_id},
            body=compact(decision=decision, webauthn_assertion=webauthn_assertion),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def approve(
        self, approval_id: str, *, request_options: RequestOptions | None = None
    ) -> Approval:
        """Shorthand for ``decide(approval_id, decision="approve")``."""
        return await self.decide(approval_id, decision="approve", request_options=request_options)

    async def deny(
        self, approval_id: str, *, request_options: RequestOptions | None = None
    ) -> Approval:
        """Shorthand for ``decide(approval_id, decision="deny")``."""
        return await self.decide(approval_id, decision="deny", request_options=request_options)
