"""AP2 payment mandates: ``/v1/mandates``."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Any, Literal

from agentbank import _operations as ops
from agentbank import owner_payloads
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._base_client import RequestOptions
from agentbank.keys import SessionKey, SignerLike
from agentbank.models import ListMandatesResponse, Mandate, OpenPaymentMandate

__all__ = ["AsyncMandates"]

MandateStatus = Literal["active", "expired", "revoked"]


class AsyncMandates(AsyncAPIResource):
    """AP2 open Payment Mandates granting an agent bounded authority."""

    async def list(
        self,
        *,
        agent_id: str | None = None,
        status: MandateStatus | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListMandatesResponse:
        """List mandates (one page)."""
        return await self._request(
            ops.LIST_MANDATES,
            ListMandatesResponse,
            query={"agent_id": agent_id, "status": status, "cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    async def list_all(
        self,
        *,
        agent_id: str | None = None,
        status: MandateStatus | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> AsyncIterator[Mandate]:
        """List mandates: iterate over every page, following ``next_cursor``."""
        async for page in self._paginate(
            ops.LIST_MANDATES,
            ListMandatesResponse,
            query={"agent_id": agent_id, "status": status, "limit": limit},
            request_options=request_options,
        ):
            for item in page.data:
                yield item

    async def create(
        self,
        *,
        agent_id: str,
        mandate: OpenPaymentMandate | Mapping[str, Any],
        owner_authorization: dict[str, Any] | None = None,
        owner: SignerLike | SessionKey | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Mandate:
        """Grant an agent authority with a mandate signed by the owner.

        Args:
            agent_id: The agent receiving the mandate.
            mandate: The AP2 open Payment Mandate (``vct``, ``constraints``,
                ``iat``, ``exp``, ``agent_id`` ...). Its defaults are made explicit
                before it is sent and signed.
            owner_authorization: A pre-signed ``mandate.issue`` authorization over
                the mandate (subject = ``agent_id``; see
                :func:`agentbank.owner_payloads.mandate_issue`).
            owner: Alternatively, the owner key; the SDK signs it.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        issue = owner_payloads.mandate_issue(agent_id, mandate)
        body: dict[str, Any] = {"agent_id": agent_id, "mandate": issue.payload}
        if owner_authorization is not None:
            body["owner_authorization"] = owner_authorization
        elif owner is not None:
            body["owner_authorization"] = await self._owner_authorization(owner, issue)
        return await self._request(
            ops.CREATE_MANDATE,
            Mandate,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def retrieve(
        self, mandate_id: str, *, request_options: RequestOptions | None = None
    ) -> Mandate:
        """Get a mandate, including cumulative ``spent`` under it."""
        return await self._request(
            ops.GET_MANDATE,
            Mandate,
            path_params={"id": mandate_id},
            request_options=request_options,
        )

    async def revoke(
        self, mandate_id: str, *, request_options: RequestOptions | None = None
    ) -> Mandate:
        """Revoke a mandate (a tightening change: immediate)."""
        return await self._request(
            ops.REVOKE_MANDATE,
            Mandate,
            path_params={"id": mandate_id},
            request_options=request_options,
        )
