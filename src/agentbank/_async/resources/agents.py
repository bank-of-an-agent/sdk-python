"""Agents: ``/v1/agents``."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Any, Literal

from agentbank import _operations as ops
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact, without_owner_authorization
from agentbank.keys import SessionKey, SignerLike
from agentbank.models import Agent, ListAgentsResponse

__all__ = ["AsyncAgents"]


class AsyncAgents(AsyncAPIResource):
    """Software identities acting for the principal."""

    async def create(
        self,
        *,
        name: str,
        description: str | None = None,
        erc8004_id: str | None = None,
        agent_card_url: str | None = None,
        metadata: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Agent:
        """Create an agent.

        Args:
            name: Display name (1-100 characters).
            description: What the agent does.
            erc8004_id: Optional ERC-8004 identity registration.
            agent_card_url: URL of the agent card listing its endpoints.
            metadata: Up to 20 string key/value pairs for your own references.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        body = compact(
            name=name,
            description=description,
            erc8004_id=erc8004_id,
            agent_card_url=agent_card_url,
            metadata=metadata,
        )
        return await self._request(
            ops.CREATE_AGENT,
            Agent,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def list(
        self,
        *,
        status: Literal["active", "frozen"] | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListAgentsResponse:
        """List agents (one page), optionally filtered by status."""
        return await self._request(
            ops.LIST_AGENTS,
            ListAgentsResponse,
            query={"status": status, "cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    async def list_all(
        self,
        *,
        status: Literal["active", "frozen"] | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> AsyncIterator[Agent]:
        """Iterate over every agent, following ``next_cursor``."""
        async for page in self._paginate(
            ops.LIST_AGENTS,
            ListAgentsResponse,
            query={"status": status, "limit": limit},
            request_options=request_options,
        ):
            for item in page.data:
                yield item

    async def get(self, agent_id: str, *, request_options: RequestOptions | None = None) -> Agent:
        """Get an agent (principal, or the agent itself)."""
        return await self._request(
            ops.GET_AGENT, Agent, path_params={"id": agent_id}, request_options=request_options
        )

    async def freeze(
        self,
        agent_id: str,
        *,
        reason: str,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Agent:
        """Freeze an agent immediately; the co-signer refuses all its operations."""
        return await self._request(
            ops.FREEZE_AGENT,
            Agent,
            path_params={"id": agent_id},
            body=compact(reason=reason),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def unfreeze(
        self,
        agent_id: str,
        *,
        reason: str,
        owner_authorization: dict[str, Any] | None = None,
        owner: SignerLike | SessionKey | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Agent:
        """Unfreeze an agent (owner signature plus a 1-hour delay).

        Args:
            agent_id: The agent.
            reason: Why the agent is being unfrozen.
            owner_authorization: A pre-signed ``agent.unfreeze`` authorization.
            owner: Alternatively, the owner key; the SDK signs ``agent.unfreeze``
                with subject = ``agent_id`` and payload ``{"reason": reason}``.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        body = compact(reason=reason, owner_authorization=owner_authorization)
        if owner_authorization is None and owner is not None:
            body["owner_authorization"] = self._owner_authorization(
                owner, "agent.unfreeze", agent_id, without_owner_authorization(body)
            )
        return await self._request(
            ops.UNFREEZE_AGENT,
            Agent,
            path_params={"id": agent_id},
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )
