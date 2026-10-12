# Generated from src/agentbank/_async/resources/agents.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""Agents: ``/v1/agents``."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any, Literal

from agentbank import _operations as ops
from agentbank import owner_payloads
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank._sync.resources._base import APIResource
from agentbank.keys import SessionKey, SignerLike
from agentbank.models import Agent, ListAgentsResponse

__all__ = ["Agents"]


class Agents(APIResource):
    """Software identities acting for the principal."""

    def create(
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
        return self._request(
            ops.CREATE_AGENT,
            Agent,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def list(
        self,
        *,
        status: Literal["active", "frozen"] | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListAgentsResponse:
        """List agents (one page), optionally filtered by status."""
        return self._request(
            ops.LIST_AGENTS,
            ListAgentsResponse,
            query={"status": status, "cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    def list_all(
        self,
        *,
        status: Literal["active", "frozen"] | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> Iterator[Agent]:
        """Iterate over every agent, following ``next_cursor``."""
        for page in self._paginate(
            ops.LIST_AGENTS,
            ListAgentsResponse,
            query={"status": status, "limit": limit},
            request_options=request_options,
        ):
            yield from page.data

    def retrieve(self, agent_id: str, *, request_options: RequestOptions | None = None) -> Agent:
        """Get an agent (principal, or the agent itself)."""
        return self._request(
            ops.GET_AGENT, Agent, path_params={"id": agent_id}, request_options=request_options
        )

    def freeze(
        self,
        agent_id: str,
        *,
        reason: str,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Agent:
        """Freeze an agent immediately; the co-signer refuses all its operations."""
        return self._request(
            ops.FREEZE_AGENT,
            Agent,
            path_params={"id": agent_id},
            body=compact(reason=reason),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def unfreeze(
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
            owner_authorization: A pre-signed ``agent.unfreeze`` authorization
                (subject = ``agent_id``, payload ``{"reason": reason}``).
            owner: Alternatively, the owner key; the SDK signs it.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        unfreeze = owner_payloads.agent_unfreeze(agent_id, reason)
        body: dict[str, Any] = dict(unfreeze.payload)
        if owner_authorization is not None:
            body["owner_authorization"] = owner_authorization
        elif owner is not None:
            body["owner_authorization"] = self._owner_authorization(owner, unfreeze)
        return self._request(
            ops.UNFREEZE_AGENT,
            Agent,
            path_params={"id": agent_id},
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )
