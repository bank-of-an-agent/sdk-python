"""Smart accounts and balances: ``/v1/agents/{id}/accounts``, ``/v1/accounts``."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Literal

from agentbank import _operations as ops
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank.models import Account, Balances, ListAccountsResponse

__all__ = ["AsyncAccounts"]

ChainName = Literal["base-sepolia", "anvil", "simulated"]


class AsyncAccounts(AsyncAPIResource):
    """One ERC-7579 smart account per agent per chain."""

    async def create(
        self,
        agent_id: str,
        *,
        chain: ChainName | None = None,
        spend_key_address: str | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Account:
        """Create the agent's smart account (counterfactual: it can receive funds at once).

        Args:
            agent_id: The agent that will own the account.
            chain: Chain name (server default ``"base-sepolia"``).
            spend_key_address: Address of the agent's x402 spend key, generated
                client-side with :func:`agentbank.generate_spend_key`.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        return await self._request(
            ops.CREATE_ACCOUNT,
            Account,
            path_params={"id": agent_id},
            body=compact(chain=chain, spend_key_address=spend_key_address),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def list(
        self,
        *,
        agent_id: str | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListAccountsResponse:
        """List accounts (one page), optionally for one agent."""
        return await self._request(
            ops.LIST_ACCOUNTS,
            ListAccountsResponse,
            query={"agent_id": agent_id, "cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    async def list_all(
        self,
        *,
        agent_id: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> AsyncIterator[Account]:
        """Iterate over every account, following ``next_cursor``."""
        async for page in self._paginate(
            ops.LIST_ACCOUNTS,
            ListAccountsResponse,
            query={"agent_id": agent_id, "limit": limit},
            request_options=request_options,
        ):
            for item in page.data:
                yield item

    async def get(
        self, account_id: str | None = None, *, request_options: RequestOptions | None = None
    ) -> Account:
        """Get an account (defaults to the client's ``account_id``)."""
        return await self._request(
            ops.GET_ACCOUNT,
            Account,
            path_params={"id": self._account(account_id)},
            request_options=request_options,
        )

    async def balances(
        self, account_id: str | None = None, *, request_options: RequestOptions | None = None
    ) -> Balances:
        """Get available, reserved, escrowed, saved and spend-float balances.

        Defaults to the client's ``account_id``. Amounts are decimal strings.
        """
        return await self._request(
            ops.GET_BALANCES,
            Balances,
            path_params={"id": self._account(account_id)},
            request_options=request_options,
        )
