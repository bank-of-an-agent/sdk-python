"""Org API keys: ``/v1/api-keys``."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence

from agentbank import _operations as ops
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank.models import ApiKey, ApiKeyWithSecret, ListApiKeysResponse

__all__ = ["AsyncApiKeys"]


class AsyncApiKeys(AsyncAPIResource):
    """API keys authenticate principals (``Authorization: Bearer abk_test_...``)."""

    async def list(
        self,
        *,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListApiKeysResponse:
        """List API keys (one page)."""
        return await self._request(
            ops.LIST_API_KEYS,
            ListApiKeysResponse,
            query={"cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    async def list_all(
        self, *, limit: int | None = None, request_options: RequestOptions | None = None
    ) -> AsyncIterator[ApiKey]:
        """Iterate over every API key, following ``next_cursor``."""
        async for page in self._paginate(
            ops.LIST_API_KEYS,
            ListApiKeysResponse,
            query={"limit": limit},
            request_options=request_options,
        ):
            for item in page.data:
                yield item

    async def create(
        self,
        *,
        name: str,
        scopes: Sequence[str] | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> ApiKeyWithSecret:
        """Create an API key. The ``secret`` is returned once: store it in a secret manager.

        Args:
            name: Display name.
            scopes: Any of ``admin``, ``agents:write``, ``payments:read``,
                ``approvals:decide``, ``ledger:read``, ``webhooks:write``
                (server default: ``["admin"]``).
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        return await self._request(
            ops.CREATE_API_KEY,
            ApiKeyWithSecret,
            body=compact(name=name, scopes=list(scopes) if scopes is not None else None),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def revoke(
        self, api_key_id: str, *, request_options: RequestOptions | None = None
    ) -> ApiKey:
        """Revoke an API key immediately."""
        return await self._request(
            ops.REVOKE_API_KEY,
            ApiKey,
            path_params={"id": api_key_id},
            request_options=request_options,
        )
