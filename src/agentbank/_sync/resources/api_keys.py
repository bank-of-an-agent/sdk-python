# Generated from src/agentbank/_async/resources/api_keys.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""Org API keys: ``/v1/api-keys``."""

from __future__ import annotations

from collections.abc import Iterator, Sequence

from agentbank import _operations as ops
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank._sync.resources._base import APIResource
from agentbank.models import ApiKey, ApiKeyWithSecret, ListApiKeysResponse

__all__ = ["ApiKeys"]


class ApiKeys(APIResource):
    """API keys authenticate principals (``Authorization: Bearer abk_test_...``)."""

    def list(
        self,
        *,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListApiKeysResponse:
        """List API keys (one page)."""
        return self._request(
            ops.LIST_API_KEYS,
            ListApiKeysResponse,
            query={"cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    def list_all(
        self, *, limit: int | None = None, request_options: RequestOptions | None = None
    ) -> Iterator[ApiKey]:
        """Iterate over every API key, following ``next_cursor``."""
        for page in self._paginate(
            ops.LIST_API_KEYS,
            ListApiKeysResponse,
            query={"limit": limit},
            request_options=request_options,
        ):
            yield from page.data

    def create(
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
        return self._request(
            ops.CREATE_API_KEY,
            ApiKeyWithSecret,
            body=compact(name=name, scopes=list(scopes) if scopes is not None else None),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def revoke(self, api_key_id: str, *, request_options: RequestOptions | None = None) -> ApiKey:
        """Revoke an API key immediately."""
        return self._request(
            ops.REVOKE_API_KEY,
            ApiKey,
            path_params={"id": api_key_id},
            request_options=request_options,
        )
