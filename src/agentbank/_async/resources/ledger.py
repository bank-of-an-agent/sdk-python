"""Ledger entries and statements: ``/v1/accounts/{id}/entries``, ``/v1/statements``."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Literal, overload

from agentbank import _operations as ops
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._base_client import RequestOptions
from agentbank.models import LedgerEntry, ListEntriesResponse, Statement

__all__ = ["AsyncLedger"]


class AsyncLedger(AsyncAPIResource):
    """The double-entry ledger: immutable, balanced journal entries."""

    async def list_entries(
        self,
        account_id: str | None = None,
        *,
        payment_id: str | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListEntriesResponse:
        """List ledger entries touching an account (one page), optionally for one payment.

        Defaults to the client's ``account_id``.
        """
        return await self._request(
            ops.LIST_ENTRIES,
            ListEntriesResponse,
            path_params={"id": self._account(account_id)},
            query={"payment_id": payment_id, "cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    async def list_entries_all(
        self,
        account_id: str | None = None,
        *,
        payment_id: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> AsyncIterator[LedgerEntry]:
        """Iterate over every ledger entry of an account, following ``next_cursor``."""
        async for page in self._paginate(
            ops.LIST_ENTRIES,
            ListEntriesResponse,
            path_params={"id": self._account(account_id)},
            query={"payment_id": payment_id, "limit": limit},
            request_options=request_options,
        ):
            for item in page.data:
                yield item

    @overload
    async def statement(
        self,
        *,
        period: str,
        account_id: str | None = ...,
        format: Literal["json"] = ...,
        request_options: RequestOptions | None = ...,
    ) -> Statement: ...

    @overload
    async def statement(
        self,
        *,
        period: str,
        account_id: str | None = ...,
        format: Literal["csv"],
        request_options: RequestOptions | None = ...,
    ) -> str: ...

    async def statement(
        self,
        *,
        period: str,
        account_id: str | None = None,
        format: Literal["json", "csv"] = "json",
        request_options: RequestOptions | None = None,
    ) -> Statement | str:
        """Get a monthly statement generated from the ledger.

        Args:
            period: ``YYYY-MM``.
            account_id: The account (defaults to the client's ``account_id``).
            format: ``"json"`` (a :class:`~agentbank.models.Statement`) or
                ``"csv"`` (the CSV text).
            request_options: Per-request overrides.
        """
        query = {"account_id": self._account(account_id), "period": period, "format": format}
        if format == "csv":
            return await self._client._request_text(
                ops.GET_STATEMENT,
                query=query,
                accept="text/csv",
                request_options=request_options,
            )
        return await self._request(
            ops.GET_STATEMENT, Statement, query=query, request_options=request_options
        )
