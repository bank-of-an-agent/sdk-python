# Generated from src/agentbank/_async/resources/ledger.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""Ledger entries and statements: ``/v1/accounts/{id}/entries``, ``/v1/statements``."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Literal, overload

from agentbank import _operations as ops
from agentbank._base_client import RequestOptions
from agentbank._sync.resources._base import APIResource
from agentbank.models import LedgerEntry, ListEntriesResponse, Statement

__all__ = ["Ledger"]


class Ledger(APIResource):
    """The double-entry ledger: immutable, balanced journal entries."""

    def list_entries(
        self,
        account_id: str | None = None,
        *,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListEntriesResponse:
        """List ledger entries touching an account (one page).

        Defaults to the client's ``account_id``.
        """
        return self._request(
            ops.LIST_ENTRIES,
            ListEntriesResponse,
            path_params={"id": self._account(account_id)},
            query={"cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    def list_entries_all(
        self,
        account_id: str | None = None,
        *,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> Iterator[LedgerEntry]:
        """Iterate over every ledger entry of an account, following ``next_cursor``."""
        for page in self._paginate(
            ops.LIST_ENTRIES,
            ListEntriesResponse,
            path_params={"id": self._account(account_id)},
            query={"limit": limit},
            request_options=request_options,
        ):
            yield from page.data

    @overload
    def statement(
        self,
        *,
        period: str,
        account_id: str | None = ...,
        format: Literal["json"] = ...,
        request_options: RequestOptions | None = ...,
    ) -> Statement: ...

    @overload
    def statement(
        self,
        *,
        period: str,
        account_id: str | None = ...,
        format: Literal["csv"],
        request_options: RequestOptions | None = ...,
    ) -> str: ...

    def statement(
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
            return self._client._request_text(
                ops.GET_STATEMENT,
                query=query,
                accept="text/csv",
                request_options=request_options,
            )
        return self._request(
            ops.GET_STATEMENT, Statement, query=query, request_options=request_options
        )
