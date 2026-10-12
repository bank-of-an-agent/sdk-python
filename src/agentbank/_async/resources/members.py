"""Org members: ``/v1/members``."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Literal

from agentbank import _operations as ops
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank.models import ListMembersResponse, Member

__all__ = ["AsyncMembers"]


class AsyncMembers(AsyncAPIResource):
    """People in the org: admins, approvers and viewers."""

    async def list(
        self,
        *,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListMembersResponse:
        """List members (one page)."""
        return await self._request(
            ops.LIST_MEMBERS,
            ListMembersResponse,
            query={"cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    async def list_all(
        self, *, limit: int | None = None, request_options: RequestOptions | None = None
    ) -> AsyncIterator[Member]:
        """Iterate over every member, following ``next_cursor``."""
        async for page in self._paginate(
            ops.LIST_MEMBERS,
            ListMembersResponse,
            query={"limit": limit},
            request_options=request_options,
        ):
            for item in page.data:
                yield item

    async def create(
        self,
        *,
        email: str,
        role: Literal["admin", "approver", "viewer"],
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Member:
        """Invite a member with a role (``admin``, ``approver`` or ``viewer``)."""
        return await self._request(
            ops.CREATE_MEMBER,
            Member,
            body=compact(email=email, role=role),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )
