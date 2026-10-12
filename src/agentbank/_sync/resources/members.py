# Generated from src/agentbank/_async/resources/members.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""Org members: ``/v1/members``."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Literal

from agentbank import _operations as ops
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank._sync.resources._base import APIResource
from agentbank.models import ListMembersResponse, Member

__all__ = ["Members"]


class Members(APIResource):
    """People in the org: admins, approvers and viewers."""

    def list(
        self,
        *,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListMembersResponse:
        """List members (one page)."""
        return self._request(
            ops.LIST_MEMBERS,
            ListMembersResponse,
            query={"cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    def list_all(
        self, *, limit: int | None = None, request_options: RequestOptions | None = None
    ) -> Iterator[Member]:
        """Iterate over every member, following ``next_cursor``."""
        for page in self._paginate(
            ops.LIST_MEMBERS,
            ListMembersResponse,
            query={"limit": limit},
            request_options=request_options,
        ):
            yield from page.data

    def create(
        self,
        *,
        email: str,
        role: Literal["admin", "approver", "viewer"],
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Member:
        """Invite a member with a role (``admin``, ``approver`` or ``viewer``)."""
        return self._request(
            ops.CREATE_MEMBER,
            Member,
            body=compact(email=email, role=role),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )
