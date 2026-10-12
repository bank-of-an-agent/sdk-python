"""Session keys: ``/v1/sessions``."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Any, Literal

from agentbank import _operations as ops
from agentbank import owner_payloads
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._base_client import RequestOptions
from agentbank.keys import SessionKey, SignerLike
from agentbank.models import ListSessionsResponse, Session, SessionScope

__all__ = ["AsyncSessions"]

SessionStatus = Literal["pending_install", "active", "expired", "revoked"]


class AsyncSessions(AsyncAPIResource):
    """Short-lived, scoped agent keys. A session key is useless without the co-signer."""

    async def list(
        self,
        *,
        account_id: str | None = None,
        agent_id: str | None = None,
        status: SessionStatus | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListSessionsResponse:
        """List sessions (one page)."""
        return await self._request(
            ops.LIST_SESSIONS,
            ListSessionsResponse,
            query={
                "account_id": account_id,
                "agent_id": agent_id,
                "status": status,
                "cursor": cursor,
                "limit": limit,
            },
            request_options=request_options,
        )

    async def list_all(
        self,
        *,
        account_id: str | None = None,
        agent_id: str | None = None,
        status: SessionStatus | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> AsyncIterator[Session]:
        """List sessions: iterate over every page, following ``next_cursor``."""
        async for page in self._paginate(
            ops.LIST_SESSIONS,
            ListSessionsResponse,
            query={
                "account_id": account_id,
                "agent_id": agent_id,
                "status": status,
                "limit": limit,
            },
            request_options=request_options,
        ):
            for item in page.data:
                yield item

    async def create(
        self,
        *,
        account_id: str,
        public_key: str,
        scope: SessionScope | Mapping[str, Any],
        owner_authorization: dict[str, Any] | None = None,
        owner: SignerLike | SessionKey | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Session:
        """Register a session key and its on-chain scope.

        The owner authorizes the grant with an EIP-712 ``session.grant``
        (subject = ``account_id``) over ``{account_id, public_key, scope}`` with
        the scope's defaults made explicit (see
        :func:`agentbank.owner_payloads.session_grant`, which builds exactly the
        body sent here). Then call :meth:`install` and have the owner sign the
        returned owner operation.

        Args:
            account_id: The agent's account.
            public_key: The session key *address* (from :func:`agentbank.generate_session_key`).
            scope: ``max_per_tx``, ``max_per_day``, ``expires_at`` and optional
                ``asset``, ``allowed_recipients``, ``allowed_contracts`` (enforced on-chain).
            owner_authorization: A pre-signed ``session.grant`` authorization.
            owner: Alternatively, the owner key; the SDK signs the grant in the
                deployment's EIP-712 domain (chain id from ``GET /v1/meta``).
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        grant = owner_payloads.session_grant(
            account_id=account_id, public_key=public_key, scope=scope
        )
        body: dict[str, Any] = dict(grant.payload)
        if owner_authorization is not None:
            body["owner_authorization"] = owner_authorization
        elif owner is not None:
            body["owner_authorization"] = await self._owner_authorization(owner, grant)
        return await self._request(
            ops.CREATE_SESSION,
            Session,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def retrieve(
        self, session_id: str, *, request_options: RequestOptions | None = None
    ) -> Session:
        """Get a session (principal, or the agent holding it)."""
        return await self._request(
            ops.GET_SESSION,
            Session,
            path_params={"id": session_id},
            request_options=request_options,
        )

    async def revoke(
        self, session_id: str, *, request_options: RequestOptions | None = None
    ) -> Session:
        """Revoke a session key off-chain (immediate: the co-signer refuses it).

        The owner should also revoke it on-chain as the hard backstop.
        """
        return await self._request(
            ops.REVOKE_SESSION,
            Session,
            path_params={"id": session_id},
            request_options=request_options,
        )

    async def install(
        self,
        session_id: str,
        *,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Session:
        """Prepare the owner operation that installs the session on-chain.

        The returned session has ``install_operation_id``; sign it with
        ``owner_operations.sign_and_submit(session.install_operation_id, owner=...)``.
        """
        return await self._request(
            ops.INSTALL_SESSION,
            Session,
            path_params={"id": session_id},
            idempotency_key=idempotency_key,
            request_options=request_options,
        )
