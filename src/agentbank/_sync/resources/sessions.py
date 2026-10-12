# Generated from src/agentbank/_async/resources/sessions.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""Session keys: ``/v1/sessions``."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agentbank import _operations as ops
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank._sync.resources._base import APIResource
from agentbank.keys import SessionKey, SignerLike
from agentbank.models import Session, SessionScope

__all__ = ["Sessions"]


class Sessions(APIResource):
    """Short-lived, scoped agent keys. A session key is useless without the co-signer."""

    def create(
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

        The owner authorizes the grant with an EIP-712 ``session.grant`` over
        ``{account_id, public_key, scope}`` (subject = ``account_id``). Then call
        :meth:`install` and have the owner sign the returned owner operation.

        Args:
            account_id: The agent's account.
            public_key: The session key *address* (from :func:`agentbank.generate_session_key`).
            scope: ``max_per_tx``, ``max_per_day``, ``expires_at`` and optional
                ``allowed_recipients``/``allowed_contracts`` (enforced on-chain).
            owner_authorization: A pre-signed ``session.grant`` authorization over
                exactly ``{"account_id", "public_key", "scope"}`` as sent.
            owner: Alternatively, the owner key; the SDK builds and signs the grant.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        body = compact(account_id=account_id, public_key=public_key, scope=scope)
        if owner_authorization is not None:
            body["owner_authorization"] = owner_authorization
        elif owner is not None:
            body["owner_authorization"] = self._owner_authorization(
                owner, "session.grant", account_id, dict(body)
            )
        return self._request(
            ops.CREATE_SESSION,
            Session,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def get(self, session_id: str, *, request_options: RequestOptions | None = None) -> Session:
        """Get a session (principal, or the agent holding it)."""
        return self._request(
            ops.GET_SESSION,
            Session,
            path_params={"id": session_id},
            request_options=request_options,
        )

    def revoke(self, session_id: str, *, request_options: RequestOptions | None = None) -> Session:
        """Revoke a session key off-chain (immediate: the co-signer refuses it).

        The owner should also revoke it on-chain as the hard backstop.
        """
        return self._request(
            ops.REVOKE_SESSION,
            Session,
            path_params={"id": session_id},
            request_options=request_options,
        )

    def install(
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
        return self._request(
            ops.INSTALL_SESSION,
            Session,
            path_params={"id": session_id},
            idempotency_key=idempotency_key,
            request_options=request_options,
        )
