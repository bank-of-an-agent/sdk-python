"""Organizations (principals): ``/v1/orgs``."""

from __future__ import annotations

from typing import Any, Literal

from agentbank import _operations as ops
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact, without_owner_authorization
from agentbank.keys import SessionKey, SignerLike
from agentbank.models import CreateOrgResponse, KybSession, Org

__all__ = ["AsyncOrgs"]


class AsyncOrgs(AsyncAPIResource):
    """The principal's organization: creation, KYC/KYB, freeze and unfreeze."""

    async def create(
        self,
        *,
        legal_name: str,
        kind: Literal["individual", "company"],
        country: str,
        contact_email: str,
        owner_address: str,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> CreateOrgResponse:
        """Create an organization and its first admin API key (public endpoint).

        Args:
            legal_name: Legal name of the person or company.
            kind: ``"individual"`` or ``"company"``.
            country: ISO 3166-1 alpha-2 country code.
            contact_email: Contact email for the principal.
            owner_address: The principal's owner key address. Agent Bank never holds it.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.

        Returns:
            The org and the admin API key (``api_key.secret`` is shown only once).
        """
        body = compact(
            legal_name=legal_name,
            kind=kind,
            country=country,
            contact_email=contact_email,
            owner_address=owner_address,
        )
        return await self._request(
            ops.CREATE_ORG,
            CreateOrgResponse,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def me(self, *, request_options: RequestOptions | None = None) -> Org:
        """Get the org the API key belongs to."""
        return await self._request(ops.GET_CURRENT_ORG, Org, request_options=request_options)

    async def start_kyb(
        self,
        *,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> KybSession:
        """Start or resume KYC/KYB verification; follow ``verification_url`` to complete it."""
        return await self._request(
            ops.START_KYB,
            KybSession,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def freeze(
        self,
        *,
        reason: str,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Org:
        """Freeze every agent in the org immediately (a tightening change).

        The co-signer refuses every operation for the org until it is unfrozen.
        """
        return await self._request(
            ops.FREEZE_ORG,
            Org,
            body=compact(reason=reason),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def unfreeze(
        self,
        *,
        reason: str,
        owner_authorization: dict[str, Any] | None = None,
        owner: SignerLike | SessionKey | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Org:
        """Unfreeze the org (a loosening change: owner signature plus a 1-hour delay).

        Args:
            reason: Why the org is being unfrozen.
            owner_authorization: A pre-signed ``org.unfreeze`` authorization.
            owner: Alternatively, the owner key; the SDK signs ``org.unfreeze`` with
                subject = the org id and payload ``{"reason": reason}``.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        body = compact(reason=reason, owner_authorization=owner_authorization)
        if owner_authorization is None and owner is not None:
            org = await self.me(request_options=request_options)
            body["owner_authorization"] = self._owner_authorization(
                owner, "org.unfreeze", org.id, without_owner_authorization(body)
            )
        return await self._request(
            ops.UNFREEZE_ORG,
            Org,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )
