# Generated from src/agentbank/_async/resources/orgs.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""Organizations (principals): ``/v1/orgs``."""

from __future__ import annotations

from typing import Any, Literal

from agentbank import _operations as ops
from agentbank import owner_payloads
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank._sync.resources._base import APIResource
from agentbank.keys import SessionKey, SignerLike
from agentbank.models import CreateOrgResponse, KybSession, Org

__all__ = ["Orgs"]


class Orgs(APIResource):
    """The principal's organization: creation, KYC/KYB, freeze and unfreeze."""

    def create(
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
        return self._request(
            ops.CREATE_ORG,
            CreateOrgResponse,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def retrieve(self, *, request_options: RequestOptions | None = None) -> Org:
        """Get the org the API key belongs to (``GET /v1/orgs/me``)."""
        return self._request(ops.GET_CURRENT_ORG, Org, request_options=request_options)

    def start_kyb(
        self,
        *,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> KybSession:
        """Start or resume KYC/KYB verification; follow ``verification_url`` to complete it."""
        return self._request(
            ops.START_KYB,
            KybSession,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def freeze(
        self,
        *,
        reason: str,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Org:
        """Freeze every agent in the org immediately (a tightening change).

        The co-signer refuses every operation for the org until it is unfrozen.
        """
        return self._request(
            ops.FREEZE_ORG,
            Org,
            body=compact(reason=reason),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def unfreeze(
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
            owner_authorization: A pre-signed ``org.unfreeze`` authorization
                (subject = the org id, payload ``{"reason": reason}``).
            owner: Alternatively, the owner key; the SDK looks up the org id and
                signs it.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        body: dict[str, Any] = {"reason": reason}
        if owner_authorization is not None:
            body["owner_authorization"] = owner_authorization
        elif owner is not None:
            org = self.retrieve(request_options=request_options)
            unfreeze = owner_payloads.org_unfreeze(org.id, reason)
            body["owner_authorization"] = self._owner_authorization(owner, unfreeze)
        return self._request(
            ops.UNFREEZE_ORG,
            Org,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def rotate_owner(
        self,
        *,
        new_owner_address: str,
        owner_authorization: dict[str, Any] | None = None,
        owner: SignerLike | SessionKey | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Org:
        """Rotate the org's owner key in Agent Bank and the co-signer (``owner.rotate``).

        Signed by the **current** owner key. Order matters: first swap the owner of
        every account with ``owner_operations.prepare_owner_swap`` (signed with the
        old key), then call this. Lost keys are recovered on-chain with guardians
        instead.

        Args:
            new_owner_address: The new owner key's address.
            owner_authorization: A pre-signed ``owner.rotate`` authorization
                (subject = the org id, payload ``{"new_owner_address": ...}``).
            owner: Alternatively, the current owner key; the SDK looks up the org id
                and signs it.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        body: dict[str, Any] = {"new_owner_address": new_owner_address}
        if owner_authorization is not None:
            body["owner_authorization"] = owner_authorization
        elif owner is not None:
            org = self.retrieve(request_options=request_options)
            rotation = owner_payloads.owner_rotate(org.id, new_owner_address)
            body["owner_authorization"] = self._owner_authorization(owner, rotation)
        return self._request(
            ops.ROTATE_OWNER,
            Org,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )
