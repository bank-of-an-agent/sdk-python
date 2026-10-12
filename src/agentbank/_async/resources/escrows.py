"""Escrow: ``/v1/escrows``."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal

from agentbank import _operations as ops
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._base_client import RequestOptions, new_idempotency_key
from agentbank._resource_helpers import (
    compact,
    has_pending_signature,
    pending_signing_request,
    signature_idempotency_key,
)
from agentbank._resource_helpers import payee as normalize_payee
from agentbank.errors import PaymentFailedError
from agentbank.models import Escrow
from agentbank.money import MoneyInput, coerce_money

__all__ = ["AsyncEscrows"]


class AsyncEscrows(AsyncAPIResource):
    """Funds locked in the ``AgentEscrow`` contract until released, refunded or resolved.

    Creating, releasing, refunding and disputing prepare an on-chain operation
    (``pending_action``) that the session key signs (``signing_request``), like
    payments; call :meth:`sign_and_submit` afterwards. :meth:`lock` creates and
    signs in one call.
    """

    async def create(
        self,
        *,
        payee: Mapping[str, Any] | str,
        amount: MoneyInput,
        expires_at: datetime | str,
        account_id: str | None = None,
        release: Literal["payer", "arbiter", "validator"] | None = None,
        arbiter: str | None = None,
        validator: Mapping[str, Any] | None = None,
        terms: str | None = None,
        memo: str | None = None,
        mandate_id: str | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Escrow:
        """Create an escrow (it still needs the session signature; see :meth:`lock`).

        Args:
            payee: ``0x`` address, ``agt_`` agent id, or ``{"address"|"agent_id": ...}``.
            amount: Decimal string (USDC), ``Decimal`` or ``Money``.
            expires_at: When the payer may reclaim the funds (timezone-aware).
            account_id: Paying account (defaults to the client's ``account_id``).
            release: Who releases: ``payer`` (default), ``arbiter`` or ``validator``.
            arbiter: Arbiter address when ``release="arbiter"``.
            validator: ``{registry, request_hash, min_response}`` for ERC-8004 validation.
            terms: Free-text terms; only their hash goes on-chain.
            memo: Free text.
            mandate_id: Mandate the escrow is created under.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        body = compact(
            account_id=self._account(account_id),
            payee=normalize_payee(payee),
            amount=coerce_money(amount),
            expires_at=expires_at,
            release=release,
            arbiter=arbiter,
            validator=validator,
            terms=terms,
            memo=memo,
            mandate_id=mandate_id,
        )
        return await self._request(
            ops.CREATE_ESCROW,
            Escrow,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def lock(
        self,
        *,
        payee: Mapping[str, Any] | str,
        amount: MoneyInput,
        expires_at: datetime | str,
        account_id: str | None = None,
        release: Literal["payer", "arbiter", "validator"] | None = None,
        arbiter: str | None = None,
        validator: Mapping[str, Any] | None = None,
        terms: str | None = None,
        memo: str | None = None,
        mandate_id: str | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Escrow:
        """Create an escrow and sign its lock operation with the session key.

        Takes the same arguments as :meth:`create`.
        """
        escrow = await self.create(
            payee=payee,
            amount=amount,
            expires_at=expires_at,
            account_id=account_id,
            release=release,
            arbiter=arbiter,
            validator=validator,
            terms=terms,
            memo=memo,
            mandate_id=mandate_id,
            idempotency_key=idempotency_key or new_idempotency_key(),
            request_options=request_options,
        )
        if escrow.status == "failed":
            raise PaymentFailedError(f"Escrow {escrow.id} failed", resource=escrow)
        if not has_pending_signature(escrow):
            return escrow
        return await self.sign_and_submit(escrow, request_options=request_options)

    async def retrieve(
        self, escrow_id: str, *, request_options: RequestOptions | None = None
    ) -> Escrow:
        """Get an escrow."""
        return await self._request(
            ops.GET_ESCROW, Escrow, path_params={"id": escrow_id}, request_options=request_options
        )

    async def submit_signature(
        self,
        escrow_id: str,
        *,
        signature: str,
        session_id: str | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Escrow:
        """Submit the session-key signature for the pending escrow operation."""
        body = compact(session_id=session_id or self._client.session_id, signature=signature)
        return await self._request(
            ops.SUBMIT_ESCROW_SIGNATURE,
            Escrow,
            path_params={"id": escrow_id},
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def sign_and_submit(
        self, escrow: Escrow, *, request_options: RequestOptions | None = None
    ) -> Escrow:
        """Sign the escrow's pending operation with the session key and submit it.

        Use it after :meth:`create`, :meth:`release`, :meth:`refund` or
        :meth:`dispute` when ``pending_action`` is set. Only an operation with a
        ``pending_action`` and an unexpired ``signing_request`` is signed.

        Raises:
            AgentBankError: ``invalid_state`` when nothing (unexpired) is pending.
            PaymentFailedError: The escrow failed on-chain.
        """
        if escrow.status == "failed":
            raise PaymentFailedError(f"Escrow {escrow.id} failed", resource=escrow)
        signing_request = pending_signing_request(escrow)
        session_id, signature = self._client._sign_operation(signing_request)
        return await self.submit_signature(
            escrow.id,
            signature=signature,
            session_id=session_id,
            idempotency_key=signature_idempotency_key(escrow.id, signing_request),
            request_options=request_options,
        )

    async def release(
        self,
        escrow_id: str,
        *,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Escrow:
        """Release escrowed funds to the payee (sign the returned ``signing_request``)."""
        return await self._request(
            ops.RELEASE_ESCROW,
            Escrow,
            path_params={"id": escrow_id},
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def refund(
        self,
        escrow_id: str,
        *,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Escrow:
        """Refund escrowed funds to the payer (payee any time, anyone after expiry)."""
        return await self._request(
            ops.REFUND_ESCROW,
            Escrow,
            path_params={"id": escrow_id},
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def dispute(
        self,
        escrow_id: str,
        *,
        reason: str,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Escrow:
        """Dispute an escrow before it expires; the arbiter decides."""
        return await self._request(
            ops.DISPUTE_ESCROW,
            Escrow,
            path_params={"id": escrow_id},
            body=compact(reason=reason),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )
