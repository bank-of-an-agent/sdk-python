# Generated from src/agentbank/_async/resources/escrows.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""Escrow: ``/v1/escrows``."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal

from agentbank import _operations as ops
from agentbank._base_client import RequestOptions, new_idempotency_key
from agentbank._resource_helpers import compact, signature_idempotency_key
from agentbank._resource_helpers import payee as normalize_payee
from agentbank._sync.resources._base import APIResource
from agentbank.errors import AgentBankError
from agentbank.models import Escrow
from agentbank.money import MoneyInput, coerce_money

__all__ = ["Escrows"]


class Escrows(APIResource):
    """Funds locked in the ``AgentEscrow`` contract until released, refunded or resolved.

    Creating, releasing, refunding and disputing prepare an on-chain operation
    that the session key signs (``signing_request``), like payments.
    :meth:`lock` creates and signs in one call.
    """

    def create(
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
        return self._request(
            ops.CREATE_ESCROW,
            Escrow,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def lock(
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
        escrow = self.create(
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
        if escrow.signing_request is None:
            return escrow
        return self.sign_and_submit(escrow, request_options=request_options)

    def get(self, escrow_id: str, *, request_options: RequestOptions | None = None) -> Escrow:
        """Get an escrow."""
        return self._request(
            ops.GET_ESCROW, Escrow, path_params={"id": escrow_id}, request_options=request_options
        )

    def submit_signature(
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
        return self._request(
            ops.SUBMIT_ESCROW_SIGNATURE,
            Escrow,
            path_params={"id": escrow_id},
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def sign_and_submit(
        self, escrow: Escrow, *, request_options: RequestOptions | None = None
    ) -> Escrow:
        """Sign the escrow's pending ``signing_request`` with the session key and submit it."""
        if escrow.signing_request is None:
            raise AgentBankError("invalid_state", f"Escrow {escrow.id} has nothing to sign")
        session_id, signature = self._client._sign_operation(escrow.signing_request)
        return self.submit_signature(
            escrow.id,
            signature=signature,
            session_id=session_id,
            idempotency_key=signature_idempotency_key(escrow.id, escrow.signing_request),
            request_options=request_options,
        )

    def release(
        self,
        escrow_id: str,
        *,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Escrow:
        """Release escrowed funds to the payee (sign the returned ``signing_request``)."""
        return self._request(
            ops.RELEASE_ESCROW,
            Escrow,
            path_params={"id": escrow_id},
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def refund(
        self,
        escrow_id: str,
        *,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Escrow:
        """Refund escrowed funds to the payer (payee any time, anyone after expiry)."""
        return self._request(
            ops.REFUND_ESCROW,
            Escrow,
            path_params={"id": escrow_id},
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def dispute(
        self,
        escrow_id: str,
        *,
        reason: str,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Escrow:
        """Dispute an escrow before it expires; the arbiter decides."""
        return self._request(
            ops.DISPUTE_ESCROW,
            Escrow,
            path_params={"id": escrow_id},
            body=compact(reason=reason),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )
