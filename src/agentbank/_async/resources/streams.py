"""Payment streams: ``/v1/streams``."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal

from agentbank import _operations as ops
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._base_client import RequestOptions, new_idempotency_key
from agentbank._resource_helpers import compact, signature_idempotency_key
from agentbank._resource_helpers import payee as normalize_payee
from agentbank.errors import AgentBankError
from agentbank.models import Stream
from agentbank.money import MoneyInput, coerce_money

__all__ = ["AsyncStreams"]


class AsyncStreams(AsyncAPIResource):
    """Pre-funded per-second streams and recurring payments (``PaymentStreams``)."""

    async def create(
        self,
        *,
        payee: Mapping[str, Any] | str,
        amount_per_interval: MoneyInput,
        interval_seconds: int,
        deposit: MoneyInput,
        account_id: str | None = None,
        kind: Literal["streaming", "recurring"] | None = None,
        settle_every_seconds: int | None = None,
        start_at: datetime | str | None = None,
        stop_at: datetime | str | None = None,
        mandate_id: str | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Stream:
        """Create a stream (it still needs the session signature; see :meth:`start`).

        Args:
            payee: ``0x`` address, ``agt_`` agent id, or ``{"address"|"agent_id": ...}``.
            amount_per_interval: Amount streamed per interval.
            interval_seconds: Interval length (``1`` for per-second streaming).
            deposit: Amount pre-funded into the stream contract.
            account_id: Paying account (defaults to the client's ``account_id``).
            kind: ``streaming`` (default) or ``recurring``.
            settle_every_seconds: Settlement cadence (server default 3600, min 60).
            start_at: When streaming starts (default: now).
            stop_at: When streaming stops.
            mandate_id: Mandate the stream is created under.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        body = compact(
            account_id=self._account(account_id),
            payee=normalize_payee(payee),
            kind=kind,
            amount_per_interval=coerce_money(amount_per_interval),
            interval_seconds=interval_seconds,
            deposit=coerce_money(deposit),
            settle_every_seconds=settle_every_seconds,
            start_at=start_at,
            stop_at=stop_at,
            mandate_id=mandate_id,
        )
        return await self._request(
            ops.CREATE_STREAM,
            Stream,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def start(
        self,
        *,
        payee: Mapping[str, Any] | str,
        amount_per_interval: MoneyInput,
        interval_seconds: int,
        deposit: MoneyInput,
        account_id: str | None = None,
        kind: Literal["streaming", "recurring"] | None = None,
        settle_every_seconds: int | None = None,
        start_at: datetime | str | None = None,
        stop_at: datetime | str | None = None,
        mandate_id: str | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Stream:
        """Create a stream and sign its funding operation. Same arguments as :meth:`create`."""
        stream = await self.create(
            payee=payee,
            amount_per_interval=amount_per_interval,
            interval_seconds=interval_seconds,
            deposit=deposit,
            account_id=account_id,
            kind=kind,
            settle_every_seconds=settle_every_seconds,
            start_at=start_at,
            stop_at=stop_at,
            mandate_id=mandate_id,
            idempotency_key=idempotency_key or new_idempotency_key(),
            request_options=request_options,
        )
        if stream.signing_request is None:
            return stream
        return await self.sign_and_submit(stream, request_options=request_options)

    async def get(self, stream_id: str, *, request_options: RequestOptions | None = None) -> Stream:
        """Get a stream."""
        return await self._request(
            ops.GET_STREAM, Stream, path_params={"id": stream_id}, request_options=request_options
        )

    async def submit_signature(
        self,
        stream_id: str,
        *,
        signature: str,
        session_id: str | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Stream:
        """Submit the session-key signature for the pending stream operation."""
        body = compact(session_id=session_id or self._client.session_id, signature=signature)
        return await self._request(
            ops.SUBMIT_STREAM_SIGNATURE,
            Stream,
            path_params={"id": stream_id},
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def sign_and_submit(
        self, stream: Stream, *, request_options: RequestOptions | None = None
    ) -> Stream:
        """Sign the stream's pending ``signing_request`` with the session key and submit it."""
        if stream.signing_request is None:
            raise AgentBankError("invalid_state", f"Stream {stream.id} has nothing to sign")
        session_id, signature = self._client._sign_operation(stream.signing_request)
        return await self.submit_signature(
            stream.id,
            signature=signature,
            session_id=session_id,
            idempotency_key=signature_idempotency_key(stream.id, stream.signing_request),
            request_options=request_options,
        )

    async def cancel(
        self,
        stream_id: str,
        *,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Stream:
        """Cancel a stream: settle what has accrued and refund the remainder."""
        return await self._request(
            ops.CANCEL_STREAM,
            Stream,
            path_params={"id": stream_id},
            idempotency_key=idempotency_key,
            request_options=request_options,
        )
