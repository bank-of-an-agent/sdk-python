# Generated from src/agentbank/_async/resources/streams.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""Payment streams: ``/v1/streams``."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from datetime import datetime
from typing import Any, Literal

from agentbank import _operations as ops
from agentbank._base_client import RequestOptions, new_idempotency_key
from agentbank._resource_helpers import (
    compact,
    has_pending_signature,
    pending_signing_request,
    signature_idempotency_key,
)
from agentbank._resource_helpers import payee as normalize_payee
from agentbank._sync.resources._base import APIResource
from agentbank.errors import PaymentFailedError
from agentbank.models import ListStreamsResponse, Stream
from agentbank.money import MoneyInput, coerce_money

__all__ = ["Streams"]

StreamStatus = Literal["requires_signature", "active", "paused", "completed", "canceled", "failed"]


class Streams(APIResource):
    """Pre-funded per-second streams and recurring payments (``PaymentStreams``)."""

    def list(
        self,
        *,
        account_id: str | None = None,
        status: StreamStatus | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListStreamsResponse:
        """List streams (one page)."""
        return self._request(
            ops.LIST_STREAMS,
            ListStreamsResponse,
            query={"account_id": account_id, "status": status, "cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    def list_all(
        self,
        *,
        account_id: str | None = None,
        status: StreamStatus | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> Iterator[Stream]:
        """List streams: iterate over every page, following ``next_cursor``."""
        for page in self._paginate(
            ops.LIST_STREAMS,
            ListStreamsResponse,
            query={"account_id": account_id, "status": status, "limit": limit},
            request_options=request_options,
        ):
            yield from page.data

    def create(
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
        return self._request(
            ops.CREATE_STREAM,
            Stream,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def start(
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
        stream = self.create(
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
        if stream.status == "failed":
            raise PaymentFailedError(f"Stream {stream.id} failed", resource=stream)
        if not has_pending_signature(stream):
            return stream
        return self.sign_and_submit(stream, request_options=request_options)

    def retrieve(self, stream_id: str, *, request_options: RequestOptions | None = None) -> Stream:
        """Get a stream."""
        return self._request(
            ops.GET_STREAM, Stream, path_params={"id": stream_id}, request_options=request_options
        )

    def submit_signature(
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
        return self._request(
            ops.SUBMIT_STREAM_SIGNATURE,
            Stream,
            path_params={"id": stream_id},
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def sign_and_submit(
        self, stream: Stream, *, request_options: RequestOptions | None = None
    ) -> Stream:
        """Sign the stream's pending operation with the session key and submit it.

        Use it after :meth:`create` or :meth:`cancel` when ``pending_action`` is
        set. Only an operation with a ``pending_action`` and an unexpired
        ``signing_request`` is signed.

        Raises:
            AgentBankError: ``invalid_state`` when nothing (unexpired) is pending.
            PaymentFailedError: The stream failed on-chain.
        """
        if stream.status == "failed":
            raise PaymentFailedError(f"Stream {stream.id} failed", resource=stream)
        signing_request = pending_signing_request(stream)
        session_id, signature = self._client._sign_operation(signing_request)
        return self.submit_signature(
            stream.id,
            signature=signature,
            session_id=session_id,
            idempotency_key=signature_idempotency_key(stream.id, signing_request),
            request_options=request_options,
        )

    def cancel(
        self,
        stream_id: str,
        *,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Stream:
        """Cancel a stream: settle what has accrued and refund the remainder."""
        return self._request(
            ops.CANCEL_STREAM,
            Stream,
            path_params={"id": stream_id},
            idempotency_key=idempotency_key,
            request_options=request_options,
        )
