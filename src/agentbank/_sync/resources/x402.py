# Generated from src/agentbank/_async/resources/x402.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""x402 pay-per-call: ``/v1/x402/*`` plus an x402-aware HTTP client."""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from decimal import Decimal
from typing import Any

import httpx

from agentbank import _operations as ops
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank._sync.resources._base import APIResource
from agentbank._sync.x402 import X402Transport
from agentbank.keys import SessionKey, SignerLike
from agentbank.models import (
    X402Payee,
    X402PaymentPayload,
    X402PaymentRequirements,
    X402PayResponse,
    X402ResourceInfo,
    X402SettleResponse,
    X402SupportedResponse,
    X402VerifyResponse,
)

__all__ = ["X402"]


class X402(APIResource):
    """Pay for HTTP resources per call (buyer) and charge per call (seller)."""

    def pay(
        self,
        *,
        resource: X402ResourceInfo | Mapping[str, Any],
        requirements: X402PaymentRequirements | Mapping[str, Any],
        account_id: str | None = None,
        mandate_id: str | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> X402PayResponse:
        """Ask Agent Bank to authorize an x402 payment within policy (agent auth).

        Most agents use :meth:`client` or :meth:`fetch` instead, which call this
        on every 402 response and sign the returned EIP-3009 authorization.

        Args:
            resource: ``{"url": ..., "description": ..., "mimeType": ...}``.
            requirements: The chosen x402 v2 ``PaymentRequirements``.
            account_id: Paying account (defaults to the client's ``account_id``).
            mandate_id: Mandate to pay under.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.

        Returns:
            The x402 payment and, when policy allows, the authorization for the
            spend key to sign (``authorization`` is ``None`` otherwise).
        """
        body = compact(
            account_id=self._account(account_id),
            resource=resource,
            requirements=requirements,
            mandate_id=mandate_id,
        )
        return self._request(
            ops.X402_PAY,
            X402PayResponse,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def verify(
        self,
        *,
        payment_payload: X402PaymentPayload | Mapping[str, Any],
        payment_requirements: X402PaymentRequirements | Mapping[str, Any],
        x402_version: int = 2,
        request_options: RequestOptions | None = None,
    ) -> X402VerifyResponse:
        """Facilitator: verify a payment payload against requirements (sellers)."""
        body = {
            "x402Version": x402_version,
            "paymentPayload": payment_payload,
            "paymentRequirements": payment_requirements,
        }
        return self._request(
            ops.X402_VERIFY, X402VerifyResponse, body=body, request_options=request_options
        )

    def settle(
        self,
        *,
        payment_payload: X402PaymentPayload | Mapping[str, Any],
        payment_requirements: X402PaymentRequirements | Mapping[str, Any],
        x402_version: int = 2,
        request_options: RequestOptions | None = None,
    ) -> X402SettleResponse:
        """Facilitator: settle a verified payment on-chain (sellers).

        Not retried after an ambiguous failure: the facilitator treats each
        authorization as single-use, so check the outcome before settling again.
        """
        body = {
            "x402Version": x402_version,
            "paymentPayload": payment_payload,
            "paymentRequirements": payment_requirements,
        }
        return self._request(
            ops.X402_SETTLE, X402SettleResponse, body=body, request_options=request_options
        )

    def supported(self, *, request_options: RequestOptions | None = None) -> X402SupportedResponse:
        """Facilitator: supported x402 versions, schemes and networks."""
        return self._request(
            ops.X402_SUPPORTED, X402SupportedResponse, request_options=request_options
        )

    def register_payee(
        self,
        *,
        domains: Sequence[str],
        account_id: str | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> X402Payee:
        """Register an account to charge per call (x402 receive) for some domains."""
        return self._request(
            ops.REGISTER_X402_PAYEE,
            X402Payee,
            body=compact(account_id=self._account(account_id), domains=tuple(domains)),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def transport(
        self,
        *,
        max_amount: str | Decimal,
        spend_key: SignerLike | SessionKey | None = None,
        account_id: str | None = None,
        mandate_id: str | None = None,
        allowed_domains: Collection[str] | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> X402Transport:
        """Build an x402-paying ``httpx`` transport bound to this client.

        See :class:`agentbank.X402Transport` for the arguments.
        """
        return X402Transport(
            self._client,
            max_amount=max_amount,
            spend_key=spend_key,
            account_id=account_id,
            mandate_id=mandate_id,
            allowed_domains=allowed_domains,
            transport=transport,
        )

    def client(
        self,
        *,
        max_amount: str | Decimal,
        spend_key: SignerLike | SessionKey | None = None,
        account_id: str | None = None,
        mandate_id: str | None = None,
        allowed_domains: Collection[str] | None = None,
        transport: httpx.BaseTransport | None = None,
        **httpx_options: Any,
    ) -> httpx.Client:
        """An ``httpx.Client`` that pays 402 responses (up to ``max_amount`` each).

        Extra keyword arguments (``timeout``, ``headers``, ...) go to ``httpx.Client``.
        """
        x402_transport = self.transport(
            max_amount=max_amount,
            spend_key=spend_key,
            account_id=account_id,
            mandate_id=mandate_id,
            allowed_domains=allowed_domains,
            transport=transport,
        )
        return httpx.Client(transport=x402_transport, **httpx_options)

    def fetch(
        self,
        url: str,
        *,
        max_amount: str | Decimal,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        content: bytes | str | None = None,
        json: Any = None,
        spend_key: SignerLike | SessionKey | None = None,
        account_id: str | None = None,
        mandate_id: str | None = None,
        allowed_domains: Collection[str] | None = None,
        timeout: float | httpx.Timeout | None = 30.0,
    ) -> httpx.Response:
        """Fetch one URL, paying a 402 challenge of at most ``max_amount`` USDC.

        Returns the (fully read) response; ``agentbank.x402.x402_receipt(response)``
        tells what was paid.
        """
        with self.client(
            max_amount=max_amount,
            spend_key=spend_key,
            account_id=account_id,
            mandate_id=mandate_id,
            allowed_domains=allowed_domains,
            timeout=timeout,
        ) as http:
            return http.request(method, url, headers=headers, content=content, json=json)
