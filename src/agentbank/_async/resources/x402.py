"""x402 pay-per-call: ``/v1/x402/*`` plus an x402-aware HTTP client."""

from __future__ import annotations

from collections.abc import Callable, Collection, Mapping, Sequence
from decimal import Decimal
from typing import Any

import httpx

from agentbank import _operations as ops
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._async.x402 import AsyncX402Transport
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank.chains import USDC, chain_for_network
from agentbank.errors import ConfigurationError
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
from agentbank.x402 import (
    DEFAULT_MAX_AMOUNT_PER_REQUEST,
    X402Receipt,
    X402Settings,
    x402_settings_from_meta,
)

__all__ = ["AsyncX402"]


class AsyncX402(AsyncAPIResource):
    """Pay for HTTP resources per call (buyer) and charge per call (seller)."""

    async def pay(
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
            The x402 payment (``requires_signature``) and the EIP-3009
            authorization for the spend key to sign. A payment outside policy is
            denied (``payment.status == "denied"``, no authorization); x402
            payments never wait for human approval.
        """
        body = compact(
            account_id=self._account(account_id),
            resource=resource,
            requirements=requirements,
            mandate_id=mandate_id,
        )
        return await self._request(
            ops.X402_PAY,
            X402PayResponse,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def verify(
        self,
        *,
        payment_payload: X402PaymentPayload | Mapping[str, Any],
        payment_requirements: X402PaymentRequirements | Mapping[str, Any],
        x402_version: int = 2,
        request_options: RequestOptions | None = None,
    ) -> X402VerifyResponse:
        """Facilitator (public): verify a payment payload against requirements (sellers)."""
        body = {
            "x402Version": x402_version,
            "paymentPayload": payment_payload,
            "paymentRequirements": payment_requirements,
        }
        return await self._request(
            ops.X402_VERIFY, X402VerifyResponse, body=body, request_options=request_options
        )

    async def settle(
        self,
        *,
        payment_payload: X402PaymentPayload | Mapping[str, Any],
        payment_requirements: X402PaymentRequirements | Mapping[str, Any],
        x402_version: int = 2,
        request_options: RequestOptions | None = None,
    ) -> X402SettleResponse:
        """Facilitator (public): settle a verified payment on-chain (sellers).

        Not retried after an ambiguous failure: the facilitator treats each
        authorization as single-use, so check the outcome before settling again.
        """
        body = {
            "x402Version": x402_version,
            "paymentPayload": payment_payload,
            "paymentRequirements": payment_requirements,
        }
        return await self._request(
            ops.X402_SETTLE, X402SettleResponse, body=body, request_options=request_options
        )

    async def supported(
        self, *, request_options: RequestOptions | None = None
    ) -> X402SupportedResponse:
        """Facilitator: supported x402 versions, schemes and networks."""
        return await self._request(
            ops.X402_SUPPORTED, X402SupportedResponse, request_options=request_options
        )

    async def settings(
        self, network: str | None = None, *, request_options: RequestOptions | None = None
    ) -> X402Settings:
        """The network and USDC this client pays x402 challenges with.

        An explicit ``network`` wins, with the SDK's USDC registry for that
        chain (or the deployment's USDC when the registry has none and
        ``GET /v1/meta`` is on that network). Otherwise both come from
        ``GET /v1/meta`` (``caip2``, ``usdc.address``, ``usdc.eip712_name`` and
        ``usdc.eip712_version``), fetched once and cached on the client.

        Args:
            network: CAIP-2 network (or x402 v1 name) to pay on, if configured.
            request_options: Per-request overrides for ``GET /v1/meta``.

        Raises:
            MainnetLockedError: The network is a mainnet.
            ConfigurationError: No USDC is known on an explicit ``network``.
        """
        if network is None:
            meta = await self._client.meta(request_options=request_options)
            return x402_settings_from_meta(meta)
        chain = chain_for_network(network)
        known = USDC.get(chain.id)
        if known is not None:
            return X402Settings(chain=chain, usdc=known)
        # No USDC in the registry (e.g. a MockUSDC on Anvil): the deployment's, if on this chain.
        deployment = x402_settings_from_meta(
            await self._client.meta(request_options=request_options)
        )
        if deployment.chain.id != chain.id:
            raise ConfigurationError(
                f"No USDC address is known for {chain.caip2} (the deployment is on "
                f"{deployment.network}); leave network unset to pay on the deployment's network"
            )
        return deployment

    async def register_payee(
        self,
        *,
        domains: Sequence[str],
        account_id: str | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> X402Payee:
        """Register an account to charge per call (x402 receive) for some domains."""
        return await self._request(
            ops.REGISTER_X402_PAYEE,
            X402Payee,
            body=compact(account_id=self._account(account_id), domains=tuple(domains)),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def transport(
        self,
        *,
        max_amount: str | Decimal = DEFAULT_MAX_AMOUNT_PER_REQUEST,
        network: str | None = None,
        spend_key: SignerLike | SessionKey | None = None,
        account_id: str | None = None,
        mandate_id: str | None = None,
        allowed_domains: Collection[str] | None = None,
        on_payment: Callable[[X402Receipt], None] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> AsyncX402Transport:
        """Build an x402-paying ``httpx`` transport bound to this client.

        See :class:`agentbank.AsyncX402Transport` for the arguments.
        """
        return AsyncX402Transport(
            self._client,
            max_amount=max_amount,
            network=network,
            spend_key=spend_key,
            account_id=account_id,
            mandate_id=mandate_id,
            allowed_domains=allowed_domains,
            on_payment=on_payment,
            transport=transport,
        )

    def client(
        self,
        *,
        max_amount: str | Decimal = DEFAULT_MAX_AMOUNT_PER_REQUEST,
        network: str | None = None,
        spend_key: SignerLike | SessionKey | None = None,
        account_id: str | None = None,
        mandate_id: str | None = None,
        allowed_domains: Collection[str] | None = None,
        on_payment: Callable[[X402Receipt], None] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        **httpx_options: Any,
    ) -> httpx.AsyncClient:
        """An ``httpx.AsyncClient`` that pays 402 responses (up to ``max_amount`` each).

        Extra keyword arguments (``timeout``, ``headers``, ...) go to ``httpx.AsyncClient``.
        """
        x402_transport = self.transport(
            max_amount=max_amount,
            network=network,
            spend_key=spend_key,
            account_id=account_id,
            mandate_id=mandate_id,
            allowed_domains=allowed_domains,
            on_payment=on_payment,
            transport=transport,
        )
        return httpx.AsyncClient(transport=x402_transport, **httpx_options)

    async def fetch(
        self,
        url: str,
        *,
        max_amount: str | Decimal = DEFAULT_MAX_AMOUNT_PER_REQUEST,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        content: bytes | str | None = None,
        json: Any = None,
        network: str | None = None,
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
        async with self.client(
            max_amount=max_amount,
            network=network,
            spend_key=spend_key,
            account_id=account_id,
            mandate_id=mandate_id,
            allowed_domains=allowed_domains,
            timeout=timeout,
        ) as http:
            return await http.request(method, url, headers=headers, content=content, json=json)
