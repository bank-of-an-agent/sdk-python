# Generated from src/agentbank/_async/x402.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""x402-aware ``httpx`` transport (synchronous)."""

from __future__ import annotations

from collections.abc import Callable, Collection
from decimal import Decimal
from typing import TYPE_CHECKING

import httpx

from agentbank.chains import chain_for_network
from agentbank.errors import ConfigurationError, X402Error
from agentbank.keys import EthSigner, SessionKey, SignerLike, to_signer
from agentbank.money import coerce_money, to_minor
from agentbank.x402 import (
    DEFAULT_MAX_AMOUNT_PER_REQUEST,
    PAYMENT_SIGNATURE_HEADER,
    RECEIPT_EXTENSION,
    V1_PAYMENT_HEADER,
    X402Receipt,
    build_payment_header,
    decode_payment_response,
    parse_payment_required,
    rejection_reason,
    select_requirement,
)

if TYPE_CHECKING:
    from agentbank._sync.client import AgentBank

__all__ = ["X402Transport"]


class X402Transport(httpx.BaseTransport):
    """An ``httpx`` transport that pays HTTP 402 (x402) challenges through Agent Bank.

    Wrap any HTTP client used by an agent; requests that come back ``402`` are
    paid within policy and retried once with the payment header::

        transport = bank.x402.transport(max_amount="0.10")
        with httpx.Client(transport=transport) as http:
            response = http.get("https://api.example-data.com/v1/report")

    Each paid response carries an :class:`agentbank.x402.X402Receipt`
    (see :func:`agentbank.x402.x402_receipt`).

    Args:
        bank: An agent-authenticated client (session key) used for ``POST /v1/x402/pay``.
        max_amount: Client-side ceiling per request in USDC (decimal string or
            ``Decimal``; default ``"1.00"``), checked before Agent Bank is asked.
        network: CAIP-2 network to pay on. Default: the deployment's network and
            USDC from ``GET /v1/meta``, resolved on the first 402 and cached on
            the client (``bank.x402.settings()``).
        spend_key: The agent's x402 spend key (defaults to the client's ``spend_key``).
        account_id: Paying account (defaults to the client's ``account_id``).
        mandate_id: Mandate to pay under, if any.
        allowed_domains: Optional allowlist of hosts this transport may pay.
        on_payment: Called with the :class:`~agentbank.x402.X402Receipt` after each
            successful paid request (for logging or accounting).
        transport: The transport to wrap (default: a new ``httpx.HTTPTransport``).

    Raises:
        ConfigurationError: No spend key or account is configured.
        MainnetLockedError: ``network`` is a mainnet (a mainnet deployment is
            refused when the first challenge is paid).
    """

    def __init__(
        self,
        bank: AgentBank,
        *,
        max_amount: str | Decimal = DEFAULT_MAX_AMOUNT_PER_REQUEST,
        network: str | None = None,
        spend_key: SignerLike | SessionKey | None = None,
        account_id: str | None = None,
        mandate_id: str | None = None,
        allowed_domains: Collection[str] | None = None,
        on_payment: Callable[[X402Receipt], None] | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        signer: EthSigner | None = (
            to_signer(spend_key) if spend_key is not None else bank.config.spend_signer
        )
        if signer is None:
            raise ConfigurationError("x402 payments need the agent's spend key (spend_key=...)")
        resolved_account = account_id or bank.account_id
        if not resolved_account:
            raise ConfigurationError("x402 payments need account_id (or a client account_id)")
        if network is not None:
            chain_for_network(network)  # refuses mainnets and unknown networks up front
        self._bank = bank
        self._signer = signer
        self._account_id = resolved_account
        self._mandate_id = mandate_id
        self._network = network
        self._max_amount = to_minor(coerce_money(max_amount))
        self._allowed_domains = (
            frozenset(d.lower() for d in allowed_domains) if allowed_domains is not None else None
        )
        self._on_payment = on_payment
        self._transport = transport or httpx.HTTPTransport()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Send ``request``; on ``402``, pay the challenge and retry once.

        Raises:
            X402Error: The challenge cannot be paid within the client's limits,
                the authorization does not match it, or the seller rejects the
                payment (``payment_rejected``).
            PaymentDeniedError: Agent Bank's policy denied the payment.
            MainnetLockedError: The deployment (``GET /v1/meta``) is on a mainnet.
        """
        request.read()  # buffer the body so the request can be replayed
        response = self._transport.handle_request(request)
        if response.status_code != 402 or _already_paid(request):
            return response
        try:
            response.read()
        finally:
            response.close()

        challenge = parse_payment_required(response.headers, response.content)
        settings = self._bank.x402.settings(self._network)
        selected = select_requirement(
            challenge,
            request_url=str(request.url),
            max_amount=self._max_amount,
            network=settings.network,
            allowed_domains=self._allowed_domains,
            usdc=settings.usdc,
        )
        authorization = self._bank.x402.pay(
            account_id=self._account_id,
            resource=selected.resource,
            requirements=selected.requirements,
            mandate_id=self._mandate_id,
        )
        header = build_payment_header(selected, authorization, self._signer)

        paid_request = httpx.Request(
            request.method,
            request.url,
            headers=request.headers.copy(),
            content=request.content,
            extensions=dict(request.extensions),
        )
        paid_request.headers[header.name] = header.value
        paid = self._transport.handle_request(paid_request)
        settlement = decode_payment_response(paid.headers)
        if paid.status_code == 402:
            try:
                paid.read()
            finally:
                paid.close()
            raise X402Error(
                "payment_rejected",
                "Seller rejected the x402 payment: " + rejection_reason(paid.headers, paid.content),
                payment=authorization.payment,
                settlement=settlement,
                response=paid,
            )
        receipt = X402Receipt(
            payment=authorization.payment,
            requirement=selected,
            header=header,
            settlement=settlement,
        )
        paid.extensions[RECEIPT_EXTENSION] = receipt
        if self._on_payment is not None:
            self._on_payment(receipt)
        return paid

    def close(self) -> None:
        """Close the wrapped transport."""
        self._transport.close()


def _already_paid(request: httpx.Request) -> bool:
    return PAYMENT_SIGNATURE_HEADER in request.headers or V1_PAYMENT_HEADER in request.headers
