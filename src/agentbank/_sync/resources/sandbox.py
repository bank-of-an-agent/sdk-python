# Generated from src/agentbank/_async/resources/sandbox.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""Sandbox helpers: ``/v1/sandbox/faucet``."""

from __future__ import annotations

from agentbank import _operations as ops
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank._sync.resources._base import APIResource
from agentbank.models import SandboxFaucetResponse
from agentbank.money import MoneyInput, coerce_money

__all__ = ["Sandbox"]


class Sandbox(APIResource):
    """Sandbox-only tools (simulated chain and Anvil deployments)."""

    def faucet(
        self,
        *,
        amount: MoneyInput,
        account_id: str | None = None,
        address: str | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> SandboxFaucetResponse:
        """Mint test USDC to an account or address (simulated chain and Anvil only).

        Unavailable on Base Sepolia, where test USDC comes from Circle's faucet.

        Args:
            amount: Decimal string (USDC), ``Decimal`` or ``Money``.
            account_id: The receiving account (defaults to the client's
                ``account_id`` when ``address`` is not given).
            address: Alternatively, any address (e.g. an agent's spend key).
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.

        Raises:
            ValueError: Both ``account_id`` and ``address`` were given.
            ConfigurationError: Neither was given and the client has no ``account_id``.
        """
        if account_id is not None and address is not None:
            raise ValueError("Pass exactly one of account_id and address")
        if account_id is None and address is None:
            account_id = self._account(None)
        return self._request(
            ops.SANDBOX_FAUCET,
            SandboxFaucetResponse,
            body=compact(account_id=account_id, address=address, amount=coerce_money(amount)),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )
