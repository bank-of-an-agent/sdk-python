# Generated from src/agentbank/_async/resources/vaults.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""Savings vaults: ``/v1/vaults``."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from typing import Any, Literal

from agentbank import _operations as ops
from agentbank import owner_payloads
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank._sync.resources._base import APIResource
from agentbank.keys import SessionKey, SignerLike
from agentbank.models import ListVaultsResponse, Vault
from agentbank.money import MoneyInput, coerce_money

__all__ = ["Vaults"]


class Vaults(APIResource):
    """Goal vaults (ledger pockets) and time-locked vaults (``TimeLockVaults``).

    Agents may deposit; only the principal withdraws, and early withdrawal from
    a locked vault needs the owner key.
    """

    def create(
        self,
        *,
        kind: Literal["goal", "locked"],
        name: str,
        account_id: str | None = None,
        target: MoneyInput | None = None,
        unlock_at: datetime | str | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Vault:
        """Create a goal or time-locked vault.

        Args:
            kind: ``"goal"`` or ``"locked"``.
            name: Display name.
            account_id: The account (defaults to the client's ``account_id``).
            target: Optional savings goal.
            unlock_at: Unlock time for ``locked`` vaults.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        body = compact(
            account_id=self._account(account_id),
            kind=kind,
            name=name,
            target=coerce_money(target) if target is not None else None,
            unlock_at=unlock_at,
        )
        return self._request(
            ops.CREATE_VAULT,
            Vault,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def list(
        self,
        *,
        account_id: str | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListVaultsResponse:
        """List vaults (one page), optionally for one account."""
        return self._request(
            ops.LIST_VAULTS,
            ListVaultsResponse,
            query={"account_id": account_id, "cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    def list_all(
        self,
        *,
        account_id: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> Iterator[Vault]:
        """Iterate over every vault, following ``next_cursor``."""
        for page in self._paginate(
            ops.LIST_VAULTS,
            ListVaultsResponse,
            query={"account_id": account_id, "limit": limit},
            request_options=request_options,
        ):
            yield from page.data

    def retrieve(self, vault_id: str, *, request_options: RequestOptions | None = None) -> Vault:
        """Get a vault and its balance."""
        return self._request(
            ops.GET_VAULT, Vault, path_params={"id": vault_id}, request_options=request_options
        )

    def deposit(
        self,
        vault_id: str,
        *,
        amount: MoneyInput,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Vault:
        """Move funds from the account into a vault (agents may deposit)."""
        return self._request(
            ops.DEPOSIT_VAULT,
            Vault,
            path_params={"id": vault_id},
            body=compact(amount=coerce_money(amount)),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def withdraw(
        self,
        vault_id: str,
        *,
        amount: MoneyInput,
        owner_authorization: dict[str, Any] | None = None,
        owner: SignerLike | SessionKey | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Vault:
        """Withdraw from a vault back to its account (principal only).

        Before a locked vault's ``unlock_at``, the owner must authorize
        ``vault.withdraw`` (subject = ``vault_id``, payload ``{"amount": ...}``).

        Args:
            vault_id: The vault.
            amount: Decimal string (USDC), ``Decimal`` or ``Money``.
            owner_authorization: A pre-signed ``vault.withdraw`` authorization.
            owner: Alternatively, the owner key; the SDK signs it.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        withdrawal = owner_payloads.vault_withdraw(vault_id, amount)
        body: dict[str, Any] = dict(withdrawal.payload)
        if owner_authorization is not None:
            body["owner_authorization"] = owner_authorization
        elif owner is not None:
            body["owner_authorization"] = self._owner_authorization(owner, withdrawal)
        return self._request(
            ops.WITHDRAW_VAULT,
            Vault,
            path_params={"id": vault_id},
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )
