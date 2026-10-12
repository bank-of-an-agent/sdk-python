# Generated from src/agentbank/_async/resources/vaults.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""Savings vaults: ``/v1/vaults``."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from datetime import datetime
from typing import Any, Literal

from agentbank import _operations as ops
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank._sync.resources._base import APIResource
from agentbank.early_withdrawal import early_withdrawal_typed_data, sign_early_withdrawal
from agentbank.errors import OwnerSignatureRequiredError
from agentbank.keys import SessionKey, SignerLike
from agentbank.models import ListVaultsResponse, Vault
from agentbank.money import MoneyInput, coerce_money

__all__ = ["Vaults"]


class Vaults(APIResource):
    """Goal vaults (ledger pockets) and time-locked vaults (``TimeLockVaults``).

    Agents may deposit; only the principal withdraws, and early withdrawal from
    a locked vault needs the owner key's ``EarlyWithdrawal`` signature (see
    :mod:`agentbank.early_withdrawal`).
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

        Goal vaults, and locked vaults past ``unlock_at``, withdraw at once.
        Before a locked vault's ``unlock_at`` the ``TimeLockVaults`` contract
        needs the owner's EIP-712 ``EarlyWithdrawal`` signature, not a
        ``vault.withdraw`` owner authorization: without one the API raises
        :class:`~agentbank.OwnerSignatureRequiredError` whose
        ``extensions["typed_data"]`` describes what to sign. With ``owner``, the
        SDK answers that challenge (checked with
        :meth:`early_withdrawal_typed_data` first) and resends the withdrawal
        under ``{idempotency_key}.signed``; the vault then comes back with
        ``pending_operation_id``, the owner operation that carries the signature.
        Sign it with ``owner_operations.sign_and_submit``, or use
        ``AgentBank.withdraw_vault``, which does every step.

        Args:
            vault_id: The vault.
            amount: Decimal string (USDC), ``Decimal`` or ``Money``.
            owner_authorization: An ``EarlyWithdrawal`` signed elsewhere (e.g. a
                hardware wallet, over :meth:`early_withdrawal_typed_data`):
                ``{"signer", "signature", "issued_at", "expires_at"}`` with
                ``expires_at`` = the signed ``deadline``. Send it under a new
                idempotency key: the API stores the challenge under the first one.
            owner: Alternatively, the owner key: answer the challenge automatically.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.

        Raises:
            OwnerSignatureRequiredError: An early withdrawal without ``owner``
                or ``owner_authorization``; ``extensions["typed_data"]`` holds
                the challenge.
            BadRequestError: With ``owner``, the challenge is not the requested
                withdrawal (nothing is signed).
        """
        if owner is not None and owner_authorization is None:
            vault, _ = self._withdraw_as_owner(
                vault_id,
                amount,
                owner,
                idempotency_key=idempotency_key,
                request_options=request_options,
            )
            return vault
        return self._withdraw(
            vault_id,
            amount,
            owner_authorization,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def early_withdrawal_typed_data(
        self,
        vault_id: str,
        *,
        amount: MoneyInput,
        typed_data: Mapping[str, Any],
        request_options: RequestOptions | None = None,
    ) -> dict[str, Any]:
        """Check an early-withdrawal challenge and build the typed data the owner signs.

        Compares the API's ``typed_data`` with the vault (``onchain_id`` and
        ``contract_address``, else ``meta.contracts["vaults"]``), the deployment's
        chain (``GET /v1/meta``) and ``amount``; see
        :func:`agentbank.early_withdrawal.early_withdrawal_typed_data`. Sign the
        result with a wallet's ``eth_signTypedData_v4``, or with
        :func:`agentbank.sign_early_withdrawal` for a software key.

        Args:
            vault_id: The vault.
            amount: The amount being withdrawn.
            typed_data: ``extensions["typed_data"]`` of the API's
                ``owner_signature_required`` error.
            request_options: Per-request overrides.

        Raises:
            BadRequestError: ``invalid_request`` when the challenge differs.
        """
        vault = self.retrieve(vault_id, request_options=request_options)
        meta = self._client.meta(request_options=request_options)
        return early_withdrawal_typed_data(
            typed_data,
            chain_id=meta.chain_id,
            contract=vault.contract_address or meta.contracts.get("vaults"),
            onchain_id=vault.onchain_id,
            amount=amount,
        )

    def _withdraw(
        self,
        vault_id: str,
        amount: MoneyInput,
        owner_authorization: dict[str, Any] | None,
        *,
        idempotency_key: str | None,
        request_options: RequestOptions | None,
    ) -> Vault:
        body: dict[str, Any] = {"amount": coerce_money(amount)}
        if owner_authorization is not None:
            body["owner_authorization"] = owner_authorization
        return self._request(
            ops.WITHDRAW_VAULT,
            Vault,
            path_params={"id": vault_id},
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def _withdraw_as_owner(
        self,
        vault_id: str,
        amount: MoneyInput,
        owner: SignerLike | SessionKey,
        *,
        idempotency_key: str | None,
        request_options: RequestOptions | None,
    ) -> tuple[Vault, bool]:
        """Withdraw, answering an early-withdrawal challenge; also says whether one came."""
        try:
            vault = self._withdraw(
                vault_id,
                amount,
                None,
                idempotency_key=idempotency_key,
                request_options=request_options,
            )
        except OwnerSignatureRequiredError as error:
            challenge = error.extensions.get("typed_data")
            if not isinstance(challenge, Mapping):
                raise
        else:
            return vault, False
        typed_data = self.early_withdrawal_typed_data(
            vault_id, amount=amount, typed_data=challenge, request_options=request_options
        )
        vault = self._withdraw(
            vault_id,
            amount,
            sign_early_withdrawal(owner, typed_data),
            idempotency_key=f"{idempotency_key}.signed" if idempotency_key else None,
            request_options=request_options,
        )
        return vault, True
