"""Org treasury, auto top-up and sweep: ``/v1/orgs/me/treasury*``, ``/v1/funds`` ..."""

from __future__ import annotations

from typing import Any, Literal

from agentbank import _operations as ops
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact, without_owner_authorization
from agentbank.keys import SessionKey, SignerLike
from agentbank.models import Account, AutoTopUpRule, ListFundsResponse, Org, SweepRule
from agentbank.money import MoneyInput, coerce_money

__all__ = ["AsyncTreasury"]


class AsyncTreasury(AsyncAPIResource):
    """The org treasury account, agent auto top-up rules and the treasury sweep.

    Funds only ever move between the org's own accounts; every rule that lets
    Agent Bank's keepers trigger such moves is configured by the owner key.
    """

    async def create_account(
        self,
        *,
        chain: Literal["base-sepolia", "anvil", "simulated"] | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Account:
        """Create the org treasury smart account (server default chain ``base-sepolia``)."""
        return await self._request(
            ops.CREATE_TREASURY_ACCOUNT,
            Account,
            body=compact(chain=chain),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def set_account(
        self,
        *,
        account_id: str,
        owner_authorization: dict[str, Any] | None = None,
        owner: SignerLike | SessionKey | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Org:
        """Set the org treasury account (owner signature).

        Args:
            account_id: The treasury account.
            owner_authorization: A pre-signed ``treasury.set`` authorization.
            owner: Alternatively, the owner key; the SDK signs ``treasury.set`` with
                subject = the org id and payload ``{"account_id": account_id}``.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        body = compact(account_id=account_id, owner_authorization=owner_authorization)
        if owner_authorization is None and owner is not None:
            org = await self._client.orgs.me(request_options=request_options)
            body["owner_authorization"] = self._owner_authorization(
                owner, "treasury.set", org.id, without_owner_authorization(body)
            )
        return await self._request(
            ops.SET_TREASURY,
            Org,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def get_auto_topup(
        self, agent_id: str, *, request_options: RequestOptions | None = None
    ) -> AutoTopUpRule | None:
        """Get the agent's auto top-up rule, or ``None`` if it has none."""
        data = await self._client._request_json(
            ops.GET_AUTO_TOP_UP, path_params={"id": agent_id}, request_options=request_options
        )
        return None if data is None else AutoTopUpRule.model_validate(data)

    async def set_auto_topup(
        self,
        agent_id: str,
        *,
        refill_to: MoneyInput,
        when_below: MoneyInput,
        max_per_day: MoneyInput,
        owner_authorization: dict[str, Any] | None = None,
        owner: SignerLike | SessionKey | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> AutoTopUpRule:
        """Refill the agent from the treasury when its balance drops (owner signature).

        Args:
            agent_id: The agent to refill.
            refill_to: Balance to top up to.
            when_below: Trigger threshold.
            max_per_day: Daily cap on top-ups.
            owner_authorization: A pre-signed ``topup.set`` authorization.
            owner: Alternatively, the owner key; the SDK signs ``topup.set`` with
                subject = ``agent_id`` and the request body as payload.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        body = compact(
            refill_to=coerce_money(refill_to),
            when_below=coerce_money(when_below),
            max_per_day=coerce_money(max_per_day),
            owner_authorization=owner_authorization,
        )
        if owner_authorization is None and owner is not None:
            body["owner_authorization"] = self._owner_authorization(
                owner, "topup.set", agent_id, without_owner_authorization(body)
            )
        return await self._request(
            ops.PUT_AUTO_TOP_UP,
            AutoTopUpRule,
            path_params={"id": agent_id},
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def list_funds(
        self, *, request_options: RequestOptions | None = None
    ) -> ListFundsResponse:
        """List eligible tokenized Treasury funds (a neutral list, not a recommendation)."""
        return await self._request(
            ops.LIST_FUNDS, ListFundsResponse, request_options=request_options
        )

    async def set_sweep_rule(
        self,
        account_id: str,
        *,
        fund_id: str,
        threshold: MoneyInput,
        max_share_bps: int,
        floor: MoneyInput | None = None,
        owner_authorization: dict[str, Any] | None = None,
        owner: SignerLike | SessionKey | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> SweepRule:
        """Configure the owner-directed treasury sweep (counsel-gated feature).

        Args:
            account_id: The account to sweep from.
            fund_id: Target fund (see :meth:`list_funds`).
            threshold: Sweep the excess above this balance.
            max_share_bps: Maximum share of the balance to sweep (basis points).
            floor: Balance that always stays liquid (server default: two days of
                trailing seven-day spend).
            owner_authorization: A pre-signed ``sweep.set`` authorization.
            owner: Alternatively, the owner key; the SDK signs ``sweep.set`` with
                subject = ``account_id`` and the request body as payload.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        body = compact(
            fund_id=fund_id,
            floor=coerce_money(floor) if floor is not None else None,
            threshold=coerce_money(threshold),
            max_share_bps=max_share_bps,
            owner_authorization=owner_authorization,
        )
        if owner_authorization is None and owner is not None:
            body["owner_authorization"] = self._owner_authorization(
                owner, "sweep.set", account_id, without_owner_authorization(body)
            )
        return await self._request(
            ops.PUT_SWEEP_RULE,
            SweepRule,
            path_params={"id": account_id},
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )
