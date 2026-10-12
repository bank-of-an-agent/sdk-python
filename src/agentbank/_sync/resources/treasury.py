# Generated from src/agentbank/_async/resources/treasury.py by scripts/unasync.py.
# Do not edit: change the async source and regenerate.
"""Org treasury, auto top-up and sweep: ``/v1/orgs/me/treasury*``, ``/v1/funds`` ..."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Literal

from agentbank import _operations as ops
from agentbank import owner_payloads
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank._sync.resources._base import APIResource
from agentbank.keys import SessionKey, SignerLike
from agentbank.models import (
    Account,
    AutoTopUpRule,
    ListAutoTopUpRulesResponse,
    ListFundsResponse,
    Org,
    SweepRule,
)
from agentbank.money import MoneyInput

__all__ = ["Treasury"]


class Treasury(APIResource):
    """The org treasury account, agent auto top-up rules and the treasury sweep.

    Funds only ever move between the org's own accounts; every rule that lets
    Agent Bank's keepers trigger such moves is configured by the owner key.
    """

    def create_account(
        self,
        *,
        chain: Literal["base-sepolia", "anvil", "simulated"] | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> Account:
        """Create the org treasury smart account (server default chain ``base-sepolia``)."""
        return self._request(
            ops.CREATE_TREASURY_ACCOUNT,
            Account,
            body=compact(chain=chain),
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def set(
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
            owner_authorization: A pre-signed ``treasury.set`` authorization
                (subject = the org id, payload ``{"account_id": account_id}``).
            owner: Alternatively, the owner key; the SDK looks up the org id and
                signs it.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        body: dict[str, Any] = {"account_id": account_id}
        if owner_authorization is not None:
            body["owner_authorization"] = owner_authorization
        elif owner is not None:
            org = self._client.orgs.retrieve(request_options=request_options)
            change = owner_payloads.treasury_set(org.id, account_id)
            body["owner_authorization"] = self._owner_authorization(owner, change)
        return self._request(
            ops.SET_TREASURY,
            Org,
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def get_auto_topup(
        self, agent_id: str, *, request_options: RequestOptions | None = None
    ) -> AutoTopUpRule | None:
        """Get the agent's auto top-up rule, or ``None`` if it has none."""
        data = self._client._request_json(
            ops.GET_AUTO_TOP_UP, path_params={"id": agent_id}, request_options=request_options
        )
        return None if data is None else AutoTopUpRule.model_validate(data)

    def put_auto_topup(
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
            owner_authorization: A pre-signed ``topup.set`` authorization
                (subject = ``agent_id``, payload ``{refill_to, when_below, max_per_day}``).
            owner: Alternatively, the owner key; the SDK signs it.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        rule = owner_payloads.topup_set(
            agent_id, refill_to=refill_to, when_below=when_below, max_per_day=max_per_day
        )
        body: dict[str, Any] = dict(rule.payload)
        if owner_authorization is not None:
            body["owner_authorization"] = owner_authorization
        elif owner is not None:
            body["owner_authorization"] = self._owner_authorization(owner, rule)
        return self._request(
            ops.PUT_AUTO_TOP_UP,
            AutoTopUpRule,
            path_params={"id": agent_id},
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    def list_auto_topup_rules(
        self,
        *,
        cursor: str | None = None,
        limit: int | None = None,
        request_options: RequestOptions | None = None,
    ) -> ListAutoTopUpRulesResponse:
        """List the org's auto top-up rules (one page)."""
        return self._request(
            ops.LIST_AUTO_TOP_UP_RULES,
            ListAutoTopUpRulesResponse,
            query={"cursor": cursor, "limit": limit},
            request_options=request_options,
        )

    def list_auto_topup_rules_all(
        self, *, limit: int | None = None, request_options: RequestOptions | None = None
    ) -> Iterator[AutoTopUpRule]:
        """Iterate over every auto top-up rule, following ``next_cursor``."""
        for page in self._paginate(
            ops.LIST_AUTO_TOP_UP_RULES,
            ListAutoTopUpRulesResponse,
            query={"limit": limit},
            request_options=request_options,
        ):
            yield from page.data

    def get_sweep_rule(
        self, account_id: str, *, request_options: RequestOptions | None = None
    ) -> SweepRule | None:
        """Get the account's treasury sweep rule, or ``None`` if it has none."""
        data = self._client._request_json(
            ops.GET_SWEEP_RULE, path_params={"id": account_id}, request_options=request_options
        )
        return None if data is None else SweepRule.model_validate(data)

    def list_funds(self, *, request_options: RequestOptions | None = None) -> ListFundsResponse:
        """List eligible tokenized Treasury funds (a neutral list, not a recommendation)."""
        return self._request(ops.LIST_FUNDS, ListFundsResponse, request_options=request_options)

    def put_sweep_rule(
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
            owner_authorization: A pre-signed ``sweep.set`` authorization
                (subject = ``account_id``, payload = the body without it).
            owner: Alternatively, the owner key; the SDK signs it.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        rule = owner_payloads.sweep_set(
            account_id,
            fund_id=fund_id,
            threshold=threshold,
            max_share_bps=max_share_bps,
            floor=floor,
        )
        body: dict[str, Any] = dict(rule.payload)
        if owner_authorization is not None:
            body["owner_authorization"] = owner_authorization
        elif owner is not None:
            body["owner_authorization"] = self._owner_authorization(owner, rule)
        return self._request(
            ops.PUT_SWEEP_RULE,
            SweepRule,
            path_params={"id": account_id},
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )
