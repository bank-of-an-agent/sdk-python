"""Spending policies: ``/v1/agents/{id}/policy`` and ``/v1/policy/check``."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agentbank import _operations as ops
from agentbank import owner_payloads
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank.canonical import to_jsonable
from agentbank.keys import SessionKey, SignerLike
from agentbank.models import AgentPolicy, PaymentIntent, PolicyDecision, PolicyDocument
from agentbank.money import coerce_money

__all__ = ["AsyncPolicies"]


class AsyncPolicies(AsyncAPIResource):
    """Owner-defined spending rules, enforced by the co-signer and on-chain scope."""

    async def retrieve(
        self, agent_id: str, *, request_options: RequestOptions | None = None
    ) -> AgentPolicy:
        """Get the agent's current policy and any pending (delayed) loosening."""
        return await self._request(
            ops.GET_POLICY,
            AgentPolicy,
            path_params={"id": agent_id},
            request_options=request_options,
        )

    async def put(
        self,
        agent_id: str,
        *,
        policy: PolicyDocument | Mapping[str, Any],
        owner_authorization: dict[str, Any] | None = None,
        owner: SignerLike | SessionKey | None = None,
        idempotency_key: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> AgentPolicy:
        """Replace the agent's policy.

        The document is normalized with the policy schema (defaults made
        explicit) before it is sent. Tightening applies immediately. Loosening
        (or a mixed change) requires an owner authorization with action
        ``policy.loosen`` over the normalized document (subject = ``agent_id``;
        see :func:`agentbank.owner_payloads.policy_loosen`) and takes effect
        after a 1-hour delay.

        Args:
            agent_id: The agent.
            policy: The full policy document.
            owner_authorization: A pre-signed ``policy.loosen`` authorization.
            owner: Alternatively, the owner key; the SDK signs ``policy.loosen``.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        loosen = owner_payloads.policy_loosen(agent_id, policy)
        body: dict[str, Any] = {"policy": loosen.payload}
        if owner_authorization is not None:
            body["owner_authorization"] = owner_authorization
        elif owner is not None:
            body["owner_authorization"] = await self._owner_authorization(owner, loosen)
        return await self._request(
            ops.PUT_POLICY,
            AgentPolicy,
            path_params={"id": agent_id},
            body=body,
            idempotency_key=idempotency_key,
            request_options=request_options,
        )

    async def check(
        self,
        *,
        intent: PaymentIntent | Mapping[str, Any],
        account_id: str | None = None,
        request_options: RequestOptions | None = None,
    ) -> PolicyDecision:
        """Dry-run a payment intent against policy (agents may call this).

        Args:
            intent: ``kind``, ``amount`` (``Money``, or a decimal string in USDC)
                and the counterparty (``to_address``, ``to_agent_id``,
                ``erc8004_id``, ``x402_domain`` or ``contract``).
            account_id: The paying account (defaults to the client's).
            request_options: Per-request overrides.

        Returns:
            The decision (``allow``, ``deny``, ``require_approval`` or
            ``require_owner``), every rule that fired, and ``retry_at`` when a
            time-based denial lifts.
        """
        payload: dict[str, Any] = to_jsonable(intent)
        if isinstance(payload.get("amount"), str):
            payload["amount"] = coerce_money(payload["amount"])
        return await self._request(
            ops.CHECK_POLICY,
            PolicyDecision,
            body=compact(account_id=self._account(account_id), intent=payload),
            request_options=request_options,
        )
