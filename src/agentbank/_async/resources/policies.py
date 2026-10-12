"""Spending policies: ``/v1/agents/{id}/policy`` and ``/v1/policy/check``."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agentbank import _operations as ops
from agentbank._async.resources._base import AsyncAPIResource
from agentbank._base_client import RequestOptions
from agentbank._resource_helpers import compact
from agentbank.canonical import to_jsonable
from agentbank.keys import SessionKey, SignerLike
from agentbank.models import AgentPolicy, PaymentIntent, PolicyDecision, PolicyDocument

__all__ = ["AsyncPolicies"]


class AsyncPolicies(AsyncAPIResource):
    """Owner-defined spending rules, enforced by the co-signer and on-chain scope."""

    async def get(
        self, agent_id: str, *, request_options: RequestOptions | None = None
    ) -> AgentPolicy:
        """Get the agent's current policy and any pending (delayed) loosening."""
        return await self._request(
            ops.GET_POLICY,
            AgentPolicy,
            path_params={"id": agent_id},
            request_options=request_options,
        )

    async def update(
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

        Tightening applies immediately. Loosening (or a mixed change) requires an
        owner authorization with action ``policy.loosen`` over the policy document
        (subject = ``agent_id``) and takes effect after a 1-hour delay.

        Args:
            agent_id: The agent.
            policy: The full policy document.
            owner_authorization: A pre-signed ``policy.loosen`` authorization over
                the policy document exactly as sent.
            owner: Alternatively, the owner key; the SDK signs ``policy.loosen``.
            idempotency_key: Optional key; generated when omitted.
            request_options: Per-request overrides.
        """
        document = to_jsonable(policy)
        body = compact(policy=document)
        if owner_authorization is not None:
            body["owner_authorization"] = owner_authorization
        elif owner is not None:
            body["owner_authorization"] = self._owner_authorization(
                owner, "policy.loosen", agent_id, document
            )
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
            intent: ``kind``, ``amount`` and the counterparty (``to_address``,
                ``to_agent_id``, ``erc8004_id`` or ``x402_domain``).
            account_id: The paying account (defaults to the client's).
            request_options: Per-request overrides.

        Returns:
            The decision (``allow``, ``deny``, ``require_approval`` or
            ``require_owner``) and every rule that fired.
        """
        return await self._request(
            ops.CHECK_POLICY,
            PolicyDecision,
            body=compact(account_id=self._account(account_id), intent=intent),
            request_options=request_options,
        )
