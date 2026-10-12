"""Canonical subject and payload for every owner action.

Mirrors ``ownerPayloads`` in ``@agentbank/core`` (``owner-actions.ts``), which the
API and the co-signer use to verify owner authorizations, so that signers and
verifiers hash exactly the same JSON:

* ``subject`` is the id of the resource the action applies to;
* ``payload`` is the request body without ``owner_authorization``, **after the
  schema's defaults are applied** (the server hashes the parsed body). The
  helpers here apply those defaults (``asset: "USDC"`` in a session scope, the
  policy document defaults, ...) and normalize money to ``{amount, asset}``;
* the EIP-712 domain chain id is the deployment's ``owner_authorization_chain_id``
  from ``GET /v1/meta`` (``client.owner_authorization_chain_id()``).

The resource methods send exactly these normalized payloads, so an
authorization signed elsewhere (for example on a hardware wallet) over
``owner_authorization_typed_data(..., payload=p.payload)`` verifies::

    from agentbank import owner_authorization_typed_data, owner_payloads

    p = owner_payloads.policy_loosen(agent_id, policy)
    typed = owner_authorization_typed_data(
        chain_id=bank.owner_authorization_chain_id(),
        action=p.action,
        subject=p.subject,
        payload=p.payload,
        issued_at=now,
        expires_at=now + 600,
    )
    signature = hardware_wallet.sign_typed_data(typed)  # your signer
    bank.policies.put(agent_id, policy=policy, owner_authorization={...})
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, TypeVar

from pydantic import BaseModel

from agentbank.canonical import to_jsonable
from agentbank.eip712 import OwnerAction
from agentbank.models import OpenPaymentMandate, PolicyDocument, SessionScope
from agentbank.money import MoneyInput, coerce_money

__all__ = [
    "OwnerActionPayload",
    "agent_unfreeze",
    "mandate_issue",
    "org_unfreeze",
    "owner_rotate",
    "policy_loosen",
    "session_grant",
    "spend_key_set",
    "sweep_set",
    "topup_set",
    "treasury_set",
    "vault_withdraw",
    "with_defaults",
]

ModelT = TypeVar("ModelT", bound=BaseModel)


@dataclass(frozen=True)
class OwnerActionPayload:
    """What an owner authorization commits to.

    Attributes:
        action: The owner action, e.g. ``"session.grant"``.
        subject: Id of the resource the action applies to.
        payload: The JSON payload whose canonical Keccak-256 is signed.
    """

    action: OwnerAction
    subject: str
    payload: Any


def with_defaults(model: type[BaseModel], value: Any) -> dict[str, Any]:
    """Validate ``value`` against ``model`` and return its JSON with defaults made explicit.

    Raises:
        pydantic.ValidationError: ``value`` does not match the schema.
    """
    validated = model.model_validate(to_jsonable(value))
    result: dict[str, Any] = to_jsonable(validated)
    return result


def _money(value: MoneyInput) -> dict[str, Any]:
    result: dict[str, Any] = to_jsonable(coerce_money(value))
    return result


def session_grant(
    *, account_id: str, public_key: str, scope: SessionScope | Mapping[str, Any]
) -> OwnerActionPayload:
    """``POST /v1/sessions``: subject = account id; payload ``{account_id, public_key, scope}``."""
    return OwnerActionPayload(
        action="session.grant",
        subject=account_id,
        payload={
            "account_id": account_id,
            "public_key": public_key,
            "scope": with_defaults(SessionScope, scope),
        },
    )


def policy_loosen(agent_id: str, policy: PolicyDocument | Mapping[str, Any]) -> OwnerActionPayload:
    """``PUT /v1/agents/{id}/policy``: subject = agent id; payload = the policy document."""
    return OwnerActionPayload(
        action="policy.loosen", subject=agent_id, payload=with_defaults(PolicyDocument, policy)
    )


def mandate_issue(
    agent_id: str, mandate: OpenPaymentMandate | Mapping[str, Any]
) -> OwnerActionPayload:
    """``POST /v1/mandates``: subject = agent id; payload = the mandate object."""
    return OwnerActionPayload(
        action="mandate.issue",
        subject=agent_id,
        payload=with_defaults(OpenPaymentMandate, mandate),
    )


def agent_unfreeze(agent_id: str, reason: str) -> OwnerActionPayload:
    """``POST /v1/agents/{id}/unfreeze``: subject = agent id; payload ``{reason}``."""
    return OwnerActionPayload(action="agent.unfreeze", subject=agent_id, payload={"reason": reason})


def org_unfreeze(org_id: str, reason: str) -> OwnerActionPayload:
    """``POST /v1/orgs/me/unfreeze``: subject = org id; payload ``{reason}``."""
    return OwnerActionPayload(action="org.unfreeze", subject=org_id, payload={"reason": reason})


def topup_set(
    agent_id: str, *, refill_to: MoneyInput, when_below: MoneyInput, max_per_day: MoneyInput
) -> OwnerActionPayload:
    """``PUT /v1/agents/{id}/auto-topup``: payload ``{refill_to, when_below, max_per_day}``."""
    return OwnerActionPayload(
        action="topup.set",
        subject=agent_id,
        payload={
            "refill_to": _money(refill_to),
            "when_below": _money(when_below),
            "max_per_day": _money(max_per_day),
        },
    )


def sweep_set(
    account_id: str,
    *,
    fund_id: str,
    threshold: MoneyInput,
    max_share_bps: int,
    floor: MoneyInput | None = None,
) -> OwnerActionPayload:
    """``PUT /v1/accounts/{id}/sweep-rule``: payload = the body without ``owner_authorization``."""
    payload: dict[str, Any] = {"fund_id": fund_id}
    if floor is not None:
        payload["floor"] = _money(floor)
    payload["threshold"] = _money(threshold)
    payload["max_share_bps"] = max_share_bps
    return OwnerActionPayload(action="sweep.set", subject=account_id, payload=payload)


def treasury_set(org_id: str, account_id: str) -> OwnerActionPayload:
    """``PUT /v1/orgs/me/treasury``: subject = org id; payload ``{account_id}``."""
    return OwnerActionPayload(
        action="treasury.set", subject=org_id, payload={"account_id": account_id}
    )


def vault_withdraw(vault_id: str, amount: MoneyInput) -> OwnerActionPayload:
    """``POST /v1/vaults/{id}/withdraw``: subject = vault id; payload ``{amount}``."""
    return OwnerActionPayload(
        action="vault.withdraw", subject=vault_id, payload={"amount": _money(amount)}
    )


def owner_rotate(org_id: str, new_owner_address: str) -> OwnerActionPayload:
    """``POST /v1/orgs/me/owner``: subject = org id; payload ``{new_owner_address}``.

    A voluntary rotation, signed by the **current** owner key. (Recovering a
    lost key is an on-chain guardian recovery instead.)
    """
    return OwnerActionPayload(
        action="owner.rotate",
        subject=org_id,
        payload={"new_owner_address": new_owner_address},
    )


def spend_key_set(account_id: str, spend_key_address: str) -> OwnerActionPayload:
    """``PUT /v1/accounts/{id}/spend-key``: payload ``{account_id, spend_key_address}``.

    Pins the agent's x402 spend key in the co-signer; float refills may only
    ever go to it (ADR 0001).
    """
    return OwnerActionPayload(
        action="spend_key.set",
        subject=account_id,
        payload={"account_id": account_id, "spend_key_address": spend_key_address},
    )
