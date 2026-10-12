"""EIP-712 typed data: owner authorizations and EIP-3009 transfer authorizations.

**Owner authorizations.** Every change that needs the principal's owner key
(installing a session, loosening a policy, issuing a mandate, unfreezing, ...) is
an EIP-712 ``OwnerAuthorization {action, subject, payloadHash, issuedAt,
expiresAt}`` in the domain ``{name: "Agent Bank", version: "1", chainId}``, where
``payloadHash`` is the Keccak-256 of the canonical JSON of the payload. This
module is byte-compatible with ``eip712.ts`` in ``@agentbank/core``.

**EIP-3009.** x402 payments are ``TransferWithAuthorization`` messages signed by
the agent's spend key in the token's own EIP-712 domain.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any, Final, Literal, get_args

from eth_account import Account
from eth_account.messages import encode_typed_data

from agentbank.canonical import canonical_keccak
from agentbank.chains import assert_testnet
from agentbank.errors import AgentBankError
from agentbank.keys import EthSigner, SessionKey, SignerLike, sign_typed_data, to_signer

__all__ = [
    "MAX_OWNER_AUTHORIZATION_SECONDS",
    "OWNER_ACTIONS",
    "OWNER_AUTHORIZATION_TYPES",
    "TRANSFER_WITH_AUTHORIZATION_TYPES",
    "OwnerAction",
    "agent_bank_domain",
    "owner_authorization_typed_data",
    "owner_authorize",
    "transfer_with_authorization_typed_data",
    "verify_owner_authorization",
]

OwnerAction = Literal[
    "session.grant",
    "policy.loosen",
    "mandate.issue",
    "agent.unfreeze",
    "org.unfreeze",
    "topup.set",
    "sweep.set",
    "treasury.set",
    "vault.withdraw",
]

#: Every action an owner authorization can carry.
OWNER_ACTIONS: Final[tuple[str, ...]] = get_args(OwnerAction)

#: Maximum validity window of one owner authorization (15 minutes).
MAX_OWNER_AUTHORIZATION_SECONDS: Final = 15 * 60

EIP712_DOMAIN_FIELDS: Final = {
    "name": {"name": "name", "type": "string"},
    "version": {"name": "version", "type": "string"},
    "chainId": {"name": "chainId", "type": "uint256"},
    "verifyingContract": {"name": "verifyingContract", "type": "address"},
}

OWNER_AUTHORIZATION_TYPES: Final = {
    "OwnerAuthorization": [
        {"name": "action", "type": "string"},
        {"name": "subject", "type": "string"},
        {"name": "payloadHash", "type": "bytes32"},
        {"name": "issuedAt", "type": "uint64"},
        {"name": "expiresAt", "type": "uint64"},
    ]
}

TRANSFER_WITH_AUTHORIZATION_TYPES: Final = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}


def agent_bank_domain(chain_id: int) -> dict[str, Any]:
    """The Agent Bank EIP-712 domain for ``chain_id``."""
    return {"name": "Agent Bank", "version": "1", "chainId": chain_id}


def _domain_types(domain: Mapping[str, Any]) -> list[dict[str, str]]:
    return [EIP712_DOMAIN_FIELDS[key] for key in EIP712_DOMAIN_FIELDS if key in domain]


def owner_authorization_typed_data(
    *,
    chain_id: int,
    action: OwnerAction | str,
    subject: str,
    payload: Any,
    issued_at: int,
    expires_at: int,
) -> dict[str, Any]:
    """Build the full EIP-712 message of an owner authorization.

    The result includes ``EIP712Domain`` in ``types``, so it can be passed to
    ``eth_signTypedData_v4`` (hardware wallets, browser wallets) or to
    ``eth_account.messages.encode_typed_data(full_message=...)``.

    Args:
        chain_id: Chain of the account the action applies to (Base Sepolia: 84532).
        action: One of :data:`OWNER_ACTIONS`.
        subject: The id the action applies to (agent id, account id, ...).
        payload: The exact payload being authorized; hashed with canonical JSON.
        issued_at: Unix seconds.
        expires_at: Unix seconds; at most 15 minutes after ``issued_at``.
    """
    domain = agent_bank_domain(chain_id)
    return {
        "types": {"EIP712Domain": _domain_types(domain), **OWNER_AUTHORIZATION_TYPES},
        "primaryType": "OwnerAuthorization",
        "domain": domain,
        "message": {
            "action": action,
            "subject": subject,
            "payloadHash": canonical_keccak(payload),
            "issuedAt": issued_at,
            "expiresAt": expires_at,
        },
    }


def owner_authorize(  # noqa: PLR0917 - positional order is part of the public API
    owner_account: SignerLike | SessionKey,
    chain_id: int,
    action: OwnerAction | str,
    subject: str,
    payload: Any,
    ttl_seconds: int = 600,
    *,
    issued_at: int | None = None,
) -> dict[str, Any]:
    """Sign an owner authorization with the principal's owner key.

    Use it for requests that carry an ``owner_authorization`` (session grants,
    policy loosening, mandates, unfreezing, treasury and vault changes). The
    payload must be exactly what the API hashes for that action; the resource
    methods that accept ``owner=`` build it for you.

    Args:
        owner_account: The owner key (``eth_account`` account, signer adapter, or
            private key). Testnet development keys only; production owner keys
            belong in a hardware wallet that signs :func:`owner_authorization_typed_data`.
        chain_id: Chain id of the account (testnets only; mainnets are refused).
        action: One of :data:`OWNER_ACTIONS`.
        subject: The id the action applies to.
        payload: The payload being authorized.
        ttl_seconds: Validity window, 1 to 900 seconds (default 600).
        issued_at: Unix seconds; defaults to now.

    Returns:
        The wire ``OwnerAuthorization``:
        ``{"signer", "signature", "issued_at", "expires_at"}``.

    Raises:
        ValueError: ``ttl_seconds`` is outside 1..900 or ``action`` is unknown.
        MainnetLockedError: ``chain_id`` is a mainnet.
    """
    if action not in OWNER_ACTIONS:
        raise ValueError(f"Unknown owner action {action!r}; expected one of {OWNER_ACTIONS}")
    if not 0 < ttl_seconds <= MAX_OWNER_AUTHORIZATION_SECONDS:
        raise ValueError("ttl_seconds must be between 1 and 900 (15 minutes)")
    assert_testnet(chain_id)
    signer: EthSigner = to_signer(owner_account)
    start = int(time.time()) if issued_at is None else issued_at
    typed = owner_authorization_typed_data(
        chain_id=chain_id,
        action=action,
        subject=subject,
        payload=payload,
        issued_at=start,
        expires_at=start + ttl_seconds,
    )
    return {
        "signer": signer.address,
        "signature": sign_typed_data(signer, typed),
        "issued_at": start,
        "expires_at": start + ttl_seconds,
    }


def verify_owner_authorization(
    *,
    owner: str,
    authorization: Mapping[str, Any],
    chain_id: int,
    action: OwnerAction | str,
    subject: str,
    payload: Any,
    now: int | None = None,
) -> None:
    """Verify an EOA owner authorization (mirrors ``verifyOwnerAuthorization``).

    Args:
        owner: The org's owner address.
        authorization: The wire ``OwnerAuthorization``
            (``signer``, ``signature``, ``issued_at``, ``expires_at``).
        chain_id: Chain id of the EIP-712 domain.
        action: The expected action.
        subject: The expected subject.
        payload: The payload that should have been signed.
        now: Unix seconds; defaults to now.

    Raises:
        AgentBankError: ``owner_signature_required`` when signed by another key,
            ``signature_invalid`` for bad windows, expiry or signatures.
    """
    signer = str(authorization["signer"])
    issued_at = int(authorization["issued_at"])
    expires_at = int(authorization["expires_at"])
    if signer.lower() != owner.lower():
        raise AgentBankError(
            "owner_signature_required", "Authorization was not signed by the org owner key"
        )
    current = int(time.time()) if now is None else now
    if expires_at <= issued_at or expires_at - issued_at > MAX_OWNER_AUTHORIZATION_SECONDS:
        raise AgentBankError(
            "signature_invalid", "Owner authorization window must be at most 15 minutes"
        )
    if current < issued_at - 60 or current > expires_at:
        raise AgentBankError("signature_invalid", "Owner authorization is expired or not yet valid")
    typed = owner_authorization_typed_data(
        chain_id=chain_id,
        action=action,
        subject=subject,
        payload=payload,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    try:
        recovered: str = Account.recover_message(
            encode_typed_data(full_message=typed), signature=str(authorization["signature"])
        )
    except Exception:  # any decoding or recovery failure means an invalid signature
        recovered = ""
    if recovered.lower() != owner.lower():
        raise AgentBankError("signature_invalid", "Owner authorization signature is invalid")


def transfer_with_authorization_typed_data(
    domain: Mapping[str, Any], authorization: Mapping[str, Any]
) -> dict[str, Any]:
    """Build the EIP-3009 ``TransferWithAuthorization`` typed data for a spend-key signature.

    Args:
        domain: The token's EIP-712 domain
            (``name``, ``version``, ``chainId``, ``verifyingContract``).
        authorization: ``from``, ``to``, ``value``, ``validAfter``, ``validBefore``
            (integers or decimal strings) and ``nonce`` (32-byte hex).
    """
    clean_domain = {key: domain[key] for key in EIP712_DOMAIN_FIELDS if key in domain}
    return {
        "types": {
            "EIP712Domain": _domain_types(clean_domain),
            **TRANSFER_WITH_AUTHORIZATION_TYPES,
        },
        "primaryType": "TransferWithAuthorization",
        "domain": clean_domain,
        "message": {
            "from": authorization["from"],
            "to": authorization["to"],
            "value": int(authorization["value"]),
            "validAfter": int(authorization["validAfter"]),
            "validBefore": int(authorization["validBefore"]),
            "nonce": authorization["nonce"],
        },
    }
