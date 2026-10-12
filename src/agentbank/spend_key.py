"""Spend-key float recovery: the EIP-2612 USDC permit signed by the spend key (ADR 0001).

Agents pay x402 from a per-agent EOA, the **spend key**, which holds a small
USDC float outside the smart account. So that the owner can always sweep that
float back without the agent, the spend key signs an EIP-2612 USDC ``permit``
when it is provisioned: owner = the spend key, spender = the agent's smart
account, value and deadline = max uint256 by default. The account's setup
owner operation executes it on-chain; afterwards the account (or the owner's
exit tool) can ``transferFrom`` the float home.

The spender is the smart account's counterfactual address, which only the API
computes, so the order is: create the account, sign the permit for
``account.address``, ``PUT /v1/accounts/{id}/spend-key``, install the first
session. ``AgentBank.provision_spend_key`` and ``AgentBank.setup_agent_account``
do all of this. Compatible with ``spend-key.ts`` in ``@agentbank/sdk``.
"""

from __future__ import annotations

import time
from typing import Any, Final

from eth_utils.address import is_hex_address, to_checksum_address

from agentbank.chains import assert_testnet
from agentbank.errors import BadRequestError
from agentbank.keys import SessionKey, SignerLike, sign_typed_data, to_signer

__all__ = [
    "EIP2612_NONCES_ABI",
    "EIP2612_PERMIT_TYPES",
    "MAX_UINT256",
    "sign_spend_key_permit",
    "spend_key_permit_typed_data",
]

#: ``2**256 - 1``: the default permit value (allowance) and deadline.
MAX_UINT256: Final = 2**256 - 1

#: EIP-712 types of an EIP-2612 ``Permit`` (as implemented by USDC FiatToken).
EIP2612_PERMIT_TYPES: Final = {
    "Permit": [
        {"name": "owner", "type": "address"},
        {"name": "spender", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
    ]
}

#: ABI of ``nonces(owner)``, to read a spend key's current permit nonce with your
#: own RPC client when the key is not fresh.
EIP2612_NONCES_ABI: Final = [
    {
        "type": "function",
        "name": "nonces",
        "stateMutability": "view",
        "inputs": [{"name": "owner", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    }
]

_DOMAIN_TYPES: Final = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]


def _uint(value: int | str, field: str) -> int:
    if isinstance(value, bool):
        raise BadRequestError("invalid_request", f"{field} must be a non-negative integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise BadRequestError(
            "invalid_request", f"{field} must be a non-negative integer"
        ) from None
    if not 0 <= parsed <= MAX_UINT256:
        raise BadRequestError("invalid_request", f"{field} must be between 0 and 2^256-1")
    return parsed


def _address(value: str, field: str) -> str:
    if not is_hex_address(value):
        raise BadRequestError("invalid_request", f"{field} must be an address")
    return str(to_checksum_address(value))


def spend_key_permit_typed_data(
    *,
    owner: str,
    account: str,
    chain_id: int,
    usdc: str,
    name: str = "USDC",
    version: str = "2",
    nonce: int | str = 0,
    value: int | str = MAX_UINT256,
    deadline: int | str = MAX_UINT256,
) -> dict[str, Any]:
    """The EIP-712 typed data of a spend-key permit (``eth_signTypedData_v4`` ready).

    Args:
        owner: The spend key address (permit owner and signer).
        account: The agent's smart account address (spender).
        chain_id: Chain id of USDC (testnets only).
        usdc: USDC contract address (verifying contract), e.g. ``meta.usdc.address``.
        name: USDC EIP-712 domain name (``meta.usdc.eip712_name``, default ``"USDC"``).
        version: USDC EIP-712 domain version (``meta.usdc.eip712_version``, default ``"2"``).
        nonce: USDC ``nonces(spend key)`` (0 for a fresh key).
        value: Allowance in USDC minor units (default max uint256; must be positive).
        deadline: Unix-seconds deadline (default max uint256, i.e. never expires).

    Raises:
        BadRequestError: Invalid addresses or numbers, a zero allowance, a past
            deadline, or a spender equal to the spend key.
        MainnetLockedError: ``chain_id`` is a mainnet.
    """
    assert_testnet(chain_id)
    permit_owner = _address(owner, "spend_key")
    spender = _address(account, "account")
    if permit_owner == spender:
        raise BadRequestError(
            "invalid_request", "The spender must be the smart account, not the spend key"
        )
    allowance = _uint(value, "value")
    if allowance == 0:
        raise BadRequestError(
            "invalid_request", "A zero allowance would not let the owner sweep the float back"
        )
    expiry = _uint(deadline, "deadline")
    if expiry <= int(time.time()):
        raise BadRequestError("invalid_request", "deadline is in the past")
    return {
        "types": {"EIP712Domain": _DOMAIN_TYPES, **EIP2612_PERMIT_TYPES},
        "primaryType": "Permit",
        "domain": {
            "name": name,
            "version": version,
            "chainId": chain_id,
            "verifyingContract": _address(usdc, "usdc"),
        },
        "message": {
            "owner": permit_owner,
            "spender": spender,
            "value": allowance,
            "nonce": _uint(nonce, "nonce"),
            "deadline": expiry,
        },
    }


def sign_spend_key_permit(
    spend_key: SignerLike | SessionKey,
    *,
    account: str,
    chain_id: int,
    usdc: str,
    name: str = "USDC",
    version: str = "2",
    nonce: int | str = 0,
    value: int | str = MAX_UINT256,
    deadline: int | str = MAX_UINT256,
) -> dict[str, str]:
    """Sign the spend key's float-recovery permit (EIP-2612 on USDC).

    Owner = the spend key, spender = the agent's smart account, value and
    deadline max uint256 by default. Returns the wire ``SpendKeyPermit``
    (decimal strings plus the signature) for ``PUT /v1/accounts/{id}/spend-key``::

        meta = bank.meta()
        permit = sign_spend_key_permit(
            spend_key,
            account=account.address,
            chain_id=account.chain_id,
            usdc=meta.usdc.address,
            name=meta.usdc.eip712_name,
            version=meta.usdc.eip712_version,
        )

    Args:
        spend_key: The agent's spend key (the permit owner and signer).
        account: The agent's smart account address (spender).
        chain_id: Chain id of USDC (testnets only).
        usdc: USDC contract address (verifying contract).
        name: USDC EIP-712 domain name (default ``"USDC"``).
        version: USDC EIP-712 domain version (default ``"2"``).
        nonce: USDC ``nonces(spend key)`` at signing time (0 for a fresh key).
        value: Allowance in USDC minor units (default max uint256).
        deadline: Unix-seconds deadline (default max uint256).

    Raises:
        BadRequestError: See :func:`spend_key_permit_typed_data`.
        MainnetLockedError: ``chain_id`` is a mainnet.
    """
    signer = to_signer(spend_key)
    typed = spend_key_permit_typed_data(
        owner=signer.address,
        account=account,
        chain_id=chain_id,
        usdc=usdc,
        name=name,
        version=version,
        nonce=nonce,
        value=value,
        deadline=deadline,
    )
    message = typed["message"]
    return {
        "value": str(message["value"]),
        "deadline": str(message["deadline"]),
        "nonce": str(message["nonce"]),
        "signature": sign_typed_data(signer, typed),
    }
