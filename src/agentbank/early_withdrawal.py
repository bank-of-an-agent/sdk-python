"""Early withdrawal from a time-locked vault: ``TimeLockVaults``' EIP-712 ``EarlyWithdrawal``.

Before a locked vault's ``unlock_at`` only the vault owner (the org owner key)
can release its funds, and the ``TimeLockVaults`` contract checks that
signature itself, so the generic ``vault.withdraw`` owner authorization does
not apply. The API runs a challenge-response instead:

1. ``POST /v1/vaults/{id}/withdraw`` without ``owner_authorization`` fails with
   ``owner_signature_required``; the problem's ``typed_data`` extension
   describes the ``EarlyWithdrawal`` to sign (integers as decimal strings).
2. The owner checks it against what was asked for and signs typed data built
   here from the checked values, never the API's object
   (:func:`early_withdrawal_typed_data`, :func:`sign_early_withdrawal`).
3. The withdrawal is sent again, under a new idempotency key, with
   ``owner_authorization = {signer, signature, issued_at, expires_at}`` where
   ``expires_at`` is the signed ``deadline``. The API answers with the vault
   and its ``pending_operation_id``: the owner operation that carries the
   signature on-chain, which the owner then signs like any other.

``AgentBank.withdraw_vault`` runs all of it; ``vaults.withdraw(owner=...)``
runs steps 1 to 3 and leaves the owner operation to the caller. The checks are
those of the console's ``vault-withdrawal.ts``.
"""

from __future__ import annotations

import copy
import re
import time
from collections.abc import Mapping
from typing import Any, Final

from eth_utils.address import is_hex_address, to_checksum_address

from agentbank.chains import assert_testnet
from agentbank.errors import BadRequestError
from agentbank.keys import SessionKey, SignerLike, sign_typed_data, to_signer
from agentbank.money import MoneyInput, to_minor

__all__ = [
    "EARLY_WITHDRAWAL_TTL_SECONDS",
    "EARLY_WITHDRAWAL_TYPES",
    "MAX_EARLY_WITHDRAWAL_DEADLINE_SECONDS",
    "TIME_LOCK_VAULTS_EIP712",
    "early_withdrawal_typed_data",
    "sign_early_withdrawal",
]

#: EIP-712 domain name and version of the ``TimeLockVaults`` contract.
TIME_LOCK_VAULTS_EIP712: Final = {"name": "AgentBank TimeLockVaults", "version": "1"}

#: EIP-712 types the vault owner signs for an early withdrawal
#: (``EARLY_WITHDRAWAL_TYPEHASH`` in ``TimeLockVaults.sol``).
EARLY_WITHDRAWAL_TYPES: Final = {
    "EarlyWithdrawal": [
        {"name": "vaultId", "type": "uint256"},
        {"name": "amount", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
    ]
}

#: The API's challenges carry a deadline 15 minutes after they are issued.
EARLY_WITHDRAWAL_TTL_SECONDS: Final = 15 * 60
#: Deadlines further away than an hour are refused: the signature would stay usable too long.
MAX_EARLY_WITHDRAWAL_DEADLINE_SECONDS: Final = 60 * 60

_MAX_UINT256: Final = 2**256 - 1
_UINT_RE: Final = re.compile(r"[0-9]{1,78}")
_DOMAIN_TYPES: Final = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]


def _refuse(reason: str) -> BadRequestError:
    return BadRequestError("invalid_request", f"Refusing to sign the early withdrawal: {reason}")


def _uint(value: object) -> int | None:
    """An unsigned 256-bit integer given as an ``int`` or a decimal string, else ``None``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and _UINT_RE.fullmatch(value):
        parsed = int(value)
    else:
        return None
    return parsed if 0 <= parsed <= _MAX_UINT256 else None


def _address(value: object) -> str | None:
    if isinstance(value, str) and is_hex_address(value):
        return str(to_checksum_address(value))
    return None


def early_withdrawal_typed_data(
    challenge: Mapping[str, Any],
    *,
    chain_id: int,
    contract: str | None,
    onchain_id: int | str | None,
    amount: MoneyInput,
    now: int | None = None,
) -> dict[str, Any]:
    """Check the API's ``EarlyWithdrawal`` description and build the typed data to sign.

    Refuses anything but exactly the withdrawal that was asked for: another
    contract, chain, vault or amount, unexpected fields, or a deadline that has
    passed or is more than an hour away. The result is built from the checked
    values (integers as ``int``, ``EIP712Domain`` included), ready for
    ``eth_account``'s ``encode_typed_data(full_message=...)`` or a wallet's
    ``eth_signTypedData_v4``.

    Args:
        challenge: The ``typed_data`` extension of the API's
            ``owner_signature_required`` problem (``error.extensions["typed_data"]``).
        chain_id: This deployment's chain id (``GET /v1/meta`` ``chain_id``).
        contract: The vault's ``contract_address`` (or ``meta.contracts["vaults"]``).
        onchain_id: The vault's ``onchain_id``.
        amount: The amount being withdrawn: decimal string (USDC), ``Decimal`` or ``Money``.
        now: Current Unix time in seconds (default: the system clock).

    Raises:
        BadRequestError: ``invalid_request`` naming what does not match.
        MainnetLockedError: ``chain_id`` is a mainnet.
    """
    assert_testnet(chain_id)
    domain = challenge.get("domain")
    message = challenge.get("message")
    if (
        challenge.get("primaryType") != "EarlyWithdrawal"
        or not isinstance(domain, Mapping)
        or not isinstance(message, Mapping)
    ):
        raise _refuse("the API did not describe a TimeLockVaults early withdrawal")
    if (
        domain.get("name") != TIME_LOCK_VAULTS_EIP712["name"]
        or domain.get("version") != TIME_LOCK_VAULTS_EIP712["version"]
    ):
        raise _refuse("the signing domain is not TimeLockVaults")
    if _uint(domain.get("chainId")) != chain_id:
        raise _refuse(
            f"it is for chain {domain.get('chainId')!r}, not this deployment's chain {chain_id}"
        )
    verifying_contract = _address(domain.get("verifyingContract"))
    expected_contract = _address(contract)
    if verifying_contract is None or verifying_contract != expected_contract:
        raise _refuse("the verifying contract is not this vault's contract")
    types = challenge.get("types")
    described_fields = types.get("EarlyWithdrawal") if isinstance(types, Mapping) else None
    if (
        described_fields is not None
        and described_fields != EARLY_WITHDRAWAL_TYPES["EarlyWithdrawal"]
    ):
        raise _refuse("the EarlyWithdrawal fields differ from TimeLockVaults'")
    vault_id = _uint(message.get("vaultId"))
    minor = _uint(message.get("amount"))
    nonce = _uint(message.get("nonce"))
    deadline = _uint(message.get("deadline"))
    if vault_id is None or minor is None or nonce is None or deadline is None:
        raise _refuse("the withdrawal fields are not unsigned integers")
    if onchain_id is None or vault_id != _uint(onchain_id):
        raise _refuse(f"it names vault {vault_id} on-chain, not this vault ({onchain_id})")
    requested = to_minor(amount)
    if minor != requested:
        raise _refuse(f"its amount ({minor} minor units) differs from the requested {requested}")
    current = int(time.time()) if now is None else now
    if not current < deadline <= current + MAX_EARLY_WITHDRAWAL_DEADLINE_SECONDS:
        raise _refuse("its deadline is in the past or more than an hour away")
    return {
        "types": {
            "EIP712Domain": copy.deepcopy(_DOMAIN_TYPES),
            **copy.deepcopy(EARLY_WITHDRAWAL_TYPES),
        },
        "primaryType": "EarlyWithdrawal",
        "domain": {
            **TIME_LOCK_VAULTS_EIP712,
            "chainId": chain_id,
            "verifyingContract": verifying_contract,
        },
        "message": {"vaultId": vault_id, "amount": minor, "nonce": nonce, "deadline": deadline},
    }


def sign_early_withdrawal(
    owner: SignerLike | SessionKey,
    typed_data: Mapping[str, Any],
    *,
    issued_at: int | None = None,
) -> dict[str, Any]:
    """Sign a checked ``EarlyWithdrawal`` with the owner key.

    Returns the ``owner_authorization`` to resend with the withdrawal:
    ``{signer, signature, issued_at, expires_at}``, where ``expires_at`` is the
    signed ``deadline`` (the API rebuilds the typed data from it).

    Args:
        owner: The org owner key, which owns every vault.
        typed_data: The result of :func:`early_withdrawal_typed_data`.
        issued_at: Unix seconds. Defaults to when the API issued the challenge
            (``deadline`` minus 15 minutes), so that resending the same signed
            request under the same idempotency key replays it instead of
            conflicting. The API does not check it for early withdrawals.

    Raises:
        MainnetLockedError: The typed data is for a mainnet.
    """
    assert_testnet(int(typed_data["domain"]["chainId"]))
    signer = to_signer(owner)
    deadline = int(typed_data["message"]["deadline"])
    return {
        "signer": signer.address,
        "signature": sign_typed_data(signer, dict(typed_data)),
        "issued_at": (
            max(0, deadline - EARLY_WITHDRAWAL_TTL_SECONDS) if issued_at is None else issued_at
        ),
        "expires_at": deadline,
    }
