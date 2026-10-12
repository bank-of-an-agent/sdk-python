"""Spend-key permits (EIP-2612 on USDC, ADR 0001).

The permit digest is rebuilt by hand exactly as USDC's FiatToken contract
computes it on-chain (``DOMAIN_SEPARATOR``, ``PERMIT_TYPEHASH``, ``abi.encode``),
and the signature must recover to the spend key from that digest. The viem
vector checks the same signature against the TypeScript ecosystem.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from eth_abi.abi import encode
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_keys.datatypes import Signature
from eth_utils.crypto import keccak

from agentbank import MainnetLockedError, sign_spend_key_permit
from agentbank.errors import BadRequestError
from agentbank.spend_key import (
    EIP2612_NONCES_ABI,
    MAX_UINT256,
    spend_key_permit_typed_data,
)
from tests.conftest import SPEND_KEY, VIEM_VECTORS

SPEND = Account.from_key(SPEND_KEY)
SMART_ACCOUNT = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

#: ``PERMIT_TYPEHASH`` as hard-coded in FiatTokenV2 (EIP2612.sol).
FIAT_TOKEN_PERMIT_TYPEHASH = bytes.fromhex(
    "6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9"
)


def fiat_token_permit_digest(
    *,
    owner: str,
    spender: str,
    value: int,
    nonce: int,
    deadline: int,
    chain_id: int = 84532,
    name: str = "USDC",
    version: str = "2",
    usdc: str = USDC,
) -> bytes:
    """The digest FiatToken's ``permit`` checks the signature against, built by hand."""
    domain_typehash = keccak(
        text="EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    )
    domain_separator = keccak(
        encode(
            ["bytes32", "bytes32", "bytes32", "uint256", "address"],
            [domain_typehash, keccak(text=name), keccak(text=version), chain_id, usdc],
        )
    )
    struct_hash = keccak(
        encode(
            ["bytes32", "address", "address", "uint256", "uint256", "uint256"],
            [FIAT_TOKEN_PERMIT_TYPEHASH, owner, spender, value, nonce, deadline],
        )
    )
    return keccak(b"\x19\x01" + domain_separator + struct_hash)


def recover(digest: bytes, signature: str) -> str:
    raw = bytes.fromhex(signature.removeprefix("0x"))
    v = raw[64] - 27 if raw[64] >= 27 else raw[64]
    signer: str = (
        Signature(raw[:64] + bytes([v]))
        .recover_public_key_from_msg_hash(digest)
        .to_checksum_address()
    )
    return signer


def test_permit_typehash_matches_fiat_token() -> None:
    permit_type = (
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    )
    assert keccak(text=permit_type) == FIAT_TOKEN_PERMIT_TYPEHASH


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({}, {"value": MAX_UINT256, "nonce": 0, "deadline": MAX_UINT256}),
        (
            {"value": 5_000_000, "nonce": 3, "deadline": 4_000_000_000},
            {"value": 5_000_000, "nonce": 3, "deadline": 4_000_000_000},
        ),
        ({"value": "7", "nonce": "1"}, {"value": 7, "nonce": 1, "deadline": MAX_UINT256}),
    ],
)
def test_permit_digest_matches_hand_built_fiat_token_digest(
    overrides: dict[str, Any], expected: dict[str, int]
) -> None:
    permit = sign_spend_key_permit(
        SPEND, account=SMART_ACCOUNT.lower(), chain_id=84532, usdc=USDC.lower(), **overrides
    )
    assert permit["value"] == str(expected["value"])
    assert permit["nonce"] == str(expected["nonce"])
    assert permit["deadline"] == str(expected["deadline"])
    digest = fiat_token_permit_digest(
        owner=SPEND.address,
        spender=SMART_ACCOUNT,
        value=expected["value"],
        nonce=expected["nonce"],
        deadline=expected["deadline"],
    )
    assert recover(digest, permit["signature"]) == SPEND.address
    # The EIP-712 encoding produces exactly the same digest.
    typed = spend_key_permit_typed_data(
        owner=SPEND.address, account=SMART_ACCOUNT, chain_id=84532, usdc=USDC, **overrides
    )
    signable = encode_typed_data(full_message=typed)
    assert keccak(b"\x19" + signable.version + signable.header + signable.body) == digest


def test_permit_domain_comes_from_the_deployment() -> None:
    permit = sign_spend_key_permit(
        SPEND,
        account=SMART_ACCOUNT,
        chain_id=1337,
        usdc="0x5dc0000000000000000000000000000000005dc0",
        name="USD Coin",
        version="3",
    )
    digest = fiat_token_permit_digest(
        owner=SPEND.address,
        spender=SMART_ACCOUNT,
        value=MAX_UINT256,
        nonce=0,
        deadline=MAX_UINT256,
        chain_id=1337,
        name="USD Coin",
        version="3",
        usdc="0x5dc0000000000000000000000000000000005dc0",
    )
    assert recover(digest, permit["signature"]) == SPEND.address


def test_permit_matches_viem() -> None:
    vector = VIEM_VECTORS["permit"]
    message = vector["message"]
    permit = sign_spend_key_permit(
        vector["spend_private_key"],
        account=message["spender"],
        chain_id=vector["domain"]["chainId"],
        usdc=vector["domain"]["verifyingContract"],
        name=vector["domain"]["name"],
        version=vector["domain"]["version"],
        nonce=message["nonce"],
        value=message["value"],
        deadline=message["deadline"],
    )
    assert permit == {
        "value": message["value"],
        "deadline": message["deadline"],
        "nonce": message["nonce"],
        "signature": vector["signature"],
    }


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"value": 0}, "zero allowance"),
        ({"value": -1}, "between 0 and 2"),
        ({"value": MAX_UINT256 + 1}, "between 0 and 2"),
        ({"value": True}, "non-negative integer"),
        ({"value": "1.5"}, "non-negative integer"),
        ({"nonce": -1}, "between 0 and 2"),
        ({"deadline": 1_000}, "deadline is in the past"),
        ({"deadline": int(time.time()) - 1}, "deadline is in the past"),
        ({"account": SPEND.address}, "spender must be the smart account"),
        ({"account": "0x1234"}, "account must be an address"),
        ({"usdc": "usdc"}, "usdc must be an address"),
    ],
)
def test_permit_validation(overrides: dict[str, Any], message: str) -> None:
    args: dict[str, Any] = {"account": SMART_ACCOUNT, "chain_id": 84532, "usdc": USDC, **overrides}
    with pytest.raises(BadRequestError, match=message) as excinfo:
        sign_spend_key_permit(SPEND, **args)
    assert excinfo.value.code == "invalid_request"


def test_permit_refuses_mainnets() -> None:
    with pytest.raises(MainnetLockedError):
        sign_spend_key_permit(SPEND, account=SMART_ACCOUNT, chain_id=8453, usdc=USDC)


def test_typed_data_shape() -> None:
    typed = spend_key_permit_typed_data(
        owner=SPEND.address.lower(), account=SMART_ACCOUNT, chain_id=84532, usdc=USDC
    )
    assert typed["primaryType"] == "Permit"
    assert typed["domain"] == {
        "name": "USDC",
        "version": "2",
        "chainId": 84532,
        "verifyingContract": USDC,
    }
    assert typed["message"]["owner"] == SPEND.address
    assert [f["name"] for f in typed["types"]["Permit"]] == [
        "owner",
        "spender",
        "value",
        "nonce",
        "deadline",
    ]
    assert EIP2612_NONCES_ABI[0]["name"] == "nonces"
