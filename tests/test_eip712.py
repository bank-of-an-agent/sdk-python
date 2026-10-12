"""Owner authorizations (EIP-712) and EIP-3009 typed data."""

from __future__ import annotations

import pytest
from eth_account import Account

from agentbank import MainnetLockedError
from agentbank.eip712 import (
    OWNER_ACTIONS,
    owner_authorization_typed_data,
    owner_authorize,
    transfer_with_authorization_typed_data,
    verify_owner_authorization,
)
from agentbank.errors import AgentBankError
from agentbank.keys import SessionKey, sign_typed_data
from tests.conftest import OWNER_KEY, VIEM_VECTORS

OWNER = Account.from_key(OWNER_KEY)
OTHER = SessionKey.generate()
NOW = 1_790_000_000
PAYLOAD = {"agent": "agt_1", "limits": {"per_day": "500.00"}}


def authorize(**overrides: object) -> dict[str, object]:
    args: dict[str, object] = {
        "owner_account": OWNER,
        "chain_id": 84532,
        "action": "policy.loosen",
        "subject": "agt_1",
        "payload": PAYLOAD,
        "ttl_seconds": 600,
        "issued_at": NOW,
    }
    args.update(overrides)
    return owner_authorize(**args)  # type: ignore[arg-type]


def verify(authorization: dict[str, object], **overrides: object) -> None:
    args: dict[str, object] = {
        "owner": OWNER.address,
        "authorization": authorization,
        "chain_id": 84532,
        "action": "policy.loosen",
        "subject": "agt_1",
        "payload": PAYLOAD,
        "now": NOW + 1,
    }
    args.update(overrides)
    verify_owner_authorization(**args)  # type: ignore[arg-type]


def test_owner_actions_match_the_typescript_list() -> None:
    assert OWNER_ACTIONS == (
        "session.grant",
        "policy.loosen",
        "mandate.issue",
        "agent.unfreeze",
        "org.unfreeze",
        "topup.set",
        "sweep.set",
        "treasury.set",
        "vault.withdraw",
    )


def test_typed_data_is_eth_sign_typed_data_v4_ready() -> None:
    typed = owner_authorization_typed_data(
        chain_id=84532,
        action="session.grant",
        subject="acct_1",
        payload={"a": 1},
        issued_at=NOW,
        expires_at=NOW + 60,
    )
    assert typed["primaryType"] == "OwnerAuthorization"
    assert typed["domain"] == {"name": "Agent Bank", "version": "1", "chainId": 84532}
    assert [f["name"] for f in typed["types"]["EIP712Domain"]] == ["name", "version", "chainId"]
    assert typed["message"]["issuedAt"] == NOW


def test_valid_authorization_verifies() -> None:
    authorization = authorize()
    assert authorization["signer"] == OWNER.address
    assert authorization["expires_at"] == NOW + 600
    verify(authorization)


def test_session_key_and_private_key_strings_are_accepted_as_owner() -> None:
    from_hex = authorize(owner_account=OWNER_KEY)
    from_session_key = authorize(owner_account=SessionKey.from_private_key(OWNER_KEY))
    assert from_hex == from_session_key == authorize()


def test_rejects_altered_payloads_other_signers_and_bad_windows() -> None:
    authorization = authorize()
    with pytest.raises(AgentBankError, match="invalid") as altered:
        verify(authorization, payload={**PAYLOAD, "limits": {"per_day": "50000.00"}})
    assert altered.value.code == "signature_invalid"
    with pytest.raises(AgentBankError, match="owner key") as other:
        verify({**authorization, "signer": OTHER.address})
    assert other.value.code == "owner_signature_required"
    with pytest.raises(AgentBankError, match="15 minutes"):
        verify({**authorization, "expires_at": NOW + 7200})
    with pytest.raises(AgentBankError, match="expired"):
        verify(authorization, now=NOW + 601)
    with pytest.raises(AgentBankError, match="invalid"):
        verify({**authorization, "signature": "0x1234"})
    other_signature = authorize(owner_account=OTHER)
    with pytest.raises(AgentBankError, match="invalid"):
        verify({**authorization, "signature": other_signature["signature"]})


def test_owner_authorize_validates_its_inputs() -> None:
    with pytest.raises(ValueError, match="900"):
        authorize(ttl_seconds=901)
    with pytest.raises(ValueError, match="900"):
        authorize(ttl_seconds=0)
    with pytest.raises(ValueError, match="Unknown owner action"):
        authorize(action="money.print")
    with pytest.raises(MainnetLockedError):
        authorize(chain_id=8453)
    with pytest.raises(AgentBankError, match="not supported"):
        authorize(chain_id=999_999)


def test_default_issued_at_is_now() -> None:
    authorization = owner_authorize(OWNER, 84532, "session.grant", "acct_1", {"x": 1})
    issued_at = authorization["issued_at"]
    assert isinstance(issued_at, int)
    assert authorization["expires_at"] == issued_at + 600


def test_eip3009_signature_matches_viem() -> None:
    vector = VIEM_VECTORS["eip3009"]
    spend = Account.from_key(vector["spend_private_key"])
    assert spend.address == vector["spend_address"]
    typed = transfer_with_authorization_typed_data(vector["domain"], vector["authorization"])
    assert typed["message"]["value"] == 10_000
    assert sign_typed_data(spend, typed) == vector["signature"]


def test_eip3009_domain_ignores_unknown_keys() -> None:
    vector = VIEM_VECTORS["eip3009"]
    typed = transfer_with_authorization_typed_data(
        {**vector["domain"], "salt": "ignored"}, vector["authorization"]
    )
    assert "salt" not in typed["domain"]
