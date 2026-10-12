"""Early withdrawal from a locked vault: TimeLockVaults' EIP-712 ``EarlyWithdrawal``.

The digest is rebuilt by hand as ``TimeLockVaults.earlyWithdrawalDigest`` computes
it on-chain (OpenZeppelin ``_hashTypedDataV4``), the signature is checked
against a viem vector, and a fake API runs the challenge-response exactly as
``apps/api/src/routes/savings.ts`` does: a 403 ``owner_signature_required``
carrying ``typed_data``, then recovery of the signer with ``deadline`` taken
from ``owner_authorization.expires_at``.
"""

from __future__ import annotations

import copy
import json
import time
from typing import Any

import httpx
import pytest
import respx
from eth_abi.abi import encode
from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data
from eth_utils.crypto import keccak

from agentbank import (
    AgentBank,
    AsyncAgentBank,
    BadRequestError,
    MainnetLockedError,
    OwnerSignatureRequiredError,
    VaultWithdrawalResult,
    early_withdrawal_typed_data,
    owner_payloads,
    sign_early_withdrawal,
)
from agentbank.early_withdrawal import (
    EARLY_WITHDRAWAL_TTL_SECONDS,
    EARLY_WITHDRAWAL_TYPES,
    TIME_LOCK_VAULTS_EIP712,
)
from agentbank.money import parse_amount
from tests.conftest import ACCOUNT_ID, OWNER_ADDRESS, OWNER_KEY, VIEM_VECTORS
from tests.factories import example, id_for
from tests.test_principal_flows import meta_json
from tests.test_spend_key import recover

VAULTS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
VAULT_ID = id_for("vlt")
OOP_ID = id_for("oop")
HASH = "0x" + "e7" * 32
ONCHAIN_ID = 7
NONCE = 3
AMOUNT = "15.00"
MINOR = 15_000_000

#: The type string hashed into ``EARLY_WITHDRAWAL_TYPEHASH`` in TimeLockVaults.sol.
CONTRACT_TYPE = "EarlyWithdrawal(uint256 vaultId,uint256 amount,uint256 nonce,uint256 deadline)"


def time_lock_vaults_digest(
    *,
    vault_id: int,
    amount: int,
    nonce: int,
    deadline: int,
    chain_id: int = 84532,
    contract: str = VAULTS,
) -> bytes:
    """``TimeLockVaults.earlyWithdrawalDigest``, built by hand."""
    domain_separator = keccak(
        encode(
            ["bytes32", "bytes32", "bytes32", "uint256", "address"],
            [
                keccak(
                    text="EIP712Domain(string name,string version,uint256 chainId,"
                    "address verifyingContract)"
                ),
                keccak(text="AgentBank TimeLockVaults"),
                keccak(text="1"),
                chain_id,
                contract,
            ],
        )
    )
    struct_hash = keccak(
        encode(
            ["bytes32", "uint256", "uint256", "uint256", "uint256"],
            [keccak(text=CONTRACT_TYPE), vault_id, amount, nonce, deadline],
        )
    )
    return keccak(b"\x19\x01" + domain_separator + struct_hash)


def challenge(*, deadline: int | None = None, **message: Any) -> dict[str, Any]:
    """The ``typed_data`` extension of the API's ``owner_signature_required`` problem."""
    return {
        "domain": {**TIME_LOCK_VAULTS_EIP712, "chainId": 84532, "verifyingContract": VAULTS},
        "types": copy.deepcopy(EARLY_WITHDRAWAL_TYPES),
        "primaryType": "EarlyWithdrawal",
        "message": {
            "vaultId": str(ONCHAIN_ID),
            "amount": str(MINOR),
            "nonce": str(NONCE),
            "deadline": str(deadline if deadline is not None else int(time.time()) + 900),
            **message,
        },
    }


def vault_json(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "id": VAULT_ID,
        "account_id": ACCOUNT_ID,
        "kind": "locked",
        "unlock_at": "2099-01-01T00:00:00Z",
        "contract_address": VAULTS,
        "onchain_id": str(ONCHAIN_ID),
        "pending_operation_id": None,
    }
    fields.update(overrides)
    return example("Vault", **fields)


def operation_json(status: str, **overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "id": OOP_ID,
        "account_id": ACCOUNT_ID,
        "purpose": "vault.withdraw",
        "subject_id": VAULT_ID,
        "status": status,
        "chain_id": 84532,
        "user_op_hash": HASH,
    }
    fields.update(overrides)
    return example("OwnerOperation", **fields)


class FakeVaultAPI:
    """``POST /v1/vaults/{id}/withdraw`` as the API implements it (savings.ts)."""

    def __init__(self, *, locked: bool = True, described: dict[str, Any] | None = None) -> None:
        self.locked = locked
        self.described = described
        self.issued: dict[str, Any] | None = None
        self.calls: list[tuple[str, dict[str, Any]]] = []

    @property
    def deadline(self) -> int:
        """The deadline of the last challenge the API issued."""
        assert self.issued is not None
        return int(self.issued["message"]["deadline"])

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body: dict[str, Any] = json.loads(request.content)
        self.calls.append((request.headers["idempotency-key"], body))
        if not self.locked:
            return httpx.Response(200, json=vault_json(kind="goal", unlock_at=None))
        authorization = body.get("owner_authorization")
        if authorization is None:
            self.issued = self.described or challenge()
            return httpx.Response(
                403,
                json={
                    "type": "urn:agentbank:problem:owner_signature_required",
                    "title": "Owner signature required",
                    "status": 403,
                    "code": "owner_signature_required",
                    "detail": "Early withdrawal needs the owner's EarlyWithdrawal signature",
                    "typed_data": self.issued,
                },
            )
        digest = time_lock_vaults_digest(
            vault_id=ONCHAIN_ID,
            amount=parse_amount(body["amount"]["amount"]),
            nonce=NONCE,
            deadline=authorization["expires_at"],
        )
        if recover(digest, authorization["signature"]) != OWNER_ADDRESS:
            return httpx.Response(
                403,
                json={
                    "type": "urn:agentbank:problem:owner_signature_required",
                    "title": "Owner signature required",
                    "status": 403,
                    "code": "owner_signature_required",
                    "detail": "The early withdrawal must be signed by the owner key",
                },
            )
        return httpx.Response(200, json=vault_json(pending_operation_id=OOP_ID))


def mock_vault_api(
    api: respx.MockRouter,
    fake: FakeVaultAPI,
    *,
    operation: dict[str, Any] | None = None,
) -> dict[str, respx.Route]:
    return {
        "withdraw": api.post(f"/v1/vaults/{VAULT_ID}/withdraw").mock(side_effect=fake),
        "vault": api.get(f"/v1/vaults/{VAULT_ID}").mock(
            side_effect=[
                httpx.Response(200, json=vault_json()),
                httpx.Response(200, json=vault_json(balance={"amount": "0.00", "asset": "USDC"})),
            ]
        ),
        "meta": api.get("/v1/meta").respond(json=meta_json(contracts={"vaults": VAULTS})),
        "operation": api.get(f"/v1/owner-operations/{OOP_ID}").mock(
            side_effect=[
                httpx.Response(200, json=operation or operation_json("requires_signature")),
                httpx.Response(200, json=operation_json("succeeded")),
            ]
        ),
        "sign": api.post(f"/v1/owner-operations/{OOP_ID}/signature").respond(
            json=operation_json("submitted")
        ),
    }


def check_authorization(authorization: dict[str, Any], deadline: int) -> None:
    assert authorization["signer"] == OWNER_ADDRESS
    assert authorization["expires_at"] == deadline
    assert authorization["issued_at"] == deadline - EARLY_WITHDRAWAL_TTL_SECONDS
    digest = time_lock_vaults_digest(
        vault_id=ONCHAIN_ID, amount=MINOR, nonce=NONCE, deadline=deadline
    )
    assert recover(digest, authorization["signature"]) == OWNER_ADDRESS


# --------------------------------------------------------------------- typed data


def test_types_match_the_contract() -> None:
    fields = EARLY_WITHDRAWAL_TYPES["EarlyWithdrawal"]
    described = ",".join(f"{field['type']} {field['name']}" for field in fields)
    assert f"EarlyWithdrawal({described})" == CONTRACT_TYPE
    assert TIME_LOCK_VAULTS_EIP712 == {"name": "AgentBank TimeLockVaults", "version": "1"}


def test_signature_matches_viem_and_the_contract_digest() -> None:
    vector = VIEM_VECTORS["early_withdrawal"]
    message = vector["message"]
    deadline = int(message["deadline"])
    described = {
        "domain": vector["domain"],
        "types": copy.deepcopy(EARLY_WITHDRAWAL_TYPES),
        "primaryType": "EarlyWithdrawal",
        "message": message,
    }
    typed = early_withdrawal_typed_data(
        described,
        chain_id=84532,
        contract=vector["domain"]["verifyingContract"],
        onchain_id=message["vaultId"],
        amount="15.00",
        now=deadline - EARLY_WITHDRAWAL_TTL_SECONDS,
    )
    authorization = sign_early_withdrawal(vector["owner_private_key"], typed)
    assert authorization == {
        "signer": vector["owner_address"],
        "signature": vector["signature"],
        "issued_at": deadline - EARLY_WITHDRAWAL_TTL_SECONDS,
        "expires_at": deadline,
    }
    digest = time_lock_vaults_digest(
        vault_id=int(message["vaultId"]),
        amount=int(message["amount"]),
        nonce=int(message["nonce"]),
        deadline=deadline,
        contract=vector["domain"]["verifyingContract"],
    )
    assert "0x" + digest.hex() == vector["digest"]
    signable = encode_typed_data(full_message=typed)
    assert keccak(b"\x19" + signable.version + signable.header + signable.body) == digest
    assert recover(digest, authorization["signature"]) == vector["owner_address"]


def test_typed_data_is_built_from_the_checked_values() -> None:
    deadline = int(time.time()) + 600
    described = challenge(deadline=deadline)
    described["domain"]["verifyingContract"] = VAULTS.lower()
    described["domain"]["chainId"] = "84532"
    typed = early_withdrawal_typed_data(
        described, chain_id=84532, contract=VAULTS, onchain_id=ONCHAIN_ID, amount=AMOUNT
    )
    assert typed["primaryType"] == "EarlyWithdrawal"
    assert typed["domain"] == {
        "name": "AgentBank TimeLockVaults",
        "version": "1",
        "chainId": 84532,
        "verifyingContract": VAULTS,
    }
    assert typed["message"] == {
        "vaultId": ONCHAIN_ID,
        "amount": MINOR,
        "nonce": NONCE,
        "deadline": deadline,
    }
    assert [field["name"] for field in typed["types"]["EIP712Domain"]] == [
        "name",
        "version",
        "chainId",
        "verifyingContract",
    ]
    typed["types"]["EarlyWithdrawal"].clear()
    assert len(EARLY_WITHDRAWAL_TYPES["EarlyWithdrawal"]) == 4
    # The API may leave out the types; the SDK uses TimeLockVaults' own.
    del described["types"]
    assert (
        early_withdrawal_typed_data(
            described, chain_id=84532, contract=VAULTS, onchain_id="7", amount=AMOUNT
        )["types"]["EarlyWithdrawal"]
        == EARLY_WITHDRAWAL_TYPES["EarlyWithdrawal"]
    )
    assert sign_early_withdrawal(OWNER_KEY, typed, issued_at=123)["issued_at"] == 123


def _domain(**fields: Any) -> dict[str, Any]:
    described = challenge()
    described["domain"].update(fields)
    return described


def _message(**fields: Any) -> dict[str, Any]:
    return challenge(**fields)


def _swapped_types() -> dict[str, Any]:
    described = challenge()
    fields = described["types"]["EarlyWithdrawal"]
    fields[1], fields[2] = fields[2], fields[1]
    return described


@pytest.mark.parametrize(
    ("described", "overrides", "reason"),
    [
        ({**challenge(), "primaryType": "Permit"}, {}, "did not describe"),
        ({**challenge(), "domain": None}, {}, "did not describe"),
        ({**challenge(), "message": ["7"]}, {}, "did not describe"),
        (_domain(name="USDC"), {}, "not TimeLockVaults"),
        (_domain(version="2"), {}, "not TimeLockVaults"),
        (_domain(chainId=1337), {}, "chain 1337"),
        (_domain(chainId="base-sepolia"), {}, "chain 'base-sepolia'"),
        (_domain(verifyingContract="0x" + "11" * 20), {}, "verifying contract"),
        (_domain(verifyingContract="0x1234"), {}, "verifying contract"),
        (challenge(), {"contract": None}, "verifying contract"),
        (challenge(), {"contract": "vaults"}, "verifying contract"),
        (_swapped_types(), {}, "fields differ"),
        (_message(vaultId="8"), {}, "names vault 8"),
        (challenge(), {"onchain_id": None}, "names vault 7"),
        (_message(amount="15000001"), {}, "amount"),
        (challenge(), {"amount": "15.01"}, "amount"),
        (_message(nonce="-1"), {}, "unsigned integers"),
        (_message(nonce=1.5), {}, "unsigned integers"),
        (_message(nonce=True), {}, "unsigned integers"),
        (_message(deadline="0x10"), {}, "unsigned integers"),
        (_message(deadline="9" * 79), {}, "unsigned integers"),
        (challenge(deadline=1_000), {}, "deadline"),
        (challenge(deadline=int(time.time()) + 3_700), {}, "deadline"),
    ],
)
def test_challenge_must_match_the_request(
    described: dict[str, Any], overrides: dict[str, Any], reason: str
) -> None:
    args: dict[str, Any] = {
        "chain_id": 84532,
        "contract": VAULTS,
        "onchain_id": str(ONCHAIN_ID),
        "amount": AMOUNT,
        **overrides,
    }
    with pytest.raises(BadRequestError, match=reason) as excinfo:
        early_withdrawal_typed_data(described, **args)
    assert excinfo.value.code == "invalid_request"
    assert str(excinfo.value.detail).startswith("Refusing to sign the early withdrawal")


def test_generic_vault_withdraw_payload_is_kept_for_parity() -> None:
    """``vault.withdraw`` mirrors ``ownerPayloads.vaultWithdraw``; the API does not verify it."""
    request = owner_payloads.vault_withdraw(VAULT_ID, "1.00")
    assert request.action == "vault.withdraw"
    assert request.subject == VAULT_ID
    assert request.payload == {"amount": {"amount": "1.00", "asset": "USDC"}}


def test_mainnets_are_refused() -> None:
    with pytest.raises(MainnetLockedError):
        early_withdrawal_typed_data(
            challenge(), chain_id=8453, contract=VAULTS, onchain_id=7, amount=AMOUNT
        )
    typed = early_withdrawal_typed_data(
        challenge(), chain_id=84532, contract=VAULTS, onchain_id=7, amount=AMOUNT
    )
    typed["domain"]["chainId"] = 8453
    with pytest.raises(MainnetLockedError):
        sign_early_withdrawal(OWNER_KEY, typed)


# --------------------------------------------------------------------- withdraw_vault


def test_withdraw_vault_answers_the_challenge_and_signs_the_operation(
    principal: AgentBank, api: respx.MockRouter
) -> None:
    fake = FakeVaultAPI()
    routes = mock_vault_api(api, fake)
    result = principal.withdraw_vault(
        VAULT_ID, AMOUNT, owner=OWNER_KEY, wait=True, idempotency_key="vault-withdraw-1"
    )
    assert isinstance(result, VaultWithdrawalResult)
    assert result.operation is not None
    assert result.operation.status == "succeeded"
    assert result.vault.balance.amount == "0.00"
    (first_key, first), (second_key, second) = fake.calls
    assert first == {"amount": {"amount": AMOUNT, "asset": "USDC"}}
    assert first_key == "vault-withdraw-1.withdraw"
    assert second_key == "vault-withdraw-1.withdraw.signed"
    authorization = second.pop("owner_authorization")
    assert second == first
    check_authorization(authorization, fake.deadline)
    sign_request = routes["sign"].calls.last.request
    assert sign_request.headers["idempotency-key"] == "vault-withdraw-1.sign"
    signature = json.loads(sign_request.content)["signature"]
    message = encode_defunct(primitive=bytes.fromhex(HASH[2:]))
    assert Account.recover_message(message, signature=signature) == OWNER_ADDRESS
    order = [(call.request.method, call.request.url.path) for call in api.calls]
    assert order == [
        ("POST", f"/v1/vaults/{VAULT_ID}/withdraw"),
        ("GET", f"/v1/vaults/{VAULT_ID}"),
        ("GET", "/v1/meta"),
        ("POST", f"/v1/vaults/{VAULT_ID}/withdraw"),
        ("GET", f"/v1/owner-operations/{OOP_ID}"),
        ("POST", f"/v1/owner-operations/{OOP_ID}/signature"),
        ("GET", f"/v1/owner-operations/{OOP_ID}"),
        ("GET", f"/v1/vaults/{VAULT_ID}"),
    ]


def test_withdraw_vault_uses_the_challenge_deadline(
    principal: AgentBank, api: respx.MockRouter
) -> None:
    deadline = int(time.time()) + 300
    fake = FakeVaultAPI(described=challenge(deadline=deadline))
    mock_vault_api(api, fake)
    result = principal.withdraw_vault(VAULT_ID, AMOUNT, owner=OWNER_KEY)
    assert result.operation is not None
    assert result.operation.status == "submitted"
    assert result.vault.pending_operation_id == OOP_ID
    (first_key, _), (second_key, second) = fake.calls
    assert first_key != second_key
    assert fake.deadline == deadline
    check_authorization(second["owner_authorization"], deadline)


def test_withdraw_vault_without_a_challenge(principal: AgentBank, api: respx.MockRouter) -> None:
    fake = FakeVaultAPI(locked=False)
    routes = mock_vault_api(api, fake)
    result = principal.withdraw_vault(VAULT_ID, "1.00", owner=OWNER_KEY)
    assert result.operation is None
    assert result.vault.kind == "goal"
    assert [body for _, body in fake.calls] == [{"amount": {"amount": "1.00", "asset": "USDC"}}]
    assert not routes["sign"].called
    assert not routes["meta"].called


@pytest.mark.parametrize(
    ("described", "reason"),
    [
        (challenge(amount="16000000"), "amount"),
        (challenge(vaultId="8"), "names vault 8"),
        ({**challenge(), "domain": {**challenge()["domain"], "chainId": 11155111}}, "chain"),
    ],
)
def test_withdraw_vault_signs_nothing_on_a_mismatch(
    principal: AgentBank, api: respx.MockRouter, described: dict[str, Any], reason: str
) -> None:
    fake = FakeVaultAPI(described=described)
    routes = mock_vault_api(api, fake)
    with pytest.raises(BadRequestError, match=reason):
        principal.withdraw_vault(VAULT_ID, AMOUNT, owner=OWNER_KEY)
    assert len(fake.calls) == 1
    assert not routes["sign"].called


def test_withdraw_vault_refuses_another_operation(
    principal: AgentBank, api: respx.MockRouter
) -> None:
    routes = mock_vault_api(
        api,
        FakeVaultAPI(),
        operation=operation_json("requires_signature", purpose="payment", subject_id="pay_1"),
    )
    with pytest.raises(BadRequestError, match="it is a payment for pay_1"):
        principal.withdraw_vault(VAULT_ID, AMOUNT, owner=OWNER_KEY)
    assert not routes["sign"].called


def test_a_challenge_without_typed_data_is_raised(
    principal: AgentBank, api: respx.MockRouter
) -> None:
    api.post(f"/v1/vaults/{VAULT_ID}/withdraw").respond(
        403, json={"code": "owner_signature_required", "detail": "Owner key required"}
    )
    with pytest.raises(OwnerSignatureRequiredError, match="Owner key required"):
        principal.withdraw_vault(VAULT_ID, AMOUNT, owner=OWNER_KEY)


def test_a_wrong_owner_key_is_rejected_by_the_api(
    principal: AgentBank, api: respx.MockRouter
) -> None:
    fake = FakeVaultAPI()
    mock_vault_api(api, fake)
    with pytest.raises(OwnerSignatureRequiredError, match="must be signed by the owner key"):
        principal.withdraw_vault(
            VAULT_ID, AMOUNT, owner=VIEM_VECTORS["permit"]["spend_private_key"]
        )
    assert len(fake.calls) == 2


# --------------------------------------------------------------------- vaults resource


def test_vaults_withdraw_with_owner_leaves_the_operation_unsigned(
    principal: AgentBank, api: respx.MockRouter
) -> None:
    fake = FakeVaultAPI()
    routes = mock_vault_api(api, fake)
    vault = principal.vaults.withdraw(
        VAULT_ID, amount=AMOUNT, owner=OWNER_KEY, idempotency_key="vault-key-01"
    )
    assert vault.pending_operation_id == OOP_ID
    assert [key for key, _ in fake.calls] == ["vault-key-01", "vault-key-01.signed"]
    assert not routes["operation"].called
    assert not routes["sign"].called


def test_hardware_wallet_flow(principal: AgentBank, api: respx.MockRouter) -> None:
    fake = FakeVaultAPI()
    mock_vault_api(api, fake)
    with pytest.raises(OwnerSignatureRequiredError) as excinfo:
        principal.vaults.withdraw(VAULT_ID, amount=AMOUNT)
    typed = principal.vaults.early_withdrawal_typed_data(
        VAULT_ID, amount=AMOUNT, typed_data=excinfo.value.extensions["typed_data"]
    )
    # What a wallet's eth_signTypedData_v4 returns for the checked typed data.
    signed = Account.sign_typed_data(OWNER_KEY, full_message=typed)
    deadline = typed["message"]["deadline"]
    vault = principal.vaults.withdraw(
        VAULT_ID,
        amount=AMOUNT,
        owner_authorization={
            "signer": OWNER_ADDRESS,
            "signature": "0x" + signed.signature.hex().removeprefix("0x"),
            "issued_at": int(time.time()),
            "expires_at": deadline,
        },
    )
    assert vault.pending_operation_id == OOP_ID
    assert fake.calls[0][0] != fake.calls[1][0]


def test_contract_falls_back_to_meta(principal: AgentBank, api: respx.MockRouter) -> None:
    api.get(f"/v1/vaults/{VAULT_ID}").respond(json=vault_json(contract_address=None))
    api.get("/v1/meta").respond(json=meta_json(contracts={"vaults": VAULTS}))
    typed = principal.vaults.early_withdrawal_typed_data(
        VAULT_ID, amount=AMOUNT, typed_data=challenge()
    )
    assert typed["domain"]["verifyingContract"] == VAULTS


# --------------------------------------------------------------------- async


async def test_async_withdraw_vault(async_principal: AsyncAgentBank, api: respx.MockRouter) -> None:
    fake = FakeVaultAPI()
    routes = mock_vault_api(api, fake)
    result = await async_principal.withdraw_vault(
        VAULT_ID, AMOUNT, owner=OWNER_KEY, wait=True, idempotency_key="vault-withdraw-2"
    )
    assert result.operation is not None
    assert result.operation.status == "succeeded"
    assert routes["sign"].calls.last.request.headers["idempotency-key"] == "vault-withdraw-2.sign"
    check_authorization(fake.calls[1][1]["owner_authorization"], fake.deadline)

    # Without waiting, the signed operation comes back as submitted.
    api.get(f"/v1/vaults/{VAULT_ID}").respond(json=vault_json())
    api.get(f"/v1/owner-operations/{OOP_ID}").respond(json=operation_json("requires_signature"))
    submitted = await async_principal.withdraw_vault(VAULT_ID, AMOUNT, owner=OWNER_KEY)
    assert submitted.operation is not None
    assert submitted.operation.status == "submitted"
    assert submitted.vault.pending_operation_id == OOP_ID

    api.post(f"/v1/vaults/{VAULT_ID}/withdraw").mock(side_effect=FakeVaultAPI(locked=False))
    immediate = await async_principal.withdraw_vault(VAULT_ID, "1.00", owner=OWNER_KEY)
    assert immediate.operation is None
    plain = await async_principal.vaults.withdraw(VAULT_ID, amount="1.00", owner=OWNER_KEY)
    assert plain.kind == "goal"


async def test_async_vaults_withdraw_with_owner(
    async_principal: AsyncAgentBank, api: respx.MockRouter
) -> None:
    fake = FakeVaultAPI(described=challenge(amount="1"))
    routes = mock_vault_api(api, fake)
    with pytest.raises(BadRequestError, match="amount"):
        await async_principal.vaults.withdraw(VAULT_ID, amount=AMOUNT, owner=OWNER_KEY)
    assert len(fake.calls) == 1
    fake.described = None
    vault = await async_principal.vaults.withdraw(VAULT_ID, amount=AMOUNT, owner=OWNER_KEY)
    assert vault.pending_operation_id == OOP_ID
    assert not routes["sign"].called
    api.post(f"/v1/vaults/{VAULT_ID}/withdraw").respond(
        403, json={"code": "owner_signature_required", "detail": "no challenge"}
    )
    with pytest.raises(OwnerSignatureRequiredError):
        await async_principal.withdraw_vault(VAULT_ID, AMOUNT, owner=OWNER_KEY)
    api.post(f"/v1/vaults/{VAULT_ID}/withdraw").mock(side_effect=FakeVaultAPI())
    api.get(f"/v1/owner-operations/{OOP_ID}").respond(
        json=operation_json("requires_signature", subject_id="vlt_01J0THERVAU1T0000000000000")
    )
    api.get(f"/v1/vaults/{VAULT_ID}").respond(json=vault_json())
    with pytest.raises(BadRequestError, match="not the withdrawal from vault"):
        await async_principal.withdraw_vault(VAULT_ID, AMOUNT, owner=OWNER_KEY)
