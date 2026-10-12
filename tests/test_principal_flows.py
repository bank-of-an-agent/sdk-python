"""Principal flows: spend-key provisioning, session grants, account setup, owner rotation."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
import respx
from eth_account import Account
from eth_account.messages import encode_defunct

from agentbank import (
    AgentBank,
    AgentBankError,
    AsyncAgentBank,
    BadRequestError,
    ConfigurationError,
    GrantSessionResult,
    SetupAgentAccountResult,
    owner_payloads,
)
from agentbank.eip712 import verify_owner_authorization
from agentbank.flows import MAX_SESSION_TTL_SECONDS, session_scope_with_expiry
from agentbank.spend_key import MAX_UINT256
from tests.conftest import (
    ACCOUNT_ID,
    AGENT_ID,
    API_KEY,
    BASE_URL,
    ORG_ID,
    OWNER_ADDRESS,
    OWNER_KEY,
    SESSION_ADDRESS,
    SESSION_ID,
    SPEND_ADDRESS,
    SPEND_KEY,
)
from tests.factories import example, id_for
from tests.test_spend_key import fiat_token_permit_digest, recover

SMART_ACCOUNT = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
NEW_OWNER = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
OOP_ID = id_for("oop")
HASH = "0x" + "c4" * 32
SCOPE = {"max_per_tx": "5.00", "max_per_day": "50.00"}


def account_json(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "id": ACCOUNT_ID,
        "agent_id": AGENT_ID,
        "role": "agent",
        "chain": "base-sepolia",
        "chain_id": 84532,
        "address": SMART_ACCOUNT,
        "spend_key_address": None,
        "spend_key_permit": "none",
    }
    fields.update(overrides)
    return example("Account", **fields)


def meta_json(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "chain": "base-sepolia",
        "chain_id": 84532,
        "caip2": "eip155:84532",
        "owner_authorization_chain_id": 84532,
        "usdc": {"address": USDC, "decimals": 6, "eip712_name": "USDC", "eip712_version": "2"},
    }
    fields.update(overrides)
    return example("Meta", **fields)


def operation_json(status: str, **overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "id": OOP_ID,
        "status": status,
        "chain_id": 84532,
        "user_op_hash": HASH,
        "account_id": ACCOUNT_ID,
    }
    fields.update(overrides)
    return example("OwnerOperation", **fields)


def session_json(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "id": SESSION_ID,
        "account_id": ACCOUNT_ID,
        "install_operation_id": None,
    }
    fields.update(overrides)
    return example("Session", **fields)


def body_of(route: respx.Route) -> dict[str, Any]:
    result: dict[str, Any] = json.loads(route.calls.last.request.content)
    return result


def verify(request: owner_payloads.OwnerActionPayload, authorization: dict[str, Any]) -> None:
    verify_owner_authorization(
        owner=OWNER_ADDRESS,
        authorization=authorization,
        chain_id=84532,
        action=request.action,
        subject=request.subject,
        payload=request.payload,
    )


def check_permit(permit: dict[str, str], spender: str = SMART_ACCOUNT, nonce: int = 0) -> None:
    digest = fiat_token_permit_digest(
        owner=SPEND_ADDRESS,
        spender=spender,
        value=int(permit["value"]),
        nonce=nonce,
        deadline=int(permit["deadline"]),
    )
    assert permit["nonce"] == str(nonce)
    assert recover(digest, permit["signature"]) == SPEND_ADDRESS


def mock_setup_routes(api: respx.MockRouter) -> dict[str, respx.Route]:
    return {
        "meta": api.get("/v1/meta").respond(json=meta_json()),
        "create": api.post(f"/v1/agents/{AGENT_ID}/accounts").respond(201, json=account_json()),
        "retrieve": api.get(f"/v1/accounts/{ACCOUNT_ID}").respond(
            json=account_json(spend_key_address=SPEND_ADDRESS, spend_key_permit="executed")
        ),
        "attach": api.put(f"/v1/accounts/{ACCOUNT_ID}/spend-key").respond(
            json=account_json(spend_key_address=SPEND_ADDRESS, spend_key_permit="pending")
        ),
        "sessions": api.post("/v1/sessions").respond(201, json=session_json()),
        "install": api.post(f"/v1/sessions/{SESSION_ID}/install").respond(
            json=session_json(install_operation_id=OOP_ID)
        ),
        "operation": api.get(f"/v1/owner-operations/{OOP_ID}").mock(
            side_effect=[
                httpx.Response(200, json=operation_json("requires_signature")),
                httpx.Response(200, json=operation_json("submitted")),
                httpx.Response(200, json=operation_json("succeeded")),
            ]
        ),
        "sign": api.post(f"/v1/owner-operations/{OOP_ID}/signature").respond(
            json=operation_json("submitted")
        ),
        "session": api.get(f"/v1/sessions/{SESSION_ID}").respond(
            json=session_json(status="active", install_operation_id=OOP_ID)
        ),
    }


# --------------------------------------------------------------------- spend keys


def test_provision_spend_key(principal: AgentBank, api: respx.MockRouter) -> None:
    routes = mock_setup_routes(api)
    account = principal.provision_spend_key(
        ACCOUNT_ID, SPEND_KEY, owner=OWNER_KEY, idempotency_key="provision-1"
    )
    assert account.spend_key_permit == "pending"
    body = body_of(routes["attach"])
    authorization = body.pop("owner_authorization")
    assert body["spend_key_address"] == SPEND_ADDRESS
    check_permit(body["permit"])
    assert body["permit"]["value"] == str(MAX_UINT256)
    verify(owner_payloads.spend_key_set(ACCOUNT_ID, SPEND_ADDRESS), authorization)
    assert routes["attach"].calls.last.request.headers["idempotency-key"] == "provision-1"
    assert routes["meta"].call_count == 1


def test_provision_spend_key_with_a_used_key(principal: AgentBank, api: respx.MockRouter) -> None:
    routes = mock_setup_routes(api)
    principal.provision_spend_key(ACCOUNT_ID, SPEND_KEY, owner=OWNER_KEY, nonce=4, value=10**9)
    permit = body_of(routes["attach"])["permit"]
    assert permit["value"] == str(10**9)
    check_permit(permit, nonce=4)


def test_spend_key_guards(principal: AgentBank, api: respx.MockRouter) -> None:
    api.get("/v1/meta").respond(json=meta_json())
    api.get(f"/v1/accounts/{ACCOUNT_ID}").respond(json=account_json(role="treasury", agent_id=None))
    attach = api.put(f"/v1/accounts/{ACCOUNT_ID}/spend-key")
    with pytest.raises(BadRequestError, match="not the treasury"):
        principal.provision_spend_key(ACCOUNT_ID, SPEND_KEY, owner=OWNER_KEY)
    api.get(f"/v1/accounts/{ACCOUNT_ID}").respond(json=account_json(chain_id=1337))
    with pytest.raises(BadRequestError, match="on chain 1337"):
        principal.provision_spend_key(ACCOUNT_ID, SPEND_KEY, owner=OWNER_KEY)
    assert not attach.called


def test_spend_key_permit_helper(principal: AgentBank, api: respx.MockRouter) -> None:
    api.get("/v1/meta").respond(json=meta_json())
    api.get(f"/v1/accounts/{ACCOUNT_ID}").respond(json=account_json())
    check_permit(principal.spend_key_permit(ACCOUNT_ID, SPEND_KEY))


def test_attach_spend_key_with_a_presigned_authorization(
    principal: AgentBank, api: respx.MockRouter
) -> None:
    route = api.put(f"/v1/accounts/{ACCOUNT_ID}/spend-key").respond(json=account_json())
    permit = {"value": "1", "deadline": "4000000000", "nonce": "0", "signature": "0x" + "ab" * 65}
    explicit = {
        "signer": OWNER_ADDRESS,
        "signature": "0x" + "11" * 65,
        "issued_at": 1,
        "expires_at": 2,
    }
    principal.accounts.attach_spend_key(
        ACCOUNT_ID, spend_key_address=SPEND_ADDRESS, permit=permit, owner_authorization=explicit
    )
    assert body_of(route) == {
        "spend_key_address": SPEND_ADDRESS,
        "permit": permit,
        "owner_authorization": explicit,
    }
    principal.accounts.attach_spend_key(ACCOUNT_ID, spend_key_address=SPEND_ADDRESS, permit=permit)
    assert "owner_authorization" not in body_of(route)


# --------------------------------------------------------------------- sessions


def test_grant_session_signs_the_install(principal: AgentBank, api: respx.MockRouter) -> None:
    routes = mock_setup_routes(api)
    result = principal.grant_session(
        account_id=ACCOUNT_ID,
        public_key=SESSION_ADDRESS,
        scope=SCOPE,
        owner=OWNER_KEY,
        wait_for_install=True,
        idempotency_key="grant-1",
    )
    assert isinstance(result, GrantSessionResult)
    assert result.session.status == "active"
    assert result.install_operation is not None
    assert result.install_operation.status == "succeeded"
    body = body_of(routes["sessions"])
    authorization = body.pop("owner_authorization")
    scope = body["scope"]
    assert scope["asset"] == "USDC"
    expires = datetime.fromisoformat(scope["expires_at"].replace("Z", "+00:00"))
    assert timedelta(hours=23) < expires - datetime.now(timezone.utc) <= timedelta(hours=24)
    verify(
        owner_payloads.session_grant(
            account_id=ACCOUNT_ID, public_key=SESSION_ADDRESS, scope=scope
        ),
        authorization,
    )
    sign_request = routes["sign"].calls.last.request
    message = encode_defunct(primitive=bytes.fromhex(HASH[2:]))
    signature = json.loads(sign_request.content)["signature"]
    assert Account.recover_message(message, signature=signature) == OWNER_ADDRESS
    keys = [
        routes[name].calls.last.request.headers["idempotency-key"]
        for name in ("sessions", "install", "sign")
    ]
    assert keys == ["grant-1.create", "grant-1.install", "grant-1.sign"]


def test_grant_session_variants(principal: AgentBank, api: respx.MockRouter) -> None:
    routes = mock_setup_routes(api)
    not_installed = principal.grant_session(
        account_id=ACCOUNT_ID,
        public_key=SESSION_ADDRESS,
        scope=SCOPE,
        owner=OWNER_KEY,
        install=False,
    )
    assert not_installed.install_operation is None
    assert not routes["install"].called
    routes["install"].respond(json=session_json(install_operation_id=None))
    nothing_to_sign = principal.grant_session(
        account_id=ACCOUNT_ID, public_key=SESSION_ADDRESS, scope=SCOPE, owner=OWNER_KEY
    )
    assert nothing_to_sign.install_operation is None
    assert not routes["sign"].called
    explicit = {**SCOPE, "expires_at": "2099-01-01T00:00:00Z"}
    with pytest.raises(BadRequestError, match="at most 7 days"):
        principal.grant_session(
            account_id=ACCOUNT_ID, public_key=SESSION_ADDRESS, scope=explicit, owner=OWNER_KEY
        )
    with pytest.raises(BadRequestError, match="ttl_seconds"):
        principal.grant_session(
            account_id=ACCOUNT_ID,
            public_key=SESSION_ADDRESS,
            scope=SCOPE,
            owner=OWNER_KEY,
            ttl_seconds=MAX_SESSION_TTL_SECONDS + 1,
        )


def test_session_scope_normalization() -> None:
    now = datetime(2026, 10, 11, 12, 0, 0, 500_000, tzinfo=timezone.utc)
    scope = session_scope_with_expiry(SCOPE, 3600, now=now)
    assert scope["asset"] == "USDC"
    assert scope["expires_at"].startswith("2026-10-11T13:00:00")
    past = {**SCOPE, "expires_at": "2020-01-01T00:00:00Z"}
    with pytest.raises(BadRequestError, match="in the future"):
        session_scope_with_expiry(past, now=now)
    with pytest.raises(BadRequestError, match="ttl_seconds"):
        session_scope_with_expiry(SCOPE, 0)
    with pytest.raises(BadRequestError, match="ttl_seconds"):
        session_scope_with_expiry(SCOPE, True)


# --------------------------------------------------------------------- account setup


def test_setup_agent_account_runs_every_step_in_order(
    principal: AgentBank, api: respx.MockRouter
) -> None:
    routes = mock_setup_routes(api)
    result = principal.setup_agent_account(
        agent_id=AGENT_ID,
        owner=OWNER_KEY,
        chain="base-sepolia",
        spend_key=SPEND_KEY,
        session={"public_key": SESSION_ADDRESS, "scope": SCOPE, "wait_for_install": True},
        idempotency_key="setup-1",
    )
    assert isinstance(result, SetupAgentAccountResult)
    assert result.account.spend_key_permit == "executed"
    assert result.session is not None
    assert result.session.status == "active"
    assert result.install_operation is not None
    order = [(call.request.method, call.request.url.path) for call in api.calls]
    assert order == [
        ("POST", f"/v1/agents/{AGENT_ID}/accounts"),
        ("GET", "/v1/meta"),
        ("PUT", f"/v1/accounts/{ACCOUNT_ID}/spend-key"),
        ("POST", "/v1/sessions"),
        ("POST", f"/v1/sessions/{SESSION_ID}/install"),
        ("GET", f"/v1/owner-operations/{OOP_ID}"),
        ("POST", f"/v1/owner-operations/{OOP_ID}/signature"),
        ("GET", f"/v1/owner-operations/{OOP_ID}"),
        ("GET", f"/v1/owner-operations/{OOP_ID}"),
        ("GET", f"/v1/sessions/{SESSION_ID}"),
        ("GET", f"/v1/accounts/{ACCOUNT_ID}"),
    ]
    keys = {
        name: routes[name].calls.last.request.headers["idempotency-key"]
        for name in ("create", "attach", "sessions", "install", "sign")
    }
    assert keys == {
        "create": "setup-1.account",
        "attach": "setup-1.spend-key",
        "sessions": "setup-1.session.create",
        "install": "setup-1.session.install",
        "sign": "setup-1.session.sign",
    }
    assert body_of(routes["create"]) == {"chain": "base-sepolia"}
    check_permit(body_of(routes["attach"])["permit"])


def test_setup_agent_account_partial_and_guards(
    principal: AgentBank, api: respx.MockRouter
) -> None:
    routes = mock_setup_routes(api)
    only_account = principal.setup_agent_account(agent_id=AGENT_ID)
    assert only_account.session is None
    assert only_account.install_operation is None
    assert body_of(routes["create"]) == {}
    session_owner_only = principal.setup_agent_account(
        agent_id=AGENT_ID,
        session={
            "public_key": SESSION_ADDRESS,
            "scope": SCOPE,
            "owner": OWNER_KEY,
            "install": False,
        },
    )
    assert session_owner_only.session is not None
    assert not routes["attach"].called
    with pytest.raises(ConfigurationError, match="owner key"):
        principal.setup_agent_account(agent_id=AGENT_ID, spend_key=SPEND_KEY)
    with pytest.raises(ConfigurationError, match="owner key"):
        principal.setup_agent_account(
            agent_id=AGENT_ID, session={"public_key": SESSION_ADDRESS, "scope": SCOPE}
        )


async def test_async_setup_agent_account(
    async_principal: AsyncAgentBank, api: respx.MockRouter
) -> None:
    routes = mock_setup_routes(api)
    result = await async_principal.setup_agent_account(
        agent_id=AGENT_ID,
        owner=OWNER_KEY,
        spend_key=SPEND_KEY,
        permit={"nonce": 2},
        session={"public_key": SESSION_ADDRESS, "scope": SCOPE},
    )
    assert result.install_operation is not None
    assert result.install_operation.status == "submitted"
    check_permit(body_of(routes["attach"])["permit"], nonce=2)
    account = await async_principal.provision_spend_key(ACCOUNT_ID, SPEND_KEY, owner=OWNER_KEY)
    assert account.spend_key_address == SPEND_ADDRESS


# --------------------------------------------------------------------- owner rotation


def test_owner_rotation_flow(principal: AgentBank, api: respx.MockRouter) -> None:
    api.get("/v1/meta").respond(json=meta_json())
    swap = api.post(f"/v1/accounts/{ACCOUNT_ID}/owner-swap").respond(
        201, json=operation_json("requires_signature", purpose="owner.swap")
    )
    api.get(f"/v1/owner-operations/{OOP_ID}").mock(
        side_effect=[
            httpx.Response(200, json=operation_json("submitted", purpose="owner.swap")),
            httpx.Response(200, json=operation_json("succeeded", purpose="owner.swap")),
        ]
    )
    sign = api.post(f"/v1/owner-operations/{OOP_ID}/signature").respond(
        json=operation_json("submitted", purpose="owner.swap")
    )
    operation = principal.owner_operations.prepare_owner_swap(
        ACCOUNT_ID,
        new_owner_address=NEW_OWNER,
        owner=OWNER_KEY,
        wait=True,
        idempotency_key="owner-swap-1",
    )
    assert operation.status == "succeeded"
    assert body_of(swap) == {"new_owner_address": NEW_OWNER}
    assert swap.calls.last.request.headers["idempotency-key"] == "owner-swap-1"
    assert sign.calls.last.request.headers["idempotency-key"] == "owner-swap-1.sign"
    unsigned = principal.owner_operations.prepare_owner_swap(
        ACCOUNT_ID, new_owner_address=NEW_OWNER
    )
    assert unsigned.status == "requires_signature"

    api.get("/v1/orgs/me").respond(json=example("Org", id=ORG_ID))
    rotate = api.post("/v1/orgs/me/owner").respond(json=example("Org", id=ORG_ID))
    principal.orgs.rotate_owner(new_owner_address=NEW_OWNER, owner=OWNER_KEY)
    body = body_of(rotate)
    authorization = body.pop("owner_authorization")
    assert body == {"new_owner_address": NEW_OWNER}
    verify(owner_payloads.owner_rotate(ORG_ID, NEW_OWNER), authorization)


def test_owner_operation_wait(principal: AgentBank, api: respx.MockRouter) -> None:
    api.get(f"/v1/owner-operations/{OOP_ID}").respond(json=operation_json("submitted"))
    with pytest.raises(AgentBankError) as excinfo:
        principal.owner_operations.wait(OOP_ID, timeout=0)
    assert excinfo.value.code == "operation_timeout"
    api.get(f"/v1/owner-operations/{OOP_ID}").respond(json=operation_json("expired"))
    assert principal.owner_operations.wait(OOP_ID).status == "expired"


# --------------------------------------------------------------------- sandbox


def test_sandbox_faucet(api: respx.MockRouter) -> None:
    route = api.post("/v1/sandbox/faucet").respond(json=example("SandboxFaucetResponse"))
    with AgentBank(api_key=API_KEY, base_url=BASE_URL, account_id=ACCOUNT_ID) as bank:
        bank.sandbox.faucet(amount="25.00")
        assert body_of(route) == {
            "account_id": ACCOUNT_ID,
            "amount": {"amount": "25.00", "asset": "USDC"},
        }
        bank.sandbox.faucet(amount="1.00", address=SPEND_ADDRESS)
        assert body_of(route) == {
            "address": SPEND_ADDRESS,
            "amount": {"amount": "1.00", "asset": "USDC"},
        }
        with pytest.raises(ValueError, match="exactly one"):
            bank.sandbox.faucet(amount="1.00", account_id=ACCOUNT_ID, address=SPEND_ADDRESS)
    with AgentBank(api_key=API_KEY, base_url=BASE_URL) as no_account:
        with pytest.raises(ConfigurationError, match="account_id"):
            no_account.sandbox.faucet(amount="1.00")


# --------------------------------------------------------------------- async twins


async def test_async_principal_flows(
    async_principal: AsyncAgentBank, api: respx.MockRouter
) -> None:
    routes = mock_setup_routes(api)
    granted = await async_principal.grant_session(
        account_id=ACCOUNT_ID,
        public_key=SESSION_ADDRESS,
        scope=SCOPE,
        owner=OWNER_KEY,
        wait_for_install=True,
    )
    assert granted.session.status == "active"
    assert granted.install_operation is not None
    assert granted.install_operation.status == "succeeded"
    not_installed = await async_principal.grant_session(
        account_id=ACCOUNT_ID,
        public_key=SESSION_ADDRESS,
        scope=SCOPE,
        owner=OWNER_KEY,
        install=False,
    )
    assert not_installed.install_operation is None
    routes["install"].respond(json=session_json(install_operation_id=None))
    nothing_to_sign = await async_principal.grant_session(
        account_id=ACCOUNT_ID, public_key=SESSION_ADDRESS, scope=SCOPE, owner=OWNER_KEY
    )
    assert nothing_to_sign.install_operation is None
    only_account = await async_principal.setup_agent_account(agent_id=AGENT_ID)
    assert only_account.session is None
    with pytest.raises(ConfigurationError, match="owner key"):
        await async_principal.setup_agent_account(agent_id=AGENT_ID, spend_key=SPEND_KEY)
    check_permit(await async_principal.spend_key_permit(ACCOUNT_ID, SPEND_KEY))
    api.get(f"/v1/accounts/{ACCOUNT_ID}").respond(json=account_json(chain_id=1337))
    with pytest.raises(BadRequestError, match="on chain 1337"):
        await async_principal.spend_key_permit(ACCOUNT_ID, SPEND_KEY)
    api.get(f"/v1/accounts/{ACCOUNT_ID}").respond(json=account_json(role="treasury"))
    with pytest.raises(BadRequestError, match="not the treasury"):
        await async_principal.provision_spend_key(ACCOUNT_ID, SPEND_KEY, owner=OWNER_KEY)


async def test_async_owner_rotation_and_sandbox(
    async_principal: AsyncAgentBank, api: respx.MockRouter
) -> None:
    api.get("/v1/meta").respond(json=meta_json())
    api.post(f"/v1/accounts/{ACCOUNT_ID}/owner-swap").respond(
        201, json=operation_json("requires_signature", purpose="owner.swap")
    )
    api.get(f"/v1/owner-operations/{OOP_ID}").mock(
        side_effect=[
            httpx.Response(200, json=operation_json("requires_signature")),
            httpx.Response(200, json=operation_json("succeeded")),
            httpx.Response(200, json=operation_json("submitted")),
        ]
    )
    sign = api.post(f"/v1/owner-operations/{OOP_ID}/signature").respond(
        json=operation_json("submitted", purpose="owner.swap")
    )
    swapped = await async_principal.owner_operations.prepare_owner_swap(
        ACCOUNT_ID, new_owner_address=NEW_OWNER, owner=OWNER_KEY, idempotency_key="owner-swap-2"
    )
    assert swapped.status == "submitted"
    assert sign.calls.last.request.headers["idempotency-key"] == "owner-swap-2.sign"
    unsigned = await async_principal.owner_operations.prepare_owner_swap(
        ACCOUNT_ID, new_owner_address=NEW_OWNER
    )
    assert unsigned.status == "requires_signature"
    # sign_and_submit by id retrieves first; then wait polls until done.
    done = await async_principal.owner_operations.sign_and_submit(
        OOP_ID, owner=OWNER_KEY, wait=True
    )
    assert done.status == "succeeded"
    with pytest.raises(AgentBankError) as excinfo:
        await async_principal.owner_operations.wait(OOP_ID, timeout=0)
    assert excinfo.value.code == "operation_timeout"

    api.get("/v1/orgs/me").respond(json=example("Org", id=ORG_ID))
    rotate = api.post("/v1/orgs/me/owner").respond(json=example("Org", id=ORG_ID))
    await async_principal.orgs.rotate_owner(new_owner_address=NEW_OWNER, owner=OWNER_KEY)
    authorization = body_of(rotate)["owner_authorization"]
    verify(owner_payloads.owner_rotate(ORG_ID, NEW_OWNER), authorization)
    explicit = {
        "signer": OWNER_ADDRESS,
        "signature": "0x" + "11" * 65,
        "issued_at": 1,
        "expires_at": 2,
    }
    await async_principal.orgs.rotate_owner(
        new_owner_address=NEW_OWNER, owner_authorization=explicit
    )
    assert body_of(rotate)["owner_authorization"] == explicit
    await async_principal.orgs.rotate_owner(new_owner_address=NEW_OWNER)
    assert body_of(rotate) == {"new_owner_address": NEW_OWNER}

    faucet = api.post("/v1/sandbox/faucet").respond(json=example("SandboxFaucetResponse"))
    async with AsyncAgentBank(api_key=API_KEY, base_url=BASE_URL, account_id=ACCOUNT_ID) as bank:
        await bank.sandbox.faucet(amount="2.50")
        assert body_of(faucet)["account_id"] == ACCOUNT_ID
        with pytest.raises(ValueError, match="exactly one"):
            await bank.sandbox.faucet(amount="1.00", account_id=ACCOUNT_ID, address=SPEND_ADDRESS)
