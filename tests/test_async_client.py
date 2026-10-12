"""Async client behaviour (the sync client is generated from the same source)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from pydantic import ValidationError

from agentbank import (
    AgentBank,
    APIConnectionError,
    APITimeoutError,
    AsyncAgentBank,
    AsyncX402Transport,
    ConfigurationError,
    PaymentError,
    PolicyDeniedError,
    ServiceUnavailableError,
    owner_payloads,
)
from agentbank.eip712 import verify_owner_authorization
from agentbank.models import Payment
from agentbank.x402 import PaymentRequired, select_requirement
from tests.conftest import (
    ACCOUNT_ID,
    AGENT_ID,
    API_KEY,
    BASE_URL,
    ORG_ID,
    OWNER_ADDRESS,
    OWNER_KEY,
    PAYMENT_ID,
    SESSION_ADDRESS,
    SESSION_ID,
    SESSION_KEY,
    SPEND_KEY,
    verify_agent_request,
)
from tests.factories import SCHEMAS, build, example, id_for

ROOT = Path(__file__).resolve().parent.parent
HASH = "0x" + "c3" * 32


def signing_request(**overrides: Any) -> dict[str, Any]:
    return {
        "session_id": SESSION_ID,
        "user_op_hash": HASH,
        "chain_id": 84532,
        "expires_at": "2026-10-11T12:10:00Z",
        **overrides,
    }


def payment(status: str, **overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "id": PAYMENT_ID,
        "status": status,
        "signing_request": None,
        "owner_operation_id": None,
        "failure_reason": None,
    }
    fields.update(overrides)
    return example("Payment", **fields)


async def test_async_retries_and_errors(
    async_agent: AsyncAgentBank, api: respx.MockRouter, sleeps: list[float]
) -> None:
    route = api.post("/v1/payments").mock(
        side_effect=[
            httpx.ConnectTimeout("connect"),
            httpx.Response(502, json={"code": "chain_error"}),
            httpx.Response(201, json=payment("submitted")),
        ]
    )
    await async_agent.payments.create(amount="1.00", to=AGENT_ID)
    assert route.call_count == 3
    assert len({c.request.headers["idempotency-key"] for c in route.calls}) == 1
    for call in route.calls:
        verify_agent_request(call.request)
    assert len(sleeps) == 2

    api.get(f"/v1/payments/{PAYMENT_ID}").mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(APITimeoutError):
        await async_agent.payments.retrieve(PAYMENT_ID)
    api.get(f"/v1/accounts/{ACCOUNT_ID}").mock(side_effect=httpx.ReadError("reset"))
    with pytest.raises(APIConnectionError):
        await async_agent.accounts.retrieve()
    api.get(f"/v1/accounts/{ACCOUNT_ID}/balances").respond(
        503, json={"code": "cosigner_unavailable"}
    )
    with pytest.raises(ServiceUnavailableError):
        await async_agent.accounts.balances(request_options={"max_retries": 0})
    api.post("/v1/policy/check").respond(422, json={"code": "policy_denied", "detail": "no"})
    with pytest.raises(PolicyDeniedError):
        await async_agent.policies.check(intent={"amount": {"amount": "1.00", "asset": "USDC"}})


async def test_async_lifecycle_and_low_level_call(api: respx.MockRouter) -> None:
    http = httpx.AsyncClient()
    bank = AsyncAgentBank(api_key=API_KEY, base_url=BASE_URL, http_client=http)
    assert "api_key" in repr(bank)
    api.get("/v1/billing/fees").respond(json={"total": "2.00"})
    assert (await bank.call("getFees", query={"period": "2026-10"}))["total"] == "2.00"
    with pytest.raises(ValueError, match="Unknown operation"):
        await bank.call("nope")
    api.get("/healthz").respond(json=build(SCHEMAS["HealthResponse"]))
    assert (await bank.health()).status == "ok"
    await bank.close()
    assert not http.is_closed
    await http.aclose()
    async with AsyncAgentBank(api_key=API_KEY, base_url=BASE_URL) as owned:
        assert owned.chain_id is None
        assert owned.session_id is None
        assert owned.account_id is None
        assert owned.config.base_url == BASE_URL


async def test_async_pay_wait_and_guards(
    async_agent: AsyncAgentBank, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    ticks = iter(range(0, 1000, 5))
    monkeypatch.setattr(AsyncAgentBank, "_monotonic", lambda self: float(next(ticks)))
    api.get(f"/v1/payments/{PAYMENT_ID}").mock(
        side_effect=[
            httpx.Response(
                200, json=payment("requires_signature", signing_request=signing_request())
            ),
            httpx.Response(200, json=payment("submitted")),
            httpx.Response(200, json=payment("settled")),
        ]
    )
    submit = api.post(f"/v1/payments/{PAYMENT_ID}/signature").respond(json=payment("submitted"))
    settled = await async_agent.payments.complete(PAYMENT_ID, wait_for_settlement=True, timeout=60)
    assert settled.status == "settled"
    assert submit.call_count == 1

    api.get(f"/v1/payments/{PAYMENT_ID}").respond(json=payment("submitted"))
    with pytest.raises(PaymentError) as timeout:
        await async_agent.payments.wait_for_settlement(PAYMENT_ID, timeout=10)
    assert timeout.value.code == "settlement_timeout"

    owner_only = Payment.model_validate(
        payment("requires_signature", owner_operation_id=id_for("oop"))
    )
    with pytest.raises(PaymentError, match="owner key"):
        await async_agent.payments.sign_and_submit(owner_only)
    signed = Payment.model_validate(
        payment("requires_signature", signing_request=signing_request())
    )
    assert async_agent.payments.sign(signed).startswith("0x")

    pending = payment("requires_signature", signing_request=signing_request())
    api.post("/v1/payments").respond(201, json=pending)
    api.post(f"/v1/payments/{PAYMENT_ID}/signature").respond(json=pending)
    assert (await async_agent.payments.pay(to=AGENT_ID, amount="1.00")).status == (
        "requires_signature"
    )


async def test_async_owner_helpers(async_principal: AsyncAgentBank, api: respx.MockRouter) -> None:
    def authorization(route: respx.Route) -> tuple[dict[str, Any], dict[str, Any]]:
        body = json.loads(route.calls.last.request.content)
        return body, body.pop("owner_authorization")

    def check(auth: dict[str, Any], action: str, subject: str, payload: Any) -> None:
        verify_owner_authorization(
            owner=OWNER_ADDRESS,
            authorization=auth,
            chain_id=84532,
            action=action,
            subject=subject,
            payload=payload,
        )

    meta = api.get("/v1/meta").respond(json=example("Meta", owner_authorization_chain_id=84532))
    sessions = api.post("/v1/sessions").respond(201, json=example("Session"))
    scope = {"max_per_tx": "1.00", "max_per_day": "10.00", "expires_at": "2026-10-12T00:00:00Z"}
    await async_principal.sessions.create(
        account_id=ACCOUNT_ID, public_key=SESSION_ADDRESS, scope=scope, owner=OWNER_KEY
    )
    body, auth = authorization(sessions)
    check(auth, "session.grant", ACCOUNT_ID, body)

    mandate = {
        "vct": "mandate.payment.open.1",
        "constraints": [{"type": "payment.budget", "currency": "USD", "max": 5000}],
        "iat": 1,
        "exp": 2,
        "agent_id": AGENT_ID,
    }
    mandates = api.post("/v1/mandates").respond(201, json=example("Mandate"))
    await async_principal.mandates.create(agent_id=AGENT_ID, mandate=mandate, owner=OWNER_KEY)
    _, auth = authorization(mandates)
    check(auth, "mandate.issue", AGENT_ID, mandate)

    policy = {"limits": {"per_tx": "10.00"}}
    policies = api.put(f"/v1/agents/{AGENT_ID}/policy").respond(json=example("AgentPolicy"))
    await async_principal.policies.put(AGENT_ID, policy=policy, owner=OWNER_KEY)
    _, auth = authorization(policies)
    check(auth, "policy.loosen", AGENT_ID, owner_payloads.policy_loosen(AGENT_ID, policy).payload)
    explicit = {
        "signer": OWNER_ADDRESS,
        "signature": "0x" + "11" * 65,
        "issued_at": 1,
        "expires_at": 2,
    }
    await async_principal.policies.put(AGENT_ID, policy=policy, owner_authorization=explicit)
    assert json.loads(policies.calls.last.request.content)["owner_authorization"] == explicit

    api.get("/v1/orgs/me").respond(json=example("Org", id=ORG_ID))
    unfreeze = api.post("/v1/orgs/me/unfreeze").respond(json=example("Org"))
    await async_principal.orgs.unfreeze(reason="ok", owner=OWNER_KEY)
    _, auth = authorization(unfreeze)
    check(auth, "org.unfreeze", ORG_ID, {"reason": "ok"})

    agent_unfreeze = api.post(f"/v1/agents/{AGENT_ID}/unfreeze").respond(json=example("Agent"))
    await async_principal.agents.unfreeze(AGENT_ID, reason="ok", owner=OWNER_KEY)
    _, auth = authorization(agent_unfreeze)
    check(auth, "agent.unfreeze", AGENT_ID, {"reason": "ok"})

    treasury = api.put("/v1/orgs/me/treasury").respond(json=example("Org"))
    await async_principal.treasury.set(account_id=ACCOUNT_ID, owner=OWNER_KEY)
    _, auth = authorization(treasury)
    check(auth, "treasury.set", ORG_ID, {"account_id": ACCOUNT_ID})

    topup = api.put(f"/v1/agents/{AGENT_ID}/auto-topup").respond(json=example("AutoTopUpRule"))
    await async_principal.treasury.put_auto_topup(
        AGENT_ID, refill_to="5.00", when_below="1.00", max_per_day="10.00", owner=OWNER_KEY
    )
    body, auth = authorization(topup)
    check(auth, "topup.set", AGENT_ID, body)

    sweep = api.put(f"/v1/accounts/{ACCOUNT_ID}/sweep-rule").respond(json=example("SweepRule"))
    await async_principal.treasury.put_sweep_rule(
        ACCOUNT_ID, fund_id=id_for("fnd"), threshold="10.00", max_share_bps=100, owner=OWNER_KEY
    )
    body, auth = authorization(sweep)
    check(auth, "sweep.set", ACCOUNT_ID, body)

    vault_id = id_for("vlt")
    withdraw = api.post(f"/v1/vaults/{vault_id}/withdraw").respond(json=example("Vault"))
    await async_principal.vaults.withdraw(vault_id, amount="1.00", owner=OWNER_KEY)
    _, auth = authorization(withdraw)
    check(auth, "vault.withdraw", vault_id, {"amount": {"amount": "1.00", "asset": "USDC"}})

    operation_id = id_for("oop")
    api.get(f"/v1/owner-operations/{operation_id}").respond(
        json=example(
            "OwnerOperation",
            id=operation_id,
            status="requires_signature",
            user_op_hash=HASH,
            chain_id=84532,
        )
    )
    submit = api.post(f"/v1/owner-operations/{operation_id}/signature").respond(
        json=example("OwnerOperation", id=operation_id, status="submitted")
    )
    result = await async_principal.owner_operations.sign_and_submit(operation_id, owner=OWNER_KEY)
    assert result.status == "submitted"
    assert meta.call_count == 1
    assert await async_principal.owner_authorization_chain_id() == 84532
    assert (await async_principal.meta()).chain == "base-sepolia"
    assert (await async_principal.meta(refresh=True)).owner_authorization_chain_id == 84532
    assert meta.call_count == 2
    assert (
        submit.calls.last.request.headers["idempotency-key"]
        == f"oop_sig_{operation_id}_{HASH[2:18]}"
    )


async def test_async_misc(
    async_principal: AsyncAgentBank, async_agent: AsyncAgentBank, api: respx.MockRouter
) -> None:
    approval_id = id_for("apr")
    decide = api.post(f"/v1/approvals/{approval_id}/decide").respond(json=example("Approval"))
    await async_principal.approvals.deny(approval_id)
    assert json.loads(decide.calls.last.request.content) == {"decision": "deny"}
    api.get(f"/v1/agents/{AGENT_ID}/auto-topup").respond(json=None)
    assert await async_agent.treasury.get_auto_topup(AGENT_ID) is None
    api.get("/v1/statements").respond(text="date,amount\n")
    assert (await async_agent.ledger.statement(period="2026-10", format="csv")) == "date,amount\n"
    escrow_id = id_for("esc")
    api.post("/v1/escrows").respond(201, json=example("Escrow", id=escrow_id, signing_request=None))
    assert (
        await async_agent.escrows.lock(
            payee={"agent_id": AGENT_ID}, amount="1.00", expires_at="2026-11-01T00:00:00Z"
        )
    ).id
    from agentbank.models import Escrow, Stream

    with pytest.raises(Exception, match="nothing to sign"):
        await async_agent.escrows.sign_and_submit(
            Escrow.model_validate(example("Escrow", signing_request=None))
        )
    stream_id = id_for("str")
    api.post("/v1/streams").respond(201, json=example("Stream", id=stream_id, signing_request=None))
    assert (
        await async_agent.streams.start(
            payee=AGENT_ID, amount_per_interval="1.00", interval_seconds=60, deposit="5.00"
        )
    ).id
    with pytest.raises(Exception, match="nothing to sign"):
        await async_agent.streams.sign_and_submit(
            Stream.model_validate(example("Stream", signing_request=None))
        )
    async with AsyncAgentBank(api_key=API_KEY, base_url=BASE_URL) as principal_only:
        with pytest.raises(ConfigurationError):
            await principal_only.payments.create(amount="1.00", to=AGENT_ID, account_id=ACCOUNT_ID)
    async with AsyncAgentBank(
        session_id=SESSION_ID, session_key=SESSION_KEY, spend_key=SPEND_KEY, account_id=ACCOUNT_ID
    ) as bank:
        transport = bank.x402.transport(max_amount="1.00", spend_key=SPEND_KEY)
        assert isinstance(transport, AsyncX402Transport)


def test_real_sleep_and_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.undo()  # restore the real _sleep implementations patched by the fixture
    with AgentBank() as bank:
        bank._sleep(0)
        assert bank._monotonic() > 0


async def test_real_async_sleep_and_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.undo()
    async with AsyncAgentBank() as bank:
        await bank._sleep(0)
        assert bank._monotonic() > 0


def test_sync_odds_and_ends(principal: AgentBank, agent: AgentBank, api: respx.MockRouter) -> None:
    from agentbank import sign_webhook

    header = sign_webhook("whsec", "{}")
    assert principal.webhooks.verify("whsec", "{}", header) > 0
    body = '{"id":"evt_1","type":"payment.settled","data":{}}'
    assert (
        principal.webhooks.construct_event("whsec", body, sign_webhook("whsec", body)).id == "evt_1"
    )
    approval_id = id_for("apr")
    decide = api.post(f"/v1/approvals/{approval_id}/decide").respond(json=example("Approval"))
    principal.approvals.deny(approval_id)
    assert json.loads(decide.calls.last.request.content)["decision"] == "deny"
    explicit = {
        "signer": OWNER_ADDRESS,
        "signature": "0x" + "11" * 65,
        "issued_at": 1,
        "expires_at": 2,
    }
    policies = api.put(f"/v1/agents/{AGENT_ID}/policy").respond(json=example("AgentPolicy"))
    principal.policies.put(AGENT_ID, policy={}, owner_authorization=explicit)
    assert json.loads(policies.calls.last.request.content)["owner_authorization"] == explicit
    sessions = api.post("/v1/sessions").respond(201, json=example("Session"))
    scope = {"max_per_tx": "1.00", "max_per_day": "2.00", "expires_at": "2026-10-12T00:00:00Z"}
    principal.sessions.create(account_id=ACCOUNT_ID, public_key=SESSION_ADDRESS, scope=scope)
    assert "owner_authorization" not in json.loads(sessions.calls.last.request.content)
    mandates = api.post("/v1/mandates").respond(201, json=example("Mandate"))
    mandate = build(SCHEMAS["OpenPaymentMandate"])
    principal.mandates.create(agent_id=AGENT_ID, mandate=mandate)
    assert "owner_authorization" not in json.loads(mandates.calls.last.request.content)
    with pytest.raises(ValidationError):
        principal.sessions.create(account_id=ACCOUNT_ID, public_key=SESSION_ADDRESS, scope={})
    escrows = api.post("/v1/escrows").respond(201, json=example("Escrow", signing_request=None))
    agent.escrows.create(
        payee={"address": OWNER_ADDRESS}, amount="1.00", expires_at="2026-11-01T00:00:00Z"
    )
    assert json.loads(escrows.calls.last.request.content)["payee"] == {"address": OWNER_ADDRESS}
    with pytest.raises(ValueError, match="Payee"):
        agent.escrows.create(payee="alice", amount="1.00", expires_at="2026-11-01T00:00:00Z")


def test_v2_challenge_without_resource_info() -> None:
    from eth_account import Account

    from agentbank.models import X402PayResponse
    from agentbank.x402 import build_payment_header
    from tests.test_x402 import REQUIREMENT_V2, RESOURCE_URL, pay_response

    selected = select_requirement(
        PaymentRequired(x402_version=2, accepts=(REQUIREMENT_V2,)),
        request_url=RESOURCE_URL,
        max_amount=10_000,
    )
    assert selected.resource == {"url": RESOURCE_URL}
    header = build_payment_header(
        selected, X402PayResponse.model_validate(pay_response()), Account.from_key(SPEND_KEY)
    )
    assert "resource" not in header.payload


def test_generated_sync_client_is_up_to_date() -> None:
    """``src/agentbank/_sync`` must match ``scripts/unasync.py`` output (CI also checks)."""
    result = subprocess.run(  # noqa: S603 - fixed argv, no user input
        [sys.executable, str(ROOT / "scripts" / "unasync.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


async def test_async_payment_outcomes(
    async_agent: AsyncAgentBank, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentbank import BadRequestError, PaymentDeniedError, PaymentFailedError

    ticks = iter(range(0, 10_000, 5))
    monkeypatch.setattr(AsyncAgentBank, "_monotonic", lambda self: float(next(ticks)))

    def created(**overrides: Any) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "amount": {"amount": "3.00", "asset": "USDC"},
            "counterparty": {
                "type": "address",
                "address": OWNER_ADDRESS,
                "agent_id": None,
                "x402_domain": None,
            },
            "signing_request": signing_request(),
        }
        fields.update(overrides)
        status = fields.pop("status", "requires_signature")
        return payment(status, **fields)

    api.post("/v1/payments").respond(201, json=created(amount={"amount": "4.00", "asset": "USDC"}))
    with pytest.raises(BadRequestError, match=r"amount 4\.00 != 3\.00"):
        await async_agent.pay(to=OWNER_ADDRESS, amount="3.00")
    other = {"type": "address", "address": SESSION_ADDRESS, "agent_id": None, "x402_domain": None}
    api.post("/v1/payments").respond(201, json=created(counterparty=other))
    with pytest.raises(BadRequestError, match="counterparty address differs"):
        await async_agent.pay(to=OWNER_ADDRESS, amount="3.00")
    agent_counterparty = {**other, "agent_id": id_for("agt")[:-1] + "9"}
    api.post("/v1/payments").respond(201, json=created(counterparty=agent_counterparty))
    with pytest.raises(BadRequestError, match="counterparty agent differs"):
        await async_agent.pay(to=AGENT_ID, amount="3.00")

    api.post("/v1/payments").respond(201, json=created(status="failed", failure_reason="revert"))
    with pytest.raises(PaymentFailedError, match="revert"):
        await async_agent.pay(to=OWNER_ADDRESS, amount="3.00")
    api.post("/v1/payments").respond(201, json=created(status="canceled"))
    with pytest.raises(PaymentError, match="canceled"):
        await async_agent.pay(to=OWNER_ADDRESS, amount="3.00")
    api.post("/v1/payments").respond(
        201, json=created(status="requires_signature", signing_request=None)
    )
    with pytest.raises(Exception, match="nothing to sign"):
        await async_agent.pay(to=OWNER_ADDRESS, amount="3.00")

    api.get(f"/v1/payments/{PAYMENT_ID}").mock(
        side_effect=[
            httpx.Response(200, json=payment("requires_approval")),
            httpx.Response(200, json=payment("denied")),
        ]
    )
    with pytest.raises(PaymentDeniedError):
        await async_agent.payments.complete(PAYMENT_ID, wait_for_approval=True)
    api.get(f"/v1/payments/{PAYMENT_ID}").respond(200, json=payment("settled"))
    submitted = Payment.model_validate(payment("submitted"))
    assert (await async_agent.payments.wait_for_settlement(submitted)).status == "settled"
    api.get(f"/v1/payments/{PAYMENT_ID}").respond(200, json=payment("submitted"))
    with pytest.raises(PaymentError, match="still submitted"):
        await async_agent.payments.wait_for_settlement(PAYMENT_ID, timeout=10)
    with pytest.raises(Exception, match="nothing to sign"):
        async_agent.payments.sign(Payment.model_validate(payment("settled")))


async def test_async_escrow_stream_and_vault_branches(
    async_agent: AsyncAgentBank, async_principal: AsyncAgentBank, api: respx.MockRouter
) -> None:
    from agentbank import PaymentFailedError
    from agentbank.models import Escrow, Stream

    future = {**signing_request(), "expires_at": "2099-01-01T00:00:00Z"}
    escrow_id, stream_id = id_for("esc"), id_for("str")
    api.post("/v1/escrows").respond(201, json=example("Escrow", id=escrow_id, status="failed"))
    with pytest.raises(PaymentFailedError):
        await async_agent.escrows.lock(
            payee=OWNER_ADDRESS, amount="1.00", expires_at="2099-01-01T00:00:00Z"
        )
    with pytest.raises(PaymentFailedError):
        await async_agent.escrows.sign_and_submit(
            Escrow.model_validate(example("Escrow", status="failed", signing_request=future))
        )
    api.post("/v1/streams").respond(201, json=example("Stream", id=stream_id, status="failed"))
    with pytest.raises(PaymentFailedError):
        await async_agent.streams.start(
            payee=OWNER_ADDRESS, amount_per_interval="1", interval_seconds=1, deposit="1"
        )
    with pytest.raises(PaymentFailedError):
        await async_agent.streams.sign_and_submit(
            Stream.model_validate(example("Stream", status="failed", signing_request=future))
        )
    vault_id = id_for("vlt")
    withdraw = api.post(f"/v1/vaults/{vault_id}/withdraw").respond(json=example("Vault"))
    explicit = {
        "signer": OWNER_ADDRESS,
        "signature": "0x" + "11" * 65,
        "issued_at": 1,
        "expires_at": 2,
    }
    await async_principal.vaults.withdraw(vault_id, amount="2.00", owner_authorization=explicit)
    assert json.loads(withdraw.calls.last.request.content)["owner_authorization"] == explicit
    with pytest.raises(ConfigurationError, match="account_id"):
        await async_principal.payment_requests.create(amount="1.00")
