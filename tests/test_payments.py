"""The two-step payment flow, escrow/stream signing, and owner-signed helpers."""

from __future__ import annotations

import json
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
    ConfigurationError,
    MainnetLockedError,
    PaymentError,
)
from agentbank.eip712 import verify_owner_authorization
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
    verify_agent_request,
)
from tests.factories import SCHEMAS, build, example, id_for

HASH_1 = "0x" + "a1" * 32
HASH_2 = "0x" + "b2" * 32
PAY_TO = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"


class Clock:
    """A fake monotonic clock advanced by the (fake) sleeps."""

    def __init__(self) -> None:
        self.now = 0.0


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    fake = Clock()

    def sleep(self: object, seconds: float) -> None:
        fake.now += seconds

    async def async_sleep(self: object, seconds: float) -> None:
        fake.now += seconds

    monkeypatch.setattr(AgentBank, "_sleep", sleep)
    monkeypatch.setattr(AsyncAgentBank, "_sleep", async_sleep)
    monkeypatch.setattr(AgentBank, "_monotonic", lambda self: fake.now)
    monkeypatch.setattr(AsyncAgentBank, "_monotonic", lambda self: fake.now)
    return fake


def signing_request(user_op_hash: str = HASH_1, **overrides: Any) -> dict[str, Any]:
    return {
        "session_id": SESSION_ID,
        "user_op_hash": user_op_hash,
        "chain_id": 84532,
        "expires_at": "2026-10-11T12:10:00Z",
        **overrides,
    }


def payment(status: str, **overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "id": PAYMENT_ID,
        "account_id": ACCOUNT_ID,
        "status": status,
        "signing_request": None,
        "owner_operation_id": None,
        "failure_reason": None,
    }
    fields.update(overrides)
    return example("Payment", **fields)


def recovered_session_signer(request: httpx.Request, user_op_hash: str) -> str:
    body = json.loads(request.content)
    message = encode_defunct(primitive=bytes.fromhex(user_op_hash[2:]))
    signer: str = Account.recover_message(message, signature=body["signature"])
    return signer


# --------------------------------------------------------------------- pay


def test_pay_creates_signs_and_submits(agent: AgentBank, api: respx.MockRouter) -> None:
    create = api.post("/v1/payments").respond(
        201, json=payment("requires_signature", signing_request=signing_request())
    )
    submit = api.post(f"/v1/payments/{PAYMENT_ID}/signature").respond(
        200, json=payment("submitted")
    )
    result = agent.pay(to=PAY_TO, amount="12.50", memo="dataset", idempotency_key="task-42-pay")
    assert result.status == "submitted"
    assert create.calls.last.request.headers["idempotency-key"] == "task-42-pay"
    request = submit.calls.last.request
    verify_agent_request(request)
    assert json.loads(request.content)["session_id"] == SESSION_ID
    assert recovered_session_signer(request, HASH_1) == SESSION_ADDRESS
    assert request.headers["idempotency-key"] == f"sig:{PAYMENT_ID}:{HASH_1}"


def test_pay_is_safe_to_rerun(agent: AgentBank, api: respx.MockRouter) -> None:
    api.post("/v1/payments").respond(
        201, json=payment("requires_signature", signing_request=signing_request())
    )
    submit = api.post(f"/v1/payments/{PAYMENT_ID}/signature").respond(
        200, json=payment("submitted")
    )
    agent.payments.pay(to=PAY_TO, amount="1.00", idempotency_key="task-43-pay")
    agent.payments.pay(to=PAY_TO, amount="1.00", idempotency_key="task-43-pay")
    first, second = (call.request for call in submit.calls)
    assert first.headers["idempotency-key"] == second.headers["idempotency-key"]
    assert json.loads(first.content) == json.loads(second.content)


def test_pay_waits_for_settlement(agent: AgentBank, api: respx.MockRouter, clock: Clock) -> None:
    api.post("/v1/payments").respond(
        201, json=payment("requires_signature", signing_request=signing_request())
    )
    api.post(f"/v1/payments/{PAYMENT_ID}/signature").respond(200, json=payment("submitted"))
    poll = api.get(f"/v1/payments/{PAYMENT_ID}").mock(
        side_effect=[
            httpx.Response(200, json=payment("submitted")),
            httpx.Response(200, json=payment("settled", tx_hash=HASH_2)),
        ]
    )
    settled = agent.pay(to=PAY_TO, amount="1.00", wait_for_settlement=True, poll_interval=3)
    assert settled.status == "settled"
    assert poll.call_count == 2
    assert clock.now == 6


def test_pay_through_human_approval(agent: AgentBank, api: respx.MockRouter, clock: Clock) -> None:
    api.post("/v1/payments").respond(201, json=payment("requires_approval"))
    api.get(f"/v1/payments/{PAYMENT_ID}").mock(
        side_effect=[
            httpx.Response(200, json=payment("requires_approval")),
            httpx.Response(
                200, json=payment("requires_signature", signing_request=signing_request(HASH_2))
            ),
            httpx.Response(200, json=payment("settled")),
        ]
    )
    submit = api.post(f"/v1/payments/{PAYMENT_ID}/signature").respond(
        200, json=payment("submitted")
    )
    result = agent.pay(to=AGENT_ID, amount="500.00", wait_for_settlement=True)
    assert result.status == "settled"
    assert recovered_session_signer(submit.calls.last.request, HASH_2) == SESSION_ADDRESS


def test_pay_without_waiting_returns_pending_approval(
    agent: AgentBank, api: respx.MockRouter
) -> None:
    api.post("/v1/payments").respond(201, json=payment("requires_approval"))
    assert agent.pay(to=AGENT_ID, amount="500.00").status == "requires_approval"


@pytest.mark.parametrize("status", ["denied", "failed", "canceled", "expired"])
def test_terminal_failures_raise_payment_errors(
    agent: AgentBank, api: respx.MockRouter, status: str
) -> None:
    api.post("/v1/payments").respond(201, json=payment(status, failure_reason="limits.per_day"))
    with pytest.raises(PaymentError) as excinfo:
        agent.pay(to=AGENT_ID, amount="1.00")
    assert excinfo.value.code == f"payment_{status}"
    assert "limits.per_day" in excinfo.value.detail
    assert excinfo.value.payment.id == PAYMENT_ID


def test_cosigner_refusal_after_submission(agent: AgentBank, api: respx.MockRouter) -> None:
    api.post("/v1/payments").respond(
        201, json=payment("requires_signature", signing_request=signing_request())
    )
    api.post(f"/v1/payments/{PAYMENT_ID}/signature").respond(200, json=payment("denied"))
    with pytest.raises(PaymentError, match="denied"):
        agent.pay(to=AGENT_ID, amount="1.00")


def test_require_owner_cannot_be_signed_by_the_agent(
    agent: AgentBank, api: respx.MockRouter
) -> None:
    api.post("/v1/payments").respond(
        201, json=payment("requires_signature", owner_operation_id=id_for("oop"))
    )
    with pytest.raises(PaymentError) as excinfo:
        agent.pay(to=AGENT_ID, amount="900.00")
    assert excinfo.value.code == "requires_owner"
    api.post("/v1/payments").respond(201, json=payment("requires_signature"))
    with pytest.raises(AgentBankError) as nothing:
        agent.pay(to=AGENT_ID, amount="1.00")
    assert nothing.value.code == "invalid_state"


def test_settlement_timeout(agent: AgentBank, api: respx.MockRouter, clock: Clock) -> None:
    api.get(f"/v1/payments/{PAYMENT_ID}").respond(200, json=payment("submitted"))
    with pytest.raises(PaymentError) as excinfo:
        agent.payments.wait_for_settlement(PAYMENT_ID, timeout=10, poll_interval=2)
    assert excinfo.value.code == "settlement_timeout"
    assert clock.now == 10


def test_same_operation_is_not_resubmitted(agent: AgentBank, api: respx.MockRouter) -> None:
    pending = payment("requires_signature", signing_request=signing_request())
    api.post("/v1/payments").respond(201, json=pending)
    submit = api.post(f"/v1/payments/{PAYMENT_ID}/signature").respond(200, json=pending)
    assert agent.pay(to=AGENT_ID, amount="1.00").status == "requires_signature"
    assert submit.call_count == 1


def test_signing_guards(agent: AgentBank, api: respx.MockRouter) -> None:
    other_session = payment(
        "requires_signature", signing_request=signing_request(session_id=id_for("ses")[:-1] + "1")
    )
    api.post("/v1/payments").respond(201, json=other_session)
    with pytest.raises(ConfigurationError, match="must be signed by session"):
        agent.pay(to=AGENT_ID, amount="1.00")
    mainnet = payment("requires_signature", signing_request=signing_request(chain_id=8453))
    api.post("/v1/payments").respond(201, json=mainnet)
    with pytest.raises(MainnetLockedError):
        agent.pay(to=AGENT_ID, amount="1.00")


def test_sign_helper(agent: AgentBank) -> None:
    from agentbank.models import Payment

    pending = Payment.model_validate(
        payment("requires_signature", signing_request=signing_request())
    )
    message = encode_defunct(primitive=bytes.fromhex(HASH_1[2:]))
    assert (
        Account.recover_message(message, signature=agent.payments.sign(pending)) == SESSION_ADDRESS
    )
    settled = Payment.model_validate(payment("settled"))
    with pytest.raises(AgentBankError, match="nothing to sign"):
        agent.payments.sign(settled)


def test_principal_clients_cannot_sign(api: respx.MockRouter) -> None:
    from agentbank.models import Payment

    with AgentBank(api_key=API_KEY, base_url=BASE_URL) as principal:
        pending = Payment.model_validate(
            payment("requires_signature", signing_request=signing_request())
        )
        with pytest.raises(ConfigurationError, match="agent credentials"):
            principal.payments.sign(pending)


@pytest.mark.parametrize(
    ("to", "expected"),
    [
        (PAY_TO, {"address": PAY_TO}),
        (AGENT_ID, {"agent_id": AGENT_ID}),
        (ACCOUNT_ID, {"account_id": ACCOUNT_ID}),
        ({"agent_id": AGENT_ID}, {"agent_id": AGENT_ID}),
    ],
)
def test_destinations(
    agent: AgentBank, api: respx.MockRouter, to: Any, expected: dict[str, str]
) -> None:
    route = api.post("/v1/payments").respond(201, json=payment("submitted"))
    agent.payments.create(amount="1.00", to=to)
    assert json.loads(route.calls.last.request.content)["to"] == expected


def test_invalid_destination_and_amounts(agent: AgentBank) -> None:
    with pytest.raises(ValueError, match="Payment destination"):
        agent.payments.create(amount="1.00", to="bob")
    with pytest.raises(AgentBankError, match="decimal strings"):
        agent.payments.create(amount=1.5, to=AGENT_ID)  # type: ignore[arg-type]


async def test_async_pay_flow(
    async_agent: AsyncAgentBank, api: respx.MockRouter, clock: Clock
) -> None:
    api.post("/v1/payments").respond(
        201, json=payment("requires_signature", signing_request=signing_request())
    )
    submit = api.post(f"/v1/payments/{PAYMENT_ID}/signature").respond(
        200, json=payment("submitted")
    )
    api.get(f"/v1/payments/{PAYMENT_ID}").respond(200, json=payment("settled"))
    result = await async_agent.pay(to=PAY_TO, amount="2.00", wait_for_settlement=True)
    assert result.status == "settled"
    assert recovered_session_signer(submit.calls.last.request, HASH_1) == SESSION_ADDRESS
    verify_agent_request(submit.calls.last.request)


async def test_async_failures(async_agent: AsyncAgentBank, api: respx.MockRouter) -> None:
    api.post("/v1/payments").respond(201, json=payment("denied"))
    with pytest.raises(PaymentError):
        await async_agent.payments.pay(to=PAY_TO, amount="2.00")


# --------------------------------------------------------------------- escrows and streams


def test_escrow_lock_signs_the_lock_operation(agent: AgentBank, api: respx.MockRouter) -> None:
    escrow_id = id_for("esc")
    pending = example("Escrow", id=escrow_id, signing_request=signing_request())
    api.post("/v1/escrows").respond(201, json=pending)
    submit = api.post(f"/v1/escrows/{escrow_id}/signature").respond(
        200, json=example("Escrow", id=escrow_id, status="locking", signing_request=None)
    )
    escrow = agent.escrows.lock(
        payee=AGENT_ID,
        amount="5.00",
        expires_at="2026-11-01T00:00:00Z",
        release="arbiter",
        arbiter=OWNER_ADDRESS,
    )
    assert escrow.status == "locking"
    assert recovered_session_signer(submit.calls.last.request, HASH_1) == SESSION_ADDRESS
    assert submit.calls.last.request.headers["idempotency-key"] == f"sig:{escrow_id}:{HASH_1}"
    done = example("Escrow", id=escrow_id, signing_request=None)
    api.post("/v1/escrows").respond(201, json=done)
    assert agent.escrows.lock(payee=PAY_TO, amount="5.00", expires_at="2026-11-01T00:00:00Z").id
    from agentbank.models import Escrow

    with pytest.raises(AgentBankError, match="nothing to sign"):
        agent.escrows.sign_and_submit(Escrow.model_validate(done))


def test_stream_start_signs_the_funding_operation(agent: AgentBank, api: respx.MockRouter) -> None:
    stream_id = id_for("str")
    api.post("/v1/streams").respond(
        201, json=example("Stream", id=stream_id, signing_request=signing_request())
    )
    submit = api.post(f"/v1/streams/{stream_id}/signature").respond(
        200, json=example("Stream", id=stream_id, status="active", signing_request=None)
    )
    stream = agent.streams.start(
        payee=PAY_TO,
        amount_per_interval="0.001",
        interval_seconds=1,
        deposit="10.00",
        kind="streaming",
        settle_every_seconds=3600,
    )
    assert stream.status == "active"
    body = json.loads(api.calls[0].request.content)
    assert body["payee"] == {"address": PAY_TO}
    assert body["deposit"] == {"amount": "10.00", "asset": "USDC"}
    assert recovered_session_signer(submit.calls.last.request, HASH_1) == SESSION_ADDRESS
    api.post("/v1/streams").respond(201, json=example("Stream", id=stream_id, signing_request=None))
    assert (
        agent.streams.start(
            payee=AGENT_ID, amount_per_interval="1.00", interval_seconds=86_400, deposit="30.00"
        ).signing_request
        is None
    )
    from agentbank.models import Stream

    with pytest.raises(AgentBankError, match="nothing to sign"):
        agent.streams.sign_and_submit(
            Stream.model_validate(example("Stream", signing_request=None))
        )
    # Example data defaults chain_id to 1 (Ethereum mainnet): the SDK refuses to sign it.
    mainnet = Stream.model_validate(
        example("Stream", signing_request=build(SCHEMAS["SigningRequest"]))
    )
    with pytest.raises(MainnetLockedError):
        agent.streams.sign_and_submit(mainnet)


async def test_async_escrow_and_stream(async_agent: AsyncAgentBank, api: respx.MockRouter) -> None:
    escrow_id, stream_id = id_for("esc"), id_for("str")
    api.post("/v1/escrows").respond(
        201, json=example("Escrow", id=escrow_id, signing_request=signing_request())
    )
    api.post(f"/v1/escrows/{escrow_id}/signature").respond(
        200, json=example("Escrow", id=escrow_id)
    )
    api.post("/v1/streams").respond(
        201, json=example("Stream", id=stream_id, signing_request=signing_request())
    )
    api.post(f"/v1/streams/{stream_id}/signature").respond(
        200, json=example("Stream", id=stream_id)
    )
    assert (
        await async_agent.escrows.lock(
            payee=PAY_TO, amount="1.00", expires_at="2026-11-01T00:00:00Z"
        )
    ).id
    started = await async_agent.streams.start(
        payee=PAY_TO, amount_per_interval="0.01", interval_seconds=1, deposit="1.00"
    )
    assert started.id == stream_id


# --------------------------------------------------------------------- owner-signed helpers


def _authorization(route: respx.Route) -> tuple[dict[str, Any], dict[str, Any]]:
    body = json.loads(route.calls.last.request.content)
    return body, body.pop("owner_authorization")


def _verify(authorization: dict[str, Any], action: str, subject: str, payload: Any) -> None:
    verify_owner_authorization(
        owner=OWNER_ADDRESS,
        authorization=authorization,
        chain_id=84532,
        action=action,
        subject=subject,
        payload=payload,
    )


def test_owner_signed_session_grant(principal: AgentBank, api: respx.MockRouter) -> None:
    route = api.post("/v1/sessions").respond(201, json=example("Session"))
    scope = {"max_per_tx": "5.00", "max_per_day": "50.00", "expires_at": "2026-10-12T00:00:00Z"}
    principal.sessions.create(
        account_id=ACCOUNT_ID, public_key=SESSION_ADDRESS, scope=scope, owner=OWNER_KEY
    )
    body, authorization = _authorization(route)
    assert body == {"account_id": ACCOUNT_ID, "public_key": SESSION_ADDRESS, "scope": scope}
    _verify(authorization, "session.grant", ACCOUNT_ID, body)


def test_owner_signed_mandate_and_policy(principal: AgentBank, api: respx.MockRouter) -> None:
    mandate = {
        "vct": "mandate.payment.open.1",
        "constraints": [{"type": "agentbank.x402_domains", "allowed": ["api.example-data.com"]}],
        "iat": 1_790_000_000,
        "exp": 1_790_086_400,
        "agent_id": AGENT_ID,
    }
    mandates = api.post("/v1/mandates").respond(201, json=example("Mandate"))
    principal.mandates.create(agent_id=AGENT_ID, mandate=mandate, owner=OWNER_KEY)
    body, authorization = _authorization(mandates)
    _verify(authorization, "mandate.issue", AGENT_ID, mandate)
    assert body["mandate"] == mandate

    policy = {"limits": {"per_day": "500.00"}, "counterparties": {"mode": "open"}}
    policies = api.put(f"/v1/agents/{AGENT_ID}/policy").respond(json=example("AgentPolicy"))
    principal.policies.update(AGENT_ID, policy=policy, owner=OWNER_KEY)
    body, authorization = _authorization(policies)
    _verify(authorization, "policy.loosen", AGENT_ID, policy)
    assert body == {"policy": policy}


def test_owner_signed_unfreeze_treasury_and_vault(
    principal: AgentBank, api: respx.MockRouter
) -> None:
    api.get("/v1/orgs/me").respond(json=example("Org", id=ORG_ID))
    org_unfreeze = api.post("/v1/orgs/me/unfreeze").respond(json=example("Org"))
    principal.orgs.unfreeze(reason="resolved", owner=OWNER_KEY)
    body, authorization = _authorization(org_unfreeze)
    _verify(authorization, "org.unfreeze", ORG_ID, {"reason": "resolved"})

    agent_unfreeze = api.post(f"/v1/agents/{AGENT_ID}/unfreeze").respond(json=example("Agent"))
    principal.agents.unfreeze(AGENT_ID, reason="fixed", owner=OWNER_KEY)
    _, authorization = _authorization(agent_unfreeze)
    _verify(authorization, "agent.unfreeze", AGENT_ID, {"reason": "fixed"})

    treasury = api.put("/v1/orgs/me/treasury").respond(json=example("Org"))
    principal.treasury.set_account(account_id=ACCOUNT_ID, owner=OWNER_KEY)
    _, authorization = _authorization(treasury)
    _verify(authorization, "treasury.set", ORG_ID, {"account_id": ACCOUNT_ID})

    topup = api.put(f"/v1/agents/{AGENT_ID}/auto-topup").respond(json=example("AutoTopUpRule"))
    principal.treasury.set_auto_topup(
        AGENT_ID, refill_to="50.00", when_below="10.00", max_per_day="100.00", owner=OWNER_KEY
    )
    body, authorization = _authorization(topup)
    _verify(authorization, "topup.set", AGENT_ID, body)

    sweep = api.put(f"/v1/accounts/{ACCOUNT_ID}/sweep-rule").respond(json=example("SweepRule"))
    principal.treasury.set_sweep_rule(
        ACCOUNT_ID, fund_id=id_for("fnd"), threshold="1000.00", max_share_bps=2500, owner=OWNER_KEY
    )
    body, authorization = _authorization(sweep)
    _verify(authorization, "sweep.set", ACCOUNT_ID, body)

    vault_id = id_for("vlt")
    withdraw = api.post(f"/v1/vaults/{vault_id}/withdraw").respond(json=example("Vault"))
    principal.vaults.withdraw(vault_id, amount="5.00", owner=OWNER_KEY)
    body, authorization = _authorization(withdraw)
    _verify(
        authorization, "vault.withdraw", vault_id, {"amount": {"amount": "5.00", "asset": "USDC"}}
    )


def test_owner_operation_sign_and_submit(principal: AgentBank, api: respx.MockRouter) -> None:
    operation_id = id_for("oop")
    pending = example(
        "OwnerOperation", id=operation_id, user_op_hash=HASH_2, status="requires_signature"
    )
    api.get(f"/v1/owner-operations/{operation_id}").respond(json=pending)
    submit = api.post(f"/v1/owner-operations/{operation_id}/signature").respond(
        json={**pending, "status": "submitted"}
    )
    result = principal.owner_operations.sign_and_submit(operation_id, owner=OWNER_KEY)
    assert result.status == "submitted"
    signature = json.loads(submit.calls.last.request.content)["signature"]
    message = encode_defunct(primitive=bytes.fromhex(HASH_2[2:]))
    assert Account.recover_message(message, signature=signature) == OWNER_ADDRESS
    api.get(f"/v1/owner-operations/{operation_id}").respond(json={**pending, "status": "succeeded"})
    assert (
        principal.owner_operations.sign_and_submit(operation_id, owner=OWNER_KEY).status
        == "succeeded"
    )
    assert submit.call_count == 1


def test_policy_check_accepts_models(agent: AgentBank, api: respx.MockRouter) -> None:
    from agentbank.models import PaymentIntent

    route = api.post("/v1/policy/check").respond(json=build(SCHEMAS["PolicyDecision"]))
    intent = PaymentIntent.model_validate(
        {
            "kind": "x402",
            "amount": {"amount": "0.01", "asset": "USDC"},
            "x402_domain": "api.example-data.com",
        }
    )
    agent.policies.check(intent=intent)
    assert json.loads(route.calls.last.request.content)["intent"] == {
        "amount": {"amount": "0.01", "asset": "USDC"},
        "kind": "x402",
        "x402_domain": "api.example-data.com",
    }
